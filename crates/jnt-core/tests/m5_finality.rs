//! M5 binding finality + testnet profile + equivocation safety
//! (Decisions 12, 13, 14 — SPEC.md §14.8).
//!
//! What this file pins, in the milestone's own terms:
//!
//! - **Activation (A):** a certificate observed below
//!   `finality_activation_height` never binds; a valid, canonical, monotonic,
//!   quorum-satisfying certificate at or above it *does*, and
//!   `Chain::adopt()` then refuses any branch forking at or below it.
//! - **Profile (B):** `testnet` is reachable by name, distinct from the other
//!   profiles, deterministic across independent constructions, four keys with
//!   quorum 3, interval 10, activation 20 — no staking, no rotation.
//! - **Conflicts (D):** every listed certificate attack fails closed, two
//!   different hashes never finalize at one height, and an otherwise-valid
//!   conflict leaves canonical, bounded, order-independent
//!   `EquivocationEvidence` behind — with no punishment attached.
//! - **Restart:** the finalized point round-trips through a store and refuses
//!   to restore onto anything but the exact canonical block.

use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{
    BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload, MockBls, ValidatorSet,
};
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::finality::{FinalityError, FinalityManager, MAX_EQUIVOCATION_EVIDENCE};
use jnt_core::hash::Hash512;
use jnt_core::params::{
    mainnet_committee_secrets, mini_committee_secrets, testnet_committee_secrets, NetworkParams,
};
use jnt_core::validators::{equivocation_evidence, ValidatorError};
use jnt_core::wallet::Wallet;
use jnt_core::Address;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn ts(height: u64, bump: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000 + bump
}

/// The testnet committee as (secret, key) pairs in canonical key order — the
/// same order `genesis_validators` and therefore every bitmap uses.
fn committee() -> Vec<(SecretKey, BlsPublicKey)> {
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = testnet_committee_secrets()
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

/// The mainnet bootstrap committee as (secret, key) pairs in canonical order.
fn mainnet_committee() -> Vec<(SecretKey, BlsPublicKey)> {
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = mainnet_committee_secrets()
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

/// A committee that is deliberately *not* the declared one (mini's derivation
/// domain never coincides with testnet's), for wrong-committee attacks.
fn foreign_committee() -> Vec<(SecretKey, BlsPublicKey)> {
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = mini_committee_secrets()
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

fn payload(height: u64, block_hash: Hash512) -> CheckpointPayload {
    CheckpointPayload {
        height,
        block_hash,
        network_id: "jounit/testnet".into(),
        epoch: height / 10,
    }
}

/// Sign `p` with `indices` into `pairs` and aggregate — the real BLS path.
fn signed_with(
    pairs: &[(SecretKey, BlsPublicKey)],
    p: CheckpointPayload,
    indices: &[usize],
) -> Checkpoint {
    let msg = p.signing_hash();
    let sigs: Vec<BlsSignature> = indices.iter().map(|&i| pairs[i].0.sign(&msg)).collect();
    let agg = RealBls::aggregate(&sigs).unwrap();
    let mut bitmap = vec![0u8; pairs.len().div_ceil(8)];
    for &i in indices {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    Checkpoint {
        payload: p,
        aggregate_sig: agg,
        signer_bitmap: bitmap,
        signer_count: indices.len() as u32,
        pq_sidecar: Vec::new(),
    }
}

fn signed(height: u64, block_hash: Hash512, indices: &[usize]) -> Checkpoint {
    signed_with(&committee(), payload(height, block_hash), indices)
}

fn miner() -> Address {
    Wallet::from_private_key_bytes(&[9u8; 32], "m5-finality")
        .unwrap()
        .address()
        .unwrap()
}

/// A canonical testnet chain to `to`, mined at exact target spacing.
fn chain_to(to: u64) -> Chain {
    let addr = miner();
    let mut chain = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=to {
        let b = chain.mine_block(addr, vec![], ts(h, 0)).unwrap();
        chain.submit(b).unwrap();
    }
    chain
}

#[allow(clippy::result_large_err)]
fn apply(chain: &mut Chain, cp: &Checkpoint) -> Result<(), FinalityError> {
    chain.apply_checkpoint(cp, &RealBls)
}

/// The refusal's named variant, with the chain's finality state untouched.
/// (Evidence assertions belong to the individual tests: the conflict path is
/// deliberately allowed to record some.)
fn refused(chain: &mut Chain, cp: &Checkpoint, expect: &str) -> FinalityError {
    let before_accepted = chain.finality().accepted_height();
    let before_binding = chain.finality().binding_finalized_height();
    let err = apply(chain, cp).expect_err(expect);
    assert_eq!(
        chain.finality().accepted_height(),
        before_accepted,
        "{expect}: a refusal must not move the observation frontier"
    );
    assert_eq!(
        chain.finality().binding_finalized_height(),
        before_binding,
        "{expect}: a refusal must not move binding finality"
    );
    err
}

// ---------------------------------------------------------------------------
// Decision 13 — the testnet profile
// ---------------------------------------------------------------------------

#[test]
fn testnet_is_reachable_by_name_and_distinct_from_every_other_profile() {
    let t = NetworkParams::by_name("testnet").unwrap();
    assert_eq!(t.name, "testnet");
    t.validate().unwrap();

    let mini = NetworkParams::mini();
    let mainnet = NetworkParams::mainnet();
    assert_ne!(t.network_id, mini.network_id);
    assert_ne!(t.network_id, mainnet.network_id);
    assert_ne!(t.network_magic, mini.network_magic);
    assert_ne!(t.network_magic, mainnet.network_magic);

    // The other names behave exactly as before.
    assert_eq!(NetworkParams::by_name("mini").unwrap().name, "mini");
    assert_eq!(NetworkParams::by_name("mainnet").unwrap().name, "mainnet");
    assert!(NetworkParams::by_name("devnet").is_err());
}

#[test]
fn two_independently_constructed_testnet_profiles_are_identical() {
    // No runtime entropy anywhere: name lookup, direct construction and a
    // second direct construction are byte-for-byte equal, committee included.
    let a = NetworkParams::testnet();
    let b = NetworkParams::by_name("testnet").unwrap();
    let c = NetworkParams::testnet();
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a.genesis_validators, b.genesis_validators);
    assert_eq!(a.genesis_validators.len(), 4);

    // The keys themselves are a pure function of their constant seeds.
    let k1: Vec<BlsPublicKey> = testnet_committee_secrets()
        .iter()
        .map(|sk| sk.public_key())
        .collect();
    let k2: Vec<BlsPublicKey> = testnet_committee_secrets()
        .iter()
        .map(|sk| sk.public_key())
        .collect();
    assert_eq!(k1, k2);

    // And two managers built from separate constructions see the same world.
    let f1 = FinalityManager::new(&a);
    let f2 = FinalityManager::new(&b);
    assert_eq!(f1.committee_len(), f2.committee_len());
    assert_eq!(f1.activation_height(), f2.activation_height());
}

#[test]
fn testnet_declares_a_four_key_committee_quorum_three_interval_ten_and_activation_twenty() {
    let t = NetworkParams::testnet();
    assert_eq!(t.genesis_validators.len(), 4, "small fixed committee");
    assert!(
        t.genesis_validators.windows(2).all(|w| w[0].0 < w[1].0),
        "the committee is canonically sorted and duplicate-free"
    );
    // ceil(4 × 6667 / 10000) = 3 — the existing rule, not a new one.
    assert_eq!(
        ValidatorSet::new(t.genesis_validators.clone()).quorum_size(),
        3
    );
    assert_eq!(t.checkpoint_interval_blocks, 10);
    assert_eq!(
        t.finality_activation_height, 20,
        "explicit activation height"
    );
    assert_eq!(
        t.finality_activation_height % t.checkpoint_interval_blocks,
        0
    );

    // Depth-only profiles stay depth-only.
    assert_eq!(NetworkParams::mini().finality_activation_height, 0);
    let mainnet = NetworkParams::mainnet();
    assert_eq!(mainnet.finality_activation_height, 100);
    assert_eq!(
        mainnet.genesis_validators.len(),
        21,
        "mainnet carries the Decision 27 bootstrap committee"
    );
    assert_eq!(
        ValidatorSet::new(mainnet.genesis_validators.clone()).quorum_size(),
        15
    );
    assert!(mainnet.l2_settlement_validators.is_empty());

    // Config-time guards: an activation that could never fire is refused
    // rather than silently inert.
    let mut off_grid = t.clone();
    off_grid.finality_activation_height = 21;
    assert!(off_grid.validate().is_err());
}

// ---------------------------------------------------------------------------
// Decision 12 — binding activation
// ---------------------------------------------------------------------------

#[test]
fn an_observed_certificate_below_the_activation_height_never_binds() {
    let mut chain = chain_to(12);
    let cp = signed(10, chain.block_hash_at(10).unwrap(), &[0, 1, 2]);
    apply(&mut chain, &cp).unwrap();

    assert!(
        chain.finality().is_observed(10),
        "observation still happens"
    );
    assert_eq!(chain.finality().binding_finalized_height(), 0);
    assert_eq!(
        chain.finalized_point(),
        None,
        "nothing to persist, nothing binding"
    );
    assert_eq!(
        chain.finalized_height(),
        0,
        "depth rule on a 12-block chain"
    );
}

#[test]
fn a_valid_certificate_binds_at_and_after_the_activation_height() {
    let mut chain = chain_to(24);

    // The rung below activation: observed only.
    let cp10 = signed(10, chain.block_hash_at(10).unwrap(), &[0, 1, 2]);
    apply(&mut chain, &cp10).unwrap();
    assert_eq!(chain.finality().binding_finalized_height(), 0);

    // The activation rung: canonical, quorum (exactly 3 of 4), monotonic.
    let h20 = chain.block_hash_at(20).unwrap();
    let cp20 = signed(20, h20, &[0, 1, 2]);
    apply(&mut chain, &cp20).unwrap();
    assert_eq!(chain.finality().binding_finalized_height(), 20);
    assert_eq!(chain.finalized_point(), Some((20, h20)));
    // Stronger of depth (24 − 20 = 4) and binding (20).
    assert_eq!(chain.finalized_height(), 20);
    assert!(chain.finality().is_finalized(20));
    assert!(chain.finality().is_finalized(19));
    assert!(!chain.finality().is_finalized(21));
}

#[test]
fn fresh_mainnet_activates_finality_with_the_bootstrap_committee_at_height_100() {
    let params = NetworkParams::mainnet();
    assert_eq!(params.genesis_validators.len(), 21);
    assert_eq!(
        ValidatorSet::new(params.genesis_validators.clone()).quorum_size(),
        15
    );

    let mut chain = Chain::new(params.clone()).unwrap();
    let addr = miner();
    for h in 1..=100u64 {
        let b = chain
            .mine_block(
                addr,
                vec![],
                jnt_core::block::GENESIS_TIMESTAMP_MS + h * 600_000,
            )
            .unwrap();
        chain.submit(b).unwrap();
    }

    let h100 = chain.block_hash_at(100).unwrap();
    let cp = signed_with(
        &mainnet_committee(),
        CheckpointPayload {
            height: 100,
            block_hash: h100,
            network_id: "jounit/mainnet".into(),
            epoch: 1,
        },
        &(0usize..15).collect::<Vec<_>>(),
    );
    apply(&mut chain, &cp).unwrap();

    assert_eq!(chain.finality().binding_finalized_height(), 100);
    assert_eq!(chain.finalized_point(), Some((100, h100)));
    assert!(chain.finality().is_finalized(100));
}

// ---------------------------------------------------------------------------
// Decision 12/14 — conflict protection: every listed attack fails closed
// ---------------------------------------------------------------------------

#[test]
fn insufficient_quorum_is_refused() {
    let mut chain = chain_to(24);
    let cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1]);
    let err = refused(&mut chain, &cp, "sub-quorum");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointQuorumShort {
            have: 2,
            need: 3
        })
    ));
}

#[test]
fn a_forged_aggregate_is_refused() {
    let mut chain = chain_to(24);
    let mut cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    cp.aggregate_sig = BlsSignature([0u8; 96]);
    let err = refused(&mut chain, &cp, "forged aggregate");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointBadSignature)
    ));
}

#[test]
fn a_certificate_signed_by_a_foreign_committee_is_refused() {
    // Right shape, right network, wrong keys: clause 5 must catch it.
    let mut chain = chain_to(24);
    let cp = signed_with(
        &foreign_committee(),
        payload(20, chain.block_hash_at(20).unwrap()),
        &[0, 1, 2],
    );
    let err = refused(&mut chain, &cp, "foreign committee");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointBadSignature)
    ));
}

#[test]
fn a_certificate_for_another_network_is_refused() {
    let mut chain = chain_to(24);
    let mut cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    cp.payload.network_id = "jounit/mainnet".into();
    let err = refused(&mut chain, &cp, "wrong network");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointWrongSet { .. })
    ));
}

#[test]
fn a_signer_count_that_cannot_match_its_bitmap_is_refused() {
    // A bitmap is a bitset: it cannot *encode* a duplicate signer, so a
    // claimed count above the popcount is the duplicate's only representation
    // — and clause 3b refuses it before anything else can act on it.
    let mut chain = chain_to(24);
    let mut cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    cp.signer_count = 4; // bitmap has exactly 3 bits set
    let err = refused(&mut chain, &cp, "duplicate signer claim");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointCountMismatch {
            bitmap_popcount: 3,
            claimed: 4
        })
    ));
}

#[test]
fn a_signer_bit_outside_the_committee_is_refused() {
    // Bit 4 names a fifth validator in a four-key set: a non-validator signer.
    let mut chain = chain_to(24);
    let mut cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    cp.signer_bitmap = vec![0b0001_0111]; // bits 0, 1, 2 and the phantom 4
    cp.signer_count = 4;
    let err = refused(&mut chain, &cp, "non-validator signer");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointBadBitmap { .. })
    ));
}

#[test]
fn a_stale_certificate_for_a_old_height_is_refused() {
    let mut chain = chain_to(24);
    let cp20 = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    apply(&mut chain, &cp20).unwrap();

    // A perfectly valid certificate for height 10 arrives after 20 was accepted.
    let cp10 = signed(10, chain.block_hash_at(10).unwrap(), &[0, 1, 2]);
    let err = refused(&mut chain, &cp10, "stale height");
    assert!(matches!(
        err,
        FinalityError::NotMonotonic {
            height: 10,
            accepted: 20
        }
    ));
}

#[test]
fn a_future_certificate_is_refused() {
    // Chain tip is 24; height 30 has no canonical block to bind to.
    let mut chain = chain_to(24);
    let cp = signed(30, [0xEE; 64], &[0, 1, 2]);
    let err = refused(&mut chain, &cp, "future height");
    assert!(matches!(err, FinalityError::NotCanonical { height: 30 }));
}

#[test]
fn a_certificate_for_a_non_canonical_block_is_refused() {
    // Valid quorum, valid epoch, valid network — but the hash names no block
    // this chain holds at height 5, and nothing is retained to conflict with.
    let mut chain = chain_to(24);
    let cp = signed(5, [0xAB; 64], &[0, 1, 2]);
    let err = refused(&mut chain, &cp, "non-canonical block");
    assert!(matches!(err, FinalityError::NotCanonical { height: 5 }));
}

#[test]
fn a_replayed_certificate_is_refused_without_evidence() {
    let mut chain = chain_to(24);
    let cp = signed(20, chain.block_hash_at(20).unwrap(), &[0, 1, 2]);
    apply(&mut chain, &cp).unwrap();

    let err = refused(&mut chain, &cp, "replay");
    assert!(matches!(
        err,
        FinalityError::NotMonotonic {
            height: 20,
            accepted: 20
        }
    ));
    assert!(
        chain.finality().evidence().is_empty(),
        "a replay is not equivocation"
    );
    assert_eq!(chain.finality().binding_finalized_height(), 20);
}

#[test]
fn a_malformed_certificate_is_refused() {
    // Codec level: arbitrary bytes never become a certificate.
    assert!(Checkpoint::deserialize(&[0xFF, 0x00, 0x01]).is_err());
    assert!(Checkpoint::deserialize(&[]).is_err());

    // Structure level: an empty bitmap cannot decode against a four-key set.
    let mut chain = chain_to(24);
    let cp = Checkpoint {
        payload: payload(20, chain.block_hash_at(20).unwrap()),
        aggregate_sig: BlsSignature([0u8; 96]),
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
    };
    let err = refused(&mut chain, &cp, "empty bitmap");
    assert!(matches!(
        err,
        FinalityError::InvalidCertificate(ValidatorError::CheckpointBadBitmap { .. })
    ));
}

#[test]
fn a_conflicting_certificate_is_refused_and_never_finalizes_both_hashes() {
    let mut chain = chain_to(24);
    let h20 = chain.block_hash_at(20).unwrap();
    let a = signed(20, h20, &[0, 1, 2]);
    apply(&mut chain, &a).unwrap();
    assert_eq!(chain.finalized_point(), Some((20, h20)));

    // Anotherwise-valid certificate for a *different* hash at the same height.
    let conflicting: Hash512 = [0xCD; 64];
    let b = signed(20, conflicting, &[0, 1, 2]);
    let before_evidence = chain.finality().evidence().len();
    let err = refused(&mut chain, &b, "conflicting finality");
    assert!(matches!(
        err,
        FinalityError::ConflictingFinality {
            height: 20,
            finalized,
            conflicting: got
        } if finalized == h20 && got == conflicting
    ));

    // Fail closed: the finalized point did not move and never will to the
    // other hash.
    assert_eq!(chain.finalized_point(), Some((20, h20)));
    assert_eq!(
        chain.finality().evidence().len(),
        before_evidence + 1,
        "the conflict is detected and retained as evidence"
    );

    // And the evidence is the canonical, arrival-order-independent form.
    let ev = &chain.finality().evidence()[before_evidence];
    assert_eq!(
        ev.offender,
        committee()[0].1,
        "first common signer, key order"
    );
    let (first, second) = if a.payload.serialize() <= b.payload.serialize() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    assert_eq!(
        Some(ev.clone()),
        equivocation_evidence(&ev.offender, first, second),
        "evidence hashes exactly the two conflicting payloads"
    );
    assert_ne!(ev.first, ev.second, "the payloads genuinely conflict");
}

// ---------------------------------------------------------------------------
// Decision 12 — reorg protection (the critical consensus test)
// ---------------------------------------------------------------------------

#[test]
fn before_activation_a_reorg_crossing_an_observed_checkpoint_still_applies() {
    let mut chain = chain_to(12);
    let observed = chain.block_hash_at(10).unwrap();
    let cp = signed(10, observed, &[0, 1, 2]);
    apply(&mut chain, &cp).unwrap();
    assert!(chain.finality().is_observed(10));
    assert_eq!(chain.finality().binding_finalized_height(), 0);

    // A heavier rival sharing only 1..=5, diverging at 6 — below the observed
    // checkpoint. With no activation, depth-only finality (12 − 20 = 0) lets it
    // through, exactly as before M5.
    let addr = miner();
    let mut rival = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=5u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 6..=18u64 {
        let b = rival.mine_block(addr, vec![], ts(h, 7)).unwrap();
        rival.submit(b).unwrap();
    }
    assert!(rival.total_work() > chain.total_work());

    for h in 6..=18u64 {
        chain.submit(rival.block_at(h).unwrap().clone()).unwrap();
    }
    assert_eq!(
        chain.height(),
        18,
        "the heavier branch must win pre-activation"
    );
    assert_ne!(chain.block_hash_at(10).unwrap(), observed);
    assert_eq!(chain.finality().binding_finalized_height(), 0);
    chain.verify_canonical_chain().unwrap();
}

#[test]
fn a_reorg_forking_at_or_below_the_finalized_height_is_rejected() {
    let mut chain = chain_to(24);
    let h20 = chain.block_hash_at(20).unwrap();
    apply(&mut chain, &signed(20, h20, &[0, 1, 2])).unwrap();
    assert_eq!(chain.finalized_height(), 20);
    let tip_before = chain.tip_hash();

    let addr = miner();

    // Rival 1: diverges at 16 — strictly *below* the finalized checkpoint, so
    // adopting it would rewrite finalized heights 16..=20.
    let mut rival = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=15u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 16..=30u64 {
        let b = rival.mine_block(addr, vec![], ts(h, 7)).unwrap();
        rival.submit(b).unwrap();
    }
    assert!(rival.total_work() > chain.total_work());
    let mut refused_count = 0;
    for h in 16..=30u64 {
        if let Err(e) = chain.submit(rival.block_at(h).unwrap().clone()) {
            assert!(
                matches!(
                    e,
                    Error::ReorgWouldCrossFinality {
                        finalized_height: 20
                    }
                ),
                "unexpected rejection: {e}"
            );
            refused_count += 1;
        }
    }
    assert!(
        refused_count > 0,
        "the crossing reorg must actually be attempted"
    );

    // Rival 2: diverges *at* the finalized height itself (shares 1..=19),
    // rewriting height 20 — the exact boundary must refuse too.
    let mut rival2 = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=19u64 {
        rival2.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 20..=30u64 {
        let b = rival2.mine_block(addr, vec![], ts(h, 13)).unwrap();
        rival2.submit(b).unwrap();
    }
    for h in 20..=30u64 {
        if let Err(e) = chain.submit(rival2.block_at(h).unwrap().clone()) {
            assert!(
                matches!(e, Error::ReorgWouldCrossFinality { .. }),
                "unexpected rejection: {e}"
            );
        }
    }

    assert_eq!(
        chain.height(),
        24,
        "tip must not move across finalized history"
    );
    assert_eq!(chain.tip_hash(), tip_before);
    assert_eq!(
        chain.block_hash_at(20).unwrap(),
        h20,
        "the finalized block is untouched by either rival"
    );
    assert_eq!(chain.finalized_point(), Some((20, h20)));
    chain.verify_canonical_chain().unwrap();
}

#[test]
fn a_reorg_forking_above_the_finalized_height_is_allowed() {
    let mut chain = chain_to(24);
    let h20 = chain.block_hash_at(20).unwrap();
    apply(&mut chain, &signed(20, h20, &[0, 1, 2])).unwrap();

    // Rival shares everything through the finalized checkpoint and forks at
    // 21, then climbs past the tip. Fork point 21 > 20: otherwise-valid, so it
    // must be adopted.
    let addr = miner();
    let mut rival = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=20u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 21..=28u64 {
        let b = rival.mine_block(addr, vec![], ts(h, 7)).unwrap();
        rival.submit(b).unwrap();
    }
    let rival_tip = rival.tip_hash();
    assert!(rival.total_work() > chain.total_work());
    let old_21 = chain.block_hash_at(21).unwrap();

    for h in 21..=28u64 {
        chain.submit(rival.block_at(h).unwrap().clone()).unwrap();
    }

    assert_eq!(chain.height(), 28, "the heavier branch above finality wins");
    assert_eq!(chain.tip_hash(), rival_tip);
    assert_eq!(
        chain.block_hash_at(20).unwrap(),
        h20,
        "history through the finalized checkpoint is byte-identical"
    );
    assert_ne!(
        chain.block_hash_at(21).unwrap(),
        old_21,
        "21+ genuinely forked"
    );
    assert_eq!(
        chain.finalized_point(),
        Some((20, h20)),
        "finality itself is unmoved"
    );
    chain.verify_canonical_chain().unwrap();
}

// ---------------------------------------------------------------------------
// Decision 14 — equivocation evidence
// ---------------------------------------------------------------------------

#[test]
fn conflicting_certificates_produce_order_independent_evidence() {
    let params = NetworkParams::testnet();
    let a = signed_with(&committee(), payload(20, [0xA1; 64]), &[0, 1, 2]);
    let b = signed_with(&committee(), payload(20, [0xB2; 64]), &[0, 1, 2]);

    // Node 1 sees A, then B. Node 2 sees B, then A. Each refuses the second
    // and retains evidence.
    let mut m1 = FinalityManager::new(&params);
    m1.accept(&a, Some(a.payload.block_hash), &RealBls).unwrap();
    assert!(matches!(
        m1.accept(&b, Some(a.payload.block_hash), &RealBls),
        Err(FinalityError::ConflictingFinality { .. })
    ));

    let mut m2 = FinalityManager::new(&params);
    m2.accept(&b, Some(b.payload.block_hash), &RealBls).unwrap();
    assert!(matches!(
        m2.accept(&a, Some(b.payload.block_hash), &RealBls),
        Err(FinalityError::ConflictingFinality { .. })
    ));

    assert_eq!(m1.evidence().len(), 1);
    assert_eq!(
        m1.evidence(),
        m2.evidence(),
        "evidence must not depend on which certificate arrived first"
    );
    let ev = &m1.evidence()[0];
    assert_eq!(ev.offender, committee()[0].1);
    assert_ne!(ev.first, ev.second);
    // Nothing was punished, and only one record exists despite two attempts.
    assert_eq!(m1.evidence().len(), 1);
}

#[test]
fn non_conflicting_checkpoints_produce_no_evidence() {
    let params = NetworkParams::testnet();
    let mut fm = FinalityManager::new(&params);

    let a = signed_with(&committee(), payload(10, [0x01; 64]), &[0, 1, 2]);
    fm.accept(&a, Some(a.payload.block_hash), &RealBls).unwrap();
    let b = signed_with(&committee(), payload(20, [0x02; 64]), &[0, 1, 2]);
    fm.accept(&b, Some(b.payload.block_hash), &RealBls).unwrap();

    // Replay of a: same payload — not equivocation, just a repeat.
    assert!(matches!(
        fm.accept(&a, Some(a.payload.block_hash), &RealBls),
        Err(FinalityError::NotMonotonic { .. })
    ));
    // A different signer set over the *same* payload at height 20: still the
    // same statement, so still not equivocation.
    let c = signed_with(&committee(), payload(20, [0x02; 64]), &[1, 2, 3]);
    assert!(matches!(
        fm.accept(&c, Some(c.payload.block_hash), &RealBls),
        Err(FinalityError::NotMonotonic { .. })
    ));
    // A brand-new valid height: no conflict anywhere.
    let d = signed_with(&committee(), payload(30, [0x03; 64]), &[0, 1, 3]);
    fm.accept(&d, Some(d.payload.block_hash), &RealBls).unwrap();

    assert!(
        fm.evidence().is_empty(),
        "no false-positive evidence from legitimate traffic"
    );
}

#[test]
fn evidence_retention_is_bounded() {
    // The structural bound, with the mock verifier so a thousand fabricated
    // quorums cost nothing: a hostile peer streaming conflicting certificates
    // grows memory up to the cap and then not at all.
    let params = NetworkParams::testnet();
    let mut fm = FinalityManager::new(&params);
    let base = Checkpoint {
        payload: payload(20, [0u8; 64]),
        aggregate_sig: BlsSignature([7u8; 96]),
        signer_bitmap: vec![0b0000_0111],
        signer_count: 3,
        pq_sidecar: Vec::new(),
    };
    fm.accept(&base, Some(base.payload.block_hash), &MockBls)
        .unwrap();

    let attempts = MAX_EQUIVOCATION_EVIDENCE + 5;
    for i in 1..=attempts {
        let mut h = [0u8; 64];
        h[0] = i as u8;
        h[1] = (i >> 8) as u8;
        let cp = Checkpoint {
            payload: payload(20, h),
            aggregate_sig: BlsSignature([7u8; 96]),
            signer_bitmap: vec![0b0000_0111],
            signer_count: 3,
            pq_sidecar: Vec::new(),
        };
        let err = fm
            .accept(&cp, Some(base.payload.block_hash), &MockBls)
            .expect_err("every distinct hash at height 20 conflicts");
        assert!(matches!(err, FinalityError::ConflictingFinality { .. }));
    }
    assert_eq!(
        fm.evidence().len(),
        MAX_EQUIVOCATION_EVIDENCE,
        "evidence is capped: {attempts} conflicts produced {} records",
        fm.evidence().len()
    );
    assert_eq!(
        fm.binding_finalized_height(),
        20,
        "finality unmoved throughout"
    );
}

// ---------------------------------------------------------------------------
// Step 3 — finality survives restart deterministically
// ---------------------------------------------------------------------------

#[test]
fn the_finalized_point_restores_onto_the_exact_canonical_chain_only() {
    let live = {
        let mut chain = chain_to(24);
        let h20 = chain.block_hash_at(20).unwrap();
        apply(&mut chain, &signed(20, h20, &[0, 1, 2])).unwrap();
        chain
    };
    let point = live.finalized_point().expect("checkpoint finalized at 20");

    // "Restart": a fresh chain rebuilt from the same stored blocks.
    let mut reborn = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=24u64 {
        reborn.submit(live.block_at(h).unwrap().clone()).unwrap();
    }
    assert_eq!(
        reborn.finalized_point(),
        None,
        "a fresh chain derives nothing until the point is restored"
    );

    // A forged or stale row cannot finalize what the chain does not hold.
    assert!(!reborn.restore_finality(point.0, [0x99; 64]), "wrong hash");
    assert!(!reborn.restore_finality(99, point.1), "beyond the tip");
    assert_eq!(reborn.finalized_point(), None);

    // The exact claim installs, and equals the pre-restart point.
    assert!(reborn.restore_finality(point.0, point.1));
    assert_eq!(reborn.finalized_point(), Some(point));
    assert_eq!(
        reborn.finality().binding_finalized_height(),
        live.finality().binding_finalized_height(),
        "finalized height/hash before restart == after restart"
    );

    // The restored point is not decorative: it gates reorgs identically.
    let addr = miner();
    let mut rival = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=15u64 {
        rival.submit(live.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 16..=30u64 {
        let b = rival.mine_block(addr, vec![], ts(h, 7)).unwrap();
        rival.submit(b).unwrap();
    }
    let mut crossed = false;
    for h in 16..=30u64 {
        if let Err(e) = reborn.submit(rival.block_at(h).unwrap().clone()) {
            if matches!(e, Error::ReorgWouldCrossFinality { .. }) {
                crossed = true;
            }
        }
    }
    assert!(
        crossed,
        "restored finality must refuse the crossing reorg too"
    );
    assert_eq!(reborn.finalized_point(), Some(point));
}

#[test]
fn two_chains_accepting_the_same_certificates_reach_the_same_finality_state() {
    // Fresh replay of certificates == incremental application of them: the
    // manager is a pure function of (params, canonical blocks, certificate
    // sequence).
    let mut c1 = chain_to(24);
    let mut c2 = {
        let mut c = Chain::new(NetworkParams::testnet()).unwrap();
        let addr = miner();
        for h in 1..=24u64 {
            let b = c.mine_block(addr, vec![], ts(h, 0)).unwrap();
            c.submit(b).unwrap();
        }
        c
    };
    assert_eq!(c1.tip_hash(), c2.tip_hash(), "deterministic fixture chains");

    for chain in [&mut c1, &mut c2] {
        let h10 = chain.block_hash_at(10).unwrap();
        let h20 = chain.block_hash_at(20).unwrap();
        apply(chain, &signed(10, h10, &[0, 1, 2])).unwrap();
        apply(chain, &signed(20, h20, &[0, 1, 2])).unwrap();
        let cp30 = signed(30, [0xEE; 64], &[0, 1, 2]);
        let _ = apply(chain, &cp30); // same refusal on both: future height
    }

    assert_eq!(c1.finalized_point(), c2.finalized_point());
    assert_eq!(
        c1.finality().accepted_height(),
        c2.finality().accepted_height()
    );
    assert_eq!(c1.finality().binding_finalized_height(), 20);
    assert_eq!(c2.finality().binding_finalized_height(), 20);
}
