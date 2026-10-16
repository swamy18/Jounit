//! M4 validator-set + finality foundation (Decision 11, SPEC.md §14).
//!
//! These tests pin the properties that make the *committee machinery* real
//! before binding activation: the genesis committee is a pure function of
//! `NetworkParams`; a full-quorum certificate is accepted and a sub-quorum one
//! is not; `mainnet`'s empty committee fails closed; a certificate for another
//! network is refused; and on a profile with no activation height (`mini`),
//! finality stays **non-binding** — a reorg crossing an accepted checkpoint
//! still applies.
//!
//! Binding activation and its reorg-refusal live in `m5_finality.rs`; this file
//! proves the M4 base is unchanged when `finality_activation_height == 0`.

use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
use jnt_core::chain::Chain;
use jnt_core::finality::FinalityManager;
use jnt_core::params::{mini_committee_secrets, NetworkParams};

/// The mini committee as (secret, key) pairs in the set's canonical order.
fn committee() -> Vec<(SecretKey, BlsPublicKey)> {
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

/// Sign `payload` with `indices` into the committee and aggregate.
fn signed(payload: CheckpointPayload, indices: &[usize]) -> Checkpoint {
    let pairs = committee();
    let msg = payload.signing_hash();
    let sigs: Vec<BlsSignature> = indices.iter().map(|&i| pairs[i].0.sign(&msg)).collect();
    let agg = RealBls::aggregate(&sigs).unwrap();
    let n = pairs.len();
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    for &i in indices {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    Checkpoint {
        payload,
        aggregate_sig: agg,
        signer_bitmap: bitmap,
        signer_count: indices.len() as u32,
        pq_sidecar: Vec::new(),
    }
}

fn payload(height: u64) -> CheckpointPayload {
    CheckpointPayload {
        height,
        block_hash: [0xAB; 64],
        network_id: "jounit/mini".into(),
        epoch: height / 10,
    }
}

/// Accept a certificate against the payload's own declared block hash, which is
/// all the observation tests need.
#[allow(clippy::result_large_err)]
fn accept(
    fm: &mut FinalityManager,
    cp: &Checkpoint,
) -> Result<(), jnt_core::finality::FinalityError> {
    fm.accept(cp, Some(cp.payload.block_hash), &RealBls)
}

// ---------------------------------------------------------------------------
// Committee derivation
// ---------------------------------------------------------------------------

#[test]
fn mini_carries_a_four_key_committee_and_mainnet_none() {
    let mini = NetworkParams::mini();
    mini.validate().unwrap();
    assert_eq!(mini.genesis_validators.len(), 4);
    assert_eq!(mini.checkpoint_interval_blocks, 10);
    assert_eq!(mini.finality_activation_height, 0, "mini does not activate");

    let main = NetworkParams::mainnet();
    main.validate().unwrap();
    assert!(
        main.genesis_validators.is_empty(),
        "mainnet has no committee yet; an empty set is the honest pre-committee state"
    );
    assert_eq!(main.checkpoint_interval_blocks, 100);
    assert_eq!(main.finality_activation_height, 100);
}

#[test]
fn the_committee_is_deterministic_and_shared_across_nodes() {
    // Two independently built profiles derive the identical set and hash.
    let a = FinalityManager::new(&NetworkParams::mini());
    let b = FinalityManager::new(&NetworkParams::mini());
    let sa = a.epoch_set(3).unwrap();
    let sb = b.epoch_set(3).unwrap();
    assert_eq!(sa.set_hash, sb.set_hash);
    assert_eq!(sa.validators.len(), 4);

    // The hash is epoch-bound: same members, different epoch, different hash.
    let s0 = a.epoch_set(0).unwrap();
    assert_ne!(s0.set_hash, sa.set_hash);
}

// ---------------------------------------------------------------------------
// Observation: quorum
// ---------------------------------------------------------------------------

#[test]
fn a_full_quorum_certificate_is_observed() {
    let params = NetworkParams::mini();
    let mut fm = FinalityManager::new(&params);
    // 4 validators, quorum ceil(4*6667/10000) = 3.
    let cp = signed(payload(10), &[0, 1, 2]);
    accept(&mut fm, &cp).unwrap();
    assert_eq!(fm.accepted_height(), 10);
    assert!(fm.is_observed(10));
    assert!(!fm.is_observed(11));
    // mini does not activate: nothing is binding.
    assert!(!fm.is_finalized(10));
    assert_eq!(fm.binding_finalized_height(), 0);
}

#[test]
fn a_sub_quorum_certificate_is_refused() {
    let params = NetworkParams::mini();
    let mut fm = FinalityManager::new(&params);
    let cp = signed(payload(10), &[0, 1]);
    assert!(accept(&mut fm, &cp).is_err());
    assert_eq!(fm.accepted_height(), 0, "nothing accepted on refusal");
}

#[test]
fn a_forged_signature_is_refused() {
    let params = NetworkParams::mini();
    let mut fm = FinalityManager::new(&params);
    let mut cp = signed(payload(10), &[0, 1, 2]);
    cp.aggregate_sig = BlsSignature([0u8; 96]);
    assert!(accept(&mut fm, &cp).is_err());
    assert_eq!(fm.accepted_height(), 0);
}

#[test]
fn a_certificate_for_another_network_is_refused() {
    let params = NetworkParams::mini();
    let mut fm = FinalityManager::new(&params);
    let mut cp = signed(payload(10), &[0, 1, 2]);
    cp.payload.network_id = "jounit/mainnet".into();
    assert!(accept(&mut fm, &cp).is_err());
    assert_eq!(fm.accepted_height(), 0);
}

#[test]
fn observation_never_moves_backwards() {
    let params = NetworkParams::mini();
    let mut fm = FinalityManager::new(&params);
    accept(&mut fm, &signed(payload(20), &[0, 1, 2])).unwrap();
    assert!(accept(&mut fm, &signed(payload(10), &[0, 1, 2])).is_err());
    assert_eq!(fm.accepted_height(), 20);
}

// ---------------------------------------------------------------------------
// Fail-closed on an empty committee
// ---------------------------------------------------------------------------

#[test]
fn mainnet_with_no_committee_accepts_nothing() {
    let params = NetworkParams::mainnet();
    let mut fm = FinalityManager::new(&params);
    assert_eq!(fm.committee_len(), 0);
    // Even a structurally perfect certificate cannot verify against no keys.
    let cp = Checkpoint {
        payload: CheckpointPayload {
            height: 100,
            block_hash: [0xCD; 64],
            network_id: "jounit/mainnet".into(),
            epoch: 1,
        },
        aggregate_sig: BlsSignature([0x11; 96]),
        signer_bitmap: vec![],
        signer_count: 0,
        pq_sidecar: Vec::new(),
    };
    assert!(accept(&mut fm, &cp).is_err());
    assert_eq!(fm.accepted_height(), 0);
}

// ---------------------------------------------------------------------------
// THE non-binding test (mini activation = 0)
// ---------------------------------------------------------------------------

/// **The rule:** on a profile with no activation height, an accepted checkpoint
/// does not gate chain acceptance.
///
/// A reorg that crosses an accepted checkpoint still applies. If someone ever
/// makes activation fire on a zero-activation profile, this test starts failing
/// — which is the point. `mini` observes; it does not enforce.
#[test]
fn a_reorg_crossing_an_accepted_checkpoint_still_applies() {
    use jnt_core::hash::Address;
    use jnt_core::wallet::Wallet;

    let miner = Wallet::new_random("m4-miner");
    let addr: Address = miner.address().unwrap();
    // Base timestamps on genesis, or the median-timestamp rule clamps a small
    // literal and two branches collapse to identical blocks.
    let ts = |h: u64, bump: u64| jnt_core::block::GENESIS_TIMESTAMP_MS + h * 1_000 + bump;

    // Canonical chain to height 12.
    let mut main = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=12u64 {
        let b = main.mine_block(addr, vec![], ts(h, 0)).unwrap();
        main.submit(b).unwrap();
    }
    let observed = main.block_hash_at(10).unwrap();

    // Accept a checkpoint at height 10 over the real canonical block.
    let cp = signed(
        CheckpointPayload {
            height: 10,
            block_hash: observed,
            network_id: "jounit/mini".into(),
            epoch: 1,
        },
        &[0, 1, 2],
    );
    main.apply_checkpoint(&cp, &RealBls).unwrap();
    assert!(main.finality().is_observed(10));
    assert_eq!(main.finality().binding_finalized_height(), 0);

    // Build a heavier rival that shares blocks 1..=5 and then diverges at
    // height 6 — *below* the accepted height — so adopting it necessarily
    // rewrites the block at height 10.
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=5u64 {
        rival.submit(main.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 6..=18u64 {
        // Distinct timestamps from the canonical chain: same heights, different
        // blocks, all the way through the checkpoint.
        let b = rival.mine_block(addr, vec![], ts(h, 7)).unwrap();
        rival.submit(b).unwrap();
    }
    assert_ne!(
        rival.block_hash_at(10).unwrap(),
        observed,
        "the fixture must actually rewrite the accepted height, or this proves nothing"
    );

    // Submit the rival branch to `main`. With activation 0, nothing enforces the
    // observation, so the reorg applies and `main` follows the heavier chain.
    for h in 6..=18u64 {
        main.submit(rival.block_at(h).unwrap().clone()).unwrap();
    }

    assert_eq!(main.height(), 18, "the heavier branch must win");
    assert_eq!(
        main.block_hash_at(10).unwrap(),
        rival.block_hash_at(10).unwrap(),
        "the reorg crossed the accepted checkpoint: finality is non-binding"
    );
    assert_ne!(main.block_hash_at(10).unwrap(), observed);
}

// ---------------------------------------------------------------------------
// Bounded codec
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_round_trips_through_the_bounded_codec() {
    let cp = signed(payload(10), &[0, 1, 2]);
    let bytes = cp.serialize();
    let back = Checkpoint::deserialize(&bytes).unwrap();
    assert_eq!(back, cp);
}

#[test]
fn an_oversized_payload_length_is_refused() {
    use jnt_core::bls_checkpoint::MAX_CHECKPOINT_PAYLOAD_BYTES;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((MAX_CHECKPOINT_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
    bytes.extend_from_slice(&[0u8; 96]);
    assert!(Checkpoint::deserialize(&bytes).is_err());
}

#[test]
fn an_oversized_signer_bitmap_is_refused() {
    use jnt_core::bls_checkpoint::MAX_SIGNER_BITMAP_BYTES;
    let cp = signed(payload(10), &[0, 1, 2]);
    let mut bytes = cp.payload.serialize();
    let mut body = Vec::new();
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.append(&mut bytes);
    body.extend_from_slice(&[0u8; 96]);
    body.extend_from_slice(&((MAX_SIGNER_BITMAP_BYTES as u32) + 1).to_le_bytes());
    assert!(Checkpoint::deserialize(&body).is_err());
}

#[test]
fn a_signer_count_that_disagrees_with_the_bitmap_is_refused() {
    let mut cp = signed(payload(10), &[0, 1, 2]);
    cp.signer_count = 2; // bitmap has 3 bits set
    let bytes = cp.serialize();
    assert!(Checkpoint::deserialize(&bytes).is_err());
}
