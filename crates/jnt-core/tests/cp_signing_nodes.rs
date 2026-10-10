//! Checkpoint signing, verified across nodes (M5, Decisions 12–14).
//!
//! The signing unit tests prove what a produced certificate looks like. This file
//! proves the properties that only exist with more than one participant, which is
//! the entire point of a quorum:
//!
//! 1. a quorum signed over the chain's own canonical hash finalizes it;
//! 2. a committee that is not the derived one produces signatures that fail;
//! 3. fewer than quorum validators fails closed;
//! 4. two conflicting certificates at one height cannot both finalize — the
//!    second is refused and recorded as equivocation;
//! 5. a node that signs, restarts from stored blocks, and re-signs reaches the
//!    same certificate byte for byte.
//!
//! Every case goes through `FinalityManager::accept` with `RealBls`, so these are
//! real pairing checks rather than structural asserts. In-process rather than
//! two live nodes because the property under test is "a second independent
//! verifier accepts or refuses these bytes", and a second `FinalityManager` over
//! the same chain is exactly that.

use jnt_core::bls::SecretKey;
use jnt_core::bls_checkpoint::BlsPublicKey;
use jnt_core::chain::Chain;
use jnt_core::finality::FinalityManager;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;
use jnt_core::signing::{CheckpointSigner, Committee, ValidatorKey};
use jnt_core::tx::Output;

fn params() -> NetworkParams {
    // `testnet`, where binding finality actually activates (height 20). The
    // finality assertions below need a profile that activates, and mining 25
    // difficulty-1 blocks is fast enough that this is not a slow test.
    NetworkParams::testnet()
}

/// Mine to here, then a binding checkpoint can be produced at an epoch boundary
/// at or after the activation height.
const MINE_TO: u64 = 25;

fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn key(seed: u8, net: &str) -> ValidatorKey {
    ValidatorKey::new(SecretKey::derive(&[seed; 32]).unwrap(), net)
}

fn committee(seeds: impl IntoIterator<Item = u8>, net: &str) -> Committee {
    let mut c = Committee::new();
    for s in seeds {
        c.add(key(s, net)).unwrap();
    }
    c
}

/// A verifier for a node whose committee is `keys` — the equivalent of a peer
/// that derived the same set from the same canonical bonds.
fn verifier(keys: &[BlsPublicKey]) -> FinalityManager {
    let mut m = FinalityManager::new(&params());
    m.set_keys(keys.to_vec());
    m
}

/// Mine to `n` and return the chain with its canonical tip hash at that height.
fn chain_to(n: u64) -> (Chain, Hash) {
    let mut chain = Chain::new(params()).unwrap();
    let miner = jnt_core::wallet::Wallet::from_private_key_bytes(&[7u8; 32], "cp-signing")
        .unwrap()
        .address()
        .unwrap();
    for h in 1..=n {
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let tip = chain.tip_hash();
    (chain, tip)
}

// ---------------------------------------------------------------------------
// 1. A quorum finalizes
// ---------------------------------------------------------------------------

/// **The happy path, through a second independent verifier.** The signer side
/// produces a certificate over the chain's own tip, and a *different*
/// `FinalityManager` holding the same committee accepts it. Two objects because
/// the property is "a peer agrees", not "the producer is self-consistent".
#[test]
fn a_quorum_certificate_finalizes_on_an_independent_verifier() {
    let p = params();
    let net = p.network_id.clone();
    let committee = committee(1..=4u8, &net);
    let (chain, tip) = chain_to(MINE_TO);

    let signer = CheckpointSigner::new(&net, p.checkpoint_interval_blocks);
    let cp = signer.sign(MINE_TO, tip, &committee).unwrap().unwrap();

    // The verifier is a separate instance, with keys set from the same committee
    // — exactly a peer that derived its set from the same canonical bonds.
    let mut peer = verifier(&committee.public_keys());
    peer.accept(&cp, Some(tip), &jnt_core::bls::RealBls)
        .expect("an independent verifier must accept a quorum certificate");

    // And the node's own finality layer agrees, which is what makes it *binding*
    // rather than merely observed.
    let mut m = FinalityManager::new(&p);
    m.set_keys(committee.public_keys());
    m.accept(&cp, Some(tip), &jnt_core::bls::RealBls).unwrap();
    assert!(m.is_finalized(MINE_TO), "a valid certificate finalizes its height");
    assert_eq!(m.binding_finalized_hash(), tip);
    let _ = chain;
}

// ---------------------------------------------------------------------------
// 2. A stranger's committee fails
// ---------------------------------------------------------------------------

/// **The committee must be the derived one.** Signatures from a set nobody
/// bonded are not merely weaker, they are refused: the bitmap indexes into the
/// *verifier's* order, so a foreign committee's bitmap names strangers.
#[test]
fn a_committee_that_is_not_the_derived_one_is_refused() {
    let p = params();
    let net = p.network_id.clone();
    let signers = committee(1..=4u8, &net);
    let (_chain, tip) = chain_to(20);

    let cp = CheckpointSigner::new(&net, p.checkpoint_interval_blocks)
        .sign(20, tip, &signers)
        .unwrap()
        .unwrap();

    // The node's actual committee is a different four validators.
    let honest = committee(5..=8u8, &net);
    let mut peer = verifier(&honest.public_keys());
    let err = peer
        .accept(&cp, Some(tip), &jnt_core::bls::RealBls)
        .expect_err("foreign signers must be refused");
    assert!(
        err.to_string().contains("signature") || err.to_string().contains("signer"),
        "the refusal must name the reason: {err}"
    );
    assert!(!peer.is_finalized(20), "nothing was accepted");
}

// ---------------------------------------------------------------------------
// 3. Below quorum fails closed
// ---------------------------------------------------------------------------

/// **The "validators are offline" case**, which is the one that has to be safe
/// without being punitive. Three of five is a perfectly valid set of signatures;
/// it is simply not enough. Nothing is accepted and nothing is recorded, so a
/// partially-reachable committee cannot stall the chain either.
#[test]
fn a_short_of_quorum_certificate_is_refused_and_records_nothing() {
    let p = params();
    let net = p.network_id.clone();
    let present = committee(1..=3u8, &net);
    let full = committee(1..=5u8, &net);
    let (_chain, tip) = chain_to(20);

    let cp = CheckpointSigner::new(&net, p.checkpoint_interval_blocks)
        .sign(20, tip, &present)
        .unwrap()
        .unwrap();

    let mut peer = verifier(&full.public_keys());
    peer.accept(&cp, Some(tip), &jnt_core::bls::RealBls)
        .expect_err("3 of 5 is below quorum");
    assert!(!peer.is_finalized(20));
    assert!(peer.evidence().is_empty(), "a short certificate is not an attack");
}

// ---------------------------------------------------------------------------
// 4. Two conflicting certificates
// ---------------------------------------------------------------------------

/// **Equivocation.** Two quorum certificates naming different blocks at the same
/// height. The first finalizes; the second must be refused *and* leave evidence
/// naming the signers, so a double-signing validator is provable later rather
/// than merely observed. This is the path that feeds the M2 slash vault.
#[test]
fn two_conflicting_certificates_cannot_both_finalize() {
    let p = params();
    let net = p.network_id.clone();
    let committee = committee(1..=4u8, &net);
    let (mut chain, _) = chain_to(MINE_TO);

    // Two blocks at the same height: the honest one, and a rival the validator
    // also signed. A validator that signs both is equivocating.
    let miner = jnt_core::wallet::Wallet::from_private_key_bytes(&[7u8; 32], "cp-signing")
        .unwrap()
        .address()
        .unwrap();
    let honest = chain.mine_block(miner, vec![], ts(MINE_TO + 1)).unwrap();
    chain.submit(honest.clone()).unwrap();

    // A rival block at the same height on a *lighter* branch: the competing chain
    // shares the prefix up to one block below the tip, so it has strictly less
    // cumulative work and cannot win fork choice.
    let mut fork = Chain::new(p.clone()).unwrap();
    for h in 1..MINE_TO {
        let b = fork.mine_block(miner, vec![], ts(h)).unwrap();
        fork.submit(b).unwrap();
    }
    let rival = fork.mine_block(miner, vec![], ts(MINE_TO + 1)).unwrap();
    chain.submit(rival.clone()).unwrap();
    // The honest block is the canonical tip, so a certificate naming the rival
    // is a certificate for a block this node does not hold.
    assert_eq!(
        chain.tip_hash(),
        honest.block_hash(),
        "the honest chain must stay canonical for the conflict to be meaningful"
    );

    let signer = CheckpointSigner::new(&net, p.checkpoint_interval_blocks);
    let first = signer.sign(MINE_TO + 1, honest.block_hash(), &committee).unwrap().unwrap();
    let second = signer.sign(MINE_TO + 1, rival.block_hash(), &committee).unwrap().unwrap();

    let mut peer = verifier(&committee.public_keys());
    peer.accept(&first, Some(honest.block_hash()), &jnt_core::bls::RealBls)
        .expect("the honest certificate is accepted");
    assert!(peer.is_finalized(MINE_TO + 1));

    let err = peer
        .accept(&second, Some(honest.block_hash()), &jnt_core::bls::RealBls)
        .expect_err("a conflicting certificate must be refused");
    // It is a conflict, not a stale replay: the height is already finalized to a
    // different hash, and the evidence names the signers.
    assert!(
        err.to_string().contains("conflict") || !peer.evidence().is_empty(),
        "the refusal must be classifiable as equivocation: {err}"
    );
    assert!(
        !peer.evidence().is_empty(),
        "the double-signing validators must be provable, not merely observed"
    );
}

// ---------------------------------------------------------------------------
// 5. Restart reaches the same bytes
// ---------------------------------------------------------------------------

/// **Determinism across a restart.** A node that signs, is rebuilt from stored
/// blocks, and signs again must produce a certificate identical byte for byte.
/// Signing that depended on wall-clock or iteration order would make the same
/// committee disagree with itself after a restart, which no amount of
/// re-verification can repair.
#[test]
fn signing_is_identical_after_a_restart_from_stored_blocks() {
    let p = params();
    let net = p.network_id.clone();
    let committee = committee(1..=4u8, &net);
    let (chain, tip) = chain_to(20);

    let signer = CheckpointSigner::new(&net, p.checkpoint_interval_blocks);
    let before = signer.sign(20, tip, &committee).unwrap().unwrap();

    // "Restart": a fresh chain rebuilt by replaying the same blocks, which is
    // what `jnt-node`'s load path does.
    let mut rebuilt = Chain::new(p.clone()).unwrap();
    for h in 1..=20u64 {
        let b = chain.block_at(h).unwrap();
        rebuilt.submit(b.clone()).unwrap();
    }
    assert_eq!(rebuilt.tip_hash(), tip, "the replay reached the same tip");

    let after = signer.sign(20, rebuilt.tip_hash(), &committee).unwrap().unwrap();
    assert_eq!(before.serialize(), after.serialize(), "signing must be deterministic");
    assert_eq!(before.signer_bitmap, after.signer_bitmap);
    assert_eq!(before.signer_count, after.signer_count);
    assert_eq!(before.payload.epoch, after.payload.epoch);
}

/// **A missing key is a missing signature, not a partial certificate.** A node
/// whose validator key file was deleted signs nothing for that slot rather than
/// shipping a bitmap with a hole in it, which every peer would refuse and which
/// would leave the operator believing they had participated.
#[test]
fn a_committee_that_lost_a_member_signs_without_it() {
    let p = params();
    let net = p.network_id.clone();
    let full = committee(1..=4u8, &net);
    let three = committee(1..=3u8, &net);
    let (_chain, tip) = chain_to(20);

    let signer = CheckpointSigner::new(&net, p.checkpoint_interval_blocks);
    let whole = signer.sign(20, tip, &full).unwrap().unwrap();
    let partial = signer.sign(20, tip, &three).unwrap().unwrap();

    // Both are well-formed; only the staffing differs, and the bitmap states it.
    assert_eq!(whole.signer_count, 4);
    assert_eq!(partial.signer_count, 3);
    assert_ne!(whole.signer_bitmap, partial.signer_bitmap);
    // And the four-signer one verifies against its own committee, so the
    // difference is quantifiable rather than a silent degradation.
    let mut peer = verifier(&full.public_keys());
    peer.accept(&whole, Some(tip), &jnt_core::bls::RealBls).unwrap();
    assert!(peer.is_finalized(20));
}
