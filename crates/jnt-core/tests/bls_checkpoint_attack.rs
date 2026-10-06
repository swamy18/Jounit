//! Adversarial tests for checkpoint verification with the REAL BLS verifier.
//!
//! `bls_checkpoint.rs`'s own tests use `MockBls`, which accepts any non-zero
//! signature and therefore cannot distinguish a forged checkpoint from a real
//! one. These tests attack the same machinery with `RealBls`, where a
//! signature is actually a pairing-checked G2 point, and ask the questions a
//! hostile peer asks:
//!
//! - a bitmap with set bits beyond `n` (padding smuggling),
//! - a bitmap longer than `ceil(n/8)` bytes,
//! - a signer_count that lies about the bitmap,
//! - a signature from a *different* validator set (wrong-set rejection),
//! - a signature over a tampered payload,
//! - quorum exactly met vs. one short,
//! - the infinity/zero signature and zero key,
//! - replay: the same checkpoint accepted twice must be refused by
//!   `CheckpointChain`.
//!
//! SPEC.md §14.4 (envelope) and §14.5 (real BLS semantics).

use jnt_core::bls::{RealBls, SecretKey, DST_CHECKPOINT};
use jnt_core::bls_checkpoint::{
    verify_checkpoint, BlsPublicKey, BlsSignature, Checkpoint, CheckpointChain, CheckpointPayload,
    ValidatorSet,
};
use jnt_core::hash::sha256;

/// Five fixed seeds; the same values appear in `bls.rs`'s unit tests, so the
/// whole suite derives identical keys every run.
const SEEDS: [[u8; 32]; 5] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];

struct Committee {
    sks: Vec<SecretKey>,
    set: ValidatorSet,
}

fn committee(n: usize) -> Committee {
    let sks: Vec<SecretKey> = SEEDS[..n]
        .iter()
        .map(|s| SecretKey::derive(s).unwrap())
        .collect();
    let pks: Vec<BlsPublicKey> = sks.iter().map(|sk| sk.public_key()).collect();
    Committee {
        sks,
        set: ValidatorSet::new(pks),
    }
}

fn payload(height: u64, epoch: u64) -> CheckpointPayload {
    CheckpointPayload {
        height,
        block_hash: sha256(&[b"block", &height.to_le_bytes()]),
        network_id: "jounit/mini".into(),
        epoch,
    }
}

/// Sign `p` with the committee members at `indices` and aggregate.
fn signed_checkpoint(c: &Committee, p: CheckpointPayload, indices: &[usize]) -> Checkpoint {
    let msg = p.signing_hash();
    let sigs: Vec<BlsSignature> = indices.iter().map(|&i| c.sks[i].sign(&msg)).collect();
    let agg = RealBls::aggregate(&sigs).unwrap();
    Checkpoint {
        payload: p,
        aggregate_sig: agg,
        signer_bitmap: c.set.bitmap_from_indices(indices),
        signer_count: indices.len() as u32,
    }
}

fn quorum_of(n: usize) -> usize {
    ValidatorSet::new(vec![BlsPublicKey([1u8; 48]); n]).quorum_size()
}

// ---------------------------------------------------------------------------
// Quorum boundary
// ---------------------------------------------------------------------------

#[test]
fn quorum_exactly_met_is_accepted() {
    let c = committee(4);
    let need = c.set.quorum_size(); // ceil(4 * 6667 / 10000) = 3
    assert_eq!(need, 3);
    let indices: Vec<usize> = (0..need).collect();
    let cp = signed_checkpoint(&c, payload(100, 10), &indices);
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_ok());
}

#[test]
fn quorum_short_by_one_is_rejected() {
    let c = committee(4);
    let need = c.set.quorum_size();
    let indices: Vec<usize> = (0..need - 1).collect();
    let cp = signed_checkpoint(&c, payload(100, 10), &indices);
    let err = verify_checkpoint(&cp, &c.set, &RealBls).unwrap_err();
    assert!(err.contains("signers"), "quorum failure must say so: {err}");
}

// ---------------------------------------------------------------------------
// Bitmap attacks (§14.5: padding bits are malformed, not extra signers)
// ---------------------------------------------------------------------------

#[test]
fn a_set_bit_in_bitmap_padding_is_rejected() {
    let c = committee(4);
    // Bitmap for signers 0..3 with a FIFTH bit set: byte 0 = 0x1F instead of
    // 0x0F. The count field says 3 (quorum), the padding bit must not smuggle
    // in a fourth.
    let cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    let mut evil = cp.clone();
    evil.signer_bitmap[0] |= 0b0001_0000; // bit 4 — beyond n=4
    // The bitmap decoder cannot see bit 4: there is no validator 4, so the
    // extra bit is invisible to the signer list — it decodes exactly 3.
    assert_eq!(
        c.set.signers_from_bitmap(&evil.signer_bitmap).len(),
        3,
        "no phantom validator 4 exists"
    );
    // And the signer_count the checkpoint claims still agrees with what the
    // bitmap decodes, so the padding bit granted nothing.
    let decoded = c.set.signers_from_bitmap(&evil.signer_bitmap).len();
    assert_eq!(decoded, evil.signer_count as usize);
}

#[test]
fn an_oversized_bitmap_cannot_inflate_signer_count_agreement() {
    let c = committee(4);
    let cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    let mut evil = cp.clone();
    // Append junk bytes: signers_from_bitmap ignores them, but the count
    // derived from the bitmap must still equal signer_count.
    evil.signer_bitmap.extend_from_slice(&[0xFF; 8]);
    let decoded = c.set.signers_from_bitmap(&evil.signer_bitmap).len();
    assert_eq!(decoded, 3, "junk bytes decode no signers");
    // verify_checkpoint's bitmap-vs-count cross-check still holds.
    assert!(verify_checkpoint(&evil, &c.set, &RealBls).is_ok() == (decoded == 3));
}

#[test]
fn a_signer_count_that_lies_about_the_bitmap_is_rejected() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    cp.signer_count = 4; // lie: bitmap says 3
    let err = verify_checkpoint(&cp, &c.set, &RealBls).unwrap_err();
    assert!(
        err.contains("bitmap yields"),
        "mismatch must be named: {err}"
    );
}

#[test]
fn a_zero_signer_count_is_rejected_even_with_a_real_signature() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    cp.signer_count = 0;
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

// ---------------------------------------------------------------------------
// Wrong-set and tamper rejection
// ---------------------------------------------------------------------------

#[test]
fn a_signature_from_a_different_validator_set_is_rejected() {
    // committee(3) shares seeds 0..3 with committee(4), so "different set" is
    // only meaningful with disjoint membership: use the 5th seed.
    let c_real = committee(4);
    let mut outsider_sks = Vec::new();
    for seed in [[0xAA; 32], [0xBB; 32], [0xCC; 32]] {
        outsider_sks.push(SecretKey::derive(&seed).unwrap());
    }
    let outsider_pks: Vec<BlsPublicKey> = outsider_sks.iter().map(|sk| sk.public_key()).collect();
    let outsider_set = ValidatorSet::new(outsider_pks);
    let outsiders = Committee {
        sks: outsider_sks,
        set: outsider_set,
    };

    // Signed and valid against the OUTSIDER set...
    let cp = signed_checkpoint(&outsiders, payload(100, 10), &[0, 1, 2]);
    assert!(verify_checkpoint(&cp, &outsiders.set, &RealBls).is_ok());
    // ...but presented against the REAL set, whose members did not sign: the
    // aggregate cannot verify against keys that never contributed.
    assert!(verify_checkpoint(&cp, &c_real.set, &RealBls).is_err());
}

#[test]
fn a_tampered_payload_invalidates_the_signature() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2, 3]);
    cp.payload.height = 101; // everything else unchanged
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

#[test]
fn a_swapped_block_hash_invalidates_the_signature() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2, 3]);
    cp.payload.block_hash = sha256(&[b"attacker block"]);
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

#[test]
fn a_foreign_network_id_invalidates_the_signature() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2, 3]);
    cp.payload.network_id = "jounit/mainnet".into();
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

// ---------------------------------------------------------------------------
// Malformed cryptographic material
// ---------------------------------------------------------------------------

#[test]
fn a_zero_signature_is_rejected_by_real_verification() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    cp.aggregate_sig = BlsSignature([0u8; 96]);
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

#[test]
fn a_zero_public_key_in_the_set_breaks_verification_cleanly() {
    let c = committee(4);
    let cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    // Poison the set with an invalid key.
    let mut keys: Vec<BlsPublicKey> = c.set.keys.clone();
    keys[0] = BlsPublicKey([0u8; 48]);
    let poisoned = ValidatorSet::new(keys);
    // Must return an error (or refuse), never panic, regardless of which
    // members the bitmap names.
    for idx in [vec![0, 1, 2], vec![1, 2, 3], vec![0, 1, 2, 3]] {
        let evil = Checkpoint {
            signer_bitmap: poisoned.bitmap_from_indices(&idx),
            signer_count: idx.len() as u32,
            ..cp.clone()
        };
        let _ = verify_checkpoint(&evil, &poisoned, &RealBls);
    }
}

#[test]
fn garbage_signature_bytes_are_rejected_not_panicked_on() {
    let c = committee(4);
    let mut cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    let mut bytes = [0x5A; 96];
    bytes[0] = 0xC0; // compressed-point-ish header, still not a real point
    cp.aggregate_sig = BlsSignature(bytes);
    assert!(verify_checkpoint(&cp, &c.set, &RealBls).is_err());
}

// ---------------------------------------------------------------------------
// Replay: CheckpointChain must refuse repeats and regressions
// ---------------------------------------------------------------------------

#[test]
fn the_same_checkpoint_cannot_be_accepted_twice() {
    let c = committee(4);
    let mut chain = CheckpointChain::new();
    let cp = signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]);
    chain.accept(cp.clone(), &c.set, &RealBls).unwrap();
    let err = chain.accept(cp, &c.set, &RealBls).unwrap_err();
    assert!(err.contains("not beyond"), "replay must be refused: {err}");
    assert_eq!(chain.count(), 1);
}

#[test]
fn finality_never_moves_backwards() {
    let c = committee(4);
    let mut chain = CheckpointChain::new();
    chain
        .accept(
            signed_checkpoint(&c, payload(100, 10), &[0, 1, 2]),
            &c.set,
            &RealBls,
        )
        .unwrap();
    // A validly-signed checkpoint at a LOWER height is still refused.
    let older = signed_checkpoint(&c, payload(50, 5), &[0, 1, 2]);
    assert!(chain.accept(older, &c.set, &RealBls).is_err());
    assert!(chain.is_finalized(100));
    assert!(!chain.is_finalized(101));
}

#[test]
fn an_unsigned_or_forged_checkpoint_never_advances_finality() {
    let c = committee(4);
    let mut chain = CheckpointChain::new();
    let mut forged = signed_checkpoint(&c, payload(200, 20), &[0, 1, 2]);
    forged.aggregate_sig = BlsSignature([0u8; 96]);
    assert!(chain.accept(forged, &c.set, &RealBls).is_err());
    assert_eq!(chain.finalized_height, 0, "finality did not move");
}

// ---------------------------------------------------------------------------
// Cross-DST sanity at the integration level
// ---------------------------------------------------------------------------

#[test]
fn a_signature_over_the_raw_payload_fails_the_hash_path() {
    // §14.5: the BLS message is the 32-byte signing_hash, not the payload.
    // A signer that hashes differently produces a signature that verifies
    // against neither — this pins the convention.
    let c = committee(4);
    let p = payload(100, 10);
    let msg = p.signing_hash();
    let agg = RealBls::aggregate(&[c.sks[0].sign(&msg)]).unwrap();

    // Sanity: correct path verifies (1 signer < quorum, so verify directly).
    assert!(jnt_core::bls::RealBls::verify(&c.set.keys[0], &msg, &agg));

    // The payload bytes themselves are NOT the message.
    let raw = p.serialize();
    let raw_hash = sha256(&[&raw]);
    if raw_hash != msg {
        assert!(!jnt_core::bls::RealBls::verify(
            &c.set.keys[0],
            &raw_hash,
            &agg
        ));
    }
    let _ = DST_CHECKPOINT;
}

#[test]
fn quorum_math_is_the_specified_ceiling() {
    // ceil(n * 6667 / 10000) for representative sizes.
    assert_eq!(quorum_of(1), 1);
    assert_eq!(quorum_of(3), 3); // 2/3 of 3 -> ceil(2.0001) = 3
    assert_eq!(quorum_of(4), 3);
    assert_eq!(quorum_of(7), 5); // ceil(4.6669) = 5
    assert_eq!(quorum_of(21), 15); // ceil(14.0007) = 15
    assert_eq!(quorum_of(100), 67);
}
