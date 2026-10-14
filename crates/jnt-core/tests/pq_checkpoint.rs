//! Dual-signed checkpoints (Decision 24, step 3): BLS aggregate plus the
//! ML-DSA-65 lattice sidecar, verified together as clause 7.
//!
//! Attacks, not smoke tests. The claim: a Shor break of BLS12-381 forges the
//! aggregate and still cannot finalize, because every bitmap signer holding a
//! registered lattice key needs a valid sidecar entry over the same decision —
//! and stripping, forging, duplicating or mispointing an entry is a named
//! refusal, never a silent pass.

use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{BlsPublicKey, Checkpoint, CheckpointPayload, PqSidecarEntry};
use jnt_core::signing::{Committee, ValidatorKey};
use jnt_core::validators::{
    derive_set, validate_checkpoint_against_set, EpochSet, SelectionRule, ValidatorRecord,
};

const NET: &str = "jounit/mini";
const EPOCH_BLOCKS: u64 = 10;

fn key(seed: u8) -> ValidatorKey {
    ValidatorKey::new(SecretKey::derive(&[seed; 32]).unwrap(), NET)
}

/// Three members: seeds 1 and 2 hold registered lattice keys, seed 3 does
/// not. The mixed set is the transition shape — the common case until every
/// validator migrates its bond.
fn records() -> Vec<ValidatorRecord> {
    let addrs = [[1u8; 20], [2u8; 20], [3u8; 20]];
    [(1u8, true), (2u8, true), (3u8, false)]
        .into_iter()
        .enumerate()
        .map(|(i, (seed, keyed))| ValidatorRecord {
            stake_address: addrs[i],
            bls_pk: key(seed).public_key(),
            stake_sat: 5_000_000 + i as u64,
            mldsa_pk: keyed.then(|| key(seed).mldsa_pubkey()),
        })
        .collect()
}

fn bls_keys_sorted() -> Vec<BlsPublicKey> {
    let mut v: Vec<BlsPublicKey> = [1u8, 2u8, 3u8]
        .iter()
        .map(|s| key(*s).public_key())
        .collect();
    v.sort_by_key(|k| k.0);
    v
}

fn committee() -> Committee {
    let mut c = Committee::new();
    for s in [1u8, 2u8, 3u8] {
        c.add(key(s)).unwrap();
    }
    c
}

fn payload() -> CheckpointPayload {
    CheckpointPayload {
        height: 25,
        block_hash: [0xABu8; 64],
        network_id: NET.into(),
        epoch: 2,
    }
}

fn epoch_set() -> EpochSet {
    derive_set(2, &records(), SelectionRule::TopN, 21).unwrap()
}

/// A dual-signed certificate from the whole committee, via the records path
/// the production loop uses.
fn dual_cert() -> Checkpoint {
    let p = payload();
    committee()
        .sign_in_set_with_records(&p, &records())
        .expect("committee holds keys")
        .expect("signing a mixed committee must succeed")
}

fn validate(cp: &Checkpoint) -> Result<(), jnt_core::validators::ValidatorError> {
    let set = epoch_set();
    validate_checkpoint_against_set(cp, |_| Ok(set.clone()), 0, EPOCH_BLOCKS, &RealBls)
}

#[test]
fn a_dual_signed_checkpoint_verifies_end_to_end() {
    let cp = dual_cert();
    // Two keyed members, one keyless: two sidecar entries, bitmap of three.
    assert_eq!(cp.signer_count, 3);
    assert_eq!(cp.pq_sidecar.len(), 2);
    assert!(validate(&cp).is_ok());
}

#[test]
fn the_sidecar_round_trips_through_the_codec() {
    let cp = dual_cert();
    let back = Checkpoint::deserialize(&cp.serialize()).unwrap();
    assert_eq!(cp, back);
}

#[test]
fn legacy_bytes_decode_to_an_empty_sidecar() {
    // Certificates written before the sidecar existed end after signer_count.
    // Cutting the trailing count off a sidecar-less certificate is that shape.
    let cp = dual_cert();
    assert!(cp.pq_sidecar.len() == 2);
    let mut plain = cp.clone();
    plain.pq_sidecar.clear();
    let bytes = plain.serialize();
    let legacy = &bytes[..bytes.len() - 4];
    let back = Checkpoint::deserialize(legacy).unwrap();
    assert_eq!(back.pq_sidecar.len(), 0);
    assert_eq!(back.signer_count, 3);
}

#[test]
fn a_stripped_sidecar_is_refused_not_silently_downgraded() {
    // The BLS aggregate still verifies — that is the point of the attack: a
    // quantum forger (or a truncating relay) presents a valid aggregate with
    // no lattice half. Clause 7 must refuse the missing entries.
    let mut cp = dual_cert();
    assert!(validate(&cp).is_ok());
    cp.pq_sidecar.clear();
    let err = validate(&cp).unwrap_err();
    assert!(
        err.to_string().contains("no sidecar entry"),
        "the refusal must name the missing entry: {err}"
    );
}

#[test]
fn a_forged_lattice_signature_is_refused() {
    // The attacker holds a real lattice key of their own and signs the same
    // decision with it. Cryptography passes for *their* key; the binding to
    // the committee member's registered key is what fails.
    let mut cp = dual_cert();
    let msg = cp.payload.signing_hash();
    let forged = key(9).sign_pq(&msg).unwrap();
    cp.pq_sidecar[0].signature = forged;
    let err = validate(&cp).unwrap_err();
    assert!(
        err.to_string().contains("lattice signature failed"),
        "the refusal must name the failed entry: {err}"
    );
}

#[test]
fn a_duplicate_sidecar_index_is_refused() {
    let mut cp = dual_cert();
    cp.pq_sidecar.push(cp.pq_sidecar[0].clone());
    let err = validate(&cp).unwrap_err();
    assert!(
        err.to_string().contains("duplicate"),
        "one member, one lattice voice: {err}"
    );
}

#[test]
fn a_sidecar_entry_for_a_non_signer_is_refused() {
    // Index 7 is in no bitmap and in no set of three: it points nowhere.
    let mut cp = dual_cert();
    cp.pq_sidecar.push(PqSidecarEntry {
        signer_index: 7,
        signature: cp.pq_sidecar[0].signature,
    });
    let err = validate(&cp).unwrap_err();
    assert!(
        err.to_string().contains("non-signer"),
        "an entry that points nowhere is not a signature: {err}"
    );
}

#[test]
fn a_sidecar_entry_for_a_keyless_member_is_refused() {
    // Member index 2 (seed 3) holds no registered key. An entry naming it can
    // verify against nothing, so it is refused rather than trusted.
    let mut cp = dual_cert();
    // Find the bitmap position of the keyless member by matching public keys
    // against the canonical order the verifier uses.
    let keys = bls_keys_sorted();
    let keyless_pos = keys.iter().position(|k| *k == key(3).public_key()).unwrap() as u32;
    cp.pq_sidecar.push(PqSidecarEntry {
        signer_index: keyless_pos,
        signature: cp.pq_sidecar[0].signature,
    });
    let err = validate(&cp).unwrap_err();
    assert!(
        err.to_string().contains("keyless"),
        "an entry with nothing to verify against is refused: {err}"
    );
}

#[test]
fn a_bond_round_trips_with_its_proof_of_possession_and_the_pre_pop_shape_is_refused() {
    use jnt_core::bls_checkpoint::BlsSignature;
    use jnt_core::tx::StakePayload;
    let pk = key(4).public_key();
    let lattice = key(4).mldsa_pubkey();
    // Codec-level proof: `from_reader` does not verify it, it only has to be
    // present and the right length. Verification lives in `check_bond_tx`.
    let pop = BlsSignature([0x5A; 96]);
    let new = StakePayload::Bond {
        bls_pk: pk,
        pop,
        mldsa_pk: Some(Box::new(lattice)),
    };
    let bytes = new.body_bytes();
    assert_eq!(bytes.len(), 48 + 96 + 1 + 1952);
    let mut r = jnt_core::ser::Reader::new(&bytes);
    let back = StakePayload::from_reader(&mut r, jnt_core::tx::TX_BOND).unwrap();
    assert_eq!(back, new);

    // The pre-PoP shape -- a bare 48-byte key -- no longer decodes at all.
    // Accepting it would mean a bond could enter the ledger without anyone
    // proving they hold the key it registers.
    let mut r = jnt_core::ser::Reader::new(&pk.0);
    let err = StakePayload::from_reader(&mut r, jnt_core::tx::TX_BOND).unwrap_err();
    assert!(
        matches!(
            err,
            jnt_core::error::Error::Malformed("bond proof of possession")
        ),
        "the pre-PoP encoding must be refused by name, got {err:?}"
    );
}
