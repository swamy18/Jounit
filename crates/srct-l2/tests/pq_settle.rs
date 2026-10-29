//! Settle lattice sidecar, end to end (Decision 24, step 3, L2 half):
//! votes carrying lattice signatures tally into a settle payload whose
//! sidecar `apply_settle` verifies, and the issued VWC carries the sidecar
//! its own validation re-verifies.
//!
//! Attacks, mirroring the checkpoint suite: a stripped sidecar, a forged
//! lattice signature, and a keyed member voting without one are all refused —
//! at apply time (no value moves, no certificate issues) and at VWC
//! validation time.

use srct_core::arbitration::{ArbitrationVote, VoteTally, ARBITRATION_VOTE_VERSION};
use srct_core::bls::SecretKey;
use srct_core::bls_checkpoint::{BlsPublicKey, BlsSignature, MockBls, ValidatorSet};
use srct_core::compute_ir::{
    reference_result_hash, ComputeAttestation, ComputeBackend, ComputeTask,
};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload,
    SubmitResultPayload, Verdict,
};
use srct_core::signing::ValidatorKey;
use srct_core::validators::{derive_set, SelectionRule, ValidatorRecord};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Effect, L2Error, L2State};

const NET: &str = "srct/mini";
const DEADLINE: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "pq-settle").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn task(deadline: u64) -> ComputeTask {
    ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 0,
        expiry_height: deadline,
        submit_height: 0,
    }
}

fn attestation(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Gpu,
        worker_address: addr(w),
        attest_height: 0,
        signature: vec![],
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

/// Three arbitrators with real BLS keys; seeds 1 and 2 hold registered
/// lattice keys, seed 3 does not — the transition shape.
fn bls_key(seed: u8) -> (SecretKey, BlsPublicKey) {
    let sk = SecretKey::derive(&[seed; 32]).unwrap();
    let pk = sk.public_key();
    (sk, pk)
}

fn vkey(seed: u8) -> ValidatorKey {
    let (sk, _) = bls_key(seed);
    ValidatorKey::new(sk, NET)
}

fn records() -> Vec<ValidatorRecord> {
    [(1u8, true), (2u8, true), (3u8, false)]
        .into_iter()
        .enumerate()
        .map(|(i, (seed, keyed))| {
            let (_, pk) = bls_key(seed);
            ValidatorRecord {
                stake_address: [(10 + i as u8); 20],
                bls_pk: pk,
                stake_sat: 5_000_000,
                mldsa_pk: keyed.then(|| vkey(seed).mldsa_pubkey()),
            }
        })
        .collect()
}

fn committee_bls() -> Vec<BlsPublicKey> {
    let mut v: Vec<BlsPublicKey> = [1u8, 2u8, 3u8].iter().map(|s| bls_key(*s).1).collect();
    v.sort_by_key(|k| k.0);
    v
}

fn keyed_set() -> ValidatorSet {
    let set = derive_set(0, &records(), SelectionRule::TopN, 21).unwrap();
    assert_eq!(set.validators.len(), 3);
    ValidatorSet::from_records(&set.validators)
}

struct World {
    state: L2State,
    task_id: Hash,
    reference: Hash,
}

fn world() -> World {
    let submitter = wallet(11);
    let worker = wallet(12);
    let challenger = wallet(13);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), 10_000_000).unwrap();
    state.credit(addr(&worker), 10_000_000).unwrap();
    state.credit(addr(&challenger), 10_000_000).unwrap();

    // Post, claim, submit the reference result, dispute it baselessly: the
    // worker is correct, so the settlement verdict is `Correct`.
    let post = PostTaskPayload::build(&submitter, 1, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let id = post.task_id;
    let apply = |state: &mut L2State, tx: &L2Transaction, height: u64| {
        state.apply(tx, height, &ValidatorSet::new(vec![]), &MockBls)
    };
    let mut s = state;
    apply(&mut s, &L2Transaction::new(L2Payload::Post(post)), 1).unwrap();
    let t = s.task(&id).unwrap();
    let reference = reference_result_hash(
        &t.task_id,
        &t.deliverable.0.ir_hash,
        &t.deliverable.0.input_hash,
        t.deliverable.0.required_memory_bytes,
    );
    apply(
        &mut s,
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&worker, id, ComputeBackend::Gpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    apply(
        &mut s,
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&worker, id, attestation(&worker, id, reference)).unwrap(),
        )),
        3,
    )
    .unwrap();
    apply(
        &mut s,
        &L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &challenger,
                id,
                [0xBBu8; 32],
                attestation(&challenger, id, [0xBBu8; 32]),
                50_000,
            )
            .unwrap(),
        )),
        4,
    )
    .unwrap();
    World {
        state: s,
        task_id: id,
        reference,
    }
}

/// One arbitrator's vote for the worker-correct decision, with a lattice
/// signature exactly when `lattice` is set.
fn vote(seed: u8, w: &World, lattice: bool, height: u64) -> ArbitrationVote {
    let (sk, pk) = bls_key(seed);
    let base = ArbitrationVote {
        version: ARBITRATION_VOTE_VERSION,
        task_id: w.task_id,
        verdict: Verdict::Correct,
        vwc_hash: w.reference,
        network_id: NET.to_string(),
        height,
        signer: pk,
        signature: BlsSignature([0u8; 96]),
        pq_sig: None,
    };
    let msg = base.signing_hash();
    ArbitrationVote {
        signature: sk.sign(&msg),
        pq_sig: lattice.then(|| vkey(seed).sign_pq(&msg).unwrap()),
        ..base
    }
}

/// Tally all three members (keyed members with lattice signatures) into a
/// settle payload.
fn settled_payload(w: &World) -> srct_core::l2::SettlePayload {
    let committee = committee_bls();
    let mut tally = VoteTally::new(3);
    for (seed, lattice) in [(1u8, true), (2u8, true), (3u8, false)] {
        tally
            .record(&vote(seed, w, lattice, 5), NET, 5, &committee)
            .unwrap();
    }
    tally.settle_payload(&committee).expect("quorum reached")
}

#[test]
fn a_dual_signed_settlement_applies_and_certifies() {
    let mut w = world();
    let set = keyed_set();
    let payload = settled_payload(&w);
    assert_eq!(payload.pq_sidecar.len(), 2, "two keyed voters");
    let effect = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            5,
            &set,
            &MockBls,
        )
        .expect("a dual-signed settlement applies");
    assert!(matches!(effect, L2Effect::Settled { .. }));
    // The issued certificate carries the sidecar and validates with it.
    let cert = w.state.vwc(&w.task_id).expect("Correct settles certify");
    assert_eq!(cert.pq_sidecar_len(), 2);
    cert.validate(&set, &MockBls).expect("the VWC validates");
    cert.validate_verified(&set, &MockBls)
        .expect("quorum basis counts as verified");
}

#[test]
fn a_settlement_stripped_of_its_sidecar_does_not_apply() {
    let mut w = world();
    let set = keyed_set();
    let mut payload = settled_payload(&w);
    payload.pq_sidecar.clear();
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            5,
            &set,
            &MockBls,
        )
        .unwrap_err();
    assert!(
        matches!(err, L2Error::BadPqSidecar(_)),
        "stripping must name the sidecar refusal: {err:?}"
    );
    assert!(
        w.state.vwc(&w.task_id).is_none(),
        "no value moved, no certificate"
    );
}

#[test]
fn a_settlement_with_a_forged_lattice_signature_does_not_apply() {
    let mut w = world();
    let set = keyed_set();
    let mut payload = settled_payload(&w);
    // The attacker's own lattice key signs the same decision: valid
    // cryptography for the wrong key.
    let msg = payload.signing_hash();
    payload.pq_sidecar[0].signature = vkey(9).sign_pq(&msg).unwrap();
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            5,
            &set,
            &MockBls,
        )
        .unwrap_err();
    assert!(matches!(err, L2Error::BadPqSidecar(_)), "{err:?}");
}

#[test]
fn a_keyed_member_voting_without_a_lattice_signature_stalls_settlement() {
    // Member 1 (keyed) votes BLS-only. The tally still reaches BLS quorum,
    // but the payload it builds has no entry for a keyed signer — and apply
    // refuses the downgrade rather than settling without the quantum half.
    let mut w = world();
    let set = keyed_set();
    let committee = committee_bls();
    let mut tally = VoteTally::new(3);
    tally
        .record(&vote(1, &w, false, 5), NET, 5, &committee)
        .unwrap();
    tally
        .record(&vote(2, &w, true, 5), NET, 5, &committee)
        .unwrap();
    tally
        .record(&vote(3, &w, false, 5), NET, 5, &committee)
        .unwrap();
    let payload = tally
        .settle_payload(&committee)
        .expect("BLS quorum reached");
    assert_eq!(payload.pq_sidecar.len(), 1);
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            5,
            &set,
            &MockBls,
        )
        .unwrap_err();
    assert!(matches!(err, L2Error::BadPqSidecar(_)), "{err:?}");
}

#[test]
fn a_vwc_stripped_of_its_sidecar_does_not_validate() {
    let mut w = world();
    let set = keyed_set();
    let payload = settled_payload(&w);
    w.state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            5,
            &set,
            &MockBls,
        )
        .unwrap();
    let mut cert = w.state.vwc(&w.task_id).expect("issued").clone();
    cert.strip_pq_sidecar_for_test();
    let err = cert.validate(&set, &MockBls).unwrap_err();
    assert!(
        matches!(err, L2Error::VwcInvalid(_)),
        "a VWC without its quantum half is not evidence: {err:?}"
    );
}
