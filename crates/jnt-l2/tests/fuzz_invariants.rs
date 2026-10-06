//! L2 fuzz-invariant regression tests.
//!
//! The Phase-3 cargo-fuzz targets in `fuzz/fuzz_targets/` (`l2_payload_decode`,
//! `m3_readers`, `dispute_arbitrate`, `l2_state_apply`) explore these same code
//! paths with a coverage-guided search, but they need a nightly toolchain with a
//! sanitizer runtime that the Windows dev box does not have. These tests enforce
//! the *same invariants* deterministically on hand-built and pseudo-random
//! adversarial inputs, so the properties hold on every `cargo test` run and in
//! CI on stable, and so a minimizing reproduction from a fuzzer has somewhere
//! permanent to live.
//!
//! Four boundaries are covered, one per target:
//!
//! 1. The L2 transaction codec — decode is total and an exact inverse.
//! 2. The M3 readers embedded in a signed payload — total, and the declared
//!    signature length is bounded before it drives an allocation.
//! 3. Dispute evidence validation and arbitration — total, deterministic, and
//!    never a default-to-guilt.
//! 4. The L2 state machine driven by a deterministic program of real, validly
//!    signed transactions — value conservation after every single step.

use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::ser::Reader;
use jnt_core::wallet::Wallet;
use jnt_l2::{Arbiter, ContractState, DisputeEngine, DisputeEvidence, L2Config, L2Error, L2State};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-fuzz-invariants").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
}

/// A deterministic pseudo-random stream. Not cryptographic — it only has to
/// reach many shapes reproducibly, so a failing case is itself a regression
/// test with no seed to save.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn hash(&mut self) -> Hash {
        let mut h = [0u8; 32];
        for chunk in h.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        h
    }
}

/// A pseudo-random but deterministic byte blob, covering the shapes a mutation
/// fuzzer reaches quickly.
fn blobs() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff],
        vec![0xff; 4],
        vec![0xff; 96],
        // A version prefix and an unknown type byte.
        vec![0x01, 0x00, 0x00, 0x00, 0xEE, 0x00],
        // A plausible header followed by truncation.
        vec![0x01, 0x00, 0x00, 0x00, 0x10],
        // A signer bitmap length that claims far more than the buffer holds.
        vec![0x01, 0x00, 0x00, 0x00, 0x14, 0xff, 0xff, 0xff, 0x7f],
    ];
    for seed in [1u64, 42, 0xDEAD_BEEF] {
        let mut rng = Rng::new(seed);
        for len in [2usize, 7, 33, 64, 129, 257, 512] {
            out.push((0..len).map(|_| rng.byte()).collect());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. L2 transaction codec (target: `l2_payload_decode`)
// ---------------------------------------------------------------------------

#[test]
fn l2_transaction_decode_is_total_and_an_exact_inverse() {
    for data in blobs() {
        // Ok or Err — never a panic, never an over-read.
        if let Ok(tx) = L2Transaction::deserialize(&data) {
            let encoded = tx.serialize();
            let again = L2Transaction::deserialize(&encoded)
                .expect("a payload that decoded once must decode after re-encoding");
            assert_eq!(again, tx, "encode/decode must be an exact inverse");
            assert_eq!(again.txid(), tx.txid(), "txid must be stable");
            assert_eq!(again.fee_sat(), tx.fee_sat());
            assert_eq!(again.tx_type(), tx.tx_type());
        }
    }
}

#[test]
fn l2_decode_survives_truncation_and_bitflips_of_real_transactions() {
    let submitter = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);

    let compute_task = ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 1 << 20,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 0,
        expiry_height: 1_000,
        submit_height: 0,
    };
    let post = PostTaskPayload::build(&submitter, 1, 1_000_000, 1_000, compute_task).unwrap();
    let id = post.task_id;

    let attest = |w: &Wallet, result: Hash| ComputeAttestation {
        task_id: id,
        result_hash: result,
        backend: ComputeBackend::Cpu,
        worker_address: addr(w),
        attest_height: 0,
        signature: vec![0x01, 0x02, 0x03],
    };

    // One real transaction of each of the five types.
    let transactions: Vec<L2Transaction> = vec![
        L2Transaction::new(L2Payload::Post(post)),
        L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&worker, id, attest(&worker, [0xAAu8; 32])).unwrap(),
        )),
        L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &challenger,
                id,
                [0xBBu8; 32],
                attest(&challenger, [0xBBu8; 32]),
                50_000,
            )
            .unwrap(),
        )),
        L2Transaction::new(L2Payload::Settle(SettlePayload {
            task_id: id,
            verdict: Verdict::Correct,
            vwc_hash: [0xAAu8; 32],
            bls_sig: [0x7Fu8; 96],
            signer_bitmap: validators(4).bitmap_from_indices(&[0, 1, 2]),
            signer_count: 3,
        })),
    ];

    for tx in &transactions {
        let bytes = tx.serialize();
        assert!(
            L2Transaction::deserialize(&bytes).is_ok(),
            "precondition: every built transaction is a valid encoding"
        );

        // Every truncation: Ok (a shorter valid encoding) or Err, never a panic.
        for cut in 0..bytes.len() {
            if let Ok(decoded) = L2Transaction::deserialize(&bytes[..cut]) {
                let re = decoded.serialize();
                let back = L2Transaction::deserialize(&re)
                    .expect("a decoded transaction must decode from its own encoding");
                assert_eq!(back, decoded, "re-encode must be stable");
            }
        }

        // Every single-byte flip: a peer controls these bytes.
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 0x80;
            if let Ok(decoded) = L2Transaction::deserialize(&flipped) {
                let _ = decoded.txid();
                let _ = decoded.fee_sat();
                let _ = decoded.payload.actor();
                let _ = decoded.payload.signing_hash();
                // Authorization may refuse garbage, but it must not panic.
                let _ = decoded.payload.verify_auth();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. M3 readers (target: `m3_readers`)
// ---------------------------------------------------------------------------

#[test]
fn m3_readers_are_total_and_invertible() {
    for data in blobs() {
        if let Ok(task) = ComputeTask::from_reader(&mut Reader::new(&data)) {
            let bytes = task.serialize();
            assert_eq!(bytes.len(), ComputeTask::SERIALIZED_LEN);
            let back = ComputeTask::from_reader(&mut Reader::new(&bytes))
                .expect("a task that decoded must decode its own encoding");
            assert_eq!(back, task);
            assert_eq!(back.task_hash(), task.task_hash());
        }

        if let Ok(attest) = ComputeAttestation::from_reader(&mut Reader::new(&data)) {
            let bytes = attest.serialize();
            let back = ComputeAttestation::from_reader(&mut Reader::new(&bytes))
                .expect("an attestation that decoded must decode its own encoding");
            assert_eq!(back, attest);
            assert!(
                attest.signature.len() <= ComputeAttestation::MAX_SIGNATURE_BYTES,
                "a decoded attestation must respect the signature cap"
            );
        }
    }
}

#[test]
fn an_oversized_attestation_signature_length_is_refused() {
    // header (task_id, result_hash, backend, worker, height) then a declared
    // length above the cap. The decoder must refuse *before* reserving.
    let mut bytes = vec![0u8; 32 + 32 + 1 + 20 + 8];
    bytes.extend_from_slice(&(ComputeAttestation::MAX_SIGNATURE_BYTES as u32 + 1).to_le_bytes());
    bytes.extend_from_slice(&vec![0u8; ComputeAttestation::MAX_SIGNATURE_BYTES + 1]);
    assert!(
        ComputeAttestation::from_reader(&mut Reader::new(&bytes)).is_err(),
        "a declared signature length over the cap must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 3. Dispute evidence and arbitration (target: `dispute_arbitrate`)
// ---------------------------------------------------------------------------

fn attestation(task_id: Hash, result: Hash, who: Address, sig: Vec<u8>) -> ComputeAttestation {
    ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Cpu,
        worker_address: who,
        attest_height: 0,
        signature: sig,
    }
}

fn well_formed_evidence() -> DisputeEvidence {
    let task = [0x11u8; 32];
    DisputeEvidence {
        task_id: task,
        submitted_result: [0xAAu8; 32],
        submitted_attestation: attestation(task, [0xAAu8; 32], [0x02u8; 20], vec![1]),
        counter_result: [0xBBu8; 32],
        counter_attestation: attestation(task, [0xBBu8; 32], [0x03u8; 20], vec![2]),
    }
}

#[test]
fn evidence_validation_is_total_over_every_mutation() {
    // Every field of the evidence, mutated to zero, to the wrong hash, and to an
    // empty signature. Validation must always return Ok or a named error.
    let base = well_formed_evidence();
    let mut cases = vec![base.clone()];

    fn zero_task(e: &mut DisputeEvidence) {
        e.task_id = [0u8; 32];
    }
    fn zero_submitted(e: &mut DisputeEvidence) {
        e.submitted_result = [0u8; 32];
    }
    fn zero_counter(e: &mut DisputeEvidence) {
        e.counter_result = [0u8; 32];
    }
    fn agree(e: &mut DisputeEvidence) {
        e.counter_result = e.submitted_result;
    }
    fn bad_submitted_task(e: &mut DisputeEvidence) {
        e.submitted_attestation.task_id = [0x99u8; 32];
    }
    fn bad_submitted_result(e: &mut DisputeEvidence) {
        e.submitted_attestation.result_hash = [0x99u8; 32];
    }
    fn bad_counter_task(e: &mut DisputeEvidence) {
        e.counter_attestation.task_id = [0x99u8; 32];
    }
    fn bad_counter_result(e: &mut DisputeEvidence) {
        e.counter_attestation.result_hash = [0x99u8; 32];
    }
    fn unsigned_submitted(e: &mut DisputeEvidence) {
        e.submitted_attestation.signature = vec![];
    }
    fn unsigned_counter(e: &mut DisputeEvidence) {
        e.counter_attestation.signature = vec![];
    }
    fn max_task(e: &mut DisputeEvidence) {
        e.task_id = [0xffu8; 32];
    }

    let mutations: [fn(&mut DisputeEvidence); 11] = [
        zero_task,
        zero_submitted,
        zero_counter,
        agree,
        bad_submitted_task,
        bad_submitted_result,
        bad_counter_task,
        bad_counter_result,
        unsigned_submitted,
        unsigned_counter,
        max_task,
    ];
    for m in mutations {
        let mut e = base.clone();
        m(&mut e);
        cases.push(e);
    }

    for e in &cases {
        let validated = e.validate().is_ok();
        match DisputeEngine::arbitrate(e, e.submitted_result) {
            Ok(v) => {
                assert!(validated, "a verdict may only come from validated evidence");
                assert_ne!(
                    v.arbiter,
                    Arbiter::Inconclusive,
                    "an Ok arbitration is never Inconclusive"
                );
                // A verdict that matches the submitted result is never a slash.
                assert_eq!(v.arbiter, Arbiter::WorkerCorrect);
            }
            Err(_) => assert!(
                !validated,
                "validated evidence must arbitrate, not fail: {e:?}"
            ),
        }
    }
}

#[test]
fn arbitration_is_a_total_deterministic_function_of_the_reference() {
    let e = well_formed_evidence();
    let references: Vec<Hash> = {
        let mut v = vec![
            e.submitted_result,
            e.counter_result,
            [0xCCu8; 32],
            [0u8; 32],
        ];
        let mut rng = Rng::new(7);
        for _ in 0..256 {
            v.push(rng.hash());
        }
        v
    };

    for reference in references {
        let a = DisputeEngine::arbitrate(&e, reference).unwrap();
        let b = DisputeEngine::arbitrate(&e, reference).unwrap();
        assert_eq!(a, b, "arbitration must be deterministic");

        // The reference is always the settle hash, and the mapping to a wire
        // verdict is a function of which claim it reproduced (or neither).
        let expected = if reference == e.submitted_result {
            Some(Verdict::Correct)
        } else if reference == e.counter_result {
            Some(Verdict::Fraudulent)
        } else {
            None
        };
        assert_eq!(a.verdict(), expected);
        assert_eq!(a.vwc_hash(), expected.map(|_| reference));
        // An inconclusive arbitration has no payload to vote on — and asking for
        // one is an error, never an empty transaction.
        match a.settle_payload([0u8; 96], vec![0xFF], 1) {
            Ok(p) => {
                assert_eq!(expected, Some(p.verdict));
                assert_eq!(p.vwc_hash, reference);
            }
            Err(err) => assert_eq!(err, L2Error::InconclusiveDispute),
        }
    }
}

// ---------------------------------------------------------------------------
// 4. L2 state machine (target: `l2_state_apply`)
// ---------------------------------------------------------------------------

/// Drive `L2State` with a deterministic program of real, validly signed
/// transactions and assert the one property that must never break, after every
/// step:
///
///     accounts + locked + burned + PSCB + vault_remaining == total credited
///
/// The program deliberately interleaves successful and impossible operations —
/// claims before posts, submits before claims, double disputes, settles of the
/// wrong hash, inconclusive references — so the invariant is exercised on the
/// rejection paths as much as the happy ones. Counters at the end assert the
/// program actually reached each path, so the test cannot pass by doing nothing.
#[test]
fn l2_value_conservation_holds_across_an_adversarial_program() {
    const FUND: u64 = 1_000_000_000;
    let submitter = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);
    let (sa, wa, ca) = (addr(&submitter), addr(&worker), addr(&challenger));

    let mut state = L2State::new(L2Config::mini());
    for a in [sa, wa, ca] {
        state.credit(a, FUND).unwrap();
    }
    let credited = FUND * 3;

    let validators = validators(4);
    let verifier = MockBls;
    let quorum = validators.quorum_size();
    let bitmap = validators.bitmap_from_indices(&(0..quorum).collect::<Vec<_>>());

    let attestation = |id: Hash, result: Hash, who: Address, salt: u8| ComputeAttestation {
        task_id: id,
        result_hash: result,
        backend: ComputeBackend::Cpu,
        worker_address: who,
        attest_height: 0,
        signature: vec![salt | 1],
    };

    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    let mut task: Option<Hash> = None;
    let mut submitted_result: Option<Hash> = None;
    let mut height = 1u64;

    // Proof the program is not vacuous.
    let mut seen = [0u64; 5];

    for step in 0..300u64 {
        let op = rng.byte() % 6;
        match op {
            // Post. A fresh nonce and a fresh task hash so the id is new.
            0 => {
                let deadline = height + 60;
                let compute_task = ComputeTask {
                    task_id: [0x11u8; 32],
                    ir_hash: rng.hash(),
                    input_hash: rng.hash(),
                    required_memory_bytes: 0,
                    backend_hint: ComputeBackend::Cpu,
                    reward_sat: 0,
                    expiry_height: deadline,
                    submit_height: height,
                };
                let payment = 40_000 + rng.next() % 2_000_000;
                if let Ok(post) =
                    PostTaskPayload::build(&submitter, step + 1, payment, deadline, compute_task)
                {
                    let id = post.task_id;
                    if state
                        .apply(
                            &L2Transaction::new(L2Payload::Post(post)),
                            height,
                            &validators,
                            &verifier,
                        )
                        .is_ok()
                    {
                        task = Some(id);
                        submitted_result = None;
                        seen[0] += 1;
                    }
                }
            }
            // Claim.
            1 => {
                if let Some(id) = task {
                    let deposit = 40_000 + rng.next() % 500_000;
                    if let Ok(c) =
                        ClaimTaskPayload::build(&worker, id, ComputeBackend::Cpu, deposit)
                    {
                        if state
                            .apply(
                                &L2Transaction::new(L2Payload::Claim(c)),
                                height,
                                &validators,
                                &verifier,
                            )
                            .is_ok()
                        {
                            seen[1] += 1;
                        }
                    }
                }
            }
            // Submit.
            2 => {
                if let Some(id) = task {
                    let result = rng.hash();
                    let a = attestation(id, result, wa, rng.byte());
                    if let Ok(s) = SubmitResultPayload::build(&worker, id, a) {
                        if state
                            .apply(
                                &L2Transaction::new(L2Payload::Submit(s)),
                                height,
                                &validators,
                                &verifier,
                            )
                            .is_ok()
                        {
                            submitted_result = Some(result);
                            seen[2] += 1;
                        }
                    }
                }
            }
            // Dispute, with a counter-result guaranteed to differ from the
            // submission so the refusal (when the state is wrong) is not merely
            // the "dispute agrees" guard.
            3 => {
                if let Some(id) = task {
                    let mut counter = rng.hash();
                    if Some(counter) == submitted_result {
                        counter[0] ^= 0xFF;
                    }
                    let a = attestation(id, counter, ca, rng.byte());
                    let deposit = 10_000 + rng.next() % 200_000;
                    if let Ok(d) = DisputePayload::build(&challenger, id, counter, a, deposit) {
                        if state
                            .apply(
                                &L2Transaction::new(L2Payload::Dispute(d)),
                                height,
                                &validators,
                                &verifier,
                            )
                            .is_ok()
                        {
                            seen[3] += 1;
                        }
                    }
                }
            }
            // Settle along the arbitrated path: ask the engine what a reference
            // implies, then settle with the verdict it returns.
            4 => {
                if let Some(id) = task {
                    let disputed = match state.task(&id).map(|t| &t.state) {
                        Some(ContractState::Disputed(c)) => {
                            Some((c.against_result, c.counter_result))
                        }
                        _ => None,
                    };
                    if let Some((against, counter)) = disputed {
                        let reference = match rng.byte() % 3 {
                            0 => against,
                            1 => counter,
                            _ => rng.hash(), // likely inconclusive
                        };
                        if let Ok(v) = DisputeEngine::resolve(state.task(&id).unwrap(), reference) {
                            if let Ok(payload) =
                                v.settle_payload([0xAAu8; 96], bitmap.clone(), quorum as u32)
                            {
                                if state
                                    .apply(
                                        &L2Transaction::new(L2Payload::Settle(payload)),
                                        height,
                                        &validators,
                                        &verifier,
                                    )
                                    .is_ok()
                                {
                                    seen[4] += 1;
                                }
                            }
                        }
                    }
                }
            }
            // Advance-only: the clock moves and implicit transitions fire.
            _ => {}
        }

        let _ = state.advance_block(height);
        height += 1;

        assert_eq!(
            state.conservation_total(),
            credited,
            "value conservation broke after step {step} (op {op})"
        );
    }

    // Every explicit path was actually reached at least once, so the invariant
    // above held over the happy paths, not only over rejections.
    assert!(seen[0] > 0, "the program never posted a task");
    assert!(seen[1] > 0, "the program never claimed a task");
    assert!(seen[2] > 0, "the program never submitted a result");
    assert!(seen[3] > 0, "the program never filed a dispute");
    assert!(
        seen[4] > 0,
        "the program never settled an arbitrated dispute"
    );

    // And a mismatch between the bitmap and the declared count is refused
    // without touching value.
    let before = state.conservation_total();
    let bad = L2Transaction::new(L2Payload::Settle(SettlePayload {
        task_id: [0x11u8; 32],
        verdict: Verdict::Correct,
        vwc_hash: [0xAAu8; 32],
        bls_sig: [0u8; 96],
        signer_bitmap: bitmap,
        signer_count: 99,
    }));
    assert!(state.apply(&bad, height, &validators, &verifier).is_err());
    assert_eq!(state.conservation_total(), before);
}
