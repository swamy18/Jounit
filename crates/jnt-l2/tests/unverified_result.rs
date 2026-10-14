//! The unverified-result problem (acceptance requirement for the launch gate).
//!
//! An unchallenged submission is accepted. That has to be true — otherwise a
//! griefer could stall every task simply by filing a dispute and never
//! arbitrating it, and no compute platform would survive. The economics already
//! price the risk: a wrong result that nobody challenges in time still pays the
//! worker, and the only party who can turn that around is a challenger who puts
//! up a deposit.
//!
//! What is *not* acceptable, and is what this file exists to prevent, is the
//! protocol representing that outcome as verification. A certificate minted
//! because a dispute window closed with nobody objecting says exactly that —
//! nobody objected in time — and nothing about whether the result is correct.
//! A relying party that reads it as "this computation was verified" has been
//! misled, and this suite makes that impossible to do by accident.
//!
//! The first test drives the real path end to end: a worker submits a result
//! that is **not** the canonical reference, no challenge is filed, the window
//! closes, the settlement goes through, and the worker is paid. That much is
//! correct protocol. The test then checks that the certificate which comes out
//! of it carries no verification claim — through `asserts_correctness`,
//! `VwcVerification::is_offline_verifiable`, and the strict
//! `validate_verified` / `validate_vwc_verified` entry points.
//!
//! The second test is the positive control: the same worker, same task shape,
//! but challenged and arbitrated. That path produces a quorum-signed verdict,
//! and *that* certificate is accepted by the strict entry point. Without this
//! half the first test proves only that the strict path refuses everything.

use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{
    reference_result_hash, ComputeAttestation, ComputeBackend, ComputeTask,
};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload,
    SubmitResultPayload,
};
use jnt_core::wallet::Wallet;
use jnt_l2::{L2Config, L2Effect, L2Error, L2State};

const DEADLINE: u64 = 100;
const CREDITED: u64 = 30_000_000;

// A result that is certainly not the canonical reference for these tasks. It is
// not "wrong" in any protocol sense until somebody challenges it — see below.
const NOT_THE_REFERENCE: Hash = [0xAAu8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "unverified-result").unwrap()
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

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
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

struct World {
    state: L2State,
    submitter: Wallet,
    worker: Wallet,
    challenger: Wallet,
    validators: ValidatorSet,
    verifier: MockBls,
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<L2Effect, L2Error> {
        self.state
            .apply(tx, height, &self.validators, &self.verifier)
    }

    /// The canonical CPU reference for the task just posted. Deterministic
    /// (Decision 21): every honest worker and every truthful challenger derives
    /// the same bytes from the same task fields.
    fn reference(&self, id: Hash) -> Hash {
        let t = self.state.task(&id).unwrap();
        reference_result_hash(
            &t.task_id,
            &t.deliverable.0.ir_hash,
            &t.deliverable.0.input_hash,
            t.deliverable.0.required_memory_bytes,
        )
    }

    fn post(&mut self, payment: u64, height: u64) -> Hash {
        let post =
            PostTaskPayload::build(&self.submitter, 1, payment, DEADLINE, task(DEADLINE)).unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), height)
            .unwrap();
        id
    }

    /// Post, claim, and submit `result` for the task. Starts nothing else: no
    /// dispute is filed, which is exactly the shape of the unverified path.
    fn post_claim_submit(&mut self, result: Hash) -> Hash {
        let id = self.post(1_000_000, 1);
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, 100_000).unwrap(),
            )),
            2,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(&self.worker, id, attestation(&self.worker, id, result))
                    .unwrap(),
            )),
            3,
        )
        .unwrap();
        id
    }

    /// Let the dispute window close and take the implicit settlement.
    fn let_the_window_close(&mut self) -> Vec<L2Effect> {
        // Posted at 1, submitted at 3, window 5: auto-settle is due once
        // `height > submitted_at + window`, so from 9.
        let mut effects = Vec::new();
        for h in 4..=10u64 {
            effects.extend(self.state.advance_block(h));
        }
        effects
    }
}

fn world() -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), CREDITED).unwrap();
    state.credit(addr(&worker), CREDITED).unwrap();
    state.credit(addr(&challenger), CREDITED).unwrap();
    World {
        state,
        submitter,
        worker,
        challenger,
        validators: validators(4),
        verifier: MockBls,
    }
}

// ---------------------------------------------------------------------------
// The attack this suite exists to close
// ---------------------------------------------------------------------------

/// **The rule:** a result is only *verified* when independent evidence backs it.
/// Nobody challenging it in time is not evidence, and must not be reported as
/// such.
///
/// **The reachable state:** a worker submits a result that is not the canonical
/// reference, no challenge is filed, the dispute window closes, and the
/// contract auto-settles `Correct` with the worker's own hash. The worker is
/// paid and a certificate is minted — all of that is correct, because the
/// timeout economics requires a challenge to overturn a settlement.
///
/// **What this test pins:** the certificate which comes out of it carries no
/// verification claim, and every entry point a relying party could reach for
/// either says so plainly or refuses.
#[test]
fn an_unchallenged_wrong_result_is_paid_but_never_presented_as_verified() {
    let mut w = world();
    let id = w.post_claim_submit(NOT_THE_REFERENCE);
    let reference = w.reference(id);
    assert_ne!(
        NOT_THE_REFERENCE, reference,
        "test setup: the submission must actually miss the reference"
    );

    // The worker is paid. This is the timeout economics working as designed and
    // must not be "fixed" by refusing the settlement.
    let effects = w.let_the_window_close();
    assert_eq!(
        effects.len(),
        1,
        "exactly one implicit settlement: {effects:?}"
    );
    assert!(matches!(effects[0], L2Effect::Settled { .. }));

    let cert = w
        .state
        .vwc(&id)
        .expect("a Correct settlement mints a certificate")
        .clone();
    assert_eq!(
        cert.result_hash, NOT_THE_REFERENCE,
        "the certificate names the worker's own result"
    );
    // The registry accepts it: it is a genuine certificate for a real
    // settlement. This is the *weak* entry point and both it and its doc comment
    // say so.
    w.state
        .validate_vwc(&cert, &w.validators, &w.verifier)
        .expect("the certificate is genuine and must still validate");
    cert.validate(&w.validators, &w.verifier)
        .expect("a WindowElapsed certificate is well-formed");

    // Now the part that matters. Nothing about it may read as verification.
    assert!(
        !cert.asserts_correctness(),
        "an unchallenged settlement must not assert the result is correct"
    );
    assert!(
        !cert.verification.is_offline_verifiable(),
        "there is no aggregate behind it, so it is not offline-verifiable"
    );
    let refused = cert.validate_verified(&w.validators, &w.verifier);
    assert!(
        refused.is_err(),
        "the strict entry point must refuse it, got {refused:?}"
    );
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("not a verification"),
        "the refusal must name the reason, not fail silently"
    );
    let refused = w
        .state
        .validate_vwc_verified(&cert, &w.validators, &w.verifier);
    assert!(
        refused.is_err(),
        "the state's strict entry point must refuse it too"
    );
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("not a verification"),
        "the refusal must name the reason"
    );

    // And conservation still holds: the failure would be a value bug, and this
    // pins that rejecting the *claim* did not disturb the accounting.
    assert!(
        w.state.check_conservation(),
        "the settlement happened; only the claim about it is refused"
    );
}

/// The positive control. Same task shape, but the result is challenged and
/// arbitrated by a quorum. That path produces a quorum-signed verdict, and
/// *that* certificate is what the strict entry point accepts.
///
/// Without this test the one above would still pass if the strict path refused
/// everything unconditionally — a "fix" that locked every relying party out
/// rather than distinguishing the two bases.
#[test]
fn a_challenged_and_arbitrated_result_is_accepted_as_verified() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    let reference = w.reference(id);

    // The worker tells the truth.
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 100_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, reference))
                .unwrap(),
        )),
        3,
    )
    .unwrap();

    // A baseless challenge: the worker was right, so arbitration returns
    // `WorkerCorrect` and the challenge is what burns.
    w.apply(
        &L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &w.challenger,
                id,
                NOT_THE_REFERENCE,
                attestation(&w.challenger, id, NOT_THE_REFERENCE),
                50_000,
            )
            .unwrap(),
        )),
        4,
    )
    .unwrap();

    let verdict = jnt_l2::DisputeEngine::resolve(w.state.task(&id).unwrap())
        .expect("a disputed contract with real references arbitrates");
    let quorum = w.validators.quorum_size();
    let payload = verdict
        .settle_payload(
            [0xAAu8; 96],
            bitmap(w.validators.len(), quorum),
            quorum as u32,
            Vec::new(),
        )
        .expect("a decisive verdict has a settle payload");
    w.apply(&L2Transaction::new(L2Payload::Settle(payload)), 5)
        .unwrap();

    let cert = w
        .state
        .vwc(&id)
        .expect("an explicit Settle mints one")
        .clone();
    assert!(
        cert.asserts_correctness(),
        "a quorum-signed verdict is independent evidence"
    );
    assert!(
        cert.verification.is_offline_verifiable(),
        "the aggregate is right there in the certificate"
    );
    w.state
        .validate_vwc_verified(&cert, &w.validators, &w.verifier)
        .expect("this is the kind of certificate the strict path exists for");
    cert.validate_verified(&w.validators, &w.verifier)
        .expect("and it must pass it");

    // It must still pass the registry check it always passed, so the strict
    // entry point is an addition and not a replacement.
    w.state
        .validate_vwc(&cert, &w.validators, &w.verifier)
        .expect("a quorum certificate is also a valid one");
}

/// A bitmap with exactly `signed` low bits set, over a `total`-validator set.
fn bitmap(total: usize, signed: usize) -> Vec<u8> {
    let mut b = vec![0u8; total.div_ceil(8).max(1)];
    for i in 0..signed.min(total) {
        b[i / 8] |= 1 << (i % 8);
    }
    b
}
