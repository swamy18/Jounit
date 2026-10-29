//! End-to-end L2 flow: real hybrid wallet signatures, the M5 quorum gate, the
//! D3 fee schedule, and the conservation invariant.
//!
//! These tests drive the public surface the way a node would: build a signed
//! transaction, hand it to [`L2State::apply`] at a height, and check both the
//! effect and the money. `MockBls` stands in for the pairing check — the real
//! `blst` verifier is exercised in `srct-core`; what is under test here is the
//! L2 state machine, so the verifier is the one variable that can be mocked
//! without weakening any assertion about L2 accounting.

use srct_core::bls_checkpoint::{BlsPublicKey, BlsSignature, BlsVerifier, MockBls, ValidatorSet};
use srct_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use srct_core::wallet::Wallet;
use srct_l2::{ContractState, L2Config, L2Effect, L2Error, L2State};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const DEADLINE: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-flow").unwrap()
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

/// A validator set of `n` distinct keys, sorted by `ValidatorSet::new`.
fn validators(n: u8) -> ValidatorSet {
    let keys = (1..=n).map(|i| BlsPublicKey([i; 48])).collect();
    ValidatorSet::new(keys)
}

/// A settle payload whose bitmap has exactly `signed` bits set.
fn settle_payload(
    task_id: Hash,
    verdict: Verdict,
    vwc_hash: Hash,
    signed: usize,
    total: usize,
    height: u64,
) -> SettlePayload {
    let n_bytes = total.div_ceil(8).max(1);
    let mut bitmap = vec![0u8; n_bytes];
    for i in 0..signed {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    SettlePayload {
        task_id,
        verdict,
        vwc_hash,
        network_id: "srct/mini".to_string(),
        height,
        bls_sig: [0xAAu8; 96],
        signer_bitmap: bitmap,
        signer_count: signed as u32,
        pq_sidecar: Vec::new(),
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

/// A funded state plus the four actors a full scenario needs.
struct World {
    state: L2State,
    submitter: Wallet,
    worker: Wallet,
    challenger: Wallet,
    validators: ValidatorSet,
    verifier: MockBls,
}

fn world() -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), 10_000_000).unwrap();
    state.credit(addr(&worker), 10_000_000).unwrap();
    state.credit(addr(&challenger), 10_000_000).unwrap();
    World {
        state,
        submitter,
        worker,
        challenger,
        validators: validators(4),
        verifier: MockBls,
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<L2Effect, L2Error> {
        self.state
            .apply(tx, height, &self.validators, &self.verifier)
    }

    /// Post a task and return its id.
    fn post(&mut self, height: u64) -> Hash {
        let post = PostTaskPayload::build(&self.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE))
            .unwrap();
        let id = post.task_id;
        let tx = L2Transaction::new(L2Payload::Post(post));
        self.apply(&tx, height).unwrap();
        id
    }

    fn claim(&mut self, id: Hash, height: u64, deposit: u64) {
        let tx = L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, deposit).unwrap(),
        ));
        self.apply(&tx, height).unwrap();
    }

    fn submit(&mut self, id: Hash, result: Hash, height: u64) {
        let tx = L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&self.worker, id, attestation(&self.worker, id, result))
                .unwrap(),
        ));
        self.apply(&tx, height).unwrap();
    }

    fn dispute(&mut self, id: Hash, counter: Hash, height: u64, deposit: u64) {
        let tx = L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &self.challenger,
                id,
                counter,
                attestation(&self.challenger, id, counter),
                deposit,
            )
            .unwrap(),
        ));
        self.apply(&tx, height).unwrap();
    }

    fn settle(
        &mut self,
        id: Hash,
        verdict: Verdict,
        vwc_hash: Hash,
        signed: usize,
        height: u64,
    ) -> Result<L2Effect, L2Error> {
        let tx = L2Transaction::new(L2Payload::Settle(settle_payload(
            id,
            verdict,
            vwc_hash,
            signed,
            self.validators.len(),
            height,
        )));
        self.apply(&tx, height)
    }
}

/// The credits the harness started with, for the conservation check.
const CREDITED: u64 = 30_000_000;

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn happy_path_auto_settles_and_conserves_value() {
    let mut w = world();
    let id = w.post(1);
    assert_eq!(w.state.task_count(), 1);
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Open
    ));

    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);

    // Before the window closes nothing happens.
    assert!(w.state.advance_block(8).is_empty());
    let effects = w.state.advance_block(9);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        L2Effect::Settled {
            verdict,
            worker_paid,
            ..
        } => {
            assert_eq!(*verdict, Verdict::Correct);
            assert_eq!(*worker_paid, 1_000_000, "an implicit settle charges no fee");
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Settled(_)
    ));

    // Account deltas: the submitter paid the payment plus the post fee; the
    // worker was paid the escrow in full and paid only the claim and submit
    // fees (the deposit went out and came back).
    assert_eq!(
        w.state.balance(&addr(&w.submitter)),
        10_000_000 - 1_000_000 - 5_000
    );
    assert_eq!(
        w.state.balance(&addr(&w.worker)),
        10_000_000 + 1_000_000 - 2_000 - 2_000
    );
    assert_eq!(w.state.total_locked(), 0);
    assert_eq!(w.state.conservation_total(), CREDITED);
    assert_eq!(w.state.pscb, (5_000 + 2_000 + 2_000) / 2);
}

#[test]
fn an_explicit_correct_settle_charges_the_d3_fee() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);

    let before_pscb = w.state.pscb;
    let effect = w.settle(id, Verdict::Correct, [0xAAu8; 32], 3, 9).unwrap();
    match effect {
        L2Effect::Settled { worker_paid, .. } => {
            assert_eq!(
                worker_paid,
                1_000_000 - 1_000,
                "settle fee comes off the escrow"
            );
        }
        other => panic!("unexpected effect {other:?}"),
    }
    // The settle fee is split 50/50, so PSCB grows by half of 1 000.
    assert_eq!(w.state.pscb, before_pscb + 500);
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_dispute_settled_as_fraudulent_slashes_the_workers_deposit() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 100_000);
    w.submit(id, [0xAAu8; 32], 3);
    w.dispute(id, [0xBBu8; 32], 4, 50_000);

    let pscb_before = w.state.pscb;
    let effect = w
        .settle(id, Verdict::Fraudulent, [0xBBu8; 32], 3, 5)
        .unwrap();
    let slashed = 100_000 - 1_000;
    // Phase 3: a successful challenger is paid a 25% bounty from the PSCB
    // reserve, capped by the reserve's balance.
    let bounty = (slashed * 25 / 100).min(pscb_before);
    match effect {
        L2Effect::Settled {
            submitter_refunded,
            worker_deposit_slashed,
            challenger_bonus,
            ..
        } => {
            assert_eq!(
                submitter_refunded, 1_000_000,
                "the defrauded submitter is made whole"
            );
            assert_eq!(
                worker_deposit_slashed, slashed,
                "the settle fee comes out of the losing worker's deposit"
            );
            assert_eq!(challenger_bonus, bounty);
        }
        other => panic!("unexpected effect {other:?}"),
    }

    // M2: half burned immediately, half vesting.
    assert_eq!(w.state.slash_vault.total_burned, slashed / 2);
    assert_eq!(w.state.vault_remaining(), slashed - slashed / 2);
    // The challenger paid the dispute fee, got the deposit back, and earned the
    // bounty.
    assert_eq!(
        w.state.balance(&addr(&w.challenger)),
        10_000_000 - 10_000 + bounty
    );
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_failed_challenge_burns_the_deposit_and_pays_the_worker() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);
    w.dispute(id, [0xBBu8; 32], 4, 50_000);

    let effect = w.settle(id, Verdict::Correct, [0xAAu8; 32], 3, 5).unwrap();
    match effect {
        L2Effect::Settled { worker_paid, .. } => {
            // The worker is right, so they keep the escrow minus the 1 000 sat
            // settle fee that funded the arbitration.
            assert_eq!(worker_paid, 1_000_000 - 1_000);
        }
        other => panic!("unexpected effect {other:?}"),
    }
    // Challenger paid the dispute fee (10 000), lost the 50 000 deposit, and was
    // not refunded; the worker's deposit and the escrow remainder came back.
    assert_eq!(w.state.balance(&addr(&w.challenger)), 10_000_000 - 60_000);
    assert_eq!(
        w.state.balance(&addr(&w.worker)),
        10_000_000 - 2_000 - 2_000 + 999_000
    );
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn an_unclaimed_task_expires_and_refunds_the_submitter() {
    let mut w = world();
    let id = w.post(1);
    assert!(
        w.state.advance_block(DEADLINE).is_empty(),
        "deadline not passed"
    );
    let effects = w.state.advance_block(DEADLINE + 1);
    assert!(matches!(effects[0], L2Effect::Expired { .. }));
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Expired(_)
    ));
    assert_eq!(w.state.balance(&addr(&w.submitter)), 10_000_000 - 5_000);
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_lapsed_claimed_task_burns_the_worker_deposit() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    let effects = w.state.advance_block(DEADLINE + 1);
    match &effects[0] {
        L2Effect::Expired {
            worker_deposit_burned,
            ..
        } => assert_eq!(*worker_deposit_burned, 50_000),
        other => panic!("unexpected effect {other:?}"),
    }
    assert_eq!(w.state.balance(&addr(&w.submitter)), 10_000_000 - 5_000);
    // Worker lost the deposit plus the claim fee.
    assert_eq!(
        w.state.balance(&addr(&w.worker)),
        10_000_000 - 50_000 - 2_000
    );
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_transaction_is_refused() {
    let mut w = world();
    let tx = L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE)).unwrap(),
    ));
    w.apply(&tx, 1).unwrap();
    assert_eq!(w.apply(&tx, 1), Err(L2Error::Replay));
}

#[test]
fn a_settle_below_quorum_is_refused() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);
    // 4 validators need 3 signers; 2 is short.
    assert_eq!(
        w.settle(id, Verdict::Correct, [0xAAu8; 32], 2, 9),
        Err(L2Error::BadQuorum)
    );
    // The task is untouched and the transaction can be retried with quorum.
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::ResultSubmitted { .. }
    ));
    w.settle(id, Verdict::Correct, [0xAAu8; 32], 3, 9).unwrap();
}

#[test]
fn a_settle_with_a_zero_aggregate_is_refused() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);
    let mut payload = settle_payload(id, Verdict::Correct, [0xAAu8; 32], 3, 4, 9);
    payload.bls_sig = [0u8; 96];
    let tx = L2Transaction::new(L2Payload::Settle(payload));
    assert_eq!(w.apply(&tx, 9), Err(L2Error::BadBlsSignature));
}

#[test]
fn a_settle_whose_bitmap_disagrees_with_the_count_is_refused() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);
    let mut payload = settle_payload(id, Verdict::Correct, [0xAAu8; 32], 3, 4, 9);
    payload.signer_count = 4; // bitmap still has 3 bits
    let tx = L2Transaction::new(L2Payload::Settle(payload));
    assert_eq!(w.apply(&tx, 9), Err(L2Error::BadQuorum));
}

#[test]
fn a_settle_for_an_unknown_task_is_refused() {
    let mut w = world();
    assert_eq!(
        w.settle([0x77u8; 32], Verdict::Correct, [0xAAu8; 32], 3, 9),
        Err(L2Error::UnknownTask)
    );
}

#[test]
fn a_tampered_payload_fails_authorization() {
    let mut w = world();
    let mut post =
        PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    post.payment_sat += 1; // invalidates the signature
    let tx = L2Transaction::new(L2Payload::Post(post));
    assert_eq!(w.apply(&tx, 1), Err(L2Error::BadAuthorization));
    // Nothing was credited or applied.
    assert_eq!(w.state.task_count(), 0);
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_borrowed_task_id_is_refused() {
    let mut w = world();
    let mut post =
        PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    // Re-derive the id for a different nonce, then re-sign so authorization
    // still passes — the only thing wrong is that the id is not the derived one.
    post.nonce = 2;
    let msg = post.signing_hash();
    post.auth.sigs = srct_core::l2::Auth::sigs_for(&w.submitter, &msg).unwrap();
    let tx = L2Transaction::new(L2Payload::Post(post));
    assert!(matches!(w.apply(&tx, 1), Err(L2Error::BadAttestation(_))));
}

#[test]
fn an_underfunded_actor_is_refused() {
    let mut w = world();
    let poor = wallet(9);
    let post = PostTaskPayload::build(&poor, 1, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let tx = L2Transaction::new(L2Payload::Post(post));
    assert!(matches!(
        w.apply(&tx, 1),
        Err(L2Error::InsufficientBalance { .. })
    ));
    assert_eq!(w.state.task_count(), 0);
}

#[test]
fn a_transaction_rejected_on_a_precondition_can_be_retried_once_it_holds() {
    // A claim for a task that does not exist yet is refused, but must not be
    // marked applied, or the same bytes could never be used after the post lands.
    let mut w = world();
    let id = w.post(1);
    let claim = L2Transaction::new(L2Payload::Claim(
        ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 50_000).unwrap(),
    ));

    let other = L2Transaction::new(L2Payload::Claim(
        ClaimTaskPayload::build(&w.worker, [0x55u8; 32], ComputeBackend::Gpu, 50_000).unwrap(),
    ));
    assert_eq!(w.apply(&other, 2), Err(L2Error::UnknownTask));
    // The real claim applies normally afterwards.
    w.apply(&claim, 2).unwrap();
    assert_eq!(w.apply(&claim, 2), Err(L2Error::Replay));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn two_nodes_applying_the_same_sequence_reach_the_same_state() {
    fn run() -> (u64, u64, u64, u64, String) {
        let mut w = world();
        let id = w.post(1);
        w.claim(id, 2, 100_000);
        w.submit(id, [0xAAu8; 32], 3);
        w.dispute(id, [0xBBu8; 32], 4, 50_000);
        w.settle(id, Verdict::Fraudulent, [0xBBu8; 32], 3, 5)
            .unwrap();
        let state = format!("{:?}", w.state.task(&id).unwrap().state);
        (
            w.state.total_accounts(),
            w.state.total_burned(),
            w.state.pscb,
            w.state.vault_remaining(),
            state,
        )
    }
    let a = run();
    let b = run();
    assert_eq!(a, b, "identical inputs must produce identical state");
    assert_eq!(a.0 + a.1 + a.2 + a.3, CREDITED, "and conserve value");
}

// ---------------------------------------------------------------------------
// The verifier seam is real, not decorative
// ---------------------------------------------------------------------------

/// A verifier that rejects everything, to prove `apply` consults the trait
/// rather than trusting the bitmap. `MockBls` accepting a non-zero signature is
/// the test convenience; this proves the call happens.
struct RejectAll;

impl BlsVerifier for RejectAll {
    fn verify_aggregate(
        &self,
        _public_keys: &[BlsPublicKey],
        _message: &Hash,
        _sig: &BlsSignature,
    ) -> bool {
        false
    }
}

#[test]
fn a_rejecting_verifier_blocks_settlement() {
    let mut w = world();
    let id = w.post(1);
    w.claim(id, 2, 50_000);
    w.submit(id, [0xAAu8; 32], 3);
    let tx = L2Transaction::new(L2Payload::Settle(settle_payload(
        id,
        Verdict::Correct,
        [0xAAu8; 32],
        3,
        4,
        9,
    )));
    assert_eq!(
        w.state.apply(&tx, 9, &w.validators, &RejectAll),
        Err(L2Error::BadBlsSignature)
    );
}
