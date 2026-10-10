//! Phase 3: the complete dispute lifecycle through the public surface.
//!
//! Task creation → claim → submit → dispute → evidence → arbitration →
//! settlement, for every outcome, with the accounting invariants asserted after
//! each one. Security cases (replay, double settlement, unauthorized actors,
//! wrong settle hash, malformed evidence) are interleaved with the happy paths
//! rather than banished to a separate file, because the point is that a
//! *rejected* dispute leaves the state untouched and the value conserved.

use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{
    reference_result_hash, ComputeAttestation, ComputeBackend, ComputeTask,
};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::wallet::Wallet;
use jnt_l2::{
    Arbiter, ContractState, DisputeEngine, DisputeEvidence, DisputeVerdict, L2Config, L2Effect,
    L2Error, L2State,
};

const DEADLINE: u64 = 100;
const CREDITED: u64 = 30_000_000;
const SUBMITTED: Hash = [0xAAu8; 32];
const COUNTER: Hash = [0xBBu8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "dispute-flow").unwrap()
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

/// A bitmap with exactly `signed` low bits set, over a `total`-validator set.
fn quorum_bitmap(total: usize, signed: usize) -> Vec<u8> {
    let mut bitmap = vec![0u8; total.div_ceil(8).max(1)];
    for i in 0..signed {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    bitmap
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

    fn post(&mut self, payment: u64, height: u64) -> Hash {
        let post =
            PostTaskPayload::build(&self.submitter, 1, payment, DEADLINE, task(DEADLINE)).unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), height)
            .unwrap();
        id
    }

    /// The default scenario: post 1 000 000, claim with `deposit`, submit, dispute.
    /// Fixed garbage results — for tests that never arbitrate through the
    /// reference (lapse, evidence, replay, authorization).
    fn disputed(&mut self, deposit: u64) -> Hash {
        let id = self.post(1_000_000, 1);
        self.finish_dispute(id, deposit, SUBMITTED, COUNTER);
        id
    }

    /// The canonical CPU reference for a task (Decision 21): what an honest
    /// worker submits and what a truthful challenger counters with.
    fn reference(&self, id: Hash) -> Hash {
        let t = self.state.task(&id).unwrap();
        reference_result_hash(
            &t.task_id,
            &t.compute_task.ir_hash,
            &t.compute_task.input_hash,
            t.compute_task.required_memory_bytes,
        )
    }

    /// Dispute where the worker ran the reference: the challenger's counter
    /// is baseless and burns.
    fn disputed_worker_correct(&mut self, deposit: u64) -> Hash {
        let id = self.post(1_000_000, 1);
        let reference = self.reference(id);
        assert_ne!(reference, COUNTER, "test setup: counter must miss");
        self.finish_dispute(id, deposit, reference, COUNTER);
        id
    }

    /// Dispute where the worker lied and the challenger ran the reference:
    /// the worker is slashed and the challenger is rewarded.
    fn disputed_challenger_correct(&mut self, deposit: u64) -> Hash {
        let id = self.post(1_000_000, 1);
        let reference = self.reference(id);
        assert_ne!(reference, SUBMITTED, "test setup: submission must miss");
        self.finish_dispute(id, deposit, SUBMITTED, reference);
        id
    }

    fn finish_dispute(&mut self, id: Hash, deposit: u64, submitted: Hash, counter: Hash) {
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, deposit).unwrap(),
            )),
            2,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(
                    &self.worker,
                    id,
                    attestation(&self.worker, id, submitted),
                )
                .unwrap(),
            )),
            3,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Dispute(
                DisputePayload::build(
                    &self.challenger,
                    id,
                    counter,
                    attestation(&self.challenger, id, counter),
                    50_000,
                )
                .unwrap(),
            )),
            4,
        )
        .unwrap();
    }

    fn arbitrate(&self, id: Hash) -> Result<DisputeVerdict, L2Error> {
        DisputeEngine::resolve(self.state.task(&id).unwrap())
    }

    fn settle_verdict(&mut self, v: &DisputeVerdict, height: u64) -> Result<L2Effect, L2Error> {
        let quorum = self.validators.quorum_size();
        let payload = v.settle_payload(
            [0xAAu8; 96],
            quorum_bitmap(self.validators.len(), quorum),
            quorum as u32,
        )?;
        self.apply(&L2Transaction::new(L2Payload::Settle(payload)), height)
    }
}

// ---------------------------------------------------------------------------
// Honest worker wins
// ---------------------------------------------------------------------------

#[test]
fn honest_worker_wins_the_dispute_and_the_baseless_challenge_burns() {
    let mut w = world();
    let id = w.disputed_worker_correct(100_000);
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Disputed(_)
    ));

    // The reference reproduces the worker's result.
    let v = w.arbitrate(id).unwrap();
    assert_eq!(v.arbiter, Arbiter::WorkerCorrect);
    assert_eq!(v.verdict(), Some(Verdict::Correct));

    let effect = w.settle_verdict(&v, 5).unwrap();
    match effect {
        L2Effect::Settled {
            verdict,
            worker_paid,
            challenger_bonus,
            ..
        } => {
            assert_eq!(verdict, Verdict::Correct);
            assert_eq!(worker_paid, 1_000_000 - 1_000);
            assert_eq!(challenger_bonus, 0, "a failed challenge earns no bounty");
        }
        other => panic!("unexpected effect {other:?}"),
    }

    // Worker's deposit came back; the challenger lost the deposit and the fee.
    assert_eq!(
        w.state.balance(&addr(&w.worker)),
        10_000_000 - 2_000 - 2_000 + 999_000
    );
    assert_eq!(w.state.balance(&addr(&w.challenger)), 10_000_000 - 60_000);
    assert_eq!(w.state.conservation_total(), CREDITED);
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Settled(_)
    ));
}

// ---------------------------------------------------------------------------
// Fraudulent worker
// ---------------------------------------------------------------------------

#[test]
fn fraudulent_worker_is_slashed_and_the_whistleblower_is_rewarded() {
    let mut w = world();
    let id = w.disputed_challenger_correct(100_000);
    let pscb_before = w.state.pscb;

    let v = w.arbitrate(id).unwrap();
    assert_eq!(v.arbiter, Arbiter::ChallengerCorrect);
    assert_eq!(v.verdict(), Some(Verdict::Fraudulent));

    let effect = w.settle_verdict(&v, 5).unwrap();
    let slashed = 100_000 - 1_000;
    // 25% of the slashed amount (24 750) exceeds the 9 500 sat reserve, so the
    // bounty is capped at the reserve balance.
    let bounty = ((slashed as u128 * 25 / 100) as u64).min(pscb_before);
    match effect {
        L2Effect::Settled {
            submitter_refunded,
            worker_deposit_slashed,
            challenger_bonus,
            ..
        } => {
            assert_eq!(submitter_refunded, 1_000_000);
            assert_eq!(worker_deposit_slashed, slashed);
            assert_eq!(challenger_bonus, bounty);
            assert_eq!(bounty, pscb_before, "the bounty consumed the whole reserve");
        }
        other => panic!("unexpected effect {other:?}"),
    }

    // M2: half the slashed deposit burned instantly, half vesting.
    assert_eq!(w.state.slash_vault.total_burned, slashed / 2);
    assert_eq!(w.state.vault_remaining(), slashed - slashed / 2);
    // Challenger: dispute fee paid, deposit back, plus the bounty.
    assert_eq!(
        w.state.balance(&addr(&w.challenger)),
        10_000_000 - 10_000 + bounty
    );
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_small_slash_pays_the_uncapped_bounty() {
    // Deposit 30 000 → 29 000 slashed → 7 250 wanted, under the 9 500 reserve,
    // so the full 25% is paid rather than the cap.
    let mut w = world();
    let id = w.disputed_challenger_correct(30_000);
    let pscb_before = w.state.pscb;
    let v = w.arbitrate(id).unwrap();

    let effect = w.settle_verdict(&v, 5).unwrap();
    match effect {
        L2Effect::Settled {
            challenger_bonus, ..
        } => {
            assert_eq!(challenger_bonus, 29_000 * 25 / 100);
            assert!(
                challenger_bonus < pscb_before,
                "this case must not hit the cap"
            );
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Inconclusive
// ---------------------------------------------------------------------------

#[test]
fn an_inconclusive_reference_settles_nothing() {
    let mut w = world();
    let id = w.disputed(100_000);
    let before = (
        w.state.total_accounts(),
        w.state.pscb,
        w.state.vault_remaining(),
    );

    let v = w.arbitrate(id).unwrap();
    assert_eq!(v.arbiter, Arbiter::Inconclusive);
    assert_eq!(w.settle_verdict(&v, 5), Err(L2Error::InconclusiveDispute));

    // Nothing moved, nothing was slashed, and the task is still disputed.
    assert_eq!(
        (
            w.state.total_accounts(),
            w.state.pscb,
            w.state.vault_remaining()
        ),
        before
    );
    assert_eq!(
        w.state.slash_vault.active_count(),
        0,
        "no slash on inconclusive"
    );
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Disputed(_)
    ));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn an_inconclusive_dispute_can_still_lapse_later() {
    let mut w = world();
    let id = w.disputed(100_000);
    // Filed at 4, resolution window 5 → lapses strictly after 9.
    assert!(w.state.advance_block(9).is_empty(), "not yet lapsed");
    let effects = w.state.advance_block(10);
    assert_eq!(effects.len(), 1);
    assert!(matches!(
        effects[0],
        L2Effect::Settled {
            verdict: Verdict::Correct,
            ..
        }
    ));
    // The challenger's deposit was burned on lapse.
    assert_eq!(w.state.balance(&addr(&w.challenger)), 10_000_000 - 60_000);
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Settled(_)
    ));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[test]
fn evidence_is_only_readable_from_a_disputed_contract() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    // Open: no evidence to read.
    assert!(matches!(
        DisputeEngine::resolve(w.state.task(&id).unwrap()),
        Err(L2Error::IllegalTransition { .. })
    ));

    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();
    // ResultSubmitted but not yet disputed.
    assert!(matches!(
        DisputeEngine::resolve(w.state.task(&id).unwrap()),
        Err(L2Error::IllegalTransition { .. })
    ));
}

#[test]
fn evidence_read_from_a_disputed_contract_is_complete_and_valid() {
    let mut w = world();
    let id = w.disputed(100_000);
    let evidence = DisputeEvidence::from_contract(w.state.task(&id).unwrap()).unwrap();
    assert_eq!(evidence.task_id, id);
    assert_eq!(evidence.submitted_result, SUBMITTED);
    assert_eq!(evidence.counter_result, COUNTER);
    evidence.validate().unwrap();
}

// ---------------------------------------------------------------------------
// Boundary amounts
// ---------------------------------------------------------------------------

#[test]
fn a_payment_equal_to_the_settle_fee_settles_with_a_zero_payout() {
    let mut w = world();
    let id = w.post(1_000, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 100_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();
    let effect = w
        .apply(
            &L2Transaction::new(L2Payload::Settle(jnt_core::l2::SettlePayload {
                task_id: id,
                verdict: Verdict::Correct,
                vwc_hash: SUBMITTED,
                bls_sig: [0xAAu8; 96],
                signer_bitmap: quorum_bitmap(4, 3),
                signer_count: 3,
            })),
            9,
        )
        .unwrap();
    match effect {
        L2Effect::Settled {
            worker_paid,
            submitter_refunded,
            ..
        } => {
            assert_eq!(worker_paid, 0, "escrow exactly covered the settle fee");
            assert_eq!(submitter_refunded, 0);
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_payment_below_the_settle_fee_is_refused_and_not_settled() {
    let mut w = world();
    let id = w.post(999, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 100_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();
    let err = w.apply(
        &L2Transaction::new(L2Payload::Settle(jnt_core::l2::SettlePayload {
            task_id: id,
            verdict: Verdict::Correct,
            vwc_hash: SUBMITTED,
            bls_sig: [0xAAu8; 96],
            signer_bitmap: quorum_bitmap(4, 3),
            signer_count: 3,
        })),
        9,
    );
    assert_eq!(
        err,
        Err(L2Error::AmountTooSmallForFee {
            available: 999,
            fee: 1_000
        })
    );
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::ResultSubmitted { .. }
    ));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[test]
fn a_zero_deposit_dispute_is_refused() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();
    let err = w.apply(
        &L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &w.challenger,
                id,
                COUNTER,
                attestation(&w.challenger, id, COUNTER),
                0,
            )
            .unwrap(),
        )),
        4,
    );
    assert_eq!(err, Err(L2Error::ZeroAmount("challenge_deposit_sat")));
}

#[test]
fn an_unauthorized_challenger_is_refused() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();

    // Signed by the challenger but claiming someone else's address.
    let mut payload = DisputePayload::build(
        &w.challenger,
        id,
        COUNTER,
        attestation(&w.challenger, id, COUNTER),
        50_000,
    )
    .unwrap();
    payload.challenger = addr(&w.worker);
    let err = w.apply(&L2Transaction::new(L2Payload::Dispute(payload)), 4);
    assert_eq!(err, Err(L2Error::BadAuthorization));
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::ResultSubmitted { .. }
    ));
}

#[test]
fn a_second_dispute_is_refused() {
    let mut w = world();
    let id = w.disputed(100_000);
    // A *different* counter-result, so this is a genuinely new transaction and
    // the refusal has to come from the state machine rather than from replay.
    let payload = DisputePayload::build(
        &w.challenger,
        id,
        [0xCCu8; 32],
        attestation(&w.challenger, id, [0xCCu8; 32]),
        50_000,
    )
    .unwrap();
    assert!(matches!(
        w.apply(&L2Transaction::new(L2Payload::Dispute(payload)), 5),
        Err(L2Error::IllegalTransition { .. })
    ));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_replayed_dispute_transaction_is_refused() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 100_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();

    let tx = L2Transaction::new(L2Payload::Dispute(
        DisputePayload::build(
            &w.challenger,
            id,
            COUNTER,
            attestation(&w.challenger, id, COUNTER),
            50_000,
        )
        .unwrap(),
    ));
    w.apply(&tx, 4).unwrap();
    assert_eq!(w.apply(&tx, 4), Err(L2Error::Replay));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_settle_hash_that_does_not_match_the_verdict_is_refused() {
    let mut w = world();
    let id = w.disputed(100_000);
    // Claim Fraudulent but hand over the *submitted* hash.
    let payload = jnt_core::l2::SettlePayload {
        task_id: id,
        verdict: Verdict::Fraudulent,
        vwc_hash: SUBMITTED,
        bls_sig: [0xAAu8; 96],
        signer_bitmap: quorum_bitmap(4, 3),
        signer_count: 3,
    };
    assert_eq!(
        w.apply(&L2Transaction::new(L2Payload::Settle(payload)), 5),
        Err(L2Error::BadVwcHash)
    );
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Disputed(_)
    ));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_task_cannot_be_settled_twice_or_slashed_twice() {
    let mut w = world();
    let id = w.disputed_challenger_correct(100_000);
    let v = w.arbitrate(id).unwrap();
    w.settle_verdict(&v, 5).unwrap();
    assert_eq!(w.state.slash_vault.active_count(), 1);

    // A second settlement is an illegal transition. A *different* verdict, so
    // the refusal is the state machine refusing to settle twice rather than the
    // replay guard refusing identical bytes.
    let again = jnt_core::l2::SettlePayload {
        task_id: id,
        verdict: Verdict::Correct,
        vwc_hash: SUBMITTED,
        bls_sig: [0xAAu8; 96],
        signer_bitmap: quorum_bitmap(4, 3),
        signer_count: 3,
    };
    assert!(matches!(
        w.apply(&L2Transaction::new(L2Payload::Settle(again)), 6),
        Err(L2Error::IllegalTransition { .. })
    ));
    // Exactly one slash record: the worker's deposit was slashed once.
    assert_eq!(w.state.slash_vault.active_count(), 1);
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_challenge_that_agrees_with_the_result_is_refused() {
    let mut w = world();
    let id = w.post(1_000_000, 1);
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, SUBMITTED))
                .unwrap(),
        )),
        3,
    )
    .unwrap();
    let err = w.apply(
        &L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &w.challenger,
                id,
                SUBMITTED,
                attestation(&w.challenger, id, SUBMITTED),
                50_000,
            )
            .unwrap(),
        )),
        4,
    );
    assert_eq!(err, Err(L2Error::DisputeAgreesWithResult));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn an_arbitrated_settlement_is_deterministic_across_independent_runs() {
    // Each scenario runs twice from a fresh world: identical inputs must
    // produce identical state, and value must conserve on every path —
    // worker-correct, challenger-correct, and inconclusive.
    fn run(worker_correct: Option<bool>) -> (u64, u64, u64, u64, u64, String) {
        let mut w = world();
        let id = match worker_correct {
            Some(true) => w.disputed_worker_correct(100_000),
            Some(false) => w.disputed_challenger_correct(100_000),
            None => w.disputed(100_000),
        };
        let v = w.arbitrate(id).unwrap();
        // An inconclusive arbitration has no payload to settle with; both runs
        // must fail the same way and leave the same state.
        let outcome = match w.settle_verdict(&v, 5) {
            Ok(e) => format!("{e:?}"),
            Err(e) => format!("refused: {e:?}"),
        };
        (
            w.state.total_accounts(),
            w.state.total_burned(),
            w.state.pscb,
            w.state.vault_remaining(),
            w.state.total_locked(),
            format!("{:?}", w.state.task(&id).unwrap().state) + &outcome,
        )
    }

    for scenario in [Some(true), Some(false), None] {
        let a = run(scenario);
        let b = run(scenario);
        assert_eq!(a, b, "identical inputs must produce identical state");
        assert_eq!(
            a.0 + a.1 + a.2 + a.3 + a.4,
            CREDITED,
            "and conserve value, whether or not the task settled"
        );
    }
}

// ---------------------------------------------------------------------------
// The quorum gate still authorizes settlement (a dispute cannot bypass it)
// ---------------------------------------------------------------------------

#[test]
fn a_dispute_verdict_still_needs_a_validator_quorum_to_settle() {
    let mut w = world();
    let id = w.disputed_challenger_correct(100_000);
    let v = w.arbitrate(id).unwrap();

    // A payload the *engine* produced, but with too few signers.
    let payload = v
        .settle_payload([0xAAu8; 96], quorum_bitmap(4, 2), 2)
        .unwrap();
    assert_eq!(
        w.apply(&L2Transaction::new(L2Payload::Settle(payload)), 5),
        Err(L2Error::BadQuorum)
    );
    assert!(
        matches!(w.state.task(&id).unwrap().state, ContractState::Disputed(_)),
        "a settlement without quorum must leave the task disputed"
    );
    assert_eq!(w.state.conservation_total(), CREDITED);

    // With quorum it applies.
    w.settle_verdict(&v, 5).unwrap();
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Settled(_)
    ));
}
