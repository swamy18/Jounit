//! The worker lifecycle through the SDK (SPEC.md §18.4–§18.9).
//!
//! Discover → claim → execute → submit → dispute window → settle → VWC →
//! earnings, then the idempotency flows: restart after claim, restart after
//! submission, timeout-then-reconcile, duplicate-claim behaviour.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::{addr, advance, client_config, wallet, Core, RealVerifier, TestNet, TestView};
use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{L2Payload, L2Transaction, PostTaskPayload, SettlePayload, Verdict};
use jnt_worker::node::Host;
use jnt_worker::{ClaimedState, CpuExecutor, SubmittedState, WorkerClient, WorkerError};

const CREDITED: u64 = 30_000_000;
const ESCROW: u64 = 1_000_000;
const DEADLINE: u64 = 100;

fn task(expiry: u64) -> ComputeTask {
    ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 0,
        expiry_height: expiry,
        submit_height: 0,
    }
}

/// Post a task as the test's submitter. `nonce` distinguishes posts.
fn post_task(core: &Rc<RefCell<Core>>, escrow: u64, deadline: u64) -> Hash {
    let submitter = wallet(1);
    let n = {
        let c = core.borrow();
        c.state.task_count() as u64 + 1
    };
    let post = PostTaskPayload::build(&submitter, n, escrow, deadline, task(deadline)).unwrap();
    let id = post.task_id;
    let tx = L2Transaction::new(L2Payload::Post(post));
    core.borrow_mut().apply(&tx).expect("post applies");
    id
}

/// A client over the shared core; `which` selects the worker wallet (2 or 3).
fn client_for(core: &Rc<RefCell<Core>>, seed: u8) -> WorkerClient<TestView, TestNet, CpuExecutor> {
    let w = wallet(seed);
    let validators = common::bls::validator_set(4);
    let host = Host::new(TestView::new(core), TestNet::new(core));
    let config = client_config(&w);
    WorkerClient::new(host, w, CpuExecutor::default(), validators, &RealVerifier)
        .with_config(config)
        .unwrap()
}

/// A settle transaction with a genuine quorum aggregate from the harness
/// validators (what the arbitrator set would broadcast).
fn signed_settle(
    _core: &Rc<RefCell<Core>>,
    id: Hash,
    verdict: Verdict,
    vwc_hash: Hash,
) -> L2Transaction {
    let validators = common::bls::validator_set(4);
    let secrets = common::bls::validator_secrets(4);
    let payload = SettlePayload {
        task_id: id,
        verdict,
        vwc_hash,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
    };
    let msg = payload.signing_hash();
    let quorum = validators.quorum_size();
    let indices: Vec<usize> = (0..quorum).collect();
    let bitmap = validators.bitmap_from_indices(&indices);
    let signers = validators.signers_from_bitmap(&bitmap);
    let sigs: Vec<_> = signers
        .iter()
        .map(|pk| {
            let sk = secrets
                .iter()
                .find(|sk| sk.public_key().0 == pk.0)
                .expect("set keys come from harness secrets");
            sk.sign(&msg)
        })
        .collect();
    let payload = SettlePayload {
        bls_sig: *jnt_core::bls::RealBls::aggregate(&sigs).unwrap().as_bytes(),
        signer_bitmap: bitmap,
        signer_count: quorum as u32,
        ..payload
    };
    L2Transaction::new(L2Payload::Settle(payload))
}

/// Helper: the full happy path, returning (task_id, worker client's wallet
/// address) — used by the earnings and VWC tests.
fn happy_path_to_settled(core: &Rc<RefCell<Core>>) -> (Hash, Address) {
    let id = post_task(core, ESCROW, DEADLINE);

    let mut w = client_for(core, 2);
    let plan = w.claim(id).unwrap();
    assert_eq!(plan.task_id, id);

    let submitted = w.execute_and_submit(id).unwrap();
    assert_eq!(submitted.task_id, id);

    // Dispute window closes; the task auto-settles Correct at height 9
    // (mini window: 5; submitted at 1 → auto-settle after 6).
    advance(core, 9);

    (id, addr(&w.wallet))
}

// ---------------------------------------------------------------------------
// Discovery (§18.4)
// ---------------------------------------------------------------------------

#[test]
fn discovery_surfaces_open_funded_tasks_in_sorted_order() {
    let mut core = Core::new(CREDITED);
    core.height = 5;
    let core = Rc::new(std::cell::RefCell::new(core));

    let a = post_task(&core, 2_000_000, 100);
    let b = post_task(&core, 3_000_000, 100);

    let w = client_for(&core, 2);
    let ids: Vec<Hash> = w
        .discover()
        .unwrap()
        .into_iter()
        .map(|t| t.task_id)
        .collect();
    let mut expected = vec![a, b];
    expected.sort_unstable();
    assert_eq!(ids, expected);
}

#[test]
fn discovery_never_exposes_unavailable_states_or_unaffordable_claims() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let w2 = client_for(&core, 2);

    let id = post_task(&core, ESCROW, DEADLINE);
    // Before claim: visible.
    assert_eq!(w2.discover().unwrap().len(), 1);
    // After claim: not available any more.
    let mut w2 = w2;
    w2.claim(id).unwrap();
    assert!(w2.discover().unwrap().is_empty());

    // A worker who cannot afford the deposit sees nothing.
    let mut broke = client_for(&core, 3);
    broke.config.worker_deposit_sat = u64::MAX - 1000;
    // Force the balance check by clearing the filter's effect via huge
    // deposit — the worker's own balance cannot cover it.
    assert!(broke.discover().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Claim → execute → submit → settle (§18.5–§18.9)
// ---------------------------------------------------------------------------

#[test]
fn claim_then_submit_then_auto_settle_then_vwc_then_earnings() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let (id, worker_addr) = happy_path_to_settled(&core);

    // Restart a fresh client and verify the observation surfaces.
    let w = client_for(&core, 2);
    assert_eq!(
        w.reconcile_submission(&id).unwrap(),
        SubmittedState::Submitted
    );

    // The certificate exists and validates (implicit → WindowElapsed).
    let cert = w.certificate(&id).unwrap().expect("auto-settle certifies");
    assert_eq!(cert.worker, worker_addr);
    assert_eq!(cert.payment_sat, ESCROW); // implicit settle: no fee

    let e = w.earnings().unwrap();
    assert_eq!(e.settled_sat, ESCROW + 100_000); // no fee on implicit settle; deposit returned
    assert_eq!(
        e.available_sat,
        CREDITED - 100_000 - 2_000 + ESCROW + 100_000 - 2_000
    );
    assert_eq!(e.pending_sat, 0);
    assert_eq!(e.deposits_at_risk_sat, 0);
    assert_eq!(e.lost_sat, 0);
}

#[test]
fn explicit_settle_credits_exactly_escrow_minus_fee() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    let mut w = client_for(&core, 2);
    w.claim(id).unwrap();
    w.execute_and_submit(id).unwrap();

    // The settle names the submitted result — recompute it the way the
    // protocol saw it (the executor's output hash).
    let state = core.borrow().state.clone();
    let submitted = match &state.task(&id).unwrap().state {
        jnt_l2::ContractState::ResultSubmitted { result_hash, .. } => *result_hash,
        other => panic!("expected ResultSubmitted, got {other:?}"),
    };
    let tx = signed_settle(&core, id, Verdict::Correct, submitted);
    {
        let mut c = core.borrow_mut();
        c.height = 7; // past the mini dispute window (submitted at height 1)
        c.apply(&tx).unwrap();
    }

    let cert = w.certificate(&id).unwrap().unwrap();
    assert_eq!(cert.payment_sat, ESCROW - 1_000);
    let e = w.earnings().unwrap();
    // settled includes the returned deposit (worker_paid + deposit_returned).
    assert_eq!(e.settled_sat, ESCROW - 1_000 + 100_000);
    assert_eq!(
        e.available_sat,
        CREDITED - 100_000 - 2_000 + ESCROW - 1_000 + 100_000 - 2_000
    );
}

// ---------------------------------------------------------------------------
// Idempotency: timeouts, restarts, duplicates (§18.9)
// ---------------------------------------------------------------------------

#[test]
fn timeout_after_claim_broadcast_is_reconciled_not_retried_blindly() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    let w = client_for(&core, 2);
    // Broadcast "times out" — but apply先 happens before the error can be
    // returned, so emulate a timeout that left the tx landed by applying
    // manually and then failing the next broadcast.
    let plan = w.claim_build(id).unwrap();
    core.borrow_mut().apply(&plan.tx).unwrap();

    // The SDK's answer to "did it land?" is reconciliation, and it says yes.
    assert_eq!(w.reconcile_claim(&id).unwrap(), ClaimedState::InProgress);

    // A re-broadcast of the same bytes (same txid) is refused by the
    // protocol's replay guard, not by a mutated resend.
    core.borrow_mut().apply(&plan.tx).unwrap_err();
}

#[test]
fn restart_after_claim_resumes_instead_of_reclaiming() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    {
        let mut w = client_for(&core, 2);
        w.claim(id).unwrap();
    } // client dropped: restart

    let w = client_for(&core, 2);
    // A discovery pass must not re-offer the task it already owns…
    assert!(w.discover().unwrap().is_empty());
    // …and reconciliation says: still ours, in progress.
    assert_eq!(w.reconcile_claim(&id).unwrap(), ClaimedState::InProgress);
}

#[test]
fn restart_after_submission_sees_the_recorded_result() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    {
        let mut w = client_for(&core, 2);
        w.claim(id).unwrap();
        w.execute_and_submit(id).unwrap();
    }

    let w = client_for(&core, 2);
    assert_eq!(
        w.reconcile_submission(&id).unwrap(),
        SubmittedState::Submitted
    );
    // And reconcile_claim matches the state's actual shape.
    assert_eq!(w.reconcile_claim(&id).unwrap(), ClaimedState::Submitted);
}

#[test]
fn reconcile_after_timeout_that_did_not_land_says_await() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    let mut w = client_for(&core, 2);
    // Broadcast refused before applying (fail_next).
    core.borrow_mut()
        .fail_next
        .push(jnt_worker::node::BroadcastError::Retryable(
            "socket reset".into(),
        ));
    match w.claim(id) {
        Err(WorkerError::BroadcastUnavailable(_)) => {}
        other => panic!("expected a retryable broadcast failure, got {other:?}"),
    }
    // The tx never landed: reconciliation says the claim is not visible.
    assert!(matches!(
        w.reconcile_claim(&id),
        Err(WorkerError::UnknownTask) | Ok(ClaimedState::ClaimedByOther)
    ));
    // Re-broadcasting the SAME plan bytes is the §18.9 rule.
    let rebuilt = w.claim_build(id).unwrap();
    core.borrow_mut().apply(&rebuilt.tx).unwrap();
    assert_eq!(w.reconcile_claim(&id).unwrap(), ClaimedState::InProgress);
}

#[test]
fn duplicate_submission_after_restart_fails_closed_not_silently() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);
    let mut w = client_for(&core, 2);
    w.claim(id).unwrap();
    w.execute_and_submit(id).unwrap();
    // The state is ResultSubmitted now: a second submit is a TaskNotAvailable,
    // never a second broadcast.
    assert!(matches!(
        w.execute_and_submit(id),
        Err(WorkerError::TaskNotAvailable("ResultSubmitted"))
    ));
}

// ---------------------------------------------------------------------------
// Determinism (§18.15)
// ---------------------------------------------------------------------------

#[test]
fn claim_and_submit_plans_are_byte_deterministic_across_restarts() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);

    let w1 = client_for(&core, 2);
    let p1 = w1.claim_build(id).unwrap();
    let w2 = client_for(&core, 2);
    let p2 = w2.claim_build(id).unwrap();
    assert_eq!(p1.txid, p2.txid, "same state, same plan, same txid");
    assert_eq!(p1.tx.serialize(), p2.tx.serialize());
}

// ---------------------------------------------------------------------------
// Expiry (§18.9 clean exits)
// ---------------------------------------------------------------------------

#[test]
fn expired_task_after_claim_reports_expired_and_burned_deposit() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);
    let mut w = client_for(&core, 2);
    w.claim(id).unwrap();

    // Deadline 100; advance past it.
    advance(&core, 105);

    let w = client_for(&core, 2);
    assert_eq!(w.reconcile_claim(&id).unwrap(), ClaimedState::Expired);
    let e = w.earnings().unwrap();
    assert_eq!(e.lost_sat, 100_000, "the deposit burned in full");
    assert_eq!(w.certificate(&id).unwrap(), None, "expiry never certifies");
}

// ---------------------------------------------------------------------------
// Task-not-mine (§18.11): executing/submitting someone else's claim
// ---------------------------------------------------------------------------

#[test]
fn executing_and_submitting_another_workers_task_fails_closed() {
    let core = Rc::new(std::cell::RefCell::new(Core::new(CREDITED)));
    let id = post_task(&core, ESCROW, DEADLINE);
    let mut w2 = client_for(&core, 2);
    w2.claim(id).unwrap();

    let mut w3 = client_for(&core, 3);
    assert!(matches!(w3.execute(id), Err(WorkerError::IdentityMismatch)));
    assert!(matches!(
        w3.execute_and_submit(id),
        Err(WorkerError::IdentityMismatch)
    ));
    // And the protocol stores only worker 2's claim.
    let state = core.borrow().state.clone();
    assert_eq!(state.task(&id).unwrap().worker.unwrap(), addr(&wallet(2)));
}
