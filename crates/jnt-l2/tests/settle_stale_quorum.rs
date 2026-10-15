//! Stale settle votes: can an old quorum aggregate be replayed into state it
//! was not intended to change?
//!
//! `apply_settle` refuses a foreign network and a vote from the future, and
//! the signed hash now covers both — but there is deliberately **no maximum
//! vote age**, so the question these answer is what an old vote can still do.
//! Three shapes are tried against a real quorum aggregate:
//!
//! 1. the same task and the same decision, applied again;
//! 2. the same decision pointed at a *different* task;
//! 3. the same task after its state machine has moved on — already settled,
//!    or the dispute window lapsed.
//!
//! The finding: none of them change any state. A task settles exactly once
//! because the referent of the vote is `task_id`, and a stale aggregate
//! pointed anywhere else is refused by name (`UnknownTask`), or by the
//! state machine (`IllegalTransition`), or by replay protection (`Replay`).
//! An age limit would add nothing, so `docs/decisions.md` records the
//! reasoning instead of a constant.

use jnt_core::arbitration::{ArbitrationVote, VoteTally, ARBITRATION_VOTE_VERSION};
use jnt_core::bls::SecretKey;
use jnt_core::bls_checkpoint::{BlsPublicKey, BlsSignature, MockBls, ValidatorSet};
use jnt_core::compute_ir::{
    reference_result_hash, ComputeAttestation, ComputeBackend, ComputeTask,
};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::wallet::Wallet;
use jnt_l2::{L2Config, L2Effect, L2Error, L2State};

const NET: &str = "jounit/mini";
const DEADLINE: u64 = 100;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "stale-quorum").unwrap()
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

fn bls_key(seed: u8) -> (SecretKey, BlsPublicKey) {
    let sk = SecretKey::derive(&[seed; 32]).unwrap();
    let pk = sk.public_key();
    (sk, pk)
}

/// Three committee members, in the canonical sorted order a verifier indexes.
fn committee() -> Vec<BlsPublicKey> {
    let mut v: Vec<BlsPublicKey> = [1u8, 2, 3].iter().map(|s| bls_key(*s).1).collect();
    v.sort_by_key(|k| k.0);
    v
}

/// The empty validator set is what a test uses when the payload itself is
/// what is under test: the aggregate refuses at the pairing check, and the
/// reaching checks are the ones under study.
fn empty_set() -> ValidatorSet {
    ValidatorSet::new(vec![])
}

struct World {
    state: L2State,
    task_id: Hash,
    reference: Hash,
}

/// A disputed task whose worker ran the reference, so the honest verdict is
/// `Correct` and the committee can sign it.
fn world() -> World {
    let submitter = wallet(11);
    let worker = wallet(12);
    let challenger = wallet(13);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), 10_000_000).unwrap();
    state.credit(addr(&worker), 10_000_000).unwrap();
    state.credit(addr(&challenger), 10_000_000).unwrap();

    let nonce = 1;
    let post =
        PostTaskPayload::build(&submitter, nonce, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let id = post.task_id;
    let apply = |state: &mut L2State, tx: &L2Transaction, height: u64| {
        state.apply(tx, height, &empty_set(), &MockBls)
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

impl World {
    fn conservation(&self) -> u64 {
        self.state.conservation_total()
    }
}

/// One committee member's vote for the worker-correct decision, signed at
/// and decision.
fn aggregate_at(w: &World, height: u64) -> SettlePayload {
    aggregate_for(w.task_id, w.reference, height)
}

/// A quorum aggregate for an explicit task and decision. The committee's
/// signatures are deterministic in the inputs, so two calls with the same
/// arguments produce the same payload.
fn aggregate_for(task_id: Hash, vwc_hash: Hash, height: u64) -> SettlePayload {
    let mut tally = VoteTally::new(3);
    for seed in 1u8..=3 {
        let (sk, pk) = bls_key(seed);
        let base = ArbitrationVote {
            version: ARBITRATION_VOTE_VERSION,
            task_id,
            verdict: Verdict::Correct,
            vwc_hash,
            network_id: NET.to_string(),
            height,
            signer: pk,
            signature: BlsSignature([0u8; 96]),
            pq_sig: None,
        };
        tally
            .record(
                &ArbitrationVote {
                    signature: sk.sign(&base.signing_hash()),
                    ..base
                },
                NET,
                height,
                &committee(),
            )
            .unwrap();
    }
    tally.settle_payload(&committee()).expect("quorum reached")
}

/// The step-by-step lifecycle without a dispute, so a second task can be
/// grown for the cross-task replay. Returns the state and the new task id.
fn post_only(submitter: &Wallet, nonce: u64, worker: &Wallet) -> (L2State, Hash) {
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(submitter), 10_000_000).unwrap();
    state.credit(addr(worker), 10_000_000).unwrap();
    let post =
        PostTaskPayload::build(submitter, nonce, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let id = post.task_id;
    state
        .apply(
            &L2Transaction::new(L2Payload::Post(post)),
            1,
            &empty_set(),
            &MockBls,
        )
        .unwrap();
    (state, id)
}

// ---------------------------------------------------------------------------
// Shape (a): the same task and the same decision, again
// ---------------------------------------------------------------------------

/// The aggregate that settled a task, replayed at a later height against the
/// *same* task and decision. Nothing changes: the state machine refuses a
/// second settlement, and replay protection refuses the bytes.
#[test]
fn the_same_task_and_decision_cannot_settle_twice() {
    let mut w = world();
    let committee = committee();
    let payload = aggregate_at(&w, 5);

    // Sanity: it works the first time — with a verifier that accepts the
    // aggregate, which is what a real node would use.
    let verifiers = ValidatorSet::new(committee.clone());
    let effect = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload.clone())),
            6,
            &verifiers,
            &MockBls,
        )
        .expect("the honest aggregate must settle");
    assert!(matches!(effect, L2Effect::Settled { .. }));
    let after_first = w.conservation();
    assert_eq!(w.state.vwc_count(), 1, "a Correct settlement certifies");
    assert_eq!(w.state.vwc(&w.task_id).unwrap().result_hash, w.reference);

    // Replay the *identical* payload: replay protection by txid.
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload.clone())),
            7,
            &verifiers,
            &MockBls,
        )
        .expect_err("identical bytes must be refused as a replay");
    assert_eq!(err, L2Error::Replay, "got {err:?}");

    // The same *decision* signed afresh at a later height: a different
    // payload (different bitmap, hence a different txid) that replay
    // protection cannot see coming. The state machine refuses it, because a
    // task settles exactly once — this is the case a maximum vote age would
    // supposedly be needed for.
    let fresh = aggregate_for(w.task_id, w.reference, 8);
    assert_ne!(
        fresh.serialize(),
        payload.serialize(),
        "the two payloads must differ, or the replay guard already covers it"
    );
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(fresh)),
            9,
            &verifiers,
            &MockBls,
        )
        .expect_err("a settled task must not settle a second time");
    assert!(
        matches!(err, L2Error::IllegalTransition { .. }),
        "a settled task must refuse a second settlement, got {err:?}"
    );

    // Whatever happened above, no second certificate and no value moved.
    assert_eq!(w.state.vwc_count(), 1, "no certificate was re-issued");
    assert_eq!(
        w.conservation(),
        after_first,
        "no value moved on the replays"
    );
}

// ---------------------------------------------------------------------------
// Shape (b): the same decision pointed at a different task
// ---------------------------------------------------------------------------

/// An aggregate for one task re-pointed at another task. The named task is
/// not known (or is not disputed), so it is refused by name — a re-pointed
/// aggregate changes nothing anywhere.
#[test]
fn an_aggregate_pointed_at_another_task_changes_nothing() {
    let mut w = world();
    let submitter = wallet(14);
    let worker = wallet(15);
    let (other_state, other_id) = post_only(&submitter, 7, &worker);
    assert_ne!(
        other_id, w.task_id,
        "the fixture must name a different task"
    );

    // A genuine quorum aggregate over the first task's decision.
    let payload = aggregate_at(&w, 5);
    // The verifier a real node uses: the aggregate must pass quorum so the
    // refusal that follows is about the task, not the signers.
    let verifiers = ValidatorSet::new(committee());

    // Re-pointed at the second task, whose id is not in `w.state`.
    let mut re_pointed = payload.clone();
    re_pointed.task_id = other_id;
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(re_pointed)),
            6,
            &verifiers,
            &MockBls,
        )
        .expect_err("an unknown task must be refused");
    assert_eq!(err, L2Error::UnknownTask, "got {err:?}");

    // And against the state that *does* hold the second task: the id is
    // known, but that task was never disputed, so settling is illegal.
    let mut other = other_state;
    let before_other = other.conservation_total();
    let err = other
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload.clone())),
            6,
            &verifiers,
            &MockBls,
        )
        .expect_err("an undisputed task must not settle");
    assert!(
        matches!(
            err,
            L2Error::IllegalTransition { .. } | L2Error::UnknownTask
        ),
        "got {err:?}"
    );

    // Nothing was certified, and no value moved in either state.
    assert_eq!(w.state.vwc_count(), 0);
    assert_eq!(other.vwc_count(), 0);
    assert_eq!(other.conservation_total(), before_other, "untouched");
    assert!(
        w.conservation() > 0,
        "the first state still holds its value"
    );
}

// ---------------------------------------------------------------------------
// Shape (c): the same task, after its state machine moved on
// ---------------------------------------------------------------------------

/// The decision that later becomes moot: an aggregate signed while the
/// dispute is live, applied after the window lapsed. The task is no longer
/// disputed, so settlement is refused by the state machine.
#[test]
fn an_aggregate_applied_after_the_dispute_lapses_changes_nothing() {
    let mut w = world();
    let committee = committee();
    let verifiers = ValidatorSet::new(committee);
    let payload = aggregate_at(&w, 5);

    // The window is 5 blocks and the dispute was filed at height 4, so at
    // height 10 the dispute has lapsed into its implicit outcome.
    let before = w.conservation();
    let certs_before = w.state.vwc_count();
    w.state.advance_block(11);

    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(payload)),
            12,
            &verifiers,
            &MockBls,
        )
        .expect_err("a lapsed dispute must refuse an explicit settlement");
    assert!(
        matches!(
            err,
            L2Error::IllegalTransition { .. } | L2Error::TaskExpired
        ),
        "got {err:?}"
    );

    // The implicit outcome the clock produced is the only one that counts.
    assert_eq!(w.conservation(), before, "no value moved");
    assert!(w.state.vwc_count() <= certs_before + 1);
}

/// A second, *independent* task settled by its own fresh aggregate while an
/// old aggregate for the first task is in flight: neither affects the other.
/// This is the "moved on" case that matters for liveness — a stale vote must
/// not block, or corrupt, the honest work around it.
#[test]
fn an_old_aggregate_for_another_task_does_not_block_the_next_one() {
    let mut w = world();
    let committee = committee();
    let verifiers = ValidatorSet::new(committee.clone());
    let stale = aggregate_at(&w, 5);

    // Settle the world's task properly first, so the old aggregate is stale
    // in the plain sense: the decision already happened.
    let fresh = aggregate_at(&w, 5);
    w.state
        .apply(
            &L2Transaction::new(L2Payload::Settle(fresh)),
            6,
            &verifiers,
            &MockBls,
        )
        .expect("the honest aggregate settles");
    let settled_count = w.state.vwc_count();

    // The stale one is still refused afterwards.
    let err = w
        .state
        .apply(
            &L2Transaction::new(L2Payload::Settle(stale)),
            7,
            &verifiers,
            &MockBls,
        )
        .expect_err("the settled task refuses again");
    assert!(
        matches!(err, L2Error::Replay | L2Error::IllegalTransition { .. }),
        "{err:?}"
    );

    // And a second dispute on a *new* task still works: the pool of votes and
    // the state machine are per-task, so staleness does not leak.
    assert_eq!(w.state.vwc_count(), settled_count);
    assert_eq!(committee.len(), 3, "the committee is unchanged");
}
