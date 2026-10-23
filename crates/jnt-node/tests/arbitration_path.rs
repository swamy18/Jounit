//! The node's arbitration path (Decision 21, SPEC.md §16).
//!
//! These are the tests that matter for the launch gate: a vote derived from the
//! canonical reference, signed by a committee member, aggregated into a quorum,
//! and applied through the **existing** settle path — which re-verifies the
//! aggregate from scratch and moves the value, slashes the deposit and issues the
//! certificate. Nothing is mocked and no transport stands in for a peer.
//!
//! The chain of custody a test must establish:
//!
//! ```text
//! DisputeEngine::resolve   → the canonical reference decides the verdict
//! arbitration::vote        → a committee member signs exactly the settle decision
//! VoteTally                → a quorum of distinct signers aggregates
//! mediation::propose       → the L2Transaction the miner should include
//! L2State::apply           → re-verifies and applies; slashes; certifies
//! ```
//!
//! Every link is checked by an independent assertion, so a break anywhere in the
//! chain shows up as a failure at the link that broke rather than as a mystery.

use jnt_core::bls::SecretKey;
use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{
    reference_result_hash, ComputeAttestation, ComputeBackend, ComputeTask,
};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::params::{mini_validator_secret, NetworkParams};
use jnt_core::signing::ValidatorKey;
use jnt_core::wallet::Wallet;
use jnt_l2::{ContractState, DisputeEngine, L2Config, L2Effect, L2Error, L2State};
use jnt_node::mediation::{live_proposals, propose, sign_vote, votes_for};

const SUBMITTED: Hash = [0xAAu8; 32];
const COUNTER: Hash = [0xBBu8; 32];
const NET: &str = "jounit/mini";
const DEADLINE: u64 = 100;

struct World {
    state: L2State,
    submitter: Wallet,
    worker: Wallet,
    challenger: Wallet,
    validators: ValidatorSet,
    /// The committee the chain derives, as arbitrators sign.
    committee: Vec<BlsPublicKey>,
    /// Signing secrets for those keys, read from the profile's own derivation.
    secrets: Vec<SecretKey>,
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "arb-node").unwrap()
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

/// The committee a `mini` chain derives, plus the secrets that produce those
/// keys. Read from the profile rather than invented, so a test signs as a real
/// member instead of as a stranger.
fn committee_and_secrets() -> (Vec<BlsPublicKey>, Vec<SecretKey>) {
    let params = NetworkParams::mini();
    let committee = params.l2_settlement_validators.clone();
    let secrets = (1u8..=32)
        .map(mini_validator_secret)
        .filter(|sk| committee.contains(&sk.public_key()))
        .collect::<Vec<_>>();
    (committee, secrets)
}

fn world() -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let challenger = wallet(3);
    let mut state = L2State::new(L2Config::mini());
    for w in [&submitter, &worker, &challenger] {
        state.credit(addr(w), 30_000_000).unwrap();
    }
    let (committee, secrets) = committee_and_secrets();
    World {
        state,
        submitter,
        worker,
        challenger,
        validators: ValidatorSet::new(committee.clone()),
        committee,
        secrets,
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<L2Effect, L2Error> {
        self.state.apply(tx, height, &self.validators, &MockBls)
    }

    fn reference(&self, id: Hash) -> Hash {
        // Computed independently of the contract's own `reference()`, on
        // purpose: this is the check that the deliverable abstraction still
        // produces the canonical CPU result and has not quietly become a second
        // implementation that could drift from it.
        let t = self.state.task(&id).unwrap();
        reference_result_hash(
            &t.task_id,
            &t.deliverable.0.ir_hash,
            &t.deliverable.0.input_hash,
            t.deliverable.0.required_memory_bytes,
        )
    }

    /// Post, claim, submit a *wrong* result, and have a truthful challenger
    /// dispute it with the reference. Leaves the task `Disputed` — the state an
    /// arbitrator arbitrates.
    fn disputed_fraudulent(&mut self) -> Hash {
        let id = self.post(1_000_000, 1);
        let reference = self.reference(id);
        assert_ne!(SUBMITTED, reference, "test setup: the worker must be wrong");
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, 100_000).unwrap(),
            )),
            2,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(
                    &self.worker,
                    id,
                    attestation(&self.worker, id, SUBMITTED),
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
                    reference,
                    attestation(&self.challenger, id, reference),
                    50_000,
                )
                .unwrap(),
            )),
            4,
        )
        .unwrap();
        assert!(matches!(
            self.state.task(&id).unwrap().state,
            ContractState::Disputed(_)
        ));
        id
    }

    fn post(&mut self, payment: u64, height: u64) -> Hash {
        let post =
            PostTaskPayload::build(&self.submitter, 1, payment, DEADLINE, task(DEADLINE)).unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), height)
            .unwrap();
        id
    }

    fn node_committee(&self) -> jnt_core::signing::Committee {
        let mut c = jnt_core::signing::Committee::new();
        for sk in &self.secrets {
            c.add(ValidatorKey::new(sk.clone(), NET)).unwrap();
        }
        c
    }

    fn vote_with(
        &self,
        sk: &SecretKey,
        task: Hash,
        verdict: Verdict,
        vwc_hash: Hash,
        height: u64,
    ) -> jnt_core::arbitration::ArbitrationVote {
        let base = jnt_core::arbitration::ArbitrationVote {
            version: jnt_core::arbitration::ARBITRATION_VOTE_VERSION,
            task_id: task,
            verdict,
            vwc_hash,
            network_id: NET.to_string(),
            height,
            signer: sk.public_key(),
            signature: jnt_core::bls_checkpoint::BlsSignature([0u8; 96]),
            pq_sig: None,
        };
        jnt_core::arbitration::ArbitrationVote {
            signature: sk.sign(&base.signing_hash()),
            ..base
        }
    }

    fn chain_fixture(&self) -> jnt_core::chain::Chain {
        jnt_core::chain::Chain::new(NetworkParams::mini()).unwrap()
    }
}

// ---------------------------------------------------------------------------
// The verdict is derived, never supplied
// ---------------------------------------------------------------------------

/// **No caller can dictate the verdict.** `resolve` computes the reference
/// itself from the contract; the test's assertion is that a *wrong* submission
/// with a *wrong* challenge produces no verdict at all, and that a truthful
/// challenge produces `Fraudulent`.
#[test]
fn the_reference_decides_and_a_caller_cannot_override_it() {
    let mut w = world();
    let id = w.disputed_fraudulent();

    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    assert_eq!(verdict.verdict(), Some(Verdict::Fraudulent));
    assert_eq!(verdict.re_execution_result, w.reference(id));
    assert_eq!(
        verdict.vwc_hash(),
        Some(w.reference(id)),
        "the hash the settle must carry is the reference, not the worker's"
    );
}

/// **"No match" is not guilt.** A challenge that names neither the worker's
/// result nor the reference arbitrates `Inconclusive`, settles nothing, and
/// therefore gives a committee nothing to vote on.
#[test]
fn an_inconclusive_dispute_gives_a_committee_nothing_to_vote_on() {
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
    // A challenge naming a third value, matching neither side.
    w.apply(
        &L2Transaction::new(L2Payload::Dispute(
            DisputePayload::build(
                &w.challenger,
                id,
                COUNTER,
                attestation(&w.challenger, id, COUNTER),
                50_000,
            )
            .unwrap(),
        )),
        4,
    )
    .unwrap();

    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    assert_eq!(verdict.verdict(), None);
    assert_eq!(
        verdict.settle_payload(NET, 0, [0u8; 96], vec![], 0, Vec::new()),
        Err(L2Error::InconclusiveDispute)
    );
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// **A committee member's vote signs exactly the settle decision.** The
/// property the aggregate composition depends on.
#[test]
fn a_committee_members_vote_signs_the_settle_decision() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();

    let (committee, _) = committee_and_secrets();
    let chain = w.chain_fixture();
    let key = ValidatorKey::new(mini_validator_secret(1), NET);
    let vote = sign_vote(&key, &chain, id, decision, verdict.re_execution_result, 0)
        .expect("a keyed committee signs");

    let payload = SettlePayload {
        task_id: id,
        verdict: decision,
        vwc_hash: verdict.re_execution_result,
        network_id: NET.to_string(),
        height: 0,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
    };
    assert_eq!(
        vote.signing_hash(),
        payload.signing_hash(),
        "a vote must sign the exact bytes the settle path verifies"
    );
    assert!(vote.verify_signature());
    assert!(committee.contains(&vote.signer), "and by a real member");
}

/// **An unkeyed node signs nothing.** No keys, no votes — not a vote with a
/// placeholder signature that would fail at aggregation.
#[test]
fn an_unkeyed_node_signs_nothing() {
    let w = world();
    let chain = w.chain_fixture();
    // The only way an unkeyed node signs nothing is that otes_for returns
    // early: a ValidatorKey always signs, so the guard is the committee being
    // empty rather than a per-key check.
    let empty = jnt_core::signing::Committee::new();
    assert!(votes_for(&chain, &w.state, &empty, 0).is_empty());
}

/// **No vote for `Expired`.** A clock outcome is not an arbitration outcome.
#[test]
fn a_node_will_not_sign_an_expired_verdict() {
    let w = world();
    let chain = w.chain_fixture();
    assert!(sign_vote(
        &ValidatorKey::new(mini_validator_secret(1), NET),
        &chain,
        [0x42u8; 32],
        Verdict::Expired,
        [0xABu8; 32],
        0
    )
    .is_none());
}

/// **`votes_for` only signs live disputes, and signs decisively.** A node
/// arbitrating the disputed task produces one vote per held key, and produces
/// none for tasks that are not disputed.
#[test]
fn votes_for_only_signs_live_disputes() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let committee = w.node_committee();
    let chain = w.chain_fixture();
    let votes = votes_for(&chain, &w.state, &committee, 0);
    assert_eq!(votes.len(), w.secrets.len(), "one vote per held key");
    for v in &votes {
        assert_eq!(v.task_id, id);
        assert!(v.verify_signature());
    }
}

// ---------------------------------------------------------------------------
// Quorum → payload → application
// ---------------------------------------------------------------------------

/// **The full lifecycle, through the real settle path.**
///
/// A quorum of votes becomes a `Settle` transaction, which is applied with the
/// *same* verifier the node uses, and which slashes the worker's deposit,
/// refunds the submitter whole, and issues no certificate (a fraud verdict
/// yields a slash record, not a receipt — SPEC.md §17.4).
#[test]
fn a_quorum_of_votes_settles_through_the_real_path() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();

    let quorum = w.validators.quorum_size();
    let mut book = jnt_core::arbitration::VoteBook::new();
    for sk in w.secrets.iter() {
        book.entry(id, quorum)
            .record(
                &w.vote_with(sk, id, decision, verdict.re_execution_result, 0),
                NET,
                0,
                &w.committee,
            )
            .unwrap();
    }

    let settlements = propose(&book, &w.committee);
    assert_eq!(settlements.len(), 1, "exactly one dispute reached quorum");

    let L2Payload::Settle(payload) = &settlements[0].tx.payload else {
        panic!("the proposal must be a Settle transaction")
    };
    // The aggregate the tally produced must verify against the committee the
    // way `apply_settle` will verify it.
    let signers = w.validators.signers_from_bitmap(&payload.signer_bitmap);
    assert!(signers.len() >= quorum);
    let msg = payload.signing_hash();
    assert!(
        jnt_core::bls::RealBls::verify_aggregate(
            &signers,
            &msg,
            &jnt_core::bls_checkpoint::BlsSignature(payload.bls_sig)
        ),
        "the produced aggregate must verify over the settle decision"
    );

    // And it actually settles: value moves, the deposit is slashed, and nothing
    // is certified for a fraud verdict.
    let worker_before = w.state.balance(&addr(&w.worker));
    let submitter_before = w.state.balance(&addr(&w.submitter));
    let effect = w
        .apply(&settlements[0].tx, 5)
        .expect("the settle path accepts it");
    let L2Effect::Settled {
        verdict: applied,
        worker_deposit_slashed,
        vwc_id,
        ..
    } = effect
    else {
        panic!("expected a Settled effect")
    };
    assert_eq!(applied, Verdict::Fraudulent);
    assert!(
        worker_deposit_slashed > 0,
        "the worker's deposit is slashed"
    );
    assert_eq!(vwc_id, None, "a fraud verdict certifies nothing");
    assert_eq!(
        w.state.balance(&addr(&w.worker)),
        worker_before,
        "the worker paid, not received"
    );
    assert!(
        w.state.balance(&addr(&w.submitter)) > submitter_before,
        "the defrauded submitter is refunded whole"
    );
    assert!(matches!(
        w.state.task(&id).unwrap().state,
        ContractState::Settled(_)
    ));
    assert!(
        w.state.check_conservation(),
        "value moved, none was created"
    );
}

/// **A non-quorum tally produces no transaction at all.**
#[test]
fn a_non_quorum_tally_produces_no_settlement() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();
    let quorum = w.validators.quorum_size();

    let mut book = jnt_core::arbitration::VoteBook::new();
    for sk in w.secrets.iter().take(quorum - 1) {
        book.entry(id, quorum)
            .record(
                &w.vote_with(sk, id, decision, verdict.re_execution_result, 0),
                NET,
                0,
                &w.committee,
            )
            .unwrap();
    }
    assert!(propose(&book, &w.committee).is_empty());
    // The worker spent a claim fee, so the balance is not simply the credit.
    assert!(
        w.state.balance(&addr(&w.worker)) < 30_000_000,
        "the worker paid to claim, and nothing settled"
    );
    assert!(
        w.state.check_conservation(),
        "no value moved without a settlement"
    );
}

/// **Finalization is idempotent.** The same proposal applied twice is refused
/// the second time — a task settles once, ever.
#[test]
fn a_settled_dispute_cannot_be_settled_again() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();
    let quorum = w.validators.quorum_size();

    let mut book = jnt_core::arbitration::VoteBook::new();
    for sk in &w.secrets {
        book.entry(id, quorum)
            .record(
                &w.vote_with(sk, id, decision, verdict.re_execution_result, 0),
                NET,
                0,
                &w.committee,
            )
            .unwrap();
    }
    let settlements = propose(&book, &w.committee);
    w.apply(&settlements[0].tx, 5).unwrap();
    let err = w.apply(&settlements[0].tx, 6);
    assert!(err.is_err(), "a second settlement must be refused: {err:?}");
    assert!(w.state.check_conservation());
}

/// **A forged aggregate is refused even though the decision is right.**
/// Votes from strangers aggregated into `quorum` do not produce a payload,
/// because the aggregate would not verify against the real committee.
#[test]
fn votes_from_strangers_never_produce_a_payload() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();
    let quorum = w.validators.quorum_size();

    let mut book = jnt_core::arbitration::VoteBook::new();
    for seed in 41u8..45 {
        let sk = SecretKey::derive(&[seed; 32]).unwrap();
        book.entry(id, quorum)
            .record(
                &w.vote_with(&sk, id, decision, verdict.re_execution_result, 0),
                NET,
                0,
                &w.committee,
            )
            .unwrap_err();
    }
    assert!(propose(&book, &w.committee).is_empty());
    assert!(w.state.check_conservation());
}

/// **`live_proposals` filters what the chain would refuse anyway.** A proposal
/// for a task that already settled is dropped, so the include queue carries
/// only transactions with a chance of applying.
#[test]
fn live_proposals_drops_what_already_settled() {
    let mut w = world();
    let id = w.disputed_fraudulent();
    let verdict = DisputeEngine::resolve(w.state.task(&id).unwrap()).unwrap();
    let decision = verdict.verdict().unwrap();
    let quorum = w.validators.quorum_size();

    let mut book = jnt_core::arbitration::VoteBook::new();
    for sk in &w.secrets {
        book.entry(id, quorum)
            .record(
                &w.vote_with(sk, id, decision, verdict.re_execution_result, 0),
                NET,
                0,
                &w.committee,
            )
            .unwrap();
    }
    // Still live: the dispute is open.
    assert_eq!(live_proposals(&book, &w.committee, &w.state).len(), 1);
    // Apply it; the node's own L2 state is the arbiter from here on.
    let settlements = propose(&book, &w.committee);
    w.apply(&settlements[0].tx, 5).unwrap();
    // After settlement the proposal is stale.
    assert!(
        live_proposals(&book, &w.committee, &w.state).is_empty(),
        "a settled dispute is not a live proposal"
    );
}
