//! Phase 6: reputation derived from canonical L2 artifacts (roadmap item 9).
//!
//! The unit under test is `jnt_l2::reputation`: it turns the VWC and
//! settlement artifacts an accepted L2 chain already carries into a
//! [`ReputationLedger`]. The properties here are the ones that make the
//! derived view trustworthy:
//!
//! - only *verified* work earns standing — a fraudulent settlement earns the
//!   penalty, not the reward;
//! - a defended challenge is distinguished from a lost one by the settlement's
//!   own accounting, not by a guess;
//! - a certificate whose id no longer recomputes is refused, so standing
//!   cannot be manufactured by editing a certificate;
//! - derivation is deterministic, so the same state always yields the same
//!   accumulator chain.

use jnt_core::agent::{derive_agent_id, AgentRole};
use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::reputation::{ReputationKind, ReputationLedger};
use jnt_core::wallet::Wallet;
use jnt_l2::reputation::{apply_dispute_outcome, apply_vwc, ledger_from_state};
use jnt_l2::{L2Config, L2Error, L2State};

const NET: &str = "jounit/mini";
const DEADLINE: u64 = 100;
const RESULT: Hash = [0xAAu8; 32];
const COUNTER: Hash = [0xBBu8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "reputation-flow").unwrap()
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

fn validators_with_keys(n: usize) -> (ValidatorSet, Vec<SecretKey>) {
    let secrets: Vec<SecretKey> = (1..=n as u8)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect();
    let set = ValidatorSet::new(secrets.iter().map(|sk| sk.public_key()).collect());
    (set, secrets)
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
    validators: ValidatorSet,
    secrets: Vec<SecretKey>,
    submitter: Wallet,
    worker: Wallet,
    challenger: Wallet,
}

fn world() -> World {
    let (validators, secrets) = validators_with_keys(4);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&wallet(1)), 10_000_000).unwrap();
    state.credit(addr(&wallet(2)), 10_000_000).unwrap();
    state.credit(addr(&wallet(3)), 10_000_000).unwrap();
    World {
        state,
        validators,
        secrets,
        submitter: wallet(1),
        worker: wallet(2),
        challenger: wallet(3),
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<(), L2Error> {
        self.state
            .apply(tx, height, &self.validators, &RealBls)
            .map(|_| ())
    }

    fn submitted(&mut self, deposit: u64) -> Hash {
        let post = PostTaskPayload::build(&self.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE))
            .unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
            .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, deposit).unwrap(),
            )),
            2,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(&self.worker, id, attestation(&self.worker, id, RESULT))
                    .unwrap(),
            )),
            3,
        )
        .unwrap();
        id
    }

    fn disputed(&mut self, deposit: u64) -> Hash {
        let id = self.submitted(deposit);
        self.apply(
            &L2Transaction::new(L2Payload::Dispute(
                DisputePayload::build(
                    &self.challenger,
                    id,
                    COUNTER,
                    attestation(&self.challenger, id, COUNTER),
                    50_000,
                )
                .unwrap(),
            )),
            4,
        )
        .unwrap();
        id
    }

    fn signed_settle(&self, id: Hash, verdict: Verdict, vwc_hash: Hash) -> SettlePayload {
        let payload = SettlePayload {
            task_id: id,
            verdict,
            vwc_hash,
            bls_sig: [0u8; 96],
            signer_bitmap: Vec::new(),
            signer_count: 0,
            pq_sidecar: Vec::new(),
        };
        let msg = payload.signing_hash();
        let quorum = self.validators.quorum_size();
        let indices: Vec<usize> = (0..quorum).collect();
        let signers = self
            .validators
            .signers_from_bitmap(&self.validators.bitmap_from_indices(&indices));
        let sigs: Vec<_> = signers
            .iter()
            .map(|pk| {
                let sk = self
                    .secrets
                    .iter()
                    .find(|sk| sk.public_key().0 == pk.0)
                    .expect("set keys come from world secrets");
                sk.sign(&msg)
            })
            .collect();
        SettlePayload {
            bls_sig: *RealBls::aggregate(&sigs).unwrap().as_bytes(),
            signer_bitmap: self.validators.bitmap_from_indices(&indices),
            signer_count: quorum as u32,
            pq_sidecar: Vec::new(),
            ..payload
        }
    }

    fn settle(&mut self, id: Hash, verdict: Verdict, vwc_hash: Hash, height: u64) {
        let payload = self.signed_settle(id, verdict, vwc_hash);
        self.apply(&L2Transaction::new(L2Payload::Settle(payload)), height)
            .unwrap();
    }

    fn worker_subject(&self) -> [u8; 20] {
        derive_agent_id(NET, AgentRole::Machine, &addr(&self.worker))
    }
}

// ---------------------------------------------------------------------------
// Verified work
// ---------------------------------------------------------------------------

#[test]
fn a_correct_settlement_gives_the_worker_verified_work() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);
    assert_eq!(
        w.state.vwc_count(),
        1,
        "a Correct settlement issues a certificate"
    );

    let ledger = ledger_from_state(&w.state, NET).expect("the chain is well-formed");
    let score = ledger
        .score(&w.worker_subject())
        .expect("the worker earned standing");
    assert_eq!(score.events, 1);
    assert_eq!(score.score, ReputationKind::VerifiedWork.weight());
    assert_eq!(score.by_kind[ReputationKind::VerifiedWork as usize], 1);
    assert_eq!(score.last_height, 10);
}

#[test]
fn the_derived_ledger_is_deterministic() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);

    let a = ledger_from_state(&w.state, NET).unwrap();
    let b = ledger_from_state(&w.state, NET).unwrap();
    let sa = a.score(&w.worker_subject()).unwrap();
    let sb = b.score(&w.worker_subject()).unwrap();
    assert_eq!(sa.accumulator, sb.accumulator, "same state, same chain");
    assert_eq!(sa.score, sb.score);
}

// ---------------------------------------------------------------------------
// Disputes
// ---------------------------------------------------------------------------

#[test]
fn a_fraudulent_settlement_marks_the_worker_lost_and_issues_no_certificate() {
    let mut w = world();
    let id = w.disputed(100_000);
    w.settle(id, Verdict::Fraudulent, COUNTER, 10);
    assert_eq!(w.state.vwc_count(), 0, "a fraud verdict certifies nothing");

    let ledger = ledger_from_state(&w.state, NET).unwrap();
    let score = ledger.score(&w.worker_subject()).unwrap();
    assert_eq!(score.by_kind[ReputationKind::DisputeLost as usize], 1);
    assert_eq!(score.score, ReputationKind::DisputeLost.weight());
    assert!(score.score < 0, "a lost dispute is a penalty, not a reward");
}

#[test]
fn a_defended_challenge_marks_the_worker_won_and_still_certifies_the_work() {
    let mut w = world();
    let id = w.disputed(100_000);
    // The worker's result was right: the challenge fails and the challenger's
    // deposit is burned, which is the settlement's own record of the outcome.
    w.settle(id, Verdict::Correct, RESULT, 10);

    let ledger = ledger_from_state(&w.state, NET).unwrap();
    let score = ledger.score(&w.worker_subject()).unwrap();
    assert_eq!(score.by_kind[ReputationKind::DisputeWon as usize], 1);
    assert_eq!(score.by_kind[ReputationKind::VerifiedWork as usize], 1);
    assert_eq!(score.events, 2);
    assert_eq!(
        score.score,
        ReputationKind::VerifiedWork.weight() + ReputationKind::DisputeWon.weight()
    );
}

#[test]
fn a_settlement_without_a_dispute_records_no_dispute_event() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);

    let ledger = ledger_from_state(&w.state, NET).unwrap();
    let score = ledger.score(&w.worker_subject()).unwrap();
    assert_eq!(score.by_kind[ReputationKind::DisputeWon as usize], 0);
    assert_eq!(score.by_kind[ReputationKind::DisputeLost as usize], 0);
}

// ---------------------------------------------------------------------------
// Tamper and refusal
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_whose_id_no_longer_recomputes_is_refused() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);

    let certs = w.state.vwcs();
    let mut forged = certs[0].clone();
    // Re-point the certificate at another worker without recomputing the id:
    // exactly the edit that would let an attacker claim someone else's work.
    forged.worker = addr(&wallet(9));
    let mut ledger = ReputationLedger::new(NET);
    let err = apply_vwc(&mut ledger, &forged, NET).expect_err("a tampered id must be refused");
    assert!(
        matches!(
            err,
            L2Error::VwcInvalid("certificate id does not recompute")
        ),
        "got {err:?}"
    );
    assert!(
        ledger.score(&w.worker_subject()).is_none(),
        "nothing was committed"
    );
}

#[test]
fn a_ledger_for_another_network_refuses_the_artifact() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);

    let cert = w.state.vwcs()[0].clone();
    let mut ledger = ReputationLedger::new("jounit/testnet");
    let err = apply_vwc(&mut ledger, &cert, NET).expect_err("network binding must hold");
    assert!(matches!(err, L2Error::Reputation(_)), "got {err:?}");
}

#[test]
fn a_task_without_a_dispute_outcome_produces_no_event() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 10);
    let task = w.state.task(&id).unwrap();

    let mut ledger = ReputationLedger::new(NET);
    let out = apply_dispute_outcome(&mut ledger, task, NET).expect("well-formed task");
    assert!(out.is_none(), "no dispute means no dispute event");
    assert_eq!(ledger.subjects(), 0);
}
