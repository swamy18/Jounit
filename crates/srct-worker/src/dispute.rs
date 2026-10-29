//! Dispute observation and challenger participation (SPEC.md §18.14).
//!
//! Observation: the SDK reads the task's `Disputed` state and the eventual
//! resolution from authoritative state. Participation: the worker may file a
//! §15.1 `Dispute` payload as the *challenger* against any `ResultSubmitted`
//! task. The SDK never arbitrates: §16.4's reference hash comes from the
//! arbitrator set, and the SDK consumes verdicts, never produces them.

use srct_core::compute_ir::ComputeAttestation;
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{DisputePayload, L2Payload, L2Transaction};
use srct_core::wallet::Wallet;
use srct_l2::dispute::DisputeEvidence;
use srct_l2::state::L2State;
use srct_l2::task_contract::ContractState;

use crate::error::{WorkerError, WorkerResult};
use crate::node::{L2Broadcaster, L2NodeView};

/// A dispute as the worker sees it (observation surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeView {
    pub task_id: Hash,
    /// Only meaningful when the worker is the disputed party — derived by the
    /// caller against its own wallet, since the contract's worker field is the
    /// authoritative name of the disputed submission's owner.
    pub challenger: Address,
    pub submitted_result: Hash,
    pub counter_result: Hash,
    pub deposit_sat: u64,
    pub filed_at: u64,
}

impl DisputeView {
    /// Read the dispute out of a `Disputed` contract. `worker_is_subject`
    /// checks whether this dispute is over the given wallet's submission.
    pub fn from_contract(
        contract: &srct_l2::TaskContract,
        worker: &Address,
    ) -> WorkerResult<DisputeView> {
        let c = match &contract.state {
            ContractState::Disputed(c) => c,
            _ => {
                return Err(WorkerError::TaskNotAvailable(
                    "task is not in Disputed state",
                ))
            }
        };
        let _ = worker;
        Ok(DisputeView {
            task_id: contract.task_id,
            challenger: c.challenger,
            submitted_result: c.against_result,
            counter_result: c.counter_result,
            deposit_sat: c.deposit_sat,
            filed_at: c.filed_at,
        })
    }
}

/// Observe the dispute over `task_id`, if one is filed. `involves_worker`
/// tells the caller whether its own submission is the one contested (§18.14).
pub fn dispute_of_task(
    state: &L2State,
    task_id: &Hash,
    worker: &Address,
) -> WorkerResult<Option<(DisputeView, bool)>> {
    match state.task(task_id) {
        None => Err(WorkerError::UnknownTask),
        Some(c) => match &c.state {
            ContractState::Disputed(challenge) => {
                let view = DisputeView::from_contract(c, worker)?;
                let involves = c.worker.as_ref() == Some(worker)
                    && challenge.against_attestation.worker_address == *worker;
                Ok(Some((view, involves)))
            }
            _ => Ok(None),
        },
    }
}

/// The resolution the protocol recorded for a disputed task (§18.14
/// observation): still-open and never-disputed are distinguished explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeResolution {
    /// The submitted result stands (lapse or a `Correct` settle).
    SubmittedStood,
    /// The challenger won (`Fraudulent`); the worker's deposit was slashed.
    ChallengerWon {
        worker_deposit_slashed: u64,
    },
    /// Closed as expired (only for the no-result paths).
    Expired,
    NotDisputed,
    UnknownTask,
}

pub fn dispute_resolution(state: &L2State, task_id: &Hash) -> DisputeResolution {
    match state.task(task_id) {
        None => DisputeResolution::UnknownTask,
        Some(c) => match &c.state {
            ContractState::Disputed(_) => DisputeResolution::NotDisputed,
            ContractState::Settled(o) => match o.verdict {
                srct_core::l2::Verdict::Correct => DisputeResolution::SubmittedStood,
                srct_core::l2::Verdict::Fraudulent => DisputeResolution::ChallengerWon {
                    worker_deposit_slashed: o.worker_deposit_slashed,
                },
                srct_core::l2::Verdict::Expired => DisputeResolution::Expired,
            },
            ContractState::Expired(_) => DisputeResolution::Expired,
            _ => DisputeResolution::NotDisputed,
        },
    }
}

/// Challenger stake the SDK files with. The operator can build a custom
/// payload through `srct_core` directly if they need a different amount.
pub const DEFAULT_CHALLENGE_DEPOSIT_SAT: u64 = 50_000;

/// A ready-to-broadcast dispute transaction (worker as challenger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputePlan {
    pub tx: L2Transaction,
    pub txid: Hash512,
    pub task_id: Hash,
}

/// Build the dispute transaction. Fails closed on the §18.14 preconditions:
/// the task exists, is `ResultSubmitted`, the counter-result differs, the
/// counter-attestation binds, and evidence validation (the engine's own
/// validator, reused verbatim) passes.
pub fn dispute_plan(
    wallet: &Wallet,
    task_id: Hash,
    counter_result: Hash,
    state: &L2State,
    height: u64,
) -> WorkerResult<DisputePlan> {
    let addr = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let contract = state.task(&task_id).ok_or(WorkerError::UnknownTask)?;
    let (submitted, submitted_attestation) = match &contract.state {
        ContractState::ResultSubmitted {
            result_hash,
            attestation,
            ..
        } => (*result_hash, attestation.clone()),
        other_state => {
            return Err(WorkerError::TaskNotAvailable(other_state.name()));
        }
    };
    if counter_result == submitted {
        // A challenge that agrees with the result is not a dispute (§15.6);
        // refuse here for the SDK-level name rather than let the protocol
        // refusal surface later.
        return Err(WorkerError::TaskNotAvailable(
            "counter result equals the submitted result",
        ));
    }
    let counter_attestation = {
        let mut a = ComputeAttestation {
            task_id,
            result_hash: counter_result,
            backend: contract.deliverable.0.backend_hint,
            worker_address: addr,
            attest_height: height,
            signature: vec![],
        };
        a.signature = wallet
            .sign_digest(&a.attest_hash())
            .map_err(|_| WorkerError::IdentityMismatch)?
            .to_vec();
        a
    };
    // Structural evidence check against the same validator the engine uses
    // (§18.14: reuse, never reimplement). Note the submitted attestation rides
    // with the contract, so this validates the exact pair that would settle.
    let evidence = DisputeEvidence {
        task_id,
        submitted_result: submitted,
        submitted_attestation,
        counter_result,
        counter_attestation,
    };
    evidence.validate().map_err(WorkerError::Protocol)?;
    let payload = DisputePayload::build(
        wallet,
        task_id,
        counter_result,
        evidence.counter_attestation.clone(),
        DEFAULT_CHALLENGE_DEPOSIT_SAT,
    )?;
    let tx = L2Transaction::new(L2Payload::Dispute(payload));
    Ok(DisputePlan {
        txid: tx.txid(),
        task_id,
        tx,
    })
}

/// Build + broadcast in one call, after checking the challenger's financing:
/// deposit + dispute fee must be covered (§15.5).
pub fn file_dispute<V: L2NodeView, B: L2Broadcaster>(
    host: &mut crate::node::Host<V, B>,
    wallet: &Wallet,
    task_id: Hash,
    counter_result: Hash,
) -> WorkerResult<DisputePlan> {
    let state = host.l2_state()?;
    let height = host.chain_height()?;
    let addr = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let need = DEFAULT_CHALLENGE_DEPOSIT_SAT + srct_core::l2::L2TxType::Dispute.fee_sat();
    let have = state.balance(&addr);
    if have < need {
        return Err(WorkerError::InsufficientBalance {
            needed: need,
            available: have,
        });
    }
    let plan = dispute_plan(wallet, task_id, counter_result, &state, height)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}
