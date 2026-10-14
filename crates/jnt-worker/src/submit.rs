//! Result submission (SPEC.md §18.7, §18.8).
//!
//! The submission is the §15.1 `SubmitResult` payload: `result_hash` = SHA-256
//! of executor output, attestation = the existing M3 `ComputeAttestation`
//! bound to the same task/worker/result, whole payload signed by the claim
//! wallet's §15.2 `Auth`. Every precondition fails closed before broadcast;
//! the final authority is the L2 state machine.

use jnt_core::compute_ir::ComputeBackend;
use jnt_core::hash::{Address, Hash, Hash512};
use jnt_core::l2::{L2Payload, L2Transaction, SubmitResultPayload};
use jnt_core::wallet::Wallet;
use jnt_l2::state::L2State;
use jnt_l2::task_contract::ContractState;

use crate::error::{WorkerError, WorkerResult};
use crate::executor::{result_hash_of, Executor};
use crate::node::{Host, L2Broadcaster, L2NodeView};

/// A ready-to-broadcast submission, identified by its txid (§18.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitPlan {
    pub tx: L2Transaction,
    pub txid: Hash512,
    pub task_id: Hash,
    pub result_hash: Hash,
    pub worker: Address,
}

/// Build the submission transaction from executor output.
pub fn submit_plan(
    wallet: &Wallet,
    task_id: Hash,
    output_bytes: &[u8],
    backend: ComputeBackend,
    state: &L2State,
    height: u64,
) -> WorkerResult<SubmitPlan> {
    if output_bytes.is_empty() {
        return Err(WorkerError::EmptyResult);
    }
    let addr = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let contract = state.task(&task_id).ok_or(WorkerError::UnknownTask)?;
    match &contract.state {
        ContractState::InProgress { .. } => {}
        other => return Err(WorkerError::TaskNotAvailable(other.name())),
    }
    // Identity: only the claimant can submit (§15.3's own check, mirrored here
    // so the SDK-level error is clear instead of a generic protocol refusal).
    if contract.worker.as_ref() != Some(&addr) {
        return Err(WorkerError::IdentityMismatch);
    }
    if height > contract.deadline_height {
        return Err(WorkerError::TaskExpired);
    }
    let result_hash = result_hash_of(output_bytes);
    // The Phase-4 rule, mirrored before we sign: an all-zero result commit is
    // the expired placeholder, refused at submission (§18.7; SPEC.md §17.6).
    if result_hash == [0u8; 32] {
        return Err(WorkerError::TaskNotAvailable(
            "result hash is the expired placeholder",
        ));
    }
    let attestation = {
        use jnt_core::compute_ir::ComputeAttestation;
        let mut a = ComputeAttestation {
            task_id,
            result_hash,
            backend,
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
    let payload = SubmitResultPayload::build(wallet, task_id, attestation)?;
    let tx = L2Transaction::new(L2Payload::Submit(payload));
    Ok(SubmitPlan {
        txid: tx.txid(),
        task_id,
        result_hash,
        worker: addr,
        tx,
    })
}

/// Execute + build + broadcast in one call. Returns the plan that was sent.
pub fn submit_result<V: L2NodeView, B: L2Broadcaster, E: Executor>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    task_id: Hash,
    executor: &E,
) -> WorkerResult<SubmitPlan> {
    let state = host.l2_state()?;
    let height = host.chain_height()?;
    let contract = state.task(&task_id).ok_or(WorkerError::UnknownTask)?;
    let work = crate::executor::ExecutionWork::from_contract(contract, height)?;
    let out = crate::executor::execute_task(executor, &work)?;
    let plan = submit_plan(wallet, task_id, &out.output, out.backend, &state, height)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Reconcile a submission after a timeout or restart (§18.9): what did the
/// protocol actually record?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmittedState {
    /// Our result is on record (submitted, disputed over our work, or settled
    /// `Correct`); the lifecycle is past submission.
    Submitted,
    /// Our claim stands but no result is on record yet; safe to (re)submit.
    AwaitingSubmission,
    /// Our claim never landed (or was beaten); nothing to submit.
    NotClaimed,
    /// Task expired before any submission stood.
    Expired,
    /// The task reached some other terminal shape not over our work.
    LostOrSettledOther,
}

pub fn reconcile_submitted(
    state: &L2State,
    wallet_address: &Address,
    task_id: &Hash,
) -> WorkerResult<SubmittedState> {
    let contract = state.task(task_id).ok_or(WorkerError::UnknownTask)?;
    let ours = contract.worker.as_ref() == Some(wallet_address);
    match &contract.state {
        ContractState::ResultSubmitted { .. } if ours => Ok(SubmittedState::Submitted),
        ContractState::Disputed(_) if ours => Ok(SubmittedState::Submitted),
        ContractState::Settled(o) if ours => match o.verdict {
            jnt_core::l2::Verdict::Correct => Ok(SubmittedState::Submitted),
            _ => Ok(SubmittedState::LostOrSettledOther),
        },
        ContractState::InProgress { .. } if ours => Ok(SubmittedState::AwaitingSubmission),
        ContractState::Open | ContractState::InProgress { .. } => Ok(SubmittedState::NotClaimed),
        ContractState::Expired(_) => Ok(SubmittedState::Expired),
        _ => Ok(SubmittedState::LostOrSettledOther),
    }
}
