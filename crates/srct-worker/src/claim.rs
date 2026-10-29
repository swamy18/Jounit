//! Task claiming (SPEC.md §18.5).
//!
//! A claim is the §15.1 `ClaimTask` payload built by
//! `ClaimTaskPayload::build(wallet, task_id, backend, worker_deposit_sat)` and
//! wrapped in `L2Transaction::new` — no other construction exists. Local
//! preconditions run before broadcast; the protocol alone has final authority.

use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{ClaimTaskPayload, L2Payload, L2Transaction};
use srct_core::wallet::Wallet;
use srct_l2::state::L2State;
use srct_l2::task_contract::ContractState;

use crate::config::WorkerConfig;
use crate::discovery::available;
use crate::error::{WorkerError, WorkerResult};
use crate::node::{Host, L2Broadcaster, L2NodeView};

/// A ready-to-broadcast claim, and the txid that identifies it (§18.9
/// idempotency: reconciliation keys on this id, never on a wish).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPlan {
    pub tx: L2Transaction,
    pub txid: Hash512,
    pub task_id: Hash,
    pub worker: Address,
}

/// Build the claim transaction. Fails closed on every §18.5 precondition.
pub fn claim_plan(
    wallet: &Wallet,
    config: &WorkerConfig,
    task_id: Hash,
    state: &L2State,
    height: u64,
) -> WorkerResult<ClaimPlan> {
    // Identity: the payload the wallet signs will act as the wallet's address,
    // so a config that disagrees with its own wallet is refused, never
    // broadcast (§18.2, §18.11).
    let addr = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    if addr != config.address {
        return Err(WorkerError::IdentityMismatch);
    }
    let contract = state.task(&task_id).ok_or(WorkerError::UnknownTask)?;
    // The claim's backend is the task's own hint (that is the only value the
    // protocol knows about at claim time; §15.1 ClaimTaskPayload).
    if !available(contract, height, state, config) {
        return Err(WorkerError::TaskNotAvailable(contract.state.name()));
    }
    // Deadline re-check against the height this decision is made at.
    if height > contract.deadline_height {
        return Err(WorkerError::TaskExpired);
    }
    // Financing: deposit + claim fee must be covered (§15.5). Re-checked here
    // even though `available` checked it, because the height may have moved.
    let need = config
        .worker_deposit_sat
        .saturating_add(srct_core::l2::L2TxType::ClaimTask.fee_sat());
    let have = state.balance(&addr);
    if have < need {
        return Err(WorkerError::InsufficientBalance {
            needed: need,
            available: have,
        });
    }
    let payload = ClaimTaskPayload::build(
        wallet,
        task_id,
        contract.deliverable.0.backend_hint,
        config.worker_deposit_sat,
    )?;
    let tx = L2Transaction::new(L2Payload::Claim(payload));
    Ok(ClaimPlan {
        txid: tx.txid(),
        task_id,
        worker: addr,
        tx,
    })
}

/// Build + broadcast in one call. Returns the plan that was sent.
///
/// A failure here is either [`WorkerError::BroadcastUnavailable`] (§18.9: the
/// transaction MAY have landed — reconcile by `txid`) or one of the named
/// local/protocol preconditions; nothing else, nothing mutated.
pub fn claim_task<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    config: &WorkerConfig,
    task_id: Hash,
) -> WorkerResult<ClaimPlan> {
    let (state, height) = host.observe()?;
    let plan = claim_plan(wallet, config, task_id, &state, height)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// The lifecycle state the SDK observes for a task it believed it claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedState {
    /// Claim visible, result not yet submitted.
    InProgress,
    /// Result accepted by the protocol (or further along over our work).
    Submitted,
    /// The task expired (deposit burned, §15.4) before our submission stood.
    Expired,
    /// Somebody else's claim won; the task is not ours to execute.
    ClaimedByOther,
}

/// Observe the authoritative state for a task the wallet believed it claimed.
///
/// This is the §18.9 reconciliation primitive: after any timeout, restart or
/// lost broadcast, callers re-derive the truth from here rather than assuming
/// a broadcast failed (or succeeded).
pub fn reconcile_claimed(
    state: &L2State,
    wallet_address: &Address,
    task_id: &Hash,
) -> WorkerResult<ClaimedState> {
    let contract = state.task(task_id).ok_or(WorkerError::UnknownTask)?;
    match &contract.state {
        ContractState::Open => Ok(ClaimedState::ClaimedByOther),
        ContractState::InProgress { .. } | ContractState::ResultSubmitted { .. } => {
            if contract.worker.as_ref() == Some(wallet_address) {
                Ok(match &contract.state {
                    ContractState::ResultSubmitted { .. } => ClaimedState::Submitted,
                    _ => ClaimedState::InProgress,
                })
            } else {
                Ok(ClaimedState::ClaimedByOther)
            }
        }
        ContractState::Disputed(_) | ContractState::Settled(_) => Ok(ClaimedState::Submitted),
        ContractState::Expired(_) => Ok(ClaimedState::Expired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_refuses_the_unknown_rather_than_guessing() {
        let state = L2State::new(srct_l2::L2Config::mini());
        let addr = [7u8; 20];
        assert!(matches!(
            reconcile_claimed(&state, &addr, &[0u8; 32]),
            Err(WorkerError::UnknownTask)
        ));
    }
}
