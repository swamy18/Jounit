//! Task discovery over authoritative state (SPEC.md §18.4).
//!
//! Discovery is a pure function of the observed `L2State` at a height plus the
//! operator's filter. Given the same state, height and filter, the output is
//! the same tasks in the same ascending-task-id order; a `HashMap` never
//! decides an outcome (`L2State::tasks` is already sorted, §15.9 style).

use srct_core::hash::Hash;
use srct_l2::state::L2State;
use srct_l2::task_contract::ContractState;

use crate::config::Filter;
use crate::error::{WorkerError, WorkerResult};
use crate::node::L2NodeView;

/// A task as surfaced to the worker: the payment/constraint surface of §18.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRef {
    pub task_id: Hash,
    pub submitter: srct_core::hash::Address,
    /// Escrow the task pays minus the settle fee on a `Correct` settle.
    pub payment_sat: u64,
    /// Deposit the claiming worker must lock (the contract's field is what a
    /// claim paid; an open task's requirement is the *target* deposit the
    /// operator configures — surfaced here as the contract's own value, zero
    /// for an unclaimed task).
    pub worker_deposit_sat: u64,
    pub deadline_height: u64,
    pub required_memory_bytes: u64,
    pub backend_hint: srct_core::compute_ir::ComputeBackend,
    /// Heights still available to claim in.
    pub blocks_left: u64,
}

impl TaskRef {
    /// The net a `Correct` settlement would pay this worker for a claim at
    /// `deposit`, i.e. `payment_sat - settle_fee` (§15.4, fee out of escrow).
    /// Decision 23 (P5): the proportional fee for this task's escrow.
    pub fn net_payment_sat(&self) -> u64 {
        self.payment_sat
            .saturating_sub(srct_core::l2::settle_fee_sat(self.payment_sat))
    }
}

/// Discover tasks available to claim, filtered and deterministically ordered.
pub fn discover_tasks<V: L2NodeView>(
    view: &V,
    config: &crate::config::WorkerConfig,
) -> WorkerResult<Vec<TaskRef>> {
    let (state, height) = view.observe()?;
    if state.task_count() > config.filter.max_scan {
        return Err(WorkerError::ObservationMalformed(
            "state exposes more tasks than the scan bound",
        ));
    }
    let mut out = Vec::new();
    for contract in state.tasks() {
        if !available(contract, height, &state, config) {
            continue;
        }
        let t = &contract.deliverable.0;
        out.push(TaskRef {
            task_id: contract.task_id,
            submitter: contract.submitter,
            payment_sat: contract.payment_sat,
            worker_deposit_sat: contract.worker_deposit_sat,
            deadline_height: contract.deadline_height,
            required_memory_bytes: t.required_memory_bytes,
            backend_hint: t.backend_hint,
            blocks_left: contract.deadline_height - height,
        });
    }
    Ok(out)
}

/// The §18.4 availability predicate: state, deadline, filter and financing.
///
/// Exposed for `claim_task`'s pre-flight and for tests; callers outside the
/// crate should go through `discover_tasks`.
pub fn available(
    contract: &srct_l2::TaskContract,
    height: u64,
    state: &L2State,
    config: &crate::config::WorkerConfig,
) -> bool {
    // 1. State: only Open tasks can be claimed (§15.3).
    if !matches!(contract.state, ContractState::Open) {
        return false;
    }
    // 2. Deadline: the same rule `TaskContract::claim` will apply.
    if height > contract.deadline_height {
        return false;
    }
    // 3. Operator filter — policy, not protocol (§18.4).
    let f: &Filter = &config.filter;
    if contract.payment_sat < f.min_payment_sat {
        return false;
    }
    let net = contract
        .payment_sat
        .saturating_sub(srct_core::l2::settle_fee_sat(contract.payment_sat));
    if net < f.min_net_payment_sat {
        return false;
    }
    if contract.deadline_height.saturating_sub(height) > f.max_deadline_distance {
        return false;
    }
    let t = &contract.deliverable.0;
    if t.required_memory_bytes > f.max_memory_bytes {
        return false;
    }
    if !f.backends.contains(&t.backend_hint) {
        return false;
    }
    // 4. Financing: the worker's own balance must cover the deposit being
    //    offered plus the claim fee (financing a claim it cannot pay for would
    //    broadcast a transaction the protocol refuses for balance, which is a
    //    wasted round trip and a worse error than a filtered-out task).
    let need = config
        .worker_deposit_sat
        .saturating_add(srct_core::l2::L2TxType::ClaimTask.fee_sat());
    state.balance(&config.address) >= need
}
