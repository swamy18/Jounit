//! The `WorkerClient` facade: one object, the full lifecycle (§18.9).
//!
//! Owns the wallet, the configuration, the node host and the executor, and
//! exposes the lifecycle in the order a worker lives it:
//! `discover → claim → execute → submit` and the observation surfaces
//! (`reconcile_*`, earnings, disputes, certificates). Construction and
//! broadcast stay separate (`*_build` vs the broadcasting variants) so an
//! operator can inspect what will be sent before it is sent.
//!
//! Certificate observation needs the era's validator set and BLS verifier;
//! the client takes them at construction (`validators`, `verifier`) because
//! a worker should not claim how finality signed without being configured
//! for it. A worker not interested in certificates can use
//! [`srct_core::bls_checkpoint::MockBls`] — §17.6 notes the mock for tests.

use srct_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use srct_core::wallet::Wallet;
use srct_l2::L2State;

use crate::claim::{claim_plan, claim_task, reconcile_claimed, ClaimPlan, ClaimedState};
use crate::config::WorkerConfig;
use crate::discovery::{discover_tasks, TaskRef};
use crate::dispute::{
    dispute_of_task, dispute_plan, dispute_resolution, file_dispute, DisputePlan,
    DisputeResolution, DisputeView,
};
use crate::error::{WorkerError, WorkerResult};
use crate::executor::{execute_task, ExecutionWork, Executor};
use crate::node::{Host, L2Broadcaster, L2NodeView};
use crate::submit::{reconcile_submitted, submit_plan, submit_result, SubmitPlan, SubmittedState};
use crate::vwc::{certificates_for_worker, observe_certificate};

/// The worker's running client.
///
/// Generic over the node host and the executor; every method is a thin,
/// documented composition of the module functions. No method holds state the
/// authoritative state does not already hold: restart-and-reconcile is the
/// designed recovery path (§18.9), not in-memory bookkeeping.
pub struct WorkerClient<V, B, E> {
    host: Host<V, B>,
    pub wallet: Wallet,
    pub config: WorkerConfig,
    executor: E,
    validators: ValidatorSet,
    verifier: &'static dyn BlsVerifier,
}

impl<V: L2NodeView, B: L2Broadcaster, E: Executor> WorkerClient<V, B, E> {
    /// Build a client. `config` is derived from the wallet by default; pass
    /// [`WorkerClient::with_config`] to narrow the filter or choose a deposit.
    pub fn new(
        host: Host<V, B>,
        wallet: Wallet,
        executor: E,
        validators: ValidatorSet,
        verifier: &'static dyn BlsVerifier,
    ) -> Self {
        let config = WorkerConfig::from_wallet(&wallet);
        WorkerClient {
            host,
            wallet,
            config,
            executor,
            validators,
            verifier,
        }
    }

    pub fn with_config(mut self, mut config: WorkerConfig) -> WorkerResult<Self> {
        // Identity is derived from the wallet; a config whose address
        // disagrees with its own wallet is refused, never guessed (§18.2).
        let addr = self
            .wallet
            .address()
            .map_err(|_| WorkerError::IdentityMismatch)?;
        config.address = addr;
        self.config = config;
        Ok(self)
    }

    // --- lifecycle: act ---------------------------------------------------

    /// §18.4: discover claimable tasks under the configured filter.
    pub fn discover(&self) -> WorkerResult<Vec<TaskRef>> {
        discover_tasks(&self.host, &self.config)
    }

    /// §18.5: claim a task (build + broadcast).
    pub fn claim(&mut self, task_id: srct_core::hash::Hash) -> WorkerResult<ClaimPlan> {
        claim_task(&mut self.host, &self.wallet, &self.config, task_id)
    }

    /// §18.5: build the claim without broadcasting.
    pub fn claim_build(&self, task_id: srct_core::hash::Hash) -> WorkerResult<ClaimPlan> {
        claim_plan(
            &self.wallet,
            &self.config,
            task_id,
            &self.l2_state()?,
            self.height()?,
        )
    }

    /// §18.6: run the executor over a task's work without submitting.
    pub fn execute(
        &self,
        task_id: srct_core::hash::Hash,
    ) -> WorkerResult<crate::executor::ExecutionOutput> {
        let state = self.l2_state()?;
        let contract = state.task(&task_id).ok_or(WorkerError::UnknownTask)?;
        if contract.worker.as_ref() != Some(&self.config.address) {
            // Executing unclaimed work burns nothing on-chain but would
            // produce a submission the protocol must refuse later; refuse
            // here where the cause is clear (§18.11).
            return Err(WorkerError::IdentityMismatch);
        }
        let work = ExecutionWork::from_contract(contract, self.height()?)?;
        execute_task(&self.executor, &work)
    }

    /// §18.7: execute + submit in one call (the common path).
    pub fn execute_and_submit(
        &mut self,
        task_id: srct_core::hash::Hash,
    ) -> WorkerResult<SubmitPlan> {
        submit_result(&mut self.host, &self.wallet, task_id, &self.executor)
    }

    /// §18.7: build the submission from caller-supplied output bytes.
    pub fn submit_build(
        &self,
        task_id: srct_core::hash::Hash,
        output_bytes: &[u8],
        backend: srct_core::compute_ir::ComputeBackend,
    ) -> WorkerResult<SubmitPlan> {
        submit_plan(
            &self.wallet,
            task_id,
            output_bytes,
            backend,
            &self.l2_state()?,
            self.height()?,
        )
    }

    /// §18.14: file a dispute as the challenger (build + broadcast).
    pub fn dispute(
        &mut self,
        task_id: srct_core::hash::Hash,
        counter_result: srct_core::hash::Hash,
    ) -> WorkerResult<DisputePlan> {
        file_dispute(&mut self.host, &self.wallet, task_id, counter_result)
    }

    /// §18.14: build the dispute without broadcasting.
    pub fn dispute_build(
        &self,
        task_id: srct_core::hash::Hash,
        counter_result: srct_core::hash::Hash,
    ) -> WorkerResult<DisputePlan> {
        dispute_plan(
            &self.wallet,
            task_id,
            counter_result,
            &self.l2_state()?,
            self.height()?,
        )
    }

    // --- lifecycle: observe -----------------------------------------------

    /// §18.9: after a claim timeout/restart, what does the protocol say?
    pub fn reconcile_claim(&self, task_id: &srct_core::hash::Hash) -> WorkerResult<ClaimedState> {
        reconcile_claimed(&self.l2_state()?, &self.config.address, task_id)
    }

    /// §18.9: after a submit timeout/restart, what does the protocol say?
    pub fn reconcile_submission(
        &self,
        task_id: &srct_core::hash::Hash,
    ) -> WorkerResult<SubmittedState> {
        reconcile_submitted(&self.l2_state()?, &self.config.address, task_id)
    }

    /// §18.14: observe a dispute over a task, and whether it involves this
    /// worker's own submission.
    pub fn dispute_view(
        &self,
        task_id: &srct_core::hash::Hash,
    ) -> WorkerResult<Option<(DisputeView, bool)>> {
        dispute_of_task(&self.l2_state()?, task_id, &self.config.address)
    }

    /// §18.14: what did the protocol decide about a disputed task?
    pub fn dispute_outcome(
        &self,
        task_id: &srct_core::hash::Hash,
    ) -> WorkerResult<DisputeResolution> {
        Ok(dispute_resolution(&self.l2_state()?, task_id))
    }

    /// §18.13: earnings derived from authoritative state.
    pub fn earnings(&self) -> WorkerResult<Earnings> {
        Ok(earnings_of(&self.l2_state()?, &self.config.address))
    }

    /// §18 (VWC observation): the certificate for a task, validated against
    /// the registry with the client's configured validator context (§17.6).
    pub fn certificate(
        &self,
        task_id: &srct_core::hash::Hash,
    ) -> WorkerResult<Option<srct_l2::vwc::VerifiedWorkCertificate>> {
        observe_certificate(&self.l2_state()?, task_id, &self.validators, self.verifier)
    }

    /// §18.13: every certificate naming this worker, sorted by task id.
    pub fn certificates(&self) -> WorkerResult<Vec<srct_l2::vwc::VerifiedWorkCertificate>> {
        Ok(
            certificates_for_worker(&self.l2_state()?, &self.config.address)
                .into_iter()
                .cloned()
                .collect(),
        )
    }

    fn l2_state(&self) -> WorkerResult<L2State> {
        self.host.l2_state()
    }

    fn height(&self) -> WorkerResult<u64> {
        self.host.chain_height()
    }
}

/// A worker's economic position, derived from state (§18.13).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Earnings {
    /// Free balance (`L2State::balance`).
    pub available_sat: u64,
    /// Payment owed to this worker when its open/submitted tasks settle
    /// `Correct`: escrow minus the settle fee, per unfinished task.
    pub pending_sat: u64,
    /// This worker's own deposits still locked in unfinished tasks.
    pub deposits_at_risk_sat: u64,
    /// Total credited across settled-correct tasks
    /// (`worker_paid + worker_deposit_returned`, summed per task).
    pub settled_sat: u64,
    /// Deposits lost to fraud/expiry burns and slashes.
    pub lost_sat: u64,
}

/// Derive the economic position from authoritative state. Every number is a
/// protocol field; nothing is accumulated or invented (§18.13).
pub fn earnings_of(state: &L2State, worker: &srct_core::hash::Address) -> Earnings {
    let mut e = Earnings {
        available_sat: state.balance(worker),
        ..Default::default()
    };
    for contract in state.tasks() {
        let mine = contract.worker.as_ref() == Some(worker);
        if !mine {
            continue;
        }
        // Decision 23 (P5): pending escrow nets the proportional settle fee,
        // not the flat schedule value.
        let settle_fee = srct_core::l2::settle_fee_sat(contract.payment_sat);
        match &contract.state {
            srct_l2::ContractState::Open => {}
            srct_l2::ContractState::InProgress { .. }
            | srct_l2::ContractState::ResultSubmitted { .. } => {
                e.deposits_at_risk_sat = e
                    .deposits_at_risk_sat
                    .saturating_add(contract.worker_deposit_sat);
                e.pending_sat = e
                    .pending_sat
                    .saturating_add(contract.payment_sat.saturating_sub(settle_fee));
            }
            srct_l2::ContractState::Disputed(_) => {
                e.deposits_at_risk_sat = e
                    .deposits_at_risk_sat
                    .saturating_add(contract.worker_deposit_sat);
            }
            srct_l2::ContractState::Settled(o) => match o.verdict {
                srct_core::l2::Verdict::Correct => {
                    e.settled_sat = e
                        .settled_sat
                        .saturating_add(o.worker_paid + o.worker_deposit_returned);
                }
                srct_core::l2::Verdict::Fraudulent => {
                    e.lost_sat = e.lost_sat.saturating_add(o.worker_deposit_slashed);
                }
                srct_core::l2::Verdict::Expired => {
                    e.lost_sat = e.lost_sat.saturating_add(o.worker_deposit_burned);
                }
            },
            srct_l2::ContractState::Expired(x) => {
                e.lost_sat = e.lost_sat.saturating_add(x.worker_deposit_burned);
            }
        }
    }
    e
}
