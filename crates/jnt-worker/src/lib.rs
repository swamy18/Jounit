//! Worker SDK for the Jounit L2 task marketplace (SPEC.md §18).
//!
//! `jnt-worker` is a **client** crate: it builds already-specified L2 payloads,
//! signs them with the existing wallet, submits them through an injected
//! broadcaster, and derives discovery/earnings/dispute views from the
//! authoritative state the protocol produces. It implements no consensus rule:
//! `TaskContract` transitions, dispute arbitration, VWC validation, settlement
//! economics and fee routing are reused from `jnt-core` and `jnt-l2` verbatim
//! (§18.1).
//!
//! Module map:
//! - [`node`] — the `L2NodeView`/`L2Broadcaster` seams (§18.3)
//! - [`discovery`] — task discovery and filtering over authoritative state (§18.4)
//! - [`claim`] / [`submit`] — the two worker-side transaction flows (§18.5, §18.7)
//! - [`executor`] — the execution seam the operator plugs its engine into (§18.6)
//! - [`dispute`] — dispute observation and challenger participation (§18.14)
//! - [`vwc`] — certificate observation/validation (§18.13, reusing §17)
//! - [`client`] — the `WorkerClient` facade and `Earnings` (§18.9, §18.13)
//! - [`config`] — operator-supplied configuration (§18.12)
//! - [`error`] — the error taxonomy and its retry classification (§18.10)

pub mod claim;
pub mod client;
pub mod config;
pub mod discovery;
pub mod dispute;
pub mod error;
pub mod executor;
pub mod node;
pub mod submit;
pub mod vwc;

pub use claim::{claim_plan, claim_task, reconcile_claimed, ClaimPlan, ClaimedState};
pub use client::{earnings_of, Earnings, WorkerClient};
pub use config::{Filter, WorkerConfig};
pub use discovery::{discover_tasks, TaskRef};
pub use dispute::{
    dispute_of_task, dispute_plan, dispute_resolution, file_dispute, DisputePlan,
    DisputeResolution, DisputeView,
};
pub use error::{is_retryable, WorkerError, WorkerResult};
pub use executor::{
    execute_task, result_hash_of, CpuExecutor, ExecError, ExecutionOutput, ExecutionWork, Executor,
    ExecutorCapabilities,
};
pub use node::{BroadcastError, L2Broadcaster, L2NodeView};
pub use submit::{reconcile_submitted, submit_plan, submit_result, SubmitPlan, SubmittedState};
pub use vwc::{certificates_for_worker, is_offline_verifiable, observe_certificate};
