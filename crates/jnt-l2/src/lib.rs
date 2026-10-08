//! # jnt-l2
//!
//! Layer 2 of Jounit: the verified-work task marketplace.
//!
//! This crate is the state machine that turns the five L2 transaction types in
//! `jnt_core::l2` into a task lifecycle — post, claim, submit, dispute, settle —
//! and moves JNT against it deterministically.
//!
//! What is here:
//! - [`TaskContract`] and [`ContractState`]: the transitions, with no economic
//!   state and no cryptography.
//! - [`L2State`]: accounts, escrow, the M2 slash vault, D3 flat fees, replay
//!   protection, and a conservation invariant.
//! - [`L2Config`]: the two network-wide parameters (dispute window, vesting
//!   period).
//!
//! What is deliberately *not* here, and why:
//! - **L1 block validity.** L2 transactions are carried in L1 blocks and
//!   committed by each block's merkle root (Decision 6), and L2 state is rebuilt
//!   from that chain by [`replay::ChainL2`]. What is *not* here is any rule that
//!   makes an L1 block invalid because of its L2 content: an L2 payload that
//!   fails to apply is recorded by the replayer and skipped deterministically,
//!   never turned into a consensus rule. That separation is what keeps this
//!   integration from touching `Chain::submit`.
//! - **BLS finality activation.** `Settle` verifies a validator-quorum aggregate
//!   through the existing `BlsVerifier` trait, but nothing here finalizes an L1
//!   block. M5 stays inert until the end of the cycle (`docs/decisions.md`).
//!
//! What arrived with Phase 4:
//! - **Verified Work Certificates** ([`vwc`], SPEC.md §17): the protocol's
//!   receipt for verified correct work, issued automatically at settlement —
//!   `Quorum`-verified for an explicit `Settle`, `WindowElapsed` for an implicit
//!   one. Certificates hold no value and sit outside the conservation sum.
//!
//! Everything here is deterministic: no wall clock, no floating point, no
//! iteration-order dependence. `L2State::advance_block` sorts task ids before it
//! touches them, and a `HashMap` never decides an outcome.

pub mod deposits;
pub mod dispute;
pub mod error;
pub mod genesis;
pub mod replay;
pub mod reputation;
pub mod state;
pub mod task_contract;
pub mod vwc;

pub use deposits::{
    DepositIgnoreReason, DepositParams, DetectedDeposit, IgnoredDeposit, PendingDeposit,
};
pub use dispute::{Arbiter, DisputeEngine, DisputeEvidence, DisputeVerdict};
pub use error::{L2Error, L2Result};
pub use genesis::L2Genesis;
pub use replay::{ChainL2, SkippedL2};
pub use state::{L2Effect, L2State};
pub use task_contract::{
    ContractState, DisputeChallenge, ExpiryOutcome, L2Config, SettlementOutcome, TaskContract,
};
pub use vwc::{VerifiedWorkCertificate, VwcVerification, VWC_VERSION};
