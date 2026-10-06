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
//! - **L1 integration.** How an L2 transaction enters an L1 block is Phase 6.
//!   Building that now would mean inventing block rules before the state machine
//!   above them was exercised.
//! - **BLS finality activation.** `Settle` verifies a validator-quorum aggregate
//!   through the existing `BlsVerifier` trait, but nothing here finalizes an L1
//!   block. M5 stays inert until the end of the cycle (`docs/decisions.md`).
//! - **Verified Work Certificates.** Settlement releases payment against a
//!   verdict; issuing a VWC is Phase 4.
//!
//! Everything here is deterministic: no wall clock, no floating point, no
//! iteration-order dependence. `L2State::advance_block` sorts task ids before it
//! touches them, and a `HashMap` never decides an outcome.

pub mod error;
pub mod state;
pub mod task_contract;

pub use error::{L2Error, L2Result};
pub use state::{L2Effect, L2State};
pub use task_contract::{
    ContractState, DisputeChallenge, ExpiryOutcome, L2Config, SettlementOutcome, TaskContract,
};
