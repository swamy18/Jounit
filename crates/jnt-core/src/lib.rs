//! # jnt-core
//!
//! Reference implementation of the Jounit base layer (SPEC.md v0.1).
//!
//! Scope of this crate:
//! - hybrid hash + neural PoW puzzle (SPEC.md §5) with a versioned puzzle registry
//! - canonical byte-level serialization (§3)
//! - UTXO ledger, transaction and block validation (§9)
//! - LWMA difficulty adjustment and tamper-resistant timestamp rules (§6)
//! - fixed-cap halving supply schedule and EIP-1559-shaped fee burn (§7, §8)
//! - deepest-chain fork choice with a finality rule
//!
//! Protocol Mechanisms (in-scope, SPEC.md §M1–§M5):
//! - M1: 50/50 PSCB base-fee split  (`fees.rs`, `chain.rs`)
//! - M2: Slash vesting vault          (`slash.rs`)
//! - M3: Hardware-agnostic compute IR (`compute_ir.rs`)
//! - M4: Memory-bound HBM scratchpad PoW (`hbm_pow.rs`)
//! - M5: Sovereign BLS finality gadget  (`bls_checkpoint.rs`)

pub mod block;
pub mod bls;
pub mod bls_checkpoint;
pub mod chain;
pub mod compute_ir;
pub mod difficulty;
pub mod error;
pub mod fees;
pub mod finality;
pub mod hash;
pub mod hbm_pow;
pub mod hexserde;
pub mod l2;
pub mod ledger;
pub mod mempool;
pub mod params;
pub mod puzzle;
pub mod ser;
pub mod sig;
pub mod slash;
pub mod supply;
pub mod tx;
pub mod u256;
pub mod validators;
pub mod wallet;

pub use error::{Error, Result};
pub use hash::{Address, Hash};
