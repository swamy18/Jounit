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
//! Deliberately **not** implemented yet: payment channels, bonds/slashing,
//! Verified Work Certificates, agent lineage, Bitcoin anchoring. See
//! `docs/roadmap.md`.

pub mod block;
pub mod chain;
pub mod difficulty;
pub mod error;
pub mod fees;
pub mod hash;
pub mod hexserde;
pub mod ledger;
pub mod params;
pub mod puzzle;
pub mod ser;
pub mod supply;
pub mod tx;
pub mod u256;
pub mod wallet;

pub use error::{Error, Result};
pub use hash::{Address, Hash};
