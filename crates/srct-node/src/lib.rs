//! Solar Cyber Unit node library root.
//!
//! [`l2::NodeL2`] is the node's L2 view, [`conservation`] is the joint L1/L2
//! supply accounting the `verify` command reports, and [`api`] is the opt-in
//! service surface. Everything else lives in the binary (`main.rs`). The split
//! exists so integration tests can drive the accepted-block path without
//! spawning a process.
pub mod api;
pub mod conservation;
pub mod l2;
pub mod mediation;
pub mod wallet_store;
