//! Jounit node library root.
//!
//! Today this crate exposes exactly one item: [`l2::NodeL2`], the node's L2
//! view. Everything else lives in the binary (`main.rs`). The split exists so
//! integration tests can drive the accepted-block path without spawning a
//! process.
pub mod l2;
