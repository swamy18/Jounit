//! Peer-to-peer transport for Jounit. **SPEC.md §13.**
//!
//! Deliberately dependency-free beyond `jnt-core` and the standard library:
//! `std::net` + `std::thread`, one thread per peer, no async runtime. Mining is
//! CPU-bound and blocking, so an async runtime brings no benefit here and a
//! dependency footprint no benefit to a crate whose job is bounded byte I/O.
//!
//! ## Boundary
//!
//! `jnt-core` is "no I/O, no clock, no network" (`lib.rs`). This crate owns all
//! of that and never re-enters consensus in a way that could surprise it: a
//! `Chain` lives on a single chain thread, peer threads hand it bytes over
//! channels, and `Error` from `jnt-core` is never mixed with network failures.
//! See `error::NetError` for that separation.

pub mod addr_book;
pub mod error;
pub mod frame;
pub mod magic;
pub mod msg;
pub mod net;
pub mod peer;
pub mod relay;
pub mod syncer;
