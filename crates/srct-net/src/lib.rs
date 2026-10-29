//! Peer-to-peer transport for Solar Cyber Unit. **SPEC.md §13.**
//!
//! Deliberately dependency-free beyond `srct-core` and the standard library:
//! `std::net` + `std::thread`, one thread per peer, no async runtime. Mining is
//! CPU-bound and blocking, so an async runtime brings no benefit here and a
//! dependency footprint no benefit to a crate whose job is bounded byte I/O.
//!
//! ## Boundary
//!
//! `srct-core` is "no I/O, no clock, no network" (`lib.rs`). This crate owns all
//! of that and never re-enters consensus in a way that could surprise it: a
//! `Chain` lives on a single chain thread, peer threads hand it bytes over
//! channels, and `Error` from `srct-core` is never mixed with network failures.
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
