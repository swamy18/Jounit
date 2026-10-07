//! The node connection seam (SPEC.md §18.3).
//!
//! The SDK never decides what the chain is and never opens a socket of its
//! own. Protocol state arrives through [`L2NodeView`]; signed transactions
//! leave through [`L2Broadcaster`]. That split is deliberate:
//!
//! - This build has no L2 wire transport yet (`jnt-net` carries only the §13
//!   P2P message set; the roadmap §13 REST API is unbuilt). Wire-neutral
//!   traits are the only shape that is not a guess.
//! - Every protocol rule stays testable without a socket: an embedded
//!   `L2State` behind these traits exercises exactly the code a connected
//!   node would run.
//! - Responses are treated as untrusted data: whatever a view hands over,
//!   the protocol layer still verifies every authorization on anything the
//!   SDK produces (§18.11), and observation treats a view it cannot read as
//!   an error, never as an empty answer.
//!
//! A combined host (`view + broadcaster` in one object) implements both
//! traits and is passed to `WorkerClient::new` as its `&mut` pair via
//! [`Host`], which exists so a single node process can be one argument.

use jnt_l2::L2State;

use crate::error::WorkerError;

/// Read side: the authoritative, replicated view of L2 protocol state.
pub trait L2NodeView {
    fn l2_state(&self) -> L2State;
    /// The height the state reflects.
    fn chain_height(&self) -> u64;
}

/// A failure the write side reported. `Retryable` marks transport trouble
/// (§18.9: a timeout here does not mean the transaction failed — reconcile
/// by `txid` through the read side); `Refused` is a definitive answer the
/// node gave, surfaced verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// Send failed / socket lost / timed out. The transaction MAY have landed.
    Retryable(String),
    /// The node definitively refused the transaction. Its reason never
    /// contains signing material.
    Refused(String),
}

impl std::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BroadcastError::Retryable(s) => write!(f, "broadcast retryable: {s}"),
            BroadcastError::Refused(s) => write!(f, "broadcast refused: {s}"),
        }
    }
}

/// Write side: hand an already-signed transaction to the network.
///
/// The SDK only ever broadcasts complete `L2Transaction`s (signature bundles
/// included); nothing here can strip or mutate an authorization.
pub trait L2Broadcaster {
    fn broadcast(&mut self, tx: &jnt_core::l2::L2Transaction) -> Result<(), BroadcastError>;
}

impl From<BroadcastError> for WorkerError {
    fn from(_: BroadcastError) -> Self {
        // Both transport shapes reconcile the same way (§18.9): the
        // protocol's real answer arrives through the authoritative state, so
        // any broadcast failure is "unknown, go look", never "build a
        // different payload".
        WorkerError::BroadcastUnavailable("transport")
    }
}

/// A combined host: one object that is both a view and a broadcaster.
///
/// `WorkerClient` holds a `Host<V, B>` where `V: L2NodeView, B:
/// L2Broadcaster`; a local node passes itself as `Host<Self, Self>`.
#[derive(Debug, Clone)]
pub struct Host<V, B> {
    pub view: V,
    pub broadcaster: B,
}

impl<V, B> Host<V, B> {
    pub fn new(view: V, broadcaster: B) -> Self {
        Host { view, broadcaster }
    }
}

impl<V: L2NodeView, B: L2Broadcaster> L2NodeView for Host<V, B> {
    fn l2_state(&self) -> L2State {
        self.view.l2_state()
    }
    fn chain_height(&self) -> u64 {
        self.view.chain_height()
    }
}

impl<V: L2NodeView, B: L2Broadcaster> L2Broadcaster for Host<V, B> {
    fn broadcast(&mut self, tx: &jnt_core::l2::L2Transaction) -> Result<(), BroadcastError> {
        self.broadcaster.broadcast(tx)
    }
}
