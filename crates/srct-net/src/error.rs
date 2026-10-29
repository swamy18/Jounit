//! Network-layer failures only.
//!
//! `srct_core::Error` documents itself as "every variant is a deterministic,
//! consensus-visible condition" (`error.rs:3`). Network failures are the
//! opposite — nondeterministic, machine-dependent, policy-driven — so they live
//! here, never in `srct_core::Error`. Mixing them would either weaken the core
//! invariant (callers branch on `Error`) or leak transport concerns into every
//! validation path.

use std::fmt;
use std::io;

/// A network-layer (non-consensus) error.
#[derive(Debug)]
pub enum NetError {
    /// First bytes on the wire did not match this network's `network_magic`.
    /// This is the cheap pre-filter that stops a foreign chain's traffic at the
    /// framing layer before any large allocation.
    InvalidMagic { got: [u8; 4], want: [u8; 4] },
    /// Magic was right but `network_id` differed.
    NetworkIdMismatch { got: String, want: String },
    /// `payload_len` exceeded `max_frame_bytes`. Checked before allocating.
    OversizedFrame { len: u32 },
    /// Stream ended mid-frame.
    Truncated(String),
    /// Protocol state machine was violated (e.g. non-`VERSION` first message).
    Protocol(String),
    /// A peer did something that is not a protocol violation but is unwanted
    /// enough to warrant a disconnect, carrying the offending detail.
    Peer(String),
    /// Ban score reached the threshold (§13.9). The string is the reason.
    Banned(String),
    /// An inner `BLOCK`/`GETBLOCKS` payload failed to decode.
    Decode(String),
    /// A §13.8 resource bound refused an operation, e.g. `max_peers` reached.
    Resource(String),
    /// Underlying socket failure.
    Io(io::Error),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::InvalidMagic { got, want } => {
                write!(f, "wrong network magic got {got:02x?} want {want:02x?}")
            }
            NetError::NetworkIdMismatch { got, want } => {
                write!(f, "network_id mismatch got `{got}` want `{want}`")
            }
            NetError::OversizedFrame { len } => {
                write!(f, "frame exceeds max_frame_bytes ({len})")
            }
            NetError::Truncated(s) => write!(f, "stream truncated: {s}"),
            NetError::Protocol(s) => write!(f, "protocol violation: {s}"),
            NetError::Peer(s) => write!(f, "peer behaviour: {s}"),
            NetError::Banned(s) => write!(f, "peer banned: {s}"),
            NetError::Decode(s) => write!(f, "decoding payload: {s}"),
            NetError::Resource(s) => write!(f, "resource bound: {s}"),
            NetError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        NetError::Io(e)
    }
}

impl From<srct_core::Error> for NetError {
    fn from(e: srct_core::Error) -> Self {
        // Only used on the framing/IO path, never on the consensus path: this
        // conversion is for decoding wire bytes, and a decode failure there is
        // a `NetError`, not a consensus `Error`.
        NetError::Decode(e.to_string())
    }
}

pub type NetResult<T> = Result<T, NetError>;
