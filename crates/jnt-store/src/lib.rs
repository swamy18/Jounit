//! Jounit persistent storage.
//!
//! **This crate holds no consensus rules and must never acquire any.** It stores
//! bytes it is given, returns them unchanged, and records which block a node has
//! decided is canonical. Whether a block is *valid* is `jnt-core`'s question; the
//! store does not ask it, and could not answer it if it tried — it has no chain
//! state. That boundary is what keeps a storage bug from becoming a consensus
//! bug: the worst this crate can do is fail to return a block, never mutate one.
//!
//! Replacing the node's `blocks.json`, which rewrote the entire chain on every
//! block (O(n) per block, O(n²) per sync).
//!
//! # Design
//!
//! - **One append-only log of blocks, and nothing else.** There is no index file,
//!   because an index file is a second source of truth that can disagree with the
//!   first. The index is rebuilt by scanning the log at open, so a corrupted
//!   index is not a failure mode that exists — the only copy of the data is the
//!   data. The cost is an O(chain) scan at startup, which is the honest trade for
//!   a store that cannot silently disagree with itself.
//! - **Canonical versus side branch is a marker, not a layout.** Side branches
//!   are simply blocks in the log; the canonical chain is a tip hash plus a
//!   height in metadata, walked backwards through parent hashes. A reorg writes
//!   eight bytes of metadata and moves nothing.
//! - **Metadata is replaced atomically** (write beside, then rename), so a crash
//!   leaves either the old tip or the new one, never half of either.
//! - **The log is durable only when asked.** [`BlockStore::flush`] flushes and
//!   [`BlockStore::sync`] asks the platform for stable storage, so a caller
//!   appending a batch of blocks pays for one flush rather than one per block.
//!
//! # What a crash can and cannot do
//!
//! | Situation | Result |
//! |---|---|
//! | Crash mid-append | The torn tail is dropped and **reported**; every earlier block survives |
//! | Crash between block and metadata | The block is present but not marked canonical; the tip is unchanged |
//! | Damage with data after it | The store **refuses to open**, naming the offset |
//! | Wrong magic or format version | Refused, not misread |
//! | Duplicate block appended | Accepted, stored once, both callers get the same reference |
//!
//! The distinction between "drop the tail" and "refuse to open" is the important
//! one. A crash is recoverable by construction; damage to already-committed data
//! is not, and truncating past it would report success while silently shortening
//! the chain. See [`log`].

pub mod blocks;
pub mod log;
pub mod meta;

use std::path::{Path, PathBuf};

pub use blocks::{AppendOutcome, BlockStore, StoreInfo};
pub use log::{RecordLog, RecordRef, Recovery};
pub use meta::{Meta, MetaFile};

/// Everything the store can go wrong with.
///
/// Every variant names what was wrong *and where*, because the alternative — a
/// store that fails with "invalid data" — leaves an operator with a corrupt
/// chain and no way to find out how far the damage goes.
#[derive(Debug)]
pub enum StoreError {
    /// An operating-system call failed.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file is not a Jounit store.
    BadMagic { path: PathBuf },
    /// The file was written by a different format version.
    BadVersion {
        path: PathBuf,
        found: u16,
        expected: u16,
    },
    /// Committed data is damaged, with more data after it.
    ///
    /// Never returned for a torn tail: that is recovered, not reported as
    /// corruption. See the module documentation.
    Corrupt {
        path: PathBuf,
        offset: u64,
        detail: String,
    },
    /// A record longer than [`log::MAX_RECORD_BYTES`].
    RecordTooLarge { len: usize, max: u32 },
    /// A block's parent is not in the store, so a canonical chain cannot be
    /// walked to it.
    MissingParent { hash: [u8; 32] },
    /// Metadata names a tip the log does not hold.
    MissingBlock { hash: [u8; 32] },
    /// A block that could not be decoded.
    BadBlock { detail: String },
    /// Metadata is unreadable even though its checksum matched its write.
    BadMeta { detail: String },
}

impl StoreError {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        StoreError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            StoreError::BadMagic { path } => {
                write!(f, "{}: not a Jounit store (bad magic)", path.display())
            }
            StoreError::BadVersion {
                path,
                found,
                expected,
            } => write!(
                f,
                "{}: store format version {found}, this build reads {expected}",
                path.display()
            ),
            StoreError::Corrupt {
                path,
                offset,
                detail,
            } => write!(
                f,
                "{}: corrupt at byte {offset} ({detail}) — refusing to open rather than \
                 truncating committed data",
                path.display()
            ),
            StoreError::RecordTooLarge { len, max } => {
                write!(f, "record of {len} bytes exceeds the {max}-byte maximum")
            }
            StoreError::MissingParent { hash } => {
                write!(f, "block {} has no parent in the store", hex(hash))
            }
            StoreError::MissingBlock { hash } => {
                write!(f, "canonical tip {} is not in the store", hex(hash))
            }
            StoreError::BadBlock { detail } => write!(f, "undecodable block: {detail}"),
            StoreError::BadMeta { detail } => write!(f, "unreadable metadata: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn hex(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in h {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
