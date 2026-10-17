//! A single-blob, crash-safe file for node-local state.
//!
//! The block log and metadata cover the chain; this covers the *books* a node
//! keeps beside it — receipts, payments, credit, escrows, delegations — the
//! state whose loss changes no consensus answer but whose loss does change what
//! the node remembers about its own counterparties. Like everything else in
//! this crate, the file stores bytes it is given and returns them unchanged:
//! what the bytes mean is the caller's question.
//!
//! Layout:
//!
//! ```text
//! file := magic(4) - version(2 LE) - reserved(2) - len(4 LE) - digest(32) - payload(len)
//! ```
//!
//! `digest` is `SHA256(payload)`. The digest makes a torn write, a bad sector
//! or a truncated flush an error rather than a shorter-but-valid file: every
//! byte of the payload is covered, so no subset of it reads back as intact.
//!
//! The distinction from [`crate::log`] applies here too, in simpler form:
//!
//! - **A missing file** is `Ok(None)` — a fresh node has nothing to load.
//! - **A damaged file** is an error, never `None` and never silent best-effort:
//!   a node that cannot read its own books must refuse to start with an empty
//!   set of them, because "I forgot every credit line" and "I have no credit
//!   lines" are the same bytes and opposite facts.
//!
//! Saves are atomic the way [`crate::meta::MetaFile`] is atomic: write beside,
//! flush, rename. The rename is the commit point.

use std::fs;
use std::path::{Path, PathBuf};

use jnt_core::hash::sha256;

use crate::StoreError;

/// File magic, so a foreign file is recognised rather than parsed.
pub const STATE_MAGIC: [u8; 4] = *b"JNTF";

/// On-disk format version.
pub const STATE_VERSION: u16 = 1;

/// Header size: magic(4) + version(2) + reserved(2) + len(4) + digest(32).
const STATE_HEADER_LEN: usize = 44;

/// Largest payload accepted.
///
/// The books are bounded by their own caps (a few thousand receipts, payments
/// and policies, each under a kilobyte), so real state sits in the low
/// megabytes; this is a lying-length guard, checked *before* any allocation,
/// not a target.
pub const MAX_STATE_BYTES: u32 = 64 * 1024 * 1024;

/// A crash-safe single-blob file: magic, version, length, digest, payload.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new(path: impl AsRef<Path>) -> Self {
        StateFile {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the payload, or `None` if the file does not exist.
    ///
    /// A *damaged* file is an error, not `None`: "never saved" and "saved but
    /// unreadable" demand opposite responses, and collapsing them would load an
    /// empty book over a corrupt one.
    pub fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::io(&self.path, e)),
        };
        // Magic before the header length: a foreign file of any size is
        // foreign, not "short".
        if bytes.len() < STATE_MAGIC.len() {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: format!(
                    "file is {} bytes, shorter than the {}-byte header",
                    bytes.len(),
                    STATE_HEADER_LEN
                ),
            });
        }
        if bytes[..4] != STATE_MAGIC {
            return Err(StoreError::BadMagic {
                path: self.path.clone(),
            });
        }
        if bytes.len() < STATE_HEADER_LEN {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: format!(
                    "file is {} bytes, shorter than the {}-byte header",
                    bytes.len(),
                    STATE_HEADER_LEN
                ),
            });
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != STATE_VERSION {
            return Err(StoreError::BadVersion {
                path: self.path.clone(),
                found: version,
                expected: STATE_VERSION,
            });
        }
        let len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if len > MAX_STATE_BYTES {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: format!("declared payload of {len} bytes is over the maximum"),
            });
        }
        let payload = &bytes[STATE_HEADER_LEN..];
        if payload.len() != len as usize {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: format!(
                    "header declares {len} payload bytes, file holds {}",
                    payload.len()
                ),
            });
        }
        let digest = sha256(&[payload]);
        if bytes[12..44] != digest {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: "payload digest does not match (torn write or bad sector)".into(),
            });
        }
        Ok(Some(payload.to_vec()))
    }

    /// Replace the payload atomically.
    ///
    /// Write beside, flush, then rename over the top. The rename is the commit
    /// point: before it the old state is authoritative, after it the new one
    /// is, and there is no moment in between.
    pub fn save(&self, payload: &[u8]) -> Result<(), StoreError> {
        use std::io::Write;

        let len = u32::try_from(payload.len()).map_err(|_| StoreError::BadState {
            path: self.path.clone(),
            detail: format!("payload of {} bytes is over the maximum", payload.len()),
        })?;
        if len > MAX_STATE_BYTES {
            return Err(StoreError::BadState {
                path: self.path.clone(),
                detail: format!("payload of {len} bytes is over the maximum"),
            });
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
            }
        }
        let digest = sha256(&[payload]);
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&STATE_MAGIC)
                .map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&STATE_VERSION.to_le_bytes())
                .map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&[0u8; 2])
                .map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&len.to_le_bytes())
                .map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&digest).map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(payload).map_err(|e| StoreError::io(&tmp, e))?;
            // The data must be on disk *before* the rename, or a crash can
            // leave the new name pointing at content that never landed.
            f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| StoreError::io(&self.path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jnt-store-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn payload_round_trips() {
        let f = StateFile::new(tmp("state1.bin"));
        let _ = fs::remove_file(f.path());
        f.save(b"the node's books").unwrap();
        assert_eq!(f.load().unwrap(), Some(b"the node's books".to_vec()));
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let f = StateFile::new(tmp("state_empty.bin"));
        f.save(b"").unwrap();
        assert_eq!(f.load().unwrap(), Some(Vec::new()));
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let f = StateFile::new(tmp("absent.bin"));
        let _ = fs::remove_file(f.path());
        assert_eq!(f.load().unwrap(), None);
    }

    /// A single flipped byte in the payload is damage, not a shorter state.
    #[test]
    fn a_damaged_payload_is_an_error() {
        let f = StateFile::new(tmp("state2.bin"));
        f.save(b"the node's books").unwrap();
        let mut bytes = fs::read(f.path()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(f.path(), bytes).unwrap();
        assert!(matches!(f.load(), Err(StoreError::BadState { .. })));
    }

    /// Truncation cannot read back as a valid shorter payload: the length
    /// field and the digest both disagree with what is left.
    #[test]
    fn a_truncated_file_is_an_error() {
        let f = StateFile::new(tmp("state3.bin"));
        f.save(b"the node's books").unwrap();
        let bytes = fs::read(f.path()).unwrap();
        fs::write(f.path(), &bytes[..bytes.len() - 4]).unwrap();
        assert!(matches!(f.load(), Err(StoreError::BadState { .. })));
    }

    #[test]
    fn a_foreign_file_is_recognised_not_parsed() {
        let f = StateFile::new(tmp("state4.bin"));
        fs::write(f.path(), b"JNTS not a state file at all").unwrap();
        assert!(matches!(f.load(), Err(StoreError::BadMagic { .. })));
    }

    #[test]
    fn a_future_version_is_refused() {
        let f = StateFile::new(tmp("state5.bin"));
        f.save(b"x").unwrap();
        let mut bytes = fs::read(f.path()).unwrap();
        bytes[4] = 99;
        // The version is not covered by the digest, so this reaches the
        // version check rather than failing as damage first.
        fs::write(f.path(), bytes).unwrap();
        assert!(matches!(
            f.load(),
            Err(StoreError::BadVersion { found: 99, .. })
        ));
    }
}
