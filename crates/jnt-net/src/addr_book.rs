//! Persistent peer address book. SPEC.md §13.6.
//!
//! Stores known peer addresses with last-seen timestamps so a restart can
//! reconnect to peers it knew before. Capped at `MAX_ADDR_BOOK_ENTRIES` to
//! prevent unbounded growth from a flood of distinct source addresses.
//!
//! This is a *local* address book only — it is not populated from `ADDR`
//! gossip (§13.6 forbids that in v0.2). Addresses enter from `--connect`
//! flags, successful handshakes, and configured bootnodes.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum entries kept in the address book (§13.11 invariant: bounded).
pub const MAX_ADDR_BOOK_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddrEntry {
    addr: String,
    last_seen_ms: u64,
}

/// A persistent set of peer addresses with last-seen timestamps.
///
/// Written atomically (temp file → fsync → rename → 0600 perms), following
/// the same pattern as `jnt-store`'s `MetaFile::save`, so a crash leaves
/// either the old book or the new one, never a torn write.
pub struct AddressBook {
    path: PathBuf,
    entries: Vec<AddrEntry>,
}

impl AddressBook {
    /// Open (or create) the address book at `path`.
    ///
    /// A missing file is not an error — the book starts empty. A file that
    /// exists but cannot be parsed is also treated as empty: the address
    /// book is a performance optimisation, not consensus data, so a corrupt
    /// book should never prevent a node from starting.
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let entries = Self::load(&path).unwrap_or_default();
        AddressBook { path, entries }
    }

    /// The path this book persists to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(path: &Path) -> Result<Vec<AddrEntry>, String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }

    /// Persist the current entries atomically.
    ///
    /// Write beside, fsync, set 0600, then rename over the top. The rename
    /// is the commit point: before it the old file is authoritative, after it
    /// the new one is, and there is no moment where a reader sees a partial
    /// write.
    fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let tmp = self.path.with_extension("tmp");
        let json = serde_json::to_vec_pretty(&self.entries).map_err(|e| e.to_string())?;
        {
            let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&json).map_err(|e| e.to_string())?;
            // The data must be on disk *before* the rename, or a crash can
            // leave the new name pointing at content that never landed.
            f.sync_all().map_err(|e| e.to_string())?;
        }
        set_private_perms(&tmp);
        fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    /// Record an address as recently contacted.
    ///
    /// If the address is already known, its timestamp is bumped and the list
    /// is re-sorted. The book is saved immediately so a crash cannot forget a
    /// peer the node just learned about.
    pub fn add(&mut self, addr: SocketAddr) {
        let addr_str = addr.to_string();
        let now = now_ms();

        // Remove existing entry so order reflects recency.
        self.entries.retain(|e| e.addr != addr_str);

        self.entries.push(AddrEntry {
            addr: addr_str,
            last_seen_ms: now,
        });

        // Keep the book bounded and most-recent first.
        if self.entries.len() > MAX_ADDR_BOOK_ENTRIES {
            self.entries.sort_by_key(|a| std::cmp::Reverse(a.last_seen_ms));
            self.entries.truncate(MAX_ADDR_BOOK_ENTRIES);
        }

        let _ = self.save();
    }

    /// Record a batch of addresses. Equivalent to calling `add` for each, but
    /// defers the save until all are inserted.
    pub fn add_many(&mut self, addrs: &[SocketAddr]) {
        let now = now_ms();
        for addr in addrs {
            let addr_str = addr.to_string();
            self.entries.retain(|e| e.addr != addr_str);
            self.entries.push(AddrEntry {
                addr: addr_str,
                last_seen_ms: now,
            });
        }
        if self.entries.len() > MAX_ADDR_BOOK_ENTRIES {
            self.entries.sort_by_key(|a| std::cmp::Reverse(a.last_seen_ms));
            self.entries.truncate(MAX_ADDR_BOOK_ENTRIES);
        }
        let _ = self.save();
    }

    /// All known addresses, in descending last-seen order.
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.entries
            .iter()
            .rev()
            .filter_map(|e| e.addr.parse().ok())
            .collect()
    }

    /// Whether the book contains `addr`.
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        let s = addr.to_string();
        self.entries.iter().any(|e| e.addr == s)
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the book has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Restrict the temp-file permissions to 0600 before rename.
///
/// On non-Unix platforms there is no chmod, but the file is still renamed
/// atomically; the default permissions from `File::create` are the best we
/// can do there.
fn set_private_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(perms) = fs::Permissions::from_mode(0o600).into() {
            let _ = fs::set_permissions(path, perms);
        }
    }
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "jnt-addr-book-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("peers.json")
    }

    #[test]
    fn a_missing_file_starts_empty() {
        let path = tmp_path("missing");
        let ab = AddressBook::new(&path);
        assert_eq!(ab.len(), 0);
        assert!(ab.addresses().is_empty());
    }

    #[test]
    fn an_address_round_trips_through_disk() {
        let path = tmp_path("roundtrip");
        let mut ab = AddressBook::new(&path);
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        ab.add(addr);
        assert!(ab.contains(&addr));

        // Reopen from disk; the entry must survive.
        let ab2 = AddressBook::new(&path);
        assert!(ab2.contains(&addr));
        assert_eq!(ab2.len(), 1);
    }

    #[test]
    fn add_many_dedupes_and_saves() {
        let path = tmp_path("many");
        let mut ab = AddressBook::new(&path);
        let a1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        ab.add_many(&[a1, a2]);
        assert_eq!(ab.len(), 2);
        ab.add(a1);
        assert_eq!(ab.len(), 2, "adding a duplicate must not grow the book");
    }

    #[test]
    fn the_book_capped_at_1000_entries() {
        let path = tmp_path("capped");
        let mut ab = AddressBook::new(&path);
        for i in 0..MAX_ADDR_BOOK_ENTRIES + 50 {
            let addr: SocketAddr = format!("10.{}.{}.1:8333", (i >> 8) as u8, (i & 0xff) as u8)
                .parse()
                .unwrap();
            ab.add(addr);
        }
        assert_eq!(ab.len(), MAX_ADDR_BOOK_ENTRIES);
    }

    #[test]
    fn addresses_are_sorted_by_recency() {
        let path = tmp_path("order");
        let mut ab = AddressBook::new(&path);
        let a1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let a3: SocketAddr = "10.0.0.3:1234".parse().unwrap();
        ab.add_many(&[a1, a2, a3]);
        // Touch a1 to make it most recent.
        ab.add(a1);
        let addrs = ab.addresses();
        assert_eq!(addrs.first(), Some(&a1));
    }

    #[test]
    fn a_corrupt_book_starts_empty() {
        let path = tmp_path("corrupt");
        fs::write(&path, "not json").unwrap();
        let ab = AddressBook::new(&path);
        assert_eq!(ab.len(), 0);
    }
}
