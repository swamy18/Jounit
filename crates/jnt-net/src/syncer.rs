//! Block synchronization and inventory relay. SPEC.md §13.7.
//!
//! Relays and synchronizes canonical blocks between peers:
//! - Locator construction and fork-point discovery (§13.7).
//! - Inventory announcement and batch GETDATA fetching.
//! - Bounded orphan pool (§13.8 `orphan_pool_max = 64`) for handling out-of-order blocks.

use std::collections::{HashMap, HashSet};

use jnt_core::block::Block;
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::hash::Hash;

use crate::msg::{InvEntry, INV_TYPE_BLOCK, MAX_INV_PER_MSG, MAX_LOCATOR_ENTRIES};

/// Maximum blocks in the orphan pool. SPEC.md §13.8.
pub const ORPHAN_POOL_MAX: usize = 64;

/// Batch size for GETDATA requests during block-first sync. SPEC.md §13.7.
pub const SYNC_BATCH_SIZE: usize = 16;

/// Build a locator list starting from the chain tip with exponential backoff.
/// SPEC.md §13.7.
///
/// ```text
/// locator[0] = tip_hash
/// locator[i] = block_hash_at(height - 10^i)
/// locator capped at 500 entries; append genesis hash if absent
/// ```
pub fn create_locator(chain: &Chain) -> Vec<Hash> {
    let mut locator = Vec::new();
    let tip_height = chain.height();
    locator.push(chain.tip_hash());

    let mut step: u64 = 1;
    let mut h = tip_height;

    while h > 0 && locator.len() < MAX_LOCATOR_ENTRIES {
        if h >= step {
            h -= step;
        } else {
            h = 0;
        }
        if let Some(hash) = chain.block_hash_at(h) {
            if !locator.contains(&hash) {
                locator.push(hash);
            }
        }
        if locator.len() > 10 {
            step = step.saturating_mul(2);
        }
        if h == 0 {
            break;
        }
    }

    // Always append genesis hash if missing
    if let Some(genesis_hash) = chain.block_hash_at(0) {
        if !locator.contains(&genesis_hash) {
            locator.push(genesis_hash);
        }
    }

    locator
}

/// Find the highest common canonical block from the locator and return an INV
/// batch of up to 500 subsequent blocks along the canonical chain. SPEC.md §13.7.
pub fn find_fork_and_collect_inv(chain: &Chain, locator: &[Hash], stop: &Hash) -> Vec<InvEntry> {
    let mut fork_height = 0;
    let mut found = false;

    // Walk locator from top to bottom to find the latest common block in canon
    for h in locator {
        if let Some(block) = chain.block_by_hash(h) {
            if chain.block_hash_at(block.header.height) == Some(*h) {
                fork_height = block.header.height;
                found = true;
                break;
            }
        }
    }

    if !found {
        fork_height = 0;
    }

    let mut entries = Vec::new();
    let tip_height = chain.height();
    let start = fork_height + 1;
    let end = (start + MAX_INV_PER_MSG as u64).min(tip_height + 1);

    for h in start..end {
        if let Some(hash) = chain.block_hash_at(h) {
            entries.push(InvEntry {
                kind: INV_TYPE_BLOCK,
                hash,
            });
            if *stop != Hash::default() && hash == *stop {
                break;
            }
        }
    }

    entries
}

/// Result of submitting a relayed block.
#[derive(Debug)]
pub enum SyncResult {
    /// Block was accepted; `extended_tip` indicates if the canonical tip advanced.
    Accepted {
        extended_tip: bool,
        new_tip: Hash,
        orphans_resolved: Vec<Hash>,
    },
    /// Block had an unknown parent and was deposited in the orphan pool.
    Orphan { missing_parent: Hash },
    /// Block is already known to the node.
    AlreadyKnown,
    /// Block failed consensus validation.
    Invalid(Error),
}

/// Manages synchronization state, orphan blocks, and in-flight requests.
pub struct SyncManager {
    /// Blocks indexed by missing parent hash: parent_hash -> Vec<Block>
    orphans_by_parent: HashMap<Hash, Vec<Block>>,
    /// Total count of orphan blocks stored
    orphan_count: usize,
    /// In-flight block requests to avoid redundant GETDATA
    requested: HashSet<Hash>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            orphans_by_parent: HashMap::new(),
            orphan_count: 0,
            requested: HashSet::new(),
        }
    }

    /// Process an inbound INV message: filter out blocks already present in the chain
    /// or orphan pool, and return up to `SYNC_BATCH_SIZE` entries to request via GETDATA.
    pub fn handle_inv(&mut self, entries: &[InvEntry], chain: &Chain) -> Vec<InvEntry> {
        let mut to_request = Vec::new();

        for e in entries {
            if e.kind != INV_TYPE_BLOCK {
                continue;
            }
            if chain.block_by_hash(&e.hash).is_some() {
                continue;
            }
            if self.requested.contains(&e.hash) {
                continue;
            }
            self.requested.insert(e.hash);
            to_request.push(e.clone());
            if to_request.len() >= SYNC_BATCH_SIZE {
                break;
            }
        }

        to_request
    }

    /// Process an inbound GETDATA message: fetch requested blocks from the chain.
    pub fn handle_get_data(&self, entries: &[InvEntry], chain: &Chain) -> Vec<Block> {
        let mut blocks = Vec::new();
        for e in entries {
            if e.kind == INV_TYPE_BLOCK {
                if let Some(b) = chain.block_by_hash(&e.hash) {
                    blocks.push(b.clone());
                }
            }
        }
        blocks
    }

    /// Process an inbound block: submit to the chain and recursively resolve orphans.
    pub fn handle_block(
        &mut self,
        block: Block,
        chain: &mut Chain,
        now_ms: Option<u64>,
    ) -> SyncResult {
        let block_hash = block.block_hash();
        self.requested.remove(&block_hash);

        let prev_tip = chain.tip_hash();

        match chain.submit_at(block.clone(), now_ms) {
            Ok(()) => {
                let current_tip = chain.tip_hash();
                let extended_tip = current_tip != prev_tip;
                let mut resolved = Vec::new();

                // Recursively resolve any orphans waiting for this block
                self.resolve_orphans(block_hash, chain, &mut resolved);

                SyncResult::Accepted {
                    extended_tip,
                    new_tip: chain.tip_hash(),
                    orphans_resolved: resolved,
                }
            }
            Err(Error::UnknownParent) => {
                let parent = block.header.prev_hash;
                self.add_orphan(parent, block);
                SyncResult::Orphan {
                    missing_parent: parent,
                }
            }
            Err(Error::AlreadyKnown) => SyncResult::AlreadyKnown,
            Err(e) => SyncResult::Invalid(e),
        }
    }

    fn add_orphan(&mut self, parent: Hash, block: Block) {
        if self.orphan_count >= ORPHAN_POOL_MAX {
            // Evict an arbitrary parent queue if capacity reached
            if let Some(k) = self.orphans_by_parent.keys().next().copied() {
                if let Some(evicted) = self.orphans_by_parent.remove(&k) {
                    self.orphan_count = self.orphan_count.saturating_sub(evicted.len());
                }
            }
        }
        self.orphans_by_parent
            .entry(parent)
            .or_default()
            .push(block);
        self.orphan_count += 1;
    }

    fn resolve_orphans(&mut self, parent: Hash, chain: &mut Chain, resolved: &mut Vec<Hash>) {
        if let Some(children) = self.orphans_by_parent.remove(&parent) {
            self.orphan_count = self.orphan_count.saturating_sub(children.len());
            for child in children {
                let child_hash = child.block_hash();
                if chain.submit(child.clone()).is_ok() {
                    resolved.push(child_hash);
                    self.resolve_orphans(child_hash, chain, resolved);
                }
            }
        }
    }

    pub fn orphan_count(&self) -> usize {
        self.orphan_count
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}
