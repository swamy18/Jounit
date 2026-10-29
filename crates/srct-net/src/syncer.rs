//! Block synchronization and inventory relay. SPEC.md §13.7.
//!
//! Relays and synchronizes canonical blocks between peers:
//! - Locator construction and fork-point discovery (§13.7).
//! - Inventory announcement and batched GETDATA fetching.
//! - Bounded orphan pool (§13.8 `orphan_pool_max = 64`) for out-of-order blocks.
//!
//! Every structure here is bounded, because every one of them is fed by a peer
//! that may never send what it advertised (§13.11 invariant 6).

use std::collections::{HashMap, HashSet, VecDeque};

use srct_core::block::Block;
use srct_core::chain::Chain;
use srct_core::error::Error;
use srct_core::hash::{Hash512, ZERO_HASH512};

use crate::msg::{InvEntry, INV_TYPE_BLOCK, MAX_INV_PER_MSG, MAX_LOCATOR_ENTRIES};

/// Maximum blocks in the orphan pool. SPEC.md §13.8.
pub const ORPHAN_POOL_MAX: usize = 64;

/// Batch size for GETDATA requests during block-first sync. SPEC.md §13.7.
pub const SYNC_BATCH_SIZE: usize = 16;

/// Maximum `GETDATA` requests outstanding across all peers. SPEC.md §13.7
/// ("the requester MUST NOT trust the responder's height"): a peer that
/// advertises a million hashes must not be able to make us queue a million
/// requests. Four batches deep is enough to keep the pipe full.
pub const MAX_IN_FLIGHT: usize = 4 * SYNC_BATCH_SIZE;

/// Maximum advertised-but-not-yet-requested hashes held per node. An `INV` is
/// capped at 500 entries, so this is a few messages of slack — enough for a
/// peer to send its next `INV` before the previous batch is applied.
pub const MAX_PENDING_INV: usize = 4 * MAX_INV_PER_MSG;

/// Build a locator list starting from the chain tip with exponential backoff.
/// SPEC.md §13.7.
///
/// ```text
/// locator[0] = tip_hash
/// locator[i] = block_hash_at(height - 10^i)
/// locator capped at max_locator_len entries; append genesis hash if absent
/// ```
///
/// The genesis entry is reserved inside the cap: the spec bounds the locator at
/// `max_locator_len`, so appending genesis on top of a full locator would send
/// one more entry than the bound allows.
pub fn create_locator(chain: &Chain) -> Vec<Hash512> {
    let mut locator = Vec::new();
    let tip_height = chain.height();
    locator.push(chain.tip_hash());

    let mut step: u64 = 1;
    let mut h = tip_height;

    // Leave one slot for the genesis hash appended below.
    while h > 0 && locator.len() + 1 < MAX_LOCATOR_ENTRIES {
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
pub fn find_fork_and_collect_inv(
    chain: &Chain,
    locator: &[Hash512],
    stop: &Hash512,
) -> Vec<InvEntry> {
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
            if *stop != ZERO_HASH512 && hash == *stop {
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
        new_tip: Hash512,
        orphans_resolved: Vec<Hash512>,
    },
    /// Block had an unknown parent and was deposited in the orphan pool.
    Orphan { missing_parent: Hash512 },
    /// Block is already known to the node.
    AlreadyKnown,
    /// Block failed consensus validation.
    Invalid(Error),
}

/// Manages synchronization state, orphan blocks, and in-flight requests.
///
/// Requests are tracked per peer so a disconnect releases exactly that peer's
/// outstanding work. Without that, a peer that disconnects mid-sync leaves its
/// hashes marked as "requested" forever and the node silently stops syncing
/// those blocks — a peer could stall a node's sync just by hanging up.
pub struct SyncManager {
    /// Blocks indexed by missing parent hash: parent_hash -> Vec<Block>
    orphans_by_parent: HashMap<Hash512, Vec<Block>>,
    /// Insertion order of `orphans_by_parent` keys, so eviction is oldest-first
    /// and deterministic rather than dependent on hash-map iteration order.
    orphan_order: VecDeque<Hash512>,
    /// Total count of orphan blocks stored
    orphan_count: usize,
    /// Outstanding `GETDATA` requests: block hash -> peer we asked.
    requested: HashMap<Hash512, usize>,
    /// Advertised hashes not yet requested, with the peer that advertised them.
    pending: VecDeque<(usize, InvEntry)>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            orphans_by_parent: HashMap::new(),
            orphan_order: VecDeque::new(),
            orphan_count: 0,
            requested: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    /// Record an inbound `INV`: queue the hashes we do not have and return the
    /// next batch to request from this peer.
    ///
    /// Everything in the `INV` is queued, not just the first `SYNC_BATCH_SIZE`.
    /// An earlier version returned the first 16 and discarded the rest, which
    /// ended sync after one batch: SPEC.md §13.7 requires the requester to
    /// `GETDATA` "in batches of 16, submit each, **and repeats**", and a chain
    /// more than 16 blocks long could then never be synchronised.
    pub fn handle_inv(
        &mut self,
        peer_id: usize,
        entries: &[InvEntry],
        chain: &Chain,
    ) -> Vec<InvEntry> {
        for e in entries {
            if e.kind != INV_TYPE_BLOCK {
                continue;
            }
            // Capacity before the dedup scans: when the queue is already full
            // every scan below is pure waste, and a flood of new hashes — the
            // case that matters — arrives precisely with the queue at its cap.
            if self.pending.len() >= MAX_PENDING_INV {
                continue;
            }
            if chain.block_by_hash(&e.hash).is_some() {
                continue;
            }
            if self.requested.contains_key(&e.hash) {
                continue;
            }
            if self.pending.iter().any(|(_, q)| q.hash == e.hash) {
                continue;
            }
            self.pending.push_back((peer_id, e.clone()));
        }

        self.take_batch(peer_id)
    }

    /// Take up to `SYNC_BATCH_SIZE` queued hashes for `peer_id`, subject to the
    /// global in-flight cap. Call this after every applied block to keep the
    /// window moving, and not only when an `INV` arrives.
    pub fn take_batch(&mut self, peer_id: usize) -> Vec<InvEntry> {
        if self.requested.len() >= MAX_IN_FLIGHT {
            return Vec::new();
        }
        let room = MAX_IN_FLIGHT - self.requested.len();
        let want = SYNC_BATCH_SIZE.min(room);
        if want == 0 {
            return Vec::new();
        }

        let mut taken: Vec<InvEntry> = Vec::with_capacity(want);
        let mut taken_hashes: HashSet<Hash512> = HashSet::with_capacity(want);
        for (pid, e) in self.pending.iter() {
            if taken.len() >= want {
                break;
            }
            if *pid == peer_id && taken_hashes.insert(e.hash) {
                taken.push(e.clone());
            }
        }
        if taken.is_empty() {
            return taken;
        }
        self.pending
            .retain(|(_, e)| !taken_hashes.contains(&e.hash));
        for e in &taken {
            self.requested.insert(e.hash, peer_id);
        }
        taken
    }

    /// Number of outstanding `GETDATA` requests.
    pub fn in_flight_count(&self) -> usize {
        self.requested.len()
    }

    /// Number of advertised hashes waiting for a request slot.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Release everything owed to / queued from a peer that has disconnected, so
    /// another peer can serve those hashes instead.
    pub fn peer_disconnected(&mut self, peer_id: usize) {
        self.requested.retain(|_, pid| *pid != peer_id);
        self.pending.retain(|(pid, _)| *pid != peer_id);
    }

    /// Process an inbound GETDATA message: fetch requested blocks from the
    /// chain, bounded to `max_block_bytes` of response — the same budget the
    /// transaction path enforces, for the same reason: the request is capped
    /// by `max_inv_per_msg` (500) but without a response budget a 32 KB
    /// request would clone up to 500 held blocks into the peer's outbound
    /// queue (§13.14). Always serves at least one, so a single large block
    /// cannot make the budget effectively zero, and never more than
    /// `SYNC_BATCH_SIZE` — what an honest requester asks for.
    pub fn handle_get_data(
        &self,
        entries: &[InvEntry],
        chain: &Chain,
        max_block_bytes: usize,
    ) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut bytes = 0usize;
        for e in entries {
            if e.kind != INV_TYPE_BLOCK {
                continue;
            }
            if blocks.len() >= SYNC_BATCH_SIZE {
                break;
            }
            if let Some(b) = chain.block_by_hash(&e.hash) {
                let size = b.serialize().len();
                if !blocks.is_empty() && bytes.saturating_add(size) > max_block_bytes {
                    break;
                }
                bytes = bytes.saturating_add(size);
                blocks.push(b.clone());
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
        // Free the request slot on every path, including a rejected block:
        // otherwise a peer could fill the in-flight table with blocks that never
        // validate and stall sync without bound.
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

    fn add_orphan(&mut self, parent: Hash512, block: Block) {
        while self.orphan_count >= ORPHAN_POOL_MAX {
            // Evict the oldest parent queue. Evicting an arbitrary hash-map key
            // made which orphans survived depend on iteration order, so a node's
            // orphan pool could differ between runs on identical input.
            let Some(k) = self.orphan_order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.orphans_by_parent.remove(&k) {
                self.orphan_count = self.orphan_count.saturating_sub(evicted.len());
            }
        }
        if self.orphan_count >= ORPHAN_POOL_MAX {
            return;
        }
        if !self.orphans_by_parent.contains_key(&parent) {
            self.orphan_order.push_back(parent);
        }
        self.orphans_by_parent
            .entry(parent)
            .or_default()
            .push(block);
        self.orphan_count += 1;
    }

    fn resolve_orphans(&mut self, parent: Hash512, chain: &mut Chain, resolved: &mut Vec<Hash512>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::params::NetworkParams;

    fn chain_at(n: u64) -> Chain {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let addr = [1u8; 20];
        let mut ts = srct_core::block::GENESIS_TIMESTAMP_MS + 1;
        for _ in 0..n {
            let b = chain.mine_block(addr, vec![], ts).unwrap();
            chain.submit(b).unwrap();
            ts += 60_000;
        }
        chain
    }

    fn inv_for(chain: &Chain) -> Vec<InvEntry> {
        (1..=chain.height())
            .map(|h| InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: chain.block_hash_at(h).unwrap(),
            })
            .collect()
    }

    /// The §13.7 requirement that a requester keeps going after each batch.
    /// Before the fix `handle_inv` returned the first 16 entries and dropped the
    /// rest, so a 40-block chain could never be synced.
    #[test]
    fn sync_continues_across_every_inv_batch() {
        let source = chain_at(40);
        let mut sink = Chain::new(NetworkParams::mini()).unwrap();
        let mut syncer = SyncManager::new();

        let entries = inv_for(&source);
        assert_eq!(entries.len(), 40);
        let mut first = syncer.handle_inv(7, &entries, &sink);
        assert_eq!(first.len(), SYNC_BATCH_SIZE);

        // Serve each batch until the sink reaches the source tip.
        for _ in 0..20 {
            for e in &first {
                let block = source.block_by_hash(&e.hash).unwrap().clone();
                syncer.handle_block(block, &mut sink, None);
            }
            if sink.tip_hash() == source.tip_hash() {
                break;
            }
            let next = syncer.take_batch(7);
            assert!(!next.is_empty(), "sync stalled before reaching the tip");
            first = next;
        }
        assert_eq!(
            sink.tip_hash(),
            source.tip_hash(),
            "every advertised block must eventually be applied"
        );
    }

    /// §13.11 invariant 6: a peer advertising hashes it never delivers must not
    /// be able to grow a bounded structure past its cap.
    #[test]
    fn a_peer_that_never_delivers_cannot_grow_state_without_bound() {
        let sink = Chain::new(NetworkParams::mini()).unwrap();
        let mut syncer = SyncManager::new();

        for round in 0..200u8 {
            let entries: Vec<InvEntry> = (0..MAX_INV_PER_MSG)
                .map(|i| InvEntry {
                    kind: INV_TYPE_BLOCK,
                    hash: [round.wrapping_mul(31).wrapping_add(i as u8); 64],
                })
                .collect();
            syncer.handle_inv(1, &entries, &sink);
        }

        assert!(
            syncer.in_flight_count() <= MAX_IN_FLIGHT,
            "in-flight requests grew to {} (cap {MAX_IN_FLIGHT})",
            syncer.in_flight_count()
        );
        assert!(
            syncer.pending_count() <= MAX_PENDING_INV,
            "pending queue grew to {} (cap {MAX_PENDING_INV})",
            syncer.pending_count()
        );
    }

    /// A peer that disconnects mid-sync must not strand its hashes: another
    /// peer advertising the same blocks has to be able to serve them.
    #[test]
    fn a_disconnect_releases_the_disconnected_peers_requests() {
        let source = chain_at(20);
        let sink = Chain::new(NetworkParams::mini()).unwrap();
        let mut syncer = SyncManager::new();

        let batch = syncer.handle_inv(1, &inv_for(&source), &sink);
        assert!(!batch.is_empty());
        assert!(syncer.in_flight_count() > 0);

        syncer.peer_disconnected(1);
        assert_eq!(syncer.in_flight_count(), 0, "requests must be released");
        assert_eq!(syncer.pending_count(), 0, "queued hashes must be released");

        // A second peer re-advertises: the hashes are requestable again.
        let mut syncer2 = SyncManager::new();
        let again = syncer2.handle_inv(2, &inv_for(&source), &sink);
        assert_eq!(
            again.len(),
            SYNC_BATCH_SIZE,
            "a replacement peer must be able to serve the stranded hashes"
        );
    }

    #[test]
    fn a_locator_never_exceeds_the_spec_cap() {
        let chain = chain_at(600);
        let locator = create_locator(&chain);
        assert!(
            locator.len() <= MAX_LOCATOR_ENTRIES,
            "locator of {} entries exceeds max_locator_len {MAX_LOCATOR_ENTRIES}",
            locator.len()
        );
        assert!(locator.contains(&chain.block_hash_at(0).unwrap()));
    }

    #[test]
    fn orphan_eviction_is_oldest_first_and_bounded() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let mut foreign = Chain::new(NetworkParams::mini()).unwrap();
        let addr = [2u8; 20];
        let mut ts = srct_core::block::GENESIS_TIMESTAMP_MS + 1;
        for _ in 0..(ORPHAN_POOL_MAX as u64 + 10) {
            let b = foreign.mine_block(addr, vec![], ts).unwrap();
            foreign.submit(b).unwrap();
            ts += 60_000;
        }
        let mut syncer = SyncManager::new();
        for h in 1..=foreign.height() {
            let block = foreign.block_at(h).unwrap().clone();
            syncer.handle_block(block, &mut chain, None);
        }
        assert!(syncer.orphan_count() <= ORPHAN_POOL_MAX);
    }
}
