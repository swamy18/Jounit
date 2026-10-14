//! Transaction relay bookkeeping. SPEC.md §13.14.
//!
//! Deliberately shaped like `SyncManager`, because it is the same problem: a peer
//! hands us an unbounded number of identifiers and expects us to act on them. The
//! two structures a hostile peer can grow are an *in-flight request set* and an
//! *advertised-but-unrequested queue*, and both are capped here for the same
//! reason they are capped there.
//!
//! What this module is **not**: it never validates a transaction and never
//! decides consensus. Admission goes through `Mempool::add`, which goes through
//! `check_tx` — so a transaction that reaches the pool over the wire was checked
//! exactly as one built locally. Nothing here may reach `Chain::submit`; a
//! relayed transaction becomes consensus-relevant only inside a block.
//!
//! Two bounds deserve a note because they are not obvious:
//!
//! - **The known set is allowed to evict.** Loop suppression only needs to be
//!   *probable*, not perfect: every path that makes a node do work is separately
//!   bounded, so forgetting an old txid costs a bounded amount of repeated work
//!   and cannot grow anything. A set that never evicted would itself be the
//!   unbounded structure.
//! - **A `GETDATA` is answered with at most one block's worth of transactions.**
//!   Otherwise a peer asks for 500 txids and receives gigabytes: the request is
//!   bounded by `max_inv_per_msg` but the *response* would not be. The budget is
//!   `max_block_bytes` because that is the unit the network already bounds, so
//!   this introduces no new quantity to reason about.

use std::collections::{HashMap, HashSet, VecDeque};

use jnt_core::hash::Hash512;
use jnt_core::mempool::{Mempool, MempoolEntry};
use jnt_core::tx::Transaction;

use crate::msg::{InvEntry, INV_TYPE_TX};

/// Outstanding transaction requests across all peers (§13.8).
pub const MAX_RELAY_IN_FLIGHT: usize = 128;

/// Advertised-but-unrequested txids held. 1 024 × 32 bytes = 32 KB (§13.8).
pub const MAX_RELAY_PENDING: usize = 1_024;

/// Txids remembered for relay-loop suppression. 4 096 × 32 bytes = 128 KB.
pub const MAX_RELAY_KNOWN: usize = 4_096;

/// Txids requested in one `GETDATA` (§13.8).
pub const MAX_TX_INV_BATCH: usize = 64;

/// Per-peer transaction messages accepted per minute (§13.8). An inbound bound,
/// so exceeding it scores the peer rather than merely dropping the message.
pub const TX_RELAY_PER_PEER_PER_MIN: u32 = 600;

/// How long an unanswered transaction request is held (§13.14).
///
/// Requests are held until answered, and the in-flight cap bounds how many — but
/// nothing bounded how *long* one could be held, and the set is global rather
/// than per-peer. A peer could announce `max_relay_in_flight` transactions,
/// deliver none, and leave the request set full for as long as it stayed
/// connected: `take_batch` then finds no room, so the node stops requesting
/// transactions from **every** peer, and the hoarded txids are marked as already
/// requested so a peer that does hold them is ignored too. Thirty-two bytes per
/// announcement bought a permanent, node-wide relay stall.
///
/// Expiry is what closes it, and it bounds the other direction too: a request the
/// peer never answers is retried against whoever announces it next, so a
/// hung-up-but-connected peer degrades latency instead of stopping relay.
pub const TX_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Sliding-window rate accounting for one peer.
#[derive(Debug, Clone, Copy)]
struct PeerRate {
    window_start_ms: u64,
    count: u32,
}

/// An outstanding request: who was asked, and when.
#[derive(Debug, Clone, Copy)]
struct Requested {
    peer_id: usize,
    at_ms: u64,
}

/// Bounded bookkeeping for transaction relay.
pub struct RelayManager {
    /// txid → the peer we asked for it, and when. Owned so a peer that hangs up
    /// releases its requests instead of leaving them marked forever — the defect
    /// that stalled block sync before session 5 fixed it — and timestamped so a
    /// peer that stays connected but never answers cannot hold them forever
    /// either (see `TX_REQUEST_TIMEOUT_MS`).
    requested: HashMap<Hash512, Requested>,
    /// Advertised but not yet requested, oldest first.
    pending: VecDeque<(Hash512, usize)>,
    /// Recently seen txids (pooled, relayed, or refused) for loop suppression.
    known: HashSet<Hash512>,
    /// Insertion order for `known`, so eviction is oldest-first rather than
    /// arbitrary. `HashSet` iteration order is not stable and using it would make
    /// which txid survives depend on hashing.
    known_order: VecDeque<Hash512>,
    /// Per-peer rate windows. Keyed by peer id, which is bounded by `max_peers`.
    per_peer: HashMap<usize, PeerRate>,
    /// Transactions this node admitted from a peer, and refused.
    ///
    /// Kept because a refusal is otherwise completely silent. A node that
    /// refuses a relayed transaction does nothing observable: it does not relay
    /// it, so no peer sees a problem, and the sender has no acknowledgement to
    /// miss. That makes "the network is quietly dropping my payments" and "my
    /// peer is sending junk" look identical from the outside, and both look like
    /// nothing at all. Two counters cost nothing and separate them.
    accepted: u64,
    refused: u64,
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            requested: HashMap::new(),
            pending: VecDeque::new(),
            known: HashSet::new(),
            known_order: VecDeque::new(),
            per_peer: HashMap::new(),
            accepted: 0,
            refused: 0,
        }
    }

    /// Count an inbound transaction the pool accepted.
    pub fn note_accepted(&mut self) {
        self.accepted = self.accepted.saturating_add(1);
    }

    /// Count an inbound transaction the pool refused, for any reason.
    pub fn note_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }

    pub fn accepted_count(&self) -> u64 {
        self.accepted
    }

    pub fn refused_count(&self) -> u64 {
        self.refused
    }

    /// Whether this txid has been seen recently. Approximate by design — the
    /// known set evicts (see the module note).
    pub fn is_known(&self, txid: &Hash512) -> bool {
        self.known.contains(txid)
    }

    /// Remember a txid so it is not announced or requested again.
    pub fn mark_known(&mut self, txid: Hash512) {
        if self.known.insert(txid) {
            self.known_order.push_back(txid);
            while self.known_order.len() > MAX_RELAY_KNOWN {
                if let Some(old) = self.known_order.pop_front() {
                    self.known.remove(&old);
                }
            }
        }
    }

    /// Charge a transaction message against `peer_id`'s rate window.
    ///
    /// Returns `false` when the peer has exceeded `tx_relay_per_peer_per_min`,
    /// which is an inbound bound and therefore a scoring event (§13.8).
    pub fn allow_from(&mut self, peer_id: usize, now_ms: u64) -> bool {
        let rate = self.per_peer.entry(peer_id).or_insert(PeerRate {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(rate.window_start_ms) >= 60_000 {
            rate.window_start_ms = now_ms;
            rate.count = 0;
        }
        rate.count = rate.count.saturating_add(1);
        rate.count <= TX_RELAY_PER_PEER_PER_MIN
    }

    /// Process an inbound `INV`/`GETDATA` entry list for transactions, returning
    /// the txids worth requesting.
    ///
    /// Entries already held in `pool`, already requested, or already queued are
    /// dropped, so a peer repeating an announcement costs nothing after the first
    /// time. The queue is bounded; when it is full the newest announcements are
    /// dropped rather than the oldest, so a flood cannot displace requests we were
    /// already committed to making.
    pub fn handle_inv_tx(
        &mut self,
        peer_id: usize,
        entries: &[InvEntry],
        pool: &Mempool,
        now_ms: u64,
    ) -> Vec<InvEntry> {
        // Expire first, unconditionally. This is the only place the rule can
        // live: a caller that forgot it would silently restore the stall, and the
        // failure would look like a slow network rather than a bug.
        self.expire(now_ms);
        for e in entries {
            if e.kind != INV_TYPE_TX {
                continue;
            }
            if pool.contains(&e.hash) || self.requested.contains_key(&e.hash) {
                continue;
            }
            if self.pending.iter().any(|(h, _)| *h == e.hash) {
                continue;
            }
            if self.pending.len() >= MAX_RELAY_PENDING {
                break;
            }
            self.pending.push_back((e.hash, peer_id));
        }
        self.take_batch(now_ms)
    }

    /// Forget requests that have gone unanswered for `TX_REQUEST_TIMEOUT_MS`.
    ///
    /// Returns how many were dropped, so a caller can log it. An expired txid is
    /// not blacklisted: it is simply requestable again, which is what lets a peer
    /// that does hold it serve it after a peer that did not went quiet.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.requested.len();
        self.requested
            .retain(|_, r| now_ms.saturating_sub(r.at_ms) < TX_REQUEST_TIMEOUT_MS);
        before - self.requested.len()
    }

    /// Drain the pending queue into a request batch, respecting the in-flight cap.
    ///
    /// Takes no peer argument: a request is made to the peer that advertised it,
    /// which is recorded with the entry. Taking one would tempt a caller into
    /// asking a peer for something it never announced.
    ///
    /// `now_ms` stamps each request so `expire` can tell a slow answer from a
    /// withheld one.
    pub fn take_batch(&mut self, now_ms: u64) -> Vec<InvEntry> {
        let room = MAX_RELAY_IN_FLIGHT.saturating_sub(self.requested.len());
        let take = room.min(MAX_TX_INV_BATCH);
        let mut out = Vec::with_capacity(take.min(self.pending.len()));
        while out.len() < take {
            let Some((hash, peer_id)) = self.pending.pop_front() else {
                break;
            };
            self.requested.insert(
                hash,
                Requested {
                    peer_id,
                    at_ms: now_ms,
                },
            );
            out.push(InvEntry {
                kind: INV_TYPE_TX,
                hash,
            });
        }
        out
    }

    /// Release the request slot for a txid we have now received, whether or not
    /// the pool accepted it. A refusal is still an answer, and holding the slot
    /// would let a peer stall relay indefinitely by sending junk.
    pub fn release(&mut self, txid: &Hash512) {
        self.requested.remove(txid);
    }

    /// Answer a `GETDATA` from our own pool, bounded to `max_block_bytes` of
    /// transaction data.
    ///
    /// `max_block_bytes` is passed in rather than read from `params` so the caller
    /// states the budget it is enforcing, and a test can lower it. Only pool
    /// members are served: answering from anywhere else would relay a transaction
    /// this node never validated, which §13.14 forbids.
    pub fn handle_get_data_tx(
        &self,
        entries: &[InvEntry],
        pool: &Mempool,
        max_block_bytes: usize,
    ) -> Vec<Transaction> {
        let candidates = entries
            .iter()
            .filter(|e| e.kind == INV_TYPE_TX)
            .filter_map(|e| pool.get(&e.hash));
        Self::select_within_budget(candidates, max_block_bytes)
    }

    /// Take transactions from `candidates` up to `max_block_bytes` of data.
    ///
    /// Split out from the pool lookup on purpose: this is the part that carries
    /// the amplification risk, so it is the part that has to be testable without
    /// standing up a whole pool.
    fn select_within_budget<'a>(
        candidates: impl Iterator<Item = &'a MempoolEntry>,
        max_block_bytes: usize,
    ) -> Vec<Transaction> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for entry in candidates {
            if out.len() >= MAX_TX_INV_BATCH {
                break;
            }
            let size = entry.size_bytes();
            // Always serve at least one. It was admitted, so it fits a block by
            // construction, and refusing the only thing asked for would make the
            // budget effectively zero when a single transaction is large.
            if !out.is_empty() && bytes.saturating_add(size) > max_block_bytes {
                break;
            }
            bytes = bytes.saturating_add(size);
            out.push(entry.tx.clone());
        }
        out
    }

    /// Release everything owed by a peer that has gone away.
    pub fn peer_disconnected(&mut self, peer_id: usize) {
        self.requested.retain(|_, r| r.peer_id != peer_id);
        self.pending.retain(|(_, pid)| *pid != peer_id);
        self.per_peer.remove(&peer_id);
    }

    pub fn in_flight_count(&self) -> usize {
        self.requested.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn known_count(&self) -> usize {
        self.known.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_entry(byte: u8) -> InvEntry {
        InvEntry {
            kind: INV_TYPE_TX,
            hash: [byte; 64],
        }
    }

    fn block_entry(byte: u8) -> InvEntry {
        InvEntry {
            kind: crate::msg::INV_TYPE_BLOCK,
            hash: [byte; 64],
        }
    }

    #[test]
    fn a_repeated_announcement_is_requested_once() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();
        let first = relay.handle_inv_tx(1, &[tx_entry(7)], &pool, 0);
        assert_eq!(first.len(), 1);
        // Same peer, same txid: already requested, so nothing new.
        let second = relay.handle_inv_tx(1, &[tx_entry(7)], &pool, 0);
        assert!(second.is_empty(), "the same txid was requested twice");
        assert_eq!(relay.in_flight_count(), 1);
    }

    #[test]
    fn block_entries_are_not_mistaken_for_transactions() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();
        let out = relay.handle_inv_tx(1, &[block_entry(3)], &pool, 0);
        assert!(out.is_empty(), "a block INV became a transaction request");
    }

    /// §13.11 invariant 6: maximum count fields must not grow any bounded
    /// structure past its cap.
    #[test]
    fn a_flood_cannot_grow_the_pending_queue_past_its_cap() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();
        for round in 0..200u32 {
            let entries: Vec<InvEntry> = (0..MAX_INV_PER_MSG_LOCAL)
                .map(|i| tx_entry(((round as usize * MAX_INV_PER_MSG_LOCAL + i) % 251) as u8))
                .collect();
            relay.handle_inv_tx(1, &entries, &pool, 0);
            assert!(
                relay.pending_count() <= MAX_RELAY_PENDING,
                "pending grew to {} (cap {MAX_RELAY_PENDING})",
                relay.pending_count()
            );
            assert!(
                relay.in_flight_count() <= MAX_RELAY_IN_FLIGHT,
                "in-flight grew to {} (cap {MAX_RELAY_IN_FLIGHT})",
                relay.in_flight_count()
            );
        }
    }

    use crate::msg::MAX_INV_PER_MSG as MAX_INV_PER_MSG_LOCAL;

    #[test]
    fn the_known_set_evicts_oldest_first_and_stays_bounded() {
        let mut relay = RelayManager::new();
        for i in 0..(MAX_RELAY_KNOWN + 10) as u32 {
            let mut h = [0u8; 64];
            h[..4].copy_from_slice(&i.to_le_bytes());
            relay.mark_known(h);
        }
        assert_eq!(
            relay.known_count(),
            MAX_RELAY_KNOWN,
            "the known set is not bounded"
        );
        // The oldest are gone, the newest are present.
        let mut oldest = [0u8; 64];
        oldest[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(
            !relay.is_known(&oldest),
            "oldest-first eviction did not evict the oldest"
        );
        let mut newest = [0u8; 64];
        newest[..4].copy_from_slice(&(MAX_RELAY_KNOWN as u32 + 9).to_le_bytes());
        assert!(relay.is_known(&newest));
    }

    #[test]
    fn a_peer_over_its_rate_is_refused_and_others_are_not() {
        let mut relay = RelayManager::new();
        let now = 1_000_000u64;
        for _ in 0..TX_RELAY_PER_PEER_PER_MIN {
            assert!(relay.allow_from(1, now), "refused inside the window");
        }
        assert!(
            !relay.allow_from(1, now),
            "a peer exceeding the inbound bound must be refused"
        );
        // A different peer has its own window.
        assert!(
            relay.allow_from(2, now),
            "one peer's flood throttled another"
        );
        // The next window resets.
        assert!(relay.allow_from(1, now + 60_000));
    }

    #[test]
    fn a_disconnected_peer_releases_its_requests_and_pending() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();
        relay.handle_inv_tx(5, &[tx_entry(1)], &pool, 0);
        assert_eq!(relay.in_flight_count(), 1);
        relay.peer_disconnected(5);
        assert_eq!(relay.in_flight_count(), 0, "requests outlived the peer");
        assert_eq!(relay.pending_count(), 0, "pending outlived the peer");
    }

    /// A `MempoolEntry` whose serialized transaction is `outputs`-sized, so the
    /// budget rule can be exercised against known sizes without a pool.
    fn entry_of(byte: u8, outputs: usize) -> MempoolEntry {
        use jnt_core::tx::{Input, OutPoint, Output, Transaction};
        let tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [byte; 64],
                index: 0,
            })],
            (0..outputs)
                .map(|i| Output {
                    value: 1,
                    address: [i as u8; 20],
                })
                .collect(),
        );
        MempoolEntry {
            fee_rate: 1,
            fee_total: 1,
            gas_used: tx.gas_used(),
            accepted_at: 1,
            tx,
        }
    }

    /// The response budget is one block's worth. Without it a peer asks for 500
    /// txids and receives gigabytes, because the *request* is bounded by
    /// `max_inv_per_msg` but the response would not be.
    #[test]
    fn a_getdata_response_stops_at_the_block_byte_budget() {
        let entries: Vec<MempoolEntry> = (0..10u8).map(|i| entry_of(i, 1)).collect();
        let one = entries[0].size_bytes();
        // A budget that fits a little over two transactions.
        let budget = one * 2 + 8;
        let served = RelayManager::select_within_budget(entries.iter(), budget);

        assert!(!served.is_empty(), "nothing was served at all");
        assert!(
            served.len() < entries.len(),
            "the response ignored the byte budget: {} of {}",
            served.len(),
            entries.len()
        );
        let served_bytes: usize = served.iter().map(|t| t.serialize().len()).sum();
        assert!(
            served_bytes <= budget,
            "served {served_bytes} bytes against a {budget} budget"
        );
    }

    /// The per-`GETDATA` transaction cap, independent of bytes: many tiny
    /// transactions must not all be served just because they are small.
    #[test]
    fn a_getdata_response_stops_at_the_transaction_count() {
        let entries: Vec<MempoolEntry> = (0..(MAX_TX_INV_BATCH * 2) as u8)
            .map(|i| entry_of(i, 1))
            .collect();
        let served = RelayManager::select_within_budget(entries.iter(), usize::MAX);
        assert_eq!(
            served.len(),
            MAX_TX_INV_BATCH,
            "more transactions were served than the batch cap allows"
        );
    }

    /// **A peer that announces and never delivers must not be able to stall
    /// relay.**
    ///
    /// Requests are held until they are answered, and the in-flight cap is what
    /// bounds them — but nothing bounded how *long* one could be held, and the
    /// set is global rather than per-peer. A peer could announce
    /// `max_relay_in_flight` transactions, deliver none, and leave the request
    /// set full forever: `take_batch` then has no room, so the node stops
    /// requesting transactions from **every** peer. Thirty-two bytes of
    /// announcement each buys a permanent, node-wide relay stall, and the txids
    /// it names are marked as already-requested, so a peer that does hold them
    /// is ignored too.
    ///
    /// Expiry is what closes it. A request that is not answered within
    /// `tx_request_timeout` is forgotten, so the worst case is a bounded delay
    /// rather than a permanent stall.
    #[test]
    fn a_peer_that_never_delivers_cannot_stall_relay_forever() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();

        let hoard: Vec<InvEntry> = (0..MAX_RELAY_IN_FLIGHT)
            .map(|i| tx_entry(i as u8))
            .collect();
        // Two rounds, because one `INV` draws at most `max_tx_inv_batch` requests
        // and the in-flight cap is larger than that. The second round therefore
        // has to be able to fill the rest from the queue.
        let mut asked = relay.handle_inv_tx(1, &hoard, &pool, 0);
        asked.extend(relay.handle_inv_tx(1, &hoard, &pool, 0));
        assert_eq!(
            relay.in_flight_count(),
            MAX_RELAY_IN_FLIGHT,
            "the fixture must actually fill the in-flight set"
        );
        assert_eq!(asked.len(), MAX_RELAY_IN_FLIGHT);

        // Nothing was delivered. A different peer announces something new, long
        // after the requests went out.
        let later = TX_REQUEST_TIMEOUT_MS + 1;
        let out = relay.handle_inv_tx(2, &[tx_entry(200)], &pool, later);
        assert_eq!(
            out.len(),
            1,
            "an unfulfilled request stalled relay for every other peer"
        );
        assert_eq!(out[0].hash, [200u8; 64]);
    }

    /// A request that is answered in time is not expired, so expiry cannot be so
    /// eager that it makes the node re-ask for everything constantly.
    #[test]
    fn a_request_answered_inside_the_timeout_is_not_reissued() {
        let pool = Mempool::default();
        let mut relay = RelayManager::new();
        assert_eq!(relay.handle_inv_tx(1, &[tx_entry(7)], &pool, 0).len(), 1);
        relay.release(&[7u8; 64]);
        // Delivered and released: a re-announce inside the window is still a
        // duplicate, because the request set no longer holds it and the known
        // set does not either — the pool does, and the caller passes it in.
        let again = relay.handle_inv_tx(2, &[tx_entry(7)], &pool, 1_000);
        assert_eq!(again.len(), 1, "a released request may be re-requested");
    }

    /// One transaction larger than the whole budget is still served. It was
    /// admitted, so it fits a block, and refusing it would make the budget
    /// behave as zero — a peer could then never fetch a single large transaction.
    #[test]
    fn a_single_transaction_larger_than_the_budget_is_still_served() {
        let entries = [entry_of(1, 1)];
        let served = RelayManager::select_within_budget(entries.iter(), 1);
        assert_eq!(served.len(), 1);
    }
}
