//! Top-level P2P networking service. SPEC.md §13.1, §13.6, §13.8.
//!
//! Owns connection listening, peer management, and dispatches network events
//! to the chain thread.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jnt_core::chain::Chain;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;

use crate::error::{NetError, NetResult};
use crate::msg::{InvEntry, Message, INV_TYPE_BLOCK};
use crate::peer::{
    perform_handshake, spawn_peer, HandshakeConfig, PeerEvent, PeerHandle, BAN_SCORE_THRESHOLD,
};
use crate::syncer::{create_locator, find_fork_and_collect_inv, SyncManager, SyncResult};

/// Score added to an address each time it exceeds an inbound bound.
/// SPEC.md §13.8: exceeding an inbound bound bans rather than merely
/// disconnecting. Five strikes reaches `ban_score_threshold`.
pub const INBOUND_VIOLATION_SCORE: u32 = 20;

/// Maximum addresses tracked for inbound-bound scoring. Keeps the ban table
/// bounded against a flood of distinct source addresses (§13.11 invariant 6).
const MAX_BAN_TRACKED: usize = 1024;

/// Per-address score with the wall-clock hour it was last updated, so the
/// 1-per-hour decay of §13.9 can be applied without a background timer.
#[derive(Debug, Clone, Copy)]
struct BanState {
    score: u32,
    updated_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Apply §13.9's 1-per-hour decay and report whether the address is banned.
fn is_banned(bans: &Arc<Mutex<HashMap<IpAddr, BanState>>>, ip: IpAddr) -> bool {
    let mut map = bans.lock().unwrap();
    let now = now_ms();
    let Some(state) = map.get_mut(&ip) else {
        return false;
    };
    let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
    if hours > 0 {
        state.score = state.score.saturating_sub(hours as u32);
        state.updated_ms = now;
    }
    state.score >= BAN_SCORE_THRESHOLD
}

/// Record an inbound-bound violation and prune the table if it grew too large.
fn score_violation(bans: &Arc<Mutex<HashMap<IpAddr, BanState>>>, ip: IpAddr) {
    let mut map = bans.lock().unwrap();
    let now = now_ms();
    let state = map.entry(ip).or_insert(BanState {
        score: 0,
        updated_ms: now,
    });
    let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
    if hours > 0 {
        state.score = state.score.saturating_sub(hours as u32);
        state.updated_ms = now;
    }
    state.score = state.score.saturating_add(INBOUND_VIOLATION_SCORE);
    if map.len() > MAX_BAN_TRACKED {
        let threshold = BAN_SCORE_THRESHOLD;
        map.retain(|_, s| s.score >= threshold);
    }
}

/// Maximum total connected peers. SPEC.md §13.8.
pub const MAX_PEERS: usize = 125;

/// Maximum inbound connections accepted. SPEC.md §13.8.
pub const MAX_INBOUND: usize = 32;

/// Configuration for the P2P network node.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub params: NetworkParams,
    pub listen_addr: Option<SocketAddr>,
    pub max_peers: usize,
    pub max_inbound: usize,
    pub user_agent: String,
}

impl P2pConfig {
    pub fn new(params: NetworkParams, listen_addr: Option<SocketAddr>) -> Self {
        Self {
            params,
            listen_addr,
            max_peers: MAX_PEERS,
            max_inbound: MAX_INBOUND,
            user_agent: "jounit/0.2.0".to_string(),
        }
    }
}

/// The P2P network controller.
pub struct P2pNode {
    config: P2pConfig,
    peers: Arc<Mutex<HashMap<usize, PeerHandle>>>,
    inbound_count: Arc<AtomicUsize>,
    next_peer_id: AtomicUsize,
    event_tx: Sender<PeerEvent>,
    event_rx: Receiver<PeerEvent>,
    running: Arc<AtomicBool>,
    /// Ban scores by address, for inbound-bound violations (SPEC.md §13.8/§13.9).
    /// v0.2 has no address book (§13.6), so this map is the only place an
    /// address can be remembered, and it is deliberately the only one.
    ban_scores: Arc<Mutex<HashMap<IpAddr, BanState>>>,
    listener_thread: Option<JoinHandle<()>>,
}

impl P2pNode {
    /// Bind the listener (if configured) and start the P2P networking layer.
    pub fn start(config: P2pConfig, initial_height: u64, initial_tip: Hash) -> NetResult<Self> {
        let (event_tx, event_rx) = channel();
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let inbound_count = Arc::new(AtomicUsize::new(0));
        let ban_scores = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));

        let listener_thread = if let Some(addr) = config.listen_addr {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;

            let l_peers = Arc::clone(&peers);
            let l_inbound = Arc::clone(&inbound_count);
            let l_running = Arc::clone(&running);
            let l_event_tx = event_tx.clone();
            let l_bans = Arc::clone(&ban_scores);
            let l_config = config.clone();

            Some(thread::spawn(move || {
                let mut peer_id_counter = 100_000usize; // Separate space for inbound IDs

                while l_running.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer_addr)) => {
                            // The listener is non-blocking so `accept` can poll.
                            // On Windows an accepted socket *inherits*
                            // WSA_FLAG_NON_BLOCKED, which makes the blocking,
                            // timeout-based handshake underneath fail
                            // immediately with `WouldBlock` — every inbound
                            // connection was refused on that platform. Clear
                            // the flag explicitly rather than relying on the
                            // platform default.
                            if let Err(_e) = stream.set_nonblocking(false) {
                                drop(stream);
                                continue;
                            }
                            // Inbound bounds first, and they *ban* rather than
                            // merely close (§13.8). `max_peers` is checked as
                            // well as `max_inbound`: it caps the total thread and
                            // descriptor count, which `max_inbound` alone does
                            // not once a node makes its own outbound connections.
                            if is_banned(&l_bans, peer_addr.ip()) {
                                drop(stream);
                                continue;
                            }
                            if l_inbound.load(Ordering::Relaxed) >= l_config.max_inbound
                                || l_peers.lock().unwrap().len() >= l_config.max_peers
                            {
                                score_violation(&l_bans, peer_addr.ip());
                                drop(stream);
                                continue;
                            }

                            let hs_config = HandshakeConfig::new(
                                l_config.params.clone(),
                                initial_height,
                                initial_tip,
                            );

                            peer_id_counter += 1;
                            let pid = peer_id_counter;
                            let p_peers = Arc::clone(&l_peers);
                            let p_inbound = Arc::clone(&l_inbound);
                            let p_event_tx = l_event_tx.clone();
                            let p_params = l_config.params.clone();

                            thread::spawn(move || {
                                match perform_handshake(&mut stream, &hs_config, false) {
                                    Ok(ver) => {
                                        // Only count the connection as inbound
                                        // once the peer thread exists. Counting
                                        // before `spawn_peer` leaked a slot
                                        // whenever spawning failed, and inbound
                                        // slots are the scarce resource (§13.8).
                                        if let Ok(handle) = spawn_peer(
                                            pid, stream, ver, false, p_params, p_event_tx,
                                        ) {
                                            p_inbound.fetch_add(1, Ordering::Relaxed);
                                            p_peers.lock().unwrap().insert(pid, handle);
                                        }
                                    }
                                    Err(_) => {
                                        // Handshake failed or rejected
                                        drop(stream);
                                    }
                                }
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }))
        } else {
            None
        };

        Ok(Self {
            config,
            peers,
            inbound_count,
            next_peer_id: AtomicUsize::new(1),
            event_tx,
            event_rx,
            running,
            ban_scores,
            listener_thread,
        })
    }

    /// Connect to a remote peer address as an initiator.
    pub fn connect(&self, addr: SocketAddr, chain: &Chain) -> NetResult<usize> {
        // SPEC.md §13.8 bounds `max_peers` as the cap on thread and descriptor
        // count. It was never enforced here, so a node could open as many
        // outbound connections as it had addresses and blow past the bound the
        // rest of the design assumes.
        if self.peer_count() >= self.config.max_peers {
            return Err(NetError::Resource(format!(
                "peer limit reached ({} configured, {} connected)",
                self.config.max_peers,
                self.peer_count()
            )));
        }
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        let hs_config =
            HandshakeConfig::new(self.config.params.clone(), chain.height(), chain.tip_hash());

        let ver = perform_handshake(&mut stream, &hs_config, true)?;
        let peer_id = self.next_peer_id.fetch_add(1, Ordering::Relaxed);

        let handle = spawn_peer(
            peer_id,
            stream,
            ver,
            true,
            self.config.params.clone(),
            self.event_tx.clone(),
        )?;

        // Send initial GETBLOCKS locator to sync with the new peer
        let locator = create_locator(chain);
        let _ = handle.send(Message::GetBlocks {
            locator,
            stop: Hash::default(),
        });

        self.peers.lock().unwrap().insert(peer_id, handle);
        Ok(peer_id)
    }

    /// Broadcast an inventory announcement to all peers except `exclude_peer`.
    pub fn broadcast_inv(&self, entries: Vec<InvEntry>, exclude_peer: Option<usize>) {
        let msg = Message::Inv(entries);
        let peers = self.peers.lock().unwrap();
        for (id, peer) in peers.iter() {
            if Some(*id) != exclude_peer {
                let _ = peer.send(msg.clone());
            }
        }
    }

    /// Announce a new canonical block to all peers.
    pub fn broadcast_block(&self, block_hash: Hash, exclude_peer: Option<usize>) {
        self.broadcast_inv(
            vec![InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: block_hash,
            }],
            exclude_peer,
        );
    }

    /// Process all pending network events against the chain and sync manager.
    /// Returns the number of events processed.
    pub fn poll_events(
        &self,
        chain: &mut Chain,
        syncer: &mut SyncManager,
        now_ms: Option<u64>,
    ) -> usize {
        let mut count = 0;

        while let Ok(event) = self.event_rx.try_recv() {
            count += 1;
            match event {
                PeerEvent::Connected {
                    peer_id, version, ..
                } => {
                    // If the peer is ahead, ask for blocks
                    if version.height > chain.height() {
                        let locator = create_locator(chain);
                        if let Some(peer) = self.peers.lock().unwrap().get(&peer_id) {
                            let _ = peer.send(Message::GetBlocks {
                                locator,
                                stop: Hash::default(),
                            });
                        }
                    }
                }
                PeerEvent::Disconnected { peer_id, .. } => {
                    // Release everything queued for / owed by that peer before
                    // dropping the handle, so its hashes can be served by
                    // another connection instead of stalling sync (§13.7).
                    syncer.peer_disconnected(peer_id);
                    let mut peers = self.peers.lock().unwrap();
                    if let Some(p) = peers.remove(&peer_id) {
                        if !p.is_outbound {
                            self.inbound_count.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
                PeerEvent::Message { peer_id, msg } => {
                    self.handle_message(peer_id, msg, chain, syncer, now_ms);
                }
            }
        }

        count
    }

    fn handle_message(
        &self,
        peer_id: usize,
        msg: Message,
        chain: &mut Chain,
        syncer: &mut SyncManager,
        now_ms: Option<u64>,
    ) {
        match msg {
            Message::GetBlocks { locator, stop } => {
                let inv = find_fork_and_collect_inv(chain, &locator, &stop);
                if !inv.is_empty() {
                    let peers = self.peers.lock().unwrap();
                    if let Some(peer) = peers.get(&peer_id) {
                        let _ = peer.send(Message::Inv(inv));
                    }
                }
            }
            Message::Inv(entries) => {
                let to_request = syncer.handle_inv(peer_id, &entries, chain);
                self.send_get_data(peer_id, to_request);
            }
            Message::GetData(entries) => {
                let blocks = syncer.handle_get_data(&entries, chain);
                let peers = self.peers.lock().unwrap();
                if let Some(peer) = peers.get(&peer_id) {
                    for b in blocks {
                        let _ = peer.send(Message::Block(Box::new(b)));
                    }
                }
            }
            Message::Block(block) => {
                let block_val = *block;
                let outcome = syncer.handle_block(block_val, chain, now_ms);
                match outcome {
                    SyncResult::Accepted {
                        extended_tip,
                        new_tip,
                        orphans_resolved,
                    } => {
                        if extended_tip {
                            // Relay the new tip to all other peers
                            self.broadcast_block(new_tip, Some(peer_id));
                            for orphan_hash in orphans_resolved {
                                self.broadcast_block(orphan_hash, Some(peer_id));
                            }
                        }
                    }
                    SyncResult::Orphan { missing_parent } => {
                        // Request missing parent block from this peer
                        self.send_get_data(
                            peer_id,
                            vec![InvEntry {
                                kind: INV_TYPE_BLOCK,
                                hash: missing_parent,
                            }],
                        );
                    }
                    SyncResult::AlreadyKnown => {}
                    SyncResult::Invalid(_) => {
                        // Misbehaviour score +10 for an invalid block (§13.9)
                        let peers = self.peers.lock().unwrap();
                        if let Some(peer) = peers.get(&peer_id) {
                            peer.add_ban_score(10);
                        }
                    }
                }
                // Keep the window moving: one block applied frees one request
                // slot, so ask for the next batch. Without this the requester
                // stops after the first batch and never finishes syncing
                // (§13.7 "and repeats").
                let next = syncer.take_batch(peer_id);
                self.send_get_data(peer_id, next);
            }
            Message::Addr(_) | Message::Unknown { .. } | Message::Pong { .. } => {
                // Ignored per spec
            }
            Message::Version(_) | Message::Verack { .. } | Message::Ping { .. } => {
                // Handled in peer thread
            }
        }
    }

    /// Number of active connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Whether an address is currently banned for inbound-bound violations.
    /// Also applies the §13.9 decay, so this is the authoritative answer rather
    /// than a raw table read.
    pub fn is_banned(&self, addr: IpAddr) -> bool {
        is_banned(&self.ban_scores, addr)
    }

    /// Addresses currently at or over the ban threshold.
    pub fn banned_count(&self) -> usize {
        let mut map = self.ban_scores.lock().unwrap();
        let now = now_ms();
        let mut count = 0;
        for state in map.values_mut() {
            let hours = now.saturating_sub(state.updated_ms) / 3_600_000;
            if hours > 0 {
                state.score = state.score.saturating_sub(hours as u32);
                state.updated_ms = now;
            }
            if state.score >= BAN_SCORE_THRESHOLD {
                count += 1;
            }
        }
        count
    }

    /// Send a `GETDATA` to one peer, if it is still connected.
    fn send_get_data(&self, peer_id: usize, entries: Vec<InvEntry>) {
        if entries.is_empty() {
            return;
        }
        let peers = self.peers.lock().unwrap();
        if let Some(peer) = peers.get(&peer_id) {
            let _ = peer.send(Message::GetData(entries));
        }
    }

    /// Stop the network listener and all peer threads.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let peers = self.peers.lock().unwrap();
        for peer in peers.values() {
            peer.stop();
        }
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.listener_thread.take() {
            let _ = handle.join();
        }
    }
}
