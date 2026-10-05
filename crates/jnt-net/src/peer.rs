//! Peer connection lifecycle and handshake state machine. SPEC.md §13.4, §13.9.

use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jnt_core::block::genesis_block;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;

use crate::error::{NetError, NetResult};
use crate::frame::{read_frame, write_frame};
use crate::magic::check_network;
use crate::msg::{Message, MessageType, Version, PROTOCOL_VERSION};

/// Timeout for completing the initial handshake. SPEC.md §13.8.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Ban threshold score. Reaching or exceeding 100 disconnects and bans. §13.8.
pub const BAN_SCORE_THRESHOLD: u32 = 100;

/// Local node handshake configuration.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub params: NetworkParams,
    pub height: u64,
    pub tip_hash: Hash,
    pub user_agent: String,
    pub services: u64,
}

impl HandshakeConfig {
    pub fn new(params: NetworkParams, height: u64, tip_hash: Hash) -> Self {
        Self {
            params,
            height,
            tip_hash,
            user_agent: "jounit/0.2.0".to_string(),
            services: 1, // bit 0 = serves blocks
        }
    }
}

/// Events emitted by peer connections to the chain / network manager.
#[derive(Debug)]
pub enum PeerEvent {
    Connected {
        peer_id: usize,
        remote_addr: SocketAddr,
        version: Version,
        is_outbound: bool,
    },
    Disconnected {
        peer_id: usize,
        reason: String,
    },
    Message {
        peer_id: usize,
        msg: Message,
    },
}

/// Handle to communicate with an active peer.
#[derive(Clone)]
pub struct PeerHandle {
    pub id: usize,
    pub remote_addr: SocketAddr,
    pub version: Version,
    pub is_outbound: bool,
    tx: Sender<Message>,
    ban_score: Arc<AtomicU32>,
    stopped: Arc<AtomicBool>,
}

impl PeerHandle {
    /// Send a message to this peer.
    pub fn send(&self, msg: Message) -> NetResult<()> {
        if self.stopped.load(Ordering::Relaxed) {
            return Err(NetError::Peer("peer disconnected".into()));
        }
        self.tx
            .send(msg)
            .map_err(|_| NetError::Peer("peer channel closed".into()))
    }

    /// Current misbehaviour ban score.
    pub fn ban_score(&self) -> u32 {
        self.ban_score.load(Ordering::Relaxed)
    }

    /// Add to the peer's ban score. If threshold is reached, disconnects.
    pub fn add_ban_score(&self, score: u32) {
        let prev = self.ban_score.fetch_add(score, Ordering::SeqCst);
        if prev + score >= BAN_SCORE_THRESHOLD {
            self.stop();
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

/// Perform the SPEC.md §13.4 handshake on a raw stream.
///
/// Both directions exchange `VERSION` and `VERACK`.
pub fn perform_handshake(
    stream: &mut TcpStream,
    config: &HandshakeConfig,
    is_initiator: bool,
) -> NetResult<Version> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let genesis = genesis_block(config.params.genesis_difficulty);
    let genesis_hash = genesis.block_hash();

    // Unique nonce for handshake challenge
    let local_nonce = generate_nonce();

    let local_version = Version {
        network_magic: config.params.network_magic,
        network_id: config.params.network_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        services: config.services,
        height: config.height,
        tip_hash: config.tip_hash,
        user_agent: config.user_agent.clone(),
        nonce: local_nonce,
    };

    let peer_version = if is_initiator {
        // Initiator sends VERSION first
        let ver_payload = Message::Version(local_version).encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Version as u8,
            &ver_payload,
        )?;

        // Wait for peer's VERSION
        let (ty, payload) = read_frame(stream, &config.params)?;
        if ty != MessageType::Version as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERSION (1), got {ty}"
            )));
        }
        let ver = match Message::decode(ty, &payload)? {
            Message::Version(v) => v,
            _ => unreachable!(),
        };

        validate_peer_version(&ver, &config.params, &genesis_hash)?;

        // Send VERACK with peer's nonce
        let verack_payload = Message::Verack { nonce: ver.nonce }.encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Verack as u8,
            &verack_payload,
        )?;

        // Wait for peer's VERACK
        let (ack_ty, ack_payload) = read_frame(stream, &config.params)?;
        if ack_ty != MessageType::Verack as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERACK (2), got {ack_ty}"
            )));
        }
        match Message::decode(ack_ty, &ack_payload)? {
            Message::Verack { nonce } => {
                if nonce != local_nonce {
                    return Err(NetError::Protocol(format!(
                        "VERACK nonce mismatch: got {nonce}, expected {local_nonce}"
                    )));
                }
            }
            _ => unreachable!(),
        }

        ver
    } else {
        // Responder: First frame MUST be VERSION
        let (ty, payload) = read_frame(stream, &config.params)?;
        if ty != MessageType::Version as u8 {
            return Err(NetError::Protocol(format!(
                "first frame must be VERSION (1), got {ty}"
            )));
        }
        let ver = match Message::decode(ty, &payload)? {
            Message::Version(v) => v,
            _ => unreachable!(),
        };

        validate_peer_version(&ver, &config.params, &genesis_hash)?;

        // Send our VERSION
        let ver_payload = Message::Version(local_version).encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Version as u8,
            &ver_payload,
        )?;

        // Send VERACK acknowledging peer's nonce
        let verack_payload = Message::Verack { nonce: ver.nonce }.encode();
        write_frame(
            stream,
            &config.params,
            MessageType::Verack as u8,
            &verack_payload,
        )?;

        // Wait for initiator's VERACK acknowledging our nonce
        let (ack_ty, ack_payload) = read_frame(stream, &config.params)?;
        if ack_ty != MessageType::Verack as u8 {
            return Err(NetError::Protocol(format!(
                "expected VERACK (2), got {ack_ty}"
            )));
        }
        match Message::decode(ack_ty, &ack_payload)? {
            Message::Verack { nonce } => {
                if nonce != local_nonce {
                    return Err(NetError::Protocol(format!(
                        "VERACK nonce mismatch: got {nonce}, expected {local_nonce}"
                    )));
                }
            }
            _ => unreachable!(),
        }

        ver
    };

    // Reset timeouts for normal steady-state operation (e.g. 60s for keepalive)
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    Ok(peer_version)
}

fn validate_peer_version(
    ver: &Version,
    params: &NetworkParams,
    genesis_hash: &Hash,
) -> NetResult<()> {
    check_network(params, ver.network_magic, &ver.network_id)?;
    if ver.protocol_version > PROTOCOL_VERSION {
        return Err(NetError::Protocol(format!(
            "unsupported protocol version: {} > {}",
            ver.protocol_version, PROTOCOL_VERSION
        )));
    }
    if ver.height == 0 && ver.tip_hash != *genesis_hash {
        return Err(NetError::Protocol(
            "peer claiming height 0 has non-genesis tip hash".into(),
        ));
    }
    Ok(())
}

fn generate_nonce() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (now as u64) ^ 0x5a5a_a5a5_3c3c_c3c3
}

/// Spawn peer read and write loops on an established TCP stream.
pub fn spawn_peer(
    peer_id: usize,
    mut stream: TcpStream,
    version: Version,
    is_outbound: bool,
    params: NetworkParams,
    event_tx: Sender<PeerEvent>,
) -> NetResult<PeerHandle> {
    let remote_addr = stream.peer_addr()?;
    let (outbound_tx, outbound_rx): (Sender<Message>, Receiver<Message>) = channel();
    let ban_score = Arc::new(AtomicU32::new(0));
    let stopped = Arc::new(AtomicBool::new(false));

    let handle = PeerHandle {
        id: peer_id,
        remote_addr,
        version: version.clone(),
        is_outbound,
        tx: outbound_tx.clone(),
        ban_score: Arc::clone(&ban_score),
        stopped: Arc::clone(&stopped),
    };

    // Notify connected
    let _ = event_tx.send(PeerEvent::Connected {
        peer_id,
        remote_addr,
        version,
        is_outbound,
    });

    let mut write_stream = stream.try_clone()?;
    let write_params = params.clone();
    let write_stopped = Arc::clone(&stopped);

    // Writer thread
    thread::spawn(move || {
        while let Ok(msg) = outbound_rx.recv() {
            if write_stopped.load(Ordering::Relaxed) {
                break;
            }
            let ty = match &msg {
                Message::Version(_) => MessageType::Version as u8,
                Message::Verack { .. } => MessageType::Verack as u8,
                Message::Ping { .. } => MessageType::Ping as u8,
                Message::Pong { .. } => MessageType::Pong as u8,
                Message::Inv(_) => MessageType::Inv as u8,
                Message::GetData(_) => MessageType::GetData as u8,
                Message::Block(_) => MessageType::Block as u8,
                Message::GetBlocks { .. } => MessageType::GetBlocks as u8,
                Message::Addr(_) => MessageType::Addr as u8,
                Message::Unknown { ty, .. } => *ty,
            };
            let payload = msg.encode();
            if write_frame(&mut write_stream, &write_params, ty, &payload).is_err() {
                break;
            }
        }
        write_stopped.store(true, Ordering::Relaxed);
    });

    // Reader thread
    let read_stopped = Arc::clone(&stopped);
    let read_ban = Arc::clone(&ban_score);
    let read_event_tx = event_tx;
    let auto_pong_tx = outbound_tx;

    thread::spawn(move || {
        let mut exit_reason = "connection closed".to_string();

        while !read_stopped.load(Ordering::Relaxed) {
            match read_frame(&mut stream, &params) {
                Ok((ty, payload)) => {
                    match Message::decode(ty, &payload) {
                        Ok(msg) => match msg {
                            Message::Ping { nonce } => {
                                // Auto respond with PONG
                                let _ = auto_pong_tx.send(Message::Pong { nonce });
                            }
                            Message::Pong { .. } => {
                                // Keepalive response acknowledged
                            }
                            other => {
                                if read_event_tx
                                    .send(PeerEvent::Message {
                                        peer_id,
                                        msg: other,
                                    })
                                    .is_err()
                                {
                                    exit_reason = "event receiver dropped".into();
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            let curr = read_ban.fetch_add(20, Ordering::SeqCst);
                            if curr + 20 >= BAN_SCORE_THRESHOLD {
                                exit_reason = format!("banned: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(NetError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    // Read timeout — idle connection keepalive check
                    continue;
                }
                Err(e) => {
                    exit_reason = e.to_string();
                    break;
                }
            }
        }

        read_stopped.store(true, Ordering::Relaxed);
        let _ = read_event_tx.send(PeerEvent::Disconnected {
            peer_id,
            reason: exit_reason,
        });
    });

    Ok(handle)
}
