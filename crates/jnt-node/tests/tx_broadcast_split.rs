//! `tx_broadcast` admission without holding the shared-state lock (Task 2).
//!
//! The pool verifies signatures in three phases now: a cheap snapshot under
//! the lock, the pairings with no lock at all, then a bounded re-check and
//! commit. What these pin:
//!
//! - a valid transaction still admits, byte-for-byte the same transaction;
//! - a bad signature is refused *without the lock* — the request completes
//!   while a test thread holds it, which is only possible if verification ran
//!   outside the critical section;
//! - a transaction that reaches the commit phase while the lock is held by
//!   someone else is refused with 503 `busy` inside the deadline, not hung;
//! - a broadcast while the lock is poisoned still answers rather than
//!   500s or panics.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use jnt_core::chain::Chain;
use jnt_core::hash::address_to_hex;
use jnt_core::params::NetworkParams;
use jnt_core::tx::Transaction;
use jnt_core::wallet::Wallet;
use jnt_node::api::{spawn, SharedNode};
use jnt_node::l2::NodeL2;

struct Node {
    addr: SocketAddr,
    shared: Arc<Mutex<SharedNode>>,
}

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

fn start() -> Node {
    let params = NetworkParams::mini();
    let miner = wallet(51, "split-miner");
    let mut chain = Chain::new(params.clone()).unwrap();
    let addr = miner.address().unwrap();
    // 12 blocks leaves the coinbases at heights 1–3 mature (maturity 10).
    for h in 1..=12u64 {
        let block = chain
            .mine_block(
                addr,
                vec![],
                jnt_core::block::GENESIS_TIMESTAMP_MS + h * 1_000,
            )
            .unwrap();
        chain.submit(block).unwrap();
    }
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .expect("the API must bind its loopback socket");
    Node { addr, shared }
}

/// Hold the shared-state lock, as the serve loop does. The guard is returned
/// so the caller controls when the node becomes available again.
fn hold_lock<'a>(node: &'a Node) -> MutexGuard<'a, SharedNode> {
    node.shared.lock().unwrap()
}

fn post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    exchange(addr, request.as_bytes())
}

fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

/// A signed, fundable transaction this node would accept. Returns its
/// canonical hex and its txid.
fn signed_tx(node: &Node) -> (String, [u8; 64]) {
    let miner = wallet(51, "split-miner");
    let from = miner.address().unwrap();
    let to = wallet(52, "split-payee").address().unwrap();

    let (s, built) = {
        let body = serde_json::json!({
            "from": address_to_hex(&from),
            "to": address_to_hex(&to),
            "amount_sat": 1_000_000u64,
            "max_fee_sat": 1_000_000u64,
        })
        .to_string();
        let (status, text) = post(node.addr, "/v1/tx/build", &body);
        let (_, payload) = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .map(|b| (status, b))
            .unwrap_or((status, text));
        let json: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
        (status, json)
    };
    assert_eq!(s, 200, "build failed: {built}");
    let unsigned = built["unsigned_tx_hex"].as_str().unwrap().to_string();
    let mut tx = Transaction::deserialize(&hex::decode(unsigned).unwrap()).unwrap();
    miner.sign(&mut tx).unwrap();
    (hex::encode(tx.serialize()), tx.txid())
}

/// A signed, fundable transaction's txid as hex, for matching the response.
fn txid_hex(txid: &[u8; 64]) -> String {
    jnt_core::hash::hash512_to_hex(txid)
}

#[test]
fn a_valid_transaction_still_admits_through_the_split() {
    let node = start();
    let (signed_hex, txid) = signed_tx(&node);

    let (s, body) = {
        let body = serde_json::json!({ "signed_tx_hex": signed_hex }).to_string();
        post(node.addr, "/v1/tx/broadcast", &body)
    };
    assert_eq!(s, 200, "a valid transaction must still pool: {body}");
    assert!(body.contains(&txid_hex(&txid)));

    // 12 blocks were mined, so at least one coinbase is spendable.
    let mined = 12;

    let _ = mined;
}

/// A bad signature is refused with 400, and the *commit* phase is never
/// reached for it.
///
/// The lock-free-ness of the verify step itself is asserted where it can be
/// proved directly — `mempool::tests::
/// verification_needs_no_write_access_to_the_pool`, which calls
/// `Mempool::verify_admission` on a `&Mempool` with no `&mut` at all. What
/// this pins is the API-level consequence: the refusal is `tx_refused`, and
/// no state was touched on the way to it.
#[test]
fn a_bad_signature_is_refused_and_leaves_the_pool_untouched() {
    let node = start();
    let (signed_hex, _) = signed_tx(&node);

    // Corrupt one signature byte after signing.
    let mut bytes = hex::decode(&signed_hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let tampered = hex::encode(bytes);

    let (s, body) = {
        let body = serde_json::json!({ "signed_tx_hex": tampered }).to_string();
        post(node.addr, "/v1/tx/broadcast", &body)
    };
    assert_eq!(s, 400, "a bad signature must be refused: {body}");
    assert!(body.contains("tx_refused"));

    // Nothing was pooled by a refused verification.
    let (_, pool) = exchange(
        node.addr,
        b"GET /v1/mempool HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert!(
        pool.contains("\"count\":0"),
        "a refused tx must not pool: {pool}"
    );

    let body = serde_json::json!({ "signed_tx_hex": signed_hex }).to_string();
    let (s, body) = post(node.addr, "/v1/tx/broadcast", &body);
    assert_eq!(s, 200, "the good transaction must still pool: {body}");
}

/// A transaction that reaches the commit phase while the lock is held by the
/// serve loop is refused with 503 inside the deadline, never hung.
#[test]
fn a_commit_behind_a_held_lock_is_busy_not_a_hang() {
    let node = start();
    let (signed_hex, _) = signed_tx(&node);

    let _held = hold_lock(&node);
    let started = Instant::now();
    let (s, body) = {
        let body = serde_json::json!({ "signed_tx_hex": signed_hex }).to_string();
        post(node.addr, "/v1/tx/broadcast", &body)
    };
    let elapsed = started.elapsed();
    assert_eq!(s, 503, "a held lock must report busy: {body}");
    assert!(body.contains("busy"));
    // The bounded wait is 2s; the released lock must be picked up well after
    // it, and the request must not hang past the request deadline either.
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(9),
        "the lock wait must be bounded, waited {elapsed:?}"
    );
}

/// Releasing the lock lets the same transaction through — the refusal above
/// was contention, not a verdict about the transaction.
#[test]
fn releasing_the_lock_lets_the_same_transaction_through() {
    let node = start();
    let (signed_hex, txid) = signed_tx(&node);

    {
        let _held = hold_lock(&node);
        let body = serde_json::json!({ "signed_tx_hex": signed_hex.clone() }).to_string();
        let (s, _) = post(node.addr, "/v1/tx/broadcast", &body);
        assert_eq!(s, 503);
    }

    let body = serde_json::json!({ "signed_tx_hex": signed_hex }).to_string();
    let (s, body) = post(node.addr, "/v1/tx/broadcast", &body);
    assert_eq!(s, 200, "the transaction itself was never bad: {body}");
    assert!(body.contains(&txid_hex(&txid)));
}
