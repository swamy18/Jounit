//! x402 facilitator + paid-endpoint integration tests.
//!
//! Drives the real server: `GET /v1/paid/weather` without payment answers 402,
//! `POST /v1/x402/verify` checks a payment, `POST /v1/x402/settle` records it,
//! and a retry with `PAYMENT-SIGNATURE` returns 200 + `PAYMENT-RESPONSE`.
//!
//! Run with `cargo test -p srct-node --test x402`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{derive_agent_id, AgentRole, PolicyBook, SpendPolicy, POLICY_VERSION};
use srct_core::chain::Chain;
use srct_core::hash::{address_to_hex, hash_to_hex};
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::payment::build_signed_payment;
use srct_core::service::{authorize_request, build_signed_request, derive_service_id, RequestSpec};
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";
const EXPIRES: u64 = 9_000;
const DEMO_AMOUNT: u64 = 500;
const DEMO_RECIPIENT: [u8; 20] = [0x42; 20];

struct Node {
    addr: SocketAddr,
    #[allow(dead_code)]
    shared: Arc<Mutex<SharedNode>>,
}

fn start() -> Node {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn_with_options(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
        Vec::new(),
    )
    .expect("bind loopback");
    Node { addr, shared }
}

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

fn exchange_raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn body_of(raw: &str) -> String {
    raw.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

fn status_of(raw: &str) -> u16 {
    raw.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[test]
fn paid_weather_challenge_verify_settle_and_retry() {
    let node = start();

    // 1. No payment -> 402 + PAYMENT-REQUIRED.
    let req = format!(
        "GET /v1/paid/weather HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        node.addr
    );
    let raw = exchange_raw(node.addr, req.as_bytes());
    assert_eq!(status_of(&raw), 402, "expected 402, got: {raw}");
    assert!(
        raw.to_ascii_lowercase().contains("payment-required"),
        "missing challenge header: {raw}"
    );
    let body: Value = serde_json::from_str(&body_of(&raw)).unwrap();
    assert_eq!(body["accepts"][0]["scheme"], "exact");
    assert_eq!(body["accepts"][0]["amount"], DEMO_AMOUNT.to_string());
    assert!(body["accepts"][0]["network"]
        .as_str()
        .unwrap()
        .starts_with("srct:"));

    // 2. Agent builds a bounded policy + payment for the demo offer.
    let payer = wallet(11, "x402-payer");
    let payer_addr = payer.address().unwrap();
    let service = derive_service_id(NET, &DEMO_RECIPIENT, b"x402-weather-v1");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer_addr),
        owner: payer_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![DEMO_RECIPIENT],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    // Fund the payer's node-local credit line so admission can reserve.
    node.shared
        .lock()
        .unwrap()
        .credit
        .deposit(payer_addr, 10_000)
        .unwrap();
    // Register the policy by issuing one authorization on the node.
    let mut book = PolicyBook::default();
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: DEMO_RECIPIENT,
            max_amount_sat: DEMO_AMOUNT,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    // Authorize on the node (registers policy in both the local book and the node).
    let auth = {
        let mut node_book = node.shared.lock().unwrap();
        // Seed node-local policy book + registry the same way /v1/authorize does.
        let auth =
            authorize_request(&mut node_book.policies, &policy, NET, &request, 0, 1).unwrap();
        node_book
            .policy_registry
            .insert(policy.hash(), policy.clone());
        // Mirror the grant in the local book for the settle path.
        let _ = authorize_request(&mut book, &policy, NET, &request, 0, 1).unwrap();
        auth
    };
    let sigs = Auth::sigs_for(&payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&payer).unwrap();
    let payment = build_signed_payment(
        &payer,
        &auth,
        NET,
        AgentRole::Machine,
        0,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();
    let payment_hex = hex::encode(payment.serialize());
    let auth_hex = hex::encode(auth.serialize());
    let sigs_hex = hex::encode(sigs.to_bytes());
    let keys_hex = hex::encode(keys.to_bytes());

    // 3. Facilitator verify (offline checks, no state change).
    let verify_body = json!({
        "payment_hex": payment_hex,
        "authorization_hex": auth_hex,
        "auth_sigs_hex": sigs_hex,
        "auth_keys_hex": keys_hex,
    })
    .to_string();
    let req = format!(
        "POST /v1/x402/verify HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        node.addr,
        verify_body.len(),
        verify_body
    );
    let raw = exchange_raw(node.addr, req.as_bytes());
    assert_eq!(status_of(&raw), 200, "verify failed: {raw}");
    let body: Value = serde_json::from_str(&body_of(&raw)).unwrap();
    assert_eq!(body["valid"], true);

    // 4. Facilitator settle (records the payment).
    let req = format!(
        "POST /v1/x402/settle HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        node.addr,
        verify_body.len(),
        verify_body
    );
    let raw = exchange_raw(node.addr, req.as_bytes());
    assert_eq!(status_of(&raw), 200, "settle failed: {raw}");
    let body: Value = serde_json::from_str(&body_of(&raw)).unwrap();
    assert_eq!(body["success"], true);
    let payment_id = body["payment_id"].as_str().unwrap().to_string();
    assert!(!payment_id.is_empty());

    // 5. Retry the paid endpoint with PAYMENT-SIGNATURE (idempotent: already settled).
    let sig_envelope = json!({
        "x402Version": 2,
        "scheme": "exact",
        "network": "srct:mini",
        "payload": {
            "payment_hex": payment_hex,
            "authorization_hex": auth_hex,
            "auth_sigs_hex": sigs_hex,
            "auth_keys_hex": keys_hex,
        }
    })
    .to_string();
    // Minimal base64 (header value): reuse the node's own encoder shape via python-free encode.
    let sig_b64 = base64_encode(sig_envelope.as_bytes());
    let req = format!(
        "GET /v1/paid/weather HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nPAYMENT-SIGNATURE: {}\r\n\r\n",
        node.addr, sig_b64
    );
    let raw = exchange_raw(node.addr, req.as_bytes());
    assert_eq!(status_of(&raw), 200, "paid retry failed: {raw}");
    assert!(
        raw.to_ascii_lowercase().contains("payment-response"),
        "missing response header: {raw}"
    );
    let body: Value = serde_json::from_str(&body_of(&raw)).unwrap();
    assert_eq!(body["report"]["weather"], "sunny");
    assert_eq!(body["payment_id"], payment_id);
    let _ = address_to_hex;
    let _ = hash_to_hex;
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let t = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((t >> 18) & 63) as usize] as char);
        out.push(T[((t >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((t >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(t & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
