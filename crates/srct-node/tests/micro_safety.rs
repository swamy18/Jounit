//! Micro-payments + wallet-safety integration tests.
//!
//! Drives the real server over raw HTTP:
//! - `POST /v1/payments/aggregate` quotes one shared settlement for N payments
//!   (savings vs N separate transactions).
//! - `POST /v1/streams/open|settle` + `GET /v1/streams/{id}` run a
//!   pay-as-you-use channel: one open, off-chain vouchers, exact settlement.
//! - `GET /v1/payments/unsettled`, `/v1/receipts/orphans`, `/v1/audit` and
//!   `/v1/risk/policy` give the reconciliation + audit trail that makes
//!   retries safe (no double-pay on timeout) and approvals visible.
//!
//! Run with `cargo test -p srct-node --test micro_safety`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{
    derive_agent_id, AgentRole, Authorization, PolicyBook, SpendPolicy, POLICY_VERSION,
};
use srct_core::chain::Chain;
use srct_core::hash::{address_to_hex, hash_to_hex};
use srct_core::l2::Auth;
use srct_core::params::NetworkParams;
use srct_core::payment::{build_signed_payment, MachinePayment};
use srct_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use srct_core::service::{
    authorize_request, build_signed_request, derive_service_id, result_hash_of, RequestSpec,
};
use srct_core::sig::Bundle;
use srct_core::stream::{build_settlement, build_stream, StreamOpenSpec, StreamSettleSpec};
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const NET: &str = "srct/mini";
const EXPIRES: u64 = 9_000;

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

fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}")),
    )
}

fn post(node: &Node, path: &str, body: &Value) -> (u16, Value) {
    let raw = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        node.addr, raw.len(), raw
    );
    exchange(node.addr, req.as_bytes())
}

fn get(node: &Node, path: &str) -> (u16, Value) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        node.addr
    );
    exchange(node.addr, req.as_bytes())
}

fn policy_sigs_hex(owner: &Wallet, policy: &SpendPolicy) -> String {
    hex::encode(
        Auth::sigs_for(owner, &policy.signing_hash())
            .unwrap()
            .to_bytes(),
    )
}

fn policy_keys_hex(owner: &Wallet) -> String {
    hex::encode(Auth::keys_for(owner).unwrap().to_bytes())
}

/// Authorize one payment amount under a fresh request nonce, then build and
/// submit the payment. Returns the payment id hex.
fn authorize_and_submit(
    node: &Node,
    payer: &Wallet,
    policy: &SpendPolicy,
    provider_addr: &[u8; 20],
    service: [u8; 32],
    amount: u64,
    nonce: u64,
) -> (String, MachinePayment, Authorization, Bundle, Bundle) {
    let request = build_signed_request(
        payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: *provider_addr,
            max_amount_sat: amount,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    let (s, granted) = post(
        node,
        "/v1/authorize",
        &json!({
            "policy_hex": hex::encode(policy.serialize()),
            "policy_sigs_hex": policy_sigs_hex(payer, policy),
            "policy_keys_hex": policy_keys_hex(payer),
            "request_hex": hex::encode(request.serialize()),
            "nonce": nonce,
        }),
    );
    assert_eq!(s, 200, "authorize refused: {granted}");
    let auth = Authorization::deserialize(
        &hex::decode(granted["authorization_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let payment = build_signed_payment(
        payer,
        &auth,
        NET,
        AgentRole::Machine,
        0,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .unwrap();
    let sigs = Auth::sigs_for(payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(payer).unwrap();
    let (s, submitted) = post(
        node,
        "/v1/payment/submit",
        &json!({
            "payment_hex": hex::encode(payment.serialize()),
            "authorization_hex": hex::encode(auth.serialize()),
            "auth_sigs_hex": hex::encode(sigs.to_bytes()),
            "auth_keys_hex": hex::encode(keys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "payment submit refused: {submitted}");
    assert_eq!(submitted["duplicate"], false);
    (
        submitted["payment_id"].as_str().unwrap().to_string(),
        payment,
        auth,
        sigs,
        keys,
    )
}

#[test]
fn batch_quote_shows_savings_over_separate_settlements() {
    let node = start();
    let payer = wallet(91, "batch-payer");
    let payer_addr = payer.address().unwrap();
    let provider_addr = wallet(92, "batch-provider").address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"micro-test");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer_addr),
        owner: payer_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": address_to_hex(&payer_addr), "amount_sat": 100_000 }),
    );
    assert_eq!(s, 200, "credit deposit refused: {b}");

    // Policy window is cumulative 100k over 10 blocks; nonces strictly increase.
    let mut ids = Vec::new();
    for nonce in 1..=5u64 {
        let (id, _, _, _, _) =
            authorize_and_submit(&node, &payer, &policy, &provider_addr, service, 400, nonce);
        ids.push(id);
    }
    let (s, quote) = post(
        &node,
        "/v1/payments/aggregate",
        &json!({ "payment_ids": ids }),
    );
    assert_eq!(s, 200, "aggregate refused: {quote}");
    assert_eq!(quote["payments"].as_array().unwrap().len(), 5);
    assert_eq!(quote["total_amount_sat"], 2_000);
    assert!(quote["savings_sat"].as_u64().unwrap() > 0);
    assert!(
        quote["fee_per_payment_sat"].as_u64().unwrap()
            < quote["separate_total_fee_sat"].as_u64().unwrap() / 5
    );

    // Unknown id is 404, never 500.
    let (s, _) = post(
        &node,
        "/v1/payments/aggregate",
        &json!({ "payment_ids": vec![hash_to_hex(&[7u8; 32])] }),
    );
    assert_eq!(s, 404);
}

#[test]
fn stream_channel_opens_settles_and_reports_claimable() {
    let node = start();
    let payer = wallet(93, "stream-payer");
    let provider_addr = wallet(94, "stream-provider").address().unwrap();
    // Human payer keeps the test focused on the channel, not the policy.
    let stream = build_stream(
        &payer,
        StreamOpenSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Human,
            recipient: provider_addr,
            service: None,
            rate_sat_per_block: 10,
            start_height: 0,
            expires_at_height: 1_000,
            max_total_sat: 1_000,
            nonce: 1,
            policy_hash: [0u8; 32],
        },
    )
    .unwrap();
    let (s, opened) = post(
        &node,
        "/v1/streams/open",
        &json!({ "stream_hex": hex::encode(stream.serialize()) }),
    );
    assert_eq!(s, 200, "stream open refused: {opened}");
    let stream_id = opened["stream_id"].as_str().unwrap().to_string();

    // One voucher for blocks 0..=0: 10 sat. Node height is 0 on a fresh chain.
    let settlement = build_settlement(
        &payer,
        &stream,
        StreamSettleSpec {
            through_height: 0,
            amount_sat: 10,
            nonce: 1,
            reference: [0u8; 32],
        },
    )
    .unwrap();
    let (s, settled) = post(
        &node,
        "/v1/streams/settle",
        &json!({
            "stream_hex": hex::encode(stream.serialize()),
            "settlement_hex": hex::encode(settlement.serialize()),
        }),
    );
    assert_eq!(s, 200, "stream settle refused: {settled}");
    assert_eq!(settled["settled_sat"], 10);

    // Replaying the same voucher is a refusal, not a second credit.
    let (s, _) = post(
        &node,
        "/v1/streams/settle",
        &json!({
            "stream_hex": hex::encode(stream.serialize()),
            "settlement_hex": hex::encode(settlement.serialize()),
        }),
    );
    assert_ne!(s, 200);

    let (s, state) = get(&node, &format!("/v1/streams/{stream_id}"));
    assert_eq!(s, 200, "stream get refused: {state}");
    assert_eq!(state["settled_sat"], 10);
    assert_eq!(state["claimable_sat"], 0);
}

#[test]
fn reconciliation_and_audit_make_retries_safe() {
    let node = start();
    let payer = wallet(95, "audit-payer");
    let payer_addr = payer.address().unwrap();
    let provider = wallet(96, "audit-provider");
    let provider_addr = provider.address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"audit-test");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer_addr),
        owner: payer_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let (s, b) = post(
        &node,
        "/v1/credit/deposit",
        &json!({ "address_hex": address_to_hex(&payer_addr), "amount_sat": 100_000 }),
    );
    assert_eq!(s, 200, "credit deposit refused: {b}");

    let (id1, _, _, _, _) =
        authorize_and_submit(&node, &payer, &policy, &provider_addr, service, 400, 1);
    let (id2, payment2, _, _, _) =
        authorize_and_submit(&node, &payer, &policy, &provider_addr, service, 400, 2);

    // Both submitted, neither bound to a settlement tx: both in flight.
    let (s, unsettled) = get(&node, "/v1/payments/unsettled");
    assert_eq!(s, 200, "unsettled refused: {unsettled}");
    let ids: Vec<String> = unsettled["payments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["payment_id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&id1) && ids.contains(&id2));

    // A receipt for a payment nobody recorded is an orphan: listed, never settled.
    let mut orphan = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.to_string(),
        payer: payer_addr,
        payer_role: AgentRole::Machine,
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer_addr),
        recipient: provider_addr,
        service_id: Some(service),
        amount_sat: 400,
        payment_id: [77u8; 32],
        request_id: [78u8; 32],
        result_hash: Some(result_hash_of(b"orphan")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 64],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut orphan, &provider).unwrap();
    let (s, _) = post(
        &node,
        "/v1/receipt",
        &json!({ "receipt_hex": hex::encode(orphan.serialize()) }),
    );
    assert_eq!(s, 200);
    let (s, orphans) = get(&node, "/v1/receipts/orphans");
    assert_eq!(s, 200, "orphans refused: {orphans}");
    assert_eq!(orphans["count"], 1);

    // Audit ring records the whole trail and verifies.
    let (s, audit) = get(&node, "/v1/audit?limit=50");
    assert_eq!(s, 200, "audit refused: {audit}");
    assert_eq!(audit["chain_valid"], true);
    let kinds: Vec<String> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"payment_admitted".to_string()));
    assert!(kinds.contains(&"authorize".to_string()));

    // Risk knobs are visible before paying.
    let (s, risk) = get(&node, "/v1/risk/policy");
    assert_eq!(s, 200, "risk refused: {risk}");
    assert!(risk.get("test_mode").is_some());

    // Idempotent retry: re-submitting payment2 is a duplicate, not a double-pay.
    let mut book = PolicyBook::default();
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider_addr,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .unwrap();
    let auth = authorize_request(&mut book, &policy, NET, &request, 0, 2).unwrap();
    let sigs = Auth::sigs_for(&payer, &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&payer).unwrap();
    let (s, dup) = post(
        &node,
        "/v1/payment/submit",
        &json!({
            "payment_hex": hex::encode(payment2.serialize()),
            "authorization_hex": hex::encode(auth.serialize()),
            "auth_sigs_hex": hex::encode(sigs.to_bytes()),
            "auth_keys_hex": hex::encode(keys.to_bytes()),
        }),
    );
    assert_eq!(s, 200, "replay refused: {dup}");
    assert_eq!(dup["duplicate"], true);
    let _ = id1;
}
