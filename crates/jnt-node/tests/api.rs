//! Service API integration tests — roadmap items 16/17, Decision 9,
//! SPEC.md §19.2.
//!
//! These drive the real server: [`jnt_node::api::spawn`] binds a socket (port 0
//! in every test, so they never race for a fixed port) and the requests below
//! go over the wire as raw HTTP. Nothing here calls a handler directly, so a
//! routing, serialization or status-code mistake fails the test.
//!
//! What they pin:
//!
//! - the API is a *read/write view*, never a consensus surface: an L1
//!   broadcast takes the exact `pool.add` path a peer transaction takes, and
//!   an unsigned or badly-signed transaction is refused rather than mined;
//! - a payment cannot be recorded without verifying, and a re-submission is
//!   idempotent rather than a second payment;
//! - a receipt binds to its payment, and two contradicting receipts for one
//!   payment are refused by name (fail closed);
//! - authorization goes through the policy engine — a replayed nonce is a
//!   refusal, not a second grant;
//! - malformed input is a client error (400/404), never a 500.
//!
//! Run with `cargo test -p jnt-node --test api`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jnt_core::agent::{
    derive_agent_id, AgentRole, Authorization, PolicyBook, SpendPolicy, POLICY_VERSION,
};
use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::{address_to_hex, hash_to_hex};
use jnt_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use jnt_core::params::NetworkParams;
use jnt_core::payment::{build_signed_payment, MachinePayment};
use jnt_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use jnt_core::service::{
    authorize_request, build_signed_request, derive_service_id, result_hash_of, RequestSpec,
};
use jnt_core::tx::Transaction;
use jnt_core::wallet::Wallet;
use jnt_node::api::{spawn, SharedNode};
use jnt_node::l2::NodeL2;

use serde_json::Value;

const NET: &str = "jounit/mini";
const EXPIRES: u64 = 9_000;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Node {
    addr: SocketAddr,
    #[allow(dead_code)]
    shared: Arc<Mutex<SharedNode>>,
}

/// Start a server on an ephemeral loopback port over a fresh mini chain.
fn start() -> Node {
    start_with(Chain::new(NetworkParams::mini()).unwrap())
}

/// Start a server over a chain the caller has already mined.
fn start_with(chain: Chain) -> Node {
    let params = NetworkParams::mini();
    let l2 = NodeL2::fresh(&params);
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn(Arc::clone(&shared), peers, "127.0.0.1:0".parse().unwrap())
        .expect("the API must bind its loopback socket");
    Node { addr, shared }
}

/// A chain of `n` blocks paying their coinbase to `miner`, at exactly the mini
/// target spacing so difficulty stays pinned at 1 and mining is cheap. These
/// tests exercise state rules, not proof-of-work.
fn mine_to(params: &NetworkParams, miner: &Wallet, n: u64) -> Chain {
    let mut chain = Chain::new(params.clone()).unwrap();
    let addr = miner.address().unwrap();
    for h in 1..=n {
        let block = chain
            .mine_block(addr, vec![], GENESIS_TIMESTAMP_MS + h * 1_000)
            .unwrap();
        chain.submit(block).unwrap();
    }
    chain
}

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

/// A raw HTTP exchange over a fresh connection. `Connection: close` makes the
/// server close after the response, so `read_to_end` is the whole body.
fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: close\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    exchange(addr, request.as_bytes())
}

fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    // A refusal may arrive before the whole oversize body is written; that is
    // the server doing its job, not a test failure.
    let _ = stream.write_all(request);
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("body was not JSON ({e}): {text}"))
}

fn get(node: &Node, path: &str) -> (u16, Value) {
    let (status, body) = http(node.addr, "GET", path, None);
    (status, json(&body))
}

fn post(node: &Node, path: &str, body: &Value) -> (u16, Value) {
    let (status, text) = http(node.addr, "POST", path, Some(&body.to_string()));
    (status, json(&text))
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

#[test]
fn health_status_fees_and_finality_answer() {
    let node = start();

    let (s, health) = get(&node, "/v1/health");
    assert_eq!(s, 200);
    assert_eq!(health["status"], "ok");

    let (s, status) = get(&node, "/v1/status");
    assert_eq!(s, 200);
    assert_eq!(status["network"], "mini");
    assert_eq!(status["network_id"], NET);
    assert_eq!(status["height"], 0);
    assert_eq!(status["mempool_len"], 0);

    let (s, fees) = get(&node, "/v1/fees");
    assert_eq!(s, 200);
    assert_eq!(fees["gas_base"], 16_000);
    assert_eq!(fees["gas_per_input"], 1_000);
    assert_eq!(fees["gas_per_output"], 250);
    // The D3 L2 flat schedule is surfaced, not recomputed.
    assert!(fees["l2_fee_schedule"].as_array().unwrap().len() >= 5);

    let (s, finality) = get(&node, "/v1/finality");
    assert_eq!(s, 200);
    assert_eq!(finality["tip_height"], 0);

    let (s, latest) = get(&node, "/v1/block/latest");
    assert_eq!(s, 200);
    assert!(latest["hash"].as_str().unwrap().len() == 64);

    let (s, pool) = get(&node, "/v1/mempool");
    assert_eq!(s, 200);
    assert_eq!(pool["count"], 0);

    let (s, tasks) = get(&node, "/v1/tasks/open");
    assert_eq!(s, 200);
    assert_eq!(tasks["count"], 0);
}

#[test]
fn metrics_endpoint_serves_prometheus_gauges_in_the_exposition_format() {
    let node = start();
    // `http`/`exchange` deliberately strip the headers, so this test reads the
    // raw response: the content type *is* part of what must be correct.
    let mut stream = TcpStream::connect(node.addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();

    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(status, 200);
    let (headers, body) = text.split_once("\r\n\r\n").expect("headers then body");
    assert!(
        headers
            .to_lowercase()
            .contains("content-type: text/plain; version=0.0.4"),
        "metrics must advertise the Prometheus text content type, got:\n{headers}"
    );

    // At height 0 the ladder is grandfathered: the allowance is u64::MAX and
    // nothing is issued. Both gauges must carry exactly those live values,
    // which is what proves they came from the chain and not a constant.
    assert!(
        body.contains(&format!(
            "jounit_rate_anchor_allowance_sat{{network=\"{NET}\"}} 18446744073709551615"
        )),
        "rate-anchor gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("jounit_issued_sat{{network=\"{NET}\"}} 0")),
        "issued gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("jounit_net_supply_sat{{network=\"{NET}\"}} 0")),
        "net-supply gauge missing or wrong:\n{body}"
    );
    assert!(
        body.contains(&format!("jounit_height{{network=\"{NET}\"}} 0")),
        "height gauge missing:\n{body}"
    );
    assert!(
        body.contains("# TYPE jounit_pscb_reserve_sat gauge"),
        "reserve gauge has no TYPE preamble:\n{body}"
    );

    // Every sample line must be exactly `name{labels} value` with an integer
    // value: one malformed line makes a real scraper drop the whole response.
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 2, "not an exposition sample line: {line:?}");
        assert!(
            parts[1].parse::<u64>().is_ok(),
            "value is not an integer: {line:?}"
        );
        assert!(parts[0].contains('{'), "sample must be labelled: {line:?}");
    }
}

#[test]
fn an_unknown_balance_address_reads_zero_and_a_malformed_one_is_a_client_error() {
    let node = start();
    let addr = wallet(31, "reader").address().unwrap();

    let (s, body) = get(&node, &format!("/v1/balance/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["confirmed_sat"], 0);
    assert_eq!(body["spendable_sat"], 0);

    let (s, _) = get(&node, "/v1/balance/not-an-address");
    assert_eq!(s, 400, "a malformed address is the caller's error");

    let (s, body) = get(&node, &format!("/v1/utxo/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["utxos"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_hashes_are_404_never_500() {
    let node = start();
    let unknown = hash_to_hex(&[0xABu8; 32]);

    let (s, body) = get(&node, &format!("/v1/tx/{unknown}"));
    assert_eq!(s, 404);
    assert_eq!(body["error"], "not_found");

    let (s, _) = get(&node, &format!("/v1/block/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/payment/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/receipt/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/task/{unknown}"));
    assert_eq!(s, 404);

    let (s, _) = get(&node, &format!("/v1/vwc/{unknown}"));
    assert_eq!(s, 404);

    // A hash that is not even the right shape is a client error, not a 404.
    let (s, _) = get(&node, "/v1/tx/deadbeef");
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Reputation (derived, non-consensus)
// ---------------------------------------------------------------------------

#[test]
fn reputation_reads_zero_for_an_address_with_no_history() {
    let node = start();
    let addr = wallet(31, "reputee").address().unwrap();

    let (s, body) = get(&node, &format!("/v1/reputation/{}", address_to_hex(&addr)));
    assert_eq!(s, 200);
    assert_eq!(body["score"], 0);
    assert_eq!(body["events"], 0);
    assert_eq!(body["worker_address"], address_to_hex(&addr));
    let expected_agent = derive_agent_id(NET, AgentRole::Machine, &addr);
    assert_eq!(body["agent_id"], address_to_hex(&expected_agent));
}

#[test]
fn reputation_rejects_a_malformed_address() {
    let node = start();
    let (s, _) = get(&node, "/v1/reputation/not-an-address");
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// L1 transaction paths
// ---------------------------------------------------------------------------

#[test]
fn tx_build_refuses_an_unfunded_address_without_signing_anything() {
    let node = start();
    let from = wallet(41, "poor").address().unwrap();
    let to = wallet(42, "payee").address().unwrap();

    let (s, body) = post(
        &node,
        "/v1/tx/build",
        &serde_json::json!({
            "from": address_to_hex(&from),
            "to": address_to_hex(&to),
            "amount_sat": 1_000,
            "max_fee_sat": 1_000_000,
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(body["error"], "insufficient_funds");
}

#[test]
fn a_local_transaction_is_built_signed_broadcast_then_looked_up() {
    let params = NetworkParams::mini();
    let miner = wallet(51, "api-miner");
    // 12 blocks leaves the coinbases at heights 1–3 mature (maturity 10).
    let chain = mine_to(&params, &miner, 12);
    let node = start_with(chain);

    let from = miner.address().unwrap();
    let to = wallet(52, "api-payee").address().unwrap();

    // The build returns *unsigned* bytes and never a signed transaction.
    let (s, built) = post(
        &node,
        "/v1/tx/build",
        &serde_json::json!({
            "from": address_to_hex(&from),
            "to": address_to_hex(&to),
            "amount_sat": 1_000_000,
            "max_fee_sat": 1_000_000,
        }),
    );
    assert_eq!(s, 200, "build failed: {built}");
    let fee = built["fee_sat"].as_u64().unwrap();
    assert!(fee > 0);
    let unsigned_hex = built["unsigned_tx_hex"].as_str().unwrap();

    // Broadcasting the unsigned bytes is refused: the API is not a way to put
    // a signature-less transaction into the pool.
    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": unsigned_hex }),
    );
    assert_eq!(s, 400, "an unsigned transaction must be refused");
    assert_eq!(body["error"], "tx_refused");

    // Sign it as the owner and broadcast the real thing.
    let mut tx = Transaction::deserialize(&hex::decode(unsigned_hex).unwrap()).unwrap();
    miner.sign(&mut tx).unwrap();
    let signed_hex = hex::encode(tx.serialize());

    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": signed_hex }),
    );
    assert_eq!(s, 200, "broadcast failed: {body}");
    let txid = body["tx_hash"].as_str().unwrap().to_string();
    assert_eq!(txid, hash_to_hex(&tx.txid()));

    // It is pending, and a re-broadcast of the same bytes is idempotent.
    let (s, body) = get(&node, &format!("/v1/tx/{txid}"));
    assert_eq!(s, 200);
    assert_eq!(body["status"], "pending");

    let (s, body) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": signed_hex }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["already_known"], true);

    let (s, pool) = get(&node, "/v1/mempool");
    assert_eq!(s, 200);
    assert_eq!(pool["count"], 1);
}

#[test]
fn garbage_bytes_are_a_client_error_not_a_panic() {
    let node = start();

    let (s, _) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": "not hex at all" }),
    );
    assert_eq!(s, 400);

    let (s, _) = post(
        &node,
        "/v1/tx/broadcast",
        &serde_json::json!({ "signed_tx_hex": "deadbeef" }),
    );
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Authorization → payment → receipt
// ---------------------------------------------------------------------------

fn machine_policy(owner: &Wallet, provider_addr: &[u8; 20], service: [u8; 32]) -> SpendPolicy {
    let owner_addr = owner.address().unwrap();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner_addr),
        owner: owner_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![*provider_addr],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

/// The full bridge, exercised through the API: policy + signed request are
/// POSTed, the returned authorization is decoded and used to build a payment,
/// the payment is submitted, and a receipt for it is recorded.
fn run_bridge(node: &Node) -> (MachinePayment, ServiceReceipt, Vec<u8>) {
    let payer = wallet(61, "api-payer");
    let provider = wallet(62, "api-provider");
    let provider_addr = provider.address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"jounit-llm");
    let policy = machine_policy(&payer, &provider_addr, service);

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
    )
    .unwrap();

    let (s, granted) = post(
        node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(policy.serialize()),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 1,
        }),
    );
    assert_eq!(s, 200, "authorize refused: {granted}");
    assert_eq!(granted["amount_sat"], 400);
    assert_eq!(granted["nonce"], 1);

    // The authorization comes back as bytes the payment layer can consume —
    // that round trip is the whole point of returning it.
    let auth_bytes = hex::decode(granted["authorization_hex"].as_str().unwrap()).unwrap();
    let auth = Authorization::deserialize(&auth_bytes).expect("authorization must decode");
    assert_eq!(hash_to_hex(&auth.signing_hash()), granted["signing_hash"]);

    let payment = build_signed_payment(
        &payer,
        &auth,
        NET,
        AgentRole::Machine,
        2_000,
        EXPIRES,
        request.request_id(),
    )
    .unwrap();

    let mut receipt = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.to_string(),
        payer: payment.payer,
        payer_role: payment.payer_type,
        agent_id: payment.agent_id,
        recipient: payment.recipient,
        service_id: payment.service,
        amount_sat: payment.amount_sat,
        payment_id: payment.signing_hash(),
        request_id: request.request_id(),
        result_hash: Some(result_hash_of(b"model-output-v1")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 32],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &provider).unwrap();
    receipt.verify_binding(&payment).unwrap();

    (payment, receipt, auth_bytes)
}

#[test]
fn authorize_grants_then_refuses_a_replayed_nonce() {
    let node = start();
    let payer = wallet(71, "nonce-payer");
    let provider_addr = wallet(72, "nonce-provider").address().unwrap();
    let service = derive_service_id(NET, &provider_addr, b"svc");
    let policy = machine_policy(&payer, &provider_addr, service);
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
    )
    .unwrap();

    let body = serde_json::json!({
        "policy_hex": hex::encode(policy.serialize()),
        "request_hex": hex::encode(request.serialize()),
        "nonce": 7,
    });

    let (s, first) = post(&node, "/v1/authorize", &body);
    assert_eq!(s, 200, "first grant failed: {first}");

    // Same nonce again: the policy engine refuses a replay by name.
    let (s, body) = post(&node, "/v1/authorize", &body);
    assert_eq!(s, 409);
    assert_eq!(body["error"], "policy_refused");

    // A policy the request does not name is a binding failure, also refused.
    let other = machine_policy(&payer, &wallet(73, "other").address().unwrap(), [9u8; 32]);
    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": hex::encode(other.serialize()),
            "request_hex": hex::encode(request.serialize()),
            "nonce": 8,
        }),
    );
    assert_eq!(s, 409);
    assert_eq!(body["error"], "session_binding");
}

#[test]
fn a_malformed_policy_is_a_client_error() {
    let node = start();
    let (s, body) = post(
        &node,
        "/v1/authorize",
        &serde_json::json!({
            "policy_hex": "0011",
            "request_hex": "0011",
            "nonce": 1,
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(body["error"], "bad_request");
}

#[test]
fn a_verified_payment_is_recorded_once_and_readable() {
    let node = start();
    let (payment, _receipt, _auth) = run_bridge(&node);
    let payment_hex = hex::encode(payment.serialize());

    let (s, body) = post(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({ "payment_hex": payment_hex }),
    );
    assert_eq!(s, 200, "payment refused: {body}");
    assert_eq!(body["duplicate"], false);
    let id = body["payment_id"].as_str().unwrap().to_string();
    assert_eq!(id, hash_to_hex(&payment.signing_hash()));

    // The exact same payment is idempotent, not a second payment.
    let (s, body) = post(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({ "payment_hex": payment_hex }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["duplicate"], true);

    let (s, body) = get(&node, &format!("/v1/payment/{id}"));
    assert_eq!(s, 200);
    assert_eq!(body["amount_sat"], 400);
    assert_eq!(body["network_id"], NET);
}

#[test]
fn a_payment_for_another_network_is_refused() {
    let node = start();
    // A structurally valid payment naming a different network: verification
    // must reject the binding rather than record it.
    let payer = wallet(81, "foreign");
    let provider = wallet(82, "provider").address().unwrap();
    let service = derive_service_id("jounit/testnet", &provider, b"svc");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: "jounit/testnet".to_string(),
        agent_id: derive_agent_id(
            "jounit/testnet",
            AgentRole::Machine,
            &payer.address().unwrap(),
        ),
        owner: payer.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![provider],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    };
    let mut book = PolicyBook::default();
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: "jounit/testnet".to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
    )
    .unwrap();
    let auth = authorize_request(&mut book, &policy, "jounit/testnet", &request, 0, 1).unwrap();
    let payment = build_signed_payment(
        &payer,
        &auth,
        "jounit/testnet",
        AgentRole::Machine,
        2_000,
        EXPIRES,
        request.request_id(),
    )
    .unwrap();

    let (s, body) = post(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({ "payment_hex": hex::encode(payment.serialize()) }),
    );
    assert_eq!(s, 400);
    assert_eq!(body["error"], "payment_refused");
}

#[test]
fn a_receipt_records_once_and_a_contradicting_one_is_refused() {
    let node = start();
    let (payment, receipt, _auth) = run_bridge(&node);

    let (s, body) = post(
        &node,
        "/v1/payment/submit",
        &serde_json::json!({ "payment_hex": hex::encode(payment.serialize()) }),
    );
    assert_eq!(s, 200, "{body}");

    let receipt_hex = hex::encode(receipt.serialize());
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": receipt_hex }),
    );
    assert_eq!(s, 200, "receipt refused: {body}");
    assert_eq!(body["outcome"], "inserted");
    let receipt_id = body["receipt_id"].as_str().unwrap().to_string();

    // The same receipt is idempotent.
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": receipt_hex }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["outcome"], "duplicate");

    // A *different* receipt claiming the same payment is refused by name.
    let provider = wallet(62, "api-provider");
    let mut forged = receipt.clone();
    forged.result_hash = Some(result_hash_of(b"a-different-outcome"));
    sign_receipt(&mut forged, &provider).unwrap();
    assert_ne!(forged.receipt_id(), receipt.receipt_id());
    let (s, body) = post(
        &node,
        "/v1/receipt",
        &serde_json::json!({ "receipt_hex": hex::encode(forged.serialize()) }),
    );
    assert_eq!(s, 409);
    assert_eq!(body["error"], "receipt_conflict");

    // Lookup by receipt id, and by the payment id it claims.
    let (s, body) = get(&node, &format!("/v1/receipt/{receipt_id}"));
    assert_eq!(s, 200);
    assert_eq!(body["amount_sat"], 400);
    let payment_id = hash_to_hex(&payment.signing_hash());
    let (s, body) = get(&node, &format!("/v1/receipt/{payment_id}"));
    assert_eq!(s, 200);
    assert_eq!(body["payment_id"], payment_id);
}

// ---------------------------------------------------------------------------
// L2 broadcast (dry-run only — state changes only via canonical replay)
// ---------------------------------------------------------------------------

fn post_payload(seed: u8) -> L2Transaction {
    let w = wallet(seed, "l2-poster");
    let task = ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 1_000_000,
        expiry_height: 1_000,
        submit_height: 1,
    };
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, 1, 5_000_000, 1_000, task).unwrap(),
    ))
}

#[test]
fn l2_broadcast_queues_a_funded_payload_and_refuses_an_unfunded_one() {
    let node = start();

    // Seed 1 holds a mini genesis grant, so its post passes the dry-run.
    let funded = post_payload(1);
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(funded.serialize()) }),
    );
    assert_eq!(s, 200, "funded post refused: {body}");
    assert_eq!(body["queued"], true);

    // Re-queuing the same txid reports it rather than duplicating the queue.
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(funded.serialize()) }),
    );
    assert_eq!(s, 200);
    assert_eq!(body["already_queued"], true);

    // Seed 9 holds no grant: the dry-run names the refusal instead of queueing.
    let unfunded = post_payload(9);
    let (s, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex::encode(unfunded.serialize()) }),
    );
    assert_eq!(s, 409);
    assert_eq!(body["error"], "l2_refused");

    // Malformed bytes never reach the dry-run.
    let (s, _) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": "zzzz" }),
    );
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn an_oversize_body_is_refused_before_it_is_parsed() {
    let node = start();
    // One byte past the 5 MiB cap.
    let body = "x".repeat(5 * 1024 * 1024 + 1);
    let (status, _) = http(
        node.addr,
        "POST",
        "/v1/tx/broadcast",
        Some(&format!(r#"{{"signed_tx_hex":"{body}"}}"#)),
    );
    assert!(
        status == 413 || status == 400,
        "an oversize body must be refused, got {status}"
    );
}

/// An unsupported withdrawal is refused **explicitly** at the API, not
/// silently ignored.
///
/// There is no L2 withdrawal transaction type (`jnt-l2/tests/exit_unavailable.rs`
/// proves the wire admits exactly five), so the withdrawal-shaped envelope below
/// is the closest thing to a withdrawal request the API can receive. It must be
/// a clean 400 that names the problem — never a 500, a panic, or a value that
/// gets queued for inclusion in a block.
#[test]
fn a_withdrawal_shaped_l2_payload_is_refused_by_name() {
    let node = start();

    // Version 1 envelope, type byte 0x16 — the byte immediately after the
    // highest defined L2 type (0x15 ExitQueue), which is where a withdrawal
    // would sit if one existed.
    let mut envelope = vec![1u8, 0, 0, 0, 0x16];
    envelope.extend_from_slice(&[0u8; 32]);
    let hex_body = hex::encode(&envelope);

    let (status, body) = post(
        &node,
        "/v1/l2/broadcast",
        &serde_json::json!({ "l2_tx_hex": hex_body }),
    );
    assert_eq!(status, 400, "a client error, never a 500: {body}");
    assert_eq!(body["error"], "bad_request");
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("unknown L2 transaction type"),
        "the refusal must name the problem, got {detail:?}"
    );

    // The refusal left nothing behind: no task, no queued transaction.
    let (s, open) = get(&node, "/v1/tasks/open");
    assert_eq!(s, 200);
    assert_eq!(open["count"], 0);
    let (s, status_json) = get(&node, "/v1/status");
    assert_eq!(s, 200);
    assert_eq!(status_json["height"], 0, "no block was mined");
    assert_eq!(status_json["l2"]["applied"], 0);
}

/// The same refusal through the CLI's own decode path, so a withdrawal attempt
/// is rejected identically whether it arrives over HTTP or from a local tool.
#[test]
fn an_undefined_l2_type_byte_is_refused_by_the_decoder() {
    let mut envelope = vec![1u8, 0, 0, 0];
    envelope.push(0x16);
    envelope.extend_from_slice(&[0u8; 32]);
    let err = jnt_core::l2::L2Transaction::deserialize(&envelope)
        .expect_err("0x16 is not an L2 transaction type");
    assert!(err.to_string().contains("unknown L2 transaction type"));
    // And the boundary is exactly six: the highest real type decodes, the
    // next byte does not.
    assert!(jnt_core::l2::L2TxType::from_wire(0x15).is_ok());
    assert!(jnt_core::l2::L2TxType::from_wire(0x16).is_err());
}
