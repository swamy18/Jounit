//! `jnt-mcp` tests — roadmap §10.
//!
//! The properties under test are the ones that make an MCP surface safe in
//! front of an autonomous agent:
//!
//! 1. it cannot mint authority — every authorization goes through the same
//!    `PolicyBook` the protocol uses, and a replayed nonce is refused;
//! 2. it cannot fabricate or launder a receipt — a receipt that verifies but
//!    does not bind to the presented payment is refused by name;
//! 3. malformed input is a named refusal, never a partial action or a panic;
//! 4. it holds no key material — the signing hash is returned for the caller
//!    to sign, and nothing here can produce a signature.
//!
//! Run with `cargo test -p jnt-mcp`.

use serde_json::json;

use jnt_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use jnt_core::hash::hash_to_hex;
use jnt_core::payment::build_signed_payment;
use jnt_core::receipt::{sign_receipt, ServiceReceipt, RECEIPT_VERSION};
use jnt_core::service::{build_signed_request, derive_service_id, result_hash_of, RequestSpec};
use jnt_core::wallet::Wallet;
use jnt_mcp::JounitMcp;

const NET: &str = "jounit/mini";
const HEIGHT: u64 = 50;
const EXPIRES: u64 = 9_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "mcp-test").unwrap()
}

fn policy(service: [u8; 32], provider: [u8; 20]) -> SpendPolicy {
    let owner = wallet(1).address().unwrap();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![provider],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
    }
}

/// The pieces a caller would assemble before talking to the surface.
struct Fixture {
    policy: SpendPolicy,
    request: jnt_core::service::PaymentRequest,
}

fn fixture() -> Fixture {
    let payer = wallet(1);
    let provider = wallet(2).address().unwrap();
    let service = derive_service_id(NET, &provider, b"jounit-llm");
    let policy = policy(service, provider);
    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider,
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
    )
    .unwrap();
    Fixture { policy, request }
}

fn authorize_request_json(f: &Fixture, nonce: u64) -> serde_json::Value {
    json!({
        "op": "authorize",
        "network_id": NET,
        "height": HEIGHT,
        "nonce": nonce,
        "policy_hex": hex::encode(f.policy.serialize()),
        "request_hex": hex::encode(f.request.serialize()),
    })
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[test]
fn capabilities_are_advertised_and_unknown_ops_are_refused() {
    let mcp = JounitMcp::new();
    let caps = mcp.capabilities();
    assert!(caps.contains(&"authorize"));
    assert!(caps.contains(&"inspect.receipt"));
    assert!(caps.contains(&"node.status"));

    let mut mcp = JounitMcp::new();
    let err = mcp
        .handle(&json!({ "op": "no.such.thing" }))
        .expect_err("an unknown op must be refused");
    assert_eq!(err.code, "bad_request");

    let err = mcp
        .handle(&json!({ "not_op": true }))
        .expect_err("a missing op must be refused");
    assert_eq!(err.code, "bad_request");
}

#[test]
fn authorize_returns_bytes_and_a_signing_hash_without_a_key() {
    let mut mcp = JounitMcp::new();
    let f = fixture();

    let out = mcp.handle(&authorize_request_json(&f, 1)).expect("grant");
    assert_eq!(out["amount_sat"], 400);
    assert_eq!(out["nonce"], 1);
    assert_eq!(out["height"], HEIGHT);

    // The returned bytes decode, and the signing hash matches the bytes —
    // i.e. the caller really can sign what it was handed.
    let bytes = hex::decode(out["authorization_hex"].as_str().unwrap()).unwrap();
    let auth = jnt_core::agent::Authorization::deserialize(&bytes).unwrap();
    assert_eq!(hash_to_hex(&auth.signing_hash()), out["signing_hash"]);
}

#[test]
fn a_replayed_nonce_is_refused_by_the_policy_engine() {
    let mut mcp = JounitMcp::new();
    let f = fixture();

    mcp.handle(&authorize_request_json(&f, 4)).expect("grant");
    let err = mcp
        .handle(&authorize_request_json(&f, 4))
        .expect_err("a replayed nonce must be refused");
    assert_eq!(err.code, "policy_refused");

    // A policy the request does not name is a binding failure.
    let other = policy([9u8; 32], wallet(3).address().unwrap());
    let err = mcp
        .handle(&json!({
            "op": "authorize",
            "network_id": NET,
            "height": HEIGHT,
            "nonce": 5,
            "policy_hex": hex::encode(other.serialize()),
            "request_hex": hex::encode(f.request.serialize()),
        }))
        .expect_err("a mismatched policy must be refused");
    assert_eq!(err.code, "session_binding");
}

#[test]
fn malformed_authorization_input_is_refused_not_panicked() {
    let mut mcp = JounitMcp::new();
    let err = mcp
        .handle(&json!({
            "op": "authorize",
            "network_id": NET,
            "height": HEIGHT,
            "nonce": 1,
            "policy_hex": "zz",
            "request_hex": "zz",
        }))
        .expect_err("bad hex must be refused");
    assert_eq!(err.code, "bad_request");

    // Missing required fields are named.
    let err = mcp
        .handle(&json!({ "op": "authorize", "network_id": NET }))
        .expect_err("missing fields must be refused");
    assert_eq!(err.code, "bad_request");
}

// ---------------------------------------------------------------------------
// Offline verification
// ---------------------------------------------------------------------------

fn authorize_and_pay(f: &Fixture) -> (jnt_core::payment::MachinePayment, ServiceReceipt) {
    let mut book = jnt_core::agent::PolicyBook::default();
    let auth =
        jnt_core::service::authorize_request(&mut book, &f.policy, NET, &f.request, HEIGHT, 1)
            .unwrap();
    let payment = build_signed_payment(
        &wallet(1),
        &auth,
        NET,
        AgentRole::Machine,
        2_000,
        EXPIRES,
        f.request.request_id(),
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
        request_id: f.request.request_id(),
        result_hash: Some(result_hash_of(b"output")),
        anchor: None,
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut receipt, &wallet(2)).unwrap();
    (payment, receipt)
}

#[test]
fn inspect_request_payment_and_receipt_verify_offline() {
    let mut mcp = JounitMcp::new();
    let f = fixture();
    let (payment, receipt) = authorize_and_pay(&f);

    let out = mcp
        .handle(&json!({
            "op": "inspect.request",
            "network_id": NET,
            "height": HEIGHT,
            "request_hex": hex::encode(f.request.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["amount_sat"], serde_json::Value::Null);
    assert_eq!(out["max_amount_sat"], 400);
    assert_eq!(out["request_id"], hash_to_hex(&f.request.request_id()));

    let out = mcp
        .handle(&json!({
            "op": "inspect.payment",
            "network_id": NET,
            "height": HEIGHT,
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["payment_id"], hash_to_hex(&payment.signing_hash()));

    let out = mcp
        .handle(&json!({
            "op": "inspect.receipt",
            "network_id": NET,
            "receipt_hex": hex::encode(receipt.serialize()),
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["bound_to_payment"], true);
    assert_eq!(out["receipt_id"], hash_to_hex(&receipt.receipt_id()));
}

#[test]
fn a_receipt_for_another_payment_is_refused_not_merely_verified() {
    let mut mcp = JounitMcp::new();
    let f = fixture();
    let (payment, receipt) = authorize_and_pay(&f);

    // A second, independently valid receipt for a *different* payment.
    let other_payer = wallet(5);
    let mut other = receipt.clone();
    other.payer = other_payer.address().unwrap();
    other.agent_id = derive_agent_id(NET, AgentRole::Machine, &other.payer);
    other.payment_id = [0x77u8; 32];
    other.request_id = [0x88u8; 32];
    sign_receipt(&mut other, &wallet(2)).unwrap();

    // Presenting `other` alongside the first payment must fail the binding
    // check even though `other` verifies on its own.
    let err = mcp
        .handle(&json!({
            "op": "inspect.receipt",
            "network_id": NET,
            "receipt_hex": hex::encode(other.serialize()),
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .expect_err("a receipt must not verify against an unrelated payment");
    assert_eq!(err.code, "receipt_not_bound");
}

#[test]
fn a_payment_on_another_network_is_refused() {
    let mut mcp = JounitMcp::new();
    let f = fixture();
    let (payment, _) = authorize_and_pay(&f);
    let err = mcp
        .handle(&json!({
            "op": "inspect.payment",
            "network_id": "jounit/testnet",
            "height": HEIGHT,
            "payment_hex": hex::encode(payment.serialize()),
        }))
        .expect_err("network binding must hold");
    assert_eq!(err.code, "payment_invalid");
}

#[test]
fn verify_authorization_uses_the_shared_owner_binding() {
    let mut mcp = JounitMcp::new();
    let f = fixture();
    let mut book = jnt_core::agent::PolicyBook::default();
    let auth =
        jnt_core::service::authorize_request(&mut book, &f.policy, NET, &f.request, HEIGHT, 1)
            .unwrap();
    let sigs = jnt_core::l2::Auth::sigs_for(&wallet(1), &auth.signing_hash()).unwrap();
    let keys = jnt_core::l2::Auth::keys_for(&wallet(1)).unwrap();

    let out = mcp
        .handle(&json!({
            "op": "verify.authorization",
            "authorization_hex": hex::encode(auth.serialize()),
            "sigs_hex": hex::encode(sigs.to_bytes()),
            "keys_hex": hex::encode(keys.to_bytes()),
        }))
        .unwrap();
    assert_eq!(out["valid"], true);

    // The same bundle presented by a *different* key must be refused: the
    // verification binds the keys to the owner before looking at signatures.
    let attacker_keys = jnt_core::l2::Auth::keys_for(&wallet(9)).unwrap();
    let err = mcp
        .handle(&json!({
            "op": "verify.authorization",
            "authorization_hex": hex::encode(auth.serialize()),
            "sigs_hex": hex::encode(sigs.to_bytes()),
            "keys_hex": hex::encode(attacker_keys.to_bytes()),
        }))
        .expect_err("a third-party key bundle must not authenticate another owner's grant");
    assert_eq!(err.code, "authorization_invalid");
}

// ---------------------------------------------------------------------------
// Node transport
// ---------------------------------------------------------------------------

#[test]
fn a_bad_endpoint_is_a_transport_error_not_a_panic() {
    let mut mcp = JounitMcp::new();
    let err = mcp
        .handle(&json!({ "op": "node.status", "endpoint": "not-an-endpoint" }))
        .expect_err("a malformed endpoint must be refused");
    assert_eq!(err.code, "bad_request");

    // A well-formed but closed port is transport trouble, clearly labelled.
    let err = mcp
        .handle(&json!({ "op": "node.status", "endpoint": "127.0.0.1:1" }))
        .expect_err("an unreachable node is a transport error");
    assert_eq!(err.code, "transport");
}
