//! A **keyless** MCP surface over the Jounit payment/service layer
//! (roadmap §10, roadmap §21–§22).
//!
//! # What this is
//!
//! A deterministic JSON request/response dispatcher that lets an MCP server
//! expose Jounit payment operations to an agent without ever touching a
//! private key. Every operation is one of:
//!
//! - **build** an authorization from a payer-signed request (delegates every
//!   budget rule to the existing `PolicyBook` — no rules are re-implemented
//!   here);
//! - **inspect/verify** a request, authorization, payment or receipt offline,
//!   against a network and height the caller supplies;
//! - **submit** an already-signed payment or receipt to a node's opt-in REST
//!   API, or read that node's status.
//!
//! # What this is not
//!
//! - **Not a trust authority.** It verifies using the same public functions
//!   every other verifier uses; it cannot mint an authorization, a payment or
//!   a receipt, and a "valid: true" answer is just the shared verification
//!   result.
//! - **Not a key holder.** No operation accepts, returns or stores a private
//!   key. Signing is the client's job: this layer hands back the bytes and the
//!   signing hash, and the client signs them (exactly as `POST /v1/authorize`
//!   does).
//! - **Not a consensus surface.** The only writes reach a node's opt-in API,
//!   which itself never touches `Chain::submit`.
//!
//! The dispatch table is [`JounitMcp::capabilities`]; every failure is a named
//! [`McpError`] and malformed input is refused rather than partially acted on.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::{json, Value};

use jnt_core::agent::{verify_authorization, PolicyBook, SpendPolicy};
use jnt_core::hash::hash_to_hex;
use jnt_core::payment::MachinePayment;
use jnt_core::receipt::{ReceiptBook, ServiceReceipt};
use jnt_core::service::{authorize_request, PaymentRequest, SessionError};

/// A named refusal. `code` is the stable machine-readable name; `detail` is a
/// human string that never contains signing material (nothing here holds any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpError {
    pub code: &'static str,
    pub detail: String,
}

impl McpError {
    fn bad(detail: impl Into<String>) -> Self {
        McpError {
            code: "bad_request",
            detail: detail.into(),
        }
    }

    fn refused(code: &'static str, detail: impl Into<String>) -> Self {
        McpError {
            code,
            detail: detail.into(),
        }
    }

    fn transport(detail: impl Into<String>) -> Self {
        McpError {
            code: "transport",
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for McpError {}

/// The dispatcher. It holds a [`PolicyBook`] so authorization state (nonce and
/// the tumbling spend window) survives across calls — a fresh book per call
/// would silently reset every anti-replay counter. It holds **no** key
/// material.
pub struct JounitMcp {
    policies: PolicyBook,
}

impl Default for JounitMcp {
    fn default() -> Self {
        JounitMcp::new()
    }
}

impl JounitMcp {
    pub fn new() -> Self {
        JounitMcp {
            policies: PolicyBook::default(),
        }
    }

    /// The operation names this surface answers. Advertise them to the agent
    /// so it never guesses a tool name.
    pub fn capabilities(&self) -> Vec<&'static str> {
        vec![
            "authorize",
            "inspect.authorization",
            "inspect.request",
            "inspect.payment",
            "inspect.receipt",
            "verify.authorization",
            "node.status",
            "payment.submit",
            "receipt.submit",
        ]
    }

    /// Dispatch one JSON request. `{"op": "...", ...}`.
    pub fn handle(&mut self, request: &Value) -> Result<Value, McpError> {
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::bad("missing `op`"))?;
        match op {
            "authorize" => self.authorize(request),
            "inspect.authorization" => self.inspect_authorization(request),
            "inspect.request" => self.inspect_request(request),
            "inspect.payment" => self.inspect_payment(request),
            "inspect.receipt" => self.inspect_receipt(request),
            "verify.authorization" => self.verify_authorization(request),
            "node.status" => self.node_status(request),
            "payment.submit" => self.payment_submit(request),
            "receipt.submit" => self.receipt_submit(request),
            other => Err(McpError::bad(format!("unknown op `{other}`"))),
        }
    }

    // -----------------------------------------------------------------------
    // Authorization
    // -----------------------------------------------------------------------

    /// `authorize` — the request → authorization step. Adds no rule of its own:
    /// `authorize_request` delegates entirely to the policy engine. Returns the
    /// authorization bytes and the signing hash the *owner* signs; this layer
    /// never signs.
    fn authorize(&mut self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let nonce = u64_field(request, "nonce")?;
        let policy_bytes = hex_field(request, "policy_hex")?;
        let request_bytes = hex_field(request, "request_hex")?;

        let policy = SpendPolicy::deserialize(&policy_bytes)
            .map_err(|e| McpError::bad(format!("policy: {e}")))?;
        let parsed = PaymentRequest::deserialize(&request_bytes)
            .map_err(|e| McpError::bad(format!("request: {e}")))?;

        let auth = authorize_request(
            &mut self.policies,
            &policy,
            network_id,
            &parsed,
            height,
            nonce,
        )
        .map_err(session_error)?;

        Ok(json!({
            "authorization_hex": hex::encode(auth.serialize()),
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "amount_sat": auth.amount_sat,
            "nonce": auth.nonce,
            "height": auth.height,
            "note": "the policy owner signs `signing_hash`; this layer holds no key",
        }))
    }

    fn inspect_authorization(&self, request: &Value) -> Result<Value, McpError> {
        let bytes = hex_field(request, "authorization_hex")?;
        let auth = jnt_core::agent::Authorization::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("authorization: {e}")))?;
        Ok(json!({
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "owner": hex::encode(auth.owner),
            "recipient": hex::encode(auth.recipient),
            "amount_sat": auth.amount_sat,
            "service_id": auth.service.map(hex::encode),
            "height": auth.height,
            "nonce": auth.nonce,
        }))
    }

    // -----------------------------------------------------------------------
    // Offline verification of the bridge stages
    // -----------------------------------------------------------------------

    fn inspect_request(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let bytes = hex_field(request, "request_hex")?;
        let parsed = PaymentRequest::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("request: {e}")))?;
        parsed
            .verify(network_id, height)
            .map_err(|e| McpError::refused("request_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            "request_id": hash_to_hex(&parsed.request_id()),
            "payer": hex::encode(parsed.payer),
            "payer_type": role_name(parsed.payer_type),
            "service_id": hex::encode(parsed.service_id),
            "recipient": hex::encode(parsed.recipient),
            "max_amount_sat": parsed.max_amount_sat,
            "expires_at_height": parsed.expires_at_height,
            "policy_hash": hash_to_hex(&parsed.policy_hash),
        }))
    }

    fn inspect_payment(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let height = u64_field(request, "height")?;
        let bytes = hex_field(request, "payment_hex")?;
        let payment = MachinePayment::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("payment: {e}")))?;
        payment
            .verify(network_id, height)
            .map_err(|e| McpError::refused("payment_invalid", e.to_string()))?;
        Ok(json!({
            "valid": true,
            "payment_id": hash_to_hex(&payment.signing_hash()),
            "payer": hex::encode(payment.payer),
            "payer_type": role_name(payment.payer_type),
            "recipient": hex::encode(payment.recipient),
            "amount_sat": payment.amount_sat,
            "fee_sat": payment.fee_sat,
            "nonce": payment.nonce,
            "expires_at_height": payment.expires_at_height,
        }))
    }

    fn inspect_receipt(&self, request: &Value) -> Result<Value, McpError> {
        let network_id = str_field(request, "network_id")?;
        let bytes = hex_field(request, "receipt_hex")?;
        let receipt = ServiceReceipt::deserialize(&bytes)
            .map_err(|e| McpError::bad(format!("receipt: {e}")))?;
        receipt
            .verify(network_id)
            .map_err(|e| McpError::refused("receipt_invalid", e.to_string()))?;

        // When the caller supplies the payment too, check the binding — a
        // receipt that verifies in isolation can still be for another payment.
        let mut bound = Value::Null;
        if let Some(payment_hex) = request.get("payment_hex").and_then(Value::as_str) {
            let payment_bytes = hex::decode(payment_hex.trim_start_matches("0x"))
                .map_err(|e| McpError::bad(format!("payment hex: {e}")))?;
            let payment = MachinePayment::deserialize(&payment_bytes)
                .map_err(|e| McpError::bad(format!("payment: {e}")))?;
            receipt
                .verify_binding(&payment)
                .map_err(|e| McpError::refused("receipt_not_bound", e.to_string()))?;
            bound = Value::Bool(true);
        }

        // `ReceiptBook` is the same replay-safe store the node uses; accepting
        // into a one-shot book answers "is this internally consistent and not
        // a self-contradiction" without inventing a second policy.
        let mut book = ReceiptBook::default();
        let outcome = book
            .accept(&receipt, network_id)
            .map_err(|e| McpError::refused("receipt_invalid", e.to_string()))?;

        Ok(json!({
            "valid": true,
            "bound_to_payment": bound,
            "outcome": format!("{outcome:?}").to_lowercase(),
            "receipt_id": hash_to_hex(&receipt.receipt_id()),
            "payment_id": hash_to_hex(&receipt.payment_id),
            "request_id": hash_to_hex(&receipt.request_id),
            "payer": hex::encode(receipt.payer),
            "recipient": hex::encode(receipt.recipient),
            "amount_sat": receipt.amount_sat,
            "result_hash": receipt.result_hash.map(|h| hash_to_hex(&h)),
        }))
    }

    /// Verify an authorization signature bundle presented by a third party.
    /// Uses the shared `verify_authorization`, which checks the keys bind to
    /// the owner *before* looking at the signature.
    fn verify_authorization(&self, request: &Value) -> Result<Value, McpError> {
        let auth_bytes = hex_field(request, "authorization_hex")?;
        let auth = jnt_core::agent::Authorization::deserialize(&auth_bytes)
            .map_err(|e| McpError::bad(format!("authorization: {e}")))?;
        let sigs_bytes = hex_field(request, "sigs_hex")?;
        let keys_bytes = hex_field(request, "keys_hex")?;
        let sigs = bundle_from_bytes(&sigs_bytes)?;
        let keys = bundle_from_bytes(&keys_bytes)?;
        verify_authorization(&sigs, &keys, &auth)
            .map_err(|e| McpError::refused("authorization_invalid", e.to_string()))?;
        Ok(json!({ "valid": true, "owner": hex::encode(auth.owner) }))
    }

    // -----------------------------------------------------------------------
    // Node transport (the opt-in REST API, loopback by design)
    // -----------------------------------------------------------------------

    fn node_status(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        http_json(endpoint, "GET", "/v1/status", None)
    }

    fn payment_submit(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        let payment_hex = str_field(request, "payment_hex")?;
        http_json(
            endpoint,
            "POST",
            "/v1/payment/submit",
            Some(&json!({ "payment_hex": payment_hex }).to_string()),
        )
    }

    fn receipt_submit(&self, request: &Value) -> Result<Value, McpError> {
        let endpoint = str_field(request, "endpoint")?;
        let receipt_hex = str_field(request, "receipt_hex")?;
        http_json(
            endpoint,
            "POST",
            "/v1/receipt",
            Some(&json!({ "receipt_hex": receipt_hex }).to_string()),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A stable lowercase role name for JSON output.
fn role_name(role: jnt_core::agent::AgentRole) -> &'static str {
    match role {
        jnt_core::agent::AgentRole::Human => "human",
        jnt_core::agent::AgentRole::Machine => "machine",
        jnt_core::agent::AgentRole::Service => "service",
    }
}

fn session_error(e: SessionError) -> McpError {
    match &e {
        SessionError::Policy(_) => McpError::refused("policy_refused", e.to_string()),
        SessionError::Binding(_) => McpError::refused("session_binding", e.to_string()),
        _ => McpError::bad(e.to_string()),
    }
}

fn str_field<'a>(v: &'a Value, name: &str) -> Result<&'a str, McpError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::bad(format!("missing string field `{name}`")))
}

fn u64_field(v: &Value, name: &str) -> Result<u64, McpError> {
    v.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| McpError::bad(format!("missing integer field `{name}`")))
}

fn hex_field(v: &Value, name: &str) -> Result<Vec<u8>, McpError> {
    let s = str_field(v, name)?;
    hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| McpError::bad(format!("{name}: {e}")))
}

fn bundle_from_bytes(bytes: &[u8]) -> Result<jnt_core::sig::Bundle, McpError> {
    let mut reader = jnt_core::ser::Reader::new(bytes);
    let bundle = jnt_core::sig::Bundle::from_reader(&mut reader)
        .map_err(|e| McpError::bad(format!("bundle: {e}")))?;
    reader
        .expect_end()
        .map_err(|_| McpError::bad("bundle has trailing bytes"))?;
    Ok(bundle)
}

/// A minimal `host:port` HTTP/1.1 client, so this crate stays dependency-free
/// and never reaches an address the caller did not name. Loopback is the
/// expected endpoint (the node API is loopback by default).
fn http_json(
    endpoint: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Value, McpError> {
    let addr: SocketAddr = endpoint
        .trim()
        .trim_start_matches("http://")
        .parse()
        .map_err(|e| McpError::bad(format!("endpoint `{endpoint}`: {e}")))?;
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: close\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );

    let mut stream = TcpStream::connect(addr)
        .map_err(|e| McpError::transport(format!("connect {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| McpError::transport(e.to_string()))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| McpError::transport(format!("send: {e}")))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| McpError::transport(format!("receive: {e}")))?;

    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| McpError::transport("node returned no HTTP status"))?;
    let payload = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or_default();
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| McpError::transport(format!("node reply was not JSON: {e}")))?;

    if status >= 400 {
        let code = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("node_refused");
        return Err(McpError::refused(
            match code {
                "bad_request" => "bad_request",
                "not_found" => "not_found",
                "payment_refused" => "payment_refused",
                "receipt_refused" => "receipt_refused",
                "receipt_conflict" => "receipt_conflict",
                _ => "node_refused",
            },
            value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("node refused the request")
                .to_string(),
        ));
    }
    Ok(value)
}
