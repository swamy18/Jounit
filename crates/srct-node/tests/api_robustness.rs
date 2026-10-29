//! Adversarial-input sweep over every mutating route (Task 7).
//!
//! Each case sends bytes a hostile or broken client could send — zero
//! amounts, empty strings, `u64::MAX`, invalid hex, wrong-length addresses,
//! unknown enum values — and asserts the node answers a client error, never a
//! panic, a hang, or a 500. A 4xx with a JSON `{"error": ...}` body is the
//! contract; an empty 4xx body is acceptable only where axum itself answers
//! (no matching route), which these cases never hit.
//!
//! Run with `cargo test -p srct-node --test api_robustness`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::chain::Chain;
use srct_core::params::NetworkParams;
use srct_node::api::{spawn, SharedNode};
use srct_node::l2::NodeL2;

fn start() -> SocketAddr {
    let params = NetworkParams::mini();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(Chain::new(params).unwrap(), l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    spawn(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .expect("the API must bind its loopback socket")
}

fn post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("connect to the API");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request.as_bytes());
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

const ADDR20: &str = "0000000000000000000000000000000000000000";
const ADDR_SHORT: &str = "abcd";
const HASH32: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const HASH_SHORT: &str = "abcd";
const MAX: u64 = u64::MAX;

#[test]
fn hostile_bodies_are_client_errors_never_panics() {
    let addr = start();
    let cases: &[(&str, &str, Vec<String>)] = &[
        (
            "/v1/tx/build",
            "zero amount, empty and short addresses, huge fee",
            vec![
                r#"{"from":"","to":"","amount_sat":0,"max_fee_sat":0}"#.into(),
                format!(r#"{{"from":"{ADDR_SHORT}","to":"{ADDR_SHORT}","amount_sat":{MAX},"max_fee_sat":{MAX}}}"#),
                format!(r#"{{"from":"{ADDR20}","to":"{ADDR20}","amount_sat":0,"max_fee_sat":{MAX}}}"#),
            ],
        ),
        (
            "/v1/tx/broadcast",
            "empty, invalid and truncated hex",
            vec![
                r#"{"signed_tx_hex":""}"#.into(),
                r#"{"signed_tx_hex":"not hex at all!!"}"#.into(),
                r#"{"signed_tx_hex":"deadbeef"}"#.into(),
                format!(r#"{{"signed_tx_hex":"{}"}}"#, "ff".repeat(10_000)),
            ],
        ),
        (
            "/v1/l2/broadcast",
            "empty, invalid and truncated hex",
            vec![
                r#"{"l2_tx_hex":""}"#.into(),
                r#"{"l2_tx_hex":"zzzz"}"#.into(),
                r#"{"l2_tx_hex":"00"}"#.into(),
            ],
        ),
        (
            "/v1/authorize",
            "empty policy and request hex",
            vec![
                r#"{"policy_hex":"","request_hex":"","nonce":0}"#.into(),
                format!(
                    r#"{{"policy_hex":"{}","request_hex":"{}","nonce":{MAX}}}"#,
                    "ff".repeat(64),
                    "ff".repeat(64)
                ),
            ],
        ),
        (
            "/v1/delegation/link",
            "empty policy hexes",
            vec![
                r#"{"parent_policy_hex":"","child_policy_hex":""}"#.into(),
                r#"{"parent_policy_hex":"zz","child_policy_hex":"zz"}"#.into(),
            ],
        ),
        (
            "/v1/policy/revoke",
            "empty policy, sigs and keys",
            vec![
                r#"{"policy_hex":"","sigs_hex":"","keys_hex":""}"#.into(),
                r#"{"policy_hex":"zz","sigs_hex":"zz","keys_hex":"zz"}"#.into(),
            ],
        ),
        (
            "/v1/payment/submit",
            "empty payment and authorization hex",
            vec![
                r#"{"payment_hex":"","authorization_hex":"","auth_sigs_hex":"","auth_keys_hex":""}"#.into(),
            ],
        ),
        (
            "/v1/receipt",
            "empty and truncated receipt hex",
            vec![
                r#"{"receipt_hex":""}"#.into(),
                r#"{"receipt_hex":"00ff"}"#.into(),
            ],
        ),
        (
            "/v1/credit/deposit",
            "zero amount, bad address",
            vec![
                format!(r#"{{"address_hex":"{ADDR20}","amount_sat":0}}"#),
                format!(r#"{{"address_hex":"{ADDR_SHORT}","amount_sat":{MAX}}}"#),
                r#"{"address_hex":"","amount_sat":1}"#.into(),
            ],
        ),
        (
            "/v1/credit/bond",
            "zero amount, unknown action, bad address",
            vec![
                format!(r#"{{"address_hex":"{ADDR20}","action":"post","amount_sat":0}}"#),
                format!(r#"{{"address_hex":"{ADDR20}","action":"explode","amount_sat":{MAX}}}"#),
                format!(r#"{{"address_hex":"{ADDR_SHORT}","action":"","amount_sat":1}}"#),
            ],
        ),
        (
            "/v1/credit/open",
            "empty and truncated spec",
            vec![
                r#"{"spec_hex":""}"#.into(),
                r#"{"spec_hex":"ff"}"#.into(),
            ],
        ),
        (
            "/v1/credit/repay",
            "zero amount, bad position id",
            vec![
                format!(r#"{{"position_id":"{HASH32}","amount_sat":0}}"#),
                format!(r#"{{"position_id":"{HASH_SHORT}","amount_sat":{MAX}}}"#),
            ],
        ),
        (
            "/v1/credit/default",
            "bad position id",
            vec![
                format!(r#"{{"position_id":"{HASH_SHORT}"}}"#),
                r#"{"position_id":""}"#.into(),
            ],
        ),
        (
            "/v1/escrow/open",
            "zero amount, bad keys and addresses",
            vec![
                format!(
                    r#"{{"network_id":"","payer":"{ADDR_SHORT}","payer_bls":"","payee":"{ADDR_SHORT}","payee_bls":"","arbitrator":"","amount_sat":0,"nonce":{MAX}}}"#
                ),
                format!(
                    r#"{{"network_id":"srct/mini","payer":"{ADDR20}","payer_bls":"zz","payee":"{ADDR20}","payee_bls":"zz","arbitrator":"zz","amount_sat":{MAX},"nonce":0}}"#
                ),
            ],
        ),
        (
            "/v1/escrow/does-not-exist/release",
            "unknown mode, empty sigs",
            vec![
                r#"{"mode":"explode"}"#.into(),
                r#"{"mode":"arbiter","arbiter_sig_hex":""}"#.into(),
                r#"{"mode":"mutual","mutual_sigs_hex":[]}"#.into(),
            ],
        ),
    ];

    for (path, what, bodies) in cases {
        for body in bodies {
            let (status, text) = post(addr, path, body);
            assert!(
                (400..500).contains(&status),
                "{path} ({what}) must be a client error, got {status}: {text} · body: {body}"
            );
            if !text.trim().is_empty() {
                let json: serde_json::Value = serde_json::from_str(&text)
                    .unwrap_or_else(|_| panic!("{path} body must be JSON: {text}"));
                assert!(
                    json.get("error").is_some(),
                    "{path} JSON body must carry an error code: {text}"
                );
            }
        }
    }
}
