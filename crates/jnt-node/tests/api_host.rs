//! Host-header validation across bind shapes (Task 1, SPEC.md §19.2).
//!
//! These drive the real server over raw HTTP: `spawn_with_options` binds the
//! socket (loopback or wildcard, port 0 so tests never race) and each case
//! below sends a hand-built request with the exact `Host` under test. What
//! they pin:
//!
//! - a loopback bind accepts loopback names and rejects everything else,
//!   including a non-loopback IP literal;
//! - a wildcard bind accepts any IP literal (DNS rebinding cannot use one)
//!   but rejects unknown hostnames unless the operator allowlisted them;
//! - a missing or bracket-malformed `Host` is refused without panicking.
//!
//! Run with `cargo test -p jnt-node --test api_host`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jnt_core::chain::Chain;
use jnt_core::params::NetworkParams;
use jnt_node::api::{spawn_with_options, SharedNode};
use jnt_node::l2::NodeL2;

const TOKEN: &str = "host-check-test-token";

/// Start a server on `listen` with `token` and `allowed` hostnames.
fn start(listen: &str, token: Option<&str>, allowed: &[&str]) -> SocketAddr {
    let params = NetworkParams::mini();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(Chain::new(params).unwrap(), l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    spawn_with_options(
        shared,
        peers,
        listen.parse().unwrap(),
        token.map(str::to_owned),
        allowed.iter().map(|s| s.to_string()).collect(),
    )
    .expect("the API must bind its test socket")
}

/// One raw exchange. `host` is the literal `Host` header value, or `None` to
/// send no `Host` header at all.
fn exchange(dial: SocketAddr, host: Option<&str>, token: Option<&str>) -> (u16, String) {
    let mut request = String::from("GET /v1/health HTTP/1.1\r\n");
    if let Some(h) = host {
        request.push_str(&format!("Host: {h}\r\n"));
    }
    if let Some(t) = token {
        request.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");

    let mut stream = TcpStream::connect(dial).expect("connect to the API");
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
    (status, text)
}

#[test]
fn loopback_bind_rejects_a_rebound_hostname() {
    let addr = start("127.0.0.1:0", None, &[]);
    let (status, _) = exchange(addr, Some("evil.example"), None);
    assert_eq!(status, 403, "a rebound name must not reach loopback");
}

#[test]
fn loopback_bind_rejects_a_non_loopback_ip_literal() {
    let addr = start("127.0.0.1:0", None, &[]);
    // 203.0.113.7 is documentation space: an IP literal, but not loopback,
    // so a loopback bind must refuse it.
    let (status, _) = exchange(addr, Some("203.0.113.7"), None);
    assert_eq!(status, 403, "only loopback names pass a loopback bind");
}

#[test]
fn loopback_bind_accepts_loopback_names_case_insensitively() {
    let addr = start("127.0.0.1:0", None, &[]);
    for host in ["localhost", "LOCALHOST", "127.0.0.1", "[::1]", "::1"] {
        let (status, _) = exchange(addr, Some(host), None);
        assert_eq!(status, 200, "loopback name {host} must pass");
    }
}

#[test]
fn wildcard_bind_accepts_any_ip_literal() {
    let bound = start("0.0.0.0:0", Some(TOKEN), &[]);
    let dial: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
    let host = format!("203.0.113.7:{}", bound.port());
    let (status, _) = exchange(dial, Some(&host), Some(TOKEN));
    assert_eq!(status, 200, "an IP literal cannot be DNS-rebound");
}

#[test]
fn wildcard_bind_rejects_an_unknown_hostname() {
    let bound = start("0.0.0.0:0", Some(TOKEN), &[]);
    let dial: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
    let (status, _) = exchange(dial, Some("evil.example"), Some(TOKEN));
    assert_eq!(status, 403, "unknown names are refused even with a token");
}

#[test]
fn wildcard_bind_accepts_an_allowlisted_hostname() {
    let bound = start("0.0.0.0:0", Some(TOKEN), &["api.example"]);
    let dial: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
    let (status, _) = exchange(dial, Some("API.EXAMPLE"), Some(TOKEN));
    assert_eq!(status, 200, "allowlist comparison must be case-insensitive");
}

#[test]
fn missing_host_header_is_rejected() {
    let addr = start("127.0.0.1:0", None, &[]);
    let (status, _) = exchange(addr, None, None);
    assert_eq!(status, 403, "no Host header means no decision to make");
}

#[test]
fn bracket_malformed_host_is_rejected_without_panicking() {
    let addr = start("127.0.0.1:0", None, &[]);
    for host in ["[::1", "[::1]evil", "[]", "["] {
        let (status, _) = exchange(addr, Some(host), None);
        assert_eq!(status, 403, "malformed Host {host} must be refused");
    }
}
