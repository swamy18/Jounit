//! CLI-level tests for the `jnt-worker` binary, focused on the `run` verb.
//!
//! These spawn the real binary through `CARGO_BIN_EXE_jnt-worker`, so they cover
//! argument parsing, the usage text, the transport's failure mode, and — the
//! part that matters most — that no code path renders the private key.
//!
//! They deliberately do **not** test the successful claim/submit path: that
//! needs a live node, and it is already covered end-to-end by
//! `jnt-node/tests/e2e_two_process.rs` and `worker_transport.rs`, which drive a
//! real `WorkerClient` over a real socket.
//!
//! The conservation gate is tested here against a **fake node** (a canned
//! `/v1/conservation` body, 404 for everything else): a report whose joint
//! supply exceeds the cap and a report that is not readable JSON are both
//! refused with a non-zero exit, while a healthy report passes the gate and
//! the daemon moves on to discovery.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_jnt-worker");

/// A per-process temp path, so parallel test binaries cannot collide.
fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("jnt-worker-cli-{}-{name}", std::process::id()))
}

/// Run the binary and return `(exit_code, stdout, stderr)`.
fn exec(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn jnt-worker");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A loopback port nothing is listening on: bind, read the port, drop it.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// A healthy `/v1/conservation` body: 10 + 1000 − 0 re-adds to 1010, well
/// under the 10000 joint bound, both L2 checks true.
const HEALTHY_REPORT: &str = concat!(
    r#"{"ok":true,"l2_closed":true,"l2_funding_ok":true,"#,
    r#""joint_sat":1010,"joint_bound_sat":10000,"headroom_sat":8990,"#,
    r#""l1_live_sat":10,"l2_held_sat":1000,"sink_held_sat":0,"#,
    r#""network_id":"jounit/mini","height":3}"#
);

/// A broken body: the terms re-add (101 + 0 − 0), but joint 101 > bound 100.
const BROKEN_REPORT: &str = concat!(
    r#"{"ok":false,"l2_closed":true,"l2_funding_ok":true,"#,
    r#""joint_sat":101,"joint_bound_sat":100,"headroom_sat":0,"#,
    r#""l1_live_sat":101,"l2_held_sat":0,"sink_held_sat":0,"#,
    r#""network_id":"jounit/mini","height":3}"#
);

/// A fake node: serves the canned conservation body for `/v1/conservation`
/// and 404 for everything else, for a bounded number of connections so the
/// listener thread always ends.
fn fake_node(conservation_body: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let body = conservation_body.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let response = if request.starts_with("GET /v1/conservation ") {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn help_lists_the_run_verb_and_its_required_flag() {
    let (code, out, _) = exec(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("run"), "usage must document `run`:\n{out}");
    assert!(out.contains("--node"), "usage must document --node:\n{out}");
}

#[test]
fn run_without_a_node_url_fails_and_names_the_missing_flag() {
    let wallet = tmp("missing-node.json");
    let (code, _, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--iterations",
        "1",
    ]);
    assert_ne!(code, 0, "a missing --node must fail, not silently succeed");
    assert!(
        err.contains("--node"),
        "the refusal must name the missing flag: {err}"
    );
}

/// Generate a wallet at `wallet` and return its private-key hex — the one
/// secret these tests must never see rendered back.
fn make_wallet(wallet: &PathBuf) -> String {
    let _ = std::fs::remove_file(wallet);
    let (code, _, err) = exec(&[
        "generate",
        "--out-file",
        wallet.to_str().unwrap(),
        "--label",
        "cli-gate",
    ]);
    assert_eq!(code, 0, "generate failed: {err}");
    let raw = std::fs::read_to_string(wallet).expect("wallet file");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("wallet is JSON");
    v["private_key"]
        .as_str()
        .expect("private_key field")
        .to_string()
}

#[test]
fn run_refuses_a_node_whose_joint_supply_exceeds_the_cap() {
    let wallet = tmp("gate-broken.json");
    let secret = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node(BROKEN_REPORT));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    assert_ne!(code, 0, "a node reporting inflation must be refused: {out}");
    assert!(
        err.contains("conservation"),
        "the refusal must name conservation: {err}"
    );
    assert!(
        err.contains("101") && err.contains("100"),
        "the refusal must name the joint figure and the cap: {err}"
    );
    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_refuses_an_unreadable_conservation_answer() {
    let wallet = tmp("gate-garbage.json");
    let _ = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node("this is not json"));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    assert_ne!(
        code, 0,
        "a node answering garbage on the gate endpoint must be refused: {out}"
    );
    assert!(
        err.contains("conservation"),
        "the refusal must name the gate: {err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_passes_the_gate_on_a_healthy_node_and_moves_on_to_discovery() {
    let wallet = tmp("gate-healthy.json");
    let secret = make_wallet(&wallet);
    let url = format!("http://127.0.0.1:{}", fake_node(HEALTHY_REPORT));

    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    // The gate passes and the daemon proceeds: discovery then hits the fake
    // node's 404 for `/v1/l2/state`, which is retryable, so the bounded run
    // still exits cleanly — with the gate's own line visible on stdout.
    assert_eq!(code, 0, "unexpected exit: stdout={out}\nstderr={err}");
    assert!(
        out.contains("conservation  ok"),
        "the gate's pass must be visible to the operator: {out}"
    );
    assert!(
        err.contains("will retry"),
        "the retryable path must be visible: {err}"
    );
    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );
    let _ = std::fs::remove_file(&wallet);
}

#[test]
fn run_against_an_unreachable_node_retries_cleanly_and_never_prints_key_material() {
    let wallet = tmp("cli-run-wallet.json");
    let _ = std::fs::remove_file(&wallet);
    let (code, _, err) = exec(&[
        "generate",
        "--out-file",
        wallet.to_str().unwrap(),
        "--label",
        "cli-test",
    ]);
    assert_eq!(code, 0, "generate failed: {err}");

    // The wallet file's only secret is `private_key`; capture it verbatim.
    let raw = std::fs::read_to_string(&wallet).expect("wallet file");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("wallet is JSON");
    let secret = v["private_key"]
        .as_str()
        .expect("private_key field")
        .to_string();
    assert_eq!(secret.len(), 64, "a 32-byte key is 64 hex chars");

    let url = format!("http://127.0.0.1:{}", closed_port());
    let (code, out, err) = exec(&[
        "run",
        "--from-file",
        wallet.to_str().unwrap(),
        "--node",
        &url,
        "--network",
        "mini",
        "--iterations",
        "1",
    ]);

    // A transient transport failure is retryable, so a bounded run still exits
    // cleanly — and it says so on stderr rather than panicking.
    assert_eq!(code, 0, "unexpected exit: stdout={out}\nstderr={err}");
    assert!(
        err.contains("will retry"),
        "the retryable path must be visible to the operator: {err}"
    );

    assert!(
        !out.contains(&secret) && !err.contains(&secret),
        "the private key must never render; stdout={out}\nstderr={err}"
    );

    let _ = std::fs::remove_file(&wallet);
}
