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
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
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
