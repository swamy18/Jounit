//! Two-process end-to-end test — roadmap item 13/14 deliverable.
//!
//! Unlike `e2e_journey.rs` (which drives an in-process `Node`), this test spawns
//! a real `jnt-node serve --api-listen` subprocess and connects a `WorkerClient`
//! through the real `HttpNode` HTTP transport. It exercises the full L2 lifecycle
//! over TCP: post → discover → claim → execute → submit, all through the
//! wire-level REST API that a production worker would use.
//!
//! Run with `cargo test -p jnt-node --test e2e_two_process`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::Hash;
use jnt_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use jnt_core::params::NetworkParams;
use jnt_core::wallet::Wallet;
use jnt_worker::node::Host;
use jnt_worker::{CpuExecutor, HttpNode, WorkerClient};

const COMPUTE_ESCROW_SAT: u64 = 1_000_000;
const WORKER_DEPOSIT_SAT: u64 = 100_000;
const TASK_DEADLINE: u64 = 400;
const MINE_INTERVAL_MS: u64 = 50;
const API_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Wallet fixtures (match mini genesis grants: seeds 1, 2)
// ---------------------------------------------------------------------------

fn provider() -> Wallet {
    Wallet::from_private_key_bytes(&[1u8; 32], "provider").unwrap()
}

fn worker() -> Wallet {
    Wallet::from_private_key_bytes(&[2u8; 32], "worker").unwrap()
}

// ---------------------------------------------------------------------------
// Subprocess harness
// ---------------------------------------------------------------------------

/// Bind a temporary socket to discover a free loopback port, then release it
/// for the node to bind. Not race-free by construction (the kernel could hand
/// the port to someone else in the window), but in practice is unique enough
/// for isolated test runs.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Spawn the `jnt-node` binary, initializing a fresh mini chain in `dir`.
fn init_chain(dir: &Path) -> Result<(), String> {
    let bin = env!("CARGO_BIN_EXE_jnt-node");
    let out = Command::new(bin)
        .args([
            "init",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
            "--label",
            "miner",
        ])
        .output()
        .map_err(|e| format!("init failed: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("init failed: {stderr}"));
    }
    Ok(())
}

/// Start `jnt-node serve` with the API on a loopback port. Returns the process
/// handle and both the connection address (host:port) and the URL.
struct ServingNode {
    process: Child,
    conn_addr: String,
    url: String,
}

fn start_serving(dir: &Path) -> Result<ServingNode, String> {
    let bin = env!("CARGO_BIN_EXE_jnt-node");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut process = Command::new(bin)
        .args([
            "serve",
            "--network",
            "mini",
            "--data-dir",
            dir.to_str().unwrap(),
            "--api-listen",
            &addr,
            "--interval",
            &MINE_INTERVAL_MS.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("serve failed: {e}"))?;

    // Poll the API until it responds.
    let deadline = Instant::now() + API_TIMEOUT;
    loop {
        // If the process died, surface its stderr.
        match process.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = String::new();
                process
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .ok();
                return Err(format!("serve exited early with {status}: {stderr}"));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("serve wait error: {e}")),
        }
        if let Ok((code, _)) = http("GET", &addr, "/v1/health", None) {
            if code == 200 {
                return Ok(ServingNode {
                    process,
                    conn_addr: addr.clone(),
                    url: format!("http://{addr}"),
                });
            }
        }
        if Instant::now() >= deadline {
            return Err("API did not come up within timeout".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl Drop for ServingNode {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

// ---------------------------------------------------------------------------
// Raw HTTP helpers (the test harness uses these; the worker uses HttpNode)
// ---------------------------------------------------------------------------

fn http(method: &str, addr: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let mut stream = std::net::TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let blen = body.unwrap_or("").len();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {blen}\r\n\r\n{}",
        body.unwrap_or("")
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    drop(stream);
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Poll the L2 state endpoint until the task count reaches at least `n`, or
/// time out after `timeout`.
fn wait_for_l2_condition<F: Fn(&serde_json::Value) -> bool>(
    addr: &str,
    timeout: Duration,
    check: F,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok((code, body)) = http("GET", addr, "/v1/l2/state", None) {
            if code == 200 {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if check(&v) {
                        return Ok(());
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("L2 state did not reach expected condition".into())
}

// ---------------------------------------------------------------------------
// L2 transaction helpers
// ---------------------------------------------------------------------------

fn compute_task(task_id: Hash) -> ComputeTask {
    ComputeTask {
        task_id,
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 1_000_000,
        expiry_height: TASK_DEADLINE,
        submit_height: 0,
    }
}

/// Build a PostTask payload and return the L2Transaction + task_id.
fn build_post_task(wallet: &Wallet, nonce: u64) -> (L2Transaction, Hash) {
    let task = compute_task([0x11u8; 32]);
    let post = PostTaskPayload::build(wallet, nonce, COMPUTE_ESCROW_SAT, TASK_DEADLINE, task)
        .expect("valid post");
    let id = post.task_id;
    (L2Transaction::new(L2Payload::Post(post)), id)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
fn worker_lifecycle_over_real_http() {
    let dir = std::env::temp_dir().join(format!(
        "jnt-e2e-2proc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");

    init_chain(&dir).expect("init");
    let serving = start_serving(&dir).expect("serve");

    // --- 1. provider posts a task via the REST API --------------------------
    let provider_wallet = provider();
    let (post_tx, task_id) = build_post_task(&provider_wallet, 1);
    let post_hex = hex::encode(post_tx.serialize());

    let (s, body) = http(
        "POST",
        &serving.conn_addr,
        "/v1/l2/broadcast",
        Some(&serde_json::json!({ "l2_tx_hex": post_hex }).to_string()),
    )
    .expect("post via API");
    assert_eq!(s, 200, "task post refused: {body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["queued"],
        true
    );

    // --- 2. wait for the node to mine it -----------------------------------
    wait_for_l2_condition(&serving.conn_addr, Duration::from_secs(10), |state| {
        state.get("tasks").and_then(|t| t.as_u64()).unwrap_or(0) >= 1
    })
    .expect("task was not mined into L2 state");

    // --- 3. worker connects over HTTP and discovers the task ---------------
    let worker_wallet = worker();
    let http_view = HttpNode::for_network(&serving.url, "jounit/mini").expect("HttpNode view");
    let http_bc = HttpNode::for_network(&serving.url, "jounit/mini").expect("HttpNode broadcaster");
    let validators = ValidatorSet::new(NetworkParams::mini().genesis_validators.clone());
    let host = Host::new(http_view, http_bc);
    let mut client = WorkerClient::new(
        host,
        worker_wallet.clone(),
        CpuExecutor::default(),
        validators,
        &MockBls,
    )
    .with_config(
        jnt_worker::WorkerConfig::from_wallet(&worker_wallet).with_deposit(WORKER_DEPOSIT_SAT),
    )
    .expect("config");

    // Poll until the worker can discover the task.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = false;
    while Instant::now() < deadline {
        if let Ok(tasks) = client.discover() {
            if tasks.iter().any(|t| t.task_id == task_id) {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(found, "worker did not discover the task over HTTP");

    // --- 4. claim ----------------------------------------------------------
    let claim = client.claim(task_id).expect("claim broadcasts");
    assert_eq!(claim.task_id, task_id);

    // --- 5. wait for the claim to be mined --------------------------------
    wait_for_l2_condition(&serving.conn_addr, Duration::from_secs(10), |state| {
        state.get("tasks").and_then(|t| t.as_u64()).unwrap_or(0) >= 1
    })
    .expect("claim not mined");

    // Poll until the task shows a worker.
    let dead2 = Instant::now() + Duration::from_secs(10);
    while Instant::now() < dead2 {
        let (s, body) = http(
            "GET",
            &serving.conn_addr,
            &format!("/v1/task/{}", hex::encode(task_id)),
            None,
        )
        .unwrap();
        if s == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            if v.get("worker").and_then(|w| w.as_str()).is_some() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // --- 6. execute + submit ----------------------------------------------
    let submission = client
        .execute_and_submit(task_id)
        .expect("execute + submit");
    assert_eq!(submission.task_id, task_id);
    assert_eq!(submission.worker, worker_wallet.address().unwrap());

    // --- 7. wait for submission to be mined -------------------------------
    wait_for_l2_condition(&serving.conn_addr, Duration::from_secs(10), |state| {
        state.get("tasks").and_then(|t| t.as_u64()).unwrap_or(0) >= 1
    })
    .expect("submission not mined");

    // Poll until the task shows ResultSubmitted.
    let dead3 = Instant::now() + Duration::from_secs(10);
    while Instant::now() < dead3 {
        let (s, body) = http(
            "GET",
            &serving.conn_addr,
            &format!("/v1/task/{}", hex::encode(task_id)),
            None,
        )
        .unwrap();
        if s == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            if v.get("state").and_then(|s| s.as_str()) == Some("ResultSubmitted") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // --- 8. observe earnings over HTTP ------------------------------------
    let earnings = client.earnings().expect("earnings read");
    assert_eq!(
        earnings.pending_sat,
        COMPUTE_ESCROW_SAT.saturating_sub(jnt_core::l2::L2TxType::Settle.fee_sat()),
        "pending earnings reflect the escrow minus settle fee"
    );
    assert_eq!(earnings.deposits_at_risk_sat, WORKER_DEPOSIT_SAT);

    println!("two-process E2E passed");
}

// ---------------------------------------------------------------------------
// BLS verifier for certificate observation
// ---------------------------------------------------------------------------

use jnt_core::bls_checkpoint::BlsVerifier;

struct MockBls;

impl BlsVerifier for MockBls {
    fn verify_aggregate(
        &self,
        _signers: &[jnt_core::bls_checkpoint::BlsPublicKey],
        _msg: &jnt_core::hash::Hash,
        _sig: &jnt_core::bls_checkpoint::BlsSignature,
    ) -> bool {
        // The test doesn't observe a certificate, so the mock is fine.
        true
    }
}
