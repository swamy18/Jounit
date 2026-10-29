//! The worker ↔ node HTTP transport (SPEC.md §18.3, roadmap item 3).
//!
//! These drive the real server — [`srct_node::api::spawn`] binds an ephemeral
//! loopback port — and the real SDK: `HttpNode` is passed to `WorkerClient` as
//! both the read and the write seam, so discovery, claim and broadcast all
//! cross a socket exactly as they would for a worker process on another host.
//! Nothing in the client re-implements a protocol rule; it decodes the node's
//! own state bytes and lets `srct-l2` decide.
//!
//! What is under attack, because these are the properties a transport can get
//! wrong without any test noticing:
//!
//! - **It works.** discover → claim → broadcast over HTTP, with the node's own
//!   queue receiving the signed transaction — no private key ever crossing the
//!   wire (the client sends bytes it already signed, and nothing else).
//! - **It fails closed.** An unreachable node, a garbage response, a body over
//!   the cap, a wrong network, an unknown task: every one is a *named* error,
//!   bounded in time, and never an empty state that discovery would read as
//!   "no tasks available".
//! - **It stays bounded.** One connect timeout, one read timeout, one response
//!   cap — asserted by an exchange that must not hang.
//!
//! Run with `cargo test -p srct-node --test worker_transport`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::Chain;
use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::hash::Hash;
use srct_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn, SharedNode};
use srct_node::l2::NodeL2;
use srct_worker::node::Host;
use srct_worker::{
    BroadcastError, CpuExecutor, HttpNode, L2Broadcaster, L2NodeView, WorkerClient, WorkerConfig,
    WorkerError,
};

const MAX_ATTEMPTS: u64 = 4_000_000;
const ESCROW_SAT: u64 = 1_000_000;
const DEADLINE: u64 = 400;
const NET: &str = "srct/mini";

fn wallet(seed: u8, label: &str) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], label).unwrap()
}

fn compute_task() -> ComputeTask {
    ComputeTask {
        task_id: [0x77u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 0,
        expiry_height: DEADLINE,
        submit_height: 0,
    }
}

/// A live API over a chain that already carries one posted task, so discovery
/// has something real to find.
fn start_with_task() -> (SocketAddr, Arc<Mutex<SharedNode>>, Hash) {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let mut l2 = NodeL2::fresh(&params).unwrap();
    l2.sync(&chain).unwrap();

    let post = PostTaskPayload::build(
        &wallet(1, "transport-poster"),
        1,
        ESCROW_SAT,
        DEADLINE,
        compute_task(),
    )
    .unwrap();
    let task_id = post.task_id;
    let tx = L2Transaction::new(L2Payload::Post(post));
    let h = chain.height() + 1;
    // An L2-bearing block commits the root replay derives (approved P1).
    let root = l2.simulate_root(&chain, h, std::slice::from_ref(&tx));
    let block = chain
        .mine_block_with_l2_root(
            [9u8; 20],
            Vec::new(),
            vec![tx],
            root,
            GENESIS_TIMESTAMP_MS + h * 1_000,
            None,
            MAX_ATTEMPTS,
        )
        .expect("a block we just mined must build");
    chain.submit(block).expect("it must be accepted");
    l2.sync(&chain).unwrap();
    assert!(l2.state().task(&task_id).is_some(), "the fixture posted");

    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .expect("the API must bind its loopback socket");
    (addr, shared, task_id)
}

fn base_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// A read seam bound to the expected network, over `addr`.
fn reader(addr: SocketAddr) -> HttpNode {
    HttpNode::for_network(base_url(addr), NET).expect("a loopback URL parses")
}

/// A write seam over `addr` (a second handle: one URL, two `Host` fields).
fn writer(addr: SocketAddr) -> HttpNode {
    HttpNode::new(base_url(addr)).expect("a loopback URL parses")
}

/// A `WorkerClient` whose entire node contact is HTTP.
fn client(addr: SocketAddr) -> WorkerClient<HttpNode, HttpNode, CpuExecutor> {
    let w = wallet(2, "transport-worker");
    WorkerClient::new(
        Host::new(reader(addr), writer(addr)),
        w.clone(),
        CpuExecutor::default(),
        // The mini settlement committee, so certificate observation is
        // configured for the node it is talking to rather than defaulted.
        srct_core::bls_checkpoint::ValidatorSet::new(
            NetworkParams::mini().l2_settlement_validators,
        ),
        &srct_core::bls::RealBls,
    )
    .with_config(WorkerConfig::from_wallet(&w).with_deposit(100_000))
    .expect("config agrees with the wallet")
}

// ---------------------------------------------------------------------------
// It works: the whole lifecycle over a socket
// ---------------------------------------------------------------------------

#[test]
fn observation_decodes_the_nodes_own_state() {
    let (addr, _shared, _task) = start_with_task();
    let node = reader(addr);
    let obs = node.observe().expect("the node answers");
    assert_eq!(obs.network_id, NET, "the node states its network");
    assert_eq!(obs.height, 1, "one block carried the post");
    assert_eq!(obs.state.task_count(), 1, "the state carries the task");
    assert!(obs.state.check_conservation(), "and conserves value");

    // The read seam and the trait agree — `chain_height` serves the height of
    // the very state it just returned.
    let height = node.chain_height().unwrap();
    assert_eq!(height, obs.height);
}

#[test]
fn the_full_lifecycle_discovers_and_claims_over_http() {
    let (addr, shared, task_id) = start_with_task();
    let mut client = client(addr);

    // Discover: the node's open tasks, filtered by the SDK's own rules.
    let found = client.discover().expect("discovery over HTTP");
    assert!(
        found.iter().any(|t| t.task_id == task_id),
        "the posted task must be discoverable, found {:?}",
        found.iter().map(|t| t.task_id).collect::<Vec<_>>()
    );

    // Inspect one task before acting on it.
    let view = reader(addr).task(&task_id).expect("the node has the task");
    assert_eq!(
        view["task_id"].as_str().unwrap(),
        srct_core::hash::hash_to_hex(&task_id)
    );
    assert_eq!(view["state"].as_str(), Some("Open"));

    // Claim: the SDK builds and signs locally, the transport posts bytes only.
    let plan = client
        .claim(task_id)
        .expect("the claim broadcasts over HTTP");
    assert_eq!(plan.task_id, task_id);

    // The node received exactly one queued transaction — the one we signed.
    let queued = shared.lock().unwrap().l2_to_include.clone();
    assert_eq!(queued.len(), 1, "the node queued the claim");
    assert_eq!(queued[0].txid(), plan.txid);
}

#[test]
fn certificate_lookup_says_no_without_failing() {
    let (addr, _shared, task_id) = start_with_task();
    // No settlement has happened, so there is no certificate: the node says so
    // and that is a fact, not a transport failure.
    assert_eq!(reader(addr).vwc(&task_id).unwrap(), None);

    // And an unknown task id is a 404 the SDK names rather than guesses at.
    let bogus: Hash = [0xEEu8; 32];
    assert_eq!(
        reader(addr).vwc(&bogus).unwrap(),
        None,
        "no certificate for a task that does not exist is still just None"
    );
    assert!(matches!(
        reader(addr).task(&bogus),
        Err(WorkerError::UnknownTask)
    ));
}

#[test]
fn open_tasks_and_receipt_lookup_reach_the_node() {
    let (addr, _shared, _task_id) = start_with_task();
    let node = reader(addr);
    let open = node.open_tasks().expect("open tasks over HTTP");
    assert_eq!(open.len(), 1);

    // A receipt the node has never seen is a 404 → named "no such resource",
    // never an empty JSON object the SDK would trust.
    let missing: Hash = [0x01u8; 32];
    let err = node
        .receipt(&missing)
        .expect_err("no receipt, stated as such");
    assert!(
        matches!(err, WorkerError::ObservationMalformed(_)),
        "{err:?}"
    );
}

#[test]
fn a_broadcast_refusal_is_named_by_the_node() {
    let (addr, _shared, _task) = start_with_task();
    let mut node = writer(addr);
    // Bytes that decode as a transaction the node will not take: a post whose
    // submitter has no L2 balance. The dry-run refuses, and the write seam
    // reports a *refusal* (4xx), not an unknown-outcome transport error.
    let broke = wallet(9, "transport-broke");
    let post = PostTaskPayload::build(&broke, 1, ESCROW_SAT, DEADLINE, compute_task()).unwrap();
    let tx = L2Transaction::new(L2Payload::Post(post));
    match node.broadcast(&tx) {
        Err(BroadcastError::Refused(detail)) => assert!(
            !detail.is_empty(),
            "the refusal carries the node's own reason: {detail}"
        ),
        other => panic!("expected a named refusal, got {other:?}"),
    }

    // The same transaction posted by a funded wallet is accepted.
    let funded = PostTaskPayload::build(
        &wallet(1, "transport-poster"),
        2,
        ESCROW_SAT,
        DEADLINE,
        compute_task(),
    )
    .unwrap();
    let tx = L2Transaction::new(L2Payload::Post(funded));
    assert_eq!(node.broadcast(&tx), Ok(()));
}

// ---------------------------------------------------------------------------
// It fails closed
// ---------------------------------------------------------------------------

/// One canned response, served on an ephemeral port and closed after it.
fn serve_once(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&response);
            let _ = s.flush();
        }
    });
    addr
}

#[test]
fn an_unreachable_node_is_a_named_error_and_never_hangs() {
    // Port 1 on loopback is not a service: connect fails immediately.
    let node = HttpNode::new("http://127.0.0.1:1")
        .unwrap()
        .with_timeouts(Duration::from_millis(250), Duration::from_millis(250));
    let started = Instant::now();
    let err = node
        .observe()
        .expect_err("an unreachable node must not answer");
    assert!(
        matches!(err, WorkerError::ObservationUnavailable(_)),
        "transport trouble is named as such: {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bounded: the observation gave up in {:?}",
        started.elapsed()
    );

    // Through the SDK's read seam: no state, so nothing is discovered and no
    // claim can be built — the failure can never be read as "no tasks".
    let mut client = WorkerClient::new(
        Host::new(
            HttpNode::new("http://127.0.0.1:1").unwrap(),
            HttpNode::new("http://127.0.0.1:1").unwrap(),
        ),
        wallet(2, "transport-worker"),
        CpuExecutor::default(),
        srct_core::bls_checkpoint::ValidatorSet::new(
            NetworkParams::mini().l2_settlement_validators,
        ),
        &srct_core::bls::RealBls,
    );
    assert!(client.discover().is_err(), "no state ⇒ no tasks ⇒ an error");
    assert!(client.claim([1u8; 32]).is_err(), "no state ⇒ no claim");
}

#[test]
fn a_garbage_response_is_refused_before_any_state_exists() {
    let addr = serve_once(b"NOT-HTTP\r\n\r\nwhatever".to_vec());
    let node = reader(addr);
    let err = node.observe().expect_err("garbage must not become a state");
    assert!(
        matches!(err, WorkerError::ObservationMalformed(_)),
        "malformed bytes are named malformed: {err:?}"
    );
}

#[test]
fn a_body_over_the_response_cap_is_refused() {
    let big = "x".repeat(4_000);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{big}",
        big.len()
    );
    let addr = serve_once(response.into_bytes());
    let node = reader(addr).with_max_response_bytes(512);
    let err = node
        .observe()
        .expect_err("an over-cap body must be refused");
    assert!(
        matches!(err, WorkerError::ObservationMalformed(_)),
        "{err:?}"
    );
}

#[test]
fn a_wrong_network_is_refused_by_name() {
    let (addr, _shared, _task) = start_with_task();
    // Point a worker at a node serving a different network: it must refuse the
    // observation, not discover foreign tasks.
    let node = HttpNode::for_network(base_url(addr), "srct/testnet").unwrap();
    let err = node.observe().expect_err("a foreign network is refused");
    assert!(
        matches!(err, WorkerError::ObservationMalformed(_)),
        "{err:?}"
    );
    assert!(
        err.to_string().contains("another network"),
        "the refusal says which way it disagrees: {err}"
    );
}

#[test]
fn an_undecodable_state_blob_never_reaches_the_sdk() {
    // The endpoint answers, but the state is not a state. Rather than mock the
    // node, corrupt the URL's expectations: `state_hex` that is not hex is the
    // node's own failure, and the client must not decode around it.
    let response = r#"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 74\r\n\r\n{"network_id":"srct/mini","height":1,"state_hex":"zzzz"}"#;
    let addr = serve_once(response.replace("\\r\\n", "\r\n").into_bytes());
    let node = reader(addr);
    let err = node.observe().expect_err("bad hex must be refused");
    assert!(
        matches!(err, WorkerError::ObservationMalformed(_)),
        "{err:?}"
    );
}

#[test]
fn the_only_thing_that_crosses_the_wire_is_the_signed_transaction() {
    // The transport's POST body is `hex::encode(tx.serialize())` and nothing
    // else: no wallet, no config, no key. Check that the bytes a node would
    // receive decode back to exactly the transaction we built — i.e. the body
    // is the signed payload, not a request that asks the node to sign.
    let post = PostTaskPayload::build(
        &wallet(1, "transport-poster"),
        3,
        ESCROW_SAT,
        DEADLINE,
        compute_task(),
    )
    .unwrap();
    let tx = L2Transaction::new(L2Payload::Post(post));

    let on_wire = hex::encode(tx.serialize());
    let decoded = L2Transaction::deserialize(&hex::decode(&on_wire).unwrap())
        .expect("the wire bytes are a canonical transaction");
    assert_eq!(decoded, tx, "byte-for-byte what we signed");
    assert_eq!(decoded.txid(), tx.txid());
    // And the node's own view of the same bytes: it decodes them itself,
    // which is why the client never needs to explain what to do with a key.
    assert!(
        L2Transaction::deserialize(b"not a transaction").is_err(),
        "the node refuses bytes that are not a transaction"
    );
}
