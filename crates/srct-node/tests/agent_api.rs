//! The HTTP surface for agent authority and credit (SPEC.md §21, §22).
//!
//! Two things are pinned here. First, that the read endpoints show what the
//! chain actually holds: a published grant and an open credit position, with
//! their counters, and a `404` for an id nobody published. Second, that the
//! whole path works end to end — a grant is signed by the owner, carried in a
//! block, replayed by the node, and then visible over HTTP.
//!
//! The rules themselves are pinned where they live
//! (`crates/srct-l2/tests/policy_flow.rs` and `credit_flow.rs`); this file is
//! about the node's view of them.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::chain::Chain;
use srct_core::hash::address_to_hex;
use srct_core::l2::{CreditOpenPayload, L2Payload, L2Transaction, PolicyPayload};
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_node::api::{spawn_with_options, SharedNode};
use srct_node::l2::NodeL2;

use serde_json::{json, Value};

const MAX_ATTEMPTS: u64 = 4_000_000;

struct Node {
    addr: SocketAddr,
    shared: Arc<Mutex<SharedNode>>,
}

fn start() -> Node {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let l2 = NodeL2::fresh(&params).unwrap();
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let addr = spawn_with_options(
        Arc::clone(&shared),
        peers,
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
        Vec::new(),
    )
    .expect("the test server starts");
    Node { addr, shared }
}

/// A raw HTTP exchange over a fresh connection.
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

/// The wallet the mini genesis funds: its L2 account holds one token, so it
/// can pay the fee of the transactions this file publishes.
fn operator(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-genesis-operator").unwrap()
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Mine a block carrying `txs`, with the L2 state root the node computes.
fn mine_with_l2(node: &Node, txs: Vec<L2Transaction>) {
    let mut sh = node.shared.lock().unwrap();
    let height = sh.chain.height() + 1;
    let root = {
        let l2 = &sh.l2;
        l2.simulate_root(&sh.chain, height, &txs)
    };
    let block = sh
        .chain
        .mine_block_with_l2_root(
            [0xEEu8; 20],
            Vec::new(),
            txs,
            root,
            ts(height),
            None,
            MAX_ATTEMPTS,
        )
        .expect("the block builds");
    sh.chain.submit(block).expect("the block is accepted");
    {
        let shared = &mut *sh;
        let chain = &shared.chain;
        let l2 = &mut shared.l2;
        l2.sync(chain).expect("the node replays its own block");
    }
}

#[test]
fn a_published_grant_is_visible_over_http() {
    let node = start();
    let owner = operator(1);
    let agent = operator(2);
    let recipient = operator(3);

    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/mini".to_string(),
        agent_id: derive_agent_id("srct/mini", AgentRole::Machine, &owner.address().unwrap()),
        owner: owner.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 10_000,
        window_blocks: 100,
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![recipient.address().unwrap()],
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: None,
    };
    let payload =
        PolicyPayload::build_from_policy(&owner, &policy, agent.address().unwrap()).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));

    // Broadcast it, then put it in a block and let the node replay.
    let (status, body) = post(
        &node,
        "/v1/l2/broadcast",
        &json!({ "l2_tx_hex": hex::encode(tx.serialize()) }),
    );
    assert_eq!(status, 200, "the transaction is accepted: {body}");
    mine_with_l2(&node, vec![tx]);

    let (status, body) = get(&node, "/v1/policies");
    assert_eq!(status, 200);
    assert_eq!(body["count"], 1, "the grant is in the chain: {body}");
    let published = &body["policies"][0];
    assert_eq!(
        published["owner"],
        address_to_hex(&owner.address().unwrap())
    );
    assert_eq!(
        published["spender"],
        address_to_hex(&agent.address().unwrap())
    );
    assert_eq!(published["per_tx_max_sat"], 10_000);
    assert_eq!(published["cumulative_max_sat"], 100_000);
    assert_eq!(published["revoked"], false);
    assert_eq!(published["last_nonce"], 0);
    assert_eq!(
        published["allowed_recipients"],
        json!([address_to_hex(&recipient.address().unwrap())])
    );

    // And by agent id.
    let agent_id = policy.agent_id;
    let (status, body) = get(&node, &format!("/v1/policies/{}", hex::encode(agent_id)));
    assert_eq!(status, 200);
    assert_eq!(body["policy_hash"], published["policy_hash"]);

    // An agent nobody published for is a 404, not an empty object.
    let (status, _) = get(
        &node,
        &format!("/v1/policies/{}", hex::encode([0x99u8; 20])),
    );
    assert_eq!(status, 404);
}

#[test]
fn an_open_credit_position_is_visible_over_http() {
    let node = start();
    let lender = operator(1);
    let borrower = operator(2);

    let payload = CreditOpenPayload::build(
        &lender,
        borrower.address().unwrap(),
        1_000_000,
        1_000_000,
        100,
        100,
        1_000_000,
        1,
    )
    .unwrap();
    let position_id = payload.derived_position_id();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));

    let (status, body) = post(
        &node,
        "/v1/l2/broadcast",
        &json!({ "l2_tx_hex": hex::encode(tx.serialize()) }),
    );
    assert_eq!(status, 200, "the transaction is accepted: {body}");
    mine_with_l2(&node, vec![tx]);

    let (status, body) = get(&node, "/v1/credit/positions");
    assert_eq!(status, 200);
    assert_eq!(body["count"], 1, "the position is in the chain: {body}");
    let position = &body["positions"][0];
    assert_eq!(position["position_id"], hex::encode(position_id));
    assert_eq!(
        position["lender"],
        address_to_hex(&lender.address().unwrap())
    );
    assert_eq!(
        position["borrower"],
        address_to_hex(&borrower.address().unwrap())
    );
    assert_eq!(position["principal_sat"], 1_000_000);
    assert_eq!(position["outstanding_sat"], 1_000_000);
    assert_eq!(position["collateral_sat"], 1_000_000);
    assert_eq!(position["state"], "Open");

    let (status, body) = get(
        &node,
        &format!("/v1/credit/positions/{}", hex::encode(position_id)),
    );
    assert_eq!(status, 200);
    assert_eq!(body["position_id"], hex::encode(position_id));

    let (status, _) = get(
        &node,
        &format!("/v1/credit/positions/{}", hex::encode([0x77u8; 32])),
    );
    assert_eq!(status, 404);
}

#[test]
fn a_restart_rebuilds_the_same_authority_state() {
    // A restart does not restore a ledger: the Layer-2 state is *derived* from
    // the canonical blocks, so what a restart has to reproduce is the replay.
    // This test publishes a grant in a block and then rebuilds the state from
    // the chain, the way a node that restarts would.
    let node = start();
    let owner = operator(1);
    let agent = operator(2);
    let recipient = operator(3);

    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/mini".to_string(),
        agent_id: derive_agent_id("srct/mini", AgentRole::Machine, &owner.address().unwrap()),
        owner: owner.address().unwrap(),
        role: AgentRole::Machine,
        per_tx_max_sat: 10_000,
        window_blocks: 100,
        cumulative_max_sat: 100_000,
        allowed_recipients: vec![recipient.address().unwrap()],
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: None,
    };
    let payload =
        PolicyPayload::build_from_policy(&owner, &policy, agent.address().unwrap()).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    mine_with_l2(&node, vec![tx]);

    // What the node holds now.
    let live = {
        let sh = node.shared.lock().unwrap();
        let l2 = sh.l2.state();
        (
            l2.committed_root(),
            l2.policies().len(),
            l2.policies()[0].spender,
        )
    };

    // What a restart would rebuild from the same chain.
    let rebuilt = {
        let sh = node.shared.lock().unwrap();
        let fresh = NodeL2::replay_from(&sh.chain, &NetworkParams::mini()).unwrap();
        let state = fresh.state();
        (
            state.committed_root(),
            state.policies().len(),
            state.policies()[0].spender,
        )
    };
    assert_eq!(
        live, rebuilt,
        "a restart must rebuild exactly the state the node was holding"
    );
}

#[test]
fn the_fee_schedule_lists_the_new_transaction_types() {
    let node = start();
    let (status, body) = get(&node, "/v1/fees");
    assert_eq!(status, 200);
    let names: Vec<&str> = body["l2_fee_schedule"]
        .as_array()
        .expect("the L2 fee list is an array")
        .iter()
        .filter_map(|v| v["tx"].as_str())
        .collect();
    for expected in [
        "TxPolicy",
        "TxPolicyRevoke",
        "TxAgentSpend",
        "TxCreditOpen",
        "TxCreditCollateral",
        "TxCreditRepay",
        "TxCreditDefault",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} must be in the fee schedule: {names:?}"
        );
    }
}
