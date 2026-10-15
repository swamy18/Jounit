//! The live conservation surface — `GET /v1/conservation` and the `/metrics`
//! joint-supply gauges (SPEC.md §19.4–§19.5).
//!
//! These pin that the endpoint reports the *same* arithmetic `jnt-node verify`
//! runs: the four terms re-add to the joint figure, the deposit-sink term is
//! right after a real matured deposit (the exact number an L2 → L1 exit has to
//! preserve), and `/metrics` exposes an identical joint figure a scraper can
//! alert on. The broken-verdict paths are pinned where they are cheapest to
//! construct honestly: `ConservationReport`'s unit tests in
//! `jnt-node/src/conservation.rs`, and the worker daemon's refusal of a broken
//! report in `jnt-worker/tests/cli_run.rs`.
//!
//! Run with `cargo test -p jnt-node --test conservation_api`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::tx::{OutPoint, Output};
use jnt_core::wallet::Wallet;
use jnt_node::api::{spawn, SharedNode};
use jnt_node::l2::NodeL2;
use serde_json::Value;

const NET: &str = "jounit/mini";

// ---------------------------------------------------------------------------
// Harness — the `api.rs` test harness, with the L2 view injectable so a test
// can serve a replayed view over a mined chain rather than a fresh one.
// ---------------------------------------------------------------------------

struct Node {
    addr: SocketAddr,
}

/// Start a server on an ephemeral loopback port over the given chain and L2 view.
fn start(chain: Chain, l2: NodeL2) -> Node {
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn(shared, peers, "127.0.0.1:0".parse().unwrap(), None)
        .expect("the API must bind its loopback socket");
    Node { addr }
}

/// A raw GET over a fresh connection; returns `(status, body)`.
fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut buf = String::new();
    s.read_to_string(&mut buf).expect("read");
    let status: u16 = buf
        .split_whitespace()
        .nth(1)
        .expect("status line")
        .parse()
        .expect("status code");
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).expect("response is JSON")
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "conservation-api").unwrap()
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

/// A chain of `n` blocks paying their coinbase to `miner`, at exactly the mini
/// target spacing so difficulty stays pinned at 1 and mining is cheap.
fn mine_to(params: &NetworkParams, miner: &jnt_core::hash::Address, n: u64) -> Chain {
    let mut chain = Chain::new(params.clone()).unwrap();
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(*miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    chain
}

fn mine_one(chain: &mut Chain, to: jnt_core::hash::Address) {
    let h = chain.height() + 1;
    let b = chain.mine_block(to, vec![], ts(h)).unwrap();
    chain.submit(b).unwrap();
}

#[test]
fn the_endpoint_reports_terms_that_re_add_and_match_status() {
    let params = NetworkParams::mini();
    let miner = wallet(1).address().unwrap();
    let chain = mine_to(&params, &miner, 3);
    let escrow = NodeL2::fresh(&params).genesis().escrow_total_sat;
    let node = start(chain, NodeL2::fresh(&params));

    let (status, body) = get(node.addr, "/v1/conservation");
    assert_eq!(status, 200, "the endpoint must serve: {body}");
    let v = json(&body);
    assert_eq!(v["network_id"], NET);
    assert_eq!(v["height"], 3);
    assert_eq!(v["ok"], true, "a healthy node must report ok: {body}");
    assert_eq!(v["l2_closed"], true, "{body}");
    assert_eq!(v["l2_funding_ok"], true, "{body}");

    let l1 = v["l1_live_sat"].as_u64().unwrap();
    let l2 = v["l2_held_sat"].as_u64().unwrap();
    let sink = v["sink_held_sat"].as_u64().unwrap();
    let joint = v["joint_sat"].as_u64().unwrap();
    let bound = v["joint_bound_sat"].as_u64().unwrap();
    let l1_bound = v["l1_bound_sat"].as_u64().unwrap();
    let ceiling = v["escrow_ceiling_sat"].as_u64().unwrap();
    assert_eq!(
        joint,
        l1 + l2 - sink,
        "the terms must re-add to the joint figure: {body}"
    );
    // The joint bound is the issuance integral at the tip plus L2's escrow
    // ceiling, and it is the whole verdict — the stock cap is gone
    // (Decision 18) and is not reported at all.
    assert_eq!(
        bound,
        l1_bound + ceiling,
        "the joint bound must be the two authorities added: {body}"
    );
    // Net supply (Decision 18 §4.5): gross issuance minus everything usage
    // removed — the dilution holders experience, served on this endpoint.
    let issued = v["l1_issued_sat"].as_u64().unwrap();
    let removed = v["l1_removed_sat"].as_u64().unwrap();
    let net = v["l1_net_sat"].as_u64().unwrap();
    assert_eq!(issued, l1_bound, "gross issuance is the integral: {body}");
    assert_eq!(
        net,
        issued - removed,
        "net is issuance minus removal: {body}"
    );
    assert_eq!(
        l1_bound,
        jnt_core::supply::cumulative_issuance_sat(&params, 3),
        "L1's bound must be the same integral the chain mints against: {body}"
    );
    assert_eq!(ceiling, params.escrow_ceiling_sat, "{body}");
    assert!(joint <= bound, "a healthy node is inside the bound: {body}");
    assert_eq!(
        l2, escrow,
        "a fresh view holds exactly the genesis escrow: {body}"
    );
    assert_eq!(sink, 0, "nothing has touched the sink: {body}");

    // The same live supply, cross-checked against `/v1/status`: both routes
    // read the same state under the same lock, so they cannot disagree.
    let (status2, body2) = get(node.addr, "/v1/status");
    assert_eq!(status2, 200);
    assert_eq!(
        l1,
        json(&body2)["total_supply_sat"].as_u64().unwrap(),
        "conservation and status must report the same live L1 supply"
    );
}

#[test]
fn metrics_exports_the_same_joint_figure_and_the_ok_flag() {
    let params = NetworkParams::mini();
    let miner = wallet(2).address().unwrap();
    let chain = mine_to(&params, &miner, 5);
    let node = start(chain, NodeL2::fresh(&params));

    let (status, body) = get(node.addr, "/v1/conservation");
    assert_eq!(status, 200);
    let joint = json(&body)["joint_sat"].as_u64().unwrap();

    let (status, metrics) = get(node.addr, "/metrics");
    assert_eq!(status, 200);
    assert!(
        metrics.contains(&format!(
            "jounit_joint_supply_sat{{network=\"{NET}\"}} {joint}"
        )),
        "the gauge must carry the endpoint's own figure:\n{metrics}"
    );
    assert!(
        metrics.contains(&format!("jounit_conservation_ok{{network=\"{NET}\"}} 1")),
        "a healthy node must export ok=1:\n{metrics}"
    );
}

#[test]
fn the_sink_term_is_reported_after_a_real_matured_deposit() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let depositor = wallet(7);
    let depositor_addr = depositor.address().unwrap();
    // Mature the first coinbase (mini maturity is 10 blocks).
    for _ in 0..11 {
        mine_one(&mut chain, depositor_addr);
    }

    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = jnt_core::supply::block_reward_sat(chain.params(), 1);
    let gas = 16_000 + 1_000 + 250 * 2;
    let fee = chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000);
    let to_sink = 3 * SAT_PER_JNT;
    let deposit = depositor
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: params.l2_deposit_sink(),
                },
                Output {
                    value: reward - to_sink - fee,
                    address: depositor_addr,
                },
            ],
            fee,
        )
        .unwrap();
    let block = {
        let h = chain.height() + 1;
        chain
            .mine_block(depositor_addr, vec![deposit], ts(h))
            .unwrap()
    };
    chain.submit(block).unwrap();

    // Mature it: depth >= finality_depth (mini: 20) so L2 credits it.
    for _ in 0..params.finality_depth + 1 {
        mine_one(&mut chain, depositor_addr);
    }

    let view = NodeL2::replay_from(&chain, &params);
    assert_eq!(
        view.state().balance(&depositor_addr),
        to_sink,
        "the deposit must actually be credited for this test to mean anything"
    );
    let escrow = view.genesis().escrow_total_sat;
    let node = start(chain, view);

    let (status, body) = get(node.addr, "/v1/conservation");
    assert_eq!(status, 200, "{body}");
    let v = json(&body);
    assert_eq!(v["ok"], true, "{body}");
    assert_eq!(v["l2_closed"], true, "{body}");
    assert_eq!(v["l2_funding_ok"], true, "{body}");

    let l1 = v["l1_live_sat"].as_u64().unwrap();
    let l2 = v["l2_held_sat"].as_u64().unwrap();
    let sink = v["sink_held_sat"].as_u64().unwrap();
    let joint = v["joint_sat"].as_u64().unwrap();

    // The sink term over the API: the deposit is counted on both sides — an
    // unspendable L1 output and its credited L2 twin — so the joint subtracts
    // it exactly once. This is the number a release rule has to reduce.
    assert_eq!(sink, to_sink, "the sink holds the deposited value: {body}");
    assert_eq!(
        l2,
        escrow + to_sink,
        "L2 holds escrow plus the twin: {body}"
    );
    assert_eq!(joint, l1 + l2 - sink, "the terms must re-add: {body}");
}
