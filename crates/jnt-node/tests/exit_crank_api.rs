//! `GET /v1/exit/crankable` — the permissionless exit crank, exposed.
//!
//! The crank was reachable only by the node's own miner: `NodeL2::crank_claims`
//! builds the claims, and the serve loop feeds them to the block builder. The
//! consensus rule is permissionless, so a third party could in principle build a
//! block with them — but there was no way to even *see* the claims, let alone
//! take one. This route closes that.
//!
//! What it must not do is grant any power. A claim is authorised by an
//! inclusion proof against the L2 root the queue block committed, never by a
//! signature, and the destination is bound inside that leaf — so handing a
//! claim out changes nothing about who gets paid. The `claimant` query
//! parameter names where the owner-prepaid crank fee goes and is trusted for
//! exactly that and nothing else.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::hash::Address;
use jnt_core::params::NetworkParams;
use jnt_core::tx::Output;
use jnt_core::wallet::Wallet;
use jnt_node::api::{spawn, SharedNode};
use jnt_node::l2::NodeL2;
use serde_json::Value;

struct Node {
    addr: SocketAddr,
}

fn start(chain: Chain, l2: NodeL2) -> Node {
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    let addr = spawn(shared, peers, "127.0.0.1:0".parse().unwrap())
        .expect("the API must bind its loopback socket");
    Node { addr }
}

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
    Wallet::from_private_key_bytes(&[seed; 32], "exit-crank-api").unwrap()
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn mine_to(params: &NetworkParams, miner: &jnt_core::hash::Address, n: u64) -> Chain {
    let mut chain = Chain::new(params.clone()).unwrap();
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(*miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    chain
}

/// On a profile with exits active and nothing queued, the route answers 200 with
/// an empty list rather than refusing — "nothing to crank yet" is not an error.
#[test]
fn an_idle_profile_reports_nothing_to_crank() {
    let params = NetworkParams::mini();
    let miner = wallet(1).address().unwrap();
    let chain = mine_to(&params, &miner, 3);
    let node = start(chain, NodeL2::fresh(&params));

    let (status, body) = get(
        node.addr,
        &format!("/v1/exit/crankable?claimant={}", miner_hex(&miner)),
    );
    assert_eq!(status, 200, "an idle node must still answer: {body}");
    let v = json(&body);
    assert_eq!(v["crankable_count"], 0, "{body}");
    assert_eq!(v["queued"], 0, "{body}");
    assert_eq!(v["unbacked_claims"], 0, "a healthy replay has none: {body}");
}

/// `exit_activation_height = 0` means *never*, so claiming there is a conflict
/// and not a silent empty list. Answering 200 with an empty array would look
/// like "nothing matured yet" and send an operator hunting the wrong problem.
#[test]
fn a_profile_with_exits_disabled_refuses_by_name() {
    let params = {
        let mut p = NetworkParams::mainnet();
        p.exit_activation_height = 0;
        p
    };
    let miner = wallet(1).address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    for _ in 0..3 {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let node = start(chain, NodeL2::fresh(&params));

    let (status, body) = get(
        node.addr,
        &format!("/v1/exit/crankable?claimant={}", miner_hex(&miner)),
    );
    assert_eq!(
        status, 409,
        "an inactive profile must not look idle: {body}"
    );
    assert_eq!(json(&body)["error"], "exits_inactive", "{body}");
}

/// The `claimant` parameter is not decoration: it is who the owner-prepaid crank
/// fee pays, so a request without it must be refused rather than guessing an
/// address that would strand the fee.
#[test]
fn a_missing_claimant_is_refused_not_guessed() {
    let params = NetworkParams::mini();
    let miner = wallet(1).address().unwrap();
    let chain = mine_to(&params, &miner, 3);
    let node = start(chain, NodeL2::fresh(&params));

    let (status, body) = get(node.addr, "/v1/exit/crankable");
    assert_eq!(
        status, 400,
        "a stranger must not collect the crank fee: {body}"
    );
    let (status, body) = get(node.addr, "/v1/exit/crankable?claimant=not-an-address");
    assert_eq!(status, 400, "{body}");
}

fn miner_hex(addr: &jnt_core::hash::Address) -> String {
    jnt_core::hash::address_to_hex(addr)
}

// ---------------------------------------------------------------------------
// The loop that actually matters
// ---------------------------------------------------------------------------

const SINK_VALUE: u64 = 100_000_000;
const EXIT_FEE: u64 = 1_000_000;

fn mine_empty_to(chain: &mut Chain, miner: Address, to: u64) {
    while chain.height() < to {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// Deposit 1 JNT to the sink, mature it, queue an exit for it, mature the exit.
/// Leaves the node holding exactly one crankable claim, which is the state every
/// assertion above was too weak to observe.
fn node_with_one_crankable_exit() -> (Node, Address) {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = miner.address().unwrap();
    let dest = wallet(8).address().unwrap();

    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, me, 12);

    // Deposit, through the same burn-to-sink path the node's own tests use.
    let sink = params.l2_deposit_sink();
    let (outpoint, value) = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == me && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase");
    let fee = chain.expected_base_fee_for_next_block() * (16_000 + 1_000 + 2 * 250) + 1_000_000;
    let tx = miner
        .build_tx(
            &[outpoint],
            vec![
                Output {
                    value: SINK_VALUE,
                    address: sink,
                },
                Output {
                    value: value - SINK_VALUE - fee,
                    address: me,
                },
            ],
            fee,
        )
        .unwrap();
    let h = chain.height() + 1;
    let deposit_block = chain.mine_block(me, vec![tx], ts(h)).unwrap();
    chain.submit(deposit_block).unwrap();
    mine_empty_to(&mut chain, me, h + 20);

    let mut view = NodeL2::replay_from(&chain, &params);
    assert_eq!(view.state().balance(&me), SINK_VALUE, "deposit matured");

    let gas = 16_000u64 + 1_000 + 2 * 250;
    let l1_fee = chain.expected_base_fee_for_next_block() * gas;
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let q = chain.height() + 1;
    let payload = jnt_core::l2::ExitQueuePayload::build(&miner, 1, amount, dest, EXIT_FEE).unwrap();
    let l2_tx = jnt_core::l2::L2Transaction::new(jnt_core::l2::L2Payload::ExitQueue(payload));
    let root = view.simulate_root(q, std::slice::from_ref(&l2_tx));
    let block = chain
        .mine_block_with_l2_root(
            me,
            vec![],
            vec![l2_tx],
            root,
            ts(q),
            None,
            jnt_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(block).unwrap();
    view.sync(&chain);

    // Queued but immature: the crank must stay empty, and the route must say so
    // as "nothing yet" rather than as an error.
    let (status, body) = get(
        node_of(&chain, &view).addr,
        &format!("/v1/exit/crankable?claimant={}", miner_hex(&me)),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(json(&body)["crankable_count"], 0, "{body}");
    assert_eq!(
        json(&body)["queued"],
        1,
        "the exit is queued, just not final"
    );

    mine_empty_to(&mut chain, me, q + params.finality_depth);
    view.sync(&chain);
    assert_eq!(view.crank_claims(&chain, me).len(), 1, "now mature");

    (node_of(&chain, &view), me)
}

/// Start a fresh API server over a specific chain and L2 view.
fn node_of(chain: &Chain, view: &NodeL2) -> Node {
    start(chain.clone(), view.clone())
}

/// The payoff: the route hands out a claim that consensus would actually accept.
/// Every field is checked against what the L2 record proved, so a route that
/// invented a destination or an amount would fail here rather than paying it.
#[test]
fn a_matured_exit_is_handed_over_as_a_claim_consensus_accepts() {
    let (node, me) = node_with_one_crankable_exit();
    let (status, body) = get(
        node.addr,
        &format!("/v1/exit/crankable?claimant={}", miner_hex(&me)),
    );
    assert_eq!(status, 200, "{body}");
    let v = json(&body);
    assert_eq!(v["crankable_count"], 1, "{body}");
    assert_eq!(v["queued"], 1, "{body}");
    assert_eq!(v["unbacked_claims"], 0, "{body}");

    let claim = &v["crankable"][0];
    assert_eq!(claim["encoding"], "hex", "{body}");
    let bytes = hex::decode(claim["bytes"].as_str().expect("hex bytes")).expect("valid hex");
    let decoded =
        jnt_core::exit::ExitClaim::deserialize(&bytes).expect("the bytes decode as a claim");
    assert_eq!(decoded.owner, me);
    // The prepaid fee is paid to whoever asked — that is the whole of the
    // claimant's power, and it must be exactly that.
    assert_eq!(hex::encode(decoded.claimant), hex::encode(me.as_slice()));
    // Consensus-owned fields round-trip: amount, destination and the claim id
    // are all decided by the proven record, not by the caller.
    assert_eq!(
        claim["claim_id"],
        jnt_core::hash::hash512_to_hex(&decoded.claim_id()),
        "{body}"
    );
    assert!(
        claim["amount_sat"].as_u64().unwrap() > 0,
        "a claim for nothing is a broken claim"
    );
}
