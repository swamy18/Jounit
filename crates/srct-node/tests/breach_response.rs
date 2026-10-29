//! Decision 17 — the conservation-breach response.
//!
//! The refusal half (`api::refuse_funding_if_breached`) and the alarm half
//! (the serve loop's repeating `CONSERVATION BREACH` line) exist to answer one
//! question: when a node discovers value that should not exist, what does it
//! stop doing and what does it keep doing?
//!
//! What these tests pin, through the real HTTP surface:
//!
//! - a **breached node refuses the two funding paths** — `/v1/l2/broadcast`
//!   outright, and `/v1/tx/broadcast` for a payment that actually carries a
//!   sink output (a real signed deposit, not a lookalike);
//! - the refusal names conservation and is `503`, so a client can tell a
//!   deliberate refusal from a malformed request (`400`);
//! - **reads stay up** — `/v1/conservation` still serves and reports the breach
//!   honestly instead of hiding it, and `/v1/status` keeps answering;
//! - an **ordinary L1 payment still relays** on a breached node: the freeze is
//!   targeted at the paths that make the number worse, not a blanket stop;
//! - a **healthy node** is completely unaffected — same requests, normal
//!   answers. A gate that fired when nothing was wrong would be worse than no
//!   gate at all.
//!
//! The breach is constructed honestly rather than faked: `L2State::credit` is
//! the out-of-band funding path (genesis and deposits are the only production
//! funders), so crediting satoshis nobody released is exactly an L2 funding
//! anomaly — the second of the three checks `conservation_report` runs.
//!
//! Run with `cargo test -p srct-node --test breach_response`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use srct_core::chain::Chain;
use srct_core::hash::Address;
use srct_core::params::{NetworkParams, SAT_PER_SRCT};
use srct_core::tx::{OutPoint, Output, Transaction};
use srct_core::wallet::Wallet;
use srct_node::api::{spawn, SharedNode};
use srct_node::l2::NodeL2;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn start(chain: Chain, l2: NodeL2) -> SocketAddr {
    let shared = Arc::new(Mutex::new(SharedNode::new(chain, l2)));
    let peers = Arc::new(AtomicUsize::new(0));
    spawn(shared, peers, "127.0.0.1:0".parse().unwrap(), None)
        .expect("the API must bind its loopback socket")
}

fn request(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let body = body.unwrap_or("");
    let mut s = TcpStream::connect(addr).expect("connect");
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
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

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    request(addr, "GET", path, None)
}

fn post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    request(addr, "POST", path, Some(body))
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).expect("response is JSON")
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "breach-response-test").unwrap()
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn mine_empty_to(chain: &mut Chain, miner: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

/// Mature coinbase outpoints of `miner`.
fn mature_outpoints(chain: &Chain, miner: Address) -> Vec<(OutPoint, u64)> {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .collect()
}

/// A valid signed L1 payment: one output to `to`, change back to the payer.
fn payment_tx(
    chain: &Chain,
    from: &Wallet,
    op: OutPoint,
    op_value: u64,
    to: Address,
    value: u64,
) -> Transaction {
    let fee = fee_for(chain, 1, 2);
    from.build_tx(
        &[op],
        vec![
            Output { value, address: to },
            Output {
                value: op_value - value - fee,
                address: from.address().unwrap(),
            },
        ],
        fee,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// A chain with a funded, mature wallet — the L1 side both scenarios need.
fn funded_chain() -> (NetworkParams, Chain, Wallet) {
    let params = NetworkParams::mini();
    let miner = wallet(61);
    let miner_addr = miner.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    // Mini coinbase maturity is 10, so height 13 matures the first three
    // coinbases — this test spends three of them in separate payments, and two
    // payments that shared one outpoint would collide in the mempool.
    mine_empty_to(&mut chain, miner_addr, 13);
    (params, chain, miner)
}

fn breached_view(params: &NetworkParams) -> NodeL2 {
    let mut l2 = NodeL2::fresh(params).unwrap();
    // Satoshis that genesis and deposits never released: exactly the L2
    // funding anomaly `ConservationReport::l2_funding_ok` is there to catch.
    l2.state_mut()
        .credit([0x99; 20], 7 * SAT_PER_SRCT)
        .expect("credit is the out-of-band funding path");
    assert!(
        !srct_node::conservation::conservation_report(&Chain::new(params.clone()).unwrap(), &l2)
            .l2_funding_ok(),
        "the fixture must actually be in breach"
    );
    l2
}

#[test]
fn a_breached_node_refuses_l2_writes_and_names_conservation() {
    let (params, chain, _) = funded_chain();
    let addr = start(chain, breached_view(&params));

    // Any payload at all: the path is refused, not the request contents.
    let (status, body) = post(addr, "/v1/l2/broadcast", r#"{"l2_tx_hex":"deadbeef"}"#);
    assert_eq!(
        status, 503,
        "a breached node must refuse the L2 write: {body}"
    );
    let v = json(&body);
    assert_eq!(v["error"], "conservation_breach", "{body}");
    let detail = v["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("conservation"),
        "the refusal must name conservation: {body}"
    );
    assert!(
        detail.contains("/v1/conservation"),
        "the refusal must point at the read to diagnose with: {body}"
    );
}

#[test]
fn a_breached_node_refuses_a_real_signed_deposit_but_relays_an_ordinary_payment() {
    let (params, chain, user) = funded_chain();
    let user_addr = user.address().unwrap();
    let funding = mature_outpoints(&chain, user_addr);
    assert!(
        funding.len() >= 3,
        "the fixture needs three spendable coinbases"
    );
    let (op_deposit, value_a) = funding[0];
    let (op_plain, value_b) = funding[1];
    let (op_escrow, value_c) = funding[2];

    // A real deposit: a signed payment carrying an output to the sink.
    let deposit = payment_tx(
        &chain,
        &user,
        op_deposit,
        value_a,
        params.l2_deposit_sink(),
        SAT_PER_SRCT,
    );
    // An ordinary payment, same shape but no sink output.
    let plain = payment_tx(
        &chain,
        &user,
        op_plain,
        value_b,
        wallet(62).address().unwrap(),
        SAT_PER_SRCT,
    );
    // And a signed payment to the *escrow* identity, which is not the sink:
    // refusing this too would be over-reach, so it is pinned as accepted.
    let to_escrow = payment_tx(
        &chain,
        &user,
        op_escrow,
        value_c,
        params.l2_escrow_address(),
        SAT_PER_SRCT,
    );

    let addr = start(chain, breached_view(&params));

    let body =
        |tx: &Transaction| format!(r#"{{"signed_tx_hex":"{}"}}"#, hex::encode(tx.serialize()));

    let (status, resp) = post(addr, "/v1/tx/broadcast", &body(&deposit));
    assert_eq!(
        status, 503,
        "a deposit must be refused during a breach: {resp}"
    );
    assert_eq!(json(&resp)["error"], "conservation_breach", "{resp}");
    let detail = json(&resp)["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        detail.contains("deposit"),
        "the refusal must say which path it refused: {resp}"
    );

    // The same node still relays an ordinary payment: the chain is not frozen.
    let (status, resp) = post(addr, "/v1/tx/broadcast", &body(&plain));
    assert_eq!(
        status, 200,
        "an ordinary L1 payment must still relay during a breach: {resp}"
    );

    let (status, resp) = post(addr, "/v1/tx/broadcast", &body(&to_escrow));
    assert_eq!(
        status, 200,
        "a payment to the escrow identity is not a deposit and must relay: {resp}"
    );
}

#[test]
fn a_breached_node_still_serves_every_read() {
    let (params, chain, _) = funded_chain();
    let addr = start(chain, breached_view(&params));

    // The breach must be *reported*, not hidden: the endpoint is the diagnostic
    // the refusal error points operators at.
    let (status, body) = get(addr, "/v1/conservation");
    assert_eq!(status, 200, "reads stay up during a breach: {body}");
    let v = json(&body);
    assert_eq!(
        v["ok"], false,
        "the endpoint must not claim all-clear: {body}"
    );
    assert_eq!(v["l2_closed"], true, "{body}");
    assert_eq!(
        v["l2_funding_ok"], false,
        "the broken check must be named: {body}"
    );

    // Every other read path keeps answering.
    for path in [
        "/v1/health",
        "/v1/status",
        "/v1/block/latest",
        "/v1/mempool",
        "/v1/l2/state",
    ] {
        let (status, body) = get(addr, path);
        assert_eq!(status, 200, "{path} must stay up during a breach: {body}");
    }
}

#[test]
fn a_healthy_node_is_completely_unaffected() {
    let (params, chain, _) = funded_chain();
    let addr = start(chain, NodeL2::fresh(&params).unwrap());

    // The same request that is refused above: on a healthy node it reaches the
    // normal path, so a malformed payload is a client error, not a breach.
    let (status, body) = post(addr, "/v1/l2/broadcast", r#"{"l2_tx_hex":"deadbeef"}"#);
    assert_eq!(
        status, 400,
        "a healthy node must not refuse the L2 path: {body}"
    );
    assert_eq!(json(&body)["error"], "bad_request", "{body}");

    let (status, body) = post(addr, "/v1/tx/broadcast", r#"{"signed_tx_hex":"deadbeef"}"#);
    assert_eq!(status, 400, "a healthy node must not refuse L1: {body}");

    let (status, body) = get(addr, "/v1/conservation");
    assert_eq!(status, 200, "{body}");
    assert_eq!(json(&body)["ok"], true, "{body}");
}
