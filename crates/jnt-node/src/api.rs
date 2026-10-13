//! The opt-in service API (Decision 9, roadmap §13, SPEC.md §19.2).
//!
//! `jnt-node serve --api-listen <addr>` starts an HTTP/REST server beside the
//! P2P daemon. Disabled by default; loopback is the expected binding and a
//! non-loopback bind prints a warning, because exposing this port is an
//! operator decision (§19.2).
//!
//! # What this is, and what it is not
//!
//! - **Not a consensus surface.** Nothing here reaches `Chain::submit`. The
//!   only writes are: an L1 transaction that passes the exact `pool.add` path
//!   a peer's relayed transaction passes, and an L2 transaction that passes a
//!   dry-run against a *clone* of L2 state and then waits in a queue for a
//!   block to carry it — L2 state is still derived from canonical blocks
//!   alone (SPEC §19.1).
//! - **No signing, ever.** The API never sees a private key. `POST
//!   /v1/tx/build` returns *unsigned* bytes for the caller to sign;
//!   `POST /v1/authorize` returns the authorization bytes and their signing
//!   hash for the owner to sign. Refusals never echo signing material.
//! - **Bounded everything.** One body-size cap for all inputs; the receipt
//!   book, payment store and policy book are cap-with-refusal, so a flood
//!   cannot grow node memory without bound.
//! - **State it holds is non-consensus**: receipts, payment ids and policy
//!   accounting are this node's view for lookup/authorization convenience.
//!   Losing them (restart) changes no coin.
//!
//! Endpoints (§13 for L1, §19.2 for the L2 additions, plus the payment/
//! receipt surface items 16–17 require):
//!
//! ```text
//! GET  /v1/health              liveness for monitors
//! GET  /metrics                Prometheus text exposition of the gauges below
//! GET  /v1/status              network, height, tip, peers, supply, finality, L2
//! GET  /v1/conservation        live joint L1+L2−sink supply vs the joint bound (the `verify` arithmetic)
//! GET  /v1/finality            finality status
//! GET  /v1/fees                fee schedule: gas, base fee, D3 L2 flat fees
//! GET  /v1/balance/{address}   confirmed / spendable / pending
//! GET  /v1/utxo/{address}      unspent outputs
//! GET  /v1/block/latest        newest block
//! GET  /v1/block/{hash}        one block by hash
//! GET  /v1/tx/{hash}           confirmed | pending | unknown (404)
//! GET  /v1/mempool             pool summary
//! POST /v1/tx/build            unsigned L1 tx (caller signs)
//! POST /v1/tx/broadcast        signed L1 tx -> pool -> relay
//! POST /v1/l2/broadcast        signed L2 tx -> dry-run -> include queue
//! GET  /v1/tasks/open          claimable tasks
//! GET  /v1/task/{task_id}      task state
//! GET  /v1/l2/state            canonical L2 state (§19.2 wire encoding)
//! GET  /v1/vwc/{task_id}       verified work certificate
//! GET  /v1/reputation/{id}      derived reputation score for a worker address
//! POST /v1/authorize           policy + payer-signed request -> authorization
//! POST /v1/payment/submit      verify + record a machine payment
//! GET  /v1/payment/{id}        recorded payment
//! POST /v1/receipt             verify + record a service receipt
//! GET  /v1/receipt/{id}        receipt by id (or by payment id)
//! GET  /v1/exit/crankable      the exit claims this node could settle now
//! POST /v1/escrow/open         open a conditional escrow with a chosen arbitrator
//! POST /v1/escrow/{id}/release arbiter- or mutual-release a live escrow (non-consensus)
//! GET  /v1/escrow/{id}         escrow state
//! ```
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use jnt_core::agent::{derive_agent_id, AgentRole};
use jnt_core::chain::Chain;
use jnt_core::credit::CreditGate;
use jnt_core::fees;
use jnt_core::hash::{address_from_hex, address_to_hex, hash_from_hex, hash_to_hex, Address, Hash};
use jnt_core::l2::L2Transaction;
use jnt_core::mempool::Mempool;
use jnt_core::params::{NetworkParams, L2_FEE_SCHEDULE, SAT_PER_JNT};
use jnt_core::payment::{MachinePayment, PaymentTracker};
use jnt_core::receipt::{ReceiptBook, ReceiptOutcome};
use jnt_core::service::{authorize_request_with_chain, SessionError};
use jnt_core::tx::{Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE};
use jnt_l2::reputation::ledger_from_state;
use jnt_l2::task_contract::{ContractState, TaskContract};

use crate::conservation::conservation_report;
use crate::l2::NodeL2;

/// Largest request body. A block is at most `max_block_bytes` (4 MB on every
/// profile), and the API only ever accepts transactions, payments, receipts,
/// policies and requests — none of which approach that. Explicit rather than
/// framework-default so the bound is visible in this file's docs.
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Everything the API and the serve loop share. One lock: the serve loop
/// takes it per iteration, handlers take it per request. No handler ever
/// holds it across an await (handlers do not await), so the async runtime
/// only exists to accept sockets and parse HTTP.
pub struct SharedNode {
    pub chain: Chain,
    pub pool: Mempool,
    pub l2: NodeL2,
    /// Verified receipts this node holds (lookup, replay-safe semantics).
    pub receipts: ReceiptBook,
    /// Exact-payment replay guard.
    pub payment_tracker: PaymentTracker,
    /// Payment id -> payment, same cap as the tracker.
    pub payment_store: BTreeMap<Hash, MachinePayment>,
    /// Admission-time credit reservation keyed by payment id. Consumed when the
    /// matching `ServiceReceipt` is accepted (roadmap item 10 / §19.4): that is
    /// the settlement event, so the credit debit is committed here rather than
    // at admission. Pre-credit nodes wire `NoCreditGate`, which yields a zero-id
    // reservation whose settle is a no-op, so this stays safe when credit is
    // unconfigured.
    pub reservations: BTreeMap<Hash, jnt_core::credit::Reservation>,
    /// Policy accounting for `POST /v1/authorize`.
    pub policies: jnt_core::agent::PolicyBook,
    /// Credit book for `POST /v1/credit/*`: free balances, posted bonds and
    /// positions. Item 2 wiring (roadmap item 2); kept here, off consensus, so
    /// a payment can only be committed if the payer's line covers it, but the
    /// coin itself still moves through the ordinary §1 UTXO path later.
    pub credit: jnt_core::credit::CreditBook,
    /// Delegation link book (roadmap item 3). Node-local authority for who
    /// descends from whom: the policy layer is not a consensus rule (SPEC §18.2.1
    /// / D4), but the engine that *issued* the policies must be the one that
    /// registers their parent links, so a delegation is auditable against the
    /// lineage that was actually permitted. `link` enforces domination on every
    /// field and the depth cap in the same pass, reusing `delegation::dominates`.
    pub delegations: jnt_core::delegation::DelegationBook,
    /// Conditional-escrow store for Item 4 (contract-selected arbitrators).
    /// Non-consensus: the ledger tracks the state machine, and the actual coin
    /// release reuses the §1 L1 exit / §19.4 path.
    pub escrows: BTreeMap<jnt_core::hash::Hash, jnt_core::escrow::ConditionalEscrow>,
    /// Policies this node has issued authorizations under, keyed by policy hash.
    ///
    /// The node keeps the policy object because admission (`POST
    /// /v1/payment/submit`) must check the policy a payment *names* is the one
    /// the engine issued under, and that it is still live at this height —
    /// neither of which the accounting alone answers. A payment naming a policy
    /// the node has never authorized under is refused, however well-formed.
    pub policy_registry: BTreeMap<Hash, jnt_core::agent::SpendPolicy>,
    /// Policy hashes the owner has revoked, by the hash the engine actually
    /// issued under.
    ///
    /// Revocation needs this set because `revoked` is inside the canonical
    /// encoding: a revoked policy is a *different hash* from the one the engine
    /// authorized, so the revoked statement cannot find the original by itself.
    /// The node maps it back — variant bytes with `revoked` cleared — and
    /// records the original. Only the owner can produce that statement, because
    /// it is the statement they sign.
    pub revoked_policies: BTreeSet<Hash>,
    /// L1 txids the API accepted; drained by the serve loop, which owns the
    /// P2P node and announces them to peers.
    pub tx_to_relay: Vec<Hash>,
    /// L2 transactions that passed the dry-run; drained by the serve loop
    /// into the next mined block's trailer.
    pub l2_to_include: Vec<L2Transaction>,
}

impl SharedNode {
    pub fn new(chain: Chain, l2: NodeL2) -> Self {
        SharedNode {
            chain,
            pool: Mempool::default(),
            l2,
            receipts: ReceiptBook::default(),
            payment_tracker: PaymentTracker::default(),
            payment_store: BTreeMap::new(),
            reservations: BTreeMap::new(),
            policies: jnt_core::agent::PolicyBook::default(),
            credit: jnt_core::credit::CreditBook::new(),
            delegations: jnt_core::delegation::DelegationBook::new(),
            escrows: BTreeMap::new(),
            policy_registry: BTreeMap::new(),
            revoked_policies: BTreeSet::new(),
            tx_to_relay: Vec::new(),
            l2_to_include: Vec::new(),
        }
    }

    /// Advance escrows whose release has matured under finality to `Finalized`
    /// (roadmap item 10, §19.4). Called each serve-loop tick so a released
    /// escrow becomes settleable without an extra client round-trip; it is also
    /// safe to call from read paths because it is idempotent and pure height
    /// math (no coin moves — finality is a ledger height-stamp only).
    pub fn advance_escrow_finality(&mut self) {
        let now = self.chain.height();
        let activation = self.chain.params().finality_activation_height;
        for escrow in self.escrows.values_mut() {
            let _ = escrow.finalize(now, activation);
        }
    }
}

#[derive(Clone)]
pub struct ApiState {
    shared: Arc<Mutex<SharedNode>>,
    peers: Arc<AtomicUsize>,
}

/// Uniform error body: a stable machine-readable code plus a detail string
/// that never contains signing material (nothing here holds any).
#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub detail: String,
}

pub type ApiResult = Result<Json<Value>, (StatusCode, Json<ErrorBody>)>;

fn fail(
    status: StatusCode,
    error: &'static str,
    detail: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error,
            detail: detail.into(),
        }),
    )
}

fn bad(detail: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    fail(StatusCode::BAD_REQUEST, "bad_request", detail)
}

fn not_found(detail: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    fail(StatusCode::NOT_FOUND, "not_found", detail)
}

/// Run `f` with exclusive access to the shared node state.
fn with_shared<T>(
    state: &ApiState,
    f: impl FnOnce(&mut SharedNode) -> T,
) -> Result<T, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.shared.lock().map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "state lock poisoned",
        )
    })?;
    Ok(f(&mut guard))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn decode_address(s: &str) -> Result<Address, (StatusCode, Json<ErrorBody>)> {
    address_from_hex(s).map_err(|e| bad(format!("address: {e}")))
}

fn decode_hash(s: &str) -> Result<Hash, (StatusCode, Json<ErrorBody>)> {
    hash_from_hex(s).map_err(|e| bad(format!("hash: {e}")))
}

fn decode_hex_bytes(s: &str, what: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorBody>)> {
    let raw = s.trim().trim_start_matches("0x");
    hex::decode(raw).map_err(|e| bad(format!("{what} hex: {e}")))
}

/// Parse and length-check a 48-byte BLS public key hex string.
fn decode_public_key(
    s: &str,
    what: &str,
) -> Result<jnt_core::bls_checkpoint::BlsPublicKey, (StatusCode, Json<ErrorBody>)> {
    let raw = decode_hex_bytes(s, what)?;
    let mut key = [0u8; 48];
    if raw.len() != 48 {
        return Err(bad(format!("{what} must be 48 hex bytes")));
    }
    key.copy_from_slice(&raw);
    Ok(jnt_core::bls_checkpoint::BlsPublicKey(key))
}

fn task_json(t: &TaskContract) -> Value {
    let mut v = json!({
        "task_id": hash_to_hex(&t.task_id),
        "submitter": address_to_hex(&t.submitter),
        "worker": t.worker.map(|a| address_to_hex(&a)),
        "payment_sat": t.payment_sat,
        "worker_deposit_sat": t.worker_deposit_sat,
        "deadline_height": t.deadline_height,
        "dispute_window": t.dispute_window,
        "state": t.state.name(),
    });
    if let ContractState::ResultSubmitted { result_hash, .. } = &t.state {
        v["result_hash"] = json!(hash_to_hex(result_hash));
    }
    v
}

// ---------------------------------------------------------------------------
// Handlers — read paths
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn status(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p: &NetworkParams = sh.chain.params();
        Json(json!({
            "network": p.name,
            "network_id": p.network_id,
            "height": sh.chain.height(),
            "tip_hash": hash_to_hex(&sh.chain.tip_hash()),
            "peers": state.peers.load(Ordering::Relaxed),
            "base_fee_sat": sh.chain.expected_base_fee_for_next_block(),
            "total_supply_sat": sh.chain.total_supply_sat(),
            "pscb_reserve_sat": sh.chain.pscb_reserve(),
            "finalized_height": sh.chain.finalized_height(),
            "finality_activation_height": p.finality_activation_height,
            "finality_depth": p.finality_depth,
            "mempool_len": sh.pool.len(),
            "l2": {
                "height": sh.l2.height(),
                "applied": sh.l2.applied_count(),
                "skipped": sh.l2.skipped().len(),
                "pending_deposits": sh.l2.pending_deposits().len(),
                // The exit pipeline (approved P1): queued exits awaiting an L1
                // release, and value that has already left L2 for L1. An
                // operator watches `exited_sat` to confirm the two directions
                // balanced rather than one side inflating.
                "pending_exits": sh.l2.pending_exits().len(),
                "exited_sat": sh.l2.state().exited_total(),
            },
        }))
    })
}

/// Live joint conservation (SPEC.md §19.4–§19.5): the arithmetic
/// `jnt-node verify` prints, served from the same state and reported for all
/// three checks at once.
///
/// Read-only, under the same lock as `/v1/status`. The terms sum the whole
/// UTXO set, so this is a self-check/monitoring endpoint, not a hot path.
/// `ok` is the full verdict (L2 closed, L2 funded by genesis plus matured
/// deposits, joint supply inside the joint bound); the component booleans and
/// the terms say *which* check moved. `jnt-worker run` gates on this before
/// its first pass, and `/metrics` exports the same joint figure as gauges —
/// all from the one implementation in `crate::conservation`, so the endpoint,
/// the exporter and `verify` cannot disagree.
async fn conservation(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let report = conservation_report(&sh.chain, &sh.l2);
        Json(json!({
            "ok": report.ok(),
            "l2_closed": report.l2_closed,
            "l2_funding_ok": report.l2_funding_ok(),
            "joint_sat": report.supply.joint_sat,
            "joint_bound_sat": report.supply.bound_sat(),
            "l1_bound_sat": report.supply.l1_bound_sat,
            "escrow_ceiling_sat": report.supply.escrow_ceiling_sat,
            "exited_sat": report.supply.exited_sat,
            "l1_issued_sat": jnt_core::supply::cumulative_issuance_sat(sh.chain.params(), sh.chain.height()),
            "l1_removed_sat": sh.chain.base_removed_total(),
            "l1_net_sat": jnt_core::supply::cumulative_issuance_sat(sh.chain.params(), sh.chain.height()).saturating_sub(sh.chain.base_removed_total()),
            "headroom_sat": report.supply.headroom_sat(),
            "l1_live_sat": report.supply.l1_live_sat,
            "l2_held_sat": report.supply.l2_held_sat,
            "sink_held_sat": report.supply.sink_held_sat,
            "network_id": sh.chain.params().network_id,
            "height": sh.chain.height(),
        }))
    })
}

async fn finality(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p = sh.chain.params();
        Json(json!({
            "tip_height": sh.chain.height(),
            "finalized_height": sh.chain.finalized_height(),
            "finality_depth": p.finality_depth,
            "finality_activation_height": p.finality_activation_height,
            "binding": p.finality_activation_height > 0,
        }))
    })
}

async fn fee_schedule(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let p = sh.chain.params();
        let base = sh.chain.expected_base_fee_for_next_block();
        let l2: Vec<Value> = L2_FEE_SCHEDULE
            .iter()
            .map(|(name, sat)| json!({ "tx": name, "fee_sat": sat }))
            .collect();
        Json(json!({
            "sat_per_jnt": SAT_PER_JNT,
            "base_fee_sat_per_gas": base,
            "gas_base": GAS_TX_BASE,
            "gas_per_input": GAS_PER_INPUT,
            "gas_per_output": GAS_PER_OUTPUT,
            "min_tx_fee_sat": fees::required_fee(base, GAS_TX_BASE),
            "l2_fee_schedule": l2,
            "l2_deposit_minimum_sat": p.l2_deposit_minimum_sat,
            "coinbase_maturity": p.coinbase_maturity,
        }))
    })
}

/// Escape a Prometheus label value: backslash, double quote and newline are the
/// only three characters the exposition format requires to be escaped.
fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Append one gauge with its `# HELP` / `# TYPE` preamble.
fn gauge(out: &mut String, name: &str, help: &str, net: &str, value: u64) {
    // Writing into a String is infallible; the `let _` keeps the fmt::Write
    // contract explicit without an unwrap that clippy would prefer anyway.
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name}{{network=\"{net}\"}} {value}");
}

/// Prometheus text exposition (Phase 7 observability).
///
/// Gauges only, read straight out of the same state `/v1/status` reports, plus
/// the two relay-queue depths the node already tracks. Deliberately no counters
/// that would need per-request bookkeeping inside the consensus loop, and the
/// only label is the static network id — so label cardinality is bounded by
/// construction and a scraper cannot amplify memory. Nothing here renders key
/// material or per-user data.
///
/// Served at `/metrics` because that is the path a Prometheus scrape config
/// expects; it carries the same loopback-by-default exposure as every other
/// route in this module.
async fn metrics(
    State(state): State<ApiState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let body = with_shared(&state, |sh| {
        let p = sh.chain.params();
        let net = escape_label_value(&p.network_id);
        let peers = state.peers.load(Ordering::Relaxed) as u64;
        let mut out = String::with_capacity(2048);

        gauge(
            &mut out,
            "jounit_height",
            "Current chain tip height.",
            &net,
            sh.chain.height(),
        );
        gauge(
            &mut out,
            "jounit_finalized_height",
            "Highest finalized height.",
            &net,
            sh.chain.finalized_height(),
        );
        gauge(
            &mut out,
            "jounit_finality_depth",
            "Depth-based finality window, in blocks.",
            &net,
            p.finality_depth,
        );
        gauge(
            &mut out,
            "jounit_finality_activation_height",
            "Binding-finality activation height (0 disables binding finality).",
            &net,
            p.finality_activation_height,
        );
        gauge(
            &mut out,
            "jounit_peers",
            "Connected peer count.",
            &net,
            peers,
        );
        gauge(
            &mut out,
            "jounit_base_fee_sat_per_gas",
            "Base fee for the next block, in satoshi per gas.",
            &net,
            sh.chain.expected_base_fee_for_next_block(),
        );
        gauge(
            &mut out,
            "jounit_total_supply_sat",
            "Live UTXO supply, in satoshi.",
            &net,
            sh.chain.total_supply_sat(),
        );
        gauge(
            &mut out,
            "jounit_rate_anchor_allowance_sat",
            "Rate anchor (Decision 18): the most gross issuance the current halving period may add, 1% of supply issued at the window's start, in satoshi. u64::MAX inside the grandfathered ladder era.",
            &net,
            jnt_core::supply::rate_anchor_allowance(p, sh.chain.height() + 1),
        );
        gauge(
            &mut out,
            "jounit_issued_sat",
            "Gross issuance so far (the issuance integral at the tip height), in satoshi; burns are what make net supply lower.",
            &net,
            jnt_core::supply::cumulative_issuance_sat(p, sh.chain.height()),
        );
        gauge(
            &mut out,
            "jounit_net_supply_sat",
            "Net supply (gross issuance minus base fees burned and PSCB-routed), in satoshi: the dilution holders experience.",
            &net,
            jnt_core::supply::cumulative_issuance_sat(p, sh.chain.height())
                .saturating_sub(sh.chain.base_removed_total()),
        );
        // Joint conservation (SPEC §19.4–§19.5): the same report
        // `GET /v1/conservation` serves and `jnt-node verify` prints. Adds one
        // UTXO-set pass per scrape — the same cost class
        // `jounit_total_supply_sat` above already pays.
        let report = conservation_report(&sh.chain, &sh.l2);
        gauge(
            &mut out,
            "jounit_joint_supply_sat",
            "Joint supply (L1 live + L2 held − deposit sink), in satoshi; must stay at or below the joint bound.",
            &net,
            report.supply.joint_sat,
        );
        gauge(
            &mut out,
            "jounit_joint_bound_sat",
            "Joint ceiling (issuance integral at the tip plus the escrow ceiling), in satoshi.",
            &net,
            report.supply.bound_sat(),
        );
        gauge(
            &mut out,
            "jounit_conservation_ok",
            "1 while L2 balances, L2 funding is genesis plus matured deposits minus value released to L1, and joint supply is inside the bound; 0 means value was created.",
            &net,
            u64::from(report.ok()),
        );
        gauge(
            &mut out,
            "jounit_pscb_reserve_sat",
            "PSCB reserve counter, in satoshi (non-spendable; never re-enters supply).",
            &net,
            sh.chain.pscb_reserve(),
        );
        gauge(
            &mut out,
            "jounit_mempool_transactions",
            "L1 transactions currently in the mempool.",
            &net,
            sh.pool.len() as u64,
        );
        gauge(
            &mut out,
            "jounit_l1_relay_queue",
            "Accepted L1 txids queued for peer relay.",
            &net,
            sh.tx_to_relay.len() as u64,
        );
        gauge(
            &mut out,
            "jounit_l2_include_queue",
            "L2 transactions queued to ride the next mined block.",
            &net,
            sh.l2_to_include.len() as u64,
        );
        gauge(
            &mut out,
            "jounit_l2_height",
            "Canonical L2 height.",
            &net,
            sh.l2.height(),
        );
        gauge(
            &mut out,
            "jounit_l2_applied_total",
            "L2 payloads applied to canonical state.",
            &net,
            sh.l2.applied_count(),
        );
        gauge(
            &mut out,
            "jounit_l2_skipped_total",
            "L2 payloads skipped (fail-closed count).",
            &net,
            sh.l2.skipped().len() as u64,
        );
        gauge(
            &mut out,
            "jounit_l2_pending_deposits",
            "L2 deposits awaiting maturity.",
            &net,
            sh.l2.pending_deposits().len() as u64,
        );
        out
    })?;
    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}

async fn balance(State(state): State<ApiState>, Path(addr): Path<String>) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let mut confirmed = 0u64;
        let mut spendable = 0u64;
        let next_height = sh.chain.height() + 1;
        for (_, u) in sh.chain.utxo().iter() {
            if u.out.address == addr {
                confirmed = confirmed.saturating_add(u.out.value);
                if sh.chain.is_mature(u.height) {
                    spendable = spendable.saturating_add(u.out.value);
                }
            }
        }
        let mut pending_in = 0u64;
        for (_, entry) in sh.pool.entries() {
            for o in &entry.tx.outputs {
                if o.address == addr {
                    pending_in = pending_in.saturating_add(o.value);
                }
            }
        }
        Json(json!({
            "address": address_to_hex(&addr),
            "confirmed_sat": confirmed,
            "spendable_sat": spendable,
            "pending_sat": pending_in,
            "next_height": next_height,
        }))
    })
}

async fn utxos(State(state): State<ApiState>, Path(addr): Path<String>) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let mut out = Vec::new();
        for (op, u) in sh.chain.utxo().iter() {
            if u.out.address == addr {
                out.push(json!({
                    "txid": hash_to_hex(&op.txid),
                    "index": op.index,
                    "value_sat": u.out.value,
                    "height": u.height,
                    "spendable": sh.chain.is_mature(u.height),
                }));
            }
        }
        Json(json!({ "address": address_to_hex(&addr), "utxos": out }))
    })
}

async fn block_latest(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let h = sh.chain.height();
        let block = sh.chain.block_at(h).ok_or_else(|| not_found("no block"))?;
        let value = serde_json::to_value(block)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        Ok(Json(
            json!({ "hash": hash_to_hex(&block.block_hash()), "block": value }),
        ))
    })?
}

async fn block_by_hash(State(state): State<ApiState>, Path(hash): Path<String>) -> ApiResult {
    let hash = decode_hash(&hash)?;
    with_shared(&state, |sh| {
        let block = sh
            .chain
            .block_by_hash(&hash)
            .ok_or_else(|| not_found("unknown block"))?;
        let value = serde_json::to_value(block)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        Ok(Json(json!({ "hash": hash_to_hex(&hash), "block": value })))
    })?
}

async fn tx_lookup(State(state): State<ApiState>, Path(hash): Path<String>) -> ApiResult {
    let hash = decode_hash(&hash)?;
    with_shared(&state, |sh| {
        // Canonical scan: O(tip) per lookup, which is the honest cost of a
        // node with no tx index. Documented in the status docs.
        for height in 1..=sh.chain.height() {
            let Some(block) = sh.chain.block_at(height) else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == hash {
                    let value = serde_json::to_value(tx).unwrap_or(Value::Null);
                    return Ok(Json(json!({
                        "status": "confirmed",
                        "block_hash": hash_to_hex(&block.block_hash()),
                        "block_height": height,
                        "tx": value,
                    })));
                }
            }
        }
        if let Some(entry) = sh.pool.get(&hash) {
            let value = serde_json::to_value(&entry.tx).unwrap_or(Value::Null);
            return Ok(Json(json!({ "status": "pending", "tx": value })));
        }
        Err(not_found("unknown transaction"))
    })?
}

async fn mempool_view(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let entries: Vec<Value> = sh
            .pool
            .entries()
            .map(|(txid, e)| {
                json!({
                    "tx_hash": hash_to_hex(txid),
                    "fee_rate": e.fee_rate,
                    "fee_sat": e.fee_total,
                    "inputs": e.tx.inputs.len(),
                    "outputs": e.tx.outputs.len(),
                })
            })
            .collect();
        Json(json!({ "count": entries.len(), "entries": entries }))
    })
}

async fn tasks_open(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let open: Vec<Value> = sh
            .l2
            .state()
            .tasks()
            .iter()
            .filter(|t| matches!(t.state, ContractState::Open))
            .map(|t| task_json(t))
            .collect();
        Json(json!({ "count": open.len(), "tasks": open }))
    })
}

async fn task_by_id(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let task = sh
            .l2
            .state()
            .tasks()
            .into_iter()
            .find(|t| t.task_id == id)
            .ok_or_else(|| not_found("unknown task"))?;
        Ok(Json(task_json(task)))
    })?
}

async fn vwc_by_task(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let cert = sh
            .l2
            .state()
            .vwc(&id)
            .ok_or_else(|| not_found("no certificate for task"))?;
        Ok(Json(json!({
            "id": hash_to_hex(&cert.id),
            "task_id": hash_to_hex(&cert.task_id),
            "worker": address_to_hex(&cert.worker),
            "result_hash": hash_to_hex(&cert.result_hash),
            "settled_height": cert.settled_height,
            "payment_sat": cert.payment_sat,
            // The certificate's own canonical encoding, so a relying party can
            // verify it offline against the validator set instead of trusting
            // this summary (SPEC.md §17.6).
            "vwc_hex": hex::encode(cert.encode()),
            "verification": match &cert.verification {
                jnt_l2::VwcVerification::Quorum { signer_count, .. } => {
                    json!({ "kind": "quorum", "signer_count": signer_count })
                }
                jnt_l2::VwcVerification::WindowElapsed => json!({ "kind": "window_elapsed" }),
            },
        })))
    })?
}

/// The canonical L2 state, in the §19.2 wire encoding.
///
/// This is the one endpoint a worker SDK needs that a task-shaped summary
/// cannot serve: `L2NodeView` hands the SDK an `L2State`, so a remote view has
/// to carry the whole state or duplicate the protocol's own rules. The bytes
/// are the node's *derived* state — replaying the canonical blocks produces
/// exactly this — so the client decodes and then checks the conservation
/// invariant itself before it believes a single balance. No signature
/// material is in here: a state is not an actor's claim.
async fn l2_state(State(state): State<ApiState>) -> ApiResult {
    with_shared(&state, |sh| {
        let l2 = sh.l2.state();
        Json(json!({
            "network_id": sh.chain.params().network_id,
            "height": sh.chain.height(),
            "tasks": l2.task_count(),
            "certificates": l2.vwc_count(),
            "state_hex": hex::encode(l2.encode()),
        }))
    })
}

/// Derived reputation for a worker, computed from canonical L2 state.
///
/// The `{id}` is the worker's **address**; the node derives the machine
/// `AgentId` from it (same derivation every identity uses) and then builds the
/// reputation ledger from the L2 state the same way a node derives L2 itself.
/// A worker that has never had a verified-work certificate or a settled dispute
/// reads as a zero score — that is genuine standing, not an error.
///
/// This is read-only, derived, and non-consensus: it cannot fork the chain, and
/// the derivation rules are the same as the ones a peer running this code
/// independently would apply.
async fn reputation_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let address = decode_address(&id)?;
    with_shared(&state, |sh| {
        let params = sh.chain.params();
        let network_id = &params.network_id;
        let subject = derive_agent_id(network_id, AgentRole::Machine, &address);
        let ledger = ledger_from_state(sh.l2.state(), network_id)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
        let mut score_obj = match ledger.score(&subject) {
            Some(s) => json!({
                "score": s.score,
                "events": s.events,
                "by_kind": {
                    "service_completed": s.by_kind[0],
                    "payment_completed": s.by_kind[1],
                    "verified_work": s.by_kind[2],
                    "dispute_won": s.by_kind[3],
                    "dispute_lost": s.by_kind[4],
                },
                "last_height": s.last_height,
                "accumulator": hash_to_hex(&s.accumulator),
                "subjects_tracked": ledger.subjects(),
            }),
            None => json!({
                "score": 0,
                "events": 0,
                "by_kind": {
                    "service_completed": 0,
                    "payment_completed": 0,
                    "verified_work": 0,
                    "dispute_won": 0,
                    "dispute_lost": 0,
                },
                "last_height": 0,
                "accumulator": hash_to_hex(&Hash::default()),
                "subjects_tracked": ledger.subjects(),
            }),
        };
        score_obj["worker_address"] = json!(address_to_hex(&address));
        score_obj["agent_id"] = json!(address_to_hex(&subject));
        score_obj["network_id"] = json!(network_id);
        Ok(Json(json!({
            "worker_address": address_to_hex(&address),
            "agent_id": address_to_hex(&subject),
            "network_id": network_id,
            "score": score_obj["score"],
            "events": score_obj["events"],
            "by_kind": score_obj["by_kind"],
            "last_height": score_obj["last_height"],
            "accumulator": score_obj["accumulator"],
            "subjects_tracked": score_obj["subjects_tracked"],
        })))
    })?
}

async fn payment_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let p = sh
            .payment_store
            .get(&id)
            .ok_or_else(|| not_found("unknown payment"))?;
        Ok(Json(json!({
            "payment_id": hash_to_hex(&id),
            "payment_hex": hex::encode(p.serialize()),
            "payer": address_to_hex(&p.payer),
            "recipient": address_to_hex(&p.recipient),
            "amount_sat": p.amount_sat,
            "fee_sat": p.fee_sat,
            "service": p.service.map(hex::encode),
            "nonce": p.nonce,
            "expires_at_height": p.expires_at_height,
            "network_id": p.network_id,
        })))
    })?
}

async fn receipt_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        let r = sh
            .receipts
            .by_receipt_id(&id)
            .or_else(|| sh.receipts.by_payment_id(&id))
            .ok_or_else(|| not_found("unknown receipt"))?;
        Ok(Json(json!({
            "receipt_id": hash_to_hex(&r.receipt_id()),
            "payment_id": hash_to_hex(&r.payment_id),
            "request_id": hash_to_hex(&r.request_id),
            "payer": address_to_hex(&r.payer),
            "recipient": address_to_hex(&r.recipient),
            "amount_sat": r.amount_sat,
            "service_id": r.service_id.map(hex::encode),
            "result_hash": r.result_hash.map(|h| hash_to_hex(&h)),
            "anchor_height": r.anchor.map(|a| a.height),
            "receipt_hex": hex::encode(r.serialize()),
        })))
    })?
}

// ---------------------------------------------------------------------------
// Handlers — write paths (no signing, no consensus surface)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TxBuildReq {
    from: String,
    to: String,
    amount_sat: u64,
    /// Ceiling on the computed fee. The build refuses rather than silently
    /// exceeding it.
    max_fee_sat: u64,
}

async fn tx_build(State(state): State<ApiState>, Json(req): Json<TxBuildReq>) -> ApiResult {
    if req.amount_sat == 0 {
        return Err(bad("amount_sat must be > 0"));
    }
    let from = decode_address(&req.from)?;
    let to = decode_address(&req.to)?;
    with_shared(&state, |sh| {
        let base_fee = sh.chain.expected_base_fee_for_next_block();
        let maturity = sh.chain.params().coinbase_maturity;
        let candidates: Vec<(jnt_core::tx::OutPoint, u64)> = sh
            .chain
            .utxo()
            .iter()
            .filter(|(_, u)| u.out.address == from && sh.chain.is_mature(u.height))
            .map(|(op, u)| (op, u.out.value))
            .collect();
        if candidates.is_empty() {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "insufficient_funds",
                format!(
                    "no mature outputs for {} (a coinbase needs {maturity} blocks)",
                    address_to_hex(&from)
                ),
            ));
        }

        // Gather inputs until amount + fee is covered; the fee depends on the
        // input count and the input count on the fee, so it settles by
        // iteration — the same rule `jnt-node send` uses.
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for (op, value) in candidates {
            let gas = GAS_TX_BASE + GAS_PER_INPUT * (chosen.len() as u64 + 1) + GAS_PER_OUTPUT * 2;
            let fee = fees::required_fee(base_fee, gas).saturating_add(1_000);
            if total >= req.amount_sat.saturating_add(fee) {
                break;
            }
            total = total.saturating_add(value);
            chosen.push(op);
        }
        let gas = GAS_TX_BASE + GAS_PER_INPUT * chosen.len() as u64 + GAS_PER_OUTPUT * 2;
        let fee = fees::required_fee(base_fee, gas).saturating_add(1_000);
        if total < req.amount_sat.saturating_add(fee) {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "insufficient_funds",
                format!("have {total} sat, need {} sat", req.amount_sat + fee),
            ));
        }
        if fee > req.max_fee_sat {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "fee_exceeds_max",
                format!("fee {fee} sat > max_fee_sat {}", req.max_fee_sat),
            ));
        }

        let change = total - req.amount_sat - fee;
        let mut outputs = vec![jnt_core::tx::Output {
            value: req.amount_sat,
            address: to,
        }];
        if change > 0 {
            outputs.push(jnt_core::tx::Output {
                value: change,
                address: from,
            });
        }
        // Unsigned by design: the caller signs these bytes with their wallet.
        // The API has no key material and must never acquire any.
        let unsigned = Transaction::standard(
            chosen.iter().map(jnt_core::tx::Input::unsigned).collect(),
            outputs,
        );
        let selected: Vec<Value> = chosen
            .iter()
            .map(|op| json!({ "txid": hash_to_hex(&op.txid), "index": op.index }))
            .collect();
        Ok(Json(json!({
            "unsigned_tx_hex": hex::encode(unsigned.serialize()),
            "fee_sat": fee,
            "change_sat": change,
            "selected_utxos": selected,
            "note": "sign every input with the `from` wallet, then POST /v1/tx/broadcast",
        })))
    })?
}

/// Which funding-shaped path a request wanted (Decision 17).
///
/// Only these two are refused during a breach. A blanket freeze was rejected:
/// it would take the node's ordinary payment traffic down with the accounting,
/// and a node that stops serving everything is indistinguishable from one that
/// crashed. The set is exactly the paths that make the broken number *worse*.
#[derive(Debug, Clone, Copy)]
enum FundingPath {
    /// L2 include-queue admission — a write into a state already known bad.
    L2Write,
    /// An L1 payment carrying an output to the deposit sink — it debits L1 and
    /// credits L2, so it grows both sides of a bound that is already broken.
    Deposit,
}

impl FundingPath {
    fn what(self) -> &'static str {
        match self {
            FundingPath::L2Write => "L2 write",
            FundingPath::Deposit => "deposit",
        }
    }
}

/// Decision 17 — the conservation-breach refusal.
///
/// When the joint-supply bound is broken, value exists that should not, and any
/// further funding-shaped write makes the accounting worse. The approved
/// response is to refuse exactly those writes, name conservation in the error,
/// and keep every read up (`/v1/conservation`, `/metrics`, blocks, UTXO and
/// balance queries) so an operator can see what happened. Halt (process exit)
/// was rejected: a crash-loop converts a safety alarm into a liveness loss and
/// destroys the diagnostics.
///
/// Recomputed per request from the one `crate::conservation` implementation the
/// endpoint, the exporter and `verify` all share, so the three cannot disagree
/// about whether there is a breach. No state is discarded and nothing is cached:
/// recovery is the operator restarting once the cause is understood, and the
/// check immediately reports all-clear.
fn refuse_funding_if_breached(
    sh: &SharedNode,
    path: FundingPath,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let report = conservation_report(&sh.chain, &sh.l2);
    if report.ok() {
        return Ok(());
    }
    let detail = report
        .first_error()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "conservation check failed".to_string());
    // Loud on every refusal, not just the first: an operator grepping logs must
    // see the condition is still live rather than infer it from silence.
    eprintln!(
        "CONSERVATION BREACH — refusing {}: {detail} (joint {} of {} sat)",
        path.what(),
        report.supply.joint_sat,
        report.supply.bound_sat()
    );
    Err(fail(
        StatusCode::SERVICE_UNAVAILABLE,
        "conservation_breach",
        format!(
            "refusing {}: joint supply is not conserved ({detail}); reads stay available — see GET /v1/conservation",
            path.what()
        ),
    ))
}

/// Refuse a funding path whose payload does not need to be inspected.
///
/// Used by `/v1/l2/broadcast`: the node refuses the *path* while the bound is
/// broken, so it does not decode, validate or queue a payload it would only
/// discard. The deposit path cannot use this — a payment has to be parsed to
/// know it carries a sink output — so there the check runs after decode.
fn ensure_funding_allowed(
    state: &ApiState,
    path: FundingPath,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    with_shared(state, |sh| refuse_funding_if_breached(sh, path))?
}

#[derive(Deserialize)]
struct TxBroadcastReq {
    signed_tx_hex: String,
}

async fn tx_broadcast(State(state): State<ApiState>, Json(req): Json<TxBroadcastReq>) -> ApiResult {
    let bytes = decode_hex_bytes(&req.signed_tx_hex, "signed_tx")?;
    let tx = Transaction::deserialize(&bytes).map_err(|e| bad(format!("tx decode: {e}")))?;
    let txid = tx.txid();
    with_shared(&state, |sh| {
        // Only a deposit is funding-shaped. An ordinary payment still relays:
        // freezing all of L1 would stop the chain without fixing the number.
        // Checked after decode so a malformed transaction stays a client error
        // (`bad_request`) rather than being reported as a breach refusal.
        let sink = sh.chain.params().l2_deposit_sink();
        if tx.outputs.iter().any(|o| o.address == sink) {
            refuse_funding_if_breached(sh, FundingPath::Deposit)?;
        }
        let outcome = sh.pool.add(
            tx,
            sh.chain.utxo(),
            sh.chain.height() + 1,
            sh.chain.params(),
            sh.chain.expected_base_fee_for_next_block(),
            sh.chain.bonds(),
        );
        match outcome {
            Ok(txid) => {
                sh.tx_to_relay.push(txid);
                Ok(Json(json!({ "tx_hash": hash_to_hex(&txid) })))
            }
            // Idempotent: the same signed transaction arriving twice is the
            // same request, not an error — dedup is by txid.
            Err(jnt_core::mempool::MempoolError::AlreadyKnown) => Ok(Json(
                json!({ "tx_hash": hash_to_hex(&txid), "already_known": true }),
            )),
            Err(e) => Err(fail(StatusCode::BAD_REQUEST, "tx_refused", e.to_string())),
        }
    })?
}

#[derive(Deserialize)]
struct L2BroadcastReq {
    l2_tx_hex: String,
}

async fn l2_broadcast(State(state): State<ApiState>, Json(req): Json<L2BroadcastReq>) -> ApiResult {
    // Decision 17, before anything else: on a breached node this write path is
    // refused outright, ahead of decode, dedup and the dry-run — the node
    // refuses the path, not the payload, and does no work it would only throw
    // away. Reads are untouched, so an operator can still diagnose.
    ensure_funding_allowed(&state, FundingPath::L2Write)?;
    let bytes = decode_hex_bytes(&req.l2_tx_hex, "l2_tx")?;
    let tx = L2Transaction::deserialize(&bytes).map_err(|e| bad(format!("l2 tx decode: {e}")))?;
    let txid = tx.txid();
    with_shared(&state, |sh| {
        if sh.l2_to_include.iter().any(|t| t.txid() == txid) {
            return Ok(Json(
                json!({ "txid": hash_to_hex(&txid), "already_queued": true }),
            ));
        }
        // Dry-run against a *clone*: the real L2 state is derived from
        // canonical blocks only (SPEC §19.1). Advisory verdict — replay at
        // inclusion height is still the authority.
        sh.l2
            .check(&tx, sh.chain.height() + 1)
            .map_err(|e| fail(StatusCode::CONFLICT, "l2_refused", format!("{e}")))?;
        sh.l2_to_include.push(tx);
        Ok(Json(json!({ "txid": hash_to_hex(&txid), "queued": true })))
    })?
}

#[derive(Deserialize)]
struct AuthorizeReq {
    /// Canonical `SpendPolicy` encoding (public: policies hold rules, keys).
    policy_hex: String,
    /// Owner signature over `SpendPolicy::signing_hash` (hybrid bundle).
    policy_sigs_hex: Option<String>,
    /// Owner public keys, whose address must be the policy's `owner`.
    policy_keys_hex: Option<String>,
    /// The ancestry for a delegated policy, oldest first. Required — and
    /// validated — whenever the policy names a parent.
    chain_hex: Option<Vec<String>>,
    /// Canonical `PaymentRequest` encoding — must be signed by the payer.
    request_hex: String,
    /// Strictly increasing per policy; the caller's own anti-replay counter.
    nonce: u64,
}

/// Decode a hex-encoded policy and check that the owner signed it.
///
/// A policy is authority: per-transaction caps, recipient allow lists, validity
/// window. A route that accepts policy bytes without the owner's signature is a
/// route where anyone may mint authority for anyone else — which is the widening
/// a delegation chain exists to prevent, arriving one step earlier. The owner's
/// keys must derive to the address the policy names as `owner`, and the
/// signature must verify over `signing_hash`, which covers every field.
fn decode_owned_policy(
    hex_str: &str,
    field: &str,
    sigs_hex: &Option<String>,
    keys_hex: &Option<String>,
) -> Result<jnt_core::agent::SpendPolicy, (StatusCode, Json<ErrorBody>)> {
    let bytes = decode_hex_bytes(hex_str, field)?;
    let policy = jnt_core::agent::SpendPolicy::deserialize(&bytes)
        .map_err(|e| bad(format!("{field}: {e}")))?;
    let (sigs_hex, keys_hex) = match (sigs_hex, keys_hex) {
        (Some(s), Some(k)) => (s, k),
        _ => {
            return Err(bad(format!(
                "{field} must carry the owner's signature over its signing hash"
            )))
        }
    };
    let sigs = decode_bundle(sigs_hex, "policy_sigs")?;
    let keys = decode_bundle(keys_hex, "policy_keys")?;
    let signing_key = keys
        .address()
        .map_err(|e| bad(format!("policy_keys: {e}")))?;
    if signing_key != policy.owner {
        return Err(bad(format!(
            "{field}: the signing key is not the policy's owner"
        )));
    }
    jnt_core::sig::verify_bundle(&sigs, &keys, &policy.signing_hash())
        .map_err(|e| bad(format!("{field}: {e}")))?;
    Ok(policy)
}

async fn authorize(State(state): State<ApiState>, Json(req): Json<AuthorizeReq>) -> ApiResult {
    let policy = decode_owned_policy(
        &req.policy_hex,
        "policy",
        &req.policy_sigs_hex,
        &req.policy_keys_hex,
    )?;
    let request_bytes = decode_hex_bytes(&req.request_hex, "request")?;
    let request = jnt_core::service::PaymentRequest::deserialize(&request_bytes)
        .map_err(|e| bad(format!("request: {e}")))?;
    // A delegated policy is authorized with, and only with, its ancestry: the
    // bytes that prove which root's authority it narrows.
    let chain = decode_chain(&req.chain_hex, "chain")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let auth = authorize_request_with_chain(
            &mut sh.policies,
            &mut sh.delegations,
            &policy,
            &chain,
            &network,
            &request,
            height,
            req.nonce,
        )
        .map_err(session_err)?;
        // Remember the policy under the hash the authorization carries, so
        // admission later can check the payment names a policy this engine
        // actually issued under. Idempotent: the same bytes hash the same.
        sh.policy_registry.insert(auth.policy_hash, policy.clone());
        // Unsigned: the *owner* signs `signing_hash` with their wallet. The
        // API never signs and never sees a key.
        Ok(Json(json!({
            "authorization_hex": hex::encode(auth.serialize()),
            "signing_hash": hash_to_hex(&auth.signing_hash()),
            "policy_hash": hash_to_hex(&auth.policy_hash),
            "agent_id": hex::encode(auth.agent_id),
            "delegation_depth": sh.delegations.depth_of(&policy),
            "amount_sat": auth.amount_sat,
            "nonce": auth.nonce,
            "height": auth.height,
            "note": "sign signing_hash with the policy owner's wallet, then use the payment layer",
        })))
    })?
}

/// Decode a presented delegation chain, oldest first. An empty list is a root
/// spend; a non-empty one must be a chain, and it is validated against the
/// narrowing rule before the caller uses it.
fn decode_chain(
    items: &Option<Vec<String>>,
    field: &str,
) -> Result<Vec<jnt_core::agent::SpendPolicy>, (StatusCode, Json<ErrorBody>)> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, hex_str) in items.iter().enumerate() {
        let bytes = decode_hex_bytes(hex_str, field)?;
        let policy = jnt_core::agent::SpendPolicy::deserialize(&bytes)
            .map_err(|e| bad(format!("{field}[{i}]: {e}")))?;
        out.push(policy);
    }
    if out.len() > jnt_core::delegation::MAX_DELEGATION_DEPTH {
        return Err(bad(format!(
            "{field} is {} policies deep, over the cap of {}",
            out.len(),
            jnt_core::delegation::MAX_DELEGATION_DEPTH
        )));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct DelegationLinkReq {
    /// The parent policy bytes: the delegator whose authority is being narrowed.
    parent_policy_hex: String,
    /// The child policy bytes: the delegate, already dominated by `parent`.
    child_policy_hex: String,
    /// Owner signatures over each policy, in the same order: parent first.
    parent_sigs_hex: Option<String>,
    parent_keys_hex: Option<String>,
    child_sigs_hex: Option<String>,
    child_keys_hex: Option<String>,
}

/// `POST /v1/delegation/link` — register a parent→child delegation link through
/// the node's lineage authority.
///
/// Delegation is a policy-layer narrowing (SPEC §18.2.1), not a consensus rule,
/// but the engine that issued the policies is the only party that may attest to
/// a lineage. Registering here is optional for admission — a chain is still
/// validated by `delegation::assert_chain` wherever it is presented — and the
/// link book is node-local so a refusal never changes a block's validity.
async fn delegation_link(
    State(state): State<ApiState>,
    Json(req): Json<DelegationLinkReq>,
) -> ApiResult {
    let parent = decode_owned_policy(
        &req.parent_policy_hex,
        "parent_policy",
        &req.parent_sigs_hex,
        &req.parent_keys_hex,
    )?;
    let child = decode_owned_policy(
        &req.child_policy_hex,
        "child_policy",
        &req.child_sigs_hex,
        &req.child_keys_hex,
    )?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        // Lineage only makes sense within one network; a cross-network link is
        // refused by `dominates` as `NetworkMismatch`, which is the right error.
        if parent.network_id != network || child.network_id != network {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "delegation_refused",
                "delegation must be scoped to this node's network",
            ));
        }
        match sh.delegations.link(&parent, &child) {
            Ok(()) => {
                // Let admission resolve the child as a known policy, the same way
                // `/v1/authorize` records a granted policy under its hash.
                sh.policy_registry.insert(child.hash(), child.clone());
                Ok(Json(json!({
                    "linked": true,
                    "child_policy_hash": hash_to_hex(&child.hash()),
                    "depth": sh.delegations.depth_of(&child),
                })))
            }
            Err(e) => Err(fail(
                StatusCode::CONFLICT,
                "delegation_refused",
                e.to_string(),
            )),
        }
    })?
}

fn session_err(e: SessionError) -> (StatusCode, Json<ErrorBody>) {
    // Refusals by the policy engine are conflicts (the policy said no);
    // malformed material is a client error. Both are non-2xx; the detail
    // names the exact clause.
    match &e {
        SessionError::Policy(_) => fail(StatusCode::CONFLICT, "policy_refused", e.to_string()),
        SessionError::Binding(_) => fail(StatusCode::CONFLICT, "session_binding", e.to_string()),
        _ => bad(e.to_string()),
    }
}

#[derive(Deserialize)]
struct PaymentSubmitReq {
    payment_hex: String,
    /// Canonical `Authorization` encoding the payment claims to be spending
    /// under. Required: a machine payment without its grant is not admitted.
    authorization_hex: String,
    /// The owner's signature over the authorization's signing hash, and the
    /// public key bundle it verifies against.
    auth_sigs_hex: String,
    auth_keys_hex: String,
}

/// Decode a signature/key bundle from its canonical bytes.
fn decode_bundle(
    hex_str: &str,
    what: &str,
) -> Result<jnt_core::sig::Bundle, (StatusCode, Json<ErrorBody>)> {
    let bytes = decode_hex_bytes(hex_str, what)?;
    let mut r = jnt_core::ser::Reader::new(&bytes);
    jnt_core::sig::Bundle::from_reader(&mut r).map_err(|e| bad(format!("{what}: {e}")))
}

/// Revoke a policy this node has issued under.
///
/// The statement is the owner's: the same policy with `revoked` set, signed by
/// the owner. The node maps it back to the hash it actually authorized by
/// clearing the flag — only possible because the encoding is known — and records
/// that hash as revoked. Nothing else may revoke: a revocation signed by anyone
/// else is a griefing vector, not a kill switch.
#[derive(Deserialize)]
struct PolicyRevokeReq {
    policy_hex: String,
    sigs_hex: String,
    keys_hex: String,
}

async fn policy_revoke(
    State(state): State<ApiState>,
    Json(req): Json<PolicyRevokeReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.policy_hex, "policy")?;
    let variant = jnt_core::agent::SpendPolicy::deserialize(&bytes)
        .map_err(|e| bad(format!("policy: {e}")))?;
    let sigs = decode_bundle(&req.sigs_hex, "sigs")?;
    let keys = decode_bundle(&req.keys_hex, "keys")?;
    with_shared(&state, |sh| {
        // The statement must be the owner's, over exactly these bytes.
        let owner = keys.address().map_err(|e| bad(format!("keys: {e}")))?;
        if owner != variant.owner {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "policy_revoked",
                "the revocation is signed by someone other than the policy owner",
            ));
        }
        jnt_core::sig::verify_bundle(&sigs, &keys, &variant.signing_hash())
            .map_err(|e| bad(format!("revocation signature: {e}")))?;
        // Map back to the hash the engine issued under.
        let mut original = variant.clone();
        original.revoked = false;
        if !sh.policy_registry.contains_key(&original.hash()) {
            return Err(fail(
                StatusCode::CONFLICT,
                "policy_refused",
                "this node never issued under the policy being revoked",
            ));
        }
        let was_new = sh.revoked_policies.insert(original.hash());
        // Revocation propagates down the recorded lineage: a kill switch on an
        // ancestor that left its descendants live would not be a kill switch at
        // all. The book's own edges decide who is downstream, so a node cannot
        // be asked to revoke a link it never recorded.
        let descendants: Vec<[u8; 32]> = sh
            .delegations
            .descendants_of(&original.hash())
            .into_iter()
            .collect();
        let mut propagated = 0usize;
        for hash in descendants {
            if sh.revoked_policies.insert(hash) {
                propagated += 1;
            }
        }
        Ok(Json(json!({
            "policy_hash": hash_to_hex(&original.hash()),
            "revoked": was_new,
            "descendants_revoked": propagated,
        })))
    })?
}

async fn payment_submit(
    State(state): State<ApiState>,
    Json(req): Json<PaymentSubmitReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.payment_hex, "payment")?;
    let payment = MachinePayment::deserialize(&bytes).map_err(|e| bad(format!("payment: {e}")))?;
    let auth_bytes = decode_hex_bytes(&req.authorization_hex, "authorization")?;
    let authorization = jnt_core::agent::Authorization::deserialize(&auth_bytes)
        .map_err(|e| bad(format!("authorization: {e}")))?;
    let auth_sigs = decode_bundle(&req.auth_sigs_hex, "auth_sigs")?;
    let auth_keys = decode_bundle(&req.auth_keys_hex, "auth_keys")?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        let height = sh.chain.height();
        let id = payment.signing_hash();
        // A revoked policy admits nothing further, whatever else is in order —
        // and that includes a policy whose *ancestor* was revoked, which is why
        // the whole chain is checked rather than the hash the payment names.
        let mut revoked_in_chain = sh.revoked_policies.contains(&payment.policy_hash);
        for ancestor in &payment.chain {
            if sh.revoked_policies.contains(&ancestor.hash()) {
                revoked_in_chain = true;
            }
        }
        if revoked_in_chain {
            return Err(fail(
                StatusCode::CONFLICT,
                "policy_revoked",
                "the policy this payment names, or an ancestor of it, has been revoked by its owner",
            ));
        }
        // A delegated spend must be under a lineage this node recorded. The
        // chain bytes are signed, which proves they narrow; recording proves the
        // links are the ones this node accepted, so an unrecorded ancestor is
        // not authority the node can vouch for.
        if !payment.chain.is_empty() {
            let recorded = sh.delegations.chain_of(payment.chain.last().unwrap());
            let provable = recorded.as_ref().map(|chain| {
                chain.len() == payment.chain.len()
                    && chain
                        .iter()
                        .zip(payment.chain.iter())
                        .all(|(a, b)| a.hash() == b.hash())
            });
            if provable != Some(true) {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "payment_refused",
                    "the delegation chain this payment names is not a lineage this node recorded",
                ));
            }
        }
        // An exact re-submission is idempotent, and it is answered *before*
        // admission: a second admission would reserve the same value twice, and
        // the second reservation would be refused for a payment that is already
        // recorded. Replay is not a refusal; it is a repeat of the first answer.
        if sh.payment_tracker.contains(&id) {
            return Ok(Json(json!({
                "payment_id": hash_to_hex(&id),
                "duplicate": true,
            })));
        }
        // Admission first: the payment must be what an authentic, live policy
        // granted. A payment that names a policy this node never authorized
        // under — or one that has since expired, or one whose authorization is
        // not signed by the owner — is refused before it touches the replay
        // tracker and before any credit is encumbered.
        let policy = match sh.policy_registry.get(&payment.policy_hash).cloned() {
            Some(policy) => policy,
            None => {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "payment_refused",
                    "the policy this payment names was never authorized under on this node",
                ));
            }
        };
        payment
            .verify(&network, height)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "payment_refused", e.to_string()))?;
        let presented = jnt_core::service::AuthPresentation {
            auth: &authorization,
            sigs: &auth_sigs,
            keys: &auth_keys,
        };
        let reservation = jnt_core::service::admit_payment(
            &sh.policies,
            &policy,
            &payment,
            presented,
            &network,
            height,
            &mut sh.credit,
        )
        .map_err(session_err)?;
        match sh.payment_tracker.accept(&payment, &network, height) {
            Ok(id) => {
                // The payment is recorded, so the reservation it holds is real:
                // it stays until the receipt settles it (§19.4), or until it is
                // released because the payment never committed.
                sh.payment_store.insert(id, payment);
                sh.reservations.insert(id, reservation);
                Ok(Json(
                    json!({ "payment_id": hash_to_hex(&id), "duplicate": false }),
                ))
            }
            // Same bytes, same id: an idempotent re-submission, not an error.
            Err(jnt_core::payment::PaymentError::AlreadySeen) => {
                let _ = sh.credit.release(&reservation);
                Ok(Json(
                    json!({ "payment_id": hash_to_hex(&id), "duplicate": true }),
                ))
            }
            Err(e) => {
                // The payment was not recorded, so the value it encumbered goes
                // straight back: a reservation for a payment nobody accepted is
                // a hold on the payer's line for nothing.
                let _ = sh.credit.release(&reservation);
                Err(fail(
                    StatusCode::BAD_REQUEST,
                    "payment_refused",
                    e.to_string(),
                ))
            }
        }
    })?
}

#[derive(Deserialize)]
struct ReceiptSubmitReq {
    receipt_hex: String,
}

async fn receipt_submit(
    State(state): State<ApiState>,
    Json(req): Json<ReceiptSubmitReq>,
) -> ApiResult {
    let bytes = decode_hex_bytes(&req.receipt_hex, "receipt")?;
    let receipt = jnt_core::receipt::ServiceReceipt::deserialize(&bytes)
        .map_err(|e| bad(format!("receipt: {e}")))?;
    with_shared(&state, |sh| {
        let network = sh.chain.params().network_id.clone();
        // Validate and bind before anything is recorded or debited. A receipt
        // that cannot be bound to a recorded payment must not reach the book,
        // because the book is what makes a conflicting receipt impossible.
        receipt
            .verify(&network)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "receipt_refused", e.to_string()))?;
        if let Some(payment) = sh.payment_store.get(&receipt.payment_id) {
            receipt
                .verify_binding(payment)
                .map_err(|e| fail(StatusCode::BAD_REQUEST, "receipt_refused", e.to_string()))?;
        }
        // A re-submitted receipt is idempotent, and it is answered before any
        // debit: the second call must not debit again. A *contradicting* receipt
        // for the same payment is not a replay, it is a second claim, and the
        // book refuses it — so the two are distinguished by id, not by order.
        if sh.receipts.by_receipt_id(&receipt.receipt_id()).is_some() {
            return Ok(Json(json!({
                "receipt_id": hash_to_hex(&receipt.receipt_id()),
                "outcome": "duplicate",
            })));
        }
        if let Some(existing) = sh.receipts.by_payment_id(&receipt.payment_id) {
            let existing = existing.receipt_id();
            return Err(fail(
                StatusCode::CONFLICT,
                "receipt_conflict",
                format!(
                    "another receipt {} already claims this payment",
                    hash_to_hex(&existing)
                ),
            ));
        }
        // Settlement event (roadmap item 10 / §19.4): the admission-time
        // reservation commits as a real debit against the payer's credit line.
        // The reservation is taken out of the map *before* the receipt is
        // accepted, so a debit that fails leaves nothing half-applied and the
        // reservation is still available for the retry.
        if let Some(reservation) = sh.reservations.remove(&receipt.payment_id) {
            if let Err(e) = sh.credit.settle(&reservation) {
                sh.reservations.insert(receipt.payment_id, reservation);
                return Err(fail(
                    StatusCode::CONFLICT,
                    "credit_settle_failed",
                    format!(
                        "receipt {} refused: credit settlement failed: {e}",
                        hash_to_hex(&receipt.receipt_id())
                    ),
                ));
            }
        }
        match sh.receipts.accept(&receipt, &network) {
            Ok(outcome) => Ok(Json(json!({
                "receipt_id": hash_to_hex(&receipt.receipt_id()),
                "outcome": match outcome {
                    ReceiptOutcome::Inserted => "inserted",
                    ReceiptOutcome::Duplicate => "duplicate",
                },
            }))),
            Err(jnt_core::receipt::ReceiptError::PaymentConflict { existing }) => Err(fail(
                StatusCode::CONFLICT,
                "receipt_conflict",
                format!(
                    "another receipt {} already claims this payment",
                    hash_to_hex(&existing)
                ),
            )),
            Err(e) => Err(fail(
                StatusCode::BAD_REQUEST,
                "receipt_refused",
                e.to_string(),
            )),
        }
    })?
}

/// `GET /v1/exit/crankable?claimant=<address>` — the exit claims this node could
/// settle right now, as encoded bytes ready to drop into a block.
///
/// The crank is permissionless by design (SPEC.md §19.6): consensus pays only
/// the destination the proven L2 record names, and the exit fee was prepaid by
/// the owner at queue time, so nothing depends on who builds the block. Until
/// now the only way to obtain a claim was to be the node's own miner. This route
/// hands them out, so a third party can build a block with them too.
///
/// Read-only and secret-free: a claim is authorised by an inclusion proof
/// against the committed L2 root, never by a signature, so returning one grants
/// no power it does not already have. `claimant` is where the prepaid fee goes
/// and is *not* trusted for anything else.
///
/// Returns 200 with `crankable` (possibly empty) and `queued`, the number of
/// exits still awaiting release, because an empty list with exits pending is
/// the exact-funding case the node cannot help (see `NodeL2::crank_claims`).
async fn exit_crankable(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(raw) = query.get("claimant") else {
        return Err(bad("claimant address is required (?claimant=<address>)"));
    };
    let claimant = decode_address(raw)?;
    with_shared(&state, |sh| {
        if !sh.chain.exit_active_at(sh.chain.height() + 1) {
            return Err(fail(
                StatusCode::CONFLICT,
                "exits_inactive",
                "this profile has no exit activation height, so no exit can be claimed \
                 (exit_activation_height = 0 means never)",
            ));
        }
        let crankable: Vec<Value> = sh
            .l2
            .crank_claims(&sh.chain, claimant)
            .iter()
            .map(|claim| {
                json!({
                    "encoding": "hex",
                    "bytes": hex::encode(claim.serialize()),
                    "claim_id": hash_to_hex(&claim.claim_id()),
                    "owner": address_to_hex(&claim.owner),
                    "nonce": claim.nonce,
                    "amount_sat": claim.amount_sat,
                    "destination": address_to_hex(&claim.destination),
                    "exit_fee_sat": claim.exit_fee_sat,
                    "queued_height": claim.queued_height,
                    "gas_used": claim.gas_used(),
                })
            })
            .collect();
        Ok(Json(json!({
            "claimant": address_to_hex(&claimant),
            "crankable": crankable,
            "crankable_count": crankable.len(),
            "queued": sh.l2.pending_exits().len(),
            "unbacked_claims": sh.l2.unbacked_claims().len(),
        })))
    })?
}

// ---------------------------------------------------------------------------
// Credit (roadmap item 2 wiring; non-consensus)
// ---------------------------------------------------------------------------
/// `POST /v1/credit/deposit` — fund an address's credit line.
///
/// Item 2 wiring only: this mints a *credit* balance in `CreditBook`, not an L1
/// coin. It exists so the credit gate can be exercised end-to-end (the book is
/// otherwise empty and every admission would refuse). A production node would
/// gate this behind an L1 deposit proof; in this crate the gate is pure
/// arithmetic and consensus-neutral regardless.
#[derive(Deserialize)]
struct CreditDepositReq {
    address_hex: String,
    amount_sat: u64,
}

async fn credit_deposit(
    State(state): State<ApiState>,
    Json(req): Json<CreditDepositReq>,
) -> ApiResult {
    let addr = decode_address(&req.address_hex)?;
    with_shared(&state, |sh| {
        sh.credit
            .deposit(addr, req.amount_sat)
            .map_err(|e| fail(StatusCode::BAD_REQUEST, "credit_refused", e.to_string()))?;
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "balance": sh.credit.free(&addr),
        })))
    })?
}

/// `GET /v1/credit/balance/{address}` — free balance + bond + live positions.
async fn credit_balance(State(state): State<ApiState>, Path(addr): Path<String>) -> ApiResult {
    let addr = decode_address(&addr)?;
    with_shared(&state, |sh| {
        let free = sh.credit.free(&addr);
        let bond = sh.credit.bond(&addr);
        let reserved = sh.credit.reserved_by(&addr);
        let positions: Vec<_> = sh
            .credit
            .live_positions()
            .filter(|(_, p)| p.borrower == addr)
            .map(|(id, p)| {
                json!({
                    "position_id": hash_to_hex(id),
                    "amount_sat": p.amount_sat,
                    "bond_sat": p.bond_sat,
                    "collateral_sat": p.collateral_sat,
                    "deadline_height": p.deadline_height,
                    "state": match p.state {
                        jnt_core::credit::PositionState::Drawn { .. } => "drawn",
                        jnt_core::credit::PositionState::Repaid { .. } => "repaid",
                        jnt_core::credit::PositionState::Defaulted { .. } => "defaulted",
                    },
                })
            })
            .collect();
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "free_balance": free,
            "reserved": reserved,
            "available": sh.credit.available(&addr),
            "bond": bond,
            "bond_pledged": bond.saturating_sub(sh.credit.unpledged_bond(&addr)),
            "positions": positions,
        })))
    })?
}

// ---------------------------------------------------------------------------
// Credit position lifecycle (roadmap item 2; non-consensus).
//
// These routes are the operations the payment path only *reads*: posting and
// releasing bonds, opening a position, repaying it, and settling one that
// reached its deadline unpaid. Without them the position machinery has no
// caller outside the core unit tests, and "the full credit lifecycle" is a
// claim about arithmetic nobody can exercise.
// ---------------------------------------------------------------------------

/// `POST /v1/credit/bond` — move free balance into a posted bond.
///
/// A bond is the discount a position is priced with, so it has to be real value
/// the agent already holds. It is not coins: nothing here touches the ledger.
#[derive(Deserialize)]
struct CreditBondReq {
    address_hex: String,
    /// `post` or `release`.
    action: String,
    amount_sat: u64,
}

async fn credit_bond(State(state): State<ApiState>, Json(req): Json<CreditBondReq>) -> ApiResult {
    let addr = decode_address(&req.address_hex)?;
    with_shared(&state, |sh| {
        match req.action.as_str() {
            "post" => {
                sh.credit
                    .post_bond(addr, req.amount_sat)
                    .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
            }
            "release" => {
                sh.credit
                    .release_bond(addr, req.amount_sat)
                    .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
            }
            other => {
                return Err(bad(format!("unknown bond action: {other}")));
            }
        }
        Ok(Json(json!({
            "address": address_to_hex(&addr),
            "bond": sh.credit.bond(&addr),
            "bond_unpledged": sh.credit.unpledged_bond(&addr),
        })))
    })?
}
/// `POST /v1/credit/open` — open a credit position under a lender's terms.
///
/// The spec is the canonical `PositionSpec` encoding, so the terms a position is
/// priced with are exactly the bytes the caller submitted and cannot drift.
#[derive(Deserialize)]
struct CreditOpenReq {
    spec_hex: String,
}

async fn credit_open(State(state): State<ApiState>, Json(req): Json<CreditOpenReq>) -> ApiResult {
    let bytes = decode_hex_bytes(&req.spec_hex, "spec")?;
    let mut r = jnt_core::ser::Reader::new(&bytes);
    let spec =
        jnt_core::credit::PositionSpec::decode(&mut r).map_err(|e| bad(format!("spec: {e}")))?;
    if r.remaining() != 0 {
        return Err(bad("spec has trailing bytes"));
    }
    with_shared(&state, |sh| {
        let id = sh
            .credit
            .open(&spec)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        let position = sh.credit.position(&id);
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "collateral_sat": position.map(|p| p.collateral_sat).unwrap_or(0),
        })))
    })?
}

/// `POST /v1/credit/repay` — repay against a position, interest first.
#[derive(Deserialize)]
struct CreditRepayReq {
    position_id: String,
    amount_sat: u64,
}

async fn credit_repay(State(state): State<ApiState>, Json(req): Json<CreditRepayReq>) -> ApiResult {
    let id = decode_hash(&req.position_id)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let repayment = sh
            .credit
            .repay(&id, req.amount_sat, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "interest_paid_sat": repayment.interest_paid_sat,
            "principal_paid_sat": repayment.principal_paid_sat,
            "remaining_debt_sat": repayment.remaining_debt_sat,
        })))
    })?
}

/// `POST /v1/credit/default` — settle an unpaid position at or after its
/// deadline. Collateral first, then the bond, never reputation.
#[derive(Deserialize)]
struct CreditDefaultReq {
    position_id: String,
}

async fn credit_default(
    State(state): State<ApiState>,
    Json(req): Json<CreditDefaultReq>,
) -> ApiResult {
    let id = decode_hash(&req.position_id)?;
    with_shared(&state, |sh| {
        let height = sh.chain.height();
        let settlement = sh
            .credit
            .default(&id, height)
            .map_err(|e| fail(StatusCode::CONFLICT, "credit_refused", e.to_string()))?;
        Ok(Json(json!({
            "position_id": hash_to_hex(&id),
            "debt_sat": settlement.debt_sat,
            "from_collateral_sat": settlement.from_collateral_sat,
            "from_bond_sat": settlement.from_bond_sat,
            "shortfall_sat": settlement.shortfall_sat,
            "excess_returned_sat": settlement.excess_returned_sat,
        })))
    })?
}

// ---------------------------------------------------------------------------
// Item 4: conditional escrow with contract-selected arbitrators (non-consensus
// state machine; coin release reuses the normal L1 exit path).
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct EscrowOpenReq {
    network_id: String,
    payer: String,
    /// The payer's BLS public key — bound into the escrow so a mutual release
    /// can only be signed by the actual party, not any key the releaser names.
    payer_bls: String,
    payee: String,
    /// The payee's BLS public key.
    payee_bls: String,
    /// The arbitrator's 48-byte BLS public key, hex. Contract-selected.
    arbitrator: String,
    amount_sat: u64,
    nonce: u64,
}

/// `POST /v1/escrow/open` — open an escrow naming a chosen arbitrator. The node
/// records the state machine only; the locked value still comes from the payer's
/// L1/L2 balance at settlement, not from this call.
async fn escrow_open(State(state): State<ApiState>, Json(req): Json<EscrowOpenReq>) -> ApiResult {
    let payer = decode_address(&req.payer)?;
    let payee = decode_address(&req.payee)?;
    let payer_key = decode_public_key(&req.payer_bls, "payer_bls")?;
    let payee_key = decode_public_key(&req.payee_bls, "payee_bls")?;
    let arbitrator = decode_public_key(&req.arbitrator, "arbitrator")?;
    let escrow = jnt_core::escrow::ConditionalEscrow::open(
        req.network_id.clone(),
        payer,
        payer_key,
        payee,
        payee_key,
        arbitrator,
        req.amount_sat,
        req.nonce,
    )
    .map_err(|e| fail(StatusCode::BAD_REQUEST, "escrow_refused", e.to_string()))?;
    let id = escrow.id();
    with_shared(&state, |sh| {
        if sh.escrows.contains_key(&id) {
            return Err(fail(
                StatusCode::CONFLICT,
                "escrow_exists",
                "an escrow with this id already exists",
            ));
        }
        sh.escrows.insert(id, escrow);
        Ok(Json(json!({ "escrow_id": hash_to_hex(&id) })))
    })?
}

/// `GET /v1/escrow/{id}` — escrow state, or 404.
async fn escrow_get(State(state): State<ApiState>, Path(id): Path<String>) -> ApiResult {
    let id = decode_hash(&id)?;
    with_shared(&state, |sh| {
        // Refresh finality first (borrows all escrows mutably), then read —
        // done in this order so the GET reflects a matured release as Finalized
        // without a second mutable borrow overlapping the lookup.
        sh.advance_escrow_finality();
        match sh.escrows.get(&id) {
            Some(e) => Ok(Json(json!({
                "escrow_id": hash_to_hex(&id),
                "payer": address_to_hex(&e.payer),
                "payee": address_to_hex(&e.payee),
                "amount_sat": e.amount_sat,
                "condition": match e.condition() {
                    jnt_core::escrow::EscrowCondition::ReleaseToPayee => "release_to_payee",
                    jnt_core::escrow::EscrowCondition::Oracle { .. } => "oracle",
                },
                "releasable": e.releasable(),
                // What an arbiter signs, and what both parties sign for a
                // mutual release. Published so a relayer can prepare a release
                // without recomputing it, and so the test can check the node is
                // asking for a signature over exactly this escrow.
                "release_hash": hash_to_hex(
                    &e.release_signing_hash(jnt_core::escrow::EscrowVerdict::ReleasedToPayee)
                ),
                "state": escrow_state_name(&e.state),
            }))),
            None => Err(fail(StatusCode::NOT_FOUND, "not_found", "no such escrow")),
        }
    })?
}

fn escrow_state_name(s: &jnt_core::escrow::EscrowState) -> &'static str {
    match s {
        jnt_core::escrow::EscrowState::Open => "open",
        jnt_core::escrow::EscrowState::ReleasedMutual { .. } => "released_mutual",
        jnt_core::escrow::EscrowState::ReleasedArbiter { .. } => "released_arbiter",
        jnt_core::escrow::EscrowState::Finalized { .. } => "finalized",
    }
}

#[derive(Deserialize)]
struct EscrowReleaseReq {
    /// One of "arbiter" or "mutual".
    mode: String,
    /// Arbiter release: a single 96-byte BLS signature.
    arbiter_sig_hex: Option<String>,
    /// Mutual release: two 96-byte BLS signatures, in payer-then-payee order.
    mutual_sigs_hex: Option<Vec<String>>,
}

/// `POST /v1/escrow/{id}/release` — release a live escrow. `arbiter` mode
/// requires a signature from the designated arbitrator; `mutual` requires both
/// parties. The released state is recorded but the coin move is deferred to
/// settlement (§19.4).
async fn escrow_release(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<EscrowReleaseReq>,
) -> ApiResult {
    let id = decode_hash(&id)?;
    let sig_to_bls = |h: Option<&String>| {
        let h = h.ok_or_else(|| bad("signature hex required"))?;
        let b = decode_hex_bytes(h, "signature")?;
        let mut s = [0u8; 96];
        if b.len() != 96 {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "escrow_refused",
                "signature must be 96 hex bytes",
            ));
        }
        s.copy_from_slice(&b);
        Ok(jnt_core::bls_checkpoint::BlsSignature(s))
    };
    let keys = jnt_core::escrow::RealBls;
    with_shared(&state, |sh| {
        let escrow = sh
            .escrows
            .get_mut(&id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found", "no such escrow"))?;
        match req.mode.as_str() {
            // The transition belongs to the escrow: this handler checks the shape
            // of what was presented, and the escrow is the only thing that
            // changes its own state.
            "arbiter" => {
                let sig = sig_to_bls(req.arbiter_sig_hex.as_ref())?;
                if !escrow.releasable() {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "escrow_refused",
                        "this escrow is gated on an oracle condition, which has no implemented verifier, so it cannot release",
                    ));
                }
                escrow
                    .release_arbiter(&sig, sh.chain.height(), &keys)
                    .map_err(|e| fail(StatusCode::CONFLICT, "escrow_refused", e.to_string()))?;
                Ok(Json(
                    json!({ "escrow_id": hash_to_hex(&id), "state": "released_arbiter" }),
                ))
            }
            "mutual" => {
                let sigs_hex = req
                    .mutual_sigs_hex
                    .ok_or_else(|| bad("mutual_sigs_hex required"))?;
                if sigs_hex.len() != 2 {
                    return Err(fail(
                        StatusCode::BAD_REQUEST,
                        "escrow_refused",
                        "a mutual release needs exactly two signatures",
                    ));
                }
                let sig_objs: Vec<_> = sigs_hex
                    .iter()
                    .map(|h| sig_to_bls(Some(h)))
                    .collect::<Result<_, _>>()?;
                // Mutual release is verified against the keys the escrow bound
                // at open time; the request only supplies the signatures.
                if !escrow.releasable() {
                    return Err(fail(
                        StatusCode::CONFLICT,
                        "escrow_refused",
                        "this escrow is gated on an oracle condition, which has no implemented verifier, so it cannot release",
                    ));
                }
                escrow
                    .release_mutual(
                        &sig_objs,
                        &[escrow.payer_key, escrow.payee_key],
                        sh.chain.height(),
                        &keys,
                    )
                    .map_err(|e| fail(StatusCode::CONFLICT, "escrow_refused", e.to_string()))?;
                Ok(Json(
                    json!({ "escrow_id": hash_to_hex(&id), "state": "released_mutual" }),
                ))
            }
            // Fail closed: an unknown release mode is a refusal, never a default.
            // A handler that guesses which rule to apply releases on the wrong
            // one.
            other => Err(fail(
                StatusCode::BAD_REQUEST,
                "escrow_refused",
                format!("unknown release mode: {other}"),
            )),
        }
    })?
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/conservation", get(conservation))
        .route("/v1/finality", get(finality))
        .route("/v1/fees", get(fee_schedule))
        .route("/v1/balance/{address}", get(balance))
        .route("/v1/utxo/{address}", get(utxos))
        .route("/v1/block/latest", get(block_latest))
        .route("/v1/block/{hash}", get(block_by_hash))
        .route("/v1/tx/{hash}", get(tx_lookup))
        .route("/v1/mempool", get(mempool_view))
        .route("/v1/tx/build", post(tx_build))
        .route("/v1/tx/broadcast", post(tx_broadcast))
        .route("/v1/l2/broadcast", post(l2_broadcast))
        .route("/v1/tasks/open", get(tasks_open))
        .route("/v1/task/{task_id}", get(task_by_id))
        .route("/v1/l2/state", get(l2_state))
        .route("/v1/vwc/{task_id}", get(vwc_by_task))
        .route("/v1/reputation/{id}", get(reputation_get))
        .route("/v1/authorize", post(authorize))
        .route("/v1/delegation/link", post(delegation_link))
        .route("/v1/policy/revoke", post(policy_revoke))
        .route("/v1/payment/submit", post(payment_submit))
        .route("/v1/payment/{payment_id}", get(payment_get))
        .route("/v1/receipt", post(receipt_submit))
        .route("/v1/receipt/{receipt_id}", get(receipt_get))
        .route("/v1/credit/deposit", post(credit_deposit))
        .route("/v1/credit/bond", post(credit_bond))
        .route("/v1/credit/open", post(credit_open))
        .route("/v1/credit/repay", post(credit_repay))
        .route("/v1/credit/default", post(credit_default))
        .route("/v1/credit/balance/{address}", get(credit_balance))
        .route("/v1/escrow/open", post(escrow_open))
        .route("/v1/escrow/{id}/release", post(escrow_release))
        .route("/v1/escrow/{id}", get(escrow_get))
        .route("/v1/exit/crankable", get(exit_crankable))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Start the API on a background thread and return the bound address.
///
/// The socket is bound here (on the caller's thread) so the caller learns the
/// real address even when it asked for port 0 — that is how tests get a free
/// port without racing. The runtime lives entirely inside the thread: it
/// exists to accept connections and parse HTTP, nothing else.
pub fn spawn(
    shared: Arc<Mutex<SharedNode>>,
    peers: Arc<AtomicUsize>,
    listen: SocketAddr,
) -> Result<SocketAddr, String> {
    if !listen.ip().is_loopback() {
        eprintln!(
            "warning: API binding {listen} is not loopback — the API is an \
             unauthenticated service surface; exposing it is an operator decision \
             (SPEC.md §19.2)"
        );
    }
    let std_listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("api bind {listen}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("api listener: {e}"))?;
    let addr = std_listener
        .local_addr()
        .map_err(|e| format!("api listener: {e}"))?;
    let app = router(ApiState { shared, peers });

    std::thread::Builder::new()
        .name("jnt-api".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("api: runtime init failed: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                // Bound inside this runtime's context so the socket registers
                // with the reactor: `from_std` must run where a reactor exists.
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("api listener conversion");
                if let Err(e) = axum::serve(listener, app).await {
                    eprintln!("api: serve error: {e}");
                }
            });
        })
        .map_err(|e| format!("api thread: {e}"))?;
    Ok(addr)
}
