# Sprint status — measured, 2026-10-08

This file records the state of the integrated sprint that ran on top of
`a8679de` ("Sprint step 1: machine/agent identity + authorization policy
engine"). It is a *measurement*, not a plan: every line marked DONE was
executed, and the numbers below were produced by the commands named at the
bottom. Nothing here overrides the historical records in `docs/status.md`,
`docs/decisions.md` or `SPEC.md` — those are kept as written.

## Commits added by this sprint

| Commit | Contents |
|---|---|
| `b209a31` | Bind offline authorization verification to the owner's address (+ regression test) |
| `2120f47` | Items 11/12/9 primitives: machine payment, service receipt, reputation ledger (21 unit tests across the three modules) |
| `0072a7d` | Items 2/6/5/7/8: service bridge, autonomous payments, batching (`bridge_session.rs`, 17 tests) |
| `f6e2c99` | Items 16/17: opt-in REST service API (Decision 9, SPEC §19.2) |
| `3d9ed13` | API integration tests (13) + `Authorization::deserialize` (2 tests) |
| `b800b26` | `jnt-mcp`: keyless MCP surface over the payment layer (9 tests) |
| `6187fec` | Item 9 completion: VWC/dispute-backed reputation derivation (8 tests) |

## Measured verification (this session)

| Check | Result |
|---|---|
| `cargo test --workspace` | **726 passed, 0 failed** (40 test binaries plus 7 doc-test targets) |
| `cargo fmt --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo build --release --workspace` | succeeded (optimized, 1m32s) |

Baseline at `a8679de` was 650 passing tests; this sprint added **76** tests.
Test-count claims in the commit table were re-counted from the files:
`bridge_session.rs` 17, `api.rs` 13, `mcp.rs` 9, `reputation_flow.rs` 8.

> Note: `0072a7d` added `crates/jnt-core/src/service.rs` but did not declare
> `pub mod service;` in `lib.rs`, so that commit did not compile in isolation.
> `f6e2c99` fixes the declaration. The history is left intact (no rewrite); this
> is recorded because a bisect across `0072a7d` would find a non-building
> commit.

## Roadmap matrix

Legend: **DONE** = implementation + integration + tests that pass + docs
consistent. **PARTIAL** = implemented but missing one of those. **BLOCKED** =
requires a decision not yet recorded. **NOT STARTED** = no work.

| # | Item | Status | Evidence |
|---|---|---|---|
| 11 | Machine/agent payment standard | **DONE** | `jnt-core/src/payment.rs`; canonical `jounit/machine-payment/v1`, exact inverse encode/decode, network + identity binding, replay guard; `payment.rs` unit tests + `bridge_session.rs` |
| 12 | Generic service/payment receipts | **DONE** | `jnt-core/src/receipt.rs`; deterministic `receipt_id`, `verify_binding`, conflict-safe `ReceiptBook`; unit tests + `bridge_session.rs` + API `receipt_conflict` test |
| 9 | Machine/agent reputation | **DONE** | `jnt-core/src/reputation.rs` (bounded accumulator + event, fixed weights) **and** `jnt-l2/src/reputation.rs` (VWC/dispute derivation), `tests/reputation_flow.rs`. Not yet exposed over the API — see "Gaps" |
| 2 | Bridge layer | **DONE** | `jnt-core/src/service.rs` (`derive_service_id`, `PaymentRequest`, `authorize_request`, `Session`, `PaymentBatch`); 17 privilege-escalation tests |
| 6 | Autonomous payments | **DONE** | `authorize_request` is the only request→authorization path; `Session::verify` requires a policy-governed payment to present its authorization; no receipt-shaped input exists, so a forged service response cannot authorize payment |
| 5/7/8 | Micropayments / machine-agent flows | **DONE** | `aggregate_payments` → `PaymentBatch` merges N verified payments from one payer into per-recipient outputs (one `GAS_TX_BASE` per settlement); `build_direct_payment` for the human path; exact-decimal `parse/format_amount_sat`. See "Micropayment floor" |
| 16 | Service API | **DONE** | `jnt-node/src/api.rs`; opt-in `--api-listen`, loopback default, not a consensus surface; `tests/api.rs` (13) |
| 17 | AI/compute/data payment surface | **DONE** | Payment/authorize/receipt endpoints + `jnt-mcp`; L2 broadcast dry-run only (state changes only via canonical replay) |
| MCP | `jnt-mcp` agent integration | **DONE** | `crates/jnt-mcp`; keyless dispatcher, 8 ops, node transport over the loopback API; `tests/mcp.rs` (9) |
| 13/14 | End-to-end worker/agent flows | **PARTIAL** | Worker SDK paths are covered by `jnt-worker` tests and the L2/node suites; a single scripted human→agent→service→receipt→reputation journey through the running node is **not** written |
| 15 | L2 production gaps | **PARTIAL** | Deposits, funding, finality and replay are complete and tested; **exits are blocked** (Decision 10) |
| 25 | Adversarial suites | **PARTIAL** | Existing `redteam.rs`, `bls_checkpoint_attack.rs`, per-crate `fuzz_invariants.rs` and the 17-test bridge attack suite pass; no *new* adversarial suite was added this sprint |
| 26 | Chaos harness | **NOT STARTED** | — |
| 27 | Benchmarks | **NOT STARTED** | No `benches/` and no perf numbers; nothing was measured, so none is claimed |
| 28 | SPEC reconciliation | **PARTIAL** | This document; see "SPEC reconciliation" |
| 29 | Mainnet readiness | **PARTIAL** | See "Mainnet readiness" — operational scaffolding is partly present, and three genuine blockers remain |

## Blockers (precise)

1. **L2 → L1 exits are blocked by an unrecorded decision.** Decision 10 records
   deposits via a burn-to-sink overlay and states *"Explicitly deferred
   (mainnet blocker): L2→L1 exits … No exit decision is recorded here."* Without
   exits, L2 holds value users cannot withdraw. **Do not implement exits without
   a recorded decision**; the mechanism is a new L1 rule, which this sprint was
   not authorised to invent.
2. **Validator economics / bonding are blocked.** Decision 8 records a fixed
   genesis committee with *no* stake transaction, bond or unbonding. Rotating a
   committee without bonded stake is not authorised; Phase 6 is a fixed-committee
   bootstrap by design.
3. **The 40M supply cap and issuance are frozen.** Decisions 7 and 10 state the
   cap, issuance paths, block rewards, halving schedule and both fee schedules
   are *explicitly unchanged*. Any change is a monetary-policy decision and was
   deliberately not made.
4. **Local fuzz execution is unavailable in this environment** (no ASan runtime
   for the MSVC target). Fuzz targets compile; representative *execution* is not
   claimed.
5. **`mainnet` carries no validator committee**, so checkpoint verification fails
   closed there (`NetworkParams::mainnet` has an empty `genesis_validators`).
   This is intentional, and it means binding finality is untestable on mainnet
   until a committee exists — which needs blocker 2.

## Micropayment floor (item 5/7/8 review, no consensus change)

The L1 floor is real: `min_tx_fee = required_fee(base_fee, GAS_TX_BASE)` and
`GAS_TX_BASE = 16_000`, so a one-output transaction cannot cost less than
`base_fee × 16` sat. On `mini` (`base_fee_min_sat = 10`) that is ~160 sat; on
`mainnet` (`base_fee_min_sat = 100`) ~1_600 sat per settlement.

This sprint did **not** change that. It made micropayments viable *without*
consensus changes by batching: `aggregate_payments` collapses many verified
payments from one payer into one settlement transaction, paying the gas floor
once instead of once per payment, and the D3 L2 flat schedule
(`L2_FEE_SCHEDULE`: post 5000 / claim 2000 / submit 2000 / dispute 10000 /
settle 20000 sat) prices on-L2 work separately. A true sub-160-sat *on-chain*
payment needs a consensus fee change, which is isolated as a decision, not
invented here.

## SPEC reconciliation (item 28)

- **`SPEC.md` is the L1/L2 consensus specification.** The agent/authorization
  layer and the service API are deliberately *not* consensus: `SPEC.md §19.2`
  is the additive service-API note, and the agent layer is tracked in roadmap
  §21–§22 rather than in SPEC. No consensus rule was added, removed or silently
  changed by this sprint.
- The API is stated in code, in `SPEC.md §19.2` and in `docs/decisions.md`
  (Decision 9) consistently: opt-in, loopback default, never a consensus
  surface, L2 state derived from canonical blocks alone.
- `jnt-core` gained `service` (bridge), `payment`, `receipt` and `reputation`
  modules, and `jnt-l2` gained `reputation`. All are additive; no existing
  encoding, hashing or state-transition rule changed.
- `docs/status.md` still quotes 650 tests and older counts. That is left as
  history; the current measured count is 726 (this file).

## Mainnet readiness (item 29)

Present and verified: network profiles (`mainnet`/`testnet`/`mini`),
genesis + params validation, `jnt-node` CLI (`init`, `mine`, `send`, `balance`,
`verify`, `show-block`, `wallet`, `export`, `serve`), a health/status surface
(`GET /v1/health`, `/v1/status`, `/v1/finality`, `/v1/fees`), deterministic
block/tx hashing with domain separation, restart/replay and reorg derivation
tests, and a documented decision log.

Not built here: monitoring hooks beyond the REST surface, backup/recovery run
books, versioning/upgrade-compatibility policy, a testnet launch procedure, a
security-disclosure process, a release checklist, and deterministic/`reproducible`
build checks. **Mainnet is not declared ready**: blockers 1–3 above are open, and
blocker 1 alone (no exits) prevents a functional economy.

## Gaps worth naming

- Reputation scores are derived in `jnt-l2` but are **not exposed** over the
  node API or MCP yet (a `GET /v1/reputation/{id}` would be the natural next
  step).
- The worker SDK's `L2NodeView` trait returns a full `L2State`, which has no wire
  encoding, so the worker↔node HTTP transport (Decision 9's other half) is still
  unimplemented; the API exists but nothing in `jnt-worker` consumes it.
- No benchmarks exist, so no performance claim is made anywhere in this sprint.

## Commands behind the numbers

```
cargo test --workspace                                   # 726 passed, 0 failed
cargo fmt --check                                        # clean
cargo clippy --workspace --all-targets --all-features -- -D warnings   # clean
cargo build --release --workspace                        # see note below
```

The release build finished successfully in 1m32s on 2026-10-08.

Local fuzz *execution* was not run (no ASan runtime for the MSVC target in this
environment); the fuzz targets compile as part of `--all-targets`. No performance
number is reported because no benchmark was run.
