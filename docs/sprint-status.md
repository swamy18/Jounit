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
| `e362dce` | Item 2: scripted end-to-end journey through the running node (`e2e_journey.rs`, 3 tests) |
| `55bdaa5` | Lock the `jnt-node` dev-dependency on `jnt-worker` (test-only, keeps the workspace buildable) |
| `df52637` | Item 3: worker↔node HTTP transport and a fail-closed L2 state wire (26 tests) |

## Measured verification (final, at `df52637`)

| Check | Result |
|---|---|
| `cargo test --workspace` | **870 passed, 0 failed** across the workspace |
| `cargo fmt --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo build --release --workspace` | succeeded (optimized, 1m32s) |

Baseline at `a8679de` was 650 passing tests. The seven commits through
`6187fec` added **76** of them; the two integration commits that followed
(`e362dce`, `df52637`) added **29** more (3 journey + 12 state-wire + 11
transport + 3 `http.rs` unit), for **105** added and 755 total. Test-count
claims were re-counted from the files: `bridge_session.rs` 17, `api.rs` 13,
`mcp.rs` 9, `reputation_flow.rs` 8, `e2e_journey.rs` 3, `state_wire.rs` 12,
`worker_transport.rs` 11, `http.rs` 3.

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
| 13/14 | End-to-end worker/agent flows | **DONE** | `crates/jnt-node/tests/e2e_journey.rs` drives one scripted journey through the real node path — mined blocks → `Chain::submit` → `NodeL2::sync` — and the real `WorkerClient` over the §18.3 seams: identity → policy → request → authorization → L2 post → claim → execute → submit → dispute → quorum settle → Quorum VWC → payment → receipt → reputation → conservation → finality → persist → restart → byte-identical state. A second test covers the undisputed path (WindowElapsed VWC) and a third a forged claim refused by name with the task untouched |
| §19.2 | Worker↔node HTTP transport | **DONE** | `jnt-worker/src/http.rs` (`HttpNode`) implements both §18.3 seams over the node's opt-in REST API; `GET /v1/l2/state` serves a versioned deterministic state blob (`state_wire.rs`, 12 tests) and `worker_transport.rs` exercises discover→claim→broadcast over a live socket plus the failure paths. Transport **authentication** is not implemented — the API is an unauthenticated loopback surface by design — see "Gaps" |
| 15 | L2 production gaps | **DONE** | Deposits, funding, finality, replay **and exits** are complete and tested (Decision 19) |
| 25 | Adversarial suites | **PARTIAL** | Existing `redteam.rs`, `bls_checkpoint_attack.rs`, per-crate `fuzz_invariants.rs` and the 17-test bridge attack suite pass; no *new* adversarial suite was added this sprint |
| 26 | Chaos harness | **NOT STARTED** | — |
| 27 | Benchmarks | **NOT STARTED** | No `benches/` and no perf numbers; nothing was measured, so none is claimed |
| 28 | SPEC reconciliation | **PARTIAL** | This document; see "SPEC reconciliation" |
| 29 | Mainnet readiness | **PARTIAL** | four open decisions remain (P2–P5) plus the mainnet `exit_activation_height`; see "Mainnet readiness" — operational scaffolding is partly present, and three genuine blockers remain |

## Blockers (precise)

1. ~~**L2 → L1 exits are blocked by an unrecorded decision.**~~ **Resolved as
   Decision 19 (2026-10-09, approved and implemented).** Decision 10's deferral
   is superseded: `ExitQueue` on L2, an inclusion-proof-authorised sink spend on
   L1, a permissionless crank in the serve loop, and the owner-prepaid
   `exit_fee_sat`. Remaining for mainnet is the `exit_activation_height`
   configuration, not protocol.
2. **Validator economics / bonding are blocked.** Decision 8 records a fixed
   genesis committee with *no* stake transaction, bond or unbonding. Rotating a
   committee without bonded stake is not authorised; Phase 6 is a fixed-committee
   bootstrap by design.
3. ~~**The 40M supply cap and issuance were frozen *at the time of this sprint*.**~~
   Decisions 7 and 10 then stated the cap, issuance paths, block rewards,
   halving schedule and both fee schedules were explicitly unchanged.
   **Decision 18 (2026-10-09) removed the cap entirely**: `supply_cap_sat` and
   `Error::SupplyCapExceeded` are gone, the mint bound is the per-height issuance
   integral `cumulative_issuance_sat(height)`, and post-ladder issuance is
   rate-anchored (≤ 1 % of the supply issued at that window's start) with a
   permanent 0.1 JNT tail floor. This paragraph records the sprint's constraint,
   which no longer matches the shipped code.
4. **Local fuzz execution is unavailable in this environment** (no ASan runtime
   for the MSVC target). Fuzz targets compile; representative *execution* is not
   claimed. *(Since superseded: campaigns now run under WSL2 + ASan — see
   `docs/fuzz.md`.)*
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
  history; the current measured count is 755 (this file).
- **Repointed a dangling reference.** The item-3 code cited `SPEC.md §19.6` for
  the state wire encoding, but **§19.6 does not exist** — the spec's Phase 6
  material ends at §19.5. All nine code and test references now cite `§19.2`,
  the subsection that actually specifies the worker↔node transport.
- **`SPEC.md §19.2` status corrected.** It was headed "SPECIFIED for M3, NOT
  IMPLEMENTED" while the transport is now built. The heading and the Phase 6
  preamble now mark §19.2 implemented, and §19.2 gained a measured
  "Implemented" / "Not implemented" pair so its authentication gap is recorded
  in the spec of record rather than only in this file. No consensus rule,
  encoding, fee or finality rule was touched by any of this.

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
build checks. **Mainnet is not declared ready**: the open items are P2–P5 plus the mainnet
`exit_activation_height` configuration — the exit path itself shipped (Decision 19).
(was: blockers 1–3 above, and
blocker 1 alone (no exits) prevents a functional economy.

## Gaps worth naming

- Reputation scores are derived in `jnt-l2` but are **not exposed** over the
  node API or MCP yet (a `GET /v1/reputation/{id}` would be the natural next
  step).
- ~~The worker↔node transport has **no authentication**: the API is an
  unauthenticated service surface, loopback binding is the only control, and a
  non-loopback bind prints a warning rather than enforcing a credential~~
  — **resolved since:** a non-loopback bind is now *refused* without a bearer
  token (`--api-token` or `JNT_API_TOKEN`), and an exposed bind additionally
  enforces Host-header validation (DNS-rebinding), a per-request deadline, a
  global in-flight cap and a per-IP rate limit, all in `jnt-node/src/api.rs`.
  Loopback remains unauthenticated by design — it is the default and what every
  test drives. What is still true: the API is a service surface and not a
  consensus surface, and the rate limiter is a token bucket per remote address,
  not a per-account quota.
- The transport is also **unexercised against a real remote node process**: the
  tests drive a live socket against an in-process server, which is a genuine
  transport test but not a two-process deployment test.
- No benchmarks exist, so no performance claim is made anywhere in this sprint.
- ~~`jnt-worker`'s CLI (`address`, `generate`) exposes no claim/submit/status
  verb~~ — **resolved since:** `jnt-worker run` ships the daemon loop
  (discover → claim → execute → submit, gated on `/v1/conservation`), exercised
  by `cli_run.rs` and the two-process E2E. `address`/`generate` remain for key
  tooling.

## Commands behind the numbers

```
cargo test --workspace                                   # 870 passed, 0 failed (supersedes older counts)
cargo fmt --check                                        # clean
cargo clippy --workspace --all-targets --all-features -- -D warnings   # clean
cargo build --release --workspace                        # see note below
```

The release build finished successfully on 2026-10-08: 1m32s measured at
`6187fec`, and 1m56s re-measured at `df52637` on the same machine, both warm.

Local fuzz *execution* was not run (no ASan runtime for the MSVC target in this
environment); the fuzz targets compile as part of `--all-targets`. No performance
number is reported because no benchmark was run.

---

## Addendum — re-measured 2026-10-09 (supersedes the counts above)

This sprint file's numbers were taken at `df52637`. `HEAD` has since moved to
`dd2e1da` (a fuzz-target fix), and the environment gap above was closed: fuzz
execution ran in WSL2. Current measured state:

| Check | Result |
|---|---|
| `cargo test --workspace` | **773 passed, 0 failed, 1 ignored** (`vwc_perf_probe`), 52 binaries |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo build --workspace --release` | succeeds |
| Fuzz campaign (WSL2 nightly + ASan, 14 targets × 30 s) | **9,352,161 executions, 0 crashes** — see `docs/fuzz.md` |
| Benchmark probes | run, real numbers recorded — see `docs/benchmarks.md` |

The `jnt-worker run` daemon verb shipped since, so the CLI limitation above no
longer stands. The exit blocker is **closed** by Decision 19 (approved and
implemented, SPEC.md §19.6) — `docs/l2-exit-design.md` is the record of the
approved design rather than a pending one, and P1 is no longer in the
*Pending* section. Local fuzz execution is available in WSL2. Remaining
blockers: P2 (stake ledger / mainnet committee), P3, P4, P5, and the mainnet
`exit_activation_height` configuration.
