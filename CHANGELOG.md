# Changelog

All notable changes to Jounit are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the workspace `version` in `Cargo.toml`.

> **Status:** Jounit is an unreleased development snapshot. There are **no git
> tags and no published release artifacts**. `0.1.0` below describes the state
> of `main` at the date shown; it is a development snapshot, not a release.
> Nothing here should be read as a mainnet-readiness claim — see
> [docs/final-report.md](docs/final-report.md) and
> [docs/mainnet-readiness.md](docs/mainnet-readiness.md).

## [Unreleased]

### Added (consensus - Decision 19, owner-approved)

- **L2 -> L1 exits (SPEC.md 19.6).** Deposits are no longer one-way.
  - L2 side: `L2TxType::ExitQueue` (`0x15`) + `ExitQueuePayload` debits
    `amount + exit_fee + queue_fee` from the owner and records the pending
    exit. Refused by name on a zero amount, a rewound or repeated nonce, an
    inactive profile or an insufficient balance; no partial state.
  - L1 side: blocks carry `exit_claims`. A claim consumes **sink outputs**
    and is authorised by an inclusion proof against the `l2_state_root`
    committed at the queue height - never a signature, since the sink holds
    no key. Exact funding only: inputs must total
    `amount + exit_fee + required L1 fee`, with no change and no tip.
  - **Permissionless crank.** `NodeL2::crank_claims` builds the matured,
    funded, proven claims and the serve loop settles them. No operator
    privilege; consensus pays only the recorded destination and the prepaid
    claimant fee, and that prepayment is what makes an unfunded crank
    impossible.
  - **Reorg-safe.** A release is an ordinary undoable L1 operation: rollback
    restores the sink outputs, clears the identity, and L2 replay regenerates
    the watch. `jnt-node/tests/exit_crank.rs` pins the whole loop with
    nobody hand-building the claim.
  - **Conservation unchanged and still holds.** The joint check needed no exit
    term at all - the L1 payment and the L2 debit cancel while the sink term
    falls by the same amount - so `tests/conservation.rs` passes untouched.
    `exited_sat` is reported by `/v1/status`, `/v1/conservation` and
    `jnt-node verify`.
  - `jnt_worker::{queue_exit, queue_exit_plan, ExitPlan}`: the SDK path for
    an owner to queue an exit, which refuses before broadcasting rather than
    after.

### Added (mechanism, part of Decision 19)

- `Chain::exit_active_at` is the single definition of the activation rule,
  shared by validation and by the miners, so the two cannot drift.
- `NodeL2::simulate_root` derives the root a replay will derive, from the
  node's own view, applying each transaction on a clone and skipping refused
  ones. The chain may not consult the L2 view - that view is what the chain
  authenticates - so the miner supplies the root instead of one being invented.
- `ChainL2::{pending_exits, ExitWatch}`: a queued exit's inclusion proof is
  captured at the queue block, where the node's root equals the block's
  committed root, so the crank never replays back to the queue height.

### Changed (consensus - Decision 19, owner-approved)

- **An L2-bearing block must commit an `l2_state_root`** once the profile
  activates exits, and must not carry one before. `exit_activation_height =
  0` means *never*, not *from genesis*: such a profile refuses both a root
  and a claim. Migrated the tests that mined rootless L2 blocks; the
  undefined-type boundary moved from `0x15` to `0x16`.

### Changed (consensus — Decision 18, owner-approved 2026-10-09)

- **The stock supply cap is gone.** `NetworkParams::supply_cap_sat` is deleted
  (all profiles) and the deprecated `Error::SupplyCapExceeded` variant is
  removed. The mint bound is the issuance integral alone; the replacement
  ceiling is the **rate anchor** — gross issuance in any post-ladder halving
  period may not exceed 1 % of the supply issued at that window's start
  (`supply::check_mint_at_height`, ladder era grandfathered). The approved tail
  sits ~3Ã— under it. `tests/vectors/supply_vectors.json` is regenerated with
  the anchor fields; the sims cross-check it.
- **Net-supply reporting.** `Chain` tracks cumulative base-fee burns
  (reorg-rewound like the PSCB reserve); `status`, `GET /v1/conservation` and
  the `/metrics` gauges (`jounit_issued_sat`, `jounit_net_supply_sat`,
  `jounit_rate_anchor_allowance_sat`) report gross issuance, removal and net.
  The old `supply_cap_sat` conservation field and `jounit_supply_cap_sat`
  gauge are removed.

### Added

- `GET /metrics` on the opt-in service API: Prometheus text exposition
  (`text/plain; version=0.0.4`) of height, finality, peers, base fee, live
  supply, rate-anchor allowance, gross issuance, net supply, PSCB reserve,
  mempool size, L1 relay queue depth, L2
  include queue depth, and L2 height/applied/skipped/pending-deposit gauges.
  Gauges only, one static `network` label, no key material or per-user data.
- `docs/decisions.md`: a *Pending monetary decisions* section (M-A … M-G) that
- `docs/decisions.md`: a *Monetary decisions* section (M-A…M-C — the tail
  decisions), which reduces `docs/monetary-redesign.md` to an analysis surface,
  so the monetary parameters sit next to the P2–P5 protocol blockers instead
  of being buried in a long proposal.

### Added (policy layer — no consensus change)

- **Streaming micro-payments (pay-as-you-use).** `crates/jnt-core/src/stream.rs`:
  a payer-signed `PaymentStream` (rate per block, window, hard cap, recipient,
  governing policy for non-human payers), payer-signed `StreamSettlement`
  receipts, and a fail-closed `StreamBook` (exact-amount, strictly-ordered,
  non-future settlement; accrual is checked, never wrapping). Settlement rides
  the ordinary payment path with `reference` = the stream id, so no new
  transaction type and no consensus rule change. Attack-first suite in
  `crates/jnt-core/tests/payment_stream.rs` (16 tests).

### Added (consensus — Decisions 20–23, owner-approved 2026-10-10)

- **Bonded stake (P2, Decision 20).** `TX_BOND`/`TX_UNBOND`/`TX_SLASH`
  (`jnt-core/src/tx.rs`, positional stake payloads; unknown `tx_type` values
  refused, never interpreted as standard) + `jnt-core/src/bond.rs` (bond
  ledger with bond-order index, pure validators shared by block application
  and mempool admission, committee = first 21 bonds). Chain integration:
  per-block undo, M2 vault advance with vesting routed to PSCB,
  `verify_canonical_chain` covers bonds and vault, finality keys follow the
  ledger (genesis fallback while empty). Mempool admits only bond-valid
  transactions; block building re-checks on a scratch ledger and skips stale
  ones instead of wedging the miner. Attack-first suite
  `tests/bond_stake.rs` (13 tests) caught a real double-count during
  development (bond output left in the UTXO set alongside the later release —
  now consumed into the ledger at apply). SPEC §3.3/§9.2/§14.6 amended.
- **Proportional settle fee (P5, Decision 23).** `settle_fee_sat` (`l2.rs`):
  0.1% of task value, minimum 1,000 sat; computed from the escrow at
  `apply_settle`, charged against the deposit on fraud with the submitter
  refunded whole. Worker estimators use the proportional fee. All pinned
  20,000-sat expectations migrated; new stress suite
  `jnt-l2/tests/settle_fee.rs` (dust boundary, 48 mixed-size tasks with exact
  50/50 split accounting, fraud-from-task-value). SPEC §15.4 amended.
- **Canonical CPU reference (P3, Decision 21).**
  `compute_ir::reference_output`/`reference_result_hash` is the single
  definition run by worker, challenger and arbitrator (no height input —
  reproducibility demands identical inputs); worker `CpuExecutor` delegates.
  `DisputeEngine::resolve` computes the reference itself from the disputed
  contract instead of taking a caller hash. Quorum-signed verdict →
  slash-record path unchanged per SPEC §16.4 (no on-chain execution, no
  interpreter). `dispute_flow.rs` arbitrates real reference outputs;
  `docs/decisions.md` records what remains (quorum coordination transport
  needs a key-custody decision). SPEC §16.6 added.
- **Exit-path audit (height still NOT flipped).** `exit_crank.rs` grew three
  tests: claim-block reorg re-cranks and settles again; queue-block reorg
  drops the watch (no phantom claim); two exits crank and settle together
  exactly once each. The batch test caught a real crank bug (two claims
  funded from the same sink output — assigned inputs now retire per exit).

### Notes

- The observability and documentation entries above are the only non-consensus
  work in this Unreleased block besides the policy-layer streaming primitive.
  The Decision-19 `### Added`/`### Changed` sections were the **first**
  consensus change since 0.1.0 — a new L2 transaction type, L1 `exit_claims`,
  and the `exit_activation_height` gate. The Decision-18 `### Changed` section
  that follows was the **second**; like it, every historical block still
  validates identically. The Decisions 20–23 `### Added` section above is the
  **third**: three new L1 transaction types, the bond ledger, the proportional
  settle fee, and the canonical CPU reference.

## [0.1.0] — 2026-10-09

Development snapshot. The full build order, with the commit that landed each
step, is recoverable from `git log`; the summary below groups it by area.

### Added

- **L1 core** (`jnt-core`): UTXO ledger, deterministic heaviest-work fork
  choice, hybrid PoW puzzle with a versioned registry, LWMA difficulty
  retarget, per-profile network identity, and a fixed-cap halving supply
  schedule (39,945,600 JNT cap; `76, 38, 19, 9, 4, 2, 1, 0` JNT ladder at a
  262,800-block halving period).
- **Fees (M1)**: EIP-1559-shaped base fee, split 50 % burned / 50 % to the
  PSCB reserve, with the odd satoshi going to the burn. The PSCB half is a
  counter that no code path converts back into UTXOs.
- **P2P** (`jnt-net`): TCP framing, magic/network-id handshake isolation,
  block and transaction relay, locator-based sync, and a bounded orphan pool.
- **L2** (`jnt-l2`): task contracts with a five-state machine, five L2
- **L2** (`jnt-l2`): task contracts with a five-state machine, six L2
  transaction types (`ExitQueue` added by Decision 19), the D3 flat fee
  schedule, dispute arbitration, and Verified Work Certificates.
  is derived by replay from canonical blocks alone; genesis-funded protocol
  escrow; user deposits via a burn-to-sink overlay.
- **Finality (M5)**: BLS12-381 aggregate checkpoint gadget with a real `blst`
  pairing core, plus equivocation evidence. Binding finality is **inactive on
  mainnet** (`finality_activation_height = 0`).
- **Machine/agent layer**: agent identity and an authorization policy engine,
  machine payments, service receipts, a reputation ledger, the service/payment
  bridge with batching, and a keyless MCP surface (`jnt-mcp`).
- **Worker SDK** (`jnt-worker`): claim/submit/dispute/VWC client flows over
  injected seams, and an HTTP transport over the node's REST API.
- **Service API** (`jnt-node`): opt-in (`--api-listen`), loopback by default,
  read/write view only — never a consensus surface, and never a signing
  surface.
- **Verification harness**: 14 `cargo-fuzz` targets, independent Python
  cross-checks of the supply schedule, difficulty retarget, puzzle and wire
  formats, and a chaos suite.

### Security

- 50/50 anti-collusion slash vault (M2) — **inert**: no rule triggers it, by
  decision.
- Red-team regression suite pinning fork-choice determinism, finality,
  apply/rollback atomicity, and input-count bounds.

### Known limitations

Recorded as blockers, not oversights, in [docs/decisions.md](docs/decisions.md):

- ~~**P1** — L2 → L1 exits are undefined.~~ **Resolved by Decision 19 (see
- **P2** — no stake/bond ledger and no mainnet validator committee
  (`mainnet` `genesis_validators` is empty, so binding finality fails closed).
- **P3** — the M2 activation rule (what proves a compute result fraudulent) is
  unspecified, so the slash vault stays inert.
- **P4** — the HBM scratchpad puzzle is not a registered `puzzle_id`; chain
  security rests on the base puzzle only.
- **P5** — a task whose escrow is below the 20,000-sat settle fee fails closed
  (`AmountTooSmallForFee`).
- ~~Monetary parameters beyond the frozen schedule … are **unapproved**.~~
  **Resolved (Decision 18, M-A…M-C, Decision M-E): the tail is approved and
  implemented, `supply_cap_sat` is deleted, and the escrow ceiling is fixed and
  validated by `NetworkParams::validate`.** No monetary parameter remains open.

[Unreleased]: https://github.com/swamy18/Jounit/commits/main
