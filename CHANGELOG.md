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

### Fixed (security)

Full write-up in [docs/security-audit-2026-10-11.md](docs/security-audit-2026-10-11.md).

- **A worker-chosen deposit made a fraud verdict unreachable, which meant a
  dishonest worker could take the whole escrow.** `TaskContract::claim` accepted
  any deposit above zero, but the settle fee is derived from the escrow
  (Decision 23), and the `Fraudulent` arm of `settle_inner` refuses when
  `deposit < fee`. A worker could claim with a dust deposit, submit a wrong
  result, and become structurally unslashable: once a result is submitted,
  `Expired` is no longer reachable either, leaving the free auto-settle `Correct`
  as the only settlement left. The worker collected the entire escrow for work
  that is provably wrong, and the penalty was a number they chose themselves.
  `claim` now refuses a deposit below `settle_fee_sat(payment_sat)`, so a fraud
  verdict is always reachable. `payment_sat` is fixed at post time, so the floor
  cannot be dodged later.
- **Miner and validator disagreed on the next base fee, wedging the chain after
  any exit claim.** `build_block` and `expected_base_fee_for_next_block` folded
  the parent's `claims_gas_used()` into the next block's base fee; `apply_block`
  used `total_gas_used()` alone. After a block carrying a claim - which
  `check_claim` makes permissionless - the miner produced a strictly higher fee
  than the validator expected and the node rejected its own next block with
  `BadFee`. `apply_block` now counts claim gas, matching the miner term for term.
  A `next_base_fee` clamp hides this while the fee sits at its bounds, so no
  existing test caught it.

### Known issues

- **L1 does not recompute the committed L2 state root** (`check_claim` trusts
  `block.l2_state_root` rather than matching it against an L2 replay), so a
  miner can commit a root over a state nobody else holds and prove a fabricated
  exit record against it. Not fixed here: `jnt-l2` depends on `jnt-core`, so
  closing it needs a dependency inversion or a consensus-path change rather than
  a surgical patch. `mainnet.exit_activation_height` is `0`, so the sink is not
  exposed on mainnet as shipped - **testnet and mini are**. See the audit
  document for detail.

### Added (attribution)

- **Authorship is now recorded throughout the project.** The code carried no
  `authors` field, the licence files named a holder that was not a person, and
  the Apache-2.0 boilerplate still had its unfilled `[yyyy] [name of copyright
  owner]` placeholder. All three are fixed:
  - `Cargo.toml` gains `authors = ["Swamy Gadila"]` and a workspace description,
    so crates.io and `cargo metadata` attribute the work.
  - `LICENSE-MIT` and `LICENSE-APACHE` now name **Swamy Gadila** as the
    copyright holder. This is a legal attribution change — previously it read
    "Copyright (c) 2026 Jounit".
  - `README.md` credits the author and copyright holder, and `TRADEMARK.md`
    states the marks belong to the same holder, with the reporting and contact
    paths pointing at a named person rather than "the maintainers".
  - `docs/mainnet-readiness.md` carries the attribution alongside the launch gate.

### Changed (documentation)

- **README expanded to cover the areas a reviewer asks about first**, and every
  claim re-derived from the code rather than carried over:
  - **Supply** — the stock cap's removal, the exact ladder figure
    (39 157 124 JNT, not the 39 157 200 a geometric shortcut gives, because
    genesis occupies a rung-0 height without minting), the tail's decay to a
    permanent 0.1 JNT floor, the two bounds that enforce it, and the measured
    consequence that net supply *falls* below break-even at ≈5 % activity.
  - **What the chain is for** — L1 as settlement, L2 as a task economy, with the
    six transaction types and six contract states tabulated.
  - **Machines, agents and robots** — identity derivation, the fail-closed
    spend-policy rules, why there is no second currency, the fixed reputation
    weight table with `DisputeLost` at −3, and streaming micro-payments.
    Carries the scope limit plainly: the layer is a pure library and is **not**
    wired into `submit_at`, so it cannot by itself move a coin.
  - **Verified Work Certificates** — what one is, the two kinds, and the
    unchallenged-result rule spelled out rather than footnoted.
  - **How fraud is detected** — the canonical reference, the full lifecycle
    diagram, the vote transport, and what a fraud verdict does to each party.
  - **How withdrawals work** — the four steps, why the claim is proof-authorised
    rather than signed, exact funding and its liveness cost, and that mainnet
    exits are off.
  - **A before/now table** recording what each mechanism was and is, so a reader
    can tell the shipped state from the earlier one.
  - **Component status** — every row is a code path that exists, with the
    honest caveat where one applies, and the five items that are *not* done
    marked as such rather than omitted.

  Nothing planned is described as shipped. Where something is a library rather
  than a consensus rule, or registered-but-inactive, or retained-as-evidence but
  not yet slashable, the README says so.

### Added (licensing)

- **`TRADEMARK.md`.** The code licence and the brand policy are now separate
  documents, which is the arrangement Bitcoin uses. The code stays `MIT OR
  Apache-2.0` so anyone can run, audit, fork and commercialise it; the *Jounit*
  name, the `JNT` ticker and the logos are trademarked so nobody can ship a
  product under our identity that is not this software.

  Written against a real tension rather than assumed away. A permissive code
  licence cannot protect a brand, and a brand left unprotected eventually gets
  used by someone who is not us, on a chain that is not this one, holding a
  token that looks like ours — and the user has no way to tell. Forks remain
  explicitly permitted; what the trademark refuses is the rebranding.

### Fixed

- `Cargo.toml` declared `repository = "https://github.com/jounit-network/jounit"`,
  which is not the actual remote. Cosmetic, but it is the first thing
  `cargo publish` would have used.

### Changed (documentation)

- **README rewritten** from 876 lines to ~240. The previous version carried a
  giant status blockquote, 15 sections, deep protocol tables and a module map
  inline, which made it hard to read and hard to keep accurate. What remains is
  what someone needs in the first five minutes — what it is, how to run it, what
  is built, what is not done, and how it is licensed. Protocol detail belongs to
  `SPEC.md`, which is normative, and to `docs/`, which already carries the design
  record. The rewritten version also fixes a broken `## License` heading that had
  merged with its own body text.

### Fixed (consensus verification only — no rule change)

- **L1/L2 exit disagreements are no longer invisible.** `ChainL2::apply_block`
  recorded an L1-accepted exit claim that the replayed L2 state could not back
  only behind a `debug_assert`, which compiles out of the build a long-running
  node actually ships. The disagreement is now recorded as an `UnbackedClaim`
  (height, owner, nonce, named reason) and exposed through
  `ChainL2::unbacked_claims()`. The watch is still dropped — L1 already
  released it, so a re-crank would only be refused — but a node that reports
  non-empty entries now knows its two views disagree instead of silently
  outliving the divergence.
- **`verify_canonical_chain` now covers the stake undo records.** It already
  compared `pscb_undo`; the same blind spot existed for `bond_undo` and
  `slash_undo`, which meant a wrong reorg unwind of a bond would have left
  `verify` blind. The ledger comparison proves the applied state, not that a
  reorg would undo it correctly — now both are checked.
- `crates/jnt-core/tests/bond_stake.rs`: `a_reorged_bond_leaves_no_undo_record_behind`
  pins the reorg path that drops the stake undo records with the block.

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

Recorded as blockers, not oversights, in [docs/decisions.md](docs/decisions.md).
Resolved items are struck through with the decision that closed them.

- ~~**P1** — L2 → L1 exits are undefined.~~ **Resolved by Decision 19 (see
  Unreleased).** The exit rule, the crank and the reorg unwind all exist; what
  remains is the *configuration* decision that sets
  `mainnet.exit_activation_height` (currently `0` = never).
- ~~**P2** — no stake/bond ledger and no mainnet validator committee.~~
  **Resolved by Decision 20 (see Unreleased).** Bonding, unbonding, slashing,
  the bond-order committee and ledger-derived finality keys are implemented and
  tested. What remains is `mainnet.genesis_validators` being empty: with no
  committee *and* no bonded stake, `mainnet` finality verification fails closed,
  which is the honest pre-committee state rather than a missing rule.
- ~~**P3** — the M2 activation rule (what proves a compute result fraudulent) is
  unspecified, so the slash vault stays inert.~~ **Resolved by Decision 21 (see
  Unreleased):** `compute_ir::reference_result_hash` is the canonical reference,
  `DisputeEngine::resolve` computes it itself from the disputed contract, and
  `Arbiter::ChallengerCorrect` + `Verdict::Fraudulent` slash the worker and pay
  a bounty. What remains is *transport*: no production code signs or relays a
  verdict, because that needs a key-custody decision
  (`docs/decisions.md`). Note the consequence, which is a design property and
  not an oversight: L2 consensus does **not** re-execute compute, so it accepts
  any non-placeholder result hash. A wrong result is only convicted when
  somebody challenges it in time — an unchallenged one auto-settles `Correct`
  with a `WindowElapsed` certificate (SPEC §16.4/§16.5 forbid an on-chain
  interpreter).
- ~~**P4** — the HBM scratchpad puzzle is not a registered `puzzle_id`; chain
  security rests on the base puzzle only.~~ **Deliberately left unresolved.**
  `hbm_pow.rs` implements the memory-hard permutation, its config scaling and
  nine tests, and it is *not* registered in `puzzle.rs` — activating it would
  change the consensus puzzle with no independent security review of the memory
  parameter choice. It stays inert by choice, not by omission.
- ~~**P5** — a task whose escrow is below the 20,000-sat settle fee fails
  closed.~~ **Resolved by Decision 23 (see Unreleased):** `settle_fee_sat` is
  0.1 % of task value with a 1,000-sat floor, so dust tasks settle.
- **Operational** (not protocol): no signed release/tag pipeline, no published
  PGP key for the security channel, no log shipping, and the permissionless
  exit crank has no submission channel outside a miner's own loop — a third
  party can satisfy the consensus rules but has no transport to hand a claim in
  with.
- ~~Monetary parameters beyond the frozen schedule … are **unapproved**.~~
  **Resolved (Decision 18, M-A…M-C, Decision M-E): the tail is approved and
  implemented, `supply_cap_sat` is deleted, and the escrow ceiling is fixed and
  validated by `NetworkParams::validate`.** No monetary parameter remains open.

[Unreleased]: https://github.com/swamy18/Jounit/commits/main
