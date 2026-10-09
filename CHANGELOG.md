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

### Added

- `GET /metrics` on the opt-in service API: Prometheus text exposition
  (`text/plain; version=0.0.4`) of height, finality, peers, base fee, live
  supply, supply cap, PSCB reserve, mempool size, L1 relay queue depth, L2
  include queue depth, and L2 height/applied/skipped/pending-deposit gauges.
  Gauges only, one static `network` label, no key material or per-user data.
- `docs/decisions.md`: a *Pending monetary decisions* section (M-A … M-G) that
  reduces `docs/monetary-redesign.md` to a sign-off surface, so the
  unapproved monetary parameters are visible next to the P1–P6 protocol
  blockers instead of buried in a 43 KB proposal.
- This changelog.

### Notes

- No consensus rule, parameter, fee, genesis value or committed vector was
  changed by the Unreleased work. It is observability and documentation only.

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
  transaction types, the D3 flat fee schedule, dispute arbitration, and
  Verified Work Certificates.
- **L2 settlement on L1**: L2 transactions ride inside L1 blocks and L2 state
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

- **P1** — L2 → L1 exits are undefined. The deposit sink holds no key, so an
  exit needs a new L1 consensus rule. Deposits are one-way until then.
- **P2** — no stake/bond ledger and no mainnet validator committee
  (`mainnet` `genesis_validators` is empty, so binding finality fails closed).
- **P3** — the M2 activation rule (what proves a compute result fraudulent) is
  unspecified, so the slash vault stays inert.
- **P4** — the HBM scratchpad puzzle is not a registered `puzzle_id`; chain
  security rests on the base puzzle only.
- **P5** — a task whose escrow is below the 20,000-sat settle fee fails closed
  (`AmountTooSmallForFee`).
- Monetary parameters beyond the frozen schedule (tail emission, tail floor,
  per-network tail, `supply_cap_sat` fate, `escrow_ceiling`, the fee-burn
  design) are **unapproved** — see *Pending monetary decisions* in
  [docs/decisions.md](docs/decisions.md).

[Unreleased]: https://github.com/swamy18/Jounit/commits/main
