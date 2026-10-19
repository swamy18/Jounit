# Mainnet Operational Readiness

**Status: READY.** All three protocol blockers have been resolved by code changes:
the mandatory 5,000 JNT validator stake has been removed (any positive bond is
accepted), the L2 fee path now has a flat minimum floor, and the credit/escrow
node-local boundary is explicit. This document records the operational state of
those decisions.

**Author and copyright holder:** Community-owned. No single person holds it,
like Bitcoin. (© 2026).

## What is actually implemented

| Area | Implemented |
|---|---|
| Versioned network profiles | `NetworkParams::{mainnet, testnet, mini}`, `by_name`, `validate` (`crates/jnt-core/src/params.rs`) |
| Deterministic genesis | genesis mints nothing; identical across profiles (SPEC §11) |
| Block storage | `jnt-store`: append-only checksummed `blocks.log` + atomic metadata; torn-tail recovery reported, mid-chain damage refused |
| Node CLI | `jnt-node {init,mine,send,status,verify,show-block,balance,wallet,export,serve}`; flags only, **no config file** |
| P2P + tx relay | `jnt-net`, SPEC §13/§13.14 |
| L2 replay, deposits, VWC, reputation | `jnt-l2`, SPEC §14–§19 |
| Opt-in REST API | `--api-listen`, `/v1/*` routes (see §2) |
| Fuzz harness | `fuzz/` (14 targets, cargo-fuzz nightly + ASan) |
| Benchmarks | inline `#[ignore]`d probes, **not** a `benches/` harness |
| Escrowed service contracts | `jnt-l2::ServiceContract` (generic over deliverable and attestation) with `ServiceContract::open` for non-compute services; `crates/jnt-l2/tests/service_contract.rs` drives a sort deliverable through claim → submit → settle. **No wire payload for a non-compute contract** — that is a new L2 transaction type and a consensus change |
| Agent credit | `jnt-core::credit::CreditBook` + the `CreditGate` trait, consulted by `POST /v1/payment/submit`; reservation encumbers capacity, settlement is idempotent per reservation, bonds are pledged to the position they price; bond/open/repay/default reachable over HTTP. Backed minting exists: `POST /v1/credit/mint` accepts only attestations signed by a key configured with `--credit-issuer` (no key configured = every mint refused), and a minted attestation can never mint twice — the replay guard is persisted, so a restart is not a replay. `POST /v1/credit/deposit` stays the ungated book writer this crate has always documented ("Item 2 wiring only"). **Non-consensus and node-local**: there is no `TXCREDIT`; credit persists across restarts through `SharedNode::encode_state`/`decode_state` and the node's atomic, digest-checked `state.bin` (fail-closed load), alongside the other node-local books |
| Payment settlement links | `POST /v1/payment/{id}/settle` binds a recorded payment to the L1 transaction that pays its recipient — the node verifies the tx exists in its chain or mempool and that its outputs to the recipient cover the amount; `GET /v1/payment/{id}` reports the link as `pending`, `confirmed` (with height) or `missing`. One payment, one link (conflict on a second txid); links persist in `state.bin` |
| Delegation chains | `jnt-core::delegation` narrowing rule, sub-agent derivation, `DelegationBook` lineage, and a signed root-first chain carried by `MachinePayment`/`PaymentRequest`; node records links, verifies owner policy signatures, propagates revocation to descendants. **Non-consensus**: delegation is not a consensus input and is not part of any transaction byte |
| Conditional escrow | `jnt-core::escrow::ConditionalEscrow` with `release_arbiter`/`release_mutual` on the type, a release hash binding network and condition, and fail-closed oracle conditions. **Settlement wired (§20.2)**: `POST /v1/escrow/{id}/settle` binds a release to the L2 exit that pays the payee, and `Finalized` waits for `Chain::exit_released` — the coin moves through the ordinary L1 exit path (§19.4) |
| Checkpoint certificates | `Committee::sign_in_set` builds the bitmap against the committee a verifier derives; the node signs against `chain.committee_keys()` for the epoch; `jnt_core::signing` covers the pure signing step |

Not implemented, and named as such: an OpenTelemetry/OTLP exporter (the
Prometheus text endpoint `/metrics` exists — §2), a node config file, a
release/tagging pipeline, reproducible-build tooling, log shipping, and the
security-disclosure channel's PGP key. (The `jnt-worker run` daemon binary
also exists now, with a conservation gate before its first pass.)

## 1. Versioning & release management

- **Version:** `0.2` (`SPEC.md` header: foundation + P2P transport).
- **SemVer policy (documented, not enforced by tooling):** major = consensus
  break; minor = backward-compatible mechanism activation; patch = no
  consensus impact.
- **Release branch convention:** `release/vMAJOR.MINOR` — cut 2 weeks before
  launch, bug/security fixes only.
- **Release checklist** (each item runnable; the ones that are not yet
  automatable say so):

  | Step | Command | Current result |
  |---|---|---|
  | 1 | `cargo fmt --all --check` | clean |
  | 2 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
  | 3 | `cargo test --workspace` | 1230 passed, 0 failed, 1 ignored (`vwc_perf_probe`) |
  | 4 | `cargo build --workspace --release` | succeeds |
  | 5 | vector cross-check: `python sim/verify_vectors.py --check` | see `docs/status.md` |
  | 6 | confirm the only `#[ignore]`d test is the manual `vwc_perf_probe` | confirmed |
  | 7 | update `CHANGELOG.md` | **no CHANGELOG exists yet** |
  | 8 | tag `vMAJOR.MINOR.PATCH`, publish to GitHub Releases | **not yet done** |

- **Supply-chain verification (release build):** every action in
  `.github/workflows/{ci,release}.yml` is pinned to a commit SHA with the tag
  it came from in a trailing comment, `.github/dependabot.yml` refreshes those
  pins weekly, and the cosign installer is pinned to both a SHA and an explicit
  `cosign-version` rather than `@main` / `latest`. Job tokens are least-
  privilege (`contents: read` by default; only `build` takes `id-token: write`
  for the keyless signing identity, and only `publish` takes `contents: write`).
  To audit a release, resolve each SHA back to its tag and confirm the pinned
  `dtolnay/rust-toolchain@stable` commit is still the branch tip it claims to be
  — `stable` and `nightly` are moving refs, and Dependabot is configured to
  *ignore* that action because its updater resolves both moving pins to the same
  tip and rewrites one with the other's SHA. They are therefore a manual step,
  not a bot's, and `.github/dependabot.yml` groups every other dependency
  update into at most one PR per ecosystem (`open-pull-requests-limit: 0`) so the
  branch list stays at `main`. A semver-major bump of `sha2`, `k256`, `argon2`
  or `chacha20poly1305` is likewise ignored by Dependabot: swapping the domain
  separator, the curve, the wallet KDF or the wallet cipher on a major is a
  protocol decision. Their patch and minor security releases still arrive.

## 2. Monitoring & observability

**A Prometheus text endpoint exists: `GET /metrics`.** It serves
`text/plain; version=0.0.4` gauges derived from the same state as `/v1/status`,
plus the two relay-queue depths. Gauges only, one static `network` label, no
counters that need per-request bookkeeping in the consensus loop, and no key
material or per-user data — see the handler in `crates/jnt-node/src/api.rs`.
It carries the same loopback-by-default exposure as every other route: a
loopback bind is unauthenticated, and a non-loopback bind is refused unless
`JNT_API_TOKEN` (preferred over `--api-token`, which is visible in `ps`)
supplies a bearer token, which the exposed stack then enforces on every
request alongside a per-request deadline, a global in-flight cap and a
bounded per-IP rate limit. Host-header validation runs on every bind,
loopback included.

The `/health` path in an earlier revision is wrong twice over: the route is
`/v1/health` and it returns only `{"status":"ok"}`. The rich JSON observables
remain `/v1/status` (and `/v1/finality`, `/v1/fees`), and the process logs are
still the only log surface — **there is no structured log shipper.**

`GET /metrics` exports (all gauges, labelled `network`):
`jounit_height`, `jounit_finalized_height`, `jounit_finality_depth`,
`jounit_finality_activation_height`, `jounit_peers`,
`jounit_base_fee_sat_per_gas`, `jounit_total_supply_sat`,
`jounit_rate_anchor_allowance_sat`, `jounit_issued_sat`,
`jounit_net_supply_sat`, `jounit_pscb_reserve_sat`,
`jounit_mempool_transactions`, `jounit_l1_relay_queue`,
`jounit_l2_include_queue`, `jounit_l2_height`, `jounit_l2_applied_total`,
`jounit_l2_skipped_total`, `jounit_l2_pending_deposits`,
`jounit_joint_supply_sat`, `jounit_conservation_ok`. The joint-supply figure
is also served with its full terms and all three check verdicts at
`GET /v1/conservation` — the same `crate::conservation` arithmetic
`jnt-node verify` prints, so the endpoint, the exporter and `verify` cannot
disagree. `jnt-worker run` gates on that endpoint before its first pass and
refuses a node reporting a breach.

The JSON surfaces remain richer: `GET /v1/status` returns `network`,
`network_id`, `height`, `tip_hash`, `peers`, `base_fee_sat`,
`total_supply_sat`, `pscb_reserve_sat`, `finalized_height`,
`finality_activation_height`, `finality_depth`, `mempool_len`, and an `l2`
block.

**Suggested alerts** (rules not yet written; the signals now exist):

| Signal | Alert if |
|---|---|
| `height` | no advance for 2 × target block interval |
| `peers` | < 3, or > 90 % of `--peers` |
| `mempool_len` | near the byte cap |
| `finalized_height` | stops advancing after activation while `height` climbs |
| `l2.skipped` | spike |
| `pscb_reserve_sat` | flat where it should move, or a jump |
| `jounit_conservation_ok` | 0 — value was created somewhere (joint supply over the cap, or an L2 check broke) |

**Logging:** line-based stdout via the node; there is no structured log
shipper. Recommended operational additions (not present): log-to-file,
rotation, and a level switch.

## 3. Backup & recovery

**Data directory** contains only:

```
<data-dir>/
  blocks.log      # append-only, checksummed, one record per block/UTXO snapshot
  meta.json       # atomic metadata: network, genesis, tip, height
  chain.json      # legacy JSON chain, migrated into blocks.log on first open
  wallets.json    # wallet key material (if any) — protect this
```

There is **no** `config.toml` and **no** `policy/` directory in the data dir
(agent policies are library values, not node files).

**Recovery procedure**

1. **Full node:** back up the data directory. Restore by copying it back and
   running `init` then `serve`; `BlockStore::open` rebuilds the hash index by
   scanning and resumes from the `meta.json` tip.
2. **Wallet:** deterministic wallets; back up `wallets.json` (or the mnemonic
   material it derives from). Losing it loses the keys.
3. **Resync:** `jnt-node init --network mainnet --data-dir <dir>` then
   `jnt-node serve --network mainnet --data-dir <dir> --connect <peer>:9333`.
   There is **no `--sync` flag**; sync is automatic once a peer is connected.
   State is replayed from genesis on load, so resync time is O(chain); there is
   no UTXO snapshot fast-path written today.

**Disaster scenarios**

| Scenario | RTO | RPO |
|---|---|---|
| Clean crash | restart | 0 blocks |
| Torn write (power loss) | reopen; torn tail dropped and reported | 0 committed blocks |
| Damage mid-chain | refuses to open (no silent truncation) → restore backup | last backup |
| Whole fleet down | restore from any node's backup | last backup |

## 4. Security disclosure

- **Bug bounty:** not announced; plan is a GitHub Security Advisory.
- **Responsible disclosure window:** 90 days (documented).
- **Severity:** chain-halting (invalid block accepted) = critical, immediate
  patch + coordinated disclosure; key-compromise = high, 7-day disclosure.
- **Contact:** security@jounit.org. **PGP key is not yet published** — the
  channel is therefore not yet operational.

## 5. Genesis & bootstrapping

- **Mainnet genesis** is deterministic and frozen (SPEC §11). It mints
  **nothing** and has no spendable output (0 % premine, enforced in code).
- **Supply** is bounded per height by the issuance integral
  (`cumulative_issuance_sat(height)`) and per halving period by the rate anchor
  (≤ 1 % of issued supply — Decision 18); there is no stock cap. It is not
  "minted over `MAX_HALVINGS × 10` epochs" (no such constant exists). The ladder
  issues **39,157,124 JNT** (the geometric `149 × 262 800` over-states it by 76
  JNT, because genesis occupies a rung-0 height without minting); after the
  ladder the approved tail keeps issuing 0.1 JNT/block forever (see
  `docs/monetary-policy.md`).
- **L2 genesis escrow** (Decision 7, amended by M-E) is bounded by its own
  validated ceiling, not new issuance:
  `NetworkParams::validate` refuses any escrow above its own
  `escrow_ceiling_sat`. `mini` allocates 10 JNT (3 grant accounts of 1 JNT
  each); `mainnet` allocates 100,000 JNT and grants nothing.
- **Testnet** uses the dedicated `testnet` profile with four deterministic
  genesis validators (Decision 13).
- **Bootnodes:** none are published on the public internet yet. A bootnode is a
  `serve --listen` node that joiners dial with `--bootnodes` (or recover via
  `peers.json`); no DNS seeding or ADDR gossip is implemented (SPEC §13.6 by
  design). `scripts/start-network` stands up a local multi-node network with
  node 1 as the seed bootnode.

## 6. Upgrade mechanism

Mechanism activation is by profile parameter, not by an on-chain governance
epoch:

| Mechanism | Consensus-active? | Authority |
|---|---|---|
| M1 (50/50 PSCB fee split) | **Yes**, everywhere | SPEC §8 |
| M2 (Anti-Collusion Slash Vault) | **No** — no rule creates a slash record | `slash.rs` |
| M3 (Canonical Compute IR) | **No** — envelopes only | `compute_ir.rs` |
| M4 (HBM scratchpad PoW) | **No** — registered as `puzzle_id = 2` but not the active mining puzzle | `hbm_pow.rs` |
| M5 (BLS aggregate finality) | **Conditional** — binding where `finality_activation_height > 0` (`testnet` = 20); observation-only on `mini`; unreachable on `mainnet` (empty committee fails closed) | Decisions 11–12, SPEC §14.7–§14.8 |

A node running pre-activation software rejects post-activation blocks per the
new rules (fail-closed). Operators must upgrade before an activation height is
reached.

## 7. Pre-launch checklist

| Item | Status |
|---|---|
| `cargo fmt --all --check` clean | ✅ |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean | ✅ |
| `cargo test --workspace` passes | ✅ 1230 passed, 0 failed, 1 ignored |
| Release build compiles | ✅ |
| Vector cross-check (Python vs Rust) | ✅ (`docs/status.md`) |
| Fuzz: 14 targets executed, real campaigns | ✅ see `docs/fuzz.md` |
| Deterministic genesis across profiles | ✅ |
| BLS finality adversarial tests | ✅ (18 checkpoint tests) |
| L2 end-to-end (deposits, tasks, VWC, reputation) | ✅ (2-process E2E + chaos suite) |
| Multi-node network test (3 real-TCP nodes: transit sync, live relay, restart catch-up) | ✅ (`jnt-net/tests/three_node_network.rs`) |
| Local multi-node launch scripts (start / stop / reset) | ✅ (`scripts/start-network`, `stop-network`, `reset-network`) |
| L2 → L1 exits | ✅ implemented and active on mainnet (`exit_activation_height = 1`) |
| Stake ledger / bond / unbond / slash | ✅ implemented and tested — any positive bond accepted, no minimum stake (Decision 20 update) |
| Validator committee derivation | ✅ stake-weighted TopN with genesis fallback |
| Checkpoint signing | ✅ built and tested (`signing.rs`, serve loop) |
| M2 / M4 | M2 closed (canonical reference + fraud slashing); M4 registered (`puzzle_id = 2`) but not active on mainnet by design |
| Live conservation surface (`/v1/conservation`, `/metrics` gauges, worker `run` gate) | ✅ |
| Log shipping, release pipeline, PGP disclosure key | ⚠ partial — release workflow exists; log shipping and PGP key remain |

## Resolution of the three protocol blockers

The following three items that were previously listed as blockers have been
resolved by code changes made to the repository:

1. **Mandatory 5,000 JNT validator stake — REMOVED.** `check_bond_tx` in
   `bond.rs` now accepts any positive bond amount. The `MIN_VALIDATOR_STAKE_SAT`
   constant has been removed entirely. The committee derivation remains
   stake-weighted (TopN), so smaller bonds simply rank lower.

2. **L2 fee path — flat minimum floor finalized.** `L2_FLAT_FEE_MINIMUM_SAT`
   (1,000 sat) added as a floor in `fee_sat()`. Every L2 fee type meets or
   exceeds this value. The flat D3 schedule routes through `split_flat_fee`,
   preserving the M1 50/50 burn/PSCB invariant and leaving the L1 fee floor
   untouched.

3. **Credit/escrow boundary — node-local made explicit.** Added a doc comment
   to `SharedNode` in `crates/jnt-node/src/api.rs` that classifies state into
   consensus (`chain`, `pool`, `l2`) and node-local (credit, escrow,
   delegations, policies — never replayed, never committed). The node-local
   books now also persist to the node's `state.bin`; see the Agent credit row
   above and `SharedNode::encode_state`.

No independent security review has been completed. A third-party security review
is recommended before any mainnet deployment with real value.
