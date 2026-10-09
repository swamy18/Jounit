# Mainnet Operational Readiness

**Status: NOT READY.** This document separates what is *documented*, what is
*implemented*, and what is *tested*. An earlier revision carried several
figures that exist nowhere in the code (a 10,000,000 JNT cap, `MAX_HALVINGS`,
a `config.toml`, a `/metrics` endpoint, a `serve --sync` flag) and a
pre-launch checklist that marked unrun items ✅. Those are corrected below.
Mainnet is blocked by three things that are not operational at all — they are
protocol decisions — and the blockers are named at the end.

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
  | 3 | `cargo test --workspace` | 773 passed, 0 failed, 1 ignored (`vwc_perf_probe`) |
  | 4 | `cargo build --workspace --release` | succeeds |
  | 5 | vector cross-check: `python sim/verify_vectors.py --check` | see `docs/status.md` |
  | 6 | confirm the only `#[ignore]`d test is the manual `vwc_perf_probe` | confirmed |
  | 7 | update `CHANGELOG.md` | **no CHANGELOG exists yet** |
  | 8 | tag `vMAJOR.MINOR.PATCH`, publish to GitHub Releases | **not yet done** |

## 2. Monitoring & observability

**A Prometheus text endpoint exists: `GET /metrics`.** It serves
`text/plain; version=0.0.4` gauges derived from the same state as `/v1/status`,
plus the two relay-queue depths. Gauges only, one static `network` label, no
counters that need per-request bookkeeping in the consensus loop, and no key
material or per-user data — see the handler in `crates/jnt-node/src/api.rs`.
It carries the same loopback-by-default exposure as every other route.

The `/health` path in an earlier revision is wrong twice over: the route is
`/v1/health` and it returns only `{"status":"ok"}`. The rich JSON observables
remain `/v1/status` (and `/v1/finality`, `/v1/fees`), and the process logs are
still the only log surface — **there is no structured log shipper.**

`GET /metrics` exports (all gauges, labelled `network`):
`jounit_height`, `jounit_finalized_height`, `jounit_finality_depth`,
`jounit_finality_activation_height`, `jounit_peers`,
`jounit_base_fee_sat_per_gas`, `jounit_total_supply_sat`,
`jounit_supply_cap_sat`, `jounit_pscb_reserve_sat`,
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
  (`cumulative_issuance_sat(height)`), clamped by the **39,945,600 JNT** sanity
  ceiling; it is not "minted over `MAX_HALVINGS × 10` epochs" (no such constant
  exists). The ladder issues **39,157,124 JNT** (the geometric `149 × 262 800`
  over-states it by 76 JNT, because genesis occupies a rung-0 height without
  minting); after the ladder the approved tail keeps issuing 0.1 JNT/block
  forever, so **788,476 JNT of the cap can never be minted** (see
  `docs/monetary-policy.md`).
- **L2 genesis escrow** (Decision 7, amended by M-E) is a *reallocation of
  headroom that can never be minted*, not new issuance:
  `NetworkParams::validate` refuses any escrow above its own
  `escrow_ceiling_sat`. `mini` allocates 10 JNT (3 grant accounts of 1 JNT
  each); `mainnet` allocates 100,000 JNT and grants nothing.
- **Testnet** uses the dedicated `testnet` profile with four deterministic
  genesis validators (Decision 13).
- **Bootnodes:** none exist yet. A bootnode is a `serve --listen` node that
  joiners dial with `--connect`; no address book or DNS seeding is implemented
  (SPEC §13.6 by design).

## 6. Upgrade mechanism

Mechanism activation is by profile parameter, not by an on-chain governance
epoch:

| Mechanism | Consensus-active? | Authority |
|---|---|---|
| M1 (50/50 PSCB fee split) | **Yes**, everywhere | SPEC §8 |
| M2 (Anti-Collusion Slash Vault) | **No** — no rule creates a slash record | `slash.rs` |
| M3 (Canonical Compute IR) | **No** — envelopes only | `compute_ir.rs` |
| M4 (HBM scratchpad PoW) | **No** — not a registered `puzzle_id` | `hbm_pow.rs` |
| M5 (BLS aggregate finality) | **Conditional** — binding where `finality_activation_height > 0` (`testnet` = 20); observation-only on `mini`; unreachable on `mainnet` (empty committee fails closed) | Decisions 11–12, SPEC §14.7–§14.8 |

A node running pre-activation software rejects post-activation blocks per the
new rules (fail-closed). Operators must upgrade before an activation height is
reached.

## 7. Pre-launch checklist

| Item | Status |
|---|---|
| `cargo fmt --all --check` clean | ✅ |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean | ✅ |
| `cargo test --workspace` passes | ✅ 773 passed, 0 failed |
| Release build compiles | ✅ |
| Vector cross-check (Python vs Rust) | ✅ (`docs/status.md`) |
| Fuzz: 14 targets executed, real campaigns | ✅ see `docs/fuzz.md` |
| Deterministic genesis across profiles | ✅ |
| BLS finality adversarial tests | ✅ (18 checkpoint tests) |
| L2 end-to-end (deposits, tasks, VWC, reputation) | ✅ (2-process E2E + chaos suite) |
| **L2 → L1 exits** | ❌ **blocked** — no recorded decision (`docs/l2-exit-design.md`) |
| **Stake ledger / mainnet validator committee** | ❌ **blocked** — Decision 8 builds none; `mainnet` has an empty committee so finality fails closed |
| M2 / M4 activation rules | ❌ **blocked** — each needs a rule that defines fraudulent compute output / how the HBM puzzle is registered |
| Live conservation surface (`/v1/conservation`, `/metrics` gauges, worker `run` gate) | ✅ |
| Log shipping, release pipeline, PGP disclosure key | ❌ operational, not built |

## Exact blockers preventing mainnet

1. **L2 → L1 exits are undefined.** Decision 10 explicitly defers them. The
   deposit sink is unspendable, so an exit needs a new L1 release rule that no
   decision authorises. Without it, mainnet deposits would trap user funds.
   (`docs/l2-exit-design.md`.)
2. **No stake ledger and no mainnet committee.** Decision 8 builds no stake
   transaction, bond, or unbonding; `mainnet` carries an empty
   `genesis_validators`, so checkpoint verification fails closed and binding
   finality is untestable on mainnet. Real bonded stake (`min_validator_stake_sat`
   = 5,000 JNT, unbonding after `finality_depth`) remains required and unbuilt.
3. **M2 and M4 activation rules are unspecified.** M2 has no rule defining what
   proves a compute result fraudulent; M4 is not a registered `puzzle_id`.
4. **Operational gaps** (below) — these do **not** block a testnet, but they
   block a defensible mainnet: no metrics/log shipping, no release/tagging
   process, no CHANGELOG, no published PGP key, no reproducible-build tooling.

Mainnet readiness is therefore **not claimed**. Testnet is the appropriate
next milestone, and it too is gated on the operational checklist above (not on
the three protocol blockers, which are mainnet-only).
