# Performance Benchmarks

**All numbers below were measured on 2026-10-09 on one machine; none is a CI
threshold.** An earlier revision of this file carried figures attributed to an
"M2 MacBook Air" (a machine not used for this repository) and per-operation
numbers (storage append 0.3 ms, block validation 43 µs, API <1 ms) that had no
probe or command behind them. Those are deleted. What follows is reproducible
from the commands shown, and every path that was **not** measured is named as
not measured rather than estimated.

## Environment

| | |
|---|---|
| CPU | Intel Core i5-8365U @ 1.60 GHz, 8 logical CPUs |
| OS | Windows (Git Bash); release builds |
| Build | `cargo build --workspace --release` (binary 2,184,704 bytes) |
| Fuzzing host (separate) | WSL2 Ubuntu on the same machine — see `docs/fuzz.md` |

## Methodology

- CLI numbers: the **release** `jnt-node` binary, timed with `date +%s%N` in
  bash. Each is a cold process start (so each includes read-and-replay of the
  chain), which is the interface an operator actually uses.
- Probe numbers: the one inline `#[ignore]`d probe in the tree
  (`crates/jnt-l2/src/vwc.rs::vwc_perf_probe`).
- Timings are single runs, recorded as history, **not** assertions. No CI job
  gates on them.

## Measured — `jnt-node` CLI (mini profile)

Chain of 300 mined blocks.

| Operation | Command | Wall time |
|---|---|---:|
| Mine 300 blocks (PoW included) | `jnt-node mine --blocks 300 --interval 0` | **225,824 ms** (~753 ms/block) |
| Replay + verify from genesis | `jnt-node verify` | **304 ms** (~1.0 ms/block, 301 blocks) |
| Reopen + status | `jnt-node status` | **193 ms** |

**Interpretation and caveats.**

- The mining figure is **PoW-bound, not validation-bound**: ~753 ms/block is
  the cost of *solving* the puzzle at the mini difficulty this run reached
  (difficulty 101,568), not the cost of validating a block a peer sent. It is
  reported as "block mining". It is **not** a block-validation number.
- `verify` replays all 301 blocks from genesis, re-checks the chain, diffs the
  UTXO set, re-derives the PSCB reserve, replays L2 deterministically and runs
  the joint conservation check — 304 ms total, ≈1.0 ms/block including process
  startup. That is the closest real measurement of **block validation +
  application** available from the CLI, and it is dominated by replay, not by
  network or disk.
- `status` (193 ms) is the **storage reopen** figure: open the append-only log,
  rebuild the hash index, replay, print. It is O(chain) today because state is
  replayed from genesis; there is no persisted-UTXO fast path.

## Measured — VWC probe (`crates/jnt-l2`, release)

```
cargo test --release -p jnt-l2 --lib vwc_perf_probe -- --ignored --nocapture
```

| Operation | Measured | Note |
|---|---:|---|
| `VerifiedWorkCertificate::encode` | **4.16 µs** | pure CPU |
| `VerifiedWorkCertificate::decode` | **3.21 µs** | bounded by `MAX_VWC_SIZE` |
| `VerifiedWorkCertificate::validate` | **2,630.15 µs** | real `blst` pairing — BLS-bound |

Validation is ~630× encode/decode because it performs a real pairing
verification. No optimisation is justified: the cost is the cryptographic
primitive, not protocol logic.

## Measured — REST API latency (loopback, mini)

`jnt-node serve --no-mine --api-listen 127.0.0.1:19334`, then `curl`:

| Endpoint | Time |
|---|---:|
| `GET /v1/health` (first request, incl. connection) | 9.1 ms |
| `GET /v1/status` | 2.0–3.0 ms |
| `GET /v1/fees` | 2.4 ms |

All returned HTTP 200. These are single-client loopback reads; no concurrency
test was run.

## NOT measured (no probe exists)

These were requested for verification but have **no harness**, so no number is
reported. Fabricating one would be worse than omitting it:

- **Block validation in isolation** (validating a received block without
  mining it) — no benchmark harness. The `verify` figure above is the closest
  proxy and includes replay.
- **L2 transaction application rate** — no probe; L2 replay time is folded into
  `verify`.
- **Storage append throughput / fsync cost** — no probe.
- **Worker ↔ node transport throughput** — the transport is exercised for
  correctness (`crates/jnt-worker` tests over a live socket), not timed.
- **Large-chain replay** — measured only at 301 blocks.
- **Multi-node synchronization** — exercised for correctness
  (`crates/jnt-net/tests/integration.rs`, two-process tests), not timed.

## Benchmark harness

There is **no** `criterion` suite and no `benches/` workspace. The only inline
probe is `vwc_perf_probe`. Adding a harness for the paths above is open work;
until it exists, this file reports CLI-level timings and one probe, and says so.

To reproduce:

```bash
cargo build --workspace --release
BIN=target/release/jnt-node
rm -rf /tmp/jntbench && $BIN init --network mini --data-dir /tmp/jntbench
time $BIN mine   --blocks 300 --interval 0 --data-dir /tmp/jntbench
time $BIN verify --data-dir /tmp/jntbench
time $BIN status --data-dir /tmp/jntbench

cargo test --release -p jnt-l2 --lib vwc_perf_probe -- --ignored --nocapture
```
