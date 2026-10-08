# Performance Benchmarks

## Methodology

All measurements use `cargo test --release` with a manual probe on an M2 MacBook Air (8-core, 16 GB RAM). Timing
bounds are recorded as history, not CI assertions: `cargo test` timing flakes across runners, so hard thresholds
would cause false negatives in CI rather than catch real regressions.

For each hot path below, the source contains an `#[ignore]`d probe test. Run any probe with:

```
cargo test --release -p jnt-l2 --lib vwc_perf_probe -- --ignored --nocapture
```

## Recorded Numbers

### VWC encode / decode / validate (`vwc_perf_probe`)

| Operation | Time (µs) | Notes |
|---|---|---|
| `VerifiedWorkCertificate::encode` | 4.6 | Pure CPU, no allocation beyond output buffer |
| `VerifiedWorkCertificate::decode` | 3.4 | Bounded by `MAX_VWC_SIZE` (§14.6) |
| `VerifiedWorkCertificate::validate` | 2,400 | Real `blst` pairing — BLS-bound by construction |

**Interpretation.** Validation is a single pairing verification, the same cost class as BLS checkpoint
verification (§14.6.2). No optimization is justified: the cost is dominated by the cryptographic primitive,
not by protocol logic.

### Puzzle solve (`puzzle::tests::test_config_is_faster_than_production`)

The HBM scratchpad PoW puzzle (M4) is configured so that the `test` profile solves in <1 ms while `production`
parameters match the difficulty ladder in `docs/decisions.md` (Decision 9). The probe confirms the production
profile is at least 50× harder than `test`, ensuring test suites never accidentally validate against trivial
difficulty.

### Block validation (chain integration)

Measured via `difficulty_test` (mini profile, 2,000 blocks):

| Operation | Time (ms for 2,000 blocks) | Per-block |
|---|---|---|
| `chain.submit` (valid block, no L2) | 86 | 43 µs |
| `chain.submit` (valid block, 1 L2 tx) | 110 | 55 µs |
| `chain.submit` (invalid block, bad PoW) | 2 | 1 µs (fast reject) |

### Block persistence (`jnt-store`)

| Operation | Time (ms) |
|---|---:|
| Append a 512-byte block to a 10,000-block log | 0.3 (amortized: single append, single fsync pair) |
| Reopen a 10,000-block store | 45 (replays meta.json + last 100 block headers) |

### API endpoints (`jnt-node`)

| Endpoint | Response time (ms) under 10 concurrent |
|---|---:|
| `GET /health` | <1 |
| `GET /v1/balance/{address}` | <1 (cached state read) |
| `PUT /v1/tx` (build + sign) | <5 (secp256k1 signing cost) |
| `GET /v1/reputation/{address}` | <5 (derived from canonical L2 state) |

## Benchmark Harness

The project does not use `criterion` or a standalone `benches/` workspace. Benchmarks are inline `#[ignore]`d
probes in the test files next to the code they measure. Rationale: the production paths are already exercised
by 773 deterministic tests; adding a separate harness would duplicate coverage without catching different bug
classes. The probes exist solely to detect orders-of-magnitude regressions that a code change might introduce.

To re-run all probes:

```bash
cargo test --release -p jnt-l2 --lib vwc_perf_probe -- --ignored --nocapture
cargo test --release -p jnt-core --lib puzzle::tests::test_config_is_faster_than_production -- --nocapture
```
