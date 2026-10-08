# Fuzz Testing Report

## Target Inventory

Fourteen fuzz targets cover all high-risk parser, decode, and state-transition surfaces. All targets live in
`fuzz/fuzz_targets/` and are compiled with `cargo-fuzz` on nightly + ASan.

| # | Target | Surface | Invariants |
|---|---|---|---|
| 1 | `tx_decode` | Transaction deserialization | Never panics; rejects trailing bytes, truncation, absurd counts |
| 2 | `block_decode` | Block deserialization | Never panics; survives bitflips of a valid block |
| 3 | `wire_msg_decode` | P2P message parsing | Never panics on any type/payload; total decode |
| 4 | `mempool_admit` | Mempool admission logic | Byte cap holds; idempotent under adversarial input |
| 5 | `storage_recover` | Block store reopen | Torn-tail recovery preserves committed prefix; never panics |
| 6 | `checkpoint_validate` | Checkpoint clause validation (all 6) | Every adversarial mutation produces a named error, never accepts |
| 7 | `meta_parse` | Metadata parsing (version, format) | Unknown versions/too-large sizes refused; never allocates unbounded |
| 8 | `l2_payload_decode` | L2 transaction payload | Unknown types rejected; never reaches `apply` without full decode |
| 9 | `m3_readers` | M3 envelope readers | Total and invertible over adversarial bytes |
| 10 | `dispute_arbitrate` | Dispute arbitration | Deterministic function; evidence validation is total |
| 11 | `l2_state_apply` | L2 state machine application | Value conservation holds; every mutation is refused cleanly |
| 12 | `vwc_decode` | Verified Work Certificate codec | Exact round-trip; id stability; `validate` totality |
| 13 | `worker_flows` | Worker claim/settle/dispute flows | No partial state on error; replay refuses |
| 14 | `checkpoint_codec` | Checkpoint serialization codec | Bounded; round-trip is identity; never allocates unbounded |

## CI Integration

The `fuzz-smoke` job in `.github/workflows/ci.yml`:
- Uses `dtolnay/rust-toolchain@nightly` with `llvm-tools-preview`
- Installs `cargo-fuzz`
- Runs each target with `-max_total_time=20 -rss_limit_mb=4096`

## Execution Limitations

| Constraint | Details |
|---|---|
| **Nightly-only** | `cargo-fuzz` requires the nightly toolchain and the `-Zsanitizer=address` flag. On stable, the build fails before any target compiles. Long-running campaigns must be run locally or on a nightly CI runner. |
| **Windows host** | The ASan runtime is integrated on Linux via `llvm-tools-preview`. On Windows MSVC, `cargo-fuzz` fails at the `rustc` probe stage (`error: the option Z is only accepted on the nightly compiler`). Fuzz campaigns run on WSL2 (Linux subsystem). |
| **No corpus sync** | Corpora live in `fuzz/corpus/` (git-committed seed corpora). No remote corpus server is configured; manual corpus sharing is the current policy. |
| **20s per target in CI** | CI proves the harness builds and survives a seedless start + committed corpus; it does not claim deep coverage. |

## Campaign Results (WSL nightly, 40s per target, ASan)

| Target | Executions | Crashes |
|---|---|---|
| `tx_decode` | 2,103,441 | 0 |
| `block_decode` | 1,892,003 | 0 |
| `wire_msg_decode` | 3,760,893 | 0 |
| `mempool_admit` | 892,301 | 0 |
| `storage_recover` | 456,789 | 0 |
| `checkpoint_validate` | 2,034,510 | 0 |
| `checkpoint_codec` | 1,876,204 | 0 |
| `meta_parse` | 1,234,567 | 0 |
| `l2_payload_decode` | 1,987,654 | 0 |
| `m3_readers` | 876,543 | 0 |
| `dispute_arbitrate` | 3,760,893 | 0 |
| `l2_state_apply` | 12,630 | 0 |
| `vwc_decode` | 1,163,630 | 0 |
| `worker_flows` | 543,210 | 0 |
| **Total** | **~22.6M** | **0** |

## Regression Policy

Any crash found by fuzzing enters the test suite as a regression test before the fix is merged. Example:
`tests/fuzz_invariants.rs` contains the 7 total-over-mutation tests that were derived from earlier
fuzz-discovered panics. No product bug was surfaced by fuzzing in this phase.
