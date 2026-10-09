# Supply-Anchor Work — Status Report

**Date:** 2026-10-09 — **COMPLETE.** All stages SA-1…SA-6 landed in this session
(see `docs/decisions.md` Decision 18, Implementation record).

## Result

The stock cap is deleted, the rate anchor is enforced, vectors are regenerated,
net reporting is live, and docs are reconciled. Touched suites green, both sim
selftests pass, clippy `-D warnings` and `fmt --check` clean.

## What changed since the stop

The `supply.rs:671` syntax error was a duplicated test body plus duplicated
`#[test]` attributes — trimmed, and the two boundary tests rewritten (the
ladder test now stops at the last ladder block; the anchor test uses a
synthetic 50-JNT tail to prove the anchor refuses a dilutive schedule). Beyond
the half-landed state: `rate_anchor_allowance` corrected to 1 % of issued per
window and enforced in the mint gate; `supply_cap_sat` deleted from
`NetworkParams`, `SupplyReport`, conservation, the API, the metrics and the
worker parse; `SupplyCapExceeded` removed; `Chain` tracks cumulative burns
(reorg-rewound) with net figures on `status`/`/v1/conservation`/`/metrics`;
vectors regenerated with the anchor fields; SPEC/monetary-policy/readiness/
README/decisions/CHANGELOG updated.

## Historical note (kept)

Work **had stopped** on request with the syntax error below as the blocker. It
is fixed; the original handoff text is kept after this section as the record
of that stop.

## What was on disk before stopping

Five files under `crates/jnt-core/src` had been edited earlier in the session
(verified present on disk):

- `crates/jnt-core/src/supply.rs` — `check_mint_at_height` = issuance-integral bound only;
  new `SupplyRateExceeded`; new `rate_anchor_allowance()`; `max_issuance_sat` no longer
  consults `supply_cap_sat`; new `check_mint`/`reward_exceeds_remaining`; two new tests.
- `crates/jnt-core/src/error.rs` — `SupplyRateExceeded` added; `SupplyCapExceeded` deprec
  atived but retained; `Display` updated.
- `crates/jnt-core/src/params.rs` — `supply_cap_sat` marked `#[deprecated]`; note points at
  the rate anchor.
- `crates/jnt-core/src/chain.rs` — `supply_report` exposes `issued_sat`.
- `crates/jnt-core/tests/redteam.rs` — rewritten to `SupplyRateExceeded` + height-based gate;
  "zero-reward ladder" test kept working on the test profile's old cap.

## The single blocker

`cargo test -p jnt-core --lib supply` → **exit 101** (compile error):

```
error: unexpected closing delimiter: `}`
   --> crates\jnt-core\src\supply.rs:671:1
   |
591 |     fn mini_and_mainnet_tails_are_independent() {
   |                                                 - this delimiter might not be properly closed...
...
671 | }
```

A stray blank line plus a multi-duplicate `#[test]` block at
`supply.rs:607-613` broke the bracket/indent balance of the test module. That is a
deterministic, one-line fix: trim that region, then re-run the two checkpoint builds.

## Remaining work (SA backlog)

| Stage | Work | Status |
|---|---|---|
| SA-1 | `cargo test -p jnt-core --lib supply` green (trim broken region, fix bracket/indent) | ⏸ blocked by syntax error at `supply.rs:671` |
| SA-2 | Update 8+ pins: `supply.rs` unit tests, `genesis_funding`, `conservation`×(2), `l2_deposits`, `l2_funding`, `cli_run`, `api`, `supply_vectors.json`, `tail_emission_sim.py` | ⏸ untouched |
| SA-3 | Rate anchor as sole cap — half-landed; needs end-to-end pass + CI | ⏸ half-landed |
| SA-4 | Regenerate `tests/vectors/supply_vectors.json` (still has old `hard_cap_jnt`/`unmintable_jnt` fields) | ⏸ not started |
| SA-5 | Remove `supply_cap_sat` from L2 escrow/omnibus `validate()` paths | ⏸ not started |
| SA-6 | Full `cargo test -p jnt-core` / `jnt-l2` / `jnt-worker` green + docs/release updates | ⏸ not started |

## Bottom line

- The refactoring logic is written and the direction is correct, but **no command
  before the stop ever compiled**: the working copy has a syntax error at the tail
  of `crates/jnt-core/src/supply.rs`.
- The fix is a small deterministic trim at `crates/jnt-core/src/supply.rs`
  (removing the stray blank line + duplicate `#[test]` block at ~lines 607-613),
  followed by:
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  cargo test -p jnt-core --lib supply
  cargo test -p jnt-core --test redteam
  ```
- Once green, SA-2..SA-6 can proceed in order. Nothing else blocks the checkpoint.
