# Supply-Anchor Work — Accompanied Memo (SA-1..SA-6)

Session start: 2026-10-09. **COMPLETE — all stages landed later the same day**
(see `docs/decisions.md` Decision 18, Implementation record). What follows is
kept as the record of the stopped state; the completion is in
`docs/supply-anchor-status.md`.

## What this change is

The approved policy (docs/decisions.md M-A..M-C, approved 2026-10-09) replaced the
old hard supply cap with a tail emission behind an issuance-integral bound, and
with the rate anchor (SA-3) as the only remaining growth cap. This session was
implementing stages SA-1..SA-6 in `crates/jnt-core/src`.

## Completed on disk (before the stop)

| File | What changed | Status |
|---|---|---|
| `crates/jnt-core/src/supply.rs` | `check_mint_at_height` is now the issuance-integral bound only (`.min(cap)` removed); added `SupplyRateExceeded`, `rate_anchor_allowance()`; `max_issuance_sat` no longer calls `.min(supply_cap_sat)`; added `check_mint` (height-oblivious, overflow-only) + `reward_exceeds_remaining`; added two new tests | written |
| `crates/jnt-core/src/error.rs` | Added `SupplyRateExceeded`; `SupplyCapExceeded` marked `#[deprecated(since="2026-10-09", ...)]` but retained for legacy call sites; `Display` updated for both | written |
| `crates/jnt-core/src/params.rs` | `supply_cap_sat` field marked `#[deprecated]` with a note pointing at the rate anchor | written |
| `crates/jnt-core/src/chain.rs` | `supply_report` now also exposes `issued_sat` (the live integral) so the report carries the real bound | written |
| `crates/jnt-core/tests/redteam.rs` | Rewritten end-to-end to use `SupplyRateExceeded` + the new height-based `check_mint_at_height` gate; "zero-reward ladder" test kept working | written |

## The blocker found this session

`cargo test -p jnt-core --lib supply` → exit 101, compile error:

```
error: unexpected closing delimiter: `}`
   --> crates\jnt-core\src\supply.rs:671:1
   |
591 |     fn mini_and_mainnet_tails_are_independent() {
   |                                                 - this delimiter might not be properly closed...
...
671 | }
```

Root cause: an earlier edit loop left a stray blank line plus a multi-duplicate
`#[test]` redirection inside the test module of `crates/jnt-core/src/supply.rs`
(about lines 607–613). That broke the bracket/indent balance, so no compile of
the lib test suite could succeed, which is why **no checkpoint ever went green**.

## Remaining work (SA backlog — not started)

1. **SA-1 verify** — trim the broken region in `crates/jnt-core/src/supply.rs`
   (~lines 607–613: the stray blank line + duplicate `#[test]` block), then
   re-run `cargo test -p jnt-core --lib supply` and `cargo test -p jnt-core --test redteam`
   until both pass. That is the checkpoint that proves SA-1 + SA-2 landed.
2. **SA-2 wiring** — update the 8+ files that still pin the old cap:
   - `crates/jnt-core/src/supply.rs` unit tests (currently broken syntax at tail)
   - `crates/jnt-l2/tests/genesis_funding.rs`
   - `crates/jnt-node/tests/conservation.rs`
   - `crates/jnt-node/tests/conservation_api.rs`
   - `crates/jnt-node/tests/l2_deposits.rs`
   - `crates/jnt-node/tests/l2_funding.rs`
   - `crates/jnt-worker/tests/cli_run.rs`
   - `crates/jnt-node/tests/api.rs`
   - (`cap_sat`/`joint` tests, `tests/vectors/supply_vectors.json`, `sim/tail_emission_sim.py`)
3. **SA-3** — rate anchor as the sole cap: already half-landed in supply.rs/error.rs,
   but needs end-to-end verification and the independent `mini`/`mainnet` tail checks.
4. **SA-4** — regenerate `tests/vectors/supply_vectors.json`; the file still carries the
   old `hard_cap_jnt`/`unmintable_jnt` stock-cap fields until the vector is regenerated in SA-4.
5. **SA-5** — remove `supply_cap_sat` from the L2 escrow/omnibus `validate()` paths
   (params.rs lines ~214 and ~893 still consult the field directly).
6. **SA-6** — full `cargo test -p jnt-core` / `cargo test -p jnt-l2` / `cargo test -p jnt-worker`
   suites green, then docs/release updates.

## Status at the stop

- **SA-1**: ✅ code written; ❌ compile blocked (bracket/indent error at
  `supply.rs:671`).
- **SA-2**: ❌ untouched, except `redteam.rs` (rewritten on disk).
- **SA-3**: ✅ half-landed (`error.rs` + `supply.rs` functions); ❌ needs pass + CI.
- **SA-4 / SA-5 / SA-6**: ⏸ not started.

## Recommendation for the next turn

The single deterministic fix is one tiny trim in `crates/jnt-core/src/supply.rs`
(removing the stray blank line + duplicate `#[test]` block at the broken region),
followed by:

```bash
cd "$(git rev-parse --show-toplevel)"
cargo test -p jnt-core --lib supply
cargo test -p jnt-core --test redteam
```

That gets SA-1 + SA-2 to a green checkpoint. After that, SA-3..SA-6 can be
worked in order; nothing else requires changes before the lib-supply check passes.
