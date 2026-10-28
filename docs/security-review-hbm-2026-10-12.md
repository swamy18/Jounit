# Security review — HBM scratchpad PoW (`hbm_pow.rs`, M4)

**Date:** 2026-10-12
**Scope:** `crates/jnt-core/src/hbm_pow.rs` + its dependency `crates/jnt-core/src/u256.rs` (`target_for_difficulty`, `U256::from_be_bytes`).
**Purpose:** Gate the registration of HBM as `puzzle_id = 2` in `PuzzleRegistry::genesis()` (README §"M4 HBM puzzle — Deliberately unregistered", `docs/decisions.md` P4).

Verdict: **passes review for registration as a *testnet* puzzle**, with one documentation/parameter defect that MUST be resolved before any mainnet production parameters are derived from `HbmConfig::production()`.

---

## 1. Verification model (sound)

- `memory_hash(header, lanes, accesses)` is fully deterministic from the serialized header (`build_seed` → `header.serialize()`).
- `hbm_satisfies` recomputes `memory_hash` and checks `U256::from_be_bytes(mh) <= target`, identical in form to the §5 `satisfies` path. No trusted setup, no oracles, no external state.
- Difficulty mapping uses the **same audited** `target_for_difficulty` = `floor((2^256 - 1) / d)` (`u256.rs`, security_audit.md §1).

## 2. Edge cases (no panics, no false accepts)

| Input | Behavior | Source |
|---|---|---|
| `difficulty == 0` | `target_for_difficulty` → `Err(InvalidDifficulty(0))` → `let Ok(..) else { return false }` → **reject** | `hbm_pow.rs:128` + `u256.rs:38` |
| `difficulty > MAX_DIFFICULTY (2^96)` | `Err(TargetOverflow)` → reject | `u256.rs:41` |
| `accesses == 0` | `mix_accesses` loop runs zero times; returns `seed` as the hash. Accepted only if `seed` meets target. Not a soundness hole (prover proves nothing → trivially fails high difficulty), but worth a `debug_assert!` | `hbm_pow.rs:102` |
| `lanes == 0` | `build_scratchpad` returns empty `Vec`; `mix_accesses` `idx % 0` would panic. Not reachable via `HbmConfig` (lanes ≥ 256), but `memory_hash` is `pub` and unsanitized. Flagged below. | `hbm_pow.rs:106` |

## 3. Index-safety review

- `idx = u64::from_le_bytes(state[..8].try_into().unwrap()) as usize % lanes`
- `state` is `Hash = [u8; 32]`; `state[..8]` is always length 8, so `try_into::<[u8;8]>()` **always succeeds** — the `unwrap` cannot panic. (A `try_into().unwrap()` is acceptable but a `let [..8] = &state[..8]` pattern would be clearer; not a defect.)
- `% lanes` keeps `idx ∈ [0, lanes)`, so `&pad[idx]` is always in bounds.

## 4. ASIC-resistance properties (design-level, not proved)

The design claims hold structurally:
- **Memory-bandwidth bound**: scratchpad size scales with `lanes`; realistic PoW ASICs have negligible on-die SRAM vs. HBM/GDDR DRAM.
- **Sequential dependency**: `access[N+1]` reads `state` derived from `access[N]`, so attempts cannot be pipelined without storing the pad.
- **No free nonce-rolling**: `build_seed` covers `nonce`, `extra_nonce`, `puzzle_id`, `difficulty`, `prev_hash`, `merkle_root`, `timestamp_ms`, etc. — the scratchpad regenerates per nonce (32,768 SHA-256 hashes for 1 MiB), so precomputation across nonces gives no advantage.

These are **design arguments, not proofs**. No memory-hard function has a formal ASIC-resistance proof; the property rests on the bandwidth/latency gap between commodity DRAM and custom silicon. Accept as intended for M4's threat model (anti-ASIC over GPUs/AI workers).

## 5. Defect — `HbmConfig::production()` mislabeled (MUST FIX before mainnet params)

```
hbm_pow.rs:44    pub const SCRATCHPAD_BYTES: usize = 1024 * 1024; // 1 MiB
hbm_pow.rs:50    pub const LANES: usize = SCRATCHPAD_BYTES / 32;     // 32,768
hbm_pow.rs:152-158
    pub fn production() -> Self {
        HbmConfig { lanes: LANES, accesses: ACCESSES }   // 1 MiB / 64 accesses
    }
```

The module doc (`hbm_pow.rs:30-34`) states production uses **8–64 MiB** scratchpad and **256–1024** accesses, but `production()` returns `1 MiB / 64 accesses` — identical to the default `SCRATCHPAD_BYTES`/`ACCESSES` constants. The constructor labeled "production-grade" is in fact the small default, not the production size.

**Impact:** If registration proceeds and `production()` is used to seed network parameters, M4 would deploy with a 1 MiB scratchpad — below the documented threshold where the bandwidth argument becomes meaningful against ASICs. This is a parameter-correctness defect in the *parameter*, not a verification-soundness bug.

**Fix:** Either (a) make `production()` return `lanes = (8..=64 MiB)/32`, `accesses` in a documented range, or (b) rename it (e.g. `mainnet()`) and add a separate `production()` that returns the large config; and gate the large config behind a network param rather than a hard-coded constant. **Blocker for mainnet; not a blocker for testnet registration.**

## 6. Defect — `memory_hash` is public with no parameter validation

`memory_hash` and `hbm_satisfies` are `pub` and accept arbitrary `lanes`/`accesses`. A `lanes == 0` call panics on `% lanes`. Mitigation: callers should use `HbmConfig` (which is non-zero by construction). Recommendation: add `debug_assert!(lanes > 0 && accesses > 0)` at the top of `memory_hash` to fail loudly in debug and leave release behavior to `HbmConfig` sanity. Low priority for testnet; recommended before mainnet.

## 7. Recommendation

- **Accept HBM for testnet registration** as `puzzle_id = 2` with the `test()` config (8 KiB / 8) used in tests and a documented non-production `HbmConfig`. This unblocks wiring (`puzzle.rs` already supports a second `PuzzleSpec` registration; `HybridPuzzleSolver` would need an HBM solver arm).
  - *Update 2026-10-28:* registration is done (`PuzzleSpec::hbm_v1`,
    `puzzle_id = 2`) and `jnt-miner` now carries the HBM solver arm
    (`PowMode::Hbm`, `hbm_satisfies_cfg`); it is still **not active** on any
    profile, and the §5/§6 items below still gate mainnet use.
- **FIX before mainnet:** item 5 (parameter config) and item 6 (panic guard). Record the large-config parameters as a `NetworkParams` field, not a compile-time constant, so they are governance-upgradeable per `docs/decisions.md` P4 ("only puzzle parameters are upgradeable, and only through the governance timelock").

No soundness, overflow, or consensus-split issues were found in the verification path.
