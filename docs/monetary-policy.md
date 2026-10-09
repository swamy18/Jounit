# Monetary Policy

**Reconciled against code and SPEC on 2026-10-09**, including the approved tail
(Decisions M-A…M-G in `docs/decisions.md`). This file previously
described a schedule that exists nowhere in the repository (a 10,000,000 JNT
cap, a 1 JNT initial reward, 210,000-block halvings, `TARGET_SUPPLY_SAT` /
`MAX_HALVINGS` constants). None of those names or numbers exist in the code.
The text below is what `crates/jnt-core/src/supply.rs` and
`crates/jnt-core/src/params.rs` actually implement, pinned by
`SPEC.md §7`/`§10`, `sim/supply_schedule_sim.py`, and
`tests/vectors/supply_vectors.json`. If any of the three ever disagree, the
tests (`supply::tests::*`, `params::tests::*`) fail first.

## Design

JNT is a **capped, time-based issuance** cryptocurrency with **no premine**:
genesis mints nothing. Minting is bounded per height by the issuance integral
`cumulative_issuance_sat(height)` through the single gate
`supply::check_mint_at_height`; `NetworkParams::supply_cap_sat` is retained as a
sanity ceiling (M-D), not as the binding rule. After the ladder the approved
tail (§Issuance schedule) keeps a small, bounded issuance flowing forever, so
the supply is capped *per height* and asymptotically unbounded in total.

There is **no `TARGET_SUPPLY_SAT`** and **no `MAX_HALVINGS` constant** in the
code. Halvings are computed as `height / halving_period` (clamped), and the
ladder reaches its last non-zero rung after 7 halvings, where the tail takes
over; `period_reward_sat` returns 0 for any epoch ≥ 64 as a hard stop.

## Parameters (actual, from `params.rs`)

| Parameter | Mainnet | Testnet / Mini |
|---|---|---|
| `supply_cap_sat` | 39,945,600 JNT = 3,994,560,000,000,000 sat | 304,000 JNT = 30,400,000,000,000 sat |
| `start_reward_sat` | 76 JNT (7,600,000,000 sat) per block | 76 JNT |
| `halving_period` | 262,800 blocks (5 years at 10 min) | 2,000 blocks |
| Reward ladder | 76, 38, 19, 9, 4, 2, 1 JNT (then the tail) | same ladder |
| Tail | 0.50 → 0.25 → 0.125 JNT, then a permanent **0.1 JNT** floor | constant **1 sat/block** |
| `GENESIS_MINT` | 0 (nothing pre-mined) | 0 |
| `SAT_PER_JNT` | 100,000,000 | 100,000,000 |

The ladder halves in **whole JNT**
(`period_reward_sat = (start_reward_jnt >> epoch) * SAT_PER_JNT`), not by
shifting satoshis — shifting would pay 9.5 JNT at epoch 3 and break the cap
arithmetic. Epochs ≥ 7 pay the tail, halved in **satoshis** and clamped by the
floor (`DecayToFloor`), never zero on any shipped profile.

## Issuance schedule (mainnet)

```
Epoch 0: 262,799 blocks × 76 JNT = 19,972,724 JNT   (genesis mints nothing)
Epoch 1: 262,800 blocks × 38 JNT =  9,986,400 JNT
Epoch 2: 262,800 blocks × 19 JNT =  4,993,200 JNT
Epoch 3: 262,800 blocks ×  9 JNT =  2,365,200 JNT
Epoch 4: 262,800 blocks ×  4 JNT =  1,051,200 JNT
Epoch 5: 262,800 blocks ×  2 JNT =    525,600 JNT
Epoch 6: 262,800 blocks ×  1 JNT =    262,800 JNT
Epoch 7 (1,839,600): tail begins at 0.50 JNT, decays to the 0.1 JNT floor
────────────────────────────────────────────────
Ladder-era issuance:  149 × 262,800 − 76 = 39,157,124 JNT
Supply cap (sanity ceiling):                39,945,600 JNT
Permanently unmintable:                          788,476 JNT
Tail (steady state):        0.1 JNT/block ≈ 5,260 JNT/yr ≈ 0.013 %/yr
```

The tail is the approved policy (Decisions M-A…M-C): the ladder's last rung is
followed by 0.50 → 0.25 → 0.125 JNT and then a **permanent 0.1 JNT floor**, so
issuance never stops. Long-run issuance is therefore unbounded by design and the
bound that consensus enforces is per-height, not a total:
`cumulative_issuance_sat(height)`, clamped by the cap as a sanity ceiling (M-D).

On `mini`/`testnet` the same ladder over 2,000-block epochs reaches
**297,924 JNT issued** against the 304,000 JNT cap; **6,076 JNT is permanently
unmintable**. Their tail is a constant **1 sat/block** (M-C): the mainnet value
on a 1-second profile would mint a four-digit percentage per year against its
own cap (`sim/supply_schedule_sim.py` prints `max_reachable_jnt 297924 /
hard_cap_jnt 304000 / unmintable_jnt 6076`).

The unmintable surplus is *provable*, not reserved: anyone can compute it
with `supply::max_issuance_sat`. If a block reward would cross the bound, the
block is refused (`supply::check_mint_at_height` → `SupplyCapExceeded`) and the
surplus is never created.

## Fee model (M1 — 50/50 PSCB split)

SPEC.md §8, implemented in `fees::split_fees` / `fees::split_flat_fee`:

| Component | Destination |
|---|---|
| **Burn** | 50% of the base-fee portion (ceil — the odd satoshi goes here), removed from the UTXO set forever |
| **PSCB** | 50% of the base-fee portion (floor) to the Protocol Security & Compute Buffer reserve |
| **Miner tip** | The full tip (`total_fees − base_fee × gas_used`) goes to the block producer |

Both L1 (`split_fees`) and L2 (`split_flat_fee`, Decision D3) round the same
way — `flat_split_puts_the_odd_satoshi_where_split_fees_does` pins it — so an
L1 fee and an L2 fee of the same size burn identical amounts. The PSCB does
not count toward the cap: those satoshis are already destroyed for cap
purposes, and the reserve is a protocol-owned accounting claim on them.

L1 has a gas floor (`min_tx_fee = base_fee × GAS_TX_BASE`, `GAS_TX_BASE =
16,000`); L2 transactions pay the flat D3 schedule
(post 5,000 / claim 2,000 / submit 2,000 / dispute 10,000 / settle 20,000
sat) and never consult the L1 floor (`l2_fees_do_not_use_the_l1_gas_floor`).

## Escrow and the L2 deposit sink (Decisions 7 and 10)

- **Genesis escrow (Decision 7, amended by M-E):** `l2_genesis_escrow_sat` is
  a *reallocation of unmintable headroom*, not new issuance: mainnet 100,000
  JNT of the 788,476 JNT that can never be minted; mini/testnet 10 JNT of
  6,076 JNT. Since the tail (M-E) the backing rule is the explicit, validated
  `escrow_ceiling_sat` — the old `cap − max_issuance_sat` gap rule is gone,
  because with a tail it no longer describes anything.
  `params::validate` rejects any profile whose escrow exceeds its ceiling
  (`escrow_respects_the_new_ceiling`).
- **User deposits (Decision 10):** an ordinary L1 payment to the
  network-bound `l2_deposit_sink` address (unspendable, holds no key) is
  read by L2 replay as a deposit, credited 1:1 after
  `finality_depth` (mini/testnet 20, mainnet 100 blocks). Sink outputs stay
  in the L1 UTXO set forever.
- **Exits:** none exist. L2→L1 withdrawal is a recorded mainnet blocker
  (`docs/l2-exit-design.md`; deferred by Decision 10). No exit path may mint or
  release value until that decision is recorded.

## Conservation laws (tested)

1. No inflation beyond the integral: `supply::tests::no_block_can_mint_beyond_cumulative_issuance`
   and `supply::tests::derived_supply_bound_holds_at_every_height`
2. No value creation from thin air: `ledger::tests::total_value_never_exceeds_the_cap_and_never_wraps`
3. Value conservation in transactions: `ledger::tests::a_transaction_can_never_create_more_value_than_it_spends`
4. L1 + L2 supply never exceeds the joint bound: `jnt-node` `tests/l2_funding.rs::joint_l1_plus_l2_supply_never_exceeds_the_cap`
   and `GET /v1/conservation` (issuance integral + escrow ceiling)
5. Escrow respects its own ceiling: `params::tests::escrow_respects_the_new_ceiling`

## Policy decisions

- **Decision 3 (§16):** mainnet reward ladder shape — matches
  `supply::tests::mainnet_reward_ladder`.
- **Decision D3 / Decision 1:** L2 fee schedule — see
  `l2::tests::fee_mapping_is_the_decided_d3_schedule`. The settle fee is
  fixed; no fee was changed by any Phase-6 milestone.
- **Decisions M-A…M-G (2026-10-09):** tail shape (E, decay to a floor),
  0.1 JNT mainnet floor, 1 sat/block on mini/testnet, cap retained as a sanity
  ceiling, an explicit `escrow_ceiling_sat`, no fee-burn target (deflation
  accepted), activation at each profile's ladder exhaustion. Implemented in
  `supply.rs`/`params.rs`/`chain.rs`, vectors regenerated, and pinned by
  `supply::tests::*`, `params::tests::*`, `sim/supply_schedule_sim.py
  --selftest` and `sim/tail_emission_sim.py --selftest`.
- The 39,945,600 JNT cap (as a sanity ceiling), the issuance paths, block
  rewards, halving schedule, tail values and both fee schedules are **frozen**
  at the recorded decisions; changing any of them is a consensus monetary
  decision requiring explicit sign-off (roadmap item 19).

## References

- `SPEC.md` §5 (PoW), §7 (supply schedule), §8 (fees), §10 (profiles)
- `crates/jnt-core/src/supply.rs` (implementation + tests)
- `crates/jnt-core/src/fees.rs` (M1 fee split)
- `sim/supply_schedule_sim.py` (independent Python reference cross-check)
- `tests/vectors/supply_vectors.json` (pinned numbers)
