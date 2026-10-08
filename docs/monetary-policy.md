# Monetary Policy

## Design

JNT is a **fixed-supply, time-based issuance** cryptocurrency. Total supply is capped at **10,000,000 JNT**
(10⁶ × 10⁶ sat = 10¹⁸ sat). Issuance follows a halving schedule with 10 halving epochs, each lasting
`REWARD_HALVING_INTERVAL` blocks.

## Parameters

| Parameter | Mainnet | Testnet / Mini |
|---|---|---|
| `TARGET_SUPPLY_SAT` | 1,000,000,000,000,000 (10²¹) | 1,000,000,000,000,000 |
| `INITIAL_REWARD_SAT` | 100,000,000 (1 JNT) per block | 100,000,000 |
| `REWARD_HALVING_INTERVAL` | 210,000 blocks | 100 blocks |
| `MAX_HALVINGS` | 10 | 10 |
| `GENESIS_MINT` | 0 (nothing pre-mined) | 0 |

## Issuance Schedule

```
Epoch 0: 210,000 blocks × 1.0 JNT/block = 210,000 JNT
Epoch 1: 210,000 blocks × 0.5 JNT/block = 105,000 JNT
Epoch 2: 210,000 blocks × 0.25 JNT/block = 52,500 JNT
...
Epoch 9: 210,000 blocks × 0.001953125 JNT/block = 409.6 JNT
────────────────────────────────────────────────────────
Total issuance: 9,999,999.999609375 JNT ≈ 10,000,000 JNT (cap)
```

On `mini` (testnet), halvings occur every 100 blocks, reaching the cap at block 1000.

## Fee Model (M1 — 50/50 PSCB Split)

SPEC.md §8 defines the fee split:

| Component | Destination |
|---|---|
| **Burn** | 50% of base fee (per-block, per-gas) |
| **PSCB** | 50% of base fee goes to the Protocol Security & Compute Buffer |
| **Miner tip** | Full tip (priority fee) goes to the block producer |

The PSCB pool funds future compute rewards (M1 reserve) and anti-collusion slashing (M2 vault). It is
**not a treasury** — it is locked in a deterministic escrow address that is network-bound per SPEC.md §9.2.

## Escrow (L2 Deposit Mechanism)

L2 deposits are credited to the L1 → L2 escrow sink on the L1 chain. This sink is a deterministic
network-bound address (`l2_escrow_identity`), not a custodial wallet. The unmintable gap between genesis
mint (0) and max issuance is exactly the escrow supply on both profiles, verified by
`mini_genesis_escrow_fits_the_unmintable_gap_on_both_profiles`.

## Conservation Laws

1. **No inflation beyond cap:** `supply::tests::cap_is_a_hard_invariant`
2. **No value creation from thin air:** `ledger::tests::total_value_never_exceeds_the_cap`
3. **Value conservation in transactions:** `ledger::tests::a_transaction_can_never_create_more_value_than_it_spends`
4. **L1+L2 supply never exceeds cap:** `l2_funding::tests::joint_l1_plus_l2_supply_never_exceeds_the_cap`

## Policy Decisions

- **Decision 3 (§16):** Mainnet reward ladder: starts at 1 JNT, ends at 100 sat, with the ladder shape
  matching `supply::tests::mainnet_reward_ladder`.
- **Decision 11 (§14):** L2 fee schedule (D3) — see `l2::tests::fee_mapping_is_the_decided_d3_schedule`. The
  settle fee is fixed; the post fee is gas-linear with the gas price at the time of submission.

## References

- SPEC.md §5 (block reward & halving)
- SPEC.md §8 (fee model)
- SPEC.md §9 (supply cap & escrow)
- `crates/jnt-core/src/supply.rs` (implementation)
- `crates/jnt-core/src/fees.rs` (M1 fee split)
- `sim/supply_schedule_sim.py` (independent Python reference cross-check)
