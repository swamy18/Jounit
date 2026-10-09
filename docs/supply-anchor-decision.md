# The supply anchor: replacing the stock cap with a rate rule

**Status: PROPOSED 2026-10-09 (owner asked for the decision; awaiting sign-off on
the mechanism before implementation).** Supersedes the `supply_cap_sat` design
in SPEC.md §7/§10 and Decisions 7 and 10 — *if* approved. Nothing here is
implemented yet; this document is the analysis, the decision, and the migration
plan.

## 1. The question

Should JNT keep a fixed numerical supply cap (39,945,600 JNT), have no cap at
all, or use a different kind of cap?

The owner's goal is a currency for AI, robotics and humans that people can buy,
sell, hold and settle business in — useful at today's scale and at a
Mars-scale one.

## 2. What the shipped design already decided

Two things are already approved and cannot both be true at once:

- **A permanent tail** (M-A…M-C, 2026-10-09): mainnet decays
  `0.5 → 0.25 → 0.125` JNT per block and then pays a **permanent 0.1 JNT floor**,
  so the security budget never reaches zero.
- **A hard stock cap** of 39,945,600 JNT, still enforced as a `min()` in the
  mint bound.

**These contradict each other.** Measured with the project's own model
(`sim/tail_emission_sim.py`, policy `DECAY` at the recommended floor):

| Quantity | Value |
|---|---|
| Stock cap | 39,945,600 JNT |
| Ladder-era integral (exact) | 39,157,124 JNT |
| Permanently unmintable under the cap | 788,476 JNT |
| Cap binds at | block **8,213,259** ≈ **156.2 years** from genesis |
| Issuance after that block | **0, forever** |
| Floor issuance before the cap | 0.1 JNT/block × 52,596 blocks/yr = **5,260 JNT/yr** |
| Floor as a share of supply | **0.0132 %/yr** |

So "permanent floor" means *156 years, then nothing*. After that the chain is
paid by fees alone. That is the whole argument against the stock cap: the cap
silently repeals the tail.

The relative dilution of the floor is also self-eliminating as the economy
grows — the same 5,260 JNT/yr is 0.0132 % of today's supply, **0.0013 % at 10×
supply, and under 0.0001 % at 100×**. An absolute trickle becomes
non-dilutive purely by the supply growing. A numerical cap does not have that
property; it has the opposite one.

## 3. Options considered

**A — keep the fixed stock cap.** Credible and familiar, but: it repeals the
permanent tail after 156 years; it leaves a growing real economy to transact in
a strictly deflating unit, where hoarding beats spending and every nominal
contract (wages, debt, machine service subscriptions) becomes a bet on the
deflator; and it makes the smallest unit coarser exactly as demand grows, which
is backwards for machine-to-machine micropayments. *Reject.*

**B — no cap, discretionary issuance.** Rejected without hesitation: a currency
people hold for business must have a rule nobody can turn, including its author.
Discretionary supply is the debasement risk a currency is supposed to solve.

**C — no stock cap, rule-based issuance + burns (chosen).** Issuance is a pure
function of height (the ladder, then the tail). Burns already exist (the M1
50/50 fee split, and slashing). Net issuance can be negative. Long-run dilution
tends to zero because the tail is absolute, so the protocol stays credibly
non-inflationary **and** never has a zero security budget.

**D — a rate cap instead of a stock cap (chosen, on top of C).** This is the
"different kind of cap" the question asked for: the anchor stops being a
*quantity of coins* and becomes a *bound on the rate of dilution*. It keeps the
only job the stock cap actually did — protecting holders from debasement — in a
dimension that scales from one user to a trillion, and it cannot be repealed by
the same 156-year accident because it bounds every period, not the total.

## 4. Decision

1. **Remove `supply_cap_sat` as a consensus bound.** The mint bound becomes the
   issuance integral alone: `bound = cumulative_issuance_sat(height)` — the
   `.min(cap)` in `supply::check_mint_at_height` goes.
2. **Keep issuance deterministic.** Ladder, then tail. No governance knob, no
   oracle, no measurable input from outside the chain. Every number is
   recomputable from the block height by anyone.
3. **Add a rate anchor** (the replacement for the stock cap):

   > After the ladder era, gross issuance in any `halving_period` must not exceed
   > **1 % of the supply issued so far** — i.e. ≤ **0.2 %/yr**, with no term
   > that can be raised without a deliberate, visible consensus change.

   Calibration: the largest tail period issues 0.5 JNT/block × 262,800 =
   131,400 JNT against ~39.16 M issued — **0.336 %**, so the ceiling sits ~3×
   above the schedule and never binds in normal operation, while still refusing
   a schedule that would dilute 10× faster. The ladder era is **grandfathered**
   and bounded instead by its own constants (the ladder cannot issue more than
   39,157,124 JNT, provable from the rungs alone), which is why the rate anchor
   governs the steady state rather than all of history.
4. **The tail floor stays** (0.1 JNT/block mainnet, 1 sat/block mini/testnet):
   it is both the security-budget floor and the reason the rate anchor is never
   the binding constraint.
5. **Burns stay, and the supply surface reports *net*.** Gross issuance is the
   schedule property the anchor bounds; dilution is what holders experience, so
   `/v1/conservation`, `/metrics` and `status` must show issuance minus burns.

## 5. Why this is the right answer for the stated goal

- **Store of value:** unchanged in substance. Long-run dilution still tends to
  zero, no one can print, and the rule is verifiable from the chain alone.
- **Medium of exchange and unit of account:** a hard cap makes the unit
  deflationary, which is bad for exactly the use cases named — business
  settlement, wages, subscriptions, machine service payments. A tiny, bounded,
  predictable trickle is what lets a currency be *spent* rather than only
  *hoarded*.
- **Security budget:** the tail can never be repealed by the cap, so block
  producers are never left with fees alone on a chain whose proof-of-work is
  expensive by design (hybrid hash + neural puzzle).
- **Trillion-agent scale:** this does **not** come from the number of coins, and
  it would be a mistake to think it does. 39.9 M JNT is 3.99 × 10¹⁵ satoshis;
  scale is served by **divisibility and throughput**, not by supply count. The
  real scaling work is (a) sub-satoshi accounting for machine micropayments,
  which belongs in the L2 account layer, and (b) L1/L2 throughput. The rate
  anchor helps only in the sense that it keeps the smallest unit from becoming
  unusably precious.

## 6. Migration — why this needs no activation height

Every existing block stays valid. The old bound was
`min(cumulative_issuance_sat(h), cap)`; the new one is
`cumulative_issuance_sat(h)`, which is **never smaller**. A bound that only
loosens cannot invalidate a block that already satisfied the tighter rule, so
historical validation is byte-identical and no network-upgrade mechanism is
required — unlike the L2 → L1 exit rule (P1), which adds a genuinely new rule
and does need one.

The escrow rule does need re-expressing: `l2_genesis_escrow_sat` was justified
as "a slice of the 788,476 JNT the ladder can never mint", and with the cap gone
that gap is no longer a meaningful quantity. The escrow stays bounded by the
explicit `escrow_ceiling_sat` (M-E) and by the L2 consensus checks; only the
prose that leaned on the cap has to change.

## 7. Blast radius (measured, not estimated)

| Area | Files |
|---|---|
| Mint bound, sanity gate, reward helpers | `supply.rs` (`check_mint_at_height`, `check_mint`, `reward_exceeds_remaining`, `max_issuance_sat`) |
| Block validation, supply report | `chain.rs` (mint gate, `supply_report.cap_sat`) |
| Parameters | `params.rs` (field, both profiles, display helper, escrow-gap justification) |
| Conservation surface | `chain.rs`/`conservation.rs` `cap_sat` term, `/v1/conservation`, `/metrics` |
| Tests | `supply.rs` unit tests, `redteam.rs`, `genesis_funding.rs`, `conservation*.rs`, `api.rs`, `l2_deposits.rs`, `l2_funding.rs`, `cli_run.rs` |
| Model + vectors | `sim/tail_emission_sim.py` (already models policies A–E and needs a rate-ceiling policy), `sim/supply_schedule_sim.py`, `tests/vectors/supply_vectors.json` |
| Docs | `SPEC.md` §7/§10, `docs/monetary-policy.md`, `docs/mainnet-readiness.md`, `README.md`, Decisions 3/7/10 |

## 8. Staging

1. **Decision recorded** (this document + `decisions.md`), owner sign-off.
2. **Remove the stock cap** from the bound and from the report; re-express the
   escrow justification; update tests and vectors. Small, monotone, safe.
3. **Add the rate anchor** as a schedule invariant (`params.validate` plus a
   consensus check at period boundaries) with its own tests and a sim policy.
4. **Net-supply reporting** on the conservation surface, so dilution is what
   users see.
5. **Docs** (SPEC, monetary policy, README, readiness) in the same commit as 4.

Stages 2–5 are `jnt-core`-local except the reporting in stage 4.
