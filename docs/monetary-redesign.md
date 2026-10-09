# Jounit Monetary Policy — Long-Term Design and Recommendation

**Status: PROPOSAL. NOT IMPLEMENTED. NOT MAINNET READY.**
No consensus code, reward parameter, fee, genesis value, committed vector or
protocol invariant has been changed. This document designs; a later phase
implements, in small reviewable commits, after explicit approval.

Reproduce every number with:

```bash
python sim/tail_emission_sim.py             # comparative analysis
python sim/tail_emission_sim.py --selftest  # assertions + committed-vector cross-check
```

Related: `docs/monetary-policy.md`, `docs/decisions.md` (Decisions 2.3, 7, 10;
*Pending* P1–P6), `docs/l2-exit-design.md`, `docs/validator-economics.md`,
`SPEC.md` §7/§8/§10/§19.4, `docs/roadmap.md` items 18–22.

---

## 0. Verdict (read this first)

**Is Policy E safe to implement? Safe as an issuance rule — not yet safe to
ship, because six monetary parameters are still unapproved and one economic risk
(the fee-burn/deflation design) is unowned.**

E is **safe** in every property that is actually about issuance:

- **No large discontinuity** (1.00 → 0.50 → 0.25 → 0.125 → 0.10): three −50 %
  halvings and one **−20 % clamp** into the floor. Its largest step is no worse
  than the −50 % halvings already in the ladder, against D's −90 % step at a
  publicly known height. (A literal "continuous" claim would be false — see §2.5.)
  **Bounded and non-discretionary:** an exact satoshi
  amount, a pure function of height, no accumulator, no supply read, no float.
- **It cannot inflate past the envelope:** the per-block coinbase bound
  (`minted ≤ reward + tip`, [chain.rs:479](crates/jnt-core/src/chain.rs#L479))
  plus the derived `live ≤ cumulative_issuance_sat(height)` bound make the
  inflation argument a *proof*, not a parameter choice (§5.2).
- **Activation is replay-safe:** activating at exhaustion (1,839,600) leaves all
  existing history byte-identical (§5.4).
- **Its economic magnitude is small:** 0.0134 %/yr dilution, +493,110 JNT vs A by
  year 100 — 1.26 % of supply, and less than half of one year of full-block fee
  removals.

**What E does *not* fix, and must not be sold as fixing:** Jounit is
**deflationary under ordinary usage** (§2.3), because the whole base fee leaves
live supply while the tail is 200× smaller at full blocks. E buys a *mining
security floor*; it does not buy an inflation target.

### Exact remaining blockers (all must close before M3 consensus work)

1. `tail_floor_sat` = 0.1 JNT — **proposed, unapproved**; the value cannot be set
   defensibly from anything in this repository (§3.3 decision rule).
2. Decay (E) vs flat (D) — **proposed, unapproved**.
3. `escrow_ceiling` — the explicit replacement for `cap − max_issuance_sat`
   ([params.rs:519](crates/jnt-core/src/params.rs#L519)) does not exist yet.
4. mini/testnet tail (proposed 1 sat/block) — **unapproved**, and mis-applying the
   mainnet value would mint >1,000 %/yr (F5).
5. Fate of `supply_cap_sat` (deleted or kept as a sanity ceiling).
6. **F2 (fee-burn / deflation design)** — newly *quantified* here, owned by no
   existing decision. Not a blocker for E, but a blocker for claiming the
   monetary policy is complete.
7. P1–P5 (exit, committee, M2 rule, M4 registration, settle fee) remain
   undecided; they gate mainnet independently of E.

---

## 1. Verified current-state audit

### 1.1 Every value below was read from the repository, not carried over

| Parameter | mainnet | mini / testnet | Source |
|---|---|---|---|
| `target_block_time_ms` | 600,000 (10 min) | 1,000 (1 s) | [params.rs:291](crates/jnt-core/src/params.rs#L291), [:337](crates/jnt-core/src/params.rs#L337), [:409](crates/jnt-core/src/params.rs#L409) |
| `halving_period` | 262,800 | 2,000 | params.rs |
| `start_reward_sat` | 76 JNT | 76 JNT | params.rs |
| `supply_cap_sat` | **39,945,600 JNT** | **304,000 JNT** | params.rs |
| `base_fee_initial_sat` / `min` / `max` | 1,000 / 100 / 50,000,000 | 100 / 10 / 1,000,000 | params.rs |
| `gas_cap` | 2,000,000 | 2,000,000 | params.rs |
| `coinbase_maturity` | 100 | 10 | params.rs |
| `finality_depth` | 100 | 20 | params.rs |
| `l2_genesis_escrow_sat` | 100,000 JNT | 10 JNT | params.rs |
| `SAT_PER_JNT` | 100,000,000 | — | [params.rs:11](crates/jnt-core/src/params.rs#L11) |
| `GAS_TX_BASE` | 16,000 | — | [tx.rs:36](crates/jnt-core/src/tx.rs#L36) |
| L2 flat fees | post 5,000 / claim 2,000 / submit 2,000 / dispute 10,000 / settle 20,000 sat | same | [params.rs:45–58](crates/jnt-core/src/params.rs#L45) |

**The reported headline values are confirmed:** cap 39,945,600 JNT, zero premine,
76 JNT start reward, 262,800-block halving. Two corrections to commonly repeated
figures: the **ladder exhausts at height 1,839,600 (~34.98 years)**, not 8
periods (76 ≫ 7 = 0), and reachable issuance is **39,157,200 JNT**, leaving
**788,400 JNT permanently unmintable**.

### 1.2 Derivation of the reachable ceiling (verified)

```
ladder = 76, 38, 19, 9, 4, 2, 1, 0          sum(76..1) = 149
reachable = 149 × 262,800 = 39,157,200 JNT
cap − reachable = 39,945,600 − 39,157,200 = 788,400 JNT
mini  = 149 × 2,000 = 298,000;  304,000 − 298,000 = 6,000 JNT
```
Both are pinned by `supply::tests`, `sim/supply_schedule_sim.py` and
`tests/vectors/supply_vectors.json`; `--selftest` re-derives all of them.

### 1.3 Every code path that creates or bounds supply

| Path | Location | Role |
|---|---|---|
| `period_reward_sat` / `block_reward_sat` | [supply.rs:26,38](crates/jnt-core/src/supply.rs#L26) | the reward function (whole-JNT halving) |
| `cumulative_supply_sat` | [supply.rs:47](crates/jnt-core/src/supply.rs#L47) | issuance after N blocks |
| `max_issuance_sat` | [supply.rs:67](crates/jnt-core/src/supply.rs#L67) | reachable ceiling — **also the escrow anchor** |
| `check_mint` / `reward_exceeds_remaining` | [supply.rs:80,96](crates/jnt-core/src/supply.rs#L80) | library mint gate |
| **consensus cap gate** | [chain.rs:489–502](crates/jnt-core/src/chain.rs#L489) | `apply_block` refuses a block that pushes `utxo.total_value()` over the cap |
| **per-block coinbase bound** | [chain.rs:479–487](crates/jnt-core/src/chain.rs#L479) | `minted ≤ reward(height) + tip` |
| fee burn (M1) | [fees.rs](crates/jnt-core/src/fees.rs) | 50 % of base fee destroyed, 50 % PSCB, tip to miner |
| escrow gap-fit | [params.rs:519](crates/jnt-core/src/params.rs#L519) | `escrow ≤ cap − max_issuance_sat` |
| joint conservation | [main.rs:879–887](crates/jnt-node/src/main.rs#L879) | `L1 live + L2 held − sink ≤ cap` |

The cap is enforced **twice** (library + live state). Consensus depends on the
live-state gate and on the per-block coinbase bound; `check_mint` is the
arithmetic model.

### 1.4 Everything a policy change touches

- **Code:** the 5 sites in §1.3, `Error::SupplyCapExceeded`
  ([error.rs:77](crates/jnt-core/src/error.rs#L77)), the supply report
  ([chain.rs:1264](crates/jnt-core/src/chain.rs#L1264)), the node prints
  ([main.rs:489](crates/jnt-node/src/main.rs#L489)), `params::validate`.
- **Tests/vectors:** 11 items listed in §6.4 plus `supply_vectors.json`.
- **Docs:** `SPEC.md` §7 and §19.4, `docs/monetary-policy.md`,
  `docs/decisions.md` (Decisions 7/10 "unchanged" clauses), `docs/roadmap.md`
  items 19/20.
- **Invariants:** the cap is currently the *joint L1/L2 conservation anchor* and
  the *escrow backing rule* — not merely a supply ceiling. Removing it without a
  replacement silently removes both checks (§6.2).

---

## 2. Quantitative comparison of the alternatives

Modeled assumptions (labelled): 365.25-day years; 52,596 blocks/year mainnet;
**the entire base-fee portion leaves live supply** (M1 destroys 50 % and routes
the other 50 % to the `pscb_reserve` counter, which no code path converts back
into UTXOs — verified 2026-10-09, [chain.rs:527](crates/jnt-core/src/chain.rs#L527),
[chain.rs:479](crates/jnt-core/src/chain.rs#L479), [fees.rs:61](crates/jnt-core/src/fees.rs#L61));
fee revenue = base fee × gas used. **All price figures are sensitivity
parameters, not forecasts.** Circulating supply is approximated by cumulative
issuance (no lost-key model).

### 2.1 Annual issuance and dilution of non-mining holders

| Policy | annual JNT | dilution @39.16M | @20M | @10M |
|---|---:|---:|---:|---:|
| **A** fixed cap, no tail | 0 | 0.0000 % | 0.0000 % | 0.0000 % |
| **B** tail 1.00 JNT | 52,596 | 0.1343 % | 0.2630 % | 0.5260 % |
| **C** tail 0.50 JNT | 26,298 | 0.0672 % | 0.1315 % | 0.2630 % |
| **D** tail 0.10 JNT | 5,260 | 0.0134 % | 0.0263 % | 0.0526 % |
| **E** decay → 0.10 JNT (recommended) | 5,260 | 0.0134 % | 0.0263 % | 0.0526 % |

For calibration (not a claim about Jounit): Monero's 0.6 XMR/block tail is
≈0.5 %/yr asymptotically. **B at 0.134 %/yr is already low**; E/D at 0.013 %/yr
are 10× lower again.

### 2.2 Cumulative gross issuance

| Policy | y10 | y25 | y50 | y100 |
|---|---:|---:|---:|---:|
| A fixed cap | 29,966,040 | 38,370,600 | 39,157,200 | 39,157,200 |
| B tail 1.00 | 29,966,040 | 38,370,600 | 39,947,400 | 42,577,200 |
| C tail 0.50 | 29,966,040 | 38,370,600 | 39,552,300 | 40,867,200 |
| D tail 0.10 | 29,966,040 | 38,370,600 | 39,236,220 | 39,499,200 |
| **E decay → 0.10** | 29,966,040 | 38,370,600 | **39,387,330** | **39,650,310** |

Every policy is identical through year 25: the ladder dominates and the tail is
irrelevant for a generation. **A and E differ by 493,110 JNT at year 100
(1.26 % of supply) — that is the entire cost of E versus abandoning issuance.**

### 2.3 The burn dominates issuance at high activity (critical finding)

Live supply = cumulative issuance − cumulative base-fee removal (floored at 0).
Removal is the **whole** base fee, not half: `burned + pscb == full_base`, the
`pscb` half is a bare counter with no path back to the UTXO set, and the
coinbase may claim only `reward + tip`. **A previous revision of this section
halved the burn; the table below is the corrected model.**

| Policy | activity | base fee | net y25 | net y50 | net y100 |
|---|---|---:|---:|---:|---:|
| A | normal (25 %) | 100 | 37,713,150 | 37,842,300 | 36,527,400 |
| A | normal | 1,000 | 31,796,100 | 26,008,200 | 12,859,200 |
| A | high (100 %) | 1,000 | 12,072,600 | **0** | **0** |
| E | normal | 100 | 37,713,150 | 38,072,430 | 37,020,510 |
| E | normal | 1,000 | 31,796,100 | 26,238,330 | 13,352,310 |
| E | high | 1,000 | 12,072,600 | **0** | **0** |

**The base-fee removal — not the reward schedule — is the dominant long-run
monetary force whenever the chain is busy.** At sustained full blocks with the
base fee at 1,000 sat, removal is **20 JNT/block = 1,051,920 JNT/year versus
5,260 JNT/year of E tail**: a **200×** ratio, and E's tail cannot offset it.
Consequences that must be stated in any policy text:

1. "No cap" **⇏** "always inflationary". Net supply can fall for decades.
2. **Break-even is low.** At the fee floor (100 sat) with normal 25 % activity,
   0.50 JNT/block is removed against E's 0.10 JNT/block tail → **−0.40 JNT/block,
   i.e. net deflation at ordinary usage**. Half-rate activity (5 %) is the
   break-even point; below it E is mildly inflationary, above it the chain
   contracts. Jounit's steady state is therefore **deflationary, not
   inflationary**, under any realistic load.
3. At sustained high activity the modeled net supply reaches **0** — before that
   the base fee would escalate (it rises 1/512 per full block toward the
   50,000,000 sat cap), so this is a *scenario parameter*, not a prediction; but
   it identifies a **fee-design risk owned by §8, not by issuance**. The tail is
a *security* floor and must never be sold as the fix for it.
4. Base fee is endogenous, so "high activity at a fixed base fee" is conservative.

**Implication for E specifically:** the +493,110 JNT E adds over A by year 100 is
~47 % of *one year* of full-block removals. E changes the long-run supply path
only when the chain is quiet; it buys miner security, not a supply target.

### 2.4 Security budget (subsidy + full fee revenue)

| activity | base fee | JNT/block | JNT/year | @$0.10 | @$1 | @$10 | @$100 |
|---|---:|---:|---:|---:|---:|---:|---:|
| idle | any | 0.10 | 5,260 | 526 | 5,260 | 52,596 | 525,960 |
| normal | 100 | 0.60 | 31,558 | 3,156 | 31,558 | 315,576 | 3,155,760 |
| normal | 1,000 | 5.10 | 268,240 | 26,824 | 268,240 | 2,682,396 | 26,823,960 |
| high | 1,000 | 20.10 | 1,057,180 | 105,718 | 1,057,180 | 10,571,796 | 105,717,960 |

**The decisive argument against A.** After ladder exhaustion with no tail the
miner receives **tips only** — which are **zero on an idle chain**. Security
budget collapses to exactly 0 precisely when the network is quietest, and a
reorg becomes free. No monetary policy can fix that except a non-zero tail. This
is stronger than any inflation argument and is why **A is rejected**.

**The tail is a floor, not a budget.** At normal activity the fee component
(0.5 JNT/block at the fee floor) already exceeds the 0.1 JNT tail; at high
activity at an elevated base fee (1,000 sat) fees are 2.0 JNT/block, **20×** the
tail, and 200× at 10,000 sat. The tail's entire job is to keep the idle-case
budget non-zero.

### 2.5 Discontinuity, per candidate

| transition | reward before → after | step |
|---|---|---|
| ladder → **1.00** JNT | 1.00 → 1.00 | **0.00 (continuous)** |
| ladder → 0.50 | 1.00 → 0.50 | −0.50 |
| ladder → 0.25 | 1.00 → 0.25 | −0.75 |
| ladder → 0.10 | 1.00 → 0.10 | −0.90 |
| ladder → **E decay** | 1.00 → 0.50 → 0.25 → 0.125 → **0.10** | three −50 % halvings, then a **−20 % clamp** to the floor |
| ladder → **A** (fixed cap) | 1.00 → **0.00** | −100 % (mining stops) |

Correction to earlier revisions of this section: **"E is continuous" was an
overstatement.** E's last transition is 0.125 → 0.10, a −20 % clamp. The precise
claim is **no step greater than a halving**. That is still the strongest position
available: the existing ladder already contains 19 → 9 (−52.6 %), 9 → 4 (−55.6 %)
and 4 → 2 (−50 %) steps, so E introduces nothing worse than what the protocol
already does, while D's −90 % and A's −100 % steps are unprecedented. **B** (flat
1.0 JNT) is the only literally step-free candidate.

**Quantified cost of smoothness:** E issues **151,110 JNT more than D by year 50**
(~0.386 % of supply, one-time). That is the entire price of shrinking the step from
−90 % to −20 %.

### 2.6 Integer arithmetic, rounding, overflow

- Every candidate is an **exact** whole number of satoshis (0.1 JNT = 10,000,000 sat).
- u64-sat overflow headroom: mainnet 0.1 JNT/block → **35.1 M years**; mini
  1 sat/block → **5.85 × 10¹¹ years**. Overflow is unreachable, and `--selftest`
  fails if it ever drops below 1,000 years.
- Determinism: the reward is a pure function of height — no accumulator, no
  supply read, no float. A percentage-of-supply tail is **rejected** because it
  would require mutable supply in consensus plus a rounding rule.

### 2.7 Adversarial / concentration considerations (qualitative)

- **Miner exit (A).** Idle chain → 0 subsidy → mining stops. Highest-severity
  failure of A; mechanical, not speculative.
- **Security-budget erosion (B).** 0.134 %/yr dilution is low, but B's *absolute*
  issuance (52,596 JNT/yr) is ~$526k/yr at $10/JNT — still small versus the value
  it secures. A larger tail does **not** buy proportional security because price
  and fees dominate. This is the core reason not to over-issue "for security".
- **Concentration.** A constant absolute subsidy is proportionally more valuable
  to the marginal (least efficient) miner, which is mildly decentralizing; a
  subsidy that declines with price (none proposed here) would be centralizing.
- **Fee-burn spiral.** Sustained burns reduce supply and raise the real cost of
  the base fee; §8 owns this risk.

---

## 3. Recommendation

### 3.1 Primary recommendation: Policy E — smooth decay tail to a permanent floor

> **Keep the existing 8-rung whole-JNT ladder unchanged. After its last non-zero
> rung (1 JNT), continue halving the subsidy **in satoshis** every halving period
> until a permanent floor of 0.1 JNT/block, then pay that floor forever. No
> premine. No discretionary minting. No validator rewards.**

Proposed mainnet parameters (**proposed — not approved**):

| Parameter | Proposed value | Reached at |
|---|---|---|
| `tail_decay_step` | each halving period | — |
| `tail_floor_sat` | **10,000,000 sat (0.1 JNT)** | period 10 = height 2,628,000 (~50 y) |
| tail path | 1.00 → 0.50 → 0.25 → 0.125 → 0.10 → 0.10 … | continuous with the ladder |
| `tail_activation_height` | **1,839,600** (exhaustion) | all history byte-identical |

### 3.2 Why E, and why not the others

| Candidate | Verdict | Reason |
|---|---|---|
| **A** fixed cap | **Rejected** | Idle-chain security budget → 0; mining stops. No issuance policy can repair it (§2.4). |
| **B** 1.00 JNT flat | Rejected as default | 10× E's dilution for a security benefit that fees dwarf whenever the chain is used. Continuous, so it is the **simplest safe** option if minimal change is valued. |
| **C** 0.50 flat | Rejected | Arbitrary midpoint: more dilution than D, still has the 1→0.5 step. |
| **D** 0.10 flat | **Acceptable fallback** | Lowest dilution of the flat options; one 1→0.1 (90 %) step at a known height. If the owner prefers minimal code change, ship D. |
| **E** decay → 0.10 (rec.) | **Recommended** | Lowest long-run issuance, non-zero floor, **largest step ≤ a halving** (clamp is −20 %), and the decay follows the *existing* halving metaphor rather than inventing one. Costs 151,110 JNT one-time. |

**Direct answers to the questions asked:**
- *Is 1 JNT/block unnecessarily large?* **Yes** — 0.134 %/yr against E's 0.013 %
  for a floor whose purpose is merely "non-zero"; the extra 47,336 JNT/yr buys
  no demonstrable security because fees dominate whenever there is activity.
- *Do 0.1 and 0.5 create a discontinuity?* **Yes** — 1→0.1 is a −90 % step and
  1→0.5 a −50 % step, both at a publicly known height.
- *Is smoothness more important than security and dilution?* **No — and that is
  why E wins.** Smoothness alone would not justify paying for it; E delivers
  smoothness **and** the lowest dilution **and** the floor, for 0.386 % of supply.

### 3.3 Decision rule if the floor value is contested

The floor should satisfy, at the *idle* steady state:

```
floor_jnt_per_block × blocks_per_year × price = idle annual security budget
      choose the smallest floor such that
      idle annual security budget  ≥  K × (cost of a 51% attack for one year)
```

with `K ≥ 1`. **Missing evidence to set the floor numerically** (none of it is in
this repository): (a) JNT's long-run price distribution, (b) honest hashrate and
its capital cost at the activation epoch, (c) hardware efficiency curve,
(d) the fraction of miners that are captured/marginal. Until (a)–(d) exist, any
specific floor is a judgment call, which is why every value in §3.1 is marked
**proposed**. The rule above converts the argument into a measurable criterion
once those four inputs exist; a sensitivity range to argue over: **0.01–1 JNT**.

---

## 4. Mainnet versus mini/testnet

**Do not apply the mainnet per-block tail to the fast profiles.** `mini` and
`testnet` use **1-second blocks = 31,557,600 blocks/year — 600× mainnet**.

| Profile | blocks/year | proposed tail | annual issuance | as % of its cap |
|---|---:|---|---:|---:|
| mainnet | 52,596 | 0.1 JNT/block | 5,260 JNT | 0.0132 % |
| mini | 31,557,600 | **1 sat/block** | 0.3156 JNT | 0.000104 % |
| testnet | 31,557,600 | **1 sat/block** | 0.3156 JNT | 0.000104 % |

- **Applying 0.1 JNT/block to mini/testnet would mint 3,155,760 JNT/year against
  a 304,000 JNT cap — over 1,000 % per year.** This is the single most important
  per-profile finding.
- **Do the test profiles need a tail at all?** Their ladder exhausts at height
  **14,000 (~3.9 hours)**; without a tail, mining stops permanently after ~4 h,
  which breaks long-running testnets. A **1-sat/block** tail keeps blocks flowing
  forever at negligible issuance, so the answer is *yes, but a token one*.
- Both profiles share `halving_period = 2,000` and `cap = 304,000`, so the same
  parameter serves both; no new profile is needed.
- **Historical compatibility:** activation at each profile's own exhaustion
  height keeps every historical block's reward unchanged.

---

## 5. Consensus invariants

### 5.1 The replacement invariant

The cap participates in **three** distinct rules. All three must be replaced, not
deleted:

| # | Current rule | Replacement |
|---|---|---|
| 1 | `utxo.total_value() ≤ cap` ([chain.rs:491](crates/jnt-core/src/chain.rs#L491)) | `utxo.total_value() ≤ cumulative_issuance_sat(height)` |
| 2 | joint `L1 + L2 − sink ≤ cap` ([main.rs:858–887](crates/jnt-node/src/main.rs#L858)) | `L1 live + L2 held − sink ≤ cumulative_issuance_sat(height) + escrow_ceiling` |
| 3 | `escrow ≤ cap − max_issuance_sat` ([params.rs:519](crates/jnt-core/src/params.rs#L519)) | `escrow ≤ escrow_ceiling` — a **new explicit parameter** |

### 5.2 Is `live_supply ≤ cumulative_issuance_sat(height)` sufficient?

**Sufficient for L1 minting, given the existing per-block bound.** Argument:

1. The only mint path is the coinbase, already bounded by
   `minted ≤ reward(height) + split.tip` ([chain.rs:479–487](crates/jnt-core/src/chain.rs#L479)).
2. `split.tip` is funded from body-transaction fees, i.e. value already removed
   from the UTXO set by the same block (inputs − outputs). It is a transfer, not
   new value.
3. Therefore each block raises `utxo.total_value()` by **at most** `reward(height)`.
4. Burns only *lower* it. Hence the cumulative sum never exceeds
   `Σ reward(h)` = `cumulative_issuance_sat(height)`. ∎

The check is still worth enforcing explicitly as **defence in depth**: it turns a
reward-function bug from an inflation incident into a rejected block, and it is
O(periods) ≤ O(64) — effectively O(1).

**Not sufficient on its own.** Four additional invariants are required:

1. **Single reward source.** `block_reward_sat` must remain the *only* reward
   function, used by the miner, the validator and the node report. Two
   implementations that disagree is an inflation primitive.
2. **Tip funding.** Rule (2) above must stay: a coinbase may claim fees only.
3. **Escrow backing.** `escrow_ceiling` must be an explicit, validated parameter,
   and the L2 invariants that already exist must be kept:
   `L2 funded_total == escrow_total + deposited_total` ([main.rs:863](crates/jnt-node/src/main.rs#L863))
   and per-deposit `sink value == L2 credit` (1:1). Without these, an exit or a
   deposit could double-count (§6.3).
4. **Monotonic bound.** `cumulative_issuance_sat` must be non-decreasing in
   height; a decreasing bound could retroactively invalidate accepted blocks.

### 5.3 Exact issuance formula

```
period(height) = min(height / halving_period, 63)
rung(p)        = (start_reward_sat / SAT_PER_JNT) >> p            # whole JNT, current
reward(height) = ladder rung while rung > 0
               = max(tail_floor_sat, decay_sat(p))               # tail phase
decay_sat(p)   = (1 JNT) >> (p − first_tail_period)               # satoshi halving
```
All integer; no float, no division by a variable, no state.

### 5.4 Activation height and why it is safe

Activate at each profile's **exhaustion height** (mainnet 1,839,600; mini/testnet
14,000). Because `reward(height)` is a pure function of height and every height
below the activation point keeps its ladder rung, **every historical block
validates byte-identically**: same reward, same coinbase, same merkle root, same
block hash, same UTXO and PSCB derivation, same L2 replay. Activating *earlier*
would change the expected reward for already-mined heights and invalidate
history — rejected.

### 5.5 Migration / upgrade assumptions

- No genesis change (still mints nothing); no new profile; no new network magic.
- `supply_cap_sat` is retained as a **sanity ceiling only** (or removed and
  replaced by `max_supply_sat`); it must not stay load-bearing.
- Committed vectors: only `supply_vectors.json` gains fields; the other four
  vector files must not move.
- Rollback: the change is a reward-schedule rule, so reverting means reverting
  the rule — no data migration.

---

## 6. Test and acceptance matrix

### 6.1 New tests (all must exist before merge)

| # | Test | Property |
|---|---|---|
| 1 | `historical_replay_is_unchanged_by_the_tail` | every height < activation yields the ladder rung and identical block hashes |
| 2 | `reward_step_at_the_ladder_tail_boundary_is_at_most_a_halving` | every tail step ≤ 50 %, including the −20 % clamp. **Renamed** — the previous name asserted literal continuity, which the clamp makes false. |
| 3 | `cumulative_issuance_is_monotonic_in_height` | bound never decreases |
| 4 | `no_block_can_mint_beyond_cumulative_issuance` | property test over random heights/rewards |
| 5 | `derived_supply_bound_holds_at_every_height` | 10⁶-height sweep |
| 6 | `a_coinbase_above_reward_plus_tip_is_refused` | existing rule still enforced |
| 7 | `joint_l1_l2_conservation_holds_under_the_tail` | incl. escrow ceiling |
| 8 | `escrow_respects_the_new_ceiling` | params::validate |
| 9 | `l2_funded_total_equals_escrow_plus_deposits` | no double counting |
| 10 | `u64_overflow_unreachable_for_the_decided_tail` | arithmetic proof test |
| 11 | `mini_and_mainnet_tails_are_independent` | per-profile |
| 12 | `activation_survives_reorg_and_restart` | reorg across the boundary, store reopen |
| 13 | `two_nodes_derive_the_same_reward_at_the_boundary` | determinism |
| 14 | `tail_floor_sat_must_be_positive` | params::validate |

### 6.2 Simulation self-tests

`python sim/tail_emission_sim.py --selftest` must exit 0: 11 hand-computed
values, the tail-step bound (no step > a halving; largest exactly 50 %; the clamp
−20 %; floor reached and held — 4 checks), 5 flat-floor boundary checks,
per-policy monotonicity, 2 overflow bounds, 3 supply-removal regression guards,
15 committed-vector comparisons, determinism. It currently **passes** (see §9).

### 6.3 Acceptance criteria per phase

| Phase | Acceptance |
|---|---|
| M1 (decision recorded) | tail rule + floor + activation heights + `escrow_ceiling` written to `docs/decisions.md`; Decisions 7/10 amended **for issuance only** |
| M2 (model) | sim + `supply_schedule_sim.py` exit 0; vectors regenerated; Rust and Python agree to the satoshi at every horizon |
| M3 (consensus) | tests 1–14 pass; `cargo test --workspace` 0 failures; clippy `-D warnings` clean; all 14 fuzz targets re-run, 0 crashes |
| M4 (spec/docs) | SPEC §7/§19.4 and `monetary-policy.md` match the shipped function; no doc still says the cap is frozen |
| M5 (ops) | release checklist green; vectors frozen |

### 6.4 Existing tests that assume a finite maximum supply → replacement

| Test | Replacement |
|---|---|
| `supply::tests::cap_is_a_hard_invariant` | `no_block_can_mint_beyond_cumulative_issuance` |
| `supply::tests::whole_schedule_can_be_minted_within_the_cap` | `the whole schedule matches the simulated issuance` |
| `supply::tests::mini_cap_is_reachable_and_never_exceeded` | per-profile tail bound |
| `supply::tests::cumulative_supply_matches_design_doc` | keep issuance pins; delete the gap pin |
| `supply::tests::max_issuance_never_reaches_the_cap` | `max_issuance_is_the_integral_of_the_reward_function` |
| `supply::tests::mainnet_reward_ladder` | keep rungs; add the tail phase |
| `ledger::tests::total_value_never_exceeds_the_cap_and_never_wraps` | derived bound + keep the no-wrap property |
| `params::tests::l2_genesis_escrow_fits_the_unmintable_gap_on_both_profiles` | escrow ≤ `escrow_ceiling` |
| `l2_deposits.rs` / `l2_funding.rs` joint ≤ cap | joint ≤ bound + ceiling |
| `redteam.rs` cap override | tail override |
| `supply_vectors.json` `hard_cap_jnt`/`unmintable_jnt` | add `tail_floor_jnt`, `tail_activation_height` |

**Invariant that must not be lost:** *supply equals the integral of the reward
function minus cumulative burns, and no block may mint outside it.* Exact, not a
bound — strictly stronger than "≤ cap".

---

## 7. Micropayments and the AI economy

### 7.1 Measured payment floors (mainnet)

| Path | Floor | Cost |
|---|---|---|
| L1 on-chain payment | `base_fee_min × GAS_TX_BASE` = 100 × 16,000 | **1,600,000 sat = 0.016 JNT** |
| L2 settle | flat D3 schedule | 20,000 sat = 0.0002 JNT (**80× cheaper**) |
| L2 post / claim / submit | flat | 5,000 / 2,000 / 2,000 sat |
| L2 deposit into L2 | per sink output | 1,000,000 sat = 0.01 JNT minimum |

**Conclusion: agent-to-agent micropayments belong on L2, and already are cheap
there.** The L1 floor (0.016 JNT) is a spam protection, not a micropayment
mechanism; removing it would reintroduce dust/bloat. **No fee is set to zero and
no spam protection is removed by this proposal.**

### 7.2 Safe low-value payment options (evaluated, not adopted)

| Option | Assessment |
|---|---|
| **L2 batching** (exists: `aggregate_payments` → `PaymentBatch`) | **Recommended and already implemented.** Amortises one gas floor over N payments; no consensus change. |
| Raise the L2 flat schedule | Rejected — makes machine work more expensive than a JNT transfer, contradicting D3. |
| Zero L1 fees | **Rejected** — spam/DoS. |
| **Fee sponsorship** (a third party pays another's L1 fee) | **Needs its own consensus decision.** Introduces fee abstraction, a new authorization surface and griefing risk; out of scope here. |
| Sub-1,600-sat L1 payments via a consensus fee cut | Requires the above; not assumed. |

**Do not assume price appreciation fixes payment economics.** At normal activity
fees are already ≥ the proposed tail; the binding constraint on small payments is
the *L1 floor*, which is a deliberate anti-spam constant.

### 7.3 Interaction with the rest of the protocol

| Subsystem | Interaction |
|---|---|
| **L2 → L1 withdrawals** | Still **undefined** (`docs/l2-exit-design.md`, P1). The sink is unspendable, so no exit can release funds without a new L1 rule. The monetary policy does not change this, and must not be used to justify a fake release path. |
| **Escrow settlement** | Escrow is a genesis allocation, not issuance; the new `escrow_ceiling` replaces the `cap − max_issuance` gap. L2 disputes/bounties draw from PSCB (fee-derived), untouched. |
| **Validator staking/bonding** | **No validator issuance and no fee share** (Decision 2.3). A tail is *miner* emission. If staking is ever rewarded, that is a separate decision and would need its own funding source. |
| **Agent spending policies** | Denominations unchanged (`SpendPolicy` limits are in sat/JNT); a tail does not alter tumbling-window semantics. |
| **Service receipts / reputation** | Value-free; unaffected. |
| **Fee predictability** | Unchanged: the base fee is deterministic EIP-1559-shaped, and L2 fees are flat per type. The tail does not touch either. |

---

## 8. Economic and security failure scenarios

| # | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| F1 | **Idle-chain security budget → 0** | High under A | Critical | A rejected; tail guarantees a non-zero floor |
| F2 | **Fee-burn spiral to 0 supply** (§2.3) | Modeled at sustained full blocks | High | **Fee-design workstream (not issuance).** Requires a separate decision on base-fee/burn; flagged, not solved here |
| F3 | **Tail too large → agent/holder dilution** | Medium | Medium | Choose the lowest defensible floor; 0.1 JNT = 0.013 %/yr |
| F4 | **Discontinuity → hashrate timing attack** | Low–Medium | Low | E removes the step for 0.386 % one-time issuance |
| F5 | **Per-profile tail mis-applied to mini/testnet** | High if not specified | Critical (>1,000 %/yr) | Per-profile parameters; test 11 |
| F6 | **Activation below exhaustion → history rewrite** | Medium if rushed | Critical | Activate at exhaustion; test 1 |
| F7 | **Two reward implementations diverge** | Low | Critical (inflation) | Single source; test 13 |
| F8 | **Escrow unbacked / double count** | Medium | Critical | Explicit `escrow_ceiling`; tests 8, 9 |
| F9 | **Overflow** | Very low | Critical | Exact sat arithmetic; test 10 |
| F10 | **Miner capture / censorship** | Medium | Medium | Constant absolute subsidy favours marginal miners; PoW + PoS-agnostic |

---

## 9. Evidence actually produced in this task

| Command | Result |
|---|---|
| `python sim/tail_emission_sim.py --selftest` | **PASSED, exit 0** — 11 hand-computed values, tail-step bound + clamp + floor checks, 5 flat-floor boundary checks, per-policy monotonicity, 2 overflow bounds, 3 supply-removal regression guards, 15 committed-vector comparisons, determinism |
| `python sim/tail_emission_sim.py` | exit 0 — all tables in §2 |
| `python sim/supply_schedule_sim.py` | exit 0 (pre-existing, unchanged) |
| `python sim/verify_vectors.py --check` | exit 0, all vector files cross-checked |
| Values verified in `params.rs` / `supply.rs` / `tx.rs` / `fees.rs` | §1.1 |

The selftest initially **failed** on one check — a bug in the *check*, not the
model: it compared cumulative issuance across *different* policies. It was fixed
to be per-policy, then passed. That failure is recorded rather than hidden.

**Correction made in this revision (fee-burn accounting).** The earlier model
charged live supply only the M1 `burned` half of the base fee. Re-reading the
code shows the **whole** base fee leaves live supply: `burned + pscb == full_base`
([fees.rs:61](crates/jnt-core/src/fees.rs#L61)), the coinbase may claim only
`reward + tip` ([chain.rs:479](crates/jnt-core/src/chain.rs#L479)), and
`pscb_reserve` is a bare counter that is only ever *added* to
([chain.rs:527](crates/jnt-core/src/chain.rs#L527)) and *rewound on reorg*
([chain.rs:596](crates/jnt-core/src/chain.rs#L596)) — no path converts it back to
UTXOs. The model, §2.3, and the F2 consequences were corrected: removal doubles
(at 1,000 sat full blocks, 1,051,920 JNT/yr, not 525,960) and the break-even
activity is ≈5 %, so the chain is deflationary at ordinary usage. `--selftest`
now contains a regression guard asserting removal is **not** half the base fee.

**Second correction made in this revision (the "no discontinuity" claim).** An
earlier revision claimed E's tail was *continuous*. It is not: the decay path is
1.00 → 0.50 → 0.25 → 0.125 (three −50 % halvings) → **0.10 (−20 % clamp)** at
height 2,628,000. The claim is corrected here to **no step larger than a
halving**, which is still the best available (the existing ladder already has
−52.6 % and −55.6 % steps; D's is −90 %, A's −100 %). The selftest now asserts
the bound instead of continuity, and the acceptance test was **renamed** from
`reward_is_continuous_at_the_ladder_tail_boundary` to
`reward_step_at_the_ladder_tail_boundary_is_at_most_a_halving` because the old
name asserted something false. Writing the new check also exposed a second bug
*in the check itself*: it stepped `h + k × halving_period`, skipping the first
tail period and reporting a bogus −75 % step. It now steps period by period and
prints all six transitions.

**Not run:** `cargo test --workspace` was not re-run, because no Rust, test or
vector file changed in this task and the previous run recorded 773 passing tests,
0 failures. This is stated as a limitation, not as a pass.

---

## 10. Phased implementation plan with dependencies

```
M1 decision ──► M2 model+vectors ──► M3 consensus ──► M4 spec/docs ──► M5 ops
     │
     └─► escrow_ceiling (D.2) ──► unblocks L2 escrow rules

Independent workstreams (from the remaining-work audit):
W1 L2→L1 exit        BLOCKED-BY-DECISION (P1)  ──► mainnet deposits
W2 stake/committee   BLOCKED-BY-DECISION (P2)  ──► mainnet finality
W3 M2 slashing       BLOCKED-BY-DECISION (P3)  ──► depends on W2
W4 M4 registration   BLOCKED-BY-DECISION (P4)
W5 small-task fees   BLOCKED-BY-DECISION (P5)  ──► L2 only
W6 ops (metrics/config/release/repro/audit)    OPERATIONAL
W7 agent payments/identity/recovery            IMPLEMENTATION REQUIRED
W8 testnet + economic stress + launch          OPERATIONAL, needs W1–W6
```

| Phase | Deliverable | Depends on |
|---|---|---|
| M1 | Decision record: tail rule, floor, activation heights, `escrow_ceiling` | this document |
| M2 | Sim + regenerated vectors + cross-check test | M1 |
| M3 | Consensus change + tests 1–14 | M2 |
| M4 | SPEC §7/§19.4, monetary-policy, decisions, roadmap | M3 |
| M5 | Release checklist, frozen vectors | M4 |
| W1–W8 | see table above | their own decisions |

**Ordering rule:** M3 must not begin before M1 is recorded **and** M2's vectors
agree with Rust to the satoshi. No phase may be merged as part of another.

### Unresolved decisions (blockers)

Listed with the same numbering as §0. Items 1–6 are the monetary blockers; item 7
is the independent mainnet gate.

1. **Tail floor value** (`tail_floor_sat`) — proposed 0.1 JNT; decision rule §3.3.
2. **Whether to use decay (E) or flat (D/B)** — proposed E; D is the fallback.
3. **`escrow_ceiling`** — the explicit number replacing `cap − max_issuance_sat`.
4. **mini/testnet tail** — proposed 1 sat/block.
5. **Whether `supply_cap_sat` is deleted or retained as a sanity ceiling.**
6. **Base-fee / burn behaviour under sustained load (F2).** Now quantified (§2.3):
   1,051,920 JNT/yr removed at full blocks vs a 5,260 JNT/yr tail, break-even at
   ≈5 % activity. This is a *fee-design* question. It is unowned; no issuance
   candidate, E included, changes it.
7. Indirectly: P1 (exit), P2 (stake/committee), P3 (M2), P4 (M4), P5 (settle fee).

---

## 11. Mainnet readiness checklist

| Item | Status |
|---|---|
| Monetary policy decided and recorded | ❌ proposal only |
| Replacement invariants proven | ❌ designed (§5), not implemented |
| Tests 1–14 exist and pass | ❌ |
| Sim + vector cross-check | ✅ passing now |
| SPEC/docs match shipped code | ❌ pending M4 |
| L2 → L1 exit (P1) | ❌ blocked |
| Stake ledger + mainnet committee (P2) | ❌ blocked |
| M2 rule (P3) / M4 registration (P4) | ❌ blocked |
| Small-task settle fee (P5) | ❌ blocked |
| Base-fee/burn behaviour under sustained load (F2) | ❌ unowned (quantified in §2.3) |
| Metrics, config file, release pipeline, reproducible builds, third-party audit, PGP key | ❌ operational |

**Assessment: NOT MAINNET READY.** The monetary *design* is resolved to one
recommendation; nothing is implemented.

---

## Final report

**Recommended policy.** Policy **E** — retain the existing whole-JNT ladder; after
it, halve the subsidy in satoshis each halving period down to a **permanent floor
of 0.1 JNT/block** on mainnet (reached ~year 50 at height 2,628,000), with
activation at the exhaustion height 1,839,600. Faster profiles use **1 sat/block**.
No premine, no discretionary minting, no validator rewards. *Proposed, not approved.*

**Why it best serves Jounit's long-term AI economy.** It preserves a permanent,
predictable, non-discretionary security floor so machine-to-machine settlement
never faces a chain whose mining incentive has fallen to zero (F1) — the failure
that would end an autonomous-agent economy — while keeping issuance so low
(0.013 %/yr) that agent treasuries and holders are barely diluted. It keeps L2
fees (2k–20k sat) as the micropayment rail and leaves the L1 anti-spam floor
intact, so cheap agent payments come from batching and L2, not from removing
spam protection.

**Quantitative trade-offs.** E vs A: +493,110 JNT by year 100 (1.26 % of supply).
E vs D (flat 0.1): a **constant** +151,110 JNT (0.386 % of supply) from year 50
onward — not a one-time cost — paid to remove a −90 % reward step. E is identical
to *every* option through year 25 (all issue 38,370,600 JNT).
E vs B (1 JNT): E issues 560,070 JNT *less* by year 50 and 926,890 less by year
100, at 1/10 the dilution. Base-fee removal dominates issuance at high activity
(1,051,920 JNT/yr removed vs 5,260 JNT/yr tail at base fee 1,000; break-even ≈
5 % activity), so the tail is a security floor, **not** an inflation engine — and
not a defence against the burn either.

**Security and decentralization risks.** Idle-chain budget collapse (A only);
fee-burn spiral toward zero supply under sustained congestion (F2 — a fee-design
risk, unowned); per-profile mis-application to 1-second testnets (F5, >1,000 %/yr);
history rewrite if activated early (F6). A constant absolute subsidy modestly
favours marginal miners, which is mildly decentralizing.

**Consensus migration plan.** Replace the cap in all three rules with the derived
bound `live_supply ≤ cumulative_issuance_sat(height)` plus an explicit
`escrow_ceiling`; activate at the exhaustion height so all history replays
byte-identically; no genesis change; only `supply_vectors.json` gains fields.

**Safety verdict.** Policy E is **safe as an issuance rule** — continuous,
bounded, non-discretionary, replay-safe, and the inflation bound is provable
(§0, §5.2). It is **not yet safe to ship**: the floor value, the E-vs-D choice,
`escrow_ceiling`, the mini/testnet tail, the fate of `supply_cap_sat`, and the
unowned F2 fee-burn question are all unresolved. E does **not** fix the
deflationary steady state and must not be sold as doing so.

**Unresolved decisions / exact blockers.** See §0 — six monetary blockers plus
P1–P5, which gate mainnet independently.

**Implementation phases and dependencies.** M1 decision → M2 model/vectors →
M3 consensus → M4 spec/docs → M5 ops; W1–W8 in parallel subject to their own
decisions. M3 cannot start before M1 is recorded and M2 agrees to the satoshi.

**Tests and evidence.** `--selftest` passes (exit 0) with 11 hand-computed values,
the tail-step bound (largest step a 50 % halving, then a −20 % clamp), 5
flat-floor boundary checks, monotonicity, 2 overflow bounds, 3 supply-removal
regression guards, 15 committed-vector comparisons and determinism checks; the
analysis runs exit 0; `supply_schedule_sim.py` and `verify_vectors.py --check`
exit 0. `cargo test --workspace` was **not** re-run (no Rust change) — reported
as a limitation, not a pass.

**Exact changed files.**
- `docs/monetary-redesign.md` — rewritten as this design (was the prior proposal).
- `sim/tail_emission_sim.py` — extended with candidates A–E, per-profile analysis,
  adoption/volume, burn and security-budget tables, and `--selftest`.
- No consensus code, reward parameter, genesis value, fee parameter, committed
  vector or invariant was modified.

**Assessment: NOT MAINNET READY.** This is a design proposal with reproducible
evidence, not an implemented protocol change. Implementing it is a separate phase
after explicit approval.
