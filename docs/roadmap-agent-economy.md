# What to Build On Top

A roadmap for the layers that compound what already ships. Every item here
builds on primitives that exist today; nothing on this list asks for a rewrite.

**Status:** design agreed, not implemented. Item 1 is the foundation and the
dependency root of the other four — start there.

---

## Why these compound

The chain already ships the three things most agent systems lack:

| Primitive | Where | State |
|---|---|---|
| Slashable bond | `bond.rs`, `slash.rs`, `task_contract.rs` | Shipped |
| Portable reputation | `reputation.rs` | Shipped |
| Verified-work receipt | `vwc.rs` | Shipped (`Quorum` verifiable) |

Together those are a **trust primitive**: bond the work, prove the result,
slash on proven fraud, carry the record with you. Today it is welded to
*compute tasks*. The items below generalize it into general-purpose machinery.

The economic claim underneath all five: if a party can produce a result anyone
else can check without re-running it, the two sides do not need to trust each
other. The blockchain is the escrow and the arbiter. That is already true here.
What is missing is generality.

---

## The dependency graph

```
        (1) ServiceContract  ──── escrow + bond + dispute, generalized
              │
      ┌───────┼───────────┬────────────────┐
      │       │           │                │
   (4) Cond. (2) Credit (3) Delegation  (5) Staking
   payments              chains
```

- **1 is the root.** Escrow, bonding and dispute currently assume a compute
  task. Every other item needs the same machinery with a different
  "what counts as delivered" predicate.
- **3 is independent** and pure policy — it can land any time and needs nothing
  from 1.
- **2, 4, 5 are consensus changes** and each needs a decision before code.

---

## 1. Escrowed service contracts — the foundation

### What it is

Generalize the L2 dispute layer into a standalone `ServiceContract`:

```text
Agent A commits deliverable X, bonds Y
Agent B escrows payment P
Settlement fires on verified proof of X
```

A task contract today is a service contract with exactly one admissible
deliverable: a `ComputeTask` whose result is checked by
`compute_ir::reference_result_hash`. The shape generalizes to any deliverable
that admits a **deterministic, height-free, RNG-free verifier**.

### The one idea that makes it work

> A service contract is an escrow plus a **predicate**, and the predicate is a
> pure function of committed inputs — never a caller's claim.

`compute_ir::reference_result_hash` already has all four required properties:
it is not interpreted (a permutation over commitments, not a runtime), it has no
height/clock/RNG input, it commits to the task rather than to a caller, and it
is reproduced by an independent Python implementation. Any predicate admitted to
`ServiceContract` must hold the same four, or it does not belong there.

### What must not regress

The unchallenged-result rule (README § *The unchallenged-result rule*). A
`WindowElapsed` certificate is a receipt, **not** a verification. Generalizing
the contract must not weaken that distinction — if it does, the generalization
has smuggled verification into a timeout.

### First slice

- `ServiceContract` state machine over a `Deliverable` trait, pure and
  deterministic — no I/O, no clock, matching `agent.rs` and `task_contract.rs`.
- `TaskContract` refactored to *be* a `ServiceContract` with
  `ComputeTask` as its deliverable. **This is the acceptance test**: one code
  path, not two. A second implementation is how the two drift.
- Fuzz target for the new predicate boundary.

**Risk:** low. Pure library, no consensus change, no new transaction type.

---

## 2. Undercollateralized agent credit

### What it is

An agent with a good track record borrows against future work instead of
pre-funding every transaction. Portable reputation plus a slashable bond stands
in for collateral that does not exist.

This is the item the rest of the roadmap is really for. It is structurally
impossible on rails with no identity and no reputation layer — a stablecoin
lending market cannot underwrite a stranger's future output, because it has
nothing to underwrite *with*.

### Why the primitives are already right

- `reputation.rs` is already portable and network-bound, with a **fixed weight
  table in code** — so reputation cannot be forged by producing a
  differently-shaped event.
- `bond.rs` already has a bond ledger, a bond-order index, and provable
  slashing.

The gap is the *join*: nothing connects a reputation score to a credit limit.
Today the two subsystems never touch.

### Open questions — these need decisions, not code

- **What is the default if reputation is unbacked?** A brand-new agent id has
  score 0. Lending to it at any positive limit is a subsidy to Sybil ids, which
  is the cheapest attack against a reputation-gated credit line. Minimum score
  alone may not be enough — an id can be aged rather than earned.
- **Who supplies liquidity, and in what asset?** Same-asset credit (JNT-denominated
  against future JNT-earning work) needs no oracle and has no FX risk. That
  seems like the honest first version; anything else drags in a price feed the
  chain does not have.
- **What happens on reputation decay or slashing mid-loan?** A slash can occur
  while a position is outstanding. Fail-closed is obvious; the interesting
  question is whether the loan is callable or simply undercollateralized.
- **Is reputation an input to a *consensus* limit?** If the limit is computed on
  chain, reputation becomes consensus-relevant and must be exactly reproducible
  and non-forgeable. If it is enforced off-chain or by a bond, it is not a
  lending protocol at all — it is a marketing claim.

That last question is the fork in the road, and it should be settled before any
code.

**Risk:** high. Consensus change, new economic surface, Sybil-sensitive.

---

## 3. Attenuated delegation chains

### What it is

```text
Owner ──▶ Agent ──▶ Sub-agent ──▶ ...
```

Each level inherits a **strict subset** of its parent's `SpendPolicy`. A
sub-agent cannot widen anything: not the per-tx cap, not the cumulative cap,
not the recipient set, not the service set, not the expiry. Ideally the window
narrows too.

### Why it is a real moat

Multi-agent frameworks implement this ad hoc, inside each framework, usually
wrongly. Making it a protocol primitive means the narrowing rule is the same
code everywhere and is audited once.

### What already exists

`agent.rs` has everything except the parent link: `SpendPolicy` already carries
`per_tx_max_sat`, `cumulative_max_sat`, `window_blocks`, `allowed_recipients`,
`allowed_services`, `not_before_height`, `expires_at_height` and `revoked`. It
already fails closed on empty lists.

What is missing is a **parent reference and a subset check**, and the rule that a
child policy is refused unless it is dominated by its parent on every field.

### The sharp edge

`derive_agent_id(network_id, role, owner)` derives an id from **owner** — the
human or machine that holds the funds. A sub-agent has no funds and no such
owner, so it needs its own derivation (from parent agent id + child role), and
that changes the identity function.

That is a compatibility decision: a new derivation is a new domain tag
(the same treatment `DOM_ADDR/v2` got), and it needs a SPEC amendment. It is
small, but it is not purely additive.

**Risk:** medium. Pure policy library, no consensus change, but one SPEC
amendment and an identity-derivation change.

---

## 4. Conditional and oracle-gated payments

### What it is

> "Release when model accuracy exceeds threshold."
> "Release when latency stays under X."

Payment conditions no general-purpose chain expresses natively. The payer escrows;
the condition decides; the outcome settles.

### The trap: who says the condition is met

This is the whole design problem, and it is not a payment problem.

- If **any observer** can evaluate the condition, it must be a deterministic
  function of committed inputs — the same discipline `compute_ir` already
  follows. Two honest observers must reach the same answer or the escrow has no
  defined outcome.
- If a **named oracle** decides, the oracle is a trusted third party, and the
  chain has just re-introduced exactly the counterparty it was built to remove.
  Its key custody becomes an organisational blocker — the same one already
  listed as unresolved for **arbitrator key custody** in the README.
- If **the worker self-reports**, it is not a gate. It is the unchallenged-result
  rule with extra steps, and `validate_verified()` must keep refusing it.

### Recommendation

Ship only the first form: conditions as deterministic predicates over committed
inputs, evaluated by the same predicate machinery as item 1. Latency and accuracy
bounds fit — they are measurable from committed evidence. "The market says" does
not, and should not be attempted until oracle custody is answered.

### Interaction with item 1

This is item 1 with a different predicate. That is the argument for building
item 1's predicate abstraction generally rather than hardcoding compute.

**Risk:** medium-high. Consensus change; the oracle question is unresolved and
should not be papered over.

---

## 5. Compute-backed validator staking

### What it is

Validators who also serve inference earn more. **The security budget and the
utility budget become the same budget.**

This is what makes the integer-NN-in-mining design pay off *economically*
rather than being merely elegant. Today the neural stage is a cost model with no
revenue attached to it.

### What already exists

- `bond.rs` — bond ledger, bond-order-derived committee, provable slashing.
- `MIN_VALIDATOR_STAKE_SAT` = 5 000 JNT, immutable consensus constant.
- `validators.rs`, `signing.rs`, `finality.rs` — the committee and checkpoint
  machinery.
- Task escrow — a source of real inference demand.

### The core difficulty

**Verification is the product, not the work.** Anyone can *run* inference;
nobody can cheaply prove they served it honestly to a paying party. So
"compute-backed" has to mean the validator is paid for work that
`ServiceContract` already verified — not for work it claims.

The honest version: a validator earns a staking discount *because* it settles
verified tasks, where "verified" means the `Quorum` VWC basis and never the
`WindowElapsed` one. Get that backwards and the staking reward becomes a subsidy
for unchallenged non-delivery, which is the exact failure the unchallenged-result
rule exists to prevent.

### Blocker

**There are no validators.** The README is explicit: no operator is bonding
5 000 JNT, `genesis_validators` is empty on mainnet, and binding finality is
off. The economic design is sound but has nothing to attach to. This item is
blocked on adoption, not on code.

**Risk:** medium technically, but gated behind adoption.

---

## Locked decisions

Recorded 2026-10-11. These are settled; implementation follows them.

### D1 — Credit is bond-backed. Reputation is a derived view, never a consensus input

**Decided.** Consensus-computed reputation feeding credit limits is rejected.

The reason is specific: it turns every reputation update into a consensus event,
and it makes fresh IDs farmable. A credit line gated on a consensus-visible score
is a subsidy to anyone willing to mint identities, which is the cheapest attack
against the gate and the most expensive to defend.

The clean split:

| | |
|---|---|
| **Reputation** | Computed deterministically from on-chain events, published as a **view** any counterparty can read. Never a consensus input. |
| **Credit** | Always **collateralized**. A posted bond *discounts* the collateral requirement, nothing more. |

Consequences that follow, and are accepted deliberately:

- **No subsidy.** A good record buys a lower requirement, never a free line.
- **No Sybil surface.** Farming an id yields nothing, because nothing reads the
  score. A bond is worth exactly its face value regardless of who posts it.
- **No consensus dependency on a mutable score.** Reputation stays off the
  critical path, so the score can be rebuilt, corrected or ignored without a
  consensus change.

The score still has value — it is the *lender's* underwriting input, and every
agent choosing to lend against reputation can read the same deterministic view.
That is a market, not a protocol rule, and it is the right place for a judgement
call that the chain should not be making.

**Implementation status:** the arithmetic exists and is pinned. `credit.rs` holds
`CreditTerms` (a lender's parameters, set before a position opens and immutable
afterwards) and `required_collateral(amount, bond)`, which returns
`max(base - discount, floor)`. Its invariants are tested rather than asserted:

- a bond discounts the requirement **satoshi for satoshi**, capped at
  `max_discount_bps` of the amount — applying a rate *as well* would charge a
  borrower for their own collateral twice, which was the first bug in this
  module;
- the requirement never rises as more bond is posted, and is monotone in the
  amount borrowed;
- it never reaches zero, and never falls below `min_collateral_bps`;
- an unrepresentable requirement is **refused**, never wrapped, because a wrapped
  product compares small and passes a bound.

`CreditPosition::open` takes a `ReputationScore` and ignores it — deliberately, and
documented at the parameter, so it cannot become a hidden input later.

### D2 — Conditional/oracle payments are blocked, off the critical path

**Decided.** Item 4 is parked as **blocked on arbitrator key custody**.

The blocker is real and already listed unresolved in the README: the transport is
built, but who runs the arbitrators is an organisational decision. An oracle-gated
payment needs the same answer before it can be specified honestly, because the
oracle *is* the untrusted party the escrow exists to eliminate.

So item 4 does not gate items 1, 2, 3 or 5, and the state machine is not
designed around it. When custody is answered, item 4 is either a deterministic
predicate (as recommended above) or a different design entirely.

### D3 — Item 1c is an acceptance test, not a phase. Refactor, do not fork

**Decided.** `TaskContract` *becomes* the `ServiceContract` with a pluggable
`Deliverable`. One code path.

> If after 1c there are two settlement paths in the tree, the abstraction failed
> and we revert.

A parallel `ServiceContract` sitting beside `TaskContract` would be strictly
worse than no abstraction: it would look generalized while the real contract —
the one holding escrows — stayed compute-specific.

**The mechanical check**: `grep -rn "fn settle_inner" crates/` must return
exactly one definition, and there must be exactly one `struct ServiceContract`
with no `struct TaskContract` beside it. `TaskContract` is a type alias
`pub type TaskContract = ServiceContract<ComputeDeliverable, ComputeAttestation>`,
so every existing call site and the whole wire format are untouched.

**Status: met.** Verified after 1b/1c — one `settle_inner`, one
`ServiceContract`, `TaskContract` an alias, 1003 tests green, vectors and
`fmt`/`clippy` clean.

### One trap the refactor actually caught

Worth recording, because it is the kind of bug a generalization invites and the
kind only a full test suite catches.

`ComputeTask` carries its own `task_id` field, and it is **not** guaranteed to
equal the contract's `task_id`. The first cut of the abstraction read the
deliverable's own id inside `Deliverable::reference()`, which looked obviously
right — "the deliverable knows its own id".

It was wrong. The contract's id is authoritative. Compute the reference under the
wrong one and a dispute resolves against the wrong commitment: every honest
settlement comes back `Inconclusive`, and no fact is settled. Five tests in
`dispute_flow.rs` failed immediately, which is the suite doing its job rather
than the refactor being cautious.

The fix was to make the id an explicit parameter, so the authority is visible at
the call site rather than implied by a field:

```rust
fn reference(&self, task_id: &Hash) -> Hash;   // contract's id, passed in
```

The lesson generalizes past this item: when generalizing a state machine that
previously reached into a concrete type, the fields of that concrete type are not
automatically authoritative. The state machine was, and the signature now says
so. `crates/jnt-core/src/deliverable.rs` has a test for exactly this case.

---

## Sequencing

| # | Item | Depends on | Consensus change | Blocked by |
|---|---|---|---|---|
| 1 | ServiceContract | — | No | Nothing |
| 3 | Delegation chains | — | No | SPEC amendment |
| 4 | Conditional payments | 1 | Yes | Oracle question |
| 2 | Agent credit | 1, 3 | Yes | Credit-limit decision |
| 5 | Compute-backed staking | 1 | Yes | Validator adoption |

**Start with 1.** It is the only item that is pure library work with no
dependency on a decision, and it unblocks two others. Refactoring `TaskContract`
to *be* a `ServiceContract` rather than sit beside one is the acceptance test —
one code path is the whole point of the exercise.

**Decide before coding:** the item-2 fork (consensus-computed credit limit vs.
bond-backed), and the item-4 oracle question. Both are design decisions with
SPEC consequences, and neither is a code question.

---

## Open findings that constrain this work

From `docs/security-audit-2026-10-11.md`, both worth carrying into any design
that touches value movement:

- **L1 does not recompute the committed L2 state root.** A miner can commit a
  root over a state nobody else holds. Any new escrow or credit primitive that
  anchors to a committed root inherits this gap. Fixing it needs a dependency
  inversion, not a patch. Testnet and mini are exposed; mainnet exits never
  activate.
- **The policy layer is not wired into spending.** `agent.rs` constrains
  spending but creates no spending authority — nothing in `submit_at` consults a
  `PolicyBook`. Every item above that claims "policy-governed" is describing a
  constraint, not an enforced one, until that is wired. This should be settled
  before building credit on top of reputation, because it decides whether
  reputation gates anything real.