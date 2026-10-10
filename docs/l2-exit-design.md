# L2 Exit Design

**Status: IMPLEMENTED (Decision 19, SPEC.md §19.6).** The exit rule shipped on
2026-10-09: `ExitQueue` on L2, a proof-authorised sink spend on L1, a
permissionless crank in the serve loop, and L2 replay absorbing the release.
What remains for mainnet is **configuration** — `exit_activation_height` — plus
the open decisions P2–P5. This document is kept as the design record the
implementation followed, and every recommendation below is now a decision.

Two things changed since the first revision of this document, and both are
evidence rather than opinion:

1. **The blocker was proven in code, then satisfied by a rule.**
   `crates/jnt-core/tests/sink_unspendable.rs` still drives the real L1 spend
   rule and shows a sink output has no valid *signature* spender — including the
   depositor trying to reclaim its own coins. Decision 19 added the L1 rule that
   makes that irrelevant: a claim is authorised by an **inclusion proof against
   the committed `l2_state_root`**, not by a signature. So the sink's keylessness
   no longer blocks an exit, and the sink was deliberately **not** replaced by a
   validator-threshold escrow.
2. **The negative halves of an exit were replaced by positive tests.**
   `exit_unavailable.rs` (the "exactly five type bytes" assertion) is gone;
   `jnt-l2/tests/exit_flow.rs`, `jnt-l2/tests/exit_claim.rs` and
   `jnt-node/tests/exit_crank.rs` now pin the exit behaviour directly.
   `sink_unspendable.rs` survives unchanged, because the signature refusal it
   pins is still true.

Related records: `docs/decisions.md` — **Decision 10** (user deposits via
burn-to-sink; its exit deferral is *superseded* by Decision 19), **Decision 19**
(the exit rule, APPROVED + IMPLEMENTED), and **Decision 18** (which deleted the
stock cap the old accounting text below assumed). There is no "Decision 21" in
this repository; an earlier revision of this file cited one that does not exist.

## Problem

L2 value enters through two paths, both now implemented and tested:

1. **Genesis escrow** (Decision 7): `l2_genesis_escrow_sat`, a reallocation
   bounded by the explicit `escrow_ceiling_sat` parameter. Credited at L2 genesis.
2. **User deposits** (Decision 10): an ordinary STANDARD L1 payment to
   `NetworkParams::l2_deposit_sink`, read by L2 replay and credited 1:1 after
   maturity.

Both paths have a return route since Decision 19. A user who deposits JNT, or a
worker paid in L2 for settled work, queues an `ExitQueue` transaction; after
finality the value is released on L1 by a proof-authorised claim. On `mini` and
`testnet` (`exit_activation_height = 1`) that path is live end to end;
`mainnet` ships `0`, meaning *never*, so mainnet deposits are closed by
configuration until an owner picks a height.

## The binding constraint: no signature can spend the sink

This is the finding that determined the whole design, and it is why the
approaches below cannot be adopted as written.

`l2_deposit_sink = SHA256("jounit/l2-deposit-sink/v1" ‖ network_id)[..20]`
holds **no key**. It is derived, not owned. L1 consensus will never validate a
signature that spends a sink output, so:

- **A sink output has no signature spender.** `sink_unspendable.rs` proves the
  depositor's own reclaim, a stranger's and an unsigned spend all fail. SPEC.md §19.5
  states the consequence: *"sink outputs remain in the L1 UTXO set … the sum is
  constant across deposits and falls on burns."*
- **So no exit can be authorised by a key.** Decision 19 added an authorisation
  that does not use one: a claim whose inputs are sink outputs covered by a
  valid, matured, unreleased **inclusion proof** is a legal L1 transaction, and
  the sink term falls by exactly the released amount. The joint conservation
  check (`L1 live + L2 held − sink-held`) is unchanged and needed **no exit
  term**; §19.5's `cap` is now the joint bound `cumulative_issuance_sat(height)
  + escrow_ceiling_sat` (Decision 18 removed the stock cap).

Therefore an exit requires a **new L1 rule** that lets consensus move value out
of sink outputs. Option (a) was authorised (Decision 19) and implemented; the
sink was **not** replaced by a validator-threshold escrow. **No fake withdrawal
path and no minting path may be built** — minting on exit would
break the cap invariant, and "releasing" from the sink without a new rule is
not expressible.

## Evaluation of the proposed approaches

All three were drafted assuming the sink could release funds. Corrected against
the actual deposit model:

### Option A — In-block challenge

**Mechanism:** a provably incorrect L2 transition is challenged on L1 within
`challenge_window` blocks; the challenge is an L1 transaction carrying an
L2→L1 state proof; a valid proof releases the corresponding value.

**Assessment:** Strongest trust model (no trusted exit operator, no new
custodian), and it reuses the existing `validators.rs` six-clause checkpoint
validator and the M3/M4 dispute machinery. **But it is insufficient on its
own:** it proves *that* a withdrawal is owed, not *how value leaves the sink*.
It still needs a consensus rule authorising a sink-release transaction, and it
requires an L2→L1 proof system that does not exist (new, large, and itself a
consensus-format decision). It also interacts with M5 binding finality: a
challenge window must not be shorter than the maximum reorg depth once finality
is binding.

### Option B — Scheduled withdrawal

**Mechanism:** a withdrawal is queued on L2; after the carrying L1 block is
final, value is paid out of the escrow sink.

**Assessment:** Simplest to reason about and predictable for users. **Adopted
as the user-facing layer.** The scheduled-withdrawal queue *is* the user-facing
API; the "paid out of the sink" half needed the rule above, not a second one —
the claim is authorised by an inclusion proof rather than a key. A
validator-threshold-signed release was rejected because it introduces a key the
model deliberately does not hold.
needs a queue structure with its own replay/finality semantics (below).

### Option C — Emergency withdrawal

**Mechanism:** a governance-triggered pause plus a time-delayed withdrawal path.

**Assessment:** A useful *safety valve*, not a primary exit. It concentrates
trust in governance and, like A and B, still needs a consensus release rule.
It should not be the primary path, and it cannot be specified while the release
rule is undefined.

**Conclusion (as adopted).** The consensus-authorised release rule is the
primitive, the scheduled withdrawal is the queue on top of it, and there is no
emergency pause in v1. This is exactly what Decision 19 approved and what
`crates/jnt-core/src/exit.rs`, `jnt-l2`'s `queue_exit` and
`NodeL2::crank_claims` implement.

## What the tests pin today

| Test file | What it pins |
|---|---|
| `crates/jnt-core/tests/sink_unspendable.rs` | A sink output has no **signature** spender: the depositor's own reclaim is `WrongAddress`, a stranger's is `WrongAddress`, an unsigned spend is `EmptySignatureBundle` (refused *before* the ownership check), and the sink/escrow identities are distinct derived addresses. Still normative — the release is authorised by a proof, not a key. |
| `crates/jnt-l2/tests/exit_flow.rs` | The sixth type byte `0x15 = ExitQueue` is a real transaction: the codec, the D3 fee mapping, activation gating, third-party-destination refusal, replay and rewound-nonce refusal, and `exited_total` accounting. |
| `crates/jnt-l2/tests/exit_claim.rs` | The L1 half: proof against the committed root, exact funding, idempotency by exit identity, maturity, reorg unwind, and that a block carrying any of it is still a valid block by every pre-exit rule. |
| `crates/jnt-node/tests/exit_crank.rs` | The node can drive the whole loop with nobody hand-building the claim, the crank settles nothing before maturity, and a profile on `exit_activation_height = 0` (mainnet) refuses both a root and a claim. |
| `crates/jnt-node/src/conservation.rs` (+ `tests/conservation.rs`) | The joint L1 + L2 supply check is one tested function. It exercises the **sink term** specifically: a deposit is counted once pending and twice once matured, and the subtraction removes exactly one copy. It passes **unchanged** across the exit rule — the L1 payment and the L2 debit cancel, so no exit term was needed. |

Deposits are no longer one-way. Value queued on L2 returns to L1 after finality
through a proof-authorised claim; `mainnet` has the path compiled and tested but
switched off by its own configuration (`exit_activation_height = 0`).

## The approved design (Decision 19, implemented)

The shape Decision 19 approved and the code implements: bracketed values are
recorded parameters, not open questions.

### 1. Required state transitions

L2 side (additive to `L2State`):

```
Queued    : account debited by amount + exit_fee + queue fee; pending-exit record { (owner, nonce) → (amount, destination, exit_fee, queued_height) }
Matured   : queued_height such that the carrying L1 block is final (see §4)
Released  : value leaves L2 accounting and is paid on L1 by the release rule
```

L1 side: one new consensus-authorised operation that moves `amount` from
`⟨release source⟩` to `destination`. This is the missing primitive.

### 2. Authorization model

- L2 side: the same §15.2 `Auth::verify_as` used by every other L2 operation —
  owner-signed, no second scheme, no exit operator.
- L1 release side: whoever is authorised must be named. Options the decision
  may consider: (i) the destination address as named in the matured exit
  record, with the release transaction carrying the L2 proof; (ii) a validator
  threshold signature (introduces a key — must be justified); (iii) a
  permissionless crank that can be run by anyone but only pays the recorded
  destination (safest permissionless shape, but still needs the release rule).
- No exit may be authorised by a party other than the depositing/holding owner,
  and no third-party recipient may be introduced beyond the recorded
  `destination`.

### 3. Replay protection

- Per-owner strictly increasing nonce (identical to L2 `PostTask`), so the same
  exit request cannot be queued twice.
- A global exit-identity set keyed by `(owner, nonce)` in `L2State`, re-derived
  on replay — never persisted as an independent ledger.
- On L1, the release operation must be idempotent by exit identity: one release
  per queued exit, ever. Replay of the release transaction must be refused by
  consensus, not by bookkeeping.
- Reorg: exits are re-derived from the winning chain exactly as deposits are
  (SPEC.md §19.5 processing order). A queued exit on a losing branch vanishes;
  a matured one that the winner still contains is released exactly once.

### 4. Finality requirement

An exit **must not** release before the L1 block containing its queue
transition is final under the **stronger** of the two rules already in use
(Decision 15): depth `finality_depth` **and**, once binding finality is active,
the binding checkpoint height. This is the same rule that governs deposit
maturity and must not be weakened for exits. Before binding finality activates,
depth alone governs — exits are never *less* safe than deposits. A consequence
to state plainly: an exit that is mature under both rules sits below two
finality lines, so its containing block is as irremovable as the chain makes
any block; a release that could be reorged away is not representable.

### 5. Accounting / conservation rules

- Per exit: L2 debited value `==` L1 released value, 1:1, no rate and no fee on
  the principal.
- Globally the §19.5 joint check must hold in the exit direction too. Today
  sink outputs stay counted in the "sink-held" term while their twins live in
  L2. On release the L2 twin leaves L2 and the value is paid on L1, so the
  released value must **leave** the sink-held term by the same amount — i.e.
  the release rule must reduce the outstanding sink claim, not create a second
  claim on already-counted coins. Getting this wrong double-counts and is an
  inflation primitive; the conservation test suite must cover it explicitly.
- The mint bound is untouched: exits move existing value and never mint. The
  bound is the per-height issuance integral plus the post-ladder rate anchor
  (Decision 18), neither of which an exit can touch. Any design that computes an
  exit amount from anything other than the committed L2 debit is rejected.

### 6. Failure / reorg behaviour

- Unmatured exit requested for release: refused by name, value stays on L2.
- Release attempted twice: refused by name (idempotent).
- Reorg removes the queue transition: exit returns to absent; any already-paid
  release on a losing branch must be undone by the same reorg machinery that
  undoes L1 transactions — which is why the release must be an ordinary,
  undoable L1 operation and not an out-of-band action.
- L2 replay failure mid-exit: no partial state; the whole transition is atomic
  (same discipline as `apply_tx`).
- Destination unspendable or malformed: refused at queue time, value stays on
  L2.

### 7. Fee handling

- The exit itself pays the D3 flat schedule through the **existing** M1 path
  (`split_flat_fee`: flat fee `== full_base`, 50/50 burn/PSCB). No new fee
  class and no exemption from the L1 gas floor.
- The L1 release operation pays the normal L1 fee the way any L1 transaction
  does. Who funds it (the exiting owner, or the release crank with an
  incentive) is an open parameter the decision must fix; an unfunded release is
  a griefing surface and must not be specified without one.
- `payment_sat`-style market pricing does not apply: an exit is a protocol
  operation, not a job.

### 8. Batching

- Multiple matured exits may be batched into one L1 release to amortise the gas
  floor (the same reasoning as `aggregate_payments`), but batching is an
  optimisation, not a semantics change: each exit identity is released exactly
  once, and a batch that contains one invalid exit must fail closed rather than
  silently drop it.

### 9. Tests required (before any release code merges)

1. `exit_queued_then_matured_then_released_reduces_l2_and_l1_consistently`
2. `exit_before_finality_is_refused_by_name`
3. `exit_replay_is_refused_by_name`
4. `release_is_idempotent_by_exit_identity`
5. `reorg_of_the_queue_block_removes_the_exit`
6. `reorg_cannot_remove_an_already_released_and_final_exit`
7. `joint_conservation_holds_across_deposit_and_exit` (extends the §19.5 check)
8. `supply_cap_is_unchanged_by_any_exit`
9. `exit_fee_matches_the_d3_schedule_and_splits_50_50`
10. `a_batch_with_one_invalid_exit_fails_closed`
11. `restart_reconstructs_identical_exit_state`
12. `exit_cannot_credit_a_third_party_destination`

### 10. SPEC changes required

- A new §19.x subsection under the L2 material (after §19.5) stating the exit
  primitive, authorization, replay identity, maturity rule, conservation term
  and reorg behaviour — normative, exactly as §19.5 is normative for deposits.
- If the release is a new L1 transaction shape, §3 serialization and §9
  consensus-validation rules gain the encoding and validity clauses, and the
  §12 vector set is extended (new frozen vectors; existing vectors must not
  move).
- The economics (release funding, any validator-signature authority) must be
  recorded in `docs/decisions.md` **before** the SPEC text is written.

## Recommended rule in detail (PROPOSED — not implemented, not approved)

This is the precise thing an owner would be approving. It is written out
because "approve an exit rule" is not a specification, and the difference
between a safe rule and an inflation primitive here is one sentence wide.

### The primitive: a consensus-authorised spend of sink outputs

A new L1 transaction shape — call it **`TxExitClaim`** — that

1. takes one or more **sink outputs** as its inputs,
2. pays `amount_sat` to the exit's recorded `destination`, and
3. is authorised by an **exit proof**, not by a signature.

**Why consume the sink outputs rather than mint against them.** The two
candidate mechanisms differ in whether the ordinary per-transaction rule
(`value_in >= value_out`) survives:

- *Consume the sink outputs.* The claim's inputs are real UTXOs with real
  value, so the normal conservation rule still applies unchanged. The only new
  thing is the **authorisation predicate**: an input is spendable if it is a
  sink output covered by a valid, matured, unreleased exit proof. Undo, reorg,
  fee and maturity machinery are all reused as-is.
- *Mint against the sink as a permanent counterweight.* The sink UTXO is never
  spent, so the claim creates L1 outputs exceeding its inputs. This is an
  explicit **inflation-exception transaction type** — the only one in the
  protocol — and it must be validated against the *joint* invariant instead.

Both conserve jointly (the arithmetic is shown in §5 of the required design).
**Recommendation: consume the sink outputs.** It keeps one conservation
invariant in force everywhere rather than carving out the single most
dangerous exception in the system, and it reuses the existing `Undo` path so a
reorg unwinds a release exactly as it unwinds any other spend.

### Exit identity and the proof

An exit is identified by **`(owner, nonce)`**, mirroring the per-owner nonce
already used by `PostTask`, plus the queued height. The claim transaction
carries:

| Field | Purpose |
|---|---|
| `owner` | the L2 account whose balance is debited |
| `nonce` | strictly increasing per owner; makes the request unique |
| `amount_sat` | bound by the proof, never by the caller |
| `destination` | bound by the proof, never by the caller |
| `queued_height` | the L1 height whose L2 state contains the queue transition |
| `l2_state_root` | the committed L2 state root at `queued_height` |
| `merkle_branch` | inclusion proof of the exit record under that root |

**The proof is the hard part, and it is the reason this is a large change.**
L2 state is currently *derived by replay* from L1 blocks and is **not** committed
on chain in a form L1 can cheaply check (`docs/decisions.md`, Decision 6 commits
L2 *transactions* via each block's merkle root, not the resulting L2 *state*). A
validating node therefore has two choices:

- **commit an L2 state root per block** (a header/consensus addition, activated
  with this rule), and require a Merkle inclusion proof against it; or
- **validate by derivation**, which is correct but requires replaying L2 state to
  `queued_height` per claim and is not viable as a consensus rule.

**Recommendation: commit the L2 state root at the activation height and require
the Merkle proof.** The root is already computable — every node derives
identical L2 state today, and `L2State` already has a canonical wire encoding —
so the addition is a commitment to a value that exists, not a new computation.

### Validation rules (all fail closed)

1. The proof must verify the exit record against the block's committed
   `l2_state_root` at `queued_height`.
2. `amount_sat` and `destination` must equal the proven record **exactly**; no
   caller-supplied override is read.
3. The chain at the claim's height must be final over `queued_height` under the
   **stronger** of the two existing rules (Decision 15) — depth `finality_depth`
   **and** the binding checkpoint height once binding finality is active. Exits
   are never less safe than deposits.
4. One release per exit identity, **ever**: consensus maintains the consumed
   identity set, so replay is refused by consensus rather than by bookkeeping.
5. The consumed sink inputs must total exactly `amount_sat` (plus the release
   fee, below). A mismatch is refused by name.
6. The claim pays the ordinary L1 fee like any transaction; the D3 exit flat fee
   is charged on the L2 side at queue time.

### Accounting

With sink outputs consumed, the joint check (§19.5, now in
`crates/jnt-node/src/conservation.rs`) is preserved **without modification**:

```
before: joint = (L_other + S) + (E + D) − S      = L_other + E + D
after:  joint = (L_other + a + S − a) + (E + D − a) − (S − a) = L_other + E + D
```

where `S` is sink-held value, `D` L2 value, `a` the released amount. The L1
payment (+a) and the L2 debit (−a) cancel exactly. **Any implementation that
moves one side without the other becomes an inflation primitive**, which is why
`tests/conservation.rs` pins the sink term now, before the rule exists.

## Decision required — with recommendations

Recorded as a blocker, not a choice, per the standing rule that protocol
economics are not invented by implementation work. Each question below carries a
**recommendation** and the reason for it; none is a decision.

1. **The L1 release primitive.** *Recommendation: a consensus-authorised spend
   of sink outputs (`TxExitClaim`), authorised by an exit proof rather than a
   signature.* Rejected alternative: replacing the keyless sink with a
   validator-threshold escrow — it introduces a key the architecture
deliberately avoids, makes a committee-key compromise a fund-loss event, and
   moves the trust problem rather than solving it.
2. **Permissionless or gated.** *Recommendation: permissionless crank.* Anyone
   may submit the claim; consensus pays only the recorded `destination`. No
   operator privilege, no second authorisation path to audit.
3. **Who funds the L1 release fee.** *Recommendation: the exiting owner, prepaid
   at queue time.* The L2 side debits `amount + exit_fee_sat`; the claimant
   receives `exit_fee_sat`, the destination receives `amount`. Prepaying is what
   makes a permissionless crank griefing-bounded: a claim that is not worth
   submitting simply is not submitted, and nobody can be forced to pay for it.
   An unfunded release, or one paid by the protocol, is a spam surface and should
   not be specified without an incentive model — which this repository has not
   decided.
4. **Cancellable queued state.** *Recommendation: no cancellation.* A cancel/claim
   race needs its own ordering rule for no benefit; the value is encumbered for
   exactly one finality window.
5. **Challenge window.** *Recommendation: none in v1.* An exit is a pure
   function of final L1 state, and finality already supplies the security
   guarantee. A challenge window can only be as strong as the reorg depth it
   guards against — which is precisely what finality *is* — so it would be a
   second, weaker mechanism layered on the first. If a challenge is wanted later
   it must be `>= finality_depth` and reconciled with the binding-finality floor.
6. **Emergency pause.** *Recommendation: not authorised in v1.* It concentrates
   trust in a governance key the current architecture does not have, and cannot
   be specified without saying who holds that key. Option C stays a documented
   safety valve for a later, separately-approved decision.

**Minimum to unblock implementation:** questions **1–3**. Questions 4–6 can
default to the recommendations above (no cancellation, no challenge window, no
pause) without further work, because each default is the *narrower* choice — it
adds no new authority to anyone.

## Migration, activation and compatibility

- **Historical blocks are unaffected.** The rule adds a new authorisation
  predicate and (if the state root is committed) a new block field activated at a
  height. Below that height nothing changes, and `TxExitClaim` is simply an
  unknown transaction type, which the decoder must refuse exactly as it refuses
  an unknown L2 type byte today.
- **Activation requires a network-upgrade mechanism.** None exists. There is no
  version bits, and the height-gated rules that *do* exist —
  `finality_activation_height`, `exit_activation_height` and the Decision 18
  `tail_activation_height` — are profile data rather than negotiated upgrades. A
  real activation mechanism is a prerequisite for changing any of them on an
  existing chain, and is currently **undecided**.
- **Vectors must not move.** Existing serialization, puzzle and supply vectors
  are pinned; the exit rule adds new shapes and must add new vectors rather than
  perturb old ones. A changed existing vector would mean the rule altered
  historical validity, which is a bug, not an upgrade.
- **Mainnet deposits stay closed by configuration.** `mainnet` carries
  `exit_activation_height = 0` (*never*), so it accepts neither a committed
  `l2_state_root` nor an exit claim, and mainnet must not accept user deposits
  until the owner sets a height. On `mini`/`testnet` (`= 1`) deposits are
  functional **and** withdrawable.
- **How the migration checklist actually went.**
  `sink_unspendable.rs` was **kept** — its claim is about signatures, which still
  cannot spend a sink output; the exit is authorised by an inclusion proof instead.
  `exit_unavailable.rs` was **deleted** and replaced by `exit_flow.rs` /
  `exit_claim.rs`. `conservation.rs` passes **unchanged**, which is the strongest
  signal the accounting was done right: the joint check needed no exit term at all.

## References

- `SPEC.md` §14.2 (L2 payload types), §15.2 (`Auth::verify_as`), §19.1
  (`l2_state_root` commitment), §19.5 (deposits, sink, conservation term,
  processing order), §19.6 (exits, normative)
- `docs/decisions.md` — Decision 7 (genesis escrow), Decision 10 (deposits),
  Decision 15 (stronger-of-two finality), **Decision 18** (removed the stock cap
  the old accounting text assumed), **Decision 19** (the exit rule)
- `crates/jnt-l2/src/` — `deposits.rs`, `state.rs`,
  `ChainL2::{replay, pending_deposits, pending_exits}`
- `crates/jnt-core/src/exit.rs` — claim codec, proof verification, identity, gas
- `crates/jnt-l2/tests/{exit_flow,exit_claim}.rs`,
  `crates/jnt-node/tests/exit_crank.rs`,
  `crates/jnt-worker/src/exit.rs` (`queue_exit`, `queue_exit_plan`, `ExitPlan`),
  `jnt-node/src/l2.rs::crank_claims`
- `crates/jnt-core/src/params.rs` — `l2_deposit_sink`, `l2_escrow_address`,
  `l2_genesis_escrow_sat`, `l2_deposit_minimum_sat`
- `docs/micro-payment-audit.md` (Layer 1 asset flow), `docs/monetary-policy.md`
  (sink and conservation)
