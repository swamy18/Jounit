# L2 Exit Design

**Status: BLOCKED — DESIGN ONLY. No exit mechanism is implemented, and none may
be implemented until a protocol decision is recorded.** This document is the
Phase-3 deliverable. It evaluates the three proposed approaches, states the
required design, and lists exactly what a decision must settle. It deliberately
does **not** choose an approach, because choosing is a protocol-owner decision
(see *Decision required* below), and inventing an exit would mint value.

Related records: `docs/decisions.md` — **Decision 10** (user deposits via
burn-to-sink, which explicitly states *"Explicitly deferred (mainnet blocker):
L2→L1 exits … No exit decision is recorded here."*). There is no "Decision 21"
in this repository; an earlier revision of this file cited one that does not
exist. The blocker is Decision 10's deferral, and this file is where the
consequences of that deferral are worked out.

## Problem

L2 value enters through two paths, both now implemented and tested:

1. **Genesis escrow** (Decision 7): `l2_genesis_escrow_sat`, a reallocation of
   coins already inside the unmintable gap. Credited at L2 genesis.
2. **User deposits** (Decision 10): an ordinary STANDARD L1 payment to
   `NetworkParams::l2_deposit_sink`, read by L2 replay and credited 1:1 after
   maturity.

Neither path has a return route. A user who deposits JNT, or a worker who is
paid in L2 for settled work, holds an `L2State` account balance with no
protocol-defined way to move that value back to L1. **Until an exit exists,
mainnet deposits would trap user funds.** Testnet deposits are functional
because testnet value is not expected to be recoverable; that is a testnet
property and is not mainnet readiness.

## The binding constraint: the sink cannot release funds

This is the finding that determines the whole design, and it is why the
approaches below cannot be adopted as written.

`l2_deposit_sink = SHA256("jounit/l2-deposit-sink/v1" ‖ network_id)[..20]`
holds **no key**. It is derived, not owned. L1 consensus will never validate a
signature that spends a sink output, so:

- **Sink outputs stay in the L1 UTXO set forever.** They are provably burned
  for spend purposes. SPEC.md §19.5 states this: *"sink outputs remain in the
  L1 UTXO set … the sum is constant across deposits and falls on burns."*
- **Consequently, no exit can "release the funds from the sink".** The value is
  not sitting in a spendable address; it is destroyed-for-spending but still
  counted, exactly so the joint conservation check
  (`L1 live + L2 held − sink-held ≤ cap`) does not read every deposit as
  inflation.

Therefore *every* viable exit requires a **new L1 rule** that either (a) lets
consensus move value out of sink outputs, or (b) replaces the unspendable sink
with an escrow whose spend authority is the validator set. Both are consensus
changes. Neither is authorised by any decision on record. **No fake withdrawal
path and no minting path may be built in the meantime** — minting on exit would
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

**Assessment:** Simplest to reason about and predictable for users. **But the
premise is wrong as written** — the sink is unspendable, so "paid out of the
sink" is not a legal L1 transaction. It would have to become either a
validator-threshold-signed release (introducing a key the current model
deliberately does not have) or a new consensus rule for sink outputs. It also
needs a queue structure with its own replay/finality semantics (below).

### Option C — Emergency withdrawal

**Mechanism:** a governance-triggered pause plus a time-delayed withdrawal path.

**Assessment:** A useful *safety valve*, not a primary exit. It concentrates
trust in governance and, like A and B, still needs a consensus release rule.
It should not be the primary path, and it cannot be specified while the release
rule is undefined.

**Conclusion.** The safest architecture compatible with the *existing* sink is:
a **consensus-authorised release rule** as the primitive, with a
**scheduled withdrawal** as the user-facing queue on top of it, and an
**emergency pause** as a bounded safety valve. The primitive is the decision;
A, B and C are policies layered on it. **None of this is implemented.**

## Required design (to be completed after the decision)

The following is the exact shape a decision must approve. Values in `⟨…⟩` are
the open parameters the decision must fix; they are **not** chosen here.

### 1. Required state transitions

L2 side (additive to `L2State`):

```
Queued    : account debited by amount; pending-exit record { (owner, nonce) → (amount, destination, queued_height) }
Matured   : queued_height such that the carrying L1 block is final (see §4)
Released  : value leaves L2 accounting and is paid on L1 by the release rule
Cancelled : (only if the decision allows) returns value to the L2 account, atomically
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
- The supply cap is untouched: exits move existing value, never mint. Any
  design that computes an exit amount from anything other than the committed
  L2 debit is rejected.

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

## Decision required (NOT decided here)

Recorded as a blocker, not a choice, per the standing rule that protocol
economics are not invented by implementation work.

**A decision is required that fixes, at minimum:**

1. The **L1 release primitive** — the new consensus rule that lets value leave
   the sink claim. Without it there is no exit. (Options: a new consensus-authorised
   release transaction type; or replacing the unspendable sink with a
   validator-threshold escrow — each with its own trust and key consequences.)
2. Whether the release is **permissionless** (anyone can crank, only the
   recorded destination is paid) or **operator/validator-gated**.
3. **Who funds the L1 release fee**, and the griefing-bounded rule for it.
4. Whether a **cancellable** queued state exists, and until when.
5. The **challenge window** (if Option A is layered on), relative to
   `finality_depth` and the binding-finality floor.
6. Whether an **emergency pause** (Option C) is authorised, and by whom.

Until all six are answered and the answers are recorded, the exit path stays
absent. The deposit sink remains a one-way sink, and **mainnet must not accept
user deposits** (Decision 10's deferral is the reason).

## References

- `SPEC.md` §14.2 (L2 payload types), §15.2 (`Auth::verify_as`), §19.5
  (deposits, sink, conservation term, processing order)
- `docs/decisions.md` — Decision 7 (genesis escrow), Decision 10 (deposits,
  exit deferral), Decision 15 (stronger-of-two finality)
- `crates/jnt-l2/src/` — `deposits.rs`, `state.rs`, `ChainL2::{replay, pending_deposits}`
- `crates/jnt-core/src/params.rs` — `l2_deposit_sink`, `l2_escrow_address`,
  `l2_genesis_escrow_sat`, `l2_deposit_minimum_sat`
- `docs/micro-payment-audit.md` (Layer 1 asset flow), `docs/monetary-policy.md`
  (sink and conservation)
