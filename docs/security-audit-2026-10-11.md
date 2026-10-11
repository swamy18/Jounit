# Security review findings — 2026-10-11

A focused review of the money-moving paths: L1 transaction validation and the
UTXO ledger, supply and fee schedule, and the L2 task/escrow/exit lifecycle.
Two defects were found and fixed. One architectural gap is recorded and **not**
fixed, because a correct fix needs a dependency inversion rather than a
surgical patch.

## Fixed

### F1 — Worker-chosen deposit made fraud settlement unreachable (escrow theft)

`TaskContract::claim` accepted any `worker_deposit_sat >= 1`. The settle fee is
derived from the *escrow* (`settle_fee_sat(payment_sat)`, Decision 23), not from
the deposit, and the `Fraudulent` arm of `settle_inner` refuses when
`deposit < fee`.

A worker could therefore claim with a dust deposit, submit a wrong result, and
become structurally unslashable: once a result is submitted, `Expired` is no
longer reachable either, leaving the free auto-settle `Correct` as the only
settlement left. The worker would collect the entire escrow for work that is
provably wrong — and the penalty would be a number the attacker chose in advance.

**Fix:** `claim` refuses a deposit below `settle_fee_sat(payment_sat)`, so a
fraud verdict is always reachable. `payment_sat` is fixed at post time, so the
floor cannot be dodged later.

Pinned by `a_claim_deposit_that_cannot_cover_the_settle_fee_is_refused` and
`the_deposit_floor_scales_with_the_escrow`.

### F2 — Miner and validator computed different base fees (consensus split)

`build_block` and `expected_base_fee_for_next_block` folded the parent's
`claims_gas_used()` into the next block's base fee. `apply_block` used
`total_gas_used()` alone.

After any block carrying an exit claim — which `check_claim` makes
permissionless — the miner produced a strictly higher base fee than the validator
expected, and the node rejected its own next block with
`BadFee("base fee does not follow the schedule")`. One crank was enough to wedge
every honest miner on an exit-enabled network.

**Fix:** `apply_block` counts claim gas, matching the miner term for term.

A `next_base_fee` clamp hides this whenever the fee sits at
`base_fee_min_sat`/`base_fee_max_sat`, which is why no existing test caught it
and why an integration test built on stock `mini` passes either way. Pinned by
`claim_gas_changes_the_next_base_fee_and_must_be_counted`, which holds the fee
strictly inside the clamp bounds and asserts the two figures differ.

## Open — not fixed here

### F3 — L1 never recomputes the committed L2 state root

`check_claim` anchors an exit record to whatever `l2_state_root` the queue block
*claimed* (`block_at(queued_height).l2_state_root`). `Chain` checks only that a
root is **present**, never that it matches a replay of the L2. A miner can
therefore commit a root over a state nobody else holds and prove a fabricated
exit record against it.

`jnt-l2/src/replay.rs` silently declines to build an exit watch on a mismatch
rather than rejecting the block. The module doc in `state_root.rs` asserts that a
lying root cannot produce a valid proof, which inverts the actual reasoning: the
committed root is the only thing the proof is checked against.

**Why it is not fixed here.** `jnt-l2` depends on `jnt-core`, so `Chain` — which
lives in `jnt-core` and owns no I/O — structurally cannot replay the L2 state to
recompute the root. Closing this means either moving root verification behind a
trait injected into `Chain`, or lifting the L2 state machine into `jnt-core`. Either
way it changes the block-validation consensus path, which is a design decision
with a SPEC implication rather than a patch.

**Exposure today.** `mainnet.exit_activation_height` is `0`, meaning exits never
activate, so the sink cannot be drained on mainnet as shipped. **Testnet and mini
activate at height 1 and are exposed.** Do not fund a sink on testnet or mini
until F3 is closed.

## Also noted, not a vulnerability

- `ArbitrationVote::signing_hash` and `SettlePayload::signing_hash` omit
  `network_id` and `height`. This is already documented in `arbitration.rs`; task
  ids carry no network domain, so aggregates are portable between chains with
  colliding task ids.
- `chain.rs` advances the M2 slash vault's vested payouts without creating a UTXO
  output for them. Accounting-only, so no attacker gain, but it double-counts in
  `base_removed_total()` and therefore in `net_supply_sat`.