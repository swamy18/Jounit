# Validator Economics Audit

**Status: audit only. No validator economics are implemented, and none is
invented here.** This is the Phase-4 deliverable: it states, per item, what is
decided, what is implemented, what is implemented-but-inert, and what is
missing, and it isolates the decisions still required. The authority for what is
*decided* is `docs/decisions.md` (Decision 2 economics, Decisions 8/11/12
mechanism). This file does not change any of them.

## Summary classification

| Item | Decision status | Implementation status |
|---|---|---|
| Minimum stake | **Decided: none** (revised — no minimum; any positive bond accepted, Jounit is permissionless) | **Implemented** (`bond.rs`, `check_bond_tx` accepts any positive amount) |
| Stake/bond transaction | Not decided as a wire rule | **Missing** |
| Unbonding (after `finality_depth`) | **Decided** (Decision 2.1) | **Missing** |
| Validator-set derivation | **Decided** (Decision 11.2) | **Implemented** (`validators.rs`), fed by genesis |
| Committee selection (TopN 21) | **Decided** (Decision 2.2) | **Partially implemented** — `SelectionRule::TopN` exists but is exercised over the *genesis list*, not live stake |
| Rotation | **Decided** (Decision 2.5: not before Phase 6; switch on after stability) | **Implemented as machinery, inert** — no rotation is driven by chain state |
| Quorum | **Decided** (Decision 12: `ceil(n × 6667 / 10000)`) | **Implemented** and enforced |
| Checkpoint validity (six clauses) | **Decided** (Decision 11.3) | **Implemented** (`validate_checkpoint_against_set`) |
| Binding finality activation | **Decided** (Decision 12) | **Implemented** on profiles with activation height > 0 (`testnet` = 20) |
| Rewards | **Decided: none** (Decision 2.3) | Correctly absent — no issuance, no fee share |
| Fee share | **Decided: none** (Decision 2.3) | Correctly absent |
| Equivocation evidence | **Decided** (Decision 14) | **Implemented** — detected and retained; **no economic punishment** (no bond to burn) |
| Slashing (equivocation) | **Decided in intent** (Decision 2.4: burn full bond) | **Missing** — needs the bond ledger |
| Slashing (L2 dispute, M2) | **Decided** (Decision 3) | **Implemented** for L2 disputes; L1 anti-collusion vault inert |
| Restart / reorg behaviour | **Decided** (SPEC §14.8, §9.3) | **Implemented** — finalized history is not rewritable; observation is replay-derived |
| Testnet activation | **Decided** (Decision 13) | **Implemented** — `testnet` profile, activation at height 20 |
| Mainnet activation | **Decided: none** | **Fail-closed** — `mainnet` has an empty committee |

## What is actually missing for production

1. **A stake/bond ledger.** No `NetworkParams` stake field, no per-validator
   bond balance, no bond accounting. Decision 8 deliberately builds none in
   Phase 6; Decision 2 leaves it "required for mainnet".
2. **A stake transaction type.** Nothing carries a bond or an unbond request,
   so the ledger (1) currently has no input.
3. **Unbonding delay enforcement.** Decided in principle (unbond after a full
   `finality_depth`) but nothing implements the delay, so a departing validator
   cannot yet be held to the window it signed.
4. **A mainnet committee.** `NetworkParams::mainnet()` has an empty
   `genesis_validators`, so `validate_checkpoint_against_set` has nothing to
   verify against and fails closed. Binding finality is therefore *untestable
   on mainnet* until a committee is chosen.
5. **Equivocation slashing.** Evidence is produced; punishment is not, because
   there is no bond. Decision 2.4 says "burn the full bond" — building that
   needs (1).
6. **Rewards and fee share are absent by decision, not by omission.** Decision
   2.3 chose `none`. They must stay absent unless a monetary decision changes
   it; adding issuance or a fee share silently would violate Decision 7 and the
   frozen cap.

## What is present and working

- **Deterministic set derivation** (`validators.rs`): identity bound to the
  epoch, canonical key-first ordering, seed-block derivation, duplicate
  key/address refusal, invalid-key refusal. 21 attack tests in
  `crates/jnt-core` pin these.
- **Six-clause checkpoint validation** as the single canonical authority
  (`validate_checkpoint_against_set`): epoch, set hash, bitmap, count, quorum,
  signature, monotonicity — each clause named on failure.
- **Real BLS** over `blst` (`bls.rs`): derive, sign, aggregate, one-pairing
  verify; 18 adversarial checkpoint tests prove `RealBls` rejects forgeries
  `MockBls` accepts.
- **Binding finality** (Decision 12): once activation height is reached, a valid
  certificate over the active committee makes its height final, and
  `Chain::adopt` refuses a branch forking at or below it.
- **Equivocation detection** (Decision 14): two conflicting valid certificates
  at one height refuse the second transition and retain canonical evidence.
- **No L2/checkpoint conflation** (Decision 11.6): L2 settlement quorums use the
  task-arbitration domain, not the checkpoint committee.

## The one thing an operator must not be misled about

**There is no staking, no bonding, no unbonding, no validator rewards and no
bond slashing anywhere in this tree.** The validator machinery that exists is a
*fixed-committee bootstrap*: a deterministic genesis key list that signs
checkpoints and makes them binding on `testnet`. It is real cryptography and a
real consensus rule, but it is not an economically-secured validator set. Mainnet
requires the stake ledger and a chosen committee first.

## Decisions still required (not made here)

Recorded in `docs/decisions.md` → *Pending protocol decisions* → **P2**. In
short: (1) the stake/bond transaction rule, (2) the bonded-stake ledger and the
selection rule that reads it, (3) unbonding enforcement, (4) the mainnet
bootstrap committee, (5) whether any reward/fee-share exists (a monetary
decision), and (6) the equivocation slashing path once a bond exists.

## References

- `crates/jnt-core/src/validators.rs`, `bls.rs`, `bls_checkpoint.rs`, `slash.rs`
- `crates/jnt-core/src/params.rs` — `genesis_validators`,
  `checkpoint_interval_blocks`, `finality_activation_height`
- `SPEC.md` §14.5–§14.8
- `docs/decisions.md` — Decisions 2, 8, 11, 12, 13, 14; *Pending* P2
