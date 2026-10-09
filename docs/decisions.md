# Protocol decisions — D3 (L2 fees) and §14.6 (validator economics)

Recorded as the protocol owner's standing decisions.

> **Reading order.** This file is chronological. Decisions 1–2 sit at the top,
> then a **dated gap audit** (a snapshot that says Phases 2–5 are NOT STARTED —
> true when it was written, superseded by the per-phase "Implementation status
> — Phase N SHIPPED" addenda further down the same file), then Decisions 3–16.
> The **authoritative** statement of what is built is the last addendum before
> the *Pending protocol decisions* section at the end. Do not read the gap
> audit's verdict table as current.
>
> **Status of the two decisions above.** Since they were recorded, D3 has been
> *consumed* (the L2 fee path shipped with Phase 2, SPEC §15) and §14.6 has been
> partially scaffolded (Decisions 11–12 built the fixed committee and binding
> activation; the stake ledger is still unbuilt — see *Pending*). At recording
> time neither changed a runtime rule; that was true then and is no longer the
> whole story.

**Neither decision changed any runtime rule at the time it was recorded**: no
code activated, the supply cap, mining economics, block rewards and monetary
policy were untouched. They become *operative* only when their enabling phases
are built (D3 → first L2 tx type, Phase 2; §14.6 → testnet activation gate,
Phase 6), each behind an explicit, reviewable change.

---

## Decision 1 — D3: L2 fee path = Option 3 (own schedule, same 50/50 split)

**Chosen: the L2 transaction types get their own flat fee schedule, and the
flat fee is split by the existing M1 mechanism, not bypassed.**

- The five flat fees already recorded in `params.rs`
  (`FEE_TX_*_SAT`: post 5 000 / claim 2 000 / submit 2 000 / dispute 10 000 /
  settle 20 000 sats) are confirmed as the L2 fee schedule for testnet.
- For an L2 transaction, the flat fee *is* `full_base` in `split_fees`: the
  M1 50/50 burn/PSCB invariant holds unchanged, one rule for both fee kinds.
- **The L1 gas floor (`base_fee * gas_used`) is untouched.** L2 transactions do
  not get an exemption; they simply ride a second, explicit schedule. No second
  base fee, no second congestion controller (option 4 stays rejected; it can be
  added later without breaking this decision).
- When the first L2 tx type is implemented (Phase 2), `check_tx`/the mempool
  fee check will route L2-type transactions to `L2_FEE_SCHEDULE` and everything
  else to the gas floor. The existing tripwire test
  (`l2_flat_fees_sit_below_the_gas_floor`) is then replaced by positive tests
  that L2 txs pay exactly the flat fee and are split 50/50.
- Sanity: 20 000 sats (max L2 fee) = 0.0002 JNT. At the mini profile this is
  cheap for workers; the schedule can be re-parameterised at mainnet without a
  consensus-format change (values live in `params.rs` constants).

Why not the others: option 1 (raise fees) contradicts the predictability
motivation for flat fees; option 2 (exemption) creates a widening-by-accident
exception; option 4 (separate fee market) is disproportionate mechanism for
five tx types today.

**Scope note:** D3 fixes *transaction fees only*. It does not decide task
*payments* (what a submitter pays a worker for compute) — that is a market
price set per-TaskContract by the participants (`payment_jnt`), never a
protocol rule.

---

## Decision 2 — §14.6: validator economics (design-only, activation stays Phase 6)

The five open items are decided as follows, values parameterised in
`NetworkParams` at implementation time, none wired into consensus now:

1. **Minimum stake: 5 000 JNT** (`min_validator_stake_sat`), **bonded** with
   unbonding after a full finality window (`finality_depth` blocks) so a
   departing validator cannot sign a checkpoint the chain cannot hold them to.
   Rationale: meaningful skin-in-the-game at ~0.0125% of supply; low enough for
   a wide testnet set.
2. **Selection: TopN over staked candidates, N = 21** — the already-implemented
   `SelectionRule::TopN` default. Stake-weighted sampling is explicitly
   rejected for now (unimplemented machinery, weaker auditability). For testnet
   Phase 6, a **fixed genesis committee of the TopN stakers at the genesis
   epoch** is the bootstrap mode; rotation switches on only after the chain is
   stable.
3. **Rewards: none for now.** Checkpoint signing earns **no new issuance and no
   fee share** at testnet. Revisit only if testnet shows signing liveness
   problems. (This deliberately leaves monetary policy exactly as it is.)
4. **Slashing for equivocation: burn the equivocator's entire bond**
   (5 000 JNT). Evidence = the already-exposed `equivocation_evidence`
   (two valid conflicting signed checkpoints, same key). 100% seizure is
   justified because equivocation is unambiguous, non-accidental, and attacks
   finality itself. The `slash.rs` vault handles the mechanics (vested
   claims, M2 interplay); equivocation slashing writes a full-bond SlashRecord.
   L2 dispute slashing (M2 amounts for fraudulent work) is *unchanged* — that
   was never part of the §14.6 open items.
5. **Activation: end of Phase 6 (public testnet), not before.** Sequence: L1
   testnet live → fixed committee signs checkpoints (finality visible but
   non-binding) → only after chaos testing passes, finality becomes binding
   (no reorg past checkpoint) in a separate, reviewable change. BLS/M5
   consensus activation is therefore still gated on its own explicit step.

**Standing rule reaffirmed:** anything that changes `Chain::submit` behaviour,
issuance, or fork choice requires its own review before it merges. These
decisions specify *what will be built when their phase starts*; they do not
build it now.

---

## Implementation pointers (for the phases that consume these decisions)

- D3 → Phase 2 (Step 6 tx types): add `l2_fee_for(tx_type)` and route the flat
  fee through `split_fees` as `full_base`.
- §14.6 → Phase 6: `min_validator_stake_sat`, `validator_count` (21), bonded
  stake accounting, equivocation → full-bond SlashRecord, fixed-committee
  bootstrap mode, activation flag.

*(The gap audit follows in the second half of this file.)*
---

# Gap audit — 6-phase L2 roadmap vs. what exists today

Audited 2026-10-06 against `docs/roadmap.md` §8 build order and the actual
crate tree (`jnt-core`, `jnt-net`, `jnt-store`, `jnt-node` — no `jnt-l2`,
no `jnt-worker` yet). Verdict per phase, with only genuinely-missing work
listed as remaining.

> **This section is a dated snapshot — it records what was true on
> 2026-10-06, and its "NOT STARTED" headings are deliberately left as written.**
> For the current status of every phase, read the **Implementation status**
> sections below, the last of which is authoritative.

## Phase 1 — L1 production-ready (Steps 1+2): **DONE**
- Mempool (`mempool.rs`): byte-bounded, fee-rate ordered, conflict-checked,
  integrated into `Chain` (`mine_from_pool`, reorg re-admission). 20+ tests.
- Persistent storage (`jnt-store`): append-only record log, crash recovery with
  reported torn tails, canonical height index, UTXO snapshots, adversarial
  fuzz/invariant coverage.
- Transaction relay over P2P (§13.14, `Tx` message) — shipped earlier in the
  session, tests in `jnt-net/tests/tx_relay.rs`.
- Real BLS via blst (`bls.rs`), storage fuzzing, checkpoint envelope (§14.4),
  validator-set machinery as an inert library (§14.6).
**Remaining: nothing for Phase 1 itself.**

## Phase 2 — TaskContract + state machine (Step 3) + Step 6 tx types: **NOT STARTED**
Requires crate `crates/jnt-l2/`:
- `TaskContract` struct + `ContractState` machine (Open → InProgress →
  ResultSubmitted → Disputed → Settled/Expired) with the 7 listed methods.
- The 5 L2 transaction types in `jnt-core/src/tx.rs` (TxPostTask, TxClaimTask,
  TxSubmitResult, TxDispute, TxSettle): Writer/Reader serialization,
  domain-separated signing hashes, validation rules, round-trip tests.
- **Unblocked now** by Decision 1 (fee path) — first thing to build.
Dependencies ready: `ComputeTask`/`ComputeAttestation` (compute_ir.rs),
mempool, store, fee schedule constants.

## Phase 3 — Dispute engine + M2/M1 wiring (Step 4): **NOT STARTED**
- `DisputeChallenge`, `DisputeVerdict`, `DisputeEngine::arbitrate/apply_verdict`
  in `crates/jnt-l2/src/dispute.rs`.
- Wiring (all primitives exist): `SlashVault` (slash.rs — vested SlashRecords,
  exhaustion), PSCB reserve on `Chain` (per-block undo maps for reorg
  correctness), whistleblower bonus from PSCB.
- Needs a re-execution verdict path: CPU-reference evaluation of M3 IR
  (roadmap §11 open question 2) — small spec item to write before coding.
**Blocked by Phase 2** (contracts must exist to dispute).

## Phase 4 — VWC issuance + tx types in jnt-core (Steps 5+6): **NOT STARTED**
- `VerifiedWorkCertificate` (`vwc.rs`): signing_hash over all fields,
  canonical serialization, quorum-gated `verify`, store lookup by task/worker.
- Note: the Step-6 tx-type work is listed under Phase 2 above (roadmap lists
  Steps 5+6 in one phase; Step 6 logically lands with the contract phase).
**Blocked by Phase 3** (a settled outcome is what a certificate certifies).

## Phase 5 — Worker client / SDK (Step 7): **NOT STARTED**
- New crate `crates/jnt-worker/`: node connection via jnt-net, task scanning,
  claim/execute/submit loop, M4 HBM proof (hbm_pow.rs exists), earnings.
- CLI (`jnt-worker run/status/earnings`) + `WorkerClient` SDK struct.
**Blocked by Phases 2+4** (nothing to claim or certify until then).

## Phase 6 — Integration + public testnet: **PARTIALLY PREPARED, NOT STARTED**
Already in place: jnt-node CLI with serve/relay, P2P networking with ban
scoring and keepalives, storage recovery, fuzz-smoke CI, difficulty-attack
sims, 360 tests.
Remaining for testnet:
- Wire all modules end-to-end in jnt-node (L2 tx handling, dispute flow,
  checkpoint relay message type — §13.5 addition, needs a vector-stable
  decision).
- Multi-node testnet tooling (compose/systemd scripts, seeds), chaos testing
  (dispute storms, partitions), bug-bounty program.
- §14.6 activation gate at the END of this phase, per Decision 2: fixed
  genesis committee signs (non-binding) first; binding finality is a separate
  reviewable change after chaos testing.

## Cross-cutting (safe to build in any order, not blind-built now)
- §14.6 economics implementation (stake accounting, slashing wiring) —
  decided above, built with Phase 6, not before.
- D3 fee routing in check_tx/mempool — built with Phase 2's first tx type.
- Agent integration layer (§12: REST API, MCP server, ElizaOS, LangChain) —
  separate roadmap section, none started; independent of Phases 2–5.
- Longer fuzz campaigns (WSL now works), more CI hardening — continuous.

## Verdict summary
| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | NOT STARTED (unblocked by Decision 1) |
| 3 — Dispute engine | NOT STARTED (needs Phase 2) |
| 4 — VWC issuance | NOT STARTED (needs Phase 3) |
| 5 — Worker SDK | NOT STARTED (needs Phases 2+4) |
| 6 — Testnet + finality activation | PREPARED, gated on 2–5 |

Recommended next: **Phase 2** — `jnt-l2` crate skeleton + TaskContract state
machine + the five L2 tx types with D3 fee routing, in that order, with the
M3-CPU-reference spec note written before Phase 3 starts.

---

# Implementation status — Phase 2 SHIPPED (2026-10-06)

This addendum supersedes the Phase-2 rows above; the audit itself is kept as the
record of what was true when it was written.

**Decision 1 (D3) is now consumed, exactly as recorded.** The five flat fees are
implemented and routed through the M1 split:

- `jnt_core::l2` defines the five payload types, their wire codes, canonical
  codecs, domain-separated signing hashes, and `L2TxType::fee_sat()` returning
  the D3 schedule. Round-trip, signing-hash-coverage, and bounded-decode tests
  live with it.
- `fees::split_flat_fee(fee)` treats the whole flat fee as `full_base` and
  applies the unchanged 50/50 burn/PSCB split (`tip = 0`; the odd satoshi goes
  to `burned`, matching `split_fees`).
- The open-question canary `l2_flat_fees_sit_below_the_gas_floor` is replaced by
  the positive test `l2_fees_do_not_use_the_l1_gas_floor`, which pins the
  separation instead of the question. **The L1 floor is untouched.**

**Phase 2 is complete.** `crates/jnt-l2` exists with `TaskContract` + the
`Open → InProgress → ResultSubmitted → Disputed → Settled/Expired` machine, and
`L2State` with accounts, escrow, the M2 slash vault, replay protection, and the
conservation invariant. SPEC.md §15 is the normative text. Dependencies reused
rather than reimplemented: `ComputeTask`/`ComputeAttestation` (M3),
`SlashVault` (M2), `ValidatorSet`/`BlsVerifier`/`BlsSignature` (M5),
`fees::split_flat_fee` (M1), and the hybrid wallet signing path.

Two implementation notes worth carrying into Phase 3:

1. **One economic constraint surfaced by implementation.** A `Correct`
   settlement takes its 20 000 sat fee out of the task escrow, and a `Fraudulent`
   one out of the worker's deposit. A task whose `payment_sat` (or deposit) is
   smaller than the settle fee therefore *cannot* be settled — the settle fails
   closed with `AmountTooSmallForFee` rather than collecting a partial fee. This
   is a real consequence of a 20 000 sat settle fee against a 5 000 sat post
   fee, it is recorded as an open economic question for Phase 6 (not a silently
   chosen rule), and Phase 3 should decide whether the fee comes from somewhere
   else or the schedule is re-parameterised.
2. **The `vwc_hash` convention before Phase 4.** `Correct` settles on the
   submitted `result_hash`, `Fraudulent` on the challenger's counter-result, and
   `Expired` on all-zero. Phase 4 replaces this with a real VWC hash; the
   convention is documented in `jnt_core::l2` (`VWC_HASH_EXPIRED`) so it is a
   named, replaceable constant rather than a magic zero.

Still gated on its own step, unchanged by this work: **M5/BLS finality
activation** (end of Phase 6). `Settle` verifies a quorum aggregate through the
existing trait, but no checkpoint finalizes an L1 block.

| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | **DONE** (commit `e3c0dab`) |
| 3 — Dispute engine | NOT STARTED (needs the M3 CPU-reference spec note first) |
| 4 — VWC issuance | NOT STARTED (needs Phase 3) |
| 5 — Worker SDK | NOT STARTED (needs Phases 2+4) |
| 6 — Testnet + finality activation | PREPARED, gated on 3–5 |

---

# Implementation status — Phase 3 SHIPPED (2026-10-06)

Phase 3 (dispute engine + M2/M1 integration) is built. **No L1 consensus rule
changed**, and no Phase-1/Phase-2 decision changed: the D3 fee schedule, the flat
fee = `full_base` rule, the M1 50/50 burn/PSCB split, the untouched L1 gas floor,
`payment_jnt` as a market payment, and the §14.6 validator economics are all
exactly as recorded above. Phase 3 consumes two of them (`split_flat_fee` for the
settle fee, and the PSCB reserve as the bounty source) and adds one new value,
recorded below rather than chosen quietly.

## Decision 3 — Dispute: arbitration rule, resolution window, whistleblower bounty

**Chosen, and now normative in SPEC.md §15.6–§15.8 (plus the M3 CPU-reference
note in §16):**

1. **Arbitration is a hash comparison, not an execution.** The reference
   re-execution (SPEC.md §16) produces a result hash; the engine compares it to
   the two competing claims. `reference == submitted → WorkerCorrect`,
   `reference == counter → ChallengerCorrect`, otherwise **`Inconclusive`**.
   `Inconclusive` is *not* a wire verdict: it settles nothing, slashes nothing
   and burns nothing. A malformed or unexecutable task therefore fails to
   *convict*, never defaults to guilt. The engine consumes only the reference
   hash — it holds no IR interpreter and no runtime.

2. **Resolution window = filing window.** A filed dispute must be resolved within
   the same number of blocks as the challenge-filing window, measured from
   `filed_at`. If it is not, the dispute **lapses**: the submitted result stands
   and settles as `Correct` with no fee, burning the challenger's deposit. An
   abandoned challenge is priced the same as a lost one.

3. **Whistleblower bounty = 25% of the slashed amount, paid from PSCB, capped by
   the reserve balance.** On an upheld challenge (`Fraudulent`) the challenger is
   refunded their deposit and additionally receives 25% of the worker's slashed
   deposit, drawn from the M1 PSCB reserve. It is a **transfer out of** the
   reserve to the challenger, not a mint, and it is capped at the reserve's
   *current* balance (computed before the settlement's own PSCB fee share is
   added, so a settlement cannot fund its own bounty). A failing challenge earns
   nothing and burns the deposit.

   Rationale for 25%: it is a coarse incentive, not a fee split that must
   reconcile to the satoshi, so it is a whole percent rather than a basis-point
   value. It rewards the party who spent money to catch fraud while leaving the
   reserve the larger share. It is parameterised in `L2Config`
   (`whistleblower_bounty_percent`) and is identical for `mainnet` and `mini`,
   because it is a rule, not a timing knob. The value can be re-parameterised
   without a consensus-format change.

**Explicitly unchanged:** the 5 000-sat post / 2 000 claim / 2 000 submit /
10 000 dispute / 20 000 settle schedule; the M1 50/50 burn/PSCB split; L2 fee =
`full_base`; the L1 gas floor; `payment_jnt` as a market price; no validator
rewards/fee share; min bond 5 000 JNT; TopN 21; full-bond equivocation burn;
binding finality only at the end of Phase 6.

**Still open, still not silently decided:** a task whose escrow or worker deposit
is smaller than the 20 000-sat settle fee cannot be settled (`AmountTooSmallForFee`
fails closed). Carried forward from Phase 2 to Phase 6 — either the fee comes
from elsewhere or the D3 schedule is re-parameterised.

| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | DONE |
| 3 — Dispute engine + M2/M1 | **DONE** (commit `bce55df`) |
| 4 — VWC issuance | NOT STARTED (needs Phase 3 — now unblocked) |
| 5 — Worker SDK | NOT STARTED (needs Phases 2+4) |
| 6 — Testnet + finality activation | PREPARED, gated on 4–5 |

---

# Implementation status — Phase 4 SHIPPED (2026-10-06)

Phase 4 (Verified Work Certificates) is built on top of the Phase-2/3 task,
dispute and settlement machinery. **No L1 consensus rule changed**, the D3 fee
schedule is untouched, and the M1 50/50 split still routes every L2 fee. SPEC.md
§17 is the normative VWC text.

## Decision 4 — VWC: a derived receipt, not a transaction

**Chosen, and now normative in SPEC.md §17:**

1. **Issuance is automatic at settlement; there is no VWC transaction type.**
   The roadmap's Step-6 note expected VWC to land with new tx types. It does
   not, deliberately: a certificate is a *derived consequence* of a settlement
   that was already authorized (quorum-signed `Settle`, or the dispute window
   closing unchallenged). An issuance transaction would let an actor request a
   certificate the protocol did not decide to grant — the exact thing a
   verified-work receipt must not allow. No new wire type, no new fee, no new
   authorization surface.
2. **No issuer key of its own.** The issuer is the protocol. `Quorum`
   certificates reuse the settle payload's M5 aggregate and verify through the
   existing `BlsVerifier`; `WindowElapsed` certificates (implicit settlements)
   carry no aggregate because none exists for a transition nobody transacted,
   and are documented as *not offline-verifiable* (§17.5) rather than being
   dressed up as stronger than they are.
3. **One certificate per task, ever.** The L2 state keeps a registry keyed by
   `task_id`; a second issuance is refused (`VwcAlreadyIssued`), never
   overwritten. Certificates hold no value and sit outside the conservation
   sum.
4. **No revocation, no expiry.** Settlement is terminal and one-way, so a
   `Correct` settlement can never be overturned later — exactly the condition
   that would make revocation necessary. If re-litigation is ever specified, it
   must bring a revocation rule as its own reviewable change.
5. **A zero-payout settlement still certifies.** An escrow that exactly covered
   the settle fee pays the worker nothing, but the work was still verified.
   `payment_sat == 0` is legal on a certificate; the Phase-4 tests caught the
   original assumption ("payment > 0") as wrong against the existing
   fee==escrow behaviour and it was corrected rather than papered over.
6. **A submitted result may never be all-zero.** `VWC_HASH_EXPIRED` is the
   all-zero hash; allowing a worker to submit it as their result would make a
   certified-correct settlement and an expired one indistinguishable in the
   settle record. Submission of the placeholder hash is now refused
   (`BadAttestation`). This is the one Phase-4 product fix; it has a permanent
   regression test.

**Explicitly unchanged:** D3 fees (post 5 000 / claim 2 000 / submit 2 000 /
dispute 10 000 / settle 20 000 sats), flat fee = `full_base`, the M1 50/50
burn/PSCB split, the L1 gas floor, `payment_jnt` as a market price, validator
economics, binding finality only at the end of Phase 6.

| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | DONE |
| 3 — Dispute engine + M2/M1 | DONE |
| 4 — Verified Work Certificates | **DONE** (commit `64650fe`) |
| 5 — Worker SDK | NOT STARTED (needs Phases 2+4 — now unblocked) |
| 6 — Testnet + finality activation | PREPARED, gated on 5 |

---

# Implementation status — Phase 5 SHIPPED (2026-10-07)

Phase 5 (Worker SDK) is built as a pure *client* over the Phase-2/3/4 L2
machinery. **No economic decision changed**: the D3 fee schedule
(post 5 000 / claim 2 000 / submit 2 000 / dispute 10 000 / settle 20 000
sats), flat fee = `full_base`, the M1 50/50 burn/PSCB split, the L1 gas
floor, `payment_jnt` as a market price, the §14.6 validator economics, and
binding finality only at the end of Phase 6 are all exactly as recorded
above. SPEC.md §18 is the normative worker-facing text.

## Decision 5 — Worker SDK: transport seams, not a transport

**Chosen, and now normative in SPEC.md §18.3/§18.17:**

1. **The worker SDK defines `L2NodeView`/`L2Broadcaster` traits instead of
   inventing a wire protocol.** This build has no L2 transport (`jnt-net`
   carries only the §13 P2P message set; the roadmap §13 REST API is
   unbuilt). Guessing one would bake in an unreviewed design; traits let a
   local node, an embedded state, or the Phase-6 REST client implement the
   seams without changing the SDK. The SDK therefore ships with no socket
   code, and every SDK rule is testable without one (the integration
   harness is an embedded single-node network behind the same traits).
2. **Worker identity is the wallet's hybrid address — there is no worker
   registration.** Authorization for claim/submit/dispute is exactly
   §15.2's `Auth::verify_as`; the SDK's identity check derives from the keys
   and refuses configuration that disagrees (§18.2). No second
   authorization scheme, no worker registry, no scoring.
3. **Idempotency by protocol identity, never by SDK bookkeeping.** Every
   mutating operation keys on task_id/txid; after any timeout the SDK
   reconciles against authoritative state, and re-broadcasting the *same
   bytes* is the safe retry (§18.9). The SDK keeps no side ledger that could
   disagree with the chain.
4. **Earnings are derived, not accumulated.** `earnings_of` reads only
   `L2State` fields (balance, task contracts, VWC registry, settle
   outcomes); the SDK invents no number and holds no account state that
   could desynchronize (§18.13).
5. **The executor is the one pluggable seam** (§18.6): hardware/agent
   engines root their own `Executor` impl; the shipped `CpuExecutor` is a
   deterministic §16-mold reference, not a production compute engine.

**Explicitly unchanged:** all standing decisions above; the
`AmountTooSmallForFee` settle-vs-fee open question stays open for Phase 6.

| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | DONE |
| 3 — Dispute engine + M2/M1 | DONE |
| 4 — Verified Work Certificates | DONE |
| 5 — Worker SDK | **DONE** (commit `c43bdef`) |
| 6 — Testnet + finality activation | PREPARED, gated on 5 (now unblocked) |

---

# Implementation status — Phase 6 STEP 0 audit, decisions recorded (2026-10-07)

Phase 6 opens with an audit rather than a work list (`docs/phase6-plan.md`,
commit `f4e9873`). It found that L2 is not merely unintegrated but
*unreachable* from consensus, and that four things the roadmap assumed were
decided are not. Those four were put to the protocol owner and decided here.
**None of them is built yet**; this section records the decisions so the build
has an authority to check against.

## Decision 6 — L2 transactions ride inside L1 blocks, committed by the existing merkle root

**Chosen: L2 transactions are carried in the L1 block body as an append-only
trailer, and the block's existing `merkle_root` commits to them. The 145-byte
header is unchanged and no L1 consensus rule is added.**

Why this shape, and not just "L2 txs in blocks":

- `block_hash = SHA256(DOM_BLOCK ‖ serialize(header))` (§3.4), so the header
  binds the body **only** through `merkle_root`. If L2 payloads rode in the body
  outside the merkle tree, two nodes could accept the same header with different
  L2 payloads and silently diverge in L2 state. Committing them to the merkle
  root is what makes L2 state a pure function of the canonical chain.
- Because the root is already covered by the header, `Chain::submit`'s existing
  merkle check authenticates L2 payloads with **zero new consensus code**. L1
  block validity is untouched.

**Encoding (append-only, so no frozen vector moves):**

```
serialize(block) = §3.5 (header ‖ sig ‖ pubkey ‖ U4LE(tx_count) ‖ txs)
                   ‖ U4LE(l2_count) ‖ serialize(l2_tx_0) …   [section OMITTED when empty]
```

- The L2 section is **absent** when there are no L2 transactions, so every
  block that exists today serializes to the same bytes, and `genesis_block()`
  is bit-identical. This is why the change breaks no §12 vector: the frozen
  vectors cover input/output/tx/header layouts, not whole blocks.
- A block whose L2 section is present but empty is **invalid** (non-canonical
  encoding): one block must have exactly one byte encoding.
- L2 leaves use a distinct domain tag (`0x02`) from L1 leaves (`0x00`) and
  internal nodes (`0x01`), so an L2 payload can never be reinterpreted as an L1
  transaction leaf.
- `l2_count` is bounded by the remaining bytes before allocation, the same rule
  §3 and §13.5 already impose on every other count field.

**What this decision does NOT do:** it does not make L2 validity an L1
block-validity rule. A miner that includes an L2 transaction that fails to apply
is not (yet) producing an invalid block; the transaction is deterministically
skipped during replay, so nodes still agree. Recording an invalid L2 payload in
an L1 block is therefore a waste of block space, not a divergence or a
consensus break. Tightening this into a block rule is a separate, reviewable
change (M2/M4), and would require `Chain` to consult L2 — which today's
dependency direction forbids by design (`jnt-l2` depends on `jnt-core`).

## Decision 7 — L2 value enters through a genesis-funded protocol escrow

**Chosen: a genesis allocation funds an L2 protocol escrow, and only escrow
movements drive `L2State::credit`. L2 burns and PSCB accrual then correspond to
real, accountable L1 supply changes. User deposits and exits are deferred.**

Rationale: `L2State` keeps a private balance ledger whose only entry point is
`credit()`, documented in the code as the Phase 6 bridge seam, and no production
path calls it. Without a funded, accountable source, L2 burns destroy nothing
real and `payment_sat` can be set by an unfunded poster — L2 would be a points
system wearing a currency's notation. A genesis-funded escrow makes
conservation span both ledgers while needing **no new L1 transaction type**,
which keeps Phase 6 inside its scope.

**Explicitly unchanged:** the 40M supply cap, issuance paths, block rewards,
halving schedule, the L1 gas floor, and the D3 L2 fee schedule. The escrow is a
*reallocation of genesis coins already inside the cap*, not new issuance.

**Deferred, and must be decided before mainnet:** user-facing deposit and exit
(the L1 lock that funds escrow from a user, and the L2→L1 withdrawal). That is
a new L1 mechanism and is not authorised by this decision.

## Decision 8 — Testnet bootstraps from a fixed genesis committee, no stake transactions

**Chosen: the testnet validator set is a fixed list in genesis. No stake
transaction type, no bonded-stake ledger, and no unbonding are built in
Phase 6.**

This is exactly Decision 2's own bootstrap mode ("a fixed genesis committee of
the TopN stakers at the genesis epoch is the bootstrap mode; rotation switches
on only after the chain is stable"). It lets the whole validator/finality path be
exercised end to end — set derivation, BLS signing and aggregation, quorum,
checkpoints, equivocation evidence, restart — without inventing the stake
economics that Decision 2 deliberately left parameterised.

Consequence to be honest about: with no stake ledger, `derive_set` is fed by
**genesis** rather than by chain state, so "TopN by stake at the seed block" is
exercised as a pure function over the genesis list, not over live stake. Real
bonded stake (`min_validator_stake_sat` = 5 000 JNT, unbonding after
`finality_depth`) remains required for mainnet and is **not** built here.

**Unchanged:** Decision 2's numbers (5 000 JNT, N = 21), no rewards, no fee
share, no issuance from validators, and equivocation burning the entire bond
through the existing M2 slash path.

## Decision 9 — The worker↔node transport is the roadmap §13 REST API

**Chosen: build §13's REST API in `jnt-node` (axum + tokio, opt-in via
`--api-listen`) and implement the Phase 5 seams (`L2NodeView`,
`L2Broadcaster`) as an HTTP client over it.**

Rationale: §13 is already the roadmap's specified interface and is the
prerequisite the roadmap names for the entire agent layer (§15 MCP, §16
ElizaOS, §17 LangChain). Extending the P2P layer instead would put
client/server query semantics into a consensus-adjacent crate and leave the
agent layer blocked; a bespoke third protocol would be thrown away when §13
lands. The cost is real and accepted: this adds the repository's first async
runtime and HTTP dependency.

**Additive extension required:** §13's broadcast endpoint is L1-shaped
(`signed_tx_hex`), while the SDK must broadcast `L2Transaction`s. The REST
surface therefore gains L2 read endpoints (task state, open tasks, VWC,
earnings inputs) and an L2 broadcast endpoint. That extension is specified in
`SPEC.md` §19.2, **not** by editing `docs/roadmap.md` (§13 stays as written).

## Pending, to be confirmed at their milestone (not yet decided)

- **P1 (M5):** whether the public testnet gets its own `NetworkParams` profile
  or runs on `mini`. Note for whoever decides it: genesis is *identical* across
  profiles today (`genesis_hash_is_identical_across_profiles`), so a profile is
  not by itself a chain ID — `network_magic`/`network_id` are the
discriminators.
- **P2 (M4):** adding frozen `msg_type = 11` for checkpoints, per §13.5's freeze
  rule and §14.6's statement that checkpoint transport is a §13.5 decision
  deferred for vector stability.
- **P3 (M4):** which checkpoint implementation is authoritative once finality is
  wired — `validators::validate_checkpoint_against_set` (six named clauses, set
  hash) or `bls_checkpoint::verify_checkpoint` — and what
  `Chain::finalized_height()` reports after activation.

| Phase | Status |
|---|---|
| 1 — L1 production | DONE |
| 2 — TaskContract + L2 txs | DONE |
| 3 — Dispute engine + M2/M1 | DONE |
| 4 — Verified Work Certificates | DONE |
| 5 — Worker SDK | DONE |
| 6 — Testnet + finality activation | **IN PROGRESS** — STEP 0 audit done; D6–D9 decided, none built; finality still gated |

---

# Implementation status — Phase 6 M3 STEP 0 audit: deposits need a decision (2026-10-07)

The M3 audit (no code changed) confirmed Decision 7 does **not** authorise user
deposits: it calls the deposit/exit mechanism "a new L1 mechanism" that "is not
authorised by this decision". The audit's recommended mechanism is Option A, a
burn-to-sink overlay needing no L1 rule change and no new transaction type. The
seven parameters below are the missing decision. They are recorded here before
any M3 code, per the M3 instruction to stop until the decision is explicit.

## Decision 10 — User L1 → L2 deposits via burn-to-sink overlay

**Chosen: an ordinary STANDARD L1 payment to a params-derived unspendable sink
is interpreted by L2 replay as a deposit. No new L1 transaction type; existing
L1 machinery is unchanged.**

1. **Sink derivation.** `SHA256("jounit/l2-deposit-sink/v1" ‖ network_id)[..20]`
   (`NetworkParams::l2_deposit_sink`). Deterministic per profile, distinct from
   the escrow identity (different domain tag), holding no key. A different
   network's sink on this chain is an ordinary burn, never a deposit.
2. **Recipient derivation.** The common owner of the transaction's inputs, each
   read as its input key bundle's address. L1 consensus already proves that
   address equals the spent UTXO's owner (`verify_input` refuses anything
   else), so replay derives ownership without re-verifying signatures and
   without UTXO history. Inputs with different owners, and coinbase
   transactions (unsigned inputs), are **not deposits**: the value stays burned
   and nothing is credited. No third-party recipient field exists in M3.
3. **Minimum deposit amount.** 1,000,000 sat (0.01 JNT) per sink output, both
   profiles (`NetworkParams::l2_deposit_minimum_sat`). Below-minimum sink
   outputs are burns without credit. Rationale: 50× the largest D3 fee, a
   dust/bloat floor — every credited deposit leaves permanent unspendable UTXO
   entries, so crediting dust would let anyone bloat both ledgers for free.
4. **Maturity rule.** A deposit is *detected* when its block is accepted but
   *credited* (spendable) only once the carrying block is final by the
   existing depth rule: `tip_height − deposit_height ≥ finality_depth`
   (20 on `mini`, 100 on `mainnet`). No new finality mechanism is introduced;
   the rule reuses the finality depth every node already enforces. Before
   maturity the deposit is pending (visible, not spendable); a reorg that
   removes the block removes the deposit by re-derivation.
5. **Replay identity.** `(txid, output_index)` of the sink output, tracked in a
   consumed set in `L2State`. The same bytes in two blocks credit once; the
   second occurrence is refused by name. Restart and reorg re-derive the set
   from the winning chain, so no persisted record can go stale or duplicate.
6. **Conservation rule.** Per deposit, exactly 1:1 — credited satoshis equal
   the sink output's satoshis, no rate, no fee on the credit itself. Globally,
   `L1 live supply + L2 held − sink-held supply ≤ supply cap`: sink outputs
   stay in the L1 UTXO set (unspendable), so the M2 joint check grows a sink
   term rather than breaking. Burns anywhere move the sum down, never up.
7. **Reorg behavior.** Derived, never undone: the winning chain is replayed and
   deposits are re-detected, re-matured and re-credited from it. A deposit on
   the losing branch vanishes; one still present but no longer deep enough
   returns to pending; one the winner shares is credited exactly once. No
   phantom, double, or stale credit is representable.

**Explicitly unchanged:** L1 consensus rules, the two L1 transaction types and
their layouts, the monetary cap and issuance, fee rules, L2 transaction
semantics, the M2 genesis allocation, finality activation.

**Explicitly deferred (mainnet blocker):** L2→L1 exits. Deposits without exits
trap user funds in L2, so M3 makes *testnet* deposits functional while mainnet
still requires a separate exit decision and implementation. No exit decision is
recorded here.

---

# Implementation status — Phase 6 M4 STEP 0 audit: foundation without activation

The M4 audit (no code changed) re-examined the tree after M3 against STEPS
1–3 and found: no stake ledger, no bond/unbond path, no committee in params,
two checkpoint validators with no declared canonical one, no checkpoint codec
at all (serialize only), no finality wire message, and `Chain` consulting none
of it. The Decision 2 economics (5,000 JNT bonded, TopN 21, no rewards, no fee
share, full-bond equivocation burn) therefore have no mechanism to run on —
which is exactly what Decision 8 scoped out of Phase 6 ("no stake transaction
type, no bonded-stake ledger, and no unbonding are built in Phase 6", with real
bonded stake "required for mainnet"). That scoping is honored, not
re-designed: the items below build only what Decisions 2 (bootstrap mode) and
8 authorized, and binding finality is explicitly NOT activated. If a future
milestone wants binding finality, it needs its own decision.

## Decision 11 — Validator set + finality foundation (non-binding)

**Chosen: fixed genesis committee in `NetworkParams`, the six-clause
validator as the single checkpoint authority, relay-only checkpoint transport,
observation without activation.**

1. **Economics (STEP 2 verdict).** The implementation does not support bonded
   stake — no stake fields, no bond ledger, no reward or slash-bond path — and
   M4 adds none of them. Unchanged and still standing: 5,000 JNT minimum,
   TopN 21 (reused as the committee-size cap), no validator rewards, no fee
   share, no issuance from validators, full-bond equivocation burn, L2 dispute
   slashing untouched. Bonding, unbonding, rewards and bond-slashing arrive
   with the stake ledger, which is mainnet-gated. Equivocation in M4 is
   detected and evidenced, not economically punished.
2. **Set derivation (STEP 3 answers).** (1) Stake lives nowhere in Phase 6.
   (2–3) No bonding/unbonding exists. (4) N/A. (5) Committee size is capped at
   21, fixed per profile, not selected. (6) No ties: the committee is an
   explicit key list, canonically sorted by key bytes. (7) Active from genesis,
   no rotation in M4. (8) The committee is explicit BLS keys in
   `NetworkParams` (`mini`: four deterministic test keys; `mainnet`: empty,
   meaning no committee yet — checkpoints verify against nothing and therefore
   fail closed). (9) Every node derives the identical `EpochSet` (epoch 0,
   set-hash bound) as a pure function of params.
3. **Canonical authority (STEP 5 verdict).** `validators::
   validate_checkpoint_against_set` (six clauses: epoch, set, bitmap, count,
   quorum, signature, monotonicity) is the single authority.
   `bls_checkpoint::verify_checkpoint` remains as its inner signature
   primitive, not a rival authority. `CheckpointChain` is the monotonic
   observation log. The payload gains no set-hash field in M4: with no
   rotation the epoch already scopes every certificate, and payload format
   changes wait until rotation needs them.
4. **Transport (STEP 6 verdict).** One relay-only message, `msg_type = 11
   CHECKPOINT`, carrying complete certificates only — no proposal/vote
   messages, because no BFT round protocol exists to give them meaning, and no
   aggregator protocol is built in M4 (test certificates are assembled from
   test keys). Received certificates are verified against the committee and
   relayed if valid; consensus never consults them. Protocol version stays 1:
   the §13.5 freeze rule already covers additive types.
5. **Non-binding gate (STEP 14).** `Chain::submit`, fork choice and
   `finalized_height` are untouched. Observed finality is reported
   (`status`/`verify`) and relayed, never enforced: a reorg crossing an
   observed checkpoint still applies, and that behavior is pinned by test so
   binding can never slip in silently. Binding finality requires a future,
   separately reviewed decision.
6. **L2 separation (STEP 10 verdict).** No L2 change. L2 `Settle` quorums
   belong to the task-arbitration domain, not the L1 checkpoint committee;
   conflating them would authorize settlements with checkpoint keys.
   `NodeL2` keeps the empty set, deposit maturity keeps `finality_depth`, and
   replay is untouched.
7. **Testnet profile (STEP 11 verdict).** No new `NetworkParams` profile in
   M4 (that is M5's P1 proposal). `mini` carries the test committee and a
   10-block checkpoint interval; `mainnet` carries an empty committee and a
   100-block interval. No public testnet starts in M4.

---

# Implementation status — Phase 6 M5 STEP 0 audit: binding finality needs four decisions

The M5 audit (no code changed) re-read the tree after M4 and found: L1 finality
is still depth-only (`Chain::finalized_height()` = `tip − finality_depth`), the
`FinalityManager` is observation-only and consulted by nothing, there is no
testnet profile, `equivocation_evidence` has no caller, L2 deposits mature by
depth only, and the node's L2 validator set is empty (fail-closed). Four
decisions are required before any consensus change: binding finality activation
(A), a testnet profile (B), equivocation detection policy (D), and L2 finality
semantics (E). This milestone records those four and implements exactly them.

## Decision 12 — Binding finality activation (A)

**Chosen: a valid checkpoint certificate over the active committee becomes
binding once the configured activation height is reached; `Chain::adopt()`
refuses to rewrite finalized history; the depth rule remains the fallback.**

The finalized checkpoint must be the canonical block at its height, carry a
valid certificate, satisfy `ceil(n × 6667 / 10000)` quorum (unchanged — no
stake-weighted quorum is invented), be strictly monotonic in height, and not
conflict with an already-finalized height. Once height H is finalized,
`Chain::adopt()` rejects any competing branch whose fork point is at or below
H (the existing `ReorgWouldCrossFinality` error, now fed by a real finalized
height). Before `activation_height`, only the depth rule applies and an
observed certificate is never binding.

## Decision 13 — Testnet profile (B)

**Chosen: a dedicated `testnet` profile — unique `network_magic`/`network_id`,
four deterministic genesis validators (quorum 3), a 10-block checkpoint
interval, and an explicit activation height. No staking, no rotation, no public
launch.**

The committee is a fixed genesis list derived from public test seeds, built by
the same derivation as `mini`, so two independently constructed `testnet`
profiles are byte-identical. This is the network config required to exercise
binding finality, not a public deployment.

## Decision 14 — Equivocation detection, no economic punishment (D)

**Chosen: retain deterministic `EquivocationEvidence` for conflicting valid
certificates; never finalize two different hashes at one height; fail closed on
the conflicting transition. Economic slashing stays deferred (no stake exists).**

When two otherwise-valid certificates disagree at the same height
(`H → A` and `H → B`), the second finalization transition is refused, the
conflict is detected, and canonical, bounded evidence is retained. Nothing is
burned and no penalty is invented, because there is no bond to burn.

## Decision 15 — L2 finality semantics (E)

**Chosen: deposit maturity requires BOTH depth and binding checkpoint finality
(take the stronger/safer); L2 settlement verifies against the declared active
committee, not the checkpoint-signing keys by convenience.**

Before binding finality activates, the M3 depth rule still governs, so M3 is
never made less safe. After activation, a deposit is not spendable merely
because depth is satisfied if the canonical history at that height is not
finalized. L2 does not grow a second finality system. `Settle`/VWC keep their
existing verification semantics but use the declared committee; a profile with
an intentionally empty committee (mainnet) continues to fail closed.

---

# Implementation status — integrated sprint 1 (2026-10-07): machine/agent layer shipped

## Decision 16 — Machine/agent identity + authorization policy (roadmap items 3, 4, 6, 10)

**Chosen: a deterministic, non-consensus policy library, `crates/jnt-core/src/agent.rs`.
No consensus rule changes; until a later decision wires it into `submit_at`, it
cannot move a coin.**

1. **Identity is derived, never assigned.**
   `agent_id = SHA256("jounit/agent-id/v1" ‖ network_id ‖ role ‖ owner)[..20]`,
   where `owner` is an ordinary §1 address derived from the owner's key bundle.
   The identity is therefore cryptographically owned (only the key holder can
   produce `owner`), network-bound (a testnet identity is not a mini identity)
   and role-separated (`Human`, `Machine`, `Service`) without creating a second
   address space. `SpendPolicy::validate` *re-derives* it and refuses a policy
   whose `agent_id` does not belong to its `owner`, so a policy cannot claim
   someone else's agent (`PolicyError::IdentityMismatch`).
2. **One economy.** Machine and human wallets both spend ordinary §1 UTXOs under
   the existing issuance schedule. No second currency, no second ledger, no
   parallel monetary base (roadmap item 18).
3. **Policy is owner-signed and total.** `SpendPolicy::signing_hash` is
   domain-separated (`jounit/agent-policy/v1`) over a bounded canonical
   encoding: version `1`, network id ≤ 64 bytes, ≤ 64 recipients, ≤ 64 service
   tags, explicit per-transaction limit, tumbling window length, cumulative
   limit, validity range, and a revoke flag. The test suite mutates **every**
   field and asserts the hash changes, so no field is outside the signature.
4. **Fail-closed default.** An **empty** recipient list authorizes nothing (not
   "anything"); an **empty** service list authorizes no service-tagged payment;
   a policy that names services refuses an untagged payment. Zero amounts,
   zero window, zero per-transaction limit, and `expires_at <= not_before` are
   refused at `validate`, before any authorization is attempted.
5. **Tumbling window, not sliding.** The cumulative limit resets every
   `window_blocks` measured from the window's own start height, so accounting is
   reproducible from `(window_start_height, height)` alone and needs no
   unbounded authorization history (a sliding window would be a
   resource-exhaustion surface). "Many small payments" therefore cannot bypass
   the per-transaction limit: the suite drives 400+400 and shows the third 400
   refused at 1 200 > 1 000 with the budget untouched by the refusal.
6. **Anti-replay.** Each authorization carries a nonce that must **strictly
   increase**, so a captured authorization cannot be re-submitted.
7. **Rotation and revocation.** Spend accounting is keyed by policy hash, not by
   agent id: a rotated-in policy starts with a fresh window and cannot inherit
   the old policy's spend, and a rotated-out policy is refused by the owner's
   `revoked` flag. `PolicyBook` is bounded (`DEFAULT_MAX_POLICIES`) and refuses
   a new policy rather than grow without limit.
8. **Offline verification.** `Authorization` has its own domain-separated
   signing hash (`jounit/agent-auth/v1`) and `verify_authorization` checks it
   against public key bundles through the existing §1 signature path
   (`sig::verify_bundle`). A third party — a service, a bridge — verifies with
   public material only: no policy, no network, no private key. Mutating the
   amount breaks verification, so the authorization is tamper-evident.
9. **No key material.** Nothing in the module reads, stores or emits a private
   key; `SpendPolicy` discloses rules, never keys.

**Explicitly unchanged:** L1 consensus, transaction/block layout, UTXO and
supply rules, fee rules, finality activation, L2 semantics, the M1–M5
mechanisms. SPEC.md gains no section for this layer because SPEC's scope is the
base-layer consensus rules; the layer is tracked in `docs/roadmap.md` §21–§22.

**Explicitly deferred:** (a) enforcing a policy inside L1/L2 transaction
validation (that would be a consensus change and needs its own decision);
(b) the canonical agent service-payment format (item 11); (c) service receipts
(item 12); (d) bridge and reputation layers. The `Authorization` type is the
seam they will build on.

---

# Pending protocol decisions (NOT decided — recorded as blockers)

These are **not** decisions. They are the questions a protocol owner must answer
before the corresponding work may proceed. They are listed so implementation
never has to guess, and so no future reader mistakes their absence for an
oversight. `SPEC.md`, the code and the monetary policy remain the authority for
what *is* decided.

## P1 — L2 → L1 exit primitive (mainnet fund-safety blocker)

**Status: APPROVED 2026-10-09 (owner).** E-1 = (a), E-2 = permissionless
crank, E-3 = exiting owner prepays the exit fee, as recommended; E-4–E-6
acknowledged at their narrow defaults. Implementation is now authorised along
exactly those lines; until it ships, deposits remain one-way.

Decision 10 defers exits and states no exit decision is recorded. The deposit
sink holds no key, so it cannot release funds; any exit needs a **new L1 rule**.
Full design and the six questions are in `docs/l2-exit-design.md`.
**Do not implement an exit until this is decided; do not mint value to fake one.**

### The blocker is proven in code, not asserted

`crates/jnt-core/tests/sink_unspendable.rs` drives the real L1 spend rule
(`ledger::check_tx` → `tx.verify_input(k, &held.out.address, …)`) against a real
mined deposit and shows:

- the **depositor cannot reclaim its own sink output** (`Error::WrongAddress`) —
  the signature verifies against the depositor but is compared to the *sink*;
- a stranger's attempt fails identically, and an unsigned attempt fails one step
  earlier (`Error::EmptySignatureBundle`);
- the sink and escrow identities are distinct, derived, and owned by no wallet.

So the conclusion is not a design preference: **no signature can authorise a
sink spend, and no L2 state can change that.** There is no implementation-only
path to an exit.

### Owner decisions — APPROVED 2026-10-09 (full text in `l2-exit-design.md`): E-1 = (a), E-2 = permissionless crank, E-3 = exiting owner prepays

| # | Decision | Recommendation |
|---|---|---|
| **E-1** | **The L1 release primitive.** Either *(a)* a consensus-authorised **spend of sink outputs** authorised by an exit proof instead of a signature, or *(b)* replace the keyless sink with a validator-threshold escrow. | **(a).** It keeps the ordinary `value_in >= value_out` rule in force everywhere and reuses the existing `Undo` path, so a reorg unwinds a release like any other spend. *(b)* introduces a key the architecture deliberately avoids and makes committee-key compromise a fund-loss event. |
| **E-2** | **Permitless crank or gated release.** | **Permissionless crank:** anyone may submit, consensus pays only the recorded `destination`. No operator privilege, no second authorisation path to audit. |
| **E-3** | **Who funds the L1 release fee.** | **The exiting owner, prepaid at queue time.** The L2 side debits `amount + exit_fee_sat`; the claimant receives the fee, the destination receives the principal. Prepayment is what makes a permissionless crank griefing-bounded. |

**E-4 to E-6 default to the narrower choice** — no cancellation, no
challenge window, no emergency pause — because each default adds authority to
nobody. Acknowledged 2026-10-09: the narrow defaults stand.

### Also required before implementation — engineering scope, authorised by the approval

- **An L2 → L1 proof mechanism.** L2 state is derived by replay and is **not**
  committed on chain in a form L1 can check. The recommendation is to commit an
  L2 state root at the activation height and require a Merkle inclusion proof.
  This is the largest single piece of the change.
- **A network-upgrade / activation mechanism.** None exists. `finality_activation_height`
  is the only height-gated rule and it is profile data, not a negotiated
  upgrade.

### What is already implemented (safe, non-consensus)

`crates/jnt-core/tests/sink_unspendable.rs`,
`crates/jnt-l2/tests/exit_unavailable.rs`,
`crates/jnt-node/src/conservation.rs` (+ `tests/conservation.rs`), and two
rejection tests in `crates/jnt-node/tests/api.rs`. These pin the one-way
behaviour and the sink accounting that the exit must preserve. When the rule is
approved, those tests are the migration checklist — see `docs/l2-exit-design.md`,
*Migration, activation and compatibility*.

## Decision 17 — Conservation-breach response: freeze funding paths, alarm (2026-10-09)

Owner-approved companion to the live conservation surface (`GET
/v1/conservation`, the `/metrics` gauges, and the `jnt-worker run` gate).
When a node detects that the joint-supply bound is broken (L2 not closed, L2
funding anomaly, or joint supply over its bound), it must:

1. **Refuse the funding-shaped paths** — L2 include-queue admission and the
   deposit/L2 write endpoints stop being accepted, with an error naming
   conservation, so the node stops making a bad situation worse;
2. **Keep serving reads** — `/v1/status`, `/v1/conservation`, `/metrics`,
   blocks and UTXO queries stay up, so operators can see what happened;
3. **Log the breach loudly** on every serve iteration while it persists.

Halt (process exit) was rejected: a crash-loop converts a safety alarm into
a liveness loss and destroys the diagnostics. Alarm-only was rejected as
insufficient once detection is this cheap. Recovery is an operator action —
restart after the cause is understood; the check re-runs on every request
and no state is discarded.

## P2 — Bonded stake / mainnet validator committee (mainnet blocker)

Decision 2 fixes the economics (5,000 JNT `min_validator_stake_sat`, bonded,
unbonding after `finality_depth`; TopN 21; no rewards; no fee share;
full-bond equivocation burn) and Decision 8 deliberately builds **none** of the
mechanism — no stake transaction, no bond ledger, no unbonding. Consequences
that remain unbuilt:

1. A **stake/bond transaction type** and its validation rules (new L1 rule).
2. A **bonded-stake ledger** and the selection rule that reads it ("TopN by
   stake at the seed block" is currently a pure function over the genesis list).
3. **Unbonding** after a full finality window, and the interaction with the
   checkpoint-signing duty.
4. **Validator rewards / fee share** — deliberately *none* today (Decision 2
   item 3). Adding any is a monetary decision and is explicitly out of scope.
5. **Equivocation slashing** — evidence exists (`EquivocationEvidence`) but no
   bond exists to burn, so punishment is deferred.
6. **A mainnet committee.** `NetworkParams::mainnet()` carries an **empty**
   `genesis_validators`, so checkpoint verification fails closed and binding
   finality is untestable on mainnet. Choosing the bootstrap committee is a
   decision.

None of 1–6 may be invented by implementation; each needs a recorded decision.

## P3 — M2 activation rule (mainnet blocker)

The anti-collusion slash vault exists (`slash.rs`) but **no rule triggers it**.
What must be decided: what *proves* a compute result fraudulent well enough to
slash, and how that verdict enters consensus. Unspecified → M2 stays inactive.

## P4 — M4 registration (mainnet blocker)

The HBM scratchpad puzzle (`hbm_pow.rs`) is **not a registered `puzzle_id`**.
What must be decided: whether M4 *replaces* or *composes with* the §5 puzzle,
and the registration/versioning rule. Unspecified → chain security rests on §5
only.

## P5 — Open interaction carried from Phase 2/3 (economic)

A task whose L2 escrow or worker deposit is smaller than the **20,000 sat
settle fee** cannot be settled (`AmountTooSmallForFee` fails closed). Carried
forward since Phase 2. What must be decided: whether the settle fee is drawn
from elsewhere or the D3 schedule is re-parameterised. Until then, small tasks
fail closed rather than collecting a partial fee — the safe direction.

## P6 — Mainnet L2 genesis escrow scale (not a blocker, a confirmation)

Decision 7 sets `mainnet` `l2_genesis_escrow_sat = 100,000 JNT` inside the
788,476 JNT that can never be minted. If the protocol owner intends a different
scale, that is a one-value change; `escrow_ceiling_sat` (M-E) is what
`NetworkParams::validate` checks, and it is currently set tight to the
allocation.

---

# Pending monetary decisions (NOT decided — recorded as blockers)

`docs/monetary-redesign.md` is a **PROPOSAL** and is not authorisation to change
consensus. It carries the full analysis, formulas and sensitivity tables; this
section is the *sign-off surface* — the same questions reduced to items a
protocol owner can accept or reject. Nothing below is approved, and **no line of
this section authorises an implementation**. While any item is `OPEN`, the
frozen state in Decisions 7 and 10 stands: cap, ladder, halving schedule and
both fee schedules are unchanged.

Confirmed current state (read from code, not carried over): cap
**39,945,600 JNT**; ladder-era issuance **39,157,124 JNT** (the earlier
39,157,200 was the geometric shortcut `149 × 262 800`, which over-states the
schedule by 76 JNT because genesis occupies a rung-0 height without minting);
**788,476 JNT** permanently unmintable; ladder `76, 38, 19, 9, 4, 2, 1, 0` in
whole JNT; `halving_period` 262,800; ladder exhausts at height **1,839,600**.

| # | Question | Options | Consequence if changed | Status |
|---|---|---|---|---|
| **M-A** | Tail emission shape at ladder exhaustion | **(A)** retain zero tail · **(D)** flat tail · **(E)** declining tail to a floor | Any tail **requires a supply-rule change** and a new issuance anchor; `cap − max_issuance_sat` can no longer be the escrow backing rule (see M-D/M-E) | **APPROVED — (E) decay tail** |
| **M-B** | Tail floor value | proposed **0.1 JNT/block** · 1.00 · 0.50 · other | Sets steady-state dilution (0.10 JNT ≈ 0.0134 %/yr); the proposal derives this from a security-floor argument, **not** from any repository constant | **APPROVED — 0.1 JNT/block mainnet floor** |
| **M-C** | Per-network tail | mainnet value · testnet/mini value (proposed **1 sat/block**) | Applying the mainnet value to mini would mint **>1,000 %/yr** (proposal F5); the two profiles must be set independently | **APPROVED — 1 sat/block on mini/testnet** |
| **M-D** | Fate of `supply_cap_sat` | **keep** as a sanity ceiling · **replace** with an explicit invariant | `supply_cap_sat` is currently the *joint L1/L2 conservation anchor* **and** the escrow backing rule, not just a ceiling. Deleting it without a replacement silently removes both checks. The proposal rejects deletion-for-convenience | **APPROVED — cap retained as a sanity ceiling** |
| **M-E** | Meaning of `escrow_ceiling` | define an explicit, validated parameter · keep the implicit `cap − max_issuance_sat` gap | No `escrow_ceiling` symbol exists in code or SPEC today. It is the proposal's replacement for the gap rule once a tail changes issuance. Ownership, release rules, reorg behaviour and interaction with spendable supply are **all unspecified** | **APPROVED — explicit validated `escrow_ceiling` parameter** |
| **M-F** | Fee-burn / deflation design (proposal F2) | own the design (set an explicit target or accept deflation) · leave unowned and state no target | Under ordinary usage the **whole** base fee leaves live supply (50 % burned + 50 % to the `pscb_reserve` counter, which no code path converts back to UTXOs — verified 2026-10-09). At high activity live supply trends to zero at ~y50 in the proposal's model. This is **not** an issuance question, but it blocks any claim that monetary policy is "complete" | **APPROVED — no numeric target; deflation accepted and documented** |
| **M-G** | Activation mechanism | network-upgrade flag/height · historical-compatibility expectation · vector changes | Proposal §5.4 argues activation at exhaustion (1,839,600) leaves existing history byte-identical. **No mainnet activation until M-A…M-F are approved**; vector changes are only legitimate once an approved rule actually changes consensus | **APPROVED — activation at each profile's ladder exhaustion (mainnet 1,839,600; mini/testnet 14,000)** |**Approved 2026-10-09 (owner), item by item:** M-A = (E) decay tail; M-B =
0.1 JNT/block mainnet floor; M-C = 1 sat/block on mini/testnet; M-D =
`supply_cap_sat` retained as a sanity ceiling only; M-E = an explicit
validated `escrow_ceiling` parameter; M-F = no numeric burn target — deflation
accepted and documented; M-G = activation at each profile's ladder
exhaustion. Implementation is authorised **only** along these lines; any
other value needs a new record here.

**What may proceed while M-A…M-G are open:** auditing, tests, simulation and
documentation that *describe* current behaviour. **What may not:** editing
`params.rs` reward/cap/escrow values, `supply.rs`, the consensus cap gate, or
committed vectors.

## Implementation record — approved 2026-10-09 (M1…M5, complete)

`docs/monetary-redesign.md` §6 is the acceptance matrix; every row below is
verified, not asserted.

| Milestone | Delivered |
|---|---|
| **M1 (decision recorded)** | M-A…M-G recorded above; Decisions 7/10 amended for issuance and the escrow rule only. Commit `e3a5713`. |
| **M2 (model)** | `sim/supply_schedule_sim.py` exits 0 and regenerated `tests/vectors/supply_vectors.json`; `sim/tail_emission_sim.py --selftest` exits 0; `sim/verify_vectors.py` exits 0. The two sims and `supply.rs` agree to the satoshi, including the period-boundary off-by-one that both previously carried and the exact ladder-era total (39,157,124.5 JNT at the first tail block). |
| **M3 (consensus)** | `supply::check_mint_at_height` is the single mint gate and `Chain::apply_block` calls it; `params::validate` refuses a zero tail floor/constant and an escrow above its ceiling; §6.1 tests 1–14 exist (`historical_replay_is_unchanged_by_the_tail` = `historical_heights_keep_their_ladder_rungs_under_the_tail`, `reward_step_at_the_ladder_tail_boundary_is_at_most_a_halving` = `every_tail_step_is_at_most_a_halving_and_reaches_the_floor`); `cargo test --workspace` 0 failures; clippy `-D warnings` clean; fmt clean. |
| **M4 (spec/docs)** | SPEC §7 and §19.4, this file, `docs/monetary-policy.md`, `docs/mainnet-readiness.md` and `README.md` re-stated to the shipped function; no document still claims a frozen zero tail or the `cap − max_issuance_sat` backing rule. |
| **M5 (ops)** | Vectors frozen in git; `jnt-node verify` and `/v1/conservation` report the joint bound; `jnt-worker run` gates on it (older nodes fall back to the sanity cap, i.e. a stricter check). |

Milestones **not** claimed here: M-F owns no numeric fee-burn target (deflation
accepted and documented in `monetary-policy.md`), and the exit rule (P1) remains
a separate, unimplemented mainnet blocker.
