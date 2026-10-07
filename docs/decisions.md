# Protocol decisions — D3 (L2 fees) and §14.6 (validator economics)

Recorded as the protocol owner's standing decisions. **Neither decision changes
any runtime rule today**: no code activates, the 40M supply cap, mining
economics, block rewards and monetary policy are untouched. They become
*operative* only when their enabling phases are built (D3 → first L2 tx type,
Phase 2; §14.6 → testnet activation gate, Phase 6), each behind an explicit,
reviewable change.

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
