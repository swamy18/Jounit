# Phase 6 — STEP 0 audit (integration, testnet, finality, mainnet readiness)

**Date:** 2026-10-07 · **Branch:** `main` @ `3ad5586` · **Scope:** audit only, no
implementation changes (per the Phase 6 instruction to complete STEP 0 first).

Audited against the real tree, not the roadmap's intent. Every claim below
carries its evidence (file:line), because the whole point of this step is to
find out which Phase 6 components are *actually* missing rather than which ones
sound missing.

---

## 1. Confirmed baseline (measured, not assumed)

| Item | Value | How measured |
|---|---|---|
| Workspace members | 6 (`jnt-core`, `jnt-l2`, `jnt-net`, `jnt-node`, `jnt-store`, `jnt-worker`) | `Cargo.toml` |
| Rust source | 30 / 10 / 13 / 1 / 5 / 16 files; 14 926 / 5 434 / 5 149 / 994 / 2 208 / 2 930 lines | `git ls-files` + `wc -l` |
| Tests | **500 passing, 0 failed, 1 ignored** | `cargo test --workspace` (this session) |
| `#[test]` by crate | core 288, l2 94, net 53, store 34, worker 32 | `grep -c '#\[test\]'` |
| Fuzz targets | 13 | `fuzz/fuzz_targets/` |
| Sim scripts | 6 | `sim/` |
| TODO/FIXME/`unimplemented!` | **0** | `grep` over `crates/` |

**Second worktree present:** `.kilo/worktrees/chatter-level` (detached
`7caf7de`) is a linked worktree belonging to another session. It is ignored and
outside this task's scope. Repo-wide greps must exclude it, and it must not be
touched. (Earlier `read_files` results already showed its paths leaking into
`referencedBy`.)

**Dependency direction (this drives everything below):**

```
jnt-core  ←  jnt-l2, jnt-net, jnt-store, jnt-node
jnt-core, jnt-l2  ←  jnt-worker        (the SDK is the only L2 consumer)
```

---

## 2. The findings that define Phase 6

### F1 — L2 is not on the L1 execution path at all  · classification: **implementation gap, spec explicitly defers**

- `crates/jnt-node/Cargo.toml` depends on `jnt-core`, `jnt-net`, `jnt-store` —
  **not `jnt-l2`**. The node binary cannot even name an L2 type.
- `Chain::submit(&mut self, block: Block)` (`chain.rs:600`) takes L1 blocks only.
- `L2Transaction` is referenced **only** inside `crates/jnt-core/src/l2.rs` and
  `fuzz/`. No block, mempool, store, net or node code mentions it.
- SPEC §15.9 lists "How L2 transactions reach a block (Phase 6)" under *what is
  not specified here*, and roadmap §4 assumed they would be "5 new L1
  transaction types" — which the Phase 2 build did **not** do: it gave L2 its own
  `L2Transaction` wire type and its own fee path (decision D3).

So "integrate L2 into the block pipeline" is not a wiring chore; its shape is an
open protocol decision. → **Decision D6** (§4).

### F2 — L2 value has no L1 backing  · classification: **interface exists, deliberately unfunded; economic decision**

`L2State` keeps **private** balances (`accounts: HashMap<Address,u64>`,
`state.rs:87`) separate from the L1 UTXO set. Every L2 operation debits that
ledger: `apply_post` charges `payment_sat + fee` from `submitter`
(`state.rs:222-240`), `collect_fee` splits it 50/50 into `burned`/`pscb`
*inside L2*. The only way value enters is:

```rust
/// Add free balance to an address. The L1→L2 funding bridge is Phase 6; this
/// is the seam it will call.
pub fn credit(&mut self, addr: Address, amount: u64)
```

`credit()` is called **only** from tests and the worker's test harness; no
production path calls it. Consequences that matter for STEP 8:

- L2 "burns" and PSCB accrual currently destroy nothing in real JNT supply —
  they are entries in a parallel ledger.
- There is no deposit, no escrow, no exit, and no conservation link between the
  two ledgers; SPEC §15.5's invariant (Σaccounts + locked + burned + PSCB +
  vault == Σcredited) is enforced **within** L2 only.
- `payment_jnt`/`payment_sat` can be set arbitrarily high by a poster who was
  never funded.

→ **Decision D7** (§4). This is the "STOP before a monetary redesign" item
STEP 8 anticipates.

### F3 — L2 state is unrecoverable across restart  · classification: **implementation gap**

`crates/jnt-l2/Cargo.toml` has **no `serde` dependency at all** — no
`Serialize`/`Deserialize`/snapshot/`to_bytes` anywhere in `crates/jnt-l2/src`.
`L2State` is pure in-memory (`HashMap`/`HashSet`), and nothing persists it.
STEP 3's scenario 9–11 (restart → re-sync → identical state) cannot pass today.

The repair is *determined by D6*: if L2 transactions live inside persisted L1
blocks, `L2State` is rebuilt by deterministic replay of the canonical chain in
block order (no new store, no new serialization format — the strongest option,
and consistent with how `Chain` itself is recovered). Otherwise L2 needs its own
persistence with its own format. Note `advance_block` already runs
deterministically in sorted task-id order (`state.rs:448-453`), so replay is
sound once every L2 tx in a block is fed to it in a canonical order.

### F4 — No stake ledger, so the validator set cannot be derived from chain state  · classification: **implementation gap + protocol decision**

`validators.rs` is a complete inert library — `ValidatorRecord { stake_address,
bls_pk, stake_sat }`, `SelectionRule::TopN`, `derive_set`, `set_hash`,
`EpochSetCache`, `quorum_size`, `validate_checkpoint_against_set`,
`equivocation_evidence`, `MAX_VALIDATORS_DEFAULT = 21`,
`EPOCH_BLOCKS_DEFAULT = 100`. But:

- `derive_set(epoch, candidates, rule, max)` takes the candidate list **as a
  parameter**. Nothing derives it from `Chain`; grepping `stake`/`bond` across
  `jnt-core/src` finds only M2 `slash.rs` and doc comments — there is **no stake
  transaction, no bonded-stake ledger, and no unbonding**.
- Decision 2's "min 5 000 JNT **bonded**, unbonding after a full finality
  window" and "TopN by stake at the genesis epoch" therefore have no mechanism
  to consume, and `NetworkParams` has **no** `min_validator_stake_sat` /
  `validator_count` fields (`params.rs`), even though Decision 2 says those
  values live there.

→ **Decision D8** (§4): how stake enters the chain at all.

### F5 — Finality has no wire transport  · classification: **spec defers deliberately; protocol decision**

`jnt-net/src/msg.rs` defines exactly `Version=1 … Tx=10` and the **entire net
crate contains zero occurrences of "checkpoint" or "finaliz"**. §14.6 states why:

> "It does not define how checkpoints travel on the wire (that is a §13.5
> message-type decision, deferred so §13.12 vectors stay stable)."

§13.5's freeze rule means a new `msg_type = 11` is *additive and safe* (a v0.2
node must ignore unknown types without disconnecting), but it is still a
protocol change needing vectors. → proposal P2 in §4.

### F6 — Two unreconciled checkpoint implementations, neither reachable from consensus  · classification: **implementation gap**

- `bls_checkpoint.rs` — the M5 gadget: `CheckpointPayload`,
  `Checkpoint { bitmap, aggregate }`, `ValidatorSet` (bare key list),
  `verify_checkpoint`, `CheckpointChain::accept/is_finalized/latest`.
- `validators.rs` — §14.6 set semantics: `EpochSet`, `derive_set`,
  `validate_checkpoint_against_set` (six named clauses).

They do not reference each other. `ValidatorSet::new(Vec<BlsPublicKey>)` takes
keys only, with no epoch/set-hash binding, while §14.6 requires verification
against `set_hash(e)`. Nothing calls either from `Chain`.

And `Chain::finalized_height()` (`chain.rs:162`) is **height-based only**:

```rust
pub fn finalized_height(&self) -> u64 {
    self.height().saturating_sub(self.params.finality_depth)
}
```

so "finality" today means "100 blocks deep", never "a BLS quorum signed it".
Reconciling these into one authority (and deciding which one `finalized_height`
reports) is part of M4. → proposal P3 in §4.

> **M4 resolution (Decision 11).** F4's gap is closed *by scoping*, not by
> building a stake ledger: with no bond path in Phase 6 (D8), the committee is a
> fixed genesis list in `NetworkParams`. F5 is closed by `msg_type = 11
> CHECKPOINT` (protocol v1, §13.5 additive). F6 is closed by making
> `validators::validate_checkpoint_against_set` the single authority, with
> `bls_checkpoint::verify_checkpoint` its inner primitive. `finalized_height`
> deliberately still reports only the depth rule — M4 observes but does not
> activate, so it must not report a BLS quorum it does not enforce.

### F7 — There is no testnet network profile  · classification: **config decision, low risk**

`NetworkParams::by_name` accepts `"mainnet"` and `"mini"` and **explicitly
errors on `"testnet"`** ("unknown network \"testnet\"; use \"mainnet\" or
\"mini\""). Also relevant to STEP 10's "chain ID": genesis is currently
**identical across profiles** (`genesis_hash_is_identical_across_profiles`
asserts it), so `network_magic`/`network_id` are the only discriminators. → proposal P1.

### F8 — Worker↔node transport: no HTTP stack exists, and the seams' write side is L2-shaped  · classification: **protocol decision**

- The repo contains **no `axum`/`tokio`/`hyper`/`http`** — networking is
  synchronous `std::net` (`jnt-net/src/net.rs:175`).
- roadmap §13 specifies a full REST API in `crates/jnt-node/src/api.rs` with
  axum, including `/v1/task/{task_id}`, `/v1/tasks/open`, `/v1/tx/broadcast` —
  which maps onto the Phase 5 seams closely, **but it is unbuilt**, and its
  broadcast endpoint is L1-transaction-shaped (`signed_tx_hex`) whereas the SDK
  must broadcast `L2Transaction`s. That coupling makes F8 depend on D6.
- STEP 2 says not to invent a new protocol "if the existing Jounit networking
  layer can support this cleanly" — but §13.5 P2P is peer-to-peer with no
  client/server request semantics and no auth beyond handshake.

→ **Decision D11** (§4).

### F9 — `docs/status.md` "Not done" is stale  · classification: **SPEC/doc outdated (implementation correct)**

The `## Not done` section still claims "**Layer 2 / Verified Work
Certificates.** The core of the project's premise" is not done, that "nothing
feeds [the mempool] and nothing reads it", and that there is "No fuzzing with a
coverage-guided harness" — all three were superseded by the Phase 2–5 SHIPPED
sections appended below it, and by `docs/status.md`'s own "Step 2 —
transaction relay: implemented". Doc-accuracy fix, no code risk. It sits in the
chronological ledger, so the repair is a pointer, not a rewrite.

### F10 — Carried open items (unchanged, still open)

- `AmountTooSmallForFee`: a task whose escrow/deposit is below the 20 000-sat
  settle fee cannot settle. Carried from Phase 2; STEP 8 item; needs a decision,
  not a patch.
- `serve` rewrites `blocks.json` in full on every change (`docs/status.md`,
  SPEC §13.10 item 4) — expected to become a real bottleneck once L2 traffic
  rides blocks. Measure in M7 before optimising (STEP 7's own instruction).
- Mempool is in-memory only (documented, acceptable).

---

## 3. Reuse map — what Phase 6 must **not** rebuild

| Need | Existing component to reuse |
|---|---|
| L2 state transition | `jnt_l2::L2State::apply` / `advance_block` / `tasks` / `vwcs` / `validate_vwc` — **the only L2 executor that may ever exist** |
| L2 wire format + auth | `jnt_core::l2`: `L2Transaction`, five payloads, `Auth`, DOM tags, `txid`, `fee_sat`, `L2TxType` |
| L2 fee path | `jnt_core::fees::split_flat_fee` + `params::L2_FEE_SCHEDULE` (D3) |
| Validator sets | `jnt_core::validators` (§14.6) — extend, don't rewrite |
| M5 checkpoint gadget | `jnt_core::bls_checkpoint` (`Checkpoint`, `verify_checkpoint`, `CheckpointChain`) |
| Equivocation evidence | `validators::equivocation_evidence`; slashing mechanics via `jnt_core::slash` (M2 vault) |
| L1 mempool/relay/sync | `jnt_core::mempool`, `jnt_net::{relay,syncer,msg,frame}` |
| Persistence + recovery | `jnt_store` (append-only block log, torn-tail recovery) |
| Worker SDK seams | `jnt_worker::node::{L2NodeView, L2Broadcaster, Host, BroadcastError}` — the transport **implements** these; the SDK is not modified to accommodate it |
| Dispute arbitration | `jnt_l2::DisputeEngine`, `DisputeEvidence::validate`, §16 CPU reference |
| Test harness patterns | `jnt-worker/tests/common::{mod,bls}.rs` (in-memory single-node network behind the seams); `l2_flow`/`vwc_flow`/`dispute_flow` integration suites |

---

## 4. Decisions required before implementation (do not invent these)

> **Status: DECIDED (2026-10-07).** All four were put to the protocol owner and
> came back on the recommended option. They are recorded as **Decisions 6–9 in
> `docs/decisions.md`**, which is now their authority; the options below are
> kept as the record of what was chosen *from*. D9 (below, §4 D11) is the
> transport decision — the question list used its working number.

### D6 — How L2 transactions reach a block *(blocks M1, and F3's repair)*

- **A (recommended):** L2 transactions are carried **inside L1 blocks** in a
  dedicated payload section, in a canonical order; each node rebuilds `L2State`
  by deterministic replay of the canonical chain. **No header change** (the
  145-byte header and §13.12 vectors stay frozen). L1 consensus is untouched:
  L2 state becomes a pure function of the block sequence.
- **B:** as A, plus an L2 commitment root **in the header** (145 → 177 bytes) —
  provable to light clients, but a format/consensus change requiring new
  vectors and a hard-fork story.
- **C:** a separate L2 chain anchored to L1 by periodic checkpoint
  commitments; no L2 txs in L1 blocks — most scalable, most new machinery, and
  furthest from the shipped code.

### D7 — The L1↔L2 value bridge *(blocks M2, STEP 8)*

- **A (recommended):** an **escrowed deposit** path — an L1 transaction locks
  JNT into an L2 escrow, and only such deposits drive `L2State::credit`; L2
  burns/PSCB then reduce real L1 supply, so the conservation invariant spans
  both ledgers. Requires a new L1 stake/lock mechanism and an exit path.
- **B:** genesis-funded protocol escrow — the smallest *real* bridge: a genesis
  allocation funds L2, burns stay real and accountable, user deposits are
  deferred. Testnet-complete without new L1 transaction types.
- **C:** keep L2 unbacked and label it testnet-only accounting, documenting that
  L2 burns are not L1 supply burns and that mainnet requires the bridge. Cheapest
  and honest, but mainnet-blocked by design.

### D8 — How stake becomes bonded validator stake *(blocks M4)*

- **A (recommended):** a **new L1 stake transaction type** (bond/unbond) with a
  bonded-stake ledger and unbonding-delayed release — the mechanism Decision 2
  already presumes; a protocol addition needing SPEC + vectors.
- **B:** genesis committee only for testnet — a fixed validator list in the
  testnet genesis, no stake transactions at all; validates finality end-to-end
  while leaving real stake economics for the mainnet phase (matches Decision 2's
  "fixed genesis committee is the bootstrap mode").
- **C:** stake as a special UTXO convention (locked outputs) — no new tx type,
  but implicit rules that are harder to audit.

### D11 — Worker↔node transport *(blocks M3)*

- **A (recommended):** build **roadmap §13's REST API** (axum + tokio) as
  specified, and implement the SDK seams as an HTTP client. Roadmap-specified,
  unlocks §15–§17 (MCP/ElizaOS/LangChain), standard tooling; costs a new async
  runtime and HTTP dependency in a repo that has none, and §13 must be extended
  with L2 read/broadcast endpoints (additive, written into SPEC §19).
- **B:** extend **`jnt-net`** with L2 query/broadcast messages and a synchronous
  client — no new dependencies, reuses framing/handshake/ban logic; but P2P is
  peer-to-peer, so this adds client/server semantics to a consensus-adjacent
  crate, and §13 stays unbuilt (blocking the agent layer).
- **C:** a minimal std-TCP JSON line protocol for the node — smallest step, no
  deps; but it invents a third protocol and would be thrown away when §13 lands.

### Proposals to confirm at their milestone (additive, low risk)

- **P1 (testnet profile, M5):** add a `testnet` `NetworkParams` profile
  (mainnet-shaped parameters, distinct `network_magic`/`network_id`) rather than
  running the public testnet on `mini`; note that genesis is identical across
  profiles today, so the profile is not a chain-ID by itself.
- **P2 (checkpoint message, M4):** add frozen `msg_type = 11 CHECKPOINT` per the
  §13.5 freeze rule, plus new §13.12 vectors, as §14.6 anticipates.
- **P3 (finality authority, M4):** make `validators::validate_checkpoint_against_set`
  the single checkpoint authority (it already enforces the six clauses and the
  set hash), and decide what `Chain::finalized_height()` reports once binding
  finality is activated.

---

## 5. Milestone plan (each ends with diff review → tests → commit)

| # | Milestone | Deliverable / acceptance criteria | Gated by |
|---|---|---|---|
| M0 | **This audit** | plan doc; no code change | — |
| M1 | L2 in the block pipeline | **DONE** (`SPEC.md` §19.1, commit pending). L2 txs carried per D6 (append-only trailer, absent when empty, so no vector or genesis change); the header's existing `merkle_root` commits to them under a distinct leaf tag, so the existing `MerkleRootMismatch` rule refuses stripped/altered sections and `Chain::submit` learns nothing new; `jnt_l2::replay::ChainL2` rebuilds state by replay (derived, not stored) and the incremental path is asserted equal to it; rejected payloads are skipped **by name** and stay retryable; `mine_block_with_l2` produces such blocks. Acceptance: two independent replays produce **equal `L2State`** (equality derived over all fields); full replay == incremental application; stripped section fails its own header. +13 tests (513 total). **Not** covered, by construction: funded accounts (M2) and validator quorum (M4) — pinned as such instead of pretended. | D6 |
| M2 | Value bridge + fee accounting | per D7; conservation asserted across L1+L2; `AmountTooSmallForFee` resolved or explicitly re-documented; `split_flat_fee` unchanged | D7, D6 |
| M3 | Worker↔node transport | per D11; seam conformance tests; auth, malformed-rejection, replay, idempotent retry, stale-state, restart/reconnect; no key material in logs/errors | D11, M1 |
| M4 | Validator set + finality (non-binding) | **DONE** (Decision 11, `SPEC.md` §14.7). Scoped per D8: no stake ledger, so a fixed genesis committee in `NetworkParams` (`mini` 4 test keys, `mainnet` empty → fail closed) instead of chain-state derivation; `validate_checkpoint_against_set` is the single authority; `FinalityManager` observes and reports; `msg_type = 11 CHECKPOINT` relays complete certificates (protocol v1, unfrozen-additive); bounded `Checkpoint`/`CheckpointPayload` deserialize. **Finality is visible but non-binding** — `Chain::submit`/fork choice untouched, reorg-crosses-checkpoint pinned by test. +13 tests (588 total) + `checkpoint_codec` fuzz target (14). Deferred to mainnet: bonded stake, unbonding, rewards, rotation, equivocation slashing. | D8, D11 |
| M5 | Multi-node testnet | per P1; ≥3 nodes incl. validators; the 11 STEP-3 scenarios scripted and reproducible; chain sync, restart/recovery, L2 + worker + VWC + dispute flows | M1–M4 |
| M6 | Adversarial + chaos | node/validator/worker/network attack matrix (STEP 5); every real bug: root cause → minimal fix → regression test → doc note | M5 |
| M7 | Performance baseline | measured L1/L2/worker/network numbers (STEP 7) before any optimisation; document what is slow and why | M5 |
| M8 | SPEC audit + mainnet checklist | implementation-vs-SPEC findings classified 1/2/3 (STEP 9); MAINNET READINESS CHECKLIST with PASS/FAIL/BLOCKED/REQUIRES DECISION (STEP 10); docs synced | M1–M7 |

**Quality gates at every milestone:** `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, release build, the six sim scripts, `fuzz/cargo check
--bins`, and a real fuzz campaign for any new target. WSL nightly + ASan for
libFuzzer (MSVC cannot run it); command shape `wsl bash -lc '…'`.

**Standing constraints honoured by this plan:** no rewrite of Phases 1–5; no
monetary-policy change (D7 is the one place a change could be *required*, and it
stops for a decision); `docs/roadmap.md` untouched; binding finality only after
M4's fuzzing and M6's chaos pass, in a separate reviewable change.
