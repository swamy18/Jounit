# Status

What is built, what is verified, and what is not finished. Read this before
relying on anything here.

## Scope

Layer 1 (base layer) implementation per SPEC.md. Includes the P2P networking layer
(`jnt-net`) supporting multi-peer block relay, locator-based sync, handshake
isolation, ban scoring and side-branch pruning. Also defines the five core
protocol mechanisms — **only M1 is consensus-active**, i.e. only M1 can change
whether a node accepts a block:

| # | Mechanism | Consensus-active | Module |
|---|---|---|---|
| M1 | 50/50 PSCB (Protocol Security & Compute Buffer) fee split | **Yes** — SPEC.md §8 | `fees.rs`, `chain.rs` |
| M2 | Time-Locked Compute Reserve & 50/50 Anti-Collusion Slash Vault | No — no rule creates a slash record yet | `slash.rs` |
| M3 | Universal Hardware-Agnostic Canonical Compute IR | No — envelopes only | `compute_ir.rs` |
| M4 | Memory-bound HBM scratchpad PoW puzzle | No — not a registered `puzzle_id` | `hbm_pow.rs` |
| M5 | Sovereign BLS aggregate finality gadget checkpoints | No — pairing core is real (`blst`), the gadget is unwired; §14.6 validator-set semantics are design-only | `bls_checkpoint.rs`, `bls.rs` |

SPEC.md §14 carries the same table and says why each of M2–M5 is inactive: each
needs a rule this repository has not specified (what proves a compute result
fraudulent, how a task enters a block, whether the HBM puzzle replaces or
composes with the §5 puzzle, who the validator set is). M2 and M4 would change
consensus, so guessing those rules in code would have been the wrong order.

## Verified

- `cargo test --workspace` — **347 tests pass (current count; older sections of
  this file quote counts as of their own dates — 242, then 263, then 293 —
  kept as history):**
  - 227 unit tests in `jnt-core` (M1–M5 suites, the 21-test validator-set suite,, the 30-test real-BLS suite in
    `bls.rs`, the 10-case mempool attack suite, the 2 pinned L2 fee-schedule
    tests, and the rest)
  - 18 adversarial checkpoint tests against the real BLS verifier
    (`tests/bls_checkpoint_attack.rs`)
  - 10 mempool↔chain integration tests in `crates/jnt-core/tests/mempool_l1.rs`
  - 11 red-team integration tests in `crates/jnt-core/tests/redteam.rs`
  - 30 persistent-storage tests in `crates/jnt-store` (torn tails, corruption
    refusal, reorg+restart, migration)
  - unit + integration tests in `jnt-net` (framing, codecs, sync, bounds,
    tx-relay socket tests), including a real-socket end-to-end sync between
    two `P2pNode`s
  - 2 wire-vector tests in `crates/jnt-net/tests/net_vectors.rs`
- **Persistent storage is implemented** (`crates/jnt-store`, appendix below):
  append-only checksummed block log, atomic metadata, crash-safe reopen;
  replaces the old whole-chain JSON rewrite.
- **P2P transaction relay is implemented** (SPEC.md §13.14): wallet → mempool →
  peer relay → remote pool → mining → confirmation was verified end to end
  with three real processes.
- **Real BLS cryptography is implemented** (`bls.rs` over `blst`): derive,
  sign, aggregate, one-pairing aggregate-verify, deterministic fixtures.
  `verify_checkpoint` with `RealBls` rejects forgeries `MockBls` accepts. This
  does NOT make finality consensus-active.
- `cargo clippy --workspace --all-targets` clean under `-D warnings`.
- `cargo fmt --check` clean across all crates.
- Two real `jnt-node serve` processes on the `mini` profile completed a full
  handshake, synced, reorged onto the heavier branch and kept relaying; both
  data directories then passed `jnt-node verify` (replay from genesis, UTXO +
  supply + PSCB match).
- An independent Python implementation of the PoW puzzle (`sim/jounit_reference.py`),
  written from the prose of SPEC.md rather than from the Rust source, reproduces
  all 21 puzzle digests in `tests/vectors/puzzle_vectors.json`. This is the only
  real evidence that SPEC.md is unambiguous rather than merely consistent with the
  Rust code.
- All five vector files in SPEC.md §12 exist, are generated from source, and are
  read by tests. `sim/verify_vectors.py` regenerates and cross-checks them.
  Each consuming test was checked to actually fail when the value it pins is
  perturbed, so none of them pass vacuously. `net_vectors.json` (§13.12) is the
  wire-format set — frame envelope, every `msg_type`, `VERSION` for both
  profiles, locator construction. It now has the independent implementation the
  puzzle set has: `sim/net_reference.py` re-derives §13.2 framing and §13.5
  messages from the prose alone and is run by `verify_vectors.py --check`. It
  found a real bug on its first run (ADDR field order, below). Five of the 28
  pinned values are chain-derived — a mined block and locator entries from a
  200-block chain — so the script reports them as **skipped** by name rather than
  passing over them silently.
- Node CLI end to end on the `mini` profile: init, mine 31 blocks, spend, verify
  (replays from genesis and diffs UTXO + supply), status. Fee burn reconciles
  exactly — 31 blocks issue 2356 JNT, live supply is 2355.99825 JNT, the
  0.00175 JNT difference being the destroyed base fee.
- Supply schedule matches design doc §16, including that only 298 000 of the
  304 000 JNT mini cap is reachable and the remainder is permanently
  unmintable rather than merely reserved.
- The mempool (`jnt-core/src/mempool.rs`) has a 10-case attack suite. Each case
  names the rule it enforces and the attack it stops: double spending one output
  twice, spending a nonexistent output, a byte-cap flood, overshooting the gas
  cap, ordering by fee *rate* rather than fee total, selection determinism
  between two nodes holding the same pool, eviction of confirmed transactions,
  transitive eviction two generations deep, re-admission after eviction, and
  leaving unrelated siblings alone. Two of those cases failed against the code
  as first written (below), and the fee-order case did not fail until the test
  itself was rebuilt — see the note below.

**The mempool is now wired into L1 (Step 1A).** `Chain` gained three things, all
of them in `jnt-core` — no networking or storage concern leaked into consensus:

- `mine_from_pool` selects from the pool at the next block's height and base fee
  and evicts exactly what the block contains. Evicting the whole *selection*
  would drop transactions the gas or byte cap left behind, and those are still
  the best candidates for the next block.
- `confirmed_above(from_height)` returns the transactions canonical blocks have
  confirmed since the caller's cursor, so a block that arrives over the wire
  evicts from the pool the same way a locally mined one does.
- `reconcile_mempool(pool, from_height)` is the whole operation: evict what the
  chain confirms, re-admit what a reorg un-confirmed, report what moved.

Ten integration tests in `crates/jnt-core/tests/mempool_l1.rs` attack the seam
rather than the pool: local tx → pool → block, eviction by a peer's block,
double spend, malformed and forged transactions, a full pool, a degenerate byte
cap, fee-rate ordering reaching the block, and two reorg cases (a disconnected
transaction coming back, and one whose input the winning branch consumed being
refused instead of re-pooled).

**Restart behaviour is defined, not accidental.** The pool is in-memory only and
does not survive a restart, so a node restarts with an empty pool and reconciles
from the tip: there is nothing to recover and nothing stale to distrust. The
cursor is therefore only needed within a run. This is honest rather than
complete — a production node would persist the pool — and it is recorded here so
nobody mistakes it for an oversight. Persisting it belongs with Step 2
(`jnt-store`), not before.

## Known bugs found and fixed

**`Transaction::value_out` panicked on an unrepresentable total.** It summed
output values with `.sum()`, so a transaction declaring outputs above `u64::MAX`
raised `attempt to add with overflow` in debug builds and wrapped to a small
number in release ones. `check_tx` compares `value_out` against the resolved
input total, so a wrapped sum could read as a transaction that spends less than
it creates — an inflation primitive. Confirmed by restoring the original
expression and watching the new test fail with the overflow panic. `value_out`
now saturates and a new `value_out_overflows` check runs in `check_tx` before
the comparison is trusted.

The rest of the arithmetic audit came back largely clean: `ser.rs`
bounds-checks every read, both `tx` and `block` deserializers reject
attacker-controlled counts larger than the remaining buffer before allocating,
`value_in` already used `checked_add`, `fees.rs` uses saturating operations
throughout, `apply_tx` records undo data that makes rollback an exact inverse,
and `apply_block` does verify the coinbase against `reward + tip` (chain.rs)
before the supply-cap check — so the inflation path is closed there. The one gap
it did turn up was block-level fee accumulation using `+=`, which panics in
debug and wraps in release, feeding a wrong total into the burn/tip split. Now
`checked_add`.

**The mempool's eviction cascade did not cascade.** `evict_confirmed` decided
what to drop by asking the `spends` reverse index who spends a given outpoint.
That index answers "who spends this outpoint", not "which transaction *created*
it", and its entries are keyed by the outpoint being spent — so for a dependent
transaction the index pointed straight back at the dependent itself, which is
never what the check needed to know. Nothing downstream of a confirmed
transaction was removed: not the direct child, and not a grandchild two hops from
the block. The pool kept entries that could never be mined and relayed them to
every peer forever. The rule is now stated as what it means: a transaction is
doomed if it spends an outpoint the block consumed, or an outpoint created by a
transaction the cascade has already removed — tracked in a `gone` set that grows
each pass. Confirmed by temporarily restoring the index-based predicate and
watching both cascade tests fail (`a tx spending a confirmed-away output stayed
pooled`, `the cascade stopped before the second generation: 2 entries left`);
with the fix in place both pass.

**A second reorg destroyed the first reorg's disconnected transactions.**
`disconnected_txs` was cleared at the top of `reselect` and assigned (rather than
extended) when a reorg committed. A syncing node submits blocks in a burst, so
two reorgs landing before the caller reconciled was ordinary behaviour, not an
edge case: the second reorg's assignment wiped the first's pending transactions,
and the pool re-admitted nothing. No error, no log — the transactions simply
did not come back. The set is now only ever *added* to, and only after a reorg has
committed; nothing clears it except the caller draining it. Confirmed by
re-instating the `clear()` and watching all three reorg tests fail
(`exactly the orphaned payment`, `the payment was not re-admitted`, `the
payment's input is gone…`).

**The puzzle overflow guard could not fire.** `PuzzleSpec::validate` computed
its accumulator bound as `(nn_input_dim as i64) * 128 * 128 + 62` and compared
against `i64::MAX`. The dimensions are `usize`, so a large value wraps negative
on the cast and the multiplication overflows *before* the comparison runs — the
check passed exactly the inputs it existed to reject. It also only considered
`nn_input_dim`, ignoring `nn_hidden_dim`, which is what every layer after the
first actually accumulates over. Now computed in `u128` with saturating
arithmetic, bounding the wider of the two, and moved ahead of the share audit
that consumes those dimensions.

Writing the test for that surfaced two more overflows on the same path:
`nn_macs` multiplied `usize x usize x usize`, and `nn_share_bps` then
multiplied by 10 000. Both are public methods a caller can reach before
`validate()`, so a hostile puzzle registry entry could panic a node rather than
be rejected. Both are saturating now.

**The LWMA retarget had no restoring force.** `d_raw` was computed as
`S / (T * W)`, which is `avg_solve / T`. That quantity is scale-invariant, so
*every* difficulty was a fixed point of the rule. Consequences, both reproduced
before the fix: halving the hashrate produced blocks at 2T, the rule answered
difficulty 2, and the interval ran away to 4T; doubling the hashrate produced
0.5, which clamped to `min_difficulty` and left the chain stuck at the floor.

It is now multiplicative from the previous difficulty:

```
d_new = d_prev * T / avg_solve
```

Perfect spacing (`avg_solve = T`) is a fixed point at *any* starting
difficulty, which is the property the test suite now asserts directly.

**The Zawy weights were inverted.** The oldest solve time in the window carried
weight `window²` and the newest carried weight 1, which is backwards and would
make the retarget sluggish. Now the newest carries `window²`.

Both bugs were invisible to the original tests because every one of them used
*uniform* solve times, where weighting direction cannot matter and the
scale-invariant formula coincides with the correct one at the starting value.
The tests now use mixed histories.

Three `chain.rs` tests encoded the broken behaviour and were corrected rather
than deleted: a timestamp helper was tuned so that slow blocks would raise
difficulty (correctly, they lower it), and one test used `expected + 1` as an
"impossible" difficulty — under the fixed rule that is the legitimate next
value at that spacing.

## Red-team pass: consensus and ledger defects

A later adversarial pass (`crates/jnt-core/tests/redteam.rs`, written
attack-first and each confirmed to fail against the pre-fix code) found six
more defects, all in the state layer. None of them were visible to the
arithmetic audit above, and none touched hashing, the puzzle, the retarget or
the serialization layout — every vector file is byte-identical after these
fixes, which is the point.

**Fork choice was not deterministic.** The final tie-break in `best_candidate`
was an arrival counter, so two nodes holding the same set of valid blocks could
and did select different tips — the test builds two rival blocks at equal height
and equal work and shows node A choosing one and node B the other, purely from
delivery order. The module doc claimed "two nodes holding the same set of valid
blocks always agree on the tip"; that was false. The tie-break is now the block
hash, so every comparison is a function of the block graph alone. `first_seen`
and `seen_counter` are gone.

**The finality rule only guarded against reorgs that shortened the chain.**
`adopt` refused when `common <= finalized && self.canon.len() > new_canon.len()`.
The length qualification meant a rival forking *below* the finality point but
ending up *longer* sailed through and rewrote settled history. The existing test
only exercised the shrinking case, which is why it stayed green. The condition
is now on the fork point alone.

**`apply_tx` was not atomic.** Inputs were removed from the UTXO map one at a
time, so a transaction whose *second* input did not exist had already taken the
first one when the `Err` fired — and the `Err` discarded the undo record that
could have restored it. One malformed transaction destroyed coins. All inputs
are now resolved against a read-only view before anything is written.

**A block that could never be applied was still counted as fork-choice work.**
`submit_at` inserted into the block store before applying and never removed on
failure, while `cumulative_work` summed the declared difficulty of everything
stored. An attacker could therefore accumulate chain weight that no
reorganization could realize: fork choice kept selecting the dead branch and
every honest block was rejected until honest work caught up, with the store
growing without bound. A state-invalid block is now dropped on submit. The one
exception is `ReorgWouldCrossFinality`, where the block is valid and dropping it
would orphan its descendants — the first attempt at this fix broke exactly that
case and the existing test caught it.

**`apply_block` could leave the ledger modified by a rejected block.** It wrote
to the UTXO set transaction by transaction, so a failure partway through left
earlier transactions applied. The reorganization path happened to be shielded by
its snapshot, which is why a first attempt to exploit it appeared to fail; the
direct-extension path was not, and would have been if fork choice had ever
routed a tip-extending block there. Writes are now recorded and unwound on any
failure, so no snapshot is needed and the happy path stays O(1) in UTXO size.

**The chain halted permanently once the reward ladder ran out.** `apply_block`
rejected a zero-value coinbase unconditionally, but SPEC.md §7 says the coinbase
collects the tips only and tips are legitimately zero on an empty block. Every
such block was refused, so the chain stopped dead at a fixed, known height
(mainnet `8 x 262 800`). The zero-value check is gone; a zero-value coinbase is
simply not recorded in the UTXO set, since `check_tx` already refuses to spend a
zero-value output and recording it would only grow the set with unspendable
entries. `rollback_block` now identifies the coinbase output directly instead of
inferring it from its position at the end of the undo list, which stopped being
reliable once that position became conditional.

Smaller items from the same pass:

- `header.sig_scheme` was committed to by the block hash and read by nothing.
  SPEC.md §1 requires nodes to reject unknown values; a block declaring scheme
  200 was accepted.
- The `tx` and `block` deserializers bounded declared counts by the raw
  remaining byte count rather than the smallest entry that could follow, so a
  4 MB block could declare ~4 000 000 inputs and force a `Vec<Input>` reservation
  many times the size of the bytes describing it.
- `Block::total_gas_used` used `.sum()`, which panics on overflow in debug and
  wraps in release, and feeds both the base-fee schedule and the gas cap. Now
  checked; the one caller on a display path falls back rather than panicking.
- `Wallet::build_tx` accepted a `fee` argument and then discarded it
  (`let _ = fee;`). It now enforces that `sum(outputs) + fee` is representable,
  and the doc says plainly that change is the caller's job because resolving
  input values needs the UTXO set.
- `halvings()` and `expected_epoch()` truncated a `u64` quotient with `as u32`.
  Clamped instead. `apply_block` also now refuses heights past `u32::MAX`, where
  the coinbase's `u32` height index stops being injective.

**A branch that forked below the finality point no longer wedges the node.**
Earlier sessions recorded this as an open design question rather than a bug: a
valid branch heavier than the tip but forking below `finality_depth` was
retained, its work was counted, fork choice kept selecting it, and the node
refused honest blocks until honest work caught up. A peer could therefore stall a
node's progress at no cost to itself.

SPEC.md §13.10 item 2 settles it, and side-branch pruning is now implemented:
every non-canonical block at or below `tip − finality_depth` is dropped, along
with any stored descendant of a dropped block. Forgetting such a branch is what
lets the node accept honest blocks again. **§9.3 is unchanged** — a reorg whose
fork point is at or below the finality height is still refused with
`ReorgWouldCrossFinality`; `reorg_cannot_rewrite_finalized_history` and
`a_longer_branch_cannot_rewrite_finalized_history` both still pass. What changed
is only how long the node remembers a branch it was never going to follow.

Canonical history is still retained in full, because undo records,
`verify_canonical_chain` and the persistence layer all replay from genesis.

## A claim that did not survive measurement

An earlier design document reported a 40% attacker with a two-hour
future-timestamp allowance reaching ~104s average block time, and presented
that as the reason for tightening the limit to one block time. That document is
no longer in this repository; the claim is recorded here because it shaped a
consensus rule and because it does not hold.

The figure is **not reproducible** and cannot be: 104s is below the solve-time
clamp floor (T/4 = 150s), so no retarget can ask for a difficulty that low. The
simulation's `--ablation` mode strips the clamp and the difficulty floor and
still does not land on 104s — it drives difficulty to zero — so the original
table came from some further difference in its model that is not recoverable.

What *is* established: under this specification, block time stays within ~1% of
target across every allowance from one minute to two hours. The short allowance
is retained anyway as defence in depth, since it bounds how far ahead a single
block can be stamped, which matters once an attacker reaches 50% and can move
the median itself. SPEC.md §6.1 states this accurately rather than repeating the
original number.

The ablation table has a caveat worth knowing when reading it: any variant that
never recovers ends up pinned on the difficulty floor, so rows matching the
full-spec row may be there for that trivial reason. Raise `--start-difficulty`
to separate them.

## P2P defects found and fixed

Every other `jnt-net` test drove `SyncManager` directly, so the event loop, the
peer threads and the sync continuation were untested. Driving them from a real
socket found all of the following.

- **Sync stopped after one batch.** §13.7 requires the requester to `GETDATA`
  "in batches of 16, submit each, **and repeats**". `handle_inv` returned the
  first 16 entries of an `INV` and discarded the rest — and worse, marked them
  all as requested, so they were poisoned as well as lost. A node more than 16
  blocks behind could never finish syncing. Now every advertised hash is queued
  (bounded), and each applied block frees a slot for the next batch.
- **A peer could stall sync by disconnecting.** Requested hashes were tracked in
  a set with no owner and no release path, so a peer that hung up mid-sync left
  its hashes marked as requested forever. Requests are now tracked per peer and
  released on disconnect.
- **The `requested` set grew without bound.** §13.11 invariant 6 says no
  structure may grow past its §13.8 bound; a peer advertising hashes it never
  delivered grew this set forever. It is now capped, and a bounded pending queue
  holds what is advertised-but-not-yet-requested.
- **`max_peers` was never enforced.** §13.8 bounds it as the cap on thread and
  descriptor count, and only `max_inbound` was checked, on the accept path only.
  Outbound dials are now refused at the limit, and the total is checked on accept
  too.
- **Every inbound connection failed on Windows.** An accepted socket inherits
  the listener's non-blocking flag on Windows, so the blocking, timeout-based
  handshake returned `WouldBlock` immediately and the peer was dropped. The flag
  is now cleared explicitly on accept. This is why the end-to-end test is worth
  having: every prior test used a plain blocking listener and passed.
- **`stop()` did not disconnect.** It set a flag; the reader thread stayed parked
  in `read_frame` for up to 60 s, still holding a thread and still able to emit
  events for a peer the node believed it had dropped — including a peer banned for
  a framing violation. The socket is now shut down, and an oversized frame or
  post-handshake bad magic scores the immediate `+100` that §13.9 already promised.
- **The handshake nonce was the wall clock.** Deriving it from
  `SystemTime::now()` made the "proof of socket possession" challenge guessable
  from block timestamps. It now mixes a `RandomState` key (OS-seeded) with a
  counter.
- **Exceeding an inbound bound disconnected instead of banning**, contrary to
  §13.8. There is now a bounded, address-keyed score table with the §13.9
  one-per-hour decay.
- **The locator could exceed `max_locator_len`.** Genesis was appended on top of
  an already-full locator, making 501 entries. The slot is now reserved.
- **`jnt-node serve` lost everything it synced.** It persisted only on its own
  mining path, so blocks that arrived from peers were never written and a restart
  replayed genesis and discarded the entire sync. It also looped with no delay,
  pegging a core on mining and O(n) JSON writes. Both fixed; `--interval`
  controls the loop period.
- **`verify` could not see M1 bugs.** `verify_canonical_chain` compared the UTXO
  set only, so a wrong PSCB unwind was invisible to the node's own checker. It now
  re-derives the reserve and its undo records by replay.

## Not done

- **Layer 2 / Verified Work Certificates.** The core of the project's premise.
- **P2P gaps.** Block relay works (verified end to end over real sockets, and
  between two `serve` processes). A bounded, attack-tested mempool now exists,
  but nothing feeds it and nothing reads it: pulling it when building a block and
  relaying transactions over the wire (§13.13) are both still missing, as are
  peer discovery (§13.6 by design — address book only), headers-first sync and
  compact blocks. Real `blst` BLS verification (M5).
- **Persisted UTXO indexing.** State is replayed from genesis on load, which is
  fine at test scale and will not be at 40M coins. `serve` also rewrites
  `blocks.json` in full whenever the chain changes (SPEC.md §13.10 item 4).
- **M2–M5 are not wired into consensus.** See the table above and SPEC.md §14.
- **No fuzzing with a coverage-guided harness** (`cargo-fuzz`/`arbitrary`),
  which is what would really exercise the parsers. In its place are
  deterministic property tests: arbitrary bytes through every deserializer,
  every truncation of a valid block, count fields claiming more entries than
  the buffer holds, wire round-trip stability, output-encoding injectivity, and
  `undo_tx` proven an exact inverse over a 64-step spend sequence. Each was
  checked to fail when the property it names is broken. The red-team suite in
  `crates/jnt-core/tests/redteam.rs` is the same idea applied to consensus and
  ledger invariants rather than parsers.
- Vector coverage is finite by construction. The crosscheck exercises seven
  header/epoch combinations; it does not cover every field permutation, and a
  Rust-only bug outside those cases would not be caught by it.
- **No release or tagging process**, and no coverage report in CI.

## Known rough edges

- `--amount` on `send` is denominated in satoshis while every other printed
  figure is in JNT. This bit me during verification and is documented in the
  command's error message, but it should probably gain a unit suffix.

## Reproducing the difficulty work

```
cargo test --workspace                                 # 139 tests
cargo test -p jnt-core --test redteam                   # red-team regression suite
cargo clippy --workspace --all-targets -- -D warnings # clean
cargo fmt --all --check                               # clean
python sim/difficulty_attack_sim.py                     # attack containment
python sim/difficulty_attack_sim.py --ablation \
    --start-difficulty 100000                           # which rule is load-bearing
python sim/supply_schedule_sim.py                       # supply vectors
python sim/puzzle_crosscheck.py                         # Rust vs independent Python
python sim/verify_vectors.py --check                    # all four vector files

# Regenerate vectors (puzzle/difficulty/ser digests must come from Rust;
# supply is arithmetic and is done in Python):
python sim/verify_vectors.py
UPDATE_PUZZLE_VECTORS=1 cargo test -p jnt-core --lib puzzle_vectors_are_stable
UPDATE_DIFFICULTY_VECTORS=1 cargo test -p jnt-core --lib difficulty_vectors_are_stable
UPDATE_SER_VECTORS=1 cargo test -p jnt-core --lib serialization_vectors_are_stable
```

A second implementation that disagrees with these vectors has a consensus split,
not a rounding difference.

## Resolved design decisions

These four were open questions blocking L2. They are now decided, so they are
recorded here rather than left as a list of things nobody has answered.

**D1 / D4 — Who are the validators?** The M5 BLS validator set **is** the L2
dispute-arbitrator set. One set, one epoch, one governance system; designing a
second would have been the more expensive mistake. Validator entry is
permissionless by staking a minimum JNT amount, and the active set is the top 21
stakers per epoch. Genesis is bootstrapped by founder nodes, since there is no
stake to rank before any exists.

**D2 — How does M3 re-execution work during a dispute?** A CPU-only reference
execution path for the ComputeIR. It must be bit-identical to the GPU path for
the same input, which is tractable precisely because M3 already forbids floating
point: the IR is integer-only, so "GPU" and "CPU" are two readers of the same
bytes. Validators run the CPU path during arbitration and therefore need no GPU.

**D3 — Gas schedule for L2 transactions.** Flat per type, not per-byte, so a
worker's cost is knowable in advance:

| Transaction | Fee (sat) |
|---|---:|
| `TxPostTask` | 5 000 |
| `TxClaimTask` | 2 000 |
| `TxSubmitResult` | 2 000 |
| `TxDispute` | 10 000 |
| `TxSettle` | 20 000 |

Recorded in `params.rs` as `FEE_TX_POST_TASK_SAT`, `FEE_TX_CLAIM_TASK_SAT`,
`FEE_TX_SUBMIT_RESULT_SAT`, `FEE_TX_DISPUTE_SAT` and `FEE_TX_SETTLE_SAT`, with
`L2_FEE_SCHEDULE` holding the exact set so a test can pin it.

**Open interaction, deliberately left visible.** Nothing consumes these yet — the
L2 transaction types do not exist — and they do not clear the fee floor the node
actually enforces. The only fee rule today is `base_fee * gas_used`, and even the
smallest transaction burns `GAS_TX_BASE` (16 000) gas, so the cheapest possible
floor for a *single* L2 transaction is orders of magnitude above a 20 000 sat
settle fee. Wiring these in as-is would have `check_tx` reject every one of them
as underpaid. L2 therefore needs either its own fee path or an explicit exemption
from the gas floor; the test `l2_flat_fees_sit_below_the_gas_floor` fails the day
that is settled, so the question cannot be forgotten.

## The L2 fee path — analysis, not yet a decision

D3's flat fees are orders of magnitude below the floor the node enforces today
(`base_fee * gas_used`, and even the smallest transaction burns `GAS_TX_BASE` =
16 000 gas). Wiring them in as-is would have `check_tx` reject every L2
transaction as underpaid. The inspector's finding is confirmed against the code,
and the options are these:

1. **Raise the flat fees above the floor.** Simplest and wrong: it makes an L2
   task post cost more than a JNT transfer, which contradicts the reason D3 chose
   flat fees at all.
2. **Exempt the five L2 types from the gas floor.** Rejected as stated: an
   exemption is a second fee rule, and one written as an exception is the easiest
   kind to widen later by accident.
3. **Give the L2 types their own fee schedule, and split the flat fee the same
   way the base fee is split.** `split_fees` currently derives `full_base` from
   `base_fee * total_gas`; for an L2 transaction `full_base` would be the flat fee
   itself, so the M1 50/50 burn/PSCB invariant holds unchanged and no rule is
   weakened — the transaction simply has a different price. **This is the
   recommended option**: it reuses the existing split rather than bypassing it,
   keeps one invariant for both fee kinds, and leaves the L1 floor untouched.
4. **A separate L2 fee market with its own base fee.** Rejected for now:
   two congestion controllers is a large amount of new mechanism for five
   transaction types, and it can be introduced later without breaking option 3.

**Not decided, and deliberately not implemented.** This needs writing into
SPEC.md before any L2 transaction type is coded, and it needs the user's sign-off
because it changes what a JNT price *means* for L2 work. The test
`l2_flat_fees_sit_below_the_gas_floor` fails the moment the gap closes, so the
question cannot be silently settled by a later commit.

## Build order

1. Mempool (`jnt-core/src/mempool.rs`) — **done**, and wired into L1 (Step 1A)
2. Transaction relay over P2P (`jnt-net`) — **done**
3. Persistent storage (`jnt-store/`)
4. Real BLS pairing — replace `MockBls` with `blst`
5. `cargo-fuzz` harness
6. L2 (`jnt-l2/`) — only after 1–4

Each step uses the red-team discipline from session 1: write the attack, confirm
it fails against the current code, then fix the cause.

---

## Step 2 — transaction relay: implemented

Turns the mempool from a module nothing feeds into one that is fed by the network.
**No consensus rule changed.** A transaction arriving over the wire is admitted by
the same `check_tx` against the same state as one built locally, and nothing in
relay can reach `Chain::submit`: a relayed transaction becomes consensus-relevant
only inside a block, which is validated exactly as before.

SPEC.md §13.14 is new and normative; §13.5 gained `msg_type = 10` (`TX`, additive
under the existing freeze rule) and `kind = 0` in `INV`/`GETDATA` stopped being
reserved and started being used. §13.8 gained `tx_request_timeout`.

| Piece | Where |
|---|---|
| `MessageType::Tx = 10`, `INV_TYPE_TX = 0`, bounded `Message::Tx` | `jnt-net/src/msg.rs` |
| Relay bookkeeping: requests, pending, known set, rate window, expiry | `jnt-net/src/relay.rs` |
| Announce / request / serve / admit / ban, peer registration | `jnt-net/src/net.rs`, `peer.rs` |
| Mine from the pool, unconditional reconcile, relay counters | `jnt-node/src/main.rs` |
| Wallet → node: `send --relay <addr>` | `jnt-node/src/main.rs` |
| Follower node: `serve --no-mine` | `jnt-node/src/main.rs` |

### Bugs found and fixed

Two real defects, each proven by re-running the test against the old code.

1. **A banned peer was never released from the live set.** `stop()` shuts the
   socket down, but the reader thread parked in a blocking read does not reliably
   wake for that — on Windows it demonstrably did not: a peer banned for ten
   invalid transactions stayed in the peer table for over a second of polling and
   its reader only returned at teardown. Until then the node believed it had a
   peer it had already banned: the slot counted against `max_peers`, broadcasts
   still queued for it, and nothing released the sync or relay state it owed.
   Fixed by releasing stopped peers in `poll_events` rather than waiting for the
   reader. **Red step:** with the sweep neutralised, only
   `repeated_invalid_transactions_get_the_peer_banned` fails.
2. **The submission path silently lost a transaction.** The first fix swept for
   stopped peers using the `stopped` flag — but the reader thread set that same
   flag whenever a stream ended, so a peer closing cleanly looked identical to a
   peer being banned and the sweep discarded its last messages. A wallet that
   connects, submits one transaction and hangs up (which is what
   `send --relay` does) had its transaction read, decoded, queued and then
   dropped, with `accepted 0 refused 0` — nothing observable anywhere. Fixed by
   giving the reader its own flag and making the release rule "stopped **and** the
   reader has not reported yet". **Red step:** with the guard removed,
   `a_one_shot_submitter_is_served_and_then_let_go` fails with that exact symptom.

A third defect was closed by design rather than by a failing test: the in-flight
request set was global and unbounded in time, so a peer could announce
`max_relay_in_flight` transactions, deliver none, and stop the node requesting
from *every* peer for as long as it stayed connected. Requests now expire after
`tx_request_timeout`, and a request that expires is retried against whoever
announces the txid next.

### Tests

- `crates/jnt-net/tests/tx_relay.rs` — 10 real-socket tests against a hand-rolled
  peer, not our own client: the whole path (pool → `INV` → `GETDATA` → `TX` →
  peer pool → mined → block back → eviction on both nodes); announce/request/serve
  round trip; forbidden signature; repeated invalid transactions reaching the ban
  threshold; duplicate announcement pooled once and not punished; conflicting
  spend refused without a ban; oversized transaction refused by the pool;
  repeated announcement drawing one request; unanswered request expiring;
  one-shot submitter served and released.
- `crates/jnt-net/src/relay.rs` — 11 unit tests for the bookkeeping, including the
  stall scenario and both response budgets.
- `tests/vectors/net_vectors.json` regenerated with `TX` and `kind = 0` bytes, plus
  the five new §13.14 bounds; `sim/net_reference.py` re-derives all of them from
  the §13 prose and now agrees on 32 values. **It caught an arithmetic error in
  the vector generator** (`inv_tx_len` typed as `4 + 1 + 32` when `INV`'s count is
  `u16`) — the kind of mistake a self-consistent encoder cannot find.

### Verified end-to-end with two real processes

`serve --listen` on node A (mining), `serve --connect ... --no-mine` on node B,
then `send --relay` from a third process:

```
relay          accepted 1 refused 0 (pool holds 1)
B chain: block 75 holds 2 txs, outputs [1000000000, 6599824000]
B balance: 8d0e399eaf9cb1f3:0  10.00000000 JNT  height 75  spendable
```

The wallet's signed transaction crossed a real handshake and a real TCP link into
A's pool, was mined at height 75, reached B by block relay, and B reports the
output as spendable. Exactly one block on B's chain contains it.

### Limitations

- **No acknowledgement.** A `TX` is silent: the sender learns that a node *took*
  the frame, not that the pool accepted it. `send --relay` says so instead of
  implying success, and the receiving node's `relay accepted/refused` line is the
  actual evidence.
- The pool is still in-memory only, so a node that restarts drops everything it
  held and never re-requests it. That is step 3's problem, and it is why the
  ordering is storage before relay hardening rather than the reverse.
- Relay is not part of the §13.11 invariant list yet; the next revision should add
  "a relayed transaction is validated exactly as a local one" explicitly.
- `INV` announcements are sent only for the first `max_inv_per_msg` pool entries
  on connect, so a pool larger than 500 entries is not fully announced to a new
  peer. Bounded and honest, but incomplete.

## Step 3 — Persistent storage (crates/jnt-store): DONE

The node no longer rewrites the whole chain as JSON. `crates/jnt-store` is an
append-only, checksummed block log plus atomic metadata, and `jnt-node` uses it
for every command.

### Design (no consensus rules live here)

- One log file (`store/blocks.log`): magic `JNTS`, version 1, then records of
  `len(4 LE) ‖ digest(4, first bytes of SHA256(payload)) ‖ payload`. Every
  record is tagged (`0x00` block, `0x01` UTXO snapshot) — the tag byte exists
  because a block's first serialized byte is its version (1), which is
  byte-identical to a naive "no tag needed for blocks" scheme.
- No index file: the hash index is rebuilt by scanning at open, so the only
  copy of the data is the data. A corrupted index is a failure mode that does
  not exist.
- Canonical chain = one metadata row (network, genesis, tip, height), replaced
  atomically (write-beside, rename). A reorg moves that row and nothing else.
- Torn tail (crash mid-append) is dropped and REPORTED. Damage with committed
  data after it refuses to open with the byte offset. The distinction matters:
  one is survivable by construction, the other must never be silently
  truncated into a shorter chain.

### Bugs found during this step (all caught by the crate's own tests)

1. Untagged block records collided with UTXO-snapshot records (block version
   byte == snapshot tag) — blocks vanished from the index. Fixed with an
   explicit tag on every record.
2. `set_tip` recorded genesis's height (0) instead of the tip's, because the
   ancestry walk is tip-first and the code read the last entry.
3. The metadata parser read the checksum line after the hex-digest line, but
   the file's trailing newline made it read an empty string.
4. The height walk omitted genesis at height 0, so every reopen reported
   `MissingParent` on the genesis block itself.
5. A file shorter than one header underflowed `file_len - pos` in the log scan
   (check_header may extend the file; the scan's length was stale).

### Verified

- 30 store tests: round-trip, duplicate, side branch, reorg + restart, orphan
  survival, unprovable tip refused with metadata untouched, foreign network
  refused, metadata lost -> honest genesis fallback, torn tail, damaged
  mid-chain record refused, UTXO snapshot tagging.
- End to end with the real binary: init -> mine -> restart -> verify; a legacy
  `blocks.json` chain migrated into the store on first open and verified after;
  two-node serve where B force-killed (`taskkill /F`, no flush) at height 35
  restarted twice, mined to 58, and replays cleanly every time.
- `verify` re-validates every stored block through `Chain::submit`, so a store
  bug cannot hand the chain a bad block silently.
- 293 workspace tests (up from 263), fmt/clippy (`-D warnings`)/release clean,
  all five sims green.

### Limitations

- UTXO persistence is sketched (tagged snapshot records) but the node does not
  yet write snapshots; `load_chain` still replays from genesis. Correct, but
  O(chain) at startup — the snapshot path lands with the next step.
- Mempool is still memory-only across restarts (unchanged from step 2).

## Step 4 — Real BLS verification (blst): crypto core DONE, gadget NOT active

SPEC.md gained §14.5, normative for real-BLS builds: min-pk BLS12-381 (keys
G1/48B, signatures G2/96B), DST `JNT_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`,
IETF KeyGen derivation for deterministic fixtures, validator-set identity
`sha256_dom([0xB2], [n ‖ sorted keys])`, bitmap padding bits declared
malformed, replay ruled out by construction, and set rotation explicitly
deferred to §14.6 (unresolved: D1 economics).

`crates/jnt-core/src/bls.rs` adds `SecretKey::derive`, `sign`, `RealBls`
(single verify, aggregate, fast-aggregate verify), `validator_set_hash`, and
point validation that rejects infinity/non-subgroup/garbage keys and
signatures without panicking. `bls_checkpoint::verify_checkpoint` now runs
real pairing checks when handed `RealBls`; `MockBls` remains only for
structural unit tests, and a test pins that a forgery MockBls accepts RealBls
rejects.

**No consensus change.** `Chain::submit` does not consult any `BlsVerifier`;
M5 remains inactive; §14.6 (who validators are, rotation, checkpoint entry
into blocks) is the documented blocker. Nothing here was activated silently.

Bugs found: `validator_set_hash` initially hashed caller order rather than
`ValidatorSet` sorted order — two views of the same committee would compute
two identities (caught by the order-insensitivity test). The committed key
fixture caught that I cannot predict derived keys by hand; the real
SEED_A value is now the test's constant. 18 adversarial checkpoint tests
(quorum boundary, bitmap padding/junk/lying count, wrong-set, tampered
payload/hash/network, zero sig, poisoned key set, replay, finality
monotonicity) all pass against RealBls.

341 workspace tests (was 293). fmt/clippy -D warnings/release clean; five
sims green.

## Step 5 — Validator-set machinery (§14.6): library DONE, activation deferred

SPEC.md §14.6 is written as **DESIGN ONLY**: the complete deterministic
machinery (identity, epoch-bound set hash, seed-block derivation, rotation,
six-clause checkpoint validation) is specified and implemented as a pure
library in `validators.rs` — with five economics questions explicitly listed
as open and reserved for the protocol owner (minimum stake, selection rule
beyond the TopN default, rewards, slashing amounts, activation timing).

`Chain::submit` does not reference `validators.rs` (grep-verified); no
consensus rule changed; no monetary rule changed.

Attack tests (21): deterministic derivation + key-first canonical ordering
(stake changes cannot reshuffle bitmap bits mid-epoch); TopN selection with
deterministic tie-breaks; duplicate key refused (a two-slot key could double
quorum weight); duplicate address refused; invalid key refused-not-skipped;
set hash binds the epoch (identical membership in two epochs → different
hashes) and the addr↔pk binding (moving a key to a new address changes the
identity); every one of the six checkpoint clauses named on failure; rotation
verifies each epoch's checkpoints against that epoch's own derivation; cache
grace-period behavior; equivocation evidence exposed as data (punishment is
an open economics item).

347 workspace tests (was 341). fmt/clippy -D warnings/release clean; five
sims green.
