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
| M5 | Sovereign BLS aggregate finality gadget checkpoints | No — `BlsVerifier` is a mock | `bls_checkpoint.rs` |

SPEC.md §14 carries the same table and says why each of M2–M5 is inactive: each
needs a rule this repository has not specified (what proves a compute result
fraudulent, how a task enters a block, whether the HBM puzzle replaces or
composes with the §5 puzzle, who the validator set is). M2 and M4 would change
consensus, so guessing those rules in code would have been the wrong order.

## Verified

- `cargo test --workspace` — 219 tests pass:
  - 179 unit tests in `jnt-core` (including M1–M5 test suites)
  - 11 red-team integration tests in `crates/jnt-core/tests/redteam.rs`
  - 15 unit tests in `jnt-net` (framing, codecs, sync continuation, bounds)
  - 12 integration tests in `crates/jnt-net/tests/integration.rs`, including a
    real-socket end-to-end sync between two `P2pNode`s
  - 2 wire-vector tests in `crates/jnt-net/tests/net_vectors.rs`
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
  profiles, locator construction. It has no independent implementation yet, the
  way `sim/jounit_reference.py` re-derives §5; that check is still owed.
- Node CLI end to end on the `mini` profile: init, mine 31 blocks, spend, verify
  (replays from genesis and diffs UTXO + supply), status. Fee burn reconciles
  exactly — 31 blocks issue 2356 JNT, live supply is 2355.99825 JNT, the
  0.00175 JNT difference being the destroyed base fee.
- Supply schedule matches design doc §16, including that only 298 000 of the
  304 000 JNT mini cap is reachable and the remainder is permanently
  unmintable rather than merely reserved.

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
  between two `serve` processes). Still missing: peer discovery (§13.6 by
  design — address book only), transaction relay and any mempool (§13.13),
  headers-first sync, compact blocks. Real `blst` BLS verification (M5).
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
