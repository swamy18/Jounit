# Working memory — red-team audit of `jnt-core`

**Date:** 2026-10-05
**Branch:** `main` (clean at start, 13 commits, working tree was clean)
**Scope:** full adversarial audit of the Jounit L1 core + node CLI against `SPEC.md`
**Outcome:** 11 defects found and fixed (6 consensus/ledger, 5 smaller). 139 tests pass. Nothing committed.

---

## 1. What this session was

The user asked for an autonomous red-team pass: find bugs, problems and security
threats, and fix everything, without further input. I audited every source file
in `jnt-core` (7,431 lines) plus the node CLI, wrote attack-first regression
tests, **confirmed each one failed against the original code**, then fixed the
cause and re-verified.

---

## 2. The method that worked

The core discipline was **red before green**:

1. Read `SPEC.md` end to end first to learn the *intended* invariants, rather than
   inferring intent from the code.
2. Read all 15 source modules looking for divergences between spec and code.
3. For each suspected bug, wrote the attack first and ran it against the
   **unmodified** code.
4. Only then wrote the fix.
5. Re-ran the *entire* suite, not just the new test.

Step 3 is what made the findings trustworthy. Two bugs I was confident about in
reading turned out to be wrong in detail, and only running the exploit showed it
(see §7 — Mistakes I made).

**Baseline before starting:** 130 unit tests passing, clippy clean, vectors green.

---

## 3. Critical bugs found and fixed

### 3.1 Fork choice was not deterministic — `chain.rs`

**Found:** `best_candidate()` tie-broke on `first_seen`, an arrival counter.

```rust
// before
let seen = self.first_seen.get(hash).copied().unwrap_or(u64::MAX);
let key = (work, std::cmp::Reverse(block.header.height), seen);
```

Two nodes holding an **identical set of valid blocks** could therefore select
different tips. The module doc explicitly claimed "two nodes holding the same set
of valid blocks always agree on the tip" — that claim was false.

**Proof:** `fork_choice_is_independent_of_block_arrival_order` builds two rival
blocks at equal height and equal work, submits them to two nodes in opposite
order, and shows different tips. Failed on original code with two completely
different hashes.

**Fix:** removed `first_seen` and `seen_counter` entirely. Every tie-break is now
a function of the block graph alone:

```rust
fn fork_choice_key(&self, hash: &Hash) -> (u128, Reverse<u64>, Reverse<Hash>) {
    let work = self.cumulative_work(hash);
    let height = self.blocks.get(hash).map(|b| b.header.height).unwrap_or(0);
    (work, Reverse(height), Reverse(*hash))
}
```

Simplification bonus: the `candidates.sort_by` + `debug_assert` scaffolding went
away too, because the comparison is now total.

---

### 3.2 Finality rule had a hole — `chain.rs`

**Found:** `adopt()` guarded finality with:

```rust
// before
if common <= finalized && self.canon.len() > new_canon.len() {
```

The `self.canon.len() > new_canon.len()` clause meant the rule **only refused
reorgs that shortened the chain**. A rival that forked *below* the finality point
but ended up *longer* sailed straight through and rewrote settled history.

**Why it survived:** the existing test `reorg_cannot_rewrite_finalized_history`
only exercised a rival *shorter* than the tip (20 blocks vs 25). It could not
catch the longer case. Classic gap-in-test-coverage.

**Proof:** `a_longer_branch_cannot_rewrite_finalized_history` — rival shares
heights 1..=3 (fork point 3, finalized height 5), climbs to 40 blocks with rising
difficulty so it genuinely out-weighs the tip. Original code accepted all 37
deliveries and adopted the branch.

**Fix:** condition is on the fork point alone:

```rust
if common <= finalized {
```

---

### 3.3 `apply_tx` was not atomic — `ledger.rs`

**Found:** inputs were removed from the UTXO map one at a time:

```rust
// before
for input in &tx.inputs {
    let u = self.map.remove(&(op.txid, op.index))
        .ok_or(Error::UnknownOutPoint)?;   // <-- inputs already deleted
    undo.spent.push((op, u));
}
```

If input 0 existed and input 1 did not, input 0 was **already deleted** when the
`Err` fired — and the `Err` discarded the `undo` value that could have restored
it. One malformed transaction destroyed coins.

**Proof:** `apply_tx_is_atomic_when_an_input_is_missing`. Failed on original code:
"a failed apply destroyed a live output: 5000000000 sat vanished".

**Fix:** resolve everything against a read-only view, then mutate. Also added
`UtxoSet::undo(&Undo)` as a standalone primitive so a partially-applied *block*
can unwind without needing the transaction that produced the record.

---

### 3.4 Unapplicable blocks still counted as fork-choice work — `chain.rs`

**Found:** `submit_at` inserted into the block store *before* applying, and never
removed on failure. Meanwhile `cumulative_work()` summed the **declared
difficulty of every stored block**:

```rust
fn cumulative_work(&self, hash: &Hash) -> u128 {
    total = total.saturating_add(block.header.difficulty);
    ...
}
```

So an attacker could bank chain weight that no reorganization could ever realize.
Fork choice kept selecting the dead branch; every honest block was rejected until
honest work caught up. Store grew without bound.

**Proof:** `an_unapplicable_block_must_not_be_retained_or_counted_as_work` — a
block with valid PoW and merkle root but a body spending a nonexistent outpoint.
Also asserts the consequence that matters: an honest block on top of the tip is
*still accepted* afterwards. Failed on original code.

**Fix:** drop the block on any error — **except** `ReorgWouldCrossFinality`,
where the block is valid and dropping it would orphan its descendants (see §7).

---

### 3.5 Chain halted forever once the reward ladder ran out — `chain.rs`

**Found:**

```rust
// before
if coinbase.has_zero_value_output() {
    return Err(Error::BadCoinbase("coinbase output must be non-zero"));
}
```

But SPEC.md §7 says when a reward would cross the cap "the coinbase collects the
tips only" — and tips are legitimately zero on an empty block. After the 8th
halving, `reward + tip == 0` for an empty block, so **every such block was
refused**. Mainnet would have stopped dead at height `8 x 262 800 = 2,102,400`.

**Proof:** `a_zero_reward_block_at_the_end_of_the_ladder_is_accepted`, using a
shortened halving period so the ladder is reachable in 20 blocks. Failed on
original: `block 14 was rejected (Some(BadCoinbase("coinbase output must be
non-zero"))) with reward 0`.

**Fix:** removed the check. A zero-value coinbase is simply not recorded in the
UTXO set, since `check_tx` already refuses to spend a zero-value output —
recording it would only grow the set with permanently unspendable entries.

**Knock-on fix:** `rollback_block` used to find the coinbase output by taking the
*last* entry of `undo.created` (`iter().rev().take(1)`). That position became
conditional once zero-value coinbases stopped being recorded, so it now
identifies the coinbase outpoint directly. More robust regardless — it no longer
depends on insertion order.

---

### 3.6 `apply_block` was not atomic — `chain.rs`

**Found:** it wrote to the UTXO set transaction by transaction, so a failure
partway through left earlier transactions applied.

**Important nuance:** the reorg path took a full snapshot before applying, so a
first exploit attempt *passed*. The direct-extension path in `submit_at` had no
such protection. So the defect was real but narrower than it first looked: the
invariant was unenforced and one path unprotected, rather than freely exploitable
as written.

**Fix:** extracted `apply_body()` and record every write:

```rust
let mut applied: Vec<Undo> = Vec::new();
let split = match self.apply_body(/* ... */) {
    Ok(split) => split,
    Err(e) => {
        for u in applied.iter().rev() { self.utxo.undo(u); }
        return Err(e);
    }
};
```

with the same unwind on the over-claim and supply-cap paths.

**Design note:** I deliberately did *not* use `snapshot()`/`restore()` here. That
would clone the entire UTXO set on every single block application, turning the
happy path into O(n). Unwinding is O(transactions actually applied).

---

## 4. Smaller defects found and fixed

| # | File | Defect | Fix |
|---|---|---|---|
| 1 | `chain.rs` | `header.sig_scheme` was committed to by the block hash and read by **nothing**. SPEC.md §1 requires rejecting unknown values; a block declaring scheme 200 was accepted. | Validate in `validate_standalone`, returning `Error::UnsupportedSigScheme` |
| 2 | `tx.rs`, `block.rs` | Count fields bounded by **raw remaining bytes** rather than smallest-entry size. A 4 MB block could declare ~4,000,000 inputs and force a `Vec<Input>` reservation many times larger than the bytes describing it. | Added `INPUT_MIN_SERIALIZED_LEN` (38) and `TX_MIN_SERIALIZED_LEN` (21); bound by `remaining / MIN` |
| 3 | `block.rs` | `total_gas_used()` used `.sum()` — panics on overflow in debug, wraps in release — and feeds both the base-fee schedule and the gas cap. | `try_fold` + `checked_add`, returns `Result`. Call sites updated; the one display-path caller falls back rather than panicking |
| 4 | `wallet.rs` | `build_tx(inputs, outputs, fee)` accepted a `fee` argument and discarded it: `let _ = fee;` | Enforces `sum(outputs) + fee` is representable; doc now states plainly that change is the caller's job (resolving inputs needs the UTXO set) |
| 5 | `supply.rs`, `block.rs`, `chain.rs` | `halvings()` and `expected_epoch()` truncated a `u64` quotient with `as u32`. `apply_block` also compared coinbase indices truncated to `u32`. | Clamped instead of truncated; `apply_block` refuses heights past `u32::MAX`, where the encoding stops being injective |

---

## 5. Verification evidence

All with **exit status preserved**, not inferred from a grep filter:

```
cargo fmt --all --check                                    exit 0
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets   exit 0
cargo test --workspace                                     exit 0  (130 unit + 9 red-team)
cargo build --workspace --release                          exit 0
python sim/verify_vectors.py --check                       exit 0
python sim/puzzle_crosscheck.py                            exit 0
python sim/supply_schedule_sim.py                          exit 0
python sim/difficulty_attack_sim.py                        exit 0
```

**The most important result: `tests/vectors/` and `sim/` are byte-identical**
(`git status` clean for both). None of the fixes touched hashing, the PoW
puzzle, the retarget, or serialization layout — so both independent Python
implementations still agree byte-for-byte with Rust. This is what proves the
changes were state-layer only and not consensus-breaking.

**CLI end-to-end** (re-run against the *final* files, not an earlier build):
`init → mine 20 → send → verify → status → balance → export → show-block`, all
exit 0. Supply reconciles exactly: 1596.00000000 JNT issued, 1595.99790000 live,
the 0.0021 difference being the burned base fee.

**No performance regression.** I A/B'd the slowest test
(`tampering_with_a_header_breaks_the_proof_of_work`) against stashed changes:
72.18s after vs 74.14s before — within noise. That test is inherently slow
either way.

---

## 6. The regression suite I added

`crates/jnt-core/tests/redteam.rs` — 637 lines, 9 tests, each written as an
attack and each naming the rule it defends:

| Test | Defends against |
|---|---|
| `a_rejected_block_must_not_leave_utxo_state_behind` | §3.6 |
| `apply_tx_is_atomic_when_an_input_is_missing` | §3.3 |
| `fork_choice_is_independent_of_block_arrival_order` | §3.1 |
| `an_unapplicable_block_must_not_be_retained_or_counted_as_work` | §3.4 |
| `a_longer_branch_cannot_rewrite_finalized_history` | §3.2 |
| `build_tx_does_not_silently_discard_the_fee_it_was_given` | §4.4 |
| `a_zero_reward_block_at_the_end_of_the_ladder_is_accepted` | §3.5 |
| `a_count_field_cannot_reserve_more_than_the_buffer_could_hold` | §4.2 |
| `an_unknown_header_sig_scheme_is_rejected` | §4.1 |

Helper worth noting: `handcraft()` builds a byte-perfect block around an
arbitrary transaction list. `mine_block` refuses to build a body it can't itself
validate, so this is what lets a hostile tx reach `apply_block`. Mini spacing
keeps difficulty pinned at 1, so every hand-built header is free valid PoW —
deliberate, since these tests attack *state* rules.

---

## 7. Mistakes I made — kept because they're the useful part

**A test that passed for the wrong reason.** My headline state-corruption exploit
passed on the original code. I nearly recorded it as "not exploitable". Instead
of accepting that, I printed the rejection reason: `WrongAddress`. My `extend()`
helper mined coinbases to `[1u8; 20]` while the attack tx was signed by a wallet
— so it failed signature verification and never reached the body loop. The test
was green while proving nothing. Fixed the harness; it then failed as predicted.

**A fix that broke an existing test.** My first attempt at §3.4 removed the block
on *every* error, including `ReorgWouldCrossFinality`. That orphaned descendants
already stacked on the refused branch, and the pre-existing test
`reorg_cannot_rewrite_finalized_history` failed. Narrowed to exclude that error.

This is the strongest evidence the existing suite was better than my initial
reading of it — that test existed before my changes and caught my regression.

**Overstating a bug in the docs.** My first write-up of §3.6 claimed it was live
and exploitable. It wasn't — the snapshot covered the path the exploit took. I
corrected the doc comment and `status.md` to describe the narrower truth: the
invariant was unenforced and one path unprotected. Writing the exploit is what
surfaced the difference.

---

## 8. Deliberately NOT fixed

**A valid branch heavier than the tip, forking below `finality_depth`, is
retained and its work *is* counted.** The node declines to reorganize and
therefore cannot accept honest blocks until the situation changes.

This follows directly from treating `finality_depth` as a hard rule: if
finalized history is genuinely immutable, a heavier branch across it *must* be
refused. Whether the node should instead follow the heavier chain, or how long to
remember a branch it will not take, is a **consensus design decision**, not a bug
fix, and I did not want to make that call unilaterally. Documented in
`docs/status.md`; strongest candidate for follow-up work.

---

## 9. Current state of the working tree

```
 M crates/jnt-core/src/block.rs      (+20/-)
 M crates/jnt-core/src/chain.rs      (+285/-)   <- largest change
 M crates/jnt-core/src/ledger.rs
 M crates/jnt-core/src/supply.rs
 M crates/jnt-core/src/tx.rs
 M crates/jnt-core/src/wallet.rs
 M docs/status.md                    (+104)
?? crates/jnt-core/tests/redteam.rs  (new, 637 lines)
```

Total: 7 files modified, 1 added, 371 insertions / 112 deletions. **Nothing is
committed.** `docs/status.md` was updated with the findings and its test counts
corrected from 130 to 139.

---

## 10. Things worth remembering for future work here

- **`adopt()` snapshots the whole UTXO set.** Fine for tests, O(chain length)
  per reorg. Not viable at 40M coins. Incremental undo already exists
  (`Undo`, `UtxoSet::undo`) so the groundwork is there.
- **State is replayed from genesis on every node load** (`load_chain` in the CLI).
  Fine at test scale, not at production scale.
- **No P2P layer.** `submit()` is the entire attack surface today, which is why
  the red-team tests can exercise every state rule directly. Once relay exists,
  these same tests should be driven over a real socket.
- **No coverage-guided fuzzing.** The parsers only have deterministic property
  tests. The attack shapes found here (`crates/jnt-core/tests/redteam.rs`) are
  the obvious seed corpus for a `cargo-fuzz` harness.
- **Vector coverage is finite by construction** — 7 header/epoch combinations. A
  bug outside those cases would not be caught by the crosscheck.