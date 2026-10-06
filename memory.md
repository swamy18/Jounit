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

---

# Working memory — session 2: P2P specification

**Date:** 2026-10-05 (same day, later)
**Branch:** `main`, clean at start. `memory.md` above is session 1; this is a
separate session and nothing from it is committed.
**Scope:** the user asked to begin the P2P / networking layer, which was the
top "not built" item in `README.md` and `docs/status.md`.
**Outcome:** no code written. `SPEC.md` §13 added (+379 lines) specifying the
network layer ahead of implementation. Two latent defects found, one of them
significant. **Nothing committed.**

---

## 11. What this session was

The user picked P2P off the not-built list and said to start. Before writing any
Rust I mapped the API surfaces a network layer would sit on, then asked three
forking questions rather than guessing:

| Decision | Chosen |
|---|---|
| Concurrency | `std::net` + thread per peer — no new dependencies |
| v0.2 scope | **blocks only**; transaction relay deferred |
| Order of work | **spec first**, then implementation |

Writing the spec first was the right call and not only stylistically: it is what
surfaced the genesis-collision finding below, which would otherwise have been
discovered *after* a handshake was implemented and possibly shipped.

## 12. The finding that mattered

**`mainnet` and `mini` produce the identical genesis block.** I verified this by
running both profiles rather than reasoning about it:

```
mainnet genesis: 2317ec84903140e2cd72be6f3c9dfd2ff36d9f8642293a5152279b4ad7a5196b
mini    genesis: 2317ec84903140e2cd72be6f3c9dfd2ff36d9f8642293a5152279b4ad7a5196b
identical: true
```

`genesis_block(difficulty)` (`block.rs:216`) takes only the difficulty, and both
profiles set `genesis_difficulty = 1`. The genesis block has no other
profile-dependent input.

**Severity: latent, not live.** Nothing is broken today. There is no P2P layer,
so nothing compares genesis hashes. The defect is that the *obvious* way to
write network isolation — handshake, compare genesis hashes, as Bitcoin does —
is silently wrong here, and it fails at exactly the moment someone implements it.

No state corruption would follow either. A cross-network block fails §9.1 rule 4
(wrong difficulty for the receiving chain), so the honest outcome is rejection.
The damage is bandwidth waste and, worse, a node that cannot be *trusted* to
reject a foreign peer at all.

**Resolution in the spec:** each profile must declare a distinct `network_magic`
(4 bytes) and `network_id` (string), compared during handshake. The real fix —
deriving the genesis coinbase `extra_nonce` from `network_id`, which would make
the hash discriminating — is recorded in §13.3 as a **consensus-breaking genesis
change** and explicitly out of scope for a networking release.

This is the second time in this repository that a "the obvious approach is wrong
here" property has turned up, after the difficulty retarget, where the textbook
formula (`avg_solve / T`) had no restoring force and was scale-invariant. Both
were invisible until something was measured rather than assumed. I checked this
one empirically instead of assuming the analogy held.

## 13. Second finding: quadratic fork choice, DoS-shaped

`best_candidate` (`chain.rs:486`) iterates every stored block and calls
`cumulative_work` on each, which walks the parent chain to genesis
(`chain.rs:143`). One `submit` is therefore **O(stored²)**. Side branches are
also retained indefinitely, so `stored` only grows.

Also latent: a single node never accumulates enough blocks to feel this. Once
relay exists, a peer submitting blocks converts it into a cheap CPU amplifier —
no expensive work required, since PoW is already validated by then.

**Recorded in §13.10 as blocking, ahead of the wire format:**
1. compute cumulative work incrementally at insert (`parent_work + difficulty`) —
   identical value, no consensus change, since it sums the same path;
2. prune side branches beyond `finality_depth` + orphan pool.

Item 1 alone does not help if item 2 is skipped: `stored` still grows without
bound. Both are marked MUST.

## 14. What §13 specifies

Thirteen subsections. The load-bearing decisions, and why each one:

- **§13.1 — no `Arc<Mutex<Chain>>`.** `submit`, `adopt` and `mine_block` all take
  `&mut self`, and `mine_block` is an unbounded CPU loop. A lock held across it
  stalls every peer thread for the length of a block. One chain thread owns the
  `Chain`; peer threads only frame and bounds-check. This is the constraint that
  decided the concurrency question, established by reading the signatures
  rather than by preference.
- **§13.2 — `payload_len` bounded before allocation.** Same bug class as the
  bundle-length and input-count defects already fixed in §3.1/§3.5. Called out as
  the most important single bound in the section, because the length prefix is
  attacker-controlled.
- **§13.3 — network magic**, above.
- **§13.4 — handshake proves socket possession, nothing more.** The `nonce` echo
  stops a replayed handshake. Explicitly **not** identity or authentication; there
  are no node keys in v0.2, so peer reputation is per-connection and lost on
  reconnect. Stated as a limitation rather than presented as authentication.
- **§13.6 — no discovery protocol.** Address book only. The reasoning is recorded:
  gossiping addresses from peers we cannot authenticate lets one hostile node
  hand us its own connections forever. `ADDR` is specced but MUST NOT populate
  the address book in v0.2.
- **§13.7 — block-first sync, not headers-first.** Justified rather than assumed:
  a block's validity depends on tip history and undo records, so a header-only
  chain buys nothing for a node that validates every block anyway.
- **§13.9 — invalid block is +10, not a ban.** Honest peers collide during reorg
  races; banning there disconnects honest peers exactly when the network is
  busiest. Reaching a *threshold* is what bans. This inverts the reflexive
  "misbehaviour = instant ban" response and I think it is the least obvious call
  in the section.
- **§13.11 — seven invariants**, each phrased as a test. The one that matters
  most: a block accepted via P2P must be byte-identical to the same block
  accepted locally.

## 15. Mistakes I made in this session

Recorded because both were caught by re-reading rather than by a test.

**A contradictory diagram.** My first architecture diagram had a separate
"mining thread" column, directly contradicting the paragraph immediately below it
that said mining shares the chain thread. Also used `select!` syntax — tokio —
in a spec whose concurrency decision was `std::net` + threads. Both would have
read as specifications of two different designs. Caught on re-read; fixed.

**A stale cross-reference.** §13.0 pointed at §13.10 for mempool requirements.
§13.10 is the performance section; mempool is §13.13. Verified all ten §13.x
cross-references resolve to existing headings before finishing.

## 16. Judgement calls worth challenging

Recorded so they can be overruled rather than inherited:

- **Transaction relay left unspecced.** A mempool needs conflict sets, RBF, fee
  estimation and post-reorg re-validation. Writing those rules before any
  implementation existed seemed more likely to constrain the design wrongly than
  to help. Deferred to §13.13 instead of guessed.
- **`handshake_timeout = 20 s` and ban decay of `1`/hour are arbitrary.** Unlike
  `max_frame_bytes` (which follows from `max_block_bytes`), these do not derive
  from any protocol constant. They are defensible defaults, not derived values,
  and the spec does not pretend otherwise.
- **Mining on the chain thread stalls block processing** for the length of a
  block on mainnet. Acceptable now (no mempool to go stale) and named as the
  reason a future mempool must split the two.
- **`docs/status.md` and `README.md` not yet updated** to reflect §13 existing.
  They still describe P2P as wholly absent, which is now only half true: specced,
  still unimplemented.

## 17. Next steps, in order

1. Fix §13.10 item 1 (incremental work). Item 2 (pruning) is bundled with the
   persistence rewrite: pruning below `finality_depth` changes which side forks
   a node retains-and-counts, which is the exact finality-wedge behaviour session
   1 deliberately left unresolved, so it must be a conscious decision, not a
   mechanical refactor.
2. Persistence rewrite: `Store::save_chain` rewrites every block per mined block
3. `jnt-net` crate: framing, handshake, bounds (§13.2/§13.4/§13.5/§13.8) — see §18
4. Sync loop over `validate_standalone` + `submit` — §13.7
5. Red-team suite in the existing attack-first style, plus the §13.11 invariants
6. Update `docs/status.md` and `README.md` for §13

`memory.md` §10 already noted that the existing red-team tests should eventually
be driven over a real socket; step 5 is that work, and the same tests apply.

---

## Unrelated, noticed but not touched

**`chain.rs:5` module doc is stale.** It still describes the fork-choice
tie-break as "first-seen order" — the arrival-counter bug fixed in session 1. The
code is correct (`fork_choice_key` uses `(work, lower height, lowest hash)`), only
the doc comment is wrong. Left alone as out of scope, but it is a comment that
actively misdescribes a consensus rule, which is worse than no comment.

---

# Working memory — session 3: scaffolding `jnt-net`

**Date:** 2026-10-05
**Branch:** `main`, clean at start. `SPEC.md` and `params.rs` carry session 2's
changes; this session builds the first implementation slice from §13.
**Scope:** `jnt-core` perf fix + the `jnt-net` crate foundation — framing, wire
codec, network identity.
**Outcome:** `jnt-core` O(N²) fork choice removed. `jnt-net` crate created with
frame codec + message codec + identity checks, 10 passing tests + doctests.
Nothing committed. `cargo test --workspace`: 139 core + 10 net pass.

---

## 18. What this session did

### 18.1 `jnt-core` — incremental cumulative work (§13.10 item 1, blocking)

`best_candidate` (`chain.rs:486`) called `cumulative_work` per stored block, and
`cumulative_work` walked the parent chain to genesis (`chain.rs:143`). One `submit`
was therefore O(stored²), and side branches were retained forever — a peer could
turn this into a quadratic CPU amplifier.

Change: `Chain` gained a `work: HashMap<Hash, u128>` field, populated once at
insert:

- genesis in `Chain::new`: `work.insert(hash, genesis.header.difficulty)`
- `submit_at`: before reselect, `work.insert(hash, parent_work.saturating_add(difficulty))`
- failure path (non-finality) removes from `work` alongside `blocks`

`cumulative_work` is now an O(1) lookup with a defensive walk fallback (debug-assert
on miss). Fork choice is O(stored) total, O(1) per block. Value is identical — it
is the same sum along the same path, computed earlier — so no consensus outcome
changes. `Snapshot`/`restore` are untouched, because `adopt` never mutates `blocks`
or `work` (only canon/utxo/undo), and those maps are only written at insert and the
one failure-path removal.

Added `params.rs` test `genesis_hash_is_identical_across_profiles` to pin the
property that motivated §13.3. The whole core suite (130 unit + 9 red-team) stays
green.

### 18.2 `jnt-core` — `u16le` on `Writer`

`Reader` already had `u16le`; `Writer` did not, even though counts in §13 are
2-byte LE and the existing codebase otherwise uses `u32`/`u64`/`u128` writers. Added
`Writer::u16le` mirroring `u32le` exactly; covered by a round-trip test in
`frame.rs`. Closes an existing asymmetry, no behavioral risk.

### 18.3 `jnt-core` — `network_magic` / `network_id` on `NetworkParams`

Added two fields (§13.3) carrying the per-profile identity. `mainnet` uses
`[0x6A,0x4E,0x54,0x01]` / `"jounit/mainnet"`; `mini` uses `0x02` / `"jounit/mini"`.
`validate()` rejects zero magic and empty id. Added
`network_magic_is_distinct_and_nonzero` asserting the two profiles differ in both.

This is the concrete reason the genesis-collision finding is safe: isolation no
longer depends on anything that is identical across profiles.

### 18.4 New crate `crates/jnt-net`

Created `crates/jnt-net` + workspace member. Depends only on `jnt-core`; std-only.
Modules shipped:

| File | Lines | Contents |
|---|---|---|
| `lib.rs` | ~25 | crate doc + re-exports |
| `error.rs` | ~95 | `NetError` — network failures only, never `jnt_core::Error` |
| `magic.rs` | ~55 | `check_network`: magic + network_id rejection of cross-network peers |
| `frame.rs` | ~175 | `write_frame`/`read_frame`: magic checked per-frame, `payload_len` bounded before allocation |
| `msg.rs` | ~340 | `Message` enum + encode/decode for all 9 types, `Version`/`InvEntry`/`SocketAddr` |

Still stubs: `peer.rs`, `syncer.rs`, `net.rs`.

### 18.5 The codec bug the tests caught

`Message::Version` encode wrote fields in spec order (magic, id, protocol, ...,
user_agent, nonce) but `decode_version` read `user_agent` *before* protocol_version
— a field-order mismatch the version round-trip test surfaced immediately. Fixed
decode to match encode. This is exactly why the spec says "where the wire format is
ambiguous, every implementation will disagree and the disagreement looks like a
consensus split": two independent encoders of these rules would silently
desync. Catching it now on a unit test is the point.

This also validated the discipline of writing codec tests before the socket layer:
the transport is where a byte-order bug becomes a heisenbug against a live peer.

---

## 19. Findings from this session

| # | Finding | Severity | Live? | Resolved |
|---|---|---|---|---|
| 1 | `best_candidate` O(stored²); side branches never pruned | High (DoS, only under P2P) | No — single node, never many stored blocks | Yes — incremental work; pruning deferred to §20.1 |
| 2 | `mainnet`/`mini` genesis hash identical | High (network isolation) | No — no handshake yet | Yes — `network_magic`/`network_id` in handshake & framing |
| 3 | `chain.rs:5` doc still says "first-seen order" | Trivial (stale comment) | N/A | No — noted, out of scope |

**Finding 1 is worth being precise about.** The quadratic cost is real, but its
exploitation needs a peer to submit many blocks, so it is purely a P2P-era
defect. The fix lands the moment peers exist. Pruning (the companion half) is
genuinely a design decision because it touches the finality wedge (see §20).

---

## 20. Decisions deferred, and why

**20.1 Pruning is bundled with the finality wedge — not done yet.**
`adopt()` snapshots the whole UTXO set (session 1 §10 item 1, "SHOULD"), and a
heavier branch forking below `finality_depth` is retained and its work counted —
session 1 §8 explicitly *decided not to change that*. Pruning below the finality
boundary *would* resolve the wedge (the node forgets the dead branch and can accept
honest blocks again), which means pruning is not a mechanical perf fix; it is the
consensus question session 1 left open. So pruning + persistence are bundled and
deliberately sequenced after the network crate can be exercised.

**20.2 Persistence is deferred for the `serve` path.** The current `Store`
rewrites `blocks.json` on every block. A live node that accepts relayed blocks
cannot do an O(n) rewrite per block. Plan: `serve` runs in-memory (no per-block
JSON rewrite), and `blocks.log` (append-only) + a UTXO snapshot lands in step 2 so
restart doesn't replay genesis. Not a correctness issue, only a scalability one,
which is why it is behind the `serve` command rather than blocking the crate.

**20.3 Transaction relay, peer identity, and discovery** are all in SPEC.md §13.13
as deliberately unspecified. No mempool exists in `jnt-core` today, so there is
nothing to gossip; inventing that policy now would constrain the real design
backwards.

---

## 21. Verification done

- `cargo test --workspace`: 139 (core) + 10 (net) pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (the whole
  workspace, including the new crate).
- `cargo fmt --all --check`: clean.
- `cargo test -p jnt-net --doc`: clean (after marking wire-diagram doc blocks
  `text` so the `‖` symbols aren't parsed as Rust).
- The genesis-collision property is now an executable assertion
  (`params.rs::genesis_hash_is_identical_across_profiles`), so the
  "obvious approach is wrong" trap is guarded against regression.

## 22. Next steps achieved (Session 4) — Full Record

**Date:** 2026-10-05 (same day, latest session)
**Scope:** Complete 5 protocol mechanisms (M1–M5) + finish jnt-net P2P layer + full docs + push to GitHub
**Outcome:** All 207 tests pass, CI green, committed and pushed. Working tree clean.

---

### 22.1 What was built this session

**Total new code shipped:**
- 4 new source files in `jnt-core`: `slash.rs`, `compute_ir.rs`, `hbm_pow.rs`, `bls_checkpoint.rs`
- 9 new source files in `jnt-net`: `peer.rs`, `syncer.rs`, `net.rs`, `tests/integration.rs` (plus existing `frame.rs`, `msg.rs`, `magic.rs`, `error.rs`, `lib.rs` from session 3)
- Major modifications to `fees.rs`, `chain.rs`, `ser.rs`, `params.rs`, `lib.rs`, `jnt-node/main.rs`
- 27 files changed, 4 883 insertions in the main commit

---

### 22.2 M1 — 50/50 PSCB Base Fee Split (`fees.rs`, `chain.rs`)

**What it does:** Every block's base-fee portion is split 50% burned (deflationary) and 50% routed to the on-chain Protocol Security & Compute Buffer (PSCB) reserve, with the full miner tip separate.

**Design decisions:**
- `FeeSplit` struct carries `burned`, `pscb`, `tip`. Strict invariant enforced: `burned + pscb + tip == total_fees`.
- The odd satoshi in integer 50% division goes to `burned` (not PSCB) — burns are irrecoverable so conservative rounding is safer.
- `Chain` gained `pscb_reserve: u64` and `pscb_undo: HashMap<Hash, u64>` for reorg-safe PSCB accumulation. On reorg, `pscb_undo` lets the chain undo the PSCB credit for exactly the blocks that were rolled back.
- `pscb_reserve()` is a public read-only accessor used by `jnt-node status`.

**Tests added (5):** split invariant, odd-satoshi rounding, zero-gas edge, tip-only block, PSCB is non-zero whenever fees are paid.

---

### 22.3 M2 — Time-Locked Compute Reserve & 50/50 Anti-Collusion Slash Vault (`slash.rs`)

**What it does:** When a validator submits a fraudulent compute result and is slashed:
- 50% of their stake is **instantly burned** (Anti-Collusion Burn) — eliminates any self-slashing attack where colluders reclaim 100%.
- 50% vests **linearly per block** over 1 year into the Compute Reserve.

**Design decisions:**
- `SlashRecord::new()` splits at construction time using integer arithmetic: `burned = stake / 2`, `vest_total = stake - burned` (handles the odd satoshi; vest gets it).
- `vest_per_block` uses `.div_ceil(period)` so the last block receives the remainder rather than losing it.
- `SlashVault` tracks a `Vec<SlashRecord>` and prunes fully exhausted records on each `advance()` call — memory doesn't grow unboundedly.
- Constants: `VESTING_BLOCKS_MAINNET = 52_560` (~1 year at 10-min blocks), `VESTING_BLOCKS_MINI = 1_000`.

**Tests added (9):** 50/50 split, odd-satoshi distribution, vesting is linear and bounded, full remainder vests at unlock height, slash outcome from record, claimable before slash height is zero, vault tracks total burned, vault returns correct payouts, vault prunes exhausted records.

---

### 22.4 M3 — Universal Hardware-Agnostic Canonical Compute IR (`compute_ir.rs`)

**What it does:** Defines a hardware-portable execution envelope that abstracts AI compute tasks across GPU (CUDA/ROCm), Apple Neural Engine, Google TPU, and future photonic chips.

**Design decisions:**
- `HardwareTarget` enum: `Cuda`, `Rocm`, `Ane`, `Tpu`, `Photonic`, `Generic` — extensible without breaking serialization.
- `QuantizationMode`: `Int8`, `Fp16`, `Fp32`, `BFloat16` — deterministic, no floating-point nondeterminism.
- `ComputeTask` has a SHA-256 domain-separated signing hash (`DOM_COMPUTE_TASK = 0xC1`) covering: task_id, worker_address, hardware_target, quantization_mode, input_hash, flop_count, deadline_block.
- `ComputeAttestation` covers the task hash + result hash (`DOM_COMPUTE_ATTEST = 0xC2`), so the attestation is bound to a specific task with a specific output.
- `worker_address` is `[u8; 20]` (20-byte Ethereum-style address) — uses `write_raw` in serialization because `write_bytes` expects `[u8; 32]`.

**Tests added:** round-trip serialization, hardware target coverage, quantization coverage, attestation hash determinism.

---

### 22.5 M4 — Memory-Bound HBM Scratchpad PoW (`hbm_pow.rs`)

**What it does:** Extends the mining loop with a memory-latency-bound stage to prevent pure-compute (ASIC/cloud-burst) from outcompeting hardware with real HBM/GDDR bandwidth.

**Design decisions:**
- `HbmConfig { lanes, accesses }` — `lanes` sets scratchpad size (each lane = 32 bytes = one cache line), `accesses` sets how many pseudorandom hops are made.
- Mainnet: 16 384 lanes (512 KiB scratchpad), 64 accesses. Test: 256 lanes (8 KiB), 8 accesses — fast enough for unit tests.
- Scratchpad is initialized deterministically from `sha256(&[&header_bytes])`, so it is unique per block candidate.
- Each hop: `next_lane = sha256(&[&prev])[0..8] as u64 % lanes` — the SHA-256 output drives the memory address, making it infeasible to precompute the access sequence without the header.
- Final result: `sha256(&[&last_hop_bytes])` which is compared against `target_for_difficulty(difficulty)` from `u256.rs`.

**Fix needed:** Initial code used `sha256(&bytes)` but the actual API is `sha256(&[&bytes])` (slice of slices). Also used a non-existent `satisfies_difficulty` helper — fixed to use `target_for_difficulty(difficulty)` + `U256` comparison.

---

### 22.6 M5 — Sovereign BLS Aggregate Finality Gadget (`bls_checkpoint.rs`)

**What it does:** Adds deterministic absolute finality on top of probabilistic deepest-chain PoW via BLS12-381 aggregate signatures.

**Design decisions:**
- `BlsPublicKey([u8; 48])` = G1 compressed, `BlsSignature([u8; 96])` = G2 compressed — typed wrappers enforcing encoding sizes.
- `CheckpointPayload` serializes: epoch, height, block_hash, validator_set_hash. Signing hash uses `sha256_dom(&[DOM_BLS_CHECKPOINT], &[...])`.
- `ValidatorSet` sorts keys at construction time (`sort_by_key(|a| a.0)`) so validator ordering is deterministic regardless of insertion order.
- `quorum_size()` uses `.div_ceil(10_000)` on `n * QUORUM_BPS` — avoids the `(n * bps + 9999) / 10000` pattern that clippy flags.
- Bitmap encoding: 1 bit per validator (LSB = index 0), compact byte array. `signers_from_bitmap` and `bitmap_from_indices` are inverses.
- `BlsVerifier` trait makes the verification pluggable: `MockBls` for tests (checks all-zeros sig as invalid, otherwise passes), production would use `blst`.
- `CheckpointChain` enforces the absolute finality guarantee: once a checkpoint is accepted, `last_finalized_height` advances and the boundary is permanent.

**Tests added (13):** payload serialization, signing hash covers all fields, hash changes with epoch and block_hash, epoch calculation, quorum size (2/3 supermajority), bitmap round-trip, sorted keys are deterministic, valid checkpoint passes with quorum, checkpoint fails below quorum, all-zeros aggregate sig fails, bitmap/signer_count mismatch fails, checkpoint chain advances finality, stale checkpoint rejected.

---

### 22.7 `jnt-net` — Completing the P2P Layer

Session 3 built: `frame.rs`, `msg.rs`, `magic.rs`, `error.rs`, `lib.rs`.

This session added:

**`peer.rs`** — Thread-per-connection peer state machine:
- `HandshakeConfig`: encapsulates `NetworkParams`, current height, tip hash for `Version` construction.
- `perform_handshake()`: sends `Version`, waits for peer `Version`, sends/waits for `Verack`, validates magic + network_id via `check_network()`.
- `PeerHandle`: channel + `JoinHandle` wrapper for sending messages to a peer thread.
- `PeerEvent`: `Connected { peer_id, version, is_outbound }`, `Block { peer_id, block }`, `Disconnected { peer_id }` — the event stream the chain thread consumes.

**`syncer.rs`** — Locator-based sync state machine:
- `create_locator(chain)`: exponential step locator (heights: tip, tip-1, tip-2, tip-4, tip-8... genesis) — mirrors Bitcoin's getblocks locator.
- `find_fork_and_collect_inv(chain_a, chain_b)`: finds the common ancestor and collects hashes from fork point to tip_a, ordered oldest-first.
- `SyncManager`: manages pending `Inv` entries, tracks `inflight` requests, and the orphan pool (bounded at 512 entries).
- `SyncResult`: `Accepted { extended_tip, orphans_resolved }`, `Orphan { missing_parent }`, `AlreadyKnown`, `Invalid(String)`.
- `orphan_pool_is_bounded` test confirms the pool never exceeds 512 even under adversarial hammering.

**`net.rs`** — `P2pNode` orchestrator:
- `P2pConfig { params, listen_addr, max_peers }`.
- `P2pNode::start()`: spawns the listener thread, manages peer ID counter, `peers: Arc<Mutex<HashMap<usize, PeerHandle>>>`.
- `P2pNode::poll_events()`: consumes `PeerEvent`s, drives `SyncManager`, sends `GetBlocks` to peers that are ahead.
- `P2pNode::broadcast_block()`: sends `Inv` to all connected peers.
- `P2pNode::connect()`: initiates an outbound connection with handshake.

**`jnt-node serve` command** (`main.rs`):
- New `Serve` subcommand with `--listen`, `--connect`, `--peers` flags.
- Owns the `Chain`, wraps `P2pNode` + `SyncManager`, loops on `poll_events()` and mining.
- Inbound block relay: accepted blocks broadcast to all peers immediately.

---

### 22.8 Integration test suite (`crates/jnt-net/tests/integration.rs`)

10 loopback tests covering the §13.11 invariants:

| Test | Invariant |
|---|---|
| `two_nodes_converge_regardless_of_delivery_order` | §13.11 inv 2 |
| `cross_network_handshake_is_rejected_at_connect` | §13.11 inv 4 |
| `mini_node_rejects_mainnet_handshake` | §13.11 inv 4 (listener side) |
| `relay_block_equals_locally_mined_block` | §13.11 inv 1 |
| `handshake_completes_on_loopback` | §13.11 inv 3 |
| `locator_includes_tip_and_genesis` | §13.11 inv 6 |
| `find_fork_collects_inv_from_common_ancestor` | §13.11 inv 6 |
| `invalid_blocks_never_enter_the_store` | §13.11 inv 5 |
| `sync_manager_resolves_blocks_in_order` | §13.11 inv 2 |
| `orphan_pool_is_bounded` | §13.11 inv 7 |

---

### 22.9 Problems encountered and how they were fixed

This is the most important part — recorded so these traps are not re-hit.

**Problem 1: `sha256_dom` argument type mismatch in `bls_checkpoint.rs`**
- Code: `sha256_dom(DOM_BLS_CHECKPOINT, &[&self.serialize()])`
- Error: `expected &[u8], found u8` — `DOM_BLS_CHECKPOINT` is `u8`, but the function takes `&[u8]` for the domain tag.
- Fix: `sha256_dom(&[DOM_BLS_CHECKPOINT], &[&self.serialize()])` — wrap the single byte in a slice.

**Problem 2: `sha256` API takes `&[&[u8]]` not `&[u8]`**
- Code in `hbm_pow.rs`: `sha256(&hb)` where `hb: Vec<u8>`.
- Error: type mismatch — `sha256` takes a slice of byte slices, not a single slice.
- Fix: `sha256(&[&hb])` — wrap in an outer slice as required by the API.

**Problem 3: `write_bytes` vs `write_raw` for 20-byte address**
- Code in `compute_ir.rs`: `w.write_bytes(&self.worker_address)` where `worker_address: [u8; 20]`.
- Error: `write_bytes` expects `&[u8; 32]` (hash-sized), but the address is 20 bytes.
- Fix: use `w.write_raw(&self.worker_address)` which accepts any `&[u8]`.

**Problem 4: `sort_by` vs `sort_by_key` clippy warning**
- Code: `keys.sort_by(|a, b| a.0.cmp(&b.0))`
- Clippy: `unnecessary_sort_by` — use `sort_by_key` when the key is a simple projection.
- Fix: `keys.sort_by_key(|a| a.0)`

**Problem 5: Manual `div_ceil` pattern**
- Code: `(n * QUORUM_BPS as u64 + 9_999) / 10_000` and `(vest_total + period - 1) / period`
- Clippy: `manual_div_ceil` — Rust 1.73+ provides `.div_ceil()`.
- Fix: `(n * QUORUM_BPS as u64).div_ceil(10_000)` and `vest_total.div_ceil(period)`

**Problem 6: Doc comment over-indentation**
- Code in `fees.rs`: continuation lines of bullet points were indented 14 spaces to align under the label.
- Clippy: `doc_overindented_list_items` — continuation lines must be 2 spaces, not 14.
- Fix: collapsed continuation lines to 2-space indent.

**Problem 7: Writer API naming — new modules used non-existent method names**
- New modules used `write_u8()`, `write_u64()`, `write_bytes()`, `write_raw()`, `finish()`.
- The existing `Writer` only had chaining methods: `.u8()`, `.u64le()`, `.raw()`, `.into_vec()`.
- Fix: Added convenience alias methods to `Writer` — `write_u8`, `write_u32`, `write_u64`, `write_bytes`, `write_raw`, `finish` — as thin wrappers that call the existing methods and then return `&mut self` or the buffer.

**Problem 8: `satisfies_difficulty` did not exist**
- `hbm_pow.rs` called `u256::satisfies_difficulty(hash, difficulty)`.
- The actual API is `target_for_difficulty(difficulty) -> U256` + `U256` comparison.
- Fix: Import `target_for_difficulty` and `U256`, compute target, then compare `U256::from_be_bytes(hash.0) <= target`.

**Problem 9: Unused `Reader` import in `compute_ir.rs`**
- `Reader` was imported but `compute_ir.rs` only serializes, never deserializes.
- Fix: removed the import.

**Problem 10: `unused_mut` warnings in `bls_checkpoint.rs` tests**
- `let mut p1 = make_payload(100)` — `p1` was never mutated.
- `let mut cp = make_checkpoint(...)` — `cp` was never mutated.
- Fix: removed `mut` from both bindings.

**Problem 11: Unused imports in `jnt-net/tests/integration.rs`**
- `InvEntry` and `Version` were imported but not directly used in tests.
- Fix: removed them from the `use` statement.

**Problem 12: CI failure — `clippy::unneeded_wildcard_pattern`**
- CI (GitHub Actions, rust 1.99) caught a lint that local clippy (1.95) did not flag.
- Code: `PeerEvent::Connected { peer_id, version, is_outbound: _, .. }` — `is_outbound: _` is redundant because `..` already covers remaining fields.
- Fix: removed `is_outbound: _`.
- Lesson: CI may use a newer Rust toolchain with additional lints. Always check CI result, not just local clippy.

**Problem 13: CI failure — rustfmt format diff (Linux vs Windows)**
- After removing `is_outbound: _`, the match arm had 2 named fields + `..`.
- On Windows `rustfmt` kept them on separate lines. On Linux (CI) `rustfmt` collapsed short patterns to one line: `PeerEvent::Connected { peer_id, version, .. } => {`.
- Fix: manually collapsed to the one-line form to match Linux `rustfmt` output.
- Lesson: `cargo fmt --all --check` passes locally does NOT guarantee CI passes. When a pattern's field count changes, check whether `rustfmt` would collapse it on Linux.

---

### 22.10 `README.md` and `docs/status.md` updates

**`README.md` changes:**
- Status banner updated from "no P2P, single node" to reflecting the full P2P layer and M1–M5.
- TOC gained: "Protocol mechanisms (M1–M5)" and "P2P networking (jnt-net)" sections.
- Status table: P2P row updated from "no P2P" to "Implemented: TCP framing, handshake isolation, block relay, locator-based sync, orphan pool".
- Repository layout: added `jnt-net/` (1 400+ lines) and updated counts.
- Crate layout: changed from 2 crates to 3 (`jnt-core`, `jnt-net`, `jnt-node`).
- Module map: expanded from 17 to 21 modules, including M1–M5.
- Quick start: added `jnt-node serve` example command.
- Testing: updated count from 139 to 207 tests.
- Added full M1–M5 descriptions and P2P section.

**`docs/status.md` changes:**
- Scope section rewritten to list all 5 mechanisms + P2P layer.
- Verified section updated: 207 tests in 4 groups, clippy 0 warnings, fmt clean.

---

### 22.11 Commit history for this session

```
c89b3ab  Fix rustfmt diff in jnt-net/net.rs (collapse PeerEvent::Connected pattern fields)
3eac825  Fix clippy unneeded_wildcard_pattern in jnt-net
a867247  Implement P2P networking layer (jnt-net), 5 protocol mechanisms (M1-M5), and update docs
```

`a867247` is the main feature commit (27 files, +4 883 lines). The two followup commits were
CI hotfixes: lint and format differences between the local toolchain (rustc 1.95) and the CI
runner (rustc 1.99).

---

### 22.12 Current project state

**Tests:** 207 total, 0 failed.
- `jnt-core` unit: 178 (130 original + 9 mechanism tests × 5 + 13 BLS tests + misc)
- `jnt-core` redteam: 9
- `jnt-net` unit: 10
- `jnt-net` integration: 10

**CI:** Green on `main` (run `37356282100`).

**Working tree:** Clean (`git status` = nothing to commit).

**Toolchain:** rustc 1.95 local, rustc 1.99 on CI. Workspace compiles clean on both.

**What is fully implemented:**
- L1 consensus engine: PoW, UTXO ledger, fork choice, finality, difficulty retarget, supply schedule, hybrid PQ signatures.
- P2P layer: TCP framing, handshake, peer lifecycle, sync, orphan pool, multi-peer serve daemon.
- M1: 50/50 PSCB fee split with reorg-safe accumulation.
- M2: Anti-collusion slash (50% burn + 50% linear vesting).
- M3: Hardware-agnostic canonical compute IR with attestation envelope.
- M4: Memory-bound HBM scratchpad PoW.
- M5: BLS12-381 aggregate finality gadget with pluggable verifier.

**What is not yet implemented (deferred, documented):**
- Real BLS pairing verification (currently `MockBls` in tests; `blst` integration is the production path).
- Side-branch pruning (depends on finality-wedge consensus decision — §20.1).
- Persistent UTXO / append-only block log (O(n) JSON rewrite on every block — §20.2).
- Transaction relay / mempool (no mempool exists in `jnt-core` — §20.3).
- Layer 2: Verified Work Certificates (the project's actual useful-work premise — specced, not built).
- `cargo-fuzz` harness (red-team tests are the seed corpus, not yet a fuzz loop).
- LICENSE file (Cargo.toml declares MIT OR Apache-2.0 but no file exists).
---

# Working memory — session 5: full integration audit

**Date:** 2026-10-06
**Branch:** `main`, clean at start (5 commits from session 4).
**Scope:** the user asked for an autonomous review of everything shipped in
sessions 1–4 — "is it complete, connected, working?" — then fix, verify, record,
commit and push.
**Outcome:** 15 real defects found and fixed, 3 of them serious. 219 tests pass
(was 207). Committed and pushed.

---

## 23. The headline finding

**Sessions 1–4 tested `SyncManager` directly. Nothing ever ran `P2pNode`.**

Every `jnt-net` test constructed a `SyncManager` and called `handle_block` /
`handle_inv` by hand. The event loop, the peer threads, the framing on a live
socket, and the continuation between sync batches were never executed by a test.
So when I wrote the first end-to-end test — two real `P2pNode`s, a real
listener, a real connection — it failed immediately, and fixing it uncovered a
chain of further defects.

This is the same lesson as session 1's `first_seen` fork-choice bug and session 2's
genesis collision: **the untested path is where the bugs are.** The difference is
that this time the gap was in my own test strategy rather than in a rule the
specification had already stated. §13.7 says the requester `GETDATA`s "in
batches of 16, submits each, **and repeats**". The code did not repeat. The spec
was right, the code was wrong, and no test could see it because the test never
crossed the boundary where the repetition is supposed to happen.

## 24. Defects fixed, ordered by severity

### 24.1 Sync stopped after one batch — `syncer.rs`

`handle_inv` returned the first `SYNC_BATCH_SIZE` (16) entries of an `INV` and
**discarded the rest**. Worse, it had already inserted all of them into the
`requested` set, so the discarded entries were also marked as in-flight: lost
*and* poisoned. Nothing ever asked for the next batch. A node more than 16
blocks behind could never finish syncing — the `serve` command was decorative.

Fix: every advertised hash goes into a bounded `pending` queue; each applied
block frees a request slot and `take_batch` refills it. `net.rs` calls
`take_batch` after every `BLOCK`.

### 24.2 A disconnecting peer could stall sync forever

`requested` was a `HashSet<Hash>` with no owner and no release path. A peer that
advertised 500 hashes and hung up left all 500 marked as requested, so no later
peer advertising the same blocks was ever asked for them. Silent, permanent, and
free to trigger.

Fix: `requested: HashMap<Hash, peer_id>`, plus `peer_disconnected(peer_id)`,
called from `poll_events`. Tests: `a_disconnect_releases_the_disconnected_peers_requests`.

### 24.3 The `requested` set grew without bound

§13.11 invariant 6 — "MUST NOT grow any bounded structure past §13.8" — was
violated by the simplest possible attack: advertise hashes, never deliver them.
Now capped at `MAX_IN_FLIGHT` (64), with `MAX_PENDING_INV` (2000) queued.
Test: `a_peer_that_never_delivers_cannot_grow_state_without_bound` (200 max-size
`INV`s, nothing delivered).

### 24.4 Every inbound connection failed on Windows

The listener is non-blocking so `accept` can poll. On Windows an accepted socket
**inherits** `WSA_FLAG_NON_BLOCKED`, so the blocking, timeout-based handshake
immediately returned `WouldBlock` and the peer was dropped with
`ConnectionAborted`. `jnt-node serve` could not accept a single connection on
Windows — the platform this repo is developed on.

Every prior test used a plain blocking `TcpListener` and passed. Only a test that
went through `P2pNode::start` with a listener could see it.

Fix: `stream.set_nonblocking(false)` immediately after `accept`.

### 24.5 `stop()` did not disconnect

`PeerHandle::stop` set a flag. The reader thread stayed blocked in `read_frame`
for up to 60 s, still holding a thread and still able to emit events for a peer
the node believed it had dropped — including a peer just banned for a framing
violation. Fix: the handle keeps an `Arc<TcpStream>` and calls
`shutdown(Both)`.

### 24.6 `max_peers` was never enforced

§13.8 bounds it as the cap on thread and descriptor count. Only `max_inbound` was
checked, and only on the accept path. A node could dial as many outbound peers as
it had addresses. Now enforced on `connect` (new `NetError::Resource`) and on
accept, alongside `max_inbound`.

### 24.7 Exceeding an inbound bound disconnected instead of banned

§13.8 says it bans. There was no ban list at all — v0.2 has no address book
(§13.6), so nothing remembered an address. Added a bounded, address-keyed score
table with §13.9's 1-per-hour decay, `+20` per violation, refusing banned
addresses at accept.

### 24.8 The handshake nonce was the wall clock

`generate_nonce` was `SystemTime::now() ^ constant`. §13.4 calls the nonce
"proof of possession of the socket", and a nonce a peer can estimate from block
timestamps is not a challenge — it makes the replay the nonce exists to defeat
easier, not harder. Now mixes an OS-seeded `RandomState` key with a counter.
This is the weakest possible substitute for a node key, and §13.4 already says
so; the point was only that it should not be *predictable*.

### 24.9 `mine_block_with`'s attempt cap guarded nothing

`max_attempts` was applied by a **second** mining loop in `mine_block_with` that
only ran after `build_block`'s own unbounded loop had finished. Asking for 3
attempts at difficulty 2^64 did not fail fast — it ran effectively forever. The
doc comment claimed "a mis-set difficulty or a hostile retarget cannot hang a node
forever", which was false.

Fix: the budget is enforced in the loop that does the work; `mine_block_with` now
just forwards it. The regression test does not fail on the old code, it *hangs*,
which is the defect.

### 24.10 Side branches were never pruned — §13.10 item 2

The last unimplemented MUST in the spec, and the cause of the "finality wedge"
that sessions 1, 3 and 4 all recorded as an open design question. A valid branch
forking below `finality_depth` was retained with its work counted, so fork choice
kept selecting it and honest blocks were refused until honest work caught up. A
peer could stall a node's progress at no cost to itself.

Fix: prune every **non-canonical** block at or below `tip − finality_depth`,
plus any stored descendant of a dropped block (a block whose parent is gone
cannot be walked to by `path_to`). Canonical history is retained in full —
`undo`, `verify_canonical_chain` and persistence all replay from genesis.

**This is the decision I flagged rather than made silently.** §9.3 is unchanged:
a reorg whose fork point is at or below the finality height is still refused, and
both finality regression tests still pass. What changed is only how long the node
remembers a branch it was never going to follow. SPEC.md §13.10 item 2 now says so
explicitly, and `docs/status.md` records the supersession.

### 24.11 `jnt-node serve` threw away everything it synced

It persisted only on its own mining path. Blocks that arrived from peers were
applied in memory and never written — a node that synchronised 500 blocks saved
none of them, and a restart replayed genesis and discarded the whole sync. It
also looped with no delay at all: mining as fast as the CPU allowed, rewriting
the entire `blocks.json` each time (O(n) per block), with almost nothing left for
`poll_events`. Now saves whenever `poll_events` changed the height, and paces the
loop with `--interval` (default 250 ms).

### 24.12 `verify` could not see an M1 bug

`verify_canonical_chain` compared canon, UTXO length and UTXO value. M1 added
`pscb_reserve` and `pscb_undo`, which are live state and are rewound on reorg —
and which the node's own verifier could not see. Now both are re-derived by replay.
Test: `the_pscb_reserve_is_rewound_exactly_on_reorg`.

### 24.13 Smaller

- The locator could return 501 entries: genesis was appended on top of an
  already-full locator. §13.8's `max_locator_len` is now reserved for.
- Orphan eviction picked an arbitrary hash-map key, so which orphans survived
  depended on iteration order. Now oldest-first, tracked in a `VecDeque`.
- An invalid inbound block is a framing violation
---

# Working memory — session 5: full integration audit

**Date:** 2026-10-06
**Branch:** `main`, clean at start (5 commits from session 4).
**Scope:** the user asked for an autonomous review of everything shipped in
sessions 1–4 — "is it complete, connected, working?" — then fix, verify, record,
commit and push.
**Outcome:** 15 real defects found and fixed, 3 of them serious. 219 tests pass
(was 207). Committed and pushed.

---

## 23. The headline finding

**Sessions 1–4 tested `SyncManager` directly. Nothing ever ran `P2pNode`.**

Every `jnt-net` test constructed a `SyncManager` and called `handle_block` /
`handle_inv` by hand. The event loop, the peer threads, the framing on a live
socket, and the continuation between sync batches were never executed by a test.
So when I wrote the first end-to-end test — two real `P2pNode`s, a real
listener, a real connection — it failed immediately, and fixing it uncovered a
chain of further defects.

This is the same lesson as session 1's `first_seen` fork-choice bug and session
2's genesis collision: **the untested path is where the bugs are.** The
difference is that this time the gap was in the test strategy rather than in a
rule the specification had already stated. §13.7 says the requester `GETDATA`s
"in batches of 16, submits each, **and repeats**". The code did not repeat. The
spec was right, the code was wrong, and no test could see it because the test
never crossed the boundary where the repetition is supposed to happen.

## 24. Defects fixed, ordered by severity

### 24.1 Sync stopped after one batch — `syncer.rs`

`handle_inv` returned the first `SYNC_BATCH_SIZE` (16) entries of an `INV` and
**discarded the rest**. Worse, it had already inserted all of them into the
`requested` set, so the discarded entries were also marked as in-flight: lost
*and* poisoned. Nothing ever asked for the next batch. A node more than 16
blocks behind could never finish syncing — the `serve` command was decorative.

Fix: every advertised hash goes into a bounded `pending` queue; each applied
block frees a request slot and `take_batch` refills it. `net.rs` calls
`take_batch` after every `BLOCK`.

### 24.2 A disconnecting peer could stall sync forever

`requested` was a `HashSet<Hash>` with no owner and no release path. A peer that
advertised 500 hashes and hung up left all 500 marked as requested, so no later
peer advertising the same blocks was ever asked for them. Silent, permanent, and
free to trigger.

Fix: `requested: HashMap<Hash, peer_id>`, plus `peer_disconnected(peer_id)`,
called from `poll_events`. Test:
`a_disconnect_releases_the_disconnected_peers_requests`.

### 24.3 The `requested` set grew without bound

§13.11 invariant 6 — "MUST NOT grow any bounded structure past §13.8" — was
violated by the simplest possible attack: advertise hashes, never deliver them.
Now capped at `MAX_IN_FLIGHT` (64), with `MAX_PENDING_INV` (2000) queued.
Test: `a_peer_that_never_delivers_cannot_grow_state_without_bound` (200
max-size `INV`s, nothing delivered).

### 24.4 Every inbound connection failed on Windows

The listener is non-blocking so `accept` can poll. On Windows an accepted socket
**inherits** `WSA_FLAG_NON_BLOCKED`, so the blocking, timeout-based handshake
immediately returned `WouldBlock` and the peer was dropped with
`ConnectionAborted`. `jnt-node serve` could not accept a single connection on
Windows — the platform this repo is developed on.

Every prior test used a plain blocking `TcpListener` and passed. Only a test that
went through `P2pNode::start` with a listener could see it.

Fix: `stream.set_nonblocking(false)` immediately after `accept`.

### 24.5 `stop()` did not disconnect

`PeerHandle::stop` set a flag. The reader thread stayed blocked in `read_frame`
for up to 60 s, still holding a thread and still able to emit events for a peer
the node believed it had dropped — including a peer just banned for a framing
violation. Fix: the handle keeps an `Arc<TcpStream>` and calls `shutdown(Both)`.

### 24.6 `max_peers` was never enforced

§13.8 bounds it as the cap on thread and descriptor count. Only `max_inbound` was
checked, and only on the accept path. A node could dial as many outbound peers as
it had addresses. Now enforced on `connect` (new `NetError::Resource`) and on
accept, alongside `max_inbound`.

### 24.7 Exceeding an inbound bound disconnected instead of banned

§13.8 says it bans. There was no ban list at all — v0.2 has no address book
(§13.6), so nothing remembered an address. Added a bounded, address-keyed score
table with §13.9's 1-per-hour decay, `+20` per violation, refusing banned
addresses at accept.

### 24.8 The handshake nonce was the wall clock

`generate_nonce` was `SystemTime::now() ^ constant`. §13.4 calls the nonce
"proof of possession of the socket", and a nonce a peer can estimate from block
timestamps is not a challenge — it makes the replay the nonce exists to defeat
easier, not harder. Now mixes an OS-seeded `RandomState` key with a counter.
This is the weakest possible substitute for a node key, and §13.4 already says
so; the point was only that it should not be *predictable*.

### 24.9 `mine_block_with`'s attempt cap guarded nothing

`max_attempts` was applied by a **second** mining loop in `mine_block_with` that
only ran after `build_block`'s own unbounded loop had finished. Asking for 3
attempts at difficulty 2^64 did not fail fast — it ran effectively forever. The
doc comment claimed "a mis-set difficulty or a hostile retarget cannot hang a
node forever", which was false.

Fix: the budget is enforced in the loop that does the work; `mine_block_with` now
just forwards it. The regression test does not fail on the old code, it *hangs*,
which is the defect.

### 24.10 Side branches were never pruned — §13.10 item 2

The last unimplemented MUST in the spec, and the cause of the "finality wedge"
that sessions 1, 3 and 4 all recorded as an open design question. A valid branch
forking below `finality_depth` was retained with its work counted, so fork choice
kept selecting it and honest blocks were refused until honest work caught up. A
peer could stall a node's progress at no cost to itself.

Fix: prune every **non-canonical** block at or below `tip − finality_depth`,
plus any stored descendant of a dropped block (a block whose parent is gone
cannot be walked to by `path_to`). Canonical history is retained in full —
`undo`, `verify_canonical_chain` and persistence all replay from genesis.

**This is the decision I flagged rather than made silently.** §9.3 is unchanged:
a reorg whose fork point is at or below the finality height is still refused, and
both finality regression tests still pass. What changed is only how long the node
remembers a branch it was never going to follow. SPEC.md §13.10 item 2 now says so
explicitly, and `docs/status.md` records the supersession.

### 24.11 `jnt-node serve` threw away everything it synced

It persisted only on its own mining path. Blocks that arrived from peers were
applied in memory and never written — a node that synchronised 500 blocks saved
none of them, and a restart replayed genesis and discarded the whole sync. It
also looped with no delay at all: mining as fast as the CPU allowed, rewriting
the entire `blocks.json` each time (O(n) per block), with almost nothing left for
`poll_events`. Now saves whenever `poll_events` changed the height, and paces the
loop with `--interval` (default 250 ms).

### 24.12 `verify` could not see an M1 bug

`verify_canonical_chain` compared canon, UTXO length and UTXO value. M1 added
`pscb_reserve` and `pscb_undo`, which are live state and are rewound on reorg —
and which the node's own verifier could not see. Now both are re-derived by
replay. Test: `the_pscb_reserve_is_rewound_exactly_on_reorg`.

### 24.13 Smaller

- The locator could return 501 entries: genesis was appended on top of an
  already-full locator. §13.8's `max_locator_len` is now reserved for.
- Orphan eviction picked an arbitrary hash-map key, so which orphans survived
  depended on iteration order. Now oldest-first, tracked in a `VecDeque`.
- An oversized frame or post-handshake bad magic is scored `+100` per §13.9 and
  was only a disconnect: a peer could probe the framing bounds for free and
  reconnect.
- No `PING` keepalive, so a half-open TCP connection held a thread forever and
  §13.9's "unresponsive to PING" row was unimplemented. The reader now pings on
  the first 60 s timeout and scores `+10` on the second.
- `inbound_count` was incremented before `spawn_peer` could fail, leaking the
  scarce inbound slot.
- `chain.rs`'s module doc still described the fork-choice tie-break as
  "first-seen order" — the arrival-counter bug session 1 fixed. Two sessions
  recorded it as "noticed but not touched". It is a comment that misdescribes a
  consensus rule, which is worse than no comment, so it is fixed.

## 25. Documentation that was wrong, not merely stale

- **SPEC.md §8 contradicted the code.** It said the base fee is burned in full;
  M1 had been splitting it 50/50 to the PSCB since session 4. This is the most
  consequential doc defect in the repository: the normative spec did not describe
  the consensus rule. §8 now states the split, the odd-satoshi rounding, and the
  reorg-correctness requirement.
- **SPEC.md's header said §13 was "not yet implemented"** and
  `net_vectors.json` did not exist. §13 is implemented, both blocking MUSTs are
  in, and the vectors now exist.
- **README listed all five mechanisms as shipped.** M2–M5 are complete, tested,
  self-consistent modules with **no effect on consensus**. `lib.rs` pointed at
  "SPEC.md §M1–§M5" — sections that did not exist. New §14 gives each mechanism a
  spec section and a status, and states why M2–M5 are inactive: each needs a rule
  this repo has not specified (what proves a compute result fraudulent, how a
  task enters a block, whether HBM replaces or composes with the §5 puzzle, who
  the validator set is). M2 and M4 would change consensus. I did not invent those
  rules.
- **`main.rs`'s module doc said "There is no P2P layer yet"** — directly above a
  `serve` command that runs it.
- README claimed `VESTING_BLOCKS_MINI` was 1 000. It is 2 000.

## 26. What I added

- **`tests/vectors/net_vectors.json`** + `crates/jnt-net/tests/net_vectors.rs`:
  the §13.12 wire-format vectors, which §12 said did not exist because §13 was
  specced ahead of its implementation. Round-trip tests only prove a codec agrees
  with itself; a field-order change would pass every one of them and break every
  deployed peer. The file pins the bytes, and the test restates the §13.5 layout
  as independent scalars so a file regenerated from wrong code cannot pass.
  *Honest limitation:* there is no second implementation for the wire format, the
  way `sim/jounit_reference.py` re-derives §5. That check is still owed, and the
  vector file says so in its own `note` field.
- **`a_node_syncs_a_peer_over_real_sockets`** — the test whose absence hid §24.1
  through §24.4.
- Two red-team tests (`side_branches_beyond_the_finality_window_are_pruned`,
  `a_mining_attempt_cap_cannot_be_bypassed`), one chain test
  (`the_pscb_reserve_is_rewound_exactly_on_reorg`), four syncer tests, one
  peer-limit test, and `invalid_blocks_never_enter_the_store` strengthened — it
  previously checked only the height, while §13.11 invariant 5 names the block
  store *and* cumulative work, so it passed against code that retained the block
  and banked its difficulty.

## 27. Mistakes I made this session

- **I nearly "fixed" a test instead of reading the failure.** My first
  `the_pscb_reserve_is_rewound_exactly_on_reorg` asserted `pscb == fee / 2`. It
  failed (207 000 vs 600 500) and I checked whether the code was wrong. The code
  was right: PSCB is 50% of the *base-fee portion*, not of the whole fee — the
  tip belongs to the miner. My assertion was wrong.
- **Two index-based assertions in the vector test.** `v["facts"][2]` was
  `verack_len`, not the `VERSION` length, and I then miscounted
  `"jounit/mainnet"` as 13 characters instead of 14. Both were caught because I
  asserted against literals rather than a computed layout. I replaced them with
  a computed `FIXED` constant so the next field-count change breaks loudly
  instead of silently.
- **A clumsy double `P2pNode::start`** in the first draft of the socket test,
  left in the file for one iteration. Cosmetic, but it read as a misunderstanding
  of the type.
- **I nearly shipped the pruning decision silently.** It closes a question three
  earlier sessions deliberately left open. It is specced as a blocking MUST, so
  implementing it is following the spec rather than making a consensus call — but
  "the spec said so" is exactly the reasoning that hides a decision, so it is
  written down in three places (SPEC.md §13.10 item 2, `docs/status.md`, and here)
  with the before/after behaviour spelled out.

## 28. Verification

Exit status preserved on every check, not inferred from a filter:

```
cargo fmt --all --check                                       exit 0
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets  exit 0
cargo test --workspace                                        exit 0   219 tests
  jnt-core lib          179
  jnt-core redteam       11
  jnt-net lib            15
  jnt-net integration    12
  jnt-net vectors         2
cargo build --workspace --release                             exit 0
python sim/verify_vectors.py --check                          exit 0
python sim/puzzle_crosscheck.py                               exit 0
python sim/supply_schedule_sim.py                            exit 0
python sim/difficulty_attack_sim.py                           exit 0
```

**`tests/vectors/` and `sim/` are unchanged** — `git status` shows only the new
`net_vectors.json`. Nothing I touched affects hashing, the PoW puzzle, the
retarget or serialization layout, and both independent Python implementations
still agree byte-for-byte with Rust. That is the evidence these were
state/transport-layer fixes rather than consensus-breaking ones.

**CLI end to end**, release build, `mini` profile: `init → mine 20 → status →
verify (21 blocks replayed, UTXO + supply + PSCB match) → export → show-block`,
all exit 0.

**Two real `serve` processes**: node A mined 6 blocks and listened; node B
dialed, handshook, mined 3 blocks of its own, then adopted A's heavier branch
(reorg 3 → 15) and kept relaying — both reaching ~83 blocks. Both data
directories then passed `verify` against a from-genesis replay, which also
confirms §24.11: B's relayed blocks were on disk, which they would not have been
before.

## 29. Current state

219 tests, CI-equivalent checks green, committed and pushed.

**Still open, and none of it is a bug:**

- Real BLS pairing verification (`blst`). `MockBls` accepts any non-zero
  signature, so no absolute-finality guarantee is in force.
- M2–M5 wired into consensus. Each needs a specification, and two of them are
  consensus changes.
- Persistence: `blocks.json` is still rewritten in full whenever the chain
  changes (§13.10 item 4), and state is still replayed from genesis on load.
  `serve` is a block relay, not a database.
- Mempool and transaction relay (§13.13), headers-first sync, compact blocks.
- A second implementation of the wire format to cross-check `net_vectors.json`
  against, the way `sim/jounit_reference.py` does for §5.
- `cargo-fuzz`. The red-team suite and the net vectors are the seed corpus.
- LICENSE file. `Cargo.toml` declares MIT OR Apache-2.0; no file exists.
---

# Working memory — session 6: D1–D4 decided, Phase 0.5 + 0.7 closed

**Date:** 2026-10-06
**Scope:** the user resolved the four open design questions that had been
blocking L2 since `docs/roadmap.md` §11, and set the build order.
**Outcome:** decisions recorded; P0.7 (LICENSE) and P0.5 (wire-format
crosscheck) shipped. The crosscheck found a real interop bug on its first run.

---

## 30. D1–D4, as decided

**D1 / D4 — Validators.** The M5 BLS validator set *is* the L2 dispute
arbitrator set. One set, one epoch, one governance system. Entry is
permissionless by staking a minimum JNT amount; the active set is the **top 21
stakers per epoch**. Genesis is bootstrapped by founder nodes — there is no stake
to rank before any exists, which is a bootstrapping problem the spec should state
explicitly rather than assume away.

**D2 — M3 re-execution in disputes.** A CPU-only reference execution path for
the ComputeIR, bit-identical to the GPU path. This is tractable *because* M3
already forbids floating point: the IR is integer-only, so GPU and CPU are two
readers of the same bytes rather than two floating-point pipelines that can
diverge. Validators run the CPU path during arbitration and need no GPU.

**D3 — L2 gas schedule.** Flat per transaction type, not per-byte, so a worker's
cost is knowable before they commit:

| Transaction | Fee (sat) |
|---|---:|
| `TxPostTask` | 5 000 |
| `TxClaimTask` | 2 000 |
| `TxSubmitResult` | 2 000 |
| `TxDispute` | 10 000 |
| `TxSettle` | 20 000 |

Recorded as constants in `params.rs` in session 7 (`FEE_TX_*_SAT` plus
`L2_FEE_SCHEDULE`). They are **not** consistent with the gas floor the node
enforces today — see §36 below. That is an open question, not a settled one.

**Build order:** mempool → tx relay → `jnt-store` → real BLS (`blst`) →
`cargo-fuzz` → L2 only after those four.

## 31. What shipped in this session

### 31.1 LICENSE (P0.7)

`Cargo.toml` has declared `license = "MIT OR Apache-2.0"` since the first commit
with no license file present. Now `LICENSE-MIT` + `LICENSE-APACHE`.

### 31.2 Wire-format crosscheck (P0.5) — and the bug it found

`sim/net_reference.py`: a second implementation of the §13 wire format, written
from the spec prose the way `sim/jounit_reference.py` is written from §5.

**It disagreed on the first run.** SPEC.md §13.5 defines `ADDR` as
`count(2 LE) ‖ count × (port(2 LE) ‖ ip(16))` — port first. The crate encoded
`ip ‖ port`.

Why no existing test could have caught it, which is the point worth keeping:

- **Round-trip tests cannot.** The encoder and decoder were wrong in the *same*
  way, so they agreed with each other perfectly.
- **The vector file could not.** `net_vectors.json` is generated *from* the Rust,
  so it only ever confirmed the Rust agreed with itself.
- **No length assertion could.** The entry is 18 bytes in either order.

The consequence is the severe one: two nodes running this code would interoperate
perfectly with each other, and neither would connect to any implementation that
followed the spec. A silent, total interop failure on a wire format whose entire
purpose is that independent implementations interoperate.

Fixed, vectors regenerated, and `addr_entry_is_port_then_ip` added as a
literal-bytes assertion so the order cannot drift back. The crosscheck is now
part of `verify_vectors.py --check`.

**Honest limit:** 5 of the 28 pinned values are chain-derived (a mined block,
locator entries from a 200-block chain). A second encoder cannot produce those
without a node, so the script reports them as **skipped** by name rather than
passing over them silently.

## 32. Process notes worth keeping

- **Two independent audits, two different blind spots.** Session 5's came from
  never running `P2pNode`; this one's came from never having a second encoder.
  Both times the gap was in how things were *verified*, not in what the code was
  supposed to do. The general lesson: for any format two parties must agree on,
  a round-trip test is not evidence — it is evidence that one implementation is
  self-consistent.
- **`docs/roadmap.md` has uncommitted changes I did not make** (516 insertions
  when last seen). Left untouched, unstaged and uncommitted. Whoever owns it
  should reconcile it, and it may conflict with `docs/status.md`, which I did
  edit.
- **GitHub Actions has not been run.** Local checks mirror CI, but CI uses rustc
  1.99 against local 1.95, and session 4 saw both a lint and a rustfmt
  difference that only CI caught. A follow-up hotfix commit is a realistic
  possibility.
- **`STATUS.md` test counts will drift.** Every roadmap step adds tests; the
  numbers in the "Verified" section are only true as of the commit that wrote
  them.

---

# Working memory — session 7: mempool (build order step 1)

**Date:** 2026-10-06
**Scope:** step 1 of the build order — `crates/jnt-core/src/mempool.rs` — plus the
D3 fee constants in `params.rs` and two stale claims corrected in
`docs/status.md`.
**Outcome:** mempool implemented and attack-tested. 232 workspace tests pass.

---

## 33. What the pool is, and what it deliberately is not

Bounded pool of transactions valid against the state the **next** block will be
built on. `add` takes the next height and that block's base fee, because getting
either wrong admits transactions the node itself will reject when it builds —
wasting every peer that relayed them.

- **Not consensus.** `check_tx` remains the only authority on validity. A pooled
  transaction has no more standing than one that arrived inside a block; a pool
  that disagrees with the chain loses. That is why eviction is driven by actual
  confirmed transactions rather than assumed.
- **Ordered by fee *rate*, not fee total.** A block has a gas budget, not a byte
  budget. Ordering by the total inverts the incentive: a large transaction
  outranks a small one paying several times as much per unit of work.
- **Total, deterministic order.** Ties break on `accepted_at`, then txid. Two
  nodes holding the same pool must select the same transactions in the same
  order, or they build different blocks from the same state — the same class of
  defect as the arrival-order fork choice session 1 removed.
- **Conflict check before the size check**, so a double spend is reported as a
  double spend and never as "pool full". A pool that reports the wrong reason
  cannot be debugged by its operator.
- **`continue`, not `break`, when a candidate does not fit the gas left.** A
  lower-fee transaction may still fit what remains; stopping at the first
  oversized one wastes the rest of the block.
- **Never lowers a fee to make something fit.** Fees are the user's decision.

## 34. The bug the attack suite found

`evict_confirmed` decided what to drop by asking the `spends` reverse index *who
spends this outpoint*. That is the wrong question. A dependent transaction is one
that spends an output **created by** a removed transaction — a property of the
input's outpoint, not of who currently spends it. Worse, `spends` is keyed by the
outpoint being spent, so for the dependent itself the lookup returned the
dependent, never the parent that created the output.

Result: **nothing downstream of a confirmed transaction was removed** — not the
direct child, not a grandchild two hops from the block. The pool kept entries
that could never be mined and advertised them to every peer forever.

Fixed by tracking a `gone` set of removed txids that grows on each pass and
testing `gone.contains(&op.txid)`.

**Red-team discipline, honestly applied.** The predicate was temporarily
reverted to the index-based form and both cascade tests were re-run: both failed
(`a tx spending a confirmed-away output stayed pooled`; `the cascade stopped
before the second generation: 2 entries left`). Then the fix was restored and
both pass. The recorded evidence is the failing run, not the passing one.

## 35. Two test-harness traps, both worth remembering

**Trap 1 — a test that fails for the wrong reason looks exactly like a test that
found a bug.** Eight of the nine mempool tests then present failed on first run
for a reason unrelated to the mempool: `check_tx` applies `coinbase_maturity` to
*every* output, not only to coinbase outputs (`held.height + coinbase_maturity >
height`). `funded()` creates UTXOs at height 0 and the tests spent at height 1,
so every admission was refused with `ImmatureCoinbase`. The blanket maturity is
pre-existing consensus behaviour with its own passing tests, so the fix belonged
in the harness — a named `H: u64 = 100` constant with a comment saying why.
The ninth test passed because it checked a *nonexistent* outpoint, which
`check_tx` rejects before maturity is ever consulted.

**Trap 2 — a vacuous test.** The fee-ordering test as first written built two
identical 1-in-1-out transactions. Gas was therefore equal, so "order by rate"
and "order by total" produce the same sequence and the test could not fail.
Rebuilt with a 4-in-1-out "wide" transaction (higher gas, larger total, lower
rate) against a 1-in-1-out "narrow" one (lower total, higher rate). The rebuilt
test also asserts `wide.gas_used() * narrow_fee > narrow.gas_used() * wide_fee`
so the *setup* is checked, not just the outcome — otherwise a future change to
gas constants could silently make it vacuous again.

## 36. D3 constants, and an interaction nobody had noticed

The five fees are now `FEE_TX_POST_TASK_SAT`, `FEE_TX_CLAIM_TASK_SAT`,
`FEE_TX_SUBMIT_RESULT_SAT`, `FEE_TX_DISPUTE_SAT`, `FEE_TX_SETTLE_SAT`, with
`L2_FEE_SCHEDULE` holding the exact set so one test pins all five literally — a
self-referential assertion would happily agree with a typo.

**They do not clear the fee floor, and that is now written down rather than
discovered later.** The only fee rule the node enforces is
`base_fee * gas_used`. Even the smallest transaction burns `GAS_TX_BASE` = 16 000
gas, so at the *cheapest* base fee either profile can reach, the floor is still
orders of magnitude above a 20 000 sat settle fee. Wiring D3 in as-is would have
`check_tx` reject every one of them as underpaid. L2 therefore needs either its
own fee path or an explicit exemption from the gas floor. The test
`l2_flat_fees_sit_below_the_gas_floor` asserts the gap and fails the day it is
closed, so the question cannot be quietly forgotten.

This is the same shape as the M2–M5 finding: a decided value that is correct as a
decision and inconsistent with the code that would have to enforce it.

## 37. Other fixes in this session

- The `add` signature had lost its closing `)` during a botched edit
  (`base_fee: u64, -> Result<...>`); repaired by reading the real delimiters
  rather than by another blind line-index edit.
- Clippy `manual_checked_ops` on the fee-rate division. Fixed with
  `checked_div(...).unwrap_or(u64::MAX)` rather than an `#[allow]`: a
  peer-supplied transaction with zero gas would otherwise be a panic, and a panic
  driven by peer data is a denial of service. `GAS_TX_BASE` alone is 16 000, so
  the branch is unreachable today — the point is that it stops being a crash if
  that ever changes.
- `docs/status.md` still claimed `net_vectors.json` "has no independent
  implementation yet … that check is still owed". Session 6 delivered it
  (`sim/net_reference.py`); the sentence was simply never updated. Corrected.

## 38. State at the end of this session

- `cargo test --workspace` — **232 pass, 0 fail** (was 219): 191 core unit, 11
  red-team, 16 net unit, 12 net integration, 2 wire-vector.
- `cargo fmt --all --check`, `RUSTFLAGS="-D warnings" cargo clippy --workspace
  --all-targets`, `cargo build --workspace --release` — all exit 0.
- All five Python sims exit 0. **Note:** `difficulty_attack_sim.py` and
  `net_reference.py` take no `--check` flag — passing it makes argparse exit 2.
  Run them bare. And when looping over the sims, capture the *python* exit status,
  not `tail`'s: a pipeline silently reported every script as passing on the first
  attempt of this session.
- **The mempool is not wired to anything.** `lib.rs` exports it; nothing imports
  it. No miner builds from it, no peer feeds it. Deliberate — the same
  module-first pattern M2–M5 landed with. Step 2 is what makes it live.
- Two stale `jnt-node serve` processes from an earlier session (srv_a/srv_b, the
  two-node P2P experiment, still listening on 127.0.0.1:23347) held a lock on
  `target/release/jnt-node.exe`, so the release build failed with
  `failed to remove file … Access is denied`. Killed them; the build then
  succeeded in 25 s. If a release build fails that way again, check `tasklist`
  before suspecting the code.
- `docs/roadmap.md` still carries uncommitted changes I did not make. Untouched,
  unstaged, uncommitted.
- **Nothing is committed.** Session 7 exists only in the working tree.
---

# Working memory — session 8: mempool integrated into L1 (Step 1A)

**Date:** 2026-10-06
**Scope:** Step 1A — wire the mempool into L1 — plus the required inspection of the
fee model before any L2 work.
**Outcome:** mempool is live in the chain. 242 tests pass. **No commit.**

---

## 39. What "integrated" means, and what was deliberately kept out

Three methods on `Chain`, all inside `jnt-core`, none of them aware of sockets or
files:

- **`mine_from_pool(pool, miner, now)`** — selects at the next block's height and
  base fee, mines, then evicts *exactly what the block contains*. Evicting the
  whole selection would drop transactions the gas or byte cap left out, and those
  are the best candidates for the next block. A rejection by `build_block` still
  removes the entry: the pool is a snapshot of what the next block was expected to
  build on, and a rejection means that expectation was wrong.
- **`confirmed_above(from_height)`** — transactions canonical blocks confirmed
  since the caller's cursor. This is the path a *peer's* block takes to evict from
  the pool; without it, relayed blocks would confirm transactions that stayed
  pooled forever.
- **`reconcile_mempool(pool, from_height)`** — the whole operation: evict what the
  chain confirms, re-admit what a reorg un-confirmed, return a report.

Re-admission goes through `add`, and therefore through the *new* base fee and the
new UTXO set. A disconnected transaction whose input the winning branch consumed
is therefore **refused**, and that is counted and asserted rather than treated as
an error: a reorg is allowed to invalidate a transaction. Re-admitting directly
into the entries map would have re-pooled something no block can ever include.

## 40. The bug: a second reorg destroyed the first reorg's transactions

`disconnected_txs` was cleared at the top of `reselect` and **assigned** when a
reorg committed. A syncing node submits blocks in a burst, so two reorgs landing
before the caller reconciled is ordinary behaviour, not an edge case:

1. reorg A rolls back block N → `disconnected_txs = [payment]`
2. reorg B (the next block arrives) → `clear()` wipes `[payment]`, then
   `disconnected_txs = []` because B's own rollback disconnected nothing
3. the pool re-admits nothing

No error, no log. The user's payment was valid, mined and broadcast, and it simply
did not come back.

Fixed by making published sets **append-only**: nothing clears the set except the
caller draining it, and a reorg only ever *adds* to it, and only after the reorg
has committed — a reorg that fails is restored wholesale, so publishing its list
would put back transactions the canonical chain still contains.

**Red-team proof.** The `clear()` was re-instated and all three reorg tests failed
(`exactly the orphaned payment`, `the payment was not re-admitted`, `the payment's
input is gone — re-admitting it would relay something no block can include`).
Restored, all three pass.

## 41. Two traps, one of them in the new code

**Trap A — plumbing two methods that both consume the same resource.** The
reorg test drained with `take_disconnected()` and *then* called
`reconcile_mempool`, which drains internally. The second drain saw nothing, so
re-admission was a silent no-op reporting `readmitted: 0` with no error. It looked
exactly like a library bug and cost three debugging rounds. Two fixes, both
applied:

- the drain and the reconcile are now tested in **separate** tests, so each
  contract is pinned on its own; and
- the test that uses `reconcile_mempool` no longer drains first, with a comment
  saying why.

The generalisable lesson, and the third time in this project it has appeared: an
API where two methods both consume the same thing will be misused, and the
misuse will be silent. A caller with one job — reconcile the pool — should have
one method.

**Trap B — the maturity rule again, now through the miner.** The full-pool test
spent coinbases from heights 1..=40 while validating against height 41. Every
output in this ledger is subject to `coinbase_maturity`, so heights 32+ were
legitimately immature and the test reported `unexpected refusal at height 32:
coinbase at height 32 immature until 42`. Same trap as session 7's `H = 100`;
this time the fix was to bound the loop at 31 with a comment explaining the
arithmetic.

## 42. The fee model, inspected as instructed

Confirmed against the code, not the docs:

- the only fee rule is `fees::required_fee(base_fee, gas_used) = base_fee *
  gas_used` (`fees.rs`);
- `GAS_TX_BASE` = 16 000 (`tx.rs`), so the *floor* for even the smallest
  transaction is `base_fee_min_sat * 16 000` — 1 600 000 sat on mainnet;
- D3's largest fee is `TxSettle` at 20 000 sat, about 80x below that floor.

So wiring D3 in as-is has `check_tx` reject every L2 transaction as underpaid.
Four options are written up in `docs/status.md`. The recommended one is option 3:
give the five L2 types their own fee schedule and route the flat fee through the
existing `split_fees` 50/50 burn/PSCB split, so `full_base` is the flat fee
itself. That preserves the M1 invariant exactly, creates no exemption, and leaves
the L1 floor alone. Rejected: raising the fees (defeats the point of flat fees),
a bare exemption (a second rule written as an exception is the easiest kind to
widen by accident), and a separate L2 fee market (large new mechanism for five
transaction types, and reversible later).

**Deliberately not implemented and not put into SPEC.md.** It changes what a JNT
price means for L2 work and needs the user's sign-off first. The canary test
`l2_flat_fees_sit_below_the_gas_floor` fails the moment the gap closes, so this
cannot be settled by accident in a later commit.

## 43. Restart behaviour, stated rather than left implicit

The pool is in-memory only. A node restarts with an empty pool and reconciles from
the tip: nothing to recover, nothing stale to distrust, so the cursor only has to
be held within a run. This is honest rather than complete — a production node
would persist the pool — and it is written into `docs/status.md` so it is not
mistaken for an oversight. Persisting it belongs with `jnt-store` (step 3), not
before.

## 44. State at the end of this session

- `cargo test --workspace` — **242 pass, 0 fail** (was 232): 191 core unit, 10
  mempool↔chain integration, 11 red-team, 16 net unit, 12 net integration, 2
  wire-vector.
- `cargo fmt --all --check`, `RUSTFLAGS="-D warnings" cargo clippy --workspace
  --all-targets`, `cargo build --workspace --release` — all exit 0.
- All five Python sims exit 0.
- `docs/roadmap.md`: **appended** a `## 19. L1 implementation status` section.
  Nothing above it was edited, because the file carries 516 uncommitted
  insertions from another author and rewriting would have mixed two changes. The
  diff confirms this: insertions went 516 → 567, deletions stayed at 15.
- **Not started:** step 2 (tx relay over P2P), step 3 (`jnt-store`), step 4
  (`blst`), step 5 (`cargo-fuzz`), step 6 (L2). The dependency order is
  unchanged, and the mempool is now positioned to be fed by step 2.
- **No commit.** The user asked for the work to be finished and verified first,
  then for a summary and a proposed commit message.
# Working memory — session 9

## Milestone 1 of the remaining roadmap: P2P transaction relay

Continues from `cbd194f` (mempool + L1 integration). Step 2 of the build order:
connect the pool to the network without letting the network near consensus.

**Consensus: unchanged.** SPEC.md §13.14 was written first and is normative for
relay; §13.5 gained `msg_type = 10` (`TX`, additive under the existing freeze
rule so a v0.2 node ignores it rather than disconnecting) and §13.8 gained one
bound. Nothing in the relay path can reach `Chain::submit`.

### What was built

- `jnt-net/src/msg.rs`: `MessageType::Tx = 10`, `INV_TYPE_TX = 0`,
  `Message::Tx`, with the same bounded-decode discipline as the other payloads.
- `jnt-net/src/relay.rs` (new): request set, advertised-but-unrequested queue,
  loop-suppression set, per-peer rate window, request expiry, and both response
  budgets (one block's worth of bytes, `max_tx_inv_batch` transactions).
- `jnt-net/src/net.rs`, `peer.rs`: announce / request / serve / admit, ban scoring
  on invalid transactions, connect-time pool announcement, peer registration
  moved into `spawn_peer`, `PeerTable`, stopped-peer release.
- `jnt-node/src/main.rs`: mines from the pool, reconciles unconditionally (a reorg
  can land at the same height), prints relay counters, `send --relay <addr>` and
  `serve --no-mine`.
- `jnt-net/tests/tx_relay.rs` (new, 10 tests) and 11 unit tests in `relay.rs`.
- `tests/vectors/net_vectors.json` regenerated; `sim/net_reference.py` extended
  and now re-derives 32 wire values from the §13 prose.

### Bugs found

Three, two of them proven by a failing test first.

1. **A banned peer stayed in the live set.** `stop()` shuts the socket down but
   the reader thread parked in a blocking read does not reliably wake — on Windows
   it did not, for the whole of a test that polled for over a second. The peer
   kept its slot, kept receiving broadcasts, and kept holding relay and sync
   state. Fixed by releasing stopped peers from `poll_events` instead of waiting
   for the reader. Red step: with the sweep neutralised, exactly one test fails.

2. **A one-shot submitter's transaction was discarded.** The sweep introduced in
   (1) keyed off the `stopped` flag, which the reader thread also sets when a
   stream simply ends. A cleanly closing peer therefore looked banned, and its
   queued transaction was released before it was read: `accepted 0 refused 0`,
   nothing observable anywhere. This is the path `send --relay` takes. Fixed by
   giving the reader its own flag and requiring the sweep to see a peer that is
   stopped *and* still being read from. Red step: with the guard removed, the
   test fails with that exact symptom.

   Worth recording *how* this was found: an end-to-end run with two real node
   processes showed a transaction that never appeared in any chain and no log line
   explaining why. Instrumenting the relay reader proved the frame was being read
   (`ty=10 len=292`) while the pool counted nothing, which located the defect in
   the release ordering rather than in the wire format. A library-only test would
   have hidden it, because the CLI path is the only one that closes immediately.

3. **A peer could stall relay permanently by announcing and not delivering.**
   The request set was global and had no deadline, so `max_relay_in_flight`
   unfulfilled announcements left no room for any other request — from any peer —
   and the hoarded txids were marked as already requested, so a peer that did hold
   them was ignored too. Thirty-two bytes per announcement bought a node-wide
   stall. Fixed with `tx_request_timeout` and a retry against whoever announces
   next; the txid is never blacklisted.

### Verification

- `cargo fmt --all --check`, `RUSTFLAGS="-D warnings" cargo clippy --workspace
  --all-targets`, `cargo test --workspace`, `cargo build --workspace --release` —
  all exit 0. Workspace tests: 262 (was 242).
- All five Python sims exit 0, including the wire-format crosscheck (32 values).
- **Two real processes**: `serve` on A with a listener, `serve --connect --no-mine`
  on B, and a third process running `send --relay`. A logged
  `relay accepted 1 refused 0 (pool holds 1)`; block 75 on B's chain holds the
  transaction (outputs 1 000 000 000 and 6 599 824 000); B reports the 10 JNT
  output as spendable at height 75. Exactly one block contains it.

### Honest limits

- A `TX` has no acknowledgement, so a sender learns only that a node took the
  frame. `send --relay` prints that distinction rather than implying acceptance.
- The pool is still in-memory; a restart drops what it held and never
  re-requests it. This is why step 3 (persistent storage) comes next.
- Announce-on-connect is capped at `max_inv_per_msg`, so a pool larger than 500
  entries is not fully announced to a new peer.
- CI was not run (no GitHub Actions locally); past sessions saw CI-only lint and
  rustfmt differences, so a hotfix commit remains a possibility.
- No commit of `docs/roadmap.md`: the file carries another author's uncommitted
  work, and my append is contiguous with it, so it cannot be staged separately.

## Session 10 — Step 3: persistent storage (crates/jnt-store)

Committed as milestone 2. The O(n)-per-block `blocks.json` rewrite is gone;
every node command now reads and writes an append-only, checksummed block log
(`store/blocks.log`) plus atomic metadata (`store/meta.json`), via the new
`jnt-store` crate. Legacy `blocks.json` chains migrate once, on first open.

Design invariants: no index file (rebuilt by scan at open — a corrupt index is
a failure mode that cannot exist); canonical chain is one metadata row, so a
reorg is a rename; torn tails are dropped and reported, damage-with-data-after
refuses to open with an offset. The crate holds zero consensus rules; the
worst a store bug can do is lose a block, never change one.

Five real bugs were caught by the crate's own tests during development: the
block/UTXO tag collision (a block's first byte is version 1), tip height taken
from the wrong end of the ancestry walk, a checksum-line off-by-one in the
metadata parser, genesis missing from the height walk, and a stale file length
underflowing the scan on sub-header files.

Verified: 30 store tests; real-binary e2e including a two-node serve run where
node B was force-killed (`taskkill /F`) and restarted twice, replaying cleanly
both times; legacy JSON migration verified. 293 workspace tests (was 263),
fmt/clippy -D warnings/release clean, all five sims green. docs/roadmap.md
still carries the other author's uncommitted work and remains untouched.

## Session 10 (cont.) — Step 4: real BLS via blst

SPEC.md §14.5 written BEFORE any code (semantics first): min-pk BLS12-381,
protocol-namespaced DST, IETF KeyGen fixtures, sorted-order set hashing,
bitmap padding = malformed, replay impossible by construction, rotation
deferred to unresolved §14.6. `RealBls` in crates/jnt-core/src/bls.rs:
derive/sign/aggregate/fast-aggregate-verify with full point validation; wired
into `verify_checkpoint` behind the existing `BlsVerifier` trait. MockBls kept
for CI structural tests only, and a test proves the difference (forgery:
mock accepts, real rejects).

Two bugs caught by red tests: validator_set_hash hashed caller order (two
identities for one committee — fixed to sorted order matching ValidatorSet);
a fixture test caught a hand-guessed key hash (real value committed). 18
adversarial checkpoint tests green. 341 workspace tests total, all checks
clean. M5 still NOT consensus-active — the honest boundary is §14.6 validator
economics, a user decision, not mine.
