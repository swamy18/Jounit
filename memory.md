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

## 22. Next steps achieved (Session 4)

All 7 items from §22 were completed, plus the 5 protocol mechanisms:
1. `jnt-net`: peer lifecycle (`peer.rs`), thread-per-connection, frame codec.
2. `jnt-net`: handshake state machine with mutual version exchange and magic verification.
3. `jnt-net`: locator-based sync loop (`syncer.rs`), orphan block pool bounded at 512 entries.
4. `jnt-node serve`: run loop owning the `Chain`, wired to `P2pNode`.
5. Loopback integration tests (`crates/jnt-net/tests/integration.rs`):
   - Two nodes converge regardless of arrival order (§13.11 inv 2)
   - Cross-network handshake rejected at connect (§13.11 inv 4)
   - Replayed blocks byte-identical to locally mined blocks (§13.11 inv 1)
   - Invalid blocks never enter store
   - Locator generation and fork point recovery
6. 5 Protocol Mechanisms implemented:
   - M1: 50/50 PSCB Base Fee Split (`fees.rs`, `chain.rs`)
   - M2: Time-Locked Compute Reserve & 50/50 Anti-Collusion Slash Vault (`slash.rs`)
   - M3: Hardware-Agnostic Canonical Compute IR (`compute_ir.rs`)
   - M4: Memory-bound HBM scratchpad PoW puzzle (`hbm_pow.rs`)
   - M5: Sovereign BLS aggregate finality gadget checkpoints (`bls_checkpoint.rs`)
7. Verification status:
   - `cargo test --workspace`: 207 tests pass (178 core unit, 9 core redteam, 10 net unit, 10 net integration)
   - `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings
   - `cargo fmt --all --check`: clean
   - `python sim/verify_vectors.py --check`: clean (all 4 vector files verified)
   - `python sim/puzzle_crosscheck.py`: clean (21 digests agree across 7 vectors)
   - `docs/status.md` and `README.md` updated to reflect the operational P2P layer and M1-M5 mechanisms.