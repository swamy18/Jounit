# Status

What is built, what is verified, and what is not finished. Read this before
relying on anything here.

## Scope

Layer 1 (base layer) only, per SPEC.md. Layer 2 — Verified Work Certificates,
the useful-work layer that is the actual point of the project — is specced as a
roadmap item and is **not implemented**. There is no P2P layer: `jnt-node` is a
single-node chain. A coin with one node is not a network yet.

## Verified

- `cargo test -p jnt-core` — 102 tests pass. Includes an independent Python
  reference implementation of the PoW puzzle (`sim/jounit_reference.py`) and
  byte-level vectors in `tests/vectors/`.
- Node CLI end to end on the `mini` profile: init, mine 31 blocks, spend, verify
  (replays from genesis and diffs UTXO + supply), status. Fee burn reconciles
  exactly — 31 blocks issue 2356 JNT, live supply is 2355.99825 JNT, the
  0.00175 JNT difference being the destroyed base fee.
- Supply schedule matches design doc §16, including that only 298 000 of the
  304 000 JNT mini cap is reachable and the remainder is permanently
  unmintable rather than merely reserved.

## Known bugs found and fixed

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

## Design doc claims that do not hold

Design doc §28.9 reports a 40% attacker with a two-hour future-timestamp
allowance reaching ~104s average block time, and presents this as the reason for
tightening the limit to one block time. That figure is **not reproducible** and
cannot be: 104s is below the solve-time clamp floor (T/4 = 150s), so no
retarget can ask for a difficulty that low. The simulation's `--ablation` mode
strips the clamp and the difficulty floor and still does not land on 104s — it
drives difficulty to zero — so the original table was produced by some further
difference in its model that cannot be recovered from the document.

What *is* established: under this specification, block time stays within ~1% of
target across every allowance from one minute to two hours. The short allowance
is retained anyway as defence in depth, since it bounds how far ahead a single
block can be stamped, which matters once an attacker reaches 50% and can move
the median itself. SPEC.md §6.1 states this accurately rather than repeating
the design doc's number.

The ablation table has a caveat worth knowing when reading it: any variant that
never recovers ends up pinned on the difficulty floor, so rows matching the
full-spec row may be there for that trivial reason. Raise `--start-difficulty`
to separate them.

## Not done

- **Layer 2 / Verified Work Certificates.** The core of the project's premise.
- **P2P.** No node discovery, no block/tx relay, no mempool gossip.
- **Persisted UTXO indexing.** State is replayed from genesis on load, which is
  fine at test scale and will not be at 40M coins.
- **`puzzle_crosscheck.py` and `verify_vectors.py`** are referenced by SPEC.md
  §12 but do not exist. `sim/jounit_reference.py` exists and is exercised, but
  nothing currently runs it automatically or diffs it against the Rust output.
- **`difficulty_vectors.json` is consumed by the test suite;
  `supply_vectors.json` is generated but not yet read by any test.** A test now
  asserts the supply file is at least valid JSON, which catches a truncated
  write but verifies nothing about its contents.
- **No fuzzing, no property tests, no adversarial block/tx corpus.**
- `chain.rs` carries a dead-code warning for a test helper (`fn out`).

## Known rough edges

- `jnt-node mine --help` tries to open a chain directory instead of printing
  help, so it fails confusingly on a fresh checkout.
- `--amount` on `send` is denominated in satoshis while every other printed
  figure is in JNT. This bit me during verification and is documented in the
  command's error message, but it should probably gain a unit suffix.

## Reproducing the difficulty work

```
cargo test -p jnt-core                                  # 102 tests
python sim/difficulty_attack_sim.py                     # attack containment
python sim/difficulty_attack_sim.py --ablation \
    --start-difficulty 100000                           # which rule is load-bearing
python sim/supply_schedule_sim.py                       # supply vectors
UPDATE_DIFFICULTY_VECTORS=1 cargo test -p jnt-core \
    --lib difficulty_vectors_are_stable                 # regenerate vectors
```

A second implementation that disagrees with `difficulty_vectors.json` has a
consensus split, not a rounding difference.
