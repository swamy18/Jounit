# Jounit (JNT)

An AI-native cryptocurrency: mining that pulls compute onto GPU/AI hardware
without weakening the security that a hash chain depends on.

**Status: base layer only, single node, not a usable network yet.** Read
[Status](#status) before treating this as anything but a work-in-progress. The
interesting part of this project — the useful-work layer — is not built.

## The idea

Bitcoin's principle is that solving must be hard and verifying must be easy. Its
mining is pure hashing, which means GPUs sit idle and the energy spent has no
relationship to anything useful.

Jounit keeps the principle and changes the work. Mining runs three stages:

1. A SHA-256 hash chain — carries the security, and is the brute-force
   expensive part.
2. An integer-only neural network — makes mining meaningful for AI hardware.
3. A final hash — binds both together.

The NN stage is capped at 50% of measured work, so it can never become the
weak link. Its weights are derived from the epoch id, so nothing can be
precomputed before an epoch starts and every result is identical on any
hardware — no floating point, no hardware-specific drift.

The base layer is this, plus an ordinary UTXO ledger. The intended second layer
is a useful-work layer where miners submit checkable solutions to real problems
(mathematical proofs, verified code fixes, circuit designs) and earn for
correctness. That layer is specced as a direction and **not implemented**; see
the design doc's Section 5.

## Repository layout

| Path | What it is |
|---|---|
| `SPEC.md` | **Normative.** The protocol specification. Where a disagreement exists, this wins. |
| `AI_Native_Currency_Idea (1).md` | The original design document (Hinglish). Intent and rationale; superseded by SPEC.md on any point of detail. |
| `crates/jnt-core` | The protocol implementation. |
| `crates/jnt-node` | A CLI over `jnt-core`. Single-node chain; no P2P. |
| `sim/` | Python: independent protocol reference, attack and supply simulations. |
| `tests/vectors/` | Consensus vectors. Regenerate, never hand-edit. |
| `docs/status.md` | What is verified, what is broken, what is missing. |
| `Researchpapers_wecanget_benefit/` | Third-party papers, included as reference. Not ours. |

`jnt-core` holds all consensus logic. The mini network profile is the same code
with different parameters, never a second codebase — so anything tested on mini
is the production code path.

## Building and running

Requires Rust 1.75+ (developed against 1.95) and Python 3.11+ for the
simulations.

```sh
cargo build --release

# Create a chain directory with a miner wallet.
./target/release/jnt-node init --network mini --data-dir ./chain

# Mine, spend, and verify.
./target/release/jnt-node mine   --network mini --data-dir ./chain --blocks 30
./target/release/jnt-node status --network mini --data-dir ./chain
./target/release/jnt-node verify --network mini --data-dir ./chain
```

`verify` replays the chain from genesis and diffs the resulting UTXO set and
supply against stored state — it is the check worth running after any change.

Two profiles, selected with `--network`:

| | mainnet | mini |
|---|---|---|
| Block time | 10 min | 1 s |
| Halving period | 262 800 blocks (~5 y) | 2 000 blocks |
| Supply cap | 39 945 600 JNT | 304 000 JNT |

Other commands: `send`, `balance`, `wallet`, `show-block`, `export`. `--help` on
any of them prints usage.

Note `send --amount` is in **satoshis**, while every printed figure is in JNT.

## Supply

76 JNT per block, halving every 262 800 blocks, 0% premine. The ladder is
halved in whole JNT, not by shifting satoshis, giving
76, 38, 19, 9, 4, 2, 1, 0 JNT.

Because each halving rounds down, the seven non-zero steps of the ladder pay out
39 157 200 JNT in total — the same as 149 periods at the full 76 JNT reward —
against a 39 945 600 cap. The remaining 788 400 JNT is **permanently
unmintable**, not merely reserved: anyone can confirm it by summing the ladder.
The cap is enforced in code at the point of minting.

## Testing

```sh
cargo test --workspace                                  # 114 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

CI runs all of the above plus the vector cross-checks on every push.

The protocol also has a second, independent implementation in Python
(`sim/jounit_reference.py`), written from SPEC.md rather than from the Rust
source. It reproduces all 21 puzzle digests in `tests/vectors/`. That
agreement is the actual evidence SPEC.md is unambiguous rather than merely
self-consistent with the code that implements it.

```sh
python sim/puzzle_crosscheck.py         # Rust vs independent Python
python sim/verify_vectors.py --check    # all four vector files
python sim/difficulty_attack_sim.py     # timestamp-attack containment
```

Vectors are generated from the implementation and regenerated only by it:

```sh
UPDATE_PUZZLE_VECTORS=1     cargo test -p jnt-core --lib puzzle_vectors_are_stable
UPDATE_DIFFICULTY_VECTORS=1 cargo test -p jnt-core --lib difficulty_vectors_are_stable
UPDATE_SER_VECTORS=1        cargo test -p jnt-core --lib serialization_vectors_are_stable
python sim/supply_schedule_sim.py
```

A second implementation disagreeing with these vectors has a consensus split,
not a rounding difference.

## Status

The base layer is implemented and tested. **It is not a usable network.** One
node cannot talk to another, so there is nothing here you could mine on with a
friend.

Not built:

- **Layer 2, the useful-work layer** — the project's actual premise
- **P2P** — no node discovery, no block or transaction relay, no mempool
- **Persisted UTXO indexing** — state replays from genesis on every load, which
  will not scale to 40M coins
- **Coverage-guided fuzzing** (`cargo-fuzz`); deterministic property tests
  cover the parsers instead

`docs/status.md` is the honest, current version of this list, along with the
consensus bugs found and fixed so far and one design-doc claim that turned out
not to hold.

### Known consensus bugs, found and fixed

Recorded because the pattern matters more than the individual fixes.

**The difficulty retarget had no restoring force.** It computed
`avg_solve / T`, which is scale-invariant — every difficulty was a fixed point.
Halving the hashrate produced blocks at 2T, the rule answered "difficulty 2", and
the interval ran away to 4T. It is now multiplicative from the previous
difficulty. The Zawy weights were also inverted, weighting the oldest solve time
most heavily.

Both were invisible to the original tests because every one of them used
*uniform* solve times, where neither the weighting direction nor the missing
`d_prev` factor can show up.

**`Transaction::value_out` could overflow.** Summing output values with `.sum()`
panicked in debug and wrapped in release. Since the total is compared against
resolved input value, a wrapped sum reads as a transaction creating value from
nothing — an inflation primitive.

**A puzzle-spec overflow guard could not fire.** It computed its bound in `i64`
from a `usize` input, so the cast wrapped before the comparison ran, passing
exactly the inputs it existed to reject.

Each was verified by restoring the faulty code and confirming a test fails.

## Licence

`Cargo.toml` declares `MIT OR Apache-2.0`. **No `LICENSE` file has been added
yet** — this needs resolving before the code is distributed.

## Status of the numbers

Design-doc figures for a difficulty-manipulation attack could not be reproduced
and should not be treated as established. `SPEC.md` §6.1 states what is actually
measured: block time stays within ~1% of target from a one-minute
future-timestamp allowance up to Bitcoin's two hours.