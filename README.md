# Jounit (JNT)

An AI-native cryptocurrency. Mining that puts real work on GPUs and AI hardware
without weakening the security a blockchain depends on.

> **Status: code complete, not launched.** Every component described below is
> implemented, tested and green in CI. Mainnet has **not** launched — see
> [Not ready to launch](#not-ready-to-launch) for the specific reasons, which are
> configuration, operators and an external audit, not missing protocol.

---

## Contents

- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [What is built](#what-is-built)
- [Repository layout](#repository-layout)
- [Network profiles](#network-profiles)
- [Commands](#commands)
- [Testing](#testing)
- [Not ready to launch](#not-ready-to-launch)
- [License and trademark](#license-and-trademark)

---

## What this is

The principle every blockchain shares is *solving is hard, verifying is easy*.
Bitcoin's solution is pure hashing, which leaves GPUs idle and ties no energy to
anything useful.

Jounit keeps the principle and changes the work. Mining runs three stages:

1. **A SHA-256 hash chain** — carries the security. This is what a quantum
   adversary has to break.
2. **An integer-only neural network** — makes the work meaningful for AI hardware.
3. **A final hash** — binds both into the value that must fall below the target.

Two properties keep the neural stage a cost model rather than a liability:

- **Capped share.** The network must account for 30–50% of modelled work. A
  registry entry outside that band is rejected outright, so it can never become
  the weak link.
- **No floating point, anywhere.** Weights derive from the epoch id by SHA-256,
  the forward pass accumulates in `i64` and wraps to `i32`, and every integer is
  explicit. Two implementations on two machines produce identical digests — which
  is tested against an independent Python reference, not assumed.

Because weights come from the epoch id, no miner can precompute them before an
epoch starts.

---

## Quick start

Requires **Rust 1.75+** (developed and tested against 1.99) and **Python 3.11+**
for the simulations.

```sh
git clone https://github.com/swamy18/Jounit.git
cd Jounit
cargo build --release
```

```sh
# Create a chain directory and a miner wallet.
./target/release/jnt-node init   --network testnet --data-dir ./chain

# Mine blocks, then check the chain agrees with itself.
./target/release/jnt-node mine   --network testnet --data-dir ./chain --blocks 25
./target/release/jnt-node status --network testnet --data-dir ./chain
./target/release/jnt-node verify --network testnet --data-dir ./chain

# Run a P2P node. It mines by default, so it settles matured exits.
./target/release/jnt-node serve  --network testnet --data-dir ./chain \
                                  --listen 127.0.0.1:9833
```

`verify` replays the whole chain from genesis and diffs the resulting UTXO set,
supply, bond ledger and binding-finalized point against stored state. It is the
check worth running after any change.

Run `jnt-node help` for the full command list; every command accepts `--help`.

---

## What is built

| Area | What exists |
|---|---|
| **L1 consensus** (`jnt-core`) | Hybrid PoW, UTXO ledger with reorg undo, LWMA difficulty retarget, EIP-1559 base fee, rate-anchored supply, deterministic fork choice |
| **P2P** (`jnt-net`) | TCP framing, handshake isolation, block/tx/checkpoint/vote relay, locator sync, bounded orphan pool |
| **Layer 2** (`jnt-l2`) | Task contracts, six L2 transaction types, dispute engine, Verified Work Certificates, deposits and L2→L1 exits |
| **Validators** | Bonded stake (`bond.rs`), bond-order committee, unbonding, slashing, and production checkpoint signing (`signing.rs`) |
| **Fraud arbitration** | Canonical CPU reference decides the verdict; signed votes relay over P2P; a quorum produces the settlement |
| **Payments** | Machine payments, service receipts, reputation, spending policies, streaming micro-payments |
| **Worker SDK** (`jnt-worker`) | Discovery → claim → execute → submit → dispute → certificate, plus L2→L1 exit queuing |

### The five protocol mechanisms

| # | Mechanism | Consensus-active |
|---|---|---|
| M1 | 50/50 PSCB base-fee split | **Yes** |
| M2 | Anti-collusion slash vault | No, but holds L2 fraud slashes |
| M3 | Canonical compute IR | No, but the CPU reference decides fraud |
| M4 | Memory-hard HBM puzzle | **No** — deliberately unregistered, see below |
| M5 | BLS aggregate finality | **No** on mainnet (activation height is 0) |

**Why M4 is off on purpose.** `hbm_pow.rs` implements the memory-hard
permutation and ships nine tests, but it is not registered as a `puzzle_id`.
Registering it would change the consensus puzzle without an independent security
review of the memory parameters — that is not a mistake worth making before a
review. Base PoW (`puzzle_id = 1`) is the active mechanism.

### How withdrawals work

An owner deposits to a derived sink, queues an exit on L2, and after finality a
**permissionless crank** settles it: a proof-authorised sink spend on L1 that
pays the destination the principal and the claimant the fee the owner prepaid.
Anyone can obtain the claims with `GET /v1/exit/crankable` and build a block with
them, so the crank is permissionless in practice, not just in the rules.

### How fraud is decided

`DisputeEngine::resolve` runs the canonical CPU reference over the disputed
contract and maps the result onto exactly one verdict — no caller can supply it.
Committee members each sign one vote per held key, votes relay over P2P, and a
quorum aggregates into a `Settle` transaction the existing settlement path applies
and re-verifies from scratch.

An **unchallenged** result is paid, because the timeout economics require a
challenge to overturn a settlement. What the protocol guarantees is that such an
outcome is never *represented* as verification: its certificate says
`WindowElapsed`, `asserts_correctness()` is false for it, and `validate_verified`
refuses it. See [docs/mainnet-readiness.md](docs/mainnet-readiness.md).

One limitation worth stating plainly: an arbitration vote signs the settle
*decision*, so a signature verifies on any chain carrying that decision. Network
and height are checked against the node's own chain at tally time rather than
cryptographically bound into the signature. Binding them into the hash would
change `SettlePayload::signing_hash` — a consensus change — so it is documented
in [`arbitration.rs`](crates/jnt-core/src/arbitration.rs) rather than made
unilaterally.

---

## Repository layout

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | **Normative.** Where a disagreement exists, this wins. |
| `crates/jnt-core/` | Protocol implementation. All consensus logic. |
| `crates/jnt-net/` | P2P wire protocol, sync and relay. |
| `crates/jnt-store/` | Append-only checksummed block log, crash recovery. |
| `crates/jnt-l2/` | Layer 2: contracts, disputes, certificates, exits. |
| `crates/jnt-node/` | CLI and node daemon. |
| `crates/jnt-worker/` | Worker-side SDK. Client only, no consensus. |
| `crates/jnt-mcp/` | Keyless MCP surface over agent identity and payments. |
| `fuzz/` | 14 cargo-fuzz targets over the attacker-controlled boundaries. |
| `sim/` | Independent Python reference and attack simulations. |
| `tests/vectors/` | Consensus vectors. Generated from source, never hand-edited. |
| `docs/` | Design records, audits and readiness reports. |

Seven crates in one workspace. **All consensus logic lives in `jnt-core`**, which
has no I/O, no clock and no network. The `mini` profile is the same code with
different parameters — never a second implementation — so anything tested on
`mini` is the production code path.

---

## Network profiles

Same code, different numbers.

| | `mainnet` | `testnet` | `mini` |
|---|---|---|---|
| Block time | 600 000 ms | 1 000 ms | 1 000 ms |
| Halving period | 262 800 | 2 000 | 2 000 |
| Start reward | 76 JNT | 76 JNT | 76 JNT |
| Finality depth | 100 | 20 | 20 |
| Coinbase maturity | 100 | 10 | 10 |
| Genesis validators | **none** | 4 deterministic | 4 deterministic |
| Binding finality | **off** | on at height 20 | off |
| Exits | **off** | on at height 1 | on at height 1 |

**Supply.** Premine is **0%**, enforced in code. There is no stock cap: the ladder
issues 39 157 124 JNT and the approved tail pays 0.1 JNT/block forever, bounded
by a rate anchor (≤ 1 % of issued supply per halving period). See
[docs/monetary-policy.md](docs/monetary-policy.md).

`mainnet` deliberately ships with no committee and no activation, so it fails
closed rather than verifying against nothing.

---

## Commands

```
jnt-node <COMMAND> [OPTIONS]

  init        Create a chain directory, a miner wallet and the genesis block
  mine        Mine blocks and extend the chain
  send        Spend from a wallet address, local or over P2P
  status      Print chain tip, difficulty, supply, wallet balance, L2 pipeline
  verify      Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance     List the unspent outputs of an address
  wallet      Create or list wallets
  validator   Add or list checkpoint-signing keys
  export      Write the canonical chain to JSON
  serve       Run a P2P node: relay, sync, opt-in REST API, exit crank, signing
```

Common options: `--network <mainnet|testnet|mini>` (default `mini`) and
`--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--peers`, `--interval`,
`--api-listen` and `--no-mine`. `send --amount` is in satoshis while printed
figures are in JNT.

### Validators

```sh
jnt-node validator --network testnet --data-dir ./chain --add --label my-key
jnt-node validator --network testnet --data-dir ./chain     # public keys only
```

Keys live in `<data-dir>/validators/`, mode 0600 on unix, deliberately separate
from `wallets.json` — a wallet holds funds this node spends, a validator key
signs consensus messages. Backing up one is never the same act as backing up the
other. A node with no keys signs nothing and still verifies and relays.

---

## Testing

```sh
cargo test --workspace                                   # 993 tests, 0 failures
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python sim/verify_vectors.py --check                     # consensus vectors
```

Targeted suites for the fast loops:

```sh
cargo test -p jnt-core --lib arbitration::    # fraud-arbitration votes
cargo test -p jnt-core --test cp_signing_nodes # quorum, conflicts, restart
cargo test -p jnt-core --test bond_stake      # bonded-stake attacks
cargo test -p jnt-l2  --test unverified_result # the unchallenged-result rule
cargo test -p jnt-node --test arbitration_path # full fraud lifecycle
cargo test -p jnt-net  --test arbitration_votes # 3 nodes, real TCP
cargo test -p jnt-node --test exit_crank_api   # withdrawal flow over HTTP
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release
build, the vector cross-checks, attack simulations, and all fourteen fuzz targets
on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a
tagged tree before publishing artifacts with checksums.

**Vectors.** `tests/vectors/` holds the consensus byte layouts, generated only
from the implementation. `sim/jounit_reference.py` is a second PoW implementation
written from `SPEC.md` rather than from the Rust, and it reproduces all 21 puzzle
digests — that agreement is the evidence the spec is unambiguous rather than
merely self-consistent.

**Fuzzing.** 14 cargo-fuzz targets over L1 wire, mempool, storage and
checkpoints; L2 codec, disputes, state and certificates; and the worker. They
assert capability invariants — decode/encode inversion, bounded allocation, value
conservation under adversarial transaction programs — not just panic-freedom.

**Red team.** `crates/jnt-core/tests/redteam.rs` holds 12 adversarial integration
tests, each confirmed to fail against the code it now guards. The full record of
defects found and fixed is in [docs/status.md](docs/status.md).

---

## Not ready to launch

The code is done. Launching mainnet is blocked by things no amount of code
replaces.

| Blocker | Why it is blocked |
|---|---|
| **No validators** | `mainnet` declares an empty committee. The ledger that would hold bonded stake is built and tested, but no operator is bonding 5 000 JNT to run a validator. Without a committee, checkpoint verification fails closed. |
| **No independent security review** | 993 passing tests are not an external audit. This cannot be self-certified, by anyone, ever. |
| **Activation heights unset** | `exit_activation_height` and `finality_activation_height` are `0` on mainnet. These are deliberately left off, and should be set only after a launch-candidate rehearsal proves the whole path. |
| **Arbitrator key custody** | The arbitration transport is built; who runs the arbitrators is an organisational decision. |
| **Operations** | No bootnodes, no log shipping, no published PGP key. Artifacts are unsigned because no signing key is published. |

What this means in practice: **a fresh `jnt-node init --network mainnet` runs
today, and on it withdrawals and binding finality are both inactive.** That is
fail-closed, not broken — no funds can be lost — but users should know before
they point real money at it.

`testnet` is the appropriate next milestone and is the right place to rehearse
everything above. [docs/mainnet-readiness.md](docs/mainnet-readiness.md) tracks
each item with its evidence.

---

## License and trademark

**Code: `MIT OR Apache-2.0`** — the standard permissive Rust dual licence. Both
texts ship at the repo root (`LICENSE-MIT`, `LICENSE-APACHE`). You may use,
modify, run, audit and redistribute the software, including commercially.

**Name and marks: trademarked.** The *Jounit* name, the `JNT` ticker and the
project's logos are trademarks, not part of the code licence. See
[TRADEMARK.md](TRADEMARK.md) for what is permitted and what is not.

The distinction matters, and it is the same one Bitcoin uses: **the code is open
so anyone can run it, and the name is protected so nobody can pass themselves off
as us.** Nothing in an open-source licence can stop someone forking the code —
that is deliberate, and it is how the ecosystem works. What the trademark stops
is someone shipping a product under our name that is not this software.

If you want to use the name or marks commercially, or you want a licence other
than the one above, get in touch first.

---

Full protocol specification: [`SPEC.md`](SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).