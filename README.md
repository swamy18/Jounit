# Jounit (JNT)

An AI-native cryptocurrency: mining that pulls compute onto GPU and AI hardware
without weakening the security a hash chain depends on.

> **Status: Layer 1 base layer + P2P networking + Layer 2 core implemented.** The
> core protocol includes hybrid hash + neural PoW, 5 protocol mechanisms (PSCB fee
> split, Time-Locked slash reserve, canonical compute IR, HBM scratchpad PoW, and
> BLS finality gadget), `jnt-net` block relay and sync, and a working Layer 2
> (`jnt-l2`): task contracts, the five L2 transaction types, D3 fees, a complete
> dispute engine with M2 slashing and M1 PSCB accounting, and Verified Work
> Certificates for settled work. The worker SDK (`jnt-worker`, Phase 5):
> a task-economy client for humans, AI agents and machines — discover,
> claim, execute, submit, dispute participation, certificate observation,
> and earnings derived from protocol state. Phase 6 (integration + testnet) has
> begun: L2 transactions now ride inside L1 blocks and L2 state is rebuilt from
> the chain (**SPEC.md §19.1**), and the node replays it on every accepted
> block (`status`/`verify` surface it). Still ahead:
> the L1→L2 funding bridge, the worker↔node transport, the genesis validator
> committee and binding finality. Read [Status](#status).

---

## Table of contents

- [Status](#status)
- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Architecture](#architecture)
- [Protocol mechanisms (M1–M5)](#protocol-mechanisms-m1m5)
- [P2P networking (`jnt-net`)](#p2p-networking-jnt-net)
- [Protocol](#protocol)
  - [Blocks and headers](#blocks-and-headers)
  - [Proof of work](#proof-of-work)
  - [Difficulty adjustment](#difficulty-adjustment)
  - [Timestamp rules](#timestamp-rules)
  - [Supply](#supply)
  - [Fees and burn](#fees-and-burn)
  - [Transactions and signatures](#transactions-and-signatures)
- [Consensus rules](#consensus-rules)
- [Network profiles](#network-profiles)
- [Node CLI reference](#node-cli-reference)
- [Testing and verification](#testing-and-verification)
- [Security: defects found and fixed](#security-defects-found-and-fixed)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Status

**Built:** a complete, tested, specification-first L1 core and P2P networking layer:
- **L1 Core (`jnt-core`)**: Hybrid hash + neural proof of work, UTXO ledger with undo, LWMA difficulty adjustment, EIP-1559 base fee with 50/50 PSCB split, fixed-cap halving supply schedule, and deepest-chain fork choice.
- **5 Protocol Mechanisms (M1–M5)**: 50/50 fee split (M1 — the only consensus-active one), 50% anti-collusion slash vault + 1-year time-locked compute reserve (M2), hardware-agnostic canonical compute IR (M3), memory-bound HBM scratchpad PoW (M4), and a sovereign BLS aggregate finality gadget (M5). See the M1–M5 table in [Protocol mechanisms](#protocol-mechanisms-m1m5) for what each one does and does not yet affect.
- **P2P Networking (`jnt-net`)**: TCP framing, handshake isolation, peer lifecycle, locator-based sync, and bounded orphan pool.
- **Node Server (`jnt-node serve`)**: Multi-peer P2P node daemon.
- **Layer 2 (`jnt-l2`)**: Task contracts over the five L2 transaction types, D3 flat fees split 50/50 burn/PSCB, escrow accounting, replay protection, a complete **dispute engine** (evidence validation, the M3 CPU-reference arbitration rule per SPEC.md §16, M2 slashing, PSCB whistleblower bounty), and **Verified Work Certificates** (SPEC.md §17): every correctly settled task issues a deterministic, id-derived receipt — `Quorum`-verified for an explicit settle, `WindowElapsed` for an implicit one — with tamper-evident validation against the on-chain registry.

**Roadmap / Future Work:**

| | |
|---|---|
| Layer 2 — Verified Work Certificates | Phases 2–4 shipped in `crates/jnt-l2`: task contracts and the five L2 tx types (Phase 2), the dispute engine with M2/M1 integration (Phase 3), and Verified Work Certificates (Phase 4) — an automatic, quorum-verifiable receipt for every correctly settled task. |
| Worker SDK | Shipped (Phase 5): [`crates/jnt-worker`](crates/jnt-worker) — a worker-side SDK over two injected node seams (`L2NodeView`/`L2Broadcaster`; no wire protocol invented). `WorkerClient` covers discovery, claim, a pluggable `Executor` (§16 CPU-reference shipped), result submission with M3 attestations, dispute observation/participation, VWC observation+validation, and earnings derived from authoritative state. Idempotent-by-txid restart/timeout flows; 32 SDK tests including a 15-test privilege-escalation/secret-hygiene suite. The transport that implements the seams (REST/P2P) is Phase 6. |
| Persisted UTXO indexing | Currently replays from genesis or fast-bootstraps via local state. |
| Coverage-guided fuzzing | Shipped: thirteen cargo-fuzz targets (L1 wire/tx/block/mempool/storage/checkpoint + L2 codec/M3 readers/dispute/state/VWC + Phase-5 `worker_flows`), with deterministic `fuzz_invariants` suites on every `cargo test` and a CI fuzz-smoke job. |
| License file | Shipped: dual `LICENSE-MIT` / `LICENSE-APACHE` at the repo root, matching `Cargo.toml`'s `MIT OR Apache-2.0`. |

---

## What this is

Bitcoin's principle is that *solving* must be hard and *verifying* must be easy.
Its mining is pure hashing, which leaves GPUs largely idle and means the energy
spent has no relationship to anything useful.

Jounit keeps the principle and changes the work. Mining runs three stages:

1. **A SHA-256 hash chain** — carries the security. This is the brute-force
   expensive part, and it is what a quantum adversary has to break.
2. **An integer-only neural network** — makes mining meaningful for AI hardware.
3. **A final hash** — binds both together into the value that must fall below
   the target.

Two properties make the NN stage a cost model rather than a liability:

- **Capped share.** The NN is required to account for 30–50% of modelled work
  (the default lands at exactly 40%). It can never become the weak link, because
  a registry entry outside that band is rejected outright.
- **No floating point, anywhere.** Weights are derived from the epoch id by
  SHA-256, the forward pass accumulates in `i64` and wraps to `i32`, and every
  integer is explicit. Two implementations on two machines produce identical
  digests — which is checked, not assumed (see
  [cross-implementation](#cross-implementation)).

Because weights come from the epoch id, no miner can precompute them before an
epoch starts.

---

## Quick start

Requires **Rust 1.75+** (`rust-version` in `Cargo.toml`; developed and tested
against 1.95) and **Python 3.11+** for the simulations.

```sh
git clone https://github.com/swamy18/Jounit.git
cd Jounit
cargo build --release
```

```sh
# Create a chain directory and a miner wallet.
./target/release/jnt-node init --network mini --data-dir ./chain

# Mine, spend, and verify.
./target/release/jnt-node mine   --network mini --data-dir ./chain --blocks 30
./target/release/jnt-node status --network mini --data-dir ./chain
./target/release/jnt-node verify --network mini --data-dir ./chain

# Run a P2P node daemon.
./target/release/jnt-node serve  --network mini --data-dir ./chain --listen 127.0.0.1:9833
```

`verify` replays the whole canonical chain from genesis and diffs the resulting
UTXO set and supply against stored state. It is the check worth running after
any change, and `memory.md` records a round-trip where the fee burn reconciled
to the satoshi.

Run `jnt-node help` for the full command list; every command accepts `--help`.

---

## Repository layout

| Path | Lines | What it is |
|---|---:|---|
| [`SPEC.md`](SPEC.md) | — | **Normative.** The protocol specification. Where a disagreement exists, this wins. |
| `crates/jnt-core/` | 14 900+ | Protocol implementation across 25 modules. All consensus logic. |
| `crates/jnt-core/tests/redteam.rs` | 724 | Adversarial regression suite (see [red-team suite](#red-team-suite)). |
| `crates/jnt-net/` | 5 100+ | P2P networking layer: wire framing, handshakes, peer sync, orphan pool. |
| `crates/jnt-net/tests/integration.rs` | 500+ | P2P integration tests, including a real-socket end-to-end sync. |
| `crates/jnt-net/tests/net_vectors.rs` | 300+ | Wire-format vectors (§13.12). |
| `crates/jnt-store/` | 2 200+ | Persistence: append-only checksummed block log, atomic metadata, crash recovery. |
| `crates/jnt-l2/` | 5 400+ | Layer 2: `TaskContract` lifecycle, `L2State` accounting, D3 flat fees, the dispute engine, M2 slashing, PSCB bounty, Verified Work Certificates. |
| `crates/jnt-node/` | 990+ | CLI and daemon runner (`init`, `mine`, `status`, `verify`, `serve`) with the L2 replay view over accepted blocks. |
| `crates/jnt-worker/` | — | Worker SDK (Phase 5, SPEC.md §18): `WorkerClient`, node seams, discovery/claim/execute/submit, dispute participation, VWC observation, earnings. A minimal secret-free CLI (`jnt-worker address`/`generate`). |
| `sim/` | 1 609 | Python: independent protocol reference plus attack and supply simulations. |
| `tests/vectors/` | — | Consensus vectors. Generated from source, never hand-edited. |
| [`docs/status.md`](docs/status.md) | — | What is verified, what is broken, what is missing. |
| [`memory.md`](memory.md) | — | Working notes from the audits and implementations. Not normative. |

---

## Architecture

### Crate layout

Five crates in one workspace:

```
jnt-core   pure protocol library — no I/O, no clock, no network
jnt-net    P2P wire protocol, peer state machines, sync and relay
jnt-store  persistent storage: append-only block log + atomic metadata
jnt-l2     Layer 2: task contracts, the five L2 transaction types, D3 fees, the dispute engine, VWCs
jnt-worker worker-side SDK (Phase 5): discovery, claim/execute/submit, disputes, VWC observation, earnings — client only, no consensus
jnt-node   CLI and node daemon (serve, mine, status, verify)
```

All consensus logic lives in `jnt-core`. The `mini` network profile is **the same
code with different parameters**, never a second codebase, so anything tested on
mini is the production code path. (`SPEC.md` §10, design doc Section 17.)

### Module map (`jnt-core`)

| Module | Lines | Responsibility |
|---|---:|---|
| `lib.rs` | 46 | Crate root and protocol scope statement |
| `error.rs` | 196 | `Error` — 41 consensus-visible failure modes |
| `params.rs` | 331 | `NetworkParams`: mainnet and mini profiles, magic bytes, network IDs, L2 fee schedule |
| `hash.rs` | 87 | SHA-256 helpers and domain-separation tags |
| `ser.rs` | 194 | `Reader`/`Writer` — canonical byte encoding with non-chaining aliases |
| `hexserde.rs` | 58 | Serde helpers for hex-encoded types |
| `u256.rs` | 212 | 256-bit target arithmetic by long division. No floating point |
| `fees.rs` | 299 | M1: 50/50 base-fee split (50% burn, 50% PSCB reserve) + miner tips, `split_flat_fee` (D3) |
| `slash.rs` | 329 | M2: 50% Anti-collusion slash burn + 1-year linear vesting Compute Reserve |
| `compute_ir.rs` | 550 | M3: Hardware-agnostic canonical compute IR (GPU/NPU/TPU/Photonic) + bounded decoders |
| `hbm_pow.rs` | 285 | M4: Memory-bound HBM/GDDR scratchpad latency PoW puzzle |
| `bls.rs` | 523 | blst-backed BLS12-381: derive/sign/verify/aggregate, IETF keygen |
| `bls_checkpoint.rs` | 561 | M5: Sovereign BLS aggregate signature checkpoint finality gadget |
| `l2.rs` | 1 051 | L2: five transaction payload types, actor auth, signing hashes, D3 fee mapping |
| `supply.rs` | 335 | Halving ladder, cumulative issuance, the cap invariant |
| `wallet.rs` | 362 | Keys, addresses, transaction building and signing |
| `block.rs` | 465 | Header, block, merkle root, genesis block |
| `difficulty.rs` | 570 | LWMA retarget, median-time rule, local-clock policy |
| `ledger.rs` | 596 | UTXO set, undo records, atomic transaction checking |
| `mempool.rs` | 938 | Byte-bounded, fee-rate-ordered pool with conflict checking |
| `sig.rs` | 636 | Signature schemes and hybrid post-quantum bundles |
| `tx.rs` | 704 | Transactions, inputs, outputs, sighash |
| `puzzle.rs` | 830 | The three PoW stages and the versioned puzzle registry |
| `validators.rs` | 936 | §14.6 validator-set machinery (deterministic TopN, checkpoint validation) — inert |
| `chain.rs` | 1 680 | Validation, application, fork choice, reorg, PSCB reserve, mining |

### Key types

- **`Chain`** — validation, application, fork choice, reorg, finality. The whole
  consensus state machine.
- **`Block` / `Header`** — the header is *exactly* 145 bytes; the block hash
  covers only the header, with the body committed transitively via the merkle
  root.
- **`UtxoSet` / `Undo`** — the ledger and what is needed to reverse one block, so
  a reorg does not replay from genesis.
- **`Transaction` / `Input` / `Output`** — the transaction model.
- **`PuzzleSpec` / `PuzzleSolver` / `PuzzleRegistry`** — PoW parameters, an
  epoch-cached weight set, and the versioned registry.
- **`NetworkParams`** — every consensus constant, in one struct (including the D3 L2 fee schedule).
- **`TaskContract` / `L2State` / `DisputeEngine`** (`jnt-l2`) — the L2 task lifecycle, its
  accounts/escrow/replay layer, and arbitration. `TaskContract` holds transitions only (no
  balances, no crypto); `L2State` is the only thing that debits an account or consults a
  validator set; `DisputeEngine` compares result hashes and never executes task code.
- **`VerifiedWorkCertificate`** (`jnt-l2::vwc`) — the receipt for verified correct work,
  issued automatically at settlement. Its id is derived from its canonical encoding (never
  serialized), and `Quorum` certificates carry the settle payload's own BLS aggregate, so a
  third party can verify the decision offline against the validator set.
- **`Error`** — 41 variants. Every one is *deterministic and consensus-visible*:
  two conforming nodes evaluating the same block must produce the same variant,
  because callers branch on it.

### Data flow

```
bytes ──▶ Reader (bounds-checked) ──▶ Block/Transaction
                                            │
                          validate_standalone│  PoW, merkle, gas, epoch, size
                                            │  (needs no chain state)
                                            ▼
                                          reselect ──▶ best_candidate
                                            │           (most work, then
                                            │            lower height,
                                            │            then lowest hash)
                                            ▼
                                          apply_block ──▶ check_tx per body tx
                                            │           ──▶ split_fees
                                            │           ──▶ reward + tip ≤ cap
                                            ▼
                                     UTXO set + undo records
```

The L2 data flow is deliberately separate and pure: a `Disputed` task hands its two
competing hashes to `DisputeEngine`, which returns a verdict; the verdict is emitted as a
`SettlePayload` that the *existing* settle path applies with quorum, fees, M2 slashing and
the PSCB bounty. Task code is never executed on-chain (SPEC.md §16).

---

## Protocol mechanisms (M1–M5)

Jounit defines five protocol-level mechanisms to align economic incentives with
long-term AI compute infrastructure. **Only M1 is consensus-active today** —
that is, only M1 can change whether an L1 node accepts a block. Phase 2–3 gave
M2, M3 and M5 their first real *consumers* at Layer 2 (L2 fraud slashes vest
through the M2 vault, L2 transactions carry M3 envelopes, L2 settlement verifies
an M5-shaped quorum aggregate), but an L2 transaction is not yet carried in an
L1 block, so L1 chain state is untouched. M4 still needs its rule (whether the
HBM puzzle replaces or composes with §5). SPEC.md §14 and §16 record that
status, and this list is repeated in `docs/status.md`.

| # | Mechanism | Consensus-active | Module |
|---|---|---|---|
| M1 | 50/50 PSCB base-fee split | **Yes** — changes the UTXO set | `fees.rs`, `chain.rs` |
| M2 | Anti-collusion slash vault | No — but holds L2 fraud slashes | `slash.rs` |
| M3 | Hardware-agnostic compute IR | No — envelopes carried by L2; §16 CPU reference | `compute_ir.rs` |
| M4 | Memory-bound HBM scratchpad PoW | No | `hbm_pow.rs` |
| M5 | BLS aggregate finality | No — L2 settle verifies the quorum trait; L1 finality inert | `bls_checkpoint.rs` |

### M1 — 50/50 PSCB Base Fee Split (`fees.rs`, `chain.rs`)
Base fees collected in each block are split equally:
- **50% Burned:** Permanently destroyed, preserving the deflationary pressure of EIP-1559.
- **50% Protocol Security & Compute Buffer (PSCB):** Accumulated on-chain in the `pscb_reserve`. Provides protocol-level liquidity and backing for useful-work validator stakes.
- **Miner Tip:** 100% of user priority tips go directly to the miner.
- **Invariant:** `burned + pscb + tip == total_fees`.
- **Reorg-correct:** the credit is rewound per rolled-back block, and `verify_canonical_chain` re-derives it by replay.

### M2 — Time-Locked Compute Reserve & 50/50 Anti-Collusion Slash Vault (`slash.rs`)
Protects against malicious or fabricated compute results submitted to the network:
- **50% Instant Burn (Anti-Collusion):** Eliminates self-slashing arbitrage where colluding parties reclaim 100% of slashed funds.
- **50% Time-Locked Vesting (Compute Reserve):** Slashed stake vests linearly per block over 1 year (52,560 blocks on mainnet, 2,000 on mini) into the community compute reserve.
- Supports validator-level penalty tracking and vault pruning.

### M3 — Universal Hardware-Agnostic Canonical Compute IR (`compute_ir.rs`)
Prevents vendor lock-in by abstracting computation across heterogeneous hardware targets:
- **Hardware Targets:** CUDA/ROCm GPUs, Apple Neural Engine (ANE), Google TPUs, and optical photonic chips.
- **Deterministic Quantization:** Quantized execution rules (INT8/FP16) ensuring zero floating-point nondeterminism.
- **Attestation Envelope:** Deterministic serialization and SHA-256 domain-separated task hashing (`DOM_COMPUTE_TASK`, `DOM_COMPUTE_ATTEST`).

### M4 — Memory-Bound HBM Scratchpad PoW (`hbm_pow.rs`)
Hardens mining against ASIC centralization and pure-compute bypasses:
- **HBM / High-Bandwidth Memory Latency:** Miners traverse a deterministic pseudorandom scratchpad using cache-line-aligned (32-byte) memory hops.
- Guarantees that mining performance is bound to actual hardware memory bus bandwidth (HBM3/GDDR6) rather than pure ALU arithmetic.
- **Not registered as a `puzzle_id`**, so it validates nothing today.

### M5 — Sovereign BLS Aggregate Finality Gadget (`bls_checkpoint.rs`)
Describes deterministic finality on top of probabilistic deepest-chain PoW:
- **Checkpoints:** every `CHECKPOINT_INTERVAL` (100 blocks on mainnet, 10 on mini).
- **BLS12-381 Aggregate Signatures:** 96-byte aggregate signatures over 48-byte validator public keys.
- **2/3 Supermajority Quorum:** `ceil(n × 2/3)` validator agreement with compact bitmask signers.
- **Absolute Immutability:** once a checkpoint is accepted by `CheckpointChain`, the boundary is permanent.
- **`BlsVerifier` is a trait and only a mock implements it** — no pairing is performed anywhere in this repository, so the finality guarantee is *not* in force. `blst` is the production path.

---

## P2P networking (`jnt-net`)

The `jnt-net` crate provides a robust, zero-external-dependency P2P transport layer:

- **Wire Framing (`frame.rs`):** 4-byte network magic, 2-byte message type ID, and 4-byte payload length prefix with allocation bounds checking.
- **Network Isolation (`magic.rs`):** Distinct magic bytes and IDs for `mainnet` (`[0x6A, 0x4E, 0x54, 0x01]`, `"jounit/mainnet"`) and `mini` (`[0x6A, 0x4E, 0x54, 0x02]`, `"jounit/mini"`) preventing cross-profile peer contamination.
- **Message Codecs (`msg.rs`):** `Version`, `Verack`, `Ping`, `Pong`, `Inv`, `GetData`, `Block`, `GetBlocks`, `Addr`, and `Tx` (transaction relay, §13.14 — additive, so older nodes ignore it rather than disconnect).
- **Peer Lifecycle (`peer.rs`):** Thread-per-connection model with non-blocking socket timeouts and handshake timeout enforcement.
- **Sync Manager (`syncer.rs`):** Locator-based block synchronization with exponential backoff and a bounded orphan pool (512 blocks).
- **Node Server Daemon (`jnt-node serve`):**
  ```sh
  jnt-node serve --network mini --listen 0.0.0.0:9833 --connect 192.168.1.10:9833 --peers 125
  ```

---

## Protocol

`SPEC.md` is normative and this section is a summary. Where they disagree,
`SPEC.md` wins.

### Blocks and headers

The header is exactly **145 bytes**:

| Field | Size | Notes |
|---|---:|---|
| `version` | 4 LE | |
| `height` | 8 LE | `0` for genesis |
| `prev_hash` | 32 | |
| `merkle_root` | 32 | |
| `timestamp_ms` | 8 LE | Unix milliseconds |
| `base_fee_sat` | 8 LE | Fee for the *next* block |
| `difficulty` | 16 LE | `u128`, `1 … 2^96` |
| `nonce` | 8 LE | |
| `puzzle_id` | 8 LE | Puzzle registry entry |
| `epoch_id` | 4 LE | NN weight epoch |
| `extra_nonce` | 16 | Miner-controlled |
| `sig_scheme` | 1 | Signature agility |

```
block_hash = SHA256("jounit/blockhash/v1" ‖ header)
```

Merkle construction is Bitcoin-style with domain-separated leaves: `0x00 ‖ tx`
for leaves, `0x01 ‖ l ‖ r` for internal nodes, and an odd node is duplicated.

### Proof of work

Three stages, `puzzle_id = 1` ("hybrid-v1").

**Stage 1 — hash chain.** 16 rounds over the serialized header plus a nonce.

**Stage 2 — integer-only neural network.** Weights derive from the epoch id via
SHA-256, so nothing can be precomputed before the epoch starts. Three layers of
16 units, `i64` accumulators, weights in `[-128, 127]`, biases in `[0, 62]`, an
arithmetic shift followed by ReLU. Every layer's *pre-activation* values are
committed to, so no layer can be skipped or approximated.

**Stage 3 — final hash.** Binds seed, activation digest, nonce and epoch.

```
solve(header) = U256_BE(final) ≤ floor((2^256 − 1) / difficulty)
```

**The 30–50% audit rule.** The protocol cannot measure wall-clock, so the
constraint is enforced as a cost model over puzzle parameters — one SHA-256
counted as 64 int32 MACs. The default spec scores exactly 4000 bps (40%) and a
registry entry outside `[3000, 5000]` is rejected. This is a proxy, not a
stopwatch, and `docs/status.md` says so plainly.

### Difficulty adjustment

Zawy-style **linearly weighted moving average**, 60-block window, ±10% per
block, clamped to `[min_difficulty, max_difficulty]`.

```
t_i   = clamp(tip[i].ts − tip[i+1].ts,  T/4,  5T)      newest first
d_raw = d_prev · T / (Σ (window−i)² · t_i) / Σ (window−i)²
```

The retarget is **multiplicative**: `d_new = d_prev · T / avg_solve`. Perfect
spacing is a fixed point at *every* difficulty, which the test suite asserts
directly. (The scale-invariant alternative `avg_solve / T` has no restoring
force at all — see [Security](#security-defects-found-and-fixed).)

While the chain is shorter than the window, the available window is used with the
same weight formula rather than pinning difficulty to a genesis value, which
would hand the first hour to whoever arrives first.

### Timestamp rules

**Consensus:** `timestamp_ms ≥ median(previous 11 timestamps)`. Deterministic, no
local clock.

**Node policy:** `timestamp_ms ≤ local_now_ms + one block time`.

There is deliberately **no consensus upper bound**. An upper bound needs a
reference that advances with wall time, and the only such thing is the local
clock — which would make validity depend on machine skew, so two honest nodes
could disagree about the same block. The ceiling is policy, applied at
`submit_at`. This is the same tradeoff Bitcoin makes, with a much tighter
window, and `sim/difficulty_attack_sim.py` measures it.

### Supply

| | |
|---|---|
| Block reward | 76 JNT |
| Halving period | 262 800 blocks (~5 years at 10 min) |
| Premine | **0%** — enforced in code, not just in prose |
| Hard cap | 39 945 600 JNT |

The ladder halves in **whole JNT**, not by shifting satoshis:

```
76, 38, 19, 9, 4, 2, 1, 0
```

Because every halving rounds down, the seven non-zero steps pay out
**39 157 200 JNT** in total — exactly 149 periods at the full reward — against a
39 945 600 cap. The remaining **788 400 JNT is permanently unmintable**, not
merely reserved: anyone can confirm it by summing the ladder. The cap is checked
at the point of minting, against live UTXO state.

### Fees and burn

EIP-1559-shaped, and the base fee is **burned**. Only the tip reaches the miner,
so no new supply is ever minted from usage and the cap cannot be crossed by
demand.

```
gas_per_tx = 16 000 + 1 000 · inputs + 250 · outputs
gas_cap    = 2 000 000 per block

coinbase.value = block_reward(height) + (total_fees − base_fee · gas_used)
```

The base fee rises by 1/512 per block when the gas target is met exactly, and is
clamped to `[base_fee_min, base_fee_max]`.

### Transactions and signatures

Scriptless by design. Validity is decided by the rules, and future primitives
(bonds, certificates, channels) will add new `tx_type` values — never a
scripting language.

The signature commits to the whole transaction except the signatures themselves,
so outputs cannot be swapped after signing:

```
sighash = SHA256(DOM_TXBODY ‖ serialize(tx with all sigs and keys blanked))
msg_k   = SHA256(DOM_SIG ‖ U4LE(k) ‖ sighash ‖ U4LE(input[k].prevout_index))
```

**Signature agility and hybrid bundles.** Each input carries a *bundle* of
signature components rather than one signature. Two rules make hybrids real
rather than decorative:

1. **Every component must verify.** A one-of-N rule would not be a hybrid: an
   adversary who breaks one primitive forges that component and strips the rest.
2. **The address commits to the whole key set**, so a hybrid key set cannot be
   quietly reduced to a smaller one that omits a component.

Two schemes ship: `1` secp256k1 ECDSA (low-`s` enforced), `2` BIP-340 Schnorr.
Scheme 2 exercises the multi-scheme path end to end; it is not post-quantum and
adds no quantum resistance on its own. A lattice scheme would slot into the
existing encoding without changing anything. The bundle is sized for a real
post-quantum signature from the start (4 096 bytes per component) rather than
being retrofitted later.

---

## Consensus rules

**Block.** Correct height and parent; valid PoW; difficulty equal to what the
retarget rule produces from the tip history; merkle root matches the body;
timestamp rule satisfied; `puzzle_id` exists and `epoch_id == height /
nn_epoch_blocks`; `gas_used ≤ gas_cap`; every transaction valid; `tx_count ≤
5 000` and serialized size ≤ 4 MB.

**Transaction.** Coinbase first and only at index 0, with exactly one input
referencing the parent and exactly one output; no coinbase txid collision
(BIP30-style); no duplicate inputs; no already-spent outpoints;
`Σ inputs ≥ Σ outputs + fee`; every signature verifies against the address
owning the spent output; coinbase maturity enforced; and
`coinbase.value ≤ reward + tip` — miners cannot over-claim.

**Fork choice.** Deepest chain by cumulative difficulty. Every tie-break is a
function of block data alone — more work, then lower height, then lowest block
hash. Two nodes holding the same set of valid blocks always agree on the tip.

**Finality.** `finality_depth` blocks below the tip are immutable; a reorg whose
fork point lands at or below them is rejected as `ReorgWouldCrossFinality`.

---

## Network profiles

Selected with `--network`. Same code, different numbers.

| | `mainnet` | `mini` |
|---|---|---|
| Target block time | 600 000 ms (10 min) | 1 000 ms |
| Halving period | 262 800 blocks | 2 000 blocks |
| Start reward | 76 JNT | 76 JNT |
| Supply cap | 39 945 600 JNT | 304 000 JNT |
| Difficulty window | 60 | 60 |
| Change limit | ±10% / block | ±10% / block |
| Genesis difficulty | 1 | 1 |
| Max difficulty | 2^96 | 2^40 |
| Coinbase maturity | 100 blocks | 10 blocks |
| Finality depth | 100 blocks | 20 blocks |
| Gas cap | 2 000 000 | 2 000 000 |
| Initial base fee | 1 000 sat | 100 sat |
| NN epoch | 50 000 blocks | 2 000 blocks |
| Puzzle id | 1 | 1 |

---

## Node CLI reference

```
jnt-node <COMMAND> [OPTIONS]

COMMANDS
  init        Create a chain directory, a miner wallet and the genesis block
  mine        Mine blocks and extend the chain
  send        Spend from a wallet address into a new block
  status      Print chain tip, difficulty, supply and wallet balance
  verify      Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance     List the unspent outputs of an address
  wallet      Create or list wallets
  export      Write the canonical chain to JSON

COMMON OPTIONS
  --network <mainnet|mini>   Default: mini
  --data-dir <path>          Default: ./chain
```

Per-command options: `--blocks`, `--interval`, `--wallet`, `--amount`, `--to`,
`--fee`, `--address`, `--height`, `--label`, `--out`, `--new`.

> `send --amount` is denominated in **satoshis**, while every printed figure is
> in JNT. This is a known rough edge.

`--help` on any command prints usage without touching the chain directory.

---

## Testing and verification

```sh
cargo test --workspace                                   # 468 tests across five crates
cargo clippy --workspace --all-targets -- -D warnings    # 0 warnings
cargo fmt --all --check
```

### Consensus vectors

`tests/vectors/` holds four files. A language implementation is correct only if
it reproduces them byte for byte.

| File | Covers |
|---|---|
| `puzzle_vectors.json` | Header serialization, stage 1 seed, stage 2 activation digest, stage 3 final, work-share accounting |
| `ser_vectors.json` | Input, output, transaction and header byte layouts |
| `difficulty_vectors.json` | LWMA output, timestamp clamp behaviour |
| `supply_vectors.json` | Reward ladder, cumulative supply, cap invariant |

```sh
python sim/verify_vectors.py --check    # present, self-consistent, cross-checked
```

Vectors are generated from the implementation and regenerated only by it:

```sh
UPDATE_PUZZLE_VECTORS=1     cargo test -p jnt-core --lib puzzle_vectors_are_stable
UPDATE_DIFFICULTY_VECTORS=1 cargo test -p jnt-core --lib difficulty_vectors_are_stable
UPDATE_SER_VECTORS=1        cargo test -p jnt-core --lib serialization_vectors_are_stable
python sim/supply_schedule_sim.py
```

A second implementation disagreeing with these vectors has a **consensus split**,
not a rounding difference.

### Cross-implementation

`sim/jounit_reference.py` is a second implementation of the PoW puzzle, written
from the prose of `SPEC.md` rather than from the Rust source. It reproduces all
21 puzzle digests.

```sh
python sim/puzzle_crosscheck.py          # Rust vs independent Python
python sim/difficulty_attack_sim.py     # timestamp-attack containment
python sim/difficulty_attack_sim.py --ablation --start-difficulty 100000
python sim/supply_schedule_sim.py       # supply vectors
```

That agreement is the actual evidence `SPEC.md` is unambiguous rather than
merely self-consistent with the code implementing it.

### CI

`.github/workflows/ci.yml` runs on every push and PR: format check, clippy with
`-D warnings`, the full test suite, a release build, the vector cross-checks, the
difficulty-attack containment simulation, the supply cross-check, and a
`fuzz-smoke` job that runs all thirteen libFuzzer targets for 20 s each on nightly
+ ASan.

### Fuzzing and invariants

`fuzz/` is a standalone cargo-fuzz crate with **thirteen targets** over the
attacker-controlled boundaries — L1: `tx_decode`, `block_decode`,
`wire_msg_decode`, `mempool_admit`, `storage_recover`, `checkpoint_validate`,
`meta_parse`; L2 (Phase 2–4): `l2_payload_decode`, `m3_readers`,
`dispute_arbitrate`, `l2_state_apply`, `vwc_decode`; worker (Phase 5):
`worker_flows` (plan construction/discovery/reconciliation determinism over
adversarial inputs). They assert capability invariants (exact
decode→encode inversion, bounded allocation, value conservation under
adversarial transaction programs), not merely panic-freedom. Campaign results
are recorded in [docs/status.md](docs/status.md).

The deterministic counterparts run on every `cargo test`: `fuzz_invariants.rs`
suites in `jnt-core`, `jnt-net`, `jnt-store` and `jnt-l2` feed hand-built
adversarial inputs — every truncation and bitflip of a valid transaction/block,
hostile length fields, forged and lying-count checkpoints, mutated dispute
evidence — through the same invariants on stable tooling.

```sh
cd fuzz && cargo check --bins       # all thirteen targets compile
cargo test -p jnt-l2 --test fuzz_invariants   # L2 invariants on stable
```

### Red-team suite

`crates/jnt-core/tests/redteam.rs` holds 11 adversarial integration tests, written
attack-first. Each builds the hostile input a peer would send and asserts the
node refuses it; each was confirmed to fail against the code it now guards.

```sh
cargo test -p jnt-core --test redteam
```

They exploit hand-built blocks — difficulty 1 makes PoW free on `mini`, which is
exactly what an attacker gets. The shapes here are the obvious seed corpus for a
`cargo-fuzz` harness when one is built.

---

## Security: defects found and fixed

Recorded because the pattern matters more than the individual fixes. Each was
confirmed by restoring the faulty code and watching a test fail. Full detail in
[`docs/status.md`](docs/status.md); working notes in [`memory.md`](memory.md).

### From the most recent red-team pass

**Fork choice was not deterministic.** The final tie-break was an arrival
counter, so two nodes holding an *identical* set of valid blocks could select
different tips. The module doc claimed the opposite. Every tie-break is now a
function of the block graph alone.

**The finality rule had a hole.** It refused reorgs only when the chain got
*shorter*, so a rival forking below the finality point but ending up *longer*
rewrote settled history. The existing test only built a shorter rival, which is
why it stayed green.

**`apply_tx` was not atomic.** Inputs were removed one at a time, so a
transaction whose second input did not exist had already taken the first when the
error fired — and the error discarded the undo record that could have restored
it. One malformed transaction destroyed coins.

**A block that could never be applied still counted as fork-choice work.** It was
stored before being applied and never removed, while `cumulative_work` summed the
declared difficulty of everything stored. An attacker could bank chain weight no
reorganization could realize: fork choice kept picking the dead branch and
rejected honest blocks.

**The chain halted permanently once the reward ladder ran out.** A zero-value
coinbase was rejected unconditionally, but `SPEC.md` §7 says the coinbase collects
tips only and tips are legitimately zero on an empty block. Mainnet would have
stopped dead at height 2 102 400.

**`apply_block` was not atomic.** It wrote to the UTXO set transaction by
transaction, so a failure partway through left earlier ones applied. Writes are
now unwound by `apply_block` itself, which also keeps the happy path O(1) in UTXO
size rather than cloning the set per block.

Plus, in the same pass: `header.sig_scheme` was committed to by the block hash and
read by nothing, despite `SPEC.md` §1 requiring rejection of unknown values; the
deserializers bounded declared counts by raw remaining bytes rather than by the
smallest entry that could follow, letting a 4 MB block force a reservation many
times its own size; `total_gas_used` used `.sum()` and feeds both the base-fee
schedule and the gas cap; `build_tx` accepted a `fee` argument and discarded it
with `let _ = fee;`; and `halvings` / `expected_epoch` truncated a `u64` quotient
with `as u32`.

**Every vector file was byte-identical afterwards.** None of this touched hashing,
the puzzle, the retarget or the serialization layout — the state layer changed and
the consensus rules did not.

### From earlier audits

**The difficulty retarget had no restoring force.** It computed `avg_solve / T`,
which is scale-invariant, so *every* difficulty was a fixed point: halving the
hashrate produced blocks at 2T and the interval ran away to 4T. The Zawy weights
were also inverted, weighting the oldest solve time most heavily. Both were
invisible to the original tests because every one used *uniform* solve times,
where neither weighting direction nor the missing `d_prev` factor can show up.

**`Transaction::value_out` could overflow.** Summing with `.sum()` panicked in
debug and wrapped in release. Since the total is compared against resolved input
value, a wrapped sum reads as a transaction creating value from nothing — an
inflation primitive.

**A puzzle-spec overflow guard could not fire.** It computed its bound in `i64`
from a `usize` input, so the cast wrapped before the comparison ran, passing
exactly the inputs it existed to reject.

### A claim that did not survive measurement

An earlier design document reported a 40% attacker with a two-hour
future-timestamp allowance reaching ~104s average block time, and presented that
as the reason to tighten the limit to one block time. **That figure is not
reproducible and cannot be:** 104s is below the solve-time clamp floor (T/4 =
150s), so no retarget can ask for a difficulty that low. The simulation's
`--ablation` mode confirms this independently.

What *is* established, per `sim/difficulty_attack_sim.py`: under this
specification, block time stays within ~1% of target from a one-minute allowance
up to Bitcoin's two hours. The tight allowance is retained anyway as defence in
depth, for the case where an attacker reaches 50% and can move the median itself.

---

## Known limitations

**Wedges the node under a finality-crossing heavier branch.** A valid branch that
forks below `finality_depth` and carries more work than the tip is retained, and
the node declines to reorganize — so it cannot accept honest blocks until the
situation changes. This follows directly from treating `finality_depth` as a
hard rule. Whether the node should instead follow the heavier chain, or how long
to remember a branch it will not take, is a consensus design decision and is not
settled here.

**`adopt()` snapshots the entire UTXO set.** Correct, but O(chain length) per
reorg. Acceptable at test scale; not at 40M coins. The incremental undo
primitives it needs already exist.

**State replays from genesis on every node load.** `Store::load_chain` re-submits
every block. Fine at test scale, not at production scale.

**The governance timelock is described but not written.** `SPEC.md` references a
`docs/roadmap.md` (now present) and a governance timelock that has no
implementation: Layer 2 is implemented through Phase 3, but the timelock and the
remaining roadmap items (Phase 4-6) are still design text only. Worth resolving
before the specification is treated as complete.

**`Cargo.toml` declares a `repository` URL that does not match the actual
remote.** Cosmetic, but it is the first thing `cargo publish` would use.

**Vector coverage is finite by construction.** The crosscheck exercises seven
header/epoch combinations; a bug outside those cases would not be caught by it.

**`SPEC.md` documents a domain tag the code does not implement.** The tag table
in §0 lists ten, including `DOM_GENESIS` (`jounit/genesis/v1`). Only nine exist:
the genesis block is hashed through the ordinary `DOM_BLOCK` path. Harmless
today — nothing depends on genesis having its own tag — but the spec and the
implementation disagree, and the spec is the document this project treats as
normative.

---

## License`Cargo.toml` declares `MIT OR Apache-2.0`, and both licence texts ship at the
root (`LICENSE-MIT`, `LICENSE-APACHE`). The `repository` URL `Cargo.toml`
declares does not match the actual remote — see the limitation above.