# JOUNIT PROTOCOL SPECIFICATION

**Version:** 0.2 (foundation + P2P transport)
**Status:** Draft — §0–§12 normative for `jnt-core` v0.1.x; §13 normative for `jnt-net` v0.2.x; §14 records the M1–M5 protocol mechanisms and, for each, whether it is consensus-active today
**Scope:** Layer 1 only (base layer). Layer 2 (useful work / Verified Work Certificates) is specced in `docs/roadmap.md`, not implemented here. §13 covers block relay between nodes; transaction relay is deferred (§13.13).

This document is the **normative reference**. Any implementation in any language must produce identical byte-level output for the vectors in `tests/vectors/`. Five vector files exist today — the four covering §0–§12, plus `net_vectors.json` (§13.12) for the wire format.

---

## 0. Conventions

| Rule | Value |
|---|---|
| Hash | SHA-256 (FIPS 180-4), 32 bytes |
| Signature | secp256k1, ECDSA, compact 64-byte `r‖s`, low-`s` enforced |
| Integer arithmetic | Signed/unsigned integers only. **No floating point anywhere in consensus.** |
| Byte order | Explicit `LE` (little-endian) or raw (byte sequence as written) on every field |
| Amounts | Satoshis (smallest unit). `1 JNT = 100,000,000 sat` (8 decimals) |
| Difficulty | `u128`, always `≥ 1` |
| Difficulty ceiling | `MAX_DIFFICULTY = 2^96` (keeps target division overflow-free in any language) |
| U256 | Big-endian 32-byte unsigned integer; `U256_BE(bytes)` is the primary comparison form |

**Domain separation.** Every hash input is prefixed with an ASCII domain tag (raw bytes, no NUL terminator). Tags are frozen and MUST NOT change for a given version suffix `/v1`.

| Tag | Bytes |
|---|---|
| `DOM_BLOCK` | `jounit/blockhash/v1` |
| `DOM_TX` | `jounit/txid/v1` |
| `DOM_TXBODY` | `jounit/txbody/v1` |
| `DOM_SIG` | `jounit/sig/v1` |
| `DOM_ADDR` | `jounit/addr/v1` |
| `DOM_S1` | `jounit/puzzle/stage1/v1` |
| `DOM_S2` | `jounit/puzzle/stage2/v1` |
| `DOM_S3` | `jounit/puzzle/stage3/v1` |
| `DOM_W` | `jounit/puzzle/weights/v1` |
| `DOM_GENESIS` | `jounit/genesis/v1` |
| `DOM_NET_HANDSHAKE` | `jounit/net/handshake/v1` |

Single-byte tags for the M3/M5 envelopes (§14). They are one byte rather than an
ASCII string because they tag a fixed-shape payload, not a message family:

| Tag | Value | Covers |
|---|---|---|
| `DOM_COMPUTE_TASK` | `0xC0` | §14.2 compute task |
| `DOM_COMPUTE_ATTEST` | `0xC1` | §14.2 compute attestation |
| `DOM_BLS_CHECKPOINT` | `0xB1` | §14.4 BLS checkpoint payload |

---

## 1. Keys, addresses, signatures

```
pubkey  = 33 bytes, compressed secp256k1 point (0x02/0x03 prefix + 32-byte X)
address = U8(U8(SHA256(DOM_ADDR ‖ pubkey))[0..20])          // 20 bytes
```

Signatures are versioned by the header field `sig_scheme` (**signature agility**, Section 20.1):

| `sig_scheme` | Scheme |
|---|---|
| `1` | secp256k1 ECDSA over SHA-256 (v0.1 only) |

A future hybrid post-quantum scheme MUST use a new `sig_scheme` value and MUST NOT reuse `1`. Nodes MUST reject unknown `sig_scheme` values.

### 1.1 Signature message

The signature for input `k` commits to the entire transaction **except** the signatures themselves, so outputs cannot be swapped after signing:

```
sighash = SHA256( DOM_TXBODY ‖ serialize(tx with every input.signature = 64 zero bytes
                                            and every input.pubkey   = 33 zero bytes) )
msg_k   = SHA256( DOM_SIG ‖ U4LE(k) ‖ sighash ‖ U4LE(input[k].prevout_index) )
```

`msg_k` is what the private key of `input[k].prevout` signs.

---

## 2. Merkle root

Standard binary Merkle tree, Bitcoin-style, domain-separated:

```
leaf(i)      = SHA256( 0x00 ‖ serialize(tx_i) )
internal(l,r) = SHA256( 0x01 ‖ l ‖ r )
```

Construction: pair leaves left-to-right; if the level has an odd node count, **duplicate the last node** and continue. The root of a single-transaction block is `leaf(0)`.

---

## 3. Serialization

All lengths are implied by the field list. Integers marked `LE` are little-endian.

### 3.1 `Input` — variable

| Field | Size |
|---|---|
| `prevout_hash` | 32 raw |
| `prevout_index` | 4 LE |
| `sigs` | signature bundle (§3.5) |
| `keys` | public-key bundle (§3.5) |

Fixed prefix is 36 bytes. The two bundles are length-prefixed, so the input is
variable-length. This is deliberate: a post-quantum signature is ~2.4 KB
(ML-DSA-44) to 3.3 KB (ML-DSA-65), and no fixed field sized to today's 64-byte
ECDSA could ever hold one. A cap that admits a real post-quantum signature would
have to be at least 4096 bytes per component regardless.

### 3.2 `Output` — 28 bytes

| Field | Size |
|---|---|
| `value` | 8 LE |
| `address` | 20 raw |

### 3.3 `Transaction` — variable

| Field | Size |
|---|---|
| `version` | 4 LE |
| `tx_type` | 1 (`0` = standard, `1` = coinbase) |
| `lock_time` | 8 LE |
| `input_count` | 4 LE |
| `inputs` | `input_count × (variable)` |
| `output_count` | 4 LE |
| `outputs` | `output_count × 28` |

### 3.5 Signature and key bundles

A bundle is an ordered, canonical list of components:

```
count          1        (0 permitted only for an unsigned or coinbase input)
per component: scheme   1
                len     2 LE
                bytes   len
```

Rules, all enforced:

- `1 ≤ count ≤ 4` for an input that claims to spend.
- `1 ≤ len ≤ 4096` per component. Checked against the *declared* length before
  any allocation, since the prefix is attacker-controlled.
- Total serialized size ≤ `2 × 4 × 4096 + 512`.
- Every `scheme` must be one this implementation can verify.
- A scheme may not repeat within one bundle — a duplicate adds bytes without
  adding independence, so it is not a hybrid.

An unsigned input and a coinbase input both carry two empty bundles
(`count = 0`), which is why `count = 0` parses. Non-emptiness is enforced by
validation, which only runs for inputs that actually claim to spend.

**Hybrid verification.** `sigs` and `keys` are parallel: `sigs[i]` is verified
by the key in `keys` declaring the same `scheme` id — matched by id, not by
position. **Every** component must verify. A one-of-N rule would not be a
hybrid: an adversary who breaks one primitive would forge that component and
strip the rest.

**Addresses commit to the whole key set.**
`address = SHA256(DOM_ADDR || serialize(keys))[0..20]`, with `DOM_ADDR` at
`/v2` because the preimage changed from a bare 33-byte pubkey to a serialized
bundle. An ECDSA-only key set and a hybrid one therefore cannot share an
address, and a hybrid key set cannot be quietly reduced.

**Schemes.** `1` = secp256k1 ECDSA (low-`s`, canonical). `2` = secp256k1
BIP-340 Schnorr. Scheme 2 exercises the multi-scheme path end to end; it is not
post-quantum and adds no quantum resistance on its own. A lattice scheme (3)
would slot in without changing any encoding, since the bundle is generic.

```
txid = SHA256( DOM_TX ‖ serialize(tx) )
```

### 3.4 `Header` — exactly 145 bytes

| Field | Size | Notes |
|---|---|---|
| `version` | 4 LE | block version |
| `height` | 8 LE | `0` for genesis |
| `prev_hash` | 32 raw | previous block hash |
| `merkle_root` | 32 raw | |
| `timestamp_ms` | 8 LE | Unix milliseconds |
| `base_fee_sat` | 8 LE | base fee for the *next* block (§8) |
| `difficulty` | 16 LE | `u128`, `≥ 1`, `≤ 2^96` |
| `nonce` | 8 LE | |
| `puzzle_id` | 8 LE | puzzle registry entry |
| `epoch_id` | 4 LE | NN weight epoch |
| `extra_nonce` | 16 raw | miner-controlled |
| `sig_scheme` | 1 | |

```
block_hash = SHA256( DOM_BLOCK ‖ serialize(header) )
```

### 3.5 `Block`

```
serialize(block) = serialize(header) ‖ signature(64 raw) ‖ signer_pubkey(33 raw)
                        ‖ U4LE(tx_count) ‖ serialize(tx_0) ‖ … ‖ serialize(tx_{n-1})
```

`signer_pubkey` is informational in v0.1 (no header-level signature requirement yet); it is committed to by the block hash so a re-signed block is a different block.

---

## 4. Difficulty → target

```
target(d) = floor( (2^256 − 1) / d )
```

Computed by 256-step binary long division (see `u256.rs`); never by floating point.

A block satisfies its own PoW iff:

```
U256_BE( block_hash ) ≤ target(header.difficulty)
```

`difficulty = 1` ⇒ `target = 2^256 − 1` ⇒ every hash is valid. This is the genesis setting (Section 16: starting difficulty must be low so the network can start).

---

## 5. Hybrid PoW puzzle (Stage 1 hash → Stage 2 NN → Stage 3 hash)

Per Section 29: security rests on the hash stages; the NN stage guarantees GPU/AI hardware participation and is an auditable fraction of mining work.

### 5.1 Puzzle parameters (`puzzle_id = 1`, "hybrid-v1")

| Constant | Value |
|---|---|
| `hash_rounds` | `16` |
| `nn_input_dim` | `16` |
| `nn_hidden_dim` | `16` |
| `nn_layers` | `3` |
| `nn_epoch_blocks` | height interval after which NN weights rotate |
| `min_nn_share_bps` | `3000` (30%) |
| `max_nn_share_bps` | `5000` (50%) |

These live in the versioned **puzzle registry**. Supply, halving and base rules are immutable; only puzzle parameters are upgradeable (Section 19.3 item 3), and only via the governance timelock (`docs/roadmap.md`).

### 5.2 Stage 1 — memory-hard-ish hash chain

```
v = SHA256( DOM_S1 ‖ serialize(header) ‖ U8LE(nonce) )
repeat hash_rounds times:
    v = SHA256( DOM_S1 ‖ v ‖ U8(r) )          // r = 0 .. hash_rounds-1
seed = v
```

`serialize(header)` already contains `nonce`, `extra_nonce`, `prev_hash`, `merkle_root`, `timestamp_ms`, `height` — so the seed is bound to the full block, and the `nonce` argument in stage 1 is redundant-but-intentional (it makes the hash input visually match stage 3).

### 5.3 Stage 2 — integer-only neural network

**Weight derivation** (no floats, no platform-dependent libs). Weights come from the epoch id, so no miner can precompute them before an epoch starts:

```
epoch_seed = SHA256( DOM_W ‖ U4LE(epoch_id) )
wstream(k) = SHA256( DOM_W ‖ epoch_seed ‖ U4LE(k) )        // 32 bytes

in_dim(l)  = 16 if l == 0 else 16                          // = nn_input_dim / nn_hidden_dim
weight(l,o,i) = let b = wstream(((l * nn_hidden_dim + o) * in_dim(l) + i))[0]
                let w = b as i32; if w > 127 { w -= 255 }; w     // ∈ [-128, 127]
bias(l,o)     = wstream(1_000_000 + l * nn_hidden_dim + o)[0] % 63   // ∈ [0, 62]
```

**Forward pass:**

```
x[j] = seed[j] as i32 − 128                for j in 0..nn_input_dim
activations = empty byte string
for l in 0 .. nn_layers-1:
    for o in 0 .. nn_hidden_dim-1:
        s = bias(l, o)
        for i in 0 .. in_dim(l)-1:
            s += x[i] * weight(l, o, i)          // i64 accumulator
        z[o] = fold32(s)                          // wrap to i32
    activations ‖= U4LE(z[o]) for all o          // ALL layers, pre-activation
    x[o] = max(z[o] >> 2, 0)                      // arithmetic shift, then ReLU
```

```
fold32(v) = let u = (v mod 2^32) as u32
            if u ≥ 2^31 then u − 2^32 else u      // returned as i32
```

Accumulator bound: `|s| ≤ 16 × 128 × 128 + 62 = 262 206 < 2^63`, so `i64` cannot overflow on any conforming implementation.

`>> 2` is an **arithmetic** shift right (sign-extending). ReLU is applied *after* the shift.

**Activation digest** — every layer, pre-activation, so no layer can be skipped or approximated:

```
act_digest = SHA256( DOM_S2 ‖ activations )
```

### 5.4 Stage 3 — final hash

```
final = SHA256( DOM_S3 ‖ seed ‖ act_digest ‖ U8LE(nonce) ‖ U4LE(epoch_id) )
```

`final` depends on the header (through `seed`), so no precomputation table can be reused across blocks.

### 5.5 PoW validity

```
solve(header) = ( U256_BE(final) ≤ target(header.difficulty) )
```

### 5.6 NN share of work (Section 29.3 audit rule)

The protocol cannot measure wall-clock, so the `30–50%` rule is enforced as an auditable **cost model** on the puzzle parameters:

```
nn_macs    = nn_layers × nn_hidden_dim × nn_hidden_dim        (default 3×16×16 = 768)
hash_cost  = (1 + hash_rounds + 1) × 64                        (1 hash ≡ 64 int32 MACs)
nn_share_bps = round( 10000 × nn_macs / (nn_macs + hash_cost) )
```

A puzzle registry entry is **valid** iff `min_nn_share_bps ≤ nn_share_bps ≤ max_nn_share_bps`.
Defaults give `nn_share_bps = 4000` (40%). Rejected at genesis otherwise. This is a proxy, not a stopwatch — stated plainly in `docs/status.md`.

---

## 6. Difficulty adjustment (LWMA)

Per Sections 28.2 / 28.10: a proven algorithm (linearly weighted moving average, Zawy-style), not a bespoke one.

Parameters: `difficulty_window = 60`, `change_limit_bps = 1000` (±10% per block), `min_difficulty`, `max_difficulty`.

Let `T = target_block_time_ms` and let `tip[i]` be the `i`-th block back from the tip (`tip[0]` = tip). For `i = 0 … window-1`:

```
t_i = clamp( tip[i].timestamp_ms − tip[i+1].timestamp_ms,  T/4,  5T )
W   = Σ_{k=1..window} k²                     // = window(window+1)(2window+1)/6
S   = Σ_{i=0..window-1} (window − i)² · t_i  // newest solve time weighs most
avg = floor( S / W )                         // weighted mean solve time, ms
d_raw = floor( d_prev · T / avg )            // MULTIPLICATIVE — see below
```

**The retarget must be multiplicative.** `d_new = d_prev · T / avg_solve`, not `avg_solve / T`. The latter is scale-invariant: it returns a number that is a fixed point at *every* difficulty, so the rule has no restoring force and cannot correct a hashrate change in either direction. Worked example at `T` and `d_prev = 1`: hashrate halves, blocks arrive at `2T`, and `avg_solve / T` yields difficulty `2`, which stretches the interval to `4T` — the chain runs away from the target instead of toward it. Symmetrically, doubled hashrate yields `0.5`, clamps to `min_difficulty = 1`, and the chain sticks at the floor.

With the multiplicative form the same case yields `1 · T / 2T = 0.5`, and the block interval returns to `T`. Perfect spacing (`avg_solve = T`) is a fixed point at every difficulty, which is the property the test suite asserts directly.

Because every `t_i` is clamped to `[T/4, 5T]`, `avg ≥ T/4`, so one step multiplies difficulty by at most `4` down or `5` up, and the result is at most `5 · d_prev` — comfortably inside `u128`.

Clamps:

```
d = clamp(d_raw,  max(1, d_prev · (10000 − change_limit_bps) / 10000),
                 min(MAX_DIFFICULTY, max(d_prev · (10000 + change_limit_bps) / 10000,
                                         d_prev + 1)) )
d = clamp(d, min_difficulty, max_difficulty)
```

The upper bound admits at least `+1`, otherwise a chain starting at difficulty `1` could never bootstrap upwards.

While the chain is shorter than `window + 1`, the *available* window is used with the same weight formula. Pinning difficulty for the first hour of a new chain would hand that hour to whoever shows up first; this is standard Zawy ramp-up behaviour.

### 6.1 Timestamp rules

**Consensus (deterministic, no local clock):**

```
M = median( timestamp_ms of the previous 11 blocks, or fewer if height < 11 )
timestamp_ms ≥ M
```

**Node policy (non-consensus):**

```
timestamp_ms ≤ local_now_ms + future_limit_ms
```

There is deliberately **no** consensus upper bound. An upper bound needs a reference that advances with wall time, and the only such thing is the local clock — which would make block validity depend on machine skew, so two honest nodes could disagree about the same block. The ceiling is therefore policy, applied when a block enters the chain (`validate_local_clock`), and `future_limit_ms = target_block_time_ms` — one block time, not Bitcoin's two hours.

A node that skips the local-clock check can be talked into accepting a higher-difficulty branch; that is the same tradeoff Bitcoin accepts, only with a wider window. See `docs/status.md`.

`sim/difficulty_attack_sim.py` measures this rule. Under the protocol as specified, a 40% attacker cannot make blocks arrive faster than the target spacing at any allowance: the median rule anchors honest timestamps at real time (a minority is outvoted six-to-five in the median), and the solve-time clamp bounds any single retarget to `[0.25, 5]`. The attacker's future stamps instead surface as `5T` solve times on the honest→attacker transitions, which the LWMA weights heavily, so the attack *raises* difficulty and slows the network down for the attacker as well.

Design doc §28.9 reports that a two-hour allowance let a 40% attacker reach ~104s average block time. That is not reproducible under this specification, and cannot be: 104s is below the solve-time clamp floor (`T/4` = 150s), so no retarget can ask for a difficulty that low. Those figures come from a model without the solve-time clamp, without a difficulty floor, and with honest miners copying the tip instead of anchoring on the median. `--design-doc-model` in the simulation reproduces the mechanism; the short allowance is retained regardless, as defence in depth for the case where an attacker reaches 50% and can move the median itself.

---

## 7. Supply schedule

Per Section 16. `SAT_PER_JNT = 100_000_000`.

| Parameter | Value |
|---|---|
| `halving_period` | `262 800` blocks (5 years at 10 min) |
| `start_reward` | `76 JNT` = `7_600_000_000 sat` |
| `supply_cap` | `39 945_600 JNT` = `3_994_560_000_000_000 sat` |
| `tail_emission` | `0` (v0.1; Section 11 notes tail emission as an option) |

```
halvings  = height / halving_period
reward(h) = (start_reward_sat >> halvings)       // 0 once halvings ≥ 7
```

Reward ladder: `76, 38, 19, 9, 4, 2, 1, 0`.

**Cap invariant (hard, enforced in code):** minting must never raise total issued above `supply_cap`. Because rewards are floor-divided, issued supply converges to `149 × 262 800 = 39 157 200 JNT`; the remaining `787 400 JNT` is **permanently unmintable**, not merely "reserved". `sim/supply_schedule_sim.py` regenerates these numbers and `tests/vectors/supply_vectors.json` pins them.

If a block reward would cross the cap, the coinbase collects the tips only and the surplus is unrecoverable (provable, not burned-from-circulation).

---

## 8. Fees, burn and the PSCB split

Per Sections 28.1 / 24.3: EIP-1559-shaped base fee. No new supply is minted from fees, so the cap can never be exceeded by usage.

```
fee_total(block)   = Σ fee(tx)
base_fee_total     = base_fee × gas_used(block)
tip_total          = fee_total − base_fee_total
coinbase.value     = block_reward(height) + tip_total
```

**The base-fee portion is split 50/50 (M1, §14).** Half is burned — removed
from the UTXO set and never reissued — and half accrues to the on-chain
Protocol Security & Compute Buffer reserve:

```
pscb_credit(block) = base_fee_total / 2        // floor
burned(block)      = base_fee_total − pscb     // == ceil(base_fee_total / 2)
coinbase.value     = block_reward(height) + tip_total
```

The odd satoshi goes to `burned`, not to the reserve: a burn is irrecoverable,
so conservative rounding on that side is the safe direction. Only the tip is
paid to the miner, as before.

`pscb_credit` is **reorg-correct**: it is credited per canonical block and
subtracted again when that block is rolled back, so the reserve always equals
the sum over the canonical chain. It does **not** count toward `supply_cap` —
those satoshis are already destroyed for cap purposes; the reserve is a
protocol-owned accounting claim on them, not new issuance. `verify_canonical_chain`
re-derives it by replay and fails if it diverges.

```
gas_per_tx  = 16 000 + 1 000 × input_count + 250 × output_count
gas_cap     = 2 000 000 per block

base_fee_next = base_fee + base_fee × (gas_used − gas_cap) / (gas_cap × 8)
               // clamped to [BASE_FEE_MIN = 100 sat, BASE_FEE_MAX]
               // when gas_used == gas_cap the fee rises by 1/512 per block
```

A transaction must pay `fee ≥ base_fee × gas_used(tx)`.

---

## 9. Consensus validation rules

### 9.1 Block

1. `header.height == prev.height + 1` (genesis exempt)
2. `header.prev_hash == block_hash(prev)`
3. `U256_BE(block_hash) ≤ target(header.difficulty)` — PoW valid
4. `header.difficulty == expected_difficulty(tip_history)` (§6)
5. `merkle_root == computed_merkle_root(txs)`
6. Timestamp rules (§6.1)
7. `puzzle_id` exists in the registry and is active at this height; `epoch_id == height / nn_epoch_blocks`
8. `gas_used ≤ gas_cap`
9. Every transaction passes §9.2
10. Size limits: `tx_count ≤ 5 000`, block bytes `≤ 4 000 000`

### 9.2 Transaction

1. `tx_type == 0` (standard) except index 0, which MUST be a coinbase
2. Coinbase: exactly 1 input with `prevout_hash == prev_hash`, `prevout_index == height`; exactly 1 output
3. Coinbase txid MUST NOT collide with any other txid in the block (BIP30-style defence)
4. No duplicate inputs within a transaction; no inputs already spent in the UTXO set
5. `Σ inputs ≥ Σ outputs + fee` (no inflation)
6. Every input's `signature` verifies against `msg_k` (§1.1) for the address owning the spent output
7. Coinbase outputs referencing the same address accumulate — a single miner cannot claim two matured rewards in one block
8. `coinbase.value ≤ block_reward(height) + tip_total` — miners may **not** over-claim
9. Standard tx: `lock_time` is advisory in v0.1

### 9.3 Maturity, finality

| Parameter | Meaning |
|---|---|
| `coinbase_maturity` | blocks before coinbase value is spendable |
| `finality_depth` | `h ≤ tip − finality_depth` is immutable; a reorg crossing it is rejected as `ReorgWouldCrossFinality` |

Mainnet: maturity `100`, finality `100`. Mini: `10`, `20`.

---

## 10. Network profiles (Section 17: mini version = same code, different config)

The mini version is **not** a second codebase. It is the same `jnt-core` with a different `NetworkParams`. Non-consensus constants live in code; consensus constants live in `params.rs` and are mirrored by `sim/` cross-checks.

| Parameter | `mainnet` | `mini` |
|---|---|---|
| `target_block_time_ms` | `600 000` | `1 000` |
| `halving_period` | `262 800` | `2 000` |
| `start_reward_jnt` | `76` | `76` |
| `supply_cap_jnt` | `39 945 600` | `304 000` |
| `difficulty_window` | `60` | `60` |
| `change_limit_bps` | `1000` | `1000` |
| `genesis_difficulty` | `1` | `1` |
| `min_difficulty` | `1` | `1` |
| `max_difficulty` | `2^96` | `2^40` |
| `coinbase_maturity` | `100` | `10` |
| `finality_depth` | `100` | `20` |
| `gas_cap` | `2 000 000` | `2 000 000` |
| `base_fee_initial_sat` | `1 000` | `100` |
| `nn_epoch_blocks` | `50 000` | `2 000` |
| `puzzle_id` | `1` | `1` |

`supply_cap_mini = 2 × 2 000 × 76 = 304 000 JNT`.

---

## 11. Genesis block

```
header.version      = 1
header.height       = 0
header.prev_hash    = 32 zero bytes
header.merkle_root  = merkle_root([coinbase])
header.timestamp_ms = 0
header.difficulty   = params.genesis_difficulty        // 1 ⇒ any hash valid
header.nonce        = 0
header.puzzle_id    = 1
header.epoch_id     = 0
header.extra_nonce  = "jounit-genesis" padded to 16 bytes
header.sig_scheme   = 1
coinbase            = version 1, tx_type 1, lock_time 0,
                      input { prev_hash = 32 zeros, index = 0, sig = 64 zeros, pubkey = 33 zeros },
                      output { value = 0, address = 20 zero bytes }
```

The genesis block is **not** a premine: it contains zero value and no spendable output (Section 16 — 0% founder premine is enforced in code, not just in prose).

---

## 12. Test vectors

`tests/vectors/*.json` are consumed by the Rust test suite. A language implementation is correct only if it reproduces them byte for byte.

| File | Covers | Generated by | Consumed by |
|---|---|---|---|
| `puzzle_vectors.json` | header serialization, stage 1 seed, stage 2 activation digest, stage 3 final, work-share accounting | `UPDATE_PUZZLE_VECTORS=1 cargo test -p jnt-core` | `puzzle_vectors_are_stable`, `sim/puzzle_crosscheck.py` |
| `ser_vectors.json` | input / output / tx / header byte layouts | `UPDATE_SER_VECTORS=1 cargo test -p jnt-core` | `serialization_vectors_are_stable` |
| `supply_vectors.json` | reward ladder, cumulative supply, cap invariant | `sim/supply_schedule_sim.py` | `a_supply_vector_file_exists_to_show_the_pattern`, `sim/verify_vectors.py` |
| `difficulty_vectors.json` | LWMA next-difficulty, timestamp clamp behaviour | `UPDATE_DIFFICULTY_VECTORS=1 cargo test -p jnt-core` | `difficulty_vectors_are_stable` |
| `net_vectors.json` | frame envelope, every `msg_type` payload, `VERSION` layout, locator construction (§13.12) | `UPDATE_NET_VECTORS=1 cargo test -p jnt-net` | `net_vectors_are_stable` |

`sim/puzzle_crosscheck.py` is the important one: it re-derives every puzzle digest with `sim/jounit_reference.py`, a second implementation written from the prose of this document rather than from the Rust source. If the two disagree, the disagreement is in the spec, not in either implementation.

Regenerate and verify everything with `python sim/verify_vectors.py` (`--check` to verify without writing).

---

## 13. Peer-to-peer layer (v0.2)

**Status: implemented in `jnt-net`, with the two §13.10 MUSTs (incremental
cumulative work, side-branch pruning) and the §13.8 resource bounds in place.**
This section is normative for the network layer and describes what `jnt-net`
MUST do. It was written before the code, per the same discipline as §5: where
the wire format is ambiguous, every implementation will disagree and the
disagreement will look like a consensus split.

### 13.0 What this section is, and is not

The P2P layer **relays data; it never decides anything.** Every rule that
determines whether a block is valid lives in §9 and is unchanged by anything here.
A node that receives a block MUST run the same `validate_standalone` +
`submit` path it runs for a block it mined itself. There is no "trusted peer"
fast path, no relaxed validation for relayed data, and no way for a peer to
influence a consensus decision.

**v0.2 relays blocks only.** Transactions are mined directly into blocks
(`mine_block` takes a body), so there is nothing to gossip until a mempool exists.
§13.13 records what a mempool will require; it is deliberately unspecified here
rather than guessed at.

### 13.1 Design constraints inherited from §9

Three properties of the base layer constrain the network layer, and each one
rules out an otherwise reasonable design:

**Fork choice is deterministic (§9, `chain.rs`).** Selection depends only on the
block graph. This is *why* the P2P layer needs no consensus changes: nodes may
receive blocks in any order and still agree. It also means a peer cannot cause a
split by withholding or reordering data.

**Validation needs chain state.** `submit` checks difficulty against tip history
and reorgs against undo records, so a block cannot be validated in isolation and
then stored. Validation and application are one operation, and the network layer
MUST NOT split them.

**`Chain` is single-owner.** `submit`, `adopt` and `mine_block` all take
`&mut self`. The network layer therefore MUST NOT hold `Arc<Mutex<Chain>>`: mining
is an unbounded CPU loop inside `mine_block` (`chain.rs`), and a lock held across
it would stall every peer thread for as long as the block takes to solve. Instead
there is one **chain thread** owning the `Chain`, and peer threads exchange
messages with it over channels. The chain thread is the only writer.

```
peer threads (N)                   chain thread (1)
  read socket                        own the Chain (sole writer)
  frame/deframe                      loop:
  validate framing bounds              - drain inbound channel -> submit() -> canon/utxo
  hand off Message ----------------->  - mine on request        -> submit(winner)
  <--------------- outbound           - fan out resulting INV to peers
```

Mining runs **on** the chain thread rather than beside it, because `mine_block`
needs `&mut Chain` to build the header against the current tip. A miner therefore
cannot build against a stale tip; it asks the chain thread to mine, which is
correct and costs nothing at v0.2 block times. On `mainnet` (10-minute blocks)
this means block processing waits on mining — acceptable, because a node that is
mining is by definition not required to process blocks at that instant, and
v0.2 has no mempool whose contents would go stale. A future mempool makes this a
real cost and is the reason that work must then split the two (§13.13).

### 13.2 Transport and framing

TCP. Every message is a length-prefixed frame:

```
frame = magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload(payload_len)
```

- `magic` MUST be the 4-byte network magic (§13.3). It is re-checked on **every**
  frame, not only at connect, so a peer cannot hand a valid handshake then switch
  to garbage.
- `payload_len` MUST be `≤ max_frame_bytes` (§13.8) **checked before any
  allocation.** The length prefix is attacker-controlled; this is the same class of
  bug as the bundle-length and input-count issues already fixed in §3.1/§3.5, and
  it is the single most important bound in this section.
- A frame larger than the cap MUST close the connection, not be skipped. There is
  no resynchronisation point in a stream protocol, so skipping leaves the peer
  desynchronised and able to confuse every later message.

Framing is deliberately **not** domain-tagged or hashed. It is transport, not
consensus: a frame is never hashed, never committed to by a block, and never
compared across implementations. `DOM_NET_HANDSHAKE` (§0) exists for the one
place where a hash *is* needed — the handshake challenge (§13.4).

### 13.3 Network identity

**The genesis hash does NOT identify the network.** `genesis_block(difficulty)`
(`block.rs`) derives the genesis block from difficulty alone, and both profiles
set `genesis_difficulty = 1`, so `mainnet` and `mini` produce the **identical**
genesis block:

```
2317ec84903140e2cd72be6f3c9dfd2ff36d9f8642293a5152279b4ad7a5196b
```

A handshake that compared genesis hashes would consider a mainnet node and a mini
node the same network and would relay `mainnet` blocks into a `mini` chain. Every
block would then fail §9.1 rule 4 (wrong difficulty), so no state corruption
would occur — but the node would waste bandwidth and, worse, could not be trusted
to reject a cross-network peer at all. Discrimination MUST use an explicit
parameter instead.

Each profile therefore declares a `network_magic` and a `network_id` string.
`mainnet` and `mini` MUST differ in both.

| Parameter | `mainnet` | `mini` |
|---|---|---|
| `network_magic` | `0x6A 0x4E 0x54 0x01` | `0x6A 0x4E 0x54 0x02` |
| `network_id` | `jounit/mainnet` | `jounit/mini` |

A new profile MUST pick a magic no existing profile uses. Magic reuse across two
live networks is the failure this rule exists to prevent.

**Long-term fix, not in v0.2:** give the genesis coinbase an `extra_nonce`
derived from `network_id`, which would make the genesis hash discriminating and
let the handshake compare hashes as Bitcoin does. That is a **consensus-breaking
change to the genesis block** and therefore out of scope for a networking release.
It is recorded here so the option is not lost.

### 13.4 Handshake

The first frame on every connection MUST be `VERSION`; anything else closes the
connection.

| Field | Size | Notes |
|---|---|---|
| `network_magic` | 4 | §13.3 |
| `network_id` | `1 + n` | length-prefixed string |
| `protocol_version` | 4 LE | `1` in v0.2 |
| `services` | 8 LE | bit 0 = serves blocks; v0.2 all nodes set it |
| `height` | 8 LE | best height, `0` if at genesis |
| `tip_hash` | 32 raw | tip block hash |
| `user_agent` | `1 + n` | length-prefixed, `≤ 64` bytes |
| `nonce` | 8 LE | see below |

A responder MUST reject the connection if `network_magic` or `network_id` does
not match its own, if `protocol_version` is greater than it supports, or if
`height == 0` while `tip_hash` is not the genesis hash (an inconsistent claim,
and free to reject before doing any work).

`nonce` makes the handshake **proof of possession of the socket** and nothing
more. The responder echoes the initiator's nonce in `VERACK`; the initiator
requires the echo. This defeats a trivially replayed handshake, which is worth
having on an unauthenticated transport. It is **not** peer identity: there is no
node key, no certificate, and no authentication in v0.2. A node MUST NOT treat a
successful handshake as evidence of anything beyond "something answered on the
other end of this socket". Peer reputation is therefore per-connection and
lost on reconnect — an acknowledged v0.2 limitation, not a design choice.

Both directions send `VERSION`; both then send `VERACK`. A node MUST NOT relay
anything before its own handshake completes.

### 13.5 Messages

`msg_type` values in v0.2. Values are frozen; unknown types MUST be ignored
without disconnecting, so a later version can add messages safely.

| Type | Name | Payload |
|---:|---|---|
| `1` | `VERSION` | §13.4 |
| `2` | `VERACK` | echoed `nonce` (8) |
| `3` | `PING` | `nonce` (8) |
| `4` | `PONG` | `nonce` (8) |
| `5` | `INV` | `count(2 LE) ‖ count × (kind(1) ‖ hash(32))` |
| `6` | `GETDATA` | same shape as `INV` |
| `7` | `BLOCK` | `serialize(block)` (§3.5) |
| `8` | `GETBLOCKS` | `count(2 LE) ‖ locator(count × 32) ‖ stop_hash(32)` |
| `9` | `ADDR` | `count(2 LE) ‖ count × (port(2 LE) ‖ ip(16))` |
| `10` | `TX` | `serialize(transaction)` (§3.6) |

`kind` is `1` = block and `0` = transaction (§13.14). Transactions were reserved
here before they existed, precisely so the *announcement* could be added without
changing `INV`/`GETDATA`'s shape; only delivery needed a new message type.

`msg_type = 10` was added in v0.3. It is additive by construction: the freeze rule
above already requires an unknown type to be ignored without disconnecting, so a
v0.2 node drops `TX` and stays connected. Such a node does not relay transactions,
which is a peer's choice and not a protocol violation.

Every `count` field MUST be bounded by the smallest entry that could follow,
checked before allocating — `INV` entries are 33 bytes, `ADDR` entries 18,
`GETBLOCKS` locators 32. Bounding by remaining bytes alone is the defect already
fixed in §3; the same bound applies here.

`count` MUST additionally be capped at `max_inv_per_msg` (§13.8).

**`ADDR` carries a 16-byte address, not 4.** IPv6-mapped IPv4 is the
representation, matching Bitcoin's historical choice. v0.2 listens on IPv4 only
and treats any address it cannot parse as a protocol violation rather than
guessing at a conversion.

### 13.6 Peer discovery

v0.2 has **no discovery protocol.** There is no `ADDR` gossip, no DNS seed, no
super-nodes. A node's peer set comes from its configured address book only.

This is a real limitation and the reason is worth stating: peer discovery needs a
sybil-resistance story that this protocol has not made yet. Gossiping addresses
from peers we cannot authenticate means one hostile node hands us its own
connections forever. That is acceptable for a small, operator-run network and is
not acceptable for an open one, so v0.2 does the former. `ADDR` is specced in §13.5
so the message exists, but a node MUST NOT populate its address book from it in
v0.2.

### 13.7 Relay and sync

**Relay (steady state).** On accepting a block that extends or reorgs the tip, a
node MUST `INV` it to every connected peer **except the one it came from**. On
receiving an `INV` for an unknown block, a node MUST send `GETDATA` for it.

**Invasion prevention.** A node MUST NOT relay a block it has not validated. This
is the rule that stops a cheap-PoW attacker (`difficulty = 1` on `mini` makes PoW
free) from using honest nodes as a bandwidth amplifier: an invalid block is
dropped at `submit` and never announced.

**Sync (initial).** Block-first, not headers-first. The requester sends `GETBLOCKS`
with a locator:

```
locator[0]      = tip_hash
locator[i]      = block_hash_at(height − 10ⁱ),   i = 1, 2, 3, …
locator         = capped at 500 entries; append genesis hash if absent
```

The responder walks its canonical chain back to the **first** locator hash it
recognises and `INV`s up to 500 hashes after it. The requester then `GETDATA`s
them in batches of 16, submits each, and repeats.

Headers-first would be faster and is what a mature node does, but it is
unnecessary here: a block's validity depends on tip history and undo records
(§13.1), so a header chain that cannot be applied buys nothing for a node that
must validate every block anyway. Recorded as a future optimisation.

**The requester MUST tolerate gaps.** A `BLOCK` whose parent is unknown MUST be
retained in a bounded orphan pool and re-offered when its parent arrives, not
discarded. `submit` returns `UnknownParent`, which is a normal outcome of racing
a peer's relay, not an error.

**The requester MUST NOT trust the responder's height.** A peer claiming height
`10⁹` is making the requester queue work it will never finish; the batch size
stays 16 and the requester advances only on blocks it has actually applied.

### 13.8 Resource bounds

Every bound here is attacker-controlled unless noted. A node that omits one has a
remotely triggerable failure, so these are requirements, not tuning.

| Bound | Value | Protects |
|---|---|---|
| `max_frame_bytes` | `4 100 000` | one `max_block_bytes` block + envelope |
| `max_inv_per_msg` | `500` | 500 × 33 = 16.5 KB per `INV` |
| `max_addr_per_msg` | `100` | 100 × 18 = 1.8 KB per `ADDR` |
| `max_locator_len` | `500` | 500 × 32 = 16 KB per `GETBLOCKS` |
| `max_peers` | `125` | thread count, fd count |
| `max_inbound` | `32` | inbound connection flood |
| `handshake_timeout` | `20 s` | half-open connection exhaustion |
| `ban_score_threshold` | `100` | misbehaviour (below) |
| `orphan_pool_max` | `64` | memory from parentless blocks |
| `max_relay_in_flight` | `128` | outstanding transaction requests (§13.14) |
| `max_relay_pending` | `1 024` | advertised-but-unrequested txids (32 KB) |
| `max_relay_known` | `4 096` | relay-loop suppression set (128 KB) |
| `max_tx_inv_batch` | `64` | txids requested per `GETDATA` |
| `tx_relay_per_peer_per_min` | `600` | transaction flood from one peer |
| `tx_request_timeout` | `30 s` | an unanswered transaction request is forgotten (§13.14) |

`max_frame_bytes` is `max_block_bytes + 100 000`, so a maximum-size block is
relayable with room for its envelope. `max_inbound < max_peers` because inbound
connections are the ones an attacker chooses; outbound are ours.

A peer exceeding any inbound bound is **banned** (§13.9), not merely
disconnected. `max_peers` alone is not a defence: an attacker who fills it stops
honest nodes connecting, which is why inbound is capped lower and why exceeding
inbound limits scores rather than merely closing.

### 13.9 Misbehaviour and bans

Each peer connection carries a ban score, starting at `0`, reset on reconnect.
Reaching `100` bans the address. Scores decay by `1` per hour.

| Misbehaviour | Score |
|---|---:|
| Frame over `max_frame_bytes` | `+100` (immediate ban) |
| Bad `magic` after handshake | `+100` (immediate ban) |
| Wrong `network_id` / `network_magic` | `+10`, disconnect |
| Oversized declared `count` in any message | `+20` |
| First frame not `VERSION` | `+20` |
| `BLOCK` failing §9 validation | `+10` |
| `BLOCK` whose parent is unknown, repeated | `+5` |
| Unresponsive to `PING` (60 s) | `+10` |
| `ADDR` ignored in v0.2, still sent | `+10` |
| `TX` failing deserialisation or `check_tx` | `+10` |

**A block failing validation is +10, not a ban.** Difficulty and PoW failures are
normal on a chain under hashrate churn, and an honest peer relaying a block during
a reorg race can easily send one the receiver has already applied differently. A
node that bans on this would disconnect honest peers precisely when the network is
busiest. Reaching a threshold of *repeated* invalid blocks is what bans.

**Invalid blocks MUST NOT enter the block store.** `submit_at` already drops a
block that cannot be applied (§9.1), and that behaviour is load-bearing here: a
stored block contributes its declared difficulty to `cumulative_work`, so retaining
an unusable one lets a peer accumulate fork-choice weight no reorganisation can
realise. `ReorgWouldCrossFinality` is the deliberate exception — the block is
valid, and dropping it would orphan its descendants.

### 13.10 Performance requirements

These are consensus-adjacent. A single node never hits them; a node accepting
relayed blocks does, and a peer can trigger them deliberately. **v0.2 MUST NOT ship
without the two marked items.**

**`cumulative_work` is O(chain length) and `best_candidate` calls it per stored
block** (`chain.rs`). One `submit` is therefore O(stored²), and side branches are
retained forever, so the cost only grows. A peer submitting blocks turns this into
a quadratic amplifier — the cheapest possible way to burn a node's CPU.

1. **MUST (blocking), implemented:** maintain cumulative work incrementally per
   stored block, computed once at insert as `parent_work + difficulty`. Fork
   choice becomes O(stored) to scan and O(1) per block to score. This changes no
   consensus outcome: the value is identical, since it is a sum along the same
   path.
2. **MUST (blocking), implemented:** prune side branches. Canonical history is
   retained in full — undo records, `verify_canonical_chain` and persistence all
   replay from genesis. Every **non-canonical** block at or below
   `tip − finality_depth` is dropped, together with any stored descendant of a
   dropped block (a block whose parent is gone cannot be walked to). Pruning runs
   when the store exceeds `canon_len + 4 × finality_depth`.

   This also settles a behaviour the rule was previously ambiguous about: a valid
   branch that forks *below* the finality point used to be retained with its work
   counted, so fork choice kept selecting it and the node refused honest blocks
   until honest work caught up. Such a branch is now forgotten, and honest blocks
   are accepted again. **§9.3 is unchanged** — a reorg whose fork point is at or
   below the finality height is still refused with `ReorgWouldCrossFinality`. What
   changes is only how long the node keeps a branch it was never going to follow.
3. **SHOULD:** `adopt()` snapshots the whole UTXO set per reorg — O(chain length).
   The incremental undo primitives already exist (`ledger.rs`), so a reorg should
   unwind block by block. Not a DoS vector on its own: a reorg crossing
   `finality_depth` is refused outright (§9.3), which bounds how often this runs.
4. **SHOULD:** persist blocks append-only rather than rewriting the whole chain
   file per block. `Store::save_chain` currently rewrites every block on every
   mined block, which is O(n) per block and O(n²) over a sync.

### 13.11 Invariants a node MUST preserve

The point of this section, and the tests that must assert them:

1. **Relay cannot change validity.** A block accepted via P2P MUST equal, byte for
   byte, the block accepted via `submit` locally. Tested by running the same block
   through both paths and comparing resulting state.
2. **Two nodes converge regardless of delivery order.** Node A and node B fed the
   same blocks in opposite orders MUST reach the same tip. This is the property
   §13.1 exists to protect; it is already tested for direct submission
   (`fork_choice_is_independent_of_block_arrival_order`) and MUST be extended to
   the P2P path.
3. **A node that has processed no blocks MUST equal a node that processed nothing.**
   A fresh node receiving a genesis-only `VERSION` MUST stay at genesis.
4. **Cross-network isolation.** A `mini` node MUST refuse a `mainnet` connection at
   handshake and MUST NOT relay a single block.
5. **Invalid blocks never enter the store.** After any sequence of invalid `BLOCK`
   messages, the block store and `cumulative_work` MUST be unchanged.
6. **No unbounded growth from hostile input.** A peer sending maximum-size frames,
   maximum `count` fields and orphan blocks MUST NOT grow any bounded structure
   past §13.8.
7. **Handshake is not authentication.** No code path may treat a completed
   handshake as authorisation for anything.

### 13.12 Test vectors

`net_vectors.json` covers the wire format, pinned the same way as the other
vector files (§12): generated from source, never hand-edited, and a second
implementation that disagrees has a bug, not a rounding difference.

| Covers | Note |
|---|---|
| Frame encode/decode round-trip at `max_frame_bytes` | the boundary that matters |
| Frame decode rejects `payload_len > max_frame_bytes` | must not allocate |
| Every `msg_type` payload round-trip | frozen values from §13.5 |
| `VERSION` field layout, all profiles | both networks |
| Locator construction from a 1 000-block chain | exponential spacing, 500 cap |
| `GETBLOCKS` response against 3 divergent chains | responder walk-back |

### 13.13 Unresolved, deliberately

Listed so these are decisions rather than oversights:

- **Peer identity.** No node keys. Reputation is per-connection (§13.4).
- **Discovery.** Address book only (§13.6). Sybil resistance unaddressed.
- ~~**Transaction relay.**~~ **Resolved in §13.14 (v0.3).** It was left unspecced
  on purpose — "better specified from a real implementation than guessed at now" —
  and the implementation is what settled the shape: the `kind = 0` reservation in
  §13.5 turned out to be sufficient for the announcement, so only delivery needed
  a new message type. Conflict sets, re-validation after reorg and fee ordering
  came from the mempool, not from the wire.
- **Headers-first sync.** Deferred with justification (§13.7).
- **Compact blocks / BIP-152.** Later; the 500-hash `INV` path is adequate first.
- **Genesis network discrimination.** Needs a consensus-breaking genesis change
  (§13.3); `network_magic` is the v0.2 workaround.

### 13.14 Transaction relay

**Transaction relay does not change consensus, and no rule here can.** A
transaction arriving over the wire is admitted by the same `check_tx` against the
same state as one built locally — §13.11 invariant 1 extended from blocks to
transactions. Nothing in this section may reach `Chain::submit`: a relayed
transaction becomes consensus-relevant only if a block containing it is mined or
received, and that block is validated exactly as §13.7 requires. The mempool is
not consensus state, so a peer cannot use this section to make an invalid
transaction valid.

**Announcement and request reuse the existing messages.** `INV` and `GETDATA`
carry `kind = 0` entries naming transaction ids, with the payload shape unchanged.
Delivery uses `TX` (§13.5).

**Flow.**

1. On a locally accepted transaction, announce its txid to every peer except the
   one it arrived from.
2. On `INV` with `kind = 0`, request the txids not already held or already
   requested, batched into `GETDATA` at `max_tx_inv_batch` per message.
3. On `GETDATA` with `kind = 0`, answer with the transactions the node's own pool
   holds, and answer nothing for the rest. A node is not obliged to serve a
   transaction it does not have, and serving one from anywhere but the pool would
   mean relaying something the node never validated.
4. On `TX`, deserialise, validate, admit to the pool; if admission succeeded and
   the transaction was not already known, announce it onward to the other peers.

**A peer may not make the node do unbounded work.**

- The relay request set is capped at `max_relay_in_flight`; the
  advertised-but-unrequested queue at `max_relay_pending` (§13.8).
- **An unanswered request is forgotten after `tx_request_timeout`.** A cap alone is
  not enough, because the request set is global rather than per-peer and the cap
  bounds how many requests can be held, not how long. Without a deadline a peer
  could announce `max_relay_in_flight` transactions, deliver none, and stop the
  node requesting transactions from *every* peer for as long as it stayed
  connected — and the withheld txids would be marked as already requested, so a
  peer that did hold them would be ignored too. Thirty-two bytes per announcement
  would buy a permanent, node-wide relay stall. Expiry bounds the worst case to a
  delay, and a request that expires is retried against whoever announces the txid
  next; the txid is never blacklisted.
- The set of txids remembered for relay-loop suppression is capped at
  `max_relay_known`, evicting oldest-first. **Eviction weakens suppression rather
  than breaking it:** a re-announced old transaction is requested at most once
  more, and every path that makes a node *do* work is separately bounded, so the
  worst case is a bounded amount of repeated work rather than growth.
- Per-peer transaction throughput is limited to `tx_relay_per_peer_per_min`.
  Exceeding it scores the peer, and the §13.8 rule applies: exceeding an inbound
  bound bans rather than merely disconnecting.
- A `TX` payload over `max_frame_bytes` is rejected by the frame layer before any
  allocation (§13.2 item 1), so no separate transaction size limit exists. There
  deliberately is not one: a relay cap tighter than `max_block_bytes` could make a
  transaction that consensus accepts permanently unrelayable, which is
  censorship. A transaction larger than a whole block is refused by the pool
  instead, where the reason is checkable against `max_block_bytes`.
- A transaction already present in the pool or already announced is not requested
  and not relayed again.

**Invalid transactions are misbehaviour, not noise.** A `TX` that fails
deserialisation or `check_tx` is charged `+10` (§13.9) and is never relayed
onward. **A node MUST NOT relay a transaction it did not itself admit** — that is
what stops a peer from using a node as an amplifier for data the node knows to be
invalid.

**Reorg re-admission is local.** A transaction the canonical chain un-confirmed is
re-admitted to the pool (§13.10) and, once re-admitted, announced like any other.
There is no wire message for un-confirmation: a peer that applied the same reorg
draws the same conclusion from the same blocks.

---

## 14. Protocol mechanisms (M1–M5)

These are the mechanisms the design calls for by name. The table below is the
authoritative statement of which are **consensus-active today** — meaning a
node's validation or state machine depends on them — and which are defined
data structures with no effect on consensus yet. The distinction is stated here
because the alternative, a document that lists all five as shipped, hides the
most important fact about them: **only M1 can change what a node accepts.**

| # | Mechanism | Module | Consensus-active | § |
|---|---|---|---|---|
| M1 | 50/50 PSCB base-fee split | `fees.rs`, `chain.rs` | **Yes** — changes the UTXO set and therefore supply accounting | §8 |
| M2 | Anti-collusion slash vault (50% burn + 50% linear vesting) | `slash.rs` | No — defined and tested, nothing creates a slash record yet | this section |
| M3 | Hardware-agnostic compute IR + attestation envelope | `compute_ir.rs` | No — serialization and signing hashes only | this section |
| M4 | Memory-bound HBM scratchpad PoW | `hbm_pow.rs` | No — an alternative puzzle body, not registered in the §5.1 registry | this section |
| M5 | BLS12-381 aggregate finality gadget | `bls_checkpoint.rs` | No — `BlsVerifier` is a trait; only a mock implementation exists | this section |

**Why M2–M5 are not wired in.** Each needs a rule that no spec currently
states: what evidence proves a compute result fraudulent (M2), who is allowed to
submit a compute task and how a result enters a block (M3), whether the HBM
puzzle replaces or composes with the §5 puzzle and how difficulty maps onto it
(M4), and who the validator set is and how a checkpoint is relayed (M5). M2 and
M4 in particular would change consensus: a slash moves coins and an HBM stage
changes what counts as valid work. Guessing those rules in code rather than in
this document would have been the wrong order, so the modules exist, are tested
against their stated invariants, and are documented as inactive.

### 14.1 M2 — Anti-collusion slash vault

On a proven-fraudulent compute result, a validator's stake splits:

```
burned     = stake / 2                        // destroyed, never reissued
vest_total = stake − burned                   // == ceil(stake / 2)
unlock     = slash_height + vesting_period
```

`vest_total` pays back to the *original* validator, `ceil(vest_total /
vesting_period)` per block. Two properties are enforced: the split is exact
(`burned + vest_total == stake`, no satoshi created or lost), and the final block
releases the remainder, so total vested over the period equals `vest_total`
exactly. Exhausted records are pruned, so the vault is bounded.

Mainnet `vesting_period` = 52 560 blocks (365 days at 10-minute blocks); the
mini profile uses 2 000.

The burn is the part that carries the security argument: a colluding validator
who slashes *themselves* recovers only the vesting half, and only by continuing
honest work for a year.

### 14.2 M3 — Compute IR and attestation

A `ComputeTask` commits, under domain tag `0xC0`, to `task_id`, `worker_address`,
`hardware_target`, `quantization_mode`, `input_hash`, `flop_count` and
`deadline_block`. A `ComputeAttestation` commits under `0xC1` to that task hash
plus a `result_hash`. Hardware targets (`Cuda`, `Rocm`, `Ane`, `Tpu`,
`Photonic`, `Generic`) and quantization modes (`Int8`, `Fp16`, `Fp32`,
`BFloat16`) are enumerated with explicit discriminants, so a future target is a
new variant rather than a change to an existing encoding.

### 14.3 M4 — Memory-bound HBM scratchpad PoW

A proof of work stage whose cost is memory *latency* rather than arithmetic: a
scratchpad of `lanes` cache lines (32 bytes each), seeded from the header hash,
followed by `accesses` pseudorandom hops where the next lane index is derived
from a SHA-256 output. Mainnet is 16 384 lanes (512 KiB) and 64 accesses.

The security claim is that the access sequence cannot be precomputed without the
header, so an ASIC cannot parallelise it and a cloud burst cannot amortise it.
It is **not** registered as a `puzzle_id` in §5.1, so it validates nothing today.

### 14.4 M5 — BLS aggregate finality

`BlsPublicKey` (48-byte compressed G1) and `BlsSignature` (96-byte compressed
G2) are typed wrappers, so a wrong-size key cannot be constructed. A
`CheckpointPayload` commits under domain tag `0xB1` to epoch, height, block hash
and validator-set hash. `ValidatorSet` sorts keys at construction, so its hash
does not depend on insertion order. Quorum is `ceil(n × 2/3)`, and a signer set
is carried as a bitmap of `n` bits. `BlsVerifier` is a trait so the pairing check
can be swapped for a real implementation (`blst`) without touching the chain.

**It is a mock today.** `MockBls` accepts any non-zero signature, so no code path
in this repository performs a pairing, and no absolute-finality guarantee is in
force. Treat §14.4 as a specification of an envelope, not of a working gadget.