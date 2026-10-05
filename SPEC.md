# JOUNIT PROTOCOL SPECIFICATION

**Version:** 0.1 (foundation)
**Status:** Draft — normative for `jnt-core` v0.1.x
**Scope:** Layer 1 only (base layer). Layer 2 (useful work / Verified Work Certificates) is specced in `docs/roadmap.md`, not implemented here.

This document is the **normative reference**. Any implementation in any language must produce identical byte-level output for the vectors in `tests/vectors/`.

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

### 3.1 `Input` — 133 bytes

| Field | Size |
|---|---|
| `prevout_hash` | 32 raw |
| `prevout_index` | 4 LE |
| `signature` | 64 raw |
| `pubkey` | 33 raw |

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
| `inputs` | `input_count × 133` |
| `output_count` | 4 LE |
| `outputs` | `output_count × 28` |

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

## 8. Fees and burn

Per Sections 28.1 / 24.3: EIP-1559-shaped base fee that is **burned**; only the tip is paid to the miner. No new supply is minted from fees, so the cap can never be exceeded by usage.

```
fee_total(block)   = Σ fee(tx)
base_fee_total     = base_fee × gas_used(block)
tip_total          = fee_total − base_fee_total
coinbase.value     = block_reward(height) + tip_total
```

`base_fee_total` is burned (removed from the UTXO set, never reissued).

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

`tests/vectors/*.json` are consumed by the Rust test suite **and** by `sim/puzzle_crosscheck.py`. A language implementation is correct only if it reproduces them byte for byte.

| File | Covers |
|---|---|
| `puzzle_vectors.json` | header serialization, stage 1 seed, stage 2 activation digest, stage 3 final, work-share accounting |
| `ser_vectors.json` | input / output / tx / header byte layouts |
| `supply_vectors.json` | reward ladder, cumulative supply, cap invariant |
| `difficulty_vectors.json` | LWMA next-difficulty, timestamp clamp behaviour |

Regenerate with `sim/verify_vectors.py`.