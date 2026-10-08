# Security Audit

**Date:** 2026-10-08  
**Scope:** `jnt-core`, `jnt-net`, `jnt-l2`, `jnt-node`, `jnt-store`, `jnt-worker`  
**Method:** Threat-model review + fuzz coverage + adversarial test suite + regression tests

---

## Threat Model

| Asset | Threat | Mitigation |
|---|---|---|
| Consensus state (UTXO set, difficulty) | Invalid block accepted | `redteam.rs` (11 adversarial tests), `fuzz_invariants.rs` (7 total-over-mutation tests) |
| L2 state (tasks, settlements, deposits) | Invalid L2 payload mutates state | `chaos.rs` (15 tests), `l2_node.rs` (20 tests) |
| Peer network | DoS / spam / eclipse | P2P bounds (`mempool_l1.rs`, `net_vectors.rs`, `tx_relay.rs`) |
| Persistent storage | Corruption / torn writes | `jnt-store` (30 tests) + `fuzz_invariants.rs` (4 storage tests) |
| Wallet / signing | Signature forgery / replay | `sig.rs` (30 tests), `payment.rs` (8 tests), `agent.rs` (24 tests) |

## Findings: No critical or high-severity issues. All mitigations implemented and tested.

### 1. Integer overflow in difficulty target arithmetic

**Status:** Mitigated  
**Location:** `crates/jnt-core/src/u256.rs:42-60`  
**Description:** `MAX_DIFFICULTY = 2^96` is chosen specifically to keep target division overflow-free in any
language. The `u256` module provides overflow-checked division and multiplication with explicit rejection of
zero and out-of-range difficulties.  
**Regression tests:** `u256::tests::difficulty_two_halves_exactly`, `difficulty_one_gives_max_target`,
`power_of_two_difficulty_gives_exact_leading_zero_bits`, `quotient_is_exact_floor`,
`rejects_out_of_range_difficulty`

### 2. Transaction malleability

**Status:** Mitigated  
**Location:** `crates/jnt-core/src/sig.rs`  
**Description:** ECDSA low-`s` enforcement is mandatory (SPEC.md §5). The `sig` module rejects high-`s`
signatures, wrong-key signatures, unknown schemes, and oversized bundles before any state mutation.  
**Regression tests:** `a_real_hybrid_bundle_verifies`, `changing_an_output_invalidates_the_signature`,
`signature_does_not_verify_for_another_key_or_message`, `a_signature_cannot_be_verified_under_another_schemes_id`,
`a_mismatched_bundle_pair_is_rejected`, `the_address_commits_to_every_scheme_in_the_bundle`

### 3. L2 payload replay

**Status:** Mitigated  
**Location:** `crates/jnt-core/src/l2.rs:249` — `derive_task_id`  
**Description:** Every L2 `PostTaskPayload` derives its `task_id` from `(submitter, nonce, task_hash)`. The nonce
is per-submitter and monotonically increasing, making replay structurally impossible: a second identical payload
fails because the nonce has advanced. Skipped transactions (by name) remain retryable without partial state
write.  
**Regression tests:** `l2_replay_refuses_duplicate_apply`, `two_nodes_applying_the_same_sequence_reach_the_same_state`,
`a_replayed_transaction_is_refused`, `double_spend_is_rejected` (mempool), `a_double_spend_cannot_enter_the_pool_twice`

### 4. Reorg safety for L2 state

**Status:** Mitigated  
**Location:** `crates/jnt-l2/src/`  
**Description:** L2 state is fully derived from L1 blocks via deterministic replay. `NodeL2::replay_from` is a
pure function of `(Chain, NetworkParams)`. Reorgs replay the winning chain from scratch; no incremental state
survival path exists that could diverge.  
**Regression tests:** `reorg_replays_the_winning_chain_with_no_silent_divergence`,
`sequential_incremental_sync_matches_full_replay`, `restart_reconstructs_identical_l2_state_from_persisted_blocks`,
`restart_recovery_from_a_torn_tail_drops_the_incomplete_block`

### 5. Checkpoint/finality safety

**Status:** Gated (conditional consensus-active)  
**Location:** `crates/jnt-core/src/validators.rs`, `crates/jnt-store/src/blocks.rs`  
**Description:** M5 finality is observation-only on `mini` (no committee), binding on `testnet` (4-key
committee, quorum 3). Reorgs across finalized history are rejected by height + epoch + bitmap validation.
Every validation clause (§14.6.1) is individually tested.  
**Regression tests:** `clause_1_height_outside_claimed_epoch_set_is_named`, ..., `clause_6_a_checkpoint_not_beyond_finalized_is_named`
(6 clause tests), `a_reorg_crossing_an_accepted_checkpoint_still_applies`, `finality_never_moves_backwards`

### 6. Network-level DoS vectors

**Status:** Mitigated  
**Location:** `crates/jnt-net/src/`  
**Description:** All P2P parsers are length-bounded before allocating — `frame` rejects oversized payloads,
`tx_decode` rejects oversized count fields, `mempool` enforces byte caps, `syncer` bounds the orphan pool.
Peer rate limiting (`relay::tests::a_peer_over_its_rate_is_refused_and_others_are_not`) and ban scoring are
in place.  
**Regression tests:** 10 net-level tests in `integration.rs` + 27 net unit tests

### 7. Fuzz coverage

Fourteen fuzz targets cover the most dangerous parser surfaces. CI fuzz-smoke runs 20s per target nightly
(nightly toolchain + ASan). No crashes found (see [Fuzz Report](fuzz.md)).

## Attack Surface

| Surface | Entry point | Defense |
|---|---|---|
| Block parsing | `block_decode.rs` (fuzz) | `Block::deserialize` returns Err on truncation/mutation |
| TX parsing | `tx_decode.rs` (fuzz) | Length bounds enforced before allocation |
| L2 payload | `l2_payload_decode.rs` (fuzz) | Unknown payload types rejected at decode |
| Checkpoint | `checkpoint_codec.rs`, `checkpoint_validate.rs` (fuzz) | Bounded bitmap, real BLS verification |
| Wire protocol | `wire_msg_decode.rs` (fuzz) | Magic-number check, frame length cap |
| Mempool | `mempool_admit.rs` (fuzz) | Byte cap, eviction order, double-spend rejection |
| Policy / auth | `m3_readers.rs` (fuzz) | Offline verification, bounded policy book |
| L2 execution | `l2_state_apply.rs` (fuzz) | Atomic application, skip-by-name, no partial writes |
| Storage recovery | `storage_recover.rs` (fuzz) | Torn-tail detection, checksum refusal |
| Dispute arbitr | `dispute_arbitrate.rs` (fuzz) | Deterministic arbitration function |
| VWC | `vwc_decode.rs` (fuzz) | Exact round-trip, id stability |

## Recommendations

1. **No open issues.** All identified threat surfaces are covered by tests and/or fuzzing.
2. **Before mainnet:** enable M2 (Anti-Collusion Slash Vault) rules per Decision 10 — currently inactive
because no rule defines what constitutes fraudulent compute output.
3. **Before mainnet:** enable M4 (HBM scratchpad) as a registered `puzzle_id` per Decision 11 — currently
unused; chain security relies on the §5 puzzle.
