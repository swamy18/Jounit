//! M4 Protocol Mechanism: Memory-Bound HBM Scratchpad PoW (Anti-ASIC).
//!
//! Standard hash-only PoW (SHA-256 used by Bitcoin) is trivially accelerated
//! by ASICs because the bottleneck is arithmetic throughput, which custom
//! silicon can provide cheaply. GPUs, NPUs, and the compute workers in the
//! Jounit network already have large, high-bandwidth DRAM (HBM2e / HBM3 /
//! GDDR6X / LPDDR5). This puzzle exploits that advantage:
//!
//! Algorithm overview
//! ------------------
//! 1. Build a deterministic **scratchpad** S of SCRATCHPAD_BYTES bytes, derived
//!    from the block header seed via iterated SHA-256 (keyed by seed).
//! 2. Perform ACCESSES memory reads of 32 bytes each. Each access address
//!    depends on the *previous* read result, creating a sequential memory
//!    access chain that cannot be pipelined without storing the entire pad.
//! 3. Mix all reads into a 32-byte accumulator using XOR + SHA-256 rounds.
//! 4. The final accumulator is the "memory hash". PoW difficulty applies to
//!    this value rather than to the plain header hash.
//!
//! ASIC resistance properties
//! --------------------------
//! - Requires SCRATCHPAD_BYTES of DRAM bandwidth per attempt (not cache-able
//!   at realistic PoW hardware cache sizes).
//! - Sequential data dependency prevents multi-attempt pipelining on the same
//!   silicon resource.
//! - Scratchpad is regenerated from the header: nonce-rolling is free (no
//!   precomputation advantage), but scratchpad-caching is not (scratchpad
//!   changes with every nonce).
//!
//! Note on defaults
//! ----------------
//! The default `SCRATCHPAD_BYTES` (1 MiB) and `ACCESSES` (64) are chosen for
//! test-suite speed. Production values would use 8–64 MiB scratchpad and
//! 256–1024 accesses; those are network parameters, not constants.
//!
//! SPEC.md §M4.

use crate::block::Header;
use crate::hash::{sha256, Hash};
use crate::u256::{target_for_difficulty, U256};

/// Default scratchpad size in bytes. Must be a power of two for fast modular
/// indexing. 1 MiB is the test-suite default; production uses larger values.
pub const SCRATCHPAD_BYTES: usize = 1024 * 1024; // 1 MiB

/// Number of sequential random-access reads to perform per PoW attempt.
pub const ACCESSES: usize = 64;

/// Number of 32-byte lanes in the scratchpad.
pub const LANES: usize = SCRATCHPAD_BYTES / 32;

// ---------------------------------------------------------------------------
// Scratchpad construction
// ---------------------------------------------------------------------------

/// Derive the ACCESSES-round memory hash for a given block header.
///
/// This is the value that PoW difficulty is applied to (instead of the plain
/// block hash). Call `satisfies_difficulty(memory_hash, difficulty)` to check
/// PoW validity.
///
/// The function is intentionally non-parallelisable:
/// - Each access address = `u64::from_le_bytes(state[..8]) % LANES`
/// - `state` depends on the previous read, so you cannot compute access[N+1]
///   without finishing access[N].
pub fn memory_hash(header: &Header, lanes: usize, accesses: usize) -> Hash {
    let seed = build_seed(header);
    let scratchpad = build_scratchpad(&seed, lanes);
    mix_accesses(&scratchpad, &seed, lanes, accesses)
}

/// Build a 64-bit seed from the block header (deterministic, covers all fields).
fn build_seed(header: &Header) -> Hash {
    // Start with the header's own serialized bytes, then SHA-256.
    let hb = header.serialize();
    sha256(&[&hb])
}

/// Expand the seed into a `lanes * 32`-byte scratchpad using iterated SHA-256.
///
/// S[0] = SHA-256(seed || 0u64_le)
/// S[i] = SHA-256(S[i-1] || i_u64_le)
///
/// This is sequential and ~1 SHA-256 per 32 bytes. For a 1 MiB pad: 32768
/// hashes. An ASIC would need ~32768 * 64ns = ~2ms per scratchpad build,
/// during which it cannot be hashing another candidate — so multi-rate ASIC
/// advantage is eliminated.
fn build_scratchpad(seed: &Hash, lanes: usize) -> Vec<Hash> {
    let mut pad = Vec::with_capacity(lanes);
    let mut prev = *seed;
    for i in 0u64..lanes as u64 {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&prev);
        input[32..].copy_from_slice(&i.to_le_bytes());
        prev = sha256(&[&input]);
        pad.push(prev);
    }
    pad
}

/// Sequential memory-access chain: mix `accesses` reads into a 32-byte state.
fn mix_accesses(pad: &[Hash], seed: &Hash, lanes: usize, accesses: usize) -> Hash {
    let mut state = *seed;
    for _ in 0..accesses {
        // Derive access index from current state (sequential dependency)
        let idx = u64::from_le_bytes(state[..8].try_into().unwrap()) as usize % lanes;
        let lane = &pad[idx];
        // XOR state with the lane, then SHA-256 to mix
        let mut mixed = [0u8; 64];
        mixed[..32].copy_from_slice(&state);
        mixed[32..].copy_from_slice(lane);
        state = sha256(&[&mixed]);
    }
    state
}

// ---------------------------------------------------------------------------
// HBM PoW checker
// ---------------------------------------------------------------------------

/// Check whether a block header satisfies the HBM scratchpad PoW target.
///
/// Replaces `U256::from_be_bytes(block.block_hash()) <= target` for M4
/// enabled blocks. The `lanes` and `accesses` parameters should come from
/// `NetworkParams` in production (see `Cargo.toml` feature gates).
pub fn hbm_satisfies(header: &Header, difficulty: u128, lanes: usize, accesses: usize) -> bool {
    let mh = memory_hash(header, lanes, accesses);
    let Ok(target) = target_for_difficulty(difficulty) else {
        return false;
    };
    U256::from_be_bytes(mh) <= target
}

/// PoW configuration for the HBM puzzle (carried in network params or block header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HbmConfig {
    /// Scratchpad size = lanes * 32 bytes.
    pub lanes: usize,
    /// Number of sequential random accesses per attempt.
    pub accesses: usize,
}

impl HbmConfig {
    /// Lightweight config for unit tests (fast, but still sequential).
    pub fn test() -> Self {
        HbmConfig {
            lanes: 256, // 8 KiB scratchpad
            accesses: 8,
        }
    }

    /// Production-grade config. 1 MiB scratchpad, 64 accesses.
    pub fn production() -> Self {
        HbmConfig {
            lanes: LANES,
            accesses: ACCESSES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::genesis_block;
    use crate::params::NetworkParams;

    fn test_cfg() -> HbmConfig {
        HbmConfig::test()
    }

    fn genesis_header() -> Header {
        genesis_block(NetworkParams::mini().genesis_difficulty).header
    }

    // ------------------------------------------------------------------
    // Scratchpad properties
    // ------------------------------------------------------------------

    #[test]
    fn scratchpad_has_correct_size() {
        let seed = [0xABu8; 32];
        let lanes = 64usize;
        let pad = build_scratchpad(&seed, lanes);
        assert_eq!(pad.len(), lanes);
    }

    #[test]
    fn scratchpad_lanes_are_distinct() {
        let seed = [0x77u8; 32];
        let pad = build_scratchpad(&seed, 16);
        // With iterated SHA-256 each lane is distinct (collision probability ~0)
        for i in 0..pad.len() {
            for j in (i + 1)..pad.len() {
                assert_ne!(pad[i], pad[j], "lanes {i} and {j} collided");
            }
        }
    }

    #[test]
    fn different_seeds_give_different_scratchpads() {
        let pad_a = build_scratchpad(&[0u8; 32], 8);
        let pad_b = build_scratchpad(&[1u8; 32], 8);
        assert_ne!(pad_a[0], pad_b[0]);
    }

    // ------------------------------------------------------------------
    // memory_hash properties
    // ------------------------------------------------------------------

    #[test]
    fn memory_hash_is_deterministic() {
        let h = genesis_header();
        let cfg = test_cfg();
        let mh1 = memory_hash(&h, cfg.lanes, cfg.accesses);
        let mh2 = memory_hash(&h, cfg.lanes, cfg.accesses);
        assert_eq!(mh1, mh2, "must be deterministic");
    }

    #[test]
    fn memory_hash_differs_from_plain_block_hash() {
        let block = genesis_block(1);
        let cfg = test_cfg();
        let mh = memory_hash(&block.header, cfg.lanes, cfg.accesses);
        let bh = block.block_hash();
        assert_ne!(mh, bh, "HBM hash and block hash must differ");
    }

    #[test]
    fn nonce_change_changes_memory_hash() {
        let mut h = genesis_header();
        let cfg = test_cfg();
        let mh1 = memory_hash(&h, cfg.lanes, cfg.accesses);
        h.nonce ^= 1;
        let mh2 = memory_hash(&h, cfg.lanes, cfg.accesses);
        assert_ne!(mh1, mh2, "nonce change must change the memory hash");
    }

    #[test]
    fn extra_nonce_change_changes_memory_hash() {
        let mut h = genesis_header();
        let cfg = test_cfg();
        let mh1 = memory_hash(&h, cfg.lanes, cfg.accesses);
        h.extra_nonce[0] ^= 0xFF;
        let mh2 = memory_hash(&h, cfg.lanes, cfg.accesses);
        assert_ne!(mh1, mh2, "extra_nonce change must propagate");
    }

    // ------------------------------------------------------------------
    // hbm_satisfies
    // ------------------------------------------------------------------

    #[test]
    fn difficulty_one_always_satisfies() {
        // Difficulty 1 means every hash satisfies (target is all-ones).
        let h = genesis_header();
        let cfg = test_cfg();
        assert!(
            hbm_satisfies(&h, 1, cfg.lanes, cfg.accesses),
            "difficulty 1 must always pass"
        );
    }

    #[test]
    fn difficulty_max_never_satisfies() {
        // u128::MAX difficulty means target is effectively zero — impossible.
        let h = genesis_header();
        let cfg = test_cfg();
        assert!(
            !hbm_satisfies(&h, u128::MAX, cfg.lanes, cfg.accesses),
            "max difficulty must always fail"
        );
    }

    // ------------------------------------------------------------------
    // HbmConfig
    // ------------------------------------------------------------------

    #[test]
    fn test_config_is_faster_than_production() {
        let t = HbmConfig::test();
        let p = HbmConfig::production();
        assert!(t.lanes < p.lanes, "test lanes must be smaller");
        assert!(t.accesses < p.accesses, "test accesses must be fewer");
    }
}
