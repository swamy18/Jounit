//! Network profiles. SPEC.md §10.
//!
//! Section 17 of the design doc requires the mini version to be the *same code*
//! with different parameters — never a second codebase. Every consensus constant
//! therefore lives here, and the mini profile differs only in numbers.

use crate::error::{Error, Result};

pub const SAT_PER_JNT: u64 = 100_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    pub name: String,
    /// Block spacing the difficulty retarget algorithm aims for.
    pub target_block_time_ms: u64,
    /// Blocks between halvings.
    pub halving_period: u64,
    /// Block reward at halving 0, in satoshis.
    pub start_reward_sat: u64,
    /// Hard supply ceiling in satoshis. Never exceeded — enforced in `supply.rs`.
    pub supply_cap_sat: u64,
    pub difficulty_window: u32,
    /// Max per-block difficulty change, in basis points (1000 = +/-10%).
    pub change_limit_bps: u32,
    pub genesis_difficulty: u128,
    pub min_difficulty: u128,
    pub max_difficulty: u128,
    /// Blocks before coinbase value is spendable.
    pub coinbase_maturity: u64,
    /// Blocks below the tip that can never be reorganized away.
    pub finality_depth: u64,
    pub gas_cap: u64,
    pub base_fee_initial_sat: u64,
    pub base_fee_min_sat: u64,
    pub base_fee_max_sat: u64,
    /// Height interval after which the neural-net weights rotate.
    pub nn_epoch_blocks: u64,
    pub puzzle_id: u64,
    pub max_tx_count: usize,
    pub max_block_bytes: usize,
    /// Reject inputs that carry a single-scheme signature bundle, requiring a
    /// hybrid (multi-scheme) one. Off by default so existing single-scheme
    /// transactions stay valid; flipping it on is how a network would declare
    /// itself post-quantum ready without a hard fork.
    pub require_hybrid_signatures: bool,
    /// 4-byte discriminator checked on every incoming frame (§13.2/§13.3) and
    /// mandatory in the handshake. `mainnet` and `mini` MUST differ; reuse
    /// across two live networks lets a node accept a foreign chain's traffic.
    /// Zero is rejected by `validate()`.
    pub network_magic: [u8; 4],
    /// Human-readable network tag exchanged in the handshake (§13.4). Also
    /// distinguishes profiles when a magic collision is ever introduced.
    pub network_id: String,
}

impl NetworkParams {
    /// Deterministic future-timestamp allowance (SPEC.md §6.1).
    ///
    /// The 2-hour allowance used by Bitcoin was shown by `sim/difficulty_attack_sim.py`
    /// to let a 40% attacker pull difficulty down; one block time does not.
    pub fn future_limit_ms(&self) -> u64 {
        self.target_block_time_ms
    }

    pub fn supply_cap_jnt(&self) -> u64 {
        self.supply_cap_sat / SAT_PER_JNT
    }

    pub fn start_reward_jnt(&self) -> u64 {
        self.start_reward_sat / SAT_PER_JNT
    }

    pub fn by_name(name: &str) -> Result<Self> {
        match name {
            "mainnet" => Ok(Self::mainnet()),
            "mini" => Ok(Self::mini()),
            other => Err(Error::Malformed(match other {
                "testnet" => "unknown network \"testnet\"; use \"mainnet\" or \"mini\"",
                _ => "unknown network; use \"mainnet\" or \"mini\"",
            })),
        }
    }

    /// Mainnet: 10-minute blocks, ~40M cap, 5-year halving (SPEC.md §7, §10).
    pub fn mainnet() -> Self {
        NetworkParams {
            name: "mainnet".into(),
            target_block_time_ms: 600_000,
            halving_period: 262_800,
            start_reward_sat: 76 * SAT_PER_JNT,
            supply_cap_sat: 39_945_600 * SAT_PER_JNT,
            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: crate::u256::MAX_DIFFICULTY,
            coinbase_maturity: 100,
            finality_depth: 100,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 1_000,
            base_fee_min_sat: 100,
            base_fee_max_sat: 50_000_000,
            nn_epoch_blocks: 50_000,
            puzzle_id: 1,
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            network_magic: [0x6A, 0x4E, 0x54, 0x01],
            network_id: "jounit/mainnet".into(),
        }
    }

    /// Mini: identical logic, parameters chosen so a full halving cycle and a
    /// reorg both happen within minutes. Used to validate the production code
    /// end to end (SPEC.md §10, design doc Section 17 step 3).
    pub fn mini() -> Self {
        NetworkParams {
            name: "mini".into(),
            target_block_time_ms: 1_000,
            halving_period: 2_000,
            start_reward_sat: 76 * SAT_PER_JNT,
            supply_cap_sat: 304_000 * SAT_PER_JNT,
            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: 1u128 << 40,
            coinbase_maturity: 10,
            finality_depth: 20,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 100,
            base_fee_min_sat: 10,
            base_fee_max_sat: 1_000_000,
            nn_epoch_blocks: 2_000,
            puzzle_id: 1,
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            // Distinct 4-byte magic so a mini peer can never be mistaken for
            // mainnet at the framing layer (§13.3). Genesis cannot do that job:
            // both profiles have genesis_difficulty=1, so genesis_block() is
            // identical, hence the identical genesis hash.
            network_magic: [0x6A, 0x4E, 0x54, 0x02],
            network_id: "jounit/mini".into(),
        }
    }

    /// Reject a profile that could never produce a valid block.
    pub fn validate(&self) -> Result<()> {
        if self.target_block_time_ms == 0 {
            return Err(Error::Malformed("target_block_time_ms must be > 0"));
        }
        if self.halving_period == 0 {
            return Err(Error::Malformed("halving_period must be > 0"));
        }
        if self.genesis_difficulty < self.min_difficulty {
            return Err(Error::Malformed("genesis_difficulty below min_difficulty"));
        }
        if self.max_difficulty < self.min_difficulty {
            return Err(Error::Malformed("max_difficulty below min_difficulty"));
        }
        if self.max_difficulty > crate::u256::MAX_DIFFICULTY {
            return Err(Error::Malformed("max_difficulty above MAX_DIFFICULTY"));
        }
        if self.coinbase_maturity == 0 {
            return Err(Error::Malformed("coinbase_maturity must be > 0"));
        }
        if self.gas_cap == 0 {
            return Err(Error::Malformed("gas_cap must be > 0"));
        }
        if self.start_reward_sat == 0 {
            return Err(Error::Malformed("start_reward_sat must be > 0"));
        }
        if self.network_magic == [0, 0, 0, 0] {
            return Err(Error::Malformed("network_magic must be non-zero"));
        }
        if self.network_id.is_empty() {
            return Err(Error::Malformed("network_id must be non-empty"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_matches_design_doc_section_16() {
        let p = NetworkParams::mainnet();
        p.validate().unwrap();
        assert_eq!(p.supply_cap_jnt(), 39_945_600);
        assert_eq!(p.start_reward_jnt(), 76);
        assert_eq!(p.halving_period, 5 * 365 * 144);
        assert_eq!(p.target_block_time_ms, 10 * 60 * 1000);
        assert_eq!(
            p.genesis_difficulty, 1,
            "genesis must be trivially mineable"
        );
    }

    #[test]
    fn mini_cap_is_two_halving_periods_of_rewards() {
        let p = NetworkParams::mini();
        p.validate().unwrap();
        assert_eq!(
            p.supply_cap_jnt(),
            2 * p.halving_period * p.start_reward_jnt()
        );
        assert_eq!(p.target_block_time_ms, 1_000);
    }

    #[test]
    fn future_limit_is_one_block_time() {
        assert_eq!(NetworkParams::mainnet().future_limit_ms(), 600_000);
        assert_eq!(NetworkParams::mini().future_limit_ms(), 1_000);
    }

    #[test]
    fn profiles_resolve_by_name() {
        assert_eq!(
            NetworkParams::by_name("mini").unwrap(),
            NetworkParams::mini()
        );
        assert!(NetworkParams::by_name("nope").is_err());
    }

    #[test]
    fn network_magic_is_distinct_and_nonzero() {
        let m = NetworkParams::mainnet();
        let n = NetworkParams::mini();
        // Non-zero, lest a default profile silently pass for any network.
        assert_ne!(m.network_magic, [0, 0, 0, 0]);
        assert_ne!(n.network_magic, [0, 0, 0, 0]);
        // Distinct across profiles: the whole reason it exists (§13.3). Genesis
        // cannot do this job because both profiles have genesis_difficulty = 1.
        assert_ne!(m.network_magic, n.network_magic);
        assert_ne!(m.network_id, n.network_id);
        assert!(m.network_id.starts_with("jounit/"));
    }

    #[test]
    fn genesis_hash_is_identical_across_profiles() {
        // The property that makes network_magic necessary: genesis_block() takes
        // only difficulty, and both profiles set genesis_difficulty = 1.
        let g = crate::block::genesis_block(NetworkParams::mainnet().genesis_difficulty);
        let h = crate::block::genesis_block(NetworkParams::mini().genesis_difficulty);
        assert_eq!(g.block_hash(), h.block_hash());
    }
}
