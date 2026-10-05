//! EIP-1559-shaped base fee that is burned rather than minted.
//! SPEC.md §8.
//!
//! Design doc Sections 24.3 and 28.1: base fees are burned, only tips reach the
//! miner, and no new supply comes from usage — so the hard cap can never be
//! crossed by demand.

use crate::error::{Error, Result};
use crate::params::NetworkParams;

/// Base fee for the block *after* the supplied one.
pub fn next_base_fee(params: &NetworkParams, current: u64, gas_used: u64) -> u64 {
    // `target*8` is the EIP-1559 denominator; precompute so the clamp is exact.
    let target8 = (params.gas_cap.max(1) as u128).saturating_mul(8);
    let used = gas_used as u128;
    let cur = current as u128;

    let next = if used == target8 / 8 {
        // Rises by at least 1/512 per block when the target is exactly met.
        cur + (cur / (target8 / 8) / 8).max(1)
    } else if used > target8 / 8 {
        cur + (cur * (used - target8 / 8)) / target8
    } else {
        cur.saturating_sub((cur * (target8 / 8 - used)) / target8)
    };

    next.clamp(params.base_fee_min_sat as u128, params.base_fee_max_sat as u128) as u64
}

/// Fee a transaction must pay: the burned portion for its own gas usage.
pub fn required_fee(base_fee: u64, gas_used: u64) -> u64 {
    base_fee.saturating_mul(gas_used)
}

pub fn exceeds_base_fee(base_fee: u64, fee: u64, gas_used: u64) -> bool {
    fee < required_fee(base_fee, gas_used)
}

/// Split a block's fees into the part that is burned and the tip the miner keeps.
pub fn split_fees(total_gas: u64, total_fees: u64, base_fee: u64) -> Result<FeeSplit> {
    let burned = base_fee.saturating_mul(total_gas);
    if burned > total_fees {
        return Err(Error::BadFee("fees below required base fee"));
    }
    Ok(FeeSplit {
        total_fees,
        burned,
        tip: total_fees - burned,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    pub total_fees: u64,
    /// Removed from the UTXO set and never reissued.
    pub burned: u64,
    /// Paid to the miner alongside the block reward.
    pub tip: u64,
}

/// Coinbase reward + tip. Base fees are *not* here — they are burned.
pub fn coinbase_value(reward_sat: u64, split: &FeeSplit) -> u64 {
    reward_sat.saturating_add(split.tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Input, OutPoint, Output, Transaction};

    fn tx(n_in: usize, n_out: usize) -> Transaction {
        let inputs: Vec<Input> = (0..n_in)
            .map(|i| Input::unsigned(&OutPoint { txid: [i as u8; 32], index: 0 }))
            .collect();
        let outputs: Vec<Output> = (0..n_out)
            .map(|_| Output { value: 1, address: [0; 20] })
            .collect();
        Transaction::standard(inputs, outputs)
    }

    #[test]
    fn base_fee_rises_when_target_is_met() {
        let p = NetworkParams::mainnet();
        let next = next_base_fee(&p, 1_000, p.gas_cap);
        assert!(next > 1_000);
        assert_eq!(next, 1_001);
    }

    #[test]
    fn base_fee_rises_faster_with_congestion() {
        let p = NetworkParams::mainnet();
        let full = next_base_fee(&p, 1_000, p.gas_cap);
        let busy = next_base_fee(&p, 1_000, p.gas_cap * 2);
        assert!(busy > full, "2x congestion must outpace 1x");
    }

    #[test]
    fn base_fee_falls_when_idle_but_stays_above_the_floor() {
        let p = NetworkParams::mainnet();
        assert_eq!(next_base_fee(&p, 1_000, 0), 875);
        assert!(next_base_fee(&p, 1_000, 0) < 1_000);
        // Repeatedly idle blocks decay to the floor and stop there.
        let mut fee = 1_000u64;
        for _ in 0..100 {
            fee = next_base_fee(&p, fee, 0);
        }
        assert_eq!(fee, p.base_fee_min_sat);
    }

    #[test]
    fn base_fee_is_clamped_at_both_ends() {
        let p = NetworkParams::mainnet();
        assert!(next_base_fee(&p, p.base_fee_max_sat, p.gas_cap * 100) <= p.base_fee_max_sat);
        assert!(next_base_fee(&p, p.base_fee_min_sat, 0) >= p.base_fee_min_sat);
    }

    #[test]
    fn base_fee_schedule_is_monotonic_in_gas() {
        let p = NetworkParams::mainnet();
        let mut prev = next_base_fee(&p, 10_000, 0);
        let step = (p.gas_cap / 20).max(1) as usize;
        for i in 0..=40u64 {
            let gas = i * step as u64;
            let f = next_base_fee(&p, 10_000, gas);
            assert!(f >= prev, "base fee fell as gas rose (gas={gas})");
            prev = f;
        }
    }

    #[test]
    fn split_burns_the_base_fee_and_keeps_the_tip() {
        let base_fee = 1_000u64;
        let gas = tx(1, 2).gas_used();
        let split = split_fees(gas, base_fee * gas + 500, base_fee).unwrap();
        assert_eq!(split.burned, base_fee * gas);
        assert_eq!(split.tip, 500);
        assert_eq!(split.total_fees, split.burned + split.tip);
    }

    #[test]
    fn split_rejects_underpayment() {
        assert!(matches!(
            split_fees(17_250, 10, 1_000),
            Err(Error::BadFee(_))
        ));
    }

    #[test]
    fn required_fee_is_base_fee_times_gas() {
        let gas = tx(2, 3).gas_used();
        assert_eq!(required_fee(1_000, gas), 1_000 * gas);
        assert!(exceeds_base_fee(1_000, 1_000 * gas - 1, gas));
        assert!(!exceeds_base_fee(1_000, 1_000 * gas, gas));
    }

    #[test]
    fn coinbase_gets_reward_plus_tip_only() {
        let split = FeeSplit {
            total_fees: 1_000,
            burned: 900,
            tip: 100,
        };
        let claim = coinbase_value(76 * 100_000_000, &split);
        assert_eq!(claim, 76 * 100_000_000 + 100);
        assert_eq!(claim - 76 * 100_000_000, split.tip);
        assert!(
            split.tip < split.total_fees,
            "the burned base fee must never reach the miner"
        );
    }
}