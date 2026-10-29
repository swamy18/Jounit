//! EIP-1559-shaped base fee: 50% burned, 50% routed to PSCB (Protocol Security
//! & Compute Buffer). SPEC.md §8, M1 protocol mechanism.
//!
//! Design doc Sections 24.3 and 28.1: base fees are the deflationary lever AND
//! the on-protocol reserve that backs slashed compute stake recovery (M2). The
//! 50% burn maintains supply pressure; the 50% PSCB accrual funds the Time-Locked
//! Compute Reserve vault as already-removed supply, never as new issuance.

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

    next.clamp(
        params.base_fee_min_sat as u128,
        params.base_fee_max_sat as u128,
    ) as u64
}

/// Fee a transaction must pay: the burned portion for its own gas usage.
pub fn required_fee(base_fee: u64, gas_used: u64) -> u64 {
    base_fee.saturating_mul(gas_used)
}

pub fn exceeds_base_fee(base_fee: u64, fee: u64, gas_used: u64) -> bool {
    fee < required_fee(base_fee, gas_used)
}

/// Split a block's fees into burned, PSCB reserve, and miner tip.
///
/// M1 protocol mechanism (50/50 PSCB split):
/// - `burned`  = 50% of the base-fee portion — permanently destroyed, no
///   reissue possible. Provides EIP-1559 deflationary pressure.
/// - `pscb`    = 50% of the base-fee portion — routed to the on-chain
///   Protocol Security & Compute Buffer reserve. Funds slashed
///   compute stake recovery (M2 Time-Locked Compute Reserve).
/// - `tip`     = everything above the full base-fee obligation — goes to the
///   miner, unchanged from EIP-1559 spec.
///
/// Invariant: burned + pscb + tip == total_fees.
pub fn split_fees(total_gas: u64, total_fees: u64, base_fee: u64) -> Result<FeeSplit> {
    let full_base = base_fee.saturating_mul(total_gas);
    if full_base > total_fees {
        return Err(Error::BadFee("fees below required base fee"));
    }
    // 50% burn, 50% PSCB. Integer arithmetic: burn gets the odd satoshi so
    // burned + pscb == full_base exactly.
    let pscb = full_base / 2;
    let burned = full_base - pscb; // == ceil(full_base / 2)
    let tip = total_fees - full_base;
    Ok(FeeSplit {
        total_fees,
        burned,
        pscb,
        tip,
    })
}

/// M1 split for the flat L2 fee schedule (decision D3).
///
/// L2 transactions pay a flat fee per type instead of `base_fee * gas_used`, so
/// there is no gas component here: the **whole flat fee is the `full_base`** and
/// the existing 50/50 burn/PSCB rule applies to it unchanged. The miner tip is
/// zero, because an L2 fee is not paid to whichever miner happens to include it.
///
/// This is deliberately a separate entry point from [`split_fees`] rather than a
/// relaxed parameter to it: the L1 gas floor stays exactly as it is, and L2 does
/// not gain an exemption from it — it has its own rule. The odd-satoshi rounding
/// matches [`split_fees`] (`burned` gets the extra sat).
pub fn split_flat_fee(fee: u64) -> FeeSplit {
    let pscb = fee / 2;
    let burned = fee - pscb; // == ceil(fee / 2)
    FeeSplit {
        total_fees: fee,
        burned,
        pscb,
        tip: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    pub total_fees: u64,
    /// Permanently removed from the UTXO set and never reissued (50% of base fee).
    pub burned: u64,
    /// Routed to the Protocol Security & Compute Buffer reserve (50% of base fee).
    /// Funds the M2 Time-Locked Compute Reserve vault.
    pub pscb: u64,
    /// Paid to the miner alongside the block reward.
    pub tip: u64,
}

/// Coinbase reward + tip. Burned and PSCB amounts are *not* here — they are
/// handled separately by the chain state machine.
pub fn coinbase_value(reward_sat: u64, split: &FeeSplit) -> u64 {
    reward_sat.saturating_add(split.tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Input, OutPoint, Output, Transaction};

    fn tx(n_in: usize, n_out: usize) -> Transaction {
        let inputs: Vec<Input> = (0..n_in)
            .map(|i| {
                Input::unsigned(&OutPoint {
                    txid: [i as u8; 64],
                    index: 0,
                })
            })
            .collect();
        let outputs: Vec<Output> = (0..n_out)
            .map(|_| Output {
                value: 1,
                address: [0; 20],
            })
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

    // -----------------------------------------------------------------------
    // M1: 50/50 PSCB split invariants
    // -----------------------------------------------------------------------

    #[test]
    fn split_m1_fifty_fifty_burn_and_pscb() {
        let base_fee = 1_000u64;
        let gas = tx(1, 2).gas_used();
        let tip_extra = 500u64;
        let total_fees = base_fee * gas + tip_extra;
        let split = split_fees(gas, total_fees, base_fee).unwrap();

        let full_base = base_fee * gas;
        assert_eq!(split.pscb, full_base / 2, "PSCB = 50% of base fee");
        // burned gets the odd satoshi on uneven amounts
        assert_eq!(
            split.burned,
            full_base - split.pscb,
            "burned = ceil(50%) of base fee"
        );
        assert_eq!(split.tip, tip_extra, "tip is unchanged");
        // Invariant: components sum to total_fees
        assert_eq!(
            split.burned + split.pscb + split.tip,
            split.total_fees,
            "burned + pscb + tip must equal total_fees"
        );
    }

    #[test]
    fn split_burns_the_base_fee_and_keeps_the_tip() {
        let base_fee = 1_000u64;
        let gas = tx(1, 2).gas_used();
        let split = split_fees(gas, base_fee * gas + 500, base_fee).unwrap();
        let full_base = base_fee * gas;
        // Under M1: burned is 50%, pscb is 50%
        assert_eq!(
            split.burned + split.pscb,
            full_base,
            "total base fee preserved"
        );
        assert_eq!(split.tip, 500);
        assert_eq!(split.total_fees, split.burned + split.pscb + split.tip);
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
            burned: 450,
            pscb: 450,
            tip: 100,
        };
        let claim = coinbase_value(76 * 100_000_000, &split);
        assert_eq!(claim, 76 * 100_000_000 + 100);
        assert_eq!(claim - 76 * 100_000_000, split.tip);
        assert!(
            split.tip < split.total_fees,
            "the burned + pscb base fee must never reach the miner"
        );
    }

    #[test]
    fn flat_fee_split_preserves_the_m1_invariant_and_leaves_no_tip() {
        for fee in [0u64, 1, 2, 3, 4_999, 5_000, 10_000, 20_000, 20_001] {
            let split = split_flat_fee(fee);
            assert_eq!(split.total_fees, fee);
            assert_eq!(split.tip, 0, "an L2 fee is never a miner tip");
            assert_eq!(split.pscb, fee / 2, "50% to PSCB");
            assert_eq!(split.burned, fee - split.pscb, "burned gets the odd sat");
            assert_eq!(
                split.burned + split.pscb + split.tip,
                fee,
                "burned + pscb + tip must equal the flat fee"
            );
        }
    }

    #[test]
    fn flat_split_puts_the_odd_satoshi_where_split_fees_does() {
        // Both paths must round the same way, or an L2 fee and an L1 fee of the
        // same size would burn different amounts.
        let flat = split_flat_fee(9);
        let l1 = split_fees(1, 9, 9).unwrap();
        assert_eq!(flat.burned, l1.burned);
        assert_eq!(flat.pscb, l1.pscb);
    }

    #[test]
    fn pscb_is_nonzero_when_fees_are_paid() {
        let gas = tx(1, 1).gas_used();
        let base_fee = 2_000u64;
        let split = split_fees(gas, base_fee * gas + 1, base_fee).unwrap();
        assert!(
            split.pscb > 0,
            "PSCB must receive funds whenever fees are paid"
        );
    }
}
