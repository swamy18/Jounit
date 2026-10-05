//! Fixed-cap halving supply schedule. SPEC.md §7.
//!
//! Design doc Section 16: cap ~39.95M JNT, 76 per block, halving every 262 800
//! blocks (5 years). The cap is enforced as a *hard code invariant*, not a
//! promise in prose: `check_mint` is the only path that creates supply and it
//! refuses to cross the ceiling.

use crate::error::{Error, Result};
use crate::params::NetworkParams;

/// Number of halvings already elapsed at `height`.
pub fn halvings(params: &NetworkParams, height: u64) -> u32 {
    (height / params.halving_period) as u32
}

/// Block reward in satoshis for the halving epoch at `period`.
///
/// The ladder is halved in **whole JNT**, not by shifting satoshis, so the
/// schedule is exactly the design doc's 76, 38, 19, 9, 4, 2, 1, 0 (Section 16).
/// Shifting satoshis instead would give 76, 38, 19, 9.5, 4.75 ... and break the
/// cap arithmetic.
pub fn period_reward_sat(params: &NetworkParams, period: u32) -> u64 {
    if period >= 64 {
        return 0;
    }
    let start_jnt = params.start_reward_sat / crate::params::SAT_PER_JNT;
    (start_jnt >> period) * crate::params::SAT_PER_JNT
}

/// Block reward in satoshis: `period_reward_sat(halvings(height))`.
/// Mainnet ladder: 76, 38, 19, 9, 4, 2, 1, 0 JNT.
pub fn block_reward_sat(params: &NetworkParams, height: u64) -> u64 {
    period_reward_sat(params, halvings(params, height))
}

/// Total issuance after `mined_blocks` blocks have been mined **on top of
/// genesis**.
///
/// Genesis mints nothing (Section 16: 0% premine), so heights run `1..=N`.
/// Getting this off-by-one wrong makes a node over-report issuance by a full
/// block reward, which is exactly the number someone would publish as
/// "coins mined".
pub fn cumulative_supply_sat(params: &NetworkParams, mined_blocks: u64) -> u64 {
    let mut total: u64 = 0;
    let mut start = 1u64;
    let mut period = 0u32;
    while start <= mined_blocks && period < 64 {
        let period_end = (period as u64 + 1).saturating_mul(params.halving_period);
        let end = mined_blocks.min(period_end);
        let reward = period_reward_sat(params, period);
        if reward == 0 {
            break;
        }
        total = total.saturating_add(reward.saturating_mul(end - start + 1));
        start = end + 1;
        period += 1;
    }
    total
}

/// Supply reachable once the ladder is exhausted: permanently unmintable
/// surplus, provable rather than "reserved".
pub fn max_issuance_sat(params: &NetworkParams) -> u64 {
    let mut sum: u64 = 0;
    for period in 0..64u32 {
        let r = period_reward_sat(params, period);
        if r == 0 {
            break;
        }
        sum = sum.saturating_add(r.saturating_mul(params.halving_period));
    }
    sum.min(params.supply_cap_sat)
}

/// The only mint gate. Callers pass the reward they intend to create.
pub fn check_mint(params: &NetworkParams, issued_so_far: u64, reward: u64) -> Result<u64> {
    let cap = params.supply_cap_sat;
    let want = issued_so_far.saturating_add(reward);
    if want > cap {
        return Err(Error::SupplyCapExceeded {
            already: issued_so_far,
            requested: reward,
            cap,
        });
    }
    Ok(want)
}

/// True when a reward at this height would cross the cap. The surplus becomes
/// unrecoverable rather than being burned out of circulation, so the cap is
/// provable by anyone running `max_issuance_sat`.
pub fn reward_exceeds_remaining(params: &NetworkParams, issued: u64, reward: u64) -> bool {
    issued.saturating_add(reward) > params.supply_cap_sat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SAT_PER_JNT;

    #[test]
    fn mainnet_reward_ladder() {
        let p = NetworkParams::mainnet();
        let expect = [76u64, 38, 19, 9, 4, 2, 1, 0];
        for (i, jnt) in expect.iter().enumerate() {
            let h = (i as u64) * p.halving_period;
            assert_eq!(
                block_reward_sat(&p, h) / SAT_PER_JNT,
                *jnt,
                "halving {i}"
            );
        }
        assert_eq!(block_reward_sat(&p, 8 * p.halving_period), 0);
    }

    #[test]
    fn reward_is_constant_within_a_period() {
        let p = NetworkParams::mini();
        for off in 0..p.halving_period {
            assert_eq!(
                block_reward_sat(&p, off),
                p.start_reward_sat,
                "reward changed at offset {off} of the first period"
            );
        }
        assert_eq!(block_reward_sat(&p, p.halving_period), 38 * crate::params::SAT_PER_JNT);
    }

    #[test]
    fn genesis_mints_nothing() {
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            assert_eq!(cumulative_supply_sat(&p, 0), 0);
            assert_eq!(
                cumulative_supply_sat(&p, 1),
                p.start_reward_sat,
                "one mined block pays exactly one reward"
            );
            assert_eq!(
                cumulative_supply_sat(&p, 5),
                p.start_reward_sat * 5
            );
        }
    }

    #[test]
    fn cumulative_supply_matches_design_doc() {
        let p = NetworkParams::mainnet();
        // Design doc Section 16: 2 x 262,800 x 76 = 39,945,600 is the *cap*.
        // Actual issuance is the floor-divided geometric sum: 149 x 262,800.
        let issued = cumulative_supply_sat(&p, 8 * p.halving_period);
        assert_eq!(issued / SAT_PER_JNT, 149 * p.halving_period);
        assert_eq!(issued / SAT_PER_JNT, 39_157_200);
        assert!(issued < p.supply_cap_sat, "issuance must stay under the cap");
        // 39,945,600 - 39,157,200 = 788,400 JNT is permanently unmintable.
        assert_eq!(p.supply_cap_sat - issued, 788_400 * SAT_PER_JNT);
    }

    #[test]
    fn max_issuance_never_reaches_the_cap() {
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            let max = max_issuance_sat(&p);
            assert_eq!(max, cumulative_supply_sat(&p, 64 * p.halving_period));
            assert!(max < p.supply_cap_sat);
            assert!(max > 0);
        }
    }

    #[test]
    fn cumulative_supply_is_monotonic_and_partial_periods_count() {
        let p = NetworkParams::mini();
        let mut prev = 0;
        for n in [
            0u64,
            1,
            2,
            p.halving_period,
            p.halving_period + 1,
            3 * p.halving_period,
        ] {
            let s = cumulative_supply_sat(&p, n);
            assert!(s >= prev, "supply must not decrease at {n} mined blocks");
            prev = s;
        }
        // One full period at the starting reward, plus one more block in
        // the second period, which pays the halved reward.
        assert_eq!(
            cumulative_supply_sat(&p, p.halving_period + 1),
            p.start_reward_sat * p.halving_period + 38 * crate::params::SAT_PER_JNT
        );
    }

    #[test]
    fn cap_is_a_hard_invariant() {
        let p = NetworkParams::mainnet();
        let cap = p.supply_cap_sat;
        assert!(check_mint(&p, cap - 1, 1).is_ok());
        assert!(matches!(
            check_mint(&p, cap, 1),
            Err(Error::SupplyCapExceeded { .. })
        ));
        assert!(matches!(
            check_mint(&p, cap - 1, 2),
            Err(Error::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn whole_schedule_can_be_minted_within_the_cap() {
        let p = NetworkParams::mainnet();
        let mut issued = 0u64;
        for period in 0..8u64 {
            let reward = block_reward_sat(&p, period * p.halving_period);
            if reward == 0 {
                continue;
            }
            for _ in 0..p.halving_period {
                issued = check_mint(&p, issued, reward).unwrap();
            }
        }
        assert_eq!(issued, max_issuance_sat(&p));
        assert!(issued < p.supply_cap_sat);
        assert!(
            !reward_exceeds_remaining(&p, issued, 1),
            "a JNT of headroom still exists, so the ladder is the binding limit"
        );
        assert!(reward_exceeds_remaining(
            &p,
            p.supply_cap_sat,
            1
        ));
    }

    #[test]
    fn mini_cap_is_reachable_and_never_exceeded() {
        let p = NetworkParams::mini();
        let mut issued = 0u64;
        for h in 0..(8 * p.halving_period) {
            issued = check_mint(&p, issued, block_reward_sat(&p, h)).unwrap();
        }
        assert!(issued < p.supply_cap_sat);
    }

    #[test]
    fn halving_is_exact_in_whole_jnt() {
        let p = NetworkParams::mainnet();
        for (i, jnt) in [76u64, 38, 19, 9, 4, 2, 1, 0].iter().enumerate() {
            let reward = period_reward_sat(&p, i as u32);
            assert_eq!(reward / crate::params::SAT_PER_JNT, *jnt, "period {i}");
            assert_eq!(
                reward % crate::params::SAT_PER_JNT,
                0,
                "period {i} must be a whole number of JNT"
            );
        }
    }
}