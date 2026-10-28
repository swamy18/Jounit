//! Pool payout ledger: PPLNS (pay-per-last-N-shares) round accounting.
//!
//! A *round* is the shares standing between two blocks the pool finds (or
//! between startup and the first block). When the pool finds a block paying
//! `coinbase_sat` to the pool address, [`RoundTracker::finalize_block`]
//! splits the reward across the **last `window` shares**, not the round:
//!
//! - the pool takes `fee_bps` basis points off the top (tracked as
//!   `operator_earned`, never mixed with miner money),
//! - the rest plus carried dust is split proportionally to shares **inside
//!   the window**, floored to whole sats,
//! - the flooring remainder (dust) is **not** kept by the operator: it
//!   carries into the next round's pot, so miners lose nothing to rounding.
//!
//! Why a window and not the round (PROP): under proportional-per-round
//! accounting a share submitted early in a long round is worth less than one
//! submitted late, so a miner who only mines fresh rounds earns more per hash
//! than a loyal one — pool hopping. Under PPLNS every share in the window is
//! worth exactly the same no matter when it landed, so there is no timing
//! edge to exploit. The window is `2 × network_difficulty /
//! share_difficulty` (≈ two blocks' worth of shares), bounded by
//! [`PPLNS_MAX_WINDOW`] so the share log is bounded memory.
//!
//! A round with no shares in the window pays the whole pot to the carry
//! (minus the fee): there is nobody to pay, and the dust rule keeps it miner
//! money.
//!
//! This ledger is accounting only. Moving actual coin is the operator's
//! on-chain transfer; [`RoundTracker::mark_paid`] records it so a miner is
//! never paid twice. All iteration is over ordered structures, so identical
//! share sequences produce byte-identical round records on every machine.

use std::collections::{BTreeMap, VecDeque};

use jnt_core::error::{Error, Result};
use jnt_core::hash::Address;

/// Upper bound on the PPLNS window (and hence on the share log): one million
/// shares ≈ 20 MB of addresses. Windows are derived as twice the expected
/// shares per block, so an operator whose rounds routinely exceed this should
/// raise share difficulty, not memory.
pub const PPLNS_MAX_WINDOW: usize = 1_000_000;

/// One finalized round: who earned what, deterministically ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRound {
    pub round_id: u64,
    pub block_height: u64,
    pub coinbase_sat: u64,
    pub fee_sat: u64,
    /// The PPLNS window this round paid over.
    pub window: usize,
    /// `(miner, sats)` sorted by address bytes.
    pub payouts: Vec<(Address, u64)>,
    /// Flooring remainder carried into the next round's pot.
    pub dust_sat: u64,
}

#[derive(Debug, Clone)]
pub struct RoundTracker {
    fee_bps: u32,
    round_id: u64,
    /// Every accepted share in arrival order. Never cleared on finalize —
    /// PPLNS pays the trailing window, so a share stays eligible across
    /// blocks until it ages out past the window or the memory cap.
    log: VecDeque<Address>,
    lifetime_shares: BTreeMap<Address, u64>,
    pending: BTreeMap<Address, u64>,
    /// Miner money carried across rounds (rounding dust + shareless pots).
    carry_sat: u64,
    /// Pool operator's earned fees, separate from miner money.
    operator_earned_sat: u64,
    rounds: Vec<FinalizedRound>,
}

impl RoundTracker {
    /// `fee_bps` is the pool fee in basis points (250 = 2.5%).
    pub fn new(fee_bps: u32) -> Result<Self> {
        if fee_bps > 10_000 {
            return Err(Error::Malformed("pool fee exceeds 100%"));
        }
        Ok(RoundTracker {
            fee_bps,
            round_id: 0,
            log: VecDeque::new(),
            lifetime_shares: BTreeMap::new(),
            pending: BTreeMap::new(),
            carry_sat: 0,
            operator_earned_sat: 0,
            rounds: Vec::new(),
        })
    }

    /// Record one accepted share for `miner` at the tail of the window.
    pub fn record_share(&mut self, miner: &Address) {
        self.log.push_back(*miner);
        if self.log.len() > PPLNS_MAX_WINDOW {
            self.log.pop_front();
        }
        *self.lifetime_shares.entry(*miner).or_insert(0) += 1;
    }

    /// Close the open round on a found block: split `coinbase_sat`
    /// proportionally to the last `window` shares. The log is kept — PPLNS
    /// pays the trailing window, so a share stays eligible across blocks
    /// until it ages out. `window == 0` (or an empty log) means nobody is
    /// payable and the whole pot carries; oversized windows simply pay the
    /// whole log.
    pub fn finalize_block(
        &mut self,
        block_height: u64,
        coinbase_sat: u64,
        window: usize,
    ) -> FinalizedRound {
        self.round_id += 1;
        // u128 throughout: a u64 coinbase times basis points overflows u64
        // long before it looks large, and a wrapped fee would silently become
        // the operator's — or the miners' — money.
        let fee_sat = (coinbase_sat as u128)
            .saturating_mul(self.fee_bps as u128)
            .saturating_div(10_000) as u64;
        self.operator_earned_sat = self.operator_earned_sat.saturating_add(fee_sat);
        let pot = coinbase_sat
            .saturating_sub(fee_sat)
            .saturating_add(self.carry_sat);
        self.carry_sat = 0;

        let window = window.min(PPLNS_MAX_WINDOW).min(self.log.len());
        let mut counts: BTreeMap<Address, u64> = BTreeMap::new();
        for miner in self.log.iter().skip(self.log.len() - window) {
            *counts.entry(*miner).or_insert(0) += 1;
        }
        let total_shares = window as u64;
        let mut payouts = Vec::new();
        if total_shares > 0 {
            let mut distributed = 0u64;
            for (miner, shares) in &counts {
                let pay = (*shares as u128)
                    .saturating_mul(pot as u128)
                    .saturating_div(total_shares as u128) as u64;
                distributed = distributed.saturating_add(pay);
                if pay > 0 {
                    *self.pending.entry(*miner).or_insert(0) = self
                        .pending
                        .get(miner)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(pay);
                    payouts.push((*miner, pay));
                }
            }
            self.carry_sat = pot.saturating_sub(distributed);
        } else {
            // Nobody payable: the whole pot carries, miner money stays miner
            // money instead of silently becoming operator revenue.
            self.carry_sat = pot;
        }
        let round = FinalizedRound {
            round_id: self.round_id,
            block_height,
            coinbase_sat,
            fee_sat,
            window,
            payouts,
            dust_sat: self.carry_sat,
        };
        self.rounds.push(round.clone());
        round
    }

    /// Record an on-chain payment of `amount_sat` to `miner` against their
    /// pending balance. Overpaying (more than pending) is refused: it would
    /// hide an accounting bug as generosity.
    pub fn mark_paid(&mut self, miner: &Address, amount_sat: u64) -> Result<()> {
        let pending = self.pending.get(miner).copied().unwrap_or(0);
        if amount_sat > pending {
            return Err(Error::Malformed("payout exceeds pending balance"));
        }
        self.pending.insert(*miner, pending - amount_sat);
        Ok(())
    }

    pub fn pending(&self, miner: &Address) -> u64 {
        self.pending.get(miner).copied().unwrap_or(0)
    }

    pub fn operator_earned(&self) -> u64 {
        self.operator_earned_sat
    }

    pub fn carry(&self) -> u64 {
        self.carry_sat
    }

    pub fn lifetime_shares(&self, miner: &Address) -> u64 {
        self.lifetime_shares.get(miner).copied().unwrap_or(0)
    }

    pub fn rounds(&self) -> &[FinalizedRound] {
        &self.rounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn proportional_split_with_fee_and_dust_carry() {
        // 3:1 shares, 10% fee, 101-sat coinbase: fee 10, pot 91.
        // A: 91*3/4 = 68, B: 91*1/4 = 22, dust 1 carries.
        let mut t = RoundTracker::new(1_000).unwrap();
        for _ in 0..3 {
            t.record_share(&addr(1));
        }
        t.record_share(&addr(2));
        let r = t.finalize_block(100, 101, 1_000_000);
        assert_eq!(r.fee_sat, 10);
        assert_eq!(r.payouts, vec![(addr(1), 68), (addr(2), 22)]);
        assert_eq!(r.dust_sat, 1);
        assert_eq!(t.pending(&addr(1)), 68);
        assert_eq!(t.pending(&addr(2)), 22);
        assert_eq!(t.operator_earned(), 10);
        assert_eq!(t.carry(), 1);

        // Next round: dust joins the pot, and — PPLNS, not PROP — the first
        // round's shares are still inside the window, so they earn again.
        // Log: A,A,A,B (old) + B (new); pot 9 + 1 dust = 10 over 5 shares:
        // A: 10*3/5 = 6, B: 10*2/5 = 4, dust 0.
        t.record_share(&addr(2));
        let r2 = t.finalize_block(101, 10, 1_000_000);
        assert_eq!(r2.payouts, vec![(addr(1), 6), (addr(2), 4)]);
        assert_eq!(r2.dust_sat, 0);
        assert_eq!(t.pending(&addr(1)), 74);
        assert_eq!(t.pending(&addr(2)), 26);
    }

    #[test]
    fn window_excludes_stale_shares() {
        // The anti-hopping property: only the last `window` shares are paid.
        // A hopper's 90 ancient shares earn nothing once 10 loyal shares
        // arrived after them and the window is 10.
        let mut t = RoundTracker::new(0).unwrap();
        for _ in 0..90 {
            t.record_share(&addr(9));
        }
        for _ in 0..10 {
            t.record_share(&addr(1));
        }
        let r = t.finalize_block(100, 100, 10);
        assert_eq!(r.window, 10);
        assert_eq!(r.payouts, vec![(addr(1), 100)]);
        assert_eq!(t.pending(&addr(9)), 0);
        assert_eq!(t.pending(&addr(1)), 100);
    }

    #[test]
    fn shares_survive_across_blocks_until_they_age_out() {
        // PPLNS, not PROP: a share unpaid in one block stays eligible for the
        // next while it is still inside the window.
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        let r1 = t.finalize_block(100, 60, 10);
        assert_eq!(r1.payouts, vec![(addr(1), 60)]);
        // No new shares, same window: the old share is still the whole
        // window, so a second block pays it again.
        let r2 = t.finalize_block(101, 40, 10);
        assert_eq!(r2.payouts, vec![(addr(1), 40)]);
        assert_eq!(t.pending(&addr(1)), 100);
    }

    #[test]
    fn shareless_round_carries_the_pot() {
        let mut t = RoundTracker::new(0).unwrap();
        let r = t.finalize_block(100, 50, 1_000_000);
        assert!(r.payouts.is_empty());
        assert_eq!(r.dust_sat, 50);
        assert_eq!(t.carry(), 50);
        assert_eq!(t.operator_earned(), 0);
    }

    #[test]
    fn overpay_is_refused_and_exact_pay_clears() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 100, 1_000_000);
        assert!(t.mark_paid(&addr(1), 101).is_err());
        t.mark_paid(&addr(1), 100).unwrap();
        assert_eq!(t.pending(&addr(1)), 0);
    }

    #[test]
    fn fee_above_100_percent_is_refused() {
        assert!(RoundTracker::new(10_001).is_err());
    }

    #[test]
    fn extreme_coinbase_values_do_not_wrap() {
        // u64::MAX coinbase at 100% fee and at 0%: the fee and every share
        // must be exact, never wrapped. (u64 arithmetic wrapped here before
        // the u128 fix — a wrapped fee silently moved money.)
        let mut t = RoundTracker::new(10_000).unwrap();
        t.record_share(&addr(1));
        let r = t.finalize_block(1, u64::MAX, 1_000_000);
        assert_eq!(r.fee_sat, u64::MAX);
        assert!(r.payouts.is_empty());
        assert_eq!(t.operator_earned(), u64::MAX);

        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.record_share(&addr(2));
        let r = t.finalize_block(1, u64::MAX, 1_000_000);
        // Odd value split two ways: 2^64-1 = 2*(2^63-1) + 1, dust 1 carries.
        let half = u64::MAX / 2;
        assert_eq!(r.payouts, vec![(addr(1), half), (addr(2), half)]);
        assert_eq!(r.dust_sat, 1);
        assert_eq!(t.carry(), 1);
    }

    #[test]
    fn rounds_are_deterministic_and_ordered() {
        let mut t = RoundTracker::new(0).unwrap();
        // Insert out of order; payouts must still sort by address.
        t.record_share(&addr(9));
        t.record_share(&addr(1));
        let r = t.finalize_block(100, 100, 1_000_000);
        assert_eq!(r.payouts, vec![(addr(1), 50), (addr(9), 50)]);
        assert_eq!(t.rounds().len(), 1);
        assert_eq!(t.rounds()[0].round_id, 1);
    }
}
