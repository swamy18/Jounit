//! Pool payout ledger: proportional (PROP) round accounting.
//!
//! A *round* is the shares submitted between two blocks the pool finds (or
//! between startup and the first block). When the pool finds a block paying
//! `coinbase_sat` to the pool address, [`RoundTracker::finalize_block`]
//! splits the reward across the round's shares:
//!
//! - the pool takes `fee_bps` basis points off the top (tracked as
//!   `operator_earned`, never mixed with miner money),
//! - the rest plus carried dust is split proportionally to shares, floored
//!   to whole sats,
//! - the flooring remainder (dust) is **not** kept by the operator: it
//!   carries into the next round's pot, so miners lose nothing to rounding.
//!
//! A round with no shares pays the whole pot to the carry (minus the fee):
//! there is nobody to pay, and the dust rule keeps it miner money.
//!
//! This ledger is accounting only. Moving actual coin is the operator's
//! on-chain transfer; [`RoundTracker::mark_paid`] records it so a miner is
//! never paid twice. All iteration is over `BTreeMap`s, so identical share
//! sequences produce byte-identical round records on every machine.

use std::collections::BTreeMap;

use jnt_core::error::{Error, Result};
use jnt_core::hash::Address;

/// One finalized round: who earned what, deterministically ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRound {
    pub round_id: u64,
    pub block_height: u64,
    pub coinbase_sat: u64,
    pub fee_sat: u64,
    /// `(miner, sats)` sorted by address bytes.
    pub payouts: Vec<(Address, u64)>,
    /// Flooring remainder carried into the next round's pot.
    pub dust_sat: u64,
}

#[derive(Debug, Clone)]
pub struct RoundTracker {
    fee_bps: u32,
    round_id: u64,
    current: BTreeMap<Address, u64>,
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
            current: BTreeMap::new(),
            lifetime_shares: BTreeMap::new(),
            pending: BTreeMap::new(),
            carry_sat: 0,
            operator_earned_sat: 0,
            rounds: Vec::new(),
        })
    }

    /// Record one accepted share for `miner` in the open round.
    pub fn record_share(&mut self, miner: &Address) {
        *self.current.entry(*miner).or_insert(0) += 1;
        *self.lifetime_shares.entry(*miner).or_insert(0) += 1;
    }

    /// Close the open round on a found block: split `coinbase_sat`
    /// proportionally to the round's shares and open a fresh round.
    pub fn finalize_block(&mut self, block_height: u64, coinbase_sat: u64) -> FinalizedRound {
        self.round_id += 1;
        let fee_sat = coinbase_sat.saturating_mul(self.fee_bps as u64) / 10_000;
        self.operator_earned_sat = self.operator_earned_sat.saturating_add(fee_sat);
        let pot = coinbase_sat
            .saturating_sub(fee_sat)
            .saturating_add(self.carry_sat);
        self.carry_sat = 0;

        let total_shares: u64 = self.current.values().sum();
        let mut payouts = Vec::new();
        if total_shares > 0 {
            let mut distributed = 0u64;
            for (miner, shares) in &self.current {
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
            // Nobody to pay: the whole pot carries, miner money stays miner
            // money instead of silently becoming operator revenue.
            self.carry_sat = pot;
        }
        self.current.clear();
        let round = FinalizedRound {
            round_id: self.round_id,
            block_height,
            coinbase_sat,
            fee_sat,
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
        let r = t.finalize_block(100, 101);
        assert_eq!(r.fee_sat, 10);
        assert_eq!(r.payouts, vec![(addr(1), 68), (addr(2), 22)]);
        assert_eq!(r.dust_sat, 1);
        assert_eq!(t.pending(&addr(1)), 68);
        assert_eq!(t.pending(&addr(2)), 22);
        assert_eq!(t.operator_earned(), 10);
        assert_eq!(t.carry(), 1);

        // Next round: dust joins the pot. 1 share, 10-sat coinbase:
        // fee 1, pot 9 + 1 dust = 10, all to the miner.
        t.record_share(&addr(2));
        let r2 = t.finalize_block(101, 10);
        assert_eq!(r2.payouts, vec![(addr(2), 10)]);
        assert_eq!(r2.dust_sat, 0);
        assert_eq!(t.pending(&addr(2)), 32);
    }

    #[test]
    fn shareless_round_carries_the_pot() {
        let mut t = RoundTracker::new(0).unwrap();
        let r = t.finalize_block(100, 50);
        assert!(r.payouts.is_empty());
        assert_eq!(r.dust_sat, 50);
        assert_eq!(t.carry(), 50);
        assert_eq!(t.operator_earned(), 0);
    }

    #[test]
    fn overpay_is_refused_and_exact_pay_clears() {
        let mut t = RoundTracker::new(0).unwrap();
        t.record_share(&addr(1));
        t.finalize_block(100, 100);
        assert!(t.mark_paid(&addr(1), 101).is_err());
        t.mark_paid(&addr(1), 100).unwrap();
        assert_eq!(t.pending(&addr(1)), 0);
    }

    #[test]
    fn fee_above_100_percent_is_refused() {
        assert!(RoundTracker::new(10_001).is_err());
    }

    #[test]
    fn rounds_are_deterministic_and_ordered() {
        let mut t = RoundTracker::new(0).unwrap();
        // Insert out of order; payouts must still sort by address.
        t.record_share(&addr(9));
        t.record_share(&addr(1));
        let r = t.finalize_block(100, 100);
        assert_eq!(r.payouts, vec![(addr(1), 50), (addr(9), 50)]);
        assert_eq!(t.rounds().len(), 1);
        assert_eq!(t.rounds()[0].round_id, 1);
    }
}
