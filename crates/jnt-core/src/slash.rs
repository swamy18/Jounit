//! M2 Protocol Mechanism: Compute Stake Slashing with Time-Locked Vesting.
//!
//! When a compute validator submits a fraudulent result (wrong output hash,
//! fabricated attestation, or double-submission), their locked stake is slashed
//! according to the following split agreed by the protocol designers:
//!
//!   - 50% Anti-Collusion Burn  — permanently destroyed, supply-deflationary.
//!     This makes self-slashing economically irrational: an attacker cannot
//!     recover their stake by colluding with themselves.
//!   - 50% Time-Locked Compute Reserve — vests linearly over 1 year
//!     (VESTING_BLOCKS on the respective network). Funded by M1 PSCB, paid
//!     out block-by-block to the *original validator* if they continue honest
//!     work. If the validator abandons the network, the remainder rolls into
//!     the PSCB permanently.
//!
//! Design rationale
//! ----------------
//! Pure slash-and-burn (Ethereum slashing model) removes honest capital from
//! the system at no net benefit. The 1-year linear vest gives validators a
//! rehabilitation path — continue honest compute, recover half your stake —
//! while the 50% burn makes collusion-with-self attacks strictly losing.
//!
//! SPEC.md §M2.

use crate::error::{Error, Result};
use crate::hash::Hash;
use crate::ser::{Reader, Writer};

/// Blocks over which slashed stake vests on mainnet (365 days × 144 blocks/day).
pub const VESTING_BLOCKS_MAINNET: u64 = 365 * 144;

/// Vesting period for the mini test profile (scaled to 20 halvings worth of blocks).
pub const VESTING_BLOCKS_MINI: u64 = 2_000;

/// A single active slash-and-vest record, created when a validator is slashed.
///
/// The record tracks how much of the *vesting half* remains unlocked
/// block-by-block. A zero `remaining_vest` means the record is exhausted and
/// can be pruned from the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashRecord {
    /// Unique identifier — txid of the slashing transaction or task attestation
    /// that triggered the slash.
    pub slash_id: Hash,
    /// Block height at which the slash was applied.
    pub slash_height: u64,
    /// Block height at which vesting ends (slash_height + vesting_period).
    pub unlock_height: u64,
    /// Total amount that entered the Time-Locked Compute Reserve (50% of
    /// original stake). Starts equal to `remaining_vest`.
    pub vest_total: u64,
    /// Amount not yet paid out. Decreases each block by `vest_per_block`.
    pub remaining_vest: u64,
    /// Satoshis released per block: `ceil(vest_total / vesting_period)`.
    pub vest_per_block: u64,
    /// Amount that was instantly burned (50% of original stake).
    pub burned: u64,
    /// Address of the original validator. Vested amounts are paid here.
    pub validator_address: [u8; 20],
}

impl SlashRecord {
    /// Create a new slash record from a raw stake amount.
    ///
    /// # Parameters
    /// - `slash_id`           — identifier (e.g. txid of the fraud proof)
    /// - `stake_sat`          — total stake being slashed (both halves combined)
    /// - `slash_height`       — current chain height at the time of slashing
    /// - `vesting_period`     — number of blocks over which the vest half unlocks
    /// - `validator_address`  — where vested amounts are sent
    pub fn new(
        slash_id: Hash,
        stake_sat: u64,
        slash_height: u64,
        vesting_period: u64,
        validator_address: [u8; 20],
    ) -> Self {
        let burned = stake_sat / 2; // 50% instant burn (Anti-Collusion Burn)
        let vest_total = stake_sat - burned; // 50% time-locked (handles odd sat)
        let period = vesting_period.max(1);
        let vest_per_block = vest_total.div_ceil(period);
        SlashRecord {
            slash_id,
            slash_height,
            unlock_height: slash_height.saturating_add(vesting_period),
            vest_total,
            remaining_vest: vest_total,
            vest_per_block,
            burned,
            validator_address,
        }
    }

    /// Amount of vested stake payable at `current_height`.
    ///
    /// Returns the clipped per-block amount — never more than `remaining_vest`.
    pub fn claimable_at(&self, current_height: u64) -> u64 {
        if current_height <= self.slash_height || self.remaining_vest == 0 {
            return 0;
        }
        if current_height >= self.unlock_height {
            return self.remaining_vest; // full remainder vests at unlock
        }
        self.vest_per_block.min(self.remaining_vest)
    }

    /// Advance vesting by one block. Returns the amount released this block.
    pub fn advance(&mut self, current_height: u64) -> u64 {
        let claimable = self.claimable_at(current_height);
        self.remaining_vest = self.remaining_vest.saturating_sub(claimable);
        claimable
    }

    /// True when there is nothing left to vest.
    pub fn is_exhausted(&self) -> bool {
        self.remaining_vest == 0
    }
}

/// The on-chain slash vault. Holds all active `SlashRecord`s and drives
/// block-by-block vesting payout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlashVault {
    records: Vec<SlashRecord>,
    /// Running total of all amounts that have been permanently burned via
    /// slashing (Anti-Collusion Burn). Informational — does not affect consensus.
    pub total_burned: u64,
}

impl SlashVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new slash event. Returns a reference to the created record.
    pub fn slash(
        &mut self,
        slash_id: Hash,
        stake_sat: u64,
        slash_height: u64,
        vesting_period: u64,
        validator_address: [u8; 20],
    ) -> &SlashRecord {
        let record = SlashRecord::new(
            slash_id,
            stake_sat,
            slash_height,
            vesting_period,
            validator_address,
        );
        self.total_burned = self.total_burned.saturating_add(record.burned);
        self.records.push(record);
        self.records.last().unwrap()
    }

    /// Advance all active records by one block, returning a list of
    /// `(validator_address, amount_sat)` payouts for this block.
    ///
    /// Exhausted records are pruned automatically.
    pub fn advance_block(&mut self, current_height: u64) -> Vec<([u8; 20], u64)> {
        let mut payouts = Vec::new();
        for record in &mut self.records {
            let released = record.advance(current_height);
            if released > 0 {
                payouts.push((record.validator_address, released));
            }
        }
        // Prune exhausted records to keep the vault bounded.
        self.records.retain(|r| !r.is_exhausted());
        payouts
    }

    /// Number of active (non-exhausted) slash records.
    pub fn active_count(&self) -> usize {
        self.records.len()
    }

    /// Iterate over all active records (read-only).
    pub fn records(&self) -> &[SlashRecord] {
        &self.records
    }

    /// Rebuild a vault from decoded records — the codec entry point used by
    /// `L2State::decode` (SPEC.md §19.2 state transport).
    ///
    /// Structural only: it re-derives no protocol rule. `total_burned` is
    /// carried as data because it is an accumulator the state owns, not a sum
    /// this function is entitled to recompute from records (records are pruned
    /// once exhausted, so the two would disagree).
    pub fn with_records(records: Vec<SlashRecord>, total_burned: u64) -> Self {
        SlashVault {
            records,
            total_burned,
        }
    }
}

/// Fixed wire size of one [`SlashRecord`]: `32 + 6·8 + 20`.
const SLASH_RECORD_WIRE_LEN: usize = 32 + 6 * 8 + 20;

impl SlashRecord {
    /// Canonical wire encoding: every field, no signatures. Fixed size.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(SLASH_RECORD_WIRE_LEN);
        w.fixed(&self.slash_id)
            .u64le(self.slash_height)
            .u64le(self.unlock_height)
            .u64le(self.vest_total)
            .u64le(self.remaining_vest)
            .u64le(self.vest_per_block)
            .u64le(self.burned)
            .fixed(&self.validator_address);
        w.into_vec()
    }

    /// Decode [`SlashRecord::encode`]: the exact inverse, bounded and
    /// fail-closed on a truncated or over-long buffer.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let slash_id = r.fixed::<32>().map_err(|_| Error::Malformed("slash id"))?;
        let slash_height = r.u64le().map_err(|_| Error::Malformed("slash height"))?;
        let unlock_height = r.u64le().map_err(|_| Error::Malformed("unlock height"))?;
        let vest_total = r.u64le().map_err(|_| Error::Malformed("vest total"))?;
        let remaining_vest = r.u64le().map_err(|_| Error::Malformed("remaining vest"))?;
        let vest_per_block = r.u64le().map_err(|_| Error::Malformed("vest per block"))?;
        let burned = r.u64le().map_err(|_| Error::Malformed("burned"))?;
        let validator_address = r
            .fixed::<20>()
            .map_err(|_| Error::Malformed("validator address"))?;
        Ok(SlashRecord {
            slash_id,
            slash_height,
            unlock_height,
            vest_total,
            remaining_vest,
            vest_per_block,
            burned,
            validator_address,
        })
    }
}

impl SlashVault {
    /// Canonical wire encoding: `total_burned ‖ count ‖ records…`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16 + self.records.len() * SLASH_RECORD_WIRE_LEN);
        w.u64le(self.total_burned).u64le(self.records.len() as u64);
        for r in &self.records {
            w.raw(&r.encode());
        }
        w.into_vec()
    }

    /// Decode [`SlashVault::encode`]. The declared record count is checked
    /// against the bytes actually remaining *before* the `Vec` is built, so a
    /// four-byte lie cannot reserve memory.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let total_burned = r
            .u64le()
            .map_err(|_| Error::Malformed("vault total burned"))?;
        let count = r.u64le().map_err(|_| Error::Malformed("vault count"))? as usize;
        if count > r.remaining() / SLASH_RECORD_WIRE_LEN {
            return Err(Error::Malformed("vault record count exceeds buffer"));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(SlashRecord::decode(r)?);
        }
        Ok(SlashVault {
            records,
            total_burned,
        })
    }
}

// ---------------------------------------------------------------------------
// SlashOutcome: summary returned to callers
// ---------------------------------------------------------------------------

/// Summary of a single slash event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashOutcome {
    /// Satoshis permanently destroyed (Anti-Collusion Burn, 50%).
    pub burned: u64,
    /// Satoshis entering the Time-Locked Compute Reserve (50%).
    pub vest_total: u64,
    /// Block height at which vesting is complete.
    pub unlock_height: u64,
}

impl From<&SlashRecord> for SlashOutcome {
    fn from(r: &SlashRecord) -> Self {
        SlashOutcome {
            burned: r.burned,
            vest_total: r.vest_total,
            unlock_height: r.unlock_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_id(n: u8) -> Hash {
        [n; 32]
    }

    fn addr(n: u8) -> [u8; 20] {
        [n; 20]
    }

    // ------------------------------------------------------------------
    // SlashRecord unit tests
    // ------------------------------------------------------------------

    #[test]
    fn slash_splits_fifty_fifty() {
        let stake = 1_000_000u64; // 0.01 JNT in sats
        let rec = SlashRecord::new(dummy_id(1), stake, 100, VESTING_BLOCKS_MINI, addr(1));
        assert_eq!(rec.burned + rec.vest_total, stake, "no satoshi lost");
        assert_eq!(rec.burned, stake / 2, "50% instant burn");
        assert_eq!(rec.vest_total, stake - stake / 2, "50% time-locked");
    }

    #[test]
    fn slash_odd_satoshi_goes_to_vest() {
        // Odd amount: 1 extra sat goes to vest_total (not burned)
        let stake = 999_999u64;
        let rec = SlashRecord::new(dummy_id(2), stake, 0, VESTING_BLOCKS_MINI, addr(2));
        assert_eq!(rec.burned, stake / 2);
        assert_eq!(rec.vest_total, stake - stake / 2);
        assert_eq!(rec.burned + rec.vest_total, stake);
    }

    #[test]
    fn vesting_is_linear_and_bounded() {
        let stake = 2_000u64;
        let period = 10u64;
        let slash_height = 50u64;
        let mut rec = SlashRecord::new(dummy_id(3), stake, slash_height, period, addr(3));

        // vest_total = 1000 (50%), period = 10 → 100 sat/block
        let expected_per_block = rec.vest_total / period;
        let mut total_paid = 0u64;

        for h in (slash_height + 1)..=(slash_height + period) {
            let paid = rec.advance(h);
            assert!(paid <= expected_per_block + 1, "per-block amount bounded");
            total_paid += paid;
        }
        assert_eq!(total_paid, rec.vest_total + rec.remaining_vest);
        assert!(rec.is_exhausted() || rec.remaining_vest == 0);
    }

    #[test]
    fn full_remainder_vests_at_unlock() {
        let mut rec = SlashRecord::new(dummy_id(4), 1_000, 0, VESTING_BLOCKS_MINI, addr(4));
        // Jump straight to unlock_height — should release everything
        let all = rec.advance(rec.unlock_height);
        assert_eq!(all, rec.vest_total);
        assert!(rec.is_exhausted());
    }

    #[test]
    fn claimable_before_slash_height_is_zero() {
        let rec = SlashRecord::new(dummy_id(5), 500, 100, 10, addr(5));
        assert_eq!(rec.claimable_at(99), 0, "no claim before slash height");
        assert_eq!(rec.claimable_at(100), 0, "no claim at slash height itself");
        assert!(rec.claimable_at(101) > 0, "first claim is one block after");
    }

    // ------------------------------------------------------------------
    // SlashVault integration tests
    // ------------------------------------------------------------------

    #[test]
    fn vault_prunes_exhausted_records() {
        let mut vault = SlashVault::new();
        let stake = 100u64;
        let period = VESTING_BLOCKS_MINI;

        vault.slash(dummy_id(10), stake, 0, period, addr(10));
        assert_eq!(vault.active_count(), 1);

        // Advance past the unlock height
        for h in 1..=(period + 5) {
            vault.advance_block(h);
        }
        assert_eq!(vault.active_count(), 0, "exhausted record must be pruned");
    }

    #[test]
    fn vault_tracks_total_burned() {
        let mut vault = SlashVault::new();
        vault.slash(dummy_id(11), 1_000, 0, 10, addr(11));
        vault.slash(dummy_id(12), 2_000, 0, 10, addr(12));
        // Each slash burns 50% of stake
        assert_eq!(vault.total_burned, 1_500);
    }

    #[test]
    fn vault_returns_correct_payouts() {
        let mut vault = SlashVault::new();
        // Stake 100, period 10: vest_total = 50, 5 sat/block
        vault.slash(dummy_id(20), 100, 0, 10, addr(20));

        let payouts = vault.advance_block(1);
        assert_eq!(payouts.len(), 1);
        let (payout_addr, amount) = payouts[0];
        assert_eq!(payout_addr, addr(20));
        assert!(amount > 0);
    }

    #[test]
    fn slash_outcome_from_record() {
        let rec = SlashRecord::new(dummy_id(30), 1_000, 100, 50, addr(30));
        let outcome = SlashOutcome::from(&rec);
        assert_eq!(outcome.burned, rec.burned);
        assert_eq!(outcome.vest_total, rec.vest_total);
        assert_eq!(outcome.unlock_height, rec.unlock_height);
    }
}
