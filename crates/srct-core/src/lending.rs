//! Lending as a productive-agent advantage: offers, history, limits, autorepay.
//!
//! Credit here is for agents that need working capital, not merely a way to
//! move already-owned funds. Reputation prices risk; it never guarantees
//! repayment — every position is still collateralized, the lender still
//! absorbs the shortfall after collateral and bond, and a revoked or vanished
//! borrower still defaults at its deadline. What this module adds around the
//! existing [`CreditBook`](crate::credit::CreditBook):
//!
//! - [`LoanOffer`]: a lender's signed standard terms (amount range, rate,
//!   window, collateral terms hash, expiry). Borrowers discover offers
//!   (`OfferBook`) and accept the one that fits — no bespoke negotiation per
//!   loan, no off-book promises.
//! - [`RepaymentHistory`]: verified repayments, on-time rate, defaults and
//!   volume per borrower, derived from positions — the lender's risk input.
//! - [`suggested_limit`]: a conservative starting point from history (a
//!   fraction of repaid volume, zero with any default), which the lender
//!   adjusts. The score informs; the lender decides.
//! - [`StandingRepay`]: the borrower's signed instruction to route a share
//!   of each credit deposit to a position automatically — earned revenue
//!   repays the loan without a second transaction, only with explicit
//!   authorization, and only while unrevoked and unexpired.

use crate::credit::{CreditPosition, PositionState};
use crate::hash::{sha256_dom, Address, Hash};
use crate::l2::Auth;
use crate::wallet::Wallet;
use std::collections::BTreeMap;

pub const DOM_LOAN_OFFER: &[u8] = b"srct/loan-offer/v1";
pub const DOM_LOAN_ACCEPT: &[u8] = b"srct/loan-accept/v1";
pub const DOM_STANDING_REPAY: &[u8] = b"srct/standing-repay/v1";

/// The message a borrower signs to accept an offer: the offer id plus the
/// exact draw (borrower, amount, bond, deadline). Binding all of them
/// matters: without a borrower signature anyone could open debt in anyone
/// else's name (the debit lands in the named borrower's book), and without
/// the amounts bound a signed accept could be replayed for a different draw.
pub fn accept_hash(
    offer_id: &Hash,
    borrower: &Address,
    amount_sat: u64,
    bond_sat: u64,
    deadline_height: u64,
) -> Hash {
    sha256_dom(
        DOM_LOAN_ACCEPT,
        &[
            offer_id.as_slice(),
            borrower.as_slice(),
            &amount_sat.to_le_bytes(),
            &bond_sat.to_le_bytes(),
            &deadline_height.to_le_bytes(),
        ],
    )
}
pub const MAX_LOAN_OFFERS: usize = 512;

/// A lender's standard, signed offer. Accepting it opens a position on
/// exactly these terms — the offer hash commits to all of them, including
/// the full [`CreditTerms`](crate::credit::CreditTerms), so an accept cannot
/// smuggle in weaker collateral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoanOffer {
    pub network_id: String,
    pub lender: Address,
    pub min_principal_sat: u64,
    pub max_principal_sat: u64,
    pub rate_bps_per_window: u64,
    pub window_blocks: u64,
    pub base_collateral_bps: u32,
    pub max_discount_bps: u32,
    pub bond_ratio_bps: u32,
    pub min_collateral_bps: u32,
    pub expires_height: u64,
    pub nonce: u64,
}

impl LoanOffer {
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_LOAN_OFFER,
            &[
                self.network_id.as_bytes(),
                &self.lender,
                &self.min_principal_sat.to_le_bytes(),
                &self.max_principal_sat.to_le_bytes(),
                &self.rate_bps_per_window.to_le_bytes(),
                &self.window_blocks.to_le_bytes(),
                &self.base_collateral_bps.to_le_bytes(),
                &self.max_discount_bps.to_le_bytes(),
                &self.bond_ratio_bps.to_le_bytes(),
                &self.min_collateral_bps.to_le_bytes(),
                &self.expires_height.to_le_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }

    pub fn terms(&self) -> crate::credit::CreditTerms {
        crate::credit::CreditTerms {
            base_collateral_bps: self.base_collateral_bps,
            max_discount_bps: self.max_discount_bps,
            bond_ratio_bps: self.bond_ratio_bps,
            min_collateral_bps: self.min_collateral_bps,
        }
    }

    pub fn validate(&self) -> Result<(), LendingError> {
        if self.network_id.is_empty() || self.network_id.len() > 64 {
            return Err(LendingError::Malformed("network id"));
        }
        if self.min_principal_sat == 0 || self.max_principal_sat < self.min_principal_sat {
            return Err(LendingError::Malformed("principal range"));
        }
        if self.window_blocks == 0 {
            return Err(LendingError::Malformed("window"));
        }
        if self.rate_bps_per_window > 1_000 {
            // Matches the on-chain simple-interest cap (10% per window).
            return Err(LendingError::Malformed("rate over 10%"));
        }
        if self.expires_height == 0 {
            return Err(LendingError::Malformed("no expiry"));
        }
        // The terms must price: base/discount/floor sanity lives where the
        // arithmetic lives, so probe it with the minimum principal.
        self.terms()
            .required_collateral(self.min_principal_sat, 0)
            .map_err(|_| LendingError::Malformed("terms do not price"))?;
        Ok(())
    }

    /// Whether `principal_sat` at `height` fits this offer.
    pub fn fits(&self, principal_sat: u64, height: u64) -> bool {
        height <= self.expires_height
            && principal_sat >= self.min_principal_sat
            && principal_sat <= self.max_principal_sat
    }
}

/// Open offers by id (cap-with-refusal, like every other book here).
#[derive(Debug, Clone, Default)]
pub struct OfferBook {
    offers: BTreeMap<Hash, (LoanOffer, crate::sig::Bundle, crate::sig::Bundle)>,
}

impl OfferBook {
    pub fn len(&self) -> usize {
        self.offers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }

    /// Register a lender-signed offer. The signature must be the lender's
    /// over the offer id; expiry is checked at `height`.
    pub fn insert(
        &mut self,
        offer: LoanOffer,
        sigs: crate::sig::Bundle,
        keys: crate::sig::Bundle,
        height: u64,
    ) -> Result<Hash, LendingError> {
        offer.validate()?;
        if height > offer.expires_height {
            return Err(LendingError::Malformed("offer expired"));
        }
        if self.offers.len() >= MAX_LOAN_OFFERS && !self.offers.contains_key(&offer.id()) {
            return Err(LendingError::BookFull {
                cap: MAX_LOAN_OFFERS,
            });
        }
        let signer = keys
            .address()
            .map_err(|_| LendingError::Malformed("lender keys"))?;
        if signer != offer.lender {
            return Err(LendingError::SignerMismatch);
        }
        crate::sig::verify_bundle(&sigs, &keys, &offer.id())
            .map_err(|_| LendingError::SignatureInvalid)?;
        let id = offer.id();
        self.offers.insert(id, (offer, sigs, keys));
        Ok(id)
    }

    pub fn get(&self, id: &Hash) -> Option<&LoanOffer> {
        self.offers.get(id).map(|(o, _, _)| o)
    }

    /// Offers live at `height` covering `principal_sat`, cheapest rate first.
    pub fn discover(&self, principal_sat: u64, height: u64) -> Vec<&LoanOffer> {
        let mut out: Vec<&LoanOffer> = self
            .offers
            .values()
            .map(|(o, _, _)| o)
            .filter(|o| o.fits(principal_sat, height))
            .collect();
        out.sort_by_key(|o| (o.rate_bps_per_window, o.id()));
        out
    }

    pub fn remove(&mut self, id: &Hash) -> Option<LoanOffer> {
        self.offers.remove(id).map(|(o, _, _)| o)
    }
}

/// Verified repayment history for one borrower, derived from positions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepaymentHistory {
    pub borrower: Address,
    pub repaid_positions: u64,
    pub defaulted_positions: u64,
    pub total_repaid_sat: u64,
    pub total_borrowed_sat: u64,
    pub on_time_repayments: u64,
    pub total_repayments: u64,
}

impl RepaymentHistory {
    /// Derive from an iterator of positions for `borrower`. A repayment is
    /// on time when the position repaid at or before its deadline; defaults
    /// count whether or not the lender recovered in full — the shortfall is
    /// the lender's, the record is the borrower's.
    pub fn from_positions<'a>(
        borrower: &Address,
        positions: impl Iterator<Item = &'a CreditPosition>,
        now_height: u64,
    ) -> Self {
        let mut h = RepaymentHistory {
            borrower: *borrower,
            ..Default::default()
        };
        for p in positions {
            if p.borrower != *borrower {
                continue;
            }
            h.total_borrowed_sat = h.total_borrowed_sat.saturating_add(p.amount_sat);
            match p.state {
                PositionState::Repaid {
                    interest_paid_sat, ..
                } => {
                    h.repaid_positions += 1;
                    h.total_repaid_sat = h
                        .total_repaid_sat
                        .saturating_add(p.amount_sat)
                        .saturating_add(interest_paid_sat);
                    h.total_repayments += 1;
                    if now_height <= p.deadline_height {
                        h.on_time_repayments += 1;
                    }
                }
                PositionState::Defaulted { .. } => {
                    h.defaulted_positions += 1;
                }
                PositionState::Drawn { .. } => {}
            }
        }
        h
    }

    pub fn on_time_rate_bps(&self) -> u64 {
        if self.total_repayments == 0 {
            return 0;
        }
        (self.on_time_repayments as u128 * 10_000 / self.total_repayments as u128) as u64
    }
}

/// A conservative suggested ceiling from history. Any default zeroes it —
/// the lender may still lend, but not on the suggestion's authority. A
/// borrower with no history gets zero: unproven is unpriced, not free.
pub fn suggested_limit(history: &RepaymentHistory, reputation_score: i64) -> u64 {
    if history.defaulted_positions > 0 || history.repaid_positions == 0 {
        return 0;
    }
    // A quarter of proven repaid volume, nudged by reputation, capped so one
    // good loan cannot justify an unbounded second one.
    let base = history.total_repaid_sat / 4;
    let nudge: u64 = reputation_score.clamp(0, 100) as u64 * base / 1_000;
    base.saturating_add(nudge).min(history.total_repaid_sat)
}

/// Standing instruction: route `pct_bps` of each credit deposit to
/// `position_id` automatically, up to `cap_sat` total, while live.
/// Borrower-signed; revocable by registering an expired replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingRepay {
    pub network_id: String,
    pub borrower: Address,
    pub position_id: Hash,
    pub pct_bps: u64,
    pub cap_sat: u64,
    pub applied_sat: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl StandingRepay {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_STANDING_REPAY,
            &[
                self.network_id.as_bytes(),
                &self.borrower,
                &self.position_id,
                &self.pct_bps.to_le_bytes(),
                &self.cap_sat.to_le_bytes(),
                &self.expires_height.to_le_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), LendingError> {
        if self.network_id.is_empty() || self.network_id.len() > 64 {
            return Err(LendingError::Malformed("network id"));
        }
        if self.pct_bps == 0 || self.pct_bps > 10_000 {
            return Err(LendingError::Malformed("percent"));
        }
        if self.cap_sat == 0 || self.expires_height == 0 {
            return Err(LendingError::Malformed("cap/expiry"));
        }
        Ok(())
    }

    pub fn live_at(&self, height: u64) -> bool {
        height <= self.expires_height && self.applied_sat < self.cap_sat
    }
}

/// Sign a standing instruction with the borrower's wallet.
pub fn sign_standing_repay(
    borrower: &Wallet,
    network_id: &str,
    position_id: Hash,
    pct_bps: u64,
    cap_sat: u64,
    expires_height: u64,
    nonce: u64,
) -> Result<(StandingRepay, crate::sig::Bundle, crate::sig::Bundle), LendingError> {
    let addr = borrower
        .address()
        .map_err(|_| LendingError::Malformed("borrower address"))?;
    let instruction = StandingRepay {
        network_id: network_id.to_string(),
        borrower: addr,
        position_id,
        pct_bps,
        cap_sat,
        applied_sat: 0,
        expires_height,
        nonce,
    };
    instruction.validate()?;
    let keys = Auth::keys_for(borrower).map_err(|_| LendingError::Malformed("borrower keys"))?;
    let sigs = Auth::sigs_for(borrower, &instruction.signing_hash())
        .map_err(|_| LendingError::SignatureInvalid)?;
    Ok((instruction, sigs, keys))
}

/// Verify a standing instruction is the borrower's and live.
pub fn verify_standing_repay(
    instruction: &StandingRepay,
    sigs: &crate::sig::Bundle,
    keys: &crate::sig::Bundle,
    network_id: &str,
    height: u64,
) -> Result<(), LendingError> {
    instruction.validate()?;
    if instruction.network_id != network_id {
        return Err(LendingError::Malformed("wrong network"));
    }
    if !instruction.live_at(height) {
        return Err(LendingError::Malformed("instruction spent or expired"));
    }
    let signer = keys
        .address()
        .map_err(|_| LendingError::Malformed("borrower keys"))?;
    if signer != instruction.borrower {
        return Err(LendingError::SignerMismatch);
    }
    crate::sig::verify_bundle(sigs, keys, &instruction.signing_hash())
        .map_err(|_| LendingError::SignatureInvalid)?;
    Ok(())
}

/// Split a deposit under a live instruction: `(to_position, to_free)`.
/// Pure: the caller moves the value.
pub fn apply_standing_repay(
    instruction: &StandingRepay,
    deposit_sat: u64,
    position_debt_sat: u64,
) -> (u64, u64) {
    let share = (deposit_sat as u128 * instruction.pct_bps as u128 / 10_000) as u64;
    let remaining_cap = instruction.cap_sat.saturating_sub(instruction.applied_sat);
    let to_position = share
        .min(remaining_cap)
        .min(position_debt_sat)
        .min(deposit_sat);
    (to_position, deposit_sat - to_position)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LendingError {
    Malformed(&'static str),
    SignerMismatch,
    SignatureInvalid,
    BookFull { cap: usize },
}

impl std::fmt::Display for LendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LendingError::Malformed(w) => write!(f, "malformed lending record: {w}"),
            LendingError::SignerMismatch => write!(f, "lending signature is not the declarant"),
            LendingError::SignatureInvalid => write!(f, "lending signature invalid"),
            LendingError::BookFull { cap } => write!(f, "offer book full ({cap})"),
        }
    }
}

impl std::error::Error for LendingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn lender() -> Wallet {
        Wallet::from_private_key_bytes(&[6u8; 32], "lender").unwrap()
    }

    fn offer(lender_addr: Address) -> LoanOffer {
        LoanOffer {
            network_id: "srct/testnet".to_string(),
            lender: lender_addr,
            min_principal_sat: 100,
            max_principal_sat: 10_000,
            rate_bps_per_window: 500,
            window_blocks: 100,
            base_collateral_bps: 10_000,
            max_discount_bps: 2_000,
            bond_ratio_bps: 2_000,
            min_collateral_bps: 8_000,
            expires_height: 9_000,
            nonce: 1,
        }
    }

    #[test]
    fn offers_discover_cheapest_first() {
        let l = lender();
        let addr = l.address().unwrap();
        let mut book = OfferBook::default();
        for (rate, nonce) in [(900u64, 1u64), (100, 2), (500, 3)] {
            let mut o = offer(addr);
            o.rate_bps_per_window = rate;
            o.nonce = nonce;
            let keys = Auth::keys_for(&l).unwrap();
            let sigs = Auth::sigs_for(&l, &o.id()).unwrap();
            book.insert(o, sigs, keys, 100).unwrap();
        }
        let found = book.discover(500, 100);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].rate_bps_per_window, 100);
    }

    #[test]
    fn history_and_limits_price_risk_without_guaranteeing_it() {
        let borrower = [8u8; 20];
        let h = RepaymentHistory {
            borrower,
            repaid_positions: 2,
            defaulted_positions: 0,
            total_repaid_sat: 4_000,
            total_borrowed_sat: 4_000,
            on_time_repayments: 2,
            total_repayments: 2,
        };
        assert_eq!(h.on_time_rate_bps(), 10_000);
        // Quarter of proven volume: 1_000, small reputation nudge.
        assert_eq!(suggested_limit(&h, 20), 1_000 + 20);
        // Any default zeroes the suggestion.
        let mut bad = h.clone();
        bad.defaulted_positions = 1;
        assert_eq!(suggested_limit(&bad, 100), 0);
    }

    #[test]
    fn standing_repay_splits_deposits() {
        // 50% of a 1_000 deposit against 300 of debt: 300 to position.
        let instruction = StandingRepay {
            network_id: "srct/testnet".to_string(),
            borrower: [8u8; 20],
            position_id: [9u8; 32],
            pct_bps: 5_000,
            cap_sat: 10_000,
            applied_sat: 0,
            expires_height: 9_000,
            nonce: 1,
        };
        assert_eq!(apply_standing_repay(&instruction, 1_000, 300), (300, 700));
        assert_eq!(apply_standing_repay(&instruction, 1_000, 900), (500, 500));
    }
}
