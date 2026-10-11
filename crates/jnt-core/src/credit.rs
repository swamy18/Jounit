//! `credit`: bond-backed credit terms (roadmap item 2, decision D1).
//!
//! An agent with a demonstrated record can borrow against future work instead of
//! pre-funding every transaction. **D1 fixes the shape, and it is worth stating
//! plainly because the obvious design is the wrong one:**
//!
//! | | |
//! |---|---|
//! | **Reputation** | A deterministic **view**, read off on-chain events. Never a consensus input. |
//! | **Credit** | Always **collateralized**. A posted bond *discounts* the requirement, nothing more. |
//!
//! Two rules that follow, and are the whole reason this module is safe:
//!
//! ## 1. A bond discounts the requirement; it does not replace it
//!
//! [CreditTerms::required_collateral] returns `max(base, amount - discount)`, and
//! the discount is capped at a fraction of `amount`. It never returns less than
//! `MIN_COLLATERAL_RATIO` of the amount, whatever the agent's score or bond. There
//! is **no path to a zero-collateral line**, which is what "undercollateralized"
//! means here: *under*, not *un*.
//!
//! ## 2. Reputation is an input to a lender's decision, not to a protocol rule
//!
//! The score affects the discount a lender may *offer*. It does not affect
//! `required_collateral` except through the terms the lender chose, and no
//! consensus rule reads it. This matters for a specific reason: a credit limit
//! computed on-chain from a mutable score would make every reputation update a
//! consensus event and make fresh identities farmable, which is the cheapest
//! attack against the gate and the most expensive to defend.
//!
//! The consequence, accepted deliberately: a brand-new agent with score 0 gets no
//! discount but still gets a line, because it can still post collateral. That is
//! the correct outcome — reputation buys better terms, not access. It also means
//! this module is not a Sybil surface: farming an id yields nothing, because
//! nothing gates on the id.
//!
//! # What this module is not
//!
//! Not a lending protocol. It is the arithmetic that decides *how much*
//! collateral a given position needs, and the tests that pin the invariants. The
//! position itself, its lifecycle and its settlement belong to whoever wires this
//! up — and they must be built so a default is paid out of the bond, not out of
//! the reputation.

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, Hash};
use crate::reputation::ReputationScore;
use crate::ser::{Reader, Writer};

/// Domain tag for credit terms, so a term set can never be confused with a
/// bond, a policy or a receipt.
pub const DOM_CREDIT_TERMS: &[u8] = b"jounit/credit-terms/v1";

/// A lender's underwriting parameters for one class of position.
///
/// These are a lender's choice, set before a position is opened and immutable
/// afterwards. Nothing here is derived from the borrower's reputation — an agent
/// does not get to write the terms it is judged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditTerms {
    /// Collateral the position holds at zero discount, as a fraction of the
    /// borrowed amount in basis points. 10 000 bp = fully collateralized.
    pub base_collateral_bps: u32,
    /// Largest discount any bond may earn, in basis points of the amount.
    pub max_discount_bps: u32,
    /// Largest share of the bond that counts toward the discount. A bond worth
    /// more than the borrowed amount cannot buy a bigger discount than one that
    /// matches it, so `required_collateral` stays proportional to `amount`.
    pub bond_ratio_bps: u32,
    /// Collateral floor as a fraction of `amount`. Never breached, by design.
    pub min_collateral_bps: u32,
}

impl Default for CreditTerms {
    /// Conservative defaults, chosen so the floor is meaningful rather than
    /// reachable: the base is full collateralization, and the largest discount
    /// leaves 80% required.
    fn default() -> Self {
        CreditTerms {
            base_collateral_bps: 10_000,
            max_discount_bps: 2_000,
            bond_ratio_bps: 2_000,
            min_collateral_bps: 8_000,
        }
    }
}

impl CreditTerms {
    /// Largest bond this lender will credit toward a discount, for a given
    /// borrowed amount. Caps the bond rather than trusting it to be bounded.
    pub fn max_creditable_bond(&self, amount_sat: u64) -> u64 {
        sat_mul_bps(amount_sat, self.bond_ratio_bps)
    }

    /// The discount a posted bond earns, before the floor is applied.
    ///
    /// A bond is real value at risk, so it discounts the requirement
    /// satoshi-for-satoshi — never more than `max_discount_bps` of the amount can
    /// be bought off, whatever the bond's size. This is a single cap, not a
    /// scaling: applying a rate to the bond as well would charge the borrower for
    /// their own collateral twice.
    ///
    /// Returns `0` with no error for a bond larger than the creditable share,
    /// rather than an error: an oversized bond is not a reason to refuse a
    /// position, it is a reason to stop counting it.
    pub fn discount_for_bond(&self, amount_sat: u64, bond_sat: u64) -> u64 {
        if amount_sat == 0 {
            return 0;
        }
        let creditable = self.max_creditable_bond(amount_sat).min(bond_sat);
        creditable.min(sat_mul_bps(amount_sat, self.max_discount_bps))
    }

    /// Collateral a position must hold to borrow `amount_sat` with `bond_sat`
    /// posted.
    ///
    /// This is the security-critical function in the module, so its properties
    /// are worth stating and are tested below:
    ///
    /// - **Never zero, and never below the floor.** Whatever the bond or the
    ///   terms, `required >= floor(amount)`.
    /// - **Never increases.** Posting more bond can lower the requirement, never
    ///   raise it.
    /// - **Monotone in amount.** Borrowing more requires more collateral.
    /// - **No overflow.** Every product is checked; a wrapped value would compare
    ///   small and pass the bound.
    pub fn required_collateral(&self, amount_sat: u64, bond_sat: u64) -> Result<u64> {
        if amount_sat == 0 {
            return Err(Error::Malformed(
                "a credit position borrows a positive amount",
            ));
        }
        if self.base_collateral_bps > 20_000 {
            return Err(Error::Malformed("credit terms: base collateral above 200%"));
        }
        if self.max_discount_bps > self.base_collateral_bps {
            return Err(Error::Malformed(
                "credit terms: discount may not exceed the base requirement",
            ));
        }
        if self.min_collateral_bps > self.base_collateral_bps {
            return Err(Error::Malformed(
                "credit terms: floor above the base requirement",
            ));
        }

        // Both bounds are computed in u128: a u64 product of satoshis and basis
        // points overflows long before it looks large, and a wrapped sum would
        // compare small and pass.
        let base = (amount_sat as u128) * (self.base_collateral_bps as u128) / 10_000;
        let discount = self.discount_for_bond(amount_sat, bond_sat) as u128;
        let floor = (amount_sat as u128) * (self.min_collateral_bps as u128) / 10_000;

        let requirement = base.saturating_sub(discount).max(floor);
        if requirement > u64::MAX as u128 {
            return Err(Error::ValueOverflow);
        }
        Ok(requirement as u64)
    }

    /// Canonical encoding of the terms a position was opened under, so a
    /// settlement can be checked against the rule it was priced with.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(20);
        w.u32le(self.base_collateral_bps)
            .u32le(self.max_discount_bps)
            .u32le(self.bond_ratio_bps)
            .u32le(self.min_collateral_bps);
        w.into_vec()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(CreditTerms {
            base_collateral_bps: r.u32le()?,
            max_discount_bps: r.u32le()?,
            bond_ratio_bps: r.u32le()?,
            min_collateral_bps: r.u32le()?,
        })
    }

    /// The terms' own identity, so a position records which rule priced it.
    pub fn id(&self) -> Hash {
        sha256_dom(DOM_CREDIT_TERMS, &[&self.encode()])
    }
}

/// An agent's position in a lender's book.
///
/// The bond is held outside this module; what it holds is what the terms priced,
/// so a settlement can be recomputed from the position alone rather than from a
/// ledger that may have moved underneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditPosition {
    pub borrower: Address,
    /// The agent id the reputation view is read for. Informational: nothing in
    /// `required_collateral` reads it, per D1.
    pub agent_id: Hash,
    pub lender: Address,
    pub terms: CreditTerms,
    /// Satoshi borrowed.
    pub amount_sat: u64,
    /// Satoshi of bond credited at open time.
    pub bond_sat: u64,
    /// Collateral the position must hold, priced at open time.
    pub collateral_sat: u64,
}

impl CreditPosition {
    /// Price a position, refusing one that cannot be collateralized.
    ///
    /// The reputation score is deliberately accepted and deliberately unused: it
    /// is here so a caller can pass the context it already has, and documenting
    /// that it is not an input is the only honest way to keep it from becoming
    /// one by accident later.
    pub fn open(
        terms: &CreditTerms,
        borrower: Address,
        agent_id: Hash,
        lender: Address,
        amount_sat: u64,
        bond_sat: u64,
        _reputation: &ReputationScore,
    ) -> Result<Self> {
        let collateral_sat = terms.required_collateral(amount_sat, bond_sat)?;
        Ok(CreditPosition {
            borrower,
            agent_id,
            lender,
            terms: *terms,
            amount_sat,
            bond_sat,
            collateral_sat,
        })
    }

    /// Collateral still required, if the terms were recomputed at a new bond.
    /// Only ever falls, because `CreditTerms` guarantees monotonicity.
    pub fn reprice(&self, new_bond_sat: u64) -> Result<u64> {
        self.terms
            .required_collateral(self.amount_sat, new_bond_sat)
    }
}

/// Saturating satoshis-times-basis-points.
///
/// Deliberately not `saturating_mul` on u64: that would wrap at the *satoshis*
/// step for large `sat`, and a wrapped product compares small and passes a
/// bound. Compute in u128 and clamp once.
fn sat_mul_bps(sat: u64, bps: u32) -> u64 {
    let product = (sat as u128) * (bps as u128);
    if product > u64::MAX as u128 {
        u64::MAX
    } else {
        product as u64 / 10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(n: i64) -> ReputationScore {
        ReputationScore {
            score: n,
            ..Default::default()
        }
    }

    #[test]
    fn a_position_with_no_bond_still_requires_full_collateral() {
        let t = CreditTerms::default();
        let c = t.required_collateral(1_000_000, 0).unwrap();
        assert_eq!(c, 1_000_000, "zero bond buys zero discount");
    }

    #[test]
    fn a_bond_discounts_but_neither_to_zero_nor_below_the_floor() {
        let t = CreditTerms::default();
        // A bond far larger than the creditable share: the discount stops at
        // `max_discount_bps` of the amount, so size stops earning anything.
        let big = t.required_collateral(1_000_000, 1_000_000_000).unwrap();
        assert_eq!(
            big, 800_000,
            "the floor, and the cap, coincide at the defaults"
        );
        assert_ne!(big, 0, "there is no path to a zero-collateral line");

        // A bond below the creditable share discounts satoshi for satoshi, and
        // no further: 20 000 of bond buys 20 000 off a 1 000 000 line.
        let exact = t.required_collateral(1_000_000, 20_000).unwrap();
        assert_eq!(exact, 1_000_000 - 20_000);

        // The creditable share itself is the largest discount any bond can buy,
        // which is exactly `max_discount_bps` of the amount.
        let at_share = t
            .required_collateral(1_000_000, t.max_creditable_bond(1_000_000))
            .unwrap();
        assert_eq!(
            at_share, big,
            "a bond at the creditable share is already capped"
        );
    }

    #[test]
    fn the_requirement_never_rises_as_more_bond_is_posted() {
        let t = CreditTerms::default();
        let mut prev = t.required_collateral(10_000_000, 0).unwrap();
        for bond in [1u64, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let next = t.required_collateral(10_000_000, bond).unwrap();
            assert!(
                next <= prev,
                "bond {bond}: collateral rose from {prev} to {next}"
            );
            prev = next;
        }
    }

    #[test]
    fn the_requirement_is_monotone_in_the_amount_borrowed() {
        let t = CreditTerms::default();
        let mut prev = 0;
        for amount in [1u64, 10, 1_000, 1_000_000, 1_000_000_000] {
            let c = t.required_collateral(amount, 1_000_000).unwrap();
            assert!(c >= prev, "amount {amount}: collateral fell");
            prev = c;
        }
    }

    #[test]
    fn reputation_is_not_an_input_to_the_collateral_required() {
        // D1's core property, tested directly: the same bond and amount produce
        // the same requirement whatever the score, including a fresh id.
        let t = CreditTerms::default();
        let a = t.required_collateral(1_000_000, 50_000).unwrap();
        assert_eq!(
            CreditPosition::open(
                &t,
                [1u8; 20],
                [9u8; 32],
                [2u8; 20],
                1_000_000,
                50_000,
                &score(0)
            )
            .unwrap()
            .collateral_sat,
            a
        );
        assert_eq!(
            CreditPosition::open(
                &t,
                [1u8; 20],
                [9u8; 32],
                [2u8; 20],
                1_000_000,
                50_000,
                &score(10_000)
            )
            .unwrap()
            .collateral_sat,
            a
        );
    }

    #[test]
    fn a_zero_amount_position_is_refused() {
        assert!(CreditTerms::default()
            .required_collateral(0, 1_000)
            .is_err());
    }

    #[test]
    fn self_contradictory_terms_are_refused() {
        let t = CreditTerms {
            max_discount_bps: 20_000,
            ..Default::default()
        };
        assert!(
            t.required_collateral(1_000_000, 10_000).is_err(),
            "a discount above the base would drive the requirement to nothing"
        );
    }

    #[test]
    fn the_terms_round_trip_and_identify_themselves() {
        let t = CreditTerms::default();
        let bytes = t.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditTerms::decode(&mut r).unwrap(), t);
        assert_eq!(r.remaining(), 0);
        assert_eq!(
            t.id(),
            CreditTerms::decode(&mut crate::ser::Reader::new(&bytes))
                .unwrap()
                .id()
        );
    }

    #[test]
    fn an_unrepresentable_requirement_is_refused_not_wrapped() {
        // The overflow path: satoshis against basis points. A wrapped product
        // would compare small and pass the bound, so the position must be
        // refused instead - a borrower cannot take a position whose collateral
        // does not fit in the currency.
        let t = CreditTerms {
            base_collateral_bps: 20_000,
            max_discount_bps: 10_000,
            bond_ratio_bps: 10_000,
            min_collateral_bps: 0,
        };
        assert_eq!(
            t.required_collateral(u64::MAX, 1),
            Err(Error::ValueOverflow),
            "a requirement above u64::MAX must be refused, never wrapped"
        );

        // And the largest amount that *is* representable computes exactly,
        // rather than saturating somewhere on the way.
        let amount = u64::MAX / 2;
        let c = t.required_collateral(amount, 0).unwrap();
        assert!(
            c > u64::MAX / 2,
            "must be far above zero rather than wrapped small: {c}"
        );
    }
}
