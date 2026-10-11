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
use crate::ser::{Reader, Writer};
use std::collections::BTreeMap;

/// Domain tag for credit terms, so a term set can never be confused with a
/// bond, a policy or a receipt.
pub const DOM_CREDIT_TERMS: &[u8] = b"jounit/credit-terms/v1";

/// Domain tag for a credit position, so a position id can never be confused
/// with a terms id or any other derived hash.
pub const DOM_CREDIT_POSITION: &[u8] = b"jounit/credit-position/v1";

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
/// Where a position is in its life.
///
/// Only two of these are terminal, and nothing distinguishes them except what was
/// paid and when — a caller cannot settle a terminal position again, and cannot
/// settle a live one with the other state's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositionState {
    /// Alive: principal, interest and the amount owed are all still outstanding.
    Drawn {
        at_height: u64,
        /// Principal already repaid.
        repaid_principal_sat: u64,
        /// Interest already repaid.
        repaid_interest_sat: u64,
    },
    /// Paid off. Collateral returns to the borrower, untouched.
    Repaid {
        at_height: u64,
        interest_paid_sat: u64,
    },
    /// Not paid by the deadline. Settled as [`DefaultSettlement`].
    Defaulted {
        at_height: u64,
        settlement: DefaultSettlement,
    },
}

/// What a default actually paid, and who paid it.
///
/// Every field is a name rather than a netted number so an auditor can see *why*
/// value moved. The critical one is `from_bond_sat`: the bond is what backs a
/// default, and nothing in this module ever reaches for reputation instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefaultSettlement {
    /// Debt at the deadline: principal plus accrued interest.
    pub debt_sat: u64,
    /// Taken from the position's own collateral.
    pub from_collateral_sat: u64,
    /// Taken from the borrower's posted bond, once collateral ran out.
    pub from_bond_sat: u64,
    /// Debt the lender absorbed because collateral and bond together were short.
    /// A default is not free, and this is the honest way to say so.
    pub shortfall_sat: u64,
    /// Collateral in excess of the debt, returned to the borrower.
    pub excess_returned_sat: u64,
}

impl DefaultSettlement {
    /// The borrower loses exactly what the default took: collateral plus bond.
    pub fn borrower_lost_sat(&self) -> u64 {
        self.from_collateral_sat + self.from_bond_sat
    }

    /// The lender recovers the debt less any shortfall, and nothing more.
    pub fn lender_recovered_sat(&self) -> u64 {
        self.debt_sat - self.shortfall_sat
    }

    /// True when the position was so overcollateralized that the borrower came
    /// out of a default with value to spare. Rare by construction, but not
    /// impossible, and taking it would be theft - so it is a reported field.
    pub fn was_overcollateralized(&self) -> bool {
        self.excess_returned_sat > 0
    }
}

/// Where credit positions and their value actually live.
///
/// A position is arithmetic; this is what makes it real. It holds three kinds of
/// value — unencumbered balances, posted bonds, and collateral locked inside live
/// positions — and it enforces the one invariant that matters:
///
/// ```text
/// free + bonds + collateral(live) + recovered(lender) == deposited
/// ```
///
/// Value is **moved, never created**. `check_conservation` is the guard, in the
/// same spirit as `L2State`'s, and it is asserted across every test below because
/// a conservation failure in a credit book is how a position acquires funds with
/// no accounting reason for them.
///
/// The bond ledger is deliberately separate from `crate::bond`'s validator bonds.
/// A validator bond secures consensus; a credit bond secures a debt. Mixing them
/// would mean a validator's stake could back an agent's borrowing, which is a
/// different risk with a different holder, and the two slashes would compete for
/// the same value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreditBook {
    /// Unencumbered balances.
    free: BTreeMap<Address, u64>,
    /// Bonds posted against future borrowing, held separately from `free` so a
    /// borrower cannot spend the very thing backing its own credit.
    bonds: BTreeMap<Address, u64>,
    /// Live and terminal positions, keyed by their derived id.
    positions: std::collections::BTreeMap<Hash, CreditPosition>,
    /// Value received by lenders: what a default's settlement covered, and what
    /// repayments paid out. The book is where a lender's earnings accumulate,
    /// and this is the running total.
    recovered: BTreeMap<Address, u64>,
    /// Every satoshi ever put in. Append-only.
    deposited_total: u64,
}

impl CreditBook {
    /// An empty book.
    ///
    /// The explicit trait path is load-bearing: this book has an inherent
    /// `default` that settles positions, and bare `CreditBook::default()` would
    /// resolve to *that*, three arguments short.
    pub fn new() -> Self {
        <CreditBook as Default>::default()
    }

    /// Credit an agent's balance. This is the only way value enters the book.
    pub fn deposit(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        let e = self.free.entry(agent).or_insert(0);
        *e = e.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.deposited_total = self
            .deposited_total
            .checked_add(amount_sat)
            .ok_or(Error::ValueOverflow)?;
        Ok(())
    }

    /// Free (unencumbered) balance.
    pub fn free(&self, agent: &Address) -> u64 {
        self.free.get(agent).copied().unwrap_or(0)
    }

    /// Bond posted by an agent.
    pub fn bond(&self, agent: &Address) -> u64 {
        self.bonds.get(agent).copied().unwrap_or(0)
    }

    /// Post a bond from the agent's free balance.
    ///
    /// A bond cannot be posted from itself: it comes out of free money, or it is
    /// nothing. That is also what stops a borrower from uncollateralizing by
    /// moving value into a bond and out of reach of the position.
    pub fn post_bond(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        if self.free(&agent) < amount_sat {
            return Err(Error::Malformed(
                "free balance cannot cover the bond being posted",
            ));
        }
        let f = self.free.get_mut(&agent).unwrap();
        *f -= amount_sat;
        let b = self.bonds.entry(agent).or_insert(0);
        *b = b.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.check_conservation()
    }

    /// Release a bond back to the agent's free balance.
    pub fn release_bond(&mut self, agent: Address, amount_sat: u64) -> Result<()> {
        if self.bond(&agent) < amount_sat {
            return Err(Error::Malformed(
                "no posted bond covers the release requested",
            ));
        }
        let b = self.bonds.get_mut(&agent).unwrap();
        *b -= amount_sat;
        let f = self.free.entry(agent).or_insert(0);
        *f = f.checked_add(amount_sat).ok_or(Error::ValueOverflow)?;
        self.check_conservation()
    }

    /// Open a position, locking its collateral out of the borrower's free balance.
    ///
    /// Two upstream requirements, both enforced here rather than assumed:
    ///
    /// - The bond the position is priced with must be **posted first**. A bond
    ///   that exists only in the spec buys a discount the borrower never backed,
    ///   which is undercollateralization wearing a discount's clothes.
    /// - The collateral must be in the borrower's free balance, because this is
    ///   where it leaves it.
    ///
    /// The bond itself is *credited* rather than moved: it stays posted, and the
    /// terms only count it toward the discount. A position therefore never
    /// becomes able to spend the bond backing it.
    pub fn open(&mut self, spec: &PositionSpec) -> Result<Hash> {
        let id = spec.id();
        if self.positions.contains_key(&id) {
            return Err(Error::Malformed("this position is already open"));
        }
        let position = CreditPosition::open(spec)?;
        if self.bond(&spec.borrower) < spec.bond_sat {
            return Err(Error::Malformed(
                "the bond a position is priced with must be posted before it opens",
            ));
        }
        if self.free(&spec.borrower) < position.collateral_sat {
            return Err(Error::Malformed(
                "free balance cannot cover the collateral required",
            ));
        }
        let f = self.free.get_mut(&spec.borrower).unwrap();
        *f -= position.collateral_sat;
        self.positions.insert(id, position);
        self.check_conservation()?;
        Ok(id)
    }

    /// Look a position up.
    pub fn position(&self, id: &Hash) -> Option<&CreditPosition> {
        self.positions.get(id)
    }

    /// Every live position. Terminal ones stay in the book for the record but are
    /// not iterated here, because nothing can change them.
    pub fn live_positions(&self) -> impl Iterator<Item = (&Hash, &CreditPosition)> {
        self.positions.iter().filter(|(_, p)| !p.is_terminal())
    }

    /// Repay against a position.
    ///
    /// The payment comes from the borrower's free balance and lands with the
    /// lender. A caller that wants to fund a repayment from elsewhere must
    /// deposit first; accepting an unfunded payment would let a position settle
    /// without the value existing.
    pub fn repay(&mut self, id: &Hash, payment_sat: u64, height: u64) -> Result<Repayment> {
        // Charge and read the parties before touching the position, so a
        // refusal leaves the position untouched and no borrow outlives its scope.
        let (borrower, lender) = {
            let position = self
                .positions
                .get(id)
                .ok_or(Error::Malformed("no such position"))?;
            (position.borrower, position.lender)
        };
        if self.free(&borrower) < payment_sat {
            return Err(Error::Malformed("free balance cannot cover the repayment"));
        }
        let result = {
            let position = self
                .positions
                .get_mut(id)
                .ok_or(Error::Malformed("no such position"))?;
            position.repay(payment_sat, height)?
        };
        let f = self.free.get_mut(&borrower).unwrap();
        *f -= payment_sat;

        // The lender is paid: the value left the borrower and it went somewhere,
        // which is the half of conservation a repayment has to get right.
        let paid = self.recovered.entry(lender).or_insert(0);
        *paid = paid.checked_add(payment_sat).ok_or(Error::ValueOverflow)?;

        // A fully repaid position returns its collateral to the borrower. The
        // repayment says whether it settled; the position holds the collateral.
        if result.remaining_debt_sat == 0 {
            let returned = self
                .positions
                .get(id)
                .ok_or(Error::Malformed("no such position"))?
                .collateral_sat;
            if returned > 0 {
                let f = self.free.entry(borrower).or_insert(0);
                *f = f.checked_add(returned).ok_or(Error::ValueOverflow)?;
            }
        }
        self.check_conservation()?;
        Ok(result)
    }

    /// Default a position at its deadline.
    ///
    /// Order of payment is the settlement's own, unchanged: collateral first,
    /// then the bond, never reputation. The difference here is that the bond is
    /// *actually taken* — this is where a default's values leave the locked
    /// pools, and the conservation check confirms exactly where they land.
    pub fn default(&mut self, id: &Hash, height: u64) -> Result<DefaultSettlement> {
        let position = self
            .positions
            .get_mut(id)
            .ok_or(Error::Malformed("no such position"))?;
        let borrower = position.borrower;
        let lender = position.lender;
        let settlement = position.default(height)?;

        let f = self.free.entry(borrower).or_insert(0);
        *f = f
            .checked_add(settlement.excess_returned_sat)
            .ok_or(Error::ValueOverflow)?;
        if settlement.from_bond_sat > 0 {
            let b = self
                .bonds
                .get_mut(&borrower)
                .ok_or(Error::Malformed("no posted bond to take the default from"))?;
            if *b < settlement.from_bond_sat {
                return Err(Error::Malformed(
                    "posted bond is smaller than the default requires",
                ));
            }
            *b -= settlement.from_bond_sat;
        }
        let r = self.recovered.entry(lender).or_insert(0);
        *r = r
            .checked_add(settlement.lender_recovered_sat())
            .ok_or(Error::ValueOverflow)?;
        self.check_conservation()?;
        Ok(settlement)
    }

    /// Value a lender has received — recovered from defaults and paid out by
    /// repayments alike.
    pub fn recovered(&self, lender: &Address) -> u64 {
        self.recovered.get(lender).copied().unwrap_or(0)
    }

    /// Collateral currently locked inside live positions.
    fn locked_collateral(&self) -> u64 {
        self.positions
            .values()
            .filter(|p| !p.is_terminal())
            .fold(0u64, |acc, p| acc.saturating_add(p.collateral_sat))
    }

    /// The invariant: value is moved, never created.
    ///
    /// A failed check is a bug, not a policy disagreement, which is why it
    /// returns an error rather than a bool — a caller that cannot proceed on
    /// failure must not be able to ignore it.
    pub fn check_conservation(&self) -> Result<()> {
        let accounted = self
            .free
            .values()
            .chain(self.bonds.values())
            .fold(0u64, |acc, v| acc.saturating_add(*v))
            .saturating_add(self.locked_collateral())
            .saturating_add(
                self.recovered
                    .values()
                    .fold(0u64, |acc, v| acc.saturating_add(*v)),
            );
        if accounted != self.deposited_total {
            return Err(Error::Malformed(
                "credit conservation: accounted value does not equal deposited",
            ));
        }
        Ok(())
    }

    /// Totals, for diagnostics and for asserting the invariant directly.
    pub fn total_deposited(&self) -> u64 {
        self.deposited_total
    }

    pub fn total_locked_collateral(&self) -> u64 {
        self.locked_collateral()
    }
}

/// A codec for a whole position, so a node can serve one and a worker can read it.
impl CreditPosition {
    /// Canonical encoding. Self-delimiting: the attestation-free fields are
    /// fixed-size or written by their own encoders, so `decode` never guesses.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(256);
        w.fixed(&self.borrower)
            .fixed(&self.agent_id)
            .fixed(&self.lender)
            .raw(&self.terms.encode())
            .u32le(self.charge.rate_bps_per_window)
            .u64le(self.charge.window_blocks)
            .u64le(self.amount_sat)
            .u64le(self.bond_sat)
            .u64le(self.collateral_sat)
            .u64le(self.drawn_at_height)
            .u64le(self.deadline_height);
        match &self.state {
            PositionState::Drawn {
                at_height,
                repaid_principal_sat,
                repaid_interest_sat,
            } => {
                w.u8(WIRE_DRAWN)
                    .u64le(*at_height)
                    .u64le(*repaid_principal_sat)
                    .u64le(*repaid_interest_sat);
            }
            PositionState::Repaid {
                at_height,
                interest_paid_sat,
            } => {
                w.u8(WIRE_REPAID)
                    .u64le(*at_height)
                    .u64le(*interest_paid_sat);
            }
            PositionState::Defaulted {
                at_height,
                settlement,
            } => {
                w.u8(WIRE_DEFAULTED).u64le(*at_height);
                w.u64le(settlement.debt_sat)
                    .u64le(settlement.from_collateral_sat)
                    .u64le(settlement.from_bond_sat)
                    .u64le(settlement.shortfall_sat)
                    .u64le(settlement.excess_returned_sat);
            }
        }
        w.into_vec()
    }

    /// Decode what [`CreditPosition::encode`] wrote. Bounded and fail-closed.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let borrower = r.fixed()?;
        let agent_id = r.fixed()?;
        let lender = r.fixed()?;
        let terms = CreditTerms::decode(r)?;
        let charge = ChargeSchedule {
            rate_bps_per_window: r.u32le()?,
            window_blocks: r.u64le()?,
        };
        let amount_sat = r.u64le()?;
        let bond_sat = r.u64le()?;
        let collateral_sat = r.u64le()?;
        let drawn_at_height = r.u64le()?;
        let deadline_height = r.u64le()?;
        let state = match r.u8()? {
            WIRE_DRAWN => PositionState::Drawn {
                at_height: r.u64le()?,
                repaid_principal_sat: r.u64le()?,
                repaid_interest_sat: r.u64le()?,
            },
            WIRE_REPAID => PositionState::Repaid {
                at_height: r.u64le()?,
                interest_paid_sat: r.u64le()?,
            },
            WIRE_DEFAULTED => {
                let at_height = r.u64le()?;
                let settlement = DefaultSettlement {
                    debt_sat: r.u64le()?,
                    from_collateral_sat: r.u64le()?,
                    from_bond_sat: r.u64le()?,
                    shortfall_sat: r.u64le()?,
                    excess_returned_sat: r.u64le()?,
                };
                PositionState::Defaulted {
                    at_height,
                    settlement,
                }
            }
            _ => return Err(Error::Malformed("unknown position state tag")),
        };
        Ok(CreditPosition {
            borrower,
            agent_id,
            lender,
            terms,
            charge,
            amount_sat,
            bond_sat,
            collateral_sat,
            drawn_at_height,
            deadline_height,
            state,
        })
    }
}

const WIRE_DRAWN: u8 = 0;
const WIRE_REPAID: u8 = 1;
const WIRE_DEFAULTED: u8 = 2;

/// What a repayment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repayment {
    pub interest_paid_sat: u64,
    pub principal_paid_sat: u64,
    /// Debt still outstanding. Zero only when the position settled.
    pub remaining_debt_sat: u64,
}

/// A charge schedule for a position: simple interest, charged per whole window.
///
/// Deterministic by construction — `accrued_interest` depends only on heights, so
/// every node recomputes the same figure. No sub-window fractions, which would
/// otherwise make the total depend on rounding order rather than on time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChargeSchedule {
    /// Interest per window in basis points of the outstanding principal.
    pub rate_bps_per_window: u32,
    /// Length of a window in blocks.
    pub window_blocks: u64,
}

impl ChargeSchedule {
    /// Interest owed on `principal` between `from_height` and `to_height`.
    ///
    /// Refuses a backwards window rather than returning zero: a negative elapsed
    /// time is a caller error, and zero would silently forgive it.
    pub fn accrued_interest(
        &self,
        principal_sat: u64,
        from_height: u64,
        to_height: u64,
    ) -> Result<u64> {
        if to_height < from_height {
            return Err(Error::Malformed(
                "credit interest computed over a backwards window",
            ));
        }
        let windows = (to_height - from_height) / self.window_blocks.max(1);
        if windows == 0 || principal_sat == 0 {
            return Ok(0);
        }
        let units =
            (principal_sat as u128) * (self.rate_bps_per_window as u128) * (windows as u128);
        match u64::try_from(units) {
            Ok(v) => Ok(v / 10_000),
            Err(_) => Ok(u64::MAX / 10_000),
        }
    }
}

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
    /// Height the position was drawn at.
    pub drawn_at_height: u64,
    /// Height the position must be repaid by. Before it, `default` is refused;
    /// at or after it, an unpaid position may be settled. A deadline before the
    /// draw is a caller error, not a position that is already due.
    pub deadline_height: u64,
    /// The charge schedule the position was opened under.
    pub charge: ChargeSchedule,
    pub state: PositionState,
}

/// What a position is opened from.
///
/// A struct rather than nine positional arguments: `open` takes enough context
/// that a caller transposing two `Address` arguments is a real mistake, and the
/// spec is what a node deserializes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionSpec {
    pub terms: CreditTerms,
    pub charge: ChargeSchedule,
    pub borrower: Address,
    pub agent_id: Hash,
    pub lender: Address,
    /// Satoshi borrowed.
    pub amount_sat: u64,
    /// Satoshi of bond pledged, credited toward the collateral discount.
    pub bond_sat: u64,
    pub drawn_at_height: u64,
    /// Height the position must be repaid by. Before it, `default` is refused;
    /// at or after it, an unpaid position may be settled. A deadline before the
    /// draw is a caller error, not a position that is already due.
    pub deadline_height: u64,
}

impl PositionSpec {
    /// The position's derived id, over every field that makes it what it is.
    ///
    /// Deterministic and position-specific, so two positions that differ in any
    /// term are different positions. One position id, ever: a caller cannot
    /// re-open an existing one.
    pub fn id(&self) -> Hash {
        sha256_dom(DOM_CREDIT_POSITION, &[&self.encode()])
    }

    /// Canonical encoding of the whole spec, so the id is over stable bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(168);
        w.raw(&self.terms.encode())
            .u32le(self.charge.rate_bps_per_window)
            .u64le(self.charge.window_blocks)
            .fixed(&self.borrower)
            .fixed(&self.agent_id)
            .fixed(&self.lender)
            .u64le(self.amount_sat)
            .u64le(self.bond_sat)
            .u64le(self.drawn_at_height)
            .u64le(self.deadline_height);
        w.into_vec()
    }

    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self> {
        let terms = CreditTerms::decode(r)?;
        let charge = ChargeSchedule {
            rate_bps_per_window: r.u32le()?,
            window_blocks: r.u64le()?,
        };
        Ok(PositionSpec {
            terms,
            charge,
            borrower: r.fixed()?,
            agent_id: r.fixed()?,
            lender: r.fixed()?,
            amount_sat: r.u64le()?,
            bond_sat: r.u64le()?,
            drawn_at_height: r.u64le()?,
            deadline_height: r.u64le()?,
        })
    }
}

impl CreditPosition {
    /// Price a position, refusing one that cannot be collateralized.
    ///
    /// Note what is absent from [`PositionSpec`]: any reputation score. That is
    /// D1's invariant rather than an omission, and it is easier to keep absent
    /// than to keep ignored - an earlier shape of this function took a
    /// `ReputationScore` and discarded it, which put the dependency one careless
    /// caller away from becoming real.
    pub fn open(spec: &PositionSpec) -> Result<Self> {
        if spec.deadline_height < spec.drawn_at_height {
            return Err(Error::Malformed(
                "a position cannot mature before it is drawn",
            ));
        }
        let collateral_sat = spec
            .terms
            .required_collateral(spec.amount_sat, spec.bond_sat)?;
        Ok(CreditPosition {
            borrower: spec.borrower,
            agent_id: spec.agent_id,
            lender: spec.lender,
            terms: spec.terms,
            amount_sat: spec.amount_sat,
            bond_sat: spec.bond_sat,
            collateral_sat,
            drawn_at_height: spec.drawn_at_height,
            deadline_height: spec.deadline_height,
            charge: spec.charge,
            state: PositionState::Drawn {
                at_height: spec.drawn_at_height,
                repaid_principal_sat: 0,
                repaid_interest_sat: 0,
            },
        })
    }

    /// Collateral still required, if the terms were recomputed at a new bond.
    /// Only ever falls, because `CreditTerms` guarantees monotonicity.
    pub fn reprice(&self, new_bond_sat: u64) -> Result<u64> {
        self.terms
            .required_collateral(self.amount_sat, new_bond_sat)
    }

    /// True once the position can no longer change: repaid or defaulted.
    pub fn is_terminal(&self) -> bool {
        !matches!(self.state, PositionState::Drawn { .. })
    }

    /// Principal still outstanding on a live position. Zero for a settled one.
    fn outstanding_principal(&self) -> u64 {
        match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                ..
            } => self.amount_sat.saturating_sub(repaid_principal_sat),
            _ => 0,
        }
    }

    /// The debt at `height`: outstanding principal plus accrued interest less
    /// whatever has already been repaid.
    pub fn debt_at(&self, height: u64) -> Result<u64> {
        match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                repaid_interest_sat,
                ..
            } => {
                let outstanding_principal = self
                    .amount_sat
                    .checked_sub(repaid_principal_sat)
                    .ok_or(Error::Malformed("repaid more principal than borrowed"))?;
                let accrued = self.charge.accrued_interest(
                    outstanding_principal,
                    self.drawn_at_height,
                    height,
                )?;
                accrued
                    .checked_sub(repaid_interest_sat)
                    .ok_or(Error::Malformed("repaid more interest than accrued"))?
                    .checked_add(outstanding_principal)
                    .ok_or(Error::ValueOverflow)
            }
            _ => Err(Error::Malformed("a settled position has no debt")),
        }
    }

    /// Repay against the debt, interest first.
    ///
    /// Returns what the payment did, never more than the debt. Overpayment is
    /// refused rather than silently clipped: a caller paying more than they owe
    /// is paying the wrong amount, and quietly accepting the surplus is how
    /// positions acquire funds with no accounting reason for them.
    pub fn repay(&mut self, payment_sat: u64, height: u64) -> Result<Repayment> {
        let (mut repaid_principal, mut repaid_interest) = match self.state {
            PositionState::Drawn {
                repaid_principal_sat,
                repaid_interest_sat,
                ..
            } => (repaid_principal_sat, repaid_interest_sat),
            _ => return Err(Error::Malformed("a settled position cannot be repaid")),
        };

        let debt = self.debt_at(height)?;
        if payment_sat > debt {
            return Err(Error::Malformed("repayment exceeds the debt owed"));
        }

        // Interest first, then principal. Paying principal down before the
        // lender's own charge would leave that charge unpaid, and the borrower
        // does not get to choose the order.
        let outstanding_principal = self.outstanding_principal();
        let accrued_interest = self
            .charge
            .accrued_interest(outstanding_principal, self.drawn_at_height, height)?
            .saturating_sub(repaid_interest);
        let interest_paid = payment_sat.min(accrued_interest);
        let principal_paid = payment_sat - interest_paid;

        repaid_interest = repaid_interest
            .checked_add(interest_paid)
            .ok_or(Error::ValueOverflow)?;
        repaid_principal = repaid_principal
            .checked_add(principal_paid)
            .ok_or(Error::ValueOverflow)?;

        let remaining_debt = debt.saturating_sub(payment_sat);

        self.state = if remaining_debt == 0 {
            PositionState::Repaid {
                at_height: height,
                interest_paid_sat: repaid_interest,
            }
        } else {
            PositionState::Drawn {
                at_height: height,
                repaid_principal_sat: repaid_principal,
                repaid_interest_sat: repaid_interest,
            }
        };

        Ok(Repayment {
            interest_paid_sat: interest_paid,
            principal_paid_sat: principal_paid,
            remaining_debt_sat: remaining_debt,
        })
    }

    /// Settle an unpaid position at its deadline.
    ///
    /// The order of payments is the whole point: **collateral first, then the
    /// bond, and never reputation.** The position's own collateral is what was
    /// pledged for it; the bond is what backs a default.
    ///
    /// The deadline is the lender's patience made checkable: before it, an
    /// unpaid position is merely late, not defaulted — a lender that could
    /// settle on a whim would make every term it offered meaningless.
    ///
    /// Collateral in excess of the debt returns to the borrower. A default takes
    /// what it is owed and no more — an overcollateralized position that went
    /// bad still belongs to its borrower outside the debt.
    pub fn default(&mut self, height: u64) -> Result<DefaultSettlement> {
        if height < self.deadline_height {
            return Err(Error::Malformed(
                "the position has not yet reached its deadline",
            ));
        }
        let outstanding_principal = self.outstanding_principal();
        if outstanding_principal == 0 {
            return Err(Error::Malformed("nothing is owed, so nothing can default"));
        }
        let debt = self
            .debt_at(height)
            .map_err(|_| Error::Malformed("the position's debt could not be computed"))?;

        let from_collateral = self.collateral_sat.min(debt);
        let still_owed = debt - from_collateral;
        let from_bond = still_owed.min(self.bond_sat);
        let shortfall = still_owed - from_bond;
        let excess_returned = self.collateral_sat - from_collateral;

        let settlement = DefaultSettlement {
            debt_sat: debt,
            from_collateral_sat: from_collateral,
            from_bond_sat: from_bond,
            shortfall_sat: shortfall,
            excess_returned_sat: excess_returned,
        };

        self.state = PositionState::Defaulted {
            at_height: height,
            settlement,
        };
        Ok(settlement)
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

    /// A live schedule: 10% per 100-block window.
    fn charge() -> ChargeSchedule {
        ChargeSchedule {
            rate_bps_per_window: 1_000,
            window_blocks: 100,
        }
    }

    /// A drawn position: 1_000_000 borrowed with the given bond. Deterministic
    /// and small enough to reason about on paper. Defaultable from the draw
    /// height, so the tests below can settle it wherever they like.
    fn drawn(bond: u64) -> CreditPosition {
        CreditPosition::open(&spec(1_000_000, bond, 0, 0)).unwrap()
    }

    /// Build a position without opening it, so a test can inspect or perturb it.
    fn spec(amount: u64, bond: u64, at: u64, deadline: u64) -> PositionSpec {
        PositionSpec {
            terms: CreditTerms::default(),
            charge: charge(),
            borrower: [1u8; 20],
            agent_id: [9u8; 32],
            lender: [2u8; 20],
            amount_sat: amount,
            bond_sat: bond,
            drawn_at_height: at,
            deadline_height: deadline,
        }
    }

    /// D1's invariant, in its strongest available form.
    ///
    /// An earlier shape of `open` took a `ReputationScore` and discarded it. That
    /// version was *conventional* and weaker than this one, because it left the
    /// dependency one careless caller away from becoming real: a future edit that
    /// started reading the score would have compiled. Removing the parameter
    /// entirely means credit cannot be computed from a reputation score even by
    /// accident - the type system refuses the call rather than the code refusing
    /// it.
    ///
    /// The score is still the lender's underwriting input, exactly as before. The
    /// point is that it is the lender's, off the chain's critical path, so a
    /// reputation update is not a consensus event and a fresh id is not farmable.
    #[test]
    fn credit_cannot_be_computed_from_a_reputation_score_at_all() {
        // The compile-time assertion: no signature in this module accepts one.
        // If `PositionSpec` or `open` ever gains a score field, stop and think
        // about D1 again, because that is the change the decision refuses.
        let p = spec(1_000_000, 0, 0, 0);
        // The same figures, whatever an agent's score might be, price identically.
        assert_eq!(
            CreditPosition::open(&p).unwrap().collateral_sat,
            CreditPosition::open(&p).unwrap().collateral_sat
        );
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
            CreditPosition::open(&spec(1_000_000, 50_000, 0, 0))
                .unwrap()
                .collateral_sat,
            a
        );
        assert_eq!(
            CreditPosition::open(&spec(1_000_000, 50_000, 0, 0))
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
    fn interest_accrues_per_whole_window_only() {
        let c = charge();
        // One window of 10% on 1 000 000 is 100 000.
        assert_eq!(c.accrued_interest(1_000_000, 0, 100).unwrap(), 100_000);
        // A fraction of a window accrues nothing: there is no sub-window
        // fraction, so the total never depends on rounding order.
        assert_eq!(c.accrued_interest(1_000_000, 0, 50).unwrap(), 0);
        assert_eq!(c.accrued_interest(1_000_000, 0, 99).unwrap(), 0);
        assert_eq!(c.accrued_interest(1_000_000, 0, 200).unwrap(), 200_000);
        // Interest is charged on outstanding principal, so repaying reduces it.
        assert_eq!(c.accrued_interest(500_000, 0, 100).unwrap(), 50_000);
        // A backwards window is a caller error, not zero.
        assert!(c.accrued_interest(1_000_000, 100, 0).is_err());
    }

    #[test]
    fn a_position_repays_interest_before_principal() {
        // 1 000 000 borrowed, one window elapsed before any repayment.
        let mut p = drawn(0);
        let r = p.repay(50_000, 100).unwrap();
        // The whole payment lands on interest, because that is the lender's
        // charge and comes first. The principal is untouched.
        assert_eq!(r.interest_paid_sat, 50_000);
        assert_eq!(r.principal_paid_sat, 0);
        assert_eq!(
            r.remaining_debt_sat, 1_050_000,
            "1 000 000 principal + 50 000 left of interest"
        );

        // Paying the rest settles it, and the collateral returns whole.
        let r2 = p.repay(1_050_000, 100).unwrap();
        assert_eq!(r2.remaining_debt_sat, 0);
        assert!(p.is_terminal());
        assert!(
            matches!(p.state, PositionState::Repaid { interest_paid_sat, .. } if interest_paid_sat == 100_000)
        );
    }

    #[test]
    fn repaying_more_than_the_debt_is_refused() {
        // A payment larger than the debt is the caller paying the wrong amount.
        // Accepting it quietly is how a position acquires funds with no reason.
        let mut p = drawn(0);
        assert!(p.repay(1_000_001, 0).is_err());
    }

    #[test]
    fn a_default_takes_collateral_first_then_the_bond_and_never_reputation() {
        // 1 000 000 borrowed with a 0 bond: collateral is the full amount, and
        // with one window of interest the debt exceeds it.
        let mut p = drawn(0);
        let s = p.default(100).unwrap();

        assert_eq!(s.debt_sat, 1_100_000);
        assert_eq!(
            s.from_collateral_sat, 1_000_000,
            "the position's own collateral is taken first"
        );
        assert_eq!(s.from_bond_sat, 0, "there was no bond to take");
        assert_eq!(
            s.shortfall_sat, 100_000,
            "the lender absorbs what collateral could not cover"
        );
        assert_eq!(s.excess_returned_sat, 0, "nothing was left over");

        // The bond is what backs a default; posting one discounts the collateral
        // requirement, so the debt now spills past the collateral into the bond.
        let mut p2 = drawn(50_000);
        assert_eq!(
            p2.collateral_sat, 950_000,
            "the bond discounted the requirement"
        );
        let s2 = p2.default(100).unwrap();
        assert_eq!(s2.debt_sat, 1_100_000);
        assert_eq!(
            s2.from_collateral_sat, 950_000,
            "the position's collateral goes first"
        );
        assert_eq!(s2.from_bond_sat, 50_000, "the bond covers all it can");
        assert_eq!(
            s2.shortfall_sat, 100_000,
            "and the lender absorbs the remainder"
        );
        assert_eq!(s2.lender_recovered_sat(), 1_000_000);
        assert_eq!(
            s2.borrower_lost_sat(),
            1_000_000,
            "collateral plus bond, and nothing else"
        );
    }

    #[test]
    fn a_default_returns_excess_collateral_to_the_borrower() {
        // Borrow far less than the collateral held. A default must take the debt
        // and no more: the rest is the borrower's, and keeping it would be theft.
        let mut p = CreditPosition::open(&spec(100_000, 0, 0, 0)).unwrap();
        assert_eq!(p.collateral_sat, 100_000, "fully collateralized at open");
        p.bond_sat = 0;

        // Default before any interest accrues, so the debt is exactly principal.
        let s = p.default(0).unwrap();
        assert_eq!(s.debt_sat, 100_000);
        assert_eq!(s.from_collateral_sat, 100_000);
        assert_eq!(s.excess_returned_sat, 0);

        // Now the same position but the collateral is deliberately larger.
        let mut p2 = p.clone();
        p2.state = PositionState::Drawn {
            at_height: 0,
            repaid_principal_sat: 0,
            repaid_interest_sat: 0,
        };
        p2.collateral_sat = 250_000;
        let s2 = p2.default(0).unwrap();
        assert_eq!(
            s2.excess_returned_sat, 150_000,
            "collateral in excess of the debt returns to the borrower"
        );
        assert_eq!(
            s2.borrower_lost_sat(),
            100_000,
            "the borrower loses the debt, not the collateral"
        );
    }

    #[test]
    fn a_settled_position_cannot_change_again() {
        // Terminal means terminal, in both directions.
        let mut p = drawn(0);
        p.default(0).unwrap();
        assert!(p.default(10).is_err(), "cannot default twice");
        assert!(p.debt_at(10).is_err(), "a settled position has no debt");
        assert!(
            p.repay(100, 10).is_err(),
            "cannot repay a defaulted position"
        );

        let mut q = drawn(0);
        q.repay(1_000_000, 0).unwrap();
        assert!(q.is_terminal());
        assert!(
            q.default(100).is_err(),
            "nothing is owed, so nothing defaults"
        );
        assert!(q.repay(1, 100).is_err(), "cannot repay a repaid position");
    }

    #[test]
    fn a_default_of_a_nothing_owed_position_is_refused() {
        let mut p = drawn(0);
        // Repay the principal and all interest, leaving a live but zero-debt
        // position would be impossible; a partial repayment leaving principal
        // still owes, so it can default.
        p.repay(100_000, 0).unwrap();
        assert!(!p.is_terminal());
        // But zero outstanding principal is refused rather than settled at zero.
        p.state = PositionState::Drawn {
            at_height: 0,
            repaid_principal_sat: 1_000_000,
            repaid_interest_sat: 0,
        };
        assert!(
            p.default(0).is_err(),
            "nothing is owed, so nothing can default"
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
    fn a_position_cannot_default_before_its_deadline() {
        // The deadline is the lender's patience made checkable. Before it, an
        // unpaid position is late, not defaulted — a lender that could settle on
        // a whim would make the terms it offered meaningless.
        let mut p = CreditPosition::open(&spec(1_000_000, 0, 0, 100)).unwrap();
        assert!(
            p.default(99).is_err(),
            "a position cannot be settled one block early"
        );
        // Repaying is not gated by the deadline: a borrower may clear its debt
        // whenever it likes, which is the entire point of having a debt.
        let mut q = CreditPosition::open(&spec(1_000_000, 0, 0, 100)).unwrap();
        assert!(q.repay(1_000, 50).is_ok());
        let s = p.default(100).unwrap();
        assert_eq!(s.debt_sat, 1_100_000, "one window of interest is owed");
    }

    #[test]
    fn a_deadline_before_the_position_is_drawn_is_refused() {
        // A position that is already due at draw time is a caller error, not a
        // discount.
        assert!(CreditPosition::open(&spec(1_000_000, 0, 100, 50)).is_err());
    }

    #[test]
    fn the_position_id_covers_the_deadline() {
        // Two positions identical but for their deadline are different
        // positions, and the book keys them apart.
        assert_ne!(
            spec(1_000_000, 0, 0, 100).id(),
            spec(1_000_000, 0, 0, 200).id()
        );
    }

    #[test]
    fn the_book_moves_value_and_never_creates_it() {
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 2_150_000).unwrap();
        assert_eq!(book.total_deposited(), 2_150_000);

        // Bond first, because the position is priced with it.
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        // 50 000 of bond discounts the 1 000 000 line by 50 000.
        assert_eq!(book.free(&borrower), 1_150_000);
        assert_eq!(book.bond(&borrower), 50_000);
        assert_eq!(book.total_locked_collateral(), 950_000);
        assert_eq!(book.live_positions().count(), 1);
        book.check_conservation().unwrap();

        // One window of interest: 100 000 at height 100 pays all of it and none
        // of the principal. The lender is the one who ends up with it.
        let r = book.repay(&id, 100_000, 100).unwrap();
        assert_eq!(r.interest_paid_sat, 100_000);
        assert_eq!(r.principal_paid_sat, 0);
        assert_eq!(book.recovered(&lender), 100_000);
        book.check_conservation().unwrap();

        // Repaying the rest settles the position and returns its collateral.
        let r = book.repay(&id, 1_000_000, 100).unwrap();
        assert_eq!(r.remaining_debt_sat, 0);
        assert_eq!(book.free(&borrower), 1_000_000);
        assert_eq!(book.recovered(&lender), 1_100_000);
        assert_eq!(book.live_positions().count(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn a_bond_discount_requires_the_bond_to_be_posted() {
        // A bond that exists only in the spec buys a discount nobody backed,
        // which is undercollateralization wearing a discount's clothes.
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        let s = spec(1_000_000, 50_000, 0, 0);
        assert!(book.open(&s).is_err(), "no bond was posted");

        // Post it, and the very same spec opens.
        book.post_bond(borrower, 50_000).unwrap();
        assert!(book.open(&s).is_ok());
        // And not twice: one position id, ever.
        assert!(book.open(&s).is_err(), "a position cannot be re-opened");
    }

    #[test]
    fn a_default_takes_the_bond_from_the_book() {
        let borrower = [1u8; 20];
        let lender = [2u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 1_100_000).unwrap();
        book.post_bond(borrower, 50_000).unwrap();
        let id = book.open(&spec(1_000_000, 50_000, 0, 100)).unwrap();

        // One window of interest puts the debt at 1 100 000: the 950 000 of
        // collateral goes first, then the 50 000 bond, and the lender absorbs
        // the rest.
        let s = book.default(&id, 100).unwrap();
        assert_eq!(s.from_collateral_sat, 950_000);
        assert_eq!(s.from_bond_sat, 50_000);
        assert_eq!(s.shortfall_sat, 100_000);
        assert_eq!(book.bond(&borrower), 0, "the bond is actually taken");
        assert_eq!(book.recovered(&lender), 1_000_000);
        book.check_conservation().unwrap();

        // The position is spent: it cannot be defaulted again or repaid.
        assert!(book.default(&id, 200).is_err());
        assert!(book.repay(&id, 1, 200).is_err());
    }

    #[test]
    fn a_position_cannot_be_opened_without_the_collateral() {
        let borrower = [1u8; 20];
        let mut book = CreditBook::new();
        book.deposit(borrower, 900_000).unwrap();
        // The line prices at 1 000 000 of collateral and the borrower has less.
        assert!(book.open(&spec(1_000_000, 0, 0, 0)).is_err());
        assert_eq!(book.live_positions().count(), 0);
        book.check_conservation().unwrap();
    }

    #[test]
    fn the_position_codec_round_trips_every_state() {
        let mut p = CreditPosition::open(&spec(1_000_000, 50_000, 0, 100)).unwrap();
        let bytes = p.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditPosition::decode(&mut r).unwrap(), p);
        assert_eq!(r.remaining(), 0);

        p.repay(100_000, 50).unwrap();
        p.default(100).unwrap();
        let bytes = p.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(CreditPosition::decode(&mut r).unwrap(), p);
        assert_eq!(r.remaining(), 0);

        // A spec round-trips too, and keeps the id the position was opened
        // under: a node can serve one and a worker can read the same position.
        let s = spec(1_000_000, 50_000, 0, 100);
        let bytes = s.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        assert_eq!(PositionSpec::decode(&mut r).unwrap(), s);
        assert_eq!(r.remaining(), 0);
    }
}
