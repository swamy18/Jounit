//! Joint L1 + L2 conservation accounting (SPEC.md §19.4–§19.5).
//!
//! This is the arithmetic that says no JNT was created anywhere. It lived inline
//! in the `jnt-node verify` command, where it could not be unit-tested and the
//! deposit-sink term could not be exercised in isolation. It is extracted here
//! because **the sink term is exactly what an L2 → L1 exit has to get right**:
//! today a deposit is counted on both sides (an unspendable L1 output and its L2
//! twin), so the joint check subtracts the sink-held total; a release would have
//! to reduce that outstanding claim by the same amount or it would double-count
//! and become an inflation primitive.
//!
//! The three checks, in order, are:
//!
//! 1. **L2 is internally closed** — everything ever released into L2 is still in
//!    one of L2's buckets (`L2State::check_conservation`).
//! 2. **L2 funding is exactly genesis plus matured deposits** — no unauthorized
//!    funding path exists.
//! 3. **Joint supply is under the cap** — L1 live plus L2 held, minus the value
//!    sitting identifiably in the deposit sink.
//!
//! Since the approved tail (`docs/decisions.md` M-A…M-E, 2026-10-09) the joint
//! ceiling is **`cumulative_issuance_sat(tip height) + escrow_ceiling_sat`**:
//! L1 can never hold more than the integral of the reward function, and L2's
//! genesis side is bounded by its own validated ceiling. `supply_cap_sat`
//! stays as a reported sanity ceiling (M-D) and is no longer the verdict.
//!
//! All three are computed once in [`conservation_report`]. Two consumers
//! render that report differently: `verify_conservation` stops at the first
//! failure (the command-line verdict), while `GET /v1/conservation` and the
//! `/metrics` gauges report every term at once (the operational view — a
//! monitor wants to know *which* check moved). One implementation, so the
//! endpoint, the exporter and `verify` can never disagree.
//!
//! Nothing here reaches `Chain::submit`: it reads state and reports.

use jnt_core::chain::Chain;

use crate::l2::NodeL2;

/// The supply terms and the bound they are compared against.
///
/// All values are satoshis. `joint_sat` is the quantity `bound_sat()` bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointSupply {
    /// Live L1 UTXO value.
    pub l1_live_sat: u64,
    /// Everything still inside L2 (accounts, locked, burned, PSCB, slash vault).
    pub l2_held_sat: u64,
    /// L1 value sitting in the deposit sink: counted by `l1_live_sat` and again
    /// by `l2_held_sat` as its credited twin, so it is subtracted once.
    pub sink_held_sat: u64,
    /// `l1_live + l2_held − sink_held`.
    pub joint_sat: u64,
    /// `cumulative_issuance_sat` at the tip height: the most L1 may hold, by
    /// the same function `Chain::apply_block` mints against.
    pub l1_bound_sat: u64,
    /// The profile's validated `escrow_ceiling_sat` (approved M-E): the most
    /// the L2 genesis side may hold.
    pub escrow_ceiling_sat: u64,
    /// The active profile's sanity ceiling (`supply_cap_sat`), retained by
    /// M-D. Reported, but **not** the joint verdict.
    pub cap_sat: u64,
}

impl JointSupply {
    /// The joint ceiling that actually binds: L1's issuance integral plus L2's
    /// escrow ceiling. Both are enforced independently; their sum is the most
    /// value the two layers may hold together.
    pub fn bound_sat(&self) -> u64 {
        self.l1_bound_sat.saturating_add(self.escrow_ceiling_sat)
    }

    /// Satoshis of headroom left under the joint bound.
    pub fn headroom_sat(&self) -> u64 {
        self.bound_sat().saturating_sub(self.joint_sat)
    }

    /// Whether the joint bound has been breached. Kept as a method so the
    /// comparison itself is unit-testable without constructing a chain that
    /// mints.
    pub fn exceeds_bound(&self) -> bool {
        self.joint_sat > self.bound_sat()
    }
}

/// Why conservation failed. Every variant names the numbers involved, so an
/// operator sees which term moved rather than a bare "conservation broken".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConservationError {
    /// L2's buckets no longer sum to what was released into L2.
    L2NotConserved {
        conservation_total: u64,
        funded_total: u64,
    },
    /// L2 released something that was not genesis funding or a matured deposit.
    L2FundingAnomaly { expected: u64, actual: u64 },
    /// L1 live plus L2 held, minus the sink, exceeded the joint bound
    /// (issuance integral plus escrow ceiling).
    JointExceedsBound { joint: u64, bound: u64 },
}

impl std::fmt::Display for ConservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConservationError::L2NotConserved {
                conservation_total,
                funded_total,
            } => write!(
                f,
                "l2 conservation broken: {conservation_total} held but {funded_total} released"
            ),
            ConservationError::L2FundingAnomaly { expected, actual } => write!(
                f,
                "l2 funding anomaly: {actual} released but genesis plus deposits is {expected}"
            ),
            ConservationError::JointExceedsBound { joint, bound } => write!(
                f,
                "joint supply exceeds its bound: {joint} > {bound} (L1 live + L2 held − sink is inflation)"
            ),
        }
    }
}

impl std::error::Error for ConservationError {}

/// Compute the terms without judging them. Read-only.
pub fn joint_supply(chain: &Chain, l2: &NodeL2) -> JointSupply {
    let l1_live_sat = chain.utxo().total_value();
    let l2_held_sat = l2.state().conservation_total();
    let sink_held_sat: u64 = chain
        .utxo()
        .outputs_for_address(&chain.params().l2_deposit_sink())
        .iter()
        .map(|(_, v)| v)
        .sum();
    JointSupply {
        l1_live_sat,
        l2_held_sat,
        sink_held_sat,
        joint_sat: l1_live_sat
            .saturating_add(l2_held_sat)
            .saturating_sub(sink_held_sat),
        l1_bound_sat: jnt_core::supply::cumulative_issuance_sat(chain.params(), chain.height()),
        escrow_ceiling_sat: chain.params().escrow_ceiling_sat,
        cap_sat: chain.params().supply_cap_sat,
    }
}

/// All three checks, with their numbers, computed once.
///
/// Plain data: every field is public and `Copy`, so the API handler, the
/// metrics exporter and the unit tests all work with the same terms rather
/// than re-deriving them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConservationReport {
    /// The four supply terms and the cap.
    pub supply: JointSupply,
    /// L2's buckets still sum to everything ever released into L2.
    pub l2_closed: bool,
    /// What L2 holds, as the funding check saw it (`conservation_total`).
    pub l2_conservation_sat: u64,
    /// What was ever released into L2 (`funded_total`).
    pub l2_funded_sat: u64,
    /// Genesis escrow plus matured deposits — what L2 was allowed to hold.
    pub l2_expected_funded_sat: u64,
}

impl ConservationReport {
    /// L2 was funded by exactly genesis plus matured deposits.
    pub fn l2_funding_ok(&self) -> bool {
        self.l2_funded_sat == self.l2_expected_funded_sat
    }

    /// The all-clear: all three checks pass.
    pub fn ok(&self) -> bool {
        self.l2_closed && self.l2_funding_ok() && !self.supply.exceeds_bound()
    }

    /// The first broken check, in the order `verify` reports them.
    pub fn first_error(&self) -> Option<ConservationError> {
        if !self.l2_closed {
            return Some(ConservationError::L2NotConserved {
                conservation_total: self.l2_conservation_sat,
                funded_total: self.l2_funded_sat,
            });
        }
        if !self.l2_funding_ok() {
            return Some(ConservationError::L2FundingAnomaly {
                expected: self.l2_expected_funded_sat,
                actual: self.l2_funded_sat,
            });
        }
        if self.supply.exceeds_bound() {
            return Some(ConservationError::JointExceedsBound {
                joint: self.supply.joint_sat,
                bound: self.supply.bound_sat(),
            });
        }
        None
    }
}

/// Compute the three checks against the live chain and L2 view. Read-only.
pub fn conservation_report(chain: &Chain, l2: &NodeL2) -> ConservationReport {
    let state = l2.state();
    ConservationReport {
        supply: joint_supply(chain, l2),
        l2_closed: state.check_conservation(),
        l2_conservation_sat: state.conservation_total(),
        l2_funded_sat: state.funded_total(),
        l2_expected_funded_sat: l2
            .genesis()
            .escrow_total_sat
            .saturating_add(state.deposited_total()),
    }
}

/// The full check: L2 closed, L2 funding accounted, joint supply under the cap.
/// Returns the terms on success so the caller can report them.
pub fn verify_conservation(chain: &Chain, l2: &NodeL2) -> Result<JointSupply, ConservationError> {
    let report = conservation_report(chain, l2);
    match report.first_error() {
        Some(e) => Err(e),
        None => Ok(report.supply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supply(joint: u64, l1_bound: u64, escrow_ceiling: u64) -> JointSupply {
        JointSupply {
            l1_live_sat: 0,
            l2_held_sat: 0,
            sink_held_sat: 0,
            joint_sat: joint,
            l1_bound_sat: l1_bound,
            escrow_ceiling_sat: escrow_ceiling,
            // The sanity ceiling is deliberately generous here so the verdict
            // is provably driven by the bound and not by this field.
            cap_sat: u64::MAX,
        }
    }

    #[test]
    fn the_bound_comparison_is_strict_and_saturating() {
        // Exactly at the bound is inside it; one satoshi over is not.
        assert!(!supply(100, 90, 10).exceeds_bound());
        assert!(supply(101, 90, 10).exceeds_bound());
        assert_eq!(supply(100, 90, 10).headroom_sat(), 0);
        assert_eq!(supply(99, 90, 10).headroom_sat(), 1);
        // An over-bound reading reports zero headroom rather than underflowing.
        assert_eq!(supply(1_000, 90, 10).headroom_sat(), 0);
        // L2's ceiling is a separate authority: the same L1 reading fails with
        // no escrow allowance and passes with the 10 JNT the genesis side holds.
        assert!(supply(100, 90, 0).exceeds_bound());
        assert!(!supply(100, 90, 10).exceeds_bound());
        assert_eq!(supply(100, 90, 10).bound_sat(), 100);
    }

    /// Build a report with chosen check outcomes and supply terms.
    fn report(
        l2_closed: bool,
        funded: u64,
        expected: u64,
        joint: u64,
        bound: u64,
    ) -> ConservationReport {
        ConservationReport {
            supply: JointSupply {
                l1_live_sat: joint,
                l2_held_sat: 0,
                sink_held_sat: 0,
                joint_sat: joint,
                l1_bound_sat: bound,
                escrow_ceiling_sat: 0,
                cap_sat: u64::MAX,
            },
            l2_closed,
            l2_conservation_sat: funded,
            l2_funded_sat: funded,
            l2_expected_funded_sat: expected,
        }
    }

    #[test]
    fn the_report_verdict_names_the_first_broken_check() {
        // Healthy: no error, funding ok, verdict ok.
        let r = report(true, 10, 10, 5, 100);
        assert!(r.ok() && r.l2_funding_ok() && r.first_error().is_none());

        // L2 not closed wins over every later check, and carries its numbers.
        let r = report(false, 11, 10, 200, 100);
        assert!(!r.ok());
        assert_eq!(
            r.first_error(),
            Some(ConservationError::L2NotConserved {
                conservation_total: 11,
                funded_total: 11,
            })
        );

        // A funding anomaly is reported before the bound is examined.
        let r = report(true, 11, 10, 5, 100);
        assert!(matches!(
            r.first_error(),
            Some(ConservationError::L2FundingAnomaly {
                expected: 10,
                actual: 11
            })
        ));

        // The joint bound is the last check.
        let r = report(true, 10, 10, 101, 100);
        assert!(matches!(
            r.first_error(),
            Some(ConservationError::JointExceedsBound {
                joint: 101,
                bound: 100
            })
        ));
    }

    #[test]
    fn conservation_errors_name_their_numbers() {
        let e = ConservationError::JointExceedsBound { joint: 5, bound: 4 };
        assert!(e.to_string().contains('5') && e.to_string().contains('4'));
        let e = ConservationError::L2FundingAnomaly {
            expected: 10,
            actual: 11,
        };
        assert!(e.to_string().contains("funding anomaly"));
    }
}
