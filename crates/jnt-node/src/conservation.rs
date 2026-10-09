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
//! Nothing here reaches `Chain::submit`: it reads state and reports.

use jnt_core::chain::Chain;

use crate::l2::NodeL2;

/// The four supply terms and the cap they are compared against.
///
/// All values are satoshis. `joint_sat` is the quantity the cap bounds.
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
    /// The active profile's supply cap.
    pub cap_sat: u64,
}

impl JointSupply {
    /// Satoshis of headroom left under the cap.
    pub fn headroom_sat(&self) -> u64 {
        self.cap_sat.saturating_sub(self.joint_sat)
    }

    /// Whether the cap has been breached. Kept as a method so the comparison
    /// itself is unit-testable without constructing a chain that mints.
    pub fn exceeds_cap(&self) -> bool {
        self.joint_sat > self.cap_sat
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
    /// L1 live plus L2 held, minus the sink, exceeded the supply cap.
    JointExceedsCap { joint: u64, cap: u64 },
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
            ConservationError::JointExceedsCap { joint, cap } => write!(
                f,
                "joint supply exceeds the cap: {joint} > {cap} (L1 live + L2 held − sink is inflation)"
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
        cap_sat: chain.params().supply_cap_sat,
    }
}

/// The full check: L2 closed, L2 funding accounted, joint supply under the cap.
/// Returns the terms on success so the caller can report them.
pub fn verify_conservation(chain: &Chain, l2: &NodeL2) -> Result<JointSupply, ConservationError> {
    let state = l2.state();
    if !state.check_conservation() {
        return Err(ConservationError::L2NotConserved {
            conservation_total: state.conservation_total(),
            funded_total: state.funded_total(),
        });
    }
    let expected = l2
        .genesis()
        .escrow_total_sat
        .saturating_add(state.deposited_total());
    if state.funded_total() != expected {
        return Err(ConservationError::L2FundingAnomaly {
            expected,
            actual: state.funded_total(),
        });
    }
    let supply = joint_supply(chain, l2);
    if supply.exceeds_cap() {
        return Err(ConservationError::JointExceedsCap {
            joint: supply.joint_sat,
            cap: supply.cap_sat,
        });
    }
    Ok(supply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supply(joint: u64, cap: u64) -> JointSupply {
        JointSupply {
            l1_live_sat: 0,
            l2_held_sat: 0,
            sink_held_sat: 0,
            joint_sat: joint,
            cap_sat: cap,
        }
    }

    #[test]
    fn the_cap_comparison_is_strict_and_saturating() {
        // Exactly at the cap is inside it; one satoshi over is not.
        assert!(!supply(100, 100).exceeds_cap());
        assert!(supply(101, 100).exceeds_cap());
        assert_eq!(supply(100, 100).headroom_sat(), 0);
        assert_eq!(supply(99, 100).headroom_sat(), 1);
        // An over-cap reading reports zero headroom rather than underflowing.
        assert_eq!(supply(1_000, 100).headroom_sat(), 0);
    }

    #[test]
    fn conservation_errors_name_their_numbers() {
        let e = ConservationError::JointExceedsCap { joint: 5, cap: 4 };
        assert!(e.to_string().contains('5') && e.to_string().contains('4'));
        let e = ConservationError::L2FundingAnomaly {
            expected: 10,
            actual: 11,
        };
        assert!(e.to_string().contains("funding anomaly"));
    }
}
