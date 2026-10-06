//! Errors for the L2 task-contract layer.
//!
//! Deliberately its own enum rather than a reuse of `jnt_core::Error`: an L2
//! failure is not a consensus failure, and folding the two together is how an
//! L2 bug becomes indistinguishable from an L1 one. Codec failures from
//! `jnt-core` are carried through as [`L2Error::Codec`] so a malformed payload
//! still names its origin.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Error {
    /// A payload's signature did not verify, or it acted as a different address
    /// than it claimed.
    BadAuthorization,
    /// The referenced task id is not registered.
    UnknownTask,
    /// A task with this id already exists (post replay, or an id collision).
    TaskAlreadyExists,
    /// This exact transaction was already applied.
    Replay,
    /// The requested transition is illegal from the task's current state.
    IllegalTransition {
        state: &'static str,
        action: &'static str,
    },
    /// The task deadline has passed.
    TaskExpired,
    /// The dispute window has closed (or has not yet opened, for settlement).
    DisputeWindowClosed,
    /// A dispute that agrees with the submitted result is pointless and refused.
    DisputeAgreesWithResult,
    /// A field that must be positive was zero.
    ZeroAmount(&'static str),
    /// The L2 deadline and the M3 envelope expiry disagree.
    DeadlineMismatch,
    /// An attestation does not bind to the task, worker or result it is filed
    /// with.
    BadAttestation(&'static str),
    /// The settle evidence did not meet quorum, or the bitmap disagrees with the
    /// declared signer count.
    BadQuorum,
    /// The settle BLS aggregate did not verify.
    BadBlsSignature,
    /// The settle hash does not match the verdict it settles.
    BadVwcHash,
    /// Arbitration evidence is missing a required part (for example an
    /// unsigned attestation).
    EvidenceIncomplete,
    /// An attestation does not bind to the task or result it is filed with.
    EvidenceMismatch(&'static str),
    /// The reference re-execution reproduced neither claim, so no verdict can be
    /// reached and nothing is slashed.
    InconclusiveDispute,
    /// A certificate already exists for this task; a task settles once, so a
    /// second issuance is a protocol violation, never an update.
    VwcAlreadyIssued,
    /// A certificate was refused: the reason is stated, and validation always
    /// fails closed (SPEC.md §17.6).
    VwcInvalid(&'static str),
    /// An account cannot cover the required fee, deposit or escrow.
    InsufficientBalance { needed: u64, available: u64 },
    /// The held amount cannot cover the settle fee.
    AmountTooSmallForFee { available: u64, fee: u64 },
    /// A numeric total did not fit.
    Overflow,
    /// A codec failure raised by `jnt-core`.
    Codec(jnt_core::Error),
}

impl fmt::Display for L2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L2Error::BadAuthorization => write!(f, "L2 authorization failed"),
            L2Error::UnknownTask => write!(f, "unknown task"),
            L2Error::TaskAlreadyExists => write!(f, "task already exists"),
            L2Error::Replay => write!(f, "transaction already applied"),
            L2Error::IllegalTransition { state, action } => {
                write!(f, "cannot {action} while the task is {state}")
            }
            L2Error::TaskExpired => write!(f, "task deadline has passed"),
            L2Error::DisputeWindowClosed => write!(f, "dispute window is closed"),
            L2Error::DisputeAgreesWithResult => {
                write!(f, "dispute agrees with the submitted result")
            }
            L2Error::ZeroAmount(w) => write!(f, "{w} must be non-zero"),
            L2Error::DeadlineMismatch => {
                write!(f, "L2 deadline and M3 envelope expiry disagree")
            }
            L2Error::BadAttestation(w) => write!(f, "bad attestation: {w}"),
            L2Error::BadQuorum => write!(f, "settle evidence does not meet quorum"),
            L2Error::BadBlsSignature => write!(f, "settle BLS aggregate did not verify"),
            L2Error::BadVwcHash => write!(f, "settle hash does not match the verdict"),
            L2Error::EvidenceIncomplete => write!(f, "dispute evidence is incomplete"),
            L2Error::EvidenceMismatch(w) => write!(f, "dispute evidence mismatch: {w}"),
            L2Error::InconclusiveDispute => {
                write!(f, "arbitration was inconclusive; nothing to settle")
            }
            L2Error::VwcAlreadyIssued => {
                write!(
                    f,
                    "a verified-work certificate already exists for this task"
                )
            }
            L2Error::VwcInvalid(why) => write!(f, "certificate refused: {why}"),
            L2Error::InsufficientBalance { needed, available } => {
                write!(f, "insufficient balance: need {needed}, have {available}")
            }
            L2Error::AmountTooSmallForFee { available, fee } => write!(
                f,
                "held amount {available} cannot cover the {fee} sat settle fee"
            ),
            L2Error::Overflow => write!(f, "arithmetic overflow"),
            L2Error::Codec(e) => write!(f, "codec: {e}"),
        }
    }
}

impl std::error::Error for L2Error {}

impl From<jnt_core::Error> for L2Error {
    fn from(e: jnt_core::Error) -> Self {
        L2Error::Codec(e)
    }
}

pub type L2Result<T> = std::result::Result<T, L2Error>;
