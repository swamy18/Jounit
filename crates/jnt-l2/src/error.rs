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
    /// The settle payload names a network this state does not belong to. The
    /// aggregate is bound to its network, so a cross-chain replay fails here
    /// by name rather than by a pairing mismatch.
    BadSettleNetwork,
    /// The settle payload claims a vote height above the applying height. A
    /// quorum formed at `H` may settle at `H+1`, but never from the future.
    BadSettleHeight,
    /// The settle lattice sidecar failed clause-7-shape verification: the
    /// detail names the signer index and the rule. See `validators::check_sidecar`.
    BadPqSidecar(String),
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
    /// The L2 genesis allocation was applied twice. Genesis funding happens
    /// exactly once per state construction (SPEC.md §19.4); a second
    /// application would duplicate every grant, so it is refused by name.
    GenesisAlreadyApplied,
    /// A genesis allocation is structurally invalid (duplicate grantee, grant
    /// to the escrow identity). The reason is stated.
    InvalidGenesis(&'static str),
    /// A deposit `(txid, output_index)` already credited. The same L1 bytes in
    /// a later block pay once; the second occurrence is refused by name
    /// (Decision 10 item 5).
    DuplicateDeposit,
    /// Exits are not active on this state: the profile never activates them
    /// (`exit_activation_height == 0`) or the queue height predates
    /// activation. Queueing would encumber funds with no release.
    ExitNotActive,
    /// The exit's prepaid release fee is below `MIN_EXIT_FEE_SAT`. A zero or
    /// dust fee pays nobody to file the L1 release, so the exit would never be
    /// claimed — refused at queue time instead.
    ExitFeeBelowMinimum,
    /// An exit nonce that repeats or rewinds the owner's last queue nonce.
    /// Nonces are strictly increasing per owner (approved P1 replay rule).
    BadExitNonce,
    /// No queued exit for this `(owner, nonce)` — never queued, or already
    /// released (release removes the record, so a spent exit has no leaf and
    /// no second release).
    UnknownExit,
    /// A codec failure raised by `jnt-core`.
    Codec(jnt_core::Error),
    /// A reputation derivation refused a canonical artifact (roadmap item 9).
    /// The reason is the underlying ledger clause, stated.
    Reputation(String),
    /// A spending-policy rule refused the transaction. The reason is stated, so
    /// a caller learns *which* clause bound it rather than only that it did not.
    Policy(String),
    /// The transaction names the wrong grant, the wrong spender or the wrong
    /// agent: a binding mismatch rather than a limit.
    PolicyBinding(&'static str),
    /// No published grant with this hash, or none for this agent.
    UnknownPolicy,
    /// The agent already has a live grant. An agent has exactly one grant at a
    /// time, so a second one cannot be used to double the caps the first one
    /// grants.
    PolicyAlreadyPublished,
    /// The grant is revoked, or it descends from a revoked grant. The owner's
    /// kill switch reaches every descendant without a separate revocation per
    /// link.
    PolicyRevoked,
    /// A cap bound the spend: per transaction, or cumulative inside the window.
    PolicyLimit(&'static str),
    /// The recipient is not on the grant's allow-list. An empty allow-list
    /// allows nothing, which is the safe reading of an empty list.
    PolicyRecipient,
    /// The service tag is not on the grant's allow-list, or the grant names
    /// services and the spend named none.
    PolicyService,
    /// The nonce repeats or rewinds the grant's last nonce. Nonces are strictly
    /// increasing per grant.
    PolicyNonce,
    /// The grant is not usable at this height: not yet valid, expired, or the
    /// height ran backwards inside the grant.
    PolicyWindow(&'static str),
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
            L2Error::BadSettleNetwork => {
                write!(f, "settle payload is for another network")
            }
            L2Error::BadSettleHeight => {
                write!(f, "settle vote height is above the applying height")
            }
            L2Error::BadPqSidecar(why) => write!(f, "settle lattice sidecar refused: {why}"),
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
            L2Error::GenesisAlreadyApplied => {
                write!(f, "l2 genesis allocation already applied")
            }
            L2Error::InvalidGenesis(why) => write!(f, "invalid l2 genesis: {why}"),
            L2Error::DuplicateDeposit => write!(f, "deposit already credited"),
            L2Error::ExitNotActive => write!(f, "exits are not active at this height"),
            L2Error::ExitFeeBelowMinimum => {
                write!(f, "exit fee is below the protocol minimum")
            }
            L2Error::BadExitNonce => write!(f, "exit nonce repeats or rewinds"),
            L2Error::UnknownExit => write!(f, "no such queued exit"),
            L2Error::Codec(e) => write!(f, "codec: {e}"),
            L2Error::Reputation(w) => write!(f, "reputation: {w}"),
            L2Error::Policy(w) => write!(f, "policy refused: {w}"),
            L2Error::PolicyBinding(w) => write!(f, "policy binding: {w}"),
            L2Error::UnknownPolicy => write!(f, "no such published policy"),
            L2Error::PolicyAlreadyPublished => {
                write!(f, "the agent already has a live published policy")
            }
            L2Error::PolicyRevoked => write!(f, "the policy is revoked"),
            L2Error::PolicyLimit(w) => write!(f, "policy limit: {w}"),
            L2Error::PolicyRecipient => write!(f, "recipient is not on the policy allow-list"),
            L2Error::PolicyService => write!(f, "service is not on the policy allow-list"),
            L2Error::PolicyNonce => write!(f, "policy nonce repeats or rewinds"),
            L2Error::PolicyWindow(w) => write!(f, "policy window: {w}"),
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
