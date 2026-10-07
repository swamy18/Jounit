//! VWC observation (Phase 4 certificates, SPEC.md §17; SDK rules §18.1/§18.13).
//!
//! A certificate is a derived consequence of a settlement (§17.4): the SDK
//! can *observe and validate* one — against the same validator the protocol
//! uses, over the same registry — but there is no claim, request or issuance
//! path, and none will be invented. "Does this worker hold a cert for task
//! T?" is a pure question of authoritative state.

use jnt_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use jnt_core::hash::{Address, Hash};
use jnt_l2::state::L2State;
use jnt_l2::vwc::{VerifiedWorkCertificate, VwcVerification};

use crate::error::{WorkerError, WorkerResult};

/// Observe the certificate issued for `task_id`, validating it against live
/// state (§17.6 checks 1–4, reusing `L2State::validate_vwc` verbatim).
///
/// Returns `Ok(None)` while the task has not settled (`Correct` certificates
/// exist only after settlement, `Fraudulent`/`Expired` settle without one);
/// a certificate that fails validation is an error, never a silent
/// downgrade — a tampered receipt must not pass for income.
pub fn observe_certificate(
    state: &L2State,
    task_id: &Hash,
    validators: &ValidatorSet,
    verifier: &dyn BlsVerifier,
) -> WorkerResult<Option<VerifiedWorkCertificate>> {
    // The task must exist for the question to be false-able at all; the
    // unknown case is refused rather than answered "no certificate".
    state.task(task_id).ok_or(WorkerError::UnknownTask)?;
    let cert = match state.vwc(task_id) {
        Some(c) => c.clone(),
        // `None` in the registry is simply "no `Correct` settlement (yet)"
        // (§17.4): every non-Correct path — `Fraudulent`, `Expired`, an
        // open/in-progress task — leaves the registry empty for that task.
        None => return Ok(None),
    };
    state
        .validate_vwc(&cert, validators, verifier)
        .map_err(WorkerError::Protocol)?;
    Ok(Some(cert))
}

/// Every certificate naming `worker`, sorted by task id — the worker's
/// certified-history view (§18.13). Unlike `observe_certificate` these are
/// read straight from the registry without re-validation: the protocol
/// already refused anything else at issuance, and §18.1 forbids a second
/// validation implementation. The worker binding is what this function adds.
pub fn certificates_for_worker<'a>(
    state: &'a L2State,
    worker: &Address,
) -> Vec<&'a VerifiedWorkCertificate> {
    state
        .vwcs()
        .into_iter()
        .filter(|c| &c.worker == worker)
        .collect()
}

/// Whether the certificate's verification kind makes it offline-verifiable
/// (§17.5): a relying party who needs independent proof MUST demand `Quorum`.
pub fn is_offline_verifiable(cert: &VerifiedWorkCertificate) -> bool {
    matches!(cert.verification, VwcVerification::Quorum { .. })
}
