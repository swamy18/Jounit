//! VWC observation (Phase 4 certificates, SPEC.md §17; SDK rules §18.1/§18.13).
//!
//! A certificate is a derived consequence of a settlement (§17.4): the SDK
//! can *observe and validate* one — against the same validator the protocol
//! uses, over the same registry — but there is no claim, request or issuance
//! path, and none will be invented. "Does this worker hold a cert for task
//! T?" is a pure question of authoritative state.

use srct_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use srct_core::hash::{Address, Hash};
use srct_l2::error::L2Error;
use srct_l2::state::L2State;
use srct_l2::vwc::VerifiedWorkCertificate;

use crate::error::{WorkerError, WorkerResult};

/// Observe the certificate issued for `task_id`, validating it against live
/// state (§17.6 checks 1–4, reusing `L2State::validate_vwc` verbatim).
///
/// Returns `Ok(None)` while the task has not settled (`Correct` certificates
/// exist only after settlement, `Fraudulent`/`Expired` settle without one);
/// a certificate that fails validation is an error, never a silent
/// downgrade — a tampered receipt must not pass for income.
///
/// **What the returned certificate is and is not.** It is genuine and this state
/// really did settle that task. Whether it verifies the *result* is a separate
/// question, and the honest answer can be no: a worker may submit a wrong
/// result, go unchallenged through the dispute window, get paid, and hold a
/// `WindowElapsed` certificate. Check
/// [`VerifiedWorkCertificate::asserts_correctness`] before treating it as
/// evidence the computation was right — or call
/// [`observe_verified_certificate`], which refuses the weak basis outright.
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

/// Observe the certificate for `task_id` **only if it verifies its result**.
///
/// The entry point for a caller about to act on a compute result — paying for
/// it, publishing it, or chaining work onto it. Unlike
/// [`observe_certificate`], a certificate that rests on an unchallenged dispute
/// window is an error rather than a returned receipt, because such a
/// certificate says nobody objected in time and nothing about whether the
/// result is correct. A worker who submits a wrong result and is not
/// challenged genuinely holds one.
///
/// `Ok(None)` still means "not settled as Correct". The refusal is the third
/// state, and it is the one `observe_certificate` cannot express.
pub fn observe_verified_certificate(
    state: &L2State,
    task_id: &Hash,
    validators: &ValidatorSet,
    verifier: &dyn BlsVerifier,
) -> WorkerResult<Option<VerifiedWorkCertificate>> {
    let Some(cert) = observe_certificate(state, task_id, validators, verifier)? else {
        return Ok(None);
    };
    if !cert.asserts_correctness() {
        return Err(WorkerError::Protocol(L2Error::VwcInvalid(
            "certificate rests on an unchallenged dispute window, which is not verification: \
             nobody disputed the result in time, which says nothing about whether it is correct",
        )));
    }
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
///
/// A re-export of the one definition in `srct_l2::vwc`, not a second
/// implementation (§18.1). `false` means "rests on nobody having disputed it",
/// not "invalid" — and an unchallenged **wrong** result does reach this state,
/// which is why `observe_certificate` refuses to present one as verified.
pub fn is_offline_verifiable(cert: &VerifiedWorkCertificate) -> bool {
    cert.verification.is_offline_verifiable()
}
