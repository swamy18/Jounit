//! VWC- and settlement-backed reputation (roadmap item 9).
//!
//! [`ReputationLedger::commit`](jnt_core::reputation::ReputationLedger::commit)
//! is deliberately low-level: it trusts the caller to have verified the
//! artifact its `source` names. This module is the in-repo caller for the two
//! L2-backed kinds — the ones whose backing artifact only exists here:
//!
//! - **`VerifiedWork`** — a [`VerifiedWorkCertificate`], issued when an L2
//!   settlement paid a worker for a result a quorum (or the dispute window)
//!   confirmed correct;
//! - **`DisputeWon` / `DisputeLost`** — a settled [`TaskContract`] whose
//!   outcome shows the worker either defended a challenge or lost one.
//!
//! # Derived, never consensus state
//!
//! Nothing here is stored in `L2State`. [`ledger_from_state`] *derives* the
//! ledger from the canonical state the same way a node derives L2 itself:
//! deterministically, from the artifacts the blocks already carry, in a fixed
//! order. Two nodes replaying the same chain therefore build byte-identical
//! ledgers, and a bug here can never fork the chain — it can only misreport
//! standing, which is why the integrity checks below are strict and the
//! counters are the ledger's own (an event cannot declare its magnitude).

use jnt_core::agent::{derive_agent_id, AgentRole};
use jnt_core::reputation::{AppliedEvent, ReputationKind, ReputationLedger};

use crate::error::{L2Error, L2Result};
use crate::state::L2State;
use crate::task_contract::{ContractState, TaskContract};
use crate::vwc::VerifiedWorkCertificate;

/// The subject a worker address resolves to: a **machine** identity on this
/// network, derived the same way every other identity is.
fn worker_subject(network_id: &str, worker: &[u8; 20]) -> [u8; 20] {
    derive_agent_id(network_id, AgentRole::Machine, worker)
}

/// Record a certificate as verified work for its worker.
///
/// The certificate must be internally consistent: its id is a function of its
/// body, so a certificate whose `id` does not recompute has been altered
/// since issuance and is refused. The quorum signature itself is checked where
/// the certificate enters state (the settlement path), not re-run here — this
/// function is about *who earned standing*, and it fails closed on everything
/// it can check from the certificate alone.
pub fn apply_vwc(
    ledger: &mut ReputationLedger,
    cert: &VerifiedWorkCertificate,
    network_id: &str,
) -> L2Result<AppliedEvent> {
    if ledger.network_id() != network_id {
        return Err(L2Error::Reputation("ledger is for another network".into()));
    }
    if cert.id != cert.id() {
        return Err(L2Error::VwcInvalid("certificate id does not recompute"));
    }
    if cert.worker == [0u8; 20] {
        return Err(L2Error::VwcInvalid("certificate names a zero worker"));
    }
    if cert.settled_height == 0 {
        return Err(L2Error::VwcInvalid("certificate has no settlement height"));
    }

    let subject = worker_subject(network_id, &cert.worker);
    let event = ledger
        .event_for(
            subject,
            ReputationKind::VerifiedWork,
            cert.settled_height,
            cert.id,
        )
        .map_err(reputation_error)?;
    ledger.commit(&event).map_err(reputation_error)
}

/// Record a settled task's dispute outcome, when there was one.
///
/// `Ok(None)` means the settlement shows no dispute at all, which is the
/// common case and not an error. The distinction is read from the outcome's
/// own accounting rather than guessed: a challenge that was *upheld* slashed
/// the worker's deposit (`worker_deposit_slashed > 0`), and a challenge that
/// *failed* burned the challenger's (`challenger_deposit_burned > 0`). A
/// settlement cannot show both, and if a future one did this refuses rather
/// than picking a winner.
pub fn apply_dispute_outcome(
    ledger: &mut ReputationLedger,
    task: &TaskContract,
    network_id: &str,
) -> L2Result<Option<AppliedEvent>> {
    if ledger.network_id() != network_id {
        return Err(L2Error::Reputation("ledger is for another network".into()));
    }
    let ContractState::Settled(outcome) = &task.state else {
        return Ok(None);
    };
    let Some(worker) = task.worker else {
        return Ok(None);
    };
    if worker == [0u8; 20] {
        return Err(L2Error::Reputation(
            "settled task names a zero worker".into(),
        ));
    }

    let worker_lost = outcome.worker_deposit_slashed > 0;
    let worker_won = outcome.challenger_deposit_burned > 0;
    if worker_lost && worker_won {
        return Err(L2Error::Reputation(
            "settlement shows both a won and a lost dispute".into(),
        ));
    }
    let kind = if worker_lost {
        ReputationKind::DisputeLost
    } else if worker_won {
        ReputationKind::DisputeWon
    } else {
        return Ok(None);
    };

    let subject = worker_subject(network_id, &worker);
    let event = ledger
        .event_for(subject, kind, outcome.at_height, task.task_id)
        .map_err(reputation_error)?;
    ledger.commit(&event).map_err(reputation_error).map(Some)
}

/// Derive the whole ledger from canonical L2 state.
///
/// Order is fixed (certificates by id, then tasks by id) so two nodes over the
/// same state produce identical accumulator chains. A refusal on any single
/// artifact is an error rather than a partial ledger — a reputation view that
/// silently dropped the event it could not read would be worse than none.
pub fn ledger_from_state(state: &L2State, network_id: &str) -> L2Result<ReputationLedger> {
    let mut ledger = ReputationLedger::new(network_id);

    let mut vwcs: Vec<&VerifiedWorkCertificate> = state.vwcs();
    vwcs.sort_by_key(|c| c.id);
    for cert in vwcs {
        apply_vwc(&mut ledger, cert, network_id)?;
    }

    let mut tasks: Vec<&TaskContract> = state.tasks();
    tasks.sort_by_key(|t| t.task_id);
    for task in tasks {
        apply_dispute_outcome(&mut ledger, task, network_id)?;
    }

    Ok(ledger)
}

/// Reputation refusals map to one L2 error, named with the underlying clause so
/// a refusal can be asserted by name without a second error tree.
fn reputation_error(e: jnt_core::reputation::ReputationError) -> L2Error {
    L2Error::Reputation(e.to_string())
}
