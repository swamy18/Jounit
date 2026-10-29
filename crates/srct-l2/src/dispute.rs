//! Dispute evidence and arbitration (Phase 3).
//!
//! A challenge puts two results in front of the arbitrator set: the worker's
//! `submitted_result` and the challenger's `counter_result`. This module turns
//! those, plus a reference re-execution (SPEC.md §16), into a verdict **without
//! creating a second task system**: it reads a `TaskContract`, and its output is
//! a `SettlePayload` that the existing settlement path already knows how to
//! apply. Escrow, fees, slashing and the PSCB all stay where Phase 2 put them.
//!
//! The engine is deliberately narrow, and deliberately pure:
//!
//! - It does not execute the task. It compares result *hashes*. Producing the
//!   reference hash is the arbitrator set's off-chain job (§16.4), the same way
//!   signing a checkpoint is.
//! - It does not verify BLS. Quorum is what *authorizes* a decision, and that
//!   check already lives in `L2State::apply_settle`.
//! - It does not move value. A verdict names the hash a settlement must carry;
//!   `TaskContract::settle` decides what that settlement pays.
//!
//! The rule itself is one comparison, and that is the point:
//!
//! ```text
//! reference == submitted  -> WorkerCorrect   (settles as Correct)
//! reference == counter    -> ChallengerCorrect (settles as Fraudulent)
//! reference == neither    -> Inconclusive    (settles nothing)
//! ```
//!
//! `Inconclusive` is not a verdict and is not a wire value. It exists because
//! the honest outcome of "the reference could not reproduce either claim" must
//! be that nobody is slashed — a malformed or unexecutable task must not become a
//! fraud conviction by default.

use srct_core::compute_ir::ComputeAttestation;
use srct_core::hash::Hash;
use srct_core::l2::{SettlePayload, Verdict};

use crate::error::{L2Error, L2Result};
use crate::task_contract::{ContractState, TaskContract};

/// The two competing claims for one task, each with its attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeEvidence {
    pub task_id: Hash,
    pub submitted_result: Hash,
    pub submitted_attestation: ComputeAttestation,
    pub counter_result: Hash,
    pub counter_attestation: ComputeAttestation,
}

impl DisputeEvidence {
    /// Read the evidence out of a disputed task.
    pub fn from_contract(contract: &TaskContract) -> L2Result<Self> {
        match &contract.state {
            ContractState::Disputed(c) => Ok(DisputeEvidence {
                task_id: contract.task_id,
                submitted_result: c.against_result,
                submitted_attestation: c.against_attestation.clone(),
                counter_result: c.counter_result,
                counter_attestation: c.counter_attestation.clone(),
            }),
            _ => Err(L2Error::IllegalTransition {
                state: contract.state.name(),
                action: "read arbitration evidence",
            }),
        }
    }

    /// Validate the evidence structurally, before it is arbitrated.
    ///
    /// Every failure is named, because "the dispute was refused" is useless to
    /// the party that filed it while "the counter attestation names a different
    /// task" is actionable. The two results must differ: a challenge that agrees
    /// with the submitted result is not a dispute.
    pub fn validate(&self) -> L2Result<()> {
        if self.counter_result == self.submitted_result {
            return Err(L2Error::DisputeAgreesWithResult);
        }
        if self.submitted_attestation.task_id != self.task_id {
            return Err(L2Error::EvidenceMismatch("submitted attestation task_id"));
        }
        if self.submitted_attestation.result_hash != self.submitted_result {
            return Err(L2Error::EvidenceMismatch("submitted attestation result"));
        }
        if self.counter_attestation.task_id != self.task_id {
            return Err(L2Error::EvidenceMismatch("counter attestation task_id"));
        }
        if self.counter_attestation.result_hash != self.counter_result {
            return Err(L2Error::EvidenceMismatch("counter attestation result"));
        }
        if self.submitted_attestation.signature.is_empty() {
            return Err(L2Error::EvidenceIncomplete);
        }
        if self.counter_attestation.signature.is_empty() {
            return Err(L2Error::EvidenceIncomplete);
        }
        Ok(())
    }
}

/// What the reference re-execution decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arbiter {
    /// The reference reproduced the worker's result.
    WorkerCorrect,
    /// The reference reproduced the challenger's result.
    ChallengerCorrect,
    /// The reference reproduced neither, so no verdict can be reached.
    Inconclusive,
}

/// The outcome of arbitration: what was decided, and on what hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeVerdict {
    pub task_id: Hash,
    pub arbiter: Arbiter,
    pub re_execution_result: Hash,
}

impl DisputeVerdict {
    /// The wire verdict, or `None` when the arbitration was inconclusive.
    pub fn verdict(&self) -> Option<Verdict> {
        match self.arbiter {
            Arbiter::WorkerCorrect => Some(Verdict::Correct),
            Arbiter::ChallengerCorrect => Some(Verdict::Fraudulent),
            Arbiter::Inconclusive => None,
        }
    }

    /// The hash a settlement must carry for this verdict.
    ///
    /// Always the reference result: on `WorkerCorrect` the reference *is* the
    /// submitted result, and on `ChallengerCorrect` it *is* the counter-result.
    /// `None` for an inconclusive arbitration, which settles nothing.
    pub fn vwc_hash(&self) -> Option<Hash> {
        self.verdict().map(|_| self.re_execution_result)
    }

    /// Build the `SettlePayload` the arbitrator quorum votes on.
    ///
    /// This is the seam between arbitration and settlement: the engine decides,
    /// and the existing `Settle` path applies. An inconclusive arbitration has
    /// no payload to vote on, and asking for one is an error rather than an
    /// empty transaction.
    ///
    /// The caller names the chain and height the quorum signed for, because the
    /// aggregate binds both: a payload without them would verify on any chain.
    pub fn settle_payload(
        &self,
        network_id: &str,
        height: u64,
        bls_sig: [u8; 96],
        signer_bitmap: Vec<u8>,
        signer_count: u32,
        pq_sidecar: Vec<srct_core::bls_checkpoint::PqSidecarEntry>,
    ) -> L2Result<SettlePayload> {
        let verdict = self.verdict().ok_or(L2Error::InconclusiveDispute)?;
        Ok(SettlePayload {
            task_id: self.task_id,
            verdict,
            vwc_hash: self.re_execution_result,
            network_id: network_id.to_string(),
            height,
            bls_sig,
            signer_bitmap,
            signer_count,
            pq_sidecar,
        })
    }
}

/// The arbitration decision procedure. Pure and total: same inputs, same verdict.
///
/// `arbitrate` validates the evidence first, so a malformed pair can never
/// produce a verdict that would slash a worker. That ordering is the safety
/// property: validation failure and inconclusiveness are both *failures to
/// convict*, never defaults to guilt.
pub struct DisputeEngine;

impl DisputeEngine {
    pub fn arbitrate(
        evidence: &DisputeEvidence,
        re_execution_result: Hash,
    ) -> L2Result<DisputeVerdict> {
        evidence.validate()?;
        // `validate` guarantees the two results differ, so these are disjoint.
        let arbiter = if re_execution_result == evidence.submitted_result {
            Arbiter::WorkerCorrect
        } else if re_execution_result == evidence.counter_result {
            Arbiter::ChallengerCorrect
        } else {
            Arbiter::Inconclusive
        };
        Ok(DisputeVerdict {
            task_id: evidence.task_id,
            arbiter,
            re_execution_result,
        })
    }

    /// Read the evidence from a contract, run the canonical CPU reference over
    /// the committed task, and arbitrate (Decision 21 — P3).
    ///
    /// The reference is computed here, never supplied by the caller: taking
    /// it as a parameter would let any caller dictate the verdict. SPEC
    /// §16.4's shape is preserved — the engine still only compares hashes;
    /// the pure reference function is data, not a runtime, and no IR is
    /// interpreted.
    pub fn resolve(contract: &TaskContract) -> L2Result<DisputeVerdict> {
        let evidence = DisputeEvidence::from_contract(contract)?;
        // Rule 3 of the predicate discipline: the reference is computed here,
        // from the contract's own committed deliverable, and is never supplied
        // by a caller. Reading it off the deliverable rather than from the
        // compute-specific fields is what keeps this one path for every kind of
        // deliverable - there is no second, compute-only arbitration.
        let reference = contract.reference();
        Self::arbitrate(&evidence, reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use srct_core::compute_ir::ComputeBackend;

    const TASK: Hash = [0x11u8; 32];
    const SUBMITTED: Hash = [0xAAu8; 32];
    const COUNTER: Hash = [0xBBu8; 32];

    fn attestation(task_id: Hash, result: Hash, sig: Vec<u8>) -> ComputeAttestation {
        ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Gpu,
            worker_address: [0x07u8; 20],
            attest_height: 0,
            signature: sig,
        }
    }

    fn evidence() -> DisputeEvidence {
        DisputeEvidence {
            task_id: TASK,
            submitted_result: SUBMITTED,
            submitted_attestation: attestation(TASK, SUBMITTED, vec![1]),
            counter_result: COUNTER,
            counter_attestation: attestation(TASK, COUNTER, vec![2]),
        }
    }

    #[test]
    fn well_formed_evidence_validates() {
        evidence().validate().unwrap();
    }

    #[test]
    fn evidence_that_agrees_is_not_a_dispute() {
        let mut e = evidence();
        e.counter_result = SUBMITTED;
        assert_eq!(e.validate(), Err(L2Error::DisputeAgreesWithResult));
    }

    #[test]
    fn each_malformed_attestation_binding_is_named() {
        let mut e = evidence();
        e.submitted_attestation.task_id = [0x99u8; 32];
        assert!(matches!(e.validate(), Err(L2Error::EvidenceMismatch(_))));

        let mut e = evidence();
        e.submitted_attestation.result_hash = [0x99u8; 32];
        assert!(matches!(e.validate(), Err(L2Error::EvidenceMismatch(_))));

        let mut e = evidence();
        e.counter_attestation.task_id = [0x99u8; 32];
        assert!(matches!(e.validate(), Err(L2Error::EvidenceMismatch(_))));

        let mut e = evidence();
        e.counter_attestation.result_hash = [0x99u8; 32];
        assert!(matches!(e.validate(), Err(L2Error::EvidenceMismatch(_))));
    }

    #[test]
    fn missing_signatures_are_incomplete_evidence() {
        let mut e = evidence();
        e.submitted_attestation.signature = vec![];
        assert_eq!(e.validate(), Err(L2Error::EvidenceIncomplete));

        let mut e = evidence();
        e.counter_attestation.signature = vec![];
        assert_eq!(e.validate(), Err(L2Error::EvidenceIncomplete));
    }

    #[test]
    fn arbitration_maps_the_reference_result_to_exactly_one_verdict() {
        let e = evidence();

        let v = DisputeEngine::arbitrate(&e, SUBMITTED).unwrap();
        assert_eq!(v.arbiter, Arbiter::WorkerCorrect);
        assert_eq!(v.verdict(), Some(Verdict::Correct));
        assert_eq!(v.vwc_hash(), Some(SUBMITTED));

        let v = DisputeEngine::arbitrate(&e, COUNTER).unwrap();
        assert_eq!(v.arbiter, Arbiter::ChallengerCorrect);
        assert_eq!(v.verdict(), Some(Verdict::Fraudulent));
        assert_eq!(v.vwc_hash(), Some(COUNTER));
    }

    #[test]
    fn a_reference_that_matches_neither_claim_is_inconclusive_and_settles_nothing() {
        // The property that stops a malformed or unexecutable task from becoming
        // a fraud conviction: no match is not guilt.
        let v = DisputeEngine::arbitrate(&evidence(), [0xCCu8; 32]).unwrap();
        assert_eq!(v.arbiter, Arbiter::Inconclusive);
        assert_eq!(v.verdict(), None);
        assert_eq!(v.vwc_hash(), None);
        assert_eq!(
            v.settle_payload("srct/mini", 4, [0u8; 96], vec![0xFF], 1, Vec::new()),
            Err(L2Error::InconclusiveDispute)
        );
    }

    #[test]
    fn malformed_evidence_is_refused_before_it_can_convict() {
        let mut e = evidence();
        e.counter_attestation.signature = vec![];
        assert_eq!(e.validate(), Err(L2Error::EvidenceIncomplete));
    }

    #[test]
    fn arbitration_is_deterministic() {
        let a = DisputeEngine::arbitrate(&evidence(), COUNTER).unwrap();
        let b = DisputeEngine::arbitrate(&evidence(), COUNTER).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_verdict_builds_the_settle_payload_the_existing_path_applies() {
        let v = DisputeEngine::arbitrate(&evidence(), COUNTER).unwrap();
        let p = v
            .settle_payload(
                "srct/mini",
                4,
                [0x7Fu8; 96],
                vec![0b0000_0111],
                3,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(p.task_id, TASK);
        assert_eq!(p.verdict, Verdict::Fraudulent);
        assert_eq!(
            p.vwc_hash, COUNTER,
            "the settle hash is the reference result"
        );
        assert_eq!(p.network_id, "srct/mini");
        assert_eq!(p.height, 4);
        assert_eq!(p.signer_count, 3);
    }
}
