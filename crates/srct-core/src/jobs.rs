//! Agent-to-agent job escrow: hire, verify, release — or hold on dispute.
//!
//! A research agent hires a data agent: the payment locks in a
//! [`ConditionalEscrow`](crate::escrow::ConditionalEscrow), the worker
//! delivers a result (hash + signed receipt), and the hirer (or the
//! arbitrator) releases exactly against that result. On dispute the funds
//! stay locked: the node refuses release, settlement and auto-refund while
//! the job is held, until the arbitrator resolves to pay or refund.
//!
//! This module is the pure state machine (`JobRecord` + transitions). The
//! coin still moves through the existing escrow open/release/settle path;
//! the node adds the hold set and the job book around it.

use crate::hash::{sha256_dom, Address, Hash};

/// Domain tag for a job id.
pub const DOM_JOB: &[u8] = b"srct/agent-job/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Offered,
    Accepted,
    Delivered,
    Released,
    Disputed,
    ResolvedRelease,
    ResolvedRefund,
    Expired,
}

impl JobState {
    pub fn as_u8(self) -> u8 {
        match self {
            JobState::Offered => 0,
            JobState::Accepted => 1,
            JobState::Delivered => 2,
            JobState::Released => 3,
            JobState::Disputed => 4,
            JobState::ResolvedRelease => 5,
            JobState::ResolvedRefund => 6,
            JobState::Expired => 7,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(JobState::Offered),
            1 => Some(JobState::Accepted),
            2 => Some(JobState::Delivered),
            3 => Some(JobState::Released),
            4 => Some(JobState::Disputed),
            5 => Some(JobState::ResolvedRelease),
            6 => Some(JobState::ResolvedRefund),
            7 => Some(JobState::Expired),
            _ => None,
        }
    }
}

/// One hire: who, for what service, for how much, decided by whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub network_id: String,
    pub hirer: Address,
    pub worker: Address,
    pub arbitrator: crate::bls_checkpoint::BlsPublicKey,
    pub service_id: [u8; 32],
    pub amount_sat: u64,
    pub result_hash: Option<Hash>,
    pub deadline_height: u64,
    pub escrow_id: Option<Hash>,
    pub state: JobState,
}

impl JobRecord {
    pub fn id(&self) -> Hash {
        let mut result = [0u8; 32];
        if let Some(h) = self.result_hash {
            result = h;
        }
        sha256_dom(
            DOM_JOB,
            &[
                self.network_id.as_bytes(),
                &self.hirer,
                &self.worker,
                &self.arbitrator.0,
                &self.service_id,
                &self.amount_sat.to_le_bytes(),
                &result,
                &self.deadline_height.to_le_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), JobError> {
        if self.network_id.is_empty() || self.network_id.len() > 64 {
            return Err(JobError::Malformed("network id"));
        }
        if self.hirer == self.worker {
            return Err(JobError::Malformed("hirer and worker must differ"));
        }
        if self.amount_sat == 0 {
            return Err(JobError::Malformed("zero amount"));
        }
        if self.deadline_height == 0 {
            return Err(JobError::Malformed("no deadline"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    Malformed(&'static str),
    BadTransition {
        from: JobState,
        action: &'static str,
    },
    ResultMismatch,
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobError::Malformed(w) => write!(f, "malformed job: {w}"),
            JobError::BadTransition { from, action } => {
                write!(f, "job cannot {action} from state {from:?}")
            }
            JobError::ResultMismatch => write!(f, "release result does not match delivery"),
        }
    }
}

impl std::error::Error for JobError {}

/// Accept an offered job (worker commits).
pub fn accept(job: &mut JobRecord, escrow_id: Hash) -> Result<(), JobError> {
    job.validate()?;
    if job.state != JobState::Offered {
        return Err(JobError::BadTransition {
            from: job.state,
            action: "accept",
        });
    }
    job.escrow_id = Some(escrow_id);
    job.state = JobState::Accepted;
    Ok(())
}

/// Record delivery of the result (worker posts hash + receipt off-chain).
pub fn deliver(job: &mut JobRecord, result_hash: Hash, height: u64) -> Result<(), JobError> {
    if job.state != JobState::Accepted {
        return Err(JobError::BadTransition {
            from: job.state,
            action: "deliver",
        });
    }
    if height > job.deadline_height {
        job.state = JobState::Expired;
        return Err(JobError::BadTransition {
            from: JobState::Expired,
            action: "deliver late",
        });
    }
    job.result_hash = Some(result_hash);
    job.state = JobState::Delivered;
    Ok(())
}

/// Release against the delivered result. Refuses a mismatched result: the
/// release pays for *this* dataset, not any dataset.
pub fn release(job: &mut JobRecord, result_hash: Hash) -> Result<(), JobError> {
    if job.state != JobState::Delivered {
        return Err(JobError::BadTransition {
            from: job.state,
            action: "release",
        });
    }
    if job.result_hash != Some(result_hash) {
        return Err(JobError::ResultMismatch);
    }
    job.state = JobState::Released;
    Ok(())
}

/// Open a dispute: funds lock until the arbitrator resolves.
pub fn dispute(job: &mut JobRecord) -> Result<(), JobError> {
    match job.state {
        JobState::Accepted | JobState::Delivered => {
            job.state = JobState::Disputed;
            Ok(())
        }
        other => Err(JobError::BadTransition {
            from: other,
            action: "dispute",
        }),
    }
}

/// Arbitrator resolves to pay the worker (optionally against a result) or
/// refund the hirer. Terminal: no further transition.
pub fn resolve(job: &mut JobRecord, pay_worker: bool) -> Result<(), JobError> {
    if job.state != JobState::Disputed {
        return Err(JobError::BadTransition {
            from: job.state,
            action: "resolve",
        });
    }
    job.state = if pay_worker {
        JobState::ResolvedRelease
    } else {
        JobState::ResolvedRefund
    };
    Ok(())
}

/// Whether the escrow funds for this job must stay locked (release, settle
/// and auto-refund are all refused while true).
pub fn funds_locked(state: JobState) -> bool {
    matches!(state, JobState::Disputed)
}

/// Domain tag for a dispute hold.
pub const DOM_JOB_DISPUTE: &[u8] = b"srct/job-dispute/v1";

/// The message a party signs to freeze a job's funds: job id + reason.
pub fn dispute_hash(job_id: &Hash, reason: &str) -> Hash {
    sha256_dom(DOM_JOB_DISPUTE, &[job_id, reason.as_bytes()])
}

/// Domain tag for an arbitrator's resolve decision.
pub const DOM_JOB_RESOLVE: &[u8] = b"srct/job-resolve/v1";

/// The message an arbitrator signs to resolve a dispute: job id, direction
/// (pay worker or refund hirer) and the result hash the decision is about
/// (zero when the decision does not hinge on a result).
pub fn resolve_hash(job_id: &Hash, pay_worker: bool, result_hash: &Hash) -> Hash {
    sha256_dom(DOM_JOB_RESOLVE, &[job_id, &[pay_worker as u8], result_hash])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> JobRecord {
        JobRecord {
            network_id: "srct/testnet".to_string(),
            hirer: [1u8; 20],
            worker: [2u8; 20],
            arbitrator: crate::bls_checkpoint::BlsPublicKey([3u8; 48]),
            service_id: [4u8; 32],
            amount_sat: 500,
            result_hash: None,
            deadline_height: 1_000,
            escrow_id: None,
            state: JobState::Offered,
        }
    }

    #[test]
    fn hire_verify_release_or_hold() {
        let mut j = job();
        accept(&mut j, [9u8; 32]).unwrap();
        deliver(&mut j, [7u8; 32], 100).unwrap();
        // Wrong result is refused: the release pays for this dataset.
        assert_eq!(release(&mut j, [8u8; 32]), Err(JobError::ResultMismatch));
        release(&mut j, [7u8; 32]).unwrap();
        assert_eq!(j.state, JobState::Released);
    }

    #[test]
    fn dispute_locks_until_resolve() {
        let mut j = job();
        accept(&mut j, [9u8; 32]).unwrap();
        dispute(&mut j).unwrap();
        assert!(funds_locked(j.state));
        assert!(release(&mut j, [7u8; 32]).is_err());
        resolve(&mut j, false).unwrap();
        assert_eq!(j.state, JobState::ResolvedRefund);
        assert!(!funds_locked(j.state));
    }
}
