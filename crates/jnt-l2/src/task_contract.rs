//! `TaskContract`: the L2 task lifecycle state machine.
//!
//! ```text
//!   Open ──claim──▶ InProgress ──submit──▶ ResultSubmitted ──dispute──▶ Disputed
//!    │                 │                        │                         │
//!    │                 │                        └─ window elapses ─▶ auto-settle Correct
//!    │                 │
//!    └─ deadline ─▶ Expired ◀─ deadline ────────┘
//! ```
//!
//! This module holds the *transitions only*: no balances, no fees, no BLS. Every
//! method either refuses an illegal transition with a named error or changes the
//! state, and nothing here can move value. The economy lives in
//! [`crate::state::L2State`], which is the only thing that debits an account and
//! the only thing that consults a validator set. That split is deliberate: it is
//! what lets the transitions be tested exhaustively without a wallet, and what
//! keeps "who pays" from being tangled with "may this happen".
//!
//! The dispute window is a protocol parameter ([`crate::L2Config`]), not a field
//! an actor chooses. A submitter who could pick their own window could pick a
//! zero-length one; a worker who could pick it could make challenges impossible.

use jnt_core::compute_ir::{ComputeAttestation, ComputeTask};
use jnt_core::fees::split_flat_fee;
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, PostTaskPayload, SubmitResultPayload, Verdict,
    VWC_HASH_EXPIRED,
};
use jnt_core::slash::VESTING_BLOCKS_MAINNET;

use crate::error::{L2Error, L2Result};

/// Protocol parameters for the L2 task layer.
///
/// All three are network-wide rather than per-task, because a value an actor
/// chooses is a value an actor can choose badly (a zero challenge window is not
/// a challenge window). `dispute_window` is how long a submitted result can be
/// challenged, and also how long a filed dispute has to be resolved;
/// `vesting_period` is the M2 vesting horizon for a fraud slash, taken from
/// `jnt_core::slash` so L2 slashing and M2 cannot drift apart;
/// `whistleblower_bounty_percent` is the share of a slashed deposit paid to a
/// successful challenger out of the PSCB reserve (SPEC.md §15.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Config {
    pub dispute_window: u64,
    pub vesting_period: u64,
    /// Whole percent, 0..=100. Not a basis-point value because the bounty is a
    /// coarse incentive, not a fee split that has to reconcile to the satoshi.
    pub whistleblower_bounty_percent: u64,
}

impl L2Config {
    /// Production values: a ~100-block (~17 hour) challenge window and the
    /// one-year M2 vesting period.
    pub fn mainnet() -> Self {
        L2Config {
            dispute_window: 100,
            vesting_period: VESTING_BLOCKS_MAINNET,
            whistleblower_bounty_percent: 25,
        }
    }

    /// The `mini` profile's shortened window, so a dispute can be resolved inside
    /// a test run. The bounty share is identical to mainnet: it is an incentive,
    /// not a timing parameter, and a test that used a different share would be
    /// testing a different rule.
    pub fn mini() -> Self {
        L2Config {
            dispute_window: 5,
            vesting_period: jnt_core::slash::VESTING_BLOCKS_MINI,
            whistleblower_bounty_percent: 25,
        }
    }
}

/// A task's lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractState {
    Open,
    InProgress {
        claimed_at: u64,
    },
    ResultSubmitted {
        result_hash: Hash,
        submitted_at: u64,
        attestation: ComputeAttestation,
    },
    Disputed(DisputeChallenge),
    Settled(SettlementOutcome),
    Expired(ExpiryOutcome),
}

impl ContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ContractState::Open => "Open",
            ContractState::InProgress { .. } => "InProgress",
            ContractState::ResultSubmitted { .. } => "ResultSubmitted",
            ContractState::Disputed(_) => "Disputed",
            ContractState::Settled(_) => "Settled",
            ContractState::Expired(_) => "Expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, ContractState::Settled(_) | ContractState::Expired(_))
    }
}

/// A filed challenge.
///
/// Both sides of the dispute are kept: `against_result` and `against_attestation`
/// are the challenged submission, and `counter_result` /
/// `counter_attestation` the challenger's answer. That makes a `Disputed`
/// contract self-describing, so the arbitration engine can read complete
/// evidence from the contract alone rather than reaching back into a prior
/// state the contract no longer carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeChallenge {
    pub challenger: Address,
    pub against_result: Hash,
    pub against_attestation: ComputeAttestation,
    pub counter_result: Hash,
    pub counter_attestation: ComputeAttestation,
    pub deposit_sat: u64,
    pub filed_at: u64,
}

/// The value movements a settlement implies.
///
/// Named fields rather than a netted number on purpose: a caller (or an auditor)
/// has to be able to see *why* value moved. Every field is applied by
/// `L2State::apply_settle`; none of them are applied here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SettlementOutcome {
    pub verdict: Verdict,
    /// Escrow paid to the worker minus the settle fee.
    pub worker_paid: u64,
    /// Deposit returned to the worker (only when the worker was right).
    pub worker_deposit_returned: u64,
    /// Deposit routed to the M2 slash vault (fraud).
    pub worker_deposit_slashed: u64,
    /// Escrow returned to the submitter (fraud or expiry).
    pub submitter_refunded: u64,
    /// Deposit returned to the challenger (challenge upheld).
    pub challenger_refunded: u64,
    /// Deposit destroyed because the challenge failed.
    pub challenger_deposit_burned: u64,
    /// Deposit destroyed in full (expiry, no vest).
    pub worker_deposit_burned: u64,
    pub fee_burned: u64,
    pub fee_pscb: u64,
    pub at_height: u64,
}

/// The value movements of an implicit expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpiryOutcome {
    pub submitter_refunded: u64,
    pub worker_deposit_burned: u64,
    pub at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskContract {
    pub task_id: Hash,
    pub submitter: Address,
    pub worker: Option<Address>,
    pub compute_task: ComputeTask,
    pub payment_sat: u64,
    pub worker_deposit_sat: u64,
    pub deadline_height: u64,
    pub dispute_window: u64,
    pub nonce: u64,
    pub state: ContractState,
}

impl TaskContract {
    /// Create an `Open` contract from a post.
    ///
    /// Rejects a task id that is not the derivable one, a deadline that is
    /// already in the past, a deadline that disagrees with the M3 envelope's own
    /// expiry (two deadlines for one task is an ambiguity, not a feature), and a
    /// zero payment.
    pub fn new(post: &PostTaskPayload, current_height: u64, dispute_window: u64) -> L2Result<Self> {
        if post.task_id != post.derived_task_id() {
            return Err(L2Error::BadAttestation("task_id is not the derived id"));
        }
        if post.payment_sat == 0 {
            return Err(L2Error::ZeroAmount("payment_sat"));
        }
        if post.deadline_height != post.compute_task.expiry_height {
            return Err(L2Error::DeadlineMismatch);
        }
        if post.deadline_height <= current_height {
            return Err(L2Error::TaskExpired);
        }
        if !post.compute_task.is_active(current_height) {
            return Err(L2Error::TaskExpired);
        }
        Ok(TaskContract {
            task_id: post.task_id,
            submitter: post.submitter,
            worker: None,
            compute_task: post.compute_task.clone(),
            payment_sat: post.payment_sat,
            worker_deposit_sat: 0,
            deadline_height: post.deadline_height,
            dispute_window,
            nonce: post.nonce,
            state: ContractState::Open,
        })
    }

    /// Reserve the task for `actor`.
    pub fn claim(
        &mut self,
        actor: Address,
        claim: &ClaimTaskPayload,
        current_height: u64,
    ) -> L2Result<()> {
        if !matches!(self.state, ContractState::Open) {
            return Err(self.illegal("claim"));
        }
        if claim.task_id != self.task_id || actor != claim.worker {
            return Err(L2Error::BadAuthorization);
        }
        if current_height > self.deadline_height {
            return Err(L2Error::TaskExpired);
        }
        if claim.worker_deposit_sat == 0 {
            return Err(L2Error::ZeroAmount("worker_deposit_sat"));
        }
        self.worker = Some(actor);
        self.worker_deposit_sat = claim.worker_deposit_sat;
        self.state = ContractState::InProgress {
            claimed_at: current_height,
        };
        Ok(())
    }

    /// Record the worker's result.
    ///
    /// The attestation must bind to this task, to the signing worker, and to the
    /// result hash in the same payload. Its own `signature` field is not
    /// independently verifiable (an attestation carries an address, not a key);
    /// the authoritative authentication is the enclosing `SubmitResult` payload's
    /// signature, which covers the attestation bytes.
    pub fn submit_result(
        &mut self,
        actor: Address,
        submit: &SubmitResultPayload,
        current_height: u64,
    ) -> L2Result<()> {
        if !matches!(self.state, ContractState::InProgress { .. }) {
            return Err(self.illegal("submit a result"));
        }
        if Some(actor) != self.worker || actor != submit.worker {
            return Err(L2Error::BadAuthorization);
        }
        if current_height > self.deadline_height {
            return Err(L2Error::TaskExpired);
        }
        if submit.task_id != self.task_id {
            return Err(L2Error::BadAttestation("task_id"));
        }
        if submit.attestation.task_id != self.task_id {
            return Err(L2Error::BadAttestation("attestation task_id"));
        }
        if submit.attestation.worker_address != actor {
            return Err(L2Error::BadAttestation("attestation worker_address"));
        }
        if submit.attestation.result_hash != submit.result_hash {
            return Err(L2Error::BadAttestation("attestation result_hash"));
        }
        if submit.attestation.signature.is_empty() {
            return Err(L2Error::BadAttestation("attestation is unsigned"));
        }
        self.state = ContractState::ResultSubmitted {
            result_hash: submit.result_hash,
            submitted_at: current_height,
            attestation: submit.attestation.clone(),
        };
        Ok(())
    }

    /// File a challenge against a submitted result.
    pub fn file_dispute(
        &mut self,
        actor: Address,
        dispute: &DisputePayload,
        current_height: u64,
    ) -> L2Result<()> {
        let (result_hash, submitted_at, against_attestation) = match &self.state {
            ContractState::ResultSubmitted {
                result_hash,
                submitted_at,
                attestation,
            } => (*result_hash, *submitted_at, attestation.clone()),
            _ => return Err(self.illegal("file a dispute")),
        };
        if dispute.task_id != self.task_id || actor != dispute.challenger {
            return Err(L2Error::BadAuthorization);
        }
        if current_height > submitted_at.saturating_add(self.dispute_window) {
            return Err(L2Error::DisputeWindowClosed);
        }
        if dispute.counter_result == result_hash {
            return Err(L2Error::DisputeAgreesWithResult);
        }
        if dispute.challenge_deposit_sat == 0 {
            return Err(L2Error::ZeroAmount("challenge_deposit_sat"));
        }
        if dispute.counter_attestation.task_id != self.task_id {
            return Err(L2Error::BadAttestation("counter attestation task_id"));
        }
        if dispute.counter_attestation.result_hash != dispute.counter_result {
            return Err(L2Error::BadAttestation("counter attestation result_hash"));
        }
        self.state = ContractState::Disputed(DisputeChallenge {
            challenger: actor,
            against_result: result_hash,
            against_attestation,
            counter_result: dispute.counter_result,
            counter_attestation: dispute.counter_attestation.clone(),
            deposit_sat: dispute.challenge_deposit_sat,
            filed_at: current_height,
        });
        Ok(())
    }

    /// The result hash that a `Correct` verdict must name, if this contract is
    /// currently settleable as correct.
    pub fn correct_settlement_hash(&self, current_height: u64) -> Option<Hash> {
        match &self.state {
            ContractState::ResultSubmitted {
                result_hash,
                submitted_at,
                ..
            } if current_height > submitted_at.saturating_add(self.dispute_window) => {
                Some(*result_hash)
            }
            ContractState::Disputed(c) => Some(c.against_result),
            _ => None,
        }
    }

    /// True when the dispute window has elapsed with no challenge, so the
    /// contract settles itself.
    pub fn due_for_auto_settle(&self, current_height: u64) -> bool {
        self.correct_settlement_hash(current_height).is_some()
            && matches!(self.state, ContractState::ResultSubmitted { .. })
    }

    /// Settle a `Correct` verdict with no fee. Only the implicit path (the
    /// dispute window closing) uses this; an explicit `Settle` transaction pays
    /// the D3 fee through [`TaskContract::settle`].
    pub fn auto_settle_correct(&mut self, current_height: u64) -> L2Result<SettlementOutcome> {
        let hash = self
            .correct_settlement_hash(current_height)
            .filter(|_| matches!(self.state, ContractState::ResultSubmitted { .. }))
            .ok_or_else(|| self.illegal("auto-settle"))?;
        self.settle_inner(Verdict::Correct, hash, current_height, 0)
    }

    /// True when a filed dispute has gone unresolved past its resolution window.
    ///
    /// The window is the same length as the filing window, measured from
    /// `filed_at`. A challenge that is filed and then abandoned does not stall
    /// the task forever, and it is not free: lapsing burns the challenger's
    /// deposit exactly as a lost challenge would.
    pub fn due_for_dispute_lapse(&self, current_height: u64) -> bool {
        match &self.state {
            ContractState::Disputed(c) => {
                current_height > c.filed_at.saturating_add(self.dispute_window)
            }
            _ => false,
        }
    }

    /// Apply the implicit settlement of a lapsed dispute: the submitted result
    /// stands, the challenger's deposit is burned, and no fee is charged because
    /// nothing was transacted.
    pub fn lapse_dispute(&mut self, current_height: u64) -> L2Result<SettlementOutcome> {
        let hash = match &self.state {
            ContractState::Disputed(c) if self.due_for_dispute_lapse(current_height) => {
                c.against_result
            }
            ContractState::Disputed(_) => return Err(L2Error::DisputeWindowClosed),
            _ => return Err(self.illegal("lapse a dispute")),
        };
        self.settle_inner(Verdict::Correct, hash, current_height, 0)
    }

    /// Apply a validator verdict, returning the value movements it implies.
    pub fn settle(
        &mut self,
        verdict: Verdict,
        vwc_hash: Hash,
        current_height: u64,
        fee: u64,
    ) -> L2Result<SettlementOutcome> {
        self.settle_inner(verdict, vwc_hash, current_height, fee)
    }

    fn settle_inner(
        &mut self,
        verdict: Verdict,
        vwc_hash: Hash,
        current_height: u64,
        fee: u64,
    ) -> L2Result<SettlementOutcome> {
        let escrow = self.payment_sat;
        let deposit = self.worker_deposit_sat;
        let challenge_deposit = match &self.state {
            ContractState::Disputed(c) => c.deposit_sat,
            _ => 0,
        };
        let split = split_flat_fee(fee);

        let mut outcome = SettlementOutcome {
            verdict,
            fee_burned: split.burned,
            fee_pscb: split.pscb,
            at_height: current_height,
            ..Default::default()
        };

        match verdict {
            Verdict::Correct => {
                let expected = match &self.state {
                    ContractState::ResultSubmitted { .. } => self
                        .correct_settlement_hash(current_height)
                        .ok_or(L2Error::DisputeWindowClosed)?,
                    ContractState::Disputed(c) => c.against_result,
                    _ => return Err(self.illegal("settle as Correct")),
                };
                if vwc_hash != expected {
                    return Err(L2Error::BadVwcHash);
                }
                if escrow < fee {
                    return Err(L2Error::AmountTooSmallForFee {
                        available: escrow,
                        fee,
                    });
                }
                outcome.worker_paid = escrow - fee;
                outcome.worker_deposit_returned = deposit;
                if matches!(self.state, ContractState::Disputed(_)) {
                    // The challenger was wrong: their deposit is destroyed in
                    // full, which is what makes a baseless challenge costly.
                    outcome.challenger_deposit_burned = challenge_deposit;
                }
            }
            Verdict::Fraudulent => {
                let challenge = match &self.state {
                    ContractState::Disputed(c) => c,
                    _ => return Err(self.illegal("settle as Fraudulent")),
                };
                if vwc_hash != challenge.counter_result {
                    return Err(L2Error::BadVwcHash);
                }
                if deposit < fee {
                    return Err(L2Error::AmountTooSmallForFee {
                        available: deposit,
                        fee,
                    });
                }
                outcome.submitter_refunded = escrow;
                outcome.challenger_refunded = challenge_deposit;
                // Fee comes out of the worker's deposit first: the submitter was
                // defrauded and deserves a whole refund, and the losing worker is
                // the party whose conduct created the cost.
                outcome.worker_deposit_slashed = deposit - fee;
            }
            Verdict::Expired => {
                // Expiry is normally implicit and free (`try_expire`). An explicit
                // Expired verdict exists so the arbitrator set can close a task a
                // vanished worker never delivered, and it pays the settle fee like
                // any other explicit settlement.
                match &self.state {
                    ContractState::Open | ContractState::InProgress { .. } => {}
                    _ => return Err(self.illegal("settle as Expired")),
                }
                if vwc_hash != VWC_HASH_EXPIRED {
                    return Err(L2Error::BadVwcHash);
                }
                if deposit == 0 {
                    if escrow < fee {
                        return Err(L2Error::AmountTooSmallForFee {
                            available: escrow,
                            fee,
                        });
                    }
                    outcome.submitter_refunded = escrow - fee;
                } else {
                    if deposit < fee {
                        return Err(L2Error::AmountTooSmallForFee {
                            available: deposit,
                            fee,
                        });
                    }
                    outcome.submitter_refunded = escrow;
                    // No vest for an expiry: a smaller penalty than a fraud slash.
                    outcome.worker_deposit_burned = deposit - fee;
                }
            }
        }

        self.state = ContractState::Settled(outcome);
        Ok(outcome)
    }

    /// Implicit expiry: the deadline passed with no result submitted.
    ///
    /// Returns the movements when the transition happened, `None` otherwise.
    /// No fee is charged — nothing was transacted, the clock simply ran out.
    pub fn try_expire(&mut self, current_height: u64) -> Option<ExpiryOutcome> {
        let outcome = match &self.state {
            ContractState::Open if current_height > self.deadline_height => ExpiryOutcome {
                submitter_refunded: self.payment_sat,
                worker_deposit_burned: 0,
                at_height: current_height,
            },
            ContractState::InProgress { .. } if current_height > self.deadline_height => {
                ExpiryOutcome {
                    submitter_refunded: self.payment_sat,
                    worker_deposit_burned: self.worker_deposit_sat,
                    at_height: current_height,
                }
            }
            _ => return None,
        };
        self.state = ContractState::Expired(outcome);
        Some(outcome)
    }

    /// The challenger, if one is on file. Read before settling, because a
    /// settled contract no longer carries the challenge.
    pub fn challenger(&self) -> Option<Address> {
        match &self.state {
            ContractState::Disputed(c) => Some(c.challenger),
            _ => None,
        }
    }

    /// Value still held by this contract, in satoshis.
    ///
    /// This is the contract's side of the conservation invariant: everything an
    /// account paid in and the contract has not yet released.
    pub fn locked_total(&self) -> u64 {
        match &self.state {
            ContractState::Open => self.payment_sat,
            ContractState::InProgress { .. } | ContractState::ResultSubmitted { .. } => {
                self.payment_sat.saturating_add(self.worker_deposit_sat)
            }
            ContractState::Disputed(c) => self
                .payment_sat
                .saturating_add(self.worker_deposit_sat)
                .saturating_add(c.deposit_sat),
            ContractState::Settled(_) | ContractState::Expired(_) => 0,
        }
    }

    fn illegal(&self, action: &'static str) -> L2Error {
        L2Error::IllegalTransition {
            state: self.state.name(),
            action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jnt_core::compute_ir::ComputeBackend;
    use jnt_core::l2::{derive_task_id, Auth};

    fn addr(n: u8) -> Address {
        [n; 20]
    }

    fn task_for(deadline: u64) -> ComputeTask {
        ComputeTask {
            task_id: [0x11u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 0,
            backend_hint: ComputeBackend::Cpu,
            reward_sat: 0,
            expiry_height: deadline,
            submit_height: 0,
        }
    }

    /// A post with an empty (unverified) authorization. Transitions never check
    /// signatures — that is `L2State`'s job — so these double as a statement of
    /// where the boundary is.
    fn post(submitter: Address, nonce: u64, payment: u64, deadline: u64) -> PostTaskPayload {
        let compute_task = task_for(deadline);
        let task_id = derive_task_id(&submitter, nonce, &compute_task.task_hash());
        PostTaskPayload {
            submitter,
            auth: Auth::default(),
            task_id,
            payment_sat: payment,
            nonce,
            deadline_height: deadline,
            compute_task,
        }
    }

    fn claim(worker: Address, task_id: Hash, deposit: u64) -> ClaimTaskPayload {
        ClaimTaskPayload {
            worker,
            auth: Auth::default(),
            task_id,
            backend: ComputeBackend::Cpu,
            worker_deposit_sat: deposit,
        }
    }

    fn attestation(worker: Address, task_id: Hash, result: Hash) -> ComputeAttestation {
        ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Cpu,
            worker_address: worker,
            attest_height: 0,
            signature: vec![0x01],
        }
    }

    fn submit(worker: Address, task_id: Hash, result: Hash) -> SubmitResultPayload {
        SubmitResultPayload {
            worker,
            auth: Auth::default(),
            task_id,
            result_hash: result,
            attestation: attestation(worker, task_id, result),
        }
    }

    fn dispute(challenger: Address, task_id: Hash, counter: Hash, deposit: u64) -> DisputePayload {
        DisputePayload {
            challenger,
            auth: Auth::default(),
            task_id,
            counter_result: counter,
            counter_attestation: attestation(challenger, task_id, counter),
            challenge_deposit_sat: deposit,
        }
    }

    fn open_contract() -> TaskContract {
        let p = post(addr(1), 1, 5_000_000, 100);
        TaskContract::new(&p, 1, 5).unwrap()
    }

    #[test]
    fn a_new_contract_rejects_a_mismatched_deadline() {
        // Only the L2 deadline moves, so the derived task id is still valid and
        // the refusal must come from the deadline rule rather than the id rule.
        let mut p = post(addr(1), 1, 1_000, 100);
        p.deadline_height = 101;
        assert_eq!(
            p.task_id,
            p.derived_task_id(),
            "the setup must keep the id valid"
        );
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::DeadlineMismatch)
        ));
    }

    #[test]
    fn a_new_contract_rejects_a_borrowed_task_id_and_zero_payment() {
        let mut p = post(addr(1), 1, 1_000, 100);
        p.task_id = [0xEEu8; 32];
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::BadAttestation(_))
        ));

        let p = post(addr(1), 1, 0, 100);
        assert!(matches!(
            TaskContract::new(&p, 1, 5),
            Err(L2Error::ZeroAmount(_))
        ));

        let p = post(addr(1), 1, 1_000, 100);
        assert!(matches!(
            TaskContract::new(&p, 100, 5),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn happy_path_open_to_settled() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        assert!(matches!(c.state, ContractState::InProgress { .. }));
        assert_eq!(c.worker, Some(addr(2)));

        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(c.state, ContractState::ResultSubmitted { .. }));

        // Window is 5 blocks, submitted at 3, so height 9 is the first settled one.
        assert!(!c.due_for_auto_settle(8));
        assert!(c.due_for_auto_settle(9));

        let outcome = c.settle(Verdict::Correct, [0xAAu8; 32], 9, 20_000).unwrap();
        assert_eq!(outcome.worker_paid, 5_000_000 - 20_000);
        assert_eq!(outcome.worker_deposit_returned, 1_000);
        assert_eq!(outcome.fee_burned + outcome.fee_pscb, 20_000);
        assert!(matches!(c.state, ContractState::Settled(_)));
        assert_eq!(c.locked_total(), 0);
    }

    #[test]
    fn a_double_claim_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        assert!(matches!(
            c.claim(addr(3), &claim(addr(3), id, 1_000), 3),
            Err(L2Error::IllegalTransition { .. })
        ));
        assert_eq!(c.worker, Some(addr(2)));
    }

    #[test]
    fn a_claim_after_the_deadline_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        assert!(matches!(
            c.claim(addr(2), &claim(addr(2), id, 1_000), 101),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn only_the_claiming_worker_may_submit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        assert!(matches!(
            c.submit_result(addr(3), &submit(addr(3), id, [1u8; 32]), 3),
            Err(L2Error::BadAuthorization)
        ));
        // And a submission whose attestation names someone else is refused too.
        let mut s = submit(addr(2), id, [1u8; 32]);
        s.attestation.worker_address = addr(9);
        assert!(matches!(
            c.submit_result(addr(2), &s, 3),
            Err(L2Error::BadAttestation(_))
        ));
    }

    #[test]
    fn a_result_after_the_deadline_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        assert!(matches!(
            c.submit_result(addr(2), &submit(addr(2), id, [1u8; 32]), 101),
            Err(L2Error::TaskExpired)
        ));
    }

    #[test]
    fn a_dispute_after_the_window_is_refused_but_inside_it_is_accepted() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();

        assert!(matches!(
            c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 9),
            Err(L2Error::DisputeWindowClosed)
        ));
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 8)
            .unwrap();
        assert!(matches!(c.state, ContractState::Disputed(_)));
    }

    #[test]
    fn a_dispute_that_agrees_with_the_result_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.file_dispute(addr(4), &dispute(addr(4), id, [0xAAu8; 32], 500), 4),
            Err(L2Error::DisputeAgreesWithResult)
        ));
    }

    #[test]
    fn settling_before_the_window_closes_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0xAAu8; 32], 7, 20_000),
            Err(L2Error::DisputeWindowClosed)
        ));
    }

    #[test]
    fn a_settle_hash_that_does_not_match_the_verdict_is_refused() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0xCCu8; 32], 9, 0),
            Err(L2Error::BadVwcHash)
        ));
    }

    #[test]
    fn a_fraud_verdict_is_refused_when_the_deposit_cannot_cover_the_fee() {
        // The settle fee comes out of the losing worker's deposit, so a deposit
        // smaller than the fee leaves no honest way to charge it. The settle must
        // fail closed rather than collect a partial fee or dip into the escrow
        // the defrauded submitter is owed.
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        assert_eq!(
            c.settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 20_000),
            Err(L2Error::AmountTooSmallForFee {
                available: 1_000,
                fee: 20_000
            })
        );
        assert!(
            matches!(c.state, ContractState::Disputed(_)),
            "a refused settle must leave the contract untouched"
        );
    }

    #[test]
    fn a_fraud_verdict_with_a_deposit_larger_than_the_fee_slashes_the_remainder() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 100_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        let outcome = c
            .settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 20_000)
            .unwrap();
        assert_eq!(outcome.worker_deposit_slashed, 80_000);
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.challenger_refunded, 500);
    }

    #[test]
    fn a_failed_challenge_burns_the_challenger_deposit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();

        // No fee, so the arithmetic is unambiguous about what was burned.
        let outcome = c.settle(Verdict::Correct, [0xAAu8; 32], 5, 0).unwrap();
        assert_eq!(outcome.challenger_deposit_burned, 500);
        assert_eq!(outcome.challenger_refunded, 0);
        assert_eq!(outcome.worker_paid, 5_000_000);
        assert_eq!(outcome.worker_deposit_returned, 1_000);
    }

    #[test]
    fn an_open_task_expires_and_refunds_the_submitter() {
        let mut c = open_contract();
        assert!(c.try_expire(100).is_none(), "deadline is 100, not passed");
        let outcome = c.try_expire(101).expect("expires the block after");
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.worker_deposit_burned, 0);
        assert!(matches!(c.state, ContractState::Expired(_)));
        assert_eq!(c.locked_total(), 0);
    }

    #[test]
    fn an_in_progress_task_that_lapses_burns_the_worker_deposit() {
        let mut c = open_contract();
        let id = c.task_id;
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        let outcome = c.try_expire(101).expect("expires the block after");
        assert_eq!(outcome.submitter_refunded, 5_000_000);
        assert_eq!(outcome.worker_deposit_burned, 1_000);
    }

    #[test]
    fn a_terminal_contract_cannot_be_settled_twice() {
        let mut c = open_contract();
        c.try_expire(101).unwrap();
        assert!(matches!(
            c.settle(Verdict::Correct, [0u8; 32], 102, 0),
            Err(L2Error::IllegalTransition { .. })
        ));
        assert!(!c.due_for_auto_settle(200));
    }

    #[test]
    fn locked_total_tracks_every_held_leg() {
        let mut c = open_contract();
        let id = c.task_id;
        assert_eq!(c.locked_total(), 5_000_000);
        c.claim(addr(2), &claim(addr(2), id, 1_000), 2).unwrap();
        assert_eq!(c.locked_total(), 5_001_000);
        c.submit_result(addr(2), &submit(addr(2), id, [0xAAu8; 32]), 3)
            .unwrap();
        assert_eq!(c.locked_total(), 5_001_000);
        c.file_dispute(addr(4), &dispute(addr(4), id, [0xBBu8; 32], 500), 4)
            .unwrap();
        assert_eq!(c.locked_total(), 5_001_500);
        c.settle(Verdict::Fraudulent, [0xBBu8; 32], 5, 0).unwrap();
        assert_eq!(c.locked_total(), 0);
    }
}
