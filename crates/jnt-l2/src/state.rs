//! `L2State`: the deterministic value layer under the task contracts.
//!
//! This is where an L2 transaction actually *does* something. `TaskContract`
//! decides whether a transition is legal; this module decides who pays, in what
//! order, and where every satoshi ends up.
//!
//! Three rules define the model:
//!
//! 1. **Accounts, not UTXOs.** L2 carries a simple account balance per address.
//!    Funding is explicit ([`L2State::credit`]) because the bridge that turns L1
//!    UTXOs into L2 balances is Phase 6 work, not something to invent here. What
//!    is real today is the accounting below it.
//! 2. **Every explicit transaction pays its D3 flat fee**, split 50/50
//!    burned/PSCB through `fees::split_flat_fee` — the unchanged M1 rule. Implicit
//!    transitions (a deadline passing, a dispute window closing) cost nothing,
//!    because nothing was transacted.
//! 3. **Value is conserved.** An L2 fee or a slashed deposit is *moved*, never
//!    conjured: burned and PSCB satoshis leave the account set and land in the
//!    counters, and a slashed deposit lands in the M2 vault. `conservation_total`
//!    is the check, and the integration tests assert it after every scenario.
//!
//! Replay is refused by transaction id, and a failed transaction is not marked
//! applied — a transaction that was rejected for a transient reason (a task not
//! yet posted) can be retried once the precondition holds, but it can never be
//! applied twice.

use std::collections::{HashMap, HashSet};

use jnt_core::bls_checkpoint::{BlsSignature, BlsVerifier, ValidatorSet};
use jnt_core::fees::split_flat_fee;
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::slash::SlashVault;

use crate::error::{L2Error, L2Result};
use crate::task_contract::{L2Config, SettlementOutcome, TaskContract};

/// What an applied transaction did, for logging, tests and (later) event streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Effect {
    Posted {
        task_id: Hash,
        submitter: Address,
        payment_sat: u64,
    },
    Claimed {
        task_id: Hash,
        worker: Address,
    },
    ResultSubmitted {
        task_id: Hash,
        worker: Address,
        result_hash: Hash,
    },
    DisputeFiled {
        task_id: Hash,
        challenger: Address,
    },
    Settled {
        task_id: Hash,
        verdict: Verdict,
        worker_paid: u64,
        submitter_refunded: u64,
        worker_deposit_slashed: u64,
        /// Whistleblower bounty paid from the PSCB reserve (Phase 3). Zero
        /// unless the challenge was upheld and the reserve had funds.
        challenger_bonus: u64,
    },
    Expired {
        task_id: Hash,
        submitter_refunded: u64,
        worker_deposit_burned: u64,
    },
}

#[derive(Debug, Clone)]
pub struct L2State {
    config: L2Config,
    accounts: HashMap<Address, u64>,
    tasks: HashMap<Hash, TaskContract>,
    /// Transaction ids that have been applied. Replay protection.
    applied: HashSet<Hash>,
    /// Permanently destroyed satoshis (fees + failed-challenge and expiry burns).
    pub burned: u64,
    /// Protocol Security & Compute Buffer accrual from L2 fees (M1).
    pub pscb: u64,
    /// M2 slash vault. Fraud slashes vest here.
    pub slash_vault: SlashVault,
}

impl L2State {
    pub fn new(config: L2Config) -> Self {
        L2State {
            config,
            accounts: HashMap::new(),
            tasks: HashMap::new(),
            applied: HashSet::new(),
            burned: 0,
            pscb: 0,
            slash_vault: SlashVault::new(),
        }
    }

    pub fn config(&self) -> L2Config {
        self.config
    }

    // --- accounts ------------------------------------------------------

    /// Add free balance to an address. The L1→L2 funding bridge is Phase 6; this
    /// is the seam it will call.
    pub fn credit(&mut self, addr: Address, amount: u64) -> L2Result<()> {
        let next = self
            .balance(&addr)
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        self.accounts.insert(addr, next);
        Ok(())
    }

    pub fn balance(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).copied().unwrap_or(0)
    }

    fn ensure_balance(&self, addr: &Address, amount: u64) -> L2Result<()> {
        let have = self.balance(addr);
        if have < amount {
            return Err(L2Error::InsufficientBalance {
                needed: amount,
                available: have,
            });
        }
        Ok(())
    }

    /// Debit a balance known to be sufficient (`ensure_balance` was called).
    fn charge_unchecked(&mut self, addr: &Address, amount: u64) {
        let have = self.balance(addr);
        self.accounts.insert(*addr, have - amount);
    }

    fn pay(&mut self, addr: &Address, amount: u64) -> L2Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let next = self
            .balance(addr)
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        self.accounts.insert(*addr, next);
        Ok(())
    }

    fn collect_fee(&mut self, fee: u64) {
        let split = split_flat_fee(fee);
        self.burned = self.burned.saturating_add(split.burned);
        self.pscb = self.pscb.saturating_add(split.pscb);
    }

    // --- task view -----------------------------------------------------

    pub fn task(&self, task_id: &Hash) -> Option<&TaskContract> {
        self.tasks.get(task_id)
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    // --- applying transactions ----------------------------------------

    /// Apply one L2 transaction at `height`.
    ///
    /// `validators` and `verifier` are consulted only for `Settle`; a non-settle
    /// call still needs them because the signature is uniform. That is a small
    /// cost for one call shape rather than five.
    pub fn apply(
        &mut self,
        tx: &L2Transaction,
        height: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<L2Effect> {
        let txid = tx.txid();
        if self.applied.contains(&txid) {
            return Err(L2Error::Replay);
        }
        tx.payload
            .verify_auth()
            .map_err(|_| L2Error::BadAuthorization)?;

        let fee = tx.fee_sat();
        let effect = match &tx.payload {
            L2Payload::Post(p) => self.apply_post(p, height, fee),
            L2Payload::Claim(p) => self.apply_claim(p, height, fee),
            L2Payload::Submit(p) => self.apply_submit(p, height, fee),
            L2Payload::Dispute(p) => self.apply_dispute(p, height, fee),
            L2Payload::Settle(p) => self.apply_settle(p, txid, height, validators, verifier, fee),
        }?;

        // Only a transaction that actually applied is marked applied. A
        // rejection leaves the id free, so a precondition that later holds lets
        // the same bytes be retried — but it can never apply twice.
        self.applied.insert(txid);
        Ok(effect)
    }

    fn apply_post(&mut self, p: &PostTaskPayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        if self.tasks.contains_key(&p.task_id) {
            return Err(L2Error::TaskAlreadyExists);
        }
        let contract = TaskContract::new(p, height, self.config.dispute_window)?;
        let need = p.payment_sat.checked_add(fee).ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.submitter, need)?;
        self.charge_unchecked(&p.submitter, need);
        self.collect_fee(fee);
        self.tasks.insert(p.task_id, contract);
        Ok(L2Effect::Posted {
            task_id: p.task_id,
            submitter: p.submitter,
            payment_sat: p.payment_sat,
        })
    }

    fn apply_claim(&mut self, p: &ClaimTaskPayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        let need = p
            .worker_deposit_sat
            .checked_add(fee)
            .ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.worker, need)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .claim(p.worker, p, height)?;
        self.charge_unchecked(&p.worker, need);
        self.collect_fee(fee);
        Ok(L2Effect::Claimed {
            task_id: p.task_id,
            worker: p.worker,
        })
    }

    fn apply_submit(
        &mut self,
        p: &SubmitResultPayload,
        height: u64,
        fee: u64,
    ) -> L2Result<L2Effect> {
        self.ensure_balance(&p.worker, fee)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .submit_result(p.worker, p, height)?;
        self.charge_unchecked(&p.worker, fee);
        self.collect_fee(fee);
        Ok(L2Effect::ResultSubmitted {
            task_id: p.task_id,
            worker: p.worker,
            result_hash: p.result_hash,
        })
    }

    fn apply_dispute(&mut self, p: &DisputePayload, height: u64, fee: u64) -> L2Result<L2Effect> {
        let need = p
            .challenge_deposit_sat
            .checked_add(fee)
            .ok_or(L2Error::Overflow)?;
        self.ensure_balance(&p.challenger, need)?;
        self.tasks
            .get_mut(&p.task_id)
            .ok_or(L2Error::UnknownTask)?
            .file_dispute(p.challenger, p, height)?;
        self.charge_unchecked(&p.challenger, need);
        self.collect_fee(fee);
        Ok(L2Effect::DisputeFiled {
            task_id: p.task_id,
            challenger: p.challenger,
        })
    }

    fn apply_settle(
        &mut self,
        p: &SettlePayload,
        txid: Hash,
        height: u64,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
        fee: u64,
    ) -> L2Result<L2Effect> {
        // Quorum is three checks, in the order the M5 checkpoint validator uses:
        // the bitmap and the declared count must agree, the count must meet the
        // threshold, and the aggregate must verify over the decision.
        let signers = validators.signers_from_bitmap(&p.signer_bitmap);
        if signers.len() != p.signer_count as usize {
            return Err(L2Error::BadQuorum);
        }
        if signers.len() < validators.quorum_size() {
            return Err(L2Error::BadQuorum);
        }
        let msg = p.signing_hash();
        if !verifier.verify_aggregate(&signers, &msg, &BlsSignature(p.bls_sig)) {
            return Err(L2Error::BadBlsSignature);
        }

        let (submitter, worker, challenger, outcome) = {
            let contract = self.tasks.get_mut(&p.task_id).ok_or(L2Error::UnknownTask)?;
            let submitter = contract.submitter;
            let worker = contract.worker;
            let challenger = contract.challenger();
            let outcome = contract.settle(p.verdict, p.vwc_hash, height, fee)?;
            (submitter, worker, challenger, outcome)
        };
        let challenger_bonus =
            self.apply_settlement(submitter, worker, challenger, outcome, txid, height)?;
        Ok(L2Effect::Settled {
            task_id: p.task_id,
            verdict: p.verdict,
            worker_paid: outcome.worker_paid,
            submitter_refunded: outcome.submitter_refunded,
            worker_deposit_slashed: outcome.worker_deposit_slashed,
            challenger_bonus,
        })
    }

    /// Move value according to a settlement. Shared by explicit `Settle` and the
    /// implicit auto-settle/lapse paths, so all are accounted identically.
    ///
    /// Returns the whistleblower bounty paid, which is the only part of a
    /// settlement that depends on state outside the contract (the PSCB balance).
    ///
    /// The bounty is a transfer *out of* the reserve to the challenger, not a
    /// mint: the reserve falls by exactly what the challenger gains, so the
    /// conservation invariant is untouched. It is computed against the reserve
    /// balance *before* this settlement's own PSCB fee share is added, so a
    /// settlement cannot fund its own bounty.
    #[allow(clippy::too_many_arguments)]
    fn apply_settlement(
        &mut self,
        submitter: Address,
        worker: Option<Address>,
        challenger: Option<Address>,
        o: SettlementOutcome,
        txid: Hash,
        height: u64,
    ) -> L2Result<u64> {
        // The submitter is always owed a refund on the paths that refund them
        // (fraud, expiry) and zero on the paths that do not, so it is credited
        // unconditionally rather than behind an `Option`.
        self.pay(&submitter, o.submitter_refunded)?;
        if let Some(w) = worker {
            self.pay(&w, o.worker_paid)?;
            self.pay(&w, o.worker_deposit_returned)?;
            if o.worker_deposit_slashed > 0 {
                // 50% is burned immediately and 50% vests through M2. Nothing is
                // credited here: the vault owns the vesting half.
                self.slash_vault.slash(
                    txid,
                    o.worker_deposit_slashed,
                    height,
                    self.config.vesting_period,
                    w,
                );
            }
        }
        let mut bonus = 0u64;
        if let Some(c) = challenger {
            self.pay(&c, o.challenger_refunded)?;
            if o.worker_deposit_slashed > 0 {
                let wanted = o
                    .worker_deposit_slashed
                    .saturating_mul(self.config.whistleblower_bounty_percent)
                    / 100;
                bonus = wanted.min(self.pscb);
                if bonus > 0 {
                    self.pay(&c, bonus)?;
                    self.pscb -= bonus;
                }
            }
        }
        self.burned = self
            .burned
            .saturating_add(o.challenger_deposit_burned)
            .saturating_add(o.worker_deposit_burned)
            .saturating_add(o.fee_burned);
        self.pscb = self.pscb.saturating_add(o.fee_pscb);
        Ok(bonus)
    }

    // --- implicit transitions -----------------------------------------

    /// Advance the state to `height`: vest M2 payouts, then auto-settle or expire
    /// every task whose clock has run out.
    ///
    /// Processed in sorted task-id order so two nodes holding the same state
    /// produce the same effects in the same order. Nothing here charges a fee.
    pub fn advance_block(&mut self, height: u64) -> Vec<L2Effect> {
        let mut effects = Vec::new();

        for (addr, amount) in self.slash_vault.advance_block(height) {
            // A payout can only fail on an impossible overflow; dropping it would
            // lose value, so a failure is ignored rather than allowed to abort
            // the transition of every other task.
            let _ = self.pay(&addr, amount);
        }

        let mut ids: Vec<Hash> = self.tasks.keys().copied().collect();
        ids.sort_unstable();

        for id in ids {
            // Two implicit settlements share this path: the dispute window
            // closing with no challenge, and a filed dispute lapsing without a
            // resolution. Both settle as `Correct` with no fee; the difference
            // is which deposits move, and `settle_inner` accounts for that.
            let settled = {
                let t = self.tasks.get_mut(&id).expect("id came from the map");
                let attrs = (t.submitter, t.worker, t.challenger());
                let outcome = if t.due_for_auto_settle(height) {
                    t.auto_settle_correct(height).ok()
                } else if t.due_for_dispute_lapse(height) {
                    t.lapse_dispute(height).ok()
                } else {
                    None
                };
                outcome.map(|o| (attrs, o))
            };
            if let Some(((submitter, worker, challenger), outcome)) = settled {
                let bonus = self
                    .apply_settlement(submitter, worker, challenger, outcome, [0u8; 32], height)
                    .unwrap_or(0);
                effects.push(L2Effect::Settled {
                    task_id: id,
                    verdict: Verdict::Correct,
                    worker_paid: outcome.worker_paid,
                    submitter_refunded: outcome.submitter_refunded,
                    worker_deposit_slashed: 0,
                    challenger_bonus: bonus,
                });
                continue;
            }

            let expired = self
                .tasks
                .get_mut(&id)
                .expect("id came from the map")
                .try_expire(height);
            if let Some(o) = expired {
                let submitter = self
                    .tasks
                    .get(&id)
                    .map(|t| t.submitter)
                    .expect("expired task still exists");
                let _ = self.pay(&submitter, o.submitter_refunded);
                self.burned = self.burned.saturating_add(o.worker_deposit_burned);
                effects.push(L2Effect::Expired {
                    task_id: id,
                    submitter_refunded: o.submitter_refunded,
                    worker_deposit_burned: o.worker_deposit_burned,
                });
            }
        }

        effects
    }

    // --- invariants ----------------------------------------------------

    pub fn total_accounts(&self) -> u64 {
        self.accounts.values().copied().sum()
    }

    pub fn total_locked(&self) -> u64 {
        self.tasks.values().map(|t| t.locked_total()).sum()
    }

    /// Everything permanently destroyed: L2 fee burns plus failed-challenge and
    /// expiry burns, and the M2 vault's immediate burns.
    pub fn total_burned(&self) -> u64 {
        self.burned.saturating_add(self.slash_vault.total_burned)
    }

    /// The vesting half still held by the M2 vault.
    pub fn vault_remaining(&self) -> u64 {
        self.slash_vault
            .records()
            .iter()
            .map(|r| r.remaining_vest)
            .sum()
    }

    /// Every satoshi still inside the system, in whatever bucket. Compared
    /// against total credited to prove nothing was created or destroyed.
    pub fn conservation_total(&self) -> u64 {
        self.total_accounts()
            .saturating_add(self.total_locked())
            .saturating_add(self.total_burned())
            .saturating_add(self.pscb)
            .saturating_add(self.vault_remaining())
    }
}
