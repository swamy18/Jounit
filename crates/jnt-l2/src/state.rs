//! `L2State`: the deterministic value layer under the task contracts.
//!
//! This is where an L2 transaction actually *does* something. `TaskContract`
//! decides whether a transition is legal; this module decides who pays, in what
//! order, and where every satoshi ends up.
//!
//! Three rules define the model:
//!
//! 1. **Accounts, not UTXOs.** L2 carries a simple account balance per address.
//!    Funding is genesis-explicit ([`L2State::apply_genesis`], SPEC.md §19.4):
//!    the profile's escrow total is released once — grants to named accounts,
//!    remainder to the protocol escrow identity — and no production path funds
//!    after that. User deposits and exits are deferred past M2. What is real
//!    today is the accounting below it.
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
    SubmitResultPayload, Verdict, VWC_HASH_EXPIRED,
};
use jnt_core::ser::{Reader, Writer};
use jnt_core::slash::SlashVault;

use crate::error::{L2Error, L2Result};
use crate::genesis::L2Genesis;
use crate::task_contract::{L2Config, SettlementOutcome, TaskContract};
use crate::vwc::{VerifiedWorkCertificate, VwcVerification};

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
        /// The Verified Work Certificate issued by this settlement (Phase 4).
        /// `Some` only for a `Correct` settlement of real work; `Fraudulent`
        /// and `Expired` issue nothing (SPEC.md §17.4).
        vwc_id: Option<Hash>,
    },
    Expired {
        task_id: Hash,
        submitter_refunded: u64,
        worker_deposit_burned: u64,
    },
}

/// Equality here is *state* equality: two nodes that replayed the same
/// canonical chain hold equal `L2State`s, which is what Phase 6's replay and
/// cross-node agreement checks assert (SPEC.md §19.1). It is derived, so it
/// compares every field — accounts, tasks, the applied-id set, the counters,
/// the vault and the certificate registry — rather than a hand-picked subset
/// that could silently stop covering a new one.
#[derive(Debug, Clone, PartialEq)]
pub struct L2State {
    config: L2Config,
    accounts: HashMap<Address, u64>,
    tasks: HashMap<Hash, TaskContract>,
    /// Transaction ids that have been applied. Replay protection.
    applied: HashSet<Hash>,
    /// Every satoshi ever released into L2: genesis allocation plus test
    /// credits. Append-only. `conservation_total() == funded_total()` is the
    /// M2 invariant — value is moved, never created — and a production state
    /// whose `funded_total` exceeds its profile's escrow total proves an
    /// unauthorized funding happened.
    funded_total: u64,
    /// Whether the genesis allocation was applied to this state. Exactly-once
    /// by construction (only the constructors apply it, to fresh state) and
    /// enforced by flag: a second application is refused rather than
    /// double-funding every grant.
    genesis_applied: bool,
    /// Deposit `(txid, output_index)` identities already credited (Decision 10
    /// item 5, SPEC.md §19.5). The same L1 bytes in a later block hit this set
    /// and are refused — replay protection for value that arrives via blocks
    /// rather than via L2 transactions (which have the separate `applied` set).
    deposits: HashSet<(Hash, u32)>,
    /// Satoshis credited through deposits, append-only. Feeds `funded_total`
    /// (every deposit credit counts there too) and lets `verify` prove
    /// `funded == escrow + deposits` — i.e. no unauthorized funding — without
    /// re-scanning blocks.
    deposited_total: u64,
    /// Permanently destroyed satoshis (fees + failed-challenge and expiry burns).
    pub burned: u64,
    /// Protocol Security & Compute Buffer accrual from L2 fees (M1).
    pub pscb: u64,
    /// M2 slash vault. Fraud slashes vest here.
    pub slash_vault: SlashVault,
    /// Verified Work Certificates, keyed by task id (Phase 4, SPEC.md §17.7).
    /// Certificates hold no value, so they are outside the conservation sum.
    vwcs: HashMap<Hash, VerifiedWorkCertificate>,
}

impl L2State {
    pub fn new(config: L2Config) -> Self {
        L2State {
            config,
            accounts: HashMap::new(),
            tasks: HashMap::new(),
            applied: HashSet::new(),
            funded_total: 0,
            genesis_applied: false,
            deposits: HashSet::new(),
            deposited_total: 0,
            burned: 0,
            pscb: 0,
            slash_vault: SlashVault::new(),
            vwcs: HashMap::new(),
        }
    }

    /// Release the genesis allocation into this state: grants to named
    /// accounts, remainder to the protocol escrow identity (SPEC.md §19.4).
    ///
    /// Only for freshly constructed states, exactly once. Replay, restart and
    /// reorg all rebuild through constructors that call this once, which is
    /// what makes funding exist exactly once in every derived state without a
    /// persisted funding record.
    pub fn apply_genesis(&mut self, genesis: &L2Genesis) -> L2Result<()> {
        if self.genesis_applied {
            return Err(L2Error::GenesisAlreadyApplied);
        }
        genesis.validate()?;
        for (addr, amount) in &genesis.grants {
            self.credit(*addr, *amount)?;
        }
        let remainder = genesis.escrow_remainder()?;
        if remainder > 0 {
            self.credit(genesis.escrow_id, remainder)?;
        }
        self.genesis_applied = true;
        Ok(())
    }

    /// Whether this state's funding came from genesis (production) rather than
    /// ad-hoc credits (unit tests).
    pub fn has_genesis(&self) -> bool {
        self.genesis_applied
    }

    /// Credit a detected L1 deposit: exactly the sink output's satoshis to the
    /// common input owner, 1:1, no rate, no fee on the credit itself (Decision
    /// 10 item 6).
    ///
    /// The caller (replay) guarantees maturity and detection; this enforces
    /// exactly-once per `(txid, index)` and conservation. A duplicate is
    /// refused by name rather than double-credited — the second occurrence of
    /// the same L1 bytes is a replay, never a second deposit.
    pub fn apply_deposit(
        &mut self,
        recipient: Address,
        amount_sat: u64,
        id: (Hash, u32),
    ) -> L2Result<()> {
        if self.deposits.contains(&id) {
            return Err(L2Error::DuplicateDeposit);
        }
        if amount_sat == 0 {
            return Err(L2Error::ZeroAmount("deposit"));
        }
        self.credit(recipient, amount_sat)?;
        self.deposits.insert(id);
        self.deposited_total = self
            .deposited_total
            .checked_add(amount_sat)
            .ok_or(L2Error::Overflow)?;
        Ok(())
    }

    /// Whether this deposit identity already credited.
    pub fn deposit_credited(&self, id: &(Hash, u32)) -> bool {
        self.deposits.contains(id)
    }

    /// Satoshis credited through deposits. `funded_total` always equals the
    /// genesis release plus this — anything else is invented money.
    pub fn deposited_total(&self) -> u64 {
        self.deposited_total
    }

    pub fn config(&self) -> L2Config {
        self.config
    }

    // --- accounts ------------------------------------------------------

    /// Add free balance to an address.
    ///
    /// Production calls this only through [`Self::apply_genesis`]: the
    /// Decision 7 bridge funds L2 exactly once, at genesis, and user deposits
    /// are deferred — so any post-genesis production credit would be invented
    /// money. Direct calls are the unit-test seam (custom-funded states) and
    /// the future deposit mechanism's entry point, not a funding source the
    /// node may invoke on its own.
    pub fn credit(&mut self, addr: Address, amount: u64) -> L2Result<()> {
        let next = self
            .balance(&addr)
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        self.accounts.insert(addr, next);
        self.funded_total = self
            .funded_total
            .checked_add(amount)
            .ok_or(L2Error::Overflow)?;
        Ok(())
    }

    /// Every satoshi ever released into this state. In production this equals
    /// the profile's escrow total forever — anything else proves an
    /// unauthorized funding happened.
    pub fn funded_total(&self) -> u64 {
        self.funded_total
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

    /// Every task, sorted by task id. Enumeration is never `HashMap` order, so
    /// two nodes holding the same state list the same contracts in the same
    /// order — the property task discovery (Phase 5's worker SDK, SPEC.md
    /// §18.4) is defined on.
    pub fn tasks(&self) -> Vec<&TaskContract> {
        let mut ids: Vec<Hash> = self.tasks.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.tasks[&id]).collect()
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

        // Issue the certificate *before* any value moves, so a refusal leaves
        // the state untouched (fail closed). Only a `Correct` settlement of real
        // work certifies: a `Fraudulent` verdict is a SlashRecord and an
        // `Expired` one is a refund, neither of which is a certificate
        // (SPEC.md §17.4). The evidence is the payload's own quorum aggregate.
        let vwc_id = if p.verdict == Verdict::Correct {
            if p.vwc_hash == VWC_HASH_EXPIRED {
                return Err(L2Error::VwcInvalid(
                    "a correct settlement named the expired-placeholder hash",
                ));
            }
            let worker =
                worker.ok_or(L2Error::VwcInvalid("a correct settlement without a worker"))?;
            let cert = VerifiedWorkCertificate::from_settlement(
                p.task_id,
                worker,
                p.vwc_hash,
                height,
                outcome.worker_paid,
                VwcVerification::Quorum {
                    bls_sig: p.bls_sig,
                    signer_bitmap: p.signer_bitmap.clone(),
                    signer_count: p.signer_count,
                },
            )?;
            Some(self.issue_vwc(cert)?)
        } else {
            None
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
            vwc_id,
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
                // The certificate binds to the result the settlement names, so
                // read it while the contract still carries it.
                let result = t.correct_settlement_hash(height);
                let outcome = if t.due_for_auto_settle(height) {
                    t.auto_settle_correct(height).ok()
                } else if t.due_for_dispute_lapse(height) {
                    t.lapse_dispute(height).ok()
                } else {
                    None
                };
                outcome.map(|o| (attrs, result, o))
            };
            if let Some(((submitter, worker, challenger), result, outcome)) = settled {
                let bonus = self
                    .apply_settlement(submitter, worker, challenger, outcome, [0u8; 32], height)
                    .unwrap_or(0);
                // An implicit settlement carries no aggregate (nothing was
                // transacted), so its certificate is `WindowElapsed` (§17.5). A
                // task settles once, so a duplicate issuance here is impossible;
                // recording nothing would mean a corrupt state, not a lost fee.
                let vwc_id = worker.zip(result).and_then(|(w, r)| {
                    match VerifiedWorkCertificate::from_settlement(
                        id,
                        w,
                        r,
                        height,
                        outcome.worker_paid,
                        VwcVerification::WindowElapsed,
                    ) {
                        Ok(cert) => {
                            let cert_id = cert.id;
                            let _ = self.issue_vwc(cert);
                            Some(cert_id)
                        }
                        Err(_) => None,
                    }
                });
                effects.push(L2Effect::Settled {
                    task_id: id,
                    verdict: Verdict::Correct,
                    worker_paid: outcome.worker_paid,
                    submitter_refunded: outcome.submitter_refunded,
                    worker_deposit_slashed: 0,
                    challenger_bonus: bonus,
                    vwc_id,
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

    // --- verified work certificates (Phase 4, SPEC.md §17) -------------

    /// The certificate issued for a task, if it settled as `Correct`.
    pub fn vwc(&self, task_id: &Hash) -> Option<&VerifiedWorkCertificate> {
        self.vwcs.get(task_id)
    }

    pub fn vwc_count(&self) -> usize {
        self.vwcs.len()
    }

    /// Every certificate, sorted by task id. Enumeration is never `HashMap`
    /// order, so two nodes holding the same state list the same certificates in
    /// the same order (§17.9).
    pub fn vwcs(&self) -> Vec<&VerifiedWorkCertificate> {
        let mut ids: Vec<Hash> = self.vwcs.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.vwcs[&id]).collect()
    }

    /// Validate a certificate against live state: everything
    /// `VerifiedWorkCertificate::validate` checks, plus the registry comparison
    /// (§17.6 check 4) — the certificate must be the one this state issued, byte
    /// for byte. A structurally valid certificate that no state issued proves
    /// nothing.
    pub fn validate_vwc(
        &self,
        cert: &VerifiedWorkCertificate,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> L2Result<()> {
        cert.validate(validators, verifier)?;
        match self.vwcs.get(&cert.task_id) {
            Some(issued) if issued == cert => Ok(()),
            Some(_) => Err(L2Error::VwcInvalid("differs from the issued certificate")),
            None => Err(L2Error::VwcInvalid("was never issued by this state")),
        }
    }

    /// Record a certificate. Exactly one per task, ever: a second issuance for
    /// the same task is a protocol violation and is refused, never silently
    /// overwritten (§17.7).
    fn issue_vwc(&mut self, cert: VerifiedWorkCertificate) -> L2Result<Hash> {
        if self.vwcs.contains_key(&cert.task_id) {
            return Err(L2Error::VwcAlreadyIssued);
        }
        let id = cert.id;
        self.vwcs.insert(cert.task_id, cert);
        Ok(id)
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

    /// The M2 invariant, self-checked: everything ever released is still
    /// somewhere in the system. Burns and PSCB accrual move value between
    /// buckets; they must never change the sum.
    pub fn check_conservation(&self) -> bool {
        self.conservation_total() == self.funded_total
    }
}

// ---------------------------------------------------------------------------
// Wire encoding (SPEC.md §19.6): the state a node serves a remote observer
// ---------------------------------------------------------------------------

/// The only state-transport version this build writes *and* reads. A blob
/// carrying another version is refused, never guessed at.
pub const L2_STATE_WIRE_VERSION: u8 = 1;

/// Smallest possible encoded account entry: `20` address + `8` balance.
const WIRE_ACCOUNT_MIN: usize = 28;
/// Smallest possible encoded applied-id entry.
const WIRE_HASH_MIN: usize = 32;
/// Smallest possible encoded deposit identity: `32` txid + `4` output index.
const WIRE_DEPOSIT_MIN: usize = 36;
/// Smallest possible encoded length-prefixed entry.
const WIRE_PREFIX_MIN: usize = 4;

fn codec_err(what: &'static str) -> L2Error {
    L2Error::Codec(jnt_core::Error::Malformed(what))
}

/// Counted section bound: a declared count can never exceed the bytes that
/// remain divided by the smallest entry it can encode, so a four-byte lie
/// cannot drive an allocation.
fn bounded_count(
    r: &Reader<'_>,
    declared: u64,
    min_entry: usize,
    what: &'static str,
) -> L2Result<usize> {
    let n = declared as usize;
    if declared > u64::try_from(usize::MAX).unwrap_or(u64::MAX) || n > r.remaining() / min_entry {
        return Err(codec_err(what));
    }
    Ok(n)
}

impl L2State {
    /// Canonical wire encoding of the whole state.
    ///
    /// Deterministic: every map is written in sorted key order, so two nodes
    /// holding equal states produce byte-identical blobs and a client can hash
    /// one for comparison. Nothing here is signed — a state is derived data,
    /// and the node's canonical blocks are what give it authority; this is only
    /// a transport (SPEC.md §19.6).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            128 + self.accounts.len() * WIRE_ACCOUNT_MIN + self.tasks.len() * 256,
        );
        w.u8(L2_STATE_WIRE_VERSION)
            .u64le(self.config.dispute_window)
            .u64le(self.config.vesting_period)
            .u64le(self.config.whistleblower_bounty_percent)
            .u8(u8::from(self.genesis_applied))
            .u64le(self.funded_total)
            .u64le(self.deposited_total)
            .u64le(self.burned)
            .u64le(self.pscb);

        let mut accounts: Vec<(&Address, &u64)> = self.accounts.iter().collect();
        accounts.sort_by_key(|(a, _)| **a);
        w.u64le(accounts.len() as u64);
        for (a, bal) in accounts {
            w.fixed(a).u64le(*bal);
        }

        let mut tasks: Vec<(&Hash, &TaskContract)> = self.tasks.iter().collect();
        tasks.sort_by_key(|(id, _)| **id);
        w.u64le(tasks.len() as u64);
        for (id, contract) in tasks {
            let bytes = contract.encode();
            w.fixed(id).u32le(bytes.len() as u32).raw(&bytes);
        }

        let mut applied: Vec<&Hash> = self.applied.iter().collect();
        applied.sort();
        w.u64le(applied.len() as u64);
        for id in applied {
            w.fixed(id);
        }

        let mut deposits: Vec<&(Hash, u32)> = self.deposits.iter().collect();
        deposits.sort_by_key(|d| d.0);
        w.u64le(deposits.len() as u64);
        for d in deposits {
            w.fixed(&d.0).u32le(d.1);
        }

        let mut vwcs: Vec<(&Hash, &VerifiedWorkCertificate)> = self.vwcs.iter().collect();
        vwcs.sort_by_key(|(id, _)| **id);
        w.u64le(vwcs.len() as u64);
        for (task_id, cert) in vwcs {
            let bytes = cert.encode();
            w.fixed(task_id).u32le(bytes.len() as u32).raw(&bytes);
        }

        w.raw(&self.slash_vault.encode());
        w.into_vec()
    }

    /// Decode [`L2State::encode`]: bounded, self-validating, fail-closed.
    ///
    /// A refusal yields no state at all — never a partially populated one. On
    /// top of the structural checks (version, counts, duplicate keys, unknown
    /// tags, trailing bytes) this runs the protocol's own invariant
    /// ([`L2State::check_conservation`]), so a blob whose counters do not add
    /// up is rejected here rather than handed to a worker that would act on it.
    pub fn decode(bytes: &[u8]) -> L2Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| codec_err("state version"))?;
        if version != L2_STATE_WIRE_VERSION {
            return Err(L2Error::Codec(jnt_core::Error::Malformed(match version {
                v if v > L2_STATE_WIRE_VERSION => "state version ahead of this build",
                _ => "state version not supported",
            })));
        }
        let config = L2Config {
            dispute_window: r.u64le().map_err(|_| codec_err("dispute window"))?,
            vesting_period: r.u64le().map_err(|_| codec_err("vesting period"))?,
            whistleblower_bounty_percent: r.u64le().map_err(|_| codec_err("bounty percent"))?,
        };
        let genesis_applied = match r.u8().map_err(|_| codec_err("genesis flag"))? {
            0 => false,
            1 => true,
            _ => return Err(codec_err("genesis flag out of range")),
        };
        let funded_total = r.u64le().map_err(|_| codec_err("funded total"))?;
        let deposited_total = r.u64le().map_err(|_| codec_err("deposited total"))?;
        let burned = r.u64le().map_err(|_| codec_err("burned"))?;
        let pscb = r.u64le().map_err(|_| codec_err("pscb"))?;

        let declared_accounts = r.u64le().map_err(|_| codec_err("account count"))?;
        let n_accounts = bounded_count(
            &r,
            declared_accounts,
            WIRE_ACCOUNT_MIN,
            "account count exceeds buffer",
        )?;
        let mut accounts = HashMap::with_capacity(n_accounts);
        for _ in 0..n_accounts {
            let a: Address = r.fixed().map_err(|_| codec_err("account address"))?;
            let bal = r.u64le().map_err(|_| codec_err("account balance"))?;
            if accounts.insert(a, bal).is_some() {
                return Err(codec_err("duplicate account in state"));
            }
        }

        let declared_tasks = r.u64le().map_err(|_| codec_err("task count"))?;
        let n_tasks = bounded_count(
            &r,
            declared_tasks,
            WIRE_PREFIX_MIN,
            "task count exceeds buffer",
        )?;
        let mut tasks = HashMap::with_capacity(n_tasks);
        for _ in 0..n_tasks {
            let id: Hash = r.fixed().map_err(|_| codec_err("task id"))?;
            let len = r.u32le().map_err(|_| codec_err("task length"))? as usize;
            if len > r.remaining() {
                return Err(codec_err("task length exceeds buffer"));
            }
            let raw = r.fixed_slice(len).map_err(|_| codec_err("task bytes"))?;
            let contract = {
                let mut sub = Reader::new(raw);
                let c = TaskContract::decode(&mut sub)?;
                sub.expect_end()
                    .map_err(|_| codec_err("task has trailing bytes"))?;
                c
            };
            if contract.task_id != id {
                return Err(codec_err("task id disagrees with its contract"));
            }
            if tasks.insert(id, contract).is_some() {
                return Err(codec_err("duplicate task in state"));
            }
        }

        let declared_applied = r.u64le().map_err(|_| codec_err("applied count"))?;
        let n_applied = bounded_count(
            &r,
            declared_applied,
            WIRE_HASH_MIN,
            "applied count exceeds buffer",
        )?;
        let mut applied = HashSet::with_capacity(n_applied);
        for _ in 0..n_applied {
            let id: Hash = r.fixed().map_err(|_| codec_err("applied id"))?;
            if !applied.insert(id) {
                return Err(codec_err("duplicate applied id"));
            }
        }

        let declared_deposits = r.u64le().map_err(|_| codec_err("deposit count"))?;
        let n_deposits = bounded_count(
            &r,
            declared_deposits,
            WIRE_DEPOSIT_MIN,
            "deposit count exceeds buffer",
        )?;
        let mut deposits = HashSet::with_capacity(n_deposits);
        for _ in 0..n_deposits {
            let txid: Hash = r.fixed().map_err(|_| codec_err("deposit txid"))?;
            let idx = r.u32le().map_err(|_| codec_err("deposit index"))?;
            if !deposits.insert((txid, idx)) {
                return Err(codec_err("duplicate deposit identity"));
            }
        }

        let declared_vwcs = r.u64le().map_err(|_| codec_err("certificate count"))?;
        let n_vwcs = bounded_count(
            &r,
            declared_vwcs,
            WIRE_PREFIX_MIN,
            "certificate count exceeds buffer",
        )?;
        let mut vwcs = HashMap::with_capacity(n_vwcs);
        for _ in 0..n_vwcs {
            let task_id: Hash = r.fixed().map_err(|_| codec_err("certificate task id"))?;
            let len = r.u32le().map_err(|_| codec_err("certificate length"))? as usize;
            if len > r.remaining() {
                return Err(codec_err("certificate length exceeds buffer"));
            }
            let raw = r
                .fixed_slice(len)
                .map_err(|_| codec_err("certificate bytes"))?;
            let cert = VerifiedWorkCertificate::decode(raw)?;
            if cert.task_id != task_id {
                return Err(codec_err("certificate names another task"));
            }
            if vwcs.insert(task_id, cert).is_some() {
                return Err(codec_err("duplicate certificate in state"));
            }
        }

        let slash_vault = SlashVault::decode(&mut r)?;
        r.expect_end()
            .map_err(|_| codec_err("state has trailing bytes"))?;

        let state = L2State {
            config,
            accounts,
            tasks,
            applied,
            funded_total,
            genesis_applied,
            deposits,
            deposited_total,
            burned,
            pscb,
            slash_vault,
            vwcs,
        };
        // The protocol's own invariant. A state that does not conserve is not
        // a valid observation of the chain, whatever its structure said.
        if !state.check_conservation() {
            return Err(codec_err("decoded state fails the conservation invariant"));
        }
        Ok(state)
    }
}
