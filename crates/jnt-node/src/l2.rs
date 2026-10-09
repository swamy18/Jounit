//! The node's L2 view: `ChainL2` kept in step with the canonical L1 chain.
//!
//! # Why this module exists
//!
//! `ChainL2` (in `jnt-l2`) rebuilds L2 state by replaying canonical L1 blocks,
//! but it is a library type with no notion of a running node: it does not know
//! which chain it has already seen, what to do when the tip moves, or what to
//! do when history is rewritten. This module is the thin adapter that answers
//! those three questions, and nothing else. It contains no L2 transition logic
//! of its own — every payload is applied by `L2State::apply` through
//! `ChainL2`, so there is exactly one state machine, not two.
//!
//! # The sync rule
//!
//! The node calls [`NodeL2::sync`] after every batch of accepted blocks (mined
//! locally or received from peers — both land in `Chain` through the same
//! `submit` path, so one call site covers both). The rule is:
//!
//! - tip unchanged → do nothing (an old side block or a rejected block leaves
//!   the tip where it was, so there is nothing to replay);
//! - the chain extended the previously synced tip → apply only the new blocks
//!   incrementally (`ChainL2::apply_block`);
//! - anything else (a reorg rewrote history, or this is the first sync after a
//!   restart) → throw the view away and [`ChainL2::replay`] the winning chain
//!   from genesis.
//!
//! The third arm is the whole reorg story: there is no undo bookkeeping to get
//! wrong, because the state is re-derived from the blocks that are canonical
//! *now*. L2 state is therefore never persisted — persisting it would create a
//! second source of truth that a restart could disagree with, which is exactly
//! the stale-state failure replay exists to avoid.
//!
//! # What this deliberately does not do
//!
//! - **No post-genesis funding.** The accounts start funded exactly once, from
//!   the profile's genesis allocation (Decision 7, SPEC.md §19.4), and no
//!   production path calls `credit` after that — user deposits are deferred.
//!   Payloads from genuinely unfunded accounts are still refused with
//!   `InsufficientBalance` and recorded as skipped.
//! - **The declared committee only.** `Settle` payloads are checked against
//!   the active validator committee the network profile declares (Decision 15,
//!   the same `genesis_validators` list the L1 finality layer verifies
//!   checkpoints against — not keys pulled from the finality machinery by
//!   convenience). A profile that intentionally declares no committee
//!   (`mainnet`) keeps the empty set, so every settlement fails closed with
//!   `BadQuorum` deterministically rather than applying without authority.
//! - **No new consensus rule.** A block the L1 layer rejects never reaches
//!   `sync` with a moved tip, so L2 state cannot be mutated by a block the node
//!   did not accept. L2 failures never reject a block either: they are recorded
//!   as skipped payloads per the M1 skip semantics.
//! - **No second finality system.** Deposit maturity consumes the L1 chain's
//!   binding-finalized height through the same [`Chain`] the tip came from
//!   (Decision 15); L2 never keeps its own checkpoint view.

use jnt_core::bls::RealBls;
use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::chain::Chain;
use jnt_core::exit::MAX_CLAIM_INPUTS;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;
use jnt_core::tx::{GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE};
use jnt_l2::{
    ChainL2, DepositParams, IgnoredDeposit, L2Config, L2Genesis, L2State, PendingDeposit, SkippedL2,
};

/// Gas an exit claim consumes for `inputs` sink outputs. Mirrors
/// `ExitClaim::gas_used`, which cannot be called before the input list exists —
/// and the input list is chosen by how much funding is needed, which depends on
/// this number.
fn exit_claim_gas(inputs: usize, has_exit_fee: bool) -> u64 {
    let outputs = if has_exit_fee { 2 } else { 1 };
    GAS_TX_BASE
        .saturating_add(GAS_PER_INPUT.saturating_mul(inputs as u64))
        .saturating_add(GAS_PER_OUTPUT.saturating_mul(outputs))
}

/// A subset of exactly `n` outputs totalling exactly `target`, or `None`.
///
/// Largest-first and refusing to overshoot: a claim must consume sink outputs
/// worth precisely its obligation, so the walk stops as soon as the running
/// total passes the target rather than trimming an output that would leave
/// change nobody may claim. Returns `None` rather than approximating — leaving
/// an exit queued costs its owner time, while paying the wrong amount costs
/// them money.
fn exact_subset(
    available: &[(jnt_core::tx::OutPoint, u64)],
    target: u64,
    n: usize,
) -> Option<Vec<jnt_core::tx::OutPoint>> {
    let mut order: Vec<&(jnt_core::tx::OutPoint, u64)> = available.iter().collect();
    order.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let mut picked = Vec::with_capacity(n);
    let mut total = 0u64;
    for (op, value) in order {
        if picked.len() == n {
            break;
        }
        match total.checked_add(*value) {
            Some(next) if next == target => {
                picked.push(*op);
                return Some(picked);
            }
            Some(next) if next < target => {
                total = next;
                picked.push(*op);
            }
            _ => {}
        }
    }
    None
}

/// L2 dispute-window parameters follow the L1 network profile: `mini` gets the
/// short test window, every other profile gets production values. The bounty
/// share is identical in both (it is an incentive, not a timing knob), so this
/// mapping changes when a block is challengeable, never how value moves.
///
/// The exit activation height always comes from the profile itself
/// (`NetworkParams::exit_activation_height`): the constructors below default
/// it to `0` (never) and this override is what activates exits per network.
pub fn config_for(params: &NetworkParams) -> L2Config {
    let mut config = if params.name == "mini" {
        L2Config::mini()
    } else {
        L2Config::mainnet()
    };
    config.exit_activation_height = params.exit_activation_height;
    config
}

/// The validator set the node checks `Settle` payloads against (Decision 15).
///
/// The profile's *declared active committee* — the same `genesis_validators`
/// list the L1 finality layer verifies checkpoint certificates against, in its
/// canonical order. Not a convenience alias for checkpoint-signing state: this
/// reads the profile declaration, so L1 and L2 agree on who the validators are
/// by construction rather than by shared plumbing.
///
/// `mainnet` intentionally declares no committee, so this stays empty there
/// and every settlement fails deterministically with `BadQuorum` — fail closed,
/// never fail open.
pub fn validator_set(params: &NetworkParams) -> ValidatorSet {
    ValidatorSet::new(params.genesis_validators.clone())
}

/// How a [`NodeL2::sync`] call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The tip had not moved: a side block, a duplicate, or a rejected block.
    /// L2 state is untouched by construction.
    Unchanged,
    /// The chain extended the previously synced tip; only the new blocks were
    /// applied.
    Incremental { blocks: u64 },
    /// History was rewritten (reorg) or this is the first sync (startup): the
    /// view was rebuilt by full replay of the winning chain.
    FullReplay { blocks: u64 },
}

/// What one `sync` call did, for logging and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub outcome: SyncOutcome,
    /// L2 height before this call.
    pub from_height: u64,
    /// L2 height after this call.
    pub to_height: u64,
    /// Newly applied L2 transactions. Saturating: a reorg that replaces
    /// history can leave fewer applied than before, and a delta must never
    /// underflow — the totals below are the exact values.
    pub applied_new: u64,
    /// Newly skipped L2 payloads. Saturating, for the same reason: a reorg
    /// can drop previously recorded skips.
    pub skipped_new: usize,
    /// Total applied after this call.
    pub applied_total: u64,
    /// Total skipped after this call.
    pub skipped_total: usize,
}

/// The node's L2 view: one `ChainL2` plus the cursor that keeps it in step
/// with one canonical chain.
///
/// The cursor is `(synced_tip, synced_height)` — the tip hash the view was
/// derived from, and the height it was derived to. Both are needed: the height
/// alone cannot tell a reorg at the same height from no change at all, and the
/// hash alone cannot tell how many blocks to apply incrementally.
#[derive(Debug, Clone)]
pub struct NodeL2 {
    inner: ChainL2,
    config: L2Config,
    genesis: L2Genesis,
    deposits: DepositParams,
    /// The profile's declared active committee (Decision 15), fixed at
    /// construction so every replay and incremental step in this view verifies
    /// settlements against the same set.
    validators: ValidatorSet,
    synced_tip: Option<Hash>,
    synced_height: u64,
}

impl NodeL2 {
    /// An empty view for `params` — the state a node holds before it has
    /// synced anything. Genesis funding is already applied (L2 height 0 holds
    /// the allocation), so the first `sync` against a non-empty chain takes
    /// the full-replay arm and converges by construction.
    pub fn fresh(params: &NetworkParams) -> Self {
        let config = config_for(params);
        let genesis = L2Genesis::for_params(params);
        let deposits = DepositParams::for_params(params);
        let validators = validator_set(params);
        NodeL2 {
            inner: ChainL2::empty(config, &genesis, deposits),
            config,
            genesis,
            deposits,
            validators,
            synced_tip: None,
            synced_height: 0,
        }
    }

    /// Rebuild the view from the whole chain — the restart path. Nothing about
    /// L2 is read from disk: the blocks the store already holds plus the
    /// profile's genesis allocation are the only inputs, so a restarted node
    /// reaches exactly the state its pre-shutdown self held. Funding exists
    /// exactly once because genesis is applied once per construction, never
    /// replayed from blocks.
    pub fn replay_from(chain: &Chain, params: &NetworkParams) -> Self {
        let config = config_for(params);
        let genesis = L2Genesis::for_params(params);
        let deposits = DepositParams::for_params(params);
        let validators = validator_set(params);
        let inner = ChainL2::replay(chain, config, &genesis, deposits, &validators, &RealBls);
        let synced_height = inner.height();
        let synced_tip = Some(chain.tip_hash());
        NodeL2 {
            inner,
            config,
            genesis,
            deposits,
            validators,
            synced_tip,
            synced_height,
        }
    }

    /// Bring the view up to `chain`'s tip. See the module docs for the rule.
    ///
    /// This must be called after every batch of accepted blocks — mined or
    /// received, both move the same tip — and only then: it reads the tip, it
    /// does not validate blocks, so calling it cannot admit anything `Chain`
    /// did not already accept.
    pub fn sync(&mut self, chain: &Chain) -> SyncReport {
        let tip = chain.tip_hash();
        let tip_height = chain.height();
        // Both Decision 15 inputs come off the same chain the tip came from:
        // the depth condition is evaluated against `tip_height`, the binding
        // floor against the L1 finality layer. A checkpoint can move this
        // floor without moving the tip, which is why it is read fresh on
        // every sync rather than cached alongside the tip.
        let binding = chain.finality().binding_finalized_height();
        let from_height = self.synced_height;
        let applied_before = self.inner.applied_count();
        let skipped_before = self.inner.skipped().len();

        // Unchanged means: same tip *and* nothing a later checkpoint could now
        // release. A pending deposit held back only by binding finality matures
        // when a certificate arrives, tip untouched — without this second
        // condition the view would sit on a spendable deposit forever.
        if self.synced_tip == Some(tip) && !self.inner.has_pending_matured(tip_height, binding) {
            return SyncReport {
                outcome: SyncOutcome::Unchanged,
                from_height,
                to_height: self.synced_height,
                applied_new: 0,
                skipped_new: 0,
                applied_total: self.inner.applied_count(),
                skipped_total: self.inner.skipped().len(),
            };
        }

        // Incremental only when the chain still contains the block we synced
        // to, at the same height, and has grown past it. Every other shape —
        // a rewritten prefix (reorg), a shorter chain, a first sync — replays.
        let can_extend = self.synced_tip.is_some()
            && tip_height > self.synced_height
            && chain.block_hash_at(self.synced_height) == self.synced_tip;
        // Cloned, not borrowed: both replay arms replace `self.inner` while
        // naming the allocation to rebuild from.
        let genesis = self.genesis.clone();
        let deposits = self.deposits;
        let validators = self.validators.clone();

        let outcome = if can_extend {
            let from = self.synced_height + 1;
            let mut missing = false;
            for h in from..=tip_height {
                match chain.block_at(h) {
                    Some(block) => {
                        self.inner
                            .apply_block(block, tip_height, binding, &validators, &RealBls);
                    }
                    None => {
                        missing = true;
                        break;
                    }
                }
            }
            if missing {
                // The chain is internally inconsistent (it claims a tip above a
                // height it has no block for). Incremental application would
                // silently skip the hole, so fall back to replay, which fails
                // loudly on the same inconsistency instead of papering over it.
                self.inner = ChainL2::replay(
                    chain,
                    self.config,
                    &genesis,
                    deposits,
                    &validators,
                    &RealBls,
                );
                SyncOutcome::FullReplay { blocks: tip_height }
            } else if self.inner.has_pending_matured(tip_height, binding) {
                // A deposit detected in an old block just became spendable —
                // by depth at the new tip, or by binding finality moving
                // without the tip. Incremental sync never re-scans old blocks,
                // so extending would leave it pending forever while a replay
                // would credit it — the two paths would diverge. Rebuild
                // instead: replay evaluates every deposit at the new tip and
                // binding floor.
                self.inner = ChainL2::replay(
                    chain,
                    self.config,
                    &genesis,
                    deposits,
                    &validators,
                    &RealBls,
                );
                SyncOutcome::FullReplay { blocks: tip_height }
            } else {
                SyncOutcome::Incremental {
                    blocks: tip_height - self.synced_height,
                }
            }
        } else {
            self.inner = ChainL2::replay(
                chain,
                self.config,
                &genesis,
                deposits,
                &validators,
                &RealBls,
            );
            SyncOutcome::FullReplay { blocks: tip_height }
        };

        self.synced_tip = Some(tip);
        self.synced_height = self.inner.height();
        SyncReport {
            outcome,
            from_height,
            to_height: self.synced_height,
            applied_new: self.inner.applied_count().saturating_sub(applied_before),
            skipped_new: self.inner.skipped().len().saturating_sub(skipped_before),
            applied_total: self.inner.applied_count(),
            skipped_total: self.inner.skipped().len(),
        }
    }

    /// The replayed L2 state. Equal states on two nodes mean they agree on
    /// every L2 fact (`L2State` equality is derived over all fields).
    pub fn state(&self) -> &L2State {
        self.inner.state()
    }

    /// Mutable access. Unit tests use this for custom-funded states; production
    /// funds only through genesis and matured deposits (Decisions 7 and 10),
    /// so a production state whose `funded_total` exceeds genesis plus
    /// deposits proves an unauthorized funding happened — and `verify` checks
    /// exactly that.
    pub fn state_mut(&mut self) -> &mut L2State {
        self.inner.state_mut()
    }

    /// Dry-run one L2 transaction against a **clone** of the current state.
    ///
    /// The API's L2-broadcast endpoint calls this so a malformed payload or one
    /// whose preconditions already fail is refused by name *before* it waits in
    /// the mining queue. The real state is deliberately untouched: L2 state is
    /// derived from canonical blocks alone (SPEC.md §19.1), and applying a
    /// payload here — outside a block — would fork this node's view from every
    /// peer's replay. Replay remains the only authority that applies; this is a
    /// pre-check whose verdict is advisory, and a payload whose preconditions
    /// change before inclusion is skipped by replay like any other.
    pub fn check(
        &self,
        tx: &jnt_core::l2::L2Transaction,
        at_height: u64,
    ) -> jnt_l2::error::L2Result<()> {
        let mut probe = self.state().clone();
        probe.apply(tx, at_height, &self.validators, &RealBls)?;
        Ok(())
    }

    /// The L2 state root that applying `txs` at `height` would produce
    /// (approved P1), for a miner to commit into the block it is building.
    ///
    /// This is [`check`] run for real on a clone and kept: a refused
    /// transaction is *skipped* rather than fatal, exactly as `sync` will skip
    /// it, so the root returned is the one replay recomputes — not the root a
    /// block "should" have had. It advances a clone too, because the per-height
    /// effects (expiry, settlement, maturity) are part of the root.
    pub fn simulate_root(&self, height: u64, txs: &[jnt_core::l2::L2Transaction]) -> Hash {
        let mut probe = self.state().clone();
        probe.advance_block(height);
        for tx in txs {
            // A refusal is not an error here: replay skips it, so the root has
            // to skip it too. `check` already refused malformed payloads before
            // they were queued; anything left is genuinely skipped.
            let _ = probe.apply(tx, height, &self.validators, &RealBls);
        }
        probe.committed_root()
    }

    /// Queued exits still awaiting an L1 release, oldest first — the crank's
    /// worklist. Re-derived on every replay, so a reorg that drops a queue block
    /// drops its watch with it.
    pub fn pending_exits(&self) -> &[jnt_l2::ExitWatch] {
        self.inner.pending_exits()
    }

    /// Matured, unreleased exits this node can settle on L1 right now, as
    /// fully-formed [`ExitClaim`]s ready for a miner to include (approved P1,
    /// E-2). The crank is permissionless: nothing here depends on who calls it,
    /// and consensus pays only the destinations recorded in the proven L2 exit
    /// records.
    ///
    /// Funding is the reason this can return fewer claims than there are mature
    /// exits. A claim must consume sink outputs totalling *exactly* its
    /// principal, its prepaid fee and its L1 fee — no change, no tip — so an
    /// exit whose sink funding is not sitting in a subset summing to that exact
    /// figure is left queued rather than paid from someone else's deposit. That
    /// is deliberate: overpaying a release would break the exact-funding
    /// invariant and let one exit drain another.
    pub fn crank_claims(
        &self,
        chain: &Chain,
        claimant: jnt_core::hash::Address,
    ) -> Vec<jnt_core::exit::ExitClaim> {
        if !chain.exit_active_at(chain.height() + 1) {
            return Vec::new();
        }
        let tip = chain.height();
        let binding = chain.finality().binding_finalized_height();
        let depth = self.deposits.maturity_depth;
        let base_fee = chain.expected_base_fee_for_next_block();
        let available: Vec<(jnt_core::tx::OutPoint, u64)> = chain
            .utxo()
            .outputs_for_address(&chain.params().l2_deposit_sink())
            .into_iter()
            .collect();
        let mut claims = Vec::new();
        for watch in self.inner.pending_exits() {
            let record = &watch.record;
            if chain.exit_released(&watch.owner, watch.nonce) {
                continue;
            }
            if !L2State::exit_is_mature(record.queued_height, tip, binding, depth) {
                continue;
            }
            let Some(principal) = record.amount_sat.checked_add(record.exit_fee_sat) else {
                continue;
            };
            // Gas depends on the input count, and the required funding depends on
            // the fee, so both are searched together: an exit whose funding sits
            // in a subset summing exactly to principal + L1 fee is claimable now,
            // anything else stays queued. Exact-sum or nothing — paying from a
            // stranger's deposit would let one exit drain another.
            let mut funded = None;
            for n in 1..=MAX_CLAIM_INPUTS.min(available.len()) {
                let gas = exit_claim_gas(n, record.exit_fee_sat != 0);
                let Some(fee) = base_fee.checked_mul(gas) else {
                    break;
                };
                let Some(needed) = principal.checked_add(fee) else {
                    break;
                };
                if let Some(inputs) = exact_subset(&available, needed, n) {
                    funded = Some(inputs);
                    break;
                }
            }
            let Some(inputs) = funded else {
                continue;
            };
            claims.push(jnt_core::exit::ExitClaim {
                owner: watch.owner,
                nonce: watch.nonce,
                amount_sat: record.amount_sat,
                destination: record.destination,
                claimant,
                exit_fee_sat: record.exit_fee_sat,
                queued_height: record.queued_height,
                inputs,
                proof: watch.proof.clone(),
            });
        }
        claims
    }

    /// The genesis allocation this view was built from.
    pub fn genesis(&self) -> &L2Genesis {
        &self.genesis
    }

    /// The deposit rules this view scans with.
    pub fn deposit_params(&self) -> DepositParams {
        self.deposits
    }

    /// L2 height replayed to — always a chain height, never ahead of it.
    pub fn height(&self) -> u64 {
        self.inner.height()
    }

    /// How many L2 transactions applied.
    pub fn applied_count(&self) -> u64 {
        self.inner.applied_count()
    }

    /// Payloads a canonical block carried that did not apply, in block order.
    /// Never a reason to reject a block.
    pub fn skipped(&self) -> &[SkippedL2] {
        self.inner.skipped()
    }

    /// Deposits detected but not yet final-deep: visible, not spendable.
    pub fn pending_deposits(&self) -> &[PendingDeposit] {
        self.inner.pending_deposits()
    }

    /// Sink outputs that credited nothing, with the named reason.
    pub fn ignored_deposits(&self) -> &[IgnoredDeposit] {
        self.inner.ignored_deposits()
    }

    /// Deposits credited (matured and applied).
    pub fn deposits_applied_count(&self) -> u64 {
        self.inner.deposits_applied_count()
    }

    /// Whether every replayed L2 transaction applied.
    pub fn is_clean(&self) -> bool {
        self.inner.is_clean()
    }

    /// The tip this view was derived from, if it has synced anything yet.
    pub fn synced_tip(&self) -> Option<Hash> {
        self.synced_tip
    }

    /// Minimal operator-visible summary: heights, counts, cleanliness.
    pub fn status(&self, chain_height: u64) -> L2Status {
        L2Status {
            chain_height,
            l2_height: self.inner.height(),
            applied: self.inner.applied_count(),
            skipped: self.inner.skipped().len(),
            clean: self.inner.is_clean(),
            deposits_applied: self.inner.deposits_applied_count(),
            deposits_pending: self.inner.pending_deposits().len(),
            deposits_ignored: self.inner.ignored_deposits().len(),
            deposited_sat: self.inner.state().deposited_total(),
            exited_sat: self.inner.state().exited_total(),
            pending_exits: self.inner.pending_exits().len(),
        }
    }
}

/// The minimum the node reports so an operator can verify L2 processing
/// actually happened: which height was replayed to, how much applied, how much
/// was refused and why (the reasons live in [`NodeL2::skipped`]), plus the
/// deposit pipeline (credited, pending maturity, refused with reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Status {
    pub chain_height: u64,
    pub l2_height: u64,
    pub applied: u64,
    pub skipped: usize,
    pub clean: bool,
    pub deposits_applied: u64,
    pub deposits_pending: usize,
    pub deposits_ignored: usize,
    pub deposited_sat: u64,
    /// Value that has left L2 for L1 through an accepted exit claim (approved
    /// P1). Reported rather than checked: the joint conservation check already
    /// holds across a release without modification, because the L1 payment and
    /// the L2 debit cancel.
    pub exited_sat: u64,
    /// Queued exits still awaiting an L1 release — the crank's worklist.
    pub pending_exits: usize,
}
