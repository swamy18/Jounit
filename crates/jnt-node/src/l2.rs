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
//! - **No funding bridge.** The L2 accounts start empty and no production path
//!   calls `credit` (Decision 7). Until the M2 escrow exists, replayed payloads
//!   are refused with `InsufficientBalance` and recorded as skipped — the same
//!   behaviour the `jnt-l2` replay tests pin, preserved here and asserted by the
//!   node integration tests.
//! - **No validator set yet.** Settlements are checked against an empty set
//!   with the production [`RealBls`] verifier, so any `Settle` payload is
//!   refused with `BadQuorum` deterministically. The fixed genesis committee
//!   (Decision 8) arrives with M4; nothing about this module's shape changes
//!   when it does — the set just stops being empty.
//! - **No new consensus rule.** A block the L1 layer rejects never reaches
//!   `sync` with a moved tip, so L2 state cannot be mutated by a block the node
//!   did not accept. L2 failures never reject a block either: they are recorded
//!   as skipped payloads per the M1 skip semantics.

use jnt_core::bls::RealBls;
use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::chain::Chain;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;
use jnt_l2::{ChainL2, L2Config, L2State, SkippedL2};

/// L2 dispute-window parameters follow the L1 network profile: `mini` gets the
/// short test window, every other profile gets production values. The bounty
/// share is identical in both (it is an incentive, not a timing knob), so this
/// mapping changes when a block is challengeable, never how value moves.
pub fn config_for(params: &NetworkParams) -> L2Config {
    if params.name == "mini" {
        L2Config::mini()
    } else {
        L2Config::mainnet()
    }
}

/// The validator set the node checks `Settle` payloads against.
///
/// Empty until the M4 genesis committee (Decision 8). With an empty set every
/// quorum check fails deterministically, so settlements are skipped by name
/// rather than applied without authority — fail closed, never fail open.
pub fn validator_set() -> ValidatorSet {
    ValidatorSet::new(Vec::new())
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
    synced_tip: Option<Hash>,
    synced_height: u64,
}

impl NodeL2 {
    /// An empty view for `params` — the state a node holds before it has
    /// synced anything. The first `sync` against a non-empty chain takes the
    /// full-replay arm, so this and [`Self::replay_from`] converge by
    /// construction.
    pub fn fresh(params: &NetworkParams) -> Self {
        let config = config_for(params);
        NodeL2 {
            inner: ChainL2::empty(config),
            config,
            synced_tip: None,
            synced_height: 0,
        }
    }

    /// Rebuild the view from the whole chain — the restart path. Nothing about
    /// L2 is read from disk: the blocks the store already holds are the only
    /// input, so a restarted node reaches exactly the state its pre-shutdown
    /// self would reach by replaying the same blocks.
    pub fn replay_from(chain: &Chain, params: &NetworkParams) -> Self {
        let config = config_for(params);
        let inner = ChainL2::replay(chain, config, &validator_set(), &RealBls);
        let synced_height = inner.height();
        let synced_tip = Some(chain.tip_hash());
        NodeL2 {
            inner,
            config,
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
        let from_height = self.synced_height;
        let applied_before = self.inner.applied_count();
        let skipped_before = self.inner.skipped().len();

        if self.synced_tip == Some(tip) {
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

        let outcome = if can_extend {
            let from = self.synced_height + 1;
            let mut missing = false;
            for h in from..=tip_height {
                match chain.block_at(h) {
                    Some(block) => self.inner.apply_block(block, &validator_set(), &RealBls),
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
                self.inner = ChainL2::replay(chain, self.config, &validator_set(), &RealBls);
                SyncOutcome::FullReplay { blocks: tip_height }
            } else {
                SyncOutcome::Incremental {
                    blocks: tip_height - self.synced_height,
                }
            }
        } else {
            self.inner = ChainL2::replay(chain, self.config, &validator_set(), &RealBls);
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

    /// Mutable access, for the funding bridge (Decision 7) and nothing else.
    /// Replay on its own never needs it.
    pub fn state_mut(&mut self) -> &mut L2State {
        self.inner.state_mut()
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
        }
    }
}

/// The minimum the node reports so an operator can verify L2 processing
/// actually happened: which height was replayed to, how much applied, how much
/// was refused and why (the reasons live in [`NodeL2::skipped`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Status {
    pub chain_height: u64,
    pub l2_height: u64,
    pub applied: u64,
    pub skipped: usize,
    pub clean: bool,
}
