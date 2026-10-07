//! L2 state rebuilt from the canonical L1 chain — Decision 6, SPEC.md §19.1.
//!
//! # Why this lives here and not in `jnt-core`
//!
//! L2 state is a pure function of the canonical chain: the L2 transactions are
//! carried in L1 blocks and committed by each block's merkle root, so every node
//! that replays the same blocks in the same order reaches the same state. That
//! function needs *both* crates — `Chain` to read blocks, `L2State` to apply
//! them — and the dependency direction is `jnt-l2 → jnt-core`. Putting the
//! replay here therefore adds no dependency edge and, more importantly, requires
//! no change to `Chain::submit`: L1 block validity is not made to depend on L2
//! rules, which is the property that keeps this integration from touching
//! consensus.
//!
//! # The one ordering rule
//!
//! For each height, the clock advances first (`L2State::advance_block`), then
//! the block's own L2 transactions are applied in block order. That order is
//! fixed and stated once, because two nodes must agree on whether a transaction
//! that lands on the same height as an expiry sees the task open or expired.
//! Vesting and expiry happen *at* the height; the block's transactions then act
//! on the result.
//!
//! # What replay does with a transaction that does not apply
//!
//! It records it in [`ChainL2::skipped`] and carries on. This is deliberate and
//! documented in Decision 6: L2 validity is not an L1 block-validity rule, so a
//! miner *can* include an L2 transaction that fails — and every other node must
//! then reach the same conclusion about it, which it does, because `apply` is a
//! pure function of state and the rejection is deterministic. The transaction is
//! not marked applied, so it stays retryable, and nothing about it can corrupt
//! state. Recording the list rather than ignoring it is what makes that visible:
//! a node can report which payloads in a block it refused, and why.

use jnt_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use jnt_core::chain::Chain;
use jnt_core::l2::L2Transaction;
use jnt_core::Hash;

use crate::error::L2Error;
use crate::genesis::L2Genesis;
use crate::state::L2State;
use crate::task_contract::L2Config;

/// An L2 transaction that a canonical block carried but that did not apply.
///
/// Not an error in the chain — an error *about* a payload. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedL2 {
    /// Height of the block that carried it.
    pub height: u64,
    /// Canonical transaction id, so the payload can be named without holding it.
    pub txid: Hash,
    /// The named reason it did not apply.
    pub error: L2Error,
}

/// The L2 view of one canonical L1 chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainL2 {
    state: L2State,
    height: u64,
    applied: u64,
    skipped: Vec<SkippedL2>,
}

impl ChainL2 {
    /// A view with no history yet — the state a node starts from before it has
    /// applied anything, so it can follow the tip with [`Self::apply_block`].
    ///
    /// Genesis funding is applied here, before any block: L2 height 0 holds
    /// the allocation, and block 1 is the first that can spend it. Recovery
    /// (`replay`) builds through this same constructor, so "start empty, then
    /// apply each block" and full replay cannot disagree about funding.
    ///
    /// This is also the second half of the recovery story: `replay` and
    /// "start empty, then apply each block" must reach the same state, and a
    /// test asserts exactly that.
    pub fn empty(config: L2Config, genesis: &L2Genesis) -> Self {
        let mut state = L2State::new(config);
        state
            .apply_genesis(genesis)
            .expect("genesis validated by NetworkParams::validate");
        ChainL2 {
            state,
            height: 0,
            applied: 0,
            skipped: Vec::new(),
        }
    }

    /// Replay a whole chain from genesis to its tip.
    ///
    /// This is the recovery path: nothing about `L2State` is persisted, so a
    /// restarting node rebuilds it from the blocks it already stores. It is also
    /// the reorg path — a fork choice that rewrites history is answered by
    /// replaying the chain that won, with no undo bookkeeping to get wrong.
    pub fn replay(
        chain: &Chain,
        config: L2Config,
        genesis: &L2Genesis,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) -> Self {
        let mut l2 = ChainL2::empty(config, genesis);
        for height in 1..=chain.height() {
            // `block_at` is total over 1..=height on a canonical chain. A
            // missing block would mean the chain is internally inconsistent,
            // which is a bug in `Chain`, not an input to route around here.
            let block = chain
                .block_at(height)
                .expect("canonical chain must have a block at every height up to its tip");
            l2.absorb(height, &block.l2_txs, validators, verifier);
        }
        l2
    }

    /// Apply one newly accepted block. The incremental twin of [`Self::replay`],
    /// used by a node that already holds state and is following the tip.
    ///
    /// `height` is taken from the block itself so the two paths cannot disagree
    /// about which height a transaction was applied at.
    pub fn apply_block(
        &mut self,
        block: &jnt_core::block::Block,
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) {
        self.absorb(block.header.height, &block.l2_txs, validators, verifier);
    }

    fn absorb(
        &mut self,
        height: u64,
        l2_txs: &[L2Transaction],
        validators: &ValidatorSet,
        verifier: &dyn BlsVerifier,
    ) {
        // The clock first, then the block's transactions. See the module docs.
        self.state.advance_block(height);
        for tx in l2_txs {
            match self.state.apply(tx, height, validators, verifier) {
                Ok(_) => self.applied += 1,
                Err(error) => self.skipped.push(SkippedL2 {
                    height,
                    txid: tx.txid(),
                    error,
                }),
            }
        }
        self.height = height;
    }

    /// The replayed state. Compare two of these directly: equal means the two
    /// nodes agree on every L2 fact, because `L2State`'s equality is derived
    /// over all of its fields.
    pub fn state(&self) -> &L2State {
        &self.state
    }

    /// Mutable access, for the funding bridge (Decision 7) and nothing else.
    /// Replay on its own never needs it.
    pub fn state_mut(&mut self) -> &mut L2State {
        &mut self.state
    }

    /// Height replayed to.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// How many L2 transactions applied.
    pub fn applied_count(&self) -> u64 {
        self.applied
    }

    /// Transactions a canonical block carried that did not apply, in block
    /// order. Empty on a healthy chain, and never a reason to reject a block.
    pub fn skipped(&self) -> &[SkippedL2] {
        &self.skipped
    }

    /// Whether every L2 transaction in every block applied.
    pub fn is_clean(&self) -> bool {
        self.skipped.is_empty()
    }
}
