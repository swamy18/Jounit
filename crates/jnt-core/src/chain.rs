//! Chain state: validation, application, fork choice, reorg, finality.
//! SPEC.md §9.
//!
//! Fork choice is heaviest cumulative difficulty. Selection is deterministic:
//! ties break on lower height, then on the lowest block hash, so two nodes
//! holding the same set of valid blocks always agree on the tip. (An earlier
//! version of this comment claimed a first-seen tie-break; that was the arrival
//! counter bug, since fixed — the comment outlived the code and misdescribed a
//! consensus rule, which is worse than no comment at all.)

use std::collections::HashMap;

use crate::block::{genesis_block, Block, Header};
use crate::difficulty::{next_difficulty, validate_local_clock, validate_timestamp};
use crate::error::{Error, Result};
use crate::fees::{next_base_fee, split_fees, FeeSplit};
use crate::finality::{FinalityError, FinalityManager};
use crate::hash::{Hash, DOM_BLOCK};
use crate::ledger::{check_tx, Undo, Utxo, UtxoSet};
use crate::mempool::{Mempool, ReconcileReport};
use crate::params::NetworkParams;
use crate::puzzle::{PuzzleRegistry, PuzzleSolver, PuzzleSpec};
use crate::supply::{block_reward_sat, max_issuance_sat};
use crate::tx::{OutPoint, Output, Transaction, TX_COINBASE};

/// Upper bound on mining attempts for a single block. Difficulty that would need
/// more work than this is a bug or an attack, not something to hang on.
pub const DEFAULT_MAX_ATTEMPTS: u64 = 200_000_000;

#[derive(Debug, Clone)]
struct Snapshot {
    canon: Vec<Hash>,
    utxo: UtxoSet,
    undo: HashMap<Hash, Undo>,
    pscb_reserve: u64,
    pscb_undo: HashMap<Hash, u64>,
}

#[derive(Debug, Clone)]
pub struct Chain {
    params: NetworkParams,
    registry: PuzzleRegistry,
    /// Caches the active epoch's neural weights across mining attempts.
    solver: PuzzleSolver,
    blocks: HashMap<Hash, Block>,
    /// `cumulative_work` for each stored block, recorded at insert as
    /// `parent_work + difficulty`. Lets fork choice be O(1) per block instead of
    /// a walk to genesis, which makes `best_candidate` O(stored) rather than
    /// O(stored²). Every block in `blocks` has an entry here.
    work: HashMap<Hash, u128>,
    canon: Vec<Hash>,
    utxo: UtxoSet,
    undo: HashMap<Hash, Undo>,
    /// Accumulated PSCB (Protocol Security & Compute Buffer) reserve.
    /// M1 protocol mechanism: 50% of every block's base-fee portion is routed
    /// here rather than burned. The reserve backs the M2 Time-Locked Compute
    /// Reserve vault without touching the hard supply cap.
    pscb_reserve: u64,
    /// Per-block PSCB deltas, keyed by block hash. Required for reorg
    /// correctness: when a canonical block is rolled back, its PSCB contribution
    /// must be subtracted from the running total.
    pscb_undo: HashMap<Hash, u64>,
    /// Non-coinbase transactions the most recent successful reorg rolled back,
    /// oldest block first. Drained by the caller so the mempool can re-admit
    /// them.
    ///
    /// Held on `Chain` rather than returned from `submit_at` because a reorg that
    /// fails is restored wholesale: a list published from a reorg that did not
    /// happen would put transactions back into the pool that the canonical chain
    /// still contains, and the pool would then relay an unmineable duplicate of
    /// a confirmed transaction.
    disconnected_txs: Vec<Transaction>,
    /// M5 binding finality (Decisions 12/14, SPEC.md §14.8). Observation before
    /// activation; once activated, `adopt()` refuses to rewrite finalized
    /// history. Restored from the store on load, never re-derived from blocks
    /// (see `restore_finality`).
    finality: FinalityManager,
}

impl Chain {
    /// Build a chain with the canonical genesis block.
    pub fn new(params: NetworkParams) -> Result<Self> {
        params.validate()?;
        let registry = PuzzleRegistry::genesis();
        registry.get(params.puzzle_id)?;
        let genesis = genesis_block(params.genesis_difficulty);
        let hash = genesis.block_hash();
        debug_assert_eq!(hash, {
            let hb = genesis.header.serialize();
            crate::hash::sha256_dom(DOM_BLOCK, &[&hb])
        });

        let mut chain = Chain {
            params,
            registry,
            solver: PuzzleSolver::new(PuzzleSpec::hybrid_v1()),
            blocks: HashMap::new(),
            work: HashMap::new(),
            canon: Vec::new(),
            utxo: UtxoSet::new(),
            undo: HashMap::new(),
            pscb_reserve: 0,
            pscb_undo: HashMap::new(),
            disconnected_txs: Vec::new(),
            finality: FinalityManager::default(),
        };
        chain.finality = FinalityManager::new(&chain.params);
        chain.blocks.insert(hash, genesis.clone());
        chain.work.insert(hash, genesis.header.difficulty);
        // Genesis mints nothing, so the UTXO set stays empty; only the block
        // bookkeeping matters.
        chain.undo.insert(hash, Undo::default());
        chain.canon = vec![hash];
        Ok(chain)
    }

    pub fn params(&self) -> &NetworkParams {
        &self.params
    }

    pub fn registry(&self) -> &PuzzleRegistry {
        &self.registry
    }

    pub fn height(&self) -> u64 {
        (self.canon.len() - 1) as u64
    }

    pub fn tip_hash(&self) -> Hash {
        *self.canon.last().expect("chain always has a genesis block")
    }

    pub fn tip(&self) -> &Block {
        self.block_by_hash(&self.tip_hash())
            .expect("tip is in canon")
    }

    pub fn block_hash_at(&self, height: u64) -> Option<Hash> {
        self.canon.get(height as usize).copied()
    }

    pub fn block_at(&self, height: u64) -> Option<&Block> {
        let h = self.block_hash_at(height)?;
        self.block_by_hash(&h)
    }

    pub fn block_by_hash(&self, h: &Hash) -> Option<&Block> {
        self.blocks.get(h)
    }

    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    pub fn total_supply_sat(&self) -> u64 {
        self.utxo.total_value()
    }

    /// Accumulated Protocol Security & Compute Buffer reserve (M1).
    ///
    /// This is the 50% of every block's base-fee portion that is diverted from
    /// the burn to the on-chain reserve. It does not count toward the hard
    /// supply cap (it has already been destroyed for cap purposes), but it is
    /// tracked here to power the M2 slash recovery vault.
    pub fn pscb_reserve(&self) -> u64 {
        self.pscb_reserve
    }

    /// Height below which history is immutable.
    ///
    /// The stronger of the depth rule and any binding checkpoint finality
    /// (Decision 12): before activation this is exactly the old depth rule, so
    /// pre-M5 behavior is unchanged; after a checkpoint finalizes at H it is
    /// at least H. `adopt()` consults this, which is what makes checkpoints
    /// binding rather than merely observed.
    pub fn finalized_height(&self) -> u64 {
        self.height()
            .saturating_sub(self.params.finality_depth)
            .max(self.finality.binding_finalized_height())
    }

    /// The binding-finality manager (Decisions 12/14). Read-only inspection;
    /// checkpoints are applied through [`Chain::apply_checkpoint`].
    pub fn finality(&self) -> &FinalityManager {
        &self.finality
    }

    /// Apply a verified checkpoint certificate, updating observed and binding
    /// finality. Returns the accepted point or a named rejection; a rejection
    /// never changes consensus state.
    ///
    /// The certificate must name the block this chain holds canonically at its
    /// height; a valid signature over a non-canonical or future block is
    /// refused (`NotCanonical`). Passing a height already finalized to a
    /// *different* hash is refused as conflicting finality and retained as
    /// evidence (Decision 14).
    pub fn apply_checkpoint(
        &mut self,
        checkpoint: &crate::bls_checkpoint::Checkpoint,
        verify: &dyn crate::bls_checkpoint::BlsVerifier,
    ) -> std::result::Result<(), FinalityError> {
        let height = checkpoint.payload.height;
        // The canonical hash this node holds at that height, if any. Fetch
        // before borrowing `finality` mutably.
        let canonical = self.block_hash_at(height);
        self.finality.accept(checkpoint, canonical, verify)
    }

    /// Restore the binding-finalized point after a restart.
    ///
    /// Only installs it if this chain actually holds that exact block
    /// canonically at that height — a stale or forged metadata row cannot
    /// finalize a block the chain does not have. Returns whether it was
    /// installed.
    pub fn restore_finality(&mut self, height: u64, hash: Hash) -> bool {
        if height == 0 {
            return false;
        }
        if self.block_hash_at(height) != Some(hash) {
            return false;
        }
        self.finality.restore_finalized(height, hash);
        true
    }

    /// The `(height, hash)` of the binding-finalized point, for persistence.
    /// `None` when binding finality has not activated or has not advanced.
    pub fn finalized_point(&self) -> Option<(u64, Hash)> {
        let h = self.finality.binding_finalized_height();
        if h == 0 {
            None
        } else {
            Some((h, self.finality.binding_finalized_hash()))
        }
    }

    /// Store size above which side-branch pruning runs. Sized off the finality
    /// window so a healthy chain never trips it, and off the canonical length
    /// so a node with real history still has room for a live fork.
    fn prune_threshold(&self) -> usize {
        let window = (self.params.finality_depth as usize).saturating_mul(4);
        (self.canon.len() + window).max(64)
    }

    /// `timestamps` of the previous `n` blocks, newest first (index 0 = tip).
    fn history(&self, n: usize) -> Vec<u64> {
        let tip_height = self.height() as usize;
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            if i > tip_height {
                break;
            }
            let h = tip_height - i;
            if let Some(hash) = self.canon.get(h) {
                if let Some(b) = self.blocks.get(hash) {
                    v.push(b.header.timestamp_ms);
                }
            }
        }
        v
    }

    fn puzzle_for(&self, id: u64) -> Result<&PuzzleSpec> {
        self.registry.get(id)
    }

    /// Cumulative PoW difficulty along the chain ending at `hash`.
    ///
    /// Recorded incrementally at insert time as `parent_work + difficulty`, so
    /// this is an O(1) lookup rather than the O(chain-length) walk to genesis it
    /// used to be. That walk made `best_candidate` O(stored²), which a peer
    /// relaying many blocks could turn into a quadratic CPU amplifier.
    ///
    /// Every block in `blocks` is entered here on insert (`Chain::new` for
    /// genesis, `submit_at` for every later block). A miss is therefore a logic
    /// error, but the walk is kept as a defensive fallback so the value stays
    /// correct for any block added outside that path; no consensus outcome
    /// depends on which branch runs.
    fn cumulative_work(&self, hash: &Hash) -> u128 {
        if let Some(&w) = self.work.get(hash) {
            return w;
        }
        debug_assert!(false, "cumulative_work miss for a stored block");
        let mut total = 0u128;
        let mut cursor = *hash;
        loop {
            let Some(block) = self.blocks.get(&cursor) else {
                return total;
            };
            total = total.saturating_add(block.header.difficulty);
            if block.header.height == 0 {
                return total;
            }
            cursor = block.header.prev_hash;
        }
    }

    // -----------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------

    /// Everything checkable without chain state. SPEC.md §9.1 items 3, 5, 7, 8, 10.
    pub fn validate_standalone(&mut self, block: &Block) -> Result<()> {
        let bytes = block.serialize();
        if bytes.len() > self.params.max_block_bytes {
            return Err(Error::BlockTooLarge {
                got: bytes.len(),
                cap: self.params.max_block_bytes,
            });
        }
        if block.txs.len() > self.params.max_tx_count {
            return Err(Error::TooManyTxs {
                got: block.txs.len(),
                cap: self.params.max_tx_count,
            });
        }
        if block.txs.is_empty() {
            return Err(Error::BadCoinbase("block has no transactions"));
        }
        // SPEC.md §1: nodes MUST reject unknown `sig_scheme` values. The field
        // is committed to by the block hash and is what a signature-scheme
        // upgrade hangs off, so accepting an unrecognised value leaves the node
        // unable to tell a v0.1 block from a hypothetical future one.
        if block.header.sig_scheme != crate::hash::SIG_SCHEME_SECP256K1_ECDSA {
            return Err(Error::UnsupportedSigScheme(block.header.sig_scheme));
        }
        if block.header.merkle_root != block.merkle_root() {
            return Err(Error::BadMerkleRoot);
        }

        let spec = self.puzzle_for(block.header.puzzle_id)?;
        let expected_epoch = block.header.expected_epoch(self.params.nn_epoch_blocks);
        if block.header.epoch_id != expected_epoch {
            return Err(Error::BadEpoch {
                expected: expected_epoch,
                got: block.header.epoch_id,
            });
        }

        let gas_used = block.total_gas_used()?;
        if gas_used > self.params.gas_cap {
            return Err(Error::GasOverCap {
                used: gas_used,
                cap: self.params.gas_cap,
            });
        }

        let mut seen = std::collections::HashSet::new();
        for tx in &block.txs {
            if !seen.insert(tx.txid()) {
                return Err(Error::DuplicateTxid);
            }
        }

        // The cached solver must agree with the registry entry it stands in for.
        if spec.id != self.solver.spec().id {
            return Err(Error::BadPuzzleSpec(format!(
                "solver holds puzzle {} but the header names {}",
                spec.id, block.header.puzzle_id
            )));
        }
        if !self.solver.satisfies(&block.header)? {
            return Err(Error::PowInvalid {
                hash: crate::hash::hash_to_hex(&block.block_hash()),
                difficulty: block.header.difficulty,
            });
        }
        Ok(())
    }

    /// Validate against chain state and apply. The UTXO set must already
    /// correspond to the block's parent.
    fn apply_block(&mut self, block: &Block) -> Result<()> {
        let parent_hash = block.header.prev_hash;
        let parent = self
            .blocks
            .get(&parent_hash)
            .ok_or(Error::UnknownParent)?
            .clone();

        let height = parent.header.height + 1;
        if block.header.height != height {
            return Err(Error::BadHeight {
                expected: height,
                got: block.header.height,
            });
        }
        // The coinbase input commits to its own height through a `u32` index
        // (SPEC.md 3.1). Past `u32::MAX` that encoding stops being injective,
        // so refuse rather than compare a truncated index.
        if height > u32::MAX as u64 {
            return Err(Error::BadHeight {
                expected: u32::MAX as u64,
                got: height,
            });
        }

        // Difficulty: SPEC.md §6.
        let history = self.history(self.params.difficulty_window as usize + 1);
        let expected_diff = next_difficulty(&self.params, parent.header.difficulty, &history);
        if block.header.difficulty != expected_diff {
            return Err(Error::BadDifficulty {
                expected: expected_diff,
                got: block.header.difficulty,
            });
        }

        // Timestamps: SPEC.md §6.1.
        validate_timestamp(&self.params, block.header.timestamp_ms, &history)?;

        // Base fee: SPEC.md §8.
        let expected_base_fee = if height == 1 {
            self.params.base_fee_initial_sat
        } else {
            next_base_fee(
                &self.params,
                parent.header.base_fee_sat,
                parent.total_gas_used()?,
            )
        };
        if block.header.base_fee_sat != expected_base_fee {
            return Err(Error::BadFee("base fee does not follow the schedule"));
        }

        // Coinbase shape: SPEC.md §9.2 rules 1-3.
        let coinbase = &block.txs[0];
        if coinbase.tx_type != TX_COINBASE {
            return Err(Error::BadCoinbase("tx 0 must be the coinbase"));
        }
        if coinbase.inputs.len() != 1 || coinbase.outputs.len() != 1 {
            return Err(Error::BadCoinbase(
                "coinbase needs exactly one input and one output",
            ));
        }
        if coinbase.inputs[0].prev_hash != parent_hash
            || coinbase.inputs[0].prev_index != height as u32
        {
            return Err(Error::BadCoinbase(
                "coinbase input must reference the parent block",
            ));
        }

        // A zero-value coinbase is legitimate, not an error. SPEC.md §7 says
        // that once the reward ladder is exhausted the coinbase collects the
        // tips only, and tips can be zero on an empty block. Rejecting it
        // unconditionally halted the chain at a fixed, known height.

        // Everything after the coinbase is an ordinary spend.
        let body = &block.txs[1..];
        let mut body_undo = Undo::default();
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;

        // Every write from here on is recorded so it can be unwound: a block
        // that fails partway through must leave the ledger exactly as it found
        // it, or the node credits outputs from a block it just rejected.
        let mut applied: Vec<Undo> = Vec::new();
        let outcome = self.apply_body(
            block,
            body,
            height,
            &mut applied,
            &mut body_undo,
            &mut total_gas,
            &mut total_fees,
        );
        let split = match outcome {
            Ok(split) => split,
            Err(e) => {
                for u in applied.iter().rev() {
                    self.utxo.undo(u);
                }
                return Err(e);
            }
        };

        // Reward + tip only: the base fee is burned (SPEC.md §8).
        let reward = block_reward_sat(&self.params, height);
        let max_claim = reward.saturating_add(split.tip);
        let minted = coinbase.outputs[0].value;
        if minted > max_claim {
            for u in applied.iter().rev() {
                self.utxo.undo(u);
            }
            return Err(Error::BadFee("coinbase claims more than reward plus tip"));
        }

        // Hard supply cap, checked against live state (SPEC.md §7).
        let already = self.utxo.total_value();
        let after = already.checked_add(minted).ok_or(Error::ValueOverflow)?;
        if after > self.params.supply_cap_sat {
            for u in applied.iter().rev() {
                self.utxo.undo(u);
            }
            return Err(Error::SupplyCapExceeded {
                already,
                requested: minted,
                cap: self.params.supply_cap_sat,
            });
        }

        // Apply the coinbase last so its output is the freshest. A zero-value
        // coinbase is not recorded at all: `check_tx` refuses to spend a
        // zero-value output, so recording it would only grow the UTXO set with
        // permanently unspendable entries.
        let cb_txid = coinbase.txid();
        let cb_op = OutPoint {
            txid: cb_txid,
            index: 0,
        };
        if minted > 0 {
            body_undo.created.push(cb_op);
            self.utxo.insert(
                cb_op,
                Utxo {
                    out: coinbase.outputs[0],
                    height,
                },
            );
        }

        let hash = block.block_hash();
        // Credit the PSCB reserve (M1). Saturate rather than panic: on a
        // pathologically congested chain the accumulated PSCB could notionally
        // exceed u64::MAX over millions of blocks, though in practice the
        // hard-capped fee schedule makes this unreachable.
        self.pscb_reserve = self.pscb_reserve.saturating_add(split.pscb);
        self.pscb_undo.insert(hash, split.pscb);
        self.undo.insert(hash, body_undo);
        Ok(())
    }

    /// Apply every non-coinbase transaction of `block`, accumulating gas, fees
    /// and undo data. Caller unwinds with the returned `applied` list on error.
    #[allow(clippy::too_many_arguments)]
    fn apply_body(
        &mut self,
        block: &Block,
        body: &[Transaction],
        height: u64,
        applied: &mut Vec<Undo>,
        body_undo: &mut Undo,
        total_gas: &mut u64,
        total_fees: &mut u64,
    ) -> Result<FeeSplit> {
        for tx in body {
            let delta = check_tx(
                &self.utxo,
                tx,
                height,
                &self.params,
                block.header.base_fee_sat,
                self.params.coinbase_maturity,
            )?;
            let undo = self.utxo.apply_tx(tx, height)?;
            applied.push(undo.clone());
            body_undo.spent.extend(undo.spent);
            body_undo.created.extend(undo.created);
            // Accumulated across the block, so use checked arithmetic: `+=`
            // panics in debug and wraps in release, and a wrapped total feeds
            // straight into the burn/tip split below, where wrapping could
            // understate the burned portion or invent a miner tip.
            *total_gas = total_gas
                .checked_add(delta.gas_used)
                .ok_or(Error::ValueOverflow)?;
            *total_fees = total_fees
                .checked_add(delta.fee_total)
                .ok_or(Error::ValueOverflow)?;
        }
        // Genesis-adjacent blocks pay no base fee on their first transaction;
        // the schedule above already starts at `base_fee_initial_sat`.
        split_fees(*total_gas, *total_fees, block.header.base_fee_sat)
    }

    fn rollback_block(&mut self, hash: &Hash) {
        let Some(block) = self.blocks.get(hash).cloned() else {
            return;
        };
        if let Some(undo) = self.undo.get(hash).cloned() {
            // Reverse the body first, then drop the coinbase output.
            for tx in block.txs[1..].iter().rev() {
                self.utxo.undo_tx(tx, &undo);
            }
            // Identify the coinbase output directly rather than by its position
            // at the end of `undo.created`: a zero-value coinbase is never
            // recorded there, so position was not a reliable handle.
            if let Some(cb) = block.txs.first() {
                self.utxo.drop_created(&[OutPoint {
                    txid: cb.txid(),
                    index: 0,
                }]);
            }
        }
        self.undo.remove(hash);
        // Undo the PSCB credit for this block (M1 reorg correctness).
        if let Some(delta) = self.pscb_undo.remove(hash) {
            self.pscb_reserve = self.pscb_reserve.saturating_sub(delta);
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            canon: self.canon.clone(),
            utxo: self.utxo.clone(),
            undo: self.undo.clone(),
            pscb_reserve: self.pscb_reserve,
            pscb_undo: self.pscb_undo.clone(),
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.canon = s.canon;
        self.utxo = s.utxo;
        self.undo = s.undo;
        self.pscb_reserve = s.pscb_reserve;
        self.pscb_undo = s.pscb_undo;
    }

    fn path_to(&self, target: &Hash) -> Option<Vec<Hash>> {
        let mut path = Vec::new();
        let mut cursor = *target;
        loop {
            let block = self.blocks.get(&cursor)?;
            path.push(cursor);
            if block.header.height == 0 {
                path.reverse();
                return Some(path);
            }
            cursor = block.header.prev_hash;
        }
    }

    /// Pick the tip: most work, then lower height, then lowest block hash.
    ///
    /// Every tie-break is a function of block data alone. An earlier version
    /// used an arrival counter as the final tie-break, which made the result
    /// depend on the order blocks happened to be delivered — two nodes holding
    /// an identical set of valid blocks could and did choose different tips,
    /// which is a consensus split rather than a rounding difference.
    fn best_candidate(&self) -> Hash {
        let tip = self.tip_hash();
        let mut best = tip;
        let mut best_key = self.fork_choice_key(&tip);

        let mut candidates: Vec<(&Hash, &Block)> = self.blocks.iter().collect();
        candidates.sort_by(|a, b| a.0.cmp(b.0)); // deterministic iteration
        for (hash, block) in candidates {
            let key = self.fork_choice_key(hash);
            debug_assert_eq!(key.1, std::cmp::Reverse(block.header.height));
            if key > best_key {
                best_key = key;
                best = *hash;
            }
        }
        best
    }

    /// Total ordering for fork choice: `(work, lower height first, lowest hash
    /// first)`. Derived only from the block graph, never from arrival order.
    fn fork_choice_key(
        &self,
        hash: &Hash,
    ) -> (u128, std::cmp::Reverse<u64>, std::cmp::Reverse<Hash>) {
        let work = self.cumulative_work(hash);
        let height = self.blocks.get(hash).map(|b| b.header.height).unwrap_or(0);
        (work, std::cmp::Reverse(height), std::cmp::Reverse(*hash))
    }

    /// Accept a block: store it, then re-run fork choice. Extends the tip or
    /// triggers a reorganization.
    pub fn submit(&mut self, block: Block) -> Result<()> {
        self.submit_at(block, None)
    }

    /// `now_ms` enables the non-consensus local-clock sanity check. Pass `None`
    /// when replaying historical blocks, where "now" is meaningless.
    pub fn submit_at(&mut self, block: Block, now_ms: Option<u64>) -> Result<()> {
        let hash = block.block_hash();
        if self.blocks.contains_key(&hash) {
            return Err(Error::AlreadyKnown);
        }
        if let Some(now) = now_ms {
            validate_local_clock(block.header.timestamp_ms, now, &self.params)?;
        }
        self.validate_standalone(&block)?;
        if !self.blocks.contains_key(&block.header.prev_hash) {
            return Err(Error::UnknownParent);
        }

        // Validate that the parent exists before recording work against it.
        let parent_work = self.cumulative_work(&block.header.prev_hash);
        let block_difficulty = block.header.difficulty; // before `block` is moved
        self.blocks.insert(hash, block);
        // Work is parent_work + this block's difficulty, computed once. Fork
        // choice reads it as an O(1) lookup instead of walking to genesis.
        self.work
            .insert(hash, parent_work.saturating_add(block_difficulty));

        let outcome = self.reselect(hash);
        if let Err(e) = &outcome {
            // A block that cannot be applied must not stay in the store.
            // `cumulative_work` sums the declared difficulty of every stored
            // block, so retaining an unusable one lets an attacker accumulate
            // chain weight that no reorganization can ever realize: fork choice
            // keeps selecting the dead branch and every honest block is
            // rejected until honest work catches up.
            //
            // A finality refusal is not that case: the block is valid, we
            // simply decline to reorganize to it, and dropping it would orphan
            // every later block already stacked on top of it.
            if !matches!(e, Error::ReorgWouldCrossFinality { .. }) {
                self.blocks.remove(&hash);
                self.work.remove(&hash);
            }
        }
        // Side branches outside the finality window are useless to us and
        // unbounded in supply (SPEC.md §13.10 item 2). Prune on a threshold so
        // the cost is amortised rather than paid per block.
        if self.blocks.len() > self.prune_threshold() {
            self.prune_side_branches();
        }
        outcome
    }

    /// Run fork choice over the stored blocks and apply whatever wins.
    fn reselect(&mut self, submitted: Hash) -> Result<()> {
        // Nothing is cleared here, and that is deliberate. Transactions
        // disconnected by an earlier reorg are still disconnected, and they stay
        // pending until the caller drains them — a reorg landing before the
        // caller gets a chance to reconcile must not wipe them. An earlier
        // version cleared this set on entry, so two reorgs in quick succession
        // (exactly what a syncing node sees) silently destroyed the first
        // reorg's transactions. Published sets are only ever *added* to, and only
        // after the reorg has committed.
        let target = self.best_candidate();
        if target != self.tip_hash() {
            return self.adopt(target);
        }
        let Some(b) = self.blocks.get(&submitted).cloned() else {
            return Ok(());
        };
        if b.header.prev_hash != self.tip_hash() {
            // A side block that lost fork choice: stored, not canonical.
            return Ok(());
        }
        // Extends the tip and nothing out-worked it. `apply_block` unwinds its
        // own writes on failure, so no snapshot is needed here.
        self.apply_block(&b)?;
        self.canon.push(submitted);
        Ok(())
    }

    fn adopt(&mut self, target: Hash) -> Result<()> {
        let new_canon = self.path_to(&target).ok_or(Error::UnknownParent)?;
        let saved = self.snapshot();

        let mut common = 0usize;
        while common < new_canon.len()
            && common < self.canon.len()
            && new_canon[common] == self.canon[common]
        {
            common += 1;
        }

        // A reorg must never rewrite finalized history. The check is on the
        // fork point alone: it used to be qualified with
        // `self.canon.len() > new_canon.len()`, which meant a rival that forked
        // below the finality point but ended up *longer* was adopted and
        // rewrote settled history.
        let finalized = self.finalized_height() as usize;
        if common <= finalized {
            self.restore(saved);
            return Err(Error::ReorgWouldCrossFinality {
                finalized_height: finalized as u64,
            });
        }

        // Collect what the reorg takes off the chain, oldest block first, so the
        // mempool can re-admit it. Recorded locally and published only once the
        // rival branch has applied cleanly — see `disconnected_txs`.
        let mut disconnected: Vec<Transaction> = Vec::new();
        for i in common..self.canon.len() {
            if let Some(block) = self.blocks.get(&self.canon[i]) {
                disconnected.extend(block.txs.iter().skip(1).cloned());
            }
        }

        for i in (common..self.canon.len()).rev() {
            let hash = self.canon[i];
            self.rollback_block(&hash);
        }
        self.canon.truncate(common);

        for hash in new_canon.iter().skip(common) {
            let Some(block) = self.blocks.get(hash).cloned() else {
                self.restore(saved);
                return Err(Error::UnknownParent);
            };
            if let Err(e) = self.apply_block(&block) {
                self.restore(saved);
                return Err(e);
            }
            self.canon.push(*hash);
        }
        // The rival branch applied cleanly, so the reorg actually happened and
        // those transactions are now genuinely unconfirmed. Extend rather than
        // assign: an earlier reorg's transactions may not have been drained yet,
        // and they are still unconfirmed.
        self.disconnected_txs.extend(disconnected);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Mining
    // -----------------------------------------------------------------

    fn build_block(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        let parent = self.tip().clone();
        let parent_hash = parent.block_hash();
        let height = parent.header.height + 1;

        let history = self.history(self.params.difficulty_window as usize + 1);
        let difficulty = difficulty_override
            .unwrap_or_else(|| next_difficulty(&self.params, parent.header.difficulty, &history));
        let base_fee = if height == 1 {
            self.params.base_fee_initial_sat
        } else {
            next_base_fee(
                &self.params,
                parent.header.base_fee_sat,
                parent.total_gas_used()?,
            )
        };
        let timestamp_ms =
            now_ms.max(crate::difficulty::median_previous_timestamp(&history).unwrap_or(0));

        // Fee split needs a UTXO view with the body applied. Do it on a copy.
        let mut probe = self.utxo.clone();
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;
        for tx in &body {
            let delta = check_tx(
                &probe,
                tx,
                height,
                &self.params,
                base_fee,
                self.params.coinbase_maturity,
            )?;
            probe.apply_tx(tx, height)?;
            total_gas = total_gas
                .checked_add(delta.gas_used)
                .ok_or(Error::ValueOverflow)?;
            total_fees = total_fees
                .checked_add(delta.fee_total)
                .ok_or(Error::ValueOverflow)?;
        }
        let split = split_fees(total_gas, total_fees, base_fee)?;
        let reward = block_reward_sat(&self.params, height);

        let claim = reward.saturating_add(split.tip);
        let cb_tx = Transaction::coinbase(
            parent_hash,
            height,
            Output {
                value: claim,
                address: miner_address,
            },
        );

        let mut txs = vec![cb_tx];
        txs.extend(body);
        let merkle = crate::block::merkle_root_with_l2(&txs, &l2_txs);

        let mut header = Header {
            version: crate::block::BLOCK_VERSION,
            height,
            prev_hash: parent_hash,
            merkle_root: merkle,
            timestamp_ms,
            base_fee_sat: base_fee,
            difficulty,
            nonce: 0,
            puzzle_id: self.params.puzzle_id,
            epoch_id: (height / self.params.nn_epoch_blocks) as u32,
            extra_nonce: [0u8; 16],
            sig_scheme: crate::hash::SIG_SCHEME_SECP256K1_ECDSA,
        };

        let mut nonce = 0u64;
        // The attempt budget is enforced here, in the loop that actually does
        // the work. It used to be applied only by the second loop in
        // `mine_block_with`, which is unreachable until this one has already
        // finished: a hostile retarget or a mis-set difficulty therefore hung
        // the node regardless of the cap its caller had asked for.
        for _ in 0..max_attempts {
            header.nonce = nonce;
            if self.solver.satisfies(&header)? {
                return Ok(Block {
                    header,
                    signature: [0u8; 64],
                    signer_pubkey: [0u8; 33],
                    txs,
                    // Cloned rather than moved: the value is also needed by the
                    // unmined block below. One clone per *successful* mine, in
                    // exchange for not threading it through the loop.
                    l2_txs: l2_txs.clone(),
                });
            }
            nonce = nonce.wrapping_add(1);
        }
        let unmined = Block {
            header,
            signature: [0u8; 64],
            signer_pubkey: [0u8; 33],
            txs,
            // Reported through the error's hash, so it must be the block that
            // would have been produced — L2 payload included.
            l2_txs,
        };
        Err(Error::PowInvalid {
            hash: crate::hash::hash_to_hex(&unmined.block_hash()),
            difficulty: unmined.header.difficulty,
        })
    }

    /// Mine the next block on top of the tip.
    pub fn mine_block(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<Block> {
        self.mine_block_with(miner_address, body, now_ms, None, DEFAULT_MAX_ATTEMPTS)
    }

    /// Mining with an explicit attempt cap, so a mis-set difficulty or a hostile
    /// retarget cannot hang a node forever. The override is for tests and for
    /// the difficulty-attack harness; a real miner loops without a cap.
    pub fn mine_block_with(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        self.build_block(
            miner_address,
            body,
            Vec::new(),
            now_ms,
            difficulty_override,
            max_attempts,
        )
    }

    /// Mine a block that also carries L2 transactions (Decision 6, SPEC.md §19.1).
    ///
    /// Additive rather than a new parameter on `mine_block_with`: every existing
    /// caller mines L1-only blocks, and threading an empty vector through all of
    /// them would be churn with no behaviour attached. The block's merkle root
    /// covers both lists, so the header commits to the L2 payload exactly as it
    /// commits to the L1 one.
    ///
    /// Note what this does *not* do: it does not validate the L2 transactions.
    /// L2 validity is not an L1 block rule (Decision 6) — the miner is expected
    /// to have applied them to its own L2 state first, and a peer that disagrees
    /// still reaches the same L2 state by replaying the same bytes.
    pub fn mine_block_with_l2(
        &mut self,
        miner_address: crate::hash::Address,
        body: Vec<Transaction>,
        l2_txs: Vec<crate::l2::L2Transaction>,
        now_ms: u64,
        difficulty_override: Option<u128>,
        max_attempts: u64,
    ) -> Result<Block> {
        self.build_block(
            miner_address,
            body,
            l2_txs,
            now_ms,
            difficulty_override,
            max_attempts,
        )
    }

    /// Mine the next block out of `pool`, submit it, and evict what it confirmed.
    ///
    /// Selection happens against the *next* block's height and base fee, which are
    /// the same numbers `build_block` re-checks every transaction against, so a
    /// selection `check_tx` would reject cannot be produced here.
    ///
    /// **The three steps are one function deliberately.** Mining, submitting and
    /// evicting were briefly separate, and the split is wrong in a way that is easy
    /// to miss: a mined block is not a confirmed transaction until it wins fork
    /// choice. A peer's heavier block arriving at the same height leaves ours as a
    /// side branch, and evicting on "mined" rather than on "canonical" would then
    /// silently drop transactions the chain never confirmed. Submitting inside
    /// means the eviction decision is made against what actually became canonical.
    pub fn mine_from_pool(
        &mut self,
        pool: &mut Mempool,
        miner_address: crate::hash::Address,
        now_ms: u64,
    ) -> Result<Block> {
        let cursor = self.height();
        let body = pool.select_for_block(self.params.gas_cap, self.params.max_block_bytes);
        // Pool mining is L1-only: the mempool holds L1 transactions. L2
        // transactions are carried by `mine_block_with_l2`.
        let block = self.build_block(
            miner_address,
            body,
            Vec::new(),
            now_ms,
            None,
            DEFAULT_MAX_ATTEMPTS,
        )?;
        self.submit_at(block.clone(), Some(now_ms))?;
        // Eviction is derived from the **canonical chain**, never from the fact
        // that we mined something. `reconcile_mempool` evicts what canonical
        // blocks above the cursor confirm, so a mined block that lost fork choice
        // evicts nothing with no special case, and a competing block that won
        // evicts its own transactions instead. An earlier version evicted the
        // block we had just built, guarded by a `tip_hash() == hash` check; that
        // guard is unreachable on today's single-threaded chain loop, which makes
        // it untestable rather than wrong — and an eviction rule that cannot be
        // exercised is one nobody will notice breaking.
        //
        // Only what the chain confirms is evicted, never the whole selection: a
        // transaction the gas or byte cap left out is still the best candidate
        // for the next block.
        let _ = self.reconcile_mempool(pool, cursor);
        Ok(block)
    }

    /// Transactions of canonical blocks in `(from_height, tip]`, oldest first.
    ///
    /// `from_height` is the caller's cursor — the height it last reconciled the
    /// pool against. At or above the tip this returns nothing, which is the
    /// common case and costs a bounds check.
    pub fn confirmed_above(&self, from_height: u64) -> Vec<Transaction> {
        let mut out = Vec::new();
        for height in from_height.saturating_add(1)..self.canon.len() as u64 {
            if let Some(block) = self.block_at(height) {
                out.extend(block.txs.iter().skip(1).cloned());
            }
        }
        out
    }

    /// Take the transactions the most recent reorg disconnected.
    ///
    /// Draining rather than reading, because re-admission must happen exactly
    /// once per reorg: a transaction re-admitted twice is at best redundant, and
    /// after the pool has changed it is a conflict against itself.
    pub fn take_disconnected(&mut self) -> Vec<Transaction> {
        std::mem::take(&mut self.disconnected_txs)
    }

    /// Keep `pool` in step with this chain: evict what the canonical chain now
    /// confirms, re-admit what a reorg un-confirmed.
    ///
    /// Returns the height the pool is now reconciled to, plus what moved. Holding
    /// that cursor is the caller's job, and it is the only state this needs:
    /// after a restart the pool is empty too, so reconciling from the tip is both
    /// correct and free.
    pub fn reconcile_mempool(
        &mut self,
        pool: &mut Mempool,
        from_height: u64,
    ) -> (u64, ReconcileReport) {
        let tip_height = self.height();
        let confirmed = self.confirmed_above(from_height);
        let disconnected = self.take_disconnected();
        let report = pool.reconcile(
            self.utxo(),
            tip_height + 1,
            &self.params,
            self.expected_base_fee_for_next_block(),
            &confirmed,
            &disconnected,
        );
        (tip_height, report)
    }

    /// Cumulative difficulty of the canonical chain. This is what fork choice
    /// compares, so it is also the honest measure of "heavier".
    pub fn total_work(&self) -> u128 {
        self.cumulative_work(&self.tip_hash())
    }

    /// Number of blocks in the store, canonical and side branch alike.
    pub fn stored_block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Drop side branches the node can no longer act on. SPEC.md §13.10 item 2.
    ///
    /// Canonical history is kept in full: undo records, `verify_canonical_chain`
    /// and the persistence layer all replay from genesis, and history below the
    /// tip is the node's own, not a peer's. What is dropped is every
    /// **non-canonical** block at or below `tip − finality_depth`, plus any
    /// stored descendant of a dropped block, since a block whose parent is gone
    /// cannot be applied or walked to (`path_to` would fail).
    ///
    /// This closes the growth vector §13.10 item 2 exists for: a peer could
    /// submit an unbounded number of valid side blocks, each retained forever,
    /// with no work of its own. It also resolves a long-standing behaviour
    /// question — see `docs/status.md`: a branch that forked *below* the
    /// finality point used to be retained with its work counted, so fork choice
    /// kept selecting it and honest blocks were refused until honest work caught
    /// up. Once forgotten, the node accepts honest blocks again. The §9.3
    /// finality rule is unchanged: a reorg across it is still refused.
    fn prune_side_branches(&mut self) -> usize {
        let tip_height = self.height();
        let cutoff = tip_height.saturating_sub(self.params.finality_depth);

        let mut canonical: HashMap<Hash, ()> = HashMap::with_capacity(self.canon.len());
        for hash in &self.canon {
            canonical.insert(*hash, ());
        }

        // Decide by ascending height so a block is only dropped after its parent
        // has been decided; a survivor therefore always has a surviving parent.
        let mut by_height: Vec<(u64, Hash)> = self
            .blocks
            .iter()
            .map(|(h, b)| (b.header.height, *h))
            .collect();
        by_height.sort_unstable();

        let mut keep: HashMap<Hash, ()> =
            HashMap::with_capacity(self.canon.len() + by_height.len());
        for hash in &self.canon {
            keep.insert(*hash, ());
        }

        let mut dropped = Vec::new();
        for (height, hash) in by_height {
            if canonical.contains_key(&hash) {
                continue;
            }
            if height > cutoff {
                // Above the window: keep only if it chains to something kept.
                let parent_kept = self
                    .blocks
                    .get(&hash)
                    .map(|b| keep.contains_key(&b.header.prev_hash))
                    .unwrap_or(false);
                if parent_kept {
                    keep.insert(hash, ());
                } else {
                    dropped.push(hash);
                }
            } else {
                dropped.push(hash);
            }
        }

        for hash in &dropped {
            self.blocks.remove(hash);
            self.work.remove(hash);
            self.undo.remove(hash);
            self.pscb_undo.remove(hash);
        }
        dropped.len()
    }

    /// Base fee the next block must carry. A wallet building a transaction has
    /// to know this, and duplicating the schedule in the client is how clients
    /// end up paying a fee the node then rejects.
    pub fn expected_base_fee_for_next_block(&self) -> u64 {
        let parent = self.tip();
        if parent.header.height == 0 {
            self.params.base_fee_initial_sat
        } else {
            // A canonical block's gas total cannot overflow (validate_standalone
            // rejects anything over the cap); fall back to the cap if it somehow
            // does rather than panicking on a display path.
            let gas = parent.total_gas_used().unwrap_or(self.params.gas_cap);
            next_base_fee(&self.params, parent.header.base_fee_sat, gas)
        }
    }

    /// Difficulty the next block must carry.
    pub fn expected_difficulty_for_next_block(&self) -> u128 {
        let history = self.history(self.params.difficulty_window as usize + 1);
        next_difficulty(&self.params, self.tip().header.difficulty, &history)
    }

    /// Coinbase maturity check for a UTXO entry at the next height.
    pub fn is_mature(&self, height: u64) -> bool {
        height + self.params.coinbase_maturity <= self.height() + 1
    }

    /// Replay the whole canonical chain from genesis and compare the result with
    /// the live state. Used by `jnt-node verify` and after every reorg in tests:
    /// if undo data were wrong, a replay would diverge here.
    pub fn verify_canonical_chain(&self) -> Result<()> {
        let mut probe = Chain::new(self.params.clone())?;
        if probe.canon[0] != self.canon[0] {
            return Err(Error::BadPrevHash);
        }
        for hash in self.canon.iter().skip(1) {
            let block = self.blocks.get(hash).ok_or(Error::UnknownParent)?;
            probe.validate_standalone(block)?;
            probe.blocks.insert(*hash, block.clone());
            probe.apply_block(block)?;
            probe.canon.push(*hash);
        }
        if probe.canon != self.canon {
            return Err(Error::Malformed("canonical path differs from replay"));
        }
        if probe.utxo.len() != self.utxo.len() {
            return Err(Error::Malformed("utxo entry count diverged on replay"));
        }
        if probe.utxo.total_value() != self.utxo.total_value() {
            return Err(Error::Malformed("utxo value diverged on replay"));
        }
        // M1's PSCB reserve is part of live state and is rewound on reorg, so a
        // wrong undo there would silently accumulate or lose funds. It was not
        // checked at all, which made `verify` blind to the one thing M1 added.
        if probe.pscb_reserve != self.pscb_reserve {
            return Err(Error::Malformed("pscb reserve diverged on replay"));
        }
        if probe.pscb_undo != self.pscb_undo {
            return Err(Error::Malformed("pscb undo records diverged on replay"));
        }
        Ok(())
    }

    /// Provable statements for `status` / the whitepaper.
    pub fn supply_report(&self) -> SupplyReport {
        SupplyReport {
            cap_sat: self.params.supply_cap_sat,
            reachable_sat: max_issuance_sat(&self.params),
            live_sat: self.utxo.total_value(),
            height: self.height(),
            reward_sat: block_reward_sat(&self.params, self.height() + 1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupplyReport {
    pub cap_sat: u64,
    pub reachable_sat: u64,
    pub live_sat: u64,
    pub height: u64,
    pub reward_sat: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Address;
    use crate::wallet::Wallet;

    fn addr(tag: u8) -> Address {
        [tag; 20]
    }

    fn ts(height: u64) -> u64 {
        crate::block::GENESIS_TIMESTAMP_MS + height * 1_000
    }

    /// Timestamps for a chain whose difficulty has genuinely risen above 1.
    ///
    /// Spacing is half a target-time, so the weighted average solve time is
    /// *below* target and the retarget rule raises difficulty. Spacing blocks
    /// out instead would lower difficulty, which is the correct response to
    /// slow blocks and would leave this at the genesis difficulty of 1.
    fn fast_ts(height: u64) -> u64 {
        let t = NetworkParams::mini().target_block_time_ms;
        crate::block::GENESIS_TIMESTAMP_MS + height * (t / 2)
    }

    #[test]
    fn genesis_is_valid_and_mines_nothing() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        assert_eq!(chain.height(), 0);
        assert_eq!(
            chain.total_supply_sat(),
            0,
            "0% premine is enforced in code"
        );
        let genesis = chain.tip().clone();
        chain.validate_standalone(&genesis).unwrap();
    }

    #[test]
    fn mines_and_extends_a_chain() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=8u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
            assert_eq!(chain.height(), h);
            assert_eq!(
                chain.total_supply_sat(),
                block_reward_sat(chain.params(), h) * h
            );
        }
        chain.verify_canonical_chain().unwrap();
    }

    #[test]
    fn coinbase_matures_then_can_be_spent() {
        let miner = Wallet::new_random("miner");
        let miner_addr = miner.address().unwrap();
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=11u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let reward = block_reward_sat(chain.params(), 11);
        assert_eq!(chain.total_supply_sat(), reward * 11);
        // Eleven coinbases exist; maturity only decides which may be *spent*.
        assert_eq!(chain.utxo().outputs_for_address(&miner_addr).len(), 11);

        // A matured coinbase pays a fee large enough to clear the burned base fee, so
        // the maturity rule is what decides the outcome, not the fee rule.
        let burn_fee = chain.tip().header.base_fee_sat * 100_000 + 1;

        let immature = OutPoint {
            txid: chain.block_at(11).unwrap().txs[0].txid(),
            index: 0,
        };
        let tx = signed_spend(&miner, immature, reward - 1 - burn_fee, [8u8; 20]);
        assert!(matches!(
            crate::ledger::check_tx(
                chain.utxo(),
                &tx,
                11,
                chain.params(),
                chain.tip().header.base_fee_sat,
                chain.params().coinbase_maturity,
            ),
            Err(Error::ImmatureCoinbase { .. })
        ));

        let mature = OutPoint {
            txid: chain.block_at(1).unwrap().txs[0].txid(),
            index: 0,
        };
        let tx = signed_spend(&miner, mature, reward - 1 - burn_fee, [8u8; 20]);
        let delta = crate::ledger::check_tx(
            chain.utxo(),
            &tx,
            11,
            chain.params(),
            chain.tip().header.base_fee_sat,
            chain.params().coinbase_maturity,
        )
        .unwrap();
        assert_eq!(delta.fee_total, burn_fee + 1);
    }

    /// Build a correctly signed 1-in 1-out spend of `op`, for rule checks that
    /// need a real transaction without mining one.
    fn signed_spend(wallet: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
        let mut tx = Transaction::standard(
            vec![crate::tx::Input::unsigned(&op)],
            vec![crate::tx::Output {
                value: pay,
                address: to,
            }],
        );
        wallet.sign(&mut tx).unwrap();
        tx
    }

    #[test]
    fn duplicate_submission_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let b = chain.mine_block(addr(1), vec![], ts(1)).unwrap();
        chain.submit(b.clone()).unwrap();
        assert!(matches!(chain.submit(b), Err(Error::AlreadyKnown)));
    }
    #[test]
    fn tampering_with_a_header_breaks_the_proof_of_work() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=6u64 {
            let b = chain.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let tip = chain.tip().clone();
        assert!(tip.header.difficulty > 1, "difficulty must exceed 1");

        // Merkle commitment and difficulty are checked before the proof, so
        // those two are deterministic rejections.
        let mut bad = tip.clone();
        bad.header.merkle_root[0] ^= 1;
        assert!(matches!(chain.submit(bad), Err(Error::BadMerkleRoot)));

        // A difficulty the retarget rule would not produce is rejected by the
        // state rules even though the proof itself is fine for that difficulty.
        let mut easy = tip.clone();
        easy.header.difficulty = 1;
        easy.header.nonce = 0;
        chain.validate_standalone(&easy).unwrap();
        // Too little work to become the tip, so it is merely stored as a side
        // block; the fork-choice rule is what keeps it out.
        chain.submit(easy).unwrap();
        assert_eq!(chain.tip_hash(), tip.block_hash());

        // Now a high-difficulty block where a single header bit is flipped.
        // At 2^18 work a lucky pass has probability 2^-18.
        let hard = chain
            .mine_block_with(addr(1), vec![], fast_ts(7), Some(1u128 << 18), 4_000_000)
            .unwrap();
        chain.validate_standalone(&hard).unwrap();
        let mut flipped = hard.clone();
        flipped.header.extra_nonce[7] ^= 1;
        assert_ne!(flipped.block_hash(), hard.block_hash());
        assert!(matches!(
            chain.validate_standalone(&flipped),
            Err(Error::PowInvalid { .. })
        ));
    }

    #[test]
    fn wrong_difficulty_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=6u64 {
            let b = chain.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        let expected = chain.tip().header.difficulty;

        // Mine honestly, then declare a difficulty the retarget rule would never
        // produce. The proof is valid for the declared difficulty, so only the
        // state rules can catch it. Note the +1: at this spacing the rule
        // raises difficulty by exactly one per block, so `expected + 1` is
        // what it *would* legitimately produce and must not be used here.
        let wrong = chain
            .mine_block_with(addr(1), vec![], fast_ts(7), Some(expected * 10), 500_000)
            .unwrap();
        chain.validate_standalone(&wrong).unwrap();
        assert!(matches!(
            chain.submit(wrong),
            Err(Error::BadDifficulty { .. })
        ));
        assert_eq!(chain.height(), 6, "a rejected block must not be adopted");
    }

    #[test]
    fn wrong_epoch_is_rejected() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let b = chain.mine_block(addr(1), vec![], ts(1)).unwrap();
        chain.validate_standalone(&b).unwrap();

        let mut wrong = b.clone();
        wrong.header.epoch_id = 7;
        assert!(matches!(
            chain.validate_standalone(&wrong),
            Err(Error::BadEpoch { .. })
        ));
    }

    #[test]
    fn heavier_fork_wins_and_state_rewinds() {
        // Node A: 1..=4.
        let mut a = Chain::new(NetworkParams::mini()).unwrap();
        let mut a_blocks = Vec::new();
        for h in 1..=4u64 {
            let b = a.mine_block(addr(1), vec![], ts(h)).unwrap();
            a.submit(b.clone()).unwrap();
            a_blocks.push(b);
        }
        let a_tip = a.tip_hash();

        // Node B: 1..=8, shared prefix then its own branch.
        let mut b = Chain::new(NetworkParams::mini()).unwrap();
        let mut b_blocks = Vec::new();
        for h in 1..=2u64 {
            let blk = b.mine_block(addr(1), vec![], ts(h)).unwrap();
            b.submit(blk.clone()).unwrap();
            b_blocks.push(blk);
        }
        for h in 3..=8u64 {
            let blk = b.mine_block(addr(9), vec![], ts(h)).unwrap();
            b.submit(blk.clone()).unwrap();
            b_blocks.push(blk);
        }
        assert_eq!(b.height(), 8);
        let b_tip = b.tip_hash();

        // Deliver B's blocks to A in an adversarial order.
        assert!(matches!(
            a.submit(b_blocks[7].clone()),
            Err(Error::UnknownParent)
        ));
        assert!(matches!(
            a.submit(b_blocks[0].clone()),
            Err(Error::AlreadyKnown)
        ));
        assert!(matches!(
            a.submit(b_blocks[1].clone()),
            Err(Error::AlreadyKnown)
        ));
        for blk in b_blocks.iter().skip(2) {
            a.submit(blk.clone()).unwrap();
        }

        assert_eq!(a.height(), 8);
        assert_eq!(a.tip_hash(), b_tip, "heavier branch must win");
        assert_ne!(a.tip_hash(), a_tip);
        assert_eq!(
            a.total_supply_sat(),
            b.total_supply_sat(),
            "state must rewind"
        );
        a.verify_canonical_chain().unwrap();

        // The abandoned branch is still stored, just no longer canonical.
        assert!(a.block_by_hash(&a_tip).is_some());
        assert_ne!(a.block_at(4).unwrap().block_hash(), a_tip);
    }

    #[test]
    fn fork_choice_prefers_more_work_at_equal_height() {
        // Both branches reach height 3. The rival's blocks arrive slowly, so the
        // retarget rule raises its difficulty and it ends up carrying more work.
        let mut main = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=3u64 {
            let blk = main.mine_block(addr(1), vec![], ts(h)).unwrap();
            main.submit(blk).unwrap();
        }
        let main_tip = main.tip_hash();
        assert_eq!(main.tip().header.difficulty, 1);

        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=2u64 {
            let blk = rival.mine_block(addr(1), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        // The rival's prefix diverges at height 1 (slow timestamps), so this is
        // a genuine competitor rather than the same chain.
        assert_ne!(
            rival_blocks[0].block_hash(),
            main.block_at(1).unwrap().block_hash()
        );

        let mut heavy = Vec::new();
        for h in 3..=3u64 {
            let blk = rival.mine_block(addr(5), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            heavy.push(blk);
        }
        assert!(rival.tip().header.difficulty > 1);

        for blk in rival_blocks.iter().chain(heavy.iter()) {
            main.submit(blk.clone()).unwrap();
        }
        assert_eq!(main.height(), 3, "equal height, but more work must win");
        assert_eq!(main.tip_hash(), heavy[0].block_hash());
        assert_ne!(main.tip_hash(), main_tip);
    }

    #[test]
    fn reorg_cannot_rewrite_finalized_history() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=25u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        assert_eq!(chain.finalized_height(), 5);

        // A rival chain that forks at genesis and climbs in difficulty. Delivering its
        // tip would rewrite finalized history, so it must be refused no matter how
        // much work it carries.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=20u64 {
            let blk = rival.mine_block(addr(7), vec![], fast_ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        assert!(
            rival.total_work() > chain.total_work(),
            "the rival must carry more work ({}) than the tip ({}) for this test to mean anything",
            rival.total_work(),
            chain.total_work()
        );

        let mut rejected = 0;
        for blk in rival_blocks.iter() {
            if let Err(e) = chain.submit(blk.clone()) {
                assert!(
                    matches!(e, Error::ReorgWouldCrossFinality { .. }),
                    "unexpected rejection reason: {e}"
                );
                rejected += 1;
            }
        }
        assert!(
            rejected > 0,
            "a reorg across the finality point was accepted"
        );
        assert_eq!(
            chain.height(),
            25,
            "tip must be unchanged after a rejected reorg"
        );
        chain.verify_canonical_chain().unwrap();
    }

    #[test]
    fn reorg_inside_the_finality_window_is_allowed() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=25u64 {
            let b = chain.mine_block(addr(1), vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }
        // Rival forks at height 24, which is above finalized_height() == 5.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        let mut rival_blocks = Vec::new();
        for h in 1..=23u64 {
            let blk = rival.mine_block(addr(1), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        let old_tip = chain.tip_hash();
        for h in 24..=27u64 {
            let blk = rival.mine_block(addr(4), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        for blk in rival_blocks.iter().skip(23) {
            chain.submit(blk.clone()).unwrap();
        }
        assert_eq!(chain.height(), 27);
        assert_ne!(chain.tip_hash(), old_tip);
        chain.verify_canonical_chain().unwrap();
    }

    #[test]
    fn a_paid_transaction_moves_value_and_burns_the_base_fee() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = Wallet::new_random("miner");
        let alice = Wallet::new_random("alice");
        let miner_addr = miner.address().unwrap();
        let alice_addr = alice.address().unwrap();

        for h in 1..=12u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }

        // A matured coinbase pays Alice.
        let coinbase = chain.block_at(1).unwrap();
        let op = OutPoint {
            txid: coinbase.txs[0].txid(),
            index: 0,
        };
        let spendable = chain.utxo().get(&op).expect("matured coinbase").out.value;
        let base_fee = chain.tip().header.base_fee_sat;

        // Spend half of it, paying a fee comfortably above the burned base fee.
        let send = spendable / 2;
        let fee = base_fee * 50_000 + 1_000;
        let tx = miner
            .build_tx(
                &[op],
                vec![crate::tx::Output {
                    value: send,
                    address: alice_addr,
                }],
                fee,
            )
            .unwrap();

        let supply_before = chain.total_supply_sat();
        let gas_used = tx.gas_used();

        let b = chain.mine_block(miner_addr, vec![tx], ts(13)).unwrap();
        // The burned amount must be read from the block that was actually mined:
        // its base fee follows the schedule, not the previous block's.
        let burned = b.header.base_fee_sat * gas_used;
        chain.submit(b).unwrap();
        chain.verify_canonical_chain().unwrap();

        assert_eq!(
            chain.utxo().outputs_for_address(&alice_addr),
            vec![(
                OutPoint {
                    txid: chain.block_at(13).unwrap().txs[1].txid(),
                    index: 0
                },
                send
            )]
        );
        // A coinbase was minted, but the base fee was burned on top of it.
        let reward = block_reward_sat(chain.params(), 13);
        assert!(
            burned > 0,
            "the test is only meaningful when something is actually burned"
        );
        assert_eq!(
            chain.total_supply_sat(),
            supply_before + reward - burned,
            "base fee must be destroyed, not redistributed"
        );
    }

    /// M1's PSCB reserve must survive a reorganization intact: credited per
    /// canonical block, rewound per rolled-back block, and equal to the sum a
    /// clean replay produces. Before the M1 checks were added to
    /// `verify_canonical_chain`, `jnt-node verify` could not see a PSCB bug at
    /// all — it compared the UTXO set only.
    #[test]
    fn the_pscb_reserve_is_rewound_exactly_on_reorg() {
        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = Wallet::new_random("miner");
        let alice = Wallet::new_random("alice");
        let miner_addr = miner.address().unwrap();
        let alice_addr = alice.address().unwrap();

        for h in 1..=12u64 {
            let b = chain.mine_block(miner_addr, vec![], ts(h)).unwrap();
            chain.submit(b).unwrap();
        }

        // A block that pays a fee, so a non-zero PSCB credit exists.
        let op = OutPoint {
            txid: chain.block_at(1).unwrap().txs[0].txid(),
            index: 0,
        };
        let spendable = chain.utxo().get(&op).unwrap().out.value;
        let fee = chain.expected_base_fee_for_next_block() * 50_000 + 1_000;
        let tx = miner
            .build_tx(
                &[op],
                vec![Output {
                    value: spendable / 2,
                    address: alice_addr,
                }],
                fee,
            )
            .unwrap();
        let gas_used = tx.gas_used();
        let paid = chain.mine_block(miner_addr, vec![tx], ts(13)).unwrap();
        // PSCB is 50% of the base-fee portion, not of the whole fee: the tip
        // above it belongs to the miner (§8, M1).
        let base_portion = paid.header.base_fee_sat * gas_used;
        chain.submit(paid).unwrap();

        let reserve_with_fee = chain.pscb_reserve();
        assert!(reserve_with_fee > 0, "no PSCB was credited for the fee");
        assert_eq!(
            reserve_with_fee,
            base_portion / 2,
            "PSCB is 50% of the base-fee portion"
        );

        // Reorg inside the finality window: fork at 11 and rebuild 12..=15.
        let mut rival = Chain::new(NetworkParams::mini()).unwrap();
        for h in 1..=10u64 {
            let blk = rival.mine_block(miner_addr, vec![], ts(h)).unwrap();
            rival.submit(blk).unwrap();
        }
        assert_eq!(
            rival.tip_hash(),
            chain.block_hash_at(10).unwrap(),
            "the rival must share the prefix"
        );
        let mut rival_blocks = Vec::new();
        for h in 11..=15u64 {
            let blk = rival.mine_block(addr(9), vec![], ts(h)).unwrap();
            rival.submit(blk.clone()).unwrap();
            rival_blocks.push(blk);
        }
        assert!(rival.total_work() > chain.total_work());
        for blk in rival_blocks {
            chain.submit(blk).unwrap();
        }

        assert_eq!(chain.height(), 15);
        assert_eq!(
            chain.pscb_reserve(),
            0,
            "the paying block was rolled back, so its PSCB credit must be rewound"
        );
        chain
            .verify_canonical_chain()
            .expect("pscb state diverged from a clean replay");
    }
}
