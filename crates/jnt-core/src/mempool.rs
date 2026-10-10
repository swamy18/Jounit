//! Unconfirmed transaction pool. Roadmap §7 Step 1.
//!
//! A mempool is the first place a peer can push *data* at a node without doing
//! any work for it — no PoW, no block. Everything here is therefore an attack
//! surface, and each rule below exists because the naive version walks into a
//! specific failure.
//!
//! What the pool is, and what it is not:
//!
//! - It holds transactions valid **against current chain state**. That is a
//!   snapshot, not a promise: a reorg invalidates entries, which is why
//!   eviction is driven by actual blocks rather than assumed.
//! - It is **not** consensus. A pooled transaction has no more standing than one
//!   that arrived inside a block, and `check_tx` remains the only authority on
//!   validity. A pool that disagrees with the chain loses.
//! - It never lowers a fee to make something fit. Fees are the user's decision;
//!   the pool only orders by them.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bond::BondLedger;
use crate::fees::required_fee;
use crate::hash::Hash;
use crate::ledger::{check_tx, UtxoSet};
use crate::params::NetworkParams;
use crate::tx::{OutPoint, Transaction};

/// Why a transaction was refused. Distinct from `crate::Error`: a mempool
/// refusal is almost never a consensus violation, it is usually the pool
/// working correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    AlreadyKnown,
    /// Spends an output another pooled transaction already spends.
    ///
    /// The double spend itself is also caught at block time, so admitting both is
    /// not an inflation bug — it is a liveness bug. Whichever transaction loses
    /// fork choice takes its input with it and silently evicts the other, so the
    /// pool's contents would depend on a race rather than on fees.
    Conflict {
        outpoint: OutPoint,
    },
    Invalid(String),
    Full,
    /// Larger than a whole block, so no block can ever include it.
    Oversized {
        size: usize,
        limit: usize,
    },
    Underpaid {
        required: u64,
        offered: u64,
    },
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::AlreadyKnown => write!(f, "already in mempool"),
            MempoolError::Conflict { outpoint } => write!(
                f,
                "double spend of {}:{}",
                hex::encode(outpoint.txid),
                outpoint.index
            ),
            MempoolError::Invalid(why) => write!(f, "invalid: {why}"),
            MempoolError::Full => write!(f, "mempool is full"),
            MempoolError::Oversized { size, limit } => write!(
                f,
                "transaction of {size} bytes exceeds the {limit} byte block limit"
            ),
            MempoolError::Underpaid { required, offered } => {
                write!(f, "fee {offered} below required {required}")
            }
        }
    }
}

impl std::error::Error for MempoolError {}

/// One pooled transaction.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    /// `fee_total / gas_used`, the ordering key.
    ///
    /// A *rate*, not a total, because a block has a gas budget and not a byte
    /// budget. Ordering by the total inverts the incentive: a large transaction
    /// would outrank a small one paying several times as much per unit of work.
    pub fee_rate: u64,
    pub fee_total: u64,
    pub gas_used: u64,
    /// Height this was accepted against, used as a deterministic tiebreak.
    pub accepted_at: u64,
}

impl MempoolEntry {
    /// Real serialized size, not an estimate. The point of the cap is to bound
    /// real memory, and a structural estimate drifts from the thing it models.
    pub fn size_bytes(&self) -> usize {
        self.tx.serialize().len()
    }
}

/// Bounded pool of unconfirmed transactions.
#[derive(Debug, Clone)]
pub struct Mempool {
    entries: BTreeMap<Hash, MempoolEntry>,
    /// Reverse index: outpoint -> the pooled transaction consuming it.
    ///
    /// Without this, conflict detection is O(n) per admission and there is no
    /// way to find the *dependent* transactions when an entry is evicted.
    spends: HashMap<OutPoint, Hash>,
    max_bytes: usize,
    bytes: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_BYTES)
    }
}

impl Mempool {
    /// 32 MiB — roughly 2 000 maximum-size blocks, which is the point of the
    /// number: the pool must never be the reason a block cannot be filled.
    pub const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

    /// Minimum satoshi-per-gas to be worth pooling. A transaction paying only
    /// the base fee costs every peer bandwidth and will eventually be mined, so
    /// admitting it lets a peer fill the pool with transactions nobody wants.
    pub const MIN_FEE_RATE: u64 = 1;

    pub fn new(max_bytes: usize) -> Self {
        Mempool {
            entries: BTreeMap::new(),
            spends: HashMap::new(),
            max_bytes,
            bytes: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size_bytes(&self) -> usize {
        self.bytes
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Iterate the pool in txid order — the same order on any two nodes
    /// holding the same set (a `BTreeMap`, never hashed iteration). The
    /// service API reads the pool through this.
    pub fn entries(&self) -> impl Iterator<Item = (&Hash, &MempoolEntry)> {
        self.entries.iter()
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.entries.contains_key(txid)
    }

    /// Every pooled txid, in ascending order.
    ///
    /// Ascending, not insertion order: a node announcing its pool to a new peer
    /// must announce the same *prefix* of it as any other node holding the same
    /// entries, or which transactions get announced when the pool is larger than
    /// one `INV` becomes a function of local history. Ordering by txid is a
    /// property of the entries alone.
    pub fn txids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }

    pub fn get(&self, txid: &Hash) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// Admit a transaction, validated against the state the **next** block will
    /// be built on.
    ///
    /// `height` is the height it would be mined at and `base_fee` the fee that
    /// block will carry. Getting either wrong admits transactions the node will
    /// reject when it builds a block, wasting every peer that relayed them.
    pub fn add(
        &mut self,
        tx: Transaction,
        utxo: &UtxoSet,
        height: u64,
        params: &NetworkParams,
        base_fee: u64,
        bonds: &BondLedger,
    ) -> Result<Hash, MempoolError> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyKnown);
        }

        let delta = check_tx(
            utxo,
            &tx,
            height,
            params,
            base_fee,
            params.coinbase_maturity,
        )
        .map_err(|e| MempoolError::Invalid(e.to_string()))?;

        // Stake overlay (Decision 20): the pool never holds what a block
        // would refuse. Full verification including the BLS pairing, like the
        // ECDSA checks `check_tx` already does at admission — same class of
        // relay cost, and the alternative (pooling slash txs no block can
        // include) is pool pollution by construction.
        if tx.is_stake_tx() {
            crate::bond::admit_stake_tx(
                &tx,
                bonds,
                &params.network_id,
                height,
                &crate::bls::RealBls,
            )
            .map_err(|e| MempoolError::Invalid(e.to_string()))?;
        }

        let required = required_fee(base_fee, delta.gas_used);
        if delta.fee_total < required {
            return Err(MempoolError::Underpaid {
                required,
                offered: delta.fee_total,
            });
        }

        // Conflict check before the size check, so a double spend is reported as
        // a double spend and never as "pool full". A pool that reports the wrong
        // reason cannot be debugged by its operator.
        for input in &tx.inputs {
            let op = input.outpoint();
            if self.spends.contains_key(&op) {
                return Err(MempoolError::Conflict { outpoint: op });
            }
        }

        let entry = MempoolEntry {
            // `gas_used` is never zero for a real transaction — `GAS_TX_BASE`
            // alone is 16 000 — but a division by zero panics, and a panic driven
            // by peer-supplied data is a denial of service. A zero-gas transaction
            // is treated as infinitely cheap per unit of work and sorted first
            // rather than crashing the node that relays it.
            fee_rate: delta
                .fee_total
                .checked_div(delta.gas_used)
                .unwrap_or(u64::MAX)
                .max(Self::MIN_FEE_RATE),
            fee_total: delta.fee_total,
            gas_used: delta.gas_used,
            accepted_at: height,
            tx,
        };

        let size = entry.size_bytes();
        // A transaction larger than a whole block can never be included by any
        // block, so pooling it wastes the bandwidth of every peer that relays it
        // and it can never be mined by anyone. Not a new consensus rule: it is
        // what `max_block_bytes` already implies. Enforced here rather than at
        // the wire because the wire has no correct answer — a relay-time size cap
        // tighter than `max_block_bytes` would make a transaction that consensus
        // accepts permanently unrelayable, which is censorship (SPEC.md §13.14).
        if size > params.max_block_bytes {
            return Err(MempoolError::Oversized {
                size,
                limit: params.max_block_bytes,
            });
        }
        if self.bytes + size > self.max_bytes {
            return Err(MempoolError::Full);
        }

        for input in &entry.tx.inputs {
            self.spends.insert(input.outpoint(), txid);
        }
        self.bytes += size;
        self.entries.insert(txid, entry);
        Ok(txid)
    }

    /// Choose transactions for the next block: highest fee rate first.
    ///
    /// `gas_cap` is a hard stop, not a target. A selection that overshoots it
    /// produces a block `validate_standalone` rejects with `GasOverCap`, so the
    /// miner stalls and every peer that relayed those transactions wasted the
    /// bandwidth.
    ///
    /// Ordering is total and deterministic. Two nodes holding the same pool must
    /// select the same transactions in the same order, or they build different
    /// blocks from the same state — the same class of defect as the arrival-order
    /// fork choice that session 1 removed.
    pub fn select_for_block(&self, gas_cap: u64, max_bytes: usize) -> Vec<Transaction> {
        let mut ordered: Vec<&MempoolEntry> = self.entries.values().collect();
        ordered.sort_by(|a, b| {
            b.fee_rate
                .cmp(&a.fee_rate)
                // Equal rate: older first, then lowest txid. Both are properties
                // of pool state, not of arrival timing at this node.
                .then(a.accepted_at.cmp(&b.accepted_at))
                .then(a.tx.txid().cmp(&b.tx.txid()))
        });

        let mut chosen = Vec::new();
        let mut gas = 0u64;
        let mut bytes = 0usize;
        for entry in ordered {
            let size = entry.size_bytes();
            // `continue`, not `break`: a lower-fee transaction may still fit the
            // gas left over, and stopping at the first oversized one wastes the
            // remainder of the block.
            if gas.saturating_add(entry.gas_used) > gas_cap {
                continue;
            }
            if bytes + size > max_bytes {
                continue;
            }
            gas += entry.gas_used;
            bytes += size;
            chosen.push(entry.tx.clone());
        }
        chosen
    }

    /// Remove transactions confirmed by `confirmed`, plus everything that
    /// depended on them.
    ///
    /// Takes the transactions rather than a `Block` so the caller decides what
    /// "confirmed" means: a reorg makes a block's transactions unconfirmed again,
    /// and the caller may need to do nothing at all.
    pub fn evict_confirmed(&mut self, confirmed: &[Transaction]) {
        let confirmed_ids: HashSet<Hash> = confirmed.iter().map(|t| t.txid()).collect();
        let spent: HashSet<OutPoint> = confirmed
            .iter()
            .flat_map(|t| t.inputs.iter().map(|i| i.outpoint()))
            .collect();

        // Everything directly confirmed goes regardless of its inputs: the block
        // consumed those outpoints, so the entry is not a pooled transaction any
        // more under any reading.
        //
        // `gone` is the set of *removed* transactions and starts as the confirmed
        // set. It is the thing the cascade below actually needs: a dependent
        // transaction is one that spends an output **created by** a removed
        // transaction, which is a property of the input's outpoint, not of who
        // currently spends it. Checking the `spends` reverse index ("who spends
        // this outpoint") cannot answer that question, so a child two hops from
        // the block survived — and so did a direct child, because the index only
        // ever pointed at the child itself.
        let mut gone: HashSet<Hash> = HashSet::new();
        for txid in &confirmed_ids {
            if let Some(entry) = self.entries.remove(txid) {
                self.forget(txid, &entry);
            }
            gone.insert(*txid);
        }

        // Transitively remove anything that spends an output the block consumed
        // or an output created by a transaction the cascade has already removed.
        loop {
            let doomed: Vec<Hash> = self
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.tx.inputs.iter().any(|i| {
                        let op = i.outpoint();
                        spent.contains(&op) || gone.contains(&op.txid)
                    })
                })
                .map(|(txid, _)| *txid)
                .collect();

            if doomed.is_empty() {
                break;
            }
            for txid in doomed {
                if let Some(entry) = self.entries.remove(&txid) {
                    self.forget(&txid, &entry);
                }
                gone.insert(txid);
            }
        }
    }

    /// Drop everything, e.g. after a reorg replaced the state entries were
    /// validated against.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.spends.clear();
        self.bytes = 0;
    }

    fn forget(&mut self, txid: &Hash, entry: &MempoolEntry) {
        for input in &entry.tx.inputs {
            if self.spends.get(&input.outpoint()) == Some(txid) {
                self.spends.remove(&input.outpoint());
            }
        }
        self.bytes = self.bytes.saturating_sub(entry.size_bytes());
    }

    pub fn summary(&self) -> MempoolSummary {
        MempoolSummary {
            count: self.entries.len(),
            bytes: self.bytes,
            total_gas: self.entries.values().map(|e| e.gas_used).sum(),
            total_fees: self.entries.values().map(|e| e.fee_total).sum(),
        }
    }

    /// Bring the pool into step with a chain that has just changed.
    ///
    /// Order is the whole point: **evict before re-admitting.** `confirmed` are
    /// transactions the canonical chain now contains, so they and everything
    /// built on them leave the pool. `disconnected` are transactions a reorg took
    /// back off the chain; they are re-validated against the new state like any
    /// other arrival, so a reorg that consumed their inputs simply refuses them
    /// rather than re-pooling something no block can ever include.
    ///
    /// Re-admission deliberately reuses the `add` path, and therefore the *new*
    /// base fee. A transaction that was mined when the fee was low may be under
    /// the floor now; refusing it is the correct answer, because pooling it would
    /// relay a transaction the next block rejects. `refused` counts exactly that,
    /// and it is not an error — a reorg is allowed to invalidate a transaction.
    ///
    /// A transaction already present counts as re-admitted: the postcondition is
    /// that it is in the pool, not that this call inserted it.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile(
        &mut self,
        utxo: &UtxoSet,
        height: u64,
        params: &NetworkParams,
        base_fee: u64,
        confirmed: &[Transaction],
        disconnected: &[Transaction],
        bonds: &BondLedger,
    ) -> ReconcileReport {
        let before = self.entries.len();
        self.evict_confirmed(confirmed);
        let evicted = before.saturating_sub(self.entries.len());

        let mut report = ReconcileReport {
            evicted,
            ..ReconcileReport::default()
        };
        for tx in disconnected {
            // A coinbase has no inputs to re-spend and is not relayable.
            if tx.is_coinbase() {
                continue;
            }
            match self.add(tx.clone(), utxo, height, params, base_fee, bonds) {
                Ok(_) | Err(MempoolError::AlreadyKnown) => report.readmitted += 1,
                Err(_) => report.refused += 1,
            }
        }
        report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolSummary {
    pub count: usize,
    pub bytes: usize,
    pub total_gas: u64,
    pub total_fees: u64,
}

/// What a [`Mempool::reconcile`] did. Returned rather than logged so a caller can
/// assert on it, and so a test can tell "nothing to do" apart from "everything
/// refused" — two states that look identical from `len()` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconcileReport {
    pub evicted: usize,
    /// Disconnected transactions back in the pool (including ones already there).
    pub readmitted: usize,
    /// Disconnected transactions the new state will not accept.
    pub refused: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Address;
    use crate::ledger::Utxo;
    use crate::tx::{Input, Output};
    use crate::wallet::Wallet;

    const FUNDED: u64 = 10_000_000_000;
    const BASE: u64 = 1_000;

    /// Height to mine a test transaction at. Every output in this ledger — not
    /// only the coinbase — is subject to `coinbase_maturity`, and a pooled
    /// transaction is validated against the *next* block's height, so spending
    /// from a UTXO created at height 0 requires a height at least that high.
    const H: u64 = 100;

    fn params() -> NetworkParams {
        NetworkParams::mini()
    }

    fn funded(w: &Wallet, n: u8) -> (UtxoSet, Vec<OutPoint>) {
        let mut set = UtxoSet::new();
        let mut ops = Vec::new();
        for i in 0..n {
            let op = OutPoint {
                txid: [i; 32],
                index: 0,
            };
            set.insert(
                op,
                Utxo {
                    out: Output {
                        value: FUNDED,
                        address: w.address().unwrap(),
                    },
                    height: 0,
                },
            );
            ops.push(op);
        }
        (set, ops)
    }

    /// Signed 1-in 1-out. Whatever is not named as `pay` becomes the fee.
    fn spend(w: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: pay,
                address: to,
            }],
        );
        w.sign(&mut tx).unwrap();
        tx
    }

    /// A fee comfortably above the base-fee burn, so the fee is what the test
    /// means it to be rather than the floor.
    fn fat_fee() -> u64 {
        BASE * 100_000 + 1_000
    }

    /// Insert an entry straight into the pool, bypassing admission.
    ///
    /// A chained transaction cannot pass `add`: its parent's output is not in the
    /// on-chain UTXO set yet, so `check_tx` refuses it as an unknown outpoint.
    /// Eviction is exactly the case that has to cope with such entries, so the
    /// tests below stage them directly rather than pretending `add` accepts them.
    fn stage(pool: &mut Mempool, tx: &Transaction, fee: u64) {
        pool.entries.insert(
            tx.txid(),
            MempoolEntry {
                fee_rate: (fee / tx.gas_used()).max(Mempool::MIN_FEE_RATE),
                fee_total: fee,
                gas_used: tx.gas_used(),
                accepted_at: H,
                tx: tx.clone(),
            },
        );
        for input in &tx.inputs {
            pool.spends.insert(input.outpoint(), tx.txid());
        }
        pool.bytes += tx.serialize().len();
    }

    // -------------------------------------------------------------------
    // 1. Conflict detection
    // -------------------------------------------------------------------

    /// **The rule:** two pooled transactions may not spend the same output.
    ///
    /// **The attack:** relay two conflicting transactions. The mempool costs a
    /// peer nothing to fill, so if it takes both, one is unbuildable into every
    /// block and whichever loses fork choice takes its input with it — the pool's
    /// contents then depend on a race rather than on fees.
    #[test]
    fn a_double_spend_cannot_enter_the_pool_twice() {
        let w = Wallet::new_random("victim");
        let thief = Wallet::new_random("thief");
        let (set, ops) = funded(&w, 1);
        let op = ops[0];
        let fee = fat_fee();

        let mut pool = Mempool::default();
        pool.add(
            spend(&w, op, FUNDED - fee, thief.address().unwrap()),
            &set,
            H,
            &params(),
            BASE,
            &BondLedger::default(),
        )
        .unwrap();

        let steal = spend(&w, op, FUNDED - fee - 1, [9u8; 20]);
        assert!(
            matches!(
                pool.add(steal, &set, H, &params(), BASE, &BondLedger::default()),
                Err(MempoolError::Conflict { .. })
            ),
            "a conflicting transaction was admitted alongside the pooled one"
        );
        assert_eq!(pool.len(), 1, "the pool must hold exactly one of the two");
    }

    /// A spend of an output that no longer exists is stale. Pooling it means
    /// relaying a transaction every peer will reject.
    #[test]
    fn a_stale_spend_is_refused() {
        let w = Wallet::new_random("victim");
        // The set is deliberately dropped: the spend is checked against an empty
        // one, so what the UTXO set holds is exactly the thing under test.
        let (_, ops) = funded(&w, 1);
        let tx = spend(&w, ops[0], FUNDED - fat_fee(), [9u8; 20]);
        let mut pool = Mempool::default();
        assert!(
            pool.add(
                tx,
                &UtxoSet::new(),
                H,
                &params(),
                BASE,
                &BondLedger::default()
            )
            .is_err(),
            "a spend of a nonexistent output was pooled"
        );
    }

    // -------------------------------------------------------------------
    // 2. Boundedness
    // -------------------------------------------------------------------

    /// **The rule:** a peer must not be able to grow a structure past its bound
    /// (§13.11 invariant 6). The mempool has no PoW cost, so this is the
    /// cheapest memory attack available.
    #[test]
    fn a_flood_cannot_grow_the_pool_past_its_byte_cap() {
        let w = Wallet::new_random("flooder");
        let (set, ops) = funded(&w, 200);
        let mut pool = Mempool::new(64 * 1024);
        let fee = fat_fee();

        let mut accepted = 0usize;
        for op in ops {
            if pool
                .add(
                    spend(&w, op, FUNDED - fee, [9u8; 20]),
                    &set,
                    H,
                    &params(),
                    BASE,
                    &BondLedger::default(),
                )
                .is_ok()
            {
                accepted += 1;
            }
        }

        assert!(
            accepted > 0,
            "the flood was refused outright, proving nothing"
        );
        assert!(
            pool.size_bytes() <= pool.max_bytes(),
            "pool holds {} bytes against a {} byte cap",
            pool.size_bytes(),
            pool.max_bytes()
        );
        assert!(
            pool.size_bytes() <= accepted * 1_000,
            "byte accounting does not track the entries actually held"
        );
    }

    /// A selection that overshoots `gas_cap` builds a block the node itself
    /// rejects, stalling the miner and wasting every relaying peer.
    #[test]
    fn selection_never_exceeds_the_gas_cap() {
        let w = Wallet::new_random("many");
        let (set, ops) = funded(&w, 20);
        let mut pool = Mempool::default();
        let fee = fat_fee();
        for op in ops {
            pool.add(
                spend(&w, op, FUNDED - fee, [9u8; 20]),
                &set,
                H,
                &params(),
                BASE,
                &BondLedger::default(),
            )
            .unwrap();
        }
        assert_eq!(pool.len(), 20);

        let one = pool
            .get(&pool.entries.keys().next().unwrap().clone())
            .unwrap()
            .gas_used;
        let cap = one * 3;
        let chosen = pool.select_for_block(cap, usize::MAX);
        let gas: u64 = chosen.iter().map(|t| t.gas_used()).sum();
        assert!(gas <= cap, "selection overshot the gas cap: {gas} > {cap}");
        assert_eq!(chosen.len(), 3, "should have filled the cap exactly");
    }

    // -------------------------------------------------------------------
    // 3. Ordering
    // -------------------------------------------------------------------

    /// **The rule:** order by fee *rate*, not fee total.
    ///
    /// **The attack:** submit a large transaction paying a modest total, and a
    /// small one paying several times the rate. Ordering by total hands the
    /// block to the large one — the wrong answer to "who paid most per unit of
    /// work", and the answer that lets a peer who can afford big transactions
    /// crowd out everyone paying genuinely more.
    #[test]
    fn ordering_is_by_fee_rate_not_by_fee_total() {
        let w = Wallet::new_random("rich");
        let (set, ops) = funded(&w, 5);

        // A *wide* transaction: four inputs and four outputs, so its gas is
        // high. A generous total fee spread over that much gas is still a low
        // rate. This is the transaction that wins if the pool orders by total.
        let wide_fee = 100_000_000u64;
        let wide = {
            let inputs: Vec<Input> = ops[0..4].iter().map(Input::unsigned).collect();
            let per = (4 * FUNDED - wide_fee) / 4;
            let outputs: Vec<Output> = (0..4)
                .map(|_| Output {
                    value: per,
                    address: [9u8; 20],
                })
                .collect();
            let mut tx = Transaction::standard(inputs, outputs);
            w.sign(&mut tx).unwrap();
            tx
        };

        // A *narrow* transaction: one input, one output, so its gas is low. It
        // pays a smaller total than the wide one but several times the rate.
        let narrow_fee = 90_000_000u64;
        let narrow = spend(&w, ops[4], FUNDED - narrow_fee, [8u8; 20]);

        assert!(
            wide.gas_used() * narrow_fee > narrow.gas_used() * wide_fee,
            "setup is wrong: the narrow transaction must out-rate the wide one"
        );

        let mut pool = Mempool::default();
        pool.add(
            wide.clone(),
            &set,
            H,
            &params(),
            BASE,
            &BondLedger::default(),
        )
        .unwrap();
        pool.add(
            narrow.clone(),
            &set,
            H,
            &params(),
            BASE,
            &BondLedger::default(),
        )
        .unwrap();

        let wide_entry = pool.get(&wide.txid()).unwrap();
        let narrow_entry = pool.get(&narrow.txid()).unwrap();
        assert!(
            narrow_entry.fee_rate > wide_entry.fee_rate,
            "setup is wrong: narrow rate {} should exceed wide rate {}",
            narrow_entry.fee_rate,
            wide_entry.fee_rate
        );
        assert!(
            wide_entry.fee_total > narrow_entry.fee_total,
            "the wide transaction must carry the larger total, or this proves nothing"
        );

        let chosen = pool.select_for_block(u64::MAX, usize::MAX);
        assert_eq!(
            chosen[0].txid(),
            narrow.txid(),
            "the higher fee rate must be selected first"
        );
    }

    /// Two nodes holding the same pool must build the same block.
    #[test]
    fn selection_is_deterministic_for_equal_fee_rates() {
        let w = Wallet::new_random("tie");
        let (set, ops) = funded(&w, 6);
        let fee = fat_fee();
        let txs: Vec<Transaction> = ops
            .iter()
            .map(|op| spend(&w, *op, FUNDED - fee, [9u8; 20]))
            .collect();

        let mut a = Mempool::default();
        for tx in &txs {
            a.add(tx.clone(), &set, H, &params(), BASE, &BondLedger::default())
                .unwrap();
        }
        let mut b = Mempool::default();
        for tx in txs.iter().rev() {
            b.add(tx.clone(), &set, H, &params(), BASE, &BondLedger::default())
                .unwrap();
        }
        assert_eq!(
            a.select_for_block(u64::MAX, usize::MAX),
            b.select_for_block(u64::MAX, usize::MAX),
            "two nodes with the same pool selected different blocks"
        );
    }

    // -------------------------------------------------------------------
    // 4. Eviction
    // -------------------------------------------------------------------

    /// A confirmed transaction leaves the pool, and so does anything that spent
    /// its outputs. Otherwise the pool fills with entries that can never be
    /// mined and advertises them to every peer forever.
    #[test]
    fn eviction_cascades_to_transactions_built_on_the_confirmed_one() {
        let w = Wallet::new_random("chain");
        // Entries are inserted below rather than admitted: the child spends an
        // output that does not exist on-chain yet, so `add` would refuse it.
        // Eviction is what this test is about.
        let (_, ops) = funded(&w, 1);
        let fee = fat_fee();

        let parent = spend(&w, ops[0], FUNDED - fee, w.address().unwrap());
        let parent_out = OutPoint {
            txid: parent.txid(),
            index: 0,
        };
        let child = spend(&w, parent_out, FUNDED - fee - 1, [7u8; 20]);

        let mut pool = Mempool::default();
        // The child cannot be validated against the current UTXO set (its parent
        // output does not exist yet), so it is admitted directly. This test is
        // about eviction, not admission.
        pool.entries.insert(
            parent.txid(),
            MempoolEntry {
                fee_rate: fee / parent.gas_used(),
                fee_total: fee,
                gas_used: parent.gas_used(),
                accepted_at: H,
                tx: parent.clone(),
            },
        );
        pool.spends.insert(ops[0], parent.txid());
        pool.bytes += parent.serialize().len();
        pool.entries.insert(
            child.txid(),
            MempoolEntry {
                fee_rate: fee / child.gas_used(),
                fee_total: fee,
                gas_used: child.gas_used(),
                accepted_at: H,
                tx: child.clone(),
            },
        );
        pool.spends.insert(parent_out, child.txid());
        pool.bytes += child.serialize().len();
        assert_eq!(pool.len(), 2);

        pool.evict_confirmed(std::slice::from_ref(&parent));

        assert!(
            !pool.contains(&parent.txid()),
            "the confirmed tx stayed pooled"
        );
        assert!(
            !pool.contains(&child.txid()),
            "a tx spending a confirmed-away output stayed pooled"
        );
        assert_eq!(pool.size_bytes(), 0, "eviction leaked the byte accounting");
        assert!(pool.spends.is_empty(), "eviction leaked the spends index");
    }

    /// **The rule:** eviction cascades transitively, not one hop.
    ///
    /// **The attack:** the child of a confirmed transaction is removed but the
    /// grandchild that spends the child's output is not, so after every block the
    /// pool keeps a tail of entries that can never be mined and advertises them to
    /// every peer forever. This is the half a "who spends this outpoint?" check
    /// gets wrong: once the child is removed the reverse index points nowhere, so
    /// the grandchild is invisible unless the cascade remembers *which
    /// transactions it removed* rather than only who spends what.
    #[test]
    fn eviction_cascades_past_the_first_generation() {
        let w = Wallet::new_random("deep");
        let (_, ops) = funded(&w, 1);
        let fee = fat_fee();

        let parent = spend(&w, ops[0], FUNDED - fee, w.address().unwrap());
        let child = spend(
            &w,
            OutPoint {
                txid: parent.txid(),
                index: 0,
            },
            FUNDED - fee - 1,
            w.address().unwrap(),
        );
        let grandchild = spend(
            &w,
            OutPoint {
                txid: child.txid(),
                index: 0,
            },
            FUNDED - fee - 2,
            [7u8; 20],
        );

        let mut pool = Mempool::default();
        stage(&mut pool, &parent, fee);
        stage(&mut pool, &child, fee);
        stage(&mut pool, &grandchild, fee);
        assert_eq!(pool.len(), 3);

        pool.evict_confirmed(std::slice::from_ref(&parent));

        assert!(
            pool.is_empty(),
            "the cascade stopped before the second generation: {} entries left",
            pool.len()
        );
        assert_eq!(pool.size_bytes(), 0, "eviction leaked the byte accounting");
        assert!(pool.spends.is_empty(), "eviction leaked the spends index");
    }

    /// An index that is not cleaned up makes a re-admitted transaction collide
    /// with itself: the pool reports a conflict against a transaction that is no
    /// longer there. That is exactly the shape of a post-reorg failure.
    #[test]
    fn a_orphaned_transaction_can_be_pooled_again() {
        let w = Wallet::new_random("again");
        let (set, ops) = funded(&w, 1);
        let tx = spend(&w, ops[0], FUNDED - fat_fee(), [9u8; 20]);

        let mut pool = Mempool::default();
        pool.add(tx.clone(), &set, H, &params(), BASE, &BondLedger::default())
            .unwrap();
        pool.evict_confirmed(std::slice::from_ref(&tx));
        assert!(pool.is_empty());

        pool.add(tx, &set, H, &params(), BASE, &BondLedger::default())
            .expect("a re-admitted transaction was refused as a conflict with itself");
    }

    /// Evicting one entry must not disturb a sibling that shares no inputs with
    /// it. Over-eager cascading would empty the pool after every block.
    #[test]
    fn eviction_leaves_unrelated_transactions_alone() {
        let w = Wallet::new_random("siblings");
        let (set, ops) = funded(&w, 3);
        let fee = fat_fee();
        let mut pool = Mempool::default();
        let txs: Vec<Transaction> = ops
            .iter()
            .map(|op| spend(&w, *op, FUNDED - fee, [9u8; 20]))
            .collect();
        for tx in &txs {
            pool.add(tx.clone(), &set, H, &params(), BASE, &BondLedger::default())
                .unwrap();
        }

        pool.evict_confirmed(std::slice::from_ref(&txs[0]));
        assert_eq!(
            pool.len(),
            2,
            "eviction removed transactions it had no cause to"
        );
        assert_eq!(pool.spends.len(), 2);
    }
}
