//! L1 → L2 deposits: the burn-to-sink overlay (Decision 10, SPEC.md §19.5).
//!
//! # What a deposit is
//!
//! An ordinary STANDARD L1 payment carrying at least one output to the
//! params-derived sink. L1 consensus validates it as a payment like any other
//! — no L1 rule changed, no new transaction type — and L2 replay reads the
//! deposit out of the accepted block. The three facts replay needs are all
//! committed by the L1 transaction itself:
//!
//! - **What:** every sink output's exact satoshis (committed by the sighash,
//!   so the amount cannot be altered after signing).
//! - **Whose:** the common owner of the inputs, each read as its input key
//!   bundle's address. L1 consensus already proved that address equals the
//!   spent UTXO's owner (`verify_input` refuses anything else), so replay
//!   derives ownership without re-verifying signatures and without UTXO
//!   history. Inputs with different owners, and coinbase transactions, are not
//!   deposits: the value stays burned and nothing is credited.
//! - **Which:** `(txid, output_index)`, the replay identity, credited once.
//!
//! # What this module does not do
//!
//! It detects; it does not credit. Crediting is `L2State::apply_deposit`
//! (exactly-once via the consumed set, counted into `funded_total`), and
//! maturity gating is `ChainL2` (which knows the tip). Detection itself is a
//! pure function of one block — no chain, no tip, no state — so it is trivially
//! deterministic and directly fuzzable.

use jnt_core::block::Block;
use jnt_core::hash::{Address, Hash512};
use jnt_core::params::NetworkParams;
use jnt_core::tx::Transaction;

/// The deposit rules for one network profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositParams {
    /// Outputs here are deposits. Derived per network (Decision 10 item 1).
    pub sink: Address,
    /// Per-sink-output floor (Decision 10 item 3). Below-minimum outputs are
    /// burns without credit.
    pub minimum_sat: u64,
    /// Blocks before a deposit is spendable (Decision 10 item 4): the existing
    /// finality depth, reused rather than reinvented.
    pub maturity_depth: u64,
}

impl DepositParams {
    pub fn for_params(params: &NetworkParams) -> Self {
        DepositParams {
            sink: params.l2_deposit_sink(),
            minimum_sat: params.l2_deposit_minimum_sat,
            maturity_depth: params.finality_depth,
        }
    }
}

/// One sink output that qualifies as a deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetectedDeposit {
    /// Block height carrying it (for maturity).
    pub height: u64,
    /// Replay identity, first half.
    pub txid: Hash512,
    /// Replay identity, second half: index into the transaction's outputs.
    pub index: u32,
    /// Common owner of the inputs (Decision 10 item 2).
    pub recipient: Address,
    /// Exact sink output satoshis, 1:1 (Decision 10 item 6).
    pub amount_sat: u64,
}

impl DetectedDeposit {
    /// The height at which this deposit becomes spendable: detected at
    /// `height`, credited once `tip >= matures_at`.
    pub fn matures_at(&self, maturity_depth: u64) -> u64 {
        self.height.saturating_add(maturity_depth)
    }

    /// Replay identity: `(txid, output_index)` (Decision 10 item 5).
    pub fn id(&self) -> (Hash512, u32) {
        (self.txid, self.index)
    }
}

/// A deposit detected but not yet spendable: its block is not final-deep yet
/// (Decision 10 item 4). Visible through `ChainL2::pending_deposits`, credited
/// once the tip reaches `matures_at`. A reorg that removes the block removes
/// the entry by re-derivation — pending is never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDeposit {
    pub deposit: DetectedDeposit,
    pub matures_at: u64,
}

/// A sink output that is a burn, not a deposit, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoredDeposit {
    pub height: u64,
    pub txid: Hash512,
    pub index: u32,
    pub amount_sat: u64,
    pub reason: DepositIgnoreReason,
}

/// Why a sink output credited nothing. Named, so an operator asking "where is
/// my deposit" gets an answer rather than silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositIgnoreReason {
    /// The inputs have no common owner (different owners, or an input whose
    /// owner cannot be derived). Fail closed: burn without credit.
    MixedOwners,
    /// Below the protocol minimum: dust stays burned.
    BelowMinimum,
    /// This `(txid, index)` already credited — same bytes in an earlier block.
    Duplicate,
}

/// Scan one accepted block for deposits (Decision 10 items 2–4).
///
/// Pure function of the block: the caller (replay) decides maturity from the
/// tip and exactly-once from the consumed set. Coinbase transactions are never
/// deposits — their inputs are unsigned parent references with no owner — and
/// non-sink outputs are irrelevant.
pub fn scan_block(
    block: &Block,
    height: u64,
    params: &DepositParams,
) -> (Vec<DetectedDeposit>, Vec<IgnoredDeposit>) {
    let mut detected = Vec::new();
    let mut ignored = Vec::new();
    for tx in block.txs.iter().skip(1) {
        debug_assert!(
            !tx.is_coinbase(),
            "only tx 0 may be the coinbase (L1 consensus)"
        );
        if tx.is_coinbase() {
            continue;
        }
        let recipient = match common_owner(tx) {
            Some(addr) => addr,
            None => {
                // No unique owner: every sink output here is a burn. Record
                // each so the refusal is visible, not silent.
                for (index, out) in tx
                    .outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| o.address == params.sink)
                {
                    ignored.push(IgnoredDeposit {
                        height,
                        txid: tx.txid(),
                        index: index as u32,
                        amount_sat: out.value,
                        reason: DepositIgnoreReason::MixedOwners,
                    });
                }
                continue;
            }
        };
        for (index, out) in tx.outputs.iter().enumerate() {
            if out.address != params.sink {
                continue;
            }
            // L1 rejects zero-value outputs, so a zero here is unreachable in
            // consensus — but belt-and-suspenders costs one comparison, and a
            // zero credit must never exist even if L1 rules ever change.
            if out.value < params.minimum_sat {
                ignored.push(IgnoredDeposit {
                    height,
                    txid: tx.txid(),
                    index: index as u32,
                    amount_sat: out.value,
                    reason: DepositIgnoreReason::BelowMinimum,
                });
                continue;
            }
            detected.push(DetectedDeposit {
                height,
                txid: tx.txid(),
                index: index as u32,
                recipient,
                amount_sat: out.value,
            });
        }
    }
    (detected, ignored)
}

/// The common owner of a transaction's inputs, from their key bundles.
///
/// `None` when the inputs disagree or an owner cannot be derived. L1 consensus
/// proved each bundle's address equals the spent UTXO's owner at acceptance,
/// so agreement here means one owner provably controlled the whole input set.
/// An empty bundle hashes to *some* address rather than failing, which is why
/// coinbase transactions are excluded by the caller instead of by this check.
fn common_owner(tx: &Transaction) -> Option<Address> {
    if tx.inputs.is_empty() {
        return None;
    }
    let mut owner: Option<Address> = None;
    for input in &tx.inputs {
        let addr = input.keys.address().ok()?;
        match owner {
            None => owner = Some(addr),
            Some(first) if first != addr => return None,
            Some(_) => {}
        }
    }
    owner
}
