//! UTXO set with undo data. SPEC.md §9.2.
//!
//! Undo records are what make reorganizations cheap: rolling a block back is
//! the exact inverse of applying it, with no replay from genesis.

use std::collections::{BTreeMap, HashSet};

use crate::error::{Error, Result};
use crate::hash::{Address, Hash512};
use crate::params::NetworkParams;
use crate::tx::{OutPoint, Output, Transaction, TX_BOND, TX_SLASH, TX_STANDARD, TX_UNBOND};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub out: Output,
    /// Height of the block that created it, for coinbase maturity checks.
    pub height: u64,
}

type Key = (Hash512, u32);

#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    map: BTreeMap<Key, Utxo>,
}

/// Everything needed to reverse one block.
#[derive(Debug, Clone, Default)]
pub struct Undo {
    pub spent: Vec<(OutPoint, Utxo)>,
    pub created: Vec<OutPoint>,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            map: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, op: &OutPoint) -> Option<&Utxo> {
        self.map.get(&(op.txid, op.index))
    }

    pub fn contains(&self, op: &OutPoint) -> bool {
        self.map.contains_key(&(op.txid, op.index))
    }

    pub fn insert(&mut self, op: OutPoint, u: Utxo) {
        self.map.insert((op.txid, op.index), u);
    }

    pub fn iter(&self) -> impl Iterator<Item = (OutPoint, &Utxo)> {
        self.map.iter().map(|((txid, index), u)| {
            (
                OutPoint {
                    txid: *txid,
                    index: *index,
                },
                u,
            )
        })
    }

    pub fn outputs_for_address(&self, address: &Address) -> Vec<(OutPoint, u64)> {
        self.iter()
            .filter(|(_, u)| &u.out.address == address)
            .map(|(op, u)| (op, u.out.value))
            .collect()
    }

    pub fn total_value(&self) -> u64 {
        self.map
            .values()
            .fold(0u64, |acc, u| acc.saturating_add(u.out.value))
    }

    /// Apply a transaction, returning what it spent. Caller must have already
    /// checked signature validity (SPEC.md §9.2 rule 6).
    ///
    /// Atomic: every input is resolved against a read-only view of the set
    /// before anything is written. Removing inputs one at a time meant a
    /// transaction whose *second* input did not exist took the first one with
    /// it — the `Err` discarded the undo record that could have restored it, so
    /// a single malformed transaction destroyed coins.
    pub fn apply_tx(&mut self, tx: &Transaction, height: u64) -> Result<Undo> {
        let mut undo = Undo::default();

        // Resolve first, mutate second.
        for input in &tx.inputs {
            let op = input.outpoint();
            let u = self
                .map
                .get(&(op.txid, op.index))
                .ok_or(Error::UnknownOutPoint)?
                .clone();
            undo.spent.push((op, u));
        }
        for (op, _) in &undo.spent {
            self.map.remove(&(op.txid, op.index));
        }

        for (index, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid: tx.txid(),
                index: index as u32,
            };
            self.map
                .insert((op.txid, op.index), Utxo { out: *out, height });
            undo.created.push(op);
        }

        Ok(undo)
    }

    /// Reverse one or more [`Self::apply_tx`] operations. Newest first.
    ///
    /// This is the primitive a partially-applied block unwinds with, so it must
    /// be usable without the transaction that produced the undo record.
    pub fn undo(&mut self, undo: &Undo) {
        for (op, u) in &undo.spent {
            self.map.insert((op.txid, op.index), u.clone());
        }
        for op in &undo.created {
            self.map.remove(&(op.txid, op.index));
        }
    }

    /// Reverse [`Self::apply_tx`].
    pub fn undo_tx(&mut self, _tx: &Transaction, undo: &Undo) {
        self.undo(undo);
    }

    /// Remove a set of created outputs (coinbase, when only the tip matters).
    pub fn drop_created(&mut self, created: &[OutPoint]) {
        for op in created {
            self.map.remove(&(op.txid, op.index));
        }
    }

    /// Remove one outpoint, returning what was there. The exit-claim path uses
    /// this after resolving every input first (the same resolve-then-mutate
    /// atomicity as [`Self::apply_tx`]); callers that need the batch form
    /// should use [`Self::apply_tx`] or [`Self::drop_created`].
    pub fn remove(&mut self, op: &OutPoint) -> Option<Utxo> {
        self.map.remove(&(op.txid, op.index))
    }
}

/// Accumulated view of one block, resolved against a UTXO set without
/// mutating it.
#[derive(Debug, Clone)]
pub struct BlockDelta {
    pub undo: Undo,
    pub value_in: u64,
    pub value_out: u64,
    pub fee_total: u64,
    pub gas_used: u64,
}

/// Check a transaction against `utxo` (SPEC.md §9.2) without applying it.
pub fn check_tx(
    utxo: &UtxoSet,
    tx: &Transaction,
    height: u64,
    params: &crate::params::NetworkParams,
    base_fee: u64,
    coinbase_maturity: u64,
) -> Result<BlockDelta> {
    if tx.is_coinbase() {
        return Err(Error::BadCoinbase(
            "use check_coinbase for the coinbase transaction",
        ));
    }
    // Transaction versioning discipline (tx.rs): future primitives add new
    // `tx_type` values, and anything unrecognised is refused rather than
    // interpreted as a standard spend.
    if !matches!(tx.tx_type, TX_STANDARD | TX_BOND | TX_UNBOND | TX_SLASH) {
        return Err(Error::Malformed("unknown tx_type"));
    }
    if tx.inputs.is_empty() {
        return Err(Error::Malformed(
            "standard transaction needs at least one input",
        ));
    }
    if tx.outputs.is_empty() {
        return Err(Error::Malformed("transaction needs at least one output"));
    }
    if tx.has_duplicate_inputs() {
        return Err(Error::DuplicateInput);
    }
    if tx.has_zero_value_output() {
        return Err(Error::BadFee("zero-value output"));
    }
    // Reject an unrepresentable output total before it is used in the
    // value_in >= value_out comparison below, where a wrapped sum would read
    // as a transaction that creates less value than it spends.
    if tx.value_out_overflows() {
        return Err(Error::ValueOverflow);
    }

    let mut seen: HashSet<Key> = HashSet::new();
    let mut value_in = 0u64;
    for (k, input) in tx.inputs.iter().enumerate() {
        let op = input.outpoint();
        if !seen.insert((op.txid, op.index)) {
            return Err(Error::DuplicateInput);
        }
        let held = utxo.get(&op).ok_or(Error::UnknownOutPoint)?;
        if held.height + coinbase_maturity > height {
            return Err(Error::ImmatureCoinbase {
                height: held.height,
                required: held.height + coinbase_maturity,
            });
        }
        if held.out.value == 0 {
            return Err(Error::BadFee("spending a zero-value output"));
        }
        // Post-quantum migration rule (age-gated, backward-compatible): once
        // `pq_activation_height` is set, inputs that spend outputs created at or
        // after that height must carry an ML-DSA-65 (scheme 3) signature
        // component. Outputs created before it — including plain ECDSA ones —
        // are exempt, so the rule never strands history: a wallet can still move
        // its old funds under their original bundle, and only future outputs are
        // tightened to demand a post-quantum component. `require_hybrid`'s
        // `>= 2 components` test would let a Schnorr-only bundle through, so the
        // scheme-3 membership check is what makes the requirement post-quantum,
        // not merely multi-scheme. The rule is inert when the height is 0.
        let pq_epoch = params.pq_activation_height;
        if pq_epoch != 0
            && height >= pq_epoch
            && held.height >= pq_epoch
            && !input.sigs.schemes().contains(&crate::sig::SCHEME_ML_DSA_65)
        {
            return Err(Error::PostQuantumRequired);
        }
        tx.verify_input(k, &held.out.address, require_hybrid(params))?;
        value_in = value_in
            .checked_add(held.out.value)
            .ok_or(Error::ValueOverflow)?;
    }

    let value_out = tx.value_out();
    if value_in < value_out {
        return Err(Error::ValueOverflow);
    }
    let fee = value_in - value_out;

    if fee < crate::fees::required_fee(base_fee, tx.gas_used()) {
        return Err(Error::BadFee("fee below the burned base fee"));
    }
    let _ = params;

    Ok(BlockDelta {
        undo: Undo::default(),
        value_in,
        value_out,
        fee_total: fee,
        gas_used: tx.gas_used(),
    })
}

/// Whether inputs must carry a hybrid (multi-scheme) signature bundle.
///
/// Driven by the network profile so a chain can require post-quantum readiness
/// without a code change. Absent an explicit flag, single-scheme inputs are
/// accepted: the point of agility is that a valid single-scheme transaction
/// stays valid, and forcing hybrids on every input would invalidate history the
/// moment the rule was added.
///
/// Coinbase spends nothing real; the node derives its inputs instead, so this
/// never applies to a coinbase.
fn require_hybrid(params: &NetworkParams) -> bool {
    params.require_hybrid_signatures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::NetworkParams;
    use crate::tx::{Input, TX_COINBASE};
    use crate::wallet::{SignMode, Wallet};

    fn tagged(value: u64, tag: u8) -> Output {
        Output {
            value,
            address: [tag; 20],
        }
    }

    /// Every spend in these tests is fully signed, because `check_tx` verifies
    /// signatures before it looks at anything else.
    fn signed_spend(
        wallet: &Wallet,
        op: OutPoint,
        pay: u64,
        to: crate::hash::Address,
    ) -> Transaction {
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: pay,
                address: to,
            }],
        );
        wallet.sign(&mut tx).unwrap();
        tx
    }

    const FUNDED: u64 = 1_000_000_000;

    fn funded_set(wallet: &Wallet) -> (UtxoSet, OutPoint) {
        let mut s = UtxoSet::new();
        let op = OutPoint {
            txid: [4u8; 64],
            index: 0,
        };
        s.insert(
            op,
            Utxo {
                out: Output {
                    value: FUNDED,
                    address: wallet.address().unwrap(),
                },
                height: 0,
            },
        );
        (s, op)
    }

    #[test]
    fn apply_then_undo_restores_the_set() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let (mut s, op) = funded_set(&w);
        let before = s.len();
        let tx = signed_spend(&w, op, FUNDED - 100, dest);
        let undo = s.apply_tx(&tx, 10).unwrap();
        assert_eq!(s.len(), before, "one spent, one created");
        assert!(s.contains(&OutPoint {
            txid: tx.txid(),
            index: 0
        }));
        s.undo_tx(&tx, &undo);
        assert_eq!(s.len(), before);
        assert!(s.contains(&op), "the spent output must come back");
        assert_eq!(s.total_value(), FUNDED);
    }

    #[test]
    fn double_spend_is_rejected() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let (mut s, op) = funded_set(&w);
        let tx = signed_spend(&w, op, FUNDED - 100, dest);
        s.apply_tx(&tx, 10).unwrap();
        let second = signed_spend(&w, op, FUNDED - 100, dest);
        assert!(matches!(
            check_tx(&s, &second, 11, &NetworkParams::mini(), 0, 10),
            Err(Error::UnknownOutPoint)
        ));
    }

    #[test]
    fn duplicate_input_within_a_tx_is_rejected() {
        let w = Wallet::new_random("a");
        let (mut s, op) = funded_set(&w);
        s.insert(
            OutPoint {
                txid: [5u8; 64],
                index: 0,
            },
            Utxo {
                out: Output {
                    value: FUNDED,
                    address: w.address().unwrap(),
                },
                height: 0,
            },
        );
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op), Input::unsigned(&op)],
            vec![tagged(1, 2)],
        );
        w.sign(&mut tx).unwrap();
        assert!(matches!(
            check_tx(&s, &tx, 10, &NetworkParams::mini(), 0, 10),
            Err(Error::DuplicateInput)
        ));
    }

    #[test]
    fn immature_coinbase_cannot_be_spent() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let mut s = UtxoSet::new();
        let op = OutPoint {
            txid: [6u8; 64],
            index: 0,
        };
        s.insert(
            op,
            Utxo {
                out: Output {
                    value: FUNDED,
                    address: w.address().unwrap(),
                },
                height: 50,
            },
        );
        let tx = signed_spend(&w, op, FUNDED - 100, dest);
        assert!(matches!(
            check_tx(&s, &tx, 55, &NetworkParams::mainnet(), 0, 100),
            Err(Error::ImmatureCoinbase {
                height: 50,
                required: 150
            })
        ));
        // Mature exactly at height + maturity.
        assert_eq!(
            check_tx(&s, &tx, 150, &NetworkParams::mainnet(), 0, 100)
                .unwrap()
                .fee_total,
            100
        );
    }

    #[test]
    fn spending_more_than_you_own_is_rejected() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let mut s = UtxoSet::new();
        let op = OutPoint {
            txid: [7u8; 64],
            index: 0,
        };
        s.insert(
            op,
            Utxo {
                out: Output {
                    value: 100,
                    address: w.address().unwrap(),
                },
                height: 0,
            },
        );
        let tx = signed_spend(&w, op, 101, dest);
        assert!(matches!(
            check_tx(&s, &tx, 10, &NetworkParams::mini(), 0, 10),
            Err(Error::ValueOverflow)
        ));
    }

    #[test]
    fn fee_below_base_fee_is_rejected() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let (s, op) = funded_set(&w);
        let tx = signed_spend(&w, op, FUNDED - 100, dest);
        let gas = tx.gas_used();
        let got = check_tx(&s, &tx, 10, &NetworkParams::mainnet(), 10_000, 10);
        assert!(matches!(got, Err(Error::BadFee(_))), "got {got:?}");
        // Paying exactly the burned base fee works.
        let paid = signed_spend(&w, op, FUNDED - 10_000 * gas, dest);
        assert!(check_tx(&s, &paid, 10, &NetworkParams::mainnet(), 10_000, 10).is_ok());
    }

    #[test]
    fn wrong_owner_cannot_spend() {
        let w = Wallet::new_random("a");
        let thief = Wallet::new_random("b");
        let dest = [9u8; 20];
        let (s, op) = funded_set(&w);
        let tx = signed_spend(&thief, op, FUNDED - 100, dest);
        assert!(matches!(
            check_tx(&s, &tx, 10, &NetworkParams::mini(), 0, 10),
            Err(Error::WrongAddress)
        ));
    }

    #[test]
    fn tampered_output_breaks_the_signature() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let (s, op) = funded_set(&w);
        let mut tx = signed_spend(&w, op, FUNDED - 100, dest);
        tx.outputs[0].value = 100;
        assert!(matches!(
            check_tx(&s, &tx, 10, &NetworkParams::mini(), 0, 10),
            Err(Error::BadSignature { .. })
        ));
    }

    #[test]
    fn coinbase_is_not_a_normal_tx() {
        let s = UtxoSet::new();
        let cb = Transaction::coinbase([1u8; 64], 1, tagged(1, 0));
        assert!(cb.tx_type == TX_COINBASE);
        assert!(check_tx(&s, &cb, 1, &NetworkParams::mini(), 0, 10).is_err());
    }

    #[test]
    fn index_by_address_works() {
        let w = Wallet::new_random("a");
        let dest = [9u8; 20];
        let (mut s, op) = funded_set(&w);
        let tx = signed_spend(&w, op, FUNDED - 100, dest);
        s.apply_tx(&tx, 10).unwrap();
        assert_eq!(s.outputs_for_address(&w.address().unwrap()).len(), 0);
        assert_eq!(s.outputs_for_address(&dest).len(), 1);
        assert_eq!(s.total_value(), FUNDED - 100);
    }

    // --- Properties -------------------------------------------------------

    #[test]
    fn undo_is_an_exact_inverse_over_a_random_spend_sequence() {
        // Roll a long mixed sequence of spends forward, then all the way back,
        // and compare the whole set entry for entry. `apply_tx`/`undo_tx` are
        // the basis of reorg handling, so a lossy undo means a node that
        // silently invents or destroys coins after a reorg.
        let w = Wallet::new_random("prop");
        let dest = [3u8; 20];
        let (mut s, first) = funded_set(&w);

        let snapshot = s.clone();
        let mut undo_log: Vec<(Transaction, Undo)> = Vec::new();
        let mut next = first;
        let mut tag = 0u8;

        for step in 0..64u64 {
            if !s.contains(&next) {
                break;
            }
            tag = tag.wrapping_add(1);
            // Vary the payment so outputs differ, and keep it non-zero and
            // below the held value so every step is a valid spend.
            let pay = 1_000 + (step % 7) * 111;
            let tx = signed_spend(&w, next, pay, dest);
            let undo = s.apply_tx(&tx, 100 + step).unwrap();
            next = OutPoint {
                txid: tx.txid(),
                index: 0,
            };
            undo_log.push((tx, undo));
        }

        assert!(!undo_log.is_empty(), "no spends were applied");
        assert_ne!(s.total_value(), snapshot.total_value());

        for (tx, undo) in undo_log.iter().rev() {
            s.undo_tx(tx, undo);
        }

        assert_eq!(s.len(), snapshot.len(), "set size changed after undo");
        assert_eq!(s.total_value(), snapshot.total_value(), "value leaked");
        for (op, u) in snapshot.iter() {
            assert_eq!(
                s.get(&op),
                Some(u),
                "output {}:{} differs after undo",
                hex::encode(op.txid),
                op.index
            );
        }
    }

    #[test]
    fn total_value_never_exceeds_the_cap_and_never_wraps() {
        // `total_value` sums the whole set. Build entries whose values would
        // overflow a u64 and confirm the sum saturates rather than wrapping to
        // a small number, which would let a cap check pass on a set that
        // actually holds more.
        let mut s = UtxoSet::new();
        for i in 0..4u8 {
            s.insert(
                OutPoint {
                    txid: [i; 64],
                    index: 0,
                },
                Utxo {
                    out: tagged(u64::MAX / 2, i),
                    height: 0,
                },
            );
        }
        assert_eq!(
            s.total_value(),
            u64::MAX,
            "an overflowing total must saturate, not wrap"
        );
    }

    #[test]
    fn a_transaction_can_never_create_more_value_than_it_spends() {
        // The core conservation property, checked over a spread of shapes
        // rather than a single happy path: whatever the fee and split, the
        // output total must not exceed the resolved input total.
        let w = Wallet::new_random("prop");
        let p = NetworkParams::mini();
        // `funded_set` always funds FUNDED, so the first tuple element is
        // documentation of the funding side rather than a varying input.
        for pay in [1u64, FUNDED - 1, FUNDED, 9] {
            let (mut s, op) = funded_set(&w);
            let tx = signed_spend(&w, op, pay, [5u8; 20]);
            let delta = match check_tx(&s, &tx, 10, &p, 0, 0) {
                Ok(d) => d,
                Err(_) => continue,
            };
            assert!(
                delta.value_out <= delta.value_in,
                "created {} from {}",
                delta.value_out,
                delta.value_in
            );
            s.apply_tx(&tx, 10).unwrap();
            assert!(s.total_value() <= FUNDED, "set grew beyond the funding");
        }
    }

    // --- Post-quantum migration rule (Step 4, backward-compatible) -------------
    //
    // `pq_activation_height` is off (0) on every shipped profile, so these are
    // the only tests that exercise the rule: a hand-built profile with a
    // nonzero activation height.

    fn pq_params(at: u64) -> NetworkParams {
        let mut p = NetworkParams::mini();
        p.pq_activation_height = at;
        p
    }

    fn utxo_at(op: OutPoint, addr: [u8; 20], created: u64) -> UtxoSet {
        let mut s = UtxoSet::new();
        s.insert(
            op,
            Utxo {
                out: Output {
                    value: FUNDED,
                    address: addr,
                },
                height: created,
            },
        );
        s
    }

    #[test]
    fn pq_activation_rejects_new_outputs_spent_without_scheme3() {
        // Activate PQ spends at height 5.
        let p = pq_params(5);
        let w = Wallet::from_private_key_bytes(&[7u8; 32], "pq").unwrap();

        // A post-activation output (created at height 6) at the wallet's hybrid
        // address. A hybrid bundle matches that address and would otherwise
        // verify, so rejecting it isolates the PQ rule from the address check.
        let op = OutPoint {
            txid: [2u8; 64],
            index: 0,
        };
        let s = utxo_at(op, w.address().unwrap(), 6);
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: FUNDED - 100,
                address: [9u8; 20],
            }],
        );
        w.sign(&mut tx).unwrap();
        assert!(matches!(
            check_tx(&s, &tx, 20, &p, 0, 10),
            Err(Error::PostQuantumRequired)
        ));

        // The rule is satisfiable: a PQ bundle (scheme 3) is accepted for the
        // same output, which must be at the PQ address to match.
        let s_pq = utxo_at(op, w.pq_address().unwrap(), 6);
        let mut tx2 = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: FUNDED - 100,
                address: [9u8; 20],
            }],
        );
        w.sign_mode(&mut tx2, SignMode::PostQuantum).unwrap();
        assert!(check_tx(&s_pq, &tx2, 20, &p, 0, 10).is_ok());
    }

    #[test]
    fn pq_activation_leaves_legacy_outputs_spendable() {
        let p = pq_params(5);
        let w = Wallet::from_private_key_bytes(&[7u8; 32], "pq-legacy").unwrap();

        // Legacy output (created at height 0, before activation). Even after
        // activation a hybrid bundle must still move it: history is not stranded.
        let op = OutPoint {
            txid: [3u8; 64],
            index: 0,
        };
        let s = utxo_at(op, w.address().unwrap(), 0);
        let tx = signed_spend(&w, op, FUNDED - 100, [8u8; 20]);
        assert!(check_tx(&s, &tx, 11, &p, 0, 10).is_ok());
    }

    #[test]
    fn pq_activation_off_by_default_rejects_nothing() {
        // Default profiles ship with pq_activation_height == 0: the rule is
        // inert, so a plain hybrid spend passes exactly as before.
        let w = Wallet::from_private_key_bytes(&[7u8; 32], "pq-off").unwrap();
        let (s, op) = funded_set(&w);
        let tx = signed_spend(&w, op, FUNDED - 100, [8u8; 20]);
        assert!(check_tx(&s, &tx, 11, &NetworkParams::mini(), 0, 10).is_ok());
    }
}
