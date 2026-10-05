//! UTXO set with undo data. SPEC.md §9.2.
//!
//! Undo records are what make reorganizations cheap: rolling a block back is
//! the exact inverse of applying it, with no replay from genesis.

use std::collections::{BTreeMap, HashSet};

use crate::error::{Error, Result};
use crate::hash::{Address, Hash};
use crate::tx::{OutPoint, Output, Transaction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub out: Output,
    /// Height of the block that created it, for coinbase maturity checks.
    pub height: u64,
}

type Key = (Hash, u32);

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
    pub fn apply_tx(&mut self, tx: &Transaction, height: u64) -> Result<Undo> {
        let mut undo = Undo::default();

        for input in &tx.inputs {
            let op = input.outpoint();
            let u = self
                .map
                .remove(&(op.txid, op.index))
                .ok_or(Error::UnknownOutPoint)?;
            undo.spent.push((op, u));
        }

        for (index, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid: tx.txid(),
                index: index as u32,
            };
            self.map.insert(
                (op.txid, op.index),
                Utxo {
                    out: *out,
                    height,
                },
            );
            undo.created.push(op);
        }

        Ok(undo)
    }

    /// Reverse [`Self::apply_tx`].
    pub fn undo_tx(&mut self, tx: &Transaction, undo: &Undo) {
        for (op, u) in &undo.spent {
            self.map.insert((op.txid, op.index), u.clone());
        }
        for op in &undo.created {
            self.map.remove(&(op.txid, op.index));
        }
        let _ = tx;
    }

    /// Remove a set of created outputs (coinbase, when only the tip matters).
    pub fn drop_created(&mut self, created: &[OutPoint]) {
        for op in created {
            self.map.remove(&(op.txid, op.index));
        }
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
    if tx.inputs.is_empty() {
        return Err(Error::Malformed("standard transaction needs at least one input"));
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
        tx.verify_input(k, &held.out.address, tx_sig_scheme(tx))?;
        value_in = value_in.checked_add(held.out.value).ok_or(Error::ValueOverflow)?;
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

/// Coinbase spends nothing real; the node derives its inputs instead.
fn tx_sig_scheme(_tx: &Transaction) -> u8 {
    crate::hash::SIG_SCHEME_SECP256K1_ECDSA
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::NetworkParams;
    use crate::tx::{Input, TX_COINBASE};
    use crate::wallet::Wallet;

    fn tagged(value: u64, tag: u8) -> Output {
        Output {
            value,
            address: [tag; 20],
        }
    }

    /// Every spend in these tests is fully signed, because `check_tx` verifies
    /// signatures before it looks at anything else.
    fn signed_spend(wallet: &Wallet, op: OutPoint, pay: u64, to: crate::hash::Address) -> Transaction {
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output { value: pay, address: to }],
        );
        wallet.sign(&mut tx).unwrap();
        tx
    }

    const FUNDED: u64 = 1_000_000_000;

    fn funded_set(wallet: &Wallet) -> (UtxoSet, OutPoint) {
        let mut s = UtxoSet::new();
        let op = OutPoint {
            txid: [4u8; 32],
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
        assert!(s.contains(&OutPoint { txid: tx.txid(), index: 0 }));
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
                txid: [5u8; 32],
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
            txid: [6u8; 32],
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
            Err(Error::ImmatureCoinbase { height: 50, required: 150 })
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
            txid: [7u8; 32],
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
        assert!(matches!(
            check_tx(&s, &tx, 10, &NetworkParams::mainnet(), 10_000, 10),
            Err(Error::BadFee(_))
        ));
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
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn coinbase_is_not_a_normal_tx() {
        let s = UtxoSet::new();
        let cb = Transaction::coinbase([1u8; 32], 1, tagged(1, 0));
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
}