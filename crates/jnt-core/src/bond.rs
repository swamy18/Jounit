//! Bonded validator stake (Decision 20 — P2, SPEC.md §14.6 amendment).
//!
//! A bond is an ordinary UTXO output paid to a derived, keyless bond identity —
//! and consumed into the [`BondLedger`] by the same block that creates it.
//! The output exists only inside the bonding transaction (conservation needs
//! it declared); it never rests in the UTXO set, so a later release cannot
//! double-count it against issuance. Unbonding recreates the value as a fresh
//! output, slashing deletes it into the vault.
//!
//! # What this module is
//!
//! - [`BondLedger`]: the live map of active bonds plus a bond-order index, so
//!   the committee is always the 21 highest-staked bonds — one definition
//!   shared by signing, slashing and finality, no history walk, no snapshots.
//! - Pure validators — [`check_bond_tx`], [`check_unbond_tx`],
//!   [`check_slash_tx`] — shared by block application and mempool admission,
//!   so the pool never holds what a block would refuse.
//! - [`BondUndoOp`] + [`unwind_bond_op`]: the inverse operations reorgs need.
//!
//! # What this module is not
//!
//! - **Not the vault.** Slashing writes a full-bond `SlashRecord` through
//!   `slash::SlashVault` (Decision 2 item 4); this module only decides *that*
//!   a slash happens and for how much. The vault, its vesting and its undo
//!   live with the chain state that owns them.
//! - **Not custody.** Bond outputs are unspendable by signature; release and
//!   burn happen only through `TX_UNBOND` / `TX_SLASH` consensus effects.
//! - **Not rewards.** Checkpoint signing earns nothing (Decision 2 item 3
//!   stands); adding any reward is a monetary decision, out of scope.
//!
//! # Fail-closed rules (locked)
//!
//! - below-minimum bonds, duplicate bonds, duplicate BLS keys, bad keys,
//!   bonds whose BLS key has no proof of possession, and multi-signer bond
//!   transactions are refused by name;
//! - unbonding before `bond_height + UNBONDING_PERIOD_BLOCKS`, by anyone but
//!   the bonder, or of an unknown bond is refused;
//! - slashing requires two checkpoints that both verify against the current
//!   committee, name the same height with different hashes, and share a
//!   signer. The offender is drawn from the bond-derived set itself, so it is
//!   bonded by construction — evidence for a key outside the set cannot
//!   verify, and an unbonded key leaves the set, which closes the evidence
//!   window with no special case;
//! - every refusal names its rule (`Error::StakeInvalid`) and commits nothing.

use crate::bls_checkpoint::{verify_checkpoint, BlsPublicKey, BlsSignature, ValidatorSet};
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, Hash, Hash512};
use crate::slash::{VESTING_BLOCKS_MAINNET, VESTING_BLOCKS_MINI};
use crate::tx::{StakePayload, Transaction, TX_BOND, TX_SLASH, TX_UNBOND};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Minimum bond: 5,000 JNT, fixed in the consensus rules (Decision 20 item 1,
/// launch principle: an immutable constant, never a tunable).
pub const MIN_VALIDATOR_STAKE_SAT: u64 = 5_000 * crate::params::SAT_PER_JNT;
/// Unbonding delay: 7 days at the mainnet 10-minute block time (Decision 20
/// item 3, fixed). On 1-second test profiles the same count is ~17 minutes,
/// which is a faster test cycle, not a weaker rule.
pub const UNBONDING_PERIOD_BLOCKS: u64 = 1008;
/// Committee size: the 21 highest-staked bonds (Decision 20 item 2 fixes the
/// size at 21; the *selection* is stake-top-N, `SelectionRule::TopN`, so that
/// signing, slashing and finality all name the same 21 keys).
pub const MAX_COMMITTEE_SIZE: usize = 21;
/// Domain tag for the derived bond identity.
pub const DOM_BOND_IDENTITY: &[u8] = b"jounit/bond-identity/v1";
/// Domain tag for a bond's proof of possession (rogue-key defence).
///
/// Distinct from [`DOM_BOND_IDENTITY`]: a signature proving key possession
/// must never be interchangeable with anything else a key is bound to.
pub const DOM_BOND_POP: &[u8] = b"jounit/bond-pop/v1";

/// A bond's id is the txid of the `TX_BOND` transaction that created it.
pub type BondId = Hash512;

/// One active bond. Records exist only while bonded: unbonding deletes the
/// record and releases the value, slashing deletes it into the vault — so no
/// status flag is needed and every map entry is an eligible validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondRecord {
    /// Address that funded the bond and may unbond it (the bond tx's signer).
    pub bonder: Address,
    /// BLS key the bond authorizes for checkpoints.
    pub bls_pk: BlsPublicKey,
    /// Lattice key the bond registers for checkpoint sidecars, if any. Never
    /// the committee identity (that stays the BLS key), only the key clause 7
    /// looks up for this validator's sidecar entry.
    pub mldsa_pk: Option<[u8; 1952]>,
    /// Locked value, always `>= MIN_VALIDATOR_STAKE_SAT` by construction.
    pub amount_sat: u64,
    /// Height of the block that bonded.
    pub bond_height: u64,
    /// Transaction index within that block (bond order tie-break).
    pub bond_index: u32,
}

/// The live bond set. The `order` index keeps committee derivation O(21):
/// iteration starts at the earliest bond and stops at 21, however many bonds
/// exist. Iteration order is what makes the committee deterministic across
/// nodes — never touch `by_key` (a `HashMap`) for consensus.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BondLedger {
    bonds: BTreeMap<BondId, BondRecord>,
    order: BTreeSet<(u64, u32, BondId)>,
    by_key: HashMap<BlsPublicKey, BondId>,
}

impl BondLedger {
    pub fn len(&self) -> usize {
        self.bonds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bonds.is_empty()
    }

    /// All active bond records in ledger order (bond_height, bond_index, id).
    /// Consensus iteration: never `by_key` (a HashMap).
    pub fn records(&self) -> Vec<BondRecord> {
        self.order
            .iter()
            .filter_map(|(_, _, id)| self.bonds.get(id).cloned())
            .collect()
    }

    pub fn get(&self, id: &BondId) -> Option<&BondRecord> {
        self.bonds.get(id)
    }

    /// The bond authorizing `key`, if any key is bonded under it.
    pub fn find_by_key(&self, key: &BlsPublicKey) -> Option<(BondId, &BondRecord)> {
        let id = self.by_key.get(key)?;
        Some((*id, self.bonds.get(id)?))
    }

    /// Insert a bond. Overwrites on the same id — the undo path restores a
    /// removed record through this same function.
    pub fn insert(&mut self, id: BondId, record: BondRecord) {
        self.order
            .insert((record.bond_height, record.bond_index, id));
        self.by_key.insert(record.bls_pk, id);
        self.bonds.insert(id, record);
    }

    /// Delete a bond, returning what was there.
    pub fn remove(&mut self, id: &BondId) -> Option<BondRecord> {
        let record = self.bonds.remove(id)?;
        self.order
            .remove(&(record.bond_height, record.bond_index, *id));
        self.by_key.remove(&record.bls_pk);
        Some(record)
    }

    /// The committee: the `MAX_COMMITTEE_SIZE` highest-staked bonds, returned
    /// in canonical key order.
    ///
    /// This is the *single* committee definition. It is consumed by signing
    /// (`Chain::committee_keys` / `committee_signing_records`), by slashing
    /// (`Chain::apply_block`'s `TX_SLASH` arm) and by finality
    /// (`Chain::committee_records`, whose `derive_set(TopN)` re-derives the
    /// same 21) — three callers that previously disagreed: signing and slashing
    /// took the *first* 21 bonds by `(bond_height, bond_index)` while finality
    /// took the *top* 21 by stake, so once a 22nd bond existed the two sides of
    /// a certificate named different key sets and no checkpoint could verify.
    ///
    /// Selection reproduces `validators::derive_set`'s TopN rule byte for byte
    /// — stake descending, ties broken by the record's canonical key order,
    /// capped at 21 — and the result is sorted into the same canonical key
    /// order the epoch set uses, so bitmap indices mean the same thing
    /// whichever caller asked. Bond order is deliberately *not* part of it:
    /// the earliest 21 bonds holding seats forever is both a permanent
    /// incumbency and the one property that could not be re-derived from
    /// stake.
    pub fn committee(&self) -> Vec<BondRecord> {
        let mut by_stake: Vec<&BondRecord> = self.bonds.values().collect();
        by_stake.sort_by(|a, b| {
            b.amount_sat
                .cmp(&a.amount_sat)
                .then_with(|| a.bls_pk.as_bytes().cmp(b.bls_pk.as_bytes()))
        });
        let mut chosen: Vec<BondRecord> = by_stake
            .into_iter()
            .take(MAX_COMMITTEE_SIZE)
            .cloned()
            .collect();
        chosen.sort_by(|a, b| a.bls_pk.as_bytes().cmp(b.bls_pk.as_bytes()));
        chosen
    }
}

/// Inverse of one ledger mutation, for reorg unwinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondUndoOp {
    /// A bond this block created: delete it on unwind.
    Inserted(BondId),
    /// A bond this block removed (unbond/slash): restore it on unwind. Boxed:
    /// a record carries an optional 1952-byte lattice key, and an undo log
    /// holding that inline would make every stake op pay for the largest one.
    Removed(BondId, Box<BondRecord>),
}

/// Per-block stake accumulator, threaded through block application the way
/// `Undo` is: ledger inverses for the block's undo record, slash value for
/// the burn totals, and the vault's pre-block state when this block touched
/// it (slash event or vesting advance with active records).
#[derive(Debug, Default)]
pub struct StakeApply {
    pub ops: Vec<BondUndoOp>,
    pub slash_burned: u64,
    pub vault_before: Option<crate::slash::SlashVault>,
}

/// Apply one inverse operation. Total with the forward path: unwind(apply(x))
/// is the identity, so a rolled-back block leaves the ledger exactly as it
/// found it.
pub fn unwind_bond_op(ledger: &mut BondLedger, op: &BondUndoOp) {
    match op {
        BondUndoOp::Inserted(id) => {
            ledger.remove(id);
        }
        BondUndoOp::Removed(id, record) => {
            ledger.insert(*id, record.as_ref().clone());
        }
    }
}

/// The derived, keyless identity a bond output pays to. Network-bound (a
/// mainnet bond is not a mini bond) and bound to both the bonder and the key,
/// so a bond output can only ever mean this bond.
pub fn bond_identity(network_id: &str, bonder: &Address, pk: &BlsPublicKey) -> Address {
    let h = sha256_dom(
        DOM_BOND_IDENTITY,
        &[network_id.as_bytes(), bonder, pk.as_bytes()],
    );
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

/// Slash-vesting period for a network: the 1-year mainnet schedule, the
/// compressed mini/testnet schedule elsewhere. Fixed per network, not a
/// tunable (launch principle).
pub fn slash_vesting_period(network_id: &str) -> u64 {
    if network_id == "jounit/mainnet" {
        VESTING_BLOCKS_MAINNET
    } else {
        VESTING_BLOCKS_MINI
    }
}

/// The message a bonder signs to prove they hold the BLS secret key behind a
/// proposed bond key: `sha256_dom(DOM_BOND_POP, network ‖ bonder ‖ pk)`.
///
/// Bound to the network (a mini proof cannot authorize a mainnet bond), to the
/// bonder (so a proof cannot be lifted into someone else's bond transaction),
/// and to the key itself (so one proof cannot cover a different key).
pub fn bond_pop_message(network_id: &str, bonder: &Address, pk: &BlsPublicKey) -> Hash {
    sha256_dom(
        DOM_BOND_POP,
        &[network_id.as_bytes(), bonder, pk.as_bytes()],
    )
}

/// Produce a proof of possession for `sk`'s own public key. The public key is
/// derived from the secret key rather than passed in, so a caller cannot
/// accidentally certify somebody else's key with their own signature.
pub fn bond_pop(sk: &crate::bls::SecretKey, network_id: &str, bonder: &Address) -> BlsSignature {
    let pk = sk.public_key();
    sk.sign(&bond_pop_message(network_id, bonder, &pk))
}

/// The single signer of a stake transaction's inputs. Bond operations speak
/// for exactly one identity: inputs from two wallets are refused rather than
/// assigned to the first.
pub fn bonder_of(tx: &Transaction) -> Result<Address> {
    let mut signer: Option<Address> = None;
    for input in &tx.inputs {
        let a = input.keys.address()?;
        match signer {
            None => signer = Some(a),
            Some(s) if s == a => {}
            Some(_) => {
                return Err(Error::StakeInvalid(
                    "stake transaction inputs must share one signer",
                ));
            }
        }
    }
    signer.ok_or(Error::StakeInvalid("stake transaction needs an input"))
}

/// Validated bond components, ready for the ledger. The caller supplies the
/// block position (`bond_index`); mempool admission passes 0 and discards the
/// draft, since admission validates but records nothing.
pub struct BondDraft {
    pub bonder: Address,
    pub bls_pk: BlsPublicKey,
    pub mldsa_pk: Option<[u8; 1952]>,
    pub amount_sat: u64,
}

/// Validate a `TX_BOND` against the ledger: shape, key, proof of possession,
/// signer, identity and minimum. UTXO checks (signatures, conservation, fees)
/// already ran in `check_tx`; this is the stake overlay alone, so mempool and
/// block application share it byte for byte.
///
/// The proof of possession is what stops two attacks that a plain key check
/// cannot:
///
/// - **key squatting** — bonding *someone else's* published BLS key first so
///   their own bond is refused as a duplicate, freezing them out of the
///   committee forever;
/// - **rogue-key aggregation** — registering a key chosen relative to a
///   victim's key (`g^a · Y^-1`) so a later aggregate verifies under the
///   attacker's control. Requiring a signature *from* the key at bond time is
///   the standard defence: producing it requires knowing its discrete log,
///   which the rogue construction does not have.
///
/// The proof is verified against the real BLS verifier, not a mock: a bond is
/// admitted by consensus, so the check must be the same on every node.
pub fn check_bond_tx(tx: &Transaction, bonds: &BondLedger, network_id: &str) -> Result<BondDraft> {
    if tx.tx_type != TX_BOND {
        return Err(Error::StakeInvalid("not a bond transaction"));
    }
    let (bls_pk, pop, mldsa_pk) = match &tx.stake {
        Some(StakePayload::Bond {
            bls_pk,
            pop,
            mldsa_pk,
        }) => (*bls_pk, *pop, mldsa_pk.clone()),
        _ => return Err(Error::StakeInvalid("bond transaction without bond payload")),
    };
    let bonder = bonder_of(tx)?;
    crate::bls::validate_public_key(&bls_pk)
        .map_err(|_| Error::StakeInvalid("bond BLS key invalid"))?;
    // Proof of possession, bound to this network, this bonder and this key.
    // Checked before anything ledger-shaped: if the bonder cannot sign for the
    // key there is no bond here, whatever the outputs say.
    let pop_msg = bond_pop_message(network_id, &bonder, &bls_pk);
    if !crate::bls::RealBls::verify(&bls_pk, &pop_msg, &pop) {
        return Err(Error::StakeInvalid(
            "bond proof of possession did not verify",
        ));
    }
    // The lattice key needs no cryptographic check here: any 1952 bytes decode
    // structurally (FIPS 204 vkDecode is total), and the check that matters —
    // that its signatures verify — runs at checkpoint time, not bond time. A
    // garbage key buys its registrant nothing: their sidecar entries will
    // simply never verify, and clause 7 will refuse checkpoints that need
    // them. What *is* refused here is sharing: one lattice key under two BLS
    // identities would let one holder sign for two stakes.
    if let Some(pk) = &mldsa_pk {
        if bonds
            .records()
            .iter()
            .any(|r| r.mldsa_pk.as_ref() == Some(pk))
        {
            return Err(Error::StakeInvalid("lattice key already bonded"));
        }
    }
    if bonds.find_by_key(&bls_pk).is_some() {
        return Err(Error::StakeInvalid("BLS key already bonded"));
    }
    let expect = bond_identity(network_id, &bonder, &bls_pk);
    let mut bond_outs = tx.outputs.iter().filter(|o| o.address == expect);
    let (first, second) = (bond_outs.next(), bond_outs.next());
    let bond_out = match (first, second) {
        (Some(o), None) => o,
        _ => {
            return Err(Error::StakeInvalid(
                "bond needs exactly one bond-identity output",
            ));
        }
    };
    if bond_out.value < MIN_VALIDATOR_STAKE_SAT {
        return Err(Error::StakeInvalid("bond below minimum stake"));
    }
    Ok(BondDraft {
        bonder,
        bls_pk,
        mldsa_pk: mldsa_pk.map(|b| *b),
        amount_sat: bond_out.value,
    })
}

/// Validate a `TX_UNBOND`: known bond, signed by the bonder, past the lock.
/// Returns the bond id and record; the caller deletes the record and creates
/// the release output.
pub fn check_unbond_tx(
    tx: &Transaction,
    bonds: &BondLedger,
    height: u64,
) -> Result<(BondId, BondRecord)> {
    if tx.tx_type != TX_UNBOND {
        return Err(Error::StakeInvalid("not an unbond transaction"));
    }
    let bond_id = match &tx.stake {
        Some(StakePayload::Unbond { bond_id }) => *bond_id,
        _ => {
            return Err(Error::StakeInvalid(
                "unbond transaction without unbond payload",
            ));
        }
    };
    let record = bonds
        .get(&bond_id)
        .cloned()
        .ok_or(Error::StakeInvalid("unbond of unknown bond"))?;
    let signer = bonder_of(tx)?;
    if signer != record.bonder {
        return Err(Error::StakeInvalid("unbond signer is not the bonder"));
    }
    let unlocks = record
        .bond_height
        .checked_add(UNBONDING_PERIOD_BLOCKS)
        .ok_or(Error::ValueOverflow)?;
    if height < unlocks {
        return Err(Error::StakeInvalid("bond still locked"));
    }
    Ok((bond_id, record))
}

/// Validate a `TX_SLASH` carrying equivocation evidence: two checkpoints that
/// both verify against the current committee, name the same height with
/// different hashes, and share a signer. Returns the bond id and record; the
/// caller deletes the record and writes the full-bond slash into the vault.
///
/// The offender needs no separate bondedness check: it is drawn from the
/// signers of checkpoints that verified against the bond-derived committee,
/// so it is bonded by construction. Evidence for a key outside the committee
/// fails verification, and an unbonded key leaves the committee — the
/// unbonding delay is the evidence window with no special case.
pub fn check_slash_tx(
    tx: &Transaction,
    bonds: &BondLedger,
    committee: &[BlsPublicKey],
    network_id: &str,
    height: u64,
    verifier: &dyn crate::bls_checkpoint::BlsVerifier,
) -> Result<(BondId, BondRecord)> {
    if tx.tx_type != TX_SLASH {
        return Err(Error::StakeInvalid("not a slash transaction"));
    }
    let (first, second) = match &tx.stake {
        Some(StakePayload::Slash { first, second }) => (first, second),
        _ => {
            return Err(Error::StakeInvalid(
                "slash transaction without slash payload",
            ));
        }
    };
    if first.payload.height != second.payload.height {
        return Err(Error::StakeInvalid("slash checkpoints differ in height"));
    }
    if first.payload.height > height {
        return Err(Error::StakeInvalid("slash evidence above tip"));
    }
    if first.payload.block_hash == second.payload.block_hash {
        return Err(Error::StakeInvalid("slash checkpoints do not conflict"));
    }
    if first.payload.network_id != network_id || second.payload.network_id != network_id {
        return Err(Error::StakeInvalid("slash evidence wrong network"));
    }
    // Cheap checks before crypto: the offender must still be bonded, or there
    // is nothing to burn and no pairing is worth doing.
    let set = ValidatorSet::new(committee.to_vec());
    let signers_first = set.signers_from_bitmap(&first.signer_bitmap);
    let signers_second = set.signers_from_bitmap(&second.signer_bitmap);
    let offender = signers_first
        .iter()
        .find(|k| signers_second.contains(k))
        .ok_or(Error::StakeInvalid("slash checkpoints share no signer"))?;
    let (bond_id, record) = bonds
        .find_by_key(offender)
        .map(|(id, r)| (id, r.clone()))
        .ok_or(Error::StakeInvalid("slash offender has no active bond"))?;
    verify_checkpoint(first, &set, verifier)
        .map_err(|_| Error::StakeInvalid("slash first checkpoint invalid"))?;
    verify_checkpoint(second, &set, verifier)
        .map_err(|_| Error::StakeInvalid("slash second checkpoint invalid"))?;
    Ok((bond_id, record))
}

/// Pure stake admission: the checks without any mutation. Mempool admission
/// shares it so the pool never holds what a block would refuse. Intra-block
/// ordering effects (a duplicate later in the same block) are the block
/// builder's filter, not the pool's — the pool sees arrivals one at a time,
/// while a block sees them in order.
pub fn admit_stake_tx(
    tx: &Transaction,
    bonds: &BondLedger,
    network_id: &str,
    height: u64,
    verifier: &dyn crate::bls_checkpoint::BlsVerifier,
) -> Result<()> {
    match tx.tx_type {
        TX_BOND => {
            check_bond_tx(tx, bonds, network_id)?;
        }
        TX_UNBOND => {
            check_unbond_tx(tx, bonds, height)?;
        }
        TX_SLASH => {
            let committee: Vec<BlsPublicKey> =
                bonds.committee().into_iter().map(|r| r.bls_pk).collect();
            check_slash_tx(tx, bonds, &committee, network_id, height, verifier)?;
        }
        _ => {}
    }
    Ok(())
}

/// Scratch-ledger stake transition: validate AND mutate a scratch ledger.
/// Mempool admission and block building share it so both see the same rule;
/// chain application uses the finer checks above plus vault effects.
///
/// `tx_index` orders bonds within a block (admission passes 0 and records
/// nothing permanent — the chain re-derives the real index at apply). Release
/// outputs and vault effects are apply-time concerns the scratch ledger does
/// not need: admission and building only decide *valid*, never *settled*.
pub fn probe_stake_tx(
    tx: &Transaction,
    bonds: &mut BondLedger,
    network_id: &str,
    height: u64,
    tx_index: u32,
    verifier: &dyn crate::bls_checkpoint::BlsVerifier,
) -> Result<()> {
    match tx.tx_type {
        TX_BOND => {
            let draft = check_bond_tx(tx, bonds, network_id)?;
            bonds.insert(
                tx.txid(),
                BondRecord {
                    bonder: draft.bonder,
                    bls_pk: draft.bls_pk,
                    mldsa_pk: draft.mldsa_pk,
                    amount_sat: draft.amount_sat,
                    bond_height: height,
                    bond_index: tx_index,
                },
            );
        }
        TX_UNBOND => {
            let (id, _) = check_unbond_tx(tx, bonds, height)?;
            bonds.remove(&id);
        }
        TX_SLASH => {
            let committee: Vec<BlsPublicKey> =
                bonds.committee().into_iter().map(|r| r.bls_pk).collect();
            let (id, _) = check_slash_tx(tx, bonds, &committee, network_id, height, verifier)?;
            bonds.remove(&id);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Input, OutPoint, Transaction};

    const NET: &str = "jounit/testnet";

    fn bls_key(seed: u8) -> BlsPublicKey {
        crate::bls::SecretKey::derive(&[seed; 32])
            .unwrap()
            .public_key()
    }

    fn unsigned_input() -> Input {
        Input::unsigned(&OutPoint {
            txid: [1u8; 64],
            index: 0,
        })
    }

    #[test]
    fn bond_identity_is_network_bound_and_unique() {
        let pk = bls_key(7);
        let a = bond_identity(NET, &[1u8; 20], &pk);
        assert_ne!(a, bond_identity("jounit/mini", &[1u8; 20], &pk));
        assert_ne!(a, bond_identity(NET, &[2u8; 20], &pk));
        assert_ne!(a, bond_identity(NET, &[1u8; 20], &bls_key(8)));
    }

    #[test]
    fn committee_takes_the_top_21_by_stake_in_key_order() {
        let mut ledger = BondLedger::default();
        for i in 0u8..25 {
            let height = 100 + u64::from(i);
            ledger.insert(
                [i; 64],
                BondRecord {
                    bonder: [i; 20],
                    bls_pk: bls_key(i + 1),
                    mldsa_pk: None,
                    // Stake rises with i, so the four earliest bonds are also
                    // the four lowest: under the old "first 21 by bond order"
                    // rule they kept their seats, under TopN they are cut.
                    amount_sat: MIN_VALIDATOR_STAKE_SAT + u64::from(i) * 1_000,
                    bond_height: height,
                    bond_index: 0,
                },
            );
        }
        let committee = ledger.committee();
        assert_eq!(committee.len(), MAX_COMMITTEE_SIZE);
        let selected: Vec<crate::bls_checkpoint::BlsPublicKey> =
            committee.iter().map(|r| r.bls_pk).collect();
        // The 21 highest stakes are in, the four lowest are out.
        for i in 4u8..25 {
            assert!(
                selected.contains(&bls_key(i + 1)),
                "bond {i} is above the stake cut and must be seated"
            );
        }
        for i in 0u8..4 {
            assert!(
                !selected.contains(&bls_key(i + 1)),
                "bond {i} is below the stake cut and must lose its seat"
            );
        }
        // Canonical key order: the same order `derive_set` puts the epoch set
        // in, so a bitmap index means the same member to every caller.
        let mut sorted = selected.clone();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(selected, sorted, "committee must be in canonical key order");
    }

    #[test]
    fn two_signers_are_refused_not_assigned_to_the_first() {
        use crate::l2::Auth;
        use crate::wallet::Wallet;
        let w1 = Wallet::new_random("one");
        let w2 = Wallet::new_random("two");
        let mut i1 = unsigned_input();
        i1.keys = Auth::keys_for(&w1).unwrap();
        let mut i2 = unsigned_input();
        i2.keys = Auth::keys_for(&w2).unwrap();
        let tx = Transaction {
            version: 1,
            tx_type: TX_BOND,
            lock_time: 0,
            inputs: vec![i1, i2],
            outputs: vec![],
            stake: None,
        };
        assert_eq!(
            bonder_of(&tx).unwrap_err(),
            Error::StakeInvalid("stake transaction inputs must share one signer")
        );
    }

    #[test]
    fn unwind_is_the_exact_inverse_of_apply() {
        let mut ledger = BondLedger::default();
        let record = BondRecord {
            bonder: [3u8; 20],
            bls_pk: bls_key(3),
            mldsa_pk: None,
            amount_sat: MIN_VALIDATOR_STAKE_SAT,
            bond_height: 10,
            bond_index: 1,
        };
        ledger.insert([9u8; 64], record.clone());
        unwind_bond_op(&mut ledger, &BondUndoOp::Inserted([9u8; 64]));
        assert!(ledger.is_empty());

        ledger.insert([9u8; 64], record.clone());
        let back = ledger.remove(&[9u8; 64]).unwrap();
        assert_eq!(back, record);
        unwind_bond_op(
            &mut ledger,
            &BondUndoOp::Removed([9u8; 64], Box::new(record.clone())),
        );
        assert_eq!(ledger.get(&[9u8; 64]), Some(&record));
        // Key index restored too: the same key bonds once.
        assert!(ledger.find_by_key(&record.bls_pk).is_some());
    }
}
