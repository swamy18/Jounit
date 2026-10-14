//! Bonded-stake suite (Decision 20 â€” P2).
//!
//! Written attack-first: each test builds the *hostile* stake transaction a
//! compromised or careless validator would submit and asserts the exact clause
//! that refuses it. The properties that matter are (1) no bond, unbond or
//! slash commits unless every rule holds, (2) a refused block leaves the bond
//! ledger and the vault exactly as found, and (3) the committee always follows
//! the ledger â€” first 21 bonds by bond order, genesis fallback when empty.
//!
//! Run with `cargo test -p jnt-core --test bond_stake`.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{BlsPublicKey, Checkpoint, CheckpointPayload};
use jnt_core::bond::{bond_identity, MIN_VALIDATOR_STAKE_SAT, UNBONDING_PERIOD_BLOCKS};
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::hash::Address;
use jnt_core::mempool::Mempool;
use jnt_core::params::NetworkParams;
use jnt_core::tx::{
    Input, OutPoint, Output, StakePayload, Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE,
    TX_BOND, TX_SLASH, TX_UNBOND,
};
use jnt_core::wallet::Wallet;

const BOND: u64 = MIN_VALIDATOR_STAKE_SAT;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "bond-stake").unwrap()
}

fn bls_pair(seed: u8) -> (SecretKey, BlsPublicKey) {
    let sk = SecretKey::derive(&[seed; 32]).unwrap();
    let pk = sk.public_key();
    (sk, pk)
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn gas(n_in: usize, n_out: usize) -> u64 {
    GAS_TX_BASE + GAS_PER_INPUT * n_in as u64 + GAS_PER_OUTPUT * n_out as u64
}

/// Mine `n` empty blocks to `to`.
fn mine(chain: &mut Chain, to: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(to, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// A chain with one rich wallet: 80 coinbases mined, the matured ones
/// returned. 70 Ã— 76 JNT funds a 5,000-JNT bond with room for fees.
fn rich_chain() -> (Chain, Wallet, Vec<OutPoint>) {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let w = wallet(1);
    let addr = w.address().unwrap();
    mine(&mut chain, addr, 80);
    let mut ops = Vec::new();
    for h in 1..=70u64 {
        ops.push(OutPoint {
            txid: chain.block_at(h).unwrap().txs[0].txid(),
            index: 0,
        });
    }
    (chain, w, ops)
}

/// Like [`rich_chain`] but with 250 matured outputs, enough to fund several
/// large bonds (66 inputs each) while respecting `coinbase_maturity`.
fn richer_chain() -> (Chain, Wallet, Vec<OutPoint>) {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let w = wallet(1);
    let addr = w.address().unwrap();
    mine(&mut chain, addr, 210);
    let mut ops = Vec::new();
    for h in 1..=200u64 {
        ops.push(OutPoint {
            txid: chain.block_at(h).unwrap().txs[0].txid(),
            index: 0,
        });
    }
    (chain, w, ops)
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas(n_in, n_out))
        .saturating_add(1_000_000)
}

fn utxo_total(chain: &Chain, ops: &[OutPoint]) -> u64 {
    ops.iter()
        .map(|op| chain.utxo().get(op).unwrap().out.value)
        .fold(0u64, |a, v| a.saturating_add(v))
}

/// Bond transaction spending `ops`, locking exactly `BOND` to the derived
/// identity, change back to the wallet. Re-signed after the payload is set â€”
/// the sighash covers the stake bytes, so a payload swap breaks every input.
fn bond_tx(chain: &Chain, w: &Wallet, ops: &[OutPoint], pk: BlsPublicKey) -> Transaction {
    bond_tx_value(chain, w, ops, pk, BOND)
}

fn bond_tx_value(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    pk: BlsPublicKey,
    value: u64,
) -> Transaction {
    let bonder = w.address().unwrap();
    let net = chain.params();
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 2);
    assert!(
        total > value + fee,
        "test funding cannot cover bond plus fee"
    );
    let mut tx = w
        .build_tx(
            ops,
            vec![
                Output {
                    value,
                    address: bond_identity(&net.network_id, &bonder, &pk),
                },
                Output {
                    value: total - value - fee,
                    address: bonder,
                },
            ],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_BOND;
    tx.stake = Some(StakePayload::Bond { bls_pk: pk });
    w.sign(&mut tx).unwrap();
    tx
}

/// Submit one block carrying `txs`; return the submit result.
fn submit_block(chain: &mut Chain, miner: Address, txs: Vec<Transaction>) -> Result<(), Error> {
    let h = chain.height() + 1;
    let b = chain.mine_block(miner, txs, ts(h)).unwrap();
    chain.submit(b)
}

/// Sign `payload` with `sk` alone into a single-signer checkpoint.
fn lone_checkpoint(sk: &SecretKey, payload: CheckpointPayload) -> Checkpoint {
    let msg = payload.signing_hash();
    let agg = RealBls::aggregate(&[sk.sign(&msg)]).unwrap();
    Checkpoint {
        payload,
        aggregate_sig: agg,
        signer_bitmap: vec![1u8],
        signer_count: 1,
    }
}

fn conflicting_pair(sk: &SecretKey, height: u64, network_id: &str) -> (Checkpoint, Checkpoint) {
    let a = CheckpointPayload {
        height,
        block_hash: [0xAAu8; 64],
        network_id: network_id.to_string(),
        epoch: 0,
    };
    let b = CheckpointPayload {
        height,
        block_hash: [0xBBu8; 64],
        network_id: network_id.to_string(),
        epoch: 0,
    };
    (lone_checkpoint(sk, a), lone_checkpoint(sk, b))
}

fn slash_tx(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    first: Checkpoint,
    second: Checkpoint,
) -> Transaction {
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 1);
    let to = w.address().unwrap();
    let mut tx = w
        .build_tx(
            ops,
            vec![Output {
                value: total - fee,
                address: to,
            }],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_SLASH;
    tx.stake = Some(StakePayload::Slash {
        first: Box::new(first),
        second: Box::new(second),
    });
    w.sign(&mut tx).unwrap();
    tx
}

fn unbond_tx(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    bond_id: jnt_core::hash::Hash512,
) -> Transaction {
    let total = utxo_total(chain, ops);
    let fee = fee_for(chain, ops.len(), 1);
    let to = w.address().unwrap();
    let mut tx = w
        .build_tx(
            ops,
            vec![Output {
                value: total - fee,
                address: to,
            }],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_UNBOND;
    tx.stake = Some(StakePayload::Unbond { bond_id });
    w.sign(&mut tx).unwrap();
    tx
}

/// Mine empty blocks until `height` reaches `target`.
fn mine_to(chain: &mut Chain, to: Address, target: u64) {
    while chain.height() < target {
        mine(chain, to, 1);
    }
}

#[test]
fn happy_path_bond_registers_and_joins_the_committee() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(7);
    let bond = bond_tx(&chain, &w, &ops[..66], pk);
    let bond_id = bond.txid();
    submit_block(&mut chain, bonder, vec![bond]).unwrap();

    let record = chain.bonds().get(&bond_id).expect("bond must be recorded");
    assert_eq!(record.bonder, bonder);
    assert_eq!(record.bls_pk, pk);
    assert_eq!(record.amount_sat, BOND);

    // The committee follows the ledger: the bonded key, and only it.
    assert_eq!(chain.committee_keys(), vec![pk]);

    // Finality follows too: a checkpoint signed by the bonded key verifies
    // against the live committee and is accepted (observation on mini).
    let h = chain.height();
    let interval = chain.params().checkpoint_interval_blocks;
    let payload = CheckpointPayload {
        height: h,
        block_hash: chain.block_at(h).unwrap().block_hash(),
        network_id: "jounit/mini".into(),
        epoch: CheckpointPayload::epoch_for(h, interval),
    };
    let (sk, _) = bls_pair(7);
    let cp = lone_checkpoint(&sk, payload);
    chain.apply_checkpoint(&cp, &RealBls).unwrap();
    assert_eq!(chain.finality().accepted_height(), h);
}

#[test]
fn a_checkpoint_from_outside_the_bonded_committee_is_refused() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(7);
    let first_bond = bond_tx(&chain, &w, &ops[..66], pk);
    submit_block(&mut chain, bonder, vec![first_bond]).unwrap();
    assert_eq!(chain.committee_keys(), vec![pk]);

    // A stranger's key signs a well-formed checkpoint â€” but the committee is
    // the bonded key now, so the bitmap names nobody and quorum fails.
    let h = chain.height();
    let interval = chain.params().checkpoint_interval_blocks;
    let payload = CheckpointPayload {
        height: h,
        block_hash: chain.block_at(h).unwrap().block_hash(),
        network_id: "jounit/mini".into(),
        epoch: CheckpointPayload::epoch_for(h, interval),
    };
    let (stranger, _) = bls_pair(9);
    let cp = lone_checkpoint(&stranger, payload);
    assert!(chain.apply_checkpoint(&cp, &RealBls).is_err());
    assert_eq!(chain.committee_keys(), vec![pk]);
}

#[test]
fn bond_refusals_name_their_rule_and_record_nothing() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let net_id = chain.params().network_id.clone();
    let (_, pk) = bls_pair(7);
    let (_, other_pk) = bls_pair(8);
    let fee = fee_for(&chain, 1, 2);
    let total = utxo_total(&chain, &ops[..1]);

    // Below-minimum bond, fully funded so the refusal is the minimum rule.
    let small = bond_tx_value(&chain, &w, &ops[..66], pk, MIN_VALIDATOR_STAKE_SAT - 1);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![small]).unwrap_err(),
        Error::StakeInvalid("bond below minimum stake")
    );

    // Bond type without a payload.
    let mut no_payload = w
        .build_tx(
            &ops[1..2],
            vec![Output {
                value: total - fee,
                address: bonder,
            }],
            fee,
        )
        .unwrap();
    no_payload.tx_type = TX_BOND;
    w.sign(&mut no_payload).unwrap();
    assert_eq!(
        submit_block(&mut chain, bonder, vec![no_payload]).unwrap_err(),
        Error::StakeInvalid("bond transaction without bond payload")
    );

    // Payload names pk but the output pays other's identity: no output funds
    // this bond.
    let total1 = utxo_total(&chain, &ops[2..3]);
    let fee1 = fee_for(&chain, 1, 2);
    let mut wrong_addr = w
        .build_tx(
            &ops[2..3],
            vec![
                Output {
                    value: total1 - fee1 - 1_000,
                    address: bond_identity(&net_id, &bonder, &other_pk),
                },
                Output {
                    value: 1_000,
                    address: bonder,
                },
            ],
            fee1,
        )
        .unwrap();
    wrong_addr.tx_type = TX_BOND;
    wrong_addr.stake = Some(StakePayload::Bond { bls_pk: pk });
    w.sign(&mut wrong_addr).unwrap();
    assert_eq!(
        submit_block(&mut chain, bonder, vec![wrong_addr]).unwrap_err(),
        Error::StakeInvalid("bond needs exactly one bond-identity output")
    );

    assert!(chain.bonds().is_empty(), "refusals must record nothing");
    assert_eq!(
        chain.committee_keys(),
        chain.params().genesis_validators.clone(),
        "committee stays on the genesis fallback"
    );
}

#[test]
fn duplicate_bonds_and_duplicate_keys_are_refused() {
    // Two bonds worth of funding: 150 blocks, ~140 matured coinbases.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let w = wallet(1);
    let bonder = w.address().unwrap();
    mine(&mut chain, bonder, 150);
    let mut ops = Vec::new();
    for h in 1..=140u64 {
        ops.push(OutPoint {
            txid: chain.block_at(h).unwrap().txs[0].txid(),
            index: 0,
        });
    }
    let (_, pk) = bls_pair(7);
    let first_bond = bond_tx(&chain, &w, &ops[..66], pk);
    submit_block(&mut chain, bonder, vec![first_bond]).unwrap();
    assert_eq!(chain.bonds().len(), 1);

    // Same bonder, same key again â€” well funded, refused as a duplicate.
    let again = bond_tx(&chain, &w, &ops[66..132], pk);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![again]).unwrap_err(),
        Error::StakeInvalid("BLS key already bonded")
    );
    assert_eq!(chain.bonds().len(), 1);

    // A stranger's bond for the taken key refuses with the same rule.
    let w2 = wallet(2);
    let bonder2 = w2.address().unwrap();
    mine(&mut chain, bonder2, 80);
    let tip = chain.height();
    let mut ops2 = Vec::new();
    for h in 1..=tip {
        let block = chain.block_at(h).unwrap();
        if block.txs[0].outputs.iter().any(|o| o.address == bonder2) && h + 10 <= tip + 1 {
            ops2.push(OutPoint {
                txid: block.txs[0].txid(),
                index: 0,
            });
        }
    }
    assert!(ops2.len() >= 66, "stranger needs a funded bond attempt");
    let stranger = bond_tx(&chain, &w2, &ops2[..66], pk);
    assert_eq!(
        submit_block(&mut chain, bonder2, vec![stranger]).unwrap_err(),
        Error::StakeInvalid("BLS key already bonded")
    );
    assert_eq!(chain.bonds().len(), 1);
}

#[test]
fn unknown_tx_type_is_refused_not_interpreted() {
    let net = NetworkParams::mini();
    let mut utxo = jnt_core::ledger::UtxoSet::new();
    let w = wallet(1);
    let op = OutPoint {
        txid: [4u8; 64],
        index: 0,
    };
    utxo.insert(
        op,
        jnt_core::ledger::Utxo {
            out: Output {
                value: 1_000_000_000,
                address: w.address().unwrap(),
            },
            height: 0,
        },
    );
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&op)],
        vec![Output {
            value: 999_000_000,
            address: [9u8; 20],
        }],
    );
    w.sign(&mut tx).unwrap();
    tx.tx_type = 9;
    assert_eq!(
        jnt_core::ledger::check_tx(&utxo, &tx, 20, &net, 0, 10).unwrap_err(),
        Error::Malformed("unknown tx_type")
    );
}

#[test]
fn mempool_admits_a_valid_bond_and_refuses_a_broken_one() {
    let (chain, w, ops) = rich_chain();
    let net = chain.params().clone();
    let (_, pk) = bls_pair(7);
    let mut pool = Mempool::default();
    let h = chain.height() + 1;
    let base = chain.expected_base_fee_for_next_block();

    // A well-formed bond is poolable.
    let bond = bond_tx(&chain, &w, &ops[..66], pk);
    pool.add(bond, chain.utxo(), h, &net, base, chain.bonds())
        .expect("a valid bond must pool");

    // A below-minimum impostor with the same shape is refused by name.
    let bonder = w.address().unwrap();
    let fee = fee_for(&chain, 1, 2);
    let total = utxo_total(&chain, &ops[67..68]);
    let mut small = w
        .build_tx(
            &ops[67..68],
            vec![
                Output {
                    value: 1_000,
                    address: bond_identity(&net.network_id, &bonder, &pk),
                },
                Output {
                    value: total - 1_000 - fee,
                    address: bonder,
                },
            ],
            fee,
        )
        .unwrap();
    small.tx_type = TX_BOND;
    small.stake = Some(StakePayload::Bond { bls_pk: pk });
    w.sign(&mut small).unwrap();
    let err = pool
        .add(small, chain.utxo(), h, &net, base, chain.bonds())
        .unwrap_err();
    assert!(
        matches!(err, jnt_core::mempool::MempoolError::Invalid(_)),
        "bond-invalid must be pool-invalid, got {err:?}"
    );
}

#[test]
fn happy_path_unbond_releases_after_the_lock() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(7);
    let bond = bond_tx(&chain, &w, &ops[..66], pk);
    let bond_id = bond.txid();
    submit_block(&mut chain, bonder, vec![bond]).unwrap();
    let bond_height = chain.height();

    // The lock is exact: one block before maturity refuses.
    let early = unbond_tx(&chain, &w, &ops[67..68], bond_id);
    mine_to(
        &mut chain,
        bonder,
        bond_height + UNBONDING_PERIOD_BLOCKS - 2,
    );
    assert_eq!(
        submit_block(&mut chain, bonder, vec![early]).unwrap_err(),
        Error::StakeInvalid("bond still locked")
    );

    // At maturity the release commits: ledger empty, value back as a normal
    // output, committee back on the genesis fallback.
    mine_to(&mut chain, bonder, bond_height + UNBONDING_PERIOD_BLOCKS);
    let unbond = unbond_tx(&chain, &w, &ops[68..69], bond_id);
    let unbond_id = unbond.txid();
    submit_block(&mut chain, bonder, vec![unbond]).unwrap();
    assert!(chain.bonds().is_empty());
    let release = OutPoint {
        txid: unbond_id,
        index: 1,
    };
    let held = chain.utxo().get(&release).expect("release must exist");
    assert_eq!(held.out.value, BOND);
    assert_eq!(held.out.address, bonder);
    assert_eq!(
        chain.committee_keys(),
        chain.params().genesis_validators.clone()
    );

    // And the release spends like any other output â€” after its own 10-block
    // maturity, which applies to every output, not just coinbases.
    let spend_at = chain.height() + 10;
    mine_to(&mut chain, bonder, spend_at);
    let fee = fee_for(&chain, 1, 1);
    let mut spend = w
        .build_tx(
            &[release],
            vec![Output {
                value: BOND - fee,
                address: bonder,
            }],
            fee,
        )
        .unwrap();
    let _ = &mut spend;
    submit_block(&mut chain, bonder, vec![spend]).unwrap();
}

#[test]
fn unbond_refusals_name_their_rule() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(7);
    let bond = bond_tx(&chain, &w, &ops[..66], pk);
    let bond_id = bond.txid();
    submit_block(&mut chain, bonder, vec![bond]).unwrap();

    // Unknown bond.
    let ghost = unbond_tx(&chain, &w, &ops[67..68], [0xFFu8; 64]);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![ghost]).unwrap_err(),
        Error::StakeInvalid("unbond of unknown bond")
    );

    // Wrong signer: a funded stranger signs the release of another's bond.
    let w2 = wallet(2);
    let bonder2 = w2.address().unwrap();
    mine(&mut chain, bonder2, 12);
    let matured = chain.height() - 11;
    let op2 = OutPoint {
        txid: chain.block_at(matured).unwrap().txs[0].txid(),
        index: 0,
    };
    let stranger = unbond_tx(&chain, &w2, &[op2], bond_id);
    assert_eq!(
        submit_block(&mut chain, bonder2, vec![stranger]).unwrap_err(),
        Error::StakeInvalid("unbond signer is not the bonder")
    );

    assert_eq!(chain.bonds().len(), 1, "refusals must not touch the bond");
}

#[test]
fn happy_path_slash_burns_the_full_bond() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk, pk) = bls_pair(7);
    let first_bond = bond_tx(&chain, &w, &ops[..66], pk);
    submit_block(&mut chain, bonder, vec![first_bond]).unwrap();
    assert_eq!(chain.committee_keys(), vec![pk]);

    // Two conflicting checkpoints, both really signed by the bonded key.
    let h = chain.height();
    let (first, second) = conflicting_pair(&sk, h, "jounit/mini");
    let slash = slash_tx(&chain, &w, &ops[67..68], first, second);
    let burned_before = chain.burned_fees_total();
    submit_block(&mut chain, bonder, vec![slash]).unwrap();

    // The bond is gone and the committee falls back.
    assert!(chain.bonds().is_empty());
    assert_eq!(
        chain.committee_keys(),
        chain.params().genesis_validators.clone()
    );
    // Half burned at once (Decision 2 item 4: full bond through the vault).
    // The vault's own counter is exact; the chain burned total carries the
    // block's transaction fee burn on top, so it is only bounded below.
    assert_eq!(chain.slash_vault().total_burned, BOND / 2);
    assert_eq!(chain.slash_vault().active_count(), 1);
    assert!(chain.burned_fees_total() - burned_before >= BOND / 2);

    // Half vests to the PSCB reserve block by block: 125M per mini block.
    // Baslined after the slash block (whose own fee also fed the reserve),
    // then only empty blocks â€” every sat of growth is vesting.
    let pscb_after_slash = chain.pscb_reserve();
    mine(&mut chain, bonder, 5);
    assert_eq!(chain.pscb_reserve() - pscb_after_slash, 5 * 125_000_000);
}

#[test]
fn slash_refusals_name_their_rule() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk, pk) = bls_pair(7);
    let first_bond = bond_tx(&chain, &w, &ops[..66], pk);
    submit_block(&mut chain, bonder, vec![first_bond]).unwrap();
    let h = chain.height();
    let net = "jounit/mini";

    // Same hash twice is a repeat, not equivocation.
    let (first, _) = conflicting_pair(&sk, h, net);
    let repeat = slash_tx(&chain, &w, &ops[67..68], first.clone(), first);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![repeat]).unwrap_err(),
        Error::StakeInvalid("slash checkpoints do not conflict")
    );

    // Evidence above the tip.
    let (future_a, future_b) = conflicting_pair(&sk, h + 100, net);
    let future = slash_tx(&chain, &w, &ops[67..68], future_a, future_b);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![future]).unwrap_err(),
        Error::StakeInvalid("slash evidence above tip")
    );

    // A foreign key signs, but the bitmap claims the bonded member signed:
    // the aggregate does not match the claimed signers, so verification â€”
    // not any bond lookup â€” refuses it. (The offender is drawn from verified
    // bitmaps over the bonded set, so an "unbonded offender" cannot verify
    // in the first place: there is no such rule to pin.)
    let (osk, _) = bls_pair(9);
    let (outsider_a, outsider_b) = conflicting_pair(&osk, h, net);
    // Re-point both bitmaps at the bonded member: the lie is now exact.
    let mut lie_a = outsider_a;
    let mut lie_b = outsider_b;
    lie_a.signer_bitmap = vec![1u8];
    lie_a.signer_count = 1;
    lie_b.signer_bitmap = vec![1u8];
    lie_b.signer_count = 1;
    let outsider = slash_tx(&chain, &w, &ops[67..68], lie_a, lie_b);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![outsider]).unwrap_err(),
        Error::StakeInvalid("slash first checkpoint invalid")
    );

    // Forged aggregate for the bonded key: crypto runs last, and fails.
    let (good_a, good_b) = conflicting_pair(&sk, h, net);
    let mut forged_a = good_a;
    forged_a.aggregate_sig = jnt_core::bls_checkpoint::BlsSignature([0u8; 96]);
    let forged = slash_tx(&chain, &w, &ops[67..68], forged_a, good_b);
    assert_eq!(
        submit_block(&mut chain, bonder, vec![forged]).unwrap_err(),
        Error::StakeInvalid("slash first checkpoint invalid")
    );

    assert_eq!(chain.bonds().len(), 1, "refusals must not touch the bond");
}

#[test]
fn a_reorg_unwinds_the_bond_exactly() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(7);
    let first_bond = bond_tx(&chain, &w, &ops[..66], pk);
    submit_block(&mut chain, bonder, vec![first_bond]).unwrap();
    let bond_tip = chain.height();
    assert_eq!(chain.bonds().len(), 1);

    // A rival with identical history through the parent, then two empty
    // blocks that out-work the bond block. Same miner and timestamps for the
    // shared prefix, so ancestry is shared byte for byte.
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..bond_tip {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    let rival_miner = wallet(2).address().unwrap();
    let r1 = rival.mine_block(rival_miner, vec![], ts(bond_tip)).unwrap();
    rival.submit(r1.clone()).unwrap();
    let r2 = rival
        .mine_block(rival_miner, vec![], ts(bond_tip + 1))
        .unwrap();
    rival.submit(r2.clone()).unwrap();

    chain.submit(r1).unwrap();
    chain.submit(r2).unwrap();
    assert_eq!(chain.height(), bond_tip + 1);
    assert!(chain.bonds().is_empty(), "the reorged bond must unwind");
    assert_eq!(
        chain.committee_keys(),
        chain.params().genesis_validators.clone()
    );
    chain.verify_canonical_chain().unwrap();
}

#[test]
fn committee_falls_back_to_genesis_when_no_bonds_exist() {
    let chain = Chain::new(NetworkParams::mini()).unwrap();
    assert!(chain.bonds().is_empty());
    assert_eq!(
        chain.committee_keys(),
        chain.params().genesis_validators.clone()
    );
    assert_eq!(chain.params().genesis_validators.len(), 4);
}

#[test]
fn stake_transaction_codec_round_trips_exactly() {
    let (chain, w, ops) = rich_chain();
    let (_, pk) = bls_pair(7);
    let (sk, _) = bls_pair(7);
    let h = chain.height();

    let bond = bond_tx(&chain, &w, &ops[..66], pk);
    let bytes = bond.serialize();
    let back = Transaction::deserialize(&bytes).expect("bond must decode");
    assert_eq!(back, bond);
    assert_eq!(back.serialize(), bytes, "bond encoding must be canonical");

    let unbond = unbond_tx(&chain, &w, &ops[67..68], bond.txid());
    let bytes = unbond.serialize();
    let back = Transaction::deserialize(&bytes).expect("unbond must decode");
    assert_eq!(back, unbond);
    assert_eq!(back.serialize(), bytes);

    let (first, second) = conflicting_pair(&sk, h, "jounit/mini");
    let slash = slash_tx(&chain, &w, &ops[67..68], first, second);
    let bytes = slash.serialize();
    let back = Transaction::deserialize(&bytes).expect("slash must decode");
    assert_eq!(back, slash);
    assert_eq!(back.serialize(), bytes);

    // A standard transaction carries no stake byte: old encodings are stable.
    let plain = Transaction::standard(vec![], vec![]);
    assert!(plain.stake.is_none());
    let back = Transaction::deserialize(&plain.serialize()).unwrap();
    assert_eq!(back, plain);
}

#[test]
fn a_reorged_bond_leaves_no_undo_record_behind() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (_, pk) = bls_pair(9);
    let bond = bond_tx(&chain, &w, &ops[..66], pk);

    // Fork with the bond, then out-work it. The bond block is briefly
    // canonical, so it owns a `bond_undo` entry; once the reorg unwinds it that
    // entry must go with it, or `verify_canonical_chain` â€” which replays only
    // the canonical path â€” diverges forever after.
    let fork_at = chain.height();
    let mut fork = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=fork_at {
        let b = fork.mine_block(bonder, vec![], ts(h)).unwrap();
        fork.submit(b).unwrap();
    }
    let forked = fork
        .mine_block(bonder, vec![bond], ts(fork_at + 1))
        .unwrap();
    chain.submit(forked).unwrap();
    assert_eq!(chain.bonds().len(), 1, "the fork won first");

    let rival_miner = wallet(2).address().unwrap();
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=fork_at {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    let r1 = rival
        .mine_block(rival_miner, vec![], ts(fork_at + 1))
        .unwrap();
    rival.submit(r1.clone()).unwrap();
    let r2 = rival
        .mine_block(rival_miner, vec![], ts(fork_at + 2))
        .unwrap();
    rival.submit(r2.clone()).unwrap();
    chain.submit(r1).unwrap();
    chain.submit(r2).unwrap();

    assert!(
        chain.bonds().is_empty(),
        "the reorged bond must unwind from the ledger"
    );
    // The stake undo records are consensus state and are checked by replay:
    // this is the assertion that fails if the reorg path forgets to drop them.
    chain.verify_canonical_chain().unwrap();
}

/// Item 5: the checkpoint committee is stake-weighted (TopN), not bond-
/// insertion-ordered. Three validators bond at the minimum with distinct BLS
/// keys. The signing committee (`committee_keys`) follows bond insertion order,
/// but the epoch set (`derive_set(TopN)`) must be in canonical key-first order
/// with a real `stake_address` (the bond identity, not the zero placeholder).
#[test]
fn committee_is_derived_by_stake_topn_not_bond_order() {
    let (mut chain, w, ops) = richer_chain();
    let bonder = w.address().unwrap();
    let net = chain.params().clone();

    // Three validators, distinct BLS keys, each at the minimum stake.
    let low = bls_pair(11);
    let mid = bls_pair(12);
    let high = bls_pair(13);
    let bonds = [(low.1, BOND), (mid.1, BOND), (high.1, BOND)];
    let mut cursor = 0usize;
    for (pk, stake) in bonds {
        let tx = bond_tx_value(&chain, &w, &ops[cursor..cursor + 66], pk, stake);
        cursor += 66;
        let h = chain.height() + 1;
        let block = chain.mine_block(bonder, vec![tx], ts(h)).unwrap();
        chain.submit(block).unwrap();
    }
    // All three bonded keys are listed for signing (genesis fallback is off):
    let keys = chain.committee_keys();
    assert_eq!(
        keys.len(),
        3,
        "all bonded validators must be in the committee key set"
    );

    // The epoch set is the TopN derivation: canonical key-first order, each
    // record carrying its bond identity and stake. Query it at the current epoch
    // â€” `refresh_committee` ran at every canonical block, so the cache holds
    // this epoch's set and the stake-backed path (not the genesis fallback)
    // answers.
    let epoch_blocks = net.checkpoint_interval_blocks;
    let epoch = chain.height() / epoch_blocks.max(1);
    let set = chain.finality().epoch_set(epoch).unwrap();
    let set_keys: Vec<BlsPublicKey> = set.validators.iter().map(|v| v.bls_pk).collect();
    assert_eq!(
        set_keys.len(),
        3,
        "all three bonded validators must make the stake-derived committee"
    );
    // Canonical order (key first) differs from the bond insertion order the
    // signing committee returns â€” that is what proves derive_set ran, not the
    // order-preserving `committee()`.
    assert_ne!(
        set_keys, keys,
        "the epoch set must be canonically ordered, not bond-insertion ordered"
    );
    // And it must be sorted by the ValidatorRecord total order (key-first).
    let mut canonical = set_keys.clone();
    canonical.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(
        set_keys, canonical,
        "epoch set must be in canonical key order"
    );
    // stake_sat is the bonded value; stake_address is the identity, never zero.
    assert!(
        set.validators
            .iter()
            .all(|v| v.stake_address != Address::default()),
        "stake_address must bind to the bond identity, not zero"
    );
    assert!(
        set.validators.iter().all(|v| v.stake_sat == BOND),
        "each validator's stake must equal its bond"
    );
    let low_identity = bond_identity(&net.network_id, &bonder, &low.1);
    assert!(
        set.validators
            .iter()
            .any(|v| v.bls_pk == low.1 && v.stake_address == low_identity),
        "low validator's stake_address must be its bond identity"
    );
}
