//! Committee rotation within an epoch (P0-1) and its reorg interplay (P2-15).
//!
//! The committee for epoch `e` is derived from the bond state at
//! `seed_height(e)` and stays fixed for the whole epoch. These tests pin that:
//! a bond bonded mid-epoch does not rotate the committee; rotation happens at
//! the epoch whose seed first sees the bond; a reorg across a seed height
//! rolls the committee back exactly; and a certificate that was valid under
//! the old committee cannot become valid under the new one (or vice versa).
//!
//! Run with `cargo test -p jnt-core --test committee_rotation`.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{BlsPublicKey, Checkpoint, CheckpointPayload};
use jnt_core::bond::{bond_identity, bond_pop};
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::hash::Address;
use jnt_core::params::NetworkParams;
use jnt_core::tx::{
    OutPoint, Output, StakePayload, Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE,
    TX_BOND,
};
use jnt_core::validators::ValidatorError;
use jnt_core::wallet::Wallet;

const BOND_A: u64 = 5 * jnt_core::params::SAT_PER_JNT;
const BOND_B: u64 = 100_000_000;

/// `mini` but with `finality_depth = 50`: stock mini's depth-20 gate makes
/// `seed_height == finalized_height` at every height (lookback == depth == 20),
/// so a reorg across a seed boundary can never clear the gate while the
/// committee actually changes. A depth of 50 gives enough runway.
fn shallow_params() -> NetworkParams {
    let mut p = NetworkParams::mini();
    p.finality_depth = 50;
    p
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "committee-rotation").unwrap()
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

fn mine(chain: &mut Chain, to: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(to, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn mine_to(chain: &mut Chain, to: Address, target: u64) {
    while chain.height() < target {
        mine(chain, to, 1);
    }
}

fn rich_chain_with(params: NetworkParams) -> (Chain, Wallet, Vec<OutPoint>) {
    let mut chain = Chain::new(params).unwrap();
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

fn rich_chain() -> (Chain, Wallet, Vec<OutPoint>) {
    rich_chain_with(NetworkParams::mini())
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

fn bond_tx(chain: &Chain, w: &Wallet, ops: &[OutPoint], sk: &SecretKey, value: u64) -> Transaction {
    let pk = sk.public_key();
    let bonder = w.address().unwrap();
    let net = chain.params().network_id.clone();
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
                    address: bond_identity(&net, &bonder, &pk),
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
    tx.stake = Some(StakePayload::Bond {
        bls_pk: pk,
        pop: bond_pop(sk, &net, &bonder),
        mldsa_pk: None,
    });
    w.sign(&mut tx).unwrap();
    tx
}

fn submit_block(chain: &mut Chain, miner: Address, txs: Vec<Transaction>) -> Result<(), Error> {
    let h = chain.height() + 1;
    let b = chain.mine_block(miner, txs, ts(h)).unwrap();
    chain.submit(b)
}

fn epoch_at(chain: &Chain, height: u64) -> u64 {
    CheckpointPayload::epoch_for(height, chain.params().checkpoint_interval_blocks)
}

fn lone_checkpoint(sk: &SecretKey, payload: CheckpointPayload) -> Checkpoint {
    let msg = payload.signing_hash();
    let agg = RealBls::aggregate(&[sk.sign(&msg)]).unwrap();
    Checkpoint {
        payload,
        aggregate_sig: agg,
        signer_bitmap: vec![1u8],
        signer_count: 1,
        pq_sidecar: Vec::new(),
    }
}

fn canonical_checkpoint(chain: &Chain, sk: &SecretKey, height: u64) -> Checkpoint {
    let payload = CheckpointPayload {
        height,
        block_hash: chain.block_at(height).unwrap().block_hash(),
        network_id: chain.params().network_id.clone(),
        epoch: epoch_at(chain, height),
    };
    lone_checkpoint(sk, payload)
}

fn sorted(mut keys: Vec<BlsPublicKey>) -> Vec<BlsPublicKey> {
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    keys
}

/// P0-1: a bond bonded mid-epoch leaves the epoch committee untouched; the
/// committee rotates only at the epoch whose seed height first sees the bond.
/// Verification follows the same rule, not the live ledger.
#[test]
fn mid_epoch_bond_does_not_rotate_the_committee_until_its_seed_epoch() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();

    // Bond A lands at height 81; epoch 11 (seed height 90) is its first
    // effective epoch.
    mine_to(&mut chain, bonder, 110);
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // An epoch-11 certificate by A verifies and is accepted.
    let cp = canonical_checkpoint(&chain, &sk_a, 110);
    chain.apply_checkpoint(&cp, &RealBls).unwrap();

    // Bond B lands mid-epoch at height 111. The epoch-11 committee stays [A].
    let (sk_b, pk_b) = bls_pair(8);
    let bond_b = bond_tx(&chain, &w, &ops[66..68], &sk_b, BOND_B);
    submit_block(&mut chain, bonder, vec![bond_b]).unwrap();
    assert_eq!(chain.height(), 111);
    assert_eq!(chain.committee_keys(), vec![pk_a]);
    mine_to(&mut chain, bonder, 119);
    assert_eq!(
        chain.committee_keys(),
        vec![pk_a],
        "mid-epoch bond entry must not rotate the committee"
    );

    // Verification agrees: B cannot sign for epoch 11, A still can.
    let bad_b = canonical_checkpoint(&chain, &sk_b, 115);
    assert!(chain.apply_checkpoint(&bad_b, &RealBls).is_err());
    let good_a = canonical_checkpoint(&chain, &sk_a, 115);
    chain.apply_checkpoint(&good_a, &RealBls).unwrap();

    // Epoch 12 (seed height 100, taken before B bonded) still names only A.
    mine_to(&mut chain, bonder, 120);
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // Epoch 14 (seed height 120, taken after B bonded) names both.
    mine_to(&mut chain, bonder, 140);
    assert_eq!(chain.committee_keys(), sorted(vec![pk_a, pk_b]));

    // The historical sets say the same thing epoch by epoch.
    let set11 = chain.historical_epoch_set(11).unwrap();
    let keys11: Vec<BlsPublicKey> = set11.validators.iter().map(|v| v.bls_pk).collect();
    assert_eq!(keys11, vec![pk_a]);
    let set14 = chain.historical_epoch_set(14).unwrap();
    let keys14: Vec<BlsPublicKey> = set14.validators.iter().map(|v| v.bls_pk).collect();
    assert_eq!(keys14, sorted(vec![pk_a, pk_b]));

    chain.verify_canonical_chain().unwrap();
}

/// P0-1: a bond placed exactly at a seed height takes effect only at the
/// epoch that seed governs — here the epoch boundary and the seed height
/// coincide, and the committee still does not move early.
#[test]
fn bond_at_a_seed_height_takes_effect_at_the_epoch_it_seeds() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();
    mine_to(&mut chain, bonder, 110);
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // Height 100 was already a seed height (for epoch 12); height 120 will be
    // the next one. Bond B at 111, i.e. strictly after seed 100: epoch 12
    // (seed 100) must still name only A.
    let (sk_b, pk_b) = bls_pair(8);
    let bond_b = bond_tx(&chain, &w, &ops[66..68], &sk_b, BOND_B);
    submit_block(&mut chain, bonder, vec![bond_b]).unwrap();
    mine_to(&mut chain, bonder, 120);
    assert_eq!(
        chain.committee_keys(),
        vec![pk_a],
        "a bond placed after a seed height waits for the next seed"
    );
    // Height 130 is still epoch 13 (seed height 110), which is before B bonded
    // at 111 — only A. Height 140 is epoch 14 (seed height 120), taken after B,
    // so both appear together.
    mine_to(&mut chain, bonder, 130);
    assert_eq!(chain.committee_keys(), vec![pk_a]);
    mine_to(&mut chain, bonder, 140);
    assert_eq!(chain.committee_keys(), sorted(vec![pk_a, pk_b]));
    let _ = sk_b;
    chain.verify_canonical_chain().unwrap();
}

/// Previous-epoch late checkpoints verify against the previous set while it
/// is within its one-epoch grace, after the committee has rotated.
#[test]
fn previous_epoch_late_checkpoint_verifies_after_rotation() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();
    mine_to(&mut chain, bonder, 110);

    // Accept an epoch-11 checkpoint at the tip.
    let cp = canonical_checkpoint(&chain, &sk_a, 110);
    chain.apply_checkpoint(&cp, &RealBls).unwrap();
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // Bond B at 111 and rotate to epoch 12 (seed 100 → still [A]).
    let (sk_b, _) = bls_pair(8);
    let bond_b = bond_tx(&chain, &w, &ops[66..68], &sk_b, BOND_B);
    submit_block(&mut chain, bonder, vec![bond_b]).unwrap();
    mine_to(&mut chain, bonder, 120);

    // A late epoch-11 checkpoint (height 115, never accepted before) still
    // verifies against the previous set inside its grace.
    let late = canonical_checkpoint(&chain, &sk_a, 115);
    assert_eq!(epoch_at(&chain, 115), 11);
    chain.apply_checkpoint(&late, &RealBls).unwrap();
    assert_eq!(chain.finality().accepted_height(), 115);
}

/// A seed height with no snapshot behind it fails closed: there is no past
/// committee to reconstruct.
#[test]
fn historical_set_without_a_snapshot_is_unavailable_not_fallback() {
    let (chain, _, _) = rich_chain();
    let err = chain
        .historical_epoch_set(1_000_000)
        .expect_err("no snapshot exists for that seed height");
    assert!(matches!(err, ValidatorError::NoCandidates { .. }));
}

/// P2-15: a bond arrives on a side branch, that branch becomes canonical (the
/// committee changes with it), then it loses and the bond, the snapshots and the
/// finality cache roll back exactly. A certificate valid under the old committee
/// is refused under the new one, and accepted again once the old committee
/// returns.
///
/// Uses `shallow_params` (`finality_depth = 50`): stock mini's depth-20 gate
/// makes `seed_height == finalized_height` at every height (lookback == depth),
/// so a reorg across a seed boundary can never clear the gate while the
/// committee actually changes. With depth 50, a fork at 80 reaches height 120
/// (seed 100, epoch 12) with finalized at 70, well below the 80 fork point.
#[test]
fn reorg_across_a_seed_height_rolls_the_committee_back() {
    let params = shallow_params();
    let mut chain = Chain::new(params.clone()).unwrap();
    let w = wallet(1);
    let bonder = w.address().unwrap();
    mine(&mut chain, bonder, 80);
    let ops: Vec<OutPoint> = (1..=70u64)
        .map(|h| OutPoint {
            txid: chain.block_at(h).unwrap().txs[0].txid(),
            index: 0,
        })
        .collect();

    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();
    // Bond A at 81 enters the epoch-12 snapshot (seed height 100) at height 110.
    mine_to(&mut chain, bonder, 110);
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // Accept an epoch-11 checkpoint so the observation frontier is real.
    let cp = canonical_checkpoint(&chain, &sk_a, 110);
    chain.apply_checkpoint(&cp, &RealBls).unwrap();

    // Keep the A-branch aside: it will take the lead back at the end.
    let mut fork = chain.clone();

    // A rival branch forking at height 80 bonds D at 81 instead. The fork
    // point (80) is well above finalized_height (60 at tip 110), so the depth
    // rule permits this reorg. The rival mines 10 more blocks to outwork.
    let mut rival = Chain::new(params.clone()).unwrap();
    for h in 1..=80u64 {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    let (sk_d, pk_d) = bls_pair(9);
    let bond_d = bond_tx(&rival, &w, &ops[..66], &sk_d, BOND_A);
    let h = rival.height() + 1;
    let b = rival.mine_block(bonder, vec![bond_d], ts(h)).unwrap();
    rival.submit(b).unwrap();
    for h in 82..=120u64 {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    // At height 120: epoch 12, seed height 100, which has bond D.
    assert_eq!(rival.committee_keys(), vec![pk_d]);

    // Hand the side branch to the main chain block by block; it adopts once
    // heavier (height 120 over 110).
    for h in 81..=120u64 {
        let b = rival.block_at(h).unwrap().clone();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 120);
    assert_eq!(chain.bonds().len(), 1);
    assert_eq!(
        chain.committee_keys(),
        vec![pk_d],
        "the winning branch's seed state governs the committee"
    );

    // An epoch-11 certificate by A — valid before the reorg — is refused
    // under the D committee and records nothing.
    let stale_a = canonical_checkpoint(&chain, &sk_a, 110);
    let err = chain
        .apply_checkpoint(&stale_a, &RealBls)
        .expect_err("A is not a member of the D committee");
    assert!(
        matches!(
            err,
            jnt_core::finality::FinalityError::InvalidCertificate(_)
        ),
        "unexpected error: {err:?}"
    );

    // The A-branch (forked at 110) takes the lead back over the rival at 120.
    // With finality_depth 50, finalized at 121 is 71, and common=81 > 71.
    for h in 111..=121u64 {
        let b = fork.mine_block(bonder, vec![], ts(h)).unwrap();
        fork.submit(b).unwrap();
    }
    for h in 111..=121u64 {
        let b = fork.block_at(h).unwrap().clone();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 121);
    assert_eq!(chain.committee_keys(), vec![pk_a]);
    assert_eq!(chain.bonds().len(), 1);
    let fresh_a = canonical_checkpoint(&chain, &sk_a, 110);
    chain.apply_checkpoint(&fresh_a, &RealBls).unwrap();

    chain.verify_canonical_chain().unwrap();
}

/// Two seed heights crossed by one reorg: bonds effective at epochs 12 and
/// 14 both roll back when a bond-less rival takes the lead, and both return
/// exactly when the bonded branch retakes it. The committee after each leg
/// equals the winning branch's seed state — never a mix of both.
///
/// Needs `finality_depth = 200`: the reorg spans ~70 blocks, so a stock
/// depth would finalize the fork point and refuse the very reorg under
/// test. The depth only moves the finality gate, not the committee rule.
#[test]
fn reorg_across_two_seed_heights_rolls_back_twice() {
    let mut p = NetworkParams::mini();
    p.finality_depth = 200;
    let (mut chain, w, ops) = rich_chain_with(p.clone());
    let bonder = w.address().unwrap();

    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();
    mine_to(&mut chain, bonder, 110);
    assert_eq!(chain.committee_keys(), vec![pk_a]);

    // Bond B lands at 111: epoch 12 (seed 100) still names only A, epoch
    // 14 (seed 120, taken after B) names both.
    let (sk_b, pk_b) = bls_pair(8);
    let bond_b = bond_tx(&chain, &w, &ops[66..68], &sk_b, BOND_B);
    submit_block(&mut chain, bonder, vec![bond_b]).unwrap();
    mine_to(&mut chain, bonder, 145);
    let both = sorted(vec![pk_a, pk_b]);
    assert_eq!(chain.committee_keys(), both);
    let set12: Vec<BlsPublicKey> = chain
        .historical_epoch_set(12)
        .unwrap()
        .validators
        .iter()
        .map(|v| v.bls_pk)
        .collect();
    assert_eq!(set12, vec![pk_a]);
    let set14: Vec<BlsPublicKey> = chain
        .historical_epoch_set(14)
        .unwrap()
        .validators
        .iter()
        .map(|v| v.bls_pk)
        .collect();
    assert_eq!(set14, both);

    // The bonded branch aside; a bond-less rival forking at 80 outworks it.
    let mut fork = chain.clone();
    let mut rival = Chain::new(p.clone()).unwrap();
    for h in 1..=80u64 {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    assert_eq!(
        rival.block_at(80).unwrap().block_hash(),
        chain.block_at(80).unwrap().block_hash()
    );
    for h in 81..=150u64 {
        let b = rival.mine_block(bonder, vec![], ts(h)).unwrap();
        rival.submit(b).unwrap();
    }
    for h in 81..=150u64 {
        let b = rival.block_at(h).unwrap().clone();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 150);
    assert_eq!(chain.bonds().len(), 0);
    assert_eq!(chain.committee_keys(), rival.committee_keys());
    assert_ne!(chain.committee_keys(), both);
    // The losing branch's seed states are gone with it, not merged.
    for epoch in [12u64, 14] {
        let keys: Vec<BlsPublicKey> = chain
            .historical_epoch_set(epoch)
            .map(|s| s.validators.iter().map(|v| v.bls_pk).collect())
            .unwrap_or_default();
        assert!(
            !keys.contains(&pk_a),
            "epoch {epoch} must not name A after the reorg"
        );
        assert!(
            !keys.contains(&pk_b),
            "epoch {epoch} must not name B after the reorg"
        );
    }

    // The bonded branch retakes the lead: both committees restore exactly.
    for h in 146..=151u64 {
        let b = fork.mine_block(bonder, vec![], ts(h)).unwrap();
        fork.submit(b).unwrap();
    }
    for h in 146..=151u64 {
        let b = fork.block_at(h).unwrap().clone();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 151);
    assert_eq!(chain.bonds().len(), 2);
    assert_eq!(chain.committee_keys(), both);
    let set12_back: Vec<BlsPublicKey> = chain
        .historical_epoch_set(12)
        .unwrap()
        .validators
        .iter()
        .map(|v| v.bls_pk)
        .collect();
    assert_eq!(set12_back, vec![pk_a]);
    let set14_back: Vec<BlsPublicKey> = chain
        .historical_epoch_set(14)
        .unwrap()
        .validators
        .iter()
        .map(|v| v.bls_pk)
        .collect();
    assert_eq!(set14_back, both);

    chain.verify_canonical_chain().unwrap();
}

/// Restart and independent sync: a chain rebuilt block-by-block from a
/// peer's blocks reaches the identical tip and committee, and a stale
/// single-signer certificate from the pre-rotation committee is refused on
/// both — while a certificate from the current committee is accepted on
/// both. Two nodes syncing the same blocks never disagree.
#[test]
fn rebuilt_chain_agrees_and_refuses_stale_certs() {
    let (mut chain, w, ops) = rich_chain();
    let bonder = w.address().unwrap();
    let (sk_a, pk_a) = bls_pair(7);
    let bond_a = bond_tx(&chain, &w, &ops[..66], &sk_a, BOND_A);
    submit_block(&mut chain, bonder, vec![bond_a]).unwrap();
    mine_to(&mut chain, bonder, 110);
    let (sk_b, pk_b) = bls_pair(8);
    let bond_b = bond_tx(&chain, &w, &ops[66..68], &sk_b, BOND_B);
    submit_block(&mut chain, bonder, vec![bond_b]).unwrap();
    mine_to(&mut chain, bonder, 140);
    let both = sorted(vec![pk_a, pk_b]);
    assert_eq!(chain.committee_keys(), both);

    // Restart proxy: a clone carries the identical tip and committee.
    let restarted = chain.clone();
    assert_eq!(restarted.tip_hash(), chain.tip_hash());
    assert_eq!(restarted.committee_keys(), chain.committee_keys());

    // Independent sync: fresh chain, same blocks in order.
    let mut peer = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=140u64 {
        peer.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    assert_eq!(peer.tip_hash(), chain.tip_hash());
    assert_eq!(peer.committee_keys(), both);

    // Stale: an epoch-11 certificate by A alone (valid before B bonded)
    // is refused under the [A, B] committee on both chains.
    let stale = canonical_checkpoint(&chain, &sk_a, 115);
    assert!(chain.apply_checkpoint(&stale, &RealBls).is_err());
    assert!(peer.apply_checkpoint(&stale, &RealBls).is_err());

    // Current: A+B jointly sign the tip; accepted on both, same finality.
    let committee = chain.committee_keys();
    let payload = CheckpointPayload {
        height: 140,
        block_hash: chain.block_at(140).unwrap().block_hash(),
        network_id: chain.params().network_id.clone(),
        epoch: epoch_at(&chain, 140),
    };
    let msg = payload.signing_hash();
    let mut sigs = Vec::new();
    for pk in &committee {
        let sk = if *pk == pk_a {
            &sk_a
        } else {
            assert_eq!(*pk, pk_b);
            &sk_b
        };
        sigs.push(sk.sign(&msg));
    }
    let joint = Checkpoint {
        payload,
        aggregate_sig: RealBls::aggregate(&sigs).unwrap(),
        // One bit per signer over the sorted committee: both of two.
        signer_bitmap: vec![0b11u8],
        signer_count: committee.len() as u32,
        pq_sidecar: Vec::new(),
    };
    chain.apply_checkpoint(&joint, &RealBls).unwrap();
    peer.apply_checkpoint(&joint, &RealBls).unwrap();
    assert_eq!(
        peer.finality().accepted_height(),
        chain.finality().accepted_height()
    );

    peer.verify_canonical_chain().unwrap();
    chain.verify_canonical_chain().unwrap();
}
