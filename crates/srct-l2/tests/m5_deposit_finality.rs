//! M5 deposit maturity under binding finality — Decision 15 (SPEC.md §19.4.1).
//!
//! The Decision E matrix, through real mined blocks and real certificates:
//!
//! - **pre-activation:** with no binding checkpoint, the M3 depth rule alone
//!   matures a deposit — never *less* safe, and never weaker than M3;
//! - **Case A:** depth satisfied, binding finality not → NOT spendable;
//! - **Case B:** binding finality satisfied, depth not → NOT spendable;
//! - **Case C:** both satisfied → spendable, exactly once;
//! - **Case D:** an attempted reorg across finalized history is refused and
//!   the deposit state stays canonical and safe;
//! - incremental application with the binding floor equals full replay.

use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
use srct_core::chain::Chain;
use srct_core::hash::{Address, Hash512};
use srct_core::params::{testnet_committee_secrets, NetworkParams, SAT_PER_SRCT};
use srct_core::tx::{OutPoint, Output};
use srct_core::wallet::Wallet;
use srct_l2::{ChainL2, DepositParams, L2Config, L2Genesis};

const SINK_VALUE: u64 = 3 * SAT_PER_SRCT;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn net() -> NetworkParams {
    NetworkParams::testnet()
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "m5-deposit-finality").unwrap()
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn chain() -> Chain {
    Chain::new(net()).unwrap()
}

fn mine_empty_to(chain: &mut Chain, miner: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

/// A mature coinbase outpoint of `miner` (testnet maturity is 10).
fn mature_outpoint(chain: &Chain, miner: Address) -> (OutPoint, u64) {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase")
}

/// Mine one block carrying a single sink output — the deposit, at the height
/// the block lands on. Returns that height.
fn deposit_block(chain: &mut Chain, miner: Address, from: &Wallet) -> u64 {
    let (op, value) = mature_outpoint(chain, miner);
    let fee = fee_for(chain, 1, 2);
    let me = from.address().unwrap();
    let tx = from
        .build_tx(
            &[op],
            vec![
                Output {
                    value: SINK_VALUE,
                    address: net().l2_deposit_sink(),
                },
                Output {
                    value: value - SINK_VALUE - fee,
                    address: me,
                },
            ],
            fee,
        )
        .unwrap();
    let h = chain.height() + 1;
    let b = chain.mine_block(miner, vec![tx], ts(h)).unwrap();
    chain.submit(b).unwrap();
    h
}

/// Sign a checkpoint over the chain's canonical block at `height` with the
/// declared testnet committee (quorum 3 of 4) and apply it.
fn checkpoint(chain: &mut Chain, height: u64) {
    let block_hash: Hash512 = chain.block_hash_at(height).unwrap();
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = testnet_committee_secrets()
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    let p = CheckpointPayload {
        height,
        block_hash,
        network_id: "srct/testnet".into(),
        epoch: height / 10,
    };
    let msg = p.signing_hash();
    let sigs: Vec<BlsSignature> = [0usize, 1, 2]
        .iter()
        .map(|&i| pairs[i].0.sign(&msg))
        .collect();
    let agg = RealBls::aggregate(&sigs).unwrap();
    let mut bitmap = vec![0u8; pairs.len().div_ceil(8)];
    for i in [0usize, 1, 2] {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    let cp = Checkpoint {
        payload: p,
        aggregate_sig: agg,
        signer_bitmap: bitmap,
        signer_count: 3,
        pq_sidecar: Vec::new(),
    };
    chain.apply_checkpoint(&cp, &RealBls).unwrap();
}

/// A full replay of `chain` the way a testnet node builds its view: profile
/// genesis, profile deposit rules, the profile's L2 config (testnet maps to
/// the mainnet config, exactly as `srct_node::l2::config_for` does).
fn replay(chain: &Chain) -> ChainL2 {
    let params = net();
    // Mainnet timings with the testnet chain identity, exactly as
    // `srct_node::l2::config_for` maps this profile.
    let mut config = L2Config::mainnet();
    config.network_id = params.network_id.clone();
    // Authority resolves per height inside replay now.
    ChainL2::replay(
        chain,
        config,
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
        &RealBls,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Pre-activation: the M3 depth rule is untouched
// ---------------------------------------------------------------------------

#[test]
fn before_binding_finality_the_depth_rule_alone_matures_a_deposit() {
    let mut chain = chain();
    let miner = wallet(71).address().unwrap();
    mine_empty_to(&mut chain, miner, 11);
    let dep_height = deposit_block(&mut chain, miner, &wallet(71));
    assert_eq!(dep_height, 12);

    let depth = DepositParams::for_params(&net()).maturity_depth;
    mine_empty_to(&mut chain, miner, depth); // tip = 12 + depth
    assert_eq!(
        chain.finality().binding_finalized_height(),
        0,
        "no certificate yet"
    );

    let view = replay(&chain);
    assert_eq!(view.deposits_applied_count(), 1, "depth rule still governs");
    assert!(view.pending_deposits().is_empty());
    assert_eq!(view.state().balance(&miner), SINK_VALUE);
    assert!(view.state().check_conservation());
}

// ---------------------------------------------------------------------------
// Cases A and C: depth alone is not enough once binding finality is live
// ---------------------------------------------------------------------------

#[test]
fn case_a_depth_satisfied_but_binding_not_is_not_spendable() {
    let mut chain = chain();
    let miner = wallet(72).address().unwrap();
    mine_empty_to(&mut chain, miner, 21);
    let dep_height = deposit_block(&mut chain, miner, &wallet(72));
    assert_eq!(dep_height, 22);

    // Depth: tip runs out to 22 + 20 = 42.
    mine_empty_to(&mut chain, miner, 20);
    assert_eq!(chain.height(), 42);

    // Binding: live, but frozen at 20 — below the deposit's height.
    checkpoint(&mut chain, 20);
    assert_eq!(chain.finality().binding_finalized_height(), 20);

    let view = replay(&chain);
    assert_eq!(
        view.deposits_applied_count(),
        0,
        "Case A: depth is satisfied but the deposit's history is not finalized"
    );
    assert_eq!(view.pending_deposits().len(), 1);
    assert_eq!(view.pending_deposits()[0].deposit.amount_sat, SINK_VALUE);
    assert_eq!(
        view.state().balance(&miner),
        0,
        "not a single satoshi credited"
    );

    // Case C: a checkpoint at or above the deposit's height satisfies the
    // second condition — now, and only now, does it credit.
    checkpoint(&mut chain, 30);
    assert_eq!(chain.finality().binding_finalized_height(), 30);
    let view = replay(&chain);
    assert_eq!(
        view.deposits_applied_count(),
        1,
        "Case C: both conditions hold"
    );
    assert!(view.pending_deposits().is_empty());
    assert_eq!(view.state().balance(&miner), SINK_VALUE);

    // Exactly once: a further replay cannot credit it again.
    let again = replay(&chain);
    assert_eq!(again.deposits_applied_count(), 1);
    assert_eq!(again.state(), view.state());
    assert!(again.state().check_conservation());
}

// ---------------------------------------------------------------------------
// Case B: binding alone is not enough either
// ---------------------------------------------------------------------------

#[test]
fn case_b_binding_satisfied_but_depth_not_is_not_spendable() {
    let mut chain = chain();
    let miner = wallet(73).address().unwrap();
    mine_empty_to(&mut chain, miner, 21);
    let dep_height = deposit_block(&mut chain, miner, &wallet(73));
    assert_eq!(dep_height, 22);

    // Tip stops at 30: binding finality can reach 30 ≥ 22, depth cannot
    // (30 < 22 + 20 = 42).
    mine_empty_to(&mut chain, miner, 8);
    assert_eq!(chain.height(), 30);
    checkpoint(&mut chain, 20);
    checkpoint(&mut chain, 30);
    assert_eq!(chain.finality().binding_finalized_height(), 30);

    let view = replay(&chain);
    assert_eq!(
        view.deposits_applied_count(),
        0,
        "Case B: finality covers the deposit but depth does not"
    );
    assert_eq!(view.pending_deposits().len(), 1);
    assert_eq!(view.state().balance(&miner), 0);

    // Mine out the remaining depth: both conditions hold, the deposit credits.
    mine_empty_to(&mut chain, miner, 12);
    assert_eq!(chain.height(), 42);
    let view = replay(&chain);
    assert_eq!(
        view.deposits_applied_count(),
        1,
        "Case C after depth catches up"
    );
    assert_eq!(view.state().balance(&miner), SINK_VALUE);

    // Fresh replay == incremental application, binding floor included.
    let params = net();
    let mut config = L2Config::mainnet();
    config.network_id = params.network_id.clone();
    let mut inc = ChainL2::empty(
        config,
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
    )
    .unwrap();
    let tip = chain.height();
    let binding = chain.finality().binding_finalized_height();
    for h in 1..=tip {
        // Authority resolves per height from the chain, the same rule the
        // full replay above applies (Decision 28).
        let validators = chain.settlement_committee_at(h);
        inc.apply_block(
            chain.block_at(h).unwrap(),
            tip,
            binding,
            &validators,
            &RealBls,
        );
    }
    assert_eq!(
        inc.state(),
        view.state(),
        "fresh replay == incremental replay"
    );
    assert_eq!(inc.deposits_applied_count(), view.deposits_applied_count());
    assert_eq!(inc.pending_deposits(), view.pending_deposits());
}

// ---------------------------------------------------------------------------
// Case D: finalized history cannot be rewritten out from under the deposit
// ---------------------------------------------------------------------------

#[test]
fn case_d_an_attempted_reorg_across_finalized_history_leaves_deposits_safe() {
    let mut chain = chain();
    let miner = wallet(74).address().unwrap();
    mine_empty_to(&mut chain, miner, 21);
    let dep_height = deposit_block(&mut chain, miner, &wallet(74));
    assert_eq!(dep_height, 22);
    mine_empty_to(&mut chain, miner, 20); // depth satisfied (tip 42)
    checkpoint(&mut chain, 20); // binding live but below the deposit

    let state_before = replay(&chain).state().clone();
    let point = chain.finalized_point();
    assert_eq!(point.map(|(h, _)| h), Some(20));
    let tip_before = chain.tip_hash();
    let deposit_block_hash = chain.block_hash_at(22).unwrap();

    // A heavier rival forking below the finalized checkpoint — the classic
    // attempt to reorg a deposit out of canonical history.
    let addr = miner;
    let mut rival = Chain::new(net()).unwrap();
    for h in 1..=15u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 16..=50u64 {
        let b = rival
            .mine_block(addr, vec![], ts(h) + 7)
            .unwrap_or_else(|e| panic!("rival must mine: {e}"));
        rival.submit(b).unwrap();
    }
    assert!(rival.total_work() > chain.total_work());
    let mut crossings = 0;
    for h in 16..=50u64 {
        if let Err(e) = chain.submit(rival.block_at(h).unwrap().clone()) {
            assert!(
                matches!(e, srct_core::error::Error::ReorgWouldCrossFinality { .. }),
                "unexpected rejection: {e}"
            );
            crossings += 1;
        }
    }
    assert!(
        crossings > 0,
        "the crossing reorg must actually be attempted"
    );

    // The chain is untouched where it matters...
    assert_eq!(chain.tip_hash(), tip_before);
    assert_eq!(chain.finalized_point(), point);
    assert_eq!(
        chain.block_hash_at(22).unwrap(),
        deposit_block_hash,
        "the deposit's block is still the canonical one"
    );

    // ...and the L2 view derived from it is byte-identical: the deposit is
    // still pending against the same canonical history, credited nowhere.
    let state_after = replay(&chain).state().clone();
    assert_eq!(
        state_after, state_before,
        "deposit state remains canonical and safe across the refused reorg"
    );
    assert_eq!(replay(&chain).deposits_applied_count(), 0);

    // The legit path still completes: a checkpoint covering the deposit lets
    // it credit exactly once.
    checkpoint(&mut chain, 30);
    let credited = replay(&chain);
    assert_eq!(credited.deposits_applied_count(), 1);
    assert_eq!(credited.state().balance(&miner), SINK_VALUE);
}
