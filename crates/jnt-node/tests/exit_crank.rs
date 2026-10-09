//! The node-side exit crank (approved P1, E-2).
//!
//! One test, because one loop is what is untested: deposit → queue → mature →
//! the node builds the claim on its own → a block settles it → L2 replay
//! absorbs the release. The consensus half (proofs, exact funding, idempotency,
//! reorg unwind) is pinned in `jnt-l2/tests/exit_claim.rs`; this file only pins
//! that *the node can drive it* without anyone hand-building the claim.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::hash::Address;
use jnt_core::l2::{ExitQueuePayload, L2Payload, L2Transaction};
use jnt_core::params::NetworkParams;
use jnt_core::tx::Output;
use jnt_core::wallet::Wallet;
use jnt_node::l2::NodeL2;

const SINK_VALUE: u64 = 100_000_000; // 1 JNT
const EXIT_FEE: u64 = 1_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "exit-crank").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn ts(h: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + h * 1_000
}

fn mine_empty_to(chain: &mut Chain, miner: Address, to: u64) {
    while chain.height() < to {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// Deposit 1 JNT to the sink and let it mature, so the L2 account holds the
/// principal an exit will queue for.
fn deposit(chain: &mut Chain, miner: &Wallet) {
    let me = addr(miner);
    let params = NetworkParams::mini();
    let (outpoint, value) = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == me && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase");
    let fee = chain.expected_base_fee_for_next_block() * (16_000 + 1_000 + 2 * 250) + 1_000_000;
    let tx = miner
        .build_tx(
            &[outpoint],
            vec![
                Output {
                    value: SINK_VALUE,
                    address: params.l2_deposit_sink(),
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
    let b = chain.mine_block(me, vec![tx], ts(h)).unwrap();
    chain.submit(b).unwrap();
    mine_empty_to(chain, me, h + 20);
}

#[test]
fn a_matured_exit_is_settled_without_anyone_hand_building_the_claim() {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, me, 12);
    deposit(&mut chain, &miner);

    let mut view = NodeL2::replay_from(&chain, &params);
    assert_eq!(
        view.state().balance(&me),
        SINK_VALUE,
        "the matured deposit is the principal the exit spends"
    );

    // Queue the exit: the whole principal minus the prepaid crank fee and the
    // L1 fee the release will owe. The exact figure must match what the crank
    // later computes, so it is derived, not guessed.
    let gas = 16_000u64 + 1_000 + 2 * 250;
    let l1_fee = chain.expected_base_fee_for_next_block() * gas;
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let q = chain.height() + 1;
    let payload = ExitQueuePayload::build(&miner, 1, amount, dest, EXIT_FEE).unwrap();
    let tx = L2Transaction::new(L2Payload::ExitQueue(payload));
    let root = view.simulate_root(q, std::slice::from_ref(&tx));
    let block = chain
        .mine_block_with_l2_root(
            me,
            vec![],
            vec![tx],
            root,
            ts(q),
            None,
            jnt_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(block).unwrap();
    view.sync(&chain);

    // Queued but not yet final: the crank must not touch it.
    assert!(
        view.crank_claims(&chain, me).is_empty(),
        "queue is immature"
    );
    assert_eq!(view.pending_exits().len(), 1, "the exit is watched");

    // Final over the queue block.
    mine_empty_to(&mut chain, me, q + params.finality_depth);
    view.sync(&chain);

    let claims = view.crank_claims(&chain, me);
    assert_eq!(claims.len(), 1, "exactly the matured exit is claimable");
    let claim = &claims[0];
    assert_eq!(claim.amount_sat, amount);
    assert_eq!(claim.destination, dest, "paid to the recorded destination");
    assert_eq!(claim.owner, me);
    assert_eq!(claim.queued_height, q);
    assert_eq!(
        claim
            .inputs
            .iter()
            .map(|op| chain.utxo().get(op).unwrap().out.value)
            .sum::<u64>(),
        amount + EXIT_FEE + l1_fee,
        "the claim consumes the deposit exactly"
    );

    // Mine it. An L1-bearing block needs no L2 root — there is no L2 trailer.
    let h = chain.height() + 1;
    chain
        .mine_from_pool_with_exits(
            &mut jnt_core::mempool::Mempool::new(params.gas_cap as usize),
            me,
            ts(h),
            Vec::new(),
            claims,
            None,
        )
        .unwrap();
    assert!(chain.exit_released(&me, 1), "consensus marked the identity");

    // L2 absorbs: the record is gone, the value left L2, and the crank offers
    // nothing further.
    view.sync(&chain);
    assert!(
        view.state().exit(&me, 1).is_none(),
        "a released exit cannot be proven again"
    );
    assert_eq!(view.state().exited_total(), amount + EXIT_FEE);
    assert!(
        view.state().check_conservation(),
        "the exit moved value, it did not create it"
    );
    assert!(
        view.crank_claims(&chain, me).is_empty(),
        "released once, ever"
    );
    assert!(view.pending_exits().is_empty(), "the watch is spent");
}

/// The crank must not act before the profile activates: a mainnet-shaped chain
/// (`exit_activation_height == 0`, meaning *never*) refuses both a claim and the
/// root that would carry it, so a node on such a profile settles nothing.
#[test]
fn a_profile_that_never_activates_cranks_nothing() {
    let params = NetworkParams::mainnet();
    let chain = Chain::new(params.clone()).unwrap();
    let view = NodeL2::fresh(&params);
    assert!(
        !chain.exit_active_at(1),
        "mainnet has chosen no activation height, so exits are off"
    );
    assert!(view.crank_claims(&chain, [7u8; 20]).is_empty());
}
