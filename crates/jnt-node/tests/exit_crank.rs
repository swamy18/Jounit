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

    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
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
    view.sync(&chain).unwrap();

    // Queued but not yet final: the crank must not touch it.
    assert!(
        view.crank_claims(&chain, me).is_empty(),
        "queue is immature"
    );
    assert_eq!(view.pending_exits().len(), 1, "the exit is watched");

    // Final over the queue block.
    mine_empty_to(&mut chain, me, q + params.finality_depth);
    view.sync(&chain).unwrap();

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
    view.sync(&chain).unwrap();
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

    // The joint check must still pass AFTER a release. This is the guard for a
    // real bug: `l2_expected_funded` counted genesis plus deposits without
    // subtracting what exits had already released, so the first accepted exit
    // read as a funding breach - verify failed, the conservation alarm fired
    // and never cleared, and the API refused every write. A release is value
    // leaving L2, not value appearing from nowhere.
    let report = jnt_node::conservation::conservation_report(&chain, &view);
    assert!(
        report.ok(),
        "conservation must survive a release: {:?}",
        report.first_error()
    );
    assert_eq!(report.supply.exited_sat, amount + EXIT_FEE);
}

/// The crank must not act before the profile activates: a mainnet-shaped chain
/// (`exit_activation_height == 0`, meaning *never*) refuses both a claim and the
/// root that would carry it, so a node on such a profile settles nothing.
#[test]
fn a_profile_that_never_activates_cranks_nothing() {
    let params = NetworkParams::mainnet();
    let chain = Chain::new(params.clone()).unwrap();
    let view = NodeL2::fresh(&params).unwrap();
    assert!(
        !chain.exit_active_at(1),
        "mainnet has chosen no activation height, so exits are off"
    );
    assert!(view.crank_claims(&chain, [7u8; 20]).is_empty());
}

/// A funded chain with `amounts.len()` exits queued (nonces 1..=n) and
/// matured, view synced — the crank-ready state every reorg test starts from.
struct QueuedSetup {
    chain: Chain,
    view: NodeL2,
    miner: Wallet,
    me: Address,
    dest: Address,
    amounts: Vec<u64>,
    queue_height: u64,
}

/// Deposit per amount, queue every exit in one L2 block, mine to maturity.
/// Fully deterministic (same miner, same timestamps, RFC6979 signatures), so
/// a second chain replaying these calls holds byte-identical history — which
/// is what lets the reorg tests below fork it.
fn build_to_maturity(
    chain: &mut Chain,
    miner: &Wallet,
    me: Address,
    dest: Address,
    amounts: &[u64],
) -> (NodeL2, u64) {
    // Funded already (see `fund`): queue, mature, sync.
    let mut view = NodeL2::replay_from(chain, chain.params()).unwrap();
    let q = submit_queue_block(chain, &mut view, miner, me, dest, amounts);
    let depth = chain.params().finality_depth;
    mine_empty_to(chain, me, q + depth);
    view.sync(chain).unwrap();
    (view, q)
}

/// Queue every exit in one L2 block at the tip. Returns the queue height.
/// Split out so reorg tests can fork between funding and queueing.
fn submit_queue_block(
    chain: &mut Chain,
    view: &mut NodeL2,
    miner: &Wallet,
    me: Address,
    dest: Address,
    amounts: &[u64],
) -> u64 {
    let q = chain.height() + 1;
    let txs: Vec<L2Transaction> = amounts
        .iter()
        .enumerate()
        .map(|(i, _)| {
            L2Transaction::new(L2Payload::ExitQueue(
                ExitQueuePayload::build(miner, (i + 1) as u64, amounts[i], dest, EXIT_FEE).unwrap(),
            ))
        })
        .collect();
    let root = view.simulate_root(q, &txs);
    let block = chain
        .mine_block_with_l2_root(
            me,
            vec![],
            txs,
            root,
            ts(q),
            None,
            jnt_core::chain::DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(block).unwrap();
    view.sync(chain).unwrap();
    q
}

fn setup_queued(n_exits: usize) -> QueuedSetup {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut chain = Chain::new(params.clone()).unwrap();
    fund(&mut chain, &miner, me, n_exits);
    // Amounts AFTER funding: the base fee has settled to its floor on empty
    // blocks, so the exact-funding equation below holds at crank time too.
    let gas = 16_000u64 + 1_000 + 2 * 250;
    let l1_fee = chain.expected_base_fee_for_next_block() * gas;
    let amounts = vec![SINK_VALUE - EXIT_FEE - l1_fee; n_exits];
    let (view, queue_height) = build_to_maturity(&mut chain, &miner, me, dest, &amounts);
    assert_eq!(view.pending_exits().len(), n_exits);
    QueuedSetup {
        chain,
        view,
        miner,
        me,
        dest,
        amounts,
        queue_height,
    }
}

/// Mine the funding prefix: 12 blocks plus one matured 1-JNT deposit per
/// exit. Fully deterministic, so replaying chains share it byte for byte.
fn fund(chain: &mut Chain, miner: &Wallet, me: Address, n_deposits: usize) {
    mine_empty_to(chain, me, 12);
    // One deposit per exit, so each claim funds from its own sink output.
    for _ in 0..n_deposits {
        deposit(chain, miner);
    }
}

fn settle_claims(s: &mut QueuedSetup) {
    let claims = s.view.crank_claims(&s.chain, s.me);
    assert_eq!(
        claims.len(),
        s.amounts.len(),
        "every matured exit is claimable"
    );
    let h = s.chain.height() + 1;
    s.chain
        .mine_from_pool_with_exits(
            &mut jnt_core::mempool::Mempool::new(s.chain.params().gas_cap as usize),
            s.me,
            ts(h),
            Vec::new(),
            claims,
            None,
        )
        .unwrap();
    s.view.sync(&s.chain).unwrap();
}

/// A reorg that takes the claim block away must not take the exit away: the
/// identity is unmarked, the crank re-offers the claim, and settling again
/// still conserves.
#[test]
fn a_claim_block_reorged_away_is_re_cranked_and_settles_again() {
    let mut s = setup_queued(1);
    settle_claims(&mut s);
    assert!(s.chain.exit_released(&s.me, 1));
    let claim_tip = s.chain.height();

    // Heavier rival fork without the claim: replay the deterministic setup
    // onto a scratch chain (byte-identical history through the claim block's
    // parent), then mine two empty blocks where main holds matures + claim.
    // Same work per block, two headers against one — the fork wins.
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    fund(&mut rival, &s.miner, s.me, 1);
    let (_, rival_q) = build_to_maturity(&mut rival, &s.miner, s.me, s.dest, &s.amounts);
    assert_eq!(rival_q, s.queue_height);
    let rival_miner = addr(&wallet(7));
    let mut fork_blocks = Vec::new();
    for h in [claim_tip, claim_tip + 1] {
        let b = rival.mine_block(rival_miner, vec![], ts(h)).unwrap();
        rival.submit(b.clone()).unwrap();
        fork_blocks.push(b);
    }
    for b in fork_blocks {
        s.chain.submit(b).unwrap();
    }
    assert_eq!(s.chain.height(), claim_tip + 1);
    assert!(
        !s.chain.exit_released(&s.me, 1),
        "the rewound release must unmark"
    );

    // The exit is still queued canonically, so the crank re-offers it and
    // settling again conserves exactly as the first time.
    s.view.sync(&s.chain).unwrap();
    assert_eq!(s.view.pending_exits().len(), 1);
    settle_claims(&mut s);
    assert!(s.chain.exit_released(&s.me, 1));
    assert!(s.view.state().check_conservation());
    let report = jnt_node::conservation::conservation_report(&s.chain, &s.view);
    assert!(report.ok(), "conservation must survive a re-release");
}

/// A reorg that removes the queue block drops the watch: no phantom claim
/// matures from history the chain no longer holds.
///
/// Note the fork is shallow *by necessity*: a queue block old enough to be
/// mature is also old enough that finality forbids rewriting it — which is
/// exactly why a matured queue can be trusted. The phantom danger lives in
/// the immature window, and that is what this test covers.
#[test]
fn a_queue_block_reorged_away_leaves_no_phantom_exit() {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut main = Chain::new(params.clone()).unwrap();
    fund(&mut main, &miner, me, 1);
    let mut view = NodeL2::replay_from(&main, &params).unwrap();
    let gas = 16_000u64 + 1_000 + 2 * 250;
    let l1_fee = main.expected_base_fee_for_next_block() * gas;
    let amounts = vec![SINK_VALUE - EXIT_FEE - l1_fee];
    let q = submit_queue_block(&mut main, &mut view, &miner, me, dest, &amounts);
    view.sync(&main).unwrap();
    assert_eq!(view.pending_exits().len(), 1);

    // Rival shares history through the queue block's parent, then out-works
    // it with two empty blocks — a depth-1 fork, inside finality.
    let mut rival = Chain::new(params.clone()).unwrap();
    fund(&mut rival, &miner, me, 1);
    assert_eq!(rival.height(), q - 1, "replay must share the parent");
    for h in [q, q + 1] {
        let b = rival.mine_block(addr(&wallet(7)), vec![], ts(h)).unwrap();
        rival.submit(b.clone()).unwrap();
        main.submit(b).unwrap();
    }
    assert_eq!(main.height(), q + 1);
    view.sync(&main).unwrap();
    assert!(
        view.pending_exits().is_empty(),
        "a reorged queue must drop its watch"
    );
    assert!(
        view.crank_claims(&main, me).is_empty(),
        "no phantom claim may mature"
    );
    // Far past finality: still nothing, ever.
    mine_empty_to(&mut main, me, q + 200);
    view.sync(&main).unwrap();
    assert!(view.crank_claims(&main, me).is_empty());
}

/// Two matured exits crank as two claims and settle in one block, each paying
/// its own destination exactly once.
#[test]
fn two_exits_crank_and_settle_together_exactly_once_each() {
    let mut s = setup_queued(2);
    settle_claims(&mut s);
    assert!(s.chain.exit_released(&s.me, 1));
    assert!(s.chain.exit_released(&s.me, 2));
    assert!(s.view.pending_exits().is_empty());
    assert!(s.view.crank_claims(&s.chain, s.me).is_empty());
    assert_eq!(s.view.state().exited_total(), 2 * (s.amounts[0] + EXIT_FEE));
    assert!(s.view.state().check_conservation());
    let report = jnt_node::conservation::conservation_report(&s.chain, &s.view);
    assert!(report.ok(), "conservation must survive two releases");
}
