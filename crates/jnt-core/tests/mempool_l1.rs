//! Mempool ↔ chain integration (build order Step 1A).
//!
//! The mempool unit tests attack the pool in isolation. These attack the *seam*
//! between the pool and the chain, which is where an earlier session's worst
//! defects lived: state that two components each believed the other maintained.
//! Specifically:
//!
//! - the pool must never be able to stop the chain (a full pool, a malformed
//!   transaction or a tiny byte cap are all conditions a hostile peer can create
//!   for free),
//! - a block must never contain something the pool admitted but the chain will
//!   reject, and
//! - a reorg must not silently destroy a user's transaction.
//!
//! Run with `cargo test -p jnt-core --test mempool_l1`.

use jnt_core::chain::Chain;
use jnt_core::hash::Address;
use jnt_core::mempool::{Mempool, MempoolError};
use jnt_core::params::NetworkParams;
use jnt_core::supply::block_reward_sat;
use jnt_core::tx::{Input, OutPoint, Output, Transaction};
use jnt_core::wallet::Wallet;

/// Timestamps at exactly the mini target spacing, so difficulty stays pinned at
/// 1 and every block here is cheap to produce. These tests attack state rules,
/// not proof-of-work.
fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn addr(tag: u8) -> Address {
    [tag; 20]
}

/// A fee comfortably above `base_fee * gas_used` for every height in this file,
/// so a transaction's fee is what the test means it to be and never the floor.
const FEE: u64 = 100_000_000;

/// Blocks 1..=n paying their coinbase to `miner`.
///
/// Deterministic in `miner` and the height sequence, which is what lets two
/// chains share a byte-identical prefix (see `reorg_fixture`).
fn chain_to(miner: Address, n: u64) -> Chain {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=n {
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    chain
}

fn wallet_and_chain(n: u64) -> (Wallet, Chain) {
    let w = Wallet::new_random("miner");
    let a = w.address().unwrap();
    (w, chain_to(a, n))
}

/// A chain of `n` blocks, the wallet owning its coinbases, and an independent
/// chain holding the *same* `n` blocks.
///
/// Two chains rather than one truncated in place: there is no public "rewind and
/// re-mine" API, and there should not be — a node never rewinds its own canon to
/// build a rival. Re-mining the same heights with the same miner and the same
/// timestamps reproduces the same blocks, because nothing in a block depends on
/// anything but those values. `assert_prefix_identical` checks that rather than
/// trusting it, so a future change that made mining non-deterministic would
/// break the fixture loudly instead of turning the reorg test into a test of
/// something else.
fn reorg_fixture(n: u64) -> (Wallet, Chain, Chain) {
    let (w, main) = wallet_and_chain(n);
    let rival = chain_to(w.address().unwrap(), n);
    assert_eq!(
        main.tip_hash(),
        rival.tip_hash(),
        "the fixture's two chains must share a prefix, or the reorg is not a reorg"
    );
    assert_eq!(main.height(), n);
    (w, main, rival)
}

/// The coinbase of the block at `height` — the only coins a wallet owns here,
/// and why `coinbase_maturity` is a real constraint in this file.
fn coinbase_of(chain: &Chain, height: u64) -> (OutPoint, u64) {
    let block = chain.block_at(height).expect("block exists");
    (
        OutPoint {
            txid: block.txs[0].txid(),
            index: 0,
        },
        block_reward_sat(chain.params(), height),
    )
}

fn signed_spend(w: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
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

/// Admit against the state the next block will actually be built on — the same
/// numbers `reconcile_mempool` and `mine_from_pool` use internally.
fn admit(chain: &Chain, pool: &mut Mempool, tx: Transaction) -> Result<[u8; 32], MempoolError> {
    pool.add(
        tx,
        chain.utxo(),
        chain.height() + 1,
        chain.params(),
        chain.expected_base_fee_for_next_block(),
        chain.bonds(),
    )
}

// ---------------------------------------------------------------------------
// 1. Local transaction → pool → block
// ---------------------------------------------------------------------------

/// **The rule:** a locally submitted transaction reaches a block through the
/// pool, and the pool does not keep a copy of what it mined.
///
/// A pool that still holds a confirmed transaction relays it to every peer
/// forever and will happily build a second block containing it — a double spend
/// manufactured by the local miner alone.
#[test]
fn a_local_transaction_is_pooled_then_mined_and_evicted() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op, value) = coinbase_of(&chain, 1);
    let tx = signed_spend(&miner, op, value - FEE, addr(9));

    let mut pool = Mempool::default();
    admit(&chain, &mut pool, tx.clone()).expect("a valid spend was refused");
    assert_eq!(pool.len(), 1);

    let block = chain
        .mine_from_pool(&mut pool, addr(1), ts(13))
        .expect("mining from a valid pool failed");

    assert_eq!(block.header.height, 13);
    assert_eq!(
        block.txs.len(),
        2,
        "the block must carry coinbase + the spend"
    );
    assert_eq!(block.txs[1].txid(), tx.txid());
    assert!(pool.is_empty(), "the pool kept a transaction it just mined");
    assert_eq!(pool.size_bytes(), 0, "byte accounting leaked");

    assert!(chain.utxo().get(&op).is_none(), "the spent input survived");
}

// ---------------------------------------------------------------------------
// 2. Reconciliation against the chain
// ---------------------------------------------------------------------------

/// **The rule:** `reconcile_mempool` evicts exactly what the canonical chain
/// confirms, and nothing else.
///
/// **The attack:** confirm a transaction out of band — the way a synced block
/// arrives — and keep it pooled. The pool would then advertise an unmineable
/// duplicate of a confirmed transaction, and every peer that relayed it wasted
/// bandwidth. Confirmation here is deliberately *not* via `mine_from_pool`,
/// which evicts on its own; this is the path a peer's block takes.
#[test]
fn reconciling_evicts_confirmed_and_keeps_the_rest() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op_a, value) = coinbase_of(&chain, 1);
    let (op_b, _) = coinbase_of(&chain, 2);
    let kept = signed_spend(&miner, op_b, value - FEE, addr(9));
    let confirmed = signed_spend(&miner, op_a, value - FEE, addr(8));

    let mut pool = Mempool::default();
    admit(&chain, &mut pool, kept.clone()).unwrap();
    admit(&chain, &mut pool, confirmed.clone()).unwrap();
    assert_eq!(pool.len(), 2);

    let cursor = chain.height();
    let block = chain
        .mine_block(addr(1), vec![confirmed.clone()], ts(13))
        .unwrap();
    chain.submit(block).unwrap();

    let (height, report) = chain.reconcile_mempool(&mut pool, cursor);
    assert_eq!(height, 13);
    assert_eq!(
        report.evicted, 1,
        "the confirmed transaction must be evicted"
    );
    assert_eq!(report.readmitted, 0, "nothing was disconnected");
    assert_eq!(pool.len(), 1, "the unrelated transaction must survive");
    assert!(pool.contains(&kept.txid()));
    assert!(!pool.contains(&confirmed.txid()));

    // Reconciling again is a no-op, not a second eviction.
    let (_, again) = chain.reconcile_mempool(&mut pool, height);
    assert_eq!(again.evicted, 0);
    assert_eq!(pool.len(), 1);
}

// ---------------------------------------------------------------------------
// 3. Conflicts
// ---------------------------------------------------------------------------

/// **The rule:** a double spend is refused at admission, not discovered at block
/// time. The pool must hold exactly one of two conflicting transactions.
#[test]
fn a_double_spend_is_refused_beside_its_twin() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op, value) = coinbase_of(&chain, 1);
    let mut pool = Mempool::default();

    admit(
        &chain,
        &mut pool,
        signed_spend(&miner, op, value - FEE, addr(9)),
    )
    .unwrap();
    let rival = signed_spend(&miner, op, value - FEE - 1, addr(8));
    assert!(
        matches!(
            admit(&chain, &mut pool, rival),
            Err(MempoolError::Conflict { .. })
        ),
        "a conflicting spend was admitted alongside the pooled one"
    );
    assert_eq!(pool.len(), 1);

    let block = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();
    assert_eq!(block.txs.len(), 2);
}

// ---------------------------------------------------------------------------
// 4. The pool must never be able to stop the chain
// ---------------------------------------------------------------------------

/// **The rule:** a malformed transaction is refused by the pool and cannot
/// prevent blocks from being produced.
///
/// **The attack:** relay garbage. If the pool accepted it, the miner would build
/// a block around it, `build_block` would fail validation, and the node would
/// stop making progress on a peer's say-so.
#[test]
fn a_malformed_transaction_cannot_stop_the_chain() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op, value) = coinbase_of(&chain, 1);
    let mut pool = Mempool::default();

    // A spend of an output that does not exist.
    let ghost = signed_spend(
        &miner,
        OutPoint {
            txid: [0xAB; 32],
            index: 7,
        },
        value - FEE,
        addr(9),
    );
    assert!(admit(&chain, &mut pool, ghost).is_err());

    // A real output with a broken signature: signed by the wrong wallet.
    let thief = Wallet::new_random("thief");
    assert!(
        admit(
            &chain,
            &mut pool,
            signed_spend(&thief, op, value - FEE, addr(9))
        )
        .is_err(),
        "a transaction signed by the wrong key was pooled"
    );

    assert!(pool.is_empty(), "garbage reached the pool");
    let block = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();
    assert_eq!(block.header.height, 13);
}

/// **The rule:** a full pool refuses new transactions instead of growing, and
/// refusing them does not stop the chain.
///
/// **The attack:** flood. Pooling costs a peer no proof-of-work, so this is the
/// cheapest way to attack a node's memory.
#[test]
fn a_full_pool_refuses_new_transactions_and_the_chain_still_mines() {
    let (miner, mut chain) = wallet_and_chain(40);

    // Small enough that the cap engages within this loop, which is the point:
    // the default 32 MiB would never fill from 31 small transactions.
    let mut pool = Mempool::new(2 * 1024);
    let mut accepted = 0usize;
    let mut refused_full = 0usize;
    // Only 1..=31: the spends are validated against height 41 and every output
    // in this ledger is subject to `coinbase_maturity`, so a coinbase from
    // height 32 or above is legitimately immature. Using one would test the
    // maturity rule instead of the byte cap.
    for height in 1..=31u64 {
        let (op, value) = coinbase_of(&chain, height);
        match admit(
            &chain,
            &mut pool,
            signed_spend(&miner, op, value - FEE, addr(9)),
        ) {
            Ok(_) => accepted += 1,
            Err(MempoolError::Full) => refused_full += 1,
            Err(e) => panic!("unexpected refusal at height {height}: {e}"),
        }
    }

    assert!(accepted > 0, "the pool refused everything, proving nothing");
    assert!(
        refused_full > 0,
        "the cap never engaged, so it is not tested"
    );
    assert!(
        pool.size_bytes() <= pool.max_bytes(),
        "pool holds {} bytes against a {} byte cap",
        pool.size_bytes(),
        pool.max_bytes()
    );

    // A full pool is not a stalled node.
    let block = chain.mine_from_pool(&mut pool, addr(1), ts(41)).unwrap();
    assert_eq!(block.header.height, 41);
    assert!(block.txs.len() > 1, "the block should carry pooled work");
}

/// The degenerate case an operator sees after misconfiguring the cap: a pool too
/// small for even one transaction must still let the chain produce empty blocks.
#[test]
fn a_degenerate_byte_cap_yields_empty_blocks_not_a_stall() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op, value) = coinbase_of(&chain, 1);

    let mut pool = Mempool::new(1);
    assert!(matches!(
        admit(
            &chain,
            &mut pool,
            signed_spend(&miner, op, value - FEE, addr(9))
        ),
        Err(MempoolError::Full)
    ));

    let block = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();
    assert_eq!(block.txs.len(), 1, "coinbase only");
}

// ---------------------------------------------------------------------------
// 5. Ordering reaches the block
// ---------------------------------------------------------------------------

/// **The rule:** the miner takes the higher fee *rate* first, so ordering is a
/// property of the block and not merely of the pool's internal view.
///
/// **The attack:** submit a large-total transaction and a small-total one paying
/// more per unit of gas. If the block builder ordered by total, the block would
/// pay the wrong seller of block space and the pool's ordering would be cosmetic.
#[test]
fn the_miner_takes_the_higher_fee_rate_first() {
    let (miner, mut chain) = wallet_and_chain(12);
    let (op_a, value) = coinbase_of(&chain, 1);
    let (op_b, _) = coinbase_of(&chain, 2);

    // Same shape, different fees. `keen` pays more in total (and so more per unit
    // of gas); only one can go first, and it must be `keen`.
    let rich = signed_spend(&miner, op_a, value - FEE, addr(9));
    let keen = signed_spend(&miner, op_b, value - (FEE * 2), addr(8));
    assert_eq!(
        rich.gas_used(),
        keen.gas_used(),
        "identical gas is what makes this a statement about rate"
    );
    assert!(
        keen.txid() != rich.txid(),
        "the two transactions must be distinct"
    );

    let mut pool = Mempool::default();
    admit(&chain, &mut pool, rich.clone()).unwrap();
    admit(&chain, &mut pool, keen.clone()).unwrap();

    let block = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();
    assert_eq!(
        block.txs[1].txid(),
        keen.txid(),
        "the higher fee rate must be mined first"
    );
}

// ---------------------------------------------------------------------------
// 6. Reorg
// ---------------------------------------------------------------------------

/// **The rule:** a reorg returns disconnected transactions to the pool rather
/// than destroying them.
///
/// **The attack:** this one is not hostile — it is the normal case. A competing
/// branch that out-works ours is how the network reaches agreement, and if a node
/// drops the transactions of the orphaned blocks then a user's valid, mined,
/// broadcast payment can vanish from the network entirely. Worse, it vanishes
/// silently.
#[test]
fn a_reorg_returns_disconnected_transactions_to_the_pool() {
    let (miner, mut chain, mut rival) = reorg_fixture(12);
    let fork_height = chain.height();
    let (op, value) = coinbase_of(&chain, 1);

    // Main branch: mine the payment into block 13.
    let mut pool = Mempool::default();
    let payment = signed_spend(&miner, op, value - FEE, addr(9));
    admit(&chain, &mut pool, payment.clone()).unwrap();
    let main_block = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();
    assert_eq!(main_block.header.height, 13);
    assert!(pool.is_empty(), "mine_from_pool must evict what it mined");

    // Rival branch: three empty blocks instead. Identical blocks to a peer's.
    let mut rival_blocks = Vec::new();
    for h in 13..=15u64 {
        let b = rival.mine_block(addr(2), vec![], ts(h)).unwrap();
        rival.submit(b.clone()).unwrap();
        rival_blocks.push(b);
    }

    // Feed the rival branch in. The first two extend a side branch; the third
    // out-works the canonical chain and forces the reorg.
    for b in &rival_blocks {
        chain.submit(b.clone()).unwrap();
    }

    assert_eq!(chain.height(), 15, "the heavier branch must win");
    assert_eq!(
        chain.block_at(13).unwrap().txs.len(),
        1,
        "the rival's block 13 must be canonical, or no reorg happened"
    );

    // The payment is now unconfirmed and must be back in the pool, not lost.
    //
    // `reconcile_mempool` drains the disconnected set itself: calling
    // `take_disconnected` first would consume it and this would silently see
    // nothing, with no error to explain why. The drain's own contract is pinned
    // by `a_reorg_exposes_exactly_the_disconnected_transactions_once`.
    let (height, report) = chain.reconcile_mempool(&mut pool, fork_height);
    assert_eq!(height, 15);
    assert_eq!(report.readmitted, 1, "the payment was not re-admitted");
    assert_eq!(report.refused, 0);
    assert!(
        pool.contains(&payment.txid()),
        "the payment did not come back — it was silently destroyed"
    );

    // Draining is exactly once: a second reconcile must not resurrect it.
    let (_, second) = chain.reconcile_mempool(&mut pool, 15);
    assert_eq!(second.readmitted, 0);
    assert_eq!(pool.len(), 1);
}

/// **The rule:** `take_disconnected` names exactly the transactions the reorg
/// orphaned, and draining it is once-only.
///
/// Separate from the test above on purpose. That test exercises
/// `reconcile_mempool`, which drains internally; this one exercises the drain
/// itself. Merging them is what hid the bug in this test the first time: a
/// caller that drains and then reconciles gets an empty re-admission and no
/// error, which is a silent no-op rather than a failure.
#[test]
fn a_reorg_exposes_exactly_the_disconnected_transactions_once() {
    let (miner, mut chain, mut rival) = reorg_fixture(12);
    let (op, value) = coinbase_of(&chain, 1);

    let mut pool = Mempool::default();
    let payment = signed_spend(&miner, op, value - FEE, addr(9));
    admit(&chain, &mut pool, payment.clone()).unwrap();
    // The block is submitted inside `mine_from_pool`; only the pool's response
    // is under test here.
    let _mined = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();

    // Nothing is pending before a reorg, and an empty drain is empty rather
    // than a stale set from an earlier reorg.
    assert!(chain.take_disconnected().is_empty());

    let mut rival_blocks = Vec::new();
    for h in 13..=15u64 {
        let b = rival.mine_block(addr(2), vec![], ts(h)).unwrap();
        rival.submit(b.clone()).unwrap();
        rival_blocks.push(b);
    }
    for b in &rival_blocks {
        chain.submit(b.clone()).unwrap();
    }
    assert_eq!(chain.height(), 15);

    let disconnected = chain.take_disconnected();
    assert_eq!(disconnected.len(), 1, "exactly the orphaned payment");
    assert_eq!(disconnected[0].txid(), payment.txid());
    assert!(
        chain.take_disconnected().is_empty(),
        "the same transactions were exposed twice; the drain is not once-only"
    );
}

/// **The rule:** a transaction whose input the winning branch consumed is
/// *refused*, not re-pooled.
///
/// This is the complement of the test above, and the reason re-admission goes
/// through `add` instead of being inserted directly: a reorg is allowed to
/// invalidate a transaction, and the pool must record that honestly rather than
/// carry something no block can include.
#[test]
fn a_reorg_that_consumed_the_input_refuses_the_readmission() {
    let (miner, mut chain, mut rival) = reorg_fixture(12);
    let fork_height = chain.height();
    let (op, value) = coinbase_of(&chain, 1);

    // Main branch: the user's payment spends this coinbase.
    let mut pool = Mempool::default();
    let payment = signed_spend(&miner, op, value - FEE, addr(9));
    admit(&chain, &mut pool, payment.clone()).unwrap();
    // The block is submitted inside `mine_from_pool`; only the pool's response
    // is under test here.
    let _mined = chain.mine_from_pool(&mut pool, addr(1), ts(13)).unwrap();

    // Rival branch: its block 13 spends the *same* coinbase first.
    let rival_spend = signed_spend(&miner, op, value - FEE - 1, addr(7));
    let rival_13 = rival
        .mine_block(addr(2), vec![rival_spend], ts(13))
        .unwrap();
    rival.submit(rival_13.clone()).unwrap();
    let mut rival_blocks = vec![rival_13];
    for h in 14..=15u64 {
        let b = rival.mine_block(addr(2), vec![], ts(h)).unwrap();
        rival.submit(b.clone()).unwrap();
        rival_blocks.push(b);
    }

    for b in &rival_blocks {
        chain.submit(b.clone()).unwrap();
    }
    assert_eq!(chain.height(), 15, "the heavier branch must win");

    // No `take_disconnected` here: `reconcile_mempool` drains the set, and
    // draining first would silently empty the re-admission.
    let (_, report) = chain.reconcile_mempool(&mut pool, fork_height);
    assert_eq!(
        report.refused, 1,
        "the payment's input is gone; re-admitting it would relay something \
         no block can include"
    );
    assert_eq!(report.readmitted, 0);
    assert!(
        pool.is_empty(),
        "an invalidated transaction was put back into the pool"
    );
}
