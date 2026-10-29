//! M2 funding-bridge node tests — Decision 7, SPEC.md §19.4.
//!
//! The STEP 9 end-to-end flow plus the STEP 6 attack matrix, all through the
//! real node path (mined blocks, `Chain::submit`, `NodeL2::sync`):
//!
//! - a genesis-funded account posts through the node and the task appears with
//!   the balance decreased by exactly payment + fee;
//! - an unfunded account still fails closed;
//! - funding exists exactly once across restart and reorg (no duplication);
//! - two independent replays agree exactly, and incremental agrees with replay;
//! - L1 live plus L2 held never exceeds the cap.

use srct_core::block::Block;
use srct_core::chain::Chain;
use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use srct_core::params::{NetworkParams, SAT_PER_SRCT};
use srct_core::wallet::Wallet;
use srct_core::Address;
use srct_l2::L2Error;
use srct_node::l2::{NodeL2, SyncOutcome};

const MAX_ATTEMPTS: u64 = 4_000_000;
const GRANT_SAT: u64 = SAT_PER_SRCT;
const PAYMENT_SAT: u64 = 5_000_000;

fn addr(tag: u8) -> Address {
    [tag; 20]
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-funding-test").unwrap()
}

fn ts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn task(nonce: u64, deadline: u64) -> ComputeTask {
    let mut task_id = [0x44u8; 32];
    task_id[0] = nonce as u8;
    task_id[1] = (nonce >> 8) as u8;
    ComputeTask {
        task_id,
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 1_000_000,
        expiry_height: deadline,
        submit_height: 1,
    }
}

fn post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, PAYMENT_SAT, deadline, task(nonce, deadline)).unwrap(),
    ))
}

fn task_id_of(tx: &L2Transaction) -> [u8; 32] {
    match &tx.payload {
        L2Payload::Post(p) => p.task_id,
        _ => unreachable!(),
    }
}

fn mine_and_submit(chain: &mut Chain, l2: Vec<L2Transaction>) -> Block {
    let h = chain.height() + 1;
    // An L2-bearing block commits the root replay derives (approved P1). The
    // view is rebuilt from the chain so far, exactly as `replay_from` would
    // for the node that later replays this block.
    let block = if l2.is_empty() {
        chain.mine_block(addr(1), Vec::new(), ts(h))
    } else if chain.exit_active_at(h) {
        let root = NodeL2::replay_from(chain, chain.params())
            .unwrap()
            .simulate_root(chain, h, &l2);
        chain.mine_block_with_l2_root(addr(1), Vec::new(), l2, root, ts(h), None, MAX_ATTEMPTS)
    } else {
        chain.mine_block_with_l2(addr(1), Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
    }
    .expect("a block we just mined must build");
    chain.submit(block.clone()).expect("it must be accepted");
    block
}

fn escrow_total(params: &NetworkParams) -> u64 {
    params.l2_genesis_escrow_sat
}

// --- STEP 9: the end-to-end funded flow -------------------------------------

#[test]
fn funded_post_flows_through_the_node_end_to_end() {
    // 1. Start the chain. 2. Genesis funding is in params (no step needed —
    // that is the point: funding is protocol state, not an operator action).
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    // 3. Replay the node. 4. Verify the funded balance.
    let mut view = NodeL2::fresh(&params).unwrap();
    view.sync(&chain).unwrap();
    let submitter = wallet(1).address().unwrap();
    assert_eq!(view.state().balance(&submitter), GRANT_SAT);
    assert_eq!(view.state().funded_total(), escrow_total(&params));

    // 5–6. Submit a valid PostTask; mine and accept the block.
    let tx = post(1, 7, 200);
    mine_and_submit(&mut chain, vec![tx.clone()]);
    // 7. NodeL2 syncs. 8. The task exists.
    let report = view.sync(&chain).unwrap();
    assert_eq!(report.outcome, SyncOutcome::Incremental { blocks: 1 });
    assert_eq!(view.applied_count(), 1);
    assert!(view.is_clean());
    assert!(view.state().task(&task_id_of(&tx)).is_some());
    // 9. The balance decreased by exactly payment + fee; conservation holds.
    assert_eq!(
        view.state().balance(&submitter),
        GRANT_SAT - PAYMENT_SAT - tx.fee_sat()
    );
    assert!(view.state().check_conservation());
    assert_eq!(view.state().funded_total(), escrow_total(&params));

    // 10–11. Replay from scratch: identical final state.
    let again = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(again.state(), view.state());
    assert_eq!(again.skipped(), view.skipped());
    assert_eq!(again.applied_count(), view.applied_count());
}

#[test]
fn unfunded_account_fails_closed_beside_funded_ones() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    // Seed 9 holds no grant; seed 1 does. Both posts ride one block.
    mine_and_submit(&mut chain, vec![post(9, 1, 200), post(1, 2, 200)]);
    let mut view = NodeL2::fresh(&params).unwrap();
    view.sync(&chain).unwrap();

    assert_eq!(view.applied_count(), 1);
    assert_eq!(view.skipped().len(), 1);
    let skip = &view.skipped()[0];
    assert!(matches!(
        skip.error,
        L2Error::InsufficientBalance { available: 0, .. }
    ));
    // Funding your neighbour does not fund you — and the refusal wrote nothing.
    assert!(view.state().check_conservation());
    assert_eq!(view.state().funded_total(), escrow_total(&params));
}

// --- no double application --------------------------------------------------

#[test]
fn same_bytes_in_two_blocks_apply_once_then_replay_refuse() {
    // An attacker rebroadcasting the same bytes in a later block must not be
    // paid twice: the txid set refuses the second application by name.
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let tx = post(1, 21, 200);
    mine_and_submit(&mut chain, vec![tx.clone()]);
    mine_and_submit(&mut chain, vec![tx.clone()]);
    let mut view = NodeL2::fresh(&params).unwrap();
    view.sync(&chain).unwrap();

    assert_eq!(view.applied_count(), 1);
    assert_eq!(view.skipped().len(), 1);
    assert_eq!(view.skipped()[0].error, L2Error::Replay);
    assert_eq!(view.skipped()[0].txid, tx.txid());
    assert!(view.state().check_conservation());
}

// --- restart: funding exists exactly once -----------------------------------

#[test]
fn restart_keeps_funding_exactly_once() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 1, 200)]);
    mine_and_submit(&mut chain, vec![post(2, 2, 200)]);
    let live = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(live.applied_count(), 2);

    // Shutdown drops everything; restart replays the same blocks. Funding is
    // re-derived from params, not re-added per block, so it appears once.
    let recovered = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(recovered.state(), live.state());
    assert_eq!(
        recovered.state().funded_total(),
        escrow_total(&params),
        "restart must not duplicate funding"
    );
    assert_eq!(
        recovered.state().balance(&wallet(1).address().unwrap()),
        GRANT_SAT - PAYMENT_SAT - post(1, 1, 200).fee_sat()
    );
    assert!(recovered.state().check_conservation());

    // Incremental-from-scratch converges to the same state (STEP 7).
    let mut inc = NodeL2::fresh(&params).unwrap();
    inc.sync(&chain).unwrap();
    assert_eq!(inc.state(), live.state());
}

// --- reorg: no duplicated funding, no kept history --------------------------

#[test]
fn reorg_does_not_duplicate_funding_or_keep_losing_tasks() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    // Main branch funds and posts (task nonce 1).
    for h in 1..=2u64 {
        mine_and_submit(&mut chain, vec![post(1, h, 200)]);
    }
    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.applied_count(), 2);
    let main_task = task_id_of(&post(1, 1, 200));

    // Rival from genesis, longer so it wins, carrying a different funded post.
    let mut rival = Chain::new(params.clone()).unwrap();
    let mut rival_blocks = Vec::new();
    for h in 1..=3u64 {
        let l2 = if h == 2 {
            vec![post(2, 42, 200)]
        } else {
            Vec::new()
        };
        let rb = if l2.is_empty() {
            rival.mine_block(addr(2), Vec::new(), ts(h)).unwrap()
        } else if rival.exit_active_at(h) {
            let root = NodeL2::replay_from(&rival, rival.params())
                .unwrap()
                .simulate_root(&rival, h, &l2);
            rival
                .mine_block_with_l2_root(addr(2), Vec::new(), l2, root, ts(h), None, MAX_ATTEMPTS)
                .unwrap()
        } else {
            rival
                .mine_block_with_l2(addr(2), Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
                .unwrap()
        };
        rival.submit(rb.clone()).unwrap();
        rival_blocks.push(rb);
    }
    assert!(rival.total_work() > chain.total_work());
    for rb in &rival_blocks {
        chain.submit(rb.clone()).unwrap();
    }
    assert_eq!(chain.height(), 3);

    let report = view.sync(&chain).unwrap();
    assert!(matches!(report.outcome, SyncOutcome::FullReplay { .. }));
    // The winner's post applied; the loser's tasks are gone; the funding was
    // neither duplicated nor lost.
    assert_eq!(view.applied_count(), 1);
    assert!(view.state().task(&main_task).is_none());
    assert!(view.state().task(&task_id_of(&post(2, 42, 200))).is_some());
    assert_eq!(view.state().funded_total(), escrow_total(&params));
    assert!(view.state().check_conservation());
    let fresh = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.state(), fresh.state());
}

// --- determinism across independent replays ---------------------------------

#[test]
fn two_independent_nodes_agree_on_everything() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 1, 200), post(9, 2, 200)]);
    mine_and_submit(&mut chain, Vec::new());
    mine_and_submit(&mut chain, vec![post(2, 3, 200)]);

    // Node A replays whole; node B follows incrementally from empty.
    let a = NodeL2::replay_from(&chain, &params).unwrap();
    let mut b = NodeL2::fresh(&params).unwrap();
    b.sync(&chain).unwrap();
    assert_eq!(a.state(), b.state());
    assert_eq!(a.skipped(), b.skipped());
    assert_eq!(a.applied_count(), b.applied_count());
    // Balances, escrow, tasks, funding records, skip records — all covered by
    // the total state equality plus these pins.
    assert_eq!(a.state().funded_total(), escrow_total(&params));
    assert_eq!(
        a.state().balance(&params.l2_escrow_address()),
        escrow_total(&params) - 3 * GRANT_SAT
    );
    assert_eq!(a.applied_count(), 2);
    assert_eq!(a.skipped().len(), 1);
    assert!(a.state().check_conservation());
}

// --- joint supply: 1 SRCT L1 can never become 1 L1 + 1 L2 --------------------

#[test]
fn joint_l1_plus_l2_supply_stays_under_the_joint_bound() {
    // The STEP 6 attack goal, stated as an invariant: no sequence of funded
    // operations may push live L1 supply plus everything L2 ever held past
    // the cap. Mining rewards grow L1 while L2 spends down its escrow.
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    for h in [1u64, 2, 3] {
        mine_and_submit(&mut chain, vec![post(1, h, 200)]);
    }
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.applied_count(), 3);

    let joint = chain
        .utxo()
        .total_value()
        .saturating_add(view.state().conservation_total());
    // The joint bound (Decision 18 removed the stock cap): L1's issuance
    // integral at the tip plus the L2 escrow ceiling.
    let bound = srct_core::supply::cumulative_issuance_sat(&params, chain.height())
        .saturating_add(params.escrow_ceiling_sat);
    assert!(joint <= bound, "joint supply {joint} exceeds bound {bound}");
    // And the slack is exactly what the gap-fit promises: L1 mints at most
    // reachable, L2 holds at most escrow.
    assert!(chain.utxo().total_value() <= srct_core::supply::max_issuance_sat(&params));
    assert!(view.state().conservation_total() <= escrow_total(&params));
}
