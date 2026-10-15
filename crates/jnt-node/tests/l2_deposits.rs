//! M3 deposit node tests — Decision 10, SPEC.md §19.5.
//!
//! Through the real node path (mined blocks, `Chain::submit`, `NodeL2::sync`):
//! the STEP 10 end-to-end flow, the STEP 7 attack matrix, reorg/restart
//! safety, A/B determinism, and the sink-aware joint supply invariant.
//!
//! Seeds 60+ are pure users: no genesis grants, so every funded balance here
//! comes from an L1 deposit or it fails the test.

use std::sync::atomic::{AtomicU64, Ordering};

use jnt_core::block::Block;
use jnt_core::chain::Chain;
use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::sig::{Bundle, Component, SCHEME_SECP256K1_ECDSA, SCHEME_SECP256K1_SCHNORR};
use jnt_core::tx::{Input, OutPoint, Output, Transaction};
use jnt_core::wallet::Wallet;
use jnt_l2::{DepositIgnoreReason, L2Error};
use jnt_node::l2::{NodeL2, SyncOutcome};
use jnt_store::BlockStore;

const MAX_ATTEMPTS: u64 = 4_000_000;
const DEPOSIT_SAT: u64 = 3 * SAT_PER_JNT;
const POST_PAYMENT_SAT: u64 = 5_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "l2-deposit-node-test").unwrap()
}

fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn mine_empty_to(chain: &mut Chain, miner: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn mine_with_body(chain: &mut Chain, miner: Address, body: Vec<Transaction>) -> Block {
    let h = chain.height() + 1;
    let b = chain.mine_block(miner, body, ts(h)).unwrap();
    chain.submit(b.clone()).unwrap();
    b
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

fn sink_of(params: &NetworkParams) -> Address {
    params.l2_deposit_sink()
}

fn escrow_of(params: &NetworkParams) -> u64 {
    params.l2_genesis_escrow_sat
}

/// Mature coinbase outpoints of `miner` (mini maturity is 10: eleven mined
/// blocks mature the first coinbase).
fn mature_outpoints(chain: &Chain, miner: Address) -> Vec<(OutPoint, u64)> {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .collect()
}

/// A valid L1 payment carrying one sink output plus change.
fn deposit_tx(
    chain: &Chain,
    from: &Wallet,
    op: OutPoint,
    op_value: u64,
    sink_value: u64,
) -> Transaction {
    let fee = fee_for(chain, 1, 2);
    let me = from.address().unwrap();
    from.build_tx(
        &[op],
        vec![
            Output {
                value: sink_value,
                address: sink_of(chain.params()),
            },
            Output {
                value: op_value - sink_value - fee,
                address: me,
            },
        ],
        fee,
    )
    .unwrap()
}

fn l2_post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    let task = ComputeTask {
        task_id: [0x55u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 1024,
        backend_hint: ComputeBackend::Cpu,
        reward_sat: 1_000,
        expiry_height: deadline,
        submit_height: 1,
    };
    let mut t = task;
    t.task_id[0] = nonce as u8;
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, POST_PAYMENT_SAT, deadline, t).unwrap(),
    ))
}

fn task_id_of(tx: &L2Transaction) -> Hash {
    match &tx.payload {
        L2Payload::Post(p) => p.task_id,
        _ => unreachable!(),
    }
}

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store_dir() -> std::path::PathBuf {
    let id = STORE_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("jnt-m3-deposit-{}-{id}", std::process::id()))
}

fn persist_chain(chain: &Chain, dir: &std::path::Path) {
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir, &params).unwrap();
    for h in 1..=chain.height() {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.tip_hash()).unwrap();
    bs.sync().unwrap();
}

fn reload_chain(dir: &std::path::Path, params: &NetworkParams) -> Chain {
    let (mut bs, _) = BlockStore::open(dir, params).unwrap();
    let (_, height) = bs.tip();
    let mut chain = Chain::new(params.clone()).unwrap();
    for h in 1..=height {
        chain
            .submit(bs.block_at_height(h).unwrap().expect("stored block"))
            .unwrap();
    }
    chain
}

// --- STEP 10: end to end ----------------------------------------------------

#[test]
fn deposit_end_to_end_funds_posttask_and_survives_restart() {
    let params = NetworkParams::mini();
    let depth = params.finality_depth;
    let user = wallet(60);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();

    // 1. L1 owner exists and holds matured mining rewards.
    mine_empty_to(&mut chain, user_addr, 11);
    let funding: Vec<_> = mature_outpoints(&chain, user_addr);
    assert!(!funding.is_empty());
    let (op, op_value) = funding[0];

    // 2–4. Valid STANDARD payment to the sink, mined and accepted.
    let tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    let deposit_height = chain.height() + 1;
    mine_with_body(&mut chain, user_addr, vec![tx.clone()]);

    // 5. Replay detects it — pending, not credited, before maturity.
    let mut view = NodeL2::fresh(&params).unwrap();
    view.sync(&chain).unwrap();
    assert_eq!(view.pending_deposits().len(), 1);
    assert_eq!(view.deposits_applied_count(), 0);
    assert_eq!(view.state().balance(&user_addr), 0);
    let p = view.pending_deposits()[0];
    assert_eq!(p.deposit.amount_sat, DEPOSIT_SAT);
    assert_eq!(p.deposit.recipient, user_addr);
    assert_eq!(p.matures_at, deposit_height + depth);

    // 6. Maturity: mine until final-deep. The maturation flips the view to a
    // full replay (incremental never re-scans old blocks).
    while chain.height() < deposit_height + depth {
        mine_empty_to(&mut chain, user_addr, 1);
    }
    let report = view.sync(&chain).unwrap();
    assert!(matches!(report.outcome, SyncOutcome::FullReplay { .. }));
    // 7. Exact credit, conservation closed, funding provenance exact.
    assert!(view.pending_deposits().is_empty());
    assert_eq!(view.deposits_applied_count(), 1);
    assert_eq!(view.state().balance(&user_addr), DEPOSIT_SAT);
    assert_eq!(view.state().deposited_total(), DEPOSIT_SAT);
    assert_eq!(
        view.state().funded_total(),
        escrow_of(&params) + DEPOSIT_SAT
    );
    assert!(view.state().check_conservation());

    // 8–9. The deposited user posts; it applies through the normal path.
    let post = l2_post(60, 1, 500);
    let h = chain.height() + 1;
    // An L2-bearing block commits the root replay derives (approved P1).
    let root = view.simulate_root(h, std::slice::from_ref(&post));
    let b = chain
        .mine_block_with_l2_root(
            user_addr,
            vec![],
            vec![post.clone()],
            root,
            ts(h),
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(b).unwrap();
    view.sync(&chain).unwrap();
    assert!(view.state().task(&task_id_of(&post)).is_some());
    // 10. Balance = deposit − payment − fee, to the satoshi.
    assert_eq!(
        view.state().balance(&user_addr),
        DEPOSIT_SAT - POST_PAYMENT_SAT - post.fee_sat()
    );
    assert!(view.state().check_conservation());

    // 11–13. Restart from persistent blocks: identical everything.
    let dir = temp_store_dir();
    persist_chain(&chain, &dir);
    let chain2 = reload_chain(&dir, &params);
    let again = NodeL2::replay_from(&chain2, &params).unwrap();
    assert_eq!(again.state(), view.state());
    assert_eq!(again.pending_deposits(), view.pending_deposits());
    assert_eq!(again.ignored_deposits(), view.ignored_deposits());
    assert_eq!(
        again.state().funded_total(),
        escrow_of(&params) + DEPOSIT_SAT,
        "restart must not duplicate funding"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// --- STEP 7 attacks ----------------------------------------------------------

#[test]
fn mixed_owner_sink_output_is_burn_without_credit() {
    // Two wallets co-sign one transaction paying the sink. Valid L1 payment
    // (both signatures check) — but no unique owner, so no deposit.
    let params = NetworkParams::mini();
    let (a, b) = (wallet(61), wallet(62));
    let (aa, ba) = (a.address().unwrap(), b.address().unwrap());
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, aa, 11);
    // Fund B with a standard (maturing) payment, then wait it out.
    let funding = mature_outpoints(&chain, aa);
    let fee = fee_for(&chain, 1, 2);
    let fund_b = a
        .build_tx(
            &[funding[0].0],
            vec![
                Output {
                    value: 20 * SAT_PER_JNT,
                    address: ba,
                },
                Output {
                    value: funding[0].1 - 20 * SAT_PER_JNT - fee,
                    address: aa,
                },
            ],
            fee,
        )
        .unwrap();
    mine_with_body(&mut chain, aa, vec![fund_b]);
    mine_empty_to(&mut chain, aa, 10);

    // One mature outpoint each; hand-assemble a tx with per-owner signatures.
    let (opa, va) = mature_outpoints(&chain, aa)
        .into_iter()
        .find(|(_, v)| *v >= 30 * SAT_PER_JNT)
        .expect("A holds a large mature output");
    let (opb, vb) = mature_outpoints(&chain, ba)
        .into_iter()
        .next()
        .expect("B holds funds");
    let sink_value = 2 * SAT_PER_JNT;
    let fee = fee_for(&chain, 2, 2);
    let mut mixed = Transaction::standard(
        vec![Input::unsigned(&opa), Input::unsigned(&opb)],
        vec![
            Output {
                value: sink_value,
                address: sink_of(&params),
            },
            Output {
                value: va + vb - sink_value - fee,
                address: aa,
            },
        ],
    );
    for (k, w) in [&a, &b].iter().enumerate() {
        let msg = mixed.message_for_input(k);
        let keys = Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, w.pubkey().unwrap().to_vec()),
                Component::new(
                    SCHEME_SECP256K1_SCHNORR,
                    w.schnorr_pubkey().unwrap().to_vec(),
                ),
            ],
        };
        let sigs = Bundle {
            components: vec![
                Component::new(
                    SCHEME_SECP256K1_ECDSA,
                    w.sign_digest(&msg).unwrap().to_vec(),
                ),
                Component::new(
                    SCHEME_SECP256K1_SCHNORR,
                    w.sign_schnorr(&msg).unwrap().to_vec(),
                ),
            ],
        };
        mixed.inputs[k].keys = keys;
        mixed.inputs[k].sigs = sigs;
    }
    // Accepted as L1 (both owners really signed)...
    mine_with_body(&mut chain, aa, vec![mixed.clone()]);
    // ...but credited to nobody.
    mine_empty_to(&mut chain, aa, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 0);
    assert_eq!(view.ignored_deposits().len(), 1);
    assert_eq!(
        view.ignored_deposits()[0].reason,
        DepositIgnoreReason::MixedOwners
    );
    assert_eq!(view.state().balance(&aa), 0);
    assert_eq!(view.state().balance(&ba), 0);
    // The burn really happened on L1: the sink holds the value.
    let sink_held: u64 = chain
        .utxo()
        .outputs_for_address(&sink_of(&params))
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(sink_held, sink_value);
    assert!(view.state().check_conservation());
}

#[test]
fn zero_amount_output_rejected_by_l1_before_l2_sees_it() {
    // L1 rejects zero-value outputs at submission: the "deposit" never becomes
    // canonical, so replay never observes it and L2 is untouched.
    let params = NetworkParams::mini();
    let user = wallet(63);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, _) = mature_outpoints(&chain, user_addr)[0];
    // Sign first, then append the zero output: either L1 rule (zero-value
    // outputs refused; signatures cover all outputs) rejects the block.
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&op)],
        vec![Output {
            value: 1_000,
            address: user_addr,
        }],
    );
    user.sign(&mut tx).unwrap();
    tx.outputs.push(Output {
        value: 0,
        address: sink_of(&params),
    });
    // Refused before it is even a block: body validation rejects zero-value
    // outputs, so the "deposit" never becomes canonical and replay never
    // observes it. (If a future builder admitted it, `submit` must still
    // refuse — either L1 gate failing keeps L2 untouched.)
    let h = chain.height() + 1;
    assert!(chain.mine_block(user_addr, vec![tx], ts(h)).is_err());
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 0);
    assert!(view.pending_deposits().is_empty());
    assert!(view.ignored_deposits().is_empty());
}

#[test]
fn below_minimum_sink_output_is_valid_l1_but_no_credit() {
    let params = NetworkParams::mini();
    let user = wallet(64);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let dust = params.l2_deposit_minimum_sat - 1;
    let tx = deposit_tx(&chain, &user, op, op_value, dust);
    mine_with_body(&mut chain, user_addr, vec![tx]);
    mine_empty_to(&mut chain, user_addr, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 0);
    assert_eq!(view.ignored_deposits().len(), 1);
    assert_eq!(
        view.ignored_deposits()[0].reason,
        DepositIgnoreReason::BelowMinimum
    );
    assert_eq!(view.state().balance(&user_addr), 0);
}

#[test]
fn wrong_sink_addresses_are_silent() {
    let params = NetworkParams::mini();
    let user = wallet(65);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let funding = mature_outpoints(&chain, user_addr);
    let fee = fee_for(&chain, 1, 3);
    // Foreign-network sink, escrow address, ordinary address: burns/payments,
    // none of them deposits.
    let tx = user
        .build_tx(
            &[funding[0].0],
            vec![
                Output {
                    value: 2_000_000,
                    address: NetworkParams::mainnet().l2_deposit_sink(),
                },
                Output {
                    value: 2_000_000,
                    address: params.l2_escrow_address(),
                },
                Output {
                    value: funding[0].1 - 4_000_000 - fee,
                    address: user_addr,
                },
            ],
            fee,
        )
        .unwrap();
    mine_with_body(&mut chain, user_addr, vec![tx]);
    mine_empty_to(&mut chain, user_addr, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 0);
    assert!(view.pending_deposits().is_empty());
    assert!(view.ignored_deposits().is_empty());
}

#[test]
fn same_deposit_on_competing_branches_credits_once() {
    // The same L1 bytes ride two competing branches (valid on each: the inputs
    // are unspent on both). The winner carries them once, so replay credits
    // once — no cross-branch double funding, no duplicate record.
    let params = NetworkParams::mini();
    let user = wallet(66);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    // Main branch carries the deposit at h12, then stalls at tip 15.
    mine_with_body(&mut chain, user_addr, vec![tx.clone()]);
    mine_empty_to(&mut chain, user_addr, 3);
    assert_eq!(chain.height(), 15);

    // Rival shares 1..=11 (above finality: finalized is 0 this deep... it
    // forks at index 12, legal), carries the SAME bytes at its own h12, and
    // out-mines main by one.
    let mut rival = Chain::new(params.clone()).unwrap();
    for h in 1..=11u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    let mut rival_blocks = Vec::new();
    // Rival miner differs so every rival block differs (same inputs would
    // otherwise mine byte-identical blocks, which fork nothing).
    let rival_miner: Address = [0xFDu8; 20];
    while rival.height() <= chain.height() {
        let h = rival.height() + 1;
        let body = if h == 12 { vec![tx.clone()] } else { vec![] };
        let rb = rival.mine_block(rival_miner, body, ts(h)).unwrap();
        rival.submit(rb.clone()).unwrap();
        rival_blocks.push(rb);
    }
    assert!(rival.total_work() > chain.total_work());
    for rb in &rival_blocks {
        chain.submit(rb.clone()).unwrap();
    }
    // Winner holds the bytes once: mature them out and expect one credit.
    mine_empty_to(&mut chain, user_addr, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 1);
    assert_eq!(view.state().balance(&user_addr), DEPOSIT_SAT);
    assert_eq!(view.state().deposited_total(), DEPOSIT_SAT);
    assert!(view.ignored_deposits().is_empty());
    assert!(view.state().check_conservation());
}

#[test]
fn mutated_transaction_rejected_by_l1() {
    // Flipping one satoshi in a signed output breaks every input signature:
    // L1 refuses the block, replay never sees it.
    let params = NetworkParams::mini();
    let user = wallet(67);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let mut tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    tx.outputs[0].value += 1;
    // Flipping one satoshi breaks every input signature: body validation
    // refuses the block, so the mutated bytes never become canonical.
    let h = chain.height() + 1;
    assert!(chain.mine_block(user_addr, vec![tx], ts(h)).is_err());
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 0);
    assert!(view.pending_deposits().is_empty());
}

#[test]
fn two_sink_outputs_credit_independently() {
    let params = NetworkParams::mini();
    let user = wallet(68);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let fee = fee_for(&chain, 1, 3);
    let (v1, v2) = (2_000_000u64, 3_000_000u64);
    let tx = user
        .build_tx(
            &[op],
            vec![
                Output {
                    value: v1,
                    address: sink_of(&params),
                },
                Output {
                    value: v2,
                    address: sink_of(&params),
                },
                Output {
                    value: op_value - v1 - v2 - fee,
                    address: user_addr,
                },
            ],
            fee,
        )
        .unwrap();
    mine_with_body(&mut chain, user_addr, vec![tx.clone()]);
    mine_empty_to(&mut chain, user_addr, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 2);
    assert_eq!(view.state().balance(&user_addr), v1 + v2);
    assert_eq!(view.state().deposited_total(), v1 + v2);
    assert!(view.state().check_conservation());
}

#[test]
fn unfunded_l2_account_still_closed() {
    // No L1 deposit, no genesis grant (seed 69): the L2 post fails closed.
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, addr_of_miner(), 3);
    let post = l2_post(69, 1, 200);
    let h = chain.height() + 1;
    // Unfunded post: replay skips it, so the committed root is the skipped one.
    let root = {
        let empty = NodeL2::fresh(&params).unwrap();
        empty.simulate_root(h, std::slice::from_ref(&post))
    };
    let b = chain
        .mine_block_with_l2_root(
            addr_of_miner(),
            vec![],
            vec![post.clone()],
            root,
            ts(h),
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(b).unwrap();
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    assert!(matches!(
        view.skipped()[0].error,
        L2Error::InsufficientBalance { .. }
    ));
}

fn addr_of_miner() -> Address {
    [0xEu8; 20]
}

// --- reorg -------------------------------------------------------------------

#[test]
fn reorg_removes_deposit_and_winner_recredits_exactly_once() {
    let params = NetworkParams::mini();
    let depth = params.finality_depth;
    let user = wallet(70);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();

    // Fund on main, deposit at h12, leave it pending (tip 15).
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    mine_with_body(&mut chain, user_addr, vec![tx.clone()]);
    mine_empty_to(&mut chain, user_addr, 3);
    assert_eq!(chain.height(), 15);
    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.pending_deposits().len(), 1);
    assert_eq!(view.deposits_applied_count(), 0);

    // Rival: share blocks 1..=11 (fork index 12, above finalized 0), then
    // out-mine without the deposit. Heavier wins; the pending deposit is gone
    // from canonical history.
    //
    // Note what is NOT tested here, deliberately: removing a *matured*
    // deposit. Mature means final-deep, and final history cannot reorg by
    // consensus rule — so a matured deposit is as irremovable as the block
    // carrying it. Tying maturity to finality depth is what makes that true.
    let mut rival = Chain::new(params.clone()).unwrap();
    let mut rival_blocks = Vec::new();
    for h in 1..=11u64 {
        rival.submit(chain.block_at(h).unwrap().clone()).unwrap();
    }
    while rival.height() <= chain.height() {
        let h = rival.height() + 1;
        let rb = rival.mine_block([0xFu8; 20], vec![], ts(h)).unwrap();
        rival.submit(rb.clone()).unwrap();
        rival_blocks.push(rb);
    }
    assert!(rival.total_work() > chain.total_work());
    for rb in &rival_blocks {
        chain.submit(rb.clone()).unwrap();
    }
    // The deposit vanished with its block: no credit, no pending, no record —
    // and funding is exactly the escrow again.
    let report = view.sync(&chain).unwrap();
    assert!(matches!(report.outcome, SyncOutcome::FullReplay { .. }));
    assert_eq!(view.deposits_applied_count(), 0);
    assert!(view.pending_deposits().is_empty());
    assert_eq!(view.state().balance(&user_addr), 0);
    assert_eq!(view.state().funded_total(), escrow_of(&params));
    assert_eq!(view.state().deposited_total(), 0);
    assert!(view.state().check_conservation());

    // The winner never spent the deposit inputs: mine the SAME bytes onto it.
    // They pend at their new height and credit at maturity — exactly once, not
    // stacked on history.
    let h = chain.height() + 1;
    let b = chain
        .mine_block([0xFu8; 20], vec![tx.clone()], ts(h))
        .unwrap();
    chain.submit(b).unwrap();
    mine_empty_to(&mut chain, [0xFu8; 20], depth);
    view.sync(&chain).unwrap();
    assert_eq!(view.deposits_applied_count(), 1);
    assert_eq!(view.state().balance(&user_addr), DEPOSIT_SAT);
    assert_eq!(view.state().deposited_total(), DEPOSIT_SAT);
    assert_eq!(
        view.state().funded_total(),
        escrow_of(&params) + DEPOSIT_SAT
    );
    assert!(view.state().check_conservation());
    let fresh = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.state(), fresh.state());
}

// --- determinism + joint supply ------------------------------------------------

#[test]
fn ab_replay_agrees_on_deposits_pending_and_ignored() {
    let params = NetworkParams::mini();
    let user = wallet(71);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    // One matured deposit, one still pending, one dust refusal.
    let tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    mine_with_body(&mut chain, user_addr, vec![tx]);
    // Node B follows incrementally: full replay to the deposit block, then an
    // incremental extension over the dust block. Both paths must agree on the
    // pending deposit and the named refusal.
    let mut b = NodeL2::fresh(&params).unwrap();
    b.sync(&chain).unwrap();
    mine_empty_to(&mut chain, user_addr, 5);
    let funding2: Vec<_> = mature_outpoints(&chain, user_addr);
    let dust_tx = deposit_tx(&chain, &user, funding2[0].0, funding2[0].1, 500_000);
    mine_with_body(&mut chain, user_addr, vec![dust_tx]);
    let inc_report = b.sync(&chain).unwrap();
    assert!(matches!(
        inc_report.outcome,
        SyncOutcome::Incremental { .. }
    ));

    let a = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(a.state(), b.state());
    assert_eq!(a.pending_deposits(), b.pending_deposits());
    assert_eq!(a.ignored_deposits(), b.ignored_deposits());
    assert_eq!(a.deposits_applied_count(), b.deposits_applied_count());
    assert_eq!(a.state().deposited_total(), b.state().deposited_total());
    // The recent dust is ignored; the older deposit is still pending here
    // (tip 11+1+5+1 = 18 < 12+20): one pending, one ignored, none applied.
    assert_eq!(a.deposits_applied_count(), 0);
    assert_eq!(a.pending_deposits().len(), 1);
    assert_eq!(a.ignored_deposits().len(), 1);
    assert!(a.state().check_conservation());
}

#[test]
fn joint_supply_holds_with_live_deposits() {
    // The STEP 8 attack goal with deposits in play: L1 live + L2 held − sink
    // stays under the cap, and the sink holds exactly what was deposited.
    let params = NetworkParams::mini();
    let user = wallet(72);
    let user_addr = user.address().unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, user_addr, 11);
    let (op, op_value) = mature_outpoints(&chain, user_addr)[0];
    let tx = deposit_tx(&chain, &user, op, op_value, DEPOSIT_SAT);
    mine_with_body(&mut chain, user_addr, vec![tx]);
    mine_empty_to(&mut chain, user_addr, params.finality_depth);
    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.deposits_applied_count(), 1);

    let sink_held: u64 = chain
        .utxo()
        .outputs_for_address(&sink_of(&params))
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(sink_held, DEPOSIT_SAT);
    let joint = chain
        .utxo()
        .total_value()
        .saturating_add(view.state().conservation_total())
        .saturating_sub(sink_held);
    assert!(
        joint
            <= jnt_core::supply::cumulative_issuance_sat(&params, chain.height())
                .saturating_add(params.escrow_ceiling_sat),
        "joint supply {joint} exceeds the joint bound"
    );
    // Without the sink term this chain would already read as inflation —
    // which is why M2's joint check grew the term rather than breaking.
    assert!(chain.utxo().total_value() + view.state().conservation_total() > joint);
}
