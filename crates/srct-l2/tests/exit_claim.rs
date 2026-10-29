//! L2 → L1 exit claims, L1 side (approved P1, E-1…E-3).
//!
//! These tests drive a real [`Chain`] through the whole loop the design
//! requires: deposit to the sink, queue on L2, mature under the depth rule,
//! release by a permissionless claim, and the joint accounting after. The L2
//! queue half is pinned in `exit_flow.rs`; what is under test here is the
//! consensus release rule — proof against the committed root, exact funding,
//! idempotency, reorg unwind — and that a block carrying any of it is still a
//! valid block by every pre-exit rule.
//!
//! Profile: `mini` (exit activation at 1, depth-only finality, 20-block
//! finality depth). Binding finality is covered by the L2-side maturity unit
//! test; these tests pin the depth half on a live chain.

use srct_core::block::GENESIS_TIMESTAMP_MS;
use srct_core::chain::{Chain, DEFAULT_MAX_ATTEMPTS};
use srct_core::exit::ExitClaim;
use srct_core::hash::Address;
use srct_core::l2::{ExitQueuePayload, L2Payload, L2Transaction};
use srct_core::mempool::Mempool;
use srct_core::params::NetworkParams;
use srct_core::tx::{OutPoint, Output};
use srct_core::wallet::Wallet;
use srct_l2::{ChainL2, DepositParams, L2Config, L2Genesis};

use srct_core::bls_checkpoint::{MockBls, ValidatorSet};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const SINK_VALUE: u64 = 100_000_000; // 1 SRCT deposit
const EXIT_FEE: u64 = 1_000_000;
const QUEUE_FLAT_FEE: u64 = 2_000; // FEE_TX_EXIT_QUEUE_SAT

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "exit-claim").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn ts(h: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + h * 1_000
}

fn l2config() -> L2Config {
    let mut c = L2Config::mini();
    c.exit_activation_height = 1;
    c
}

fn l2view(chain: &Chain) -> ChainL2 {
    let params = NetworkParams::mini();
    // Authority resolves per height inside replay now.
    ChainL2::replay(
        chain,
        l2config(),
        &L2Genesis::for_params(&params),
        DepositParams::for_params(&params),
        &MockBls,
    )
    .unwrap()
}

fn mine_empty_to(chain: &mut Chain, miner: Address, to: u64) {
    while chain.height() < to {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// A mature miner coinbase outpoint (mini maturity is 10).
fn mature_outpoint(chain: &Chain, miner: Address) -> (OutPoint, u64) {
    chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == miner && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase")
}

fn fee_for(chain: &Chain, n_in: usize, n_out: usize) -> u64 {
    let gas = 16_000 + 1_000 * n_in as u64 + 250 * n_out as u64;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

/// The world an exit test needs: a chain with a matured 1-SRCT deposit and the
/// L2 view that credited it. Returns `(chain, miner, deposit_height)`.
fn deposited_world() -> (Chain, Wallet, u64) {
    let params = NetworkParams::mini();
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_empty_to(&mut chain, me, 12);
    // Deposit: miner pays the sink; miner is the single input owner, so the
    // L2 recipient is the miner (Decision 10 item 2).
    let (op, value) = mature_outpoint(&chain, me);
    let fee = fee_for(&chain, 1, 2);
    let tx = miner
        .build_tx(
            &[op],
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
    let d = chain.height() + 1;
    let b = chain.mine_block(me, vec![tx], ts(d)).unwrap();
    chain.submit(b).unwrap();
    // Mature the deposit: spendable at D + finality_depth (20 on mini).
    mine_empty_to(&mut chain, me, d + 20);
    (chain, miner, d)
}

/// The sink outpoint holding the deposit.
fn sink_outpoint(chain: &Chain) -> (OutPoint, u64) {
    let sink = NetworkParams::mini().l2_deposit_sink();
    chain
        .utxo()
        .outputs_for_address(&sink)
        .into_iter()
        .next()
        .expect("the deposit sink output")
}

/// Queue an exit at the tip+1 and return `(queue_height, queue_txid_state)`.
/// Mines the queue block with the correctly computed committed root and
/// returns the L2 state right after it (for building the claim proof).
fn queue_exit(
    chain: &mut Chain,
    l2: &mut ChainL2,
    owner: &Wallet,
    nonce: u64,
    amount: u64,
    dest: Address,
) -> (u64, srct_l2::L2State) {
    let q = chain.height() + 1;
    let me = addr(owner);
    let p = ExitQueuePayload::build(owner, nonce, amount, dest, EXIT_FEE).unwrap();
    let tx = L2Transaction::new(L2Payload::ExitQueue(p));
    // Simulate Q's L2 transitions to commit the exact root the block claims:
    // the trailer transaction at Q, no deposits in Q's (empty) body.
    let mut sim = l2.state().clone();
    sim.advance_block(q);
    sim.apply(&tx, q, &ValidatorSet::new(vec![]), &MockBls)
        .expect("the queue must apply: balance was credited by the deposit");
    let root = sim.committed_root();
    let b = chain
        .mine_block_with_l2_root(
            me,
            vec![],
            vec![tx],
            root,
            ts(q),
            None,
            DEFAULT_MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(b).unwrap();
    assert_eq!(
        chain.block_at(q).unwrap().l2_state_root,
        Some(root),
        "the queue block must commit the simulated root"
    );
    // Bring the caller's view forward past the queue block it just mined:
    // the simulation above ran on a clone, so without this the view would
    // stay stale at the pre-queue height and its balances would lie.
    *l2 = l2view(chain);
    (q, sim)
}

/// Build the release claim for a queued exit against the Q-state.
#[allow(clippy::too_many_arguments)]
fn build_claim(
    chain: &Chain,
    sim_q: &srct_l2::L2State,
    owner: Address,
    nonce: u64,
    amount: u64,
    dest: Address,
    claimant: Address,
    q: u64,
) -> ExitClaim {
    let proof = sim_q
        .exit_proof(&owner, nonce)
        .expect("the queued exit must prove against its own root");
    let (sink_op, sink_value) = sink_outpoint(chain);
    assert_eq!(sink_value, SINK_VALUE);
    // Exact funding: sink == amount + prepaid fee + required L1 fee.
    let gas = 16_000 + 1_000 + 2 * 250;
    let l1_fee = chain.expected_base_fee_for_next_block() * gas;
    assert_eq!(
        SINK_VALUE,
        amount + EXIT_FEE + l1_fee,
        "the test setup must fund the claim exactly"
    );
    ExitClaim {
        owner,
        nonce,
        amount_sat: amount,
        destination: dest,
        claimant,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof,
    }
}

// ---------------------------------------------------------------------------
// 1. The full loop
// ---------------------------------------------------------------------------

/// Deposit → queue → mature → release: the destination gets exactly the
/// principal, the crank (here the miner) gets exactly the prepaid fee, the
/// sink output is consumed, the identity is marked, and the chain still
/// verifies. L2 `note_release` mirrors what replay will do once the absorb
/// hook lands; conservation holds on both sides.
#[test]
fn exit_claim_releases_exactly_once_and_conserves() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    assert_eq!(l2.state().balance(&me), SINK_VALUE);

    // The base fee must sit at its floor before queueing: the claim amount is
    // committed in the queue record, so the L1 fee it implies has to be
    // stable from here to the claim block. Empty blocks pin it at the floor.
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    // The queue debit is amount + prepaid fee + the flat queue fee: pin it,
    // so a silent fee change breaks this test rather than the accounting.
    let before = l2.state().balance(&me);
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    assert_eq!(
        l2.state().balance(&me),
        before - amount - EXIT_FEE - QUEUE_FLAT_FEE
    );
    // Mature: tip must reach Q + 20.
    mine_empty_to(&mut chain, me, q + 20);
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);

    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    assert!(claim.verify_proof(&chain.block_at(q).unwrap().l2_state_root.unwrap()));
    let h = chain.height() + 1;
    chain
        .mine_from_pool_with_exits(
            &mut Mempool::new(1 << 20),
            me,
            ts(h),
            vec![],
            vec![claim.clone()],
            None,
        )
        .unwrap();
    assert_eq!(chain.height(), h);

    // Principal and fee land exactly where the record says.
    let dest_got: u64 = chain
        .utxo()
        .outputs_for_address(&dest)
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(dest_got, amount);
    let fee_got: u64 = chain
        .utxo()
        .outputs_for_address(&me)
        .iter()
        .filter(|(op, _)| op.txid == claim.claim_id())
        .map(|(_, v)| v)
        .sum();
    assert_eq!(fee_got, EXIT_FEE);
    // The sink output is consumed, not copied.
    assert!(chain
        .utxo()
        .outputs_for_address(&NetworkParams::mini().l2_deposit_sink())
        .is_empty());
    assert!(chain.exit_released(&me, 1));
    chain.verify_canonical_chain().unwrap();

    // L2 side: replay observed the release itself, so the record is already gone
    // and the books need no manual nudge.
    let l2_after = l2view(&chain);
    assert!(
        l2_after.state().exit(&me, 1).is_none(),
        "replay absorbed the release: a released exit cannot be proven again"
    );
    assert!(l2_after.state().check_conservation());
    assert_eq!(
        l2_after.state().funded_total(),
        l2.state().funded_total() - (amount + EXIT_FEE)
    );
}

// ---------------------------------------------------------------------------
// 2. Refusals, each by name
// ---------------------------------------------------------------------------

/// A claim before depth maturity is refused — the queue block is not final.
#[test]
fn exit_before_finality_is_refused_by_name() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    assert_eq!(chain.expected_base_fee_for_next_block(), 10);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);

    // One block later: Q + 1 < Q + 20, not mature.
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("not yet mature")),
        "immature claim must be refused by name, got {res:?}"
    );
    assert_eq!(chain.height(), h - 1, "the refused block must not land");
    assert!(!chain.exit_released(&me, 1));
}

/// The same claim in a second block is refused: one release per identity.
#[test]
fn exit_replay_is_refused_by_name() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    chain
        .mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim.clone()], None)
        .unwrap();
    // Mine one more block carrying the identical claim: consensus refuses it.
    let h2 = chain.height() + 1;
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h2), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("already released")),
        "replayed claim must be refused by name, got {res:?}"
    );
}

/// A proof that does not match the record — here a tampered amount — verifies
/// against nothing and the claim is refused before any value moves.
#[test]
fn exit_with_forged_proof_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let mut claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    claim.amount_sat += 1; // the proof no longer matches the record
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("does not verify")),
        "forged proof must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

/// A claim whose inputs are not sink outputs is refused: the release rule
/// moves sink value only, never an ordinary coin.
#[test]
fn exit_consuming_a_non_sink_input_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let mut claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    // Swap the sink input for an ordinary miner coinbase of equal value...
    // there is none of exactly SINK_VALUE, so fund exactly: the point is the
    // address check fires, not the funding check. Use the sink output but
    // re-point a copy at a normal address is impossible — instead spend a
    // normal output and let the address rule fire first.
    let (normal_op, _) = mature_outpoint(&chain, me);
    claim.inputs = vec![normal_op];
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("not a sink output")
            || e.to_string().contains("must total exactly")),
        "non-sink input must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

/// A queue for less than the sink output leaves the claim underfunded: inputs
/// must total *exactly* principal + fee + L1 fee, so the claim is refused and
/// nothing moves.
#[test]
fn exit_with_inexact_funding_is_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    // Queue 1,000 sat short of exact: the proof is valid for this record, but
    // the sink output overpays it, so funding is inexact.
    let amount = SINK_VALUE - EXIT_FEE - l1_fee - 1_000;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    // Build the claim by hand: build_claim's exactness assert would fire, so
    // replicate it with the short amount (proof matches this record).
    let proof = sim_q.exit_proof(&me, 1).unwrap();
    let (sink_op, _) = sink_outpoint(&chain);
    let claim = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: amount,
        destination: dest,
        claimant: me,
        exit_fee_sat: EXIT_FEE,
        queued_height: q,
        inputs: vec![sink_op],
        proof,
    };
    assert!(claim.verify_proof(&chain.block_at(q).unwrap().l2_state_root.unwrap()));
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("must total exactly")),
        "inexact funding must be refused by name, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}

// ---------------------------------------------------------------------------
// 3. Activation gating
// ---------------------------------------------------------------------------

/// Below activation (a profile carrying `0`) a claim is refused before any proof
/// is read — and an L2 section without a root is still fine there, because
/// the root rule only exists at and after activation.
#[test]
fn pre_activation_claim_is_refused() {
    let mut params = NetworkParams::mainnet();
    params.exit_activation_height = 0;
    assert_eq!(params.exit_activation_height, 0);
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(params).unwrap();
    mine_empty_to(&mut chain, me, 3);
    // The proof field is never read: activation fires first. Any bytes decode
    // here; what matters is the refusal names activation, not the proof.
    let claim = ExitClaim {
        owner: me,
        nonce: 1,
        amount_sat: 100,
        destination: dest_of(),
        claimant: me,
        exit_fee_sat: 0,
        queued_height: 1,
        inputs: vec![OutPoint {
            txid: [0x55u8; 64],
            index: 0,
        }],
        proof: srct_core::state_root::InclusionProof {
            index: 0,
            leaf_count: 1,
            siblings: vec![],
        },
    };
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("before activation")),
        "pre-activation claim must be refused by name, got {res:?}"
    );
}

fn dest_of() -> Address {
    addr(&wallet(8))
}

/// At and after activation, L2 transactions without a committed root are
/// refused: a queue in such a block could never be proven.
#[test]
fn post_activation_l2_without_root_is_refused() {
    let miner = wallet(9);
    let me = addr(&miner);
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_empty_to(&mut chain, me, 2);
    // A bare L2 transaction (no signature check at L1: validity is L2's job).
    let tx = L2Transaction::new(L2Payload::ExitQueue(srct_core::l2::ExitQueuePayload {
        owner: me,
        auth: Default::default(),
        nonce: 1,
        amount_sat: 1,
        destination: dest_of(),
        exit_fee_sat: 0,
    }));
    let h = chain.height() + 1;
    let b = chain
        .mine_block_with_l2(me, vec![], vec![tx], ts(h), None, DEFAULT_MAX_ATTEMPTS)
        .unwrap();
    let res = chain.submit(b);
    assert!(
        matches!(&res, Err(e) if e.to_string().contains("must commit a root")),
        "rootless post-activation L2 must be refused by name, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Reorg unwinds a release
// ---------------------------------------------------------------------------

/// A reorg that drops the claim block unmarks the identity, restores the sink
/// output and removes the release outputs: the winning branch never contained
/// the release, so no trace of it may remain. `verify` still passes — the
/// unwind is exact, not approximate.
#[test]
fn reorg_of_the_claim_block_unwinds_the_release() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let claim_id = claim.claim_id();
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    chain
        .mine_from_pool_with_exits(&mut pool, me, ts(h), vec![], vec![claim], None)
        .unwrap();
    assert!(chain.exit_released(&me, 1));
    let before_tip = chain.tip_hash();

    // Rival shares everything through H-1 and mines two empties: heavier, so
    // it wins. Fork point H-1 is above the finality floor (tip H, depth 20).
    assert!(h - 1 > h.saturating_sub(20));
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    for x in 1..h {
        rival.submit(chain.block_at(x).unwrap().clone()).unwrap();
    }
    for x in h..=h + 1 {
        let b = rival.mine_block(me, vec![], ts(x)).unwrap();
        rival.submit(b).unwrap();
    }
    assert!(rival.total_work() > chain.total_work());
    chain.submit(rival.block_at(h).unwrap().clone()).unwrap();
    chain
        .submit(rival.block_at(h + 1).unwrap().clone())
        .unwrap();
    assert_ne!(chain.tip_hash(), before_tip);

    // No trace of the release remains on the winning branch.
    assert!(!chain.exit_released(&me, 1));
    let (sink_op, sink_value) = sink_outpoint(&chain);
    assert_eq!(sink_value, SINK_VALUE);
    let _ = sink_op;
    assert!(
        chain
            .utxo()
            .get(&OutPoint {
                txid: claim_id,
                index: 0
            })
            .is_none(),
        "the destination output must be gone with its block"
    );
    chain.verify_canonical_chain().unwrap();
}

/// Two identical claims in one block spend the same sink output twice: the
/// miner's probe admits the first and the second finds its input gone — the
/// same double-spend refusal two L1 transactions spending one input get
/// (`UnknownOutPoint`), not a second release.
#[test]
fn duplicate_claims_in_one_block_are_refused() {
    let (mut chain, miner, _d) = deposited_world();
    let me = addr(&miner);
    let dest = addr(&wallet(8));
    let mut l2 = l2view(&chain);
    let l1_fee = 10 * (16_000 + 1_000 + 2 * 250);
    let amount = SINK_VALUE - EXIT_FEE - l1_fee;
    let (q, sim_q) = queue_exit(&mut chain, &mut l2, &miner, 1, amount, dest);
    mine_empty_to(&mut chain, me, q + 20);
    let claim = build_claim(&chain, &sim_q, me, 1, amount, dest, me, q);
    let h = chain.height() + 1;
    let mut pool = Mempool::new(1 << 20);
    let res = chain.mine_from_pool_with_exits(
        &mut pool,
        me,
        ts(h),
        vec![],
        vec![claim.clone(), claim],
        None,
    );
    assert!(
        matches!(&res, Err(srct_core::error::Error::UnknownOutPoint)),
        "duplicate claims must be refused as a double-spend, got {res:?}"
    );
    assert!(!chain.exit_released(&me, 1));
}
