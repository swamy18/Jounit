//! L2-in-the-block-pipeline integration tests — Decision 6, SPEC.md §19.1.
//!
//! What these cover: L2 transactions carried inside real, mined L1 blocks, and
//! the L2 state that replaying that chain produces. What they deliberately do
//! **not** cover: funded L2 accounts, because there is no L1→L2 funding bridge
//! yet (Decision 7 funds it in the next milestone). With no bridge, every L2
//! transaction in a replayed chain is refused for insufficient balance — and the
//! tests assert that refusal is *deterministic*, named and identical on every
//! replay, rather than pretending the marketplace works before it is funded.

use srct_core::bls_checkpoint::{MockBls, ValidatorSet};
use srct_core::chain::Chain;
use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use srct_core::params::NetworkParams;
use srct_core::wallet::Wallet;
use srct_core::Address;

use srct_l2::{ChainL2, DepositParams, L2Config, L2Error, L2Genesis, L2State};

const MAX_ATTEMPTS: u64 = 4_000_000;

fn addr(tag: u8) -> Address {
    [tag; 20]
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "replay-test").unwrap()
}

fn ts(height: u64) -> u64 {
    // One second per block: the mini profile targets 1000 ms.
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn task(nonce: u64, deadline: u64) -> ComputeTask {
    // The nonce is folded into the id so each height posts a distinct task;
    // nothing else about the task varies.
    let mut task_id = [0x11u8; 32];
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

/// A post-task transaction signed by `seed`.
fn post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, 5_000_000, deadline, task(nonce, deadline)).unwrap(),
    ))
}

/// Mine and submit `n` blocks; the block at each height in `l2_at` carries one
/// L2 post.
///
/// Mining only *builds* a block — submission is a separate step — so both calls
/// are needed for these to become canonical history.
///
/// Every L2-bearing block commits the root a replay derives (approved P1):
/// a scratch L2 view advances alongside mining, applying each trailer
/// transaction exactly as replay does — including skipping the unfunded posts
/// (this file's whole point is unfunded behaviour), so the committed root is
/// the skipped outcome replay recomputes.
fn chain_with_l2(l2_at: &[u64], n: u64) -> Chain {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let (set, verifier) = empty_set();
    let mut sim = L2State::new(L2Config::mini());
    for h in 1..=n {
        let l2 = if l2_at.contains(&h) {
            vec![post(1, h, 200)]
        } else {
            Vec::new()
        };
        sim.advance_block(h);
        for tx in &l2 {
            let _ = sim.apply(tx, h, &set, &verifier);
        }
        let block = if l2.is_empty() {
            chain.mine_block(addr(1), Vec::new(), ts(h)).unwrap()
        } else {
            chain
                .mine_block_with_l2_root(
                    addr(1),
                    Vec::new(),
                    l2,
                    sim.committed_root(),
                    ts(h),
                    None,
                    MAX_ATTEMPTS,
                )
                .unwrap()
        };
        chain
            .submit_at(block, Some(ts(h)))
            .expect("a block we just mined must be accepted");
    }
    assert_eq!(
        chain.height(),
        n,
        "every mined block must have been accepted"
    );
    chain
}

fn empty_set() -> (ValidatorSet, MockBls) {
    // No validators yet: the genesis committee arrives with Decision 8's
    // milestone. Nothing in these tests reaches `Settle`, which is the only
    // payload that consults the set.
    (ValidatorSet::new(Vec::new()), MockBls)
}

fn replay(chain: &Chain) -> ChainL2 {
    let (_, verifier) = empty_set();
    // Empty genesis, deliberately: these tests pin the M1 unfunded behaviour
    // (every payload refused for insufficient balance). Funded replay is
    // covered by `genesis_funding.rs` and the node integration tests.
    // Real deposit params: no test block pays the sink, so no deposit is ever
    // detected and the M1 assertions stand unchanged.
    // Authority resolves per height inside replay (Decision 28).
    let deposits = DepositParams::for_params(&NetworkParams::mini());
    ChainL2::replay(
        chain,
        L2Config::mini(),
        &L2Genesis::empty(),
        deposits,
        &verifier,
    )
    .unwrap()
}

#[test]
fn two_replays_of_the_same_chain_agree_exactly() {
    // The core Phase 6 property: L2 state is a pure function of the canonical
    // chain, so two nodes that replay it hold equal state.
    let chain = chain_with_l2(&[2, 3, 5], 6);
    let a = replay(&chain);
    let b = replay(&chain);

    assert_eq!(a.state(), b.state(), "two replays disagreed on L2 state");
    assert_eq!(a.applied_count(), b.applied_count());
    assert_eq!(a.skipped(), b.skipped());
    assert_eq!(a.height(), chain.height());
}

#[test]
fn full_replay_equals_incremental_application() {
    // The recovery path (`replay`) and the following-the-tip path
    // (`apply_block`) must not be two different state machines.
    let chain = chain_with_l2(&[1, 4], 6);
    let full = replay(&chain);

    let (_, verifier) = empty_set();
    let deposits = DepositParams::for_params(&NetworkParams::mini());
    let mut incremental = ChainL2::empty(L2Config::mini(), &L2Genesis::empty(), deposits).unwrap();
    // Evaluated at the final tip, exactly as full replay evaluates every
    // block: with no sink outputs present the tip value is moot, but the call
    // must still name the tip maturity is measured against. Authority resolves
    // per height from the chain, the same rule replay applies (Decision 28).
    let tip = chain.height();
    let binding = chain.finality().binding_finalized_height();
    for h in 1..=tip {
        let block = chain.block_at(h).unwrap();
        let set = chain.settlement_committee_at(h);
        incremental.apply_block(block, tip, binding, &set, &verifier);
    }

    assert_eq!(
        incremental.state(),
        full.state(),
        "incremental application diverged from full replay"
    );
    assert_eq!(incremental.applied_count(), full.applied_count());
    assert_eq!(incremental.height(), full.height());
    assert!(!full.is_clean());
}

#[test]
fn a_chain_with_no_l2_transactions_replays_clean() {
    let chain = chain_with_l2(&[], 4);
    let l2 = replay(&chain);

    assert_eq!(l2.applied_count(), 0);
    assert_eq!(l2.skipped().len(), 0);
    assert!(l2.is_clean());
    // Nothing was applied, so the state is the pristine one — and in particular
    // replaying an L1-only chain invents no L2 money.
    let mut pristine = L2State::new(L2Config::mini());
    pristine.apply_genesis(&L2Genesis::empty()).unwrap();
    assert_eq!(l2.state(), &pristine);
}

#[test]
fn an_unfunded_l2_transaction_is_skipped_by_name_not_silently_applied() {
    // There is no L1→L2 bridge yet (Decision 7), so a post cannot be paid for.
    // What must *not* happen is that the payload is applied anyway, or that the
    // chain is rejected — either would be a lie about the economics.
    let chain = chain_with_l2(&[2], 3);
    let l2 = replay(&chain);

    assert_eq!(l2.applied_count(), 0, "an unfunded post must not apply");
    assert_eq!(l2.skipped().len(), 1);
    let skipped = &l2.skipped()[0];
    assert_eq!(skipped.height, 2, "the skip must name the carrying block");
    assert_eq!(skipped.txid, post(1, 2, 200).txid());
    assert!(
        matches!(
            skipped.error,
            L2Error::InsufficientBalance { needed, available }
                if needed > 0 && available == 0
        ),
        "expected a named insufficient-balance refusal, got {:?}",
        skipped.error
    );
}

#[test]
fn a_skipped_transaction_stays_retryable() {
    // A rejected payload is not marked applied (SPEC.md §15.5), so the same
    // bytes could apply later once the account is funded. This is what makes
    // skipping safe rather than a silent loss.
    let chain = chain_with_l2(&[2], 2);
    let mut l2 = replay(&chain);
    assert_eq!(l2.state().applied_count(), 0);

    let tx = post(1, 2, 200);
    // Directly against the replayed state: still a first-seen transaction, so
    // the refusal is the balance precondition and not replay protection.
    let (set, verifier) = empty_set();
    let err = l2.state_mut().apply(&tx, 2, &set, &verifier).unwrap_err();
    assert!(
        matches!(err, L2Error::InsufficientBalance { .. }),
        "a skipped transaction must stay retryable, got {err:?}"
    );
}

#[test]
fn replay_is_a_function_of_the_chain_not_of_how_it_grew() {
    // Mine one chain, replay it; mine an identical chain and replay it. Nothing
    // about wall-clock time, insertion order or a hash map's iteration order may
    // leak into the result.
    let a = chain_with_l2(&[1, 3], 5);
    let b = chain_with_l2(&[1, 3], 5);

    assert_eq!(
        a.tip_hash(),
        b.tip_hash(),
        "the two chains must be identical"
    );
    let ra = replay(&a);
    let rb = replay(&b);
    assert_eq!(ra.state(), rb.state());
    assert_eq!(ra.skipped(), rb.skipped());
}

#[test]
fn l2_transactions_are_carried_and_committed_by_the_block() {
    // The property the whole design rests on: the block really does carry the
    // payload, and its header really does commit to it.
    let chain = chain_with_l2(&[4], 4);
    let block = chain.block_at(4).unwrap();

    assert_eq!(block.l2_count(), 1, "block 4 must carry its L2 payload");
    assert_eq!(
        block.header.merkle_root,
        block.merkle_root(),
        "the header must commit to the L2 payload"
    );
    assert_eq!(chain.block_at(3).unwrap().l2_count(), 0);
}
