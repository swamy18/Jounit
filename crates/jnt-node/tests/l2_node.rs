//! Node-side L2 integration tests — M1, SPEC.md §19.1.
//!
//! These drive the production path: real mined blocks through `Chain::submit`,
//! with the node's [`NodeL2`](jnt_node::l2::NodeL2) view following the tip. What
//! they pin:
//!
//! - the accepted-block flow replays L2 (no second execution path);
//! - a rejected L1 block never mutates L2 state;
//! - L2 failures follow skip semantics (chain accepted, payload named, no
//!   partial mutation);
//! - restart and reorg reconstruct deterministically by replay;
//! - the unfunded-ledger behaviour (Decision 7 not yet built) is preserved,
//!   not worked around.
//!
//! There is no funding bridge yet, so a well-formed payload replays to an
//! `InsufficientBalance` skip. That is the expected M1 behaviour and these
//! tests assert it by name rather than treating it as a failure.

use std::sync::atomic::{AtomicU64, Ordering};

use jnt_core::block::Block;
use jnt_core::chain::Chain;
use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::hash_to_hex;
use jnt_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload, Verdict,
};
use jnt_core::params::NetworkParams;
use jnt_core::wallet::Wallet;
use jnt_core::Address;
use jnt_l2::{L2Config, L2Error};
use jnt_node::l2::{NodeL2, SyncOutcome};
use jnt_store::BlockStore;

const MAX_ATTEMPTS: u64 = 4_000_000;

fn addr(tag: u8) -> Address {
    [tag; 20]
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "node-l2-test").unwrap()
}

fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn task(nonce: u64, deadline: u64) -> ComputeTask {
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

/// A well-formed post signed by `seed`. Well-formed but unfunded: no
/// production path credits L2 accounts yet (Decision 7), so replay refuses it
/// with `InsufficientBalance` — asserted by name wherever it matters.
fn post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, 5_000_000, deadline, task(nonce, deadline)).unwrap(),
    ))
}

/// A post whose signature no longer matches its body. Authorization is checked
/// before balances, so this fails as `BadAuthorization` even on an empty
/// ledger — the only named refusal reachable without funding.
fn bad_auth_post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let mut tx = post(seed, nonce, deadline);
    let L2Payload::Post(ref mut p) = tx.payload else {
        unreachable!("post() builds a Post");
    };
    p.payment_sat += 1;
    tx
}

fn claim_unknown_task(seed: u8) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Claim(
        ClaimTaskPayload::build(&w, [0xABu8; 32], ComputeBackend::Cpu, 1_000).unwrap(),
    ))
}

/// A quorum settlement against the M1 empty validator set. No aggregate can
/// verify with no signers, so this is refused deterministically (`BadQuorum`
/// or `BadBlsSignature` depending on which check fires first) — never applied
/// without authority.
fn settle_no_quorum() -> L2Transaction {
    L2Transaction::new(L2Payload::Settle(SettlePayload {
        task_id: [0x77u8; 32],
        verdict: Verdict::Correct,
        vwc_hash: [0x99u8; 32],
        bls_sig: [0x01u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
    }))
}

/// Mine `l2` into the next block and submit it — the node's accepted-block
/// path in miniature. Returns the accepted block.
fn mine_and_submit(chain: &mut Chain, l2: Vec<L2Transaction>) -> Block {
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(addr(1), Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
        .expect("a block we just mined must build");
    chain.submit(block.clone()).expect("it must be accepted");
    block
}

fn is_insufficient(e: &L2Error) -> bool {
    matches!(
        e,
        L2Error::InsufficientBalance { needed, available: 0 } if *needed > 0
    )
}

// --- block with no L2 -------------------------------------------------------

#[test]
fn block_with_no_l2_syncs_clean() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let mut view = NodeL2::fresh(chain.params());
    mine_and_submit(&mut chain, Vec::new());
    mine_and_submit(&mut chain, Vec::new());

    let report = view.sync(&chain);
    assert!(matches!(
        report.outcome,
        SyncOutcome::FullReplay { blocks: 2 }
    ));
    assert_eq!(view.height(), 2);
    assert_eq!(view.applied_count(), 0);
    assert!(view.is_clean());
    assert_eq!(view.status(chain.height()).chain_height, 2);
}

// --- block with valid (well-formed, unfunded) L2 ----------------------------

#[test]
fn block_with_valid_l2_is_carried_committed_and_skipped_by_name() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let expected = post(1, 2, 200);
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(
            addr(1),
            Vec::new(),
            vec![expected.clone()],
            ts(h),
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    // The header commits to the payload: this is the M1 security boundary.
    assert_eq!(block.l2_count(), 1);
    assert_eq!(block.header.merkle_root, block.merkle_root());
    chain.submit(block).unwrap();

    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);
    // Accepted by L1, refused by L2 for the documented reason: no funding.
    assert_eq!(view.height(), 1);
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    let s = &view.skipped()[0];
    assert_eq!(s.height, 1);
    assert_eq!(s.txid, expected.txid());
    assert!(is_insufficient(&s.error), "got {:?}", s.error);
    assert!(!view.is_clean());
}

#[test]
fn block_with_multiple_l2_transactions_skips_each_by_name() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let a = post(1, 10, 200);
    let b = post(1, 11, 200);
    mine_and_submit(&mut chain, vec![a.clone(), b.clone()]);

    let mut view = NodeL2::fresh(chain.params());
    let report = view.sync(&chain);
    assert_eq!(report.skipped_new, 2);
    assert_eq!(report.applied_new, 0);
    assert_eq!(view.skipped().len(), 2);
    // Block order is preserved, so two nodes name the same refusals in the
    // same order.
    assert_eq!(view.skipped()[0].txid, a.txid());
    assert_eq!(view.skipped()[1].txid, b.txid());
    assert!(view.skipped().iter().all(|s| is_insufficient(&s.error)));
}

// --- invalid / unapplicable payloads ----------------------------------------

#[test]
fn invalid_l2_payload_is_skipped_and_the_block_is_still_accepted() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let bad = bad_auth_post(1, 5, 200);
    let block = mine_and_submit(&mut chain, vec![bad.clone()]);
    assert_eq!(block.l2_count(), 1, "miner carries what it is given");

    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);
    assert_eq!(chain.height(), 1);
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    assert_eq!(
        view.skipped()[0].error,
        L2Error::BadAuthorization,
        "authorization is checked before balances"
    );
}

#[test]
fn settle_without_quorum_is_skipped_and_never_applied() {
    // Empty validator set (Decision 8 arrives with M4) + production verifier:
    // fail closed with a named refusal.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![settle_no_quorum()]);

    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);
    assert_eq!(chain.height(), 1);
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    assert!(
        matches!(
            view.skipped()[0].error,
            L2Error::BadQuorum | L2Error::BadBlsSignature
        ),
        "got {:?}",
        view.skipped()[0].error
    );
}

// --- malformed / stripped / modified trailers -------------------------------

#[test]
fn malformed_l2_trailer_never_decodes_so_it_never_reaches_submit() {
    // A present-but-empty section is a second encoding of a block that
    // serializes without one, and is refused at decode (SPEC §19.1).
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, Vec::new());
    let block = chain.block_at(1).unwrap();
    let mut bytes = block.serialize();
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let err = Block::deserialize(&bytes).unwrap_err();
    assert!(format!("{err}").contains("empty L2 section"), "got {err}");
    // And the untouched block still round-trips: the rule rejects the second
    // encoding, not L2 blocks.
    assert_eq!(Block::deserialize(&block.serialize()).unwrap(), *block);
}

#[test]
fn stripped_l2_trailer_is_rejected_and_l2_state_is_untouched() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let carried = post(1, 2, 200);
    mine_and_submit(&mut chain, vec![carried]);
    let before = NodeL2::replay_from(&chain, chain.params());

    // Strip the trailer but keep the header: the committed root no longer
    // matches, so the existing L1 rule refuses it — no new consensus code.
    let mut stripped = chain.block_at(1).unwrap().clone();
    stripped.l2_txs.clear();
    assert_ne!(
        stripped.header.merkle_root,
        stripped.merkle_root(),
        "stripping must break the commitment"
    );
    assert!(chain.submit(stripped).is_err());

    // The failed submit moved no tip, so a sync is a no-op by construction.
    let mut view = NodeL2::replay_from(&chain, chain.params());
    let report = view.sync(&chain);
    assert_eq!(report.outcome, SyncOutcome::Unchanged);
    assert_eq!(view.state(), before.state());
    assert_eq!(view.skipped(), before.skipped());
}

#[test]
fn modified_l2_payload_is_rejected_and_l2_state_is_untouched() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 2, 200)]);
    let skipped_before = NodeL2::replay_from(&chain, chain.params());

    let mut tampered = chain.block_at(1).unwrap().clone();
    let L2Payload::Post(ref mut p) = tampered.l2_txs[0].payload else {
        panic!("expected a Post payload");
    };
    p.payment_sat += 1;
    assert!(chain.submit(tampered).is_err());

    let mut view = NodeL2::replay_from(&chain, chain.params());
    assert_eq!(view.sync(&chain).outcome, SyncOutcome::Unchanged);
    assert_eq!(view.state(), skipped_before.state());
}

// --- replay -----------------------------------------------------------------

#[test]
fn replaying_the_same_tip_is_a_noop() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 2, 200)]);
    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);
    let applied = view.applied_count();
    let skipped = view.skipped().len();

    // `ChainL2::apply_block` itself is not idempotent — the wrapper's tip
    // cursor is what makes re-sync safe. Call it twice more.
    assert_eq!(view.sync(&chain).outcome, SyncOutcome::Unchanged);
    assert_eq!(view.sync(&chain).outcome, SyncOutcome::Unchanged);
    assert_eq!(view.applied_count(), applied);
    assert_eq!(view.skipped().len(), skipped);
    assert_eq!(view.height(), 1);
}

#[test]
fn sequential_blocks_advance_incrementally() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let mut view = NodeL2::fresh(chain.params());
    mine_and_submit(&mut chain, vec![post(1, 1, 200)]);
    let first = view.sync(&chain);
    assert!(matches!(first.outcome, SyncOutcome::FullReplay { .. }));

    mine_and_submit(&mut chain, vec![post(1, 2, 200)]);
    mine_and_submit(&mut chain, Vec::new());
    let second = view.sync(&chain);
    assert_eq!(second.outcome, SyncOutcome::Incremental { blocks: 2 });
    assert_eq!(second.from_height, 1);
    assert_eq!(second.to_height, 3);
    assert_eq!(view.height(), 3);
    assert_eq!(view.skipped().len(), 2);
    // Incremental and full replay are the same state machine: assert it here,
    // at the node level, not just in `jnt-l2`.
    let full = NodeL2::replay_from(&chain, chain.params());
    assert_eq!(view.state(), full.state());
    assert_eq!(view.skipped(), full.skipped());
}

#[test]
fn deterministic_reconstruction_two_views_agree_exactly() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=4u64 {
        let l2 = if h % 2 == 0 {
            vec![post(1, h, 200)]
        } else {
            Vec::new()
        };
        mine_and_submit(&mut chain, l2);
    }
    let a = NodeL2::replay_from(&chain, chain.params());
    let b = NodeL2::replay_from(&chain, chain.params());
    assert_eq!(a.state(), b.state());
    assert_eq!(a.skipped(), b.skipped());
    assert_eq!(a.applied_count(), b.applied_count());

    let mut inc = NodeL2::fresh(chain.params());
    inc.sync(&chain);
    assert_eq!(inc.state(), a.state());
}

// --- restart / recovery through the real store ------------------------------

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store_dir() -> std::path::PathBuf {
    let id = STORE_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("jnt-node-l2-test-{}-{id}", std::process::id()))
}

/// Persist every canonical block the way `jnt-node` does (append + tip +
/// sync), then drop everything and rebuild the chain from the store alone.
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
        let block = bs
            .block_at_height(h)
            .unwrap()
            .unwrap_or_else(|| panic!("store lost block at height {h}"));
        chain.submit(block).unwrap();
    }
    chain
}

#[test]
fn restart_reconstructs_identical_l2_state_from_persisted_blocks() {
    let dir = temp_store_dir();
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 1, 200)]);
    mine_and_submit(&mut chain, Vec::new());
    mine_and_submit(&mut chain, vec![post(1, 3, 200), bad_auth_post(1, 4, 200)]);
    let live = NodeL2::replay_from(&chain, &params);
    persist_chain(&chain, &dir);

    // Shutdown: drop chain and view. Restart: rebuild from the store only.
    drop(chain);
    drop(live);
    let chain2 = reload_chain(&dir, &params);
    let recovered = NodeL2::replay_from(&chain2, &params);

    let chain3 = reload_chain(&dir, &params);
    let live_again = NodeL2::replay_from(&chain3, &params);
    assert_eq!(recovered.state(), live_again.state());
    assert_eq!(recovered.skipped(), live_again.skipped());
    assert_eq!(recovered.applied_count(), live_again.applied_count());
    assert_eq!(recovered.height(), 3);
    assert_eq!(recovered.skipped().len(), 3);
    assert!(recovered
        .skipped()
        .iter()
        .any(|s| is_insufficient(&s.error)));
    assert!(recovered
        .skipped()
        .iter()
        .any(|s| s.error == L2Error::BadAuthorization));

    std::fs::remove_dir_all(&dir).ok();
}

// --- failure behaviour ------------------------------------------------------

#[test]
fn l1_invalid_block_does_not_mutate_l2_state() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 1, 200)]);
    let mut view = NodeL2::replay_from(&chain, chain.params());

    // A duplicate is already known: rejected before any state moves.
    let dup = chain.block_at(1).unwrap().clone();
    assert!(chain.submit(dup).is_err());
    // A block with no known parent is rejected too.
    let mut orphan = chain.block_at(1).unwrap().clone();
    orphan.header.prev_hash = [0xEEu8; 32];
    assert!(chain.submit(orphan).is_err());

    assert_eq!(view.sync(&chain).outcome, SyncOutcome::Unchanged);
    assert_eq!(view.height(), 1);
    assert_eq!(view.skipped().len(), 1);
}

#[test]
fn l2_failure_leaves_no_partial_state_behind() {
    // One block, two failing payloads. Both must be named, nothing applies,
    // and the resulting state must equal a chain that never carried L2 at all
    // (same heights, so the same clock) — i.e. the failures wrote nothing.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(
        &mut chain,
        vec![bad_auth_post(1, 9, 200), settle_no_quorum()],
    );

    let mut plain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut plain, Vec::new());
    assert_ne!(plain.tip_hash(), chain.tip_hash());

    let view = NodeL2::replay_from(&chain, chain.params());
    let clean = NodeL2::replay_from(&plain, plain.params());
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 2);
    assert_eq!(
        view.skipped()[0].error,
        L2Error::BadAuthorization,
        "first failure keeps its own name"
    );
    assert!(
        matches!(
            view.skipped()[1].error,
            L2Error::BadQuorum | L2Error::BadBlsSignature
        ),
        "second failure keeps its own name"
    );
    assert_eq!(
        view.state(),
        clean.state(),
        "failed payloads must write nothing: state equals the L2-free chain"
    );
}

// --- reorg ------------------------------------------------------------------

#[test]
fn reorg_replays_the_winning_chain_with_no_silent_divergence() {
    // Canonical: h1..h3 carrying posts (miner 1). The view follows it.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    for h in 1..=3u64 {
        mine_and_submit(&mut chain, vec![post(1, h, 200)]);
    }
    let mut view = NodeL2::replay_from(&chain, chain.params());
    let main_skipped: Vec<_> = view.skipped().to_vec();
    assert_eq!(main_skipped.len(), 3);

    // Rival: a separate chain forking genesis (its h1 already differs by
    // miner), h1..h4 with different L2 content. Longer at equal difficulty =
    // heavier = wins fork choice, and the fork point (genesis, common index
    // 1) is above finalized height 0, so the reorg is legal.
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    let mut rival_blocks = Vec::new();
    for h in 1..=4u64 {
        let l2 = if h == 2 {
            vec![bad_auth_post(9, 42, 200)]
        } else {
            Vec::new()
        };
        let rb = rival
            .mine_block_with_l2(addr(2), Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
            .unwrap();
        rival.submit(rb.clone()).unwrap();
        rival_blocks.push(rb);
    }
    assert_ne!(
        rival_blocks[0].block_hash(),
        chain.block_at(1).unwrap().block_hash(),
        "the rival must genuinely fork, or this test proves nothing"
    );
    assert!(
        rival.total_work() > chain.total_work(),
        "the rival must be heavier for the reorg to happen"
    );
    for rb in &rival_blocks {
        chain.submit(rb.clone()).unwrap();
    }

    assert_eq!(chain.height(), 4);
    assert_eq!(chain.tip_hash(), rival_blocks[3].block_hash());
    let report = view.sync(&chain);
    assert!(
        matches!(report.outcome, SyncOutcome::FullReplay { .. }),
        "a rewritten prefix must replay, never extend, got {:?}",
        report.outcome
    );
    // The view is exactly the winning chain's replay — nothing of the old
    // branch survives, nothing is silently kept.
    let fresh = NodeL2::replay_from(&chain, chain.params());
    assert_eq!(view.state(), fresh.state());
    assert_eq!(view.skipped(), fresh.skipped());
    assert_eq!(report.skipped_total, 1);
    assert_eq!(report.applied_total, 0);
    assert!(
        !view.skipped().iter().any(|s| main_skipped.contains(s)),
        "losing-branch payloads must be gone after the reorg"
    );
    assert_eq!(view.skipped().len(), 1);
    assert_eq!(view.skipped()[0].error, L2Error::BadAuthorization);
}

// --- funding seam (Decision 7 not built) -------------------------------------

#[test]
fn credit_seam_still_funds_and_replay_still_derives() {
    // The two halves of the M1 contract: `credit` (the bridge seam) makes a
    // payload applicable, and replay derives state from blocks alone — so a
    // restart deterministically returns to the unfunded skip.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![post(3, 1, 200)]);
    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);
    assert_eq!(view.skipped().len(), 1);

    // Fund the submitter through the seam and apply the same bytes directly:
    // retryable means applicable once the precondition holds.
    let funded_post = post(3, 1, 200);
    let actor = match &funded_post.payload {
        L2Payload::Post(p) => p.submitter,
        _ => unreachable!(),
    };
    view.state_mut().credit(actor, 10_000_000).unwrap();
    let (set, verifier) = (
        jnt_core::bls_checkpoint::ValidatorSet::new(Vec::new()),
        jnt_core::bls_checkpoint::MockBls,
    );
    view.state_mut()
        .apply(&funded_post, 1, &set, &verifier)
        .expect("a funded post must apply");
    assert!(view
        .state()
        .task(&funded_post_task_id(&funded_post))
        .is_some());

    // Restart: replay derives from blocks only, so the funding is gone and the
    // skip is back — deterministically, not as corruption.
    let again = NodeL2::replay_from(&chain, chain.params());
    assert_eq!(again.applied_count(), 0);
    assert_eq!(again.skipped().len(), 1);
    assert!(is_insufficient(&again.skipped()[0].error));
}

fn funded_post_task_id(tx: &L2Transaction) -> [u8; 32] {
    match &tx.payload {
        L2Payload::Post(p) => p.task_id,
        _ => unreachable!(),
    }
}

#[test]
fn funded_claim_for_unknown_task_is_skipped_without_partial_write() {
    // A funded worker claiming a task that was never posted: the balance check
    // passes, so the refusal names the missing precondition (`UnknownTask`).
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, Vec::new());
    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);

    let claim = claim_unknown_task(5);
    let worker = match &claim.payload {
        L2Payload::Claim(p) => p.worker,
        _ => unreachable!(),
    };
    view.state_mut().credit(worker, 10_000_000).unwrap();
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(
            addr(1),
            Vec::new(),
            vec![claim.clone()],
            ts(h),
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(block).unwrap();
    let report = view.sync(&chain);
    assert_eq!(report.outcome, SyncOutcome::Incremental { blocks: 1 });
    assert_eq!(view.skipped().len(), 1);
    assert_eq!(view.skipped()[0].error, L2Error::UnknownTask);
    assert_eq!(view.skipped()[0].txid, claim.txid());
    assert_eq!(view.applied_count(), 0);
}

#[test]
fn funded_post_applies_through_incremental_sync() {
    // The valid path through the real node flow: fund via the seam, mine a
    // block carrying the post, sync incrementally — it applies.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, Vec::new());
    let mut view = NodeL2::fresh(chain.params());
    view.sync(&chain);

    let tx = post(4, 1, 200);
    let actor = match &tx.payload {
        L2Payload::Post(p) => p.submitter,
        _ => unreachable!(),
    };
    view.state_mut().credit(actor, 10_000_000).unwrap();
    let h = chain.height() + 1;
    let block = chain
        .mine_block_with_l2(
            addr(1),
            Vec::new(),
            vec![tx.clone()],
            ts(h),
            None,
            MAX_ATTEMPTS,
        )
        .unwrap();
    chain.submit(block).unwrap();
    let report = view.sync(&chain);
    assert_eq!(report.outcome, SyncOutcome::Incremental { blocks: 1 });
    assert_eq!(report.applied_new, 1);
    assert_eq!(view.applied_count(), 1);
    assert!(view.is_clean());
    assert!(view.state().task(&funded_post_task_id(&tx)).is_some());
}

#[test]
fn l2_config_follows_the_network_profile() {
    assert_eq!(
        jnt_node::l2::config_for(&NetworkParams::mini()),
        L2Config::mini()
    );
    assert_eq!(
        jnt_node::l2::config_for(&NetworkParams::mainnet()),
        L2Config::mainnet()
    );
}

#[test]
fn node_reports_enough_to_verify_processing_happened() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    mine_and_submit(&mut chain, vec![post(1, 1, 200)]);
    mine_and_submit(&mut chain, Vec::new());
    let view = NodeL2::replay_from(&chain, chain.params());
    let s = view.status(chain.height());
    assert_eq!(s.chain_height, 2);
    assert_eq!(s.l2_height, 2);
    assert_eq!(s.applied, 0);
    assert_eq!(s.skipped, 1);
    assert!(!s.clean);
    // And the skip names everything an operator needs: height, txid, reason.
    let skip = &view.skipped()[0];
    assert_eq!(skip.height, 1);
    assert_eq!(hash_to_hex(&skip.txid).len(), 64);
    assert!(!format!("{}", skip.error).is_empty());
}
