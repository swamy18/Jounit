//! M5 node-level finality tests — Decisions 12/15 (SPEC.md §14.8, §19.4.1).
//!
//! Through the real node path (mined blocks, `Chain::submit`, `NodeL2::sync`,
//! the store's finalized point):
//!
//! - a `Settle` payload applies only under the profile's *declared* committee
//!   — foreign keys and empty committees are refused by name;
//! - a checkpoint can move binding finality **without moving the tip**, and
//!   the view matures a pending deposit at that moment (not before);
//! - the finalized point and the L2 state it gates survive a restart
//!   identically: replay, incremental follow, and a second replay agree.

use std::sync::atomic::{AtomicU64, Ordering};

use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::{
    BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload, ValidatorSet,
};
use jnt_core::chain::Chain;
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash, Hash512};
use jnt_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::params::{
    mini_committee_secrets, testnet_committee_secrets, NetworkParams, SAT_PER_JNT,
};
use jnt_core::tx::{OutPoint, Output};
use jnt_core::wallet::Wallet;
use jnt_l2::L2Error;
use jnt_node::l2::{NodeL2, SyncOutcome};
use jnt_store::BlockStore;

const MAX_ATTEMPTS: u64 = 4_000_000;
const PAYMENT_SAT: u64 = 5_000_000;
const CLAIM_DEPOSIT_SAT: u64 = 1_000_000;
const DEADLINE: u64 = 200;
const RESULT: Hash = [0x42u8; 32];
const COUNTER: Hash = [0x43u8; 32];
const CHALLENGE_DEPOSIT_SAT: u64 = 50_000;
const SINK_VALUE: u64 = 3 * SAT_PER_JNT;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "m5-node-finality").unwrap()
}

fn addr_of(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

fn task(nonce: u64, deadline: u64) -> ComputeTask {
    let mut task_id = [0x66u8; 32];
    task_id[0] = nonce as u8;
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

fn attestation(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Gpu,
        worker_address: addr_of(w),
        attest_height: 0,
        signature: vec![],
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

fn post(seed: u8, nonce: u64) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, PAYMENT_SAT, DEADLINE, task(nonce, DEADLINE)).unwrap(),
    ))
}

fn claim(seed: u8, task_id: Hash) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Claim(
        ClaimTaskPayload::build(&w, task_id, ComputeBackend::Gpu, CLAIM_DEPOSIT_SAT).unwrap(),
    ))
}

fn submit_result(seed: u8, task_id: Hash) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Submit(
        SubmitResultPayload::build(&w, task_id, attestation(&w, task_id, RESULT)).unwrap(),
    ))
}

/// A challenge against `task_id` — the state an *explicit* Correct settlement
/// is legal in. (While the task sits merely ResultSubmitted, the first height
/// past the dispute window auto-settles it in `advance_block` before the
/// block's own transactions run, so an explicit settle there can never win;
/// a disputed task settles explicitly at any point before the lapse.)
fn dispute(seed: u8, task_id: Hash) -> L2Transaction {
    let w = wallet(seed);
    L2Transaction::new(L2Payload::Dispute(
        jnt_core::l2::DisputePayload::build(
            &w,
            task_id,
            COUNTER,
            attestation(&w, task_id, COUNTER),
            CHALLENGE_DEPOSIT_SAT,
        )
        .unwrap(),
    ))
}

fn post_task_id(tx: &L2Transaction) -> Hash {
    match &tx.payload {
        L2Payload::Post(p) => p.task_id,
        _ => unreachable!("post() builds a Post"),
    }
}

/// A `Settle` for `task_id` signed by `signers_secrets` over the bitmap
/// positions they occupy in `set`. For a Correct verdict the named vwc hash
/// must be the disputed-against result, per §15.3. Signing with keys that are
/// NOT in `set` produces exactly the foreign-committee attack: same bytes,
/// wrong signers.
fn signed_settle(
    set: &ValidatorSet,
    signers_secrets: &[(SecretKey, BlsPublicKey)],
    task_id: Hash,
) -> L2Transaction {
    let payload = SettlePayload {
        task_id,
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
    };
    let msg = payload.signing_hash();
    let quorum = set.quorum_size();
    let indices: Vec<usize> = (0..quorum).collect();
    let bitmap = set.bitmap_from_indices(&indices);
    // Sign with the supplied pairs in their canonical order: passing the
    // declared committee produces a genuine aggregate over the bitmap-named
    // keys; passing a foreign committee produces the attack — same bitmap,
    // keys that are not in the set.
    let sigs: Vec<BlsSignature> = signers_secrets[..quorum]
        .iter()
        .map(|(sk, _)| sk.sign(&msg))
        .collect();
    let bls_sig = *RealBls::aggregate(&sigs).unwrap().as_bytes();
    L2Transaction::new(L2Payload::Settle(SettlePayload {
        bls_sig,
        signer_bitmap: bitmap,
        signer_count: quorum as u32,
        task_id,
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
    }))
}

/// The declared committee of `params`, as (secret, key) pairs in canonical
/// order — public test material, exactly as the profile derives it.
fn declared_committee(params: &NetworkParams) -> Vec<(SecretKey, BlsPublicKey)> {
    let secrets = if params.name == "mini" {
        mini_committee_secrets()
    } else {
        testnet_committee_secrets()
    };
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = secrets
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

fn mine_and_submit(chain: &mut Chain, l2: Vec<L2Transaction>) {
    let h = chain.height() + 1;
    // An L2-bearing block commits the root replay derives (approved P1).
    let block = if l2.is_empty() {
        chain.mine_block([1u8; 20], Vec::new(), ts(h))
    } else if chain.exit_active_at(h) {
        let root = NodeL2::replay_from(chain, chain.params()).simulate_root(h, &l2);
        chain.mine_block_with_l2_root([1u8; 20], Vec::new(), l2, root, ts(h), None, MAX_ATTEMPTS)
    } else {
        // Pre-activation profile: the trailer rides without a root.
        chain.mine_block_with_l2([1u8; 20], Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
    }
    .expect("a block we just mined must build");
    chain.submit(block).expect("it must be accepted");
}

// ---------------------------------------------------------------------------
// Step 9 — the settlement validator seam
// ---------------------------------------------------------------------------

#[test]
fn the_declared_committee_is_the_settlement_set_on_every_profile() {
    let mini = NetworkParams::mini();
    let testnet = NetworkParams::testnet();
    let mainnet = NetworkParams::mainnet();

    // The seam reads the profile declaration — the same list the finality
    // layer verifies checkpoints against.
    for params in [&mini, &testnet] {
        let set = jnt_node::l2::validator_set(params);
        assert_eq!(set.quorum_size(), 3, "{}: quorum is 3 of 4", params.name);
        let all = set.signers_from_bitmap(&[0b0000_1111]);
        assert_eq!(
            all, params.genesis_validators,
            "{}: L2 settles against the declared active committee, byte for byte",
            params.name
        );
        // Deterministic: two calls name the same set.
        let again = jnt_node::l2::validator_set(params);
        assert_eq!(again.signers_from_bitmap(&[0b0000_1111]), all);
    }

    // Mainnet intentionally declares none: empty means nothing verifies.
    assert!(jnt_node::l2::validator_set(&mainnet)
        .signers_from_bitmap(&[0xFF, 0xFF])
        .is_empty());
}

#[test]
fn a_settlement_applies_under_the_declared_committee() {
    // The full lifecycle through mined blocks on `mini` (the profile with a
    // declared committee *and* funded actors): post → claim → submit →
    // dispute → settle, with a genuine 3-of-4 aggregate over the declared
    // keys.
    let params = NetworkParams::mini();
    let committee = declared_committee(&params);
    let set = jnt_node::l2::validator_set(&params);
    let mut chain = Chain::new(params.clone()).unwrap();

    let tx_post = post(2, 1);
    let task_id = post_task_id(&tx_post);
    mine_and_submit(&mut chain, vec![tx_post]);
    mine_and_submit(&mut chain, vec![claim(3, task_id)]);
    mine_and_submit(&mut chain, vec![submit_result(3, task_id)]);
    mine_and_submit(&mut chain, vec![dispute(1, task_id)]);
    mine_and_submit(&mut chain, vec![signed_settle(&set, &committee, task_id)]);

    let view = NodeL2::replay_from(&chain, &params);
    assert!(
        view.skipped().is_empty(),
        "the lifecycle must apply cleanly: {:?}",
        view.skipped()
    );
    assert_eq!(view.applied_count(), 5);
    assert_eq!(
        view.state().vwc_count(),
        1,
        "a Correct settlement under the declared committee issues its certificate"
    );
    assert!(view.state().task(&task_id).is_some());
    assert!(view.state().check_conservation());
}

#[test]
fn a_settlement_signed_by_a_foreign_committee_is_refused() {
    // Same lifecycle, same bytes — but the aggregate comes from the testnet
    // keys, not mini's declared committee. The bitmap still names mini's
    // signers, so verification must fail rather than apply without authority.
    let params = NetworkParams::mini();
    let foreign = declared_committee(&NetworkParams::testnet());
    let set = jnt_node::l2::validator_set(&params);
    let mut chain = Chain::new(params.clone()).unwrap();

    let tx_post = post(2, 1);
    let task_id = post_task_id(&tx_post);
    mine_and_submit(&mut chain, vec![tx_post]);
    mine_and_submit(&mut chain, vec![claim(3, task_id)]);
    mine_and_submit(&mut chain, vec![submit_result(3, task_id)]);
    mine_and_submit(&mut chain, vec![dispute(1, task_id)]);
    mine_and_submit(&mut chain, vec![signed_settle(&set, &foreign, task_id)]);

    let view = NodeL2::replay_from(&chain, &params);
    assert_eq!(view.applied_count(), 4, "the first four payloads applied");
    assert_eq!(view.skipped().len(), 1);
    assert!(
        matches!(view.skipped()[0].error, L2Error::BadBlsSignature),
        "foreign keys must fail at the aggregate check, got {:?}",
        view.skipped()[0].error
    );
    assert_eq!(
        view.state().vwc_count(),
        0,
        "no certificate issues without a valid declared-committee aggregate"
    );
}

#[test]
fn a_profile_without_a_committee_fails_closed_on_settlements() {
    // Mainnet is the honest pre-committee state: an empty set means a
    // plausible-looking quorum verifies against nothing and is refused by
    // name, through the real node path.
    let params = NetworkParams::mainnet();
    let mut chain = Chain::new(params.clone()).unwrap();

    let fake = SettlePayload {
        task_id: [0x77; 32],
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
        // Signs over nothing: on a profile with a committee this would fail
        // at the aggregate; with no committee it must not even get there.
        bls_sig: [0x01; 96],
        signer_bitmap: vec![0b0000_0111],
        signer_count: 3,
    };
    mine_and_submit(
        &mut chain,
        vec![L2Transaction::new(L2Payload::Settle(fake))],
    );

    let view = NodeL2::replay_from(&chain, &params);
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    assert!(
        matches!(view.skipped()[0].error, L2Error::BadQuorum),
        "empty committee must refuse a quorum claim, got {:?}",
        view.skipped()[0].error
    );
    assert_eq!(view.state().vwc_count(), 0);
}

// ---------------------------------------------------------------------------
// Steps 8/10 — a checkpoint matures deposits without a tip move, and restart
// keeps every view identical
// ---------------------------------------------------------------------------

fn testnet_mine_empty_to(chain: &mut Chain, miner: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn testnet_deposit_block(chain: &mut Chain, from: &Wallet) -> u64 {
    let me = addr_of(from);
    let (op, value): (OutPoint, u64) = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == me && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .next()
        .expect("a mature coinbase");
    let gas = 16_000 + 1_000 + 250 * 2;
    let fee = chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000);
    let tx = from
        .build_tx(
            &[op],
            vec![
                Output {
                    value: SINK_VALUE,
                    address: NetworkParams::testnet().l2_deposit_sink(),
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
    h
}

fn checkpoint_at(chain: &mut Chain, height: u64) {
    let block_hash: Hash512 = chain.block_hash_at(height).unwrap();
    let pairs = declared_committee(chain.params());
    let p = CheckpointPayload {
        height,
        block_hash,
        network_id: chain.params().network_id.clone(),
        epoch: height / chain.params().checkpoint_interval_blocks,
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
    };
    chain.apply_checkpoint(&cp, &RealBls).unwrap();
}

/// A testnet chain carrying one deposit at height 22, tip 42 (depth
/// satisfied), with the binding checkpoint frozen at 20 — Case A's world.
fn case_a_chain() -> Chain {
    let mut chain = Chain::new(NetworkParams::testnet()).unwrap();
    let miner = wallet(81);
    testnet_mine_empty_to(&mut chain, addr_of(&miner), 21);
    let dep = testnet_deposit_block(&mut chain, &miner);
    assert_eq!(dep, 22);
    testnet_mine_empty_to(&mut chain, addr_of(&miner), 20);
    assert_eq!(chain.height(), 42);
    checkpoint_at(&mut chain, 20);
    assert_eq!(chain.finality().binding_finalized_height(), 20);
    chain
}

#[test]
fn a_checkpoint_without_a_tip_move_matures_a_pending_deposit() {
    let mut chain = case_a_chain();
    let params = NetworkParams::testnet();

    // Depth is satisfied; binding finality is live but below the deposit.
    let mut view = NodeL2::fresh(&params);
    let report = view.sync(&chain);
    assert!(matches!(report.outcome, SyncOutcome::FullReplay { .. }));
    assert_eq!(
        view.pending_deposits().len(),
        1,
        "Case A: not spendable yet"
    );
    assert_eq!(view.deposits_applied_count(), 0);
    assert_eq!(view.state().balance(&addr_of(&wallet(81))), 0);

    // A certificate at 30 moves finality with the tip standing still. The
    // next sync must notice — without this, the deposit would sit pending
    // forever until some unrelated block arrived.
    checkpoint_at(&mut chain, 30);
    assert_eq!(chain.height(), 42, "the tip did not move");
    let report = view.sync(&chain);
    assert_eq!(
        report.outcome,
        SyncOutcome::FullReplay { blocks: 42 },
        "binding finality alone must trigger the maturity re-evaluation"
    );
    assert_eq!(view.pending_deposits().len(), 0);
    assert_eq!(
        view.deposits_applied_count(),
        1,
        "Case C: both conditions hold"
    );
    assert_eq!(view.state().balance(&addr_of(&wallet(81))), SINK_VALUE);

    // Nothing left to do: the next sync is a no-op.
    let report = view.sync(&chain);
    assert_eq!(report.outcome, SyncOutcome::Unchanged);
    assert_eq!(view.deposits_applied_count(), 1, "credited exactly once");
}

// ---------------------------------------------------------------------------
// Step 3/10 — restart: finality and L2 state come back identical
// ---------------------------------------------------------------------------

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store_dir() -> std::path::PathBuf {
    let id = STORE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("jnt-node-m5-finality-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn persist(chain: &Chain, dir: &std::path::Path) {
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir, &params).unwrap();
    for h in 1..=chain.height() {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.tip_hash()).unwrap();
    if let Some((fh, fhash)) = chain.finalized_point() {
        bs.set_finalized(fh, fhash).unwrap();
    }
    bs.sync().unwrap();
}

/// The node's load path: replay stored blocks, then restore the finalized
/// point only onto the exact canonical chain that replay produced.
fn reload(dir: &std::path::Path, params: &NetworkParams) -> Chain {
    let (mut bs, _) = BlockStore::open(dir, params).unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    let (_, height) = bs.tip();
    for h in 1..=height {
        chain
            .submit(bs.block_at_height(h).unwrap().unwrap())
            .unwrap();
    }
    if let Some((fh, fhash)) = bs.finalized() {
        assert!(chain.restore_finality(fh, fhash));
    }
    chain
}

#[test]
fn finality_and_l2_state_survive_a_restart_identically() {
    let dir = temp_store_dir();
    let params = NetworkParams::testnet();
    let chain = case_a_chain();
    let point = chain.finalized_point().unwrap();

    let live = NodeL2::replay_from(&chain, &params);
    assert_eq!(live.pending_deposits().len(), 1, "Case A before restart");

    persist(&chain, &dir);
    drop(chain);
    drop(live);

    // Restart.
    let mut reborn = reload(&dir, &params);
    assert_eq!(
        reborn.finalized_point(),
        Some(point),
        "finalized height/hash before restart == after restart"
    );

    let recovered = NodeL2::replay_from(&reborn, &params);
    assert_eq!(recovered.pending_deposits().len(), 1);
    assert_eq!(recovered.deposits_applied_count(), 0);

    // Fresh replay == the view a node builds by following the tip from
    // scratch (incremental) == a second fresh replay.
    let mut incremental = NodeL2::fresh(&params);
    incremental.sync(&reborn);
    let again = NodeL2::replay_from(&reborn, &params);

    let third = NodeL2::replay_from(&reborn, &params); // third derivation
    for (name, view) in [
        ("recovered", &recovered),
        ("incremental", &incremental),
        ("again", &again),
        ("third", &third),
    ] {
        assert_eq!(
            view.state(),
            recovered.state(),
            "{name}: every derivation of L2 state agrees"
        );
        assert_eq!(view.pending_deposits(), recovered.pending_deposits());
        assert_eq!(view.height(), recovered.height());
    }

    // And the restarted chain still refuses to be reorged across its restored
    // finality — the persisted point is enforced, not merely displayed.
    let mut rival = Chain::new(params.clone()).unwrap();
    let addr = [1u8; 20];
    for h in 1..=15u64 {
        rival.submit(reborn.block_at(h).unwrap().clone()).unwrap();
    }
    for h in 16..=50u64 {
        let b = rival
            .mine_block(addr, vec![], ts(h) + 7)
            .expect("rival mines");
        rival.submit(b).unwrap();
    }
    let mut crossings = 0;
    for h in 16..=50u64 {
        if let Err(e) = reborn.submit(rival.block_at(h).unwrap().clone()) {
            if matches!(e, jnt_core::error::Error::ReorgWouldCrossFinality { .. }) {
                crossings += 1;
            }
        }
    }
    assert!(
        crossings > 0,
        "restored finality must gate adopt() after restart"
    );
    assert_eq!(reborn.finalized_point(), Some(point));

    let _ = std::fs::remove_dir_all(&dir);
}
