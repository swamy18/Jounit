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

use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::{
    BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload, ValidatorSet,
};
use srct_core::bond::{bond_identity, bond_pop};
use srct_core::chain::Chain;
use srct_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use srct_core::params::{
    mainnet_committee_secrets, mini_committee_secrets, testnet_committee_secrets, NetworkParams,
    SAT_PER_SRCT,
};
use srct_core::tx::{
    OutPoint, Output, StakePayload, Transaction, GAS_PER_INPUT, GAS_PER_OUTPUT, GAS_TX_BASE,
    TX_BOND,
};
use srct_core::wallet::Wallet;
use srct_l2::L2Error;
use srct_node::l2::{NodeL2, SyncOutcome};
use srct_store::BlockStore;

const MAX_ATTEMPTS: u64 = 4_000_000;
const PAYMENT_SAT: u64 = 5_000_000;
const CLAIM_DEPOSIT_SAT: u64 = 1_000_000;
const DEADLINE: u64 = 200;
const RESULT: Hash = [0x42u8; 32];
const COUNTER: Hash = [0x43u8; 32];
const CHALLENGE_DEPOSIT_SAT: u64 = 50_000;
const SINK_VALUE: u64 = 3 * SAT_PER_SRCT;

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
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
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
        srct_core::l2::DisputePayload::build(
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
    network_id: &str,
    vote_height: u64,
) -> L2Transaction {
    let payload = SettlePayload {
        task_id,
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
        network_id: network_id.to_string(),
        height: vote_height,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
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
        pq_sidecar: Vec::new(),
        task_id,
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
        network_id: network_id.to_string(),
        height: vote_height,
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
        let root = NodeL2::replay_from(chain, chain.params())
            .unwrap()
            .simulate_root(chain, h, &l2);
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
fn the_declared_settlement_committee_matches_the_genesis_committee() {
    let mini = NetworkParams::mini();
    let testnet = NetworkParams::testnet();
    let mainnet = NetworkParams::mainnet();

    // The seam reads the declared committee, which matches each profile's L1
    // genesis committee.
    for params in [&mini, &testnet] {
        let set = srct_node::l2::validator_set(params);
        assert_eq!(set.quorum_size(), 3, "{}: quorum is 3 of 4", params.name);
        let all = set.signers_from_bitmap(&[0b0000_1111]);
        assert_eq!(
            all, params.l2_settlement_validators,
            "{}: L2 settles against the declared settlement committee, byte for byte",
            params.name
        );
        // Deterministic: two calls name the same set.
        let again = srct_node::l2::validator_set(params);
        assert_eq!(again.signers_from_bitmap(&[0b0000_1111]), all);
    }

    // Mainnet declares the same 21 bootstrap keys that secure L1 pre-bond
    // (Decision 28). The declaration alone is not a permanent grant:
    // verification resolves the live committee per block height, so the first
    // bond rotates L2 authority to the bonded TopN.
    assert_eq!(mainnet.genesis_validators.len(), 21);
    assert_eq!(
        mainnet.l2_settlement_validators, mainnet.genesis_validators,
        "mainnet declares its bootstrap keys for L2, like mini/testnet declare theirs"
    );
    let set = srct_node::l2::validator_set(&mainnet);
    assert_eq!(set.quorum_size(), 15, "mainnet: quorum is 15 of 21");
    assert_eq!(
        set.signers_from_bitmap(&[0xFF, 0xFF, 0xFF]),
        mainnet.genesis_validators,
        "mainnet: the declared set names every bootstrap key, byte for byte"
    );
}

#[test]
fn a_settlement_applies_under_the_declared_committee() {
    // The full lifecycle through mined blocks on `mini` (the profile with a
    // declared committee *and* funded actors): post → claim → submit →
    // dispute → settle, with a genuine 3-of-4 aggregate over the declared
    // keys.
    let params = NetworkParams::mini();
    let committee = declared_committee(&params);
    let set = srct_node::l2::validator_set(&params);
    let mut chain = Chain::new(params.clone()).unwrap();

    let tx_post = post(2, 1);
    let task_id = post_task_id(&tx_post);
    mine_and_submit(&mut chain, vec![tx_post]);
    mine_and_submit(&mut chain, vec![claim(3, task_id)]);
    mine_and_submit(&mut chain, vec![submit_result(3, task_id)]);
    mine_and_submit(&mut chain, vec![dispute(1, task_id)]);
    let vote_height = chain.height();
    mine_and_submit(
        &mut chain,
        vec![signed_settle(
            &set,
            &committee,
            task_id,
            &params.network_id,
            vote_height,
        )],
    );

    let view = NodeL2::replay_from(&chain, &params).unwrap();
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
    let set = srct_node::l2::validator_set(&params);
    let mut chain = Chain::new(params.clone()).unwrap();

    let tx_post = post(2, 1);
    let task_id = post_task_id(&tx_post);
    mine_and_submit(&mut chain, vec![tx_post]);
    mine_and_submit(&mut chain, vec![claim(3, task_id)]);
    mine_and_submit(&mut chain, vec![submit_result(3, task_id)]);
    mine_and_submit(&mut chain, vec![dispute(1, task_id)]);
    let vote_height = chain.height();
    mine_and_submit(
        &mut chain,
        vec![signed_settle(
            &set,
            &foreign,
            task_id,
            &params.network_id,
            vote_height,
        )],
    );

    let view = NodeL2::replay_from(&chain, &params).unwrap();
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
fn a_settlement_with_no_signers_at_all_is_refused() {
    // A quorum claim that names no signers verifies against nothing and is
    // refused by name through the real node path — on every profile.
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();

    let fake = SettlePayload {
        task_id: [0x77; 32],
        verdict: Verdict::Correct,
        vwc_hash: RESULT,
        network_id: "srct/mini".to_string(),
        height: 0,
        // Signs over nothing: on a profile with a committee this would fail
        // at the aggregate; with no signers it must not even get there.
        bls_sig: [0x01; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
    };
    mine_and_submit(
        &mut chain,
        vec![L2Transaction::new(L2Payload::Settle(fake))],
    );

    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(view.applied_count(), 0);
    assert_eq!(view.skipped().len(), 1);
    assert!(
        matches!(view.skipped()[0].error, L2Error::BadQuorum),
        "a signerless quorum claim must be refused, got {:?}",
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
        pq_sidecar: Vec::new(),
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
    let mut view = NodeL2::fresh(&params).unwrap();
    let report = view.sync(&chain).unwrap();
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
    let report = view.sync(&chain).unwrap();
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
    let report = view.sync(&chain).unwrap();
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
        std::env::temp_dir().join(format!("srct-node-m5-finality-{}-{id}", std::process::id()));
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

    let live = NodeL2::replay_from(&chain, &params).unwrap();
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

    let recovered = NodeL2::replay_from(&reborn, &params).unwrap();
    assert_eq!(recovered.pending_deposits().len(), 1);
    assert_eq!(recovered.deposits_applied_count(), 0);

    // Fresh replay == the view a node builds by following the tip from
    // scratch (incremental) == a second fresh replay.
    let mut incremental = NodeL2::fresh(&params).unwrap();
    incremental.sync(&reborn).unwrap();
    let again = NodeL2::replay_from(&reborn, &params).unwrap();

    let third = NodeL2::replay_from(&reborn, &params).unwrap(); // third derivation
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
            if matches!(e, srct_core::error::Error::ReorgWouldCrossFinality { .. }) {
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

// ---------------------------------------------------------------------------
// Decision 28 — mainnet settlement authority follows the live committee
// ---------------------------------------------------------------------------
//
// The old blocker: mainnet's `l2_settlement_validators` was empty, so every
// `Settle` on mainnet failed with `BadQuorum`. The resolution is two halves:
// the declared set names the 21 bootstrap keys (worker/offline use), and
// verification resolves the live L1 committee per block height — bootstrap
// pre-bond, bonded TopN after the first bond. These tests run the affected
// workflows (post → claim → submit → dispute → settle) on the real mainnet
// profile through mined blocks, first under the bootstrap committee and then
// across a rotation to a bonded committee.

/// The mainnet bootstrap committee as (secret, key) pairs in canonical
/// order — public test material, exactly as the profile derives it.
fn mainnet_committee() -> Vec<(SecretKey, BlsPublicKey)> {
    let mut pairs: Vec<(SecretKey, BlsPublicKey)> = mainnet_committee_secrets()
        .into_iter()
        .map(|sk| {
            let pk = sk.public_key();
            (sk, pk)
        })
        .collect();
    pairs.sort_by_key(|a| a.1 .0);
    pairs
}

/// Mainnet-paced timestamps: one block time (600 s) apart, so the LWMA
/// retarget holds difficulty at its fixed point. Ultrafast test blocks would
/// ramp difficulty up block after block (change-limit floor admits +1 from
/// difficulty 1), turning a 200-block rotation walk into minutes of PoW
/// grinding.
fn mts(height: u64) -> u64 {
    srct_core::block::GENESIS_TIMESTAMP_MS + height * 600_000
}

/// Mine one mainnet block carrying `l2`, committing the root the node's own
/// replay derives, then follow it with `view`. Actors are credited by the
/// test (mainnet grants nothing); the point under test is settlement
/// authorization, not deposit funding. `step_ms` is the timestamp spacing;
/// pass 600_000 for long walks so difficulty stays pinned at 1.
fn mine_l2_mainnet(chain: &mut Chain, view: &mut NodeL2, l2: Vec<L2Transaction>, step_ms: u64) {
    let h = chain.height() + 1;
    let root = view.simulate_root(chain, h, &l2);
    let block = chain
        .mine_block_with_l2_root(
            [1u8; 20],
            Vec::new(),
            l2,
            root,
            srct_core::block::GENESIS_TIMESTAMP_MS + h * step_ms,
            None,
            MAX_ATTEMPTS,
        )
        .expect("a mainnet block we just mined must build");
    chain.submit(block).expect("it must be accepted");
    view.sync(chain).unwrap();
}

fn mainnet_bond(
    chain: &Chain,
    w: &Wallet,
    ops: &[OutPoint],
    sk: &SecretKey,
    value: u64,
) -> Transaction {
    let pk = sk.public_key();
    let bonder = w.address().unwrap();
    let net = chain.params().network_id.clone();
    let total: u64 = ops
        .iter()
        .map(|op| chain.utxo().get(op).unwrap().out.value)
        .fold(0u64, |a, v| a.saturating_add(v));
    let fee = chain
        .expected_base_fee_for_next_block()
        .saturating_mul(GAS_TX_BASE + GAS_PER_INPUT * ops.len() as u64 + GAS_PER_OUTPUT * 2)
        .saturating_add(1_000_000);
    assert!(
        total > value + fee,
        "test funding cannot cover bond plus fee"
    );
    let mut tx = w
        .build_tx(
            ops,
            vec![
                Output {
                    value,
                    address: bond_identity(&net, &bonder, &pk),
                },
                Output {
                    value: total - value - fee,
                    address: bonder,
                },
            ],
            fee,
        )
        .unwrap();
    tx.tx_type = TX_BOND;
    tx.stake = Some(StakePayload::Bond {
        bls_pk: pk,
        pop: bond_pop(sk, &net, &bonder),
        mldsa_pk: None,
    });
    w.sign(&mut tx).unwrap();
    tx
}

/// Run one full lifecycle on deposit-funded actors only: no test credits,
/// so every sat is chain-derived and a fresh replay applies the same way.
/// Returns the settled task id.
fn mainnet_post_bond_lifecycle(
    chain: &mut Chain,
    view: &mut NodeL2,
    secrets: &[(SecretKey, BlsPublicKey)],
) -> Hash {
    // The view replays the unfunded pre-bond history first, so it already
    // carries deterministic skips — only *new* skips from this lifecycle
    // would indicate a failure.
    let skipped_before = view.skipped().len();
    let tx_post = L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&wallet(2), 31, PAYMENT_SAT, 1200, task(31, 1200)).unwrap(),
    ));
    let task_id = post_task_id(&tx_post);
    mine_l2_mainnet(chain, view, vec![tx_post], 600_000);
    mine_l2_mainnet(chain, view, vec![claim(3, task_id)], 600_000);
    mine_l2_mainnet(chain, view, vec![submit_result(3, task_id)], 600_000);
    mine_l2_mainnet(chain, view, vec![dispute(1, task_id)], 600_000);
    let h = chain.height();
    let set = chain.settlement_committee_at(h + 1);
    mine_l2_mainnet(
        chain,
        view,
        vec![signed_settle(
            &set,
            secrets,
            task_id,
            &chain.params().network_id.clone(),
            h,
        )],
        600_000,
    );
    assert_eq!(
        view.skipped().len(),
        skipped_before,
        "the funded lifecycle must apply cleanly: {:?}",
        view.skipped()
    );
    assert!(view.state().task(&task_id).is_some());
    task_id
}

/// Run one full lifecycle (post → claim → submit → dispute → settle) on
/// `chain`/`view` at the current tip, with the settle quorum drawn from
/// `secrets`.
fn mainnet_lifecycle(
    chain: &mut Chain,
    view: &mut NodeL2,
    secrets: &[(SecretKey, BlsPublicKey)],
    nonce: u64,
    deadline: u64,
    step_ms: u64,
) -> Hash {
    for (seed, amount) in [(2u8, 100_000_000), (3u8, 100_000_000), (1u8, 100_000_000)] {
        view.state_mut()
            .credit(wallet(seed).address().unwrap(), amount)
            .unwrap();
    }
    let tx_post = L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(
            &wallet(2),
            nonce,
            PAYMENT_SAT,
            deadline,
            task(nonce, deadline),
        )
        .unwrap(),
    ));
    let task_id = post_task_id(&tx_post);
    mine_l2_mainnet(chain, view, vec![tx_post], step_ms);
    mine_l2_mainnet(chain, view, vec![claim(3, task_id)], step_ms);
    mine_l2_mainnet(chain, view, vec![submit_result(3, task_id)], step_ms);
    mine_l2_mainnet(chain, view, vec![dispute(1, task_id)], step_ms);
    let h = chain.height();
    let set = chain.settlement_committee_at(h + 1);
    mine_l2_mainnet(
        chain,
        view,
        vec![signed_settle(
            &set,
            secrets,
            task_id,
            &chain.params().network_id.clone(),
            h,
        )],
        step_ms,
    );
    assert!(
        view.skipped().is_empty(),
        "the mainnet lifecycle must apply cleanly: {:?}",
        view.skipped()
    );
    assert!(view.state().task(&task_id).is_some());
    task_id
}

#[test]
fn mainnet_settlement_applies_under_the_bootstrap_committee() {
    // The documented blocker, resolved: a 15-of-21 bootstrap aggregate
    // settles a task on mainnet through mined blocks — previously every
    // such settle died with `BadQuorum` against the empty declared set.
    let params = NetworkParams::mainnet();
    let mut chain = Chain::new(params.clone()).unwrap();
    let committee = mainnet_committee();
    assert_eq!(committee.len(), 21);

    // Authority resolves per height to the bootstrap set while no bonds exist.
    for h in [1u64, 50] {
        let set = chain.settlement_committee_at(h);
        assert_eq!(set.quorum_size(), 15);
        assert_eq!(
            set.keys, params.l2_settlement_validators,
            "pre-bond L2 authority is the declared bootstrap committee"
        );
    }

    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
    let task_id = mainnet_lifecycle(&mut chain, &mut view, &committee, 11, 500, 1_000);
    assert_eq!(view.applied_count(), 5);
    assert_eq!(view.state().vwc_count(), 1);
    assert!(view.state().task(&task_id).is_some());

    // Replay determinism: two fresh replays of the same chain agree exactly.
    // (They cannot equal the live view: the test-only actor credits live in
    // the view, not on the chain — without them the unfunded payloads skip,
    // deterministically, in both replays.)
    let again = NodeL2::replay_from(&chain, &params).unwrap();
    let third = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(third.state(), again.state());
    assert_eq!(third.applied_count(), again.applied_count());
}

#[test]
fn mainnet_settlement_rotates_to_the_bonded_committee() {
    // After the first bond, L2 authority is the bonded TopN — bootstrap keys
    // authorize nothing further. Pre-bond history still verifies on replay
    // (per-height resolution), and a bootstrap-only quorum for a post-bond
    // task is refused by name.
    let params = NetworkParams::mainnet();
    let mut chain = Chain::new(params.clone()).unwrap();
    let bonder = wallet(90);
    let bonder_addr = addr_of(&bonder);
    // Fund the bonder past coinbase maturity (100 on mainnet). All bulk
    // mining uses mainnet-paced timestamps so difficulty stays pinned at 1.
    for _ in 0..101 {
        let h = chain.height() + 1;
        let b = chain.mine_block(bonder_addr, Vec::new(), mts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 101);

    let committee = mainnet_committee();
    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
    // Pre-bond lifecycle on view-only credits: proves the previously blocked
    // bootstrap verification path applies end to end. (Credits are test
    // injection, not chain state, so this history is live-view-only by
    // construction — the replayable history starts with the deposits below.)
    let pre_id = mainnet_lifecycle(&mut chain, &mut view, &committee, 21, 800, 600_000);
    assert!(view.state().task(&pre_id).is_some());
    assert_eq!(view.state().vwc_count(), 1);

    // Honest funding for the replayable history: bonder transfers to three
    // actors, each deposits to the L2 sink. Note the ledger applies the
    // maturity rule to *every* output (ledger.rs), so transfer outputs
    // created at 107 are spendable at 207, and the deposits mature at depth
    // 100 after that — the post-bond lifecycle runs once all of it clears.
    let transfer = {
        let fee = chain
            .expected_base_fee_for_next_block()
            .saturating_mul(GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT * 4);
        let total = 76 * SAT_PER_SRCT;
        let per_actor = 200_000_000u64;
        let mut tx = bonder
            .build_tx(
                &[OutPoint {
                    txid: chain.block_at(1).unwrap().txs[0].txid(),
                    index: 0,
                }],
                vec![
                    Output {
                        value: per_actor,
                        address: addr_of(&wallet(2)),
                    },
                    Output {
                        value: per_actor,
                        address: addr_of(&wallet(3)),
                    },
                    Output {
                        value: per_actor,
                        address: addr_of(&wallet(1)),
                    },
                    Output {
                        value: total - 3 * per_actor - fee,
                        address: bonder_addr,
                    },
                ],
                fee,
            )
            .unwrap();
        bonder.sign(&mut tx).unwrap();
        tx
    };
    // Transfer lands at 107, spending the matured block-1 coinbase.
    let h = chain.height() + 1;
    let tb = chain
        .mine_block(bonder_addr, vec![transfer], mts(h))
        .unwrap();
    chain.submit(tb).unwrap();
    assert_eq!(chain.height(), 107);

    // Bond a fresh key (not a bootstrap member) at 108: coinbase #2 matured
    // at 102, and 108 < 180, so epoch 2's committee is the bonded TopN.
    let bond_sk = SecretKey::derive(&[77u8; 32]).unwrap();
    let bond_pk = bond_sk.public_key();
    let op = OutPoint {
        txid: chain.block_at(2).unwrap().txs[0].txid(),
        index: 0,
    };
    let bond = mainnet_bond(&chain, &bonder, &[op], &bond_sk, SAT_PER_SRCT);
    let h = chain.height() + 1;
    let bb = chain.mine_block(bonder_addr, vec![bond], mts(h)).unwrap();
    chain.submit(bb).unwrap();

    // Walk to 207. Rotation takes effect at height 200 (epoch 2, seed 180),
    // and the transfer outputs mature at 207 — both gates clear together.
    while chain.height() < 207 {
        let h = chain.height() + 1;
        let b = chain.mine_block(bonder_addr, Vec::new(), mts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    assert_eq!(chain.height(), 207);
    assert_eq!(chain.committee_keys(), vec![bond_pk]);
    let post_set = chain.settlement_committee_at(chain.height());
    assert_eq!(post_set.keys, vec![bond_pk]);
    assert_eq!(post_set.quorum_size(), 1);

    // Deposits at 208, spending the now-mature transfer outputs — one per
    // actor, since a deposit credits its input owner. They mature at 308.
    let sink = params.l2_deposit_sink();
    let mut deposits = Vec::new();
    for seed in [2u8, 3, 1] {
        let w = wallet(seed);
        let op = chain
            .utxo()
            .iter()
            .filter(|(_, u)| u.out.address == addr_of(&w))
            .map(|(op, _)| op)
            .next()
            .expect("the transfer must have funded the actor");
        let value = chain.utxo().get(&op).unwrap().out.value;
        let fee = chain
            .expected_base_fee_for_next_block()
            .saturating_mul(GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT * 2);
        assert!(value >= 100_000_000 + fee);
        let mut tx = w
            .build_tx(
                &[op],
                vec![
                    Output {
                        value: 100_000_000,
                        address: sink,
                    },
                    Output {
                        value: value - 100_000_000 - fee,
                        address: addr_of(&w),
                    },
                ],
                fee,
            )
            .unwrap();
        w.sign(&mut tx).unwrap();
        deposits.push(tx);
    }
    let h = chain.height() + 1;
    let db = chain.mine_block(bonder_addr, deposits, mts(h)).unwrap();
    chain.submit(db).unwrap();
    assert_eq!(chain.height(), 208);

    // Walk to maturity (208 + 100). Fresh replay from here: the deposits
    // are chain state, so actors are funded without any test injection.
    while chain.height() < 308 {
        let h = chain.height() + 1;
        let b = chain.mine_block(bonder_addr, Vec::new(), mts(h)).unwrap();
        chain.submit(b).unwrap();
    }
    let mut view = NodeL2::replay_from(&chain, &params).unwrap();
    for seed in [2u8, 3, 1] {
        assert_eq!(
            view.state().balance(&addr_of(&wallet(seed))),
            100_000_000,
            "deposits matured on chain"
        );
    }

    // Post-bond lifecycle under the bonded key alone: one signature meets
    // a one-member quorum. Fully replayable — every sat is chain-derived.
    let bonded = vec![(bond_sk, bond_pk)];
    let post_id = mainnet_post_bond_lifecycle(&mut chain, &mut view, &bonded);
    assert!(view.state().task(&post_id).is_some());
    assert_eq!(view.state().vwc_count(), 1);

    // Fresh replay and incremental follow agree on the funded history; the
    // view-only pre-bond lifecycle skips deterministically (no credits on a
    // fresh replay), while the deposit-funded post-bond lifecycle applies.
    let replayed = NodeL2::replay_from(&chain, &params).unwrap();
    assert!(replayed.state().task(&post_id).is_some());
    assert!(replayed.state().task(&pre_id).is_none());
    assert_eq!(replayed.state().vwc_count(), 1);
    assert!(replayed
        .skipped()
        .iter()
        .any(|s| matches!(s.error, L2Error::InsufficientBalance { .. })));
    let mut followed = NodeL2::fresh(&params).unwrap();
    followed.sync(&chain).unwrap();
    assert_eq!(followed.state(), replayed.state());
    assert_eq!(followed.applied_count(), replayed.applied_count());

    // A bootstrap-only quorum for a post-bond task is refused: 15 signatures
    // over the old 21-key set verify against nothing now. (Bitmap positions
    // beyond the one-member set resolve to no signer, and the declared count
    // disagrees with the resolved one — `BadQuorum`, never applied.)
    for (seed, amount) in [(4u8, 100_000_000), (5u8, 100_000_000), (6u8, 100_000_000)] {
        view.state_mut()
            .credit(wallet(seed).address().unwrap(), amount)
            .unwrap();
    }
    let tx_post = L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&wallet(4), 41, PAYMENT_SAT, 1200, task(41, 1200)).unwrap(),
    ));
    let stale_id = post_task_id(&tx_post);
    mine_l2_mainnet(&mut chain, &mut view, vec![tx_post], 600_000);
    mine_l2_mainnet(&mut chain, &mut view, vec![claim(5, stale_id)], 600_000);
    mine_l2_mainnet(
        &mut chain,
        &mut view,
        vec![submit_result(5, stale_id)],
        600_000,
    );
    mine_l2_mainnet(&mut chain, &mut view, vec![dispute(6, stale_id)], 600_000);
    let h = chain.height();
    // A 15-of-21 bootstrap quorum, built exactly as the pre-bond path
    // builds it — now verified against the one-member bonded set.
    let boot = srct_node::l2::validator_set(&params);
    assert_eq!(boot.quorum_size(), 15);
    let stale_settle = signed_settle(
        &boot,
        &committee,
        stale_id,
        &chain.params().network_id.clone(),
        h,
    );
    let skipped_before = view.skipped().len();
    mine_l2_mainnet(&mut chain, &mut view, vec![stale_settle], 600_000);
    assert_eq!(view.skipped().len(), skipped_before + 1);
    assert!(
        matches!(view.skipped().last().unwrap().error, L2Error::BadQuorum),
        "bootstrap-only quorum post-bond must be refused, got {:?}",
        view.skipped().last().unwrap().error
    );
    assert_eq!(view.state().vwc_count(), 1, "no certificate issues");
}
