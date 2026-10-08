//! The scripted end-to-end journey — roadmap items 13/14, the "one complete
//! journey" deliverable.
//!
//! Everything below runs against the *real* node path: L2 transactions are
//! carried inside genuine mined L1 blocks, accepted by `Chain::submit`, and
//! applied by `NodeL2::sync`, exactly as a running node does — the clock
//! advances first, then the block's payload, per `jnt-l2`'s replay rules.
//! Nothing is applied by hand to a detached `L2State`. The worker side runs the
//! real `WorkerClient` (discover → claim → execute → submit) over the §18.3
//! seams, whose broadcaster queues into the same block-building pipeline.
//!
//! The journey, in order:
//!
//! ```text
//! human owner ─signs─▶ SpendPolicy ─▶ machine agent identity
//!        │                                   │
//!        └─▶ PaymentRequest ─▶ PolicyBook ─▶ Authorization
//!                                                 │
//!   service (provider) ◀── service payment ◀──────┘
//!        │
//!        ├─▶ L2 PostTask (escrow)
//!        │      └─▶ worker discovers ─▶ claims ─▶ executes ─▶ submits
//!        ├─▶ challenger files a Dispute
//!        ├─▶ arbitrator quorum Settle(Correct) ─▶ VWC (Quorum)
//!        ├─▶ ServiceReceipt (bound to the payment, anchored to the settled block)
//!        └─▶ Reputation: VerifiedWork + DisputeWon + ServiceCompleted + PaymentCompleted
//!                                   │
//!                            finality ─▶ persist ─▶ restart ─▶ identical state
//! ```
//!
//! Run with `cargo test -p jnt-node --test e2e_journey`.
//!
//! ## Why the dispute is in the main line
//!
//! An undisputed submission cannot be settled by an explicit `Settle`: a
//! `Correct` verdict on a `ResultSubmitted` contract is only *settleable* once
//! the window has closed (`TaskContract::correct_settlement_hash`), and at
//! exactly that height the window's own auto-settlement fires first. So the
//! quorum path — the one that yields an offline-verifiable `Quorum` certificate
//! — only exists over a **disputed** task, where the arbitrator decides inside
//! the window. The undisputed path (window elapses → `WindowElapsed` VWC) is the
//! second test in this file, and both are the same protocol.
//!
//! ## Profile
//!
//! `NetworkParams::mini()`, deliberately: it is the profile the L2 module tests
//! already use, it carries the genesis L2 grants that fund the three L2 actors,
//! and its five-block dispute window keeps the journey inside one test run. The
//! `testnet` profile carries no L2 grants, so funding there needs the (already
//! tested) deposit-and-mature path; nothing here is profile-specific except
//! those numbers, all of which are read from `params` at runtime.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use jnt_core::agent::{
    derive_agent_id, AgentRole, Authorization, PolicyBook, SpendPolicy, POLICY_VERSION,
};
use jnt_core::block::{Block, GENESIS_TIMESTAMP_MS};
use jnt_core::bls::{RealBls, SecretKey};
use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::chain::Chain;
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    Auth, ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload,
    SettlePayload, Verdict,
};
use jnt_core::params::{mini_committee_secrets, NetworkParams, SAT_PER_JNT};
use jnt_core::payment::{build_signed_payment, MachinePayment, PaymentTracker};
use jnt_core::receipt::{
    sign_receipt, ReceiptAnchor, ReceiptBook, ReceiptOutcome, ServiceReceipt, RECEIPT_VERSION,
};
use jnt_core::reputation::ReputationKind;
use jnt_core::service::{
    authorize_request, build_signed_request, derive_service_id, PaymentRequest, RequestSpec,
    Session,
};
use jnt_core::sig::Bundle;
use jnt_core::wallet::Wallet;
use jnt_l2::reputation::ledger_from_state;
use jnt_l2::{ContractState, L2Config, L2State, VwcVerification};
use jnt_node::l2::NodeL2;
use jnt_store::BlockStore;
use jnt_worker::node::{BroadcastError, Host, L2Broadcaster, L2NodeView};
use jnt_worker::{CpuExecutor, WorkerClient, WorkerConfig, WorkerResult};

const MAX_ATTEMPTS: u64 = 4_000_000;
/// What the service charges the agent, in satoshis.
const SERVICE_PRICE_SAT: u64 = 1_200_000;
/// What the service escrows on L2 for the compute it is buying.
const COMPUTE_ESCROW_SAT: u64 = 1_000_000;
/// What the worker locks against its claim.
const WORKER_DEPOSIT_SAT: u64 = 100_000;
/// What the challenger locks against its challenge.
const CHALLENGE_DEPOSIT_SAT: u64 = 50_000;
/// L2 deadline every task in this journey posts with.
const TASK_DEADLINE: u64 = 400;

// ---------------------------------------------------------------------------
// Wallets: one owner, one service/provider, one worker, one challenger
// ---------------------------------------------------------------------------

/// The owner's wallet. It is the *human* identity and the payer of record; the
/// machine identity the policy governs is derived from this same address, which
/// is exactly the role separation the policy layer defines (§6).
fn owner() -> Wallet {
    Wallet::from_private_key_bytes(&[21u8; 32], "journey-owner").unwrap()
}

/// The funded L2 operator that also acts as the *service*: it posts the compute
/// task (mini grants seed 1) and issues the receipt.
fn provider() -> Wallet {
    Wallet::from_private_key_bytes(&[1u8; 32], "journey-provider").unwrap()
}

/// The funded L2 operator that does the work (mini grants seed 2).
fn worker() -> Wallet {
    Wallet::from_private_key_bytes(&[2u8; 32], "journey-worker").unwrap()
}

/// A funded L2 operator that challenges the work (mini grants seed 3).
fn challenger() -> Wallet {
    Wallet::from_private_key_bytes(&[3u8; 32], "journey-challenger").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

// ---------------------------------------------------------------------------
// The node under test
// ---------------------------------------------------------------------------

/// A real chain plus its L2 projection, driven by the test. The worker SDK sees
/// it only through the §18.3 seams, below.
struct Node {
    chain: Chain,
    view: NodeL2,
    params: NetworkParams,
    /// L2 transactions the SDK broadcast, waiting for the next block — the
    /// queue a live node's mempool would hold.
    queued: Vec<L2Transaction>,
}

impl Node {
    fn new(params: NetworkParams) -> Self {
        let chain = Chain::new(params.clone()).unwrap();
        let mut view = NodeL2::fresh(&params);
        view.sync(&chain);
        Node {
            chain,
            view,
            params,
            queued: Vec::new(),
        }
    }

    fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Mine the queued L2 transactions into the next block, accept it, and let
    /// the node's L2 view apply it. This is the whole write path.
    fn mine_queued(&mut self) -> Block {
        let l2 = std::mem::take(&mut self.queued);
        self.mine_l2(l2)
    }

    /// Mine and sync, requiring that the node's L2 replay accepted everything.
    fn mine_l2(&mut self, l2: Vec<L2Transaction>) -> Block {
        let block = self.mine_l2_raw(l2);
        assert!(
            self.view.is_clean(),
            "the node's own L2 replay refused nothing: {:?}",
            self.view.skipped()
        );
        block
    }

    /// Mine and sync without that expectation — for blocks that deliberately
    /// carry an invalid payload, where a refusal is the point.
    fn mine_l2_raw(&mut self, l2: Vec<L2Transaction>) -> Block {
        let h = self.chain.height() + 1;
        let block = self
            .chain
            .mine_block_with_l2([9u8; 20], Vec::new(), l2, ts(h), None, MAX_ATTEMPTS)
            .expect("a block we just mined must build");
        self.chain
            .submit(block.clone())
            .expect("it must be accepted");
        self.view.sync(&self.chain);
        block
    }

    fn mine_empty(&mut self) -> Block {
        self.mine_l2(Vec::new())
    }
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Read seam. Clones the authoritative state — observation is a query.
struct View(Rc<RefCell<Node>>);

impl L2NodeView for View {
    fn l2_state(&self) -> WorkerResult<L2State> {
        Ok(self.0.borrow().view.state().clone())
    }
    fn chain_height(&self) -> WorkerResult<u64> {
        Ok(self.0.borrow().chain.height())
    }
}

/// Write seam. Hands an already-signed transaction to the node's block builder;
/// the test mines it. A live node's broadcast is the same "accepted, not yet
/// final" contract.
struct Net(Rc<RefCell<Node>>);

impl L2Broadcaster for Net {
    fn broadcast(&mut self, tx: &L2Transaction) -> Result<(), BroadcastError> {
        self.0.borrow_mut().queued.push(tx.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Journey helpers
// ---------------------------------------------------------------------------

fn mini_validators() -> ValidatorSet {
    ValidatorSet::new(NetworkParams::mini().genesis_validators)
}

/// A quorum settle transaction signed by the profile's real committee, i.e.
/// what the arbitrator set would broadcast. The validators are the node's own,
/// so the aggregate verifies inside `NodeL2::sync`.
fn quorum_settle(task_id: Hash, verdict: Verdict, vwc_hash: Hash) -> L2Transaction {
    let validators = mini_validators();
    let secrets = mini_committee_secrets();
    let payload = SettlePayload {
        task_id,
        verdict,
        vwc_hash,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
    };
    let msg = payload.signing_hash();
    let quorum = validators.quorum_size();
    let bitmap = validators.bitmap_from_indices(&(0..quorum).collect::<Vec<_>>());
    let signers = validators.signers_from_bitmap(&bitmap);
    let sigs: Vec<_> = signers
        .iter()
        .map(|pk| {
            let sk = secrets
                .iter()
                .find(|sk: &&SecretKey| sk.public_key().0 == pk.0)
                .expect("the profile's committee secrets back its own keys");
            sk.sign(&msg)
        })
        .collect();
    let payload = SettlePayload {
        bls_sig: *RealBls::aggregate(&sigs).unwrap().as_bytes(),
        signer_bitmap: bitmap,
        signer_count: quorum as u32,
        ..payload
    };
    L2Transaction::new(L2Payload::Settle(payload))
}

/// A worker's signed attestation over `result` for `task_id`.
fn attestation(
    w: &Wallet,
    task_id: Hash,
    result: Hash,
    backend: ComputeBackend,
) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend,
        worker_address: addr(w),
        attest_height: 0,
        signature: Vec::new(),
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

fn compute_task(task_id: Hash, backend: ComputeBackend) -> ComputeTask {
    ComputeTask {
        task_id,
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: backend,
        reward_sat: 0,
        expiry_height: TASK_DEADLINE,
        submit_height: 0,
    }
}

/// The submitted result hash the protocol recorded for `task_id`.
fn submitted_result(state: &L2State, task_id: &Hash) -> Hash {
    match &state.task(task_id).expect("task exists").state {
        ContractState::ResultSubmitted { result_hash, .. } => *result_hash,
        other => panic!("expected a submitted result, found {other:?}"),
    }
}

/// A worker client over the live node.
fn worker_client(node: &Rc<RefCell<Node>>) -> WorkerClient<View, Net, CpuExecutor> {
    let w = worker();
    WorkerClient::new(
        Host::new(View(Rc::clone(node)), Net(Rc::clone(node))),
        w.clone(),
        CpuExecutor::default(),
        mini_validators(),
        &RealBls,
    )
    .with_config(WorkerConfig::from_wallet(&w).with_deposit(WORKER_DEPOSIT_SAT))
    .expect("config agrees with the wallet")
}

// ---------------------------------------------------------------------------
// Test 1: the whole journey, dispute path (Quorum certificate)
// ---------------------------------------------------------------------------

#[test]
fn the_full_journey_agent_to_settlement_vwc_receipt_reputation_finality() {
    let params = NetworkParams::mini();
    let node = Rc::new(RefCell::new(Node::new(params.clone())));
    let net = params.network_id.clone();
    assert_eq!(net, "jounit/mini");

    // --- 1. chain start ----------------------------------------------------
    node.borrow_mut().mine_empty();
    assert_eq!(node.borrow().height(), 1);

    // --- 2. agent identity -------------------------------------------------
    // One owner, role-separated identities. The machine agent that will spend
    // is derived from the owner's address, so identity is a pure function —
    // never a registration.
    let owner_addr = addr(&owner());
    let human_id = derive_agent_id(&net, AgentRole::Human, &owner_addr);
    let machine_id = derive_agent_id(&net, AgentRole::Machine, &owner_addr);
    assert_ne!(human_id, machine_id, "roles must not share an identity");
    assert_ne!(
        machine_id,
        derive_agent_id("jounit/testnet", AgentRole::Machine, &owner_addr),
        "an identity must be network-bound"
    );

    // --- 3. the owner grants a spend policy --------------------------------
    let service_addr = addr(&provider());
    let service_id = derive_service_id(&net, &service_addr, b"jounit-compute");
    let policy = SpendPolicy {
        version: POLICY_VERSION,
        network_id: net.clone(),
        agent_id: machine_id,
        owner: owner_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: SERVICE_PRICE_SAT,
        window_blocks: 10,
        cumulative_max_sat: 3 * SERVICE_PRICE_SAT,
        allowed_recipients: vec![service_addr],
        allowed_services: vec![service_id],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
    };
    policy.validate().expect("the grant is well-formed");

    // The owner signs the grant; verification is offline and public-only.
    let policy_sigs = Auth::sigs_for(&owner(), &policy.signing_hash()).unwrap();
    let policy_keys = Auth::keys_for(&owner()).unwrap();
    jnt_core::sig::verify_bundle(&policy_sigs, &policy_keys, &policy.signing_hash())
        .expect("the owner's own signature must verify against the policy");

    // --- 4. the agent asks the service for work ----------------------------
    let request: PaymentRequest = build_signed_request(
        &owner(),
        RequestSpec {
            network_id: net.clone(),
            payer_type: AgentRole::Machine,
            service_id,
            recipient: service_addr,
            max_amount_sat: SERVICE_PRICE_SAT,
            expires_at_height: 9_000,
            policy_hash: policy.hash(),
        },
    )
    .expect("the payer-signed request builds");
    request
        .verify(&net, node.borrow().height())
        .expect("and self-verifies");

    // --- 5. authorization: the only path from request to money -------------
    let mut book = PolicyBook::default();
    let auth: Authorization = authorize_request(
        &mut book,
        &policy,
        &net,
        &request,
        node.borrow().height(),
        1,
    )
    .expect("an in-policy grant");
    assert_eq!(auth.amount_sat, SERVICE_PRICE_SAT);
    assert_eq!(auth.service, Some(service_id));
    let auth_sigs: Bundle = Auth::sigs_for(&owner(), &auth.signing_hash()).unwrap();
    let auth_keys: Bundle = Auth::keys_for(&owner()).unwrap();

    // A replayed nonce must not grant a second time.
    assert!(
        authorize_request(
            &mut book,
            &policy,
            &net,
            &request,
            node.borrow().height(),
            1
        )
        .is_err(),
        "a replayed nonce is refused"
    );

    // --- 6. the service buys compute on L2 ---------------------------------
    let submitter = provider();
    let post = PostTaskPayload::build(
        &submitter,
        1,
        COMPUTE_ESCROW_SAT,
        TASK_DEADLINE,
        compute_task([0x44u8; 32], ComputeBackend::Cpu),
    )
    .expect("a valid post");
    let task_id = post.task_id;
    let post_fee = jnt_core::l2::L2TxType::PostTask.fee_sat();
    node.borrow_mut()
        .mine_l2(vec![L2Transaction::new(L2Payload::Post(post))]);
    let posted_at = node.borrow().height();
    assert_eq!(
        node.borrow().view.state().balance(&addr(&submitter)),
        SAT_PER_JNT - COMPUTE_ESCROW_SAT - post_fee,
        "exactly the escrow plus the post fee left the submitter's balance"
    );

    // --- 7. the worker discovers and claims --------------------------------
    let mut client = worker_client(&node);
    let found = client.discover().expect("discovery reads the node");
    assert!(
        found.iter().any(|t| t.task_id == task_id),
        "the posted task must be discoverable, found {:?}",
        found.iter().map(|t| t.task_id).collect::<Vec<_>>()
    );

    let claim = client.claim(task_id).expect("the claim broadcasts");
    assert_eq!(claim.task_id, task_id);
    node.borrow_mut().mine_queued();
    let claimed_at = node.borrow().height();
    assert_eq!(
        node.borrow().view.state().task(&task_id).unwrap().worker,
        Some(addr(&worker())),
        "the claim names the worker"
    );

    // --- 8. execute and submit ---------------------------------------------
    let submission = client
        .execute_and_submit(task_id)
        .expect("execute + submit broadcasts");
    assert_eq!(submission.task_id, task_id);
    assert_eq!(submission.worker, addr(&worker()));
    node.borrow_mut().mine_queued();
    let submitted_at = node.borrow().height();
    let result_hash = submitted_result(node.borrow().view.state(), &task_id);
    assert_eq!(submission.result_hash, result_hash);
    assert!(
        submitted_at > claimed_at && submitted_at > posted_at,
        "the lifecycle advances one block at a time"
    );

    // --- 9. a challenger files a dispute -----------------------------------
    // The counter-attestation claims a different result; the arbitrator will
    // uphold the worker. Filed inside the window (submitted + 5).
    let counter_hash = [0xEEu8; 32];
    assert_ne!(counter_hash, result_hash);
    let dispute = DisputePayload::build(
        &challenger(),
        task_id,
        counter_hash,
        attestation(&challenger(), task_id, counter_hash, ComputeBackend::Cpu),
        CHALLENGE_DEPOSIT_SAT,
    )
    .expect("a well-formed challenge");
    node.borrow_mut()
        .mine_l2(vec![L2Transaction::new(L2Payload::Dispute(dispute))]);
    let disputed_at = node.borrow().height();
    assert!(
        disputed_at <= submitted_at + L2Config::mini().dispute_window,
        "the challenge lands inside the filing window"
    );
    assert!(matches!(
        node.borrow().view.state().task(&task_id).unwrap().state,
        ContractState::Disputed(_)
    ));

    // --- 10. the arbitrator settles, and the VWC it issues -----------------
    node.borrow_mut()
        .mine_l2(vec![quorum_settle(task_id, Verdict::Correct, result_hash)]);
    let settled_at = node.borrow().height();
    assert!(settled_at > disputed_at);

    let cert = client
        .certificate(&task_id)
        .expect("certificate observation")
        .expect("a correct settlement certifies");
    assert_eq!(cert.task_id, task_id);
    assert_eq!(cert.worker, addr(&worker()));
    assert_eq!(cert.result_hash, result_hash);
    assert_eq!(cert.payment_sat, COMPUTE_ESCROW_SAT - 20_000);
    assert!(
        matches!(cert.verification, VwcVerification::Quorum { .. }),
        "an explicit settle carries the quorum aggregate"
    );

    // The worker was right: it is paid, its deposit returns, and the baseless
    // challenge costs the challenger its whole deposit.
    let e = client.earnings().expect("the node's state is readable");
    assert_eq!(
        e.settled_sat,
        COMPUTE_ESCROW_SAT - 20_000 + WORKER_DEPOSIT_SAT
    );
    assert_eq!(e.lost_sat, 0);
    assert_eq!(e.pending_sat, 0);

    // --- 11. the service is paid, and issues a receipt ---------------------
    let payment: MachinePayment = build_signed_payment(
        &owner(),
        &auth,
        &net,
        AgentRole::Machine,
        2_000,
        8_000,
        request.request_id(),
    )
    .expect("a payment linked to the grant");
    payment.verify(&net, settled_at).expect("it verifies");
    payment.linked_to(&auth).expect("and is bound to the grant");

    // Replayed payment bytes must not be accepted twice.
    let mut paid = PaymentTracker::default();
    paid.observe(&payment.signing_hash(), payment.expires_at_height)
        .expect("first sighting");
    assert_eq!(
        paid.observe(&payment.signing_hash(), payment.expires_at_height)
            .unwrap_err(),
        jnt_core::payment::PaymentError::AlreadySeen,
        "a duplicate payment is refused by name"
    );

    // The receipt anchors to the exact block that settled the work, and its
    // `result_hash` is the result the worker actually submitted — one artifact
    // chain from the agent's payment to the machine that ran the job.
    let settled_hash = node
        .borrow()
        .chain
        .block_hash_at(settled_at)
        .expect("the settled block is canonical");
    let mut receipt = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: net.clone(),
        payer: payment.payer,
        payer_role: payment.payer_type,
        agent_id: payment.agent_id,
        recipient: payment.recipient,
        service_id: payment.service,
        amount_sat: payment.amount_sat,
        payment_id: payment.signing_hash(),
        request_id: request.request_id(),
        result_hash: Some(result_hash),
        anchor: Some(ReceiptAnchor {
            height: settled_at,
            block_hash: settled_hash,
        }),
        keys: Bundle::default(),
        sigs: Bundle::default(),
    };
    sign_receipt(&mut receipt, &provider()).expect("the issuer signs");
    receipt.verify(&net).expect("the receipt verifies offline");
    receipt
        .verify_binding(&payment)
        .expect("and binds to the payment");

    Session::new(&request)
        .with_authorization(&auth, &auth_sigs, &auth_keys)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(&net, settled_at)
        .expect("request → authorization → payment → receipt must verify end to end");

    let mut receipts = ReceiptBook::default();
    assert_eq!(
        receipts.accept(&receipt, &net).unwrap(),
        ReceiptOutcome::Inserted
    );
    assert_eq!(
        receipts.accept(&receipt, &net).unwrap(),
        ReceiptOutcome::Duplicate,
        "the same receipt is idempotent, not a second sale"
    );

    // --- 12. reputation, derived from what actually happened ---------------
    let mut ledger = ledger_from_state(node.borrow().view.state(), &net)
        .expect("the ledger derives from canonical state");
    ledger
        .apply_receipt(&receipt, &net)
        .expect("the verified receipt is the only way receipt-backed standing is minted");

    let worker_subject = derive_agent_id(&net, AgentRole::Machine, &addr(&worker()));
    let service_subject = derive_agent_id(&net, AgentRole::Service, &service_addr);
    assert_eq!(
        ledger.score(&worker_subject).unwrap().by_kind[ReputationKind::VerifiedWork as usize],
        1,
        "the quorum settlement is exactly one VerifiedWork event"
    );
    assert_eq!(
        ledger.score(&worker_subject).unwrap().by_kind[ReputationKind::DisputeWon as usize],
        1,
        "winning the challenge is a separate, named event"
    );
    assert_eq!(
        ledger.score(&service_subject).unwrap().by_kind[ReputationKind::ServiceCompleted as usize],
        1
    );
    assert_eq!(
        ledger.score(&payment.agent_id).unwrap().by_kind[ReputationKind::PaymentCompleted as usize],
        1
    );
    assert_eq!(
        ledger.score(&worker_subject).unwrap().score,
        ReputationKind::VerifiedWork.weight() + ReputationKind::DisputeWon.weight()
    );

    // Replaying the receipt cannot mint a second event.
    assert!(ledger.apply_receipt(&receipt, &net).is_err());

    // --- 13. conservation and finality -------------------------------------
    let state = node.borrow().view.state().clone();
    assert!(
        state.check_conservation(),
        "value is conserved across the run"
    );
    assert_eq!(state.funded_total(), params.l2_genesis_escrow_sat);

    let depth = params.finality_depth;
    for _ in 0..depth + 2 {
        node.borrow_mut().mine_empty();
    }
    let finalized = node.borrow().chain.finalized_height();
    assert!(
        finalized >= settled_at,
        "the settling block must be final: finalized {finalized} < settled {settled_at}"
    );

    // --- 14. restart: the whole thing reconstructs -------------------------
    let dir = temp_store_dir();
    persist(&node.borrow(), &dir);
    let before_state = node.borrow().view.state().clone();
    let before_ledger = ledger.clone();
    drop(client);
    drop(node);

    let reloaded = reload(&dir, &params);
    let recovered = NodeL2::replay_from(&reloaded, &params);

    assert_eq!(
        recovered.state(),
        &before_state,
        "a restarted node reaches byte-identical L2 state"
    );
    assert!(recovered.state().check_conservation());
    let rederived = ledger_from_state(recovered.state(), &net).expect("rederivation");
    assert_eq!(
        rederived.score(&worker_subject),
        before_ledger.score(&worker_subject),
        "reputation re-derives from state, never from stored bookkeeping"
    );
    let recovered_cert = recovered
        .state()
        .vwc(&task_id)
        .expect("the certificate survived restart");
    assert_eq!(recovered_cert.id, cert.id);
    assert_eq!(recovered_cert.result_hash, result_hash);
    assert_eq!(reloaded.finalized_height(), finalized);
}

// ---------------------------------------------------------------------------
// Test 2: the undisputed path — window elapses, WindowElapsed certificate
// ---------------------------------------------------------------------------

#[test]
fn the_undisputed_path_pays_through_the_windows_own_settlement() {
    let params = NetworkParams::mini();
    let node = Rc::new(RefCell::new(Node::new(params.clone())));
    let net = params.network_id.clone();
    assert_eq!(net, "jounit/mini");
    node.borrow_mut().mine_empty();

    let submitter = provider();
    let post = PostTaskPayload::build(
        &submitter,
        7,
        COMPUTE_ESCROW_SAT,
        TASK_DEADLINE,
        compute_task([0x55u8; 32], ComputeBackend::Cpu),
    )
    .unwrap();
    let task_id = post.task_id;
    node.borrow_mut()
        .mine_l2(vec![L2Transaction::new(L2Payload::Post(post))]);

    let mut client = worker_client(&node);
    client.claim(task_id).expect("claim");
    node.borrow_mut().mine_queued();
    client.execute_and_submit(task_id).expect("submit");
    node.borrow_mut().mine_queued();
    let submitted_at = node.borrow().height();
    let result_hash = submitted_result(node.borrow().view.state(), &task_id);

    // Nobody challenges. Mine past the window; the task settles itself.
    // (The clock advances before each block's payload, so the settlement lands
    // in the block *after* the window closes.)
    while node.borrow().height() <= submitted_at + L2Config::mini().dispute_window {
        node.borrow_mut().mine_empty();
    }

    let cert = client
        .certificate(&task_id)
        .expect("observation")
        .expect("the window's settlement certifies");
    assert!(
        matches!(cert.verification, VwcVerification::WindowElapsed),
        "an implicit settlement carries no aggregate"
    );
    assert_eq!(
        cert.payment_sat, COMPUTE_ESCROW_SAT,
        "implicit settlement pays no settle fee"
    );
    assert_eq!(cert.result_hash, result_hash);
    assert_eq!(
        cert.settled_height,
        submitted_at + L2Config::mini().dispute_window + 1
    );

    let e = client.earnings().expect("the node's state is readable");
    assert_eq!(e.settled_sat, COMPUTE_ESCROW_SAT + WORKER_DEPOSIT_SAT);
    assert_eq!(e.lost_sat, 0);
    assert!(node.borrow().view.state().check_conservation());
}

// ---------------------------------------------------------------------------
// Test 3: an unsupported claim is refused, and changes nothing
// ---------------------------------------------------------------------------

#[test]
fn a_forged_claim_fails_closed_through_the_node() {
    let params = NetworkParams::mini();
    let node = Rc::new(RefCell::new(Node::new(params.clone())));
    node.borrow_mut().mine_empty();

    let post = PostTaskPayload::build(
        &provider(),
        3,
        COMPUTE_ESCROW_SAT,
        TASK_DEADLINE,
        compute_task([0x66u8; 32], ComputeBackend::Cpu),
    )
    .unwrap();
    let task_id = post.task_id;
    node.borrow_mut()
        .mine_l2(vec![L2Transaction::new(L2Payload::Post(post))]);
    let before = node.borrow().view.state().clone();

    // A claim signed by the worker but naming a worker address the wallet does
    // not control: `ClaimTaskPayload::build` signs the body, so swapping the
    // address after signing is exactly the forgery the node must refuse.
    let mut forged =
        ClaimTaskPayload::build(&worker(), task_id, ComputeBackend::Cpu, WORKER_DEPOSIT_SAT)
            .unwrap();
    forged.worker = addr(&challenger());
    let claimed_height = node.borrow().height() + 1;
    node.borrow_mut()
        .mine_l2_raw(vec![L2Transaction::new(L2Payload::Claim(forged))]);

    // The node skipped it by name, and the state is untouched.
    let node_ref = node.borrow();
    let skipped = node_ref.view.skipped();
    assert_eq!(skipped.len(), 1, "exactly the forged claim was refused");
    assert_eq!(skipped[0].height, claimed_height);
    assert!(
        matches!(
            node_ref.view.state().task(&task_id).unwrap().state,
            ContractState::Open
        ),
        "the task is still open — a refused claim changes nothing"
    );
    assert_eq!(node_ref.view.state().task(&task_id).unwrap().worker, None);
    assert_eq!(node_ref.view.state(), &before);
}

// ---------------------------------------------------------------------------
// Restart plumbing (the same shape `jnt-node` uses on disk)
// ---------------------------------------------------------------------------

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store_dir() -> PathBuf {
    let id = STORE_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("jnt-e2e-journey-{}-{id}", std::process::id()))
}

/// Persist every canonical block, plus the finalized point, the way a node does.
fn persist(node: &Node, dir: &std::path::Path) {
    let params = node.params.clone();
    let (mut bs, _) = BlockStore::open(dir, &params).unwrap();
    for h in 1..=node.chain.height() {
        bs.append_block(node.chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&node.chain.tip_hash()).unwrap();
    if let Some((fh, fhash)) = node.chain.finalized_point() {
        bs.set_finalized(fh, fhash).unwrap();
    }
    bs.sync().unwrap();
}

/// Rebuild the chain from the store alone — no in-memory state is carried.
fn reload(dir: &std::path::Path, params: &NetworkParams) -> Chain {
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
    if let Some((fh, fhash)) = bs.finalized() {
        assert!(
            chain.restore_finality(fh, fhash),
            "the persisted finality point must match the canonical chain"
        );
    }
    chain
}
