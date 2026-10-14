//! Decision 23 (P5) stress suite: the proportional settle fee at its boundary,
//! in bulk, and on the fraud path.
//!
//! The rule under test is `settle_fee_sat`: 0.1% of task value, minimum
//! 1,000 sat. Every test below goes through `L2State::apply` (the consensus
//! path), never `TaskContract::settle` directly with a hand-picked fee — the
//! point is that the state machine charges what the rule says.
//!
//! Run with `cargo test -p jnt-l2 --test settle_fee`.

use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use jnt_core::wallet::Wallet;
use jnt_l2::{ContractState, L2Config, L2Effect, L2Error, L2State};

const EXPIRY: u64 = 100_000;
const RESULT: Hash = [0xAAu8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "settle-fee").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn task() -> ComputeTask {
    ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 0,
        expiry_height: EXPIRY,
        submit_height: 0,
    }
}

fn validators() -> ValidatorSet {
    ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect())
}

fn quorum_bitmap() -> Vec<u8> {
    vec![0b111u8]
}

fn attestation(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
    let mut a = ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Gpu,
        worker_address: addr(w),
        attest_height: 0,
        signature: vec![],
    };
    a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
    a
}

struct World {
    state: L2State,
    submitter: Wallet,
    worker: Wallet,
    validators: ValidatorSet,
    verifier: MockBls,
}

fn world(submitter_funds: u64, worker_funds: u64) -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), submitter_funds).unwrap();
    state.credit(addr(&worker), worker_funds).unwrap();
    World {
        state,
        submitter,
        worker,
        validators: validators(),
        verifier: MockBls,
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<L2Effect, L2Error> {
        self.state
            .apply(tx, height, &self.validators, &self.verifier)
    }

    /// Post → claim → submit → settle(Correct) one task; return the paid amount.
    /// Settles after the dispute window elapses unchallenged (mini window is
    /// 5): an explicit Correct settle names the undisputed result.
    fn run_to_settle(&mut self, nonce: u64, payment: u64, height: u64) -> u64 {
        let post = PostTaskPayload::build(&self.submitter, nonce, payment, EXPIRY, task()).unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), height)
            .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
            )),
            height + 1,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(&self.worker, id, attestation(&self.worker, id, RESULT))
                    .unwrap(),
            )),
            height + 2,
        )
        .unwrap();
        let effect = self
            .apply(
                &L2Transaction::new(L2Payload::Settle(SettlePayload {
                    task_id: id,
                    verdict: Verdict::Correct,
                    vwc_hash: RESULT,
                    bls_sig: [0xAAu8; 96],
                    signer_bitmap: quorum_bitmap(),
                    signer_count: 3,
                    pq_sidecar: Vec::new(),
                })),
                height + 8,
            )
            .unwrap();
        match effect {
            L2Effect::Settled { worker_paid, .. } => {
                assert!(matches!(
                    self.state.task(&id).unwrap().state,
                    ContractState::Settled(_)
                ));
                worker_paid
            }
            other => panic!("unexpected effect {other:?}"),
        }
    }
}

#[test]
fn fee_boundary_exact_from_dust_to_whale() {
    let mut w = world(100_000_000, 10_000_000);
    // Below the floor the fee exceeds the value: refused, task untouched.
    let id = {
        let post = PostTaskPayload::build(&w.submitter, 1, 999, EXPIRY, task()).unwrap();
        let id = post.task_id;
        w.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
            .unwrap();
        w.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Cpu, 50_000).unwrap(),
            )),
            2,
        )
        .unwrap();
        w.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, RESULT))
                    .unwrap(),
            )),
            3,
        )
        .unwrap();
        id
    };
    assert_eq!(
        w.apply(
            &L2Transaction::new(L2Payload::Settle(SettlePayload {
                task_id: id,
                verdict: Verdict::Correct,
                vwc_hash: RESULT,
                bls_sig: [0xAAu8; 96],
                signer_bitmap: quorum_bitmap(),
                signer_count: 3,
                pq_sidecar: Vec::new(),
            })),
            9,
        ),
        Err(L2Error::AmountTooSmallForFee {
            available: 999,
            fee: 1_000
        })
    );

    // At and above the floor: escrow minus exactly the rule's fee.
    assert_eq!(w.run_to_settle(10, 1_000, 10), 0);
    assert_eq!(w.run_to_settle(11, 1_001, 20), 1);
    assert_eq!(w.run_to_settle(12, 1_000_000, 30), 999_000);
    assert_eq!(w.run_to_settle(13, 5_000_000, 40), 4_995_000);
}

#[test]
fn bulk_settlement_across_sizes_conserves_value_exactly() {
    // Fifty tasks across four orders of magnitude. Fees: 1k floor below 1M
    // escrow, 0.1% above — every sat accounted, none created.
    let sizes: [u64; 6] = [1_000, 5_000, 100_000, 1_000_000, 2_500_000, 10_000_000];
    let per_task_fees: [u64; 6] = [1_000, 1_000, 1_000, 1_000, 2_500, 10_000];
    let submitter_funds = 500_000_000u64;
    let credited = submitter_funds + 50_000_000;
    let mut w = world(submitter_funds, 50_000_000);

    let mut total_escrow = 0u64;
    let mut total_paid = 0u64;
    let mut total_fee = 0u64;
    for (i, (&payment, &fee)) in sizes.iter().zip(per_task_fees.iter()).enumerate() {
        for rep in 0..8u64 {
            let nonce = (i as u64) * 100 + rep + 1;
            let height = 10 + (i as u64) * 100 + rep * 10;
            let paid = w.run_to_settle(nonce, payment, height);
            assert_eq!(paid, payment - fee, "task value {payment}");
            total_escrow += payment;
            total_paid += paid;
            total_fee += fee;
        }
    }
    // 48 tasks settled (nonce 1..48 used once each — task ids unique).
    assert_eq!(total_paid + total_fee, total_escrow);
    assert_eq!(w.state.conservation_total(), credited);
    // The 50/50 fee split holds to the sat across the whole run — settle
    // fees plus the flat post/claim/submit fees every task paid.
    let flat_per_task = 5_000 + 2_000 + 2_000;
    let all_fees: Vec<u64> = per_task_fees
        .iter()
        .flat_map(|&fee| std::iter::repeat([flat_per_task, fee]).take(8).flatten())
        .collect();
    assert_eq!(all_fees.len(), 96);
    let expect_pscb: u64 = all_fees.iter().map(|f| f / 2).sum();
    let expect_burned: u64 = all_fees.iter().map(|f| f - f / 2).sum();
    assert_eq!(w.state.pscb, expect_pscb);
    assert_eq!(w.state.burned, expect_burned);
}

#[test]
fn fraud_fee_comes_from_task_value_not_deposit_size() {
    // A 10M task with a 100k deposit: the fee is 0.1% of the 10M task value
    // (10k), charged against the deposit — the submitter is still made whole.
    let mut w = world(30_000_000, 10_000_000);
    let post = PostTaskPayload::build(&w.submitter, 1, 10_000_000, EXPIRY, task()).unwrap();
    let id = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
        .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 100_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, RESULT)).unwrap(),
        )),
        3,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Dispute(
            jnt_core::l2::DisputePayload::build(
                &w.submitter,
                id,
                [0xBBu8; 32],
                attestation(&w.submitter, id, [0xBBu8; 32]),
                50_000,
            )
            .unwrap(),
        )),
        4,
    )
    .unwrap();
    // Settle fraudulent directly with a quorum payload carrying the counter
    // result: the M2 path slashes deposit minus the task-value fee.
    let effect = w
        .apply(
            &L2Transaction::new(L2Payload::Settle(SettlePayload {
                task_id: id,
                verdict: Verdict::Fraudulent,
                vwc_hash: [0xBBu8; 32],
                bls_sig: [0xAAu8; 96],
                signer_bitmap: quorum_bitmap(),
                signer_count: 3,
                pq_sidecar: Vec::new(),
            })),
            5,
        )
        .unwrap();
    match effect {
        L2Effect::Settled {
            submitter_refunded,
            worker_deposit_slashed,
            ..
        } => {
            assert_eq!(submitter_refunded, 10_000_000);
            assert_eq!(worker_deposit_slashed, 100_000 - 10_000);
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert_eq!(w.state.conservation_total(), 40_000_000);
}
