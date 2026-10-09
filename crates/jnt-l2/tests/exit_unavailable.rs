//! There is no L2 → L1 exit, and this file pins that as a property of the code
//! rather than a claim in a document.
//!
//! `docs/l2-exit-design.md` records the blocker: a release requires a **new L1
//! consensus rule**, because the deposit sink has no spender (proven in
//! `jnt-core/tests/sink_unspendable.rs`). Until that rule is decided, the honest
//! statements are:
//!
//! 1. **No withdrawal transaction type exists.** The L2 wire has exactly five
//!    type bytes. A withdrawal-shaped byte is refused at decode time, so it can
//!    never reach the state machine, the mempool, or a block.
//! 2. **Value never leaves L2.** `L2State::funded_total` is append-only, and
//!    `conservation_total() == funded_total` means every satoshi that entered L2
//!    is still inside one of L2's buckets after a full settlement lifecycle.
//!    Nothing debits an account *to L1*.
//!
//! These are the negative halves of an exit implementation. When the exit rule
//! is approved, `funded_total` gains a decrement path and *these tests must
//! change* — which is precisely why they are written down: a change that breaks
//! them is a consensus change, and it should be impossible to make one by
//! accident.

use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use jnt_core::error::Error;
use jnt_core::hash::{Address, Hash};
use jnt_core::l2::{
    ClaimTaskPayload, L2Payload, L2Transaction, L2TxType, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict, L2_TX_CLAIM, L2_TX_DISPUTE, L2_TX_POST, L2_TX_SETTLE,
    L2_TX_SUBMIT,
};
use jnt_core::wallet::Wallet;
use jnt_l2::{L2Config, L2State};

// ---------------------------------------------------------------------------
// 1. The wire format admits five types and nothing else
// ---------------------------------------------------------------------------

/// Exhaustive over every possible type byte: exactly the five known values are
/// accepted, and every other byte is refused **by name**.
///
/// The failure mode this defends against is silent: if a future edit taught the
/// decoder to treat some byte as a withdrawal, this test would fail at the byte
/// that changed rather than at the point where value escaped.
#[test]
fn exactly_five_l2_transaction_types_exist_and_none_is_a_withdrawal() {
    let known = [
        L2_TX_POST,
        L2_TX_CLAIM,
        L2_TX_SUBMIT,
        L2_TX_DISPUTE,
        L2_TX_SETTLE,
    ];
    let mut accepted = Vec::new();
    for byte in 0u8..=255 {
        match L2TxType::from_wire(byte) {
            Ok(t) => accepted.push(t),
            Err(e) => {
                // Refused *by name*, not with a generic decode failure.
                assert!(
                    matches!(&e, Error::Malformed(m) if *m == "unknown L2 transaction type"),
                    "byte {byte:#04x} must be refused by name, got {e:?}"
                );
            }
        }
    }
    assert_eq!(accepted.len(), 5, "exactly five L2 transaction types exist");
    assert_eq!(
        accepted,
        vec![
            L2TxType::PostTask,
            L2TxType::ClaimTask,
            L2TxType::SubmitResult,
            L2TxType::Dispute,
            L2TxType::Settle,
        ]
    );
    // The type byte immediately after the highest defined one — where a
    // withdrawal would go — is refused.
    assert!(L2TxType::from_wire(L2_TX_SETTLE + 1).is_err());
    assert_eq!(known.len(), 5);
}

/// A withdrawal-shaped payload cannot get past the decoder, so it can never
/// reach `L2State::apply`, a mempool, or a block body.
#[test]
fn a_withdrawal_shaped_payload_is_refused_at_decode_time() {
    // A well-formed envelope header (version 1) carrying an undefined type byte.
    for byte in [L2_TX_SETTLE + 1, 0x00, 0x7f, 0xff] {
        let mut bytes = vec![1u8, 0, 0, 0]; // version = 1, little-endian
        bytes.push(byte);
        bytes.extend_from_slice(&[0u8; 64]); // payload bytes a decoder might read
        let err = L2Transaction::deserialize(&bytes)
            .expect_err("an undefined L2 type byte must never decode");
        assert!(
            err.to_string().contains("unknown L2 transaction type"),
            "type byte {byte:#04x} must be named in the refusal, got {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Value never leaves L2
// ---------------------------------------------------------------------------

const DEADLINE: u64 = 100;
/// `world()` credits two accounts (submitter and worker) at 10 JNT each.
const CREDITED: u64 = 20_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "exit-unavailable").unwrap()
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
        expiry_height: DEADLINE,
        submit_height: 0,
    }
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
}

fn settle_payload(
    task_id: Hash,
    verdict: Verdict,
    vwc_hash: Hash,
    signed: usize,
    total: usize,
) -> SettlePayload {
    let n_bytes = total.div_ceil(8).max(1);
    let mut bitmap = vec![0u8; n_bytes];
    for i in 0..signed {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    SettlePayload {
        task_id,
        verdict,
        vwc_hash,
        bls_sig: [0xAAu8; 96],
        signer_bitmap: bitmap,
        signer_count: signed as u32,
    }
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

fn world() -> World {
    let submitter = wallet(1);
    let worker = wallet(2);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&submitter), 10_000_000).unwrap();
    state.credit(addr(&worker), 10_000_000).unwrap();
    World {
        state,
        submitter,
        worker,
        validators: validators(4),
        verifier: MockBls,
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) {
        self.state
            .apply(tx, height, &self.validators, &self.verifier)
            .expect("a well-formed step of the lifecycle");
    }

    /// `funded_total` is the invariant under test: append-only, so a decrease
    /// would mean value left L2.
    fn assert_closed(&self, step: &str, expected_funded: u64) {
        assert_eq!(
            self.state.funded_total(),
            expected_funded,
            "{step}: released value changed — value entered or left L2"
        );
        assert!(
            self.state.check_conservation(),
            "{step}: conservation broken (conservation_total {} != funded_total {})",
            self.state.conservation_total(),
            self.state.funded_total()
        );
    }
}

/// A complete lifecycle — funded post, claim, submit, explicit quorum settle —
/// moves value between L2 buckets and never out of L2.
///
/// Every step asserts `funded_total` is unchanged and conservation holds. The
/// worker ends with real spendable balance and the escrow is empty: the money is
/// entirely inside L2 at the end, with no route to L1.
#[test]
fn value_never_leaves_l2_across_a_full_settlement_lifecycle() {
    let mut w = world();
    let funded = w.state.funded_total();
    assert_eq!(funded, CREDITED);

    let post = PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task()).unwrap();
    let id = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1);
    w.assert_closed("post", funded);

    let claim = ClaimTaskPayload::build(&w.worker, id, ComputeBackend::Gpu, 50_000).unwrap();
    w.apply(&L2Transaction::new(L2Payload::Claim(claim)), 2);
    w.assert_closed("claim", funded);

    let result = [0xAAu8; 32];
    let submit =
        SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, result)).unwrap();
    w.apply(&L2Transaction::new(L2Payload::Submit(submit)), 3);
    w.assert_closed("submit", funded);

    let settle = settle_payload(id, Verdict::Correct, result, 3, w.validators.len());
    w.apply(&L2Transaction::new(L2Payload::Settle(settle)), 9);
    w.assert_closed("settle", funded);

    // The lifecycle actually completed and paid the worker: this is not a test
    // that passes because nothing happened.
    assert!(w.state.total_locked() == 0, "escrow must be fully released");
    assert!(
        w.state.balance(&addr(&w.worker)) > 10_000_000,
        "the worker must have been paid"
    );
    // And every satoshi is still inside L2 — accounts plus the fee buckets.
    assert_eq!(w.state.conservation_total(), funded);
}

/// The accumulated L2 fees are burned or parked in PSCB, never moved to L1:
/// the fee path is a *reduction inside L2*, not a payment out of it.
#[test]
fn l2_fees_reduce_l2_buckets_and_never_reach_l1() {
    let mut w = world();
    let funded = w.state.funded_total();
    let post = PostTaskPayload::build(&w.submitter, 1, 1_000_000, DEADLINE, task()).unwrap();
    let id = post.task_id;
    let fee = L2Transaction::new(L2Payload::Post(post.clone())).fee_sat();
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1);

    // The D3 flat fee splits 50/50: half burns, half accrues to PSCB. Both are
    // buckets *inside* L2, which is what makes a fee a reduction rather than an
    // exit channel. `pscb` gets the floor half, `burned` the odd satoshi.
    assert_eq!(w.state.pscb, fee / 2, "half the post fee accrues to PSCB");
    assert_eq!(w.state.burned, fee - fee / 2, "the rest is burned in L2");
    w.assert_closed("post fee", funded);
    assert!(w.state.task(&id).is_some());
}

/// The protocol escrow identity holds an L2 balance and has no key — the same
/// structural fact as the L1 sink, on the L2 side.
#[test]
fn the_l2_escrow_identity_has_no_key_and_no_withdrawal_path() {
    use jnt_core::params::{NetworkParams, SAT_PER_JNT};
    use jnt_l2::{L2Genesis, L2State};

    let params = NetworkParams::mini();
    let mut state = L2State::new(L2Config::mini());
    state
        .apply_genesis(&L2Genesis::for_params(&params))
        .unwrap();

    let escrow = params.l2_escrow_address();
    // The escrow identity is funded at genesis and never again.
    assert!(state.balance(&escrow) > 0);
    assert_eq!(
        state.balance(&escrow),
        params.l2_genesis_escrow_sat - 3 * SAT_PER_JNT
    );
    // It is a derived address: no wallet in a sample owns it.
    for seed in 1..=8u8 {
        assert_ne!(addr(&wallet(seed)), escrow);
    }
    // And there is no L2 type that pays it out — the five type bytes above are
    // the complete set.
    assert!(state.check_conservation());
}
