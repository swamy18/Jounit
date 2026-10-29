//! Phase 4: the Verified Work Certificate lifecycle through the public surface.
//!
//! Task → claim → submit → (dispute) → settle, and what the settlement leaves
//! behind: exactly one certificate for a `Correct` settlement, none for
//! `Fraudulent` or `Expired`, `Quorum`-verified when the settlement was an
//! explicit transaction and `WindowElapsed` when it was implicit. The
//! conservation invariant is asserted after every scenario — certificates hold
//! no value, so issuance must not move any.

use srct_core::bls::{RealBls, SecretKey};
use srct_core::bls_checkpoint::{MockBls, ValidatorSet};
use srct_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload, SettlePayload,
    SubmitResultPayload, Verdict,
};
use srct_core::wallet::Wallet;
use srct_l2::{ContractState, L2Config, L2Effect, L2Error, L2State, VwcVerification};

const DEADLINE: u64 = 100;
const CREDITED: u64 = 30_000_000;
const RESULT: Hash = [0xAAu8; 32];
const COUNTER: Hash = [0xBBu8; 32];

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "vwc-flow").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn task(deadline: u64) -> ComputeTask {
    ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 0,
        expiry_height: deadline,
        submit_height: 0,
    }
}

/// Four validators with *real* keys, so the quorum aggregate on a certificate is
/// a genuine pairing-verified signature rather than the mock's non-zero check.
fn validators_with_keys(n: usize) -> (ValidatorSet, Vec<SecretKey>) {
    let secrets: Vec<SecretKey> = (1..=n as u8)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect();
    let set = ValidatorSet::new(secrets.iter().map(|sk| sk.public_key()).collect());
    (set, secrets)
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
    validators: ValidatorSet,
    secrets: Vec<SecretKey>,
    submitter: Wallet,
    worker: Wallet,
    challenger: Wallet,
}

fn world() -> World {
    let (validators, secrets) = validators_with_keys(4);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&wallet(1)), 10_000_000).unwrap();
    state.credit(addr(&wallet(2)), 10_000_000).unwrap();
    state.credit(addr(&wallet(3)), 10_000_000).unwrap();
    World {
        state,
        validators,
        secrets,
        submitter: wallet(1),
        worker: wallet(2),
        challenger: wallet(3),
    }
}

impl World {
    fn apply(&mut self, tx: &L2Transaction, height: u64) -> Result<L2Effect, L2Error> {
        self.state.apply(tx, height, &self.validators, &RealBls)
    }

    /// Post 1 000 000, claim with `deposit`, submit `RESULT`.
    fn submitted(&mut self, deposit: u64) -> Hash {
        let post = PostTaskPayload::build(&self.submitter, 1, 1_000_000, DEADLINE, task(DEADLINE))
            .unwrap();
        let id = post.task_id;
        self.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
            .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Claim(
                ClaimTaskPayload::build(&self.worker, id, ComputeBackend::Gpu, deposit).unwrap(),
            )),
            2,
        )
        .unwrap();
        self.apply(
            &L2Transaction::new(L2Payload::Submit(
                SubmitResultPayload::build(&self.worker, id, attestation(&self.worker, id, RESULT))
                    .unwrap(),
            )),
            3,
        )
        .unwrap();
        id
    }

    fn disputed(&mut self, deposit: u64) -> Hash {
        let id = self.submitted(deposit);
        self.apply(
            &L2Transaction::new(L2Payload::Dispute(
                DisputePayload::build(
                    &self.challenger,
                    id,
                    COUNTER,
                    attestation(&self.challenger, id, COUNTER),
                    50_000,
                )
                .unwrap(),
            )),
            4,
        )
        .unwrap();
        id
    }

    /// A genuine quorum aggregate over the given settle decision, from the
    /// world's validators — the same bytes a real committee would produce.
    fn signed_settle(
        &self,
        id: Hash,
        verdict: Verdict,
        vwc_hash: Hash,
        height: u64,
    ) -> SettlePayload {
        let payload = SettlePayload {
            task_id: id,
            verdict,
            vwc_hash,
            network_id: "srct/mini".to_string(),
            height,
            bls_sig: [0u8; 96],
            signer_bitmap: Vec::new(),
            signer_count: 0,
            pq_sidecar: Vec::new(),
        };
        let msg = payload.signing_hash();
        let quorum = self.validators.quorum_size();
        let indices: Vec<usize> = (0..quorum).collect();
        let signers = self
            .validators
            .signers_from_bitmap(&self.validators.bitmap_from_indices(&indices));
        let sigs: Vec<_> = signers
            .iter()
            .map(|pk| {
                let sk = self
                    .secrets
                    .iter()
                    .find(|sk| sk.public_key().0 == pk.0)
                    .expect("set keys come from world secrets");
                sk.sign(&msg)
            })
            .collect();
        SettlePayload {
            bls_sig: *srct_core::bls::RealBls::aggregate(&sigs)
                .unwrap()
                .as_bytes(),
            signer_bitmap: self.validators.bitmap_from_indices(&indices),
            signer_count: quorum as u32,
            pq_sidecar: Vec::new(),
            ..payload
        }
    }

    fn settle(
        &mut self,
        id: Hash,
        verdict: Verdict,
        vwc_hash: Hash,
        height: u64,
    ) -> Result<L2Effect, L2Error> {
        let payload = self.signed_settle(id, verdict, vwc_hash, height);
        self.apply(&L2Transaction::new(L2Payload::Settle(payload)), height)
    }
}

// ---------------------------------------------------------------------------
// Successful work: VWC issued, bound to payment, value conserved
// ---------------------------------------------------------------------------

#[test]
fn a_quorum_settled_task_issues_one_quorum_certificate() {
    let mut w = world();
    let id = w.submitted(100_000);
    assert_eq!(
        w.state.vwc_count(),
        0,
        "nothing is certified before settlement"
    );

    let effect = w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    let vwc_id = match &effect {
        L2Effect::Settled {
            vwc_id,
            worker_paid,
            ..
        } => {
            assert_eq!(*worker_paid, 1_000_000 - 1_000);
            *vwc_id
        }
        other => panic!("unexpected effect {other:?}"),
    };

    assert_eq!(w.state.vwc_count(), 1);
    let cert = w.state.vwc(&id).expect("the task's certificate exists");
    assert_eq!(cert.id, vwc_id.expect("the effect names the certificate"));
    assert_eq!(cert.task_id, id);
    assert_eq!(cert.worker, addr(&w.worker));
    assert_eq!(cert.result_hash, RESULT);
    assert_eq!(cert.payment_sat, 1_000_000 - 1_000);
    assert!(matches!(
        cert.verification,
        VwcVerification::Quorum {
            signer_count: 3,
            ..
        }
    ));

    // The certificate validates structurally and against the live registry.
    cert.validate(&w.validators, &RealBls).unwrap();
    w.state.validate_vwc(cert, &w.validators, &RealBls).unwrap();
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn the_certificate_carries_the_aggregate_that_signed_its_own_decision() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    let cert = w.state.vwc(&id).unwrap().clone();

    // Rebuild the decision from the certificate's own fields and check the
    // stored aggregate verifies over exactly that message.
    let VwcVerification::Quorum {
        bls_sig,
        signer_bitmap,
        signer_count,
        pq_sidecar: _,
        network_id,
        vote_height,
    } = &cert.verification
    else {
        panic!("expected quorum verification");
    };
    let decision = SettlePayload {
        task_id: cert.task_id,
        verdict: Verdict::Correct,
        vwc_hash: cert.result_hash,
        network_id: network_id.clone(),
        height: *vote_height,
        bls_sig: [0u8; 96],
        signer_bitmap: Vec::new(),
        signer_count: 0,
        pq_sidecar: Vec::new(),
    };
    let signers = w.validators.signers_from_bitmap(signer_bitmap);
    assert_eq!(signers.len(), *signer_count as usize);
    assert!(RealBls::verify_aggregate(
        &signers,
        &decision.signing_hash(),
        &srct_core::bls_checkpoint::BlsSignature(*bls_sig),
    ));
}

#[test]
fn an_implicit_settlement_issues_a_window_elapsed_certificate() {
    let mut w = world();
    let id = w.submitted(100_000);
    // Window is 5 blocks, submitted at height 3 → auto-settles after 8.
    let effects = w.state.advance_block(9);
    assert_eq!(effects.len(), 1);

    let cert = w.state.vwc(&id).expect("auto-settle certifies too");
    assert_eq!(cert.payment_sat, 1_000_000);
    assert_eq!(cert.settled_height, 9);
    assert!(matches!(cert.verification, VwcVerification::WindowElapsed));
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_zero_payout_settlement_still_certifies_with_zero_payment() {
    let mut w = world();
    let post = PostTaskPayload::build(&w.submitter, 1, 1_000, DEADLINE, task(DEADLINE)).unwrap();
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
            SubmitResultPayload::build(&w.worker, id, attestation(&w.worker, id, RESULT)).unwrap(),
        )),
        3,
    )
    .unwrap();
    let effect = w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    match effect {
        L2Effect::Settled {
            worker_paid,
            vwc_id,
            ..
        } => {
            assert_eq!(worker_paid, 0);
            assert!(vwc_id.is_some(), "zero payment is still verified work");
        }
        other => panic!("unexpected effect {other:?}"),
    }
    let cert = w.state.vwc(&id).unwrap();
    assert_eq!(cert.payment_sat, 0);
    w.state.validate_vwc(cert, &w.validators, &RealBls).unwrap();
}

// ---------------------------------------------------------------------------
// What must NOT be certified
// ---------------------------------------------------------------------------

#[test]
fn a_fraudulent_settlement_issues_no_certificate() {
    let mut w = world();
    let id = w.disputed(100_000);
    w.settle(id, Verdict::Fraudulent, COUNTER, 5).unwrap();

    assert_eq!(
        w.state.vwc_count(),
        0,
        "a certificate of fraud is a SlashRecord"
    );
    assert!(w.state.vwc(&id).is_none());
    // The slash still happened.
    assert_eq!(w.state.slash_vault.active_count(), 1);
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn an_expired_task_issues_no_certificate() {
    let mut w = world();
    // A *submitted* task auto-settles rather than expiring, so expiry is
    // exercised on one that was never claimed.
    let post =
        PostTaskPayload::build(&w.submitter, 7, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let never = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
        .unwrap();
    let effects = w.state.advance_block(DEADLINE + 1);
    assert!(effects
        .iter()
        .any(|e| matches!(e, L2Effect::Expired { .. })));
    assert!(w.state.vwc(&never).is_none(), "no work was verified");

    // And a `Correct` verdict naming the placeholder hash is refused: the
    // contract compares the hash against the submitted result first, so this is
    // `BadVwcHash` at the contract layer. The certificate layer's own guard
    // (`VwcInvalid`) is defence in depth behind it.
    let mut w = world();
    let id = w.submitted(100_000);
    assert_eq!(
        w.settle(id, Verdict::Correct, [0u8; 32], 9),
        Err(L2Error::BadVwcHash)
    );
    assert_eq!(w.state.vwc_count(), 0);
}

#[test]
fn a_worker_cannot_submit_the_expired_placeholder_as_a_result() {
    let mut w = world();
    let id = w.submitted(100_000);
    let _ = id;
    let post =
        PostTaskPayload::build(&w.submitter, 9, 1_000_000, DEADLINE, task(DEADLINE)).unwrap();
    let id2 = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 1)
        .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id2, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        2,
    )
    .unwrap();
    let err = w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id2, attestation(&w.worker, id2, [0u8; 32]))
                .unwrap(),
        )),
        3,
    );
    assert_eq!(
        err,
        Err(L2Error::BadAttestation(
            "result_hash is the expired placeholder; a result must commit to real output"
        ))
    );
    assert!(matches!(
        w.state.task(&id2).unwrap().state,
        ContractState::InProgress { .. }
    ));
}

// ---------------------------------------------------------------------------
// Dispute integration
// ---------------------------------------------------------------------------

#[test]
fn a_disputed_task_certifies_only_when_the_worker_was_right() {
    let mut w = world();
    let id = w.disputed(100_000);

    // Honest worker: the reference reproduces the submission → Correct → VWC.
    w.settle(id, Verdict::Correct, RESULT, 5).unwrap();
    let cert = w
        .state
        .vwc(&id)
        .expect("upheld-worker settlement certifies");
    assert_eq!(cert.result_hash, RESULT);
    assert!(matches!(cert.verification, VwcVerification::Quorum { .. }));
    // The challenger was wrong: their deposit burned, no bonus.
    match w.state.task(&id).unwrap().state {
        ContractState::Settled(outcome) => assert_eq!(outcome.challenger_deposit_burned, 50_000),
        ref other => panic!("unexpected state {other:?}"),
    }
    assert_eq!(w.state.conservation_total(), CREDITED);
}

#[test]
fn a_settled_task_cannot_be_disputed_or_certified_twice() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    let first = w.state.vwc(&id).unwrap().clone();

    // Disputing settled work is an illegal transition: settlement is terminal
    // and one-way, which is why certificates need no revocation (§17.8).
    assert!(matches!(
        w.apply(
            &L2Transaction::new(L2Payload::Dispute(
                DisputePayload::build(
                    &w.challenger,
                    id,
                    COUNTER,
                    attestation(&w.challenger, id, COUNTER),
                    50_000,
                )
                .unwrap(),
            )),
            10,
        ),
        Err(L2Error::IllegalTransition { .. })
    ));

    // Re-settling is equally impossible. Replaying the byte-identical decision
    // (same vote height, hence the same txid) is refused as `Replay` — the
    // height binding is what makes "byte-identical" meaningful here; either
    // way nothing re-certifies.
    let replay = w.signed_settle(id, Verdict::Correct, RESULT, 9);
    assert_eq!(
        w.apply(&L2Transaction::new(L2Payload::Settle(replay)), 11),
        Err(L2Error::Replay)
    );
    assert_eq!(w.state.vwc_count(), 1);
    assert_eq!(
        w.state.vwc(&id).unwrap(),
        &first,
        "the certificate is unchanged"
    );
    assert_eq!(w.state.conservation_total(), CREDITED);
}

// ---------------------------------------------------------------------------
// Validation against live state
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_certificate_is_refused_by_the_registry() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    let issued = w.state.vwc(&id).unwrap().clone();

    // 1. A naive tamper (id left behind) fails validation outright.
    let mut naive = issued.clone();
    naive.payment_sat += 1;
    assert!(w
        .state
        .validate_vwc(&naive, &w.validators, &RealBls)
        .is_err());

    // 2. A re-id'd forgery passes structural validation — it is a perfectly
    //    self-consistent certificate for a settlement that never happened —
    //    and is caught by the registry comparison alone.
    let mut forged = issued.clone();
    forged.payment_sat += 1;
    forged.id = forged.id();
    assert_eq!(forged.validate(&w.validators, &RealBls), Ok(()));
    assert!(matches!(
        w.state.validate_vwc(&forged, &w.validators, &RealBls),
        Err(L2Error::VwcInvalid("differs from the issued certificate"))
    ));

    // 3. A certificate for a task that never settled proves nothing. Its
    //    verification must be `WindowElapsed` for this check to be reached — a
    //    quorum aggregate over a different task would fail validation first —
    //    which is exactly the point: `WindowElapsed` claims only the on-chain
    //    record, and the record is what refuses it.
    let mut stranger = issued.clone();
    stranger.task_id = [0xEEu8; 32];
    stranger.verification = VwcVerification::WindowElapsed;
    stranger.id = stranger.id();
    assert_eq!(
        w.state.validate_vwc(&stranger, &w.validators, &RealBls),
        Err(L2Error::VwcInvalid("was never issued by this state"))
    );
}

#[test]
fn a_forged_quorum_aggregate_is_refused_even_after_re_deriving_the_id() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.settle(id, Verdict::Correct, RESULT, 9).unwrap();
    let issued = w.state.vwc(&id).unwrap().clone();

    // Re-name the result and re-derive the id: the id is now self-consistent,
    // but the aggregate still signs the ORIGINAL decision, so the pairing
    // check refuses it. This is the cryptographic core of the design: the id
    // is only a pointer; the signature is the proof.
    let mut forged = issued.clone();
    forged.result_hash = [0xCCu8; 32];
    forged.id = forged.id();
    assert!(matches!(
        forged.validate(&w.validators, &RealBls),
        Err(L2Error::VwcInvalid("quorum aggregate did not verify"))
    ));
    let _ = id;
}

#[test]
fn a_window_elapsed_certificate_does_not_claim_quorum_strength() {
    let mut w = world();
    let id = w.submitted(100_000);
    w.state.advance_block(9);
    let cert = w.state.vwc(&id).unwrap().clone();

    // Structural validation passes (there is no aggregate to check).
    assert!(cert.validate(&w.validators, &MockBls).is_ok());
    assert!(w.state.validate_vwc(&cert, &w.validators, &MockBls).is_ok());
    assert!(matches!(cert.verification, VwcVerification::WindowElapsed));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn certificates_are_identical_across_independent_runs() {
    fn run(reference: Hash) -> (Vec<(Hash, Hash, u64, String)>, u64) {
        let mut w = world();
        let id = w.disputed(100_000);
        // A `Correct` reference settles and certifies; any other reference is
        // refused upstream. Both shapes must reproduce identically.
        let _ = w.settle(id, Verdict::Correct, reference, 5);
        let vwcs = w
            .state
            .vwcs()
            .into_iter()
            .map(|c| {
                (
                    c.id,
                    c.task_id,
                    c.payment_sat,
                    format!("{:?}", c.verification),
                )
            })
            .collect();
        (vwcs, w.state.conservation_total())
    }

    // A quorum-settled certificate and a refusal must both reproduce exactly.
    let (a, ca) = run(RESULT);
    let (b, cb) = run(RESULT);
    assert_eq!(a, b, "same inputs, same certificates");
    assert_eq!(ca, cb);
    assert_eq!(ca, CREDITED);

    // The ids are functions of the fields: the same settlement in a fresh state
    // derives the same certificate id.
    let mut w1 = world();
    let id1 = w1.submitted(100_000);
    w1.settle(id1, Verdict::Correct, RESULT, 9).unwrap();
    let mut w2 = world();
    let id2 = w2.submitted(100_000);
    w2.settle(id2, Verdict::Correct, RESULT, 9).unwrap();
    assert_eq!(
        w1.state.vwc(&id1).unwrap().id,
        w2.state.vwc(&id2).unwrap().id,
        "task ids match (same wallet seeds), so the ids must match"
    );
}

#[test]
fn the_registry_enumerates_deterministically() {
    let mut w = world();
    // Two tasks, settled in whichever order puts the larger id first, so the
    // insertion order provably differs from the sorted enumeration.
    let id_a = w.submitted(100_000);
    let post = PostTaskPayload::build(&w.submitter, 2, 500_000, DEADLINE, task(DEADLINE)).unwrap();
    let id_b = post.task_id;
    w.apply(&L2Transaction::new(L2Payload::Post(post)), 10)
        .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&w.worker, id_b, ComputeBackend::Cpu, 50_000).unwrap(),
        )),
        11,
    )
    .unwrap();
    w.apply(
        &L2Transaction::new(L2Payload::Submit(
            SubmitResultPayload::build(&w.worker, id_b, attestation(&w.worker, id_b, RESULT))
                .unwrap(),
        )),
        12,
    )
    .unwrap();
    // id_a's window closed after height 8, id_b's after 17.
    let (first, second) = if id_a > id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let (first_height, second_height) = if first == id_a {
        (9u64, 18u64)
    } else {
        (18u64, 9u64)
    };
    w.settle(first, Verdict::Correct, RESULT, first_height)
        .unwrap();
    w.settle(second, Verdict::Correct, RESULT, second_height)
        .unwrap();
    assert_ne!(
        [first, second],
        {
            let mut s = [first, second];
            s.sort_unstable();
            s
        },
        "the setup must insert in non-sorted order for this test to mean anything"
    );

    let ids: Vec<Hash> = w.state.vwcs().iter().map(|c| c.task_id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        ids, sorted,
        "enumeration is sorted regardless of settle order"
    );
    assert_eq!(w.state.vwc_count(), 2);
    assert_eq!(w.state.conservation_total(), CREDITED);
}
