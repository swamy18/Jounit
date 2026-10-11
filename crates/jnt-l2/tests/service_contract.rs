//! Proof that the ServiceContract abstraction generalizes.
//!
//! `TaskContract` is `ServiceContract<ComputeDeliverable, ComputeAttestation>`, so
//! every compute test already exercises the generic type. What none of them do is
//! drive it with a deliverable that is *not* compute - until a second impl
//! exists, "generic" is a claim about the type signature and nothing more.
//!
//! This file exists so that a regression that welds the state machine back onto
//! `ComputeAttestation` fails to compile. That is the acceptance test for
//! `docs/roadmap-agent-economy.md` item 1: one settlement path, worked by more
//! than one kind of deliverable.

use jnt_core::deliverable::{Deliverable, SortAttestation, SortDeliverable};
use jnt_core::hash::{sha256, Address, Hash};
use jnt_l2::task_contract::{ContractState, ServiceContract};
use jnt_l2::L2Error;

fn addr(n: u8) -> Address {
    [n; 20]
}

/// A contract over the sort deliverable, in the same `Open` state a compute
/// contract would be in. Values chosen so the settle fee (0.1% of escrow, 1 000
/// sat floor) is well below the deposit, mirroring the compute fixture.
fn sort_contract(deposit: u64) -> ServiceContract<SortDeliverable, SortAttestation> {
    let deliverable = SortDeliverable {
        input_leaf: sha256(&[b"records to order"]),
        ascending: true,
    };
    let contract_id = sha256(&[b"a sort job"]);
    let min = jnt_core::l2::settle_fee_sat(5_000_000);
    assert!(
        deposit >= min,
        "the test's deposit must clear the settle fee, or the contract is unslashable"
    );
    ServiceContract {
        task_id: contract_id,
        submitter: addr(1),
        worker: None,
        deliverable,
        payment_sat: 5_000_000,
        worker_deposit_sat: deposit,
        deadline_height: 100,
        dispute_window: 5,
        nonce: 1,
        state: ContractState::Open,
    }
}

/// The deliberately-unslashable contract.
///
/// `TaskContract::claim` refuses a deposit below the settle fee, so a compute
/// contract can never be built this way. A sort contract has no `Post` to derive
/// one from, which means the caller is the only line of defence - this fixture
/// exists to show what that line has to prevent, not to model a reachable state.
fn unslashable_contract() -> ServiceContract<SortDeliverable, SortAttestation> {
    let mut c = sort_contract_raw();
    c.worker_deposit_sat = 1;
    c
}

/// Identical to [`sort_contract`] without the bond-floor assertion, so a test can
/// model a contract the claim step would have refused.
fn sort_contract_raw() -> ServiceContract<SortDeliverable, SortAttestation> {
    let deliverable = SortDeliverable {
        input_leaf: sha256(&[b"records to order"]),
        ascending: true,
    };
    let contract_id = sha256(&[b"a sort job"]);
    ServiceContract {
        task_id: contract_id,
        submitter: addr(1),
        worker: None,
        deliverable,
        payment_sat: 5_000_000,
        worker_deposit_sat: 0,
        deadline_height: 100,
        dispute_window: 5,
        nonce: 1,
        state: ContractState::Open,
    }
}

#[test]
fn a_sort_deliverable_is_claimed_submitted_and_settled() {
    let mut c = sort_contract(10_000);
    let id = c.task_id;
    let worker = addr(2);

    // Claim: the deposit floor is the same rule compute enforces.
    let min = jnt_core::l2::settle_fee_sat(c.payment_sat);
    assert_eq!(min, 5_000);

    // The reference is computed under the *contract's* id, not the deliverable's
    // own - the trap that made honest settlements read as inconclusive once.
    let reference = c.reference();
    assert_ne!(reference, c.deliverable.task_id());
    assert_eq!(
        reference,
        c.deliverable.reference(&id),
        "the contract's id is authoritative"
    );

    // The worker claims, then submits a *correct* result.
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    let good = SortAttestation {
        task_id: id,
        result_hash: reference,
        worker_address: worker,
        signature: vec![1, 2, 3],
    };
    c.submit(worker, reference, good.clone(), 3).unwrap();
    assert!(
        matches!(c.state, ContractState::ResultSubmitted { .. }),
        "a correct result is accepted by the generic path"
    );

    // Nobody challenges, so the window elapses and it settles Correct.
    assert!(c.due_for_auto_settle(9), "window is 5 blocks from height 3");
    let outcome = c.auto_settle_correct(9).unwrap();
    assert_eq!(outcome.verdict, jnt_core::l2::Verdict::Correct);
    assert_eq!(outcome.worker_paid, 5_000_000, "auto-settle charges no fee");
    assert_eq!(
        outcome.worker_deposit_returned, 10_000,
        "an honest worker gets its bond back"
    );
}

#[test]
fn a_wrong_sort_result_is_slashable_by_the_same_machinery() {
    let mut c = sort_contract(10_000);
    let id = c.task_id;
    let worker = addr(2);
    let challenger = addr(4);

    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    let reference = c.reference();

    // The worker submits something that is not the reference.
    let wrong: Hash = sha256(&[b"a wrong ordering"]);
    assert_ne!(wrong, reference);
    let worker_claim = SortAttestation {
        task_id: id,
        result_hash: wrong,
        worker_address: worker,
        signature: vec![9, 9, 9],
    };
    c.submit(worker, wrong, worker_claim, 3).unwrap();

    // A truthful challenger files the reference. The same `dispute` transition
    // that a compute challenge uses, with a different attestation type.
    let counter = SortAttestation {
        task_id: id,
        result_hash: reference,
        worker_address: challenger,
        signature: vec![4, 4],
    };
    c.dispute(challenger, reference, counter, 500, 4).unwrap();
    assert!(
        matches!(c.state, ContractState::Disputed(_)),
        "the generic dispute transition accepts a non-compute attestation"
    );

    // And the Fraudulent verdict is reachable - which it would not be if the
    // deposit floor did not clear the settle fee.
    let outcome = c
        .settle(jnt_core::l2::Verdict::Fraudulent, reference, 5, 5_000)
        .unwrap();
    assert_eq!(
        outcome.submitter_refunded, 5_000_000,
        "the defrauded submitter is made whole"
    );
    assert_eq!(outcome.worker_deposit_slashed, 5_000);
    assert_eq!(
        outcome.challenger_refunded, 500,
        "the truthful challenger is repaid"
    );
}

#[test]
fn the_generic_transitions_refuse_the_same_illegal_moves() {
    let mut c = sort_contract(10_000);
    let worker = addr(2);

    // Cannot submit before being claimed.
    let a = SortAttestation {
        task_id: c.task_id,
        result_hash: sha256(&[b"x"]),
        worker_address: worker,
        signature: vec![1],
    };
    assert!(c.submit(worker, sha256(&[b"x"]), a, 2).is_err());

    // An attestation naming another worker is refused, so a claimant cannot
    // borrow someone else's claim.
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    let by_someone_else = SortAttestation {
        task_id: c.task_id,
        result_hash: c.reference(),
        worker_address: addr(7),
        signature: vec![1],
    };
    assert!(
        c.submit(worker, c.reference(), by_someone_else, 3).is_err(),
        "an attestation by someone other than the claiming worker is refused"
    );

    // An unsigned attestation attests to nothing.
    let unsigned = SortAttestation {
        task_id: c.task_id,
        result_hash: c.reference(),
        worker_address: worker,
        signature: Vec::new(),
    };
    assert!(
        c.submit(worker, c.reference(), unsigned, 3).is_err(),
        "an unsigned attestation is refused by shape"
    );

    // The expired placeholder is not a commitment.
    c.state = ContractState::InProgress { claimed_at: 2 };
    let placeholder = SortAttestation {
        task_id: c.task_id,
        result_hash: jnt_core::l2::VWC_HASH_EXPIRED,
        worker_address: worker,
        signature: vec![1],
    };
    assert!(
        c.submit(worker, jnt_core::l2::VWC_HASH_EXPIRED, placeholder, 3)
            .is_err(),
        "the expired placeholder must never read as a result"
    );
}

#[test]
fn a_dust_deposit_makes_fraud_slapping_unreachable() {
    // The escrow-theft guard from the security review is not compute-specific:
    // a contract whose bond cannot cover the settle fee is structurally
    // unslashable in exactly the same way, whatever the deliverable is.
    let mut c = unslashable_contract();
    let id = c.task_id;
    let worker = addr(2);
    let challenger = addr(4);
    c.worker = Some(worker);
    c.state = ContractState::InProgress { claimed_at: 2 };
    let reference = c.reference();

    let claim = SortAttestation {
        task_id: id,
        result_hash: reference,
        worker_address: worker,
        signature: vec![1],
    };
    c.submit(worker, reference, claim, 3).unwrap();

    // A truthful challenger files the reference, so the verdict path is open.
    // (The counter must differ from what was submitted, or the challenge is
    // pointless and is refused by name.)
    let truth: Hash = sha256(&[b"another ordering"]);
    let counter = SortAttestation {
        task_id: id,
        result_hash: truth,
        worker_address: challenger,
        signature: vec![2],
    };
    c.dispute(challenger, truth, counter, 500, 4).unwrap();
    assert!(matches!(c.state, ContractState::Disputed(_)));

    // With a 1-sat bond the Fraudulent verdict is refused - not because the
    // evidence is weak, but because there is nothing to take the fee from.
    // This is the state `TaskContract::claim` exists to prevent a contract
    // reaching in the first place.
    assert_eq!(
        c.settle(jnt_core::l2::Verdict::Fraudulent, truth, 5, 5_000),
        Err(L2Error::AmountTooSmallForFee {
            available: 1,
            fee: 5_000
        })
    );
    assert!(
        matches!(c.state, ContractState::Disputed(_)),
        "a refused settle must leave the contract untouched"
    );

    // And the same contract, bonded properly, slashes.
    c.worker_deposit_sat = 10_000;
    let outcome = c
        .settle(jnt_core::l2::Verdict::Fraudulent, truth, 5, 5_000)
        .expect("a properly bonded contract is slashable");
    assert_eq!(outcome.submitter_refunded, 5_000_000);
    assert_eq!(outcome.worker_deposit_slashed, 5_000);
}
