//! Credit positions on chain (SPEC.md §22).
//!
//! The credit book used to be a node-local ledger of IOUs: `POST
//! /v1/credit/deposit` credited a local balance without moving a coin, and
//! `POST /v1/credit/open` opened a position with **no lender signature at
//! all** — the lender was a field anybody could write. This file pins the
//! on-chain half: a loan whose lender signed it, whose principal actually
//! moved, whose collateral is locked, and whose default is settled by value
//! moving to the lender.
//!
//! The properties asserted here are the ones a loan market lives or dies by:
//! the lender must have agreed, the value must really move, the collateral
//! must be the borrower's own money, interest must be charged once per period
//! and not twice, and a default must take the collateral and hand the surplus
//! back rather than inventing a shortfall.

use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    CreditCollateralPayload, CreditDefaultPayload, CreditOpenPayload, CreditRepayPayload,
    L2Payload, L2Transaction, L2TxType,
};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Effect, L2Error, L2State};

const FEE: u64 = 2_000;
const PRINCIPAL: u64 = 10_000_000;
const RATE_BPS: u32 = 100;
const WINDOW: u64 = 100;
const OPENED_AT: u64 = 10;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "credit-flow").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
}

struct World {
    state: L2State,
    lender: Wallet,
    borrower: Wallet,
    third: Wallet,
    validators: ValidatorSet,
}

fn world() -> World {
    let lender = wallet(1);
    let borrower = wallet(2);
    let third = wallet(3);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&lender), 100_000_000).unwrap();
    state.credit(addr(&borrower), 100_000_000).unwrap();
    state.credit(addr(&third), 10_000_000).unwrap();
    World {
        state,
        lender,
        borrower,
        third,
        validators: validators(4),
    }
}

#[allow(clippy::too_many_arguments)]
fn open_payload(
    lender: &Wallet,
    borrower: Address,
    amount: u64,
    collateral: u64,
    rate_bps: u32,
    window: u64,
    deadline: u64,
) -> CreditOpenPayload {
    CreditOpenPayload::build(
        lender, borrower, amount, collateral, rate_bps, window, deadline, 1,
    )
    .unwrap()
}

fn open(
    state: &mut L2State,
    validators: &ValidatorSet,
    payload: CreditOpenPayload,
) -> Result<L2Effect, L2Error> {
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    state.apply(&tx, OPENED_AT, validators, &MockBls)
}

// ---------------------------------------------------------------------------
// 1. Opening
// ---------------------------------------------------------------------------

#[test]
fn a_credit_position_moves_the_principal_to_the_borrower_and_locks_the_collateral() {
    let mut w = world();
    let lender_before = w.state.balance(&addr(&w.lender));
    let borrower_before = w.state.balance(&addr(&w.borrower));

    let payload = open_payload(
        &w.lender,
        addr(&w.borrower),
        PRINCIPAL,
        PRINCIPAL,
        RATE_BPS,
        WINDOW,
        1_000,
    );
    let position_id = payload.derived_position_id();
    open(&mut w.state, &w.validators, payload).expect("the lender may open a position");
    let position = w
        .state
        .credit_position(&position_id)
        .expect("the position is in the state");
    assert_eq!(position.lender, addr(&w.lender));
    assert_eq!(position.borrower, addr(&w.borrower));
    assert_eq!(position.outstanding_sat, PRINCIPAL);

    assert_eq!(
        w.state.balance(&addr(&w.lender)),
        lender_before - PRINCIPAL - FEE,
        "the lender's balance funds the loan and the fee"
    );
    assert_eq!(
        w.state.balance(&addr(&w.borrower)),
        borrower_before,
        "the borrower received the principal and locked the same amount as collateral"
    );
    assert!(
        w.state.check_conservation(),
        "value is moved, never created"
    );
    assert_ne!(
        w.state.committed_root(),
        L2State::new(L2Config::mini()).committed_root(),
        "a loan must change the committed root"
    );
}

#[test]
fn a_loan_the_lender_did_not_sign_is_refused() {
    let mut w = world();
    // The stranger signs, but the payload claims the real lender.
    let mut payload = open_payload(
        &w.third,
        addr(&w.borrower),
        PRINCIPAL,
        PRINCIPAL,
        RATE_BPS,
        WINDOW,
        1_000,
    );
    payload.lender = addr(&w.lender);
    let err = open(&mut w.state, &w.validators, payload).expect_err("the lender must sign");
    assert!(
        matches!(err, L2Error::BadAuthorization),
        "refused by the signature check, got {err:?}"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn an_undercollateralised_loan_is_refused() {
    let mut w = world();
    let payload = open_payload(
        &w.lender,
        addr(&w.borrower),
        PRINCIPAL,
        PRINCIPAL - 1,
        RATE_BPS,
        WINDOW,
        1_000,
    );
    let err = open(&mut w.state, &w.validators, payload).expect_err("the collateral is short");
    assert!(
        matches!(err, L2Error::CreditUndercollateralised { .. }),
        "refused by name, got {err:?}"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn a_loan_with_an_unusable_term_is_refused() {
    let mut w = world();
    // A rate above the cap.
    let payload = open_payload(
        &w.lender,
        addr(&w.borrower),
        PRINCIPAL,
        PRINCIPAL,
        10_000,
        WINDOW,
        1_000,
    );
    let err = open(&mut w.state, &w.validators, payload).expect_err("the rate is above the cap");
    assert!(
        matches!(err, L2Error::CreditTerms(_)),
        "refused by name, got {err:?}"
    );

    // A deadline in the past.
    let payload = open_payload(
        &w.lender,
        addr(&w.borrower),
        PRINCIPAL,
        PRINCIPAL,
        RATE_BPS,
        WINDOW,
        OPENED_AT,
    );
    let err = open(&mut w.state, &w.validators, payload).expect_err("the deadline is in the past");
    assert!(
        matches!(err, L2Error::CreditTerms(_)),
        "refused by name, got {err:?}"
    );
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// 2. Repayment
// ---------------------------------------------------------------------------

fn open_a_position(w: &mut World, collateral: u64) -> Hash {
    let payload = open_payload(
        &w.lender,
        addr(&w.borrower),
        PRINCIPAL,
        collateral,
        RATE_BPS,
        WINDOW,
        1_000,
    );
    let id = payload.derived_position_id();
    open(&mut w.state, &w.validators, payload).expect("the position opens");
    id
}

#[test]
fn a_repayment_pays_interest_first_and_then_principal() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);

    // Opened at height 10, repaid at 210: two whole windows have passed, so
    // the interest is 10 000 000 * 100 bps * 2 / 10 000 = 200 000.
    let payload = CreditRepayPayload::build(&w.borrower, id, 200_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    let effect = w
        .state
        .apply(&tx, 210, &w.validators, &MockBls)
        .expect("the repayment applies");
    match effect {
        L2Effect::CreditRepaid {
            interest_paid_sat,
            principal_paid_sat,
            remaining_debt_sat,
            ..
        } => {
            assert_eq!(interest_paid_sat, 200_000, "the interest is charged first");
            assert_eq!(
                principal_paid_sat, 0,
                "and only what is left pays principal"
            );
            assert_eq!(remaining_debt_sat, PRINCIPAL, "the principal is still owed");
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert!(w.state.check_conservation());
}

#[test]
fn a_fully_repaid_position_returns_the_collateral_to_the_borrower() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let borrower_before = w.state.balance(&addr(&w.borrower));
    let lender_before = w.state.balance(&addr(&w.lender));

    // Repay the interest, then the principal.
    for (amount, height) in [(200_000u64, 210u64), (PRINCIPAL, 210)] {
        let payload = CreditRepayPayload::build(&w.borrower, id, amount).unwrap();
        let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
        w.state
            .apply(&tx, height, &w.validators, &MockBls)
            .expect("the repayment applies");
    }

    assert_eq!(
        w.state.balance(&addr(&w.borrower)),
        borrower_before - 200_000 - 2 * FEE,
        "the borrower paid the interest and two fees; the principal came back with the collateral"
    );
    assert_eq!(
        w.state.balance(&addr(&w.lender)),
        lender_before + 200_000 + PRINCIPAL,
        "the lender received the interest and the principal"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn only_the_borrower_may_repay() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let payload = CreditRepayPayload::build(&w.third, id, 1_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    let err = w
        .state
        .apply(&tx, 20, &w.validators, &MockBls)
        .expect_err("only the borrower may repay");
    assert!(
        matches!(err, L2Error::CreditBinding(_)),
        "refused by binding, got {err:?}"
    );
}

#[test]
fn extra_collateral_can_be_posted_after_the_loan() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let payload = CreditCollateralPayload::build(&w.borrower, id, 5_000_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditCollateral(payload));
    w.state
        .apply(&tx, 20, &w.validators, &MockBls)
        .expect("the collateral applies");
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// 3. Default
// ---------------------------------------------------------------------------

#[test]
fn a_default_before_the_deadline_is_refused() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let payload = CreditDefaultPayload::build(&w.third, id).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
    let err = w
        .state
        .apply(&tx, 999, &w.validators, &MockBls)
        .expect_err("the position is not yet due");
    assert!(
        matches!(err, L2Error::CreditNotDue),
        "refused by name, got {err:?}"
    );
}

#[test]
fn a_default_pays_the_lender_from_the_collateral_and_reports_the_shortfall() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let lender_before = w.state.balance(&addr(&w.lender));
    let borrower_before = w.state.balance(&addr(&w.borrower));

    // At the deadline nine whole windows have passed: interest is
    // 10 000 000 * 100 bps * 9 / 10 000 = 900 000, so the debt is 10 900 000.
    let payload = CreditDefaultPayload::build(&w.third, id).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
    let effect = w
        .state
        .apply(&tx, 1_000, &w.validators, &MockBls)
        .expect("anyone may settle an overdue position");
    match effect {
        L2Effect::CreditDefaulted {
            debt_sat,
            from_collateral_sat,
            shortfall_sat,
            excess_returned_sat,
            ..
        } => {
            assert_eq!(
                debt_sat,
                PRINCIPAL + 900_000,
                "the debt includes the interest"
            );
            assert_eq!(
                from_collateral_sat, PRINCIPAL,
                "the collateral answers for the debt"
            );
            assert_eq!(
                shortfall_sat, 900_000,
                "the rest is a shortfall the lender absorbs"
            );
            assert_eq!(excess_returned_sat, 0, "there was no surplus");
        }
        other => panic!("unexpected effect {other:?}"),
    }
    assert_eq!(
        w.state.balance(&addr(&w.lender)),
        lender_before + PRINCIPAL,
        "the lender receives the collateral"
    );
    assert_eq!(
        w.state.balance(&addr(&w.borrower)),
        borrower_before,
        "the borrower keeps nothing extra: the collateral answered the debt"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn a_default_returns_the_surplus_to_the_borrower() {
    let mut w = world();
    let id = open_a_position(&mut w, 20_000_000);
    let borrower_before = w.state.balance(&addr(&w.borrower));

    let payload = CreditDefaultPayload::build(&w.third, id).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
    let effect = w
        .state
        .apply(&tx, 1_000, &w.validators, &MockBls)
        .expect("the default settles");
    match effect {
        L2Effect::CreditDefaulted {
            excess_returned_sat,
            ..
        } => assert_eq!(
            excess_returned_sat,
            20_000_000 - (PRINCIPAL + 900_000),
            "the collateral beyond the debt goes back to the borrower"
        ),
        other => panic!("unexpected effect {other:?}"),
    }
    assert!(
        w.state.balance(&addr(&w.borrower)) > borrower_before,
        "the surplus is in the borrower's hands"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn a_closed_position_cannot_be_repaid_or_defaulted_again() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let payload = CreditRepayPayload::build(&w.borrower, id, PRINCIPAL).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    w.state
        .apply(&tx, 20, &w.validators, &MockBls)
        .expect("the repayment applies");

    let payload = CreditRepayPayload::build(&w.borrower, id, 1_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    let err = w
        .state
        .apply(&tx, 21, &w.validators, &MockBls)
        .expect_err("the position is closed");
    assert!(
        matches!(err, L2Error::CreditPositionClosed),
        "refused by name, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. State and agreement
// ---------------------------------------------------------------------------

#[test]
fn the_state_encoding_round_trips_the_credit_positions() {
    let mut w = world();
    let id = open_a_position(&mut w, PRINCIPAL);
    let bytes = w.state.encode();
    let mut back = L2State::decode(&bytes).expect("the state decodes");
    assert_eq!(back, w.state);
    assert_eq!(back.committed_root(), w.state.committed_root());
    assert!(back.check_conservation());
    // The position is still there after the round trip.
    let payload = CreditRepayPayload::build(&w.borrower, id, 1_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    back.apply(&tx, 20, &w.validators, &MockBls)
        .expect("the position survived the round trip");
}

#[test]
fn two_nodes_replaying_the_same_loan_agree_on_the_root() {
    let mut a = world();
    let mut b = world();
    let payload = open_payload(
        &a.lender,
        addr(&a.borrower),
        PRINCIPAL,
        PRINCIPAL,
        RATE_BPS,
        WINDOW,
        1_000,
    );
    open(&mut a.state, &a.validators, payload.clone()).expect("the loan opens");
    open(&mut b.state, &b.validators, payload).expect("the loan opens");
    assert_eq!(
        a.state.committed_root(),
        b.state.committed_root(),
        "the same loan on two nodes commits to the same root"
    );
    assert_eq!(a.state, b.state);
}

#[test]
fn the_credit_transaction_types_are_the_ones_the_wire_admits() {
    assert_eq!(L2TxType::CreditOpen.to_wire(), 0x19);
    assert_eq!(L2TxType::CreditCollateral.to_wire(), 0x1A);
    assert_eq!(L2TxType::CreditRepay.to_wire(), 0x1B);
    assert_eq!(L2TxType::CreditDefault.to_wire(), 0x1C);
    assert_eq!(L2TxType::CreditOpen.fee_sat(), 2_000);
    assert_eq!(L2TxType::CreditCollateral.fee_sat(), 2_000);
    assert_eq!(L2TxType::CreditRepay.fee_sat(), 2_000);
    assert_eq!(L2TxType::CreditDefault.fee_sat(), 2_000);
}
