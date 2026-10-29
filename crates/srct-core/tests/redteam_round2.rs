//! Red-team round 2: credit-book reservation accounting.
//!
//! Three defects found by attacking the book rather than reading it:
//!
//! 1. A reservation that drew on position headroom left the payer's free
//!    balance untouched, so the same free value could back a second admitted
//!    payment while the first also claimed it (double-admission).
//! 2. A draw spread over several positions recorded only the last one, so the
//!    release over-released that position and leaked the encumbrance on the
//!    rest.
//! 3. `ChargeSchedule::accrued_interest` multiplied in u128 without a check:
//!    adversarial (principal, rate, windows) panicked in debug, wrapped in
//!    release (undercharging interest), and silently capped otherwise.
//!
//! Each test below failed against the code it now guards.

use srct_core::credit::{ChargeSchedule, CreditBook, CreditGate, CreditTerms, PositionSpec};

fn charge() -> ChargeSchedule {
    ChargeSchedule {
        rate_bps_per_window: 0,
        window_blocks: 100,
    }
}

fn spec(borrower: [u8; 20], lender: [u8; 20]) -> PositionSpec {
    PositionSpec {
        terms: CreditTerms::default(),
        charge: charge(),
        borrower,
        agent_id: [9u8; 32],
        lender,
        amount_sat: 5_000,
        bond_sat: 0,
        drawn_at_height: 0,
        deadline_height: 100,
    }
}

#[test]
fn a_mixed_reservation_sweeps_free_so_it_cannot_back_two_payments() {
    let mut book = CreditBook::new();
    let borrower = [7u8; 20];
    let lender = [8u8; 20];
    book.deposit(borrower, 10_000).unwrap();
    let id = book.open(&spec(borrower, lender)).unwrap();
    let free = book.free(&borrower);
    assert!(free > 0 && free < 10_000, "collateral locked, free remains");

    // Reserve more than the free balance: the remainder draws on the position.
    let res = book.reserve(&borrower, free + 1_000, 1).unwrap();
    assert_eq!(res.from_free_sat, free, "the whole free balance is swept");
    assert_eq!(
        book.available(&borrower),
        0,
        "nothing spendable is left behind"
    );
    assert_eq!(
        res.position_draws.iter().map(|(_, take)| take).sum::<u64>(),
        1_000,
        "the remainder is drawn, draw by draw"
    );

    // The swept free value cannot back a second admitted payment.
    assert!(
        book.reserve(&borrower, free, 1).is_err(),
        "swept free cannot be re-admitted"
    );

    // A position-touching reservation is refused at settle before any debit,
    // so no half-debit lands.
    let settled_before = book.total_settled();
    assert!(
        book.settle(&res).is_err(),
        "position-backed settle is refused"
    );
    assert_eq!(book.total_settled(), settled_before, "no half-debit");

    // Release returns everything exactly and leaves the position alone.
    book.release(&res).unwrap();
    assert_eq!(book.free(&borrower), free, "free returned exactly");
    assert_eq!(book.total_reserved(), 0, "no leaked headroom");
    book.check_conservation().unwrap();
    assert!(book.live_positions().any(|(pid, _)| pid == &id));
}

#[test]
fn a_refused_reservation_leaves_the_book_exactly_as_it_was() {
    let mut book = CreditBook::new();
    let borrower = [7u8; 20];
    book.deposit(borrower, 1_000).unwrap();
    let before = book.clone();
    // No positions exist, so the remainder past free cannot be drawn: the free
    // swept first must roll back rather than strand in `reserved`.
    assert!(book.reserve(&borrower, 5_000, 1).is_err());
    assert_eq!(book, before, "refused admission has no side effect");
    book.check_conservation().unwrap();
}

#[test]
fn interest_overflow_is_refused_never_wrapped_or_silently_capped() {
    let hostile = ChargeSchedule {
        rate_bps_per_window: u32::MAX,
        window_blocks: 1,
    };
    let err = hostile
        .accrued_interest(u64::MAX / 2, 0, u64::MAX / 2)
        .unwrap_err();
    assert!(
        matches!(err, srct_core::error::Error::ValueOverflow),
        "overflow is a refusal, not a number: {err:?}"
    );
    // Ordinary values still price exactly.
    let sane = ChargeSchedule {
        rate_bps_per_window: 1_000,
        window_blocks: 100,
    };
    assert_eq!(sane.accrued_interest(1_000_000, 0, 100).unwrap(), 100_000);
}
