// Red-team probes against the credit book, the delegation chain rule and the
// escrow condition set. Each test is written from the attacker's side: it tries
// a sequence that *should* be impossible and asserts the code refuses it rather
// than trusting that it looks impossible.
//
// The randomized prover at the end is the one that earns its keep: it drives
// random legal-and-illegal sequences and asserts the conservation invariant
// after every single mutation, which is the property that catches a mutation
// that is locally reasonable and globally wrong.

use jnt_core::credit::CreditGate;
use jnt_core::credit::{
    ChargeSchedule, CreditBook, CreditPosition, CreditTerms, PositionSpec, ReservationOutcome,
};
use jnt_core::error::Error;

fn addr(n: u8) -> [u8; 20] {
    [n; 20]
}

fn spec(
    borrower: [u8; 20],
    lender: [u8; 20],
    amount: u64,
    bond: u64,
    drawn_at: u64,
    deadline: u64,
) -> PositionSpec {
    PositionSpec {
        terms: CreditTerms::default(),
        charge: ChargeSchedule {
            rate_bps_per_window: 1_000,
            window_blocks: 100,
        },
        borrower,
        agent_id: [9u8; 32],
        lender,
        amount_sat: amount,
        bond_sat: bond,
        drawn_at_height: drawn_at,
        deadline_height: deadline,
    }
}

/// A tiny deterministic xorshift so the prover needs no dependency and replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn value_cannot_be_squeezed_out_of_the_book_by_interleaving_every_operation() {
    // The prover: every legal and illegal move from every actor, in random
    // order, with the invariant checked after each one. A sequence that
    // over-drafts a free balance, repays a settled position, releases a
    // reservation twice, or defaults one twice has to be refused by name
    // *and* leave the book's accounting intact.
    let mut longest_run = 0usize;
    for seed in 1..=64u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let mut book = CreditBook::new();
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);
        let parties = [alice, bob, carol];

        // Seed the book so most moves are reachable.
        for p in parties {
            book.deposit(p, 10_000_000).unwrap();
        }
        book.post_bond(alice, 200_000).unwrap();
        book.post_bond(bob, 300_000).unwrap();

        let mut positions: Vec<jnt_core::hash::Hash> = Vec::new();
        let mut reservations: Vec<jnt_core::credit::Reservation> = Vec::new();
        let mut ops = 0usize;

        for step in 0..200u64 {
            let actor = parties[rng.below(3) as usize];
            let lender = parties[rng.below(3) as usize];
            match rng.below(11) {
                0 => {
                    let amount = rng.below(500_000);
                    let b = book.deposit(actor, amount);
                    ops += 1;
                    assert!(b.is_ok(), "deposit must never fail: {b:?}");
                }
                1 => {
                    let amount = rng.below(300_000);
                    let _ = book.post_bond(actor, amount);
                    ops += 1;
                }
                2 => {
                    let s = spec(
                        actor,
                        lender,
                        100_000 + rng.below(900_000),
                        10_000 + rng.below(200_000),
                        step,
                        10_000,
                    );
                    match book.open(&s) {
                        Ok(id) => positions.push(id),
                        // An opening that cannot fund its collateral, or whose
                        // bond is not posted and unpledged, is refused and must
                        // leave nothing behind.
                        Err(e) => assert!(
                            e.to_string().contains("bond")
                                || e.to_string().contains("collateral")
                                || e.to_string().contains("already open"),
                            "unexpected refusal for a new position: {e}"
                        ),
                    }
                    ops += 1;
                }
                3 => {
                    let amount = 1 + rng.below(400_000);
                    match book.reserve(&actor, amount, step) {
                        Ok(r) => reservations.push(r),
                        // Over-encumbrance is a refusal, not a negative reserve.
                        Err(Error::InsufficientFunds { .. }) => {}
                        Err(e) => panic!("unexpected reservation refusal: {e}"),
                    }
                    ops += 1;
                }
                4 => {
                    if let Some(r) = reservations.pop() {
                        match book.settle(&r) {
                            Ok(()) => {}
                            Err(e) => {
                                let m = e.to_string();
                                assert!(
                                    m.contains("released") || m.contains("no outstanding"),
                                    "unexpected settle refusal: {e}"
                                );
                            }
                        }
                    }
                    ops += 1;
                }
                5 => {
                    if let Some(r) = reservations.pop() {
                        // Releasing must always be possible, and twice must be
                        // idempotent rather than crediting twice.
                        book.release(&r).expect("release of a live reservation");
                        book.release(&r).expect("a second release is idempotent");
                    }
                    ops += 1;
                }
                6 => {
                    if let Some(id) =
                        positions.get(rng.below(positions.len().max(1) as u64) as usize)
                    {
                        let amount = rng.below(2_000_000);
                        let _ = book.repay(id, amount, step);
                    }
                    ops += 1;
                }
                7 => {
                    if let Some(id) =
                        positions.get(rng.below(positions.len().max(1) as u64) as usize)
                    {
                        let before = book.clone();
                        if book.default(id, step).is_err() {
                            assert_eq!(
                                book.total_locked_collateral(),
                                before.total_locked_collateral(),
                                "a refused default changed the book"
                            );
                        }
                    }
                    ops += 1;
                }
                8 => {
                    // Fuzzing the amounts against the *book's own* answers tests
                    // the accessors, which is where an off-by-one in the pledge
                    // arithmetic would show up as an over-reserve.
                    let a = book.available(&actor);
                    let u = book.unpledged_bond(&actor);
                    assert!(u <= book.bond(&actor), "unpledged bond exceeded the bond");
                    let _ = a;
                    ops += 1;
                }
                9 => {
                    // A replayed reservation id is settled once, never twice.
                    if let Some(r) = reservations.first().cloned() {
                        let already = book.reservation_outcome(&r.id);
                        if let Some(ReservationOutcome::Settled) = already {
                            let settled_before = book.total_settled();
                            book.settle(&r)
                                .expect("a settled reservation re-settles idempotently");
                            assert_eq!(
                                book.total_settled(),
                                settled_before,
                                "a replayed settlement debited a second time"
                            );
                        }
                    }
                    ops += 1;
                }
                _ => {
                    let amount = rng.below(200_000);
                    let _ = book.release_bond(actor, amount);
                    ops += 1;
                }
            }

            // The invariant, after every single mutation, whatever the move was.
            book.check_conservation().unwrap_or_else(|e| {
                panic!("conservation broke at seed {seed} step {step} after {ops} ops: {e}")
            });
        }
        longest_run = longest_run.max(ops);
    }
    assert!(longest_run > 0, "the prover ran nothing");
}

#[test]
fn a_reservation_drawn_against_a_position_cannot_settle_into_nothing() {
    // A position-backed reservation is encumbered but never debited by
    // `settle`: the debit is a lifecycle event. The prover accepts that as a
    // named refusal; this test pins that the refusal is not silent success,
    // which would be the version that loses the payer's line for nothing.
    let borrower = addr(1);
    let lender = addr(2);
    let mut book = CreditBook::new();
    let s = spec(borrower, lender, 1_000_000, 100_000, 0, 10_000);
    let collateral = CreditPosition::open(&s).unwrap().collateral_sat;
    book.deposit(borrower, collateral + 100_000).unwrap();
    book.post_bond(borrower, 100_000).unwrap();
    let id = book.open(&s).unwrap();

    // The free balance is exhausted by the collateral, so the draw is charged
    // against the position's principal headroom.
    let res = book
        .reserve(&borrower, 1_000_000, 1)
        .expect("draws on the position");
    assert_eq!(res.position_id, Some(id));
    assert_eq!(book.total_reserved(), 1_000_000);

    let err = book.settle(&res).unwrap_err();
    assert!(
        err.to_string().contains("no outstanding"),
        "a position-backed reservation must not settle into nothing: {err}"
    );
    book.check_conservation().unwrap();

    // And releasing it returns the headroom, leaving the position untouched.
    book.release(&res).unwrap();
    assert_eq!(book.total_reserved(), 0);
    book.check_conservation().unwrap();
}
