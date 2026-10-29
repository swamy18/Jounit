//! Streaming micro-payment suite — pay-as-you-use over `stream.rs`.
//!
//! Written attack-first: each test builds the *hostile* settlement a
//! compromised or careless party would present and asserts the exact clause
//! that refuses it. The two properties that matter are (1) a receipt can
//! never settle more than exactly what accrued, and (2) a refusal never
//! consumes budget or advances state.
//!
//! Run with `cargo test -p srct-core --test payment_stream`.

use srct_core::agent::AgentRole;
use srct_core::stream::{
    build_settlement, build_stream, StreamBook, StreamError, StreamOpenSpec, StreamSettleSpec,
    STREAM_VERSION,
};
use srct_core::wallet::Wallet;

const NET: &str = "srct/testnet";

fn payer() -> Wallet {
    Wallet::new_random("payer")
}

/// rate 10/block, start 100, expiry 200, cap 900 (= 90 blocks at rate).
fn open_spec(recipient: [u8; 20]) -> StreamOpenSpec {
    StreamOpenSpec {
        network_id: NET.to_string(),
        payer_type: AgentRole::Machine,
        recipient,
        service: Some([9u8; 32]),
        rate_sat_per_block: 10,
        start_height: 100,
        expires_at_height: 200,
        max_total_sat: 900,
        nonce: 1,
        policy_hash: [7u8; 32],
    }
}

fn settle_spec(through: u64, amount: u64, nonce: u64) -> StreamSettleSpec {
    StreamSettleSpec {
        through_height: through,
        amount_sat: amount,
        nonce,
        reference: [0u8; 32],
    }
}

#[test]
fn happy_path_stream_accrues_and_settles_exactly() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).expect("open must build");
    let mut book = StreamBook::default();
    let id = book.open(&stream, NET).expect("open must register");

    // Pre-start nothing is claimable.
    assert_eq!(book.claimable(&stream, 99), Some(0));
    // Ten blocks in: 10 blocks x 10 sat = 100.
    assert_eq!(stream.accrued(109), Some(100));
    assert_eq!(book.claimable(&stream, 109), Some(100));

    let r1 = build_settlement(&w, &stream, settle_spec(109, 100, 1)).expect("receipt");
    let total = book.settle(&stream, &r1, 150).expect("first settle");
    assert_eq!(total, 100);
    assert_eq!(book.claimable(&stream, 150), Some(410));

    // Accrual freezes at the cap; the tail settles exactly to it.
    assert_eq!(stream.accrued(10_000), Some(900));
    let r2 = build_settlement(&w, &stream, settle_spec(10_000, 800, 2)).expect("receipt");
    let total = book.settle(&stream, &r2, 10_000).expect("final settle");
    assert_eq!(total, 900);

    let st = book.state(&id).copied().expect("state must exist");
    assert_eq!(st.settled_sat, 900);
    assert_eq!(st.settlements, 2);
    assert_eq!(st.last_nonce, 2);
    assert_eq!(st.last_settled_height, Some(10_000));
    assert_eq!(book.claimable(&stream, 10_001), Some(0));
}

#[test]
fn a_settlement_above_accrual_is_refused_and_settles_nothing() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    // Accrued through 109 is 100; 101 over-claims by one sat.
    let r = build_settlement(&w, &stream, settle_spec(109, 101, 1)).unwrap();
    assert_eq!(
        book.settle(&stream, &r, 150).unwrap_err(),
        StreamError::AmountMismatch {
            expected: 100,
            got: 101
        }
    );
    assert_eq!(book.claimable(&stream, 150), Some(510));
}

#[test]
fn a_settlement_below_accrual_is_refused_too() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    // Settling less would strand value off the books; exact or nothing.
    let r = build_settlement(&w, &stream, settle_spec(109, 99, 1)).unwrap();
    assert_eq!(
        book.settle(&stream, &r, 150).unwrap_err(),
        StreamError::AmountMismatch {
            expected: 100,
            got: 99
        }
    );
    let id = stream.signing_hash();
    assert!(
        book.state(&id).unwrap().last_settled_height.is_none(),
        "a refused receipt must not advance state"
    );
}

#[test]
fn settling_the_same_height_twice_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    let r1 = build_settlement(&w, &stream, settle_spec(109, 100, 1)).unwrap();
    book.settle(&stream, &r1, 150).unwrap();

    // Same range again, even with a fresh nonce: the height already settled.
    let r2 = build_settlement(&w, &stream, settle_spec(109, 100, 2)).unwrap();
    assert_eq!(
        book.settle(&stream, &r2, 150).unwrap_err(),
        StreamError::HeightRewind {
            through: 109,
            last: 109
        }
    );
}

#[test]
fn a_rewound_through_height_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    let r1 = build_settlement(&w, &stream, settle_spec(150, 510, 1)).unwrap();
    book.settle(&stream, &r1, 160).unwrap();

    // Going backwards re-claims an already-settled range.
    let r2 = build_settlement(&w, &stream, settle_spec(120, 210, 2)).unwrap();
    assert_eq!(
        book.settle(&stream, &r2, 160).unwrap_err(),
        StreamError::HeightRewind {
            through: 120,
            last: 150
        }
    );
}

#[test]
fn claiming_unaccrued_blocks_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    // Through 200 claims 910 sat but at height 150 only 510 accrued.
    let r = build_settlement(&w, &stream, settle_spec(200, 910, 1)).unwrap();
    assert_eq!(
        book.settle(&stream, &r, 150).unwrap_err(),
        StreamError::ClaimBeforeTime {
            through: 200,
            at: 150
        }
    );
}

#[test]
fn a_replayed_nonce_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    let r1 = build_settlement(&w, &stream, settle_spec(109, 100, 5)).unwrap();
    book.settle(&stream, &r1, 150).unwrap();

    // A later receipt with an older or equal nonce replays the sequence.
    let r2 = build_settlement(&w, &stream, settle_spec(119, 100, 5)).unwrap();
    assert_eq!(
        book.settle(&stream, &r2, 150).unwrap_err(),
        StreamError::NonceReplay { got: 5, last: 5 }
    );
}

#[test]
fn a_settlement_signed_by_another_key_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    let attacker = Wallet::new_random("attacker");
    let err = build_settlement(&attacker, &stream, settle_spec(109, 100, 1)).unwrap_err();
    assert!(
        matches!(err, StreamError::SignerNotPayer { .. }),
        "a third party cannot mint receipts for a stream it does not fund"
    );
}

#[test]
fn a_settlement_for_another_stream_is_refused() {
    let w = payer();
    let s1 = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut spec2 = open_spec([2u8; 20]);
    spec2.nonce = 2;
    let s2 = build_stream(&w, spec2).unwrap();
    assert_ne!(s1.signing_hash(), s2.signing_hash());

    let mut book = StreamBook::default();
    book.open(&s1, NET).unwrap();
    book.open(&s2, NET).unwrap();

    // s2's receipt presented against s1 must not settle s1.
    let r = build_settlement(&w, &s2, settle_spec(109, 100, 1)).unwrap();
    assert_eq!(
        book.settle(&s1, &r, 150).unwrap_err(),
        StreamError::NotOurStream
    );
}

#[test]
fn settling_a_stream_the_book_never_opened_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();

    let r = build_settlement(&w, &stream, settle_spec(109, 100, 1)).unwrap();
    assert_eq!(
        book.settle(&stream, &r, 150).unwrap_err(),
        StreamError::UnknownStream
    );
}

#[test]
fn a_machine_stream_without_a_policy_is_refused() {
    let w = payer();
    let mut spec = open_spec([1u8; 20]);
    spec.policy_hash = [0u8; 32];
    let err = build_stream(&w, spec).unwrap_err();
    assert_eq!(err, StreamError::PolicyRequired);

    // A human payer may open directly.
    let mut human = open_spec([1u8; 20]);
    human.payer_type = AgentRole::Human;
    human.policy_hash = [0u8; 32];
    build_stream(&w, human).expect("human may open policy-less");
}

#[test]
fn degenerate_windows_and_rates_are_refused() {
    let w = payer();

    let mut zero_rate = open_spec([1u8; 20]);
    zero_rate.rate_sat_per_block = 0;
    zero_rate.max_total_sat = 0;
    assert_eq!(
        build_stream(&w, zero_rate).unwrap_err(),
        StreamError::ZeroRate
    );

    let mut thin_cap = open_spec([1u8; 20]);
    thin_cap.max_total_sat = 9;
    assert_eq!(
        build_stream(&w, thin_cap).unwrap_err(),
        StreamError::CapBelowRate { rate: 10, cap: 9 }
    );

    let mut flat = open_spec([1u8; 20]);
    flat.start_height = 200;
    assert_eq!(
        build_stream(&w, flat).unwrap_err(),
        StreamError::BadWindow {
            start: 200,
            expires: 200
        }
    );

    let mut backwards = open_spec([1u8; 20]);
    backwards.start_height = 300;
    assert_eq!(
        build_stream(&w, backwards).unwrap_err(),
        StreamError::BadWindow {
            start: 300,
            expires: 200
        }
    );
}

#[test]
fn overflow_refuses_rather_than_wraps() {
    let w = payer();
    let mut spec = open_spec([1u8; 20]);
    spec.rate_sat_per_block = u64::MAX / 2;
    spec.max_total_sat = u64::MAX;
    let stream = build_stream(&w, spec).expect("the open itself fits");

    let mut book = StreamBook::default();
    book.open(&stream, NET).unwrap();

    // Three blocks at half-max cannot be represented: the book refuses.
    let r = build_settlement(&w, &stream, settle_spec(102, 1, 1));
    let r = r.expect("the receipt builds; the book refuses");
    assert_eq!(
        book.settle(&stream, &r, 200).unwrap_err(),
        StreamError::Overflow
    );
}

#[test]
fn the_book_refuses_duplicates_and_a_full_book() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();

    let mut tiny = StreamBook::with_capacity(1);
    tiny.open(&stream, NET).unwrap();
    assert_eq!(
        tiny.open(&stream, NET).unwrap_err(),
        StreamError::DuplicateStream
    );

    let mut spec2 = open_spec([2u8; 20]);
    spec2.nonce = 2;
    let other = build_stream(&w, spec2).unwrap();
    assert_eq!(
        tiny.open(&other, NET).unwrap_err(),
        StreamError::BookFull { cap: 1 }
    );
}

#[test]
fn opening_on_the_wrong_network_is_refused() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let mut book = StreamBook::default();
    assert!(matches!(
        book.open(&stream, "srct/mini").unwrap_err(),
        StreamError::WrongNetwork { .. }
    ));
    assert!(book.is_empty(), "a refused open must not create state");
}

#[test]
fn a_receipt_round_trips_and_binds_to_its_stream() {
    let w = payer();
    let stream = build_stream(&w, open_spec([1u8; 20])).unwrap();
    let r = build_settlement(&w, &stream, settle_spec(109, 100, 1)).unwrap();

    let bytes = r.serialize();
    let back = srct_core::stream::StreamSettlement::deserialize(&bytes, &stream)
        .expect("receipt must decode");
    assert_eq!(back, r);
    assert_eq!(
        back.serialize(),
        bytes,
        "receipt encoding must be canonical"
    );
    assert_eq!(r.version, STREAM_VERSION);

    // Decoding against a different stream refuses by name.
    let mut spec2 = open_spec([2u8; 20]);
    spec2.nonce = 2;
    let other = build_stream(&w, spec2).unwrap();
    assert_eq!(
        srct_core::stream::StreamSettlement::deserialize(&bytes, &other).unwrap_err(),
        StreamError::NotOurStream
    );
}
