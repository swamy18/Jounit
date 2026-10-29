#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the L2 transaction codec (SPEC.md §15.1, `srct_core::l2`).
//
// The decoder is an attacker-controlled boundary: every field is length-prefixed
// or count-driven, and an `L2Transaction` arrives from a peer. Two properties
// must hold for arbitrary bytes:
//
//   1. `deserialize` never panics and never over-reads.
//   2. `deserialize` -> `serialize` -> `deserialize` is the identity, so an
//      accepted payload cannot be silently re-encoded differently. That is the
//      property that failed once before in this project on
//      `srct_net::Message::Unknown`, which is why it is asserted here by fuzzing
//      rather than only by a fixed vector.
//
// Authorization is checked for *panics* only: a decoded payload is unsigned
// garbage by construction, so `verify_auth` is expected to refuse it.
fuzz_target!(|data: &[u8]| {
    use srct_core::l2::L2Transaction;

    let Ok(tx) = L2Transaction::deserialize(data) else {
        return;
    };

    // Round-trip stability: re-encoding an accepted payload must reproduce the
    // same bytes, and decoding them must reproduce the same payload.
    let encoded = tx.serialize();
    let again = L2Transaction::deserialize(&encoded)
        .expect("a payload that decoded once must decode after re-encoding");
    assert_eq!(again, tx, "encode/decode must be an exact inverse");
    assert_eq!(again.txid(), tx.txid(), "txid must be stable under round-trip");
    assert_eq!(again.fee_sat(), tx.fee_sat());

    // Authorization must not panic on adversarial bundles. It may refuse.
    let _ = tx.payload.verify_auth();
    let _ = tx.payload.signing_hash();
    let _ = tx.payload.actor();
});
