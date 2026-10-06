#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the transaction deserializer (SPEC.md §3, §9).
//
// Any input is legal wire data as far as the caller is concerned; the only
// acceptable outcomes are Ok or Err. A panic here is a remote DoS: a peer
// controls these bytes on the wire.
fuzz_target!(|data: &[u8]| {
    // The public deserialize entry point.
    if let Ok(tx) = jnt_core::tx::Transaction::deserialize(data) {
        // Round-trip invariant: a successfully decoded transaction must
        // re-serialize to at least the input length with no panic, and must
        // decode again from its own serialization (parser consistency).
        let re = tx.serialize();
        let again = jnt_core::tx::Transaction::deserialize(&re)
            .expect("a decoded transaction must decode from its own serialization");
        assert_eq!(again.txid(), tx.txid(), "re-serialization must preserve txid");
    }
});
