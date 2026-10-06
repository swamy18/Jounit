#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the wire message decoder (SPEC.md §13.5).
//
// `jnt_net::msg::Message::decode(ty, payload)` is what every byte from a peer
// flows through. The frame layer bounds payload size before this runs; here
// we attack the per-type payload parsers with arbitrary (ty, payload) pairs,
// including type bytes that do not exist.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ty = data[0];
    let payload = &data[1..];

    // Ok or Err — never a panic, never an unbounded allocation.
    if let Ok(msg) = jnt_net::msg::Message::decode(ty, payload) {
        // Round-trip: a decoded message must re-encode to a payload the same
        // decoder accepts with the same type byte.
        let payload2 = msg.encode();
        let again = jnt_net::msg::Message::decode(ty, &payload2)
            .expect("an encoded message must decode from its own encoding");
        // Message does not derive PartialEq; compare the canonical re-encodes,
        // which is the property the wire actually depends on.
        assert_eq!(again.encode(), payload2, "re-encode must be stable");
        assert_eq!(again.encode(), msg.encode());
    }
});
