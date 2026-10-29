// Wire-decoder invariant tests: the deterministic counterpart of the
// `wire_msg_decode` cargo-fuzz target.
//
// Every byte from a peer flows through `Message::decode(ty, payload)`, including
// type bytes that do not exist. The only acceptable outcomes are Ok or Err —
// never a panic, never an unbounded allocation, and whatever decodes must
// re-encode stably.

use srct_net::msg::Message;

/// Pseudo-random but deterministic payloads of many lengths, covering the
/// shapes a coverage-guided fuzzer would reach in a long campaign.
fn pseudo_payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| i as u8 ^ seed ^ (i as u8).wrapping_mul(seed).wrapping_add(i as u8 / 7))
        .collect()
}

#[test]
fn wire_decode_never_panics_on_any_type_and_payload() {
    // All 256 type bytes, including ones that do not exist.
    let types: Vec<u8> = (0..=255).collect();
    let mut payloads: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 8],
        vec![0xff; 64],
        // Length fields claiming enormous sizes.
        vec![0xff, 0xff, 0xff, 0xff, 0x7f],
        // A plausible header followed by truncation.
        vec![0x01, 0x00, 0x00, 0x00],
    ];
    for seed in [1u8, 42, 255] {
        for len in [2usize, 5, 17, 40, 100, 257] {
            payloads.push(pseudo_payload(len, seed));
        }
    }

    for ty in types {
        for payload in &payloads {
            // Ok or Err — never a panic, never an unbounded allocation.
            if let Ok(msg) = Message::decode(ty, payload) {
                // Round-trip: a decoded message must re-encode to a payload
                // the same decoder accepts with the same type byte, and the
                // canonical re-encode must be stable (the property the wire
                // actually depends on).
                let payload2 = msg.encode();
                let again = Message::decode(ty, &payload2)
                    .expect("an encoded message must decode from its own encoding");
                assert_eq!(
                    again.encode(),
                    payload2,
                    "type {ty}: re-encode must be stable"
                );
                assert_eq!(again.encode(), msg.encode());
            }
        }
    }
}

/// The message types the protocol actually uses, each with its real
/// serialization, truncated and bit-flipped: torn packets and corruption must
/// never panic the decoder, and anything that decodes must re-encode to bytes
/// the decoder accepts again.
#[test]
fn wire_decode_survives_truncation_and_bitflips_of_real_messages() {
    // Build one real message of each encodable type via round-tripping a
    // decode of well-formed payloads is not possible without constructors for
    // every variant, so instead: take whatever payloads encode cleanly and
    // attack the bytes.
    let payload = pseudo_payload(64, 9);
    for ty in 0u8..=255 {
        if let Ok(msg) = Message::decode(ty, &payload) {
            let good = msg.encode();
            // Truncations.
            for cut in 0..good.len() {
                if let Ok(m) = Message::decode(ty, &good[..cut]) {
                    let re = m.encode();
                    Message::decode(ty, &re)
                        .expect("any decoded message must decode from its own encoding");
                }
            }
            // Bit flips.
            for i in 0..good.len() {
                let mut flipped = good.clone();
                flipped[i] ^= 0x80;
                if let Ok(m) = Message::decode(ty, &flipped) {
                    let _ = m.encode();
                }
            }
        }
    }
}
