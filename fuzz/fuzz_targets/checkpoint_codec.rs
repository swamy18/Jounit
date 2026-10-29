#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the M4 bounded checkpoint codec (Decision 11, SPEC.md §14).
//
// `Checkpoint::deserialize` and `CheckpointPayload::deserialize` are the only
// parsers that touch bytes arriving from a peer for msg_type = 11. Both are
// length-bounded and both must return Ok or Err — never panic, never allocate
// an unbounded amount from a crafted length field.
fuzz_target!(|data: &[u8]| {
    use srct_core::bls_checkpoint::{Checkpoint, CheckpointPayload};

    // A payload is always allowed to fail; it must never panic.
    let _ = CheckpointPayload::deserialize(data);

    if let Ok(cp) = Checkpoint::deserialize(data) {
        // A decoded certificate must re-encode to bytes the same decoder
        // accepts, and decoding again must reproduce the same certificate.
        let bytes = cp.serialize();
        let again = Checkpoint::deserialize(&bytes)
            .expect("a certificate must decode from its own encoding");
        assert_eq!(again, cp, "checkpoint round-trip must be the identity");
    }
});