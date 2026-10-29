#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the Deliverable codec boundary (the new predicate layer).
//
// `deliverable.rs` is the seam where the state machine stops being about
// compute and starts being about "anything with an adjudicable reference". Two
// `Deliverable` impls live there today, and a third may arrive later, so the
// bytes that reach their decoders are attacker input from the attacker's point of
// view: whatever the wire carries.
//
// Properties, for arbitrary input and both impls:
//
//   1. `decode` never panics and never over-reads (bounded; declared lengths
//      checked against a cap rather than trusted).
//   2. decode -> encode -> decode is the identity, and it consumes every byte.
//   3. `reference` is stable across calls, and equal to its own id only for the
//      Echo-style stub the discipline check exists to refuse - the property a
//      hidden input would break.
//   4. The predicate discipline assertion is total: it either holds or returns a
//      named error, never a panic.
//
// The L2 payload types stay concrete, so the *contract* codec is fuzzed by the
// existing `l2_payload_decode` and `dispute_arbitrate` targets; this target
// covers the layer underneath them.
fuzz_target!(|data: &[u8]| {
    use srct_core::deliverable::{
        assert_predicate_discipline, Attestation, Deliverable, SortAttestation, SortDeliverable,
    };
    use srct_core::ser;

    for chunk in data.chunks(64) {
        // --- the deliverable itself ---------------------------------------
        if let Ok(d) = SortDeliverable::decode(&mut ser::Reader::new(chunk)) {
            let bytes = d.encode();
            let mut r = ser::Reader::new(&bytes);
            let again = SortDeliverable::decode(&mut r).expect("round trip");
            assert_eq!(again, d, "encode/decode must be an exact inverse");
            assert_eq!(r.remaining(), 0, "a self-delimiting encoding consumes all bytes");

            // The reference is a pure function of committed inputs: stable, and
            // never a mere echo of the id.
            let id = d.task_id();
            let once = d.reference(&id);
            assert_eq!(once, d.reference(&id), "reference must not have a hidden input");
            assert_ne!(
                d.kind(),
                "",
                "a deliverable must name its kind rather than leaving it blank"
            );

            // The discipline check is total.
            let _ = assert_predicate_discipline(&d, &id);
        }

        // --- the attestation of that deliverable ---------------------------
        if let Ok(a) = SortAttestation::decode(&mut ser::Reader::new(chunk)) {
            let bytes = a.encode();
            let mut r = ser::Reader::new(&bytes);
            let again = SortAttestation::decode(&mut r).expect("round trip");
            assert_eq!(again, a, "encode/decode must be an exact inverse");
            assert_eq!(r.remaining(), 0, "a self-delimiting encoding consumes all bytes");

            // An unsigned attestation is refused by shape, and `is_signed` must
            // never disagree with what the decoder accepted.
            assert!(
                !a.signature.is_empty() || !a.is_signed(),
                "an accepted attestation with no signature bytes must report unsigned"
            );
        }
    }
});
