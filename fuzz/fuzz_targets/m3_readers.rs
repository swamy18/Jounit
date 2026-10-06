#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the M3 decoders (SPEC.md §14.2) now that an L2 payload embeds a
// `ComputeTask` and a `ComputeAttestation` in its signed body.
//
// `ComputeTask::from_reader` is fixed-size and cannot over-read; the attestation
// reader takes a declared signature length, which *is* attacker-controlled and
// must be bounded before it drives an allocation (SPEC.md §15.1). The invariant
// is the same as every other codec here: no panic, and an exact inverse.
fuzz_target!(|data: &[u8]| {
    use jnt_core::compute_ir::{ComputeAttestation, ComputeTask};
    use jnt_core::ser::Reader;

    if let Ok(task) = ComputeTask::from_reader(&mut Reader::new(data)) {
        let bytes = task.serialize();
        assert_eq!(
            bytes.len(),
            ComputeTask::SERIALIZED_LEN,
            "a decoded task must re-serialize to the fixed length"
        );
        let back = ComputeTask::from_reader(&mut Reader::new(&bytes))
            .expect("a task that decoded must decode its own encoding");
        assert_eq!(back, task, "M3 task codec must be an exact inverse");
        assert_eq!(back.task_hash(), task.task_hash());
        let _ = task.is_active(u64::MAX);
    }

    if let Ok(attest) = ComputeAttestation::from_reader(&mut Reader::new(data)) {
        let bytes = attest.serialize();
        let back = ComputeAttestation::from_reader(&mut Reader::new(&bytes))
            .expect("an attestation that decoded must decode its own encoding");
        assert_eq!(back, attest, "M3 attestation codec must be an exact inverse");
        assert_eq!(back.attest_hash(), attest.attest_hash());
        assert!(
            attest.signature.len() <= ComputeAttestation::MAX_SIGNATURE_BYTES,
            "a decoded attestation must respect the signature cap"
        );
    }
});
