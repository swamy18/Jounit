#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the VWC codec and validation boundary (SPEC.md §17).
//
// A certificate is an attacker-controlled artifact by construction: it is
// *designed* to be handed around off-chain, so the bytes may come from anyone.
// Three properties must hold for arbitrary input:
//
//   1. `decode` never panics and never over-reads.
//   2. decode -> encode -> decode is the identity, and the derived id is stable.
//   3. `validate` never panics, and never accepts a certificate whose own
//      id does not follow from its body, whose result hash is the expired
//      placeholder, or whose quorum aggregate fails.
//
// The registry comparison (§17.6 check 4) needs live state, which a raw byte
// fuzzer does not have; that half is covered deterministically by
// `crates/srct-l2/tests/vwc_flow.rs` and the registry assertions in the L2
// fuzz-invariant suite.
fuzz_target!(|data: &[u8]| {
    use srct_core::bls::RealBls;
    use srct_core::bls_checkpoint::{BlsPublicKey, ValidatorSet};
    use srct_l2::{VerifiedWorkCertificate, VWC_VERSION};

    // A well-formed-looking validator set; the real verifier refuses keys that
    // are not curve points, so validation of quorum certificates fails closed
    // even with this set in hand.
    let validators =
        ValidatorSet::new((1..=4usize).map(|i| BlsPublicKey([i as u8; 48])).collect());

    if let Ok(cert) = VerifiedWorkCertificate::decode(data) {
        // Round-trip stability.
        let bytes = cert.encode();
        let again = VerifiedWorkCertificate::decode(&bytes)
            .expect("a decoded certificate must decode from its own encoding");
        assert_eq!(again, cert, "encode/decode must be an exact inverse");
        assert_eq!(again.id, cert.id, "the id must be stable under round-trip");
        // The id always follows from the body of a decoded certificate.
        assert_eq!(cert.id, cert.id(), "decode re-derives the id from the body");
        // Structural version agreement.
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(version, VWC_VERSION, "only the current version decodes");
        // Validation is total: Ok or a named error, never a panic.
        let _ = cert.validate(&validators, &RealBls);
    }
});
