#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz dispute evidence validation and arbitration (SPEC.md §15.6, §16).
//
// Everything an attacker can put in a dispute is fuzzed here: the two result
// hashes, both attestations (including their declared signature length, via the
// M3 reader), and the reference result. Two invariants must hold:
//
//   1. No input, however malformed, panics or slashes anyone by default.
//      A verdict may only be produced for *validated* evidence, and an
//      inconclusive reference must never produce one.
//   2. Arbitration is deterministic: the same evidence and reference give the
//      same verdict, every time. The engine is called twice and compared.
fuzz_target!(|data: &[u8]| {
    use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend};
    use jnt_core::hash::Hash;
    use jnt_core::ser::Reader;
    use jnt_l2::{Arbiter, DisputeEngine, DisputeEvidence};

    if data.len() < 128 {
        return;
    }
    let hash32 = |at: usize| -> Hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[at..at + 32]);
        h
    };
    let task_id = hash32(0);
    let submitted = hash32(32);
    let counter = hash32(64);
    let reference = hash32(96);

    // Attestations decoded from the trailing bytes: arbitrary but structurally
    // parsed, so the signature cap is exercised rather than ignored.
    let mk_attest = |result: Hash, sig_byte: u8| -> ComputeAttestation {
        let mut a = ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Cpu,
            worker_address: [sig_byte; 20],
            attest_height: 0,
            signature: vec![sig_byte, sig_byte],
        };
        if let Ok(decoded) = ComputeAttestation::from_reader(&mut Reader::new(&data[128..])) {
            a.signature = decoded.signature;
        }
        a
    };

    let evidence = DisputeEvidence {
        task_id,
        submitted_result: submitted,
        submitted_attestation: mk_attest(submitted, data[0]),
        counter_result: counter,
        counter_attestation: mk_attest(counter, data[1]),
    };

    // Validation must be total: Ok or a named error, never a panic.
    let validated = evidence.validate().is_ok();

    match DisputeEngine::arbitrate(&evidence, reference) {
        Ok(v) => {
            assert!(validated, "a verdict may only come from validated evidence");
            // `Ok` does *not* imply a guilty verdict. When the reference
            // reproduces neither claim the engine returns `Inconclusive` — a
            // real, legitimate outcome that slashes no one (SPEC.md §15.6).
            // Asserting the two shapes separately is the whole point: a
            // conviction (Some) and an inconclusive result (None) are
            // structurally distinct, and only a conviction names the settle
            // hash or yields a payload.
            match v.arbiter {
                Arbiter::Inconclusive => {
                    assert_eq!(v.verdict(), None, "inconclusive is not a wire verdict");
                    assert_eq!(v.vwc_hash(), None, "inconclusive settles nothing");
                    assert!(
                        v.settle_payload([0u8; 96], vec![0xFF], 1).is_err(),
                        "an inconclusive arbitration must have no settle payload"
                    );
                }
                Arbiter::WorkerCorrect | Arbiter::ChallengerCorrect => {
                    assert!(v.verdict().is_some());
                    assert_eq!(v.vwc_hash(), Some(reference));
                    assert!(v.settle_payload([0u8; 96], vec![0xFF], 1).is_ok());
                }
            }
            // Determinism: the same inputs must yield the same verdict.
            let again = DisputeEngine::arbitrate(&evidence, reference)
                .expect("the same validated evidence must arbitrate again");
            assert_eq!(again, v, "arbitration must be deterministic");
        }
        Err(_) => {
            // A refusal is the expected outcome for malformed evidence.
            assert!(!validated, "validated evidence must not fail arbitration");
        }
    }
});
