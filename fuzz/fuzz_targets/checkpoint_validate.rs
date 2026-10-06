#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz checkpoint validation with adversarial validator/checkpoint inputs
// (SPEC.md §14.5, §14.6).
//
// The input drives: which validator seeds make up the verifying set, the
// checkpoint payload, the aggregate signature bytes, and the signer bitmap.
// Validation must return Ok or a named clause error — never panic, never
// accept a structurally impossible checkpoint.
fuzz_target!(|data: &[u8]| {
    use jnt_core::bls::RealBls;
    use jnt_core::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
    use jnt_core::validators::{
        derive_set,
        validate_checkpoint_against_set,
        SelectionRule,
        ValidatorError,
    };

    if data.len() < 8 {
        return;
    }
    // Deterministic committee from the first bytes.
    let n_validators = (data[0] as usize % 7) + 1; // 1..=7
    let epoch = u64::from_le_bytes([data[1], data[2], data[3], data[4], 0, 0, 0, 0]);
    let height = u64::from_le_bytes([data[5], data[6], data[7], 0, 0, 0, 0, 0]);
    let sig_bytes: [u8; 96] = {
        let mut s = [0u8; 96];
        for (i, b) in s.iter_mut().enumerate() {
            *b = data.get(8 + i).copied().unwrap_or(0);
        }
        s
    };
    let bitmap: Vec<u8> = data.get(104..).unwrap_or(&[]).to_vec();

    // The set the verifier derives (candidates: seeds 1..=n, real keys).
    let candidates: Vec<jnt_core::validators::ValidatorRecord> = (1..=n_validators as u8)
        .map(|i| {
            let sk = jnt_core::bls::SecretKey::derive(&[i; 32]).unwrap();
            jnt_core::validators::ValidatorRecord {
                stake_address: [i; 20],
                bls_pk: sk.public_key(),
                stake_sat: u64::from(i) * 100,
            }
        })
        .collect();
    let set = match derive_set(epoch, &candidates, SelectionRule::TopN, 21) {
        Ok(s) => s,
        Err(_) => return, // duplicates impossible here; defensive
    };

    let payload = CheckpointPayload {
        height,
        block_hash: jnt_core::hash::sha256(&[b"fuzz", &height.to_le_bytes()]),
        network_id: "jounit/mini".into(),
        epoch,
    };

    let cp = Checkpoint {
        payload,
        aggregate_sig: BlsSignature(sig_bytes),
        signer_bitmap: bitmap,
        signer_count: u32::MAX, // hostile count; clause 3b must catch lies
    };

    let finalized = 0;
    let epoch_blocks = 100;
    let set_for_epoch =
        |e: u64| -> Result<jnt_core::validators::EpochSet, ValidatorError> {
            if e == epoch {
                Ok(set.clone())
            } else {
                Err(ValidatorError::NoCandidates { epoch: e })
            }
        };

    // Ok or named Err. Never panic.
    let result =
        validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls);
    if let Ok(()) = result {
        // If it somehow validated, the claimed count must have been honest and
        // the signature real — assert the invariants that make acceptance
        // meaningful.
        let pop: usize = cp
            .signer_bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum();
        assert_eq!(pop, cp.signer_count as usize, "accepted checkpoint must have honest count");
        assert!(cp.signer_count as usize >= set.quorum_size(), "accepted checkpoint must meet quorum");
        // Zero signature must never validate.
        assert_ne!(cp.aggregate_sig.as_bytes(), &[0u8; 96]);
        let _ = BlsPublicKey([0u8; 48]);
    }
});
