#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz checkpoint validation with adversarial validator/checkpoint inputs
// (SPEC.md §14.5, §14.6), then the M5 binding-finality state machine
// (Decisions 12/14, §14.8) over the same bytes.
//
// Two harnesses, one `fuzz_target!`: libfuzzer-sys emits one
// `LLVMFuzzerInitialize` per macro expansion, so a second macro in this file
// would collide at link time.

/// Clause-level validation: the input drives which validator seeds make up the
/// verifying set, the checkpoint payload, the aggregate signature bytes, and
/// the signer bitmap. Validation must return Ok or a named clause error —
/// never panic, never accept a structurally impossible checkpoint.
fn run_checkpoint_validation(data: &[u8]) {
    use jnt_core::bls::RealBls;
    use jnt_core::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
    use jnt_core::validators::{
        derive_set, validate_checkpoint_against_set, SelectionRule, ValidatorError,
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
        block_hash: jnt_core::hash::sha512(&[b"fuzz", &height.to_le_bytes()]),
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
    let set_for_epoch = |e: u64| -> Result<jnt_core::validators::EpochSet, ValidatorError> {
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
        assert_eq!(
            pop, cp.signer_count as usize,
            "accepted checkpoint must have honest count"
        );
        assert!(
            cp.signer_count as usize >= set.quorum_size(),
            "accepted checkpoint must meet quorum"
        );
        // Zero signature must never validate.
        assert_ne!(cp.aggregate_sig.as_bytes(), &[0u8; 96]);
        let _ = BlsPublicKey([0u8; 48]);
    }
}

/// Finality state machine (M5, Decisions 12/14 — SPEC.md §14.8): drive
/// `FinalityManager::accept` through a scripted sequence of certificates.
/// With the structural (Mock) verifier, arbitrary inputs reach the
/// canonical/conflict/monotonic clauses directly. Invariants, after every
/// single call:
///
/// - never panics;
/// - evidence is bounded (`MAX_EQUIVOCATION_EVIDENCE`);
/// - no two *accepted* certificates ever name different hashes at one height;
/// - the binding point, if set, is always an accepted certificate's own
///   (height, hash) — no conflicting-finality acceptance, ever;
/// - evidence construction over arbitrary payloads is total: Some exactly when
///   the payloads differ, None otherwise, and never panics.
fn run_finality_state(data: &[u8]) {
    use jnt_core::bls_checkpoint::{BlsSignature, Checkpoint, CheckpointPayload, MockBls};
    use jnt_core::finality::{FinalityManager, MAX_EQUIVOCATION_EVIDENCE};
    use jnt_core::params::NetworkParams;
    use jnt_core::validators::equivocation_evidence;
    use std::collections::HashMap;

    if data.len() < 12 {
        return;
    }
    let params = NetworkParams::testnet(); // deterministic committee, activation 20
    let mut fm = FinalityManager::new(&params);
    // Local model of what accept() has actually returned Ok for.
    let mut accepted: HashMap<u64, jnt_core::hash::Hash512> = HashMap::new();

    let mut off = 0usize;
    while off + 12 <= data.len() {
        let height = u64::from(data[off] as u32 % 64);
        let variant = data[off + 1];
        let signers = data[off + 2] & 0b0000_1111; // bitmap over 4 keys
        let sig_nonzero = data[off + 3] != 0;
        let wrong_network = data[off + 4] & 1 == 1;
        let canonical_mode = data[off + 5] % 3; // 0 = exact, 1 = other hash, 2 = absent
        let count = data[off + 6];

        let block_hash = jnt_core::hash::sha512(&[&[variant], &height.to_le_bytes()]);
        let payload = CheckpointPayload {
            height,
            block_hash,
            network_id: if wrong_network {
                "jounit/another-network".into()
            } else {
                "jounit/testnet".into()
            },
            epoch: height / params.checkpoint_interval_blocks,
        };
        let cp = Checkpoint {
            payload,
            aggregate_sig: BlsSignature([if sig_nonzero { 7 } else { 0 }; 96]),
            signer_bitmap: vec![signers],
            signer_count: count as u32,
        };
        let canonical = match canonical_mode {
            0 => Some(block_hash),
            1 => Some(jnt_core::hash::sha512(&[b"other", &height.to_le_bytes()])),
            _ => None,
        };

        let before_binding = (fm.binding_finalized_height(), fm.binding_finalized_hash());
        let result = fm.accept(&cp, canonical, &MockBls);

        match result {
            Ok(()) => {
                // Never accept two different hashes at the same height.
                if let Some(prev) = accepted.get(&height) {
                    assert_eq!(
                        *prev, block_hash,
                        "two different hashes accepted at height {height}"
                    );
                }
                accepted.insert(height, block_hash);
                assert_eq!(fm.accepted_height(), height);
            }
            Err(_) => {
                // A refusal never moves binding finality.
                assert_eq!(
                    (fm.binding_finalized_height(), fm.binding_finalized_hash()),
                    before_binding,
                    "a refused certificate moved binding finality"
                );
            }
        }

        // Bounded resources, always.
        assert!(
            fm.evidence().len() <= MAX_EQUIVOCATION_EVIDENCE,
            "evidence exceeded its bound"
        );
        // The binding point, when set, is an accepted certificate's own
        // (height, hash) — the system never finalizes a hash it did not
        // accept, and never two at one height.
        if fm.binding_finalized_height() > 0 {
            let bh = fm.binding_finalized_height();
            assert_eq!(
                accepted.get(&bh),
                Some(&fm.binding_finalized_hash()),
                "binding finality names a certificate that was never accepted"
            );
        }

        // Evidence construction over arbitrary payloads: total, deterministic,
        // and None exactly for identical payloads.
        let sig = BlsSignature([if sig_nonzero { 9 } else { 0 }; 96]);
        let cp2 = Checkpoint {
            payload: CheckpointPayload {
                height,
                block_hash: jnt_core::hash::sha512(&[&[variant ^ 0xFF], &height.to_le_bytes()]),
                network_id: "jounit/testnet".into(),
                epoch: height / params.checkpoint_interval_blocks,
            },
            aggregate_sig: sig,
            signer_bitmap: vec![signers],
            signer_count: count as u32,
        };
        let key = params.genesis_validators[0];
        let same = equivocation_evidence(&key, &cp, &cp);
        assert!(same.is_none(), "identical payloads are not equivocation");
        let conflicted = equivocation_evidence(&key, &cp, &cp2);
        match conflicted {
            Some(ev) => {
                assert_ne!(ev.first, ev.second);
                assert_eq!(ev.offender, key);
                // Deterministic: repeating the call yields byte-identical evidence.
                assert_eq!(Some(ev.clone()), equivocation_evidence(&key, &cp, &cp2));
            }
            None => assert!(
                cp.payload.serialize() == cp2.payload.serialize(),
                "payloads differ, so evidence must exist"
            ),
        }

        off += 12;
    }
}

fuzz_target!(|data: &[u8]| {
    run_checkpoint_validation(data);
    run_finality_state(data);
});
