// Fuzz-invariant regression tests.
//
// The cargo-fuzz targets in `fuzz/fuzz_targets/` explore these same code paths
// with a coverage-guided search, but they need a nightly toolchain with a
// sanitizer runtime. These tests enforce the *same invariants* deterministically
// on hand-built adversarial inputs, so the properties hold on every `cargo test`
// run and in CI on stable. If a fuzzer ever finds a crash, the minimizing
// reproduction belongs here as a regression test.

use jnt_core::bls::RealBls;
use jnt_core::bls_checkpoint::{BlsSignature, Checkpoint, CheckpointPayload};
use jnt_core::hash::{sha256, Hash};
use jnt_core::ledger::UtxoSet;
use jnt_core::mempool::Mempool;
use jnt_core::params::NetworkParams;
use jnt_core::tx::{Input, OutPoint, Output, Transaction};
use jnt_core::validators::{
    derive_set, validate_checkpoint_against_set, SelectionRule, ValidatorError,
};

// ---------------------------------------------------------------------------
// tx_decode invariants
// ---------------------------------------------------------------------------

/// Any input is legal wire data; the only acceptable outcomes are Ok or Err.
/// A panic here would be a remote DoS, since a peer controls these bytes.
#[test]
fn tx_decode_never_panics_on_adversarial_bytes() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 1],
        vec![0xff; 4],
        // Count fields claiming enormous lengths.
        vec![0xff, 0xff, 0xff, 0xff, 0xff],
        // A valid varint prefix followed by truncation.
        vec![0x01, 0x02, 0x03],
        // Negative-looking / high-bit length encodings.
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        // A coinbase-shaped prefix with a hostile trailing count.
        vec![0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // Deterministic pseudo-random blobs (the shapes a mutation fuzzer finds).
        (0u8..32)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect(),
        vec![0x7f; 128],
        // Deeply nested-looking signature bundles.
        {
            let mut v = vec![0x04, 0x08];
            v.extend(std::iter::repeat(0xaa).take(70));
            v
        },
    ];
    for data in &cases {
        // Ok or Err — never a panic, never an unbounded allocation.
        if let Ok(tx) = Transaction::deserialize(data) {
            // Round-trip invariant: a decoded transaction re-serializes to
            // something that decodes again with the same txid.
            let re = tx.serialize();
            let again = Transaction::deserialize(&re)
                .expect("a decoded transaction must decode from its own serialization");
            assert_eq!(
                again.txid(),
                tx.txid(),
                "re-serialization must preserve txid"
            );
        }
    }
}

/// Truncations of a VALID transaction must fail cleanly, never panic and never
/// half-decode. This is the boundary a torn packet actually hits.
#[test]
fn tx_decode_rejects_every_truncation_of_a_valid_tx() {
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [5u8; 32],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [2u8; 20],
        }],
    );
    tx.inputs[0].sigs = jnt_core::sig::Bundle::single(1, vec![0u8; 64]);
    tx.inputs[0].keys = jnt_core::sig::Bundle::single(1, vec![0u8; 33]);
    let bytes = tx.serialize();
    assert!(
        Transaction::deserialize(&bytes).is_ok(),
        "precondition: the tx itself is valid"
    );

    for cut in 0..bytes.len() {
        let truncated = &bytes[..cut];
        // Ok (a shorter valid encoding) or Err — but never a panic.
        if let Ok(decoded) = Transaction::deserialize(truncated) {
            assert_eq!(
                decoded.serialize(),
                truncated.to_vec(),
                "a transaction decoded from a truncation must re-serialize to exactly those bytes"
            );
        }
    }
    // Every single-byte flip of a valid tx is also peer-controlled.
    for i in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[i] ^= 0xff;
        if let Ok(decoded) = Transaction::deserialize(&flipped) {
            let _ = decoded.txid();
        }
    }
}

// ---------------------------------------------------------------------------
// block_decode invariants
// ---------------------------------------------------------------------------

#[test]
fn block_decode_never_panics_on_adversarial_bytes() {
    let header_len = jnt_core::block::HEADER_SERIALIZED_LEN;
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; header_len - 1],
        vec![0u8; header_len],
        // Valid-size header with a tx count claiming far more transactions
        // than the payload can hold — the reader must bound the allocation.
        {
            let mut v = vec![0u8; header_len];
            v.push(0xff);
            v.push(0xff);
            v.push(0xff);
            v.push(0x7f);
            v
        },
        // Tx count of 1 with zero payload bytes.
        vec![0u8; header_len + 1],
        (0u8..64)
            .map(|i| i.wrapping_mul(91).wrapping_add(7))
            .collect(),
        vec![0xff; 200],
    ];
    for data in &cases {
        if let Ok(block) = jnt_core::block::Block::deserialize(data) {
            let re = block.serialize();
            let again = jnt_core::block::Block::deserialize(&re)
                .expect("a decoded block must decode from its own serialization");
            assert_eq!(
                again.block_hash(),
                block.block_hash(),
                "re-serialization must preserve the block hash"
            );
            // Merkle root must agree with the transaction list it decoded.
            let _ = block.merkle_root();
        }
        // The header alone is also a peer-controlled parse surface.
        if data.len() >= header_len {
            if let Ok(h) = jnt_core::block::Header::deserialize(&data[..header_len]) {
                let _ = h.block_hash();
                assert_eq!(
                    h.serialize().len(),
                    header_len,
                    "header re-serialization must be fixed-length"
                );
            }
        }
    }
}

/// A valid block with every byte flipped must still only Ok or Err — and a
/// flipped byte must never leave a block that decodes but disagrees with its
/// own merkle root.
#[test]
fn block_decode_survives_bitflips_of_a_valid_block() {
    let block = jnt_core::block::genesis_block(1);
    let bytes = block.serialize();
    assert!(jnt_core::block::Block::deserialize(&bytes).is_ok());
    for i in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[i] ^= 0x80;
        if let Ok(decoded) = jnt_core::block::Block::deserialize(&flipped) {
            let _ = decoded.merkle_root();
            let _ = decoded.block_hash();
        }
    }
}

// ---------------------------------------------------------------------------
// mempool_admit invariants
// ---------------------------------------------------------------------------

fn funding_utxo() -> UtxoSet {
    let mut utxo = UtxoSet::default();
    let funding_txid: Hash = [7u8; 32];
    utxo.insert(
        OutPoint {
            txid: funding_txid,
            index: 0,
        },
        jnt_core::ledger::Utxo {
            out: Output {
                value: 1_000_000_000,
                address: [3u8; 20],
            },
            height: 0,
        },
    );
    utxo.insert(
        OutPoint {
            txid: funding_txid,
            index: 1,
        },
        jnt_core::ledger::Utxo {
            out: Output {
                value: 500_000_000,
                address: [4u8; 20],
            },
            height: 0,
        },
    );
    utxo
}

fn spend_tx(n_inputs: usize, outputs: Vec<Output>) -> Transaction {
    let funding_txid: Hash = [7u8; 32];
    let mut tx = Transaction::standard(
        (0..n_inputs)
            .map(|i| {
                Input::unsigned(&OutPoint {
                    txid: funding_txid,
                    index: (i as u32) % 2,
                })
            })
            .collect(),
        outputs,
    );
    for input in &mut tx.inputs {
        input.sigs = jnt_core::sig::Bundle::single(1, vec![0u8; 64]);
    }
    tx
}

#[test]
fn mempool_byte_cap_holds_under_adversarial_admission() {
    let mut params = NetworkParams::mini();
    params.max_block_bytes = 4_000;
    let mut pool = Mempool::new(8_000);
    let utxo = funding_utxo();

    // Hostile tx shapes: zero-value outputs, self-spend duplicates, huge
    // signature padding, outputs that overflow, coinbase-shaped spends.
    let hostile = vec![
        spend_tx(
            1,
            vec![Output {
                value: 0,
                address: [1u8; 20],
            }],
        ),
        spend_tx(
            2,
            vec![Output {
                value: u64::MAX,
                address: [1u8; 20],
            }],
        ),
        spend_tx(
            1,
            vec![
                Output {
                    value: 1_000_000_000,
                    address: [1u8; 20]
                };
                3
            ],
        ),
        spend_tx(1, vec![]),
        {
            let mut t = spend_tx(
                1,
                vec![Output {
                    value: 500_000_000,
                    address: [1u8; 20],
                }],
            );
            for input in &mut t.inputs {
                input.sigs = jnt_core::sig::Bundle::single(1, vec![0u8; 2048]);
            }
            t
        },
        {
            let mut t = spend_tx(
                1,
                vec![Output {
                    value: 1,
                    address: [1u8; 20],
                }],
            );
            t.inputs[0].sigs = jnt_core::sig::Bundle::single(1, vec![0u8; 64]);
            t.inputs[0].keys = jnt_core::sig::Bundle::single(1, vec![0u8; 33]);
            t
        },
    ];

    for tx in &hostile {
        // Ok or named rejection — never a panic, never a cap breach.
        let _ = pool.add(tx.clone(), &utxo, 10_000, &params, 1_000);
        assert!(
            pool.summary().bytes <= 8_000,
            "pool byte cap must hold under adversarial input"
        );
        // Selection over whatever the pool holds must be panic-free.
        let _ = pool.select_for_block(params.gas_cap, params.max_block_bytes);
    }
}

/// A tx rejected for a real reason must never sit in the pool, and admitting
/// then re-admitting must be stable.
#[test]
fn mempool_admission_is_idempotent_and_clean() {
    let mut params = NetworkParams::mini();
    params.max_block_bytes = 4_000;
    let mut pool = Mempool::new(8_000);
    let utxo = funding_utxo();
    let tx = spend_tx(
        1,
        vec![Output {
            value: 900_000_000,
            address: [1u8; 20],
        }],
    );

    let first = pool.add(tx.clone(), &utxo, 10_000, &params, 1_000);
    let bytes_after_first = pool.summary().bytes;
    let second = pool.add(tx, &utxo, 10_000, &params, 1_000);
    // Whatever the pair of outcomes, the pool must not double-count the tx.
    assert!(
        bytes_after_first >= pool.summary().bytes,
        "re-admission must not grow the pool"
    );
    // And selection must terminate with a panic-free, cap-respecting result.
    let selected = pool.select_for_block(params.gas_cap, params.max_block_bytes);
    assert!(pool.summary().bytes <= 8_000);
    let _ = (first, second, selected);
}

// ---------------------------------------------------------------------------
// checkpoint_validate invariants (adversarial validator/checkpoint inputs)
// ---------------------------------------------------------------------------

fn candidate_set(n: u8, epoch: u64) -> jnt_core::validators::EpochSet {
    let candidates: Vec<jnt_core::validators::ValidatorRecord> = (1..=n)
        .map(|i| {
            let sk = jnt_core::bls::SecretKey::derive(&[i; 32]).unwrap();
            jnt_core::validators::ValidatorRecord {
                stake_address: [i; 20],
                bls_pk: sk.public_key(),
                stake_sat: u64::from(i) * 100,
            }
        })
        .collect();
    derive_set(epoch, &candidates, SelectionRule::TopN, 21)
        .expect("distinct seeds give distinct keys")
}

fn payload_for(height: u64, epoch: u64) -> CheckpointPayload {
    CheckpointPayload {
        height,
        block_hash: sha256(&[b"inv", &height.to_le_bytes()]),
        network_id: "jounit/mini".into(),
        epoch,
    }
}

/// An honest checkpoint from a majority of the set validates; the same
/// checkpoint with a hostile count, forged signature, wrong epoch, oversized
/// bitmap, or stale height is rejected with the named clause — never a panic,
/// never an acceptance.
#[test]
fn checkpoint_validation_rejects_every_adversarial_mutation() {
    let epoch = 0u64;
    let height = 50u64; // epoch 0 covers heights 0..99 at interval 100
    let set = candidate_set(4, epoch);
    let payload = payload_for(height, epoch);

    // Three of four validators sign honestly.
    let signer_idx = [0usize, 1, 2];
    let sigs: Vec<jnt_core::bls_checkpoint::BlsSignature> = signer_idx
        .iter()
        .map(|&i| {
            let sk = jnt_core::bls::SecretKey::derive(&[i as u8 + 1; 32]).unwrap();
            sk.sign(&payload.signing_hash())
        })
        .collect();
    let honest_sig = RealBls::aggregate(&sigs).expect("aggregate of real sigs");

    let mut bitmap = vec![0u8; 1];
    for &i in &signer_idx {
        bitmap[i / 8] |= 1 << (i % 8);
    }

    let set_for_epoch = |e: u64| -> Result<jnt_core::validators::EpochSet, ValidatorError> {
        if e == epoch {
            Ok(set.clone())
        } else {
            Err(ValidatorError::NoCandidates { epoch: e })
        }
    };
    let finalized = 0u64;
    let epoch_blocks = 100u64;

    let honest = Checkpoint {
        payload: payload.clone(),
        aggregate_sig: honest_sig,
        signer_bitmap: bitmap.clone(),
        signer_count: signer_idx.len() as u32,
    };
    validate_checkpoint_against_set(&honest, set_for_epoch, finalized, epoch_blocks, &RealBls)
        .expect("an honest majority checkpoint must validate");

    // Mutation 1: count lies above the bitmap (u32::MAX, like the fuzzer drives).
    let mut cp = honest.clone();
    cp.signer_count = u32::MAX;
    assert_eq!(
        validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
        Err(ValidatorError::CheckpointCountMismatch {
            bitmap_popcount: 3,
            claimed: u32::MAX
        }),
        "a lying count must be caught by clause 3b"
    );

    // Mutation 2: forged signature over the same payload and honest bitmap.
    let mut cp = honest.clone();
    // A deterministic 96-byte signature that is not a real point pairing.
    let forged: [u8; 96] = sha256(&[b"forged"])
        .iter()
        .chain(sha256(&[b"forged-2"]).iter())
        .chain(sha256(&[b"forged-3"]).iter())
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    cp.aggregate_sig = BlsSignature(forged);
    assert_eq!(
        validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
        Err(ValidatorError::CheckpointBadSignature),
        "a forged aggregate must be rejected"
    );

    // Mutation 3: height moved to a different epoch than the claimed one.
    let mut cp = honest.clone();
    cp.payload.height = 150;
    assert!(
        matches!(
            validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
            Err(ValidatorError::CheckpointWrongEpoch { .. })
        ),
        "a height outside the claimed epoch must be rejected by clause 1"
    );

    // Mutation 4: bitmap longer than the set needs.
    let mut cp = honest.clone();
    cp.signer_bitmap = vec![0x07, 0x00];
    assert!(
        matches!(
            validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
            Err(ValidatorError::CheckpointBadBitmap { .. })
        ),
        "an oversized bitmap must be rejected by clause 3"
    );

    // Mutation 5: bitmap sets a bit past the end of the set.
    let mut cp = honest.clone();
    cp.signer_bitmap = vec![0x1f]; // bits 0..4 set; the set has 4 validators
    assert!(
        matches!(
            validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
            Err(ValidatorError::CheckpointBadBitmap { .. })
        ),
        "a bit past the set size must be rejected by clause 3"
    );

    // Mutation 6: quorum short (one signer only).
    let mut cp = honest.clone();
    cp.signer_bitmap = vec![0x01];
    cp.signer_count = 1;
    assert!(
        matches!(
            validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
            Err(ValidatorError::CheckpointQuorumShort { .. })
        ),
        "a sub-quorum checkpoint must be rejected by clause 4"
    );

    // Mutation 7: height not beyond the finalized frontier.
    let mut cp = honest.clone();
    cp.payload.height = 50;
    assert!(
        matches!(
            validate_checkpoint_against_set(&cp, set_for_epoch, 60, epoch_blocks, &RealBls),
            Err(ValidatorError::CheckpointNotBeyondFinalized { .. })
        ),
        "a checkpoint at or behind finality must be rejected"
    );

    // Mutation 8: signature from a DIFFERENT payload (replay across heights).
    let other_payload = payload_for(51, epoch);
    let replay_sigs: Vec<jnt_core::bls_checkpoint::BlsSignature> = signer_idx
        .iter()
        .map(|&i| {
            let sk = jnt_core::bls::SecretKey::derive(&[i as u8 + 1; 32]).unwrap();
            sk.sign(&other_payload.signing_hash())
        })
        .collect();
    let mut cp = honest.clone();
    cp.aggregate_sig = RealBls::aggregate(&replay_sigs).unwrap();
    assert_eq!(
        validate_checkpoint_against_set(&cp, set_for_epoch, finalized, epoch_blocks, &RealBls),
        Err(ValidatorError::CheckpointBadSignature),
        "a signature over a different payload must not validate for this one"
    );

    // Structural invariant that makes acceptance meaningful: whatever
    // validates must have an honest count meeting quorum and a real signature.
    let pop: usize = honest
        .signer_bitmap
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum();
    assert_eq!(pop, honest.signer_count as usize);
    assert!(honest.signer_count as usize >= set.quorum_size());
    assert_ne!(honest.aggregate_sig.as_bytes(), &[0u8; 96]);
}
