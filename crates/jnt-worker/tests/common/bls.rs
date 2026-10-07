//! Real-BLS validator keys for the harness (the `[i;48]` placeholder keys are
//! not curve points and the real verifier refuses them — Phase 4 lesson).

#![allow(dead_code)]

use jnt_core::bls::SecretKey;
use jnt_core::bls_checkpoint::ValidatorSet;

/// A validator set of `n` real, distinct keys, sorted by `ValidatorSet::new`.
pub fn validator_set(n: usize) -> ValidatorSet {
    let secrets: Vec<SecretKey> = (1..=n as u8)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect();
    ValidatorSet::new(secrets.iter().map(|sk| sk.public_key()).collect())
}

/// The secrets behind [`validator_set`], for signing quorum aggregates in
/// tests that build settle transactions.
pub fn validator_secrets(n: usize) -> Vec<SecretKey> {
    (1..=n as u8)
        .map(|i| SecretKey::derive(&[i; 32]).unwrap())
        .collect()
}
