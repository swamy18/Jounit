//! M4 finality observation (Decision 11, SPEC.md §14).
//!
//! **NON-BINDING — NOT CONSENSUS-ACTIVE.** This type verifies checkpoint
//! certificates against the fixed genesis committee and remembers the highest
//! observed height. It is never consulted by `Chain::submit`, fork choice, or
//! `Chain::finalized_height`: a reorg crossing an observed checkpoint still
//! applies, and that is pinned by test so binding can never slip in silently.
//!
//! The point of M4 is to make the validator/finality machinery real and
//! observable without letting it decide anything. `FinalityManager` reports
//! what the committee has signed; it does not enforce it.

use crate::bls_checkpoint::{BlsPublicKey, BlsVerifier, Checkpoint};
use crate::hash::Hash;
use crate::params::NetworkParams;
use crate::validators::{
    genesis_epoch_set_at, validate_checkpoint_against_set, EpochSet, ValidatorError,
};

/// Observed checkpoints: the node's local view of what the committee signed.
///
/// Deliberately carries no authority. The only mutable state is the accepted
/// checkpoint list, and nothing outside this type reads it to gate block
/// acceptance.
#[derive(Debug, Default)]
pub struct FinalityManager {
    /// The fixed genesis committee (Decision 11). Empty on `mainnet` until a
    /// committee is declared, which makes every observation fail closed.
    keys: Vec<BlsPublicKey>,
    /// The network this manager observes, checked against each checkpoint's
    /// payload so a certificate signed for another network is refused even if
    /// the keys happened to match.
    network_id: String,
    /// Blocks per epoch, for the height→epoch clause.
    epoch_blocks: u64,
    /// Highest observed checkpoint height (0 = none observed).
    observed_height: u64,
    /// (height, block_hash) for each observed checkpoint, in ascending height.
    observed: Vec<(u64, Hash)>,
}

impl FinalityManager {
    /// Build from a profile's declared committee and checkpoint interval.
    pub fn new(params: &NetworkParams) -> Self {
        Self {
            keys: params.genesis_validators.clone(),
            network_id: params.network_id.clone(),
            epoch_blocks: params.checkpoint_interval_blocks,
            observed_height: 0,
            observed: Vec::new(),
        }
    }

    /// Number of validators in the declared committee.
    pub fn committee_len(&self) -> usize {
        self.keys.len()
    }

    /// Highest height the committee has been observed signing (0 = none).
    pub fn observed_height(&self) -> u64 {
        self.observed_height
    }

    /// True if `height` is at or below the highest observed checkpoint.
    /// Observation only: does not authorize reorg refusal.
    pub fn is_observed_final(&self, height: u64) -> bool {
        height <= self.observed_height
    }

    /// The block hash observed at `height`, if any.
    pub fn observed_block_at(&self, height: u64) -> Option<Hash> {
        self.observed
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| *hash)
    }

    /// Number of checkpoints observed so far.
    pub fn observed_count(&self) -> usize {
        self.observed.len()
    }

    /// Verify a checkpoint certificate against the declared committee and, if
    /// valid and strictly newer, record it.
    ///
    /// Fails closed: with an empty committee there is no set to verify
    /// against, so clause 4/5 reject every certificate. Rejections name their
    /// clause via `ValidatorError`; nothing is recorded on failure.
    pub fn observe(
        &mut self,
        checkpoint: &Checkpoint,
        verify: &dyn BlsVerifier,
    ) -> Result<(), ValidatorError> {
        // Cross-network defence before any signature work: a certificate for
        // another network must not be observed here even if its keys matched.
        if checkpoint.payload.network_id != self.network_id {
            return Err(ValidatorError::CheckpointWrongSet {
                expected: crate::hash::sha256_dom(
                    b"jounit/network-id-mismatch/v1",
                    &[checkpoint.payload.network_id.as_bytes()],
                ),
            });
        }

        let keys = &self.keys;
        let epoch_blocks = self.epoch_blocks;
        validate_checkpoint_against_set(
            checkpoint,
            |epoch| genesis_epoch_set_at(epoch, keys),
            self.observed_height,
            epoch_blocks,
            verify,
        )?;

        self.observed_height = checkpoint.payload.height;
        self.observed
            .push((checkpoint.payload.height, checkpoint.payload.block_hash));
        Ok(())
    }

    /// The epoch set for `epoch`, for callers that want to inspect it.
    pub fn epoch_set(&self, epoch: u64) -> Result<EpochSet, ValidatorError> {
        genesis_epoch_set_at(epoch, &self.keys)
    }
}
