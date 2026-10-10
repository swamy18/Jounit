//! M5 binding finality (Decisions 12/14, SPEC.md §14.8).
//!
//! **BINDING once activated.** A valid checkpoint certificate over the active
//! committee becomes consensus-final when its height reaches the profile's
//! `finality_activation_height`. From then on `Chain::adopt()` refuses any
//! branch that forks at or below the finalized height — the same
//! `ReorgWouldCrossFinality` gate that previously used only the depth rule.
//!
//! Before activation the manager still verifies and records certificates
//! (observation), but `binding_finalized_height()` stays 0, so consensus is
//! unchanged — this is the M4 behavior, preserved by construction.
//!
//! Conflict safety (Decision 14): two otherwise-valid certificates that name
//! different block hashes at the same height never both finalize. The second
//! transition is refused, the conflict is retained as deterministic
//! [`EquivocationEvidence`], and nothing is burned — there is no bond to burn.

use crate::bls_checkpoint::{BlsPublicKey, BlsVerifier, Checkpoint, ValidatorSet};
use crate::hash::Hash;
use crate::params::NetworkParams;
use crate::validators::{
    equivocation_evidence, genesis_epoch_set_at, validate_checkpoint_against_set, EpochSet,
    EquivocationEvidence, ValidatorError,
};

/// Maximum retained equivocation evidence records. Evidence is diagnostic until
/// economic slashing exists (no stake ledger in Phase 6), so it is bounded
/// rather than allowed to grow with every conflict a hostile peer invents.
pub const MAX_EQUIVOCATION_EVIDENCE: usize = 1024;

/// A certificate rejection or a finality conflict. Not a block-validity error:
/// a refused checkpoint never invalidates a block, it just fails to finalize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityError {
    /// The certificate did not satisfy the six validation clauses.
    InvalidCertificate(ValidatorError),
    /// The certificate's block is not the canonical block at its height (or the
    /// height is beyond the tip — a future certificate).
    NotCanonical { height: u64 },
    /// The height is not strictly beyond the last accepted height (a replay, or
    /// a stale certificate).
    NotMonotonic { height: u64, accepted: u64 },
    /// A different block hash is already finalized/accepted at this height.
    /// Retained as equivocation evidence; fail closed.
    ConflictingFinality {
        height: u64,
        finalized: Hash,
        conflicting: Hash,
    },
}

impl std::fmt::Display for FinalityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalityError::InvalidCertificate(e) => {
                write!(f, "invalid checkpoint certificate: {e}")
            }
            FinalityError::NotCanonical { height } => {
                write!(
                    f,
                    "checkpoint at height {height} is not the canonical block"
                )
            }
            FinalityError::NotMonotonic { height, accepted } => write!(
                f,
                "checkpoint height {height} is not beyond the accepted height {accepted}"
            ),
            FinalityError::ConflictingFinality { height, .. } => {
                write!(f, "conflicting finalized block at height {height}")
            }
        }
    }
}

impl std::error::Error for FinalityError {}

/// The node's view of the committee's certificates and the resulting finalized
/// point. Owned by [`crate::chain::Chain`]; consulted by `adopt()`.
#[derive(Debug, Default, Clone)]
pub struct FinalityManager {
    /// The fixed genesis committee (Decision 11). Empty means no committee, so
    /// every certificate fails closed.
    keys: Vec<BlsPublicKey>,
    /// The network this manager observes; a certificate for another network is
    /// refused even if the keys happened to match.
    network_id: String,
    /// Blocks per epoch, for the height→epoch clause.
    epoch_blocks: u64,
    /// Height at which a valid certificate becomes binding (0 = never).
    activation_height: u64,
    /// Highest accepted (verified, canonical, monotonic) checkpoint height.
    /// This is the observation frontier; certificates at or below it are
    /// replays.
    accepted_height: u64,
    /// Highest binding-finalized height (0 = not activated / none).
    finalized_height: u64,
    /// Canonical block hash finalized at `finalized_height`.
    finalized_hash: Hash,
    /// The certificate that set the binding height, kept for conflict evidence.
    finalized_checkpoint: Option<Checkpoint>,
    /// A bounded ring of recent accepted certificates, for conflict evidence at
    /// heights not yet finalized.
    recent: Vec<Checkpoint>,
    /// Deterministic equivocation evidence, bounded.
    evidence: Vec<EquivocationEvidence>,
}

/// How many recent certificates are retained for conflict evidence. Bounded so
/// a hostile peer cannot grow memory by streaming certificates.
pub const MAX_RECENT_CHECKPOINTS: usize = 256;

impl FinalityManager {
    /// Build from a profile's declared committee, interval, and activation.
    pub fn new(params: &NetworkParams) -> Self {
        Self {
            keys: params.genesis_validators.clone(),
            network_id: params.network_id.clone(),
            epoch_blocks: params.checkpoint_interval_blocks,
            activation_height: params.finality_activation_height,
            accepted_height: 0,
            finalized_height: 0,
            finalized_hash: [0u8; 32],
            finalized_checkpoint: None,
            recent: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Number of validators in the declared committee.
    pub fn committee_len(&self) -> usize {
        self.keys.len()
    }

    /// Replace the committee key set (Decision 20). The chain calls this
    /// whenever canonical bond state advances or rewinds, so certificates are
    /// always validated against the ledger-derived committee. With no bonds
    /// the chain passes the profile's declared committee and nothing changes.
    pub fn set_keys(&mut self, keys: Vec<BlsPublicKey>) {
        self.keys = keys;
    }

    /// The configured activation height (0 = binding finality never activates).
    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    /// Highest binding-finalized height (0 = none).
    pub fn binding_finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Canonical hash finalized at the binding height (zero if none).
    pub fn binding_finalized_hash(&self) -> Hash {
        self.finalized_hash
    }

    /// Highest accepted (observation) checkpoint height.
    pub fn accepted_height(&self) -> u64 {
        self.accepted_height
    }

    /// True if `height` is at or below the accepted observation frontier.
    /// Observation only: unlike [`Self::is_finalized`], this does not authorize
    /// reorg refusal.
    pub fn is_observed(&self, height: u64) -> bool {
        self.accepted_height > 0 && height <= self.accepted_height
    }

    /// True if `height` is at or below the binding finalized height.
    pub fn is_finalized(&self, height: u64) -> bool {
        self.finalized_height > 0 && height <= self.finalized_height
    }

    /// Retained equivocation evidence.
    pub fn evidence(&self) -> &[EquivocationEvidence] {
        &self.evidence
    }

    /// Verify a checkpoint certificate and, if it extends the observation
    /// frontier, accept it. When activated and at/after the activation height,
    /// acceptance also sets the binding finalized point.
    ///
    /// `canonical` is the node's own canonical block hash at the certificate's
    /// height (`None` if the height is beyond the tip). A certificate is only
    /// accepted if it names exactly that hash, so a valid signature over a
    /// non-canonical block — or a future block — never finalizes.
    ///
    /// Fails closed: a rejection records nothing and never moves finality.
    pub fn accept(
        &mut self,
        checkpoint: &Checkpoint,
        canonical: Option<Hash>,
        verify: &dyn BlsVerifier,
    ) -> Result<(), FinalityError> {
        let height = checkpoint.payload.height;

        // Cross-network defence before any signature work.
        if checkpoint.payload.network_id != self.network_id {
            return Err(FinalityError::InvalidCertificate(
                ValidatorError::CheckpointWrongSet {
                    expected: crate::hash::sha256_dom(
                        b"jounit/network-id-mismatch/v1",
                        &[checkpoint.payload.network_id.as_bytes()],
                    ),
                },
            ));
        }

        // Full certificate validity (epoch, set, bitmap, count, quorum,
        // signature). Monotonicity is checked here, not by clause 6, so a
        // same-height conflicting certificate is classified as a conflict
        // rather than a stale replay. A floor of 0 makes clause 6 inert.
        let keys = &self.keys;
        validate_checkpoint_against_set(
            checkpoint,
            |epoch| genesis_epoch_set_at(epoch, keys),
            0,
            self.epoch_blocks,
            verify,
        )
        .map_err(FinalityError::InvalidCertificate)?;

        // Conflict (Decision 14): a different hash already accepted/finalized at
        // this height. Checked *before* the canonical clause so that a
        // certificate for `H -> hash_B` when `H -> hash_A` is retained is
        // classified as the conflict it is — and produces evidence — instead of
        // being misfiled as merely non-canonical. Both certificates were
        // otherwise valid (six clauses passed), which is exactly the
        // equivocation shape Decision 14 requires be detected.
        if let Some(prior) = self.prior_at(height).cloned() {
            if prior.payload.block_hash != checkpoint.payload.block_hash {
                if let Some(ev) = conflict_evidence(&self.keys, &prior, checkpoint) {
                    self.record_evidence(ev);
                }
                return Err(FinalityError::ConflictingFinality {
                    height,
                    finalized: prior.payload.block_hash,
                    conflicting: checkpoint.payload.block_hash,
                });
            }
        }

        // Canonical-chain binding: the certificate must name the block this node
        // holds canonically at that height. A valid signature over a
        // non-canonical block (with no retained conflict to prove) fails here.
        match canonical {
            Some(h) if h == checkpoint.payload.block_hash => {}
            _ => return Err(FinalityError::NotCanonical { height }),
        }

        // Monotonic: strictly beyond the accepted frontier. (Same-height
        // same-hash lands here as a replay.)
        if height <= self.accepted_height {
            return Err(FinalityError::NotMonotonic {
                height,
                accepted: self.accepted_height,
            });
        }

        // Record the observation.
        self.accepted_height = height;
        self.push_recent(checkpoint.clone());

        // Activate binding finality once the height reaches the threshold.
        if self.activation_height > 0 && height >= self.activation_height {
            self.finalized_height = height;
            self.finalized_hash = checkpoint.payload.block_hash;
            self.finalized_checkpoint = Some(checkpoint.clone());
        }

        Ok(())
    }

    /// Restore a persisted binding-finalized point after a restart. The caller
    /// (`Chain`) must have validated that `hash` is the canonical block at
    /// `height`; this only installs the value.
    pub fn restore_finalized(&mut self, height: u64, hash: Hash) {
        if height > self.finalized_height {
            self.finalized_height = height;
            self.finalized_hash = hash;
            self.accepted_height = self.accepted_height.max(height);
        }
    }

    /// The certificate that set the binding height, if any.
    pub fn finalized_checkpoint(&self) -> Option<&Checkpoint> {
        self.finalized_checkpoint.as_ref()
    }

    /// The most recent accepted certificate whose height equals `height`.
    fn prior_at(&self, height: u64) -> Option<&Checkpoint> {
        if let Some(c) = &self.finalized_checkpoint {
            if c.payload.height == height {
                return Some(c);
            }
        }
        self.recent.iter().find(|c| c.payload.height == height)
    }

    fn push_recent(&mut self, cp: Checkpoint) {
        self.recent.push(cp);
        if self.recent.len() > MAX_RECENT_CHECKPOINTS {
            self.recent.remove(0);
        }
    }

    fn record_evidence(&mut self, ev: EquivocationEvidence) {
        // Dedup: the same offender/payload pair produces the same evidence, and
        // a hostile peer can replay it.
        if !self.evidence.contains(&ev) {
            if self.evidence.len() >= MAX_EQUIVOCATION_EVIDENCE {
                self.evidence.remove(0);
            }
            self.evidence.push(ev);
        }
    }

    /// The epoch set for `epoch`, for callers that want to inspect it.
    pub fn epoch_set(&self, epoch: u64) -> Result<EpochSet, ValidatorError> {
        genesis_epoch_set_at(epoch, &self.keys)
    }
}

/// Find the first committee key that signed both conflicting certificates and
/// bind it with `equivocation_evidence`.
///
/// Two determinism guarantees, so two nodes that saw the certificates in
/// opposite orders retain byte-identical evidence:
/// - the payload pair is ordered by serialized bytes before hashing, so
///   `first`/`second` never depend on arrival order;
/// - the offender is the first *common* signer in canonical key order (the
///   bitmap iterates keys exactly as `ValidatorSet`/`EpochSet` sort them).
fn conflict_evidence(
    keys: &[BlsPublicKey],
    a: &Checkpoint,
    b: &Checkpoint,
) -> Option<EquivocationEvidence> {
    let set = ValidatorSet::new(keys.to_vec());
    let signers_a = set.signers_from_bitmap(&a.signer_bitmap);
    let signers_b = set.signers_from_bitmap(&b.signer_bitmap);
    let offender = signers_a.into_iter().find(|k| signers_b.contains(k))?;
    // Canonical order: the lexicographically smaller payload serialization is
    // always `a` in the evidence.
    let (first, second) = if a.payload.serialize() <= b.payload.serialize() {
        (a, b)
    } else {
        (b, a)
    };
    equivocation_evidence(&offender, first, second)
}
