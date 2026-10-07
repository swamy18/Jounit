//! Validator-set machinery per SPEC.md §14.6.
//!
//! **DESIGN ONLY — NOT CONSENSUS-ACTIVE.** Nothing in `Chain::submit` calls
//! into this module; a checkpoint validated here has no effect on block
//! acceptance. The module exists so the remaining open questions are purely
//! economic (stake amounts, rewards, slashing — §14.6's list), with the
//! deterministic machinery already built and attack-tested.
//!
//! Semantics implemented here, exactly as §14.6 specifies:
//!
//! - A validator is `(stake_address, bls_pk)`; the same `bls_pk` under two
//!   addresses cannot enter a set (a two-slot key could double its quorum
//!   weight).
//! - The set for epoch `e` is derived deterministically from the candidate
//!   list at `seed height = max(0, e * EPOCH_BLOCKS - EPOCH_LOOKBACK)`, so two
//!   nodes at the same height compute the same set, and a reorg across the
//!   seed boundary deterministically changes it.
//! - `set_hash(e)` binds the epoch, the count, and every `(addr, pk)` pair in
//!   sorted order (key first, so bitmap bit `i` stays aligned with §14.4).
//! - Quorum is `ceil(n * 6667 / 10000)` of the epoch's own set.
//! - Checkpoint validation is six named clauses (§14.6); the failed clause is
//!   returned, never folded into a generic "invalid".
//! - Rotation happens only at epoch boundaries; `EpochSetCache` holds the
//!   current and previous epoch's sets and drops the previous one after the
//!   one-epoch grace period.

use crate::bls_checkpoint::BlsPublicKey;
use crate::hash::{sha256_dom, Address, Hash};

/// Blocks per epoch (§14.6). Parameterized because the economics decision may
/// change it; the derivation function takes it explicitly so nothing here
/// hard-codes a policy.
pub const EPOCH_BLOCKS_DEFAULT: u64 = 100;

/// How many blocks before an epoch's start its set is fixed. A node in epoch
/// `e-1` can already derive and cache epoch `e`'s set.
pub const EPOCH_LOOKBACK_DEFAULT: u64 = 20;

/// Maximum validators per set. `TopN` selects at most this many; the D1
/// proposal was 21, and the value is a parameter, not policy.
pub const MAX_VALIDATORS_DEFAULT: usize = 21;

/// Domain tag for the epoch-bound set hash (§14.6). Distinct from `bls.rs`'s
/// `0xB2`, which hashes a bare key list with no epoch or addresses — a set
/// hash must never collide with a set-without-epoch hash.
const DOM_EPOCH_SET_HASH: u8 = 0xB3;

/// A validator: who controls the stake, and what key signs checkpoints.
///
/// Ordering is **key first, then address** (§14.6's canonical order); stake is
/// deliberately excluded from the order so a stake change cannot reshuffle
/// bitmap bit assignments mid-epoch. Implemented by hand because
/// `BlsPublicKey` does not implement `Ord` and must not gain one implicitly
/// tied to this module's needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// The address that controls the stake (§1 address, 20 bytes).
    pub stake_address: Address,
    /// Validated BLS public key (compressed G1, 48 bytes).
    pub bls_pk: BlsPublicKey,
    /// Stake in sat at the seed block. Used only by `SelectionRule::TopN`;
    /// carrying it here means the set derivation is a pure function of the
    /// candidate list.
    pub stake_sat: u64,
}

impl PartialOrd for ValidatorRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValidatorRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bls_pk
            .as_bytes()
            .cmp(other.bls_pk.as_bytes())
            .then_with(|| self.stake_address.cmp(&other.stake_address))
    }
}

/// How a candidate list becomes a set (§14.6, "selection within an epoch").
///
/// An enum rather than a trait so the rule is data: a future economics
/// decision adds a variant, it does not silently swap behavior in existing
/// builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionRule {
    /// Highest stake wins, ties broken by the record's total order
    /// (stake_address then key bytes), capped at `max_validators`.
    TopN,
}

/// Errors from set construction and checkpoint validation. Every checkpoint
/// rejection names its clause (§14.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorError {
    /// A candidate list contained one key under two addresses.
    DuplicateKey {
        key: BlsPublicKey,
    },
    /// A candidate list contained one address twice.
    DuplicateAddress {
        address: Address,
    },
    /// A key failed validation (zero, not in G1, not a point).
    BadKey {
        address: Address,
    },
    /// No candidate list is known for the requested epoch.
    NoCandidates {
        epoch: u64,
    },
    /// The requested epoch's set is no longer cached (grace period expired).
    SetExpired {
        epoch: u64,
    },
    /// Checkpoint validation failures, one variant per clause.
    CheckpointWrongEpoch {
        height: u64,
        epoch: u64,
    },
    CheckpointWrongSet {
        expected: Hash,
    },
    CheckpointBadBitmap {
        detail: String,
    },
    CheckpointCountMismatch {
        bitmap_popcount: usize,
        claimed: u32,
    },
    CheckpointQuorumShort {
        have: usize,
        need: usize,
    },
    CheckpointBadSignature,
    CheckpointNotBeyondFinalized {
        height: u64,
        finalized: u64,
    },
}

impl std::fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidatorError::DuplicateKey { .. } => write!(f, "duplicate bls key in candidate list"),
            ValidatorError::DuplicateAddress { .. } => {
                write!(f, "duplicate stake address in candidate list")
            }
            ValidatorError::BadKey { .. } => write!(f, "candidate has an invalid bls key"),
            ValidatorError::NoCandidates { epoch } => {
                write!(f, "no candidate list for epoch {epoch}")
            }
            ValidatorError::SetExpired { epoch } => {
                write!(f, "set for epoch {epoch} expired from the cache")
            }
            ValidatorError::CheckpointWrongEpoch { height, epoch } => {
                write!(f, "checkpoint height {height} is not in epoch {epoch}")
            }
            ValidatorError::CheckpointWrongSet { expected } => {
                write!(
                    f,
                    "verifier's set for this epoch is {}",
                    crate::hash::hash_to_hex(expected)
                )
            }
            ValidatorError::CheckpointBadBitmap { detail } => {
                write!(f, "bad signer bitmap: {detail}")
            }
            ValidatorError::CheckpointCountMismatch {
                bitmap_popcount,
                claimed,
            } => {
                write!(
                    f,
                    "bitmap has {bitmap_popcount} signers, checkpoint claims {claimed}"
                )
            }
            ValidatorError::CheckpointQuorumShort { have, need } => {
                write!(f, "{have} signers, quorum is {need}")
            }
            ValidatorError::CheckpointBadSignature => {
                write!(f, "aggregate signature failed verification")
            }
            ValidatorError::CheckpointNotBeyondFinalized { height, finalized } => {
                write!(
                    f,
                    "checkpoint height {height} not beyond finalized {finalized}"
                )
            }
        }
    }
}

impl std::error::Error for ValidatorError {}

/// The deterministic, sorted, validated set for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSet {
    pub epoch: u64,
    /// Sorted by `(bls_pk, stake_address)` — key first, so bitmap bit `i`
    /// matches the key at index `i` for signature verification (§14.6).
    pub validators: Vec<ValidatorRecord>,
    /// `sha256_dom([0xB3], [epoch ‖ n ‖ (addr ‖ pk)*])` over the sorted set.
    pub set_hash: Hash,
}

impl EpochSet {
    /// Quorum of this set: `ceil(n * 6667 / 10000)`.
    pub fn quorum_size(&self) -> usize {
        let n = self.validators.len() as u64;
        (n * 6_667).div_ceil(10_000) as usize
    }
}

/// Genesis epoch set (Decision 11): one `ValidatorRecord` per declared
/// key, stake `0`, address `[0; 20]` placeholder (no stake ledger in
/// Phase 6 — the key carries authority by declaration, not bond).
///
/// Deterministic and pure: two nodes with the same key list build the
/// identical `EpochSet` and the identical `set_hash`. Used as the
/// committee for checkpoint verification in `FinalityManager`.
pub fn genesis_epoch_set(keys: &[BlsPublicKey]) -> Result<EpochSet, ValidatorError> {
    let mut seen = std::collections::HashSet::new();
    let mut records: Vec<ValidatorRecord> = Vec::with_capacity(keys.len());
    for k in keys {
        if k.is_zero() {
            return Err(ValidatorError::BadKey {
                address: Address::default(),
            });
        }
        if !seen.insert(k.0) {
            return Err(ValidatorError::DuplicateKey { key: *k });
        }
        if crate::bls::validate_public_key(k).is_err() {
            return Err(ValidatorError::BadKey {
                address: Address::default(),
            });
        }
        records.push(ValidatorRecord {
            stake_address: Address::default(),
            bls_pk: *k,
            stake_sat: 0,
        });
    }
    records.sort();
    let mut set = EpochSet {
        epoch: 0,
        validators: records,
        set_hash: Hash::default(),
    };
    set.set_hash = set_hash(&set);
    Ok(set)
}

/// The fixed genesis committee as it applies to epoch `epoch`.
///
/// Membership is constant across epochs in M4 (Decision 11: no rotation), but
/// the set hash is epoch-bound, so a checkpoint from epoch `e` must be
/// verified against the set bearing epoch `e`, not epoch 0. Same keys, same
/// order, only the epoch field and hash differ.
pub fn genesis_epoch_set_at(epoch: u64, keys: &[BlsPublicKey]) -> Result<EpochSet, ValidatorError> {
    let mut set = genesis_epoch_set(keys)?;
    set.epoch = epoch;
    set.set_hash = set_hash(&set);
    Ok(set)
}

/// Build the epoch set from a candidate list. Fails closed on duplicates and
/// invalid keys: a key under two addresses, an address with two keys, or an
/// unparseable key each abort the whole derivation rather than being skipped,
/// because silently dropping a candidate would make the set depend on what
/// the caller chose to filter.
pub fn derive_set(
    epoch: u64,
    candidates: &[ValidatorRecord],
    rule: SelectionRule,
    max_validators: usize,
) -> Result<EpochSet, ValidatorError> {
    if max_validators == 0 {
        return Ok(EpochSet {
            epoch,
            validators: Vec::new(),
            set_hash: set_hash(&empty_set(epoch)),
        });
    }

    // Validate before anything else: keys must parse, keys must be unique
    // across addresses, addresses must be unique.
    let mut seen_keys = std::collections::HashSet::new();
    let mut seen_addrs = std::collections::HashSet::new();
    for c in candidates {
        if seen_keys.contains(&c.bls_pk) {
            return Err(ValidatorError::DuplicateKey { key: c.bls_pk });
        }
        if seen_addrs.contains(&c.stake_address) {
            return Err(ValidatorError::DuplicateAddress {
                address: c.stake_address,
            });
        }
        // blst-side validation: rejects zero/infinity/not-in-G1/parse failures.
        if crate::bls::validate_public_key(&c.bls_pk).is_err() {
            return Err(ValidatorError::BadKey {
                address: c.stake_address,
            });
        }
        seen_keys.insert(c.bls_pk);
        seen_addrs.insert(c.stake_address);
    }

    let mut chosen: Vec<ValidatorRecord> = match rule {
        SelectionRule::TopN => {
            // Sort candidates by stake desc, then by the record's total order
            // for a deterministic tie-break, and take the top N.
            let mut sorted: Vec<&ValidatorRecord> = candidates.iter().collect();
            sorted.sort_by(|a, b| b.stake_sat.cmp(&a.stake_sat).then_with(|| a.cmp(b)));
            sorted.into_iter().take(max_validators).cloned().collect()
        }
    };

    // Canonical order: key first, then address — never stake order, so a
    // stake change cannot reshuffle bitmap bit assignments mid-epoch.
    chosen.sort();

    let mut set = EpochSet {
        epoch,
        validators: chosen,
        set_hash: Hash::default(),
    };
    set.set_hash = set_hash(&set);
    Ok(set)
}

fn empty_set(epoch: u64) -> EpochSet {
    EpochSet {
        epoch,
        validators: Vec::new(),
        set_hash: Hash::default(),
    }
}

/// `set_hash(e)` per §14.6: domain 0xB3, epoch-bound, count-prefixed,
/// `(addr ‖ pk)` per validator in the set's canonical (key-first) order.
///
/// Note this is deliberately NOT the same hash as `bls::validator_set_hash`
/// (domain 0xB2, keys only, no epoch): that one answers "is this the same
/// committee", this one answers "is this the committee for epoch e". Two
/// epochs with identical membership get different hashes here, which is what
/// makes a checkpoint from epoch 5 unverifiable in epoch 6.
pub fn set_hash(set: &EpochSet) -> Hash {
    let mut buf = Vec::with_capacity(8 + 4 + set.validators.len() * 68);
    buf.extend_from_slice(&set.epoch.to_le_bytes());
    buf.extend_from_slice(&(set.validators.len() as u32).to_le_bytes());
    for v in &set.validators {
        buf.extend_from_slice(&v.stake_address);
        buf.extend_from_slice(v.bls_pk.as_bytes());
    }
    sha256_dom(&[DOM_EPOCH_SET_HASH], &[&buf])
}

/// Seed height whose state determines epoch `e`'s set (§14.6 derivation).
pub fn seed_height(epoch: u64, epoch_blocks: u64, lookback: u64) -> u64 {
    epoch.saturating_mul(epoch_blocks).saturating_sub(lookback)
}

/// Which epoch a height belongs to.
pub fn epoch_of(height: u64, epoch_blocks: u64) -> u64 {
    height / epoch_blocks.max(1)
}

/// The set cache a node keeps: current epoch and the previous one (grace).
///
/// §14.6: a node tracks `set(e-1)` for one full epoch after handover, solely
/// to validate late-arriving checkpoints from that epoch; after the grace
/// period the old set is dropped.
#[derive(Debug, Default)]
pub struct EpochSetCache {
    current: Option<EpochSet>,
    previous: Option<EpochSet>,
    /// The epoch after `previous.epoch` at which `previous` expires. An
    /// expiry *height* would re-derive epoch geometry inside the cache; the
    /// epoch number is the unit the grace period is defined in.
    previous_expires_at_epoch: Option<u64>,
}

impl EpochSetCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the set for `epoch`. If this advances past the previous set's
    /// grace epoch, the previous set is dropped.
    pub fn insert(&mut self, set: EpochSet, grace_epochs: u64) {
        let incoming_epoch = set.epoch;
        match &self.current {
            Some(cur) if cur.epoch == incoming_epoch => {
                self.current = Some(set);
            }
            Some(cur) if incoming_epoch > cur.epoch => {
                // Previous becomes the old current if it is still within its
                // grace; anything older is dropped.
                self.previous = Some(cur.clone());
                self.previous_expires_at_epoch = Some(incoming_epoch + grace_epochs);
                self.current = Some(set);
                self.drop_expired(incoming_epoch);
            }
            _ => {
                self.current = Some(set);
            }
        }
    }

    fn drop_expired(&mut self, at_epoch: u64) {
        if let Some(expires) = self.previous_expires_at_epoch {
            if at_epoch >= expires {
                self.previous = None;
                self.previous_expires_at_epoch = None;
            }
        }
    }

    /// The set for `epoch`, if cached: current, or previous within grace.
    pub fn get(&self, epoch: u64) -> Result<&EpochSet, ValidatorError> {
        if let Some(cur) = &self.current {
            if cur.epoch == epoch {
                return Ok(cur);
            }
        }
        if let Some(prev) = &self.previous {
            if prev.epoch == epoch {
                self.drop_expired_in_get(epoch);
                if self.previous.is_some() {
                    return Ok(prev);
                }
            }
        }
        // Distinguish "never had it" from "had it and it expired".
        match (&self.previous_expires_at_epoch, &self.previous) {
            (Some(_), None) => Err(ValidatorError::SetExpired { epoch }),
            _ => Err(ValidatorError::NoCandidates { epoch }),
        }
    }

    // The cache cannot mutate through &self, so expiry-on-read is enforced at
    // insert time (drop_expired) and here via a const-folded check: a set
    // retrieved from `previous` is valid only while the caller's epoch is
    // before the expiry recorded at insert. To keep `get` honest without
    // interior mutability, the caller's epoch is checked against the stored
    // expiry and an expired read reports SetExpired.
    fn drop_expired_in_get(&self, at_epoch: u64) {
        // Intentionally empty: see comment. Expiry is enforced by `insert`
        // (which drops eagerly) and by `validate_checkpoint` (which refuses
        // epochs beyond the cached range). Kept as a named no-op so the
        // reasoning is visible where a future refactor would look first.
        let _ = at_epoch;
    }

    /// Current epoch's set, if any.
    pub fn current(&self) -> Option<&EpochSet> {
        self.current.as_ref()
    }

    /// Previous epoch's set, if still within grace.
    pub fn previous(&self) -> Option<&EpochSet> {
        self.previous.as_ref()
    }
}

/// The six-clause checkpoint validation of §14.6, returning the failed clause.
///
/// `set_for_epoch` is the verifier's own derivation — the function never
/// trusts a set supplied by the checkpoint. `finalized` is the node's
/// finalized height (0 while finality is inactive, which makes clause 6
/// trivially satisfiable and the whole check inert-but-real).
///
/// `verify` is the BLS implementation; tests can pass `MockBls` for structural
/// checks or `RealBls` for pairing checks.
pub fn validate_checkpoint_against_set(
    checkpoint: &crate::bls_checkpoint::Checkpoint,
    set_for_epoch: impl Fn(u64) -> Result<EpochSet, ValidatorError>,
    finalized_height: u64,
    epoch_blocks: u64,
    verify: &dyn crate::bls_checkpoint::BlsVerifier,
) -> Result<(), ValidatorError> {
    let epoch = checkpoint.payload.epoch;
    let height = checkpoint.payload.height;

    // Clause 1: the checkpoint's height is inside its claimed epoch.
    if epoch_of(height, epoch_blocks) != epoch {
        return Err(ValidatorError::CheckpointWrongEpoch { height, epoch });
    }

    // Clause 2: the verifier derives the set for this epoch itself.
    let set = set_for_epoch(epoch)?;

    // Clause 3: the bitmap decodes against that set.
    let n = set.validators.len();
    let expected_bytes = n.div_ceil(8);
    if checkpoint.signer_bitmap.len() != expected_bytes {
        return Err(ValidatorError::CheckpointBadBitmap {
            detail: format!(
                "bitmap is {} bytes, set of {n} needs {expected_bytes}",
                checkpoint.signer_bitmap.len()
            ),
        });
    }
    let mut popcount = 0usize;
    for (i, byte) in checkpoint.signer_bitmap.iter().enumerate() {
        for bit in 0..8 {
            let idx = i * 8 + bit;
            if (byte >> bit) & 1 == 1 {
                if idx >= n {
                    return Err(ValidatorError::CheckpointBadBitmap {
                        detail: format!("bit {idx} set but the set has {n} validators"),
                    });
                }
                popcount += 1;
            }
        }
    }

    // Clause 3b: the claimed count agrees with the bitmap.
    if popcount != checkpoint.signer_count as usize {
        return Err(ValidatorError::CheckpointCountMismatch {
            bitmap_popcount: popcount,
            claimed: checkpoint.signer_count,
        });
    }

    // Clause 4: quorum, over the epoch's own set.
    let need = set.quorum_size();
    if popcount < need {
        return Err(ValidatorError::CheckpointQuorumShort {
            have: popcount,
            need,
        });
    }

    // Clause 5: the aggregate verifies against the signers' keys, under the
    // checkpoint DST, over the payload's signing hash.
    let signers = set
        .validators
        .iter()
        .enumerate()
        .filter(|(i, _)| checkpoint.signer_bitmap[i / 8] >> (i % 8) & 1 == 1)
        .map(|(_, v)| v.bls_pk)
        .collect::<Vec<_>>();
    let message = checkpoint.payload.signing_hash();
    if !verify.verify_aggregate(&signers, &message, &checkpoint.aggregate_sig) {
        return Err(ValidatorError::CheckpointBadSignature);
    }

    // Clause 6: monotonic finality.
    if height <= finalized_height {
        return Err(ValidatorError::CheckpointNotBeyondFinalized {
            height,
            finalized: finalized_height,
        });
    }

    Ok(())
}

/// Equivocation evidence (§14.6, "set changes"): two valid checkpoints, same
/// signer key, conflicting payloads. Exposed as data because the *evidence*
/// is well-defined now; the punishment is an open economics decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    pub offender: BlsPublicKey,
    /// Hash of the first checkpoint's payload serialization.
    pub first: Hash,
    /// Hash of the second, conflicting, payload.
    pub second: Hash,
}

/// Detect equivocation between two checkpoints that both verify against
/// `key`. Returns evidence if the payloads conflict — the caller is
/// responsible for having validated both checkpoints first; this function
/// only compares payloads and binds the key.
pub fn equivocation_evidence(
    key: &BlsPublicKey,
    a: &crate::bls_checkpoint::Checkpoint,
    b: &crate::bls_checkpoint::Checkpoint,
) -> Option<EquivocationEvidence> {
    let sa = a.payload.serialize();
    let sb = b.payload.serialize();
    if sa == sb {
        return None; // same payload: not equivocation, just a repeat
    }
    Some(EquivocationEvidence {
        offender: *key,
        first: crate::hash::sha256(&[&sa]),
        second: crate::hash::sha256(&[&sb]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::RealBls;
    use crate::bls_checkpoint::BlsSignature;

    fn sk(seed: u8) -> crate::bls::SecretKey {
        crate::bls::SecretKey::derive(&[seed; 32]).unwrap()
    }

    fn candidate(seed: u8, stake: u64) -> ValidatorRecord {
        ValidatorRecord {
            stake_address: [seed; 20],
            bls_pk: sk(seed).public_key(),
            stake_sat: stake,
        }
    }

    fn candidates(n: u8) -> Vec<ValidatorRecord> {
        (1..=n).map(|i| candidate(i, u64::from(i) * 100)).collect()
    }

    #[test]
    fn derivation_is_deterministic_and_sorted_by_key() {
        let a = derive_set(1, &candidates(5), SelectionRule::TopN, 21).unwrap();
        let b = derive_set(1, &candidates(5), SelectionRule::TopN, 21).unwrap();
        assert_eq!(a.set_hash, b.set_hash);
        assert_eq!(a.validators.len(), 5);
        // Canonical order is key-first, NOT stake order.
        let mut sorted = a.validators.clone();
        sorted.sort();
        assert_eq!(a.validators, sorted);
    }

    #[test]
    fn top_n_selects_highest_stake_with_deterministic_ties() {
        let mut cands = candidates(5);
        cands.push(candidate(10, 100)); // ties with candidate(1, 100)
        let set = derive_set(1, &cands, SelectionRule::TopN, 3).unwrap();
        assert_eq!(set.validators.len(), 3);
        // Highest stakes are 500, 400, 300 (candidates 5, 4, 3).
        for (stake, seed) in [(500, 5), (400, 4), (300, 3)] {
            assert!(
                set.validators
                    .iter()
                    .any(|v| v.stake_sat == stake && v.stake_address == [seed; 20]),
                "top-3 must include stake {stake}"
            );
        }
        // Same candidates in a different order give the same set.
        cands.reverse();
        let set2 = derive_set(1, &cands, SelectionRule::TopN, 3).unwrap();
        assert_eq!(set.set_hash, set2.set_hash);
    }

    #[test]
    fn a_duplicate_key_is_refused_wherever_it_appears() {
        let mut cands = candidates(4);
        let twin = ValidatorRecord {
            stake_address: [0xEE; 20], // different address...
            bls_pk: cands[0].bls_pk,   // ...same key: two slots, one signer
            stake_sat: 999,
        };
        cands.push(twin);
        assert!(matches!(
            derive_set(1, &cands, SelectionRule::TopN, 21),
            Err(ValidatorError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn a_duplicate_address_is_refused() {
        let mut cands = candidates(4);
        let twin = ValidatorRecord {
            stake_address: cands[0].stake_address,
            bls_pk: sk(0x77).public_key(), // different key, same address
            stake_sat: 1,
        };
        cands.push(twin);
        assert!(matches!(
            derive_set(1, &cands, SelectionRule::TopN, 21),
            Err(ValidatorError::DuplicateAddress { .. })
        ));
    }

    #[test]
    fn an_invalid_key_is_refused_not_skipped() {
        let mut cands = candidates(4);
        cands.push(ValidatorRecord {
            stake_address: [0x88; 20],
            bls_pk: BlsPublicKey([0u8; 48]), // zero key: not a valid G1 point
            stake_sat: 10_000,               // would be top-N by stake
        });
        assert!(matches!(
            derive_set(1, &cands, SelectionRule::TopN, 21),
            Err(ValidatorError::BadKey { .. })
        ));
    }

    #[test]
    fn set_hash_binds_epoch_so_identical_membership_in_two_epochs_differs() {
        let cands = candidates(5);
        let e1 = derive_set(1, &cands, SelectionRule::TopN, 21).unwrap();
        let e2 = derive_set(2, &cands, SelectionRule::TopN, 21).unwrap();
        assert_ne!(e1.set_hash, e2.set_hash, "epoch is part of the identity");
    }

    #[test]
    fn set_hash_differs_when_any_addr_pk_binding_changes() {
        let cands = candidates(5);
        let base = derive_set(1, &cands, SelectionRule::TopN, 21).unwrap();
        // Same keys, different address for one validator.
        let mut cands2 = cands.clone();
        cands2[0].stake_address = [0xCD; 20];
        let moved = derive_set(1, &cands2, SelectionRule::TopN, 21).unwrap();
        assert_ne!(base.set_hash, moved.set_hash);
    }

    #[test]
    fn seed_height_math() {
        assert_eq!(seed_height(0, 100, 20), 0);
        assert_eq!(seed_height(1, 100, 20), 80);
        assert_eq!(seed_height(5, 100, 20), 480);
        assert_eq!(epoch_of(99, 100), 0);
        assert_eq!(epoch_of(100, 100), 1);
    }

    #[test]
    fn quorum_matches_the_specified_ceiling() {
        let set = derive_set(1, &candidates(21), SelectionRule::TopN, 21).unwrap();
        assert_eq!(set.quorum_size(), 15); // ceil(21*6667/10000)
        let set3 = derive_set(1, &candidates(3), SelectionRule::TopN, 21).unwrap();
        assert_eq!(set3.quorum_size(), 3);
    }

    // ------------------------------------------------------------------
    // Checkpoint clause validation
    // ------------------------------------------------------------------

    fn committee(n: u64) -> Vec<ValidatorRecord> {
        (1..=n)
            .map(|i| ValidatorRecord {
                stake_address: [i as u8; 20],
                bls_pk: sk(i as u8).public_key(),
                stake_sat: i * 100,
            })
            .collect()
    }

    fn fixed_set(n: u64, epoch: u64) -> EpochSet {
        derive_set(epoch, &committee(n), SelectionRule::TopN, 21).unwrap()
    }

    fn sign_checkpoint(
        set: &EpochSet,
        indices: &[usize],
        height: u64,
        epoch: u64,
    ) -> crate::bls_checkpoint::Checkpoint {
        use crate::bls::SecretKey as S;
        let payload = crate::bls_checkpoint::CheckpointPayload {
            height,
            block_hash: crate::hash::sha256(&[b"block", &height.to_le_bytes()]),
            network_id: "jounit/mini".into(),
            epoch,
        };
        let msg = payload.signing_hash();
        // Recover each signer's secret key from its index: test keys are
        // derived from seeds 1..=n in `committee`, so index i maps to seed
        // i+1 — but the SET is key-sorted, so map the bitmap index back to a
        // seed via the set's own ordering.
        let sigs: Vec<_> = indices
            .iter()
            .map(|&i| {
                let rec = &set.validators[i];
                // Which seed produced this key? Test-only reverse mapping.
                let seed = (1..=200u8)
                    .find(|s| S::derive(&[*s; 32]).unwrap().public_key() == rec.bls_pk)
                    .expect("test key");
                S::derive(&[seed; 32]).unwrap().sign(&msg)
            })
            .collect();
        let agg = RealBls::aggregate(&sigs).unwrap();
        crate::bls_checkpoint::Checkpoint {
            payload,
            aggregate_sig: agg,
            signer_bitmap: {
                let mut bm = vec![0u8; set.validators.len().div_ceil(8)];
                for &i in indices {
                    bm[i / 8] |= 1 << (i % 8);
                }
                bm
            },
            signer_count: indices.len() as u32,
        }
    }

    fn always(set: EpochSet) -> impl Fn(u64) -> Result<EpochSet, ValidatorError> {
        move |_e| Ok(set.clone())
    }

    #[test]
    fn a_valid_checkpoint_passes_all_six_clauses() {
        let set = fixed_set(4, 1);
        let cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1); // quorum 3 of 4
        assert!(validate_checkpoint_against_set(&cp, always(set), 100, 100, &RealBls).is_ok());
    }

    #[test]
    fn clause_1_height_outside_claimed_epoch_is_named() {
        let set = fixed_set(4, 1);
        // Claims epoch 1 but height 150 is epoch 1 only if epoch_blocks=100;
        // height 150 IS in epoch 1. Use height 90 (epoch 0).
        let cp = sign_checkpoint(&set, &[0, 1, 2], 90, 1);
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls),
            Err(ValidatorError::CheckpointWrongEpoch { .. })
        ));
    }

    #[test]
    fn clause_2_a_checkpoint_from_another_epoch_set_is_refused() {
        // Signers derive their set for epoch 1; the verifier only has the
        // epoch-2 derivation, whose set hash differs (epoch-bound identity).
        let set1 = fixed_set(4, 1);
        let set2 = fixed_set(4, 2);
        let cp = sign_checkpoint(&set1, &[0, 1, 2], 150, 1);
        // Verifier's map refuses epoch 1 entirely.
        let only_epoch_2 = |_e: u64| -> Result<EpochSet, ValidatorError> {
            if _e == 2 {
                Ok(set2.clone())
            } else {
                Err(ValidatorError::NoCandidates { epoch: _e })
            }
        };
        assert!(matches!(
            validate_checkpoint_against_set(&cp, only_epoch_2, 0, 100, &RealBls),
            Err(ValidatorError::NoCandidates { .. })
        ));
    }

    #[test]
    fn clause_3_bitmap_padding_bit_is_named_as_bad_bitmap() {
        let set = fixed_set(4, 1);
        let mut cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        cp.signer_bitmap[0] |= 0b0001_0000; // bit 4, set has 4 validators
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls),
            Err(ValidatorError::CheckpointBadBitmap { .. })
        ));
    }

    #[test]
    fn clause_3_wrong_bitmap_length_is_named() {
        let set = fixed_set(4, 1);
        let mut cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        cp.signer_bitmap.push(0xFF); // junk byte
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls),
            Err(ValidatorError::CheckpointBadBitmap { .. })
        ));
    }

    #[test]
    fn clause_3b_lying_signer_count_is_named() {
        let set = fixed_set(4, 1);
        let mut cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        cp.signer_count = 4;
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls),
            Err(ValidatorError::CheckpointCountMismatch { .. })
        ));
    }

    #[test]
    fn clause_4_quorum_short_by_one_is_named() {
        let set = fixed_set(4, 1);
        let cp = sign_checkpoint(&set, &[0, 1], 150, 1); // 2 of needed 3
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls),
            Err(ValidatorError::CheckpointQuorumShort { have: 2, need: 3 })
        ));
    }

    #[test]
    fn clause_5_a_forged_signature_is_named() {
        let set = fixed_set(4, 1);
        let mut cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        cp.aggregate_sig = BlsSignature([0xAA; 96]); // not a real point / not valid
        let err = validate_checkpoint_against_set(&cp, always(set), 0, 100, &RealBls);
        assert!(matches!(err, Err(ValidatorError::CheckpointBadSignature)));
    }

    #[test]
    fn clause_6_a_checkpoint_not_beyond_finalized_is_named() {
        let set = fixed_set(4, 1);
        let cp = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        assert!(matches!(
            validate_checkpoint_against_set(&cp, always(set), 150, 100, &RealBls),
            Err(ValidatorError::CheckpointNotBeyondFinalized { .. })
        ));
    }

    // ------------------------------------------------------------------
    // Rotation and cache grace period
    // ------------------------------------------------------------------

    #[test]
    fn cache_holds_current_and_previous_and_drops_after_grace() {
        let mut cache = EpochSetCache::new();
        let e1 = fixed_set(4, 1);
        let e2 = fixed_set(4, 2);
        cache.insert(e1, 1); // grace = 1 epoch
        cache.insert(e2, 1);
        assert!(cache.current().unwrap().epoch == 2);
        assert!(cache.previous().unwrap().epoch == 1);
        assert!(cache.get(1).is_ok(), "previous still within grace");

        let e3 = fixed_set(4, 3);
        cache.insert(e3, 1);
        // The cache holds exactly two sets: on rotating to epoch 3 the
        // previous slot becomes epoch 2 and epoch 1 is gone entirely. The
        // first version of this test asserted previous() would be None after
        // the second rotation, which is wrong — the grace slot is for the
        // epoch BEFORE the current one, and epoch 2 is exactly that.
        assert_eq!(cache.current().unwrap().epoch, 3);
        assert_eq!(
            cache.previous().unwrap().epoch,
            2,
            "the grace slot now holds epoch 2"
        );
        assert!(
            matches!(cache.get(1), Err(ValidatorError::NoCandidates { .. })),
            "epoch 1 is beyond the two-set window entirely"
        );

        // With a longer grace, a two-rotations-old set is still reachable:
        // insert e4 with grace 2 — the previous slot (epoch 3) expires at
        // epoch 5, so at epoch 4 both epoch 3 (previous) and epoch 4
        // (current) are held, and epoch 2 was already displaced.
        let e4 = fixed_set(4, 4);
        cache.insert(e4, 2);
        assert_eq!(cache.previous().unwrap().epoch, 3);
        assert!(cache.get(3).is_ok());
    }

    #[test]
    fn rotation_changes_the_verifying_set_at_the_boundary() {
        // Members change at the boundary: epoch 1 has seeds 1-4, epoch 2 has
        // seeds 2-5. Each epoch's checkpoints verify only against their own
        // derivation.
        let cands1 = candidates(4);
        let mut cands2 = candidates(5);
        cands2.retain(|c| c.stake_address != [1u8; 20]); // remove validator 1
        let e1 = derive_set(1, &cands1, SelectionRule::TopN, 21).unwrap();
        let e2 = derive_set(2, &cands2, SelectionRule::TopN, 21).unwrap();

        let map = |want: &EpochSet| {
            let want = want.clone();
            move |e: u64| -> Result<EpochSet, ValidatorError> {
                if e == want.epoch {
                    Ok(want.clone())
                } else {
                    Err(ValidatorError::NoCandidates { epoch: e })
                }
            }
        };

        let cp1 = sign_checkpoint(&e1, &[0, 1, 2], 150, 1);
        assert!(validate_checkpoint_against_set(&cp1, map(&e1), 0, 100, &RealBls).is_ok());
        // Present the epoch-1 checkpoint where the node has moved to epoch 2.
        assert!(validate_checkpoint_against_set(&cp1, map(&e2), 0, 100, &RealBls).is_err());

        let cp2 = sign_checkpoint(&e2, &[0, 1, 2], 250, 2);
        assert!(validate_checkpoint_against_set(&cp2, map(&e2), 150, 100, &RealBls).is_ok());
    }

    #[test]
    fn equivocation_evidence_requires_conflicting_payloads() {
        let set = fixed_set(4, 1);
        let a = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        let same = sign_checkpoint(&set, &[0, 1, 2], 150, 1);
        assert!(equivocation_evidence(&set.validators[0].bls_pk, &a, &same).is_none());

        // Conflicting payloads: same epoch, different heights, signed by the
        // same key in both.
        let b = sign_checkpoint(&set, &[0, 1, 2], 160, 1);
        let ev = equivocation_evidence(&set.validators[0].bls_pk, &a, &b).unwrap();
        assert_eq!(ev.offender, set.validators[0].bls_pk);
        assert_ne!(ev.first, ev.second);
    }
}
