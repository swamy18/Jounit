//! Validator-set machinery per SPEC.md §14.6 (Decision 11).
//!
//! **Consensus-relevant through M5, per profile.** `Chain::apply_checkpoint`
//! validates a certificate through this module, and once a profile's
//! `finality_activation_height` is reached, `Chain::adopt()` refuses any branch
//! forking at or below the binding-finalized height
//! (`Error::ReorgWouldCrossFinality`). Binding finality activates on
//! `testnet` at height 20 and on `mainnet` at height 100; `mini` remains
//! observation-only with activation height `0`.
//!
//! The committee is a **bootstrap** set until stake exists: Decision 27 gives
//! mainnet 21 deterministic public keys, and Decision 20's bond ledger replaces
//! them with the TopN staked committee as soon as a bond exists. mini/testnet
//! carry four declared test keys. The remaining §14.6 questions are economic
//! (rewards, rotation, equivocation slashing) and are tracked as P2.
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
    /// Lattice key this validator registered for checkpoint sidecars, if any.
    /// Never the committee identity and never part of the record order (that
    /// stays `(bls_pk, stake_address)`, so registering a key cannot reshuffle
    /// bitmap bit assignments). `None` for genesis committees and for bonds
    /// written before lattice registration existed.
    pub mldsa_pk: Option<[u8; 1952]>,
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
    /// A candidate list contained one lattice key under two BLS identities.
    /// One holder signing for two stakes would make the sidecar ambiguous
    /// about whose stake each lattice signature backs, so it is refused like
    /// a duplicate BLS key.
    DuplicateMldsaKey,
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
    /// Clause 7: the lattice sidecar is missing, malformed, or fails. The
    /// detail names which signer and which rule, like the bitmap clause does.
    CheckpointBadSidecar {
        detail: String,
    },
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
            ValidatorError::DuplicateMldsaKey => {
                write!(f, "duplicate lattice key in candidate list")
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
            ValidatorError::CheckpointBadSidecar { detail } => {
                write!(f, "bad lattice sidecar: {detail}")
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
            mldsa_pk: None,
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
    let mut seen_mldsa = std::collections::HashSet::new();
    for c in candidates {
        if seen_keys.contains(&c.bls_pk) {
            return Err(ValidatorError::DuplicateKey { key: c.bls_pk });
        }
        if seen_addrs.contains(&c.stake_address) {
            return Err(ValidatorError::DuplicateAddress {
                address: c.stake_address,
            });
        }
        if let Some(pk) = c.mldsa_pk {
            if !seen_mldsa.insert(pk) {
                return Err(ValidatorError::DuplicateMldsaKey);
            }
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
        // A registered lattice key extends its validator's preimage; a
        // validator without one contributes nothing further, so a set in
        // which nobody registered hashes exactly as before.
        if let Some(pk) = &v.mldsa_pk {
            buf.push(0x01);
            buf.extend_from_slice(pk);
        }
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

/// True when `height` is a seed height for some epoch: `height == 0`, or
/// `height + lookback` is a positive multiple of `epoch_blocks` (i.e. there
/// is an epoch `e >= 1` with `seed_height(e) == height`). Checked arithmetic:
/// `height + lookback` overflowing `u64` is not a seed height.
pub fn is_seed_height(height: u64, epoch_blocks: u64, lookback: u64) -> bool {
    let epoch_blocks = epoch_blocks.max(1);
    if height == 0 {
        return true;
    }
    match height.checked_add(lookback) {
        Some(s) => s % epoch_blocks == 0,
        None => false,
    }
}

/// The set cache a node keeps: current epoch and the previous one (grace).
///
/// §14.6: a node tracks `set(e-1)` for one full epoch after handover, solely
/// to validate late-arriving checkpoints from that epoch; after the grace
/// period the old set is dropped.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EpochSetCache {
    current: Option<EpochSet>,
    previous: Option<EpochSet>,
    /// The epoch after `previous.epoch` at which `previous` expires. An
    /// expiry *height* would re-derive epoch geometry inside the cache; the
    /// epoch number is the unit the grace period is defined in.
    previous_expires_at_epoch: Option<u64>,
    /// The epoch of the current set, used by `get` to decide whether a
    /// previous-set read has passed its grace expiry without waiting for a
    /// future `insert()` to eager-drop it.
    current_epoch: Option<u64>,
    /// The epoch of the most recent previous set that aged out. Kept so `get`
    /// reports `SetExpired` (we held it, it expired) rather than
    /// `NoCandidates` (we never had it) for a displaced-but-expired set.
    expired_previous_epoch: Option<u64>,
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
                self.current_epoch = Some(incoming_epoch);
            }
            Some(cur) if incoming_epoch > cur.epoch => {
                // The old previous is being displaced by the old current. If the
                // old previous has already reached its expiry, remember it so
                // `get` reports `SetExpired` rather than `NoCandidates`.
                if let Some(prev) = &self.previous {
                    let prev_expires = self.previous_expires_at_epoch.unwrap_or(incoming_epoch);
                    if incoming_epoch >= prev_expires {
                        self.expired_previous_epoch = Some(prev.epoch);
                    }
                }
                self.previous = Some(cur.clone());
                self.previous_expires_at_epoch = Some(incoming_epoch + grace_epochs);
                self.current = Some(set);
                self.current_epoch = Some(incoming_epoch);
            }
            _ => {
                self.current = Some(set);
                self.current_epoch = Some(incoming_epoch);
            }
        }
    }

    /// The set for `epoch`, if cached: current, or previous within grace.
    ///
    /// Never returns an expired set: a previous-set read is refused once the
    /// recorded grace expiry has passed, without waiting for a future
    /// `insert()` to eager-drop it. Distinguishes `SetExpired` (we held the
    /// set and it aged out) from `NoCandidates` (we never had it).
    pub fn get(&self, epoch: u64) -> std::result::Result<&EpochSet, ValidatorError> {
        if let Some(cur) = &self.current {
            if cur.epoch == epoch {
                return Ok(cur);
            }
        }
        if let Some(prev) = &self.previous {
            if prev.epoch == epoch {
                let expired = self
                    .previous_expires_at_epoch
                    .is_some_and(|expires| self.current_epoch.is_some_and(|c| c >= expires));
                if expired {
                    return Err(ValidatorError::SetExpired { epoch });
                }
                return Ok(prev);
            }
        }
        if self.expired_previous_epoch == Some(epoch) {
            return Err(ValidatorError::SetExpired { epoch });
        }
        Err(ValidatorError::NoCandidates { epoch })
    }

    /// Current epoch's set, if any.
    pub fn current(&self) -> Option<&EpochSet> {
        self.current.as_ref()
    }

    /// Previous epoch's set, if any (for inspection only; callers should use
    /// `get` so expiry is enforced).
    pub fn previous(&self) -> Option<&EpochSet> {
        self.previous.as_ref()
    }

    /// Drop all cached epoch sets, restoring the genesis-fallback behaviour
    /// (used by `FinalityManager::refresh_committee` when no bonds are live).
    pub fn clear(&mut self) {
        self.current = None;
        self.previous = None;
        self.previous_expires_at_epoch = None;
        self.current_epoch = None;
        self.expired_previous_epoch = None;
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

    // Clause 7: the lattice sidecar. For every bitmap signer holding a
    // registered lattice key, exactly one sidecar entry with that bitmap
    // index must verify over the same signing hash the aggregate covers.
    // Signers without a registered key pass on BLS alone — that is the
    // transition, not a hole: a key is registered by a bond transaction no
    // caller can forge, and unregistering means unbonding.
    //
    // What is refused, and why each refusal matters:
    //
    // - an entry for a non-signer or an out-of-range index: the index names
    //   the member, the set names the key, the caller names neither — so an
    //   entry that points nowhere is not a signature;
    // - a duplicate index: one member, one lattice voice, like one BLS voice
    //   in the aggregate;
    // - an entry for a member with no registered key: there is nothing it
    //   could honestly verify against, so accepting it would be trusting the
    //   caller-supplied bytes by another name;
    // - a missing entry for a keyed signer: accepting it would let a quorum
    //   quietly drop its quantum half, which is the downgrade this clause
    //   exists to prevent — including a sidecar stripped off in transit,
    //   which lands here as "missing", never as "valid without".
    verify_pq_sidecar(checkpoint, &set, &message)?;

    // Clause 6: monotonic finality.
    if height <= finalized_height {
        return Err(ValidatorError::CheckpointNotBeyondFinalized {
            height,
            finalized: finalized_height,
        });
    }

    Ok(())
}

/// Clause 7 of checkpoint validation: the lattice sidecar. See the call site
/// for what each refusal means.
pub fn verify_pq_sidecar(
    checkpoint: &crate::bls_checkpoint::Checkpoint,
    set: &EpochSet,
    message: &crate::hash::Hash,
) -> Result<(), ValidatorError> {
    let n = set.validators.len();
    let is_signer =
        |idx: usize| idx < n && (checkpoint.signer_bitmap[idx / 8] >> (idx % 8)) & 1 == 1;
    let mut seen = vec![false; n];
    check_sidecar(
        &checkpoint.pq_sidecar,
        n,
        is_signer,
        |idx| set.validators[idx].mldsa_pk,
        message,
        &mut seen,
    )
    .map_err(|r| ValidatorError::CheckpointBadSidecar { detail: r.detail })
}

/// A sidecar refusal, described rather than enumerated: the detail names the
/// signer index and the rule, the caller decides the error type. One
/// implementation serves checkpoint clause 7, settle application and VWC
/// validation, so the three cannot disagree on what "valid" means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarRefusal {
    pub detail: String,
}

impl std::fmt::Display for SidecarRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad lattice sidecar: {}", self.detail)
    }
}

impl std::error::Error for SidecarRefusal {}

/// Check lattice sidecar entries against a membership: `is_signer` answers
/// the bitmap, `key_of` answers the registry, and every bitmap signer holding
/// a registered key must have exactly one entry. Every rule from clause 7, in
/// one place; `seen` is filled for the caller to inspect.
#[allow(clippy::too_many_arguments)]
pub fn check_sidecar(
    entries: &[crate::bls_checkpoint::PqSidecarEntry],
    member_count: usize,
    is_signer: impl Fn(usize) -> bool,
    key_of: impl Fn(usize) -> Option<[u8; 1952]>,
    message: &crate::hash::Hash,
    seen: &mut [bool],
) -> Result<(), SidecarRefusal> {
    let refuse = |detail: String| SidecarRefusal { detail };
    for e in entries {
        let idx = e.signer_index as usize;
        if idx >= member_count || !is_signer(idx) {
            return Err(refuse(format!("sidecar entry for non-signer {idx}")));
        }
        if seen[idx] {
            return Err(refuse(format!("duplicate sidecar entry for signer {idx}")));
        }
        seen[idx] = true;
        let key =
            key_of(idx).ok_or_else(|| refuse(format!("sidecar entry for keyless member {idx}")))?;
        crate::sig::verify_ml_dsa(&key, &e.signature, message)
            .map_err(|_| refuse(format!("lattice signature failed for signer {idx}")))?;
    }
    for (i, covered) in seen.iter().enumerate().take(member_count) {
        if is_signer(i) && key_of(i).is_some() && !covered {
            return Err(refuse(format!("keyed signer {i} has no sidecar entry")));
        }
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
            mldsa_pk: None,
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
            mldsa_pk: None,
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
            mldsa_pk: None,
        };
        cands.push(twin);
        assert!(matches!(
            derive_set(1, &cands, SelectionRule::TopN, 21),
            Err(ValidatorError::DuplicateAddress { .. })
        ));
    }

    #[test]
    fn a_duplicate_mldsa_key_is_refused() {
        let mut cands = candidates(4);
        let shared_pk = [0x42u8; 1952];
        cands.push(ValidatorRecord {
            stake_address: [0x88; 20],
            bls_pk: sk(0x88).public_key(),
            stake_sat: 1,
            mldsa_pk: Some(shared_pk),
        });
        cands.push(ValidatorRecord {
            stake_address: [0x89; 20],
            bls_pk: sk(0x89).public_key(),
            stake_sat: 1,
            mldsa_pk: Some(shared_pk),
        });
        assert!(matches!(
            derive_set(1, &cands, SelectionRule::TopN, 21),
            Err(ValidatorError::DuplicateMldsaKey)
        ));
    }

    #[test]
    fn an_invalid_key_is_refused_not_skipped() {
        let mut cands = candidates(4);
        cands.push(ValidatorRecord {
            stake_address: [0x88; 20],
            bls_pk: BlsPublicKey([0u8; 48]), // zero key: not a valid G1 point
            stake_sat: 10_000,               // would be top-N by stake
            mldsa_pk: None,
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
    fn seed_height_membership_matches_the_formula() {
        // mainnet shape: seeds are 0, 80, 180, ...
        for h in [0u64, 80, 180, 280] {
            assert!(is_seed_height(h, 100, 20), "height {h} is a seed height");
        }
        for h in [1u64, 79, 81, 100, 179] {
            assert!(
                !is_seed_height(h, 100, 20),
                "height {h} is not a seed height"
            );
        }
        // mini shape: seeds are 0, 10, 20, 30, ...
        for h in [0u64, 10, 20, 30] {
            assert!(is_seed_height(h, 10, 20), "height {h} is a seed height");
        }
        for h in [1u64, 9, 11, 21] {
            assert!(
                !is_seed_height(h, 10, 20),
                "height {h} is not a seed height"
            );
        }
        // Checked arithmetic: an overflowing height + lookback is not a seed.
        assert!(!is_seed_height(u64::MAX, 100, 20));
        assert!(!is_seed_height(u64::MAX, 1, 1));
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
                mldsa_pk: None,
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
            block_hash: crate::hash::sha512(&[b"block", &height.to_le_bytes()]),
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
            pq_sidecar: Vec::new(),
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
        // The cache holds exactly two sets: on rotating to epoch 3 the previous
        // slot becomes epoch 2; epoch 1 has reached its expiry (epoch 3) and is
        // reported as `SetExpired` rather than silently dropped.
        // The grace slot is for the epoch before the current one, and epoch 2
        // is exactly that.
        assert_eq!(cache.current().unwrap().epoch, 3);
        assert_eq!(
            cache.previous().unwrap().epoch,
            2,
            "the grace slot now holds epoch 2"
        );
        // Epoch 1 was held as the previous set and reached its expiry (epoch 3)
        // exactly as we rotated to epoch 3: it aged out, so it is `SetExpired`,
        // not `NoCandidates` (we did hold it once).
        assert!(
            matches!(cache.get(1), Err(ValidatorError::SetExpired { .. })),
            "epoch 1 aged out at epoch 3"
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

    // ------------------------------------------------------------------
    // EpochSetCache expiry semantics (P1-5)
    // ------------------------------------------------------------------

    #[test]
    fn cache_get_never_returns_an_expired_set() {
        let mut cache = EpochSetCache::new();
        let e1 = fixed_set(4, 1);
        let e2 = fixed_set(4, 2);
        // Grace of 1: epoch 1 expires once we reach epoch 2 + 1 = 3.
        cache.insert(e1, 1);
        cache.insert(e2, 1); // current=2, previous=1, expires at epoch 3

        // Previous epoch (1) is still within grace at current epoch 2.
        assert!(cache.get(1).is_ok());
        // Current epoch is available.
        assert!(cache.get(2).is_ok());

        // Advance to epoch 3: epoch 1 is now past its grace expiry.
        let e3 = fixed_set(4, 3);
        cache.insert(e3, 1); // current=3, previous=2 (1 dropped eagerly)
        assert!(matches!(
            cache.get(1),
            Err(ValidatorError::SetExpired { .. })
        ));
        // Previous (2) still within grace at epoch 3 (expires at 4).
        assert!(cache.get(2).is_ok());
        // Current available.
        assert!(cache.get(3).is_ok());

        // Advance past expiry of epoch 2 (grace 1: expires at 4).
        let e4 = fixed_set(4, 4);
        cache.insert(e4, 1); // current=4, previous=3 (2 dropped eagerly)
        assert!(matches!(
            cache.get(2),
            Err(ValidatorError::SetExpired { .. })
        ));
        assert!(cache.get(3).is_ok());
    }

    #[test]
    fn cache_get_distinguishes_expired_from_never_had() {
        let mut cache = EpochSetCache::new();
        // Never had any set: NoCandidates.
        assert!(matches!(
            cache.get(5),
            Err(ValidatorError::NoCandidates { .. })
        ));

        // Install and age out a set: SetExpired.
        let e1 = fixed_set(4, 1);
        let e2 = fixed_set(4, 2);
        cache.insert(e1, 1);
        cache.insert(e2, 0); // grace 0: epoch 1 expires immediately at epoch 2
        assert!(matches!(
            cache.get(1),
            Err(ValidatorError::SetExpired { .. })
        ));
    }

    #[test]
    fn cache_get_missing_epoch_is_nocandidates() {
        let mut cache = EpochSetCache::new();
        let e5 = fixed_set(4, 5);
        cache.insert(e5, 1);
        // Epochs other than current are never held (no previous): NoCandidates.
        assert!(matches!(
            cache.get(3),
            Err(ValidatorError::NoCandidates { .. })
        ));
        assert!(matches!(
            cache.get(4),
            Err(ValidatorError::NoCandidates { .. })
        ));
        assert!(matches!(
            cache.get(6),
            Err(ValidatorError::NoCandidates { .. })
        ));
        assert!(cache.get(5).is_ok());
    }

    #[test]
    fn cache_previous_survives_one_epoch_grace_then_expires() {
        let mut cache = EpochSetCache::new();
        let e1 = fixed_set(4, 1);
        let e2 = fixed_set(4, 2);
        let e3 = fixed_set(4, 3);
        cache.insert(e1, 1);
        cache.insert(e2, 1); // current=2, previous=1, expires at 3
        assert!(cache.get(1).is_ok());
        cache.insert(e3, 1); // current=3, previous=2 (1 expired)
        assert!(matches!(
            cache.get(1),
            Err(ValidatorError::SetExpired { .. })
        ));
        assert!(cache.get(2).is_ok());
    }
}
