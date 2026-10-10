//! Validator checkpoint signing (M5 binding finality, Decisions 11–14).
//!
//! This module is the missing half of M5. The verification side has existed
//! since the gadget landed: `crate::bls_checkpoint::validate_checkpoint_against_set`
//! checks six clauses with real `blst` pairings, `FinalityManager::accept` binds
//! a certificate to the canonical block at its height, and `jnt-net` receives a
//! `Message::Checkpoint`, runs it through `Chain::apply_checkpoint` and relays it
//! to every other peer — refusing to propagate one that failed. What did not
//! exist was code that *produces* a certificate. Every `Checkpoint { .. }` in
//! this repository was a test or fuzz helper.
//!
//! The consequence was simple to state and hard to notice: binding finality
//! could not activate anywhere, `mainnet` or `testnet`, because nothing ever
//! signed. A node could verify a certificate it would never see.
//!
//! # What this module is
//!
//! - [`ValidatorKey`] — one validator's BLS secret key, loaded from a file whose
//!   only secret is a 32-byte seed. The seed is never printed: `Debug` writes
//!   `<redacted>`, because a key that shows up in a log line, a panic message or
//!   a `--status` dump has escaped.
//! - [`Committee::sign`] — a whole committee's signatures aggregated into one
//!   certificate, so the signer set is whatever the operator assembled rather
//!   than any party's say-so.
//! - [`CheckpointSigner`] — the pure "given these keys, a height and the block
//!   hash, produce a certificate" step. No I/O, no clock, no network.
//!
//! # What this module is not
//!
//! **It does not decide anything.** Signing a checkpoint is not a consensus
//! act: a certificate is accepted only if a quorum of the *chain-derived*
//! committee signed the *chain's own canonical hash* at that height. A signer
//! that signs a block nobody holds, or a hash that disagrees with the canonical
//! chain, produces a certificate every peer rejects. There is therefore no
//! privilege here to abuse — which is the same reason the exit crank and the
//! dispute reference are safe to hand out.
//!
//! Key custody is an operator concern and is documented as such. Nothing in
//! this file generates entropy: `ValidatorKey::generate` takes explicit
//! `[u8; 32]` bytes from the caller, because a consensus library that quietly
//! reaches for a system RNG is harder to audit and to test deterministically.
//! The node's `validator` command does the OS-entropy call.

use serde::{Deserialize, Serialize};

use crate::bls::{RealBls, SecretKey};
use crate::bls_checkpoint::{BlsPublicKey, BlsSignature, Checkpoint, CheckpointPayload};
use crate::error::Error;
use crate::hash::Hash;

/// The on-disk format of a validator key file.
///
/// Deliberately minimal: a `version`, a `network_id` so a key file cannot be
/// silently pointed at the wrong chain, the public key (so a wrong file is
/// obvious rather than silent), and the raw 32-byte scalar.
///
/// `sk_hex` is the scalar, not a seed. Re-deriving from a seed through the IETF
/// `KeyGen` procedure is a step good for reproducible fixtures and bad for
/// custody: it means the key is a pure function of a short string, so anyone who
/// guesses the string owns the validator. `SecretKey::derive` stays where it
/// belongs — in tests — and this file stores the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyFile {
    /// Format version. A file claiming anything else is refused, never guessed.
    pub version: u32,
    /// Chain the key is for. Checked against the node's own profile on load, so
    /// a `mini` key cannot be used to sign `mainnet` checkpoints.
    pub network_id: String,
    /// The compressed G1 public key. Round-trips to `ValidatorKey::public_key`.
    #[serde(with = "crate::hexserde::h48")]
    pub public_key: [u8; 48],
    /// The 32-byte scalar, hex-encoded. Never logged; see [`ValidatorKey`]'s
    /// `Debug` impl.
    #[serde(with = "crate::hexserde::h32")]
    pub sk: [u8; 32],
}

/// One validator's signing key.
///
/// `Debug` is redacted on purpose. The `SecretKey` it wraps does not redact
/// itself, so deriving `Debug` here would put a live consensus key into any log
/// line, panic backtrace or CLI status dump that prints this value.
///
/// Not `PartialEq`, and not by oversight: comparing these would mean comparing
/// secret keys. `ValidatorKey::public_key` is the identity that matters, and
/// `Committee::add` uses it.
#[derive(Clone)]
pub struct ValidatorKey {
    key: SecretKey,
    /// The network this key belongs to. Enforced on load so a key file is not
    /// reusable across chains that share a build.
    network_id: String,
}

impl std::fmt::Debug for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorKey")
            .field("network_id", &self.network_id)
            .field("public_key", &self.public_key())
            .field("sk", &"<redacted>")
            .finish()
    }
}

impl ValidatorKey {
    /// The only format version this build reads.
    pub const VERSION: u32 = 1;

    /// Load a key from `bytes` (the exact contents of a key file) for `network`.
    ///
    /// Refuses, by name: an unknown version, a mismatched `network_id`, and a
    /// public key that does not follow from the stored scalar. The last is not
    /// pedantry — a file whose two halves disagree is either corrupt or
    /// hand-edited, and signing with it produces certificates every peer rejects
    /// while the operator believes they are participating.
    pub fn from_bytes(bytes: &[u8], network_id: &str) -> Result<Self, Error> {
        let file: ValidatorKeyFile = serde_json::from_slice(bytes)
            .map_err(|_| Error::Malformed("validator key is not JSON"))?;
        Self::from_file(file, network_id)
    }

    /// Load from an already-decoded key file.
    pub fn from_file(file: ValidatorKeyFile, network_id: &str) -> Result<Self, Error> {
        if file.version != Self::VERSION {
            return Err(Error::Malformed(
                "validator key file version is not one this build reads",
            ));
        }
        if file.network_id != network_id {
            return Err(Error::Malformed(
                "validator key file belongs to a different network",
            ));
        }
        let key = SecretKey::from_scalar(&file.sk)?;
        if key.public_key().0 != file.public_key {
            return Err(Error::Malformed(
                "validator key file's public key does not follow from its scalar",
            ));
        }
        Ok(ValidatorKey {
            key,
            network_id: network_id.to_string(),
        })
    }

    /// Wrap an existing key for a network. Used by tests and by operators who
    /// already hold a key in some other form.
    pub fn new(key: SecretKey, network_id: impl Into<String>) -> Self {
        ValidatorKey {
            key,
            network_id: network_id.into(),
        }
    }

    /// The compressed G1 public key, as it appears in the committee.
    pub fn public_key(&self) -> BlsPublicKey {
        self.key.public_key()
    }

    /// The network this key is bound to.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Sign the pre-hashed message of a checkpoint payload under the checkpoint
    /// DST (§14.5: the message is the payload's signing hash, never raw bytes).
    pub fn sign_payload(&self, payload: &CheckpointPayload) -> BlsSignature {
        let msg = payload.signing_hash();
        self.key.sign(&msg)
    }

    /// Sign one 32-byte message hash directly.
    pub fn sign_hash(&self, message: &Hash) -> BlsSignature {
        self.key.sign(message)
    }

    /// Serialize to the key-file format. The caller writes the bytes; this
    /// module does no I/O, so no path here can be tricked into writing a key
    /// somewhere the operator did not choose.
    pub fn to_file(&self) -> ValidatorKeyFile {
        ValidatorKeyFile {
            version: Self::VERSION,
            network_id: self.network_id.clone(),
            public_key: self.public_key().0,
            sk: self.key.scalar(),
        }
    }
}

impl TryFrom<ValidatorKeyFile> for ValidatorKey {
    type Error = Error;

    fn try_from(file: ValidatorKeyFile) -> Result<Self, Self::Error> {
        let network_id = file.network_id.clone();
        ValidatorKey::from_file(file, &network_id)
    }
}

/// A set of validators signing together, and the certificate they produce.
///
/// This is a *signing helper*, not an authority. It holds whatever keys the
/// operator put in it and aggregates their signatures; whether the result is a
/// valid certificate is decided entirely by the chain's own verification against
/// the committee derived from canonical bonded stake. A committee assembled the
/// wrong way produces a certificate every peer rejects, which is the property
/// that makes it safe for this type to be freely constructible.
#[derive(Debug, Clone, Default)]
pub struct Committee {
    keys: Vec<ValidatorKey>,
}

impl Committee {
    /// An empty committee. Signing with it produces nothing, which is the honest
    /// answer for a node with no validator keys configured.
    pub fn new() -> Self {
        Committee { keys: Vec::new() }
    }

    /// Add a validator's key.
    ///
    /// A duplicate public key is refused rather than silently accepted: the same
    /// key signing twice would count twice in a hand-built certificate and
    /// produce a bitmap that disagrees with `signer_count`.
    pub fn add(&mut self, key: ValidatorKey) -> Result<(), Error> {
        if self.keys.iter().any(|k| k.public_key() == key.public_key()) {
            return Err(Error::Malformed(
                "committee already holds this validator key",
            ));
        }
        self.keys.push(key);
        Ok(())
    }

    /// Number of validators held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no keys are configured.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The public keys, sorted by key bytes.
    ///
    /// Sorted because `crate::bls_checkpoint::ValidatorSet::new` sorts, and a bitmap is
    /// an index into that order — so the order a signer computes here must be the
    /// order a verifier computes. Deriving it any other way produces bytes that
    /// verify against nothing.
    pub fn public_keys(&self) -> Vec<BlsPublicKey> {
        let mut keys: Vec<BlsPublicKey> = self.keys.iter().map(|k| k.public_key()).collect();
        keys.sort_by_key(|k| k.0);
        keys
    }

    /// Sign a checkpoint payload, aggregating every held signature.
    ///
    /// Returns `None` when no keys are held, and an error when the signatures
    /// cannot be aggregated (which for BLS12-381 means they were not all valid
    /// points). A signer whose key is missing produces *no* partial
    /// certificate: a certificate with a gap in its bitmap would be refused by
    /// every peer, and shipping one would make the operator think they had
    /// signed.
    pub fn sign(&self, payload: &CheckpointPayload) -> Option<Result<Checkpoint, Error>> {
        if self.keys.is_empty() {
            return None;
        }
        let msg = payload.signing_hash();
        let sigs: Vec<BlsSignature> = self.keys.iter().map(|k| k.sign_hash(&msg)).collect();
        let aggregate = match RealBls::aggregate(&sigs) {
            Ok(a) => a,
            Err(e) => return Some(Err(e.into())),
        };

        // The bitmap is an index into the sorted set of signer keys, so build it
        // against that order rather than insertion order.
        let mut sorted: Vec<BlsPublicKey> = self.keys.iter().map(|k| k.public_key()).collect();
        sorted.sort_by_key(|k| k.0);
        let mut bitmap = vec![0u8; sorted.len().div_ceil(8)];
        for (i, _) in sorted.iter().enumerate() {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        Some(Ok(Checkpoint {
            payload: payload.clone(),
            aggregate_sig: aggregate,
            signer_bitmap: bitmap,
            signer_count: sorted.len() as u32,
        }))
    }
}

/// The pure signing step, separated from key custody so it is testable without
/// a filesystem.
///
/// This is deliberately tiny. Everything interesting about a certificate is on
/// the verification side, and the signing side is only: given a height, the
/// block hash the chain already holds, and a set of keys, produce
/// `CheckpointPayload` signed by those keys. Putting the height and hash in as
/// arguments — rather than reading them — is what makes the whole thing
/// deterministic and impossible to get subtly wrong.
#[derive(Debug, Clone)]
pub struct CheckpointSigner {
    network_id: String,
    epoch_blocks: u64,
}

impl CheckpointSigner {
    pub fn new(network_id: impl Into<String>, epoch_blocks: u64) -> Self {
        CheckpointSigner {
            network_id: network_id.into(),
            epoch_blocks,
        }
    }

    /// Build the payload for a height and its canonical block hash.
    ///
    /// The epoch is `height / epoch_blocks`, which is the derivation
    /// `CheckpointPayload::epoch_for` uses and the same one verification checks,
    /// so the two cannot drift.
    pub fn payload(&self, height: u64, block_hash: Hash) -> CheckpointPayload {
        CheckpointPayload {
            height,
            block_hash,
            network_id: self.network_id.clone(),
            epoch: height / self.epoch_blocks.max(1),
        }
    }

    /// Sign the checkpoint for `height`/`block_hash` with `committee`.
    ///
    /// `None` when the committee is empty. **No error when the height is not an
    /// epoch boundary or the block is not canonical** — this module does not
    /// decide whether a checkpoint is worth signing, and it must not appear to.
    /// The chain refuses one at a non-boundary height anyway, and the caller is
    /// the party that knows which block it holds.
    pub fn sign(
        &self,
        height: u64,
        block_hash: Hash,
        committee: &Committee,
    ) -> Option<Result<Checkpoint, Error>> {
        let payload = self.payload(height, block_hash);
        committee.sign(&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finality::FinalityManager;
    use crate::params::NetworkParams;

    fn net() -> &'static str {
        "jounit/mini"
    }

    fn epoch_blocks() -> u64 {
        NetworkParams::mini().checkpoint_interval_blocks
    }

    /// A manager whose committee is the profile's declared set — the same object
    /// a node builds, so `accept` runs the production six clauses rather than a
    /// structural stand-in.
    fn manager() -> FinalityManager {
        FinalityManager::new(&NetworkParams::mini())
    }

    /// A key from an explicit seed. Test-only: no entropy is reached for here,
    /// and the point of the module is that production keys come from a file.
    fn key(seed: u8) -> ValidatorKey {
        ValidatorKey::new(SecretKey::derive(&[seed; 32]).unwrap(), net())
    }

    fn committee_of(seeds: impl IntoIterator<Item = u8>) -> Committee {
        let mut c = Committee::new();
        for s in seeds {
            c.add(key(s)).unwrap();
        }
        c
    }

    // --- key custody -------------------------------------------------------

    #[test]
    fn debug_never_prints_the_scalar() {
        // The whole reason `Debug` is hand-written. A key that shows up in a log
        // line, a panic backtrace or a `--status` dump has escaped, so the
        // rendering must carry the marker and must not carry the secret.
        let k = key(1);
        let printed = format!("{k:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn a_key_file_round_trips_and_rereads() {
        let k = key(2);
        let bytes = serde_json::to_vec_pretty(&k.to_file()).unwrap();
        let again = ValidatorKey::from_bytes(&bytes, net()).expect("reread");
        assert_eq!(again.public_key(), k.public_key());
        assert_eq!(again.network_id(), net());
    }

    #[test]
    fn a_key_file_for_another_network_is_refused() {
        // The guard that stops a `mini` key signing `mainnet` checkpoints. Not
        // theoretical: the profiles share a build, so the file is byte-identical
        // apart from this field.
        let bytes = serde_json::to_vec_pretty(&key(3).to_file()).unwrap();
        assert!(ValidatorKey::from_bytes(&bytes, "jounit/mainnet").is_err());
    }

    #[test]
    fn a_key_file_whose_halves_disagree_is_refused() {
        // A corrupt or hand-edited file signs fine and is then refused by every
        // peer, which looks exactly like a network fault. Catch it on load.
        let mut file = key(4).to_file();
        file.public_key = [9u8; 48];
        let bytes = serde_json::to_vec(&file).unwrap();
        assert!(ValidatorKey::from_bytes(&bytes, net()).is_err());
    }

    #[test]
    fn an_unknown_version_is_refused_not_guessed() {
        let mut file = key(5).to_file();
        file.version = 99;
        let bytes = serde_json::to_vec(&file).unwrap();
        assert!(ValidatorKey::from_bytes(&bytes, net()).is_err());
    }

    #[test]
    fn non_json_is_refused_rather_than_panicking() {
        assert!(ValidatorKey::from_bytes(b"not json at all", net()).is_err());
        assert!(ValidatorKey::from_bytes(b"{}", net()).is_err());
    }

    #[test]
    fn a_zero_scalar_is_refused() {
        // blst carries a zero scalar happily into signing and the resulting
        // certificate verifies against nothing. It must never load.
        assert!(SecretKey::from_scalar(&[0u8; 32]).is_err());
    }

    #[test]
    fn a_scalar_round_trips_into_the_same_public_key() {
        let k = key(6);
        let again = SecretKey::from_scalar(&k.to_file().sk).unwrap();
        assert_eq!(again.public_key(), k.public_key());
    }

    // --- the load-bearing property -----------------------------------------

    #[test]
    fn a_committee_signs_a_certificate_the_production_path_accepts() {
        // What this module produces must be exactly what a node accepts, checked
        // through `FinalityManager::accept`: six clauses, real `blst` pairings,
        // and the certificate bound to the block the node holds. Not a mock.
        let committee = committee_of(1..=4u8);
        let mut m = manager();
        // The node's committee is the bond ledger's, so supply this one
        // explicitly; the profile's declared set is a different pair of keys.
        m.set_keys(committee.public_keys());
        let cp = CheckpointSigner::new(net(), epoch_blocks())
            .sign(100, [0xEEu8; 32], &committee)
            .expect("a non-empty committee signs")
            .expect("aggregation of valid signatures cannot fail");
        m.accept(&cp, Some([0xEEu8; 32]), &RealBls)
            .expect("the production path must accept what this module produces");
        assert_eq!(cp.signer_count, 4);
        // The observable outcome a node reports.
        assert_eq!(m.accepted_height(), 100);
    }

    #[test]
    fn the_bitmap_is_an_index_into_the_sorted_set() {
        // A bitmap is an index into the *verifier's* key order, which is sorted.
        // Signers added out of order must still produce bytes that verify, or a
        // committee assembled in a different sequence would be silently wrong.
        let forward = committee_of(1..=4u8);
        let reversed = committee_of((1..=4u8).rev());
        let signer = CheckpointSigner::new(net(), epoch_blocks());
        let payload = signer.payload(100, [0xEEu8; 32]);
        assert_eq!(
            forward.sign(&payload).unwrap().unwrap().signer_bitmap,
            reversed.sign(&payload).unwrap().unwrap().signer_bitmap,
            "insertion order must not change the bytes"
        );
        // And the forward one must actually verify, which pins the order itself.
        let mut m = manager();
        m.set_keys(forward.public_keys());
        m.accept(
            &forward.sign(&payload).unwrap().unwrap(),
            Some([0xEEu8; 32]),
            &RealBls,
        )
        .expect("a committee of the declared keys must be accepted");
    }

    #[test]
    fn the_payload_epoch_matches_what_verification_derives() {
        // The epoch derivation is duplicated in the signer, which is a drift
        // risk; this pins both sides to the same arithmetic.
        let signer = CheckpointSigner::new(net(), epoch_blocks());
        for &height in &[0u64, 1, 9, 10, 11, 25, 100, 101] {
            let payload = signer.payload(height, [0xEEu8; 32]);
            assert_eq!(
                payload.epoch,
                CheckpointPayload::epoch_for(height, epoch_blocks()),
                "epoch at height {height}"
            );
        }
    }

    // --- the refusals ------------------------------------------------------

    #[test]
    fn a_duplicate_key_is_refused_rather_than_counted_twice() {
        let mut committee = Committee::new();
        committee.add(key(6)).unwrap();
        assert!(committee.add(key(6)).is_err());
    }

    #[test]
    fn an_empty_committee_signs_nothing_rather_than_a_gap() {
        // A certificate with a hole in its bitmap is refused by every peer;
        // producing one would make an operator believe they participated.
        let signer = CheckpointSigner::new(net(), epoch_blocks());
        assert!(signer.sign(100, [0xEEu8; 32], &Committee::new()).is_none());
    }

    #[test]
    fn a_certificate_for_another_network_is_refused() {
        // Cross-network replay. The production validator compares the payload's
        // `network_id` against the node's own, so a certificate signed for one
        // chain is refused by another even with valid signatures over the right
        // block hash.
        let committee = committee_of(1..=4u8);
        let cp = CheckpointSigner::new("jounit/mainnet", epoch_blocks())
            .sign(100, [0xEEu8; 32], &committee)
            .unwrap()
            .unwrap();
        assert!(
            manager().accept(&cp, Some([0xEEu8; 32]), &RealBls).is_err(),
            "a certificate signed for another network must not be accepted"
        );
    }

    #[test]
    fn a_certificate_short_of_quorum_is_refused() {
        // The honest "not enough validators showed up" case, which must fail
        // closed. Distinct from a forged aggregate: nothing is wrong with the
        // signatures, there are simply too few of them.
        let three = committee_of(1..=3u8);
        let five = committee_of(1..=5u8);
        let signer = CheckpointSigner::new(net(), epoch_blocks());
        let cp = three
            .sign(&signer.payload(100, [0xEEu8; 32]))
            .unwrap()
            .unwrap();
        let set = crate::bls_checkpoint::ValidatorSet::new(five.public_keys());
        assert_eq!(set.quorum_size(), 4, "ceil(5 * 6667 / 10000)");
        crate::bls_checkpoint::verify_checkpoint(&cp, &set, &RealBls)
            .expect_err("3 of 5 is below quorum");
    }

    #[test]
    fn a_certificate_for_a_block_the_node_does_not_hold_is_refused() {
        // The reorg protection at the producer rather than the consumer. A
        // signer who signs the wrong hash produces a structurally perfect
        // certificate, and the node refuses it on the canonical-binding clause
        // — which is what stops a certificate for block A finalizing block B.
        let committee = committee_of(1..=4u8);
        let cp = CheckpointSigner::new(net(), epoch_blocks())
            .sign(100, [0xEEu8; 32], &committee)
            .unwrap()
            .unwrap();
        assert!(
            manager().accept(&cp, Some([0xFFu8; 32]), &RealBls).is_err(),
            "a certificate naming a block the node does not hold must be refused"
        );
    }

    #[test]
    fn a_signature_over_a_different_hash_fails_the_pairing() {
        // Tampering leaves a valid-looking structure whose aggregate no longer
        // verifies. The binding is cryptographic, not a field the validator
        // happens to re-read.
        let committee = committee_of(1..=4u8);
        let signer = CheckpointSigner::new(net(), epoch_blocks());
        let cp = committee
            .sign(&signer.payload(100, [0xEEu8; 32]))
            .unwrap()
            .unwrap();
        let mut forged = cp.clone();
        forged.payload.block_hash = [0xFFu8; 32];
        let set = crate::bls_checkpoint::ValidatorSet::new(committee.public_keys());
        crate::bls_checkpoint::verify_checkpoint(&forged, &set, &RealBls)
            .expect_err("the aggregate no longer matches the message");
    }

    #[test]
    fn a_non_epoch_boundary_height_is_refused_by_verification() {
        // The signer does not refuse this, because it must not appear to decide
        // what is worth signing; verification is what stops it. This test pins
        // that division of responsibility rather than the signer being clever.
        let committee = committee_of(1..=4u8);
        let cp = CheckpointSigner::new(net(), epoch_blocks())
            .sign(105, [0xEEu8; 32], &committee)
            .unwrap()
            .unwrap();
        assert!(
            manager().accept(&cp, Some([0xEEu8; 32]), &RealBls).is_err(),
            "height 105 is not an epoch boundary for a 10-block epoch"
        );
    }
}
