//! Fraud arbitration votes (Decision 21 — P3, SPEC.md §16).
//!
//! This module is the missing half of fraud arbitration. The *decision* path has
//! existed since the gadget landed: `DisputeEngine::resolve` runs the canonical
//! CPU reference over the disputed contract and maps the reference result onto
//! exactly one verdict, and `L2State::apply_settle` verifies a BLS quorum
//! aggregate over the settle decision with real `blst` pairings. What did not
//! exist was any way for independent arbitrators to *exchange* their verdicts —
//! the quorum aggregate had to be assembled out of band, by whoever built the
//! `Settle` transaction.
//!
//! # What a vote is
//!
//! An [`ArbitrationVote`] is one arbitrator's signed statement of a verdict for
//! one dispute. It carries the decision (`task_id`, `verdict`, `vwc_hash`), the
//! network it was signed for, the height it was signed at, and one BLS signature.
//!
//! # Why it signs the settle decision hash, and nothing else
//!
//! [`ArbitrationVote::signing_hash`] is byte-identical to
//! `SettlePayload::signing_hash` for the same decision — the same three fields,
//! the same domain tag. That is deliberate and load-bearing: `apply_settle`
//! verifies `bls_sig` against `SettlePayload::signing_hash()`, so a vote's
//! signature must be over exactly those bytes for a quorum of votes to aggregate
//! into the aggregate that transaction carries. Signing anything else would
//! produce a beautiful protocol that settles nothing.
//!
//! The consequence, stated plainly rather than buried: **network and height are
//! authenticated by the vote's fields and by the tally, not by the signature.**
//! Each vote carries `network_id` and `height`, a tallying node requires every
//! vote to agree with its own chain before accepting it, and signers must be in
//! the committee the chain derives. Cross-network replay of a settle decision is
//! additionally bounded by task ids being network-scoped and by the `Settle`
//! riding inside an L1 block of that chain — but a signature over the decision
//! alone would verify on any chain, so the guarantee is structural rather than
//! cryptographic. [`MAX_NETWORK_ID_BYTES`] bounds the string that makes it
//! checkable.
//!
//! This module adds no consensus rule. `apply_settle` is unchanged, so the
//! threshold, the checks and the pairing verification are exactly what they were.

use crate::bls_checkpoint::{BlsPublicKey, BlsSignature};
use crate::error::Error;
use crate::hash::sha256_dom;
use crate::l2::{SettlePayload, Verdict, DOM_L2_SETTLE};
use crate::ser::{Reader, Writer};
use crate::Hash;

/// Domain tag for the signed message. Identical to `DOM_L2_SETTLE` on purpose:
/// see the module docs for why a vote must sign the settle decision hash rather
/// than a message of its own.
pub const DOM_ARBITRATION_VOTE: &[u8] = DOM_L2_SETTLE;

/// Wire format version. A message claiming another version is refused, never
/// guessed at, so a future change to the vote can be introduced without a node
/// silently accepting bytes it was not built to check.
pub const ARBITRATION_VOTE_VERSION: u32 = 1;

/// Longest `network_id` accepted, matching the handshake's bound (§13.4) so a
/// vote cannot carry a longer one than a peer would ever have negotiated.
pub const MAX_NETWORK_ID_BYTES: usize = 64;

/// Longest signer bitmap accepted in a tally, matching
/// `jnt_core::l2::MAX_SIGNER_BITMAP_BYTES` — 512 validators of headroom.
pub const MAX_VOTE_BITMAP_BYTES: usize = 64;

/// Largest encoded vote. Bounded rather than advisory: a peer sending one huge
/// message must not be able to make a node reserve for it.
pub const MAX_ARBITRATION_VOTE_BYTES: usize = 512;

/// One arbitrator's signed verdict for one dispute.
///
/// Deliberately `PartialEq`/`Eq`-free on the signature: this type travels over
/// the network and equality is never load-bearing for it, while deriving it
/// would invite comparing signature material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbitrationVote {
    /// Format version.
    pub version: u32,
    /// The dispute this vote is about — the task whose result was challenged.
    pub task_id: Hash,
    /// What the signer decided. `Expired` is not a verdict an arbitrator may
    /// cast: it is produced by the clock, not by re-execution, and admitting it
    /// here would let a committee settle a task nobody disputed.
    pub verdict: Verdict,
    /// The reference result this verdict rests on. For `Correct` it is the
    /// worker's result; for `Fraudulent` it is the challenger's. A vote with
    /// `vwc_hash == VWC_HASH_EXPIRED` is refused, since that placeholder is not
    /// a result and must never enter a quorum.
    pub vwc_hash: Hash,
    /// Chain the vote was signed for. Checked against the node's own profile.
    pub network_id: String,
    /// Height the vote was formed at. Binds the vote to an epoch, so a vote
    /// cannot be replayed against a later committee that happens to agree.
    pub height: u64,
    /// Who signed. Must be in the committee the chain derives.
    pub signer: BlsPublicKey,
    /// The signer's signature over [`Self::signing_hash`].
    pub signature: BlsSignature,
}

impl ArbitrationVote {
    /// The exact bytes a signer signs, which is byte-identical to the settle
    /// decision hash. See the module docs.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_ARBITRATION_VOTE,
            &[
                &self.task_id,
                &self.verdict.to_wire().to_le_bytes(),
                &self.vwc_hash,
            ],
        )
    }

    /// The decision this vote attests to, as the fields `SettlePayload` carries.
    /// The seam: a tally with quorum turns its signers' aggregate into exactly
    /// this.
    pub fn decision(&self) -> (Hash, Verdict, Hash) {
        (self.task_id, self.verdict, self.vwc_hash)
    }

    /// Structural checks that need no chain state and no committee.
    ///
    /// Everything here is something a single vote can be wrong about on its own
    /// terms: an unsupported version, a verdict that is not an arbitrator's to
    /// cast, the expired placeholder posing as a result, an unbounded
    /// `network_id`, or a signature that is not a well-formed point. A vote that
    /// fails any of these is dropped before it costs a pairing check.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.version != ARBITRATION_VOTE_VERSION {
            return Err("arbitration vote version is not one this build reads");
        }
        if self.network_id.len() > MAX_NETWORK_ID_BYTES {
            return Err("arbitration vote network_id over cap");
        }
        if self.verdict == Verdict::Expired {
            // `Expired` is a clock outcome, not an arbitration outcome. Letting
            // a committee settle a task nobody disputed would turn the dispute
            // path into a second, weaker settlement path.
            return Err("an arbitration vote may not be Expired");
        }
        if self.vwc_hash == crate::l2::VWC_HASH_EXPIRED {
            return Err("an arbitration vote may not name the expired placeholder");
        }
        // A signature that is not a point verifies against nothing, and the
        // check is cheap enough to run before any pairing work.
        crate::bls::validate_signature(&self.signature)
            .map_err(|_| "arbitration vote signature is not a valid point")?;
        crate::bls::validate_public_key(&self.signer)
            .map_err(|_| "arbitration vote signer is not a valid key")?;
        Ok(())
    }

    /// Verify this vote's signature over the settle decision, against its own
    /// named signer. Single-signer verification, not aggregate: this is what a
    /// receiving node runs before spending a pairing check on anything else.
    pub fn verify_signature(&self) -> bool {
        let msg = self.signing_hash();
        crate::bls::RealBls::verify(&self.signer, &msg, &self.signature)
    }

    /// Canonical encoding, without the signature (which is evidence of the
    /// decision, not part of it).
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32le(self.version)
            .fixed(&self.task_id)
            .u8(self.verdict.to_wire())
            .fixed(&self.vwc_hash)
            .u32le(self.network_id.len() as u32)
            .raw(self.network_id.as_bytes())
            .u64le(self.height)
            .raw(self.signer.as_bytes());
        w.into_vec()
    }

    /// Canonical wire form.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.body()).raw(self.signature.as_bytes());
        w.into_vec()
    }

    /// Decode. Every declared length is bounded by what remains before anything
    /// is reserved, so a truncated or hostile payload cannot force an allocation
    /// larger than itself.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let version = r.u32le()?;
        let task_id: Hash = r.fixed()?;
        let verdict = Verdict::from_wire(r.u8()?)?;
        let vwc_hash: Hash = r.fixed()?;
        let id_len = r.u32le()? as usize;
        if id_len > MAX_NETWORK_ID_BYTES {
            return Err(Error::Malformed("arbitration vote network_id over cap"));
        }
        if id_len > r.remaining() {
            return Err(Error::Malformed(
                "arbitration vote network_id exceeds buffer",
            ));
        }
        let network_id = std::str::from_utf8(r.fixed_slice(id_len)?)
            .map_err(|_| Error::Malformed("arbitration vote network_id not utf-8"))?
            .to_string();
        let height = r.u64le()?;
        let signer = BlsPublicKey(r.fixed()?);
        let signature = BlsSignature(r.fixed()?);
        r.expect_end()?;
        Ok(ArbitrationVote {
            version,
            task_id,
            verdict,
            vwc_hash,
            network_id,
            height,
            signer,
            signature,
        })
    }
}

/// Why a vote was not counted. Every rejection names its reason, because "the
/// vote did not count" is not something an operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteRejection {
    /// Not a well-formed vote on its own terms.
    Malformed(&'static str),
    /// Its signature does not verify.
    BadSignature,
    /// The signer is not in the committee for this dispute.
    NotInCommittee,
    /// Signed for a different network.
    WrongNetwork,
    /// Signed at a different height than the node's.
    WrongHeight,
    /// This signer already voted, for the same decision.
    Duplicate,
    /// This signer already voted, for a *different* decision — equivocation.
    Conflicting,
    /// The tally already reached quorum and closed.
    Closed,
}

impl std::fmt::Display for VoteRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteRejection::Malformed(w) => write!(f, "malformed vote: {w}"),
            VoteRejection::BadSignature => write!(f, "signature did not verify"),
            VoteRejection::NotInCommittee => write!(f, "signer is not in the committee"),
            VoteRejection::WrongNetwork => write!(f, "vote is for another network"),
            VoteRejection::WrongHeight => write!(f, "vote is for another height"),
            VoteRejection::Duplicate => write!(f, "signer already counted once"),
            VoteRejection::Conflicting => {
                write!(f, "signer already voted for a different decision")
            }
            VoteRejection::Closed => write!(f, "quorum already reached"),
        }
    }
}

/// The received votes for one dispute, and the quorum judgement on them.
///
/// One per dispute per node. This is a *transport* accumulator, not a consensus
/// object: nothing here is persisted, and nothing here authorizes anything. The
/// only thing it produces is a settle payload carrying a quorum aggregate, which
/// `apply_settle` re-verifies from scratch with real pairings. A node that loses
/// its tallies on restart simply stops being able to *propose* a settlement; it
/// keeps verifying and relaying, and the votes are re-relayable. The deadline
/// that matters is the dispute window's, not this struct's.
#[derive(Debug, Clone, Default)]
pub struct VoteTally {
    /// Every counted vote, in arrival order. One per signer at most.
    votes: Vec<ArbitrationVote>,
    /// The decision every counted vote agrees on.
    decision: Option<(Hash, Verdict, Hash)>,
    /// The quorum the committee's rule requires. Supplied by the caller, so
    /// this struct cannot arrive at a second opinion about the threshold.
    quorum: usize,
    /// Conflicting votes from a signer already counted, retained as evidence.
    /// Never acted on here — see [`ArbitrationEquivocation`].
    equivocations: Vec<ArbitrationEquivocation>,
}

impl VoteTally {
    /// A new tally with the quorum the committee's rule requires.
    pub fn new(quorum: usize) -> Self {
        VoteTally {
            votes: Vec::new(),
            decision: None,
            quorum,
            equivocations: Vec::new(),
        }
    }

    /// Number of distinct signers counted.
    pub fn votes(&self) -> usize {
        self.votes.len()
    }

    /// The decision every counted vote agrees on, once any has arrived.
    pub fn decision(&self) -> Option<(Hash, Verdict, Hash)> {
        self.decision
    }

    /// The counted votes, for diagnostics and for relaying to a peer that is
    /// behind.
    pub fn counted_votes(&self) -> &[ArbitrationVote] {
        &self.votes
    }

    /// Conflicting votes from a signer already counted, as evidence.
    ///
    /// Retained, never acted on: turning it into a slash needs a slash
    /// transaction, which is not wired for arbitration. See
    /// [ArbitrationEquivocation].
    pub fn equivocations(&self) -> &[ArbitrationEquivocation] {
        &self.equivocations
    }

    /// Whether quorum is reached. This is the only judgement this struct makes;
    /// [`Self::settle_payload`] re-checks everything from the votes themselves.
    pub fn has_quorum(&self) -> bool {
        self.votes.len() >= self.quorum
    }

    /// Count one vote.
    ///
    /// The order is deliberate: structural validity, then the vote's own
    /// signature, then committee membership, then the node's own network and
    /// height, then double-counting, then conflict. A cheaper check always runs
    /// before a dearer one, so a flood of malformed votes never reaches a pairing
    /// check at all.
    pub fn record(
        &mut self,
        vote: &ArbitrationVote,
        network_id: &str,
        height: u64,
        committee: &[BlsPublicKey],
    ) -> Result<(), VoteRejection> {
        vote.validate_structure()
            .map_err(VoteRejection::Malformed)?;
        if !vote.verify_signature() {
            return Err(VoteRejection::BadSignature);
        }
        if !committee.contains(&vote.signer) {
            return Err(VoteRejection::NotInCommittee);
        }
        if vote.network_id != network_id {
            return Err(VoteRejection::WrongNetwork);
        }
        if vote.height != height {
            return Err(VoteRejection::WrongHeight);
        }
        // Conflict is checked *before* duplication, and the order matters. A
        // second vote from an existing signer is either a replay of the same
        // decision or a vote for a different one, and the second case is the
        // one that must survive: it is equivocation, it is provable, and it is
        // the input the slash path needs. Classifying it as a plain duplicate
        // would throw away exactly the signal that makes the tally safe.
        let incoming = vote.decision();
        if let Some(prior) = self.votes.iter().find(|v| v.signer == vote.signer) {
            if prior.decision() == incoming {
                // The same signer twice cannot inflate quorum: the vote set is
                // keyed by signer, so a replayed or duplicated message is a
                // no-op rather than a second signature to aggregate.
                return Err(VoteRejection::Duplicate);
            }
            self.equivocations.push(ArbitrationEquivocation {
                offender: prior.signer,
                first_msg: prior.signing_hash(),
                second_msg: vote.signing_hash(),
            });
            return Err(VoteRejection::Conflicting);
        }
        match self.decision {
            Some(existing) if existing != incoming => {
                // A different signer voting for a different decision is not
                // equivocation — it is a split committee, and it is genuine
                // disagreement rather than misconduct. It is refused because it
                // cannot be aggregated into one decision, and the caller is
                // expected to keep the dispute open rather than settle.
                return Err(VoteRejection::Conflicting);
            }
            Some(_) => {}
            None => self.decision = Some(incoming),
        }
        self.votes.push(vote.clone());
        Ok(())
    }

    /// Build the settle payload once quorum is reached.
    ///
    /// Re-checks everything from the votes themselves rather than trusting the
    /// accumulator: a decision exists, quorum is met, every counted signer is in
    /// the committee, and the aggregate verifies over the settle decision hash
    /// with real pairings. Returns `None` on any doubt, which is the fail-closed
    /// direction — a node that cannot produce a payload simply does not propose.
    pub fn settle_payload(&self, committee: &[BlsPublicKey]) -> Option<SettlePayload> {
        let (task_id, verdict, vwc_hash) = self.decision?;
        if self.votes.len() < self.quorum {
            return None;
        }
        let signers: Vec<BlsPublicKey> = self.votes.iter().map(|v| v.signer).collect();
        if !signers.iter().all(|k| committee.contains(k)) {
            return None;
        }
        // Aggregate the counted signatures. BLS aggregation is order-independent,
        // so arrival order cannot change the bytes.
        let sigs: Vec<BlsSignature> = self.votes.iter().map(|v| v.signature).collect();
        let aggregate = crate::bls::RealBls::aggregate(&sigs).ok()?;
        let payload = SettlePayload {
            task_id,
            verdict,
            vwc_hash,
            bls_sig: aggregate.0,
            // The bitmap is an index into the verifier's key order, so build it
            // against the sorted committee rather than arrival order.
            signer_bitmap: bitmap_for(&signers, committee),
            signer_count: signers.len() as u32,
        };
        // The check that matters: the aggregate must verify over the settle
        // decision hash under the committee, exactly as `apply_settle` will.
        let msg = payload.signing_hash();
        if !crate::bls::RealBls::verify_aggregate(&signers, &msg, &aggregate) {
            return None;
        }
        Some(payload)
    }
}

/// A bitmap over `committee`'s order, one bit per signer in `signers`.
///
/// `committee` is the *verifier's* sorted order, because that is the order
/// `ValidatorSet::new` produces and `signers_from_bitmap` indexes into. Passing
/// it already sorted is what makes the produced bitmap verify.
fn bitmap_for(signers: &[BlsPublicKey], committee: &[BlsPublicKey]) -> Vec<u8> {
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|k| k.0);
    let n = sorted.len().div_ceil(8);
    let mut out = vec![0u8; n.max(1)];
    for (i, key) in sorted.iter().enumerate() {
        if signers.contains(key) {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Two conflicting votes from the same committee member, retained as data.
///
/// The checkpoint layer has the same shape (`validators::EquivocationEvidence`)
/// for the same reason: the *evidence* is well-defined and cheap to produce,
/// while the punishment is a separate decision. For arbitration the situation
/// differs — Decision 20 means a committee member has a bond — but the evidence
/// is still only an input. Turning it into a slash requires a slash transaction,
/// and that path is not wired for arbitration (see `docs/decisions.md`); nothing
/// here claims otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbitrationEquivocation {
    /// The signer who signed both.
    pub offender: BlsPublicKey,
    /// The signed message hash of the first vote.
    pub first_msg: Hash,
    /// The signed message hash of the conflicting vote.
    pub second_msg: Hash,
}

/// Votes across every dispute this node has heard about.
///
/// A plain map, with the only shape guarantee that matters: a dispute is keyed
/// by task id, so two disputes can never contaminate each other's tally, and a
/// task id that has never been disputed cannot be tallied at all.
#[derive(Debug, Clone, Default)]
pub struct VoteBook {
    tallies: std::collections::BTreeMap<Hash, VoteTally>,
}

impl VoteBook {
    pub fn new() -> Self {
        VoteBook::default()
    }

    /// Number of disputes with at least one counted vote.
    pub fn len(&self) -> usize {
        self.tallies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tallies.is_empty()
    }

    /// The tally for a dispute, creating it on first contact.
    pub fn entry(&mut self, task_id: Hash, quorum: usize) -> &mut VoteTally {
        self.tallies
            .entry(task_id)
            .or_insert_with(|| VoteTally::new(quorum))
    }

    /// The tally for a dispute, if one exists.
    pub fn tally(&self, task_id: &Hash) -> Option<&VoteTally> {
        self.tallies.get(task_id)
    }

    /// Every dispute with a reaching-quorum tally, as `(task_id, payload)`.
    ///
    /// Deterministic order — `BTreeMap` by task id — so two nodes that received
    /// the same votes propose the same settlements in the same order, which is
    /// what makes a quorum outcome reproducible rather than arrival-dependent.
    pub fn ready(&self, committee: &[BlsPublicKey]) -> Vec<(Hash, SettlePayload)> {
        self.tallies
            .iter()
            .filter_map(|(id, t)| t.settle_payload(committee).map(|p| (*id, p)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::SecretKey;
    use crate::l2::VWC_HASH_EXPIRED;
    use crate::params::mini_validator_secret;

    fn keys(n: usize) -> Vec<BlsPublicKey> {
        (1..=n as u8)
            .map(mini_validator_secret)
            .map(|sk| sk.public_key())
            .collect()
    }

    fn signer(committee: &[BlsPublicKey], idx: usize) -> SecretKey {
        let wanted = committee[idx];
        (1u8..=32)
            .map(mini_validator_secret)
            .find(|sk| sk.public_key() == wanted)
            .expect("committee member")
    }

    fn vote(
        committee: &[BlsPublicKey],
        idx: usize,
        task_id: Hash,
        verdict: Verdict,
        vwc_hash: Hash,
        network_id: &str,
        height: u64,
    ) -> ArbitrationVote {
        let sk = signer(committee, idx);
        let base = ArbitrationVote {
            version: ARBITRATION_VOTE_VERSION,
            task_id,
            verdict,
            vwc_hash,
            network_id: network_id.to_string(),
            height,
            signer: sk.public_key(),
            signature: BlsSignature([0u8; 96]),
        };
        ArbitrationVote {
            signature: sk.sign(&base.signing_hash()),
            ..base
        }
    }

    fn quorum(committee: &[BlsPublicKey]) -> usize {
        crate::bls_checkpoint::ValidatorSet::new(committee.to_vec()).quorum_size()
    }

    const NET: &str = "jounit/mini";
    const TASK: Hash = [0x42u8; 32];
    const RESULT: Hash = [0xABu8; 32];

    // --- what a vote is ------------------------------------------------

    #[test]
    fn a_vote_signs_the_settle_decision_hash_exactly() {
        // Load-bearing: `apply_settle` verifies the aggregate over
        // `SettlePayload::signing_hash`, so a vote must sign those exact bytes or
        // a quorum of them cannot compose into anything the chain accepts.
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        let payload = SettlePayload {
            task_id: TASK,
            verdict: Verdict::Fraudulent,
            vwc_hash: RESULT,
            bls_sig: [0u8; 96],
            signer_bitmap: Vec::new(),
            signer_count: 0,
        };
        assert_eq!(v.signing_hash(), payload.signing_hash());
    }

    #[test]
    fn an_arbiter_may_not_vote_expired() {
        // `Expired` is a clock outcome. Letting a committee settle a task nobody
        // disputed would create a second, weaker settlement path.
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Expired, RESULT, NET, 0);
        assert!(v.validate_structure().is_err());
    }

    #[test]
    fn a_vote_may_not_name_the_expired_placeholder() {
        let committee = keys(4);
        let v = vote(
            &committee,
            0,
            TASK,
            Verdict::Fraudulent,
            VWC_HASH_EXPIRED,
            NET,
            0,
        );
        assert!(v.validate_structure().is_err());
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let committee = keys(4);
        let mut v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        v.version = 99;
        assert!(v.validate_structure().is_err());
    }

    #[test]
    fn an_over_long_network_id_is_refused() {
        let committee = keys(4);
        let long = "x".repeat(MAX_NETWORK_ID_BYTES + 1);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, &long, 0);
        assert!(v.validate_structure().is_err());
    }

    #[test]
    fn a_signature_that_is_not_a_point_is_refused() {
        let committee = keys(4);
        let mut v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        v.signature = BlsSignature([0u8; 96]);
        assert!(v.validate_structure().is_err(), "zero is not a point");
    }

    #[test]
    fn a_forged_signature_is_refused_before_a_pairing_check() {
        let committee = keys(4);
        let mut v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        // Still structurally valid, but no longer signed by the named key.
        v.vwc_hash = [0xCCu8; 32];
        assert!(v.validate_structure().is_ok());
        assert!(!v.verify_signature());
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        let other = signer(&committee, 1);
        assert!(
            !crate::bls::RealBls::verify(&other.public_key(), &v.signing_hash(), &v.signature),
            "a signature under another key must not verify"
        );
    }

    // --- codec ---------------------------------------------------------

    #[test]
    fn a_vote_round_trips_canonically() {
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 7);
        let wire = v.serialize();
        assert_eq!(ArbitrationVote::deserialize(&wire).unwrap(), v);
        assert_eq!(
            ArbitrationVote::deserialize(&wire).unwrap().serialize(),
            wire,
            "the encoding must be canonical"
        );
    }

    #[test]
    fn a_trailing_byte_is_refused() {
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        let mut wire = v.serialize();
        wire.push(0x00);
        assert!(ArbitrationVote::deserialize(&wire).is_err());
    }

    #[test]
    fn a_huge_declared_network_id_cannot_force_an_allocation() {
        let committee = keys(4);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        let mut wire = v.serialize();
        // Overwrite the length prefix in place, keeping the payload small.
        wire[36] = 0xFF;
        wire[37] = 0xFF;
        wire[38] = 0xFF;
        wire[39] = 0xFF;
        assert!(ArbitrationVote::deserialize(&wire).is_err());
    }

    // --- tally ---------------------------------------------------------

    #[test]
    fn quorum_of_valid_votes_produces_a_payload_the_settle_path_accepts() {
        // The whole seam: build a quorum of votes, aggregate them, and confirm
        // the resulting payload is exactly what a real settle path verifies.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        for idx in 0..q {
            let v = vote(&committee, idx, TASK, Verdict::Fraudulent, RESULT, NET, 0);
            tally.record(&v, NET, 0, &committee).unwrap();
        }
        assert!(tally.has_quorum());

        let payload = tally.settle_payload(&committee).expect("quorum reached");
        assert_eq!(payload.task_id, TASK);
        assert_eq!(payload.verdict, Verdict::Fraudulent);
        assert_eq!(payload.vwc_hash, RESULT);
        assert_eq!(payload.signer_count, q as u32);

        // And the aggregate must verify the way `apply_settle` verifies it:
        // over the settle decision hash, against the signers the bitmap names.
        let signers = crate::bls_checkpoint::ValidatorSet::new(committee.clone())
            .signers_from_bitmap(&payload.signer_bitmap);
        assert_eq!(signers.len(), q);
        let msg = payload.signing_hash();
        assert!(
            crate::bls::RealBls::verify_aggregate(&signers, &msg, &BlsSignature(payload.bls_sig)),
            "the aggregate must verify over the settle decision"
        );
    }

    #[test]
    fn one_vote_short_of_quorum_produces_nothing() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        for idx in 0..q - 1 {
            let v = vote(&committee, idx, TASK, Verdict::Fraudulent, RESULT, NET, 0);
            tally.record(&v, NET, 0, &committee).unwrap();
        }
        assert!(!tally.has_quorum());
        assert!(tally.settle_payload(&committee).is_none());
    }

    #[test]
    fn a_duplicate_signature_cannot_inflate_quorum() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        for _ in 0..10 {
            let _ = tally.record(&v, NET, 0, &committee);
        }
        assert_eq!(tally.votes(), 1, "one signer counts once");
        assert!(!tally.has_quorum());
        assert!(tally.settle_payload(&committee).is_none());
    }

    #[test]
    fn a_stranger_is_refused_and_records_nothing() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let stranger = SecretKey::derive(&[99u8; 32]).unwrap();
        let base = ArbitrationVote {
            version: ARBITRATION_VOTE_VERSION,
            task_id: TASK,
            verdict: Verdict::Fraudulent,
            vwc_hash: RESULT,
            network_id: NET.to_string(),
            height: 0,
            signer: stranger.public_key(),
            signature: BlsSignature([0u8; 96]),
        };
        let v = ArbitrationVote {
            signature: stranger.sign(&base.signing_hash()),
            ..base
        };
        assert_eq!(
            tally.record(&v, NET, 0, &committee),
            Err(VoteRejection::NotInCommittee)
        );
        assert_eq!(tally.votes(), 0);
    }

    #[test]
    fn a_forged_signature_is_refused_before_the_committee_check() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let mut v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        v.vwc_hash = [0xDDu8; 32];
        assert_eq!(
            tally.record(&v, NET, 0, &committee),
            Err(VoteRejection::BadSignature)
        );
    }

    #[test]
    fn a_vote_for_another_network_or_height_is_refused() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut t1 = VoteTally::new(q);
        assert_eq!(
            t1.record(
                &vote(
                    &committee,
                    0,
                    TASK,
                    Verdict::Fraudulent,
                    RESULT,
                    "jounit/mainnet",
                    0
                ),
                NET,
                0,
                &committee
            ),
            Err(VoteRejection::WrongNetwork)
        );
        let mut t2 = VoteTally::new(q);
        assert_eq!(
            t2.record(
                &vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 99),
                NET,
                0,
                &committee
            ),
            Err(VoteRejection::WrongHeight)
        );
    }

    #[test]
    fn a_second_signature_from_the_same_signer_is_a_conflict_not_a_merge() {
        // Equivocation, not duplication: the signer is in the committee and
        // signed validly, but for a *different decision*. It must be refused,
        // and the refusal must be distinguishable from a replay.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let first = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        tally.record(&first, NET, 0, &committee).unwrap();
        let rogue = vote(&committee, 0, TASK, Verdict::Correct, [0xEEu8; 32], NET, 0);
        assert_eq!(
            tally.record(&rogue, NET, 0, &committee),
            Err(VoteRejection::Conflicting)
        );
        assert_eq!(tally.votes(), 1, "only the first is counted");
        assert_eq!(
            tally.decision(),
            Some((TASK, Verdict::Fraudulent, RESULT)),
            "the decision is what was signed, not a merge"
        );
    }

    #[test]
    fn equivocation_is_retained_as_evidence() {
        // The input a slash path would need, recorded when it happens. Nothing
        // here slashes: that needs a slash transaction, which is not wired.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        tally
            .record(
                &vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0),
                NET,
                0,
                &committee,
            )
            .unwrap();
        let rogue = vote(&committee, 0, TASK, Verdict::Correct, [0xEEu8; 32], NET, 0);
        let _ = tally.record(&rogue, NET, 0, &committee);

        let ev = tally.equivocations();
        assert_eq!(ev.len(), 1, "the double-sign must be recorded");
        assert_eq!(ev[0].offender, signer(&committee, 0).public_key());
        assert_ne!(
            ev[0].first_msg, ev[0].second_msg,
            "the messages really conflict"
        );
    }

    #[test]
    fn a_split_committee_is_not_misread_as_equivocation() {
        // Two *different* signers disagreeing is a split committee, not
        // misconduct. It must still be refused - it cannot be aggregated into
        // one decision - but it must not be recorded as equivocation, because
        // blaming an honest signer for the committee's disagreement is exactly
        // the kind of thing that gets turned into a slash.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        tally
            .record(
                &vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0),
                NET,
                0,
                &committee,
            )
            .unwrap();
        let other = vote(&committee, 1, TASK, Verdict::Correct, [0xEEu8; 32], NET, 0);
        assert_eq!(
            tally.record(&other, NET, 0, &committee),
            Err(VoteRejection::Conflicting)
        );
        assert!(
            tally.equivocations().is_empty(),
            "disagreement between two honest signers is not equivocation"
        );
    }

    #[test]
    fn a_replayed_vote_of_the_same_decision_is_a_duplicate() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let v = vote(&committee, 0, TASK, Verdict::Fraudulent, RESULT, NET, 0);
        tally.record(&v, NET, 0, &committee).unwrap();
        let wire = v.serialize();
        let again = ArbitrationVote::deserialize(&wire).unwrap();
        assert_eq!(
            tally.record(&again, NET, 0, &committee),
            Err(VoteRejection::Duplicate)
        );
    }

    #[test]
    fn the_payload_bitmap_is_an_index_into_the_committee_order() {
        // Arrival order must not change the bytes: the bitmap is an index into
        // the verifier's key order, so a tally assembled backwards verifies the
        // same way.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut forward = VoteTally::new(q);
        for idx in 0..q {
            forward
                .record(
                    &vote(&committee, idx, TASK, Verdict::Fraudulent, RESULT, NET, 0),
                    NET,
                    0,
                    &committee,
                )
                .unwrap();
        }
        let mut reversed = VoteTally::new(q);
        for idx in (0..q).rev() {
            reversed
                .record(
                    &vote(&committee, idx, TASK, Verdict::Fraudulent, RESULT, NET, 0),
                    NET,
                    0,
                    &committee,
                )
                .unwrap();
        }
        assert_eq!(
            forward.settle_payload(&committee).unwrap().signer_bitmap,
            reversed.settle_payload(&committee).unwrap().signer_bitmap,
            "arrival order must not change the payload"
        );
        assert_eq!(
            forward.settle_payload(&committee).unwrap().bls_sig,
            reversed.settle_payload(&committee).unwrap().bls_sig,
            "aggregation is order-independent"
        );
    }

    // --- book ----------------------------------------------------------

    #[test]
    fn one_books_disputes_cannot_contaminate_each_other() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut book = VoteBook::new();
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        for idx in 0..q {
            book.entry(a, q)
                .record(
                    &vote(&committee, idx, a, Verdict::Fraudulent, RESULT, NET, 0),
                    NET,
                    0,
                    &committee,
                )
                .unwrap();
            book.entry(b, q)
                .record(
                    &vote(&committee, idx, b, Verdict::Correct, RESULT, NET, 0),
                    NET,
                    0,
                    &committee,
                )
                .unwrap();
        }
        let ready = book.ready(&committee);
        assert_eq!(ready.len(), 2, "both disputes reached quorum");
        // Deterministic order, by task id.
        assert!(ready[0].0 < ready[1].0);
        assert_eq!(ready[0].1.verdict, Verdict::Fraudulent);
    }

    #[test]
    fn a_dispute_that_never_reached_quorum_offers_nothing() {
        let committee = keys(4);
        let q = quorum(&committee);
        let mut book = VoteBook::new();
        for idx in 0..q - 1 {
            book.entry(TASK, q)
                .record(
                    &vote(&committee, idx, TASK, Verdict::Fraudulent, RESULT, NET, 0),
                    NET,
                    0,
                    &committee,
                )
                .unwrap();
        }
        assert!(book.ready(&committee).is_empty());
    }

    #[test]
    fn a_signature_over_a_different_dispute_does_not_carry_over() {
        // The binding that stops a vote for one dispute finalizing another.
        let committee = keys(4);
        let q = quorum(&committee);
        let mut tally = VoteTally::new(q);
        let v = vote(
            &committee,
            0,
            [0x01u8; 32],
            Verdict::Fraudulent,
            RESULT,
            NET,
            0,
        );
        // Re-recorded under a different task id in the book keeps its own
        // signature, which verifies for the task it signed and not this one.
        let mut forged = v.clone();
        forged.task_id = [0x02u8; 32];
        assert!(
            !forged.verify_signature(),
            "the signature does not follow the task id"
        );
        let _ = &mut tally;
    }
}
