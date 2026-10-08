//! Machine/agent reputation — roadmap item 9.
//!
//! A **minimal, cryptographically verifiable, accumulator-based** reputation
//! primitive. Not a social network: there are no profiles, no followers, no
//! free-text claims and no administrator. Reputation is only ever moved by a
//! *verified artifact* the repository already trusts:
//!
//! | event kind          | backing artifact              | verified by                    |
//! |---------------------|-------------------------------|--------------------------------|
//! | `ServiceCompleted`  | service receipt (subject = service, derived) | receipt signature |
//! | `PaymentCompleted`  | service receipt (subject = payer)           | receipt signature |
//! | `VerifiedWork`      | verified work certificate      | quorum BLS verify (in `jnt-l2`) |
//! | `DisputeWon`        | settled dispute outcome        | settle auth (in `jnt-l2`)      |
//! | `DisputeLost`       | settled dispute outcome        | settle auth (in `jnt-l2`)      |
//!
//! # Design rules (locked)
//!
//! - **Identity-bound.** Scores are keyed by `AgentId`, which re-derives from
//!   `(network, role, owner)`, so a subject cannot be forged or impersonated.
//! - **Deterministic.** `accumulator = SHA256("jounit/reputation-acc/v1" ‖
//!   prev ‖ event_id)`; two ledgers that see the same events agree exactly.
//! - **Replay-resistant.** Each event must chain onto the subject's current
//!   accumulator (the ledger assigns `prev`), and each `source` (receipt id,
//!   VWC id, settlement id) may be counted **once per subject** — tracked in
//!   a bounded ring of the most recent [`MAX_TRACKED_SOURCES`] sources.
//! - **Bounded.** Fixed-size state per subject (hash + counters), a cap on
//!   subjects, a cap on the source ring. There is **no** unbounded raw event
//!   history anywhere.
//! - **Not mintable.** Weights are a fixed table keyed by kind — an event
//!   carries no amount, no weight and no signature of its own. Every public
//!   `apply_*` entry point verifies its backing artifact before committing,
//!   and a refusal mutates nothing.
//! - **No administrator.** There is no owner, no override, no remote feed.
//!
//! # Known residual risk (documented, not hidden)
//!
//! Two colluding parties can mint *genuine* receipts between fresh
//! identities, so counterparty-attested events (`ServiceCompleted`,
//! `PaymentCompleted`, weight +1 each) are weak evidence by themselves.
//! Quorum-backed `VerifiedWork` (+2) and dispute outcomes (±3) are the strong
//! signals, because producing them requires the L2 settlement machinery and,
//! for disputes, an actual challenge. There is no stake to slash yet
//! (validator economics are deferred by Decision 2), so Sybil cost cannot be
//! made economic here — that dependency is recorded rather than faked.

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Hash};
use crate::receipt::ServiceReceipt;
use crate::ser::{Reader, Writer};
use std::collections::BTreeMap;
use std::fmt;

/// Reputation encoding version. A future format MUST use a new value.
pub const REPUTATION_VERSION: u8 = 1;
/// Domain tag for the reputation event id.
pub const DOM_REPUTATION_EVENT: &[u8] = b"jounit/reputation-event/v1";
/// Domain tag for the accumulator chain.
pub const DOM_REPUTATION_ACC: &[u8] = b"jounit/reputation-acc/v1";
/// Longest accepted network id (bytes).
pub const MAX_REPUTATION_NETWORK_ID_LEN: usize = 64;
/// Distinct sources remembered per subject (ring buffer).
pub const MAX_TRACKED_SOURCES: usize = 128;
/// Default cap on tracked subjects, so a caller cannot grow state forever.
pub const DEFAULT_MAX_SUBJECTS: usize = 8192;

/// What happened. The discriminant is part of the event id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReputationKind {
    /// The subject delivered a service (receipt-backed).
    ServiceCompleted = 0,
    /// The subject completed its payment (receipt-backed).
    PaymentCompleted = 1,
    /// The subject produced verified work (VWC-backed, applied in `jnt-l2`).
    VerifiedWork = 2,
    /// The subject won a dispute (settled-outcome-backed, `jnt-l2`).
    DisputeWon = 3,
    /// The subject lost a dispute / acted fraudulently (`jnt-l2`).
    DisputeLost = 4,
}

impl ReputationKind {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Total: a hostile byte is never silently coerced.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ReputationKind::ServiceCompleted),
            1 => Some(ReputationKind::PaymentCompleted),
            2 => Some(ReputationKind::VerifiedWork),
            3 => Some(ReputationKind::DisputeWon),
            4 => Some(ReputationKind::DisputeLost),
            _ => None,
        }
    }

    /// The fixed weight table. Not a field of the event: an event cannot
    /// declare its own magnitude, so score cannot be minted by construction.
    pub fn weight(self) -> i64 {
        match self {
            ReputationKind::ServiceCompleted => 1,
            ReputationKind::PaymentCompleted => 1,
            ReputationKind::VerifiedWork => 2,
            ReputationKind::DisputeWon => 1,
            ReputationKind::DisputeLost => -3,
        }
    }
}

/// Why an event or receipt was refused. Named and `PartialEq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReputationError {
    /// Bytes could not be decoded as an event.
    Malformed(&'static str),
    /// `version` is not [`REPUTATION_VERSION`].
    UnsupportedVersion(u8),
    /// Ledger and event are for different networks.
    WrongNetwork { expected: String, got: String },
    /// `network_id` empty or over [`MAX_REPUTATION_NETWORK_ID_LEN`].
    BadNetworkId(usize),
    /// The event does not chain onto the subject's accumulator.
    ChainBroken { subject: AgentId },
    /// This source already counted for this subject (replay).
    DuplicateSource { source: Hash },
    /// The ledger is at its subject cap and refuses rather than grows.
    SubjectLimit { cap: usize },
    /// A counter or score would overflow.
    Overflow,
    /// The backing artifact (receipt, …) failed its own verification.
    ArtifactInvalid(&'static str),
}

impl fmt::Display for ReputationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReputationError::Malformed(w) => write!(f, "malformed reputation event: {w}"),
            ReputationError::UnsupportedVersion(v) => {
                write!(f, "unsupported reputation version {v}")
            }
            ReputationError::WrongNetwork { expected, got } => {
                write!(f, "reputation ledger is {expected}, event is {got}")
            }
            ReputationError::BadNetworkId(n) => {
                write!(f, "reputation network id length {n} invalid")
            }
            ReputationError::ChainBroken { subject } => {
                write!(f, "event does not chain onto accumulator of {subject:02x?}")
            }
            ReputationError::DuplicateSource { source } => {
                write!(
                    f,
                    "source {} already counted for this subject",
                    hex::encode(source)
                )
            }
            ReputationError::SubjectLimit { cap } => {
                write!(f, "reputation ledger is at its subject cap ({cap})")
            }
            ReputationError::Overflow => write!(f, "arithmetic overflow in reputation accounting"),
            ReputationError::ArtifactInvalid(w) => {
                write!(f, "backing artifact failed verification: {w}")
            }
        }
    }
}

impl std::error::Error for ReputationError {}

/// One reputation event: a fixed-shape fact chained onto a subject's
/// accumulator. Contains no weight, no amount and no signature of its own —
/// legitimacy comes from the artifact that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationEvent {
    pub version: u8,
    /// Network binding, ≤ [`MAX_REPUTATION_NETWORK_ID_LEN`] bytes.
    pub network_id: String,
    /// Whose standing this event moves.
    pub subject: AgentId,
    /// What happened (discriminant inside the id).
    pub kind: ReputationKind,
    /// Informational height of the backing artifact (0 when unanchored).
    pub height: u64,
    /// The backing artifact's id: receipt id, VWC id, settlement id. Counted
    /// at most once per subject.
    pub source: Hash,
    /// The subject's accumulator before this event (zero for the first).
    pub prev: Hash,
}

impl ReputationEvent {
    /// Canonical bounded encoding of the event body.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.subject)
            .u8(self.kind.as_u8())
            .u64le(self.height)
            .fixed(&self.source)
            .fixed(&self.prev);
        w.into_vec()
    }

    /// Bounded decode; exact inverse of [`ReputationEvent::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ReputationError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| ReputationError::Malformed("version"))?;
        if version != REPUTATION_VERSION {
            return Err(ReputationError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| ReputationError::Malformed("network len"))? as usize;
        if net_len == 0 || net_len > MAX_REPUTATION_NETWORK_ID_LEN {
            return Err(ReputationError::BadNetworkId(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| ReputationError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| ReputationError::Malformed("network id is not utf-8"))?
            .to_string();
        let subject = r
            .fixed::<20>()
            .map_err(|_| ReputationError::Malformed("subject"))?;
        let kind_raw = r.u8().map_err(|_| ReputationError::Malformed("kind"))?;
        let kind = ReputationKind::from_u8(kind_raw)
            .ok_or(ReputationError::Malformed("kind out of range"))?;
        let height = r
            .u64le()
            .map_err(|_| ReputationError::Malformed("height"))?;
        let source = r
            .fixed::<32>()
            .map_err(|_| ReputationError::Malformed("source"))?;
        let prev = r
            .fixed::<32>()
            .map_err(|_| ReputationError::Malformed("prev"))?;
        r.expect_end()
            .map_err(|_| ReputationError::Malformed("trailing bytes"))?;
        Ok(ReputationEvent {
            version,
            network_id,
            subject,
            kind,
            height,
            source,
            prev,
        })
    }

    /// Domain-separated event id.
    pub fn event_id(&self) -> Hash {
        sha256_dom(DOM_REPUTATION_EVENT, &[&self.serialize()])
    }
}

/// Fixed-size per-subject state: the accumulator chain plus counters. This is
/// the *entire* history requirement — raw events are never stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReputationScore {
    /// Chain hash: `SHA256(DOM ‖ prev ‖ event_id)` folded per event.
    pub accumulator: Hash,
    /// Total events counted.
    pub events: u64,
    /// Net score (fixed weights, checked arithmetic).
    pub score: i64,
    /// Per-kind counters, indexed by `ReputationKind as usize`.
    pub by_kind: [u64; 5],
    /// Height of the most recent event (informational).
    pub last_height: u64,
}

impl ReputationScore {
    fn new() -> Self {
        ReputationScore {
            accumulator: [0u8; 32],
            ..Default::default()
        }
    }
}

/// Outcome of a successful commit: the event as chained and its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEvent {
    pub event: ReputationEvent,
    pub event_id: Hash,
    pub score: ReputationScore,
}

/// The bounded reputation ledger for one network.
#[derive(Debug, Clone)]
pub struct ReputationLedger {
    network_id: String,
    scores: BTreeMap<AgentId, ReputationScore>,
    /// Per-subject ring of already-counted sources (bounded replay guard).
    sources: BTreeMap<AgentId, std::collections::VecDeque<Hash>>,
    max_subjects: usize,
}

impl ReputationLedger {
    pub fn new(network_id: impl Into<String>) -> Self {
        ReputationLedger::with_capacity(network_id, DEFAULT_MAX_SUBJECTS)
    }

    pub fn with_capacity(network_id: impl Into<String>, max_subjects: usize) -> Self {
        ReputationLedger {
            network_id: network_id.into(),
            scores: BTreeMap::new(),
            sources: BTreeMap::new(),
            max_subjects,
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn subjects(&self) -> usize {
        self.scores.len()
    }

    pub fn score(&self, subject: &AgentId) -> Option<&ReputationScore> {
        self.scores.get(subject)
    }

    /// Build the event chaining onto the subject's current accumulator. The
    /// ledger — not the caller — supplies `prev`, so a caller cannot fabricate
    /// an alternate history for a subject.
    pub fn event_for(
        &self,
        subject: AgentId,
        kind: ReputationKind,
        height: u64,
        source: Hash,
    ) -> Result<ReputationEvent, ReputationError> {
        if self.network_id.is_empty() || self.network_id.len() > MAX_REPUTATION_NETWORK_ID_LEN {
            return Err(ReputationError::BadNetworkId(self.network_id.len()));
        }
        let prev = self
            .scores
            .get(&subject)
            .map(|s| s.accumulator)
            .unwrap_or([0u8; 32]);
        Ok(ReputationEvent {
            version: REPUTATION_VERSION,
            network_id: self.network_id.clone(),
            subject,
            kind,
            height,
            source,
            prev,
        })
    }

    /// Low-level commit. **Callers must have verified the backing artifact**
    /// named by `event.source` — the in-repo entry points are
    /// [`ReputationLedger::apply_receipt`] here, and `jnt_l2::reputation`'s
    /// `apply_vwc` / `apply_dispute_outcome` for VWC- and settlement-backed
    /// events. This function still fails closed on everything it can check
    /// offline: network, chain link, source replay, subject cap, counters.
    /// A refusal mutates nothing.
    pub fn commit(&mut self, event: &ReputationEvent) -> Result<AppliedEvent, ReputationError> {
        if event.version != REPUTATION_VERSION {
            return Err(ReputationError::UnsupportedVersion(event.version));
        }
        if event.network_id != self.network_id {
            return Err(ReputationError::WrongNetwork {
                expected: self.network_id.clone(),
                got: event.network_id.clone(),
            });
        }
        let known = self.scores.contains_key(&event.subject);
        if !known && self.scores.len() >= self.max_subjects {
            return Err(ReputationError::SubjectLimit {
                cap: self.max_subjects,
            });
        }
        let current = self
            .scores
            .get(&event.subject)
            .cloned()
            .unwrap_or_else(ReputationScore::new);
        if event.prev != current.accumulator {
            return Err(ReputationError::ChainBroken {
                subject: event.subject,
            });
        }
        // Replay guard: one source counts once per subject.
        let ring = self.sources.entry(event.subject).or_default();
        if ring.contains(&event.source) {
            return Err(ReputationError::DuplicateSource {
                source: event.source,
            });
        }
        if ring.len() >= MAX_TRACKED_SOURCES {
            ring.pop_front();
        }
        ring.push_back(event.source);

        let event_id = event.event_id();
        let accumulator = {
            let mut w = Writer::with_capacity(64);
            w.raw(&current.accumulator).fixed(&event_id);
            sha256_dom(DOM_REPUTATION_ACC, &[w.as_slice()])
        };
        let events = current
            .events
            .checked_add(1)
            .ok_or(ReputationError::Overflow)?;
        let score = current
            .score
            .checked_add(event.kind.weight())
            .ok_or(ReputationError::Overflow)?;
        let k = event.kind.as_u8() as usize;
        let mut by_kind = current.by_kind;
        by_kind[k] = by_kind[k].checked_add(1).ok_or(ReputationError::Overflow)?;
        let next = ReputationScore {
            accumulator,
            events,
            score,
            by_kind,
            last_height: event.height.max(current.last_height),
        };
        self.scores.insert(event.subject, next.clone());
        Ok(AppliedEvent {
            event: event.clone(),
            event_id,
            score: next,
        })
    }

    /// Receipt-backed entry point: verifies the receipt against
    /// `expected_network`, then commits two events — the service's
    /// `ServiceCompleted` and the payer's `PaymentCompleted`, both sourced by
    /// the deterministic receipt id. Nothing is applied when verification
    /// fails.
    pub fn apply_receipt(
        &mut self,
        receipt: &ServiceReceipt,
        expected_network: &str,
    ) -> Result<[AppliedEvent; 2], ReputationError> {
        receipt
            .verify(expected_network)
            .map_err(|_| ReputationError::ArtifactInvalid("receipt verification failed"))?;
        let receipt_id = receipt.receipt_id();
        let height = receipt.anchor.map(|a| a.height).unwrap_or(0);

        let service_subject = crate::agent::derive_agent_id(
            expected_network,
            crate::agent::AgentRole::Service,
            &receipt.recipient,
        );
        let payer_subject = receipt.agent_id;
        if service_subject == payer_subject {
            // Only representable when a service pays itself; one source can
            // only count once per subject, so refuse instead of half-applying.
            return Err(ReputationError::ArtifactInvalid(
                "receipt payer and service resolve to one subject",
            ));
        }
        // Capacity and replay are both decided *before* anything commits, so
        // a refusal can never leave a half-applied receipt behind.
        let unknown = [service_subject, payer_subject]
            .iter()
            .filter(|s| !self.scores.contains_key(*s))
            .count();
        if self.scores.len() + unknown > self.max_subjects {
            return Err(ReputationError::SubjectLimit {
                cap: self.max_subjects,
            });
        }
        for s in [service_subject, payer_subject] {
            if self
                .sources
                .get(&s)
                .map(|ring| ring.contains(&receipt_id))
                .unwrap_or(false)
            {
                return Err(ReputationError::DuplicateSource { source: receipt_id });
            }
        }

        // Build both events (the ledger alone knows `prev`), then commit. The
        // subjects are distinct, so neither commit invalidates the other's
        // chain link.
        let ev_service = self.event_for(
            service_subject,
            ReputationKind::ServiceCompleted,
            height,
            receipt_id,
        )?;
        let ev_payer = self.event_for(
            payer_subject,
            ReputationKind::PaymentCompleted,
            height,
            receipt_id,
        )?;
        let first = self.commit(&ev_service)?;
        let second = self.commit(&ev_payer)?;
        Ok([first, second])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{derive_agent_id, AgentRole};
    use crate::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
    use crate::sig::Bundle;
    use crate::wallet::Wallet;

    const NET: &str = "jounit/testnet";

    fn issuer() -> Wallet {
        Wallet::from_private_key_bytes(&[21u8; 32], "service").expect("valid key")
    }

    fn receipt() -> ServiceReceipt {
        let payer = [7u8; 20];
        let mut r = ServiceReceipt {
            version: RECEIPT_VERSION,
            network_id: NET.into(),
            payer,
            payer_role: AgentRole::Machine,
            agent_id: derive_agent_id(NET, AgentRole::Machine, &payer),
            recipient: issuer().address().expect("issuer address"),
            service_id: Some([9u8; 32]),
            amount_sat: 500,
            payment_id: [1u8; 32],
            request_id: [2u8; 32],
            result_hash: Some([3u8; 32]),
            anchor: Some(ReceiptAnchor {
                height: 12,
                block_hash: [4u8; 32],
            }),
            keys: Bundle::default(),
            sigs: Bundle::default(),
        };
        sign_receipt(&mut r, &issuer()).expect("issuer signs");
        r
    }

    #[test]
    fn a_receipt_moves_two_subjects_deterministically() {
        let r = receipt();
        let mut a = ReputationLedger::new(NET);
        let mut b = ReputationLedger::new(NET);
        let ea = a.apply_receipt(&r, NET).expect("apply").clone();
        let eb = b.apply_receipt(&r, NET).expect("apply").clone();
        assert_eq!(ea[0].event_id, eb[0].event_id, "ids must be deterministic");
        assert_eq!(a.score(&ea[0].event.subject), b.score(&eb[0].event.subject));
        assert_eq!(a.score(&ea[0].event.subject).unwrap().score, 1);
        assert_eq!(a.score(&ea[1].event.subject).unwrap().score, 1);
        assert_eq!(a.subjects(), 2);
    }

    #[test]
    fn the_same_receipt_cannot_be_counted_twice() {
        let r = receipt();
        let mut ledger = ReputationLedger::new(NET);
        ledger.apply_receipt(&r, NET).expect("first apply");
        // Replay: the second application hits the source ring on the first
        // subject it tries to move.
        let err = ledger
            .apply_receipt(&r, NET)
            .expect_err("replay must refuse");
        assert!(
            matches!(err, ReputationError::DuplicateSource { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_forged_receipt_applies_nothing() {
        let mut r = receipt();
        r.amount_sat = 10_000_000; // tamper after signing
        let mut ledger = ReputationLedger::new(NET);
        assert!(matches!(
            ledger.apply_receipt(&r, NET),
            Err(ReputationError::ArtifactInvalid(_))
        ));
        assert_eq!(ledger.subjects(), 0, "a refusal must not mutate the ledger");
    }

    #[test]
    fn a_wrong_network_event_is_refused() {
        let mut ledger = ReputationLedger::new(NET);
        let ev = ledger
            .event_for([1u8; 20], ReputationKind::ServiceCompleted, 1, [2u8; 32])
            .unwrap();
        let mut other = ev.clone();
        other.network_id = "jounit/mini".into();
        assert_eq!(
            ledger.commit(&other).unwrap_err(),
            ReputationError::WrongNetwork {
                expected: NET.into(),
                got: "jounit/mini".into()
            }
        );
    }

    #[test]
    fn a_broken_chain_is_refused() {
        let mut ledger = ReputationLedger::new(NET);
        let ev = ledger
            .event_for([1u8; 20], ReputationKind::ServiceCompleted, 1, [2u8; 32])
            .unwrap();
        ledger.commit(&ev).unwrap();
        // A hand-built event with prev = zero against a subject that has a
        // non-zero accumulator.
        let forged = ReputationEvent {
            version: REPUTATION_VERSION,
            network_id: NET.into(),
            subject: [1u8; 20],
            kind: ReputationKind::ServiceCompleted,
            height: 2,
            source: [3u8; 32],
            prev: [0u8; 32],
        };
        assert_eq!(
            ledger.commit(&forged).unwrap_err(),
            ReputationError::ChainBroken { subject: [1u8; 20] }
        );
    }

    #[test]
    fn the_subject_cap_refuses_growth() {
        let mut ledger = ReputationLedger::with_capacity(NET, 1);
        let ev = ledger
            .event_for([1u8; 20], ReputationKind::ServiceCompleted, 1, [2u8; 32])
            .unwrap();
        ledger.commit(&ev).unwrap();
        let ev2 = ledger
            .event_for([2u8; 20], ReputationKind::ServiceCompleted, 1, [3u8; 32])
            .unwrap();
        let err = ledger.commit(&ev2).unwrap_err();
        assert_eq!(err, ReputationError::SubjectLimit { cap: 1 });
        assert_eq!(ledger.subjects(), 1);
    }

    #[test]
    fn every_event_field_changes_the_event_id() {
        let ledger = ReputationLedger::new(NET);
        let base = ledger
            .event_for([1u8; 20], ReputationKind::ServiceCompleted, 7, [2u8; 32])
            .unwrap();
        let id = base.event_id();

        let mut net = base.clone();
        net.network_id = "jounit/mini".into();
        assert_ne!(net.event_id(), id);

        let mut subject = base.clone();
        subject.subject = [9u8; 20];
        assert_ne!(subject.event_id(), id);

        let mut kind = base.clone();
        kind.kind = ReputationKind::VerifiedWork;
        assert_ne!(kind.event_id(), id);

        let mut height = base.clone();
        height.height = 8;
        assert_ne!(height.event_id(), id);

        let mut source = base.clone();
        source.source = [5u8; 32];
        assert_ne!(source.event_id(), id);

        let mut prev = base.clone();
        prev.prev = [6u8; 32];
        assert_ne!(prev.event_id(), id);

        let mut version = base.clone();
        version.version = 2;
        assert_ne!(version.event_id(), id);
    }

    #[test]
    fn events_round_trip_exactly() {
        let ledger = ReputationLedger::new(NET);
        let ev = ledger
            .event_for([1u8; 20], ReputationKind::DisputeLost, 3, [2u8; 32])
            .unwrap();
        let bytes = ev.serialize();
        let back = ReputationEvent::deserialize(&bytes).expect("decode");
        assert_eq!(back, ev);
        assert_eq!(back.serialize(), bytes);
        assert!(ReputationEvent::deserialize(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn weights_are_fixed_and_disputes_dominate() {
        // The table is code, not data: forging an event cannot pick a weight.
        assert_eq!(ReputationKind::ServiceCompleted.weight(), 1);
        assert_eq!(ReputationKind::PaymentCompleted.weight(), 1);
        assert_eq!(ReputationKind::VerifiedWork.weight(), 2);
        assert_eq!(ReputationKind::DisputeWon.weight(), 1);
        assert_eq!(ReputationKind::DisputeLost.weight(), -3);
    }
}
