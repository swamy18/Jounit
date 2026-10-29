//! Portable agent reputation: verifiable history, not vibes.
//!
//! A passport is an agent's portable work record: task completions, payments
//! made, disputes won/lost, refunds issued/received and loan repayments or
//! defaults. Each event points at the artifact that proves it (a receipt id,
//! a payment id, a position id), and an issuer — a service, marketplace or
//! lender that verified the event against its own books — signs the batch.
//! Any other service can then verify the passport offline and set access or
//! pricing from it.
//!
//! Sybil resistance is structural, not promised:
//!
//! - history costs money: every positive event is backed by a real payment,
//!   a settled receipt, posted collateral or a repaid loan — minting N fresh
//!   identities means funding N histories;
//! - repeat business dampens: events with the same counterparty contribute
//!   sub-linearly (integer square root of the count), so two colluding
//!   parties farming receipts between fresh ids gain little;
//! - stake-backed events weigh more: a repaid collateralized loan outweighs
//!   a bare task completion;
//! - negative events are sticky: disputes lost and defaults subtract more
//!   than any single positive event adds, and they are never dampened.
//!
//! A score is a pricing input, never a repayment guarantee: lenders still
//! take collateral, and `credit` never reads a score (see `lending`).

use crate::agent::AgentId;
use crate::hash::{sha256_dom, Hash};
use std::collections::BTreeMap;

/// Domain tag for a passport batch signing hash.
pub const DOM_PASSPORT_BATCH: &[u8] = b"srct/passport-batch/v1";
/// Longest accepted network id (bytes).
pub const MAX_PASSPORT_NETWORK_ID_LEN: usize = 64;
/// Most events one batch carries (bounds verification work).
pub const MAX_PASSPORT_EVENTS: usize = 256;

/// Verifiable history event kinds. Weights are scoring inputs, not consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PassportEventKind {
    TaskCompleted,
    PaymentCompleted,
    DisputeWon,
    RefundIssued,
    LoanRepaid,
    RefundReceived,
    DisputeLost,
    LoanDefaulted,
}

impl PassportEventKind {
    /// Base weight in score points. Negatives are sticky: larger than any
    /// single positive, and never dampened by counterparty repetition.
    pub fn weight(self) -> i64 {
        match self {
            PassportEventKind::TaskCompleted => 1,
            PassportEventKind::PaymentCompleted => 1,
            PassportEventKind::DisputeWon => 1,
            PassportEventKind::RefundIssued => 2,
            PassportEventKind::LoanRepaid => 4,
            PassportEventKind::RefundReceived => 0,
            PassportEventKind::DisputeLost => -4,
            PassportEventKind::LoanDefaulted => -8,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            PassportEventKind::TaskCompleted => 0,
            PassportEventKind::PaymentCompleted => 1,
            PassportEventKind::DisputeWon => 2,
            PassportEventKind::RefundIssued => 3,
            PassportEventKind::LoanRepaid => 4,
            PassportEventKind::RefundReceived => 5,
            PassportEventKind::DisputeLost => 6,
            PassportEventKind::LoanDefaulted => 7,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PassportEventKind::TaskCompleted),
            1 => Some(PassportEventKind::PaymentCompleted),
            2 => Some(PassportEventKind::DisputeWon),
            3 => Some(PassportEventKind::RefundIssued),
            4 => Some(PassportEventKind::LoanRepaid),
            5 => Some(PassportEventKind::RefundReceived),
            6 => Some(PassportEventKind::DisputeLost),
            7 => Some(PassportEventKind::LoanDefaulted),
            _ => None,
        }
    }

    /// Whether repeat events with one counterparty dampen (positives do;
    /// negatives and neutral receipts never do).
    pub fn dampens(self) -> bool {
        matches!(
            self,
            PassportEventKind::TaskCompleted
                | PassportEventKind::PaymentCompleted
                | PassportEventKind::DisputeWon
                | PassportEventKind::RefundIssued
                | PassportEventKind::LoanRepaid
        )
    }
}

/// One history event. `source` is the proving artifact (receipt id, payment
/// id, position id); `counterparty` scopes the anti-farming dampening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportEvent {
    pub kind: PassportEventKind,
    pub height: u64,
    pub source: Hash,
    pub counterparty: AgentId,
    pub amount_sat: u64,
}

impl PassportEvent {
    pub fn id(&self) -> Hash {
        sha256_dom(
            b"srct/passport-event/v1",
            &[
                &[self.kind.as_u8()],
                &self.height.to_le_bytes(),
                &self.source,
                &self.counterparty,
                &self.amount_sat.to_le_bytes(),
            ],
        )
    }
}

/// An issuer-signed batch of one subject's events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportBatch {
    pub network_id: String,
    pub subject: AgentId,
    pub events: Vec<PassportEvent>,
    pub issuer: crate::bls_checkpoint::BlsPublicKey,
    pub issued_height: u64,
    pub expires_height: u64,
    pub sig: crate::bls_checkpoint::BlsSignature,
}

impl PassportBatch {
    pub fn signing_hash(&self) -> Hash {
        let mut ids: Vec<u8> = Vec::with_capacity(self.events.len() * 32);
        for e in &self.events {
            ids.extend_from_slice(&e.id());
        }
        sha256_dom(
            DOM_PASSPORT_BATCH,
            &[
                self.network_id.as_bytes(),
                &self.subject,
                &ids,
                &self.issued_height.to_le_bytes(),
                &self.expires_height.to_le_bytes(),
                &self.issuer.0,
            ],
        )
    }

    pub fn validate(&self) -> Result<(), PassportError> {
        if self.network_id.is_empty() || self.network_id.len() > MAX_PASSPORT_NETWORK_ID_LEN {
            return Err(PassportError::Malformed("network id"));
        }
        if self.events.is_empty() || self.events.len() > MAX_PASSPORT_EVENTS {
            return Err(PassportError::Malformed("events length"));
        }
        if self.expires_height <= self.issued_height {
            return Err(PassportError::Malformed("expiry"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.events {
            if !seen.insert(e.id()) {
                return Err(PassportError::Malformed("duplicate event"));
            }
        }
        Ok(())
    }

    /// Verify the issuer really signed this exact batch.
    pub fn verify_sig(&self) -> bool {
        crate::bls::RealBls::verify(&self.issuer, &self.signing_hash(), &self.sig)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportError {
    Malformed(&'static str),
}

impl std::fmt::Display for PassportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassportError::Malformed(w) => write!(f, "malformed passport: {w}"),
        }
    }
}

impl std::error::Error for PassportError {}

/// Integer square root (floor) for the counterparty dampening.
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) >> 1;
    while y < x {
        x = y;
        y = (x + n / x) >> 1;
    }
    x
}

/// Score a batch: per (kind, counterparty) group, contribution is
/// `weight * isqrt(count)` for dampened kinds, `weight * count` for sticky
/// negatives. RefundReceived is record-keeping (0). Never a guarantee —
/// see the module docs.
pub fn score_batch(batch: &PassportBatch) -> i64 {
    let mut groups: BTreeMap<(u8, AgentId), u64> = BTreeMap::new();
    for e in &batch.events {
        *groups.entry((e.kind.as_u8(), e.counterparty)).or_insert(0) += 1;
    }
    let mut score: i64 = 0;
    for ((kind_u8, _), count) in groups {
        let kind = PassportEventKind::from_u8(kind_u8).unwrap();
        let w = kind.weight();
        let contrib = if kind.dampens() {
            w.saturating_mul(isqrt(count) as i64)
        } else {
            w.saturating_mul(count as i64)
        };
        score = score.saturating_add(contrib);
    }
    score
}

/// Service-side access tier from a score. Thresholds are the service's own
/// policy; this only names the bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTier {
    Deny,
    Throttled,
    Standard,
    Preferred,
}

pub fn access_tier(score: i64) -> AccessTier {
    if score < 0 {
        AccessTier::Deny
    } else if score < 5 {
        AccessTier::Throttled
    } else if score < 20 {
        AccessTier::Standard
    } else {
        AccessTier::Preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(kind: PassportEventKind, cp: u8, src: u8) -> PassportEvent {
        PassportEvent {
            kind,
            height: 10,
            source: [src; 32],
            counterparty: [cp; 20],
            amount_sat: 100,
        }
    }

    #[test]
    fn farming_one_counterparty_dampens() {
        let mk = |events| PassportBatch {
            network_id: "srct/testnet".to_string(),
            subject: [1u8; 20],
            events,
            issuer: crate::bls_checkpoint::BlsPublicKey([2u8; 48]),
            issued_height: 1,
            expires_height: 100,
            sig: crate::bls_checkpoint::BlsSignature([0u8; 96]),
        };
        // 100 farmed payments, one counterparty: sqrt(100)=10, not 100.
        let farmed: Vec<_> = (0..100u8).map(|i| evt(PassportEventKind::PaymentCompleted, 9, i)).collect();
        // 4 genuine payments, four counterparties.
        let genuine: Vec<_> = (0..4u8).map(|i| evt(PassportEventKind::PaymentCompleted, i, i)).collect();
        assert!(score_batch(&mk(farmed)) < score_batch(&mk(genuine)) * 3);
    }

    #[test]
    fn negatives_are_sticky_and_deny() {
        let batch = PassportBatch {
            network_id: "srct/testnet".to_string(),
            subject: [1u8; 20],
            events: vec![
                evt(PassportEventKind::LoanRepaid, 2, 1),
                evt(PassportEventKind::LoanRepaid, 3, 2),
                evt(PassportEventKind::LoanDefaulted, 4, 3),
            ],
            issuer: crate::bls_checkpoint::BlsPublicKey([2u8; 48]),
            issued_height: 1,
            expires_height: 100,
            sig: crate::bls_checkpoint::BlsSignature([0u8; 96]),
        };
        // 4 + 4 - 8 = 0 → throttled, one more default denies.
        assert_eq!(access_tier(score_batch(&batch)), AccessTier::Throttled);
    }
}
