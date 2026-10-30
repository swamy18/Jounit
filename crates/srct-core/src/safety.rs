//! A safer agent wallet: session budgets, risk checks, audit trail, test mode.
//!
//! `SpendPolicy` caps one policy hash; rotation starts a fresh window by
//! design. This module closes the gaps around it without touching consensus:
//!
//! - [`SessionBook`] — per-agent aggregate spend across rotated policies, with
//!   the same tumbling-window rule as `PolicyBook`. Splitting spend across N
//!   policies no longer bypasses the budget.
//! - [`RiskPolicy`] — high-value human-approval threshold, per-payer velocity
//!   limit, and a mainnet guard for test mode. Pure checks; the node wires
//!   them into `payment_submit` / `authorize` and exports the verdict.
//! - [`AuditLog`] — bounded, hash-chained journal of authorize/payment/receipt
//!   events. Tamper-evident (each entry commits to the previous hash), never
//!   a consensus input, exported via `GET /v1/audit`.
//! - [`reconcile`] — unsettled payments and orphan receipts from node-local
//!   books, so a network timeout cannot silently double-pay: the agent lists
//!   what is in flight before retrying.
//!
//! Fail-closed: every refusal is named; a full book/log refuses rather than
//! evicts security state.

use crate::agent::AgentId;
use crate::hash::{hash_from_hex, hash_to_hex, sha256_dom, Hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// Domain tag for audit-chain entries.
pub const DOM_AUDIT_ENTRY: &[u8] = b"srct/audit-entry/v1";
/// Most session states tracked (cap-with-refusal, like `PolicyBook`).
pub const DEFAULT_MAX_SESSIONS: usize = 1024;
/// Most audit entries kept in memory (ring; full history lives in the
/// payment/receipt stores the audit references).
pub const DEFAULT_MAX_AUDIT_ENTRIES: usize = 512;
/// Env var enabling test mode (refuses `srct/mainnet` spends).
pub const TEST_MODE_ENV: &str = "SRCT_TEST_MODE";

/// Why a safety check refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    Malformed(&'static str),
    SessionLimitExceeded { spent: u64, cap: u64 },
    SessionBookFull { cap: usize },
    HighValueRequiresApproval { amount: u64, threshold: u64 },
    VelocityLimited { recent: usize, limit: usize },
    MainnetBlockedInTestMode,
    AuditFull { cap: usize },
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyError::Malformed(w) => write!(f, "malformed safety state: {w}"),
            SafetyError::SessionLimitExceeded { spent, cap } => {
                write!(f, "session budget exceeded: spent {spent} of {cap}")
            }
            SafetyError::SessionBookFull { cap } => write!(f, "session book full ({cap})"),
            SafetyError::HighValueRequiresApproval { amount, threshold } => write!(
                f,
                "amount {amount} needs human approval (threshold {threshold})"
            ),
            SafetyError::VelocityLimited { recent, limit } => {
                write!(
                    f,
                    "velocity limited: {recent} recent payments, limit {limit}"
                )
            }
            SafetyError::MainnetBlockedInTestMode => {
                write!(f, "test mode refuses srct/mainnet spends")
            }
            SafetyError::AuditFull { cap } => write!(f, "audit log full ({cap})"),
        }
    }
}

impl std::error::Error for SafetyError {}

/// Per-agent aggregate spend across all of the agent's policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    pub window_start_height: u64,
    pub spent_in_window_sat: u64,
    pub total_spent_sat: u64,
}

/// Tumbling-window session budgets keyed by agent id.
#[derive(Debug, Clone)]
pub struct SessionBook {
    states: BTreeMap<AgentId, SessionState>,
    max_sessions: usize,
}

impl Default for SessionBook {
    fn default() -> Self {
        SessionBook::with_capacity(DEFAULT_MAX_SESSIONS)
    }
}

impl SessionBook {
    pub fn with_capacity(max_sessions: usize) -> Self {
        SessionBook {
            states: BTreeMap::new(),
            max_sessions,
        }
    }

    pub fn state(&self, agent: &AgentId) -> Option<&SessionState> {
        self.states.get(agent)
    }

    /// Restore one agent's session accounting (restart recovery only). Refuses
    /// a duplicate agent or a full book.
    pub fn restore(&mut self, agent: AgentId, state: SessionState) -> Result<(), SafetyError> {
        if self.states.contains_key(&agent) {
            return Err(SafetyError::Malformed("duplicate session"));
        }
        if self.states.len() >= self.max_sessions {
            return Err(SafetyError::SessionBookFull {
                cap: self.max_sessions,
            });
        }
        self.states.insert(agent, state);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Iterate `(agent, state)` in agent order (deterministic for encoding).
    pub fn iter(&self) -> impl Iterator<Item = (&AgentId, &SessionState)> {
        self.states.iter()
    }

    /// Record `amount_sat` for `agent` at `height` under a tumbling window of
    /// `window_blocks` capped at `cap_sat`. Rolls the window forward when the
    /// height leaves it; refuses (without mutating) on over-cap or overflow.
    pub fn record(
        &mut self,
        agent: &AgentId,
        height: u64,
        amount_sat: u64,
        window_blocks: u64,
        cap_sat: u64,
    ) -> Result<(), SafetyError> {
        if window_blocks == 0 || cap_sat == 0 {
            return Err(SafetyError::Malformed("window/cap"));
        }
        let st = match self.states.get(agent) {
            Some(st) => {
                if height
                    >= st
                        .window_start_height
                        .checked_add(window_blocks)
                        .ok_or(SafetyError::Malformed("window overflow"))?
                {
                    SessionState {
                        window_start_height: height,
                        spent_in_window_sat: 0,
                        total_spent_sat: st.total_spent_sat,
                    }
                } else {
                    *st
                }
            }
            None => {
                if self.states.len() >= self.max_sessions {
                    return Err(SafetyError::SessionBookFull {
                        cap: self.max_sessions,
                    });
                }
                SessionState {
                    window_start_height: height,
                    spent_in_window_sat: 0,
                    total_spent_sat: 0,
                }
            }
        };
        let spent = st
            .spent_in_window_sat
            .checked_add(amount_sat)
            .ok_or(SafetyError::Malformed("spent overflow"))?;
        if spent > cap_sat {
            return Err(SafetyError::SessionLimitExceeded {
                spent,
                cap: cap_sat,
            });
        }
        let total = st
            .total_spent_sat
            .checked_add(amount_sat)
            .ok_or(SafetyError::Malformed("total overflow"))?;
        self.states.insert(
            *agent,
            SessionState {
                window_start_height: st.window_start_height,
                spent_in_window_sat: spent,
                total_spent_sat: total,
            },
        );
        Ok(())
    }
}

/// Operator risk knobs (from env/config; pure struct so tests pin behavior).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RiskPolicy {
    /// Amounts at/above this need human approval (0 = disabled).
    pub high_value_threshold_sat: u64,
    /// Most payments per payer in the node-local store (0 = disabled).
    pub max_payments_per_payer: usize,
    /// When true, `srct/mainnet` spends are refused.
    pub test_mode: bool,
}

/// Advisory verdict: `Ok`, or approval-gated. Refusals are errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskVerdict {
    Ok,
    RequireHumanApproval,
}

impl RiskPolicy {
    /// Whether `test_mode` is on (`SRCT_TEST_MODE=1`).
    pub fn test_mode_from_env() -> bool {
        std::env::var(TEST_MODE_ENV)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub fn from_env() -> Self {
        let threshold = std::env::var("SRCT_HIGH_VALUE_THRESHOLD_SAT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let velocity = std::env::var("SRCT_MAX_PAYMENTS_PER_PAYER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        RiskPolicy {
            high_value_threshold_sat: threshold,
            max_payments_per_payer: velocity,
            test_mode: Self::test_mode_from_env(),
        }
    }

    /// Gate `amount_sat` on network/velocity/value. Returns advisory approval
    /// verdict or a refusal; never mutates.
    pub fn check(
        &self,
        network_id: &str,
        amount_sat: u64,
        recent_payments_by_payer: usize,
    ) -> Result<RiskVerdict, SafetyError> {
        if self.test_mode && network_id == "srct/mainnet" {
            return Err(SafetyError::MainnetBlockedInTestMode);
        }
        if self.max_payments_per_payer > 0
            && recent_payments_by_payer >= self.max_payments_per_payer
        {
            return Err(SafetyError::VelocityLimited {
                recent: recent_payments_by_payer,
                limit: self.max_payments_per_payer,
            });
        }
        if self.high_value_threshold_sat > 0 && amount_sat >= self.high_value_threshold_sat {
            return Ok(RiskVerdict::RequireHumanApproval);
        }
        Ok(RiskVerdict::Ok)
    }
}

/// One tamper-evident audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub kind: &'static str,
    pub payment_id: Option<Hash>,
    pub amount_sat: Option<u64>,
    pub detail: String,
    pub prev_hash: Hash,
    pub hash: Hash,
}

impl AuditEntry {
    fn compute_hash(
        seq: u64,
        kind: &str,
        payment_id: &Option<Hash>,
        amount: &Option<u64>,
        detail: &str,
        prev: &Hash,
    ) -> Hash {
        let mut amt = [0u8; 8];
        if let Some(a) = amount {
            amt = a.to_le_bytes();
        }
        let mut pid = [0u8; 32];
        if let Some(p) = payment_id {
            pid = *p;
        }
        sha256_dom(
            DOM_AUDIT_ENTRY,
            &[
                &seq.to_le_bytes(),
                kind.as_bytes(),
                &pid,
                &amt,
                detail.as_bytes(),
                prev,
            ],
        )
    }
}

/// Bounded in-memory audit ring (full history stays in payment/receipt stores).
#[derive(Debug, Clone)]
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    max_entries: usize,
    next_seq: u64,
    tip: Hash,
}

impl Default for AuditLog {
    fn default() -> Self {
        AuditLog::with_capacity(DEFAULT_MAX_AUDIT_ENTRIES)
    }
}

impl AuditLog {
    pub fn with_capacity(max_entries: usize) -> Self {
        AuditLog {
            entries: VecDeque::new(),
            max_entries,
            next_seq: 0,
            tip: [0u8; 32],
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append one entry, hash-chained to the tip. Refuses when full rather
    /// than silently dropping history the operator has not exported.
    pub fn push(
        &mut self,
        kind: &'static str,
        payment_id: Option<Hash>,
        amount_sat: Option<u64>,
        detail: String,
    ) -> Result<&AuditEntry, SafetyError> {
        if detail.len() > 512 {
            return Err(SafetyError::Malformed("audit detail too long"));
        }
        if self.entries.len() >= self.max_entries {
            return Err(SafetyError::AuditFull {
                cap: self.max_entries,
            });
        }
        let seq = self.next_seq;
        let hash =
            AuditEntry::compute_hash(seq, kind, &payment_id, &amount_sat, &detail, &self.tip);
        let entry = AuditEntry {
            seq,
            kind,
            payment_id,
            amount_sat,
            detail,
            prev_hash: self.tip,
            hash,
        };
        self.tip = hash;
        self.next_seq += 1;
        self.entries.push_back(entry);
        Ok(self.entries.back().unwrap())
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, AuditEntry> {
        self.entries.iter()
    }

    /// Verify the hash chain from genesis. Refuses on the first broken link.
    pub fn verify_chain(&self) -> Result<(), SafetyError> {
        let mut prev = [0u8; 32];
        for e in &self.entries {
            if e.prev_hash != prev {
                return Err(SafetyError::Malformed("audit chain link"));
            }
            let recomputed = AuditEntry::compute_hash(
                e.seq,
                e.kind,
                &e.payment_id,
                &e.amount_sat,
                &e.detail,
                &prev,
            );
            if recomputed != e.hash {
                return Err(SafetyError::Malformed("audit entry hash"));
            }
            prev = e.hash;
        }
        Ok(())
    }
}

/// One audit entry in exportable form: hex strings and owned data, so an
/// auditor or insurer can read and re-verify the chain without the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportEntry {
    pub seq: u64,
    pub kind: String,
    pub payment_id: Option<String>,
    pub amount_sat: Option<u64>,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

/// The whole export: the entries in order plus the tip, so the reader knows
/// what "complete" means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExport {
    pub entries: Vec<AuditExportEntry>,
    pub tip: String,
}

impl AuditLog {
    /// Export the in-memory ring as auditor-readable JSON. The entries carry
    /// their hashes, so the reader re-verifies rather than trusts.
    pub fn export(&self) -> AuditExport {
        AuditExport {
            entries: self
                .entries
                .iter()
                .map(|e| AuditExportEntry {
                    seq: e.seq,
                    kind: e.kind.to_string(),
                    payment_id: e.payment_id.map(|h| hash_to_hex(&h)),
                    amount_sat: e.amount_sat,
                    detail: e.detail.clone(),
                    prev_hash: hash_to_hex(&e.prev_hash),
                    hash: hash_to_hex(&e.hash),
                })
                .collect(),
            tip: hash_to_hex(&self.tip),
        }
    }

    /// Serialize what [`AuditLog::export`] produced.
    pub fn export_json(&self) -> String {
        serde_json::to_string(&self.export()).unwrap_or_else(|_| "{}".to_string())
    }

    /// Verify an export: chain links, entry hashes, ordering from genesis, and
    /// the tip. Returns the entry count. Refuses the first broken link by name
    /// — an auditor must never have to guess which entry failed.
    pub fn verify_export(export: &AuditExport) -> Result<usize, SafetyError> {
        let genesis = [0u8; 32];
        let mut prev = genesis;
        for (i, e) in export.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(SafetyError::Malformed("audit export out of order"));
            }
            if e.detail.len() > 512 {
                return Err(SafetyError::Malformed("audit detail too long"));
            }
            let prev_hash =
                hash_from_hex(e.prev_hash.trim()).map_err(|_| SafetyError::Malformed("prev hash"))?;
            let hash =
                hash_from_hex(e.hash.trim()).map_err(|_| SafetyError::Malformed("entry hash"))?;
            if prev_hash != prev {
                return Err(SafetyError::Malformed("audit chain link"));
            }
            let payment_id = match &e.payment_id {
                None => None,
                Some(s) => Some(
                    hash_from_hex(s.trim()).map_err(|_| SafetyError::Malformed("payment id"))?,
                ),
            };
            let recomputed = AuditEntry::compute_hash(
                e.seq,
                &e.kind,
                &payment_id,
                &e.amount_sat,
                &e.detail,
                &prev,
            );
            if recomputed != hash {
                return Err(SafetyError::Malformed("audit entry hash"));
            }
            prev = hash;
        }
        let tip = hash_from_hex(export.tip.trim()).map_err(|_| SafetyError::Malformed("tip"))?;
        if tip != prev {
            return Err(SafetyError::Malformed("audit tip mismatch"));
        }
        Ok(export.entries.len())
    }

    /// Parse and verify export JSON in one step.
    pub fn verify_export_json(raw: &str) -> Result<usize, SafetyError> {
        if raw.len() > 256 * 1024 {
            return Err(SafetyError::Malformed("audit export over cap"));
        }
        let export: AuditExport =
            serde_json::from_str(raw).map_err(|_| SafetyError::Malformed("audit export json"))?;
        Self::verify_export(&export)
    }
}

/// Reconciliation views over node-local books.
pub mod reconcile {
    use super::Hash;
    use std::collections::{BTreeMap, BTreeSet};

    /// Payments recorded but not yet bound to a settlement tx and not expired:
    /// retry these (idempotently) instead of building duplicates.
    pub fn unsettled(
        recorded: &BTreeMap<Hash, (u64, u64)>,
        settled: &BTreeSet<Hash>,
        height: u64,
    ) -> Vec<Hash> {
        recorded
            .iter()
            .filter(|item| !settled.contains(item.0) && height < item.1 .1)
            .map(|item| *item.0)
            .collect()
    }

    /// Receipts that claim a payment this node never recorded: investigate,
    /// never auto-settle.
    pub fn orphan_receipts(
        receipts: &BTreeMap<Hash, Hash>,
        recorded_payments: &BTreeSet<Hash>,
    ) -> Vec<(Hash, Hash)> {
        receipts
            .iter()
            .filter(|(_, payment)| !recorded_payments.contains(*payment))
            .map(|(receipt, payment)| (*receipt, *payment))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_budget_aggregates_across_policies() {
        let mut book = SessionBook::default();
        let agent = [3u8; 20];
        book.record(&agent, 100, 400, 10, 1_000).unwrap();
        // Second policy, same agent: still counts.
        book.record(&agent, 101, 400, 10, 1_000).unwrap();
        assert_eq!(
            book.record(&agent, 102, 300, 10, 1_000),
            Err(SafetyError::SessionLimitExceeded {
                spent: 1_100,
                cap: 1_000
            })
        );
        // Window rolls forward.
        book.record(&agent, 200, 300, 10, 1_000).unwrap();
        assert_eq!(book.state(&agent).unwrap().spent_in_window_sat, 300);
    }

    #[test]
    fn risk_policy_gates_value_velocity_and_test_mode() {
        let policy = RiskPolicy {
            high_value_threshold_sat: 10_000,
            max_payments_per_payer: 2,
            test_mode: true,
        };
        assert_eq!(policy.check("srct/mini", 100, 0).unwrap(), RiskVerdict::Ok);
        assert_eq!(
            policy.check("srct/mini", 10_000, 0).unwrap(),
            RiskVerdict::RequireHumanApproval
        );
        assert_eq!(
            policy.check("srct/mini", 100, 2),
            Err(SafetyError::VelocityLimited {
                recent: 2,
                limit: 2
            })
        );
        assert_eq!(
            policy.check("srct/mainnet", 100, 0),
            Err(SafetyError::MainnetBlockedInTestMode)
        );
    }

    #[test]
    fn audit_log_chains_and_verifies() {
        let mut log = AuditLog::with_capacity(4);
        log.push("authorize", None, Some(500), "grant".to_string())
            .unwrap();
        log.push("payment", Some([1u8; 32]), Some(500), "submit".to_string())
            .unwrap();
        log.verify_chain().unwrap();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn audit_export_round_trips_and_tampering_is_refused() {
        let mut log = AuditLog::with_capacity(4);
        log.push("authorize", None, Some(500), "grant".to_string())
            .unwrap();
        log.push("payment", Some([1u8; 32]), Some(500), "submit".to_string())
            .unwrap();
        let json = log.export_json();
        assert_eq!(AuditLog::verify_export_json(&json).unwrap(), 2);
        let mut export = log.export();
        // Rewriting history breaks the entry hash, not just the link.
        export.entries[0].detail = "forged".to_string();
        assert!(AuditLog::verify_export(&export).is_err());
        // Truncating the tip is a different refusal, not silent acceptance.
        let mut short = log.export();
        short.tip = hash_to_hex(&[0u8; 32]);
        assert!(AuditLog::verify_export(&short).is_err());
    }

    #[test]
    fn reconcile_finds_in_flight_and_orphans() {
        use std::collections::{BTreeMap, BTreeSet};
        let mut recorded = BTreeMap::new();
        recorded.insert([1u8; 32], (100u64, 9_000u64));
        recorded.insert([2u8; 32], (200u64, 9_000u64));
        let settled: BTreeSet<Hash> = [[1u8; 32]].into_iter().collect();
        let in_flight = reconcile::unsettled(&recorded, &settled, 300);
        assert_eq!(in_flight, vec![[2u8; 32]]);
        let mut receipts = BTreeMap::new();
        receipts.insert([9u8; 32], [2u8; 32]);
        receipts.insert([8u8; 32], [7u8; 32]);
        let known: BTreeSet<Hash> = [[1u8; 32], [2u8; 32]].into_iter().collect();
        let orphans = reconcile::orphan_receipts(&receipts, &known);
        assert_eq!(orphans, vec![([8u8; 32], [7u8; 32])]);
    }
}
