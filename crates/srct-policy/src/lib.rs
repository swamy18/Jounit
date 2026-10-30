//! Chain-agnostic agent policy engine.
//!
//! The policy layer (`agent`, `delegation`, `safety`, `tiers`, `x402` guard,
//! portable envelopes) is pure: no chain state, no clock, no I/O. This crate
//! is its cross-chain face — it depends on `srct-core` only for those pure
//! modules and re-exports the portable surface every rail speaks:
//!
//! - input: a [`PaymentIntent`] (who pays whom how much, where, when);
//! - output: a [`PolicyDecision`] — allow, deny, or approval-needed;
//! - travel: [`SignedPolicy`] (the grant any chain verifies), [`DelegationProof`]
//!   (the verifiable tree), [`BoundAuthorization`] (the short-lived,
//!   exact-transaction grant), and the hash-chained [`AuditExport`].
//!
//! Nothing here imports consensus (`chain`, `ledger`, `l2` state, mempool): a
//! foreign rail vendors this crate (or its TypeScript/Python bindings, which
//! speak the same JSON) and gets the same decisions the node gets.
//!
//! [`PaymentIntent`]: portable::PaymentIntent
//! [`PolicyDecision`]: portable::PolicyDecision
//! [`SignedPolicy`]: portable::SignedPolicy
//! [`DelegationProof`]: portable::DelegationProof
//! [`BoundAuthorization`]: portable::BoundAuthorization
//! [`AuditExport`]: safety::AuditExport

pub use srct_core::portable::{
    evaluate_policy, BoundAuthorization, DecodedIntent, DelegationProof, PaymentIntent,
    PolicyDecision, SignedPolicy, MAX_BOUND_LIFETIME_BLOCKS, MAX_PORTABLE_JSON_LEN,
    PORTABLE_POLICY_VERSION,
};
pub use srct_core::safety::{AuditExport, AuditExportEntry, AuditLog};
pub use srct_core::x402::{GuardGrant, X402Budget, MAX_GUARD_LIFETIME_BLOCKS};

/// Decide from JSON: parse a portable policy, parse a payment intent, and
/// answer allow / deny / approval-needed as [`PolicyDecision`] JSON.
///
/// Both inputs are verified on parse (`SignedPolicy::from_json` refuses an
/// unverified grant), so a caller holding hostile bytes gets an `Err`, never
/// a forged allow. Stateful clauses (nonce freshness, tumbling-window spend)
/// are not committed here — this is the pre-check; `PolicyBook::authorize` on
/// the settling rail commits.
pub fn decide(
    policy_portable_json: &str,
    intent_json: &str,
    approval_threshold_sat: Option<u64>,
) -> Result<String, String> {
    let signed = SignedPolicy::from_json(policy_portable_json).map_err(|e| e.to_string())?;
    let intent: PaymentIntent =
        serde_json::from_str(intent_json).map_err(|_| "malformed intent json".to_string())?;
    if signed.policy.network_id != intent.network_id {
        return Err(format!(
            "policy is for network {}, intent for {}",
            signed.policy.network_id, intent.network_id
        ));
    }
    let decoded = intent.decoded().map_err(|e| e.to_string())?;
    let decision = evaluate_policy(&signed.policy, &decoded, intent.height, approval_threshold_sat);
    serde_json::to_string(&decision).map_err(|_| "decision json".to_string())
}

/// Verify a delegation proof from JSON. Returns `leaf_agent/leaf_policy_hash`
/// on success so the caller can route without re-parsing.
pub fn verify_proof(proof_json: &str) -> Result<String, String> {
    let proof = DelegationProof::from_json(proof_json).map_err(|e| e.to_string())?;
    Ok(format!(
        "{}/{}",
        hex::encode(proof.leaf().agent_id),
        srct_core::hash::hash_to_hex(&proof.leaf().hash())
    ))
}

/// Verify an exported audit chain from JSON. Returns the entry count.
pub fn verify_audit(audit_json: &str) -> Result<usize, String> {
    AuditLog::verify_export_json(audit_json).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_json_answers_allow_and_deny() {
        use srct_core::agent::{derive_agent_id, AgentRole, POLICY_VERSION};
        use srct_core::agent::SpendPolicy;
        use srct_core::l2::Auth;
        use srct_core::wallet::Wallet;

        let network = "srct/testnet";
        let wallet = Wallet::new_random("owner");
        let owner = wallet.address().unwrap();
        let policy = SpendPolicy {
            version: POLICY_VERSION,
            network_id: network.to_string(),
            agent_id: derive_agent_id(network, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 1_000,
            window_blocks: 100,
            cumulative_max_sat: 5_000,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        };
        let keys = Auth::keys_for(&wallet).unwrap();
        let sigs = Auth::sigs_for(&wallet, &policy.signing_hash()).unwrap();
        let signed = SignedPolicy {
            policy,
            sigs,
            keys,
        };
        let policy_json = signed.to_json();
        let intent = PaymentIntent {
            agent_id: hex::encode(signed.policy.agent_id),
            recipient: srct_core::hash::address_to_hex(&[1u8; 20]),
            amount_sat: 500,
            service: None,
            height: 100,
            nonce: 1,
            network_id: network.to_string(),
        };
        let out = decide(&policy_json, &serde_json::to_string(&intent).unwrap(), None).unwrap();
        let decision: PolicyDecision = serde_json::from_str(&out).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);

        let intent = PaymentIntent {
            recipient: srct_core::hash::address_to_hex(&[9u8; 20]),
            ..intent
        };
        let out = decide(&policy_json, &serde_json::to_string(&intent).unwrap(), None).unwrap();
        let decision: PolicyDecision = serde_json::from_str(&out).unwrap();
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }
}
