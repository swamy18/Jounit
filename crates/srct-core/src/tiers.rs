//! Tiered agent wallets: max-spend and min-spend sub-wallets.
//!
//! A user funds one agent (say 500 SRCT) but wants different spend powers in
//! different contexts: a max-spend wallet for trusted services (up to 20 SRCT
//! per transaction) and a min-spend wallet for experiments (up to 1 SRCT).
//! Tiers are exactly that: child [`SpendPolicy`]s narrowed from the parent by
//! [`delegation::dominates`], so a tier can never exceed its parent —
//! per-transaction cap, window, cumulative cap, recipients, services and
//! validity are all subsets of the parent's.
//!
//! - **Temporary spending keys**: a tier carries a short `expires_at_height`;
//!   expiry is enforced by the policy engine, no revocation round-trip needed.
//! - **Emergency revocation**: revoke the parent and every descendant is
//!   disabled at payment submission (`revoked_policies` covers the chain),
//!   so one transaction stops the whole tree.
//!
//! The node never builds tiers (it never holds keys): `POST /v1/wallet/tier`
//! only validates a signed tier against its parent and registers the lineage.

use crate::agent::{derive_sub_agent_id, SpendPolicy, POLICY_VERSION};
use crate::delegation::dominates;
use crate::wallet::Wallet;

/// A tier request: the narrowed powers for one sub-wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierSpec {
    pub network_id: String,
    pub label: String,
    pub per_tx_max_sat: u64,
    pub window_blocks: u64,
    pub cumulative_max_sat: u64,
    pub allowed_recipients: Vec<crate::hash::Address>,
    pub allowed_services: Vec<[u8; 32]>,
    pub not_before_height: u64,
    pub expires_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierError {
    Malformed(&'static str),
    NotNarrowed(&'static str),
}

impl std::fmt::Display for TierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TierError::Malformed(w) => write!(f, "malformed tier: {w}"),
            TierError::NotNarrowed(w) => write!(f, "tier exceeds parent: {w}"),
        }
    }
}

impl std::error::Error for TierError {}

/// Build a tier child policy from a signed parent. The owner's wallet signs
/// the child (via `sign_tier`); this constructor only assembles the bytes —
/// the caller signs and the node validates.
pub fn build_tier(parent: &SpendPolicy, spec: &TierSpec) -> Result<SpendPolicy, TierError> {
    if spec.network_id != parent.network_id {
        return Err(TierError::Malformed("tier network must match parent"));
    }
    if spec.label.is_empty() || spec.label.len() > 64 {
        return Err(TierError::Malformed("tier label"));
    }
    if spec.per_tx_max_sat == 0 || spec.cumulative_max_sat == 0 || spec.window_blocks == 0 {
        return Err(TierError::Malformed("tier caps"));
    }
    if spec.expires_at_height <= spec.not_before_height {
        return Err(TierError::Malformed("tier window"));
    }
    let agent_id = derive_sub_agent_id(&spec.network_id, &parent.agent_id, parent.role);
    let child = SpendPolicy {
        version: POLICY_VERSION,
        network_id: spec.network_id.clone(),
        agent_id,
        owner: parent.owner,
        role: parent.role,
        per_tx_max_sat: spec.per_tx_max_sat,
        window_blocks: spec.window_blocks,
        cumulative_max_sat: spec.cumulative_max_sat,
        allowed_recipients: spec.allowed_recipients.clone(),
        allowed_services: spec.allowed_services.clone(),
        not_before_height: spec.not_before_height.max(parent.not_before_height),
        expires_at_height: spec.expires_at_height.min(parent.expires_at_height),
        revoked: false,
        parent_agent_id: Some(parent.agent_id),
    };
    if dominates(parent, &child).is_err() {
        return Err(TierError::NotNarrowed("child must narrow the parent"));
    }
    Ok(child)
}

/// Standard two-tier split: a max-spend tier under the parent and a min-spend
/// tier under the max tier. Tiers nest because delegation names exactly one
/// child per (parent, role): the min tier narrows the max tier, which narrows
/// the parent, so revoking the parent still stops the whole tree. Amounts are
/// the caller's choice; this only enforces the ordering (min <= max) and the
/// narrowing at each link.
pub fn build_tier_pair(
    parent: &SpendPolicy,
    max: &TierSpec,
    min: &TierSpec,
) -> Result<(SpendPolicy, SpendPolicy), TierError> {
    if min.per_tx_max_sat > max.per_tx_max_sat {
        return Err(TierError::Malformed("min tier exceeds max tier"));
    }
    let max_policy = build_tier(parent, max)?;
    let min_policy = build_tier(&max_policy, min)?;
    Ok((max_policy, min_policy))
}

/// Whether `child` is a valid tier of `parent` (dominance + same owner +
/// same network + child linked to the parent agent id).
pub fn is_valid_tier(parent: &SpendPolicy, child: &SpendPolicy) -> bool {
    child.parent_agent_id == Some(parent.agent_id)
        && child.owner == parent.owner
        && child.network_id == parent.network_id
        && child.role == parent.role
        && dominates(parent, child).is_ok()
}

/// Sign a tier policy with the owner's wallet (same shape as policies).
pub fn sign_tier(
    owner: &Wallet,
    tier: &SpendPolicy,
) -> Result<(crate::sig::Bundle, crate::sig::Bundle), TierError> {
    use crate::l2::Auth;
    let keys = Auth::keys_for(owner).map_err(|_| TierError::Malformed("owner keys"))?;
    let sigs = Auth::sigs_for(owner, &tier.signing_hash())
        .map_err(|_| TierError::Malformed("owner sign"))?;
    Ok((sigs, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{derive_agent_id, AgentRole};

    fn parent() -> SpendPolicy {
        let owner = [9u8; 20];
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: "srct/testnet".to_string(),
            agent_id: derive_agent_id("srct/testnet", AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 20,
            window_blocks: 100,
            cumulative_max_sat: 500,
            allowed_recipients: vec![[1u8; 20], [2u8; 20]],
            allowed_services: vec![[3u8; 32]],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    fn spec(label: &str, per_tx: u64, expiry: u64) -> TierSpec {
        TierSpec {
            network_id: "srct/testnet".to_string(),
            label: label.to_string(),
            per_tx_max_sat: per_tx,
            window_blocks: 100,
            cumulative_max_sat: 500,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![[3u8; 32]],
            not_before_height: 0,
            expires_at_height: expiry,
        }
    }

    #[test]
    fn max_and_min_tiers_nest_and_narrow() {
        let p = parent();
        let (max, min) = build_tier_pair(&p, &spec("max-spend", 20, 5_000), &spec("min-spend", 1, 500)).unwrap();
        assert!(is_valid_tier(&p, &max));
        // The min tier hangs under max (one child identity per parent), so it
        // must validate against max, not the root.
        assert!(is_valid_tier(&max, &min));
        assert!(!is_valid_tier(&p, &min));
        assert_eq!(min.expires_at_height, 500); // temporary key by construction
        // A tier that widens the parent is refused.
        let mut wide = spec("wide", 1, 500);
        wide.allowed_recipients = vec![[9u8; 20]];
        assert!(build_tier(&p, &wide).is_err());
    }
}
