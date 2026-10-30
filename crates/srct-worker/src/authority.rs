//! Agent authority and credit from the worker SDK (SPEC.md §21, §22).
//!
//! Two flows an agent needs and that no other SDK path covered:
//!
//! - **Authority.** The owner publishes a grant once, and the agent spends
//!   under it as many times as the grant allows. The owner signs the
//!   publication; the agent signs the spends. Neither needs the other online.
//! - **Credit.** One agent lends to another: the lender signs the terms, the
//!   principal moves to the borrower, and the borrower repays (or the
//!   collateral answers for it).
//!
//! Both follow the SDK's shape: plan locally, then broadcast. The plan is
//! built against an observed state so a caller learns *now* that a balance or
//! a grant will not cover the transaction - but the chain is the authority, so
//! the SDK never re-implements a cap rule. Where a check is done here it is
//! the check the chain would refuse first, and it is named as such.

use srct_core::agent::{AgentId, SpendPolicy};
use srct_core::hash::{Address, Hash, Hash512};
use srct_core::l2::{
    AgentSpendPayload, CreditCollateralPayload, CreditDefaultPayload, CreditOpenPayload,
    CreditRepayPayload, L2Payload, L2Transaction, PolicyPayload, PolicyRevokePayload,
};
use srct_core::wallet::Wallet;
use srct_l2::L2State;

use crate::error::{WorkerError, WorkerResult};
use crate::node::{Host, L2Broadcaster, L2NodeView};

/// A published grant, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    /// The transaction the node must carry for the grant to take effect.
    pub tx: L2Transaction,
    /// The grant's hash: the handle every later spend names.
    pub policy_hash: Hash,
    /// The owner who signed it.
    pub owner: Address,
    /// The agent identity the grant names.
    pub agent_id: AgentId,
    /// The key that may exercise the grant.
    pub spender: Address,
    /// The fee the publication costs.
    pub fee_sat: u64,
    /// Transaction id, for reconciling a broadcast whose outcome is unknown.
    pub txid: Hash512,
}

/// A spend under a published grant, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpendPlan {
    pub tx: L2Transaction,
    pub policy_hash: Hash,
    pub agent: Address,
    pub recipient: Address,
    pub amount_sat: u64,
    pub nonce: u64,
    pub fee_sat: u64,
    pub txid: Hash512,
}

/// A credit position opening, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditOpenPlan {
    pub tx: L2Transaction,
    pub position_id: Hash,
    pub lender: Address,
    pub borrower: Address,
    pub amount_sat: u64,
    pub collateral_sat: u64,
    pub fee_sat: u64,
    pub txid: Hash512,
}

/// A credit repayment, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditRepayPlan {
    pub tx: L2Transaction,
    pub position_id: Hash,
    pub borrower: Address,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub txid: Hash512,
}

/// Additional collateral for a credit position, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditCollateralPlan {
    pub tx: L2Transaction,
    pub position_id: Hash,
    pub borrower: Address,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub txid: Hash512,
}

/// A credit default, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditDefaultPlan {
    pub tx: L2Transaction,
    pub position_id: Hash,
    pub actor: Address,
    pub fee_sat: u64,
    pub txid: Hash512,
}

/// Build the publication of a grant without broadcasting it.
///
/// The owner signs. The pre-check is only the fee: the grant's own rules are
/// the chain's to enforce, and the owner is the one who decides them.
pub fn publish_policy_plan(
    wallet: &Wallet,
    policy: &SpendPolicy,
    spender: Address,
    state: &L2State,
) -> WorkerResult<PolicyPlan> {
    let owner = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let fee_sat = srct_core::l2::L2TxType::Policy.fee_sat();
    let have = state.balance(&owner);
    if have < fee_sat {
        return Err(WorkerError::InsufficientBalance {
            needed: fee_sat,
            available: have,
        });
    }
    // Build failures carry their own L2 reason (bad policy, bad binding):
    // collapsing them into `IdentityMismatch` lied about the cause and made
    // deterministic refusals look retryable-adjacent. `From` surfaces them
    // as `Protocol` (non-retryable), which is what a refused build is.
    let payload = PolicyPayload::build_from_policy(wallet, policy, spender)?;
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    Ok(PolicyPlan {
        txid: tx.txid(),
        policy_hash: policy.hash(),
        owner,
        agent_id: policy.agent_id,
        spender,
        fee_sat,
        tx,
    })
}

/// Publish a grant and broadcast it.
pub fn publish_policy<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    policy: &SpendPolicy,
    spender: Address,
) -> WorkerResult<PolicyPlan> {
    let plan = publish_policy_plan(wallet, policy, spender, &host.l2_state()?)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build the revocation of a grant without broadcasting it.
pub fn revoke_policy_plan(
    wallet: &Wallet,
    agent_id: AgentId,
    state: &L2State,
) -> WorkerResult<PolicyPlan> {
    let owner = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let fee_sat = srct_core::l2::L2TxType::PolicyRevoke.fee_sat();
    let have = state.balance(&owner);
    if have < fee_sat {
        return Err(WorkerError::InsufficientBalance {
            needed: fee_sat,
            available: have,
        });
    }
    let payload = PolicyRevokePayload::build(wallet, agent_id)?;
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    Ok(PolicyPlan {
        txid: tx.txid(),
        policy_hash: Hash::from([0u8; 32]),
        owner,
        agent_id,
        spender: owner,
        fee_sat,
        tx,
    })
}

/// Revoke a grant and broadcast it.
pub fn revoke_policy<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    agent_id: AgentId,
) -> WorkerResult<PolicyPlan> {
    let plan = revoke_policy_plan(wallet, agent_id, &host.l2_state()?)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build a spend under a published grant without broadcasting it.
///
/// The spender signs. Two pre-checks, both of which the chain would refuse
/// first: the grant must be published, and the grant must name this key. The
/// caps are the chain's business — the SDK does not re-implement them, and a
/// spend that breaches one is refused by the state machine, not here.
pub fn agent_spend_plan(
    wallet: &Wallet,
    policy_hash: Hash,
    nonce: u64,
    recipient: Address,
    amount_sat: u64,
    service: Option<[u8; 32]>,
    state: &L2State,
) -> WorkerResult<AgentSpendPlan> {
    let agent = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let entry = state
        .policy(&policy_hash)
        .ok_or(WorkerError::TaskNotAvailable(
            "no published policy with that hash",
        ))?;
    if entry.spender != agent {
        return Err(WorkerError::IdentityMismatch);
    }
    if entry.revoked {
        return Err(WorkerError::TaskNotAvailable("the policy is revoked"));
    }
    let payload =
        AgentSpendPayload::build(wallet, policy_hash, nonce, recipient, amount_sat, service)?;
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    Ok(AgentSpendPlan {
        txid: tx.txid(),
        policy_hash,
        agent,
        recipient,
        amount_sat,
        nonce,
        fee_sat: srct_core::l2::L2TxType::AgentSpend.fee_sat(),
        tx,
    })
}

/// Spend under a published grant and broadcast it.
pub fn agent_spend<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    policy_hash: Hash,
    nonce: u64,
    recipient: Address,
    amount_sat: u64,
    service: Option<[u8; 32]>,
) -> WorkerResult<AgentSpendPlan> {
    let plan = agent_spend_plan(
        wallet,
        policy_hash,
        nonce,
        recipient,
        amount_sat,
        service,
        &host.l2_state()?,
    )?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build the opening of a credit position without broadcasting it.
///
/// The lender signs. The pre-checks are the balances the chain would refuse
/// first: the lender funds the principal and the fee, and the borrower holds
/// the collateral in its own balance.
#[allow(clippy::too_many_arguments)]
pub fn open_credit_plan(
    wallet: &Wallet,
    borrower: Address,
    amount_sat: u64,
    collateral_sat: u64,
    rate_bps_per_window: u32,
    window_blocks: u64,
    deadline_height: u64,
    nonce: u64,
    state: &L2State,
) -> WorkerResult<CreditOpenPlan> {
    let lender = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let fee_sat = srct_core::l2::L2TxType::CreditOpen.fee_sat();
    let needed = amount_sat
        .checked_add(fee_sat)
        .ok_or(WorkerError::Protocol(srct_l2::L2Error::Overflow))?;
    let have = state.balance(&lender);
    if have < needed {
        return Err(WorkerError::InsufficientBalance {
            needed,
            available: have,
        });
    }
    let collateral_have = state.balance(&borrower);
    if collateral_have < collateral_sat {
        return Err(WorkerError::InsufficientBalance {
            needed: collateral_sat,
            available: collateral_have,
        });
    }
    let payload = CreditOpenPayload::build(
        wallet,
        borrower,
        amount_sat,
        collateral_sat,
        rate_bps_per_window,
        window_blocks,
        deadline_height,
        nonce,
    )?;
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload.clone()));
    Ok(CreditOpenPlan {
        txid: tx.txid(),
        position_id: payload.derived_position_id(),
        lender,
        borrower,
        amount_sat,
        collateral_sat,
        fee_sat,
        tx,
    })
}

/// Open a credit position and broadcast it.
#[allow(clippy::too_many_arguments)]
pub fn open_credit<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    borrower: Address,
    amount_sat: u64,
    collateral_sat: u64,
    rate_bps_per_window: u32,
    window_blocks: u64,
    deadline_height: u64,
    nonce: u64,
) -> WorkerResult<CreditOpenPlan> {
    let plan = open_credit_plan(
        wallet,
        borrower,
        amount_sat,
        collateral_sat,
        rate_bps_per_window,
        window_blocks,
        deadline_height,
        nonce,
        &host.l2_state()?,
    )?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build a repayment against a credit position without broadcasting it.
pub fn repay_credit_plan(
    wallet: &Wallet,
    position_id: Hash,
    amount_sat: u64,
    state: &L2State,
) -> WorkerResult<CreditRepayPlan> {
    let borrower = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let position = state
        .credit_position(&position_id)
        .ok_or(WorkerError::TaskNotAvailable("no such credit position"))?;
    if position.borrower != borrower {
        return Err(WorkerError::IdentityMismatch);
    }
    let fee_sat = srct_core::l2::L2TxType::CreditRepay.fee_sat();
    let needed = amount_sat
        .checked_add(fee_sat)
        .ok_or(WorkerError::Protocol(srct_l2::L2Error::Overflow))?;
    let have = state.balance(&borrower);
    if have < needed {
        return Err(WorkerError::InsufficientBalance {
            needed,
            available: have,
        });
    }
    let payload = CreditRepayPayload::build(wallet, position_id, amount_sat)?;
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    Ok(CreditRepayPlan {
        txid: tx.txid(),
        position_id,
        borrower,
        amount_sat,
        fee_sat,
        tx,
    })
}

/// Repay a credit position and broadcast it.
pub fn repay_credit<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    position_id: Hash,
    amount_sat: u64,
) -> WorkerResult<CreditRepayPlan> {
    let plan = repay_credit_plan(wallet, position_id, amount_sat, &host.l2_state()?)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build the addition of collateral to a credit position, without broadcasting.
pub fn add_credit_collateral_plan(
    wallet: &Wallet,
    position_id: Hash,
    amount_sat: u64,
    state: &L2State,
) -> WorkerResult<CreditCollateralPlan> {
    let borrower = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let position = state
        .credit_position(&position_id)
        .ok_or(WorkerError::TaskNotAvailable("no such credit position"))?;
    if position.borrower != borrower {
        return Err(WorkerError::IdentityMismatch);
    }
    let fee_sat = srct_core::l2::L2TxType::CreditCollateral.fee_sat();
    let needed = amount_sat
        .checked_add(fee_sat)
        .ok_or(WorkerError::Protocol(srct_l2::L2Error::Overflow))?;
    let have = state.balance(&borrower);
    if have < needed {
        return Err(WorkerError::InsufficientBalance {
            needed,
            available: have,
        });
    }
    let payload = CreditCollateralPayload::build(wallet, position_id, amount_sat)?;
    let tx = L2Transaction::new(L2Payload::CreditCollateral(payload));
    Ok(CreditCollateralPlan {
        txid: tx.txid(),
        position_id,
        borrower,
        amount_sat,
        fee_sat,
        tx,
    })
}

/// Add collateral to a credit position and broadcast it.
pub fn add_credit_collateral<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    position_id: Hash,
    amount_sat: u64,
) -> WorkerResult<CreditCollateralPlan> {
    let plan = add_credit_collateral_plan(wallet, position_id, amount_sat, &host.l2_state()?)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}

/// Build the settlement of an overdue credit position without broadcasting it.
///
/// Permissionless: anyone may trigger it, because a default only the lender
/// could trigger is a default that could be delayed.
pub fn default_credit_plan(
    wallet: &Wallet,
    position_id: Hash,
    state: &L2State,
    height: u64,
) -> WorkerResult<CreditDefaultPlan> {
    let actor = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    let position = state
        .credit_position(&position_id)
        .ok_or(WorkerError::TaskNotAvailable("no such credit position"))?;
    if height < position.deadline_height {
        return Err(WorkerError::TaskNotAvailable("the position is not yet due"));
    }
    let fee_sat = srct_core::l2::L2TxType::CreditDefault.fee_sat();
    let have = state.balance(&actor);
    if have < fee_sat {
        return Err(WorkerError::InsufficientBalance {
            needed: fee_sat,
            available: have,
        });
    }
    let payload = CreditDefaultPayload::build(wallet, position_id)?;
    let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
    Ok(CreditDefaultPlan {
        txid: tx.txid(),
        position_id,
        actor,
        fee_sat,
        tx,
    })
}

/// Settle an overdue credit position and broadcast it.
pub fn default_credit<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    position_id: Hash,
) -> WorkerResult<CreditDefaultPlan> {
    let (state, height) = host.observe()?;
    let plan = default_credit_plan(wallet, position_id, &state, height)?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}
