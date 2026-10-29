//! Agent authority and credit through the worker SDK (SPEC.md §21, §22).
//!
//! The flows an agent actually needs: an owner publishes a grant, the agent
//! spends under it, the owner revokes it, and an agent lends to another agent
//! and is repaid. Every broadcast goes through the SDK's seams, so what is
//! tested here is the path a real agent takes.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::{addr, wallet, Core, TestNet, TestView};
use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::hash::Address;
use srct_worker::node::Host;
use srct_worker::{
    agent_spend, open_credit, publish_policy, repay_credit, revoke_policy, WorkerError,
};

const CREDITED: u64 = 100_000_000;

fn grant(
    owner: Address,
    role: AgentRole,
    agent_id: srct_core::agent::AgentId,
    recipients: Vec<Address>,
) -> SpendPolicy {
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/mini".to_string(),
        agent_id,
        owner,
        role,
        per_tx_max_sat: 10_000,
        window_blocks: 100,
        cumulative_max_sat: 100_000,
        allowed_recipients: recipients,
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: None,
    }
}

#[test]
fn an_owner_publishes_a_grant_and_the_agent_spends_under_it() {
    let core = Rc::new(RefCell::new(Core::new(CREDITED)));
    let mut host = Host::new(TestView::new(&core), TestNet::new(&core));
    let owner = wallet(1);
    let agent = wallet(2);
    let recipient = wallet(3);

    let agent_id = derive_agent_id("srct/mini", AgentRole::Machine, &addr(&owner));
    let policy = grant(
        addr(&owner),
        AgentRole::Machine,
        agent_id,
        vec![addr(&recipient)],
    );

    // The owner publishes; the grant's hash is the handle.
    let plan = publish_policy(&mut host, &owner, &policy, addr(&agent)).expect("published");
    assert_eq!(plan.owner, addr(&owner));
    assert_eq!(plan.spender, addr(&agent));
    assert_eq!(plan.policy_hash, policy.hash());

    // The agent spends under it.
    let spend = agent_spend(
        &mut host,
        &agent,
        plan.policy_hash,
        1,
        addr(&recipient),
        5_000,
        None,
    )
    .expect("the spend is inside every cap");
    assert_eq!(spend.amount_sat, 5_000);

    // And the state agrees: the grant is published, the counters moved.
    let state = core.borrow().state.clone();
    let entry = state
        .policy(&plan.policy_hash)
        .expect("the grant is in the state");
    assert_eq!(entry.spends, 1);
    assert_eq!(entry.total_spent_sat, 5_000);
    assert_eq!(entry.last_nonce, 1);
}

#[test]
fn a_revoked_grant_stops_being_usable() {
    let core = Rc::new(RefCell::new(Core::new(CREDITED)));
    let mut host = Host::new(TestView::new(&core), TestNet::new(&core));
    let owner = wallet(1);
    let agent = wallet(2);
    let recipient = wallet(3);

    let agent_id = derive_agent_id("srct/mini", AgentRole::Machine, &addr(&owner));
    let policy = grant(
        addr(&owner),
        AgentRole::Machine,
        agent_id,
        vec![addr(&recipient)],
    );
    let plan = publish_policy(&mut host, &owner, &policy, addr(&agent)).expect("published");

    revoke_policy(&mut host, &owner, agent_id).expect("the owner may revoke");

    // The SDK refuses locally, before spending a fee on a doomed transaction.
    let err = agent_spend(
        &mut host,
        &agent,
        plan.policy_hash,
        1,
        addr(&recipient),
        1_000,
        None,
    )
    .expect_err("a revoked grant is not usable");
    assert!(
        matches!(err, WorkerError::TaskNotAvailable(_)),
        "refused by name, got {err:?}"
    );
}

#[test]
fn a_spend_under_a_grant_the_signer_does_not_hold_is_refused() {
    let core = Rc::new(RefCell::new(Core::new(CREDITED)));
    let mut host = Host::new(TestView::new(&core), TestNet::new(&core));
    let owner = wallet(1);
    let agent = wallet(2);
    let stranger = wallet(3);

    let agent_id = derive_agent_id("srct/mini", AgentRole::Machine, &addr(&owner));
    let policy = grant(
        addr(&owner),
        AgentRole::Machine,
        agent_id,
        vec![addr(&stranger)],
    );
    let plan = publish_policy(&mut host, &owner, &policy, addr(&agent)).expect("published");

    let err = agent_spend(
        &mut host,
        &stranger,
        plan.policy_hash,
        1,
        addr(&stranger),
        1_000,
        None,
    )
    .expect_err("only the named spender may spend");
    assert!(
        matches!(err, WorkerError::IdentityMismatch),
        "refused by name, got {err:?}"
    );
}

#[test]
fn an_agent_lends_to_another_agent_and_is_repaid() {
    let core = Rc::new(RefCell::new(Core::new(CREDITED)));
    let mut host = Host::new(TestView::new(&core), TestNet::new(&core));
    let lender = wallet(1);
    let borrower = wallet(2);

    let plan = open_credit(
        &mut host,
        &lender,
        addr(&borrower),
        1_000_000,
        1_000_000,
        100,
        100,
        1_000,
        1,
    )
    .expect("the lender may open a position");
    assert_eq!(plan.lender, addr(&lender));
    assert_eq!(plan.borrower, addr(&borrower));

    // The principal really moved.
    let state = core.borrow().state.clone();
    let position = state
        .credit_position(&plan.position_id)
        .expect("the position is in the state");
    assert_eq!(position.outstanding_sat, 1_000_000);
    assert_eq!(position.collateral_sat, 1_000_000);

    // The borrower repays it.
    repay_credit(&mut host, &borrower, plan.position_id, 1_000_000).expect("repaid");
    let state = core.borrow().state.clone();
    let position = state
        .credit_position(&plan.position_id)
        .expect("the position is still there");
    assert_eq!(position.outstanding_sat, 0, "the debt is settled");
    assert_eq!(position.collateral_sat, 0, "and the collateral came back");
}

#[test]
fn a_loan_the_lender_cannot_fund_is_refused_before_it_is_broadcast() {
    let core = Rc::new(RefCell::new(Core::new(1_000)));
    let mut host = Host::new(TestView::new(&core), TestNet::new(&core));
    let lender = wallet(1);
    let borrower = wallet(2);

    let err = open_credit(
        &mut host,
        &lender,
        addr(&borrower),
        1_000_000,
        1_000_000,
        100,
        100,
        1_000,
        1,
    )
    .expect_err("the lender cannot fund it");
    assert!(
        matches!(err, WorkerError::InsufficientBalance { .. }),
        "refused by name, got {err:?}"
    );
}
