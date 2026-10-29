//! Hardening for the authority and credit layers (SPEC.md §21, §22).
//!
//! The behaviour tests in `policy_flow.rs` and `credit_flow.rs` pin what the
//! rules *do*. This file pins what they must *never* do: move value on a
//! refusal, wrap an arithmetic overflow, accept a forged signature, apply the
//! same transaction twice, or leave a state that a restart would not rebuild.
//!
//! Every case here is one that a rule enforced by one node, or by a caller,
//! rather than by the chain, would get wrong.

use srct_core::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    AgentSpendPayload, CreditOpenPayload, CreditRepayPayload, L2Payload, L2Transaction,
    PolicyPayload, PolicyRevokePayload,
};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Error, L2State};

const FUND: u64 = 100_000_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "authority-hardening").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn validators() -> ValidatorSet {
    ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect())
}

fn grant(
    owner: Address,
    agent_id: [u8; 20],
    recipients: Vec<Address>,
    per_tx: u64,
    window: u64,
    cumulative: u64,
) -> SpendPolicy {
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: "srct/mini".to_string(),
        agent_id,
        owner,
        role: AgentRole::Machine,
        per_tx_max_sat: per_tx,
        window_blocks: window,
        cumulative_max_sat: cumulative,
        allowed_recipients: recipients,
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: None,
    }
}

struct World {
    state: L2State,
    owner: Wallet,
    agent: Wallet,
    recipient: Wallet,
    other: Wallet,
    lender: Wallet,
    borrower: Wallet,
}

fn world() -> World {
    let owner = wallet(1);
    let agent = wallet(2);
    let recipient = wallet(3);
    let other = wallet(4);
    let lender = wallet(5);
    let borrower = wallet(6);
    let mut state = L2State::new(L2Config::mini());
    for w in [&owner, &agent, &recipient, &other, &lender, &borrower] {
        state.credit(addr(w), FUND).unwrap();
    }
    World {
        state,
        owner,
        agent,
        recipient,
        other,
        lender,
        borrower,
    }
}

impl World {
    fn lender_wallet(&self) -> Wallet {
        self.lender.clone()
    }

    fn borrower_wallet(&self) -> Wallet {
        self.borrower.clone()
    }
}

impl World {
    fn agent_id(&self) -> [u8; 20] {
        derive_agent_id("srct/mini", AgentRole::Machine, &addr(&self.owner))
    }
}

/// Publish a grant and check that the state moved only if it should have.
fn publish(
    state: &mut L2State,
    owner: &Wallet,
    policy: &SpendPolicy,
    spender: Address,
) -> Result<Hash, L2Error> {
    let payload = PolicyPayload::build_from_policy(owner, policy, spender).expect("a payload");
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let before = state.committed_root();
    let result = state.apply(&tx, 1, &validators(), &MockBls);
    if result.is_ok() {
        assert_ne!(
            before,
            state.committed_root(),
            "an applied publication must change the committed root"
        );
    } else {
        assert_eq!(
            before,
            state.committed_root(),
            "a refused publication must not change the state"
        );
    }
    result.map(|_| policy.hash())
}

/// Spend under a grant and check that the state moved only if it should have.
fn spend(
    state: &mut L2State,
    policy_hash: Hash,
    nonce: u64,
    to: Address,
    amount: u64,
    signer: &Wallet,
    height: u64,
) -> Result<(), L2Error> {
    let payload = AgentSpendPayload::build(signer, policy_hash, nonce, to, amount, None).unwrap();
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    let before = state.committed_root();
    let result = state.apply(&tx, height, &validators(), &MockBls);
    if result.is_ok() {
        assert_ne!(
            before,
            state.committed_root(),
            "an applied spend must change the committed root"
        );
    } else {
        assert_eq!(
            before,
            state.committed_root(),
            "a refused spend must not change the state"
        );
    }
    result.map(|_| ())
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[test]
fn the_same_transaction_applied_twice_is_a_replay() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");

    // Build one transaction and apply it twice, byte for byte.
    let payload =
        AgentSpendPayload::build(&w.agent, hash, 1, addr(&w.recipient), 1_000, None).unwrap();
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    let root = w.state.committed_root();
    w.state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect("the first application");
    let after_first = w.state.committed_root();
    assert_ne!(root, after_first, "the first application changed the state");

    let err = w
        .state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect_err("the same transaction must not apply twice");
    assert!(
        matches!(err, L2Error::Replay),
        "refused as a replay, got {err:?}"
    );
    assert_eq!(
        after_first,
        w.state.committed_root(),
        "a replay must not change the state"
    );
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

#[test]
fn a_publication_whose_actor_was_tampered_with_is_refused() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    // The payload is signed by the owner, but it claims to be somebody else's.
    let mut payload = PolicyPayload::build_from_policy(&w.owner, &policy, addr(&w.agent)).unwrap();
    payload.owner = addr(&w.other);
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let before = w.state.committed_root();
    let err = w
        .state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect_err("a tampered actor must be refused");
    assert!(
        matches!(err, L2Error::BadAuthorization),
        "refused by the signature check, got {err:?}"
    );
    assert_eq!(before, w.state.committed_root());
    assert!(w.state.check_conservation());
}

#[test]
fn a_spend_signed_by_the_wrong_key_is_refused() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");
    // The stranger signs a spend that names the agent as the actor.
    let mut payload =
        AgentSpendPayload::build(&w.other, hash, 1, addr(&w.recipient), 1_000, None).unwrap();
    payload.agent = addr(&w.agent);
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    let before = w.state.committed_root();
    let err = w
        .state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect_err("a forged spend must be refused");
    assert!(
        matches!(err, L2Error::BadAuthorization),
        "refused by the signature check, got {err:?}"
    );
    assert_eq!(before, w.state.committed_root());
}

// ---------------------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------------------

#[test]
fn publishing_the_same_grant_twice_is_refused() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");

    // The identical transaction is a replay: the signature is deterministic,
    // so the same terms produce the same bytes and the same transaction id.
    let err = publish(&mut w.state, &w.owner, &policy, addr(&w.agent))
        .expect_err("the same publication must not apply twice");
    assert!(
        matches!(err, L2Error::Replay),
        "refused as a replay, got {err:?}"
    );

    // A *different* grant for the same agent is not a replay, and it is
    // refused for the reason that matters: one live grant per agent, so a
    // second one cannot double the caps the first one grants.
    let mut second = policy.clone();
    second.per_tx_max_sat = 20_000;
    let err = publish(&mut w.state, &w.owner, &second, addr(&w.agent))
        .expect_err("a second live grant must be refused");
    assert!(
        matches!(err, L2Error::PolicyAlreadyPublished),
        "refused by name, got {err:?}"
    );

    // One grant, not two.
    assert_eq!(w.state.policies().len(), 1);
    assert!(w.state.check_conservation());
}

#[test]
fn opening_the_same_credit_twice_is_refused() {
    let mut w = world();
    let lender = w.lender_wallet();
    let borrower = w.borrower_wallet();
    let build = || {
        CreditOpenPayload::build(
            &lender,
            addr(&borrower),
            1_000_000,
            1_000_000,
            100,
            100,
            1_000,
            1,
        )
        .unwrap()
    };
    let payload = build();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    w.state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect("the first opening");
    let before = w.state.committed_root();
    // The identical transaction is a replay: the terms and the deterministic
    // signature make the same bytes, and a position is opened once.
    let payload = build();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    let err = w
        .state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect_err("the same position must not open twice");
    assert!(
        matches!(err, L2Error::Replay),
        "refused as a replay, got {err:?}"
    );
    assert_eq!(before, w.state.committed_root());
    assert_eq!(w.state.credit_positions().len(), 1);
    assert!(w.state.check_conservation());
}

#[test]
fn revoking_twice_is_refused_as_a_replay_and_the_grant_stays_revoked() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");
    let payload = PolicyRevokePayload::build(&w.owner, policy.agent_id).unwrap();
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    w.state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect("the first revocation");
    // The revocation is fully determined by the agent it names, so the second
    // one is the same transaction and the replay guard refuses it. What
    // matters is that the grant stays revoked either way.
    let payload = PolicyRevokePayload::build(&w.owner, policy.agent_id).unwrap();
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    let err = w
        .state
        .apply(&tx, 3, &validators(), &MockBls)
        .expect_err("the same revocation must not apply twice");
    assert!(
        matches!(err, L2Error::Replay),
        "refused as a replay, got {err:?}"
    );
    let entry = w.state.policy(&policy.hash()).expect("the grant is there");
    assert!(entry.revoked, "the grant stays revoked");
    assert!(w.state.check_conservation());
}

#[test]
fn revoking_a_grant_that_does_not_exist_is_refused() {
    let mut w = world();
    let payload = PolicyRevokePayload::build(&w.owner, [0x99u8; 20]).unwrap();
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    let err = w
        .state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect_err("there is no such grant");
    assert!(
        matches!(err, L2Error::UnknownPolicy),
        "refused by name, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_grant_is_refused_and_changes_nothing() {
    let mut w = world();
    // Bytes that are not a grant at all.
    let payload =
        PolicyPayload::build(&w.owner, vec![0xFFu8; 32], addr(&w.agent), w.agent_id()).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let before = w.state.committed_root();
    let err = w
        .state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect_err("a malformed grant must be refused");
    assert!(
        matches!(err, L2Error::Policy(_)),
        "refused by name, got {err:?}"
    );
    assert_eq!(before, w.state.committed_root());
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------------

#[test]
fn an_overflowing_spend_is_refused_rather_than_wrapped() {
    let mut w = world();
    // A grant whose caps are the largest number there is.
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        u64::MAX,
        u64::MAX,
        u64::MAX,
    );
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");
    let owner_before = w.state.balance(&addr(&w.owner));
    let err = spend(
        &mut w.state,
        hash,
        1,
        addr(&w.recipient),
        u64::MAX,
        &w.agent,
        2,
    )
    .expect_err("the arithmetic refuses rather than wrapping");
    assert!(
        matches!(err, L2Error::Overflow | L2Error::InsufficientBalance { .. }),
        "refused by name, got {err:?}"
    );
    assert_eq!(
        owner_before,
        w.state.balance(&addr(&w.owner)),
        "no value moved"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn an_overflowing_credit_open_is_refused_rather_than_wrapped() {
    let mut w = world();
    let lender = w.lender_wallet();
    let borrower = w.borrower_wallet();
    let payload = CreditOpenPayload::build(
        &lender,
        addr(&borrower),
        u64::MAX,
        u64::MAX,
        100,
        100,
        1_000,
        1,
    )
    .unwrap();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    let before = w.state.committed_root();
    let err = w
        .state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect_err("the arithmetic refuses rather than wrapping");
    assert!(
        matches!(err, L2Error::Overflow | L2Error::InsufficientBalance { .. }),
        "refused by name, got {err:?}"
    );
    assert_eq!(before, w.state.committed_root());
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// Validity windows
// ---------------------------------------------------------------------------

#[test]
fn a_spend_outside_the_grants_window_is_refused() {
    let mut w = world();
    let mut policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    policy.not_before_height = 50;
    policy.expires_at_height = 60;
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");

    // Before the grant is valid.
    let err = spend(
        &mut w.state,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        &w.agent,
        10,
    )
    .expect_err("the grant is not valid yet");
    assert!(
        matches!(err, L2Error::PolicyWindow(_)),
        "refused by name, got {err:?}"
    );

    // After the grant has expired.
    let err = spend(
        &mut w.state,
        hash,
        2,
        addr(&w.recipient),
        1_000,
        &w.agent,
        60,
    )
    .expect_err("the grant has expired");
    assert!(
        matches!(err, L2Error::PolicyWindow(_)),
        "refused by name, got {err:?}"
    );

    // Inside the window.
    spend(
        &mut w.state,
        hash,
        3,
        addr(&w.recipient),
        1_000,
        &w.agent,
        55,
    )
    .expect("the grant is valid at this height");
    assert!(w.state.check_conservation());
}

#[test]
fn a_spend_at_a_height_below_the_grants_window_is_refused() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");
    // A spend at height 0 after the grant was published at height 1: the
    // height ran backwards inside the grant.
    let err = spend(
        &mut w.state,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        &w.agent,
        0,
    )
    .expect_err("time does not run backwards inside a grant");
    assert!(
        matches!(err, L2Error::PolicyWindow(_)),
        "refused by name, got {err:?}"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn a_repayment_larger_than_the_debt_is_refused() {
    let mut w = world();
    let lender = w.lender_wallet();
    let borrower = w.borrower_wallet();
    let payload = CreditOpenPayload::build(
        &lender,
        addr(&borrower),
        1_000_000,
        1_000_000,
        100,
        100,
        1_000,
        1,
    )
    .unwrap();
    let id = payload.derived_position_id();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    w.state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect("the position opens");

    let borrower_before = w.state.balance(&addr(&borrower));
    let lender_before = w.state.balance(&addr(&lender));
    let payload = CreditRepayPayload::build(&w.borrower_wallet(), id, 5_000_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    let err = w
        .state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect_err("the repayment is larger than the debt");
    assert!(
        matches!(err, L2Error::CreditRepaymentExceedsDebt { .. }),
        "refused by name, got {err:?}"
    );
    assert_eq!(
        borrower_before,
        w.state.balance(&addr(&borrower)),
        "the borrower keeps everything"
    );
    assert_eq!(
        lender_before,
        w.state.balance(&addr(&lender)),
        "the lender is paid the debt and not a satoshi more"
    );
    assert!(w.state.check_conservation());
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn a_restart_rebuilds_the_same_authority_state() {
    let mut w = world();
    let policy = grant(
        addr(&w.owner),
        w.agent_id(),
        vec![addr(&w.recipient)],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.owner, &policy, addr(&w.agent)).expect("published");
    spend(
        &mut w.state,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        &w.agent,
        2,
    )
    .expect("the spend");

    // The state a restart would rebuild, from the bytes on disk.
    let bytes = w.state.encode();
    let restarted = L2State::decode(&bytes).expect("the state decodes");
    assert_eq!(
        restarted.committed_root(),
        w.state.committed_root(),
        "a restart must not change what the chain committed to"
    );
    assert_eq!(restarted, w.state);
    let entry = restarted.policy(&hash).expect("the grant survived");
    assert_eq!(entry.spends, 1);
    assert_eq!(entry.last_nonce, 1);
    assert_eq!(entry.spent_in_window_sat, 1_000);
    assert!(restarted.check_conservation());
}

#[test]
fn a_restart_rebuilds_the_same_credit_state() {
    let mut w = world();
    let lender = w.lender_wallet();
    let borrower = w.borrower_wallet();
    let payload = CreditOpenPayload::build(
        &lender,
        addr(&borrower),
        1_000_000,
        1_000_000,
        100,
        100,
        1_000,
        1,
    )
    .unwrap();
    let id = payload.derived_position_id();
    let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
    w.state
        .apply(&tx, 1, &validators(), &MockBls)
        .expect("the position opens");
    let payload = CreditRepayPayload::build(&w.borrower_wallet(), id, 400_000).unwrap();
    let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
    w.state
        .apply(&tx, 2, &validators(), &MockBls)
        .expect("the repayment");

    let bytes = w.state.encode();
    let restarted = L2State::decode(&bytes).expect("the state decodes");
    assert_eq!(restarted, w.state);
    let position = restarted
        .credit_position(&id)
        .expect("the position survived");
    assert_eq!(position.outstanding_sat, 600_000);
    assert_eq!(position.interest_paid_sat, 0);
    assert_eq!(position.collateral_sat, 1_000_000);
    assert_eq!(
        restarted.credit_locked(),
        1_000_000,
        "the collateral is still locked"
    );
    assert!(restarted.check_conservation());
}
