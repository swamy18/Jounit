//! Spending policies on chain (SPEC.md §21).
//!
//! The agent policy layer used to be node-local: a policy constrained a
//! payment *on the node that issued it*, and the chain never saw it. This file
//! pins the on-chain half: publication, revocation, and spending under a grant,
//! with every rule the grant states enforced against state the chain keeps —
//! the per-transaction cap, the tumbling per-window cap, the recipient and
//! service allow-lists, the validity window, and the strictly increasing
//! nonce.
//!
//! The properties asserted here are the ones a delegation scheme lives or dies
//! by: authority narrows, revocation reaches descendants, and a cap is a rule
//! rather than a suggestion.

use srct_core::agent::{derive_agent_id, derive_sub_agent_id, AgentId, AgentRole, SpendPolicy};
use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
use srct_core::hash::{Address, Hash};
use srct_core::l2::{
    AgentSpendPayload, L2Payload, L2Transaction, L2TxType, PolicyPayload, PolicyRevokePayload,
};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Effect, L2Error, L2State};

const FEE: u64 = 2_000;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "policy-flow").unwrap()
}

fn addr(w: &Wallet) -> Address {
    w.address().unwrap()
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new((1..=n).map(|i| BlsPublicKey([i; 48])).collect())
}

fn network() -> String {
    L2Config::mini().network_id
}

struct World {
    state: L2State,
    owner: Wallet,
    agent: Wallet,
    recipient: Wallet,
    validators: ValidatorSet,
}

fn world() -> World {
    let owner = wallet(1);
    let agent = wallet(2);
    let recipient = wallet(3);
    let mut state = L2State::new(L2Config::mini());
    state.credit(addr(&owner), 100_000_000).unwrap();
    state.credit(addr(&agent), 100_000_000).unwrap();
    World {
        state,
        owner,
        agent,
        recipient,
        validators: validators(4),
    }
}

/// A grant the owner's signature covers.
///
/// Every field is stated here rather than defaulted, because a test that
/// inherits a default cap tests nothing about the cap.
#[allow(clippy::too_many_arguments)]
fn grant(
    owner: Address,
    role: AgentRole,
    parent: Option<AgentId>,
    recipients: Vec<Address>,
    services: Vec<[u8; 32]>,
    per_tx: u64,
    window: u64,
    cumulative: u64,
) -> SpendPolicy {
    let net = network();
    let agent_id = match parent {
        Some(p) => derive_sub_agent_id(&net, &p, role),
        None => derive_agent_id(&net, role, &owner),
    };
    SpendPolicy {
        version: srct_core::agent::POLICY_VERSION,
        network_id: net,
        agent_id,
        owner,
        role,
        per_tx_max_sat: per_tx,
        window_blocks: window,
        cumulative_max_sat: cumulative,
        allowed_recipients: recipients,
        allowed_services: services,
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: parent,
    }
}

/// Publish a grant, signed by the owner it names.
fn publish(
    state: &mut L2State,
    validators: &ValidatorSet,
    owner: &Wallet,
    policy: &SpendPolicy,
    spender: Address,
) -> Hash {
    let payload = PolicyPayload::build_from_policy(owner, policy, spender).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    state
        .apply(&tx, 10, validators, &MockBls)
        .expect("the grant publishes");
    policy.hash()
}

/// Try to spend under a grant. Returns the refusal, if any.
#[allow(clippy::too_many_arguments)]
fn spend(
    state: &mut L2State,
    validators: &ValidatorSet,
    policy_hash: Hash,
    nonce: u64,
    to: Address,
    amount: u64,
    service: Option<[u8; 32]>,
    signer: &Wallet,
    height: u64,
) -> Result<L2Effect, L2Error> {
    let payload =
        AgentSpendPayload::build(signer, policy_hash, nonce, to, amount, service).unwrap();
    let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
    state.apply(&tx, height, validators, &MockBls)
}

// ---------------------------------------------------------------------------
// 1. Publication
// ---------------------------------------------------------------------------

#[test]
fn a_published_grant_is_recorded_and_committed_to_the_state_root() {
    let mut w = world();
    let before = w.state.committed_root();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let _hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    assert_ne!(
        before,
        w.state.committed_root(),
        "a published grant must change the committed root"
    );
    assert!(
        w.state.check_conservation(),
        "value is moved, never created"
    );
}

#[test]
fn a_grant_naming_another_owner_is_refused() {
    let mut w = world();
    let stranger = wallet(9);
    let p = grant(
        addr(&stranger),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    // The owner signs, but the grant names somebody else.
    let payload = PolicyPayload::build_from_policy(&w.owner, &p, addr(&w.agent)).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let err = w
        .state
        .apply(&tx, 10, &w.validators, &MockBls)
        .expect_err("a grant for another owner is refused");
    assert!(
        matches!(err, L2Error::PolicyBinding(_)),
        "refused by binding, got {err:?}"
    );
}

#[test]
fn an_agent_has_one_live_grant_at_a_time() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    // A second grant for the same agent would double the caps, so it is
    // refused while the first is live.
    let mut p2 = p.clone();
    p2.per_tx_max_sat = 20_000;
    let payload = PolicyPayload::build_from_policy(&w.owner, &p2, addr(&w.agent)).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let err = w
        .state
        .apply(&tx, 11, &w.validators, &MockBls)
        .expect_err("a second live grant is refused");
    assert!(
        matches!(err, L2Error::PolicyAlreadyPublished),
        "refused by name, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Spending under a grant
// ---------------------------------------------------------------------------

#[test]
fn a_spend_under_a_grant_moves_value_from_the_grant_owner() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    let owner_before = w.state.balance(&addr(&w.owner));
    let recipient_before = w.state.balance(&addr(&w.recipient));
    spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        5_000,
        None,
        &w.agent,
        11,
    )
    .expect("the spend is inside every cap");

    assert_eq!(
        w.state.balance(&addr(&w.recipient)),
        recipient_before + 5_000,
        "the recipient is paid"
    );
    assert_eq!(
        w.state.balance(&addr(&w.owner)),
        owner_before - 5_000 - FEE,
        "the owner pays the amount and the fee"
    );
    assert!(w.state.check_conservation());
}

#[test]
fn a_spend_above_the_per_transaction_cap_is_refused() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        10_001,
        None,
        &w.agent,
        11,
    )
    .expect_err("above the per-transaction cap");
    assert!(
        matches!(err, L2Error::PolicyLimit(_)),
        "refused by the cap, got {err:?}"
    );
}

#[test]
fn a_spend_above_the_window_cap_is_refused_and_the_window_rolls_over() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        10,
        10_000,
    );
    // Published at height 10, so the window runs 10..20.
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        6_000,
        None,
        &w.agent,
        11,
    )
    .expect("inside the window cap");

    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        2,
        addr(&w.recipient),
        5_000,
        None,
        &w.agent,
        12,
    )
    .expect_err("the window cap binds");
    assert!(
        matches!(err, L2Error::PolicyLimit(_)),
        "refused by the window cap, got {err:?}"
    );

    // The window rolls forward, so the same amount is spendable again — but
    // the nonce still has to increase.
    spend(
        &mut w.state,
        &w.validators,
        hash,
        3,
        addr(&w.recipient),
        9_000,
        None,
        &w.agent,
        20,
    )
    .expect("the window rolled over");
    assert!(w.state.check_conservation());
}

#[test]
fn a_recipient_outside_the_allow_list_is_refused() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.owner),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect_err("the recipient is not on the list");
    assert!(
        matches!(err, L2Error::PolicyRecipient),
        "refused by name, got {err:?}"
    );
}

#[test]
fn an_empty_allow_list_authorises_nothing() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect_err("an empty list allows nothing");
    assert!(
        matches!(err, L2Error::PolicyRecipient),
        "refused by name, got {err:?}"
    );
}

#[test]
fn a_service_tag_must_be_on_the_list_and_a_tagged_grant_refuses_untagged_spends() {
    let mut w = world();
    let tag = [0x77u8; 32];
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![tag],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    // A tagged grant does not authorise untagged spending: the tag is how the
    // owner restricts *what* the money buys.
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect_err("a tagged grant refuses an untagged spend");
    assert!(
        matches!(err, L2Error::PolicyService),
        "refused by name, got {err:?}"
    );

    // A tag that is not on the list is refused too.
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        2,
        addr(&w.recipient),
        1_000,
        Some([0x88u8; 32]),
        &w.agent,
        11,
    )
    .expect_err("an unknown tag is refused");
    assert!(
        matches!(err, L2Error::PolicyService),
        "refused by name, got {err:?}"
    );

    // The listed tag works.
    spend(
        &mut w.state,
        &w.validators,
        hash,
        3,
        addr(&w.recipient),
        1_000,
        Some(tag),
        &w.agent,
        11,
    )
    .expect("the listed tag is accepted");
}

#[test]
fn a_replayed_nonce_is_refused() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));
    spend(
        &mut w.state,
        &w.validators,
        hash,
        5,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect("the first spend");

    // The identical bytes are a replay of the transaction id itself, refused
    // before the nonce rule is even reached.
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        5,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect_err("the identical transaction is a replay");
    assert!(
        matches!(err, L2Error::Replay),
        "refused as a replay, got {err:?}"
    );

    // A *different* transaction that reuses the nonce is the nonce rule
    // itself: the bytes differ, so the replay guard cannot catch it.
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        5,
        addr(&w.recipient),
        2_000,
        None,
        &w.agent,
        11,
    )
    .expect_err("the nonce repeats");
    assert!(
        matches!(err, L2Error::PolicyNonce),
        "refused by name, got {err:?}"
    );
}

#[test]
fn only_the_named_spender_may_exercise_a_grant() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    // A different key, even with a valid signature of its own, is refused:
    // the grant names the spender.
    let stranger = wallet(7);
    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        None,
        &stranger,
        11,
    )
    .expect_err("only the named spender may spend");
    assert!(
        matches!(err, L2Error::PolicyBinding(_)),
        "refused by binding, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Revocation
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_grant_authorises_nothing() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));

    let payload = PolicyRevokePayload::build(&w.owner, p.agent_id).unwrap();
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    w.state
        .apply(&tx, 11, &w.validators, &MockBls)
        .expect("the owner may revoke");

    let err = spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        12,
    )
    .expect_err("a revoked grant authorises nothing");
    assert!(
        matches!(err, L2Error::PolicyRevoked),
        "refused by name, got {err:?}"
    );
}

#[test]
fn a_revoked_parent_kills_its_descendant() {
    let mut w = world();
    let parent = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        100_000,
        100,
        1_000_000,
    );
    let parent_hash = publish(
        &mut w.state,
        &w.validators,
        &w.owner,
        &parent,
        addr(&w.agent),
    );

    // A child that narrows its parent: a smaller cap, the same recipients.
    let child = grant(
        addr(&w.owner),
        AgentRole::Machine,
        Some(parent.agent_id),
        vec![addr(&w.recipient)],
        vec![],
        1_000,
        50,
        10_000,
    );
    let child_hash = publish(
        &mut w.state,
        &w.validators,
        &w.owner,
        &child,
        addr(&w.agent),
    );
    assert_ne!(parent_hash, child_hash);

    // The child works while the parent is live.
    spend(
        &mut w.state,
        &w.validators,
        child_hash,
        1,
        addr(&w.recipient),
        500,
        None,
        &w.agent,
        11,
    )
    .expect("the child is live");

    // Revoking the parent reaches the descendant without a second revocation.
    let payload = PolicyRevokePayload::build(&w.owner, parent.agent_id).unwrap();
    let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
    w.state
        .apply(&tx, 12, &w.validators, &MockBls)
        .expect("the owner may revoke");

    let err = spend(
        &mut w.state,
        &w.validators,
        child_hash,
        2,
        addr(&w.recipient),
        500,
        None,
        &w.agent,
        13,
    )
    .expect_err("a revoked parent kills its descendant");
    assert!(
        matches!(err, L2Error::PolicyRevoked),
        "refused by name, got {err:?}"
    );
}

#[test]
fn a_widening_grant_is_refused() {
    let mut w = world();
    let parent = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    publish(
        &mut w.state,
        &w.validators,
        &w.owner,
        &parent,
        addr(&w.agent),
    );

    // The child claims a bigger per-transaction cap than its parent: that is
    // the whole attack a delegation scheme has to refuse.
    let child = grant(
        addr(&w.owner),
        AgentRole::Machine,
        Some(parent.agent_id),
        vec![addr(&w.recipient)],
        vec![],
        20_000,
        50,
        10_000,
    );
    let payload = PolicyPayload::build_from_policy(&w.owner, &child, addr(&w.agent)).unwrap();
    let tx = L2Transaction::new(L2Payload::Policy(payload));
    let err = w
        .state
        .apply(&tx, 11, &w.validators, &MockBls)
        .expect_err("a widening grant is refused");
    assert!(
        matches!(err, L2Error::Policy(_)),
        "refused by the domination rule, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. State and agreement
// ---------------------------------------------------------------------------

#[test]
fn the_state_encoding_round_trips_the_published_grants() {
    let mut w = world();
    let p = grant(
        addr(&w.owner),
        AgentRole::Machine,
        None,
        vec![addr(&w.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut w.state, &w.validators, &w.owner, &p, addr(&w.agent));
    spend(
        &mut w.state,
        &w.validators,
        hash,
        1,
        addr(&w.recipient),
        1_000,
        None,
        &w.agent,
        11,
    )
    .expect("the spend");

    let bytes = w.state.encode();
    let back = L2State::decode(&bytes).expect("the state decodes");
    assert_eq!(
        back.committed_root(),
        w.state.committed_root(),
        "a round trip must not change what the chain committed to"
    );
    assert_eq!(back, w.state);
}

#[test]
fn two_nodes_replaying_the_same_transactions_agree_on_the_root() {
    let mut a = world();
    let mut b = world();
    assert_eq!(a.state.committed_root(), b.state.committed_root());

    let p = grant(
        addr(&a.owner),
        AgentRole::Machine,
        None,
        vec![addr(&a.recipient)],
        vec![],
        10_000,
        100,
        100_000,
    );
    let hash = publish(&mut a.state, &a.validators, &a.owner, &p, addr(&a.agent));
    publish(&mut b.state, &b.validators, &b.owner, &p, addr(&b.agent));
    assert_eq!(
        a.state.committed_root(),
        b.state.committed_root(),
        "the same grant on two nodes commits to the same root"
    );

    spend(
        &mut a.state,
        &a.validators,
        hash,
        1,
        addr(&a.recipient),
        1_000,
        None,
        &a.agent,
        11,
    )
    .expect("the spend");
    spend(
        &mut b.state,
        &b.validators,
        hash,
        1,
        addr(&b.recipient),
        1_000,
        None,
        &b.agent,
        11,
    )
    .expect("the spend");
    assert_eq!(
        a.state.committed_root(),
        b.state.committed_root(),
        "the same spend on two nodes commits to the same root"
    );
    assert_eq!(a.state, b.state);
}

#[test]
fn the_transaction_types_are_the_ones_the_wire_admits() {
    assert_eq!(L2TxType::Policy.to_wire(), 0x16);
    assert_eq!(L2TxType::PolicyRevoke.to_wire(), 0x17);
    assert_eq!(L2TxType::AgentSpend.to_wire(), 0x18);
    assert_eq!(L2TxType::Policy.fee_sat(), 2_000);
    assert_eq!(L2TxType::PolicyRevoke.fee_sat(), 2_000);
    assert_eq!(L2TxType::AgentSpend.fee_sat(), 2_000);
}
