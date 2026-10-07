//! Machine/agent authorization policy suite — roadmap items 3, 4, 6, 10.
//!
//! Written attack-first: each test builds the *hostile* request a compromised
//! or careless agent would make and asserts the exact clause that refuses it.
//! The two properties that matter are (1) no ambiguity is ever resolved in the
//! spender's favour, and (2) a refusal never consumes budget or advances state.
//!
//! Run with `cargo test -p jnt-core --test agent_policy`.

use jnt_core::agent::{
    derive_agent_id, verify_authorization, AgentRole, Authorization, AuthorizationRequest,
    PolicyBook, PolicyError, SpendPolicy, MAX_NETWORK_ID_LEN, MAX_POLICY_RECIPIENTS,
    POLICY_VERSION,
};
use jnt_core::hash::Address;
use jnt_core::sig::Bundle;
use jnt_core::wallet::Wallet;

const NET: &str = "jounit/testnet";

fn owner() -> Address {
    [7u8; 20]
}

fn machine_policy() -> SpendPolicy {
    let owner = owner();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![[1u8; 20], [2u8; 20]],
        allowed_services: Vec::new(),
        not_before_height: 5,
        expires_at_height: 1_000,
        revoked: false,
    }
}

fn ask(p: &SpendPolicy, to: Address, amount: u64, height: u64, nonce: u64) -> AuthorizationRequest {
    AuthorizationRequest {
        agent_id: p.agent_id,
        recipient: to,
        amount_sat: amount,
        service: None,
        height,
        nonce,
    }
}

#[test]
fn happy_path_machine_micropayment_is_authorized_and_counted() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    let auth = book
        .authorize(&p, NET, &ask(&p, [1u8; 20], 250, 6, 1))
        .expect("an in-policy payment must authorize");

    assert_eq!(auth.amount_sat, 250);
    assert_eq!(auth.owner, p.owner);
    assert_eq!(auth.policy_hash, p.hash());
    assert_eq!(auth.version, POLICY_VERSION);

    let st = book.state(&p.hash()).copied().expect("state must exist");
    assert_eq!(st.spent_in_window_sat, 250);
    assert_eq!(st.total_spent_sat, 250);
    assert_eq!(st.last_nonce, 1);
    assert_eq!(st.authorizations, 1);
    assert_eq!(st.window_start_height, 6);
}

#[test]
fn a_payment_above_the_per_transaction_limit_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [1u8; 20], 601, 6, 1))
            .unwrap_err(),
        PolicyError::PerTxLimitExceeded {
            amount: 601,
            limit: 600
        }
    );
    assert!(book.is_empty(), "a refused payment must not create state");
}

#[test]
fn a_payment_before_the_policy_starts_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 4, 1))
            .unwrap_err(),
        PolicyError::NotYetValid {
            not_before: 5,
            height: 4
        }
    );
}

#[test]
fn a_payment_at_or_after_expiry_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 1_000, 1))
            .unwrap_err(),
        PolicyError::PolicyExpired {
            expires_at: 1_000,
            height: 1_000
        }
    );
    // One block earlier is still inside the policy.
    book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 999, 1))
        .expect("height 999 is still before expiry");
}

#[test]
fn a_zero_amount_payment_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [1u8; 20], 0, 6, 1))
            .unwrap_err(),
        PolicyError::ZeroAmount
    );
}

#[test]
fn a_recipient_outside_the_allow_list_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [9u8; 20], 10, 6, 1))
            .unwrap_err(),
        PolicyError::RecipientNotAllowed
    );
}

#[test]
fn a_payment_from_another_agent_is_refused() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    let mut r = ask(&p, [1u8; 20], 10, 6, 1);
    r.agent_id = derive_agent_id(NET, AgentRole::Machine, &[8u8; 20]);
    assert_eq!(
        book.authorize(&p, NET, &r).unwrap_err(),
        PolicyError::WrongAgent
    );
}

#[test]
fn time_cannot_run_backwards_inside_a_policy() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 50, 1))
        .unwrap();
    assert_eq!(
        book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 40, 2))
            .unwrap_err(),
        PolicyError::HeightWentBackwards {
            window_start: 50,
            height: 40
        }
    );
}

#[test]
fn a_structurally_impossible_policy_is_refused_before_it_is_used() {
    // per-tx above cumulative: no payment could ever satisfy both.
    let mut p = machine_policy();
    p.per_tx_max_sat = 2_000;
    assert_eq!(
        p.validate().unwrap_err(),
        PolicyError::PerTxAboveCumulative {
            per_tx: 2_000,
            cumulative: 1_000
        }
    );

    // zero window: the cumulative limit could never roll over.
    let mut q = machine_policy();
    q.window_blocks = 0;
    assert_eq!(q.validate().unwrap_err(), PolicyError::ZeroWindowBlocks);

    // expiry at or before start: never usable.
    let mut r = machine_policy();
    r.expires_at_height = r.not_before_height;
    assert!(matches!(
        r.validate().unwrap_err(),
        PolicyError::ExpiryNotAfterStart { .. }
    ));

    // zero per-tx limit: authorizes nothing, so it is a bug not a policy.
    let mut s = machine_policy();
    s.per_tx_max_sat = 0;
    s.cumulative_max_sat = 0;
    assert_eq!(s.validate().unwrap_err(), PolicyError::ZeroPerTxLimit);
}

#[test]
fn the_signing_hash_covers_every_field() {
    let base = machine_policy();
    let h0 = base.signing_hash();

    /// One field mutation, named so a failure says which field leaks out of
    /// the signing hash.
    type Mutation = (&'static str, Box<dyn Fn(&mut SpendPolicy)>);

    let mutations: Vec<Mutation> = vec![
        (
            "network",
            Box::new(|p: &mut SpendPolicy| {
                p.network_id = "jounit/mini".into();
                p.agent_id = derive_agent_id("jounit/mini", AgentRole::Machine, &p.owner);
            }),
        ),
        ("owner", Box::new(|p: &mut SpendPolicy| p.owner = [9u8; 20])),
        (
            "role",
            Box::new(|p: &mut SpendPolicy| p.role = AgentRole::Service),
        ),
        (
            "agent_id",
            Box::new(|p: &mut SpendPolicy| p.agent_id = [3u8; 20]),
        ),
        (
            "per_tx",
            Box::new(|p: &mut SpendPolicy| p.per_tx_max_sat = 601),
        ),
        (
            "window",
            Box::new(|p: &mut SpendPolicy| p.window_blocks = 11),
        ),
        (
            "cumulative",
            Box::new(|p: &mut SpendPolicy| p.cumulative_max_sat = 1_001),
        ),
        (
            "recipients",
            Box::new(|p: &mut SpendPolicy| p.allowed_recipients.push([3u8; 20])),
        ),
        (
            "services",
            Box::new(|p: &mut SpendPolicy| p.allowed_services.push([4u8; 32])),
        ),
        (
            "not_before",
            Box::new(|p: &mut SpendPolicy| p.not_before_height = 6),
        ),
        (
            "expires",
            Box::new(|p: &mut SpendPolicy| p.expires_at_height = 999),
        ),
        ("revoked", Box::new(|p: &mut SpendPolicy| p.revoked = true)),
        ("version", Box::new(|p: &mut SpendPolicy| p.version = 2)),
    ];

    for (name, mutate) in mutations {
        let mut m = base.clone();
        mutate(&mut m);
        assert_ne!(
            m.signing_hash(),
            h0,
            "field `{name}` is outside the signing hash"
        );
    }
}

#[test]
fn rotation_starts_a_fresh_window_and_cannot_inherit_spend() {
    let mut book = PolicyBook::default();
    let v1 = machine_policy();
    book.authorize(&v1, NET, &ask(&v1, [1u8; 20], 600, 6, 1))
        .unwrap();
    let v1_state = *book.state(&v1.hash()).unwrap();
    assert_eq!(v1_state.spent_in_window_sat, 600);

    // Rotate: same owner and role, wider limits, later expiry — a new hash.
    let mut v2 = machine_policy();
    v2.per_tx_max_sat = 600;
    v2.cumulative_max_sat = 600;
    v2.not_before_height = 6;
    v2.expires_at_height = 500;
    assert_ne!(v1.hash(), v2.hash(), "a rotation must be a new policy");

    // The rotated-in policy starts clean, even though it names the same agent.
    book.authorize(&v2, NET, &ask(&v2, [1u8; 20], 600, 6, 1))
        .expect("the new policy has its own budget");

    // The rotated-out policy is refused by its owner's kill switch.
    let mut revoked_v1 = v1.clone();
    revoked_v1.revoked = true;
    assert_eq!(
        book.authorize(&revoked_v1, NET, &ask(&revoked_v1, [1u8; 20], 1, 7, 2))
            .unwrap_err(),
        PolicyError::PolicyRevoked
    );
    // Forgetting a policy drops exactly its accounting.
    assert_eq!(book.forget(&v1.hash()), Some(v1_state));
    assert!(book.state(&v1.hash()).is_none());
    assert!(book.state(&v2.hash()).is_some());
}

#[test]
fn the_policy_book_is_bounded_and_refuses_rather_than_grows() {
    let mut book = PolicyBook::with_capacity(1);
    let p = machine_policy();
    book.authorize(&p, NET, &ask(&p, [1u8; 20], 10, 6, 1))
        .unwrap();

    // A different policy (different bytes => different hash) cannot be tracked.
    let mut q = machine_policy();
    q.window_blocks = 11;
    assert_eq!(
        book.authorize(&q, NET, &ask(&q, [1u8; 20], 10, 6, 1))
            .unwrap_err(),
        PolicyError::PolicyBookFull { cap: 1 }
    );
}

#[test]
fn network_binding_refuses_a_foreign_network_policy() {
    let p = machine_policy(); // signed for testnet
    let mut book = PolicyBook::default();
    // The same bytes replayed against mini must refuse by name.
    assert_eq!(
        book.authorize(&p, "jounit/mini", &ask(&p, [1u8; 20], 10, 6, 1))
            .unwrap_err(),
        PolicyError::WrongNetwork {
            expected: NET.to_string(),
            got: "jounit/mini".to_string()
        }
    );
}

#[test]
fn encoding_rejects_oversized_lists_and_unknown_versions() {
    // A declared recipient count above the cap is refused without allocating.
    let mut p = machine_policy();
    p.allowed_recipients.clear();
    p.allowed_recipients
        .extend((0..MAX_POLICY_RECIPIENTS).map(|i| [i as u8; 20]));
    p.allowed_recipients.push([200u8; 20]);
    assert_eq!(
        p.validate().unwrap_err(),
        PolicyError::TooManyRecipients {
            got: MAX_POLICY_RECIPIENTS + 1,
            cap: MAX_POLICY_RECIPIENTS
        }
    );

    // A very long network id is refused by name, not truncated.
    let mut q = machine_policy();
    q.network_id = "x".repeat(MAX_NETWORK_ID_LEN + 1);
    q.agent_id = derive_agent_id(&q.network_id, q.role, &q.owner);
    assert_eq!(
        q.validate().unwrap_err(),
        PolicyError::NetworkIdTooLong(MAX_NETWORK_ID_LEN + 1)
    );

    // Version tag is exclusive: an unknown one is refused, not guessed.
    let mut w = machine_policy();
    w.version = 9;
    let bytes = w.serialize();
    assert_eq!(
        SpendPolicy::deserialize(&bytes).unwrap_err(),
        PolicyError::UnsupportedVersion(9)
    );
}

#[test]
fn authorization_is_offline_verifiable_and_tamper_evident() {
    let p = machine_policy();
    let mut book = PolicyBook::default();
    let auth = book
        .authorize(&p, NET, &ask(&p, [1u8; 20], 250, 6, 1))
        .unwrap();

    // The owner signs the authorization's signing hash; a third party verifies
    // it with public key material only — no policy, no network, no secret.
    let wallet = Wallet::new_random("agent-owner");
    let digest = auth.signing_hash();
    let sig = wallet.sign_digest(&digest).expect("signing must succeed");
    let sigs = Bundle::single(1, sig.to_vec());
    let keys = Bundle::single(1, wallet.pubkey().unwrap().to_vec());

    verify_authorization(&sigs, &keys, &auth).expect("a valid authorization must verify");

    // Mutating the amount must break verification: the receipt is tamper-evident.
    let mut forged = auth.clone();
    forged.amount_sat = 1_000;
    assert!(
        verify_authorization(&sigs, &keys, &forged).is_err(),
        "a mutated authorization verified"
    );

    // A different key must not verify the original.
    let other = Wallet::new_random("attacker");
    let other_keys = Bundle::single(1, other.pubkey().unwrap().to_vec());
    assert!(verify_authorization(&sigs, &other_keys, &auth).is_err());

    // And the receipt round-trips through its canonical encoding.
    let bytes = auth.serialize();
    let decoded = Authorization {
        version: bytes[0],
        ..auth.clone()
    };
    assert_eq!(decoded.signing_hash(), auth.signing_hash());
}

#[test]
fn determinism_two_engines_reaching_the_same_inputs_agree() {
    let p = machine_policy();
    let mut a = PolicyBook::default();
    let mut b = PolicyBook::default();
    let requests = [
        ask(&p, [1u8; 20], 300, 6, 1),
        ask(&p, [2u8; 20], 300, 7, 2),
        ask(&p, [1u8; 20], 300, 8, 3),
        ask(&p, [1u8; 20], 300, 20, 4),
    ];
    for r in &requests {
        let ra = a.authorize(&p, NET, r);
        let rb = b.authorize(&p, NET, r);
        assert_eq!(ra, rb, "two engines disagreed on the same request");
    }
    assert_eq!(a.state(&p.hash()), b.state(&p.hash()));
}
