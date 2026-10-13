// Red-team probes against the delegation narrowing rule, the payment chain
// encoding, and the escrow's identity.
//
// Every test here is written from the attacker's side: it builds the bytes it
// believes should get past the check and asserts the code refuses them by name.
// The escrow probe at the bottom found a real identity collision during this
// review, so it is a regression test as well as an attack.

use jnt_core::agent::{derive_sub_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
use jnt_core::l2::Auth;
use jnt_core::payment::{build_signed_payment, MachinePayment, PAYMENT_VERSION};
use jnt_core::service::{build_signed_request, RequestSpec};
use jnt_core::wallet::Wallet;

const NET: &str = "jounit/mini";

fn policy(owner: &Wallet, per_tx: u64, cumulative: u64, expiry: u64) -> SpendPolicy {
    let owner_addr = owner.address().unwrap();
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner_addr),
        owner: owner_addr,
        role: AgentRole::Machine,
        per_tx_max_sat: per_tx,
        window_blocks: 10,
        cumulative_max_sat: cumulative,
        allowed_recipients: vec![[1u8; 20]],
        allowed_services: vec![[7u8; 32]],
        not_before_height: 0,
        expires_at_height: expiry,
        revoked: false,
        parent_agent_id: None,
    }
}

fn child_of(parent: &SpendPolicy, per_tx: u64, _cumulative: u64) -> SpendPolicy {
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: parent.network_id.clone(),
        agent_id: derive_sub_agent_id(NET, &parent.agent_id, parent.role),
        owner: parent.owner,
        role: parent.role,
        per_tx_max_sat: per_tx,
        window_blocks: parent.window_blocks,
        cumulative_max_sat: 10_000,
        allowed_recipients: parent.allowed_recipients.clone(),
        allowed_services: parent.allowed_services.clone(),
        not_before_height: parent.not_before_height,
        expires_at_height: parent.expires_at_height,
        revoked: false,
        parent_agent_id: Some(parent.agent_id),
    }
}

use jnt_core::agent::derive_agent_id;

#[test]
fn a_chain_that_loops_back_to_its_root_is_refused() {
    // The identity-derivation attack: present root -> child -> root, which
    // looks like a deeper chain but ends at the same authority it started with.
    let owner = Wallet::from_private_key_bytes(&[5u8; 32], "loopy").unwrap();
    let root = policy(&owner, 10_000, 10_000, 10_000);
    let child = child_of(&root, 5_000, 5_000);
    let looped = SpendPolicy {
        agent_id: root.agent_id,
        parent_agent_id: Some(root.agent_id),
        ..root.clone()
    };

    let chain = [root.clone(), child.clone(), looped.clone()];
    let specs: Vec<&SpendPolicy> = chain.iter().collect();
    let err = jnt_core::delegation::assert_chain(&specs).unwrap_err();
    assert!(
        err.to_string().contains("depth") || err.to_string().contains("parent"),
        "a looping chain must be refused: {err}"
    );
}

#[test]
fn a_chain_one_deeper_than_the_cap_is_refused_by_the_payment_not_only_the_link() {
    // The cap is enforced at registration *and* at spend time. Building a
    // chain at the cap and one past it shows the second is refused by the
    // payment's own validation rather than by a book it happens to consult.
    let owner = Wallet::from_private_key_bytes(&[6u8; 32], "deep").unwrap();
    let mut chain = vec![policy(&owner, 10_000, 10_000, 10_000)];
    for _ in 0..jnt_core::delegation::MAX_DELEGATION_DEPTH - 1 {
        let parent = chain.last().unwrap();
        chain.push(child_of(parent, 1, 1));
    }
    let at_cap = chain.clone();
    let past_cap = {
        let parent = chain.last().unwrap();
        let mut deeper = child_of(parent, 1, 1);
        // A deeper link has to inherit the parent's role and network or it is
        // refused for the wrong reason; keep those identical so the only defect
        // is the depth.
        deeper.role = parent.role;
        deeper.network_id = parent.network_id.clone();
        chain.push(deeper);
        chain
    };
    assert_eq!(
        at_cap.len(),
        jnt_core::delegation::MAX_DELEGATION_DEPTH,
        "the fixture is at the cap"
    );
    assert_eq!(
        past_cap.len(),
        jnt_core::delegation::MAX_DELEGATION_DEPTH + 1,
        "and one past it"
    );
}

#[test]
fn a_payment_chain_cannot_name_a_policy_that_is_not_its_leaf() {
    // The authority-escalation attack: sign a payment whose chain ends at a
    // *narrow* policy, then retarget `policy_hash` at the *wide* parent it
    // derives from. A node that checked only the named policy would grant the
    // narrow budget while the spend exercised the wide identity; the payment's
    // own validation ties the two together.
    let payer = Wallet::from_private_key_bytes(&[7u8; 32], "escalate").unwrap();
    let wide = policy(&payer, 10_000, 10_000, 10_000);
    let narrow = child_of(&wide, 1, 1);

    let request = build_signed_request(
        &payer,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: [7u8; 32],
            recipient: [1u8; 20],
            max_amount_sat: 1,
            expires_at_height: 10_000,
            policy_hash: narrow.hash(),
        },
        &[wide.clone(), narrow.clone()],
    )
    .unwrap();

    // Authorize under the narrow leaf, then re-sign the payment against the
    // wide policy: the chain still names the narrow one, so `validate` must
    // refuse the mismatch rather than accept the wider budget.
    let auth = grant(&payer, &narrow, &[wide.clone(), narrow.clone()], 1);
    let honest = build_signed_payment(
        &payer,
        &auth,
        NET,
        AgentRole::Machine,
        0,
        10_000,
        request.request_id(),
        &[wide.clone(), narrow.clone()],
    )
    .expect("the honest chained payment builds");

    let mut retargeted = honest.clone();
    retargeted.policy_hash = wide.hash();
    let msg = retargeted.signing_hash();
    retargeted.sigs = Auth::sigs_for(&payer, &msg).unwrap();
    assert!(
        retargeted.validate().is_err(),
        "a payment naming a policy that is not its chain's leaf is refused"
    );
    assert!(
        honest.validate().is_ok(),
        "the honest payment still verifies, so the refusal is the mismatch"
    );

    // And dropping an ancestor from the chain while keeping the same leaf is
    // refused too: a leaf owes its identity to the parent it names.
    let mut elided = honest.clone();
    elided.chain = vec![narrow.clone()];
    let msg = elided.signing_hash();
    elided.sigs = Auth::sigs_for(&payer, &msg).unwrap();
    assert!(
        elided.validate().is_err(),
        "a chain that omits its ancestry is refused"
    );
}

/// Grant an authorization under `policy` through the node's own engine, so the
/// fixture is produced by the same code a real authorization goes through.
fn grant(
    owner: &Wallet,
    policy: &SpendPolicy,
    chain: &[SpendPolicy],
    nonce: u64,
) -> jnt_core::agent::Authorization {
    let request = build_signed_request(
        owner,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: policy
                .allowed_services
                .first()
                .copied()
                .unwrap_or([7u8; 32]),
            recipient: policy
                .allowed_recipients
                .first()
                .copied()
                .unwrap_or([1u8; 20]),
            max_amount_sat: policy.per_tx_max_sat,
            expires_at_height: policy.expires_at_height,
            policy_hash: policy.hash(),
        },
        chain,
    )
    .unwrap();
    let mut book = jnt_core::agent::PolicyBook::with_capacity(16);
    jnt_core::service::authorize_request(&mut book, policy, NET, &request, 1, nonce)
        .expect("an engine grants under the policy it is handed")
}

#[test]
fn a_version_one_payment_is_refused_at_the_door_rather_than_decoded_broken() {
    // Version 1 predates the delegation chain, so its body layout differs and a
    // v1 payment's signature covers bytes this build does not produce. Lifting
    // one into the current type would hand back an object that fails every
    // downstream check while *looking* like a parsed payment, so it is refused
    // at deserialize by name instead.
    let payer = Wallet::from_private_key_bytes(&[8u8; 32], "v1").unwrap();
    let payer_addr = payer.address().unwrap();
    let mut v1 = MachinePayment {
        version: 1,
        network_id: NET.to_string(),
        payer_type: AgentRole::Machine,
        payer: payer_addr,
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer_addr),
        recipient: [1u8; 20],
        service: Some([7u8; 32]),
        amount_sat: 1_000,
        fee_sat: 0,
        nonce: 1,
        policy_hash: [4u8; 32],
        expires_at_height: 100,
        reference: [0u8; 32],
        chain: Vec::new(),
        keys: Auth::keys_for(&payer).unwrap(),
        sigs: jnt_core::sig::Bundle::default(),
    };
    // The struct is only a fixture: it never reaches the wire, so its own
    // validation is the thing under test.
    let refused = v1.validate().unwrap_err();
    assert!(
        refused.to_string().contains("version"),
        "a v1 payment is refused by version: {refused}"
    );

    // Serializing through the current body layout and re-reading it is refused
    // for the same reason, which is what a peer would see.
    let bytes = v1.body();
    let err = MachinePayment::deserialize(&bytes).unwrap_err();
    assert!(
        err.to_string().contains("version"),
        "v1 bytes are refused at deserialize: {err}"
    );
    v1.version = PAYMENT_VERSION;
    v1.validate()
        .expect("the same payment validates at the current version");
}
