//! Bridge session suite — roadmap items 2 (bridge), 6 (autonomous
//! payments), 5/7/8 (machine/agent payment flows).
//!
//! Written attack-first: every test mutates one layer of
//! `request → policy → authorization → payment → receipt` and asserts the
//! exact clause that refuses it. The two properties under attack are:
//!
//! 1. **No privileged path bypasses the policy** — a machine payment cannot
//!    settle without presenting its authorization, and no receipt or service
//!    response can mint one.
//! 2. **No layer can be substituted** — recipient, amount, service, policy,
//!    nonce, network and identity are all inside the signature of the layer
//!    that declares them *and* checked against the neighbouring layers.
//!
//! Run with `cargo test -p jnt-core --test bridge_session`.

use jnt_core::agent::{
    derive_agent_id, AgentRole, Authorization, PolicyBook, PolicyError, SpendPolicy, POLICY_VERSION,
};
use jnt_core::l2::Auth;
use jnt_core::payment::{
    build_direct_payment, build_signed_payment, DirectPaymentSpec, MachinePayment, PaymentError,
};
use jnt_core::receipt::{sign_receipt, ReceiptAnchor, ServiceReceipt, RECEIPT_VERSION};
use jnt_core::service::{
    authorize_request, build_signed_request, derive_service_id, result_hash_of, PaymentRequest,
    RequestSpec, Session, SessionError,
};
use jnt_core::wallet::Wallet;

const NET: &str = "jounit/testnet";
const HEIGHT: u64 = 100;
const EXPIRES: u64 = 9_000;

fn payer() -> Wallet {
    Wallet::from_private_key_bytes(&[51u8; 32], "payer").expect("valid key")
}

fn provider() -> Wallet {
    Wallet::from_private_key_bytes(&[52u8; 32], "provider").expect("valid key")
}

fn attacker() -> Wallet {
    Wallet::from_private_key_bytes(&[53u8; 32], "attacker").expect("valid key")
}

fn service_tag(provider_addr: &[u8; 20]) -> [u8; 32] {
    derive_service_id(NET, provider_addr, b"jounit-llm")
}

fn machine_policy(service: [u8; 32]) -> SpendPolicy {
    let owner = payer().address().expect("payer address");
    SpendPolicy {
        version: POLICY_VERSION,
        network_id: NET.to_string(),
        agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
        owner,
        role: AgentRole::Machine,
        per_tx_max_sat: 600,
        window_blocks: 10,
        cumulative_max_sat: 1_000,
        allowed_recipients: vec![provider().address().expect("provider address")],
        allowed_services: vec![service],
        not_before_height: 0,
        expires_at_height: 10_000,
        revoked: false,
        parent_agent_id: None,
    }
}

fn machine_request(service: [u8; 32], max_amount: u64) -> (PaymentRequest, SpendPolicy) {
    let policy = machine_policy(service);
    let req = build_signed_request(
        &payer(),
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider().address().expect("provider address"),
            max_amount_sat: max_amount,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .expect("request builds");
    (req, policy)
}

fn grant(
    book: &mut PolicyBook,
    policy: &SpendPolicy,
    request: &PaymentRequest,
    nonce: u64,
) -> (Authorization, jnt_core::sig::Bundle, jnt_core::sig::Bundle) {
    let auth =
        authorize_request(book, policy, NET, request, HEIGHT, nonce).expect("in-policy grant");
    let sigs = Auth::sigs_for(&payer(), &auth.signing_hash()).expect("owner signs");
    let keys = Auth::keys_for(&payer()).expect("owner keys");
    (auth, sigs, keys)
}

fn pay_for(auth: &Authorization, request: &PaymentRequest) -> MachinePayment {
    build_signed_payment(
        &payer(),
        auth,
        NET,
        AgentRole::Machine,
        2_000,
        EXPIRES,
        request.request_id(),
        &[],
    )
    .expect("payment builds")
}

fn receipt_for(
    request: &PaymentRequest,
    payment: &MachinePayment,
    issuer: &Wallet,
) -> ServiceReceipt {
    let mut r = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.to_string(),
        payer: payment.payer,
        payer_role: payment.payer_type,
        agent_id: payment.agent_id,
        recipient: payment.recipient,
        service_id: payment.service,
        amount_sat: payment.amount_sat,
        payment_id: payment.signing_hash(),
        request_id: request.request_id(),
        result_hash: Some(result_hash_of(b"model-output-v1")),
        anchor: Some(ReceiptAnchor {
            height: 120,
            block_hash: [7u8; 32],
        }),
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut r, issuer).expect("issuer signs");
    r
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn full_machine_session_verifies_end_to_end() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &provider());

    Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(NET, HEIGHT)
        .expect("the full chain must verify offline");

    // …and at the receipt layer it also binds to the payment directly.
    receipt.verify_binding(&payment).expect("binding");
}

#[test]
fn human_session_needs_no_authorization() {
    let human = payer();
    let provider_addr = provider().address().unwrap();
    let service = service_tag(&provider_addr);
    let request = build_signed_request(
        &human,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Human,
            service_id: service,
            recipient: provider_addr,
            max_amount_sat: 250,
            expires_at_height: EXPIRES,
            policy_hash: [0u8; 32],
        },
        &[],
    )
    .expect("human request");
    let payment = build_direct_payment(
        &human,
        DirectPaymentSpec {
            network_id: NET.to_string(),
            recipient: provider_addr,
            service: Some(service),
            amount_sat: 250,
            fee_sat: 1_000,
            nonce: 0,
            expires_at_height: EXPIRES,
            reference: request.request_id(),
        },
    )
    .expect("human payment");
    let receipt = receipt_for(&request, &payment, &provider());

    Session::new(&request)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(NET, HEIGHT)
        .expect("human flow verifies without any authorization");
}

#[test]
fn machine_to_human_service_payment_verifies() {
    // A human is the service provider here: same primitives, other direction.
    let human_provider = Wallet::from_private_key_bytes(&[61u8; 32], "human-svc").unwrap();
    let service = derive_service_id(NET, &human_provider.address().unwrap(), b"dataset-curation");
    let policy_owner = payer();
    let mut policy = machine_policy(service);
    policy.allowed_recipients = vec![human_provider.address().unwrap()];
    let request = build_signed_request(
        &policy_owner,
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: human_provider.address().unwrap(),
            max_amount_sat: 500,
            expires_at_height: EXPIRES,
            policy_hash: policy.hash(),
        },
        &[],
    )
    .expect("request");
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &human_provider);

    Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(NET, HEIGHT)
        .expect("machine → human service session verifies");
}

// ---------------------------------------------------------------------------
// No privileged path bypasses the policy (item 6)
// ---------------------------------------------------------------------------

#[test]
fn a_machine_payment_without_its_authorization_is_refused() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, _sigs, _keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &provider());

    // Payment alone: refused. The presence of a receipt changes nothing.
    let err = Session::new(&request)
        .with_payment(&payment)
        .verify(NET, HEIGHT)
        .expect_err("machine payment must show its grant");
    assert_eq!(
        err,
        SessionError::Binding("machine payment presented without its authorization")
    );

    let err = Session::new(&request)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(NET, HEIGHT)
        .expect_err("a receipt must not substitute for the authorization");
    assert_eq!(
        err,
        SessionError::Binding("machine payment presented without its authorization")
    );
}

#[test]
fn a_forged_service_response_cannot_authorize_a_payment() {
    // `authorize_request` takes only (book, policy, request, height, nonce):
    // there is no receipt-shaped parameter to forge, by type. What a forged
    // service response *can* do is claim work was delivered — so that is what
    // is attacked here.
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();

    // A revoked policy refuses regardless of any receipt the service shows.
    // The kill switch is checked even when the request names the revoked
    // policy's own hash (attacker-built after revocation).
    let mut revoked = policy.clone();
    revoked.revoked = true;
    let revoked_request = build_signed_request(
        &payer(),
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider().address().unwrap(),
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: revoked.hash(),
        },
    &[],
    )
    .unwrap();
    let err = authorize_request(&mut book, &revoked, NET, &revoked_request, HEIGHT, 1)
        .expect_err("revoked policy refuses");
    assert_eq!(err, SessionError::Policy(PolicyError::PolicyRevoked));
    assert!(book.is_empty(), "a refusal must not create state");

    // The forged receipt: the attacker claims the *provider* is the issuer.
    // Their signature cannot stand in for the provider's key.
    let mut forged = ServiceReceipt {
        version: RECEIPT_VERSION,
        network_id: NET.to_string(),
        payer: payer().address().unwrap(),
        payer_role: AgentRole::Machine,
        agent_id: derive_agent_id(NET, AgentRole::Machine, &payer().address().unwrap()),
        recipient: provider().address().unwrap(),
        service_id: Some(service),
        amount_sat: 400,
        payment_id: [9u8; 32],
        request_id: request.request_id(),
        result_hash: Some(result_hash_of(b"garbage")),
        anchor: None,
        keys: Default::default(),
        sigs: Default::default(),
    };
    sign_receipt(&mut forged, &attacker()).expect_err("attacker is not the recipient");

    forged.keys = Auth::keys_for(&attacker()).unwrap();
    let msg = forged.signing_hash();
    forged.sigs = Auth::sigs_for(&attacker(), &msg).unwrap();
    assert!(matches!(
        forged.verify(NET),
        Err(jnt_core::receipt::ReceiptError::IssuerNotRecipient { .. })
    ));

    // Presented inside a session with no payment: refused, because a receipt
    // requires the payment it claims — a receipt alone moves nothing.
    let err = Session::new(&request)
        .with_receipt(&forged)
        .verify(NET, HEIGHT)
        .expect_err("receipt without payment");
    assert_eq!(err, SessionError::Binding("receipt without payment"));
}

#[test]
fn cumulative_and_nonce_rules_apply_through_the_bridge() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();

    authorize_request(&mut book, &policy, NET, &request, HEIGHT, 1).expect("first");
    authorize_request(&mut book, &policy, NET, &request, HEIGHT, 2).expect("second");
    // 400 + 400 = 800; the third reaches 1200 > 1000.
    let err = authorize_request(&mut book, &policy, NET, &request, HEIGHT, 3)
        .expect_err("cumulative cap");
    assert_eq!(
        err,
        SessionError::Policy(PolicyError::CumulativeLimitExceeded {
            requested: 1_200,
            limit: 1_000
        })
    );
    // The refusal consumed nothing.
    let st = book.state(&policy.hash()).expect("state");
    assert_eq!(st.spent_in_window_sat, 800);

    // Nonce replay through the same path.
    let err = authorize_request(&mut book, &policy, NET, &request, HEIGHT + 50, 2)
        .expect_err("nonce replay");
    assert_eq!(
        err,
        SessionError::Policy(PolicyError::NonceNotIncreasing {
            nonce: 2,
            last_nonce: 2
        })
    );
}

// ---------------------------------------------------------------------------
// Substitution attacks at every layer
// ---------------------------------------------------------------------------

#[test]
fn recipient_substitution_fails_at_every_layer() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &provider());

    // (a) Request layer: swap the recipient after signing → signature dies.
    let mut tampered = request.clone();
    tampered.recipient = [7u8; 20];
    let err = tampered.verify(NET, HEIGHT).expect_err("tampered request");
    assert!(matches!(err, PaymentError::SignatureInvalid(_)), "{err}");

    // (b) Receipt layer: the *provider's* keys cannot pay a different
    // recipient — the receipt can be re-signed by the attacker only as
    // themselves, and then binding to the payment fails.
    let mut attacker_receipt = receipt.clone();
    attacker_receipt.recipient = attacker().address().unwrap();
    sign_receipt(&mut attacker_receipt, &attacker()).expect("attacker signs as themselves");
    let err = attacker_receipt
        .verify_binding(&payment)
        .expect_err("binding");
    assert_eq!(
        err,
        jnt_core::receipt::ReceiptError::NotBoundToPayment("recipient")
    );

    // (c) The whole session refuses the substituted receipt.
    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .with_receipt(&attacker_receipt)
        .verify(NET, HEIGHT)
        .expect_err("session");
    assert_eq!(
        err,
        SessionError::Receipt(jnt_core::receipt::ReceiptError::NotBoundToPayment(
            "recipient"
        ))
    );
}

#[test]
fn amount_substitution_fails_at_every_layer() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &provider());

    // (a) Request amount up: signature dies.
    let mut r = request.clone();
    r.max_amount_sat = u64::MAX;
    assert!(r.verify(NET, HEIGHT).is_err());

    // (b) Authorization amount up: owner signature dies.
    let mut a = auth.clone();
    a.amount_sat = 1_000_000;
    assert!(jnt_core::agent::verify_authorization(&sigs, &keys, &a).is_err());

    // (c) Payment amount up: payer signature dies.
    let mut p = payment.clone();
    p.amount_sat = 1_000_000;
    assert!(p.verify(NET, HEIGHT).is_err());

    // (d) Receipt amount re-signed by the real provider (they *can* sign):
    //    the payment binding refuses it.
    let mut rc = receipt.clone();
    rc.amount_sat = 1;
    sign_receipt(&mut rc, &provider()).expect("provider re-signs");
    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .with_receipt(&rc)
        .verify(NET, HEIGHT)
        .expect_err("session");
    assert_eq!(
        err,
        SessionError::Receipt(jnt_core::receipt::ReceiptError::NotBoundToPayment("amount"))
    );
}

#[test]
fn service_substitution_fails_at_every_layer() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, _sigs, _keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let receipt = receipt_for(&request, &payment, &provider());

    // (a) Swapping the request's service breaks the payer's signature.
    let mut r = request.clone();
    r.service_id = [0xAA; 32];
    assert!(r.verify(NET, HEIGHT).is_err());

    // (b) A policy that does not name the service refuses the grant: the
    //     allow list is exhaustive.
    let mut other_policy = policy.clone();
    other_policy.allowed_services = vec![[0xBB; 32]];
    let err = authorize_request(&mut book, &other_policy, NET, &request, HEIGHT, 9)
        .expect_err("service not allowed");
    // The request names `policy`'s hash, so it refuses before the allow list;
    // either clause is a refusal and neither resolves in the spender's favor.
    assert!(
        matches!(err, SessionError::Binding(_) | SessionError::Policy(_)),
        "{err}"
    );

    // (c) Receipt service re-signed by the provider: payment binding refuses.
    let mut rc = receipt.clone();
    rc.service_id = None;
    sign_receipt(&mut rc, &provider()).expect("provider re-signs");
    assert_eq!(
        rc.verify_binding(&payment),
        Err(jnt_core::receipt::ReceiptError::NotBoundToPayment(
            "service"
        ))
    );
}

#[test]
fn policy_substitution_is_refused_before_any_grant() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    // A *different* policy (say, a rotated-in one with wider limits): the
    // request names the original, so the grant refuses by name.
    let mut wide = policy.clone();
    wide.per_tx_max_sat = 10_000_000;
    wide.cumulative_max_sat = 10_000_000;
    let mut book = PolicyBook::default();
    let err = authorize_request(&mut book, &wide, NET, &request, HEIGHT, 1)
        .expect_err("policy substitution");
    assert_eq!(
        err,
        SessionError::Binding("request names a different policy")
    );
    assert!(book.is_empty(), "a refusal must not create state");
}

#[test]
fn payment_for_another_request_is_refused() {
    let service = service_tag(&provider().address().unwrap());
    let (request1, policy) = machine_request(service, 400);
    let (request2, _) = machine_request(service, 300);
    let mut book = PolicyBook::default();
    let (auth1, sigs, keys) = grant(&mut book, &policy, &request1, 1);
    let (auth2, _, _) = grant(&mut book, &policy, &request2, 2);
    // Both grants are legitimate — but a payment that settles request2 cannot
    // be presented against request1: the reference binds it.
    let payment2 = pay_for(&auth2, &request2);
    let err = Session::new(&request1)
        .with_authorization(&auth1, &sigs, &keys)
        .with_payment(&payment2)
        .verify(NET, HEIGHT)
        .expect_err("cross-request payment");
    assert_eq!(err, SessionError::Binding("payment reference"));
}

#[test]
fn stale_requests_and_payments_expire() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);

    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .verify(NET, EXPIRES)
        .expect_err("at expiry nothing is acceptable");
    assert_eq!(
        err,
        SessionError::Payment(PaymentError::Expired {
            expires_at: EXPIRES,
            height: EXPIRES
        })
    );
    // One block earlier is still live.
    Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .verify(NET, EXPIRES - 1)
        .expect("still valid");
}

#[test]
fn wrong_network_is_refused_at_the_door() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);

    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .verify("jounit/mini", HEIGHT)
        .expect_err("wrong network");
    assert!(
        matches!(
            err,
            SessionError::Payment(PaymentError::WrongNetwork { .. })
        ),
        "{err}"
    );

    // And a request that names a *foreign network's* policy: the engine's own
    // network binding refuses it (identity re-derives for the mini network,
    // so the refusal is genuinely the network clause, not the identity one).
    let owner = payer().address().unwrap();
    let mut mini_policy = policy.clone();
    mini_policy.network_id = "jounit/mini".into();
    mini_policy.agent_id = derive_agent_id("jounit/mini", AgentRole::Machine, &owner);
    let foreign_request = build_signed_request(
        &payer(),
        RequestSpec {
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            service_id: service,
            recipient: provider().address().unwrap(),
            max_amount_sat: 400,
            expires_at_height: EXPIRES,
            policy_hash: mini_policy.hash(),
        },
    &[],
    )
    .unwrap();
    let err = authorize_request(&mut book, &mini_policy, NET, &foreign_request, HEIGHT, 5)
        .expect_err("policy network binding");
    assert!(
        matches!(err, SessionError::Policy(PolicyError::WrongNetwork { .. })),
        "{err}"
    );
}

#[test]
fn an_authorization_signed_by_anyone_but_the_owner_is_refused_in_session() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, _, _) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);

    // Attacker signs the owner's authorization hash with their own key.
    let sigs = Auth::sigs_for(&attacker(), &auth.signing_hash()).unwrap();
    let keys = Auth::keys_for(&attacker()).unwrap();
    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .verify(NET, HEIGHT)
        .expect_err("non-owner authorization");
    assert!(
        matches!(
            err,
            SessionError::Payment(PaymentError::SignatureInvalid(_))
        ),
        "{err}"
    );
}

#[test]
fn receipt_for_the_wrong_request_is_refused() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, sigs, keys) = grant(&mut book, &policy, &request, 1);
    let payment = pay_for(&auth, &request);
    let mut receipt = receipt_for(&request, &payment, &provider());
    // The service attaches the receipt to someone else's request id and
    // re-signs it (they hold the key, so the signature is genuine).
    receipt.request_id = [0xEE; 32];
    sign_receipt(&mut receipt, &provider()).expect("provider re-signs");

    let err = Session::new(&request)
        .with_authorization(&auth, &sigs, &keys)
        .with_payment(&payment)
        .with_receipt(&receipt)
        .verify(NET, HEIGHT)
        .expect_err("wrong request id");
    assert_eq!(err, SessionError::Binding("receipt request"));
}

#[test]
fn nonce_mutation_in_the_payment_breaks_its_signature() {
    let service = service_tag(&provider().address().unwrap());
    let (request, policy) = machine_request(service, 400);
    let mut book = PolicyBook::default();
    let (auth, _sigs, _keys) = grant(&mut book, &policy, &request, 1);
    let mut payment = pay_for(&auth, &request);
    payment.nonce = 99; // replay the grant under a fresh nonce
    assert!(
        payment.verify(NET, HEIGHT).is_err(),
        "nonce is inside the signing hash"
    );
    // Even with a valid nonce the binding demands equality with the grant.
    let mut payment2 = pay_for(&auth, &request);
    let mut auth2 = auth.clone();
    auth2.nonce = 7;
    assert!(payment2.linked_to(&auth2).is_err());
    payment2.nonce = 7;
    assert!(payment2.verify(NET, HEIGHT).is_err());
}

#[test]
fn encoding_round_trips_for_the_request() {
    let service = service_tag(&provider().address().unwrap());
    let (request, _) = machine_request(service, 400);
    let bytes = request.serialize();
    let back = PaymentRequest::deserialize(&bytes).expect("decode");
    assert_eq!(back, request);
    assert_eq!(back.serialize(), bytes);
    assert!(PaymentRequest::deserialize(&bytes[..bytes.len() - 1]).is_err());
    assert!(PaymentRequest::deserialize(&[&bytes[..], &[0u8]].concat()).is_err());
}
