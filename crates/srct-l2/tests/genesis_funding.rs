//! L2 genesis funding tests — Decision 7, SPEC.md §19.4.
//!
//! What these pin at the state level (node flow is in
//! `srct-node/tests/l2_funding.rs`):
//!
//! - genesis funds exactly the grants plus the escrow remainder, with exact
//!   balances and nothing else;
//! - a second application is refused by name (no duplicate funding, ever);
//! - malformed allocations fail closed (duplicate, zero, escrow-named,
//!   over-total, over-gap);
//! - the joint invariant composes on both profiles: L1 reachable plus L2
//!   escrow stays under the cap, so no L1 rule had to change;
//! - conservation is self-proving after every step.

use srct_core::compute_ir::{ComputeBackend, ComputeTask};
use srct_core::l2::{L2Payload, L2Transaction, PostTaskPayload};
use srct_core::params::{NetworkParams, SAT_PER_SRCT};
use srct_core::wallet::Wallet;
use srct_l2::{L2Config, L2Error, L2Genesis, L2State};

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "genesis-funding-test").unwrap()
}

fn mini_genesis() -> L2Genesis {
    L2Genesis::for_params(&NetworkParams::mini())
}

fn funded_state() -> L2State {
    let mut s = L2State::new(L2Config::mini());
    s.apply_genesis(&mini_genesis()).unwrap();
    s
}

fn post(seed: u8, nonce: u64, deadline: u64) -> L2Transaction {
    let w = wallet(seed);
    let task = ComputeTask {
        task_id: [0x11u8; 32],
        ir_hash: [0x22u8; 32],
        input_hash: [0x33u8; 32],
        required_memory_bytes: 4 * 1024 * 1024,
        backend_hint: ComputeBackend::Gpu,
        reward_sat: 1_000_000,
        expiry_height: deadline,
        submit_height: 1,
    };
    L2Transaction::new(L2Payload::Post(
        PostTaskPayload::build(&w, nonce, 5_000_000, deadline, task).unwrap(),
    ))
}

#[test]
fn genesis_funds_grants_and_escrow_remainder_exactly() {
    let g = mini_genesis();
    g.validate().unwrap();
    assert_eq!(g.escrow_total_sat, 10 * SAT_PER_SRCT);
    assert_eq!(g.granted_total().unwrap(), 3 * SAT_PER_SRCT);
    assert_eq!(g.escrow_remainder().unwrap(), 7 * SAT_PER_SRCT);

    let s = funded_state();
    assert!(s.has_genesis());
    // Each operator grant lands whole.
    for seed in [1u8, 2, 3] {
        assert_eq!(
            s.balance(&wallet(seed).address().unwrap()),
            SAT_PER_SRCT,
            "seed {seed} grant missing"
        );
    }
    // The remainder parks with the protocol identity — and nowhere else.
    let params = NetworkParams::mini();
    assert_eq!(s.balance(&params.l2_escrow_address()), 7 * SAT_PER_SRCT);
    assert_eq!(s.balance(&[0x77u8; 20]), 0);
    // The invariant holds from the first state: released == held.
    assert_eq!(s.funded_total(), g.escrow_total_sat);
    assert!(s.check_conservation());
}

#[test]
fn genesis_applies_exactly_once() {
    let g = mini_genesis();
    let mut s = L2State::new(L2Config::mini());
    s.apply_genesis(&g).unwrap();
    let err = s.apply_genesis(&g).unwrap_err();
    assert_eq!(err, L2Error::GenesisAlreadyApplied);
    // The refusal wrote nothing: balances and totals are untouched.
    assert_eq!(s.funded_total(), g.escrow_total_sat);
    assert!(s.check_conservation());
}

#[test]
fn empty_genesis_changes_nothing() {
    // Unit-test states built via `credit` keep working: empty genesis funds
    // nothing, refuses nothing, and still marks itself applied.
    let mut s = L2State::new(L2Config::mini());
    s.apply_genesis(&L2Genesis::empty()).unwrap();
    assert!(s.has_genesis());
    assert_eq!(s.funded_total(), 0);
    assert!(s.check_conservation());
    s.credit([9u8; 20], 100).unwrap();
    assert_eq!(s.funded_total(), 100);
    assert!(s.check_conservation());
}

#[test]
fn two_genesis_constructions_agree_exactly() {
    let (mut a, mut b) = (
        L2State::new(L2Config::mini()),
        L2State::new(L2Config::mini()),
    );
    a.apply_genesis(&mini_genesis()).unwrap();
    b.apply_genesis(&mini_genesis()).unwrap();
    assert_eq!(a, b, "genesis must be a pure function of params");
}

#[test]
fn funded_post_moves_value_and_conservation_holds() {
    use srct_core::bls_checkpoint::{MockBls, ValidatorSet};

    let mut s = funded_state();
    let tx = post(1, 1, 200);
    let before = s.balance(&wallet(1).address().unwrap());
    let (set, verifier) = (ValidatorSet::new(Vec::new()), MockBls);
    s.apply(&tx, 1, &set, &verifier).unwrap();

    // Payment plus the D3 fee leaves the account; nothing leaves the system.
    let fee = tx.fee_sat();
    assert_eq!(
        s.balance(&wallet(1).address().unwrap()),
        before - 5_000_000 - fee
    );
    assert!(s.task_count() == 1);
    assert_eq!(s.funded_total(), 10 * SAT_PER_SRCT);
    assert!(s.check_conservation());
}

#[test]
fn unfunded_account_still_fails_closed_with_genesis_present() {
    use srct_core::bls_checkpoint::{MockBls, ValidatorSet};

    // Genesis funds others; seed 9 holds nothing, so its post is refused by
    // name — funding your neighbours does not fund you.
    let mut s = funded_state();
    let (set, verifier) = (ValidatorSet::new(Vec::new()), MockBls);
    let err = s.apply(&post(9, 1, 200), 1, &set, &verifier).unwrap_err();
    assert!(
        matches!(err, L2Error::InsufficientBalance { available: 0, .. }),
        "got {err:?}"
    );
    assert!(s.check_conservation());
}

#[test]
fn malformed_allocations_fail_closed() {
    let g = mini_genesis();
    // Duplicate grantee pays twice.
    let mut dup = g.clone();
    dup.grants.push(dup.grants[0]);
    assert!(matches!(dup.validate(), Err(L2Error::InvalidGenesis(_))));
    let mut s = L2State::new(L2Config::mini());
    assert!(s.apply_genesis(&dup).is_err());
    assert!(!s.has_genesis());
    assert_eq!(s.funded_total(), 0);

    // Zero grant.
    let mut zero = g.clone();
    zero.grants[0].1 = 0;
    assert!(matches!(zero.validate(), Err(L2Error::ZeroAmount(_))));

    // Grant naming the escrow identity blurs backing and remainder.
    let mut esc = g.clone();
    esc.grants[0].0 = esc.escrow_id;
    assert!(matches!(esc.validate(), Err(L2Error::InvalidGenesis(_))));

    // Grants above the total invent value.
    let mut over = g.clone();
    over.grants[0].1 = over.escrow_total_sat + 1;
    assert!(over.validate().is_err());
    assert!(over.escrow_remainder().is_err());
    let mut s = L2State::new(L2Config::mini());
    assert!(s.apply_genesis(&over).is_err());
    // A refused genesis funds nothing and marks nothing applied: a later
    // valid genesis still applies cleanly.
    assert!(!s.has_genesis());
    s.apply_genesis(&g).unwrap();
    assert_eq!(s.funded_total(), g.escrow_total_sat);
}

#[test]
fn l2_genesis_escrow_fits_under_its_own_ceiling_on_both_profiles() {
    // The composition the whole model rests on, stated in one place: L1 is
    // bounded by the issuance integral (checked by the mint gate), and L2's
    // genesis side is bounded by its own validated ceiling (approved M-E).
    // There is no stock cap any more (Decision 18), so the escrow's own
    // ceiling is the bound this test pins.
    for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
        p.validate().unwrap();
        let g = L2Genesis::for_params(&p);
        g.validate().unwrap();
        assert!(
            g.escrow_total_sat <= p.escrow_ceiling_sat,
            "{}: escrow would breach its ceiling",
            p.name
        );
        // And the escrow identity is bound to its own network.
        assert_eq!(
            g.escrow_id,
            p.l2_escrow_address(),
            "escrow identity must derive from its profile"
        );
    }
    assert_ne!(
        L2Genesis::for_params(&NetworkParams::mini()).escrow_id,
        L2Genesis::for_params(&NetworkParams::mainnet()).escrow_id,
        "escrow identities must not cross networks"
    );
}

#[test]
fn mainnet_genesis_is_escrow_only() {
    // No hard-coded mainnet beneficiaries: real allocation arrives with the
    // deposit mechanism. The escrow total is still reserved inside the gap.
    let g = L2Genesis::for_params(&NetworkParams::mainnet());
    g.validate().unwrap();
    assert!(g.grants.is_empty());
    assert_eq!(g.escrow_total_sat, 100_000 * SAT_PER_SRCT);
    assert_eq!(
        g.escrow_remainder().unwrap(),
        g.escrow_total_sat,
        "with no grants the whole escrow parks with the protocol"
    );
    let mut s = L2State::new(L2Config::mainnet());
    s.apply_genesis(&g).unwrap();
    assert_eq!(
        s.balance(&NetworkParams::mainnet().l2_escrow_address()),
        100_000 * SAT_PER_SRCT
    );
    assert!(s.check_conservation());
}
