//! L2 state-root commitment and account inclusion proofs — P1 exit proof.
//!
//! These tests pin the *proof surface only*. Nothing here asserts a consensus
//! rule, because none was added: `jnt-core/src/state_root.rs` grants no
//! authority and no L1 rule consumes a proof yet. What is asserted is that the
//! commitment is honest when an exit rule does arrive:
//!
//! - a real account proves against the real root, at every state size;
//! - a forged balance does **not** prove (the whole point of the exercise);
//! - an absent account has no proof, rather than a proof of zero;
//! - a proof taken before a state change does not verify against the root after
//!   it — the property a reorg or a replay correction depends on;
//! - building a root changes nothing about conservation or balances.

use jnt_core::hash::{Address, Hash};
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::state_root::account_leaf;
use jnt_l2::{L2Config, L2Genesis, L2State};

fn genesis() -> L2Genesis {
    L2Genesis::for_params(&NetworkParams::mini())
}

fn funded() -> L2State {
    let mut s = L2State::new(L2Config::mini());
    s.apply_genesis(&genesis()).unwrap();
    s
}

fn escrow_addr() -> Address {
    NetworkParams::mini().l2_escrow_address()
}

#[test]
fn every_real_account_proves_against_the_root() {
    let s = funded();
    assert!(s.total_accounts() > 1, "genesis should open accounts");
    let root = s.state_root();
    for (addr, balance) in s.account_leaves() {
        let proof = s
            .account_proof(&addr)
            .unwrap_or_else(|| panic!("no proof for an existing account"));
        assert!(
            jnt_core::state_root::verify_inclusion(root, account_leaf(&addr, balance), &proof),
            "existing account failed to prove"
        );
        assert!(s.verify_account(&addr, balance));
        assert_eq!(
            s.balance(&addr),
            balance,
            "proof must describe the real balance"
        );
    }
}

#[test]
fn a_forged_balance_does_not_prove() {
    let s = funded();
    let real = s.balance(&escrow_addr());
    assert!(s.verify_account(&escrow_addr(), real));
    // One satoshi more than the commitment contains.
    assert!(!s.verify_account(&escrow_addr(), real + 1));
    // And the whole escrow, which would be the interesting forgery.
    assert!(!s.verify_account(&escrow_addr(), real * 2 + 1));
}

#[test]
fn an_absent_account_has_no_proof_rather_than_a_proof_of_zero() {
    let s = funded();
    let stranger: Address = [0xAB; 20];
    assert_eq!(s.balance(&stranger), 0);
    assert!(
        s.account_proof(&stranger).is_none(),
        "an account that does not exist must not be provable"
    );
    assert!(!s.verify_account(&stranger, 0));
}

#[test]
fn a_proof_from_before_a_change_does_not_verify_after_it() {
    let mut s = funded();
    let addr = escrow_addr();
    let before_balance = s.balance(&addr);
    let before_root = s.state_root();
    let proof = s.account_proof(&addr).unwrap();

    // A real state change, the same shape a deposit or a settlement makes.
    s.credit(addr, 5 * SAT_PER_JNT).unwrap();

    let after_root = s.state_root();
    assert_ne!(
        before_root, after_root,
        "a balance change must move the root"
    );
    assert!(
        !jnt_core::state_root::verify_inclusion(
            after_root,
            account_leaf(&addr, before_balance),
            &proof
        ),
        "a stale proof must not verify against the new root"
    );
    // The same proof still describes the old commitment exactly.
    assert!(jnt_core::state_root::verify_inclusion(
        before_root,
        account_leaf(&addr, before_balance),
        &proof
    ));
    // And the honest current proof verifies against the current root.
    assert!(s.verify_account(&addr, s.balance(&addr)));
}

#[test]
fn the_root_is_deterministic_and_order_independent_of_insertion() {
    // Two states built by different insertion orders must commit identically:
    // a root that depended on HashMap iteration order would not be consensus
    // material at all.
    let mut a = L2State::new(L2Config::mini());
    let mut b = L2State::new(L2Config::mini());
    let (x, y): (Address, Address) = ([0x11; 20], [0x22; 20]);
    a.credit(x, 100).unwrap();
    a.credit(y, 200).unwrap();
    b.credit(y, 200).unwrap();
    b.credit(x, 100).unwrap();
    assert_eq!(a.account_leaves(), b.account_leaves());
    assert_eq!(a.state_root(), b.state_root());
}

#[test]
fn committing_the_state_moves_no_value() {
    let s = funded();
    let accounts_before = s.total_accounts();
    let funded_before = s.funded_total();
    let conservation_before = s.conservation_total();
    let root = s.state_root();
    let _ = s.account_leaves();
    let _ = s.account_proof(&escrow_addr());

    // A commitment is a read. Every counter is untouched by taking it.
    assert_eq!(s.total_accounts(), accounts_before);
    assert_eq!(s.funded_total(), funded_before);
    assert_eq!(s.conservation_total(), conservation_before);
    assert!(s.check_conservation());
    assert_ne!(
        root,
        Hash::default(),
        "a funded state is not the empty root"
    );
}

#[test]
fn an_empty_state_has_the_empty_root_and_no_proofs() {
    let s = L2State::new(L2Config::mini());
    assert_eq!(s.account_leaves().len(), 0);
    assert_eq!(s.state_root(), [0u8; 32]);
    assert!(s.account_proof(&[0x01; 20]).is_none());
}
