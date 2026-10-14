//! Post-quantum signature path (scheme 3, FIPS 204 ML-DSA-65).
//!
//! Attacks, not smoke tests. The security claim is: a CRQC that breaks
//! secp256k1 can forge the classical components of a bundle and still cannot
//! spend, because (a) every component must verify, (b) the address commits to
//! the whole key set so a bundle cannot be reduced to its breakable half, and
//! (c) the length rules refuse a truncated component before any lattice work.

use jnt_core::sig::{verify_bundle, Bundle, Component, SCHEME_ML_DSA_65};
use jnt_core::tx::{Input, OutPoint, Output, Transaction};
use jnt_core::wallet::{SignMode, Wallet};

fn wallet() -> Wallet {
    Wallet::from_private_key_bytes(&[7u8; 32], "pq").unwrap()
}

/// A *different* wallet: `[7u8; 32]` reused would make every "attacker" the
/// same wallet as the honest one, and the forgery tests would pass for the
/// wrong reason.
fn attacker_wallet() -> Wallet {
    Wallet::from_private_key_bytes(&[9u8; 32], "attacker").unwrap()
}

fn pq_keys(w: &Wallet) -> Bundle {
    Bundle {
        components: vec![
            Component::new(1, w.pubkey().unwrap().to_vec()),
            Component::new(2, w.schnorr_pubkey().unwrap().to_vec()),
            Component::new(SCHEME_ML_DSA_65, w.ml_dsa_pubkey().unwrap()),
        ],
    }
}

fn pq_sigs(w: &Wallet, msg: &[u8; 32]) -> Bundle {
    Bundle {
        components: vec![
            Component::new(1, w.sign_digest(msg).unwrap().to_vec()),
            Component::new(2, w.sign_schnorr(msg).unwrap().to_vec()),
            Component::new(SCHEME_ML_DSA_65, w.sign_ml_dsa(msg).unwrap()),
        ],
    }
}

#[test]
fn a_post_quantum_bundle_verifies_and_commits_to_its_own_address() {
    let w = wallet();
    assert_eq!(w.ml_dsa_pubkey().unwrap().len(), 1952);

    let msg = [0x5Au8; 32];
    verify_bundle(&pq_sigs(&w, &msg), &pq_keys(&w), &msg).expect("a real PQ bundle verifies");

    // A PQ address is not the hybrid one: the address commits to the whole
    // key set, so funds at one are unspendable under the other.
    assert_ne!(w.pq_address().unwrap(), w.hybrid_address().unwrap());
    assert_ne!(w.pq_address().unwrap(), w.ecdsa_address().unwrap());
}

#[test]
fn a_post_quantum_signed_input_spends_only_from_its_own_pq_address() {
    // The full spend: a PQ-bundle input verified against the address its own
    // key set commits to passes, and against the hybrid address fails.
    let w = wallet();
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [3u8; 64],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [9u8; 20],
        }],
    );
    w.sign_mode(&mut tx, SignMode::PostQuantum).unwrap();

    assert!(tx.verify_input(0, &w.pq_address().unwrap(), false).is_ok());

    // The same bundle at the hybrid address is refused: the key set that
    // signed is not the one that address commits to.
    assert!(tx
        .verify_input(0, &w.hybrid_address().unwrap(), false)
        .is_err());
}

#[test]
fn a_crqc_attacker_cannot_spend_a_post_quantum_output() {
    // A machine that breaks secp256k1 can only produce perfect classical
    // components. Three things it cannot do, all of them named refusals.
    let honest = wallet();
    let attacker = attacker_wallet();
    let owner = honest.pq_address().unwrap();
    let msg = honest_tx_message();

    // 1. Sign with the attacker's own key set: the derivation does not name
    //    the owner, so the address check refuses before any crypto runs.
    let mut mine_theirs = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [3u8; 64],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [9u8; 20],
        }],
    );
    attacker
        .sign_mode(&mut mine_theirs, SignMode::PostQuantum)
        .unwrap();
    match mine_theirs.verify_input(0, &owner, false) {
        Err(e) => assert!(
            e.to_string().contains("does not own"),
            "a forger's key set must not resolve to the owner: {e}"
        ),
        Ok(()) => panic!("an attacker's own bundle must not spend the honest address"),
    }

    // 2. Keep the honest key bundle but replace the lattice component with
    //    one from another wallet under the same scheme id: the scheme matches,
    //    so this is the case a one-of-N verifier would wave through.
    let keys = pq_keys(&honest);
    let forgeries = Bundle {
        components: vec![
            Component::new(1, honest.sign_digest(&msg).unwrap().to_vec()),
            Component::new(2, honest.sign_schnorr(&msg).unwrap().to_vec()),
            Component::new(SCHEME_ML_DSA_65, attacker.sign_ml_dsa(&msg).unwrap()),
        ],
    };
    assert!(verify_bundle(&forgeries, &keys, &msg).is_err());

    // 3. Strip the lattice component out entirely, leaving a valid hybrid
    //    bundle: fewer components than the address commits to.
    let reduced = Bundle {
        components: vec![
            Component::new(1, honest.sign_digest(&msg).unwrap().to_vec()),
            Component::new(2, honest.sign_schnorr(&msg).unwrap().to_vec()),
        ],
    };
    assert!(verify_bundle(&reduced, &keys, &msg).is_err());

    // And a genuine PQ signature does not transfer to another message.
    assert!(verify_bundle(&pq_sigs(&honest, &msg), &keys, &other_msg()).is_err());
}

/// A message the same wallet did not sign, so a replay attempt tests transfer.
fn other_msg() -> [u8; 32] {
    [0xBEu8; 32]
}

/// The message a one-input transaction commits its input 0 to.
fn honest_tx_message() -> [u8; 32] {
    let tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [3u8; 64],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [9u8; 20],
        }],
    );
    tx.message_for_input(0)
}

#[test]
fn a_wrong_length_lattice_component_is_refused_before_any_lattice_work() {
    let w = wallet();
    let msg = [0x33u8; 32];
    // One component on each side, so the count rule is satisfied and the
    // length rule inside the scheme is what refuses.
    let keys = Bundle::single(SCHEME_ML_DSA_65, w.ml_dsa_pubkey().unwrap());
    let mut short = w.sign_ml_dsa(&msg).unwrap();
    short.pop();
    let err = verify_bundle(&Bundle::single(SCHEME_ML_DSA_65, short), &keys, &msg).unwrap_err();
    assert!(
        err.to_string().contains("length"),
        "the length rule should name itself: {err}"
    );
}

#[test]
fn the_hybrid_requirement_is_about_arity_and_the_pq_requirement_is_about_content() {
    // `require_hybrid` rejects a single-scheme input. A PQ-ready bundle
    // satisfies it, and so must a plain hybrid one: the flag is a floor on
    // component count, which is what keeps it usable while scheme 3 is
    // optional. What makes a bundle *post-quantum* is the lattice component
    // being present, which is the address's job to pin.
    let w = wallet();
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [3u8; 64],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [9u8; 20],
        }],
    );

    w.sign_mode(&mut tx, SignMode::Classical).unwrap();
    assert!(tx
        .verify_input(0, &w.ecdsa_address().unwrap(), true)
        .is_err());

    w.sign_mode(&mut tx, SignMode::Hybrid).unwrap();
    assert!(tx
        .verify_input(0, &w.hybrid_address().unwrap(), true)
        .is_ok());

    w.sign_mode(&mut tx, SignMode::PostQuantum).unwrap();
    assert!(tx.verify_input(0, &w.pq_address().unwrap(), true).is_ok());
}
