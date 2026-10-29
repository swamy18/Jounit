//! Migration-rule primitive (Decision 24, step 4): `verify_input_pq`.
//!
//! Three cases, no more: a PQ bundle passes, a hybrid one is refused, a
//! classical one is refused. Consensus does not call this yet — the tests pin
//! the primitive the activation will flip to, not the flip itself.

use srct_core::tx::{Input, OutPoint, Output, Transaction};
use srct_core::wallet::{SignMode, Wallet};

fn wallet() -> Wallet {
    Wallet::from_private_key_bytes(&[7u8; 32], "migrate").unwrap()
}

fn spend() -> Transaction {
    Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [3u8; 64],
            index: 0,
        })],
        vec![Output {
            value: 1_000,
            address: [9u8; 20],
        }],
    )
}

#[test]
fn a_post_quantum_input_satisfies_the_migration_rule() {
    let w = wallet();
    let mut tx = spend();
    w.sign_mode(&mut tx, SignMode::PostQuantum).unwrap();
    assert!(tx.verify_input_pq(0, &w.pq_address().unwrap()).is_ok());
}

#[test]
fn a_hybrid_input_is_refused_by_the_migration_rule() {
    let w = wallet();
    let mut tx = spend();
    w.sign_mode(&mut tx, SignMode::Hybrid).unwrap();
    assert!(tx.verify_input_pq(0, &w.hybrid_address().unwrap()).is_err());
}

#[test]
fn a_classical_input_is_refused_by_the_migration_rule() {
    let w = wallet();
    let mut tx = spend();
    w.sign_mode(&mut tx, SignMode::Classical).unwrap();
    assert!(tx.verify_input_pq(0, &w.ecdsa_address().unwrap()).is_err());
}
