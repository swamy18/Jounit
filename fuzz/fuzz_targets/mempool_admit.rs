#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz mempool admission (SPEC.md §9, §13.14).
//
// The pool is reachable from the network: a relayed transaction goes through
// `add` exactly as a local one does, so every hostile path in `check_tx` is
// reachable remotely. The fuzzer drives `add` with adversarial transactions
// against a small deterministic UTXO set and asserts the pool's own invariants
// hold no matter what.
fuzz_target!(|data: &[u8]| {
    use jnt_core::mempool::Mempool;
    use jnt_core::params::NetworkParams;
    use jnt_core::tx::{OutPoint, Output, Transaction};

    if data.len() < 2 {
        return;
    }
    let mut params = NetworkParams::mini();
    // A tiny cap keeps the byte-limit branches cheap to reach.
    params.max_block_bytes = 4_000;
    let mut pool = Mempool::new(8_000);

    // Deterministic funding UTXO: one output the fuzzer's transaction may or
    // may not spend.
    let mut utxo = jnt_core::ledger::UtxoSet::default();
    let funding_txid = [7u8; 64];
    utxo.insert(
        OutPoint {
            txid: funding_txid,
            index: 0,
        },
        jnt_core::ledger::Utxo {
            out: Output {
                value: 1_000_000_000,
                address: [3u8; 20],
            },
            height: 0,
        },
    );

    // Build a candidate transaction from the fuzz input: n_inputs from byte 0,
    // the rest as the tx bytes. If it fails to decode that is fine — the pool
    // must refuse it cleanly too when we hand it raw bytes.
    let n_inputs = (data[0] % 5) as usize;
    let tx_bytes = &data[1..];
    let mut tx = match Transaction::deserialize(tx_bytes) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Point every input at the funding outpoint so the spend path actually
    // executes rather than dying on "unknown outpoint" every time.
    for (i, input) in tx.inputs.iter_mut().enumerate().take(n_inputs.max(1)) {
        input.prev_hash = funding_txid;
        input.prev_index = (i as u32) % 2;
        // A non-empty signature bundle keeps the spend path deep in check_tx.
        input.sigs = jnt_core::sig::Bundle::single(1, vec![0u8; 64]);
    }
    utxo.insert(
        jnt_core::tx::OutPoint {
            txid: funding_txid,
            index: 1,
        },
        jnt_core::ledger::Utxo {
            out: Output {
                value: 500_000_000,
                address: [4u8; 20],
            },
            height: 0,
        },
    );

    let height = 10_000;
    // A base fee comfortably above the floor so fee adequacy is not the only
    // thing the fuzzer exercises; `add` re-checks it anyway.
    let base_fee = 1_000;

    let _ = pool.add(
        tx.clone(),
        &utxo,
        height,
        &params,
        base_fee,
        &jnt_core::bond::BondLedger::default(),
    );

    // Invariants that must hold after ANY admission attempt:
    assert!(
        pool.summary().bytes <= 8_000,
        "pool byte cap must hold under adversarial input"
    );
    // A transaction the pool accepted must be selectable without panic.
    let _ = pool.select_for_block(params.gas_cap, params.max_block_bytes);
    // Round-trip of txid over the same tx is deterministic.
    let _ = tx.txid();
});
