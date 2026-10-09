//! The L2 deposit sink has no spender — proven against the real L1 spend rule.
//!
//! This is the finding that makes an L2 → L1 exit a **consensus change** rather
//! than an implementation detail, so it is pinned as a test rather than stated
//! in prose.
//!
//! `NetworkParams::l2_deposit_sink()` is `SHA256(domain_tag ‖ network_id)[..20]`
//! — a hash of public data with no known preimage, not a key anyone holds. Every
//! L1 spend must satisfy [`ledger::check_tx`], which ends in
//! `tx.verify_input(k, &held.out.address, …)`: the input's signature must verify
//! against the **address of the output being spent**, not against whatever key
//! the spender happens to own. No signature can verify against an address for
//! which no key exists, so a sink output is permanently unspendable — and no
//! amount of L2 state can change that.
//!
//! The consequence, and the reason this file exists: value that reaches the sink
//! can only be moved by a **new consensus rule** that authorises it. There is no
//! privileged API, no operator key, and no signature that can reclaim it. A
//! withdrawal implementation that "releases" sink funds without such a rule
//! would have to bypass `check_tx`, which is exactly the minting path this
//! repository forbids.
//!
//! The tests below are adversarial: they give the *depositor* its own coins back
//! on the most plausible reclaim path, and require the refusal anyway.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::hash::Address;
use jnt_core::ledger::check_tx;
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::tx::{Input, OutPoint, Output};
use jnt_core::wallet::Wallet;

// The transaction cost model, mirrored from `jnt_core::tx` so a fee is computed
// the same way the consensus rule computes it.
const GAS_TX_BASE: u64 = 16_000;
const GAS_PER_INPUT: u64 = 1_000;
const GAS_PER_OUTPUT: u64 = 250;

fn gas(n_in: u64, n_out: u64) -> u64 {
    GAS_TX_BASE + GAS_PER_INPUT * n_in + GAS_PER_OUTPUT * n_out
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "sink-unspendable").unwrap()
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Mine `n` empty blocks to `to`.
fn mine(chain: &mut Chain, to: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(to, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// Mine blocks until `height` reaches `target`.
fn mine_to(chain: &mut Chain, to: Address, target: u64) {
    while chain.height() < target {
        mine(chain, to, 1);
    }
}

/// A chain holding a real, matured deposit to the sink. Returns the chain, the
/// depositor's wallet, and the sink outpoint — the whole obstacle in one value.
fn chain_with_a_matured_sink_output() -> (Chain, Wallet, OutPoint, u64) {
    let net = NetworkParams::mini();
    let mut chain = Chain::new(net.clone()).unwrap();
    let depositor = wallet(1);
    let depositor_addr = depositor.address().unwrap();
    // Mature the first coinbase (mini maturity is 10 blocks).
    mine(&mut chain, depositor_addr, 11);

    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = jnt_core::supply::block_reward_sat(chain.params(), 1);
    let fee = chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas(1, 2))
        .saturating_add(1_000_000);
    let to_sink = 2 * SAT_PER_JNT;
    let deposit = depositor
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: net.l2_deposit_sink(),
                },
                Output {
                    value: reward - to_sink - fee,
                    address: depositor_addr,
                },
            ],
            fee,
        )
        .unwrap();
    let h = chain.height() + 1;
    let block = chain
        .mine_block(depositor_addr, vec![deposit.clone()], ts(h))
        .unwrap();
    chain.submit(block).unwrap();

    // Respect the maturity rule that applies to every output.
    let deposit_height = chain.height();
    let matures = deposit_height + net.coinbase_maturity;
    mine_to(&mut chain, depositor_addr, matures);

    let sink_op = OutPoint {
        txid: deposit.txid(),
        index: 0,
    };
    (chain, depositor, sink_op, to_sink)
}

/// The load-bearing assertion: the depositor cannot take its own deposit back.
///
/// This is the most plausible "unauthorized path" — the coins were the
/// depositor's a block earlier, and it holds the key that spent them into the
/// sink. The refusal is `WrongAddress`, because the signature verifies against
/// the depositor, and `check_tx` compares it to the *sink*, not to the depositor.
#[test]
fn the_depositor_cannot_reclaim_its_own_sink_output() {
    let (chain, depositor, sink_op, to_sink) = chain_with_a_matured_sink_output();
    let net = chain.params();
    let depositor_addr = depositor.address().unwrap();

    // The output is genuinely there: the refusal below is about authorization,
    // not about the outpoint being unknown or absent.
    let held = chain
        .utxo()
        .get(&sink_op)
        .expect("sink output is in the UTXO set");
    assert_eq!(held.out.address, net.l2_deposit_sink());
    assert_eq!(held.out.value, to_sink);

    let height = chain.height() + 1;
    let base_fee = chain.expected_base_fee_for_next_block();
    let fee = base_fee.saturating_mul(gas(1, 1)).saturating_add(1_000_000);
    let reclaim = depositor
        .build_tx(
            &[sink_op],
            vec![Output {
                value: to_sink - fee,
                address: depositor_addr,
            }],
            fee,
        )
        .expect("the wallet can build and sign the attempt");

    let err = check_tx(
        chain.utxo(),
        &reclaim,
        height,
        net,
        base_fee,
        net.coinbase_maturity,
    )
    .expect_err("a sink output must never be spendable");
    assert!(
        matches!(err, Error::WrongAddress),
        "expected the ownership check to refuse, got {err:?}"
    );
}

/// A stranger's attempt fares no better — this is not about who is asking.
#[test]
fn a_stranger_cannot_spend_a_sink_output_either() {
    let (chain, _depositor, sink_op, to_sink) = chain_with_a_matured_sink_output();
    let net = chain.params();
    let stranger = wallet(2);
    let stranger_addr = stranger.address().unwrap();

    let height = chain.height() + 1;
    let base_fee = chain.expected_base_fee_for_next_block();
    let fee = base_fee.saturating_mul(gas(1, 1)).saturating_add(1_000_000);
    let steal = stranger
        .build_tx(
            &[sink_op],
            vec![Output {
                value: to_sink - fee,
                address: stranger_addr,
            }],
            fee,
        )
        .unwrap();

    let err = check_tx(
        chain.utxo(),
        &steal,
        height,
        net,
        base_fee,
        net.coinbase_maturity,
    )
    .expect_err("a sink output must never be spendable");
    assert!(matches!(err, Error::WrongAddress), "got {err:?}");
}

/// Without a signature there is nothing to verify, and the spend is refused
/// even earlier than the ownership check — the sink must not be spendable "by
/// omission" either.
///
/// The variant is pinned deliberately: `EmptySignatureBundle` proves the
/// refusal happens *before* `verify_input` runs, so a would-be spender cannot
/// reach the ownership comparison at all, let alone pass it.
#[test]
fn an_unsigned_spend_of_a_sink_output_is_refused() {
    let (chain, _depositor, sink_op, to_sink) = chain_with_a_matured_sink_output();
    let net = chain.params();
    let height = chain.height() + 1;
    let base_fee = chain.expected_base_fee_for_next_block();

    let unsigned = jnt_core::tx::Transaction::standard(
        vec![Input::unsigned(&sink_op)],
        vec![Output {
            value: to_sink - 1,
            address: [9u8; 20],
        }],
    );
    let err = check_tx(
        chain.utxo(),
        &unsigned,
        height,
        net,
        base_fee,
        net.coinbase_maturity,
    )
    .expect_err("an unsigned spend of a sink output must be refused");
    assert!(
        matches!(err, Error::EmptySignatureBundle),
        "an unsigned spend must be refused before the ownership check, got {err:?}"
    );
}

/// The sink and the escrow identity are distinct, and both are derived rather
/// than owned — so neither is spendable, and a deposit can never fund the
/// escrow (or the reverse) by confusion.
#[test]
fn the_sink_and_the_escrow_identity_are_distinct_derived_addresses() {
    let mini = NetworkParams::mini();
    let mainnet = NetworkParams::mainnet();
    assert_ne!(mini.l2_deposit_sink(), mini.l2_escrow_address());
    assert_ne!(mainnet.l2_deposit_sink(), mainnet.l2_escrow_address());
    // Bound to the network: a mainnet sink output on mini is an ordinary burn.
    assert_ne!(mini.l2_deposit_sink(), mainnet.l2_deposit_sink());
    // Derived, not owned: no wallet address in a sample can equal either one.
    // Seeds start at 1 because `[0u8; 32]` is not a valid secp256k1 scalar.
    for seed in 1..=16u8 {
        let addr = wallet(seed).address().unwrap();
        assert_ne!(addr, mini.l2_deposit_sink());
        assert_ne!(addr, mini.l2_escrow_address());
    }
}
