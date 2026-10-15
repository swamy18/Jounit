//! Joint L1 + L2 conservation accounting — the check an L2 → L1 exit must
//! preserve (SPEC.md §19.4–§19.5).
//!
//! These drive the real path: mined blocks, a real signed deposit to the sink,
//! maturity by replay, and the extracted `jnt_node::conservation` module that
//! `jnt-node verify` now reports from.
//!
//! The sink term gets its own test because it is the one that breaks first if an
//! exit is implemented carelessly: a deposit is counted on **both** sides (an
//! unspendable L1 output and its credited L2 twin), so the joint total subtracts
//! the sink-held value once. A release that moved value out of L2 without
//! reducing that outstanding claim would read as inflation, not as a payment.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::hash::Address;
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::tx::{OutPoint, Output};
use jnt_core::wallet::Wallet;
use jnt_node::conservation::{joint_supply, verify_conservation, ConservationError};
use jnt_node::l2::NodeL2;

fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "conservation-test").unwrap()
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

fn mine(chain: &mut Chain, to: Address, n: u64) {
    for _ in 0..n {
        let h = chain.height() + 1;
        let b = chain.mine_block(to, vec![], ts(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

fn fee_for(chain: &Chain, n_in: u64, n_out: u64) -> u64 {
    let gas = 16_000 + 1_000 * n_in + 250 * n_out;
    chain
        .expected_base_fee_for_next_block()
        .saturating_mul(gas)
        .saturating_add(1_000_000)
}

/// A chain holding one matured deposit to the sink, and the replay view that
/// credits it. Returns `(chain, view, depositor_address, deposited_sat)`.
fn chain_with_a_matured_deposit() -> (Chain, NodeL2, Address, u64) {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let depositor = wallet(7);
    let depositor_addr = depositor.address().unwrap();
    // Mature the first coinbase (mini maturity is 10 blocks).
    mine(&mut chain, depositor_addr, 11);

    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = jnt_core::supply::block_reward_sat(chain.params(), 1);
    let fee = fee_for(&chain, 1, 2);
    let to_sink = 3 * SAT_PER_JNT;
    let deposit = depositor
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: params.l2_deposit_sink(),
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
        .mine_block(depositor_addr, vec![deposit], ts(h))
        .unwrap();
    chain.submit(block).unwrap();

    // Mature it: depth >= finality_depth (mini: 20) so L2 credits it.
    mine(&mut chain, depositor_addr, params.finality_depth + 1);

    let view = NodeL2::replay_from(&chain, &params).unwrap();
    assert_eq!(
        view.state().balance(&depositor_addr),
        to_sink,
        "the deposit must actually be credited for these tests to mean anything"
    );
    (chain, view, depositor_addr, to_sink)
}

#[test]
fn joint_supply_subtracts_the_sink_exactly_once() {
    let (chain, view, _depositor, to_sink) = chain_with_a_matured_deposit();
    let s = joint_supply(&chain, &view);

    // The sink term is real and non-zero: without it the joint total would
    // double-count every deposit.
    assert_eq!(
        s.sink_held_sat, to_sink,
        "the sink must hold exactly the deposited principal"
    );
    assert!(s.sink_held_sat > 0, "this test must exercise the sink term");
    assert_eq!(
        s.joint_sat,
        s.l1_live_sat + s.l2_held_sat - s.sink_held_sat,
        "joint = l1 live + l2 held - sink held"
    );
    // Subtracting the sink is what keeps the total below the un-adjusted sum.
    assert!(s.joint_sat < s.l1_live_sat + s.l2_held_sat);
    // The bound terms: L1's issuance integral at the tip plus the escrow
    // ceiling; there is no stock cap term any more (Decision 18).
    assert_eq!(s.l1_live_sat, chain.utxo().total_value());
    assert_eq!(s.escrow_ceiling_sat, chain.params().escrow_ceiling_sat);
}

#[test]
fn verify_conservation_passes_with_a_real_deposit_and_reports_headroom() {
    let (chain, view, _depositor, _) = chain_with_a_matured_deposit();
    let s = verify_conservation(&chain, &view).expect("a healthy chain must conserve");
    assert!(
        s.headroom_sat() > 0,
        "a real chain occupies only a fraction of the cap"
    );
    assert!(!s.exceeds_bound());
    // The joint bound is the issuance integral plus the escrow ceiling; the
    // sanity cap is reported but no longer decides the verdict.
    assert_eq!(
        s.bound_sat(),
        s.l1_bound_sat + s.escrow_ceiling_sat,
        "the bound must be the two authorities added"
    );
    assert_eq!(s.escrow_ceiling_sat, chain.params().escrow_ceiling_sat);
    assert_eq!(
        s.l1_bound_sat,
        jnt_core::supply::cumulative_issuance_sat(chain.params(), chain.height()),
        "L1's bound must be the same integral the chain mints against"
    );
    // L2 holds exactly the genesis escrow plus the deposit that arrived.
    assert_eq!(
        s.l2_held_sat,
        view.genesis().escrow_total_sat + view.state().deposited_total()
    );
}

#[test]
fn verify_conservation_passes_on_an_empty_chain() {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let view = NodeL2::fresh(&params).unwrap();
    let s = verify_conservation(&chain, &view).expect("genesis-only state must conserve");
    assert_eq!(s.sink_held_sat, 0, "no deposits yet");
    assert_eq!(s.l2_held_sat, params.l2_genesis_escrow_sat);
}

/// Value released into L2 by anything other than genesis funding or a matured
/// deposit is caught — this is the check that would fail if an exit credited L2
/// without an L1 counterpart, or an L1 release forgot to debit L2.
#[test]
fn l2_funding_from_an_unauthorized_path_is_refused_by_name() {
    let params = NetworkParams::mini();
    let chain = Chain::new(params.clone()).unwrap();
    let mut view = NodeL2::fresh(&params).unwrap();
    let before = view.state().funded_total();
    assert_eq!(before, params.l2_genesis_escrow_sat);

    // A test-seam credit: value appears in an L2 account and in `funded_total`,
    // so L2 is still internally closed...
    let stranger = [0x5Au8; 20];
    view.state_mut().credit(stranger, 1_000_000).unwrap();
    assert!(
        view.state().check_conservation(),
        "the seam keeps L2 internally closed, which is why provenance needs its own check"
    );

    // ...but it is neither genesis nor a deposit, so the funding check refuses.
    let err = verify_conservation(&chain, &view).expect_err("unauthorized funding must be caught");
    match err {
        ConservationError::L2FundingAnomaly { expected, actual } => {
            assert_eq!(expected, params.l2_genesis_escrow_sat);
            assert_eq!(actual, params.l2_genesis_escrow_sat + 1_000_000);
        }
        other => panic!("expected a funding anomaly, got {other:?}"),
    }
    // The refusal names both numbers and reads as a sentence an operator can act
    // on, rather than a bare "conservation broken".
    assert!(err.to_string().contains("funding anomaly"));
}

/// A deposit is counted on both sides, and the sink term cancels exactly that.
///
/// The two phases are asserted separately because they are genuinely different:
/// while pending, the value sits in the sink and is counted **once**; once
/// matured, it also exists as an L2 balance and would be counted **twice**
/// without the subtraction. This is the accounting an exit has to keep intact.
///
/// (No "the joint total must not rise" claim is made: mining the deposit block
/// also mints a block reward, so the total legitimately rises by issuance. The
/// property under test is that the deposit itself is never double-counted.)
#[test]
fn a_deposit_is_counted_once_while_pending_and_cancelled_once_matured() {
    let params = NetworkParams::mini();
    let mut chain = Chain::new(params.clone()).unwrap();
    let depositor = wallet(8);
    let depositor_addr = depositor.address().unwrap();
    mine(&mut chain, depositor_addr, 11);

    let before =
        verify_conservation(&chain, &NodeL2::replay_from(&chain, &params).unwrap()).unwrap();

    let op = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let reward = jnt_core::supply::block_reward_sat(chain.params(), 1);
    let fee = fee_for(&chain, 1, 2);
    let to_sink = 4 * SAT_PER_JNT;
    let deposit = depositor
        .build_tx(
            &[op],
            vec![
                Output {
                    value: to_sink,
                    address: params.l2_deposit_sink(),
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
        .mine_block(depositor_addr, vec![deposit], ts(h))
        .unwrap();
    chain.submit(block).unwrap();

    // Phase 1 — pending: the sink holds the value, L2 has not credited it yet,
    // so the value is counted exactly once.
    let pending_view = NodeL2::replay_from(&chain, &params).unwrap();
    let pending = verify_conservation(&chain, &pending_view).unwrap();
    assert_eq!(
        pending.sink_held_sat, to_sink,
        "the sink holds the principal"
    );
    assert_eq!(
        pending.l2_held_sat, params.l2_genesis_escrow_sat,
        "an unmatured deposit must not be credited in L2"
    );
    assert_eq!(
        pending_view.state().balance(&depositor_addr),
        0,
        "no L2 balance before maturity"
    );
    assert_eq!(
        pending.joint_sat,
        pending.l1_live_sat + pending.l2_held_sat - pending.sink_held_sat
    );

    // Phase 2 — matured: the L2 twin now exists, so the same satoshis are
    // present on both sides until the sink term removes one copy.
    mine(&mut chain, depositor_addr, params.finality_depth + 1);
    let matured_view = NodeL2::replay_from(&chain, &params).unwrap();
    let matured = verify_conservation(&chain, &matured_view).unwrap();
    assert_eq!(matured.sink_held_sat, to_sink);
    assert_eq!(
        matured.l2_held_sat,
        params.l2_genesis_escrow_sat + to_sink,
        "the matured deposit is now L2 value as well"
    );
    assert_eq!(
        matured_view.state().balance(&depositor_addr),
        to_sink,
        "and it is spendable L2 balance"
    );
    // The naive sum (no sink term) would count the deposit twice; the reported
    // joint total removes exactly one copy.
    let naive = matured.l1_live_sat + matured.l2_held_sat;
    assert_eq!(matured.joint_sat, naive - to_sink);
    // The principal is fully accounted for and still inside the system: value
    // moved between buckets, and the check that caught every step is the same
    // one an exit must not break.
    assert!(matured.joint_sat <= matured.bound_sat());
    assert!(!matured.exceeds_bound());
    // Sanity: the baseline was taken and the chains really are the same chain.
    assert!(matured.l1_live_sat > before.l1_live_sat);
}
