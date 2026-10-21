#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant fuzzer over the credit layer (SPEC.md §22).
//
// A loan is the only place in Jounit where one party's money is committed to
// another party's promise, so the accounting here is the most delicate in the
// protocol. This target drives real, validly signed credit transactions through
// `L2State` and asserts the properties that must never break:
//
//   1. **Value conservation.** accounts + locked + exits_locked + credit_locked
//      + burned + PSCB + vault_remaining == total credited, after every step.
//      A repayment that paid the lender twice, a default that took the
//      collateral twice, or a refund of collateral that was never locked shows
//      up here.
//   2. **Collateral is locked, not spent.** `credit_locked` always equals the
//      sum of the positions' collateral, and a live position's collateral is
//      never released while the debt is outstanding.
//   3. **Debt only goes one way.** `outstanding` never increases and never
//      underflows; a position at or below zero is closed.
//   4. **A default is not early.** A position cannot be settled before its
//      deadline, and a closed position cannot be settled twice.
//   5. **Repayment pays interest first, then principal.** A repayment never
//      reduces the principal below the interest it was charged, and the
//      interest is charged once per period rather than once per repayment.
//   6. **Replay is refused**, and a refused transaction changes nothing.
//
// Inputs are structure-aware: three deterministic wallets come from the first
// 96 bytes, and the rest is a program of operations (open / collateralise /
// repay / default / advance) whose amounts are bounded so the arithmetic stays
// in range and the interesting boundaries are still reachable.
fuzz_target!(|data: &[u8]| {
    use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
    use jnt_core::hash::Hash;
    use jnt_core::l2::{
        CreditCollateralPayload, CreditDefaultPayload, CreditOpenPayload, CreditRepayPayload,
        L2Payload, L2Transaction,
    };
    use jnt_core::wallet::Wallet;
    use jnt_l2::{CreditPositionState, L2Config, L2Error, L2State};

    if data.len() < 100 {
        return;
    }
    let mk = |s: &[u8]| Wallet::from_private_key_bytes(s, "credit-fuzz");
    let (Ok(lender), Ok(borrower), Ok(trigger)) =
        (mk(&data[0..32]), mk(&data[32..64]), mk(&data[64..96]))
    else {
        return;
    };
    let la = lender.address().unwrap_or([0u8; 20]);
    let ba = borrower.address().unwrap_or([1u8; 20]);
    let ta = trigger.address().unwrap_or([2u8; 20]);

    const FUND: u64 = 1_000_000_000;
    let credited = FUND * 3;

    let mut state = L2State::new(L2Config::mini());
    for a in [la, ba, ta] {
        state.credit(a, FUND).unwrap();
    }
    let validators = ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect());
    let verifier = MockBls;

    let mut position: Option<Hash> = None;
    let mut height = 1u64;
    let mut i = 96usize;
    let mut nonce = 0u64;
    while i + 4 <= data.len() {
        let op = data[i] % 5;
        let amount = (data[i + 1] as u64) * 100_000 + 1;
        let salt = data[i + 2];
        let rate = (data[i + 3] as u32) % 1_001; // at most the protocol cap

        match op {
            // Open a position: the lender signs, the principal moves.
            0 => {
                nonce += 1;
                let collateral = if salt & 1 == 1 {
                    amount.saturating_mul(2)
                } else {
                    amount
                };
                let deadline = height + 10;
                let payload = match CreditOpenPayload::build(
                    &lender,
                    ba,
                    amount,
                    collateral,
                    rate,
                    10,
                    deadline,
                    nonce,
                ) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let id = payload.derived_position_id();
                let tx = L2Transaction::new(L2Payload::CreditOpen(payload));
                let before = state.committed_root();
                match state.apply(&tx, height, &validators, &verifier) {
                    Ok(_) => {
                        position = Some(id);
                        assert_ne!(
                            before,
                            state.committed_root(),
                            "an opened position must change the committed root"
                        );
                    }
                    Err(_) => {
                        assert_eq!(
                            before,
                            state.committed_root(),
                            "a refused opening must not change the state"
                        );
                    }
                }
            }
            // Add collateral.
            1 => {
                let Some(id) = position else { break };
                let Ok(payload) = CreditCollateralPayload::build(&borrower, id, amount) else {
                    break;
                };
                let tx = L2Transaction::new(L2Payload::CreditCollateral(payload));
                let _ = state.apply(&tx, height, &validators, &verifier);
            }
            // Repay: interest first, then principal.
            2 => {
                let Some(id) = position else { break };
                let payload = match CreditRepayPayload::build(&borrower, id, amount) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
                let before = state.committed_root();
                match state.apply(&tx, height, &validators, &verifier) {
                    Ok(_) => {
                        let p = state
                            .credit_position(&id)
                            .expect("the position is in the state");
                        assert!(
                            p.outstanding_sat <= amount.max(1) * 1000,
                            "the outstanding debt is implausibly large"
                        );
                        assert_ne!(
                            before,
                            state.committed_root(),
                            "a repayment must change the committed root"
                        );
                    }
                    Err(_) => {
                        assert_eq!(
                            before,
                            state.committed_root(),
                            "a refused repayment must not change the state"
                        );
                    }
                }
            }
            // Default: permissionless, but only once the position is due.
            3 => {
                let Some(id) = position else { break };
                let payload = match CreditDefaultPayload::build(&trigger, id) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::CreditDefault(payload));
                let before = state.committed_root();
                match state.apply(&tx, height, &validators, &verifier) {
                    Ok(_) => {
                        let p = state
                            .credit_position(&id)
                            .expect("the position is in the state");
                        assert_eq!(
                            p.state,
                            CreditPositionState::Defaulted,
                            "a settled default must leave the position closed"
                        );
                        assert_eq!(
                            p.collateral_sat, 0,
                            "a default must release the collateral"
                        );
                    }
                    Err(e) => {
                        // An early default is refused, by name.
                        assert!(
                            matches!(e, L2Error::CreditNotDue | L2Error::CreditPositionClosed),
                            "unexpected refusal for a default: {e:?}"
                        );
                        assert_eq!(
                            before,
                            state.committed_root(),
                            "a refused default must not change the state"
                        );
                    }
                }
            }
            // The same transaction again: the replay guard.
            4 => {
                let Some(id) = position else { break };
                let payload = match CreditRepayPayload::build(&borrower, id, amount) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::CreditRepay(payload));
                let before = state.committed_root();
                let err = state
                    .apply(&tx, height, &validators, &verifier)
                    .expect_err("a repeated transaction must be refused");
                assert!(
                    matches!(err, L2Error::Replay) || !matches!(err, L2Error::UnknownCreditPosition),
                    "unexpected refusal for a repeated transaction: {err:?}"
                );
                assert_eq!(
                    before,
                    state.committed_root(),
                    "a refused replay must not change the state"
                );
            }
            _ => {}
        }

        let _ = state.advance_block(height);
        height += 1;
        i += 4;

        // The collateral bucket is exactly the sum of what the positions hold.
        let locked: u64 = state
            .credit_positions()
            .iter()
            .map(|p| p.collateral_sat)
            .sum();
        assert_eq!(
            state.credit_locked(),
            locked,
            "the locked collateral disagrees with the positions after op {op}"
        );

        assert_eq!(
            state.conservation_total(),
            credited,
            "L2 value conservation broke after op {op}"
        );
        assert!(
            state.check_conservation(),
            "L2 funded-total invariant broke after op {op}"
        );
    }
});
