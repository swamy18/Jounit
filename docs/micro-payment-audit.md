# Micro-Payment Security Audit

## Scope

The micro-payment path spans three layers:

1. **L1 → L2 bridge** (deposit credits L2 account)
2. **L2 compute task posting** (post task → worker claims → settle/VWC)
3. **Worker → reputation ledger** (verified work accumulates reputation)

Each layer has distinct security properties and failure modes.

---

## Layer 1: L1 → L2 Deposit

### Asset flow

```
L1:  sink output (burnt) → L2 escrow escrow address
L2:  L2 escrow balance → task posting / settlement payout
```

### Properties verified

- **Credits each sink output independently:** `scan_credits_each_sink_output_independently`
- **No double-credit:** `same_deposit_in_competing_branches_credits_once`
- **Reorg removes deposits:** `reorg_removes_deposit_and_winner_recredits_exactly_once`
- **Immature deposits cannot be spent:** `before_binding_finality_the_depth_rule_alone_matures_a_deposit`
- **Zero-amount outputs rejected:** `zero_amount_output_rejected_by_l1_before_l2_sees_it`

### Attack vectors

| Vector | Mitigation | Test |
|---|---|---|
| Deposit replay across chains | Network-bound escrow identity (`params::l2_escrow_identity_is_deterministic_and_network_bound`) | `l2_escrow_fits_the_unmintable_gap_on_both_profiles` |
| Under-credited deposit | Credits mature only at `finality_depth`; reorgs remove unconfirmed credits | `case_a_depth_satisfied_but_binding_not_is_not_spendable` |
| Fake sink output | Only canonical L2 escrow address is recognized; `scan_finds_a_single_owner_sink_output_exactly` | `deposit_end_to_end_funds_posttask_and_survives_restart` |

## Layer 2: Compute Task Lifecycle

### Flow

```
1. PostTask: submitter locks JNT → task contract
2. Worker claims: worker posts deposit → task transitions to "claimed"
3. Settle: worker submits VWC → either (a) correct, payout to worker, or (b)
   disputed
4. Dispute: challenger posts evidence → arbitrated to fraud/correct verdict
```

### Properties verified (all in `dispute_flow.rs`)

| Property | Test |
|---|---|
| Payment below settle fee refused | `a_payment_below_the_settle_fee_is_refused_and_not_settled` |
| Unauthorized challenger refused | `an_unauthorized_challenger_is_refused` |
| Same task cannot settle twice | `a_task_cannot_be_settled_twice_or_slashed_twice` |
| Fraudulent worker slashed | `fraudulent_worker_is_slashed_and_the_whistleblower_is_rewarded` |
| Inconclusive dispute settles nothing | `an_inconclusive_dispute_can_still_lapse_later` |
| Expired task refunds submitter | `an_unclaimed_task_expires_and_refunds_the_submitter` |
| Settle after deadline refused | `a_settle_after_the_window_closes` |

### Economic security

- **Settle deposit:** Worker must post a deposit ≥ settle fee. If challenged fraudulently,
  the challenger's deposit is at risk (burned on failed challenge per `a_failed_challenge_burns_the_deposit`).
- **Deadline:** Tasks must settle within `settle_window` blocks. After deadline, the task
  lapses and the submitter is refunded (no worker payout).
- **Quorum:** Settlement requires M5 quorum (3/4 on testnet). A single worker signature is insufficient.

## Layer 3: Reputation Ledger

### Properties

- **Deterministic derivation:** Reputation is derived from L2 state (settlements + disputes),
  not stored separately. Two nodes replaying the same chain produce identical ledgers.
- **Event immutability:** Every settlement or dispute event is a 1:1 mapping from L2 state.
  No off-chain input affects reputation.
- **Weights fixed:** Correct settlements +1, disputes defended +2, fraud -10. No dynamic weights.

### Test coverage

- `reputation::tests::the_same_receipt_cannot_be_counted_twice`
- `reputation::tests::every_event_field_changes_the_event_id`
- `reputation_flow.rs::a_correct_settlement_gives_the_worker_verified_work`

## Streaming micro-payments (pay-as-you-use, policy layer)

`crates/jnt-core/src/stream.rs` covers continuous usage billing, which the
three layers above do not: a payer-signed `PaymentStream` (rate per block,
window, hard cap) accrues `min(rate × blocks, cap)` per height, and the
recipient withdraws with payer-signed `StreamSettlement` receipts against a
fail-closed `StreamBook`.

### Properties verified (all in `payment_stream.rs` + `stream.rs` unit tests)

| Property | Test |
|---|---|
| Settlement above or below accrual refused | `a_settlement_above_accrual_is_refused_and_settles_nothing`, `a_settlement_below_accrual_is_refused_too` |
| Same range cannot settle twice | `settling_the_same_height_twice_is_refused`, `a_rewound_through_height_is_refused` |
| Future (unaccrued) blocks cannot be claimed | `claiming_unaccrued_blocks_is_refused` |
| Third party cannot mint receipts | `a_settlement_signed_by_another_key_is_refused` |
| Receipts are stream-bound | `a_settlement_for_another_stream_is_refused` |
| Overflow refuses instead of wrapping | `overflow_refuses_rather_than_wraps` |
| Machine payer without policy refused | `a_machine_stream_without_a_policy_is_refused` |

### Notes

- Opening a stream locks nothing on chain: the cap is a signed promise, and
  the payer's balance is checked at settlement time like any other off-chain
  authorization. Settlement rides the ordinary payment path (`reference` = the
  stream id), so no new transaction type exists to audit.
- A refused receipt commits nothing: budget is consumed only on `Ok`.

## Risk Assessment

| Risk | Severity | Status |
|---|---|---|
| L2 state divergence between nodes | Critical | Mitigated — full deterministic replay from L1 |
| Micro-payment dust accumulation | Low | Mitigated — per-tx fee floor enforced (`fee_below_base_fee_is_rejected`) |
| Worker double-claim | High | Mitigated — task contract state transition is atomic (`apply_tx_is_atomic_when_an_input_is_missing`) |
| Reputation gaming via reorg | Medium | Mitigated — reputation is derived from canonical L1 finality, not L2 mempool state |
| Settle deadline griefing | Medium | Mitigated — lapsed tasks refund submitter; worker loses nothing |

## Recommendations

1. **No open issues.** The micro-payment path is fully covered by adversarial tests.
2. **Before production:** Add a circuit breaker for the deposit flow (pause during active exploits).
3. **Consider:** Rate-limiting `PostTask` per L2 address to prevent mempool flooding.
