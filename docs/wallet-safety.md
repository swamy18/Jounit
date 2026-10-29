# A safer agent wallet

The agent wallet is safer than a normal crypto wallet by construction: every
spend is policy-governed, every grant is owner-signed, every payment is
replay-safe, and every event is auditable. This page is the operator and
developer guide to the safety layer.

## Layers

1. **Spend policy** (`agent::SpendPolicy` + `PolicyBook`): per-transaction
   cap, tumbling window + cumulative cap, recipient and service allow-lists
   (empty allows nothing), validity heights, strict nonce increase, owner
   revocation, delegation narrowing. Fail-closed and ordered; nothing mutates
   on refusal.
2. **Session budget** (`safety::SessionBook`): the per-agent aggregate across
   rotated policies. A policy rotation starts a fresh policy window by design;
   the session book stops spend being split across N policies. Enforced in
   `POST /v1/payment/submit` and the x402 settle path when configured:
   `SRCT_SESSION_WINDOW_BLOCKS` + `SRCT_SESSION_CAP_SAT` (both zero =
   gate off, policy windows only).
3. **Risk checks** (`safety::RiskPolicy`): high-value human-approval advisory
   (`SRCT_HIGH_VALUE_THRESHOLD_SAT`), per-payer velocity cap
   (`SRCT_MAX_PAYMENTS_PER_PAYER`), mainnet guard in test mode
   (`SRCT_TEST_MODE=1` refuses `srct/mainnet` spends). `payment_submit`
   answers `requires_human_approval: true` when the amount crosses the
   threshold — the agent pauses for a human, the chain never decides.
4. **Idempotency**: `PaymentTracker` (exact replay → `duplicate: true` before
   admission, so a retry never double-reserves), `ReceiptBook` (same receipt
   → `duplicate`; different receipt for the same payment → `receipt_conflict`
   409), strictly increasing policy nonces. A network timeout can be retried,
   never rebuilt: check `GET /v1/payments/unsettled` first.
5. **Receipts + reconciliation**: every admission holds a credit reservation
   until its receipt settles it; reservations release on any failure path.
   `GET /v1/payments/unsettled` lists recorded-but-unbound payments (retry
   these, do not rebuild); `GET /v1/receipts/orphans` lists receipts claiming
   unrecorded payments (investigate, never auto-settle).

## Test mode

Set `SRCT_TEST_MODE=1` on a dev node: `srct/mainnet` spends are refused with
`test_mode` while `mini`/`testnet` work unchanged. No separate binary, no
flag that can leak into prod config unnoticed — the env var is read per
request and exported in `GET /v1/risk/policy`.

## Audit trail

Every grant, admission, duplicate, refusal, revocation, stream open/settle
and receipt appends to a bounded, hash-chained `AuditLog` (each entry commits
to the previous hash; `GET /v1/audit` reports `chain_valid`). The ring is
in-memory by design — full history lives in the payment/receipt stores it
references. Export:

```bash
curl "$NODE/v1/audit?limit=200"   # newest last, hash chain verified
curl "$NODE/v1/risk/policy"       # thresholds, velocity, test mode, session envelope
curl "$NODE/v1/payments/unsettled"
curl "$NODE/v1/receipts/orphans"
```

## High-risk flow (recommended)

1. Set `SRCT_HIGH_VALUE_THRESHOLD_SAT` to the amount that needs a human.
2. The agent treats `requires_human_approval: true` as a pause, not a
   payment: it presents the `payment_id`, amount, recipient and policy to the
   operator with the audit trail.
3. The operator approves out of band (hardware key, second channel); only
   then does the agent proceed to settlement binding.
4. Velocity and session caps stay on as the backstop for compromised keys.

## Key custody (unchanged, still true)

`wallets.json` is Argon2id + ChaCha20-Poly1305, 0600, atomic write; plaintext
only with explicit `--allow-plaintext-wallet`; the API never signs and never
sees a key. No HSM/seed-phrase support yet — that is future work, and the
policy/session/approval layers above are what make a file key survivable
until then.
