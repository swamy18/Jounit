# Agent-to-agent job escrow

A research agent hires a data agent: payment locks in escrow, work is
verified on delivery, release pays exactly that result. On dispute the funds
stay locked until the arbitrator decides.

## Flow

```
POST /v1/jobs/open                 hirer locks payment + posts the job
POST /v1/jobs/{id}/accept          worker commits (signature over the job id)
POST /v1/jobs/{id}/deliver         worker posts result hash (+ signed receipt)
POST /v1/jobs/{id}/resolve|release hirer/arbitrator releases against the result
— or —
POST /v1/jobs/{id}/dispute         hirer, worker or arbitrator freezes funds
POST /v1/escrow/{id}/release       refused while held (escrow_held)
POST /v1/escrow/{id}/settle        refused while held; no auto-refund either
POST /v1/jobs/{id}/resolve         arbitrator signs (job, pay|refund, result);
                                   hold lifts; coin moves via escrow release/settle
GET  /v1/jobs/{id}                 record + escrow state + held flag
```

Result binding is the point: `release` against a delivered job refuses a
mismatched hash — the release pays for *this* dataset, not any dataset. The
resolve signature binds (job id, direction, result hash) to the arbitrator
key the escrow named at open, so no other key can decide.

Dispute locks are node-enforced (`held_escrows`, persisted in `state.bin`
v6): release, settlement binding and the timeout auto-refund all refuse while
a job is disputed. An unresponsive arbitrator cannot be distinguished from a
slow one by the machine — expiry policy says the hirer should pick
arbitrators with live tooling, and jobs carry deadlines regardless.

## Receipts on every payment

Machine-verifiable receipts already exist (`ServiceReceipt`: issuer-signed,
bound to payment id, recipient, amount, service). The node cannot sign for a
provider, so the guarantee is structural: `GET /v1/payments/{id}/receipt_status`
reports `{recorded, receipt_present, settlement_tx}` and agents poll it —
treating a payment as complete before its receipt appears is a client bug,
and the endpoint makes that check one call.
