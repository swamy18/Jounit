# Productive lending for agents

Credit for working capital — not merely moving already-owned funds. Lenders
publish standard terms, borrowers discover and accept them, history prices
risk, and revenue repays loans by itself where the borrower authorized it.

## Standard offers and discovery

```bash
curl -X POST $NODE/v1/loans/offers -d '{lender-signed terms...}'  # rate ≤10%/window, full collateral terms
curl "$NODE/v1/loans/offers/list?principal=1000"                  # live offers, cheapest first
curl -X POST $NODE/v1/loans/accept -d '{"offer_id":"...","borrower_hex":"...",
  "bond_sat":200,"amount_sat":1000,"deadline_height":9000}'       # terms come from the offer
```

Accepting opens a position on exactly the signed terms — amount and deadline
are the borrower's only choices. Bond and collateral must already be funded.
The accept carries the borrower's own signature over (offer, borrower,
amount, bond, deadline): the debt lands in the named borrower's book, so
only that borrower can authorize it.

## History, limits, dashboards

- `GET /v1/lending/borrower/{addr}` — verified repayments, on-time rate,
  defaults, total repaid/borrowed, reputation score, and a suggested ceiling.
- `GET /v1/lending/limit/{borrower}` — the ceiling plus its factors.
- `GET /v1/lending/dashboard` — exposure by lender, due-soon positions,
  defaulted positions with shortfalls, expected interest.
- `GET /v1/lending/collateral/{position_id}` — live collateral vs
  debt + accrued interest (coverage in bps).

The suggestion is advisory: any default zeroes it, no history means zero
(unproven is unpriced, not free), and the lender decides. Reputation is an
input to pricing, never a guarantee of repayment.

## Who bears losses

Collateral first, then the borrower's posted bond, then the lender absorbs
the shortfall. A vanished borrower or a revoked owner key changes nothing
about this order: the position still defaults at its deadline and settles by
these rules. Define this in the loan agreement, not in the score.

## Automatic repayment from revenue

```bash
curl -X POST $NODE/v1/lending/autorepay -d '{"borrower_hex":"...","position_id":"...",
  "pct_bps":5000,"cap_sat":10000,"expires_height":9000,"nonce":1,
  "sigs_hex":"...","keys_hex":"..."}'   # borrower-signed, revocable by replacement
curl $NODE/v1/lending/autorepay/<borrower>               # live instruction, if any
```

While live, each credit deposit routes the authorized share to the position
first (`credit/deposit` answers `autorepay: {position_id, repaid_sat, ...}`).
Only explicit borrower authorization, only while unexpired and under cap.
Replacing the instruction needs a strictly greater nonce (a stale signature
never unedits the live one), and the routed total carries over — editing the
cap or rate cannot silently reset what was already repaid through it.
