# Dollar prices, SRCT settlement

SRCT is a mined coin, not a pegged asset: its schedule never promises a
dollar price. Services that want dollar pricing quote in USD (or a supported
stablecoin) and settle in SRCT at a transparent, locked rate.

Trust statement: rate issuers are trusted — rates come from a configured
whitelist (`SRCT_FX_ISSUERS`), and a dishonest issuer's quotes are only as
good as the trail they leave. Rates are per-node books: two nodes can hold
different rate sets. Quote against your own node, and check the rate is live
before you pay it.

## Flow

```bash
# 1. Operator registers a signed rate (issuer must be in SRCT_FX_ISSUERS).
curl -X POST $NODE/v1/fx/rates -d '{"base":"USDC","sat_per_minor":1000,...}'
curl $NODE/v1/fx/rates/list                       # live rates at this height

# 2. Lock a quote: $1.00 at 1000 sat/cent, 1% fee, 0.5% slippage → 101,500 due.
curl -X POST $NODE/v1/fx/quote \
  -d '{"base":"USDC","amount_minor":100,"fee_bps":100,"slippage_bps":50,"ttl_blocks":60}'
# → {sat_due, fee_sat, slippage_bps, rate_sat_per_minor, expires_height}

# 3. Stablecoin-in: the agent holds USDC off-protocol, pays SRCT on market.
curl -X POST $NODE/v1/fx/swap -d '{"payer_hex":"...","stable_asset":"USDC",
  "stable_minor":100,"sat_due":101500,...,"stable_ref":"usdc-tx-abc","nonce":1}'
```

Every number is stated up front: amount, exact satoshis due, fee, slippage
headroom, rate, expiry. A quote whose rate is not the live rate is refused;
an expired quote is refused. The swap re-verifies the arithmetic server-side:
`sat_due` must equal gross-at-live-rate plus the declared `fee_sat` (the
quote's slippage headroom rides inside that declared fee), so a swap cannot
understate what the payer owes while pointing at the live rate. Custody of
the stablecoin never touches the node — the swap intent is the audit trail,
not a custody receipt.

## Pegged-asset policy

If SRCT ever ships a dollar-pegged asset, it needs a credible reserve,
redemption, legal and independent-audit model — published, attested, redeemable.
An unsupported promise that an algorithm will maintain the peg is not a
model and will not ship under that name. Until then: quote dollars, settle
SRCT, show every fee.
