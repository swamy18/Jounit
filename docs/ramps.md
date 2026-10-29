# Entering and exiting SRCT

If users cannot obtain SRCT, price in it, or convert back, even excellent
payment technology will not be adopted. The node is the auditable registry
for entry and exit; custody and compliance live with the ramp provider
(exchange, on-ramp widget, OTC desk) off-protocol.

## Flow

```bash
# Provider publishes a signed quote (fiat or stablecoin, either direction).
curl -X POST $NODE/v1/ramp/quote -d '{"network_id":"srct/mini","provider_hex":"...",
  "direction":"stable_to_srct","asset":"USDC","asset_minor":100,
  "sat_amount":101500,"fee_sat":1000,"expires_height":9000,"nonce":1,
  "provider_sigs_hex":"...","provider_keys_hex":"..."}'

curl "$NODE/v1/ramp/quotes?direction=stable_to_srct"   # live entry quotes
curl -X POST $NODE/v1/ramp/intent -d '{"quote_id":"...","user_hex":"...","fill_ref":"bank-ref-1"}'
# Provider fills out of band, then closes the intent (only the quoted provider can):
curl -X POST $NODE/v1/ramp/intent/<id>/settle \
  -d '{"outcome":"filled","fill_ref":"bank-ref-1-done","provider_sigs_hex":"...","provider_keys_hex":"..."}'
curl $NODE/v1/ramp/intents                              # registry trail
```

Quotes expire; intents are terminal (filled or refunded, never both); the
settle signature covers (intent id + outcome) so only the quoted provider
closes its own intent. Exchange integrations implement the provider side
against these four calls: publish, list, accept, settle.
