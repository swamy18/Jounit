# Testnet Readiness

## Launch Runbook

### Phase 0: Pre-launch (24h before)

1. **Seed peers:** Ensure 3 bootnodes are running:
   ```
   jnt-node serve --network testnet --bootnode
   ```
2. **Committee keys:** Generate 4 BLS keys, publish to a sealed
   `committee.json` (quorum = 3). Keys must be from different operators.
3. **Verify genesis:**
   ```python
   python sim/verify_vectors.py --check
   ```
4. **Final CI:** Run `cargo test --workspace` and monitor for flakes.

### Phase 1: Boot (T+0)

1. Start all 3 bootnodes with `--network testnet`.
2. Bootnodes must be reachable on port 9333 (main) and 9334 (API).
3. First validator connects within 30s; sync should complete in <2 min.

### Phase 2: Join (T+1h)

1. **Node operators:** Run:
   ```
   jnt-node init --network testnet
   jnt-node serve --network testnet --api-listen 0.0.0.0:9334
   ```
2. **Workers:** Run worker against any node:
   ```
   jnt-worker --network testnet --node http://localhost:9334
   ```

### Phase 3: Validate (T+6h)

1. Mine at least 50 blocks (2+ finality windows on mini profile).
2. Confirm L2 tasks are being created, claimed, settled with VWCs.
3. Confirm `/v1/reputation/{address}` returns a derived ledger.
4. Check `/metrics` for expected counters.

## Configuration (`config.toml`)

```toml
network = "testnet"
listen = "0.0.0.0:9333"
api_listen = "0.0.0.0:9334"

[storage]
dir = "/var/lib/jnt"
max_block_bytes = 1048576

[sync]
max_peers = 100
sync_timeout_ms = 30000

[finality]
# M5 binding on testnet: committee of 4, quorum 3, activation at block 20
# (see SPEC.md §14.8, Decision 12)
activation_height = 20
```

## Known Limitations (Testnet)

| Issue | Workaround |
|---|---|
| M2 (Anti-Collusion) inactive | Slashing vault exists but no rule triggers. Manual slashing via governance. |
| M4 (HBM scratchpad) inactive | Chain security is from §5 double-PoW only. |
| No fee market dynamics yet | Base fee is flat per `fees.rs` schedule; congestion model arrives in v0.3.0. |
| Transaction relay not yet on L1 wire | Txs broadcast via API; P2P tx relay (§13.13) is post-testnet. |

## Monitoring During Testnet

### Health check

```bash
curl -s http://localhost:9334/health | jq .
```
Expected: `{"status": "ok", "height": <N>, "peers": <N>}`

### Alert thresholds (testnet)

| Metric | Alert if |
|---|---|
| `jnt_blocks_seen_total` | No new block for 2 × `target_block_time` (20s on testnet) |
| `jnt_peer_count` | Drops below 2 |
| `jnt_rejected_blocks_total` | > 10 rejections in 5 min |
| `jnt_l2_skipped_total` | > 5 skips in 10 blocks |

## Graduation Criteria

Testnet → Mainnet when all of:

1. No consensus-critical bugs in 14 days of continuous operation
2. ≥20 independent nodes have synced
3. ≥500 L2 tasks created/settled with VWCs
4. Checkpoint finality is verified on 3 independent sync restarts
5. Fuzz smoke has 0 crashes for 72h continuous
6. Security team sign-off on the attack-surface review
7. Community audit window open + response period ended
