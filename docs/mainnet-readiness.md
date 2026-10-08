# Mainnet Operational Readiness

## 1. Versioning & Release Management

- **Current version:** 0.2.0 (foundation + P2P transport) per `SPEC.md` header
- **SemVer policy:** Major = consensus-breaking (halving, checkpoint, validator set); Minor = backward-compatible
  feature or protocol mechanism activation; Patch = bug fix with no consensus impact.
- **Release branch convention:** `release/vMAJOR.MINOR` — cut 2 weeks before mainnet launch, receive only
  bug fixes and security patches.
- **Release checklist:**
  1. `cargo fmt --all --check`
  2. `cargo clippy --workspace --all-targets -- -D warnings`
  3. `cargo test --workspace` (all test suites pass, 0 failures)
  4. `cargo build --workspace --release` (no link errors)
  5. Verify `SUPPORTED_PROTOCOL_VERSIONS` in `jnt-core/src/params.rs`
  6. Verify no `#[ignore]`d tests remain relevant (only `vwc_perf_probe` is intentionally ignored)
  7. Update `CHANGELOG.md`
  8. Tag `vMAJOR.MINOR.PATCH` and publish to GitHub Releases

## 2. Monitoring & Observability

### Metrics (to be exposed via `/metrics` endpoint)

| Metric | Type | Alert threshold |
|---|---|---|
| `jnt_chain_height` | gauge | < prev - 1 for 2 min |
| `jnt_peer_count` | gauge | < 3 or > 90% of max |
| `jnt_mempool_size` | gauge | > 95% of byte cap |
| `jnt_blocks_seen_total` | counter | 0 for 3 block intervals |
| `jnt_rejected_blocks_total` | counter | spike > 2σ |
| `jnt_l2_applied_total` | counter | 0 for >5 blocks |
| `jnt_l2_skipped_total` | counter | spike > 2σ |
| `jnt_fees_collected_sat` | counter | flat for 10 min |
| `jnt_finality_height` | gauge | no advance for 30 min (testnet only) |

### Logs

| Level | Condition |
|---|---|
| `WARN` | Invalid block from peer |
| `WARN` | L2 payload skipped by name |
| `WARN` | Reorg deeper than finality window |
| `ERROR` | Storage open failure |
| `INFO` | Block accepted with timestamp, height, miner |
| `INFO` | L2 payload applied/skipped with reason |

## 3. Backup & Recovery

### Data directories

```
~/.jnt/
  blocks.log          # append-only, checksummed
  meta.json           # atomic metadata (height, tip, network)
  config.toml         # node configuration
  policy/             # agent authorization policies (Decision 16)
```

### Recovery procedure

1. **Full node:** Back up `~/.jnt/` daily (blocks.log grows ~864 MB at 1 KB/block for 14 days of mainnet).
   Recovery: copy directory, `jnt-node serve` — `BlockStore::open` replays from `meta.json` tip.
2. **Wallet:** Seed phrase (mnemonic per BIP-39). Wallet files are deterministic; no backup needed.
3. **Lost node:** Resync from any peer: `jnt-node init --network mainnet`, then `jnt-node serve --sync`.
   Sync speed: ~10k blocks/sec from a single peer (limited by disk I/O, not network).

### Disaster scenarios

| Scenario | RTO | RPO |
|---|---|---|
| Node crash (clean) | <30s | 0 blocks |
| Torn write (power loss) | <2 min | 0 blocks (torn tail dropped) |
| Disk failure, last backup ≤24h old | <30 min (resync) | ≤24h |
| Entire operator fleet down | Restore from any other node's snapshot | 0 blocks |

## 4. Security Disclosure

- **Bug bounty:** Not yet announced; will be via GitHub Security Advisory.
- **Responsible disclosure window:** 90 days.
- **Criticality:** Chain-halting bugs (invalid block accepted) = critical, immediate patch + coordinated
  disclosure. Wallet compromise bugs = high, 7-day disclosure.
- **Contact:** security@jounit.org (PGP key to be published).

## 5. Genesis & Bootstrapping

- **Mainnet genesis** is deterministic + frozen (SPEC.md §9). No allocations. Total supply mints over
  `MAX_HALVINGS * 10` halving epochs to the cap (10,000,000 JNT).
- **Mini genesis** (for testnet/dev): seeds 1-3 funded with 1 JNT each, escrow sink per Decision 11.
- **Testnet genesis:** identical to mainnet structure; committee of 4 keys (quorum 3) declared at activation.
- **Bootnodes:** To be announced. Current testnet uses 2 stable bootnodes on separate clouds.

## 6. Upgrade Mechanism

Consensus upgrades use **epoch-based activation** (SPEC.md §10):

| Mechanism | Activation | Consensus-active? |
|---|---|---|
| M1 | Always (§8) | Yes |
| M2 | Decision 10 | No (inactive) |
| M3 | Decision 9 | No (envelope only) |
| M4 | Decision 11 | No (inactive) |
| M5 | Decision 12 (testnet: epoch 20, mainnet: none) | Conditional |

A node running pre-upgrade software will reject blocks post-activation per the new rules (fail-closed),
ensuring a hard fork boundary. Operators must upgrade before the activation epoch to stay on consensus.

## 7. Pre-Launch Checklist

| Item | Status |
|---|---|
| Clippy clean | ✅ |
| `cargo fmt --check` clean | ✅ |
| All tests pass | ✅ (773 passed, 0 failed) |
| Release build compiles | ✅ (`cargo build --release`) |
| Vector cross-check | ✅ (Python reference matches Rust) |
| Fuzz smoke | ✅ (14 targets, 0 crashes) |
| Genesis hash verified | ✅ (deterministic across profiles) |
| BLS finality tested | ✅ (18 adversarial checkpoint tests) |
| L2 end-to-end | ✅ (reputation API, 2-process E2E, chaos suite) |
| **Before mainnet:** M2/M4 activation rules | ❌ (blocked - needs protocol decision) |
| **Before mainnet:** M5 committee for mainnet | ❌ (empty committee fails closed) |
