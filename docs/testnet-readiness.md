# Testnet Readiness

**Status: prepared, not launched.** Every command below is the real CLI as
implemented in `crates/jnt-node` and `crates/jnt-worker` (hand-rolled argument
parsing, `--name value`). An earlier revision of this file documented flags
that do not exist (`--bootnode`, `--network` on the worker, a `config.toml`
that nothing reads) and a `/metrics` endpoint and a `/health` route that were
never implemented. Those have been removed; what is here is what runs. Where a
piece of the runbook names something that is *documented but not implemented*,
it says so explicitly.

## What exists today

| Capability | State |
|---|---|
| `testnet` network profile | **Implemented** — `NetworkParams::testnet()`: unique `network_magic`/`network_id` (`jounit/testnet`), four deterministic genesis BLS validators, `checkpoint_interval_blocks = 10`, `finality_activation_height = 20` (Decision 13) |
| Binding finality (M5) on testnet | **Implemented** — real `blst` verification; once height 20 is finalized a reorg crossing it is refused (Decision 12) |
| L1 node (`jnt-node`) with P2P | **Implemented** — `serve` with `--listen`, `--connect`, `--no-mine`, `--api-listen` |
| L1 transaction relay over P2P | **Implemented** (SPEC §13.14, `msg_type = 10`) |
| L2 deposits | **Implemented** — burn-to-sink, maturity by depth **and** binding finality (Decisions 10/15) |
| L2 exits | **Implemented** (Decision 19, SPEC §19.6) — a sink-output claim authorised by an inclusion proof, released by the permissionless crank, with `jnt_worker::{queue_exit, ExitPlan}` for owners. Active only where `exit_activation_height > 0`; check that value in `NetworkParams::testnet()` before assuming withdrawals work. |
| L2 task lifecycle / VWC / reputation | **Implemented** — driven by L2 replay; exercised by `crates/jnt-node/tests/e2e_journey.rs` |
| Opt-in REST API | **Implemented** — `--api-listen`; loopback by default and unauthenticated; a **non-loopback bind is refused** unless a bearer token is supplied via `JNT_API_TOKEN` (preferred — `--api-token` is visible in `ps`) (SPEC §19.2). Host-header validation runs on every bind including loopback; exposed binds then also enforce bearer auth (constant-time compare), a per-request deadline, a global in-flight cap and a bounded per-IP rate limit |
| `jnt-worker` run loop | **Implemented** — `jnt-worker run --from-file <wallet> --node <url>` drives discover → claim → execute → submit over the node's REST API, using the production `RealBls` verifier. Bounded by `--iterations`; otherwise runs until the process is terminated (no portable signal handler — the node's own `serve` loop has none either). Covered by `crates/jnt-worker/tests/cli_run.rs` and the two-process E2E test. Gates on `GET /v1/conservation` before the first pass |
| Live conservation surface | **Implemented** — `GET /v1/conservation` reports the joint L1 + L2 − sink supply against the joint bound (issuance integral + escrow ceiling) with all three check verdicts (the `jnt-node verify` arithmetic, served live); `/metrics` exports `jounit_joint_supply_sat` and `jounit_conservation_ok`; `jnt-worker run` refuses to start against a node reporting a breach or unreadable numbers (an unreachable or non-reporting node warns and continues). Covered by `crates/jnt-node/tests/conservation_api.rs` and the `cli_run.rs` gate tests |
| `/metrics` (Prometheus) | **Implemented** — `GET /metrics` serves `text/plain; version=0.0.4` gauges (height, finality, peers, base fee, supply, PSCB reserve, mempool, relay/queue depths, L2 counters). `/v1/status` JSON remains for the richer view |
| Node config file | **NOT implemented** — the node is CLI-flags-only; no `config.toml` is read |

## Launch runbook (real commands)

Default network is `mini` and default data dir is `chain`; both are overridden
per command. `--network` accepts `mainnet`, `testnet`, `mini`.

### Phase 0 — pre-launch (24 h before)

1. **Bootstrap nodes.** A "bootnode" is not a flag: it is an ordinary `serve`
   node started with `--listen` that other nodes dial with `--connect`. Start
   three on distinct hosts:
   ```
   jnt-node init  --network testnet --data-dir /var/lib/jnt
   jnt-node serve --network testnet --data-dir /var/lib/jnt \
                  --listen 0.0.0.0:9333
   ```
2. **Committee keys.** The testnet committee is **deterministic** (derived from
   public test seeds by `testnet_validator_key(seed)`, seeds 1..4). There is
   no key-generation ceremony and no sealed `committee.json`; two independently
   built `testnet` profiles are byte-identical. Quorum is the §14.7
   `ceil(n × 6667 / 10000)` = 3 of 4.
3. **Verify vectors and genesis:**
   ```
   python sim/verify_vectors.py --check
   python sim/supply_schedule_sim.py
   ```
4. **Final CI:** `cargo test --workspace` and `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

### Phase 1 — boot (T+0)

1. Start the three bootstrap nodes as above (they begin mining by default).
2. Joiners connect to any bootstrap node:
   ```
   jnt-node init  --network testnet --data-dir /var/lib/jnt
   jnt-node serve --network testnet --data-dir /var/lib/jnt \
                  --connect <bootnode-host>:9333 --no-mine
   ```
   `--connect` takes a comma-separated list; `--no-mine` makes a
   validate/relay/sync-only node.
3. Confirm sync by polling status (see Monitoring).

### Phase 2 — service node (T+1 h)

To expose the opt-in REST API (needed by the worker SDK / MCP surface):
```
jnt-node serve --network testnet --data-dir /var/lib/jnt \
               --listen 0.0.0.0:9333 --api-listen 127.0.0.1:9334
```
The API is **unauthenticated**; bind it to loopback or a trusted network only.

### Phase 3 — validate (T+6 h)

1. Mine past height 20 and confirm `finalized_height` advances in
   `/v1/status` (binding finality activates at 20 on testnet).
2. Confirm L2 replay reports no skipped payloads and the deposit pipeline is
   live (`/v1/status` carries the L2 block).
3. Drive an L2 task lifecycle through the test suite path
   (`cargo test -p jnt-node --test e2e_journey`) or the API, and confirm a VWC
   and a derived reputation appear at `/v1/vwc/{task_id}` and
   `/v1/reputation/{id}`.

## Configuration

There is no config file. All configuration is command-line flags. The relevant
`testnet` parameters are fixed in `NetworkParams::testnet()` and are **not**
operator-tunable:

| Parameter | testnet value |
|---|---|
| `network_id` | `jounit/testnet` |
| `finality_depth` | 20 |
| `finality_activation_height` | 20 |
| `checkpoint_interval_blocks` | 10 |
| `genesis_validators` | 4 deterministic keys (quorum 3) |
| Stock supply cap | none (rate anchor: ≤ 1 % of issued per halving period) |
| `base_fee_initial_sat` / `min` / `max` | 100 / 10 / 1,000,000 |

Node flags that exist: `--network`, `--data-dir`, `--listen`, `--connect`,
`--peers`, `--no-mine`, `--interval`, `--api-listen` (serve); `--network`,
`--data-dir`, `--blocks`, `--wallet`, `--to`, `--amount`, `--fee`, `--relay`,
`--label`, `--address`, `--height`, `--out` (other commands). Anything else is
rejected as an unexpected argument.

## Known limitations (testnet)

| Issue | Consequence / workaround |
|---|---|
| L2 → L1 exits are activation-gated, not missing | Withdrawal works only where the profile's `exit_activation_height > 0`. Check the value in `NetworkParams::testnet()`; if it is `0`, deposited L2 value cannot be withdrawn on testnet — by configuration, not because the protocol lacks the path. |
| M2 (Anti-Collusion slash vault) inactive | The vault exists; no rule triggers it. |
| M4 (HBM scratchpad) not a registered `puzzle_id` | Chain security rests on the §5 double-PoW puzzle only. |
| No stake ledger / validator rotation | The committee is fixed at genesis (Decision 8); bonding/unbonding are mainnet-gated. |
| API is unauthenticated | Loopback/tunnel only. |
| Metrics are gauges only | `/metrics` exports no request/error counters — scraping it does not reveal how many requests failed. Poll `/v1/status` alongside it. |
| MemPool is in-memory only | A restart begins with an empty pool. |
| Worker daemon has no signal handler | `jnt-worker run` loops until stopped; it stops between passes, never mid-transaction, but does not trap SIGINT itself. Use `--iterations N` for a bounded run. |

## Monitoring during testnet

Health is a liveness check only:
```
curl -s http://127.0.0.1:9334/v1/health
# => {"status":"ok"}
```
The real observable is `/v1/status`, which returns network id, height, tip,
peer count, base fee, total supply, PSCB reserve, `finalized_height`,
`finality_activation_height`, `finality_depth`, mempool length and the L2
block. `/metrics` (Prometheus text) and `/v1/conservation` (the joint-supply
report `jnt-worker run` gates on) carry the same signals for scrapers.
Alert on:

| Signal (from `/v1/status`) | Alert if |
|---|---|
| `height` | unchanged for 2 × the target block interval |
| `peers` | drops below 2 |
| `finalized_height` | stops advancing after activation height while `height` climbs |
| `l2.skipped` | grows more than 5 entries in 10 blocks |
| `pscb_reserve_sat` | moves unexpectedly |
| `jounit_conservation_ok` (from `/metrics`) | drops to 0 — joint supply broke the cap or an L2 check failed; treat as value creation and stop the fleet |

## Graduation criteria (testnet → mainnet)

Unchanged and still unmet:

1. No consensus-critical bugs in 14 days of continuous operation.
2. ≥ 20 independent nodes synced.
3. ≥ 500 L2 tasks created/settled with VWCs.
4. Checkpoint finality verified across ≥ 3 independent sync restarts.
5. Fuzz smoke clean for 72 h continuous.
6. Security sign-off on the attack-surface review.
7. Community audit window opened and closed.

**Mainnet remains blocked independently of these** by `mainnet`'s
`exit_activation_height` being unset (Decision 19 implemented the rule but the
profile has chosen no height), the absent stake ledger / mainnet committee
(Decision 8 / P2, `docs/decisions.md`), and the M2/M4 activation rules (P3/P4).
P5 (settle-fee vs small task) is also open. See `docs/mainnet-readiness.md`.
