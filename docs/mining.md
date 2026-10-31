# Mining guide

The three ways to mine (in-node, standalone miner, pool) and where rewards
go are in the [README](../README.md#mining). This guide holds the detail:
seed boxes, the pool protocol, hardware backends, and the upgrade route.

## Seed node on a small box (24×7)

A seed node keeps the network alive while mining happens elsewhere. It needs
almost nothing — 512 MB RAM and a few GB of persistent disk are enough —
because it relays and validates but never grinds. Run it relay-only:

```sh
./target/release/srct-node serve --network mainnet --data-dir ./chain \
  --no-mine --listen 0.0.0.0:9833
```

Three things matter here: `--no-mine` (no CPU burn), `--data-dir` on a disk
that survives restarts (lose it and the node resyncs from genesis), and port
`9833` reachable from the internet so other nodes can dial in. Point
`srct-miner --node` at this box's API port and your laptop keeps mining while
the box keeps the chain.

## Option C — mine through a pool

Pools speak stratum-lite JSON-lines over TCP: `getjob` hands each miner an
unsolved template, `submit` returns shares. Jobs are single-use, one solved
proof counts as one share pool-wide (no double-billing across jobs),
submissions are pinned to the job (same transactions, difficulty and history
— swapping the coinbase invalidates the share), weak proofs count as shares
for accounting while only full-difficulty proofs go to the chain as blocks.
Rewards split over the last N shares (PPLNS, N ≈ two blocks' worth — every
share is worth the same no matter when it landed, so pool hopping has no
timing edge) minus the pool fee, rounding dust
carries to the next round instead of leaking to the operator, and every payout
is recorded before it is paid. Pool accounting never mints: only the consensus
coinbase creates coins.

## What hardware mines

Anything. The PoW is integer-only — no floats anywhere — so CPU, GPU, NPU,
TPU, photonic chips and domestic accelerators all compute bit-identical
results, and the three stages pull in different directions (hash throughput,
matrix-vector units, memory bandwidth), so no single exotic chip dominates.
`srct-miner` exposes one `ComputeBackend` contract with two in-tree backends:

| Flag | Backend | Meaning |
|---|---|---|
| `--backend cpu` | `CpuBackend` | Reference implementation. Default. |
| `--backend portable` | `PortableBackend` | Independently written implementation; differential-tested equal to the reference on every candidate. The template silicon vendors port. |
| `--backend auto` | — | Same as `cpu` today; picks the best available backend. Also via `SRCT_MINER_BACKEND`. |

A new chip joins by implementing the same contract and passing the
differential test — never by forking consensus. (SPEC §5.3 names the exact
kernel surface; SPEC §13.1/§19.2 specify the template and pool protocols.)

## Upgrade route: hbm-v1

A second puzzle, `hbm-v1` (`puzzle_id = 2`), is designed and registered in
code but is **not** the active mining puzzle — the chain rests on §5 alone
(Decision 22). The memory-hard HBM path is the upgrade route for when ASIC
pressure appears, not a second live puzzle.
