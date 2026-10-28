# AGENTS.md

This is the source of truth for the checks to run during a session, so they are not
re-derived each turn.

## Lint and type-check

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
```

## Tests

```bash
# Run everything.
cargo test --workspace
# Core escrow + service unit tests.
cargo test -p jnt-core --lib
# Node HTTP API integration tests (roadmap items 2 and 4).
cargo test -p jnt-node --test api
# Mining stack: solver/stratum/payouts/backends, template/submit roundtrips.
cargo test -p jnt-miner
cargo test -p jnt-core --test committee_rotation
cargo test -p jnt-node --test api external_miner
# Escrow-specific subsets.
cargo test -p jnt-core --lib escrow
cargo test -p jnt-node --test api escrow
```

## Style notes

- Edition 2021; code uses 4-space indentation, no emojis.
- Prefer editing existing files; do not add doc files unless asked.
- Do not commit unless explicitly requested.
