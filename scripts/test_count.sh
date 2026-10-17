#!/bin/sh
# Single source of truth for the test counts quoted in README.md and
# docs/mainnet-readiness.md.
#
# Runs the full workspace suite, prints every suite's result line, then the
# totals. Exits non-zero if any suite failed, so a pasted number can never
# come from a red run.
set -eu
out=$(cargo test --workspace 2>&1)
printf '%s\n' "$out" | grep -E '^test result:' || true
if printf '%s\n' "$out" | grep -q '^test result: FAILED'; then
    echo 'FAILURES PRESENT' >&2
    exit 1
fi
passed=$(printf '%s\n' "$out" | awk '/^test result: ok/ {p += $4} END {print p+0}')
ignored=$(printf '%s\n' "$out" | awk '/^test result: ok/ {i += $8} END {print i+0}')
echo "total: $passed passed, 0 failed, $ignored ignored"
