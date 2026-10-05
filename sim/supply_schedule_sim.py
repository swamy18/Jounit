"""Supply schedule simulation (SPEC.md section 7; design doc section 16).

Regenerates the numbers the design doc commits to and checks them against the
Rust implementation. Run directly to print the whole schedule:

    python sim/supply_schedule_sim.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SAT_PER_JNT = 100_000_000

MAINNET = {
    "name": "mainnet",
    "halving_period": 262_800,
    "start_reward_jnt": 76,
    "cap_jnt": 39_945_600,
    "block_time_s": 600,
}
MINI = {
    "name": "mini",
    "halving_period": 2_000,
    "start_reward_jnt": 76,
    "cap_jnt": 304_000,
    "block_time_s": 1,
}


def halvings(params: dict, height: int) -> int:
    return height // params["halving_period"]


def reward_jnt(params: dict, height: int) -> int:
    """Halved in whole JNT, never in satoshis (see supply.rs for why)."""
    return params["start_reward_jnt"] >> halvings(params, height)


def reward_ladder(params: dict) -> list[int]:
    return [reward_jnt(params, p * params["halving_period"]) for p in range(8)]


def cumulative_jnt(params: dict, mined_blocks: int) -> int:
    """Issuance after `mined_blocks` blocks mined on top of genesis."""
    total = 0
    start = 1
    period = 0
    while start <= mined_blocks and period < 64:
        period_end = (period + 1) * params["halving_period"]
        end = min(mined_blocks, period_end)
        r = reward_jnt(params, start)
        if r == 0:
            break
        total += r * (end - start + 1)
        start = end + 1
        period += 1
    return total


def max_issuance_jnt(params: dict) -> int:
    return cumulative_jnt(params, 64 * params["halving_period"])


def year_of(height: int, params: dict) -> float:
    """Elapsed years for `height` blocks (365.25-day years)."""
    return height * params["block_time_s"] / (86_400 * 365.25)


def report(params: dict) -> dict:
    ladder = reward_ladder(params)
    reachable = max_issuance_jnt(params)
    cap = params["cap_jnt"]
    periods = params["halving_period"]
    return {
        "network": params["name"],
        "ladder_jnt": ladder,
        "halving_period_blocks": periods,
        "halving_period_years": round(year_of(periods, params), 3),
        "issued_after_first_period_jnt": cumulative_jnt(params, periods),
        "issued_after_two_periods_jnt": cumulative_jnt(params, 2 * periods),
        "max_reachable_jnt": reachable,
        "hard_cap_jnt": cap,
        "unmintable_jnt": cap - reachable,
        "final_reward_jnt": next((r for r in ladder if r == 0), None),
    }


def check_design_doc_claims() -> list[str]:
    """The numbers the design doc asserts, verified rather than repeated."""
    problems: list[str] = []
    m = report(MAINNET)

    # Section 16: cap = 2 x 262,800 x 76.
    if m["hard_cap_jnt"] != 2 * 262_800 * 76:
        problems.append(f"cap is {m['hard_cap_jnt']}, expected {2 * 262_800 * 76}")
    if m["hard_cap_jnt"] != 39_945_600:
        problems.append("cap does not match the stated ~39.95M")
    if m["ladder_jnt"] != [76, 38, 19, 9, 4, 2, 1, 0]:
        problems.append(f"reward ladder is {m['ladder_jnt']}, expected [76,38,19,9,4,2,1,0]")
    if abs(m["halving_period_years"] - 5.0) > 0.01:
        problems.append(f"halving period is {m['halving_period_years']}y, expected 5y")

    # The geometric-series shortcut over-states issuance: floor division means
    # the real total is 149 x 262,800, and the remainder is unreachable.
    geometric = 2 * 262_800 * 76
    if m["max_reachable_jnt"] != 149 * 262_800:
        problems.append(
            f"reachable issuance is {m['max_reachable_jnt']}, expected {149 * 262_800}"
        )
    if m["unmintable_jnt"] != geometric - 149 * 262_800:
        problems.append("unmintable remainder does not reconcile with the cap formula")
    if m["max_reachable_jnt"] >= m["hard_cap_jnt"]:
        problems.append("reachable issuance must stay strictly under the cap")

    # The cap can never be crossed, which is the property that matters.
    for mined in [1, 262_800, 2 * 262_800, 7 * 262_800, 64 * 262_800, 10**9]:
        if cumulative_jnt(MAINNET, mined) > m["hard_cap_jnt"]:
            problems.append(f"supply exceeded the cap after {mined} blocks")

    mi = report(MINI)
    if mi["hard_cap_jnt"] != 2 * mi["halving_period_blocks"] * 76:
        problems.append("mini cap does not follow the same formula")
    return problems


def main() -> int:
    for params in (MAINNET, MINI):
        print(f"=== {params['name']} ===")
        for key, value in report(params).items():
            print(f"  {key:32} {value}")
        print()

    problems = check_design_doc_claims()
    print("design-doc cross-check:", "OK" if not problems else "FAILED")
    for p in problems:
        print("  -", p)

    out = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "supply_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "sat_per_jnt": SAT_PER_JNT,
                "mainnet": report(MAINNET),
                "mini": report(MINI),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())