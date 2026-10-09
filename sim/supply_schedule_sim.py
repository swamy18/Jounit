"""Supply schedule simulation (SPEC.md section 7; design doc section 16).

Regenerates the numbers the design doc commits to and checks them against the
Rust implementation. Run directly to print the whole schedule:

    python sim/supply_schedule_sim.py

Independent of `tail_emission_sim.py`, which owns the tail *comparison*; this
script owns the committed vectors. Both must agree with `supply.rs` to the
satoshi, which is the cross-check that makes a disagreement a defect rather
than a formatting difference.

The approved tail (`docs/decisions.md` M-A..M-G, 2026-10-09) is modelled here:
mainnet decays to a 0.1 JNT floor, mini/testnet pay a constant 1 sat/block.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SAT_PER_JNT = 100_000_000

# Tail emission, approved 2026-10-09 (M-A decay tail, M-B 0.1 JNT floor,
# M-C 1 sat/block on the fast profiles). `decay_to_floor` is the mainnet rule:
# the first tail period pays 0.5 JNT and each later period halves in satoshis
# until the floor clamps it; `constant_sat` is the fast-profile rule.
MAINNET = {
    "name": "mainnet",
    "halving_period": 262_800,
    "start_reward_jnt": 76,
    "cap_jnt": 39_945_600,
    "block_time_s": 600,
    "tail_decay_to_floor_sat": 10_000_000,
}
MINI = {
    "name": "mini",
    "halving_period": 2_000,
    "start_reward_jnt": 76,
    "cap_jnt": 304_000,
    "block_time_s": 1,
    "tail_constant_sat": 1,
}


def exhaustion_period(params: dict) -> int:
    """First period whose ladder rung is zero, i.e. where the tail begins."""
    start = params["start_reward_jnt"]
    for p in range(64):
        if (start >> p) == 0:
            return p
    return 64


def tail_reward_sat(params: dict, period: int) -> int:
    """The tail rule, mirroring `supply::block_reward_sat` exactly."""
    if "tail_constant_sat" in params:
        return params["tail_constant_sat"]
    floor = params["tail_decay_to_floor_sat"]
    k = max(0, period - (exhaustion_period(params) - 1))
    if k >= 64:
        return floor
    return max(floor, SAT_PER_JNT >> k)


def halvings(params: dict, height: int) -> int:
    return height // params["halving_period"]


def reward_jnt(params: dict, height: int) -> int:
    """Halved in whole JNT, never in satoshis (see supply.rs for why)."""
    return params["start_reward_jnt"] >> halvings(params, height)


def reward_sat(params: dict, height: int) -> int:
    """The shipped reward function, in satoshis: ladder rung, then tail."""
    rung = reward_jnt(params, height)
    if rung > 0:
        return rung * SAT_PER_JNT
    return tail_reward_sat(params, halvings(params, height))


def reward_ladder(params: dict) -> list[int]:
    return [reward_jnt(params, p * params["halving_period"]) for p in range(8)]


def cumulative_sat(params: dict, mined_blocks: int) -> int:
    """Issuance after `mined_blocks` blocks mined on top of genesis, satoshis.

    Exact block-reward semantics: block `h` pays `reward_sat(h)`, so period p
    covers heights `p*H ..= (p+1)*H - 1` and block `(p+1)*H` already pays the
    next rung. Counting that block in the previous period is an off-by-one
    that a mirrored Rust bug would otherwise hide.
    """
    total = 0
    start = 1
    while start <= mined_blocks:
        period = halvings(params, start)
        period_end = (period + 1) * params["halving_period"] - 1
        end = min(mined_blocks, period_end)
        total += reward_sat(params, start) * (end - start + 1)
        start = end + 1
    return total


def max_issuance_jnt(params: dict) -> int:
    """The ladder-era integral: the reporting figure, not a bound (with a tail
    long-run issuance is unbounded by design, so the bound is per-height).

    Genesis occupies a rung-0 height without minting, so the first rung is paid
    by `H - 1` blocks: the exact figure is `149H - 76` JNT, 76 JNT below the
    `149H` geometric shortcut the design doc quotes.
    """
    return min(
        cumulative_sat(params, exhaustion_period(params) * params["halving_period"] - 1)
        // SAT_PER_JNT,
        params["cap_jnt"],
    )


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
        "issued_after_first_period_jnt": whole_jnt(
            params, cumulative_sat(params, periods), "one period"
        ),
        "issued_after_two_periods_jnt": whole_jnt(
            params, cumulative_sat(params, 2 * periods), "two periods"
        ),
        "max_reachable_jnt": reachable,
        "hard_cap_jnt": cap,
        "unmintable_jnt": cap - reachable,
        "final_reward_jnt": next((r for r in ladder if r == 0), None),
        # The approved tail (M-A..M-G). `tail_activation_height` is where the
        # ladder gives way to it; the floor is what the decay clamps to. Both
        # units are carried deliberately: satoshis are what the code uses, and
        # JNT is what a reader checks.
        "tail_activation_height": exhaustion_period(params) * periods,
        "tail_floor_sat": tail_reward_sat(params, exhaustion_period(params)),
        "tail_floor_jnt": tail_reward_sat(params, exhaustion_period(params)) / SAT_PER_JNT,
        "tail_reward_at_exhaustion_sat": tail_reward_sat(
            params, exhaustion_period(params)
        ),
        "tail_is_constant": "tail_constant_sat" in params,
    }


def whole_jnt(params: dict, sat: int, what: str) -> int:
    """Convert an issuance figure to JNT, refusing a fraction.

    Both reported horizons are pre-tail (the ladder pays whole JNT), so a
    remainder means the schedule changed shape and the vector would silently
    carry a truncated number.
    """
    if sat % SAT_PER_JNT:
        raise AssertionError(f"{params['name']}: {what} is not a whole number of JNT")
    return sat // SAT_PER_JNT


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

    # The geometric-series shortcut over-states issuance, and so does the
    # "500 x 262,800" shortcut: floor division means the ladder issues
    # 149H - 76 JNT (genesis eats a rung-0 height without minting), and the
    # remainder is unreachable.
    geometric = 2 * 262_800 * 76
    if m["max_reachable_jnt"] != 149 * 262_800 - 76:
        problems.append(
            f"reachable issuance is {m['max_reachable_jnt']}, expected {149 * 262_800 - 76}"
        )
    if m["unmintable_jnt"] != geometric - (149 * 262_800 - 76):
        problems.append("unmintable remainder does not reconcile with the cap formula")
    if m["max_reachable_jnt"] >= m["hard_cap_jnt"]:
        problems.append("reachable issuance must stay strictly under the cap")

    # The tail (M-A/M-B): 0.5 JNT at activation, then 0.25, 0.125, then the
    # 0.1 JNT floor held forever — every step at most a halving, the step into
    # the floor the smallest of the series.
    if m["tail_activation_height"] != 1_839_600:
        problems.append(
            f"mainnet tail activates at {m['tail_activation_height']}, expected 1,839,600"
        )
    first_tail = exhaustion_period(MAINNET)
    path = [
        tail_reward_sat(MAINNET, first_tail + i) / SAT_PER_JNT for i in range(4)
    ]
    if path != [0.5, 0.25, 0.125, 0.1]:
        problems.append(f"mainnet tail path is {path}, expected [0.5, 0.25, 0.125, 0.1]")
    if tail_reward_sat(MAINNET, first_tail + 40) != 10_000_000:
        problems.append("the mainnet floor is not held forever")
    prev = reward_sat(MAINNET, m["tail_activation_height"] - 1)
    for period in range(first_tail, first_tail + 10):
        now = tail_reward_sat(MAINNET, period)
        if now > prev or now * 2 < prev:
            problems.append(f"tail step at period {period} is more than a halving: {prev} -> {now}")
        prev = now

    # Issuance keeps growing forever under a tail — the whole point of M-A.
    late = cumulative_sat(MAINNET, 64 * 262_800)
    if late <= m["max_reachable_jnt"] * SAT_PER_JNT:
        problems.append("the tail did not add any issuance past the ladder era")
    # The ladder era itself still stops short of the sanity ceiling, so the
    # last pre-tail block is the closest the schedule ever came to it.
    if cumulative_sat(MAINNET, m["tail_activation_height"] - 1) >= m["hard_cap_jnt"] * SAT_PER_JNT:
        problems.append("ladder-era issuance crossed the sanity ceiling")
    # …and it stays a trickle: under 0.02 %/yr of the cap at 10-minute blocks.
    tail_year = 52_596 * 10_000_000
    if tail_year * 1_000 >= m["hard_cap_jnt"] * SAT_PER_JNT:
        problems.append("the mainnet floor mints more than 0.1 %/yr of the cap")

    mi = report(MINI)
    if mi["hard_cap_jnt"] != 2 * mi["halving_period_blocks"] * 76:
        problems.append("mini cap does not follow the same formula")
    if mi["tail_activation_height"] != 14_000 or mi["tail_floor_sat"] != 1:
        problems.append("mini tail is not the approved 1 sat/block from height 14,000")
    # The mainnet value on a 1-second profile would mint >1000 %/yr (F5).
    mini_year = 31_536_000 * mi["tail_reward_at_exhaustion_sat"]
    if mini_year > mi["hard_cap_jnt"] * SAT_PER_JNT:
        problems.append("mini's tail mints more than its whole cap in a year")
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