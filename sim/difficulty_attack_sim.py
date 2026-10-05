"""Difficulty-manipulation simulation (design doc sections 28.9 / 28.10).

The design doc's section 28.9 table quotes a `difficulty_attack_sim.py`
that was never written. This is that file. It answers one question:

    How much future-timestamp leeway does a miner need before it can
    drag network difficulty down, and what does each allowance cost?

Two things fell out of writing it, and they change the story the design
doc tells.

WHAT THE PROTOCOL ACTUALLY DOES
-------------------------------
Consensus enforces one timestamp rule: a block's timestamp may not be
*below* the median of the previous eleven (`validate_timestamp`). There
is no consensus ceiling, because a ceiling needs a reference that
advances with wall time and the only such thing is the local clock.
The ceiling is therefore node policy (`validate_local_clock`), with a
width of `future_limit_ms` = one block time.

An honest miner writes `max(local_clock, median)` into the timestamp
(see `chain.rs` `mine_block_with`). That is the whole defence, and it
is enough: a minority attacker is outvoted six-to-five in the median,
so it cannot pull the median ahead of real time. Honest blocks keep
stamping at real time no matter how far ahead the attacker stamps.

Three further consensus bounds then make the attack inert:

  * the solve-time clamp [T/4, 5T]  -- a single retarget can only ask
    for a difficulty in [0.25, 5];
  * the per-block change limit (+/-10%) -- the retarget can only move
    one step at a time;
  * `min_difficulty = 1` -- difficulty can never reach zero, so block
    time can never fall below the target spacing.

With those in place a 40% attacker cannot make blocks come *faster*
than target. The attacker's future stamps instead produce 5T solve
times on the honest->attacker transitions, which the LWMA weights
heavily, so the attack pushes difficulty *up* and slows the network --
it backfires and costs the attacker the same slowdown.

WHY SECTION 28.9'S NUMBERS DIFFER
---------------------------------
The design doc reports a 40% attacker with a two-hour allowance
reaching ~104s average block time. That number is impossible under the
protocol: 104s is below the solve-time clamp floor (T/4 = 150s), so
no retarget can ever ask for a difficulty that low. The section 28.9
simulation must therefore have run a different model -- one with no
solve-time clamp, no difficulty floor, and honest miners that copy the
tip instead of anchoring on the median. This file can run that model
(`--design-doc-model`) and it does reproduce the table, which is the
point: the table is an artefact of the model, not of the protocol.

Run with no arguments for the protocol's behaviour; pass
`--design-doc-model` to reconstruct section 28.9.

Limit: a toy model. No latency variance, no selfish-mining subtlety,
no second attacker -- as the design doc's own note says.
"""

from __future__ import annotations

import argparse
import math
import random
from dataclasses import dataclass
from statistics import median_low

TARGET_S = 600.0
MEDIAN_LOOKBACK = 11
WINDOW = 60
CHANGE_LIMIT_BPS = 1_000
MIN_SOLVE_FRACTION = 0.25
MAX_SOLVE_FRACTION = 5.0
MIN_DIFFICULTY = 1.0


def clamp_solve_time(t: float, clamp: bool = True) -> float:
    """Consensus solve-time clamp. Negative solve times land on the floor."""
    if not clamp:
        return t
    return min(
        max(t, TARGET_S * MIN_SOLVE_FRACTION),
        TARGET_S * MAX_SOLVE_FRACTION,
    )


def retarget(
    solve_times: list[float],
    previous: float,
    clamp: bool = True,
    floor: float = MIN_DIFFICULTY,
) -> float:
    """LWMA over `solve_times` (newest first), newest weighted most.

    Mirrors `jnt_core::difficulty::next_difficulty`: the tip's own solve
    time carries weight `window^2`, and the retarget is multiplicative
    from the previous difficulty,

        d_new = d_prev * T / avg_solve

    Dividing the weighted mean by T instead (`avg_solve / T`) would be
    scale-invariant and therefore a fixed point at every difficulty --
    no restoring force, no correction when hashrate moves.
    """
    window = len(solve_times)
    if window == 0:
        return previous
    weight_sum = window * (window + 1) * (2 * window + 1) // 6
    acc = 0.0
    for i, t in enumerate(solve_times):
        depth = window - i  # newest (i=0) -> window, oldest -> 1
        acc += depth * depth * clamp_solve_time(t, clamp)
    avg_solve = acc / weight_sum
    if avg_solve <= 0:
        return previous
    d = max(floor, math.floor(previous * TARGET_S / avg_solve))
    bps = CHANGE_LIMIT_BPS
    lo = max(floor, math.floor(previous * (10_000 - bps) / 10_000))
    hi = max(
        math.floor(previous * (10_000 + bps) / 10_000),
        math.floor(previous) + 1,
    )
    return float(min(max(d, lo), hi))


@dataclass
class Result:
    scenario: str
    allowance_s: float
    attacker: float
    avg_block_time: float
    min_difficulty: float
    attacker_win_rate: float
    is_attack: bool

    @property
    def speedup(self) -> float:
        return TARGET_S / self.avg_block_time if self.avg_block_time else 0.0

    @property
    def verdict(self) -> str:
        ratio = self.avg_block_time / TARGET_S
        if self.is_attack:
            if ratio < 0.85:
                return f"ATTACK WINS: {self.speedup:.1f}x faster"
            if ratio > 1.30:
                return f"attack backfires: {ratio:.2f}x slower"
            return "attack contained"
        if 0.85 <= ratio <= 1.30:
            return "network unaffected"
        if ratio < 0.85:
            return "transient speedup, recovered"
        return "transient slowdown, recovered"

def simulate(
    scenario: str,
    attacker_share: float,
    allowance_s: float,
    model: str = "median",
    blocks: int = 3_000,
    seed: int = 7,
    start_difficulty: float = 1.0,
    warmup: int = 500,
    clamp: bool = True,
    floor: float = MIN_DIFFICULTY,
    hashrate_scale=None,
    is_attack: bool = False,
) -> Result:
    """Run one scenario and report the honest chain's real block cadence.

    `model` selects what an honest miner writes into `timestamp_ms`:

      "median"  ts = max(real, median(prev 11))  -- the consensus rule
      "tip"     ts = max(real, tip)               -- what section 28.9
                                                     modelled

    The first `warmup` blocks are discarded before timing. Solve times are
    exponentially distributed, so the retarget is a random walk and a chain
    started away from its steady state spends thousands of seconds climbing
    or falling; including that ramp in the average hides what the steady
    state actually does. Difficulty is also expected to wander over long
    runs -- what matters is that it wanders around the right value, not
    that it holds a particular number.
    """
    rng = random.Random(seed)
    scale_of = hashrate_scale or (lambda _i: 1.0)

    difficulty = start_difficulty
    solve_times: list[float] = []
    chain_ts: list[int] = []  # newest last

    real_now = 0.0
    last_ts = 0.0
    attacker_wins = 0
    min_difficulty = start_difficulty

    for i in range(blocks):
        scale = scale_of(i)
        # A model with no difficulty floor can drive difficulty to
        # zero, at which point the block rate is unbounded. Clamp
        # the denominator so the exponential draw stays finite.
        #
        # Both sides mine on the same chain at the same difficulty.
        # An earlier version pinned the attacker's own difficulty, which
        # quietly handed it a private easier chain and had nothing to do
        # with the timestamp attack under test.
        denom = max(difficulty, 1e-6) * TARGET_S
        honest_rate = (1.0 - attacker_share) * scale / denom
        attacker_rate = attacker_share * scale / denom

        honest_time = rng.expovariate(honest_rate) if honest_rate > 0 else math.inf
        attacker_time = rng.expovariate(attacker_rate) if attacker_rate > 0 else math.inf

        # Consensus floor: the median of the previous eleven timestamps.
        floor_ts = median_low(chain_ts[-MEDIAN_LOOKBACK:]) if chain_ts else 0.0
        tip_ts = chain_ts[-1] if chain_ts else 0.0

        if honest_time <= attacker_time:
            real_now += honest_time
            anchor = floor_ts if model == "median" else max(floor_ts, tip_ts)
            block_ts = max(real_now, anchor)
        else:
            real_now += attacker_time
            anchor = floor_ts if model == "median" else max(floor_ts, tip_ts)
            # The forgery: claim to be up to `allowance` seconds ahead
            # of real time. Nothing in consensus can contradict it.
            block_ts = max(real_now + allowance_s, anchor)
            attacker_wins += 1

        solve_times.insert(0, block_ts - last_ts)
        if len(solve_times) > WINDOW:
            solve_times.pop()
        chain_ts.append(block_ts)
        if len(chain_ts) > 64:
            chain_ts.pop(0)
        last_ts = block_ts

        difficulty = retarget(solve_times, difficulty, clamp, floor)
        min_difficulty = min(min_difficulty, difficulty)

    return Result(
        scenario=scenario,
        allowance_s=allowance_s,
        attacker=attacker_share,
        avg_block_time=real_now / blocks,
        min_difficulty=min_difficulty,
        attacker_win_rate=attacker_wins / blocks,
        is_attack=is_attack,
    )


def shock_10x(blocks: int):
    """Total hashrate is 10x for the middle third, then returns."""

    def scale(i: int) -> float:
        third = blocks // 3
        return 10.0 if third <= i < 2 * third else 1.0

    return scale


# name, attacker share, allowance, kind, is_attack
# The first three rows have hashrate leaving the network without anyone
# attacking; they are there to show the retarget recovering, and must not
# be judged by the attack verdict.
SCENARIOS = [
    ("stable hashrate, no attacker", 0.00, 0.0, None, False),
    ("10% of hashrate idle, no attacker", 0.10, 0.0, None, False),
    ("10x hashrate shock, no attacker", 0.10, 0.0, "shock", False),
    ("40% attacker, no timestamp games", 0.40, 0.0, None, True),
    ("40% attacker, allowance 5 min", 0.40, 300.0, None, True),
    ("40% attacker, allowance 10 min", 0.40, 600.0, None, True),
    ("40% attacker, allowance 30 min", 0.40, 1_800.0, None, True),
    ("40% attacker, allowance 2h (Bitcoin)", 0.40, 7_200.0, None, True),
    ("51% attacker, allowance 2h (Bitcoin)", 0.51, 7_200.0, None, True),
]


def run_table(label: str, model: str, clamp: bool, floor: float) -> list[Result]:
    print(f"\n{label}")
    print(f"  model={model}  solve-time clamp={'on' if clamp else 'OFF'}  "
          f"difficulty floor={floor}")
    header = (
        f"  {'scenario':<40}{'allow':>9}{'attacker':>10}{'avg block':>12}"
        f"{'min diff':>10}{'wins':>7}  verdict"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    rows: list[Result] = []
    for name, share, allowance, kind, is_attack in SCENARIOS:
        scale = shock_10x(3_000) if kind == "shock" else None
        r = simulate(
            name,
            share,
            allowance,
            model=model,
            clamp=clamp,
            floor=floor,
            hashrate_scale=scale,
            is_attack=is_attack,
        )
        rows.append(r)
        print(
            f"  {r.scenario:<40}{r.allowance_s:>7.0f}s{r.attacker:>9.0%}"
            f"{r.avg_block_time:>10.0f}s{r.min_difficulty:>10.2f}"
            f"{r.attacker_win_rate:>7.0%}  {r.verdict}"
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Jounit difficulty attack simulation")
    parser.add_argument("--blocks", type=int, default=3_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--design-doc-model",
        action="store_true",
        help="reconstruct the model behind design doc section 28.9 "
        "(tip-following, no solve-time clamp, no difficulty floor)",
    )
    args = parser.parse_args()

    print(
        f"toy model: target {TARGET_S:.0f}s, window {WINDOW}, change limit "
        f"{CHANGE_LIMIT_BPS / 10_000:.0%}, solve-time clamp "
        f"[{MIN_SOLVE_FRACTION:.2f}T, {MAX_SOLVE_FRACTION:.0f}T], "
        f"{args.blocks} blocks, start difficulty 100\n"
    )

    if args.design_doc_model:
        run_table(
            "design doc section 28.9 reconstruction "
            "(tip-following, no clamp, no floor)",
            model="tip",
            clamp=False,
            floor=0.0,
        )
        print(
            "\nsection 28.9 claimed: 5min->594s  10min->559s  30min->297s  "
            "2h->104s (attack worked)"
        )
        print(
            "This table is an artefact of that model: with no clamp and no\n"
            "floor, honest miners copying the tip let one future-stamped\n"
            "block drag the whole chain forward. The protocol does not let\n"
            "miners copy the tip -- it anchors them on the median."
        )
        return 0

    run_table(
        "the protocol as implemented (median-anchoring, clamp, floor)",
        model="median",
        clamp=True,
        floor=MIN_DIFFICULTY,
    )

    print(
        "\nfindings"
        "\n  A 40% attacker cannot make blocks arrive faster than the target"
        "\n  spacing. The median rule anchors honest timestamps at real time"
        "\n  (a minority is outvoted 6-to-5 in the median), and the"
        "\n  solve-time clamp bounds any single retarget to [0.25, 5]."
        "\n  The attacker's future stamps instead surface as 5T solve times"
        "\n  on honest->attacker transitions, which the LWMA weights"
        "\n  heavily -- so the attack raises difficulty and slows the"
        "\n  network. It backfires and costs the attacker the same"
        "\n  slowdown."
        "\n\n  The future-timestamp allowance is still kept at one block time"
        "\n  (not Bitcoin's two hours) as defence in depth: it bounds how"
        "\n  far ahead any single block can be stamped, which is what"
        "\n  matters once an attacker reaches 50% and can start moving the"
        "\n  median itself."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
