# HBM Composition Draft (P4 — Decision 22, NOT activated)

**Status: DRAFT.** Nothing here is implemented, and nothing here activates
anything. Chain security rests on the §5 base puzzle alone until the checklist
at the end is complete. This document exists so the composition choice
(Decision 22: compose, never silently replace) has a concrete shape to be
reviewed against.

## Chosen shape: additional header commitment

The base proof-of-work stays exactly what it is (SPEC §5, `puzzle_id`,
difficulty, fork choice — all untouched). A miner that also proves
memory-hard work commits to it in the header alongside the base proof:

- New header field `hbm_commitment: [u8; 32]` — the root of the HBM
  scratchpad proof for this block's header bytes (`hbm_pow.rs` defines the
  scratchpad construction; the draft pins the commitment, not a new puzzle).
- New `puzzle_id` registration for "base + HBM" blocks, versioned through the
  existing puzzle registry — never a silent reinterpretation of `puzzle_id 1`.
- Verification is two deterministic checks: the base PoW verifies exactly as
  today, AND the HBM commitment verifies against the header. A block with a
  valid base proof but an invalid HBM commitment is invalid under the new
  `puzzle_id`, exactly as a block with a bad nonce is invalid today.
- Header size grows 145 → 177 bytes. `HEADER_SERIALIZED_LEN`, the genesis
  block, and every header vector change together; old software rejects the
  new `puzzle_id` as unknown (fail-closed), so activation needs a coordinated
  upgrade, not a flag day in the code.

## What is deliberately NOT in this draft

- No change to difficulty adjustment, fork choice, rewards, or finality.
- No replacement path: a proposal that drops the base puzzle will be rejected
  with reference to Decision 22. Composition is the only shape on the table.
- No activation height, no profile parameter, no miner policy knob. Per the
  launch principle there is nothing here to govern after launch; activation,
  when approved, is a registered `puzzle_id` miners adopt by upgrading.

## Activation checklist (all required, none started)

1. **Security analysis**: cost model of the composed puzzle (memory-latency
   bound vs. hash-rate bound), ASIC/FPGA/GPU trade-offs, selfish-mining and
   withholding effects of the second proof, verification-cost DoS bounds.
2. **Benchmarks**: prove/verify timings on reference hardware (CPU, commodity
   GPU, memory-constrained devices), block-propagation impact of +32 bytes and
   verification latency on the critical path.
3. **Test vectors**: pinned HBM commitments for fixed headers, cross-checked by
   the Python reference like every other vector set.
4. **Adversarial suite**: malformed commitments, commitment mismatches,
   registry version confusion, mixed old/new-puzzle-id chains and reorgs
   across the activation boundary.

## Open questions for review

- Should the HBM commitment cover the coinbase (binding the payout to the
  memory proof) or the header without it?
- Scratchpad epoching: per-block fresh scratch (maximum memory hardness) or
  epoch-cached (cheaper verification, weaker hardness)?
- Minimum memory threshold: what excludes botnets without excluding phones?
