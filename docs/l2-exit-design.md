# L2 Exit Design

**Status:** Proposal — blocked on protocol decision (see Decision 21)

## Problem

Today, L2 transactions are executed within L1 blocks as commitments. A worker submits a
`PostTaskPayload` → `ClaimTaskPayload` → `SettlePayload` sequence. If the L2 state transitions
disagree with what a user expected, they need a way to withdraw their funds.

Currently there is no explicit L2 → L1 withdraw path. The L2 deposit flow (L1 → L2) exists and
is tested end-to-end, but the return path is an open design question.

## Design Options

### Option A: In-Block Challenge (preferred)

**Mechanism:** Any L2 state transition that is provably incorrect can be challenged on L1 within
`challenge_window` blocks. The challenge is a special L1 transaction referencing a block height
and the disputed L2 tx index.

**Pros:**
- Fully on-chain — no trusted exit contract
- Users don't need L2 nodes to withdraw; they submit an L1 tx with the disputing proof
- Compatible with the existing dispute arbitration (M3/M4)

**Cons:**
- Requires L2 → L1 state proof generation (new code)
- Challenge window must be longer than the maximum L2 reorg depth

### Option B: Scheduled Withdrawal

**Mechanism:** A `WithdrawPayload` L2 transaction queues a withdrawal. After `finality_depth` L1
blocks confirm the L2 commit, the funds are released from the escrow sink.

**Pros:**
- Simpler — no proof generation needed
- Predictable timeline for users

**Cons:**
- Requires a withdrawal queue contract on L1
- If the queue contract is buggy, funds are stuck
- Users must wait for L1 finality (currently 6 blocks on mainnet)

### Option C: Emergency Withdrawal

**Mechanism:** A governance-triggered emergency pause freezes new deposits and enables a
time-delayed withdrawal path.

**Pros:**
- Safety valve for bugs
- Doesn't require per-transaction proofs

**Cons:**
- Trust in governance
- Can be gamed if governance is compromised

## Recommended Approach

**Option B (Scheduled Withdrawal)** as the primary path, **Option A (Challenge)** as a bypass
for the case where the withdrawal queue is stuck.

### Required new L2 payload type

```rust
pub enum L2Payload {
    PostTask(PostTaskPayload),      // §14.2.1
    Claim(ClaimTaskPayload),        // §14.2.2
    Settle(SettlePayload),          // §14.2.3
    Dispute(DisputePayload),        // §14.2.4
    // NEW (proposed):
    Withdraw(WithdrawPayload),      // §14.2.5 — queues withdrawal from L2 → L1
}
```

### `WithdrawPayload` sketch

```rust
pub struct WithdrawPayload {
    pub nonce: u64,            // per-submitter nonce, same scheme as PostTask
    pub amount_sat: u64,       // amount in satoshis
    pub destination: Address,  // L1 address to receive funds
    pub sig: CompactSignature, // owner-signed
}
```

### Exit flow

1. User submits `WithdrawPayload` on L2
2. L2 state records the withdrawal (debiting the L2 account)
3. After `finality_depth` L1 blocks confirm the containing L1 block, the escrow
   sink releases the funds to `destination`
4. If the node is unresponsive, the user can submit the withdrawal proof to any
   other full node via the exit API (Option A bypass)

## Open Questions (before implementation)

1. **What is `finality_depth` for L2 exits?** Currently no value is defined. Suggestion:
   6 blocks (matching M5 checkpoint depth on testnet).
2. **Who pays the L1 gas for the release transaction?** The node operator that wins the
   withdrawal auction, or the user directly?
3. **Can withdrawals be batched?** A batch of N withdrawals in one L1 tx to reduce costs.

## Decision Needed

See `docs/decisions.md` (Decision 21). The team must decide whether L2 exits require
on-chain challenge proofs (Option A) or scheduled withdrawals (Option B) before
implementation can begin.

## References

- SPEC.md §14.2 (L2 payload types)
- `docs/decisions.md` (Decision 21: L2 exit mechanism)
- `crates/jnt-l2/src/l2.rs` (payload serialization and `derive_task_id`)
- `docs/micro-payment-audit.md` (Layer 1 deposit flow)
