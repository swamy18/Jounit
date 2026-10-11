# Jounit (JNT)

An AI-native cryptocurrency. Mining that puts real work on GPUs and AI hardware
without weakening the security a blockchain depends on.

> **Status: code complete, not launched.** Every mechanism described here is
> implemented and tested. Mainnet has **not** launched — see
> [Not ready to launch](#not-ready-to-launch). What remains is configuration,
> operators, and an external audit: not missing protocol.

---

## Contents

- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [Supply](#supply)
- [What the chain is for](#what-the-chain-is-for)
- [Machines, agents and robots](#machines-agents-and-robots)
- [Verified Work Certificates](#verified-work-certificates)
- [How fraud is detected](#how-fraud-is-detected)
- [How withdrawals work](#how-withdrawals-work)
- [Validators and finality](#validators-and-finality)
- [Component status](#component-status)
- [What changed, and when](#what-changed-and-when)
- [Repository layout](#repository-layout)
- [Network profiles](#network-profiles)
- [Commands](#commands)
- [Testing](#testing)
- [Not ready to launch](#not-ready-to-launch)
- [License and trademark](#license-and-trademark)

---

## What this is

The principle every blockchain shares is *solving is hard, verifying is easy*.
Bitcoin's solution is pure hashing, which leaves GPUs idle and ties no energy to
anything useful.

Jounit keeps the principle and changes the work. Mining runs three stages:

1. **A SHA-256 hash chain** — carries the security. This is what a quantum
   adversary has to break.
2. **An integer-only neural network** — makes the work meaningful for AI hardware.
3. **A final hash** — binds both into the value that must fall below the target.

Two properties keep the neural stage a cost model rather than a liability:

- **Capped share.** The network must account for 30–50% of modelled work. A
  registry entry outside that band is rejected outright, so it can never become
  the weak link.
- **No floating point, anywhere.** Weights derive from the epoch id by SHA-256,
  the forward pass accumulates in `i64` and wraps to `i32`, and every integer is
  explicit. Two implementations on two machines produce identical digests — which
  is tested against an independent Python reference, not assumed.

Because weights come from the epoch id, no miner can precompute them before an
epoch starts.

---

## Quick start

Requires **Rust 1.75+** (developed and tested against 1.99) and **Python 3.11+**
for the simulations.

```sh
git clone https://github.com/swamy18/Jounit.git
cd Jounit
cargo build --release
```

```sh
# Create a chain directory and a miner wallet.
./target/release/jnt-node init   --network testnet --data-dir ./chain

# Mine blocks, then check the chain agrees with itself.
./target/release/jnt-node mine   --network testnet --data-dir ./chain --blocks 25
./target/release/jnt-node status --network testnet --data-dir ./chain
./target/release/jnt-node verify --network testnet --data-dir ./chain

# Run a P2P node. It mines by default, so it settles matured exits.
./target/release/jnt-node serve  --network testnet --data-dir ./chain \
                                  --listen 127.0.0.1:9833
```

`verify` replays the whole chain from genesis and diffs the resulting UTXO set,
supply, bond ledger and binding-finalized point against stored state. It is the
check worth running after any change.

Run `jnt-node help` for the full command list; every command accepts `--help`.

---

## Supply

There is **no stock cap**. That is a deliberate change — see
[Decision 18](docs/decisions.md) — and the current bounds are different in kind.

**The ladder** halves in whole JNT every 262 800 blocks (~5 years at a 10-minute
block):

```
76, 38, 19, 9, 4, 2, 1 JNT
```

Whole JNT, not shifted satoshis: halving 9.5 → 4.75 would break the arithmetic.

**Premine is 0%**, enforced in code rather than in prose. Genesis mints nothing.

**The ladder totals exactly 39 157 124 JNT.** Not the 39 157 200 a geometric
shortcut suggests — genesis occupies a rung-0 height without minting, so the
first rung is paid by `H − 1` blocks rather than `H`. That 76 JNT is the
difference between the design document's approximation and what the chain can
actually reach, and `supply::max_issuance_sat` reports the real figure.

**The tail** takes over after the ladder (height 1 839 600) and never stops:

```
0.50 → 0.25 → 0.125 JNT, then a permanent 0.1 JNT floor
```

So issuance continues forever, reaching the floor at height 2 628 000 (~50 years)
instead of terminating. Testnet and mini pay a constant 1 sat per block from their
first tail period.

**Two bounds enforce this**, both checked in `Chain::apply_block` so the miner,
validator and node cannot disagree about what is mintable at a height:

1. **The issuance integral.** A block may not mint past
   `cumulative_issuance_sat(height)`. Overflow is refused rather than wrapped — a
   wrapped sum would compare small and pass the bound.
2. **The rate anchor.** After ladder exhaustion, gross issuance inside the current
   halving window may not exceed **1% of the supply issued at that window's
   start**. The approved schedule sits ~3× under it, so the anchor never binds it
   today — it exists to refuse a *future* schedule that would dilute far faster.
   The ladder era is grandfathered.

**Net supply can fall.** The base fee splits 50/50 into a burn and an on-chain
reserve, so usage *removes* supply from the spendable set. Combined with a
declining tail reward, the simulation measures net supply falling below
break-even at ≈5% activity and being at 25% at the fee floor. This is a measured
consequence, not a bug — the analysis and sensitivity tables are in
[docs/monetary-policy.md](docs/monetary-policy.md).

Gross issuance, removal and net supply are reported by `status`,
`GET /v1/conservation` and the `/metrics` gauges.

---

## What the chain is for

Two distinct layers, with different jobs:

**Layer 1** is a conventional UTXO chain — wallets, transfers, blocks, P2P. It
exists to be a durable settlement layer, and nothing about it is AI-specific.

**Layer 2** is the part that makes the compute work worth doing. It is a task
economy: a **submitter** posts an escrow for a described computation, a **worker**
claims it, runs it and submits a result hash, and anyone may **challenge** that
result. A committee then decides whether the work was correct, and settlement
moves the money accordingly.

The six L2 transaction types are the whole vocabulary:

| Type | Value | Purpose |
|---|---|---|
| `0x10` Post | Submitter | Open a task, lock the escrow, publish the compute spec |
| `0x11` Claim | Worker | Take the task, post a deposit |
| `0x12` Submit | Worker | Submit the result hash with a signed attestation |
| `0x13` Dispute | Anyone | Challenge the result with a counter-result and a deposit |
| `0x14` Settle | Committee | Apply the decision: pay, refund, slash |
| `0x15` ExitQueue | Owner | Start withdrawing back to Layer 1 |

A task moves through six states: `Open → InProgress → ResultSubmitted →
Disputed? → Settled`, with `Expired` as the timeout branch.

**What this is for, concretely.** If a machine can produce a result that anyone
else can check without re-running it, that machine can be paid for it without
both sides trusting each other. That is the economic claim: verifiable
delegation of computation, with the blockchain as the escrow and the arbiter.

---

## Machines, agents and robots

There is a full policy layer for software acting on someone's behalf. It lives in
`jnt-core/src/agent.rs` and is **pure and deterministic** — no clock, no
randomness, no I/O — so a wallet and a service reaching the same inputs reach the
same answer.

**Agent identity.** `derive_agent_id(network_id, role, owner)` gives a stable
identifier for an actor. Three roles exist: `Human` (a wallet), `Machine` (a
device spending under a policy), and `Service` (an identity that *receives*
payments). The ID is network-bound, so the same device has different IDs on
different chains.

**Spending policies.** A `SpendPolicy` is owner-signed and answers exactly one
question: *may this agent, at this height, spend this much to this recipient?*
Every refusal is a named error, and the ambiguous cases all fail closed:

- an **empty recipient list** authorizes nothing — not "anything";
- an **empty service list** authorizes no service-tagged payment;
- a **nonce must strictly increase**, so an authorization cannot be replayed;
- a height below the policy's own window start refuses — time does not run
  backwards inside a policy;
- cumulative spend is bounded **per window**, and the window rolls over rather
  than accumulating forever.

**No second currency.** The `owner` field is an ordinary address, so machine and
human balances live in the same UTXO set under the same issuance schedule. There
is no separate "machine token".

**Payments.** `MachinePayment` is the canonical format. `ReceiptBook` records
deterministic service receipts and refuses a receipt that conflicts with an
existing one for the same payment. `PaymentTracker` is an exact-payment replay
guard.

**Reputation.** A bounded accumulator per identity, driven by a **fixed weight
table in code, not data**:

| Event | Weight |
|---|---|
| Service completed | +1 |
| Payment completed | +1 |
| Verified work | +2 |
| Dispute won | +1 |
| **Dispute lost** | **−3** |

An event carries no amount, no weight and no signature of its own — the weights
are not forgeable by producing a differently-shaped event. Losing a dispute costs
three times what winning one earns, so baseless challenges are expensive. It is
**not mintable**: nothing here creates a token.

**Streaming micro-payments.** `PaymentStream` is pay-as-you-use: a payer-signed
rate per block, a window, a hard cap, a recipient, and the governing policy for
non-human payers. Settlement receipts are payer-signed and the `StreamBook` is
fail-closed — exact amounts, strictly ordered, non-future settlements, accrual
checked for wraparound. Settlement rides the ordinary payment path with the
stream id as the reference, so there is no new transaction type.

**MCP.** `jnt-mcp` is a keyless MCP surface over agent identity, payments,
receipts and reputation.

> **Scope limit worth stating.** This layer changes no consensus rule. It is a
> library the node, wallet and worker SDK all call. Until a decision wires it into
> `submit_at`, it cannot by itself move a coin — a policy constrains spending, it
> does not create spending authority.

---

## Verified Work Certificates

A **VWC** is the protocol's receipt for work that settled as correct: task `T`
settled `Correct` with result `R`, worker `W` paid `P` satoshi at height `H`. It
is a *derived consequence* of a settlement, never a claim an actor makes — there
is no issuance transaction and no issuer key, because the settlement path already
did all the authorizing.

**What makes it trustworthy.** Its `id` is derived from every other field, so a
tampered certificate cannot carry a matching id, and its encoding is byte-unique.

**There are two kinds, and the difference is load-bearing:**

| Kind | What backs it | Offline-verifiable? |
|---|---|---|
| `Quorum` | The settle payload's own BLS aggregate over the decision | **Yes** — against the validator set |
| `WindowElapsed` | Nothing but the on-chain record that nobody objected in time | **No** |

### The unchallenged-result rule

This is the most important thing to understand about VWC certificates.

A worker submits a result, and if nobody challenges it inside the dispute window,
the task auto-settles `Correct` and the worker is paid. **That is correct
protocol behaviour.** The timeout economics require a challenge to overturn a
settlement, because otherwise anyone could file a dispute and never resolve it,
stalling every task forever.

So a wrong result that nobody challenges in time *is* paid. What must never
happen is that payment being mistaken for verification. Three things prevent it:

- `asserts_correctness()` returns `false` for a `WindowElapsed` certificate;
- `validate_verified()` refuses it by name;
- `is_offline_verifiable()` returns `false`.

A relying party that needs independent proof must call `validate_verified`, and
there is no argument by which the weak basis satisfies it. The distinction is
structural, not a doc comment you can forget.

The residual risk is economic, not cryptographic: an unchallenged wrong result
earns its payment, and the only correction is a challenger who posts a deposit
and acts in time.

### What a VWC is used for

- **Reputation.** A `VerifiedWork` event carries weight +2.
- **Offline settlement.** A party that will not trust an on-chain record can
  check a `Quorum` certificate's aggregate against the validator set directly.
- **Earnings.** `jnt-worker` derives earnings from protocol state rather than
  from anything a server tells it.

A `Fraudulent` or `Expired` settlement issues **no** certificate — those are a
slash record and a refund respectively, not evidence of correct work.

---

## How fraud is detected

The canonical CPU reference decides. Nothing else is authoritative, and no
caller can supply the answer.

### The reference

`compute_ir::reference_result_hash(task_id, ir_hash, input_hash, required_memory_bytes)`
is a fixed-round permutation over the task's own committed fields. It commits to
the *task*, never to a caller's claim about it.

Two properties make it authoritative:

- **It is not interpreted.** The reference is a permutation over commitments, not
  an interpreter for arbitrary IR. SPEC §16.4/§16.5 forbid an on-chain
  interpreter, and this is the shape that respects that: a fixed function, not a
  runtime.
- **It has no height, clock or RNG input.** Identical task fields produce
  identical bytes on every machine, every run.

### The lifecycle

```
worker submits R
      │
      ├─ nobody challenges inside the window
      │     → auto-settle Correct → paid → WindowElapsed VWC
      │                          (a receipt, NOT a verification)
      │
      └─ challenger files R' with a deposit
            → DisputeEngine::resolve computes the reference itself
                  reference == R   → WorkerCorrect     → Verdict::Correct
                  reference == R'  → ChallengerCorrect → Verdict::Fraudulent
                  reference == neither → Inconclusive  → settles nothing
```

`DisputeEngine::resolve` reads the evidence from the contract and computes the
reference from the contract's own fields. It never accepts the reference as a
parameter — taking it as an argument would let any caller dictate the verdict.

**"No match is not guilt."** An inconclusive arbitration settles nothing. A
malformed or unexecutable task cannot become a fraud conviction by accident.

### The vote transport

A committee member signs one vote per held key — four keys is four committee
members, not one member with four signatures, because a quorum counts *distinct*
signers.

A vote binds the task, the verdict, the reference result, the network, the height
and the signer, under its own domain separation tag. It signs exactly
`SettlePayload::signing_hash`, which is what lets a quorum of votes aggregate
into the aggregate the settlement transaction carries — and lets the settlement
path re-verify it from scratch with real BLS pairings.

Receiving nodes check a vote against **their own** committee and height, and relay
only what they accepted, so a bad vote travels at most one hop. One vote per
signer means a replay, a duplicate, or a relay loop cannot inflate quorum.

A **split committee** (two honest members disagreeing) is refused but *not*
recorded as equivocation — blaming an honest signer for the committee's
disagreement is exactly the kind of thing that gets turned into a slash. A genuine
double-sign is recorded as `ArbitrationEquivocation`.

> **One stated limitation.** A vote signs the settle *decision*, so its signature
> verifies on any chain carrying that decision. Network and height are checked
> against the node's own chain at tally time rather than bound into the signature.
> Binding them into the hash would change `SettlePayload::signing_hash` — a
> consensus change — so it is documented in
> [`arbitration.rs`](crates/jnt-core/src/arbitration.rs) rather than made
> unilaterally.

### What a fraud verdict does

| | |
|---|---|
| Worker | Deposit slashed through the M2 vault: 50% burned immediately, 50% vests linearly over a year |
| Submitter | Refunded whole |
| Challenger | Paid a bounty from the PSCB reserve; their deposit returns |
| Certificate | **None** — a fraud verdict is not evidence of correct work |

Settlement fees are proportional: 0.1% of task value, 1 000-sat minimum.

---

## How withdrawals work

Deposits are not one-way. An owner on Layer 2 can bring value back to Layer 1.

1. **Deposit.** An ordinary Layer 1 payment to the profile's derived sink
   address. No new transaction type. Credited 1:1 after finality depth.
2. **Queue.** The owner signs an `ExitQueue` transaction, which debits
   `amount + exit_fee + queue_fee` and records `(owner, nonce) → (amount,
   destination, height)`. Nonces are per-owner and strictly increasing.
3. **Mature.** After finality depth *and* binding finality, the exit is
   settleable. Exits use the same or a stronger rule than deposits, never weaker.
4. **Release.** A **permissionless crank** builds the claim: it consumes sink
   outputs and proves the exit record against the L2 state root committed at the
   queue block.

The claim is authorised by an **inclusion proof, not a signature**, because the
sink holds no key. Consensus pays only the destination the proven record names —
a caller cannot redirect it — and the claimant collects a fee the owner prepaid
at queue time, which is what makes a crank nobody wants to run a non-issue rather
than a griefing vector.

**Exact funding only.** A claim must consume sink outputs summing *exactly* to
`amount + exit_fee + required L1 fee`, with no change and no tip. An exit whose
funding is not sitting in a subset summing to that figure stays queued rather
than draining a stranger's deposit. The cost is a liveness edge: it can wait.

**Anyone can crank.** Consensus has always been permissionless here, but until
recently the only way to obtain a claim was to be the node's own miner.
`GET /v1/exit/crankable?claimant=<address>` hands the settleable claims to any
third party, so a non-miner can build a block with them.

**Reorg-safe.** A release is an ordinary undoable Layer 1 operation: rollback
restores the sink outputs, clears the identity, and L2 replay regenerates the
watch.

**Conservation is unchanged.** The joint check needed no exit term at all — the
L1 payment and the L2 debit cancel while the sink term falls by the same amount.

> **Not active on mainnet.** `mainnet.exit_activation_height` is `0`, which means
> *never*, not *from genesis*. A fresh mainnet node refuses both a committed L2
> root and an exit claim. Testnet and mini activate at height 1.

---

## Validators and finality

**Bonded stake** (`bond.rs`, Decision 20). Three transaction types — `TX_BOND`,
`TX_UNBOND`, `TX_SLASH` — feed a bond ledger with a bond-order index. Minimum
stake is `MIN_VALIDATOR_STAKE_SAT` = 5 000 JNT, an immutable consensus constant
rather than a tunable. Unbonding locks for `UNBONDING_PERIOD_BLOCKS` = 1 008
(seven days). Provable equivocation burns the full bond.

The committee is the **first 21 bonds by bond order**, derived from canonical
chain state and nothing else. Finality keys follow the ledger, so a bond changes
the validator set and a reorg rewinds it.

**Checkpoint signing** (`signing.rs`) is the other half of M5. Verification has
existed since the gadget landed — six clauses with real BLS12-381 pairings,
bound to the canonical block at the certificate's height. What was missing was any
code that *produced* a certificate: every one in the tree was a test helper, so
binding finality could not activate anywhere because nothing ever signed.

It exists now:

```sh
jnt-node validator --network testnet --data-dir ./chain --add --label my-key
```

Keys live in `<data-dir>/validators/`, mode 0600 on unix, deliberately separate
from `wallets.json` — a wallet holds funds this node spends, a validator key
signs consensus messages. `serve` loads them, signs a checkpoint at each epoch
boundary for a block it holds as its own canonical tip, and broadcasts it. A node
with no keys signs nothing and still verifies and relays.

Signing is not a privilege. A certificate is accepted only if a quorum of the
*chain-derived* committee signed the *chain's own* hash, so a signer producing
bytes for a block nobody holds gets a certificate every peer rejects.

**Why it is off on mainnet.** `finality_activation_height` is `0`, and
`genesis_validators` is empty. With no committee and no bonded stake, checkpoint
verification fails closed — the honest state, not a broken one. Testnet activates
at height 20 with four deterministic keys and quorum 3 of 4.

---

## Component status

Every row is a code path that exists today, with the honest caveat where one
applies.

| Component | State | Notes |
|---|---|---|
| L1 consensus, fork choice, reorg | **Shipped** | 12 red-team regressions pin the failure modes |
| Hybrid PoW (3 stages) | **Shipped** | Independent Python reference reproduces all 21 digests |
| Supply, ladder, tail, rate anchor | **Shipped** | Stock cap removed by Decision 18 |
| P2P: blocks, transactions, checkpoints, votes | **Shipped** | Real sockets; 3-node tests over real transport |
| L2 task lifecycle (6 states, 6 tx types) | **Shipped** | Full lifecycle suites |
| L2 deposits | **Shipped** | Active on testnet/mini |
| L2 → L1 exits | **Shipped** | **Off on mainnet** (activation height unset) |
| Dispute engine + canonical reference | **Shipped** | Reference computed by the engine, never supplied |
| Arbitration vote transport | **Shipped** | Signed, relayed, tallied, quorum-checked |
| **Arbitrator key custody** | **Not decided** | Organisational — who runs the arbitrators |
| **Slash transaction for vote equivocation** | **Not built** | Evidence is recorded; the slash path is not wired |
| Verified Work Certificates | **Shipped** | `Quorum` verifiable; `WindowElapsed` refused by `validate_verified` |
| Bonded stake, unbonding, slashing | **Shipped** | 15 attack-first tests |
| Checkpoint signing | **Shipped** | 18 unit + 6 cross-node tests |
| **A live validator committee** | **Does not exist** | No operator is bonding 5 000 JNT |
| Machine/agent policy layer | **Shipped** | Pure library; **not wired into `submit_at`** |
| Payments, receipts, reputation, streaming | **Shipped** | Policy layer, no consensus change |
| Worker SDK | **Shipped** | 43 tests including privilege-escalation suite |
| M1 fee split | **Consensus-active** | The only mechanism that is |
| M2 slash vault | Holds L2 slashes | Not otherwise triggered |
| M3 compute IR | Provides the reference | Envelopes carried, no interpreter |
| M4 HBM puzzle | **Deliberately unregistered** | See below |
| M5 finality | **Off on mainnet** | Both sides built; activation unset |
| REST API, `/metrics` | **Shipped** | Opt-in, loopback, unauthenticated |
| Release pipeline | **Shipped** | CI-gated, 3 targets, checksums, **unsigned** |
| **Independent security review** | **Not done** | Cannot be self-certified |

### Why M4 is off, deliberately

`hbm_pow.rs` implements the memory-hard permutation, its parameter scaling and
ten tests. It is **not** registered as a `puzzle_id`, so it validates nothing.
Registering it would change the consensus puzzle without an independent security
review of the memory parameters — that is not a mistake worth making before a
review. Base PoW (`puzzle_id = 1`) is the active mechanism.

---

## What changed, and when

Where a mechanism was built in stages, this is what was true before and what is
true now. Full record in [CHANGELOG.md](CHANGELOG.md).

| Area | Before | Now |
|---|---|---|
| **Stock supply cap** | A hard cap on total issuance | **Removed** (Decision 18). The ladder totals 39 157 124 JNT, then an approved tail pays 0.1 JNT/block forever, bounded by a 1%-per-period rate anchor |
| **L2 withdrawals** | Undefined; deposits were one-way | **Implemented** (Decision 19): `ExitQueue`, a proof-authorised sink spend, a permissionless crank, reorg-safe |
| **Exit accessibility** | Only a node's own miner could build a claim | **`GET /v1/exit/crankable`** hands claims to any third party |
| **Stake and bonds** | No bond ledger, no stake transaction | **Implemented** (Decision 20): bond/unbond/slash, bond-order committee, ledger-derived finality keys |
| **What counts as fraud** | Unspecified — the slash vault stayed inert | **The canonical CPU reference decides** (Decision 21). No caller can supply it |
| **Arbitration transport** | No way to exchange verdicts; the quorum had to be assembled out of band | **Signed votes relay over P2P**; a quorum aggregates into the settlement |
| **Checkpoint signing** | Verification existed; **nothing ever signed**, so binding finality could not activate anywhere | **Production signing** via `jnt-node validator` and the serve loop |
| **Settle fee** | A flat fee a small escrow could not cover, failing closed | **Proportional** (Decision 23): 0.1% of task value, 1 000-sat minimum |
| **L1/L2 disagreement** | An exit claim with no L2 record was caught only by `debug_assert`, which compiles out of release builds | **Recorded as `UnbackedClaim`** and exposed, so a release build reports the divergence |
| **Unchallenged results** | A wrong unchallenged result produced a certificate that `validate()` accepted with no signal | **`asserts_correctness()` / `validate_verified`** make the weak basis unmissable |
| **HBM** | Unregistered, unspecified | Unregistered **by decision**, with the reason recorded — an open item, not an omission |

---

## Repository layout

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | **Normative.** Where a disagreement exists, this wins. |
| `crates/jnt-core/` | Protocol implementation. All consensus logic. |
| `crates/jnt-net/` | P2P wire protocol, sync and relay. |
| `crates/jnt-store/` | Append-only checksummed block log, crash recovery. |
| `crates/jnt-l2/` | Layer 2: contracts, disputes, certificates, exits. |
| `crates/jnt-node/` | CLI and node daemon. |
| `crates/jnt-worker/` | Worker-side SDK. Client only, no consensus. |
| `crates/jnt-mcp/` | Keyless MCP surface over agent identity and payments. |
| `fuzz/` | 14 cargo-fuzz targets over the attacker-controlled boundaries. |
| `sim/` | Independent Python reference and attack simulations. |
| `tests/vectors/` | Consensus vectors. Generated from source, never hand-edited. |
| `docs/` | Design records, audits and readiness reports. |

Seven crates in one workspace. **All consensus logic lives in `jnt-core`**, which
has no I/O, no clock and no network. The `mini` profile is the same code with
different parameters — never a second implementation — so anything tested on
`mini` is the production code path.

Key documents: [`docs/decisions.md`](docs/decisions.md) for design decisions,
[`docs/status.md`](docs/status.md) for the verification record,
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md) for what blocks launch,
[`docs/monetary-policy.md`](docs/monetary-policy.md) for the supply analysis.

---

## Network profiles

Same code, different numbers.

| | `mainnet` | `testnet` | `mini` |
|---|---|---|---|
| Block time | 600 000 ms | 1 000 ms | 1 000 ms |
| Halving period | 262 800 | 2 000 | 2 000 |
| Start reward | 76 JNT | 76 JNT | 76 JNT |
| Finality depth | 100 | 20 | 20 |
| Coinbase maturity | 100 | 10 | 10 |
| Genesis validators | **none** | 4 deterministic | 4 deterministic |
| Binding finality | **off** | on at height 20 | off |
| Exits | **off** | on at height 1 | on at height 1 |

`mainnet` deliberately ships with no committee and no activation, so it fails
closed rather than verifying against nothing.

---

## Commands

```
jnt-node <COMMAND> [OPTIONS]

  init        Create a chain directory, a miner wallet and the genesis block
  mine        Mine blocks and extend the chain
  send        Spend from a wallet address, local or over P2P
  status      Print chain tip, difficulty, supply, wallet balance, L2 pipeline
  verify      Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance     List the unspent outputs of an address
  wallet      Create or list wallets
  validator   Add or list checkpoint-signing keys
  export      Write the canonical chain to JSON
  serve       Run a P2P node: relay, sync, opt-in REST API, exit crank, signing
```

Common options: `--network <mainnet|testnet|mini>` (default `mini`) and
`--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--peers`, `--interval`,
`--api-listen` and `--no-mine`. `send --amount` is in satoshis while printed
figures are in JNT.

---

## Testing

```sh
cargo test --workspace                                   # 993 tests, 0 failures
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python sim/verify_vectors.py --check                     # consensus vectors
```

Targeted suites for the fast loops:

```sh
cargo test -p jnt-core --lib arbitration::    # fraud-arbitration votes
cargo test -p jnt-core --test cp_signing_nodes # quorum, conflicts, restart
cargo test -p jnt-core --test bond_stake      # bonded-stake attacks
cargo test -p jnt-l2  --test unverified_result # the unchallenged-result rule
cargo test -p jnt-node --test arbitration_path # full fraud lifecycle
cargo test -p jnt-net  --test arbitration_votes # 3 nodes, real TCP
cargo test -p jnt-node --test exit_crank_api   # withdrawal flow over HTTP
cargo test -p jnt-core --test redteam          # adversarial regressions
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release
build, the vector cross-checks, attack simulations, and all fourteen fuzz targets
on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a
tagged tree before publishing artifacts with checksums.

**Vectors.** `tests/vectors/` holds the consensus byte layouts, generated only
from the implementation. `sim/jounit_reference.py` is a second PoW implementation
written from `SPEC.md` rather than from the Rust, and it reproduces all 21 puzzle
digests — that agreement is the evidence the spec is unambiguous rather than
merely self-consistent.

**Fuzzing.** 14 cargo-fuzz targets over L1 wire, mempool, storage and
checkpoints; L2 codec, disputes, state and certificates; and the worker. They
assert capability invariants — decode/encode inversion, bounded allocation, value
conservation under adversarial transaction programs — not just panic-freedom.

**Red team.** `crates/jnt-core/tests/redteam.rs` holds 12 adversarial integration
tests, each confirmed to fail against the code it now guards. The full record of
defects found and fixed is in [docs/status.md](docs/status.md).

---

## Not ready to launch

The code is done. Launching mainnet is blocked by things no amount of code
replaces.

| Blocker | Why it is blocked |
|---|---|
| **No validators** | `mainnet` declares an empty committee. The ledger that would hold bonded stake is built and tested, but no operator is bonding 5 000 JNT to run a validator. Without a committee, checkpoint verification fails closed. |
| **No independent security review** | 993 passing tests are not an external audit. This cannot be self-certified, by anyone, ever. |
| **Activation heights unset** | `exit_activation_height` and `finality_activation_height` are `0` on mainnet. Deliberately off, and should be set only after a launch-candidate rehearsal proves the whole path. |
| **Arbitrator key custody** | The arbitration transport is built; who runs the arbitrators is an organisational decision. |
| **Operations** | No bootnodes, no log shipping, no published PGP key. Artifacts are unsigned because no signing key is published. |

What this means in practice: **a fresh `jnt-node init --network mainnet` runs
today, and on it withdrawals and binding finality are both inactive.** That is
fail-closed, not broken — no funds can be lost — but users should know before
they point real money at it.

`testnet` is the appropriate next milestone and the right place to rehearse
everything above. [docs/mainnet-readiness.md](docs/mainnet-readiness.md) tracks
each item with its evidence.

---

## License and trademark

**Code: `MIT OR Apache-2.0`** — the standard permissive Rust dual licence. Both
texts ship at the repo root (`LICENSE-MIT`, `LICENSE-APACHE`). You may use,
modify, run, audit and redistribute the software, including commercially.

**Name and marks: trademarked.** The *Jounit* name, the `JNT` ticker and the
project's logos are trademarks, not part of the code licence. See
[TRADEMARK.md](TRADEMARK.md).

The distinction is the same one Bitcoin uses: **the code is open so anyone can
run it, and the name is protected so nobody can pass themselves off as us.**
Nothing in an open-source licence can stop someone forking the code — that is
deliberate, and it is how the ecosystem works. What the trademark stops is
someone shipping a product under our name that is not this software.

If you want to use the name or marks commercially, or you want a licence other
than the one above, get in touch first.

---

Full protocol specification: [`SPEC.md`](SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).