# Jounit (JNT)

AI-native cryptocurrency. Mining that does useful work, and a payment layer built for AI agents. Pre-launch.

> **Status: ready to launch.** Every mechanism described here is implemented
> and tested. Withdrawals (`exit_activation_height = 1`) and binding finality
> (`finality_activation_height = 100`) are active on mainnet from genesis —
> no validator committee or pre-existing operator required, like Bitcoin. Run
> `jnt-node init --network mainnet`, then `jnt-node run --network mainnet`.

**Author and copyright:** Swamy Gadila. The code is Â© 2026 Swamy Gadila, and
the *Jounit* name, `JNT` ticker and logos are his trademarks â€” see
[License and trademark](#license-and-trademark).

---

## Contents

- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [Supply](#supply)
- [What the chain is for](#what-the-chain-is-for)
- [Capabilities the project is building](#capabilities-the-project-is-building)
- [What makes this different](#what-makes-this-different)
- [Use cases](#use-cases)
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

1. **A SHA-256 hash chain** â€” carries the security. This is what a quantum
   adversary has to break.
2. **An integer-only neural network** â€” makes the work meaningful for AI hardware.
3. **A final hash** â€” binds both into the value that must fall below the target.

Two properties keep the neural stage a cost model rather than a liability:

- **Capped share.** The network must account for 30â€“50% of modelled work. A
  registry entry outside that band is rejected outright, so it can never become
  the weak link.
- **No floating point, anywhere.** Weights derive from the epoch id by SHA-256,
  the forward pass accumulates in `i64` and wraps to `i32`, and every integer is
  explicit. Two implementations on two machines produce identical digests â€” which
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
# Wallet keys are encrypted at rest: set a passphrase for this shell, or add
# --allow-plaintext-wallet to init if you deliberately want a plaintext file.
export JNT_WALLET_PASSPHRASE=change-me

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

There is **no stock cap**. That is a deliberate change â€” see
[Decision 18](docs/decisions.md) â€” and the current bounds are different in kind.

**The ladder** halves in whole JNT every 262 800 blocks (~5 years at a 10-minute
block):

```
76, 38, 19, 9, 4, 2, 1 JNT
```

Whole JNT, not shifted satoshis: halving 9.5 â†’ 4.75 would break the arithmetic.

**Premine is 0%**, enforced in code rather than in prose. Genesis mints nothing.

**The ladder totals exactly 39 157 124 JNT.** Not the 39 157 200 a geometric
shortcut suggests â€” genesis occupies a rung-0 height without minting, so the
first rung is paid by `H âˆ’ 1` blocks rather than `H`. That 76 JNT is the
difference between the design document's approximation and what the chain can
actually reach, and `supply::max_issuance_sat` reports the real figure.

**The tail** takes over after the ladder (height 1 839 600) and never stops:

```
0.50 â†’ 0.25 â†’ 0.125 JNT, then a permanent 0.1 JNT floor
```

So issuance continues forever, reaching the floor at height 2 628 000 (~50 years)
instead of terminating. Testnet and mini pay a constant 1 sat per block from their
first tail period.

**Two bounds enforce this**, both checked in `Chain::apply_block` so the miner,
validator and node cannot disagree about what is mintable at a height:

1. **The issuance integral.** A block may not mint past
   `cumulative_issuance_sat(height)`. Overflow is refused rather than wrapped â€” a
   wrapped sum would compare small and pass the bound.
2. **The rate anchor.** After ladder exhaustion, gross issuance inside the current
   halving window may not exceed **1% of the supply issued at that window's
   start**. The approved schedule sits ~3Ã— under it, so the anchor never binds it
   today â€” it exists to refuse a *future* schedule that would dilute far faster.
   The ladder era is grandfathered.

**Net supply can fall.** The base fee splits 50/50 into a burn and an on-chain
reserve, so usage *removes* supply from the spendable set. Combined with a
declining tail reward, the simulation measures net supply falling below
break-even at â‰ˆ5% activity and being at 25% at the fee floor. This is a measured
consequence, not a bug â€” the analysis and sensitivity tables are in
[docs/monetary-policy.md](docs/monetary-policy.md).

Gross issuance, removal and net supply are reported by `status`,
`GET /v1/conservation` and the `/metrics` gauges.

---

## What the chain is for

Two distinct layers, with different jobs:

**Layer 1** is a conventional UTXO chain â€” wallets, transfers, blocks, P2P. It
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

A task moves through six states: `Open â†’ InProgress â†’ ResultSubmitted â†’
Disputed? â†’ Settled`, with `Expired` as the timeout branch.

---

## Capabilities the project is building

The base layer above is complete and running. What follows is where it is going,
listed in dependency order because several of these are only meaningful once the
first exists.

Each section says what the capability is and what it supports. **What is actually
built differs per item, and the status is stated in each heading rather than
implied by being on the same page** â€” the [Component status](#component-status)
table carries the same labels. Two of the five are held on decisions that are
organisational rather than technical, and are marked as such instead of being
started to look further along.

### Escrowed service contracts â€” _in development_

**Built:** the general `ServiceContract`, its transitions, a validated
`ServiceContract::open` constructor for non-compute deliverables, and a
non-compute deliverable that drives them.

The task economy above is a *specific case* of a general primitive: party A
commits to a deliverable and bonds against it, party B escrows payment,
settlement fires when the deliverable is verified. Refactoring that into a
standalone **ServiceContract** means the same escrow, bonding and dispute
machinery serves any computation with an admissible verifier â€” not only a neural
network task.

The design constraint is what makes it work: the verifier must be a
deterministic function of committed inputs, free of height, clock and randomness.
Work already covers the general form, and the compute task is one instantiation
of it rather than the only one.

**What it supports:** any task where one party can produce a result that another
can check without re-running it.

### Attenuated delegation chains â€” _in development_

Multi-agent systems need an owner to grant an agent a subset of their own
spending authority, and that agent to do the same downward. Each level inherits a
**strict subset** of its parent's spend policy — never a wider one — so authority
narrows as it travels.

A spend under a chain carries the chain, signed: a payment names its own
agent id, which is derived from the ancestry it presents rather than from the
payer's address. The node records the links (so it can prove the lineage later),
verifies the owner's signature on every policy it grants under, and propagates a
revocation down to every recorded descendant. Consent, key custody and the
existence of a committee are organisational choices this document does not make.

**What it supports:** machine fleets and agent hierarchies where the operator
must bound what any single agent can spend, without re-authorizing each
transaction by hand.

### Conditional and oracle-gated payments â€” _in development_

Payment that releases against a stated condition rather than a manual approval:
"release when the result matches," "release when latency stayed under a
threshold." This is designed so that only conditions a third party can evaluate
deterministically are admitted, which is the discipline that keeps the escrow from
acquiring a trusted party. Conditions that genuinely require an oracle are
refused when the escrow opens: this codebase implements no oracle verifier, so
an oracle-gated escrow would be a contract nobody could ever satisfy. Every
escrow also expires `ESCROW_EXPIRY_BLOCKS` (1 008 blocks, seven days) after it
opens and refunds its payer, so a lost key or a silent arbitrator can no longer
hold value forever.

**What it supports:** pay-as-you-use and outcome-based pricing that settles
itself, without a human in the loop to release funds.

### Undercollateralized agent credit â€” _in development_

**Built:** the collateral arithmetic, the position lifecycle with a repayment
deadline, and a credit book that holds bonds, balances and locked collateral
under a conservation invariant.

An agent with a demonstrated track record can borrow against future work rather
than pre-funding every transaction. This is deliberately built on two
constraints: reputation is published as a deterministic **view** read off
on-chain events, and credit is **always collateralized** â€” a posted bond
discounts the requirement, never replaces it.

The design is explicit that reputation is not a consensus input. A credit limit
computed on-chain from a mutable score would make every reputation update a
consensus event and make fresh identities farmable, which is the cheapest attack
against the gate. So `credit.rs` has no signature that accepts a score at all â€”
the guarantee is the type system refusing the call, not the code declining it.

**If a position defaults**, settlement takes the position's own collateral first,
then the bond, and **never reputation**. Collateral in excess of the debt returns
to the borrower: a default takes what it is owed and no more, so an
overcollateralized position that went bad still belongs to its borrower outside
the debt. Any debt left after both is a reported shortfall, which the lender
absorbs rather than the protocol inventing funds to cover.

**A position runs to a deadline.** Before it, a default is refused â€” a lender
cannot settle a merely late position on a whim â€” and the bond a position is
priced with must be posted before it opens, so no discount is ever unbacked.
The credit book holds free balances, posted bonds and collateral locked inside
live positions, and asserts after every mutation that their sum equals
everything deposited: value is moved, never created.

**What it supports:** an agent earning from work it has not yet performed, with
the risk carried by a bond instead of by trust in a stranger.

### Compute-backed validator staking â€” _implemented, empty on mainnet_

Validators that also serve verified work earn more, which ties the protocol's
security budget and its utility budget into one budget. The condition is that
what a validator is paid for is *verified* work, where verified means a quorum
proved it â€” not work that was merely submitted and left unchallenged. The
committee is derived **by bonded stake** (TopN), see [Validators and
finality](#validators-and-finality).

**What it supports:** making the neural stage of mining economically useful
rather than merely elegant, and aligning the interests that secure the chain with
the work the chain exists to sell.

---

## What makes this different

These are properties verifiable in this repository, not aspirations.

### A verifier that cannot be talked out of its answer

The canonical reference that decides fraud is computed by the arbitration engine
from the task's own committed fields. It is never accepted as an argument, so no
caller can dictate the verdict. This is a structural property rather than a
policy â€” see
[How fraud is detected](#how-fraud-is-detected).

### A receipt that is not mistaken for verification

When a result goes unchallenged, the protocol pays it and issues a certificate â€”
and that certificate states plainly that it proves nothing. A `WindowElapsed`
certificate is a record that nobody objected; `validate_verified()` refuses it by
name, and `asserts_correctness()` returns `false`. Relying parties that need
independent proof must demand the quorum basis, and there is no argument by which
the weak one satisfies it.

The distinction is structural rather than documented, which is the point: the
weak basis is unmissable rather than a convention a caller can forget.

### Consensus with no floating point anywhere

The consensus core computes in integers end to end: weights derive from the epoch
id by SHA-256, forward passes accumulate in `i64` and wrap to `i32`, difficulty
and supply use explicit arithmetic with every overflow refused rather than
wrapped. A wrapped sum would compare small and pass a bound â€” this is a security
property, not a style preference.

Two separate implementations, in two languages, produce identical digests. The
Python reference under `sim/` was written from the specification rather than from
the Rust, and reproduces the puzzle digests the chain uses. That agreement is
evidence the specification is unambiguous rather than merely self-consistent.

### Work that cannot be precomputed

Mining weights derive from the epoch id, so no miner can compute them before an
epoch starts. The neural stage is a cost model with a bounded contribution rather
than the load-bearing part of the proof â€” the SHA-256 chain carries the security,
so the neural work can never become the weak link it is meant to make useful.

---

## Use cases

These are the things a UTXO chain with a task economy on top of it can do that
the two layers alone cannot.

**Settlement for work nobody re-runs.** Someone pays for a result; someone else
checks it without re-doing it. The chain holds the escrow and decides the
outcome, so the two sides need no prior relationship and no arbitrator they both
trust.

**Machines spending under a written policy.** An owner authorizes once, offline,
and every later spend is checked against it with the owner offline â€” bounded per
transaction, bounded per window, to named recipients and named services, with a
nonce that makes an authorization unreplayable and a kill switch.

**Payment for what a machine produced, not what it claimed.** A verified-work
certificate is a derived consequence of a settled task, never a claim an actor
makes, so it can be shown to a third party as evidence.

**Reputation that travels with the identity and cannot be bought.** An event
carries no weight of its own, so a differently-shaped event cannot forge a
better score, and losing a dispute costs three times what winning one earns.

**Value that comes back.** Deposits are not one-way. An owner can bring value
back to Layer 1 through a queue, a maturity period and a proof-authorised release
that anyone can crank.

**What this is for, concretely.** If a machine can produce a result that anyone
else can check without re-running it, that machine can be paid for it without
both sides trusting each other. That is the economic claim: verifiable
delegation of computation, with the blockchain as the escrow and the arbiter.

---

## Machines, agents and robots

There is a full policy layer for software acting on someone's behalf. It lives in
`jnt-core/src/agent.rs` and is **pure and deterministic** â€” no clock, no
randomness, no I/O â€” so a wallet and a service reaching the same inputs reach the
same answer.

**Agent identity.** `derive_agent_id(network_id, role, owner)` gives a stable
identifier for an actor. Three roles exist: `Human` (a wallet), `Machine` (a
device spending under a policy), and `Service` (an identity that *receives*
payments). The ID is network-bound, so the same device has different IDs on
different chains.

**Spending policies.** A `SpendPolicy` is owner-signed and answers exactly one
question: *may this agent, at this height, spend this much to this recipient?*
Every refusal is a named error, and the ambiguous cases all fail closed:

- an **empty recipient list** authorizes nothing â€” not "anything";
- an **empty service list** authorizes no service-tagged payment;
- a **nonce must strictly increase**, so an authorization cannot be replayed;
- a height below the policy's own window start refuses â€” time does not run
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
| **Dispute lost** | **âˆ’3** |

An event carries no amount, no weight and no signature of its own â€” the weights
are not forgeable by producing a differently-shaped event. Losing a dispute costs
three times what winning one earns, so baseless challenges are expensive. It is
**not mintable**: nothing here creates a token.

**Streaming micro-payments.** `PaymentStream` is pay-as-you-use: a payer-signed
rate per block, a window, a hard cap, a recipient, and the governing policy for
non-human payers. Settlement receipts are payer-signed and the `StreamBook` is
fail-closed â€” exact amounts, strictly ordered, non-future settlements, accrual
checked for wraparound. Settlement rides the ordinary payment path with the
stream id as the reference, so there is no new transaction type.

**MCP.** `jnt-mcp` is a keyless MCP surface over agent identity, payments,
receipts and reputation.

> **Scope limit worth stating.** This layer changes no consensus rule. It is a
> library the node, wallet and worker SDK all call. Until a decision wires it into
> `submit_at`, it cannot by itself move a coin â€” a policy constrains spending, it
> does not create spending authority.

---

## Verified Work Certificates

A **VWC** is the protocol's receipt for work that settled as correct: task `T`
settled `Correct` with result `R`, worker `W` paid `P` satoshi at height `H`. It
is a *derived consequence* of a settlement, never a claim an actor makes â€” there
is no issuance transaction and no issuer key, because the settlement path already
did all the authorizing.

**What makes it trustworthy.** Its `id` is derived from every other field, so a
tampered certificate cannot carry a matching id, and its encoding is byte-unique.

**There are two kinds, and the difference is load-bearing:**

| Kind | What backs it | Offline-verifiable? |
|---|---|---|
| `Quorum` | The settle payload's own BLS aggregate over the decision | **Yes** â€” against the validator set |
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

A `Fraudulent` or `Expired` settlement issues **no** certificate â€” those are a
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
  an interpreter for arbitrary IR. SPEC Â§16.4/Â§16.5 forbid an on-chain
  interpreter, and this is the shape that respects that: a fixed function, not a
  runtime.
- **It has no height, clock or RNG input.** Identical task fields produce
  identical bytes on every machine, every run.

### The lifecycle

```
worker submits R
      â”‚
      â”œâ”€ nobody challenges inside the window
      â”‚     â†’ auto-settle Correct â†’ paid â†’ WindowElapsed VWC
      â”‚                          (a receipt, NOT a verification)
      â”‚
      â””â”€ challenger files R' with a deposit
            â†’ DisputeEngine::resolve computes the reference itself
                  reference == R   â†’ WorkerCorrect     â†’ Verdict::Correct
                  reference == R'  â†’ ChallengerCorrect â†’ Verdict::Fraudulent
                  reference == neither â†’ Inconclusive  â†’ settles nothing
```

`DisputeEngine::resolve` reads the evidence from the contract and computes the
reference from the contract's own fields. It never accepts the reference as a
parameter â€” taking it as an argument would let any caller dictate the verdict.

**"No match is not guilt."** An inconclusive arbitration settles nothing. A
malformed or unexecutable task cannot become a fraud conviction by accident.

### The vote transport

A committee member signs one vote per held key â€” four keys is four committee
members, not one member with four signatures, because a quorum counts *distinct*
signers.

A vote binds the task, the verdict, the reference result, the network, the height
and the signer, under its own domain separation tag. It signs exactly
`SettlePayload::signing_hash`, which is what lets a quorum of votes aggregate
into the aggregate the settlement transaction carries â€” and lets the settlement
path re-verify it from scratch with real BLS pairings.

Receiving nodes check a vote against **their own** committee and height, and relay
only what they accepted, so a bad vote travels at most one hop. One vote per
signer means a replay, a duplicate, or a relay loop cannot inflate quorum.

A **split committee** (two honest members disagreeing) is refused but *not*
recorded as equivocation â€” blaming an honest signer for the committee's
disagreement is exactly the kind of thing that gets turned into a slash. A genuine
double-sign is recorded as `ArbitrationEquivocation`.

> **Fixed before mainnet.** A vote used to sign the settle *decision* only, so
> its signature verified on any chain carrying that decision. Network and
> height are now part of the signed message: `SettlePayload` carries both,
> `SettlePayload::signing_hash` covers them, and `apply` refuses a payload
> naming another network or a vote from the future. The tally still re-checks
> that every counted vote names one network and one height, and the quorum
> certificate carries the same chain context so it stays re-verifiable.

### What a fraud verdict does

| | |
|---|---|
| Worker | Deposit slashed through the M2 vault: 50% burned immediately, 50% vests linearly over a year |
| Submitter | Refunded whole |
| Challenger | Paid a bounty from the PSCB reserve; their deposit returns |
| Certificate | **None** â€” a fraud verdict is not evidence of correct work |

Settlement fees are proportional: 0.1% of task value, 1 000-sat minimum.

---

## How withdrawals work

Deposits are not one-way. An owner on Layer 2 can bring value back to Layer 1.

1. **Deposit.** An ordinary Layer 1 payment to the profile's derived sink
   address. No new transaction type. Credited 1:1 after finality depth.
2. **Queue.** The owner signs an `ExitQueue` transaction, which debits
   `amount + exit_fee + queue_fee` and records `(owner, nonce) â†’ (amount,
   destination, height)`. Nonces are per-owner and strictly increasing.
3. **Mature.** After finality depth *and* binding finality, the exit is
   settleable. Exits use the same or a stronger rule than deposits, never weaker.
4. **Release.** A **permissionless crank** builds the claim: it consumes sink
   outputs and proves the exit record against the L2 state root committed at the
   queue block.

The claim is authorised by an **inclusion proof, not a signature**, because the
sink holds no key. Consensus pays only the destination the proven record names â€”
a caller cannot redirect it â€” and the claimant collects a fee the owner prepaid
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

**Conservation is unchanged.** The joint check needed no exit term at all â€” the
L1 payment and the L2 debit cancel while the sink term falls by the same amount.

> **Active on mainnet.** `mainnet.exit_activation_height` is `1`, which means
> exits work from genesis — same as Bitcoin spends. Testnet and mini activate
> at height 1.

---

## Validators and finality

**Bonded stake** (`bond.rs`, Decision 20). Three transaction types â€” `TX_BOND`,
`TX_UNBOND`, `TX_SLASH` â€” feed a bond ledger with a bond-order index. Minimum
stake is `MIN_VALIDATOR_STAKE_SAT` = 5 000 JNT, an immutable consensus constant
rather than a tunable. Unbonding locks for `UNBONDING_PERIOD_BLOCKS` = 1 008
(seven days). Provable equivocation burns the full bond.

The committee is the **top 21 bonded validators by stake** (`derive_set` /
`SelectionRule::TopN`), each record carrying its bond-identity `stake_address`
and `stake_sat`, derived from canonical chain state — a reorg unwinds the set.
With no bonds the committee falls back to the profile's declared
`genesis_validators`, so empty-stake is still well-defined on mainnet.

This is the **one** committee definition: signing (`committee_keys` /
`committee_signing_records`), slashing (`TX_SLASH`) and finality
(`committee_records` feeding the epoch set) all read
`BondLedger::committee()`, so a certificate's bitmap indexes the same 21 keys
the verifier checks it against. Bonds only admit keys whose holder proves they
hold them: `TX_BOND` carries a 96-byte proof-of-possession signature bound to
network, bonder and key, and a payload without one does not decode.

**Checkpoint signing** (`signing.rs`) is the other half of M5. Verification has
existed since the gadget landed â€” six clauses with real BLS12-381 pairings,
bound to the canonical block at the certificate's height. What was missing was any
code that *produced* a certificate: every one in the tree was a test helper, so
binding finality could not activate anywhere because nothing ever signed.

It exists now:

```sh
jnt-node validator --network testnet --data-dir ./chain --add --label my-key
```

Keys live in `<data-dir>/validators/`, mode 0600 on unix, deliberately separate
from `wallets.json` — a wallet holds funds this node spends, a validator key
signs consensus messages. New keys are encrypted under
`JNT_VALIDATOR_PASSPHRASE` (falling back to `JNT_WALLET_PASSPHRASE` with a
warning); creation without a passphrase is refused. Old plaintext key files
still load, with a warning per file. `serve` loads them, signs a checkpoint at each epoch
boundary for a block it holds as its own canonical tip, and broadcasts it. A node
with no keys signs nothing and still verifies and relays.

`wallets.json` itself is written mode 0600 through a temp-file rename and
encrypted under `JNT_WALLET_PASSPHRASE` (Argon2id + ChaCha20-Poly1305);
writing plaintext keys requires an explicit `--allow-plaintext-wallet`.

Signing is not a privilege. A certificate is accepted only if a quorum of the
*chain-derived* committee signed the *chain's own* hash, so a signer producing
bytes for a block nobody holds gets a certificate every peer rejects.

**Active on mainnet.** `finality_activation_height` is `100`, so checkpoint
certificates become binding from height 100 onward. Before that, depth-based
finality (100 blocks) secures the chain — the same Bitcoin-style rule. With no
committee yet, checkpoint verification falls back to depth-only until validators
bond and sign checkpoints. Testnet activates at height 20 with four
deterministic keys and quorum 3 of 4.

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
| L2 â†’ L1 exits | **Shipped** | Active on mainnet from genesis (`exit_activation_height = 1`) |
| Dispute engine + canonical reference | **Shipped** | Reference computed by the engine, never supplied |
| Arbitration vote transport | **Shipped** | Signed, relayed, tallied, quorum-checked |
| **Arbitrator key custody** | **Decided (Decision 9)** | The arbitration quorum is organisational (run by Jounit operators). Separately, conditional *escrow* release names a contract-selected independent BLS arbitrator per escrow — no Jounit-held release key. |
| **Slash transaction for vote equivocation** | **Wired** | `TX_SLASH` (two conflicting, same-height, shared-signer checkpoints) verifies via `check_slash_tx` (`bond.rs`), is admitted by the mempool (`admit_stake_tx`) and applied in `apply_state_tx`: the bond is removed and 50% of its value burns in the M2 vault immediately, 50% vests to the PSCB reserve (`slash.rs`). A node API to *build* a slash tx is not exposed (submit it like any stake tx) |
| Verified Work Certificates | **Shipped** | `Quorum` verifiable; `WindowElapsed` refused by `validate_verified` |
| Bonded stake, unbonding, slashing | **Shipped** | 16 attack-first tests, including proof-of-possession refusals |
| Checkpoint signing | **Shipped** | 18 unit + 6 cross-node tests |
| **A live validator committee** | **Code shipped, no operators yet** | Bond ledger, committee derivation, checkpoint signing all built and tested. `mainnet` starts with empty `genesis_validators`; depth finality secures the chain until operators bond 5 000 JNT and sign checkpoints |
| Machine/agent policy layer | **Shipped** | Pure library; **not wired into `submit_at`** |
| Payments, receipts, reputation, streaming | **Shipped** | Policy layer, no consensus change |
| **Post-quantum signatures** | **Accepted, not required** | Scheme `3` = ML-DSA-65 (FIPS 204) verifies inside the hybrid bundle: a spend can be signed `ECDSA + Schnorr + ML-DSA`, every component must verify, and the address commits to the whole key set so a bundle cannot be reduced to its classical half. Checkpoints carry a lattice sidecar verified as clause 7 — every bitmap signer holding a registered lattice key needs a valid entry, signers without one pass on BLS. Settlements and the VWCs they issue carry the same sidecar: arbitration votes sign it, `apply_settle` and certificate validation verify it. Validators register lattice keys in their bonds; the production loop signs both halves. Migration: moving funds is an ordinary spend to a `pq_address`; the `verify_input_pq` enforcement primitive is built and pinned, activation NOT set (Decision 24) |
| Worker SDK | **Shipped** | 44 tests including privilege-escalation suite |
| **Escrowed service contracts** | **In development** | The general contract and its transitions, a validated `ServiceContract::open` for non-compute deliverables, one non-compute deliverable shipping. Item 10 settlement is the non-custodial ledger commit (`ConditionalEscrow::finalize`, `Released` → `Finalized`, gated on `finality_activation_height` and advanced by the serve loop); there is no on-chain payout |
| **Agent credit** | **Wired to a caller** | The credit gate (`CreditBook`/`NoCreditGate`) is consulted by `POST /v1/payment/submit` via `admit_payment(&mut sh.credit)`; a reservation *encumbers* capacity (free to `reserved`, or a position's principal headroom) so one balance cannot back two admitted payments, and settlement is idempotent per reservation. Round-2 hardening: a mixed free+position reservation sweeps the whole free balance, per-position draws are tracked and released by name, a refused admission leaves the book untouched, and interest overflow is refused rather than wrapped. The position lifecycle (bond post/release, open, repay, default) is reachable over HTTP; the *debit commit* lands at receipt acceptance, and the matching debit is the Item 10 ledger settlement (`credit.settle`, behind the `settled_payments` conservation bucket), idempotent per reservation |
| **Delegation chains** | **Wired into the payment path** | A payment and a request carry a signed, root-first delegation chain; identity is proved from the chain rather than from the payer address, so a spend cannot claim more than its whole ancestry permits. The node records links, verifies owner signatures on every policy, propagates revocation to descendants, and refuses a chain it did not record. Still non-consensus (no `TXVALIDATOR` policy byte) |
| **Conditional payments** | **In development** | Contract-selected independent arbitrator (BLS) release path; state machine in `jnt-core::escrow`, node API wired, tests green. The transition lives on the escrow (`release_arbiter`/`release_mutual`), the escrow id and the release hash both bind network and condition, and **oracle conditions are refused at open** — with no oracle verifier implemented, an escrow that could never release cannot be opened at all. Every escrow **expires 1 008 blocks after open and refunds its payer**, and a release past that timeout is refused, so a lost key or a silent arbitrator cannot hold value. Settlement is the non-custodial Item 10 ledger commit, not an on-chain payout |
| **Wallet keys at rest** | **Hardened** | `wallets.json` is written mode 0600 through a temp-file rename and encrypted under `JNT_WALLET_PASSPHRASE` (Argon2id + ChaCha20-Poly1305); an encrypted file without the passphrase is refused by name, and plaintext writes require `--allow-plaintext-wallet` |
| **Compute-backed staking** | **Implemented** | Stake-weighted TopN committee (`derive_set`), `MIN_VALIDATOR_STAKE_SAT` = 5 000 JNT, `committee_records()` feeds the finality epoch set; testnet checkpoint verification is stake-bound |
| M1 fee split | **Consensus-active** | The only mechanism that is |
| M2 slash vault | Holds L2 slashes | Not otherwise triggered |
| M3 compute IR | Provides the reference | Envelopes carried, no interpreter |
| M4 HBM puzzle | **Registered (off on mainnet)** | `hbm_pow.rs` scratchpad PoW is registered as `puzzle_id = 2` (reviewed in `docs/security-review-hbm-2026-10-12.md`); `Chain::pow_satisfies` dispatches by puzzle id. `mini`/`testnet` keep mining `puzzle_id = 1` (hybrid); M4 is recognized but not activated as the mining puzzle |
| M5 finality | **Off on mainnet** | Both sides built; activation unset |
| REST API, `/metrics` | **Shipped** | Opt-in (`--api-listen`). **Loopback by default and unauthenticated**; a **non-loopback bind is refused** unless `JNT_API_TOKEN` (preferred — `--api-token` leaks via `ps`) supplies a bearer token (§19.2). **Every bind** enforces Host-header validation (DNS-rebinding); an exposed bind adds bearer auth on every request and a per-IP token bucket |
| API DoS guards | **Shipped** | Always on, on every binding including loopback, because they bound the shared-state `Mutex` rather than defend a remote attacker: a 10-second per-request deadline and a 64-request in-flight cap, so a flood of slow requests cannot wedge block production |
| Zeroizing wallet keys | **Shipped** | The Argon2id-derived symmetric key is held in a `Zeroizing` wrapper and dropped on release, so a decrypted key is not left in freed memory for the next allocation to expose |
| Release pipeline | **Shipped** | CI-gated, 3 targets, checksums, keyless cosign/Sigstore bundle wiring — **no signed release published yet**. Every action pinned to a commit SHA; job tokens least-privilege; Dependabot refreshes pins without opening PR branches |
| Net frame reads | **Shipped** | A frame body is read incrementally into a reserved buffer in 64 KiB chunks, so a peer cannot ask for one allocation larger than the whole frame cache |
| Per-request panic discipline | **Shipped** | No `unwrap`/`expect`/`unreachable!` is reachable from a request or a peer frame on the audited paths. With `panic = "abort"` in the release profile, one panic is a whole-node crash, so each is either made an error return or proved an unreachable invariant |
| **Independent security review** | **In progress** | A focused self-review of the HBM permutation gates M4 registration (`docs/security-review-hbm-2026-10-12.md`); a focused internal pass over request-path panics, exposure controls and CI supply-chain hygiene closed 15 items on Oct 15. **A third-party audit is still required before mainnet** — neither self-review substitutes for one |

### Why M4 is registered but not activated

`hbm_pow.rs` implements the memory-bound scratchpad permutation, its parameter
scaling, the `test()`/`production()` configs and the unit tests. It is now
**registered as `puzzle_id = 2`** in `PuzzleRegistry::genesis()`, and
`Chain::pow_satisfies` dispatches PoW verification: `puzzle_id = 1` uses the
§5 hybrid `PuzzleSolver`; `puzzle_id = 2` verifies the HBM scratchpad proof
against the network's `HbmConfig`. Registration was gated on the focused
security review in `docs/security-review-hbm-2026-10-12.md`.

M4 is **recognized but not the active mining puzzle**: `mini`/`testnet` mine
`puzzle_id = 1`, and mainnet mining of HBM is not switched on. Switching a
profile to `puzzle_id = 2` is a consensus choice that lives in the launch
decision, not in this code change. An unregistered `puzzle_id` is rejected
structurally (`Chain::submit` returns `UnknownPuzzle`) before any proof is
read.


---

## What changed, and when

Where a mechanism was built in stages, this is what was true before and what is
true now. Full record in [CHANGELOG.md](CHANGELOG.md).

| Area | Before | Now |
|---|---|---|
| **Stock supply cap** | A hard cap on total issuance | **Removed** (Decision 18). The ladder totals 39 157 124 JNT, then an approved tail pays 0.1 JNT/block forever, bounded by a 1%-per-period rate anchor |
| **L2 withdrawals** | Undefined; deposits were one-way | **Implemented** (Decision 19): `ExitQueue`, a proof-authorised sink spend, a permissionless crank, reorg-safe |
| **Exit accessibility** | Only a node's own miner could build a claim | **`GET /v1/exit/crankable`** hands claims to any third party |
| **Stake and bonds** | No bond ledger, no stake transaction | **Implemented** (Decision 20): bond/unbond/slash, TopN stake-weighted committee, ledger-derived finality keys |
| **What counts as fraud** | Unspecified â€” the slash vault stayed inert | **The canonical CPU reference decides** (Decision 21). No caller can supply it |
| **Arbitration transport** | No way to exchange verdicts; the quorum had to be assembled out of band | **Signed votes relay over P2P**; a quorum aggregates into the settlement |
| **Checkpoint signing** | Verification existed; **nothing ever signed**, so binding finality could not activate anywhere | **Production signing** via `jnt-node validator` and the serve loop |
| **Settle fee** | A flat fee a small escrow could not cover, failing closed | **Proportional** (Decision 23): 0.1% of task value, 1 000-sat minimum |
| **L1/L2 disagreement** | An exit claim with no L2 record was caught only by `debug_assert`, which compiles out of release builds | **Recorded as `UnbackedClaim`** and exposed, so a release build reports the divergence |
| **Unchallenged results** | A wrong unchallenged result produced a certificate that `validate()` accepted with no signal | **`asserts_correctness()` / `validate_verified`** make the weak basis unmissable |
| **HBM** | Registered but not the active mining puzzle | Registered as `puzzle_id = 2` with a security review; `mini`/`testnet`/mainnet still mine `puzzle_id = 1` (hybrid), so registration is an open item made safe, not a mainnet-readiness change |
| **Escrow identity** | Two escrows with the same parties and amount under different conditions shared one id, so the second open silently replaced the first | **The condition is part of the escrow id**, so different contracts are different escrows |
| **Credit reservation accounting** | A position-backed reservation left free balance spendable (double-admit), recorded one position of a multi-position spread, and interest overflow wrapped or capped silently | **Free is swept at admission, draws are tracked per position, refused admissions leave the book untouched, and interest overflow is refused**; and `POST /v1/payment/submit` **fails fast** on a position-backed admission it cannot service instead of locking that capacity forever; pinned by 3 new `redteam_round2` regressions |
| **Chain identity hashes** | `txid` and `block_hash` were 32-byte SHA-256: ~128-bit preimage and ~85-bit collision resistance against a quantum attacker | **Widened to 64-byte SHA-512** under new domain tags (`DOM_TX512`, `DOM_BLOCK512`), as a separate `Hash512` type. PoW target math, Merkle nodes and addresses keep their widths; vectors regenerated |
| **Quantum succession** | A CRQC breaks secp256k1 and BLS12-381, so spends, checkpoints and VWCs were all classically signed | **Three dual-signature paths**: spends accept an ML-DSA-65 component (scheme 3) inside the hybrid bundle, checkpoints carry a lattice sidecar verified as clause 7, and settlements and their VWCs carry one their votes sign. Validators register lattice keys in their bonds. Every rule is accepted-not-required: `pq_activation_height` is `0` on every profile until a rehearsal flips it |
| **Bond admission** | Anyone could hand the chain a published public key they do not own: squatting a validator out of their own key, or registering a rogue key chosen to cancel another key inside an aggregate | **Proof of possession is mandatory**: `TX_BOND` carries a 96-byte signature over network + bonder + key, checked by `check_bond_tx`, and a payload without one does not decode |
| **BLS validation** | `uncompress` decoded a point without `validate()`, and verification passed `sig_groupcheck=false`, so the subgroup check the module's own comments promised never ran | **`key_validate`/`sig_validate` at parse and `sig_groupcheck=true`** on single and aggregate verification; the point-at-infinity encoding is pinned by a regression test |
| **Committee definition** | Two definitions coexisted: signing and slashing took the first 21 bonds by order while finality took the top 21 by stake, so from a 22nd bond the two sides of one certificate named different key sets | **One definition**: `BondLedger::committee()` (top 21 by stake, canonical key order) feeds signing, slashing and finality alike |
| **Escrow timeouts** | No expiry and no refund: a lost key or a silent arbitrator held the value forever, and an oracle escrow could be opened although nothing could ever release it | **A 7-day expiry refunds the payer** (`opened_height` + `ESCROW_EXPIRY_BLOCKS`), a release past the timeout is refused, and oracle conditions are refused at open |
| **Wallet keys at rest** | `wallets.json` held plain-hex private keys at whatever permissions the umask allowed | **Mode 0600 via temp-file rename and encrypted** under `JNT_WALLET_PASSPHRASE` (Argon2id + ChaCha20-Poly1305); plaintext writes require `--allow-plaintext-wallet` |
| **Item 10 settlement** | A credit reservation could never settle and a released escrow never committed: the debit and the state change had no landing place | **Non-custodial ledger settlement**: `credit.settle` commits at receipt acceptance behind a `settled_payments` conservation bucket, and `ConditionalEscrow::finalize` commits `Released` → `Finalized` under finality, driven by the serve loop |
| **Zero-amount credit requests** | A bond, release, repay or open for `0` sat dereferenced a `get_mut()` on an address that had no credit entry — a panic, and with `panic = "abort"` a whole-node crash from one malformed request | **Refused by name** as `Malformed` before any mutation, and the entry is taken with `entry().or_insert(0)` so no code path can panic on a missing row. Pinned by 4 new regressions |
| **API exposure** | The REST API was unauthenticated on any bind — loopback was the only control — and no request had a deadline or an in-flight cap, so slow requests held the shared-state `Mutex` for as long as they liked | **A non-loopback bind is refused without a token**; Host-header validation (a DNS-rebound name cannot answer for it) runs on *every* binding including loopback, and an exposed bind adds bearer auth (constant-time compare, `JNT_API_TOKEN` preferred over `--api-token`) and a bounded per-IP token bucket. A 10-second deadline and a 64-request cap apply on *every* binding, loopback included |
| **Key material in memory** | The Argon2id-derived wallet key was an ordinary `[u8; 32]`, so it stayed readable in freed memory until something else overwrote it | **`Zeroizing`** wraps the derived key for its whole life and drops it on release, so the decrypt-and-reencrypt path does not leave a key behind |
| **Net frame allocation** | `read_frame` reserved the full declared length up front, so a peer that declared a near-maximum length got the node to allocate that in one shot before reading a byte of it | **Read incrementally**: no upfront reserve for the declared length — the buffer grows in 64 KiB chunks as bytes actually arrive, capping pinned memory at `chunk × max_peers`, and an over-cap length is refused before anything is read |
| **Handshake failure handling** | Four `unreachable!()`s sat after `Message::decode` in `peer.rs`, each reachable from a peer's bytes | **`NetError::Protocol`** returns instead, so a malformed handshake costs one connection rather than the process |
| **HBM scratchpad lane** | The lane was indexed with `state % lanes as u64` **after** the modulo on a `u64` — correct on 64-bit, but it cast the *modulus* to `usize` rather than reducing the state, so it was one edit away from a truncation | **Reduce before the width cast**: `state % lanes as u64` is computed on the same width at both sites, which is identical on 64-bit and correct on 32-bit |
| **Arbitration tally** | `settle_payload` re-checked committee, quorum and the BLS aggregate, but the signed message covered the decision only — a quorum aggregate verified on any chain | **Network and height are bound by the signature**: `SettlePayload` carries both, `signing_hash` covers them, and `apply` refuses a foreign network or a vote from the future. The tally still re-checks unanimity across every counted vote, and the quorum certificate carries the same chain context so it stays re-verifiable |
| **L2 replay failure handling** | `replay_to` *aborted the process* if `block_at` returned `None` for any height up to the tip — and with `panic = "abort"` that took the node down, including every open connection | **Stops the replay** at the first unreadable height and lets the node's `apply_block` catch-up resume from the L2 tip. The case is provably unreachable (`Chain::prune_side_branches` keeps every canonical block), so this removes the abort mode without changing behaviour |

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
different parameters â€” never a second implementation â€” so anything tested on
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
| PQ spend requirement | **off** | off | off |

`mainnet` deliberately ships with no committee and no activation, so it fails
closed rather than verifying against nothing. The PQ row is the
`pq_activation_height` of Decision 24: `0` means no input is refused for
lacking an ML-DSA-65 component, and the rule is age-gated when it is flipped —
only outputs created at or after the height must carry the component, so
history is never stranded.

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

`serve` also takes `--listen`, `--connect`, `--bootnodes`, `--peers`,
`--interval`, `--api-listen`, `--api-token`, `--api-allowed-host`
and `--no-mine`. `--bootnodes` dials peers at startup (SPEC §13.6: v0.2 has no
ADDR gossip, so bootnodes plus `peers.json` are the only peer sources).
`send --amount` is in satoshis while printed

The API defaults to loopback and needs no credentials. Binding anything
non-loopback is refused unless a token is supplied:

```sh
# Non-loopback: a bearer token is mandatory (§19.2). Pass it through the
# environment, not --api-token: flags are visible in `ps`.
export JNT_API_TOKEN="..."
jnt-node serve --network testnet --data-dir ./chain --api-listen 0.0.0.0:8080

# Loopback: unchanged, and unauthenticated.
jnt-node serve --network testnet --data-dir ./chain --api-listen 127.0.0.1:8080
```

Every request to an exposed bind must carry `Authorization: Bearer <token>`
(compared in constant time). Every bind — loopback included — requires a
`Host` header (DNS-rebinding defense): a loopback bind accepts loopback names
only, while a non-loopback bind additionally accepts any IP literal, the bound
address, and hostnames listed via `--api-allowed-host` (comma-separated) or
`JNT_API_ALLOWED_HOSTS`. A missing, unknown, or bracket-malformed `Host` is
403. Exposed binds also rate-limit per remote address, and every bind caps a
request at 10 seconds and 64 in flight.
figures are in JNT.

Credit, escrow and delegation state is node-local: it lives in memory, is
reachable over the API, and is lost on restart — it is never persisted and
never consensus.

---

## Testing

```sh
cargo test --workspace                                   # 1194 passed, 0 failed, 1 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python sim/verify_vectors.py --check                     # consensus vectors
```

The test count above is refreshed from `scripts/test_count.sh`, which is the
single source of truth — run it and paste the total rather than hand-editing.

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
cargo test -p jnt-core --test redteam_round2   # round-2 credit regressions
cargo test -p jnt-core --test pq_signature     # post-quantum bundle attacks
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release
build, the vector cross-checks, attack simulations, and all fourteen fuzz targets
on nightly with ASan. `.github/workflows/release.yml` re-runs the same gate on a
tagged tree before publishing artifacts with checksums and a keyless
cosign/Sigstore bundle.

**Every action is pinned to a commit SHA**, with the tag it came from in a
trailing comment, so a compromised or retagged action cannot silently change
what CI runs. Job tokens are least-privilege: `contents: read` by default, and
only the two jobs that genuinely write (the signing job's `id-token: write` for
the OIDC identity, the publish job's `contents: write`) take more. Dependabot
keeps the pins honest but opens **no pull requests** — every update PR is a
branch, and this repository keeps `main` as its only branch, so applying a bump
is an owner step (`cargo update -p <crate>` plus `cargo audit`). Security
*alerts* are unaffected: those come from the advisory database, not from PRs.

**Vectors.** `tests/vectors/` holds the consensus byte layouts, generated only
from the implementation. `sim/jounit_reference.py` is a second PoW implementation
written from `SPEC.md` rather than from the Rust, and it reproduces all 21 puzzle
digests â€” that agreement is the evidence the spec is unambiguous rather than
merely self-consistent.

**Fuzzing.** 14 cargo-fuzz targets over L1 wire, mempool, storage and
checkpoints; L2 codec, disputes, state and certificates; and the worker. They
assert capability invariants â€” decode/encode inversion, bounded allocation, value
conservation under adversarial transaction programs â€” not just panic-freedom.

**Red team.** `crates/jnt-core/tests/redteam*.rs` holds 21 adversarial integration
tests across four files (`redteam`, `redteam_credit`, `redteam_delegation`,
`redteam_round2`), each confirmed to fail against the code it now guards. The full record of
defects found and fixed is in [docs/status.md](docs/status.md).

---

## Not ready to launch

The code is done and CI is green. Mainnet is ready to run — withdrawals and
binding finality are active from genesis. What remains before pointing real
money at it:

| Item | Why it remains |
|---|---|
| **No independent security audit** | 1194 passing tests are not an external audit. This cannot be self-certified, by anyone, ever. |
| **No validator operators** | `mainnet` declares an empty `genesis_validators`. The bond ledger, committee derivation, and checkpoint signing are all built and tested, but no operator is bonding 5 000 JNT to run a validator. Binding finality verifies against whatever committee exists — empty means no checkpoint can finalize until validators appear, but depth-based finality (100 blocks) still secures the chain. |
| **Arbitrator key custody** | The arbitration quorum transport is built; who runs the committee is organisational. The per-escrow *release* path needs no committee: it is contract-selected and independent (Item 4). |
| **Operations** | No bootnode directory. `--bootnodes` dials configured peers at startup and `peers.json` persists learned addresses across restarts; no public bootnode list is published. No log shipping. No signed release published yet; the pipeline wires keyless cosign/Sigstore bundles, which need no published key. |

`jnt-node init --network mainnet` runs today. Withdrawals and binding finality
are both active — `exit_activation_height = 1` and `finality_activation_height = 100`.
This is not fail-closed: the chain mines, confirms, and settles from height 1.
Operators and an audit are the only remaining launch items.

[docs/mainnet-readiness.md](docs/mainnet-readiness.md) tracks each item with its
evidence.

---

## License and trademark

**Copyright Â© 2026 Swamy Gadila.**

**Code: `MIT OR Apache-2.0`** â€” the standard permissive Rust dual licence. Both
texts ship at the repo root (`LICENSE-MIT`, `LICENSE-APACHE`). You may use,
modify, run, audit and redistribute the software, including commercially.

**Name and marks: trademarked by the author.** The *Jounit* name, the `JNT`
ticker and the project's logos are trademarks of Swamy Gadila, not part of the
code licence. See [TRADEMARK.md](TRADEMARK.md).

The distinction is the same one Bitcoin uses: **the code is open so anyone can
run it, and the name is protected so nobody can pass themselves off as us.**
Nothing in an open-source licence can stop someone forking the code â€” that is
deliberate, and it is how the ecosystem works. What the trademark stops is
someone shipping a product under our name that is not this software.

Forks are explicitly permitted. The code belongs to everyone under the terms
above; the name belongs to the author.

If you want to use the name or marks commercially, or you want a licence other
than the one above, get in touch first.

---

Full protocol specification: [`SPEC.md`](SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).