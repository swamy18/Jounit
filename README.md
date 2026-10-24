# Jounit (JNT)

AI-native cryptocurrency. Mining that does useful work, and a payment layer built for AI agents. Pre-launch.

**Author and copyright:** Community-owned. The code is open source — no single
person holds it, like Bitcoin. The *Jounit* name, `JNT` ticker and logos are
community marks — see [License and trademark](#license-and-trademark).

**Built by:** Swamy Gadila. The project is open for anyone to use,
and redistribute — no single person owns it.

---

## Contents

- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [Supply](#supply)
- [What the chain is for](#what-the-chain-is-for)
- [Use cases](#use-cases)
- [Machines, agents and robots](#machines-agents-and-robots)
- [How fraud is detected](#how-fraud-is-detected)
- [How withdrawals work](#how-withdrawals-work)
- [Validators and finality](#validators-and-finality)
- [Repository layout](#repository-layout)
- [Network profiles](#network-profiles)
- [Commands](#commands)
- [Testing](#testing)
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

To stand up a local multi-node network (deterministic genesis, separate data
dirs, node 1 as seed, the rest dialing it via `--bootnodes`):

```sh
scripts/start-network --nodes 3          # init, serve, wait until all share a tip
scripts/stop-network                     # graceful stop via pid files
scripts/reset-network                    # stop and delete the data root
```

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

The L2 transaction types are the whole vocabulary — six for the task economy and
the exit mechanism, seven for the authority and credit layers (thirteen total):

| Type | Value | Purpose |
|---|---|---|
| `PostTask` | `0x10` | Submitter: open a task, lock the escrow, publish the compute spec |
| `ClaimTask` | `0x11` | Worker: take the task, post a deposit |
| `SubmitResult` | `0x12` | Worker: submit the result hash with a signed attestation |
| `Dispute` | `0x13` | Anyone: challenge the result with a counter-result and a deposit |
| `Settle` | `0x14` | Committee: apply the decision — pay, refund, slash |
| `ExitQueue` | `0x15` | Owner: start withdrawing back to Layer 1 |
| `Policy` | `0x16` | Owner: publish a spending grant (agent authority) |
| `PolicyRevoke` | `0x17` | Owner: kill a grant — every descendant dies with it |
| `AgentSpend` | `0x18` | Spender: spend under a published grant |
| `CreditOpen` | `0x19` | Lender: open a loan; the principal moves to the borrower |
| `CreditCollateral` | `0x1A` | Borrower: add collateral to a position |
| `CreditRepay` | `0x1B` | Borrower: repay (interest first, then principal) |
| `CreditDefault` | `0x1C` | Anyone: settle a position that was not repaid by its deadline |

A task moves through six states: `Open → InProgress → ResultSubmitted →
Disputed? → Settled`, with `Expired` as the timeout branch.

---

## Use cases

These are the things a UTXO chain with a task economy on top of it can do that
the two layers alone cannot.

**Settlement for work nobody re-runs.** Someone pays for a result; someone else
checks it without re-doing it. The chain holds the escrow and decides the
outcome, so the two sides need no prior relationship and no arbitrator they both
trust.

**Machines spending under a written policy.** An owner authorizes once, offline,
and every later spend is checked against it with the owner offline — bounded per
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
guard. A settled payment also carries its proof: `POST /v1/payment/{id}/settle`
binds the Layer 1 transaction that paid it (a tx that does not pay the recipient
is refused), `GET /v1/payment/{id}` reports the link as `settlement`, and the
link persists across restarts.

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
receipts and reputation, and over the agent authority and credit layer:
`inspect.policy`, `inspect.agent_spend` and `inspect.credit` read the terms an
agent is about to sign and the hash to sign.

> **What changed.** The spending-policy layer used to be node-local: a policy
> constrained a payment *on the node that issued it*, and the chain never saw
> it. It is now **consensus state** (SPEC.md §21, Decision 25). A grant is
> published on chain, the owner's signature binds it to a named spender and a
> named agent, the caps and allow-lists and the nonce are enforced against
> state the chain keeps, and revoking a grant kills every descendant of it. The
> same is true of credit (SPEC.md §22, Decision 26): a loan is a chain fact
> with the lender's signature over its terms, the principal really moves, and
> the collateral answers for the debt.
>
> What is still node-local is the *service layer* around them: the payment
> book, the receipt book, the credit gate used for admission and the
> authorisation helper the API issues offline. Those are operational
> bookkeeping, not sources of spendable balance.

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
      ┤─ challenger files R' with a deposit
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
third party, so a non-miner can build a block with them. An escrow settlement
rides this same path — `POST /v1/escrow/{id}/settle` queues the release's exit
and the crank pays it, with no separate escrow coin.

**Reorg-safe.** A release is an ordinary undoable Layer 1 operation: rollback
restores the sink outputs, clears the identity, and L2 replay regenerates the
watch.

**Conservation is unchanged.** The joint check needed no exit term at all — the
L1 payment and the L2 debit cancel while the sink term falls by the same amount.

> **Active on mainnet.** `mainnet.exit_activation_height` is `1`, which means
> exits work from genesis — same as Bitcoin spends. Testnet and mini activate
> at height 1.

---

## Validators and finality

**Bonded stake** (`bond.rs`, Decision 20). Three transaction types — `TX_BOND`,
`TX_UNBOND`, `TX_SLASH` — feed a bond ledger with a bond-order index. Any
positive bond amount is accepted — there is no minimum stake threshold. Unbonding
locks for `UNBONDING_PERIOD_BLOCKS` = 1 008 (seven days). Provable
equivocation burns the full bond.

Bonds only admit keys whose holder proves they hold them: `TX_BOND` carries a
96-byte proof-of-possession signature bound to network, bonder and key, and a
payload without one does not decode.

**Finality.** Binding finality activates at `finality_activation_height = 100`
on mainnet from genesis. Depth-based finality (100 blocks) secures the chain
before that — the same Bitcoin-style rule. The 21-key bootstrap committee signs
until the first bond, then the stake-weighted TopN set replaces it.

---

## Repository layout

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | **Normative.** Where a disagreement exists, this wins. |
| [`AGENTS.md`](AGENTS.md) | Lint, type-check and test commands for this session. |
| `crates/jnt-core/` | Protocol implementation. All consensus logic. |
| `crates/jnt-net/` | P2P wire protocol, sync and relay. |
| `crates/jnt-store/` | Append-only checksummed block log, crash recovery. |
| `crates/jnt-l2/` | Layer 2: contracts, disputes, certificates, exits. |
| `crates/jnt-node/` | CLI and node daemon. |
| `crates/jnt-worker/` | Worker-side SDK. Client only, no consensus. |
| `crates/jnt-mcp/` | Keyless MCP surface over agent identity and payments. |
| `fuzz/` | 17 cargo-fuzz targets over the attacker-controlled boundaries. |
| `sim/` | Independent Python reference and attack simulations. |
| `tests/vectors/` | Consensus vectors. Generated from source, never hand-edited. |
| `docs/` | Design records, verification status and readiness reports. |
| `paper/` | The Jounit protocol paper (LaTeX + PDF). |

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
| Genesis validators | 21 public bootstrap (quorum 15) | 4 deterministic | 4 deterministic |
| L2 settlement validators | **none** (fail closed) | 4 deterministic | 4 deterministic |
| Binding finality | on at height 100 | on at height 20 | off |
| Exits | on at height 1 | on at height 1 | on at height 1 |
| PQ spend requirement | **off** | off | off |

`mainnet` ships with 21 public deterministic bootstrap keys (quorum 15) so
finality can bind before any stake exists; the first bond replaces them with
the stake-weighted TopN committee. Its separate L2 settlement set stays empty,
so settlements fail closed. Exits are active from height 1. The PQ row is the
`pq_activation_height` of Decision 24: `0` means no input is refused for
lacking an ML-DSA-65 component, and the rule is age-gated when it is flipped —
only outputs created at or after the height must carry the component, so
history is never stranded.

Network magic bytes (§13.3): `mainnet` = `6A4E5402`, `mini` = `6A4E5403`,
`testnet` = `6A4E5404`. These move with each protocol version that changes the
wire format or state root, so pre-bump peers are refused at framing before they
can join.

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
  policy      Publish, revoke or list spending grants (agent authority)
  agent-spend Spend under a published grant
  credit      Open, repay, default or list credit positions
  l2          Layer-2 summary, and the deposit address
  validator   Add or list checkpoint-signing keys
  export      Write the canonical chain to JSON
  serve       Run a P2P node: relay, sync, opt-in REST API, exit crank, signing
```

### Agent authority and credit, from the terminal

A grant is the owner's signed authority for a named spender. It is published
on chain, so every node enforces it:

```sh
# The deposit address: an ordinary L1 payment to it credits your L2 balance.
jnt-node l2 --deposit-address
jnt-node send --to <deposit-address> --amount 5

# Publish a grant: this key may spend up to 0.01 JNT per payment and
# 0.05 JNT per window, to this recipient only.
jnt-node policy --spender <spender> --per-tx 1000000 --cumulative 5000000 \
                --recipients <recipient>

# The agent spends under it.
jnt-node agent-spend --policy <policy-hash> --to <recipient> --amount 0.002 --nonce 1

# The owner kills it; every descendant of the grant dies with it.
jnt-node policy --revoke --agent-id <agent-id>
jnt-node policy --list
```

Credit works the same way — the **lender** signs, the principal really moves,
and the collateral answers for the debt:

```sh
jnt-node credit --to <borrower> --amount 1 --collateral 100000000
jnt-node credit --repay --position <position-hash> --amount 1
jnt-node credit --list
```

Every one of these commands checks the transaction against the state the chain
will replay and refuses with the chain's own reason, rather than mining a
block the replay would skip.

Common options: `--network <mainnet|testnet|mini>` (default `mini`) and
`--data-dir <path>` (default `./chain`).

`serve` also takes `--listen`, `--connect`, `--bootnodes`, `--peers`,
`--interval`, `--api-listen`, `--api-token`, `--api-allowed-host` and
`--no-mine`. `--bootnodes` dials peers at startup (SPEC §13.6: v0.2 has no
ADDR gossip, so bootnodes plus `peers.json` are the only peer sources).
`--credit-issuer` lists the BLS keys trusted to sign credit attestations for
`POST /v1/credit/mint` (comma-separated 48-byte hex keys; with none listed,
every mint is refused). `send --amount` takes JNT (`--amount-sat` takes satoshis); printed balances
are in JNT.

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
request at 10 seconds, 64 requests in flight, 128 open connections, and 30
seconds to finish sending request headers (the slowloris bound).

Credit, escrow and delegation state is node-local and never consensus, but it
is no longer lost on restart: the books beside the chain (receipts, replay
tracker, payments and their settlement links, reservations, policy accounting,
credit and the attestations already minted, delegations, issued policies,
revocations, escrows and their exit bindings) persist to `state.bin` — an atomic,
digest-checked file with a fail-closed load (a corrupt file refuses to start)
— flushed when their bytes change, plus once at shutdown.

---

## Testing

```sh
cargo test --workspace                                   # 1307 passed, 0 failed, 1 ignored
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
cargo test -p jnt-node --test state_persist    # books survive restart
cargo test -p jnt-node --test api escrow       # escrow open/settle over HTTP
cargo test -p jnt-core --test redteam          # adversarial regressions
cargo test -p jnt-core --test redteam_round2   # round-2 credit regressions
cargo test -p jnt-core --test pq_signature     # post-quantum bundle attacks
```

CI (`.github/workflows/ci.yml`) runs format, clippy, the full suite, a release
build, the vector cross-checks, attack simulations, and all 17 fuzz targets
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
digests — that agreement is the evidence the spec is unambiguous rather than
merely self-consistent.

**Fuzzing.** 17 cargo-fuzz targets over L1 wire, mempool, storage and
checkpoints; L2 codec, disputes, state and certificates; and the worker. They
assert capability invariants — decode/encode inversion, bounded allocation, value
conservation under adversarial transaction programs — not just panic-freedom.

**Red team.** `crates/jnt-core/tests/redteam*.rs` holds 21 adversarial integration
tests across four files (`redteam`, `redteam_credit`, `redteam_delegation`,
`redteam_round2`), each confirmed to fail against the code it now guards. The full
record of defects found and fixed is in [docs/status.md](docs/status.md).

---

## License and trademark

**Copyright © 2026.** The code is open — no single person holds it, like Bitcoin.

**Code: `MIT OR Apache-2.0`** — the standard permissive Rust dual licence. Both
texts ship at the repo root (`LICENSE-MIT`, `LICENSE-APACHE`). You may use,
modify, run and redistribute the software, including commercially.

**Name and marks: community-owned.** The *Jounit* name, the `JNT`
ticker and the project's logos are community marks, not part of the code
licence. See [TRADEMARK.md](TRADEMARK.md).

The distinction is the same one Bitcoin uses: **the code is open so anyone can
run it, and the name is a community mark.** Nothing in an open-source licence
can stop someone from using the code — that is deliberate, and it is how the
ecosystem works. The code belongs to everyone under the terms above; the name
belongs to the community.

If you want to use the name or marks commercially, open an issue — no single
person holds it.

---

## Security

[`SECURITY.md`](SECURITY.md) is the disclosure policy: what counts as a
vulnerability, the severity model, the 90-day window, and the intake channel
(GitHub Security Advisory, or `security@jounit.org`). Do not open a public
issue for a security defect.

---

Full protocol specification: [`SPEC.md`](SPEC.md).
Design decisions: [`docs/decisions.md`](docs/decisions.md).
