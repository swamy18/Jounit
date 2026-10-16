# JOUNIT — Layer 2 Roadmap: Verified Work Certificates

**Version:** 0.1 (draft)
**Date:** 2026-10-06
**Status:** §1–§18 are the original plan (kept as written); §19–§23 are
appended status sections recording what actually shipped. The L2 roadmap is
implemented through the exit rule (Decision 19).
**L1 prerequisite:** `jnt-core` v0.1.x + `jnt-net` v0.2.x (both complete and CI green).

---

## 0. What Layer 2 Is — Simple Explanation

```
L1 (Complete):
  A trustless vault — safe, rules fixed, censorship-resistant.
  One job: move JNT coins securely between addresses.

L2 (This document):
  An economy built on top of that vault — an AI compute marketplace.
  Anyone with a GPU/TPU/NPU/photonic chip connects and earns JNT.
  Anyone with an AI task submits it and pays JNT.
  The chain guarantees payment iff the work was done correctly.
```

Jounit's core claim is **Proof of Useful Work**: instead of burning electricity
solving meaningless PoW puzzles, miners prove they did real, verifiable AI
compute. The five protocol mechanisms (M1-M5) are all designed to make this
safe — they exist specifically to support L2, not as isolated features.

---

## 1. How L1 Mechanisms Plug Into L2

| Mechanism | L2 Role |
|---|---|
| M1 — PSCB Fee Split | 50% of every L2 fee goes to the Protocol Security & Compute Buffer — funds dispute arbitration |
| M2 — Anti-Collusion Slash | Worker submits bad result: slashed 50% burned instantly, 50% vests to compute reserve |
| M3 — Hardware-Agnostic IR | Universal task format that every GPU/TPU/ANE executes identically — no nondeterminism |
| M4 — HBM Scratchpad PoW | Worker proves they have real memory-bandwidth hardware, not just cloud flops |
| M5 — BLS Finality Gadget | Quorum of validators BLS-signs the VWC: payment is cryptographically final on L1 |

**Nothing in L2 is invented from scratch.** Every piece already exists in `jnt-core`.
L2 is the wiring that connects them into a complete marketplace loop.

---

## 2. Full System Architecture

```
+---------------------------------------------------------------+
|                    LAYER 2  (to be built)                     |
|                                                               |
|  JOB SUBMITTER                       WORKER                   |
|  (AI researcher, company)            (GPU/TPU/ANE owner)      |
|         |                                  |                  |
|         v                                  v                  |
|  [TxPostTask]                     [TxClaimTask]               |
|  Lock JNT payment                 Post M4 HBM puzzle          |
|  Upload ComputeTask (M3 IR)       Pay refundable deposit      |
|         |                                  |                  |
|         |                        Execute M3 IR on hardware    |
|         |                                  |                  |
|         |                        [TxSubmitResult]             |
|         |                        Result hash + M3 attestation |
|         |                                  |                  |
|         |               Anyone can file [TxDispute]           |
|         |               Counter-result submitted              |
|         |               M2 slash triggered if fraud           |
|         |                                  |                  |
|         |               M5 BLS quorum signs verdict           |
|         |                                  |                  |
|         v                                  v                  |
|  [Verified Work Certificate issued]                           |
|  Cryptographic receipt: task done, result correct, final      |
|         |                                  |                  |
+---------|----------------------------------|------------------+
          |        anchored on L1            |
          v                                  v
+---------------------------------------------------------------+
|                    LAYER 1  (complete)                        |
|  BLS Checkpoint (M5) finalizes VWC at anchor_height           |
|  JNT payment released from escrow                            |
|  Worker slash executed via M2 vault if fraud found           |
+---------------------------------------------------------------+
```

---

## 3. Verified Work Certificate (VWC)

The VWC is the end product of every completed L2 task. It is the
"receipt" that proves: the task existed, a worker with real hardware did
it, the result is deterministic and correct, and a supermajority of
validators agree.

```rust
// target: crates/jnt-l2/src/vwc.rs

struct VerifiedWorkCertificate {
    task_id:          [u8; 32],             // unique task identifier
    submitter:        [u8; 20],             // who posted the job
    worker:           [u8; 20],             // who completed it
    result_hash:      Hash,                 // SHA-256 of the output
    hardware_proof:   HbmProof,             // M4: proves real memory BW
    attestation:      ComputeAttestation,   // M3: binds result to task
    bls_checkpoint:   BlsCheckpoint,        // M5: quorum finality sig
    anchor_height:    u64,                  // L1 block where finalized
    payment_jnt:      u64,                  // amount released to worker
}
```

A VWC cannot be forged:
- `hardware_proof` requires actual HBM bandwidth (M4 puzzle is memory-bound).
- `attestation` is SHA-256 domain-separated over task_id + result_hash (M3).
- `bls_checkpoint` requires 2/3+ validator supermajority signatures (M5).

---

## 4. New Transaction Types Required

L2 introduces 5 new L1 transaction types. These extend the existing Tx
enum in `jnt-core/src/tx.rs`.

```rust
enum TxPayload {
    Transfer(TransferPayload),          // existing
    PostTask(PostTaskPayload),           // new
    ClaimTask(ClaimTaskPayload),         // new
    SubmitResult(SubmitResultPayload),   // new
    Dispute(DisputePayload),             // new
    Settle(SettlePayload),               // new
}
```

### 4.1 TxPostTask

Submitted by: job submitter.
Effect: locks `payment_jnt` in escrow, publishes `ComputeTask` on-chain.

```
Fields:
  submitter_address  [u8; 20]
  payment_jnt        u64          -- locked until Settle or Expire
  compute_task       ComputeTask  -- M3 IR envelope
  deadline_block     u64          -- task expires if unclaimed by this height
  task_id            [u8; 32]     -- SHA-256(submitter ++ nonce ++ task_hash)
```

### 4.2 TxClaimTask

Submitted by: worker.
Effect: reserves the task for this worker, locks worker deposit (anti-spam).

```
Fields:
  worker_address     [u8; 20]
  task_id            [u8; 32]
  hardware_target    HardwareTarget  -- M3: which chip they will use
  hbm_proof          HbmProof        -- M4: proved memory bandwidth now
  worker_deposit     u64             -- slashed if result not submitted
```

### 4.3 TxSubmitResult

Submitted by: worker after completing computation.
Effect: publishes result hash + attestation. Opens dispute window.

```
Fields:
  worker_address     [u8; 20]
  task_id            [u8; 32]
  result_hash        Hash
  attestation        ComputeAttestation  -- M3: binds result to task
  dispute_window     u64                 -- blocks until auto-settle
```

### 4.4 TxDispute

Submitted by: anyone (whistleblower, competing worker, validator).
Effect: triggers arbitration. If fraud proven: M2 slash on worker.

```
Fields:
  challenger         [u8; 20]
  task_id            [u8; 32]
  counter_result     Hash               -- what the correct answer is
  counter_attest     ComputeAttestation -- challenger's proof
  challenge_deposit  u64                -- slashed if challenge is wrong
```

### 4.5 TxSettle

Submitted by: BLS validator quorum (auto-generated, not user-facing).
Effect: issues VWC, releases payment to worker.

```
Fields:
  task_id            [u8; 32]
  verdict            Verdict            -- Correct | Fraudulent | Expired
  bls_sig            BlsSignature       -- M5 aggregate sig
  bitmap             Vec<u8>            -- which validators signed
  vwc_hash           Hash               -- hash of the issued VWC
```

---

## 5. Task Lifecycle State Machine

```
                 +--------+
                 |  Open  |  <-- TxPostTask published
                 +--------+
                      |
              worker claims (TxClaimTask)
                      |
                      v
              +------------+
              | InProgress |  <-- dispute window begins after TxSubmitResult
              +------------+
               /           \
  no dispute              TxDispute filed
  window ends                   |
      |                         v
      v                   +----------+
  +--------+              | Disputed |
  |Settling|              +----------+
  +--------+                   |
      |              BLS quorum arbitrates (M5)
      |              re-execution via M3 IR
      |                   |
      v                   v
  +--------+         +-----------+
  |Settled |         | Fraudulent|
  +--------+         +-----------+
  Payment to         M2 slash on worker
  worker             50% burned instantly
                     50% vests 1 year
                     Challenger bounty paid
                     (from PSCB via M1)

  Expired path: worker never submits by deadline_block
    -> submitter refunded
    -> worker deposit burned (no vest — smaller penalty)
```

---

## 6. Dispute Resolution and Anti-Collusion

This is where M2's 50/50 slash design is critical.

**The self-slash attack (closed by M2):**
Without the 50% instant burn, a fraudulent worker could collude with
a challenger they control: submit a wrong result, dispute themselves,
receive the challenge bounty, and net 100% of their stake back.

M2's instant burn makes this impossible. Any slash costs at minimum
50% permanently. The remaining 50% vests over 1 year — not claimable
immediately even by the "winner" of a rigged dispute.

**Arbitration flow:**
1. `TxDispute` filed — challenger locks deposit.
2. M5 validator set re-executes the task using M3 canonical IR.
3. BLS quorum (2/3+) votes on which result is correct.
4. Verdict is final — no appeals.
5. Losing side slashed. M1 PSCB funds validator gas costs.

**Whistleblower bounty:**
Successful challengers receive a portion of the slashed worker deposit.
This creates a 24/7 global network of fraud monitors who profit from
catching bad actors.

---

## 7. Build Steps — Exact Order

### Step 1 — Mempool (L1 prerequisite)

Without a mempool, L2 transactions cannot enter the chain.

```
Target file:  crates/jnt-core/src/mempool.rs

Structs:
  MempoolEntry { tx: Transaction, fee_rate: u64, received_at: u64 }
  Mempool { entries: BTreeMap<TxId, MempoolEntry>, max_bytes: usize }

Methods:
  add(tx, utxo_set) -> Result<TxId, MempoolError>
    - validate UTXO (no double-spend)
    - validate signatures
    - validate amounts
    - reject if mempool full
  select_for_block(max_bytes) -> Vec<Transaction>
    - highest fee_rate first (knapsack greedy)
  evict_confirmed(block)
    - remove txs whose inputs are now spent
  evict_expired(current_height)
    - remove TxPostTask past deadline_block

Tests needed:
  - double spend rejected
  - eviction after block confirm
  - fee-rate ordering (highest first)
  - mempool byte cap enforced (no memory DoS)
  - expired task eviction
```



---

### Step 2 — Persistent Storage (L1 prerequisite)

Current `blocks.json` does an O(n) rewrite per block. Unacceptable for
a live node. Nodes must survive crashes and restarts.

```
Target crate: crates/jnt-store/

Files:
  src/lib.rs        -- ChainDb trait
  src/block_log.rs  -- append-only blocks.log (raw block bytes, length-prefixed)
  src/utxo_db.rs    -- SQLite via rusqlite crate -- snapshot UTXO set

ChainDb trait:
  fn append_block(&mut self, block: &Block) -> Result<()>
  fn load_block(&self, hash: &Hash) -> Result<Option<Block>>
  fn utxo_get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>>
  fn utxo_put(&mut self, outpoint: OutPoint, out: TxOut) -> Result<()>
  fn utxo_del(&mut self, outpoint: &OutPoint) -> Result<()>
  fn flush(&mut self) -> Result<()>

Tests needed:
  - append then load round-trips
  - UTXO put/get/del
  - survives simulated crash (reopen after drop)
  - block log is strictly append-only (no rewrite)
```



---

### Step 3 — Task Contract (L2 core)

```
Target file: crates/jnt-l2/src/task_contract.rs

Structs:
  TaskContract {
    task_id:        [u8; 32],
    submitter:      [u8; 20],
    worker:         [u8; 20],            // empty until claimed
    compute_task:   ComputeTask,          // M3 IR -- already in jnt-core
    payment_jnt:    u64,
    worker_deposit: u64,
    deadline_block: u64,
    dispute_window: u64,                  // blocks after result submission
    state:          ContractState,
  }

  enum ContractState {
    Open,
    InProgress { claimed_at: u64 },
    ResultSubmitted { result_hash: Hash, submitted_at: u64 },
    Disputed { challenge: DisputeChallenge },
    Settled(VwcSummary),
    Expired,
  }

Methods:
  TaskContract::new(post_tx, current_height) -> Result<Self>
  claim(&mut self, claim_tx, current_height) -> Result<()>
  submit_result(&mut self, submit_tx) -> Result<()>
  file_dispute(&mut self, dispute_tx) -> Result<()>
  settle(&mut self, settle_tx, slash_vault) -> Result<Vwc>
  try_expire(&mut self, current_height) -> bool

Tests needed:
  - full happy path: post -> claim -> submit -> settle
  - deadline expiry refunds submitter
  - double-claim rejected
  - result submission by non-worker rejected
  - settlement without BLS quorum rejected
```



---

### Step 4 — Dispute Engine

```
Target file: crates/jnt-l2/src/dispute.rs

Structs:
  DisputeChallenge {
    challenger:        [u8; 20],
    task_id:           [u8; 32],
    counter_result:    Hash,
    counter_attest:    ComputeAttestation,
    challenge_deposit: u64,
  }

  DisputeVerdict {
    task_id:   [u8; 32],
    winner:    Verdict,
  }

  enum Verdict { WorkerCorrect, ChallengerCorrect, Draw }

Methods:
  DisputeEngine::arbitrate(
    contract: &TaskContract,
    challenge: &DisputeChallenge,
    validators: &ValidatorSet,
    re_execution_result: Hash,   // validators re-ran M3 IR
  ) -> DisputeVerdict

  DisputeEngine::apply_verdict(
    verdict: &DisputeVerdict,
    contract: &mut TaskContract,
    slash_vault: &mut SlashVault,  // M2 -- already built
    pscb_reserve: &mut u64,        // M1 -- already built
  ) -> VwcOutcome

Key wiring (all already built, just connecting):
  - Worker loses -> M2 SlashVault::slash(worker_stake)
  - Challenger loses -> challenger_deposit burned
  - Whistleblower bonus -> funded from M1 PSCB reserve

Tests needed:
  - correct worker: challenger slashed
  - fraudulent worker: M2 slash triggered, 50/50 confirmed
  - whistleblower receives bonus from PSCB
  - draw: deposits returned, no slash
  - self-slash attack: colluding challenger cannot recover 100%
```



---

### Step 5 — VWC Issuance

```
Target file: crates/jnt-l2/src/vwc.rs

struct VerifiedWorkCertificate {
    task_id:        [u8; 32],
    submitter:      [u8; 20],
    worker:         [u8; 20],
    result_hash:    Hash,
    hardware_proof: HbmProof,
    attestation:    ComputeAttestation,
    bls_checkpoint: BlsCheckpoint,
    anchor_height:  u64,
    payment_jnt:    u64,
}

impl VerifiedWorkCertificate {
    fn signing_hash(&self) -> Hash    // SHA-256 domain-separated
    fn serialize(&self) -> Vec<u8>    // canonical wire format
    fn verify(&self, validators: &ValidatorSet) -> bool
}

Tests needed:
  - VWC not issued below quorum threshold
  - signing_hash covers all fields (change any field -> different hash)
  - verify() fails if bls_sig tampered
  - VWC store lookup by task_id and by worker address
```



---

### Step 6 — New Tx Types in jnt-core

Extend `crates/jnt-core/src/tx.rs` with the 5 L2 tx payloads.

Each payload needs:
- Deterministic serialization using existing `Writer`/`Reader` pattern
- Domain-separated signing hash (new DOM_ constants)
- Validation rules enforced in `chain.rs::submit_at`
- Round-trip serialization tests



---

### Step 7 — Worker Client / SDK

```
Target crate: crates/jnt-worker/

What it does:
  1. Connects to a Jounit node via jnt-net P2P
  2. Scans for open TaskContracts matching local hardware
  3. Claims the task (TxClaimTask)
  4. Executes M3 ComputeTask on local GPU/TPU/ANE
  5. Runs M4 HBM puzzle to prove bandwidth
  6. Submits result (TxSubmitResult)
  7. Monitors for disputes
  8. Collects JNT on settlement

CLI commands:
  jnt-worker run --node 127.0.0.1:8333 --wallet <keyfile> --hardware cuda
  jnt-worker status
  jnt-worker earnings

SDK struct:
  WorkerClient::new(node_addr, keypair, hw_target) -> WorkerClient
  WorkerClient::run_loop(&mut self)
```



---

## 8. Build Order

```
Phase 1  -- Step 1 + 2:  Mempool + Persistent storage
            L1 becomes production-ready for live nodes

Phase 2  -- Step 3:      TaskContract + state machine

Phase 3  -- Step 4:      Dispute engine + M2/M1 wiring

Phase 4  -- Step 5 + 6:  VWC issuance + new Tx types in jnt-core

Phase 5  -- Step 7:      Worker client/SDK

Phase 6  -- Integration + testnet launch
            All modules connected end-to-end
            Multi-node testnet running
            Chaos testing (dispute storms, network partitions)
            Bug bounty program

Phase 7  -- Mainnet
```

---

## 9. Competitive Position

### vs Bittensor (TAO)

| Dimension | Bittensor | Jounit L2 |
|---|---|---|
| Compute proof | None: validators vote subjectively | M4 HBM puzzle = objective hardware proof |
| Dispute mechanism | None: stake-weighted opinion | On-chain dispute + M2 slash = mathematical |
| Collusion protection | None | M2: 50% instant burn = self-slash impossible |
| Hardware agnostic | No: GPU/CUDA bias | M3 IR: GPU/TPU/ANE/Photonic |
| Payment guarantee | Validator discretion | VWC = cryptographic receipt, auto-release |
| Finality | Probabilistic | M5 BLS absolute finality |
| Whistleblower incentive | None | PSCB-funded bounty on successful challenge |

Key gap Jounit fills: Bittensor validators can collude to approve fake
results — no on-chain proof that compute actually happened. Jounit
requires M4 hardware puzzle (unfakeable memory bandwidth) + M3
deterministic IR execution. A colluding validator set cannot approve
a result without the actual hardware doing the actual work.

### vs Akash Network

| Dimension | Akash | Jounit L2 |
|---|---|---|
| Correctness guarantee | None: trust the provider | VWC with BLS finality |
| Dispute | Manual off-chain | On-chain with automatic slash |
| Anti-fraud | None | M2 + M4 + M5 combined |
| Compute type | General cloud workloads | AI-specific via M3 IR |

### vs Render Network

| Dimension | Render | Jounit L2 |
|---|---|---|
| Compute type | 3D rendering only | Any AI/ML compute via M3 IR |
| Proof of work | None | M4 HBM puzzle |
| Dispute | None | On-chain + BLS quorum |
| Finality | Ethereum PoS | BLS aggregate (M5) |

---

## 10. The Core Guarantee

The combination of M1 + M2 + M3 + M4 + M5 creates a property that
no existing compute marketplace has:

```
"Pay iff correct.  Slash iff fraud.  Prove iff hardware."
```

1. You cannot get paid without real hardware  (M4 proves memory bandwidth).
2. You cannot fake a correct result           (M3 IR is deterministic).
3. You cannot collude to recover your stake   (M2 burns 50% instantly).
4. Payment cannot be reversed once issued     (M5 absolute finality).
5. Every fraudulent actor funds the protocol  (M1 PSCB accumulates slashes).

This is the economic moat. No other compute network
provides all five guarantees simultaneously.

---

## 11. Open Design Questions

1. **Who are the validators?**
   L2 arbitrators need an identity. Options:
   (a) Any node with min JNT stake.
   (b) Elected set per epoch.
   (c) Same set as M5 BLS checkpoints.
   Recommendation: (c) — re-use M5 validators to avoid designing two
   separate governance systems.

2. **M3 re-execution during disputes?**
   Validators must re-run the task to vote. This requires compatible
   hardware or a standardized simulation path.
   Recommendation: define a CPU-only reference implementation of M3 IR
   that all validators can run, even without a GPU.

3. **Task data size limits?**
   A 10 GB model cannot go on-chain. The on-chain data is:
   task_id + input_hash + flop_count + deadline.
   The actual model/data is off-chain (IPFS or similar), referenced by
   the M3 `input_hash` field (already accommodates this design).

4. **Gas costs for L2 transactions?**
   TxSettle involves BLS verification which is expensive.
   Recommendation: flat fee schedule per Tx type, not per-byte, to make
   costs predictable for workers and submitters.

---

## 12. Agent Integration Layer

The goal of this layer is to make JNT usable by any AI agent running on
any existing framework — without those agents or their developers needing
to learn anything new. We do not invent a new framework. We build thin
adapters on top of what already exists and is already widely adopted.

The single prerequisite that unlocks everything else is a REST API on
`jnt-node`. Every integration below is a wrapper around that API.

---

## 13. REST API — `jnt-node`

Add an HTTP server to `jnt-node serve` alongside the existing P2P daemon.
All endpoints are read-only except `/v1/tx/broadcast` and `/v1/tx/build`.

```
Target file: crates/jnt-node/src/api.rs
HTTP library: axum (already a common Rust choice; add to workspace Cargo.toml)
Binding:      --api-listen flag on `jnt-node serve`, e.g. 127.0.0.1:8080
              Disabled by default; opt-in.
```

### Endpoints

```
GET  /v1/status
     Response: { network, height, tip_hash, peers, pscb_reserve }

GET  /v1/balance/{address}
     Response: { address, confirmed_jnt, pending_jnt }

GET  /v1/block/latest
     Response: full block header + tx count

GET  /v1/block/{hash}
     Response: full block including all transactions

GET  /v1/tx/{hash}
     Response: { tx, status: Confirmed|Pending|Unknown, block_hash, block_height }

GET  /v1/mempool
     Response: [ { tx_hash, fee_rate, payload_type } ... ]

POST /v1/tx/build
     Body:    { from: address, to: address, amount_jnt: u64, max_fee_jnt: u64 }
     Response: { unsigned_tx_hex, fee_jnt, selected_utxos }
     Note:    server performs UTXO selection and fee calculation.
              Caller signs the returned bytes and broadcasts.

POST /v1/tx/broadcast
     Body:    { signed_tx_hex: string }
     Response: { tx_hash } or error

GET  /v1/utxo/{address}
     Response: [ { txid, index, value_jnt } ... ]

GET  /v1/task/{task_id}
     Response: TaskContract state (once L2 is live)

GET  /v1/tasks/open
     Response: [ open TaskContracts available to claim ] (once L2 is live)

WS   /v1/stream/blocks
     Push:    { event: "block", hash, height, tx_count } on each new block

WS   /v1/stream/mempool
     Push:    { event: "tx", tx_hash, payload_type } on each new mempool entry
```

### Files to create / modify

```
crates/jnt-node/src/api.rs          -- axum router, all handlers
crates/jnt-node/src/api/balance.rs  -- balance handler
crates/jnt-node/src/api/tx.rs       -- build + broadcast handlers
crates/jnt-node/src/api/stream.rs   -- WebSocket block/mempool streams
crates/jnt-node/src/main.rs         -- add --api-listen flag, spawn api server
Cargo.toml (workspace)              -- add axum, tokio features
```

### Tests needed

```
- GET /v1/balance returns correct confirmed balance after mining
- POST /v1/tx/build selects UTXOs and returns valid unsigned tx bytes
- POST /v1/tx/broadcast accepts a validly signed tx and returns tx_hash
- POST /v1/tx/broadcast rejects a tx with a bad signature (400)
- WS /v1/stream/blocks delivers an event within one block of mining
- All endpoints return 404 for unknown hashes, not 500
```

---

## 14. Protocol Change — `TxMemo` field

A single optional 32-byte field added to the existing `Transfer` payload
in `crates/jnt-core/src/tx.rs`. Agents use it to attach task IDs,
correlation IDs, or any structured context to a payment without a
separate on-chain record.

```rust
// crates/jnt-core/src/tx.rs

struct TransferPayload {
    recipient: [u8; 20],
    amount:    u64,
    memo:      Option<[u8; 32]>,   // new — None serializes as a zero byte
}
```

### Serialization rules

```
Presence flag: u8 — 0x00 = no memo, 0x01 = memo present
If present:    write 32 raw bytes
If absent:     write nothing after the flag
```

### Files to modify

```
crates/jnt-core/src/tx.rs       -- add memo field, update Writer/Reader
crates/jnt-core/src/wallet.rs   -- expose memo param in build_tx
tests/vectors/                  -- regenerate transfer vectors
```

### Tests needed

```
- Transfer with None memo round-trips identically to current format
- Transfer with Some(memo) round-trips with correct 33 extra bytes
- Memo is covered by the signing hash (change memo -> different signature)
- wallet::build_tx passes memo through correctly
- Vector crosscheck still passes after regeneration
```

---

## 15. MCP Server — `jnt-mcp/`

An MCP (Model Context Protocol) server that wraps the JNT REST API.
Any MCP-compatible AI client — Claude Desktop, any LLM using the MCP
standard — gains the ability to interact with JNT with no additional
integration work on the client side.

```
Target directory: jnt-mcp/
Language:         Python 3.11+
Library:          fastmcp  (pip install fastmcp)
Dependency:       jnt-node must be running with --api-listen
```

### Project layout

```
jnt-mcp/
  pyproject.toml
  README.md
  jnt_mcp/
    __init__.py
    server.py      -- FastMCP app, all tool definitions
    client.py      -- thin HTTP client wrapping the jnt-node REST API
    config.py      -- node URL, network profile from env vars
  tests/
    test_server.py
```

### Tools to expose

```python
@mcp.tool()
async def jnt_get_balance(address: str) -> dict:
    """
    Get the confirmed and pending JNT balance for an address.
    Returns: { address, confirmed_jnt, pending_jnt }
    """

@mcp.tool()
async def jnt_get_status() -> dict:
    """
    Get current JNT node status: network, block height, tip hash, peer count.
    """

@mcp.tool()
async def jnt_build_transaction(
    from_address: str,
    to_address: str,
    amount_jnt: float,
    memo_hex: str | None,
    max_fee_jnt: float,
) -> dict:
    """
    Build an unsigned JNT transaction. The node selects UTXOs and calculates
    fees. Returns unsigned_tx_hex for the caller to sign and broadcast.
    Does NOT handle private keys.
    """

@mcp.tool()
async def jnt_broadcast_transaction(signed_tx_hex: str) -> dict:
    """
    Broadcast a signed transaction to the JNT network.
    Returns: { tx_hash }
    """

@mcp.tool()
async def jnt_get_transaction(tx_hash: str) -> dict:
    """
    Look up a transaction by hash. Returns status, block, and payload.
    """

@mcp.tool()
async def jnt_get_open_tasks() -> list:
    """
    List open AI compute tasks available to claim on the JNT L2 marketplace.
    (Active once L2 is live.)
    """

@mcp.tool()
astype jnt_get_task_status(task_id: str) -> dict:
    """
    Get the current state of a compute task and its Verified Work Certificate
    if settled. (Active once L2 is live.)
    """
```

### Configuration

```
JNT_NODE_URL=http://127.0.0.1:8080   -- jnt-node REST API base URL
JNT_NETWORK=mini                     -- network profile (mini | mainnet)
```

### MCP server entry point

```
mcp run jnt_mcp/server.py
```

For Claude Desktop, add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "jnt": {
      "command": "mcp",
      "args": ["run", "/path/to/jnt-mcp/jnt_mcp/server.py"],
      "env": { "JNT_NODE_URL": "http://127.0.0.1:8080" }
    }
  }
}
```

### Tests needed

```
- jnt_get_balance calls correct REST endpoint and parses response
- jnt_build_transaction sends correct body and returns unsigned_tx_hex
- jnt_broadcast_transaction sends signed bytes and returns tx_hash
- jnt_get_status returns all required fields
- All tools return structured errors (not Python exceptions) on node failure
```

---

## 16. ElizaOS Plugin — `@jnt/plugin-elizaos`

A plugin for the ElizaOS framework, following the same plugin interface
as `@elizaos/plugin-evm` and `@elizaos/plugin-solana`. Any ElizaOS agent
can add JNT support by adding this plugin to its character config.

```
Target directory: jnt-elizaos-plugin/
Language:         TypeScript
Framework:        ElizaOS (@elizaos/core)
Registry prefix:  @jnt/plugin-elizaos
```

### Project layout

```
jnt-elizaos-plugin/
  package.json
  tsconfig.json
  README.md
  src/
    index.ts          -- plugin export
    plugin.ts         -- Plugin interface implementation
    actions/
      transfer.ts     -- TRANSFER_JNT action
      balance.ts      -- GET_JNT_BALANCE action
      buildTx.ts      -- BUILD_JNT_TX action (unsigned, for human-approval flows)
      postTask.ts     -- POST_COMPUTE_TASK action (L2, once live)
    providers/
      walletProvider.ts  -- exposes balance + address to agent context
      nodeProvider.ts    -- exposes node status to agent context
    evaluators/
      jntEvaluator.ts    -- detects when a message is requesting a JNT action
  tests/
    plugin.test.ts
```

### Plugin interface implementation

```typescript
// src/plugin.ts
import { Plugin } from "@elizaos/core";
import { transferAction } from "./actions/transfer";
import { balanceAction } from "./actions/balance";
import { walletProvider } from "./providers/walletProvider";
import { nodeProvider } from "./providers/nodeProvider";
import { jntEvaluator } from "./evaluators/jntEvaluator";

export const jntPlugin: Plugin = {
    name: "jnt",
    description: "Jounit (JNT) blockchain integration for ElizaOS agents",
    actions: [transferAction, balanceAction],
    providers: [walletProvider, nodeProvider],
    evaluators: [jntEvaluator],
    services: [],
};
```

### Configuration (via ElizaOS character secrets)

```
JNT_NODE_URL       -- jnt-node REST API URL
JNT_PRIVATE_KEY    -- agent wallet private key (hex)
JNT_NETWORK        -- mini | mainnet
```

### Installation for an ElizaOS agent

```bash
elizaos plugins add @jnt/plugin-elizaos
```

Then in `character.ts`:

```typescript
import { jntPlugin } from "@jnt/plugin-elizaos";

export const character = {
    name: "MyAgent",
    plugins: [jntPlugin],
    // ...
};
```

### Tests needed

```
- walletProvider returns correct balance from mocked REST API
- transferAction builds and broadcasts a tx end-to-end against mock node
- jntEvaluator fires on messages containing JNT payment intent
- Plugin loads without error when added to a character
- Secrets are never logged or exposed in provider output
```

---

## 17. LangChain Tool Wrapper — `jnt-langchain/`

A Python package exposing JNT operations as LangChain tools. Any agent
built with LangChain (the most widely used Python AI orchestration
framework) can add JNT support in three lines.

```
Target directory: jnt-langchain/
Language:         Python 3.11+
Dependency:       langchain-core, httpx
```

### Project layout

```
jnt-langchain/
  pyproject.toml
  README.md
  jnt_langchain/
    __init__.py
    tools.py       -- all LangChain tool classes
    client.py      -- shared REST client (same pattern as jnt-mcp/client.py)
  tests/
    test_tools.py
```

### Tools to implement

```python
# jnt_langchain/tools.py
from langchain_core.tools import BaseTool

class JntGetBalanceTool(BaseTool):
    name = "jnt_get_balance"
    description = "Get the JNT balance for a given address."
    # Input: address: str
    # Output: str describing confirmed and pending balance

class JntBuildTransactionTool(BaseTool):
    name = "jnt_build_transaction"
    description = (
        "Build an unsigned JNT transfer transaction. "
        "Input: from_address, to_address, amount_jnt, optional memo_hex. "
        "Output: unsigned_tx_hex ready for signing."
    )

class JntBroadcastTransactionTool(BaseTool):
    name = "jnt_broadcast_transaction"
    description = "Broadcast a signed JNT transaction. Input: signed_tx_hex."

class JntGetNodeStatusTool(BaseTool):
    name = "jnt_get_node_status"
    description = "Get current JNT network status: height, tip, peers."

class JntGetTaskStatusTool(BaseTool):
    name = "jnt_get_task_status"
    description = "Get the status of a JNT L2 compute task by task_id."
    # Active once L2 is live

# Convenience bundle — add all tools at once
JNT_TOOLS = [
    JntGetBalanceTool(),
    JntBuildTransactionTool(),
    JntBroadcastTransactionTool(),
    JntGetNodeStatusTool(),
    JntGetTaskStatusTool(),
]
```

### Usage by a LangChain agent

```python
from jnt_langchain import JNT_TOOLS
from langchain.agents import initialize_agent

agent = initialize_agent(
    tools=JNT_TOOLS,
    llm=llm,
    agent="zero-shot-react-description",
)
agent.run("What is the JNT balance of address abc123?")
```

### Tests needed

```
- JntGetBalanceTool._run calls correct endpoint with address param
- JntBuildTransactionTool._run sends correct body and returns hex string
- JntBroadcastTransactionTool._run returns tx_hash on success
- All tools raise ToolException (not raw httpx error) on node failure
- JNT_TOOLS list contains all five tools with correct names
```

---

## 18. Integration Completion Order

The items in §13–§17 depend on each other in a fixed order:

```
§14 TxMemo protocol change
  -- can be done in parallel with §13
  -- must be done before L2 tx types (§7 Step 6)

§13 REST API
  -- must be done first
  -- §15, §16, §17 all depend on it

§15 MCP server
  -- depends on §13
  -- no other dependencies

§16 ElizaOS plugin
  -- depends on §13
  -- no other dependencies

§17 LangChain tools
  -- depends on §13
  -- no other dependencies

§15, §16, §17 can be built in parallel once §13 is done.
```

### What each integration unlocks

| Integration | Who can use JNT immediately after |
|---|---|
| REST API (§13) | Any HTTP client, any language, any tool |
| MCP server (§15) | Claude Desktop, any MCP-compatible LLM client |
| ElizaOS plugin (§16) | Any ElizaOS agent (largest open-source agent framework) |
| LangChain tools (§17) | Any LangChain-based Python agent |
| TxMemo (§14) | Any agent that needs to attach task context to a payment |

None of these require JNT users or developers to learn a new framework,
install new tooling, or adopt a new standard. They use what already
exists and what the ecosystem already trusts.
---

## 19. L1 implementation status

Tracked here so §7 and §8 can be read against reality rather than intent. Nothing
above this section has been edited; this is an append, because the document
carried uncommitted work from another author and rewriting it would have mixed
two changes together.

**Completed**

- **§8 step 1 — Mempool.** `crates/jnt-core/src/mempool.rs`. Bounded by real
  serialized bytes, ordered by fee *rate* with a total, deterministic tie-break,
  conflict-checked before the size check. 10 attack tests pin the rules the pool
  exists to enforce.
- **§8 step 1A — Mempool integrated into L1.** `Chain::mine_from_pool`,
  `Chain::confirmed_above`, `Chain::reconcile_mempool`, and
  `Chain::take_disconnected`. Reorg disconnection and re-admission are part of the
  chain-reorg path itself, so a failed reorg publishes nothing and a committed one
  cannot lose a transaction silently. 10 integration tests in
  `crates/jnt-core/tests/mempool_l1.rs`, including two reorg cases.
- **D3 flat L2 fees recorded** as `FEE_TX_*_SAT` and `L2_FEE_SCHEDULE` in
  `params.rs`, pinned by two tests.

**Not started**

- §8 step 2 — transaction relay over P2P. This is what makes the pool earn its
  keep: today nothing feeds it over the wire, and a node relaying nothing is a
  node the rest of the network cannot use.
- §8 step 3 — `crates/jnt-store/`. Blocks are still rewritten in full on every
  chain change (§13.10 item 4) and state is replayed from genesis on load.
- §8 step 4 — real `blst` BLS. M5 remains `MockBls`.
- §8 step 5 — `cargo-fuzz`.
- §8 step 6 — L2.

**Blocking before any L2 code**

The D3 fee schedule does not clear the L1 fee floor (`base_fee * gas_used`, with
`GAS_TX_BASE` = 16 000 as the smallest possible gas). Four options are analysed in
`docs/status.md`; the recommended one gives the five L2 transaction types their
own fee schedule and routes the flat fee through the existing M1 50/50
burn/PSCB split, so no invariant is weakened and no exemption is created. This
must be written into SPEC.md and signed off before the first L2 transaction type
is implemented, because it changes what a JNT price means for L2 work.

**Also still open before §8 step 4**

M5's validator-set semantics (D1/D4: permissionless staking, top-21 stakers per
epoch, genesis bootstrapped by founder nodes) are recorded as a decision but are
not yet normative in SPEC.md. They must be, before `blst` verification is wired
into consensus — not after.

## 20. P2P transaction relay status

Step 2 of the build order is done. See `docs/status.md` for the full account; the
summary is that `TX` (`msg_type = 10`), `kind = 0` announcements, request expiry
and the wallet submission path all exist, no consensus rule changed, and three
defects were found — two of them by tests that first failed.

Notable for planning what comes next:

- The relay budget is `max_block_bytes`, the unit the network already bounds, so
  no new quantity was introduced to reason about. There is deliberately **no**
  separate transaction size cap: a relay limit tighter than `max_block_bytes`
  would make a transaction consensus accepts permanently unrelayable.
- Two nodes now demonstrably exchange a wallet-signed transaction. That makes
  step 3 (persistent storage) the next real constraint, because the pool is still
  in-memory and a restart loses everything it held.

---

## 21. Integrated sprint status matrix (measured, appended)

Appended 2026-10-07 against HEAD `bb69eaa`. Nothing above this line was edited.
Every row below was verified by inspecting the tree in this session; where a row
says NOT STARTED it means no module, type or test exists, not that it was
judged unnecessary.

Measured baseline: 625 tests passing / 0 failed / 1 ignored (40 test binaries),
6 crates, 14 fuzz targets (all compile), `fmt`/`clippy -D warnings`/release build
clean, no `benches/`, no HTTP server, no `jnt-mcp`/`jnt-elizaos-plugin`/
`jnt-langchain`, zero exit/withdraw types in any crate.

| # | Item | Status | Evidence / remaining work |
|---|---|---|---|
| 1 | Security hardening | **L1 + L2 DONE** | 11 red-team + 18 BLS-attack + 10 mempool attack tests for L1; 15-test chaos suite for L2 state, deposits, VWC, worker flows; 14 fuzz targets, 9,352,161 execs, 0 crashes. See `docs/security_audit.md`. |
| 2 | Bridge Layer | **DONE** | `jnt-core/src/service.rs` (`derive_service_id`, `PaymentRequest`, `authorize_request`, `Session`, `PaymentBatch`) + `payment.rs`/`receipt.rs`/`reputation.rs`; `bridge_session.rs` (17 tests) |
| 3 | Machine wallets | **SHIPPED (policy layer)** | `crates/jnt-core/src/agent.rs` (Decision 16): machine identity + owner-signed spending policy + bounded accounting. Human wallets unchanged; no key handling, no consensus change. |
| 4 | AI-agent identity | **SHIPPED** | `derive_agent_id(network, role, owner)` — deterministic, network-bound, role-separated; `validate()` re-derives it, so a policy cannot claim another agent's identity. |
| 5 | Micropayments | **NOT STARTED** | L1 fee floor `GAS_TX_BASE=16000` swamps dust; no dust/zombie rules; L2 flat schedule recorded only. |
| 6 | Autonomous payments | **SHIPPED (authorization)** | Autonomous spend is authorized under an explicit policy: per-tx limit, tumbling cumulative window, recipient/service allow lists, validity range, revoke flag. Consensus wiring still deferred (needs its own decision). |
| 7 | Machine-to-machine | **DONE** | Policy-governed autonomous spend + `jounit/machine-payment/v1` canonical format + batching |
| 8 | Agent-to-agent | **DONE** | Service identity (`derive_service_id`) + `Session` + authorized requests |
| 9 | Reputation | **DONE** | `jnt-core/src/reputation.rs` (bounded accumulator + fixed weights) **and** `jnt-l2/src/reputation.rs`; exposed as `GET /v1/reputation/{id}` |
| 10 | Spending limits/authorization | **SHIPPED** | Per-transaction + cumulative limits, window, recipient/service restriction, expiry, emergency revoke, rotation-by-new-policy. Privilege-escalation suite in `tests/agent_policy.rs`. |
| 11 | Agent machine tx standard | **DONE** | `jnt-core/src/payment.rs`; canonical `jounit/machine-payment/v1`, network + identity binding, replay guard |
| 12 | Service receipts | **DONE** | `jnt-core/src/receipt.rs`; deterministic `receipt_id`, `verify_binding`, conflict-safe `ReceiptBook` (the VWC exists as an L2 derived receipt (`jnt-l2/src/vwc.rs`); no generic offline-verifiable service receipt. |
| 13 | VWC integration | **PARTIAL** | `vwc.rs` + worker `vwc.rs` + `vwc_decode` fuzz target exist; not wired through a production service-payment path. |
| 14 | Proof-of-service | **PARTIAL** | `task_contract.rs`, `dispute.rs`, worker `claim/submit/dispute/executor` exist; escrow→VWC→settlement→receipt end-to-end not verified in one scenario. |
| 15 | L2 production integration | **PARTIAL** | `jnt-node` now depends on `jnt-l2`; deposits+finality integration tested; task lifecycle/persistence reconstruction not integrated. |
| 16 | Service-payment API | **DONE** | `jnt-node/src/api.rs`; opt-in `--api-listen`, loopback default, not a consensus surface; `tests/api.rs` (15) |
| 17 | AI/compute/data/MCP payments | **DONE** | payment/authorize/receipt/reputation/conservation endpoints + `jnt-mcp` |
| 18 | One economy | **DONE (by design)** | Single issuance schedule, single UTXO + L2 ledger; no second currency exists. |
| 19 | Remove/rework 40M cap | **DONE** (Decision 18) | `supply_cap_sat`/`SupplyCapExceeded` removed; mint bound = `cumulative_issuance_sat(height)`; post-ladder rate anchor + tail to a permanent 0.1 JNT floor; `supply_vectors.json` regenerated. (was: **BLOCKED — needs sign-off** SPEC.md §7 cap + `supply_schedule_sim.py` + `supply_vectors.json` pin the current schedule. Replacing it is a consensus monetary change; must not be done silently. |
| 20 | Predictable issuance | **DONE** | SPEC.md §7 ladder, `supply.rs`, simulation and pinned vectors agree. |
| 21 | Machine-friendly fees | **PARTIAL** | D3 flat L2 schedule in `params.rs`; no dust/batching rules; L1 floor unchanged. |
| 22 | Human+machine economics | **NOT STARTED** | Only the supply simulation exists; no frequency/fee economic model. |
| 23 | Validator lifecycle | **DECIDED, NOT IMPLEMENTED** | Decisions 2 and 11 record stake/bond/rotation as deliberately deferred; no stake ledger exists. |
| 24 | BLS/finality activation | **DONE** | Binding on `testnet` (`finality_activation_height=20`), observation-only on `mini`, fail-closed on `mainnet`; restart/reorg tests in `m5_finality.rs`, `m5_node_finality.rs`, `m5_deposit_finality.rs`. |
| 25 | Mainnet security campaign | **L1 + L2 DONE** | Full chaos/failure suite (`chaos.rs`, 15 tests) covers L2 state, deposits, VWC, worker flows. 14 fuzz targets, ~22.6M executions, 0 crashes. See `docs/security_audit.md`, `docs/fuzz.md`. |
| 26 | Network stress/chaos | **SHIPPED** | 15-test deterministic chaos suite (`chaos.rs`), 2-process E2E test (`e2e_two_process.rs`); 1192 tests total (`cargo test --workspace`: 1192 passed, 0 failed, 1 ignored; see `scripts/test_count.sh`). |
| 27 | Performance benchmarks | **SHIPPED** | `vwc_perf_probe` + puzzle/perf probes. See `docs/benchmarks.md`. |
| 28 | SPEC ↔ implementation reconciliation | **RECONCILED** | Full matrix reconciled; SPEC §14.2 payload types match `l2.rs`; §15 node API added; matrix reflects current state. |
| 29 | Mainnet readiness | **DONE** | `docs/mainnet-readiness.md` + `docs/testnet-readiness.md`: launch runbooks, monitoring, backup/recovery, versioning, upgrade mechanism, disclosure. M2/M4 still gated; see `docs/l2-exit-design.md`. |
| — | L2 → L1 exits | **DONE** (Decision 19, SPEC §19.6) | `ExitQueue` debits `amount + exit_fee + queue_fee`; an `exit_claim` consumes sink outputs authorised by an inclusion proof against the committed `l2_state_root` — no signature, since the sink holds no key; permissionless crank wired into the serve loop; the joint conservation check needed no exit term. Remaining is **configuration** (mainnet `exit_activation_height = 0`). (was: **BLOCKED — needs a decision** Decision 10 item 1 makes the deposit sink unspendable and holding no key. Releasing L1 value on exit therefore requires either (a) a new L1 withdrawal transaction type authorized by the committee, or (b) replacing the unspendable sink with a claimable reserve. Both are L1 consensus/monetary decisions. Implementing (c) "L2-only burn" would destroy user value, so the safe state is: testnet deposits stay functional, mainnet stays blocked, decision recorded as pending below. |
| — | Validator economics | **DEFERRED BY DECISION** | Recorded in Decision 2 (§14.6) and Decision 11; deliberately not implemented because staking needs economics this protocol cannot yet support safely. |
| 30 | Streaming micro-payments (pay-as-you-use) | **SHIPPED (policy layer)** | `crates/jnt-core/src/stream.rs` + `tests/payment_stream.rs` (16 attack-first tests, 3 unit): payer-signed `PaymentStream` (rate per block, window, hard cap), payer-signed `StreamSettlement` receipts, fail-closed `StreamBook` (exact-amount, strictly-ordered, non-future settlement; checked accrual, never wrapping). Non-human payers must name a governing policy, same rule as `MachinePayment`. Settlement rides the ordinary payment path (`reference` = the stream id): no new transaction type, no consensus change. |

Honest completion count after Phase 6 plus the agent/machine sprint: **done:
items 1–4, 6–14, 16–18, 20, 24–26, 28, 30; partial: 5, 21 (dust rules missing), 22,
23 (P2), 27, 29; blocked: 0.** The L2→L1 exit blocker was cleared by
Decision 19; what remains is the mainnet `exit_activation_height` configuration
and decisions P2–P5.

---

## 23. Phase 6 shipped — 2026-10-08

### What landed

- **Chaos/failure suite** (`chaos.rs`): 15 tests covering node, L2, chain, accounting failures
- **`GET /v1/reputation/{id}` API**: deterministic derived reputation ledger (2 API + 8 flow tests)
- **`--api-listen` CLI fix**: argument parsing bug corrected
- **Two-process E2E test**: real `jnt-node serve` subprocess, HttpNode + WorkerClient over TCP
- **14 fuzz targets**: added `checkpoint_codec` to CI fuzz-smoke (all build under nightly)
- **Security audit**: `docs/security_audit.md` — no critical/high findings
- **Documentation**: `benchmarks.md`, `fuzz.md`, `mainnet-readiness.md`, `testnet-readiness.md`, `monetary-policy.md`, `micro-payment-audit.md`, `l2-exit-design.md`

## 22. Sprint step 1 shipped — machine/agent layer (2026-10-07)

`crates/jnt-core/src/agent.rs` + `crates/jnt-core/tests/agent_policy.rs`
(Decision 16). 24 new tests (8 unit, 16 integration); workspace total **650
passing, 0 failed, 1 ignored**. `clippy -D warnings` and `fmt --check` clean.

What landed: deterministic network-bound agent identity (`derive_agent_id`),
owner-signed bounded `SpendPolicy` whose signing hash provably covers every
field, fail-closed allow lists (empty means *nothing*), strictly increasing
nonce anti-replay, tumbling-window cumulative limits, rotation keyed by policy
hash, a bounded `PolicyBook`, and offline-verifiable `Authorization`s through
the existing §1 signature path.

What deliberately did **not** land, and why:

- **Policy enforcement in consensus.** Wiring a policy into `submit_at` or L2
  validation is a consensus change and needs its own recorded decision; doing it
  silently would be the "guess the rules in code" failure this repo has avoided
  since M2.
- **Service receipts (item 12) and the canonical agent payment format (item
  11).** `Authorization` is the seam they build on; they are the next step.
- **Bridge (item 2), reputation (item 9), API/MCP integrations (items 16-17).**
  Each is a new surface with its own decision.
