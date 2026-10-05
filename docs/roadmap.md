# JOUNIT — Layer 2 Roadmap: Verified Work Certificates

**Version:** 0.1 (draft)
**Date:** 2026-10-06
**Status:** Specced, not yet implemented.
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

Estimated effort: 2-3 weeks.

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

Estimated effort: 1-2 weeks.

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

Estimated effort: 3-4 weeks.

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

Estimated effort: 2-3 weeks.

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

Estimated effort: 1-2 weeks.

---

### Step 6 — New Tx Types in jnt-core

Extend `crates/jnt-core/src/tx.rs` with the 5 L2 tx payloads.

Each payload needs:
- Deterministic serialization using existing `Writer`/`Reader` pattern
- Domain-separated signing hash (new DOM_ constants)
- Validation rules enforced in `chain.rs::submit_at`
- Round-trip serialization tests

Estimated effort: 2 weeks.

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

Estimated effort: 3-4 weeks.

---

## 8. Full Timeline

```
Month 1  -- Step 1 + 2:  Mempool + Persistent storage
            L1 becomes production-ready for live nodes

Month 2  -- Step 3:      TaskContract + state machine

Month 3  -- Step 4:      Dispute engine + M2/M1 wiring

Month 4  -- Step 5 + 6:  VWC issuance + new Tx types in jnt-core

Month 5  -- Step 7:      Worker client/SDK

Month 6  -- Integration + testnet launch
            All modules connected end-to-end
            Multi-node testnet running
            Chaos testing (dispute storms, network partitions)
            Bug bounty program

Month 7+ -- Mainnet
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

This is the economic moat. No other decentralized compute network
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
