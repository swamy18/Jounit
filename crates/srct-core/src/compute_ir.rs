//! M3 Protocol Mechanism: Universal Hardware-Agnostic Compute Layer.
//!
//! Solar Cyber Unit is NOT a "GPU coin". It is a hardware-neutral compute marketplace
//! where any silicon capable of running a well-defined computation can
//! participate:
//!
//!   NVIDIA / AMD GPUs   — CUDA / ROCm backends
//!   Apple NPUs          — Core ML / ANE backends
//!   Google TPUs         — XLA backends
//!   Huawei / Ascend     — CANN backends
//!   Intel / AMD CPUs    — AVX-512 / OpenMP fallback
//!   FPGAs               — bitstream-specific
//!   Photonic processors — future optical backends
//!
//! The "compute task" is expressed in a hardware-neutral Intermediate
//! Representation (IR) that any backend can execute. The result is a
//! cryptographic commitment (SHA-256 of outputs) that the chain verifies
//! without knowing *which* hardware produced it.
//!
//! Attestation model
//! -----------------
//! 1. A task issuer posts a `ComputeTask` on-chain (or off-chain with an
//!    on-chain hash anchor).
//! 2. Any registered compute worker picks it up and runs it on their hardware.
//! 3. The worker submits a `ComputeAttestation` containing:
//!    - `task_id`        — hash of the `ComputeTask`
//!    - `result_hash`    — SHA-256 of the raw output tensor
//!    - `backend`        — which hardware class performed the work
//!    - `worker_address` — 20-byte address for reward routing
//!    - `signature`      — secp256k1 ECDSA over the attestation body
//! 4. The chain or an off-chain aggregator validates that N-of-M workers
//!    agree on the `result_hash` (quorum). Disagreeing workers trigger M2
//!    slashing.
//!
//! SPEC.md §M3.

use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Hash};
use crate::ser::{Reader, Writer};

/// Domain tag for compute task hashing (prevents cross-domain preimage attacks).
pub const DOM_COMPUTE_TASK: u8 = 0xC0;
/// Domain tag for attestation signing.
pub const DOM_COMPUTE_ATTEST: u8 = 0xC1;

// ---------------------------------------------------------------------------
// ComputeBackend: identifies the hardware class
// ---------------------------------------------------------------------------

/// Hardware class that executed a compute task.
///
/// The `u8` wire encoding matches the `backend_hint` field of `ComputeTask`
/// and the `backend` field of `ComputeAttestation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ComputeBackend {
    /// Any x86-64 / ARM64 CPU (OpenMP / AVX-512 implementation).
    Cpu = 0x00,
    /// NVIDIA / AMD GPU (CUDA or ROCm).
    Gpu = 0x01,
    /// Apple Neural Processing Unit (Core ML / ANE).
    Npu = 0x02,
    /// Google Tensor Processing Unit (XLA).
    Tpu = 0x03,
    /// Huawei Ascend (CANN).
    Ascend = 0x04,
    /// Intel / Xilinx FPGA (custom bitstream).
    Fpga = 0x05,
    /// Photonic / optical processor (reserved for future backends).
    Photonic = 0x06,
    /// Unknown / future backend. Wire-compatible with new hardware.
    Unknown(u8),
}

impl ComputeBackend {
    pub fn to_wire(&self) -> u8 {
        match self {
            ComputeBackend::Cpu => 0x00,
            ComputeBackend::Gpu => 0x01,
            ComputeBackend::Npu => 0x02,
            ComputeBackend::Tpu => 0x03,
            ComputeBackend::Ascend => 0x04,
            ComputeBackend::Fpga => 0x05,
            ComputeBackend::Photonic => 0x06,
            ComputeBackend::Unknown(b) => *b,
        }
    }

    pub fn from_wire(b: u8) -> Self {
        match b {
            0x00 => ComputeBackend::Cpu,
            0x01 => ComputeBackend::Gpu,
            0x02 => ComputeBackend::Npu,
            0x03 => ComputeBackend::Tpu,
            0x04 => ComputeBackend::Ascend,
            0x05 => ComputeBackend::Fpga,
            0x06 => ComputeBackend::Photonic,
            other => ComputeBackend::Unknown(other),
        }
    }

    /// Human-readable name for display / logging.
    pub fn name(&self) -> &'static str {
        match self {
            ComputeBackend::Cpu => "CPU",
            ComputeBackend::Gpu => "GPU",
            ComputeBackend::Npu => "NPU",
            ComputeBackend::Tpu => "TPU",
            ComputeBackend::Ascend => "Ascend",
            ComputeBackend::Fpga => "FPGA",
            ComputeBackend::Photonic => "Photonic",
            ComputeBackend::Unknown(_) => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// ComputeTask: the unit of work
// ---------------------------------------------------------------------------

/// A hardware-agnostic compute task posted to the network.
///
/// The IR bytecode is intentionally opaque at this layer — it is the job of
/// the runtime (GPU driver, NPU SDK, etc.) to interpret it. The chain only
/// stores the hash of the IR, not the IR itself, to keep block sizes manageable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeTask {
    /// Issuer-assigned unique identifier.
    pub task_id: Hash,
    /// SHA-256 of the IR bytecode. The actual IR is distributed off-chain.
    pub ir_hash: Hash,
    /// SHA-256 of the input data blob. Distributed off-chain.
    pub input_hash: Hash,
    /// Minimum memory required to run this task, in bytes.
    /// Helps route to hardware with sufficient memory bandwidth (M4 alignment).
    pub required_memory_bytes: u64,
    /// Suggested backend class. Workers of other classes MAY still attempt the
    /// task; `backend_hint` is informational only.
    pub backend_hint: ComputeBackend,
    /// Reward for correct completion, in satoshis.
    pub reward_sat: u64,
    /// Block height after which the task expires and the reward is reclaimed.
    pub expiry_height: u64,
    /// Chain height at which the task was submitted.
    pub submit_height: u64,
}

impl ComputeTask {
    /// Exact serialized length. `serialize` writes a fixed set of fields with no
    /// length-prefixed member, so the encoding is constant-size and a decoder
    /// needs no bound arithmetic.
    pub const SERIALIZED_LEN: usize = 32 + 32 + 32 + 8 + 1 + 8 + 8 + 8;

    /// Canonical serialization of the task for hashing.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(&self.task_id);
        w.write_bytes(&self.ir_hash);
        w.write_bytes(&self.input_hash);
        w.write_u64(self.required_memory_bytes);
        w.write_u8(self.backend_hint.to_wire());
        w.write_u64(self.reward_sat);
        w.write_u64(self.expiry_height);
        w.write_u64(self.submit_height);
        w.finish()
    }

    /// Domain-separated SHA-256 hash of the task (used as task_id by issuers).
    pub fn task_hash(&self) -> Hash {
        sha256_dom(&[DOM_COMPUTE_TASK], &[&self.serialize()])
    }

    /// True when the task is still valid at `current_height`.
    pub fn is_active(&self, current_height: u64) -> bool {
        current_height <= self.expiry_height
    }

    /// Parse the exact bytes [`ComputeTask::serialize`] produces.
    ///
    /// Field order must match `serialize` byte-for-byte. Kept beside it so a
    /// reordering is a compile-adjacent change rather than a silent wire break:
    /// an embedded task is part of an L2 transaction's signed body.
    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let task_id = r.fixed()?;
        let ir_hash = r.fixed()?;
        let input_hash = r.fixed()?;
        let required_memory_bytes = r.u64le()?;
        let backend_hint = ComputeBackend::from_wire(r.u8()?);
        let reward_sat = r.u64le()?;
        let expiry_height = r.u64le()?;
        let submit_height = r.u64le()?;
        Ok(ComputeTask {
            task_id,
            ir_hash,
            input_hash,
            required_memory_bytes,
            backend_hint,
            reward_sat,
            expiry_height,
            submit_height,
        })
    }
}

// ---------------------------------------------------------------------------
// Canonical CPU reference (SPEC.md §16.2, Decision 21 — P3).
// ---------------------------------------------------------------------------

/// The canonical CPU-reference output for a task: a fixed, dependency-free
/// 32-round Keccak-style permutation over the task's own commitment hashes.
///
/// This is the single definition every party runs — worker, challenger,
/// arbitrator: same commitments, same bytes, no clock, no RNG, no floating
/// point, no platform types. It satisfies SPEC §16.2's MUSTs (determinism,
/// canonical little-endian lanes, wrapping `u64` arithmetic, fixed reduction
/// order, total termination) by construction.
///
/// Two deliberate scope notes, so neither is discovered later:
///
/// - The function mixes the *commitments* (hashes), not the IR bytecode: the
///   chain stores hashes precisely so blocks stay small (see `ComputeTask`),
///   and SPEC §16.5 forbids an on-chain interpreter. What consensus and the
///   engine compare is therefore *reproducibility against the commitments* —
///   a worker whose result differs from this output cannot have run the
///   reference over the committed task.
/// - There is deliberately **no height input**. Decision 21 requires
///   "deterministic CPU re-execution with *identical* inputs": a height is
///   never identical across the worker's run, the challenger's re-run and a
///   later arbitration, so mixing one would make honest agreement impossible.
///   Replay protection stays where it belongs — task expiry and attestation
///   heights — not inside the reference.
pub fn reference_output(
    task_id: &Hash,
    ir_hash: &Hash,
    input_hash: &Hash,
    required_memory_bytes: u64,
) -> [u8; 64] {
    let mut state = [0u64; 25];
    let mut fill = |i: usize, bytes: &[u8]| {
        for (j, chunk) in bytes.chunks(8).enumerate() {
            let mut v = [0u8; 8];
            v[..chunk.len()].copy_from_slice(chunk);
            state[i * 4 + j % 4] ^= u64::from_le_bytes(v);
        }
    };
    fill(0, task_id);
    fill(1, ir_hash);
    fill(2, input_hash);
    state[12] ^= required_memory_bytes;

    for _round in 0..32 {
        // θ: parity of each column.
        let mut par = [0u64; 4];
        for (i, s) in state.iter().enumerate() {
            par[i % 4] ^= *s;
        }
        for s in state.iter_mut() {
            *s ^= par[0].rotate_left(1) ^ par[1].rotate_left(7);
        }
        // ρ+π (fixed shuffle) and χ (nonlinear step).
        let mut next = [0u64; 25];
        for i in 0..25 {
            next[(i * 7 + 3) % 25] = state[i].rotate_left((i % 8 + 1) as u32);
        }
        for i in 0..25 {
            let a = next[i];
            let b = next[(i + 1) % 25];
            let c = next[(i + 4) % 25];
            state[i] = a ^ (!b & c);
        }
        state[0] ^= 0x1F_u64.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    let mut out = [0u8; 64];
    for (lane, chunk) in state.iter().take(8).zip(out.chunks_mut(8)) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// The M3 result commitment for the reference output: `SHA-256` of
/// [`reference_output`]. A result hash "reproduces" a task iff it equals
/// this — the comparison the dispute engine runs.
pub fn reference_result_hash(
    task_id: &Hash,
    ir_hash: &Hash,
    input_hash: &Hash,
    required_memory_bytes: u64,
) -> Hash {
    crate::hash::sha256(&[&reference_output(
        task_id,
        ir_hash,
        input_hash,
        required_memory_bytes,
    )])
}

// ---------------------------------------------------------------------------
// ComputeAttestation: a worker's claim to have completed a task
// ---------------------------------------------------------------------------

/// A worker's attestation that they have completed `task_id` and the output
/// is `result_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeAttestation {
    /// Must match a posted `ComputeTask::task_id`.
    pub task_id: Hash,
    /// SHA-256 of the raw output tensor / result blob.
    pub result_hash: Hash,
    /// Hardware class that performed the computation.
    pub backend: ComputeBackend,
    /// Worker's 20-byte address (reward destination).
    pub worker_address: [u8; 20],
    /// Block height at which this attestation was produced.
    pub attest_height: u64,
    /// secp256k1 ECDSA signature over `signing_payload()` (DER-encoded).
    pub signature: Vec<u8>,
}

impl ComputeAttestation {
    /// Largest attestation signature this decoder will accept, in bytes.
    ///
    /// Generous on purpose: an ML-DSA-65 signature is 3309 bytes, so sizing this
    /// to today's ~72-byte DER ECDSA signature would make a post-quantum
    /// attestation undecodable. The cap exists so a declared length cannot force
    /// a large reservation, exactly like `Bundle::MAX_COMPONENT_BYTES`.
    pub const MAX_SIGNATURE_BYTES: usize = 4096;

    /// The bytes that the worker signs. Commits to every consensus-relevant
    /// field; excluding `signature` itself (prevents circular dependency).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(&self.task_id);
        w.write_bytes(&self.result_hash);
        w.write_u8(self.backend.to_wire());
        w.write_raw(&self.worker_address);
        w.write_u64(self.attest_height);
        w.finish()
    }

    /// Domain-separated hash of the signing payload.
    pub fn attest_hash(&self) -> Hash {
        sha256_dom(&[DOM_COMPUTE_ATTEST], &[&self.signing_payload()])
    }

    /// Serialize the full attestation (signing payload + signature length + sig).
    pub fn serialize(&self) -> Vec<u8> {
        let mut payload = self.signing_payload();
        let sig_len = self.signature.len() as u32;
        payload.extend_from_slice(&sig_len.to_le_bytes());
        payload.extend_from_slice(&self.signature);
        payload
    }

    /// Parse the bytes [`ComputeAttestation::serialize`] produces.
    ///
    /// The signature length is attacker-controlled, so it is checked against the
    /// cap and against the remaining bytes *before* any allocation is driven by
    /// it. An empty signature is allowed here and rejected by the layer that
    /// requires a signed attestation, so the codec is an exact inverse.
    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let task_id = r.fixed()?;
        let result_hash = r.fixed()?;
        let backend = ComputeBackend::from_wire(r.u8()?);
        let worker_address: [u8; 20] = r.fixed()?;
        let attest_height = r.u64le()?;
        let sig_len = r.u32le()? as usize;
        if sig_len > Self::MAX_SIGNATURE_BYTES {
            return Err(Error::Malformed("attestation signature over cap"));
        }
        if sig_len > r.remaining() {
            return Err(Error::Malformed("attestation signature exceeds buffer"));
        }
        let signature = r.fixed_slice(sig_len)?.to_vec();
        Ok(ComputeAttestation {
            task_id,
            result_hash,
            backend,
            worker_address,
            attest_height,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Quorum validation
// ---------------------------------------------------------------------------

/// Verify that a set of attestations for the same task agrees on `result_hash`.
///
/// Returns `Ok(result_hash)` if `threshold` or more attestations share the
/// same result, or `Err(attests_that_disagree)` if a quorum cannot be formed.
///
/// Disagreeing workers are candidates for M2 slashing.
pub fn verify_quorum(
    attestations: &[ComputeAttestation],
    threshold: usize,
) -> std::result::Result<Hash, Vec<usize>> {
    if attestations.is_empty() || threshold == 0 {
        return Err(Vec::new());
    }

    // Count votes for each result_hash
    let mut counts: std::collections::HashMap<Hash, Vec<usize>> = std::collections::HashMap::new();
    for (i, attest) in attestations.iter().enumerate() {
        counts.entry(attest.result_hash).or_default().push(i);
    }

    // Find the majority result (if any reaches the threshold)
    if let Some((winning_hash, _)) = counts.iter().find(|(_, voters)| voters.len() >= threshold) {
        return Ok(*winning_hash);
    }

    // No quorum: return indices of all attestations that disagree with plurality
    let plurality_hash = counts
        .iter()
        .max_by_key(|(_, voters)| voters.len())
        .map(|(h, _)| *h)
        .unwrap_or_default();

    let dissenters: Vec<usize> = attestations
        .iter()
        .enumerate()
        .filter(|(_, a)| a.result_hash != plurality_hash)
        .map(|(i, _)| i)
        .collect();

    Err(dissenters)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(n: u8) -> Hash {
        [n; 32]
    }

    fn make_attest(task_id: Hash, result: Hash, worker: u8) -> ComputeAttestation {
        ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Gpu,
            worker_address: [worker; 20],
            attest_height: 100,
            signature: vec![],
        }
    }

    // ------------------------------------------------------------------
    // ComputeBackend
    // ------------------------------------------------------------------

    #[test]
    fn backend_round_trips_wire_encoding() {
        let backends = [
            ComputeBackend::Cpu,
            ComputeBackend::Gpu,
            ComputeBackend::Npu,
            ComputeBackend::Tpu,
            ComputeBackend::Ascend,
            ComputeBackend::Fpga,
            ComputeBackend::Photonic,
            ComputeBackend::Unknown(0xFF),
        ];
        for b in backends {
            assert_eq!(
                ComputeBackend::from_wire(b.to_wire()),
                b,
                "wire round-trip failed for {:?}",
                b
            );
        }
    }

    #[test]
    fn unknown_backend_preserved_not_rejected() {
        let b = ComputeBackend::from_wire(0x42);
        assert_eq!(b, ComputeBackend::Unknown(0x42));
        assert_eq!(b.to_wire(), 0x42);
    }

    // ------------------------------------------------------------------
    // ComputeTask
    // ------------------------------------------------------------------

    #[test]
    fn task_hash_is_deterministic() {
        let task = ComputeTask {
            task_id: dummy_hash(1),
            ir_hash: dummy_hash(2),
            input_hash: dummy_hash(3),
            required_memory_bytes: 8 * 1024 * 1024,
            backend_hint: ComputeBackend::Gpu,
            reward_sat: 1_000_000,
            expiry_height: 1000,
            submit_height: 500,
        };
        assert_eq!(task.task_hash(), task.task_hash(), "must be deterministic");
    }

    #[test]
    fn task_is_active_before_expiry_only() {
        let task = ComputeTask {
            task_id: dummy_hash(1),
            ir_hash: dummy_hash(2),
            input_hash: dummy_hash(3),
            required_memory_bytes: 0,
            backend_hint: ComputeBackend::Cpu,
            reward_sat: 0,
            expiry_height: 100,
            submit_height: 50,
        };
        assert!(task.is_active(100));
        assert!(!task.is_active(101));
    }

    // ------------------------------------------------------------------
    // ComputeAttestation
    // ------------------------------------------------------------------

    #[test]
    fn signing_payload_covers_all_fields() {
        let attest = make_attest(dummy_hash(1), dummy_hash(2), 3);
        let payload = attest.signing_payload();
        // Payload must contain the task_id, result_hash, etc.
        assert!(payload.len() >= 32 + 32 + 1 + 20 + 8);
    }

    #[test]
    fn attest_hash_changes_with_result() {
        let a1 = make_attest(dummy_hash(1), dummy_hash(10), 1);
        let a2 = make_attest(dummy_hash(1), dummy_hash(11), 1); // different result
        assert_ne!(a1.attest_hash(), a2.attest_hash());
    }

    // ------------------------------------------------------------------
    // Quorum verification
    // ------------------------------------------------------------------

    #[test]
    fn quorum_succeeds_with_supermajority() {
        let task = dummy_hash(0);
        let correct = dummy_hash(42);
        let wrong = dummy_hash(99);

        let attests = vec![
            make_attest(task, correct, 1),
            make_attest(task, correct, 2),
            make_attest(task, correct, 3),
            make_attest(task, wrong, 4), // dissenter
        ];

        let result = verify_quorum(&attests, 3);
        assert_eq!(result, Ok(correct));
    }

    #[test]
    fn quorum_fails_without_threshold() {
        let task = dummy_hash(0);
        let attests = vec![
            make_attest(task, dummy_hash(1), 1),
            make_attest(task, dummy_hash(2), 2),
            make_attest(task, dummy_hash(3), 3),
        ];
        assert!(verify_quorum(&attests, 3).is_err(), "no consensus reached");
    }

    #[test]
    fn dissenters_are_identified_for_slashing() {
        let task = dummy_hash(0);
        let majority = dummy_hash(5);
        let attests = vec![
            make_attest(task, majority, 1),
            make_attest(task, majority, 2),
            make_attest(task, dummy_hash(9), 3), // dissenter at index 2
        ];
        // Threshold = 3 so no quorum, dissenters returned
        let Err(dissenters) = verify_quorum(&attests, 3) else {
            panic!("expected Err");
        };
        assert!(
            dissenters.contains(&2),
            "dissenter at index 2 must be flagged"
        );
    }

    #[test]
    fn all_backends_have_a_name() {
        for b in 0..=7u8 {
            let backend = ComputeBackend::from_wire(b);
            assert!(!backend.name().is_empty());
        }
    }

    // ------------------------------------------------------------------
    // Decoders: the codec must be an exact inverse
    // ------------------------------------------------------------------

    #[test]
    fn compute_task_round_trips_through_its_decoder() {
        let task = ComputeTask {
            task_id: dummy_hash(1),
            ir_hash: dummy_hash(2),
            input_hash: dummy_hash(3),
            required_memory_bytes: 8 * 1024 * 1024,
            backend_hint: ComputeBackend::Unknown(0x42),
            reward_sat: 1_000_000,
            expiry_height: 1000,
            submit_height: 500,
        };
        let bytes = task.serialize();
        assert_eq!(bytes.len(), ComputeTask::SERIALIZED_LEN);
        let mut r = crate::ser::Reader::new(&bytes);
        let back = ComputeTask::from_reader(&mut r).unwrap();
        r.expect_end().unwrap();
        assert_eq!(back, task);
        assert_eq!(back.task_hash(), task.task_hash());
    }

    #[test]
    fn attestation_round_trips_and_bounds_its_signature() {
        let mut attest = make_attest(dummy_hash(4), dummy_hash(5), 6);
        attest.signature = vec![0xAB; 72];
        let bytes = attest.serialize();
        let mut r = crate::ser::Reader::new(&bytes);
        let back = ComputeAttestation::from_reader(&mut r).unwrap();
        r.expect_end().unwrap();
        assert_eq!(back, attest);

        // A declared length over the cap is refused before it drives an
        // allocation, even when the buffer really is that long.
        let mut huge = vec![0u8; 32 + 32 + 1 + 20 + 8];
        huge.extend_from_slice(&(ComputeAttestation::MAX_SIGNATURE_BYTES as u32 + 1).to_le_bytes());
        huge.extend_from_slice(&vec![0u8; ComputeAttestation::MAX_SIGNATURE_BYTES + 1]);
        let mut r = crate::ser::Reader::new(&huge);
        assert!(matches!(
            ComputeAttestation::from_reader(&mut r),
            Err(crate::error::Error::Malformed(_))
        ));
    }

    // ------------------------------------------------------------------
    // Canonical reference: one definition, reproducible everywhere
    // ------------------------------------------------------------------

    #[test]
    fn reference_output_is_deterministic_and_sensitive() {
        let a = reference_output(&dummy_hash(1), &dummy_hash(2), &dummy_hash(3), 4096);
        let b = reference_output(&dummy_hash(1), &dummy_hash(2), &dummy_hash(3), 4096);
        assert_eq!(
            a, b,
            "identical commitments must reproduce byte-identically"
        );
        assert_eq!(a.len(), 64);
        // Every commitment matters: changing any one changes the output.
        assert_ne!(
            a,
            reference_output(&dummy_hash(9), &dummy_hash(2), &dummy_hash(3), 4096)
        );
        assert_ne!(
            a,
            reference_output(&dummy_hash(1), &dummy_hash(9), &dummy_hash(3), 4096)
        );
        assert_ne!(
            a,
            reference_output(&dummy_hash(1), &dummy_hash(2), &dummy_hash(9), 4096)
        );
        assert_ne!(
            a,
            reference_output(&dummy_hash(1), &dummy_hash(2), &dummy_hash(3), 8192)
        );
    }

    #[test]
    fn reference_result_hash_commits_the_output() {
        let out = reference_output(&dummy_hash(1), &dummy_hash(2), &dummy_hash(3), 4096);
        assert_eq!(
            reference_result_hash(&dummy_hash(1), &dummy_hash(2), &dummy_hash(3), 4096),
            crate::hash::sha256(&[&out])
        );
    }
}
