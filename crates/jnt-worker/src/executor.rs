//! The execution seam (SPEC.md §18.6).
//!
//! Execution is the SDK's one pluggable boundary: the operator supplies an
//! [`Executor`] (CPU worker, GPU worker, AI agent loop, external compute
//! service); the SDK routes the task's commitment hashes to it and hashes the
//! output into the result the protocol sees. Execution holds no keys, no state
//! handle and no broadcast path — isolation by type, not by convention.
//!
//! The SDK ships exactly one executor ([`CpuExecutor`]): the SPEC.md §16
//! CPU-reference shape, needed by tests and by dispute observation. Everything
//! real roots its own `Executor` impl; the SDK never interprets `ir_hash` or
//! `input_hash` (fetching off-chain IR is the operator's transport).

use jnt_core::compute_ir::{ComputeBackend, ComputeTask};
use jnt_core::hash::{sha256, Hash};

use jnt_l2::TaskContract;

use crate::error::{WorkerError, WorkerResult};

/// The work one execution receives: commitment hashes and constraints, never
/// keys, never state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWork {
    pub task_id: Hash,
    pub ir_hash: Hash,
    pub input_hash: Hash,
    pub required_memory_bytes: u64,
    pub backend_hint: ComputeBackend,
    pub current_height: u64,
}

impl ExecutionWork {
    /// Project from a live contract, or refuse when it is not claimable work.
    pub fn from_contract(contract: &TaskContract, current_height: u64) -> WorkerResult<Self> {
        let t: &ComputeTask = &contract.compute_task;
        Ok(ExecutionWork {
            task_id: contract.task_id,
            ir_hash: t.ir_hash,
            input_hash: t.input_hash,
            required_memory_bytes: t.required_memory_bytes,
            backend_hint: t.backend_hint,
            current_height,
        })
    }
}

/// The executor's declared capabilities, matched against a task before claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorCapabilities {
    pub backend: ComputeBackend,
    pub max_memory_bytes: u64,
}

/// What an executor produced: the raw output bytes (whose SHA-256 is the
/// protocol's `result_hash`) and the backend that ran, which MUST be one the
/// executor declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub output: Vec<u8>,
    pub backend: ComputeBackend,
}

/// Failure from inside the executor. The reason is opaque operator text; keys
/// never cross this seam, and the SDK never echoes executor output or errors
/// into protocol-visible fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError {
    pub reason: String,
}

/// The pluggable execution engine.
pub trait Executor {
    fn capabilities(&self) -> ExecutorCapabilities;

    fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError>;
}

/// Run `executor` against `contract` and produce the signed-attestation-ready
/// output. Fails closed on a capability mismatch or an empty result.
pub fn execute_task<E: Executor>(
    executor: &E,
    work: &ExecutionWork,
) -> WorkerResult<ExecutionOutput> {
    let caps = executor.capabilities();
    // The executor must be able to do the job the task describes: a mismatch
    // is refused rather than downgraded (a claim on hardware that cannot run
    // the task would burn the worker's deposit through expiry, §15.4). An
    // `Unknown(hint)` task carries no class commitment, so any executor MAY
    // attempt it — that is what the wire value means (§M3).
    if work.backend_hint != ComputeBackend::Unknown(0) && caps.backend != work.backend_hint {
        return Err(WorkerError::TaskNotAvailable("backend mismatch"));
    }
    if caps.max_memory_bytes < work.required_memory_bytes {
        return Err(WorkerError::TaskNotAvailable("insufficient memory"));
    }
    let out = executor
        .execute(work)
        .map_err(|e| WorkerError::ExecutionFailed {
            backend: caps.backend.name(),
            reason: e.reason,
        })?;
    if out.output.is_empty() {
        return Err(WorkerError::EmptyResult);
    }
    Ok(out)
}

/// The SHA-256 of executor output — the `result_hash` the protocol sees.
///
/// Free-standing because it is also the disputed-side rule: a challenger
/// re-execution hashes the same way (SPEC.md §16.2).
pub fn result_hash_of(output: &[u8]) -> Hash {
    sha256(&[output])
}

/// The reference executor: the SPEC.md §16 CPU shape.
///
/// Deterministic by construction — same work, same bytes, no clock, no RNG —
/// which is what lets a challenger reproduce it. The embedded program is a
/// pure function of the task's own commitment hashes: it mixes `ir_hash` and
/// `input_hash` through a fixed permutation, so two tasks agreeing on the
/// chain produce the same result and different tasks (almost always) do not.
pub struct CpuExecutor {
    /// Memory budget the operator provisions; defaults permissive.
    pub max_memory_bytes: u64,
}

impl Default for CpuExecutor {
    fn default() -> Self {
        CpuExecutor {
            max_memory_bytes: u64::MAX,
        }
    }
}

impl Executor for CpuExecutor {
    fn capabilities(&self) -> ExecutorCapabilities {
        ExecutorCapabilities {
            backend: ComputeBackend::Cpu,
            max_memory_bytes: self.max_memory_bytes,
        }
    }

    fn execute(&self, work: &ExecutionWork) -> Result<ExecutionOutput, ExecError> {
        // A fixed, dependency-free 32-round Keccak-style permutation over the
        // commitments. No floating point (SPEC.md §16.3), no platform types.
        let mut state = [0u64; 25];
        let mut fill = |i: usize, bytes: &[u8]| {
            for (j, chunk) in bytes.chunks(8).enumerate() {
                let mut v = [0u8; 8];
                v[..chunk.len()].copy_from_slice(chunk);
                state[i * 4 + j % 4] ^= u64::from_le_bytes(v);
            }
        };
        fill(0, &work.task_id);
        fill(1, &work.ir_hash);
        fill(2, &work.input_hash);
        state[12] ^= work.required_memory_bytes;
        state[13] ^= work.current_height;

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

        let mut out = Vec::with_capacity(64);
        for lane in state.iter().take(8) {
            out.extend_from_slice(&lane.to_le_bytes());
        }
        Ok(ExecutionOutput {
            output: out,
            backend: ComputeBackend::Cpu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(seed: u8) -> ExecutionWork {
        ExecutionWork {
            task_id: [seed; 32],
            ir_hash: [seed.wrapping_add(1); 32],
            input_hash: [seed.wrapping_add(2); 32],
            required_memory_bytes: 1024,
            backend_hint: ComputeBackend::Cpu,
            current_height: 10,
        }
    }

    #[test]
    fn cpu_reference_is_deterministic() {
        let e = CpuExecutor::default();
        let a = e.execute(&work(7)).unwrap();
        let b = e.execute(&work(7)).unwrap();
        assert_eq!(a, b, "same work must produce the same bytes");
        let c = e.execute(&work(8)).unwrap();
        assert_ne!(a.output, c.output, "different tasks must diverge");
    }

    #[test]
    fn result_hash_is_the_sha256_of_the_output() {
        let e = CpuExecutor::default();
        let out = e.execute(&work(3)).unwrap();
        assert_eq!(result_hash_of(&out.output), sha256(&[&out.output]));
    }
}
