//! GPU seam: batched stage-2 evaluation for the mining loop.
//!
//! The consensus math is **not** reimplemented here: every digest below is
//! produced by the same verified `jnt-core` stage functions the sequential
//! solver calls, only applied to many candidates at once. The batch boundary
//! is exactly where a GPU backend plugs in — stage 2 is a data-parallel
//! matrix-vector forward pass over independent seeds, which is what GPUs
//! (and the HBM scratchpad design) are for.
//!
//! [`NnBackend`] is the contract a future wgpu/CUDA backend implements:
//! same inputs, same outputs, same order as [`CpuBackend`]. [`BatchSolver`]
//! drives it with one weight derivation per batch instead of one per
//! candidate, and [`solve_header_batched`] is the threaded grind over that
//! interface. Equivalence with the sequential solver is pinned by tests, so
//! swapping the backend can never silently change what counts as a solution.

use jnt_core::block::Header;
use jnt_core::error::{Error, Result};
use jnt_core::hash::Hash;
use jnt_core::puzzle::{
    stage1_seed, stage2_activation_digest_with, stage3_final, EpochWeights, PuzzleRun,
    PuzzleSolver, PuzzleSpec,
};

/// Stage-2 backend contract: digests for `seeds` under `weights`, in order.
///
/// A GPU implementation moves the forward pass (and only the forward pass)
/// onto the device; weight derivation and stage 1/3 stay on the host, so the
/// host still commits every layer exactly as consensus requires.
pub trait NnBackend {
    fn stage2_batch(&self, spec: &PuzzleSpec, seeds: &[Hash], weights: &EpochWeights) -> Vec<Hash>;
}

/// Reference backend: the verified host forward pass, one seed at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuBackend;

impl NnBackend for CpuBackend {
    fn stage2_batch(&self, spec: &PuzzleSpec, seeds: &[Hash], weights: &EpochWeights) -> Vec<Hash> {
        seeds
            .iter()
            .map(|seed| stage2_activation_digest_with(spec, seed, weights))
            .collect()
    }
}

/// Batched evaluator: one weight derivation per batch, backend-driven
/// stage 2, consensus-identical stage 1/3. All headers in a batch must share
/// `epoch_id` (mining batches always do — they grind one template); mixed
/// batches are refused rather than silently evaluated under one epoch's
/// weights.
#[derive(Debug, Clone)]
pub struct BatchSolver<B: NnBackend = CpuBackend> {
    spec: PuzzleSpec,
    weights: EpochWeights,
    backend: B,
}

impl<B: NnBackend> BatchSolver<B> {
    pub fn with_backend(spec: PuzzleSpec, backend: B) -> Self {
        let weights = EpochWeights::build(&spec, 0);
        BatchSolver {
            spec,
            weights,
            backend,
        }
    }

    /// Full runs for `headers`, in input order.
    pub fn evaluate(&mut self, headers: &[Header]) -> Result<Vec<PuzzleRun>> {
        let Some(first) = headers.first() else {
            return Ok(Vec::new());
        };
        if headers.iter().any(|h| h.epoch_id != first.epoch_id) {
            return Err(Error::Malformed("batch spans more than one epoch"));
        }
        if self.weights.epoch_id != first.epoch_id {
            self.weights = EpochWeights::build(&self.spec, first.epoch_id);
        }
        let seeds: Vec<Hash> = headers.iter().map(|h| stage1_seed(&self.spec, h)).collect();
        let acts = self.backend.stage2_batch(&self.spec, &seeds, &self.weights);
        Ok(headers
            .iter()
            .zip(seeds.iter().zip(acts.iter()))
            .map(|(h, (seed, act))| {
                let final_hash = stage3_final(&self.spec, seed, act, h.nonce, h.epoch_id);
                PuzzleRun {
                    seed: *seed,
                    activation_digest: *act,
                    final_hash,
                }
            })
            .collect())
    }
}

impl BatchSolver<CpuBackend> {
    pub fn new(spec: PuzzleSpec) -> Self {
        BatchSolver::with_backend(spec, CpuBackend)
    }
}

/// Batched grind: same search order and solution as [`crate::solve_header`]
/// (single thread), but candidates are evaluated `batch` at a time through
/// [`BatchSolver`]. `batch == 0` means 1 (sequential-equivalent). This is the
/// entry point a GPU backend accelerates: swap [`CpuBackend`] for the device
/// backend and the loop above it does not change.
pub fn evaluate_batch_sequential(spec: &PuzzleSpec, headers: &[Header]) -> Result<Vec<PuzzleRun>> {
    BatchSolver::new(spec.clone()).evaluate(headers)
}

/// Threaded grind over the batch interface.
///
/// `batch <= 1` delegates to [`crate::solve_header`] exactly (same code path
/// the existing tests pin); larger batches evaluate `batch` strided nonces
/// per step through one [`BatchSolver`] per thread. Search order — and hence
/// the winning nonce on one thread — is identical either way.
///
/// HBM templates ignore `batch` and grind sequentially per candidate: the
/// memory-hard pass has no batch interface (that is what a device backend
/// would add), and silently batching it would change nothing but the
/// accounting.
pub fn solve_header_batched(
    template: &Header,
    mode: crate::PowMode,
    threads: usize,
    batch: usize,
    max_attempts: u64,
) -> Result<Option<crate::MineSolution>> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    if batch <= 1 {
        return crate::solve_header(template, mode, threads, max_attempts);
    }
    if max_attempts == 0 {
        return Ok(None);
    }
    if template.difficulty == 0 {
        return Err(Error::InvalidDifficulty(0));
    }
    let target = jnt_core::u256::target_for_difficulty(template.difficulty)?;
    // Same agreement check as the sequential path: the mode's puzzle must be
    // the template's puzzle, or a miner could "solve" under one puzzle and
    // submit under another.
    let spec = match &mode {
        crate::PowMode::Hybrid(spec) => {
            if template.puzzle_id != spec.id {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds {}",
                    template.puzzle_id, spec.id
                )));
            }
            spec.validate()?;
            Some(spec.clone())
        }
        crate::PowMode::Hbm(cfg) => {
            if template.puzzle_id != 2 {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds hbm-v1",
                    template.puzzle_id
                )));
            }
            cfg.validate()?;
            None
        }
    };

    let n_threads = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        threads
    }
    .max(1);
    let per_thread = max_attempts.div_ceil(n_threads as u64);
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let solution: Arc<Mutex<Option<Header>>> = Arc::new(Mutex::new(None));

    std::thread::scope(|s| {
        for t in 0..n_threads {
            let found = found.clone();
            let attempts = attempts.clone();
            let solution = solution.clone();
            let template = template.clone();
            let mode = mode.clone();
            let spec = spec.clone();
            s.spawn(move || {
                let stride = n_threads as u64;
                let mut extra: u128 = u128::from_le_bytes(template.extra_nonce);
                let mut batch_solver = spec.clone().map(BatchSolver::new);
                let mut seq_solver = match &mode {
                    crate::PowMode::Hybrid(spec) => Some(PuzzleSolver::new(spec.clone())),
                    crate::PowMode::Hbm(_) => None,
                };
                let mut local: u64 = 0;
                let mut chunk: Vec<Header> = Vec::with_capacity(batch);
                // Evaluate one filled chunk in nonce order.
                // Ok(Some(h)) = solution found; Ok(None) = keep grinding;
                // Err(()) = solver refused (poisoned backend) — stop, never spin.
                let mut flush =
                    |chunk: &mut Vec<Header>| -> std::result::Result<Option<Header>, ()> {
                        if chunk.is_empty() {
                            return Ok(None);
                        }
                        if let Some(bs) = batch_solver.as_mut() {
                            let runs = match bs.evaluate(chunk) {
                                Ok(runs) => runs,
                                Err(_) => return Err(()),
                            };
                            for (h, run) in chunk.iter().zip(runs.iter()) {
                                if jnt_core::u256::U256::from_be_bytes(run.final_hash) <= target {
                                    return Ok(Some(h.clone()));
                                }
                            }
                            Ok(None)
                        } else if let Some(solver) = seq_solver.as_mut() {
                            for h in chunk.iter() {
                                match solver.satisfies(h) {
                                    Ok(true) => return Ok(Some(h.clone())),
                                    Ok(false) => {}
                                    Err(_) => return Err(()),
                                }
                            }
                            Ok(None)
                        } else {
                            Ok(None)
                        }
                    };
                loop {
                    let mut nonce = t as u64;
                    let mut wrapped = false;
                    loop {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }
                        if local >= per_thread {
                            return;
                        }
                        // Fill one batch from this thread's strided subsequence.
                        chunk.clear();
                        let mut exhausted = false;
                        while chunk.len() < batch {
                            let prev = attempts.fetch_add(1, Ordering::Relaxed);
                            if prev >= max_attempts {
                                exhausted = true;
                                break;
                            }
                            let mut h = template.clone();
                            h.nonce = nonce;
                            h.extra_nonce = extra.to_le_bytes();
                            chunk.push(h);
                            local += 1;
                            match nonce.checked_add(stride) {
                                Some(next) => nonce = next,
                                None => {
                                    wrapped = true;
                                    break;
                                }
                            }
                        }
                        let won = match flush(&mut chunk) {
                            Err(()) => return,
                            Ok(hit) => hit,
                        };
                        if let Some(h) = won {
                            if !found.swap(true, Ordering::Relaxed) {
                                *solution.lock().unwrap() = Some(h);
                            }
                            return;
                        }
                        if exhausted {
                            return;
                        }
                        if wrapped {
                            break;
                        }
                        let _ = t;
                    }
                    extra = extra.wrapping_add(1);
                    if extra == u128::from_le_bytes(template.extra_nonce) {
                        return;
                    }
                }
            });
        }
    });

    let header = solution.lock().unwrap().clone();
    match header {
        Some(header) => Ok(Some(crate::MineSolution {
            header,
            attempts: attempts.load(Ordering::Relaxed),
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PowMode;
    use jnt_core::puzzle::run_puzzle;

    fn header_with_nonce(nonce: u64) -> Header {
        let mut h = jnt_core::block::genesis_block(1).header;
        h.height = 1;
        h.difficulty = 1;
        h.puzzle_id = 1;
        h.nonce = nonce;
        h
    }

    #[test]
    fn batch_matches_sequential_candidate_for_candidate() {
        let spec = PuzzleSpec::hybrid_v1();
        let headers: Vec<Header> = (0..64u64).map(header_with_nonce).collect();
        let mut solver = BatchSolver::new(spec.clone());
        let batched = solver.evaluate(&headers).unwrap();
        for (h, run) in headers.iter().zip(batched.iter()) {
            assert_eq!(*run, run_puzzle(&spec, h));
        }
    }

    #[test]
    fn batch_rebuilds_weights_across_epochs() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec.clone());
        let mut a = header_with_nonce(0);
        a.epoch_id = 3;
        let mut b = header_with_nonce(1);
        b.epoch_id = 3;
        let batched = solver.evaluate(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(batched[0], run_puzzle(&spec, &a));
        assert_eq!(batched[1], run_puzzle(&spec, &b));
        // A later batch under another epoch re-derives instead of reusing.
        let mut c = header_with_nonce(2);
        c.epoch_id = 4;
        let batched2 = solver.evaluate(&[c.clone()]).unwrap();
        assert_eq!(batched2[0], run_puzzle(&spec, &c));
    }

    #[test]
    fn mixed_epoch_batch_is_refused() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec);
        let mut b = header_with_nonce(1);
        b.epoch_id = 9;
        let err = solver.evaluate(&[header_with_nonce(0), b]).unwrap_err();
        assert_eq!(err, Error::Malformed("batch spans more than one epoch"));
    }

    #[test]
    fn empty_batch_is_empty() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec);
        assert!(solver.evaluate(&[]).unwrap().is_empty());
    }

    /// The batched grind finds the same first solution as the sequential
    /// grind on the same template: batching must never reorder the search.
    #[test]
    fn solve_batched_matches_solve_sequential() {
        use crate::accel::solve_header_batched;

        let template = header_with_nonce(0);
        let seq = crate::solve_header(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            50_000,
        )
        .unwrap()
        .expect("difficulty 1 solves");
        for batch in [2usize, 7, 64, 1024] {
            let batched = solve_header_batched(
                &template,
                PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
                1,
                batch,
                50_000,
            )
            .unwrap()
            .expect("batched must solve too");
            assert_eq!(
                batched.header.nonce, seq.header.nonce,
                "batch {batch} must find the same first nonce"
            );
        }
    }

    #[test]
    fn solve_batched_zero_budget_and_passthrough() {
        use crate::accel::solve_header_batched;

        let template = header_with_nonce(0);
        assert!(solve_header_batched(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            64,
            0
        )
        .unwrap()
        .is_none());
        // batch <= 1 delegates to the sequential path exactly.
        let sol = solve_header_batched(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            1,
            100,
        )
        .unwrap()
        .expect("passthrough must solve");
        assert_eq!(sol.header.nonce, 0);
    }
}
