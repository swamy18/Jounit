//! Standalone CPU miner for Jounit (`hybrid-v1` and `hbm-v1`).
//!
//! The node builds an unsolved block with [`Chain::build_template_with`]
//! (everything fixed except `nonce` / `extra_nonce`, which both commit into
//! the proof via the serialized header). This crate grinds that template:
//! nonce space is partitioned across threads, each with its own
//! [`PuzzleSolver`] (or HBM check), and the first solution wins. A solved
//! header is handed back to the node, which re-validates the proof in
//! `submit` — the miner is never trusted.
//!
//! v1 scope: CPU only, single header template, `nonce` + `extra_nonce[16]`
//! search. The [`stratum`] module adds the pool-side job protocol;
//! GPU kernels are follow-ups.

pub mod stratum;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use jnt_core::block::Header;
use jnt_core::error::{Error, Result};
use jnt_core::hbm_pow::HbmConfig;
use jnt_core::puzzle::{PuzzleKind, PuzzleSolver, PuzzleSpec};

/// How the proof is checked for one candidate header.
#[derive(Debug, Clone)]
pub enum PowMode {
    Hybrid(PuzzleSpec),
    Hbm(HbmConfig),
}

/// Outcome of a successful grind.
#[derive(Debug, Clone)]
pub struct MineSolution {
    pub header: Header,
    /// Total candidates tested across all threads (including the winner).
    pub attempts: u64,
}

fn satisfies(mode: &PowMode, solver: &mut PuzzleSolver, header: &Header) -> Result<bool> {
    match mode {
        PowMode::Hybrid(_) => solver.satisfies(header),
        PowMode::Hbm(cfg) => {
            let ok = jnt_core::hbm_pow::hbm_satisfies_cfg(header, header.difficulty, cfg)?;
            Ok(ok)
        }
    }
}

/// Grind `template` until the proof satisfies the header difficulty.
///
/// `threads == 0` means one thread per CPU. `max_attempts` caps the total
/// candidates across all threads (0 = refuse immediately). Returns `None`
/// when the budget is exhausted without a solution.
///
/// The search covers `nonce` first; when `nonce` wraps, `extra_nonce` is
/// treated as a little-endian u128 counter and the nonce scan restarts. Both
/// fields commit into the proof through the serialized header, so rolling
/// either is consensus-safe.
pub fn solve_header(
    template: &Header,
    mode: PowMode,
    threads: usize,
    max_attempts: u64,
) -> Result<Option<MineSolution>> {
    if max_attempts == 0 {
        return Ok(None);
    }
    if template.difficulty == 0 {
        return Err(Error::InvalidDifficulty(0));
    }
    // The mode's spec must agree with the template's puzzle id, or a miner
    // could "solve" under one puzzle and submit under another.
    match &mode {
        PowMode::Hybrid(spec) => {
            if template.puzzle_id != spec.id {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds {}",
                    template.puzzle_id, spec.id
                )));
            }
            if spec.kind != PuzzleKind::Hybrid {
                return Err(Error::BadPuzzleSpec(
                    "hybrid mode needs a hybrid spec".into(),
                ));
            }
            spec.validate()?;
        }
        PowMode::Hbm(cfg) => {
            if template.puzzle_id != 2 {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds hbm-v1",
                    template.puzzle_id
                )));
            }
            cfg.validate()?;
        }
    }

    let n_threads = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        threads
    };
    let n_threads = n_threads.max(1);

    // Single-thread fast path: no atomics, no threads.
    if n_threads == 1 {
        let spec_owned = match &mode {
            PowMode::Hybrid(spec) => Some(spec.clone()),
            PowMode::Hbm(_) => None,
        };
        let mut solver =
            PuzzleSolver::new(spec_owned.unwrap_or_else(jnt_core::puzzle::PuzzleSpec::hybrid_v1));
        let mut header = template.clone();
        let mut extra: u128 = u128::from_le_bytes(header.extra_nonce);
        let mut attempts: u64 = 0;
        loop {
            for nonce in 0..=u64::MAX {
                if attempts >= max_attempts {
                    return Ok(None);
                }
                header.nonce = nonce;
                header.extra_nonce = extra.to_le_bytes();
                attempts += 1;
                if satisfies(&mode, &mut solver, &header)? {
                    return Ok(Some(MineSolution { header, attempts }));
                }
                if nonce == u64::MAX {
                    break;
                }
            }
            extra = extra.wrapping_add(1);
            // Full 2^64 x 2^128 space exhausted without a solution.
            if extra == u128::from_le_bytes(template.extra_nonce) {
                return Ok(None);
            }
        }
    }

    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let solution: Arc<Mutex<Option<Header>>> = Arc::new(Mutex::new(None));
    let per_thread = max_attempts.div_ceil(n_threads as u64);

    std::thread::scope(|s| {
        for t in 0..n_threads {
            let found = found.clone();
            let attempts = attempts.clone();
            let solution = solution.clone();
            let template = template.clone();
            let mode = mode.clone();
            s.spawn(move || {
                let spec_owned = match &mode {
                    PowMode::Hybrid(spec) => Some(spec.clone()),
                    PowMode::Hbm(_) => None,
                };
                let mut solver = PuzzleSolver::new(
                    spec_owned.unwrap_or_else(jnt_core::puzzle::PuzzleSpec::hybrid_v1),
                );
                // Strided nonce assignment: thread t tries t, t+n, t+2n...
                // so every thread makes progress on every extra_nonce round
                // and no range arithmetic can skip or double-cover a nonce.
                let stride = n_threads as u64;
                let mut extra: u128 = u128::from_le_bytes(template.extra_nonce);
                let mut header = template.clone();
                let mut local: u64 = 0;
                loop {
                    let mut nonce = t as u64;
                    loop {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }
                        // Global budget check before spending a hash.
                        let prev = attempts.fetch_add(1, Ordering::Relaxed);
                        if prev >= max_attempts {
                            return;
                        }
                        header.nonce = nonce;
                        header.extra_nonce = extra.to_le_bytes();
                        local += 1;
                        let ok = match satisfies(&mode, &mut solver, &header) {
                            Ok(ok) => ok,
                            Err(_) => return,
                        };
                        if ok {
                            if !found.swap(true, Ordering::Relaxed) {
                                *solution.lock().unwrap() = Some(header.clone());
                            }
                            return;
                        }
                        if local >= per_thread {
                            return;
                        }
                        match nonce.checked_add(stride) {
                            Some(next) => nonce = next,
                            None => break,
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
        Some(header) => Ok(Some(MineSolution {
            header,
            attempts: attempts.load(Ordering::Relaxed),
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_template() -> Header {
        let mut h = jnt_core::block::genesis_block(1).header;
        h.height = 1;
        h.difficulty = 1;
        h.puzzle_id = 1;
        h
    }

    #[test]
    fn zero_budget_solves_nothing() {
        let h = header_template();
        let mode = PowMode::Hybrid(PuzzleSpec::hybrid_v1());
        assert!(solve_header(&h, mode, 1, 0).unwrap().is_none());
    }

    #[test]
    fn zero_difficulty_is_refused() {
        let mut h = header_template();
        h.difficulty = 0;
        let mode = PowMode::Hybrid(PuzzleSpec::hybrid_v1());
        assert!(matches!(
            solve_header(&h, mode, 1, 10),
            Err(Error::InvalidDifficulty(0))
        ));
    }

    #[test]
    fn wrong_puzzle_is_refused() {
        let h = header_template();
        let mode = PowMode::Hybrid(PuzzleSpec::hbm_v1());
        assert!(matches!(
            solve_header(&h, mode, 1, 10),
            Err(Error::BadPuzzleSpec(_))
        ));
    }

    #[test]
    fn difficulty_one_solves_on_one_thread() {
        // Difficulty 1: every candidate satisfies, so the first try wins.
        let h = header_template();
        let mode = PowMode::Hybrid(PuzzleSpec::hybrid_v1());
        let sol = solve_header(&h, mode, 1, 100)
            .unwrap()
            .expect("difficulty 1 must solve immediately");
        assert_eq!(sol.header.nonce, 0);
        assert_eq!(sol.attempts, 1);
    }

    #[test]
    fn difficulty_one_solves_on_four_threads() {
        let h = header_template();
        let mode = PowMode::Hybrid(PuzzleSpec::hybrid_v1());
        let sol = solve_header(&h, mode, 4, 1000)
            .unwrap()
            .expect("difficulty 1 must solve immediately");
        let mut solver = PuzzleSolver::new(PuzzleSpec::hybrid_v1());
        assert!(solver.satisfies(&sol.header).unwrap());
    }

    /// End-to-end external-miner loop: the node builds a template, this
    /// crate solves it, the node submits it. Uses difficulty 1 so the
    /// proof is trivially satisfiable and the test stays fast.
    #[test]
    fn template_solve_submit_roundtrip() {
        use jnt_core::chain::Chain;
        use jnt_core::params::NetworkParams;

        let mut chain = Chain::new(NetworkParams::mini()).unwrap();
        let miner = [7u8; 20];
        let template = chain
            .build_template_with(miner, vec![], 1_767_225_601_000, Some(1))
            .unwrap();
        assert_eq!(template.header.nonce, 0);
        assert_eq!(template.header.extra_nonce, [0u8; 16]);

        let mode = PowMode::Hybrid(PuzzleSpec::hybrid_v1());
        let sol = solve_header(&template.header, mode, 2, 10_000)
            .unwrap()
            .expect("difficulty 1 template must solve");
        let mut block = template;
        block.header = sol.header;
        let height_before = chain.height();
        chain.submit(block).unwrap();
        assert_eq!(chain.height(), height_before + 1);
    }
}
