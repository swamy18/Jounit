//! Hashrate probe: build a mini template at a given difficulty, grind it with
//! the multithreaded CPU miner, print attempts/elapsed/H/s.
//!
//! Usage: `cargo run -p jnt-miner --example bench_hashrate -- <threads> <difficulty> <max_attempts>`
//! Example: `cargo run -p jnt-miner --example bench_hashrate -- 4 5000 2000000`
//!
//! Debug builds are 10-50x slower than release; use `--release` for numbers
//! you publish.

use jnt_core::chain::Chain;
use jnt_core::params::NetworkParams;
use jnt_miner::{solve_header, PowMode};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threads: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let difficulty: u128 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5_000);
    let max_attempts: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let template = chain
        .build_template_with([7u8; 20], vec![], 1_767_225_601_000, Some(difficulty))
        .expect("template must build");
    let mode = PowMode::Hybrid(jnt_core::puzzle::PuzzleSpec::hybrid_v1());

    let start = std::time::Instant::now();
    let sol =
        solve_header(&template.header, mode, threads, max_attempts).expect("miner must not error");
    let elapsed = start.elapsed();

    match sol {
        Some(sol) => {
            let hs = sol.attempts as f64 / elapsed.as_secs_f64();
            println!(
                "solved height={} nonce={} attempts={} elapsed={:.2}s hashrate={:.0} H/s",
                sol.header.height,
                sol.header.nonce,
                sol.attempts,
                elapsed.as_secs_f64(),
                hs
            );
        }
        None => {
            let hs = max_attempts as f64 / elapsed.as_secs_f64();
            println!(
                "unsolved after {max_attempts} attempts in {:.2}s ({hs:.0} H/s); raise the budget or lower difficulty",
                elapsed.as_secs_f64()
            );
        }
    }
}
