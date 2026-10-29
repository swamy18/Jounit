//! `srct-miner`: standalone CPU mining binary (XMRig-equivalent v1).
//!
//! Loops forever: fetch an unsolved template from the node, grind it with
//! the multithreaded solver, submit the solved block. The node re-validates
//! everything, so a buggy or hostile miner can only waste its own CPU.
//!
//! Usage:
//! ```text
//! srct-miner --node 127.0.0.1:PORT --miner <20-byte hex> [--threads N] [--batch N] [--backend cpu|portable|auto]
//! ```
//!
//! `--threads 0` (default) means one thread per CPU. `--batch N` evaluates N
//! candidates per solver step through the batch interface (`accel`); 1 is the
//! plain sequential path. `--backend` (or `SRCT_MINER_BACKEND`) selects the
//! compute substrate: `cpu` is the reference, `portable` the independent
//! implementation every substrate backend must match — GPU, NPU, TPU,
//! photonic and domestic accelerators all plug into the same trait, so the
//! flag is where a vendor backend gets selected once built. Blocks are solved
//! at the template's own difficulty; when the network outruns us the submit
//! is refused as stale and we fetch a fresh template.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use srct_core::block::Block;

use srct_miner::PowMode;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_SLEEP: Duration = Duration::from_secs(2);

fn usage() -> ! {
    eprintln!(
        "usage: srct-miner --node 127.0.0.1:PORT --miner <20-byte hex> [--threads N] [--batch N] [--backend cpu|portable|auto]"
    );
    std::process::exit(2);
}

struct Args {
    node: SocketAddr,
    miner: String,
    threads: usize,
    batch: usize,
    backend: srct_miner::accel::BackendKind,
}

fn parse_args() -> Args {
    let mut node = None;
    let mut miner = None;
    let mut threads = 0usize;
    let mut batch = 1usize;
    let mut backend_flag = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--node" => node = it.next(),
            "--miner" => miner = it.next(),
            "--threads" => {
                threads = it.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--threads needs a number");
                    usage()
                })
            }
            "--batch" => {
                batch = it.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--batch needs a number");
                    usage()
                })
            }
            "--backend" => backend_flag = it.next(),
            _ => usage(),
        }
    }
    let (Some(node), Some(miner)) = (node, miner) else {
        usage()
    };
    let node = node.parse().unwrap_or_else(|_| {
        eprintln!("--node must be ADDR:PORT");
        usage()
    });
    if srct_core::hash::address_from_hex(&miner).is_err() {
        eprintln!("--miner must be a 20-byte hex address");
        usage();
    }
    // Flag wins over the environment; unset means the environment, unset
    // means the reference CPU backend.
    let backend = backend_flag
        .map(|s| {
            srct_miner::accel::BackendKind::parse(&s).unwrap_or_else(|e| {
                eprintln!("--backend: {e}");
                usage()
            })
        })
        .or_else(|| {
            srct_miner::accel::BackendKind::from_env()
                .map_err(|e| {
                    eprintln!("SRCT_MINER_BACKEND: {e}");
                    usage()
                })
                .ok()
        })
        .unwrap_or_default();
    // Clamp resource use at the CLI boundary: thread and batch counts are
    // operator input, and an unbounded count is a local OOM (`--threads
    // 1000000` spawns a million OS threads; `--batch 100000000` sizes a
    // per-thread buffer). `0` keeps its existing meanings: one thread per
    // CPU, and sequential (batch 1) solving.
    const MAX_THREADS: usize = 1024;
    const MAX_BATCH: usize = 65_536;
    if threads > MAX_THREADS {
        eprintln!("--threads capped at {MAX_THREADS}");
        usage();
    }
    if batch > MAX_BATCH {
        eprintln!("--batch capped at {MAX_BATCH}");
        usage();
    }
    let batch = if batch == 0 { 1 } else { batch };
    Args {
        node,
        miner,
        threads,
        batch,
        backend,
    }
}

/// Raw HTTP exchange over a fresh connection. `Connection: close` makes the
/// server close after the response, so `read_to_end` is the whole body.
fn http(
    node: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {node}\r\n\
         Connection: close\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect_timeout(&node, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {node}: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    // Cap the response: a compromised node must not be able to OOM the miner
    // with an unbounded body. 16 MiB matches the pool/API line caps.
    const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
    let mut buf = Vec::new();
    // A refusal may arrive before the whole body is written; that is the
    // server doing its job, not a failure of this client.
    let _ = stream.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut buf);
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("response over the 16 MiB cap".to_string());
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "malformed HTTP status line".to_string())?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .ok_or_else(|| "malformed HTTP response (no header terminator)".to_string())?;
    Ok((status, body))
}

fn main() {
    let args = parse_args();
    let threads_label = if args.threads == 0 {
        "auto".to_string()
    } else {
        args.threads.to_string()
    };
    println!(
        "srct-miner: {threads_label} threads -> {} paying {}",
        args.node, args.miner
    );
    loop {
        if let Err(e) = mine_once(&args) {
            eprintln!("srct-miner: {e}; retrying in {}s", RETRY_SLEEP.as_secs());
            std::thread::sleep(RETRY_SLEEP);
        }
    }
}

/// One template -> solve -> submit cycle. Returns Err only when the cycle
/// should be retried (stale template, refused submit, transport error).
fn mine_once(args: &Args) -> Result<(), String> {
    // 1. Template.
    let (s, body) = http(
        args.node,
        "GET",
        &format!("/v1/mine/template?miner={}", args.miner),
        None,
    )?;
    if s != 200 {
        return Err(format!("template refused (http {s}): {body}"));
    }
    let tpl: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("template not json: {e}"))?;
    let block_hex = tpl
        .get("block_hex")
        .and_then(|v| v.as_str())
        .ok_or("template missing block_hex")?;
    let raw = hex::decode(block_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("template block hex: {e}"))?;
    let template = Block::deserialize(&raw).map_err(|e| format!("template block decode: {e}"))?;
    let height = template.header.height;
    let difficulty = template.header.difficulty;

    // 2. Solve. v1 mines hybrid-v1 only: HBM templates need the network's
    // HBM config, which no endpoint serves yet — refusing loudly beats
    // grinding a puzzle the node would judge by different parameters.
    if template.header.puzzle_id != 1 {
        return Err(format!(
            "template names puzzle {} (binary mines hybrid-v1 only)",
            template.header.puzzle_id
        ));
    }
    let mode = PowMode::Hybrid(srct_core::puzzle::PuzzleSpec::hybrid_v1());
    let backend_name = match args.backend {
        srct_miner::accel::BackendKind::Cpu => "cpu",
        srct_miner::accel::BackendKind::Portable => "portable",
    };
    println!(
        "srct-miner: [{backend_name}] grinding height {height} at difficulty {difficulty} ..."
    );
    let Some(sol) = match args.backend {
        srct_miner::accel::BackendKind::Cpu => srct_miner::accel::solve_header_batched(
            &template.header,
            mode,
            args.threads,
            args.batch,
            u64::MAX,
        ),
        srct_miner::accel::BackendKind::Portable => srct_miner::accel::solve_header_batched_with(
            &template.header,
            mode,
            args.threads,
            args.batch,
            u64::MAX,
            srct_miner::accel::PortableBackend,
        ),
    }
    .map_err(|e| format!("solver: {e}"))?
    else {
        return Err("nonce space exhausted without a solution".into());
    };
    println!(
        "srct-miner: solved height {height} nonce={} attempts={}",
        sol.header.nonce, sol.attempts
    );

    // 3. Submit: the solved header back into the template block.
    let mut solved = template;
    solved.header = sol.header;
    let solved_hex = hex::encode(solved.serialize());
    let (s, body) = http(
        args.node,
        "POST",
        "/v1/mine/submit",
        Some(&serde_json::json!({ "block_hex": solved_hex }).to_string()),
    )?;
    if s != 200 {
        return Err(format!("submit refused (http {s}): {body}"));
    }
    println!("srct-miner: accepted height {height}: {body}");
    Ok(())
}
