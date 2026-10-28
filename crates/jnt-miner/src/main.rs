//! `jnt-miner`: standalone CPU mining binary (XMRig-equivalent v1).
//!
//! Loops forever: fetch an unsolved template from the node, grind it with
//! the multithreaded solver, submit the solved block. The node re-validates
//! everything, so a buggy or hostile miner can only waste its own CPU.
//!
//! Usage:
//! ```text
//! jnt-miner --node 127.0.0.1:PORT --miner <20-byte hex> [--threads N] [--batch N]
//! ```
//!
//! `--threads 0` (default) means one thread per CPU. `--batch N` evaluates N
//! candidates per solver step through the batch interface (`accel`); 1 is the
//! plain sequential path. Blocks are solved at the template's own difficulty;
//! when the network outruns us the submit is refused as stale and we fetch a
//! fresh template.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use jnt_core::block::Block;

use jnt_miner::PowMode;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_SLEEP: Duration = Duration::from_secs(2);

fn usage() -> ! {
    eprintln!(
        "usage: jnt-miner --node 127.0.0.1:PORT --miner <20-byte hex> [--threads N] [--batch N]"
    );
    std::process::exit(2);
}

struct Args {
    node: SocketAddr,
    miner: String,
    threads: usize,
    batch: usize,
}

fn parse_args() -> Args {
    let mut node = None;
    let mut miner = None;
    let mut threads = 0usize;
    let mut batch = 1usize;
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
    if jnt_core::hash::address_from_hex(&miner).is_err() {
        eprintln!("--miner must be a 20-byte hex address");
        usage();
    }
    Args {
        node,
        miner,
        threads,
        batch,
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
    let mut buf = Vec::new();
    // A refusal may arrive before the whole body is written; that is the
    // server doing its job, not a failure of this client.
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
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
        "jnt-miner: {threads_label} threads -> {} paying {}",
        args.node, args.miner
    );
    loop {
        if let Err(e) = mine_once(&args) {
            eprintln!("jnt-miner: {e}; retrying in {}s", RETRY_SLEEP.as_secs());
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
    println!("jnt-miner: grinding height {height} at difficulty {difficulty} ...");
    let mode = PowMode::Hybrid(jnt_core::puzzle::PuzzleSpec::hybrid_v1());
    let Some(sol) = jnt_miner::accel::solve_header_batched(
        &template.header,
        mode,
        args.threads,
        args.batch,
        u64::MAX,
    )
    .map_err(|e| format!("solver: {e}"))?
    else {
        return Err("nonce space exhausted without a solution".into());
    };
    println!(
        "jnt-miner: solved height {height} nonce={} attempts={}",
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
    println!("jnt-miner: accepted height {height}: {body}");
    Ok(())
}
