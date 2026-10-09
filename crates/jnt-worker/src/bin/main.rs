//! The worker CLI — secret-free (SPEC.md §18, "CLI" item).
//!
//! Commands:
//!
//! - `address`   print the wallet's Jounit address (`jt1…`)
//! - `generate`  create a wallet file (0600-equivalent, operator-supplied path)
//! - `run`       the worker daemon loop: discover → claim → execute → submit,
//!   over a live node's REST API (§18.3). It uses the SDK's injected seams
//!   and the **production** `RealBls` verifier, so it exercises the same code
//!   path an operator's own integration would; it implements no consensus
//!   rule of its own. Before the first pass it gates on the node's live
//!   conservation report (`GET /v1/conservation`): this daemon moves real
//!   value, so a node reporting joint supply over the joint bound — or numbers that
//!   do not re-add — is refused rather than earned from.
//!
//! No command ever prints a private key; `generate` writes the file and prints
//! only the path, and `run` logs task ids and errors but never key material
//! (§18.16).
//!
//! **Shutdown:** the `run` loop is bounded by `--iterations` for operators who
//! want that, and otherwise runs until the process is terminated. There is no
//! portable signal handler here (and the node's own `serve` loop has none
//! either); between passes nothing is left half-written, because every step in
//! a pass is a complete signed transaction broadcast to the node.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use jnt_core::bls::RealBls;
use jnt_core::bls_checkpoint::ValidatorSet;
use jnt_core::hash::{address_to_hex, hash_to_hex, Hash};
use jnt_core::params::NetworkParams;
use jnt_worker::node::Host;
use jnt_worker::{is_retryable, CpuExecutor, HttpNode, WorkerClient, WorkerConfig, WorkerError};

/// The concrete client the CLI builds: the HTTP transport serves as both the
/// read view and the broadcaster, and the CPU executor is the SDK's reference
/// engine.
type CliClient = WorkerClient<HttpNode, HttpNode, CpuExecutor>;

fn usage() -> String {
    "usage:
  jnt-worker address  --from-file <path>
  jnt-worker generate --out-file <path> [--label <label>]
  jnt-worker run      --from-file <path> --node <base-url> [--network <name>]
                      [--iterations <n>] [--interval-ms <n>] [--max-tasks <n>]
                      [--deposit-sat <n>]

  run defaults: --network mini, --iterations 0 (until stopped),
                --interval-ms 2000, --max-tasks 4, --deposit-sat 0

  run gates on GET /v1/conservation first: a node reporting joint supply
  over the joint bound (or unreadable numbers) is refused; an unreachable or
  non-reporting node warns and continues."
        .to_string()
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().ok_or_else(usage)?;
    match cmd.as_str() {
        "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        "address" => cmd_address(args),
        "generate" => cmd_generate(args),
        "run" => cmd_run(args),
        other => Err(format!("unknown command `{other}`\n{}", usage())),
    }
}

fn str_arg<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let path = str_arg(args, "--from-file").ok_or("address needs --from-file <path>")?;
    let wallet = load_wallet(path)?;
    let addr = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;
    println!("{}", jnt_core::hash::address_to_hex(&addr));
    Ok(())
}

fn cmd_generate(args: &[String]) -> Result<(), String> {
    let out = str_arg(args, "--out-file").ok_or("generate needs --out-file <path>")?;
    let label = str_arg(args, "--label")
        .cloned()
        .unwrap_or_else(|| "worker".to_string());
    let wallet = jnt_core::wallet::Wallet::new_random(label);
    let json =
        serde_json::to_string_pretty(&wallet).map_err(|e| format!("wallet encode failed: {e}"))?;
    // Best-effort restrictive permissions; on Windows the file inherits the
    // directory ACL, which the operator is responsible for placing sensibly.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| format!("cannot create {out}: {e}"))?;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o600));
    }
    // Print only the path. The key bytes now exist in exactly one operator-
    // controlled file and nowhere else in this process's output.
    println!("{}", out);
    Ok(())
}

/// A u64 flag, or `default` when absent. A present-but-unparseable value is an
/// error rather than a silent fallback, so a typo cannot change the daemon's
/// behaviour behind the operator's back.
fn num_arg(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match str_arg(args, name) {
        None => Ok(default),
        Some(v) => v.parse::<u64>().map_err(|e| format!("{name}: {e}")),
    }
}

/// First 12 hex chars of a hash, for legible logs. Never truncates fewer than
/// the string it has.
fn short(id: &Hash) -> String {
    let h = hash_to_hex(id);
    h[..12.min(h.len())].to_string()
}

/// The worker daemon loop (§18.3 transport, §18.4–§18.7 lifecycle).
fn cmd_run(args: &[String]) -> Result<(), String> {
    let file = str_arg(args, "--from-file").ok_or("run needs --from-file <wallet>")?;
    let node_url = str_arg(args, "--node").ok_or("run needs --node <base-url>")?;
    let network = str_arg(args, "--network")
        .map(String::as_str)
        .unwrap_or("mini");
    let params = NetworkParams::by_name(network).map_err(|e| e.to_string())?;

    let iterations = num_arg(args, "--iterations", 0)?;
    let interval_ms = num_arg(args, "--interval-ms", 2_000)?;
    let max_tasks = num_arg(args, "--max-tasks", 4)?;
    let deposit_sat = num_arg(args, "--deposit-sat", 0)?;

    let wallet = load_wallet(file)?;
    let address = wallet
        .address()
        .map_err(|e| format!("wallet unusable: {e}"))?;
    let config = WorkerConfig::from_wallet(&wallet).with_deposit(deposit_sat);

    // Two independent transports: a view (reads) and a broadcaster (writes).
    // Neither sees the key — signing happens inside the client (§18.3). The
    // network id is checked by `for_network`, so a mini worker cannot be
    // pointed at a mainnet node by accident.
    let view = HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;

    // Conservation gate (SPEC §19.4–§19.5): value created anywhere — L1 or
    // L2 — turns every later payment into a claim on nothing, so the daemon
    // refuses to run against a node whose joint supply is broken. The three
    // verdicts are recomputed here from the report's own numbers rather than
    // trusted from its `ok` flag. An unreachable node, or one too old to
    // report, warns and continues: discovery's own retry loop is the right
    // handler for those. An answer that is wrong or unreadable is refused —
    // that node is answering, and cannot be trusted.
    match view.conservation() {
        Ok(Some(r)) if r.holds() => println!(
            "conservation  ok (joint {} of {} sat bound, headroom {})",
            r.joint_sat,
            r.joint_bound_sat,
            r.headroom_sat()
        ),
        Ok(Some(r)) => {
            return Err(format!(
                "conservation gate failed: joint {} of {} sat (l1 {} + l2 {} - sink {}), \
                 l2_closed {}, l2_funding_ok {} — refusing to run against this node",
                r.joint_sat, r.joint_bound_sat, r.l1_live_sat, r.l2_held_sat, r.sink_held_sat,
                r.l2_closed, r.l2_funding_ok
            ));
        }
        Ok(None) => eprintln!(
            "conservation  not reported by this node (older build?); continuing without the self-check"
        ),
        Err(WorkerError::ObservationUnavailable(why)) => {
            eprintln!("conservation  unavailable ({why}); continuing without the self-check")
        }
        Err(e) => return Err(format!("conservation gate could not read the node: {e}")),
    }

    let broadcaster =
        HttpNode::for_network(node_url, &params.network_id).map_err(|e| e.to_string())?;
    let host = Host::new(view, broadcaster);
    let validators = ValidatorSet::new(params.genesis_validators.clone());
    let mut client = WorkerClient::new(host, wallet, CpuExecutor::default(), validators, &RealBls)
        .with_config(config)
        .map_err(|e| format!("worker config: {e}"))?;

    println!("worker         {}", address_to_hex(&address));
    println!("node           {node_url}");
    println!("network        {}", params.network_id);
    println!("max tasks/pass {max_tasks}");
    println!("deposit (sat)  {deposit_sat}");

    let mut pass: u64 = 0;
    loop {
        pass += 1;
        run_one_pass(&mut client, max_tasks, pass)?;
        if iterations != 0 && pass >= iterations {
            break;
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    Ok(())
}

/// One discovery → claim → execute → submit pass.
///
/// Task-local failures are logged and skipped: a task that expires mid-flight
/// must not stop the daemon, and a claim the protocol refused is information,
/// not a crash. Only a discovery failure that `is_retryable` rejects is fatal,
/// because at that point the node is answering but its answer is unusable.
fn run_one_pass(client: &mut CliClient, max_tasks: u64, pass: u64) -> Result<(), String> {
    let tasks = match client.discover() {
        Ok(t) => t,
        Err(e) if is_retryable(&e) => {
            eprintln!("pass {pass}: discovery unavailable, will retry: {e}");
            return Ok(());
        }
        Err(e) => return Err(format!("discovery failed, refusing to continue: {e}")),
    };
    println!("pass {pass}: {} claimable task(s)", tasks.len());

    for task in tasks.iter().take(max_tasks as usize) {
        let id = task.task_id;
        match client.claim(id) {
            Ok(_) => println!(
                "  claim   {} net={} sat",
                short(&id),
                task.net_payment_sat()
            ),
            Err(e) => {
                eprintln!("  claim   {} refused: {e}", short(&id));
                continue;
            }
        }
        match client.execute_and_submit(id) {
            Ok(_) => println!("  submit  {} ok", short(&id)),
            Err(e) => eprintln!("  submit  {} refused: {e}", short(&id)),
        }
    }
    Ok(())
}

fn load_wallet(path: &str) -> Result<jnt_core::wallet::Wallet, String> {
    let text =
        fs::read_to_string(PathBuf::from(path)).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not a wallet file: {e}"))
}
