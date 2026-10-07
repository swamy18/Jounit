//! The worker CLI — minimal, secret-free (SPEC.md §18, "CLI" item).
//!
//! The SDK's architecture is an in-process library over injected seams, so a
//! *useful* worker CLI needs a live node transport, which this build does not
//! have yet (§18.3). What IS appropriate today — and provided here — is the
//! worker's own key tooling on the SDK's primitives:
//!
//! - `address`  print the wallet's Jounit address (`jt1…`)
//! - `generate` create a wallet file (0600-equivalent, operator-supplied path)
//!
//! Anything beyond (claim/submit/status) is Phase 6 with the REST API, and is
//! documented as such in the SDK README/docs. No command ever prints a
//! private key; `generate` writes the file and prints only the path.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn usage() -> String {
    "usage:
  jnt-worker address --from-file <path>
  jnt-worker generate --out-file <path> [--label <label>]"
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

fn load_wallet(path: &str) -> Result<jnt_core::wallet::Wallet, String> {
    let text =
        fs::read_to_string(PathBuf::from(path)).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not a wallet file: {e}"))
}
