//! CLI-level tests for the authority and credit commands, against a real chain.
//!
//! These spawn the real `srct-node` binary, so they cover the parts a user
//! actually touches: the argument parsing, the deposit that funds a Layer-2
//! balance, the publication of a grant, a spend under it, the revocation, and
//! the credit flow - and, most importantly, that the CLI agrees with the
//! chain. The CLI checks every transaction against the state the chain will
//! replay and refuses with the chain's own reason, so a command that reports
//! success means the chain accepted it.
//!
//! The chain here is the `mini` profile, whose difficulty is 1: the blocks are
//! cheap, and the test mines what it needs rather than mocking anything.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_srct-node");

/// A per-process temp path, so parallel test binaries cannot collide.
fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("srct-node-cli-{}-{name}", std::process::id()))
}

/// Run the binary and return `(exit_code, stdout, stderr)`.
fn exec(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .env("SRCT_WALLET_PASSPHRASE", "cli-authority-test")
        .current_dir(dir)
        .output()
        .expect("spawn srct-node");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run(dir: &PathBuf, args: &[&str]) -> String {
    let (code, stdout, stderr) = exec(dir, args);
    assert_eq!(
        code,
        0,
        "`srct-node {}` failed: {}{}",
        args.join(" "),
        stdout,
        stderr
    );
    stdout
}

/// The value of a `key   value` line.
fn field(text: &str, key: &str) -> String {
    text.lines()
        .map(str::trim_start)
        .find(|l| l.starts_with(key))
        .unwrap_or_else(|| panic!("no `{key}` line in:\n{text}"))
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("no value after `{key}` in:\n{text}"))
        .to_string()
}

/// The agent identity out of a `policy --list` line.
///
/// The line reads `<hash>  agent <id>  spender <id> ...`, so the identity is
/// the token after the word `agent`.
fn agent_id_of(listing: &str) -> String {
    let tokens: Vec<&str> = listing.split_whitespace().collect();
    let at = tokens
        .iter()
        .position(|t| *t == "agent")
        .expect("the listing names the agent");
    tokens[at + 1].to_string()
}

#[test]
fn the_authority_flow_works_from_the_terminal() {
    let dir = tmp("authority");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir");

    // A chain with a wallet.
    let init = run(&dir, &["init", "--network", "mini", "--data-dir", "chain"]);
    let me = field(&init, "address");

    // The coinbase has to mature before it can be spent.
    run(
        &dir,
        &[
            "mine",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--blocks",
            "12",
        ],
    );

    // A deposit funds the Layer-2 balance the grants and the loans spend from.
    let sink = run(
        &dir,
        &[
            "l2",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--deposit-address",
        ],
    )
    .lines()
    .next()
    .unwrap()
    .trim()
    .to_string();
    assert!(
        sink.starts_with("jt1"),
        "the deposit address is printed: {sink}"
    );

    run(
        &dir,
        &[
            "send",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--to",
            &sink,
            "--amount",
            "5",
        ],
    );

    // The deposit is credited once it is final.
    run(
        &dir,
        &[
            "mine",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--blocks",
            "25",
        ],
    );
    let l2 = run(&dir, &["l2", "--network", "mini", "--data-dir", "chain"]);
    assert!(
        l2.contains("conserved     true"),
        "the Layer-2 state conserves value:\n{l2}"
    );

    // Publish a grant: this key may spend up to 0.01 SRCT per payment, to this
    // recipient only.
    let published = run(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--spender",
            &me,
            "--per-tx",
            "1000000",
            "--cumulative",
            "5000000",
            "--recipients",
            &me,
        ],
    );
    let policy_hash = field(&published, "policy");

    // The agent spends under it.
    let spent = run(
        &dir,
        &[
            "agent-spend",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--policy",
            &policy_hash,
            "--to",
            &me,
            "--amount",
            "0.002",
            "--nonce",
            "1",
        ],
    );
    assert!(spent.contains("spent"), "the spend is reported:\n{spent}");

    // The grant is on chain, with the counters the spend moved.
    let listed = run(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--list",
        ],
    );
    assert!(
        listed.contains(&policy_hash),
        "the grant is listed:\n{listed}"
    );
    assert!(
        listed.contains("spends 1"),
        "the spend is in the counters:\n{listed}"
    );

    // The owner kills the grant.
    let agent = agent_id_of(&run(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--list",
        ],
    ));
    run(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--revoke",
            "--agent-id",
            &agent,
        ],
    );
    let listed = run(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--list",
        ],
    );
    assert!(
        listed.contains("revoked true"),
        "the grant is revoked:\n{listed}"
    );

    // And a spend under a revoked grant is refused, by the chain's reason.
    let (code, _, stderr) = exec(
        &dir,
        &[
            "agent-spend",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--policy",
            &policy_hash,
            "--to",
            &me,
            "--amount",
            "0.001",
            "--nonce",
            "2",
        ],
    );
    assert_ne!(code, 0, "a spend under a revoked grant must fail");
    assert!(
        stderr.contains("revoked"),
        "the refusal names the reason: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_credit_flow_works_from_the_terminal() {
    let dir = tmp("credit");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir");

    let init = run(&dir, &["init", "--network", "mini", "--data-dir", "chain"]);
    let me = field(&init, "address");
    run(
        &dir,
        &[
            "mine",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--blocks",
            "12",
        ],
    );

    let sink = run(
        &dir,
        &[
            "l2",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--deposit-address",
        ],
    )
    .lines()
    .next()
    .unwrap()
    .trim()
    .to_string();
    run(
        &dir,
        &[
            "send",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--to",
            &sink,
            "--amount",
            "5",
        ],
    );
    run(
        &dir,
        &[
            "mine",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--blocks",
            "25",
        ],
    );

    // A loan: the lender signs, the principal moves, the collateral locks.
    let opened = run(
        &dir,
        &[
            "credit",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--to",
            &me,
            "--amount",
            "1",
            "--collateral",
            "100000000",
            "--rate-bps",
            "100",
            "--window",
            "100",
            "--deadline",
            "100000",
            "--nonce",
            "1",
        ],
    );
    let position = field(&opened, "position");

    let listed = run(
        &dir,
        &[
            "credit",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--list",
        ],
    );
    assert!(
        listed.contains("state Open"),
        "the position is open:\n{listed}"
    );

    // Repayment: interest first, then principal, and the collateral comes back
    // when the debt is settled.
    run(
        &dir,
        &[
            "credit",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--repay",
            "--position",
            &position,
            "--amount",
            "1",
        ],
    );
    let listed = run(
        &dir,
        &[
            "credit",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--list",
        ],
    );
    assert!(
        listed.contains("state Repaid"),
        "the position is repaid:\n{listed}"
    );
    assert!(
        listed.contains("outstanding 0.00000000"),
        "the debt is settled:\n{listed}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_command_the_chain_would_skip_is_refused_before_it_mines_anything() {
    let dir = tmp("refuse");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir");

    let init = run(&dir, &["init", "--network", "mini", "--data-dir", "chain"]);
    let me = field(&init, "address");
    run(
        &dir,
        &[
            "mine",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--blocks",
            "12",
        ],
    );

    // A grant whose caps are not numbers is refused by the parser, and one the
    // chain would refuse is refused with the chain's reason - and neither
    // mines a block.
    let before = run(
        &dir,
        &["status", "--network", "mini", "--data-dir", "chain"],
    );
    let height_before = field(&before, "height");

    let (code, _, stderr) = exec(
        &dir,
        &[
            "policy",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--spender",
            &me,
            "--per-tx",
            "not-a-number",
            "--cumulative",
            "1000",
        ],
    );
    assert_ne!(code, 0, "a bad cap is refused");
    assert!(
        stderr.contains("per-tx") || stderr.contains("number"),
        "the refusal names the problem: {stderr}"
    );

    // A grant for a spend that no one can make is fine, but a spend under a
    // grant that was never published is refused by the chain.
    let (code, _, stderr) = exec(
        &dir,
        &[
            "agent-spend",
            "--network",
            "mini",
            "--data-dir",
            "chain",
            "--policy",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--to",
            &me,
            "--amount",
            "0.001",
            "--nonce",
            "1",
        ],
    );
    assert_ne!(code, 0, "a spend under an unknown grant must fail");
    assert!(
        stderr.contains("skip") || stderr.contains("policy"),
        "the refusal names the reason: {stderr}"
    );

    let after = run(
        &dir,
        &["status", "--network", "mini", "--data-dir", "chain"],
    );
    assert_eq!(
        field(&after, "height"),
        height_before,
        "a refused command mines nothing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
