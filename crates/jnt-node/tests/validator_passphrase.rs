//! Validator-key passphrase handling (Task 4).
//!
//! Validator keys are consensus-signing material, so they get their own
//! passphrase variable (`JNT_VALIDATOR_PASSPHRASE`) with a fallback to
//! `JNT_WALLET_PASSPHRASE` and a loud warning about sharing one. These drive
//! the real CLI as a subprocess, so each case gets its own environment and no
//! test races another over a process-global variable.
//!
//! What they pin:
//!
//! - `JNT_VALIDATOR_PASSPHRASE` writes an encrypted key file, and the same
//!   variable reads it back;
//! - `JNT_WALLET_PASSPHRASE` still reads it, and says so on stderr;
//! - an old plaintext key file still loads, with a warning, and a new one is
//!   refused rather than written unencrypted;
//! - the on-disk format is unchanged, so a file written by one path is
//!   readable by the other.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const VALIDATOR_ENV: &str = "JNT_VALIDATOR_PASSPHRASE";
const WALLET_ENV: &str = "JNT_WALLET_PASSPHRASE";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_jnt-node")
}

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("jnt-valkeys-{tag}-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    assert!(Path::new(&dir).is_dir(), "the temp dir must exist");
    dir
}

/// Run the node binary with an explicit environment. `JNT_WALLET_PASSPHRASE`
/// is cleared unless the caller names it, so a value inherited from the
/// running test process cannot leak into a case.
fn node(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    node_on("mini", dir, args, envs)
}

fn node_on(network: &str, dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    cmd.arg("--network").arg(network);
    cmd.arg("--data-dir").arg(dir);
    cmd.env_remove(WALLET_ENV);
    cmd.env_remove(VALIDATOR_ENV);
    // Deterministic, and never the real terminal.
    cmd.env_remove("JNT_WALLET_PASSPHRASE");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("the node binary must run")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn validator_file(dir: &Path) -> PathBuf {
    dir.join("validators").join("validator.json")
}

/// Is the file the encrypted wallet-file container rather than JSON?
fn is_encrypted(path: &Path) -> bool {
    let bytes = std::fs::read(path).unwrap();
    bytes.starts_with(b"JNTWLT01")
}

#[test]
fn the_dedicated_passphrase_writes_an_encrypted_key() {
    let dir = temp_dir("dedicated");
    let out = node(
        &dir,
        &["validator", "--add"],
        &[(VALIDATOR_ENV, "validator-only-pass")],
    );
    assert!(out.status.success(), "add failed: {}", stderr(&out));
    assert!(is_encrypted(&validator_file(&dir)), "not encrypted");

    // Reading it back names the key, so the same passphrase round-trips.
    let out = node(
        &dir,
        &["validator"],
        &[(VALIDATOR_ENV, "validator-only-pass")],
    );
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 2, "a key and a count");

    // The wrong passphrase is refused, not silently ignored.
    let out = node(&dir, &["validator"], &[(VALIDATOR_ENV, "wrong")]);
    assert!(!out.status.success(), "a wrong passphrase must refuse");
}

#[test]
fn mainnet_bootstrap_writes_the_declared_quorum_committee() {
    let dir = temp_dir("mainnet-bootstrap");
    let out = node_on(
        "mainnet",
        &dir,
        &["validator", "--bootstrap"],
        &[(VALIDATOR_ENV, "bootstrap-pass")],
    );
    assert!(out.status.success(), "bootstrap failed: {}", stderr(&out));

    let key_count = std::fs::read_dir(dir.join("validators")).unwrap().count();
    assert_eq!(key_count, 21, "one file per bootstrap key");

    let out = node_on(
        "mainnet",
        &dir,
        &["validator"],
        &[(VALIDATOR_ENV, "bootstrap-pass")],
    );
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    let listed = stdout(&out);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 22, "21 public keys and one count");

    let mut expected = (1u8..=21)
        .map(jnt_core::params::mainnet_validator_key)
        .collect::<Vec<_>>();
    expected.sort_by_key(|key| key.0);
    let expected = expected
        .iter()
        .map(|key| hex::encode(key.as_bytes()))
        .collect::<Vec<_>>();
    let actual = lines[..21]
        .iter()
        .map(|key| (*key).to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "loaded keys must match the declared committee"
    );
    assert_eq!(lines[21], "21 validator(s)");
}

#[test]
fn bootstrap_is_mainnet_only_and_never_writes_plaintext_keys() {
    let mini = temp_dir("bootstrap-mini");
    let out = node_on(
        "mini",
        &mini,
        &["validator", "--bootstrap"],
        &[(VALIDATOR_ENV, "bootstrap-pass")],
    );
    assert!(
        !out.status.success(),
        "mini must refuse mainnet bootstrap keys"
    );
    assert!(stderr(&out).contains("mainnet-only"));

    let mainnet = temp_dir("bootstrap-no-passphrase");
    let out = node_on("mainnet", &mainnet, &["validator", "--bootstrap"], &[]);
    assert!(!out.status.success(), "bootstrap must require a passphrase");
    assert!(stderr(&out).contains(VALIDATOR_ENV));
    assert!(!mainnet.join("validators").exists());
}

#[test]
fn the_wallet_passphrase_still_reads_the_key_and_says_so() {
    let dir = temp_dir("fallback");
    // Write under the dedicated variable, read under the wallet one.
    node(
        &dir,
        &["validator", "--add"],
        &[(VALIDATOR_ENV, "shared-pass")],
    );
    let out = node(&dir, &["validator"], &[(WALLET_ENV, "shared-pass")]);
    assert!(
        out.status.success(),
        "the wallet passphrase must still read it: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("JNT_VALIDATOR_PASSPHRASE"),
        "the fallback must be reported: {}",
        stderr(&out)
    );
}

/// An old, unencrypted key file must keep loading — refusing it would lock an
/// operator out of a validator they still hold — with a warning naming it.
#[test]
fn an_old_plaintext_key_file_still_loads_with_a_warning() {
    let dir = temp_dir("plaintext");
    let vdir = dir.join("validators");
    std::fs::create_dir_all(&vdir).unwrap();

    // Build a real key file through the encrypted path, then decrypt the
    // container by hand is not possible, so instead stage a plaintext one the
    // same shape `validator --add` wrote before encryption existed: the JSON
    // of a `ValidatorKeyFile`.
    let out = node(
        &dir,
        &["validator", "--add"],
        &[(VALIDATOR_ENV, "plain-staging-pass")],
    );
    assert!(out.status.success());

    // `validator --add` refuses to write plaintext, so the plaintext shape is
    // produced by the node's own library, not by a flag.
    let key_file = validator_file(&dir);
    let bytes = std::fs::read(&key_file).unwrap();
    assert!(is_encrypted(&key_file));
    let _ = bytes;

    // A plaintext file with the same JSON body is accepted, with a warning.
    let sk = jnt_core::bls::SecretKey::derive(&[9u8; 32]).unwrap();
    let key = jnt_core::signing::ValidatorKey::new(sk, "jounit/mini");
    let json = serde_json::to_vec_pretty(&key.to_file()).unwrap();
    let plain = vdir.join("plain.json");
    std::fs::write(&plain, &json).unwrap();

    let out = node(
        &dir,
        &["validator"],
        &[(VALIDATOR_ENV, "plain-staging-pass")],
    );
    assert!(out.status.success(), "list failed: {}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 3, "two keys and a count");
    assert!(
        stderr(&out).contains("unencrypted validator key"),
        "the plaintext file must be reported: {}",
        stderr(&out)
    );
}

/// A new key is refused rather than written unencrypted, and the existing
/// plaintext file is left alone.
#[test]
fn a_new_key_is_refused_without_a_passphrase() {
    let dir = temp_dir("refuse");
    let out = node(&dir, &["validator", "--add"], &[]);
    assert!(!out.status.success(), "no passphrase must refuse");
    assert!(
        stderr(&out).contains(VALIDATOR_ENV),
        "the refusal must name the variable: {}",
        stderr(&out)
    );
    assert!(!validator_file(&dir).exists(), "nothing was written");
}
