//! At-rest protection for `wallets.json`.
//!
//! The file holds raw secp256k1 private keys: anyone who reads it spends the
//! wallets. Two properties, in the order they buy something:
//!
//! - **0600 permissions, written atomically.** The file is created through a
//!   temp file that is *already* 0600 (no world-readable window) and renamed
//!   into place, so a crash mid-write cannot leave a half-written key file and
//!   an over-broad umask cannot leave a readable one.
//! - **Encryption under a passphrase** ([`PASSPHRASE_ENV`]). Argon2id derives
//!   a key from the passphrase and a per-file random salt; ChaCha20-Poly1305
//!   seals the JSON. Without the passphrase the file is inert, which is the
//!   property that survives the failure mode permissions do not: a copied
//!   backup, a tarball, a CI artifact, or a disk someone else now owns.
//!
//! Writing plaintext remains *possible* (`--allow-plaintext-wallet`) because
//! throwaway chains and tests exist — but it has to be asked for. The default
//! is a refusal, so the insecure path is a decision rather than a habit.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

/// File magic: `SRCTWLT` plus the format version `01`. Present only on
/// encrypted files, so plaintext JSON is still recognized by shape.
pub const MAGIC: &[u8] = b"SRCTWLT01";

/// Environment variable carrying the wallet-file passphrase. Read at each
/// load/save rather than cached, so a long-running `serve` can be given it at
/// start and nothing holds it beyond that call.
pub const PASSPHRASE_ENV: &str = "SRCT_WALLET_PASSPHRASE";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Poly1305 tag, appended by `encrypt`.
const TAG_LEN: usize = 16;

/// The passphrase to encrypt under, if the operator supplied one. Returned
/// `Zeroizing` so the parsed copy wipes on drop — the env block outlives the
/// call either way, but the heap copy need not linger.
pub fn passphrase_from_env() -> Option<Zeroizing<String>> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new)
}

/// Whether a file's bytes are an encrypted wallet file rather than JSON.
pub fn is_encrypted(blob: &[u8]) -> bool {
    blob.starts_with(MAGIC)
}

/// Derive the ChaCha20-Poly1305 key from the passphrase, returned in a
/// `Zeroizing` buffer so the in-memory key is overwritten when it goes out of
/// scope rather than sitting in a freed allocation for the next taker.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    // Argon2id at the crate's defaults (RFC 9106 second recommended option):
    // memory-hard on purpose, so an attacker with the file cannot brute-force
    // a human passphrase at the speed of a GPU hash.
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Seal `plaintext` under `passphrase`: `magic ‖ salt(16) ‖ nonce(12) ‖ ct+tag`.
///
/// Salt and nonce are fresh on every write, so saving twice leaks no equality
/// between the two files and a stolen file cannot be matched against another.
pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    // `new_from_slice`/`Nonce::from` rather than the deprecated `from_slice`
    // constructors, which generic-array 0.14 warns on.
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "wallet cipher setup failed".to_string())?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| "wallet encryption failed".to_string())?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`encrypt`]. Refuses a wrong passphrase, a
/// truncated file and a tampered file by name — all three surface as a MAC
/// failure, and the caller's message must not pretend to know which.
pub fn decrypt(passphrase: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let header = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if blob.len() < header + TAG_LEN {
        return Err("wallet file is truncated".to_string());
    }
    let (prefix, rest) = blob.split_at(MAGIC.len());
    if prefix != MAGIC {
        return Err("wallet file has an unknown format".to_string());
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);
    let key = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "wallet cipher setup failed".to_string())?;
    cipher
        .decrypt(&Nonce::from(nonce_bytes), ct)
        .map(Zeroizing::new)
        .map_err(|_| "wrong passphrase, or the wallet file was modified".to_string())
}

/// Write `bytes` to `path` so that no other account can read them and no crash
/// can leave a partial file.
///
/// The temp file is created with mode 0600 (unix) before a single byte of key
/// material is written, fsynced, then renamed over the destination — rename is
/// atomic within a directory, so `path` always holds either the old file or the
/// complete new one. Any stale temp file from an earlier crash is removed
/// first: reusing it would inherit whatever permissions it was created with.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = Path::new(&tmp_name);
    let _ = fs::remove_file(tmp);

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Ignored on non-unix platforms, where the file inherits the
            // directory's ACLs instead; there is no portable std call for it.
            opts.mode(0o600);
        }
        let mut file = opts
            .open(tmp)
            .map_err(|e| format!("wallet temp file: {e}"))?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }

    fs::rename(tmp, path).map_err(|e| format!("wallet file replace: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let plain = br#" [{"label":"miner","private_key":"00"}] "#;
        let blob = encrypt("correct horse", plain).unwrap();
        assert!(is_encrypted(&blob));
        assert!(!is_encrypted(plain), "JSON is not mistaken for ciphertext");
        assert_eq!(decrypt("correct horse", &blob).unwrap().as_slice(), plain);
    }

    #[test]
    fn a_wrong_passphrase_and_a_tamper_are_both_refused() {
        let blob = encrypt("right", b"secret keys").unwrap();

        let err = decrypt("wrong", &blob).unwrap_err();
        assert!(
            err.contains("wrong passphrase") || err.contains("modified"),
            "{err}"
        );

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decrypt("right", &tampered).is_err());

        // A truncated file is refused before any crypto runs.
        assert!(decrypt("right", &blob[..MAGIC.len() + 2]).is_err());
        // And a plaintext file is not silently "decrypted".
        assert!(decrypt("right", b"[{\"label\":\"x\"}]").is_err());
    }

    #[test]
    fn every_write_uses_a_fresh_salt_and_nonce() {
        let a = encrypt("p", b"same bytes").unwrap();
        let b = encrypt("p", b"same bytes").unwrap();
        assert_ne!(a, b, "identical plaintext must not produce identical bytes");
    }

    #[test]
    fn write_private_leaves_no_temp_file_and_replaces_atomically() {
        let dir =
            std::env::temp_dir().join(format!("srct-wallet-store-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallets.json");

        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(
            !path.with_file_name("wallets.json.tmp").exists(),
            "the temp file must not survive the rename"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "wallet file must not be group- or world-accessible"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
