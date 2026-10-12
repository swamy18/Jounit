use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

/// All-zero hash: the placeholder identity used by `NoCreditGate` (no position
/// id, no reserved debit). Not a valid position id, by construction.
pub const ZERO_HASH: Hash = [0u8; 32];

/// Domain-separation tags. Frozen; the `/v1` suffix must never be reused by a
/// different construction. See SPEC.md §0.
pub const DOM_BLOCK: &[u8] = b"jounit/blockhash/v1";
pub const DOM_TX: &[u8] = b"jounit/txid/v1";
pub const DOM_TXBODY: &[u8] = b"jounit/txbody/v1";
pub const DOM_SIG: &[u8] = b"jounit/sig/v1";
pub const DOM_ADDR: &[u8] = b"jounit/addr/v2";
pub const DOM_S1: &[u8] = b"jounit/puzzle/stage1/v1";
pub const DOM_S2: &[u8] = b"jounit/puzzle/stage2/v1";
pub const DOM_S3: &[u8] = b"jounit/puzzle/stage3/v1";
pub const DOM_W: &[u8] = b"jounit/puzzle/weights/v1";

pub const SIG_SCHEME_SECP256K1_ECDSA: u8 = 1;

/// SHA-256 over a domain tag followed by a concatenation of byte slices.
pub fn sha256_dom(dom: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(dom);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha256(parts: &[&[u8]]) -> Hash {
    sha256_dom(&[], parts)
}

/// Single-key address derivation, for the common case of an ECDSA-only bundle.
///
/// Equivalent to `Bundle::single(SCHEME_SECP256K1_ECDSA, pubkey).address()`.
/// Kept so callers that genuinely hold one key do not have to build a bundle.
pub fn address_from_pubkey(pubkey: &[u8; 33]) -> Address {
    crate::sig::Bundle::single(crate::sig::SCHEME_SECP256K1_ECDSA, pubkey.to_vec())
        .address()
        .expect("a single ECDSA bundle is always structurally valid")
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).map_err(|_| Error::Malformed("invalid hex string"))
}

pub fn hash_to_hex(h: &Hash) -> String {
    to_hex(h)
}

pub fn hash_from_hex(s: &str) -> Result<Hash> {
    let v = from_hex(s)?;
    if v.len() != 32 {
        return Err(Error::BadLength {
            expected: 32,
            got: v.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn address_to_hex(a: &Address) -> String {
    format!("jt1{}", to_hex(a))
}

pub fn address_from_hex(s: &str) -> Result<Address> {
    let s = s.trim().strip_prefix("jt1").unwrap_or(s.trim());
    let v = from_hex(s)?;
    if v.len() != 20 {
        return Err(Error::BadLength {
            expected: 20,
            got: v.len(),
        });
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    Ok(out)
}
