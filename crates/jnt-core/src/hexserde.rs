//! Hex-string serde adapters for fixed-size byte arrays.
//!
//! `serde` only derives for arrays up to 32 elements, and every hash-like field
//! here is 32, 33 or 64 bytes. Rather than widen the types or add a dependency,
//! these adapters serialize fixed arrays as hex strings — which also makes the
//! node's JSON files readable.

use serde::{de, Deserialize, Deserializer, Serializer};

macro_rules! hex_mod {
    ($name:ident, $n:expr) => {
        pub mod $name {
            use super::*;

            pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let raw = String::deserialize(d)?;
                let bytes = hex::decode(raw.trim()).map_err(de::Error::custom)?;
                if bytes.len() != $n {
                    return Err(de::Error::custom(concat!(
                        "expected ",
                        stringify!($n),
                        " bytes of hex"
                    )));
                }
                let mut out = [0u8; $n];
                out.copy_from_slice(&bytes);
                Ok(out)
            }
        }
    };
}

hex_mod!(h16, 16);
hex_mod!(h20, 20);
hex_mod!(h32, 32);
hex_mod!(h33, 33);
hex_mod!(h64, 64);

/// Variable-length byte vectors, serialized as hex strings.
///
/// Needed by the signature bundles: a post-quantum component is ~2.4 KB, which
/// no fixed-size adapter covers, and hex keeps the node's JSON export readable.
pub mod var_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(d)?;
        hex::decode(raw.trim()).map_err(de::Error::custom)
    }
}
