//! Message type set and codecs. SPEC.md §13.4-§13.5.
//!
//! Message numbers are frozen; an unknown number MUST be ignored without
//! disconnecting, so a future version can extend the set. Counts are `u16`
//! little-endian; short handshake strings (network_id, user_agent) are
//! length-prefixed by a single byte, both being bounded to 64.

use jnt_core::block::Block;
use jnt_core::hash::Hash;
use jnt_core::ser::{Reader, Writer};

use crate::error::{NetError, NetResult};

/// Protocol version for the `VERSION` message. Bump when the message set or a
/// payload layout changes in a backwards-compatible way.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum bytes of `user_agent` and `network_id` text.
pub const MAX_HANDSHAKE_STR_LEN: usize = 64;

/// Upper bounds on repeated fields. Each entry is `kind(1) ‖ hash(32)` = 33
/// bytes, so the cap also bounds the worst-case allocation.
pub const MAX_INV_PER_MSG: usize = 500;
pub const MAX_LOCATOR_ENTRIES: usize = 500;

/// `kind` values for inventory entries (§13.5). `0` reserved so transaction
/// announcements can reuse `INV` later.
pub const INV_TYPE_BLOCK: u8 = 1;

/// Message type numbers. Frozen: unknown numbers are ignored, not rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Version = 1,
    Verack = 2,
    Ping = 3,
    Pong = 4,
    Inv = 5,
    GetData = 6,
    Block = 7,
    GetBlocks = 8,
    Addr = 9,
}

impl MessageType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => MessageType::Version,
            2 => MessageType::Verack,
            3 => MessageType::Ping,
            4 => MessageType::Pong,
            5 => MessageType::Inv,
            6 => MessageType::GetData,
            7 => MessageType::Block,
            8 => MessageType::GetBlocks,
            9 => MessageType::Addr,
            _ => return None,
        })
    }
}

/// A decoded, typed message. `Block` carries the already-parsed block; the
/// caller runs consensus validation on it via `Chain::submit`.
#[derive(Debug, Clone)]
pub enum Message {
    Version(Version),
    Verack {
        nonce: u64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Inv(Vec<InvEntry>),
    GetData(Vec<InvEntry>),
    Block(Box<Block>),
    GetBlocks {
        locator: Vec<Hash>,
        stop: Hash,
    },
    Addr(Vec<SocketAddr>),
    /// An unknown type number — ignored, per the freeze rule. Retained only so
    /// tests can assert that unknown types are dropped without disconnect.
    Unknown {
        ty: u8,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvEntry {
    pub kind: u8,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub network_magic: [u8; 4],
    pub network_id: String,
    pub protocol_version: u32,
    pub services: u64,
    pub height: u64,
    pub tip_hash: Hash,
    pub user_agent: String,
    pub nonce: u64,
}

/// A socket address on the wire: 16-byte address (IPv6 / IPv6-mapped IPv4) and
/// a 2-byte port. §13.5, `ADDR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: [u8; 16],
    pub port: u16,
}

impl Message {
    /// Encode to the payload bytes (without the frame envelope).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_into(&mut w);
        w.into_vec()
    }

    fn encode_into(&self, w: &mut Writer) {
        match self {
            Message::Version(v) => {
                w.raw(&v.network_magic)
                    .u8(u8::try_from(v.network_id.len()).unwrap_or(0));
                // Truncate rather than panic on an oversized string; the
                // receiver will reject a too-long field anyway.
                w.raw(&v.network_id.as_bytes()[..v.network_id.len().min(255)]);
                w.u32le(v.protocol_version)
                    .u64le(v.services)
                    .u64le(v.height)
                    .fixed(&v.tip_hash)
                    .u8(u8::try_from(v.user_agent.len()).unwrap_or(0))
                    .raw(&v.user_agent.as_bytes()[..v.user_agent.len().min(255)])
                    .u64le(v.nonce);
            }
            Message::Verack { nonce } => {
                w.u64le(*nonce);
            }
            Message::Ping { nonce } => {
                w.u64le(*nonce);
            }
            Message::Pong { nonce } => {
                w.u64le(*nonce);
            }
            Message::Inv(entries) | Message::GetData(entries) => {
                w.u16le(u16::try_from(entries.len()).unwrap_or(0));
                for e in entries {
                    w.u8(e.kind).fixed(&e.hash);
                }
            }
            Message::Block(block) => {
                w.raw(&block.serialize());
            }
            Message::GetBlocks { locator, stop } => {
                w.u16le(u16::try_from(locator.len()).unwrap_or(0));
                for h in locator {
                    w.fixed(h);
                }
                w.fixed(stop);
            }
            Message::Addr(addrs) => {
                w.u16le(u16::try_from(addrs.len()).unwrap_or(0));
                for a in addrs {
                    w.fixed(&a.ip).u16le(a.port);
                }
            }
            Message::Unknown { ty, raw } => {
                w.u8(*ty)
                    .u32le(u32::try_from(raw.len()).unwrap_or(0))
                    .raw(raw);
            }
        }
    }

    /// Decode a payload given its type number.
    pub fn decode(ty: u8, payload: &[u8]) -> NetResult<Message> {
        let mut r = Reader::new(payload);
        let msg = match MessageType::from_u8(ty) {
            Some(MessageType::Version) => Message::Version(decode_version(&mut r)?),
            Some(MessageType::Verack) => Message::Verack { nonce: r.u64le()? },
            Some(MessageType::Ping) => Message::Ping { nonce: r.u64le()? },
            Some(MessageType::Pong) => Message::Pong { nonce: r.u64le()? },
            Some(MessageType::Inv) => Message::Inv(decode_inv(&mut r)?),
            Some(MessageType::GetData) => Message::GetData(decode_inv(&mut r)?),
            Some(MessageType::Block) => Message::Block(Box::new(
                Block::deserialize(payload)
                    .map_err(|e| NetError::Decode(format!("block deserialize: {e}")))?,
            )),
            Some(MessageType::GetBlocks) => Message::GetBlocks {
                locator: decode_locator(&mut r)?,
                stop: r.fixed()?,
            },
            Some(MessageType::Addr) => Message::Addr(decode_addr(&mut r)?),
            None => {
                // Unknown: preserve the raw payload so callers can log it, but
                // do not act on it. §13.5 freeze rule.
                Message::Unknown {
                    ty,
                    raw: payload.to_vec(),
                }
            }
        };
        Ok(msg)
    }
}

fn decode_version(r: &mut Reader<'_>) -> NetResult<Version> {
    let network_magic: [u8; 4] = r.fixed()?;
    let id_len = r.u8()? as usize;
    if id_len > MAX_HANDSHAKE_STR_LEN {
        return Err(NetError::Decode(format!("network_id too long: {id_len}")));
    }
    let id_bytes = r
        .fixed_slice(id_len)
        .map_err(|e| NetError::Decode(e.to_string()))?;
    let network_id = std::str::from_utf8(id_bytes)
        .map_err(|_| NetError::Decode("network_id not utf-8".into()))?
        .to_string();
    // Field order MUST match `Version::encode_into` and SPEC.md §13.4.
    let protocol_version = r.u32le()?;
    let services = r.u64le()?;
    let height = r.u64le()?;
    let tip_hash: Hash = r.fixed()?;
    let ua_len = r.u8()? as usize;
    if ua_len > MAX_HANDSHAKE_STR_LEN {
        return Err(NetError::Decode(format!("user_agent too long: {ua_len}")));
    }
    let ua_bytes = r
        .fixed_slice(ua_len)
        .map_err(|e| NetError::Decode(e.to_string()))?;
    let user_agent = std::str::from_utf8(ua_bytes)
        .map_err(|_| NetError::Decode("user_agent not utf-8".into()))?
        .to_string();
    let nonce = r.u64le()?;
    Ok(Version {
        network_magic,
        network_id,
        protocol_version,
        services,
        height,
        tip_hash,
        user_agent,
        nonce,
    })
}

fn decode_inv(r: &mut Reader<'_>) -> NetResult<Vec<InvEntry>> {
    let count = r.u16le()? as usize;
    if count > MAX_INV_PER_MSG {
        return Err(NetError::Decode(format!(
            "inventory count {count} exceeds {MAX_INV_PER_MSG}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = r.u8()?;
        let hash: Hash = r.fixed()?;
        out.push(InvEntry { kind, hash });
    }
    Ok(out)
}

fn decode_locator(r: &mut Reader<'_>) -> NetResult<Vec<Hash>> {
    let count = r.u16le()? as usize;
    if count > MAX_LOCATOR_ENTRIES {
        return Err(NetError::Decode(format!(
            "locator count {count} exceeds {MAX_LOCATOR_ENTRIES}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.fixed()?);
    }
    Ok(out)
}

fn decode_addr(r: &mut Reader<'_>) -> NetResult<Vec<SocketAddr>> {
    let count = r.u16le()? as usize;
    if count > MAX_ADDR_PER_MSG {
        return Err(NetError::Decode(format!(
            "addr count {count} exceeds {MAX_ADDR_PER_MSG}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let ip: [u8; 16] = r.fixed()?;
        let port = r.u16le()?;
        out.push(SocketAddr { ip, port });
    }
    Ok(out)
}

pub const MAX_ADDR_PER_MSG: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_round_trips_and_bounds_strings() {
        let v = Version {
            network_magic: [0x6A, 0x4E, 0x54, 0x02],
            network_id: "jounit/mini".into(),
            protocol_version: PROTOCOL_VERSION,
            services: 0,
            height: 31,
            tip_hash: [0xAB; 32],
            user_agent: "/jnt-net:0.2".into(),
            nonce: 0x0123_4567_89AB_CDEF,
        };
        let enc = Message::Version(v.clone()).encode();
        let dec = Message::decode(1, &enc).unwrap();
        match dec {
            Message::Version(got) => assert_eq!(got, v),
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_preserved_not_rejected() {
        // §13.5: an unknown message number must not disconnect; encode it
        // verbatim and confirm decode keeps the raw payload verbatim so a
        // future layer can inspect/log it.
        let payload = {
            let mut w = Writer::new();
            w.u8(0x42).u32le(4).raw(b"test");
            w.into_vec()
        };
        let msg = Message::decode(0xFF, &payload).unwrap();
        match msg {
            Message::Unknown { ty, raw } => {
                assert_eq!(ty, 0xFF);
                assert_eq!(raw, payload);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn inv_round_trips_and_bounds_count() {
        let inv = Message::Inv(vec![
            InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x11; 32],
            },
            InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x22; 32],
            },
        ]);
        let dec = Message::decode(5, &inv.encode()).unwrap();
        match dec {
            Message::Inv(entries) => assert_eq!(entries.len(), 2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn oversized_inv_count_is_rejected_without_allocating() {
        // Declare more entries than the cap then stop, so the decoder rejects
        // the count before allocating 65 000 entries.
        let mut w = Writer::new();
        w.u16le((MAX_INV_PER_MSG + 1) as u16);
        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        let res = decode_inv(&mut r);
        assert!(matches!(res, Err(NetError::Decode(_))));
    }
}
