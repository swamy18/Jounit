//! Length-prefixed frame codec. SPEC.md §13.2.
//!
//! ```text
//! frame = magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload(payload_len)
//! ```
//!
//! Two rules from the spec are non-negotiable here, and both are enforced in
//! this module:
//!
//! 1. `payload_len` is checked against `MAX_FRAME_PAYLOAD` **before** any
//!    allocation. The length prefix is attacker-controlled, which is the same
//!    class of bug as the bundle-length and input-count defects already fixed
//!    in `SPEC.md §3.1/§3.5`; the same discipline applies here.
//! 2. A frame larger than the cap closes the connection rather than being
//!    skipped. There is no resynchronisation point in a stream protocol, so
//!    skipping leaves the peer able to confuse every later message.

use std::io::{Read, Write};

use crate::error::{NetError, NetResult};
use jnt_core::params::NetworkParams;
use jnt_core::ser::Writer;

/// `max_block_bytes` (4 000 000) plus headroom for the frame envelope and the
/// largest legal `GETBLOCKS`/`INV` payloads. A `BLOCK` frame carrying a
/// maximum-size block is always within this cap.
pub const MAX_FRAME_PAYLOAD: u32 = 4_100_000;

/// Write one complete, self-delimiting frame to anything that is `Write`.
///
/// The magic is taken from the node's own `NetworkParams`, so a mismatch on the
/// receiving end is caught at the first byte — including on frames sent *after*
/// the handshake, which stops a peer from switching networks mid-session.
pub fn write_frame<W: Write>(
    w: &mut W,
    params: &NetworkParams,
    msg_type: u8,
    payload: &[u8],
) -> NetResult<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        NetError::Protocol(format!(
            "payload too large to frame: {} bytes",
            payload.len()
        ))
    })?;
    let mut buf = Writer::with_capacity(4 + 1 + 4 + payload.len());
    buf.raw(&params.network_magic).u8(msg_type).u32le(len);
    let head: &[u8] = buf.as_slice();
    w.write_all(head)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read and validate exactly one frame from a stream.
///
/// Returns `(msg_type, payload)` with `payload` already bounded to
/// `MAX_FRAME_PAYLOAD` bytes, allocated exactly once. A violating length is
/// rejected before `payload` is ever read, so a peer cannot force an
/// oversized allocation.
pub fn read_frame<R: Read>(r: &mut R, params: &NetworkParams) -> NetResult<(u8, Vec<u8>)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(truncated("magic"))?;
    if magic != params.network_magic {
        // Checked on EVERY frame, not only at handshake. A peer that starts on
        // the right network and then spews garbage is caught here.
        return Err(NetError::InvalidMagic {
            got: magic,
            want: params.network_magic,
        });
    }

    let mut type_buf = [0u8; 1];
    r.read_exact(&mut type_buf).map_err(truncated("msg_type"))?;
    let msg_type = type_buf[0];

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(truncated("payload_len"))?;
    let payload_len = u32::from_le_bytes(len_buf);
    if payload_len > MAX_FRAME_PAYLOAD {
        // Deliberately reject rather than skip. Skipping desynchronises the
        // stream; the only safe action on a frame that cannot fit is to close.
        return Err(NetError::OversizedFrame { len: payload_len });
    }

    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        r.read_exact(&mut payload).map_err(truncated("payload"))?;
    }

    Ok((msg_type, payload))
}

fn truncated(what: &'static str) -> impl Fn(std::io::Error) -> NetError {
    move |e| trunc(e, what)
}

fn trunc(e: std::io::Error, what: &str) -> NetError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        NetError::Truncated(what.to_string())
    } else {
        NetError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jnt_core::ser::Reader;
    use std::io::Cursor;

    #[test]
    fn round_trip_is_bytes() {
        let p = NetworkParams::mini();
        let payload = b"hello world".to_vec();
        let mut wire = Cursor::new(Vec::new());
        write_frame(&mut wire, &p, 7, &payload).unwrap();
        wire.set_position(0);
        let (ty, got) = read_frame(&mut wire, &p).unwrap();
        assert_eq!(ty, 7);
        assert_eq!(got, payload);
    }

    #[test]
    fn rejects_oversized_length_before_allocating() {
        let p = NetworkParams::mini();
        // A length that lies far past the cap: the read must reject without
        // reading `payload_len` bytes of payload, i.e. without allocating.
        let wire = {
            let mut w = Writer::new();
            w.raw(&p.network_magic).u8(7).u32le(MAX_FRAME_PAYLOAD + 1);
            w.into_vec()
        };
        let mut cursor = Cursor::new(wire);
        match read_frame(&mut cursor, &p) {
            Err(NetError::OversizedFrame { len }) => {
                assert_eq!(len, MAX_FRAME_PAYLOAD + 1);
            }
            other => panic!("expected OversizedFrame, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_magic() {
        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&[0xFF, 0xFF, 0xFF, 0xFF]).u8(7).u32le(0);
        let mut cursor = Cursor::new(w.into_vec());
        assert!(matches!(
            read_frame(&mut cursor, &p),
            Err(NetError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let p = NetworkParams::mini();
        let mut w = Writer::new();
        w.raw(&p.network_magic).u8(7).u32le(10).raw(&[0u8; 4]);
        let mut cursor = Cursor::new(w.into_vec());
        assert!(matches!(
            read_frame(&mut cursor, &p),
            Err(NetError::Truncated(_))
        ));
    }

    // The Reader is the same one `jnt_core`'s own serializers use, and the
    // `u16le` writer I added must agree with `Reader::u16le`.
    #[test]
    fn u16le_round_trips() {
        let mut w = Writer::new();
        w.u16le(0x0301);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.u16le().unwrap(), 0x0301);
        assert!(r.expect_end().is_ok());
    }
}
