//! Canonical byte-level serialization. SPEC.md §3.
//!
//! Every multi-byte integer carries an explicit endianness marker; every fixed
//! array is written raw. `Reader` fails loudly rather than panicking, so a
//! malformed block can never abort a node.

use crate::error::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32le(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64le(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u128le(&mut self, v: u128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn fixed<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_done(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Malformed("unexpected end of buffer"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32le(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn u64le(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        Ok(u64::from_le_bytes(b))
    }

    pub fn u128le(&mut self) -> Result<u128> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(u128::from_le_bytes(b))
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub fn expect_end(&self) -> Result<()> {
        if self.is_done() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes after object"))
        }
    }
}
