//! Block header, block, merkle root and the genesis block. SPEC.md §2, §3.4-§3.5, §11.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::{sha256, sha256_dom, Hash, DOM_BLOCK};
use crate::ser::{Reader, Writer};
use crate::tx::{Output, Transaction, TX_COINBASE};

pub const HEADER_SERIALIZED_LEN: usize = 145;
pub const BLOCK_VERSION: u32 = 1;

/// Frozen genesis timestamp: 2026-01-01T00:00:00Z.
///
/// It must be a realistic time, not zero: the median-time rule anchors on it, so
/// a zero genesis would make the first blocks unsatisfiable.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_767_225_600_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub height: u64,
    #[serde(with = "crate::hexserde::h32")]
    pub prev_hash: Hash,
    #[serde(with = "crate::hexserde::h32")]
    pub merkle_root: Hash,
    pub timestamp_ms: u64,
    pub base_fee_sat: u64,
    pub difficulty: u128,
    pub nonce: u64,
    pub puzzle_id: u64,
    pub epoch_id: u32,
    #[serde(with = "crate::hexserde::h16")]
    pub extra_nonce: [u8; 16],
    pub sig_scheme: u8,
}

impl Header {
    pub fn genesis(merkle_root: Hash, difficulty: u128) -> Self {
        let mut extra = [0u8; 16];
        extra[..14].copy_from_slice(b"jounit-genesis");
        Header {
            version: BLOCK_VERSION,
            height: 0,
            prev_hash: [0u8; 32],
            merkle_root,
            timestamp_ms: GENESIS_TIMESTAMP_MS,
            base_fee_sat: 0,
            difficulty,
            nonce: 0,
            puzzle_id: 1,
            epoch_id: 0,
            extra_nonce: extra,
            sig_scheme: crate::hash::SIG_SCHEME_SECP256K1_ECDSA,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(HEADER_SERIALIZED_LEN);
        w.u32le(self.version)
            .u64le(self.height)
            .fixed(&self.prev_hash)
            .fixed(&self.merkle_root)
            .u64le(self.timestamp_ms)
            .u64le(self.base_fee_sat)
            .u128le(self.difficulty)
            .u64le(self.nonce)
            .u64le(self.puzzle_id)
            .u32le(self.epoch_id)
            .fixed(&self.extra_nonce)
            .u8(self.sig_scheme);
        debug_assert_eq!(w.len(), HEADER_SERIALIZED_LEN);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SERIALIZED_LEN {
            return Err(Error::BadLength {
                expected: HEADER_SERIALIZED_LEN,
                got: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let h = Header {
            version: r.u32le()?,
            height: r.u64le()?,
            prev_hash: r.fixed()?,
            merkle_root: r.fixed()?,
            timestamp_ms: r.u64le()?,
            base_fee_sat: r.u64le()?,
            difficulty: r.u128le()?,
            nonce: r.u64le()?,
            puzzle_id: r.u64le()?,
            epoch_id: r.u32le()?,
            extra_nonce: r.fixed()?,
            sig_scheme: r.u8()?,
        };
        r.expect_end()?;
        Ok(h)
    }

    pub fn block_hash(&self) -> Hash {
        sha256_dom(DOM_BLOCK, &[&self.serialize()])
    }

    pub fn expected_epoch(&self, nn_epoch_blocks: u64) -> u32 {
        // Clamped rather than truncated: `height / nn_epoch_blocks` exceeds
        // `u32::MAX` past ~2.1e14 blocks, and a silent `as u32` wrap would make
        // the epoch check disagree with itself.
        (self.height / nn_epoch_blocks).min(u32::MAX as u64) as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    #[serde(with = "crate::hexserde::h64")]
    pub signature: [u8; 64],
    #[serde(with = "crate::hexserde::h33")]
    pub signer_pubkey: [u8; 33],
    pub txs: Vec<Transaction>,
}

impl Block {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.header.serialize().len() + 512);
        w.raw(&self.header.serialize())
            .fixed(&self.signature)
            .fixed(&self.signer_pubkey)
            .u32le(self.txs.len() as u32);
        for tx in &self.txs {
            w.raw(&tx.serialize());
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SERIALIZED_LEN {
            return Err(Error::Malformed("block shorter than header"));
        }
        let header = Header::deserialize(&bytes[..HEADER_SERIALIZED_LEN])?;
        let mut r = Reader::new(&bytes[HEADER_SERIALIZED_LEN..]);
        let signature = r.fixed()?;
        let signer_pubkey = r.fixed()?;
        let n = r.u32le()? as usize;
        // Bounded by the smallest a transaction can be, not by the raw byte
        // count, so a small buffer cannot force a large reservation.
        if n > r.remaining() / crate::tx::TX_MIN_SERIALIZED_LEN {
            return Err(Error::Malformed("tx_count exceeds buffer"));
        }
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            let tx = Transaction::from_reader(&mut r)?;
            txs.push(tx);
        }
        r.expect_end()?;
        Ok(Block {
            header,
            signature,
            signer_pubkey,
            txs,
        })
    }

    pub fn block_hash(&self) -> Hash {
        self.header.block_hash()
    }

    pub fn merkle_root(&self) -> Hash {
        merkle_root(&self.txs)
    }

    /// Gas for the whole block.
    ///
    /// Checked, not `.sum()`: `sum` panics on overflow in debug and wraps in
    /// release, and this feeds the base-fee schedule and the gas cap. A node
    /// reading blocks from a file or the network must not be crashable by one.
    pub fn total_gas_used(&self) -> Result<u64> {
        self.txs.iter().try_fold(0u64, |acc, t| {
            acc.checked_add(t.gas_used()).ok_or(Error::ValueOverflow)
        })
    }
}

const LEAF_TAG: u8 = 0x00;
const INTERNAL_TAG: u8 = 0x01;

/// Binary merkle root with domain-separated leaves and internal nodes.
/// Odd nodes are duplicated, Bitcoin-style. SPEC.md §2.
pub fn merkle_root(txs: &[Transaction]) -> Hash {
    if txs.is_empty() {
        // A valid block always carries a coinbase, so this is unreachable in
        // consensus; defined anyway so the function is total.
        return [0u8; 32];
    }
    let mut level: Vec<Hash> = txs
        .iter()
        .map(|t| sha256(&[&[LEAF_TAG], &t.serialize()]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(sha256(&[&[INTERNAL_TAG], &pair[0], &pair[0]]));
            } else {
                next.push(sha256(&[&[INTERNAL_TAG], &pair[0], &pair[1]]));
            }
        }
        level = next;
    }
    level[0]
}

/// The canonical genesis block. Contains zero value and no spendable output:
/// the 0% premine promised in the design doc (Section 16) is enforced by code.
pub fn genesis_block(difficulty: u128) -> Block {
    let coinbase = Transaction::coinbase(
        [0u8; 32],
        0,
        Output {
            value: 0,
            address: [0u8; 20],
        },
    );
    debug_assert!(coinbase.is_coinbase());
    let header = Header::genesis(merkle_root(std::slice::from_ref(&coinbase)), difficulty);
    Block {
        header,
        signature: [0u8; 64],
        signer_pubkey: [0u8; 33],
        txs: vec![coinbase],
    }
}

pub fn is_genesis_shape_ok(block: &Block) -> bool {
    block.txs.len() == 1
        && block.txs[0].tx_type == TX_COINBASE
        && block.txs[0].outputs[0].value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Input;

    fn tx_with_tag(tag: u8) -> Transaction {
        Transaction::standard(
            vec![Input::unsigned(&crate::tx::OutPoint {
                txid: [tag; 32],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [tag; 20],
            }],
        )
    }

    #[test]
    fn header_is_exactly_145_bytes_and_roundtrips() {
        let g = genesis_block(1);
        let bytes = g.header.serialize();
        assert_eq!(bytes.len(), HEADER_SERIALIZED_LEN);
        assert_eq!(Header::deserialize(&bytes).unwrap(), g.header);
    }

    #[test]
    fn header_hash_is_domain_separated() {
        let g = genesis_block(1);
        assert_eq!(
            g.header.block_hash(),
            sha256_dom(DOM_BLOCK, &[&g.header.serialize()])
        );
        assert_ne!(g.header.block_hash(), sha256(&[&g.header.serialize()]));
    }

    #[test]
    fn block_roundtrips() {
        let mut g = genesis_block(1);
        g.txs.push(tx_with_tag(3));
        g.header.merkle_root = g.merkle_root();
        let bytes = g.serialize();
        assert_eq!(Block::deserialize(&bytes).unwrap(), g);
    }

    #[test]
    fn block_hash_commits_to_the_merkle_root_not_the_tx_list() {
        let g1 = genesis_block(1);
        let mut g2 = genesis_block(1);
        g2.txs.push(tx_with_tag(9));
        // The header is what gets hashed, so an unchanged header means an
        // unchanged block hash even though the tx list differs. In practice the
        // merkle root inside the header is what binds the two.
        g2.header.merkle_root = g2.merkle_root();
        assert_eq!(g1.block_hash(), g1.block_hash());
        assert_ne!(g1.merkle_root(), g2.merkle_root());
        assert_ne!(g1.block_hash(), g2.block_hash());
    }

    #[test]
    fn merkle_single_tx_is_the_leaf() {
        let t = tx_with_tag(1);
        let leaf = sha256(&[&[LEAF_TAG], &t.serialize()]);
        assert_eq!(merkle_root(&[t]), leaf);
    }

    #[test]
    fn merkle_duplicate_last_for_odd_count() {
        let a = tx_with_tag(1);
        let b = tx_with_tag(2);
        let c = tx_with_tag(3);
        let la = sha256(&[&[LEAF_TAG], &a.serialize()]);
        let lb = sha256(&[&[LEAF_TAG], &b.serialize()]);
        let lc = sha256(&[&[LEAF_TAG], &c.serialize()]);
        let left = sha256(&[&[INTERNAL_TAG], &la, &lb]);
        let right = sha256(&[&[INTERNAL_TAG], &lc, &lc]);
        assert_eq!(
            merkle_root(&[a, b, c]),
            sha256(&[&[INTERNAL_TAG], &left, &right])
        );
    }

    #[test]
    fn genesis_mints_nothing() {
        let g = genesis_block(1);
        assert!(is_genesis_shape_ok(&g));
        assert_eq!(g.txs[0].value_out(), 0);
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.difficulty, 1);
        assert_eq!(g.header.prev_hash, [0u8; 32]);
        assert_eq!(g.header.merkle_root, g.merkle_root());
    }

    #[test]
    fn expected_epoch_follows_height() {
        let mut h = Header::genesis([0u8; 32], 1);
        assert_eq!(h.expected_epoch(50_000), 0);
        h.height = 49_999;
        assert_eq!(h.expected_epoch(50_000), 0);
        h.height = 50_000;
        assert_eq!(h.expected_epoch(50_000), 1);
        h.height = 120_000;
        assert_eq!(h.expected_epoch(50_000), 2);
    }

    // --- Properties -------------------------------------------------------
    //
    // A node parses bytes it did not produce, so every deserializer has to
    // reject hostile input by returning an error, never by panicking. There is
    // no fuzz harness here yet, so these properties run over a deterministic
    // spread of adversarial shapes instead of random bytes only: truncated
    // buffers, count fields claiming more entries than the buffer holds, and
    // length-prefix fields pinned to their extremes.

    /// Deterministic pseudo-random bytes, so a failure is reproducible from
    /// the seed alone rather than needing the original fuzz corpus.
    fn pseudo_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                // xorshift64*, chosen for being short and obviously
                // deterministic rather than for quality.
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_deserializers() {
        for seed in 0..256u64 {
            let len = (seed as usize * 37) % 400;
            let bytes = pseudo_bytes(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), len);
            // The only requirement is that these return rather than panic.
            let _ = Block::deserialize(&bytes);
            let _ = Header::deserialize(&bytes);
            let _ = Transaction::deserialize(&bytes);
        }
    }

    #[test]
    fn every_truncation_of_a_valid_block_is_rejected_not_panicked() {
        let mut b = genesis_block(1);
        b.header.height = 1;
        b.header.prev_hash = [7u8; 32];
        b.header.timestamp_ms = GENESIS_TIMESTAMP_MS + 600_000;
        b.header.difficulty = 1;
        b.header.nonce = 1;
        let full = b.serialize();

        // Any prefix short of the whole thing must fail cleanly.
        for cut in 0..full.len() {
            assert!(
                Block::deserialize(&full[..cut]).is_err(),
                "a {cut}-byte prefix of a {}-byte block was accepted",
                full.len()
            );
        }
        // And trailing junk must fail rather than be ignored.
        let mut extended = full.clone();
        extended.push(0xAB);
        assert!(Block::deserialize(&extended).is_err());
    }

    #[test]
    fn a_count_field_cannot_claim_more_entries_than_the_buffer_holds() {
        // header + signature + pubkey, then a tx_count of u32::MAX against a
        // buffer with nothing after it. Without the remaining-buffer check
        // this would try to reserve four billion entries.
        let mut b = genesis_block(1);
        b.txs.clear();
        let mut bytes = b.serialize();
        bytes.truncate(HEADER_SERIALIZED_LEN + 64 + 33);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            Block::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));

        // Same shape one level down, inside a transaction. The count fields are
        // hand-assembled because `Transaction::standard` would refuse the
        // empty input and output lists this needs.
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u32.to_le_bytes()); // version
        raw.push(crate::tx::TX_STANDARD);
        raw.extend_from_slice(&0u64.to_le_bytes()); // lock_time
        raw.extend_from_slice(&u32::MAX.to_le_bytes()); // input_count
        raw.extend_from_slice(&u32::MAX.to_le_bytes()); // output_count
        assert!(Transaction::deserialize(&raw).is_err());
    }

    #[test]
    fn serialization_round_trips_bit_for_bit() {
        let b = genesis_block(1);
        let bytes = b.serialize();
        let back = Block::deserialize(&bytes).unwrap();
        assert_eq!(back.serialize(), bytes, "block round-trip is not stable");
        assert_eq!(back.block_hash(), b.block_hash());

        let tx = &b.txs[0];
        let raw = tx.serialize();
        assert_eq!(Transaction::deserialize(&raw).unwrap(), *tx);
    }

    #[test]
    fn serialization_is_injective_for_every_output_value() {
        // Distinct value/address pairs must not collide on the wire, which is
        // what makes the coinbase value check in apply_block meaningful.
        let mut seen = std::collections::HashSet::new();
        for v in [0u64, 1, 76 * 100_000_000, u64::MAX - 1, u64::MAX] {
            let out = crate::tx::Output {
                value: v,
                address: [0xABu8; 20],
            };
            let bytes = out.to_bytes();
            assert!(
                seen.insert(bytes),
                "output value {v} collided with another on the wire"
            );
        }
    }
}
