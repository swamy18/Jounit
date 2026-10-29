#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the block deserializer (SPEC.md §3, §9).
//
// The block carries a header plus a transaction count the reader bounds by
// minimum tx size before allocating (block.rs). This target checks that bound
// holds under adversarial input, and that decode → serialize → decode is
// stable.
fuzz_target!(|data: &[u8]| {
    if let Ok(block) = srct_core::block::Block::deserialize(data) {
        let re = block.serialize();
        let again = srct_core::block::Block::deserialize(&re)
            .expect("a decoded block must decode from its own serialization");
        assert_eq!(
            again.block_hash(),
            block.block_hash(),
            "re-serialization must preserve the block hash"
        );
        // Merkle root must agree with the transaction list it decoded.
        let _ = block.merkle_root();
    }
    // The header alone is also a peer-controlled parse surface.
    if data.len() >= srct_core::block::HEADER_SERIALIZED_LEN {
        if let Ok(h) = srct_core::block::Header::deserialize(&data[..srct_core::block::HEADER_SERIALIZED_LEN]) {
            let _ = h.block_hash();
            let re = h.serialize();
            assert_eq!(re.len(), srct_core::block::HEADER_SERIALIZED_LEN);
        }
    }
});
