#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the store's metadata parser (jnt-store meta.rs).
//
// `MetaFile::load` reads a text file an operator or a crash may have damaged.
// The parser must return None (absent), Some (valid), or a named BadMeta
// error — never panic, never accept a body whose checksum does not match,
// never accept a structurally impossible metadata (height 0 with non-genesis
// tip).
fuzz_target!(|data: &[u8]| {
    let hex = jnt_core::hash::hash_to_hex(&jnt_core::hash::sha256(&[data]));
    let dir = std::env::temp_dir().join(format!("jnt-fuzz-meta-{}", &hex[..16]));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("meta.json");
    std::fs::write(&path, data).unwrap();

    let mf = jnt_store::MetaFile::new(&path);
    match mf.load() {
        Ok(None) => {}
        Ok(Some(meta)) => {
            // Structural invariants of anything the parser accepts:
            if meta.height == 0 {
                assert_eq!(
                    meta.tip, meta.genesis,
                    "accepted metadata: height 0 must mean genesis tip"
                );
            }
            // M5 finality fields (Decision 12): their pairing invariants hold
            // for every accepted file, present or absent (absent parses as the
            // zero pair).
            if meta.finalized_height == 0 {
                assert_eq!(
                    meta.finalized_hash, [0u8; 32],
                    "no finalized height must mean no finalized hash"
                );
            } else {
                assert_ne!(
                    meta.finalized_hash, [0u8; 32],
                    "a finalized height must carry its hash"
                );
                assert!(
                    meta.finalized_height <= meta.height,
                    "finalized height cannot exceed the tip"
                );
            }
            // Round-trip: whatever parses must re-render and re-parse identically.
            mf.save(&meta).unwrap();
            let reparsed = mf.load().unwrap().expect("saved metadata must reload");
            assert_eq!(reparsed, meta, "render/parse round-trip must be identity");
        }
        Err(jnt_store::StoreError::BadMeta { .. }) => {}
        Err(e) => panic!("metadata parser returned an unexpected error class: {e:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
});
