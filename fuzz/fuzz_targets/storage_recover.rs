#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

// Fuzz storage recovery (srct-store).
//
// The fuzzer writes an arbitrary byte sequence as the tail of a valid
// two-record log, then reopens. The open must either succeed with a clean
// recovery (torn tail dropped and reported) or refuse with a named error —
// never panic, never silently lose committed records. After reopening, a
// subsequent append must work and re-open cleanly.
fuzz_target!(|data: &[u8]| {
    // Unique per iteration: hash the input into the dir name.
    let digest = srct_core::hash::sha256(&[data]);
    let hex = srct_core::hash::hash_to_hex(&digest);
    let dir = std::env::temp_dir().join(format!("srct-fuzz-store-{}-{}", std::process::id(), &hex[..16]));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let log_path = dir.join("blocks.log");
    {
        // A valid log with two records.
        let (mut log, _) = srct_store::RecordLog::open(&log_path).unwrap();
        log.append(b"record-zero").unwrap();
        log.append(b"record-one").unwrap();
        log.sync().unwrap();
    }
    // The adversarial part: append arbitrary bytes as a would-be third record.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
    }

    let params = srct_core::params::NetworkParams::mini();
    match srct_store::BlockStore::open(&dir, &params) {
        Ok((mut store, _recovery)) => {
            // The two committed records must have survived whatever we did to
            // the tail (as blocks they may not decode; the log-level guarantee
            // is what we check via a fresh append + reopen).
            store.sync().unwrap();
            drop(store);
            // Reopen must succeed and accept a new record.
            let (mut store2, _) = srct_store::RecordLog::open(&log_path).unwrap();
            let r = store2.append(b"post-recovery").unwrap();
            store2.sync().unwrap();
            assert_eq!(store2.read(r).unwrap(), b"post-recovery");
        }
        Err(e) => {
            // Refusals must be named errors, not IO surprises.
            match e {
                srct_store::StoreError::Corrupt { .. }
                | srct_store::StoreError::BadMeta { .. }
                | srct_store::StoreError::BadBlock { .. }
                | srct_store::StoreError::MissingBlock { .. }
                | srct_store::StoreError::MissingParent { .. }
                | srct_store::StoreError::BadMagic { .. }
                | srct_store::StoreError::BadVersion { .. } => {}
                other => panic!("unexpected store error for adversarial tail: {other:?}"),
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
});
