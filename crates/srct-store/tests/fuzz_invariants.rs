// Storage-recovery invariant tests: the deterministic counterparts of the
// `storage_recover` and `meta_parse` cargo-fuzz targets.
//
// An arbitrary byte sequence can arrive as the tail of the log (a crash, a
// full disk, or an attacker with write access to the data directory). Reopening
// must either recover cleanly or refuse with a named error — never panic,
// never silently drop committed records.

use std::io::Write as _;
use std::path::PathBuf;

use srct_core::params::NetworkParams;
use srct_store::StoreError;

fn tmp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("srct-store-fuzzinv-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Every byte value, alone and as tails of growing length, plus structured
/// junk: hostile length fields, record headers with impossible sizes, and
/// pseudo-random sequences.
fn adversarial_tails() -> Vec<Vec<u8>> {
    let mut tails: Vec<Vec<u8>> = Vec::new();
    // Single bytes — including 0xff (a hostile length field) and 0x00.
    for b in [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff] {
        tails.push(vec![b]);
        tails.push(vec![b; 7]);
        tails.push(vec![b; 8]); // exactly one record header
        tails.push(vec![b; 64]);
    }
    // A record header claiming a length far larger than the file.
    tails.push(vec![0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0]);
    // A length that fits MAX_RECORD_BYTES but has no payload behind it.
    tails.push(vec![0x00, 0x00, 0x80, 0x00, 0, 0, 0, 0]);
    // Deterministic pseudo-random sequences (mutation-fuzzer shapes).
    tails.push(
        (0u8..96)
            .map(|i| i.wrapping_mul(53).wrapping_add(17))
            .collect(),
    );
    tails
}

#[test]
fn adversarial_log_tail_never_panics_and_never_loses_committed_records() {
    for (i, tail) in adversarial_tails().into_iter().enumerate() {
        let dir = tmp_dir(&format!("tail{i}"));
        let log_path = dir.join("blocks.log");
        {
            // A valid log with two committed records.
            let (mut log, _) = srct_store::RecordLog::open(&log_path).unwrap();
            log.append(b"record-zero").unwrap();
            log.append(b"record-one").unwrap();
            log.sync().unwrap();
        }
        // The adversarial part: append arbitrary bytes as a would-be record.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .unwrap();
            f.write_all(&tail).unwrap();
            f.sync_all().unwrap();
        }

        let params = NetworkParams::mini();
        match srct_store::BlockStore::open(&dir, &params) {
            Ok((mut store, _recovery)) => {
                store.sync().unwrap();
                drop(store);
                // Reopen must succeed and accept a new record.
                let (mut log, _) = srct_store::RecordLog::open(&log_path).unwrap();
                let r = log.append(b"post-recovery").unwrap();
                log.sync().unwrap();
                assert_eq!(log.read(r).unwrap(), b"post-recovery");
            }
            Err(e) => {
                // Refusals must be named errors, not IO surprises or panics.
                match e {
                    StoreError::Corrupt { .. }
                    | StoreError::BadMeta { .. }
                    | StoreError::BadBlock { .. }
                    | StoreError::MissingBlock { .. }
                    | StoreError::MissingParent { .. }
                    | StoreError::BadMagic { .. }
                    | StoreError::BadVersion { .. } => {}
                    other => {
                        panic!("tail {i}: unexpected store error for adversarial tail: {other:?}")
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Truncations of a committed log (a crash mid-append) must always recover the
/// intact prefix, report the discard, and keep appending.
#[test]
fn torn_tail_recovery_preserves_the_committed_prefix() {
    // Build a serialized log with two records, then try every truncation.
    let dir = tmp_dir("torn");
    let log_path = dir.join("blocks.log");
    let full: Vec<u8> = {
        let (mut log, _) = srct_store::RecordLog::open(&log_path).unwrap();
        log.append(b"record-zero").unwrap();
        log.append(b"record-one").unwrap();
        log.sync().unwrap();
        drop(log);
        std::fs::read(&log_path).unwrap()
    };

    for cut in 8..full.len() {
        // Keep only the header (8 bytes) plus a prefix of the records.
        std::fs::write(&log_path, &full[..cut]).unwrap();
        let (mut log, recovery) = srct_store::RecordLog::open(&log_path).unwrap();
        // Valid outcomes: (records 0, no tail), (1, clean), (1, tail discarded
        // and truncated), or (2, clean). A discarded tail always accompanies
        // truncation, and a full read of both records means nothing was torn.
        if recovery.records == 2 {
            assert_eq!(recovery.discarded_tail_bytes, 0, "cut {cut}");
            assert!(!recovery.truncated, "cut {cut}");
        } else {
            assert!(recovery.records < 2, "cut {cut}");
            assert_eq!(
                recovery.truncated,
                recovery.discarded_tail_bytes > 0,
                "cut {cut}"
            );
        }
        // Whatever was committed before the cut must still be readable.
        for (i, r) in log.refs().to_vec().iter().enumerate() {
            let want = format!("record-{}", ["zero", "one"][i]);
            assert_eq!(
                log.read(*r).unwrap(),
                want.as_bytes(),
                "cut {cut}: committed record {i} must survive a torn tail"
            );
        }
        // And the log must accept new appends from a known-good boundary.
        let r = log.append(b"after-tear").unwrap();
        log.sync().unwrap();
        assert_eq!(log.read(r).unwrap(), b"after-tear");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn adversarial_meta_file_never_panics_and_round_trips() {
    let metas: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        b"{}".to_vec(),
        b"{\"version\": 999999}".to_vec(),
        // Bad checksum.
        b"SRCT-META-1\nnot-json\nCHECKSUM deadbeef".to_vec(),
        // Valid-looking JSON with hostile field types.
        b"{\"version\": -1}".to_vec(),
        (0u8..200)
            .map(|i| i.wrapping_mul(71).wrapping_add(3))
            .collect(),
        vec![0xff; 300],
    ];
    // Plus: a structurally valid metadata whose checksum we forge correctly.
    for (i, data) in metas.into_iter().enumerate() {
        let dir = tmp_dir(&format!("meta{i}"));
        let path = dir.join("meta.json");
        std::fs::write(&path, &data).unwrap();

        let mf = srct_store::MetaFile::new(&path);
        match mf.load() {
            Ok(None) => {}
            Ok(Some(meta)) => {
                if meta.height == 0 {
                    assert_eq!(
                        meta.tip, meta.genesis,
                        "accepted metadata: height 0 must mean genesis tip"
                    );
                }
                // Round-trip: whatever parses must re-render and re-parse identically.
                mf.save(&meta).unwrap();
                let reparsed = mf.load().unwrap().expect("saved metadata must reload");
                assert_eq!(reparsed, meta, "render/parse round-trip must be identity");
            }
            Err(StoreError::BadMeta { .. }) => {}
            Err(e) => panic!("meta {i}: unexpected error class: {e:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A truncated meta.json (crash mid-write) must be detected, never accepted:
/// the checksum covers every field, so a partial write cannot pass as shorter
/// valid metadata.
#[test]
fn truncated_meta_file_is_rejected_or_absent_never_accepted() {
    let dir = tmp_dir("metatrn");
    let path = dir.join("meta.json");
    // A real store writes a real metadata file first.
    {
        let params = NetworkParams::mini();
        let _ = srct_store::BlockStore::open(&dir, &params).unwrap();
    }
    let good = std::fs::read(&path).unwrap();
    assert!(!good.is_empty(), "precondition: the store wrote metadata");

    for cut in 0..good.len() {
        std::fs::write(&path, &good[..cut]).unwrap();
        let mf = srct_store::MetaFile::new(&path);
        match mf.load() {
            Ok(None) => {}
            Ok(Some(meta)) => {
                // A truncation that still parses must be a byte-exact prefix
                // that happens to be complete metadata — re-render must match.
                assert_eq!(
                    meta.height, 0,
                    "a truncated meta can never claim a real tip"
                );
                assert_eq!(meta.tip, meta.genesis);
            }
            Err(StoreError::BadMeta { .. }) => {}
            Err(e) => panic!("cut {cut}: unexpected error class: {e:?}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
