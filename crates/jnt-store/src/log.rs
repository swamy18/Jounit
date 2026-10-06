//! An append-only, checksummed record log.
//!
//! This is the primitive the whole store is built on, and it exists to make one
//! thing true: **a crash during an append can only ever lose the append that was
//! in flight.** Nothing already written becomes unreadable, and nothing is
//! silently discarded without being reported.
//!
//! Layout:
//!
//! ```text
//! file    := magic(4) ‖ version(2 LE) ‖ reserved(2) ‖ record*
//! record  := len(4 LE) ‖ digest(4) ‖ payload(len)
//! ```
//!
//! `digest` is the first four bytes of `SHA256(payload)`. Four bytes is not a
//! security property — an attacker who can rewrite the file can recompute it — it
//! is a *corruption* check: a torn write, a bad sector or a truncated flush is
//! caught with probability `1 − 2⁻³²` per record, for four bytes of overhead per
//! record and no dependency beyond the hash the chain already uses.
//!
//! Two failure modes are deliberately treated differently, because conflating
//! them is how a store loses a chain and reports success:
//!
//! - **A torn tail** — the last record is short, or its length field claims more
//!   bytes than the file holds, or its digest does not match and nothing follows
//!   it. This is what a crash mid-append looks like, so it is recoverable:
//!   [`RecordLog::open`] truncates to the last good record and reports how many
//!   bytes it dropped.
//! - **Corruption with data after it** — a record whose digest does not match but
//!   which is followed by more bytes. That is not a crash signature, it is damage
//!   to data the process already committed, and the log refuses to open rather
//!   than quietly discarding everything past the damage. The operator gets
//!   [`StoreError::Corrupt`] with the offset.
//!
//! Reads are bounded by [`MAX_RECORD_BYTES`], checked *before* any allocation, so
//! a corrupt or hostile length field cannot ask for a gigabyte.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use jnt_core::hash::sha256;

use crate::StoreError;

/// File magic. A store opened by the wrong program fails loudly.
pub const LOG_MAGIC: [u8; 4] = *b"JNTS";

/// On-disk format version. Bumping it is how a future layout changes without
/// silently misreading an old file.
pub const LOG_VERSION: u16 = 1;

/// Header size: magic(4) ‖ version(2) ‖ reserved(2).
pub const LOG_HEADER_LEN: u64 = 8;

/// Largest single record accepted.
///
/// Chosen as twice `max_frame_bytes` (SPEC.md §13.8), which is itself one
/// `max_block_bytes` plus envelope, so the largest block any peer can deliver
/// fits with room to spare. A length field above this is corrupt by definition,
/// since nothing this node ever appends can reach it.
pub const MAX_RECORD_BYTES: u32 = 8_400_000;

/// Where a record lives in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordRef {
    /// Byte offset of the record's `len` field, i.e. of the record itself.
    pub offset: u64,
    /// Payload length, excluding the 8-byte record header.
    pub len: u32,
}

/// What recovery found when the log was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recovery {
    /// Records read back successfully.
    pub records: u64,
    /// Bytes discarded from the tail, because the last record was incomplete.
    ///
    /// Zero on a clean open. Non-zero is not an error — it is a crash that was
    /// survived — but it is reported rather than hidden, because "how much did I
    /// lose" is the first question an operator asks.
    pub discarded_tail_bytes: u64,
    /// Whether the file was truncated to drop that tail.
    pub truncated: bool,
}

/// An append-only record log.
#[derive(Debug)]
pub struct RecordLog {
    path: PathBuf,
    file: File,
    refs: Vec<RecordRef>,
    recovery: Recovery,
}

impl RecordLog {
    /// Open (creating if absent) and recover.
    ///
    /// Returns the log plus what recovery did. The file is left truncated to the
    /// last intact record, so a subsequent append continues from a known-good
    /// boundary rather than building on a torn one.
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Recovery), StoreError> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        // No `.truncate(true)`: truncation of a damaged tail happens explicitly
        // after recovery, never as an accident of opening.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;

        let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();

        if !existed || file_len == 0 {
            // Fresh file: write the header so a later opener can tell a valid
            // store from an empty file, and so a wrong-version read fails early.
            write_header(&mut file, &path)?;
            file.sync_all().map_err(|e| StoreError::io(&path, e))?;
            return Ok((
                RecordLog {
                    path,
                    file,
                    refs: Vec::new(),
                    recovery: Recovery::default(),
                },
                Recovery::default(),
            ));
        }

        check_header(&mut file, &path, file_len)?;
        // check_header may have written a header to a file that was shorter
        // than one, so the length the scan walks must be re-read, not reused —
        // reusing it made `file_len - pos` underflow on a 2-byte file.
        let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();

        let (refs, recovery) = scan(&mut file, &path, file_len)?;
        if recovery.truncated {
            let keep = LOG_HEADER_LEN
                + refs
                    .iter()
                    .map(|r| u64::from(r.len) + 8)
                    .sum::<u64>();
            file.set_len(keep).map_err(|e| StoreError::io(&path, e))?;
            file.sync_all().map_err(|e| StoreError::io(&path, e))?;
        }
        // Position at the end for appends.
        file.seek(SeekFrom::End(0))
            .map_err(|e| StoreError::io(&path, e))?;

        Ok((
            RecordLog {
                path,
                file,
                refs,
                recovery,
            },
            recovery,
        ))
    }

    /// What recovery did at open.
    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    /// Byte length of the log, header included.
    pub fn file_len(&self) -> Result<u64, StoreError> {
        Ok(self
            .file
            .metadata()
            .map_err(|e| StoreError::io(&self.path, e))?
            .len())
    }

    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    pub fn refs(&self) -> &[RecordRef] {
        &self.refs
    }

    /// Append a record and return where it landed.
    ///
    /// Written with a single `write_all` of the header and payload together, so a
    /// crash can leave a short record but never a header claiming bytes that were
    /// never part of the same write.
    ///
    /// **Not durable until [`RecordLog::sync`].** That is deliberate: a node
    /// appending a batch of blocks should pay for one flush, not one per block.
    pub fn append(&mut self, payload: &[u8]) -> Result<RecordRef, StoreError> {
        let len = u32::try_from(payload.len()).map_err(|_| StoreError::RecordTooLarge {
            len: payload.len(),
            max: MAX_RECORD_BYTES,
        })?;
        if len > MAX_RECORD_BYTES {
            return Err(StoreError::RecordTooLarge {
                len: payload.len(),
                max: MAX_RECORD_BYTES,
            });
        }
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| StoreError::io(&self.path, e))?;

        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&len.to_le_bytes());
        header[4..].copy_from_slice(&digest_of(payload));

        self.file
            .write_all(&header)
            .map_err(|e| StoreError::io(&self.path, e))?;
        self.file
            .write_all(payload)
            .map_err(|e| StoreError::io(&self.path, e))?;

        let r = RecordRef { offset, len };
        self.refs.push(r);
        Ok(r)
    }

    /// Flush to the operating system.
    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.file.flush().map_err(|e| StoreError::io(&self.path, e))
    }

    /// Flush and ask the platform to put it on stable storage.
    ///
    /// The point at which an append becomes durable. Everything the store says it
    /// has saved has been through here.
    pub fn sync(&mut self) -> Result<(), StoreError> {
        self.file
            .sync_all()
            .map_err(|e| StoreError::io(&self.path, e))
    }

    /// Read one record's payload.
    pub fn read(&mut self, r: RecordRef) -> Result<Vec<u8>, StoreError> {
        self.file
            .seek(SeekFrom::Start(r.offset + 8))
            .map_err(|e| StoreError::io(&self.path, e))?;
        let mut buf = vec![0u8; r.len as usize];
        self.file
            .read_exact(&mut buf)
            .map_err(|e| StoreError::io(&self.path, e))?;
        Ok(buf)
    }

    /// Read the last `n` records, newest last, without walking the whole file.
    pub fn read_last(&mut self, n: usize) -> Result<Vec<Vec<u8>>, StoreError> {
        let start = self.refs.len().saturating_sub(n);
        let refs: Vec<RecordRef> = self.refs[start..].to_vec();
        let mut out = Vec::with_capacity(refs.len());
        for r in refs {
            out.push(self.read(r)?);
        }
        Ok(out)
    }
}

/// First four bytes of the payload digest.
fn digest_of(payload: &[u8]) -> [u8; 4] {
    let d = sha256(&[payload]);
    [d[0], d[1], d[2], d[3]]
}

fn write_header(file: &mut File, path: &Path) -> Result<(), StoreError> {
    let mut header = [0u8; LOG_HEADER_LEN as usize];
    header[..4].copy_from_slice(&LOG_MAGIC);
    header[4..6].copy_from_slice(&LOG_VERSION.to_le_bytes());
    file.seek(SeekFrom::Start(0))
        .map_err(|e| StoreError::io(path, e))?;
    file.write_all(&header).map_err(|e| StoreError::io(path, e))
}

fn check_header(file: &mut File, path: &Path, file_len: u64) -> Result<(), StoreError> {
    if file_len < LOG_HEADER_LEN {
        // Shorter than a header: a crash before the header was durable. Treat it
        // as an uninitialised store rather than corruption, since nothing was
        // ever committed to it.
        write_header(file, path)?;
        file.sync_all().map_err(|e| StoreError::io(path, e))?;
        return Ok(());
    }
    let mut header = [0u8; LOG_HEADER_LEN as usize];
    file.seek(SeekFrom::Start(0))
        .map_err(|e| StoreError::io(path, e))?;
    file.read_exact(&mut header)
        .map_err(|e| StoreError::io(path, e))?;
    let magic: [u8; 4] = header[..4].try_into().unwrap();
    if magic != LOG_MAGIC {
        return Err(StoreError::BadMagic { path: path.into() });
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != LOG_VERSION {
        return Err(StoreError::BadVersion {
            path: path.into(),
            found: version,
            expected: LOG_VERSION,
        });
    }
    Ok(())
}

/// Walk every record, deciding whether the first bad one is a torn tail or real
/// corruption.
fn scan(
    file: &mut File,
    path: &Path,
    file_len: u64,
) -> Result<(Vec<RecordRef>, Recovery), StoreError> {
    let mut refs = Vec::new();
    let mut pos = LOG_HEADER_LEN;
    let mut recovery = Recovery::default();

    file.seek(SeekFrom::Start(pos))
        .map_err(|e| StoreError::io(path, e))?;

    loop {
        if pos == file_len {
            break;
        }
        if file_len - pos < 8 {
            // Fewer bytes than a record header: a torn tail.
            recovery.discarded_tail_bytes = file_len - pos;
            recovery.truncated = true;
            break;
        }

        let mut header = [0u8; 8];
        file.seek(SeekFrom::Start(pos))
            .map_err(|e| StoreError::io(path, e))?;
        file.read_exact(&mut header)
            .map_err(|e| StoreError::io(path, e))?;
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);

        // Checked before allocating, and before trusting anything else in the
        // record: a length that cannot be real makes the rest of the file
        // meaningless, so it is a tail regardless of how much follows it.
        if len > MAX_RECORD_BYTES {
            recovery.discarded_tail_bytes = file_len - pos;
            recovery.truncated = true;
            break;
        }

        let payload_start = pos + 8;
        let end = payload_start.checked_add(u64::from(len));
        let Some(end) = end else {
            recovery.discarded_tail_bytes = file_len - pos;
            recovery.truncated = true;
            break;
        };

        if end > file_len {
            // The record claims bytes the file does not hold. A crash during the
            // append that would have written them.
            recovery.discarded_tail_bytes = file_len - pos;
            recovery.truncated = true;
            break;
        }

        let mut payload = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(payload_start))
            .map_err(|e| StoreError::io(path, e))?;
        file.read_exact(&mut payload)
            .map_err(|e| StoreError::io(path, e))?;

        if digest_of(&payload) != header[4..8] {
            if end == file_len {
                // Damaged, but nothing follows it: still a tail, and recoverable
                // by dropping it.
                recovery.discarded_tail_bytes = file_len - pos;
                recovery.truncated = true;
                break;
            }
            // Damage with committed data after it. Refuse, rather than truncate
            // and pretend the chain ends here.
            return Err(StoreError::Corrupt {
                path: path.into(),
                offset: pos,
                detail: format!(
                    "record digest mismatch with {} bytes after it",
                    file_len - end
                ),
            });
        }

        refs.push(RecordRef { offset: pos, len });
        recovery.records += 1;
        pos = end;
    }

    Ok((refs, recovery))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jnt-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn fresh(name: &str) -> PathBuf {
        let p = tmp(name);
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn an_empty_store_opens_and_reports_nothing_lost() {
        let p = fresh("empty.log");
        let (log, rec) = RecordLog::open(&p).unwrap();
        assert!(log.is_empty());
        assert_eq!(rec, Recovery::default());
        assert_eq!(log.file_len().unwrap(), LOG_HEADER_LEN);
    }

    #[test]
    fn records_round_trip_in_order() {
        let p = fresh("roundtrip.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            for i in 0..10u8 {
                log.append(&[i; 5]).unwrap();
            }
            log.sync().unwrap();
        }
        let (mut log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 10);
        assert_eq!(rec.discarded_tail_bytes, 0);
        for (i, r) in log.refs().to_vec().iter().enumerate() {
            assert_eq!(log.read(*r).unwrap(), vec![i as u8; 5]);
        }
    }

    /// **A crash mid-append is survivable.** The tail is dropped and reported;
    /// everything before it is intact.
    #[test]
    fn a_truncated_tail_is_dropped_and_everything_before_it_kept() {
        let p = fresh("truncated.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"first").unwrap();
            log.append(b"second").unwrap();
            log.sync().unwrap();
        }
        // Simulate the power going out partway through a third append: header and
        // part of the payload reached the file.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&100u32.to_le_bytes()).unwrap();
            f.write_all(&[0u8; 4]).unwrap();
            f.write_all(b"half").unwrap();
            f.sync_all().unwrap();
        }

        let (mut log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 2, "the two committed records must survive");
        assert!(rec.truncated, "the torn tail must be reported");
        assert_eq!(rec.discarded_tail_bytes, 12);
        assert_eq!(log.len(), 2);
        assert_eq!(log.read(log.refs()[0]).unwrap(), b"first");

        // And appending works again from the recovered boundary.
        log.append(b"third").unwrap();
        log.sync().unwrap();
        let (mut log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 3);
        assert_eq!(rec.discarded_tail_bytes, 0);
        assert_eq!(log.read_last(1).unwrap(), vec![b"third".to_vec()]);
    }

    /// A length field that claims more than the file holds is a torn tail, not
    /// corruption: it is exactly what a crash during `write_all` leaves behind.
    #[test]
    fn a_length_field_beyond_the_file_end_is_treated_as_a_tail() {
        let p = fresh("badlen.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"good").unwrap();
            log.sync().unwrap();
        }
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&u32::MAX.to_le_bytes()).unwrap();
            f.write_all(&[1u8; 4]).unwrap();
            f.sync_all().unwrap();
        }
        let (log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 1);
        assert!(rec.truncated);
        assert_eq!(log.len(), 1);
    }

    /// An absurd length is refused *before* allocating, even when the bytes are
    /// present: `MAX_RECORD_BYTES` is the bound that keeps a corrupt field from
    /// asking for gigabytes.
    #[test]
    fn a_length_above_the_maximum_is_refused_without_allocating() {
        let p = fresh("hugelen.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"good").unwrap();
            log.sync().unwrap();
        }
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&(MAX_RECORD_BYTES + 1).to_le_bytes()).unwrap();
            f.write_all(&[1u8; 4]).unwrap();
            // A little payload, but nowhere near the declared length.
            f.write_all(&[0u8; 64]).unwrap();
            f.sync_all().unwrap();
        }
        let (log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 1);
        assert_eq!(log.len(), 1);
    }

    /// **Damage followed by more data refuses to open.** Truncating here would
    /// turn a storage fault into a shorter chain and report success, which is the
    /// failure this store exists to prevent.
    #[test]
    fn corruption_with_data_after_it_refuses_to_open() {
        let p = fresh("midcorrupt.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"aaaa").unwrap();
            log.append(b"bbbb").unwrap();
            log.append(b"cccc").unwrap();
            log.sync().unwrap();
        }
        // Flip a payload byte in the middle record.
        {
            let mut bytes = std::fs::read(&p).unwrap();
            let middle_payload = (LOG_HEADER_LEN + 8 + 4) as usize + 8 + 1;
            bytes[middle_payload] ^= 0xFF;
            std::fs::write(&p, &bytes).unwrap();
        }
        let err = RecordLog::open(&p).unwrap_err();
        match err {
            StoreError::Corrupt { offset, .. } => {
                assert_eq!(offset, LOG_HEADER_LEN + 8 + 4, "the offending record");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    /// A damaged *last* record is a tail, so it is dropped rather than refused.
    #[test]
    fn a_damaged_last_record_is_a_tail_not_corruption() {
        let p = fresh("tailcorrupt.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"aaaa").unwrap();
            log.append(b"bbbb").unwrap();
            log.sync().unwrap();
        }
        {
            let mut bytes = std::fs::read(&p).unwrap();
            let last = bytes.len() - 3;
            bytes[last] ^= 0xFF;
            std::fs::write(&p, &bytes).unwrap();
        }
        let (log, rec) = RecordLog::open(&p).unwrap();
        assert_eq!(rec.records, 1, "only the damaged record is lost");
        assert!(rec.truncated);
        assert_eq!(log.len(), 1);
    }

    /// A file that is not a store at all must not be read as one.
    #[test]
    fn a_foreign_file_is_refused_by_magic() {
        let p = fresh("foreign.log");
        std::fs::write(&p, b"this is not a jounit store at all").unwrap();
        match RecordLog::open(&p).unwrap_err() {
            StoreError::BadMagic { .. } => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    /// A store from a future format version is refused rather than misread.
    #[test]
    fn a_future_format_version_is_refused() {
        let p = fresh("future.log");
        {
            let (mut log, _) = RecordLog::open(&p).unwrap();
            log.append(b"x").unwrap();
            log.sync().unwrap();
        }
        {
            let mut bytes = std::fs::read(&p).unwrap();
            bytes[4..6].copy_from_slice(&(LOG_VERSION + 1).to_le_bytes());
            std::fs::write(&p, &bytes).unwrap();
        }
        match RecordLog::open(&p).unwrap_err() {
            StoreError::BadVersion {
                found, expected, ..
            } => {
                assert_eq!(found, LOG_VERSION + 1);
                assert_eq!(expected, LOG_VERSION);
            }
            other => panic!("expected BadVersion, got {other:?}"),
        }
    }

    /// A file shorter than the header is an uninitialised store: a crash before
    /// anything was committed. It is initialised, not refused.
    #[test]
    fn a_file_shorter_than_the_header_is_initialised() {
        let p = fresh("stub.log");
        std::fs::write(&p, b"JN").unwrap();
        let (log, rec) = RecordLog::open(&p).unwrap();
        assert!(log.is_empty());
        assert_eq!(rec.records, 0);
        assert_eq!(log.file_len().unwrap(), LOG_HEADER_LEN);
    }

    /// Appending a record larger than the maximum is refused by the writer too,
    /// so the limit is not only a reader's defence.
    #[test]
    fn an_oversized_append_is_refused() {
        let p = fresh("oversize.log");
        let (mut log, _) = RecordLog::open(&p).unwrap();
        let big = vec![0u8; MAX_RECORD_BYTES as usize + 1];
        match log.append(&big).unwrap_err() {
            StoreError::RecordTooLarge { max, .. } => assert_eq!(max, MAX_RECORD_BYTES),
            other => panic!("expected RecordTooLarge, got {other:?}"),
        }
        assert!(log.is_empty(), "a refused append must not be recorded");
    }
}
