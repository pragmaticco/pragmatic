//! The erasure ledger (design 4.2 and 4.13): `<data_dir>/erasure-ledger.jsonl`,
//! one JSON line per erasure, shred and retention delete, fsynced before the
//! operation is reported done.
//!
//! The ledger exists for restores. A backup taken before an erasure still
//! holds the erased content; restoring it would bring that content back.
//! `restore` therefore re-applies every ledger record newer than the
//! backup, from a copy of the ledger kept off the host (the documentation
//! requires streaming it off the host; the `erasure` and `retention`
//! webhooks carry the same records). Records hold positions and counts,
//! never content and never the free-text reason.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::fsutil;

/// What a record did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    /// Chosen slots were erased.
    Erasure,
    /// Every content slot was erased by retention.
    Shred,
    /// The run was deleted by retention and tombstoned.
    Delete,
}

/// One ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    /// Position in the ledger, from 1.
    pub seq: u64,
    /// RFC 3339.
    pub at: String,
    pub kind: LedgerKind,
    pub run_id: String,
    /// The slots changed from sealed to erased.
    #[serde(default)]
    pub slots: Vec<(u64, u8)>,
    pub reason_code: String,
    /// Token id, or `server:retention`.
    pub by: String,
    pub access_log_cursor: Option<u64>,
    pub note_cursor: Option<u64>,
    pub entries_before: u64,
    pub entries_after: u64,
    pub head_after: String,
    pub anchored_entries: u64,
}

/// The ledger file, appended under a lock.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    file: Mutex<(File, u64)>,
}

impl Ledger {
    /// `<data_dir>/erasure-ledger.jsonl`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("erasure-ledger.jsonl")
    }

    /// Open (or create) the ledger. A last line cut off by a crash is
    /// dropped.
    pub fn open(data_dir: &Path) -> io::Result<Ledger> {
        let path = Ledger::path(data_dir);
        let records = read(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        let valid = records_len(&path)?;
        if file.metadata()?.len() != valid {
            file.set_len(valid)?;
            file.sync_all()?;
        }
        file.flush()?;
        let last = records.last().map_or(0, |r| r.seq);
        fsutil::fsync_dir(data_dir)?;
        Ok(Ledger {
            path,
            file: Mutex::new((file, last)),
        })
    }

    /// Append a record (its `seq` is assigned here) and fsync. Returns the
    /// record as written.
    pub fn append(&self, mut record: LedgerRecord) -> io::Result<LedgerRecord> {
        let mut guard = self.file.lock().expect("ledger lock");
        record.seq = guard.1 + 1;
        let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
        line.push(b'\n');
        guard.0.write_all(&line)?;
        guard.0.sync_data()?;
        guard.1 = record.seq;
        Ok(record)
    }

    /// The file's path.
    pub fn file_path(&self) -> &Path {
        &self.path
    }

    /// The last sequence number written.
    pub fn last_seq(&self) -> u64 {
        self.file.lock().expect("ledger lock").1
    }
}

/// Every complete record of a ledger file (missing file: none). A final
/// line without its newline is a write cut off by a crash and is ignored;
/// any other bad line is an error.
pub fn read(path: &Path) -> io::Result<Vec<LedgerRecord>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break;
        }
        let record: LedgerRecord = serde_json::from_slice(&line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: record {}: {e}", path.display(), out.len() + 1),
            )
        })?;
        out.push(record);
    }
    Ok(out)
}

/// The length of the complete lines at the start of a ledger file.
fn records_len(path: &Path) -> io::Result<u64> {
    let bytes = std::fs::read(path)?;
    Ok(bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i as u64 + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;

    fn record(run: &str) -> LedgerRecord {
        LedgerRecord {
            seq: 0,
            at: "2026-10-13T00:00:00Z".into(),
            kind: LedgerKind::Erasure,
            run_id: run.into(),
            slots: vec![(3, 0)],
            reason_code: "dsar".into(),
            by: "tok_1".into(),
            access_log_cursor: Some(9),
            note_cursor: Some(10),
            entries_before: 10,
            entries_after: 11,
            head_after: "00".repeat(32),
            anchored_entries: 0,
        }
    }

    #[test]
    fn records_append_in_sequence_and_survive_a_torn_line() {
        let d = TestDir::new("ledger");
        let l = Ledger::open(&d).unwrap();
        assert_eq!(l.append(record("a")).unwrap().seq, 1);
        assert_eq!(l.append(record("b")).unwrap().seq, 2);
        drop(l);
        let mut f = OpenOptions::new()
            .append(true)
            .open(Ledger::path(&d))
            .unwrap();
        f.write_all(b"{\"seq\":3,\"at\"").unwrap();
        drop(f);
        let l = Ledger::open(&d).unwrap();
        assert_eq!(l.last_seq(), 2);
        assert_eq!(l.append(record("c")).unwrap().seq, 3);
        let all = read(&Ledger::path(&d)).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[2].run_id, "c");
        assert_eq!(all[0].slots, vec![(3, 0)]);
    }
}
