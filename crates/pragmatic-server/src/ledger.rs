//! The erasure ledger (design 4.2 and 4.13): `<data_dir>/erasure-ledger.jsonl`,
//! one JSON line per erasure, shred, retention delete and legal hold
//! change, fsynced *before* the operation commits.
//!
//! The ledger exists for restores. A backup taken before an erasure still
//! holds the erased content; restoring it would bring that content back,
//! and a backup taken before a hold would lose the hold, after which
//! retention could delete what the hold protects. `restore` therefore
//! re-applies every ledger record newer than the backup, in order, from a
//! copy of the ledger kept off the host (the documentation requires
//! streaming it off the host; the `erasure`, `retention` and `hold`
//! webhooks announce each record). Because a record is written before its
//! operation commits, no committed operation lacks one; a record whose
//! operation then failed is harmless to re-apply, since it does what an
//! admin or a retention policy asked for. Records hold positions, counts
//! and hold scopes, never content and never the free-text reason.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::fsutil;
use crate::holds::Hold;

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
    /// A legal hold was placed (`hold` holds it).
    HoldAdd,
    /// A legal hold was removed (`hold` holds it).
    HoldRemove,
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
    /// The hold a hold record places or removes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold: Option<Hold>,
}

impl LedgerRecord {
    /// The record of a hold change (`run_id` is empty: a hold may cover
    /// many runs, including runs created later).
    pub fn hold(kind: LedgerKind, hold: Hold, by: &str, access_log_cursor: u64) -> LedgerRecord {
        LedgerRecord {
            seq: 0,
            at: crate::timefmt::now_rfc3339(),
            kind,
            run_id: String::new(),
            slots: Vec::new(),
            reason_code: "legal_hold".into(),
            by: by.to_string(),
            access_log_cursor: Some(access_log_cursor),
            note_cursor: None,
            entries_before: 0,
            entries_after: 0,
            head_after: String::new(),
            anchored_entries: 0,
            hold: Some(hold),
        }
    }
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

/// The seq of the last complete record of a ledger file (0 when it has
/// none), read line by line without holding the records.
pub fn last_seq(path: &Path) -> io::Result<u64> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    #[derive(Deserialize)]
    struct Seq {
        seq: u64,
    }
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut last = 0;
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            return Ok(last);
        }
        last = serde_json::from_slice::<Seq>(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .seq;
    }
}

/// The length of the complete lines at the start of a ledger file.
fn records_len(path: &Path) -> io::Result<u64> {
    complete_len(&File::open(path)?)
}

/// The length of the complete lines at the start of an open ledger file,
/// found by reading backwards from its end (a cut-off last line is at most
/// one record long).
pub fn complete_len(file: &File) -> io::Result<u64> {
    let len = file.metadata()?.len();
    let mut end = len;
    let mut buf = vec![0u8; 64 << 10];
    while end > 0 {
        let start = end.saturating_sub(buf.len() as u64);
        let chunk = &mut buf[..(end - start) as usize];
        fsutil::read_exact_at(file, chunk, start)?;
        if let Some(i) = chunk.iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        end = start;
    }
    Ok(0)
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
            hold: None,
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
        assert_eq!(last_seq(&Ledger::path(&d)).unwrap(), 3);
        assert_eq!(last_seq(&d.join("missing.jsonl")).unwrap(), 0);
    }

    #[test]
    fn hold_records_carry_their_hold() {
        let d = TestDir::new("ledger-hold");
        let l = Ledger::open(&d).unwrap();
        let hold = Hold {
            id: "hold_1".into(),
            matter: "case-42".into(),
            scope: crate::holds::HoldScope {
                run_ids: None,
                prefix: Some("case-".into()),
            },
            created_at: "2026-10-13T00:00:00Z".into(),
            created_by: "tok_admin".into(),
        };
        let r = l
            .append(LedgerRecord::hold(
                LedgerKind::HoldAdd,
                hold.clone(),
                "tok_admin",
                7,
            ))
            .unwrap();
        let back = read(&Ledger::path(&d)).unwrap();
        assert_eq!(back[0], r);
        assert_eq!(back[0].hold.as_ref(), Some(&hold));
        assert_eq!(back[0].kind, LedgerKind::HoldAdd);
        // Erasure records do not carry the field at all.
        drop(l);
        let l = Ledger::open(&d).unwrap();
        l.append(record("x")).unwrap();
        let text = std::fs::read_to_string(Ledger::path(&d)).unwrap();
        assert_eq!(text.matches("\"hold\"").count(), 1);
    }
}
