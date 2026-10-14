//! The access log (design 4.11): one record per request, in a journal of
//! its own (`<data_dir>/audit/access.journal`, journal format 2).
//!
//! # Records
//!
//! Each record is a note on the meta branch. Its `data` holds the
//! structural fields (token id, role, method, route template, run id,
//! status, raw, cursors, query parameter *names*), and its one payload
//! slot holds the fields that identify a person (principal, source address,
//! user agent), apart from the structural fields that are never personal
//! data. Query-string values are never logged: they can carry search terms,
//! and a search term can be personal data.
//!
//! The first record of a new log is a `run.start` note for the reserved
//! run id `pragmatic:access-log`, so the log reads like any run in the CLI.
//!
//! # Group commit
//!
//! One writer thread appends. It collects records for at most 50 ms since
//! its last fsync, writes them with one positioned write and fsyncs once,
//! so a busy server pays one fsync per 50 ms for its whole access log
//! rather than one per request. Most requests do not wait for their record;
//! erasure, holds, retention, token changes and raw-content reads do
//! ([`AccessLog::durable`]): they act only once their record is on disk.
//! One write is at most [`WRITE_CHUNK`] bytes (a larger batch is written
//! and fsynced in pieces), so a crash can tear only that much.
//!
//! # Failing closed
//!
//! If a write or fsync fails, the log is marked failed for good (an fsync
//! failure cannot be retried: the kernel may already have dropped the
//! pages), and every authenticated request is refused with 503
//! `storage_unavailable` until the server is restarted. A server that
//! cannot record who read what must not serve anything. The failure is
//! reported through [`AccessLog::on_failure`] (the server raises a webhook
//! and fails `/readyz`) and [`AccessLog::is_failed`] (a metric).
//!
//! # Never in memory
//!
//! The log only grows: it is never shredded by retention policies, and an
//! unauthenticated request adds a record as surely as an authenticated
//! one. So nothing about it is kept per record in memory:
//!
//! - the writer keeps the chain's tail ([`NoteAppender`]);
//! - reads go to the file through an index of frame offsets kept on disk
//!   (`access.index`, 20 bytes per record: offset, length and a tag of the
//!   record's run id), which is rebuilt from the log at every start and is
//!   never trusted over it;
//! - opening and verifying the log read it frame by frame
//!   ([`NoteAppender::follow`]), holding one frame at a time, and after a
//!   crash at most [`TAIL_LIMIT`] bytes of torn tail.
//!
//! Each read examines at most [`SCAN_LIMIT`] index entries and then returns
//! where to continue, whether or not anything matched, so no request walks
//! the whole log.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use pragmatic::journal::{self, decode_frame, NoteAppender};
use pragmatic::sha256::{sha256, Digest};
use pragmatic::{Event, SlotState, Value};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};

use crate::fsutil;
use crate::timefmt;
use crate::tokens::scope_matches;

/// The longest the writer waits after its last fsync before the next one.
pub const GROUP_COMMIT: Duration = Duration::from_millis(50);

/// The reserved run id of the access log's `run.start` note.
pub const ACCESS_LOG_RUN_ID: &str = "pragmatic:access-log";

/// The most bytes one write (and fsync) carries. A batch larger than this
/// is written in pieces, each durable before the next starts.
pub const WRITE_CHUNK: usize = 16 << 20;

/// The most bytes after the last good frame that a restart reads to tell
/// a torn write from damage. A torn write is never longer than
/// [`WRITE_CHUNK`] plus one record, so a longer tail is corruption, which
/// is never truncated.
pub const TAIL_LIMIT: u64 = 64 << 20;

/// The most index entries one read examines.
pub const SCAN_LIMIT: u64 = 4096;

/// Bytes per index entry: offset (u64), frame length (u32), run tag (u64).
const INDEX_ENTRY: usize = 20;

/// `<data_dir>/audit/access.journal`.
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("audit").join("access.journal")
}

/// The offset index next to a log: `access.index`.
pub fn index_path(log: &Path) -> PathBuf {
    log.with_extension("index")
}

/// `<data_dir>/audit/anchor.json`: the access log's last anchor leaf.
pub fn leaf_path(data_dir: &Path) -> PathBuf {
    data_dir.join("audit").join("anchor.json")
}

/// The access log's last leaf in the anchor log (design 4.7), so the next
/// batch offers the log only when it grew and names this leaf as its
/// predecessor, and a restart can tell whether the log still holds the
/// anchored prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLeaf {
    pub leaf_index: u64,
    pub entries: u64,
    /// Lowercase hex of the chain head after `entries` records.
    pub head: String,
}

/// Read the access log's last leaf (`None` before its first batch).
pub fn read_leaf(data_dir: &Path) -> io::Result<Option<AccessLeaf>> {
    fsutil::read_json(&leaf_path(data_dir))
}

/// Record the access log's last leaf (atomic write).
pub fn write_leaf(data_dir: &Path, leaf: &AccessLeaf) -> io::Result<()> {
    fsutil::write_json_atomic(&leaf_path(data_dir), leaf)
}

/// One access-log record before it is written.
#[derive(Debug, Clone, Default)]
pub struct AccessRecord {
    /// The note kind: `request`, `intent`, `config.loaded`, `key.rotate`,
    /// `restore`, `verify-data`, `regression.accepted`, ...
    pub kind: String,
    /// Structural fields. Never personal data.
    pub data: Map<String, JsonValue>,
    /// Fields that identify a person: principal, source address, user
    /// agent. Stored in the payload slot.
    pub personal: Map<String, JsonValue>,
    /// The run the record concerns, for filtering.
    pub run_id: Option<String>,
}

impl AccessRecord {
    /// A record of `kind` with structural `data`.
    pub fn new(kind: &str, data: JsonValue) -> AccessRecord {
        let data = match data {
            JsonValue::Object(m) => m,
            _ => Map::new(),
        };
        let run_id = data
            .get("run_id")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        AccessRecord {
            kind: kind.to_string(),
            data,
            personal: Map::new(),
            run_id,
        }
    }
}

/// The access log is not writable: every authenticated request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

type Ack = tokio::sync::oneshot::Sender<Result<u64, Unavailable>>;

/// Called once, from the writer thread, when the log fails.
type FailHook = Box<dyn Fn(&str) + Send + Sync>;

enum Msg {
    Record(Box<AccessRecord>, Option<Ack>),
    Flush(Ack),
}

/// The durable end of the log.
#[derive(Debug, Clone, Copy)]
struct Tip {
    entries: u64,
    head: Digest,
    byte_len: u64,
}

struct Shared {
    failed: AtomicBool,
    reason: Mutex<Option<String>>,
    on_fail: OnceLock<FailHook>,
    queued: AtomicU64,
    oldest_ns: AtomicU64,
    /// Records that are durable and indexed: readers never look further.
    durable: AtomicU64,
    tip: Mutex<Tip>,
    inject_failure: AtomicBool,
}

impl Shared {
    fn tip(&self) -> Tip {
        *self.tip.lock().expect("tip lock")
    }
}

/// The access log: a handle to its writer thread, its file and its index.
#[derive(Clone)]
pub struct AccessLog {
    tx: Sender<Msg>,
    shared: Arc<Shared>,
    file: Arc<File>,
    index: Arc<File>,
    path: PathBuf,
}

/// One record as the API serves it.
pub type RecordView = Map<String, JsonValue>;

/// Records read back: `(cursor, run id, entry)`, and the cursor to continue
/// after when more may follow.
pub type ReadPage = (Vec<(u64, Option<String>, journal::Entry)>, Option<u64>);

/// Which records a read returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Every record.
    All,
    /// The records of one run.
    Run(String),
    /// The records of runs within these scopes (an auditor's view).
    Scopes(Vec<String>),
}

impl Filter {
    fn keeps(&self, run: Option<&str>) -> bool {
        match (self, run) {
            (Filter::All, _) => true,
            (Filter::Run(want), Some(r)) => r == want,
            (Filter::Scopes(scopes), Some(r)) => scope_matches(scopes, r),
            _ => false,
        }
    }

    /// Whether an index entry with this tag can match, before its record is
    /// read.
    fn may_keep(&self, tag: u64) -> bool {
        match self {
            Filter::All => true,
            Filter::Run(want) => tag == run_tag(want),
            Filter::Scopes(_) => tag != 0,
        }
    }
}

/// What verifying the log found (design 4.13).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AccessVerify {
    pub ok: bool,
    /// Records that verified.
    pub entries: u64,
    /// The first record that does not verify.
    pub first_bad: Option<u64>,
    /// Bytes after the last record that a crash left (offline only).
    pub torn_bytes: u64,
    /// Erased slots: the server never erases access-log records, so any is
    /// a change made outside it.
    pub unaccounted_erasures: u64,
    pub error: Option<String>,
}

impl AccessLog {
    /// Open (or create) the log at `path`, rebuild its index and start its
    /// writer thread.
    ///
    /// The whole file is read once, frame by frame. A torn tail (a crash
    /// during a write) is moved aside to `access.journal.torn-<unix_ms>`
    /// and truncated; corruption is an error, and the server refuses to
    /// start rather than append to a log whose history it cannot vouch for.
    pub fn open(path: &Path) -> io::Result<AccessLog> {
        if let Some(dir) = path.parent() {
            fsutil::create_dir_durable(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let index_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(index_path(path))?;
        let len = file.metadata()?.len();
        let (appender, entries) = if len == 0 {
            create(&file, &index_file)?
        } else {
            recover(path, &file, &index_file, len)?
        };
        let shared = Arc::new(Shared {
            failed: AtomicBool::new(false),
            reason: Mutex::new(None),
            on_fail: OnceLock::new(),
            queued: AtomicU64::new(0),
            oldest_ns: AtomicU64::new(0),
            durable: AtomicU64::new(entries),
            tip: Mutex::new(Tip {
                entries,
                head: appender.head(),
                byte_len: appender.byte_len(),
            }),
            inject_failure: AtomicBool::new(false),
        });
        let file = Arc::new(file);
        let index = Arc::new(index_file);
        let (tx, rx) = mpsc::channel();
        let writer = Writer {
            rx,
            file: file.clone(),
            index: index.clone(),
            committed: appender.clone(),
            appender,
            shared: shared.clone(),
            last_sync: Instant::now() - GROUP_COMMIT,
        };
        std::thread::Builder::new()
            .name("pragmatic-access-log".into())
            .spawn(move || writer.run())?;
        Ok(AccessLog {
            tx,
            shared,
            file,
            index,
            path: path.to_path_buf(),
        })
    }

    /// Run `hook` (once, on the writer thread) when the log fails.
    pub fn on_failure(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        let _ = self.shared.on_fail.set(Box::new(hook));
    }

    /// Queue a record without waiting for it to be durable.
    pub fn submit(&self, record: AccessRecord) {
        self.enqueue(Msg::Record(Box::new(record), None));
    }

    /// Append a record and wait until it is durable. Returns its cursor.
    pub async fn durable(&self, record: AccessRecord) -> Result<u64, Unavailable> {
        let (ack, wait) = tokio::sync::oneshot::channel();
        self.enqueue(Msg::Record(Box::new(record), Some(ack)));
        wait.await
            .unwrap_or_else(|_| Err(Unavailable("access log writer stopped".into())))
    }

    /// [`durable`](Self::durable) for synchronous code (blocking tasks).
    pub fn durable_blocking(&self, record: AccessRecord) -> Result<u64, Unavailable> {
        let (ack, wait) = tokio::sync::oneshot::channel();
        self.enqueue(Msg::Record(Box::new(record), Some(ack)));
        wait.blocking_recv()
            .unwrap_or_else(|_| Err(Unavailable("access log writer stopped".into())))
    }

    /// Wait until everything queued so far is durable.
    pub async fn flush(&self) -> Result<(), Unavailable> {
        let (ack, wait) = tokio::sync::oneshot::channel();
        self.enqueue(Msg::Flush(ack));
        wait.await
            .unwrap_or_else(|_| Err(Unavailable("access log writer stopped".into())))
            .map(|_| ())
    }

    fn enqueue(&self, msg: Msg) {
        if self.shared.queued.fetch_add(1, Ordering::SeqCst) == 0 {
            self.shared
                .oldest_ns
                .store(timefmt::now_unix_ns(), Ordering::SeqCst);
        }
        if let Err(mpsc::SendError(msg)) = self.tx.send(msg) {
            self.shared.queued.fetch_sub(1, Ordering::SeqCst);
            let ack = match msg {
                Msg::Record(_, ack) => ack,
                Msg::Flush(ack) => Some(ack),
            };
            if let Some(ack) = ack {
                let _ = ack.send(Err(Unavailable("access log writer stopped".into())));
            }
        }
    }

    /// True once a write has failed: requests must be refused.
    pub fn is_failed(&self) -> bool {
        self.shared.failed.load(Ordering::SeqCst)
    }

    /// Why the log failed, if it has.
    pub fn failure(&self) -> Option<String> {
        self.shared.reason.lock().expect("reason lock").clone()
    }

    /// Seconds since the oldest record that is not yet durable was queued
    /// (0 when everything is durable).
    pub fn lag_seconds(&self) -> f64 {
        let oldest = self.shared.oldest_ns.load(Ordering::SeqCst);
        if oldest == 0 || self.shared.queued.load(Ordering::SeqCst) == 0 {
            return 0.0;
        }
        timefmt::now_unix_ns().saturating_sub(oldest) as f64 / 1e9
    }

    /// `(entries, head)` of the durable log, for anchoring.
    pub fn tip(&self) -> (u64, Digest) {
        let t = self.shared.tip();
        (t.entries, t.head)
    }

    /// TEST ONLY: make every later write fail, as a full or failing disk
    /// would.
    #[cfg(any(test, feature = "testing"))]
    pub fn inject_write_failure(&self) {
        self.shared.inject_failure.store(true, Ordering::SeqCst);
    }

    /// The `(offset, length, run tag)` of each durable record in
    /// `first..first + count` (fewer at the end of the log).
    fn index_entries(&self, first: u64, count: u64) -> io::Result<Vec<(u64, u32, u64)>> {
        let durable = self.shared.durable.load(Ordering::Acquire);
        let end = first.saturating_add(count).min(durable);
        if first >= end {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; ((end - first) as usize) * INDEX_ENTRY];
        fsutil::read_exact_at(&self.index, &mut buf, first * INDEX_ENTRY as u64)?;
        Ok(buf.chunks_exact(INDEX_ENTRY).map(decode_index).collect())
    }

    /// The durable record at `cursor`, decoded.
    fn record(&self, cursor: u64, offset: u64, len: u32) -> io::Result<journal::Entry> {
        let mut buf = vec![0u8; len as usize];
        fsutil::read_exact_at(&self.file, &mut buf, offset)?;
        decode_frame(&buf, cursor).map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))
    }

    /// The chain hash of the durable record at `cursor`, if there is one.
    pub fn hash_at(&self, cursor: u64) -> io::Result<Option<Digest>> {
        let Some(&(offset, len, _)) = self.index_entries(cursor, 1)?.first() else {
            return Ok(None);
        };
        let mut hash = [0u8; 32];
        fsutil::read_exact_at(&self.file, &mut hash, offset + u64::from(len) - 32)?;
        Ok(Some(hash))
    }

    /// Up to `limit` durable records after cursor `after` (from the start
    /// when `None`) that pass `filter`, examining at most [`SCAN_LIMIT`]
    /// records. Returns the records and the cursor to continue after when
    /// more may follow: the last record returned, or the last one examined
    /// when the scan stopped first.
    pub fn read(&self, after: Option<u64>, limit: usize, filter: &Filter) -> io::Result<ReadPage> {
        let start = after.map_or(0, |a| a.saturating_add(1));
        let entries = self.index_entries(start, SCAN_LIMIT)?;
        let durable = self.shared.durable.load(Ordering::Acquire);
        let mut out = Vec::new();
        let mut last = None;
        for (i, (offset, len, tag)) in entries.into_iter().enumerate() {
            let cursor = start + i as u64;
            last = Some(cursor);
            if !filter.may_keep(tag) {
                continue;
            }
            let entry = self.record(cursor, offset, len)?;
            let run = note_run_id(&entry.event);
            if filter.keeps(run.as_deref()) {
                out.push((cursor, run, entry));
                if out.len() >= limit {
                    break;
                }
            }
        }
        let next = last.filter(|&c| c + 1 < durable);
        Ok((out, next))
    }

    /// Verify the durable log, frame by frame: every record decodes, its
    /// commitments hold and it chains, and the chain ends where the writer
    /// says it does (design 4.13).
    pub fn verify(&self) -> AccessVerify {
        let tip = self.shared.tip();
        let mut report = verify_file(&self.path, Some(tip.byte_len));
        if report.error.is_none() && report.first_bad.is_none() && report.entries != tip.entries {
            report.ok = false;
            report.error = Some(format!(
                "the log holds {} records but the writer has {}",
                report.entries, tip.entries
            ));
        }
        report
    }
}

/// Verify a log file on its own, frame by frame (offline, or the durable
/// prefix `upto` of a live log, past which a writer may be mid-write).
pub fn verify_file(path: &Path, upto: Option<u64>) -> AccessVerify {
    let mut report = AccessVerify::default();
    let len = match upto {
        Some(n) => Ok(n),
        None => std::fs::metadata(path).map(|m| m.len()),
    };
    let scanned = len.and_then(|len| {
        scan(path, len, |_, _, entry| {
            report.unaccounted_erasures += entry
                .slots
                .iter()
                .filter(|s| s.state == SlotState::Erased)
                .count() as u64;
            Ok(())
        })
    });
    match scanned {
        Err(e) => report.error = Some(e.to_string()),
        Ok(s) => {
            report.entries = s.tail.entries();
            match s.damage {
                None => {}
                // Inside the durable prefix of a live log nothing can be
                // torn: every byte of it was fsynced.
                Some(Damage::Tail { .. }) if upto.is_some() => {
                    report.first_bad = Some(s.tail.entries())
                }
                Some(Damage::Tail { offset }) => match classify(path, &s.tail, offset, s.len) {
                    Ok(None) => report.torn_bytes = s.len - offset,
                    Ok(Some(_)) => report.first_bad = Some(s.tail.entries()),
                    Err(e) => report.error = Some(e.to_string()),
                },
            }
        }
    }
    report.ok =
        report.error.is_none() && report.first_bad.is_none() && report.unaccounted_erasures == 0;
    report
}

/// The JSON view of a record: cursor, time, chain hash, kind, structural
/// fields and, from the payload, the personal ones.
pub fn record_view(cursor: u64, entry: &journal::Entry) -> RecordView {
    let mut out = Map::new();
    out.insert("cursor".into(), cursor.into());
    out.insert("at".into(), timefmt::rfc3339_ns(entry.at).into());
    out.insert(
        "hash".into(),
        pragmatic::encoding::hex_encode(&entry.hash).into(),
    );
    if let Event::Note {
        kind,
        data,
        payload,
    } = &entry.event
    {
        out.insert("kind".into(), kind.clone().into());
        if let Ok(JsonValue::Object(fields)) = serde_json::from_str::<JsonValue>(data) {
            for (k, v) in fields {
                out.entry(k).or_insert(v);
            }
        }
        if let Some(value) = payload.first().and_then(|c| c.value()) {
            if let Ok(JsonValue::Object(fields)) =
                serde_json::from_slice::<JsonValue>(value.as_bytes())
            {
                for (k, v) in fields {
                    out.entry(k).or_insert(v);
                }
            }
        }
    }
    out
}

/// The tag of a run id in the index: the first 8 bytes of its SHA-256
/// (never 0, which marks a record without a run). Equal tags are confirmed
/// against the record itself.
fn run_tag(run_id: &str) -> u64 {
    let d = sha256(run_id.as_bytes());
    let tag = u64::from_le_bytes(d[..8].try_into().expect("8 bytes"));
    tag.max(1)
}

fn encode_index(offset: u64, len: u32, run: Option<&str>) -> [u8; INDEX_ENTRY] {
    let mut out = [0u8; INDEX_ENTRY];
    out[..8].copy_from_slice(&offset.to_le_bytes());
    out[8..12].copy_from_slice(&len.to_le_bytes());
    out[12..].copy_from_slice(&run.map_or(0, run_tag).to_le_bytes());
    out
}

fn decode_index(b: &[u8]) -> (u64, u32, u64) {
    (
        u64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
        u32::from_le_bytes(b[8..12].try_into().expect("4 bytes")),
        u64::from_le_bytes(b[12..20].try_into().expect("8 bytes")),
    )
}

/// Start a new log: header, then the `run.start` note.
fn create(file: &File, index: &File) -> io::Result<(NoteAppender, u64)> {
    let mut appender = NoteAppender::new(None);
    let mut nonce = [0u8; 16];
    pragmatic::rand::fill(&mut nonce)?;
    let data = serde_json::json!({
        "format": 2,
        "labels": {},
        "nonce": pragmatic::encoding::hex_encode(&nonce),
        "run_id": ACCESS_LOG_RUN_ID,
        "sdk": "pragmatic-server",
        "sdk_version": env!("CARGO_PKG_VERSION"),
    })
    .to_string();
    let (_, frame) = appender
        .append(timefmt::now_unix_ns(), journal::note::RUN_START, &data, &[])
        .map_err(io::Error::other)?;
    let mut bytes = journal::header(0).to_vec();
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(&frame);
    fsutil::write_all_at(file, &bytes, 0)?;
    file.sync_all()?;
    fsutil::write_all_at(index, &encode_index(offset, frame.len() as u32, None), 0)?;
    Ok((appender, 1))
}

/// Where reading a log stopped following its chain.
enum Damage {
    /// The frame at `offset` (and everything after it) does not follow.
    Tail { offset: u64 },
}

/// What reading a log frame by frame found.
struct Scanned {
    tail: NoteAppender,
    len: u64,
    damage: Option<Damage>,
}

/// Read the first `len` bytes of the log at `path` frame by frame, calling
/// `each(offset, frame length, entry)` for every frame that follows the
/// chain, and stop at the first that does not.
fn scan(
    path: &Path,
    len: u64,
    mut each: impl FnMut(u64, u32, &journal::Entry) -> io::Result<()>,
) -> io::Result<Scanned> {
    let header_len = journal::HEADER_LEN as u64;
    let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?.take(len));
    let mut header = [0u8; journal::HEADER_LEN];
    if len < header_len || reader.read_exact(&mut header).is_err() {
        return Err(invalid(format!("{}: no journal header", path.display())));
    }
    if header != journal::header(0) {
        return Err(invalid(format!(
            "{}: not an unkeyed format 2 journal",
            path.display()
        )));
    }
    let mut tail = NoteAppender::new(None);
    let mut offset = header_len;
    let mut frame = Vec::new();
    while offset < len {
        let damaged = Some(Damage::Tail { offset });
        let rest = len - offset;
        if rest < 4 {
            return Ok(Scanned {
                tail,
                len,
                damage: damaged,
            });
        }
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix)?;
        let record = u64::from(u32::from_le_bytes(prefix));
        let frame_len = 4 + record + 32;
        if record > journal::MAX_RECORD_BYTES || frame_len > rest {
            return Ok(Scanned {
                tail,
                len,
                damage: damaged,
            });
        }
        frame.clear();
        frame.extend_from_slice(&prefix);
        frame.resize(frame_len as usize, 0);
        reader.read_exact(&mut frame[4..])?;
        match tail.follow(&frame) {
            Ok(entry) => each(offset, frame_len as u32, &entry)?,
            Err(_) => {
                return Ok(Scanned {
                    tail,
                    len,
                    damage: damaged,
                })
            }
        }
        offset += frame_len;
    }
    Ok(Scanned {
        tail,
        len,
        damage: None,
    })
}

/// Classify the bytes from `offset` to `len` of the log (design 2.14):
/// `None` for a torn tail. A tail longer than [`TAIL_LIMIT`] is corruption
/// without being read.
fn classify(path: &Path, tail: &NoteAppender, offset: u64, len: u64) -> io::Result<Option<String>> {
    if len - offset > TAIL_LIMIT {
        return Ok(Some(format!(
            "{} bytes after the last record that verifies, more than any write leaves",
            len - offset
        )));
    }
    let mut bytes = vec![0u8; (len - offset) as usize];
    fsutil::read_exact_at(&File::open(path)?, &mut bytes, offset)?;
    Ok(tail.classify_tail(&bytes, offset))
}

/// Verify an existing log frame by frame, rebuild its index, and move a
/// torn tail aside.
fn recover(path: &Path, file: &File, index: &File, len: u64) -> io::Result<(NoteAppender, u64)> {
    let mut out = BufWriter::new(index);
    let scanned = scan(path, len, |offset, frame_len, entry| {
        let run = note_run_id(&entry.event);
        out.write_all(&encode_index(offset, frame_len, run.as_deref()))
    })?;
    out.flush()?;
    drop(out);
    if let Some(Damage::Tail { offset }) = scanned.damage {
        if let Some(why) = classify(path, &scanned.tail, offset, len)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "access log {}: corrupt at record {}: {why}",
                    path.display(),
                    scanned.tail.entries()
                ),
            ));
        }
        let mut torn = vec![0u8; (len - offset) as usize];
        fsutil::read_exact_at(file, &mut torn, offset)?;
        let aside = path.with_extension(format!(
            "journal.torn-{}",
            timefmt::now_unix_ns() / 1_000_000
        ));
        fsutil::write_atomic(&aside, &torn)?;
        file.set_len(offset)?;
        file.sync_all()?;
    }
    let entries = scanned.tail.entries();
    Ok((scanned.tail, entries))
}

/// The `run_id` in a record's data, if any.
fn note_run_id(event: &Event) -> Option<String> {
    let Event::Note { kind, data, .. } = event else {
        return None;
    };
    if kind == journal::note::RUN_START {
        return None;
    }
    let doc: JsonValue = serde_json::from_str(data).ok()?;
    doc.get("run_id")?.as_str().map(str::to_string)
}

struct Writer {
    rx: Receiver<Msg>,
    file: Arc<File>,
    index: Arc<File>,
    /// The tail new records are encoded against.
    appender: NoteAppender,
    /// The tail of what is durable: `appender` goes back to it when a
    /// write fails.
    committed: NoteAppender,
    shared: Arc<Shared>,
    last_sync: Instant,
}

/// Records encoded for one write, with where each goes.
#[derive(Default)]
struct Chunk {
    bytes: Vec<u8>,
    index: Vec<u8>,
    msgs: Vec<(Msg, Option<u64>)>,
}

impl Writer {
    fn run(mut self) {
        while let Ok(first) = self.rx.recv() {
            let mut batch = vec![first];
            let deadline = self.last_sync + GROUP_COMMIT;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                match self.rx.recv_timeout(deadline - now) {
                    Ok(m) => batch.push(m),
                    Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            while let Ok(m) = self.rx.try_recv() {
                batch.push(m);
            }
            let n = batch.len() as u64;
            self.commit(batch);
            self.last_sync = Instant::now();
            if self.shared.queued.fetch_sub(n, Ordering::SeqCst) == n {
                self.shared.oldest_ns.store(0, Ordering::SeqCst);
            } else {
                self.shared
                    .oldest_ns
                    .store(timefmt::now_unix_ns(), Ordering::SeqCst);
            }
        }
    }

    /// Encode a batch and make it durable in chunks of at most
    /// [`WRITE_CHUNK`] bytes, answering each chunk's waiters once it is on
    /// disk. After a failure every remaining waiter is refused.
    fn commit(&mut self, batch: Vec<Msg>) {
        let mut chunk = Chunk::default();
        let mut msgs = batch.into_iter();
        while let Some(msg) = msgs.next() {
            if self.shared.failed.load(Ordering::SeqCst) {
                let rest = std::iter::once(msg).chain(msgs).collect();
                return self.refuse(chunk, rest);
            }
            let cursor = match &msg {
                Msg::Record(record, _) => match self.encode(record, &mut chunk) {
                    Ok(c) => Some(c),
                    Err(why) => {
                        let rest = std::iter::once(msg).chain(msgs).collect();
                        return self.fail_chunk(chunk, rest, why);
                    }
                },
                Msg::Flush(_) => None,
            };
            chunk.msgs.push((msg, cursor));
            if chunk.bytes.len() >= WRITE_CHUNK {
                if let Err(why) = self.write(&mut chunk) {
                    return self.fail_chunk(chunk, msgs.collect(), why);
                }
            }
        }
        if let Err(why) = self.write(&mut chunk) {
            self.fail_chunk(chunk, Vec::new(), why);
        }
    }

    /// Encode one record into the chunk. Returns its cursor.
    fn encode(&mut self, record: &AccessRecord, chunk: &mut Chunk) -> Result<u64, String> {
        let data = JsonValue::Object(record.data.clone()).to_string();
        let payload = if record.personal.is_empty() {
            Vec::new()
        } else {
            vec![Value::from(
                JsonValue::Object(record.personal.clone()).to_string(),
            )]
        };
        let offset = self.appender.byte_len();
        let (cursor, frame) = self
            .appender
            .append(timefmt::now_unix_ns(), &record.kind, &data, &payload)
            .map_err(|f| format!("access record could not be encoded: {f}"))?;
        chunk.index.extend_from_slice(&encode_index(
            offset,
            frame.len() as u32,
            record.run_id.as_deref(),
        ));
        chunk.bytes.extend_from_slice(&frame);
        Ok(cursor)
    }

    /// Write and fsync the chunk, index it, publish the new tip and answer
    /// its waiters. The chunk is left empty.
    fn write(&mut self, chunk: &mut Chunk) -> Result<(), String> {
        if !chunk.bytes.is_empty() {
            if self.shared.inject_failure.load(Ordering::SeqCst) {
                return Err("access log write failed: injected write failure".into());
            }
            fsutil::write_all_at(&self.file, &chunk.bytes, self.committed.byte_len())
                .and_then(|_| self.file.sync_data())
                .map_err(|e| format!("access log write failed: {e}"))?;
            // The index is derived from the log and rebuilt at every start,
            // so it is written but not fsynced. A write that fails leaves
            // records durable that readers cannot reach: fail closed.
            let at = self.committed.entries() * INDEX_ENTRY as u64;
            if let Err(e) = fsutil::write_all_at(&self.index, &chunk.index, at) {
                self.mark_failed(format!("access log index write failed: {e}"));
            }
        }
        self.committed = self.appender.clone();
        let entries = self.committed.entries();
        *self.shared.tip.lock().expect("tip lock") = Tip {
            entries,
            head: self.committed.head(),
            byte_len: self.committed.byte_len(),
        };
        if !self.shared.failed.load(Ordering::SeqCst) {
            self.shared.durable.store(entries, Ordering::Release);
        }
        let durable = entries.saturating_sub(1);
        for (msg, cursor) in std::mem::take(&mut chunk.msgs) {
            match msg {
                Msg::Record(_, Some(ack)) => {
                    let _ = ack.send(Ok(cursor.unwrap_or(durable)));
                }
                Msg::Flush(ack) => {
                    let _ = ack.send(Ok(durable));
                }
                Msg::Record(_, None) => {}
            }
        }
        chunk.bytes.clear();
        chunk.index.clear();
        Ok(())
    }

    /// A chunk could not be made durable: roll the file and the tail back
    /// to the last durable state, fail for good, and refuse the chunk's
    /// waiters and everything after them.
    fn fail_chunk(&mut self, chunk: Chunk, rest: Vec<Msg>, why: String) {
        let _ = self.file.set_len(self.committed.byte_len());
        let _ = self.file.sync_all();
        // Back to the durable tail: the encoded frames were never written.
        self.appender = self.committed.clone();
        self.mark_failed(why);
        self.refuse(chunk, rest);
    }

    /// Refuse every waiter of `chunk` and of `rest`.
    fn refuse(&mut self, chunk: Chunk, rest: Vec<Msg>) {
        let why = self.shared.reason.lock().expect("reason lock").clone();
        let msgs = chunk.msgs.into_iter().map(|(m, _)| m).chain(rest);
        answer_all(msgs, Err(Unavailable(why.unwrap_or_default())));
    }

    fn mark_failed(&self, why: String) {
        *self.shared.reason.lock().expect("reason lock") = Some(why.clone());
        if !self.shared.failed.swap(true, Ordering::SeqCst) {
            if let Some(hook) = self.shared.on_fail.get() {
                hook(&why);
            }
        }
    }
}

fn answer_all(msgs: impl IntoIterator<Item = Msg>, result: Result<u64, Unavailable>) {
    for msg in msgs {
        let ack = match msg {
            Msg::Record(_, ack) => ack,
            Msg::Flush(ack) => Some(ack),
        };
        if let Some(ack) = ack {
            let _ = ack.send(result.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use pragmatic::Journal;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn rec(run: &str, n: u64) -> AccessRecord {
        let mut r = AccessRecord::new(
            "request",
            serde_json::json!({"run_id": run, "status": 200, "n": n}),
        );
        r.personal.insert("source_ip".into(), "203.0.113.9".into());
        r
    }

    fn all(log: &AccessLog, filter: &Filter) -> Vec<u64> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let (page, next) = log.read(after, 1000, filter).unwrap();
            out.extend(page.iter().map(|(c, _, _)| *c));
            match next {
                Some(n) => after = Some(n),
                None => return out,
            }
        }
    }

    #[test]
    fn records_are_durable_and_read_back_in_order() {
        let d = TestDir::new("alog");
        let p = path(&d);
        let log = AccessLog::open(&p).unwrap();
        let rt = rt();
        for i in 0..5 {
            log.submit(rec(if i % 2 == 0 { "a" } else { "b" }, i));
        }
        let c = rt.block_on(log.durable(rec("a", 99))).unwrap();
        assert_eq!(c, 6);
        let (page, next) = log.read(None, 100, &Filter::All).unwrap();
        assert_eq!(page.len(), 7);
        assert_eq!(next, None);
        assert_eq!(page[0].2.event.note_kind(), Some("run.start"));
        let (only_a, _) = log.read(None, 100, &Filter::Run("a".into())).unwrap();
        assert_eq!(only_a.len(), 4);
        let view = record_view(only_a[0].0, &only_a[0].2);
        assert_eq!(view["run_id"], "a");
        assert_eq!(view["source_ip"], "203.0.113.9");
        assert_eq!(view["kind"], "request");
        assert_eq!(view["hash"].as_str().unwrap().len(), 64);
        let scoped = Filter::Scopes(vec!["b".into()]);
        assert_eq!(all(&log, &scoped), vec![2, 4]);
        let (page, next) = log.read(None, 2, &Filter::All).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(next, Some(1));
        assert_eq!(log.hash_at(6).unwrap(), Some(log.tip().1));
        assert_eq!(log.hash_at(7).unwrap(), None);

        // Reopen: the file verifies, the index is rebuilt, and the log
        // continues.
        drop(log);
        let log = AccessLog::open(&p).unwrap();
        assert_eq!(log.tip().0, 7);
        assert_eq!(all(&log, &Filter::Run("a".into())), vec![1, 3, 5, 6]);
        rt.block_on(log.durable(rec("c", 1))).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        let parsed = Journal::parse(&bytes, None).unwrap();
        assert_eq!(parsed.journal.len(), 8);
        assert_eq!(parsed.journal.head(), log.tip().1);
        let report = log.verify();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.entries, 8);
    }

    #[test]
    fn a_write_failure_fails_closed_for_good_and_says_so_once() {
        let d = TestDir::new("alog-fail");
        let log = AccessLog::open(&path(&d)).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        log.on_failure(move |why| {
            assert!(why.contains("injected"));
            c.fetch_add(1, Ordering::SeqCst);
        });
        let rt = rt();
        rt.block_on(log.durable(rec("a", 1))).unwrap();
        log.inject_write_failure();
        assert!(rt.block_on(log.durable(rec("a", 2))).is_err());
        assert!(log.is_failed());
        log.shared.inject_failure.store(false, Ordering::SeqCst);
        // Sticky: even once writes would work again.
        assert!(rt.block_on(log.durable(rec("a", 3))).is_err());
        assert!(rt.block_on(log.flush()).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let bytes = std::fs::read(path(&d)).unwrap();
        assert_eq!(Journal::parse(&bytes, None).unwrap().journal.len(), 2);
        // What was durable before the failure stays readable.
        assert_eq!(all(&log, &Filter::All), vec![0, 1]);
    }

    #[test]
    fn a_torn_tail_is_moved_aside_and_corruption_refused() {
        let d = TestDir::new("alog-torn");
        let p = path(&d);
        let log = AccessLog::open(&p).unwrap();
        rt().block_on(log.durable(rec("a", 1))).unwrap();
        drop(log);
        let mut bytes = std::fs::read(&p).unwrap();
        bytes.extend_from_slice(&[7, 0, 0]);
        std::fs::write(&p, &bytes).unwrap();
        let log = AccessLog::open(&p).unwrap();
        assert_eq!(log.tip().0, 2);
        drop(log);
        let torn: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("torn-"))
            .collect();
        assert_eq!(torn.len(), 1);
        // Flip a byte inside the first record: corruption, not a tail.
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[journal::HEADER_LEN + 20] ^= 1;
        std::fs::write(&p, &bytes).unwrap();
        let err = AccessLog::open(&p).err().unwrap();
        assert!(err.to_string().contains("corrupt at record 0"), "{err}");
        let report = verify_file(&p, None);
        assert!(!report.ok);
        assert_eq!(report.first_bad, Some(0));
    }

    #[test]
    fn the_index_is_derived_and_never_trusted() {
        let d = TestDir::new("alog-index");
        let p = path(&d);
        let log = AccessLog::open(&p).unwrap();
        for i in 0..10 {
            log.submit(rec(&format!("r{}", i % 3), i));
        }
        rt().block_on(log.flush()).unwrap();
        drop(log);
        // A damaged or stale index does not matter: it is rebuilt.
        std::fs::write(index_path(&p), b"garbage").unwrap();
        let log = AccessLog::open(&p).unwrap();
        assert_eq!(all(&log, &Filter::Run("r1".into())), vec![2, 5, 8]);
        assert_eq!(
            std::fs::metadata(index_path(&p)).unwrap().len(),
            11 * INDEX_ENTRY as u64
        );
    }

    #[test]
    fn reads_examine_a_bounded_number_of_records() {
        let d = TestDir::new("alog-scan");
        let log = AccessLog::open(&path(&d)).unwrap();
        for i in 0..SCAN_LIMIT + 10 {
            log.submit(rec("busy", i));
        }
        log.submit(rec("quiet", 0));
        rt().block_on(log.flush()).unwrap();
        let quiet = Filter::Run("quiet".into());
        // The first page examines SCAN_LIMIT records, finds nothing and says
        // where to go on; the second finds the record.
        let (page, next) = log.read(None, 10, &quiet).unwrap();
        assert!(page.is_empty());
        assert_eq!(next, Some(SCAN_LIMIT - 1));
        let (page, next) = log.read(next, 10, &quiet).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, SCAN_LIMIT + 11);
        assert_eq!(next, None);
        // Out of scope, the same bound holds.
        let none = Filter::Scopes(vec!["nobody:".into()]);
        assert_eq!(log.read(None, 10, &none).unwrap().1, Some(SCAN_LIMIT - 1));
    }

    #[test]
    fn large_batches_are_written_in_chunks_that_each_verify() {
        let d = TestDir::new("alog-chunks");
        let p = path(&d);
        let log = AccessLog::open(&p).unwrap();
        let big = "u".repeat(1 << 20);
        let n = (WRITE_CHUNK >> 20) as u64 + 4;
        for i in 0..n {
            let mut r = rec("big", i);
            r.personal.insert("user_agent".into(), big.clone().into());
            log.submit(r);
        }
        rt().block_on(log.flush()).unwrap();
        assert_eq!(log.tip().0, n + 1);
        assert!(log.verify().ok);
        drop(log);
        let log = AccessLog::open(&p).unwrap();
        assert_eq!(all(&log, &Filter::Run("big".into())).len() as u64, n);
    }

    #[test]
    fn group_commit_batches_concurrent_records() {
        let d = TestDir::new("alog-batch");
        let log = AccessLog::open(&path(&d)).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = Instant::now();
        rt.block_on(async {
            let mut tasks = Vec::new();
            for i in 0..200 {
                let log = log.clone();
                tasks.push(tokio::spawn(async move { log.durable(rec("x", i)).await }));
            }
            for t in tasks {
                t.await.unwrap().unwrap();
            }
        });
        // 200 sequential fsyncs would take far longer on most disks; a few
        // group commits do not. Generous bound for slow CI machines.
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(log.tip().0, 201);
        assert_eq!(log.lag_seconds(), 0.0);
    }
}
