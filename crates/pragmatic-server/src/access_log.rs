//! The access log (design 4.11): one record per request, in a journal of
//! its own (`<data_dir>/audit/access.journal`, journal format 2).
//!
//! # Records
//!
//! Each record is a note on the meta branch. Its `data` holds the
//! structural fields (token id, role, method, route template, run id,
//! status, raw, cursors, query parameter *names*), and its one payload
//! slot holds the fields that identify a person (principal, source address,
//! user agent), so they can be erased like any other content while the
//! chain still verifies. Query-string values are never logged: they can
//! carry search terms, and a search term can be personal data.
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
//!
//! # Failing closed
//!
//! If a write or fsync fails, the log is marked failed for good (an fsync
//! failure cannot be retried: the kernel may already have dropped the
//! pages), and every authenticated request is refused with 503
//! `storage_unavailable` until the server is restarted. A server that
//! cannot record who read what must not serve anything.
//!
//! The log only grows: it is never shredded by retention policies. It is
//! not held in memory: the writer keeps the chain's tail
//! ([`NoteAppender`]), and reads go to the file through an index of frame
//! offsets.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use pragmatic::journal::{self, decode_frame, split_frames, NoteAppender};
use pragmatic::sha256::Digest;
use pragmatic::{Event, Journal, Value};
use serde_json::{Map, Value as JsonValue};

use crate::fsutil;
use crate::timefmt;

/// The longest the writer waits after its last fsync before the next one.
pub const GROUP_COMMIT: Duration = Duration::from_millis(50);

/// The reserved run id of the access log's `run.start` note.
pub const ACCESS_LOG_RUN_ID: &str = "pragmatic:access-log";

/// `<data_dir>/audit/access.journal`.
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("audit").join("access.journal")
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

enum Msg {
    Record(Box<AccessRecord>, Option<Ack>),
    Flush(Ack),
}

/// Byte offsets and runs of the durable records, for serving reads.
#[derive(Default)]
struct Index {
    /// `(offset, length)` of each frame, by cursor.
    frames: Vec<(u64, u32)>,
    /// Interned run id of each record (`u32::MAX` for none).
    runs: Vec<u32>,
    names: Vec<String>,
    by_name: HashMap<String, u32>,
    head: Digest,
}

impl Index {
    fn push(&mut self, offset: u64, len: u32, run: Option<&str>) {
        self.frames.push((offset, len));
        let id = match run {
            None => u32::MAX,
            Some(name) => match self.by_name.get(name) {
                Some(&i) => i,
                None => {
                    let i = self.names.len() as u32;
                    self.names.push(name.to_string());
                    self.by_name.insert(name.to_string(), i);
                    i
                }
            },
        };
        self.runs.push(id);
    }

    fn run(&self, cursor: usize) -> Option<&str> {
        match self.runs.get(cursor) {
            Some(&u32::MAX) | None => None,
            Some(&i) => Some(self.names[i as usize].as_str()),
        }
    }
}

struct Shared {
    failed: AtomicBool,
    reason: Mutex<Option<String>>,
    queued: AtomicU64,
    oldest_ns: AtomicU64,
    index: RwLock<Index>,
    inject_failure: AtomicBool,
}

/// The access log: a handle to its writer thread and its index.
#[derive(Clone)]
pub struct AccessLog {
    tx: Sender<Msg>,
    shared: Arc<Shared>,
    file: Arc<File>,
}

/// One record as the API serves it.
pub type RecordView = Map<String, JsonValue>;

/// Records read back: `(cursor, run id, entry)`, and the cursor to continue
/// after when more may follow.
pub type ReadPage = (Vec<(u64, Option<String>, journal::Entry)>, Option<u64>);

impl AccessLog {
    /// Open (or create) the log at `path` and start its writer thread.
    ///
    /// The whole file is verified once. A torn tail (a crash during a
    /// write) is moved aside to `access.journal.torn-<unix_ms>` and
    /// truncated; corruption is an error, and the server refuses to start
    /// rather than append to a log whose history it cannot vouch for.
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
        let len = file.metadata()?.len();
        let (appender, index) = if len == 0 {
            create(&file)?
        } else {
            recover(path, &file, len)?
        };
        let shared = Arc::new(Shared {
            failed: AtomicBool::new(false),
            reason: Mutex::new(None),
            queued: AtomicU64::new(0),
            oldest_ns: AtomicU64::new(0),
            index: RwLock::new(index),
            inject_failure: AtomicBool::new(false),
        });
        let file = Arc::new(file);
        let (tx, rx) = mpsc::channel();
        let writer = Writer {
            rx,
            file: file.clone(),
            appender,
            shared: shared.clone(),
            last_sync: Instant::now() - GROUP_COMMIT,
        };
        std::thread::Builder::new()
            .name("pragmatic-access-log".into())
            .spawn(move || writer.run())?;
        Ok(AccessLog { tx, shared, file })
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
        let index = self.shared.index.read().expect("index lock");
        (index.frames.len() as u64, index.head)
    }

    /// TEST ONLY: make every later write fail, as a full or failing disk
    /// would.
    #[cfg(any(test, feature = "testing"))]
    pub fn inject_write_failure(&self) {
        self.shared.inject_failure.store(true, Ordering::SeqCst);
    }

    /// Up to `limit` durable records after cursor `after` (from the start
    /// when `None`) whose run passes `keep`. Returns the records and the
    /// cursor to continue after, if more may follow.
    pub fn read(
        &self,
        after: Option<u64>,
        limit: usize,
        keep: impl Fn(Option<&str>) -> bool,
    ) -> io::Result<ReadPage> {
        let picks: Vec<(u64, u64, u32, Option<String>)> = {
            let index = self.shared.index.read().expect("index lock");
            let start = after.map_or(0, |a| a + 1) as usize;
            let mut picks = Vec::new();
            for c in start..index.frames.len() {
                let run = index.run(c);
                if keep(run) {
                    let (off, len) = index.frames[c];
                    picks.push((c as u64, off, len, run.map(str::to_string)));
                    if picks.len() > limit {
                        break;
                    }
                }
            }
            picks
        };
        let more = picks.len() > limit;
        let mut out = Vec::with_capacity(limit.min(picks.len()));
        for (cursor, off, len, run) in picks.into_iter().take(limit) {
            let mut buf = vec![0u8; len as usize];
            fsutil::read_exact_at(&self.file, &mut buf, off)?;
            let entry = decode_frame(&buf, cursor)
                .map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))?;
            out.push((cursor, run, entry));
        }
        let next = if more {
            out.last().map(|(c, _, _)| *c)
        } else {
            None
        };
        Ok((out, next))
    }
}

/// The JSON view of a record: cursor, time, kind, structural fields and,
/// from the payload, the personal ones.
pub fn record_view(cursor: u64, entry: &journal::Entry) -> RecordView {
    let mut out = Map::new();
    out.insert("cursor".into(), cursor.into());
    out.insert("at".into(), timefmt::rfc3339_ns(entry.at).into());
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

/// Start a new log: header, then the `run.start` note.
fn create(file: &File) -> io::Result<(NoteAppender, Index)> {
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
    let mut index = Index::default();
    index.push(offset, frame.len() as u32, None);
    index.head = appender.head();
    Ok((appender, index))
}

/// Verify an existing log, move a torn tail aside, and index it.
fn recover(path: &Path, file: &File, len: u64) -> io::Result<(NoteAppender, Index)> {
    let bytes = fsutil::read_prefix(file, len)?;
    let parsed = Journal::parse(&bytes, None).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("access log {}: {e}", path.display()),
        )
    })?;
    if parsed.tail_len > 0 {
        let tail = &bytes[parsed.valid_len as usize..];
        let aside = path.with_extension(format!(
            "journal.torn-{}",
            timefmt::now_unix_ns() / 1_000_000
        ));
        fsutil::write_atomic(&aside, tail)?;
        file.set_len(parsed.valid_len)?;
        file.sync_all()?;
    }
    let journal = parsed.journal;
    let appender = NoteAppender::after(&journal).map_err(io::Error::other)?;
    let frames = split_frames(&bytes[journal::HEADER_LEN..parsed.valid_len as usize])
        .map_err(|(_, why)| io::Error::new(io::ErrorKind::InvalidData, why))?;
    let mut index = Index::default();
    let mut offset = journal::HEADER_LEN as u64;
    for (frame, entry) in frames.iter().zip(journal.entries()) {
        let run = note_run_id(&entry.event);
        index.push(offset, frame.len() as u32, run.as_deref());
        offset += frame.len() as u64;
    }
    index.head = journal.head();
    Ok((appender, index))
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
    appender: NoteAppender,
    shared: Arc<Shared>,
    last_sync: Instant,
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

    /// Encode, write and fsync one batch, then answer every waiter.
    fn commit(&mut self, batch: Vec<Msg>) {
        if self.shared.failed.load(Ordering::SeqCst) {
            let why = self.shared.reason.lock().expect("reason lock").clone();
            return answer_all(batch, Err(Unavailable(why.unwrap_or_default())));
        }
        let before = self.appender.clone();
        let mut bytes = Vec::new();
        let mut placed: Vec<(u64, u32, Option<String>)> = Vec::new();
        let mut cursors: Vec<Option<u64>> = Vec::with_capacity(batch.len());
        for msg in &batch {
            let Msg::Record(record, _) = msg else {
                cursors.push(None);
                continue;
            };
            match self.encode(record) {
                Ok((cursor, frame)) => {
                    let offset = before.byte_len() + bytes.len() as u64;
                    placed.push((offset, frame.len() as u32, record.run_id.clone()));
                    bytes.extend_from_slice(&frame);
                    cursors.push(Some(cursor));
                }
                Err(why) => return self.fail(batch, before, why),
            }
        }
        if !bytes.is_empty() {
            if let Err(e) = self.write(&bytes, before.byte_len()) {
                return self.fail(batch, before, format!("access log write failed: {e}"));
            }
        }
        {
            let mut index = self.shared.index.write().expect("index lock");
            for (offset, len, run) in placed {
                index.push(offset, len, run.as_deref());
            }
            index.head = self.appender.head();
        }
        let durable = self.appender.entries().saturating_sub(1);
        for (msg, cursor) in batch.into_iter().zip(cursors) {
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
    }

    fn encode(&mut self, record: &AccessRecord) -> Result<(u64, Vec<u8>), String> {
        let data = JsonValue::Object(record.data.clone()).to_string();
        let payload = if record.personal.is_empty() {
            Vec::new()
        } else {
            vec![Value::from(
                JsonValue::Object(record.personal.clone()).to_string(),
            )]
        };
        self.appender
            .append(timefmt::now_unix_ns(), &record.kind, &data, &payload)
            .map_err(|f| format!("access record could not be encoded: {f}"))
    }

    fn write(&self, bytes: &[u8], offset: u64) -> io::Result<()> {
        if self.shared.inject_failure.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected write failure"));
        }
        fsutil::write_all_at(&self.file, bytes, offset)?;
        self.file.sync_data()
    }

    /// Mark the log failed for good, roll the file back to its last durable
    /// length, and refuse every waiter.
    fn fail(&mut self, batch: Vec<Msg>, before: NoteAppender, why: String) {
        let _ = self.file.set_len(before.byte_len());
        let _ = self.file.sync_all();
        self.appender = before;
        *self.shared.reason.lock().expect("reason lock") = Some(why.clone());
        self.shared.failed.store(true, Ordering::SeqCst);
        answer_all(batch, Err(Unavailable(why)));
    }
}

fn answer_all(batch: Vec<Msg>, result: Result<u64, Unavailable>) {
    for msg in batch {
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
        let (all, next) = log.read(None, 100, |_| true).unwrap();
        assert_eq!(all.len(), 7);
        assert_eq!(next, None);
        assert_eq!(all[0].2.event.note_kind(), Some("run.start"));
        let (only_a, _) = log.read(None, 100, |r| r == Some("a")).unwrap();
        assert_eq!(only_a.len(), 4);
        let view = record_view(only_a[0].0, &only_a[0].2);
        assert_eq!(view["run_id"], "a");
        assert_eq!(view["source_ip"], "203.0.113.9");
        assert_eq!(view["kind"], "request");
        let (page, next) = log.read(None, 2, |_| true).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(next, Some(1));

        // Reopen: the file verifies and continues.
        drop(log);
        let log = AccessLog::open(&p).unwrap();
        assert_eq!(log.tip().0, 7);
        rt.block_on(log.durable(rec("c", 1))).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        let parsed = Journal::parse(&bytes, None).unwrap();
        assert_eq!(parsed.journal.len(), 8);
        assert_eq!(parsed.journal.head(), log.tip().1);
    }

    #[test]
    fn a_write_failure_fails_closed_for_good() {
        let d = TestDir::new("alog-fail");
        let log = AccessLog::open(&path(&d)).unwrap();
        let rt = rt();
        rt.block_on(log.durable(rec("a", 1))).unwrap();
        log.inject_write_failure();
        assert!(rt.block_on(log.durable(rec("a", 2))).is_err());
        assert!(log.is_failed());
        log.shared.inject_failure.store(false, Ordering::SeqCst);
        // Sticky: even once writes would work again.
        assert!(rt.block_on(log.durable(rec("a", 3))).is_err());
        let bytes = std::fs::read(path(&d)).unwrap();
        assert_eq!(Journal::parse(&bytes, None).unwrap().journal.len(), 2);
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
        assert!(AccessLog::open(&p).is_err());
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
