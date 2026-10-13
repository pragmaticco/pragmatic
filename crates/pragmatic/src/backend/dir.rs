//! [`DirBackend`]: one journal file per run in a local directory (spec
//! 3.3).
//!
//! # Files
//!
//! A run's files are named by `hex(SHA-256(run_id))`, so any run id maps to
//! a safe, fixed-length name:
//!
//! - `<64hex>.journal`: the journal. Never locked, so readers (snapshots,
//!   the CLI, the console) never wait and never block a writer.
//! - `<64hex>.lock`: the sidecar lock file. Created on first use and never
//!   renamed, truncated or read by readers; it holds the writer's pid, host
//!   and start time for diagnostics only.
//! - `<64hex>.torn-<unix_ms>`: a torn tail moved aside by a writer.
//! - `<64hex>.journal.tmp-*`: a temp file during creation or erasure.
//!
//! A format 1 journal (0.4 and 0.5) is found under its old name (the run id
//! with every character outside `[A-Za-z0-9_-]` replaced by `_`) only when
//! no hashed file exists, and is read-only.
//!
//! # Locking
//!
//! A checkout first claims the lock path in a process-global registry (so
//! two checkouts in one process conflict even where the OS would let one
//! process lock a file twice), then takes an exclusive `File::try_lock` on
//! the sidecar. A held lock is [`Fault::Locked`]; a filesystem without
//! locks is [`Fault::Unsupported`]. Locks give no exclusion across hosts on
//! network filesystems: use the server for that.
//!
//! # Durability
//!
//! The sink tracks the journal's byte length and entry count. Each persist
//! checks the file's size first (a mismatch is a conflict: someone else
//! wrote), writes every frame with one positioned write at the tracked
//! length, and fsyncs. If the write or the fsync fails, it truncates back to
//! the tracked length and refuses every later persist: an fsync failure
//! cannot be retried, because the kernel may already have dropped the dirty
//! pages it failed to write.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::fault::Fault;
use crate::journal::{
    header, validate_run_id, Journal, TornTail, FLAG_KEYED, FORMAT, FORMAT1_READ_ONLY, HEADER_LEN,
    MAGIC, MAX_RECORD_BYTES,
};
use crate::sha256::{hex, sha256, Digest, DIGEST_LEN};
use crate::sys;

use super::{check_frames, check_run_start, count_frames, Backend, Checkout, CheckoutGuard};
use super::{Sink, SinkError};

/// Bytes of diagnostics written at the start of a lock file.
const DIAG_LEN: usize = 256;

/// Journals as files in one directory.
#[derive(Clone, Debug)]
pub struct DirBackend {
    dir: PathBuf,
}

/// `hex(SHA-256(run_id))`, the stem of every file of a run.
pub fn hashed_name(run_id: &str) -> String {
    hex(&sha256(run_id.as_bytes()))
}

/// The format 1 file stem of a run id.
pub fn legacy_name(run_id: &str) -> String {
    run_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn is_hashed_name(stem: &str) -> bool {
    stem.len() == 64 && stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl DirBackend {
    /// A backend over `dir`, which is created if missing. The path is
    /// canonicalized so that two backends on the same directory, however
    /// spelled, share lock identities.
    pub fn new(dir: impl AsRef<Path>) -> Result<DirBackend, Fault> {
        fs::create_dir_all(dir.as_ref())?;
        Ok(DirBackend {
            dir: fs::canonicalize(dir.as_ref())?,
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The journal file of a run.
    pub fn journal_path(&self, run_id: &str) -> PathBuf {
        self.dir.join(format!("{}.journal", hashed_name(run_id)))
    }

    /// The lock file of a run.
    pub fn lock_path(&self, run_id: &str) -> PathBuf {
        self.dir.join(format!("{}.lock", hashed_name(run_id)))
    }

    /// Where a format 1 journal of this run would be.
    pub fn legacy_path(&self, run_id: &str) -> PathBuf {
        self.dir.join(format!("{}.journal", legacy_name(run_id)))
    }

    /// True if a format 1 journal of this run exists.
    fn has_legacy(&self, run_id: &str) -> bool {
        is_format1(&self.legacy_path(run_id))
    }
}

/// True if `path` is a file that starts with a format 1 header.
fn is_format1(path: &Path) -> bool {
    let mut head = [0u8; 12];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head[..8] == MAGIC
        && head[8..12] == 1u32.to_le_bytes()
}

impl Backend for DirBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        validate_run_id(run_id)?;
        let name = hashed_name(run_id);
        let path = self.journal_path(run_id);
        let (guard, held) = acquire_lock(&self.lock_path(run_id))?;
        // Everything below runs under the lock; an early return drops the
        // guard and releases it.
        remove_stale_temps(&self.dir, &name);
        let exists = fs::metadata(&path).is_ok_and(|m| m.len() >= HEADER_LEN as u64);
        if !exists {
            if self.has_legacy(run_id) {
                return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
            }
            if !create {
                return Err(Fault::Io(format!("no journal for run '{run_id}'")));
            }
            let flags = if key.is_some() { FLAG_KEYED } else { 0 };
            create_journal(&self.dir, &name, &path, flags)?;
        }
        let file = open_current(&path, || {})?;
        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes)?;
        let parsed = Journal::parse(&bytes, key)?;
        if parsed.journal.format() != FORMAT {
            return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
        }
        // The id check comes before any truncation: a tail is never cut off
        // a journal that belongs to another run.
        check_run_start(&parsed.journal, run_id, &path.display().to_string())?;
        let torn = if parsed.tail_len > 0 {
            let at_cursor = parsed.journal.len();
            Some(move_tail(
                &self.dir,
                &name,
                &file,
                &bytes,
                parsed.valid_len,
                at_cursor,
            )?)
        } else {
            None
        };
        let sink = DirSink {
            file,
            path,
            dir: self.dir.clone(),
            name,
            byte_len: parsed.valid_len,
            entries: parsed.journal.len(),
            held,
            failed: false,
        };
        let mut checkout = Checkout {
            journal: parsed.journal,
            sink: Box::new(sink),
            guard,
            torn: None,
        };
        checkout.record_torn(torn)?;
        Ok(checkout)
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        let path = self.journal_path(run_id);
        let (bytes, path) = match fs::read(&path) {
            Ok(bytes) => (bytes, path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let legacy = self.legacy_path(run_id);
                if !is_format1(&legacy) {
                    return Err(Fault::Io(format!("no journal for run '{run_id}'")));
                }
                (fs::read(&legacy)?, legacy)
            }
            Err(e) => return Err(e.into()),
        };
        let journal = Journal::parse(&bytes, key)?.journal;
        if journal.format() == FORMAT {
            check_run_start(&journal, run_id, &path.display().to_string())?;
        }
        Ok(journal)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(".journal")) else {
                continue;
            };
            let path = entry.path();
            if is_hashed_name(stem) {
                if let Some(id) = read_run_start(&path) {
                    if hashed_name(&id) == stem {
                        ids.push(id);
                    }
                }
            } else if is_format1(&path) {
                ids.push(stem.to_string());
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    #[cfg(any(test, feature = "testing"))]
    fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        let path = self.journal_path(run_id);
        let bytes = fs::read(&path)?;
        let len = super::prefix_len(&bytes, keep);
        let file = OpenOptions::new().write(true).open(&path)?;
        file.set_len(len as u64)?;
        file.sync_all()?;
        Ok(())
    }
}

/// The run id in the `run.start` note at the head of a journal file,
/// reading only the header and the first frame.
fn read_run_start(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut head = vec![0u8; HEADER_LEN + 4];
    file.read_exact(&mut head).ok()?;
    let len = u32::from_le_bytes(head[HEADER_LEN..].try_into().unwrap()) as u64;
    if len > MAX_RECORD_BYTES {
        return None;
    }
    let mut rest = vec![0u8; len as usize + DIGEST_LEN];
    file.read_exact(&mut rest).ok()?;
    head.extend_from_slice(&rest);
    crate::journal::first_run_start_id(&head)
}

// ---------------------------------------------------------------------------
// Locks
// ---------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lock paths held by checkouts in this process.
fn registry() -> MutexGuard<'static, HashSet<PathBuf>> {
    static HELD: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    lock(HELD.get_or_init(Default::default))
}

fn locked() -> Fault {
    Fault::Locked {
        retry_after_secs: None,
    }
}

/// Take the run's lock (spec 3.3 checkout steps 1 to 3). Returns the guard
/// that releases it and the flag sinks consult before writing.
fn acquire_lock(path: &Path) -> Result<(CheckoutGuard, Arc<Mutex<bool>>), Fault> {
    if !registry().insert(path.to_path_buf()) {
        return Err(locked());
    }
    let file = match lock_file(path) {
        Ok(file) => file,
        Err(fault) => {
            registry().remove(path);
            return Err(fault);
        }
    };
    let held = Arc::new(Mutex::new(true));
    let flag = held.clone();
    let path = path.to_path_buf();
    let guard = CheckoutGuard::new(move || {
        // Clearing the flag waits for any persist in flight (it holds the
        // flag's mutex while writing), so nothing is written after this.
        *lock(&flag) = false;
        let _ = file.unlock();
        drop(file);
        registry().remove(&path);
    });
    Ok((guard, held))
}

/// Open the sidecar lock file. `std` sets `O_CLOEXEC` (and makes Windows
/// handles non-inheritable), so a child process never inherits the lock.
fn open_lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn lock_file(path: &Path) -> Result<File, Fault> {
    let file = open_lock_file(path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(locked()),
        Err(TryLockError::Error(e)) if sys::lock_unsupported(&e) => {
            return Err(Fault::Unsupported(
                "journal directory does not support file locks".into(),
            ))
        }
        Err(TryLockError::Error(e)) => {
            return Err(Fault::Io(format!("cannot lock {}: {e}", path.display())))
        }
    }
    write_diagnostics(&file);
    Ok(file)
}

/// Record who holds the lock, overwriting in place (the lock file is never
/// truncated). Best effort: the lock is what matters, not this text.
fn write_diagnostics(file: &File) {
    let mut line = format!(
        "pid {} host {} started_unix_ms {}",
        std::process::id(),
        sys::host_name(),
        sys::now_unix_ms()
    )
    .into_bytes();
    line.truncate(DIAG_LEN - 1);
    line.resize(DIAG_LEN - 1, b' ');
    line.push(b'\n');
    let _ = sys::write_all_at(file, &line, 0);
}

// ---------------------------------------------------------------------------
// Files under the lock
// ---------------------------------------------------------------------------

fn temp_path(dir: &Path, name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        "{name}.journal.tmp-{}-{}-{n}",
        std::process::id(),
        crate::journal::system_clock()
    ))
}

/// Remove temp files a crashed creation or erasure left behind. Only called
/// under the run's lock, so no live writer owns them.
fn remove_stale_temps(dir: &Path, name: &str) {
    let prefix = format!("{name}.journal.tmp-");
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix))
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Create the journal with just its header: temp file, fsync, rename into
/// place, fsync the directory (spec 3.3 checkout step 4).
fn create_journal(dir: &Path, name: &str, path: &Path, flags: u32) -> Result<(), Fault> {
    let temp = temp_path(dir, name);
    let result = write_synced(&temp, &header(flags), path)
        .and_then(|()| sys::rename_replace(&temp, path))
        .and_then(|()| sys::fsync_dir(dir));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    Ok(result?)
}

/// Open `path` and make sure the handle is the file the path names now
/// (spec 3.3 checkout step 5). If the path was replaced between the open and
/// the check (an erasure's rename, say), open it again. `between` runs after
/// each open; tests use it to replace the file at the worst moment.
fn open_current(path: &Path, mut between: impl FnMut()) -> io::Result<File> {
    for _ in 0..8 {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        between();
        let opened = sys::file_id(&file)?;
        match sys::path_id(path) {
            Ok(now) if now == opened => return Ok(file),
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(format!(
        "{} keeps being replaced while it is opened",
        path.display()
    )))
}

/// Move the bytes past `valid_len` to `<name>.torn-<unix_ms>` and truncate
/// the journal to `valid_len` (spec 2.14). The copy is durable before the
/// truncation, so a crash between the two loses nothing.
fn move_tail(
    dir: &Path,
    name: &str,
    file: &File,
    bytes: &[u8],
    valid_len: u64,
    at_cursor: u64,
) -> Result<TornTail, Fault> {
    let tail = &bytes[valid_len as usize..];
    let mut ms = sys::now_unix_ms();
    let moved_to = loop {
        let moved_to = format!("{name}.torn-{ms}");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(&moved_to))
        {
            Ok(mut f) => {
                f.write_all(tail)?;
                f.sync_all()?;
                break moved_to;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => ms += 1,
            Err(e) => return Err(e.into()),
        }
    };
    sys::fsync_dir(dir)?;
    file.set_len(valid_len)?;
    file.sync_all()?;
    Ok(TornTail {
        offset: valid_len,
        bytes: tail.len() as u64,
        sha256: sha256(tail),
        moved_to,
        at_cursor,
    })
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

/// Places where tests inject failures and crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum FailPoint {
    /// Write half of the frames, then fail.
    PersistWrite,
    /// Fail the fsync after a complete write.
    PersistSync,
    /// Crash with the erasure temp file half written.
    TempPartial,
    /// Crash with the temp file written and fsynced, before the rename.
    TempWritten,
    /// Crash right after the rename, before the directory fsync.
    Renamed,
    /// Crash after the directory fsync, before the journal is reopened.
    DirSynced,
}

#[cfg(test)]
static FAIL_POINTS: Mutex<Vec<(PathBuf, FailPoint)>> = Mutex::new(Vec::new());

/// Arm `point` for the next operation on `path` (tests only).
#[cfg(test)]
pub(crate) fn arm(path: &Path, point: FailPoint) {
    lock(&FAIL_POINTS).push((path.to_path_buf(), point));
}

#[cfg(test)]
fn fire(path: &Path, point: FailPoint) -> bool {
    let mut points = lock(&FAIL_POINTS);
    match points.iter().position(|(p, f)| p == path && *f == point) {
        Some(i) => {
            points.remove(i);
            true
        }
        None => false,
    }
}

#[cfg(not(test))]
fn fire(_path: &Path, _point: FailPoint) -> bool {
    false
}

const INJECTED: &str = "injected failure";

fn injected() -> io::Error {
    io::Error::other(INJECTED)
}

/// A simulated crash leaves its files behind, as a real one would.
fn is_injected(e: &io::Error) -> bool {
    cfg!(test) && e.to_string() == INJECTED
}

fn crash_at(path: &Path, point: FailPoint) -> io::Result<()> {
    if fire(path, point) {
        Err(injected())
    } else {
        Ok(())
    }
}

/// Write `bytes` to a new file at `temp` and fsync it.
fn write_synced(temp: &Path, bytes: &[u8], journal: &Path) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(temp)?;
    if fire(journal, FailPoint::TempPartial) {
        f.write_all(&bytes[..bytes.len() / 2])?;
        return Err(injected());
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    crash_at(journal, FailPoint::TempWritten)
}

/// Persists a [`DirBackend`] checkout's frames.
struct DirSink {
    file: File,
    path: PathBuf,
    dir: PathBuf,
    name: String,
    /// The journal's length as this writer last left it.
    byte_len: u64,
    /// Entries in the journal as this writer last left it.
    entries: u64,
    /// False once the checkout guard has released the lock.
    held: Arc<Mutex<bool>>,
    /// Set by any write or fsync failure; every later call fails.
    failed: bool,
}

impl DirSink {
    fn failed_error() -> SinkError {
        SinkError::Io(io::Error::other(
            "an earlier write to this journal failed; check the run out again",
        ))
    }

    /// Undo a failed append as far as possible and refuse further writes.
    fn fail_append(&mut self) {
        self.failed = true;
        let _ = self.file.set_len(self.byte_len);
        let _ = self.file.sync_all();
    }

    /// Check that the file is still exactly what this writer left.
    fn check_size(&self) -> Result<(), SinkError> {
        let actual = self.file.metadata()?.len();
        if actual != self.byte_len {
            return Err(SinkError::Conflict {
                expected: self.byte_len,
                actual,
            });
        }
        Ok(())
    }

    /// Spec 2.13 step 3 and 4: temp file, fsync, rename over the journal,
    /// fsync the directory, reopen.
    fn replace(&self, bytes: &[u8]) -> io::Result<File> {
        let temp = temp_path(&self.dir, &self.name);
        if let Err(e) = write_synced(&temp, bytes, &self.path) {
            if !is_injected(&e) {
                let _ = fs::remove_file(&temp);
            }
            return Err(e);
        }
        if let Err(e) = sys::rename_replace(&temp, &self.path) {
            let _ = fs::remove_file(&temp);
            return Err(e);
        }
        crash_at(&self.path, FailPoint::Renamed)?;
        sys::fsync_dir(&self.dir)?;
        crash_at(&self.path, FailPoint::DirSynced)?;
        open_current(&self.path, || {})
    }
}

impl Sink for DirSink {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError> {
        // Hold the release flag for the whole write, so the guard cannot
        // release the lock halfway through.
        let held = Arc::clone(&self.held);
        let held = lock(&held);
        if !*held {
            return Err(SinkError::LeaseLost);
        }
        if self.failed {
            return Err(Self::failed_error());
        }
        if at != self.entries {
            return Err(SinkError::Conflict {
                expected: self.entries,
                actual: at,
            });
        }
        let n = check_frames(frames, head_after)?;
        if n == 0 {
            return Ok(());
        }
        self.check_size()?;
        let write = if fire(&self.path, FailPoint::PersistWrite) {
            let _ = sys::write_all_at(&self.file, &frames[..frames.len() / 2], self.byte_len);
            Err(injected())
        } else {
            sys::write_all_at(&self.file, frames, self.byte_len)
        };
        if let Err(e) = write {
            self.fail_append();
            return Err(SinkError::Io(e));
        }
        let sync = if fire(&self.path, FailPoint::PersistSync) {
            Err(injected())
        } else {
            self.file.sync_data()
        };
        if let Err(e) = sync {
            // Never retried: after a failed fsync the kernel may have
            // dropped the pages, so a second fsync could falsely succeed.
            self.fail_append();
            return Err(SinkError::Io(e));
        }
        self.byte_len += frames.len() as u64;
        self.entries += n;
        Ok(())
    }

    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError> {
        let held = Arc::clone(&self.held);
        let held = lock(&held);
        if !*held {
            return Err(SinkError::LeaseLost);
        }
        if self.failed {
            return Err(Self::failed_error());
        }
        self.check_size()?;
        let invalid = |m: &str| SinkError::Io(io::Error::new(io::ErrorKind::InvalidInput, m));
        if file.len() < HEADER_LEN || &file[..8] != MAGIC || file[8..12] != FORMAT.to_le_bytes() {
            return Err(invalid("rewrite needs a complete format 2 journal"));
        }
        let entries = count_frames(&file[HEADER_LEN..]).map_err(invalid)?;
        match self.replace(file) {
            Ok(reopened) => {
                self.file = reopened;
                self.byte_len = file.len() as u64;
                self.entries = entries;
                Ok(())
            }
            Err(e) => {
                // The journal on disk is either the old file or the new one,
                // both valid, but this sink no longer knows which.
                self.failed = true;
                Err(SinkError::Io(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::test_dir;
    use crate::journal::{note, Content, EraseSelector, ErasureNote, Event, SlotState, META, ROOT};

    fn run_start(id: &str) -> Event {
        Event::Note {
            kind: note::RUN_START.into(),
            data: format!("{{\"format\":2,\"run_id\":\"{id}\"}}"),
            payload: vec![],
        }
    }

    fn recv(v: &str) -> Event {
        Event::ChannelRecv {
            channel: "inbox".into(),
            value: Content::from(v),
        }
    }

    /// A run with `run.start` and `n` receives, persisted.
    fn seed(b: &DirBackend, id: &str, n: usize) {
        let mut co = b.checkout(id, true, None).unwrap();
        co.journal.append(META, run_start(id)).unwrap();
        for i in 0..n {
            co.journal
                .append(ROOT, recv(&format!("message {i}")))
                .unwrap();
        }
        co.persist().unwrap();
    }

    fn locked_fault() -> Fault {
        Fault::Locked {
            retry_after_secs: None,
        }
    }

    #[test]
    fn checkout_persist_snapshot_round_trip() {
        let dir = test_dir("dir-roundtrip");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "run-1", 3);
        let path = b.journal_path("run-1");
        assert!(path.file_name().unwrap().to_str().unwrap().len() == 64 + 8);
        assert!(b.lock_path("run-1").exists());
        let snap = b.snapshot("run-1", None).unwrap();
        assert_eq!(snap.len(), 4);
        assert!(snap.audit().is_ok());
        assert_eq!(snap.to_bytes(), fs::read(&path).unwrap());

        // Reopen and continue.
        let mut co = b.checkout("run-1", false, None).unwrap();
        assert_eq!(co.journal.head(), snap.head());
        co.journal.append(ROOT, recv("more")).unwrap();
        co.persist().unwrap();
        drop(co);
        assert_eq!(b.snapshot("run-1", None).unwrap().len(), 5);
    }

    #[test]
    fn lock_contention_in_one_process() {
        let dir = test_dir("dir-lock-local");
        let b = DirBackend::new(&*dir).unwrap();
        let co = b.checkout("r", true, None).unwrap();
        assert_eq!(b.checkout("r", false, None).unwrap_err(), locked_fault());
        // A second backend on the same directory, spelled differently.
        let other = DirBackend::new(dir.join(".")).unwrap();
        assert_eq!(other.checkout("r", true, None).unwrap_err(), locked_fault());
        // Snapshots never wait for the lock.
        assert!(other.snapshot("r", None).is_ok());
        // Other runs are independent.
        assert!(b.checkout("s", true, None).is_ok());
        drop(co);
        assert!(other.checkout("r", false, None).is_ok());
    }

    #[test]
    fn racing_threads_never_share_a_run() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        let dir = test_dir("dir-lock-race");
        let b = Arc::new(DirBackend::new(&*dir).unwrap());
        seed(&b, "race", 0);
        let inside = Arc::new(AtomicBool::new(false));
        let wins = Arc::new(AtomicU32::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (b, inside, wins) = (b.clone(), inside.clone(), wins.clone());
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        match b.checkout("race", false, None) {
                            Ok(mut co) => {
                                assert!(!inside.swap(true, Ordering::SeqCst), "two holders");
                                co.journal.append(ROOT, recv("x")).unwrap();
                                co.persist().unwrap();
                                inside.store(false, Ordering::SeqCst);
                                wins.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(Fault::Locked { .. }) => std::thread::yield_now(),
                            Err(other) => panic!("{other}"),
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let wins = wins.load(Ordering::SeqCst);
        assert!(wins > 0);
        let snap = b.snapshot("race", None).unwrap();
        assert_eq!(snap.len(), 1 + u64::from(wins));
        assert!(snap.audit().is_ok());
    }

    #[test]
    fn lock_is_released_when_checkout_fails() {
        let dir = test_dir("dir-lock-release");
        let b = DirBackend::new(&*dir).unwrap();
        assert!(matches!(
            b.checkout("missing", false, None),
            Err(Fault::Io(_))
        ));
        assert!(b.checkout("missing", true, None).is_ok());
    }

    #[test]
    fn stale_sink_refuses_after_release() {
        let dir = test_dir("dir-stale-sink");
        let b = DirBackend::new(&*dir).unwrap();
        let mut co = b.checkout("r", true, None).unwrap();
        co.journal.append(META, run_start("r")).unwrap();
        let (at, frames, head) = co
            .journal
            .pending()
            .map(|(a, f, h)| (a, f.to_vec(), h))
            .unwrap();
        let Checkout {
            mut sink, guard, ..
        } = co;
        drop(guard);
        assert!(matches!(
            sink.persist(at, &frames, &head),
            Err(SinkError::LeaseLost)
        ));
        assert!(matches!(sink.rewrite(&frames), Err(SinkError::LeaseLost)));
    }

    #[test]
    fn lock_file_records_diagnostics() {
        let dir = test_dir("dir-lock-diag");
        let b = DirBackend::new(&*dir).unwrap();
        let _co = b.checkout("r", true, None).unwrap();
        let text = fs::read_to_string(b.lock_path("r")).unwrap();
        assert_eq!(text.len(), DIAG_LEN);
        assert!(text.starts_with(&format!("pid {} host ", std::process::id())));
        assert!(text.contains("started_unix_ms "));
    }

    #[cfg(unix)]
    #[test]
    fn descriptors_are_close_on_exec() {
        use std::ffi::c_int;
        use std::os::fd::AsRawFd;
        extern "C" {
            fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        }
        const F_GETFD: c_int = 1;
        const FD_CLOEXEC: c_int = 1;
        let cloexec = |f: &File| {
            // SAFETY: F_GETFD takes no argument and only reads the flags of
            // a descriptor this test owns.
            let flags = unsafe { fcntl(f.as_raw_fd(), F_GETFD) };
            flags >= 0 && flags & FD_CLOEXEC != 0
        };
        let dir = test_dir("dir-cloexec");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 0);
        assert!(cloexec(&open_lock_file(&b.lock_path("r")).unwrap()));
        assert!(cloexec(&open_current(&b.journal_path("r"), || {}).unwrap()));
    }

    /// Not a test on its own: the child half of
    /// `lock_contention_across_processes`, run in a separate process.
    #[test]
    fn lock_helper_child() {
        let Ok(dir) = std::env::var("PRAGMATIC_TEST_LOCK_DIR") else {
            return;
        };
        let b = DirBackend::new(dir).unwrap();
        let co = b.checkout("shared", true, None).unwrap();
        println!("LOCK-HELPER-READY");
        io::stdout().flush().unwrap();
        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        drop(co);
    }

    #[test]
    fn lock_contention_across_processes() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let dir = test_dir("dir-lock-process");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::dir::tests::lock_helper_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PRAGMATIC_TEST_LOCK_DIR", &*dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = false;
        let mut line = String::new();
        while out.read_line(&mut line).unwrap() > 0 {
            if line.contains("LOCK-HELPER-READY") {
                ready = true;
                break;
            }
            line.clear();
        }
        assert!(ready, "the helper process never took the lock");

        // This process has no registry entry for the lock: the OS lock alone
        // must keep it out.
        let b = DirBackend::new(&*dir).unwrap();
        assert_eq!(
            b.checkout("shared", false, None).unwrap_err(),
            locked_fault()
        );

        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(b.checkout("shared", false, None).is_ok());
    }

    #[test]
    fn identity_mismatch_reopens() {
        let dir = test_dir("dir-identity");
        let path = dir.join("j");
        let replacement = dir.join("replacement");
        fs::write(&path, b"old").unwrap();
        fs::write(&replacement, b"new").unwrap();
        let mut replaced = false;
        let file = open_current(&path, || {
            if !replaced {
                replaced = true;
                sys::rename_replace(&replacement, &path).unwrap();
            }
        })
        .unwrap();
        assert!(replaced);
        let mut text = String::new();
        (&file).read_to_string(&mut text).unwrap();
        assert_eq!(text, "new");
        assert_eq!(sys::file_id(&file).unwrap(), sys::path_id(&path).unwrap());
    }

    #[test]
    fn run_id_collision_is_detected() {
        let dir = test_dir("dir-collision");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "alpha", 1);
        // Put alpha's journal where beta's would be: what a hash collision,
        // or a file copied under the wrong name, looks like.
        fs::copy(b.journal_path("alpha"), b.journal_path("beta")).unwrap();
        let before = fs::read(b.journal_path("beta")).unwrap();
        match b.checkout("beta", false, None) {
            Err(Fault::Io(m)) => assert!(m.contains("collides with 'alpha'"), "{m}"),
            other => panic!("expected a collision, got {other:?}"),
        }
        assert!(matches!(b.snapshot("beta", None), Err(Fault::Io(_))));
        assert_eq!(fs::read(b.journal_path("beta")).unwrap(), before);
        // list only reports ids whose hash matches the file name.
        assert_eq!(b.list().unwrap(), vec!["alpha".to_string()]);
    }

    #[test]
    fn short_journal_is_recreated_under_the_lock() {
        let dir = test_dir("dir-short");
        let b = DirBackend::new(&*dir).unwrap();
        fs::write(b.journal_path("r"), b"PRAG").unwrap();
        let mut co = b.checkout("r", true, None).unwrap();
        assert!(co.journal.is_empty());
        co.journal.append(META, run_start("r")).unwrap();
        co.persist().unwrap();
        drop(co);
        assert_eq!(b.snapshot("r", None).unwrap().len(), 1);
    }

    #[test]
    fn keyed_journal_needs_its_key() {
        let dir = test_dir("dir-keyed");
        let b = DirBackend::new(&*dir).unwrap();
        let mut co = b.checkout("k", true, Some(b"secret")).unwrap();
        assert!(co.journal.is_keyed());
        co.journal.append(META, run_start("k")).unwrap();
        co.persist().unwrap();
        drop(co);
        assert!(matches!(
            b.checkout("k", false, None),
            Err(Fault::Unsupported(_))
        ));
        assert!(matches!(b.snapshot("k", None), Err(Fault::Unsupported(_))));
        assert!(matches!(
            b.checkout("k", false, Some(b"other")),
            Err(Fault::Io(_))
        ));
        assert!(b.checkout("k", false, Some(b"secret")).is_ok());
    }

    #[test]
    fn format_1_is_found_by_its_old_name_and_read_only() {
        let dir = test_dir("dir-format1");
        let legacy = dir.join(format!("{}.journal", legacy_name("old run.1")));
        {
            let mut v1 = crate::journal_v1::Journal::create(&legacy).unwrap();
            v1.append(crate::journal_v1::Event::Clock { nanos: 5 })
                .unwrap();
            v1.sync().unwrap();
        }
        let before = fs::read(&legacy).unwrap();
        let b = DirBackend::new(&*dir).unwrap();
        let snap = b.snapshot("old run.1", None).unwrap();
        assert_eq!((snap.format(), snap.len()), (1, 1));
        assert!(snap.verify().is_ok());
        assert!(matches!(
            b.checkout("old_run_1", false, None),
            Err(Fault::Unsupported(m)) if m == FORMAT1_READ_ONLY
        ));
        assert!(matches!(
            b.checkout("old_run_1", true, None),
            Err(Fault::Unsupported(_))
        ));
        assert_eq!(fs::read(&legacy).unwrap(), before);
        assert!(!b.journal_path("old_run_1").exists());
        assert_eq!(b.list().unwrap(), vec!["old_run_1".to_string()]);
    }

    #[test]
    fn list_reads_ids_from_run_start() {
        let dir = test_dir("dir-list");
        let b = DirBackend::new(&*dir).unwrap();
        for id in ["b-run", "a:run", "c.run"] {
            seed(&b, id, 1);
        }
        // An empty journal has no id to report yet.
        drop(b.checkout("no-start", true, None).unwrap());
        fs::write(dir.join("unrelated.txt"), b"x").unwrap();
        assert_eq!(b.list().unwrap(), vec!["a:run", "b-run", "c.run"]);
    }

    #[test]
    fn conflict_when_the_file_changes_underneath() {
        let dir = test_dir("dir-conflict");
        let b = DirBackend::new(&*dir).unwrap();
        let mut co = b.checkout("r", true, None).unwrap();
        co.journal.append(META, run_start("r")).unwrap();
        co.persist().unwrap();
        let len = fs::metadata(b.journal_path("r")).unwrap().len();
        // Someone else appends behind the lock's back.
        OpenOptions::new()
            .append(true)
            .open(b.journal_path("r"))
            .unwrap()
            .write_all(b"rogue")
            .unwrap();
        co.journal.append(ROOT, recv("x")).unwrap();
        assert_eq!(
            co.persist().unwrap_err(),
            Fault::Conflict {
                expected: len,
                actual: len + 5
            }
        );
        // Nothing was written over the rogue bytes.
        assert_eq!(fs::metadata(b.journal_path("r")).unwrap().len(), len + 5);
    }

    #[test]
    fn failed_write_rolls_back_and_sticks() {
        for point in [FailPoint::PersistWrite, FailPoint::PersistSync] {
            let dir = test_dir("dir-fail-write");
            let b = DirBackend::new(&*dir).unwrap();
            seed(&b, "r", 1);
            let path = b.journal_path("r");
            let len = fs::metadata(&path).unwrap().len();
            let mut co = b.checkout("r", false, None).unwrap();
            co.journal.append(ROOT, recv("lost")).unwrap();
            arm(&path, point);
            assert!(matches!(co.persist(), Err(Fault::Io(_))));
            assert_eq!(fs::metadata(&path).unwrap().len(), len, "{point:?}");
            // Sticky: no retry, even though nothing is armed any more.
            assert!(matches!(co.persist(), Err(Fault::Io(_))));
            drop(co);
            assert_eq!(b.snapshot("r", None).unwrap().len(), 2);
        }
    }

    #[test]
    fn torn_tail_is_moved_aside_by_a_writer_only() {
        let dir = test_dir("dir-torn");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 2);
        let path = b.journal_path("r");
        let clean = fs::read(&path).unwrap();
        // A crash mid-append: a frame's first bytes, then nothing.
        let tail = [200u8, 0, 0, 0, 6, 1, 2, 3];
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&tail)
            .unwrap();
        let torn_file = fs::read(&path).unwrap();

        // Read-only consumers ignore the tail and never write.
        let snap = b.snapshot("r", None).unwrap();
        assert_eq!(
            (snap.len(), snap.audit().torn_bytes),
            (3, tail.len() as u64)
        );
        assert_eq!(fs::read(&path).unwrap(), torn_file);

        let co = b.checkout("r", false, None).unwrap();
        let torn = co.torn.clone().unwrap();
        assert_eq!(torn.offset, clean.len() as u64);
        assert_eq!(torn.bytes, tail.len() as u64);
        assert_eq!(torn.at_cursor, 3);
        assert_eq!(torn.sha256, sha256(&tail));
        assert!(torn
            .moved_to
            .starts_with(&format!("{}.torn-", hashed_name("r"))));
        assert_eq!(fs::read(dir.join(&torn.moved_to)).unwrap(), tail);
        let last = co.journal.entries().last().unwrap();
        assert_eq!(last.event.note_kind(), Some(note::TORN_TAIL));
        drop(co);

        let after = b.snapshot("r", None).unwrap();
        assert_eq!((after.len(), after.torn_bytes()), (4, 0));
        assert!(after.audit().is_ok());
        assert_eq!(&fs::read(&path).unwrap()[..clean.len()], &clean[..]);
    }

    #[test]
    fn zero_filled_tail_is_torn() {
        let dir = test_dir("dir-zero-tail");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 2);
        let path = b.journal_path("r");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0u8; 4096])
            .unwrap();
        let co = b.checkout("r", false, None).unwrap();
        assert_eq!(co.torn.as_ref().unwrap().bytes, 4096);
    }

    #[test]
    fn whole_journal_torn_leaves_an_empty_run() {
        let dir = test_dir("dir-torn-empty");
        let b = DirBackend::new(&*dir).unwrap();
        drop(b.checkout("r", true, None).unwrap());
        let path = b.journal_path("r");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[9, 0, 0])
            .unwrap();
        let co = b.checkout("r", false, None).unwrap();
        // No note: run.start must be the first entry of the run.
        assert!(co.journal.is_empty());
        assert_eq!(co.torn.as_ref().unwrap().at_cursor, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), HEADER_LEN as u64);
    }

    #[test]
    fn corruption_is_never_truncated() {
        let dir = test_dir("dir-corrupt");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 4);
        let path = b.journal_path("r");
        let mut bytes = fs::read(&path).unwrap();
        // Flip a bit in the length of the second frame.
        let first_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let second = 16 + 4 + first_len + 32;
        bytes[second + 1] ^= 0x10;
        fs::write(&path, &bytes).unwrap();
        match b.checkout("r", false, None) {
            Err(Fault::Io(m)) => assert!(m.contains("corrupt at cursor 1"), "{m}"),
            other => panic!("expected corruption, got {other:?}"),
        }
        assert!(b.snapshot("r", None).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(fs::read_dir(&*dir).unwrap().flatten().all(|e| !e
            .file_name()
            .to_str()
            .unwrap()
            .contains(".torn-")));
    }

    /// Seed a run whose third slot repeats a large message, then erase it
    /// with `point` armed; return the backend and the bytes before erasure.
    fn erase_with_crash(dir: &Path, point: FailPoint) -> (DirBackend, Vec<u8>) {
        let b = DirBackend::new(dir).unwrap();
        seed(&b, "r", 2);
        let path = b.journal_path("r");
        let before = fs::read(&path).unwrap();
        let mut co = b.checkout("r", false, None).unwrap();
        arm(&path, point);
        let result = co.erase(
            &EraseSelector::Slots(vec![(1, 0)]),
            &ErasureNote::local("test", "crash test"),
        );
        assert!(result.is_err(), "{point:?} did not fire");
        drop(co);
        (b, before)
    }

    #[test]
    fn erasure_survives_a_crash_at_every_step() {
        for point in [FailPoint::TempPartial, FailPoint::TempWritten] {
            let dir = test_dir("dir-erase-crash-early");
            let (b, before) = erase_with_crash(&dir, point);
            // The journal is untouched; the temp file is cleaned up by the
            // next writer.
            assert_eq!(fs::read(b.journal_path("r")).unwrap(), before);
            let mut co = b.checkout("r", false, None).unwrap();
            assert!(fs::read_dir(&*dir).unwrap().flatten().all(|e| !e
                .file_name()
                .to_str()
                .unwrap()
                .contains(".tmp-")));
            assert!(co.journal.audit().is_ok());
            // Repairable: erasing again completes.
            co.erase(
                &EraseSelector::Slots(vec![(1, 0)]),
                &ErasureNote::local("test", "again"),
            )
            .unwrap();
            drop(co);
            let snap = b.snapshot("r", None).unwrap();
            assert!(snap.audit().is_ok());
            assert_eq!(snap.entries()[1].slots[0].state, SlotState::Erased);
        }
        for point in [FailPoint::Renamed, FailPoint::DirSynced] {
            let dir = test_dir("dir-erase-crash-late");
            let (b, before) = erase_with_crash(&dir, point);
            // The new file is in place: hashes unchanged, erasure accounted.
            let snap = b.snapshot("r", None).unwrap();
            assert_eq!(snap.len(), 4);
            assert!(snap.audit().is_ok(), "{point:?}: {:?}", snap.audit());
            assert_eq!(snap.entries()[1].slots[0].state, SlotState::Erased);
            let old = Journal::parse(&before, None).unwrap().journal;
            for (o, n) in old.entries().iter().zip(snap.entries()) {
                assert_eq!(o.hash, n.hash);
            }
            let mut co = b.checkout("r", false, None).unwrap();
            co.journal.append(ROOT, recv("after")).unwrap();
            co.persist().unwrap();
        }
    }

    #[test]
    fn rewrite_reopens_the_journal() {
        let dir = test_dir("dir-rewrite-reopen");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 2);
        let path = b.journal_path("r");
        let id_before = sys::path_id(&path).unwrap();
        let mut co = b.checkout("r", false, None).unwrap();
        co.erase(&EraseSelector::All, &ErasureNote::local("shred", ""))
            .unwrap();
        assert_ne!(sys::path_id(&path).unwrap(), id_before);
        // Appends after the erasure go to the new file.
        co.journal.append(ROOT, recv("after erasure")).unwrap();
        co.persist().unwrap();
        drop(co);
        let snap = b.snapshot("r", None).unwrap();
        assert_eq!(snap.len(), 5);
        assert!(snap.audit().is_ok());
        assert!(snap.entries()[4].event.slot_contents()[0].is_sealed());
    }

    #[test]
    fn crash_truncate_keeps_a_prefix() {
        let dir = test_dir("dir-crash-truncate");
        let b = DirBackend::new(&*dir).unwrap();
        seed(&b, "r", 3);
        b.crash_truncate("r", 2).unwrap();
        let snap = b.snapshot("r", None).unwrap();
        assert_eq!((snap.len(), snap.torn_bytes()), (2, 0));
    }
}
