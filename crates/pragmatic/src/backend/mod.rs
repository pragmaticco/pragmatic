//! Where journals live: backends and sinks (spec 3.3).
//!
//! A [`Backend`] hands out journals. A *checkout* takes the run's write lock
//! (or server lease), reads the journal and returns it together with a
//! [`Sink`] that persists new frames and a [`CheckoutGuard`] that releases
//! the lock when dropped. A *snapshot* reads the durable prefix without any
//! lock and never writes, which is what auditors, the CLI and strict replay
//! use.
//!
//! The journal itself ([`Journal`]) is a pure in-memory value; all I/O goes
//! through these traits, so the same runtime works over local files
//! ([`DirBackend`]), memory ([`MemoryBackend`]) or a server.
//!
//! # Torn tails
//!
//! Only a lock holder may truncate a torn tail (spec 2.14). A checkout that
//! finds one moves the tail bytes aside, truncates the journal to its valid
//! length, and reports what it did in [`Checkout::torn`]. When the valid
//! prefix is not empty it also appends and persists a `torn_tail` note, so
//! the journal itself records the truncation; when the prefix is empty the
//! next `run.start` must come first, and the report travels in
//! `attempt.start` instead.

mod dir;
mod memory;

pub use dir::DirBackend;
pub use memory::MemoryBackend;

use std::fmt;
use std::io;

use crate::fault::Fault;
use crate::journal::{Cursor, EraseSelector, ErasureNote, Journal, TornTail};
use crate::sha256::{Digest, DIGEST_LEN};

/// A store of journals, one per run id.
///
/// Methods take `&self` and implementations are `Send + Sync`, so one
/// backend can serve every thread of a process. Internal locks are held only
/// inside these calls, never across agent code.
pub trait Backend: Send + Sync {
    /// Take the run's write lock and read its journal. With `create`, a
    /// missing journal is created (keyed when `key` is given). A second
    /// checkout of a run that is already checked out is
    /// [`Fault::Locked`].
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault>;

    /// Read the run's durable prefix without a lock. Never writes: a torn
    /// tail is ignored, not truncated.
    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault>;

    /// Every run id the backend holds.
    fn list(&self) -> Result<Vec<String>, Fault>;

    /// True for backends whose runs live on a server. Recovery then has no
    /// default for an effect left without a result: a resumed run needs an
    /// explicit policy ([`Fault::DanglingEffect`] otherwise), because other
    /// processes may have acted on the run in the meantime.
    fn is_remote(&self) -> bool {
        false
    }

    /// TEST ONLY: keep the first `keep` entries of the stored journal, as if
    /// the process had crashed with only that prefix durable.
    #[cfg(any(test, feature = "testing"))]
    fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        let _ = (run_id, keep);
        Err(Fault::Unsupported(
            "this backend cannot simulate crashes".into(),
        ))
    }
}

/// Where a checked-out journal's new frames go.
pub trait Sink: Send {
    /// Durably append `frames`, the encoded frames of entries `at..`, whose
    /// last hash is `head_after`. Either every frame is durable when this
    /// returns `Ok`, or the stored journal is left as it was.
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError>;

    /// Atomically replace the whole journal with `file`. Used only by
    /// erasure and truncation.
    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError>;
}

/// Why a sink could not persist.
#[derive(Debug)]
pub enum SinkError {
    /// An I/O error. The sink should be considered failed.
    Io(io::Error),
    /// The stored journal is not what this writer last saw.
    Conflict { expected: u64, actual: u64 },
    /// Another writer holds the run.
    Locked { retry_after_secs: Option<u64> },
    /// The lease or lock was released or taken over.
    LeaseLost,
    /// The request exceeds the store's limit.
    TooLarge { limit: u64 },
    /// The run was deleted.
    Deleted,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinkError::Io(e) => write!(f, "io error: {e}"),
            SinkError::Conflict { expected, actual } => {
                write!(f, "conflict: expected {expected}, found {actual}")
            }
            SinkError::Locked {
                retry_after_secs: Some(s),
            } => write!(f, "locked (retry after {s}s)"),
            SinkError::Locked {
                retry_after_secs: None,
            } => write!(f, "locked"),
            SinkError::LeaseLost => write!(f, "lease lost"),
            SinkError::TooLarge { limit } => write!(f, "too large (limit {limit} bytes)"),
            SinkError::Deleted => write!(f, "deleted"),
        }
    }
}

impl std::error::Error for SinkError {}

impl From<io::Error> for SinkError {
    fn from(e: io::Error) -> Self {
        SinkError::Io(e)
    }
}

impl SinkError {
    /// The fault for this error, given the size of what was being written
    /// (reported by [`Fault::TooLarge`]).
    pub fn into_fault(self, size: u64) -> Fault {
        match self {
            SinkError::Io(e) => Fault::Io(e.to_string()),
            SinkError::Conflict { expected, actual } => Fault::Conflict { expected, actual },
            SinkError::Locked { retry_after_secs } => Fault::Locked { retry_after_secs },
            SinkError::LeaseLost => Fault::LeaseLost,
            SinkError::TooLarge { limit } => Fault::TooLarge { size, limit },
            SinkError::Deleted => Fault::Deleted,
        }
    }
}

impl From<SinkError> for Fault {
    /// See [`SinkError::into_fault`]; the size of a `TooLarge` is reported
    /// as 0.
    fn from(e: SinkError) -> Fault {
        e.into_fault(0)
    }
}

/// Releases a checkout's lock or lease when dropped.
///
/// Release happens whatever else still holds references to the journal or
/// sink: sinks share the release with their guard and refuse to write
/// ([`SinkError::LeaseLost`]) once it has happened.
pub struct CheckoutGuard {
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl CheckoutGuard {
    /// A guard that runs `release` exactly once, on drop or on
    /// [`release`](Self::release).
    pub fn new(release: impl FnOnce() + Send + 'static) -> CheckoutGuard {
        CheckoutGuard {
            release: Some(Box::new(release)),
        }
    }

    /// Release now.
    pub fn release(mut self) {
        self.run();
    }

    fn run(&mut self) {
        if let Some(f) = self.release.take() {
            f();
        }
    }
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        self.run();
    }
}

impl fmt::Debug for CheckoutGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckoutGuard")
            .field("held", &self.release.is_some())
            .finish()
    }
}

/// A checked-out journal: the journal, where its frames go, and the guard
/// that holds the run.
pub struct Checkout {
    /// The journal's valid prefix, everything persisted.
    pub journal: Journal,
    /// Persists new frames.
    pub sink: Box<dyn Sink>,
    /// Holds the lock or lease until dropped.
    pub guard: CheckoutGuard,
    /// The torn tail this checkout truncated, if any. Its size and cursor
    /// belong in the next `attempt.start` (`torn_bytes`, `torn_at_cursor`).
    pub torn: Option<TornTail>,
}

impl fmt::Debug for Checkout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkout")
            .field("journal", &self.journal)
            .field("guard", &self.guard)
            .field("torn", &self.torn)
            .finish()
    }
}

impl Checkout {
    /// Persist the journal's pending frames through the sink.
    pub fn persist(&mut self) -> Result<(), Fault> {
        let Some((at, frames, head)) = self.journal.pending() else {
            return Ok(());
        };
        let size = frames.len() as u64;
        let upto = self.journal.len();
        self.sink
            .persist(at, frames, &head)
            .map_err(|e| e.into_fault(size))?;
        self.journal.mark_persisted(upto);
        Ok(())
    }

    /// Erase slots (spec 2.13): build and validate the new file, commit it
    /// atomically through the sink, and continue with the erased journal.
    /// Returns the slots that changed from sealed to erased.
    pub fn erase(
        &mut self,
        what: &EraseSelector,
        note: &ErasureNote,
    ) -> Result<Vec<(Cursor, u8)>, Fault> {
        let erasure = self.journal.erase(what, note, self.journal.now())?;
        self.sink
            .rewrite(&erasure.file)
            .map_err(|e| e.into_fault(erasure.file.len() as u64))?;
        self.journal = erasure.journal;
        Ok(erasure.slots)
    }

    /// Record a torn tail this checkout truncated: keep the report, and when
    /// the journal already has entries, append and persist the `torn_tail`
    /// note.
    fn record_torn(&mut self, torn: Option<TornTail>) -> Result<(), Fault> {
        if let Some(t) = &torn {
            if !self.journal.is_empty() {
                self.journal.append_torn_tail(self.journal.now(), t)?;
                self.persist()?;
            }
        }
        self.torn = torn;
        Ok(())
    }
}

/// Check that a journal belongs to `run_id`: a non-empty journal must start
/// with a `run.start` note naming exactly that id. Two runs whose ids hash
/// to the same file name, or a file copied under the wrong name, fail here
/// instead of being written into.
fn check_run_start(journal: &Journal, run_id: &str, location: &str) -> Result<(), Fault> {
    if journal.is_empty() {
        return Ok(());
    }
    match journal.run_start_id() {
        Some(id) if id == run_id => Ok(()),
        Some(other) => Err(Fault::Io(format!(
            "run id collides with '{other}', recorded in {location}"
        ))),
        None => Err(Fault::Io(format!(
            "the journal at {location} does not begin with a run.start note"
        ))),
    }
}

/// The number of whole frames in `frames`, or an error if the bytes do not
/// split exactly into frames.
fn count_frames(frames: &[u8]) -> Result<u64, &'static str> {
    let mut pos = 0usize;
    let mut n = 0u64;
    while pos < frames.len() {
        if frames.len() - pos < 4 {
            return Err("frames end in a partial length prefix");
        }
        let len = u32::from_le_bytes(frames[pos..pos + 4].try_into().unwrap()) as usize;
        let end = pos
            .checked_add(4 + len + DIGEST_LEN)
            .filter(|&e| e <= frames.len())
            .ok_or("frames end in a partial frame")?;
        pos = end;
        n += 1;
    }
    Ok(n)
}

/// Check what a sink was handed: whole frames, the last of which carries
/// `head_after`. Returns the frame count.
fn check_frames(frames: &[u8], head_after: &Digest) -> Result<u64, SinkError> {
    let invalid = |m: &str| SinkError::Io(io::Error::new(io::ErrorKind::InvalidInput, m));
    let n = count_frames(frames).map_err(invalid)?;
    if n > 0 && &frames[frames.len() - DIGEST_LEN..] != head_after {
        return Err(invalid("head_after is not the hash of the last frame"));
    }
    Ok(n)
}

/// The byte offset where entry `keep` starts in a stored journal (the file
/// length after keeping `keep` entries), found by walking frame lengths so
/// no key is needed.
#[cfg(any(test, feature = "testing"))]
fn prefix_len(bytes: &[u8], keep: u64) -> usize {
    let v1 = bytes.get(8..12) == Some(&1u32.to_le_bytes()[..]);
    let mut pos = if v1 { 12 } else { crate::journal::HEADER_LEN }.min(bytes.len());
    for _ in 0..keep {
        let Some(len) = bytes.get(pos..pos + 4) else {
            break;
        };
        let end = pos + 4 + u32::from_le_bytes(len.try_into().unwrap()) as usize + DIGEST_LEN;
        if end > bytes.len() {
            break;
        }
        pos = end;
    }
    pos
}

/// A fresh, empty directory for one test, removed again on drop.
#[cfg(test)]
pub(crate) struct TestDir(std::path::PathBuf);

#[cfg(test)]
pub(crate) fn test_dir(name: &str) -> TestDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("pragmatic-test-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    TestDir(path)
}

#[cfg(test)]
impl std::ops::Deref for TestDir {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{note, Event, META};

    #[test]
    fn frames_are_counted_exactly() {
        let mut j = Journal::new(None);
        for i in 0..3 {
            j.append(
                META,
                Event::Note {
                    kind: note::ATTEMPT_START.into(),
                    data: format!("{{\"attempt\":{i}}}"),
                    payload: vec![],
                },
            )
            .unwrap();
        }
        let (_, frames, head) = j.pending().unwrap();
        assert_eq!(count_frames(frames), Ok(3));
        assert_eq!(check_frames(frames, &head).unwrap(), 3);
        assert!(check_frames(frames, &[0u8; 32]).is_err());
        assert!(count_frames(&frames[..frames.len() - 1]).is_err());
        assert!(count_frames(&frames[..2]).is_err());
        assert_eq!(count_frames(&[]), Ok(0));
    }

    #[test]
    fn storage_types_cross_threads() {
        fn send_sync<T: Send + Sync>() {}
        fn send<T: Send>() {}
        send_sync::<MemoryBackend>();
        send_sync::<DirBackend>();
        send_sync::<std::sync::Arc<dyn Backend>>();
        send_sync::<Journal>();
        send::<Checkout>();
        send::<Box<dyn Sink>>();
    }

    #[test]
    fn guard_releases_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicU32::new(0));
        let h = hits.clone();
        let guard = CheckoutGuard::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        guard.release();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let h = hits.clone();
        drop(CheckoutGuard::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn sink_errors_map_to_faults() {
        assert_eq!(
            Fault::from(SinkError::Conflict {
                expected: 1,
                actual: 2
            }),
            Fault::Conflict {
                expected: 1,
                actual: 2
            }
        );
        assert_eq!(
            SinkError::TooLarge { limit: 10 }.into_fault(11),
            Fault::TooLarge {
                size: 11,
                limit: 10
            }
        );
        assert_eq!(Fault::from(SinkError::LeaseLost), Fault::LeaseLost);
        assert_eq!(Fault::from(SinkError::Deleted), Fault::Deleted);
        assert_eq!(
            Fault::from(SinkError::Locked {
                retry_after_secs: Some(3)
            }),
            Fault::Locked {
                retry_after_secs: Some(3)
            }
        );
        assert!(matches!(
            Fault::from(SinkError::Io(io::Error::other("x"))),
            Fault::Io(_)
        ));
    }
}
