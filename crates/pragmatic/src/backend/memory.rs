//! [`MemoryBackend`]: journals held in process memory.
//!
//! It behaves like a durable store in every way the runtime can observe:
//! it keeps the *persisted bytes* of each run (not a live `Journal`), so a
//! checkout parses a copy exactly as it would parse a file, unpersisted
//! frames are lost when a checkout is dropped, and only one checkout of a
//! run may exist at a time. That makes it the backend for tests and
//! ephemeral runs, and a faithful model of the durable ones.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::fault::Fault;
use crate::journal::{header, validate_run_id, Journal, TornTail, VerifyReport, FLAG_KEYED};
use crate::sha256::{sha256, Digest};

use super::{check_frames, check_run_start, count_frames, Backend, Checkout, CheckoutGuard};
use super::{Sink, SinkError};

/// One run's persisted bytes and who holds it.
struct MemRun {
    bytes: Vec<u8>,
    /// Entries in `bytes`.
    entries: u64,
    /// The token of the checkout holding the run.
    holder: Option<u64>,
}

#[derive(Default)]
struct Shared {
    runs: Mutex<HashMap<String, MemRun>>,
    next_token: AtomicU64,
}

impl Shared {
    fn runs(&self) -> MutexGuard<'_, HashMap<String, MemRun>> {
        // A panic while holding the lock cannot leave a run half-updated
        // (every update is a single assignment or push), so poisoning is
        // safe to ignore.
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Journals in memory. Cloning shares the same store.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    shared: Arc<Shared>,
}

impl MemoryBackend {
    /// An empty store.
    pub fn new() -> MemoryBackend {
        MemoryBackend::default()
    }

    /// The persisted bytes of a run (inspection, export, tests).
    pub fn bytes(&self, run_id: &str) -> Option<Vec<u8>> {
        self.shared.runs().get(run_id).map(|r| r.bytes.clone())
    }

    /// Replace the persisted bytes of a run, for tests and tools that need
    /// to model what a crash or a damaged disk leaves behind. The run must
    /// not be checked out.
    pub fn set_bytes(&self, run_id: &str, bytes: Vec<u8>) -> Result<(), Fault> {
        let mut runs = self.shared.runs();
        if runs.get(run_id).is_some_and(|r| r.holder.is_some()) {
            return Err(Fault::Locked {
                retry_after_secs: None,
            });
        }
        let entries = whole_frames(&bytes);
        runs.insert(
            run_id.to_string(),
            MemRun {
                bytes,
                entries,
                holder: None,
            },
        );
        Ok(())
    }
}

/// Frames that can be counted from the bytes of a stored journal, stopping
/// at anything that is not a whole frame.
fn whole_frames(bytes: &[u8]) -> u64 {
    let start = crate::journal::HEADER_LEN.min(bytes.len());
    let mut body = &bytes[start..];
    let mut n = 0;
    while body.len() >= 4 {
        let len = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
        let Some(end) = (4 + len).checked_add(32).filter(|&e| e <= body.len()) else {
            break;
        };
        body = &body[end..];
        n += 1;
    }
    n
}

impl Backend for MemoryBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        validate_run_id(run_id)?;
        let token = self.shared.next_token.fetch_add(1, Ordering::Relaxed);
        let (journal, torn) = {
            let mut runs = self.shared.runs();
            if !runs.contains_key(run_id) {
                if !create {
                    return Err(Fault::Io(format!("no journal for run '{run_id}'")));
                }
                let flags = if key.is_some() { FLAG_KEYED } else { 0 };
                runs.insert(
                    run_id.to_string(),
                    MemRun {
                        bytes: header(flags).to_vec(),
                        entries: 0,
                        holder: None,
                    },
                );
            }
            let run = runs.get_mut(run_id).expect("inserted above");
            if run.holder.is_some() {
                return Err(Fault::Locked {
                    retry_after_secs: None,
                });
            }
            let parsed = Journal::parse(&run.bytes, key)?;
            if parsed.journal.format() == 1 {
                return Err(Fault::Unsupported(crate::journal::FORMAT1_READ_ONLY.into()));
            }
            check_run_start(&parsed.journal, run_id, "memory")?;
            let torn = (parsed.tail_len > 0).then(|| {
                let tail = run.bytes.split_off(parsed.valid_len as usize);
                TornTail {
                    offset: parsed.valid_len,
                    bytes: tail.len() as u64,
                    sha256: sha256(&tail),
                    moved_to: String::new(),
                    at_cursor: parsed.journal.len(),
                }
            });
            run.entries = parsed.journal.len();
            run.holder = Some(token);
            (parsed.journal, torn)
        };
        let shared = self.shared.clone();
        let id = run_id.to_string();
        let guard = CheckoutGuard::new(move || {
            if let Some(run) = shared.runs().get_mut(&id) {
                if run.holder == Some(token) {
                    run.holder = None;
                }
            }
        });
        let sink = MemorySink {
            shared: self.shared.clone(),
            run_id: run_id.to_string(),
            token,
        };
        let mut checkout = Checkout {
            journal,
            sink: Box::new(sink),
            guard,
            torn: None,
        };
        checkout.record_torn(torn)?;
        Ok(checkout)
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        let bytes = self
            .bytes(run_id)
            .ok_or_else(|| Fault::Io(format!("no journal for run '{run_id}'")))?;
        let journal = Journal::parse(&bytes, key)?.journal;
        if journal.format() != 1 {
            check_run_start(&journal, run_id, "memory")?;
        }
        Ok(journal)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        let mut ids: Vec<String> = self.shared.runs().keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }

    fn verify(&self, run_id: &str, key: Option<&[u8]>) -> Result<VerifyReport, Fault> {
        let bytes = self
            .bytes(run_id)
            .ok_or_else(|| Fault::Io(format!("no journal for run '{run_id}'")))?;
        let (journal, report) = Journal::audit_bytes(&bytes, key)?;
        if journal.format() != 1 {
            check_run_start(&journal, run_id, "memory")?;
        }
        Ok(report)
    }

    #[cfg(any(test, feature = "testing"))]
    fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        let mut runs = self.shared.runs();
        let run = runs
            .get_mut(run_id)
            .ok_or_else(|| Fault::Io(format!("no journal for run '{run_id}'")))?;
        let len = super::prefix_len(&run.bytes, keep);
        run.bytes.truncate(len);
        run.entries = whole_frames(&run.bytes);
        Ok(())
    }
}

/// Appends to a [`MemoryBackend`] run while its checkout holds it.
struct MemorySink {
    shared: Arc<Shared>,
    run_id: String,
    token: u64,
}

impl Sink for MemorySink {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError> {
        let n = check_frames(frames, head_after)?;
        let mut runs = self.shared.runs();
        let run = runs.get_mut(&self.run_id).ok_or(SinkError::Deleted)?;
        if run.holder != Some(self.token) {
            return Err(SinkError::LeaseLost);
        }
        if at != run.entries {
            return Err(SinkError::Conflict {
                expected: run.entries,
                actual: at,
            });
        }
        run.bytes.extend_from_slice(frames);
        run.entries += n;
        Ok(())
    }

    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError> {
        let mut runs = self.shared.runs();
        let run = runs.get_mut(&self.run_id).ok_or(SinkError::Deleted)?;
        if run.holder != Some(self.token) {
            return Err(SinkError::LeaseLost);
        }
        let body = file.get(crate::journal::HEADER_LEN..).unwrap_or(&[]);
        let n = count_frames(body)
            .map_err(|m| SinkError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, m)))?;
        run.bytes = file.to_vec();
        run.entries = n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{note, Content, EraseSelector, ErasureNote, Event, META, ROOT};

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

    #[test]
    fn checkout_persist_and_reread() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("r1", true, None).unwrap();
        co.journal.append(META, run_start("r1")).unwrap();
        co.journal.append(ROOT, recv("hello")).unwrap();
        co.persist().unwrap();
        let head = co.journal.head();
        drop(co);
        let snap = b.snapshot("r1", None).unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.head(), head);
        assert!(snap.audit().is_ok());
        assert_eq!(b.list().unwrap(), vec!["r1".to_string()]);
    }

    #[test]
    fn double_checkout_is_locked_until_released() {
        let b = MemoryBackend::new();
        let co = b.checkout("r", true, None).unwrap();
        assert_eq!(
            b.checkout("r", false, None).unwrap_err(),
            Fault::Locked {
                retry_after_secs: None
            }
        );
        // A clone shares the store, and the lock with it.
        assert!(b.clone().checkout("r", true, None).is_err());
        drop(co);
        assert!(b.checkout("r", false, None).is_ok());
    }

    #[test]
    fn unpersisted_frames_are_lost_with_the_checkout() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("r", true, None).unwrap();
        co.journal.append(META, run_start("r")).unwrap();
        co.persist().unwrap();
        co.journal.append(ROOT, recv("never persisted")).unwrap();
        drop(co);
        assert_eq!(b.snapshot("r", None).unwrap().len(), 1);
    }

    #[test]
    fn sink_refuses_after_release_and_on_conflict() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("r", true, None).unwrap();
        co.journal.append(META, run_start("r")).unwrap();
        let (at, frames, head) = co
            .journal
            .pending()
            .map(|(a, f, h)| (a, f.to_vec(), h))
            .unwrap();
        // Wrong `at`: the writer's view of the journal is stale.
        assert!(matches!(
            co.sink.persist(at + 1, &frames, &head),
            Err(SinkError::Conflict {
                expected: 0,
                actual: 1
            })
        ));
        let Checkout {
            mut sink, guard, ..
        } = co;
        drop(guard);
        assert!(matches!(
            sink.persist(at, &frames, &head),
            Err(SinkError::LeaseLost)
        ));
        // A later checkout's sink is unaffected by the stale one.
        let mut co2 = b.checkout("r", false, None).unwrap();
        co2.journal.append(META, run_start("r")).unwrap();
        co2.persist().unwrap();
        assert!(matches!(
            sink.persist(at, &frames, &head),
            Err(SinkError::LeaseLost)
        ));
    }

    #[test]
    fn missing_run_without_create() {
        let b = MemoryBackend::new();
        assert!(matches!(b.checkout("nope", false, None), Err(Fault::Io(_))));
        assert!(b.snapshot("nope", None).is_err());
        assert!(matches!(
            b.checkout("pragmatic:reserved", true, None),
            Err(Fault::Unsupported(_))
        ));
    }

    #[test]
    fn keyed_runs_need_their_key() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("k", true, Some(b"key")).unwrap();
        co.journal.append(META, run_start("k")).unwrap();
        co.persist().unwrap();
        drop(co);
        assert!(matches!(b.snapshot("k", None), Err(Fault::Unsupported(_))));
        assert!(b.snapshot("k", Some(b"key")).is_ok());
        assert!(matches!(
            b.checkout("k", false, None),
            Err(Fault::Unsupported(_))
        ));
    }

    #[test]
    fn torn_tail_is_truncated_only_by_a_checkout() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("t", true, None).unwrap();
        co.journal.append(META, run_start("t")).unwrap();
        co.journal.append(ROOT, recv("kept")).unwrap();
        co.persist().unwrap();
        drop(co);
        let mut bytes = b.bytes("t").unwrap();
        let clean = bytes.len();
        bytes.extend_from_slice(&[7, 0, 0, 0, 1, 2]);
        b.set_bytes("t", bytes.clone()).unwrap();

        // A snapshot ignores the tail and changes nothing.
        let snap = b.snapshot("t", None).unwrap();
        assert_eq!((snap.len(), snap.torn_bytes()), (2, 6));
        assert_eq!(b.bytes("t").unwrap(), bytes);

        let co = b.checkout("t", false, None).unwrap();
        let torn = co.torn.clone().unwrap();
        assert_eq!(
            (torn.offset, torn.bytes, torn.at_cursor),
            (clean as u64, 6, 2)
        );
        // The truncation is recorded in the journal itself.
        assert_eq!(co.journal.len(), 3);
        assert_eq!(
            co.journal.entries()[2].event.note_kind(),
            Some(note::TORN_TAIL)
        );
        drop(co);
        let after = b.snapshot("t", None).unwrap();
        assert_eq!((after.len(), after.torn_bytes()), (3, 0));
        assert!(after.audit().is_ok());
    }

    #[test]
    fn erase_through_a_checkout() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("e", true, None).unwrap();
        co.journal.append(META, run_start("e")).unwrap();
        co.journal
            .append(ROOT, recv("my ssn is 078-05-1120"))
            .unwrap();
        co.persist().unwrap();
        let slots = co
            .erase(
                &EraseSelector::Match(b"078-05-1120".to_vec()),
                &ErasureNote::local("dsar", ""),
            )
            .unwrap();
        assert_eq!(slots, vec![(1, 0)]);
        co.journal.append(ROOT, recv("after")).unwrap();
        co.persist().unwrap();
        drop(co);
        let snap = b.snapshot("e", None).unwrap();
        assert_eq!(snap.len(), 4);
        assert!(snap.audit().is_ok());
        assert_eq!(snap.entries()[1].event.slot_contents()[0], &Content::Erased);
        let stored = b.bytes("e").unwrap();
        assert!(!stored.windows(11).any(|w| w == b"078-05-1120"));
    }

    #[test]
    fn crash_truncate_keeps_a_prefix() {
        let b = MemoryBackend::new();
        let mut co = b.checkout("c", true, None).unwrap();
        co.journal.append(META, run_start("c")).unwrap();
        for i in 0..4 {
            co.journal.append(ROOT, recv(&format!("v{i}"))).unwrap();
        }
        co.persist().unwrap();
        drop(co);
        b.crash_truncate("c", 2).unwrap();
        let snap = b.snapshot("c", None).unwrap();
        assert_eq!((snap.len(), snap.torn_bytes()), (2, 0));
        let mut co = b.checkout("c", false, None).unwrap();
        co.journal.append(ROOT, recv("again")).unwrap();
        co.persist().unwrap();
    }

    #[test]
    fn format_1_is_read_only() {
        let b = MemoryBackend::new();
        let mut v1 = crate::journal_v1::Journal::in_memory();
        v1.append(crate::journal_v1::Event::Clock { nanos: 1 })
            .unwrap();
        let mut bytes = b"PRAGJRNL".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let e = &v1.entries()[0];
        let payload = e.event.encode();
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&e.hash);
        b.set_bytes("old", bytes).unwrap();
        assert_eq!(b.snapshot("old", None).unwrap().format(), 1);
        assert!(matches!(
            b.checkout("old", false, None),
            Err(Fault::Unsupported(m)) if m == crate::journal::FORMAT1_READ_ONLY
        ));
    }
}
