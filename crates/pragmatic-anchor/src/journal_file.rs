//! A journal (format 2, through the core [`Journal`]) kept in one file by
//! one writer, for the records the server keeps about itself: in witness
//! mode, the journal of cosigned checkpoints (design 4.8).
//!
//! The writer follows the core's durability rules: an entry counts only
//! once its frame is written and fsynced, a failed write is cut back so the
//! file never holds half a frame, and a torn tail found at open is moved
//! aside to `<name>.torn-<unix ms>` and recorded in a `torn_tail` note
//! before anything else is appended (design 2.14). The caller must be the
//! only writer (the server holds `server.lock`).
//!
//! A new journal is published whole, its header and `run.start` note in
//! one file that appears complete or not at all. An existing file that is
//! too short for a header or holds no entries can then only be damage, and
//! is refused rather than started afresh: a witness that started its
//! journal afresh would have forgotten what it cosigned.
//!
//! The whole journal is held in memory (the core [`Journal`] keeps every
//! entry, for deduplication and completion checks) and parsed in full at
//! open. A witness cosigning for many logs at short intervals grows by
//! about a kilobyte per cosignature; bounded memory needs a core API to
//! append from a journal's tail state, deferred to 0.7 (design 10).
//!
//! Using the journal format, rather than a bespoke log, means these
//! records get the same hash chain, the same verifier and the same
//! anchoring as any run: the server anchors this journal as run
//! [`WITNESS_RUN_ID`](crate::WITNESS_RUN_ID) in its own anchor log.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{self, note, Cursor, Journal, TornTail, META};
use pragmatic::json::Json;
use pragmatic::sha256::{sha256, Digest};
use pragmatic::{Event, Value};

use crate::error::AnchorError;
use crate::fsutil::{create_new_durable, publish_new_durable, unix_millis};

/// A journal file with one writer. See the module documentation.
pub struct JournalFile {
    path: PathBuf,
    run_id: String,
    file: File,
    journal: Journal,
    failed: bool,
}

impl std::fmt::Debug for JournalFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalFile")
            .field("path", &self.path)
            .field("entries", &self.journal.len())
            .finish()
    }
}

impl JournalFile {
    /// Open the journal at `path`, creating it (with a `run.start` note for
    /// `run_id`) if it does not exist.
    ///
    /// A new journal is published whole, header and `run.start` together
    /// (temporary file, fsync, link), so a crash leaves either no file or
    /// one that starts with `run.start`. An existing file that is shorter
    /// than a header, or holds no entries, was therefore damaged, and is
    /// refused as [`AnchorError::Corrupt`] rather than started afresh: for
    /// the witness journal a fresh start would forget every cosigned
    /// checkpoint and let the witness cosign a fork of a log it has already
    /// cosigned (design 4.8).
    pub fn open_or_create(
        path: impl AsRef<Path>,
        run_id: &str,
    ) -> Result<JournalFile, AnchorError> {
        let path = path.as_ref().to_path_buf();
        match std::fs::metadata(&path) {
            Ok(m) if m.len() < journal::HEADER_LEN as u64 => {
                return Err(AnchorError::Corrupt(format!(
                    "{} is {} bytes, shorter than a journal header: it was damaged",
                    path.display(),
                    m.len()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(&path, run_id)?,
            Err(e) => return Err(AnchorError::io(format!("reading {}", path.display()))(e)),
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(AnchorError::io(format!("opening {}", path.display())))?;
        let mut jf = JournalFile {
            journal: Journal::new(None),
            path,
            run_id: run_id.to_string(),
            file,
            failed: false,
        };
        let tail = jf.load(run_id)?;
        if let Some(torn) = tail {
            jf.journal
                .append_torn_tail(journal::system_clock(), &torn)
                .map_err(|f| AnchorError::Corrupt(f.to_string()))?;
            jf.persist()?;
        }
        Ok(jf)
    }

    /// Read the file into memory. A torn tail is moved aside and cut off;
    /// it is returned so the caller can note it. A file whose valid prefix
    /// does not start with `run_id`'s `run.start` is refused before
    /// anything is moved.
    fn load(&mut self, run_id: &str) -> Result<Option<TornTail>, AnchorError> {
        let ctx = format!("reading {}", self.path.display());
        let bytes = std::fs::read(&self.path).map_err(AnchorError::io(&ctx))?;
        let parsed = Journal::parse(&bytes, None)
            .map_err(|e| AnchorError::Corrupt(format!("{}: {e}", self.path.display())))?;
        if parsed.journal.format() != journal::FORMAT {
            return Err(AnchorError::Corrupt(format!(
                "{} is not journal format 2",
                self.path.display()
            )));
        }
        if parsed.journal.is_empty() {
            return Err(AnchorError::Corrupt(format!(
                "{} holds no entries, not even its run.start: it was damaged",
                self.path.display()
            )));
        }
        if parsed.journal.run_start_id().as_deref() != Some(run_id) {
            return Err(AnchorError::Corrupt(format!(
                "{} is not the journal of {run_id}",
                self.path.display()
            )));
        }
        self.journal = parsed.journal;
        if parsed.tail_len == 0 {
            return Ok(None);
        }
        let tail = &bytes[parsed.valid_len as usize..];
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("journal");
        let moved_to = format!("{name}.torn-{}", unix_millis());
        create_new_durable(&self.path.with_file_name(&moved_to), tail)?;
        self.file
            .set_len(parsed.valid_len)
            .and_then(|_| self.file.sync_all())
            .map_err(AnchorError::io(&ctx))?;
        Ok(Some(TornTail {
            offset: parsed.valid_len,
            bytes: tail.len() as u64,
            sha256: sha256(tail),
            moved_to,
            at_cursor: self.journal.len(),
        }))
    }

    /// The journal as persisted.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `(entries, head)`: what the server snapshots to anchor this journal.
    pub fn state(&self) -> (u64, Digest) {
        (self.journal.len(), self.journal.head())
    }

    /// Append a note on the meta branch and make it durable before
    /// returning. `data` must be strict JSON with no personal data (design
    /// 2.11).
    pub fn append_note(
        &mut self,
        kind: &str,
        data: &Json,
        payload: Vec<Value>,
    ) -> Result<Cursor, AnchorError> {
        if self.failed {
            return Err(AnchorError::Poisoned);
        }
        let event = Event::Note {
            kind: kind.to_string(),
            data: data.to_string(),
            payload: payload
                .into_iter()
                .map(pragmatic::Content::Sealed)
                .collect(),
        };
        let cursor = self
            .journal
            .append(META, event)
            .map_err(|f| AnchorError::Json(f.to_string()))?;
        self.persist()?;
        Ok(cursor)
    }

    /// Write and fsync the pending frames. On failure the file is cut back
    /// and the journal reloaded from it, so memory never runs ahead of the
    /// disk; if even that fails, the writer refuses further appends.
    fn persist(&mut self) -> Result<(), AnchorError> {
        let Some((_, frames, _)) = self.journal.pending() else {
            return Ok(());
        };
        let frames = frames.to_vec();
        let expected = self.journal.byte_len() - frames.len() as u64;
        let result = (|| -> std::io::Result<()> {
            let actual = self.file.metadata()?.len();
            if actual != expected {
                return Err(std::io::Error::other(format!(
                    "journal file is {actual} bytes, expected {expected}"
                )));
            }
            (&self.file).seek(SeekFrom::Start(expected))?;
            (&self.file).write_all(&frames)?;
            self.file.sync_data()
        })();
        match result {
            Ok(()) => {
                self.journal.mark_persisted(self.journal.len());
                Ok(())
            }
            Err(e) => {
                let run_id = self.run_id.clone();
                let restored = self
                    .file
                    .set_len(expected)
                    .and_then(|_| self.file.sync_all())
                    .is_ok()
                    && self.load(&run_id).is_ok();
                if !restored {
                    self.failed = true;
                }
                Err(AnchorError::io(format!(
                    "appending to {}",
                    self.path.display()
                ))(e))
            }
        }
    }
}

/// Publish a new journal at `path`: the header and the `run.start` note
/// for `run_id`, in one file that appears whole or not at all.
fn create(path: &Path, run_id: &str) -> Result<(), AnchorError> {
    let mut nonce = [0u8; 16];
    pragmatic::rand::fill(&mut nonce).map_err(AnchorError::io("reading the OS CSPRNG"))?;
    let data = Json::Object(vec![
        ("run_id".into(), run_id.into()),
        ("nonce".into(), hex_encode(&nonce).into()),
        ("sdk".into(), "pragmatic-anchor".into()),
        ("sdk_version".into(), env!("CARGO_PKG_VERSION").into()),
        ("format".into(), 2u32.into()),
        ("labels".into(), Json::Object(Vec::new())),
    ]);
    let mut journal = Journal::new(None);
    journal
        .append(
            META,
            Event::Note {
                kind: note::RUN_START.to_string(),
                data: data.to_string(),
                payload: Vec::new(),
            },
        )
        .map_err(|f| AnchorError::Json(f.to_string()))?;
    publish_new_durable(path, &journal.to_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_appends_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.journal");
        let mut jf = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        assert_eq!(jf.journal().len(), 1);
        assert_eq!(
            jf.journal().run_start_id().as_deref(),
            Some("pragmatic:witness")
        );
        let data = Json::Object(vec![("n".into(), 1u32.into())]);
        assert_eq!(
            jf.append_note("witness.cosign", &data, Vec::new()).unwrap(),
            1
        );
        let state = jf.state();
        drop(jf);

        let jf = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        assert_eq!(jf.state(), state);
        assert!(jf.journal().verify().is_ok());
        // The bytes are an ordinary journal: the core parses them as one.
        let parsed = Journal::parse(&std::fs::read(&path).unwrap(), None).unwrap();
        assert_eq!(parsed.journal.head(), state.1);
        // Another run id is refused.
        assert!(JournalFile::open_or_create(&path, "pragmatic:other").is_err());
    }

    #[test]
    fn torn_tail_is_moved_aside_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.journal");
        let mut jf = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        jf.append_note("witness.cosign", &Json::Object(vec![]), Vec::new())
            .unwrap();
        drop(jf);
        // A crash in the middle of a frame leaves a partial one.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        drop(f);

        let jf = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        let last = jf.journal().entries().last().unwrap();
        assert_eq!(last.event.note_kind(), Some(note::TORN_TAIL));
        assert_eq!(jf.journal().len(), 3);
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".torn-"))
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(
            std::fs::read(aside[0].path()).unwrap(),
            vec![9, 0, 0, 0, 1, 2]
        );
        assert!(
            Journal::parse(&std::fs::read(&path).unwrap(), None)
                .unwrap()
                .tail_len
                == 0
        );
    }

    /// A new journal appears whole: header and run.start in one file, with
    /// no temporary name left behind.
    #[test]
    fn a_new_journal_is_published_with_its_run_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.journal");
        JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        let parsed = Journal::parse(&std::fs::read(&path).unwrap(), None).unwrap();
        assert_eq!(parsed.journal.len(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// A damaged journal is refused, never started afresh: for the witness
    /// that would forget every cosigned checkpoint.
    #[test]
    fn a_damaged_journal_is_refused_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.journal");
        let mut jf = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap();
        jf.append_note("witness.cosign", &Json::Object(vec![]), Vec::new())
            .unwrap();
        drop(jf);
        let good = std::fs::read(&path).unwrap();
        // Inside the header, at exactly a header, and inside the first
        // frame (only a run.start-less prefix is left).
        for keep in [0usize, 7, journal::HEADER_LEN, journal::HEADER_LEN + 9] {
            std::fs::write(&path, &good[..keep]).unwrap();
            let err = JournalFile::open_or_create(&path, "pragmatic:witness").unwrap_err();
            assert!(matches!(err, AnchorError::Corrupt(_)), "{keep}: {err}");
            assert_eq!(std::fs::read(&path).unwrap(), &good[..keep], "{keep}");
        }
    }
}
