//! The format 1 journal written by Pragmatic 0.4 and 0.5, kept as a writer
//! of test fixtures only.
//!
//! Pragmatic 0.6 reads format 1 files read-only through
//! [`crate::journal::Journal::parse`]; nothing records into this format any
//! more. The module is compiled for the crate's own tests and under the
//! `testing` feature, so test suites can build the 0.4 and 0.5 journals the
//! read-only path must accept.
//!
//! Format 1 in brief: a 12-byte header (`PRAGJRNL`, version 1), then frames
//! of `len u32 LE ‖ payload ‖ hash`, chained as
//! `h_i = H(h_{i-1} ‖ cursor ‖ payload)` from an all-zero genesis, where `H`
//! is SHA-256, or HMAC-SHA-256 when a key is configured. On open, a partial
//! final record (a crash mid-write) is truncated.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::sha256::{hmac_sha256, sha256, Digest, DIGEST_LEN};
use crate::value::Value;

/// Magic bytes at the head of a journal file.
const MAGIC: &[u8; 8] = b"PRAGJRNL";
/// On-disk format version.
const VERSION: u32 = 1;

pub use crate::journal::Cursor;

/// The journal event alphabet (paper Definition 4.2).
///
/// Only *externally determined* outcomes are journaled. Deterministic
/// computation between events is reconstructed by re-execution during replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A realized oracle outcome: the model was called with `prompt` and the
    /// sampled completion was `outcome`. `provenance` identifies the model /
    /// sampler that produced it (for audit; not consulted during replay).
    OracleDraw {
        prompt: Value,
        outcome: Value,
        provenance: String,
    },
    /// A value received on a channel (the other source of externally
    /// determined data - adversarial scheduling realized as a message).
    ChannelRecv { channel: String, value: Value },
    /// Write-ahead intent for a durable effect: journaled *before* the effect
    /// runs ([Eff-intent]).
    EffectIntent { name: String, arg: Value },
    /// The effect's committed result, journaled *after* it succeeds
    /// ([Eff-commit]). An `EffectIntent` without a matching `EffectCommit` is
    /// a dangling intent - a crash inside the write-ahead window.
    EffectCommit { name: String, result: Value },
    /// A saga compensation closed this effect's open intent. Tagged
    /// distinctly so replay never double-undoes ([Sup-comp]).
    EffectCompensated { name: String },
    /// A realized clock read (logical or wall time is externally determined,
    /// so it is journaled like any other draw).
    Clock { nanos: u64 },
    /// Identity of the agent program driving this run: name plus a hash of
    /// its source tokens (emitted by `#[pragmatic::durable]`). Replay checks
    /// it first, turning assumption A2 ("the same term is replayed") into an
    /// enforced property - changed code fails loudly as a `JournalDesync`
    /// instead of misreplaying.
    Program { name: String, hash: String },
}

impl Event {
    /// Stable binary encoding: `tag ‖ (len ‖ bytes)*` with little-endian u64
    /// lengths. This is what gets framed on disk and fed to the hash chain.
    pub fn encode(&self) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
            buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        let mut buf = Vec::new();
        match self {
            Event::OracleDraw {
                prompt,
                outcome,
                provenance,
            } => {
                buf.push(1);
                put(&mut buf, prompt.as_bytes());
                put(&mut buf, outcome.as_bytes());
                put(&mut buf, provenance.as_bytes());
            }
            Event::ChannelRecv { channel, value } => {
                buf.push(2);
                put(&mut buf, channel.as_bytes());
                put(&mut buf, value.as_bytes());
            }
            Event::EffectIntent { name, arg } => {
                buf.push(3);
                put(&mut buf, name.as_bytes());
                put(&mut buf, arg.as_bytes());
            }
            Event::EffectCommit { name, result } => {
                buf.push(4);
                put(&mut buf, name.as_bytes());
                put(&mut buf, result.as_bytes());
            }
            Event::EffectCompensated { name } => {
                buf.push(5);
                put(&mut buf, name.as_bytes());
            }
            Event::Clock { nanos } => {
                buf.push(6);
                buf.extend_from_slice(&nanos.to_le_bytes());
            }
            Event::Program { name, hash } => {
                buf.push(7);
                put(&mut buf, name.as_bytes());
                put(&mut buf, hash.as_bytes());
            }
        }
        buf
    }

    /// Decode an event from its stable encoding. Returns `None` on any
    /// malformed input (treated by the loader as a torn/corrupt record).
    pub fn decode(bytes: &[u8]) -> Option<Event> {
        struct R<'a>(&'a [u8]);
        impl<'a> R<'a> {
            fn field(&mut self) -> Option<Vec<u8>> {
                if self.0.len() < 8 {
                    return None;
                }
                let len = u64::from_le_bytes(self.0[..8].try_into().ok()?) as usize;
                self.0 = &self.0[8..];
                if self.0.len() < len {
                    return None;
                }
                let out = self.0[..len].to_vec();
                self.0 = &self.0[len..];
                Some(out)
            }
            fn u64(&mut self) -> Option<u64> {
                if self.0.len() < 8 {
                    return None;
                }
                let v = u64::from_le_bytes(self.0[..8].try_into().ok()?);
                self.0 = &self.0[8..];
                Some(v)
            }
            fn done(&self) -> bool {
                self.0.is_empty()
            }
        }
        let (&tag, rest) = bytes.split_first()?;
        let mut r = R(rest);
        let ev = match tag {
            1 => Event::OracleDraw {
                prompt: Value(r.field()?),
                outcome: Value(r.field()?),
                provenance: String::from_utf8(r.field()?).ok()?,
            },
            2 => Event::ChannelRecv {
                channel: String::from_utf8(r.field()?).ok()?,
                value: Value(r.field()?),
            },
            3 => Event::EffectIntent {
                name: String::from_utf8(r.field()?).ok()?,
                arg: Value(r.field()?),
            },
            4 => Event::EffectCommit {
                name: String::from_utf8(r.field()?).ok()?,
                result: Value(r.field()?),
            },
            5 => Event::EffectCompensated {
                name: String::from_utf8(r.field()?).ok()?,
            },
            6 => Event::Clock { nanos: r.u64()? },
            7 => Event::Program {
                name: String::from_utf8(r.field()?).ok()?,
                hash: String::from_utf8(r.field()?).ok()?,
            },
            _ => return None,
        };
        if r.done() {
            Some(ev)
        } else {
            None
        }
    }
}

/// One committed journal entry: the event plus its position and chain hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub cursor: Cursor,
    pub event: Event,
    /// `H(prev_hash ‖ cursor ‖ payload)` - the link in the tamper-evident chain.
    pub hash: Digest,
}

/// Where journal entries are durably persisted.
enum Sink {
    /// In-memory only (tests, benchmarks, ephemeral runs).
    Memory,
    /// Append-only file, buffered; `sync` flushes and fsyncs.
    File {
        writer: BufWriter<File>,
        path: PathBuf,
    },
}

/// An append-only, hash-chained journal for one run.
pub struct Journal {
    entries: Vec<Entry>,
    sink: Sink,
    /// Optional runtime key: entries are chained with HMAC-SHA-256 instead of
    /// plain SHA-256, making the log attributable as well as tamper-evident.
    key: Option<Vec<u8>>,
}

/// Result of loading a durable journal from disk.
pub struct Loaded {
    pub journal: Journal,
    /// Number of trailing bytes discarded because the final record was torn
    /// (crash mid-write). Zero for a cleanly closed journal.
    pub torn_bytes: u64,
}

impl Journal {
    /// A fresh in-memory journal (nothing persisted).
    pub fn in_memory() -> Self {
        Journal {
            entries: Vec::new(),
            sink: Sink::Memory,
            key: None,
        }
    }

    /// A fresh in-memory journal whose chain is keyed with HMAC-SHA-256.
    pub fn in_memory_keyed(key: &[u8]) -> Self {
        Journal {
            entries: Vec::new(),
            sink: Sink::Memory,
            key: Some(key.to_vec()),
        }
    }

    /// Create a new durable journal at `path` (fails if it already exists).
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::create_inner(path.as_ref(), None)
    }

    /// Create a new durable, keyed journal at `path`.
    pub fn create_keyed(path: impl AsRef<Path>, key: &[u8]) -> io::Result<Self> {
        Self::create_inner(path.as_ref(), Some(key.to_vec()))
    }

    fn create_inner(path: &Path, key: Option<Vec<u8>>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(MAGIC)?;
        writer.write_all(&VERSION.to_le_bytes())?;
        writer.flush()?;
        Ok(Journal {
            entries: Vec::new(),
            sink: Sink::File {
                writer,
                path: path.to_path_buf(),
            },
            key,
        })
    }

    /// Open an existing durable journal, replay-verifying the hash chain and
    /// truncating any torn tail left by a crash mid-append.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Loaded> {
        Self::open_inner(path.as_ref(), None)
    }

    /// Open an existing keyed journal.
    pub fn open_keyed(path: impl AsRef<Path>, key: &[u8]) -> io::Result<Loaded> {
        Self::open_inner(path.as_ref(), Some(key.to_vec()))
    }

    fn open_inner(path: &Path, key: Option<Vec<u8>>) -> io::Result<Loaded> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        if bytes.len() < MAGIC.len() + 4 || &bytes[..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a pragmatic journal (bad magic)",
            ));
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported journal version {version}"),
            ));
        }

        let mut entries: Vec<Entry> = Vec::new();
        let mut prev: Digest = [0u8; DIGEST_LEN];
        let mut pos = 12usize; // just past the header
        let mut good_end = pos; // offset after the last intact record

        loop {
            // Frame: [u32 payload_len][payload][32-byte hash]
            if pos + 4 > bytes.len() {
                break; // torn length prefix (or clean EOF)
            }
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            let frame_end = pos + 4 + len + DIGEST_LEN;
            if frame_end > bytes.len() {
                break; // torn payload/hash - crash mid-write
            }
            let payload = &bytes[pos + 4..pos + 4 + len];
            let mut hash = [0u8; DIGEST_LEN];
            hash.copy_from_slice(&bytes[pos + 4 + len..frame_end]);

            let cursor = entries.len() as Cursor;
            let expect = chain_hash(key.as_deref(), &prev, cursor, payload);
            if hash != expect {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("journal hash chain broken at cursor {cursor}"),
                ));
            }
            let event = Event::decode(payload).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("undecodable journal event at cursor {cursor}"),
                )
            })?;
            entries.push(Entry {
                cursor,
                event,
                hash,
            });
            prev = hash;
            pos = frame_end;
            good_end = pos;
        }

        let torn = (bytes.len() - good_end) as u64;
        if torn > 0 {
            // Truncate the torn tail so future appends extend a clean prefix
            // (Definition 3.12: after a crash, the journal *is* its durable
            // prefix).
            let f = OpenOptions::new().write(true).open(path)?;
            f.set_len(good_end as u64)?;
            f.sync_all()?;
        }

        let writer = BufWriter::new(OpenOptions::new().append(true).open(path)?);
        Ok(Loaded {
            journal: Journal {
                entries,
                sink: Sink::File {
                    writer,
                    path: path.to_path_buf(),
                },
                key,
            },
            torn_bytes: torn,
        })
    }

    /// Append an event. O(1): one hash over the encoded event, one `Vec`
    /// push, and (for durable journals) one buffered write.
    pub fn append(&mut self, event: Event) -> io::Result<Cursor> {
        let cursor = self.entries.len() as Cursor;
        let payload = event.encode();
        let prev = self
            .entries
            .last()
            .map(|e| e.hash)
            .unwrap_or([0u8; DIGEST_LEN]);
        let hash = chain_hash(self.key.as_deref(), &prev, cursor, &payload);

        if let Sink::File { writer, .. } = &mut self.sink {
            writer.write_all(&(payload.len() as u32).to_le_bytes())?;
            writer.write_all(&payload)?;
            writer.write_all(&hash)?;
        }
        self.entries.push(Entry {
            cursor,
            event,
            hash,
        });
        Ok(cursor)
    }

    /// Flush buffered appends to stable storage (fsync). The journal length
    /// at the moment `sync` returns is a *checkpoint* (Definition 3.12): a
    /// crash after this point loses nothing before it.
    pub fn sync(&mut self) -> io::Result<()> {
        if let Sink::File { writer, .. } = &mut self.sink {
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        Ok(())
    }

    /// Number of committed entries (the write cursor).
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `cursor`, if committed.
    pub fn get(&self, cursor: Cursor) -> Option<&Entry> {
        self.entries.get(cursor as usize)
    }

    /// All committed entries, in order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The head of the hash chain (the whole run's integrity commitment).
    pub fn head(&self) -> Option<Digest> {
        self.entries.last().map(|e| e.hash)
    }

    /// Walk the full chain and confirm every link. Returns the first bad
    /// cursor on failure.
    pub fn verify(&self) -> Result<(), Cursor> {
        let mut prev: Digest = [0u8; DIGEST_LEN];
        for e in &self.entries {
            let expect = chain_hash(self.key.as_deref(), &prev, e.cursor, &e.event.encode());
            if e.hash != expect {
                return Err(e.cursor);
            }
            prev = e.hash;
        }
        Ok(())
    }

    /// Effect names whose `EffectIntent` has no matching `EffectCommit` or
    /// `EffectCompensated` - crashes inside the write-ahead window. Feeds the
    /// no-orphaned-effect recovery rule ([Eff-recover]).
    pub fn dangling_intents(&self) -> Vec<(Cursor, String)> {
        let mut open: Vec<(Cursor, String)> = Vec::new();
        for e in &self.entries {
            match &e.event {
                Event::EffectIntent { name, .. } => open.push((e.cursor, name.clone())),
                Event::EffectCommit { name, .. } | Event::EffectCompensated { name } => {
                    if let Some(i) = open.iter().rposition(|(_, n)| n == name) {
                        open.remove(i);
                    }
                }
                _ => {}
            }
        }
        open
    }

    /// TEST/CRASH-SIMULATION ONLY: keep the first `keep` entries and discard
    /// the rest, modeling "the disk only durably held a prefix".
    pub fn truncate(&mut self, keep: u64) -> io::Result<()> {
        self.entries.truncate(keep as usize);
        if let Sink::File { writer, path } = &mut self.sink {
            writer.flush()?;
            // Recompute the byte offset of the surviving prefix.
            let mut end = 12u64; // header
            for e in &self.entries {
                end += 4 + e.event.encode().len() as u64 + DIGEST_LEN as u64;
            }
            let f = OpenOptions::new().write(true).open(&*path)?;
            f.set_len(end)?;
            f.sync_all()?;
            *writer = BufWriter::new(OpenOptions::new().append(true).open(&*path)?);
        }
        Ok(())
    }

    /// TEST ONLY: corrupt the stored event at `cursor` (for tamper-evidence
    /// tests). Does not touch disk.
    #[doc(hidden)]
    pub fn tamper(&mut self, cursor: Cursor, event: Event) {
        if let Some(e) = self.entries.get_mut(cursor as usize) {
            e.event = event;
        }
    }
}

fn chain_hash(key: Option<&[u8]>, prev: &Digest, cursor: Cursor, payload: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(DIGEST_LEN + 8 + payload.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(&cursor.to_le_bytes());
    buf.extend_from_slice(payload);
    match key {
        Some(k) => hmac_sha256(k, &buf),
        None => sha256(&buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draw(p: &str, o: &str) -> Event {
        Event::OracleDraw {
            prompt: p.into(),
            outcome: o.into(),
            provenance: "test".into(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let events = vec![
            draw("plan the task", "step1;step2"),
            Event::ChannelRecv {
                channel: "c".into(),
                value: "hello".into(),
            },
            Event::EffectIntent {
                name: "write_report".into(),
                arg: "v1".into(),
            },
            Event::EffectCommit {
                name: "write_report".into(),
                result: "ok".into(),
            },
            Event::EffectCompensated {
                name: "write_report".into(),
            },
            Event::Clock { nanos: 123_456_789 },
        ];
        for ev in events {
            assert_eq!(Event::decode(&ev.encode()).unwrap(), ev);
        }
    }

    #[test]
    fn chain_verifies_and_detects_tamper() {
        let mut j = Journal::in_memory();
        for i in 0..10 {
            j.append(draw(&format!("p{i}"), &format!("o{i}"))).unwrap();
        }
        assert!(j.verify().is_ok());
        j.tamper(4, draw("p4", "FORGED"));
        assert_eq!(j.verify(), Err(4));
    }

    #[test]
    fn keyed_chain_differs_from_unkeyed() {
        let mut a = Journal::in_memory();
        let mut b = Journal::in_memory_keyed(b"runtime-key");
        a.append(draw("p", "o")).unwrap();
        b.append(draw("p", "o")).unwrap();
        assert_ne!(a.head(), b.head());
    }

    #[test]
    fn dangling_intent_detection() {
        let mut j = Journal::in_memory();
        j.append(Event::EffectIntent {
            name: "a".into(),
            arg: "x".into(),
        })
        .unwrap();
        j.append(Event::EffectCommit {
            name: "a".into(),
            result: "ok".into(),
        })
        .unwrap();
        j.append(Event::EffectIntent {
            name: "b".into(),
            arg: "y".into(),
        })
        .unwrap();
        let d = j.dangling_intents();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].1, "b");
    }
}
