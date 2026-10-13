//! Frames that arrive from another process (spec 2.4 and 4.6), and journals
//! that grow one note at a time without being held in memory.
//!
//! # Receiving frames
//!
//! Pragmatic Server stores frames that an SDK encoded, salted and hashed. A
//! server that stored whatever bytes it was sent would turn every client bug
//! (or every hostile agent) into a journal that no longer reads back, so
//! [`Journal::append_frames`] holds received frames to the rules a reader
//! applies and to the rules for what a client may write:
//!
//! - each frame is canonically decoded, re-encoded and byte-compared, so the
//!   stored bytes are exactly what a second implementation would produce
//!   from the same values;
//! - every sealed slot's commitment is recomputed and every ref resolved;
//! - every chain link is recomputed from the journal's current head;
//! - completions name an earlier intent of their kind on their own branch;
//! - no slot is erased (state 2) or withheld (state 3), no ref points at an
//!   erased slot, and no note is of a server-only kind: those are evidence
//!   about the journal itself, written only by erasure, truncation and the
//!   server's custody path.
//!
//! A batch is all or nothing: if any frame is refused, the journal is left
//! exactly as it was. Accepted frames are *pending*, like frames from
//! [`Journal::append`]: the caller writes them durably and then calls
//! [`Journal::mark_persisted`], or calls [`Journal::discard_pending`] if the
//! write failed.
//!
//! # Appending notes to a long journal
//!
//! [`NoteAppender`] keeps only a journal's tail (entry count, head and file
//! length) and encodes new notes against it. The server's access log is a
//! journal that grows for as long as the server runs; holding every record
//! in memory to append the next one would grow without bound. Notes never
//! complete an intent and their payloads are written sealed, so nothing
//! about earlier entries is needed to encode one. [`decode_frame`] reads one
//! frame back on its own, for serving records from such a journal by
//! offset.

use std::fmt;
use std::hash::BuildHasher;
use std::ops::Range;

use crate::fault::Fault;
use crate::rand;
use crate::sha256::{Digest, DIGEST_LEN};
use crate::value::Value;

use super::codec::{self, DecodeOpts, RawBody, SALT_LEN};
use super::{
    check_append, note, Content, Cursor, Entry, Event, Journal, SlotMeta, SlotState,
    DEDUP_MIN_BYTES, FORMAT, HEADER_LEN, MAX_RECORD_BYTES, META, META_ID,
};

/// Why a batch of received frames was refused.
///
/// The reason describes structure, never content, so it can be returned to
/// the client and logged without leaking what a slot held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameError {
    /// Position of the refused frame within the batch, from zero.
    pub index: u64,
    /// The cursor the refused frame would have taken.
    pub cursor: Cursor,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frame {} (cursor {}) refused: {}",
            self.index, self.cursor, self.reason
        )
    }
}

impl std::error::Error for FrameError {}

/// Split `bytes` into whole frames (`len u32 ‖ record ‖ hash`).
///
/// Only the length prefixes are read: nothing is decoded or verified. `Err`
/// carries the number of whole frames before the problem and the reason,
/// when the bytes end inside a frame or a length exceeds the record limit.
pub fn split_frames(bytes: &[u8]) -> Result<Vec<&[u8]>, (u64, &'static str)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let index = out.len() as u64;
        if bytes.len() - pos < 4 {
            return Err((index, "frames end in a partial length prefix"));
        }
        let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as u64;
        if len > MAX_RECORD_BYTES {
            return Err((index, "frame length exceeds the 256 MiB record limit"));
        }
        let end = pos as u64 + 4 + len + DIGEST_LEN as u64;
        if end > bytes.len() as u64 {
            return Err((index, "frames end in a partial frame"));
        }
        out.push(&bytes[pos..end as usize]);
        pos = end as usize;
    }
    Ok(out)
}

/// The stored chain hash of a frame: its last 32 bytes. `None` for bytes too
/// short to be a frame.
pub fn frame_hash(frame: &[u8]) -> Option<Digest> {
    if frame.len() < 4 + DIGEST_LEN {
        return None;
    }
    frame[frame.len() - DIGEST_LEN..].try_into().ok()
}

/// Where a batch started, so a refused batch can be undone exactly.
#[derive(Clone, Copy)]
struct Mark {
    entries: usize,
    pending: usize,
    byte_len: u64,
}

impl Journal {
    /// Validate frames written by another process and append them as
    /// pending entries (spec 2.4 and 4.6; see the module documentation for
    /// the rules).
    ///
    /// Returns the cursors of the new entries. On error nothing is
    /// appended. The new entries stay pending until
    /// [`mark_persisted`](Self::mark_persisted); call
    /// [`discard_pending`](Self::discard_pending) if they could not be
    /// written.
    pub fn append_frames(&mut self, frames: &[u8]) -> Result<Range<Cursor>, FrameError> {
        let start = self.len();
        let refuse = |index: u64, reason: &'static str| FrameError {
            index,
            cursor: start + index,
            reason,
        };
        if self.format != FORMAT {
            return Err(refuse(0, "journal format 1 is read-only"));
        }
        if self.allow_withheld {
            return Err(refuse(0, "an evidence journal cannot be appended to"));
        }
        let split = split_frames(frames).map_err(|(index, reason)| refuse(index, reason))?;
        let mark = Mark {
            entries: self.entries.len(),
            pending: self.pending.len(),
            byte_len: self.byte_len,
        };
        for (index, frame) in split.iter().enumerate() {
            if let Err(reason) = self.accept_frame(frame) {
                self.rollback(mark);
                return Err(refuse(index as u64, reason));
            }
        }
        Ok(start..self.len())
    }

    /// Drop every entry that was appended but never marked persisted, as if
    /// it had never been appended: the write that should have made it
    /// durable failed.
    pub fn discard_pending(&mut self) {
        let mark = Mark {
            entries: self.persisted as usize,
            pending: 0,
            byte_len: self.byte_len - self.pending.len() as u64,
        };
        self.rollback(mark);
    }

    /// Check one received frame against the journal as it stands and, if it
    /// passes, append it as pending.
    fn accept_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let cursor = self.len();
        let rec = &frame[4..frame.len() - DIGEST_LEN];
        let stored = frame_hash(frame).ok_or("incomplete frame")?;
        let raw = codec::decode_raw(rec)?;
        for slot in &raw.slots {
            match (slot.state, &slot.body) {
                (2, _) => return Err("erased slots cannot be appended"),
                (3, _) => return Err("withheld slots cannot be appended"),
                (_, RawBody::Sealed { salt, content }) => {
                    if codec::commitment(salt, content) != slot.commitment {
                        return Err("slot content does not match its commitment");
                    }
                }
                _ => {}
            }
        }
        let (mut entry, salts) =
            codec::build_entry(&raw, cursor, &self.entries, DecodeOpts::default())?;
        check_received(&entry)?;
        let mut again = Vec::with_capacity(rec.len());
        codec::encode_record(&mut again, &entry, &salts);
        if again != rec {
            return Err("record is not canonically encoded");
        }
        codec::check_completion(&entry.event, &entry.branch, cursor, &self.entries)?;
        let implied = codec::link(
            self.key.as_deref(),
            &self.head(),
            cursor,
            &codec::skeleton(&entry),
        );
        if implied != stored {
            return Err("chain link does not verify from the current head");
        }
        entry.hash = stored;
        self.index_entry(&entry);
        self.entries.push(entry);
        self.salts.push(salts);
        self.byte_len += frame.len() as u64;
        self.pending.extend_from_slice(frame);
        Ok(())
    }

    /// Undo everything appended since `mark`, including the dedup index
    /// entries of the dropped entries.
    fn rollback(&mut self, mark: Mark) {
        let keep = mark.entries as Cursor;
        for entry in &self.entries[mark.entries..] {
            for (meta, content) in entry.slots.iter().zip(entry.event.slot_contents()) {
                let Some(v) = content.value() else { continue };
                if meta.state != SlotState::Sealed || v.len() < DEDUP_MIN_BYTES {
                    continue;
                }
                let key = self.dedup_seed.hash_one(v.as_bytes());
                if let Some(list) = self.dedup.get_mut(&key) {
                    list.retain(|&(c, _)| c < keep);
                    if list.is_empty() {
                        self.dedup.remove(&key);
                    }
                }
            }
        }
        self.entries.truncate(mark.entries);
        self.salts.truncate(mark.entries);
        self.pending.truncate(mark.pending);
        self.byte_len = mark.byte_len;
        self.persisted = self.persisted.min(self.len());
    }
}

/// The rules for what a client may write that a reader does not need:
/// no content that is already gone, no server-only notes, and forks that
/// stay inside the child numbering range.
fn check_received(entry: &Entry) -> Result<(), &'static str> {
    for (meta, content) in entry.slots.iter().zip(entry.event.slot_contents()) {
        if meta.state == SlotState::Ref && !content.is_sealed() {
            return Err("a ref to an erased slot cannot be appended");
        }
    }
    match &entry.event {
        Event::Note { kind, .. } if note::SERVER_ONLY.contains(&kind.as_str()) => {
            Err("server-only note kinds cannot be appended")
        }
        Event::Fork { base, children }
            if u64::from(*base) + u64::from(*children) > u64::from(META_ID) =>
        {
            Err("fork would number a child at or past 0xFFFF_FFFF")
        }
        _ => Ok(()),
    }
}

/// Decode one frame on its own, outside the journal it belongs to.
///
/// The record is decoded canonically (re-encoded and byte-compared) and
/// every sealed slot's commitment is checked, but the chain link is not:
/// the caller must have verified the journal the frame came from. Refs
/// cannot be resolved without the earlier entries, so a ref slot keeps its
/// target in [`SlotMeta::ref_target`] and reads as [`Content::Erased`].
/// The entry's hash is the stored hash.
pub fn decode_frame(frame: &[u8], cursor: Cursor) -> Result<Entry, &'static str> {
    let parts = split_frames(frame).map_err(|(_, reason)| reason)?;
    let [one] = parts.as_slice() else {
        return Err("expected exactly one frame");
    };
    let rec = &one[4..one.len() - DIGEST_LEN];
    let raw = codec::decode_raw(rec)?;
    for slot in &raw.slots {
        if let RawBody::Sealed { salt, content } = &slot.body {
            if codec::commitment(salt, content) != slot.commitment {
                return Err("slot content does not match its commitment");
            }
        }
    }
    let opts = DecodeOpts {
        allow_withheld: false,
        probe: true,
    };
    let (mut entry, salts) = codec::build_entry(&raw, cursor, &[], opts)?;
    let mut again = Vec::with_capacity(rec.len());
    codec::encode_record(&mut again, &entry, &salts);
    if again != rec {
        return Err("record is not canonically encoded");
    }
    entry.hash = frame_hash(one).ok_or("incomplete frame")?;
    Ok(entry)
}

/// Appends notes to a journal that is not held in memory.
///
/// Only the tail is kept: the entry count, the head the next entry chains
/// on and the file length. [`append`](Self::append) encodes a note frame
/// against it and advances it; the caller writes the frame. To undo
/// encoded frames that could not be written, keep a copy of the appender
/// from before (it is small and `Clone`).
#[derive(Clone)]
pub struct NoteAppender {
    key: Option<Vec<u8>>,
    entries: u64,
    head: Digest,
    byte_len: u64,
}

impl fmt::Debug for NoteAppender {
    /// Shape only: never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteAppender")
            .field("keyed", &self.key.is_some())
            .field("entries", &self.entries)
            .field("byte_len", &self.byte_len)
            .finish()
    }
}

impl NoteAppender {
    /// The tail of a new, empty format 2 journal (whose file is just the
    /// header, [`super::header`]).
    pub fn new(key: Option<&[u8]>) -> NoteAppender {
        let journal = Journal::new(key);
        NoteAppender {
            key: key.map(<[u8]>::to_vec),
            entries: 0,
            head: journal.head(),
            byte_len: HEADER_LEN as u64,
        }
    }

    /// Continue after `journal`, which must be format 2, stored (not from an
    /// evidence bundle) and fully persisted. The journal can be dropped
    /// afterwards.
    pub fn after(journal: &Journal) -> Result<NoteAppender, Fault> {
        if journal.format != FORMAT {
            return Err(Fault::Unsupported(super::FORMAT1_READ_ONLY.into()));
        }
        if journal.allow_withheld {
            return Err(Fault::Unsupported(
                "an evidence journal cannot be appended to".into(),
            ));
        }
        if journal.pending().is_some() {
            return Err(Fault::Unsupported(
                "the journal has entries that are not persisted".into(),
            ));
        }
        Ok(NoteAppender {
            key: journal.key.clone(),
            entries: journal.len(),
            head: journal.head(),
            byte_len: journal.byte_len(),
        })
    }

    /// The number of entries, which is the cursor the next note takes.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// The chain head: the hash of the last entry, or the genesis value.
    pub fn head(&self) -> Digest {
        self.head
    }

    /// The file length: header plus every frame.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Encode a note on the meta branch, stamped `at`, and advance the tail
    /// past it. Returns the note's cursor and its frame bytes.
    ///
    /// The same rules as [`Journal::append`] apply: strict JSON data, at
    /// most two payload slots of at most 64 MiB, a record of at most
    /// 256 MiB, salts from the operating system's CSPRNG, and no
    /// server-only kinds. Payloads are always sealed (never deduplicated
    /// into refs, which would need the earlier entries).
    pub fn append(
        &mut self,
        at: u64,
        kind: &str,
        data: &str,
        payload: &[Value],
    ) -> Result<(Cursor, Vec<u8>), Fault> {
        if note::SERVER_ONLY.contains(&kind) {
            return Err(Fault::Unsupported(format!(
                "note kind '{kind}' is written only by the erase, truncate and custody paths"
            )));
        }
        let event = Event::Note {
            kind: kind.to_string(),
            data: data.to_string(),
            payload: payload.iter().cloned().map(Content::Sealed).collect(),
        };
        check_append(META, &event)?;
        let slots_placeholder: Vec<SlotMeta> = payload
            .iter()
            .map(|_| SlotMeta::new([0u8; DIGEST_LEN], SlotState::Sealed, None))
            .collect();
        let record_len = codec::record_len(META, &event, &slots_placeholder);
        if record_len > MAX_RECORD_BYTES {
            return Err(Fault::TooLarge {
                size: record_len,
                limit: MAX_RECORD_BYTES,
            });
        }
        let mut salt_bytes = vec![0u8; payload.len() * SALT_LEN];
        rand::fill(&mut salt_bytes).map_err(|e| {
            Fault::Io(format!(
                "operating system random number generator failed: {e}"
            ))
        })?;
        let mut salts = Vec::with_capacity(payload.len());
        let mut slots = Vec::with_capacity(payload.len());
        for (value, salt) in payload.iter().zip(salt_bytes.chunks_exact(SALT_LEN)) {
            let salt: [u8; SALT_LEN] = salt.try_into().expect("exact chunk");
            let commitment = codec::commitment(&salt, value.as_bytes());
            slots.push(SlotMeta::new(commitment, SlotState::Sealed, None));
            salts.push(Some(salt));
        }
        let cursor = self.entries;
        let mut entry = Entry {
            cursor,
            at,
            branch: META.to_vec(),
            event,
            slots,
            hash: [0u8; DIGEST_LEN],
        };
        entry.hash = codec::link(
            self.key.as_deref(),
            &self.head,
            cursor,
            &codec::skeleton(&entry),
        );
        let mut frame = Vec::with_capacity(4 + record_len as usize + DIGEST_LEN);
        codec::encode_frame(&mut frame, &entry, &salts);
        self.entries += 1;
        self.head = entry.hash;
        self.byte_len += frame.len() as u64;
        Ok((cursor, frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{note as kinds, EraseSelector, ErasureNote, ROOT};

    fn run_start(id: &str) -> Event {
        Event::Note {
            kind: kinds::RUN_START.into(),
            data: format!("{{\"run_id\":\"{id}\"}}"),
            payload: vec![],
        }
    }

    fn recv(v: &str) -> Event {
        Event::ChannelRecv {
            channel: "in".into(),
            value: Content::from(v),
        }
    }

    /// A writer journal with `n` receives after `run.start`, everything
    /// persisted, and a receiver parsed from its bytes.
    fn pair(n: usize) -> (Journal, Journal) {
        let mut w = Journal::new(None);
        w.append(META, run_start("r")).unwrap();
        for i in 0..n {
            w.append(ROOT, recv(&format!("v{i}"))).unwrap();
        }
        w.mark_persisted(w.len());
        let r = Journal::parse(&w.to_bytes(), None).unwrap().journal;
        (w, r)
    }

    fn pending_frames(w: &Journal) -> Vec<u8> {
        w.pending().map(|(_, f, _)| f.to_vec()).unwrap_or_default()
    }

    #[test]
    fn frames_from_a_writer_are_accepted_byte_for_byte() {
        let (mut w, mut r) = pair(2);
        w.append(ROOT, recv("next")).unwrap();
        let intent = w
            .append(
                ROOT,
                Event::EffectIntent {
                    name: "send".into(),
                    arg: Content::from("x".repeat(300)),
                },
            )
            .unwrap();
        w.append(
            ROOT,
            Event::EffectResult {
                intent,
                outcome: crate::journal::EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Content::from("x".repeat(300))),
            },
        )
        .unwrap();
        let frames = pending_frames(&w);
        let got = r.append_frames(&frames).unwrap();
        assert_eq!(got, 3..6);
        assert_eq!(r.head(), w.head());
        assert_eq!(r.pending().unwrap().1, frames.as_slice());
        r.mark_persisted(r.len());
        assert_eq!(r.to_bytes(), w.to_bytes());
        // The duplicate payload was written as a ref and resolves.
        assert_eq!(r.get(5).unwrap().slots[0].state, SlotState::Ref);
        assert_eq!(r.verify(), Ok(()));
    }

    #[test]
    fn a_bad_chain_link_is_refused_and_nothing_is_appended() {
        let (mut w, mut r) = pair(1);
        w.append(ROOT, recv("a")).unwrap();
        w.append(ROOT, recv("b")).unwrap();
        let mut frames = pending_frames(&w);
        let last = frames.len() - 1;
        frames[last] ^= 1;
        let before = r.to_bytes();
        let err = r.append_frames(&frames).unwrap_err();
        assert_eq!((err.index, err.cursor), (1, 3));
        assert!(err.reason.contains("chain link"), "{err}");
        assert_eq!(r.len(), 2);
        assert!(r.pending().is_none());
        assert_eq!(r.to_bytes(), before);
    }

    #[test]
    fn a_bad_commitment_is_refused() {
        let (mut w, mut r) = pair(0);
        w.append(ROOT, recv("hello")).unwrap();
        let mut frames = pending_frames(&w);
        let at = frames.windows(5).position(|x| x == b"hello").unwrap();
        frames[at] = b'j';
        let err = r.append_frames(&frames).unwrap_err();
        assert!(err.reason.contains("commitment"), "{err}");
    }

    #[test]
    fn frames_from_another_head_do_not_chain() {
        let (mut w, _) = pair(1);
        let (_, mut other) = pair(2);
        w.append(ROOT, recv("x")).unwrap();
        let err = other.append_frames(&pending_frames(&w)).unwrap_err();
        assert!(err.reason.contains("chain link"), "{err}");
    }

    #[test]
    fn erased_slots_and_refs_to_them_are_refused() {
        let (mut w, _) = pair(0);
        let big = "personal ".repeat(40);
        w.append(ROOT, recv(&big)).unwrap();
        w.append(ROOT, recv(&big)).unwrap();
        w.mark_persisted(w.len());
        assert_eq!(w.get(2).unwrap().slots[0].state, SlotState::Ref);
        let note = ErasureNote::local("test", "");
        let erased = w
            .erase(&EraseSelector::Slots(vec![(1, 0)]), &note, 1)
            .unwrap();

        // The erased frame of cursor 1 still chains, but its slot is state 2.
        let mut r = Journal::parse(&w.to_bytes(), None).unwrap().journal;
        r.truncate(1);
        let err = r
            .append_frames(&erased.journal.frame_bytes(1).unwrap())
            .unwrap_err();
        assert_eq!(err.reason, "erased slots cannot be appended");

        // A receiver whose copy of cursor 1 is erased refuses the original
        // ref frame of cursor 2.
        let mut r = erased.journal.clone();
        r.truncate(2);
        let err = r.append_frames(&w.frame_bytes(2).unwrap()).unwrap_err();
        assert_eq!(err.reason, "a ref to an erased slot cannot be appended");
    }

    #[test]
    fn server_only_notes_are_refused() {
        for kind in kinds::SERVER_ONLY {
            let (mut w, mut r) = pair(1);
            w.append_server_note(5, kind, "{}", vec![]).unwrap();
            let err = r.append_frames(&pending_frames(&w)).unwrap_err();
            assert_eq!(err.reason, "server-only note kinds cannot be appended");
        }
    }

    #[test]
    fn partial_frames_are_refused() {
        let (mut w, mut r) = pair(0);
        w.append(ROOT, recv("a")).unwrap();
        w.append(ROOT, recv("b")).unwrap();
        let frames = pending_frames(&w);
        let err = r.append_frames(&frames[..frames.len() - 3]).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.reason, "frames end in a partial frame");
        let err = r.append_frames(&frames[..2]).unwrap_err();
        assert_eq!(err.reason, "frames end in a partial length prefix");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_refused_batch_leaves_dedup_intact() {
        let (mut w, mut r) = pair(0);
        let big = "z".repeat(400);
        w.append(ROOT, recv(&big)).unwrap();
        w.append(ROOT, recv("small")).unwrap();
        let mut frames = pending_frames(&w);
        let last = frames.len() - 1;
        frames[last] ^= 0x80;
        assert!(r.append_frames(&frames).is_err());
        // Had the refused big slot stayed in the dedup index, this append
        // would be written as a ref to a cursor that does not exist.
        r.append(ROOT, recv(&big)).unwrap();
        assert_eq!(r.get(1).unwrap().slots[0].state, SlotState::Sealed);
        r.mark_persisted(r.len());
        assert!(Journal::parse(&r.to_bytes(), None).is_ok());
    }

    #[test]
    fn discard_pending_restores_the_persisted_journal() {
        let (mut w, mut r) = pair(2);
        let before = r.to_bytes();
        let len = r.byte_len();
        w.append(ROOT, recv(&"q".repeat(500))).unwrap();
        w.append(ROOT, recv("r")).unwrap();
        r.append_frames(&pending_frames(&w)).unwrap();
        assert_eq!(r.len(), 5);
        r.discard_pending();
        assert_eq!(r.len(), 3);
        assert_eq!(r.byte_len(), len);
        assert!(r.pending().is_none());
        assert_eq!(r.to_bytes(), before);
        // And the same frames can be offered again.
        assert_eq!(r.append_frames(&pending_frames(&w)).unwrap(), 3..5);
    }

    #[test]
    fn note_appender_writes_a_journal_that_reads_back() {
        let mut file = super::super::header(0).to_vec();
        let mut a = NoteAppender::new(None);
        for i in 0..3u64 {
            let (cursor, frame) = a
                .append(
                    10 + i,
                    "access",
                    &format!("{{\"n\":{i}}}"),
                    &[Value::from("who")],
                )
                .unwrap();
            assert_eq!(cursor, i);
            file.extend_from_slice(&frame);
        }
        let parsed = Journal::parse(&file, None).unwrap();
        assert_eq!(parsed.tail_len, 0);
        assert_eq!(parsed.journal.len(), 3);
        assert_eq!(parsed.journal.head(), a.head());
        assert_eq!(parsed.journal.byte_len(), a.byte_len());

        // Continue after the parsed journal.
        let mut b = NoteAppender::after(&parsed.journal).unwrap();
        let (cursor, frame) = b.append(20, "access", "{}", &[]).unwrap();
        assert_eq!(cursor, 3);
        file.extend_from_slice(&frame);
        let parsed = Journal::parse(&file, None).unwrap().journal;
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed.head(), b.head());
        assert_eq!(parsed.verify(), Ok(()));
    }

    #[test]
    fn note_appender_refuses_what_append_refuses() {
        let mut a = NoteAppender::new(None);
        assert!(a.append(1, kinds::ERASURE, "{}", &[]).is_err());
        assert!(a.append(1, "x", "{\"a\":1,\"a\":2}", &[]).is_err());
        let three = [Value::from("1"), Value::from("2"), Value::from("3")];
        assert!(a.append(1, "x", "{}", &three).is_err());
        assert_eq!(a.entries(), 0);
        let keyed = NoteAppender::new(Some(b"k"));
        assert_eq!(keyed.head(), Journal::new(Some(b"k")).head());
    }

    #[test]
    fn decode_frame_reads_one_frame_alone() {
        let (mut w, _) = pair(0);
        let big = "m".repeat(300);
        w.append(ROOT, recv(&big)).unwrap();
        w.append(ROOT, recv(&big)).unwrap();
        let one = decode_frame(&w.frame_bytes(1).unwrap(), 1).unwrap();
        assert_eq!(&one, w.get(1).unwrap());
        let reference = decode_frame(&w.frame_bytes(2).unwrap(), 2).unwrap();
        assert_eq!(reference.slots[0].ref_target, Some((1, 0)));
        assert_eq!(reference.event.slot_contents()[0], &Content::Erased);
        assert_eq!(reference.hash, w.get(2).unwrap().hash);
        let mut bad = w.frame_bytes(1).unwrap();
        let at = bad.windows(3).position(|x| x == b"mmm").unwrap();
        bad[at] = b'n';
        assert!(decode_frame(&bad, 1).is_err());
        let two = [w.frame_bytes(0).unwrap(), w.frame_bytes(1).unwrap()].concat();
        assert_eq!(decode_frame(&two, 0), Err("expected exactly one frame"));
    }
}
