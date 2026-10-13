//! Reading a journal file: [`Journal::parse`] (spec 2.1, 2.4 and 2.14).
//!
//! Parsing is pure. It takes bytes and returns a journal, the length of the
//! valid prefix and the length of the tail after it; it never writes, so
//! every read-only consumer (CLI, console, snapshots, strict replay,
//! evidence) can call it on a live file.
//!
//! # Torn tails and corruption
//!
//! The tail starts at the first frame that is incomplete, fails to decode,
//! fails a commitment or fails its chain link. What happens next depends on
//! whether the damage looks like an interrupted write or like something
//! else:
//!
//! - A crash during an append leaves the *end* of the file damaged: a
//!   partial frame, or a region the filesystem extended but never filled
//!   (zeros). Nothing valid follows it. That is a **torn tail**: the parse
//!   succeeds with `tail_len > 0`, and a writer holding the lock may move
//!   the tail aside and truncate.
//! - If a complete, well-formed frame after the tail start chains from the
//!   failing frame (spec 2.14), entries were damaged in the middle of the
//!   file. That is **corruption**: an error at the failing cursor, and the
//!   file is never truncated.
//!
//! Two refinements keep a single damaged byte from being mistaken for a
//! crash, which would let a writer truncate acknowledged entries:
//!
//! - The successor is also tried against the hash the failing frame's
//!   content implies, so a bit flip in a stored hash (which leaves the
//!   successor chaining from the *true* hash) is corruption too.
//! - A frame that is complete, decodes canonically, has valid commitments
//!   and fails only its chain link, with a stored hash that does not end in
//!   zeros, is corruption on its own. A crash cannot produce it (an
//!   unwritten hash reads back as zeros), but a wrong key, a cleared keyed
//!   flag or tampering does, and none of those may ever be "repaired" by
//!   truncation.

use std::fmt;
use std::io;

use crate::fault::Fault;
use crate::sha256::{Digest, DIGEST_LEN};

use super::codec::{self, DecodeOpts, MIN_RECORD};
use super::legacy;
use super::{
    Cursor, Entry, Event, Journal, Salts, SlotState, FLAG_KEYED, FORMAT, HEADER_LEN, MAGIC,
    MAX_RECORD_BYTES,
};

/// The result of [`Journal::parse`].
#[derive(Clone, Debug)]
pub struct Parsed {
    /// The entries of the valid prefix.
    pub journal: Journal,
    /// Bytes of the valid prefix (header included).
    pub valid_len: u64,
    /// Bytes after the valid prefix: a torn tail, zero for a clean file.
    pub tail_len: u64,
}

/// Why a journal could not be read.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// Not a journal, an unknown format, reserved header bits, or a key
    /// supplied for an unkeyed journal (spec 2.1).
    InvalidData(String),
    /// A keyed journal read without its key. Unkeyed verification is never
    /// attempted as a fallback.
    Unsupported(String),
    /// Damage in the middle of the journal. Never truncated.
    Corrupt { cursor: Cursor, reason: String },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalError::InvalidData(m) => write!(f, "invalid journal: {m}"),
            JournalError::Unsupported(m) => f.write_str(m),
            JournalError::Corrupt { cursor, reason } => {
                write!(f, "journal corrupt at cursor {cursor}: {reason}")
            }
        }
    }
}

impl std::error::Error for JournalError {}

impl From<JournalError> for Fault {
    fn from(e: JournalError) -> Fault {
        match e {
            JournalError::Unsupported(m) => Fault::Unsupported(m),
            other => Fault::Io(other.to_string()),
        }
    }
}

impl From<JournalError> for io::Error {
    fn from(e: JournalError) -> io::Error {
        let kind = match e {
            JournalError::Unsupported(_) => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e.to_string())
    }
}

impl Journal {
    /// Read a stored journal from its file bytes.
    ///
    /// `key` must be the HMAC key for a keyed journal and `None` for an
    /// unkeyed one; a mismatch either way is an error, never a fallback.
    /// Format 1 journals are read too (keyed or not, as `key` says) and come
    /// back read-only.
    ///
    /// The returned journal holds the valid prefix. A torn tail is reported
    /// in [`Parsed::tail_len`] and ignored; corruption is
    /// [`JournalError::Corrupt`]. See the module documentation for how the
    /// two are told apart.
    pub fn parse(bytes: &[u8], key: Option<&[u8]>) -> Result<Parsed, JournalError> {
        parse_inner(bytes, key, false)
    }

    /// Read the journal inside an evidence bundle: always unkeyed, and slots
    /// may be withheld (state 3). The caller decides whether trailing bytes
    /// are acceptable (for a bundle they are not).
    pub fn parse_evidence(bytes: &[u8]) -> Result<Parsed, JournalError> {
        parse_inner(bytes, None, true)
    }
}

fn parse_inner(
    bytes: &[u8],
    key: Option<&[u8]>,
    allow_withheld: bool,
) -> Result<Parsed, JournalError> {
    if bytes.len() < legacy::HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(JournalError::InvalidData(
            "not a Pragmatic journal (bad magic)".into(),
        ));
    }
    match u32::from_le_bytes(bytes[8..12].try_into().unwrap()) {
        1 => parse_v1(bytes, key),
        FORMAT => {
            let flags = check_header(bytes, key)?;
            parse_v2(bytes, key, flags, allow_withheld)
        }
        v => Err(JournalError::InvalidData(format!(
            "unsupported journal format {v}"
        ))),
    }
}

/// The opening rules of spec 2.1.
fn check_header(bytes: &[u8], key: Option<&[u8]>) -> Result<u32, JournalError> {
    if bytes.len() < HEADER_LEN {
        return Err(JournalError::InvalidData(
            "journal header is truncated".into(),
        ));
    }
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if flags & !FLAG_KEYED != 0 {
        return Err(JournalError::InvalidData(
            "journal header has reserved flag bits set".into(),
        ));
    }
    let keyed = flags & FLAG_KEYED != 0;
    match (keyed, key.is_some()) {
        (false, true) => Err(JournalError::InvalidData(
            "journal is unkeyed but a key was supplied".into(),
        )),
        (true, false) => Err(JournalError::Unsupported(
            "journal is keyed: supply its key to read it".into(),
        )),
        _ => Ok(flags),
    }
}

/// Why the frame at the tail start failed, with what the classifier needs.
struct Failure {
    reason: &'static str,
    /// When the frame decoded: where it ends and the chain hash its content
    /// implies.
    implied: Option<(usize, Digest)>,
    /// The frame is intact and only its link fails (see the module docs).
    intact_link_mismatch: bool,
}

impl Failure {
    fn plain(reason: &'static str) -> Failure {
        Failure {
            reason,
            implied: None,
            intact_link_mismatch: false,
        }
    }
}

/// `(record, stored hash, end offset)` of the frame at `pos`.
fn read_frame(bytes: &[u8], pos: usize) -> Result<(&[u8], Digest, usize), &'static str> {
    if bytes.len() - pos < 4 {
        return Err("incomplete frame");
    }
    let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as u64;
    if len > MAX_RECORD_BYTES {
        return Err("frame length exceeds the 256 MiB record limit");
    }
    let end = pos as u64 + 4 + len + DIGEST_LEN as u64;
    if end > bytes.len() as u64 {
        return Err("incomplete frame");
    }
    let end = end as usize;
    let rec = &bytes[pos + 4..end - DIGEST_LEN];
    let stored: Digest = bytes[end - DIGEST_LEN..end].try_into().unwrap();
    Ok((rec, stored, end))
}

/// A hash whose last four bytes are zero is treated as possibly unwritten:
/// filesystems read never-written blocks back as zeros, so a write cut off
/// at a block boundary inside the hash leaves a zero suffix. A real SHA-256
/// output looks like that with probability 2^-32.
fn looks_unwritten(hash: &Digest) -> bool {
    hash[DIGEST_LEN - 4..] == [0; 4]
}

impl Journal {
    fn push_parsed(&mut self, entry: Entry, salts: Salts, frame_len: usize) {
        self.index_entry(&entry);
        self.entries.push(entry);
        self.salts.push(salts);
        self.byte_len += frame_len as u64;
        self.persisted = self.len();
    }
}

/// The run id of the `run.start` note in the first frame of a format 2
/// file, given at least its header and first frame. Nothing is verified
/// beyond decoding that one record: this is for listing runs, not for
/// trusting them.
pub(crate) fn first_run_start_id(prefix: &[u8]) -> Option<String> {
    if prefix.len() < HEADER_LEN || &prefix[..8] != MAGIC || prefix[8..12] != FORMAT.to_le_bytes() {
        return None;
    }
    let (rec, _, _) = read_frame(prefix, HEADER_LEN).ok()?;
    let raw = codec::decode_raw(rec).ok()?;
    let (entry, _) = codec::build_entry(&raw, 0, &[], DecodeOpts::default()).ok()?;
    super::run_start_id_of(&entry)
}

// ---------------------------------------------------------------------------
// Format 2
// ---------------------------------------------------------------------------

fn parse_v2(
    bytes: &[u8],
    key: Option<&[u8]>,
    flags: u32,
    allow_withheld: bool,
) -> Result<Parsed, JournalError> {
    let mut j = Journal::empty(FORMAT, flags, key, codec::genesis(key, flags));
    j.allow_withheld = allow_withheld;
    let opts = DecodeOpts {
        allow_withheld,
        probe: false,
    };
    let mut pos = HEADER_LEN;
    while pos < bytes.len() {
        match next_v2(&j, bytes, pos, opts) {
            Ok((entry, salts, end)) => {
                j.push_parsed(entry, salts, end - pos);
                pos = end;
            }
            Err(fail) => {
                let probe = |p: usize, prev: &Digest| probe_v2(&j, bytes, p, prev, opts);
                if let Some(reason) = classify(bytes, pos, &fail, probe) {
                    return Err(JournalError::Corrupt {
                        cursor: j.len(),
                        reason,
                    });
                }
                return Ok(torn(j, bytes, pos));
            }
        }
    }
    Ok(torn(j, bytes, pos))
}

/// Decode, re-encode, byte-compare, check commitments and the chain link of
/// the frame at `pos`.
fn next_v2(
    j: &Journal,
    bytes: &[u8],
    pos: usize,
    opts: DecodeOpts,
) -> Result<(Entry, Salts, usize), Failure> {
    let cursor = j.len();
    let (rec, stored, end) = read_frame(bytes, pos).map_err(Failure::plain)?;
    let raw = codec::decode_raw(rec).map_err(Failure::plain)?;
    let (mut entry, salts) =
        codec::build_entry(&raw, cursor, &j.entries, opts).map_err(Failure::plain)?;
    let mut again = Vec::with_capacity(rec.len());
    codec::encode_record(&mut again, &entry, &salts);
    if again != rec {
        return Err(Failure::plain("record is not canonically encoded"));
    }
    let implied = codec::link(
        j.key.as_deref(),
        &j.head(),
        cursor,
        &codec::skeleton(&entry),
    );
    let contents = entry.event.slot_contents();
    for ((meta, content), salt) in entry.slots.iter().zip(contents).zip(&salts) {
        if meta.state != SlotState::Sealed {
            continue;
        }
        let (Some(salt), Some(value)) = (salt, content.value()) else {
            continue;
        };
        if codec::commitment(salt, value.as_bytes()) != meta.commitment {
            return Err(Failure {
                reason: "slot content does not match its commitment",
                implied: Some((end, implied)),
                intact_link_mismatch: false,
            });
        }
    }
    if implied != stored {
        return Err(Failure {
            reason: "chain link does not verify (wrong key, tampering or corruption)",
            implied: Some((end, implied)),
            intact_link_mismatch: !looks_unwritten(&stored),
        });
    }
    entry.hash = stored;
    Ok((entry, salts, end))
}

/// True if a complete, well-formed format 2 frame at `p` chains from
/// `prev` as the entry after the failed one.
fn probe_v2(j: &Journal, bytes: &[u8], p: usize, prev: &Digest, opts: DecodeOpts) -> bool {
    let cursor = j.len() + 1;
    let Ok((rec, stored, _)) = read_frame(bytes, p) else {
        return false;
    };
    if rec.len() < MIN_RECORD {
        return false;
    }
    let Ok(raw) = codec::decode_raw(rec) else {
        return false;
    };
    let probe = DecodeOpts {
        probe: true,
        ..opts
    };
    let Ok((entry, _)) = codec::build_entry(&raw, cursor, &j.entries, probe) else {
        return false;
    };
    codec::link(j.key.as_deref(), prev, cursor, &codec::skeleton(&entry)) == stored
}

// ---------------------------------------------------------------------------
// Format 1
// ---------------------------------------------------------------------------

fn parse_v1(bytes: &[u8], key: Option<&[u8]>) -> Result<Parsed, JournalError> {
    let mut j = Journal::empty(1, 0, key, [0u8; DIGEST_LEN]);
    let mut pos = legacy::HEADER_LEN;
    while pos < bytes.len() {
        match next_v1(&j, bytes, pos) {
            Ok((entry, end)) => {
                j.push_parsed(entry, Vec::new(), end - pos);
                pos = end;
            }
            Err(fail) => {
                let probe = |p: usize, prev: &Digest| probe_v1(&j, bytes, p, prev);
                if let Some(reason) = classify(bytes, pos, &fail, probe) {
                    return Err(JournalError::Corrupt {
                        cursor: j.len(),
                        reason,
                    });
                }
                return Ok(torn(j, bytes, pos));
            }
        }
    }
    Ok(torn(j, bytes, pos))
}

fn next_v1(j: &Journal, bytes: &[u8], pos: usize) -> Result<(Entry, usize), Failure> {
    let cursor = j.len();
    let (payload, stored, end) = read_frame(bytes, pos).map_err(Failure::plain)?;
    let event = legacy::decode(payload).map_err(Failure::plain)?;
    if legacy::encode(&event) != payload {
        return Err(Failure::plain("record is not canonically encoded"));
    }
    let implied = legacy::link(j.key.as_deref(), &j.head(), cursor, payload);
    if implied != stored {
        return Err(Failure {
            reason: "chain link does not verify (wrong key, tampering or corruption)",
            implied: Some((end, implied)),
            intact_link_mismatch: !looks_unwritten(&stored),
        });
    }
    Ok((
        Entry {
            cursor,
            at: 0,
            branch: Vec::new(),
            event: Event::Legacy(event),
            slots: Vec::new(),
            hash: stored,
        },
        end,
    ))
}

fn probe_v1(j: &Journal, bytes: &[u8], p: usize, prev: &Digest) -> bool {
    let cursor = j.len() + 1;
    let Ok((payload, stored, _)) = read_frame(bytes, p) else {
        return false;
    };
    if legacy::decode(payload).is_err() {
        return false;
    }
    legacy::link(j.key.as_deref(), prev, cursor, payload) == stored
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// `Some(reason)` if the damage at `tail_start` is corruption, `None` if it
/// is a torn tail.
fn classify(
    bytes: &[u8],
    tail_start: usize,
    fail: &Failure,
    probe: impl Fn(usize, &Digest) -> bool,
) -> Option<String> {
    if fail.intact_link_mismatch {
        return Some(fail.reason.to_string());
    }
    if let Some((end, implied)) = fail.implied {
        if probe(end, &implied) {
            return Some(fail.reason.to_string());
        }
    }
    // Every offset after the failing frame's length prefix could be where
    // its successor starts (the length itself may be what was damaged). The
    // successor chains from the 32 bytes just before it, which are the
    // failing frame's stored hash.
    let first = tail_start + 4 + MIN_RECORD + DIGEST_LEN;
    for p in first..bytes.len() {
        let prev: Digest = bytes[p - DIGEST_LEN..p].try_into().unwrap();
        if probe(p, &prev) {
            return Some(format!(
                "{} (a later frame at byte {p} still chains from it)",
                fail.reason
            ));
        }
    }
    None
}

/// Finish a parse whose valid prefix ends at `valid_len`.
fn torn(mut journal: Journal, bytes: &[u8], valid_len: usize) -> Parsed {
    let tail_len = (bytes.len() - valid_len) as u64;
    journal.tail_len = tail_len;
    Parsed {
        journal,
        valid_len: valid_len as u64,
        tail_len,
    }
}
