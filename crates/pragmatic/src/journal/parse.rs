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
//! - If a complete, well-formed frame after the tail start chains from a
//!   frame before it (spec 2.14), entries were damaged in the middle of the
//!   file. That is **corruption**: an error at the failing cursor, and the
//!   file is never truncated.
//!
//! A writer truncates whatever is classified as a torn tail, so every rule
//! below leans towards corruption whenever the damage could have hit
//! acknowledged entries:
//!
//! - **Successors at any distance.** Damage can destroy more than the
//!   failing frame: a zeroed sector can take its stored hash and the next
//!   frame's length, or whole frames. The first intact frame after it then
//!   chains from bytes that are gone, but the one after that chains from
//!   it. So a candidate frame is tried at every cursor it could have, given
//!   that each destroyed frame took at least the smallest frame's size, and
//!   any frame that chains makes the damage corruption. The successor of
//!   the failing frame is also tried against the hash its content implies,
//!   so a bit flip in a stored hash is corruption too.
//! - **Fully formed frames.** A frame whose stored hash equals the hash its
//!   decoded skeleton implies was written whole by a writer that computed
//!   that hash. If its content then fails a commitment, the content was
//!   damaged afterwards (bit rot, tampering) unless the damage looks like
//!   blocks the filesystem never wrote: a crash can leave the block with
//!   the hash on disk and a block of content reading back as zeros. Without
//!   such a zero block the frame is corruption on its own. The same goes
//!   for a frame whose completion names an intent it cannot complete: the
//!   intent cursor is a hashed field, so the writer wrote it.
//! - **Hashes that do not match.** A frame that decodes and has valid
//!   commitments but a stored hash that is not the implied one is
//!   corruption on its own (a wrong key, a cleared keyed flag, tampering),
//!   unless the stored hash is the implied hash with its last bytes zero:
//!   the shape a write cut off inside the hash leaves behind, and one a
//!   wrong key cannot produce.
//!
//! [`Journal::audit_bytes`] reads a file the same way but reports
//! corruption as a failed [`VerifyReport`] naming the first bad cursor,
//! which is what a verifier needs; a reader that only wants entries uses
//! [`Journal::parse`].

use std::fmt;
use std::io;

use crate::fault::Fault;
use crate::sha256::{Digest, DIGEST_LEN};

use super::codec::{self, DecodeOpts, RawBody, MIN_RECORD};
use super::legacy;
use super::{
    Cursor, Entry, Event, Journal, Salts, VerifyReport, FLAG_KEYED, FORMAT, HEADER_LEN, MAGIC,
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

/// A parse that went as far as the damage: the valid prefix, and where and
/// why the file is corrupt, if it is.
type Lenient = (Parsed, Option<(Cursor, String)>);

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
        strict(parse_inner(bytes, key, false)?)
    }

    /// Read the journal inside an evidence bundle: always unkeyed, and slots
    /// may be withheld (state 3). The caller decides whether trailing bytes
    /// are acceptable (for a bundle they are not).
    pub fn parse_evidence(bytes: &[u8]) -> Result<Parsed, JournalError> {
        strict(parse_inner(bytes, None, true)?)
    }

    /// Verify a stored journal from its file bytes: the full
    /// [`audit`](Journal::audit) of everything that reads, with corruption
    /// reported as [`VerifyReport::first_bad`] instead of as an error.
    /// Returns the valid prefix (everything before the first bad cursor)
    /// with the report.
    ///
    /// A verifier asks "is this journal intact, and if not, where does it
    /// first go wrong?", and tampering in the middle of a file is exactly
    /// what makes [`parse`](Journal::parse) refuse it. Errors are left for
    /// files that cannot be judged at all: not a journal, or a key
    /// mismatch.
    pub fn audit_bytes(
        bytes: &[u8],
        key: Option<&[u8]>,
    ) -> Result<(Journal, VerifyReport), JournalError> {
        let (parsed, corrupt) = parse_inner(bytes, key, false)?;
        let mut report = parsed.journal.audit();
        if let Some((cursor, _)) = corrupt {
            report.first_bad = Some(report.first_bad.map_or(cursor, |c| c.min(cursor)));
        }
        Ok((parsed.journal, report))
    }
}

/// A parse result for callers that refuse corruption.
fn strict((parsed, corrupt): Lenient) -> Result<Parsed, JournalError> {
    match corrupt {
        Some((cursor, reason)) => Err(JournalError::Corrupt { cursor, reason }),
        None => Ok(parsed),
    }
}

fn parse_inner(
    bytes: &[u8],
    key: Option<&[u8]>,
    allow_withheld: bool,
) -> Result<Lenient, JournalError> {
    if bytes.len() < legacy::HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(JournalError::InvalidData(
            "not a Pragmatic journal (bad magic)".into(),
        ));
    }
    match u32::from_le_bytes(bytes[8..12].try_into().unwrap()) {
        1 => Ok(parse_v1(bytes, key)),
        FORMAT => {
            let flags = check_header(bytes, key)?;
            Ok(parse_v2(bytes, key, flags, allow_withheld))
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
    /// The frame is complete and its damage cannot be what an interrupted
    /// write leaves behind, so it is corruption whatever follows (see the
    /// module docs).
    intact: bool,
}

impl Failure {
    fn plain(reason: &'static str) -> Failure {
        Failure {
            reason,
            implied: None,
            intact: false,
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

/// True if `stored` is what a write cut off inside the hash leaves: the
/// implied hash up to some byte, and zeros from there to the end (a block
/// the filesystem extended but never wrote reads back as zeros). A wrong
/// key or a forged hash differs from the implied hash before its zeros.
fn hash_possibly_unwritten(stored: &Digest, implied: &Digest) -> bool {
    let zeros = stored.iter().rev().take_while(|&&b| b == 0).count();
    zeros > 0 && stored[..DIGEST_LEN - zeros] == implied[..DIGEST_LEN - zeros]
}

/// The block size unwritten regions are aligned to: the smallest sector
/// size, which every filesystem block size is a multiple of.
const BLOCK: usize = 512;

/// True if the bytes `bytes[start..end]` (a slot's content) contain a
/// stretch that reads like a block the filesystem never wrote: for some
/// 512-byte-aligned block of the file, its overlap with the content is all
/// zeros.
fn shows_unwritten_block(bytes: &[u8], start: usize, end: usize) -> bool {
    if start >= end {
        return false;
    }
    let mut block = start - start % BLOCK;
    while block < end {
        let lo = block.max(start);
        let hi = (block + BLOCK).min(end);
        if bytes[lo..hi].iter().all(|&b| b == 0) {
            return true;
        }
        block += BLOCK;
    }
    false
}

/// Where `part` starts within `whole`, for a sub-slice of it.
fn offset_in(whole: &[u8], part: &[u8]) -> usize {
    part.as_ptr() as usize - whole.as_ptr() as usize
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

/// The smallest possible format 2 frame: length, the smallest record, hash.
const MIN_FRAME_V2: usize = 4 + MIN_RECORD + DIGEST_LEN;

fn parse_v2(bytes: &[u8], key: Option<&[u8]>, flags: u32, allow_withheld: bool) -> Lenient {
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
                let probe = |p: usize| probe_v2(&j, bytes, p, opts);
                let scan = Scan {
                    bytes,
                    tail_start: pos,
                    failing: j.len(),
                    min_frame: MIN_FRAME_V2,
                    key,
                    link: codec::link,
                };
                let corrupt = scan.classify(&fail, probe).map(|reason| (j.len(), reason));
                return (torn(j, bytes, pos), corrupt);
            }
        }
    }
    (torn(j, bytes, pos), None)
}

/// Decode, re-encode, byte-compare, check commitments, the chain link and
/// the completion reference of the frame at `pos`.
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
    let linked = implied == stored;
    for slot in &raw.slots {
        let RawBody::Sealed { salt, content } = &slot.body else {
            continue;
        };
        if codec::commitment(salt, content) == slot.commitment {
            continue;
        }
        // A fully formed frame whose content no longer matches was damaged
        // after it was written, unless the damage is a block the
        // filesystem never wrote. A frame whose hash does not match either
        // was cut off by a crash only if its hash shows that too.
        let intact = if linked {
            let start = offset_in(bytes, content);
            !shows_unwritten_block(bytes, start, start + content.len())
        } else {
            !hash_possibly_unwritten(&stored, &implied)
        };
        return Err(Failure {
            reason: "slot content does not match its commitment",
            implied: Some((end, implied)),
            intact,
        });
    }
    if !linked {
        return Err(Failure {
            reason: "chain link does not verify (wrong key, tampering or corruption)",
            implied: Some((end, implied)),
            intact: !hash_possibly_unwritten(&stored, &implied),
        });
    }
    if let Err(reason) = codec::check_completion(&entry.event, &entry.branch, cursor, &j.entries) {
        return Err(Failure {
            reason,
            implied: Some((end, implied)),
            intact: true,
        });
    }
    entry.hash = stored;
    Ok((entry, salts, end))
}

/// A complete, well-formed format 2 frame at `p`, as the scan needs it: its
/// stored hash and its skeleton (what the chain hashes besides the previous
/// hash and the cursor).
fn probe_v2(j: &Journal, bytes: &[u8], p: usize, opts: DecodeOpts) -> Option<(Digest, Vec<u8>)> {
    let (rec, stored, _) = read_frame(bytes, p).ok()?;
    if rec.len() < MIN_RECORD {
        return None;
    }
    let raw = codec::decode_raw(rec).ok()?;
    let probe = DecodeOpts {
        probe: true,
        ..opts
    };
    // Refs to entries the damage destroyed are accepted unresolved: the
    // largest cursor keeps "points backwards" from rejecting them.
    let (entry, _) = codec::build_entry(&raw, Cursor::MAX, &j.entries, probe).ok()?;
    Some((stored, codec::skeleton(&entry)))
}

// ---------------------------------------------------------------------------
// Format 1
// ---------------------------------------------------------------------------

/// The smallest possible format 1 frame: length, a tag and one empty
/// length-prefixed field (or a clock), hash.
const MIN_FRAME_V1: usize = 4 + 1 + 8 + DIGEST_LEN;

fn parse_v1(bytes: &[u8], key: Option<&[u8]>) -> Lenient {
    let mut j = Journal::empty(1, 0, key, [0u8; DIGEST_LEN]);
    let mut pos = legacy::HEADER_LEN;
    while pos < bytes.len() {
        match next_v1(&j, bytes, pos) {
            Ok((entry, end)) => {
                j.push_parsed(entry, Vec::new(), end - pos);
                pos = end;
            }
            Err(fail) => {
                let probe = |p: usize| probe_v1(bytes, p);
                let scan = Scan {
                    bytes,
                    tail_start: pos,
                    failing: j.len(),
                    min_frame: MIN_FRAME_V1,
                    key,
                    link: legacy::link,
                };
                let corrupt = scan.classify(&fail, probe).map(|reason| (j.len(), reason));
                return (torn(j, bytes, pos), corrupt);
            }
        }
    }
    (torn(j, bytes, pos), None)
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
            intact: !hash_possibly_unwritten(&stored, &implied),
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

fn probe_v1(bytes: &[u8], p: usize) -> Option<(Digest, Vec<u8>)> {
    let (payload, stored, _) = read_frame(bytes, p).ok()?;
    legacy::decode(payload).ok()?;
    Some((stored, payload.to_vec()))
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// The chain function of a format: `H(prev ‖ cursor ‖ input)`.
type LinkFn = fn(Option<&[u8]>, &Digest, Cursor, &[u8]) -> Digest;

/// The most chain links one classification computes. A torn tail holds at
/// most a few candidate frames, so this is only reached by bytes crafted to
/// look like many frames; they are then reported as corruption, which is
/// never truncated.
const MAX_LINK_TRIES: u64 = 1 << 18;

/// The search for a frame that still chains after the damage at
/// `tail_start` (spec 2.14).
struct Scan<'a> {
    bytes: &'a [u8],
    tail_start: usize,
    /// The cursor of the failing frame.
    failing: Cursor,
    min_frame: usize,
    key: Option<&'a [u8]>,
    link: LinkFn,
}

impl Scan<'_> {
    /// `Some(reason)` if the damage is corruption, `None` if it is a torn
    /// tail. `probe(p)` decodes a complete, well-formed frame at `p`.
    fn classify(
        &self,
        fail: &Failure,
        probe: impl Fn(usize) -> Option<(Digest, Vec<u8>)>,
    ) -> Option<String> {
        if fail.intact {
            return Some(fail.reason.to_string());
        }
        let next = self.failing + 1;
        if let Some((end, implied)) = fail.implied {
            if let Some((stored, input)) = probe(end) {
                if (self.link)(self.key, &implied, next, &input) == stored {
                    return Some(fail.reason.to_string());
                }
            }
        }
        // Every offset after the failing frame's smallest extent could be
        // where a surviving frame starts (the failing frame's own length may
        // be what was damaged). A surviving frame chains from the 32 bytes
        // just before it, which are its predecessor's stored hash: the
        // failing frame's, or that of a frame after it when the damage
        // destroyed more than one. Each destroyed frame took at least
        // `min_frame` bytes, which bounds the cursors to try.
        let mut tries = 0u64;
        let first = self.tail_start + self.min_frame;
        for p in first..self.bytes.len() {
            let Some((stored, input)) = probe(p) else {
                continue;
            };
            let prev: Digest = self.bytes[p - DIGEST_LEN..p].try_into().unwrap();
            let span = ((p - self.tail_start) / self.min_frame) as u64;
            for cursor in next..=next + span {
                tries += 1;
                if tries > MAX_LINK_TRIES {
                    return Some(format!(
                        "{} (the bytes after it hold too many frame-like records to tell a \
                         torn write from damage)",
                        fail.reason
                    ));
                }
                if (self.link)(self.key, &prev, cursor, &input) == stored {
                    return Some(format!(
                        "{} (a later frame at byte {p} still chains, as cursor {cursor})",
                        fail.reason
                    ));
                }
            }
        }
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_hashes_are_told_from_wrong_ones() {
        let implied: Digest = std::array::from_fn(|i| i as u8 + 1);
        for zeros in 1..=DIGEST_LEN {
            let mut cut = implied;
            cut[DIGEST_LEN - zeros..].fill(0);
            assert!(hash_possibly_unwritten(&cut, &implied), "{zeros}");
        }
        assert!(!hash_possibly_unwritten(&implied, &implied));
        let mut other = implied;
        other[0] ^= 1;
        other[DIGEST_LEN - 1] = 0;
        assert!(!hash_possibly_unwritten(&other, &implied));
    }

    #[test]
    fn unwritten_blocks_are_aligned_zero_runs() {
        let mut bytes = vec![7u8; 4 * BLOCK];
        // Content spanning [100, 1500): no zeros at all.
        assert!(!shows_unwritten_block(&bytes, 100, 1500));
        // A zero run that is not a whole aligned block inside the content.
        bytes[600..1000].fill(0);
        assert!(!shows_unwritten_block(&bytes, 100, 1500));
        // The block [1024, 1536) zero where it overlaps the content.
        bytes[1024..1500].fill(0);
        assert!(shows_unwritten_block(&bytes, 100, 1500));
        // An empty content shows nothing.
        assert!(!shows_unwritten_block(&bytes, 50, 50));
    }
}
