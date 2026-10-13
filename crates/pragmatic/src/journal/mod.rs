//! The **Journal**: Pragmatic's append-only, hash-chained record of what an
//! agent did (journal format 2, spec section 2).
//!
//! Every model call, tool call, channel receive, random draw and clock read
//! made through Pragmatic is appended as an [`Entry`] before its result
//! reaches the agent. The journal is the system of record: it is replayed to
//! recover a crashed run without repeating work, and it is verified by
//! parties who do not trust whoever stored it.
//!
//! # Layout
//!
//! A journal file is a 16-byte header (`PRAGJRNL`, version 2, flags)
//! followed by frames `len u32 ‖ record ‖ hash`. A record holds structural
//! **fields** (names, cursors, small JSON metadata: never personal data,
//! never erasable) and up to 255 content **slots** (prompts, responses, tool
//! arguments: erasable). Each slot is stored with a salted commitment
//! `SHA-256("pragmatic/v2/slot" ‖ salt ‖ len ‖ content)`.
//!
//! # Integrity
//!
//! The chain covers each record's *skeleton*, in which every slot is
//! replaced by its commitment:
//!
//! ```text
//! h_{-1} = H("pragmatic/v2/genesis" ‖ flags)
//! h_i    = H(h_{i-1} ‖ cursor_i ‖ skeleton_i)
//! ```
//!
//! `H` is SHA-256, or HMAC-SHA-256 when the header's keyed bit is set.
//! Because content enters the chain only through commitments, a slot can be
//! erased (its content and salt dropped, its commitment kept) and every
//! chain hash still verifies. [`Journal::verify`] checks the chain and every
//! commitment; [`Journal::audit`] also accounts for every erased slot.
//!
//! # Reading
//!
//! [`Journal::parse`] is pure: it never writes. Every record is decoded
//! canonically, re-encoded and byte-compared (spec 2.4). A damaged end of
//! file is classified as a torn tail (safe to truncate, by a lock holder
//! only) or as corruption (an error, never truncated); see
//! [`Journal::parse`].
//!
//! # Writing
//!
//! [`Journal::append`] encodes a new entry, salts each sealed slot with 16
//! bytes from the operating system's CSPRNG and replaces a large slot that
//! repeats an earlier one with a reference to it. New frames stay pending
//! until a storage [`Sink`](crate::backend::Sink) has persisted them
//! ([`Journal::pending`], [`Journal::mark_persisted`]).

mod codec;
mod erase;
mod legacy;
mod parse;
mod receive;
mod withhold;

#[cfg(test)]
mod tests;

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;

use crate::fault::Fault;
use crate::json::Json;
use crate::rand;
use crate::sha256::{hex, Digest, DIGEST_LEN};
use crate::value::Value;

pub use erase::{EraseSelector, Erasure, ErasureNote};
pub use legacy::LegacyEvent;
pub use parse::{JournalError, Parsed};
pub use receive::{decode_frame, frame_hash, split_frames, FrameError, NoteAppender};
pub use withhold::Withheld;

pub(crate) use parse::first_run_start_id;

use codec::SALT_LEN;

/// A journal key: the entry's position in the log, counted from zero.
///
/// The cursor is the identity of an entry. It is independent of the entry's
/// content, so record and replay land on the same entry, and ordering is
/// always by cursor (never by the `at` wall-clock time).
pub type Cursor = u64;

/// A branch: the path of `u32` child indices from the root. The root branch
/// is the empty path; parallel regions fork child branches below it.
pub type Branch = Vec<u32>;

/// The root branch.
pub const ROOT: &[u32] = &[];
/// The single branch component of the meta branch.
pub const META_ID: u32 = 0xFFFF_FFFF;
/// The meta branch `[0xFFFF_FFFF]`, which holds only notes. Program replay
/// never reads it.
pub const META: &[u32] = &[META_ID];

/// The eight magic bytes that start every journal file.
pub const MAGIC: &[u8; 8] = b"PRAGJRNL";
/// The journal format this module writes.
pub const FORMAT: u32 = 2;
/// Bytes in a format 2 header: magic, version and flags.
pub const HEADER_LEN: usize = 16;
/// Header flag bit 0: the chain is keyed with HMAC-SHA-256.
pub const FLAG_KEYED: u32 = 1;

/// The largest content a single slot may hold (spec 2.15).
pub const MAX_SLOT_BYTES: u64 = 64 << 20;
/// The largest record a reader accepts; longer frames are corruption.
pub const MAX_RECORD_BYTES: u64 = 256 << 20;
/// The most slots one record may hold.
pub const MAX_SLOTS: usize = 255;
/// The deepest branch a record may sit on.
pub const MAX_DEPTH: usize = 32;
/// Content at least this long that repeats an earlier sealed slot is stored
/// as a ref to it instead of a second copy.
pub const DEDUP_MIN_BYTES: usize = 256;

/// The longest run id (spec 2.15).
pub const MAX_RUN_ID_LEN: usize = 200;
/// Run ids starting with this prefix are reserved for Pragmatic itself.
pub const RESERVED_RUN_ID_PREFIX: &str = "pragmatic:";

/// The message of the fault raised when a format 1 journal is opened for
/// writing (spec 2.16).
pub const FORMAT1_READ_ONLY: &str =
    "journal format 1 is read-only in 0.6: verify and export it with the CLI";

/// Note kinds (spec 2.11).
pub mod note {
    /// The first entry of every run: run id, nonce, SDK and labels.
    pub const RUN_START: &str = "run.start";
    /// The start of one attempt (run or resume).
    pub const ATTEMPT_START: &str = "attempt.start";
    /// The end of one attempt and its outcome.
    pub const ATTEMPT_END: &str = "attempt.end";
    /// A recorded program hash change accepted under `Continue`.
    pub const PROGRAM_CHANGE: &str = "program.change";
    /// A recovery decision for a frontier intent.
    pub const RECOVERY: &str = "recovery";
    /// Slots erased, by whom and why. Written only by erasure.
    pub const ERASURE: &str = "erasure";
    /// A lease's custody record. Written only by the server.
    pub const CUSTODY: &str = "custody";
    /// A torn tail that was moved aside. Written only by the writer that
    /// truncated it.
    pub const TORN_TAIL: &str = "torn_tail";
    /// Kinds that [`Journal::append`](super::Journal::append) refuses: they
    /// are evidence about the journal itself, so agent code must not be able
    /// to forge them.
    pub const SERVER_ONLY: [&str; 3] = [ERASURE, CUSTODY, TORN_TAIL];
}

/// The steps and faults of a [`Event::Refusal`] (spec 2.6).
pub mod refusal {
    /// A model call refused by the run's budget.
    pub const DRAW: &str = "draw";
    /// An effect refused because the run holds no capability for it.
    pub const EFFECT: &str = "effect";
    /// A receive that found the channel's inbox empty.
    pub const RECV: &str = "recv";
    /// The fault of a refused draw.
    pub const BUDGET_EXHAUSTED: &str = "BudgetExhausted";
    /// The fault of a refused effect.
    pub const CAPABILITY_DENIED: &str = "CapabilityDenied";
    /// The fault of a refused receive.
    pub const TIMEOUT: &str = "Timeout";
}

/// The content of one slot as a reader sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// The content is present.
    Sealed(Value),
    /// The content was erased; only its commitment remains.
    Erased,
    /// The content was withheld from an evidence bundle (redaction); only
    /// its commitment is included.
    Withheld,
}

impl Content {
    /// The value, if the content is present.
    pub fn value(&self) -> Option<&Value> {
        match self {
            Content::Sealed(v) => Some(v),
            _ => None,
        }
    }

    /// True if the content is present.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Content::Sealed(_))
    }
}

impl From<Value> for Content {
    fn from(v: Value) -> Self {
        Content::Sealed(v)
    }
}

impl From<&str> for Content {
    fn from(s: &str) -> Self {
        Content::Sealed(Value::from(s))
    }
}

impl From<String> for Content {
    fn from(s: String) -> Self {
        Content::Sealed(Value::from(s))
    }
}

impl From<Vec<u8>> for Content {
    fn from(b: Vec<u8>) -> Self {
        Content::Sealed(Value::from(b))
    }
}

/// How an effect ended (`EffectResult.outcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectOutcome {
    /// `perform` returned; the slot holds its result.
    Ok,
    /// `perform` raised; the slot holds the message.
    Failed,
    /// Recovery wrote the effect off; the replayed program performs it
    /// again under a new intent. No slot.
    Compensated,
}

impl EffectOutcome {
    /// The stored text: `ok`, `failed` or `compensated`.
    pub fn as_str(self) -> &'static str {
        match self {
            EffectOutcome::Ok => "ok",
            EffectOutcome::Failed => "failed",
            EffectOutcome::Compensated => "compensated",
        }
    }

    /// Parse the stored text.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"ok" => Some(EffectOutcome::Ok),
            b"failed" => Some(EffectOutcome::Failed),
            b"compensated" => Some(EffectOutcome::Compensated),
            _ => None,
        }
    }
}

/// The journal event alphabet (spec 2.6).
///
/// Fields (strings, cursors, JSON metadata) are structural and never
/// erasable. Every [`Content`] is a slot and can be erased.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A model call is about to be made with these request parts.
    DrawIntent {
        provenance: String,
        parts: Vec<Content>,
    },
    /// The response to the draw at `intent`. `meta` is strict JSON with
    /// usage, model and outcome.
    DrawResult {
        intent: Cursor,
        meta: String,
        head: Content,
        body: Content,
    },
    /// A value received on a channel.
    ChannelRecv { channel: String, value: Content },
    /// An effect is about to be performed with this argument.
    EffectIntent { name: String, arg: Content },
    /// How the effect at `intent` ended. `payload` is the result (ok) or the
    /// message (failed), and absent for compensated.
    EffectResult {
        intent: Cursor,
        outcome: EffectOutcome,
        error_kind: String,
        payload: Option<Content>,
    },
    /// A clock read.
    Clock { nanos: u64 },
    /// The identity of the program driving this branch.
    Program { name: String, hash: String },
    /// A parallel region forked `children` branches, numbered from `base`.
    Fork { base: u32, children: u32 },
    /// A code patch marker.
    Marker { name: String },
    /// A note on the meta branch: `kind` and strict JSON `data`, plus up to
    /// two payload slots.
    Note {
        kind: String,
        data: String,
        payload: Vec<Content>,
    },
    /// A random draw: `source` and strict JSON `args`, and the value.
    Random {
        source: String,
        args: String,
        value: Content,
    },
    /// A step the runtime refused without touching the world, raising
    /// `fault`: a receive on `name` that found its inbox empty
    /// ([`refusal::RECV`], `Timeout`), a draw over the budget
    /// ([`refusal::DRAW`], `BudgetExhausted`) or an effect `name` the run
    /// holds no capability for ([`refusal::EFFECT`], `CapabilityDenied`).
    /// It is journaled once the agent carries on past the fault, so replay
    /// raises the same fault at the same step.
    Refusal {
        step: String,
        name: String,
        fault: String,
    },
    /// An entry of a format 1 journal, which is read-only.
    Legacy(LegacyEvent),
}

impl Event {
    /// The kind's name as it appears in the spec and in Entry JSON.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Event::DrawIntent { .. } => "DrawIntent",
            Event::DrawResult { .. } => "DrawResult",
            Event::ChannelRecv { .. } => "ChannelRecv",
            Event::EffectIntent { .. } => "EffectIntent",
            Event::EffectResult { .. } => "EffectResult",
            Event::Clock { .. } => "Clock",
            Event::Program { .. } => "Program",
            Event::Fork { .. } => "Fork",
            Event::Marker { .. } => "Marker",
            Event::Note { .. } => "Note",
            Event::Random { .. } => "Random",
            Event::Refusal { .. } => "Refusal",
            Event::Legacy(_) => "Legacy",
        }
    }

    /// The slot contents in slot order (slot `k` is element `k`).
    pub fn slot_contents(&self) -> Vec<&Content> {
        match codec::event_parts(self) {
            Some((_, _, contents)) => contents,
            None => Vec::new(),
        }
    }

    /// Mutable slot contents in slot order.
    fn slot_contents_mut(&mut self) -> Vec<&mut Content> {
        match self {
            Event::DrawIntent { parts, .. } => parts.iter_mut().collect(),
            Event::DrawResult { head, body, .. } => vec![head, body],
            Event::ChannelRecv { value, .. }
            | Event::EffectIntent { arg: value, .. }
            | Event::Random { value, .. } => vec![value],
            Event::EffectResult { payload, .. } => payload.iter_mut().collect(),
            Event::Note { payload, .. } => payload.iter_mut().collect(),
            _ => Vec::new(),
        }
    }

    /// For a note, its kind.
    pub fn note_kind(&self) -> Option<&str> {
        match self {
            Event::Note { kind, .. } => Some(kind),
            _ => None,
        }
    }
}

/// The stored state of a slot (the `state` byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SlotState {
    /// Salt and content are stored.
    Sealed = 1,
    /// Content and salt were dropped by erasure.
    Erased = 2,
    /// Content was left out of an evidence bundle. Never in a stored journal.
    Withheld = 3,
    /// The content is that of an earlier sealed (or erased) slot.
    Ref = 4,
}

/// What the journal records about one slot besides its content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotMeta {
    /// The salted commitment to the content. Survives erasure.
    pub commitment: Digest,
    /// The stored state.
    pub state: SlotState,
    /// For a ref, the `(cursor, slot)` it points to.
    pub ref_target: Option<(Cursor, u8)>,
}

impl SlotMeta {
    fn new(commitment: Digest, state: SlotState, ref_target: Option<(Cursor, u8)>) -> Self {
        SlotMeta {
            commitment,
            state,
            ref_target,
        }
    }
}

/// One committed journal entry.
///
/// Salts are deliberately not part of an entry: they stay inside the
/// [`Journal`], so an entry can be shown or exported without handing out
/// what an attacker would need to test guesses against an erased
/// commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The entry's position in the journal.
    pub cursor: Cursor,
    /// Wall clock of the appending process, Unix nanoseconds UTC.
    /// Informational: chained, but never compared on replay and not
    /// guaranteed monotonic across machines.
    pub at: u64,
    /// The branch the entry was recorded on.
    pub branch: Branch,
    /// What happened.
    pub event: Event,
    /// One element per slot, in slot order.
    pub slots: Vec<SlotMeta>,
    /// The chain hash `h_cursor`.
    pub hash: Digest,
}

/// The full integrity report of [`Journal::audit`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// The first cursor whose chain link, commitment or ref fails.
    pub first_bad: Option<Cursor>,
    /// Erased slots that no later `erasure` note lists: erasure by a tool
    /// that bypassed Pragmatic, or bit rot.
    pub unaccounted_erasures: Vec<(Cursor, u8)>,
    /// Slots an `erasure` note lists that still hold content. Erasing them
    /// again repairs this.
    pub erasure_incomplete: Vec<(Cursor, u8)>,
    /// `erasure` notes that list slots that do not exist (or that are not
    /// earlier than the note), or whose data cannot be read.
    pub invalid_erasure_notes: Vec<Cursor>,
    /// Bytes past the valid prefix when the journal was read (a torn tail
    /// left by a crash).
    pub torn_bytes: u64,
}

impl VerifyReport {
    /// True when the chain, every commitment and every erasure check out.
    ///
    /// A torn tail does not make a report fail: it is what a crash during an
    /// append leaves behind, and the valid prefix before it verifies on its
    /// own. It is still reported in [`torn_bytes`](Self::torn_bytes).
    pub fn is_ok(&self) -> bool {
        self.first_bad.is_none()
            && self.unaccounted_erasures.is_empty()
            && self.erasure_incomplete.is_empty()
            && self.invalid_erasure_notes.is_empty()
    }
}

/// A torn tail moved aside by the writer that truncated it (spec 2.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TornTail {
    /// Byte offset where the tail started (the new file length).
    pub offset: u64,
    /// How many bytes were moved.
    pub bytes: u64,
    /// SHA-256 of the moved bytes.
    pub sha256: Digest,
    /// File name the bytes were moved to, in the journal's directory (empty
    /// when the backend has no files).
    pub moved_to: String,
    /// The number of entries in the valid prefix, which is the cursor the
    /// next entry takes.
    pub at_cursor: Cursor,
}

/// Check a run id against spec 2.15: `^[A-Za-z0-9._:-]{1,200}$`, and not
/// starting with the reserved `pragmatic:` prefix.
pub fn validate_run_id(id: &str) -> Result<(), Fault> {
    let ok_char = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-');
    if id.is_empty() || id.len() > MAX_RUN_ID_LEN || !id.bytes().all(ok_char) {
        return Err(Fault::Unsupported(
            "run ids must be 1 to 200 characters from A-Z, a-z, 0-9, '.', '_', ':' and '-'".into(),
        ));
    }
    if id.starts_with(RESERVED_RUN_ID_PREFIX) {
        return Err(Fault::Unsupported(
            "run ids starting with 'pragmatic:' are reserved".into(),
        ));
    }
    Ok(())
}

/// The 16-byte format 2 header for `flags`.
pub fn header(flags: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..12].copy_from_slice(&FORMAT.to_le_bytes());
    h[12..16].copy_from_slice(&flags.to_le_bytes());
    h
}

/// Wall clock in Unix nanoseconds, the default source of `at`.
pub fn system_clock() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Per-slot salts of one entry (`None` for slots that are not sealed).
type Salts = Vec<Option<[u8; SALT_LEN]>>;

/// An append-only, hash-chained journal for one run.
///
/// A `Journal` is an in-memory value. It does no I/O itself: it is read from
/// bytes ([`Journal::parse`]) and its new frames are handed to a storage
/// sink ([`Journal::pending`]), so the same journal works over files, memory
/// or a server.
#[derive(Clone)]
pub struct Journal {
    /// 1 for a read-only format 1 journal, 2 otherwise.
    format: u32,
    flags: u32,
    key: Option<Vec<u8>>,
    genesis: Digest,
    entries: Vec<Entry>,
    /// Salts of sealed slots, parallel to `entries`.
    salts: Vec<Salts>,
    /// Sealed slots of at least [`DEDUP_MIN_BYTES`], by a keyed hash of
    /// their content. The hasher is seeded per journal so crafted content
    /// cannot pile many slots into one bucket.
    dedup: HashMap<u64, Vec<(Cursor, u8)>>,
    dedup_seed: RandomState,
    /// Header plus every frame.
    byte_len: u64,
    /// Entries known to be durable.
    persisted: u64,
    /// Encoded frames of entries `persisted..len`.
    pending: Vec<u8>,
    /// Bytes past the valid prefix when the journal was parsed.
    tail_len: u64,
    /// Evidence journals may hold withheld slots.
    allow_withheld: bool,
    clock: fn() -> u64,
}

impl fmt::Debug for Journal {
    /// Shape only: never the key, never content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Journal")
            .field("format", &self.format)
            .field("keyed", &self.is_keyed())
            .field("entries", &self.entries.len())
            .field("byte_len", &self.byte_len)
            .field("persisted", &self.persisted)
            .field("head", &hex(&self.head()))
            .finish()
    }
}

impl Journal {
    /// An empty format 2 journal. With a key, the chain is keyed with
    /// HMAC-SHA-256 and the header's keyed bit is set.
    pub fn new(key: Option<&[u8]>) -> Journal {
        let flags = if key.is_some() { FLAG_KEYED } else { 0 };
        Journal::empty(FORMAT, flags, key, codec::genesis(key, flags))
    }

    fn empty(format: u32, flags: u32, key: Option<&[u8]>, genesis: Digest) -> Journal {
        let header_len = if format == 1 {
            legacy::HEADER_LEN
        } else {
            HEADER_LEN
        };
        Journal {
            format,
            flags,
            key: key.map(<[u8]>::to_vec),
            genesis,
            entries: Vec::new(),
            salts: Vec::new(),
            dedup: HashMap::new(),
            dedup_seed: RandomState::new(),
            byte_len: header_len as u64,
            persisted: 0,
            pending: Vec::new(),
            tail_len: 0,
            allow_withheld: false,
            clock: system_clock,
        }
    }

    /// The journal format: 2, or 1 for a read-only 0.4/0.5 journal.
    pub fn format(&self) -> u32 {
        self.format
    }

    /// The header flags (format 2).
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// True if the chain is keyed with HMAC-SHA-256.
    pub fn is_keyed(&self) -> bool {
        self.key.is_some()
    }

    /// The genesis value `h_{-1}` the chain starts from.
    pub fn genesis(&self) -> Digest {
        self.genesis
    }

    /// The header bytes of this journal's file.
    pub fn header_bytes(&self) -> Vec<u8> {
        if self.format == 1 {
            legacy::header().to_vec()
        } else {
            header(self.flags).to_vec()
        }
    }

    /// Number of entries.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// True if the journal has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in cursor order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry at `cursor`.
    pub fn get(&self, cursor: Cursor) -> Option<&Entry> {
        self.entries.get(cursor as usize)
    }

    /// The entries on program branches: everything except the meta branch.
    /// Use this for length and cursor assertions about what an agent did,
    /// since notes come and go with attempts.
    pub fn program_entries(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.branch != META).collect()
    }

    /// The chain head: the hash of the last entry, or the genesis value for
    /// an empty journal (the value the next entry chains on).
    pub fn head(&self) -> Digest {
        self.entries.last().map_or(self.genesis, |e| e.hash)
    }

    /// Size of the journal file: header plus every frame.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Bytes past the valid prefix when this journal was parsed.
    pub fn torn_bytes(&self) -> u64 {
        self.tail_len
    }

    /// The run id recorded in the `run.start` note at cursor 0, if there is
    /// one.
    pub fn run_start_id(&self) -> Option<String> {
        run_start_id_of(self.entries.first()?)
    }

    /// The journal clock's current reading, for stamping entries the journal
    /// layer writes itself (erasure and torn-tail notes).
    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Replace the source of `at` for appends (tests, deterministic
    /// fixtures). The default is [`system_clock`].
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    // -----------------------------------------------------------------
    // Appending
    // -----------------------------------------------------------------

    /// Append `event` on `branch`, stamped with the journal's clock.
    ///
    /// Every content must be [`Content::Sealed`]. The event is checked
    /// against the same rules a reader applies (spec 2.4), so a journal can
    /// never be written that would fail to read back:
    ///
    /// - a slot over 64 MiB, or a record over 256 MiB, is
    ///   [`Fault::TooLarge`];
    /// - the CSPRNG failing to produce a salt is [`Fault::Io`], with no
    ///   fallback;
    /// - anything else malformed (counts, non-strict JSON, a note off the
    ///   meta branch, a branch deeper than 32, a fork whose children would
    ///   reach index `0xFFFF_FFFF`, a result that does not complete an
    ///   earlier intent of its kind on its own branch, a refusal whose fault
    ///   does not fit its step, a server-only note kind, a format 1
    ///   journal) is [`Fault::Unsupported`].
    ///
    /// The new frame is pending until [`mark_persisted`](Self::mark_persisted).
    pub fn append(&mut self, branch: &[u32], event: Event) -> Result<Cursor, Fault> {
        let at = (self.clock)();
        self.append_at(at, branch, event)
    }

    /// [`append`](Self::append) with an explicit `at` (Unix nanoseconds).
    pub fn append_at(&mut self, at: u64, branch: &[u32], event: Event) -> Result<Cursor, Fault> {
        if let Some(kind) = event.note_kind() {
            if note::SERVER_ONLY.contains(&kind) {
                return Err(Fault::Unsupported(format!(
                    "note kind '{kind}' is written only by the erase, truncate and custody paths"
                )));
            }
        }
        self.push(at, branch, event)
    }

    /// Append a server-only note (`erasure`, `custody` or `torn_tail`).
    ///
    /// This is the path the server uses for custody records and the path
    /// erasure and torn-tail truncation use internally. It refuses every
    /// other kind, so ordinary notes keep going through
    /// [`append`](Self::append).
    pub fn append_server_note(
        &mut self,
        at: u64,
        kind: &str,
        data: &str,
        payload: Vec<Value>,
    ) -> Result<Cursor, Fault> {
        if !note::SERVER_ONLY.contains(&kind) {
            return Err(Fault::Unsupported(format!(
                "note kind '{kind}' is not a server-only kind"
            )));
        }
        let event = Event::Note {
            kind: kind.to_string(),
            data: data.to_string(),
            payload: payload.into_iter().map(Content::Sealed).collect(),
        };
        self.push(at, META, event)
    }

    /// Append the `torn_tail` note describing a tail the caller moved aside.
    pub fn append_torn_tail(&mut self, at: u64, torn: &TornTail) -> Result<Cursor, Fault> {
        let data = Json::Object(vec![
            ("bytes".into(), torn.bytes.into()),
            ("moved_to".into(), torn.moved_to.as_str().into()),
            ("offset".into(), torn.offset.into()),
            ("sha256".into(), hex(&torn.sha256).into()),
        ])
        .to_string();
        self.append_server_note(at, note::TORN_TAIL, &data, Vec::new())
    }

    /// Encode, salt, deduplicate, chain and buffer one entry. All checks
    /// happen before any state changes, so a failed append leaves the
    /// journal exactly as it was.
    fn push(&mut self, at: u64, branch: &[u32], mut event: Event) -> Result<Cursor, Fault> {
        if self.format != FORMAT {
            return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
        }
        check_append(branch, &event)?;
        let cursor = self.len();
        codec::check_completion(&event, branch, cursor, &self.entries)
            .map_err(|why| Fault::Unsupported(why.to_string()))?;

        // Dedup decisions first, so salts are drawn only for slots that are
        // actually sealed.
        let contents = event.slot_contents();
        let mut refs: Vec<Option<(Cursor, u8, Digest)>> = Vec::with_capacity(contents.len());
        for content in &contents {
            let value = content.value().expect("checked sealed");
            refs.push(self.find_duplicate(value.as_bytes()));
        }
        drop(contents);
        // A ref slot holds its target's bytes, so share the target's buffer
        // and let the caller's copy go: an agent that resends a long
        // conversation on every call then keeps one copy of each message.
        for (content, r) in event.slot_contents_mut().into_iter().zip(&refs) {
            if let Some((c, s, _)) = r {
                let target = self.entries[*c as usize].event.slot_contents()[*s as usize];
                *content = target.clone();
            }
        }

        // The size is known once the dedup decisions are made, so an
        // oversized record is refused before any content is hashed.
        let mut slots: Vec<SlotMeta> = refs
            .iter()
            .map(|r| match r {
                Some((c, s, commitment)) => {
                    SlotMeta::new(*commitment, SlotState::Ref, Some((*c, *s)))
                }
                None => SlotMeta::new([0u8; DIGEST_LEN], SlotState::Sealed, None),
            })
            .collect();
        let record_len = codec::record_len(branch, &event, &slots);
        if record_len > MAX_RECORD_BYTES {
            return Err(Fault::TooLarge {
                size: record_len,
                limit: MAX_RECORD_BYTES,
            });
        }

        // One CSPRNG read per append, never buffered across appends.
        let sealed = refs.iter().filter(|r| r.is_none()).count();
        let mut salt_bytes = vec![0u8; sealed * SALT_LEN];
        rand::fill(&mut salt_bytes).map_err(|e| {
            Fault::Io(format!(
                "operating system random number generator failed: {e}"
            ))
        })?;
        let mut fresh = salt_bytes.chunks_exact(SALT_LEN);
        let mut salts: Salts = Vec::with_capacity(slots.len());
        for (slot, content) in slots.iter_mut().zip(event.slot_contents()) {
            if slot.state != SlotState::Sealed {
                salts.push(None);
                continue;
            }
            let salt: [u8; SALT_LEN] = fresh.next().unwrap().try_into().unwrap();
            let bytes = content.value().expect("checked sealed").as_bytes();
            slot.commitment = codec::commitment(&salt, bytes);
            salts.push(Some(salt));
        }

        let mut entry = Entry {
            cursor,
            at,
            branch: branch.to_vec(),
            event,
            slots,
            hash: [0u8; DIGEST_LEN],
        };
        entry.hash = codec::link(
            self.key.as_deref(),
            &self.head(),
            cursor,
            &codec::skeleton(&entry),
        );

        // Encode straight into the pending buffer: content is copied once.
        let start = self.pending.len();
        self.pending
            .extend_from_slice(&(record_len as u32).to_le_bytes());
        codec::encode_record(&mut self.pending, &entry, &salts);
        debug_assert_eq!((self.pending.len() - start - 4) as u64, record_len);
        self.pending.extend_from_slice(&entry.hash);
        self.byte_len += 4 + record_len + DIGEST_LEN as u64;
        self.index_entry(&entry);
        self.entries.push(entry);
        self.salts.push(salts);
        Ok(cursor)
    }

    /// A sealed slot whose content equals `bytes`, if `bytes` is long enough
    /// to be worth deduplicating.
    fn find_duplicate(&self, bytes: &[u8]) -> Option<(Cursor, u8, Digest)> {
        if bytes.len() < DEDUP_MIN_BYTES {
            return None;
        }
        let candidates = self.dedup.get(&self.dedup_seed.hash_one(bytes))?;
        candidates.iter().find_map(|&(c, s)| {
            let entry = &self.entries[c as usize];
            let meta = entry.slots[s as usize];
            let same = meta.state == SlotState::Sealed
                && entry.event.slot_contents()[s as usize]
                    .value()
                    .is_some_and(|v| v.as_bytes() == bytes);
            same.then_some((c, s, meta.commitment))
        })
    }

    /// Add an entry's large sealed slots to the dedup index.
    fn index_entry(&mut self, entry: &Entry) {
        for (k, (meta, content)) in entry
            .slots
            .iter()
            .zip(entry.event.slot_contents())
            .enumerate()
        {
            if meta.state != SlotState::Sealed {
                continue;
            }
            let Some(v) = content.value() else { continue };
            if v.len() >= DEDUP_MIN_BYTES {
                let key = self.dedup_seed.hash_one(v.as_bytes());
                self.dedup
                    .entry(key)
                    .or_default()
                    .push((entry.cursor, k as u8));
            }
        }
    }

    // -----------------------------------------------------------------
    // Persistence bookkeeping
    // -----------------------------------------------------------------

    /// Frames appended since the last [`mark_persisted`](Self::mark_persisted):
    /// `(cursor of the first frame, frame bytes, head after them)`, or `None`
    /// when everything is persisted. This is exactly what a sink's
    /// `persist(at, frames, head_after)` takes.
    pub fn pending(&self) -> Option<(Cursor, &[u8], Digest)> {
        if self.persisted == self.len() {
            None
        } else {
            Some((self.persisted, &self.pending, self.head()))
        }
    }

    /// Entries known to be durable.
    pub fn persisted_len(&self) -> u64 {
        self.persisted
    }

    /// Record that the first `upto` entries are durable, and drop their
    /// buffered frames. Values outside `persisted..=len` are clamped.
    pub fn mark_persisted(&mut self, upto: u64) {
        let upto = upto.clamp(self.persisted, self.len());
        let mut cut = 0usize;
        for _ in self.persisted..upto {
            let len = u32::from_le_bytes(self.pending[cut..cut + 4].try_into().unwrap()) as usize;
            cut += 4 + len + DIGEST_LEN;
        }
        self.pending.drain(..cut);
        self.persisted = upto;
    }

    /// The complete file: header and every frame.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len as usize);
        out.extend_from_slice(&self.header_bytes());
        for i in 0..self.entries.len() {
            self.encode_frame_into(&mut out, i);
        }
        out
    }

    /// The encoded frame of the entry at `cursor`.
    pub fn frame_bytes(&self, cursor: Cursor) -> Option<Vec<u8>> {
        let i = usize::try_from(cursor).ok()?;
        if i >= self.entries.len() {
            return None;
        }
        let mut out = Vec::new();
        self.encode_frame_into(&mut out, i);
        Some(out)
    }

    fn encode_frame_into(&self, out: &mut Vec<u8>, i: usize) {
        let entry = &self.entries[i];
        match &entry.event {
            Event::Legacy(ev) => legacy::encode_frame(out, ev, &entry.hash),
            _ => codec::encode_frame(out, entry, &self.salts[i]),
        }
    }

    // -----------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------

    /// Check every commitment, every ref, every completion's intent
    /// reference and every chain link. `Err` names the first bad cursor.
    /// Erasure accounting is in [`audit`](Self::audit).
    pub fn verify(&self) -> Result<(), Cursor> {
        let key = self.key.as_deref();
        let mut prev = self.genesis;
        for (i, entry) in self.entries.iter().enumerate() {
            let cursor = i as Cursor;
            let expect = match &entry.event {
                Event::Legacy(ev) => legacy::link(key, &prev, cursor, &legacy::encode(ev)),
                _ => {
                    let completes = codec::check_completion(
                        &entry.event,
                        &entry.branch,
                        cursor,
                        &self.entries[..i],
                    );
                    if !self.slots_consistent(i) || completes.is_err() {
                        return Err(cursor);
                    }
                    codec::link(key, &prev, cursor, &codec::skeleton(entry))
                }
            };
            if entry.cursor != cursor || entry.hash != expect {
                return Err(cursor);
            }
            prev = entry.hash;
        }
        Ok(())
    }

    /// True if every slot of entry `i` agrees with its stored state: sealed
    /// content matches its commitment, refs resolve, erased and withheld
    /// slots hold nothing.
    fn slots_consistent(&self, i: usize) -> bool {
        let entry = &self.entries[i];
        let contents = entry.event.slot_contents();
        if contents.len() != entry.slots.len() || self.salts[i].len() != entry.slots.len() {
            return false;
        }
        let opts = codec::DecodeOpts {
            allow_withheld: self.allow_withheld,
            probe: false,
        };
        entry
            .slots
            .iter()
            .zip(contents)
            .zip(&self.salts[i])
            .all(
                |((meta, content), salt)| match (meta.state, content, salt) {
                    (SlotState::Sealed, Content::Sealed(v), Some(salt)) => {
                        codec::commitment(salt, v.as_bytes()) == meta.commitment
                    }
                    (SlotState::Erased, Content::Erased, None) => true,
                    (SlotState::Withheld, Content::Withheld, None) => self.allow_withheld,
                    (SlotState::Ref, content, None) => meta.ref_target.is_some_and(|(c, s)| {
                        codec::resolve_ref(c, s, &meta.commitment, i as Cursor, &self.entries, opts)
                            .is_ok_and(|resolved| &resolved == content)
                    }),
                    _ => false,
                },
            )
    }

    /// The full report: [`verify`](Self::verify) plus erasure accounting
    /// (spec 2.13) and the torn tail seen when the journal was read.
    pub fn audit(&self) -> VerifyReport {
        let mut report = VerifyReport {
            first_bad: self.verify().err(),
            torn_bytes: self.tail_len,
            ..VerifyReport::default()
        };
        let mut listed = std::collections::BTreeSet::new();
        for entry in &self.entries {
            let Event::Note { kind, data, .. } = &entry.event else {
                continue;
            };
            if kind != note::ERASURE {
                continue;
            }
            match erase::listed_slots(data, entry.cursor, &self.entries) {
                Ok(slots) => listed.extend(slots),
                Err(in_range) => {
                    report.invalid_erasure_notes.push(entry.cursor);
                    listed.extend(in_range);
                }
            }
        }
        for &(c, s) in &listed {
            if self.slot_holds_content(c, s) {
                report.erasure_incomplete.push((c, s));
            }
        }
        for entry in &self.entries {
            for (k, meta) in entry.slots.iter().enumerate() {
                if meta.state == SlotState::Erased && !listed.contains(&(entry.cursor, k as u8)) {
                    report.unaccounted_erasures.push((entry.cursor, k as u8));
                }
            }
        }
        report
    }

    /// True if slot `(c, s)` still yields content: sealed, or a ref whose
    /// target is sealed.
    fn slot_holds_content(&self, c: Cursor, s: u8) -> bool {
        self.get(c)
            .and_then(|e| {
                e.event
                    .slot_contents()
                    .get(s as usize)
                    .map(|c| c.is_sealed())
            })
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------
    // Test and crash-simulation hooks
    // -----------------------------------------------------------------

    /// TEST AND CRASH SIMULATION ONLY: keep the first `keep` entries, as if
    /// the storage had only durably held that prefix.
    #[doc(hidden)]
    pub fn truncate(&mut self, keep: u64) {
        let keep = keep.min(self.len()) as usize;
        self.entries.truncate(keep);
        self.salts.truncate(keep);
        self.byte_len = self.header_bytes().len() as u64;
        for i in 0..keep {
            let mut frame = Vec::new();
            self.encode_frame_into(&mut frame, i);
            self.byte_len += frame.len() as u64;
        }
        self.persisted = self.persisted.min(keep as u64);
        self.pending.clear();
        for i in self.persisted as usize..keep {
            let mut frame = Vec::new();
            self.encode_frame_into(&mut frame, i);
            self.pending.extend_from_slice(&frame);
        }
        self.dedup.clear();
        for i in 0..keep {
            let entry = self.entries[i].clone();
            self.index_entry(&entry);
        }
    }

    /// TEST ONLY: change an entry in place (without touching its hash), to
    /// check that verification notices.
    #[doc(hidden)]
    pub fn tamper(&mut self, cursor: Cursor, f: impl FnOnce(&mut Entry)) {
        if let Some(e) = self.entries.get_mut(cursor as usize) {
            f(e);
        }
    }
}

/// Parse a JSON field (note data, draw meta, random args) with the
/// journal's strict rules (spec 3.7): `None` if the text is not strict JSON.
pub(crate) fn strict_json_field(text: &str) -> Option<Json> {
    codec::strict_json(text.as_bytes()).ok()
}

/// The `run_id` of a `run.start` note.
fn run_start_id_of(entry: &Entry) -> Option<String> {
    match &entry.event {
        Event::Note { kind, data, .. } if kind == note::RUN_START => {
            let doc = codec::strict_json(data.as_bytes()).ok()?;
            doc.get("run_id")?.as_str().map(str::to_string)
        }
        _ => None,
    }
}

/// Check an event for appending against the reader's rules, plus the rules
/// that only make sense at write time (sealed content only, fork range).
fn check_append(branch: &[u32], event: &Event) -> Result<(), Fault> {
    let unsupported = |m: &str| Err(Fault::Unsupported(m.to_string()));
    if matches!(event, Event::Legacy(_)) {
        return unsupported("format 1 events cannot be appended");
    }
    if branch.len() > MAX_DEPTH {
        return unsupported("branch deeper than 32");
    }
    let is_note = matches!(event, Event::Note { .. });
    if is_note != (branch == META) {
        return unsupported("notes go on the meta branch, and only notes do");
    }
    let contents = event.slot_contents();
    if contents.len() > MAX_SLOTS {
        return unsupported("more than 255 slots in one record");
    }
    for content in &contents {
        match content {
            Content::Sealed(v) if v.len() as u64 > MAX_SLOT_BYTES => {
                return Err(Fault::TooLarge {
                    size: v.len() as u64,
                    limit: MAX_SLOT_BYTES,
                });
            }
            Content::Sealed(_) => {}
            _ => return unsupported("only sealed content can be appended"),
        }
    }
    let json_field = |text: &str, what: &str| -> Result<(), Fault> {
        codec::strict_json(text.as_bytes())
            .map(|_| ())
            .map_err(|why| Fault::Unsupported(format!("{what} is not strict JSON: {why}")))
    };
    match event {
        Event::DrawIntent { parts, .. } if parts.is_empty() => {
            return unsupported("a draw needs at least one request part");
        }
        Event::DrawResult { meta, .. } => json_field(meta, "draw result meta")?,
        Event::EffectResult {
            outcome, payload, ..
        } => {
            let want = *outcome != EffectOutcome::Compensated;
            if payload.is_some() != want {
                return unsupported("effect result payload does not match its outcome");
            }
        }
        Event::Fork { base, children } => {
            if *children == 0 {
                return unsupported("a fork needs at least one child");
            }
            if u64::from(*base) + u64::from(*children) > u64::from(META_ID) {
                return unsupported("fork would number a child at or past 0xFFFF_FFFF");
            }
        }
        Event::Note { data, payload, .. } => {
            json_field(data, "note data")?;
            if payload.len() > 2 {
                return unsupported("a note has at most two payload slots");
            }
        }
        Event::Random { args, .. } => json_field(args, "random args")?,
        Event::Refusal { step, name, fault } => codec::check_refusal(step, name, fault)
            .map_err(|why| Fault::Unsupported(why.to_string()))?,
        _ => {}
    }
    Ok(())
}
