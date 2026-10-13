//! Byte-level encoding of journal format 2 (spec 2.1 to 2.6).
//!
//! Everything here is pure: bytes in, values out, no I/O and no state. The
//! module has three jobs.
//!
//! - **Encoding.** [`encode_frame`] turns an [`Entry`] plus its salts into
//!   `len ‖ record ‖ hash`, and [`skeleton`] produces the content-free view
//!   of a record that the hash chain covers.
//! - **Canonical decoding.** [`decode_raw`] checks the structure of a record
//!   (widths, counts, UTF-8, strict JSON, limits) and [`build_entry`] checks
//!   what needs context (refs, the meta branch, withheld slots) and turns it
//!   into an [`Entry`]. Callers then re-encode the entry and byte-compare it
//!   with the input, so the bytes that were hashed are exactly the bytes a
//!   second implementation would produce from the same values.
//! - **Hashing.** The genesis value, slot commitments and chain links.
//!
//! Error reasons are static strings that describe the structure, never the
//! content, so they can be shown to an operator or an auditor without
//! leaking what a slot held.

use std::borrow::Cow;

use crate::json::{self, Json};
use crate::sha256::{hmac_sha256, sha256, Digest, Sha256, DIGEST_LEN};
use crate::value::Value;

use super::{
    Content, Cursor, EffectOutcome, Entry, Event, Salts, SlotMeta, SlotState, MAX_DEPTH,
    MAX_SLOT_BYTES, META_ID,
};

/// Domain-separation tag for the genesis value `h_{-1}`.
pub(crate) const GENESIS_TAG: &[u8] = b"pragmatic/v2/genesis";
/// Domain-separation tag for slot commitments.
pub(crate) const SLOT_TAG: &[u8] = b"pragmatic/v2/slot";
/// Strict JSON nesting limit (spec 3.7). The general-purpose parser in
/// [`crate::json`] allows deeper documents, so journal fields are checked
/// against this tighter bound here.
pub(crate) const JSON_MAX_DEPTH: usize = 64;
/// Bytes in a slot salt.
pub(crate) const SALT_LEN: usize = 16;
/// The smallest possible record: kind, `at`, depth, nfields and nslots with
/// no branch, fields or slots. No real kind is this small, which makes it a
/// safe lower bound when scanning damaged bytes for frame boundaries.
pub(crate) const MIN_RECORD: usize = 1 + 8 + 1 + 1 + 1;

/// Kind tags (spec 2.6).
pub(crate) mod tag {
    pub const DRAW_INTENT: u8 = 1;
    pub const DRAW_RESULT: u8 = 2;
    pub const CHANNEL_RECV: u8 = 3;
    pub const EFFECT_INTENT: u8 = 4;
    pub const EFFECT_RESULT: u8 = 5;
    pub const CLOCK: u8 = 6;
    pub const PROGRAM: u8 = 7;
    pub const FORK: u8 = 8;
    pub const MARKER: u8 = 9;
    pub const NOTE: u8 = 10;
    pub const RANDOM: u8 = 11;
    pub const REFUSAL: u8 = 12;
}

/// The type of one structural field, which fixes how its bytes are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    /// UTF-8 text.
    Str,
    /// Strict JSON text (spec 3.7).
    Json,
    /// A little-endian `u64`, exactly 8 bytes.
    U64,
    /// A little-endian `u32`, exactly 4 bytes.
    U32,
    /// `ok`, `failed` or `compensated`.
    Outcome,
}

/// Field types and slot-count bounds for each kind, straight from the table
/// in spec 2.6. `EffectResult` narrows its slot bounds by outcome, which
/// [`slot_bounds`] applies.
fn fields_of_kind(kind: u8) -> Option<(&'static [Ty], u8, u8)> {
    use Ty::*;
    Some(match kind {
        tag::DRAW_INTENT => (&[Str], 1, 255),
        tag::DRAW_RESULT => (&[U64, Json], 2, 2),
        tag::CHANNEL_RECV => (&[Str], 1, 1),
        tag::EFFECT_INTENT => (&[Str], 1, 1),
        tag::EFFECT_RESULT => (&[U64, Outcome, Str], 0, 1),
        tag::CLOCK => (&[U64], 0, 0),
        tag::PROGRAM => (&[Str, Str], 0, 0),
        tag::FORK => (&[U32, U32], 0, 0),
        tag::MARKER => (&[Str], 0, 0),
        tag::NOTE => (&[Str, Json], 0, 2),
        tag::RANDOM => (&[Str, Json], 1, 1),
        tag::REFUSAL => (&[Str, Str, Str], 0, 0),
        _ => return None,
    })
}

/// The exact slot-count bounds for a record, given its decoded fields.
fn slot_bounds(kind: u8, outcome: Option<EffectOutcome>) -> (u8, u8) {
    match (kind, outcome) {
        (tag::EFFECT_RESULT, Some(EffectOutcome::Compensated)) => (0, 0),
        (tag::EFFECT_RESULT, Some(_)) => (1, 1),
        _ => fields_of_kind(kind).map_or((0, 0), |(_, lo, hi)| (lo, hi)),
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// `H`: SHA-256, or HMAC-SHA-256 under `key` for keyed journals.
pub(crate) fn chain_h(key: Option<&[u8]>, data: &[u8]) -> Digest {
    match key {
        Some(k) => hmac_sha256(k, data),
        None => sha256(data),
    }
}

/// `h_{-1} = H("pragmatic/v2/genesis" ‖ u32 LE flags)`.
///
/// Binding the flags into the genesis means a journal cannot be relabeled
/// (for example, its keyed bit cleared) without every chain link failing.
pub(crate) fn genesis(key: Option<&[u8]>, flags: u32) -> Digest {
    let mut buf = Vec::with_capacity(GENESIS_TAG.len() + 4);
    buf.extend_from_slice(GENESIS_TAG);
    buf.extend_from_slice(&flags.to_le_bytes());
    chain_h(key, &buf)
}

/// `h_i = H(h_{i-1} ‖ u64 LE cursor ‖ skeleton)`.
pub(crate) fn link(key: Option<&[u8]>, prev: &Digest, cursor: Cursor, skeleton: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(DIGEST_LEN + 8 + skeleton.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(&cursor.to_le_bytes());
    buf.extend_from_slice(skeleton);
    chain_h(key, &buf)
}

/// `SHA-256("pragmatic/v2/slot" ‖ salt ‖ u64 LE len ‖ content)`.
///
/// Always plain SHA-256, keyed journal or not: a commitment has to be
/// checkable by anyone who holds the content and the salt, which is exactly
/// what lets an erased journal keep verifying.
pub(crate) fn commitment(salt: &[u8; SALT_LEN], content: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(SLOT_TAG);
    h.update(salt);
    h.update(&(content.len() as u64).to_le_bytes());
    h.update(content);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Strict JSON
// ---------------------------------------------------------------------------

/// Validate a JSON field: UTF-8, RFC 8259 syntax (no BOM, no lone
/// surrogates), no duplicate keys and nesting of at most 64 (spec 3.7).
///
/// The text is kept as stored rather than re-serialized, so the check only
/// accepts or rejects; it never changes bytes.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Json, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "JSON field is not UTF-8")?;
    // The parser enforces the same limits, so its reasons are mapped onto the
    // journal's own wording to keep one message per rule.
    let value = json::parse(text).map_err(|e| match e.reason {
        "duplicate object key" => "JSON field has a duplicate key",
        "nesting too deep" => "JSON field is nested deeper than 64",
        other => other,
    })?;
    if value.duplicate_key().is_some() {
        return Err("JSON field has a duplicate key");
    }
    if json_depth(&value) > JSON_MAX_DEPTH {
        return Err("JSON field is nested deeper than 64");
    }
    Ok(value)
}

fn json_depth(value: &Json) -> usize {
    match value {
        Json::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Json::Object(members) => {
            1 + members
                .iter()
                .map(|(_, v)| json_depth(v))
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// One structural field, borrowed where possible.
pub(crate) type Field<'a> = Cow<'a, [u8]>;

/// The kind tag, the fields in table order and the slot contents in slot
/// order of a format 2 event. `None` for [`Event::Legacy`], which has no
/// format 2 encoding.
pub(crate) fn event_parts(event: &Event) -> Option<(u8, Vec<Field<'_>>, Vec<&Content>)> {
    fn s(text: &str) -> Field<'_> {
        Cow::Borrowed(text.as_bytes())
    }
    fn u64f(v: u64) -> Field<'static> {
        Cow::Owned(v.to_le_bytes().to_vec())
    }
    fn u32f(v: u32) -> Field<'static> {
        Cow::Owned(v.to_le_bytes().to_vec())
    }
    Some(match event {
        Event::DrawIntent { provenance, parts } => (
            tag::DRAW_INTENT,
            vec![s(provenance)],
            parts.iter().collect(),
        ),
        Event::DrawResult {
            intent,
            meta,
            head,
            body,
        } => (
            tag::DRAW_RESULT,
            vec![u64f(*intent), s(meta)],
            vec![head, body],
        ),
        Event::ChannelRecv { channel, value } => (tag::CHANNEL_RECV, vec![s(channel)], vec![value]),
        Event::EffectIntent { name, arg } => (tag::EFFECT_INTENT, vec![s(name)], vec![arg]),
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            payload,
        } => (
            tag::EFFECT_RESULT,
            vec![u64f(*intent), s(outcome.as_str()), s(error_kind)],
            payload.iter().collect(),
        ),
        Event::Clock { nanos } => (tag::CLOCK, vec![u64f(*nanos)], vec![]),
        Event::Program { name, hash } => (tag::PROGRAM, vec![s(name), s(hash)], vec![]),
        Event::Fork { base, children } => (tag::FORK, vec![u32f(*base), u32f(*children)], vec![]),
        Event::Marker { name } => (tag::MARKER, vec![s(name)], vec![]),
        Event::Note {
            kind,
            data,
            payload,
        } => (tag::NOTE, vec![s(kind), s(data)], payload.iter().collect()),
        Event::Random {
            source,
            args,
            value,
        } => (tag::RANDOM, vec![s(source), s(args)], vec![value]),
        Event::Refusal { step, name, fault } => {
            (tag::REFUSAL, vec![s(step), s(name), s(fault)], vec![])
        }
        Event::Legacy(_) => return None,
    })
}

/// `kind ‖ at ‖ depth ‖ branch ‖ nfields ‖ fields`, the prefix shared by a
/// record and its skeleton.
fn encode_head(out: &mut Vec<u8>, kind: u8, at: u64, branch: &[u32], fields: &[Field<'_>]) {
    out.push(kind);
    out.extend_from_slice(&at.to_le_bytes());
    out.push(branch.len() as u8);
    for id in branch {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out.push(fields.len() as u8);
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
}

/// The skeleton the chain hashes (spec 2.5): the record with every slot
/// replaced by `0x01 ‖ commitment`, whatever its state. This is why erasing,
/// withholding or deduplicating a slot never changes a chain hash.
pub(crate) fn skeleton(entry: &Entry) -> Vec<u8> {
    let (kind, fields, _) = event_parts(&entry.event).expect("format 2 entry");
    let mut out = Vec::with_capacity(64 + entry.slots.len() * (1 + DIGEST_LEN));
    encode_head(&mut out, kind, entry.at, &entry.branch, &fields);
    out.push(entry.slots.len() as u8);
    for slot in &entry.slots {
        out.push(0x01);
        out.extend_from_slice(&slot.commitment);
    }
    out
}

/// Append the record bytes of `entry` to `out`.
///
/// `salts[k]` is the salt of slot `k` when it is sealed. A sealed slot's
/// content comes from the event; erased and withheld slots carry nothing;
/// a ref carries its target.
pub(crate) fn encode_record(out: &mut Vec<u8>, entry: &Entry, salts: &[Option<[u8; SALT_LEN]>]) {
    let (kind, fields, contents) = event_parts(&entry.event).expect("format 2 entry");
    encode_head(out, kind, entry.at, &entry.branch, &fields);
    out.push(entry.slots.len() as u8);
    for (k, slot) in entry.slots.iter().enumerate() {
        out.push(slot.state as u8);
        out.extend_from_slice(&slot.commitment);
        match slot.state {
            SlotState::Sealed => {
                let salt = salts[k].expect("sealed slot has a salt");
                let content = match contents[k] {
                    Content::Sealed(v) => v.as_bytes(),
                    _ => panic!("sealed slot without sealed content"),
                };
                out.extend_from_slice(&salt);
                out.extend_from_slice(&(content.len() as u32).to_le_bytes());
                out.extend_from_slice(content);
            }
            SlotState::Erased | SlotState::Withheld => {}
            SlotState::Ref => {
                let (c, s) = slot.ref_target.expect("ref slot has a target");
                out.extend_from_slice(&c.to_le_bytes());
                out.push(s);
            }
        }
    }
}

/// The exact encoded length of a record, computed before encoding so an
/// oversized record is refused without first being built in memory.
pub(crate) fn record_len(branch: &[u32], event: &Event, slots: &[SlotMeta]) -> u64 {
    let (_, fields, contents) = event_parts(event).expect("format 2 event");
    let mut len = 1 + 8 + 1 + 4 * branch.len() as u64 + 1 + 1;
    len += fields.iter().map(|f| 4 + f.len() as u64).sum::<u64>();
    for (slot, content) in slots.iter().zip(contents) {
        len += 1 + DIGEST_LEN as u64;
        len += match slot.state {
            SlotState::Sealed => {
                SALT_LEN as u64 + 4 + content.value().map_or(0, |v| v.len() as u64)
            }
            SlotState::Ref => 8 + 1,
            SlotState::Erased | SlotState::Withheld => 0,
        };
    }
    len
}

/// Append the whole frame `len ‖ record ‖ hash` of `entry` to `out`.
pub(crate) fn encode_frame(out: &mut Vec<u8>, entry: &Entry, salts: &[Option<[u8; SALT_LEN]>]) {
    let len_at = out.len();
    out.extend_from_slice(&[0u8; 4]);
    encode_record(out, entry, salts);
    let len = (out.len() - len_at - 4) as u32;
    out[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&entry.hash);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// A slot as stored, before context checks.
pub(crate) struct RawSlot<'a> {
    pub state: u8,
    pub commitment: Digest,
    pub body: RawBody<'a>,
}

/// The state-specific tail of a stored slot.
pub(crate) enum RawBody<'a> {
    Sealed {
        salt: [u8; SALT_LEN],
        content: &'a [u8],
    },
    Empty,
    Ref {
        cursor: u64,
        slot: u8,
    },
}

/// A record whose structure is valid, before context checks.
pub(crate) struct RawRecord<'a> {
    pub kind: u8,
    pub at: u64,
    pub branch: Vec<u32>,
    pub fields: Vec<&'a [u8]>,
    pub slots: Vec<RawSlot<'a>>,
}

/// A bounds-checked little-endian reader over one record.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if n > self.remaining() {
            return Err("record ends early");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        Ok(self.take(N)?.try_into().unwrap())
    }
}

/// Check one field against its type.
fn check_field(ty: Ty, bytes: &[u8]) -> Result<(), &'static str> {
    match ty {
        Ty::Str => std::str::from_utf8(bytes)
            .map(|_| ())
            .map_err(|_| "text field is not UTF-8"),
        Ty::Json => strict_json(bytes).map(|_| ()),
        Ty::U64 if bytes.len() != 8 => Err("u64 field is not 8 bytes"),
        Ty::U32 if bytes.len() != 4 => Err("u32 field is not 4 bytes"),
        Ty::U64 | Ty::U32 => Ok(()),
        Ty::Outcome => EffectOutcome::parse(bytes)
            .map(|_| ())
            .ok_or("unknown effect outcome"),
    }
}

/// Structural decoding of one record (spec 2.4, the rules that need no
/// context): the kind is known, field and slot counts match the kind,
/// fixed-width fields have their width, text is UTF-8, JSON is strict, slot
/// states are known, lengths stay within the record and the slot limit, and
/// the record is consumed exactly.
pub(crate) fn decode_raw(rec: &[u8]) -> Result<RawRecord<'_>, &'static str> {
    let mut r = Reader { buf: rec, pos: 0 };
    let kind = r.u8()?;
    let (types, _, _) = fields_of_kind(kind).ok_or("unknown record kind")?;
    let at = r.u64()?;
    let depth = r.u8()? as usize;
    if depth > MAX_DEPTH {
        return Err("branch deeper than 32");
    }
    let mut branch = Vec::with_capacity(depth);
    for _ in 0..depth {
        branch.push(r.u32()?);
    }
    if r.u8()? as usize != types.len() {
        return Err("field count does not match the kind");
    }
    let mut fields = Vec::with_capacity(types.len());
    let mut outcome = None;
    for &ty in types {
        let len = r.u32()? as usize;
        if len > r.remaining() {
            return Err("field length exceeds the record");
        }
        let bytes = r.take(len)?;
        check_field(ty, bytes)?;
        if ty == Ty::Outcome {
            outcome = EffectOutcome::parse(bytes);
        }
        fields.push(bytes);
    }
    let nslots = r.u8()?;
    let (lo, hi) = slot_bounds(kind, outcome);
    if nslots < lo || nslots > hi {
        return Err("slot count does not match the kind");
    }
    let mut slots = Vec::with_capacity(nslots as usize);
    for _ in 0..nslots {
        let state = r.u8()?;
        let commitment: Digest = r.array()?;
        let body = match state {
            1 => {
                let salt = r.array()?;
                let len = r.u32()? as u64;
                // The limit is checked before the remaining length so that a
                // huge declared length is reported as what it is.
                if len > MAX_SLOT_BYTES {
                    return Err("slot exceeds the 64 MiB limit");
                }
                if len > r.remaining() as u64 {
                    return Err("slot length exceeds the record");
                }
                RawBody::Sealed {
                    salt,
                    content: r.take(len as usize)?,
                }
            }
            2 | 3 => RawBody::Empty,
            4 => RawBody::Ref {
                cursor: r.u64()?,
                slot: r.u8()?,
            },
            _ => return Err("unknown slot state"),
        };
        slots.push(RawSlot {
            state,
            commitment,
            body,
        });
    }
    if r.remaining() != 0 {
        return Err("trailing bytes in record");
    }
    Ok(RawRecord {
        kind,
        at,
        branch,
        fields,
        slots,
    })
}

/// How a record is being decoded.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DecodeOpts {
    /// Accept state 3 (withheld). Only an evidence bundle may contain it.
    pub allow_withheld: bool,
    /// Scanning damaged bytes for a frame that chains from a failed one:
    /// refs to entries that did not parse are accepted unresolved.
    pub probe: bool,
}

/// Context checks and conversion to an [`Entry`] (spec 2.4, the rules that
/// need the earlier entries): state 3 only where allowed, refs point
/// backwards to a sealed or erased slot with an equal commitment, and the
/// branch is the meta branch exactly for notes.
///
/// Returns the entry with a zero hash (the caller fills it in once the chain
/// link is known) and the salts of its sealed slots. Commitments of sealed
/// slots are not recomputed here; the caller does that separately so it can
/// tell a damaged slot from a malformed record.
pub(crate) fn build_entry(
    raw: &RawRecord<'_>,
    cursor: Cursor,
    prior: &[Entry],
    opts: DecodeOpts,
) -> Result<(Entry, Salts), &'static str> {
    let is_meta = raw.branch.len() == 1 && raw.branch[0] == META_ID;
    if is_meta != (raw.kind == tag::NOTE) {
        return Err("only notes may be on the meta branch, and notes must be");
    }
    let mut metas = Vec::with_capacity(raw.slots.len());
    let mut contents = Vec::with_capacity(raw.slots.len());
    let mut salts = Vec::with_capacity(raw.slots.len());
    for slot in &raw.slots {
        let (meta, content, salt) = match (&slot.body, slot.state) {
            (RawBody::Sealed { salt, content }, _) => (
                SlotMeta::new(slot.commitment, SlotState::Sealed, None),
                Content::Sealed(Value::new(*content)),
                Some(*salt),
            ),
            (RawBody::Empty, 2) => (
                SlotMeta::new(slot.commitment, SlotState::Erased, None),
                Content::Erased,
                None,
            ),
            (RawBody::Empty, _) => {
                if !opts.allow_withheld {
                    return Err("withheld slot in a stored journal");
                }
                (
                    SlotMeta::new(slot.commitment, SlotState::Withheld, None),
                    Content::Withheld,
                    None,
                )
            }
            (
                RawBody::Ref {
                    cursor: tc,
                    slot: ts,
                },
                _,
            ) => {
                let content = resolve_ref(*tc, *ts, &slot.commitment, cursor, prior, opts)?;
                (
                    SlotMeta::new(slot.commitment, SlotState::Ref, Some((*tc, *ts))),
                    content,
                    None,
                )
            }
        };
        metas.push(meta);
        contents.push(content);
        salts.push(salt);
    }
    let event = build_event(raw.kind, &raw.fields, contents)?;
    Ok((
        Entry {
            cursor,
            at: raw.at,
            branch: raw.branch.clone(),
            event,
            slots: metas,
            hash: [0u8; DIGEST_LEN],
        },
        salts,
    ))
}

/// Resolve a ref to the content it stands for, checking the rules of spec
/// 2.4: strictly backwards, to a slot that exists, is sealed or erased
/// (withheld too inside a bundle, never another ref), and carries an equal
/// commitment.
pub(crate) fn resolve_ref(
    target_cursor: u64,
    target_slot: u8,
    commitment: &Digest,
    cursor: Cursor,
    prior: &[Entry],
    opts: DecodeOpts,
) -> Result<Content, &'static str> {
    if target_cursor >= cursor {
        return Err("ref does not point to an earlier entry");
    }
    let Some(target) = prior.get(target_cursor as usize) else {
        // Only reachable while probing past a failed frame, whose own slots
        // are unknown.
        return if opts.probe {
            Ok(Content::Erased)
        } else {
            Err("ref target entry is missing")
        };
    };
    let meta = target
        .slots
        .get(target_slot as usize)
        .ok_or("ref target slot does not exist")?;
    match meta.state {
        SlotState::Sealed | SlotState::Erased => {}
        SlotState::Withheld if opts.allow_withheld => {}
        SlotState::Withheld => return Err("ref target is withheld"),
        SlotState::Ref => return Err("ref points to another ref"),
    }
    if &meta.commitment != commitment {
        return Err("ref commitment differs from its target");
    }
    Ok(target
        .event
        .slot_contents()
        .get(target_slot as usize)
        .map(|c| (*c).clone())
        .unwrap_or(Content::Erased))
}

/// Check the fields of a `Refusal` (spec 2.6): a known step, the fault that
/// step raises without effect, and no name for a draw (a receive names its
/// channel and an effect its name, either of which may be empty).
pub(crate) fn check_refusal(step: &str, name: &str, fault: &str) -> Result<(), &'static str> {
    use super::refusal;
    let fits = match step {
        refusal::DRAW => fault == refusal::BUDGET_EXHAUSTED && name.is_empty(),
        refusal::RECV => fault == refusal::TIMEOUT,
        refusal::EFFECT => fault == refusal::CAPABILITY_DENIED,
        _ => return Err("refusal of an unknown step"),
    };
    if fits {
        Ok(())
    } else {
        Err("refusal fault or name does not fit its step")
    }
}

/// Check what a completion names (spec 2.4): a `DrawResult` completes an
/// earlier `DrawIntent`, an `EffectResult` an earlier `EffectIntent`, on
/// the same branch. Replay finds completions through this reference, so a
/// result that pointed anywhere else would hand one kind of step the record
/// of another.
pub(crate) fn check_completion(
    event: &Event,
    branch: &[u32],
    cursor: Cursor,
    prior: &[Entry],
) -> Result<(), &'static str> {
    let (intent, draw) = match event {
        Event::DrawResult { intent, .. } => (*intent, true),
        Event::EffectResult { intent, .. } => (*intent, false),
        _ => return Ok(()),
    };
    let target = usize::try_from(intent)
        .ok()
        .filter(|&i| (i as u64) < cursor)
        .and_then(|i| prior.get(i))
        .ok_or("result does not name an earlier entry")?;
    let fits = match target.event {
        Event::DrawIntent { .. } => draw,
        Event::EffectIntent { .. } => !draw,
        _ => false,
    };
    if !fits {
        return Err("result names an entry that is not an intent of its kind");
    }
    if target.branch != branch {
        return Err("result is not on its intent's branch");
    }
    Ok(())
}

fn text(bytes: &[u8]) -> String {
    // Fields were checked by `decode_raw`, so this never replaces anything.
    String::from_utf8_lossy(bytes).into_owned()
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("checked width"))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("checked width"))
}

/// Assemble the typed event from checked fields and resolved contents.
fn build_event(kind: u8, f: &[&[u8]], contents: Vec<Content>) -> Result<Event, &'static str> {
    let mut it = contents.into_iter();
    // `decode_raw` already matched the slot count to the kind, so a missing
    // content here is a bug, not bad input.
    let mut one = || it.next().expect("slot count checked");
    let event = match kind {
        tag::DRAW_INTENT => {
            let provenance = text(f[0]);
            let first = one();
            let mut parts = vec![first];
            parts.extend(it);
            return Ok(Event::DrawIntent { provenance, parts });
        }
        tag::DRAW_RESULT => Event::DrawResult {
            intent: le_u64(f[0]),
            meta: text(f[1]),
            head: one(),
            body: one(),
        },
        tag::CHANNEL_RECV => Event::ChannelRecv {
            channel: text(f[0]),
            value: one(),
        },
        tag::EFFECT_INTENT => Event::EffectIntent {
            name: text(f[0]),
            arg: one(),
        },
        tag::EFFECT_RESULT => {
            let outcome = EffectOutcome::parse(f[1]).expect("checked outcome");
            let payload = match outcome {
                EffectOutcome::Compensated => None,
                _ => Some(one()),
            };
            Event::EffectResult {
                intent: le_u64(f[0]),
                outcome,
                error_kind: text(f[2]),
                payload,
            }
        }
        tag::CLOCK => Event::Clock {
            nanos: le_u64(f[0]),
        },
        tag::PROGRAM => Event::Program {
            name: text(f[0]),
            hash: text(f[1]),
        },
        tag::FORK => {
            let children = le_u32(f[1]);
            if children == 0 {
                return Err("fork has no children");
            }
            Event::Fork {
                base: le_u32(f[0]),
                children,
            }
        }
        tag::MARKER => Event::Marker { name: text(f[0]) },
        tag::NOTE => {
            let (kind, data) = (text(f[0]), text(f[1]));
            return Ok(Event::Note {
                kind,
                data,
                payload: it.collect(),
            });
        }
        tag::RANDOM => Event::Random {
            source: text(f[0]),
            args: text(f[1]),
            value: one(),
        },
        tag::REFUSAL => {
            let (step, name, fault) = (text(f[0]), text(f[1]), text(f[2]));
            check_refusal(&step, &name, &fault)?;
            Event::Refusal { step, name, fault }
        }
        _ => return Err("unknown record kind"),
    };
    Ok(event)
}
