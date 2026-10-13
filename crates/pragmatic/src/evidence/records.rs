//! The `records` section: the journal decoded for human reading.
//!
//! A bundle carries the journal itself (the bytes the chain covers) and,
//! next to it, the same entries as plain JSON, so an auditor can read a
//! run with any JSON tool and a spreadsheet can import it. The two must say
//! the same thing, which verification checks by decoding the journal again
//! and comparing record by record (step 6): a bundle whose readable copy
//! disagrees with its journal fails, so nobody is shown text the chain does
//! not vouch for.
//!
//! One record per entry:
//!
//! ```text
//! {"cursor": n, "at": unix_ns, "branch": [u32...], "kind": "<Event kind>",
//!  "fields": {...}, "slots": [slot...], "hash": "<hex chain hash>"}
//! slot := {"state": "sealed"|"erased"|"withheld"|"ref",
//!          "commitment": "<hex>", "len": n|null, "text": str|null,
//!          "base64": str|null, "ref": [cursor, slot]|null}
//! ```
//!
//! `fields` holds the kind's structural fields under their names in design
//! section 2.6. Integers are numbers; strict JSON fields (`meta`, note
//! `data`, random `args`) are kept as the exact stored text. A slot with
//! content carries it as `text` when it is UTF-8 and as `base64` otherwise,
//! with `len` its size in bytes. A ref carries its target in `ref` and the
//! target's content when the target still has it.

use crate::encoding::{base64_decode, base64_encode, hex_decode_exact, hex_encode};
use crate::journal::{Content, Cursor, Entry, Event, SlotMeta, SlotState};
use crate::json::Json;
use crate::sha256::Digest;

use super::schema::{self, Obj};

/// One entry of the journal, decoded.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub cursor: Cursor,
    /// Unix nanoseconds of the appending process (informational).
    pub at: u64,
    pub branch: Vec<u32>,
    /// The event kind's name (`DrawIntent`, `Note`, ...).
    pub kind: String,
    /// The structural fields, as a JSON object.
    pub fields: Json,
    pub slots: Vec<RecordSlot>,
    /// The entry's chain hash.
    pub hash: Digest,
}

/// One slot of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSlot {
    pub state: SlotState,
    pub commitment: Digest,
    /// The content's length in bytes, when the content is present.
    pub len: Option<u64>,
    /// The content, when it is present and UTF-8.
    pub text: Option<String>,
    /// The content in base64, when it is present and not UTF-8.
    pub base64: Option<String>,
    /// A ref's target `(cursor, slot)`.
    pub ref_target: Option<(Cursor, u8)>,
}

/// The name of a slot state in records and Entry JSON.
pub fn state_name(state: SlotState) -> &'static str {
    match state {
        SlotState::Sealed => "sealed",
        SlotState::Erased => "erased",
        SlotState::Withheld => "withheld",
        SlotState::Ref => "ref",
    }
}

fn state_from_name(name: &str) -> Option<SlotState> {
    Some(match name {
        "sealed" => SlotState::Sealed,
        "erased" => SlotState::Erased,
        "withheld" => SlotState::Withheld,
        "ref" => SlotState::Ref,
        _ => return None,
    })
}

impl Record {
    /// The record of a format 2 entry. `None` for a format 1 entry, which
    /// never goes into a bundle.
    pub fn of_entry(entry: &Entry) -> Option<Record> {
        let fields = fields_of(&entry.event)?;
        let slots = entry
            .slots
            .iter()
            .zip(entry.event.slot_contents())
            .map(|(meta, content)| RecordSlot::of(meta, content))
            .collect();
        Some(Record {
            cursor: entry.cursor,
            at: entry.at,
            branch: entry.branch.clone(),
            kind: entry.event.kind_name().to_string(),
            fields,
            slots,
            hash: entry.hash,
        })
    }

    /// The record as JSON (key order is irrelevant: bundles are compared
    /// and signed in canonical form).
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("at".into(), self.at.into()),
            (
                "branch".into(),
                Json::Array(self.branch.iter().map(|&b| b.into()).collect()),
            ),
            ("cursor".into(), self.cursor.into()),
            ("fields".into(), self.fields.clone()),
            ("hash".into(), hex_encode(&self.hash).into()),
            ("kind".into(), self.kind.as_str().into()),
            (
                "slots".into(),
                Json::Array(self.slots.iter().map(RecordSlot::to_json).collect()),
            ),
        ])
    }

    /// Read a record, checking its shape (every key present, no other key,
    /// the right types). Whether it matches the journal is verification's
    /// business.
    pub(crate) fn from_json(value: &Json, at: &str) -> Result<Record, String> {
        let o = Obj::new(
            value,
            at,
            &["at", "branch", "cursor", "fields", "hash", "kind", "slots"],
        )?;
        let fields = o.get("fields");
        if fields.as_object().is_none() {
            return Err(format!("{at}.fields is not an object"));
        }
        let branch = o
            .array("branch")?
            .iter()
            .enumerate()
            .map(|(i, b)| {
                b.as_u64_strict()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| format!("{at}.branch[{i}] is not a u32"))
            })
            .collect::<Result<Vec<u32>, String>>()?;
        let slots = o
            .array("slots")?
            .iter()
            .enumerate()
            .map(|(i, s)| RecordSlot::from_json(s, &format!("{at}.slots[{i}]")))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Record {
            cursor: o.u64("cursor")?,
            at: o.u64("at")?,
            branch,
            kind: o.str("kind")?.to_string(),
            fields: fields.clone(),
            slots,
            hash: o.hex32("hash")?,
        })
    }
}

impl RecordSlot {
    fn of(meta: &SlotMeta, content: &Content) -> RecordSlot {
        let mut slot = RecordSlot {
            state: meta.state,
            commitment: meta.commitment,
            len: None,
            text: None,
            base64: None,
            ref_target: meta.ref_target,
        };
        if let Content::Sealed(v) = content {
            slot.len = Some(v.len() as u64);
            match std::str::from_utf8(v.as_bytes()) {
                Ok(t) => slot.text = Some(t.to_string()),
                Err(_) => slot.base64 = Some(base64_encode(v.as_bytes())),
            }
        }
        slot
    }

    /// The content's bytes, when the record carries them.
    pub fn content(&self) -> Option<Vec<u8>> {
        if let Some(t) = &self.text {
            return Some(t.as_bytes().to_vec());
        }
        self.base64.as_deref().and_then(|b| base64_decode(b).ok())
    }

    fn to_json(&self) -> Json {
        let opt_str = |s: &Option<String>| s.as_deref().map_or(Json::Null, Json::from);
        Json::Object(vec![
            ("base64".into(), opt_str(&self.base64)),
            ("commitment".into(), hex_encode(&self.commitment).into()),
            ("len".into(), self.len.map_or(Json::Null, Json::from)),
            (
                "ref".into(),
                self.ref_target
                    .map_or(Json::Null, |(c, s)| Json::Array(vec![c.into(), s.into()])),
            ),
            ("state".into(), state_name(self.state).into()),
            ("text".into(), opt_str(&self.text)),
        ])
    }

    fn from_json(value: &Json, at: &str) -> Result<RecordSlot, String> {
        let o = Obj::new(
            value,
            at,
            &["base64", "commitment", "len", "ref", "state", "text"],
        )?;
        let state = state_from_name(o.str("state")?)
            .ok_or_else(|| format!("{at}.state is not a known slot state"))?;
        let opt_string = |k: &str| -> Result<Option<String>, String> {
            match o.get(k) {
                Json::Null => Ok(None),
                Json::String(s) => Ok(Some(s.clone())),
                _ => Err(format!("{at}.{k} is not a string or null")),
            }
        };
        let base64 = opt_string("base64")?;
        if let Some(b) = &base64 {
            base64_decode(b).map_err(|e| format!("{at}.base64: {e}"))?;
        }
        let len = match o.get("len") {
            Json::Null => None,
            v => Some(
                v.as_u64_strict()
                    .ok_or_else(|| format!("{at}.len is not an integer or null"))?,
            ),
        };
        let ref_target = match o.get("ref") {
            Json::Null => None,
            v => Some(
                schema::slot_pair(v).ok_or_else(|| format!("{at}.ref is not [cursor, slot]"))?,
            ),
        };
        Ok(RecordSlot {
            state,
            commitment: hex_decode_exact(o.str("commitment")?)
                .map_err(|e| format!("{at}.commitment: {e}"))?,
            len,
            text: opt_string("text")?,
            base64,
            ref_target,
        })
    }
}

/// The structural fields of an event, keyed by their names in design 2.6.
fn fields_of(event: &Event) -> Option<Json> {
    let s = |v: &str| Json::from(v);
    let members: Vec<(&str, Json)> = match event {
        Event::DrawIntent { provenance, .. } => vec![("provenance", s(provenance))],
        Event::DrawResult { intent, meta, .. } => {
            vec![("intent", (*intent).into()), ("meta", s(meta))]
        }
        Event::ChannelRecv { channel, .. } => vec![("channel", s(channel))],
        Event::EffectIntent { name, .. } => vec![("name", s(name))],
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            ..
        } => vec![
            ("error_kind", s(error_kind)),
            ("intent", (*intent).into()),
            ("outcome", s(outcome.as_str())),
        ],
        Event::Clock { nanos } => vec![("nanos", (*nanos).into())],
        Event::Program { name, hash } => vec![("hash", s(hash)), ("name", s(name))],
        Event::Fork { base, children } => {
            vec![("base", (*base).into()), ("children", (*children).into())]
        }
        Event::Marker { name } => vec![("name", s(name))],
        Event::Note { kind, data, .. } => vec![("data", s(data)), ("kind", s(kind))],
        Event::Random { source, args, .. } => vec![("args", s(args)), ("source", s(source))],
        Event::Refusal { step, name, fault } => {
            vec![("fault", s(fault)), ("name", s(name)), ("step", s(step))]
        }
        _ => return None,
    };
    Some(Json::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    ))
}
