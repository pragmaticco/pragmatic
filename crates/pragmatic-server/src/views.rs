//! Entry JSON (design 4.4): journal entries as the API serves them.
//!
//! ```text
//! {cursor, at, branch, kind, fields: {name: value},
//!  slots: [{state, commitment, text|null, base64|null,
//!           binary: {media_type, bytes, sha256}|null, truncated, len}],
//!  hash}
//! ```
//!
//! Fields are structural (never personal data) and are shown as stored,
//! with JSON fields embedded as JSON. Slot content is shown raw to viewers
//! with `view_raw` (`text` when it is UTF-8, otherwise `base64`), and
//! redacted otherwise ([`crate::redaction`]). Salts are never included, in
//! any view: with a salt, anyone could test guesses against an erased
//! slot's commitment.

use pragmatic::encoding::{base64_encode, hex_encode};
use pragmatic::{Content, Entry, Event, SlotState};
use serde_json::{json, Map, Value as JsonValue};

use crate::redaction::{Redacted, Redactor};
use crate::store::ReadEntry;

/// Slot content longer than this is truncated in entry listings; the slot
/// endpoint serves it whole.
pub const LIST_SLOT_LIMIT: usize = 64 * 1024;

/// How content is shown.
#[derive(Debug, Clone, Copy)]
pub struct ViewOptions<'a> {
    pub raw: bool,
    pub redactor: &'a Redactor,
    /// Truncate slot content to this many bytes (`None`: whole).
    pub limit: Option<usize>,
}

fn state_name(state: SlotState) -> &'static str {
    match state {
        SlotState::Sealed => "sealed",
        SlotState::Erased => "erased",
        SlotState::Withheld => "withheld",
        SlotState::Ref => "ref",
    }
}

/// A JSON field as JSON (it was checked strict when it was appended), or
/// as a string if it somehow does not parse.
fn json_field(text: &str) -> JsonValue {
    serde_json::from_str(text).unwrap_or_else(|_| JsonValue::String(text.to_string()))
}

/// The structural fields of an event, by name (design 2.6).
pub fn fields(event: &Event) -> JsonValue {
    match event {
        Event::DrawIntent { provenance, .. } => json!({ "provenance": provenance }),
        Event::DrawResult { intent, meta, .. } => {
            json!({ "intent": intent, "meta": json_field(meta) })
        }
        Event::ChannelRecv { channel, .. } => json!({ "channel": channel }),
        Event::EffectIntent { name, .. } => json!({ "name": name }),
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            ..
        } => json!({ "intent": intent, "outcome": outcome.as_str(), "error_kind": error_kind }),
        Event::Clock { nanos } => json!({ "nanos": nanos }),
        Event::Program { name, hash } => json!({ "name": name, "hash": hash }),
        Event::Fork { base, children } => json!({ "base": base, "children": children }),
        Event::Marker { name } => json!({ "name": name }),
        Event::Note { kind, data, .. } => json!({ "kind": kind, "data": json_field(data) }),
        Event::Random { source, args, .. } => {
            json!({ "source": source, "args": json_field(args) })
        }
        Event::Refusal { step, name, fault } => {
            json!({ "step": step, "name": name, "fault": fault })
        }
        _ => json!({}),
    }
}

/// One slot's JSON.
pub fn slot_json(
    state: SlotState,
    commitment: &[u8; 32],
    content: &Content,
    opts: ViewOptions<'_>,
) -> JsonValue {
    let mut m = Map::new();
    m.insert("state".into(), state_name(state).into());
    m.insert("commitment".into(), hex_encode(commitment).into());
    let (mut text, mut b64, mut binary, mut truncated) =
        (JsonValue::Null, JsonValue::Null, JsonValue::Null, false);
    let len = match content.value() {
        None => JsonValue::Null,
        Some(v) => {
            let bytes = v.as_bytes();
            if opts.raw {
                match std::str::from_utf8(bytes) {
                    Ok(t) => {
                        let (t, cut) = truncate_text(t, opts.limit);
                        text = t.into();
                        truncated = cut;
                    }
                    Err(_) => {
                        let (b, cut) = truncate_bytes(bytes, opts.limit);
                        b64 = base64_encode(b).into();
                        truncated = cut;
                    }
                }
            } else {
                match opts.redactor.redact_slot(bytes) {
                    Redacted::Text(t) => {
                        let (t, cut) = truncate_text(&t, opts.limit);
                        text = t.into();
                        truncated = cut;
                    }
                    Redacted::Binary(info) => {
                        binary = serde_json::to_value(info).unwrap_or(JsonValue::Null);
                    }
                }
            }
            JsonValue::from(bytes.len() as u64)
        }
    };
    m.insert("text".into(), text);
    m.insert("base64".into(), b64);
    m.insert("binary".into(), binary);
    m.insert("truncated".into(), truncated.into());
    m.insert("len".into(), len);
    JsonValue::Object(m)
}

fn truncate_text(t: &str, limit: Option<usize>) -> (&str, bool) {
    match limit {
        Some(n) if t.len() > n => {
            let mut cut = n;
            while !t.is_char_boundary(cut) {
                cut -= 1;
            }
            (&t[..cut], true)
        }
        _ => (t, false),
    }
}

fn truncate_bytes(b: &[u8], limit: Option<usize>) -> (&[u8], bool) {
    match limit {
        Some(n) if b.len() > n => (&b[..n], true),
        _ => (b, false),
    }
}

/// One entry's JSON.
pub fn entry_json(entry: &Entry, opts: ViewOptions<'_>) -> JsonValue {
    entry_json_with(entry, &entry.event.slot_contents(), opts)
}

/// One entry read from disk: its ref slots show their targets' content.
pub fn read_entry_json(e: &ReadEntry, opts: ViewOptions<'_>) -> JsonValue {
    entry_json_with(&e.entry, &e.contents(), opts)
}

/// One entry's JSON, with each slot's content given (refs resolved).
fn entry_json_with(entry: &Entry, contents: &[&Content], opts: ViewOptions<'_>) -> JsonValue {
    let slots: Vec<JsonValue> = entry
        .slots
        .iter()
        .zip(contents)
        .map(|(meta, content)| slot_json(meta.state, &meta.commitment, content, opts))
        .collect();
    json!({
        "cursor": entry.cursor,
        "at": entry.at,
        "branch": entry.branch,
        "kind": entry.event.kind_name(),
        "fields": fields(&entry.event),
        "slots": slots,
        "hash": hex_encode(&entry.hash),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;
    use pragmatic::journal::{EraseSelector, ErasureNote, META, ROOT};
    use pragmatic::Journal;

    fn redactor() -> Redactor {
        Redactor::new(&RedactionConfig::default()).unwrap()
    }

    #[test]
    fn redacted_and_raw_views() {
        let mut j = Journal::new(None);
        j.append(
            META,
            Event::Note {
                kind: "run.start".into(),
                data: r#"{"run_id":"r"}"#.into(),
                payload: vec![],
            },
        )
        .unwrap();
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "in".into(),
                value: Content::from("reach me at ann@example.com"),
            },
        )
        .unwrap();
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "bin".into(),
                value: Content::from(vec![0xffu8, 0, 1]),
            },
        )
        .unwrap();
        let r = redactor();
        let red = ViewOptions {
            raw: false,
            redactor: &r,
            limit: Some(LIST_SLOT_LIMIT),
        };
        let raw = ViewOptions { raw: true, ..red };
        let e = entry_json(j.get(1).unwrap(), red);
        assert_eq!(e["kind"], "ChannelRecv");
        assert_eq!(e["fields"]["channel"], "in");
        assert_eq!(e["slots"][0]["state"], "sealed");
        assert!(e["slots"][0]["text"].as_str().unwrap().contains("[email]"));
        assert_eq!(e["slots"][0]["len"], 27);
        let e = entry_json(j.get(1).unwrap(), raw);
        assert!(e["slots"][0]["text"]
            .as_str()
            .unwrap()
            .contains("ann@example.com"));
        let b = entry_json(j.get(2).unwrap(), red);
        assert!(b["slots"][0]["base64"].is_null());
        assert_eq!(b["slots"][0]["binary"]["bytes"], 3);
        let b = entry_json(j.get(2).unwrap(), raw);
        assert_eq!(b["slots"][0]["base64"], "/wAB");
        let note = entry_json(j.get(0).unwrap(), red);
        assert_eq!(note["branch"], json!([0xFFFF_FFFFu32]));
        assert_eq!(note["fields"]["data"]["run_id"], "r");
        // No view ever carries a salt; there is no field for one.
        assert!(!note.to_string().contains("salt"));

        j.mark_persisted(j.len());
        let erased = j
            .erase(
                &EraseSelector::Slots(vec![(1, 0)]),
                &ErasureNote::local("x", ""),
                1,
            )
            .unwrap();
        let e = entry_json(erased.journal.get(1).unwrap(), raw);
        assert_eq!(e["slots"][0]["state"], "erased");
        assert!(e["slots"][0]["text"].is_null());
        assert!(e["slots"][0]["len"].is_null());
    }

    #[test]
    fn long_slots_are_truncated_on_char_boundaries() {
        let t = "é".repeat(10);
        let (cut, flag) = truncate_text(&t, Some(5));
        assert!(flag);
        assert_eq!(cut, "éé");
        assert_eq!(truncate_text(&t, None), (t.as_str(), false));
    }
}
