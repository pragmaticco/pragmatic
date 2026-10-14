//! Read-only views of journals for the Python package: Entry JSON (spec
//! 4.4), local run summaries, verify reports, and the byte-level checks
//! `python -m pragmatic push` and the test server need.
//!
//! Views are built as strict JSON text here, with the core's serializer,
//! and parsed into Python objects by the package. A local view never
//! truncates or redacts: the caller already holds the journal file.

use std::collections::{BTreeMap, HashSet};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use pragmatic_rt::encoding::{base64_encode, hex_encode};
use pragmatic_rt::journal::{note, Content, Entry, Event, Journal, SlotState};
use pragmatic_rt::json::Json;
use pragmatic_rt::sha256::hex;
use pragmatic_rt::VerifyReport;

fn obj(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// A JSON field (meta, note data, random args) as a JSON value; text that
/// is not JSON stays a string.
fn json_field(text: &str) -> Json {
    Json::parse(text).unwrap_or_else(|_| Json::from(text))
}

fn branch_json(branch: &[u32]) -> Json {
    Json::Array(branch.iter().map(|&i| Json::from(i)).collect())
}

/// The structural fields of an event, named as in the table of spec 2.6.
fn fields(event: &Event) -> Json {
    match event {
        Event::DrawIntent { provenance, .. } => {
            obj(vec![("provenance", provenance.as_str().into())])
        }
        Event::DrawResult { intent, meta, .. } => obj(vec![
            ("intent", (*intent).into()),
            ("meta", json_field(meta)),
        ]),
        Event::ChannelRecv { channel, .. } => obj(vec![("channel", channel.as_str().into())]),
        Event::EffectIntent { name, .. } => obj(vec![("name", name.as_str().into())]),
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            ..
        } => obj(vec![
            ("intent", (*intent).into()),
            ("outcome", outcome.as_str().into()),
            ("error_kind", error_kind.as_str().into()),
        ]),
        Event::Clock { nanos } => obj(vec![("nanos", (*nanos).into())]),
        Event::Program { name, hash } => obj(vec![
            ("name", name.as_str().into()),
            ("hash", hash.as_str().into()),
        ]),
        Event::Fork { base, children } => obj(vec![
            ("base", (*base).into()),
            ("children", (*children).into()),
        ]),
        Event::Marker { name } => obj(vec![("name", name.as_str().into())]),
        Event::Note { kind, data, .. } => obj(vec![
            ("kind", kind.as_str().into()),
            ("data", json_field(data)),
        ]),
        Event::Random { source, args, .. } => obj(vec![
            ("source", source.as_str().into()),
            ("args", json_field(args)),
        ]),
        Event::Refusal { step, name, fault } => obj(vec![
            ("step", step.as_str().into()),
            ("name", name.as_str().into()),
            ("fault", fault.as_str().into()),
        ]),
        _ => obj(Vec::new()),
    }
}

fn slot_json(state: SlotState, commitment: &[u8; 32], content: Option<&Content>) -> Json {
    let state_name = match state {
        SlotState::Sealed => "sealed",
        SlotState::Erased => "erased",
        SlotState::Withheld => "withheld",
        SlotState::Ref => "ref",
    };
    let value = content.and_then(Content::value);
    let (text, b64) = match value {
        Some(v) => match std::str::from_utf8(v.as_bytes()) {
            Ok(t) => (Json::from(t), Json::Null),
            Err(_) => (Json::Null, Json::from(base64_encode(v.as_bytes()))),
        },
        None => (Json::Null, Json::Null),
    };
    obj(vec![
        ("state", state_name.into()),
        ("commitment", hex_encode(commitment).into()),
        ("text", text),
        ("base64", b64),
        ("binary", Json::Null),
        ("truncated", false.into()),
        (
            "len",
            value.map_or(Json::Null, |v| Json::from(v.len() as u64)),
        ),
    ])
}

/// One entry in the Entry JSON shape of spec 4.4.
pub fn entry_json(e: &Entry) -> Json {
    let contents = e.event.slot_contents();
    let slots = e
        .slots
        .iter()
        .enumerate()
        .map(|(k, s)| slot_json(s.state, &s.commitment, contents.get(k).copied()))
        .collect();
    obj(vec![
        ("cursor", e.cursor.into()),
        ("at", e.at.into()),
        ("branch", branch_json(&e.branch)),
        ("kind", e.event.kind_name().into()),
        ("fields", fields(&e.event)),
        ("slots", Json::Array(slots)),
        ("hash", hex(&e.hash).into()),
    ])
}

/// Every entry of `journal` as a JSON array.
pub fn entries_json(journal: &Journal) -> String {
    Json::Array(journal.entries().iter().map(entry_json).collect()).to_string()
}

/// Unix nanoseconds as RFC 3339 UTC with millisecond precision.
pub fn rfc3339(nanos: u64) -> String {
    let secs = (nanos / 1_000_000_000) as i64;
    let millis = (nanos / 1_000_000) % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn note_data(e: &Entry) -> Option<Json> {
    match &e.event {
        Event::Note { data, .. } => Json::parse(data).ok(),
        _ => None,
    }
}

/// A summary of a local run in the RunSummary shape of spec 4.4. A local
/// store has no anchors, holds or leases: `anchored_entries` is 0, `holds`
/// is empty, and `status` is `dangling` when an intent has no result and
/// `idle` otherwise.
pub fn summary_json(run_id: &str, journal: &Journal) -> String {
    let entries = journal.entries();
    let mut completed = HashSet::new();
    let mut erased = 0u64;
    let mut usage: BTreeMap<String, u64> = BTreeMap::new();
    let (mut labels, mut program, mut created_by, mut last_outcome) =
        (Json::Object(Vec::new()), Json::Null, Json::Null, Json::Null);
    for e in entries {
        erased += e
            .slots
            .iter()
            .filter(|s| s.state == SlotState::Erased)
            .count() as u64;
        match &e.event {
            Event::DrawResult { intent, meta, .. } => {
                completed.insert(*intent);
                let usage_json = Json::parse(meta).ok().and_then(|m| m.get("usage").cloned());
                for (k, v) in usage_json.as_ref().and_then(Json::as_object).unwrap_or(&[]) {
                    if let Some(n) = v.as_u64() {
                        *usage.entry(k.clone()).or_default() += n;
                    }
                }
            }
            Event::EffectResult { intent, .. } => {
                completed.insert(*intent);
            }
            Event::Note { kind, .. } => {
                let data = note_data(e);
                let get = |k: &str| data.as_ref().and_then(|d| d.get(k)).cloned();
                match kind.as_str() {
                    note::RUN_START => labels = get("labels").unwrap_or(labels),
                    note::ATTEMPT_START => {
                        program = get("program").unwrap_or(Json::Null);
                        if created_by == Json::Null {
                            created_by = get("principal").unwrap_or(Json::Null);
                        }
                    }
                    note::ATTEMPT_END => last_outcome = get("outcome").unwrap_or(Json::Null),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let dangling = entries.iter().any(|e| {
        matches!(
            e.event,
            Event::DrawIntent { .. } | Event::EffectIntent { .. }
        ) && !completed.contains(&e.cursor)
    });
    let len = journal.len();
    let at = |e: Option<&Entry>| e.map_or(Json::Null, |e| Json::from(rfc3339(e.at)));
    obj(vec![
        ("run_id", run_id.into()),
        ("entries", len.into()),
        (
            "head",
            if len == 0 {
                Json::Null
            } else {
                hex(&journal.head()).into()
            },
        ),
        ("created_at", at(entries.first())),
        ("updated_at", at(entries.last())),
        ("status", if dangling { "dangling" } else { "idle" }.into()),
        ("erased_slots", erased.into()),
        ("anchored_entries", 0u64.into()),
        ("unanchored_entries", len.into()),
        ("holds", Json::Array(Vec::new())),
        ("labels", labels),
        ("program", program),
        ("created_by", created_by),
        ("last_outcome", last_outcome),
        (
            "usage",
            Json::Object(usage.into_iter().map(|(k, v)| (k, Json::from(v))).collect()),
        ),
    ])
    .to_string()
}

/// A verify report as a dict.
pub fn verify_dict<'py>(py: Python<'py>, r: &VerifyReport) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("first_bad", r.first_bad)?;
    d.set_item("unaccounted_erasures", r.unaccounted_erasures.clone())?;
    d.set_item("erasure_incomplete", r.erasure_incomplete.clone())?;
    d.set_item("invalid_erasure_notes", r.invalid_erasure_notes.clone())?;
    d.set_item("torn_bytes", r.torn_bytes)?;
    Ok(d)
}

/// What a journal file is, read without a key: `format`, `keyed`,
/// `entries` and `head` (unkeyed journals only), `valid_len`, `tail_len`
/// and `unpushable` (why a server would refuse its frames from a client,
/// or `None`). Used by `python -m pragmatic push` to refuse what a server
/// cannot hold before anything is sent.
#[pyfunction]
pub fn journal_info<'py>(
    py: Python<'py>,
    data: Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyDict>> {
    let bytes = data.as_bytes();
    if bytes.len() < 12 || &bytes[..8] != pragmatic_rt::journal::MAGIC {
        return Err(PyValueError::new_err("not a Pragmatic journal (bad magic)"));
    }
    let format = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    let flags = bytes
        .get(12..16)
        .map_or(0, |f| u32::from_le_bytes(f.try_into().expect("4 bytes")));
    let keyed = format == 2 && flags & pragmatic_rt::journal::FLAG_KEYED != 0;
    let d = PyDict::new(py);
    d.set_item("format", format)?;
    d.set_item("keyed", keyed)?;
    if format == 2 && !keyed {
        let parsed = py
            .detach(|| Journal::parse(bytes, None))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        d.set_item("entries", parsed.journal.len())?;
        d.set_item("head", hex(&parsed.journal.head()))?;
        d.set_item("valid_len", parsed.valid_len)?;
        d.set_item("tail_len", parsed.tail_len)?;
        let run_id = parsed.journal.run_start_id();
        d.set_item("run_id", run_id)?;
        // What a server would refuse from a client (spec 4.6): the same
        // frame checks it runs, so push refuses before creating the run.
        let frames = &bytes[pragmatic_rt::journal::HEADER_LEN..parsed.valid_len as usize];
        let refused = py.detach(|| {
            Journal::new(None)
                .append_frames(frames)
                .err()
                .map(|e| e.to_string())
        });
        d.set_item("unpushable", refused)?;
    }
    Ok(d)
}

/// Parse unkeyed journal bytes strictly (canonical decoding, chain and
/// commitments, no torn tail), returning `(entries, head_hex)`. Raises
/// `ValueError` naming the problem. Test servers use it to validate what a
/// client appends.
#[pyfunction]
pub fn check_journal(py: Python<'_>, data: Bound<'_, PyBytes>) -> PyResult<(u64, String)> {
    let bytes = data.as_bytes();
    let parsed = py
        .detach(|| Journal::parse(bytes, None))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    if parsed.tail_len > 0 {
        return Err(PyValueError::new_err(format!(
            "{} bytes after the last whole frame",
            parsed.tail_len
        )));
    }
    let j = parsed.journal;
    let head = if j.is_empty() {
        hex(&j.genesis())
    } else {
        hex(&j.head())
    };
    Ok((j.len(), head))
}

/// The 16-byte header of an unkeyed format 2 journal, which a Python store
/// writes when it creates a run.
pub fn unkeyed_header() -> [u8; 16] {
    pragmatic_rt::journal::header(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic_rt::journal::EffectOutcome;

    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_123_000_000), "2000-02-29T00:00:00.123Z");
        assert_eq!(
            rfc3339(1_791_888_000_000_000_000),
            "2026-10-13T10:40:00.000Z"
        );
    }

    #[test]
    fn entries_follow_the_entry_json_shape() {
        let mut j = Journal::new(None);
        j.append(
            &[],
            Event::EffectIntent {
                name: "send".into(),
                arg: Content::from("hello"),
            },
        )
        .unwrap();
        j.append(
            &[],
            Event::EffectResult {
                intent: 0,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Content::from(vec![0xffu8, 0xfe])),
            },
        )
        .unwrap();
        let doc = Json::parse(&entries_json(&j)).unwrap();
        let entries = doc.as_array().unwrap();
        assert_eq!(
            entries[0].get("kind").unwrap().as_str(),
            Some("EffectIntent")
        );
        let slot = &entries[0].get("slots").unwrap().as_array().unwrap()[0];
        assert_eq!(slot.get("state").unwrap().as_str(), Some("sealed"));
        assert_eq!(slot.get("text").unwrap().as_str(), Some("hello"));
        assert_eq!(slot.get("len").unwrap().as_u64(), Some(5));
        let binary = &entries[1].get("slots").unwrap().as_array().unwrap()[0];
        assert_eq!(binary.get("text"), Some(&Json::Null));
        assert_eq!(binary.get("base64").unwrap().as_str(), Some("//4="));
        let fields = entries[1].get("fields").unwrap();
        assert_eq!(fields.get("outcome").unwrap().as_str(), Some("ok"));
    }
}
