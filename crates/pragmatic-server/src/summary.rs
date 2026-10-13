//! What the server knows about a run without reading its journal: labels,
//! program, last outcome, usage, erased slots, open intents and the
//! subjects index entries (design 4.2, 4.4 and 4.9).
//!
//! Everything here is derived from the journal, so it can always be rebuilt
//! by folding the entries in order ([`Summary::rebuild`]); on append the
//! server folds only the new entries ([`Summary::observe`]). It is stored
//! in the run's `meta.json` so that listing a million runs never parses a
//! journal.

use std::collections::BTreeMap;

use pragmatic::encoding::hex_encode;
use pragmatic::sha256::hmac_sha256;
use pragmatic::{Content, Entry, Event, Journal, SlotState};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// An intent that has no result yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIntent {
    pub cursor: u64,
    /// `draw` or `effect`.
    pub kind: String,
}

/// The program that last drove the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramRef {
    pub name: String,
    pub hash: String,
}

/// The derived facts about a run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Summary {
    pub labels: BTreeMap<String, String>,
    pub program: Option<ProgramRef>,
    /// `ok`, `fault` or `error` from the last `attempt.end`.
    pub last_outcome: Option<String>,
    /// An attempt started and has not ended (running, or crashed).
    pub attempt_open: bool,
    pub attempts: u64,
    /// Token usage summed over every `DrawResult`'s meta.
    pub usage: BTreeMap<String, u64>,
    pub erased_slots: u64,
    /// Slots that still hold their own content (refs not counted): zero
    /// once a run is shredded.
    pub sealed_slots: u64,
    pub open_intents: Vec<OpenIntent>,
    /// HMAC-SHA-256 (hex) of each subject in `run.start`'s payload, under
    /// the server's index key.
    pub subjects: Vec<String>,
}

/// What an observed entry means for the rest of the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Observed {
    /// An attempt ended ok: anchor soon (design 4.7).
    pub attempt_ended_ok: bool,
}

/// The subjects index key of one subject.
pub fn subject_hash(index_key: &[u8], subject: &str) -> String {
    hex_encode(&hmac_sha256(index_key, subject.as_bytes()))
}

impl Summary {
    /// Fold every entry of a journal.
    pub fn rebuild(journal: &Journal, index_key: &[u8]) -> Summary {
        let mut s = Summary::default();
        for e in journal.entries() {
            s.observe(e, index_key);
        }
        s
    }

    /// Fold one entry, appended after every entry folded so far.
    pub fn observe(&mut self, entry: &Entry, index_key: &[u8]) -> Observed {
        let count = |state| entry.slots.iter().filter(|s| s.state == state).count() as u64;
        self.erased_slots += count(SlotState::Erased);
        self.sealed_slots += count(SlotState::Sealed);
        let mut out = Observed::default();
        match &entry.event {
            Event::DrawIntent { .. } => self.open(entry.cursor, "draw"),
            Event::EffectIntent { .. } => self.open(entry.cursor, "effect"),
            Event::DrawResult { intent, meta, .. } => {
                self.close(*intent);
                self.add_usage(meta);
            }
            Event::EffectResult { intent, .. } => self.close(*intent),
            Event::Program { name, hash } => {
                self.program = Some(ProgramRef {
                    name: name.clone(),
                    hash: hash.clone(),
                })
            }
            Event::Note {
                kind,
                data,
                payload,
            } => {
                out = self.note(entry.cursor, kind, data, payload, index_key);
            }
            _ => {}
        }
        out
    }

    fn open(&mut self, cursor: u64, kind: &str) {
        self.open_intents.push(OpenIntent {
            cursor,
            kind: kind.into(),
        });
    }

    fn close(&mut self, intent: u64) {
        self.open_intents.retain(|o| o.cursor != intent);
    }

    /// True if an effect has no result.
    pub fn has_open_effect(&self) -> bool {
        self.open_intents.iter().any(|o| o.kind == "effect")
    }

    /// True if the last attempt ended ok and none has started since.
    pub fn finished_ok(&self) -> bool {
        !self.attempt_open && self.last_outcome.as_deref() == Some("ok")
    }

    fn add_usage(&mut self, meta: &str) {
        let Ok(doc) = serde_json::from_str::<JsonValue>(meta) else {
            return;
        };
        let Some(usage) = doc.get("usage").and_then(JsonValue::as_object) else {
            return;
        };
        for (k, v) in usage {
            if let Some(n) = v.as_u64() {
                let total = self.usage.entry(k.clone()).or_insert(0);
                *total = total.saturating_add(n);
            }
        }
    }

    fn note(
        &mut self,
        cursor: u64,
        kind: &str,
        data: &str,
        payload: &[Content],
        index_key: &[u8],
    ) -> Observed {
        let doc: JsonValue = serde_json::from_str(data).unwrap_or(JsonValue::Null);
        match kind {
            "run.start" if cursor == 0 => {
                if let Some(labels) = doc.get("labels").and_then(JsonValue::as_object) {
                    self.labels = labels
                        .iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                        .collect();
                }
                self.subjects = subjects_of(payload.first(), index_key);
            }
            "attempt.start" => {
                self.attempt_open = true;
                self.attempts += 1;
                if let Some(p) = doc.get("program") {
                    if let (Some(name), Some(hash)) = (
                        p.get("name").and_then(JsonValue::as_str),
                        p.get("hash").and_then(JsonValue::as_str),
                    ) {
                        self.program = Some(ProgramRef {
                            name: name.into(),
                            hash: hash.into(),
                        });
                    }
                }
            }
            "attempt.end" => {
                self.attempt_open = false;
                let outcome = doc.get("outcome").and_then(JsonValue::as_str);
                self.last_outcome = outcome.map(str::to_string);
                return Observed {
                    attempt_ended_ok: outcome == Some("ok"),
                };
            }
            _ => {}
        }
        Observed::default()
    }
}

/// The subject hashes in a `run.start` payload slot: `{"subjects": [...]}`.
fn subjects_of(slot: Option<&Content>, index_key: &[u8]) -> Vec<String> {
    let Some(value) = slot.and_then(Content::value) else {
        return Vec::new();
    };
    let Ok(doc) = serde_json::from_slice::<JsonValue>(value.as_bytes()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = doc
        .get("subjects")
        .and_then(JsonValue::as_array)
        .map(|a| {
            a.iter()
                .filter_map(JsonValue::as_str)
                .map(|s| subject_hash(index_key, s))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::journal::{EraseSelector, ErasureNote, META, ROOT};
    use pragmatic::EffectOutcome;

    fn note(kind: &str, data: &str, payload: Vec<Content>) -> Event {
        Event::Note {
            kind: kind.into(),
            data: data.into(),
            payload,
        }
    }

    fn sample() -> Journal {
        let mut j = Journal::new(None);
        j.append(
            META,
            note(
                "run.start",
                r#"{"run_id":"r","labels":{"team":"a"}}"#,
                vec![Content::from(r#"{"subjects":["user-42","user-7"]}"#)],
            ),
        )
        .unwrap();
        j.append(
            META,
            note(
                "attempt.start",
                r#"{"attempt":1,"program":{"name":"agent","hash":"abc"}}"#,
                vec![],
            ),
        )
        .unwrap();
        let d = j
            .append(
                ROOT,
                Event::DrawIntent {
                    provenance: "p".into(),
                    parts: vec![Content::from("hi")],
                },
            )
            .unwrap();
        j.append(
            ROOT,
            Event::DrawResult {
                intent: d,
                meta: r#"{"outcome":"ok","usage":{"input_tokens":10,"output_tokens":5}}"#.into(),
                head: Content::from("{}"),
                body: Content::from("hello"),
            },
        )
        .unwrap();
        j.append(
            ROOT,
            Event::EffectIntent {
                name: "send".into(),
                arg: Content::from("x"),
            },
        )
        .unwrap();
        j
    }

    #[test]
    fn folds_labels_program_usage_intents_and_subjects() {
        let key = b"index key";
        let mut j = sample();
        let s = Summary::rebuild(&j, key);
        assert_eq!(s.labels["team"], "a");
        assert_eq!(s.program.as_ref().unwrap().hash, "abc");
        assert_eq!(s.usage["input_tokens"], 10);
        assert!(s.attempt_open);
        assert!(s.has_open_effect());
        assert_eq!(s.open_intents.len(), 1);
        assert_eq!(s.subjects.len(), 2);
        assert!(s.subjects.contains(&subject_hash(key, "user-42")));
        assert!(!s.finished_ok());

        let mut incremental = s.clone();
        let c = j
            .append(
                ROOT,
                Event::EffectResult {
                    intent: 4,
                    outcome: EffectOutcome::Ok,
                    error_kind: String::new(),
                    payload: Some(Content::from("done")),
                },
            )
            .unwrap();
        let end = j
            .append(
                META,
                note("attempt.end", r#"{"attempt":1,"outcome":"ok"}"#, vec![]),
            )
            .unwrap();
        assert!(!incremental.observe(j.get(c).unwrap(), key).attempt_ended_ok);
        assert!(
            incremental
                .observe(j.get(end).unwrap(), key)
                .attempt_ended_ok
        );
        assert_eq!(incremental, Summary::rebuild(&j, key));
        assert!(incremental.finished_ok());
        assert!(incremental.open_intents.is_empty());
    }

    #[test]
    fn erasing_the_subjects_slot_drops_the_index_entries() {
        let key = b"k";
        let mut j = sample();
        j.mark_persisted(j.len());
        let erased = j
            .erase(
                &EraseSelector::Slots(vec![(0, 0)]),
                &ErasureNote::local("dsar", ""),
                1,
            )
            .unwrap();
        let s = Summary::rebuild(&erased.journal, key);
        assert!(s.subjects.is_empty());
        assert_eq!(s.erased_slots, 1);
        let shredded = erased
            .journal
            .erase(&EraseSelector::All, &ErasureNote::local("retention", ""), 2)
            .unwrap();
        assert_eq!(Summary::rebuild(&shredded.journal, key).sealed_slots, 0);
    }
}
