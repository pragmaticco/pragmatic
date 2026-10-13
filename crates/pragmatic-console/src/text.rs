//! How entries are described in words: one label and one summary line per
//! entry, for format 2 and for read-only format 1 journals.
//!
//! The CLI prints these to a terminal and the HTML views escape them, so
//! everything here is plain text, and every piece of journal content that
//! goes into it passes through [`clip`] or [`sanitize`]: control characters
//! (an escape sequence in a model's output, say) are shown as `\u{..}`
//! rather than sent to a terminal, so recorded content can never move the
//! cursor, recolor a report or pose as one of its lines.
//!
//! Erased and withheld slots are always shown as such, never as empty
//! text, so a reader can tell "said nothing" from "erased".

use std::collections::{HashMap, HashSet};

use pragmatic::evidence::time::rfc3339_nanos;
use pragmatic::journal::{
    Content, Cursor, EffectOutcome, Entry, Event, Journal, LegacyEvent, META,
};
use pragmatic::json::Json;
use pragmatic::redact::binary;
use pragmatic::VerifyReport;

/// A branch for display: `-` for the root, `meta` for the meta branch,
/// otherwise the child indices joined by `.`.
pub fn branch_label(branch: &[u32]) -> String {
    if branch.is_empty() {
        "-".to_string()
    } else if branch == META {
        "meta".to_string()
    } else {
        branch
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// `s` with every control character written as `\u{..}` (newlines and tabs
/// too), so untrusted text prints on one line and cannot drive a terminal.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` on one line, cut to `width` characters. Newlines and tabs become
/// spaces; other control characters are escaped as in [`sanitize`].
pub fn clip(s: &str, width: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .take(width + 1)
        .collect();
    let mut out = sanitize(&flat.chars().take(width).collect::<String>());
    if flat.chars().count() > width {
        out.push('\u{2026}');
    }
    out
}

/// A slot's content on one line: text (with binary values summarized),
/// a binary summary, or the slot's state.
pub fn content(c: &Content, width: usize) -> String {
    match c {
        Content::Sealed(v) => {
            let scanned = binary::scan(v.as_bytes());
            match scanned.text {
                Some(t) => clip(&t, width),
                None => scanned.binary[0].placeholder(),
            }
        }
        Content::Erased => "[erased]".to_string(),
        Content::Withheld => "[withheld]".to_string(),
    }
}

/// The time of an entry, `at` in Unix nanoseconds, as RFC 3339 UTC to the
/// millisecond, always `YYYY-MM-DDTHH:MM:SS.mmmZ` so columns line up.
pub fn time(at: u64) -> String {
    let whole = rfc3339_nanos(at - at % 1_000_000_000);
    let ms = at / 1_000_000 % 1_000;
    format!("{}.{ms:03}Z", whole.trim_end_matches('Z'))
}

/// The short event label of an entry.
pub fn label(event: &Event) -> String {
    match event {
        Event::DrawIntent { .. } => "draw.intent".into(),
        Event::DrawResult { meta, .. } => format!("draw.{}", draw_meta(meta).outcome),
        Event::ChannelRecv { .. } => "chan.recv".into(),
        Event::EffectIntent { .. } => "effect.intent".into(),
        Event::EffectResult { outcome, .. } => format!("effect.{}", outcome.as_str()),
        Event::Clock { .. } => "clock".into(),
        Event::Program { .. } => "program".into(),
        Event::Fork { .. } => "fork".into(),
        Event::Marker { .. } => "marker".into(),
        Event::Note { kind, .. } => format!("note.{}", clip(kind, 32)),
        Event::Random { .. } => "random".into(),
        Event::Refusal { step, .. } => format!("{}.refused", clip(step, 16)),
        Event::Legacy(l) => match l {
            LegacyEvent::OracleDraw { .. } => "oracle.draw".into(),
            LegacyEvent::ChannelRecv { .. } => "chan.recv".into(),
            LegacyEvent::EffectIntent { .. } => "effect.intent".into(),
            LegacyEvent::EffectCommit { .. } => "effect.commit".into(),
            LegacyEvent::EffectCompensated { .. } => "effect.comp".into(),
            LegacyEvent::Clock { .. } => "clock".into(),
            LegacyEvent::Program { .. } => "program".into(),
        },
        other => other.kind_name().to_lowercase(),
    }
}

/// What a draw result's `meta` says (design 2.6). Missing values are
/// empty or `None`; malformed meta reads as outcome `?`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrawMeta {
    pub outcome: String,
    pub provider: String,
    pub model: String,
    pub stop_reason: String,
    pub status: Option<u64>,
    pub error_kind: String,
    pub error_type: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub latency_ms: Option<u64>,
}

/// Parse draw result meta.
pub fn draw_meta(meta: &str) -> DrawMeta {
    let Ok(doc) = Json::parse(meta) else {
        return DrawMeta {
            outcome: "?".into(),
            ..DrawMeta::default()
        };
    };
    let s = |k: &str| doc.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let usage = |k: &str| {
        doc.get("usage")
            .and_then(|u| u.get(k))
            .and_then(Json::as_u64)
    };
    let outcome = s("outcome");
    DrawMeta {
        outcome: if outcome.is_empty() {
            "?".into()
        } else {
            outcome
        },
        provider: s("provider"),
        model: s("model"),
        stop_reason: s("stop_reason"),
        status: doc.get("status").and_then(Json::as_u64),
        error_kind: s("error_kind"),
        error_type: s("error_type"),
        input_tokens: usage("input_tokens"),
        output_tokens: usage("output_tokens"),
        cache_read_tokens: usage("cache_read_tokens"),
        cache_write_tokens: usage("cache_write_tokens"),
        reasoning_tokens: usage("reasoning_tokens"),
        latency_ms: doc.get("latency_ms").and_then(Json::as_u64),
    }
}

impl DrawMeta {
    /// `model, 1830 in / 42 out, 812 ms`, as much as is known.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.model.is_empty() {
            parts.push(clip(&self.model, 48));
        }
        if let (Some(i), Some(o)) = (self.input_tokens, self.output_tokens) {
            parts.push(format!("{i} in / {o} out"));
        }
        if let Some(ms) = self.latency_ms {
            parts.push(format!("{ms} ms"));
        }
        if !self.error_kind.is_empty() {
            parts.push(clip(&self.error_kind, 32));
        }
        if !self.error_type.is_empty() {
            parts.push(clip(&self.error_type, 64));
        }
        if let Some(st) = self.status {
            if st >= 400 {
                parts.push(format!("HTTP {st}"));
            }
        }
        parts.join(", ")
    }
}

/// A one-line summary of an entry.
pub fn summary(event: &Event, width: usize) -> String {
    match event {
        Event::DrawIntent { provenance, parts } => {
            let last = parts.last().map(|p| content(p, width)).unwrap_or_default();
            let more = if parts.len() > 1 {
                format!(" (last of {} parts)", parts.len())
            } else {
                String::new()
            };
            format!("{last}{more}  [{}]", clip(provenance, 40))
        }
        Event::DrawResult {
            intent, meta, body, ..
        } => {
            let m = draw_meta(meta);
            let about = m.describe();
            let about = if about.is_empty() {
                String::new()
            } else {
                format!(" ({about})")
            };
            format!("for #{intent}{about}: {}", content(body, width))
        }
        Event::ChannelRecv { channel, value } => {
            format!("{} ? {}", clip(channel, 40), content(value, width))
        }
        Event::EffectIntent { name, arg } => format!("{}({})", clip(name, 48), content(arg, width)),
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            payload,
        } => {
            let shown = payload
                .as_ref()
                .map(|p| content(p, width))
                .unwrap_or_default();
            match outcome {
                EffectOutcome::Ok => format!("for #{intent}: {shown}"),
                EffectOutcome::Failed => {
                    format!("for #{intent}: {}: {shown}", clip(error_kind, 48))
                }
                EffectOutcome::Compensated => {
                    format!("for #{intent}: written off; performed again under a new intent")
                }
            }
        }
        Event::Clock { nanos } => format!("{nanos} ns ({})", time(*nanos)),
        Event::Program { name, hash } => format!("{} [{}]", clip(name, 64), clip(hash, 64)),
        Event::Fork { base, children } => {
            let last = u64::from(*base) + u64::from(*children) - 1;
            format!("parallel region: {children} children, branches {base}..={last}")
        }
        Event::Marker { name } => format!("took patch '{}'", clip(name, 64)),
        Event::Note {
            kind,
            data,
            payload,
        } => note_summary(kind, data, payload, width),
        Event::Random {
            source,
            args,
            value,
        } => format!(
            "{}{} = {}",
            clip(source, 16),
            clip(args, 32),
            content(value, width)
        ),
        Event::Refusal { step, name, fault } if name.is_empty() => {
            format!("{} refused: {}", clip(step, 16), clip(fault, 32))
        }
        Event::Refusal { step, name, fault } => format!(
            "{} '{}' refused: {}",
            clip(step, 16),
            clip(name, 48),
            clip(fault, 32)
        ),
        Event::Legacy(l) => legacy_summary(l, width),
        other => other.kind_name().to_string(),
    }
}

/// A note's summary, by kind (design 2.11). Unknown kinds show their data.
pub fn note_summary(kind: &str, data: &str, payload: &[Content], width: usize) -> String {
    let Ok(d) = Json::parse(data) else {
        return clip(data, width);
    };
    let s = |k: &str| match d.get(k) {
        Some(Json::String(v)) => clip(v, 64),
        Some(Json::Null) | None => String::new(),
        Some(other) => clip(&other.to_string(), 64),
    };
    match kind {
        "run.start" => {
            let labels = d
                .get("labels")
                .and_then(Json::as_object)
                .map(|l| {
                    l.iter()
                        .map(|(k, v)| {
                            format!("{}={}", clip(k, 32), clip(v.as_str().unwrap_or(""), 32))
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let labels = if labels.is_empty() {
                String::new()
            } else {
                format!("; labels {labels}")
            };
            format!(
                "run {} started by {} {}{labels}",
                s("run_id"),
                s("sdk"),
                s("sdk_version")
            )
        }
        "attempt.start" => {
            let torn = d.get("torn_bytes").and_then(Json::as_u64).unwrap_or(0);
            let torn = if torn > 0 {
                format!("; {torn} torn bytes truncated")
            } else {
                String::new()
            };
            format!(
                "attempt {} ({}) on {} pid {} as {}{torn}",
                s("attempt"),
                s("mode"),
                s("host"),
                s("pid"),
                s("principal")
            )
        }
        "attempt.end" => {
            let fault = match (s("fault_kind").as_str(), s("fault_cursor").as_str()) {
                ("", _) => String::new(),
                (k, "") => format!(": {k}"),
                (k, c) => format!(": {k} at #{c}"),
            };
            let message = payload
                .get(1)
                .filter(|p| !matches!(p, Content::Sealed(v) if v.is_empty()))
                .map(|p| format!(" ({})", content(p, width / 2)))
                .unwrap_or_default();
            format!(
                "attempt {} ended {}{fault}{message}; {} fresh, {} replayed",
                s("attempt"),
                s("outcome"),
                s("fresh"),
                s("replayed")
            )
        }
        "program.change" => format!(
            "program changed at #{}: {} -> {}",
            s("cursor"),
            s("from"),
            s("to")
        ),
        "recovery" => {
            let saga = s("saga");
            let saga = if saga.is_empty() {
                String::new()
            } else {
                format!(" (saga {saga})")
            };
            format!(
                "recovery decided {} for {} (intent #{}, result #{}){saga}",
                s("decision"),
                s("name"),
                s("intent"),
                s("result")
            )
        }
        "erasure" => {
            let slots: Vec<String> = d
                .get("slots")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|p| match p.as_array()? {
                    [c, k] => Some(format!("{c}:{k}")),
                    _ => None,
                })
                .collect();
            let auth = if d.get("authenticated").and_then(Json::as_bool) == Some(true) {
                "authenticated"
            } else {
                "unauthenticated"
            };
            format!(
                "erased {} slot(s) [{}] by {} ({auth}), reason {}",
                slots.len(),
                clip(&slots.join(" "), 48),
                s("by"),
                s("reason_code")
            )
        }
        "custody" => {
            let skew = if d.get("clock_skew").and_then(Json::as_bool) == Some(true) {
                "; clock skew flagged"
            } else {
                ""
            };
            format!(
                "lease held by {} (token {}): entries {}..{}, {} request(s){skew}",
                s("principal"),
                s("token"),
                s("from_entries"),
                s("to_entries"),
                s("requests")
            )
        }
        "torn_tail" => format!(
            "{} torn bytes at offset {} moved to {}",
            s("bytes"),
            s("offset"),
            s("moved_to")
        ),
        _ => clip(data, width),
    }
}

fn legacy_summary(l: &LegacyEvent, width: usize) -> String {
    let v = |x: &pragmatic::Value| clip(&x.as_str(), width);
    match l {
        LegacyEvent::Program { name, hash } => format!("{} [{}]", clip(name, 64), clip(hash, 64)),
        LegacyEvent::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => format!(
            "{} -> {}  [{}]",
            v(prompt),
            v(outcome),
            clip(provenance, 40)
        ),
        LegacyEvent::ChannelRecv { channel, value } => {
            format!("{} ? {}", clip(channel, 40), v(value))
        }
        LegacyEvent::EffectIntent { name, arg } => format!("{}({})", clip(name, 48), v(arg)),
        LegacyEvent::EffectCommit { name, result } => {
            format!("{} -> {}", clip(name, 48), v(result))
        }
        LegacyEvent::EffectCompensated { name } => clip(name, 48),
        LegacyEvent::Clock { nanos } => format!("{nanos} ns"),
    }
}

/// The results recorded for each intent, by intent cursor, in cursor order.
pub fn results_by_intent(journal: &Journal) -> HashMap<Cursor, Vec<Cursor>> {
    let mut out: HashMap<Cursor, Vec<Cursor>> = HashMap::new();
    for e in journal.entries() {
        if let Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } = e.event {
            out.entry(intent).or_default().push(e.cursor);
        }
    }
    out
}

/// Intents (draw or effect) that have no result: work a crash interrupted.
/// Format 1 effect intents count when no commit or compensation follows.
pub fn open_intents(journal: &Journal) -> Vec<Cursor> {
    let completed: HashSet<Cursor> = results_by_intent(journal).into_keys().collect();
    let mut open = Vec::new();
    let mut legacy_open: Vec<(Cursor, String)> = Vec::new();
    for e in journal.entries() {
        match &e.event {
            Event::DrawIntent { .. } | Event::EffectIntent { .. } => {
                if !completed.contains(&e.cursor) {
                    open.push(e.cursor);
                }
            }
            Event::Legacy(LegacyEvent::EffectIntent { name, .. }) => {
                legacy_open.push((e.cursor, name.clone()))
            }
            Event::Legacy(
                LegacyEvent::EffectCommit { name, .. } | LegacyEvent::EffectCompensated { name },
            ) => {
                if let Some(i) = legacy_open.iter().rposition(|(_, n)| n == name) {
                    legacy_open.remove(i);
                }
            }
            _ => {}
        }
    }
    open.extend(legacy_open.into_iter().map(|(c, _)| c));
    open.sort_unstable();
    open
}

/// Model calls in the journal: draw intents (format 2) or draws (format 1).
pub fn draws(journal: &Journal) -> usize {
    journal
        .entries()
        .iter()
        .filter(|e| {
            matches!(
                e.event,
                Event::DrawIntent { .. } | Event::Legacy(LegacyEvent::OracleDraw { .. })
            )
        })
        .count()
}

/// Effects that completed: ok results (format 2) or commits (format 1).
pub fn effects_committed(journal: &Journal) -> usize {
    journal
        .entries()
        .iter()
        .filter(|e| {
            matches!(
                e.event,
                Event::EffectResult {
                    outcome: EffectOutcome::Ok,
                    ..
                } | Event::Legacy(LegacyEvent::EffectCommit { .. })
            )
        })
        .count()
}

/// Erased slots in an entry (refs to an erased target included).
pub fn erased_slots(entry: &Entry) -> usize {
    entry
        .event
        .slot_contents()
        .iter()
        .filter(|c| matches!(c, Content::Erased))
        .count()
}

/// Attempts started in the journal (`attempt.start` notes).
pub fn attempts(journal: &Journal) -> usize {
    journal
        .entries()
        .iter()
        .filter(|e| e.event.note_kind() == Some("attempt.start"))
        .count()
}

/// One line of the verify report: `verified`, or the problems.
pub fn verify_line(report: &VerifyReport) -> String {
    let problems = verify_problems(report);
    if problems.is_empty() {
        "verified".to_string()
    } else {
        problems.join("; ")
    }
}

/// Every problem in a verify report, one per line, empty when it is ok. A
/// torn tail is not a problem (it is what a crash leaves) and is reported
/// separately.
pub fn verify_problems(report: &VerifyReport) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some(c) = report.first_bad {
        problems.push(format!(
            "HASH CHAIN BROKEN at cursor {c}: entries from here on are not covered by the chain"
        ));
    }
    let list = |slots: &[(Cursor, u8)]| {
        slots
            .iter()
            .take(8)
            .map(|(c, s)| format!("{c}:{s}"))
            .collect::<Vec<_>>()
            .join(" ")
            + if slots.len() > 8 { " ..." } else { "" }
    };
    if !report.unaccounted_erasures.is_empty() {
        problems.push(format!(
            "{} erased slot(s) no erasure note accounts for: {}",
            report.unaccounted_erasures.len(),
            list(&report.unaccounted_erasures)
        ));
    }
    if !report.erasure_incomplete.is_empty() {
        problems.push(format!(
            "{} slot(s) listed as erased still hold content (erase again to repair): {}",
            report.erasure_incomplete.len(),
            list(&report.erasure_incomplete)
        ));
    }
    if !report.invalid_erasure_notes.is_empty() {
        problems.push(format!(
            "{} invalid erasure note(s), at cursor(s) {}",
            report.invalid_erasure_notes.len(),
            report
                .invalid_erasure_notes
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_never_reach_a_terminal() {
        assert_eq!(sanitize("a\x1b[31mb"), "a\\u{1b}[31mb");
        assert_eq!(sanitize("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(clip("one\ntwo\x07", 20), "one two\\u{7}");
        assert_eq!(clip("abcdef", 3), "abc\u{2026}");
    }

    #[test]
    fn times_have_a_fixed_width() {
        assert_eq!(time(1_791_916_268_600_000_000), "2026-10-13T18:31:08.600Z");
        assert_eq!(time(1_791_916_268_000_123_000), "2026-10-13T18:31:08.000Z");
        assert_eq!(time(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn draw_meta_reads_usage_and_errors() {
        let m = draw_meta(
            r#"{"outcome":"ok","model":"m1","usage":{"input_tokens":5,"output_tokens":7},"latency_ms":3}"#,
        );
        assert_eq!(m.outcome, "ok");
        assert_eq!(m.describe(), "m1, 5 in / 7 out, 3 ms");
        let e = draw_meta(r#"{"outcome":"error","error_kind":"timeout","status":503}"#);
        assert_eq!(e.describe(), "timeout, HTTP 503");
        assert_eq!(draw_meta("not json").outcome, "?");
    }

    #[test]
    fn notes_are_described_by_kind() {
        let s = note_summary(
            "erasure",
            r#"{"access_log_cursor":null,"authenticated":false,"by":"local:a@b","reason_code":"gdpr","slots":[[3,0],[4,1]]}"#,
            &[],
            80,
        );
        assert_eq!(
            s,
            "erased 2 slot(s) [3:0 4:1] by local:a@b (unauthenticated), reason gdpr"
        );
        let c = note_summary(
            "custody",
            r#"{"clock_skew":true,"first_received":1,"from_entries":0,"last_received":2,"lease":"ab","principal":"svc","requests":3,"to_entries":9,"token":"t1"}"#,
            &[],
            80,
        );
        assert!(c.contains("entries 0..9") && c.contains("clock skew"));
        assert_eq!(note_summary("x", "{bad", &[], 10), "{bad");
    }
}
