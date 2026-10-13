//! How the CLI and the console describe journal entries: one label and one
//! summary line per entry, for format 2 and for read-only format 1
//! journals.
//!
//! Slot content is shown clipped; erased and withheld slots are shown as
//! such, never as empty text, so a reader can tell "said nothing" from
//! "erased".

use std::collections::HashSet;

use pragmatic::journal::{
    Content, Cursor, EffectOutcome, Entry, Event, Journal, LegacyEvent, META,
};

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

/// `s` on one line, cut to `width` characters.
pub fn clip(s: &str, width: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() > width {
        let cut: String = s.chars().take(width).collect();
        format!("{cut}…")
    } else {
        s
    }
}

/// A slot's content for display.
pub fn content(c: &Content, width: usize) -> String {
    match c {
        Content::Sealed(v) => clip(&v.as_str(), width),
        Content::Erased => "[erased]".to_string(),
        Content::Withheld => "[withheld]".to_string(),
    }
}

/// The full text of a slot, for detail views.
pub fn content_full(c: &Content) -> String {
    match c {
        Content::Sealed(v) => v.as_str().into_owned(),
        Content::Erased => "[erased: only the commitment remains]".to_string(),
        Content::Withheld => "[withheld]".to_string(),
    }
}

/// The short event label of an entry.
pub fn label(event: &Event) -> String {
    match event {
        Event::DrawIntent { .. } => "draw.intent".into(),
        Event::DrawResult { .. } => "draw.result".into(),
        Event::ChannelRecv { .. } => "chan.recv".into(),
        Event::EffectIntent { .. } => "effect.intent".into(),
        Event::EffectResult { outcome, .. } => format!("effect.{}", outcome.as_str()),
        Event::Clock { .. } => "clock".into(),
        Event::Program { .. } => "program".into(),
        Event::Fork { .. } => "fork".into(),
        Event::Marker { .. } => "marker".into(),
        Event::Note { kind, .. } => format!("note.{kind}"),
        Event::Random { .. } => "random".into(),
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

/// The `outcome` of a draw result's metadata.
fn draw_outcome(meta: &str) -> String {
    pragmatic::json::Json::parse(meta)
        .ok()
        .and_then(|m| {
            m.get("outcome")
                .and_then(|o| o.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| "?".to_string())
}

/// A one-line summary of an entry.
pub fn summary(event: &Event, width: usize) -> String {
    match event {
        Event::DrawIntent { provenance, parts } => {
            let first = parts.first().map(|p| content(p, width)).unwrap_or_default();
            let more = if parts.len() > 1 {
                format!(" (+{} parts)", parts.len() - 1)
            } else {
                String::new()
            };
            format!("{first}{more}  ({provenance})")
        }
        Event::DrawResult {
            intent, meta, body, ..
        } => format!(
            "for {intent}: {} ⟶ {}",
            draw_outcome(meta),
            content(body, width)
        ),
        Event::ChannelRecv { channel, value } => format!("{channel} ? {}", content(value, width)),
        Event::EffectIntent { name, arg } => format!("{name}({})", content(arg, width)),
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
                EffectOutcome::Ok => format!("for {intent} ⟶ {shown}"),
                EffectOutcome::Failed => format!("for {intent}: {error_kind}: {shown}"),
                EffectOutcome::Compensated => format!("for {intent}: written off"),
            }
        }
        Event::Clock { nanos } => format!("{nanos} ns"),
        Event::Program { name, hash } => format!("{name} [{hash}]"),
        Event::Fork { base, children } => {
            format!(
                "children {base}..{}",
                u64::from(*base) + u64::from(*children)
            )
        }
        Event::Marker { name } => format!("patch '{name}'"),
        Event::Note { data, payload, .. } => {
            let slots = if payload.is_empty() {
                String::new()
            } else {
                format!("  (+{} payload slots)", payload.len())
            };
            format!("{}{slots}", clip(data, width))
        }
        Event::Random {
            source,
            args,
            value,
        } => format!("{source}{args} ⟶ {}", content(value, width)),
        Event::Legacy(l) => legacy_summary(l, width),
        other => other.kind_name().to_string(),
    }
}

fn legacy_summary(l: &LegacyEvent, width: usize) -> String {
    match l {
        LegacyEvent::Program { name, hash } => format!("{name} [{hash}]"),
        LegacyEvent::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => format!(
            "{} ⟶ {}  ({provenance})",
            clip(&prompt.as_str(), width),
            clip(&outcome.as_str(), width)
        ),
        LegacyEvent::ChannelRecv { channel, value } => {
            format!("{channel} ? {}", clip(&value.as_str(), width))
        }
        LegacyEvent::EffectIntent { name, arg } => {
            format!("{name}({})", clip(&arg.as_str(), width))
        }
        LegacyEvent::EffectCommit { name, result } => {
            format!("{name} ⟶ {}", clip(&result.as_str(), width))
        }
        LegacyEvent::EffectCompensated { name } => name.to_string(),
        LegacyEvent::Clock { nanos } => format!("{nanos} ns"),
    }
}

/// Intents (draw or effect) that have no result: work a crash interrupted.
/// Format 1 effect intents count when no commit or compensation follows.
pub fn open_intents(journal: &Journal) -> Vec<Cursor> {
    let mut completed: HashSet<Cursor> = HashSet::new();
    for e in journal.entries() {
        if let Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } = e.event {
            completed.insert(intent);
        }
    }
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

/// Slots that are erased in an entry.
pub fn erased_slots(entry: &Entry) -> usize {
    entry
        .event
        .slot_contents()
        .iter()
        .filter(|c| matches!(c, Content::Erased))
        .count()
}

/// One line of the verify report.
pub fn verify_line(report: &pragmatic::VerifyReport) -> String {
    let mut problems = Vec::new();
    if let Some(c) = report.first_bad {
        problems.push(format!("HASH CHAIN BROKEN at cursor {c}"));
    }
    if !report.unaccounted_erasures.is_empty() {
        problems.push(format!(
            "{} erased slot(s) no erasure note accounts for (first at cursor {})",
            report.unaccounted_erasures.len(),
            report.unaccounted_erasures[0].0
        ));
    }
    if !report.erasure_incomplete.is_empty() {
        problems.push(format!(
            "{} slot(s) listed as erased still hold content (erase again to repair)",
            report.erasure_incomplete.len()
        ));
    }
    if !report.invalid_erasure_notes.is_empty() {
        problems.push(format!(
            "{} invalid erasure note(s)",
            report.invalid_erasure_notes.len()
        ));
    }
    if problems.is_empty() {
        "verified".to_string()
    } else {
        problems.join("; ")
    }
}
