//! Evidence bundles for people: the verification report as a page, and the
//! records as CSV.
//!
//! The page leads with the verdict and what it means in the words the
//! design permits (a verified anchor proves a journal prefix existed by a
//! time; it proves nothing about whether the content was true), then the
//! step-by-step checks, every finding with its code, each anchor with its
//! witnesses and how far each can be trusted, and finally the run's
//! timeline decoded from the bundle's own journal, as the run page shows
//! it. Every string from the bundle is escaped: a bundle is adversarial
//! input, and its text is never presented as the verifier's own.

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::{
    state_name, AnchorReport, Bundle, CheckStatus, EvidenceReport, Record, Severity,
    SignatureStatus, Verdict, WitnessClass,
};
use pragmatic::journal::Journal;
use pragmatic::redact::binary;

use crate::html::{diamond, document, empty, esc, masthead, mono, notice, Crumb, Frame, Page};
use crate::rows::{Facts, Liveness};
use crate::run::{time_words, timeline, when, RunView};
use crate::text;

/// The verification report and timeline of a bundle as a page.
pub fn render_evidence(bundle: &Bundle, report: &EvidenceReport) -> String {
    let mut main = verdict(bundle, report);
    main.push_str(&checks(report));
    main.push_str(&findings(report));
    main.push_str(&anchors(report));
    match Journal::parse_evidence(&bundle.journal.bytes) {
        Ok(p) if p.tail_len == 0 => {
            let j = &p.journal;
            let audit = j.audit();
            let facts = Facts::of(j, Liveness::Unknown);
            let view = RunView::new(&bundle.run_id, j, &audit);
            let (rows, next) = timeline(j, &facts, &view, 0);
            let more = if next.is_some() {
                "<p class=\"pager end\">The CSV rendering of this bundle has a row for every \
                 entry.</p>"
            } else {
                ""
            };
            main.push_str(&format!(
                "<section class=\"sect\"><h2 class=\"rhead\">Timeline</h2>\
                 <article class=\"sheet\" aria-label=\"Timeline\">{rows}{more}</article></section>"
            ));
        }
        _ => main.push_str(&records_table(&bundle.records)),
    }
    let right = format!(
        "<span class=\"mast-note\">Bundle made {} \u{b7} an unsigned time</span>",
        esc(&time_words(&text::clip(&bundle.generated_at, 40)))
    );
    let mast = masthead(
        None,
        &[
            Crumb::word("Evidence", None),
            Crumb::id(&bundle.run_id, None),
        ],
        &right,
    );
    document(
        &Frame::FILE,
        &Page {
            title: &format!("Evidence {}", text::clip(&bundle.run_id, 80)),
            masthead: mast,
            main,
            skip: Some(("main", "Skip to content")),
            ..Page::default()
        },
    )
}

/// `1 operator`, `2 operators`.
fn operators(n: usize) -> String {
    if n == 1 {
        "1 independent operator".to_string()
    } else {
        format!("{n} independent operators")
    }
}

/// Text with the command-line flags in it (`--log-key`) set in mono, as
/// escaped HTML.
fn flags_in_mono(text: &str) -> String {
    let mut out = String::new();
    for (i, word) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let lead = word.len() - word.trim_start_matches(['(', '"']).len();
        let core = &word[lead..];
        let core_end = core.trim_end_matches([')', '.', ',', ';', ':', '"']).len();
        let (flag, tail) = core.split_at(core_end);
        if flag.len() > 2 && flag.starts_with("--") {
            out.push_str(&esc(&word[..lead]));
            out.push_str(&format!("<span class=\"m\">{}</span>", esc(flag)));
            out.push_str(&esc(tail));
        } else {
            out.push_str(&esc(word));
        }
    }
    out
}

fn verdict(b: &Bundle, r: &EvidenceReport) -> String {
    let min = r.min_operators.max(1);
    let time = |entries: u64| {
        r.anchors
            .iter()
            .filter(|a| a.independent && a.entries == entries)
            .filter_map(|a| a.earliest)
            .min()
            .map(|t| format!(" no later than {}", when(&t.rfc3339())))
            .unwrap_or_default()
    };
    let (badge, text) = match r.verdict {
        Verdict::Verified => (
            format!(
                "<span class=\"badge lg\">{}Verified</span>",
                diamond(true, false)
            ),
            format!(
                "All {} entries are anchored: witnesses from at least {} the verifier trusts \
                 vouch that the journal up to its head existed{}.",
                text::count(r.entries),
                operators(min),
                time(r.anchored_entries)
            ),
        ),
        Verdict::Partial { unanchored } => (
            format!(
                "<span class=\"badge lg\">{}Verified up to #{}</span>",
                diamond(false, false),
                r.anchored_entries.saturating_sub(1)
            ),
            format!(
                "The first {} of {} entries are independently anchored{}; the last {} not \
                 anchored by at least {} the verifier trusts.",
                text::count(r.anchored_entries),
                text::count(r.entries),
                time(r.anchored_entries),
                if unanchored == 1 {
                    "is".to_string()
                } else {
                    format!("{} are", text::count(unanchored))
                },
                operators(min)
            ),
        ),
        Verdict::Unanchored => (
            format!(
                "<span class=\"badge lg\">{}Unanchored</span>",
                diamond(false, false)
            ),
            format!(
                "The journal's integrity checks pass, but no anchor is witnessed by at least {} \
                 the verifier trusts, so nothing ties it to a time.",
                operators(min)
            ),
        ),
        Verdict::Failed => (
            format!(
                "<span class=\"badge lg alarm\">{}Failed</span>",
                diamond(true, true)
            ),
            "An integrity check failed, or an audit the verifier was asked for could not be \
             completed: the bundle cannot be relied on as it stands. The failures are listed \
             below."
                .to_string(),
        ),
    };
    let n = |x: String| format!("<span class=\"n\">{x}</span>");
    let sig = match &r.bundle_signature {
        SignatureStatus::Verified { key } => format!("signature verified with {}", mono(key)),
        SignatureStatus::OperatorAsserted => "signature operator-asserted".to_string(),
        SignatureStatus::Unsigned => "unsigned".to_string(),
        SignatureStatus::Invalid => "<span class=\"alarm\">signature invalid</span>".to_string(),
    };
    // Only the bundle signature covers these fields; unless a pinned key
    // verified it, they are whatever the file says.
    let claim = if matches!(r.bundle_signature, SignatureStatus::Verified { .. }) {
        "signed"
    } else {
        "unsigned claim"
    };
    let facts = [
        format!("run {}", mono(&b.run_id)),
        format!("{} entries", n(text::count(r.entries))),
        format!(
            "{} {}",
            n(b.anchors.len().to_string()),
            if b.anchors.len() == 1 {
                "anchor"
            } else {
                "anchors"
            }
        ),
        format!(
            "redaction {}, {} withheld",
            mono(&b.redaction.mode),
            n(b.redacted_slots.len().to_string())
        ),
        sig,
        format!(
            "made by {} <span class=\"s\">({claim})</span>",
            mono(&text::clip(&b.generator, 64))
        ),
        format!(
            "for {} <span class=\"s\">({claim})</span>",
            mono(&text::clip(&b.requested_by, 64))
        ),
    ];
    format!(
        "<section class=\"sheet verdict\" aria-labelledby=\"verdict\">\
         <h1 class=\"sh-title\" id=\"verdict\">{badge}<span class=\"exit\">{} \u{b7} exit {}</span></h1>\
         <p class=\"lede\">{}</p><p class=\"facts\">{}</p>\
         <p class=\"caveat\">A verified anchor proves that a journal prefix of the stated length, \
         with the stated chain head, existed no later than the witness time. It does not prove \
         that the content was true when recorded, that nothing happened outside the journaled \
         interfaces, or anything about the run before its first anchor. Trust comes only from \
         the roots and keys the verifier pinned; nothing in the bundle is a trust anchor.</p>\
         </section>",
        r.verdict.label(),
        r.exit_code(),
        text,
        facts.join(" \u{b7} ")
    )
}

fn checks(r: &EvidenceReport) -> String {
    let mut rows = String::new();
    let mut step = "";
    for c in &r.checks {
        // A step with several checks shows its number once.
        let shown = if c.step == step {
            "<span class=\"sr-only\">same step</span>".to_string()
        } else {
            esc(c.step)
        };
        step = c.step;
        let (mark, word) = match c.status {
            CheckStatus::Pass => (diamond(true, false), "pass".to_string()),
            CheckStatus::Fail => (
                diamond(true, true),
                "<span class=\"alarm\">fail</span>".to_string(),
            ),
            CheckStatus::Skipped => (
                diamond(false, false),
                "<span class=\"dim\">skipped</span>".to_string(),
            ),
            CheckStatus::Info => (diamond(false, false), "info".to_string()),
        };
        rows.push_str(&format!(
            "<tr><td class=\"mk\">{mark}</td><td class=\"m r\" data-label=\"Step\">{shown}</td>\
             <td class=\"head\">{}</td><td data-label=\"Result\">{word}</td>\
             <td class=\"m\" data-label=\"Detail\">{}</td></tr>",
            esc(c.name),
            esc(&text::sanitize(&c.detail))
        ));
    }
    format!(
        "<section class=\"sect\"><h2 class=\"rhead\">Checks</h2><p class=\"lede\">Numbered by \
         the steps of the verification procedure, which <span class=\"m\"><span class=\"nw\">pragmatic</span> \
         <span class=\"nw\">verify-evidence</span> <span class=\"nw\">--explain</span></span> \
         prints. A step with more than one check shows its \
         number once, and a step this bundle gives nothing to check is left out.</p>\
         <div class=\"tsheet\"><div class=\"tscroll\">\
         <table class=\"stack\"><caption class=\"sr-only\">Checks</caption><thead><tr>\
         <th class=\"caps\"><span class=\"sr-only\">State</span></th><th class=\"caps r\" scope=\"col\">Step</th>\
         <th class=\"caps\" scope=\"col\">Check</th><th class=\"caps\" scope=\"col\">Result</th>\
         <th class=\"caps\" scope=\"col\">Detail</th></tr></thead><tbody>{rows}</tbody></table></div></div></section>"
    )
}

fn findings(r: &EvidenceReport) -> String {
    if r.findings.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<_> = r.findings.iter().collect();
    sorted.sort_by_key(|f| f.severity());
    let mut rows = String::new();
    for f in sorted {
        let sev = match f.severity() {
            Severity::Failure => "<span class=\"alarm\">failure</span>",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        rows.push_str(&format!(
            "<tr><td class=\"m head\">{}</td><td data-label=\"Severity\">{sev}</td>\
             <td data-label=\"Finding\">{}</td></tr>",
            f.code.as_str(),
            flags_in_mono(&text::sanitize(&f.message))
        ));
    }
    format!(
        "<section class=\"sect\"><h2 class=\"rhead\">Findings</h2><div class=\"tsheet\"><div class=\"tscroll\">\
         <table class=\"stack\"><caption class=\"sr-only\">Findings</caption><thead><tr>\
         <th class=\"caps\" scope=\"col\">Code</th><th class=\"caps\" scope=\"col\">Severity</th>\
         <th class=\"caps\" scope=\"col\">Finding</th></tr></thead><tbody>{rows}</tbody></table></div></div></section>"
    )
}

fn anchors(r: &EvidenceReport) -> String {
    if r.anchors.is_empty() {
        return format!(
            "<section class=\"sect\"><h2 class=\"rhead\">Anchors</h2><div class=\"tsheet\">{}</div></section>",
            empty(
                "This bundle carries no anchors, so nothing ties its journal to a time. Bundles \
                 made from a local journal carry none in 0.6; Pragmatic Server anchors the runs \
                 it stores."
            )
        );
    }
    let blocks: String = r.anchors.iter().map(anchor).collect();
    format!(
        "<section class=\"sect\"><h2 class=\"rhead\">Anchors</h2><div class=\"card\">{blocks}</div></section>"
    )
}

fn anchor(a: &AnchorReport) -> String {
    let (mark, status) = if !a.sound {
        (
            diamond(true, true),
            "<span class=\"alarm\">fails its checks</span>",
        )
    } else if a.independent {
        (diamond(true, false), "independent")
    } else {
        (diamond(false, false), "not enough trusted operators")
    };
    let ops = if a.trusted_operators.is_empty() {
        "<span class=\"s\">none</span>".to_string()
    } else {
        a.trusted_operators
            .iter()
            .map(|o| esc(o))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let time = a
        .earliest
        .map(|t| format!(" \u{b7} no later than {}", when(&t.rfc3339())))
        .unwrap_or_default();
    let mut out = format!(
        "<div class=\"anc\"><p>{mark}Anchor {} \u{b7} {status} \u{b7} {} entries \u{b7} leaf {} of a \
         tree of {} \u{b7} trusted operators {ops}{time}</p><ul class=\"ops\">",
        mono(&a.seq.to_string()),
        text::count(a.entries),
        a.leaf_index,
        a.tree_size
    );
    for w in &a.witnesses {
        let i = match w.class {
            WitnessClass::Trusted => "<i aria-hidden=\"true\"></i>",
            WitnessClass::SelfAsserted => "<i class=\"o\" aria-hidden=\"true\"></i>",
            WitnessClass::OperatorControlled => "<i class=\"o\" aria-hidden=\"true\"></i>",
        };
        let operator = match (&w.operator, &w.claimed_operator) {
            (Some(o), _) => esc(o),
            (None, Some(c)) => format!(
                "<span class=\"s\">claims {}</span>",
                esc(&text::clip(c, 48))
            ),
            (None, None) => String::new(),
        };
        // The parts that are there, joined: no separator leads.
        let mut parts = Vec::new();
        if !operator.is_empty() {
            parts.push(operator);
        }
        if let Some(t) = w.time {
            parts.push(when(&t.rfc3339()));
        }
        if !w.detail.is_empty() {
            parts.push(flags_in_mono(&text::sanitize(&w.detail)));
        }
        out.push_str(&format!(
            "<li class=\"op\">{i}<span class=\"nm\">{}</span><span class=\"st\">{} \u{b7} {}</span>\
             <span class=\"root\">{}</span></li>",
            esc(&text::clip(&w.label, 64)),
            esc(w.kind),
            esc(w.class.as_str()),
            parts.join(" \u{b7} ")
        ));
    }
    out.push_str("</ul></div>");
    out
}

/// The records as a table, for a bundle whose journal does not parse.
fn records_table(records: &[Record]) -> String {
    let mut rows = String::new();
    for r in records.iter().take(10_000) {
        rows.push_str(&format!(
            "<tr><td class=\"m r head\">{}</td><td class=\"m\" data-label=\"Branch\">{}</td>\
             <td class=\"m\" data-label=\"Kind\">{}</td><td class=\"m\" data-label=\"Fields\">{}</td>\
             <td class=\"m\" data-label=\"Slots\">{}</td></tr>",
            r.cursor,
            esc(&text::branch_label(&r.branch)),
            esc(&text::clip(&r.kind, 32)),
            esc(&text::clip(&r.fields.to_string(), 200)),
            esc(&slots_text(r, 200))
        ));
    }
    format!(
        "<section class=\"sect\"><h2 class=\"rhead\">Records</h2>{}<div class=\"tsheet\"><div class=\"tscroll\">\
         <table class=\"stack\"><caption class=\"sr-only\">Records as stated</caption><thead><tr>\
         <th class=\"caps r\" scope=\"col\">Entry</th><th class=\"caps\" scope=\"col\">Branch</th>\
         <th class=\"caps\" scope=\"col\">Kind</th><th class=\"caps\" scope=\"col\">Fields</th>\
         <th class=\"caps\" scope=\"col\">Slots</th></tr></thead><tbody>{rows}</tbody></table></div></div></section>",
        notice(
            "The bundle's journal does not parse, so these are its records as stated, which \
             nothing vouches for.",
            true
        )
    )
}

/// A record's slots on one line: content, binary summary or state.
fn slots_text(r: &Record, width: usize) -> String {
    r.slots
        .iter()
        .map(|s| match s.content() {
            Some(bytes) => {
                let scanned = binary::scan(&bytes);
                match scanned.text {
                    Some(t) => text::clip(&t, width),
                    None => scanned.binary[0].placeholder(),
                }
            }
            None => match s.ref_target {
                Some((c, k)) => format!("[{}: {c}:{k}]", state_name(s.state)),
                None => format!("[{}]", state_name(s.state)),
            },
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The records of a bundle as CSV (RFC 4180, CRLF line ends), one row per
/// entry, for spreadsheets, with the verification verdict on every row.
///
/// Columns: `verdict, anchored, cursor, at_ns, at_utc, branch, kind,
/// fields, slot_states, content, hash`. `verdict` is the report's verdict
/// (`VERIFIED`, `VERIFIED (PARTIAL)`, `UNANCHORED` or `FAILED`), the same
/// on every row, so a spreadsheet passed on keeps it; `anchored` is `yes`
/// for the entries an independent anchor covers. `content` joins the slots
/// with ` | `; binary values are summarized and each cell is cut to 32,000
/// characters (spreadsheets hold at most 32,767). Cells that a spreadsheet
/// would read as a formula (starting with `=`, `+`, `-`, `@`, a tab or a
/// carriage return) are prefixed with `'`, since the content is untrusted.
///
/// Rows are decoded from the bundle's journal, never taken from its
/// `records` section as stated: a bundle whose records were edited after
/// the fact fails verification, and its edits must not reach a
/// spreadsheet. Only when the journal cannot be read at all are the stated
/// records used, and the verdict on every row is then `FAILED`.
pub fn render_csv(bundle: &Bundle, report: &EvidenceReport) -> String {
    let decoded: Option<Vec<Record>> = Journal::parse_evidence(&bundle.journal.bytes)
        .ok()
        .filter(|p| p.tail_len == 0)
        .map(|p| {
            p.journal
                .entries()
                .iter()
                .filter_map(Record::of_entry)
                .collect()
        });
    let records = decoded.as_deref().unwrap_or(&bundle.records);
    let verdict = report.verdict.label();
    let mut out = String::from(
        "verdict,anchored,cursor,at_ns,at_utc,branch,kind,fields,slot_states,content,hash\r\n",
    );
    for r in records {
        let states = r
            .slots
            .iter()
            .map(|s| state_name(s.state))
            .collect::<Vec<_>>()
            .join(" ");
        let anchored = r.cursor < report.anchored_entries && report.verdict != Verdict::Failed;
        let cells = [
            verdict.to_string(),
            if anchored { "yes" } else { "no" }.to_string(),
            r.cursor.to_string(),
            r.at.to_string(),
            if r.at == 0 {
                String::new()
            } else {
                pragmatic::evidence::time::rfc3339_nanos(r.at)
            },
            text::branch_label(&r.branch),
            r.kind.clone(),
            r.fields.canonical_string(),
            states,
            slots_text(r, 32_000),
            hex_encode(&r.hash),
        ];
        let row: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// One quoted CSV cell, cut and defused.
fn csv_cell(value: &str) -> String {
    let (cut, _) = crate::slots::truncate(value, 32_000 * 4);
    let mut cell: String = cut.chars().take(32_000).collect();
    if cell.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        cell.insert(0, '\'');
    }
    format!("\"{}\"", cell.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_flags_are_set_as_data() {
        assert_eq!(
            when("2026-10-14T04:01:30Z"),
            "14\u{a0}Oct\u{a0}2026, <span class=\"m nw\">04:01:30</span>\u{a0}UTC"
        );
        assert_eq!(when("<x>"), "<span class=\"m nw\">&lt;x&gt;</span>");
        assert_eq!(
            flags_in_mono("pin a key (pass --log-key). <b>"),
            "pin a key (pass <span class=\"m\">--log-key</span>). &lt;b&gt;"
        );
        assert_eq!(flags_in_mono("-- --"), "-- --");
    }

    #[test]
    fn csv_cells_are_quoted_and_defused() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1"), "\"'-1\"");
        assert_eq!(csv_cell(&"x".repeat(40_000)).len(), 32_002);
    }
}
