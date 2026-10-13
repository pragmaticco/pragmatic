//! Evidence bundles for people: the verification report as a page, and the
//! records as CSV.
//!
//! The page leads with the verdict and what it means in the words the
//! design permits (a verified anchor proves a journal prefix existed by a
//! time; it proves nothing about whether the content was true), then the
//! step-by-step checks, every finding with its code, each anchor with its
//! witnesses and how far each can be trusted, and finally the run's
//! timeline decoded from the bundle's own journal. Every string from the
//! bundle is escaped: a bundle is adversarial input, and its text is never
//! presented as the verifier's own.

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::{
    state_name, AnchorReport, Bundle, CheckStatus, EvidenceReport, Record, Severity,
    SignatureStatus, Verdict, WitnessClass,
};
use pragmatic::journal::Journal;
use pragmatic::redact::binary;

use crate::html::{esc, masthead, page, pill};
use crate::run::timeline;
use crate::text;

/// The verification report and timeline of a bundle as a page.
pub fn render_evidence(bundle: &Bundle, report: &EvidenceReport) -> String {
    let mut body = masthead(
        None,
        &format!("evidence / {}", esc(&bundle.run_id)),
        &format!("generated {} (unsigned time)", esc(&bundle.generated_at)),
    );
    body.push_str(&verdict(report));
    body.push_str(&facts(bundle, report));
    body.push_str(
        "<p class=\"lede\">A verified anchor proves that a journal prefix of the stated length, \
         with the stated chain head, existed no later than the witness time. It does not prove \
         that the content was true when recorded, that nothing happened outside the journaled \
         interfaces, or anything about the run before its first anchor. Trust comes only from \
         the roots and keys the verifier pinned; nothing in the bundle is a trust anchor.</p>",
    );
    body.push_str(&checks(report));
    body.push_str(&findings(report));
    body.push_str(&anchors(report));
    body.push_str("<h2>timeline</h2>");
    match Journal::parse_evidence(&bundle.journal.bytes) {
        Ok(p) if p.tail_len == 0 => {
            let (rows, next) = timeline(&p.journal, 0, None, None);
            body.push_str(&rows);
            if next.is_some() {
                body.push_str(
                    "<p class=\"lede\">The CSV rendering of this bundle has a row for every \
                     entry.</p>",
                );
            }
        }
        _ => body.push_str(&records_table(&bundle.records)),
    }
    page(
        &format!("evidence {} \u{b7} pragmatic", esc(&bundle.run_id)),
        &body,
    )
}

fn verdict(r: &EvidenceReport) -> String {
    let min = r.min_operators.max(1);
    let time = |entries: u64| {
        r.anchors
            .iter()
            .filter(|a| a.independent && a.entries == entries)
            .filter_map(|a| a.earliest)
            .min()
            .map(|t| format!(" no later than {}", t.rfc3339()))
            .unwrap_or_default()
    };
    let (class, text) = match r.verdict {
        Verdict::Verified => (
            "",
            format!(
                "All {} entries are anchored: witnesses from at least {min} independent \
                 operator(s) the verifier trusts vouch that the journal up to its head existed{}.",
                r.entries,
                time(r.anchored_entries)
            ),
        ),
        Verdict::Partial { unanchored } => (
            "warn",
            format!(
                "The first {} of {} entries are independently anchored{}; the last {unanchored} \
                 are not anchored by at least {min} trusted operator(s).",
                r.anchored_entries,
                r.entries,
                time(r.anchored_entries)
            ),
        ),
        Verdict::Unanchored => (
            "warn",
            format!(
                "The journal's integrity checks pass, but no anchor is witnessed by at least \
                 {min} independent operator(s) the verifier trusts, so nothing ties it to a time."
            ),
        ),
        Verdict::Failed => (
            "bad",
            "An integrity check failed, or an audit the verifier was asked for could not be \
             completed: the bundle cannot be relied on as it stands. The failures are listed \
             below."
                .to_string(),
        ),
    };
    format!(
        "<div class=\"verdict {class}\"><div class=\"v\">{} \u{b7} exit {}</div><p>{}</p></div>",
        r.verdict.label(),
        r.exit_code(),
        esc(&text)
    )
}

fn facts(b: &Bundle, r: &EvidenceReport) -> String {
    let sig = match &r.bundle_signature {
        SignatureStatus::Verified { key } => format!("signature <b>verified</b> ({})", esc(key)),
        SignatureStatus::OperatorAsserted => "signature <b>operator-asserted</b>".to_string(),
        SignatureStatus::Unsigned => "<b>unsigned</b>".to_string(),
        SignatureStatus::Invalid => "<span class=\"alarm\">signature INVALID</span>".to_string(),
    };
    // Only the bundle signature covers these fields; unless a pinned key
    // verified it, they are whatever the file says.
    let claim = if matches!(r.bundle_signature, SignatureStatus::Verified { .. }) {
        "signed"
    } else {
        "unsigned claim"
    };
    let f = [
        format!("run <b>{}</b>", esc(&b.run_id)),
        format!("<b>{}</b> entries", r.entries),
        format!("<b>{}</b> anchor(s)", b.anchors.len()),
        format!(
            "redaction <b>{}</b>, <b>{}</b> slot(s) withheld",
            esc(&b.redaction.mode),
            b.redacted_slots.len()
        ),
        sig,
        format!("by <b>{}</b> ({claim})", esc(&text::clip(&b.generator, 64))),
        format!(
            "for <b>{}</b> ({claim})",
            esc(&text::clip(&b.requested_by, 64))
        ),
    ];
    let items: String = f.iter().map(|x| format!("<div>{x}</div>")).collect();
    format!("<div class=\"facts\">{items}</div>")
}

fn checks(r: &EvidenceReport) -> String {
    let mut out = String::from(
        "<h2>checks</h2><div class=\"scroll\"><table><tr><th>step</th><th>check</th>\
         <th>result</th><th>detail</th></tr>",
    );
    for c in &r.checks {
        let status = match c.status {
            CheckStatus::Pass => pill("ok", "pass"),
            CheckStatus::Fail => pill("bad", "fail"),
            CheckStatus::Skipped => pill("", "skipped"),
            CheckStatus::Info => pill("", "info"),
        };
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{status}</td><td>{}</td></tr>",
            c.step,
            esc(c.name),
            esc(&text::sanitize(&c.detail))
        ));
    }
    out.push_str("</table></div>");
    out
}

fn findings(r: &EvidenceReport) -> String {
    if r.findings.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "<h2>findings</h2><div class=\"scroll\"><table><tr><th>code</th><th>severity</th>\
         <th>finding</th></tr>",
    );
    let mut sorted: Vec<_> = r.findings.iter().collect();
    sorted.sort_by_key(|f| f.severity());
    for f in sorted {
        let sev = match f.severity() {
            Severity::Failure => pill("bad", "failure"),
            Severity::Warning => pill("warn", "warning"),
            Severity::Info => pill("", "info"),
        };
        out.push_str(&format!(
            "<tr><td>{}</td><td>{sev}</td><td>{}</td></tr>",
            f.code.as_str(),
            esc(&text::sanitize(&f.message))
        ));
    }
    out.push_str("</table></div>");
    out
}

fn anchors(r: &EvidenceReport) -> String {
    if r.anchors.is_empty() {
        return "<h2>anchors</h2><p class=\"lede\">No anchors: nothing ties this journal to a \
                time. Bundles from a local journal are always unanchored in 0.6.</p>"
            .to_string();
    }
    let mut out = String::from("<h2>anchors</h2>");
    for a in &r.anchors {
        out.push_str(&anchor(a));
    }
    out
}

fn anchor(a: &AnchorReport) -> String {
    let status = if !a.sound {
        pill("bad", "fails its checks")
    } else if a.independent {
        pill("ok", "independent")
    } else {
        pill("warn", "not enough trusted operators")
    };
    let ops = if a.trusted_operators.is_empty() {
        "none".to_string()
    } else {
        a.trusted_operators
            .iter()
            .map(|o| esc(o))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let time = a
        .earliest
        .map(|t| format!(", no later than <b>{}</b>", t.rfc3339()))
        .unwrap_or_default();
    let mut out = format!(
        "<p class=\"lede\">{status} anchor <b>{}</b>: <b>{}</b> entries, leaf {} of a tree of {}; \
         trusted operators: <b>{ops}</b>{time}</p>",
        a.seq, a.entries, a.leaf_index, a.tree_size
    );
    out.push_str(
        "<div class=\"scroll\"><table><tr><th>witness</th><th>name</th><th>class</th>\
         <th>operator</th><th>signed time</th><th>detail</th></tr>",
    );
    for w in &a.witnesses {
        let class = match w.class {
            WitnessClass::Trusted => pill("ok", w.class.as_str()),
            WitnessClass::SelfAsserted => pill("warn", w.class.as_str()),
            WitnessClass::OperatorControlled => pill("", w.class.as_str()),
        };
        let operator = match (&w.operator, &w.claimed_operator) {
            (Some(o), _) => esc(o),
            (None, Some(c)) => format!(
                "<span class=\"faint\">claims {}</span>",
                esc(&text::clip(c, 48))
            ),
            (None, None) => String::new(),
        };
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{class}</td><td>{operator}</td><td>{}</td><td>{}</td></tr>",
            w.kind,
            esc(&text::clip(&w.label, 64)),
            w.time.map(|t| t.rfc3339()).unwrap_or_default(),
            esc(&text::sanitize(&w.detail))
        ));
    }
    out.push_str("</table></div>");
    out
}

/// The records as a table, for a bundle whose journal does not parse.
fn records_table(records: &[Record]) -> String {
    let mut out = String::from(
        "<p class=\"lede\">The bundle's journal does not parse, so these are its records as \
         stated, which nothing vouches for.</p><div class=\"scroll\"><table><tr><th>cur</th>\
         <th>branch</th><th>kind</th><th>fields</th><th>slots</th></tr>",
    );
    for r in records.iter().take(10_000) {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            r.cursor,
            esc(&text::branch_label(&r.branch)),
            esc(&text::clip(&r.kind, 32)),
            esc(&text::clip(&r.fields.to_string(), 200)),
            esc(&slots_text(r, 200))
        ));
    }
    out.push_str("</table></div>");
    out
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
    fn csv_cells_are_quoted_and_defused() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1"), "\"'-1\"");
        assert_eq!(csv_cell(&"x".repeat(40_000)).len(), 32_002);
    }
}
