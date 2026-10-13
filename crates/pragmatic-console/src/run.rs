//! One run's page: facts, attempts, the timeline and the verification
//! report.
//!
//! The timeline lists every entry in cursor order (the journal's only
//! order; `at` times come from the appending process and are shown, never
//! trusted for ordering). Each row sits in a lane for its branch, drawn as
//! one rail per level of nesting, so a parallel region's children read as
//! nested lanes under the fork that made them, and notes sit in the meta
//! lane. Intents carry the status of their latest result and link to it;
//! results link back. Expanding a row shows its fields, metadata and every
//! slot.
//!
//! A run can hold millions of entries and gigabytes of content, so the
//! timeline is shown a page at a time: a page ends after [`PAGE_ENTRIES`]
//! entries, or before the entry that would take its rows past
//! [`PAGE_BYTES`] of HTML, whichever comes first, and links to the next.
//! Every entry is on some page, and every page is bounded whatever the
//! journal holds (only one entry larger than the budget makes a page
//! larger, and an entry is bounded too: at most 255 slots of at most
//! 64 KiB shown each).

use std::collections::HashMap;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{
    Content, Cursor, EffectOutcome, Entry, Event, Journal, LegacyEvent, META,
};
use pragmatic::json::Json;
use pragmatic::VerifyReport;

use crate::html::{block, esc, masthead, page, pill, pre, pretty_json};
use crate::slots::{slot_html, value_html};
use crate::text;

/// The most timeline entries one page shows.
pub const PAGE_ENTRIES: usize = 5_000;

/// The most bytes of timeline HTML one page holds. The page ends before the
/// entry whose row would pass it, unless that entry is the page's first.
pub const PAGE_BYTES: usize = 16 << 20;

/// What a page needs to show one run.
#[derive(Clone, Copy, Debug)]
pub struct RunView<'a> {
    pub run_id: &'a str,
    pub journal: &'a Journal,
    /// The journal's verification report (`Journal::audit`, or a
    /// backend's `verify`, which reads past corruption).
    pub report: &'a VerifyReport,
    /// Anchoring status, when the page is served by something that knows
    /// it (Pragmatic Server).
    pub anchor: Option<&'a AnchorStatus>,
    /// Where the run lives (a directory, a server), for the masthead.
    pub source: Option<&'a str>,
    /// The run index to link back to, for a live console.
    pub home: Option<&'a str>,
    /// The cursor the timeline page starts at (0 for the first page).
    pub from: Cursor,
    /// How to link to another page of the timeline: a URL to which a
    /// page's first cursor is appended, such as `/run/r1?from=`. Without
    /// one (an exported file), the page says where the next one starts.
    pub page_link: Option<&'a str>,
}

impl<'a> RunView<'a> {
    pub fn new(run_id: &'a str, journal: &'a Journal, report: &'a VerifyReport) -> Self {
        RunView {
            run_id,
            journal,
            report,
            anchor: None,
            source: None,
            home: None,
            from: 0,
            page_link: None,
        }
    }
}

/// One page of a run, and where the next one starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPage {
    pub html: String,
    /// The first cursor of the next page, `None` on the last page.
    pub next: Option<Cursor>,
}

/// A run's anchoring as the server knows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorStatus {
    /// The longest anchored prefix.
    pub anchored_entries: u64,
    /// True when that anchor is witnessed by enough independent operators;
    /// false when only the operator's own signature vouches for it.
    pub independent: bool,
    /// The operators that witnessed it.
    pub operators: Vec<String>,
    /// The witness time, from a signed structure, as RFC 3339.
    pub time: Option<String>,
}

/// The page for one run: its facts, attempts and verification, and the
/// page of the timeline that starts at `view.from`.
pub fn render_run(view: &RunView<'_>) -> String {
    render_run_page(view).html
}

/// [`render_run`], also saying where the next page of the timeline starts.
pub fn render_run_page(view: &RunView<'_>) -> RunPage {
    let j = view.journal;
    let mut body = String::new();
    let right = view.source.map(esc).unwrap_or_default();
    body.push_str(&masthead(
        view.home,
        &format!("runs / {}", esc(view.run_id)),
        &right,
    ));
    body.push_str(&facts(view));
    body.push_str(&alarms(view));
    if let Some(a) = view.anchor {
        body.push_str(&anchor_block(a, j.len()));
    }
    if j.format() == 2 {
        body.push_str(&attempts_table(j));
    } else {
        body.push_str(
            "<p class=\"lede\">A format 1 journal (Pragmatic 0.4 or 0.5): read-only in 0.6. \
             It can be verified and exported, not run, resumed or replayed.</p>",
        );
    }
    body.push_str("<h2>timeline</h2>");
    let (rows, next) = timeline(j, view.from, view.page_link);
    body.push_str(&rows);
    body.push_str(&verification(view.report, j));
    RunPage {
        html: page(&format!("{} \u{b7} pragmatic", esc(view.run_id)), &body),
        next,
    }
}

/// Totals over a journal, for the facts line.
#[derive(Default)]
struct Totals {
    draws: usize,
    input_tokens: u64,
    output_tokens: u64,
    effects_ok: usize,
    effects_failed: usize,
    effects_compensated: usize,
    erased: usize,
    withheld: usize,
    first_at: Option<u64>,
    last_at: Option<u64>,
}

fn totals(j: &Journal) -> Totals {
    let mut t = Totals {
        draws: text::draws(j),
        ..Totals::default()
    };
    for e in j.entries() {
        if e.at > 0 {
            t.first_at = Some(t.first_at.map_or(e.at, |f| f.min(e.at)));
            t.last_at = Some(t.last_at.map_or(e.at, |l| l.max(e.at)));
        }
        for c in e.event.slot_contents() {
            match c {
                Content::Erased => t.erased += 1,
                Content::Withheld => t.withheld += 1,
                Content::Sealed(_) => {}
            }
        }
        match &e.event {
            Event::DrawResult { meta, .. } => {
                let m = text::draw_meta(meta);
                t.input_tokens += m.input_tokens.unwrap_or(0);
                t.output_tokens += m.output_tokens.unwrap_or(0);
            }
            Event::EffectResult { outcome, .. } => match outcome {
                EffectOutcome::Ok => t.effects_ok += 1,
                EffectOutcome::Failed => t.effects_failed += 1,
                EffectOutcome::Compensated => t.effects_compensated += 1,
            },
            // Format 1 records commits and write-offs, not failures.
            Event::Legacy(LegacyEvent::EffectCommit { .. }) => t.effects_ok += 1,
            Event::Legacy(LegacyEvent::EffectCompensated { .. }) => t.effects_compensated += 1,
            _ => {}
        }
    }
    t
}

fn facts(view: &RunView<'_>) -> String {
    let j = view.journal;
    let t = totals(j);
    let head = hex_encode(&j.head());
    let chain = if view.report.is_ok() {
        "chain <b>verified</b>".to_string()
    } else {
        "<span class=\"alarm\">chain BROKEN</span>".to_string()
    };
    let mut f = vec![
        format!("run <b>{}</b>", esc(view.run_id)),
        format!("format <b>{}</b>", j.format()),
        format!("<b>{}</b> entries", j.len()),
    ];
    if j.format() == 2 {
        f.push(format!("<b>{}</b> attempt(s)", text::attempts(j)));
    }
    if j.format() == 2 {
        f.push(format!(
            "<b>{}</b> model calls ({} in / {} out tokens)",
            t.draws, t.input_tokens, t.output_tokens
        ));
        f.push(format!(
            "effects <b>{}</b> ok, <b>{}</b> failed, <b>{}</b> written off",
            t.effects_ok, t.effects_failed, t.effects_compensated
        ));
    } else {
        // Format 1 records no token usage and no failed effects.
        f.push(format!("<b>{}</b> model calls", t.draws));
        f.push(format!(
            "effects <b>{}</b> ok, <b>{}</b> written off (format 1 records no failures)",
            t.effects_ok, t.effects_compensated
        ));
    }
    if t.erased + t.withheld > 0 {
        f.push(format!(
            "<b>{}</b> erased, <b>{}</b> withheld slot(s)",
            t.erased, t.withheld
        ));
    }
    f.push(chain);
    if let (Some(a), Some(b)) = (t.first_at, t.last_at) {
        f.push(format!(
            "<b>{}</b> to <b>{}</b>",
            esc(&text::time(a)),
            esc(&text::time(b))
        ));
    }
    f.push(format!("head <b title=\"{head}\">{}</b>", &head[..16]));
    let items: String = f.iter().map(|x| format!("<div>{x}</div>")).collect();
    format!("<div class=\"facts\">{items}</div>")
}

fn alarms(view: &RunView<'_>) -> String {
    let mut out = String::new();
    for p in text::verify_problems(view.report) {
        out.push_str(&format!(
            "<div><span class=\"alarm\">{}</span></div>",
            esc(&p)
        ));
    }
    let open = text::open_intents(view.journal);
    if !open.is_empty() {
        out.push_str(&format!(
            "<div><span class=\"alarm\">{} open intent(s)</span> without a result, first at \
             <a href=\"#c{}\">#{}</a>: interrupted by a crash; a resume decides them</div>",
            open.len(),
            open[0],
            open[0]
        ));
    }
    if view.report.torn_bytes > 0 {
        out.push_str(&format!(
            "<div>{} bytes after the valid prefix were ignored (a torn tail left by a crash)</div>",
            view.report.torn_bytes
        ));
    }
    if out.is_empty() {
        out
    } else {
        format!("<div class=\"alarms\">{out}</div>")
    }
}

fn anchor_block(a: &AnchorStatus, entries: u64) -> String {
    let status = if a.anchored_entries == 0 {
        pill("warn", "unanchored")
    } else if a.independent {
        pill("ok", "independently anchored")
    } else {
        pill("warn", "operator-only anchor")
    };
    let ops = if a.operators.is_empty() {
        String::new()
    } else {
        format!(
            " by {}",
            a.operators
                .iter()
                .map(|o| esc(o))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let time = a
        .time
        .as_deref()
        .map(|t| format!(", no later than <b>{}</b>", esc(t)))
        .unwrap_or_default();
    format!(
        "<h2>anchoring</h2><p class=\"lede\">{status} <b>{}</b> of {entries} entries{ops}{time}. \
         An anchor proves the journal prefix existed by the witness time; it does not \
         prove the content was true, or anything outside the journaled interfaces.</p>",
        a.anchored_entries
    )
}

/// One attempt, from its notes.
struct AttemptRow {
    cursor: Cursor,
    at: u64,
    start: Json,
    end: Option<(Cursor, Json)>,
}

fn attempts_table(j: &Journal) -> String {
    let mut rows: Vec<AttemptRow> = Vec::new();
    // Attempt number to its latest row, so each end is matched in O(1):
    // a journal of many ends that name no started attempt (hostile or
    // broken) must not cost starts times ends.
    let mut latest: HashMap<u64, usize> = HashMap::new();
    for e in j.entries() {
        let Event::Note { kind, data, .. } = &e.event else {
            continue;
        };
        if kind != "attempt.start" && kind != "attempt.end" {
            continue;
        }
        let Ok(doc) = Json::parse(data) else { continue };
        let n = doc.get("attempt").and_then(Json::as_u64);
        if kind == "attempt.start" {
            if let Some(n) = n {
                latest.insert(n, rows.len());
            }
            rows.push(AttemptRow {
                cursor: e.cursor,
                at: e.at,
                start: doc,
                end: None,
            });
        } else if let Some(&i) = n.and_then(|n| latest.get(&n)) {
            rows[i].end = Some((e.cursor, doc));
        }
    }
    if rows.is_empty() {
        return String::new();
    }
    // Note data is untrusted: values are clipped here and escaped once,
    // where they are inserted.
    let s = |d: &Json, k: &str| match d.get(k) {
        Some(Json::String(v)) => text::clip(v, 48),
        Some(Json::Null) | None => String::new(),
        Some(v) => text::clip(&v.to_string(), 48),
    };
    let mut out = String::from(
        "<h2>attempts</h2><div class=\"scroll\"><table><tr><th>#</th><th>mode</th><th>started</th>\
         <th>host</th><th>principal</th><th>outcome</th><th class=\"r\">fresh</th>\
         <th class=\"r\">replayed</th></tr>",
    );
    for r in &rows {
        let (outcome, fresh, replayed) = match &r.end {
            Some((c, d)) => {
                let o = s(d, "outcome");
                let class = if o == "ok" { "ok" } else { "bad" };
                let fault = s(d, "fault_kind");
                let label = if fault.is_empty() {
                    o.clone()
                } else {
                    format!("{o}: {fault}")
                };
                (
                    format!("<a href=\"#c{c}\">{}</a>", pill(class, &label)),
                    s(d, "fresh"),
                    s(d, "replayed"),
                )
            }
            None => (
                pill("warn", "no end: crashed or running"),
                String::new(),
                String::new(),
            ),
        };
        out.push_str(&format!(
            "<tr><td><a href=\"#c{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{outcome}</td><td class=\"r\">{}</td><td class=\"r\">{}</td></tr>",
            r.cursor,
            esc(&s(&r.start, "attempt")),
            esc(&s(&r.start, "mode")),
            esc(&text::time(r.at)),
            esc(&s(&r.start, "host")),
            esc(&s(&r.start, "principal")),
            esc(&fresh),
            esc(&replayed),
        ));
    }
    out.push_str("</table></div>");
    out
}

/// One page of the timeline, as nested lanes, from cursor `from`, and the
/// cursor the next page starts at (see the module documentation).
pub(crate) fn timeline(j: &Journal, from: Cursor, link: Option<&str>) -> (String, Option<Cursor>) {
    let results = text::results_by_intent(j);
    let mut out = String::new();
    let total = j.len();
    let from = from.min(total);
    if from > 0 {
        out.push_str(&format!(
            "<p class=\"lede\">Entries from #{from} of {total}. {}</p>",
            page_link(link, 0, "The timeline starts on the first page")
        ));
    }
    out.push_str(
        "<div class=\"cols\"><span>time (utc)</span><span>cur</span><span>lane</span>\
         <span>event</span><span>summary: click to expand</span><span style=\"text-align:right\">hash</span></div>",
    );
    let mut size = 0usize;
    let mut next = None;
    for (n, e) in j.entries()[from as usize..].iter().enumerate() {
        if n == PAGE_ENTRIES {
            next = Some(e.cursor);
            break;
        }
        let html = row(e, j, &results);
        if n > 0 && size + html.len() > PAGE_BYTES {
            next = Some(e.cursor);
            break;
        }
        size += html.len();
        out.push_str(&html);
    }
    if j.is_empty() {
        out.push_str("<div class=\"empty\">no entries</div>");
    }
    if let Some(c) = next {
        out.push_str(&format!(
            "<p class=\"lede\">This page ends before #{c}, to keep it a size a browser opens \
             quickly; {} entries remain. {}</p>",
            total - c,
            page_link(link, c, &format!("The next page starts at cursor {c}"))
        ));
    }
    (out, next)
}

/// A link to the page starting at `from`, or the plain `text` when there is
/// no way to link (an exported file).
fn page_link(link: Option<&str>, from: Cursor, text: &str) -> String {
    match link {
        Some(prefix) => format!("<a href=\"{}{from}\">{}</a>", esc(prefix), esc(text)),
        None => format!("{}.", esc(text)),
    }
}

fn lane(branch: &[u32]) -> String {
    if branch == META {
        return "meta".to_string();
    }
    let rails = "<i></i>".repeat(branch.len().min(12));
    format!("{rails}{}", esc(&text::branch_label(branch)))
}

/// The status of an intent: its latest result's outcome, or `open`.
fn intent_status(j: &Journal, latest: Option<Cursor>) -> (String, &'static str) {
    let Some(r) = latest.and_then(|c| j.get(c)) else {
        return ("open".into(), "warn");
    };
    match &r.event {
        Event::DrawResult { meta, .. } => {
            let o = text::draw_meta(meta).outcome;
            let class = match o.as_str() {
                "ok" => "ok",
                "partial" => "warn",
                _ => "bad",
            };
            (o, class)
        }
        Event::EffectResult { outcome, .. } => {
            let class = match outcome {
                EffectOutcome::Ok => "ok",
                EffectOutcome::Compensated => "warn",
                EffectOutcome::Failed => "bad",
            };
            (outcome.as_str().to_string(), class)
        }
        _ => ("?".into(), ""),
    }
}

/// One timeline row.
fn row(e: &Entry, j: &Journal, results: &HashMap<Cursor, Vec<Cursor>>) -> String {
    let hash = hex_encode(&e.hash);
    let is_meta = e.branch == META;
    let (quiet, explain, status) = describe(e, j, results);
    let at = if e.at == 0 {
        String::new()
    } else {
        text::time(e.at)
    };
    let short_time = at.get(11..23).unwrap_or("").to_string();
    let label = text::label(&e.event);
    format!(
        "<details class=\"ev{meta}\" id=\"c{cursor}\"><summary>\
         <span class=\"t\" title=\"{at}\">{short_time}</span>\
         <span class=\"cur\">#{cursor}</span>\
         <span class=\"lane\">{lane}</span>\
         <span class=\"evt{quiet}\">{label} {status}</span>\
         <span class=\"sum\">{summary}</span>\
         <span class=\"h\" title=\"{hash}\">{hash10}</span>\
         </summary><div class=\"detail\">{detail}</div></details>\n",
        meta = if is_meta { " meta" } else { "" },
        cursor = e.cursor,
        at = esc(&at),
        lane = lane(&e.branch),
        quiet = if quiet { " quiet" } else { "" },
        label = esc(&label),
        summary = esc(&text::summary(&e.event, 160)),
        hash10 = &hash[..10],
        detail = detail(e, explain, &at, &hash),
    )
}

/// Whether a row is quiet, its explanation (HTML) and its status pill.
fn describe(
    e: &Entry,
    j: &Journal,
    results: &HashMap<Cursor, Vec<Cursor>>,
) -> (bool, String, String) {
    let link = |c: Cursor| format!("<a href=\"#c{c}\">#{c}</a>");
    match &e.event {
        Event::DrawIntent { .. } | Event::EffectIntent { .. } => {
            let rs = results.get(&e.cursor).cloned().unwrap_or_default();
            let (status, class) = intent_status(j, rs.last().copied());
            let what = if matches!(e.event, Event::DrawIntent { .. }) {
                "model call intent, durable <b>before</b> the call was made"
            } else {
                "effect intent, durable <b>before</b> the effect ran; an intent without a \
                 result marks a crash inside the effect"
            };
            let res = if rs.is_empty() {
                "no result recorded".to_string()
            } else {
                format!(
                    "result(s): {}",
                    rs.iter().map(|&c| link(c)).collect::<Vec<_>>().join(", ")
                )
            };
            (true, format!("{what} \u{b7} {res}"), pill(class, &status))
        }
        Event::DrawResult { intent, meta, .. } => {
            let m = text::draw_meta(meta);
            let class = match m.outcome.as_str() {
                "ok" => "ok",
                "partial" => "warn",
                _ => "bad",
            };
            let what = match m.outcome.as_str() {
                "partial" => {
                    "a stream closed before it ended; replay serves these bytes and ends the stream"
                }
                "error" => {
                    "the call failed; replay raises the same error without calling the model"
                }
                _ => "replay serves this response without calling the model",
            };
            (
                false,
                format!("response to {} \u{b7} {what}", link(*intent)),
                pill(class, &m.outcome),
            )
        }
        Event::EffectResult {
            intent, outcome, ..
        } => {
            let (what, class) = match outcome {
                EffectOutcome::Ok => ("replay returns this result; the effect is not performed again", "ok"),
                EffectOutcome::Failed => ("replay fails the effect again with this message", "bad"),
                EffectOutcome::Compensated => (
                    "written off by recovery; the run performed the effect again under a new intent",
                    "warn",
                ),
            };
            (
                false,
                format!("result of {} \u{b7} {what}", link(*intent)),
                String::new() + &pill(class, outcome.as_str()),
            )
        }
        Event::Clock { .. } => (
            true,
            "journaled clock read: replay sees this time, not the current one".into(),
            String::new(),
        ),
        Event::Program { .. } => (
            true,
            "program identity: replay checks the running program against it".into(),
            String::new(),
        ),
        Event::Fork { .. } => (
            false,
            "parallel region: each child runs on its own branch (the nested lanes below)".into(),
            String::new(),
        ),
        Event::Marker { .. } => (
            true,
            "this run took a code patch; replay requires the same patch".into(),
            String::new(),
        ),
        Event::Note { kind, .. } => (
            true,
            format!(
                "note <b>{}</b> on the meta branch; replay never reads it",
                esc(kind)
            ),
            String::new(),
        ),
        Event::Random { .. } => (true, "journaled random draw".into(), String::new()),
        Event::Refusal { .. } => (
            false,
            "refused without touching the world; replay raises the same fault here".into(),
            pill("warn", "refused"),
        ),
        _ => (false, "format 1 entry (read-only)".into(), String::new()),
    }
}

fn kv(k: &str, v: &str) -> String {
    format!("<div class=\"kv\">{k} <b>{}</b></div>", esc(v))
}

/// The labels of an entry's slots.
fn slot_labels(event: &Event) -> Vec<String> {
    let n = event.slot_contents().len();
    match event {
        Event::DrawIntent { .. } => (0..n).map(|k| format!("request part {k}")).collect(),
        Event::DrawResult { .. } => vec!["response head".into(), "response body".into()],
        Event::ChannelRecv { .. } | Event::Random { .. } => vec!["value".into()],
        Event::EffectIntent { .. } => vec!["argument".into()],
        Event::EffectResult { outcome, .. } => vec![if *outcome == EffectOutcome::Failed {
            "failure message".into()
        } else {
            "result".into()
        }],
        Event::Note { kind, .. } => (0..n)
            .map(|k| match (kind.as_str(), k) {
                ("run.start", 0) => "subjects".into(),
                ("attempt.end", 0) => "output".into(),
                ("attempt.end", 1) => "fault or error message".into(),
                ("erasure", 0) => "reason".into(),
                _ => format!("payload {k}"),
            })
            .collect(),
        _ => (0..n).map(|k| format!("slot {k}")).collect(),
    }
}

fn detail(e: &Entry, explain: String, at: &str, hash: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("<div class=\"kv\">{explain}</div>"));
    match &e.event {
        Event::DrawResult { meta, .. } => {
            out.push_str(&block(
                "meta",
                &pre(&pretty_json(meta).unwrap_or_else(|| meta.clone())),
            ));
        }
        Event::Note { data, .. } => {
            out.push_str(&block(
                "data",
                &pre(&pretty_json(data).unwrap_or_else(|| data.clone())),
            ));
        }
        Event::Random { source, args, .. } => {
            out.push_str(&kv("source", source));
            out.push_str(&kv("args", args));
        }
        Event::Legacy(l) => out.push_str(&legacy_detail(l)),
        _ => {}
    }
    let labels = slot_labels(&e.event);
    for (k, (meta, content)) in e.slots.iter().zip(e.event.slot_contents()).enumerate() {
        let label = labels
            .get(k)
            .cloned()
            .unwrap_or_else(|| format!("slot {k}"));
        out.push_str(&slot_html(&label, meta, content));
    }
    out.push_str(&kv("branch", &text::branch_label(&e.branch)));
    if !at.is_empty() {
        out.push_str(&kv(
            "at (appending process clock, informational)",
            &pragmatic::evidence::time::rfc3339_nanos(e.at),
        ));
    }
    out.push_str(&kv("entry hash", hash));
    out
}

/// A format 1 entry in full: its structural fields as key and value, and
/// each recorded value (prompt, outcome, argument, result, received value)
/// in its own block, shown the way a format 2 slot is.
fn legacy_detail(l: &LegacyEvent) -> String {
    let value = |label: &str, v: &pragmatic::Value| value_html(label, v.as_bytes());
    match l {
        LegacyEvent::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => format!(
            "{}{}{}",
            kv("provenance", provenance),
            value("prompt", prompt),
            value("outcome", outcome)
        ),
        LegacyEvent::ChannelRecv { channel, value: v } => {
            format!("{}{}", kv("channel", channel), value("value", v))
        }
        LegacyEvent::EffectIntent { name, arg } => {
            format!("{}{}", kv("effect", name), value("argument", arg))
        }
        LegacyEvent::EffectCommit { name, result } => {
            format!("{}{}", kv("effect", name), value("result", result))
        }
        LegacyEvent::EffectCompensated { name } => kv("effect", name),
        LegacyEvent::Clock { nanos } => kv("nanos", &nanos.to_string()),
        LegacyEvent::Program { name, hash } => format!("{}{}", kv("name", name), kv("hash", hash)),
    }
}

fn verification(report: &VerifyReport, j: &Journal) -> String {
    let mut out = String::from("<h2>verification</h2>");
    let problems = text::verify_problems(report);
    if problems.is_empty() {
        out.push_str(&format!(
            "<p class=\"lede\">{} Every chain link, commitment and ref verifies, and every erased \
             slot is listed by a later erasure note ({} entries, head <b>{}</b>).</p>",
            pill("ok", "verified"),
            j.len(),
            hex_encode(&j.head())
        ));
    } else {
        out.push_str("<div class=\"alarms\">");
        for p in problems {
            out.push_str(&format!(
                "<div><span class=\"alarm\">{}</span></div>",
                esc(&p)
            ));
        }
        out.push_str("</div>");
    }
    if report.torn_bytes > 0 {
        out.push_str(&format!(
            "<p class=\"lede\">{} torn bytes after the valid prefix were ignored.</p>",
            report.torn_bytes
        ));
    }
    out
}
