//! The run index: one row per run, in a table on a leaf.

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::time::now_rfc3339;
use pragmatic::journal::{Event, Journal};
use pragmatic::json::Json;
use pragmatic::sha256::Digest;
use pragmatic::VerifyReport;

use crate::html::{diamond, document, empty, esc, masthead, mono, source_note, Crumb, Frame, Page};
use crate::rows::quote;
use crate::{gist, text};

/// One run in the index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRow {
    pub run_id: String,
    /// Where the run's page is, if it has one.
    pub href: Option<String>,
    /// Why the run could not be read, if it could not; the other fields
    /// are then empty.
    pub error: Option<String>,
    pub format: u32,
    pub entries: u64,
    pub draws: usize,
    pub attempts: usize,
    /// The outcome of the last `attempt.end` (`ok`, `fault`, `error`).
    pub last_outcome: Option<String>,
    /// The last attempt has no end (running, or crashed).
    pub open_attempt: bool,
    pub verified: bool,
    pub open_intents: usize,
    pub torn_bytes: u64,
    /// The latest `at`, Unix nanoseconds.
    pub last_at: Option<u64>,
    pub head: Option<Digest>,
}

impl RunRow {
    /// The row of a readable run.
    pub fn from_journal(run_id: &str, j: &Journal, report: &VerifyReport) -> RunRow {
        let mut last_outcome = None;
        let mut open_attempt = false;
        for e in j.entries().iter().rev() {
            match &e.event {
                Event::Note { kind, data, .. } if kind == "attempt.end" => {
                    last_outcome = Json::parse(data)
                        .ok()
                        .and_then(|d| d.get("outcome").and_then(Json::as_str).map(str::to_string));
                    break;
                }
                Event::Note { kind, .. } if kind == "attempt.start" => {
                    open_attempt = true;
                    break;
                }
                _ => {}
            }
        }
        RunRow {
            run_id: run_id.to_string(),
            href: None,
            error: None,
            format: j.format(),
            entries: j.len(),
            draws: text::draws(j),
            attempts: text::attempts(j),
            last_outcome,
            open_attempt,
            verified: report.is_ok(),
            open_intents: text::open_intents(j).len(),
            torn_bytes: report.torn_bytes,
            last_at: j.entries().iter().map(|e| e.at).filter(|&a| a > 0).max(),
            head: Some(j.head()),
        }
    }

    /// The row of a run that could not be read.
    pub fn unreadable(run_id: &str, error: &str) -> RunRow {
        RunRow {
            run_id: run_id.to_string(),
            href: None,
            error: Some(error.to_string()),
            format: 0,
            entries: 0,
            draws: 0,
            attempts: 0,
            last_outcome: None,
            open_attempt: false,
            verified: false,
            open_intents: 0,
            torn_bytes: 0,
            last_at: None,
            head: None,
        }
    }

    /// The same row, linked.
    pub fn linked(mut self, href: &str) -> RunRow {
        self.href = Some(href.to_string());
        self
    }
}

/// The index page of runs, as a single file.
pub fn render_index(rows: &[RunRow]) -> String {
    render_index_of(rows, None, None)
}

/// The index page, naming where the runs live (`source`), in `frame`
/// (`pragmatic serve`'s), or as a single file without one.
pub fn render_index_of(rows: &[RunRow], source: Option<&str>, frame: Option<&Frame<'_>>) -> String {
    let readable: Vec<&RunRow> = rows.iter().filter(|r| r.error.is_none()).collect();
    let verified = readable.iter().filter(|r| r.verified).count();
    let entries: u64 = readable.iter().map(|r| r.entries).sum();
    let open: usize = readable.iter().map(|r| r.open_intents).sum();
    let n = |x: String| format!("<span class=\"n\">{x}</span>");
    let mut facts = format!(
        "{} {} \u{b7} {} journal {} \u{b7} {} of {} chains verified",
        n(text::count(rows.len() as u64)),
        if rows.len() == 1 { "run" } else { "runs" },
        n(text::count(entries)),
        if entries == 1 { "entry" } else { "entries" },
        n(text::count(verified as u64)),
        n(text::count(rows.len() as u64)),
    );
    if open > 0 {
        facts.push_str(&format!(
            " \u{b7} <span class=\"alarm\">{} open {}</span>",
            n(text::count(open as u64)),
            if open == 1 { "call" } else { "calls" }
        ));
    }
    if let Some(s) = source {
        facts.push_str(&format!(" \u{b7} in {}", mono(s)));
    }
    let table = if rows.is_empty() {
        let dir = source.map(mono).unwrap_or_else(|| "this directory".into());
        empty(&format!(
            "No runs in {dir} yet. Point an agent's runtime here, for example \
             <span class=\"m\">pragmatic.Runtime(\"journals\")</span>, and runs appear as they \
             record. Refresh to follow."
        ))
    } else {
        let this_year = now_rfc3339();
        let this_year = this_year.get(..4).unwrap_or("");
        let body: String = rows.iter().map(|r| index_row(r, this_year)).collect();
        format!(
            "<div class=\"tscroll\"><table class=\"stack\"><caption class=\"sr-only\">Runs</caption>\
             <thead><tr><th class=\"caps\"><span class=\"sr-only\">State</span></th>\
             <th class=\"caps\" scope=\"col\">Run</th><th class=\"caps\" scope=\"col\">Last outcome</th>\
             <th class=\"caps\" scope=\"col\">Chain</th><th class=\"caps r\" scope=\"col\">Entries</th>\
             <th class=\"caps r\" scope=\"col\">Model calls</th><th class=\"caps r\" scope=\"col\">Attempts</th>\
             <th class=\"caps\" scope=\"col\">Open calls</th><th class=\"caps\" scope=\"col\">Last activity (UTC)</th>\
             <th class=\"caps\" scope=\"col\">Head</th></tr></thead><tbody>{body}</tbody></table></div>"
        )
    };
    let main = format!(
        "<div class=\"page-h\"><h1 class=\"title\">Runs</h1><p class=\"facts\">{facts}</p></div>\
         <section class=\"tsheet\" aria-label=\"Runs\">{table}</section>"
    );
    let nav = source_note(source.unwrap_or(""), true);
    let file = Frame {
        nav: &nav,
        ..Frame::FILE
    };
    let frame = frame.unwrap_or(&file);
    let mast = masthead(frame.home, &[Crumb::word("Runs", None)], frame.nav);
    document(
        frame,
        &Page {
            title: "Runs",
            masthead: mast,
            main,
            skip: Some(("main", "Skip to content")),
            ..Page::default()
        },
    )
}

fn index_row(r: &RunRow, this_year: &str) -> String {
    let name = match &r.href {
        Some(h) => format!(
            "<a class=\"m\" href=\"{}\">{}</a>",
            esc(h),
            esc(&text::clip(&r.run_id, 80))
        ),
        None => mono(&text::clip(&r.run_id, 80)),
    };
    if let Some(e) = &r.error {
        return format!(
            "<tr><td class=\"mk\">{}</td><td class=\"head m\">{name}</td>\
             <td colspan=\"8\"><span class=\"alarm\">Unreadable</span> \
             <span class=\"s\">\u{b7}</span> {}</td></tr>",
            diamond(true, true),
            quote(&gist::excerpt(e, 120))
        );
    }
    let failed = matches!(r.last_outcome.as_deref(), Some(o) if o != "ok");
    let mark = if !r.verified || (failed && !r.open_attempt) {
        diamond(true, true)
    } else if r.open_intents > 0 {
        diamond(false, true)
    } else if r.last_outcome.as_deref() == Some("ok") && !r.open_attempt {
        diamond(true, false)
    } else {
        diamond(false, false)
    };
    let outcome = match r.last_outcome.as_deref() {
        _ if r.open_attempt => "<span class=\"s\">no end yet</span>".to_string(),
        Some("ok") => "ok".to_string(),
        Some(o) => format!("<span class=\"alarm\">{}</span>", esc(&text::clip(o, 16))),
        None => "<span class=\"s dim\">none</span>".to_string(),
    };
    let chain = if r.verified {
        "Verified".to_string()
    } else {
        "<span class=\"alarm\">Broken</span>".to_string()
    };
    let open = if r.open_intents > 0 {
        format!(
            "<span class=\"alarm\">{} open</span>",
            text::count(r.open_intents as u64)
        )
    } else {
        "<span class=\"s dim\">settled</span>".to_string()
    };
    let torn = if r.torn_bytes > 0 {
        format!(
            "<span class=\"note\">{} torn bytes ignored</span>",
            text::count(r.torn_bytes)
        )
    } else {
        String::new()
    };
    let head = r
        .head
        .map(|h| hex_encode(&h)[..12].to_string())
        .unwrap_or_default();
    let last = r
        .last_at
        .map(|a| text::short_time(&text::time(a), this_year, false))
        .unwrap_or_default();
    format!(
        "<tr><td class=\"mk\">{mark}</td><td class=\"head m\">{name}{torn}</td>\
         <td data-label=\"Last outcome\">{outcome}</td><td data-label=\"Chain\">{chain}</td>\
         <td class=\"m r\" data-label=\"Entries\">{}</td><td class=\"m r\" data-label=\"Model calls\">{}</td>\
         <td class=\"m r\" data-label=\"Attempts\">{}</td><td data-label=\"Open calls\">{open}</td>\
         <td class=\"m nw\" data-label=\"Last activity\">{}</td>\
         <td class=\"m dim\" data-label=\"Head\">{head}</td></tr>",
        text::count(r.entries),
        text::count(r.draws as u64),
        text::count(r.attempts as u64),
        esc(&last),
    )
}
