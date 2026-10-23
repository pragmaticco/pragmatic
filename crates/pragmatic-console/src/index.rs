//! The run index: one row per run, on a leaf, in the timeline's language.

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::time::now_rfc3339;
use pragmatic::journal::{Event, Journal};
use pragmatic::json::Json;
use pragmatic::sha256::Digest;
use pragmatic::VerifyReport;

use crate::html::{
    diamond, dir_name, document, empty, esc, masthead, mono, tag, Crumb, Frame, Page,
};
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
/// (`pragmatic serve`'s), or as a single file without one. Each run is a
/// row in the language of the run page's timeline: its state diamond, its
/// id and verification, a sentence of its state, and its last time and
/// head.
pub fn render_index_of(rows: &[RunRow], source: Option<&str>, frame: Option<&Frame<'_>>) -> String {
    let readable: Vec<&RunRow> = rows.iter().filter(|r| r.error.is_none()).collect();
    let verified = readable.iter().filter(|r| r.verified).count();
    let entries: u64 = readable.iter().map(|r| r.entries).sum();
    let n = |x: String| format!("<span class=\"n\">{x}</span>");
    let mut facts = vec![format!(
        "{} {}",
        n(text::count(rows.len() as u64)),
        if rows.len() == 1 { "run" } else { "runs" }
    )];
    if !rows.is_empty() {
        facts.push(format!(
            "{} {}",
            n(text::count(entries)),
            if entries == 1 { "entry" } else { "entries" }
        ));
        facts.push(if verified == rows.len() {
            match rows.len() {
                1 => "its chain verified".to_string(),
                2 => "both chains verified".to_string(),
                k => format!("all {} chains verified", n(text::count(k as u64))),
            }
        } else {
            format!(
                "<span class=\"alarm\">{} of {} chains verified</span>",
                n(text::count(verified as u64)),
                n(text::count(rows.len() as u64))
            )
        });
    }
    let body = if rows.is_empty() {
        let (dir, example) = match source {
            Some(s) => (
                mono(s),
                format!(
                    " Point an agent's runtime at it, for example \
                     <span class=\"m\">pragmatic.Runtime({})</span>, and runs appear here as \
                     they record.",
                    esc(&pragmatic::json::Json::String(s.to_string()).to_string())
                ),
            ),
            None => ("this directory".to_string(), String::new()),
        };
        empty(&format!("No runs in {dir} yet.{example}"))
    } else {
        let this_year = now_rfc3339();
        let this_year = this_year.get(..4).unwrap_or("");
        let list: String = rows.iter().map(|r| index_row(r, this_year)).collect();
        format!(
            "<p class=\"cols caps\" aria-hidden=\"true\"><span>Run</span>\
             <span class=\"c-time\">Last entry (UTC) \u{b7} head</span>\
             <span class=\"c-hash\">Last entry (UTC)</span></p><ol class=\"rl\">{list}</ol>"
        )
    };
    let facts = if rows.is_empty() {
        String::new()
    } else {
        format!("<p class=\"facts\">{}</p>", facts.join(" \u{b7} "))
    };
    let main = format!(
        "<div class=\"page-h\"><h1 class=\"title\">Runs</h1>{facts}</div>\
         <section class=\"tsheet runs\" aria-label=\"Runs\">{body}</section>"
    );
    let frame = frame.unwrap_or(&Frame::FILE);
    let crumbs: Vec<Crumb<'_>> = source
        .and_then(dir_name)
        .map(|d| Crumb::word(d, None))
        .into_iter()
        .collect();
    let mast = masthead(frame.home, &crumbs, frame.nav);
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

/// One run in the list.
fn index_row(r: &RunRow, this_year: &str) -> String {
    let id = format!(
        "<span class=\"rid\">{}</span>",
        esc(&text::clip(&r.run_id, 80))
    );
    let wrap = |mark: &str, inner: String| match &r.href {
        Some(h) => format!(
            "<li class=\"rr {mark}\"><a class=\"rr-a\" href=\"{}\">{inner}</a></li>",
            esc(h)
        ),
        None => format!("<li class=\"rr {mark}\"><div class=\"rr-a\">{inner}</div></li>"),
    };
    if let Some(e) = &r.error {
        return wrap(
            "mk-alarm",
            format!(
                "<span class=\"rr-t\">{id}<span class=\"badge alarm\">Unreadable</span></span>\
                 <span class=\"rr-s\">{}</span>",
                quote(&gist::excerpt(e, 120))
            ),
        );
    }
    let failed = matches!(r.last_outcome.as_deref(), Some(o) if o != "ok");
    let (state, mark) = if r.format == 1 {
        ("Format 1, from Stet 0.4 or 0.5".to_string(), "mk-fill")
    } else if r.open_attempt {
        ("Open".to_string(), "mk-hollow")
    } else {
        match r.last_outcome.as_deref() {
            Some("ok") => ("Ended ok".to_string(), "mk-fill"),
            Some("fault") => (
                "<span class=\"alarm\">Ended with a fault</span>".to_string(),
                "mk-alarm-big",
            ),
            Some(o) => (format!("Ended {}", mono(&text::clip(o, 16))), "mk-fill"),
            None => ("No attempts".to_string(), "mk-hollow"),
        }
    };
    let mark = if !r.verified {
        "mk-alarm"
    } else if r.open_intents > 0 && !r.open_attempt {
        "mk-alarm-hollow"
    } else if failed && mark == "mk-fill" {
        "mk-alarm"
    } else {
        mark
    };
    let mut sentence = vec![state];
    let count = |k: usize, one: &str, many: &str| {
        format!(
            "{} {}",
            text::count(k as u64),
            if k == 1 { one } else { many }
        )
    };
    if r.format == 2 {
        sentence.push(count(r.attempts, "attempt", "attempts"));
    }
    sentence.push(count(r.draws, "model call", "model calls"));
    sentence.push(count(r.entries as usize, "entry", "entries"));
    if r.open_intents > 0 && !r.open_attempt {
        sentence.push(format!(
            "<span class=\"alarm\">{}</span>",
            count(r.open_intents, "interrupted call", "interrupted calls")
        ));
    }
    if r.torn_bytes > 0 {
        sentence.push(format!(
            "{} ignored",
            count(r.torn_bytes as usize, "torn byte", "torn bytes")
        ));
    }
    let badge = if r.verified {
        format!(
            "<span class=\"badge\">{}Verified</span>",
            diamond(true, false)
        )
    } else {
        format!(
            "<span class=\"badge alarm\">{}Chain broken</span>",
            diamond(false, true)
        )
    };
    let read_only = if r.format == 1 {
        tag("Read-only")
    } else {
        String::new()
    };
    let head = r
        .head
        .map(|h| hex_encode(&h)[..12].to_string())
        .unwrap_or_default();
    let last = r
        .last_at
        .map(|a| text::short_time(&text::time(a), this_year, true))
        .unwrap_or_default();
    wrap(
        mark,
        format!(
            "<span class=\"rr-t\">{id}{badge}{read_only}</span><span class=\"rr-tm\">{}</span>\
             <span class=\"rr-s\">{}</span><span class=\"rr-h\">{head}</span>",
            esc(&last),
            sentence.join(" \u{b7} ")
        ),
    )
}
