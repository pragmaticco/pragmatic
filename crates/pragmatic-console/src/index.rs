//! The run index: one row per run.

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{Event, Journal};
use pragmatic::json::Json;
use pragmatic::sha256::Digest;
use pragmatic::VerifyReport;

use crate::html::{esc, masthead, page, pill};
use crate::text;

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
        let last_outcome = j.entries().iter().rev().find_map(|e| match &e.event {
            Event::Note { kind, data, .. } if kind == "attempt.end" => Json::parse(data)
                .ok()
                .and_then(|d| d.get("outcome").and_then(Json::as_str).map(str::to_string)),
            _ => None,
        });
        RunRow {
            run_id: run_id.to_string(),
            href: None,
            error: None,
            format: j.format(),
            entries: j.len(),
            draws: text::draws(j),
            attempts: text::attempts(j),
            last_outcome,
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

/// The index page of runs.
pub fn render_index(rows: &[RunRow]) -> String {
    render_index_of(rows, None, None)
}

/// The index page, naming where the runs live (`source`) and linking the
/// wordmark to `home`.
pub fn render_index_of(rows: &[RunRow], source: Option<&str>, home: Option<&str>) -> String {
    let readable: Vec<&RunRow> = rows.iter().filter(|r| r.error.is_none()).collect();
    let verified = readable.iter().filter(|r| r.verified).count();
    let entries: u64 = readable.iter().map(|r| r.entries).sum();
    let open: usize = readable.iter().map(|r| r.open_intents).sum();
    let mut facts = vec![
        format!("<b>{}</b> runs", rows.len()),
        format!("<b>{entries}</b> journal entries"),
        format!("chains <b>{verified}/{}</b> verified", rows.len()),
    ];
    if open > 0 {
        facts.push(format!(
            "<span class=\"alarm\">{open} open intent(s)</span>"
        ));
    }
    if let Some(s) = source {
        facts.push(format!("in <b>{}</b>", esc(s)));
    }
    let facts: String = facts.iter().map(|f| format!("<div>{f}</div>")).collect();
    let table = if rows.is_empty() {
        "<div class=\"empty\">no runs yet: point an agent's runtime here and runs appear as \
         they record</div>"
            .to_string()
    } else {
        let body: String = rows.iter().map(index_row).collect();
        format!(
            "<div class=\"scroll\"><table><tr><th>run</th><th class=\"r\">fmt</th>\
             <th class=\"r\">entries</th><th class=\"r\">calls</th><th class=\"r\">attempts</th>\
             <th>last outcome</th><th>chain</th><th>intents</th><th>last activity (utc)</th>\
             <th>head</th></tr>{body}</table></div>"
        )
    };
    let body = format!(
        "{}<div class=\"facts\">{facts}</div>{table}",
        masthead(home, "runs", "refresh to follow live runs")
    );
    page("runs \u{b7} pragmatic", &body)
}

fn index_row(r: &RunRow) -> String {
    let name = match &r.href {
        Some(h) => format!("<a href=\"{}\">{}</a>", esc(h), esc(&r.run_id)),
        None => esc(&r.run_id),
    };
    if let Some(e) = &r.error {
        return format!(
            "<tr class=\"run\"><td class=\"name\">{name}</td><td colspan=\"9\">{} {}</td></tr>",
            pill("bad", "unreadable"),
            esc(&text::clip(e, 200))
        );
    }
    let chain = if r.verified {
        pill("ok", "verified")
    } else {
        pill("bad", "broken")
    };
    let intents = if r.open_intents > 0 {
        pill("warn", &format!("{} open", r.open_intents))
    } else {
        "<span class=\"faint\">settled</span>".to_string()
    };
    let outcome = match r.last_outcome.as_deref() {
        Some("ok") => pill("ok", "ok"),
        Some(o) => pill("bad", &text::clip(o, 16)),
        None => "<span class=\"faint\">none</span>".to_string(),
    };
    let torn = if r.torn_bytes > 0 {
        format!(
            " <span class=\"faint\">({} torn bytes ignored)</span>",
            r.torn_bytes
        )
    } else {
        String::new()
    };
    let head = r
        .head
        .map(|h| hex_encode(&h)[..12].to_string())
        .unwrap_or_default();
    format!(
        "<tr class=\"run\"><td class=\"name\">{name}{torn}</td><td class=\"r\">{}</td>\
         <td class=\"r\">{}</td><td class=\"r\">{}</td><td class=\"r\">{}</td><td>{outcome}</td>\
         <td>{chain}</td><td>{intents}</td><td>{}</td><td><span class=\"faint\">{head}</span></td></tr>",
        r.format,
        r.entries,
        r.draws,
        r.attempts,
        esc(&r.last_at.map(text::time).unwrap_or_default()),
    )
}
