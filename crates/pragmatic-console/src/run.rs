//! One run's page: the run sheet (its title, facts and state, the
//! timeline and the chain), and beside it the Anchoring, Evidence check
//! and Run cards.
//!
//! The timeline lists every entry in cursor order (the journal's only
//! order; `at` times come from the appending process and are shown, never
//! trusted for ordering), as rows ([`crate::rows`]): a step's intent with
//! its results, notes, and the rows the console derives where an attempt
//! has no end. Each attempt is a group; nested branches hang on nested
//! rails. Expanding a row shows each of its entries: what it means for
//! replay, its fields, and every slot.
//!
//! A run can hold millions of entries and gigabytes of content, so the
//! timeline is shown a page at a time: a page ends after [`PAGE_ENTRIES`]
//! entries, or before the entry that would take its rows past
//! [`PAGE_BYTES`] of HTML, whichever comes first, and links to the next.
//! Every entry is on some page, and every page is bounded whatever the
//! journal holds (only one entry larger than the budget makes a page
//! larger, and an entry is bounded too: at most 255 slots of at most
//! 64 KiB shown each).

use std::collections::BTreeSet;

use pragmatic::encoding::hex_encode;
use pragmatic::evidence::time::{now_rfc3339, rfc3339_nanos};
use pragmatic::journal::{
    Content, Cursor, EffectOutcome, Entry, Event, Journal, LegacyEvent, META,
};
use pragmatic::json::Json;
use pragmatic::VerifyReport;

use crate::html::{
    command, data_list, diamond, dir_name, document, empty, esc, esc_capped, masthead, mono,
    notice, pretty_json_html_capped, tag, Crumb, Frame, Page,
};
use crate::rows::{self, Attempt, Ctx, Facts, Liveness};
use crate::slots::{slot_html, value_html, RefTarget, SlotAt, MAX_INLINE};
use crate::text;

/// The most timeline entries one page shows.
pub const PAGE_ENTRIES: usize = 5_000;

/// The most bytes of timeline HTML one page holds. The page ends before the
/// entry whose row would pass it, unless that entry is the page's first.
pub const PAGE_BYTES: usize = 16 << 20;

/// What a row adds to its entries' detail, at most, for the page budget.
/// Everything a row writes besides its entries' sections is bounded: its
/// title's excerpts and gists are clipped, and it names at most
/// [`rows::SHOWN`] attempts that read it back and later results.
const ROW_BYTES: usize = 2048;

/// How many failures, and attempts at each end of a run, the attempts
/// card lists to jump to.
const JUMPS: usize = 8;

/// Content shown in place of each present slot's content, for a viewer
/// who may not see it raw (Pragmatic Server's redaction for tokens without
/// `view_raw`). It sees every slot's bytes and returns what to show; refs
/// resolve to their target's content first, so a repeated message is
/// filtered the same way wherever it appears.
#[derive(Clone, Copy)]
pub struct SlotFilter<'a>(pub &'a (dyn Fn(&[u8]) -> Vec<u8> + Sync));

impl std::fmt::Debug for SlotFilter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotFilter")
    }
}

/// What Pragmatic Server adds to a run's page.
#[derive(Clone, Copy, Debug, Default)]
pub struct ServerRun<'a> {
    /// The run's status: `active`, `idle`, `dangling`, `regressed` or
    /// `missing`.
    pub status: &'a str,
    /// Legal holds on the run.
    pub holds: usize,
    /// The holds page, for administrators.
    pub holds_href: Option<&'a str>,
    /// Notices at the top of the page (escaped HTML).
    pub notices: &'a str,
    /// The Evidence check card's foot (escaped HTML): the bundle downloads,
    /// for auditors and administrators.
    pub evidence: Option<&'a str>,
    /// The erasure disclosure (escaped HTML), for administrators: the
    /// last thing in the side column.
    pub erase: Option<&'a str>,
    /// Who each server token is, as `(token id, principal)`: the Run card
    /// names the token that recorded each attempt. Empty for a viewer who
    /// may not see personal data.
    pub principals: &'a [(String, String)],
}

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
    /// Where the run lives (a directory, a server), for the Run card and
    /// the commands that check it.
    pub source: Option<&'a str>,
    /// The cursor the timeline page starts at (0 for the first page).
    pub from: Cursor,
    /// How to link to another page of the timeline: a URL to which a
    /// page's first cursor is appended, such as `/run/r1?from=`. Without
    /// one (an exported file), the page says which command writes the next.
    pub page_link: Option<&'a str>,
    /// How the page is framed. Without one, a single-file page: the strict
    /// policy, inline fonts, and the source directory on the masthead.
    pub frame: Option<&'a Frame<'a>>,
    /// What to show in place of slot content, when the viewer may not see
    /// it raw.
    pub filter: Option<SlotFilter<'a>>,
    /// Pragmatic Server's additions.
    pub server: Option<ServerRun<'a>>,
    /// When a file was exported (RFC 3339), for its footer.
    pub exported: Option<&'a str>,
}

impl<'a> RunView<'a> {
    pub fn new(run_id: &'a str, journal: &'a Journal, report: &'a VerifyReport) -> Self {
        RunView {
            run_id,
            journal,
            report,
            anchor: None,
            source: None,
            from: 0,
            page_link: None,
            frame: None,
            filter: None,
            server: None,
            exported: None,
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

/// How far an operator's witness can be trusted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WitnessTrust {
    /// Checked against a root or key the server trusts.
    Trusted,
    /// The server's own signature.
    #[default]
    Operator,
    /// Configured, and has not witnessed yet.
    Waiting,
    /// Failed its check.
    Failed,
}

/// One timestamp service or witness of a run's anchor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorWitness {
    /// The operator, as an identifier (`digicert`).
    pub operator: String,
    /// The operator's name as people know it (`DigiCert`), when the server
    /// was given one; without one, the card sets the identifier in mono.
    pub name: Option<String>,
    /// `RFC 3161`, `cosignature` or `server signature`.
    pub kind: String,
    pub trust: WitnessTrust,
    /// The trust root it chains to, when known.
    pub root: Option<String>,
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
    /// Each witness, as far as the server can tell (empty when it does
    /// not say: the operators are shown instead).
    pub witnesses: Vec<AnchorWitness>,
}

/// The page for one run: its sheet and side cards, and the page of the
/// timeline that starts at `view.from`.
pub fn render_run(view: &RunView<'_>) -> String {
    render_run_page(view).html
}

/// [`render_run`], also saying where the next page of the timeline starts.
pub fn render_run_page(view: &RunView<'_>) -> RunPage {
    let j = view.journal;
    let live = match view.server {
        Some(s) => Liveness::of_status(s.status),
        None => Liveness::Unknown,
    };
    let facts = Facts::of(j, live);
    let totals = totals(j, &facts);
    let (timeline, next) = timeline(j, &facts, view, view.from);
    let page = Span {
        from: view.from.min(j.len()),
        end: next.unwrap_or(j.len()),
        link: view.page_link,
    };
    let mut main = String::new();
    if let Some(s) = view.server {
        main.push_str(s.notices);
    }
    main.push_str("<div class=\"run-grid\">");
    main.push_str(&format!(
        "<article class=\"sheet\" aria-labelledby=\"run-title\">{}{timeline}{}</article>",
        sheet_head(view, &facts, &totals, &page),
        chain_foot(view.report, j)
    ));
    main.push_str("<aside class=\"side\" aria-label=\"About this run\">");
    // Anchoring is Pragmatic Server's: a local journal has none, and its
    // page says nothing about it rather than something negative.
    if view.server.is_some() || view.anchor.is_some() {
        main.push_str(&anchor_card(view.anchor, j.len()));
    }
    main.push_str(&check_card(view));
    main.push_str("<div class=\"stick\">");
    main.push_str(&run_card(view, &facts, &totals, &page));
    if let Some(erase) = view.server.and_then(|s| s.erase) {
        main.push_str(erase);
    }
    main.push_str("</div></aside></div>");

    let footer = view
        .exported
        .map(|t| format!("Exported {}", esc(&time_words(t))))
        .unwrap_or_default();
    let file_frame = Frame {
        footer: &footer,
        ..Frame::FILE
    };
    let frame = view.frame.unwrap_or(&file_frame);
    // Pragmatic Server: Runs / refund-20417. A directory of journals:
    // journals / refund-20417.
    let up = if view.server.is_some() {
        Some(Crumb::word("Runs", frame.home))
    } else {
        view.source
            .and_then(dir_name)
            .map(|d| Crumb::word(d, frame.home))
    };
    let mut crumbs: Vec<Crumb<'_>> = up.into_iter().collect();
    crumbs.push(Crumb::id(view.run_id, None));
    let mast = masthead(frame.home, &crumbs, frame.nav);
    let html = document(
        frame,
        &Page {
            title: view.run_id,
            masthead: mast,
            main,
            skip: Some(("timeline", "Skip to the timeline")),
            ..Page::default()
        },
    );
    RunPage { html, next }
}

/// The page of the timeline a run page shows, for links to rows on it or
/// on other pages.
struct Span<'a> {
    from: Cursor,
    end: Cursor,
    link: Option<&'a str>,
}

impl Span<'_> {
    /// The `href` of an anchor (`c14`, `a10`) at cursor `c`, or none in a
    /// file that does not hold it.
    fn href(&self, c: Cursor, anchor: &str) -> Option<String> {
        if c >= self.from && c < self.end {
            Some(format!("#{anchor}"))
        } else {
            self.link.map(|l| format!("{}{c}#{anchor}", esc(l)))
        }
    }
}

/// An RFC 3339 UTC time as the console sets it in a sentence: `14 Oct
/// 2026, 04:24:53 UTC`, the time in mono; the line breaks only after the
/// comma. Seconds are always shown: a bound such as "no later than"
/// rounded down to the minute would claim more than its token proves.
pub(crate) fn when(rfc: &str) -> String {
    match (rfc.get(11..19), rfc.len() >= 20) {
        (Some(hms), true) if rfc.as_bytes().get(10) == Some(&b'T') => format!(
            "{}, <span class=\"m nw\">{}</span>\u{a0}UTC",
            esc(&text::day_of(rfc)).replace(' ', "\u{a0}"),
            esc(hms)
        ),
        _ => format!("<span class=\"m nw\">{}</span>", esc(&text::clip(rfc, 40))),
    }
}

/// `14 Oct 2026, 00:31 UTC` for an RFC 3339 time.
pub(crate) fn time_words(rfc: &str) -> String {
    match rfc.get(11..16) {
        Some(hm) if rfc.len() >= 20 => format!("{}, {hm} UTC", text::day_of(rfc)),
        _ => text::clip(rfc, 40),
    }
}

fn n(x: impl std::fmt::Display) -> String {
    format!("<span class=\"n\">{x}</span>")
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{} {one}", n(1))
    } else {
        format!("{} {many}", n(text::count(count)))
    }
}

/// Totals over a journal.
#[derive(Default)]
struct Totals {
    draws: usize,
    tools: usize,
    effects: usize,
    tool_ok: usize,
    tool_failed: usize,
    tool_off: usize,
    effect_ok: usize,
    effect_failed: usize,
    effect_off: usize,
    failed: usize,
    /// The intents of failed steps, the first [`JUMPS`] of them by cursor.
    failures: Vec<Cursor>,
    erased: usize,
    /// The first entry with an erased slot.
    first_erased: Option<Cursor>,
    withheld: usize,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    models: BTreeSet<String>,
    program: Option<(String, String)>,
    first_at: Option<u64>,
    last_at: Option<u64>,
}

fn totals(j: &Journal, facts: &Facts) -> Totals {
    let mut t = Totals {
        draws: text::draws(j),
        ..Totals::default()
    };
    let is_tool = |name: &str| name.starts_with("tool:") && name.len() > 5;
    // The run's own span: record keeping written after it (an erasure
    // hours later) does not stretch it.
    let run_end = facts.run_end(j);
    for e in j.entries() {
        if e.at > 0 && e.cursor < run_end {
            t.first_at = Some(t.first_at.map_or(e.at, |f| f.min(e.at)));
            t.last_at = Some(t.last_at.map_or(e.at, |l| l.max(e.at)));
        }
        for c in e.event.slot_contents() {
            match c {
                Content::Erased => {
                    t.erased += 1;
                    t.first_erased.get_or_insert(e.cursor);
                }
                Content::Withheld => t.withheld += 1,
                Content::Sealed(_) => {}
            }
        }
        match &e.event {
            Event::DrawIntent { provenance, .. } if t.models.len() < 4 => {
                t.models.insert(text::clip(provenance, 48));
            }
            Event::DrawResult { meta, .. } => {
                let m = text::draw_meta(meta);
                if let Some(i) = m.input_tokens {
                    t.input_tokens = Some(t.input_tokens.unwrap_or(0) + i);
                }
                if let Some(o) = m.output_tokens {
                    t.output_tokens = Some(t.output_tokens.unwrap_or(0) + o);
                }
            }
            Event::EffectIntent { name, .. }
            | Event::Legacy(LegacyEvent::EffectIntent { name, .. }) => {
                if is_tool(name) {
                    t.tools += 1;
                } else {
                    t.effects += 1;
                }
            }
            Event::Program { name, hash } | Event::Legacy(LegacyEvent::Program { name, hash }) => {
                t.program = Some((text::clip(name, 48), text::clip(hash, 64)));
            }
            _ => {}
        }
    }
    // Each step's state is its latest result's.
    for (&intent, rs) in &facts.results {
        let (Some(Event::EffectIntent { name, .. }), Some(last)) = (
            j.get(intent).map(|e| &e.event),
            rs.last().and_then(|&r| j.get(r)),
        ) else {
            if let Some(Event::DrawResult { meta, .. }) =
                rs.last().and_then(|&r| j.get(r)).map(|e| &e.event)
            {
                if text::draw_meta(meta).outcome == "error" {
                    t.failed += 1;
                    t.failures.push(intent);
                }
            }
            continue;
        };
        let tool = is_tool(name);
        if let Event::EffectResult { outcome, .. } = &last.event {
            let slot = match (outcome, tool) {
                (EffectOutcome::Ok, true) => &mut t.tool_ok,
                (EffectOutcome::Failed, true) => &mut t.tool_failed,
                (EffectOutcome::Compensated, true) => &mut t.tool_off,
                (EffectOutcome::Ok, false) => &mut t.effect_ok,
                (EffectOutcome::Failed, false) => &mut t.effect_failed,
                (EffectOutcome::Compensated, false) => &mut t.effect_off,
            };
            *slot += 1;
            if *outcome == EffectOutcome::Failed {
                t.failed += 1;
                t.failures.push(intent);
            }
        }
    }
    t.failures.sort_unstable();
    t.failures.truncate(JUMPS);
    // Format 1 records commits and write-offs, not failures.
    for e in j.entries() {
        if let Event::Legacy(l) = &e.event {
            let tool = |name: &str| is_tool(name);
            match l {
                LegacyEvent::EffectCommit { name, .. } if tool(name) => t.tool_ok += 1,
                LegacyEvent::EffectCommit { .. } => t.effect_ok += 1,
                LegacyEvent::EffectCompensated { name } if tool(name) => t.tool_off += 1,
                LegacyEvent::EffectCompensated { .. } => t.effect_off += 1,
                _ => {}
            }
        }
    }
    t
}

/// The title block: run id and verification badge, facts, state, and the
/// notices that belong to the sheet.
fn sheet_head(view: &RunView<'_>, facts: &Facts, t: &Totals, page: &Span<'_>) -> String {
    let j = view.journal;
    let report = view.report;
    let problems = text::verify_problems(report);
    let badge = if report.is_ok() {
        format!(
            "<span class=\"badge\">{}Verified</span>",
            diamond(true, false)
        )
    } else if let Some(c) = report.first_bad {
        format!(
            "<span class=\"badge alarm\">{}Chain broken at #{c}</span>",
            diamond(false, true)
        )
    } else {
        format!(
            "<span class=\"badge alarm\">{}{}</span>",
            diamond(false, true),
            if problems.len() == 1 {
                "1 verification problem".to_string()
            } else {
                format!("{} verification problems", problems.len())
            }
        )
    };
    let read_only = if j.format() == 1 {
        tag("Read-only")
    } else {
        String::new()
    };
    // A count that leads to its rows, when the page can link to them.
    let linked = |words: String, at: Option<Cursor>, anchor: &dyn Fn(Cursor) -> String| match at
        .and_then(|c| page.href(c, &anchor(c)))
    {
        Some(h) => format!("<a href=\"{h}\">{words}</a>"),
        None => words,
    };
    let mut items = vec![
        format!("Format {}", n(j.format())),
        plural(j.len(), "entry", "entries"),
    ];
    if j.format() == 2 {
        items.push(plural(text::attempts(j) as u64, "attempt", "attempts"));
    }
    items.push(plural(t.draws as u64, "model call", "model calls"));
    items.push(plural(t.tools as u64, "tool call", "tool calls"));
    if t.effects > 0 {
        items.push(plural(t.effects as u64, "effect", "effects"));
    }
    if t.failed > 0 {
        items.push(format!(
            "<span class=\"alarm\">{}</span>",
            linked(
                format!("{} failed", n(text::count(t.failed as u64))),
                t.failures.first().copied(),
                &|c| format!("c{c}")
            )
        ));
    }
    if t.erased > 0 {
        items.push(linked(
            format!("{} erased", plural(t.erased as u64, "slot", "slots")),
            t.first_erased,
            &|c| format!("c{c}"),
        ));
    }
    if t.withheld > 0 {
        items.push(format!("{} withheld", n(text::count(t.withheld as u64))));
    }
    let open = open_calls(view, facts);
    if !open.is_empty() {
        items.push(format!(
            "<span class=\"alarm\">{}</span>",
            plural(open.len() as u64, "interrupted call", "interrupted calls")
        ));
    }
    // Each fact is kept whole; the line breaks only between facts.
    let items: Vec<String> = items
        .into_iter()
        .map(|i| format!("<span class=\"nw\">{i}</span>"))
        .collect();
    let mut facts_line = items.join(" \u{b7} ");
    if view.filter.is_some() {
        facts_line.push_str(&tag("Redacted"));
    }
    let mut out = format!(
        "<header class=\"sh-head\"><div class=\"sh-title\"><h1 class=\"rid\" id=\"run-title\">{}</h1>\
         {badge}{read_only}</div><p class=\"facts\">{facts_line}</p><p class=\"state\">{}</p>",
        esc(view.run_id),
        state_line(view, facts, t)
    );
    // Notices that belong to the sheet.
    let link = |c: Cursor| match page.href(c, &format!("c{c}")) {
        Some(h) => format!("<a class=\"m\" href=\"{h}\">#{c}</a>"),
        None => format!("<span class=\"m\">#{c}</span>"),
    };
    for p in &problems {
        out.push_str(&notice(&esc(p), true));
    }
    if !open.is_empty() {
        let shown: Vec<String> = open.iter().take(5).map(|&c| link(c)).collect();
        let more = if open.len() > 5 { ", \u{2026}" } else { "" };
        let sentence = if open.len() == 1 {
            format!(
                "1 call has no result ({}): a crash interrupted it, and a resume decides it.",
                shown[0]
            )
        } else {
            format!(
                "{} calls have no result ({}{more}): a crash interrupted them, and a resume \
                 decides them.",
                text::count(open.len() as u64),
                shown.join(", ")
            )
        };
        out.push_str(&notice(&sentence, true));
    }
    if view.filter.is_some() {
        out.push_str(&notice(
            "Content is redacted for you: personal data and secrets the server finds are \
             replaced, attachments are summarised, and the user and machine each attempt ran \
             as are withheld. Redaction does not inspect images, PDFs or audio, and is not \
             de-identification.",
            false,
        ));
    }
    out.push_str("</header>");
    out
}

/// The calls without a result that a crash interrupted: not those of a
/// last attempt that is running, or that may be (a local journal's).
fn open_calls(view: &RunView<'_>, facts: &Facts) -> Vec<Cursor> {
    text::open_intents(view.journal)
        .into_iter()
        .filter(|&c| !facts.pending(view.journal, c))
        .collect()
}

/// `recorded 14 Oct 2026, 00:29:52 to 00:29:58 UTC`: the run's own entries,
/// not the record keeping after it.
fn span(t: &Totals) -> String {
    let (Some(a), Some(b)) = (t.first_at, t.last_at) else {
        return String::new();
    };
    if text::clock(a) == text::clock(b) && text::day(a) == text::day(b) {
        format!(
            "recorded {}, {} UTC",
            esc(&text::day(a)),
            mono(&text::clock(a))
        )
    } else if text::day(a) == text::day(b) {
        format!(
            "recorded {}, {} to {} UTC",
            esc(&text::day(a)),
            mono(&text::clock(a)),
            mono(&text::clock(b))
        )
    } else {
        format!(
            "recorded {}, {} to {}, {} UTC",
            esc(&text::day(a)),
            mono(&text::clock(a)),
            esc(&text::day(b)),
            mono(&text::clock(b))
        )
    }
}

fn state_line(view: &RunView<'_>, facts: &Facts, t: &Totals) -> String {
    let j = view.journal;
    if j.format() == 1 {
        return "A format 1 journal from Pragmatic 0.4 or 0.5: it can be verified and \
                exported, not run, resumed or replayed."
            .to_string();
    }
    let recorded = span(t);
    let with_span = |s: String| {
        if recorded.is_empty() {
            s
        } else {
            format!("{s} \u{b7} {recorded}")
        }
    };
    let mut out = match facts.attempts.last() {
        None => {
            let mut r = recorded.clone();
            if let Some(first) = r.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            r
        }
        Some(a) => match (&a.end, facts.live) {
            (Some(end), _) if end.outcome == "ok" => with_span("Ended ok".into()),
            (Some(end), _) if end.outcome == "fault" => {
                let kind = if end.fault_kind.is_empty() {
                    String::new()
                } else {
                    format!(" \u{b7} {}", mono(&end.fault_kind))
                };
                with_span(format!(
                    "<span class=\"alarm\">Ended with a fault{kind}</span>"
                ))
            }
            (Some(end), _) => with_span(format!("Ended {}", mono(&end.outcome))),
            (None, Liveness::Running) => format!(
                "<i class=\"dm o br\" aria-hidden=\"true\"></i>Running \u{b7} {} since {} UTC",
                esc(&a.name()),
                mono(&text::clock(a.at))
            ),
            (None, Liveness::Stopped | Liveness::Dangling) => format!(
                "<span class=\"alarm\">{}No end: {} crashed</span>",
                diamond(false, true),
                esc(&a.name())
            ),
            // A local journal cannot say whether a process still writes
            // it: the line says only what the journal holds.
            (None, Liveness::Unknown) => with_span(format!(
                "{}Open \u{b7} {}",
                diamond(false, false),
                esc(&a.name())
            )),
        },
    };
    if let Some(s) = view.server {
        match s.status {
            "active" => {}
            "regressed" | "missing" => out.push_str(&format!(
                " \u{b7} <span class=\"alarm\">{}</span>",
                esc(s.status)
            )),
            "dangling" => {
                out.push_str(" \u{b7} <span class=\"alarm\">an effect was left open</span>")
            }
            "idle" => {}
            other => out.push_str(&format!(" \u{b7} {}", esc(other))),
        }
        if s.holds > 0 {
            let words = if s.holds == 1 {
                "1 hold".to_string()
            } else {
                format!("{} holds", s.holds)
            };
            match s.holds_href {
                Some(h) => out.push_str(&format!(" \u{b7} <a href=\"{}\">{words}</a>", esc(h))),
                None => out.push_str(&format!(" \u{b7} {words}")),
            }
        }
    }
    out
}

/// One page of the timeline from cursor `from` (column heads, paging
/// strips, groups and rows), and the cursor the next page starts at.
pub(crate) fn timeline(
    j: &Journal,
    facts: &Facts,
    view: &RunView<'_>,
    from: Cursor,
) -> (String, Option<Cursor>) {
    let total = j.len();
    let from = from.min(total);
    // The entries of the page: their detail sections are the bulk of the
    // page, so they decide where it ends.
    let mut page: Vec<Entry> = Vec::new();
    let mut sections: Vec<String> = Vec::new();
    let mut size = 0usize;
    let mut next = None;
    let probe = Ctx {
        j,
        facts,
        filter: view.filter,
        from,
        end: total,
        link: view.page_link,
    };
    for (k, e) in j.entries()[from as usize..].iter().enumerate() {
        if k == PAGE_ENTRIES {
            next = Some(e.cursor);
            break;
        }
        let entry = match view.filter {
            Some(f) => rows::filtered(e, f),
            None => e.clone(),
        };
        let section = entry_section(&probe, &entry);
        if k > 0 && size + section.len() + ROW_BYTES > PAGE_BYTES {
            next = Some(e.cursor);
            break;
        }
        size += section.len() + ROW_BYTES;
        sections.push(section);
        page.push(entry);
    }
    let end = next.unwrap_or(total);
    let ctx = Ctx { end, ..probe };
    if next.is_some() {
        // The sections were made before the page's end was known: make
        // them again, so links to entries past it lead to their page.
        sections = page.iter().map(|e| entry_section(&ctx, e)).collect();
    }
    let groups = rows::build(&ctx, &page);
    let section = |c: Cursor| -> String {
        sections
            .get((c - from) as usize)
            .cloned()
            .unwrap_or_default()
    };
    let mut out = String::from(
        "<h2 class=\"sr-only\" id=\"timeline\" tabindex=\"-1\">Timeline</h2>\
         <p class=\"cols caps\" aria-hidden=\"true\"><span>Entries</span>\
         <span class=\"c-time\">UTC \u{b7} entry hash</span><span class=\"c-hash\">Entry hash</span></p>",
    );
    if from > 0 {
        let first = match view.page_link {
            Some(prefix) => format!(" \u{b7} <a href=\"{}0\">First page</a>", esc(prefix)),
            None => format!(
                " \u{b7} the first page: <span class=\"m\">pragmatic export {}</span>",
                esc(view.run_id)
            ),
        };
        out.push_str(&format!(
            "<p class=\"pager\">Entries #{} to #{} of {}{first}</p>",
            text::count(from),
            text::count(end.saturating_sub(1)),
            text::count(total)
        ));
    }
    if page.is_empty() {
        out.push_str(&empty("No entries."));
    } else {
        out.push_str(&format!(
            "<div class=\"tl\">{}</div>",
            rows::render(&ctx, &groups, &section)
        ));
    }
    if let Some(c) = next {
        let go = match view.page_link {
            Some(prefix) => format!(" <a class=\"go\" href=\"{}{c}\">Next page</a>", esc(prefix)),
            None => format!(
                " The next file: <span class=\"m\">pragmatic export {} --from {c}</span>",
                esc(view.run_id)
            ),
        };
        out.push_str(&format!(
            "<p class=\"pager end\">This page ends before #{} to keep it quick to open; {} \
             remain.{go}</p>",
            text::count(c),
            if total - c == 1 {
                "1 entry".to_string()
            } else {
                format!("{} entries", text::count(total - c))
            }
        ));
    }
    (out, next)
}

/// What an entry means for replay.
fn meaning(e: &Entry) -> &'static str {
    match &e.event {
        Event::DrawIntent { .. } => "Written before the model was called.",
        Event::DrawResult { meta, .. } => match text::draw_meta(meta).outcome.as_str() {
            "partial" => {
                "The stream closed before it ended. Replay serves these bytes and ends the \
                 stream the same way."
            }
            "error" => "The call failed. Replay raises the same error without calling the model.",
            _ => "The response. Replay serves it without calling the model.",
        },
        Event::EffectIntent { .. } => {
            "Written before the tool ran. An intent with no result marks a crash during the call."
        }
        Event::EffectResult { outcome, .. } => match outcome {
            EffectOutcome::Ok => "The result. Replay returns it; the tool does not run again.",
            EffectOutcome::Failed => "The tool failed. Replay fails it again with this message.",
            EffectOutcome::Compensated => {
                "Written off by recovery; the run performed the effect again under a new intent."
            }
        },
        Event::Clock { .. } => {
            "A journaled clock read: replay sees this time, not the current one."
        }
        Event::Random { .. } => "A journaled random draw: replay sees this value.",
        Event::ChannelRecv { .. } => "A received value: replay delivers it again.",
        Event::Program { .. } => {
            "The program's identity: replay checks the running program against it."
        }
        Event::Fork { .. } => "A parallel region: each branch runs on its own lane, nested below.",
        Event::Marker { .. } => "The run took a code patch; replay requires the same patch.",
        Event::Refusal { .. } => {
            "Refused without touching the world. Replay raises the same fault here."
        }
        Event::Note { .. } => "A note on the meta lane. Replay never reads it.",
        _ => "A format 1 entry, read-only in 0.6.",
    }
}

/// The longest field value an expanded row shows, in characters.
const FIELD: usize = 4096;

/// A recorded field's value in mono: on one line, control and bidi
/// characters escaped, clipped.
fn field(value: &str) -> String {
    mono(&text::clip(value, FIELD))
}

/// One entry in an expanded row: its kind, cursor and time, what it means,
/// its fields and its slots.
fn entry_section(ctx: &Ctx<'_>, e: &Entry) -> String {
    let at = if e.at == 0 {
        String::new()
    } else {
        format!("<span class=\"dim\">{}</span>", esc(&rfc3339_nanos(e.at)))
    };
    let mut links = String::new();
    match &e.event {
        Event::DrawIntent { .. } | Event::EffectIntent { .. } => {
            let rs: &[Cursor] = ctx.facts.results.get(&e.cursor).map_or(&[], |v| v);
            if rs.is_empty() {
                links = " No result recorded.".into();
            } else {
                // The first few, linked, and a count of the rest: an intent
                // can have any number of results, and its section must not
                // grow with them.
                let l: Vec<String> = rs
                    .iter()
                    .take(rows::SHOWN)
                    .map(|&c| ctx.cursor(c))
                    .collect();
                let more = rs.len() - l.len();
                let word = if rs.len() == 1 { "Result" } else { "Results" };
                links = if more == 0 {
                    format!(" {word}: {}.", l.join(", "))
                } else {
                    format!(
                        " {word}: {} and {} more.",
                        l.join(", "),
                        text::count(more as u64)
                    )
                };
            }
        }
        Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } => {
            links = format!(" For: {}.", ctx.cursor(*intent));
        }
        _ => {}
    }
    let mut out = format!(
        "<section class=\"ent\"><p class=\"ent-h\">{} {}{at}</p><p class=\"ent-w\">{}{links}</p>",
        esc(&text::label(&e.event)),
        ctx.cursor(e.cursor),
        meaning(e)
    );
    let mut fields: Vec<(&str, String)> = Vec::new();
    let mut withheld: Option<String> = None;
    let mut block: Option<(&str, &str)> = None;
    match &e.event {
        Event::DrawIntent { provenance, .. } => fields.push(("provenance", field(provenance))),
        Event::DrawResult { meta, .. } => {
            let m = text::draw_meta(meta);
            fields.push(("outcome", field(&m.outcome)));
            if !m.model.is_empty() {
                fields.push(("model", field(&m.model)));
            }
            if m.input_tokens.is_some() || m.output_tokens.is_some() {
                fields.push((
                    "tokens",
                    esc(&format!(
                        "{} in, {} out",
                        m.input_tokens.map_or("?".into(), text::count),
                        m.output_tokens.map_or("?".into(), text::count)
                    )),
                ));
            }
            if let Some(ms) = m.latency_ms {
                fields.push(("latency", esc(&format!("{} ms", text::count(ms)))));
            }
            if !m.stop_reason.is_empty() {
                fields.push(("stop reason", field(&m.stop_reason)));
            }
            if let Some(st) = m.status {
                fields.push(("status", esc(&st.to_string())));
            }
            if !m.error_kind.is_empty() {
                fields.push(("error kind", field(&m.error_kind)));
            }
            if !m.error_type.is_empty() {
                fields.push(("error type", field(&m.error_type)));
            }
            block = Some(("meta", meta));
        }
        Event::EffectIntent { name, .. } => fields.push(("effect", field(name))),
        Event::EffectResult {
            outcome,
            error_kind,
            ..
        } => {
            fields.push(("outcome", field(outcome.as_str())));
            if !error_kind.is_empty() {
                fields.push(("error kind", field(error_kind)));
            }
        }
        Event::ChannelRecv { channel, .. } => fields.push(("channel", field(channel))),
        Event::Clock { nanos } => {
            fields.push(("read", mono(&rfc3339_nanos(*nanos))));
            fields.push(("nanoseconds", mono(&nanos.to_string())));
        }
        Event::Program { name, hash } => {
            fields.push(("name", field(name)));
            fields.push(("hash", field(hash)));
        }
        Event::Fork { base, children } => {
            fields.push(("first branch", mono(&base.to_string())));
            fields.push(("branches", mono(&children.to_string())));
        }
        Event::Marker { name } => fields.push(("patch", field(name))),
        Event::Note { kind, data, .. } => {
            fields.push(("kind", field(kind)));
            // The user and machine an attempt ran as are personal data: a
            // viewer who may not see content raw does not see them.
            if ctx.filter.is_some() && kind == "attempt.start" {
                withheld = withhold_identity(data);
            }
            block = Some(("data", withheld.as_deref().unwrap_or(data)));
        }
        Event::Random { source, args, .. } => {
            fields.push(("source", field(source)));
            fields.push(("arguments", field(args)));
        }
        Event::Refusal { step, name, fault } => {
            fields.push(("step", field(step)));
            if !name.is_empty() {
                fields.push(("name", field(name)));
            }
            fields.push(("fault", field(fault)));
        }
        _ => {}
    }
    let branch = if e.branch.is_empty() {
        "root".to_string()
    } else if e.branch == META {
        "meta".to_string()
    } else {
        text::branch_label(&e.branch)
    };
    fields.push(("branch", mono(&branch)));
    let hash = hex_encode(&e.hash);
    fields.push(("entry hash", mono(&hash)));
    out.push_str(&data_list("", &fields));
    if let Some((label, json)) = block {
        out.push_str(&format!("<p class=\"slot-l caps\">{label}</p>"));
        // Capped like a slot: indentation and markup make the HTML far
        // larger than the JSON.
        let (html, cut) = match pretty_json_html_capped(json, MAX_INLINE) {
            Some((h, cut)) => (format!("<pre class=\"json\">{h}</pre>"), cut),
            None => {
                let (h, cut) = esc_capped(json, MAX_INLINE);
                (format!("<pre>{h}</pre>"), cut)
            }
        };
        out.push_str(&html);
        if cut {
            out.push_str(&format!(
                "<p class=\"slot-n\">Showing the first 64 KiB of {} bytes.</p>",
                text::count(json.len() as u64)
            ));
        }
    }
    if let Event::Legacy(l) = &e.event {
        out.push_str(&legacy_detail(l));
    }
    let labels = text::slot_labels(&e.event);
    for (k, (meta, content)) in e.slots.iter().zip(e.event.slot_contents()).enumerate() {
        let label = labels
            .get(k)
            .cloned()
            .unwrap_or_else(|| format!("slot {k}"));
        let target = meta.ref_target.map(|(c, s)| RefTarget {
            link: ctx.cursor(c),
            label: ctx
                .j
                .get(c)
                .and_then(|t| text::slot_labels(&t.event).get(s as usize).cloned())
                .unwrap_or_else(|| format!("slot {s}")),
        });
        out.push_str(&slot_html(
            SlotAt {
                cursor: e.cursor,
                slot: k as u8,
                label: &label,
            },
            meta,
            content,
            target.as_ref(),
        ));
    }
    out.push_str("</section>");
    out
}

/// What a viewer without `view_raw` sees in place of a personal field, as
/// Pragmatic Server's access log shows it.
const WITHHELD: &str = "[withheld]";

/// An attempt note's data with its `principal` and `host` withheld, or
/// `None` when the data is not a JSON object.
fn withhold_identity(data: &str) -> Option<String> {
    let Ok(Json::Object(members)) = Json::parse(data) else {
        return None;
    };
    let members = members
        .into_iter()
        .map(|(k, v)| match (k.as_str(), &v) {
            ("principal" | "host", Json::Null) => (k, v),
            ("principal" | "host", _) => (k, Json::String(WITHHELD.into())),
            _ => (k, v),
        })
        .collect();
    Some(Json::Object(members).to_string())
}

/// A format 1 entry in full: each recorded value (prompt, outcome,
/// argument, result, received value) in its own block, shown the way a
/// format 2 slot is.
fn legacy_detail(l: &LegacyEvent) -> String {
    let value = |label: &str, v: &pragmatic::Value| value_html(label, v.as_bytes());
    let fields = |rows: &[(&str, String)]| data_list("", rows);
    match l {
        LegacyEvent::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => format!(
            "{}{}{}",
            fields(&[("provenance", field(provenance))]),
            value("prompt", prompt),
            value("outcome", outcome)
        ),
        LegacyEvent::ChannelRecv { channel, value: v } => {
            format!(
                "{}{}",
                fields(&[("channel", field(channel))]),
                value("value", v)
            )
        }
        LegacyEvent::EffectIntent { name, arg } => {
            format!(
                "{}{}",
                fields(&[("effect", field(name))]),
                value("argument", arg)
            )
        }
        LegacyEvent::EffectCommit { name, result } => {
            format!(
                "{}{}",
                fields(&[("effect", field(name))]),
                value("result", result)
            )
        }
        LegacyEvent::EffectCompensated { name } => fields(&[("effect", field(name))]),
        LegacyEvent::Clock { nanos } => fields(&[("nanoseconds", mono(&nanos.to_string()))]),
        LegacyEvent::Program { name, hash } => {
            fields(&[("name", field(name)), ("hash", field(hash))])
        }
    }
}

/// The sheet's foot: the chain, as the header shows it.
fn chain_foot(report: &VerifyReport, j: &Journal) -> String {
    let head = hex_encode(&j.head());
    let torn = if report.torn_bytes > 0 {
        format!(
            "<span class=\"s\">\u{b7} {} torn bytes after the valid prefix ignored</span>",
            text::count(report.torn_bytes)
        )
    } else {
        String::new()
    };
    if let Some(c) = report.first_bad {
        return format!(
            "<p class=\"chain alarm\">{}<span>Chain broken at</span> <span class=\"m\">#{c}</span>\
             <span class=\"s\">\u{b7} entries from #{c} on are not covered by the chain</span>{torn}</p>",
            diamond(false, true)
        );
    }
    let problems = text::verify_problems(report).len();
    let extra = if problems > 0 {
        format!(
            "<span class=\"s alarm\">\u{b7} {} erasure {}, listed above</span>",
            problems,
            if problems == 1 { "problem" } else { "problems" }
        )
    } else {
        String::new()
    };
    // The full head, to copy: it breaks only at its middle.
    format!(
        "<p class=\"chain\">{}<span>Chain verified</span><span class=\"s\">\u{b7} {}</span>\
         <span class=\"m hd\"><span class=\"d\">\u{b7} </span>head <span class=\"hx\">{}<wbr>{}</span></span>{extra}{torn}</p>",
        diamond(true, false),
        if j.len() == 1 {
            "1 entry".to_string()
        } else {
            format!("{} entries", text::count(j.len()))
        },
        &head[..32],
        &head[32..]
    )
}

/// The Anchoring card, on Pragmatic Server.
pub(crate) fn anchor_card(anchor: Option<&AnchorStatus>, entries: u64) -> String {
    let caveat = "<p class=\"note\">An anchor proves these entries existed by then, not that \
                  they were true.</p>";
    let Some(a) = anchor else {
        return format!(
            "<section class=\"card anchor\" aria-labelledby=\"h-anchor\"><div class=\"card-h\">\
             <h2 class=\"card-t o\" id=\"h-anchor\">Not yet anchored</h2>{}</div>\
             <div class=\"rule\"></div><div class=\"card-b\"><p>No timestamp service has \
             witnessed this run yet.</p></div></section>",
            tag("Preview")
        );
    };
    let anchored = a.anchored_entries.min(entries);
    let share = if entries == 0 {
        0.0
    } else {
        anchored as f64 * 100.0 / entries as f64
    };
    let witnesses: Vec<AnchorWitness> = if a.witnesses.is_empty() {
        a.operators
            .iter()
            .map(|o| AnchorWitness {
                operator: o.clone(),
                name: None,
                kind: String::new(),
                trust: if a.independent {
                    WitnessTrust::Trusted
                } else {
                    WitnessTrust::Operator
                },
                root: None,
            })
            .collect()
    } else {
        a.witnesses.clone()
    };
    let (title, class, body) = if anchored == 0 {
        (
            "Not yet anchored".to_string(),
            "card-t o",
            "<p>No timestamp service has witnessed this run yet.</p>".to_string(),
        )
    } else if !a.independent {
        (
            "Signed by this server only".to_string(),
            "card-t o",
            format!(
                "<p>{} of {} entries \u{b7} no independent timestamp service has witnessed \
                 it yet.</p>",
                text::count(anchored),
                text::count(entries)
            ),
        )
    } else {
        let services = witnesses
            .iter()
            .filter(|w| w.trust == WitnessTrust::Trusted)
            .count()
            .max(a.operators.len());
        let title = if anchored >= entries {
            if services == 1 {
                "Anchored by 1 independent timestamp service".to_string()
            } else {
                format!("Anchored by {services} independent timestamp services")
            }
        } else {
            format!("Anchored up to #{}", anchored - 1)
        };
        let when = a
            .time
            .as_deref()
            .map(|t| format!(" \u{b7} existed no later than {}", when(t)))
            .unwrap_or_default();
        let body = if anchored >= entries {
            format!(
                "<p>{} of {} entries{when}</p>",
                text::count(anchored),
                text::count(entries)
            )
        } else {
            format!(
                "<p>{} of {} entries \u{b7} <span class=\"note\">the newest {} not anchored \
                 yet</span></p>",
                text::count(anchored),
                text::count(entries),
                if entries - anchored == 1 {
                    "is".to_string()
                } else {
                    format!("{} are", text::count(entries - anchored))
                }
            )
        };
        (title, "card-t", body)
    };
    let mut ops = String::new();
    for w in &witnesses {
        let (mark, note) = match w.trust {
            WitnessTrust::Trusted => ("<i aria-hidden=\"true\"></i>", "trusted"),
            WitnessTrust::Operator => ("<i class=\"o\" aria-hidden=\"true\"></i>", "operator only"),
            WitnessTrust::Waiting => ("<i class=\"o\" aria-hidden=\"true\"></i>", "waiting"),
            WitnessTrust::Failed => (
                "<i class=\"a\" aria-hidden=\"true\"></i>",
                "failed its check",
            ),
        };
        let st = if w.kind.is_empty() || w.trust == WitnessTrust::Waiting {
            note.to_string()
        } else {
            format!("{} \u{b7} {note}", text::clip(&w.kind, 24))
        };
        // The root a trusted witness's pinned anchors chain to.
        let root = w
            .root
            .as_deref()
            .filter(|_| w.trust == WitnessTrust::Trusted)
            .map(|r| format!("<span class=\"root\">{}</span>", esc(&text::clip(r, 80))))
            .unwrap_or_default();
        // A name as people know it, or else the identifier, set as one.
        let name = match w.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) => format!("<span class=\"nm\">{}</span>", esc(&text::clip(n, 64))),
            None => format!(
                "<span class=\"nm m\">{}</span>",
                esc(&text::clip(&w.operator, 64))
            ),
        };
        ops.push_str(&format!(
            "<li class=\"op\">{mark}{name}<span class=\"st\">{}</span>{root}</li>",
            esc(&st)
        ));
    }
    let ops = if ops.is_empty() {
        ops
    } else {
        format!("<ul class=\"ops\">{ops}</ul>")
    };
    // The card's head is divided by a hairline like every card's. Only a
    // partial anchor draws its share, as a meter inside the card above the
    // count it shows in words, so it never reads as a border.
    let meter = if anchored > 0 && anchored < entries {
        format!(
            "<div class=\"meter\" aria-hidden=\"true\"><span style=\"width:{share:.2}%\"></span></div>"
        )
    } else {
        String::new()
    };
    format!(
        "<section class=\"card anchor\" aria-labelledby=\"h-anchor\"><div class=\"card-h\">\
         <h2 class=\"{class}\" id=\"h-anchor\">{}</h2>{}</div>\
         <div class=\"rule\"></div>{ops}<div class=\"card-b\">{meter}{body}{caveat}</div></section>",
        esc(&title),
        tag("Preview")
    )
}

/// The Evidence check card: the verification report, as `pragmatic
/// verify` prints it.
fn check_card(view: &RunView<'_>) -> String {
    let r = view.report;
    let j = view.journal;
    let head = hex_encode(&j.head());
    let list = |slots: &[(Cursor, u8)]| {
        if slots.is_empty() {
            "none".to_string()
        } else {
            let shown: Vec<String> = slots
                .iter()
                .take(8)
                .map(|(c, s)| format!("{c}:{s}"))
                .collect();
            let more = if slots.len() > 8 { " \u{2026}" } else { "" };
            format!(
                "<span class=\"alarm\">{}{more}</span>",
                esc(&shown.join(" "))
            )
        }
    };
    let chain = match r.first_bad {
        Some(c) => format!("<span class=\"alarm\">broken at #{c}</span>"),
        None => "every link, commitment and ref verifies".to_string(),
    };
    let invalid = if r.invalid_erasure_notes.is_empty() {
        "none".to_string()
    } else {
        let shown: Vec<String> = r
            .invalid_erasure_notes
            .iter()
            .take(8)
            .map(|c| format!("#{c}"))
            .collect();
        format!("<span class=\"alarm\">{}</span>", esc(&shown.join(" ")))
    };
    let result = if r.is_ok() {
        format!(
            "<span class=\"res\">{}verified</span>",
            diamond(true, false)
        )
    } else {
        format!(
            "<span class=\"res alarm\">{}failed</span>",
            diamond(true, true)
        )
    };
    let rows = [
        (
            "journal",
            esc(&format!(
                "format {}, {} entries",
                j.format(),
                text::count(j.len())
            )),
        ),
        (
            "head",
            format!(
                "<span class=\"id\" title=\"{head}\">{}\u{2026}</span>",
                &head[..12]
            ),
        ),
        ("chain", chain),
        ("unaccounted erasures", list(&r.unaccounted_erasures)),
        ("erasure incomplete", list(&r.erasure_incomplete)),
        ("invalid erasure notes", invalid),
        ("torn bytes", text::count(r.torn_bytes)),
        ("", String::new()),
        ("result", result),
    ];
    let checked = now_rfc3339();
    let checked = checked.get(11..16).unwrap_or("");
    let foot = match view.server {
        Some(s) => s
            .evidence
            .map(|f| format!("<div class=\"card-f\">{f}</div>"))
            .unwrap_or_default(),
        None => {
            let run = shell_word(view.run_id);
            let dir: Vec<String> = view
                .source
                .map(|d| format!("--dir {}", shell_word(d)))
                .into_iter()
                .collect();
            let verify = [vec![format!("pragmatic verify {run}")], dir.clone()].concat();
            let bundle = [
                vec![
                    format!("pragmatic evidence {run}"),
                    format!(
                        "-o {}",
                        shell_word(&format!("{}.evidence.json", view.run_id))
                    ),
                ],
                dir,
            ]
            .concat();
            format!(
                "<div class=\"card-f\"><p class=\"lbl\">Check it yourself</p>{}\
                 <p class=\"lbl\">Make an evidence bundle {}</p>{}</div>",
                command(&verify),
                tag("Preview"),
                command(&bundle)
            )
        }
    };
    format!(
        "<section class=\"card check\" aria-labelledby=\"h-check\"><div class=\"card-h\">\
         <h2 class=\"card-t\" id=\"h-check\">Evidence check</h2>\
         <span class=\"note\">checked {checked} UTC</span></div>\
         <div class=\"card-b\">{}</div>{foot}</section>",
        data_list("", &rows)
    )
}

/// A word for a shell command line: quoted when it holds anything but
/// plain characters.
fn shell_word(s: &str) -> String {
    let s = text::sanitize(s);
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@+=,".contains(c))
    {
        s
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The Run card: what the sheet does not say.
fn run_card(view: &RunView<'_>, facts: &Facts, t: &Totals, page: &Span<'_>) -> String {
    let j = view.journal;
    // The run's state, status and holds are on the sheet's state line.
    let mut rows: Vec<(&str, String)> = Vec::new();
    let labels = j
        .entries()
        .iter()
        .find(|e| e.event.note_kind() == Some("run.start"))
        .and_then(|e| match &e.event {
            Event::Note { data, .. } => Json::parse(data).ok(),
            _ => None,
        })
        .and_then(|d| {
            d.get("labels").and_then(Json::as_object).map(|l| {
                l.iter()
                    .take(8)
                    .map(|(k, v)| {
                        let v = v
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string());
                        format!("{}={}", text::clip(k, 32), text::clip(&v, 48))
                    })
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    let none = "<span class=\"s\">none</span>";
    let not_recorded = "<span class=\"s\">not recorded</span>".to_string();
    rows.push((
        "labels",
        if labels.is_empty() {
            none.to_string()
        } else {
            esc(&labels.join(" "))
        },
    ));
    // Names, hashes and model ids are units: each on one line.
    let id = |s: &str| format!("<span class=\"id\">{}</span>", esc(s));
    rows.push((
        "program",
        match &t.program {
            Some((name, hash)) => format!("{} {}", id(name), id(&text::clip(hash, 12))),
            None => not_recorded.clone(),
        },
    ));
    rows.push((
        "model",
        if t.models.is_empty() {
            not_recorded.clone()
        } else {
            t.models.iter().map(|m| id(m)).collect::<Vec<_>>().join(" ")
        },
    ));
    rows.push((
        "tokens",
        match (t.input_tokens, t.output_tokens) {
            (None, None) => not_recorded.clone(),
            (i, o) => esc(&format!(
                "{} in \u{b7} {} out",
                i.map_or("?".into(), text::count),
                o.map_or("?".into(), text::count)
            )),
        },
    ));
    // Format 1 records commits and write-offs, not failures.
    // Each count keeps its words on one line.
    let outcomes = |ok: usize, failed: usize, off: usize| {
        if j.format() == 1 {
            format!(
                "{ok}\u{a0}ok \u{b7} {off}\u{a0}written\u{a0}off \u{b7} format 1 records no \
                 failures"
            )
        } else {
            format!("{ok}\u{a0}ok \u{b7} {failed}\u{a0}failed \u{b7} {off}\u{a0}written\u{a0}off")
        }
    };
    rows.push((
        "tool calls",
        esc(&outcomes(t.tool_ok, t.tool_failed, t.tool_off)),
    ));
    if t.effects > 0 {
        rows.push((
            "effects",
            esc(&outcomes(t.effect_ok, t.effect_failed, t.effect_off)),
        ));
    }
    rows.push((
        "slots",
        esc(&format!(
            "{}\u{a0}erased \u{b7} {}\u{a0}withheld",
            t.erased, t.withheld
        )),
    ));
    format!(
        "<section class=\"card run\" aria-labelledby=\"h-run\"><div class=\"card-h\">\
         <h2 class=\"card-t\" id=\"h-run\">Run</h2></div><div class=\"card-b\">{}{}</div></section>",
        data_list("n", &rows),
        run_lists(view, facts, t, page)
    )
}

/// The words an attempt's outcome is told in, everywhere it is told, and
/// whether they are trouble.
fn attempt_outcome(a: &Attempt, live: Liveness, last: bool) -> (String, bool) {
    match &a.end {
        Some(e) if e.outcome == "ok" => {
            let mut s = String::from("Ended ok");
            if let (Some(f), Some(r)) = (e.fresh, e.replayed) {
                s.push_str(&format!(" \u{b7} {f} fresh, {r} replayed"));
            }
            (s, false)
        }
        Some(e) if e.outcome == "fault" => {
            let mut s = String::from("Ended with a fault");
            if !e.fault_kind.is_empty() {
                s.push_str(&format!(" \u{b7} {}", e.fault_kind));
            }
            (s, true)
        }
        Some(e) => (format!("Ended {}", e.outcome), false),
        None if !last => ("No end: crashed".into(), true),
        None => match live {
            Liveness::Running => ("Running".into(), false),
            Liveness::Unknown => ("Open".into(), false),
            Liveness::Stopped | Liveness::Dangling => ("No end: crashed".into(), true),
        },
    }
}

/// "Tool call issue_refund", "Model call": a step's words, for a list.
fn step_words(j: &Journal, intent: Cursor) -> String {
    match j.get(intent).map(|e| &e.event) {
        Some(Event::EffectIntent { name, .. }) => match name.strip_prefix("tool:") {
            Some(tool) if !tool.is_empty() => {
                format!("Tool call {}", mono(&text::clip(tool, 40)))
            }
            _ => format!("Effect {}", mono(&text::clip(name, 40))),
        },
        Some(Event::DrawIntent { .. }) => "Model call".to_string(),
        _ => "Step".to_string(),
    }
}

/// The Run card's lists: every attempt (or, in a long run, the first and
/// the last), then its failures and the record keeping after it, each a
/// link to its place in the timeline. On a wide screen the card stays in
/// view while a long timeline scrolls.
fn run_lists(view: &RunView<'_>, facts: &Facts, t: &Totals, page: &Span<'_>) -> String {
    let j = view.journal;
    // The server token that recorded an attempt, for a viewer who may see
    // personal data. The SDK's own identity (the user and machine it ran
    // as) stays in the attempt's note.
    let principals = match (view.server, view.filter) {
        (Some(s), None) => s.principals,
        _ => &[],
    };
    let item = |href: Option<String>, inner: String| match href {
        Some(h) => format!("<li><a href=\"{h}\">{inner}</a></li>"),
        None => format!("<li><span class=\"ja\">{inner}</span></li>"),
    };
    let mut body = String::new();
    let count = facts.attempts.len();
    if count > 0 {
        // A long run lists its first attempts and its last ones.
        let (head, tail) = if count > 2 * JUMPS {
            (JUMPS / 2, JUMPS)
        } else {
            (count, 0)
        };
        let shown = facts.attempts[..head].iter().enumerate().chain(
            facts.attempts[count - tail..]
                .iter()
                .enumerate()
                .map(|(i, a)| (count - tail + i, a)),
        );
        body.push_str(&format!(
            "<p class=\"caps\" id=\"attempts\">{}</p><ol class=\"jl\">",
            if count == 1 {
                "Attempt".to_string()
            } else {
                format!("{} attempts", text::count(count as u64))
            }
        ));
        for (i, a) in shown {
            if tail > 0 && i == count - tail {
                body.push_str(&format!(
                    "<li class=\"more\">and {} more</li>",
                    text::count((count - head - tail) as u64)
                ));
            }
            let (outcome, alarm) = attempt_outcome(a, facts.live, i + 1 == count);
            let mut words = esc(&a.title());
            if !a.mode.is_empty() {
                words.push_str(&format!(" \u{b7} {}", esc(&text::clip(&a.mode, 16))));
            }
            let when = if a.at == 0 {
                String::new()
            } else if facts.multi_day {
                esc(&format!("{} {}", text::day(a.at), text::clock(a.at)))
            } else {
                esc(&text::clock(a.at))
            };
            // When it began, which token recorded it and its process, each
            // kept whole: the line breaks only between them.
            let mut parts: Vec<String> = Vec::new();
            if !when.is_empty() {
                parts.push(when);
            }
            if let Some((_, who)) = principals
                .iter()
                .find(|(id, _)| !a.token.is_empty() && *id == a.token)
            {
                parts.push(esc(&text::clip(who, 64)));
            }
            if !a.pid.is_empty() {
                parts.push(esc(&format!("pid {}", text::clip(&a.pid, 16))));
            }
            let out_class = if alarm { "out alarm" } else { "out" };
            let who = if parts.is_empty() {
                String::new()
            } else {
                let parts: Vec<String> = parts
                    .iter()
                    .map(|p| format!("<span class=\"nw\">{p}</span>"))
                    .collect();
                format!("<span class=\"who\">{}</span>", parts.join(" \u{b7} "))
            };
            body.push_str(&item(
                page.href(a.start, &format!("a{}", a.start)),
                format!(
                    "<span class=\"w\">{words}</span><span class=\"{out_class}\">{}</span>{who}",
                    esc(&outcome)
                ),
            ));
        }
        body.push_str("</ol>");
    }
    if t.failed > 0 {
        body.push_str("<p class=\"caps\">Failures</p><ol class=\"jl\">");
        for &c in &t.failures {
            body.push_str(&item(
                page.href(c, &format!("c{c}")),
                format!(
                    "<span class=\"w\">{}</span><span class=\"out\">{}</span>",
                    step_words(j, c),
                    mono(&format!("#{c}"))
                ),
            ));
        }
        if t.failed > t.failures.len() {
            body.push_str(&format!(
                "<li class=\"more\">and {} more</li>",
                text::count((t.failed - t.failures.len()) as u64)
            ));
        }
        body.push_str("</ol>");
    }
    if let Some(after) = facts.after {
        body.push_str("<p class=\"caps\">After the run</p><ol class=\"jl\">");
        let notes = &j.entries()[after as usize..];
        for e in notes.iter().take(JUMPS) {
            let words = match e.event.note_kind() {
                Some("erasure") => "Erasure",
                Some("custody") => "Lease custody",
                _ => "Note",
            };
            body.push_str(&item(
                page.href(e.cursor, &format!("c{}", e.cursor)),
                format!(
                    "<span class=\"w\">{words}</span><span class=\"out\">{}</span>",
                    mono(&format!("#{}", e.cursor))
                ),
            ));
        }
        if notes.len() > JUMPS {
            body.push_str(&format!(
                "<li class=\"more\">and {} more</li>",
                text::count((notes.len() - JUMPS) as u64)
            ));
        }
        body.push_str("</ol>");
    }
    body
}
