//! The timeline's rows: which entries make a row, and what each row says.
//!
//! The console walks a page's entries in cursor order, the journal's only
//! order, and makes rows of them:
//!
//! - a step (a model call or a tool call) is one row from its intent and
//!   every result recorded for it, however far away; its state follows
//!   the latest result;
//! - a result whose intent is on an earlier page is a row of its own,
//!   titled from that intent; a result that names no intent says so;
//! - `run.start` and the first attempt's `attempt.start` right after it
//!   make one row, "Run started";
//! - each `attempt.start` opens a group, and its `attempt.end` closes it;
//! - an attempt that stopped without an end gets a derived row: "No end:
//!   crashed" where a later attempt shows it crashed, or, at the end of
//!   the run, what is known (running, crashed, or for a local journal
//!   "running, or crashed");
//! - every other entry is a row of its own.
//!
//! Every entry on the page is in exactly one row, and every row names all
//! of its entries in its kinds line (`draw.intent #2 · draw.ok #3`).
//!
//! A row's title is the console's own phrase ("Model call", "Tool call",
//! "Run started"), recorded data in mono, and italic accents after a
//! middle dot. Recorded content reaches a title only as an excerpt in the
//! console's quotes or a gist in mono ([`crate::gist`]); every value is
//! escaped.

use std::borrow::Cow;
use std::collections::HashMap;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{
    Content, Cursor, EffectOutcome, Entry, Event, Journal, LegacyEvent, META,
};
use pragmatic::json::Json;

use crate::gist::{self, Gist, EXCERPT, GIST};
use crate::html::esc;
use crate::run::SlotFilter;
use crate::text;

/// What the page knows of whether the run is still going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    /// A local journal: nothing says whether a process still writes it.
    Unknown,
    /// Pragmatic Server holds a live lease for it.
    Running,
    /// Pragmatic Server holds no lease and the run's last effect is open.
    Dangling,
    /// Pragmatic Server holds no lease.
    Stopped,
}

impl Liveness {
    /// From a Pragmatic Server run status.
    pub fn of_status(status: &str) -> Liveness {
        match status {
            "active" => Liveness::Running,
            "dangling" => Liveness::Dangling,
            _ => Liveness::Stopped,
        }
    }
}

/// One attempt, from its notes.
#[derive(Clone, Debug)]
pub struct Attempt {
    /// The `attempt` number its notes give.
    pub n: Option<u64>,
    pub start: Cursor,
    pub at: u64,
    pub mode: String,
    pub pid: String,
    pub host: String,
    pub principal: String,
    pub torn: u64,
    pub end: Option<AttemptEnd>,
    /// The next attempt's start: this attempt's entries end before it.
    pub until: Option<Cursor>,
    /// Recovery notes that wrote off or retried an effect, and written-off
    /// results, in this attempt.
    pub repeated: usize,
    pub first_repeated: Option<Cursor>,
}

/// How an attempt ended.
#[derive(Clone, Debug)]
pub struct AttemptEnd {
    pub cursor: Cursor,
    pub outcome: String,
    pub fault_kind: String,
    pub fault_cursor: Option<u64>,
    pub fresh: Option<u64>,
    pub replayed: Option<u64>,
    pub passthrough: u64,
}

impl Attempt {
    /// "attempt 2", or "an attempt" when its notes give no number.
    pub fn name(&self) -> String {
        match self.n {
            Some(n) => format!("attempt {n}"),
            None => "an attempt".into(),
        }
    }

    /// "Attempt 2", or "Attempt" without a number.
    pub fn title(&self) -> String {
        match self.n {
            Some(n) => format!("Attempt {n}"),
            None => "Attempt".into(),
        }
    }
}

/// What the rows of every page need to know about the whole run.
pub struct Facts {
    pub results: HashMap<Cursor, Vec<Cursor>>,
    pub attempts: Vec<Attempt>,
    /// For each completed step (an intent with a result), its first
    /// result.
    first_result: HashMap<Cursor, Cursor>,
    /// Attempts whose `replayed` matches the steps completed before them:
    /// (start, attempt number), by start.
    read_back: Vec<(Cursor, u64)>,
    /// Effect intents by name, in cursor order.
    effects_by_name: HashMap<String, Vec<Cursor>>,
    /// Format 1: an effect intent's commit or write-off.
    legacy_result: HashMap<Cursor, Cursor>,
    legacy_intent: HashMap<Cursor, Cursor>,
    /// The run's entries cross a UTC day.
    pub multi_day: bool,
    pub live: Liveness,
}

fn json_str(d: &Json, k: &str, width: usize) -> String {
    match d.get(k) {
        Some(Json::String(v)) => text::clip(v, width),
        Some(Json::Null) | None => String::new(),
        Some(v) => text::clip(&v.to_string(), width),
    }
}

impl Facts {
    pub fn of(j: &Journal, live: Liveness) -> Facts {
        let results = text::results_by_intent(j);
        let mut first_result = HashMap::new();
        let mut completed: Vec<Cursor> = Vec::new();
        for (&intent, rs) in &results {
            if let Some(&r) = rs.first() {
                first_result.insert(intent, r);
                completed.push(r);
            }
        }
        completed.sort_unstable();
        let mut attempts: Vec<Attempt> = Vec::new();
        // Attempt number to its latest attempt, so each end is matched in
        // O(1): a journal of many ends that name no started attempt
        // (hostile or broken) must not cost starts times ends.
        let mut latest: HashMap<u64, usize> = HashMap::new();
        let mut effects_by_name: HashMap<String, Vec<Cursor>> = HashMap::new();
        let mut legacy_open: Vec<(Cursor, String)> = Vec::new();
        let mut legacy_result = HashMap::new();
        let mut legacy_intent = HashMap::new();
        let (mut first_at, mut last_at) = (u64::MAX, 0u64);
        for e in j.entries() {
            if e.at > 0 {
                first_at = first_at.min(e.at);
                last_at = last_at.max(e.at);
            }
            match &e.event {
                Event::Note { kind, data, .. } if kind == "attempt.start" => {
                    let d = Json::parse(data).unwrap_or(Json::Null);
                    let n = d.get("attempt").and_then(Json::as_u64);
                    if let Some(prev) = attempts.last_mut() {
                        prev.until = Some(e.cursor);
                    }
                    if let Some(n) = n {
                        latest.insert(n, attempts.len());
                    }
                    attempts.push(Attempt {
                        n,
                        start: e.cursor,
                        at: e.at,
                        mode: json_str(&d, "mode", 24),
                        pid: json_str(&d, "pid", 24),
                        host: json_str(&d, "host", 128),
                        principal: json_str(&d, "principal", 128),
                        torn: d.get("torn_bytes").and_then(Json::as_u64).unwrap_or(0),
                        end: None,
                        until: None,
                        repeated: 0,
                        first_repeated: None,
                    });
                }
                Event::Note { kind, data, .. } if kind == "attempt.end" => {
                    let d = Json::parse(data).unwrap_or(Json::Null);
                    let n = d.get("attempt").and_then(Json::as_u64);
                    if let Some(&i) = n.and_then(|n| latest.get(&n)) {
                        attempts[i].end = Some(AttemptEnd {
                            cursor: e.cursor,
                            outcome: json_str(&d, "outcome", 24),
                            fault_kind: json_str(&d, "fault_kind", 48),
                            fault_cursor: d.get("fault_cursor").and_then(Json::as_u64),
                            fresh: d.get("fresh").and_then(Json::as_u64),
                            replayed: d.get("replayed").and_then(Json::as_u64),
                            passthrough: d
                                .get("passthrough_calls")
                                .and_then(Json::as_u64)
                                .unwrap_or(0),
                        });
                    }
                }
                Event::Note { kind, data, .. } if kind == "recovery" => {
                    let d = Json::parse(data).unwrap_or(Json::Null);
                    let decision = d.get("decision").and_then(Json::as_str);
                    if matches!(decision, Some("compensate" | "retry")) {
                        if let Some(a) = attempts.last_mut() {
                            a.repeated += 1;
                            a.first_repeated.get_or_insert(e.cursor);
                        }
                    }
                }
                Event::EffectResult {
                    outcome: EffectOutcome::Compensated,
                    ..
                } => {
                    if let Some(a) = attempts.last_mut() {
                        a.repeated += 1;
                        a.first_repeated.get_or_insert(e.cursor);
                    }
                }
                Event::EffectIntent { name, .. } => {
                    effects_by_name
                        .entry(name.clone())
                        .or_default()
                        .push(e.cursor);
                }
                Event::Legacy(LegacyEvent::EffectIntent { name, .. }) => {
                    legacy_open.push((e.cursor, name.clone()));
                }
                Event::Legacy(
                    LegacyEvent::EffectCommit { name, .. }
                    | LegacyEvent::EffectCompensated { name },
                ) => {
                    if let Some(i) = legacy_open.iter().rposition(|(_, n)| n == name) {
                        let (intent, _) = legacy_open.remove(i);
                        legacy_result.insert(intent, e.cursor);
                        legacy_intent.insert(e.cursor, intent);
                    }
                }
                _ => {}
            }
        }
        let mut read_back = Vec::new();
        for a in &attempts {
            let (Some(n), Some(end)) = (a.n, &a.end) else {
                continue;
            };
            if !matches!(a.mode.as_str(), "run" | "resume") {
                continue;
            }
            let before = completed.partition_point(|&r| r < a.start) as u64;
            if end.replayed == Some(before) && before > 0 {
                read_back.push((a.start, n));
            }
        }
        let multi_day = first_at <= last_at && text::day(first_at) != text::day(last_at);
        Facts {
            results,
            attempts,
            first_result,
            read_back,
            effects_by_name,
            legacy_result,
            legacy_intent,
            multi_day,
            live,
        }
    }

    /// The attempts that read the step at `intent` back from the journal.
    pub fn read_back_by(&self, intent: Cursor) -> Vec<u64> {
        let Some(&r) = self.first_result.get(&intent) else {
            return Vec::new();
        };
        let i = self.read_back.partition_point(|&(s, _)| s <= r);
        self.read_back[i..].iter().map(|&(_, n)| n).collect()
    }

    /// The attempt whose entries include `cursor`.
    pub fn attempt_at(&self, cursor: Cursor) -> Option<&Attempt> {
        let i = self.attempts.partition_point(|a| a.start <= cursor);
        i.checked_sub(1).map(|i| &self.attempts[i])
    }

    /// The next intent of effect `name` after `cursor`.
    fn next_effect(&self, name: &str, after: Cursor) -> Option<Cursor> {
        let list = self.effects_by_name.get(name)?;
        list.get(list.partition_point(|&c| c <= after)).copied()
    }

    /// The format 1 commit or write-off of an effect intent.
    pub fn legacy_result(&self, intent: Cursor) -> Option<Cursor> {
        self.legacy_result.get(&intent).copied()
    }

    /// The format 1 intent a commit or write-off closes.
    pub fn legacy_intent(&self, result: Cursor) -> Option<Cursor> {
        self.legacy_intent.get(&result).copied()
    }

    /// The last attempt, when it has not ended: the run is running, or it
    /// crashed.
    pub fn open_last(&self) -> Option<&Attempt> {
        self.attempts.last().filter(|a| a.end.is_none())
    }
}

/// A row's diamond (see the design: what each marker means).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// On the record and complete.
    Fill,
    /// Complete, and read back by a later attempt.
    Ring,
    /// A boundary, or something waiting.
    Hollow,
    /// An attempt that ended ok.
    Big,
    /// Stopped without an end.
    AlarmHollow,
    /// A recorded failure.
    Alarm,
    /// An attempt that ended with a fault.
    AlarmBig,
    /// Running now (it breathes).
    Breathe,
}

impl Mark {
    fn class(self) -> &'static str {
        match self {
            Mark::Fill => "mk-fill",
            Mark::Ring => "mk-ring",
            Mark::Hollow => "mk-hollow",
            Mark::Big => "mk-big",
            Mark::AlarmHollow => "mk-alarm-hollow",
            Mark::Alarm => "mk-alarm",
            Mark::AlarmBig => "mk-alarm-big",
            Mark::Breathe => "mk-breathe",
        }
    }
}

/// One row of the timeline.
#[derive(Clone, Debug)]
pub struct Row {
    /// The entries of the row on this page, by cursor.
    pub cursors: Vec<Cursor>,
    /// Results of the row's step that are on a later page.
    pub later: Vec<Cursor>,
    /// The title (escaped HTML).
    pub title: String,
    /// The kinds line (escaped HTML).
    pub kinds: String,
    pub mark: Mark,
    /// Lane depth (0 for the root lane and the meta lane).
    pub depth: usize,
    /// A crash row: terracotta rule and wash.
    pub crash: bool,
    /// The step was read back by these attempts.
    pub read_back: Vec<u64>,
}

/// A group of rows: one attempt, or the entries before the first.
#[derive(Clone, Debug, Default)]
pub struct Group {
    /// The label (escaped HTML), or none.
    pub label: Option<String>,
    /// The id the label carries, for links to the group.
    pub id: String,
    pub rows: Vec<Row>,
}

/// What row builders need besides the entry.
pub struct Ctx<'a> {
    pub j: &'a Journal,
    pub facts: &'a Facts,
    pub filter: Option<SlotFilter<'a>>,
    /// The page's range of cursors.
    pub from: Cursor,
    pub end: Cursor,
    /// How to link to a page that starts at a cursor (`?from=`).
    pub link: Option<&'a str>,
}

impl Ctx<'_> {
    /// The entry at `c`, its slots seen through the page's filter.
    pub fn entry(&self, c: Cursor) -> Option<Cow<'_, Entry>> {
        let e = self.j.get(c)?;
        Some(match self.filter {
            Some(f) => Cow::Owned(filtered(e, f)),
            None => Cow::Borrowed(e),
        })
    }

    /// A link to the row holding `c`: on this page, on the page that
    /// starts there, or the bare cursor in a file.
    pub fn cursor(&self, c: Cursor) -> String {
        if c >= self.from && c < self.end {
            format!("<a class=\"m\" href=\"#c{c}\">#{c}</a>")
        } else if let Some(prefix) = self.link {
            format!("<a class=\"m\" href=\"{}{c}#c{c}\">#{c}</a>", esc(prefix))
        } else {
            format!("<span class=\"m\">#{c}</span>")
        }
    }

    fn running(&self, cursor: Cursor) -> bool {
        self.facts.live == Liveness::Running
            && self.facts.open_last().is_some_and(|a| cursor >= a.start)
    }
}

/// An entry with every present slot's content passed through `filter`
/// (fields are structural and shown as they are).
pub fn filtered(e: &Entry, filter: SlotFilter<'_>) -> Entry {
    let f = |c: &Content| match c {
        Content::Sealed(v) => Content::Sealed(pragmatic::Value::new((filter.0)(v.as_bytes()))),
        other => other.clone(),
    };
    let event = match &e.event {
        Event::DrawIntent { provenance, parts } => Event::DrawIntent {
            provenance: provenance.clone(),
            parts: parts.iter().map(f).collect(),
        },
        Event::DrawResult {
            intent,
            meta,
            head,
            body,
        } => Event::DrawResult {
            intent: *intent,
            meta: meta.clone(),
            head: f(head),
            body: f(body),
        },
        Event::ChannelRecv { channel, value } => Event::ChannelRecv {
            channel: channel.clone(),
            value: f(value),
        },
        Event::EffectIntent { name, arg } => Event::EffectIntent {
            name: name.clone(),
            arg: f(arg),
        },
        Event::EffectResult {
            intent,
            outcome,
            error_kind,
            payload,
        } => Event::EffectResult {
            intent: *intent,
            outcome: *outcome,
            error_kind: error_kind.clone(),
            payload: payload.as_ref().map(f),
        },
        Event::Note {
            kind,
            data,
            payload,
        } => Event::Note {
            kind: kind.clone(),
            data: data.clone(),
            payload: payload.iter().map(f).collect(),
        },
        Event::Random {
            source,
            args,
            value,
        } => Event::Random {
            source: source.clone(),
            args: args.clone(),
            value: f(value),
        },
        // No slots (format 1 entries hold no slots either; a server holds
        // only format 2 journals).
        other => other.clone(),
    };
    Entry { event, ..e.clone() }
}

// ---------------------------------------------------------------------------
// Titles
// ---------------------------------------------------------------------------

/// A title under construction: the console's words, data in mono, and
/// accents after a middle dot. Every value is escaped as it is added.
#[derive(Default)]
struct Title(String);

impl Title {
    /// The console's own words (a literal).
    fn words(mut self, w: &str) -> Self {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(&esc(w));
        self
    }

    /// Recorded data, in mono.
    fn data(mut self, d: &str) -> Self {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0
            .push_str(&format!("<span class=\"m\">{}</span>", esc(d)));
        self
    }

    /// The website's drawn arrow ("asks for").
    fn arrow(mut self) -> Self {
        self.0.push_str(
            " <span class=\"ar\" aria-hidden=\"true\"></span><span class=\"sr-only\">asks for</span>",
        );
        self
    }

    /// An italic accent after a middle dot (escaped HTML).
    fn accent(mut self, html: &str) -> Self {
        self.0
            .push_str(&format!(" <span class=\"s\">\u{b7} {html}</span>"));
        self
    }

    /// An italic accent without the dot (escaped HTML).
    fn italic(mut self, html: &str) -> Self {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(&format!("<span class=\"s\">{html}</span>"));
        self
    }

    /// Recorded content after a middle dot: a gist in mono, an excerpt in
    /// the console's quotes, or a state in italic.
    fn gist(mut self, g: &Gist) -> Self {
        self.0.push_str(" <span class=\"s\">\u{b7}</span> ");
        self.0.push_str(&gist_html(g));
        self
    }

    /// Everything so far in terracotta.
    fn alarm(self) -> Self {
        Title(format!("<span class=\"alarm\">{}</span>", self.0))
    }

    fn html(self) -> String {
        self.0
    }
}

/// A gist as HTML.
pub fn gist_html(g: &Gist) -> String {
    match g {
        Gist::Data(d) => format!("<span class=\"m\">{}</span>", esc(d)),
        Gist::Quote(q) => quote(q),
        Gist::State(s) => format!("<span class=\"s\">{}</span>", esc(s)),
    }
}

/// An excerpt of recorded prose in the console's quotes.
pub fn quote(text: &str) -> String {
    format!("<bdi class=\"q\">\u{201c}{}\u{201d}</bdi>", esc(text))
}

/// The tool calls of the SDKs are effects named `tool:<name>`.
fn effect_name(name: &str) -> (&'static str, &str) {
    match name.strip_prefix("tool:") {
        Some(t) if !t.is_empty() => ("Tool call", t),
        _ => ("Effect", name),
    }
}

/// The gist of a slot's content: its state, or what it holds.
fn content_gist(c: &Content, minus: Option<&Json>, limit: usize) -> Gist {
    match c {
        Content::Erased => Gist::State("content erased"),
        Content::Withheld => Gist::State("content withheld"),
        Content::Sealed(v) => gist::gist_bytes(v.as_bytes(), minus, limit),
    }
}

/// An argument's input: the slot as JSON, its envelope unwrapped.
fn input_of(arg: &Content) -> Option<Json> {
    let v = arg.value()?;
    let text = std::str::from_utf8(v.as_bytes()).ok()?;
    Json::parse(text).ok().map(gist::unwrap_argument)
}

fn input_gist(arg: &Content) -> Gist {
    match (arg, input_of(arg)) {
        (Content::Sealed(_), Some(input)) => gist::gist_json(&input, None, GIST),
        _ => content_gist(arg, None, GIST),
    }
}

/// A model call's title from its latest result.
fn draw_title(result: Option<&Entry>, waiting: bool) -> (String, Mark) {
    let Some(Event::DrawResult { meta, body, .. }) = result.map(|r| &r.event) else {
        return if waiting {
            (
                Title::default()
                    .words("Model call")
                    .accent("waiting for the response")
                    .html(),
                Mark::Hollow,
            )
        } else {
            (
                Title::default()
                    .words("Model call")
                    .accent("no response recorded")
                    .html(),
                Mark::AlarmHollow,
            )
        };
    };
    let m = text::draw_meta(meta);
    if m.outcome == "error" {
        let mut t = Title::default().words("Model call failed").alarm();
        if !m.error_kind.is_empty() {
            t = t.gist(&Gist::Data(text::clip(&m.error_kind, 48)));
        }
        if let Some(st) = m.status.filter(|&s| s >= 400) {
            t = t.accent(&format!("HTTP {st}"));
        }
        if !m.error_type.is_empty() {
            t = Title(format!(
                "{} <span class=\"s\">\u{b7}</span> <span class=\"m\">{}</span>",
                t.0,
                esc(&text::clip(&m.error_type, 48))
            ));
        }
        return (t.html(), Mark::Alarm);
    }
    let partial = m.outcome == "partial";
    let mut cut = matches!(m.stop_reason.as_str(), "max_tokens" | "length");
    let mut t = Title::default().words("Model call");
    match body {
        Content::Erased => t = t.arrow().italic("content erased"),
        Content::Withheld => t = t.arrow().italic("content withheld"),
        Content::Sealed(v) => {
            let scanned = pragmatic::redact::binary::scan(v.as_bytes());
            match scanned.text {
                None => {
                    let b = &scanned.binary[0];
                    t = t.gist(&Gist::Data(gist::binary_summary(&b.media_type, b.bytes)));
                }
                Some(body) => {
                    let r = gist::reply(&body);
                    cut |= r.cut;
                    if r.recognised && !r.tools.is_empty() {
                        let names: Vec<String> =
                            r.tools.iter().take(3).map(|n| text::clip(n, 40)).collect();
                        t = t.arrow().data(&names.join(", "));
                        if r.tools.len() > 3 {
                            t = t.italic(&format!("+ {} more", r.tools.len() - 3));
                        }
                    } else if r.recognised {
                        match r.text.as_deref().map(str::trim) {
                            Some(reply) if !reply.is_empty() => {
                                t = t
                                    .arrow()
                                    .italic("reply")
                                    .gist(&Gist::Quote(gist::excerpt(reply, EXCERPT)));
                            }
                            _ if r.streamed => t = t.arrow().italic("streamed reply"),
                            _ => t = t.arrow().italic("reply").gist(&Gist::State("empty")),
                        }
                    } else if body.trim_start().starts_with("event:")
                        || body.trim_start().starts_with("data:")
                    {
                        t = t.arrow().italic("streamed reply");
                    } else if body.trim().is_empty() {
                        t = t.gist(&Gist::State("empty"));
                    } else {
                        // An unrecognised shape: data as a gist, prose as
                        // an excerpt.
                        t = t.gist(&gist::gist_bytes(body.as_bytes(), None, GIST));
                    }
                }
            }
        }
    }
    if cut {
        t = t.accent("cut off at the token limit");
    }
    if partial {
        t = t.accent("stream ended early");
        return (t.html(), Mark::Hollow);
    }
    (t.html(), Mark::Fill)
}

/// A tool call's (or effect's) title from its intent and latest result.
fn effect_title(
    ctx: &Ctx<'_>,
    name: &str,
    arg: &Content,
    result: Option<&Entry>,
    waiting: bool,
) -> (String, Mark) {
    let (what, shown) = effect_name(name);
    let shown = text::clip(shown, 64);
    let base = || Title::default().words(what).data(&shown);
    let Some(Event::EffectResult {
        outcome,
        error_kind,
        payload,
        ..
    }) = result.map(|r| &r.event)
    else {
        return if waiting {
            (
                base().gist(&input_gist(arg)).accent("running").html(),
                Mark::Hollow,
            )
        } else {
            (
                base()
                    .gist(&input_gist(arg))
                    .accent("no result recorded")
                    .html(),
                Mark::AlarmHollow,
            )
        };
    };
    let result_cursor = result.map(|r| r.cursor).unwrap_or(0);
    match outcome {
        EffectOutcome::Ok => {
            let input = input_of(arg);
            let g = match payload {
                Some(Content::Sealed(v)) => {
                    let parsed = std::str::from_utf8(v.as_bytes())
                        .ok()
                        .and_then(|t| Json::parse(t).ok());
                    match parsed.as_ref().and_then(gist::unwrap_result) {
                        Some(tr) if tr.is_error => {
                            let g = match &tr.content {
                                Json::String(s) => Gist::Quote(gist::excerpt(s, GIST)),
                                other => gist::gist_json(other, None, GIST),
                            };
                            let t = base().words("returned an error").alarm().gist(&g);
                            return (t.html(), Mark::Alarm);
                        }
                        Some(tr) => gist::gist_json(&tr.content, input.as_ref(), GIST),
                        None => gist::gist_bytes(v.as_bytes(), input.as_ref(), GIST),
                    }
                }
                Some(c) => content_gist(c, None, GIST),
                None => Gist::State("empty"),
            };
            let g = if g == Gist::State("empty") {
                input_gist(arg)
            } else {
                g
            };
            (base().gist(&g).html(), Mark::Fill)
        }
        EffectOutcome::Failed => {
            let mut t = base().words("failed").alarm();
            if !error_kind.is_empty() {
                t = t.gist(&Gist::Data(text::clip(error_kind, 48)));
            }
            if let Some(p) = payload {
                let g = match p {
                    Content::Sealed(v) => {
                        let s = String::from_utf8_lossy(v.as_bytes());
                        if s.trim().is_empty() {
                            Gist::State("empty")
                        } else {
                            Gist::Quote(gist::excerpt(&s, GIST))
                        }
                    }
                    other => content_gist(other, None, GIST),
                };
                t = t.gist(&g);
            }
            (t.html(), Mark::Alarm)
        }
        EffectOutcome::Compensated => {
            let again = match ctx.facts.next_effect(name, result_cursor) {
                Some(c) => format!(
                    "written off by recovery, performed again at {}",
                    ctx.cursor(c)
                ),
                None => "written off by recovery".to_string(),
            };
            (base().accent(&again).html(), Mark::Hollow)
        }
    }
}

/// The gloss of a known refusal.
fn refusal_gloss(step: &str, fault: &str) -> Option<&'static str> {
    match (step, fault) {
        ("draw", "BudgetExhausted") => Some("over the run's budget"),
        ("effect", "CapabilityDenied") => Some("no capability for it"),
        ("recv", "Timeout") => Some("inbox empty"),
        _ => None,
    }
}

/// `+ N labels` after the first three.
fn labels_accent(d: &Json) -> (Vec<String>, usize) {
    let Some(labels) = d.get("labels").and_then(Json::as_object) else {
        return (Vec::new(), 0);
    };
    let shown = labels
        .iter()
        .take(3)
        .map(|(k, v)| {
            let v = match v {
                Json::String(s) => s.clone(),
                other => other.to_string(),
            };
            format!("{}={}", text::clip(k, 24), text::clip(&v, 32))
        })
        .collect();
    (shown, labels.len().saturating_sub(3))
}

fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The accents of an attempt's start row.
fn attempt_start_title(ctx: &Ctx<'_>, a: &Attempt) -> String {
    let mut t = Title::default().words(&a.title());
    let replayed = a.end.as_ref().and_then(|e| e.replayed);
    let read = replayed.map(|r| plural(r, "step read back", "steps read back"));
    match (a.mode.as_str(), a.n) {
        ("resume", _) => {
            if let Some(r) = read {
                t = t.accent(&esc(&r));
            }
        }
        ("run", Some(n)) if n > 1 => {
            t = t.accent("run again");
            if let Some(r) = read {
                t = t.accent(&esc(&r));
            }
        }
        ("run", _) => t = t.accent("started"),
        (mode, _) => {
            t = Title(format!(
                "{} <span class=\"s\">\u{b7}</span> <span class=\"m\">{}</span>",
                t.0,
                esc(mode)
            ));
            if let Some(r) = read {
                t = t.accent(&esc(&r));
            }
        }
    }
    if a.end.is_some() && a.mode == "resume" || a.end.is_some() && a.n.is_some_and(|n| n > 1) {
        if a.repeated == 0 {
            t = t.accent("nothing repeated");
        } else {
            let what = plural(
                a.repeated as u64,
                "effect performed again",
                "effects performed again",
            );
            let html = match a.first_repeated {
                Some(c) => format!("<a href=\"{}\">{}</a>", cursor_href(ctx, c), esc(&what)),
                None => esc(&what),
            };
            t = t.accent(&html);
        }
    }
    if a.torn > 0 {
        t = t.accent(&esc(&plural(
            a.torn,
            "torn byte cut from the tail",
            "torn bytes cut from the tail",
        )));
    }
    t.html()
}

/// The `href` of a cursor's row.
fn cursor_href(ctx: &Ctx<'_>, c: Cursor) -> String {
    if (c >= ctx.from && c < ctx.end) || ctx.link.is_none() {
        format!("#c{c}")
    } else {
        format!("{}{c}#c{c}", esc(ctx.link.unwrap_or("")))
    }
}

fn attempt_end_title(
    ctx: &Ctx<'_>,
    end: &AttemptEnd,
    a: Option<&Attempt>,
    payload: &[Content],
) -> (String, Mark) {
    let who = a.map(|a| a.title()).unwrap_or_else(|| "Attempt".into());
    match end.outcome.as_str() {
        "ok" => {
            let mut parts = Vec::new();
            if let Some(f) = end.fresh {
                parts.push(format!("{f} fresh"));
            }
            if let Some(r) = end.replayed {
                parts.push(format!("{r} replayed"));
            }
            if end.passthrough > 0 {
                parts.push(format!("{} passed through", end.passthrough));
            }
            let mut t = Title::default().words(&format!("{who} ended ok"));
            if !parts.is_empty() {
                t = t.accent(&esc(&parts.join(", ")));
            }
            (t.html(), Mark::Big)
        }
        "fault" => {
            let mut t = Title::default()
                .words(&format!("{who} ended with a fault"))
                .alarm();
            if !end.fault_kind.is_empty() {
                let at = end
                    .fault_cursor
                    .map(|c| format!(" <span class=\"s\">at</span> {}", ctx.cursor(c)))
                    .unwrap_or_default();
                t = Title(format!(
                    "{} <span class=\"s\">\u{b7}</span> <span class=\"m alarm\">{}</span>{at}",
                    t.0,
                    esc(&end.fault_kind)
                ));
            }
            if let Some(Content::Sealed(v)) = payload.get(1) {
                let s = String::from_utf8_lossy(v.as_bytes());
                if !s.trim().is_empty() {
                    t = t.gist(&Gist::Quote(gist::excerpt(&s, GIST)));
                }
            }
            (t.html(), Mark::AlarmBig)
        }
        other => (
            Title::default()
                .words(&format!("{who} ended"))
                .data(other)
                .html(),
            Mark::Big,
        ),
    }
}

/// A note's title and kinds-line extra, by kind.
fn note_title(
    ctx: &Ctx<'_>,
    e: &Entry,
    kind: &str,
    data: &str,
    payload: &[Content],
) -> (String, String, Mark) {
    let d = Json::parse(data).unwrap_or(Json::Null);
    let s = |k: &str| json_str(&d, k, 64);
    match kind {
        "run.start" => {
            let mut t = Title::default().words("Run started");
            let sdk = format!("{} {}", s("sdk"), s("sdk_version"));
            if !sdk.trim().is_empty() {
                t = t.gist(&Gist::Data(sdk.trim().to_string()));
            }
            let (labels, more) = labels_accent(&d);
            if !labels.is_empty() {
                t = t.gist(&Gist::Data(labels.join(" ")));
            }
            if more > 0 {
                let what = if more == 1 { "label" } else { "labels" };
                t = t.accent(&format!("+ {more} {what}"));
            }
            (t.html(), String::new(), Mark::Hollow)
        }
        "attempt.start" => {
            let a = ctx.facts.attempts.iter().find(|a| a.start == e.cursor);
            let title = match a {
                Some(a) => attempt_start_title(ctx, a),
                None => Title::default().words("Attempt").html(),
            };
            (title, String::new(), Mark::Hollow)
        }
        "attempt.end" => {
            let n = d.get("attempt").and_then(Json::as_u64);
            let a = ctx
                .facts
                .attempts
                .iter()
                .rev()
                .find(|a| a.end.as_ref().is_some_and(|end| end.cursor == e.cursor));
            let end = a.and_then(|a| a.end.clone()).unwrap_or(AttemptEnd {
                cursor: e.cursor,
                outcome: s("outcome"),
                fault_kind: json_str(&d, "fault_kind", 48),
                fault_cursor: d.get("fault_cursor").and_then(Json::as_u64),
                fresh: d.get("fresh").and_then(Json::as_u64),
                replayed: d.get("replayed").and_then(Json::as_u64),
                passthrough: d
                    .get("passthrough_calls")
                    .and_then(Json::as_u64)
                    .unwrap_or(0),
            });
            let fallback;
            let a = match a {
                Some(a) => Some(a),
                None => {
                    fallback = Attempt {
                        n,
                        start: e.cursor,
                        at: e.at,
                        mode: String::new(),
                        pid: String::new(),
                        host: String::new(),
                        principal: String::new(),
                        torn: 0,
                        end: None,
                        until: None,
                        repeated: 0,
                        first_repeated: None,
                    };
                    Some(&fallback)
                }
            };
            let (t, m) = attempt_end_title(ctx, &end, a, payload);
            (t, String::new(), m)
        }
        "program.change" => {
            let at = d
                .get("cursor")
                .and_then(Json::as_u64)
                .map(|c| ctx.cursor(c))
                .unwrap_or_default();
            let mut t = Title::default().words("Program changed");
            if !at.is_empty() {
                t = Title(format!("{} <span class=\"s\">at</span> {at}", t.0));
            }
            let short = |x: String| text::clip(&x, 12).trim_end_matches('\u{2026}').to_string();
            let t = Title(format!(
                "{} <span class=\"s\">\u{b7}</span> <span class=\"m\">{}</span> \
                 <span class=\"ar\" aria-hidden=\"true\"></span><span class=\"sr-only\">to</span> \
                 <span class=\"m\">{}</span>",
                t.0,
                esc(&short(s("from"))),
                esc(&short(s("to")))
            ));
            (t.html(), String::new(), Mark::Fill)
        }
        "recovery" => {
            let name = s("name");
            let (_, shown) = effect_name(&name);
            let extra = format!(
                " \u{b7} for #{} \u{b7} result #{}",
                esc(&s("intent")),
                esc(&s("result"))
            );
            let (t, m) = match s("decision").as_str() {
                "commit" => (
                    Title::default()
                        .words("Recovery recorded a result for")
                        .data(shown),
                    Mark::Fill,
                ),
                "compensate" => {
                    let mut t = Title::default()
                        .words("Recovery wrote off")
                        .data(shown)
                        .accent("it runs again");
                    let saga = s("saga");
                    if !saga.is_empty() {
                        t = Title(format!(
                            "{} <span class=\"s\">\u{b7} saga</span> <span class=\"m\">{}</span>",
                            t.0,
                            esc(&saga)
                        ));
                    }
                    (t, Mark::Hollow)
                }
                "retry" => (
                    Title::default().words("Recovery retries").data(shown),
                    Mark::Hollow,
                ),
                other => (
                    Title::default()
                        .words("Recovery")
                        .data(other)
                        .words("for")
                        .data(shown),
                    Mark::Hollow,
                ),
            };
            (t.html(), extra, m)
        }
        "erasure" => {
            let n = d
                .get("slots")
                .and_then(Json::as_array)
                .map_or(0, |a| a.len()) as u64;
            let mut t = Title::default().words(&format!("Erased {}", plural(n, "slot", "slots")));
            let code = s("reason_code");
            if !code.is_empty() {
                t = Title(format!(
                    "{} <span class=\"s\">\u{b7} reason</span> <span class=\"m\">{}</span>",
                    t.0,
                    esc(&code)
                ));
            }
            let mut extra = format!(" \u{b7} by {}", esc(&s("by")));
            if d.get("authenticated").and_then(Json::as_bool) != Some(true) {
                extra.push_str(" \u{b7} unauthenticated");
            }
            (t.html(), extra, Mark::Fill)
        }
        "custody" => {
            // Counts are numbers; anything else is left out rather than
            // set in the console's words.
            let num = |k: &str| d.get(k).and_then(Json::as_u64);
            let mut t = Title::default()
                .words("Lease custody")
                .gist(&Gist::Data(s("principal")));
            if let (Some(a), Some(b)) = (num("from_entries"), num("to_entries")) {
                let requests = num("requests").unwrap_or(0);
                t = t.accent(&esc(&format!(
                    "entries {a} to {b}, {}",
                    plural(requests, "request", "requests")
                )));
            }
            if d.get("clock_skew").and_then(Json::as_bool) == Some(true) {
                t = t.accent("clock skew flagged");
            }
            (t.html(), String::new(), Mark::Fill)
        }
        "torn_tail" => {
            let num = |k: &str| d.get(k).and_then(Json::as_u64);
            let mut t = Title::default().words("Torn tail moved aside");
            if let (Some(bytes), Some(offset)) = (num("bytes"), num("offset")) {
                t = t.accent(&esc(&format!(
                    "{} at offset {}",
                    plural(bytes, "byte", "bytes"),
                    text::count(offset)
                )));
            }
            (t.html(), String::new(), Mark::Fill)
        }
        other => {
            let g = match Json::parse(data) {
                Ok(doc) => gist::gist_json(&doc, None, GIST),
                Err(_) => Gist::Quote(gist::excerpt(data, GIST)),
            };
            let t = Title::default()
                .words("Note")
                .data(&text::clip(other, 32))
                .gist(&g);
            (t.html(), String::new(), Mark::Fill)
        }
    }
}

/// The title of a clock read: the time it read, with its date when that
/// is not the day of the entry.
fn clock_title(nanos: u64, at: u64) -> String {
    let when = if at > 0 && text::day(nanos) == text::day(at) {
        format!("{} UTC", text::clock_ms(nanos))
    } else {
        format!("{}, {} UTC", text::day(nanos), text::clock_ms(nanos))
    };
    Title::default()
        .words("Clock read")
        .gist(&Gist::Data(when))
        .html()
}

/// `randint(1, 6) = 4`.
fn random_title(source: &str, args: &str, value: &Content) -> String {
    let args = match Json::parse(args) {
        Ok(Json::Array(items)) => items
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        Ok(other) => other.to_string(),
        Err(_) => args.to_string(),
    };
    let value = match content_gist(value, None, 24) {
        Gist::Data(d) => d,
        Gist::Quote(q) => format!("\"{q}\""),
        Gist::State(s) => s.to_string(),
    };
    let call = format!(
        "{}({}) = {}",
        text::clip(source, 24),
        text::clip(&args, 24),
        value
    );
    Title::default()
        .words("Random draw")
        .gist(&Gist::Data(call))
        .html()
}

// ---------------------------------------------------------------------------
// Building rows
// ---------------------------------------------------------------------------

/// The lane depth of an entry: its branch's depth, or 0 on the meta lane.
fn depth(e: &Entry) -> usize {
    if e.branch == META {
        0
    } else {
        e.branch.len()
    }
}

/// The kinds-line prefix of a nested lane.
fn lane_prefix(e: &Entry) -> String {
    if e.branch == META || e.branch.is_empty() {
        String::new()
    } else {
        format!("branch {} \u{b7} ", esc(&text::branch_label(&e.branch)))
    }
}

fn kind_of(e: &Entry) -> String {
    format!("{} #{}", esc(&text::label(&e.event)), e.cursor)
}

/// A group's label: `Attempt 1 · run · pid 9919`. Mode and pid pass
/// through the stylesheet's capitals only when they are a closed
/// vocabulary or digits; anything else keeps its case.
pub fn group_label(a: &Attempt) -> String {
    let mut out = esc(&a.title());
    if !a.mode.is_empty() {
        if a.mode.len() <= 16 && a.mode.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            out.push_str(&format!(" \u{b7} {}", a.mode));
        } else {
            out.push_str(&format!(
                " \u{b7} <span class=\"nc\">{}</span>",
                esc(&a.mode)
            ));
        }
    }
    if !a.pid.is_empty() {
        if a.pid.len() <= 12 && a.pid.bytes().all(|b| b.is_ascii_digit()) {
            out.push_str(&format!(" \u{b7} pid {}", a.pid));
        } else {
            out.push_str(&format!(
                " \u{b7} pid <span class=\"nc\">{}</span>",
                esc(&a.pid)
            ));
        }
    }
    out
}

/// The crash row of an attempt with no end that a later attempt followed.
fn crash_row(ctx: &Ctx<'_>, a: &Attempt, next_start: Cursor) -> Row {
    let last = next_start.saturating_sub(1);
    let mut t = Title::default().words("No end: crashed").accent(&format!(
        "{} stopped after {}",
        esc(&a.name()),
        ctx.cursor(last)
    ));
    if let Some(e) = ctx.entry(last) {
        let open = match &e.event {
            Event::DrawIntent { .. } | Event::EffectIntent { .. } => !ctx
                .facts
                .results
                .get(&last)
                .is_some_and(|rs| rs.iter().any(|&r| r < next_start)),
            _ => false,
        };
        if open {
            let during = match &e.event {
                Event::EffectIntent { name, .. } => {
                    let (what, shown) = effect_name(name);
                    format!(
                        "during <span class=\"rm\">{what}</span> <span class=\"m\">{}</span>",
                        esc(&text::clip(shown, 64))
                    )
                }
                _ => "during <span class=\"rm\">Model call</span>".to_string(),
            };
            t = t.accent(&during);
        }
    }
    Row {
        cursors: Vec::new(),
        later: Vec::new(),
        title: t.html(),
        kinds: format!("no note.attempt.end for {}", esc(&a.name())),
        mark: Mark::AlarmHollow,
        depth: 0,
        crash: true,
        read_back: Vec::new(),
    }
}

/// The row at the end of a run whose last attempt has not ended.
fn open_end_row(ctx: &Ctx<'_>, a: &Attempt) -> Row {
    let last = ctx.j.len().saturating_sub(1);
    let (title, mark, crash) = match ctx.facts.live {
        Liveness::Running => (
            Title::default()
                .words("Running")
                .accent(&format!("{} holds the lease", esc(&a.name())))
                .accent("refresh to follow")
                .html(),
            Mark::Breathe,
            false,
        ),
        Liveness::Stopped | Liveness::Dangling => {
            let mut t = Title::default().words("No end: crashed").accent(&format!(
                "{} stopped after {}",
                esc(&a.name()),
                ctx.cursor(last)
            ));
            if ctx.facts.live == Liveness::Dangling {
                t = t.accent("an effect was left open");
            }
            (t.html(), Mark::AlarmHollow, true)
        }
        Liveness::Unknown => (
            Title::default()
                .words("No end yet")
                .accent("running, or crashed; refresh to see whether it continues")
                .html(),
            Mark::Hollow,
            false,
        ),
    };
    Row {
        cursors: Vec::new(),
        later: Vec::new(),
        title,
        kinds: format!("no note.attempt.end for {} yet", esc(&a.name())),
        mark,
        depth: 0,
        crash,
        read_back: Vec::new(),
    }
}

/// The groups and rows of a page, from its entries (`page`, already
/// filtered, cursors `ctx.from` to `ctx.end`).
pub fn build(ctx: &Ctx<'_>, page: &[Entry]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    // A page that starts inside an attempt continues its group.
    let first = match ctx.facts.attempt_at(ctx.from) {
        Some(a) if a.start < ctx.from => Group {
            label: Some(format!(
                "{} <span class=\"nc s\">(continued)</span>",
                group_label(a)
            )),
            id: format!("a{}", a.start),
            rows: Vec::new(),
        },
        _ => Group::default(),
    };
    groups.push(first);
    let mut done = vec![false; page.len()];
    let index = |c: Cursor| -> Option<usize> {
        (c >= ctx.from && c < ctx.from + page.len() as u64).then(|| (c - ctx.from) as usize)
    };
    for i in 0..page.len() {
        if done[i] {
            continue;
        }
        done[i] = true;
        let e = &page[i];
        // A new attempt opens a group, after the crash row of the one
        // before it when that one has no end.
        let starts = match &e.event {
            Event::Note { kind, .. } if kind == "attempt.start" => Some(e.cursor),
            Event::Note { kind, .. } if kind == "run.start" => page
                .get(i + 1)
                .filter(|n| {
                    n.cursor == e.cursor + 1 && n.event.note_kind() == Some("attempt.start")
                })
                .map(|n| n.cursor),
            _ => None,
        };
        if let Some(start) = starts {
            let prev = ctx
                .facts
                .attempts
                .iter()
                .position(|a| a.start == start)
                .and_then(|k| k.checked_sub(1))
                .map(|k| &ctx.facts.attempts[k]);
            if let Some(p) = prev.filter(|p| p.end.is_none()) {
                let row = crash_row(ctx, p, start);
                if let Some(g) = groups.last_mut() {
                    g.rows.push(row);
                }
            }
            let a = ctx.facts.attempts.iter().find(|a| a.start == start);
            groups.push(Group {
                label: a.map(group_label),
                id: format!("a{start}"),
                rows: Vec::new(),
            });
        }
        let row = row_of(ctx, page, e, &mut done, index);
        if let Some(g) = groups.last_mut() {
            g.rows.push(row);
        }
    }
    // The end of the run: its last attempt has not ended.
    if ctx.end >= ctx.j.len() {
        if let Some(a) = ctx.facts.open_last() {
            let row = open_end_row(ctx, a);
            if let Some(g) = groups.last_mut() {
                g.rows.push(row);
            }
        }
    }
    groups.retain(|g| g.label.is_some() || !g.rows.is_empty());
    groups
}

/// The row that starts with entry `e` (marking every entry it takes).
fn row_of(
    ctx: &Ctx<'_>,
    page: &[Entry],
    e: &Entry,
    done: &mut [bool],
    index: impl Fn(Cursor) -> Option<usize>,
) -> Row {
    let mut row = Row {
        cursors: vec![e.cursor],
        later: Vec::new(),
        title: String::new(),
        kinds: format!("{}{}", lane_prefix(e), kind_of(e)),
        mark: Mark::Fill,
        depth: depth(e),
        crash: false,
        read_back: Vec::new(),
    };
    // Join a step's results on this page; note those on later pages.
    let join_results = |row: &mut Row, intent: Cursor, done: &mut [bool]| {
        let rs = ctx.facts.results.get(&intent).cloned().unwrap_or_default();
        for r in rs {
            if r <= row.cursors[0] {
                continue;
            }
            match index(r) {
                Some(k) => {
                    if !done[k] {
                        done[k] = true;
                        row.cursors.push(r);
                        row.kinds
                            .push_str(&format!(" \u{b7} {}", kind_of(&page[k])));
                    }
                }
                None => {
                    row.later.push(r);
                    row.kinds.push_str(&format!(" \u{b7} result #{r}"));
                }
            }
        }
    };
    let latest = |intent: Cursor| -> Option<Cow<'_, Entry>> {
        let r = *ctx.facts.results.get(&intent)?.last()?;
        ctx.entry(r)
    };
    match &e.event {
        Event::DrawIntent { .. } => {
            join_results(&mut row, e.cursor, done);
            let r = latest(e.cursor);
            let (t, m) = draw_title(r.as_deref(), ctx.running(e.cursor));
            row.title = t;
            row.mark = m;
            mark_read_back(ctx, &mut row, e.cursor);
        }
        Event::EffectIntent { name, arg } => {
            join_results(&mut row, e.cursor, done);
            let r = latest(e.cursor);
            let (t, m) = effect_title(ctx, name, arg, r.as_deref(), ctx.running(e.cursor));
            row.title = t;
            row.mark = m;
            mark_read_back(ctx, &mut row, e.cursor);
        }
        Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } => {
            let intent_entry = ctx.entry(*intent);
            let is_draw = matches!(e.event, Event::DrawResult { .. });
            let matched = match intent_entry.as_deref().map(|i| &i.event) {
                Some(Event::DrawIntent { .. }) => is_draw,
                Some(Event::EffectIntent { .. }) => !is_draw,
                _ => false,
            };
            if !matched || *intent >= e.cursor {
                row.title = Title::default()
                    .words("Result for")
                    .data(&format!("#{intent}"))
                    .accent("no matching intent")
                    .html();
                row.mark = Mark::AlarmHollow;
                return row;
            }
            // Its intent is on an earlier page: the row starts here, with
            // every later result of the same step on this page.
            let rs = ctx.facts.results.get(intent).cloned().unwrap_or_default();
            for r in rs {
                if r <= e.cursor {
                    continue;
                }
                match index(r) {
                    Some(k) if !done[k] => {
                        done[k] = true;
                        row.cursors.push(r);
                        row.kinds
                            .push_str(&format!(" \u{b7} {}", kind_of(&page[k])));
                    }
                    Some(_) => {}
                    None => {
                        row.later.push(r);
                        row.kinds.push_str(&format!(" \u{b7} result #{r}"));
                    }
                }
            }
            let r = latest(*intent);
            let (t, m) = match intent_entry.as_deref().map(|i| &i.event) {
                Some(Event::EffectIntent { name, arg }) => {
                    effect_title(ctx, name, arg, r.as_deref(), false)
                }
                _ => draw_title(r.as_deref(), false),
            };
            row.title = format!(
                "{t} <span class=\"s\">\u{b7} its intent, {}, is on an earlier page</span>",
                ctx.cursor(*intent)
            );
            row.mark = m;
            mark_read_back(ctx, &mut row, *intent);
        }
        Event::Note {
            kind,
            data,
            payload,
        } => {
            if kind == "run.start" {
                if let Some(n) = page
                    .get(index(e.cursor).unwrap_or(0) + 1)
                    .filter(|n| n.cursor == e.cursor + 1)
                    .filter(|n| n.event.note_kind() == Some("attempt.start"))
                {
                    if let Some(k) = index(n.cursor) {
                        done[k] = true;
                    }
                    row.cursors.push(n.cursor);
                    row.kinds.push_str(&format!(" \u{b7} {}", kind_of(n)));
                }
            }
            let (t, extra, m) = note_title(ctx, e, kind, data, payload);
            row.title = t;
            row.kinds.push_str(&extra);
            row.mark = m;
        }
        Event::ChannelRecv { channel, value } => {
            row.title = Title::default()
                .words("Received on")
                .data(&text::clip(channel, 48))
                .gist(&content_gist(value, None, GIST))
                .html();
        }
        Event::Clock { nanos } => row.title = clock_title(*nanos, e.at),
        Event::Random {
            source,
            args,
            value,
        } => row.title = random_title(source, args, value),
        Event::Program { name, hash } => {
            row.title = Title::default()
                .words("Program")
                .data(&text::clip(name, 48))
                .gist(&Gist::Data(
                    text::clip(hash, 12)
                        .trim_end_matches('\u{2026}')
                        .to_string(),
                ))
                .html();
        }
        Event::Fork { base, children } => {
            row.title = Title::default()
                .words("Parallel region")
                .accent(&esc(&plural(u64::from(*children), "branch", "branches")))
                .html();
            let child = |k: u32| {
                let mut b = if e.branch == META {
                    Vec::new()
                } else {
                    e.branch.clone()
                };
                b.push(k);
                text::branch_label(&b)
            };
            if *children > 0 {
                let last = base.saturating_add(children - 1);
                if *children == 1 {
                    row.kinds
                        .push_str(&format!(" \u{b7} branch {}", esc(&child(*base))));
                } else {
                    row.kinds.push_str(&format!(
                        " \u{b7} branches {} to {}",
                        esc(&child(*base)),
                        esc(&child(last))
                    ));
                }
            }
        }
        Event::Marker { name } => {
            row.title = Title::default()
                .words("Patch taken")
                .gist(&Gist::Data(text::clip(name, 48)))
                .html();
        }
        Event::Refusal { step, name, fault } => {
            let fault_c = text::clip(fault, 32);
            let t = match step.as_str() {
                "draw" => Title::default().words("Model call refused"),
                "effect" => {
                    let (what, shown) = effect_name(name);
                    Title::default()
                        .words(what)
                        .data(&text::clip(shown, 48))
                        .words("refused")
                }
                "recv" => Title::default()
                    .words("Receive on")
                    .data(&text::clip(name, 48))
                    .words("refused"),
                other => {
                    let mut t = Title::default().words("Step").data(&text::clip(other, 16));
                    if !name.is_empty() {
                        t = t.data(&text::clip(name, 48));
                    }
                    t.words("refused")
                }
            };
            let mut t = t.alarm().gist(&Gist::Data(fault_c));
            if let Some(g) = refusal_gloss(step, fault) {
                t = t.accent(g);
            }
            row.title = t.html();
            row.mark = Mark::Alarm;
        }
        Event::Legacy(l) => legacy_row(ctx, page, e, l, &mut row, done, &index),
        other => {
            row.title = Title::default().words(other.kind_name()).html();
        }
    }
    row
}

fn mark_read_back(ctx: &Ctx<'_>, row: &mut Row, intent: Cursor) {
    let by = ctx.facts.read_back_by(intent);
    if !by.is_empty() && row.mark == Mark::Fill {
        row.mark = Mark::Ring;
    }
    row.read_back = by;
}

/// A format 1 entry's row; an effect intent takes its commit or write-off.
fn legacy_row(
    ctx: &Ctx<'_>,
    page: &[Entry],
    e: &Entry,
    l: &LegacyEvent,
    row: &mut Row,
    done: &mut [bool],
    index: &impl Fn(Cursor) -> Option<usize>,
) {
    let value_gist = |v: &pragmatic::Value| gist::gist_bytes(v.as_bytes(), None, GIST);
    match l {
        LegacyEvent::OracleDraw { outcome, .. } => {
            let text = String::from_utf8_lossy(outcome.as_bytes());
            let g = if text.trim().is_empty() {
                Gist::State("empty")
            } else {
                Gist::Quote(gist::excerpt(&text, EXCERPT))
            };
            row.title = Title::default().words("Model call").gist(&g).html();
        }
        LegacyEvent::EffectIntent { name, arg } => {
            let (what, shown) = effect_name(name);
            let base = Title::default().words(what).data(&text::clip(shown, 64));
            let result = ctx.facts.legacy_result(e.cursor);
            if let Some(r) = result {
                match index(r) {
                    Some(k) => {
                        done[k] = true;
                        row.cursors.push(r);
                        row.kinds
                            .push_str(&format!(" \u{b7} {}", kind_of(&page[k])));
                    }
                    None => {
                        row.later.push(r);
                        row.kinds.push_str(&format!(" \u{b7} result #{r}"));
                    }
                }
            }
            let result = result.and_then(|r| ctx.j.get(r));
            (row.title, row.mark) = match result.map(|r| &r.event) {
                Some(Event::Legacy(LegacyEvent::EffectCommit { result, .. })) => {
                    (base.gist(&value_gist(result)).html(), Mark::Fill)
                }
                Some(Event::Legacy(LegacyEvent::EffectCompensated { .. })) => {
                    (base.accent("written off").html(), Mark::Hollow)
                }
                _ => (
                    base.gist(&value_gist(arg))
                        .accent("no result recorded")
                        .html(),
                    Mark::AlarmHollow,
                ),
            };
        }
        LegacyEvent::EffectCommit { name, result } => {
            let (what, shown) = effect_name(name);
            let mut t = Title::default()
                .words(what)
                .data(&text::clip(shown, 64))
                .gist(&value_gist(result));
            match ctx.facts.legacy_intent(e.cursor) {
                Some(i) => {
                    t = t.accent(&format!(
                        "its intent, {}, is on an earlier page",
                        ctx.cursor(i)
                    ))
                }
                None => t = t.accent("no matching intent"),
            }
            row.title = t.html();
        }
        LegacyEvent::EffectCompensated { name } => {
            let (what, shown) = effect_name(name);
            row.title = Title::default()
                .words(what)
                .data(&text::clip(shown, 64))
                .accent("written off")
                .html();
            row.mark = Mark::Hollow;
        }
        LegacyEvent::ChannelRecv { channel, value } => {
            row.title = Title::default()
                .words("Received on")
                .data(&text::clip(channel, 48))
                .gist(&value_gist(value))
                .html();
        }
        LegacyEvent::Clock { nanos } => row.title = clock_title(*nanos, e.at),
        LegacyEvent::Program { name, hash } => {
            row.title = Title::default()
                .words("Program")
                .data(&text::clip(name, 48))
                .gist(&Gist::Data(
                    text::clip(hash, 12)
                        .trim_end_matches('\u{2026}')
                        .to_string(),
                ))
                .html();
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The HTML of the groups, each row's detail panel made of its entries'
/// sections (`section(cursor)`).
pub fn render(ctx: &Ctx<'_>, groups: &[Group], section: &dyn Fn(Cursor) -> String) -> String {
    let mut out = String::new();
    let mut last_day = String::new();
    for g in groups {
        match &g.label {
            Some(label) => out.push_str(&format!(
                "<section class=\"grp\" aria-labelledby=\"{id}\"><h3 class=\"grp-label caps\" id=\"{id}\">{label}</h3><ol class=\"rows\">",
                id = esc(&g.id)
            )),
            None => out.push_str("<section class=\"grp\"><ol class=\"rows\">"),
        }
        for row in &g.rows {
            if ctx.facts.multi_day {
                if let Some(at) = row
                    .cursors
                    .first()
                    .and_then(|&c| ctx.j.get(c))
                    .map(|e| e.at)
                    .filter(|&a| a > 0)
                {
                    let d = text::day(at);
                    if d != last_day {
                        out.push_str(&format!(
                            "<li class=\"grp-label caps\" aria-hidden=\"true\">{}</li>",
                            esc(&d)
                        ));
                        last_day = d;
                    }
                }
            }
            out.push_str(&row_html(ctx, row, section));
        }
        out.push_str("</ol></section>");
    }
    out
}

fn row_html(ctx: &Ctx<'_>, row: &Row, section: &dyn Fn(Cursor) -> String) -> String {
    let d = row.depth.min(6);
    let mut class = format!("row {}", row.mark.class());
    if d > 0 {
        class.push_str(&format!(" d{d}"));
    }
    if row.crash {
        class.push_str(" crash");
    }
    if row.cursors.is_empty() {
        class.push_str(" derived");
        return format!(
            "<li class=\"{class}\"><div class=\"sum\"><span class=\"t\">{}</span>\
             <span class=\"k\">{}</span></div></li>\n",
            row.title, row.kinds
        );
    }
    let anchors: String = row
        .cursors
        .iter()
        .map(|c| format!("<span id=\"c{c}\"></span>"))
        .collect();
    let first = ctx.j.get(row.cursors[0]);
    let last = row.cursors.last().and_then(|&c| ctx.j.get(c));
    let at = first.map(|e| e.at).unwrap_or(0);
    let (tm, tm_words) = if at > 0 {
        let t = text::clock_ms(at);
        (t.clone(), format!("began {t} UTC, "))
    } else {
        (String::new(), String::new())
    };
    let hash = last.map(|e| hex_encode(&e.hash)).unwrap_or_default();
    let h10 = hash.get(..10).unwrap_or("");
    let sections: String = row.cursors.iter().map(|&c| section(c)).collect();
    let mut notes = String::new();
    if !row.read_back.is_empty() {
        let by: Vec<String> = row.read_back.iter().map(u64::to_string).collect();
        let who = if by.len() == 1 {
            format!("attempt {}", by[0])
        } else {
            format!("attempts {}", by.join(" and "))
        };
        notes.push_str(&format!(
            "<p class=\"ent-w\">Read back by {who}: replayed from the journal, not repeated.</p>"
        ));
    }
    if !row.later.is_empty() {
        let links: Vec<String> = row.later.iter().map(|&c| ctx.cursor(c)).collect();
        notes.push_str(&format!(
            "<p class=\"ent-w\">Recorded on a later page: {}.</p>",
            links.join(", ")
        ));
    }
    let notes = if notes.is_empty() {
        notes
    } else {
        format!("<div class=\"ent\">{notes}</div>")
    };
    format!(
        "<li class=\"{class}\"><details><summary class=\"sum\">{anchors}\
         <span class=\"t\"><span class=\"tt\">{title}</span></span>\
         <span class=\"tm\" aria-hidden=\"true\">{tm}</span>\
         <span class=\"k\">{kinds}</span>\
         <span class=\"h\" title=\"{hash}\" aria-hidden=\"true\">{h10}</span>\
         <span class=\"sr-only\">, {tm_words}entry hash {h10}. Show the recorded entries.</span>\
         </summary><div class=\"detail\">{notes}{sections}</div></details></li>\n",
        title = row.title,
        kinds = row.kinds,
    )
}
