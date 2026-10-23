//! The console's pages (design 4.14), rendered with `pragmatic-console`,
//! the renderer the CLI uses too, so a run looks the same wherever it is
//! read, and in the same design as the website: warm paper and ink, EB
//! Garamond for words and IBM Plex Mono for data, the brand's diamond as
//! the only icon, and terracotta kept for trouble.
//!
//! - The run page is `pragmatic-console`'s run view (the run sheet with
//!   its timeline a page at a time, and the Anchoring, Evidence check and
//!   Run cards), with the run's status and holds, its anchoring
//!   (independent, or the operator's own signature only), its evidence
//!   downloads and, for administrators, the erasure disclosure. A viewer
//!   without `view_raw` sees every slot through the server's redaction.
//! - The runs list speaks the run page's language: a row per run with its
//!   state diamond, id, a sentence of its state, and its time and head.
//! - The access log, holds and retention, and tokens are tables on leaves
//!   in the same frame.
//! - Every action that cannot be undone (erasure, removing a hold,
//!   revoking a token, running retention) shows a confirmation first.
//! - Sign-in and errors are single cards in the middle of the page.
//!
//! Every page carries a Content-Security-Policy that runs no script, loads
//! nothing but the console's own fonts, and lets forms submit only to the
//! console itself. Every value that comes from a journal, a token, a hold
//! or a request is escaped. Every form that changes something carries the
//! session's CSRF token.

use pragmatic_console::fonts::Fonts;
use pragmatic_console::html::{
    command, diamond, document, empty, esc, masthead, mono, notice, solo_card, tag, Crumb, Frame,
    Page, CONSOLE_POLICY, MARK,
};
use pragmatic_console::{render_run_page, text, RunView, ServerRun, SlotFilter};
use serde_json::Value as JsonValue;

use crate::hooks::{
    ConsoleConfirm, ConsoleError, ConsoleNotice, ConsolePage, ConsoleRenderer, ConsoleViewer,
};
use crate::redaction::Redacted;

/// Where the console serves its fonts.
pub const ASSETS: &str = "/console/assets/";

/// The console renderer. See the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleUi;

impl ConsoleRenderer for ConsoleUi {
    fn render(&self, page: &ConsolePage<'_>) -> Result<String, ConsoleError> {
        Ok(match page {
            ConsolePage::SignIn {
                error,
                notice,
                licensee,
                csrf,
            } => sign_in(*error, *notice, licensee, csrf),
            ConsolePage::Runs {
                viewer,
                runs,
                next,
                filters,
            } => runs_page(viewer, runs, *next, filters),
            ConsolePage::Run {
                viewer,
                run_id,
                summary,
                journal,
                report,
                anchor,
                from,
                redactor,
                principals,
                notice,
            } => {
                let path = format!("/console/runs/{}", encode(run_id));
                let link = format!("{path}?from=");
                let (nav, footer) = chrome(viewer, "runs");
                let frame = frame(&nav, &footer);
                let filter_fn = |bytes: &[u8]| -> Vec<u8> {
                    match redactor.map(|r| r.redact_slot(bytes)) {
                        Some(Redacted::Text(t)) => t.into_bytes(),
                        Some(Redacted::Binary(b)) => b.placeholder().into_bytes(),
                        None => bytes.to_vec(),
                    }
                };
                let status = text_of(&summary["status"]);
                let holds = summary["holds"].as_array().map_or(0, Vec::len);
                let notices = notice_html(*notice);
                let evidence = evidence_foot(viewer, &path, run_id);
                let erase = erase_card(viewer, &path);
                let server = ServerRun {
                    status: &status,
                    holds,
                    holds_href: (viewer.role == "admin").then_some("/console/holds"),
                    notices: &notices,
                    evidence: evidence.as_deref(),
                    erase: erase.as_deref(),
                    principals,
                };
                let view = RunView {
                    anchor: *anchor,
                    source: Some("Stet Server"),
                    from: *from,
                    page_link: Some(&link),
                    frame: Some(&frame),
                    filter: redactor.map(|_| SlotFilter(&filter_fn)),
                    server: Some(server),
                    ..RunView::new(run_id, journal, report)
                };
                render_run_page(&view).html
            }
            ConsolePage::AccessLog {
                viewer,
                records,
                next,
            } => access_page(viewer, records, *next),
            ConsolePage::Holds {
                viewer,
                holds,
                retention,
                notice,
            } => holds_page(viewer, holds, retention, *notice),
            ConsolePage::Tokens {
                viewer,
                tokens,
                issued,
                notice,
            } => tokens_page(viewer, tokens, *issued, *notice),
            ConsolePage::Confirm {
                viewer,
                action,
                back,
                confirm,
            } => confirm_page(viewer, action, back, confirm),
            ConsolePage::Error {
                viewer,
                licensee,
                status,
                code,
                run_id,
                form,
            } => error_page(*viewer, licensee, *status, code, *run_id, *form),
        })
    }
}

/// What a path segment keeps unencoded: the run id alphabet's
/// punctuation, so links read like the ids they name.
const SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b':');

/// A path segment, percent-encoded.
pub fn encode(segment: &str) -> String {
    percent_encoding::utf8_percent_encode(segment, SEGMENT).to_string()
}

/// A query value, form-encoded.
fn query_value(v: &str) -> String {
    form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

/// The hidden CSRF field of a form.
fn csrf_field(csrf: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        esc(csrf)
    )
}

/// The frame of every console page.
fn frame<'a>(nav: &'a str, footer: &'a str) -> Frame<'a> {
    Frame {
        csp: CONSOLE_POLICY,
        fonts: Fonts::Served(ASSETS),
        home: Some("/console"),
        nav,
        footer,
    }
}

/// The role in words.
fn role_words(role: &str) -> String {
    match role {
        "witness_client" => "witness client".to_string(),
        other => text::clip(other, 24),
    }
}

/// The navigation (with the current section marked) and the footer of a
/// signed-in viewer's pages.
fn chrome(viewer: &ConsoleViewer, current: &str) -> (String, String) {
    let mut items = vec![("runs", "/console", "Runs")];
    if viewer.role == "admin" || viewer.role == "auditor" {
        items.push(("access", "/console/access", "Access log"));
    }
    if viewer.role == "admin" {
        items.push(("holds", "/console/holds", "Holds and retention"));
        items.push(("tokens", "/console/tokens", "Tokens"));
    }
    let links: String = items
        .iter()
        .map(|(key, href, words)| {
            let cur = if *key == current {
                " aria-current=\"page\""
            } else {
                ""
            };
            format!("<a href=\"{href}\"{cur}>{words}</a>")
        })
        .collect();
    let nav = format!(
        "<nav class=\"nav\" aria-label=\"Console\">{links}</nav>\
         <form class=\"out\" method=\"post\" action=\"/console/sign-out\">{}\
         <button class=\"lkb\" type=\"submit\">Sign out</button></form>",
        csrf_field(&viewer.csrf)
    );
    let raw = if viewer.view_raw {
        "content shown raw"
    } else {
        "content redacted"
    };
    let mut footer = format!(
        "Signed in as {} ({}, {raw})",
        mono(&text::clip(&viewer.name, 64)),
        esc(&role_words(&viewer.role)),
    );
    let licensee = licensee_text(&viewer.licensee);
    if !licensee.is_empty() {
        footer.push_str(&format!(" \u{b7} {licensee}"));
    }
    (nav, footer)
}

/// "Licensed to Example Corp", or nothing when no licensee is configured:
/// the console's own chrome does not carry a configuration note.
fn licensee_text(licensee: &str) -> String {
    if licensee.is_empty() {
        String::new()
    } else {
        format!("Licensed to {}", esc(&text::clip(licensee, 120)))
    }
}

/// A page in the viewer's frame.
fn framed(
    viewer: &ConsoleViewer,
    current: &str,
    title: &str,
    crumbs: &[Crumb<'_>],
    main: String,
) -> String {
    let (nav, footer) = chrome(viewer, current);
    let frame = frame(&nav, &footer);
    document(
        &frame,
        &Page {
            title,
            masthead: masthead(frame.home, crumbs, frame.nav),
            main,
            skip: Some(("main", "Skip to content")),
            ..Page::default()
        },
    )
}

fn notice_html(n: Option<&ConsoleNotice>) -> String {
    let Some(n) = n else {
        return String::new();
    };
    let mut html = esc(&n.text);
    if let Some(code) = &n.code {
        html = format!("{html} {}.", mono(code));
    }
    notice(&html, n.refused)
}

fn text_of(v: &JsonValue) -> String {
    match v {
        JsonValue::Null => String::new(),
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A JSON value as table text, clipped and with control characters
/// escaped, then escaped for HTML.
fn cell(v: &JsonValue, width: usize) -> String {
    esc(&text::clip(&text_of(v), width))
}

fn this_year() -> String {
    pragmatic::evidence::time::now_rfc3339()
        .get(..4)
        .unwrap_or("")
        .to_string()
}

/// A table on a leaf: its caption, heads (`(words, right-aligned)`), rows
/// and an optional foot (escaped HTML).
fn table(caption: &str, heads: &[(&str, bool)], rows: &str, foot: &str) -> String {
    let heads: String = heads
        .iter()
        .map(|(h, right)| {
            let class = if *right { "caps r" } else { "caps" };
            if h.is_empty() {
                format!("<th class=\"{class}\"><span class=\"sr-only\">State</span></th>")
            } else {
                format!("<th class=\"{class}\" scope=\"col\">{}</th>", esc(h))
            }
        })
        .collect();
    format!(
        "<div class=\"tscroll\"><table class=\"stack\"><caption class=\"sr-only\">{}</caption>\
         <thead><tr>{heads}</tr></thead><tbody>{rows}</tbody></table></div>{foot}",
        esc(caption)
    )
}

// ---------------------------------------------------------------------------
// Sign in
// ---------------------------------------------------------------------------

fn sign_in(error: Option<&str>, note: Option<&str>, licensee: &str, csrf: &str) -> String {
    let frame = frame("", "");
    let mut main = String::new();
    if let Some(n) = note {
        main.push_str(&notice(&esc(n), false));
    }
    let err = error
        .map(|e| {
            format!(
                "<p class=\"err-line\" id=\"token-err\" role=\"alert\">{}{}</p>",
                diamond(false, true),
                esc(e)
            )
        })
        .unwrap_or_default();
    let invalid = if error.is_some() {
        " aria-invalid=\"true\" aria-describedby=\"token-err\""
    } else {
        ""
    };
    main.push_str(&format!(
        "<section class=\"solo w420\" aria-labelledby=\"sign-in\">\
         <div class=\"lockup\">{MARK}<span>Stet</span></div>\
         <p class=\"lockup-sub\">Server console</p>\
         <h1 class=\"title\" id=\"sign-in\">Sign in</h1>\
         <p class=\"lede\">Sign in with a Stet Server token. It is exchanged for a session \
         that ends after 15 minutes without a request, or 12 hours after sign-in. The browser \
         does not keep the token. Every sign-in and sign-out is in the access log.</p>\
         <form method=\"post\" action=\"/console/sign-in\" class=\"fields\">{}{err}\
         <div class=\"field\"><label for=\"token\">Token</label>\
         <input class=\"m\" id=\"token\" type=\"password\" name=\"token\" autocomplete=\"off\" \
         required{invalid}></div>\
         <div class=\"actions\"><button class=\"btn\" type=\"submit\">Sign in</button></div>\
         </form></section>{}",
        csrf_field(csrf),
        Some(licensee_text(licensee))
            .filter(|l| !l.is_empty())
            .map(|l| format!("<p class=\"under\">{l}</p>"))
            .unwrap_or_default()
    ));
    document(
        &frame,
        &Page {
            title: "Sign in",
            main,
            class: "center",
            ..Page::default()
        },
    )
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

/// A run's state in the words and with the diamond the run page uses: its
/// sentence (escaped HTML) and its marker class.
fn run_state(r: &JsonValue) -> (String, &'static str) {
    let status = text_of(&r["status"]);
    let outcome = text_of(&r["last_outcome"]);
    let open = r["attempt_open"].as_bool().unwrap_or(false);
    let alarm = |w: &str| format!("<span class=\"alarm\">{w}</span>");
    match status.as_str() {
        "regressed" => (alarm("Regressed: the stored journal went back"), "mk-alarm"),
        "missing" => (alarm("Missing from storage"), "mk-alarm"),
        "active" => ("Running".to_string(), "mk-breathe"),
        "dangling" => (
            alarm("No end: crashed \u{b7} an effect was left open"),
            "mk-alarm-hollow",
        ),
        _ if open => (alarm("No end: crashed"), "mk-alarm-hollow"),
        _ => match outcome.as_str() {
            "ok" => ("Ended ok".to_string(), "mk-fill"),
            "fault" => (alarm("Ended with a fault"), "mk-alarm-big"),
            "" => ("No attempts".to_string(), "mk-hollow"),
            other => (format!("Ended {}", mono(&text::clip(other, 16))), "mk-fill"),
        },
    }
}

fn runs_page(
    viewer: &ConsoleViewer,
    runs: &[JsonValue],
    next: Option<&str>,
    filters: &JsonValue,
) -> String {
    let f = |k: &str| esc(&text_of(&filters[k]));
    let set = |k: &str| !text_of(&filters[k]).is_empty();
    let any = [
        "q", "status", "prefix", "label", "program", "since", "until",
    ]
    .iter()
    .any(|k| set(k));
    let more_open = ["prefix", "label", "program", "since", "until"]
        .iter()
        .any(|k| set(k));
    let statuses = [
        ("", "Any status"),
        ("active", "Running"),
        ("idle", "Not running"),
        ("dangling", "Effect left open"),
        ("regressed", "Regressed"),
        ("missing", "Missing"),
    ];
    let options: String = statuses
        .iter()
        .map(|(v, words)| {
            let selected = if text_of(&filters["status"]) == *v {
                " selected"
            } else {
                ""
            };
            format!("<option value=\"{v}\"{selected}>{words}</option>")
        })
        .collect();
    let clear = if any {
        "<a class=\"clear\" href=\"/console\">Clear filters</a>"
    } else {
        ""
    };
    let field = |id: &str, name: &str, label: &str, mono_field: bool| {
        format!(
            "<div class=\"field\"><label for=\"{id}\">{label}</label>\
             <input{} id=\"{id}\" name=\"{name}\" value=\"{}\"></div>",
            if mono_field { " class=\"m\"" } else { "" },
            f(name)
        )
    };
    let filter_bar = format!(
        "<form class=\"band filters\" method=\"get\" action=\"/console\" role=\"search\">\
         <div class=\"row1\"><div class=\"field fq\"><label for=\"f-q\">Run id or label value</label>\
         <input class=\"m\" id=\"f-q\" name=\"q\" value=\"{}\"></div>\
         <div class=\"field fs\"><label for=\"f-status\">Status</label><div class=\"sel\">\
         <select id=\"f-status\" name=\"status\">{options}</select></div></div>\
         <button class=\"btn\" type=\"submit\">Filter</button>{clear}</div>\
         <details{}><summary>More filters</summary><div class=\"more\">{}{}{}{}{}</div></details></form>",
        f("q"),
        if more_open { " open" } else { "" },
        field("f-prefix", "prefix", "Run id prefix", true),
        field("f-label", "label", "Label (key=value)", true),
        field("f-program", "program", "Program", true),
        field("f-since", "since", "Updated since (RFC 3339)", true),
        field("f-until", "until", "Updated until (RFC 3339)", true),
    );
    let year = this_year();
    let rows: String = runs
        .iter()
        .map(|r| {
            let id = text_of(&r["run_id"]);
            let (state, mark) = run_state(r);
            let entries = r["entries"].as_u64().unwrap_or(0);
            let anchored = r["anchored_entries"].as_u64().unwrap_or(0);
            let count = |k: u64, one: &str, many: &str| {
                format!("{} {}", text::count(k), if k == 1 { one } else { many })
            };
            let mut sentence = vec![state];
            if let Some(a) = r["attempts"].as_u64().filter(|&a| a > 0) {
                sentence.push(count(a, "attempt", "attempts"));
            }
            sentence.push(count(entries, "entry", "entries"));
            sentence.push(if anchored == 0 {
                "not yet anchored".to_string()
            } else if anchored >= entries {
                "anchored".to_string()
            } else {
                format!(
                    "anchored to #{}",
                    text::count(anchored.min(entries).saturating_sub(1))
                )
            });
            let holds = r["holds"].as_array().map_or(0, Vec::len) as u64;
            if holds > 0 {
                sentence.push(count(holds, "hold", "holds"));
            }
            if let JsonValue::Object(p) = &r["program"] {
                let name = p.get("name").map(text_of).unwrap_or_default();
                if !name.trim().is_empty() {
                    sentence.push(format!("program {}", mono(&text::clip(&name, 32))));
                }
            }
            let head = text::clip(&text_of(&r["head"]), 12)
                .trim_end_matches('\u{2026}')
                .to_string();
            format!(
                "<li class=\"rr {mark}\"><a class=\"rr-a\" href=\"/console/runs/{}\" title=\"{}\">\
                 <span class=\"rr-t\"><span class=\"rid\">{}</span></span>\
                 <span class=\"rr-tm\">{}</span><span class=\"rr-s\">{}</span>\
                 <span class=\"rr-h\">{}</span></a></li>",
                esc(&encode(&id)),
                esc(&id),
                esc(&text::clip(&id, 64)),
                esc(&text::short_time(&text_of(&r["updated_at"]), &year, true)),
                sentence.join(" \u{b7} "),
                esc(&head),
            )
        })
        .collect();
    let body = if runs.is_empty() {
        if any {
            empty("No runs match these filters. <a href=\"/console\">Clear filters</a>")
        } else {
            empty(
                "No runs yet. Point an agent's runtime at this server and runs appear as they \
                 record.",
            )
        }
    } else {
        let mut pages = String::new();
        if set("after") {
            let mut query = String::new();
            if let Some(map) = filters.as_object() {
                for (k, v) in map {
                    if k != "after" && !text_of(v).is_empty() {
                        query.push_str(&format!(
                            "{}={}&",
                            query_value(k),
                            query_value(&text_of(v))
                        ));
                    }
                }
            }
            pages.push_str(&format!(
                "<a href=\"/console?{}\">First page</a>",
                esc(query.trim_end_matches('&'))
            ));
        }
        if let Some(n) = next {
            let mut query = String::new();
            if let Some(map) = filters.as_object() {
                for (k, v) in map {
                    if k != "after" {
                        query.push_str(&format!(
                            "{}={}&",
                            query_value(k),
                            query_value(&text_of(v))
                        ));
                    }
                }
            }
            pages.push_str(&format!(
                "<a class=\"go\" href=\"/console?{}after={}\">Next page</a>",
                esc(&query),
                esc(&query_value(n))
            ));
        }
        let foot = if pages.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"tfoot\"><span class=\"note\">By run id</span><span class=\"pg\">{pages}</span></div>"
            )
        };
        format!(
            "<p class=\"cols caps\" aria-hidden=\"true\"><span>Run</span>\
             <span class=\"c-time\">Updated (UTC) \u{b7} head</span>\
             <span class=\"c-hash\">Updated (UTC)</span></p><ol class=\"rl\">{rows}</ol>{foot}"
        )
    };
    let shown = match (runs.len(), next.is_some()) {
        (1, false) => "<span class=\"n\">1</span> run".to_string(),
        (k, false) => format!("<span class=\"n\">{}</span> runs", text::count(k as u64)),
        (k, true) => format!(
            "the first <span class=\"n\">{}</span> runs",
            text::count(k as u64)
        ),
    };
    let shown = if any {
        format!("{shown} matching these filters, by run id")
    } else {
        format!("{shown}, by run id")
    };
    let main = format!(
        "<div class=\"page-h\"><h1 class=\"title\">Runs</h1><p class=\"facts\">{shown}</p></div>\
         <section class=\"tsheet runs\" aria-label=\"Runs\">{filter_bar}{body}</section>"
    );
    framed(viewer, "runs", "Runs", &[], main)
}

// ---------------------------------------------------------------------------
// The run page's parts
// ---------------------------------------------------------------------------

/// The Evidence check card's foot: bundle downloads, for auditors and
/// administrators.
fn evidence_foot(viewer: &ConsoleViewer, path: &str, run_id: &str) -> Option<String> {
    if viewer.role != "auditor" && viewer.role != "admin" {
        return None;
    }
    // `none` and `binary` carry text unredacted, so only a viewer with
    // view_raw is offered them (the API refuses them otherwise).
    let mut modes = vec![
        ("detectors", "Redacted by detectors"),
        ("all", "All content withheld"),
    ];
    if viewer.view_raw {
        modes.insert(0, ("none", "Unredacted"));
        modes.push(("binary", "Attachments withheld, text unredacted"));
    }
    let links: String = modes
        .iter()
        .map(|(m, words)| {
            format!(
                "<li><a href=\"{}/evidence?redact={m}\">{words}</a></li>",
                esc(path)
            )
        })
        .collect();
    let file = format!("{}.evidence.json", text::clip(run_id, 80));
    Some(format!(
        "<p class=\"lbl\">Evidence bundle {}</p><ul class=\"dls\">{links}</ul>\
         <p class=\"lbl\">Verify it offline</p>{}\
         <p class=\"note\">Against trust roots of your own choosing.</p>",
        tag("Preview"),
        command(&["pragmatic verify-evidence".to_string(), file])
    ))
}

/// Erasure, for administrators: a quiet disclosure at the end of the run
/// page's side column, which opens on the form. Its button leads to a
/// confirmation; it erases nothing itself.
fn erase_card(viewer: &ConsoleViewer, path: &str) -> Option<String> {
    if viewer.role != "admin" {
        return None;
    }
    Some(format!(
        "<details class=\"erase\"><summary>Erase content\u{2026}</summary>\
         <section class=\"card\" aria-labelledby=\"h-erase\"><div class=\"card-h\">\
         <h2 class=\"card-t alarm\" id=\"h-erase\">Erase content</h2>{}</div><div class=\"card-b\">\
         <p>Erasure drops slot content and its salt for good. The chain still verifies, and an \
         erasure note records who, why and when.</p>\
         <form method=\"post\" action=\"{}/erase\" class=\"fields\">{}\
         <div class=\"field\"><label for=\"e-slots\">Slots</label><input class=\"m\" id=\"e-slots\" \
         name=\"slots\" aria-describedby=\"e-slots-h\"><p class=\"hint\" id=\"e-slots-h\">\
         <span class=\"m\">cursor:slot</span>, space-separated. Each slot's address is in its \
         expanded row, for example <span class=\"m\">5:0</span>.</p></div>\
         <div class=\"field\"><label for=\"e-match\">Or every slot containing</label>\
         <input id=\"e-match\" name=\"match\"></div>\
         <label class=\"cbox\"><input type=\"checkbox\" name=\"all\" value=\"on\"> Or every slot</label>\
         <div class=\"field\"><label for=\"e-code\">Reason code</label><input class=\"m\" id=\"e-code\" \
         name=\"reason_code\" required pattern=\"[a-z0-9_.:-]{{1,64}}\" aria-describedby=\"e-code-h\">\
         <p class=\"hint\" id=\"e-code-h\">Lowercase letters, digits and <span class=\"m\">_ . : -</span>, \
         for example <span class=\"m\">gdpr.art17</span>.</p></div>\
         <div class=\"field\"><label for=\"e-reason\">Reason (optional)</label>\
         <input id=\"e-reason\" name=\"reason\"></div>\
         <label class=\"cbox\"><input type=\"checkbox\" name=\"force\" value=\"on\"> Revoke a live lease</label>\
         <label class=\"cbox\"><input type=\"checkbox\" name=\"allow_unfinished\" value=\"on\"> The run did \
         not finish; it can no longer resume</label>\
         <div class=\"actions\"><button class=\"btn danger\" type=\"submit\">\
         Review erasure</button></div></form></div></section></details>",
        tag("Admin"),
        esc(path),
        csrf_field(&viewer.csrf)
    ))
}

// ---------------------------------------------------------------------------
// Access log
// ---------------------------------------------------------------------------

/// A personal field: italic "withheld" when it is withheld from the
/// viewer.
fn personal(v: &JsonValue) -> String {
    match v {
        JsonValue::String(s) if s == "[withheld]" => "<span class=\"s dim\">withheld</span>".into(),
        other => cell(other, 64),
    }
}

fn access_page(viewer: &ConsoleViewer, records: &[JsonValue], next: Option<u64>) -> String {
    let year = this_year();
    let rows: String = records
        .iter()
        .map(|r| {
            let request = if r["route"].is_null() {
                text_of(&r["action"])
            } else {
                format!("{} {}", text_of(&r["method"]), text_of(&r["route"]))
            };
            let status = r["status"].as_u64();
            let status_html = match status {
                Some(s) if s >= 400 => format!("<span class=\"alarm\">{s}</span>"),
                Some(s) => s.to_string(),
                None => String::new(),
            };
            let run = match &r["run_id"] {
                JsonValue::String(id) => format!(
                    "<a class=\"m\" href=\"/console/runs/{}\">{}</a>",
                    esc(&encode(id)),
                    esc(&text::clip(id, 48))
                ),
                _ => String::new(),
            };
            let raw = if r["raw"] == JsonValue::Bool(true) {
                format!(" {}", tag("Raw"))
            } else {
                String::new()
            };
            // Who: the principal, then the role in words.
            let role = role_words(&text_of(&r["role"]));
            let who = match (personal(&r["principal"]), role.is_empty()) {
                (p, true) => p,
                (p, false) if p.is_empty() => format!("<span class=\"s dim\">{}</span>", esc(&role)),
                (p, false) => format!(
                    "<span class=\"m\">{p}</span> <span class=\"s dim\">\u{b7} {}</span>",
                    esc(&role)
                ),
            };
            format!(
                "<tr><td class=\"m r head\">{}</td><td class=\"m nw\" data-label=\"At (UTC)\">{}</td>\
                 <td class=\"m nw\" data-label=\"Kind\">{}</td><td class=\"nw\" data-label=\"Request\">{}{raw}</td>\
                 <td class=\"m r\" data-label=\"Status\">{status_html}</td><td class=\"nw\" data-label=\"Run\">{run}</td>\
                 <td class=\"nw\" data-label=\"Who\">{who}</td><td class=\"m nw\" data-label=\"Token\">{}</td>\
                 <td class=\"m nw\" data-label=\"Source\">{}</td></tr>",
                cell(&r["cursor"], 24),
                esc(&text::short_time(&text_of(&r["at"]), &year, true)),
                cell(&r["kind"], 24),
                if request.trim().is_empty() {
                    String::new()
                } else {
                    mono(&text::clip(&request, 64))
                },
                cell(&r["token_id"], 32),
                personal(&r["source_ip"]),
            )
        })
        .collect();
    let body = if records.is_empty() {
        empty("No requests recorded yet.")
    } else {
        let next = next
            .map(|n| format!("<a class=\"go\" href=\"/console/access?after={n}\">Next page</a>"))
            .unwrap_or_default();
        table(
            "Access log",
            &[
                ("#", true),
                ("At (UTC)", false),
                ("Kind", false),
                ("Request", false),
                ("Status", true),
                ("Run", false),
                ("Who", false),
                ("Token", false),
                ("Source", false),
            ],
            &rows,
            &format!(
                "<div class=\"tfoot\"><span class=\"note\">Oldest first</span><span class=\"pg\">{next}</span></div>"
            ),
        )
    };
    let main = format!(
        "<div class=\"page-h\"><h1 class=\"title\">Access log</h1></div>\
         <p class=\"lede\" style=\"margin:-8px 0 20px\">Every request to the API and the console, \
         including refused ones, with who made it and what it touched. Query values are never \
         recorded.</p><section class=\"tsheet\" aria-label=\"Access log\">{body}</section>"
    );
    framed(viewer, "access", "Access log", &[], main)
}

// ---------------------------------------------------------------------------
// Holds and retention
// ---------------------------------------------------------------------------

fn scope_text(h: &JsonValue) -> String {
    match (&h["scope"]["prefix"], &h["scope"]["run_ids"]) {
        (JsonValue::String(p), _) => format!("prefix {}", mono(&text::clip(p, 64))),
        (_, JsonValue::Array(ids)) => {
            let shown: Vec<String> = ids
                .iter()
                .take(20)
                .map(|i| text::clip(&text_of(i), 64))
                .collect();
            let more = if ids.len() > 20 {
                format!(" and {} more", ids.len() - 20)
            } else {
                String::new()
            };
            format!("{}{more}", mono(&shown.join(" ")))
        }
        _ => String::new(),
    }
}

fn days(v: &JsonValue) -> String {
    match v.as_u64() {
        Some(0) | None => "<span class=\"s dim\">never</span>".to_string(),
        Some(d) => format!("{d} days"),
    }
}

fn holds_page(
    viewer: &ConsoleViewer,
    holds: &[JsonValue],
    retention: &JsonValue,
    note: Option<&ConsoleNotice>,
) -> String {
    let csrf = csrf_field(&viewer.csrf);
    let year = this_year();
    let mut main = notice_html(note);
    main.push_str("<div class=\"page-h\"><h1 class=\"title\">Holds and retention</h1></div>");
    let rows: String = holds
        .iter()
        .map(|h| {
            let id = text_of(&h["id"]);
            format!(
                "<tr><td class=\"m head\">{}</td><td data-label=\"Matter\">{}</td>\
                 <td data-label=\"Scope\">{}</td><td class=\"m nw\" data-label=\"Placed\">{}</td>\
                 <td class=\"m\" data-label=\"By\">{}</td><td class=\"r\">\
                 <form method=\"post\" action=\"/console/holds/{}/remove\">{csrf}\
                 <button class=\"btn sm danger\" type=\"submit\">Remove</button></form></td></tr>",
                esc(&text::clip(&id, 48)),
                cell(&h["matter"], 120),
                scope_text(h),
                esc(&text::short_time(&text_of(&h["created_at"]), &year, false)),
                cell(&h["created_by"], 48),
                esc(&encode(&id)),
            )
        })
        .collect();
    let holds_table = if holds.is_empty() {
        empty("No holds. Runs can be erased, and retention applies to them.")
    } else {
        table(
            "Legal holds",
            &[
                ("Hold", false),
                ("Matter", false),
                ("Scope", false),
                ("Placed", false),
                ("By", false),
                ("", true),
            ],
            &rows,
            "",
        )
        .replace(
            "<span class=\"sr-only\">State</span>",
            "<span class=\"sr-only\">Remove</span>",
        )
    };
    main.push_str(&format!(
        "<section class=\"sect\" aria-labelledby=\"h-holds\"><h2 class=\"rhead\" id=\"h-holds\">Legal holds</h2>\
         <p class=\"lede\">A run under a hold cannot be erased, shredded or deleted, and neither can \
         runs created later under a held prefix. Placing and removing a hold are recorded in the \
         access log and the erasure ledger before they act.</p>\
         <div class=\"tsheet\">{holds_table}</div>\
         <section class=\"card formcard\" aria-labelledby=\"h-place\"><div class=\"card-h\">\
         <h3 class=\"card-t\" id=\"h-place\">Place a hold</h3></div><div class=\"card-b\">\
         <form method=\"post\" action=\"/console/holds\">{csrf}<div class=\"grid3\">\
         <div class=\"field\"><label for=\"h-matter\">Matter</label><input id=\"h-matter\" name=\"matter\" required></div>\
         <div class=\"field\"><label for=\"h-prefix\">Run id prefix</label><input class=\"m\" id=\"h-prefix\" name=\"prefix\"></div>\
         <div class=\"field\"><label for=\"h-ids\">Or run ids, space-separated</label><input class=\"m\" id=\"h-ids\" name=\"run_ids\"></div>\
         </div><div class=\"actions\"><button class=\"btn\" type=\"submit\">Place hold</button></div></form>\
         </div></section></section>"
    ));
    let policies = retention.as_array().cloned().unwrap_or_default();
    let rows: String = policies
        .iter()
        .map(|p| {
            format!(
                "<tr><td class=\"m head\">{}</td><td class=\"r\" data-label=\"Keep at least\">{}</td>\
                 <td class=\"r\" data-label=\"Shred after\">{}</td><td class=\"r\" data-label=\"Delete after\">{}</td>\
                 <td class=\"m\" data-label=\"Erasure during the minimum\">{}</td></tr>",
                esc(&text::clip(&p["match"].to_string(), 120)),
                days(&p["retain_min_days"]),
                days(&p["shred_after_days"]),
                days(&p["delete_after_days"]),
                cell(&p["erasure"], 32),
            )
        })
        .collect();
    let retention_table = if policies.is_empty() {
        empty("No retention policies: runs are kept.")
    } else {
        table(
            "Retention policies",
            &[
                ("Match", false),
                ("Keep at least", true),
                ("Shred after", true),
                ("Delete after", true),
                ("Erasure during the minimum", false),
            ],
            &rows,
            "",
        )
    };
    main.push_str(&format!(
        "<section class=\"sect\" aria-labelledby=\"h-ret\"><h2 class=\"rhead\" id=\"h-ret\">Retention</h2>\
         <p class=\"lede\">The configured policies. Retention runs every hour; runs under a hold or a \
         live lease are skipped, and every action is in the erasure ledger.</p>\
         <div class=\"tsheet\">{retention_table}<div class=\"tfoot\"><span class=\"note\">Run every \
         policy now, instead of at the next hour</span>\
         <form method=\"post\" action=\"/console/retention/run\">{csrf}\
         <button class=\"btn sm danger\" type=\"submit\">Run retention now</button></form></div></div></section>"
    ));
    framed(viewer, "holds", "Holds and retention", &[], main)
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

fn tokens_page(
    viewer: &ConsoleViewer,
    tokens: &[JsonValue],
    issued: Option<(&str, &JsonValue)>,
    note: Option<&ConsoleNotice>,
) -> String {
    let csrf = csrf_field(&viewer.csrf);
    let year = this_year();
    let mut main = notice_html(note);
    main.push_str("<div class=\"page-h\"><h1 class=\"title\">Tokens</h1></div>");
    if let Some((value, record)) = issued {
        main.push_str(&format!(
            "<section class=\"issued\" aria-labelledby=\"h-issued\" role=\"status\">\
             <p class=\"t\" id=\"h-issued\">Token {} issued for {} ({})</p>\
             <p>Copy it now. It is shown only this once; the server keeps only its SHA-256.</p>\
             <span class=\"secret\">{}</span></section>",
            mono(&text_of(&record["id"])),
            mono(&text::clip(&text_of(&record["principal"]), 64)),
            esc(&role_words(&text_of(&record["role"]))),
            esc(value)
        ));
    }
    let rows: String = tokens
        .iter()
        .map(|t| {
            let id = text_of(&t["id"]);
            let scopes = t["scopes"]
                .as_array()
                .map(|s| s.iter().map(text_of).collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            let revoked = !t["revoked_at"].is_null();
            let (class, action) = if revoked {
                (
                    " class=\"revoked\"",
                    format!(
                        "<span class=\"s\">Revoked</span> <span class=\"m\">{}</span>",
                        esc(&text::short_time(&text_of(&t["revoked_at"]), &year, false))
                    ),
                )
            } else {
                (
                    "",
                    format!(
                        "<form method=\"post\" action=\"/console/tokens/{}/revoke\">{csrf}\
                         <button class=\"btn sm danger\" type=\"submit\">Revoke</button></form>",
                        esc(&encode(&id))
                    ),
                )
            };
            let expires = match &t["expires_at"] {
                JsonValue::Null => "<span class=\"s dim\">never</span>".to_string(),
                v => esc(&text::short_time(&text_of(v), &year, false)),
            };
            format!(
                "<tr{class}><td class=\"m head\">{}</td><td data-label=\"Name\">{}</td>\
                 <td class=\"m\" data-label=\"Principal\">{}</td><td data-label=\"Role\">{}</td>\
                 <td class=\"m\" data-label=\"Scopes\">{}</td><td data-label=\"Raw\">{}</td>\
                 <td class=\"m nw\" data-label=\"Created\">{}</td><td class=\"m nw\" data-label=\"Expires\">{expires}</td>\
                 <td class=\"r nw\">{action}</td></tr>",
                esc(&text::clip(&id, 48)),
                cell(&t["name"], 64),
                cell(&t["principal"], 64),
                esc(&role_words(&text_of(&t["role"]))),
                esc(&text::clip(&scopes, 80)),
                if t["view_raw"] == JsonValue::Bool(true) {
                    tag("Raw")
                } else {
                    String::new()
                },
                esc(&text::short_time(&text_of(&t["created_at"]), &year, false)),
            )
        })
        .collect();
    let body = table(
        "Tokens",
        &[
            ("Token", false),
            ("Name", false),
            ("Principal", false),
            ("Role", false),
            ("Scopes", false),
            ("Raw", false),
            ("Created", false),
            ("Expires", false),
            ("", true),
        ],
        &rows,
        "",
    )
    .replace(
        "<span class=\"sr-only\">State</span>",
        "<span class=\"sr-only\">Revoke</span>",
    );
    main.push_str(&format!(
        "<section class=\"tsheet\" aria-label=\"Tokens\">{body}</section>\
         <section class=\"card formcard\" aria-labelledby=\"h-issue\"><div class=\"card-h\">\
         <h2 class=\"card-t\" id=\"h-issue\">Issue a token</h2></div><div class=\"card-b\">\
         <form method=\"post\" action=\"/console/tokens\">{csrf}<div class=\"grid3\">\
         <div class=\"field\"><label for=\"t-name\">Name</label><input id=\"t-name\" name=\"name\" required></div>\
         <div class=\"field\"><label for=\"t-principal\">Principal</label><input class=\"m\" id=\"t-principal\" \
         name=\"principal\" required aria-describedby=\"t-principal-h\"><p class=\"hint\" id=\"t-principal-h\">\
         A person or a service.</p></div>\
         <div class=\"field\"><label for=\"t-role\">Role</label><div class=\"sel\"><select id=\"t-role\" name=\"role\">\
         <option value=\"agent\">Agent</option><option value=\"auditor\">Auditor</option>\
         <option value=\"admin\">Admin</option><option value=\"witness_client\">Witness client</option>\
         </select></div></div>\
         <div class=\"field span2\"><label for=\"t-scopes\">Scopes</label><input class=\"m\" id=\"t-scopes\" \
         name=\"scopes\" aria-describedby=\"t-scopes-h\"><p class=\"hint\" id=\"t-scopes-h\">Run id prefixes, \
         space-separated; <span class=\"m\">*</span> for all.</p></div>\
         <div class=\"field\"><label for=\"t-expires\">Expires at (optional)</label><input class=\"m\" \
         id=\"t-expires\" name=\"expires_at\" aria-describedby=\"t-expires-h\"><p class=\"hint\" \
         id=\"t-expires-h\">RFC 3339, for example <span class=\"m\">2027-01-01T00:00:00Z</span>.</p></div>\
         </div><label class=\"cbox\" style=\"margin-top:14px\"><input type=\"checkbox\" name=\"view_raw\" \
         value=\"on\"> May see content raw</label>\
         <div class=\"actions\"><button class=\"btn\" type=\"submit\">Issue token</button></div></form>\
         </div></section>"
    ));
    framed(viewer, "tokens", "Tokens", &[], main)
}

// ---------------------------------------------------------------------------
// Confirmations
// ---------------------------------------------------------------------------

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
        esc(name),
        esc(value)
    )
}

fn confirm_page(
    viewer: &ConsoleViewer,
    action: &str,
    back: &str,
    confirm: &ConsoleConfirm,
) -> String {
    let mut fields = String::new();
    let (label, title, consequence, list, button, crumbs_tail, current) = match confirm {
        ConsoleConfirm::Erase {
            run_id,
            slots,
            total,
            reason_code,
            reason,
            force,
            allow_unfinished,
            fields: form,
        } => {
            for (k, v) in form {
                fields.push_str(&hidden(k, v));
            }
            let what = if *total == 1 {
                "1 slot".to_string()
            } else {
                format!("{} slots", text::count(*total as u64))
            };
            let mut consequence = String::from(
                "<p class=\"lede\">Erasure drops the content and its salt for good. The chain still \
                 verifies, and an erasure note records who, why and when. This cannot be undone.</p>",
            );
            if *allow_unfinished {
                consequence.push_str(
                    "<p class=\"lede alarm\"><span class=\"s\">The run can no longer resume.</span></p>",
                );
            }
            if *force {
                consequence.push_str(
                    "<p class=\"lede\"><span class=\"s\">Its live lease is revoked.</span></p>",
                );
            }
            let mut list: String = slots
                .iter()
                .map(|s| {
                    format!(
                        "<li><span class=\"m\">#{} \u{b7} slot {}</span> \u{b7} {} \u{b7} {} bytes</li>",
                        s.cursor,
                        s.slot,
                        esc(&s.what),
                        text::count(s.bytes)
                    )
                })
                .collect();
            if *total > slots.len() {
                list.push_str(&format!(
                    "<li><span class=\"s\">and {} more</span></li>",
                    text::count((*total - slots.len()) as u64)
                ));
            }
            list.push_str(&format!(
                "<li>Reason code {}</li>",
                mono(&text::clip(reason_code, 64))
            ));
            if !reason.trim().is_empty() {
                list.push_str(&format!(
                    "<li>Reason <span class=\"s\">\u{201c}{}\u{201d}</span></li>",
                    esc(&pragmatic_console::gist::excerpt(reason, 200))
                ));
            }
            (
                "Confirm erasure",
                format!("Erase {what} from {}?", mono(&text::clip(run_id, 64))),
                consequence,
                list,
                format!("Erase {what}"),
                Some(run_id.clone()),
                "runs",
            )
        }
        ConsoleConfirm::RemoveHold { hold } => (
            "Confirm removal",
            format!(
                "Remove the hold {}?",
                mono(&text::clip(&text_of(&hold["id"]), 48))
            ),
            "<p class=\"lede\">Runs it covers can then be erased, and retention can shred or \
             delete them.</p>"
                .to_string(),
            format!(
                "<li>Matter {}</li><li>Scope {}</li>",
                cell(&hold["matter"], 120),
                scope_text(hold)
            ),
            "Remove hold".to_string(),
            None,
            "holds",
        ),
        ConsoleConfirm::RevokeToken { token } => (
            "Confirm revocation",
            format!("Revoke {}?", mono(&text::clip(&text_of(&token["id"]), 48))),
            "<p class=\"lede\">Its sessions end at once, and anything using it can no longer read \
             or append.</p>"
                .to_string(),
            format!(
                "<li>Name {}</li><li>Principal {}</li><li>Role {}</li>",
                cell(&token["name"], 64),
                mono(&text::clip(&text_of(&token["principal"]), 64)),
                esc(&role_words(&text_of(&token["role"])))
            ),
            "Revoke token".to_string(),
            None,
            "tokens",
        ),
        ConsoleConfirm::RunRetention { policies } => {
            let list: String = policies
                .as_array()
                .map(|ps| {
                    ps.iter()
                        .map(|p| {
                            format!(
                                "<li>{} \u{b7} shred after {} \u{b7} delete after {}</li>",
                                mono(&text::clip(&p["match"].to_string(), 80)),
                                days(&p["shred_after_days"]),
                                days(&p["delete_after_days"])
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let list = if list.is_empty() {
                "<li><span class=\"s\">No retention policies: nothing will change.</span></li>"
                    .to_string()
            } else {
                list
            };
            (
                "Confirm retention",
                "Run retention now?".to_string(),
                "<p class=\"lede\">Every policy acts at once: runs past their limits are shredded \
                 or deleted. Runs under a hold or a live lease are skipped.</p>"
                    .to_string(),
                list,
                "Run retention".to_string(),
                None,
                "holds",
            )
        }
    };
    let main = format!(
        "<section class=\"solo w640\" aria-labelledby=\"confirm-t\">\
         <p class=\"lbl caps alarm\">{label}</p><h1 class=\"title\" id=\"confirm-t\">{title}</h1>\
         {consequence}<ul class=\"ledger\">{list}</ul>\
         <form method=\"post\" action=\"{}\">{fields}{}{}\
         <div class=\"actions\"><button class=\"btn fill\" type=\"submit\">{}</button>\
         <a href=\"{}\">Cancel</a></div></form></section>",
        esc(action),
        hidden("confirm", "1"),
        csrf_field(&viewer.csrf),
        esc(&button),
        esc(back),
    );
    let page_title = label.to_string();
    match crumbs_tail {
        Some(run) => {
            let run_href = format!("/console/runs/{}", encode(&run));
            framed(
                viewer,
                current,
                &page_title,
                &[
                    Crumb::word("Runs", Some("/console")),
                    Crumb::id(&run, Some(&run_href)),
                    Crumb::word("Erase", None),
                ],
                main,
            )
        }
        None => framed(
            viewer,
            current,
            &page_title,
            &[Crumb::word(
                if current == "tokens" {
                    "Tokens"
                } else {
                    "Holds and retention"
                },
                None,
            )],
            main,
        ),
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn error_page(
    viewer: Option<&ConsoleViewer>,
    licensee: &str,
    status: u16,
    code: &str,
    run_id: Option<&str>,
    form: bool,
) -> String {
    let back = "<p class=\"actions\"><a class=\"go\" href=\"/console\">Back to runs</a></p>";
    let lede = |s: &str| format!("<p class=\"lede\">{s}</p>");
    let (title, body, refresh) = match (status, code) {
        (404, _) => match run_id {
            Some(id) => (
                format!("No run named {}", mono(&text::clip(id, 80))),
                format!(
                    "{}{back}",
                    lede(
                        "There is no run with this id that your token can open. Retention may \
                         have deleted it, or the id may be mistyped."
                    )
                ),
                None,
            ),
            None => ("No such page".to_string(), back.to_string(), None),
        },
        (403, "forbidden") if !form && viewer.is_some() => {
            let v = viewer.expect("checked");
            (
                "This page is not open to your role".to_string(),
                format!(
                    "{}{back}",
                    lede(&format!(
                        "Your token cannot open this page, or make this request. You are signed in \
                         as {} ({}).",
                        mono(&text::clip(&v.name, 64)),
                        esc(&role_words(&v.role))
                    ))
                ),
                None,
            )
        }
        (403, _) => (
            "This form could not be accepted".to_string(),
            format!(
                "{}{back}",
                lede(
                    "It was sent from another page, or your session changed after the page \
                     loaded. Nothing was changed. Go back, reload the page and send it again."
                )
            ),
            None,
        ),
        (503, "starting") => (
            "The server is starting".to_string(),
            lede("It is building its index of runs. This page reloads in 5 seconds."),
            Some(5),
        ),
        (503, _) => (
            "The console is paused".to_string(),
            lede(
                "The server cannot record who reads what right now, so it serves nothing until it \
                 can. Nothing is lost. Try again in a minute.",
            ),
            None,
        ),
        (400..=499, _) => (
            "The request was not accepted".to_string(),
            format!(
                "{}{back}",
                lede(&format!(
                    "The server refused it with the code {}. Nothing was changed.",
                    mono(&text::clip(code, 32))
                ))
            ),
            None,
        ),
        _ => (
            "Something went wrong on the server".to_string(),
            format!("{}{back}", lede("The details are in the server's log.")),
            None,
        ),
    };
    let main = solo_card(&format!("Error {status}"), &title, &body);
    let (nav, footer) = match viewer {
        Some(v) => chrome(v, ""),
        None => (String::new(), licensee_text(licensee)),
    };
    let frame = frame(&nav, &footer);
    let crumbs: [Crumb<'_>; 0] = [];
    document(
        &frame,
        &Page {
            title: &format!("Error {status}"),
            masthead: masthead(frame.home, &crumbs, frame.nav),
            main,
            refresh,
            ..Page::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn viewer(role: &str) -> ConsoleViewer {
        ConsoleViewer {
            token_id: "tok_1".into(),
            name: "<b>pat</b>".into(),
            role: role.into(),
            view_raw: false,
            licensee: "Example & Co".into(),
            csrf: "c5rf".into(),
        }
    }

    fn render(page: ConsolePage<'_>) -> String {
        ConsoleUi.render(&page).unwrap()
    }

    /// Every `<form method="post">` carries the CSRF field.
    fn every_form_has_csrf(html: &str, csrf: &str) {
        let field = format!("name=\"csrf\" value=\"{csrf}\"");
        for form in html.split("<form").skip(1) {
            let form = &form[..form.find("</form>").unwrap()];
            if form.contains("method=\"post\"") {
                assert!(form.contains(&field), "a post form without CSRF: {form}");
                assert!(
                    form.contains("action=\"/console"),
                    "posts only to the console: {form}"
                );
            }
        }
    }

    fn no_script(html: &str) {
        assert!(!html.contains("<script"));
        assert!(!html.to_ascii_lowercase().contains("javascript:"));
        assert!(!html.contains(" onclick") && !html.contains(" onerror"));
        assert!(html.contains("font-src 'self'"));
        assert!(html.contains("url(/console/assets/eb-garamond-latin."));
    }

    #[test]
    fn pages_escape_everything_and_carry_the_policy_footer_and_csrf() {
        let v = viewer("admin");
        let hostile = json!({"run_id": "<script>x</script>", "status": "idle", "entries": 2,
                             "anchored_entries": 2, "holds": [], "program": {"name": "\"><img>", "hash": "ab"},
                             "updated_at": "now", "last_outcome": "ok"});
        let html = render(ConsolePage::Runs {
            viewer: &v,
            runs: &[hostile],
            next: Some("a b"),
            filters: &json!({"prefix": "<x>"}),
        });
        no_script(&html);
        every_form_has_csrf(&html, "c5rf");
        assert!(!html.contains("<img>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("form-action 'self'"));
        assert!(html.contains("Licensed to Example &amp; Co"));
        assert!(html.contains("&lt;b&gt;pat&lt;/b&gt;"));
        assert!(html.contains("after=a+b"));
        assert!(html.contains("<details open><summary>More filters"));
        // Each run is a row in the run page's language, and a top-level
        // page has no breadcrumb to repeat its navigation.
        assert!(html.contains("<li class=\"rr mk-fill\"><a class=\"rr-a\" href=\"/console/runs/%3Cscript%3Ex%3C%2Fscript%3E\""));
        assert!(html.contains("<span class=\"rr-s\">Ended ok \u{b7} 2 entries \u{b7} anchored"));
        assert!(!html.contains("class=\"crumbs\""));
        let crashed = json!({"run_id": "r", "status": "idle", "attempt_open": true, "entries": 3,
                             "anchored_entries": 0, "holds": ["h"], "last_outcome": "ok"});
        let html = render(ConsolePage::Runs {
            viewer: &v,
            runs: &[crashed],
            next: None,
            filters: &json!({}),
        });
        assert!(html.contains("<li class=\"rr mk-alarm-hollow\">"));
        assert!(html.contains("<span class=\"alarm\">No end: crashed</span> \u{b7} 3 entries \u{b7} not yet anchored \u{b7} 1 hold"));
        let html = render(ConsolePage::Tokens {
            viewer: &v,
            tokens: &[
                json!({"id": "tok_2", "name": "n", "principal": "p", "role": "agent",
                             "scopes": ["a:"], "view_raw": false, "created_at": "t",
                             "expires_at": null, "revoked_at": null}),
            ],
            issued: Some(("prag_secret", &json!({"id": "tok_2", "role": "agent"}))),
            notice: None,
        });
        no_script(&html);
        every_form_has_csrf(&html, "c5rf");
        assert!(html.contains("<span class=\"secret\">prag_secret</span>"));
        assert!(html.contains("/console/tokens/tok_2/revoke"));
        let html = render(ConsolePage::SignIn {
            error: Some("<no>"),
            notice: Some("You are signed out."),
            licensee: "",
            csrf: "s1gn",
        });
        no_script(&html);
        every_form_has_csrf(&html, "s1gn");
        assert!(html.contains("&lt;no&gt;"));
        assert!(html.contains("You are signed out."));
        assert!(!html.contains("No licensee") && !html.contains("Licensed to"));
        assert!(!html.contains("class=\"under\""));
        assert!(html.contains("aria-invalid=\"true\""));
    }

    #[test]
    fn every_page_guards_its_forms() {
        let v = viewer("admin");
        let hold = json!({"id": "h<1>", "matter": "M & co", "scope": {"prefix": "case-"},
                          "created_at": "2026-10-14T00:00:00Z", "created_by": "tok_1"});
        let retention = json!([{"match": {"prefix": "x"}, "retain_min_days": 30,
                                "shred_after_days": 0, "delete_after_days": 90, "erasure": "allowed"}]);
        let notice = ConsoleNotice {
            text: "The request was refused:".into(),
            code: Some("odd_code".into()),
            refused: true,
        };
        let html = render(ConsolePage::Holds {
            viewer: &v,
            holds: std::slice::from_ref(&hold),
            retention: &retention,
            notice: Some(&notice),
        });
        no_script(&html);
        every_form_has_csrf(&html, "c5rf");
        assert!(html.contains("/console/holds/h%3C1%3E/remove"));
        assert!(html.contains("notice bad"));
        assert!(html.contains("<span class=\"m\">odd_code</span>."));
        assert!(html.contains("M &amp; co"));
        let confirms = [
            ConsoleConfirm::Erase {
                run_id: "r<1>".into(),
                slots: vec![crate::hooks::ErasePreviewSlot {
                    cursor: 5,
                    slot: 0,
                    what: "result of tool call <x>".into(),
                    bytes: 180,
                }],
                total: 3,
                reason_code: "gdpr".into(),
                reason: "asked \"twice\"".into(),
                force: false,
                allow_unfinished: true,
                fields: vec![("slots".into(), "5:0 \"><x>".into())],
            },
            ConsoleConfirm::RemoveHold { hold: hold.clone() },
            ConsoleConfirm::RevokeToken {
                token: json!({"id": "tok_2", "name": "<n>", "principal": "p", "role": "agent"}),
            },
            ConsoleConfirm::RunRetention {
                policies: retention.clone(),
            },
        ];
        for c in &confirms {
            let html = render(ConsolePage::Confirm {
                viewer: &v,
                action: "/console/runs/r%3C1%3E/erase",
                back: "/console",
                confirm: c,
            });
            no_script(&html);
            every_form_has_csrf(&html, "c5rf");
            assert!(html.contains("name=\"confirm\" value=\"1\""));
            assert!(html.contains("class=\"btn fill\""));
            assert!(!html.contains("<x>") && !html.contains("<n>"));
        }
        let erase = render(ConsolePage::Confirm {
            viewer: &v,
            action: "/console/runs/r/erase",
            back: "/console/runs/r",
            confirm: &confirms[0],
        });
        assert!(erase.contains("Erase 3 slots from"));
        assert!(erase.contains("#5 \u{b7} slot 0"));
        assert!(erase.contains("and 2 more"));
        assert!(erase.contains("The run can no longer resume."));
        assert!(erase.contains("value=\"5:0 &quot;&gt;&lt;x&gt;\""));
        for (status, code, run, form) in [
            (404, "not_found", Some("r<1>"), false),
            (404, "not_found", None, false),
            (403, "forbidden", None, false),
            (403, "forbidden", Some("r"), true),
            (503, "starting", None, false),
            (503, "storage_unavailable", None, true),
            (409, "<odd>", None, true),
            (500, "internal", None, false),
        ] {
            let html = render(ConsolePage::Error {
                viewer: Some(&v),
                licensee: "",
                status,
                code,
                run_id: run,
                form,
            });
            assert_eq!(
                html.contains("This form could not be accepted"),
                status == 403 && form
            );
            no_script(&html);
            every_form_has_csrf(&html, "c5rf");
            assert!(html.contains(&format!("Error {status}")));
            assert!(!html.contains("<odd>") && !html.contains("<1>"));
            assert_eq!(html.contains("http-equiv=\"refresh\""), code == "starting");
        }
    }

    #[test]
    fn only_admins_see_admin_navigation_and_auditors_see_evidence() {
        let path = "/console/runs/r";
        assert!(evidence_foot(&viewer("agent"), path, "r").is_none());
        assert!(erase_card(&viewer("agent"), path).is_none());
        let auditor = evidence_foot(&viewer("auditor"), path, "r").unwrap();
        assert!(auditor.contains("evidence?redact=detectors"));
        assert!(!auditor.contains("redact=none"), "no view_raw");
        assert!(
            !auditor.contains("redact=binary"),
            "binary bundles carry text unredacted: view_raw only"
        );
        assert!(erase_card(&viewer("auditor"), path).is_none());
        let admin = erase_card(&viewer("admin"), path).unwrap();
        // A quiet disclosure, closed until it is opened.
        assert!(
            admin.starts_with("<details class=\"erase\"><summary>Erase content\u{2026}</summary>")
        );
        assert!(admin.contains(">Or every slot containing</label>"));
        assert!(admin.contains("> Or every slot</label>"));
        assert!(admin.contains("/console/runs/r/erase"));
        assert!(admin.contains("name=\"csrf\" value=\"c5rf\""));
        assert!(admin.contains("Review erasure"));
        let (nav, _) = chrome(&viewer("auditor"), "runs");
        assert!(!nav.contains("/console/tokens"));
        assert!(nav.contains("<a href=\"/console\" aria-current=\"page\">Runs</a>"));
        let (nav, _) = chrome(&viewer("admin"), "tokens");
        assert!(nav.contains("/console/tokens") && nav.contains("/console/holds"));
        let (nav, _) = chrome(&viewer("agent"), "runs");
        assert!(
            !nav.contains("/console/access"),
            "agents cannot read the access log"
        );
    }
}
