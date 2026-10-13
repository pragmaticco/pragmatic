//! The console's pages (design 4.14), rendered with `pragmatic-console`,
//! the renderer the CLI uses too, so a run looks the same wherever it is
//! read.
//!
//! - The run page is `pragmatic-console`'s run view (facts, attempts,
//!   nested lanes, intents and results, erased, withheld and ref slots,
//!   verification), a page of the timeline at a time, with the run's
//!   anchoring (independent, or the operator's own signature only), its
//!   evidence downloads and, for administrators, erasure. A viewer without
//!   `view_raw` sees every slot through the server's redaction.
//! - The runs list, the access log, holds and retention, and tokens are
//!   tables in the same frame.
//!
//! Every page is framed by [`pragmatic_console::html::Frame`]: a
//! Content-Security-Policy that loads and runs nothing and lets forms
//! submit only to the console itself, navigation, and a footer naming the
//! viewer and the licensee. Every value that comes from a journal, a
//! token, a hold or a request is escaped. Every form that changes
//! something carries the session's CSRF token.

use pragmatic_console::html::{esc, masthead, page_framed, pill, Frame, CONSOLE_POLICY};
use pragmatic_console::{render_run_page, RunView, SlotFilter};
use serde_json::Value as JsonValue;

use crate::hooks::{ConsoleError, ConsolePage, ConsoleRenderer, ConsoleViewer};
use crate::redaction::Redacted;

/// The console renderer. See the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleUi;

impl ConsoleRenderer for ConsoleUi {
    fn render(&self, page: &ConsolePage<'_>) -> Result<String, ConsoleError> {
        Ok(match page {
            ConsolePage::SignIn {
                error,
                licensee,
                csrf,
            } => sign_in(*error, licensee, csrf),
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
                notice,
            } => {
                let path = format!("/console/runs/{}", encode(run_id));
                let link = format!("{path}?from=");
                let actions = run_actions(viewer, &path, summary, *notice);
                let (nav, footer) = chrome(viewer);
                let frame = Frame {
                    csp: CONSOLE_POLICY,
                    nav: &nav,
                    footer: &footer,
                };
                let filter_fn = |bytes: &[u8]| -> Vec<u8> {
                    match redactor.map(|r| r.redact_slot(bytes)) {
                        Some(Redacted::Text(t)) => t.into_bytes(),
                        Some(Redacted::Binary(b)) => b.placeholder().into_bytes(),
                        None => bytes.to_vec(),
                    }
                };
                let view = RunView {
                    anchor: *anchor,
                    source: Some("Pragmatic Server"),
                    home: Some("/console"),
                    from: *from,
                    page_link: Some(&link),
                    frame: Some(&frame),
                    filter: redactor.map(|_| SlotFilter(&filter_fn)),
                    actions: Some(&actions),
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

/// The navigation and the footer of a signed-in viewer's pages.
fn chrome(viewer: &ConsoleViewer) -> (String, String) {
    let mut nav = String::from(
        "<span class=\"nav\"><a href=\"/console\">runs</a>\
         <a href=\"/console/access\">access log</a>",
    );
    if viewer.role == "admin" {
        nav.push_str(
            "<a href=\"/console/holds\">holds and retention</a>\
             <a href=\"/console/tokens\">tokens</a>",
        );
    }
    nav.push_str(&format!(
        "<form class=\"inline\" method=\"post\" action=\"/console/sign-out\">{}\
         <button class=\"link\" type=\"submit\">sign out</button></form></span>",
        csrf_field(&viewer.csrf)
    ));
    let raw = if viewer.view_raw {
        ", content shown raw"
    } else {
        ", content redacted"
    };
    let mut footer = format!(
        "signed in as <b>{}</b> ({}{raw})",
        esc(&viewer.name),
        esc(&viewer.role)
    );
    footer.push_str(&licensee_text(&viewer.licensee));
    (nav, footer)
}

fn licensee_text(licensee: &str) -> String {
    if licensee.is_empty() {
        " \u{b7} no licensee configured".to_string()
    } else {
        format!(" \u{b7} licensed to <b>{}</b>", esc(licensee))
    }
}

/// A page in the viewer's frame.
fn framed(viewer: &ConsoleViewer, title: &str, section: &str, body: &str) -> String {
    let (nav, footer) = chrome(viewer);
    let frame = Frame {
        csp: CONSOLE_POLICY,
        nav: &nav,
        footer: &footer,
    };
    let mut html = masthead(Some("/console"), &esc(section), &nav);
    html.push_str(body);
    page_framed(
        &format!("{} \u{b7} pragmatic", esc(title)),
        &html,
        Some(&frame),
    )
}

fn notice_html(notice: Option<&str>) -> String {
    notice
        .map(|n| format!("<div class=\"notice\">{}</div>", esc(n)))
        .unwrap_or_default()
}

fn text(v: &JsonValue) -> String {
    match v {
        JsonValue::Null => String::new(),
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn sign_in(error: Option<&str>, licensee: &str, csrf: &str) -> String {
    let frame_footer = licensee_text(licensee);
    let frame = Frame {
        csp: CONSOLE_POLICY,
        nav: "",
        footer: frame_footer.trim_start_matches(" \u{b7} "),
    };
    let mut body = masthead(None, "sign in", "");
    if let Some(e) = error {
        body.push_str(&format!(
            "<div class=\"alarms\"><div><span class=\"alarm\">{}</span></div></div>",
            esc(e)
        ));
    }
    body.push_str(&format!(
        "<p class=\"lede\">Sign in with a Pragmatic Server token. It is exchanged for a session \
         cookie that ends after 15 minutes without a request or 12 hours after sign-in, and the \
         token itself is not kept by the browser. Every sign-in and sign-out is recorded in the \
         access log.</p>\
         <div class=\"forms\"><form method=\"post\" action=\"/console/sign-in\">{}\
         <label for=\"token\">token</label>\
         <input id=\"token\" type=\"password\" name=\"token\" autocomplete=\"off\" size=\"48\" required> \
         <button type=\"submit\">sign in</button></form></div>",
        csrf_field(csrf)
    ));
    page_framed("sign in \u{b7} pragmatic", &body, Some(&frame))
}

fn status_pill(status: &str) -> String {
    let class = match status {
        "active" | "idle" => "ok",
        "dangling" => "warn",
        _ => "bad",
    };
    pill(class, status)
}

fn runs_page(
    viewer: &ConsoleViewer,
    runs: &[JsonValue],
    next: Option<&str>,
    filters: &JsonValue,
) -> String {
    let f = |k: &str| esc(&text(&filters[k]));
    let statuses = ["", "active", "idle", "dangling", "regressed", "missing"];
    let options: String = statuses
        .iter()
        .map(|s| {
            let selected = if text(&filters["status"]) == *s {
                " selected"
            } else {
                ""
            };
            let label = if s.is_empty() { "any status" } else { s };
            format!("<option value=\"{s}\"{selected}>{label}</option>")
        })
        .collect();
    let mut body = format!(
        "<div class=\"forms\"><form method=\"get\" action=\"/console\">\
         <label>run id prefix <input name=\"prefix\" value=\"{}\"></label>\
         <label>run id or label value <input name=\"q\" value=\"{}\"></label>\
         <label>label (key=value) <input name=\"label\" value=\"{}\"></label>\
         <label>program <input name=\"program\" value=\"{}\"></label>\
         <label>status <select name=\"status\">{options}</select></label>\
         <label>updated since (RFC 3339) <input name=\"since\" value=\"{}\"></label>\
         <label>updated until (RFC 3339) <input name=\"until\" value=\"{}\"></label>\
         <button type=\"submit\">filter</button></form></div>",
        f("prefix"),
        f("q"),
        f("label"),
        f("program"),
        f("since"),
        f("until"),
    );
    if runs.is_empty() {
        body.push_str("<div class=\"empty\">no runs match</div>");
    } else {
        body.push_str(
            "<div class=\"scroll\"><table><tr><th>run</th><th>status</th><th class=\"r\">entries</th>\
             <th class=\"r\">anchored</th><th>last outcome</th><th>program</th><th>updated</th>\
             <th class=\"r\">holds</th></tr>",
        );
        for r in runs {
            let id = text(&r["run_id"]);
            let entries = r["entries"].as_u64().unwrap_or(0);
            let anchored = r["anchored_entries"].as_u64().unwrap_or(0);
            let anchor = if anchored == 0 {
                pill("warn", "unanchored")
            } else if anchored >= entries {
                pill("ok", &format!("{anchored}"))
            } else {
                pill("warn", &format!("{anchored}"))
            };
            body.push_str(&format!(
                "<tr class=\"run\"><td class=\"name\"><a href=\"/console/runs/{}\">{}</a></td>\
                 <td>{}</td><td class=\"r\">{entries}</td><td class=\"r\">{anchor}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td class=\"r\">{}</td></tr>",
                esc(&encode(&id)),
                esc(&id),
                status_pill(&text(&r["status"])),
                esc(&text(&r["last_outcome"])),
                esc(&text(&r["program"])),
                esc(&text(&r["updated_at"])),
                r["holds"].as_array().map_or(0, Vec::len),
            ));
        }
        body.push_str("</table></div>");
    }
    if let Some(n) = next {
        let mut query = String::new();
        if let Some(map) = filters.as_object() {
            for (k, v) in map {
                if k != "after" {
                    query.push_str(&format!("{}={}&", query_value(k), query_value(&text(v))));
                }
            }
        }
        body.push_str(&format!(
            "<p class=\"lede\"><a href=\"/console?{}after={}\">next page</a></p>",
            esc(&query),
            esc(&query_value(n))
        ));
    }
    framed(viewer, "runs", "runs", &body)
}

/// The run page's actions: evidence downloads and, for administrators,
/// erasure.
fn run_actions(
    viewer: &ConsoleViewer,
    path: &str,
    summary: &JsonValue,
    notice: Option<&str>,
) -> String {
    let mut out = notice_html(notice);
    let status = text(&summary["status"]);
    let holds = summary["holds"].as_array().map_or(0, Vec::len);
    out.push_str(&format!(
        "<p class=\"lede\">status {} \u{b7} {} hold(s) \u{b7} {} of {} entries independently \
         anchored</p>",
        status_pill(&status),
        holds,
        summary["anchored_entries"].as_u64().unwrap_or(0),
        summary["entries"].as_u64().unwrap_or(0),
    ));
    if viewer.role == "auditor" || viewer.role == "admin" {
        let mut modes = vec![
            ("detectors", "redacted by detectors"),
            ("binary", "attachments withheld"),
            ("all", "all content withheld"),
        ];
        if viewer.view_raw {
            modes.insert(0, ("none", "unredacted"));
        }
        let links: Vec<String> = modes
            .iter()
            .map(|(m, label)| format!("<a href=\"{}/evidence?redact={m}\">{label}</a>", esc(path)))
            .collect();
        out.push_str(&format!(
            "<h2>evidence</h2><p class=\"lede\">Download an evidence bundle, signed by this \
             server, to verify offline with <b>pragmatic verify-evidence</b> against trust roots \
             of your own choosing: {}.</p>",
            links.join(" \u{b7} ")
        ));
    }
    if viewer.role == "admin" {
        out.push_str(&format!(
            "<h2>erasure</h2><p class=\"lede\">Erasure drops slot content and its salt for good; \
             the chain still verifies and an erasure note records who, why and when. Give exactly \
             one of the slots, a text to match, or all.</p>\
             <div class=\"forms\"><form method=\"post\" action=\"{}/erase\">{}\
             <label>slots (cursor:slot, space separated) <input name=\"slots\" size=\"24\"></label>\
             <label>or every slot containing <input name=\"match\" size=\"24\"></label>\
             <label><input type=\"checkbox\" name=\"all\" value=\"on\"> or every slot</label>\
             <label>reason code <input name=\"reason_code\" required pattern=\"[a-z0-9_.-]{{1,64}}\"></label>\
             <label>reason <input name=\"reason\" size=\"32\"></label>\
             <label><input type=\"checkbox\" name=\"force\" value=\"on\"> revoke a live lease</label>\
             <label><input type=\"checkbox\" name=\"allow_unfinished\" value=\"on\"> the run did not \
             finish; it can no longer resume</label>\
             <button type=\"submit\">erase</button></form></div>",
            esc(path),
            csrf_field(&viewer.csrf)
        ));
    }
    out
}

fn access_page(viewer: &ConsoleViewer, records: &[JsonValue], next: Option<u64>) -> String {
    let mut body = String::from(
        "<p class=\"lede\">Every request to the API and the console, including refused ones, \
         with who made it and what it touched. Query values are never recorded.</p>",
    );
    if records.is_empty() {
        body.push_str("<div class=\"empty\">no records</div>");
    } else {
        body.push_str(
            "<div class=\"scroll\"><table><tr><th class=\"r\">#</th><th>at</th><th>kind</th>\
             <th>request</th><th class=\"r\">status</th><th>token</th><th>role</th><th>run</th>\
             <th>raw</th><th>principal</th><th>source</th></tr>",
        );
        for r in records {
            let request = if r["route"].is_null() {
                text(&r["action"])
            } else {
                format!("{} {}", text(&r["method"]), text(&r["route"]))
            };
            body.push_str(&format!(
                "<tr><td class=\"r\">{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"r\">{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&text(&r["cursor"])),
                esc(&text(&r["at"])),
                esc(&text(&r["kind"])),
                esc(&request),
                esc(&text(&r["status"])),
                esc(&text(&r["token_id"])),
                esc(&text(&r["role"])),
                esc(&text(&r["run_id"])),
                if r["raw"] == JsonValue::Bool(true) {
                    "raw"
                } else {
                    ""
                },
                esc(&text(&r["principal"])),
                esc(&text(&r["source_ip"])),
            ));
        }
        body.push_str("</table></div>");
    }
    if let Some(n) = next {
        body.push_str(&format!(
            "<p class=\"lede\"><a href=\"/console/access?after={n}\">next page</a></p>"
        ));
    }
    framed(viewer, "access log", "access log", &body)
}

fn holds_page(
    viewer: &ConsoleViewer,
    holds: &[JsonValue],
    retention: &JsonValue,
    notice: Option<&str>,
) -> String {
    let csrf = csrf_field(&viewer.csrf);
    let mut body = notice_html(notice);
    body.push_str(
        "<h2>legal holds</h2><p class=\"lede\">A run under a hold cannot be erased, shredded or \
         deleted, including runs created later under a held prefix. Placing and removing a hold \
         are recorded in the access log and the erasure ledger before they act.</p>",
    );
    if holds.is_empty() {
        body.push_str("<div class=\"empty\">no holds</div>");
    } else {
        body.push_str(
            "<div class=\"scroll\"><table><tr><th>hold</th><th>matter</th><th>scope</th>\
             <th>placed</th><th>by</th><th></th></tr>",
        );
        for h in holds {
            let scope = match (&h["scope"]["prefix"], &h["scope"]["run_ids"]) {
                (JsonValue::String(p), _) => format!("prefix {p:?}"),
                (_, JsonValue::Array(ids)) => format!(
                    "runs {}",
                    ids.iter().map(text).collect::<Vec<_>>().join(", ")
                ),
                _ => String::new(),
            };
            let id = text(&h["id"]);
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>\
                 <form class=\"inline\" method=\"post\" action=\"/console/holds/{}/remove\">{csrf}\
                 <button type=\"submit\">remove</button></form></td></tr>",
                esc(&id),
                esc(&text(&h["matter"])),
                esc(&scope),
                esc(&text(&h["created_at"])),
                esc(&text(&h["created_by"])),
                esc(&encode(&id)),
            ));
        }
        body.push_str("</table></div>");
    }
    body.push_str(&format!(
        "<div class=\"forms\"><form method=\"post\" action=\"/console/holds\">{csrf}\
         <label>matter <input name=\"matter\" required size=\"32\"></label>\
         <label>run id prefix <input name=\"prefix\"></label>\
         <label>or run ids (space separated) <input name=\"run_ids\" size=\"32\"></label>\
         <button type=\"submit\">place hold</button></form></div>"
    ));
    body.push_str(
        "<h2>retention</h2><p class=\"lede\">The configured policies. Retention runs hourly; \
         runs under a hold or a live lease are skipped, and every action is in the erasure \
         ledger.</p>",
    );
    let policies = retention.as_array().cloned().unwrap_or_default();
    if policies.is_empty() {
        body.push_str("<div class=\"empty\">no retention policies: runs are kept</div>");
    } else {
        body.push_str(
            "<div class=\"scroll\"><table><tr><th>match</th><th class=\"r\">keep at least \
             (days)</th><th class=\"r\">shred after</th><th class=\"r\">delete after</th>\
             <th>erasure during the minimum</th></tr>",
        );
        for p in &policies {
            let days = |k: &str| match p[k].as_u64() {
                Some(0) | None => "never".to_string(),
                Some(d) => d.to_string(),
            };
            body.push_str(&format!(
                "<tr><td>{}</td><td class=\"r\">{}</td><td class=\"r\">{}</td>\
                 <td class=\"r\">{}</td><td>{}</td></tr>",
                esc(&p["match"].to_string()),
                p["retain_min_days"].as_u64().unwrap_or(0),
                esc(&days("shred_after_days")),
                esc(&days("delete_after_days")),
                esc(&text(&p["erasure"])),
            ));
        }
        body.push_str("</table></div>");
    }
    body.push_str(&format!(
        "<div class=\"forms\"><form method=\"post\" action=\"/console/retention/run\">{csrf}\
         <button type=\"submit\">run retention now</button></form></div>"
    ));
    framed(viewer, "holds and retention", "holds and retention", &body)
}

fn tokens_page(
    viewer: &ConsoleViewer,
    tokens: &[JsonValue],
    issued: Option<(&str, &JsonValue)>,
    notice: Option<&str>,
) -> String {
    let csrf = csrf_field(&viewer.csrf);
    let mut body = notice_html(notice);
    if let Some((value, record)) = issued {
        body.push_str(&format!(
            "<div class=\"notice\">Token <b>{}</b> issued for {} ({}). Copy it now: it is shown \
             only this once, and the server keeps only its SHA-256.<br>\
             <span class=\"secret\">{}</span></div>",
            esc(&text(&record["id"])),
            esc(&text(&record["principal"])),
            esc(&text(&record["role"])),
            esc(value)
        ));
    }
    body.push_str(
        "<div class=\"scroll\"><table><tr><th>token</th><th>name</th><th>principal</th>\
         <th>role</th><th>scopes</th><th>raw</th><th>created</th><th>expires</th>\
         <th>revoked</th><th></th></tr>",
    );
    for t in tokens {
        let id = text(&t["id"]);
        let scopes = t["scopes"]
            .as_array()
            .map(|s| s.iter().map(text).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let revoke = if t["revoked_at"].is_null() {
            format!(
                "<form class=\"inline\" method=\"post\" action=\"/console/tokens/{}/revoke\">{csrf}\
                 <button type=\"submit\">revoke</button></form>",
                esc(&encode(&id))
            )
        } else {
            String::new()
        };
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{revoke}</td></tr>",
            esc(&id),
            esc(&text(&t["name"])),
            esc(&text(&t["principal"])),
            esc(&text(&t["role"])),
            esc(&scopes),
            if t["view_raw"] == JsonValue::Bool(true) {
                "yes"
            } else {
                ""
            },
            esc(&text(&t["created_at"])),
            esc(&text(&t["expires_at"])),
            esc(&text(&t["revoked_at"])),
        ));
    }
    body.push_str("</table></div>");
    body.push_str(&format!(
        "<h2>issue a token</h2><div class=\"forms\"><form method=\"post\" action=\"/console/tokens\">\
         {csrf}<label>name <input name=\"name\" required></label>\
         <label>principal (a person or service) <input name=\"principal\" required></label>\
         <label>role <select name=\"role\"><option>agent</option><option>auditor</option>\
         <option>admin</option><option>witness_client</option></select></label>\
         <label>scopes (run id prefixes, space separated; * for all) <input name=\"scopes\"></label>\
         <label><input type=\"checkbox\" name=\"view_raw\" value=\"on\"> may see content raw</label>\
         <label>expires at (RFC 3339, optional) <input name=\"expires_at\"></label>\
         <button type=\"submit\">issue</button></form></div>"
    ));
    framed(viewer, "tokens", "tokens", &body)
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

    #[test]
    fn pages_escape_everything_and_carry_the_policy_footer_and_csrf() {
        let v = viewer("admin");
        let hostile = json!({"run_id": "<script>x</script>", "status": "idle", "entries": 2,
                             "anchored_entries": 2, "holds": [], "program": "\"><img>",
                             "updated_at": "now", "last_outcome": "ok"});
        let html = render(ConsolePage::Runs {
            viewer: &v,
            runs: &[hostile],
            next: Some("a b"),
            filters: &json!({"prefix": "<x>"}),
        });
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("form-action 'self'"));
        assert!(html.contains("licensed to <b>Example &amp; Co</b>"));
        assert!(html.contains("&lt;b&gt;pat&lt;/b&gt;"));
        assert!(html.contains("name=\"csrf\" value=\"c5rf\""));
        assert!(html.contains("after=a+b"));
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
        assert!(html.contains("prag_secret"));
        assert!(html.contains("/console/tokens/tok_2/revoke"));
        let html = render(ConsolePage::SignIn {
            error: Some("<no>"),
            licensee: "",
            csrf: "s1gn",
        });
        assert!(html.contains("&lt;no&gt;"));
        assert!(html.contains("value=\"s1gn\""));
        assert!(html.contains("no licensee configured"));
    }

    #[test]
    fn only_admins_see_admin_navigation_and_auditors_see_evidence() {
        let summary = json!({"status": "idle", "holds": [], "entries": 3, "anchored_entries": 0});
        let agent = run_actions(&viewer("agent"), "/console/runs/r", &summary, None);
        assert!(!agent.contains("evidence?redact"));
        assert!(!agent.contains("/erase"));
        let auditor = run_actions(&viewer("auditor"), "/console/runs/r", &summary, None);
        assert!(auditor.contains("evidence?redact=detectors"));
        assert!(!auditor.contains("redact=none"), "no view_raw");
        assert!(!auditor.contains("/erase"));
        let admin = run_actions(&viewer("admin"), "/console/runs/r", &summary, None);
        assert!(admin.contains("/console/runs/r/erase"));
        let (nav, _) = chrome(&viewer("auditor"));
        assert!(!nav.contains("/console/tokens"));
        let (nav, _) = chrome(&viewer("admin"));
        assert!(nav.contains("/console/tokens") && nav.contains("/console/holds"));
    }
}
