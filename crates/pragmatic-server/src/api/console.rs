//! Console routes (design 4.3 and 4.14).
//!
//! The server prepares each page's data with the same checks as the API
//! (role, scope, redaction, raw-read logging) and hands it to the
//! [`ConsoleRenderer`](crate::hooks::ConsoleRenderer). Forms that change
//! something go through the same operations as the API (holds, retention,
//! erasure, tokens), so the access log and the erasure ledger record them
//! the same way, and they are refused unless they carry the session's CSRF
//! token and come from the console's own origin (see [`crate::console`]).
//! A successful form redirects back to its page with a fixed notice; a
//! refused one redirects with the error code (never with text from the
//! request). A form whose action cannot be undone (erasure, removing a
//! hold, revoking a token, running retention) answers its first post with
//! a confirmation page; only the confirming post, which repeats the fields
//! with `confirm=1` and the CSRF token, acts.
//!
//! A console request that fails is answered with an HTML page in the
//! console's frame ([`html_error`]), not the API's JSON.
//!
//! Every console page carries a Content-Security-Policy that loads and
//! runs nothing and lets forms submit only to the console, and is never
//! cached or framed.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pragmatic::Journal;
use serde_json::{json, Value as JsonValue};

use super::admin::{audit_filter, withhold_personal};
use super::middleware::{durable_intent, intent};
use super::runs::{erase_run, EraseRequest};
use super::{
    blocking, need, noted, query_pairs, query_u64, read_body, AccessNote, AppState, Caller, READERS,
};
use crate::access_log::record_view;
use crate::console::{
    clear_cookie, named_cookie, random_hex, secrets_match, set_cookie, sign_in_cookie,
    SIGN_IN_COOKIE,
};
use crate::error::ApiError;
use crate::holds::{HoldScope, NewHold};
use crate::hooks::{
    ConsoleConfirm, ConsoleError, ConsoleNotice, ConsolePage, ConsoleViewer, ErasePreviewSlot,
};
use crate::store::{ListQuery, Selector};
use crate::timefmt;
use crate::tokens::{IssueRequest, Role};

/// The largest form body.
const FORM_LIMIT: u64 = 64 * 1024;

/// Timeline entries the access record of a run page names; the console
/// crate ends a page earlier when its HTML grows past its byte bound.
const PAGE_ENTRIES: u64 = pragmatic_console::PAGE_ENTRIES as u64;

fn viewer(app: &AppState, c: &Caller) -> ConsoleViewer {
    viewer_of(app, &c.principal, c.csrf.as_deref())
}

/// The viewer of a page, from a principal and its session's CSRF token.
pub fn viewer_of(
    app: &AppState,
    p: &crate::tokens::Principal,
    csrf: Option<&str>,
) -> ConsoleViewer {
    ConsoleViewer {
        token_id: p.token_id.clone(),
        name: p.name.clone(),
        role: p.role.as_str().into(),
        view_raw: p.view_raw,
        licensee: app.config.license.licensee.clone(),
        csrf: csrf.unwrap_or_default().to_string(),
    }
}

/// The headers every console page carries.
fn page_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(pragmatic_console::html::CONSOLE_POLICY),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // `same-origin`, not `no-referrer`: under `no-referrer` a browser sends
    // `Origin: null` with a form's post, which the console's origin check
    // refuses. Nothing is sent to any other site either way.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
}

/// Render a page, or explain that the renderer is missing.
fn render(app: &AppState, page: &ConsolePage<'_>, status: StatusCode) -> Response {
    match app.hooks.console.render(page) {
        Ok(html) => {
            let mut resp = (status, html).into_response();
            page_headers(&mut resp);
            resp
        }
        Err(ConsoleError::NotImplemented) => {
            let code = if status.is_success() {
                StatusCode::NOT_IMPLEMENTED
            } else {
                status
            };
            (
                code,
                "The console renderer is not part of this build. The API under /v1 serves the same data.\n",
            )
                .into_response()
        }
        Err(ConsoleError::Internal(m)) => (StatusCode::INTERNAL_SERVER_ERROR, m).into_response(),
    }
}

/// A 303 to `location`.
fn see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// A form's fields.
async fn read_form(
    app: &AppState,
    headers: &HeaderMap,
    body: Body,
) -> Result<Vec<(String, String)>, ApiError> {
    let bytes = read_body(app, headers, body, FORM_LIMIT).await?;
    Ok(form_urlencoded::parse(&bytes)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect())
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    form.iter()
        .find(|(k, _)| k == name)
        .map_or("", |(_, v)| v.as_str())
}

fn checked(form: &[(String, String)], name: &str) -> bool {
    field(form, name) == "on"
}

/// Refuse a form a browser marks as sent from another site, or whose
/// `Origin` is not this server: the session cookie is `SameSite=Strict`
/// already, and this holds even for a browser that ignores it.
fn same_origin(app: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        if site != "same-origin" && site != "none" {
            return Err(ApiError::forbidden("the form was sent from another site"));
        }
    }
    if let Some(origin) = get("origin") {
        let host = get("host").unwrap_or("");
        let public = app.config.public_url.trim_end_matches('/');
        let public_origin = public
            .find("://")
            .map(|i| match public[i + 3..].find('/') {
                Some(j) => &public[..i + 3 + j],
                None => public,
            })
            .unwrap_or("");
        let ours = origin == format!("http://{host}")
            || origin == format!("https://{host}")
            || (!public_origin.is_empty() && origin == public_origin);
        if !ours {
            return Err(ApiError::forbidden("the form was sent from another origin"));
        }
    }
    Ok(())
}

/// The checks every state-changing console form passes: same origin, and
/// the session's CSRF token.
fn check_form(
    app: &AppState,
    headers: &HeaderMap,
    c: &Caller,
    form: &[(String, String)],
) -> Result<(), ApiError> {
    same_origin(app, headers)?;
    match &c.csrf {
        Some(token) if secrets_match(token, field(form, "csrf")) => Ok(()),
        _ => Err(ApiError::forbidden(
            "the form's CSRF token does not match this session",
        )),
    }
}

/// The sentence for a refusal code the console knows.
fn refusal(code: &str) -> Option<&'static str> {
    Some(match code {
        "on_hold" => "The request was refused: the run is under a legal hold.",
        "run_locked" => {
            "The request was refused: a live lease holds the run. Check \u{2018}Revoke a live \
             lease\u{2019} to erase anyway."
        }
        "unfinished" => {
            "The request was refused: the run did not finish. Check \u{2018}The run did not \
             finish\u{2019} to erase anyway; it then can no longer resume."
        }
        "retention_locked" => {
            "The request was refused: erasure is not allowed while the retention minimum applies."
        }
        "chain_broken" => {
            "The request was refused: the stored journal is damaged, and an administrator must \
             act first."
        }
        "run_deleted" => "The request was refused: the run was deleted.",
        "bad_selector" => {
            "The request was refused: give exactly one of slots, a text to match, or every slot."
        }
        "bad_slots" => {
            "The request was refused: write each slot as cursor:slot, for example 5:0, and name \
             only slots that exist."
        }
        "bad_reason_code" => {
            "The request was refused: a reason code is 1 to 64 lowercase letters, digits and \
             _ . : -"
        }
        "nothing_to_erase" => "Nothing was erased: no sealed slot matches.",
        "bad_role" => "The request was refused: choose a role from the list.",
        "not_found" => "The request was refused: what it names does not exist.",
        "forbidden" => "The request was refused: your role cannot do this.",
        _ => return None,
    })
}

/// The notice for a `done=` or `error=` parameter: fixed text, never text
/// from the request (an unknown error code is shown as a code, checked to
/// be short lowercase letters).
fn notice(raw: Option<&str>) -> Option<ConsoleNotice> {
    let mut out = None;
    let done = |text: &str| ConsoleNotice {
        text: text.into(),
        code: None,
        refused: false,
    };
    for (k, v) in query_pairs(raw) {
        let n = match (k.as_str(), v.as_str()) {
            ("done", "erased") => done("Erased. The erasure note records who, why and when."),
            ("done", "hold_placed") => done("The hold is placed."),
            ("done", "hold_removed") => done("The hold is removed."),
            ("done", "retention") => done("Retention ran. Its actions are in the erasure ledger."),
            ("done", "token_revoked") => done("The token is revoked; its sessions are over."),
            ("error", code)
                if code.len() <= 32
                    && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') =>
            {
                match refusal(code) {
                    Some(text) => ConsoleNotice {
                        text: text.into(),
                        code: None,
                        refused: code != "nothing_to_erase",
                    },
                    None => ConsoleNotice {
                        text: "The request was refused:".into(),
                        code: Some(code.to_string()),
                        refused: true,
                    },
                }
            }
            _ => continue,
        };
        out = Some(n);
    }
    out
}

/// Where a refused form goes: back to its page with the error code.
fn refused(back: &str, e: &ApiError) -> Response {
    let code = if e.extra.get("unfinished") == Some(&JsonValue::Bool(true)) {
        "unfinished"
    } else {
        e.code
    };
    refused_with(back, code)
}

/// Back to the form's page with a console refusal code.
fn refused_with(back: &str, code: &str) -> Response {
    let sep = if back.contains('?') { '&' } else { '?' };
    see_other(&format!("{back}{sep}error={code}"))
}

/// True when the confirming post of a confirmation page sent the form.
fn confirmed(form: &[(String, String)]) -> bool {
    field(form, "confirm") == "1"
}

/// The sign-in page's notice, from its `notice=` parameter.
fn sign_in_notice(raw: Option<&str>) -> Option<&'static str> {
    query_pairs(raw)
        .into_iter()
        .find(|(k, _)| k == "notice")
        .and_then(|(_, v)| match v.as_str() {
            "signed_out" => Some("You are signed out."),
            "ended" => Some(
                "Your session has ended: sessions end after 15 minutes without a request, 12 \
                 hours after sign-in, or when their token is revoked. Sign in again to go on.",
            ),
            _ => None,
        })
}

/// `GET /console/assets/{file}`: the console's fonts, served from its own
/// origin (its policy allows `font-src 'self'` and nothing else from
/// anywhere). Each name carries a hash of the font, so it is cached for a
/// year. Open to everyone: the sign-in page needs them too, and they are
/// the same for every server.
pub async fn asset(file: Result<Path<String>, PathRejection>) -> Response {
    let font = file
        .ok()
        .and_then(|Path(name)| pragmatic_console::fonts::served(&name));
    let Some(font) = font else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };
    let mut resp = (StatusCode::OK, font.bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(pragmatic_console::fonts::FONT_TYPE),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(pragmatic_console::fonts::FONT_CACHE),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    resp
}

/// A failed console request as an HTML page in the console's frame,
/// keeping its status, its `Retry-After` and what the access log records
/// of it. A response that is not an error, or that the renderer cannot
/// draw (the 501 stand-in), is returned as it is.
pub fn html_error(
    app: &AppState,
    who: Option<(&crate::tokens::Principal, Option<&str>)>,
    run_id: Option<&str>,
    form: bool,
    mut resp: Response,
) -> Response {
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
    let Some(note) = resp.extensions().get::<super::ErrorNote>().cloned() else {
        return resp;
    };
    if !is_json {
        return resp;
    }
    let viewer = who.map(|(p, csrf)| viewer_of(app, p, csrf));
    let page = ConsolePage::Error {
        viewer: viewer.as_ref(),
        licensee: &app.config.license.licensee,
        status: status.as_u16(),
        code: note.code,
        run_id,
        form,
    };
    let Ok(html) = app.hooks.console.render(&page) else {
        return resp;
    };
    let mut out = (status, html).into_response();
    page_headers(&mut out);
    if let Some(v) = resp.headers().get(header::RETRY_AFTER) {
        out.headers_mut().insert(header::RETRY_AFTER, v.clone());
    }
    if let Some(n) = resp.extensions_mut().remove::<AccessNote>() {
        out.extensions_mut().insert(n);
    }
    out.extensions_mut().insert(note);
    out
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| named_cookie(h, name))
}

/// `GET /console/sign-in`: the form, with a fresh anti-forgery value in a
/// cookie of its own.
pub async fn sign_in_page(
    State(app): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let value = random_hex()?;
    let page = ConsolePage::SignIn {
        error: None,
        notice: sign_in_notice(raw.as_deref()),
        licensee: &app.config.license.licensee,
        csrf: &value,
    };
    let mut resp = render(&app, &page, StatusCode::OK);
    if let Ok(v) = HeaderValue::from_str(&sign_in_cookie(&value, app.config.serves_https())) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

fn sign_in_note(extra: Vec<(&str, JsonValue)>) -> AccessNote {
    AccessNote {
        extra: std::iter::once(("action".to_string(), JsonValue::from("sign_in")))
            .chain(extra.into_iter().map(|(k, v)| (k.to_string(), v)))
            .collect(),
        ..AccessNote::default()
    }
}

/// `POST /console/sign-in` with a form field `token`: exchange the token
/// for a session cookie. The form must carry its anti-forgery value.
pub async fn sign_in(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let form = read_form(&app, &headers, body).await?;
    let secure = app.config.serves_https();
    let expected = cookie(&headers, SIGN_IN_COOKIE).unwrap_or("").to_string();
    if same_origin(&app, &headers).is_err() || !secrets_match(&expected, field(&form, "csrf")) {
        let fresh = random_hex()?;
        let page = ConsolePage::SignIn {
            error: Some("The sign-in form expired or was not sent from this console. Try again."),
            notice: None,
            licensee: &app.config.license.licensee,
            csrf: &fresh,
        };
        let mut resp = render(&app, &page, StatusCode::FORBIDDEN);
        if let Ok(v) = HeaderValue::from_str(&sign_in_cookie(&fresh, secure)) {
            resp.headers_mut().insert(header::SET_COOKIE, v);
        }
        return Ok(noted(resp, sign_in_note(vec![("csrf", false.into())])));
    }
    let token = field(&form, "token").trim().to_string();
    match app.tokens.authenticate(&token, timefmt::now_unix_secs()) {
        Ok(p) if p.role != Role::WitnessClient => {
            let value = app.sessions.create(&p.token_id)?;
            let mut resp = see_other("/console");
            if let Ok(v) = HeaderValue::from_str(&set_cookie(&value, secure)) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
            Ok(noted(
                resp,
                AccessNote {
                    principal: Some(p),
                    ..sign_in_note(Vec::new())
                },
            ))
        }
        result => {
            app.metrics.token_rejected();
            let fp = match &result {
                Err(f) => f.fingerprint.clone(),
                Ok(_) => String::new(),
            };
            let error = match &result {
                Ok(_) => "This token cannot open the console.",
                Err(_) => "That token was not accepted.",
            };
            let page = ConsolePage::SignIn {
                error: Some(error),
                notice: None,
                licensee: &app.config.license.licensee,
                csrf: &expected,
            };
            let resp = render(&app, &page, StatusCode::UNAUTHORIZED);
            Ok(noted(
                resp,
                sign_in_note(vec![("token_fp", JsonValue::from(fp))]),
            ))
        }
    }
}

/// `POST /console/sign-out`: ends the session. A live session's form must
/// carry its CSRF token, so another site cannot sign a viewer out.
pub async fn sign_out(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let form = read_form(&app, &headers, body).await?;
    let value = cookie(&headers, crate::console::COOKIE).map(str::to_string);
    if let Some(s) = value.as_deref().and_then(|v| app.sessions.session(v)) {
        if same_origin(&app, &headers).is_err() || !secrets_match(&s.csrf, field(&form, "csrf")) {
            return Err(ApiError::forbidden(
                "the sign-out form's CSRF token does not match this session",
            ));
        }
    }
    let who = value
        .and_then(|v| app.sessions.remove(&v))
        .and_then(|id| app.tokens.principal_by_id(&id, timefmt::now_unix_secs()));
    let mut resp = see_other("/console/sign-in?notice=signed_out");
    if let Ok(v) = HeaderValue::from_str(&clear_cookie(app.config.serves_https())) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(noted(
        resp,
        AccessNote {
            principal: who,
            extra: [("action".to_string(), JsonValue::from("sign_out"))]
                .into_iter()
                .collect(),
            ..AccessNote::default()
        },
    ))
}

/// `GET /console`: the runs list.
pub async fn runs(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, READERS)?;
    let mut q = ListQuery {
        limit: 100,
        ..ListQuery::default()
    };
    let mut filters = serde_json::Map::new();
    for (k, v) in query_pairs(raw.as_deref()) {
        filters.insert(k.clone(), v.clone().into());
        if v.is_empty() {
            continue;
        }
        match k.as_str() {
            "prefix" => q.prefix = Some(v),
            "q" => q.q = Some(v),
            "program" => q.program = Some(v),
            "status" => q.status = Some(v),
            "after" => q.after = Some(v),
            "since" => q.since = timefmt::parse_rfc3339(&v),
            "until" => q.until = timefmt::parse_rfc3339(&v),
            "label" => {
                if let Some((k, v)) = v.split_once('=') {
                    q.labels.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            other => {
                if let Some(label) = other.strip_prefix("label.") {
                    q.labels.push((label.to_string(), v));
                }
            }
        }
    }
    let (a, who) = (app.clone(), p.clone());
    let page = blocking(move || Ok(a.store.list(&q, &a.holds, |id| who.in_scope(id)))).await?;
    let v = viewer(&app, &c);
    let filters = JsonValue::Object(filters);
    let data = ConsolePage::Runs {
        viewer: &v,
        runs: &page.runs,
        next: page.next.as_deref(),
        filters: &filters,
    };
    Ok(render(&app, &data, StatusCode::OK))
}

fn path_id(id: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    id.map(|Path(v)| v)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))
}

/// The run's anchoring as the console shows it: its newest independently
/// anchored leaf, or else its newest leaf, which only the operator's own
/// signature vouches for.
fn anchor_status(app: &AppState, run_id: &str) -> Option<pragmatic_console::AnchorStatus> {
    let anchors = app.hooks.anchoring.run_anchors(run_id).ok()?;
    let mut pairs = anchors.anchors.iter().zip(&anchors.witnessing);
    let pick = pairs
        .clone()
        .rev()
        .find(|(_, w)| w.independent)
        .or_else(|| pairs.next_back())?;
    let (anchor, w) = pick;
    use pragmatic::evidence::Witness;
    use pragmatic_console::{AnchorWitness, WitnessTrust};
    // The witnesses of that anchor: trusted when the server counts their
    // operator towards independence, its own signature otherwise.
    let witnesses = anchor
        .witnesses
        .iter()
        .map(|wit| {
            let (operator, kind) = match wit {
                Witness::Rfc3161 { operator, .. } => (operator.clone(), "RFC 3161"),
                Witness::Cosignature { name, .. } => (name.clone(), "cosignature"),
            };
            let trust = if w.independent && w.operators.contains(&operator) {
                WitnessTrust::Trusted
            } else {
                WitnessTrust::Operator
            };
            // A configured TSA's name and the root its pinned anchors
            // chain to: shown, never counted.
            let label = matches!(wit, Witness::Rfc3161 { .. })
                .then(|| app.tsa_labels.iter().find(|l| l.operator == operator))
                .flatten();
            AnchorWitness {
                name: label.map(|l| l.name.clone()).filter(|n| !n.is_empty()),
                root: label.and_then(|l| l.root.clone()),
                operator,
                kind: kind.to_string(),
                trust,
            }
        })
        .collect();
    Some(pragmatic_console::AnchorStatus {
        anchored_entries: pragmatic::evidence::Leaf::decode(&anchor.leaf)
            .map(|l| l.entries)
            .unwrap_or(0),
        independent: w.independent,
        operators: w.operators.clone(),
        time: w.time.map(|t| timefmt::rfc3339(t as i64)),
        witnesses,
    })
}

/// `GET /console/runs/{id}?from=`: the run's page, a page of its timeline
/// at a time, its anchoring, evidence downloads and (admin) erasure.
pub async fn run(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = path_id(id)?;
    let p = c.principal.clone();
    need(&p, READERS)?;
    super::in_scope(&p, &id)?;
    let mut from = 0u64;
    for (k, v) in query_pairs(raw.as_deref()) {
        if k == "from" {
            from = query_u64("from", &v)?;
        }
    }
    if p.view_raw {
        durable_intent(
            &app,
            intent("read_raw", &p, Some(&id), json!({"what": "console"})),
        )
        .await?;
    }
    let notice = notice(raw.as_deref());
    let v = viewer(&app, &c);
    let a = app.clone();
    let run = id.clone();
    let (page, shown) = blocking(move || {
        let summary = a.store.summary(&run, &a.holds)?;
        // The journal is held twice while it is parsed: take its share of
        // the byte budget for both.
        let durable = a.store.durable_scaled(&run, 3)?;
        let (journal, report) = Journal::audit_bytes(&durable.bytes, None)
            .map_err(|e| ApiError::chain_broken(&e.to_string()))?;
        drop(durable);
        let anchor = anchor_status(&a, &run);
        // The principal of each token, to name the one that recorded each
        // attempt: personal data, so only for a viewer who sees content
        // raw (as the access log does).
        let principals: Vec<(String, String)> = if v.view_raw {
            a.tokens
                .list()
                .into_iter()
                .map(|t| (t.id, t.principal))
                .collect()
        } else {
            Vec::new()
        };
        let from = from.min(journal.len());
        let shown = (from, from.saturating_add(PAGE_ENTRIES).min(journal.len()));
        let data = ConsolePage::Run {
            viewer: &v,
            run_id: &run,
            summary: &summary,
            journal: &journal,
            report: &report,
            anchor: anchor.as_ref(),
            from,
            redactor: (!v.view_raw).then_some(a.redactor.as_ref()),
            principals: &principals,
            notice: notice.as_ref(),
        };
        Ok((render(&a, &data, StatusCode::OK), shown))
    })
    .await?;
    Ok(noted(
        page,
        AccessNote {
            raw: p.view_raw,
            cursor_from: Some(shown.0),
            cursor_to: Some(shown.1),
            ..AccessNote::default()
        },
    ))
}

/// `GET /console/runs/{id}/evidence?redact=`: download a bundle.
pub async fn evidence(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = path_id(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Auditor, Role::Admin])?;
    super::in_scope(&p, &id)?;
    let redact = query_pairs(raw.as_deref())
        .into_iter()
        .find(|(k, _)| k == "redact")
        .map(|(_, v)| v);
    super::runs::build_evidence(app, p, id, redact, false).await
}

/// `POST /console/runs/{id}/erase` (admin): the erasure form. Its first
/// post shows what would be erased, from the stored journal, and erases
/// nothing; the confirming post erases.
pub async fn erase(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path_id(id)?;
    need(&c.principal, &[Role::Admin])?;
    super::in_scope(&c.principal, &id)?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    let back = format!("/console/runs/{}", crate::console_ui::encode(&id));
    let selector = match (
        field(&form, "slots").trim(),
        field(&form, "match"),
        checked(&form, "all"),
    ) {
        (slots, "", false) if !slots.is_empty() => {
            let mut out = Vec::new();
            for pair in slots.split([' ', ',']).filter(|s| !s.is_empty()) {
                let parsed = pair.split_once(':').and_then(|(c, s)| {
                    Some((c.trim().parse::<u64>().ok()?, s.trim().parse::<u8>().ok()?))
                });
                match parsed {
                    Some(p) => out.push(p),
                    None => return Ok(refused_with(&back, "bad_slots")),
                }
            }
            Selector::Slots(out)
        }
        ("", m, false) if !m.is_empty() => Selector::Match(m.to_string()),
        ("", "", true) => Selector::All,
        _ => return Ok(refused_with(&back, "bad_selector")),
    };
    let reason_code = field(&form, "reason_code").to_string();
    let reason_ok = !reason_code.is_empty()
        && reason_code.len() <= 64
        && reason_code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.:-".contains(&b));
    if !reason_ok {
        return Ok(refused_with(&back, "bad_reason_code"));
    }
    if !confirmed(&form) {
        // A run under a hold is refused before anything is asked.
        if !app.holds.matching(&id).is_empty() {
            return Ok(refused_with(&back, "on_hold"));
        }
        // A preview of "every slot containing" says whether the run holds
        // that text, which is a read of its content: it is logged as a raw
        // read before it is made, so probing a run leaves the same record
        // as reading it.
        if let Selector::Match(_) = &selector {
            durable_intent(
                &app,
                intent(
                    "read_raw",
                    &c.principal,
                    Some(&id),
                    json!({"what": "erase_preview"}),
                ),
            )
            .await?;
        }
        return erase_confirmation(&app, &c, &id, &back, &form, &selector).await;
    }
    let request = EraseRequest {
        selector,
        reason_code,
        reason: field(&form, "reason").to_string(),
        force: checked(&form, "force"),
        allow_unfinished: checked(&form, "allow_unfinished"),
    };
    Ok(match erase_run(&app, &c.principal, id, request).await {
        Ok(_) => see_other(&format!("{back}?done=erased")),
        Err(e) => refused(&back, &e),
    })
}

/// The confirmation of an erasure: the slots it would erase, resolved
/// from the stored journal exactly as the erasure resolves them, and the
/// form's fields to post again.
async fn erase_confirmation(
    app: &AppState,
    c: &Caller,
    id: &str,
    back: &str,
    form: &[(String, String)],
    selector: &Selector,
) -> Result<Response, ApiError> {
    use pragmatic::journal::EraseSelector;
    let wanted = match selector {
        Selector::Slots(s) => EraseSelector::Slots(s.clone()),
        Selector::Match(t) => EraseSelector::Match(t.as_bytes().to_vec()),
        Selector::All => EraseSelector::All,
    };
    let (a, run) = (app.clone(), id.to_string());
    let preview = blocking(move || {
        let durable = a.store.durable_scaled(&run, 3)?;
        let (journal, _) = Journal::audit_bytes(&durable.bytes, None)
            .map_err(|e| ApiError::chain_broken(&e.to_string()))?;
        drop(durable);
        let targets = match journal.erase_targets(&wanted) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let slots: Vec<ErasePreviewSlot> = targets
            .iter()
            .take(50)
            .map(|&(cursor, k)| ErasePreviewSlot {
                cursor,
                slot: k,
                what: pragmatic_console::text::slot_title(&journal, cursor, k as usize),
                bytes: journal
                    .get(cursor)
                    .and_then(|e| e.event.slot_contents().get(k as usize).copied())
                    .and_then(|c| c.value())
                    .map_or(0, |v| v.len() as u64),
            })
            .collect();
        Ok(Some((slots, targets.len())))
    })
    .await?;
    let Some((slots, total)) = preview else {
        return Ok(refused_with(back, "bad_slots"));
    };
    if total == 0 {
        return Ok(refused_with(back, "nothing_to_erase"));
    }
    let keep = [
        "slots",
        "match",
        "all",
        "reason_code",
        "reason",
        "force",
        "allow_unfinished",
    ];
    let fields: Vec<(String, String)> = form
        .iter()
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .cloned()
        .collect();
    let confirm = ConsoleConfirm::Erase {
        run_id: id.to_string(),
        slots,
        total,
        reason_code: field(form, "reason_code").to_string(),
        reason: field(form, "reason").to_string(),
        force: checked(form, "force"),
        allow_unfinished: checked(form, "allow_unfinished"),
        fields,
    };
    let v = viewer(app, c);
    let action = format!("{back}/erase");
    let page = ConsolePage::Confirm {
        viewer: &v,
        action: &action,
        back,
        confirm: &confirm,
    };
    Ok(render(app, &page, StatusCode::OK))
}

/// A confirmation page for a form with no fields of its own.
fn confirmation(
    app: &AppState,
    c: &Caller,
    action: &str,
    back: &str,
    confirm: ConsoleConfirm,
) -> Response {
    let v = viewer(app, c);
    let page = ConsolePage::Confirm {
        viewer: &v,
        action,
        back,
        confirm: &confirm,
    };
    render(app, &page, StatusCode::OK)
}

/// `GET /console/access?after=`: the access log (admins: all; auditors:
/// their runs). Personal fields are withheld without `view_raw`.
pub async fn access(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, &[Role::Admin, Role::Auditor])?;
    let mut after = None;
    for (k, v) in query_pairs(raw.as_deref()) {
        if k == "after" {
            after = Some(query_u64("after", &v)?);
        }
    }
    let filter = audit_filter(&p, None);
    let a = app.clone();
    let (records, next) =
        blocking(move || a.access.read(after, 200, &filter).map_err(ApiError::from)).await?;
    let records: Vec<JsonValue> = records
        .into_iter()
        .map(|(cursor, _, entry)| {
            let mut view = record_view(cursor, &entry);
            if !p.view_raw {
                withhold_personal(&mut view);
            }
            JsonValue::Object(view)
        })
        .collect();
    let v = viewer(&app, &c);
    let data = ConsolePage::AccessLog {
        viewer: &v,
        records: &records,
        next,
    };
    Ok(render(&app, &data, StatusCode::OK))
}

/// `GET /console/holds`: holds and retention policies (admin).
pub async fn holds(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    need(&c.principal, &[Role::Admin])?;
    let holds: Vec<JsonValue> = app.holds.list().into_iter().map(|h| json!(h)).collect();
    let retention = json!(app.config.retention);
    let notice = notice(raw.as_deref());
    let v = viewer(&app, &c);
    let data = ConsolePage::Holds {
        viewer: &v,
        holds: &holds,
        retention: &retention,
        notice: notice.as_ref(),
    };
    Ok(render(&app, &data, StatusCode::OK))
}

/// `POST /console/holds` (admin): place a hold.
pub async fn add_hold(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    need(&c.principal, &[Role::Admin])?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    let ids: Vec<String> = field(&form, "run_ids")
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let prefix = field(&form, "prefix");
    let new = NewHold {
        matter: field(&form, "matter").to_string(),
        scope: HoldScope {
            run_ids: (!ids.is_empty()).then_some(ids),
            prefix: (!prefix.is_empty()).then(|| prefix.to_string()),
        },
    };
    Ok(
        match super::admin::place_hold(&app, &c.principal, new).await {
            Ok(_) => see_other("/console/holds?done=hold_placed"),
            Err(e) => refused("/console/holds", &e),
        },
    )
}

/// `POST /console/holds/{id}/remove` (admin).
pub async fn remove_hold(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path_id(id)?;
    need(&c.principal, &[Role::Admin])?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    if !confirmed(&form) {
        let Some(hold) = app.holds.get(&id) else {
            return Ok(refused_with("/console/holds", "not_found"));
        };
        let action = format!("/console/holds/{}/remove", crate::console_ui::encode(&id));
        return Ok(confirmation(
            &app,
            &c,
            &action,
            "/console/holds",
            ConsoleConfirm::RemoveHold { hold: json!(hold) },
        ));
    }
    Ok(
        match super::admin::lift_hold(&app, &c.principal, id).await {
            Ok(_) => see_other("/console/holds?done=hold_removed"),
            Err(e) => refused("/console/holds", &e),
        },
    )
}

/// `POST /console/retention/run` (admin).
pub async fn retention(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    need(&c.principal, &[Role::Admin])?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    if !confirmed(&form) {
        return Ok(confirmation(
            &app,
            &c,
            "/console/retention/run",
            "/console/holds",
            ConsoleConfirm::RunRetention {
                policies: json!(app.config.retention),
            },
        ));
    }
    Ok(
        match super::admin::run_retention(&app, &c.principal).await {
            Ok(_) => see_other("/console/holds?done=retention"),
            Err(e) => refused("/console/holds", &e),
        },
    )
}

fn token_page(
    app: &AppState,
    c: &Caller,
    issued: Option<(&str, &JsonValue)>,
    notice: Option<&ConsoleNotice>,
) -> Response {
    let tokens: Vec<JsonValue> = app.tokens.list().into_iter().map(|t| json!(t)).collect();
    let v = viewer(app, c);
    let data = ConsolePage::Tokens {
        viewer: &v,
        tokens: &tokens,
        issued,
        notice,
    };
    render(app, &data, StatusCode::OK)
}

/// `GET /console/tokens` (admin).
pub async fn tokens(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    need(&c.principal, &[Role::Admin])?;
    let notice = notice(raw.as_deref());
    Ok(token_page(&app, &c, None, notice.as_ref()))
}

/// `POST /console/tokens` (admin): issue a token. The value is shown on
/// the page that answers, once, and never put in a URL.
pub async fn issue_token(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    need(&c.principal, &[Role::Admin])?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    let Some(role) = Role::parse(field(&form, "role")) else {
        return Ok(refused_with("/console/tokens", "bad_role"));
    };
    let expires = field(&form, "expires_at").trim();
    let req = IssueRequest {
        name: field(&form, "name").to_string(),
        principal: field(&form, "principal").to_string(),
        role,
        scopes: field(&form, "scopes")
            .split([' ', ','])
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        view_raw: checked(&form, "view_raw"),
        expires_at: (!expires.is_empty()).then(|| expires.to_string()),
    };
    Ok(match super::admin::issue(&app, &c.principal, req).await {
        Ok((value, view)) => {
            let record = json!(view);
            token_page(&app, &c, Some((&value, &record)), None)
        }
        Err(e) => refused("/console/tokens", &e),
    })
}

/// `POST /console/tokens/{id}/revoke` (admin).
pub async fn revoke_token(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path_id(id)?;
    need(&c.principal, &[Role::Admin])?;
    let form = read_form(&app, &headers, body).await?;
    check_form(&app, &headers, &c, &form)?;
    if !confirmed(&form) {
        let Some(token) = app.tokens.list().into_iter().find(|t| t.id == id) else {
            return Ok(refused_with("/console/tokens", "not_found"));
        };
        let action = format!("/console/tokens/{}/revoke", crate::console_ui::encode(&id));
        return Ok(confirmation(
            &app,
            &c,
            &action,
            "/console/tokens",
            ConsoleConfirm::RevokeToken {
                token: json!(token),
            },
        ));
    }
    Ok(match super::admin::revoke(&app, &c.principal, id).await {
        Ok(_) => see_other("/console/tokens?done=token_revoked"),
        Err(e) => refused("/console/tokens", &e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_are_fixed_text() {
        let text = |raw: &str| notice(Some(raw)).map(|n| (n.text, n.code, n.refused));
        assert_eq!(
            text("done=erased"),
            Some((
                "Erased. The erasure note records who, why and when.".into(),
                None,
                false
            ))
        );
        assert_eq!(
            text("error=on_hold"),
            Some((
                "The request was refused: the run is under a legal hold.".into(),
                None,
                true
            ))
        );
        assert_eq!(
            text("error=odd_code"),
            Some((
                "The request was refused:".into(),
                Some("odd_code".into()),
                true
            ))
        );
        assert_eq!(notice(Some("error=%3Cscript%3E")), None);
        assert_eq!(notice(Some("done=whatever")), None);
        assert_eq!(
            sign_in_notice(Some("notice=signed_out")),
            Some("You are signed out.")
        );
        assert_eq!(sign_in_notice(Some("notice=%3Cx%3E")), None);
    }
}
