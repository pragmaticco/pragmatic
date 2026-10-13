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
//! request).
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
use crate::hooks::{ConsoleError, ConsolePage, ConsoleViewer};
use crate::store::{ListQuery, Selector};
use crate::timefmt;
use crate::tokens::{IssueRequest, Role};

/// The largest form body.
const FORM_LIMIT: u64 = 64 * 1024;

/// Timeline entries the access record of a run page names; the console
/// crate ends a page earlier when its HTML grows past its byte bound.
const PAGE_ENTRIES: u64 = pragmatic_console::PAGE_ENTRIES as u64;

fn viewer(app: &AppState, c: &Caller) -> ConsoleViewer {
    let p = &c.principal;
    ConsoleViewer {
        token_id: p.token_id.clone(),
        name: p.name.clone(),
        role: p.role.as_str().into(),
        view_raw: p.view_raw,
        licensee: app.config.license.licensee.clone(),
        csrf: c.csrf.clone().unwrap_or_default(),
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
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
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

/// The notice for a `done=` or `error=` parameter: fixed text, never text
/// from the request.
fn notice(raw: Option<&str>) -> Option<String> {
    let mut out = None;
    for (k, v) in query_pairs(raw) {
        let text = match (k.as_str(), v.as_str()) {
            ("done", "erased") => "Erased. The erasure note records who, why and when.".into(),
            ("done", "hold_placed") => "The hold is placed.".into(),
            ("done", "hold_removed") => "The hold is removed.".into(),
            ("done", "retention") => "Retention ran. Its actions are in the erasure ledger.".into(),
            ("done", "token_revoked") => "The token is revoked; its sessions are over.".into(),
            ("error", code)
                if code.len() <= 32
                    && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') =>
            {
                format!("The request was refused: {code}.")
            }
            _ => continue,
        };
        out = Some(text);
    }
    out
}

/// Where a refused form goes: back to its page with the error code.
fn refused(back: &str, e: &ApiError) -> Response {
    let sep = if back.contains('?') { '&' } else { '?' };
    see_other(&format!("{back}{sep}error={}", e.code))
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
pub async fn sign_in_page(State(app): State<AppState>) -> Result<Response, ApiError> {
    let value = random_hex()?;
    let page = ConsolePage::SignIn {
        error: None,
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
            let page = ConsolePage::SignIn {
                error: Some("That token was not accepted."),
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
    let mut resp = see_other("/console/sign-in");
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
    Some(pragmatic_console::AnchorStatus {
        anchored_entries: pragmatic::evidence::Leaf::decode(&anchor.leaf)
            .map(|l| l.entries)
            .unwrap_or(0),
        independent: w.independent,
        operators: w.operators.clone(),
        time: w.time.map(|t| timefmt::rfc3339(t as i64)),
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
            notice: notice.as_deref(),
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

/// `POST /console/runs/{id}/erase` (admin): the erasure form.
pub async fn erase(
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
                    None => return Ok(refused(&back, &ApiError::bad_request("slots"))),
                }
            }
            Selector::Slots(out)
        }
        ("", m, false) if !m.is_empty() => Selector::Match(m.to_string()),
        ("", "", true) => Selector::All,
        _ => return Ok(refused(&back, &ApiError::bad_request("selector"))),
    };
    let request = EraseRequest {
        selector,
        reason_code: field(&form, "reason_code").to_string(),
        reason: field(&form, "reason").to_string(),
        force: checked(&form, "force"),
        allow_unfinished: checked(&form, "allow_unfinished"),
    };
    Ok(match erase_run(&app, &c.principal, id, request).await {
        Ok(_) => see_other(&format!("{back}?done=erased")),
        Err(e) => refused(&back, &e),
    })
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
        notice: notice.as_deref(),
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
    notice: Option<&str>,
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
    Ok(token_page(&app, &c, None, notice.as_deref()))
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
        return Ok(refused("/console/tokens", &ApiError::bad_request("role")));
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
        assert_eq!(
            notice(Some("done=erased")).as_deref(),
            Some("Erased. The erasure note records who, why and when.")
        );
        assert_eq!(
            notice(Some("error=on_hold")).as_deref(),
            Some("The request was refused: on_hold.")
        );
        assert_eq!(notice(Some("error=%3Cscript%3E")), None);
        assert_eq!(notice(Some("done=whatever")), None);
    }
}
