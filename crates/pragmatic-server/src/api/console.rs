//! Console routes (design 4.3 and 4.14).
//!
//! The server prepares each page's data with the same checks as the API
//! (role, scope, redaction, raw-read logging) and hands it to the
//! [`ConsoleRenderer`](crate::hooks::ConsoleRenderer). Until the renderer
//! is integrated, pages answer 501; sign-in and sign-out work regardless.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value as JsonValue};

use super::admin::{audit_filter, withhold_personal};
use super::middleware::{durable_intent, intent};
use super::{
    blocking, need, noted, query_pairs, query_u64, read_body, AccessNote, AppState, Caller, READERS,
};
use crate::access_log::record_view;
use crate::console::{clear_cookie, cookie_value, set_cookie};
use crate::error::ApiError;
use crate::hooks::{ConsoleError, ConsolePage, ConsoleViewer};
use crate::store::ListQuery;
use crate::timefmt;
use crate::tokens::{Principal, Role};
use crate::views::{self, ViewOptions, LIST_SLOT_LIMIT};

fn viewer(app: &AppState, p: &Principal) -> ConsoleViewer {
    ConsoleViewer {
        token_id: p.token_id.clone(),
        name: p.name.clone(),
        role: p.role.as_str().into(),
        view_raw: p.view_raw,
        licensee: app.config.license.licensee.clone(),
    }
}

/// Render a page, or explain that the renderer is missing.
fn render(app: &AppState, page: &ConsolePage<'_>, status: StatusCode) -> Response {
    match app.hooks.console.render(page) {
        Ok(html) => {
            let mut resp = (status, html).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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

/// `GET /console/sign-in`.
pub async fn sign_in_page(State(app): State<AppState>) -> Response {
    let page = ConsolePage::SignIn {
        error: None,
        licensee: &app.config.license.licensee,
    };
    render(&app, &page, StatusCode::OK)
}

/// `POST /console/sign-in` with a form field `token`: exchange the token
/// for a session cookie.
pub async fn sign_in(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let body = read_body(&app, &headers, body, 4096).await?;
    let token = form_urlencoded::parse(&body)
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let secure = app.config.serves_https();
    match app
        .tokens
        .authenticate(token.trim(), timefmt::now_unix_secs())
    {
        Ok(p) if p.role != Role::WitnessClient => {
            let value = app.sessions.create(&p.token_id)?;
            let mut resp = StatusCode::SEE_OTHER.into_response();
            let h = resp.headers_mut();
            h.insert(header::LOCATION, HeaderValue::from_static("/console"));
            if let Ok(v) = HeaderValue::from_str(&set_cookie(&value, secure)) {
                h.insert(header::SET_COOKIE, v);
            }
            Ok(noted(
                resp,
                AccessNote {
                    principal: Some(p),
                    extra: [("action".to_string(), JsonValue::from("sign_in"))]
                        .into_iter()
                        .collect(),
                    ..AccessNote::default()
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
            };
            let resp = render(&app, &page, StatusCode::UNAUTHORIZED);
            Ok(noted(
                resp,
                AccessNote {
                    extra: [
                        ("action".to_string(), JsonValue::from("sign_in")),
                        ("token_fp".to_string(), JsonValue::from(fp)),
                    ]
                    .into_iter()
                    .collect(),
                    ..AccessNote::default()
                },
            ))
        }
    }
}

/// `POST /console/sign-out`.
pub async fn sign_out(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let value = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(cookie_value)
        .map(str::to_string);
    let who = value
        .and_then(|v| app.sessions.remove(&v))
        .and_then(|id| app.tokens.principal_by_id(&id, timefmt::now_unix_secs()));
    let mut resp = StatusCode::SEE_OTHER.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::LOCATION,
        HeaderValue::from_static("/console/sign-in"),
    );
    if let Ok(v) = HeaderValue::from_str(&clear_cookie(app.config.serves_https())) {
        h.insert(header::SET_COOKIE, v);
    }
    noted(
        resp,
        AccessNote {
            principal: who,
            extra: [("action".to_string(), JsonValue::from("sign_out"))]
                .into_iter()
                .collect(),
            ..AccessNote::default()
        },
    )
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
        match k.as_str() {
            "prefix" => q.prefix = Some(v),
            "q" => q.q = Some(v),
            "program" => q.program = Some(v),
            "status" => q.status = Some(v),
            "after" => q.after = Some(v),
            "since" => q.since = timefmt::parse_rfc3339(&v),
            "until" => q.until = timefmt::parse_rfc3339(&v),
            other => {
                if let Some(label) = other.strip_prefix("label.") {
                    q.labels.push((label.to_string(), v));
                }
            }
        }
    }
    let (a, who) = (app.clone(), p.clone());
    let page = blocking(move || Ok(a.store.list(&q, &a.holds, |id| who.in_scope(id)))).await?;
    let v = viewer(&app, &p);
    let filters = JsonValue::Object(filters);
    let data = ConsolePage::Runs {
        viewer: &v,
        runs: &page.runs,
        next: page.next.as_deref(),
        filters: &filters,
    };
    Ok(render(&app, &data, StatusCode::OK))
}

/// `GET /console/runs/{id}`: summary, timeline page and anchors.
pub async fn run(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = id
        .map(|Path(v)| v)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))?;
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
    let (a, run_id) = (app.clone(), id.clone());
    let (summary, page) = blocking(move || {
        let s = a.store.summary(&run_id, &a.holds)?;
        let page = a.store.entries_page(&run_id, from, 200)?;
        Ok((s, page))
    })
    .await?;
    let opts = ViewOptions {
        raw: p.view_raw,
        redactor: &app.redactor,
        limit: Some(LIST_SLOT_LIMIT),
    };
    let entries: Vec<JsonValue> = page
        .entries
        .iter()
        .map(|e| views::read_entry_json(e, opts))
        .collect();
    let end = from + entries.len() as u64;
    let next = page.next;
    let v = viewer(&app, &p);
    let data = ConsolePage::Run {
        viewer: &v,
        summary: &summary,
        entries: &entries,
        next,
        anchors: &[],
    };
    Ok(noted(
        render(&app, &data, StatusCode::OK),
        AccessNote {
            raw: p.view_raw,
            cursor_from: Some(from),
            cursor_to: Some(end),
            ..AccessNote::default()
        },
    ))
}

/// `GET /console/runs/{id}/evidence`: download a bundle.
pub async fn evidence(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = id
        .map(|Path(v)| v)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))?;
    let p = c.principal.clone();
    need(&p, &[Role::Auditor, Role::Admin])?;
    super::in_scope(&p, &id)?;
    let redact = query_pairs(raw.as_deref())
        .into_iter()
        .find(|(k, _)| k == "redact")
        .map(|(_, v)| v);
    super::runs::build_evidence(app, p, id, redact, false).await
}

/// `GET /console/access`: the access log (admins: all; auditors: their
/// runs).
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
    let v = viewer(&app, &p);
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
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, &[Role::Admin])?;
    let holds: Vec<JsonValue> = app.holds.list().into_iter().map(|h| json!(h)).collect();
    let retention = json!(app.config.retention);
    let v = viewer(&app, &p);
    let data = ConsolePage::Holds {
        viewer: &v,
        holds: &holds,
        retention: &retention,
    };
    Ok(render(&app, &data, StatusCode::OK))
}

/// `GET /console/tokens` (admin).
pub async fn tokens(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, &[Role::Admin])?;
    let tokens: Vec<JsonValue> = app.tokens.list().into_iter().map(|t| json!(t)).collect();
    let v = viewer(&app, &p);
    let data = ConsolePage::Tokens {
        viewer: &v,
        tokens: &tokens,
    };
    Ok(render(&app, &data, StatusCode::OK))
}
