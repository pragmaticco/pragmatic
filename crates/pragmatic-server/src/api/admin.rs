//! Holds, subjects, retention, verification, the access log and tokens
//! (design 4.3, 4.9, 4.11 and 4.13).
//!
//! Hold changes, retention runs and token changes are recorded durably in
//! the access log before they act.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{json, Map, Value as JsonValue};

use super::middleware::{durable_intent, intent};
use super::{
    blocking, json_response, need, ok, parse_json, query_pairs, query_u64, read_body, AppState,
    Caller, JSON_LIMIT,
};
use crate::access_log::record_view;
use crate::error::ApiError;
use crate::holds::NewHold;
use crate::summary::subject_hash;
use crate::timefmt;
use crate::tokens::{IssueRequest, Role, TokenError};

const ADMIN: &[Role] = &[Role::Admin];

fn path<T>(p: Result<Path<T>, PathRejection>) -> Result<T, ApiError> {
    p.map(|Path(v)| v)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))
}

/// `POST /v1/holds`.
pub async fn add_hold(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, ADMIN)?;
    let new: NewHold = parse_json(&read_body(&headers, body, JSON_LIMIT).await?)?;
    new.check().map_err(ApiError::bad_request)?;
    durable_intent(
        &app,
        intent(
            "hold.add",
            &p,
            None,
            json!({"matter": new.matter, "scope": new.scope}),
        ),
    )
    .await?;
    let hold = blocking(move || {
        let hold = app.holds.add(new, &p.token_id)?;
        // Wait out any retention action already acting on a covered run;
        // every later one re-reads holds under the run's lock and sees it.
        for id in app.store.run_ids() {
            if hold.matches(&id) {
                app.store.quiesce(&id);
            }
        }
        Ok(hold)
    })
    .await?;
    Ok(json_response(StatusCode::CREATED, &json!(hold)))
}

/// `DELETE /v1/holds/{id}`.
pub async fn remove_hold(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, ADMIN)?;
    if app.holds.get(&id).is_none() {
        return Err(ApiError::not_found());
    }
    durable_intent(&app, intent("hold.remove", &p, None, json!({"hold": id}))).await?;
    let removed = blocking(move || app.holds.remove(&id)?.ok_or_else(ApiError::not_found)).await?;
    Ok(ok(json!(removed)))
}

/// `GET /v1/holds`.
pub async fn list_holds(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    need(&c.principal, ADMIN)?;
    Ok(ok(json!({ "holds": app.holds.list() })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectBody {
    subject: String,
}

/// `POST /v1/subjects/search`: the identifier is in the body, which is
/// never logged.
pub async fn subjects(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    need(&c.principal, ADMIN)?;
    let req: SubjectBody = parse_json(&read_body(&headers, body, JSON_LIMIT).await?)?;
    if req.subject.is_empty() {
        return Err(ApiError::bad_request("subject must not be empty"));
    }
    let hash = subject_hash(&app.index_key, &req.subject);
    let runs = blocking(move || Ok(app.store.runs_with_subject(&hash))).await?;
    Ok(ok(json!({ "run_ids": runs })))
}

/// `POST /v1/retention/run`.
pub async fn retention(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, ADMIN)?;
    durable_intent(&app, intent("retention.run", &p, None, json!({}))).await?;
    let report = blocking(move || Ok(crate::retention::run(&app))).await?;
    Ok(ok(report))
}

/// `POST /v1/verify-data`: verify everything now (also what the
/// `verify-data` subcommand calls on a running server).
pub async fn verify_data(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    need(&c.principal, ADMIN)?;
    let report = blocking(move || Ok(crate::retention::verify_data(&app))).await?;
    Ok(ok(report))
}

/// `GET /v1/audit?run_id=&after=&limit=`: admins read every record;
/// auditors read the records of runs in their scopes.
pub async fn audit(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, &[Role::Admin, Role::Auditor])?;
    let (mut run, mut after, mut limit) = (None, None, 100u64);
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "run_id" => run = Some(v),
            "after" => after = Some(query_u64("after", &v)?),
            "limit" => limit = query_u64("limit", &v)?.clamp(1, 1000),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    if let Some(r) = &run {
        super::in_scope(&p, r)?;
    }
    let admin = p.role == Role::Admin;
    let (a, who) = (app.clone(), p.clone());
    let (records, next) = blocking(move || {
        a.access
            .read(after, limit as usize, |rid| match (&run, rid) {
                (Some(want), r) => r == Some(want.as_str()),
                (None, _) if admin => true,
                (None, Some(r)) => who.in_scope(r),
                (None, None) => false,
            })
            .map_err(ApiError::from)
    })
    .await?;
    let mut out = Vec::with_capacity(records.len());
    for (cursor, _, entry) in records {
        let mut view = record_view(cursor, &entry);
        if !p.view_raw {
            redact_personal(&app, &mut view);
        }
        out.push(JsonValue::Object(view));
    }
    Ok(ok(json!({ "records": out, "next": next })))
}

/// Redact the personal fields of a record for a viewer without
/// `view_raw`.
pub fn redact_personal(app: &AppState, view: &mut Map<String, JsonValue>) {
    for key in ["principal", "source_ip", "user_agent"] {
        if let Some(JsonValue::String(s)) = view.get(key) {
            let redacted = app.redactor.redact_text(s);
            view.insert(key.into(), redacted.into());
        }
    }
}

/// `POST /v1/tokens`: the token value is in the response, once.
pub async fn issue_token(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, ADMIN)?;
    let req: IssueRequest = parse_json(&read_body(&headers, body, JSON_LIMIT).await?)?;
    durable_intent(
        &app,
        intent(
            "token.issue",
            &p,
            None,
            json!({"role": req.role.as_str(), "scopes": req.scopes, "view_raw": req.view_raw}),
        ),
    )
    .await?;
    let a = app.clone();
    let (value, view) = blocking(move || {
        a.tokens
            .issue(req, timefmt::now_unix_secs())
            .map_err(token_error)
    })
    .await?;
    app.metrics.token_issued();
    // The new token's id, for the record that follows this one.
    app.access.submit(crate::access_log::AccessRecord::new(
        "token.issued",
        json!({"token_id": p.token_id, "issued": view.id, "role": view.role.as_str()}),
    ));
    Ok(json_response(
        StatusCode::CREATED,
        &json!({ "token": value, "record": view }),
    ))
}

fn token_error(e: TokenError) -> ApiError {
    match e {
        TokenError::Invalid(m) => ApiError::bad_request(m),
        TokenError::NotFound => ApiError::not_found(),
        TokenError::Io(e) => ApiError::from(e),
    }
}

/// `DELETE /v1/tokens/{id}`.
pub async fn revoke_token(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, ADMIN)?;
    durable_intent(
        &app,
        intent("token.revoke", &p, None, json!({"revoked": id})),
    )
    .await?;
    let a = app.clone();
    let view = blocking(move || {
        a.tokens
            .revoke(&id, timefmt::now_unix_secs())
            .map_err(token_error)
    })
    .await?;
    app.metrics.token_revoked();
    Ok(ok(json!(view)))
}

/// `GET /v1/tokens`.
pub async fn list_tokens(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    need(&c.principal, ADMIN)?;
    Ok(ok(json!({ "tokens": app.tokens.list() })))
}
