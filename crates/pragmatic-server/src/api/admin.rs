//! Holds, subjects, retention, verification, the access log and tokens
//! (design 4.3, 4.9, 4.11 and 4.13).
//!
//! Hold changes, retention runs and token changes are recorded durably in
//! the access log before they act. Hold changes are also written to the
//! erasure ledger (fsynced) before they act, so a restore from an earlier
//! backup places and removes them again (design 4.13), and the `hold`
//! webhook announces each one.

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
use crate::access_log::{record_view, Filter};
use crate::error::ApiError;
use crate::holds::{Hold, Holds, NewHold};
use crate::ledger::{LedgerKind, LedgerRecord};
use crate::summary::subject_hash;
use crate::timefmt;
use crate::tokens::{IssueRequest, Role, TokenError};
use crate::webhooks::WebhookEvent;

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
    let new: NewHold = parse_json(&read_body(&app, &headers, body, JSON_LIMIT).await?)?;
    new.check().map_err(ApiError::bad_request)?;
    let hold = Holds::prepare(new, &p.token_id)?;
    let cursor = durable_intent(
        &app,
        intent(
            "hold.add",
            &p,
            None,
            json!({"hold": hold.id, "matter": hold.matter, "scope": hold.scope}),
        ),
    )
    .await?;
    let hold = blocking(move || {
        let record = LedgerRecord::hold(LedgerKind::HoldAdd, hold.clone(), &p.token_id, cursor);
        let record = app.ledger.append(record)?;
        let hold = app.holds.insert(hold)?;
        hold_webhook(&app, "add", &hold, record.seq);
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

/// The `hold` webhook: the action, the hold's id and scope, and its ledger
/// record (never the matter, which can name people).
fn hold_webhook(app: &AppState, action: &str, hold: &Hold, seq: u64) {
    app.webhooks.send(WebhookEvent::new(
        "hold",
        None,
        json!({"action": action, "hold": hold.id, "scope": hold.scope, "ledger_seq": seq}),
    ));
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
    let Some(hold) = app.holds.get(&id) else {
        return Err(ApiError::not_found());
    };
    let cursor = durable_intent(&app, intent("hold.remove", &p, None, json!({"hold": id}))).await?;
    let removed = blocking(move || {
        let record = LedgerRecord::hold(LedgerKind::HoldRemove, hold, &p.token_id, cursor);
        let record = app.ledger.append(record)?;
        let removed = app.holds.remove(&id)?.ok_or_else(ApiError::not_found)?;
        hold_webhook(&app, "remove", &removed, record.seq);
        Ok(removed)
    })
    .await?;
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
    let req: SubjectBody = parse_json(&read_body(&app, &headers, body, JSON_LIMIT).await?)?;
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
    let filter = audit_filter(&p, run);
    let a = app.clone();
    let (records, next) = blocking(move || {
        a.access
            .read(after, limit as usize, &filter)
            .map_err(ApiError::from)
    })
    .await?;
    let mut out = Vec::with_capacity(records.len());
    for (cursor, _, entry) in records {
        let mut view = record_view(cursor, &entry);
        if !p.view_raw {
            withhold_personal(&mut view);
        }
        out.push(JsonValue::Object(view));
    }
    Ok(ok(json!({ "records": out, "next": next })))
}

/// Which access-log records a caller reads: one run's, every record (an
/// admin), or the records of the caller's in-scope runs.
pub fn audit_filter(p: &crate::tokens::Principal, run: Option<String>) -> Filter {
    match run {
        Some(r) => Filter::Run(r),
        None if p.role == Role::Admin => Filter::All,
        None => Filter::Scopes(p.scopes.clone()),
    }
}

/// The fields of an access-log record that hold personal data: the payload
/// slot's fields.
pub const PERSONAL_FIELDS: [&str; 5] = [
    "principal",
    "source_ip",
    "user_agent",
    "token_name",
    "token_principal",
];

/// What a viewer without `view_raw` sees in place of a personal field.
pub const WITHHELD: &str = "[withheld]";

/// Withhold the personal fields of a record from a viewer without
/// `view_raw`. They are replaced whole rather than run through the content
/// detectors: an address or a name the detectors do not recognize (an IPv6
/// address, a principal that is not an email address) would otherwise be
/// served as is, and with `[redaction] builtin = []` everything would be.
pub fn withhold_personal(view: &mut Map<String, JsonValue>) {
    for key in PERSONAL_FIELDS {
        if let Some(v) = view.get_mut(key) {
            if !v.is_null() {
                *v = WITHHELD.into();
            }
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
    let req: IssueRequest = parse_json(&read_body(&app, &headers, body, JSON_LIMIT).await?)?;
    let (value, record) = app
        .tokens
        .prepare(req, &p.token_id, timefmt::now_unix_secs())
        .map_err(token_error)?;
    // Durable before the token exists, and naming it: who issued which
    // token is never lost with the records queued after it.
    let mut rec = intent(
        "token.issue",
        &p,
        None,
        json!({"issued": record.id, "issued_role": record.role.as_str(),
               "scopes": record.scopes, "view_raw": record.view_raw}),
    );
    rec.personal
        .insert("token_name".into(), record.name.clone().into());
    rec.personal
        .insert("token_principal".into(), record.principal.clone().into());
    durable_intent(&app, rec).await?;
    let a = app.clone();
    let view = blocking(move || a.tokens.add(record).map_err(token_error)).await?;
    app.metrics.token_issued();
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
