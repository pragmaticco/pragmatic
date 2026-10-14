//! Witness mode endpoints (design 4.8): `POST /add-checkpoint` (also at
//! `POST /v1/witness`), `GET /v1/witness/log/{origin}` and
//! `POST /v1/witness/resume/{origin}`.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use serde::Deserialize;
use serde_json::json;

use super::middleware::{durable_intent, intent};
use super::{
    blocking, need, ok, parse_json, query_pairs, query_u64, read_body, AppState, Caller, JSON_LIMIT,
};
use crate::error::ApiError;
use crate::tokens::Role;
use crate::witness::record_run_id;

/// The largest add-checkpoint body: a checkpoint, its signatures and a
/// proof of at most 63 hashes fit easily.
const BODY_LIMIT: u64 = 64 * 1024;

/// `POST /add-checkpoint`, `POST /v1/witness`.
pub async fn add_checkpoint(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, &[Role::WitnessClient])?;
    let Some(witness) = app.witness.clone() else {
        return Err(ApiError::not_found());
    };
    let origin = p
        .scopes
        .first()
        .cloned()
        .ok_or_else(|| ApiError::forbidden("this token is not bound to an origin"))?;
    let body = read_body(&app, &headers, body, BODY_LIMIT).await?;
    let result = blocking(move || {
        Ok(witness.add_checkpoint(&app.store, app.hooks.anchoring.as_ref(), &origin, &body))
    })
    .await?;
    let (status, content_type, text) = match result {
        Ok(line) => (StatusCode::OK, "text/plain; charset=utf-8", line),
        Err(e) => (
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
            e.content_type,
            e.body,
        ),
    };
    let mut resp = (status, text).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(resp)
}

/// `GET /v1/witness/log/{origin}?after=`: admins, and auditors whose
/// scopes cover the origin's record (`pragmatic:witness:<origin>`).
///
/// The answer is `{origin, origin_line, witness, cosigned, next}`. An
/// auditor turns the pages into the `--witness-log` file of design 5.3,
/// `{"witness": witness, "origin": origin_line, "checkpoints": [every
/// cosigned[].checkpoint, in order]}`: each checkpoint is the signed note
/// with this witness's cosignature line.
pub async fn log(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    origin: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let origin = origin
        .map(|Path(o)| o)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))?;
    let p = c.principal.clone();
    need(&p, &[Role::Admin, Role::Auditor])?;
    if !p.in_scope(&record_run_id(&origin)) {
        return Err(ApiError::not_found());
    }
    let mut after = None;
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "after" => after = Some(query_u64("after", &v)?),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    let Some(witness) = app.witness.clone() else {
        return Err(ApiError::not_found());
    };
    let page = blocking(move || witness.log(&app.store, &origin, after)).await?;
    Ok(ok(page))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeBody {
    /// The latest checkpoint this witness cosigned for the origin: the
    /// signed note with this witness's cosignature line.
    checkpoint: String,
    #[serde(default)]
    reason: String,
}

/// `POST /v1/witness/resume/{origin}` (admin): resume a held witness record
/// from the latest checkpoint the witness cosigned for the origin, taken
/// from outside this host (design 4.8, 4.13). Logged durably before it
/// acts.
pub async fn resume(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    origin: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let origin = origin
        .map(|Path(o)| o)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))?;
    let p = c.principal.clone();
    need(&p, &[Role::Admin])?;
    let Some(witness) = app.witness.clone() else {
        return Err(ApiError::not_found());
    };
    let req: ResumeBody = parse_json(&read_body(&app, &headers, body, JSON_LIMIT).await?)?;
    if req.reason.len() > 4096 {
        return Err(ApiError::bad_request("reason: at most 4096 bytes"));
    }
    let record = record_run_id(&origin);
    durable_intent(
        &app,
        intent(
            "witness_resume",
            &p,
            Some(&record),
            json!({"reason": req.reason}),
        ),
    )
    .await?;
    let out = blocking(move || {
        let anchored = super::runs::independent_leaves(&app, &record);
        witness.resume(&app.store, &anchored, &origin, &req.checkpoint)
    })
    .await?;
    Ok(ok(out))
}
