//! Witness mode endpoints (design 4.8): `POST /add-checkpoint` (also at
//! `POST /v1/witness`) and `GET /v1/witness/log/{origin}`.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::{blocking, need, ok, query_pairs, query_u64, read_body, AppState, Caller};
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
    let result = blocking(move || Ok(witness.add_checkpoint(&app.store, &origin, &body))).await?;
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
    let o = origin.clone();
    let (records, next) = blocking(move || witness.log(&app.store, &o, after)).await?;
    Ok(ok(
        json!({ "origin": origin, "cosigned": records, "next": next }),
    ))
}
