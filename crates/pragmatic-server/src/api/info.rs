//! `/v1/info`, `/v1/whoami`, `/v1/keys` and the unauthenticated health
//! and metrics endpoints.

use axum::extract::{Extension, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::{json_response, need, ok, AppState, Caller};
use crate::error::ApiError;
use crate::tokens::Role;

const ANY: &[Role] = &[Role::Agent, Role::Auditor, Role::Admin, Role::WitnessClient];

/// `GET /v1/info`.
pub async fn info(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    need(&c.principal, ANY)?;
    Ok(ok(crate::server::info(&app)))
}

/// `GET /v1/whoami`.
pub async fn whoami(Extension(c): Extension<Caller>) -> Result<Response, ApiError> {
    let p = &c.principal;
    need(p, ANY)?;
    Ok(ok(json!({
        "token_id": p.token_id,
        "name": p.name,
        "principal": p.principal,
        "role": p.role.as_str(),
        "scopes": p.scopes,
    })))
}

/// `GET /v1/keys`: every server signing key and its validity window.
pub async fn keys(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
) -> Result<Response, ApiError> {
    need(&c.principal, ANY)?;
    Ok(ok(json!({ "keys": app.key_ring })))
}

/// `GET /healthz`: the process is up.
pub async fn healthz() -> Response {
    json_response(StatusCode::OK, &json!({"status": "ok"}))
}

/// `GET /readyz`: the index is built.
pub async fn readyz(State(app): State<AppState>) -> Response {
    if app.is_ready() {
        json_response(StatusCode::OK, &json!({"status": "ready"}))
    } else {
        ApiError::starting().into_response()
    }
}

/// `GET /metrics`: no run ids, no label values.
pub async fn metrics(State(app): State<AppState>) -> Response {
    let body = app.metrics.render(app.gauges());
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    resp
}
