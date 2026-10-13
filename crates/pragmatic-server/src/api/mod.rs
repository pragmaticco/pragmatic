//! The HTTP API v1 (design 4.4), the console routes and the health
//! endpoints.
//!
//! Every request to `/v1`, to the console and to `/add-checkpoint` passes
//! through [`middleware::access`] first, which authenticates it, refuses it
//! when the access log has failed or the index is not ready, and writes
//! its access-log record when it is done (whatever the outcome, 401s, 403s
//! and 404s included). Handlers then check role and scope:
//!
//! - a role that may never make a request gets 403 `forbidden`;
//! - a run outside the token's scopes is 404 `not_found`, the same answer
//!   as a run that does not exist, so scopes reveal nothing; only `PUT`
//!   answers 403 for an out-of-scope id, because there is nothing to hide
//!   about a run that would be created.
//!
//! `/healthz`, `/readyz` and `/metrics` need no token and are not logged.

pub mod admin;
pub mod anchors;
pub mod console;
pub mod info;
pub mod middleware;
pub mod runs;
pub mod stream;
pub mod witness;

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value as JsonValue};

use crate::error::ApiError;
use crate::server::App;
use crate::tokens::{Principal, Role};

/// The shared state of every handler.
pub type AppState = Arc<App>;

/// The largest JSON request body (every JSON endpoint takes a small
/// document).
pub const JSON_LIMIT: u64 = 1 << 20;

/// The authenticated caller, placed in the request's extensions by the
/// middleware.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: Principal,
}

/// What a handler adds to its request's access-log record.
#[derive(Debug, Clone, Default)]
pub struct AccessNote {
    /// Raw content (journal bytes or unredacted slots) was served.
    pub raw: bool,
    pub cursor_from: Option<u64>,
    pub cursor_to: Option<u64>,
    pub extra: Map<String, JsonValue>,
    /// For console sign-in and sign-out: who.
    pub principal: Option<Principal>,
}

/// The error code of a refused request, for the access log.
#[derive(Debug, Clone)]
pub struct ErrorNote {
    pub code: &'static str,
    pub reason: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = json_response(status, &self.body());
        if let Some(secs) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp.extensions_mut().insert(ErrorNote {
            code: self.code,
            reason: self
                .extra
                .get("reason")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
        });
        resp
    }
}

/// A JSON response.
pub fn json_response(status: StatusCode, value: &JsonValue) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// A 200 JSON response.
pub fn ok(value: JsonValue) -> Response {
    json_response(StatusCode::OK, &value)
}

/// Attach an access note to a response.
pub fn noted(mut resp: Response, note: AccessNote) -> Response {
    resp.extensions_mut().insert(note);
    resp
}

/// Refuse a caller whose role may not make this request.
pub fn need(p: &Principal, roles: &[Role]) -> Result<(), ApiError> {
    if p.is(roles) {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!(
            "the {} role may not make this request",
            p.role.as_str()
        )))
    }
}

/// Every role that reads runs.
pub const READERS: &[Role] = &[Role::Agent, Role::Auditor, Role::Admin];

/// A run outside the caller's scopes does not exist for them.
pub fn in_scope(p: &Principal, run_id: &str) -> Result<(), ApiError> {
    if p.in_scope(run_id) {
        Ok(())
    } else {
        Err(ApiError::not_found())
    }
}

/// Run blocking store work off the async threads.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::storage_unavailable(format!("internal task failed: {e}")))?
}

/// Read a request body of at most `limit` bytes (413 beyond).
pub async fn read_body(headers: &HeaderMap, body: Body, limit: u64) -> Result<Bytes, ApiError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit) {
        return Err(ApiError::payload_too_large(limit));
    }
    match Limited::new(body, limit as usize).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            Err(ApiError::payload_too_large(limit))
        }
        Err(e) => Err(ApiError::bad_request(format!(
            "could not read the request body: {e}"
        ))),
    }
}

/// Parse a strict JSON request body (design 3.7: no duplicate keys,
/// nesting of at most 64) into `T`, which refuses unknown keys.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ApiError::bad_request("the request body is not UTF-8"))?;
    pragmatic::json::parse(text)
        .map_err(|e| ApiError::bad_request(format!("the request body is not strict JSON: {e}")))?;
    serde_json::from_str(text).map_err(|e| ApiError::bad_request(format!("request body: {e}")))
}

/// Query parameters in order.
pub fn query_pairs(raw: Option<&str>) -> Vec<(String, String)> {
    raw.map(|q| {
        form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    })
    .unwrap_or_default()
}

/// Parse an unsigned query value.
pub fn query_u64(name: &str, v: &str) -> Result<u64, ApiError> {
    v.parse()
        .map_err(|_| ApiError::bad_request(format!("{name} must be a non-negative integer")))
}

/// A required header as text.
pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The routes.
pub fn router(app: AppState) -> Router {
    let logged: Router<AppState> = Router::new()
        .route("/v1/info", get(info::info))
        .route("/v1/whoami", get(info::whoami))
        .route("/v1/keys", get(info::keys))
        .route("/v1/runs", get(runs::list))
        .route("/v1/runs/{id}", get(runs::get_run).put(runs::create))
        .route("/v1/runs/{id}/entries", get(runs::entries))
        .route("/v1/runs/{id}/entries/{cursor}/slots/{k}", get(runs::slot))
        .route("/v1/runs/{id}/journal", get(runs::journal))
        .route(
            "/v1/runs/{id}/lease",
            post(runs::lease).delete(runs::release),
        )
        .route("/v1/runs/{id}/frames", post(runs::frames))
        .route("/v1/runs/{id}/evidence", get(runs::evidence))
        .route("/v1/runs/{id}/erase", post(runs::erase))
        .route(
            "/v1/runs/{id}/accept-regression",
            post(runs::accept_regression),
        )
        .route("/v1/holds", post(admin::add_hold).get(admin::list_holds))
        .route("/v1/holds/{id}", delete(admin::remove_hold))
        .route("/v1/subjects/search", post(admin::subjects))
        .route("/v1/retention/run", post(admin::retention))
        .route("/v1/verify-data", post(admin::verify_data))
        .route("/v1/anchors", get(anchors::list))
        .route("/v1/anchors/log", get(anchors::log))
        .route("/v1/anchors/{seq}", get(anchors::one))
        .route("/v1/audit", get(admin::audit))
        .route(
            "/v1/tokens",
            post(admin::issue_token).get(admin::list_tokens),
        )
        .route("/v1/tokens/{id}", delete(admin::revoke_token))
        .route("/v1/witness", post(witness::add_checkpoint))
        .route("/add-checkpoint", post(witness::add_checkpoint))
        .route("/v1/witness/log/{origin}", get(witness::log))
        .route("/console", get(console::runs))
        .route(
            "/console/sign-in",
            get(console::sign_in_page).post(console::sign_in),
        )
        .route("/console/sign-out", post(console::sign_out))
        .route("/console/runs/{id}", get(console::run))
        .route("/console/runs/{id}/evidence", get(console::evidence))
        .route("/console/access", get(console::access))
        .route("/console/holds", get(console::holds))
        .route("/console/tokens", get(console::tokens))
        .route_layer(axum::middleware::from_fn_with_state(
            app.clone(),
            middleware::access,
        ));
    let open: Router<AppState> = Router::new()
        .route("/healthz", get(info::healthz))
        .route("/readyz", get(info::readyz))
        .route("/metrics", get(info::metrics));
    logged
        .merge(open)
        .fallback(middleware::fallback)
        .layer(DefaultBodyLimit::disable())
        .with_state(app)
}
