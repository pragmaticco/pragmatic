//! Authentication and the access log, for every logged request (design
//! 4.3 and 4.11).
//!
//! Order of work for one request:
//!
//! 1. authenticate: a bearer token for `/v1` and `/add-checkpoint`, the
//!    session cookie for the console (its sign-in page needs none);
//! 2. a failed credential is answered 401 (the console redirects to sign
//!    in) and logged with the first 8 hex digits of the credential's
//!    SHA-256, never the credential;
//! 3. if the access log has failed, every authenticated request gets 503
//!    `storage_unavailable`: a server that cannot record who read what
//!    serves nothing;
//! 4. run endpoints answer 503 `starting` until the index is built;
//! 5. the handler runs;
//! 6. the record is queued: token id, role, method, route template, run
//!    id, status, whether raw content was served, cursors, query parameter
//!    names (never values), and, in the payload slot, principal, source
//!    address and user agent.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;
use serde_json::{json, Value as JsonValue};

use super::{AccessNote, AppState, Caller, ErrorNote};
use crate::access_log::AccessRecord;
use crate::console::cookie_value;
use crate::error::ApiError;
use crate::server::App;
use crate::timefmt;
use crate::tokens::Principal;

/// The longest user agent kept.
const MAX_USER_AGENT: usize = 256;

/// What the middleware knows about a request before the handler runs.
struct Context {
    method: String,
    route: String,
    run_id: Option<String>,
    query: Vec<String>,
    source_ip: String,
    user_agent: String,
}

impl Context {
    fn of(app: &App, req: &Request, route: String) -> Context {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        let query = req
            .uri()
            .query()
            .map(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .map(|(k, _)| k.chars().take(64).collect::<String>())
                    .collect()
            })
            .unwrap_or_default();
        Context {
            method: req.method().as_str().to_string(),
            run_id: run_id_from_path(&route, req.uri().path()),
            route,
            query,
            source_ip: source_ip(app, req.headers(), peer),
            user_agent: req
                .headers()
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.chars().take(MAX_USER_AGENT).collect())
                .unwrap_or_default(),
        }
    }
}

/// The client address: the last entry of the trusted proxy's header (the
/// one the proxy itself added), or the connection's peer.
fn source_ip(app: &App, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let name = &app.config.trusted_proxy_header;
    if !name.is_empty() {
        if let Some(v) = headers.get(name.as_str()).and_then(|v| v.to_str().ok()) {
            if let Some(last) = v
                .rsplit(',')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return last.chars().take(64).collect();
            }
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_default()
}

/// The run id in a run route's path, percent-decoded.
fn run_id_from_path(route: &str, path: &str) -> Option<String> {
    let prefix = if route.starts_with("/v1/runs/{id}") {
        "/v1/runs/"
    } else if route.starts_with("/console/runs/{id}") {
        "/console/runs/"
    } else {
        return None;
    };
    let rest = path.strip_prefix(prefix)?;
    let segment = rest.split('/').next()?;
    percent_decode_str(segment)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// True for endpoints that read or change runs: they wait for the index.
fn needs_index(route: &str) -> bool {
    [
        "/v1/runs",
        "/v1/holds",
        "/v1/subjects",
        "/v1/retention",
        "/v1/verify-data",
        "/v1/anchors",
        "/v1/witness",
        "/add-checkpoint",
        "/console",
    ]
    .iter()
    .any(|p| route.starts_with(p))
        && route != "/console/sign-in"
        && route != "/console/sign-out"
}

enum Auth {
    Ok(Principal),
    /// No credential needed (the console's sign-in and sign-out).
    Anonymous,
    Failed {
        fingerprint: Option<String>,
        reason: &'static str,
    },
}

fn bearer_auth(app: &App, headers: &HeaderMap) -> Auth {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Auth::Failed {
            fingerprint: None,
            reason: "missing bearer token",
        };
    };
    let text = value.to_str().unwrap_or("");
    let Some(token) = text.strip_prefix("Bearer ").map(str::trim) else {
        return Auth::Failed {
            fingerprint: Some(fingerprint(value.as_bytes())),
            reason: "expected Authorization: Bearer <token>",
        };
    };
    match app.tokens.authenticate(token, timefmt::now_unix_secs()) {
        Ok(p) => Auth::Ok(p),
        Err(f) => Auth::Failed {
            fingerprint: Some(f.fingerprint),
            reason: f.reason,
        },
    }
}

fn console_auth(app: &App, headers: &HeaderMap, route: &str) -> Auth {
    if route == "/console/sign-in" || route == "/console/sign-out" {
        return Auth::Anonymous;
    }
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(cookie_value);
    let Some(value) = cookie else {
        return Auth::Failed {
            fingerprint: None,
            reason: "not signed in",
        };
    };
    let principal = app
        .sessions
        .get(value)
        .and_then(|id| app.tokens.principal_by_id(&id, timefmt::now_unix_secs()));
    match principal {
        Some(p) => Auth::Ok(p),
        None => Auth::Failed {
            fingerprint: Some(fingerprint(value.as_bytes())),
            reason: "the session expired or its token was revoked",
        },
    }
}

/// The first 8 hex digits of a credential's SHA-256.
fn fingerprint(credential: &[u8]) -> String {
    pragmatic::encoding::hex_encode(&pragmatic::sha256::sha256(credential)[..4])
}

/// Where the console sends a visitor who is not signed in.
fn to_sign_in() -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_static("/console/sign-in"),
    );
    resp
}

/// The middleware (see the module documentation).
pub async fn access(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unknown>".into());
    let cx = Context::of(&app, &req, route);
    let console = cx.route.starts_with("/console");
    let auth = if console {
        console_auth(&app, req.headers(), &cx.route)
    } else {
        bearer_auth(&app, req.headers())
    };
    let (resp, principal, fp) = match auth {
        Auth::Failed {
            fingerprint,
            reason,
        } => {
            if fingerprint.is_some() {
                app.metrics.token_rejected();
            }
            let resp = if console {
                to_sign_in()
            } else {
                ApiError::unauthorized(reason).into_response()
            };
            (resp, None, fingerprint)
        }
        Auth::Anonymous | Auth::Ok(_) if app.access.is_failed() => {
            let why = app.access.failure().unwrap_or_default();
            return ApiError::storage_unavailable(format!(
                "the access log cannot be written ({why}); requests are refused until it can"
            ))
            .into_response();
        }
        Auth::Anonymous => (next.run(req).await, None, None),
        Auth::Ok(p) => {
            if needs_index(&cx.route) && !app.is_ready() {
                (ApiError::starting().into_response(), Some(p), None)
            } else {
                req.extensions_mut().insert(Caller {
                    principal: p.clone(),
                });
                (next.run(req).await, Some(p), None)
            }
        }
    };
    app.access
        .submit(record(&cx, principal.as_ref(), fp, &resp));
    resp
}

/// The access-log record of a finished request.
fn record(
    cx: &Context,
    principal: Option<&Principal>,
    fp: Option<String>,
    resp: &Response,
) -> AccessRecord {
    let note = resp
        .extensions()
        .get::<AccessNote>()
        .cloned()
        .unwrap_or_default();
    let who = note.principal.as_ref().or(principal);
    let error = resp.extensions().get::<ErrorNote>();
    let mut data = json!({
        "token_id": who.map(|p| p.token_id.clone()),
        "token_fp": fp,
        "role": who.map(|p| p.role.as_str()),
        "method": cx.method,
        "route": cx.route,
        "run_id": cx.run_id,
        "status": resp.status().as_u16(),
        "raw": note.raw,
        "cursor_from": note.cursor_from,
        "cursor_to": note.cursor_to,
        "query": cx.query,
    });
    if let Some(e) = error {
        data["error"] = e.code.into();
        if let Some(r) = &e.reason {
            data["reason"] = r.clone().into();
        }
    }
    for (k, v) in note.extra {
        data[k] = v;
    }
    let mut rec = AccessRecord::new("request", data);
    rec.personal.insert(
        "principal".into(),
        who.map_or(JsonValue::Null, |p| p.principal.clone().into()),
    );
    rec.personal
        .insert("source_ip".into(), cx.source_ip.clone().into());
    rec.personal
        .insert("user_agent".into(), cx.user_agent.clone().into());
    rec
}

/// An intent record (written and made durable before acting).
pub fn intent(action: &str, p: &Principal, run_id: Option<&str>, extra: JsonValue) -> AccessRecord {
    let mut data = json!({
        "action": action,
        "token_id": p.token_id,
        "role": p.role.as_str(),
        "run_id": run_id,
    });
    if let JsonValue::Object(m) = extra {
        for (k, v) in m {
            data[k] = v;
        }
    }
    let mut rec = AccessRecord::new("intent", data);
    rec.personal
        .insert("principal".into(), p.principal.clone().into());
    rec
}

/// Make an intent record durable, or refuse the request.
pub async fn durable_intent(app: &App, rec: AccessRecord) -> Result<u64, ApiError> {
    app.access
        .durable(rec)
        .await
        .map_err(|e| ApiError::storage_unavailable(format!("access log: {}", e.0)))
}

/// Requests no route matches. `/v1`, console and witness paths are
/// authenticated and logged like any other request.
pub async fn fallback(State(app): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let logged =
        path.starts_with("/v1") || path.starts_with("/console") || path == "/add-checkpoint";
    if !logged {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let cx = Context::of(&app, &req, "<unknown>".into());
    let (resp, principal, fp) = match bearer_auth(&app, req.headers()) {
        Auth::Ok(p) => {
            if app.access.is_failed() {
                return ApiError::storage_unavailable("the access log cannot be written")
                    .into_response();
            }
            (ApiError::not_found().into_response(), Some(p), None)
        }
        Auth::Failed {
            fingerprint,
            reason,
        } => {
            if fingerprint.is_some() {
                app.metrics.token_rejected();
            }
            (
                ApiError::unauthorized(reason).into_response(),
                None,
                fingerprint,
            )
        }
        Auth::Anonymous => (ApiError::not_found().into_response(), None, None),
    };
    app.access
        .submit(record(&cx, principal.as_ref(), fp, &resp));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_come_from_run_routes_only() {
        assert_eq!(
            run_id_from_path("/v1/runs/{id}/frames", "/v1/runs/a%3Ab/frames").as_deref(),
            Some("a:b")
        );
        assert_eq!(
            run_id_from_path("/v1/tokens/{id}", "/v1/tokens/tok_1"),
            None
        );
        assert_eq!(
            run_id_from_path("/console/runs/{id}", "/console/runs/r1").as_deref(),
            Some("r1")
        );
    }

    #[test]
    fn index_gating() {
        assert!(needs_index("/v1/runs/{id}/frames"));
        assert!(needs_index("/console"));
        assert!(!needs_index("/console/sign-in"));
        assert!(!needs_index("/v1/info"));
        assert!(!needs_index("/v1/tokens"));
    }
}
