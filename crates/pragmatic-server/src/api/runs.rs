//! Run endpoints (design 4.4 to 4.6 and 4.9).

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pragmatic::journal::{self, validate_run_id};
use pragmatic::Journal;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};

use super::middleware::{durable_intent, intent};
use super::{
    blocking, header_str, in_scope, json_response, need, noted, ok, parse_json, query_pairs,
    query_u64, read_body, AccessNote, AppState, Caller, JSON_LIMIT, READERS,
};
use crate::error::ApiError;
use crate::hooks::{BatchReason, EvidenceError, EvidenceRequest};
use crate::ledger::LedgerKind;
use crate::store::{AppendRequest, EraseContext, EraseParams, ListQuery, Selector};
use crate::timefmt;
use crate::tokens::{Principal, Role};
use crate::views::{self, ViewOptions, LIST_SLOT_LIMIT};

/// The most entries one page returns.
const MAX_PAGE: u64 = 1000;

fn path<T>(p: Result<Path<T>, PathRejection>) -> Result<T, ApiError> {
    p.map(|Path(v)| v)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))
}

/// A run id that clients may write: refuse malformed and reserved ids.
fn writable_id(id: &str) -> Result<(), ApiError> {
    validate_run_id(id).map_err(|f| ApiError::bad_request(f.to_string()))
}

/// `GET /v1/runs`.
pub async fn list(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    need(&c.principal, READERS)?;
    let mut q = ListQuery {
        limit: 100,
        ..ListQuery::default()
    };
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "prefix" => q.prefix = Some(v),
            "q" => q.q = Some(v),
            "program" => q.program = Some(v),
            "status" => q.status = Some(v),
            "after" => q.after = Some(v),
            "since" | "until" => {
                let t = timefmt::parse_rfc3339(&v)
                    .ok_or_else(|| ApiError::bad_request(format!("{k} must be RFC 3339")))?;
                if k == "since" {
                    q.since = Some(t);
                } else {
                    q.until = Some(t);
                }
            }
            "limit" => q.limit = query_u64("limit", &v)?.clamp(1, MAX_PAGE) as usize,
            other => match other.strip_prefix("label.") {
                Some(label) if !label.is_empty() => q.labels.push((label.to_string(), v)),
                _ => {
                    return Err(ApiError::bad_request(format!(
                        "unknown parameter '{other}'"
                    )))
                }
            },
        }
    }
    let p = c.principal.clone();
    let page = blocking(move || Ok(app.store.list(&q, &app.holds, |id| p.in_scope(id)))).await?;
    Ok(ok(json!({ "runs": page.runs, "next": page.next })))
}

/// `GET /v1/runs/{id}`.
pub async fn get_run(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    need(&c.principal, READERS)?;
    in_scope(&c.principal, &id)?;
    let summary = blocking(move || app.store.summary(&id, &app.holds)).await?;
    Ok(ok(summary))
}

/// Make the access record of a raw read durable before serving it.
async fn raw_read(app: &AppState, p: &Principal, run_id: &str, what: &str) -> Result<(), ApiError> {
    durable_intent(
        app,
        intent("read_raw", p, Some(run_id), json!({ "what": what })),
    )
    .await?;
    Ok(())
}

/// `GET /v1/runs/{id}/entries?from=&limit=`.
pub async fn entries(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = &c.principal;
    need(p, READERS)?;
    in_scope(p, &id)?;
    let (mut from, mut limit) = (0u64, 100u64);
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "from" => from = query_u64("from", &v)?,
            "limit" => limit = query_u64("limit", &v)?.clamp(1, MAX_PAGE),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    if p.view_raw {
        raw_read(&app, p, &id, "entries").await?;
    }
    let (a, run) = (app.clone(), id.clone());
    let journal = blocking(move || a.store.snapshot(&run)).await?;
    let len = journal.len();
    let end = from.saturating_add(limit).min(len);
    let opts = ViewOptions {
        raw: p.view_raw,
        redactor: &app.redactor,
        limit: Some(LIST_SLOT_LIMIT),
    };
    let list: Vec<JsonValue> = (from.min(len)..end)
        .filter_map(|cur| journal.get(cur))
        .map(|e| views::entry_json(e, opts))
        .collect();
    let next = (end < len).then_some(end);
    let resp = ok(json!({ "entries": list, "next": next, "total": len }));
    Ok(noted(
        resp,
        AccessNote {
            raw: p.view_raw,
            cursor_from: Some(from),
            cursor_to: Some(end),
            ..AccessNote::default()
        },
    ))
}

/// `GET /v1/runs/{id}/entries/{cursor}/slots/{k}`.
pub async fn slot(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    params: Result<Path<(String, u64, u8)>, PathRejection>,
) -> Result<Response, ApiError> {
    let (id, cursor, k) = path(params)?;
    let p = &c.principal;
    need(p, READERS)?;
    in_scope(p, &id)?;
    if p.view_raw {
        raw_read(&app, p, &id, "slot").await?;
    }
    let (a, run) = (app.clone(), id.clone());
    let journal = blocking(move || a.store.snapshot(&run)).await?;
    let entry = journal.get(cursor).ok_or_else(ApiError::not_found)?;
    let meta = entry
        .slots
        .get(k as usize)
        .ok_or_else(ApiError::not_found)?;
    let content = entry.event.slot_contents()[k as usize];
    let opts = ViewOptions {
        raw: p.view_raw,
        redactor: &app.redactor,
        limit: None,
    };
    let mut body = views::slot_json(meta.state, &meta.commitment, content, opts);
    body["cursor"] = cursor.into();
    body["slot"] = k.into();
    Ok(noted(
        ok(body),
        AccessNote {
            raw: p.view_raw,
            cursor_from: Some(cursor),
            cursor_to: Some(cursor + 1),
            ..AccessNote::default()
        },
    ))
}

/// `GET /v1/runs/{id}/journal`: an agent holding the run's lease, an
/// admin, or an auditor with `view_raw`.
pub async fn journal(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, READERS)?;
    in_scope(&p, &id)?;
    match p.role {
        Role::Agent => {
            let lease = header_str(&headers, "pragmatic-lease")
                .ok_or_else(|| {
                    ApiError::forbidden("agents read a journal only while holding its lease")
                })?
                .to_string();
            let (a, run, who) = (app.clone(), id.clone(), p.clone());
            blocking(move || a.store.check_lease(&who, &run, &lease)).await?;
        }
        Role::Auditor if !p.view_raw => {
            return Err(ApiError::forbidden("journal bytes need view_raw"));
        }
        _ => {}
    }
    raw_read(&app, &p, &id, "journal").await?;
    let (a, run) = (app.clone(), id.clone());
    let durable = blocking(move || a.store.open_durable(&run)).await?;
    let (entries, head) = (durable.entries, durable.head.clone());
    let mut resp = Response::new(super::stream::file_body(durable.file, durable.byte_len));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(durable.byte_len));
    h.insert("pragmatic-entries", HeaderValue::from(entries));
    if let Ok(v) = HeaderValue::from_str(&head) {
        h.insert("pragmatic-head", v);
    }
    Ok(noted(
        resp,
        AccessNote {
            raw: true,
            cursor_from: Some(0),
            cursor_to: Some(entries),
            ..AccessNote::default()
        },
    ))
}

/// A holder id: 1 to 128 characters of `[A-Za-z0-9._:-]`.
fn check_holder(h: &str) -> Result<(), ApiError> {
    let ok = !h.is_empty()
        && h.len() <= 128
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "holder: 1 to 128 characters from A-Z, a-z, 0-9, '.', '_', ':' and '-'",
        ))
    }
}

/// `PUT /v1/runs/{id}`: body is the 16-byte journal header (flags 0).
pub async fn create(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Agent, Role::Admin])?;
    writable_id(&id)?;
    if !p.in_scope(&id) {
        return Err(ApiError::forbidden(
            "the run id is outside this token's scopes",
        ));
    }
    let bytes = read_body(&headers, body, 64).await?;
    if bytes.as_ref() != journal::header(0).as_slice() {
        return Err(ApiError::bad_request(
            "the body must be the 16-byte journal header: PRAGJRNL, version 2, flags 0",
        ));
    }
    let holder = header_str(&headers, "pragmatic-holder").map(str::to_string);
    if let Some(h) = &holder {
        check_holder(h)?;
    }
    let grant = blocking(move || app.store.create_run(&p, &id, holder.as_deref())).await?;
    Ok(json_response(
        StatusCode::CREATED,
        &json!({ "lease": grant.lease, "ttl_secs": grant.ttl_secs, "entries": grant.entries }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseBody {
    holder: String,
}

/// `POST /v1/runs/{id}/lease`.
pub async fn lease(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Agent, Role::Admin])?;
    writable_id(&id)?;
    in_scope(&p, &id)?;
    let presented = header_str(&headers, "pragmatic-lease").map(str::to_string);
    let req: LeaseBody = parse_json(&read_body(&headers, body, JSON_LIMIT).await?)?;
    check_holder(&req.holder)?;
    let grant = blocking(move || {
        app.store
            .acquire_lease(&p, &id, &req.holder, presented.as_deref())
    })
    .await?;
    Ok(ok(
        json!({ "lease": grant.lease, "ttl_secs": grant.ttl_secs, "entries": grant.entries }),
    ))
}

/// `DELETE /v1/runs/{id}/lease`.
pub async fn release(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Agent, Role::Admin])?;
    writable_id(&id)?;
    in_scope(&p, &id)?;
    let lease = header_str(&headers, "pragmatic-lease")
        .ok_or_else(|| ApiError::bad_request("Pragmatic-Lease is required"))?
        .to_string();
    blocking(move || app.store.release_lease(&p, &id, &lease)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /v1/runs/{id}/frames?at=N` (design 4.6).
pub async fn frames(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Agent, Role::Admin])?;
    writable_id(&id)?;
    in_scope(&p, &id)?;
    let mut at = None;
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "at" => at = Some(query_u64("at", &v)?),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    let at = at.ok_or_else(|| ApiError::bad_request("the at parameter is required"))?;
    let lease = header_str(&headers, "pragmatic-lease")
        .ok_or_else(|| ApiError::bad_request("Pragmatic-Lease is required"))?
        .to_string();
    let count = header_str(&headers, "pragmatic-frames")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= 1)
        .ok_or_else(|| ApiError::bad_request("Pragmatic-Frames must be a positive integer"))?;
    let head = header_str(&headers, "pragmatic-head")
        .filter(|h| crate::config::is_sha256_hex(h))
        .ok_or_else(|| ApiError::bad_request("Pragmatic-Head must be 64 lowercase hex digits"))?
        .to_string();
    let body = read_body(&headers, body, app.config.max_request_bytes).await?;
    let done = blocking(move || {
        app.store.append(
            &p,
            &id,
            AppendRequest {
                at,
                count,
                lease: &lease,
                head: &head,
                body: &body,
            },
        )
    })
    .await?;
    Ok(noted(
        ok(json!({ "entries": done.entries, "head": done.head, "duplicate": done.duplicate })),
        AccessNote {
            cursor_from: Some(done.from),
            cursor_to: Some(done.to),
            extra: [("duplicate".to_string(), done.duplicate.into())]
                .into_iter()
                .collect(),
            ..AccessNote::default()
        },
    ))
}

/// `GET /v1/runs/{id}/evidence?redact=&anchor=now`.
pub async fn evidence(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Auditor, Role::Admin])?;
    in_scope(&p, &id)?;
    let mut redact = None;
    let mut anchor_now = false;
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "redact" => redact = Some(v),
            "anchor" if v == "now" => anchor_now = true,
            "anchor" => return Err(ApiError::bad_request("anchor must be \"now\"")),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    build_evidence(app, p, id, redact, anchor_now).await
}

/// Shared by the API and the console.
pub async fn build_evidence(
    app: AppState,
    p: Principal,
    id: String,
    redact: Option<String>,
    anchor_now: bool,
) -> Result<Response, ApiError> {
    let redact = redact.unwrap_or_else(|| if p.view_raw { "none" } else { "detectors" }.into());
    if !["none", "detectors", "binary", "all"].contains(&redact.as_str()) {
        return Err(ApiError::bad_request(
            "redact must be none, detectors, binary or all",
        ));
    }
    if redact == "none" && !p.view_raw {
        return Err(ApiError::forbidden("an unredacted bundle needs view_raw"));
    }
    let a = app.clone();
    let run = id.clone();
    blocking(move || a.store.find(&run).map(|_| ())).await?;
    if anchor_now {
        let a = app.clone();
        blocking(move || {
            a.anchor_batch(BatchReason::Now)
                .map(|_| ())
                .map_err(|e| ApiError::storage_unavailable(format!("anchoring failed: {e}")))
        })
        .await?;
    }
    if redact == "none" {
        raw_read(&app, &p, &id, "evidence").await?;
    }
    let a = app.clone();
    let run = id.clone();
    let durable = blocking(move || a.store.durable(&run)).await?;
    let a = app.clone();
    let built = blocking(move || {
        let journal = Journal::parse(&durable.bytes, None)
            .map(|parsed| parsed.journal)
            .map_err(|e| ApiError::chain_broken(&e.to_string()))?;
        let generator = format!("pragmatic-server {}", env!("CARGO_PKG_VERSION"));
        let req = EvidenceRequest {
            run_id: &id,
            journal: &journal,
            journal_bytes: &durable.bytes,
            requested_by: &p.token_id,
            redact: &redact,
            redactor: &a.redactor,
            anchoring: a.hooks.anchoring.as_ref(),
            key: &a.key,
            independent: a.hooks.anchoring.independent(),
            generator: &generator,
        };
        a.hooks.evidence.build(req).map_err(|e| match e {
            EvidenceError::NotImplemented => ApiError::not_implemented(
                "evidence bundles are built by the evidence module, which is not part of this build",
            ),
            EvidenceError::BadRequest(m) => ApiError::bad_request(m),
            EvidenceError::Internal(m) => ApiError::storage_unavailable(m),
        })
    })
    .await?;
    let mut resp = Response::new(Body::from(built.body));
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&built.content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", built.file_name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseBody {
    #[serde(default)]
    slots: Option<JsonValue>,
    #[serde(default, rename = "match")]
    matching: Option<String>,
    reason_code: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    allow_unfinished: bool,
}

fn selector(body: &EraseBody) -> Result<Selector, ApiError> {
    match (&body.slots, &body.matching) {
        (Some(JsonValue::String(s)), None) if s == "all" => Ok(Selector::All),
        (Some(JsonValue::Array(pairs)), None) if !pairs.is_empty() => {
            let mut out = Vec::with_capacity(pairs.len());
            for pair in pairs {
                let parsed = pair.as_array().and_then(|p| match p.as_slice() {
                    [c, s] => Some((c.as_u64()?, u8::try_from(s.as_u64()?).ok()?)),
                    _ => None,
                });
                out.push(parsed.ok_or_else(|| {
                    ApiError::bad_request("slots: a list of [cursor, slot] pairs")
                })?);
            }
            Ok(Selector::Slots(out))
        }
        (None, Some(m)) if !m.is_empty() => Ok(Selector::Match(m.clone())),
        _ => Err(ApiError::bad_request(
            "give exactly one of slots ([[cursor, slot], ...] or \"all\") and match (non-empty text)",
        )),
    }
}

fn check_reason_code(code: &str) -> Result<(), ApiError> {
    if crate::config::is_label_key(code) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "reason_code: 1 to 64 characters from a-z, 0-9, '_', '.' and '-'",
        ))
    }
}

/// `POST /v1/runs/{id}/erase` (design 4.9).
pub async fn erase(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Admin])?;
    let body: EraseBody = parse_json(&read_body(&headers, body, JSON_LIMIT).await?)?;
    let sel = selector(&body)?;
    check_reason_code(&body.reason_code)?;
    if body.reason.len() > 4096 {
        return Err(ApiError::bad_request("reason: at most 4096 bytes"));
    }
    let params = EraseParams {
        selector: sel,
        reason_code: body.reason_code.clone(),
        reason: body.reason,
        force: body.force,
        allow_unfinished: body.allow_unfinished,
        by: p.token_id.clone(),
        kind: LedgerKind::Erasure,
    };
    let rec = intent(
        "erase",
        &p,
        Some(&id),
        json!({"reason_code": body.reason_code, "force": body.force}),
    );
    let done = blocking(move || {
        let cx = EraseContext {
            holds: &app.holds,
            policies: &app.config.retention,
            access: &app.access,
            ledger: &app.ledger,
            intent: rec,
        };
        app.store.erase(&id, &params, cx)
    })
    .await?;
    let mut out = json!({
        "erased": done.slots,
        "note_cursor": done.note_cursor,
        "entries": done.entries,
        "head": done.head,
        "access_log_cursor": done.access_log_cursor,
        "ledger_seq": done.ledger_seq,
        "can_resume": done.can_resume,
    });
    if !done.can_resume {
        out["warning"] =
            "the run's last attempt did not end ok; it can no longer be resumed".into();
    }
    Ok(ok(out))
}

/// `POST /v1/runs/{id}/accept-regression`: accept a regressed run's
/// journal as its history from here on. Logged durably first.
pub async fn accept_regression(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    id: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let id = path(id)?;
    let p = c.principal.clone();
    need(&p, &[Role::Admin])?;
    durable_intent(&app, intent("accept_regression", &p, Some(&id), json!({}))).await?;
    let run = id.clone();
    let (entries, before) = blocking(move || app.store.accept_regression(&run)).await?;
    Ok(ok(
        json!({ "run_id": id, "entries": entries, "anchored_entries_before": before }),
    ))
}
