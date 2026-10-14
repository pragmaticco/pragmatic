//! Anchor endpoints (design 4.4 and 4.7). The anchoring library supplies
//! checkpoints and leaves; this layer filters them by scope: an auditor
//! sees the leaves of runs in its scopes, and the access log's leaves. An
//! access-log leaf holds a record count and a chain head, nothing about any
//! run or person, and it is what lets an auditor check that the records
//! it reads (each served with its chain hash) belong to an anchored log
//! that was not cut back or rewritten.

use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::response::Response;
use serde_json::{json, Value as JsonValue};

use super::{blocking, need, ok, query_pairs, query_u64, AppState, Caller};
use crate::error::ApiError;
use crate::hooks::{CheckpointView, LeafView};
use crate::tokens::{Principal, Role};

const ROLES: &[Role] = &[Role::Auditor, Role::Admin];

/// The most leaves one request returns.
const MAX_LEAVES: u64 = 10_000;

/// Whether `p` may see `leaf`. Decided by the leaf's type, never by
/// whether its run is known: an access-log leaf is shown to every auditor,
/// a run leaf only in scope, and a run leaf whose run cannot be told (its
/// batch index is gone, under HMAC run ids) only to administrators, so the
/// filter never fails open.
fn visible(p: &Principal, leaf: &LeafView) -> bool {
    if leaf.access_log {
        return true;
    }
    match &leaf.run_id {
        Some(id) => p.in_scope(id),
        None => p.role == Role::Admin,
    }
}

fn leaf_json(leaf: LeafView) -> JsonValue {
    let mut body = leaf.body;
    if !body.is_object() {
        body = json!({ "leaf": body });
    }
    body["index"] = leaf.index.into();
    body
}

fn checkpoint_json(p: &Principal, cp: CheckpointView) -> JsonValue {
    let leaves: Vec<JsonValue> = cp
        .leaves
        .into_iter()
        .filter(|l| visible(p, l))
        .map(leaf_json)
        .collect();
    let mut body = cp.body;
    if !body.is_object() {
        body = json!({ "checkpoint": body });
    }
    body["seq"] = cp.seq.into();
    body["leaves"] = leaves.into();
    body
}

fn anchor_err(e: crate::hooks::AnchorError) -> ApiError {
    ApiError::storage_unavailable(format!("anchoring: {e}"))
}

/// `GET /v1/anchors?after=&limit=`.
pub async fn list(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, ROLES)?;
    let (mut after, mut limit) = (None, 100u64);
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "after" => after = Some(query_u64("after", &v)?),
            "limit" => limit = query_u64("limit", &v)?.clamp(1, 1000),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    let list = blocking(move || {
        app.hooks
            .anchoring
            .checkpoints(after, limit as usize)
            .map_err(anchor_err)
    })
    .await?;
    let next = (list.len() as u64 == limit)
        .then(|| list.last().map(|c| c.seq))
        .flatten();
    let out: Vec<JsonValue> = list.into_iter().map(|cp| checkpoint_json(&p, cp)).collect();
    Ok(ok(json!({ "checkpoints": out, "next": next })))
}

/// `GET /v1/anchors/{seq}`.
pub async fn one(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    seq: Result<Path<u64>, PathRejection>,
) -> Result<Response, ApiError> {
    let seq = seq
        .map(|Path(s)| s)
        .map_err(|e| ApiError::bad_request(format!("path: {e}")))?;
    let p = c.principal.clone();
    need(&p, ROLES)?;
    let cp = blocking(move || app.hooks.anchoring.checkpoint(seq).map_err(anchor_err))
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(ok(checkpoint_json(&p, cp)))
}

/// `GET /v1/anchors/log?from=&to=`: admins get every raw leaf; auditors
/// their in-scope leaves, each with an inclusion proof.
pub async fn log(
    State(app): State<AppState>,
    Extension(c): Extension<Caller>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let p = c.principal.clone();
    need(&p, ROLES)?;
    let (mut from, mut to) = (0u64, None);
    for (k, v) in query_pairs(raw.as_deref()) {
        match k.as_str() {
            "from" => from = query_u64("from", &v)?,
            "to" => to = Some(query_u64("to", &v)?),
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown parameter '{other}'"
                )))
            }
        }
    }
    let to = to.unwrap_or(from.saturating_add(MAX_LEAVES));
    if to < from || to - from > MAX_LEAVES {
        return Err(ApiError::bad_request(format!(
            "from..to spans at most {MAX_LEAVES} leaves"
        )));
    }
    let proofs = p.role != Role::Admin;
    let leaves = blocking(move || {
        app.hooks
            .anchoring
            .leaves(from, to, proofs)
            .map_err(anchor_err)
    })
    .await?;
    let out: Vec<JsonValue> = leaves
        .into_iter()
        .filter(|l| visible(&p, l))
        .map(leaf_json)
        .collect();
    Ok(ok(json!({ "leaves": out, "from": from, "to": to })))
}
