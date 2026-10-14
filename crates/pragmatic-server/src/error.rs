//! API errors (design 4.4): `{"error": {"code", "message", ...}}` with the
//! status and client action the design assigns to each code.
//!
//! | code | status | client action |
//! |---|---|---|
//! | `unauthorized`, `forbidden` | 401, 403 | fail the session; never retry |
//! | `not_found` | 404 | on lease during create: PUT; otherwise fail |
//! | `run_exists` | 409 | POST lease |
//! | `run_locked` | 409 | raise `Locked(retry_after)` |
//! | `lease_lost`, `lease_expired` | 409 | fail the session; raise `Locked` |
//! | `conflict` | 409 | reconcile through the duplicate rule, otherwise fail |
//! | `regressed` | 409 | fail; an admin must act |
//! | `chain_broken` | 409 | fail; an admin must act |
//! | `on_hold`, `retention_locked` | 409 | erasure refused (admin) |
//! | `run_deleted` | 410 | raise `Deleted`; never recreate |
//! | `invalid_frames` | 422 | fail; never retry |
//! | `payload_too_large` | 413 | fail; raise `TooLarge` |
//! | `starting`, `storage_unavailable` | 503 + `Retry-After` | resend the identical request until the lease deadline |
//! | `bad_request` | 400 | fail |
//! | `not_implemented` | 501 | fail (a component is not integrated in this build) |

use std::fmt;
use std::io;

use serde_json::{Map, Value as JsonValue};

/// One API error.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    /// Extra members of the error object.
    pub extra: Map<String, JsonValue>,
    /// Seconds for the `Retry-After` header.
    pub retry_after: Option<u64>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// Seconds a client should wait before resending after a 503.
pub const RETRY_SECS: u64 = 1;

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            code,
            message: message.into(),
            extra: Map::new(),
            retry_after: None,
        }
    }

    /// Add a member to the error object.
    pub fn with(mut self, key: &str, value: impl Into<JsonValue>) -> ApiError {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    pub fn retry(mut self, secs: u64) -> ApiError {
        self.retry_after = Some(secs);
        self
    }

    /// The JSON body.
    pub fn body(&self) -> JsonValue {
        let mut inner = self.extra.clone();
        inner.insert("code".into(), self.code.into());
        inner.insert("message".into(), self.message.clone().into());
        serde_json::json!({ "error": inner })
    }

    pub fn unauthorized(message: impl Into<String>) -> ApiError {
        ApiError::new(401, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> ApiError {
        ApiError::new(403, "forbidden", message)
    }

    /// The same body for a run that does not exist and a run outside the
    /// caller's scopes, so the two cannot be told apart.
    pub fn not_found() -> ApiError {
        ApiError::new(404, "not_found", "not found")
    }

    pub fn run_exists() -> ApiError {
        ApiError::new(
            409,
            "run_exists",
            "the run already exists; acquire its lease instead",
        )
    }

    pub fn run_locked(retry_after: u64, holder_expires_in: u64) -> ApiError {
        ApiError::new(409, "run_locked", "another holder has the run's lease")
            .with("holder_expires_in", holder_expires_in)
            .retry(retry_after)
    }

    pub fn lease_lost() -> ApiError {
        ApiError::new(409, "lease_lost", "this lease was released or revoked")
    }

    pub fn lease_expired() -> ApiError {
        ApiError::new(
            409,
            "lease_expired",
            "this lease expired and the run was taken over",
        )
    }

    pub fn conflict(expected: u64, actual: u64, head: &str) -> ApiError {
        ApiError::new(
            409,
            "conflict",
            format!("the run has {expected} entries; frames were sent for cursor {actual}"),
        )
        .with("expected", expected)
        .with("actual", actual)
        .with("entries", expected)
        .with("head", head)
    }

    pub fn regressed() -> ApiError {
        ApiError::new(
            409,
            "regressed",
            "the run has fewer entries than were anchored; an admin must run accept-regression",
        )
    }

    pub fn chain_broken(reason: &str) -> ApiError {
        ApiError::new(
            409,
            "chain_broken",
            format!("the stored journal is damaged ({reason}); an admin must act"),
        )
    }

    pub fn on_hold(holds: Vec<String>) -> ApiError {
        ApiError::new(409, "on_hold", "the run is under a legal hold").with("holds", holds)
    }

    pub fn retention_locked(retain_until: &str) -> ApiError {
        ApiError::new(
            409,
            "retention_locked",
            "erasure is refused while the retention minimum applies",
        )
        .with("retain_until", retain_until)
        .with("reason", "legal_obligation")
    }

    pub fn run_deleted() -> ApiError {
        ApiError::new(
            410,
            "run_deleted",
            "the run was deleted and cannot be recreated",
        )
    }

    pub fn invalid_frames(message: impl Into<String>) -> ApiError {
        ApiError::new(422, "invalid_frames", message)
    }

    pub fn payload_too_large(limit: u64) -> ApiError {
        ApiError::new(413, "payload_too_large", "the request body is too large")
            .with("limit", limit)
    }

    pub fn starting() -> ApiError {
        ApiError::new(503, "starting", "the server is building its index").retry(RETRY_SECS)
    }

    pub fn storage_unavailable(message: impl Into<String>) -> ApiError {
        ApiError::new(503, "storage_unavailable", message).retry(RETRY_SECS)
    }

    pub fn bad_request(message: impl Into<String>) -> ApiError {
        ApiError::new(400, "bad_request", message)
    }

    pub fn not_implemented(message: impl Into<String>) -> ApiError {
        ApiError::new(501, "not_implemented", message)
    }
}

impl From<io::Error> for ApiError {
    fn from(e: io::Error) -> ApiError {
        ApiError::storage_unavailable(format!("storage error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_have_the_design_shape() {
        let e = ApiError::run_locked(7, 6);
        assert_eq!(e.status, 409);
        assert_eq!(e.retry_after, Some(7));
        let b = e.body();
        assert_eq!(b["error"]["code"], "run_locked");
        assert_eq!(b["error"]["holder_expires_in"], 6);
        assert!(b["error"]["message"].is_string());
        assert_eq!(ApiError::not_found().body(), ApiError::not_found().body());
        assert_eq!(ApiError::starting().status, 503);
        assert_eq!(ApiError::run_deleted().status, 410);
        assert_eq!(ApiError::payload_too_large(5).status, 413);
        assert_eq!(ApiError::invalid_frames("x").status, 422);
    }
}
