//! Console sessions (design 4.3).
//!
//! Signing in to the console exchanges a token for a session cookie:
//! `HttpOnly` (scripts cannot read it), `SameSite=Strict` (other sites
//! cannot make the browser send it, which is what protects the console's
//! POST forms), and `Secure` when the server is reached over HTTPS. A
//! session ends after 15 minutes without a request or 12 hours after sign
//! in, whichever comes first, and every request re-checks the token behind
//! it, so revoking a token ends its sessions at once.
//!
//! Only the SHA-256 of a session id is kept, in memory: a restart signs
//! everyone out.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pragmatic::encoding::hex_encode;
use pragmatic::sha256::sha256;

/// Idle timeout.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// Absolute limit.
pub const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
/// The cookie's name.
pub const COOKIE: &str = "pragmatic_session";

struct Session {
    token_id: String,
    created: Instant,
    last_seen: Instant,
}

impl Session {
    fn live(&self, now: Instant) -> bool {
        now.duration_since(self.last_seen) < IDLE && now.duration_since(self.created) < ABSOLUTE
    }
}

/// Every live session.
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Session>>,
}

fn key(value: &str) -> String {
    hex_encode(&sha256(value.as_bytes()))
}

impl Sessions {
    /// Start a session for a token. Returns the cookie value.
    pub fn create(&self, token_id: &str) -> std::io::Result<String> {
        let mut b = [0u8; 32];
        pragmatic::rand::fill(&mut b)?;
        let value = hex_encode(&b);
        let now = Instant::now();
        self.map.lock().expect("sessions").insert(
            key(&value),
            Session {
                token_id: token_id.to_string(),
                created: now,
                last_seen: now,
            },
        );
        Ok(value)
    }

    /// The token id behind a live session, refreshing its idle timer.
    pub fn get(&self, value: &str) -> Option<String> {
        let now = Instant::now();
        let mut map = self.map.lock().expect("sessions");
        let k = key(value);
        let live = map.get(&k).is_some_and(|s| s.live(now));
        if !live {
            map.remove(&k);
            return None;
        }
        let s = map.get_mut(&k)?;
        s.last_seen = now;
        Some(s.token_id.clone())
    }

    /// End a session. Returns its token id.
    pub fn remove(&self, value: &str) -> Option<String> {
        self.map
            .lock()
            .expect("sessions")
            .remove(&key(value))
            .map(|s| s.token_id)
    }

    /// Drop expired sessions.
    pub fn expire(&self) {
        let now = Instant::now();
        self.map
            .lock()
            .expect("sessions")
            .retain(|_, s| s.live(now));
    }

    /// TEST ONLY: age every session by `by`.
    #[cfg(any(test, feature = "testing"))]
    pub fn age(&self, by: Duration) {
        for s in self.map.lock().expect("sessions").values_mut() {
            s.last_seen = s.last_seen.checked_sub(by).unwrap_or(s.last_seen);
            s.created = s.created.checked_sub(by).unwrap_or(s.created);
        }
    }
}

/// The `Set-Cookie` value that starts a session.
pub fn set_cookie(value: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={value}; Path=/console; HttpOnly; SameSite=Strict; Max-Age={}{}",
        ABSOLUTE.as_secs(),
        if secure { "; Secure" } else { "" }
    )
}

/// The `Set-Cookie` value that ends a session.
pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{COOKIE}=; Path=/console; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The session cookie's value in a `Cookie` header.
pub fn cookie_value(header: &str) -> Option<&str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_when_idle_or_old() {
        let s = Sessions::default();
        let v = s.create("tok_1").unwrap();
        assert_eq!(s.get(&v).as_deref(), Some("tok_1"));
        s.age(IDLE + Duration::from_secs(1));
        assert_eq!(s.get(&v), None);
        let v = s.create("tok_2").unwrap();
        assert_eq!(s.remove(&v).as_deref(), Some("tok_2"));
        assert_eq!(s.get(&v), None);
    }

    #[test]
    fn cookies_are_strict_and_http_only() {
        let c = set_cookie("abc", true);
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.ends_with("Secure"));
        assert!(!set_cookie("abc", false).contains("Secure"));
        assert_eq!(cookie_value("a=b; pragmatic_session=xyz; c=d"), Some("xyz"));
        assert_eq!(cookie_value("pragmatic_session="), None);
        assert_eq!(cookie_value("other=1"), None);
    }
}
