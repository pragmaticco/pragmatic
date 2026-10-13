//! Tokens, roles and scopes (design 4.3).
//!
//! A token is a random bearer secret. The server stores only its SHA-256,
//! so `tokens.json` (and every backup of it) cannot be used to sign in.
//! Every presented token is hashed and compared against every stored hash
//! in constant time; the comparison does not stop at the first match, so
//! response timing says nothing about which token, if any, came close.
//!
//! Three kinds of token exist:
//!
//! - the **bootstrap admin**, configured by hash in `[bootstrap]`, which
//!   issues every other token;
//! - **issued** tokens in `tokens.json`, created and revoked through
//!   `POST /v1/tokens` and `DELETE /v1/tokens/{id}` (or the `token`
//!   subcommand, which calls them);
//! - **witness clients** configured by hash in `[witness_mode] origins`,
//!   each bound to one origin.
//!
//! Every token names a `principal` (who or what uses it). Every role except
//! `admin` needs explicit `scopes`, a list of run-id prefixes; `["*"]` is
//! all runs, and must be written out. An admin token covers every run (it
//! manages tokens, holds and the whole access log, which no scope can
//! narrow), so its scopes are `["*"]`: issuing one with narrower scopes is
//! refused, and a stored admin record with narrower scopes (written by
//! hand, or by an earlier build) never authenticates. Showing scopes that
//! are not enforced would be worse than refusing them.
//!
//! Each issued token records the token id that issued it (`created_by`),
//! and the issue's access-log intent, durable before the token exists,
//! names the new token's id.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use pragmatic::encoding::{hex_decode_exact, hex_encode};
use pragmatic::sha256::sha256;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::fsutil;
use crate::timefmt;

/// What a token may do (design 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// In scope: create runs, lease, append, read a journal only while
    /// holding its lease, read summaries and entries.
    Agent,
    /// In scope: list and read (redacted unless `view_raw`), journals with
    /// `view_raw`, verify, evidence, anchors and the access log.
    Auditor,
    /// Everything, including tokens, erasure, holds, retention and the
    /// whole access log.
    Admin,
    /// Witness mode only, bound to one origin.
    WitnessClient,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Auditor => "auditor",
            Role::Admin => "admin",
            Role::WitnessClient => "witness_client",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "agent" => Some(Role::Agent),
            "auditor" => Some(Role::Auditor),
            "admin" => Some(Role::Admin),
            "witness_client" => Some(Role::WitnessClient),
            _ => None,
        }
    }
}

/// The id of the bootstrap admin token.
pub const BOOTSTRAP_ID: &str = "bootstrap";

/// The authenticated caller of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub token_id: String,
    pub name: String,
    pub principal: String,
    pub role: Role,
    pub scopes: Vec<String>,
    pub view_raw: bool,
}

impl Principal {
    /// True if the run is within this token's scopes. Admins see every run.
    pub fn in_scope(&self, run_id: &str) -> bool {
        self.role == Role::Admin || scope_matches(&self.scopes, run_id)
    }

    /// True if any of the roles may make the request.
    pub fn is(&self, roles: &[Role]) -> bool {
        roles.contains(&self.role)
    }

    /// The principal the server itself acts as (retention, startup).
    pub fn system(what: &str) -> Principal {
        Principal {
            token_id: format!("server:{what}"),
            name: format!("server {what}"),
            principal: "server".into(),
            role: Role::Admin,
            scopes: vec!["*".into()],
            view_raw: true,
        }
    }
}

/// True if a run id matches one of the scope prefixes.
pub fn scope_matches(scopes: &[String], run_id: &str) -> bool {
    scopes
        .iter()
        .any(|s| s == "*" || (!s.is_empty() && run_id.starts_with(s.as_str())))
}

/// A stored token. `sha256` is never served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    pub principal: String,
    pub role: Role,
    pub scopes: Vec<String>,
    pub view_raw: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub sha256: String,
    /// The token id that issued this token.
    #[serde(default)]
    pub created_by: Option<String>,
}

impl TokenRecord {
    /// An admin record whose scopes are not `["*"]` (see the module
    /// documentation): never accepted.
    fn narrowed_admin(&self) -> bool {
        self.role == Role::Admin && self.scopes != ["*"]
    }
}

/// The record as the API shows it: everything except the hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub principal: String,
    pub role: Role,
    pub scopes: Vec<String>,
    pub view_raw: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_by: Option<String>,
}

impl From<&TokenRecord> for TokenView {
    fn from(r: &TokenRecord) -> Self {
        TokenView {
            id: r.id.clone(),
            name: r.name.clone(),
            principal: r.principal.clone(),
            role: r.role,
            scopes: r.scopes.clone(),
            view_raw: r.view_raw,
            created_at: r.created_at.clone(),
            expires_at: r.expires_at.clone(),
            revoked_at: r.revoked_at.clone(),
            created_by: r.created_by.clone(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    tokens: Vec<TokenRecord>,
}

/// Why a presented credential was refused. `fingerprint` is the first 8
/// hex digits of its SHA-256, for the access log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure {
    pub fingerprint: String,
    pub reason: &'static str,
}

/// A request to issue a token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    pub name: String,
    pub principal: String,
    pub role: Role,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub view_raw: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Why a token could not be issued or revoked.
#[derive(Debug)]
pub enum TokenError {
    Invalid(String),
    NotFound,
    Io(io::Error),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Invalid(m) => f.write_str(m),
            TokenError::NotFound => f.write_str("no such token"),
            TokenError::Io(e) => write!(f, "tokens.json: {e}"),
        }
    }
}

/// A configured token: known by hash, never stored in `tokens.json`.
#[derive(Debug, Clone)]
struct Configured {
    sha256: [u8; 32],
    principal: Principal,
}

/// Every token the server accepts.
#[derive(Debug)]
pub struct TokenStore {
    path: PathBuf,
    issued: RwLock<Vec<TokenRecord>>,
    configured: Vec<Configured>,
    witness_origins: Vec<String>,
}

/// SHA-256 of a token value, as lowercase hex.
pub fn token_sha256(value: &str) -> String {
    hex_encode(&sha256(value.as_bytes()))
}

/// A fresh token value: `prag_` and 64 hex digits (256 random bits).
pub fn new_token_value() -> io::Result<String> {
    let mut b = [0u8; 32];
    pragmatic::rand::fill(&mut b)?;
    Ok(format!("prag_{}", hex_encode(&b)))
}

fn new_id(prefix: &str) -> io::Result<String> {
    let mut b = [0u8; 8];
    pragmatic::rand::fill(&mut b)?;
    Ok(format!("{prefix}{}", hex_encode(&b)))
}

impl TokenStore {
    /// `<data_dir>/tokens.json`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("tokens.json")
    }

    /// Load issued tokens and the configured ones.
    pub fn open(data_dir: &Path, config: &Config) -> io::Result<TokenStore> {
        let path = TokenStore::path(data_dir);
        let issued = fsutil::read_json::<TokensFile>(&path)?
            .unwrap_or_default()
            .tokens;
        let mut configured = Vec::new();
        if !config.bootstrap.admin_token_sha256.is_empty() {
            configured.push(Configured {
                sha256: hex_decode_exact(&config.bootstrap.admin_token_sha256)
                    .map_err(|_| io::Error::other("bootstrap.admin_token_sha256 is not hex"))?,
                principal: Principal {
                    token_id: BOOTSTRAP_ID.into(),
                    name: "bootstrap admin".into(),
                    principal: BOOTSTRAP_ID.into(),
                    role: Role::Admin,
                    scopes: vec!["*".into()],
                    view_raw: true,
                },
            });
        }
        let mut witness_origins = Vec::new();
        if config.witness_mode.enabled {
            for o in &config.witness_mode.origins {
                witness_origins.push(o.name.clone());
                configured.push(Configured {
                    sha256: hex_decode_exact(&o.token_sha256)
                        .map_err(|_| io::Error::other("witness token_sha256 is not hex"))?,
                    principal: Principal {
                        token_id: format!("witness:{}", o.name),
                        name: format!("witness client for {}", o.name),
                        principal: o.name.clone(),
                        role: Role::WitnessClient,
                        scopes: vec![o.name.clone()],
                        view_raw: false,
                    },
                });
            }
        }
        Ok(TokenStore {
            path,
            issued: RwLock::new(issued),
            configured,
            witness_origins,
        })
    }

    /// Authenticate a presented token value at Unix time `now`.
    pub fn authenticate(&self, presented: &str, now: i64) -> Result<Principal, AuthFailure> {
        let digest = sha256(presented.as_bytes());
        let fingerprint = hex_encode(&digest[..4]);
        let fail = |reason| AuthFailure {
            fingerprint: fingerprint.clone(),
            reason,
        };
        // Constant time over every candidate: no early exit.
        let mut found_configured: Option<usize> = None;
        for (i, c) in self.configured.iter().enumerate() {
            if bool::from(c.sha256.ct_eq(&digest)) {
                found_configured = Some(i);
            }
        }
        let issued = self.issued.read().expect("token lock");
        let mut found_issued: Option<usize> = None;
        for (i, r) in issued.iter().enumerate() {
            let stored: [u8; 32] = hex_decode_exact(&r.sha256).unwrap_or([0u8; 32]);
            if bool::from(stored.ct_eq(&digest)) {
                found_issued = Some(i);
            }
        }
        if let Some(i) = found_configured {
            return Ok(self.configured[i].principal.clone());
        }
        let Some(i) = found_issued else {
            return Err(fail("unknown token"));
        };
        let r = &issued[i];
        if r.revoked_at.is_some() {
            return Err(fail("token revoked"));
        }
        if r.narrowed_admin() {
            return Err(fail(
                "admin tokens cover every run; this one names narrower scopes",
            ));
        }
        if let Some(exp) = &r.expires_at {
            if timefmt::parse_rfc3339(exp).is_none_or(|t| t <= now) {
                return Err(fail("token expired"));
            }
        }
        Ok(Principal {
            token_id: r.id.clone(),
            name: r.name.clone(),
            principal: r.principal.clone(),
            role: r.role,
            scopes: r.scopes.clone(),
            view_raw: r.view_raw,
        })
    }

    /// The principal of a token that is still valid at `now`, by id (for
    /// console sessions, which re-check their token on every request).
    pub fn principal_by_id(&self, id: &str, now: i64) -> Option<Principal> {
        if let Some(c) = self.configured.iter().find(|c| c.principal.token_id == id) {
            return Some(c.principal.clone());
        }
        let issued = self.issued.read().expect("token lock");
        let r = issued.iter().find(|r| r.id == id)?;
        if r.revoked_at.is_some() || r.narrowed_admin() {
            return None;
        }
        if let Some(exp) = &r.expires_at {
            if timefmt::parse_rfc3339(exp).is_none_or(|t| t <= now) {
                return None;
            }
        }
        Some(Principal {
            token_id: r.id.clone(),
            name: r.name.clone(),
            principal: r.principal.clone(),
            role: r.role,
            scopes: r.scopes.clone(),
            view_raw: r.view_raw,
        })
    }

    /// Check an issue request against the rules of design 4.3.
    fn check_issue(&self, req: &IssueRequest, now: i64) -> Result<(), TokenError> {
        let invalid = |m: &str| Err(TokenError::Invalid(m.to_string()));
        let printable = |s: &str| !s.chars().any(char::is_control);
        if req.name.is_empty() || req.name.len() > 128 || !printable(&req.name) {
            return invalid("name: 1 to 128 printable characters");
        }
        if req.principal.is_empty() || req.principal.len() > 256 || !printable(&req.principal) {
            return invalid("principal is required: 1 to 256 printable characters");
        }
        for s in &req.scopes {
            if s.is_empty() || s.len() > 200 || s.contains(char::is_whitespace) || !printable(s) {
                return invalid("scopes: each is a non-empty run-id prefix, or \"*\"");
            }
        }
        if req.scopes.iter().any(|s| s == "*") && req.scopes.len() > 1 {
            return invalid("scopes: \"*\" stands alone");
        }
        match req.role {
            Role::Admin if req.scopes.is_empty() || req.scopes == ["*"] => {}
            Role::Admin => {
                return invalid(
                    "admin tokens cover every run (tokens, holds and the whole access log \
                     cannot be scoped); give no scopes, or [\"*\"], or issue an auditor or \
                     agent token for narrower access",
                )
            }
            Role::WitnessClient => {
                if req.scopes.len() != 1 || !self.witness_origins.contains(&req.scopes[0]) {
                    return invalid(
                        "a witness_client token is bound to exactly one configured origin, given \
                         as its only scope",
                    );
                }
            }
            _ if req.scopes.is_empty() => {
                return invalid(
                    "scopes are required for every role except admin; use [\"*\"] for all runs",
                )
            }
            _ => {}
        }
        if let Some(exp) = &req.expires_at {
            match timefmt::parse_rfc3339(exp) {
                Some(t) if t > now => {}
                Some(_) => return invalid("expires_at is in the past"),
                None => return invalid("expires_at must be RFC 3339"),
            }
        }
        Ok(())
    }

    /// Check an issue request and make the token: its value (shown once)
    /// and its record, not yet stored. The server makes the record of the
    /// issue durable, naming the new id, before [`add`](Self::add) stores
    /// it.
    pub fn prepare(
        &self,
        req: IssueRequest,
        created_by: &str,
        now: i64,
    ) -> Result<(String, TokenRecord), TokenError> {
        self.check_issue(&req, now)?;
        let value = new_token_value().map_err(TokenError::Io)?;
        let scopes = if req.role == Role::Admin {
            vec!["*".to_string()]
        } else {
            req.scopes
        };
        let record = TokenRecord {
            id: new_id("tok_").map_err(TokenError::Io)?,
            name: req.name,
            principal: req.principal,
            role: req.role,
            scopes,
            view_raw: req.view_raw,
            created_at: timefmt::rfc3339(now),
            expires_at: req
                .expires_at
                .and_then(|e| timefmt::parse_rfc3339(&e))
                .map(timefmt::rfc3339),
            revoked_at: None,
            sha256: token_sha256(&value),
            created_by: Some(created_by.to_string()),
        };
        Ok((value, record))
    }

    /// Store a prepared token; it authenticates once this returns.
    pub fn add(&self, record: TokenRecord) -> Result<TokenView, TokenError> {
        let view = TokenView::from(&record);
        let mut issued = self.issued.write().expect("token lock");
        let mut next = issued.clone();
        next.push(record);
        self.save(&next).map_err(TokenError::Io)?;
        *issued = next;
        Ok(view)
    }

    /// Issue a token at once ([`prepare`](Self::prepare), then
    /// [`add`](Self::add)). Returns the token value and its record.
    pub fn issue(
        &self,
        req: IssueRequest,
        created_by: &str,
        now: i64,
    ) -> Result<(String, TokenView), TokenError> {
        let (value, record) = self.prepare(req, created_by, now)?;
        Ok((value, self.add(record)?))
    }

    /// Revoke a token by id. Revoking twice is harmless.
    pub fn revoke(&self, id: &str, now: i64) -> Result<TokenView, TokenError> {
        if self.configured.iter().any(|c| c.principal.token_id == id) {
            return Err(TokenError::Invalid(
                "this token is configured in the server config; remove it there".into(),
            ));
        }
        let mut issued = self.issued.write().expect("token lock");
        let i = issued
            .iter()
            .position(|r| r.id == id)
            .ok_or(TokenError::NotFound)?;
        if issued[i].revoked_at.is_none() {
            let mut next = issued.clone();
            next[i].revoked_at = Some(timefmt::rfc3339(now));
            self.save(&next).map_err(TokenError::Io)?;
            *issued = next;
        }
        Ok(TokenView::from(&issued[i]))
    }

    /// Every issued token, without hashes.
    pub fn list(&self) -> Vec<TokenView> {
        self.issued
            .read()
            .expect("token lock")
            .iter()
            .map(TokenView::from)
            .collect()
    }

    /// The ids of every token the server accepts (for `config.loaded`).
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .configured
            .iter()
            .map(|c| c.principal.token_id.clone())
            .collect();
        ids.extend(
            self.issued
                .read()
                .expect("token lock")
                .iter()
                .filter(|r| r.revoked_at.is_none() && !r.narrowed_admin())
                .map(|r| r.id.clone()),
        );
        ids
    }

    /// Counts for `/metrics`: issued, revoked.
    pub fn counts(&self) -> (u64, u64) {
        let issued = self.issued.read().expect("token lock");
        let revoked = issued.iter().filter(|r| r.revoked_at.is_some()).count() as u64;
        (issued.len() as u64, revoked)
    }

    fn save(&self, tokens: &[TokenRecord]) -> io::Result<()> {
        fsutil::write_json_atomic(
            &self.path,
            &TokensFile {
                tokens: tokens.to_vec(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WitnessOrigin;
    use crate::fsutil::testdir::TestDir;

    fn store(dir: &Path, admin: &str) -> TokenStore {
        let mut c = Config::default();
        c.bootstrap.admin_token_sha256 = token_sha256(admin);
        TokenStore::open(dir, &c).unwrap()
    }

    fn req(role: Role, scopes: &[&str]) -> IssueRequest {
        IssueRequest {
            name: "ci".into(),
            principal: "svc-ci".into(),
            role,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            view_raw: false,
            expires_at: None,
        }
    }

    #[test]
    fn bootstrap_admin_authenticates() {
        let d = TestDir::new("tok-boot");
        let s = store(&d, "prag_admin");
        let p = s.authenticate("prag_admin", 0).unwrap();
        assert_eq!(p.role, Role::Admin);
        assert_eq!(p.token_id, BOOTSTRAP_ID);
        let f = s.authenticate("prag_wrong", 0).unwrap_err();
        assert_eq!(f.fingerprint, token_sha256("prag_wrong")[..8]);
        assert_eq!(f.reason, "unknown token");
    }

    #[test]
    fn issued_tokens_are_stored_by_hash_and_survive_reopen() {
        let d = TestDir::new("tok-issue");
        let s = store(&d, "a");
        let (value, view) = s
            .issue(req(Role::Agent, &["team-a/"]), "tok_a", 100)
            .unwrap();
        assert!(value.starts_with("prag_") && value.len() == 69);
        let text = std::fs::read_to_string(TokenStore::path(&d)).unwrap();
        assert!(!text.contains(&value));
        assert!(text.contains(&token_sha256(&value)));
        let s = store(&d, "a");
        let p = s.authenticate(&value, 101).unwrap();
        assert_eq!(p.token_id, view.id);
        assert!(p.in_scope("team-a/run-1"));
        assert!(!p.in_scope("team-b/run-1"));
    }

    #[test]
    fn scopes_principals_and_roles_are_required() {
        let d = TestDir::new("tok-rules");
        let s = store(&d, "a");
        assert!(s.issue(req(Role::Agent, &[]), "tok_a", 0).is_err());
        assert!(s.issue(req(Role::Auditor, &[""]), "tok_a", 0).is_err());
        assert!(s
            .issue(req(Role::Auditor, &["*", "x"]), "tok_a", 0)
            .is_err());
        assert!(s
            .issue(req(Role::WitnessClient, &["acme"]), "tok_a", 0)
            .is_err());
        let mut r = req(Role::Agent, &["*"]);
        r.principal = String::new();
        assert!(s.issue(r, "tok_a", 0).is_err());
        let (_, admin) = s.issue(req(Role::Admin, &[]), "tok_a", 0).unwrap();
        assert_eq!(admin.scopes, vec!["*"]);
        assert_eq!(admin.created_by.as_deref(), Some("tok_a"));
        // An admin token covers every run: narrower scopes are refused.
        assert!(s.issue(req(Role::Admin, &["team-a:"]), "tok_a", 0).is_err());
        assert!(s.issue(req(Role::Admin, &["*"]), "tok_a", 0).is_ok());
        let mut r = req(Role::Agent, &["*"]);
        r.expires_at = Some("1970-01-01T00:00:00Z".into());
        assert!(s.issue(r, "tok_a", 10).is_err());
    }

    #[test]
    fn revoked_and_expired_tokens_are_refused() {
        let d = TestDir::new("tok-revoke");
        let s = store(&d, "a");
        let mut r = req(Role::Auditor, &["*"]);
        r.expires_at = Some(timefmt::rfc3339(1000));
        let (v1, t1) = s.issue(r, "tok_a", 0).unwrap();
        assert!(s.authenticate(&v1, 999).is_ok());
        assert_eq!(
            s.authenticate(&v1, 1000).unwrap_err().reason,
            "token expired"
        );
        let (v2, t2) = s.issue(req(Role::Agent, &["x"]), "tok_a", 0).unwrap();
        s.revoke(&t2.id, 5).unwrap();
        assert_eq!(s.authenticate(&v2, 6).unwrap_err().reason, "token revoked");
        assert!(matches!(s.revoke("tok_nope", 0), Err(TokenError::NotFound)));
        assert!(matches!(
            s.revoke(BOOTSTRAP_ID, 0),
            Err(TokenError::Invalid(_))
        ));
        assert!(s.ids().contains(&t1.id));
        assert!(!s.ids().contains(&t2.id));
        assert_eq!(s.counts(), (2, 1));
    }

    #[test]
    fn witness_clients_are_bound_to_their_origin() {
        let d = TestDir::new("tok-witness");
        let mut c = Config::default();
        c.witness_mode.enabled = true;
        c.witness_mode.origins.push(WitnessOrigin {
            name: "example.com/log".into(),
            token_sha256: token_sha256("prag_w"),
            public_key: String::new(),
        });
        let s = TokenStore::open(&d, &c).unwrap();
        let p = s.authenticate("prag_w", 0).unwrap();
        assert_eq!(p.role, Role::WitnessClient);
        assert_eq!(p.scopes, vec!["example.com/log"]);
        let (_, t) = s
            .issue(req(Role::WitnessClient, &["example.com/log"]), "tok_a", 0)
            .unwrap();
        assert_eq!(t.role, Role::WitnessClient);
    }

    #[test]
    fn stored_admin_records_with_narrow_scopes_never_authenticate() {
        let d = TestDir::new("tok-narrow");
        let s = store(&d, "a");
        let (value, view) = s.issue(req(Role::Admin, &[]), "tok_a", 0).unwrap();
        assert!(s.authenticate(&value, 1).is_ok());
        // A record written by hand (or by an earlier build) with narrower
        // scopes: shown, but never accepted.
        let path = TokenStore::path(&d);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"*\"", "\"team-a:\"")).unwrap();
        let s = store(&d, "a");
        let f = s.authenticate(&value, 1).unwrap_err();
        assert!(
            f.reason.contains("admin tokens cover every run"),
            "{}",
            f.reason
        );
        assert!(s.principal_by_id(&view.id, 1).is_none());
        assert!(!s.ids().contains(&view.id));
        assert_eq!(s.list()[0].scopes, vec!["team-a:"]);
    }

    #[test]
    fn scope_prefixes() {
        let scopes = vec!["a/".to_string()];
        assert!(scope_matches(&scopes, "a/1"));
        assert!(!scope_matches(&scopes, "b/1"));
        assert!(scope_matches(&["*".to_string()], "anything"));
        assert!(!scope_matches(&["".to_string()], "anything"));
        assert!(!scope_matches(&[], "anything"));
    }
}
