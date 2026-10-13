//! The server configuration (design 4.1): a TOML file with defaults for
//! every key, checked before anything else happens.
//!
//! Unknown keys are errors everywhere. A misspelled security setting (say
//! `alow_plain_http`) silently falling back to its default is exactly the
//! kind of mistake an operator cannot see, so the file must say only things
//! the server understands.
//!
//! Two kinds of checks run at startup:
//!
//! - [`Config::validate`] checks the file on its own: ranges, names,
//!   regular expressions, retention policies.
//! - [`Config::check_startup_rules`] checks the rules that protect a
//!   deployment: listening only on loopback unless plain HTTP behind a
//!   proxy is allowed, at least one independent witness unless
//!   self-anchoring is allowed, and the signing key outside the data
//!   directory.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use pragmatic::redact::Kind;
use serde::{Deserialize, Serialize};

/// Why a configuration was refused. The message names the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// The whole configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// The server's name. Anchoring checkpoints use the origin
    /// `pragmatic/<name>`, and witness mode cosigns under it. Empty means
    /// the host name.
    pub name: String,
    /// The address to listen on, `IP:port`.
    pub listen: String,
    /// Where runs, the access log, tokens and anchors live.
    pub data_dir: PathBuf,
    /// Listen on a non-loopback address without TLS. TLS then terminates
    /// at a proxy or ingress in front of the server.
    pub allow_plain_http: bool,
    /// The header a trusted proxy puts the client address in, such as
    /// `x-forwarded-for`. Empty means the connection's peer address.
    pub trusted_proxy_header: String,
    /// How long a lease lasts without renewal.
    pub lease_ttl_secs: u64,
    /// The largest request body accepted.
    pub max_request_bytes: u64,
    /// Entries whose `at` differs from the server clock by more than this
    /// are accepted but flagged in the lease's custody note.
    pub max_clock_skew_secs: u64,
    /// The URL clients and the console use, if it differs from `listen`.
    /// An `https://` URL makes console cookies `Secure`.
    pub public_url: String,
    /// How often every chain, commitment and anchor proof is re-verified.
    pub verify_interval_hours: u64,
    pub keys: KeysConfig,
    pub bootstrap: BootstrapConfig,
    pub anchoring: AnchoringConfig,
    pub retention: Vec<RetentionPolicy>,
    pub redaction: RedactionConfig,
    pub webhooks: Vec<WebhookConfig>,
    pub witness_mode: WitnessModeConfig,
    pub license: LicenseConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: String::new(),
            listen: "127.0.0.1:7272".into(),
            data_dir: PathBuf::from("/var/lib/pragmatic"),
            allow_plain_http: false,
            trusted_proxy_header: String::new(),
            lease_ttl_secs: 60,
            max_request_bytes: 268_435_456,
            max_clock_skew_secs: 300,
            public_url: String::new(),
            verify_interval_hours: 24,
            keys: KeysConfig::default(),
            bootstrap: BootstrapConfig::default(),
            anchoring: AnchoringConfig::default(),
            retention: Vec::new(),
            redaction: RedactionConfig::default(),
            webhooks: Vec::new(),
            witness_mode: WitnessModeConfig::default(),
            license: LicenseConfig::default(),
        }
    }
}

/// `[keys]`: the server's Ed25519 signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeysConfig {
    /// A PKCS#8 PEM Ed25519 private key (`pragmatic-server keygen` writes
    /// one; `openssl genpkey -algorithm ed25519` too).
    pub signing_key_file: PathBuf,
    /// Allow the key inside `data_dir`. Off by default: a backup of the
    /// data directory would otherwise carry the key that signs it.
    pub allow_key_in_data_dir: bool,
}

impl Default for KeysConfig {
    fn default() -> Self {
        KeysConfig {
            signing_key_file: PathBuf::from("/etc/pragmatic/server.ed25519"),
            allow_key_in_data_dir: false,
        }
    }
}

/// `[bootstrap]`: the first admin token, given by its SHA-256.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BootstrapConfig {
    /// Lowercase hex SHA-256 of the bootstrap admin token. Every other
    /// token is issued through the API.
    pub admin_token_sha256: String,
}

/// `[anchoring]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnchoringConfig {
    /// Seconds between anchoring batches, 60 to 3600.
    pub interval_secs: u64,
    /// RFC 3161 time-stamping authorities.
    pub tsa: Vec<TsaConfig>,
    /// C2SP `tlog-witness` cosigners.
    pub witness: Vec<WitnessConfig>,
    /// Start without any independent witness. Bundles then carry
    /// `"independent": false`.
    pub allow_self_anchoring: bool,
    /// `plain` puts run ids in anchor leaves; `hmac` puts a keyed hash.
    pub anchor_run_ids: String,
    /// Distinct witness operators a checkpoint needs before it counts as
    /// independently anchored.
    pub min_independent_operators: u32,
}

impl Default for AnchoringConfig {
    fn default() -> Self {
        AnchoringConfig {
            interval_secs: 600,
            tsa: Vec::new(),
            witness: Vec::new(),
            allow_self_anchoring: false,
            anchor_run_ids: "plain".into(),
            min_independent_operators: 2,
        }
    }
}

/// One RFC 3161 time-stamping authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsaConfig {
    pub url: String,
    /// PEM file of the pinned roots its tokens must chain to.
    pub roots_pem: PathBuf,
    /// Who runs it, for counting distinct operators. Empty means the URL's
    /// host.
    #[serde(default)]
    pub operator: String,
}

/// One `tlog-witness` cosigner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    pub url: String,
    /// The witness's Ed25519 public key, 64 lowercase hex digits.
    pub public_key: String,
    /// A file holding the bearer token for the witness, if it needs one.
    #[serde(default)]
    pub token_file: PathBuf,
    /// The witness's cosigner name (its key name in signature lines).
    /// Empty means the URL's host.
    #[serde(default)]
    pub name: String,
    /// Who runs it. Empty means the cosigner name.
    #[serde(default)]
    pub operator: String,
}

/// `[[retention]]`: one retention policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetentionPolicy {
    /// Which runs the policy covers.
    #[serde(rename = "match")]
    pub matcher: RetentionMatch,
    /// Days after the last append during which content must be kept.
    pub retain_min_days: u64,
    /// Days after the last append after which every content slot is
    /// erased. 0 means never.
    pub shred_after_days: u64,
    /// Days after the last append after which the run is deleted and
    /// tombstoned. 0 means never.
    pub delete_after_days: u64,
    /// `allow`, or `deny_during_min` to refuse erasure requests while
    /// `retain_min_days` has not passed.
    pub erasure: ErasurePolicy,
}

/// `match = { prefix = "", labels = {} }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetentionMatch {
    /// Run-id prefix; empty matches every run.
    pub prefix: String,
    /// Labels that must all be present with these values.
    pub labels: BTreeMap<String, String>,
}

/// Whether erasure requests are honored during the retention minimum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasurePolicy {
    #[default]
    Allow,
    DenyDuringMin,
}

/// `[redaction]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionConfig {
    /// Built-in detectors: `email`, `phone`, `ssn`, `card`, `iban`,
    /// `ipv4`, `secret` (every credential detector), or any detector name
    /// from the core `redact` module.
    pub builtin: Vec<String>,
    /// Extra regular expressions. Matches are replaced with `[redacted]`.
    pub patterns: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        RedactionConfig {
            builtin: ["email", "phone", "ssn", "card", "iban", "ipv4", "secret"]
                .map(String::from)
                .to_vec(),
            patterns: Vec::new(),
        }
    }
}

impl RedactionConfig {
    /// The core detectors the configured names select, deduplicated.
    pub fn kinds(&self) -> Result<Vec<Kind>, ConfigError> {
        let mut out = Vec::new();
        for name in &self.builtin {
            let kinds: Vec<Kind> = match name.as_str() {
                "card" => vec![Kind::PaymentCard],
                "secret" => Kind::SECRETS.to_vec(),
                other => match Kind::from_name(other) {
                    Some(k) => vec![k],
                    None => return err(format!("redaction.builtin: unknown detector '{other}'")),
                },
            };
            for k in kinds {
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }
}

/// Webhook event types (design 4.12).
pub const WEBHOOK_EVENTS: [&str; 8] = [
    "chain_broken",
    "anchor_failed",
    "regressed",
    "erasure",
    "retention",
    "dangling_effect",
    "clock_skew",
    "record_missing",
];

/// `[[webhooks]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebhookConfig {
    pub url: String,
    /// A file holding the HMAC secret for `Pragmatic-Signature`.
    pub secret_file: PathBuf,
    pub events: Vec<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            url: String::new(),
            secret_file: PathBuf::new(),
            events: WEBHOOK_EVENTS.map(String::from).to_vec(),
        }
    }
}

/// `[witness_mode]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WitnessModeConfig {
    pub enabled: bool,
    pub origins: Vec<WitnessOrigin>,
}

/// A log this server witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessOrigin {
    /// The log's origin line.
    pub name: String,
    /// SHA-256 of the `witness_client` token the log authenticates with.
    pub token_sha256: String,
    /// The log's signed-note verifier key (`<name>+<key id>+<key>`).
    pub public_key: String,
}

/// `[license]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LicenseConfig {
    /// Shown in the console footer and in `/v1/info`. Nothing is enforced.
    pub licensee: String,
}

/// True for 64 lowercase hex digits.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_http_url(s: &str) -> bool {
    (s.starts_with("https://") || s.starts_with("http://")) && !s.contains(char::is_whitespace)
}

/// The host part of an `http(s)://host[:port]/...` URL.
pub fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

impl Config {
    /// Parse a configuration file's text and validate it.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config =
            toml::from_str(text).map_err(|e| ConfigError(format!("config: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Read, parse and validate a configuration file. Returns the
    /// configuration and the SHA-256 of the file's bytes (recorded in the
    /// `config.loaded` access-log record).
    pub fn load(path: &Path) -> Result<(Config, [u8; 32]), ConfigError> {
        let bytes = std::fs::read(path)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigError(format!("{} is not UTF-8", path.display())))?;
        let config = Config::parse(text)?;
        Ok((config, pragmatic::sha256::sha256(&bytes)))
    }

    /// The server name: `name`, or the host name when it is empty.
    pub fn server_name(&self) -> String {
        if !self.name.is_empty() {
            return self.name.clone();
        }
        host_name()
    }

    /// The listen address.
    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen.parse().map_err(|_| {
            ConfigError(format!(
                "listen: '{}' is not an IP address and port",
                self.listen
            ))
        })
    }

    /// True when at least one independent witness is configured.
    pub fn has_independent_witness(&self) -> bool {
        !self.anchoring.tsa.is_empty() || !self.anchoring.witness.is_empty()
    }

    /// True when console cookies must be `Secure`.
    pub fn serves_https(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    /// Check the file on its own (see the module documentation).
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_top()?;
        self.validate_anchoring()?;
        self.validate_retention()?;
        self.redaction.kinds()?;
        for (i, p) in self.redaction.patterns.iter().enumerate() {
            regex::Regex::new(p)
                .map_err(|e| ConfigError(format!("redaction.patterns[{i}]: {e}")))?;
        }
        self.validate_webhooks()?;
        self.validate_witness_mode()?;
        Ok(())
    }

    fn validate_top(&self) -> Result<(), ConfigError> {
        if !self.name.is_empty() && !pragmatic::note::is_valid_origin(&self.name) {
            return err(
                "name: must be 1 to 255 bytes with no white space, '+' or control characters",
            );
        }
        self.listen_addr()?;
        if self.data_dir.as_os_str().is_empty() {
            return err("data_dir: must not be empty");
        }
        let header = &self.trusted_proxy_header;
        if !header.is_empty()
            && !header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return err("trusted_proxy_header: must be a header name such as x-forwarded-for");
        }
        if !(1..=3600).contains(&self.lease_ttl_secs) {
            return err("lease_ttl_secs: must be between 1 and 3600");
        }
        if !(1024..=(1 << 30)).contains(&self.max_request_bytes) {
            return err("max_request_bytes: must be between 1024 and 1073741824");
        }
        if self.max_clock_skew_secs == 0 {
            return err("max_clock_skew_secs: must be at least 1");
        }
        if !self.public_url.is_empty() && !is_http_url(&self.public_url) {
            return err("public_url: must be an http:// or https:// URL");
        }
        if !(1..=24 * 365).contains(&self.verify_interval_hours) {
            return err("verify_interval_hours: must be between 1 and 8760");
        }
        if self.keys.signing_key_file.as_os_str().is_empty() {
            return err("keys.signing_key_file: must not be empty");
        }
        let admin = &self.bootstrap.admin_token_sha256;
        if !admin.is_empty() && !is_sha256_hex(admin) {
            return err("bootstrap.admin_token_sha256: must be 64 lowercase hex digits");
        }
        Ok(())
    }

    fn validate_anchoring(&self) -> Result<(), ConfigError> {
        let a = &self.anchoring;
        if !(60..=3600).contains(&a.interval_secs) {
            return err("anchoring.interval_secs: must be between 60 and 3600");
        }
        if a.anchor_run_ids != "plain" && a.anchor_run_ids != "hmac" {
            return err("anchoring.anchor_run_ids: must be \"plain\" or \"hmac\"");
        }
        if a.min_independent_operators == 0 {
            return err("anchoring.min_independent_operators: must be at least 1");
        }
        for (i, t) in a.tsa.iter().enumerate() {
            if !is_http_url(&t.url) {
                return err(format!("anchoring.tsa[{i}].url: must be an http(s) URL"));
            }
            if t.roots_pem.as_os_str().is_empty() {
                return err(format!("anchoring.tsa[{i}].roots_pem: must not be empty"));
            }
        }
        for (i, w) in a.witness.iter().enumerate() {
            if !is_http_url(&w.url) {
                return err(format!(
                    "anchoring.witness[{i}].url: must be an http(s) URL"
                ));
            }
            if !is_sha256_hex(&w.public_key) {
                return err(format!(
                    "anchoring.witness[{i}].public_key: must be 64 lowercase hex digits"
                ));
            }
        }
        Ok(())
    }

    fn validate_retention(&self) -> Result<(), ConfigError> {
        for (i, p) in self.retention.iter().enumerate() {
            let min = p.retain_min_days;
            if p.shred_after_days != 0 && p.shred_after_days < min {
                return err(format!(
                    "retention[{i}]: shred_after_days must be at least retain_min_days"
                ));
            }
            if p.delete_after_days != 0 && p.delete_after_days < min {
                return err(format!(
                    "retention[{i}]: delete_after_days must be at least retain_min_days"
                ));
            }
            for key in p.matcher.labels.keys() {
                if !is_label_key(key) {
                    return err(format!(
                        "retention[{i}].match.labels: '{key}' is not a label key"
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_webhooks(&self) -> Result<(), ConfigError> {
        for (i, w) in self.webhooks.iter().enumerate() {
            if !is_http_url(&w.url) {
                return err(format!("webhooks[{i}].url: must be an http(s) URL"));
            }
            if w.secret_file.as_os_str().is_empty() {
                return err(format!("webhooks[{i}].secret_file: must not be empty"));
            }
            for e in &w.events {
                if !WEBHOOK_EVENTS.contains(&e.as_str()) {
                    return err(format!("webhooks[{i}].events: unknown event '{e}'"));
                }
            }
        }
        Ok(())
    }

    fn validate_witness_mode(&self) -> Result<(), ConfigError> {
        let mut seen = Vec::new();
        for (i, o) in self.witness_mode.origins.iter().enumerate() {
            if o.name.is_empty() || o.name.chars().any(|c| c < ' ') {
                return err(format!(
                    "witness_mode.origins[{i}].name: must be an origin line"
                ));
            }
            if seen.contains(&&o.name) {
                return err(format!("witness_mode.origins[{i}].name: duplicate origin"));
            }
            seen.push(&o.name);
            if !is_sha256_hex(&o.token_sha256) {
                return err(format!(
                    "witness_mode.origins[{i}].token_sha256: must be 64 lowercase hex digits"
                ));
            }
            pragmatic::note::VerifierKey::parse(&o.public_key)
                .map_err(|e| ConfigError(format!("witness_mode.origins[{i}].public_key: {e}")))?;
        }
        Ok(())
    }

    /// The rules that protect a deployment (design 4.1). `key_path` and
    /// `data_dir` are compared after resolving symbolic links where the
    /// paths exist.
    pub fn check_startup_rules(&self) -> Result<(), ConfigError> {
        let addr = self.listen_addr()?;
        if !addr.ip().is_loopback() && !self.allow_plain_http {
            return err(format!(
                "refusing to listen on {addr}: it is not a loopback address. Put the server \
                 behind a TLS-terminating proxy and set allow_plain_http = true"
            ));
        }
        if !self.has_independent_witness() && !self.anchoring.allow_self_anchoring {
            return err(
                "refusing to start without an independent witness: configure an [anchoring] tsa \
                 or witness, or set allow_self_anchoring = true (evidence then says \
                 \"independent\": false)",
            );
        }
        if !self.keys.allow_key_in_data_dir
            && is_inside(&self.keys.signing_key_file, &self.data_dir)
        {
            return err(
                "refusing to use a signing key inside data_dir: a backup of the data would carry \
                 the key that signs it. Move it, or set keys.allow_key_in_data_dir = true",
            );
        }
        Ok(())
    }
}

/// True for a label key `[a-z0-9_.-]{1,64}` (design 2.11).
pub fn is_label_key(key: &str) -> bool {
    (1..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

/// True if `path` is `dir` or below it, after resolving symbolic links in
/// the longest part of each path that exists (a key file or data directory
/// that is not created yet is judged by its nearest existing ancestor).
fn is_inside(path: &Path, dir: &Path) -> bool {
    resolve(path).starts_with(resolve(dir))
}

fn resolve(p: &Path) -> PathBuf {
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let mut existing = absolute.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(c) = std::fs::canonicalize(existing) {
            let mut out = c;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            _ => return absolute,
        }
    }
}

/// The host name, for a default server name.
fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| pragmatic::note::is_valid_origin(h))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|h| pragmatic::note::is_valid_origin(h))
        })
        .unwrap_or_else(|| "pragmatic-server".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../deploy/pragmatic.example.toml");

    fn base() -> Config {
        Config {
            anchoring: AnchoringConfig {
                allow_self_anchoring: true,
                ..AnchoringConfig::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn defaults_match_the_design() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.listen, "127.0.0.1:7272");
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/pragmatic"));
        assert!(!c.allow_plain_http);
        assert_eq!(c.lease_ttl_secs, 60);
        assert_eq!(c.max_request_bytes, 268_435_456);
        assert_eq!(c.max_clock_skew_secs, 300);
        assert_eq!(c.anchoring.interval_secs, 600);
        assert_eq!(c.anchoring.anchor_run_ids, "plain");
        assert_eq!(c.anchoring.min_independent_operators, 2);
        assert_eq!(c.verify_interval_hours, 24);
        assert_eq!(c.redaction.builtin.len(), 7);
        assert_eq!(c.redaction.kinds().unwrap().len(), 6 + Kind::SECRETS.len());
        assert!(!c.witness_mode.enabled);
    }

    #[test]
    fn the_example_file_is_valid() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert!(c.has_independent_witness());
        assert!(c.check_startup_rules().is_ok() || c.keys.signing_key_file.exists());
    }

    #[test]
    fn unknown_keys_are_refused() {
        let e = Config::parse("alow_plain_http = true").unwrap_err();
        assert!(e.0.contains("alow_plain_http"), "{e}");
        let e = Config::parse("[keys]\nsigning_key = \"x\"").unwrap_err();
        assert!(e.0.contains("signing_key"), "{e}");
    }

    #[test]
    fn ranges_are_checked() {
        for bad in [
            "lease_ttl_secs = 0",
            "max_request_bytes = 10",
            "listen = \"localhost:80\"",
            "[anchoring]\ninterval_secs = 10",
            "[anchoring]\nanchor_run_ids = \"sha\"",
            "[bootstrap]\nadmin_token_sha256 = \"ABC\"",
            "[redaction]\nbuiltin = [\"passport\"]",
            "[redaction]\npatterns = [\"(\"]",
            "trusted_proxy_header = \"x forwarded\"",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn retention_windows_must_cover_the_minimum() {
        let bad = "[[retention]]\nretain_min_days = 30\nshred_after_days = 10";
        assert!(Config::parse(bad).is_err());
        let bad = "[[retention]]\nretain_min_days = 30\ndelete_after_days = 29";
        assert!(Config::parse(bad).is_err());
        let ok = "[[retention]]\nmatch = { prefix = \"eu-\", labels = { tier = \"gold\" } }\n\
                  retain_min_days = 30\nshred_after_days = 30\ndelete_after_days = 0\n\
                  erasure = \"deny_during_min\"";
        let c = Config::parse(ok).unwrap();
        assert_eq!(c.retention[0].erasure, ErasurePolicy::DenyDuringMin);
        assert_eq!(c.retention[0].matcher.labels["tier"], "gold");
    }

    #[test]
    fn plain_http_needs_loopback_or_permission() {
        let mut c = base();
        c.listen = "0.0.0.0:7272".into();
        assert!(c.check_startup_rules().unwrap_err().0.contains("loopback"));
        c.allow_plain_http = true;
        c.check_startup_rules().unwrap();
        c.listen = "[::1]:7272".into();
        c.allow_plain_http = false;
        c.check_startup_rules().unwrap();
    }

    #[test]
    fn an_independent_witness_is_required_unless_waived() {
        let mut c = Config::default();
        assert!(c
            .check_startup_rules()
            .unwrap_err()
            .0
            .contains("independent witness"));
        c.anchoring.tsa.push(TsaConfig {
            url: "https://tsa.example/tsr".into(),
            roots_pem: "/etc/roots.pem".into(),
            operator: String::new(),
        });
        c.check_startup_rules().unwrap();
    }

    #[test]
    fn the_signing_key_must_live_outside_the_data_dir() {
        let mut c = base();
        c.data_dir = "/var/lib/pragmatic".into();
        c.keys.signing_key_file = "/var/lib/pragmatic/keys/server.ed25519".into();
        assert!(c.check_startup_rules().unwrap_err().0.contains("inside"));
        c.keys.allow_key_in_data_dir = true;
        c.check_startup_rules().unwrap();
        c.keys.allow_key_in_data_dir = false;
        c.keys.signing_key_file = "/var/lib/pragmatic-keys/server.ed25519".into();
        c.check_startup_rules().unwrap();
    }

    #[test]
    fn redaction_aliases_expand() {
        let r = RedactionConfig {
            builtin: vec!["card".into(), "secret".into(), "jwt".into()],
            patterns: vec![],
        };
        let kinds = r.kinds().unwrap();
        assert!(kinds.contains(&Kind::PaymentCard));
        assert!(kinds.contains(&Kind::Jwt));
        assert_eq!(kinds.len(), 1 + Kind::SECRETS.len());
    }

    #[test]
    fn url_hosts() {
        assert_eq!(
            url_host("https://timestamp.digicert.com/x"),
            "timestamp.digicert.com"
        );
        assert_eq!(url_host("http://127.0.0.1:9000/tsr"), "127.0.0.1");
        assert_eq!(url_host("https://w.example"), "w.example");
    }
}
