//! RFC 3161 time-stamping of checkpoints (design 4.7, witness type
//! `rfc3161`).
//!
//! For each checkpoint the server asks every configured Time-Stamp
//! Authority to timestamp `anchor_digest = SHA-256(checkpoint body)`. A
//! token proves that the checkpoint, and so every journal prefix under its
//! root, existed no later than the TSA's signed `genTime`, attested by a
//! party the server's operator does not control.
//!
//! # The exchange
//!
//! - The request is the core's [`tsp::request`]: a SHA-256 imprint of the
//!   anchor digest, a fresh 64-bit nonce from the OS CSPRNG, and
//!   `certReq = true` so the token carries the TSA's certificate. It is
//!   POSTed as `application/timestamp-query` with a 30-second timeout.
//! - Requests to one TSA are spaced at least 15 seconds apart. Public TSAs
//!   are free services with rate limits; a server that hammered one would
//!   be blocked and lose its witness. The docs ask operators to obtain
//!   written permission for automated use.
//! - A failed attempt is retried with backoff and a *fresh* nonce, so a
//!   stale or replayed response for an earlier nonce can never be
//!   accepted.
//!
//! # What is checked before a token is stored
//!
//! 1. The response parses as strict DER and its status is granted
//!    ([`tsp::parse_response`]).
//! 2. The token's nonce equals the one sent and its imprint is SHA-256 of
//!    exactly the anchor digest ([`tsp::parse_token`]).
//! 3. The CMS signature verifies, through the signer certificate's chain,
//!    to one of the TSA's configured pinned roots, with the
//!    `id-kp-timeStamping` extended key usage that OpenSSL requires to be
//!    critical. That is OpenSSL's job (X.509 path building and several
//!    signature algorithms are not something to reimplement), invoked
//!    exactly as the design specifies:
//!
//!    ```text
//!    openssl ts -verify -token_in -in <i>.der -digest <anchor_digest hex>
//!                -CAfile <configured roots> -untrusted <i>.pem
//!    ```
//!
//!    where `<i>.pem` holds the certificates carried in the token itself.
//!    The files live in a fresh 0700 temporary directory, are named by
//!    index, and OpenSSL is run directly, never through a shell.
//!
//! The stored witness object carries the token and that certificate chain,
//! so an auditor can rerun the same check offline against roots they pin
//! themselves.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pragmatic::encoding::{base64_encode, hex_encode};
use pragmatic::json::Json;
use pragmatic::sha256::Digest;
use pragmatic::tsp::{self, TstInfo};

use crate::operator::canonical_operator;

/// `Content-Type` of a time-stamp request.
pub const QUERY_CONTENT_TYPE: &str = "application/timestamp-query";

/// The largest response accepted. Tokens with full chains are a few
/// kilobytes; anything near this is not a time-stamp response.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// Why a time-stamp could not be obtained or was refused.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TsaError {
    /// The request could not be sent or the response not read (DNS,
    /// connect, TLS, timeout).
    Transport(String),
    /// The TSA answered with a non-200 HTTP status.
    Http { status: u16 },
    /// The response is not a well-formed `TimeStampResp` or token.
    Malformed(String),
    /// The TSA refused the request (PKIStatus not granted).
    Rejected {
        status: u8,
        text: Vec<String>,
        fail_info: Option<u32>,
    },
    /// The token carries no nonce, or another nonce than the one sent.
    NonceMismatch,
    /// The token timestamps something other than the anchor digest.
    ImprintMismatch,
    /// The token carries no certificates, although `certReq` asked for
    /// them.
    NoCertificates,
    /// `openssl ts -verify` refused the token against the pinned roots.
    Verify(String),
    /// OpenSSL could not be run, or a local file could not be prepared.
    Local(String),
}

impl TsaError {
    /// True for failures a later attempt (with a fresh nonce) may not hit:
    /// network trouble, server errors and refusals, and responses that do
    /// not match the request. A token that fails CMS verification against
    /// the pinned roots, or a local failure, will fail again the same way.
    pub fn is_retryable(&self) -> bool {
        !matches!(self, TsaError::Verify(_) | TsaError::Local(_))
    }
}

impl std::fmt::Display for TsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TsaError::Transport(m) => write!(f, "TSA unreachable: {m}"),
            TsaError::Http { status } => write!(f, "TSA answered HTTP {status}"),
            TsaError::Malformed(m) => write!(f, "malformed time-stamp response: {m}"),
            TsaError::Rejected {
                status,
                text,
                fail_info,
            } => write!(
                f,
                "TSA refused the request (status {status}, fail info {fail_info:?}): {}",
                text.join("; ")
            ),
            TsaError::NonceMismatch => f.write_str("time-stamp nonce does not match the request"),
            TsaError::ImprintMismatch => {
                f.write_str("time-stamp imprint is not SHA-256 of the anchor digest")
            }
            TsaError::NoCertificates => f.write_str("time-stamp token carries no certificates"),
            TsaError::Verify(m) => write!(f, "time-stamp token failed verification: {m}"),
            TsaError::Local(m) => write!(f, "time-stamp verification could not run: {m}"),
        }
    }
}

impl std::error::Error for TsaError {}

// ---------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------

/// An HTTP response, as much of it as the anchoring clients read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// The one HTTP operation anchoring needs: a POST with a timeout. A trait
/// so the server can share one connection pool and tests can count
/// requests.
pub trait HttpTransport: Send + Sync {
    fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String>;
}

/// [`HttpTransport`] over `ureq` (blocking, rustls with the webpki roots
/// for `https` witnesses and TSAs).
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::new()
    }
}

impl UreqTransport {
    pub fn new() -> UreqTransport {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("pragmatic-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        UreqTransport { agent }
    }
}

impl HttpTransport for UreqTransport {
    fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut resp = req
            .config()
            .timeout_global(Some(timeout))
            .build()
            .send(body)
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(HttpResponse {
            status,
            content_type,
            body,
        })
    }
}

// ---------------------------------------------------------------------
// OpenSSL
// ---------------------------------------------------------------------

/// Runs the `openssl` command line tool for what the core does not do:
/// CMS signature and certificate chain verification.
#[derive(Clone, Debug)]
pub struct OpensslVerifier {
    program: PathBuf,
}

impl Default for OpensslVerifier {
    /// `openssl` from `PATH`.
    fn default() -> Self {
        OpensslVerifier::new("openssl")
    }
}

impl OpensslVerifier {
    pub fn new(program: impl Into<PathBuf>) -> OpensslVerifier {
        OpensslVerifier {
            program: program.into(),
        }
    }

    /// `openssl version`, or an error if OpenSSL cannot be run. The server
    /// checks this at startup when TSAs are configured.
    pub fn version(&self) -> Result<String, TsaError> {
        let out = self.run(&["version"])?;
        if !out.status.success() {
            return Err(TsaError::Local("openssl version failed".into()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// The certificates a token carries, as PEM (`openssl pkcs7
    /// -print_certs`), with OpenSSL's subject and issuer comment lines
    /// removed. These are passed to verification as untrusted
    /// intermediates only.
    pub fn token_certs_pem(&self, token: &[u8]) -> Result<String, TsaError> {
        let dir = private_temp_dir()?;
        let der = dir.path().join("0.der");
        write_file(&der, token)?;
        let out = self.run(&[
            OsStr::new("pkcs7"),
            OsStr::new("-inform"),
            OsStr::new("DER"),
            OsStr::new("-in"),
            der.as_os_str(),
            OsStr::new("-print_certs"),
        ])?;
        if !out.status.success() {
            return Err(TsaError::Malformed(format!(
                "openssl pkcs7 could not read the token: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(pem_certificates(&String::from_utf8_lossy(&out.stdout)))
    }

    /// `openssl ts -verify -token_in -in <i>.der -digest <hex> -CAfile
    /// <roots> -untrusted <i>.pem`. Succeeds only if OpenSSL exits 0 and
    /// reports `Verification: OK`.
    pub fn verify_token(
        &self,
        token: &[u8],
        digest: &Digest,
        roots_pem: &Path,
        untrusted_pem: &str,
    ) -> Result<(), TsaError> {
        if !roots_pem.is_file() {
            return Err(TsaError::Local(format!(
                "pinned TSA roots {} not found",
                roots_pem.display()
            )));
        }
        let dir = private_temp_dir()?;
        let der = dir.path().join("0.der");
        let pem = dir.path().join("0.pem");
        write_file(&der, token)?;
        write_file(&pem, untrusted_pem.as_bytes())?;
        let digest_hex = hex_encode(digest);
        let out = self.run(&[
            OsStr::new("ts"),
            OsStr::new("-verify"),
            OsStr::new("-token_in"),
            OsStr::new("-in"),
            der.as_os_str(),
            OsStr::new("-digest"),
            OsStr::new(&digest_hex),
            OsStr::new("-CAfile"),
            roots_pem.as_os_str(),
            OsStr::new("-untrusted"),
            pem.as_os_str(),
        ])?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && stdout.contains("Verification: OK") {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(TsaError::Verify(first_error_line(&stderr, &stdout)))
        }
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<std::process::Output, TsaError> {
        Command::new(&self.program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| TsaError::Local(format!("cannot run {}: {e}", self.program.display())))
    }
}

/// A fresh directory readable only by this user, removed on drop.
fn private_temp_dir() -> Result<tempfile::TempDir, TsaError> {
    let dir = tempfile::Builder::new()
        .prefix("pragmatic-tsa-")
        .tempdir()
        .map_err(|e| TsaError::Local(format!("creating a temporary directory: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| TsaError::Local(format!("restricting the temporary directory: {e}")))?;
    }
    Ok(dir)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), TsaError> {
    std::fs::write(path, bytes)
        .map_err(|e| TsaError::Local(format!("writing {}: {e}", path.display())))
}

/// Only the `BEGIN CERTIFICATE` to `END CERTIFICATE` blocks of OpenSSL's
/// output.
fn pem_certificates(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
        if line == "-----END CERTIFICATE-----" {
            inside = false;
        }
    }
    out
}

/// A short reason from OpenSSL's output for logs and alerts.
fn first_error_line(stderr: &str, stdout: &str) -> String {
    stderr
        .lines()
        .chain(stdout.lines())
        .find(|l| l.contains("error") || l.contains("FAILED"))
        .or_else(|| stderr.lines().next())
        .unwrap_or("verification failed")
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------
// Validation and the client
// ---------------------------------------------------------------------

/// Check a `TimeStampResp` against the request it answers: granted status,
/// the nonce sent, and an imprint of exactly `digest`. Returns the token
/// and its parsed `TSTInfo`. The CMS signature is not checked here.
pub fn validate_response(
    response: &[u8],
    digest: &Digest,
    nonce: u64,
) -> Result<(Vec<u8>, TstInfo), TsaError> {
    let parsed = tsp::parse_response(response).map_err(|e| TsaError::Malformed(e.to_string()))?;
    if !parsed.status.is_granted() {
        return Err(TsaError::Rejected {
            status: parsed.status.code(),
            text: parsed.status_text,
            fail_info: parsed.fail_info,
        });
    }
    let token = parsed
        .token
        .ok_or_else(|| TsaError::Malformed("no token".into()))?;
    let info = tsp::parse_token(&token).map_err(|e| TsaError::Malformed(e.to_string()))?;
    if info.nonce_u64() != Some(nonce) {
        return Err(TsaError::NonceMismatch);
    }
    if !info.imprint_matches(digest) {
        return Err(TsaError::ImprintMismatch);
    }
    Ok((token, info))
}

/// A configured TSA (`[anchoring] tsa = [{ url, operator, roots_pem }]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaConfig {
    pub url: String,
    /// Who runs it, canonicalized (see [`crate::operator`]).
    pub operator: String,
    /// PEM file with the root certificates pinned for this TSA.
    pub roots_pem: PathBuf,
}

impl TsaConfig {
    pub fn new(url: &str, operator: &str, roots_pem: impl Into<PathBuf>) -> TsaConfig {
        TsaConfig {
            url: url.to_string(),
            operator: canonical_operator(operator),
            roots_pem: roots_pem.into(),
        }
    }
}

/// Timing for one TSA. The defaults are the design's values; tests lower
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsaPolicy {
    /// Per request: 30 seconds.
    pub timeout: Duration,
    /// Between two requests to the same TSA: at least 15 seconds.
    pub min_spacing: Duration,
    /// Attempts per [`TsaClient::timestamp`] call: 3.
    pub max_attempts: u32,
    /// Backoff before the second attempt, doubling after that: 2 seconds.
    pub initial_backoff: Duration,
    /// The longest backoff: 60 seconds.
    pub max_backoff: Duration,
}

impl Default for TsaPolicy {
    fn default() -> Self {
        TsaPolicy {
            timeout: Duration::from_secs(30),
            min_spacing: Duration::from_secs(15),
            max_attempts: 3,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// A verified time-stamp token for one anchor digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaToken {
    pub url: String,
    pub operator: String,
    /// The token (CMS `ContentInfo` DER), exactly as received.
    pub token: Vec<u8>,
    /// The certificates the token carries, PEM.
    pub certs_pem: String,
    pub nonce: u64,
    pub info: TstInfo,
}

impl TsaToken {
    /// `genTime` in Unix seconds (0 if before the epoch, which no valid
    /// token is).
    pub fn gen_time_unix(&self) -> u64 {
        u64::try_from(self.info.gen_time_unix).unwrap_or(0)
    }

    /// The witness object in evidence (design 5.1):
    /// `{type: "rfc3161", tsa, operator, token, certs_pem}`.
    pub fn evidence_json(&self) -> Json {
        Json::Object(vec![
            ("type".into(), "rfc3161".into()),
            ("tsa".into(), self.url.as_str().into()),
            ("operator".into(), self.operator.as_str().into()),
            ("token".into(), base64_encode(&self.token).into()),
            ("certs_pem".into(), self.certs_pem.as_str().into()),
        ])
    }
}

/// A client for one TSA: spacing, retries, validation and verification.
pub struct TsaClient {
    config: TsaConfig,
    policy: TsaPolicy,
    transport: Arc<dyn HttpTransport>,
    verifier: OpensslVerifier,
    last_request: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for TsaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsaClient")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .finish()
    }
}

impl TsaClient {
    pub fn new(
        config: TsaConfig,
        policy: TsaPolicy,
        transport: Arc<dyn HttpTransport>,
        verifier: OpensslVerifier,
    ) -> TsaClient {
        TsaClient {
            config,
            policy,
            transport,
            verifier,
            last_request: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &TsaConfig {
        &self.config
    }

    /// Obtain a verified token for `digest`, retrying with backoff and a
    /// fresh nonce per attempt. Blocks for the spacing and backoff, so it
    /// belongs on the anchoring task, never on a request path.
    pub fn timestamp(&self, digest: &Digest) -> Result<TsaToken, TsaError> {
        let mut last = TsaError::Transport("no attempt made".into());
        for attempt in 0..self.policy.max_attempts.max(1) {
            if attempt > 0 {
                std::thread::sleep(self.backoff(attempt));
            }
            match self.timestamp_once(digest, fresh_nonce()?) {
                Ok(token) => return Ok(token),
                Err(e) if e.is_retryable() => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// One attempt with a given nonce (after waiting out the spacing).
    pub fn timestamp_once(&self, digest: &Digest, nonce: u64) -> Result<TsaToken, TsaError> {
        let request = tsp::request(digest, nonce);
        self.wait_for_spacing();
        let resp = self
            .transport
            .post(
                &self.config.url,
                &[("Content-Type", QUERY_CONTENT_TYPE)],
                &request,
                self.policy.timeout,
            )
            .map_err(TsaError::Transport)?;
        if resp.status != 200 {
            return Err(TsaError::Http {
                status: resp.status,
            });
        }
        let (token, info) = validate_response(&resp.body, digest, nonce)?;
        let certs_pem = self.verifier.token_certs_pem(&token)?;
        if certs_pem.is_empty() {
            return Err(TsaError::NoCertificates);
        }
        self.verifier
            .verify_token(&token, digest, &self.config.roots_pem, &certs_pem)?;
        Ok(TsaToken {
            url: self.config.url.clone(),
            operator: self.config.operator.clone(),
            token,
            certs_pem,
            nonce,
            info,
        })
    }

    /// Sleep until at least `min_spacing` has passed since the previous
    /// request to this TSA, then claim the slot. Concurrent callers queue
    /// on the lock, so they are spaced too.
    fn wait_for_spacing(&self) {
        let mut last = self.last_request.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = *last {
            let since = prev.elapsed();
            if since < self.policy.min_spacing {
                std::thread::sleep(self.policy.min_spacing - since);
            }
        }
        *last = Some(Instant::now());
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32 << (attempt - 1).min(16);
        self.policy
            .initial_backoff
            .saturating_mul(factor)
            .min(self.policy.max_backoff)
    }
}

/// A fresh 64-bit nonce from the OS CSPRNG.
fn fresh_nonce() -> Result<u64, TsaError> {
    let mut b = [0u8; 8];
    pragmatic::rand::fill(&mut b).map_err(|e| TsaError::Local(format!("CSPRNG failed: {e}")))?;
    Ok(u64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_classification() {
        assert!(TsaError::Transport("x".into()).is_retryable());
        assert!(TsaError::Http { status: 503 }.is_retryable());
        assert!(TsaError::NonceMismatch.is_retryable());
        assert!(!TsaError::Verify("x".into()).is_retryable());
        assert!(!TsaError::Local("x".into()).is_retryable());
    }

    #[test]
    fn pem_filter_keeps_only_certificates() {
        let text = "subject=CN=a\nissuer=CN=b\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\nsubject=CN=c\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_certificates(text),
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let client = TsaClient::new(
            TsaConfig::new("http://x", "x", "/nonexistent"),
            TsaPolicy::default(),
            Arc::new(UreqTransport::new()),
            OpensslVerifier::default(),
        );
        assert_eq!(client.backoff(1), Duration::from_secs(2));
        assert_eq!(client.backoff(2), Duration::from_secs(4));
        assert_eq!(client.backoff(10), Duration::from_secs(60));
        assert_eq!(client.config().operator, "x");
    }

    #[test]
    fn validation_rejects_garbage() {
        assert!(matches!(
            validate_response(b"not der", &[0; 32], 1),
            Err(TsaError::Malformed(_))
        ));
    }
}
