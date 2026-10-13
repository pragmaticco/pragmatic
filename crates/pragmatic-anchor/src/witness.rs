//! C2SP `tlog-witness`: the client a server uses to have its checkpoints
//! cosigned, and the witness-mode service that cosigns other logs'
//! checkpoints (design 4.7, witness type `witness`, and 4.8).
//!
//! A witness remembers the latest checkpoint it cosigned for each log and
//! cosigns a new one only if the log proves it is an extension of that
//! one. A log can therefore never show two different histories to parties
//! who check the same witness: a fork is refused, and the refusal is
//! evidence.
//!
//! # The protocol (`c2sp.org/tlog-witness`)
//!
//! The log POSTs to `<witness url>/add-checkpoint`:
//!
//! ```text
//! old <size of the last checkpoint this witness cosigned for the log>\n
//! <base64 consistency proof hash>\n      (zero to 63 lines)
//! \n
//! <the signed checkpoint note>
//! ```
//!
//! The witness checks, in this order: the origin is known (404) and the
//! log's signature verifies with its configured key (403); the old size
//! does not exceed the checkpoint's (400); the old size is the size it last
//! cosigned for the origin (otherwise 409, with that size in the body as
//! `text/x.tlog.size`, so the log can retry from it); an empty tree has
//! the empty root (422); the consistency proof verifies, and must be empty
//! from size 0 (422); equal sizes have equal roots (422). On success it
//! persists the new checkpoint, atomically with the size check, and only
//! then returns its `cosignature/v1` line: an Ed25519 signature over
//! `"cosignature/v1\ntime <unix>\n" ‖ checkpoint body`.
//!
//! # Witness mode in Pragmatic Server
//!
//! Each origin is configured with the log's public key and bound to the
//! `witness_client` token that may submit for it; the origin always comes
//! from the configuration, never from the request (a checkpoint naming
//! another origin is refused with 403). A witness keeps one cosigned tree
//! per origin line, so no two configured logs may share an origin line
//! (or a configuration name); [`WitnessService::open`] refuses such a
//! configuration. Every cosigned checkpoint is
//! appended, before the cosignature is returned, to the witness's own
//! journal ([`JournalFile`]) as a `witness.cosign` note; the server
//! anchors that journal like any run, so the witness's own history is
//! itself witnessed. Consistency failures from a correctly signed
//! checkpoint (a fork attempt) are recorded as `witness.reject` notes.
//! [`WitnessService::log`] serves the cosigned history
//! (`GET /v1/witness/log/{origin}`).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pragmatic::encoding::{base64_decode_exact, base64_encode, hex_encode};
use pragmatic::journal::{Cursor, Event};
use pragmatic::json::Json;
use pragmatic::merkle;
use pragmatic::note::{
    self, cosignature_v1_message, Checkpoint, Note, NoteSignature, SignatureType, VerifierKey,
};
use pragmatic::sha256::Digest;

use crate::anchorer::Snapshot;
use crate::checkpoint::{json_hex, json_str, json_u64, NoteSigner};
use crate::error::AnchorError;
use crate::journal_file::JournalFile;
use crate::leaf::{LeafType, WITNESS_RUN_ID};
use crate::operator::canonical_operator;
use crate::tsa::HttpTransport;

/// The most consistency proof lines a request may carry.
pub const MAX_PROOF_LINES: usize = 63;
/// `Content-Type` of a 409 response body.
pub const SIZE_CONTENT_TYPE: &str = "text/x.tlog.size";
/// The note kind of a cosigned checkpoint in the witness journal.
pub const COSIGN_NOTE: &str = "witness.cosign";
/// The note kind of a refused fork attempt in the witness journal.
pub const REJECT_NOTE: &str = "witness.reject";
/// The most records one witness log query returns.
pub const MAX_LOG_PAGE: usize = 1000;

// ---------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------

/// A parsed `add-checkpoint` request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddCheckpointRequest {
    pub old_size: u64,
    pub proof: Vec<Digest>,
    /// The signed checkpoint note, as sent.
    pub note: String,
}

/// The request body for `add-checkpoint`.
pub fn encode_add_checkpoint(
    old_size: u64,
    proof: &[Digest],
    signed_note: &str,
) -> Result<String, String> {
    if proof.len() > MAX_PROOF_LINES {
        return Err(format!(
            "a consistency proof of {} hashes exceeds the protocol's {MAX_PROOF_LINES}",
            proof.len()
        ));
    }
    let mut out = format!("old {old_size}\n");
    for h in proof {
        out.push_str(&base64_encode(h));
        out.push('\n');
    }
    out.push('\n');
    out.push_str(signed_note);
    Ok(out)
}

/// Parse an `add-checkpoint` request body. Every malformation is a 400.
pub fn parse_add_checkpoint(body: &[u8]) -> Result<AddCheckpointRequest, String> {
    let text = std::str::from_utf8(body).map_err(|_| "body is not UTF-8".to_string())?;
    let (first, mut rest) = text
        .split_once('\n')
        .ok_or_else(|| "missing the old size line".to_string())?;
    let old_size = first
        .strip_prefix("old ")
        .and_then(parse_decimal)
        .ok_or_else(|| "the first line must be 'old <size>'".to_string())?;
    let mut proof = Vec::new();
    loop {
        let (line, after) = rest
            .split_once('\n')
            .ok_or_else(|| "missing the empty line before the checkpoint".to_string())?;
        rest = after;
        if line.is_empty() {
            break;
        }
        if proof.len() == MAX_PROOF_LINES {
            return Err(format!("more than {MAX_PROOF_LINES} proof lines"));
        }
        proof.push(
            base64_decode_exact::<32>(line)
                .map_err(|_| "a proof line is not base64 of 32 bytes".to_string())?,
        );
    }
    if rest.is_empty() {
        return Err("missing the checkpoint".into());
    }
    Ok(AddCheckpointRequest {
        old_size,
        proof,
        note: rest.to_string(),
    })
}

/// An ASCII decimal with no sign and no leading zeros.
fn parse_decimal(s: &str) -> Option<u64> {
    let canonical = match s.as_bytes() {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    canonical.then(|| s.parse().ok()).flatten()
}

// ---------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------

/// A configured witness (`[anchoring] witness = [{ url, vkey, operator,
/// token_file }]`).
#[derive(Clone, Debug)]
pub struct WitnessConfig {
    /// The witness's submission prefix; requests go to
    /// `<url>/add-checkpoint`.
    pub url: String,
    /// The witness's `cosignature/v1` verifier key (its vkey).
    pub key: VerifierKey,
    /// Who runs it, canonicalized; defaults to the key name. Never empty,
    /// so a configured witness always counts towards independence.
    pub operator: String,
    /// A bearer token, if the witness requires one (a Pragmatic Server in
    /// witness mode does).
    pub token: Option<String>,
}

impl WitnessConfig {
    /// A witness config. Fails if the key is not a `cosignature/v1` key.
    ///
    /// The operator defaults to the key name (design 4.7) when it is
    /// `None` or names nothing once canonicalized (`""`, blanks, dashes):
    /// configuration files spell "not set" as `operator = ""`, and an empty
    /// operator would otherwise be silently left out of the independence
    /// count, so the witness could never make a checkpoint independent.
    pub fn new(
        url: &str,
        key: VerifierKey,
        operator: Option<&str>,
        token: Option<String>,
    ) -> Result<WitnessConfig, AnchorError> {
        if key.signature_type() != SignatureType::CosignatureV1 {
            return Err(AnchorError::Key(
                "a witness key must be a cosignature/v1 (type 0x04) vkey".into(),
            ));
        }
        let operator = operator
            .map(canonical_operator)
            .filter(|o| !o.is_empty())
            .unwrap_or_else(|| canonical_operator(key.name()));
        if operator.is_empty() {
            return Err(AnchorError::Key(format!(
                "witness key {:?} gives no operator name; set operator",
                key.name()
            )));
        }
        Ok(WitnessConfig {
            url: url.trim_end_matches('/').to_string(),
            operator,
            key,
            token,
        })
    }
}

/// A verified cosignature on one checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// The witness's key name.
    pub name: String,
    /// The signature line, without its newline.
    pub line: String,
    /// The signed timestamp, Unix seconds.
    pub timestamp: u64,
}

impl Cosignature {
    /// The witness object in evidence (design 5.1):
    /// `{type: "cosignature", name, line}`.
    pub fn evidence_json(&self) -> Json {
        Json::Object(vec![
            ("type".into(), "cosignature".into()),
            ("name".into(), self.name.as_str().into()),
            ("line".into(), self.line.as_str().into()),
        ])
    }
}

/// Why a witness did not cosign.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessClientError {
    /// 409: the witness last cosigned a tree of `size` leaves for this log;
    /// retry with a proof from that size.
    Conflict { size: u64 },
    /// Any other non-200 status.
    Status { status: u16, body: String },
    /// The request could not be sent or the response not read.
    Transport(String),
    /// A 200 response without a valid cosignature from the configured key.
    NoValidCosignature(String),
    /// The request could not be built.
    Request(String),
}

impl std::fmt::Display for WitnessClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessClientError::Conflict { size } => {
                write!(f, "witness has cosigned up to size {size}")
            }
            WitnessClientError::Status { status, body } => {
                write!(f, "witness answered HTTP {status}: {body}")
            }
            WitnessClientError::Transport(m) => write!(f, "witness unreachable: {m}"),
            WitnessClientError::NoValidCosignature(m) => {
                write!(f, "witness returned no valid cosignature: {m}")
            }
            WitnessClientError::Request(m) => write!(f, "cannot build the request: {m}"),
        }
    }
}

impl std::error::Error for WitnessClientError {}

/// A client for one witness.
pub struct WitnessClient {
    config: WitnessConfig,
    transport: Arc<dyn HttpTransport>,
    timeout: Duration,
}

impl std::fmt::Debug for WitnessClient {
    /// Never prints the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessClient")
            .field("url", &self.config.url)
            .field("key", &self.config.key.encode())
            .field("operator", &self.config.operator)
            .finish()
    }
}

impl WitnessClient {
    /// A client with a 30-second request timeout.
    pub fn new(config: WitnessConfig, transport: Arc<dyn HttpTransport>) -> WitnessClient {
        WitnessClient {
            config,
            transport,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn config(&self) -> &WitnessConfig {
        &self.config
    }

    /// Submit `signed_note` with the consistency proof from `old_size`, and
    /// return the witness's verified cosignature.
    pub fn add_checkpoint(
        &self,
        old_size: u64,
        proof: &[Digest],
        signed_note: &str,
    ) -> Result<Cosignature, WitnessClientError> {
        let body = encode_add_checkpoint(old_size, proof, signed_note)
            .map_err(WitnessClientError::Request)?;
        let checkpoint_body = Note::parse(signed_note)
            .map_err(|e| WitnessClientError::Request(e.to_string()))?
            .body;
        let auth = self.config.token.as_ref().map(|t| format!("Bearer {t}"));
        let mut headers = vec![("Content-Type", "text/plain; charset=utf-8")];
        if let Some(a) = &auth {
            headers.push(("Authorization", a.as_str()));
        }
        let url = format!("{}/add-checkpoint", self.config.url);
        let resp = self
            .transport
            .post(&url, &headers, body.as_bytes(), self.timeout)
            .map_err(WitnessClientError::Transport)?;
        let text = String::from_utf8_lossy(&resp.body);
        match resp.status {
            200 => self.find_cosignature(&checkpoint_body, &text),
            409 => parse_decimal(text.trim_end_matches('\n'))
                .map(|size| WitnessClientError::Conflict { size })
                .map_or_else(
                    || {
                        Err(WitnessClientError::Status {
                            status: 409,
                            body: truncate(&text),
                        })
                    },
                    Err,
                ),
            status => Err(WitnessClientError::Status {
                status,
                body: truncate(&text),
            }),
        }
    }

    /// The configured witness's verified line among the response's
    /// signature lines.
    fn find_cosignature(
        &self,
        body: &str,
        response: &str,
    ) -> Result<Cosignature, WitnessClientError> {
        for line in response.lines().filter(|l| !l.is_empty()) {
            let Ok(sig) = NoteSignature::parse_line(line) else {
                continue;
            };
            if let Some(timestamp) = verify_cosignature(&self.config.key, body, &sig) {
                return Ok(Cosignature {
                    name: sig.name.clone(),
                    line: line.to_string(),
                    timestamp,
                });
            }
        }
        Err(WitnessClientError::NoValidCosignature(truncate(response)))
    }
}

/// The signed timestamp of `sig` if it is a valid `cosignature/v1` from
/// `key` over the checkpoint `body` (through the core verifier).
pub fn verify_cosignature(key: &VerifierKey, body: &str, sig: &NoteSignature) -> Option<u64> {
    (key.signature_type() == SignatureType::CosignatureV1 && key.verify(body, sig))
        .then(|| sig.cosignature_timestamp())
        .flatten()
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

// ---------------------------------------------------------------------
// Witness mode
// ---------------------------------------------------------------------

/// The witness's own key: signs `cosignature/v1` lines.
#[derive(Debug)]
pub struct Cosigner(NoteSigner);

impl Cosigner {
    /// A cosigner named `name` (a valid origin-style name, at most 255
    /// bytes) from a 32-byte seed.
    pub fn from_seed(name: &str, seed: [u8; 32]) -> Result<Cosigner, AnchorError> {
        Ok(Cosigner(NoteSigner::from_seed(
            name,
            SignatureType::CosignatureV1,
            seed,
        )?))
    }

    pub fn generate(name: &str) -> Result<Cosigner, AnchorError> {
        Ok(Cosigner(NoteSigner::generate(
            name,
            SignatureType::CosignatureV1,
        )?))
    }

    /// Parse a key file in the Go `note` private key format with type
    /// `0x04`.
    pub fn parse_skey(skey: &str) -> Result<Cosigner, AnchorError> {
        let s = NoteSigner::parse_skey(skey)?;
        if s.signature_type() != SignatureType::CosignatureV1 {
            return Err(AnchorError::Key("a witness key must have type 0x04".into()));
        }
        Ok(Cosigner(s))
    }

    pub fn encode_skey(&self) -> String {
        self.0.encode_skey()
    }

    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// The vkey logs configure for this witness.
    pub fn verifier_key(&self) -> VerifierKey {
        self.0.verifier_key()
    }

    /// The cosignature on checkpoint `body` at `timestamp` (Unix seconds).
    pub fn cosign(&self, body: &str, timestamp: u64) -> NoteSignature {
        let sig = self
            .0
            .sign(cosignature_v1_message(timestamp, body).as_bytes());
        let mut bytes = timestamp.to_be_bytes().to_vec();
        bytes.extend_from_slice(&sig);
        self.0.note_signature(bytes)
    }
}

/// One origin this witness cosigns for (`[witness_mode] origins`).
#[derive(Clone, Debug)]
pub struct WitnessOrigin {
    /// The configuration name, bound to the `witness_client` token and used
    /// in `GET /v1/witness/log/{name}`.
    pub name: String,
    /// The checkpoint origin line the log signs, e.g. `pragmatic/acme`.
    pub origin: String,
    /// The log's signing keys (Ed25519 note keys).
    pub log_keys: Vec<VerifierKey>,
}

/// Why `add-checkpoint` was refused, with the HTTP status tlog-witness
/// prescribes.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddCheckpointError {
    /// 400: a malformed body, or an old size beyond the checkpoint's.
    BadRequest(String),
    /// 403: no valid log signature, or a checkpoint for another origin
    /// than the token's.
    Forbidden(String),
    /// 404: no origin is configured under this name.
    UnknownOrigin,
    /// 409: the old size is not the size last cosigned for the origin.
    Conflict { size: u64 },
    /// 422: the checkpoint is not consistent with what was cosigned.
    Unprocessable(String),
    /// 503: the witness journal could not be written, so nothing was
    /// cosigned.
    Unavailable(String),
}

impl AddCheckpointError {
    pub fn status(&self) -> u16 {
        match self {
            AddCheckpointError::BadRequest(_) => 400,
            AddCheckpointError::Forbidden(_) => 403,
            AddCheckpointError::UnknownOrigin => 404,
            AddCheckpointError::Conflict { .. } => 409,
            AddCheckpointError::Unprocessable(_) => 422,
            AddCheckpointError::Unavailable(_) => 503,
        }
    }

    /// The response `Content-Type`.
    pub fn content_type(&self) -> &'static str {
        match self {
            AddCheckpointError::Conflict { .. } => SIZE_CONTENT_TYPE,
            _ => "text/plain; charset=utf-8",
        }
    }

    /// The response body: the current size and a newline for 409, a short
    /// reason otherwise.
    pub fn body(&self) -> String {
        match self {
            AddCheckpointError::Conflict { size } => format!("{size}\n"),
            other => format!("{other}\n"),
        }
    }
}

impl std::fmt::Display for AddCheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddCheckpointError::BadRequest(m) => write!(f, "bad request: {m}"),
            AddCheckpointError::Forbidden(m) => write!(f, "forbidden: {m}"),
            AddCheckpointError::UnknownOrigin => f.write_str("unknown origin"),
            AddCheckpointError::Conflict { size } => write!(f, "conflict: latest size {size}"),
            AddCheckpointError::Unprocessable(m) => write!(f, "unprocessable: {m}"),
            AddCheckpointError::Unavailable(m) => write!(f, "unavailable: {m}"),
        }
    }
}

impl std::error::Error for AddCheckpointError {}

/// One cosigned checkpoint in the witness's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignedRecord {
    /// The note's cursor in the witness journal (the paging key).
    pub cursor: Cursor,
    pub origin: String,
    pub old_size: u64,
    pub tree_size: u64,
    pub root: Digest,
    pub timestamp: u64,
    /// The signed checkpoint note as submitted.
    pub checkpoint: String,
    /// This witness's cosignature line.
    pub cosignature: String,
}

impl CosignedRecord {
    fn note_data(&self) -> Json {
        Json::Object(vec![
            ("origin".into(), self.origin.as_str().into()),
            ("old_size".into(), self.old_size.into()),
            ("tree_size".into(), self.tree_size.into()),
            ("root".into(), hex_encode(&self.root).into()),
            ("timestamp".into(), self.timestamp.into()),
            ("checkpoint".into(), self.checkpoint.as_str().into()),
            ("cosignature".into(), self.cosignature.as_str().into()),
        ])
    }

    fn from_note(cursor: Cursor, data: &str) -> Result<CosignedRecord, AnchorError> {
        let doc = Json::parse(data).map_err(|e| AnchorError::Json(e.to_string()))?;
        Ok(CosignedRecord {
            cursor,
            origin: json_str(&doc, "origin")?.to_string(),
            old_size: json_u64(&doc, "old_size")?,
            tree_size: json_u64(&doc, "tree_size")?,
            root: json_hex(&doc, "root")?,
            timestamp: json_u64(&doc, "timestamp")?,
            checkpoint: json_str(&doc, "checkpoint")?.to_string(),
            cosignature: json_str(&doc, "cosignature")?.to_string(),
        })
    }

    /// The record in a witness log response.
    pub fn to_json(&self) -> Json {
        let mut members = vec![("cursor".into(), self.cursor.into())];
        if let Json::Object(rest) = self.note_data() {
            members.extend(rest);
        }
        Json::Object(members)
    }
}

/// One page of `GET /v1/witness/log/{origin}?after=`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessLogPage {
    pub name: String,
    pub records: Vec<CosignedRecord>,
    /// The `after` value for the next page, if there may be one.
    pub next: Option<Cursor>,
}

impl WitnessLogPage {
    /// `{origin, records: [...], next}`.
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("origin".into(), self.name.as_str().into()),
            (
                "records".into(),
                Json::Array(self.records.iter().map(CosignedRecord::to_json).collect()),
            ),
            ("next".into(), self.next.map_or(Json::Null, Json::from)),
        ])
    }
}

struct WitnessState {
    journal: JournalFile,
    /// Latest cosigned (size, root) per origin line.
    latest: HashMap<String, (u64, Digest)>,
    /// Cursors of cosigned records per origin line, ascending.
    history: HashMap<String, Vec<Cursor>>,
}

/// The witness-mode service. Thread-safe; requests for all origins are
/// serialized on one lock, which also makes each origin's size check and
/// journal append atomic.
pub struct WitnessService {
    cosigner: Cosigner,
    origins: Vec<WitnessOrigin>,
    state: Mutex<WitnessState>,
}

impl std::fmt::Debug for WitnessService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessService")
            .field("cosigner", &self.cosigner)
            .field("origins", &self.origins.len())
            .finish()
    }
}

impl WitnessService {
    /// Open the witness journal at `journal_path` (creating it), recover
    /// every origin's latest cosigned checkpoint from it, and serve the
    /// configured `origins`.
    ///
    /// Fails if two origin entries share a configuration name or an origin
    /// line. A witness's whole state (the size and root it last cosigned,
    /// and the history it serves) is per origin line, as in every
    /// `tlog-witness`, so two logs behind one origin line would block each
    /// other forever, each one's honest checkpoints would be journaled as
    /// fork attempts against the other, and each one's history would be
    /// served to the other's auditors.
    pub fn open(
        journal_path: impl AsRef<Path>,
        cosigner: Cosigner,
        origins: Vec<WitnessOrigin>,
    ) -> Result<WitnessService, AnchorError> {
        check_origins(&origins)?;
        let journal = JournalFile::open_or_create(journal_path, WITNESS_RUN_ID)?;
        let mut state = WitnessState {
            journal,
            latest: HashMap::new(),
            history: HashMap::new(),
        };
        let records: Vec<CosignedRecord> = state
            .journal
            .journal()
            .entries()
            .iter()
            .filter_map(|e| match &e.event {
                Event::Note { kind, data, .. } if kind == COSIGN_NOTE => {
                    Some(CosignedRecord::from_note(e.cursor, data))
                }
                _ => None,
            })
            .collect::<Result<_, _>>()?;
        for r in records {
            state.latest.insert(r.origin.clone(), (r.tree_size, r.root));
            state.history.entry(r.origin).or_default().push(r.cursor);
        }
        Ok(WitnessService {
            cosigner,
            origins,
            state: Mutex::new(state),
        })
    }

    pub fn cosigner(&self) -> &Cosigner {
        &self.cosigner
    }

    fn origin(&self, name: &str) -> Option<&WitnessOrigin> {
        self.origins.iter().find(|o| o.name == name)
    }

    /// Handle `POST /add-checkpoint` for the origin bound to the caller's
    /// token. Returns the response body (the cosignature line and a
    /// newline) on success.
    pub fn add_checkpoint(
        &self,
        origin_name: &str,
        body: &[u8],
        now_unix: u64,
    ) -> Result<String, AddCheckpointError> {
        let origin = self
            .origin(origin_name)
            .ok_or(AddCheckpointError::UnknownOrigin)?;
        let req = parse_add_checkpoint(body).map_err(AddCheckpointError::BadRequest)?;
        let signed =
            Note::parse(&req.note).map_err(|e| AddCheckpointError::BadRequest(e.to_string()))?;
        let checkpoint = Checkpoint::parse(&signed.body)
            .map_err(|e| AddCheckpointError::BadRequest(e.to_string()))?;
        if checkpoint.origin != origin.origin {
            return Err(AddCheckpointError::Forbidden(
                "the checkpoint's origin is not the origin bound to this token".into(),
            ));
        }
        note::verify_note(&signed, &origin.log_keys)
            .map_err(|e| AddCheckpointError::Forbidden(e.to_string()))?;
        if req.old_size > checkpoint.tree_size {
            return Err(AddCheckpointError::BadRequest(
                "old size exceeds the checkpoint's size".into(),
            ));
        }

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (latest_size, latest_root) = state
            .latest
            .get(&origin.origin)
            .copied()
            .unwrap_or((0, merkle::empty_root()));
        if req.old_size != latest_size {
            return Err(AddCheckpointError::Conflict { size: latest_size });
        }
        if let Err(why) = check_consistency(&req, &checkpoint, &latest_root) {
            // A correctly signed checkpoint that does not extend what was
            // cosigned is evidence of a fork: record it.
            let reject = Json::Object(vec![
                ("origin".into(), origin.origin.as_str().into()),
                ("old_size".into(), req.old_size.into()),
                ("tree_size".into(), checkpoint.tree_size.into()),
                ("root".into(), hex_encode(&checkpoint.root).into()),
                ("checkpoint".into(), req.note.as_str().into()),
                ("reason".into(), why.as_str().into()),
            ]);
            let _ = state.journal.append_note(REJECT_NOTE, &reject, Vec::new());
            return Err(AddCheckpointError::Unprocessable(why));
        }

        let sig = self.cosigner.cosign(&signed.body, now_unix);
        let line = sig
            .to_line()
            .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?;
        let record = CosignedRecord {
            cursor: 0,
            origin: origin.origin.clone(),
            old_size: req.old_size,
            tree_size: checkpoint.tree_size,
            root: checkpoint.root,
            timestamp: now_unix,
            checkpoint: req.note.clone(),
            cosignature: line.clone(),
        };
        // Durable before the cosignature leaves: a witness that forgot a
        // cosignature after a crash could be talked into signing a fork.
        let cursor = state
            .journal
            .append_note(COSIGN_NOTE, &record.note_data(), Vec::new())
            .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?;
        state.latest.insert(
            origin.origin.clone(),
            (checkpoint.tree_size, checkpoint.root),
        );
        state
            .history
            .entry(origin.origin.clone())
            .or_default()
            .push(cursor);
        Ok(format!("{line}\n"))
    }

    /// The latest checkpoint cosigned for the origin named `origin_name`.
    pub fn latest(&self, origin_name: &str) -> Option<(u64, Digest)> {
        let origin = self.origin(origin_name)?;
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.latest.get(&origin.origin).copied()
    }

    /// The cosigned history of the origin named `origin_name`, records
    /// with cursors after `after`, at most `limit` (capped at
    /// [`MAX_LOG_PAGE`]).
    pub fn log(
        &self,
        origin_name: &str,
        after: Option<Cursor>,
        limit: usize,
    ) -> Result<WitnessLogPage, AddCheckpointError> {
        let origin = self
            .origin(origin_name)
            .ok_or(AddCheckpointError::UnknownOrigin)?;
        let limit = limit.clamp(1, MAX_LOG_PAGE);
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let cursors = state
            .history
            .get(&origin.origin)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let start = after.map_or(0, |a| cursors.partition_point(|c| *c <= a));
        let page = &cursors[start..cursors.len().min(start + limit)];
        let mut records = Vec::with_capacity(page.len());
        for &cursor in page {
            let entry = state.journal.journal().get(cursor).ok_or_else(|| {
                AddCheckpointError::Unavailable("witness journal is missing a record".into())
            })?;
            let Event::Note { data, .. } = &entry.event else {
                return Err(AddCheckpointError::Unavailable(
                    "witness journal record is not a note".into(),
                ));
            };
            records.push(
                CosignedRecord::from_note(cursor, data)
                    .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?,
            );
        }
        let more = start + page.len() < cursors.len();
        Ok(WitnessLogPage {
            name: origin.name.clone(),
            next: more.then(|| *page.last().expect("non-empty when more")),
            records,
        })
    }

    /// The witness journal's state, to anchor it in the server's own log
    /// as run [`WITNESS_RUN_ID`].
    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (entries, head) = state.journal.state();
        Snapshot {
            leaf_type: LeafType::Run,
            id: WITNESS_RUN_ID.to_string(),
            entries,
            head,
        }
    }
}

/// The configured origins must be usable and must not share a name or an
/// origin line (see [`WitnessService::open`]).
fn check_origins(origins: &[WitnessOrigin]) -> Result<(), AnchorError> {
    let mut names = std::collections::HashSet::new();
    let mut lines = std::collections::HashSet::new();
    for o in origins {
        if o.name.is_empty() {
            return Err(AnchorError::Key(format!(
                "origin {:?}: the configuration name is empty",
                o.origin
            )));
        }
        if !note::is_valid_origin(&o.origin) {
            return Err(AnchorError::Key(format!(
                "origin {}: {:?} is not a valid origin line",
                o.name, o.origin
            )));
        }
        if o.log_keys.is_empty() {
            return Err(AnchorError::Key(format!("origin {}: no log key", o.name)));
        }
        if o.log_keys
            .iter()
            .any(|k| k.signature_type() != SignatureType::Ed25519)
        {
            return Err(AnchorError::Key(format!(
                "origin {}: log keys must be Ed25519 note keys",
                o.name
            )));
        }
        if !names.insert(o.name.as_str()) {
            return Err(AnchorError::Key(format!(
                "two origins are named {:?}",
                o.name
            )));
        }
        if !lines.insert(o.origin.as_str()) {
            return Err(AnchorError::Key(format!(
                "origins share the origin line {:?}: a witness keeps one cosigned tree per \
                 origin line, so each log must have its own",
                o.origin
            )));
        }
    }
    Ok(())
}

/// tlog-witness checks 4 to 6: the empty tree, the consistency proof, and
/// equal roots at equal sizes.
fn check_consistency(
    req: &AddCheckpointRequest,
    checkpoint: &Checkpoint,
    latest_root: &Digest,
) -> Result<(), String> {
    if checkpoint.tree_size == 0 && checkpoint.root != merkle::empty_root() {
        return Err("an empty tree must have the empty root".into());
    }
    if req.old_size == 0 {
        return if req.proof.is_empty() {
            Ok(())
        } else {
            Err("a proof from size 0 must be empty".into())
        };
    }
    if req.old_size == checkpoint.tree_size {
        return if req.proof.is_empty() && checkpoint.root == *latest_root {
            Ok(())
        } else {
            Err("a checkpoint of the cosigned size must have the cosigned root".into())
        };
    }
    if merkle::verify_consistency(
        req.old_size,
        checkpoint.tree_size,
        latest_root,
        &checkpoint.root,
        &req.proof,
    ) {
        Ok(())
    } else {
        Err("the consistency proof does not verify".into())
    }
}

#[cfg(test)]
mod tests;
