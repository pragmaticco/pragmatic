//! Where separately built components plug into the server.
//!
//! Three parts of the server are built as their own components and
//! integrated here:
//!
//! - **Anchoring** (design 4.7, the `pragmatic-anchor` library): the
//!   cumulative Merkle log, signed checkpoints and witnesses. The server
//!   calls [`Anchoring::anchor`] every `interval_secs`, within 30 s of a
//!   successful `attempt.end`, and for `anchor=now`, with the tips of every
//!   run that changed; anchoring calls back through [`AnchorHost`] when
//!   runs become independently anchored or when something fails.
//! - **Evidence bundles** (design 5): [`EvidenceBuilder::build`] turns a
//!   run's durable journal into a bundle.
//! - **The console** (design 4.14, the `pragmatic-console` renderer):
//!   [`ConsoleRenderer::render`] turns page data (the same JSON shapes the
//!   API serves) into HTML.
//!
//! Each has a stub that is clearly not the real thing: [`NoAnchoring`]
//! anchors nothing, [`EvidenceStub`] answers 501, and [`ConsoleStub`]
//! answers 501. The server is complete without them in every other
//! respect: access control, redaction and the access log all happen before
//! a hook is called, so an integration never has to repeat them.

use std::collections::HashMap;
use std::fmt;

use pragmatic::sha256::Digest;
use pragmatic::Journal;
use serde_json::Value as JsonValue;

use crate::keys::ServerKey;
use crate::redaction::Redactor;

// ---------------------------------------------------------------------------
// Anchoring
// ---------------------------------------------------------------------------

/// The durable tip of one run, snapshotted under the run's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunTip {
    pub run_id: String,
    pub entries: u64,
    pub head: Digest,
    /// The run's previous leaf in the log, if it has one.
    pub prev_leaf: Option<u64>,
}

/// The durable tip of the access log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTip {
    pub entries: u64,
    pub head: Digest,
    pub prev_leaf: Option<u64>,
}

/// What one batch should anchor: every run (and the access log) that
/// changed since its last leaf. Runs created by PUT appear even with zero
/// entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchInput {
    pub runs: Vec<RunTip>,
    pub access_log: Option<LogTip>,
}

/// Why a batch runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchReason {
    /// The regular `interval_secs` tick.
    Interval,
    /// A run's attempt ended ok within the last 30 s.
    AttemptEnded,
    /// `GET /v1/runs/{id}/evidence?anchor=now`.
    Now,
}

/// One leaf a batch appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafPlaced {
    /// The run, or `None` for the access log.
    pub run_id: Option<String>,
    pub entries: u64,
    pub leaf_index: u64,
}

/// What a batch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchReceipt {
    pub seq: u64,
    pub tree_size: u64,
    pub leaves: Vec<LeafPlaced>,
}

/// Something an operator must hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorAlert {
    /// A batch or a witness failed (webhook `anchor_failed`).
    Failed { reason: String },
}

/// Why anchoring could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorError(pub String);

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One checkpoint as `GET /v1/anchors` serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointView {
    pub seq: u64,
    /// Checkpoint text, signatures, witness results and anything else the
    /// anchoring library records, as JSON.
    pub body: JsonValue,
    /// The leaves of this batch, filtered by scope before serving.
    pub leaves: Vec<LeafView>,
}

/// One leaf of the log.
#[derive(Debug, Clone, PartialEq)]
pub struct LeafView {
    pub index: u64,
    /// The run whose tip this is (`None` for the access log). Used only to
    /// filter by scope; whether it is shown is the library's choice (with
    /// `anchor_run_ids = "hmac"` it should not be).
    pub run_id: Option<String>,
    pub body: JsonValue,
}

/// What the server offers anchoring.
pub trait AnchorHost: Send + Sync {
    /// These runs are independently anchored up to these entry counts:
    /// their `anchored_entries` advance (never back).
    fn anchored(&self, runs: &[(String, u64)]);
    /// Raise an alert (metric and webhook).
    fn alert(&self, alert: AnchorAlert);
}

/// The anchoring library, as the server calls it. Every method may block:
/// the server calls them from blocking tasks.
pub trait Anchoring: Send + Sync + 'static {
    /// True when at least one independent witness is configured. Bundles
    /// say `"independent": false` otherwise.
    fn independent(&self) -> bool;

    /// Append leaves for `input` (in order of type and raw id bytes), end
    /// the batch in a signed checkpoint, and start witnessing it. `None`
    /// when there was nothing to anchor. For [`BatchReason::Now`] return
    /// only once the checkpoint file is stored.
    fn anchor(
        &self,
        host: &dyn AnchorHost,
        input: BatchInput,
        reason: BatchReason,
    ) -> Result<Option<BatchReceipt>, AnchorError>;

    /// Checkpoints after `after` (from the first when `None`), at most
    /// `limit`.
    fn checkpoints(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<CheckpointView>, AnchorError>;

    /// One checkpoint.
    fn checkpoint(&self, seq: u64) -> Result<Option<CheckpointView>, AnchorError>;

    /// Raw leaves `from..to`, each with an inclusion proof against the
    /// latest checkpoint in its body when `with_proofs`.
    fn leaves(&self, from: u64, to: u64, with_proofs: bool) -> Result<Vec<LeafView>, AnchorError>;

    /// Re-verify every inclusion and consistency proof (for `verify-data`).
    fn verify(&self) -> Result<JsonValue, AnchorError>;

    /// The anchored length of every run the log knows (for restore's
    /// regression detection).
    fn anchored_lengths(&self) -> Result<HashMap<String, u64>, AnchorError>;

    /// Age of the oldest append not yet in a batch, for the metric.
    fn lag_seconds(&self) -> f64;
}

/// INTEGRATION STUB: anchors nothing. Runs never become anchored, so
/// `anchored_entries` stays 0 and nothing can regress. Replace with the
/// `pragmatic-anchor` library.
#[derive(Debug, Clone, Default)]
pub struct NoAnchoring {
    pub independent: bool,
}

impl Anchoring for NoAnchoring {
    fn independent(&self) -> bool {
        self.independent
    }

    fn anchor(
        &self,
        _host: &dyn AnchorHost,
        _input: BatchInput,
        _reason: BatchReason,
    ) -> Result<Option<BatchReceipt>, AnchorError> {
        Ok(None)
    }

    fn checkpoints(
        &self,
        _after: Option<u64>,
        _limit: usize,
    ) -> Result<Vec<CheckpointView>, AnchorError> {
        Ok(Vec::new())
    }

    fn checkpoint(&self, _seq: u64) -> Result<Option<CheckpointView>, AnchorError> {
        Ok(None)
    }

    fn leaves(
        &self,
        _from: u64,
        _to: u64,
        _with_proofs: bool,
    ) -> Result<Vec<LeafView>, AnchorError> {
        Ok(Vec::new())
    }

    fn verify(&self) -> Result<JsonValue, AnchorError> {
        Ok(serde_json::json!({"checked": 0, "note": "anchoring is not integrated in this build"}))
    }

    fn anchored_lengths(&self) -> Result<HashMap<String, u64>, AnchorError> {
        Ok(HashMap::new())
    }

    fn lag_seconds(&self) -> f64 {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Everything an evidence bundle is built from. Access control has already
/// happened: the requester may see this run, and `redact` was checked
/// against `view_raw` (a viewer without it never gets `none`).
pub struct EvidenceRequest<'a> {
    pub run_id: &'a str,
    /// The durable journal, read under the run's shared lock.
    pub journal: &'a Journal,
    pub journal_bytes: &'a [u8],
    /// The token id of the requester (`requested_by`).
    pub requested_by: &'a str,
    /// `none`, `detectors`, `binary` or `all`.
    pub redact: &'a str,
    pub redactor: &'a Redactor,
    pub anchoring: &'a dyn Anchoring,
    pub key: &'a ServerKey,
    pub independent: bool,
    /// `pragmatic-server <version>`.
    pub generator: &'a str,
}

/// A built bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub file_name: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Why a bundle could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The builder is not part of this build (501).
    NotImplemented,
    /// The request cannot be satisfied (400).
    BadRequest(String),
    /// Something failed (500).
    Internal(String),
}

/// Builds evidence bundles (design 5).
pub trait EvidenceBuilder: Send + Sync + 'static {
    fn build(&self, req: EvidenceRequest<'_>) -> Result<EvidenceBundle, EvidenceError>;
}

/// INTEGRATION STUB: answers 501 until the evidence module is integrated.
#[derive(Debug, Clone, Default)]
pub struct EvidenceStub;

impl EvidenceBuilder for EvidenceStub {
    fn build(&self, _req: EvidenceRequest<'_>) -> Result<EvidenceBundle, EvidenceError> {
        Err(EvidenceError::NotImplemented)
    }
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

/// Who is looking at a console page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleViewer {
    pub token_id: String,
    pub name: String,
    pub role: String,
    pub view_raw: bool,
    /// `[license] licensee`, for the footer.
    pub licensee: String,
}

/// The data of one console page. Every JSON value has the shape the API
/// serves for the same thing (RunSummary, Entry JSON, access-log records,
/// holds, tokens), already filtered by scope and redacted for the viewer.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsolePage<'a> {
    SignIn {
        error: Option<&'a str>,
        licensee: &'a str,
    },
    Runs {
        viewer: &'a ConsoleViewer,
        runs: &'a [JsonValue],
        next: Option<&'a str>,
        filters: &'a JsonValue,
    },
    Run {
        viewer: &'a ConsoleViewer,
        summary: &'a JsonValue,
        entries: &'a [JsonValue],
        next: Option<u64>,
        anchors: &'a [JsonValue],
    },
    AccessLog {
        viewer: &'a ConsoleViewer,
        records: &'a [JsonValue],
        next: Option<u64>,
    },
    Holds {
        viewer: &'a ConsoleViewer,
        holds: &'a [JsonValue],
        retention: &'a JsonValue,
    },
    Tokens {
        viewer: &'a ConsoleViewer,
        tokens: &'a [JsonValue],
    },
}

/// Why a page could not be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleError {
    /// The renderer is not part of this build (501).
    NotImplemented,
    Internal(String),
}

/// Renders console pages to HTML (design 4.14).
pub trait ConsoleRenderer: Send + Sync + 'static {
    fn render(&self, page: &ConsolePage<'_>) -> Result<String, ConsoleError>;
}

/// INTEGRATION STUB: answers 501 until the console renderer is integrated.
#[derive(Debug, Clone, Default)]
pub struct ConsoleStub;

impl ConsoleRenderer for ConsoleStub {
    fn render(&self, _page: &ConsolePage<'_>) -> Result<String, ConsoleError> {
        Err(ConsoleError::NotImplemented)
    }
}

// ---------------------------------------------------------------------------
// Testing
// ---------------------------------------------------------------------------

/// TEST ONLY: an anchoring that "anchors" every tip at once, independently,
/// and remembers the leaves in memory. It lets tests exercise everything
/// that depends on `anchored_entries` (regression detection, `missing`
/// runs, restore drills) without TSAs or witnesses.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct InstantAnchoring {
    state: std::sync::Mutex<InstantState>,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
struct InstantState {
    leaves: Vec<(Option<String>, u64)>,
    batches: Vec<(u64, usize, usize)>,
    anchored: HashMap<String, u64>,
}

#[cfg(any(test, feature = "testing"))]
impl Anchoring for InstantAnchoring {
    fn independent(&self) -> bool {
        true
    }

    fn anchor(
        &self,
        host: &dyn AnchorHost,
        input: BatchInput,
        _reason: BatchReason,
    ) -> Result<Option<BatchReceipt>, AnchorError> {
        if input.runs.is_empty() && input.access_log.is_none() {
            return Ok(None);
        }
        let mut s = self.state.lock().expect("anchoring state");
        let first = s.leaves.len();
        let mut placed = Vec::new();
        let mut anchored = Vec::new();
        if let Some(log) = &input.access_log {
            placed.push(LeafPlaced {
                run_id: None,
                entries: log.entries,
                leaf_index: s.leaves.len() as u64,
            });
            s.leaves.push((None, log.entries));
        }
        for tip in &input.runs {
            placed.push(LeafPlaced {
                run_id: Some(tip.run_id.clone()),
                entries: tip.entries,
                leaf_index: s.leaves.len() as u64,
            });
            s.leaves.push((Some(tip.run_id.clone()), tip.entries));
            s.anchored.insert(tip.run_id.clone(), tip.entries);
            anchored.push((tip.run_id.clone(), tip.entries));
        }
        let seq = s.batches.len() as u64;
        let end = s.leaves.len();
        s.batches.push((seq, first, end));
        drop(s);
        host.anchored(&anchored);
        Ok(Some(BatchReceipt {
            seq,
            tree_size: end as u64,
            leaves: placed,
        }))
    }

    fn checkpoints(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<CheckpointView>, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        Ok(s.batches
            .iter()
            .filter(|(seq, _, _)| after.is_none_or(|a| *seq > a))
            .take(limit)
            .map(|(seq, from, to)| view(&s, *seq, *from, *to))
            .collect())
    }

    fn checkpoint(&self, seq: u64) -> Result<Option<CheckpointView>, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        Ok(s.batches
            .iter()
            .find(|(q, _, _)| *q == seq)
            .map(|(seq, from, to)| view(&s, *seq, *from, *to)))
    }

    fn leaves(&self, from: u64, to: u64, _with_proofs: bool) -> Result<Vec<LeafView>, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        let to = (to as usize).min(s.leaves.len());
        Ok((from as usize..to).map(|i| leaf_view(&s, i)).collect())
    }

    fn verify(&self) -> Result<JsonValue, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        Ok(serde_json::json!({"checked": s.leaves.len(), "failures": 0}))
    }

    fn anchored_lengths(&self) -> Result<HashMap<String, u64>, AnchorError> {
        Ok(self.state.lock().expect("anchoring state").anchored.clone())
    }

    fn lag_seconds(&self) -> f64 {
        0.0
    }
}

#[cfg(any(test, feature = "testing"))]
fn leaf_view(s: &InstantState, i: usize) -> LeafView {
    let (run, entries) = &s.leaves[i];
    LeafView {
        index: i as u64,
        run_id: run.clone(),
        body: serde_json::json!({"index": i, "run_id": run, "entries": entries}),
    }
}

#[cfg(any(test, feature = "testing"))]
fn view(s: &InstantState, seq: u64, from: usize, to: usize) -> CheckpointView {
    CheckpointView {
        seq,
        body: serde_json::json!({"seq": seq, "tree_size": to, "independent": true}),
        leaves: (from..to).map(|i| leaf_view(s, i)).collect(),
    }
}
