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
//! `pragmatic-server serve` plugs in the integrated components
//! ([`crate::server::Hooks::integrated`]): [`crate::anchoring`] over the
//! anchoring library, [`crate::evidence`] over the core evidence module,
//! and [`crate::console_ui`] over `pragmatic-console`.
//!
//! Each hook also has a stub that is clearly not the real thing, for tests
//! and for embedding the server without a component: [`NoAnchoring`]
//! anchors nothing, [`EvidenceStub`] answers 501, and [`ConsoleStub`]
//! answers 501. Access control, redaction and the access log all happen
//! before a hook is called, so a component never has to repeat them. A
//! stub never claims what it does not do: [`NoAnchoring`] reports no
//! independent witness whatever the configuration names, and `/v1/info`
//! says which components are not integrated.

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
    /// The chain head after `entries` entries, as the signed leaf records
    /// it. At startup the access log is checked against this, not against
    /// `audit/anchor.json`, which is only a cache of it.
    pub head: Digest,
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
    /// A batch failed, or anchoring found a problem that did not stop it
    /// (webhook `anchor_failed`).
    Failed { reason: String },
    /// One witness attempt failed; it is retried with backoff (metric
    /// only: a witness that is down fails every pass, and the webhook
    /// fires once checkpoints stay short of the policy).
    WitnessFailed {
        seq: u64,
        witness: String,
        reason: String,
    },
    /// A witness has seen checkpoints this log no longer has (design
    /// 4.7): the log was restored from an old backup or rolled back, and
    /// signing on would fork it. Anchoring is held until an administrator
    /// re-establishes the log (`pragmatic-server confirm-anchors`); webhook
    /// `anchor_failed` with `fork: true`.
    Fork { reason: String },
    /// A snapshot contradicts a signed leaf: fewer entries than the
    /// object's latest leaf, or the same entries and another head (design
    /// 4.7). It was not anchored. The run (`None`: the access log) was
    /// rolled back or rewritten after it was anchored, so the server marks
    /// it `regressed` (the access log: `chain_broken`).
    Contradicted {
        run_id: Option<String>,
        /// The entries of the latest leaf the snapshot contradicts.
        anchored_entries: u64,
        reason: String,
    },
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
    /// True for an access-log leaf (a record count and a chain head, shown
    /// to every auditor); false for a run's leaf.
    pub access_log: bool,
    /// The run whose tip this is, when it is known (never for the access
    /// log). Used only to filter by scope: a run leaf whose run is unknown
    /// is shown to administrators only. Whether the id itself is shown is
    /// the library's choice (with `anchor_run_ids = "hmac"` it is not).
    pub run_id: Option<String>,
    pub body: JsonValue,
}

/// How one anchor of a run is witnessed, for the console.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorWitnessing {
    /// The stored witnesses meet `min_independent_operators`.
    pub independent: bool,
    /// The distinct operators of the stored witnesses.
    pub operators: Vec<String>,
    /// The earliest witness time (Unix seconds), from a signed structure.
    pub time: Option<u64>,
}

/// A run's anchors as an evidence bundle carries them (design 5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunAnchors {
    /// The run's key k_run under `anchor_run_ids = "hmac"`.
    pub anchor_id: Option<[u8; 32]>,
    /// The run's whole leaf chain, first leaf first.
    pub anchors: Vec<pragmatic::evidence::Anchor>,
    /// For each anchor, how it is witnessed (not part of a bundle: a
    /// verifier decides from its own pins).
    pub witnessing: Vec<AnchorWitnessing>,
    /// The log's latest checkpoint, which every consistency proof leads
    /// to.
    pub latest_checkpoint: Option<String>,
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
    /// False for a stand-in that anchors nothing ([`NoAnchoring`]).
    fn integrated(&self) -> bool {
        true
    }

    /// True when at least one independent witness is configured and in
    /// use. Bundles say `"independent": false` otherwise.
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

    /// The last leaf of every object in the log: each run's (by id) and
    /// the access log's (`run_id: None`). At startup the server raises each
    /// run's last leaf to this: the log is durable before `meta.json`
    /// records a leaf, and a run whose meta lost its last leaf would be
    /// anchored again with a `prev_leaf` that skips it, a fork in its leaf
    /// chain.
    fn last_leaves(&self) -> Result<Vec<LeafPlaced>, AnchorError>;

    /// Retry the witnesses that still owe results, between batches. Runs
    /// whose checkpoints become independently anchored are reported to
    /// `host`, as after a batch.
    fn retry(&self, _host: &dyn AnchorHost) {}

    /// The sequence number of the latest checkpoint, if any. An evidence
    /// request notes it before reading the journal and builds the bundle's
    /// anchors through it ([`Anchoring::run_anchors_through`]).
    fn latest_seq(&self) -> Option<u64> {
        None
    }

    /// The run's anchors for an evidence bundle: its whole leaf chain with
    /// proofs, checkpoints and witnesses, as of the latest checkpoint.
    /// Empty for a run never anchored.
    fn run_anchors(&self, run_id: &str) -> Result<RunAnchors, AnchorError> {
        self.run_anchors_through(run_id, self.latest_seq())
    }

    /// The run's anchors as of checkpoint `through`: the leaves inside that
    /// checkpoint's tree, each proven consistent with it, and it as the
    /// latest checkpoint. `None` gives no anchors.
    fn run_anchors_through(
        &self,
        _run_id: &str,
        _through: Option<u64>,
    ) -> Result<RunAnchors, AnchorError> {
        Ok(RunAnchors::default())
    }

    /// True when the log holds a leaf of this run. The server never starts
    /// a fresh record under an id the log has anchored: that history was
    /// lost, not never written (design 4.8).
    fn has_leaf(&self, _run_id: &str) -> Result<bool, AnchorError> {
        Ok(false)
    }

    /// Why anchoring is held (no checkpoint is signed), if it is: the log
    /// was restored from a backup, or a witness has seen checkpoints the
    /// log no longer has (design 4.7, 4.13).
    fn held(&self) -> Option<String> {
        None
    }
}

/// INTEGRATION STUB: anchors nothing. Runs never become anchored, so
/// `anchored_entries` stays 0, nothing can regress, and nothing is
/// independently witnessed, whatever the configuration names: `/v1/info`
/// reports `independent_witness: false` and `anchoring: "not_integrated"`,
/// and the anchoring lag grows from the first append. Replace with the
/// `pragmatic-anchor` library.
#[derive(Debug, Clone, Default)]
pub struct NoAnchoring;

impl Anchoring for NoAnchoring {
    fn integrated(&self) -> bool {
        false
    }

    fn independent(&self) -> bool {
        false
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

    fn last_leaves(&self) -> Result<Vec<LeafPlaced>, AnchorError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Everything an evidence bundle is built from. Access control has already
/// happened: the requester may see this run, and `redact` was checked
/// against `view_raw` (a viewer without it only gets `detectors` or `all`).
pub struct EvidenceRequest<'a> {
    pub run_id: &'a str,
    /// The durable journal, read under the run's shared lock.
    pub journal: &'a Journal,
    pub journal_bytes: &'a [u8],
    /// The latest checkpoint when the journal was read (noted before the
    /// read). The bundle's anchors run through it, and it is the bundle's
    /// `latest_checkpoint` (design 4.17).
    pub anchors_through: Option<u64>,
    /// The token id of the requester (`requested_by`).
    pub requested_by: &'a str,
    /// `none`, `detectors`, `binary` or `all`.
    pub redact: &'a str,
    pub redactor: &'a Redactor,
    pub anchoring: &'a dyn Anchoring,
    pub key: &'a ServerKey,
    /// At least one external witness is configured. The bundle claims
    /// `independent` only when this holds and one of its anchors is
    /// independently witnessed.
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
    /// False for a stand-in that builds nothing ([`EvidenceStub`]): the
    /// server then answers 501 before reading the journal.
    fn integrated(&self) -> bool {
        true
    }

    fn build(&self, req: EvidenceRequest<'_>) -> Result<EvidenceBundle, EvidenceError>;
}

/// INTEGRATION STUB: answers 501 until the evidence module is integrated.
#[derive(Debug, Clone, Default)]
pub struct EvidenceStub;

impl EvidenceBuilder for EvidenceStub {
    fn integrated(&self) -> bool {
        false
    }

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
    /// The session's CSRF token, which every form that changes something
    /// carries.
    pub csrf: String,
}

/// A sentence at the top of a console page after a form: fixed text of
/// the server's, never text from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleNotice {
    pub text: String,
    /// An error code to show after the text, in mono, for a refusal the
    /// server has no sentence for (a short lowercase code, checked).
    pub code: Option<String>,
    /// A refusal (terracotta), rather than news (ink).
    pub refused: bool,
}

/// One slot an erasure would erase, for its confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasePreviewSlot {
    pub cursor: u64,
    pub slot: u8,
    /// `result of tool call lookup_order`.
    pub what: String,
    pub bytes: u64,
}

/// What a confirmation page asks about. Each carries the form fields the
/// confirming post repeats (with `confirm=1` and the CSRF token).
#[derive(Debug, Clone, PartialEq)]
pub enum ConsoleConfirm {
    Erase {
        run_id: String,
        /// The slots it would erase (at most 50 listed) and how many in all.
        slots: Vec<ErasePreviewSlot>,
        total: usize,
        reason_code: String,
        reason: String,
        force: bool,
        allow_unfinished: bool,
        fields: Vec<(String, String)>,
    },
    RemoveHold {
        hold: JsonValue,
    },
    RevokeToken {
        token: JsonValue,
    },
    RunRetention {
        policies: JsonValue,
    },
}

/// The data of one console page, already filtered by scope for the viewer.
/// List pages carry the JSON the API serves for the same thing
/// (RunSummary, access-log records with personal fields withheld, holds,
/// tokens); the run page carries the durable journal, which the renderer
/// shows through `redactor` when the viewer may not see content raw.
#[derive(Clone)]
pub enum ConsolePage<'a> {
    SignIn {
        error: Option<&'a str>,
        /// "You are signed out", "Your session has ended".
        notice: Option<&'a str>,
        licensee: &'a str,
        /// The sign-in form's anti-forgery value (its cookie's value).
        csrf: &'a str,
    },
    Runs {
        viewer: &'a ConsoleViewer,
        runs: &'a [JsonValue],
        next: Option<&'a str>,
        filters: &'a JsonValue,
    },
    Run {
        viewer: &'a ConsoleViewer,
        run_id: &'a str,
        summary: &'a JsonValue,
        journal: &'a Journal,
        report: &'a pragmatic::VerifyReport,
        anchor: Option<&'a pragmatic_console::AnchorStatus>,
        /// The first cursor of the timeline page.
        from: u64,
        /// Set when the viewer may not see content raw.
        redactor: Option<&'a Redactor>,
        notice: Option<&'a ConsoleNotice>,
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
        notice: Option<&'a ConsoleNotice>,
    },
    Tokens {
        viewer: &'a ConsoleViewer,
        tokens: &'a [JsonValue],
        /// A token just issued: its value (shown this once) and record.
        issued: Option<(&'a str, &'a JsonValue)>,
        notice: Option<&'a ConsoleNotice>,
    },
    /// An action that cannot be undone, or that opens the door to one: the
    /// first post shows this page, and only its confirming post acts.
    Confirm {
        viewer: &'a ConsoleViewer,
        /// Where the form posts again.
        action: &'a str,
        /// Where "Cancel" goes.
        back: &'a str,
        confirm: &'a ConsoleConfirm,
    },
    /// A console request that failed, as a page.
    Error {
        /// The signed-in viewer, if any.
        viewer: Option<&'a ConsoleViewer>,
        licensee: &'a str,
        status: u16,
        /// The API's error code (`not_found`, `forbidden`, ...).
        code: &'a str,
        /// The run the request named, if any.
        run_id: Option<&'a str>,
        /// The request posted a form (a refusal is then about the form).
        form: bool,
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
    /// False for a stand-in that renders nothing ([`ConsoleStub`]).
    fn integrated(&self) -> bool {
        true
    }

    fn render(&self, page: &ConsolePage<'_>) -> Result<String, ConsoleError>;
}

/// INTEGRATION STUB: answers 501 until the console renderer is integrated.
#[derive(Debug, Clone, Default)]
pub struct ConsoleStub;

impl ConsoleRenderer for ConsoleStub {
    fn integrated(&self) -> bool {
        false
    }

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
    leaves: Vec<(Option<String>, u64, Digest)>,
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
                head: log.head,
            });
            s.leaves.push((None, log.entries, log.head));
        }
        for tip in &input.runs {
            placed.push(LeafPlaced {
                run_id: Some(tip.run_id.clone()),
                entries: tip.entries,
                leaf_index: s.leaves.len() as u64,
                head: tip.head,
            });
            s.leaves
                .push((Some(tip.run_id.clone()), tip.entries, tip.head));
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

    fn last_leaves(&self) -> Result<Vec<LeafPlaced>, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        let mut last: HashMap<Option<String>, LeafPlaced> = HashMap::new();
        for (i, (run_id, entries, head)) in s.leaves.iter().enumerate() {
            last.insert(
                run_id.clone(),
                LeafPlaced {
                    run_id: run_id.clone(),
                    entries: *entries,
                    leaf_index: i as u64,
                    head: *head,
                },
            );
        }
        Ok(last.into_values().collect())
    }

    fn latest_seq(&self) -> Option<u64> {
        let s = self.state.lock().expect("anchoring state");
        s.batches.last().map(|(seq, _, _)| *seq)
    }

    fn has_leaf(&self, run_id: &str) -> Result<bool, AnchorError> {
        let s = self.state.lock().expect("anchoring state");
        Ok(s.leaves
            .iter()
            .any(|(id, _, _)| id.as_deref() == Some(run_id)))
    }
}

#[cfg(any(test, feature = "testing"))]
fn leaf_view(s: &InstantState, i: usize) -> LeafView {
    let (run, entries, _) = &s.leaves[i];
    LeafView {
        index: i as u64,
        access_log: run.is_none(),
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
