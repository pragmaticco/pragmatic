//! One anchoring batch end to end (design 4.7): snapshot the changed runs,
//! append their leaves, sign and store the checkpoint, collect witnesses,
//! retry the ones that failed, and report which runs are now
//! independently anchored further than before.
//!
//! # Contract with the server
//!
//! - The server implements [`SnapshotProvider`]: for every run (and the
//!   access log) that changed since its last leaf, the fsynced
//!   `(entries, head)` read under that run's lock. Runs created by `PUT`
//!   are included even with zero entries.
//! - [`Anchorer::run_batch`] is called by one anchoring task, every
//!   interval, within 30 seconds of a successful `attempt.end`, and on
//!   `anchor=now`. Batches are serialized internally. Anchoring never
//!   blocks journaling: nothing here takes a run lock, and network calls
//!   happen with no lock on the anchor log held.
//! - [`BatchOutcome::leaves`] lists the leaves committed (the server
//!   records `last_anchor_leaf` from it). [`BatchOutcome::advanced`] lists
//!   leaves whose checkpoint just became independently anchored: the
//!   server sets `anchored_entries = max(anchored_entries, entries)` for
//!   each. Only then does a run's anchored length advance.
//! - Evidence and the anchors API read through [`Anchorer::log`] and
//!   [`Anchorer::anchor_section`] concurrently with a batch.
//!
//! # Snapshots that are not anchored
//!
//! A snapshot equal to its id's latest leaf is skipped as unchanged. A
//! snapshot with fewer entries than its latest leaf, or the same entries
//! and another head, contradicts a signed leaf: the journal was rolled back
//! or rewritten. It is never anchored (that would put the rewrite under a
//! signature) and is reported as [`SkipReason::Regressed`] or
//! [`SkipReason::HeadMismatch`], for the server to mark the run
//! `regressed` and alert. Two snapshots for one id abort the whole batch
//! ([`AnchorError::DuplicateId`]).
//!
//! # Witnesses and retries
//!
//! A new checkpoint is offered to every configured external witness at
//! once, one thread per witness. A witness that fails is retried against
//! the *same* checkpoint on later passes (each RFC 3161 retry with a fresh
//! nonce), with exponential backoff. Older checkpoints are retried in
//! ascending order before the new one, so a `tlog-witness` cosigner sees
//! the log's checkpoints in order; once a cosigner has cosigned a newer
//! checkpoint it can never cosign an older one, and that retry is dropped
//! as superseded (TSAs can still cover it). A witness that fails during a
//! pass is not tried again in the same pass.
//!
//! A checkpoint becomes independently anchored once the stored results
//! cover `min_independent_operators` distinct operators
//! ([`IndependencePolicy`]). [`AnchorStatus::consecutive_short_batches`]
//! counts batches in a row that ended short of that, for the alert after 3
//! intervals.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use pragmatic::encoding::hex_encode;
use pragmatic::journal::MAX_RUN_ID_LEN;
use pragmatic::sha256::{sha256, Digest};

use crate::checkpoint::LogSigner;
use crate::error::AnchorError;
use crate::evidence::{self, AnchorSection};
use crate::fsutil::unix_secs;
use crate::leaf::{LeafType, RunIdMode};
use crate::log::{
    AnchorLog, NewLeaf, RecoveryReport, StoredCheckpoint, WitnessKind, WitnessRecord,
};
use crate::operator::IndependencePolicy;
use crate::tsa::TsaClient;
use crate::witness::{WitnessClient, WitnessClientError};

/// The fsynced state of one journal, read under its lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub leaf_type: LeafType,
    /// The plain id: the run id for a run.
    pub id: String,
    pub entries: u64,
    /// The chain head after `entries` entries (the genesis value for an
    /// empty journal).
    pub head: Digest,
}

/// Where a batch's snapshots come from. See the module documentation.
pub trait SnapshotProvider {
    /// Every run, and the access log, that changed since its last leaf.
    fn changed(&self) -> Result<Vec<Snapshot>, String>;
}

impl<F: Fn() -> Result<Vec<Snapshot>, String>> SnapshotProvider for F {
    fn changed(&self) -> Result<Vec<Snapshot>, String> {
        self()
    }
}

/// An external witness: a TSA or a `tlog-witness` cosigner.
#[derive(Debug)]
pub enum ExternalWitness {
    Tsa(TsaClient),
    Cosigner(WitnessClient),
}

impl ExternalWitness {
    pub fn kind(&self) -> WitnessKind {
        match self {
            ExternalWitness::Tsa(_) => WitnessKind::Rfc3161,
            ExternalWitness::Cosigner(_) => WitnessKind::Cosignature,
        }
    }

    /// The canonical operator.
    pub fn operator(&self) -> &str {
        match self {
            ExternalWitness::Tsa(c) => &c.config().operator,
            ExternalWitness::Cosigner(c) => &c.config().operator,
        }
    }

    pub fn url(&self) -> &str {
        match self {
            ExternalWitness::Tsa(c) => &c.config().url,
            ExternalWitness::Cosigner(c) => &c.config().url,
        }
    }

    /// A stable, file-name-safe label: `tsa-<8 hex of SHA-256(url)>` or
    /// `witness-<key id>`. Results are stored under it, so reordering the
    /// configuration does not confuse old results with new witnesses.
    pub fn label(&self) -> String {
        match self {
            ExternalWitness::Tsa(c) => {
                format!(
                    "tsa-{}",
                    hex_encode(&sha256(c.config().url.as_bytes())[..4])
                )
            }
            ExternalWitness::Cosigner(c) => {
                format!("witness-{}", hex_encode(&c.config().key.key_id()))
            }
        }
    }
}

/// Backoff and bounds for witness retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Wait before the first retry, doubling after: 30 seconds.
    pub initial_backoff: Duration,
    /// The longest wait between retries: 1 hour.
    pub max_backoff: Duration,
    /// Retries of older checkpoints per pass (the new checkpoint is always
    /// tried): 32. Bounds how long one pass can take after an outage.
    pub max_retries_per_pass: usize,
    /// Checkpoints examined for pending witnesses at startup, newest first:
    /// 1024. Older ones are not retried.
    pub max_backlog: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            initial_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            max_retries_per_pass: 32,
            max_backlog: 1024,
        }
    }
}

/// How the anchorer is configured.
#[derive(Clone, Debug, Default)]
pub struct AnchorerConfig {
    pub id_mode: RunIdMode,
    pub policy: IndependencePolicy,
    pub retry: RetryPolicy,
}

/// Why a snapshot was not anchored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Same entries and head as its latest leaf.
    Unchanged,
    /// Fewer entries than its latest leaf (`anchored` there).
    Regressed { anchored: u64 },
    /// The latest leaf has the same entry count and another head: the
    /// anchored history was rewritten.
    HeadMismatch,
    /// The id is empty, too long, or not a valid run id.
    InvalidId,
}

/// A snapshot that was not anchored, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedRun {
    pub leaf_type: LeafType,
    pub id: String,
    pub reason: SkipReason,
}

/// A leaf committed in this batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchoredLeaf {
    pub seq: u64,
    pub leaf_index: u64,
    pub leaf_type: LeafType,
    pub id: String,
    pub entries: u64,
    pub head: Digest,
}

/// A leaf whose checkpoint became independently anchored: its journal's
/// first `entries` entries now are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advanced {
    pub seq: u64,
    pub leaf_index: u64,
    pub leaf_type: LeafType,
    pub id: String,
    pub entries: u64,
    pub head: Digest,
}

/// One witness attempt on one checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessAttempt {
    pub seq: u64,
    pub witness: String,
    pub kind: WitnessKind,
    pub operator: String,
    /// `Ok(())` once verified and stored.
    pub result: Result<(), String>,
}

/// What a batch (or a retry pass) did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    /// The checkpoint committed by this batch, if any leaves were new.
    pub committed: Option<StoredCheckpoint>,
    pub leaves: Vec<AnchoredLeaf>,
    pub skipped: Vec<SkippedRun>,
    pub attempts: Vec<WitnessAttempt>,
    /// Checkpoints that became independently anchored in this pass.
    pub newly_independent: Vec<u64>,
    pub advanced: Vec<Advanced>,
    /// Problems that did not stop the pass (an unreadable batch index, a
    /// witness result that could not be stored). Alert on them.
    pub errors: Vec<String>,
}

/// Counters for metrics and alerts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorStatus {
    pub latest_seq: Option<u64>,
    pub tree_size: u64,
    pub latest_independent_seq: Option<u64>,
    /// Checkpoints still waiting for witnesses.
    pub pending: Vec<u64>,
    /// Batches in a row whose checkpoint ended its first pass short of the
    /// independence policy. Alert at 3.
    pub consecutive_short_batches: u32,
    pub witness_failures_total: u64,
    pub batches_total: u64,
}

/// A witness owed for one checkpoint.
#[derive(Clone, Debug)]
struct PendingWitness {
    witness: usize,
    attempts: u32,
    next_at: Instant,
}

#[derive(Debug, Default)]
struct State {
    /// Checkpoint seq to the witnesses it still needs.
    pending: BTreeMap<u64, Vec<PendingWitness>>,
    latest_independent_seq: Option<u64>,
    consecutive_short: u32,
    witness_failures: u64,
    batches: u64,
}

/// How one witness attempt ended.
enum AttemptError {
    /// Worth retrying later.
    Failed(String),
    /// A cosigner has cosigned a newer checkpoint and can never cosign this
    /// one.
    Superseded,
}

/// The anchoring engine. See the module documentation.
pub struct Anchorer {
    log: RwLock<AnchorLog>,
    signer: LogSigner,
    witnesses: Vec<ExternalWitness>,
    config: AnchorerConfig,
    state: Mutex<State>,
    /// The size each cosigner last cosigned for this log, as far as known.
    cosigned_sizes: Mutex<Vec<Option<u64>>>,
    batch: Mutex<()>,
}

impl std::fmt::Debug for Anchorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anchorer")
            .field("origin", &self.signer.origin())
            .field("witnesses", &self.witnesses)
            .finish()
    }
}

impl Anchorer {
    /// Open the anchor log in `anchors_dir`, recover it, and queue retries
    /// for recent checkpoints that are not yet independently anchored.
    pub fn open(
        anchors_dir: impl AsRef<Path>,
        signer: LogSigner,
        witnesses: Vec<ExternalWitness>,
        config: AnchorerConfig,
    ) -> Result<(Anchorer, RecoveryReport), AnchorError> {
        let (log, report) = AnchorLog::open(anchors_dir)?;
        Anchorer::with_log(log, signer, witnesses, config).map(|a| (a, report))
    }

    /// [`Anchorer::open`] over an already opened log.
    pub fn with_log(
        log: AnchorLog,
        signer: LogSigner,
        witnesses: Vec<ExternalWitness>,
        config: AnchorerConfig,
    ) -> Result<Anchorer, AnchorError> {
        if let Some(latest) = log.latest_checkpoint() {
            let stored = log.checkpoint(latest.seq)?;
            if stored.signed.checkpoint.origin != signer.origin() {
                return Err(AnchorError::Key(format!(
                    "the log's origin is {:?} but the signing key is for {:?}",
                    stored.signed.checkpoint.origin,
                    signer.origin()
                )));
            }
        }
        let labels: Vec<String> = witnesses.iter().map(ExternalWitness::label).collect();
        if labels.iter().collect::<HashSet<_>>().len() != labels.len() {
            return Err(AnchorError::Key("two witnesses share a URL or key".into()));
        }
        let anchorer = Anchorer {
            cosigned_sizes: Mutex::new(vec![None; witnesses.len()]),
            log: RwLock::new(log),
            signer,
            witnesses,
            config,
            state: Mutex::new(State::default()),
            batch: Mutex::new(()),
        };
        anchorer.recover_pending()?;
        Ok(anchorer)
    }

    /// Queue the witnesses owed by recent checkpoints, newest first, up to
    /// the backlog bound.
    fn recover_pending(&self) -> Result<(), AnchorError> {
        let log = self.read_log();
        let mut state = self.lock_state();
        let now = Instant::now();
        for meta in log
            .checkpoints()
            .iter()
            .rev()
            .take(self.config.retry.max_backlog)
        {
            let records = log.witnesses(meta.seq)?;
            if self.is_independent(&records) {
                state.latest_independent_seq = state.latest_independent_seq.max(Some(meta.seq));
                continue;
            }
            let done: HashSet<&str> = records.iter().map(|r| r.label.as_str()).collect();
            let owed: Vec<PendingWitness> = self
                .witnesses
                .iter()
                .enumerate()
                .filter(|(_, w)| !done.contains(w.label().as_str()))
                .map(|(i, _)| PendingWitness {
                    witness: i,
                    attempts: 0,
                    next_at: now,
                })
                .collect();
            if !owed.is_empty() {
                state.pending.insert(meta.seq, owed);
            }
        }
        Ok(())
    }

    /// The anchor log, for the anchors API and evidence. Hold the guard
    /// briefly: a batch waits for it to append.
    pub fn log(&self) -> RwLockReadGuard<'_, AnchorLog> {
        self.read_log()
    }

    pub fn signer(&self) -> &LogSigner {
        &self.signer
    }

    pub fn witnesses(&self) -> &[ExternalWitness] {
        &self.witnesses
    }

    pub fn config(&self) -> &AnchorerConfig {
        &self.config
    }

    /// The evidence anchor section of `id` (design 5.1).
    pub fn anchor_section(
        &self,
        leaf_type: LeafType,
        id: &str,
    ) -> Result<AnchorSection, AnchorError> {
        evidence::anchor_section(
            &self.read_log(),
            &self.config.id_mode,
            &self.config.policy,
            leaf_type,
            id,
        )
    }

    /// Counters for `/metrics` and alerts.
    pub fn status(&self) -> AnchorStatus {
        let log = self.read_log();
        let state = self.lock_state();
        AnchorStatus {
            latest_seq: log.latest_checkpoint().map(|c| c.seq),
            tree_size: log.size(),
            latest_independent_seq: state.latest_independent_seq,
            pending: state.pending.keys().copied().collect(),
            consecutive_short_batches: state.consecutive_short,
            witness_failures_total: state.witness_failures,
            batches_total: state.batches,
        }
    }

    /// True if checkpoint `seq` is independently anchored by its stored
    /// witness results.
    pub fn checkpoint_is_independent(&self, seq: u64) -> Result<bool, AnchorError> {
        let records = self.read_log().witnesses(seq)?;
        Ok(self.is_independent(&records))
    }

    fn is_independent(&self, records: &[WitnessRecord]) -> bool {
        self.config
            .policy
            .is_independent(records.iter().map(|r| r.operator.as_str()))
    }

    fn read_log(&self) -> RwLockReadGuard<'_, AnchorLog> {
        self.log.read().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -----------------------------------------------------------------
    // Batches
    // -----------------------------------------------------------------

    /// Run one batch: see the module documentation. Returns without a
    /// checkpoint when nothing changed (pending witnesses are still
    /// retried).
    pub fn run_batch(&self, provider: &dyn SnapshotProvider) -> Result<BatchOutcome, AnchorError> {
        let _batch = self.batch.lock().unwrap_or_else(|e| e.into_inner());
        let mut outcome = BatchOutcome::default();
        let snapshots = provider.changed().map_err(AnchorError::Provider)?;
        let new_leaves = self.prepare(snapshots, &mut outcome)?;
        let mut new_seq = None;
        if !new_leaves.is_empty() {
            let batch = {
                let mut log = self.log.write().unwrap_or_else(|e| e.into_inner());
                log.append_batch(new_leaves, &self.signer, unix_secs())?
            };
            let seq = batch.checkpoint.seq;
            outcome.leaves = batch
                .leaves
                .iter()
                .map(|c| AnchoredLeaf {
                    seq,
                    leaf_index: c.index,
                    leaf_type: c.leaf.leaf_type,
                    id: c.plain_id.clone(),
                    entries: c.leaf.entries,
                    head: c.leaf.head,
                })
                .collect();
            outcome.committed = Some(batch.checkpoint);
            new_seq = Some(seq);
            let mut state = self.lock_state();
            state.batches += 1;
            let now = Instant::now();
            let owed: Vec<PendingWitness> = (0..self.witnesses.len())
                .map(|i| PendingWitness {
                    witness: i,
                    attempts: 0,
                    next_at: now,
                })
                .collect();
            state.pending.insert(seq, owed);
        }
        self.witness_pass(new_seq, &mut outcome);
        if let Some(seq) = new_seq {
            let mut state = self.lock_state();
            if outcome.newly_independent.contains(&seq) {
                state.consecutive_short = 0;
            } else {
                state.consecutive_short += 1;
            }
        }
        Ok(outcome)
    }

    /// Retry pending witnesses without starting a batch (for a timer
    /// between batches).
    pub fn retry_pending(&self) -> BatchOutcome {
        let _batch = self.batch.lock().unwrap_or_else(|e| e.into_inner());
        let mut outcome = BatchOutcome::default();
        self.witness_pass(None, &mut outcome);
        outcome
    }

    /// Turn snapshots into new leaves, skipping and reporting the ones that
    /// must not be anchored. Duplicate ids abort.
    fn prepare(
        &self,
        snapshots: Vec<Snapshot>,
        outcome: &mut BatchOutcome,
    ) -> Result<Vec<NewLeaf>, AnchorError> {
        let mut seen = HashSet::new();
        for s in &snapshots {
            if !seen.insert((s.leaf_type, s.id.as_str())) {
                return Err(AnchorError::DuplicateId {
                    leaf_type: s.leaf_type.byte(),
                    id_hex: hex_encode(s.id.as_bytes()),
                });
            }
        }
        let log = self.read_log();
        let mut out = Vec::new();
        for s in snapshots {
            let skip = |reason| SkippedRun {
                leaf_type: s.leaf_type,
                id: s.id.clone(),
                reason,
            };
            if !valid_plain_id(s.leaf_type, &s.id) {
                outcome.skipped.push(skip(SkipReason::InvalidId));
                continue;
            }
            let leaf_id = self.config.id_mode.leaf_id(s.leaf_type, &s.id);
            if let Some(latest) = log.latest_leaf(s.leaf_type, &leaf_id) {
                let reason = if s.entries < latest.entries {
                    Some(SkipReason::Regressed {
                        anchored: latest.entries,
                    })
                } else if s.entries == latest.entries && s.head != latest.head {
                    Some(SkipReason::HeadMismatch)
                } else if s.entries == latest.entries {
                    Some(SkipReason::Unchanged)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    outcome.skipped.push(skip(reason));
                    continue;
                }
            }
            out.push(NewLeaf {
                leaf_type: s.leaf_type,
                plain_id: s.id,
                leaf_id,
                entries: s.entries,
                head: s.head,
            });
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Witnessing
    // -----------------------------------------------------------------

    /// Try the witnesses that are due: older checkpoints first (bounded),
    /// then `new_seq`. Records results, independence and advancement in
    /// `outcome`.
    ///
    /// Problems land in `outcome.errors` rather than failing the pass: by
    /// now a batch may have committed, and its outcome must reach the
    /// server whatever happens to its witnesses.
    fn witness_pass(&self, new_seq: Option<u64>, outcome: &mut BatchOutcome) {
        let work = self.due_work(new_seq);
        let mut down: HashSet<usize> = HashSet::new();
        for (seq, due) in work {
            let due: Vec<usize> = due.into_iter().filter(|w| !down.contains(w)).collect();
            if !due.is_empty() {
                let stored = match self.read_log().checkpoint(seq) {
                    Ok(stored) => stored,
                    Err(e) => {
                        outcome
                            .errors
                            .push(format!("reading checkpoint {seq} to witness it: {e}"));
                        continue;
                    }
                };
                let results = self.attempt_all(&stored, &due);
                for (w, result) in results {
                    if self.record_attempt(seq, w, result, outcome) {
                        down.insert(w);
                    }
                }
            }
            if let Err(e) = self.settle(seq, outcome) {
                outcome
                    .errors
                    .push(format!("checking checkpoint {seq}'s witnesses: {e}"));
            }
        }
    }

    /// The `(seq, witnesses)` pairs due now, in ascending seq order, with at
    /// most `max_retries_per_pass` attempts on checkpoints other than
    /// `new_seq`.
    fn due_work(&self, new_seq: Option<u64>) -> Vec<(u64, Vec<usize>)> {
        let now = Instant::now();
        let state = self.lock_state();
        let mut budget = self.config.retry.max_retries_per_pass;
        let mut work = Vec::new();
        for (&seq, owed) in &state.pending {
            let mut due: Vec<usize> = owed
                .iter()
                .filter(|p| p.next_at <= now)
                .map(|p| p.witness)
                .collect();
            if Some(seq) != new_seq {
                due.truncate(budget);
                budget -= due.len();
            }
            if !due.is_empty() || Some(seq) == new_seq {
                work.push((seq, due));
            }
        }
        work
    }

    /// Attempt every witness in `due` on one checkpoint, in parallel.
    fn attempt_all(
        &self,
        stored: &StoredCheckpoint,
        due: &[usize],
    ) -> Vec<(usize, Result<WitnessRecord, AttemptError>)> {
        std::thread::scope(|scope| {
            let handles: Vec<_> = due
                .iter()
                .map(|&w| (w, scope.spawn(move || self.attempt(w, stored))))
                .collect();
            handles
                .into_iter()
                .map(|(w, h)| {
                    let r = h.join().unwrap_or_else(|_| {
                        Err(AttemptError::Failed("witness thread panicked".into()))
                    });
                    (w, r)
                })
                .collect()
        })
    }

    /// One witness on one checkpoint, ending in a verified record.
    fn attempt(&self, w: usize, stored: &StoredCheckpoint) -> Result<WitnessRecord, AttemptError> {
        let witness = &self.witnesses[w];
        let (time, object) = match witness {
            ExternalWitness::Tsa(client) => {
                let token = client
                    .timestamp(&stored.signed.anchor_digest)
                    .map_err(|e| AttemptError::Failed(e.to_string()))?;
                (token.gen_time_unix(), token.evidence_json())
            }
            ExternalWitness::Cosigner(client) => {
                let cosig = self.cosign(w, client, stored)?;
                (cosig.timestamp, cosig.evidence_json())
            }
        };
        Ok(WitnessRecord {
            seq: stored.seq,
            label: witness.label(),
            kind: witness.kind(),
            operator: witness.operator().to_string(),
            time,
            recorded_at: unix_secs(),
            object,
        })
    }

    /// Submit to a cosigner from the size it last cosigned, learning that
    /// size from a 409 when unknown (once per attempt).
    fn cosign(
        &self,
        w: usize,
        client: &WitnessClient,
        stored: &StoredCheckpoint,
    ) -> Result<crate::witness::Cosignature, AttemptError> {
        let size = stored.tree_size();
        let mut old = self.cosigned_size(w).unwrap_or(0);
        for _ in 0..2 {
            if old > size {
                return Err(self.newer_than(old));
            }
            let proof = if old == 0 {
                Vec::new()
            } else {
                self.read_log()
                    .consistency_proof(old, size)
                    .map_err(|e| AttemptError::Failed(e.to_string()))?
            };
            match client.add_checkpoint(old, &proof, &stored.signed.note) {
                Ok(c) => {
                    self.set_cosigned_size(w, size);
                    return Ok(c);
                }
                Err(WitnessClientError::Conflict { size: theirs }) if theirs != old => {
                    self.set_cosigned_size(w, theirs);
                    old = theirs;
                }
                Err(e) => return Err(AttemptError::Failed(e.to_string())),
            }
        }
        Err(AttemptError::Failed(
            "the witness kept answering 409 Conflict".into(),
        ))
    }

    /// A cosigner reports a size beyond this checkpoint: superseded if the
    /// log holds that size, otherwise the witness has seen a tree this log
    /// does not have (a fork, or a log restored from an old backup).
    fn newer_than(&self, theirs: u64) -> AttemptError {
        let ours = self.read_log().size();
        if theirs <= ours {
            AttemptError::Superseded
        } else {
            AttemptError::Failed(format!(
                "the witness has cosigned {theirs} leaves for this origin but the log holds {ours}: \
                 possible fork or rollback"
            ))
        }
    }

    fn cosigned_size(&self, w: usize) -> Option<u64> {
        self.cosigned_sizes
            .lock()
            .unwrap_or_else(|e| e.into_inner())[w]
    }

    fn set_cosigned_size(&self, w: usize, size: u64) {
        self.cosigned_sizes
            .lock()
            .unwrap_or_else(|e| e.into_inner())[w] = Some(size);
    }

    /// Store one attempt's result and update the retry queue. Returns true
    /// if the witness failed (and so is skipped for the rest of the pass).
    fn record_attempt(
        &self,
        seq: u64,
        w: usize,
        result: Result<WitnessRecord, AttemptError>,
        outcome: &mut BatchOutcome,
    ) -> bool {
        let witness = &self.witnesses[w];
        let mut attempt = WitnessAttempt {
            seq,
            witness: witness.label(),
            kind: witness.kind(),
            operator: witness.operator().to_string(),
            result: Ok(()),
        };
        let failed = match result {
            Ok(record) => {
                let stored = self
                    .log
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .store_witness(&record);
                match stored {
                    Ok(_) => {
                        self.forget_pending(seq, w);
                        false
                    }
                    Err(e) => {
                        outcome
                            .errors
                            .push(format!("storing a witness result: {e}"));
                        attempt.result = Err(e.to_string());
                        self.back_off(seq, w);
                        true
                    }
                }
            }
            Err(AttemptError::Superseded) => {
                attempt.result =
                    Err("superseded: the witness has cosigned a newer checkpoint".into());
                self.forget_pending(seq, w);
                false
            }
            Err(AttemptError::Failed(why)) => {
                attempt.result = Err(why);
                self.back_off(seq, w);
                true
            }
        };
        outcome.attempts.push(attempt);
        failed
    }

    fn forget_pending(&self, seq: u64, w: usize) {
        let mut state = self.lock_state();
        if let Some(owed) = state.pending.get_mut(&seq) {
            owed.retain(|p| p.witness != w);
        }
    }

    fn back_off(&self, seq: u64, w: usize) {
        let retry = self.config.retry;
        let mut state = self.lock_state();
        state.witness_failures += 1;
        if let Some(p) = state
            .pending
            .get_mut(&seq)
            .and_then(|owed| owed.iter_mut().find(|p| p.witness == w))
        {
            p.attempts += 1;
            let factor = 1u32 << (p.attempts - 1).min(16);
            let wait = retry
                .initial_backoff
                .saturating_mul(factor)
                .min(retry.max_backoff);
            p.next_at = Instant::now() + wait;
        }
    }

    /// After a checkpoint's attempts: if its stored results now meet the
    /// policy, it is independent and its leaves advance; if nothing is left
    /// to try, it leaves the queue.
    fn settle(&self, seq: u64, outcome: &mut BatchOutcome) -> Result<(), AnchorError> {
        let records = self.read_log().witnesses(seq)?;
        let independent = self.is_independent(&records);
        let mut state = self.lock_state();
        let owed_left = state.pending.get(&seq).is_some_and(|o| !o.is_empty());
        if !independent && owed_left {
            return Ok(());
        }
        // Only a checkpoint still in the queue can newly become independent
        // (each one enters the queue once).
        if state.pending.remove(&seq).is_none() {
            return Ok(());
        }
        if !independent {
            return Ok(());
        }
        state.latest_independent_seq = state.latest_independent_seq.max(Some(seq));
        drop(state);
        outcome.newly_independent.push(seq);
        match self.batch_leaves(seq) {
            Ok(advanced) => outcome.advanced.extend(advanced),
            Err(e) => outcome.errors.push(format!(
                "checkpoint {seq} is anchored but its leaves cannot be listed: {e}"
            )),
        }
        Ok(())
    }

    /// The leaves of batch `seq` with their plain ids.
    fn batch_leaves(&self, seq: u64) -> Result<Vec<Advanced>, AnchorError> {
        let log = self.read_log();
        let metas = log.checkpoints();
        let i = metas
            .binary_search_by_key(&seq, |c| c.seq)
            .map_err(|_| AnchorError::OutOfRange(format!("no checkpoint {seq}")))?;
        let from = if i == 0 { 0 } else { metas[i - 1].tree_size };
        let leaves = log.read_leaves(from, metas[i].tree_size)?;
        let index = log.batch_index(seq)?;
        if index.len() != leaves.len() {
            return Err(AnchorError::Corrupt(format!(
                "batch index {seq} lists {} leaves, the log holds {}",
                index.len(),
                leaves.len()
            )));
        }
        leaves
            .into_iter()
            .zip(index)
            .enumerate()
            .map(|(k, (leaf, entry))| {
                let leaf_index = from + k as u64;
                let expected = self.config.id_mode.leaf_id(entry.leaf_type, &entry.id);
                if entry.leaf_index != leaf_index
                    || entry.leaf_type != leaf.leaf_type
                    || expected != leaf.id
                {
                    return Err(AnchorError::Corrupt(format!(
                        "batch index {seq} does not match leaf {leaf_index}"
                    )));
                }
                Ok(Advanced {
                    seq,
                    leaf_index,
                    leaf_type: leaf.leaf_type,
                    id: entry.id,
                    entries: leaf.entries,
                    head: leaf.head,
                })
            })
            .collect()
    }
}

/// A plain id the anchor log accepts: a run id of 1 to 200 characters
/// from the run id alphabet (the reserved `pragmatic:` prefix is allowed,
/// for the server's own journals), or a non-empty access log id.
fn valid_plain_id(leaf_type: LeafType, id: &str) -> bool {
    match leaf_type {
        LeafType::Run => {
            !id.is_empty()
                && id.len() <= MAX_RUN_ID_LEN
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        }
        LeafType::AccessLog => !id.is_empty() && id.len() <= crate::leaf::MAX_ID_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ids() {
        assert!(valid_plain_id(LeafType::Run, "user.42"));
        assert!(valid_plain_id(LeafType::Run, crate::WITNESS_RUN_ID));
        assert!(!valid_plain_id(LeafType::Run, ""));
        assert!(!valid_plain_id(LeafType::Run, "a/b"));
        assert!(!valid_plain_id(LeafType::Run, &"a".repeat(201)));
        assert!(valid_plain_id(LeafType::AccessLog, "access"));
    }
}
