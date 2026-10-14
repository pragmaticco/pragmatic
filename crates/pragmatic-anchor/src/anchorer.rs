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
//! - [`Anchorer::run_batch`] is called every interval, within 30 seconds
//!   of a successful `attempt.end`, and on `anchor=now`;
//!   [`Anchorer::retry_pending`] on a timer between batches. Both may be
//!   called from any thread. Anchoring never blocks journaling: nothing
//!   here takes a run lock.
//! - Commits never wait for the network. A batch's commit (snapshot,
//!   leaves, checkpoint) and the witness passes are serialized separately,
//!   so a batch commits at once even while another call's pass is waiting
//!   on a slow TSA; only that batch's own witnessing waits for the running
//!   pass to end. Each pass is bounded ([`RetryPolicy::max_pass_time`]).
//! - [`BatchOutcome::leaves`] lists the leaves committed (the server
//!   records `last_anchor_leaf` from it). [`BatchOutcome::advanced`] lists
//!   leaves whose checkpoint is independently anchored: the server sets
//!   `anchored_entries = max(anchored_entries, entries)` for each. Only
//!   then does a run's anchored length advance.
//! - Advancement is reported again after a restart. The witness results
//!   that make a checkpoint independent are durable before the server can
//!   record the advancement, so a crash in between would otherwise lose it
//!   for good (a finished run never changes again, and its anchoring lag
//!   would alert forever). The first pass after [`Anchorer::open`] (or
//!   after the log is reopened) therefore reports, in `advanced`, the
//!   newest independently anchored leaf of every id in the recovery window
//!   ([`RetryPolicy::max_backlog`] checkpoints). Applying `max` makes the
//!   repeat harmless.
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
//! Every configured external witness owes a result for every checkpoint.
//! In a pass, each witness works through the checkpoints it owes, oldest
//! first, on its own thread, so witnesses run in parallel and each one
//! sees the log's checkpoints in order. That order matters for a
//! `tlog-witness` cosigner: once it has cosigned a checkpoint it can never
//! cosign an older one, so a newer checkpoint is never offered to a
//! witness while it still owes an older one. A witness stops at its first
//! failure and backs off, exponentially, as a whole (never per
//! checkpoint), and is not asked about any checkpoint until its backoff
//! ends; each RFC 3161 retry uses a fresh nonce. A cosigner that reports
//! it has already cosigned past a checkpoint (it can happen after a
//! restart) no longer owes that one. A cosigner that reports a larger tree
//! than the log holds, or refuses a checkpoint as inconsistent with the
//! tree it cosigned (422), has seen checkpoints this log no longer has:
//! the log was restored from an old backup or rolled back, and each new
//! checkpoint up to that size would fork its signed history. That is
//! reported in [`BatchOutcome::forks`] for the caller to stop signing and
//! alert, never retried away.
//!
//! A checkpoint becomes independently anchored once the stored results
//! cover `min_independent_operators` distinct operators
//! ([`IndependencePolicy`]); its leaves are reported then, once. Witnesses
//! that still owe it keep being retried until they succeed: an auditor
//! counts only the witnesses they trust (design 5.2), so the more results
//! a checkpoint carries, the more auditors it satisfies. A checkpoint
//! leaves the retry queue when nothing is owed for it, and the queue holds
//! at most [`RetryPolicy::max_backlog`] checkpoints, dropping the oldest.
//! [`AnchorStatus::consecutive_short_batches`] counts batches in a row
//! that ended short of the policy, for the alert after 3 intervals.
//!
//! # A poisoned log
//!
//! If a write leaves the anchor log poisoned ([`AnchorLog::is_poisoned`]:
//! a checkpoint published but not known to be durable), no witness is
//! asked about anything until the next call reopens the log, whose
//! recovery settles what was committed; witnesses owed are then queued
//! again from what is stored.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};
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
use crate::tsa::{check_operator_anchors, TsaClient};
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
    /// How long a witness that failed is left alone before it is asked
    /// again, doubling with each failure in a row: 30 seconds. Backoff is
    /// per witness, never per checkpoint, so a witness is never offered a
    /// newer checkpoint while an older one it owes waits out a backoff.
    pub initial_backoff: Duration,
    /// The longest backoff: 1 hour.
    pub max_backoff: Duration,
    /// Checkpoints each witness is asked about per pass, oldest first: 32.
    /// Bounds how long one pass can take after an outage; the rest wait
    /// for the next pass.
    pub max_attempts_per_pass: usize,
    /// No witness starts an attempt after a pass has run this long: 5
    /// minutes. An attempt already running finishes (a TSA attempt is
    /// bounded by its own timeouts).
    pub max_pass_time: Duration,
    /// Checkpoints kept in the retry queue, and examined at startup
    /// (newest first) for witnesses still owed and for advancement to
    /// report again: 1024. Older ones are not retried.
    pub max_backlog: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            initial_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            max_attempts_per_pass: 32,
            max_pass_time: Duration::from_secs(300),
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

/// A leaf whose checkpoint is independently anchored: its journal's first
/// `entries` entries are.
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
    /// In checkpoint order, then configuration order.
    pub attempts: Vec<WitnessAttempt>,
    /// Checkpoints that became independently anchored in this pass.
    pub newly_independent: Vec<u64>,
    /// Leaves to advance `anchored_entries` to (with `max`): those of the
    /// checkpoints in `newly_independent`, and, in the first pass after an
    /// open, the newest independently anchored leaf of every id in the
    /// recovery window again (see the module documentation).
    pub advanced: Vec<Advanced>,
    /// Problems that did not stop the pass (an unreadable batch index, a
    /// witness result that could not be stored, a reopened log). Alert on
    /// them.
    pub errors: Vec<String>,
    /// Cosigners that report having cosigned a larger tree for this
    /// origin than the log holds. The log has forgotten checkpoints it
    /// signed (restored from an old backup, or rolled back), so every
    /// checkpoint it signs from here up to that size forks the history
    /// the cosigner vouches for. Stop signing and alert: this is never
    /// retried away.
    pub forks: Vec<String>,
}

/// Counters for metrics and alerts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorStatus {
    pub latest_seq: Option<u64>,
    pub tree_size: u64,
    pub latest_independent_seq: Option<u64>,
    /// Checkpoints some witness still owes a result, independent or not.
    pub pending: Vec<u64>,
    /// Of those, the ones not yet independently anchored.
    pub not_independent: Vec<u64>,
    /// Batches in a row whose checkpoint ended its first pass short of the
    /// independence policy. Alert at 3.
    pub consecutive_short_batches: u32,
    pub witness_failures_total: u64,
    pub batches_total: u64,
}

/// What the witnesses still owe for one checkpoint.
#[derive(Clone, Debug)]
struct Pending {
    /// Indexes of the witnesses that owe a result, ascending.
    owed: Vec<usize>,
    /// True once the checkpoint was found independent (and its leaves
    /// reported, or queued to be reported again after an open).
    independent: bool,
}

/// One witness's backoff: failures in a row, and when it may be asked
/// again.
#[derive(Clone, Copy, Debug)]
struct Backoff {
    failures: u32,
    next_at: Instant,
}

#[derive(Debug)]
struct State {
    /// Checkpoint seq to what it is still owed.
    pending: BTreeMap<u64, Pending>,
    /// Per witness, in configuration order.
    backoff: Vec<Backoff>,
    /// Independent checkpoints found at open whose leaves the next pass
    /// reports again.
    unreported: BTreeSet<u64>,
    latest_independent_seq: Option<u64>,
    consecutive_short: u32,
    witness_failures: u64,
    batches: u64,
}

impl State {
    /// An empty queue, and no witness backing off.
    fn new(witnesses: usize) -> State {
        let ready = Backoff {
            failures: 0,
            next_at: Instant::now(),
        };
        State {
            pending: BTreeMap::new(),
            backoff: vec![ready; witnesses],
            unreported: BTreeSet::new(),
            latest_independent_seq: None,
            consecutive_short: 0,
            witness_failures: 0,
            batches: 0,
        }
    }
}

/// How one witness attempt ended.
enum AttemptError {
    /// Worth retrying later.
    Failed(String),
    /// A cosigner has cosigned a newer checkpoint and can never cosign this
    /// one.
    Superseded,
    /// A cosigner has cosigned a larger tree for this origin than the log
    /// holds: the log forgot checkpoints it signed (see
    /// [`BatchOutcome::forks`]).
    Fork(String),
}

/// What one witness did in one pass.
#[derive(Default)]
struct WitnessRun {
    attempts: Vec<WitnessAttempt>,
    errors: Vec<String>,
    forks: Vec<String>,
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
    /// Serializes commits (snapshot, leaves, checkpoint). Never held across
    /// a network call.
    commits: Mutex<()>,
    /// Serializes witness passes. Taken after `commits` when both are held.
    passes: Mutex<()>,
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
    /// for recent checkpoints that witnesses still owe.
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
    ///
    /// Fails if the signing key is for another origin than the log's, if
    /// two witnesses share a URL or key, or if TSAs of different operators
    /// share a trust anchor ([`check_operator_anchors`]).
    pub fn with_log(
        log: AnchorLog,
        signer: LogSigner,
        witnesses: Vec<ExternalWitness>,
        config: AnchorerConfig,
    ) -> Result<Anchorer, AnchorError> {
        check_setup(&log, &signer, &witnesses)?;
        let anchorer = Anchorer {
            cosigned_sizes: Mutex::new(vec![None; witnesses.len()]),
            state: Mutex::new(State::new(witnesses.len())),
            log: RwLock::new(log),
            signer,
            witnesses,
            config,
            commits: Mutex::new(()),
            passes: Mutex::new(()),
        };
        anchorer.recover_pending()?;
        Ok(anchorer)
    }

    /// Rebuild the retry queue from what is stored, for the newest
    /// checkpoints up to the backlog bound: every witness without a stored
    /// result for a checkpoint owes one, and every independent checkpoint's
    /// leaves are reported again by the next pass.
    fn recover_pending(&self) -> Result<(), AnchorError> {
        let log = self.read_log();
        let mut state = self.lock_state();
        state.pending.clear();
        state.unreported.clear();
        for meta in log
            .checkpoints()
            .iter()
            .rev()
            .take(self.config.retry.max_backlog)
        {
            let records = log.witnesses(meta.seq)?;
            let independent = self.is_independent(&records);
            if independent {
                state.latest_independent_seq = state.latest_independent_seq.max(Some(meta.seq));
                state.unreported.insert(meta.seq);
            }
            let done: HashSet<&str> = records.iter().map(|r| r.label.as_str()).collect();
            let owed: Vec<usize> = (0..self.witnesses.len())
                .filter(|&w| !done.contains(self.witnesses[w].label().as_str()))
                .collect();
            if !owed.is_empty() {
                state
                    .pending
                    .insert(meta.seq, Pending { owed, independent });
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

    /// The evidence anchor section of `id` as of checkpoint `through`
    /// ([`evidence::anchor_section_through`]).
    pub fn anchor_section_through(
        &self,
        leaf_type: LeafType,
        id: &str,
        through: Option<u64>,
    ) -> Result<AnchorSection, AnchorError> {
        evidence::anchor_section_through(
            &self.read_log(),
            &self.config.id_mode,
            &self.config.policy,
            leaf_type,
            id,
            through,
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
            not_independent: state
                .pending
                .iter()
                .filter(|(_, p)| !p.independent)
                .map(|(seq, _)| *seq)
                .collect(),
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

    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -----------------------------------------------------------------
    // Batches
    // -----------------------------------------------------------------

    /// Run one batch: commit the changed snapshots (if any are new), then a
    /// witness pass. See the module documentation. Returns without a
    /// checkpoint when nothing changed (pending witnesses are still
    /// retried).
    pub fn run_batch(&self, provider: &dyn SnapshotProvider) -> Result<BatchOutcome, AnchorError> {
        let mut outcome = BatchOutcome::default();
        let new_seq = self.commit(provider, &mut outcome)?;
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
        let mut outcome = BatchOutcome::default();
        let healed = if self.read_log().is_poisoned() {
            let _commit = self.commits.lock().unwrap_or_else(|e| e.into_inner());
            self.heal(&mut outcome)
        } else {
            Ok(())
        };
        if let Err(e) = healed {
            outcome
                .errors
                .push(format!("the anchor log could not be reopened: {e}"));
            return outcome;
        }
        self.witness_pass(None, &mut outcome);
        outcome
    }

    /// The commit half of a batch: snapshots, leaves, checkpoint, and the
    /// new checkpoint's place in the retry queue. Returns its seq, or
    /// `None` when nothing was new.
    fn commit(
        &self,
        provider: &dyn SnapshotProvider,
        outcome: &mut BatchOutcome,
    ) -> Result<Option<u64>, AnchorError> {
        let _commit = self.commits.lock().unwrap_or_else(|e| e.into_inner());
        self.heal(outcome)?;
        let snapshots = provider.changed().map_err(AnchorError::Provider)?;
        let new_leaves = self.prepare(snapshots, outcome)?;
        if new_leaves.is_empty() {
            return Ok(None);
        }
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
        self.queue_new_checkpoint(seq, outcome);
        Ok(Some(seq))
    }

    /// Every witness owes the new checkpoint `seq` a result. The queue
    /// keeps the newest `max_backlog` checkpoints; older ones leave it,
    /// with an error to alert on.
    fn queue_new_checkpoint(&self, seq: u64, outcome: &mut BatchOutcome) {
        let mut state = self.lock_state();
        state.batches += 1;
        state.pending.insert(
            seq,
            Pending {
                owed: (0..self.witnesses.len()).collect(),
                independent: false,
            },
        );
        while state.pending.len() > self.config.retry.max_backlog.max(1) {
            if let Some((dropped, _)) = state.pending.pop_first() {
                outcome.errors.push(format!(
                    "checkpoint {dropped} left the witness retry queue, which holds the newest \
                     {} checkpoints; its missing witness results will not be retried",
                    self.config.retry.max_backlog
                ));
            }
        }
    }

    /// If an earlier write poisoned the log, reopen it (running recovery)
    /// and rebuild the retry queue from what is stored. Called with
    /// `commits` held; waits for a running pass, since the queue it reads
    /// is replaced.
    fn heal(&self, outcome: &mut BatchOutcome) -> Result<(), AnchorError> {
        if !self.read_log().is_poisoned() {
            return Ok(());
        }
        let _pass = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        let report = self
            .log
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .reopen()?;
        self.recover_pending()?;
        outcome.errors.push(format!(
            "the anchor log was reopened after a failed write: {} checkpoints, next seq {}, \
             {} uncommitted bytes moved aside",
            report.checkpoints, report.next_seq, report.uncommitted_bytes
        ));
        Ok(())
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

    /// One witness pass: report advancement found at open, let every
    /// witness that is not backing off work through what it owes (in
    /// parallel, each oldest first), then settle every checkpoint touched.
    ///
    /// Problems land in `outcome.errors` rather than failing the pass: by
    /// now a batch may have committed, and its outcome must reach the
    /// server whatever happens to its witnesses.
    fn witness_pass(&self, new_seq: Option<u64>, outcome: &mut BatchOutcome) {
        let _pass = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        self.report_recovered(outcome);
        if self.read_log().is_poisoned() {
            outcome.errors.push(
                "no witness was asked: the anchor log is poisoned until it is reopened".into(),
            );
            return;
        }
        let plan = self.plan();
        let deadline = Instant::now() + self.config.retry.max_pass_time;
        let runs: Vec<WitnessRun> = std::thread::scope(|scope| {
            let handles: Vec<_> = plan
                .iter()
                .map(|(w, seqs)| scope.spawn(move || self.work(*w, seqs, deadline)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| WitnessRun {
                        errors: vec!["a witness thread panicked".into()],
                        ..WitnessRun::default()
                    })
                })
                .collect()
        });
        let mut attempts: Vec<(u64, usize, WitnessAttempt)> = Vec::new();
        for ((w, _), run) in plan.iter().zip(runs) {
            attempts.extend(run.attempts.into_iter().map(|a| (a.seq, *w, a)));
            outcome.errors.extend(run.errors);
            outcome.forks.extend(run.forks);
        }
        attempts.sort_by_key(|(seq, w, _)| (*seq, *w));
        let mut touched: BTreeSet<u64> = attempts.iter().map(|(seq, _, _)| *seq).collect();
        touched.extend(new_seq);
        outcome
            .attempts
            .extend(attempts.into_iter().map(|(_, _, a)| a));
        for seq in touched {
            if let Err(e) = self.settle(seq, outcome) {
                outcome
                    .errors
                    .push(format!("checking checkpoint {seq}'s witnesses: {e}"));
            }
        }
    }

    /// Per witness that is not backing off, the checkpoints it owes,
    /// oldest first, at most `max_attempts_per_pass`.
    fn plan(&self) -> Vec<(usize, Vec<u64>)> {
        let now = Instant::now();
        let state = self.lock_state();
        (0..self.witnesses.len())
            .filter(|&w| state.backoff[w].next_at <= now)
            .map(|w| {
                let owed: Vec<u64> = state
                    .pending
                    .iter()
                    .filter(|(_, p)| p.owed.contains(&w))
                    .map(|(seq, _)| *seq)
                    .take(self.config.retry.max_attempts_per_pass)
                    .collect();
                (w, owed)
            })
            .filter(|(_, owed)| !owed.is_empty())
            .collect()
    }

    /// One witness's share of a pass: the checkpoints `seqs`, in order,
    /// stopping at the first failure (so it never sees a newer checkpoint
    /// before an older one it owes) or at the deadline.
    fn work(&self, w: usize, seqs: &[u64], deadline: Instant) -> WitnessRun {
        let mut run = WitnessRun::default();
        for &seq in seqs {
            if Instant::now() >= deadline {
                break;
            }
            let stored = match self.read_log().checkpoint(seq) {
                Ok(stored) => stored,
                Err(e) => {
                    run.errors
                        .push(format!("reading checkpoint {seq} to witness it: {e}"));
                    break;
                }
            };
            let result = self.attempt(w, &stored);
            if !self.record_attempt(seq, w, result, &mut run) {
                break;
            }
        }
        run
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
                // tlog-witness answers 422 when a checkpoint is not
                // consistent with the tree it cosigned for this origin.
                // This log never signs a tree inconsistent with an earlier
                // one, so it has forgotten one it signed.
                Err(WitnessClientError::Status { status: 422, body }) => {
                    return Err(AttemptError::Fork(format!(
                        "the witness refuses checkpoint {} (size {size}) as inconsistent with \
                         the tree it cosigned for this origin from size {old}: {body}",
                        stored.seq
                    )))
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
    /// does not have (a log restored from an old backup, or a fork), which
    /// is fatal rather than worth a retry.
    fn newer_than(&self, theirs: u64) -> AttemptError {
        let ours = self.read_log().size();
        if theirs <= ours {
            AttemptError::Superseded
        } else {
            AttemptError::Fork(format!(
                "the witness has cosigned {theirs} leaves for this origin but the log holds {ours}: \
                 the log forgot checkpoints it signed (restored from an old backup, or rolled \
                 back), and signing on would fork it"
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

    /// Store one attempt's result and update the retry queue and the
    /// witness's backoff. Returns true if the witness may go on to its next
    /// checkpoint in this pass.
    fn record_attempt(
        &self,
        seq: u64,
        w: usize,
        result: Result<WitnessRecord, AttemptError>,
        run: &mut WitnessRun,
    ) -> bool {
        let witness = &self.witnesses[w];
        let mut attempt = WitnessAttempt {
            seq,
            witness: witness.label(),
            kind: witness.kind(),
            operator: witness.operator().to_string(),
            result: Ok(()),
        };
        let go_on = match result {
            Ok(record) => {
                let stored = self
                    .log
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .store_witness(&record);
                match stored {
                    Ok(_) => {
                        self.settled_owed(seq, w);
                        self.reset_backoff(w);
                        true
                    }
                    // A commit poisoned the log during this pass: not the
                    // witness's fault, so no backoff; the next call heals
                    // the log and the result is fetched again.
                    Err(e @ AnchorError::Poisoned) => {
                        attempt.result = Err(e.to_string());
                        false
                    }
                    Err(e) => {
                        run.errors.push(format!("storing a witness result: {e}"));
                        attempt.result = Err(e.to_string());
                        self.back_off(w);
                        false
                    }
                }
            }
            Err(AttemptError::Superseded) => {
                attempt.result =
                    Err("superseded: the witness has cosigned a newer checkpoint".into());
                self.settled_owed(seq, w);
                true
            }
            Err(AttemptError::Failed(why)) => {
                attempt.result = Err(why);
                self.back_off(w);
                false
            }
            Err(AttemptError::Fork(why)) => {
                run.forks.push(format!("{}: {why}", witness.label()));
                attempt.result = Err(why);
                self.back_off(w);
                false
            }
        };
        run.attempts.push(attempt);
        go_on
    }

    /// Witness `w` no longer owes checkpoint `seq`.
    fn settled_owed(&self, seq: u64, w: usize) {
        let mut state = self.lock_state();
        if let Some(p) = state.pending.get_mut(&seq) {
            p.owed.retain(|&o| o != w);
        }
    }

    fn back_off(&self, w: usize) {
        let retry = self.config.retry;
        let mut state = self.lock_state();
        state.witness_failures += 1;
        let b = &mut state.backoff[w];
        b.failures = b.failures.saturating_add(1);
        let factor = 1u32 << (b.failures - 1).min(16);
        let wait = retry
            .initial_backoff
            .saturating_mul(factor)
            .min(retry.max_backoff);
        b.next_at = Instant::now() + wait;
    }

    fn reset_backoff(&self, w: usize) {
        self.lock_state().backoff[w].failures = 0;
    }

    /// After a pass touched checkpoint `seq`: if its stored results now
    /// meet the policy for the first time, it is independent and its
    /// leaves advance; if nothing is owed any more, it leaves the queue.
    fn settle(&self, seq: u64, outcome: &mut BatchOutcome) -> Result<(), AnchorError> {
        let records = self.read_log().witnesses(seq)?;
        let independent = self.is_independent(&records);
        let mut state = self.lock_state();
        let Some(p) = state.pending.get_mut(&seq) else {
            return Ok(());
        };
        let newly = independent && !p.independent;
        p.independent |= independent;
        if p.owed.is_empty() {
            state.pending.remove(&seq);
        }
        if !newly {
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

    /// Report again the leaves of the independent checkpoints found at
    /// open: per id, its newest leaf among them.
    fn report_recovered(&self, outcome: &mut BatchOutcome) {
        let seqs = std::mem::take(&mut self.lock_state().unreported);
        let mut newest: BTreeMap<(LeafType, String), Advanced> = BTreeMap::new();
        for seq in seqs {
            match self.batch_leaves(seq) {
                Ok(leaves) => {
                    for a in leaves {
                        let key = (a.leaf_type, a.id.clone());
                        if newest.get(&key).is_none_or(|b| b.entries < a.entries) {
                            newest.insert(key, a);
                        }
                    }
                }
                Err(e) => outcome.errors.push(format!(
                    "checkpoint {seq} is anchored but its leaves cannot be listed: {e}"
                )),
            }
        }
        outcome.advanced.extend(newest.into_values());
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

/// Refuse a setup that cannot anchor honestly: a signing key for another
/// origin than the log's (the server must never sign for a log whose
/// checkpoints name another origin, design 4.7), two witnesses with one
/// URL or key (their results would share a label), or TSAs of different
/// operators sharing a trust anchor ([`check_operator_anchors`]).
fn check_setup(
    log: &AnchorLog,
    signer: &LogSigner,
    witnesses: &[ExternalWitness],
) -> Result<(), AnchorError> {
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
    let tsas: Vec<_> = witnesses
        .iter()
        .filter_map(|w| match w {
            ExternalWitness::Tsa(c) => Some(c.config()),
            ExternalWitness::Cosigner(_) => None,
        })
        .collect();
    check_operator_anchors(&tsas)
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
