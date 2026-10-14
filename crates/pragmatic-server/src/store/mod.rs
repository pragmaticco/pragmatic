//! Runs on disk and in memory (design 4.2, 4.5 and 4.6).
//!
//! # Locks
//!
//! Every run has two locks:
//!
//! - `file`, a read-write lock on the journal file's identity. Readers of
//!   the journal, its entries and evidence hold it shared while they read;
//!   erasure and deletion, which replace or remove the file, hold it
//!   exclusively, and advance the run's file *generation* before they
//!   release it. Appends only extend the file, so they never need it
//!   exclusively. A journal download streams for as long as its client
//!   takes, so it does not hold the lock throughout: it takes it for each
//!   chunk it reads and stops (aborting the response) once the generation
//!   has moved, so no byte read after an erasure or deletion committed is
//!   ever served.
//! - `state`, a mutex over the run's index (entries, byte length, head),
//!   its lease and its writer's journal. Every change takes it: appends,
//!   leases, custody notes, erasure, retention, anchoring snapshots.
//!
//! The lock order is `file`, then `state`, then holds. The run map is
//! never held while waiting for a run's lock: lookups copy what they need
//! out of it and release it first. A run's `state` may be held while the
//! map is locked (creating or deleting a run), which cannot deadlock for
//! that reason.
//!
//! # The index
//!
//! The index (entries, byte length, head) is updated only after the
//! journal's fsync, under `state`, so it never runs ahead of the disk.
//! `meta.json` is rewritten at most once per second per run (and at clean
//! shutdown); lease changes, erasure and creation write it at once. At
//! startup a journal whose size equals `meta.byte_len` and whose last 32
//! bytes equal `meta.head` is trusted; anything else is parsed again.
//!
//! All of this is synchronous: the HTTP layer calls it from blocking tasks.

mod admin;
mod frames;
mod index;
mod read;
mod write;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use pragmatic::Journal;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::layout::{stem as layout_stem, Layout};
use crate::metrics::Metrics;
use crate::summary::Summary;
use crate::webhooks::{WebhookEvent, Webhooks};

pub use admin::{EraseContext, EraseOutcome, EraseParams, Selector};
pub use frames::{BudgetGuard, ByteBudget, ReadEntry, FULL_READ_BUDGET};
pub use index::IndexReport;
pub use read::{verify_json, Durable, DurableFile, EntryPage, ListQuery, RunPage};
pub use write::{AppendOk, AppendRequest, LeaseGrant};

/// How often `meta.json` may be rewritten for appends.
pub const META_INTERVAL: Duration = Duration::from_secs(1);

/// The run's previous leaf in the anchor log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafRef {
    pub index: u64,
    pub entries: u64,
}

/// A lease as `meta.json` stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// The lease id. A capability only together with the token that
    /// acquired it; the custody note records its hash.
    pub id: String,
    /// The client's holder id. `None` for a lease granted by PUT until the
    /// first POST lease from the same token names one.
    pub holder: Option<String>,
    pub token_id: String,
    pub granted_at: String,
    pub from_entries: u64,
    pub requests: u64,
    pub first_received: Option<u64>,
    pub last_received: Option<u64>,
    pub clock_skew: bool,
}

/// `runs/<hh>/<64hex>.meta.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub format: u32,
    pub run_id: String,
    pub created_at: String,
    /// The last client append (or creation). Retention ages count from it.
    pub updated_at: String,
    pub entries: u64,
    pub byte_len: u64,
    pub head: String,
    pub anchored_entries: u64,
    pub last_anchor_leaf: Option<LeafRef>,
    pub leases: Vec<LeaseRecord>,
    /// Holds that matched when the file was written (informational: holds
    /// are matched live).
    pub holds: Vec<String>,
    /// `active`, `idle`, `dangling`, `regressed` or `missing` when written.
    pub status: String,
    /// The token id that created the run.
    pub created_by: Option<String>,
    /// Fewer entries than were anchored; appends are refused until an admin
    /// accepts the regression.
    pub regressed: bool,
    /// When the oldest append not yet independently anchored was made
    /// (Unix seconds), for the anchoring lag (design 4.7).
    #[serde(default)]
    pub unanchored_since: Option<i64>,
    /// An administrator accepted this run's journal as its history after
    /// it contradicted its anchored leaf (`accept-regression`). The anchor
    /// log keeps refusing the contradicting snapshots until the run grows
    /// past its last leaf, so they are not reported again until a batch
    /// places a new leaf for the run.
    #[serde(default)]
    pub regression_accepted: bool,
    pub summary: Summary,
}

/// `runs/<hh>/<64hex>.tombstone.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub run_id: String,
    pub deleted_at: String,
    pub entries: u64,
    pub head: String,
    /// The retention rules that deleted the run.
    pub policy: serde_json::Value,
}

/// Why a lease ended, for answering its holder's next request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Released,
    Expired,
    Revoked,
    /// The lease came back with a restored backup and was ended by the
    /// restore.
    Restored,
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Released => "released",
            EndReason::Expired => "expired",
            EndReason::Revoked => "revoked",
            EndReason::Restored => "restored",
        }
    }
}

/// A live lease.
#[derive(Debug, Clone)]
pub struct Lease {
    pub record: LeaseRecord,
    /// On the server's monotonic clock.
    pub expires: Instant,
}

/// The run's journal as its writer holds it.
pub struct Writer {
    pub journal: Journal,
    pub file: File,
}

/// The cached result of verifying a run.
#[derive(Debug, Clone)]
pub struct VerifyCache {
    pub report: pragmatic::VerifyReport,
    /// Entries the report covers. Appends after it were validated frame by
    /// frame on the way in, so the report stays true for them.
    pub entries: u64,
    pub checked_at: String,
    /// Why the stored journal is damaged, when it is (the report is then
    /// never ok).
    pub damaged: Option<String>,
}

/// Everything mutable about a run.
pub struct RunState {
    pub meta: Meta,
    pub writer: Option<Writer>,
    pub lease: Option<Lease>,
    /// Recently ended leases (newest last).
    pub ended: VecDeque<(String, EndReason)>,
    /// The last renewal, lease grant or append, on the monotonic clock.
    pub last_activity: Instant,
    pub meta_written: Option<Instant>,
    /// The stored journal is damaged: reads serve the valid prefix and
    /// writes are refused.
    pub broken: Option<String>,
    /// The only damage is slots an erasure note lists that still hold
    /// content: erasing again repairs it, so erasure stays allowed.
    pub repairable: bool,
    /// The anchor log knows the run but neither a journal nor a tombstone
    /// exists.
    pub missing: bool,
    pub deleted: bool,
    pub verify: Option<VerifyCache>,
    pub dangling_alerted: bool,
}

/// One run.
pub struct Run {
    pub id: String,
    pub stem: String,
    pub file: RwLock<()>,
    pub state: Mutex<RunState>,
    /// Advanced, with `file` held exclusively, whenever the journal file is
    /// replaced (erasure) or removed (deletion): readers that hold an open
    /// descriptor or cached offsets of an earlier generation must not use
    /// them.
    generation: AtomicU64,
}

impl Run {
    pub fn new(id: &str, stem: &str, state: RunState) -> Run {
        Run {
            id: id.to_string(),
            stem: stem.to_string(),
            file: RwLock::new(()),
            state: Mutex::new(state),
            generation: AtomicU64::new(0),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, RunState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The journal file's generation (see the module documentation).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The journal file was replaced or removed. Call with `file` held
    /// exclusively.
    fn replaced(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

/// What the store needs to tell the rest of the server.
#[derive(Clone)]
pub struct Signals {
    pub metrics: Arc<Metrics>,
    pub webhooks: Webhooks,
    /// Set when an attempt ended ok, so a batch runs soon.
    pub anchor_soon: Arc<AnchorSoon>,
}

/// A wake-up for the anchoring scheduler.
#[derive(Debug, Default)]
pub struct AnchorSoon {
    pending: AtomicBool,
    notify: tokio::sync::Notify,
}

impl AnchorSoon {
    pub fn request(&self) {
        if !self.pending.swap(true, Ordering::SeqCst) {
            self.notify.notify_one();
        }
    }

    /// Wait for a request, then clear it.
    pub async fn wait(&self) {
        loop {
            if self.pending.swap(false, Ordering::SeqCst) {
                return;
            }
            self.notify.notified().await;
        }
    }
}

/// Settings the store needs from the configuration.
#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub lease_ttl: Duration,
    pub max_clock_skew: Duration,
    pub index_key: [u8; 32],
}

/// Every run.
pub struct Store {
    pub layout: Layout,
    runs: RwLock<BTreeMap<String, Arc<Run>>>,
    tombstones: RwLock<HashMap<String, Tombstone>>,
    dirty: Mutex<HashSet<String>>,
    frames: Mutex<frames::FrameCache>,
    /// Bytes of journals held whole by readers at once.
    budget: Arc<ByteBudget>,
    /// Stems (and `runs/<hh>` shard names) whose files could not be read
    /// at startup: their ids are never treated as absent.
    unavailable: Mutex<HashSet<String>>,
    /// Stems whose tombstone could not be read: their ids are deleted.
    deleted_stems: RwLock<HashSet<String>>,
    /// One late load at a time.
    late: Mutex<()>,
    opts: StoreOptions,
    signals: Signals,
}

impl Store {
    /// An empty store over `layout`; [`Store::index`] fills it.
    pub fn new(layout: Layout, opts: StoreOptions, signals: Signals) -> Store {
        Store {
            layout,
            runs: RwLock::new(BTreeMap::new()),
            tombstones: RwLock::new(HashMap::new()),
            dirty: Mutex::new(HashSet::new()),
            frames: Mutex::new(frames::FrameCache::default()),
            budget: Arc::new(ByteBudget::new(FULL_READ_BUDGET)),
            unavailable: Mutex::new(HashSet::new()),
            deleted_stems: RwLock::new(HashSet::new()),
            late: Mutex::new(()),
            opts,
            signals,
        }
    }

    /// True when the run with this stem could not be read at startup (its
    /// own files, or its whole shard).
    fn is_unavailable(&self, stem: &str) -> bool {
        let set = self.unavailable.lock().expect("unavailable lock");
        !set.is_empty() && (set.contains(stem) || set.contains(&stem[..2]))
    }

    /// The run with this stem was loaded (or found absent) after all.
    fn available(&self, stem: &str) {
        self.unavailable
            .lock()
            .expect("unavailable lock")
            .remove(stem);
    }

    /// The budget for journals held whole (verification, evidence).
    pub fn budget(&self) -> &Arc<ByteBudget> {
        &self.budget
    }

    pub fn options(&self) -> &StoreOptions {
        &self.opts
    }

    /// The run, if it exists.
    pub fn get(&self, run_id: &str) -> Option<Arc<Run>> {
        self.runs.read().expect("runs lock").get(run_id).cloned()
    }

    /// The run, or 410 for a tombstone, or 503 while its files cannot be
    /// read, or 404.
    pub fn find(&self, run_id: &str) -> Result<Arc<Run>, ApiError> {
        if let Some(run) = self.get(run_id) {
            return Ok(run);
        }
        if self.is_tombstoned(run_id) {
            return Err(ApiError::run_deleted());
        }
        self.load_late(run_id)?.ok_or_else(ApiError::not_found)
    }

    pub fn is_tombstoned(&self, run_id: &str) -> bool {
        if self
            .tombstones
            .read()
            .expect("tombstones lock")
            .contains_key(run_id)
        {
            return true;
        }
        let stems = self.deleted_stems.read().expect("deleted stems lock");
        !stems.is_empty() && stems.contains(&layout_stem(run_id))
    }

    /// Every run id, in order.
    pub fn run_ids(&self) -> Vec<String> {
        self.runs
            .read()
            .expect("runs lock")
            .keys()
            .cloned()
            .collect()
    }

    /// Every run.
    pub fn all(&self) -> Vec<Arc<Run>> {
        self.runs
            .read()
            .expect("runs lock")
            .values()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.runs.read().expect("runs lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn webhook(&self, event: &'static str, run_id: &str, detail: serde_json::Value) {
        self.signals
            .webhooks
            .send(WebhookEvent::new(event, Some(run_id), detail));
    }

    /// Mark a run's journal damaged: refuse writes, alert once.
    fn mark_broken(&self, run_id: &str, st: &mut RunState, reason: String) {
        if st.broken.is_none() {
            self.signals.metrics.chain_broken();
            self.webhook(
                "chain_broken",
                run_id,
                serde_json::json!({"entries": st.meta.entries}),
            );
        }
        st.broken = Some(reason);
        st.writer = None;
    }

    /// Act on a run's verification report. Anything but an ok report marks
    /// the run damaged, as a broken chain does: content erased without an
    /// `erasure` note, or a note listing slots that do not exist, is exactly
    /// the tampering design 2.13 exists to catch, so it raises the
    /// `chain_broken` webhook and metric, refuses writes and is listed by
    /// verify-data. Slots a note lists that still hold content can be
    /// repaired by erasing again, so that alone leaves erasure allowed; an
    /// ok report afterwards clears it.
    fn judge(&self, run_id: &str, st: &mut RunState, r: &pragmatic::VerifyReport) {
        if r.is_ok() {
            if st.repairable {
                st.broken = None;
                st.repairable = false;
            }
            return;
        }
        let mut why = Vec::new();
        if let Some(c) = r.first_bad {
            why.push(format!("verification failed at cursor {c}"));
        }
        if !r.unaccounted_erasures.is_empty() {
            why.push(format!(
                "{} erased slots no erasure note accounts for",
                r.unaccounted_erasures.len()
            ));
        }
        if !r.invalid_erasure_notes.is_empty() {
            why.push(format!(
                "{} invalid erasure notes",
                r.invalid_erasure_notes.len()
            ));
        }
        if !r.erasure_incomplete.is_empty() {
            why.push(format!(
                "{} slots listed as erased still hold content",
                r.erasure_incomplete.len()
            ));
        }
        let repairable = why.len() == 1 && !r.erasure_incomplete.is_empty();
        if st.broken.is_some() && !st.repairable {
            return;
        }
        self.mark_broken(run_id, st, why.join("; "));
        st.repairable = repairable;
    }

    /// Write `meta.json` now, or (when `force` is false and it was written
    /// less than a second ago) mark it for the flusher.
    fn save_meta(&self, run: &Run, st: &mut RunState, force: bool) -> Result<(), ApiError> {
        let due = st.meta_written.is_none_or(|t| t.elapsed() >= META_INTERVAL);
        if !force && !due {
            self.dirty
                .lock()
                .expect("dirty lock")
                .insert(run.id.clone());
            return Ok(());
        }
        self.write_meta(run, st)
    }

    /// Queue the run's `meta.json` for the flusher.
    fn mark_dirty(&self, run_id: &str) {
        self.dirty
            .lock()
            .expect("dirty lock")
            .insert(run_id.to_string());
    }

    fn write_meta(&self, run: &Run, st: &mut RunState) -> Result<(), ApiError> {
        if st.missing {
            // A missing run has no files, and must not get a meta.json
            // either: meta without a journal and nothing anchored is taken
            // at startup for a run whose PUT crashed, and begun again
            // empty, which would turn a lost history into a fresh one.
            return Ok(());
        }
        st.meta.leases = st.lease.iter().map(|l| l.record.clone()).collect();
        st.meta.status = self.status(st).to_string();
        crate::fsutil::write_json_atomic(&self.layout.meta(&run.stem), &st.meta)?;
        st.meta_written = Some(Instant::now());
        Ok(())
    }

    /// Write every `meta.json` that is due (or every dirty one, with
    /// `all`). Called every second and at shutdown.
    pub fn flush_meta(&self, all: bool) -> usize {
        let ids: Vec<String> = self.dirty.lock().expect("dirty lock").drain().collect();
        let mut written = 0;
        for id in ids {
            let Some(run) = self.get(&id) else { continue };
            let mut st = run.lock();
            if st.deleted {
                continue;
            }
            let due = st.meta_written.is_none_or(|t| t.elapsed() >= META_INTERVAL);
            if all || due {
                if self.write_meta(&run, &mut st).is_ok() {
                    written += 1;
                } else {
                    self.dirty.lock().expect("dirty lock").insert(id);
                }
            } else {
                self.dirty.lock().expect("dirty lock").insert(id);
            }
        }
        written
    }

    /// The run's status (design 4.4).
    pub fn status(&self, st: &RunState) -> &'static str {
        if st.meta.regressed {
            return "regressed";
        }
        if st.missing {
            return "missing";
        }
        if st
            .lease
            .as_ref()
            .is_some_and(|l| l.expires > Instant::now())
        {
            return "active";
        }
        if self.is_dangling(st) {
            return "dangling";
        }
        "idle"
    }

    /// An effect without a result and no lease activity for more than twice
    /// the lease TTL (design 4.5).
    fn is_dangling(&self, st: &RunState) -> bool {
        st.meta.summary.has_open_effect()
            && st.last_activity.elapsed() > self.opts.lease_ttl * 2
            && st
                .lease
                .as_ref()
                .is_none_or(|l| l.expires <= Instant::now())
    }

    /// Periodic housekeeping: raise `dangling_effect` for newly dangling
    /// runs, update the dangling and anchoring-lag gauges, and drop writer
    /// journals of runs nobody has touched for a while.
    pub fn sweep(&self) {
        let mut dangling = 0u64;
        let mut oldest: Option<i64> = None;
        for run in self.all() {
            let mut st = run.lock();
            if st.deleted {
                continue;
            }
            if st.meta.entries > st.meta.anchored_entries {
                let since = *st
                    .meta
                    .unanchored_since
                    .get_or_insert_with(crate::timefmt::now_unix_secs);
                oldest = Some(oldest.map_or(since, |o| o.min(since)));
            }
            if self.is_dangling(&st) {
                dangling += 1;
                if !st.dangling_alerted {
                    st.dangling_alerted = true;
                    let open = st.meta.summary.open_effects;
                    self.webhook(
                        "dangling_effect",
                        &run.id,
                        serde_json::json!({"open_effects": open}),
                    );
                }
            }
            let idle = st.last_activity.elapsed() > self.opts.lease_ttl * 2;
            let leased = st
                .lease
                .as_ref()
                .is_some_and(|l| l.expires > Instant::now());
            if idle && !leased {
                st.writer = None;
            }
        }
        self.signals.metrics.set_dangling_effects(dangling);
        self.signals.metrics.set_oldest_unanchored(oldest);
    }

    fn forget_cached(&self, run_id: &str) {
        self.frames.lock().expect("frame cache").forget(run_id);
    }
}

/// A fresh state for a run read from disk.
fn state_from_meta(meta: Meta, ttl: Duration) -> RunState {
    let now = Instant::now();
    let lease = meta.leases.first().map(|r| Lease {
        record: r.clone(),
        expires: now + ttl,
    });
    RunState {
        meta,
        writer: None,
        lease,
        ended: VecDeque::new(),
        last_activity: now,
        meta_written: Some(now),
        broken: None,
        repairable: false,
        missing: false,
        deleted: false,
        verify: None,
        dangling_alerted: false,
    }
}

#[cfg(test)]
mod tests;
