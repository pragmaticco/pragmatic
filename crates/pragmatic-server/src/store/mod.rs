//! Runs on disk and in memory (design 4.2, 4.5 and 4.6).
//!
//! # Locks
//!
//! Every run has two locks:
//!
//! - `file`, a read-write lock on the journal file's identity. Readers of
//!   the journal, its entries and evidence hold it shared while they read;
//!   erasure and deletion, which replace or remove the file, hold it
//!   exclusively. Appends only extend the file, so they never need it
//!   exclusively.
//! - `state`, a mutex over the run's index (entries, byte length, head),
//!   its lease and its writer's journal. Every change takes it: appends,
//!   leases, custody notes, erasure, retention, anchoring snapshots.
//!
//! The lock order is: the run map, then `file`, then `state`, then holds.
//! The run map is never held while a run's locks are, except when a new run
//! is inserted (its locks are taken before anyone can see it).
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
mod index;
mod read;
mod write;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use pragmatic::Journal;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::layout::Layout;
use crate::metrics::Metrics;
use crate::summary::{OpenIntent, Summary};
use crate::webhooks::{WebhookEvent, Webhooks};

pub use admin::{EraseContext, EraseOutcome, EraseParams, Selector};
pub use index::IndexReport;
pub use read::{verify_json, Durable, ListQuery, RunPage};
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
    pub open_intents: Vec<OpenIntent>,
    /// `active`, `idle`, `dangling`, `regressed` or `missing` when written.
    pub status: String,
    /// The token id that created the run.
    pub created_by: Option<String>,
    /// Fewer entries than were anchored; appends are refused until an admin
    /// accepts the regression.
    pub regressed: bool,
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
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Released => "released",
            EndReason::Expired => "expired",
            EndReason::Revoked => "revoked",
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
}

impl Run {
    pub fn lock(&self) -> MutexGuard<'_, RunState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
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

/// Parsed journals for readers, by run and byte length.
#[derive(Default)]
struct ReadCache {
    map: HashMap<String, (u64, Arc<Journal>)>,
    order: VecDeque<String>,
    bytes: u64,
}

/// The most journal bytes kept parsed for readers.
const READ_CACHE_BYTES: u64 = 256 << 20;

impl ReadCache {
    fn get(&mut self, run: &str, byte_len: u64) -> Option<Arc<Journal>> {
        match self.map.get(run) {
            Some((len, j)) if *len == byte_len => Some(j.clone()),
            _ => None,
        }
    }

    fn put(&mut self, run: &str, byte_len: u64, j: Arc<Journal>) {
        if byte_len > READ_CACHE_BYTES / 4 {
            return;
        }
        if let Some((old, _)) = self.map.insert(run.to_string(), (byte_len, j)) {
            self.bytes -= old;
            self.order.retain(|r| r != run);
        }
        self.bytes += byte_len;
        self.order.push_back(run.to_string());
        while self.bytes > READ_CACHE_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some((len, _)) = self.map.remove(&oldest) {
                self.bytes -= len;
            }
        }
    }

    fn forget(&mut self, run: &str) {
        if let Some((len, _)) = self.map.remove(run) {
            self.bytes -= len;
            self.order.retain(|r| r != run);
        }
    }
}

/// Every run.
pub struct Store {
    pub layout: Layout,
    runs: RwLock<BTreeMap<String, Arc<Run>>>,
    tombstones: RwLock<HashMap<String, Tombstone>>,
    dirty: Mutex<HashSet<String>>,
    cache: Mutex<ReadCache>,
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
            cache: Mutex::new(ReadCache::default()),
            opts,
            signals,
        }
    }

    pub fn options(&self) -> &StoreOptions {
        &self.opts
    }

    /// The run, if it exists.
    pub fn get(&self, run_id: &str) -> Option<Arc<Run>> {
        self.runs.read().expect("runs lock").get(run_id).cloned()
    }

    /// The run, or 410 for a tombstone, or 404.
    pub fn find(&self, run_id: &str) -> Result<Arc<Run>, ApiError> {
        if let Some(run) = self.get(run_id) {
            return Ok(run);
        }
        if self.is_tombstoned(run_id) {
            return Err(ApiError::run_deleted());
        }
        Err(ApiError::not_found())
    }

    pub fn is_tombstoned(&self, run_id: &str) -> bool {
        self.tombstones
            .read()
            .expect("tombstones lock")
            .contains_key(run_id)
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
        st.meta.leases = st.lease.iter().map(|l| l.record.clone()).collect();
        st.meta.open_intents = st.meta.summary.open_intents.clone();
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
    /// runs, update the gauge, and drop writer journals of runs nobody has
    /// touched for a while.
    pub fn sweep(&self) {
        let mut dangling = 0u64;
        for run in self.all() {
            let mut st = run.lock();
            if st.deleted {
                continue;
            }
            if self.is_dangling(&st) {
                dangling += 1;
                if !st.dangling_alerted {
                    st.dangling_alerted = true;
                    let open = st
                        .meta
                        .summary
                        .open_intents
                        .iter()
                        .filter(|o| o.kind == "effect")
                        .count();
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
    }

    fn forget_cached(&self, run_id: &str) {
        self.cache.lock().expect("cache lock").forget(run_id);
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
        missing: false,
        deleted: false,
        verify: None,
        dangling_alerted: false,
    }
}

#[cfg(test)]
mod tests;
