//! Starting, running and stopping the server (design 4.1 and 4.2).
//!
//! Startup, in order:
//!
//! 1. the startup rules: loopback or `allow_plain_http`, an independent
//!    witness or `allow_self_anchoring`, the signing key outside
//!    `data_dir`;
//! 2. an exclusive lock on `<data_dir>/server.lock` (a second server on the
//!    same data exits);
//! 3. `FORMAT` (written for a fresh directory, refused when unknown);
//! 4. the signing key and the key ring, tokens, holds, the erasure ledger
//!    and the access log (verified; a damaged access log stops startup);
//! 5. listening. `/healthz` answers at once; `/readyz` and every run
//!    endpoint answer 503 `starting` until the index is built;
//! 6. the `config.loaded` access-log record;
//! 7. the index, in the background, then from the anchor log each run's
//!    last leaf (missing and rolled-back runs found), and a check that the
//!    access log still holds what its last leaf in the anchor log covers,
//!    then full verification, also in the background.
//!
//! Background tasks: the `meta.json` flusher (every second), the sweeper
//! (dangling effects, idle writers, the anchoring lag and its alert),
//! anchoring batches, retention (hourly), verify-data (every
//! `verify_interval_hours`) and console session expiry.
//!
//! # Serving
//!
//! Connections are served by hyper directly, with the [`Limits`]: a client
//! must send each request's headers within `header_read_timeout` (an idle
//! kept-alive connection is closed after it too), at most
//! `max_connections` are served at once (more wait in the listen queue),
//! and request bodies being received at once share `body_budget_bytes` and
//! must arrive at `min_body_rate` after `body_grace`. A slow or idle client
//! therefore holds a bounded share of the server, for a bounded time.

use std::fmt;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pragmatic::encoding::hex_encode;
use serde_json::{json, Value as JsonValue};
use tokio::sync::watch;

use crate::access_log::{self, AccessLeaf, AccessLog, AccessRecord};
use crate::anchoring;
use crate::config::Config;
use crate::console::Sessions;
use crate::holds::Holds;
use crate::hooks::{
    AnchorAlert, AnchorHost, Anchoring, BatchInput, BatchReason, ConsoleRenderer, ConsoleStub,
    EvidenceBuilder, EvidenceStub, LogTip, NoAnchoring,
};
use crate::keys::{self, KeyEntry, ServerKey};
use crate::layout::{self, Layout};
use crate::ledger::Ledger;
use crate::metrics::{Gauges, Metrics};
use crate::redaction::Redactor;
use crate::store::{AnchorSoon, Signals, Store, StoreOptions};
use crate::tokens::TokenStore;
use crate::webhooks::{WebhookEvent, Webhooks};
use crate::witness::Witness;
use crate::{fsutil, retention};

/// The components plugged in at startup (see [`crate::hooks`]).
#[derive(Clone)]
pub struct Hooks {
    pub anchoring: Arc<dyn Anchoring>,
    pub evidence: Arc<dyn EvidenceBuilder>,
    pub console: Arc<dyn ConsoleRenderer>,
}

impl Hooks {
    /// The integration stubs: no anchoring (and no independent witness,
    /// whatever the configuration names), evidence and console answer 501.
    pub fn stubs(_config: &Config) -> Hooks {
        Hooks {
            anchoring: Arc::new(NoAnchoring),
            evidence: Arc::new(EvidenceStub),
            console: Arc::new(ConsoleStub),
        }
    }

    /// The integrated components: anchoring with the anchoring library
    /// over the configured witnesses, evidence bundles from the core
    /// evidence module, and the console rendered with `pragmatic-console`.
    /// Opens (and recovers) the anchor log, so it runs with the data
    /// directory's lock held. Returns notes from the recovery to print.
    pub fn integrated(
        config: &Config,
        key: &ServerKey,
        ring: &[KeyEntry],
        options: anchoring::Options,
    ) -> Result<(Hooks, Vec<String>), String> {
        let (anchoring, notes) = anchoring::LibraryAnchoring::open(config, key, ring, options)?;
        Ok((
            Hooks {
                anchoring: Arc::new(anchoring),
                evidence: Arc::new(crate::evidence::BundleBuilder),
                console: Arc::new(crate::console_ui::ConsoleUi),
            },
            notes,
        ))
    }
}

/// Where a starting server gets its components: given (tests, and the
/// stubs), or built once the data directory is locked (a real server).
pub enum HooksSource {
    Given(Hooks),
    Integrated(anchoring::Options),
}

impl From<Hooks> for HooksSource {
    fn from(h: Hooks) -> HooksSource {
        HooksSource::Given(h)
    }
}

/// What one client may hold of the server (see the module documentation).
#[derive(Debug, Clone)]
pub struct Limits {
    /// A request's headers must arrive within this; an idle kept-alive
    /// connection is closed after it.
    pub header_read_timeout: Duration,
    /// Connections served at once.
    pub max_connections: usize,
    /// Request body bytes received at once, across every request (never
    /// less than `max_request_bytes`, so one largest request always fits).
    pub body_budget_bytes: u64,
    /// After `body_grace`, a body must keep arriving at least this fast
    /// (bytes per second), or the request is refused.
    pub min_body_rate: u64,
    pub body_grace: Duration,
    /// How long a shutdown waits for requests in flight.
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            header_read_timeout: Duration::from_secs(30),
            max_connections: 4096,
            body_budget_bytes: 1 << 30,
            min_body_rate: 256 << 10,
            body_grace: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// How often witnesses that still owe results are retried between
/// batches.
pub const RETRY_TICK: Duration = Duration::from_secs(30);

/// Request body bytes per permit of the body budget.
pub const BODY_UNIT: u64 = 64 << 10;

/// Why the server did not start.
#[derive(Debug)]
pub struct StartError(pub String);

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StartError {}

fn fail<T>(what: &str, e: impl fmt::Display) -> Result<T, StartError> {
    Err(StartError(format!("{what}: {e}")))
}

/// How the console names one configured TSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaLabel {
    /// The operator, canonical, as its witnesses carry it.
    pub operator: String,
    /// `[anchoring] tsa` `name`, or empty.
    pub name: String,
    /// The root its pinned anchors chain to, when it can be read.
    pub root: Option<String>,
}

fn tsa_labels(tsa: &[crate::config::TsaConfig]) -> Vec<TsaLabel> {
    tsa.iter()
        .map(|t| TsaLabel {
            operator: pragmatic_anchor::operator::canonical_operator(&t.operator),
            name: t.name.trim().to_string(),
            root: pragmatic_anchor::tsa::anchor_root_name(&t.roots_pem),
        })
        .collect()
}

/// Everything a request handler can reach.
pub struct App {
    pub config: Config,
    pub config_sha256: [u8; 32],
    pub server_name: String,
    pub store: Arc<Store>,
    pub tokens: Arc<TokenStore>,
    pub access: AccessLog,
    pub holds: Arc<Holds>,
    pub ledger: Arc<Ledger>,
    pub metrics: Arc<Metrics>,
    pub webhooks: Webhooks,
    pub redactor: Arc<Redactor>,
    pub key: Arc<ServerKey>,
    pub key_ring: Vec<KeyEntry>,
    pub index_key: [u8; 32],
    pub hooks: Hooks,
    pub sessions: Arc<Sessions>,
    pub witness: Option<Arc<Witness>>,
    pub ready: AtomicBool,
    /// One anchoring batch at a time.
    pub anchor_lock: std::sync::Mutex<()>,
    pub anchor_soon: Arc<AnchorSoon>,
    /// The access log's last anchor leaf (design 4.7): a cache of the
    /// anchor log's leaf (`audit/anchor.json`), reconciled with the anchor
    /// log at startup.
    pub access_leaf: std::sync::Mutex<Option<AccessLeaf>>,
    /// The anchoring-lag alert has fired and not yet cleared.
    pub lag_alerted: AtomicBool,
    /// How the console names each configured TSA: its operator as
    /// witnesses carry it, the configured display name (or empty), and the
    /// root its pinned anchors chain to, read once at startup.
    pub tsa_labels: Vec<TsaLabel>,
    pub limits: Limits,
    /// Request body bytes being received, in [`BODY_UNIT`]s.
    pub body_budget: Arc<tokio::sync::Semaphore>,
}

impl App {
    /// True once the index is built.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// The numbers `/metrics` reads from elsewhere.
    pub fn gauges(&self) -> Gauges {
        Gauges {
            access_log_lag_seconds: self.access.lag_seconds(),
            access_log_failed: self.access.is_failed(),
            anchor_lag_seconds: self.metrics.anchor_lag_seconds(),
            tokens_active: self.tokens.ids().len() as u64,
        }
    }

    /// Retry the witnesses that still owe results (blocking; never at the
    /// same time as a batch).
    pub fn anchor_retry(&self) {
        let _one = self.anchor_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.hooks.anchoring.retry(&Host { app: self });
    }

    /// Run one anchoring batch now (blocking; one batch at a time). Only
    /// what changed since its last leaf is offered: each run that grew,
    /// and the access log if it grew, naming its previous leaf. A batch
    /// with nothing to anchor does not run.
    pub fn anchor_batch(
        &self,
        reason: BatchReason,
    ) -> Result<Option<crate::hooks::BatchReceipt>, String> {
        let _one = self.anchor_lock.lock().unwrap_or_else(|p| p.into_inner());
        let (entries, head) = self.access.tip();
        let last = self
            .access_leaf
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let access_log = match &last {
            Some(l) if l.entries == entries => None,
            _ => Some(LogTip {
                entries,
                head,
                prev_leaf: last.as_ref().map(|l| l.leaf_index),
            }),
        };
        let input = BatchInput {
            runs: self.store.anchor_tips(),
            access_log,
        };
        if input.runs.is_empty() && input.access_log.is_none() {
            return Ok(None);
        }
        let host = Host { app: self };
        match self.hooks.anchoring.anchor(&host, input, reason) {
            Ok(Some(receipt)) => {
                self.store.record_leaves(&receipt.leaves);
                if let Some(leaf) = receipt.leaves.iter().find(|l| l.run_id.is_none()) {
                    self.record_access_leaf(leaf.leaf_index, leaf.entries, head);
                }
                Ok(Some(receipt))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                host.alert(AnchorAlert::Failed {
                    reason: e.0.clone(),
                });
                Err(e.0)
            }
        }
    }
}

impl App {
    /// Raise `anchor_failed` once the anchoring lag passes three anchoring
    /// intervals (design 4.7: "an alert fires if fewer than the minimum
    /// succeed for 3 intervals"), and re-arm once it falls back. Driven by
    /// time from the sweeper, not by batches: a batch runs only when new
    /// leaves exist, so on a quiet server whose witnesses are down the
    /// last finished run would otherwise stay unanchored with no alert.
    /// Only with an external witness configured: a self-anchored
    /// deployment's lag grows by design, and says so in its metric.
    pub fn check_anchoring_lag(&self) {
        if !(self.hooks.anchoring.integrated() && self.hooks.anchoring.independent()) {
            return;
        }
        let lag = self.metrics.anchor_lag_seconds();
        let limit = 3 * self.config.anchoring.interval_secs;
        if lag > limit as f64 {
            if !self.lag_alerted.swap(true, Ordering::SeqCst) {
                Host { app: self }.alert(AnchorAlert::Failed {
                    reason: format!(
                        "the oldest append not independently anchored is {lag:.0} s old, more \
                         than three anchoring intervals ({limit} s): fewer than \
                         min_independent_operators = {} witnesses are succeeding",
                        self.config.anchoring.min_independent_operators
                    ),
                });
            }
        } else {
            self.lag_alerted.store(false, Ordering::SeqCst);
        }
    }

    /// Remember where a batch put the access log's leaf, on disk first.
    fn record_access_leaf(&self, leaf_index: u64, entries: u64, head: pragmatic::sha256::Digest) {
        let leaf = AccessLeaf {
            leaf_index,
            entries,
            head: hex_encode(&head),
        };
        if let Err(e) = access_log::write_leaf(&self.config.data_dir, &leaf) {
            eprintln!("pragmatic-server: audit/anchor.json: {e}");
        }
        *self.access_leaf.lock().unwrap_or_else(|p| p.into_inner()) = Some(leaf);
    }

    /// Whether the access log still holds what its last leaf anchored: as
    /// many records, ending in the same hash. The leaf is the anchor log's
    /// own (signed, witnessed) when anchoring can say, and the cached
    /// `audit/anchor.json` otherwise; a cache that disagrees with the
    /// anchor log is itself a finding. `None` before the first leaf.
    pub fn access_log_matches_leaf(&self) -> Option<Result<(), String>> {
        let cached = self
            .access_leaf
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let anchored = self.hooks.anchoring.last_leaves().ok().and_then(|leaves| {
            leaves
                .into_iter()
                .find(|l| l.run_id.is_none())
                .map(|l| AccessLeaf {
                    leaf_index: l.leaf_index,
                    entries: l.entries,
                    head: hex_encode(&l.head),
                })
        });
        let leaf = match (anchored, cached) {
            (Some(a), Some(c)) if c.leaf_index > a.leaf_index => {
                return Some(Err(format!(
                    "audit/anchor.json names access-log leaf {}, which the anchor log does not \
                     hold (its last is {})",
                    c.leaf_index, a.leaf_index
                )))
            }
            (Some(a), Some(c)) if c.leaf_index == a.leaf_index && c != a => {
                return Some(Err(format!(
                    "audit/anchor.json disagrees with the anchor log's access-log leaf {}",
                    a.leaf_index
                )))
            }
            (Some(a), _) => a,
            (None, Some(c)) => c,
            (None, None) => return None,
        };
        self.access_log_holds(&leaf)
    }

    /// Whether the access log holds `leaf`'s records, ending in its head.
    fn access_log_holds(&self, leaf: &AccessLeaf) -> Option<Result<(), String>> {
        let (entries, _) = self.access.tip();
        if entries < leaf.entries {
            return Some(Err(format!(
                "the access log holds {entries} records, but {} were anchored (leaf {})",
                leaf.entries, leaf.leaf_index
            )));
        }
        let at = leaf.entries.checked_sub(1)?;
        Some(match self.access.hash_at(at) {
            Ok(Some(h)) if hex_encode(&h) == leaf.head => Ok(()),
            Ok(_) => Err(format!(
                "access-log record {at} no longer has the hash anchored in leaf {}",
                leaf.leaf_index
            )),
            Err(e) => Err(format!("access-log record {at}: {e}")),
        })
    }
}

/// What anchoring calls back into.
struct Host<'a> {
    app: &'a App,
}

impl AnchorHost for Host<'_> {
    fn anchored(&self, runs: &[(String, u64)]) {
        self.app.store.mark_anchored(runs);
    }

    fn alert(&self, alert: AnchorAlert) {
        match alert {
            AnchorAlert::Failed { reason } => {
                eprintln!("pragmatic-server: anchoring: {reason}");
                self.app.metrics.anchor_failed();
                self.app.webhooks.send(WebhookEvent::new(
                    "anchor_failed",
                    None,
                    json!({"reason": reason}),
                ));
            }
            AnchorAlert::WitnessFailed { .. } => self.app.metrics.anchor_failed(),
            AnchorAlert::Fork { reason } => {
                eprintln!("pragmatic-server: anchoring is held: {reason}");
                self.app.metrics.anchor_failed();
                self.app.webhooks.send(WebhookEvent::new(
                    "anchor_failed",
                    None,
                    json!({"reason": reason, "fork": true, "held": true}),
                ));
            }
            AnchorAlert::Contradicted {
                run_id: Some(run_id),
                anchored_entries,
                reason,
            } => {
                eprintln!("pragmatic-server: anchoring refused {run_id}: {reason}");
                self.app
                    .store
                    .mark_contradicted(&run_id, anchored_entries, &reason);
            }
            AnchorAlert::Contradicted {
                run_id: None,
                reason,
                ..
            } => {
                let why = format!("the access log contradicts its anchor: {reason}");
                eprintln!("pragmatic-server: {why}");
                self.app.metrics.chain_broken();
                self.app.webhooks.send(WebhookEvent::new(
                    "chain_broken",
                    Some(access_log::ACCESS_LOG_RUN_ID),
                    json!({"reason": why}),
                ));
            }
        }
    }
}

/// A running server.
pub struct ServerHandle {
    pub addr: SocketAddr,
    pub app: Arc<App>,
    shutdown: watch::Sender<bool>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    _lock: File,
}

impl ServerHandle {
    /// `http://<addr>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Wait until the index is built.
    pub async fn wait_ready(&self) {
        while !self.app.is_ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Stop serving, flush every `meta.json` and the access log, and
    /// release the data directory.
    pub async fn shutdown(self) -> std::io::Result<()> {
        let _ = self.shutdown.send(true);
        let served = self.serving.await.map_err(std::io::Error::other)?;
        let app = self.app.clone();
        tokio::task::spawn_blocking(move || app.store.flush_meta(true))
            .await
            .map_err(std::io::Error::other)?;
        let _ = self.app.access.flush().await;
        served
    }

    /// Serve until ctrl-c or SIGTERM, then shut down cleanly.
    pub async fn run_until_signal(self) -> std::io::Result<()> {
        wait_for_signal().await;
        self.shutdown().await
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Take the data directory's server lock. `Err` names the lock file when
/// another server holds it.
pub fn lock_data_dir(layout: &Layout) -> Result<File, StartError> {
    if let Err(e) = fsutil::create_dir_durable(&layout.data_dir) {
        return fail("data_dir", e);
    }
    match fsutil::try_lock_exclusive(&layout.server_lock()) {
        Ok(Some(f)) => Ok(f),
        Ok(None) => Err(StartError(format!(
            "another pragmatic-server holds {}",
            layout.server_lock().display()
        ))),
        Err(e) => fail("server.lock", e),
    }
}

/// Start the server with the default [`Limits`] (see the module
/// documentation). Must run inside a multi-threaded tokio runtime.
pub async fn start(
    config: Config,
    config_sha256: [u8; 32],
    hooks: impl Into<HooksSource>,
) -> Result<ServerHandle, StartError> {
    start_with(config, config_sha256, hooks, Limits::default()).await
}

/// [`start`] with chosen [`Limits`].
pub async fn start_with(
    config: Config,
    config_sha256: [u8; 32],
    hooks: impl Into<HooksSource>,
    limits: Limits,
) -> Result<ServerHandle, StartError> {
    let source = hooks.into();
    if let Err(e) = config.check_startup_rules() {
        return Err(StartError(e.0));
    }
    let layout = Layout::new(config.data_dir.clone());
    let lock = lock_data_dir(&layout)?;
    if let Err(e) = layout::check_format(&layout) {
        return Err(StartError(e));
    }
    let key = match ServerKey::load(&config.keys.signing_key_file) {
        Ok(k) => k,
        Err(e) => {
            return Err(StartError(format!(
                "{e} (create one with `pragmatic-server keygen`)"
            )))
        }
    };
    // The origin is fixed by the first key (design 4.7). A configured name
    // that disagrees with it is a mistake to stop at, not to paper over: a
    // renamed server would otherwise sign checkpoints for an origin its
    // configuration does not mention.
    if !config.name.is_empty() && key.server_name() != Some(config.name.as_str()) {
        return Err(StartError(format!(
            "the signing key is for the origin {}, but name = {:?}: the origin is fixed by the \
             log's first key. Set name = {:?}, or leave it empty",
            key.origin(),
            config.name,
            key.server_name().unwrap_or("")
        )));
    }
    let key_ring =
        keys::ensure_current(&layout.data_dir, &key).or_else(|e| fail("keys.json", e))?;
    let hooks = match source {
        HooksSource::Given(h) => h,
        HooksSource::Integrated(options) => {
            let (hooks, notes) =
                Hooks::integrated(&config, &key, &key_ring, options).map_err(StartError)?;
            for n in notes {
                eprintln!("pragmatic-server: {n}");
            }
            hooks
        }
    };
    let index_key = layout::index_key(&layout).or_else(|e| fail("index.key", e))?;
    let tokens = TokenStore::open(&layout.data_dir, &config).or_else(|e| fail("tokens.json", e))?;
    let holds = Holds::open(&layout.data_dir).or_else(|e| fail("holds.json", e))?;
    let ledger = Ledger::open(&layout.data_dir).or_else(|e| fail("erasure ledger", e))?;
    let access =
        AccessLog::open(&access_log::path(&layout.data_dir)).or_else(|e| fail("access log", e))?;
    let redactor = Redactor::new(&config.redaction).map_err(|e| StartError(e.0))?;
    let webhooks = Webhooks::start(&config.webhooks).map_err(StartError)?;
    let metrics = Arc::new(Metrics::default());
    let hook = webhooks.clone();
    access.on_failure(move |why| {
        eprintln!("pragmatic-server: the access log failed, refusing requests: {why}");
        hook.send(WebhookEvent::new(
            "access_log_failed",
            None,
            json!({"reason": why}),
        ));
    });
    let access_leaf =
        access_log::read_leaf(&layout.data_dir).or_else(|e| fail("audit/anchor.json", e))?;
    let body_budget = Arc::new(tokio::sync::Semaphore::new(body_units(
        limits.body_budget_bytes.max(config.max_request_bytes),
    )));
    let anchor_soon = Arc::new(AnchorSoon::default());
    let store = Arc::new(Store::new(
        layout.clone(),
        StoreOptions {
            lease_ttl: Duration::from_secs(config.lease_ttl_secs),
            max_clock_skew: Duration::from_secs(config.max_clock_skew_secs),
            index_key,
        },
        Signals {
            metrics: metrics.clone(),
            webhooks: webhooks.clone(),
            anchor_soon: anchor_soon.clone(),
        },
    ));
    // The name the log's origin was made for, which may differ from the
    // host name a container gets when `name` is left empty.
    let server_name = key
        .server_name()
        .map_or_else(|| config.server_name(), str::to_string);
    let key = Arc::new(key);
    let witness = Witness::from_config(&config)
        .map_err(StartError)?
        .map(Arc::new);
    let addr = config.listen_addr().map_err(|e| StartError(e.0))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .or_else(|e| fail(&format!("listen {addr}"), e))?;
    let addr = listener.local_addr().or_else(|e| fail("listen", e))?;

    let tsa_labels = tsa_labels(&config.anchoring.tsa);
    let app = Arc::new(App {
        config,
        config_sha256,
        server_name,
        store,
        tokens: Arc::new(tokens),
        access,
        holds: Arc::new(holds),
        ledger: Arc::new(ledger),
        metrics,
        webhooks,
        redactor: Arc::new(redactor),
        key,
        key_ring,
        index_key,
        hooks,
        sessions: Arc::new(Sessions::default()),
        witness,
        ready: AtomicBool::new(false),
        anchor_lock: std::sync::Mutex::new(()),
        anchor_soon,
        access_leaf: std::sync::Mutex::new(access_leaf),
        lag_alerted: AtomicBool::new(false),
        tsa_labels,
        body_budget,
        limits,
    });

    let (shutdown, shutdown_rx) = watch::channel(false);
    let router = crate::api::router(app.clone());
    let serving = tokio::spawn(serve(
        listener,
        router,
        app.limits.clone(),
        shutdown_rx.clone(),
    ));

    record_config_loaded(&app).await?;
    spawn_index(app.clone());
    spawn_background(app.clone(), shutdown_rx);
    Ok(ServerHandle {
        addr,
        app,
        shutdown,
        serving,
        _lock: lock,
    })
}

/// `config.loaded {config_sha256, token_ids, key_id}`.
async fn record_config_loaded(app: &App) -> Result<(), StartError> {
    let record = AccessRecord::new(
        "config.loaded",
        json!({
            "config_sha256": hex_encode(&app.config_sha256),
            "token_ids": app.tokens.ids(),
            "key_id": app.key.key_id(),
            "public_key": hex_encode(&app.key.public_key()),
            "origin": app.key.origin(),
            "server_version": env!("CARGO_PKG_VERSION"),
        }),
    );
    app.access
        .durable(record)
        .await
        .map(|_| ())
        .map_err(|e| StartError(format!("access log: {}", e.0)))
}

/// Body budget permits for `bytes`.
pub fn body_units(bytes: u64) -> usize {
    bytes.div_ceil(BODY_UNIT).max(1) as usize
}

/// Serve connections until shutdown (see the module documentation), then
/// let the requests in flight finish for at most `shutdown_grace`.
async fn serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    limits: Limits,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let (close, closing) = watch::channel(false);
    let mut conns = tokio::task::JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let slot = tokio::select! {
            s = slots.clone().acquire_owned() => s.expect("the connection semaphore is never closed"),
            _ = stopped(&mut shutdown) => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    // Out of descriptors or a connection reset before it
                    // was accepted: wait a moment and go on.
                    eprintln!("pragmatic-server: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = stopped(&mut shutdown) => break,
        };
        let svc = connection_service(router.clone(), peer);
        let mut closing = closing.clone();
        let timeout = limits.header_read_timeout;
        conns.spawn(async move {
            let _slot = slot;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(timeout)
                .serve_connection(TokioIo::new(stream), svc);
            tokio::pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = stopped(&mut closing) => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
        });
    }
    let _ = close.send(true);
    let drain = async { while conns.join_next().await.is_some() {} };
    if tokio::time::timeout(limits.shutdown_grace, drain)
        .await
        .is_err()
    {
        conns.shutdown().await;
    }
    Ok(())
}

/// Wait until `rx` says stop (or its sender is gone).
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await.map(|_| ());
}

/// The service of one connection: the router, with the peer's address in
/// every request (for the access log).
fn connection_service(
    router: axum::Router,
    peer: SocketAddr,
) -> impl hyper::service::Service<
    hyper::Request<hyper::body::Incoming>,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
    Future = impl std::future::Future<
        Output = Result<axum::response::Response, std::convert::Infallible>,
    > + Send,
> + Clone {
    hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        tower::ServiceExt::oneshot(router.clone(), req)
    })
}

/// Build the index in the background, then mark the server ready and
/// verify everything.
///
/// Before the server is ready, the index is completed from the anchor
/// log, which a crash cannot lose: every run the log holds a leaf for but
/// the data directory has no trace of (neither journal nor tombstone) is
/// `missing`, whether or not it was independently anchored (a record that
/// was only self-anchored, or whose witnesses were down, was still written
/// and signed); every run's last leaf is raised to the log's, and a run
/// that holds less than its last leaf is `regressed` at once rather than
/// at the next batch, so nothing is appended to a rolled-back history in
/// between; and the access log is checked against its leaf. A pass over
/// the anchor log that fails is alerted on, never ignored.
fn spawn_index(app: Arc<App>) {
    tokio::task::spawn_blocking(move || {
        let report = app.store.index();
        for e in &report.errors {
            eprintln!("pragmatic-server: index: {e}");
        }
        let host = Host { app: &app };
        let lengths = match app.hooks.anchoring.anchored_lengths() {
            Ok(l) => l,
            Err(e) => {
                host.alert(AnchorAlert::Failed {
                    reason: format!("reading anchored lengths from the anchor log at startup: {e}"),
                });
                Default::default()
            }
        };
        let leaves = match app.hooks.anchoring.last_leaves() {
            Ok(l) => l,
            Err(e) => {
                host.alert(AnchorAlert::Failed {
                    reason: format!("reading last leaves from the anchor log at startup: {e}"),
                });
                Vec::new()
            }
        };
        for leaf in &leaves {
            let Some(run_id) = &leaf.run_id else { continue };
            if !app.store.is_tombstoned(run_id) {
                let anchored = lengths.get(run_id).copied().unwrap_or(0);
                app.store.register_missing(run_id, anchored);
            }
        }
        app.store.apply_anchored_lengths(&lengths);
        app.store.apply_last_leaves(&leaves);
        recover_access_leaf(&app, &leaves);
        app.store.sweep();
        app.ready.store(true, Ordering::SeqCst);
        app.store.verify_all();
    });
}

/// Check, at startup, that the access log still holds what its last leaf
/// covers: the records the leaf counts, ending in the leaf's head (design
/// 4.7). A log that lost or rewrote anchored records was cut or tampered
/// with: `chain_broken` fires for `pragmatic:access-log` and the finding
/// is recorded in the log itself. The server goes on (refusing to start
/// would stop the record of everything that follows).
///
/// The leaf is the anchor log's, which is the record that was signed and
/// witnessed; `audit/anchor.json` is only its cache (it lags the anchor log
/// after a crash between the two writes), is brought to it, and is a
/// finding of its own when it names a leaf the anchor log does not hold.
/// The current log's hash is never taken for the anchored head: a
/// rewritten prefix would then be adopted as anchored. Without a leaf in
/// the anchor log (anchoring not integrated), the cache is checked.
fn recover_access_leaf(app: &App, leaves: &[crate::hooks::LeafPlaced]) {
    let cached = app
        .access_leaf
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let Some(leaf) = leaves.iter().find(|l| l.run_id.is_none()) else {
        if let Some(Err(why)) = cached.and_then(|leaf| app.access_log_holds(&leaf)) {
            access_log_broken(app, why);
        }
        return;
    };
    let anchored = AccessLeaf {
        leaf_index: leaf.leaf_index,
        entries: leaf.entries,
        head: hex_encode(&leaf.head),
    };
    if let Some(c) = &cached {
        if c.leaf_index >= anchored.leaf_index && *c != anchored {
            access_log_broken(
                app,
                format!(
                    "audit/anchor.json (leaf {}, {} records) disagrees with the anchor log's \
                     access-log leaf {} ({} records)",
                    c.leaf_index, c.entries, anchored.leaf_index, anchored.entries
                ),
            );
        }
    }
    if cached.as_ref() != Some(&anchored) {
        app.record_access_leaf(leaf.leaf_index, leaf.entries, leaf.head);
    }
    if let Some(Err(why)) = app.access_log_holds(&anchored) {
        access_log_broken(app, why);
    }
}

/// The access log contradicts its anchor: `chain_broken` for
/// `pragmatic:access-log`, and a record of the finding in the log itself.
fn access_log_broken(app: &App, why: String) {
    eprintln!("pragmatic-server: {why}");
    app.metrics.chain_broken();
    app.webhooks.send(WebhookEvent::new(
        "chain_broken",
        Some(access_log::ACCESS_LOG_RUN_ID),
        json!({"reason": why}),
    ));
    app.access.submit(AccessRecord::new(
        "access_log.damaged",
        json!({"reason": why}),
    ));
}

fn spawn_background(app: Arc<App>, shutdown: watch::Receiver<bool>) {
    every(
        app.clone(),
        shutdown.clone(),
        Duration::from_secs(1),
        |app| {
            app.store.flush_meta(false);
        },
    );
    every(
        app.clone(),
        shutdown.clone(),
        Duration::from_secs(15),
        |app| {
            if app.is_ready() {
                app.store.sweep();
                app.check_anchoring_lag();
            }
            app.sessions.expire();
        },
    );
    every(
        app.clone(),
        shutdown.clone(),
        Duration::from_secs(3600),
        |app| {
            if app.is_ready() {
                retention::run(app);
            }
        },
    );
    let verify_every = Duration::from_secs(app.config.verify_interval_hours * 3600);
    every(app.clone(), shutdown.clone(), verify_every, |app| {
        if app.is_ready() {
            retention::verify_data(app);
        }
    });
    let interval = Duration::from_secs(app.config.anchoring.interval_secs);
    every(app.clone(), shutdown.clone(), interval, |app| {
        if app.is_ready() {
            let _ = app.anchor_batch(BatchReason::Interval);
        }
    });
    // Witnesses that failed are retried between batches; each one backs
    // off on its own schedule (30 s doubling to an hour), so a short tick
    // asks nothing of a witness that is backing off.
    every(app.clone(), shutdown.clone(), RETRY_TICK, |app| {
        if app.is_ready() {
            app.anchor_retry();
        }
    });
    // Within 30 s of an attempt ending ok: wait a few seconds to gather
    // other runs finishing at the same time, then batch.
    let mut stop = shutdown;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = app.anchor_soon.wait() => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            let a = app.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if a.is_ready() {
                    let _ = a.anchor_batch(BatchReason::AttemptEnded);
                }
            })
            .await;
        }
    });
}

/// Run `f` on a blocking thread every `period` (first run after one
/// period) until shutdown.
fn every(app: Arc<App>, mut stop: watch::Receiver<bool>, period: Duration, f: fn(&App)) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            let a = app.clone();
            let _ = tokio::task::spawn_blocking(move || f(&a)).await;
        }
    });
}

/// The JSON of `/v1/info` (design 4.4).
pub fn info(app: &App) -> JsonValue {
    let max_frame = 4 + pragmatic::journal::MAX_RECORD_BYTES + 32;
    json!({
        "server": "pragmatic-server",
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": 1,
        "min_sdk": "0.6.0",
        "journal_format": 2,
        "chain": "sha256",
        "lease_ttl_secs": app.config.lease_ttl_secs,
        "max_request_bytes": app.config.max_request_bytes,
        "max_frame_bytes": max_frame.min(app.config.max_request_bytes),
        "server_time": crate::timefmt::now_rfc3339(),
        "independent_witness": app.hooks.anchoring.integrated() && app.hooks.anchoring.independent(),
        "components": {
            "anchoring": integration(app.hooks.anchoring.integrated()),
            "evidence": integration(app.hooks.evidence.integrated()),
            "console": integration(app.hooks.console.integrated()),
        },
        "licensee": app.config.license.licensee,
    })
}

fn integration(integrated: bool) -> &'static str {
    if integrated {
        "integrated"
    } else {
        "not_integrated"
    }
}
