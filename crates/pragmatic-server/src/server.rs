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
//! 7. the index, in the background, then full verification, also in the
//!    background.
//!
//! Background tasks: the `meta.json` flusher (every second), the sweeper
//! (dangling effects, idle writers), anchoring batches, retention (hourly),
//! verify-data (every `verify_interval_hours`) and console session expiry.

use std::fmt;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pragmatic::encoding::hex_encode;
use serde_json::{json, Value as JsonValue};
use tokio::sync::watch;

use crate::access_log::{self, AccessLog, AccessRecord};
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
    /// The integration stubs: no anchoring, evidence and console answer
    /// 501.
    pub fn stubs(config: &Config) -> Hooks {
        Hooks {
            anchoring: Arc::new(NoAnchoring {
                independent: config.has_independent_witness(),
            }),
            evidence: Arc::new(EvidenceStub),
            console: Arc::new(ConsoleStub),
        }
    }
}

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
            anchor_lag_seconds: self.hooks.anchoring.lag_seconds(),
            tokens_active: self.tokens.ids().len() as u64,
        }
    }

    /// Run one anchoring batch now (blocking; one batch at a time).
    pub fn anchor_batch(
        &self,
        reason: BatchReason,
    ) -> Result<Option<crate::hooks::BatchReceipt>, String> {
        let _one = self.anchor_lock.lock().unwrap_or_else(|p| p.into_inner());
        let (entries, head) = self.access.tip();
        let input = BatchInput {
            runs: self.store.anchor_tips(),
            access_log: Some(LogTip {
                entries,
                head,
                prev_leaf: None,
            }),
        };
        let host = Host { app: self };
        match self.hooks.anchoring.anchor(&host, input, reason) {
            Ok(Some(receipt)) => {
                self.store.record_leaves(&receipt.leaves);
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
                self.app.metrics.anchor_failed();
                self.app.webhooks.send(WebhookEvent::new(
                    "anchor_failed",
                    None,
                    json!({"reason": reason}),
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

/// Start the server (see the module documentation). Must run inside a
/// multi-threaded tokio runtime.
pub async fn start(
    config: Config,
    config_sha256: [u8; 32],
    hooks: Hooks,
) -> Result<ServerHandle, StartError> {
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
    let key_ring =
        keys::ensure_current(&layout.data_dir, &key).or_else(|e| fail("keys.json", e))?;
    let index_key = layout::index_key(&layout).or_else(|e| fail("index.key", e))?;
    let tokens = TokenStore::open(&layout.data_dir, &config).or_else(|e| fail("tokens.json", e))?;
    let holds = Holds::open(&layout.data_dir).or_else(|e| fail("holds.json", e))?;
    let ledger = Ledger::open(&layout.data_dir).or_else(|e| fail("erasure ledger", e))?;
    let access =
        AccessLog::open(&access_log::path(&layout.data_dir)).or_else(|e| fail("access log", e))?;
    let redactor = Redactor::new(&config.redaction).map_err(|e| StartError(e.0))?;
    let webhooks = Webhooks::start(&config.webhooks).map_err(StartError)?;
    let metrics = Arc::new(Metrics::default());
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
    let server_name = config.server_name();
    let key = Arc::new(key);
    let witness = Witness::from_config(&config, &server_name, key.clone())
        .map_err(StartError)?
        .map(Arc::new);
    let addr = config.listen_addr().map_err(|e| StartError(e.0))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .or_else(|e| fail(&format!("listen {addr}"), e))?;
    let addr = listener.local_addr().or_else(|e| fail("listen", e))?;

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
    });

    let (shutdown, shutdown_rx) = watch::channel(false);
    let router = crate::api::router(app.clone());
    let mut rx = shutdown_rx.clone();
    let serving = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.wait_for(|stop| *stop).await;
        })
        .await
    });

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
            "server_version": env!("CARGO_PKG_VERSION"),
        }),
    );
    app.access
        .durable(record)
        .await
        .map(|_| ())
        .map_err(|e| StartError(format!("access log: {}", e.0)))
}

/// Build the index in the background, then mark the server ready and
/// verify everything.
fn spawn_index(app: Arc<App>) {
    tokio::task::spawn_blocking(move || {
        let report = app.store.index();
        for e in &report.errors {
            eprintln!("pragmatic-server: index: {e}");
        }
        if let Ok(lengths) = app.hooks.anchoring.anchored_lengths() {
            for (run_id, entries) in &lengths {
                if !app.store.is_tombstoned(run_id) {
                    app.store.register_missing(run_id, *entries);
                }
            }
            app.store.apply_anchored_lengths(&lengths);
        }
        app.ready.store(true, Ordering::SeqCst);
        app.store.verify_all();
    });
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
        "independent_witness": app.hooks.anchoring.independent(),
        "licensee": app.config.license.licensee,
    })
}
