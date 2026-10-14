//! Anchoring with the anchoring library (design 4.7): the server's
//! [`Anchoring`] hook implemented over [`pragmatic_anchor::Anchorer`].
//!
//! # What the server supplies
//!
//! - **Snapshots.** Every batch starts from the [`BatchInput`] the server
//!   builds: the fsynced `(entries, head)` of every run that changed since
//!   its last leaf, read under that run's lock (runs created by `PUT`
//!   included with zero entries), and the access log's tip when it grew.
//!   This adapter hands them to the library as its snapshot provider; the
//!   library links each leaf to the object's previous leaf itself, from
//!   the log, so a `meta.json` that lags the log can never fork a leaf
//!   chain (a repeated snapshot is skipped as unchanged).
//! - **Batches** every `interval_secs`, within 30 s of a successful
//!   `attempt.end`, and for `anchor=now`, one at a time. A batch commits
//!   its leaves and checkpoint, then runs one witness pass, so an
//!   `anchor=now` bundle carries the witnesses that answered at once.
//! - **Retries** of witnesses that still owe results, on a timer between
//!   batches ([`Anchoring::retry`]).
//!
//! # What the server hears back
//!
//! - Leaves of independently anchored checkpoints ([`AnchorHost::anchored`]):
//!   a run's `anchored_entries` advances only then, to the largest
//!   `entries` among them, and the anchoring lag moves with it. The first
//!   pass after startup reports the recent ones again, which is harmless
//!   under `max`.
//! - Snapshots the library refused because they contradict a signed leaf
//!   (fewer entries than the latest leaf, or the same entries and another
//!   head): the run was rolled back or rewritten after it was anchored, and
//!   the server marks it `regressed` ([`AnchorAlert::Contradicted`]).
//! - Failed witness attempts (the `pragmatic_anchor_failures_total`
//!   metric), problems that did not stop a pass, and three batches in a
//!   row that ended short of `min_independent_operators` (the
//!   `anchor_failed` webhook).
//! - A witness that has seen checkpoints this log no longer has
//!   ([`AnchorAlert::Fork`]): the log was restored from an old backup or
//!   rolled back. Anchoring is then *held* (below).
//!
//! # Holds
//!
//! While `anchors/hold.json` exists no checkpoint is signed: a batch
//! answers with the hold's reason, and the snapshots wait. `restore`
//! places a hold (the backup's anchor log is older than the one the
//! server published before the disaster, and signing on from it would
//! sign other trees under sequence numbers and sizes already signed: a
//! fork of the log, design 4.7 and 4.13), and so does a fork alarm. Only
//! `pragmatic-server confirm-anchors` lifts it, once the operator has
//! shown the log is current or started a new log under a new origin.
//!
//! # Startup and recovery
//!
//! The library recovers the log when it opens: uncommitted leaves are
//! moved aside, every checkpoint root is recomputed, and a damaged log
//! stops the server. The server then reads every object's last leaf and
//! every run's independently anchored length from the log
//! ([`Anchoring::last_leaves`], [`Anchoring::anchored_lengths`]): the log
//! is durable before `meta.json` records a leaf, so the log is the record
//! a crash cannot lose. A checkpoint whose batch index is missing, or does
//! not match its leaves, is read from the leaves themselves where they
//! carry plain ids (the access log's always do) and otherwise skipped,
//! with an alert, rather than stopping the whole pass.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use pragmatic::encoding::{base64_decode, hex_decode_exact, hex_encode};
use pragmatic::evidence::{Anchor as BundleAnchor, Witness as BundleWitness};
use pragmatic::json::Json;
use pragmatic::merkle;
use pragmatic::note::{self, SignatureType, VerifierKey};
use pragmatic_anchor::tsa::{
    HttpTransport, OpensslVerifier, TsaClient, TsaConfig as LibTsaConfig, TsaPolicy, UreqTransport,
};
use pragmatic_anchor::witness::{WitnessClient, WitnessConfig as LibWitnessConfig};
use pragmatic_anchor::{
    Anchorer, AnchorerConfig, BatchOutcome, ExternalWitness, IndependencePolicy, Leaf, LeafType,
    RetryPolicy, RunIdMode, SkipReason, Snapshot, WitnessRecord, ACCESS_LOG_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

use crate::config::Config;
use crate::hooks::{
    AnchorAlert, AnchorError, AnchorHost, AnchorWitnessing, Anchoring, BatchInput, BatchReason,
    BatchReceipt, CheckpointView, LeafPlaced, LeafView, RunAnchors,
};
use crate::keys::{self, KeyEntry, ServerKey};

/// Batches in a row that ended short of the independence policy before the
/// `anchor_failed` webhook fires (design 4.7: "for 3 intervals").
pub const SHORT_BATCHES_ALERT: u32 = 3;

/// How the library reaches witnesses. The defaults are the design's; tests
/// shorten the timing and may route requests elsewhere.
#[derive(Clone)]
pub struct Options {
    pub tsa_policy: TsaPolicy,
    pub retry: RetryPolicy,
    pub transport: Arc<dyn HttpTransport>,
    pub openssl: OpensslVerifier,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            tsa_policy: TsaPolicy::default(),
            retry: RetryPolicy::default(),
            transport: Arc::new(UreqTransport::new()),
            openssl: OpensslVerifier::default(),
        }
    }
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("tsa_policy", &self.tsa_policy)
            .field("retry", &self.retry)
            .finish()
    }
}

/// The [`Anchoring`] hook over the anchoring library. See the module
/// documentation.
pub struct LibraryAnchoring {
    anchorer: Anchorer,
    /// At least one external witness is configured.
    independent: bool,
    /// Every key that has signed this log's checkpoints (the key ring),
    /// for `verify-data`.
    log_keys: Vec<VerifierKey>,
    /// `<data_dir>`, where the hold file lives.
    data_dir: PathBuf,
    /// The hold, if anchoring is held (see the module documentation).
    hold: Mutex<Option<Hold>>,
    /// Problems a pass over the log found without stopping (a batch index
    /// missing or not matching its leaves), alerted on by the next batch
    /// or retry pass.
    problems: Mutex<Vec<String>>,
}

/// `anchors/hold.json`: why no checkpoint may be signed until an
/// administrator re-establishes the log (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hold {
    pub reason: String,
    pub since: String,
    /// The log's latest checkpoint when the hold was placed.
    pub latest_seq: Option<u64>,
    pub latest_tree_size: u64,
}

/// `<data_dir>/anchors/hold.json`.
pub fn hold_path(data_dir: &Path) -> PathBuf {
    anchors_dir(data_dir).join("hold.json")
}

/// The hold on a data directory's anchor log, if there is one.
pub fn read_hold(data_dir: &Path) -> Result<Option<Hold>, String> {
    let path = hold_path(data_dir);
    crate::fsutil::read_json(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Place a hold (atomically, durably).
pub fn write_hold(data_dir: &Path, hold: &Hold) -> Result<(), String> {
    let path = hold_path(data_dir);
    crate::fsutil::create_dir_durable(&anchors_dir(data_dir)).map_err(|e| e.to_string())?;
    crate::fsutil::write_json_atomic(&path, hold).map_err(|e| format!("{}: {e}", path.display()))
}

/// Lift the hold (durably).
pub fn clear_hold(data_dir: &Path) -> Result<(), String> {
    let path = hold_path(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => crate::fsutil::fsync_dir(&anchors_dir(data_dir)).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// How an administrator lifts a hold, for messages.
pub const HOLD_HELP: &str = "anchoring is held: no checkpoint is signed until an administrator \
     re-establishes the anchor log with `pragmatic-server confirm-anchors` (docs/server.md, \
     \"Restoring the anchor log\")";

impl std::fmt::Debug for LibraryAnchoring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibraryAnchoring")
            .field("anchorer", &self.anchorer)
            .finish()
    }
}

fn err(e: impl std::fmt::Display) -> AnchorError {
    AnchorError(e.to_string())
}

/// `<data_dir>/anchors`.
pub fn anchors_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("anchors")
}

/// The run id mode `[anchoring] anchor_run_ids` selects, with the anchor
/// key read for `hmac`.
fn id_mode(config: &Config) -> Result<RunIdMode, String> {
    match config.anchoring.anchor_run_ids.as_str() {
        "hmac" => keys::load_anchor_key(&config.keys.anchor_key_file)
            .map(|key| RunIdMode::Hmac { key })
            .map_err(|e| e.to_string()),
        _ => Ok(RunIdMode::Plain),
    }
}

/// Refuse to start TSAs with an `openssl` that cannot verify their tokens
/// as the design requires (`ts -verify ... -partial_chain`): LibreSSL, or
/// none at all. Without this, every token would fail verification and the
/// log would never be independently anchored, which the operator would
/// only learn from the anchoring lag.
pub fn check_openssl(openssl: &OpensslVerifier) -> Result<String, String> {
    let version = openssl
        .version()
        .map_err(|e| format!("anchoring: TSAs are configured but {e}"))?;
    if !version.starts_with("OpenSSL") {
        return Err(format!(
            "anchoring: TSA tokens are verified with OpenSSL, and `openssl` on PATH is {version}"
        ));
    }
    let help = Command::new("openssl")
        .args(["ts", "-help"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("anchoring: cannot run openssl: {e}"))?;
    let mut text = String::from_utf8_lossy(&help.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&help.stderr));
    if !text.contains("-partial_chain") {
        return Err(format!(
            "anchoring: {version} cannot verify against pinned issuing CAs (its `ts` command has \
             no -partial_chain); install a current OpenSSL"
        ));
    }
    Ok(version)
}

impl LibraryAnchoring {
    /// Open the anchor log under `config.data_dir` (recovering it) with the
    /// configured witnesses. Call with the data directory's server lock
    /// held. Returns the recovery report's notes to print.
    pub fn open(
        config: &Config,
        key: &ServerKey,
        ring: &[KeyEntry],
        options: Options,
    ) -> Result<(LibraryAnchoring, Vec<String>), String> {
        let a = &config.anchoring;
        let mut witnesses = Vec::new();
        if !a.tsa.is_empty() {
            check_openssl(&options.openssl)?;
        }
        for t in &a.tsa {
            let cfg = LibTsaConfig::new(&t.url, &t.operator, &t.roots_pem)
                .map_err(|e| format!("anchoring.tsa {}: {e}", t.url))?;
            witnesses.push(ExternalWitness::Tsa(TsaClient::new(
                cfg,
                options.tsa_policy,
                options.transport.clone(),
                options.openssl.clone(),
            )));
        }
        for w in &a.witness {
            let vkey = VerifierKey::parse(&w.vkey)
                .map_err(|e| format!("anchoring.witness {}: {e}", w.url))?;
            let token = if w.token_file.as_os_str().is_empty() {
                None
            } else {
                let text = std::fs::read_to_string(&w.token_file).map_err(|e| {
                    format!(
                        "anchoring.witness {}: {}: {e}",
                        w.url,
                        w.token_file.display()
                    )
                })?;
                Some(text.trim().to_string())
            };
            let operator = Some(w.operator.as_str()).filter(|o| !o.trim().is_empty());
            let cfg = LibWitnessConfig::new(&w.url, vkey, operator, token)
                .map_err(|e| format!("anchoring.witness {}: {e}", w.url))?;
            witnesses.push(ExternalWitness::Cosigner(WitnessClient::new(
                cfg,
                options.transport.clone(),
            )));
        }
        let independent = !witnesses.is_empty();
        let anchorer_config = AnchorerConfig {
            id_mode: id_mode(config)?,
            // The server's own signature never counts (design 4.7), so the
            // policy needs at least one operator even if a caller passed 0.
            policy: IndependencePolicy {
                min_independent_operators: (a.min_independent_operators as usize).max(1),
            },
            retry: options.retry,
        };
        let (anchorer, report) = Anchorer::open(
            anchors_dir(&config.data_dir),
            key.log_signer(),
            witnesses,
            anchorer_config,
        )
        .map_err(|e| format!("anchoring: {e}"))?;
        let hold = read_hold(&config.data_dir).map_err(|e| format!("anchoring: {e}"))?;
        let mut notes = Vec::new();
        if let Some(h) = &hold {
            notes.push(format!("{HOLD_HELP}. Held since {}: {}", h.since, h.reason));
        }
        if let Some(p) = &report.moved_aside {
            notes.push(format!(
                "anchoring: {} uncommitted bytes moved aside to {}",
                report.uncommitted_bytes,
                p.display()
            ));
        }
        for seq in &report.missing_batch_index {
            notes.push(format!(
                "anchoring: the batch index of checkpoint {seq} is missing"
            ));
        }
        Ok((
            LibraryAnchoring {
                anchorer,
                independent,
                log_keys: log_keys(key, ring),
                data_dir: config.data_dir.clone(),
                hold: Mutex::new(hold),
                problems: Mutex::new(Vec::new()),
            },
            notes,
        ))
    }

    /// The log alone, without witnesses, for work on a stopped server's
    /// data (`restore`, `verify-data --offline`).
    pub fn open_offline(config: &Config) -> Result<LibraryAnchoring, String> {
        let key = ServerKey::load(&config.keys.signing_key_file).map_err(|e| e.to_string())?;
        let ring = keys::read_key_ring(&config.data_dir).unwrap_or_default();
        let anchorer_config = AnchorerConfig {
            id_mode: id_mode(config)?,
            policy: IndependencePolicy {
                min_independent_operators: (config.anchoring.min_independent_operators as usize)
                    .max(1),
            },
            retry: RetryPolicy::default(),
        };
        let (anchorer, _) = Anchorer::open(
            anchors_dir(&config.data_dir),
            key.log_signer(),
            Vec::new(),
            anchorer_config,
        )
        .map_err(|e| format!("anchoring: {e}"))?;
        let hold = read_hold(&config.data_dir).map_err(|e| format!("anchoring: {e}"))?;
        Ok(LibraryAnchoring {
            anchorer,
            independent: false,
            log_keys: log_keys(&key, &ring),
            data_dir: config.data_dir.clone(),
            hold: Mutex::new(hold),
            problems: Mutex::new(Vec::new()),
        })
    }

    /// The library, for tests and diagnostics.
    pub fn anchorer(&self) -> &Anchorer {
        &self.anchorer
    }

    fn policy(&self) -> &IndependencePolicy {
        &self.anchorer.config().policy
    }

    fn plain_ids(&self) -> bool {
        matches!(self.anchorer.config().id_mode, RunIdMode::Plain)
    }

    /// The hold, if anchoring is held.
    fn current_hold(&self) -> Option<Hold> {
        self.hold.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Hold anchoring (see the module documentation), on disk first so a
    /// restart keeps it. The first hold's reason is kept.
    fn place_hold(&self, reason: &str) {
        let mut held = self.hold.lock().unwrap_or_else(|p| p.into_inner());
        if held.is_some() {
            return;
        }
        let latest = self.anchorer.log().latest_checkpoint();
        let hold = Hold {
            reason: reason.to_string(),
            since: crate::timefmt::now_rfc3339(),
            latest_seq: latest.map(|c| c.seq),
            latest_tree_size: latest.map_or(0, |c| c.tree_size),
        };
        if let Err(e) = write_hold(&self.data_dir, &hold) {
            eprintln!("pragmatic-server: anchoring: placing the hold: {e}");
        }
        *held = Some(hold);
    }

    /// Note a problem a pass over the log found, for the next report (once,
    /// however many passes find it before then).
    fn problem(&self, why: String) {
        let mut problems = self.problems.lock().unwrap_or_else(|p| p.into_inner());
        if !problems.contains(&why) {
            eprintln!("pragmatic-server: anchoring: {why}");
            problems.push(why);
        }
    }

    /// Tell the server what a batch or a retry pass did.
    fn report(&self, host: &dyn AnchorHost, input: Option<&BatchInput>, outcome: &BatchOutcome) {
        let problems =
            std::mem::take(&mut *self.problems.lock().unwrap_or_else(|p| p.into_inner()));
        for why in problems {
            host.alert(AnchorAlert::Failed { reason: why });
        }
        for fork in &outcome.forks {
            self.place_hold(fork);
            host.alert(AnchorAlert::Fork {
                reason: fork.clone(),
            });
        }
        let runs: Vec<(String, u64)> = outcome
            .advanced
            .iter()
            .filter(|a| a.leaf_type == LeafType::Run)
            .map(|a| (a.id.clone(), a.entries))
            .collect();
        if !runs.is_empty() {
            host.anchored(&runs);
        }
        for skip in &outcome.skipped {
            let run_id = (skip.leaf_type == LeafType::Run).then(|| skip.id.clone());
            match skip.reason {
                SkipReason::Unchanged => {}
                SkipReason::Regressed { anchored } => host.alert(AnchorAlert::Contradicted {
                    run_id,
                    anchored_entries: anchored,
                    reason: format!(
                        "the journal holds fewer entries than its leaf in the anchor log, which \
                         covers {anchored}: it was rolled back after it was anchored"
                    ),
                }),
                SkipReason::HeadMismatch => {
                    let entries = input
                        .and_then(|i| entries_of(i, skip.leaf_type, &skip.id))
                        .unwrap_or(0);
                    host.alert(AnchorAlert::Contradicted {
                        run_id,
                        anchored_entries: entries,
                        reason: format!(
                            "the journal's head after {entries} entries is not the head its \
                             leaf in the anchor log records: it was rewritten after it was \
                             anchored"
                        ),
                    })
                }
                SkipReason::InvalidId => host.alert(AnchorAlert::Failed {
                    reason: format!("{:?} cannot be anchored: not a valid id", skip.id),
                }),
            }
        }
        for attempt in &outcome.attempts {
            if let Err(why) = &attempt.result {
                host.alert(AnchorAlert::WitnessFailed {
                    seq: attempt.seq,
                    witness: attempt.witness.clone(),
                    reason: why.clone(),
                });
            }
        }
        for e in &outcome.errors {
            host.alert(AnchorAlert::Failed { reason: e.clone() });
        }
        if outcome.committed.is_some() {
            let short = self.anchorer.status().consecutive_short_batches;
            if short >= SHORT_BATCHES_ALERT && self.independent {
                host.alert(AnchorAlert::Failed {
                    reason: format!(
                        "{short} batches in a row ended short of min_independent_operators = {}: \
                         the checkpoints are not independently anchored",
                        self.policy().min_independent_operators
                    ),
                });
            }
        }
    }

    /// The plain ids of batch `seq`'s leaves (`leaves`, from leaf `from`),
    /// from its batch index when the index is there and matches the leaves
    /// (each entry's index, type and id, recomputed in the log's id mode),
    /// as the library's own `batch_leaves` checks it. Otherwise each leaf's
    /// id is read from the leaf where it is plain (the access log's always
    /// is; a run's only under plain ids), and `None` where it cannot be
    /// known. The second value says why the index was not used.
    fn batch_ids(
        &self,
        log: &pragmatic_anchor::AnchorLog,
        seq: u64,
        from: u64,
        leaves: &[Leaf],
    ) -> (Vec<Option<String>>, Option<String>) {
        let mode = &self.anchorer.config().id_mode;
        let checked = log
            .batch_index(seq)
            .map_err(|e| e.to_string())
            .and_then(|index| {
                if index.len() != leaves.len() {
                    return Err(format!(
                        "it lists {} leaves, the log holds {}",
                        index.len(),
                        leaves.len()
                    ));
                }
                index
                    .into_iter()
                    .zip(leaves)
                    .enumerate()
                    .map(|(k, (b, leaf))| {
                        let ok = b.leaf_index == from + k as u64
                            && b.leaf_type == leaf.leaf_type
                            && mode.leaf_id(b.leaf_type, &b.id) == leaf.id;
                        ok.then_some(Some(b.id))
                            .ok_or_else(|| format!("it does not match leaf {}", from + k as u64))
                    })
                    .collect::<Result<Vec<_>, _>>()
            });
        match checked {
            Ok(ids) => (ids, None),
            Err(why) => {
                let ids = leaves
                    .iter()
                    .map(|leaf| match leaf.leaf_type {
                        LeafType::AccessLog => {
                            Some(String::from_utf8_lossy(ACCESS_LOG_ID).into_owned())
                        }
                        LeafType::Run if self.plain_ids() => {
                            String::from_utf8(leaf.id.clone()).ok()
                        }
                        LeafType::Run => None,
                    })
                    .collect();
                (ids, Some(why))
            }
        }
    }

    /// One checkpoint as the anchors API serves it.
    fn view(&self, seq: u64, from: u64) -> Result<CheckpointView, AnchorError> {
        let (stored, records, leaves, ids) = {
            let log = self.anchorer.log();
            let stored = log.checkpoint(seq).map_err(err)?;
            let records = log.witnesses(seq).map_err(err)?;
            let leaves = log.read_leaves(from, stored.tree_size()).map_err(err)?;
            let (ids, _) = self.batch_ids(&log, seq, from, &leaves);
            (stored, records, leaves, ids)
        };
        let mut body = to_serde(&stored.to_json());
        body["witnesses"] = records
            .iter()
            .map(|r| to_serde(&r.to_json()))
            .collect::<Vec<_>>()
            .into();
        body["independent"] = self
            .policy()
            .is_independent(records.iter().map(|r| r.operator.as_str()))
            .into();
        let leaves = leaves
            .into_iter()
            .zip(ids)
            .enumerate()
            .map(|(k, (leaf, id))| self.leaf_view(from + k as u64, &leaf, id, None))
            .collect();
        Ok(CheckpointView { seq, body, leaves })
    }

    /// One leaf as the anchors API serves it. The plain run id is shown
    /// only when leaves carry plain ids (it is in the leaf then anyway);
    /// it is always kept for filtering by scope.
    fn leaf_view(
        &self,
        index: u64,
        leaf: &Leaf,
        plain_id: Option<String>,
        proof: Option<(u64, Vec<[u8; 32]>)>,
    ) -> LeafView {
        let access_log = leaf.leaf_type == LeafType::AccessLog;
        let run_id = match leaf.leaf_type {
            LeafType::Run => plain_id,
            LeafType::AccessLog => None,
        };
        let mut body = json!({
            "index": index,
            "type": leaf.leaf_type.name(),
            "leaf": hex_encode(&leaf.encode()),
            "entries": leaf.entries,
            "head": hex_encode(&leaf.head),
            "prev_leaf_index": leaf.prev_leaf_index,
        });
        if self.plain_ids() {
            body["run_id"] = run_id.clone().into();
        }
        if let Some((tree_size, proof)) = proof {
            body["tree_size"] = tree_size.into();
            body["inclusion_proof"] = proof
                .iter()
                .map(|h| hex_encode(h))
                .collect::<Vec<_>>()
                .into();
        }
        LeafView {
            index,
            access_log,
            run_id,
            body,
        }
    }

    /// One pass over the whole log: every object's last leaf, and every
    /// run's largest `entries` among its independently anchored leaves.
    ///
    /// A checkpoint whose batch index is missing or does not match its
    /// leaves does not stop the pass (one lost file must not switch off
    /// missing-run and regression detection for every run): its leaves are
    /// read by the ids they carry where those are plain, the rest are
    /// skipped, and the problem is alerted on.
    fn scan(&self) -> Result<(Vec<LeafPlaced>, HashMap<String, u64>), AnchorError> {
        let metas = self.anchorer.log().checkpoints().to_vec();
        let mut last: BTreeMap<(u8, String), LeafPlaced> = BTreeMap::new();
        let mut anchored: HashMap<String, u64> = HashMap::new();
        let mut from = 0u64;
        for meta in metas {
            let (leaves, ids, why, records) = {
                let log = self.anchorer.log();
                let leaves = log.read_leaves(from, meta.tree_size).map_err(err)?;
                let (ids, why) = self.batch_ids(&log, meta.seq, from, &leaves);
                let records = log.witnesses(meta.seq).map_err(err)?;
                (leaves, ids, why, records)
            };
            if let Some(why) = why {
                let unmapped = ids.iter().filter(|i| i.is_none()).count();
                self.problem(format!(
                    "the batch index of checkpoint {} cannot be used ({why}); its leaves were \
                     read from the log{}",
                    meta.seq,
                    if unmapped > 0 {
                        format!(
                            ", and {unmapped} leaves with HMAC run ids could not be mapped to runs"
                        )
                    } else {
                        String::new()
                    }
                ));
            }
            let independent = self
                .policy()
                .is_independent(records.iter().map(|r| r.operator.as_str()));
            for (k, (leaf, id)) in leaves.iter().zip(ids).enumerate() {
                let Some(id) = id else { continue };
                let run_id = (leaf.leaf_type == LeafType::Run).then(|| id.clone());
                last.insert(
                    (leaf.leaf_type.byte(), id.clone()),
                    LeafPlaced {
                        run_id,
                        entries: leaf.entries,
                        leaf_index: from + k as u64,
                        head: leaf.head,
                    },
                );
                if independent && leaf.leaf_type == LeafType::Run {
                    let a = anchored.entry(id).or_insert(0);
                    *a = (*a).max(leaf.entries);
                }
            }
            from = meta.tree_size;
        }
        Ok((last.into_values().collect(), anchored))
    }
}

/// The verifier keys of every log key in the ring (and the current one),
/// under the log's origin.
pub(crate) fn log_keys(key: &ServerKey, ring: &[KeyEntry]) -> Vec<VerifierKey> {
    let mut publics: BTreeSet<[u8; 32]> = ring
        .iter()
        .filter_map(|k| hex_decode_exact::<32>(&k.public_key).ok())
        .collect();
    publics.insert(key.public_key());
    publics
        .into_iter()
        .filter_map(|pk| VerifierKey::new(key.origin(), SignatureType::Ed25519, pk).ok())
        .collect()
}

/// The entries of the snapshot of `(leaf_type, id)` in a batch's input.
fn entries_of(input: &BatchInput, leaf_type: LeafType, id: &str) -> Option<u64> {
    match leaf_type {
        LeafType::Run => input
            .runs
            .iter()
            .find(|t| t.run_id == id)
            .map(|t| t.entries),
        LeafType::AccessLog => input.access_log.as_ref().map(|l| l.entries),
    }
}

/// The library's snapshots for a batch's input.
fn snapshots(input: &BatchInput) -> Vec<Snapshot> {
    let mut out: Vec<Snapshot> = input
        .runs
        .iter()
        .map(|t| Snapshot {
            leaf_type: LeafType::Run,
            id: t.run_id.clone(),
            entries: t.entries,
            head: t.head,
        })
        .collect();
    if let Some(log) = &input.access_log {
        out.push(Snapshot {
            leaf_type: LeafType::AccessLog,
            id: String::from_utf8_lossy(ACCESS_LOG_ID).into_owned(),
            entries: log.entries,
            head: log.head,
        });
    }
    out
}

/// The core's JSON as `serde_json`.
fn to_serde(doc: &Json) -> JsonValue {
    serde_json::from_str(&doc.to_string()).unwrap_or(JsonValue::Null)
}

/// A stored witness object as an evidence bundle's witness (design 5.1).
fn bundle_witness(record: &WitnessRecord) -> Option<BundleWitness> {
    let o = &record.object;
    let text = |k: &str| o.get(k).and_then(Json::as_str).map(str::to_string);
    match text("type")?.as_str() {
        "rfc3161" => Some(BundleWitness::Rfc3161 {
            tsa: text("tsa")?,
            operator: text("operator")?,
            token: base64_decode(&text("token")?).ok()?,
            certs_pem: text("certs_pem")?,
        }),
        "cosignature" => Some(BundleWitness::Cosignature {
            name: text("name")?,
            line: text("line")?,
        }),
        _ => None,
    }
}

impl Anchoring for LibraryAnchoring {
    fn independent(&self) -> bool {
        self.independent
    }

    fn anchor(
        &self,
        host: &dyn AnchorHost,
        input: BatchInput,
        _reason: BatchReason,
    ) -> Result<Option<BatchReceipt>, AnchorError> {
        if let Some(h) = self.current_hold() {
            return Err(AnchorError(format!("{HOLD_HELP}. {}", h.reason)));
        }
        let snaps = snapshots(&input);
        let provider = move || -> Result<Vec<Snapshot>, String> { Ok(snaps.clone()) };
        let outcome = self.anchorer.run_batch(&provider).map_err(err)?;
        self.report(host, Some(&input), &outcome);
        Ok(outcome.committed.as_ref().map(|c| BatchReceipt {
            seq: c.seq,
            tree_size: c.tree_size(),
            leaves: outcome
                .leaves
                .iter()
                .map(|l| LeafPlaced {
                    run_id: (l.leaf_type == LeafType::Run).then(|| l.id.clone()),
                    entries: l.entries,
                    leaf_index: l.leaf_index,
                    head: l.head,
                })
                .collect(),
        }))
    }

    fn retry(&self, host: &dyn AnchorHost) {
        let outcome = self.anchorer.retry_pending();
        self.report(host, None, &outcome);
    }

    fn checkpoints(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<CheckpointView>, AnchorError> {
        let metas = self.anchorer.log().checkpoints().to_vec();
        let mut out = Vec::new();
        for (i, meta) in metas.iter().enumerate() {
            if after.is_some_and(|a| meta.seq <= a) {
                continue;
            }
            if out.len() == limit {
                break;
            }
            let from = if i == 0 { 0 } else { metas[i - 1].tree_size };
            out.push(self.view(meta.seq, from)?);
        }
        Ok(out)
    }

    fn checkpoint(&self, seq: u64) -> Result<Option<CheckpointView>, AnchorError> {
        let metas = self.anchorer.log().checkpoints().to_vec();
        let Ok(i) = metas.binary_search_by_key(&seq, |c| c.seq) else {
            return Ok(None);
        };
        let from = if i == 0 { 0 } else { metas[i - 1].tree_size };
        self.view(seq, from).map(Some)
    }

    fn leaves(&self, from: u64, to: u64, with_proofs: bool) -> Result<Vec<LeafView>, AnchorError> {
        let log = self.anchorer.log();
        let to = to.min(log.size());
        if from >= to {
            return Ok(Vec::new());
        }
        let leaves = log.read_leaves(from, to).map_err(err)?;
        // Plain ids, for filtering by scope, from the batch indexes the
        // range touches (checked against their leaves).
        let mut ids: HashMap<u64, String> = HashMap::new();
        let metas = log.checkpoints();
        let first = metas.partition_point(|c| c.tree_size <= from);
        for (i, meta) in metas.iter().enumerate().skip(first) {
            let start = if i == 0 { 0 } else { metas[i - 1].tree_size };
            let batch = log.read_leaves(start, meta.tree_size).map_err(err)?;
            let (batch_ids, _) = self.batch_ids(&log, meta.seq, start, &batch);
            for (k, id) in batch_ids.into_iter().enumerate() {
                let index = start + k as u64;
                if let (true, Some(id)) = ((from..to).contains(&index), id) {
                    ids.insert(index, id);
                }
            }
            if meta.tree_size >= to {
                break;
            }
        }
        let latest = log.latest_checkpoint().map_or(0, |c| c.tree_size);
        let mut out = Vec::with_capacity(leaves.len());
        for (k, leaf) in leaves.iter().enumerate() {
            let index = from + k as u64;
            let proof = if with_proofs {
                Some((latest, log.inclusion_proof(index, latest).map_err(err)?))
            } else {
                None
            };
            out.push(self.leaf_view(index, leaf, ids.remove(&index), proof));
        }
        Ok(out)
    }

    /// Re-verify the log through the live handle: every checkpoint file
    /// reads and agrees with the log, its signature verifies with a key of
    /// the ring under the log's origin, each tree is consistent with the
    /// previous one by its stored proof, and the latest root is recomputed
    /// from every leaf's data. (Opening the log at startup did the same,
    /// and checked every `prev_leaf_index` chain.)
    fn verify(&self) -> Result<JsonValue, AnchorError> {
        let metas = self.anchorer.log().checkpoints().to_vec();
        let mut failures: Vec<String> = Vec::new();
        let mut prev: Option<(u64, [u8; 32])> = None;
        for meta in &metas {
            let stored = match self.anchorer.log().checkpoint(meta.seq) {
                Ok(s) => s,
                Err(e) => {
                    failures.push(format!("checkpoint {}: {e}", meta.seq));
                    continue;
                }
            };
            if stored.tree_size() != meta.tree_size || stored.root() != meta.root {
                failures.push(format!(
                    "checkpoint {} names another tree than the log holds",
                    meta.seq
                ));
            }
            let signed = note::Note::parse(&stored.signed.note)
                .map_err(|e| e.to_string())
                .and_then(|n| note::verify_note(&n, &self.log_keys).map_err(|e| e.to_string()));
            if let Err(why) = signed {
                failures.push(format!("checkpoint {} signature: {why}", meta.seq));
            }
            if let Some((size, root)) = prev {
                let consistent = stored.prev_tree_size == size
                    && (size == 0
                        || merkle::verify_consistency(
                            size,
                            meta.tree_size,
                            &root,
                            &meta.root,
                            &stored.consistency_from_prev,
                        ));
                if !consistent {
                    failures.push(format!(
                        "checkpoint {} is not consistent with checkpoint {}",
                        meta.seq,
                        meta.seq.saturating_sub(1)
                    ));
                }
            }
            prev = Some((meta.tree_size, meta.root));
        }
        let size = metas.last().map_or(0, |m| m.tree_size);
        let mut hashes = Vec::with_capacity(size as usize);
        const STEP: u64 = 4096;
        let mut at = 0;
        while at < size {
            let end = (at + STEP).min(size);
            match self.anchorer.log().read_leaves(at, end) {
                Ok(leaves) => hashes.extend(leaves.iter().map(Leaf::hash)),
                Err(e) => {
                    failures.push(format!("leaves {at}..{end}: {e}"));
                    break;
                }
            }
            at = end;
        }
        if hashes.len() as u64 == size {
            if let Some(last) = metas.last() {
                if merkle::root(&hashes) != last.root {
                    failures.push(format!(
                        "the leaves do not reproduce checkpoint {}'s root",
                        last.seq
                    ));
                }
            }
        }
        let status = self.anchorer.status();
        Ok(json!({
            "ok": failures.is_empty(),
            "checkpoints": metas.len(),
            "leaves": size,
            "latest_independent_seq": status.latest_independent_seq,
            "pending_witness_results": status.pending.len(),
            "failures": failures,
            "held": self.current_hold().map(|h| h.reason),
        }))
    }

    fn anchored_lengths(&self) -> Result<HashMap<String, u64>, AnchorError> {
        self.scan().map(|(_, anchored)| anchored)
    }

    fn last_leaves(&self) -> Result<Vec<LeafPlaced>, AnchorError> {
        self.scan().map(|(last, _)| last)
    }

    fn latest_seq(&self) -> Option<u64> {
        self.anchorer.log().latest_checkpoint().map(|c| c.seq)
    }

    fn has_leaf(&self, run_id: &str) -> Result<bool, AnchorError> {
        let id = self
            .anchorer
            .config()
            .id_mode
            .leaf_id(LeafType::Run, run_id);
        Ok(self
            .anchorer
            .log()
            .latest_leaf(LeafType::Run, &id)
            .is_some())
    }

    fn held(&self) -> Option<String> {
        self.current_hold().map(|h| h.reason)
    }

    fn run_anchors_through(
        &self,
        run_id: &str,
        through: Option<u64>,
    ) -> Result<RunAnchors, AnchorError> {
        let section = self
            .anchorer
            .anchor_section_through(LeafType::Run, run_id, through)
            .map_err(err)?;
        let mut out = RunAnchors {
            anchor_id: section.anchor_id,
            latest_checkpoint: section.latest_checkpoint.clone(),
            ..RunAnchors::default()
        };
        for a in section.anchors {
            out.witnessing.push(AnchorWitnessing {
                independent: a.independent,
                operators: IndependencePolicy::distinct(
                    a.witnesses.iter().map(|w| w.operator.as_str()),
                ),
                time: a.witnesses.iter().map(|w| w.time).min(),
            });
            out.anchors.push(BundleAnchor {
                seq: a.seq,
                tree_size: a.tree_size,
                leaf_index: a.leaf_index,
                leaf: a.leaf.encode(),
                inclusion_proof: a.inclusion_proof,
                root: a.root,
                checkpoint: a.checkpoint,
                anchor_digest: a.anchor_digest,
                consistency_to_latest: a.consistency_to_latest,
                witnesses: a.witnesses.iter().filter_map(bundle_witness).collect(),
            });
        }
        Ok(out)
    }
}

/// The library opened on demand on a stopped server's data, for `restore`
/// (after the backup is copied in) and `verify-data --offline` (under the
/// data directory's lock, which those commands take).
#[derive(Debug, Clone)]
pub struct OfflineAnchoring {
    pub config: Config,
}

impl OfflineAnchoring {
    fn open(&self) -> Result<LibraryAnchoring, AnchorError> {
        LibraryAnchoring::open_offline(&self.config).map_err(AnchorError)
    }
}

impl Anchoring for OfflineAnchoring {
    fn independent(&self) -> bool {
        false
    }

    fn anchor(
        &self,
        _host: &dyn AnchorHost,
        _input: BatchInput,
        _reason: BatchReason,
    ) -> Result<Option<BatchReceipt>, AnchorError> {
        Err(AnchorError("a stopped server does not anchor".into()))
    }

    fn checkpoints(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<CheckpointView>, AnchorError> {
        self.open()?.checkpoints(after, limit)
    }

    fn checkpoint(&self, seq: u64) -> Result<Option<CheckpointView>, AnchorError> {
        self.open()?.checkpoint(seq)
    }

    fn leaves(&self, from: u64, to: u64, with_proofs: bool) -> Result<Vec<LeafView>, AnchorError> {
        self.open()?.leaves(from, to, with_proofs)
    }

    fn verify(&self) -> Result<JsonValue, AnchorError> {
        self.open()?.verify()
    }

    fn anchored_lengths(&self) -> Result<HashMap<String, u64>, AnchorError> {
        self.open()?.anchored_lengths()
    }

    fn last_leaves(&self) -> Result<Vec<LeafPlaced>, AnchorError> {
        self.open()?.last_leaves()
    }

    fn has_leaf(&self, run_id: &str) -> Result<bool, AnchorError> {
        self.open()?.has_leaf(run_id)
    }
}
