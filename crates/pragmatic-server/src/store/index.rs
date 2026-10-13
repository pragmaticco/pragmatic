//! Building the index at startup (design 4.2).
//!
//! Every `runs/<hh>/` directory is read in parallel. For each run:
//!
//! - a **tombstone** registers the id as deleted (and finishes a deletion a
//!   crash interrupted, by removing what is left of the run);
//! - a journal whose size equals `meta.byte_len` and whose last 32 bytes
//!   equal `meta.head` is **trusted** without parsing (a million runs must
//!   index in seconds; full verification runs in the background);
//! - any other journal is **parsed again** and its meta rebuilt. A torn
//!   tail (a crash during an append) is moved aside to
//!   `<64hex>.torn-<unix_ms>` and truncated, and a `torn_tail` note records
//!   it, unless that would cut below `anchored_entries`, which marks the
//!   run damaged instead (the server never truncates anchored history);
//! - **corruption** marks the run damaged (`chain_broken`): readable up to
//!   the damage, never written, never truncated;
//! - meta without a journal is a run created by PUT whose journal was not
//!   yet renamed into place (recreated, when nothing was anchored), or a
//!   **missing** run (`record_missing`);
//! - a run with fewer entries than were anchored is **regressed**.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pragmatic::encoding::hex_encode;
use pragmatic::journal::TornTail;
use pragmatic::sha256::sha256;
use pragmatic::Journal;

use super::{state_from_meta, Meta, Run, RunState, Store, Tombstone};
use crate::fsutil;
use crate::layout::{self, DATA_FORMAT};
use crate::summary::Summary;
use crate::timefmt;

/// What indexing found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexReport {
    pub runs: u64,
    pub trusted: u64,
    pub reparsed: u64,
    pub torn: u64,
    pub tombstones: u64,
    pub broken: Vec<String>,
    pub regressed: Vec<String>,
    pub missing: Vec<String>,
    /// Files that belong to no run (no meta and no `run.start`).
    pub orphans: Vec<PathBuf>,
    pub errors: Vec<String>,
}

impl IndexReport {
    fn merge(&mut self, o: IndexReport) {
        self.runs += o.runs;
        self.trusted += o.trusted;
        self.reparsed += o.reparsed;
        self.torn += o.torn;
        self.tombstones += o.tombstones;
        self.broken.extend(o.broken);
        self.regressed.extend(o.regressed);
        self.missing.extend(o.missing);
        self.orphans.extend(o.orphans);
        self.errors.extend(o.errors);
    }
}

/// The files of one run found in a shard directory.
#[derive(Default)]
struct Found {
    meta: bool,
    journal: bool,
    tombstone: bool,
}

/// One indexed run, before it joins the map.
struct Loaded {
    run: Arc<Run>,
}

impl Store {
    /// Index the data directory. Call once, before serving run endpoints.
    pub fn index(&self) -> IndexReport {
        let shards = match shard_dirs(&self.layout.runs_dir()) {
            Ok(s) => s,
            Err(e) => {
                return IndexReport {
                    errors: vec![format!("runs directory: {e}")],
                    ..IndexReport::default()
                }
            }
        };
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 16);
        let queue = Mutex::new(shards);
        let results = Mutex::new((Vec::new(), Vec::new(), IndexReport::default()));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let Some(dir) = queue.lock().expect("queue").pop() else {
                        break;
                    };
                    let (runs, tombs, report) = self.index_shard(&dir);
                    let mut r = results.lock().expect("results");
                    r.0.extend(runs);
                    r.1.extend(tombs);
                    r.2.merge(report);
                });
            }
        });
        let (runs, tombs, mut report) = results.into_inner().expect("results");
        {
            let mut map = self.runs.write().expect("runs lock");
            for l in runs {
                map.insert(l.run.id.clone(), l.run);
            }
            report.runs = map.len() as u64;
        }
        {
            let mut t = self.tombstones.write().expect("tombstones lock");
            for tomb in tombs {
                t.insert(tomb.run_id.clone(), tomb);
            }
        }
        self.signals.metrics.set_runs(report.runs);
        for id in &report.broken {
            self.signals.metrics.chain_broken();
            self.webhook("chain_broken", id, serde_json::json!({}));
        }
        for id in &report.regressed {
            self.webhook("regressed", id, serde_json::json!({}));
        }
        for id in &report.missing {
            self.webhook("record_missing", id, serde_json::json!({}));
        }
        report
    }

    /// Register a run the anchor log knows but the data directory has no
    /// trace of (neither journal nor tombstone): it is `missing`.
    pub fn register_missing(&self, run_id: &str, anchored_entries: u64) -> bool {
        if self.get(run_id).is_some() || self.is_tombstoned(run_id) {
            return false;
        }
        let mut meta = empty_meta(run_id);
        meta.anchored_entries = anchored_entries;
        let mut st = state_from_meta(meta, self.opts.lease_ttl);
        st.missing = true;
        let run = Arc::new(Run {
            id: run_id.to_string(),
            stem: layout::stem(run_id),
            file: Default::default(),
            state: Mutex::new(st),
        });
        self.runs
            .write()
            .expect("runs lock")
            .insert(run_id.to_string(), run);
        self.webhook(
            "record_missing",
            run_id,
            serde_json::json!({"anchored_entries": anchored_entries}),
        );
        true
    }

    fn index_shard(&self, dir: &Path) -> (Vec<Loaded>, Vec<Tombstone>, IndexReport) {
        let mut report = IndexReport::default();
        let mut runs = Vec::new();
        let mut tombs = Vec::new();
        let found = match scan_shard(dir) {
            Ok(f) => f,
            Err(e) => {
                report.errors.push(format!("{}: {e}", dir.display()));
                return (runs, tombs, report);
            }
        };
        for (stem, f) in found {
            if f.tombstone {
                match self.load_tombstone(&stem) {
                    Ok(t) => {
                        report.tombstones += 1;
                        tombs.push(t);
                    }
                    Err(e) => report.errors.push(e),
                }
                continue;
            }
            match self.load_run(&stem, &f, &mut report) {
                Ok(Some(l)) => runs.push(l),
                Ok(None) => {}
                Err(e) => report.errors.push(e),
            }
        }
        (runs, tombs, report)
    }

    /// Read a tombstone and finish the deletion it records.
    fn load_tombstone(&self, stem: &str) -> Result<Tombstone, String> {
        let path = self.layout.tombstone(stem);
        let t: Tombstone = fsutil::read_json(&path)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{} vanished", path.display()))?;
        if layout::stem(&t.run_id) != stem {
            return Err(format!(
                "{}: run id does not match the file name",
                path.display()
            ));
        }
        for p in [self.layout.journal(stem), self.layout.meta(stem)] {
            match fs::remove_file(&p) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.to_string()),
                _ => {}
            }
        }
        Ok(t)
    }

    fn load_run(
        &self,
        stem: &str,
        f: &Found,
        report: &mut IndexReport,
    ) -> Result<Option<Loaded>, String> {
        let meta_path = self.layout.meta(stem);
        let meta: Option<Meta> = if f.meta {
            match fsutil::read_json::<Meta>(&meta_path) {
                Ok(m) => m,
                Err(e) if f.journal => {
                    report
                        .errors
                        .push(format!("{e}; rebuilding from the journal"));
                    None
                }
                Err(e) => return Err(e.to_string()),
            }
        } else {
            None
        };
        if let Some(m) = &meta {
            if layout::stem(&m.run_id) != stem {
                return Err(format!(
                    "{}: run id does not match the file name",
                    meta_path.display()
                ));
            }
        }
        let jpath = self.layout.journal(stem);
        // A trusted meta is left alone: rewriting a million meta files at
        // startup would cost two fsyncs each.
        let (mut st, id, mut rewrite) = match (meta, f.journal) {
            (Some(m), false) => (self.journal_absent(m, &jpath, report)?, None, true),
            (meta, true) => match self.journal_present(stem, meta, &jpath, report)? {
                Some((st, id)) => {
                    let reparsed = id.is_some();
                    (st, id, reparsed)
                }
                None => return Ok(None),
            },
            (None, false) => return Ok(None),
        };
        let id = id.unwrap_or_else(|| st.meta.run_id.clone());
        if st.meta.entries < st.meta.anchored_entries && !st.meta.regressed {
            st.meta.regressed = true;
            report.regressed.push(id.clone());
            rewrite = true;
        }
        let run = Arc::new(Run {
            id: id.clone(),
            stem: stem.to_string(),
            file: Default::default(),
            state: Mutex::new(st),
        });
        if rewrite && run.lock().broken.is_none() {
            let mut guard = run.lock();
            let st: &mut RunState = &mut guard;
            if let Err(e) = self.write_meta(&run, st) {
                report.errors.push(format!("{id}: meta.json: {e}"));
            }
        }
        Ok(Some(Loaded { run }))
    }

    /// Meta without a journal: recreate the header of a run nothing was
    /// anchored for (a crash between writing meta and the journal on PUT);
    /// otherwise the run is missing.
    fn journal_absent(
        &self,
        meta: Meta,
        jpath: &Path,
        report: &mut IndexReport,
    ) -> Result<RunState, String> {
        let mut st = state_from_meta(meta, self.opts.lease_ttl);
        if st.meta.entries == 0 && st.meta.anchored_entries == 0 {
            fsutil::write_atomic(jpath, &pragmatic::journal::header(0))
                .map_err(|e| e.to_string())?;
            st.meta.byte_len = pragmatic::journal::HEADER_LEN as u64;
            st.meta.head = hex_encode(&Journal::new(None).head());
        } else {
            st.missing = true;
            report.missing.push(st.meta.run_id.clone());
        }
        Ok(st)
    }

    /// A journal, with or without meta. `None` for an orphan.
    fn journal_present(
        &self,
        stem: &str,
        meta: Option<Meta>,
        jpath: &Path,
        report: &mut IndexReport,
    ) -> Result<Option<(RunState, Option<String>)>, String> {
        if let Some(m) = &meta {
            if trusted(jpath, m).map_err(|e| e.to_string())? {
                report.trusted += 1;
                return Ok(Some((
                    state_from_meta(m.clone(), self.opts.lease_ttl),
                    None,
                )));
            }
        }
        report.reparsed += 1;
        let bytes = fs::read(jpath).map_err(|e| format!("{}: {e}", jpath.display()))?;
        let parsed = match Journal::parse(&bytes, None) {
            Ok(p) => p,
            Err(e) => {
                let Some(m) = meta else {
                    report.orphans.push(jpath.to_path_buf());
                    return Ok(None);
                };
                let mut st = state_from_meta(m, self.opts.lease_ttl);
                st.broken = Some(e.to_string());
                report.broken.push(st.meta.run_id.clone());
                return Ok(Some((st, None)));
            }
        };
        let run_id = match (&meta, parsed.journal.run_start_id()) {
            (Some(m), Some(id)) if m.run_id != id => {
                let mut st = state_from_meta(meta.clone().expect("some"), self.opts.lease_ttl);
                st.broken = Some(format!("the journal belongs to run '{id}'"));
                report.broken.push(st.meta.run_id.clone());
                return Ok(Some((st, None)));
            }
            (Some(m), _) => m.run_id.clone(),
            (None, Some(id)) if layout::stem(&id) == stem => id,
            (None, _) => {
                report.orphans.push(jpath.to_path_buf());
                return Ok(None);
            }
        };
        let mut meta = meta.unwrap_or_else(|| empty_meta(&run_id));
        let mut journal = parsed.journal;
        let mut broken = None;
        if parsed.tail_len > 0 {
            if journal.len() < meta.anchored_entries {
                broken = Some(format!(
                    "a torn tail at cursor {} would cut below the {} anchored entries",
                    journal.len(),
                    meta.anchored_entries
                ));
                report.broken.push(run_id.clone());
            } else {
                self.truncate_torn(stem, jpath, &bytes, parsed.valid_len, &mut journal)
                    .map_err(|e| format!("{}: {e}", jpath.display()))?;
                report.torn += 1;
            }
        }
        if broken.is_none() {
            meta.entries = journal.len();
            meta.byte_len = journal.byte_len();
            meta.head = hex_encode(&journal.head());
            meta.summary = Summary::rebuild(&journal, &self.opts.index_key);
        }
        let mut st = state_from_meta(meta, self.opts.lease_ttl);
        st.broken = broken;
        Ok(Some((st, Some(run_id))))
    }

    /// Move a torn tail aside, truncate, and record it with a `torn_tail`
    /// note (when the valid prefix is not empty).
    fn truncate_torn(
        &self,
        stem: &str,
        jpath: &Path,
        bytes: &[u8],
        valid_len: u64,
        journal: &mut Journal,
    ) -> io::Result<()> {
        let tail = &bytes[valid_len as usize..];
        let ms = timefmt::now_unix_ns() / 1_000_000;
        let aside = self.layout.torn(stem, ms);
        fsutil::write_atomic(&aside, tail)?;
        let file = OpenOptions::new().read(true).write(true).open(jpath)?;
        file.set_len(valid_len)?;
        file.sync_all()?;
        if journal.is_empty() {
            return Ok(());
        }
        let torn = TornTail {
            offset: valid_len,
            bytes: tail.len() as u64,
            sha256: sha256(tail),
            moved_to: aside
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            at_cursor: journal.len(),
        };
        journal
            .append_torn_tail(timefmt::now_unix_ns(), &torn)
            .map_err(io::Error::other)?;
        if let Some((_, frames, _)) = journal.pending() {
            fsutil::write_all_at(&file, frames, valid_len)?;
            file.sync_data()?;
        }
        let len = journal.len();
        journal.mark_persisted(len);
        Ok(())
    }
}

/// A meta for a run known only by its id.
fn empty_meta(run_id: &str) -> Meta {
    let now = timefmt::now_rfc3339();
    Meta {
        format: DATA_FORMAT,
        run_id: run_id.to_string(),
        created_at: now.clone(),
        updated_at: now,
        entries: 0,
        byte_len: pragmatic::journal::HEADER_LEN as u64,
        head: hex_encode(&Journal::new(None).head()),
        anchored_entries: 0,
        last_anchor_leaf: None,
        leases: Vec::new(),
        holds: Vec::new(),
        open_intents: Vec::new(),
        status: "idle".into(),
        created_by: None,
        regressed: false,
        summary: Summary::default(),
    }
}

/// The startup shortcut: the size matches `meta.byte_len` and the file
/// ends in `meta.head` (or is just a header for an empty run).
fn trusted(path: &Path, meta: &Meta) -> io::Result<bool> {
    let file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size != meta.byte_len {
        return Ok(false);
    }
    if meta.entries == 0 {
        return Ok(size == pragmatic::journal::HEADER_LEN as u64);
    }
    if size < pragmatic::journal::HEADER_LEN as u64 + 32 {
        return Ok(false);
    }
    let mut last = [0u8; 32];
    fsutil::read_exact_at(&file, &mut last, size - 32)?;
    Ok(hex_encode(&last) == meta.head)
}

/// The `runs/<hh>` directories.
fn shard_dirs(runs: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    match fs::read_dir(runs) {
        Ok(entries) => {
            for e in entries {
                let e = e?;
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.len() == 2 && e.file_type()?.is_dir() {
                    out.push(e.path());
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(out)
}

/// The runs in one shard, by stem.
fn scan_shard(dir: &Path) -> io::Result<BTreeMap<String, Found>> {
    let mut out: BTreeMap<String, Found> = BTreeMap::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let (stem, kind) = match name.split_once('.') {
            Some(x) => x,
            None => continue,
        };
        if !layout::is_stem(stem) {
            continue;
        }
        let f = out.entry(stem.to_string()).or_default();
        match kind {
            "journal" => f.journal = true,
            "meta.json" => f.meta = true,
            "tombstone.json" => f.tombstone = true,
            _ => {}
        }
    }
    out.retain(|_, f| f.journal || f.meta || f.tombstone);
    Ok(out)
}
