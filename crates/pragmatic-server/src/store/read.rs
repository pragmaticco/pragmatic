//! Reading runs: journal bytes, entries, summaries, lists and
//! verification.
//!
//! Readers never write and never wait for writers longer than it takes to
//! copy the index: they take the run's file lock shared (so erasure cannot
//! swap the file underneath them), read the index (entries, byte length,
//! head) under the state lock, and then read exactly that prefix of the
//! file. Appends only extend the file, so the prefix stays valid while they
//! read.
//!
//! What a read holds is bounded by the read, not by the journal:
//!
//! - entries and slots are read frame by frame at their offsets
//!   ([`super::frames`]), at most [`PAGE_BYTES`] of frames per page (and at
//!   least one entry);
//! - a journal download streams from an open descriptor in chunks;
//! - the reads that need a whole journal (verification, evidence, the
//!   valid prefix of a damaged journal) take its size from the store's
//!   [`ByteBudget`](super::ByteBudget) first;
//! - a list examines at most [`LIST_SCAN`] runs per page.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::Arc;

use pragmatic::Journal;
use serde_json::{json, Value as JsonValue};

use super::frames::{self, BudgetGuard, ReadEntry};
use super::{Run, RunState, Store, VerifyCache};
use crate::error::ApiError;
use crate::fsutil;
use crate::holds::Holds;
use crate::timefmt;

/// The most frame bytes one page of entries reads (a single larger entry
/// is still served, alone).
pub const PAGE_BYTES: u64 = 64 << 20;

/// The most runs one list request examines.
pub const LIST_SCAN: usize = 10_000;

/// Runs copied out of the run map per lock acquisition while listing.
const LIST_CHUNK: usize = 256;

/// The durable prefix of a run, held whole (for evidence bundles). Holds
/// its share of the store's byte budget until dropped.
pub struct Durable {
    pub entries: u64,
    pub head: String,
    pub bytes: Vec<u8>,
    /// Why the stored journal is damaged, if it is: `bytes` is then what
    /// the file still holds of the indexed prefix (its valid prefix is all
    /// a reader can use), and `entries` and `head` are the index's.
    pub damaged: Option<String>,
    budget: BudgetGuard,
}

impl Durable {
    /// Keep the budget share after the bytes are gone (for what was built
    /// from them).
    pub fn into_budget(self) -> BudgetGuard {
        self.budget
    }
}

/// `GET /v1/runs` filters.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub prefix: Option<String>,
    /// Matches run ids and label values only, never content.
    pub q: Option<String>,
    pub labels: Vec<(String, String)>,
    pub program: Option<String>,
    pub status: Option<String>,
    /// RFC 3339 bounds on `updated_at`.
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: usize,
    /// Continue after this run id.
    pub after: Option<String>,
}

/// One page of run summaries.
pub struct RunPage {
    pub runs: Vec<JsonValue>,
    /// Where to continue: after the last run returned, or after the last
    /// run examined when the page stopped at [`LIST_SCAN`].
    pub next: Option<String>,
}

/// One page of entries.
pub struct EntryPage {
    pub entries: Vec<ReadEntry>,
    /// Entries in the journal (its valid prefix, for a damaged one).
    pub total: u64,
    /// The cursor to continue from, if the page stopped before the end.
    pub next: Option<u64>,
}

/// An open journal file and the length of its durable prefix, for
/// streaming a download.
///
/// The descriptor would keep reading the old contents after an erasure
/// renamed a new file into place, or after a deletion unlinked it. So a
/// download reads through [`DurableFile::read_at`], which takes the run's
/// file lock shared for each read and refuses once the file's generation
/// has moved: no byte read after an erasure or deletion committed is
/// served, and an erasure never waits for a slow download.
pub struct DurableFile {
    pub file: File,
    pub byte_len: u64,
    pub entries: u64,
    pub head: String,
    run: Arc<Run>,
    generation: u64,
}

impl DurableFile {
    /// Read `buf.len()` bytes at `offset`, unless the journal was erased or
    /// deleted since it was opened.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let _shared = self.run.file.read().unwrap_or_else(|p| p.into_inner());
        if self.run.generation() != self.generation {
            return Err(io::Error::other(
                "the journal was erased or deleted while it was being read",
            ));
        }
        fsutil::read_exact_at(&self.file, buf, offset)
    }
}

/// What a reader copies out of a run's state under its lock.
struct Snapshot {
    entries: u64,
    byte_len: u64,
    head: String,
    broken: Option<String>,
    generation: u64,
}

impl Store {
    /// The run's index, after the checks every read makes. Call with the
    /// file lock held shared.
    fn read_state(&self, run: &Run) -> Result<Snapshot, ApiError> {
        let st = run.lock();
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        if st.missing {
            return Err(ApiError::chain_broken("the journal is missing"));
        }
        Ok(Snapshot {
            entries: st.meta.entries,
            byte_len: st.meta.byte_len,
            head: st.meta.head.clone(),
            broken: st.broken.clone(),
            generation: run.generation(),
        })
    }

    /// Open the run's journal and note its durable prefix, under the file
    /// lock held shared. A damaged journal is refused with `chain_broken`
    /// before anything is streamed: its index may name bytes the file no
    /// longer holds, and raw journal bytes stand for the run's whole
    /// history, which the server knows this file is not. (Entries and the
    /// console serve its valid prefix.)
    pub fn open_durable(&self, run_id: &str) -> Result<DurableFile, ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let s = self.read_state(&run)?;
        if let Some(why) = &s.broken {
            return Err(ApiError::chain_broken(why));
        }
        let file = File::open(self.layout.journal(&run.stem))?;
        Ok(DurableFile {
            file,
            byte_len: s.byte_len,
            entries: s.entries,
            head: s.head,
            run: run.clone(),
            generation: s.generation,
        })
    }

    /// The run's durable prefix as bytes, taken from the byte budget first.
    pub fn durable(&self, run_id: &str) -> Result<Durable, ApiError> {
        self.durable_scaled(run_id, 1)
    }

    /// [`Store::durable`], taking `factor` times the journal's size from
    /// the byte budget, for a reader that builds more from it (an evidence
    /// bundle holds the journal again as base64 and as records). One take,
    /// never two: a reader holding part of the budget while waiting for
    /// more could wait for itself.
    ///
    /// A damaged journal yields what the file still holds of its indexed
    /// prefix, with [`Durable::damaged`] set: never an error for a file
    /// shorter than its index (that damage is permanent, so answering
    /// `storage_unavailable`, which clients resend, would be wrong).
    pub fn durable_scaled(&self, run_id: &str, factor: u64) -> Result<Durable, ApiError> {
        let run = self.find(run_id)?;
        let size = run.lock().meta.byte_len;
        let budget = self.budget.take(size.saturating_mul(factor.max(1)));
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let s = self.read_state(&run)?;
        let bytes = self.read_prefix(&run, s.byte_len, s.broken.is_some())?;
        Ok(Durable {
            entries: s.entries,
            head: s.head,
            bytes,
            damaged: s.broken,
            budget,
        })
    }

    /// Up to `limit` entries from cursor `from`, read from disk frame by
    /// frame (refs resolved), and at most [`PAGE_BYTES`] of frames (at
    /// least one). A damaged journal serves its valid prefix.
    pub fn entries_page(&self, run_id: &str, from: u64, limit: u64) -> Result<EntryPage, ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let s = self.read_state(&run)?;
        if s.broken.is_some() {
            drop(_file);
            return self.damaged_page(&run, from, limit);
        }
        let file = File::open(self.layout.journal(&run.stem))?;
        let end = from.saturating_add(limit).min(s.entries);
        let all = |range| {
            frames::spans(
                &self.frames,
                &run.id,
                s.generation,
                &file,
                s.byte_len,
                s.entries,
                range,
            )
        };
        let spans = all(from.min(end)..end)?;
        let mut targets = HashMap::new();
        let mut out = Vec::with_capacity(spans.len());
        let mut bytes = 0u64;
        for (i, span) in spans.into_iter().enumerate() {
            if bytes > 0 && bytes + span.1 > PAGE_BYTES {
                break;
            }
            bytes += span.1;
            let cursor = from + i as u64;
            let entry = frames::read_entry(&file, cursor, span)?;
            let span_of = |c: u64| all(c..c + 1).ok().and_then(|v| v.first().copied());
            out.push(frames::resolve(&file, entry, &mut targets, &span_of)?);
        }
        let stop = from + out.len() as u64;
        Ok(EntryPage {
            entries: out,
            total: s.entries,
            next: (stop < s.entries).then_some(stop),
        })
    }

    /// One entry (refs resolved), or `None` past the end.
    pub fn entry(&self, run_id: &str, cursor: u64) -> Result<Option<ReadEntry>, ApiError> {
        let page = self.entries_page(run_id, cursor, 1)?;
        Ok(page
            .entries
            .into_iter()
            .next()
            .filter(|e| e.entry.cursor == cursor))
    }

    /// A page of a damaged journal's valid prefix, which only a full parse
    /// can find (under the byte budget).
    fn damaged_page(&self, run: &Run, from: u64, limit: u64) -> Result<EntryPage, ApiError> {
        let journal = self.parse_whole(run)?;
        let total = journal.len();
        let end = from.saturating_add(limit).min(total);
        let entries = (from.min(end)..end)
            .filter_map(|c| journal.get(c))
            .map(|e| ReadEntry::parsed(e.clone()))
            .collect();
        Ok(EntryPage {
            entries,
            total,
            next: (end < total).then_some(end),
        })
    }

    /// The bytes of a run's journal a reader may use: the indexed prefix,
    /// or for a damaged journal (which may be shorter than its index says)
    /// whatever of that prefix the file still holds.
    fn read_prefix(&self, run: &Run, byte_len: u64, broken: bool) -> Result<Vec<u8>, ApiError> {
        let file = File::open(self.layout.journal(&run.stem))?;
        let len = if broken {
            byte_len.min(file.metadata()?.len())
        } else {
            byte_len
        };
        Ok(fsutil::read_prefix(&file, len)?)
    }

    /// The run's durable prefix, parsed whole (a damaged journal yields
    /// its valid prefix), under the byte budget.
    fn parse_whole(&self, run: &Run) -> Result<Journal, ApiError> {
        let size = run.lock().meta.byte_len;
        let _budget = self.budget.take(size);
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let s = self.read_state(run)?;
        let bytes = self.read_prefix(run, s.byte_len, s.broken.is_some())?;
        if s.broken.is_some() {
            Journal::audit_bytes(&bytes, None)
                .map(|(j, _)| j)
                .map_err(|e| ApiError::chain_broken(&e.to_string()))
        } else {
            Journal::parse(&bytes, None)
                .map(|p| p.journal)
                .map_err(|e| ApiError::chain_broken(&e.to_string()))
        }
    }

    /// The stored chain hash of entry `cursor`, from the writer's journal
    /// when it is loaded and otherwise from disk by offset (never by loading
    /// the journal). Call with the file lock held shared and the state lock
    /// held.
    pub(super) fn stored_hash(
        &self,
        run: &Run,
        st: &RunState,
        cursor: u64,
    ) -> Result<Option<[u8; 32]>, ApiError> {
        if cursor >= st.meta.entries {
            return Ok(None);
        }
        if let Some(w) = &st.writer {
            return Ok(w.journal.get(cursor).map(|e| e.hash));
        }
        let file = File::open(self.layout.journal(&run.stem))?;
        let spans = frames::spans(
            &self.frames,
            &run.id,
            run.generation(),
            &file,
            st.meta.byte_len,
            st.meta.entries,
            cursor..cursor + 1,
        )?;
        match spans.first() {
            Some(span) => frames::read_hash(&file, *span).map(Some),
            None => Ok(None),
        }
    }

    /// The run's RunSummary JSON plus its cached verification report.
    pub fn summary(&self, run_id: &str, holds: &Holds) -> Result<JsonValue, ApiError> {
        let run = self.find(run_id)?;
        let (mut out, missing) = {
            let st = run.lock();
            if st.deleted {
                return Err(ApiError::run_deleted());
            }
            (self.summary_json(&run, &st, holds), st.missing)
        };
        out["verify"] = if missing {
            serde_json::json!({"ok": false, "missing": true})
        } else {
            verify_json(&self.verify_cached(&run)?)
        };
        Ok(out)
    }

    /// RunSummary (design 4.4).
    pub(super) fn summary_json(&self, run: &Run, st: &RunState, holds: &Holds) -> JsonValue {
        let m = &st.meta;
        json!({
            "run_id": run.id,
            "entries": m.entries,
            "head": m.head,
            "created_at": m.created_at,
            "updated_at": m.updated_at,
            "status": self.status(st),
            "erased_slots": m.summary.erased_slots,
            "anchored_entries": m.anchored_entries,
            "unanchored_entries": m.entries.saturating_sub(m.anchored_entries),
            "holds": holds.matching(&run.id),
            "labels": m.summary.labels,
            "program": m.summary.program,
            "created_by": m.created_by,
            "last_outcome": m.summary.last_outcome,
            "usage": m.summary.usage,
        })
    }

    /// A page of summaries matching `q`, among the runs `visible` admits.
    ///
    /// Runs are copied out of the run map a chunk at a time (the map's lock
    /// is released between chunks), and at most [`LIST_SCAN`] runs are
    /// examined per page: a filter that matches nothing returns an empty
    /// page and where to continue rather than walking every run.
    pub fn list(&self, q: &ListQuery, holds: &Holds, visible: impl Fn(&str) -> bool) -> RunPage {
        let mut out = Vec::new();
        let mut cursor = q.after.clone();
        let mut examined = 0usize;
        loop {
            let (chunk, last, done) =
                self.list_chunk(q, cursor.as_deref(), &visible, &mut examined);
            for run in chunk {
                let st = run.lock();
                if st.deleted || !matches(&run.id, &st, q, self.status(&st)) {
                    continue;
                }
                out.push(self.summary_json(&run, &st, holds));
                if out.len() == q.limit {
                    return RunPage {
                        runs: out,
                        next: Some(run.id.clone()),
                    };
                }
            }
            match last {
                Some(l) if !done && examined < LIST_SCAN => cursor = Some(l),
                Some(l) if !done => {
                    return RunPage {
                        runs: out,
                        next: Some(l),
                    }
                }
                _ => {
                    return RunPage {
                        runs: out,
                        next: None,
                    }
                }
            }
        }
    }

    /// The next chunk of candidate runs after `after`: those `visible`
    /// admits under the prefix. Returns them, the last id examined, and
    /// whether the map (or the prefix's range) ended.
    fn list_chunk(
        &self,
        q: &ListQuery,
        after: Option<&str>,
        visible: &impl Fn(&str) -> bool,
        examined: &mut usize,
    ) -> (Vec<Arc<Run>>, Option<String>, bool) {
        use std::ops::Bound;
        let runs = self.runs.read().expect("runs lock");
        // A prefix is a contiguous range of the sorted map: start at it.
        let start = match (after, q.prefix.as_deref()) {
            (Some(a), Some(p)) if p > a => Bound::Included(p.to_string()),
            (Some(a), _) => Bound::Excluded(a.to_string()),
            (None, Some(p)) => Bound::Included(p.to_string()),
            (None, None) => Bound::Unbounded,
        };
        let mut chunk = Vec::new();
        let mut last = None;
        for (id, run) in runs.range((start, Bound::Unbounded)) {
            if q.prefix
                .as_ref()
                .is_some_and(|p| !id.starts_with(p.as_str()))
            {
                return (chunk, last, true);
            }
            *examined += 1;
            last = Some(id.clone());
            if visible(id) {
                chunk.push(run.clone());
            }
            if chunk.len() == LIST_CHUNK || *examined >= LIST_SCAN {
                return (chunk, last, false);
            }
        }
        (chunk, last, true)
    }

    /// The cached verification report, computed now if there is none.
    fn verify_cached(&self, run: &Run) -> Result<VerifyCache, ApiError> {
        if let Some(v) = run.lock().verify.clone() {
            return Ok(v);
        }
        self.verify_run(run)
    }

    /// Verify a run's whole journal (chain, commitments, erasure
    /// accounting) under the byte budget, cache the report, and mark the
    /// run damaged unless the report is ok (design 2.13: content erased
    /// without a note is tampering, as a broken chain is).
    ///
    /// A damaged journal never gets an ok report, even when the prefix the
    /// file still holds verifies on its own: a journal that lost
    /// acknowledged entries is not intact. Its report fails at the first
    /// entry it no longer holds (`first_bad`), counts only the entries it
    /// holds (`verified_entries`), and names the damage.
    pub fn verify_run(&self, run: &Run) -> Result<VerifyCache, ApiError> {
        let size = run.lock().meta.byte_len;
        let _budget = self.budget.take(size);
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let s = self.read_state(run)?;
        let bytes = self.read_prefix(run, s.byte_len, s.broken.is_some())?;
        let (held, mut report) = match Journal::audit_bytes(&bytes, None) {
            Ok((journal, report)) => (journal.len(), report),
            Err(e) => {
                let mut st = run.lock();
                self.mark_broken(&run.id, &mut st, e.to_string());
                return Err(ApiError::chain_broken(&e.to_string()));
            }
        };
        drop(bytes);
        let entries = if s.broken.is_some() {
            if report.is_ok() || held < s.entries {
                report.first_bad = Some(report.first_bad.map_or(held, |c| c.min(held)));
            }
            held.min(s.entries)
        } else {
            s.entries
        };
        let cache = VerifyCache {
            report,
            entries,
            checked_at: timefmt::now_rfc3339(),
            damaged: s.broken.clone(),
        };
        let mut st = run.lock();
        self.judge(&run.id, &mut st, &cache.report);
        st.verify = Some(cache.clone());
        Ok(cache)
    }

    /// Verify every run (background, after startup and every
    /// `verify_interval_hours`). Returns the runs checked and the ids of
    /// those failing, in order: a report that is not ok, a damaged or
    /// missing journal, or one that could not be read. The count and the
    /// list are the same set, so verify-data never names a run as failing
    /// without counting it.
    pub fn verify_all(&self) -> (u64, Vec<String>) {
        let mut checked = 0;
        let mut failing = Vec::new();
        for run in self.all() {
            if run.lock().deleted {
                continue;
            }
            checked += 1;
            let ok = matches!(self.verify_run(&run), Ok(v) if v.report.is_ok());
            let st = run.lock();
            if !ok || st.broken.is_some() || st.missing {
                failing.push(run.id.clone());
            }
        }
        failing.sort();
        (checked, failing)
    }

    /// The runs whose journal is damaged or failed verification.
    pub fn failing_run_ids(&self) -> Vec<String> {
        self.all()
            .iter()
            .filter(|r| {
                let st = r.lock();
                !st.deleted && (st.broken.is_some() || st.missing)
            })
            .map(|r| r.id.clone())
            .collect()
    }
}

/// The VerifyReport JSON. `damaged` names why the stored journal is
/// damaged (`null` when it is not); a damaged journal's report is never ok.
pub fn verify_json(v: &VerifyCache) -> JsonValue {
    let r = &v.report;
    json!({
        "ok": r.is_ok() && v.damaged.is_none(),
        "damaged": v.damaged,
        "first_bad": r.first_bad,
        "unaccounted_erasures": r.unaccounted_erasures,
        "erasure_incomplete": r.erasure_incomplete,
        "invalid_erasure_notes": r.invalid_erasure_notes,
        "torn_bytes": r.torn_bytes,
        "verified_entries": v.entries,
        "checked_at": v.checked_at,
    })
}

fn matches(run_id: &str, st: &RunState, q: &ListQuery, status: &str) -> bool {
    let s = &st.meta.summary;
    if let Some(text) = &q.q {
        let hit =
            run_id.contains(text.as_str()) || s.labels.values().any(|v| v.contains(text.as_str()));
        if !hit {
            return false;
        }
    }
    if !q.labels.iter().all(|(k, v)| s.labels.get(k) == Some(v)) {
        return false;
    }
    if let Some(p) = &q.program {
        if s.program.as_ref().is_none_or(|prog| &prog.name != p) {
            return false;
        }
    }
    if q.status.as_deref().is_some_and(|want| want != status) {
        return false;
    }
    let updated = timefmt::parse_rfc3339(&st.meta.updated_at).unwrap_or(0);
    if q.since.is_some_and(|t| updated < t) || q.until.is_some_and(|t| updated > t) {
        return false;
    }
    true
}
