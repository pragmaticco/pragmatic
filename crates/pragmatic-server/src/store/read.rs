//! Reading runs: journal bytes, parsed snapshots, summaries, lists and
//! verification.
//!
//! Readers never write and never wait for writers longer than it takes to
//! copy the index: they take the run's file lock shared (so erasure cannot
//! swap the file underneath them), read the index (entries, byte length,
//! head) under the state lock, and then read exactly that prefix of the
//! file. Appends only extend the file, so the prefix stays valid while they
//! read.

use std::fs::File;
use std::sync::Arc;

use pragmatic::Journal;
use serde_json::{json, Value as JsonValue};

use super::{Run, RunState, Store, VerifyCache};
use crate::error::ApiError;
use crate::fsutil;
use crate::holds::Holds;
use crate::timefmt;

/// The durable prefix of a run.
pub struct Durable {
    pub entries: u64,
    pub head: String,
    pub bytes: Vec<u8>,
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
    pub next: Option<String>,
}

impl Store {
    /// The run's durable prefix as bytes. Holds the file lock shared while
    /// reading.
    pub fn durable(&self, run_id: &str) -> Result<Durable, ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let (entries, head, byte_len) = {
            let st = run.lock();
            if st.deleted {
                return Err(ApiError::run_deleted());
            }
            if st.missing {
                return Err(ApiError::chain_broken("the journal is missing"));
            }
            (st.meta.entries, st.meta.head.clone(), st.meta.byte_len)
        };
        let file = File::open(self.layout.journal(&run.stem))?;
        let bytes = fsutil::read_prefix(&file, byte_len)?;
        Ok(Durable {
            entries,
            head,
            bytes,
        })
    }

    /// The run's durable prefix, parsed (cached by size). A damaged journal
    /// yields its valid prefix.
    pub fn snapshot(&self, run_id: &str) -> Result<Arc<Journal>, ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let (byte_len, broken) = {
            let st = run.lock();
            if st.deleted {
                return Err(ApiError::run_deleted());
            }
            if st.missing {
                return Err(ApiError::chain_broken("the journal is missing"));
            }
            (st.meta.byte_len, st.broken.is_some())
        };
        if let Some(j) = self.cache.lock().expect("cache lock").get(run_id, byte_len) {
            return Ok(j);
        }
        let file = File::open(self.layout.journal(&run.stem))?;
        let bytes = fsutil::read_prefix(&file, byte_len)?;
        let journal = if broken {
            Journal::audit_bytes(&bytes, None)
                .map(|(j, _)| j)
                .map_err(|e| ApiError::chain_broken(&e.to_string()))?
        } else {
            Journal::parse(&bytes, None)
                .map(|p| p.journal)
                .map_err(|e| ApiError::chain_broken(&e.to_string()))?
        };
        let journal = Arc::new(journal);
        self.cache
            .lock()
            .expect("cache lock")
            .put(run_id, byte_len, journal.clone());
        Ok(journal)
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
    pub fn list(&self, q: &ListQuery, holds: &Holds, visible: impl Fn(&str) -> bool) -> RunPage {
        let candidates: Vec<Arc<Run>> = {
            let runs = self.runs.read().expect("runs lock");
            let start = match &q.after {
                Some(a) => std::ops::Bound::Excluded(a.clone()),
                None => std::ops::Bound::Unbounded,
            };
            runs.range((start, std::ops::Bound::Unbounded))
                .filter(|(id, _)| visible(id))
                .filter(|(id, _)| q.prefix.as_ref().is_none_or(|p| id.starts_with(p.as_str())))
                .map(|(_, r)| r.clone())
                .collect()
        };
        let mut out = Vec::new();
        let mut next = None;
        for run in candidates {
            let st = run.lock();
            if st.deleted || !matches(&run.id, &st, q, self.status(&st)) {
                continue;
            }
            if out.len() == q.limit {
                next = out
                    .last()
                    .and_then(|v: &JsonValue| v["run_id"].as_str().map(str::to_string));
                break;
            }
            out.push(self.summary_json(&run, &st, holds));
        }
        RunPage { runs: out, next }
    }

    /// The cached verification report, computed now if there is none.
    fn verify_cached(&self, run: &Run) -> Result<VerifyCache, ApiError> {
        if let Some(v) = run.lock().verify.clone() {
            return Ok(v);
        }
        self.verify_run(run)
    }

    /// Verify a run's whole journal (chain, commitments, erasure
    /// accounting), cache the report, and raise `chain_broken` if it fails.
    pub fn verify_run(&self, run: &Run) -> Result<VerifyCache, ApiError> {
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let (byte_len, entries) = {
            let st = run.lock();
            if st.deleted {
                return Err(ApiError::run_deleted());
            }
            if st.missing {
                return Err(ApiError::chain_broken("the journal is missing"));
            }
            (st.meta.byte_len, st.meta.entries)
        };
        let file = File::open(self.layout.journal(&run.stem))?;
        let bytes = fsutil::read_prefix(&file, byte_len)?;
        let report = match Journal::audit_bytes(&bytes, None) {
            Ok((_, report)) => report,
            Err(e) => {
                let mut st = run.lock();
                self.mark_broken(&run.id, &mut st, e.to_string());
                return Err(ApiError::chain_broken(&e.to_string()));
            }
        };
        let cache = VerifyCache {
            report,
            entries,
            checked_at: timefmt::now_rfc3339(),
        };
        let mut st = run.lock();
        if let Some(bad) = cache.report.first_bad {
            self.mark_broken(
                &run.id,
                &mut st,
                format!("verification failed at cursor {bad}"),
            );
        }
        st.verify = Some(cache.clone());
        Ok(cache)
    }

    /// Verify every run (background, after startup and every
    /// `verify_interval_hours`). Returns `(runs checked, runs failing)`.
    pub fn verify_all(&self) -> (u64, u64) {
        let (mut checked, mut failing) = (0, 0);
        for run in self.all() {
            match self.verify_run(&run) {
                Ok(v) if v.report.is_ok() => checked += 1,
                Ok(_) | Err(_) => {
                    checked += 1;
                    failing += 1;
                }
            }
        }
        (checked, failing)
    }
}

/// The VerifyReport JSON.
pub fn verify_json(v: &VerifyCache) -> JsonValue {
    let r = &v.report;
    json!({
        "ok": r.is_ok(),
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
