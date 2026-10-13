//! Erasure, shredding, deletion, regression and anchoring bookkeeping
//! (design 4.7, 4.9 and 4.13).
//!
//! # Erasure
//!
//! Erasure takes the run's file lock exclusively, so no reader is halfway
//! through the old file, and its state lock, so no append or lease change
//! interleaves. Before changing anything it checks, in order: holds
//! (`on_hold`), the retention minimum under `deny_during_min`
//! (`retention_locked`), whether the last attempt ended ok (otherwise
//! `allow_unfinished` is needed), the lease (a live lease is `run_locked`
//! unless `force`, which revokes it so the holder's next call gets
//! `lease_lost`), and, when a lease is to end, the selector itself (the
//! core builds the erasure once and drops it): a refused erasure changes
//! nothing, the lease included. Then:
//!
//! 1. the access-log record is made durable, and its cursor goes into the
//!    erasure note (`access_log_cursor`);
//! 2. a lease still recorded is ended with its custody note, and
//!    `meta.json` is written at once, so a crash cannot bring the lease
//!    back after its custody note says it ended;
//! 3. the core builds and validates the erased file (design 2.13);
//! 4. the erasure ledger gets its record (fsynced) *before* anything is
//!    committed: a restore re-applies the ledger, so an erasure must never
//!    be committed without its record (a record whose erasure then fails to
//!    commit is harmless: re-applying it erases what was asked);
//! 5. moved-aside torn tails of the run are removed (they may hold the
//!    same content);
//! 6. the file is committed: temp file, fsync, rename, directory fsync,
//!    and the file generation advances, so a download in flight stops;
//! 7. the index and `meta.json` are updated (a `meta.json` that cannot be
//!    written is left to the flusher: the journal is the record), and the
//!    subjects index entries go if `run.start`'s payload was erased;
//! 8. the `erasure` webhook fires.
//!
//! # Deletion
//!
//! A retention delete writes its ledger record, then the tombstone. Once
//! the tombstone is durable the deletion has happened: the run leaves the
//! run map (its tombstone joins the tombstones first, so a `PUT` in
//! between cannot recreate it), and its files are removed. A file that
//! cannot be removed is removed at the next start, which finishes every
//! deletion a tombstone records; the run never takes another write.

use std::fs::OpenOptions;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{EraseSelector, ErasureNote};
use pragmatic::Journal;
use serde_json::{json, Value as JsonValue};

use super::{EndReason, LeafRef, RunState, Store, Tombstone, VerifyCache, Writer};
use crate::access_log::{AccessLog, AccessRecord};
use crate::config::RetentionPolicy;
use crate::error::ApiError;
use crate::fsutil;
use crate::holds::Holds;
use crate::hooks::{LeafPlaced, RunTip};
use crate::ledger::{Ledger, LedgerKind, LedgerRecord};
use crate::policy;
use crate::summary::Summary;
use crate::timefmt;

/// Which slots to erase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Slots(Vec<(u64, u8)>),
    Match(String),
    All,
}

/// An erasure request, after the HTTP layer checked it.
#[derive(Debug, Clone)]
pub struct EraseParams {
    pub selector: Selector,
    pub reason_code: String,
    /// Free text, stored in the note's payload slot.
    pub reason: String,
    pub force: bool,
    pub allow_unfinished: bool,
    /// The token id (or `server:retention`); never a client-supplied value.
    pub by: String,
    pub kind: LedgerKind,
}

/// What an erasure did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraseOutcome {
    pub slots: Vec<(u64, u8)>,
    pub note_cursor: u64,
    pub entries: u64,
    pub head: String,
    pub access_log_cursor: u64,
    /// False when the run's last attempt did not end ok: it can no longer
    /// be resumed.
    pub can_resume: bool,
    pub ledger_seq: u64,
}

/// What erasure needs besides the run.
pub struct EraseContext<'a> {
    pub holds: &'a Holds,
    pub policies: &'a [RetentionPolicy],
    pub access: &'a AccessLog,
    pub ledger: &'a Ledger,
    /// The access-log record to make durable before acting.
    pub intent: AccessRecord,
}

impl Store {
    /// Erase slots of a run (see the module documentation).
    pub fn erase(
        &self,
        run_id: &str,
        p: &EraseParams,
        cx: EraseContext<'_>,
    ) -> Result<EraseOutcome, ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.write().unwrap_or_else(|e| e.into_inner());
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        self.check_erasable(run_id, st, p, &cx)?;
        let selector = match &p.selector {
            Selector::Slots(s) => EraseSelector::Slots(s.clone()),
            Selector::Match(t) => EraseSelector::Match(t.as_bytes().to_vec()),
            Selector::All => EraseSelector::All,
        };
        let now = std::time::Instant::now();
        let ending = st.lease.as_ref().map(|l| {
            if l.expires > now {
                EndReason::Revoked
            } else {
                EndReason::Expired
            }
        });
        let mut note = ErasureNote {
            by: p.by.clone(),
            authenticated: true,
            reason_code: p.reason_code.clone(),
            access_log_cursor: None,
            reason: p.reason.clone(),
        };
        if ending.is_some() {
            // Ending the lease cannot be undone, so the selector is checked
            // first: a refused erasure must leave the holder its lease.
            self.writer(&run, st)?
                .journal
                .erase(&selector, &note, timefmt::now_unix_ns())
                .map_err(|f| ApiError::bad_request(f.to_string()))?;
        }
        let intent = cx
            .access
            .durable_blocking(cx.intent)
            .map_err(|e| ApiError::storage_unavailable(e.0))?;
        if let Some(reason) = ending {
            self.end_lease(&run, st, reason)?;
            self.write_meta(&run, st)?;
        }
        let entries_before = st.meta.entries;
        note.access_log_cursor = Some(intent);
        let erasure = self
            .writer(&run, st)?
            .journal
            .erase(&selector, &note, timefmt::now_unix_ns())
            .map_err(|f| ApiError::bad_request(f.to_string()))?;
        let record = cx
            .ledger
            .append(LedgerRecord {
                seq: 0,
                at: timefmt::now_rfc3339(),
                kind: p.kind,
                run_id: run_id.to_string(),
                slots: erasure.slots.clone(),
                reason_code: p.reason_code.clone(),
                by: p.by.clone(),
                access_log_cursor: Some(intent),
                note_cursor: Some(erasure.note_cursor),
                entries_before,
                entries_after: erasure.journal.len(),
                head_after: hex_encode(&erasure.journal.head()),
                anchored_entries: st.meta.anchored_entries,
                hold: None,
            })
            .map_err(|e| {
                ApiError::storage_unavailable(format!(
                    "the erasure ledger could not be written, so nothing was erased: {e}"
                ))
            })?;
        for torn in self.layout.torn_files(&run.stem)? {
            std::fs::remove_file(torn)?;
        }
        self.commit_rewrite(&run, st, &erasure.file, erasure.journal)?;
        let event = if p.kind == LedgerKind::Shred {
            "retention"
        } else {
            "erasure"
        };
        self.webhook(
            event,
            run_id,
            json!({"action": if p.kind == LedgerKind::Shred { "shred" } else { "erase" },
                   "slots": erasure.slots.len(), "reason_code": p.reason_code, "ledger_seq": record.seq}),
        );
        Ok(EraseOutcome {
            slots: erasure.slots,
            note_cursor: erasure.note_cursor,
            entries: st.meta.entries,
            head: st.meta.head.clone(),
            access_log_cursor: intent,
            can_resume: st.meta.summary.finished_ok(),
            ledger_seq: record.seq,
        })
    }

    /// The refusals that come before anything changes.
    fn check_erasable(
        &self,
        run_id: &str,
        st: &RunState,
        p: &EraseParams,
        cx: &EraseContext<'_>,
    ) -> Result<(), ApiError> {
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        if let Some(why) = &st.broken {
            if !st.repairable {
                return Err(ApiError::chain_broken(why));
            }
        }
        if st.missing {
            return Err(ApiError::chain_broken("the journal is missing"));
        }
        let holds = cx.holds.matching(run_id);
        if !holds.is_empty() {
            return Err(ApiError::on_hold(holds));
        }
        if p.kind == LedgerKind::Erasure {
            let updated = timefmt::parse_rfc3339(&st.meta.updated_at).unwrap_or(0);
            if let Some(e) = policy::effective(cx.policies, run_id, &st.meta.summary.labels) {
                if e.erasure_locked(updated, timefmt::now_unix_secs()) {
                    return Err(ApiError::retention_locked(&timefmt::rfc3339(
                        e.retain_until(updated),
                    )));
                }
            }
        }
        if !st.meta.summary.finished_ok() && !p.allow_unfinished {
            return Err(ApiError::bad_request(
                "the run's last attempt did not end ok, so erasing it means it can no longer be \
                 resumed; pass allow_unfinished",
            )
            .with("unfinished", true));
        }
        if let Some(l) = &st.lease {
            let now = std::time::Instant::now();
            if l.expires > now && !p.force {
                let left = (l.expires - now).as_secs_f64().ceil() as u64;
                return Err(ApiError::run_locked(left.max(1), left));
            }
        }
        Ok(())
    }

    /// Replace the journal file with `file` (which parses to `journal`):
    /// temp, fsync, rename, directory fsync, then advance the file
    /// generation. Then update the index and `meta.json`. Once the rename
    /// is durable the erasure has happened, so nothing after it fails the
    /// call: a `meta.json` that cannot be written is left to the flusher,
    /// and a journal that cannot be reopened is reopened on next use.
    fn commit_rewrite(
        &self,
        run: &super::Run,
        st: &mut RunState,
        file: &[u8],
        journal: Journal,
    ) -> Result<(), ApiError> {
        let path = self.layout.journal(&run.stem);
        st.writer = None;
        fsutil::write_atomic(&path, file)?;
        run.replaced();
        self.forget_cached(&run.id);
        st.meta.entries = journal.len();
        st.meta.byte_len = journal.byte_len();
        st.meta.head = hex_encode(&journal.head());
        st.meta.summary = Summary::rebuild(&journal, &self.opts.index_key);
        let report = journal.audit();
        self.judge(&run.id, st, &report);
        st.verify = Some(VerifyCache {
            report,
            entries: journal.len(),
            checked_at: timefmt::now_rfc3339(),
        });
        if let Ok(handle) = OpenOptions::new().read(true).write(true).open(&path) {
            st.writer = Some(Writer {
                journal,
                file: handle,
            });
        }
        if self.write_meta(run, st).is_err() {
            self.mark_dirty(&run.id);
        }
        Ok(())
    }

    /// Delete a run for retention (see the module documentation). Returns
    /// the ledger record and, if some of the run's files could not be
    /// removed yet, why (the next start removes them).
    pub fn delete_run(
        &self,
        run_id: &str,
        policy_json: JsonValue,
        holds: &Holds,
        access: &AccessLog,
        ledger: &Ledger,
        intent: AccessRecord,
    ) -> Result<(LedgerRecord, Option<String>), ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.write().unwrap_or_else(|e| e.into_inner());
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        let held = holds.matching(run_id);
        if !held.is_empty() {
            return Err(ApiError::on_hold(held));
        }
        if st
            .lease
            .as_ref()
            .is_some_and(|l| l.expires > std::time::Instant::now())
        {
            return Err(ApiError::run_locked(1, 1));
        }
        let cursor = access
            .durable_blocking(intent)
            .map_err(|e| ApiError::storage_unavailable(e.0))?;
        let tomb = Tombstone {
            run_id: run_id.to_string(),
            deleted_at: timefmt::now_rfc3339(),
            entries: st.meta.entries,
            head: st.meta.head.clone(),
            policy: policy_json,
        };
        let record = ledger.append(LedgerRecord {
            seq: 0,
            at: tomb.deleted_at.clone(),
            kind: LedgerKind::Delete,
            run_id: run_id.to_string(),
            slots: Vec::new(),
            reason_code: "retention".into(),
            by: "server:retention".into(),
            access_log_cursor: Some(cursor),
            note_cursor: None,
            entries_before: tomb.entries,
            entries_after: 0,
            head_after: tomb.head.clone(),
            anchored_entries: st.meta.anchored_entries,
            hold: None,
        })?;
        fsutil::write_json_atomic(&self.layout.tombstone(&run.stem), &tomb)?;
        let leftover = self.forget_deleted(&run, st, tomb.clone()).err();
        self.webhook(
            "retention",
            run_id,
            json!({"action": "delete", "entries": tomb.entries, "ledger_seq": record.seq}),
        );
        Ok((record, leftover.map(|e| e.to_string())))
    }

    /// A run's tombstone is durable: the run is deleted. Take it out of
    /// memory (its tombstone in first, so no `PUT` can slip in between)
    /// and remove its files; any that cannot be removed now are removed at
    /// the next start.
    fn forget_deleted(
        &self,
        run: &super::Run,
        st: &mut RunState,
        tomb: Tombstone,
    ) -> std::io::Result<()> {
        st.writer = None;
        st.deleted = true;
        st.lease = None;
        run.replaced();
        self.tombstones
            .write()
            .expect("tombstones lock")
            .insert(run.id.clone(), tomb);
        self.runs.write().expect("runs lock").remove(&run.id);
        self.dirty.lock().expect("dirty lock").remove(&run.id);
        self.forget_cached(&run.id);
        self.signals.metrics.add_runs(-1);
        remove_if_exists(&self.layout.journal(&run.stem))?;
        remove_if_exists(&self.layout.meta(&run.stem))?;
        for torn in self.layout.torn_files(&run.stem)? {
            remove_if_exists(&torn)?;
        }
        fsutil::fsync_dir(&self.layout.run_dir(&run.stem))
    }

    /// `accept-regression`: clear the flag, accepting the stored journal as
    /// the run's history from here on. Returns `(entries, anchored before)`.
    pub fn accept_regression(&self, run_id: &str) -> Result<(u64, u64), ApiError> {
        let run = self.find(run_id)?;
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if !st.meta.regressed {
            return Err(ApiError::bad_request("the run is not regressed"));
        }
        let before = st.meta.anchored_entries;
        st.meta.regressed = false;
        st.meta.anchored_entries = st.meta.entries;
        st.meta.unanchored_since = None;
        self.write_meta(&run, st)?;
        Ok((st.meta.entries, before))
    }

    /// The tips of every run that changed since its last leaf (design 4.7),
    /// each snapshotted under the run's lock. Runs created by PUT appear
    /// with zero entries.
    pub fn anchor_tips(&self) -> Vec<RunTip> {
        let mut tips = Vec::new();
        for run in self.all() {
            let st = run.lock();
            if st.deleted || st.missing || st.broken.is_some() {
                continue;
            }
            let changed = st
                .meta
                .last_anchor_leaf
                .is_none_or(|l| l.entries != st.meta.entries);
            if !changed {
                continue;
            }
            let head =
                pragmatic::encoding::hex_decode_exact::<32>(&st.meta.head).unwrap_or([0; 32]);
            tips.push(RunTip {
                run_id: run.id.clone(),
                entries: st.meta.entries,
                head,
                prev_leaf: st.meta.last_anchor_leaf.map(|l| l.index),
            });
        }
        tips.sort_by(|a, b| a.run_id.as_bytes().cmp(b.run_id.as_bytes()));
        tips
    }

    /// Record where a batch put each run's leaf. `meta.json` is written at
    /// once: the leaf is already durable in the anchor log, and a meta that
    /// forgot it would make the next batch anchor the run again with a
    /// `prev_leaf` that skips it, a fork in the run's leaf chain. (The
    /// flusher would write these within a second anyway; startup also
    /// recovers last leaves from the anchor log, see
    /// [`Store::apply_last_leaves`].)
    pub fn record_leaves(&self, leaves: &[LeafPlaced]) {
        for leaf in leaves {
            let Some(id) = &leaf.run_id else { continue };
            let Some(run) = self.get(id) else { continue };
            let mut guard = run.lock();
            let st: &mut RunState = &mut guard;
            let newer = st
                .meta
                .last_anchor_leaf
                .is_none_or(|l| l.index < leaf.leaf_index);
            if newer {
                st.meta.last_anchor_leaf = Some(LeafRef {
                    index: leaf.leaf_index,
                    entries: leaf.entries,
                });
                let _ = self.save_meta(&run, st, true);
            }
        }
    }

    /// Raise each run's last leaf to what the anchor log holds (at
    /// startup): the log is the durable record, and `meta.json` may lag it
    /// by a crash.
    pub fn apply_last_leaves(&self, leaves: &[LeafPlaced]) {
        self.record_leaves(leaves);
    }

    /// Runs became independently anchored up to these lengths.
    pub fn mark_anchored(&self, runs: &[(String, u64)]) {
        for (id, entries) in runs {
            let Some(run) = self.get(id) else { continue };
            let mut guard = run.lock();
            let st: &mut RunState = &mut guard;
            if *entries > st.meta.anchored_entries {
                st.meta.anchored_entries = *entries;
                if st.meta.entries < st.meta.anchored_entries && !st.meta.regressed {
                    st.meta.regressed = true;
                    self.webhook(
                        "regressed",
                        id,
                        json!({"entries": st.meta.entries, "anchored_entries": entries}),
                    );
                }
                if st.meta.anchored_entries >= st.meta.entries {
                    st.meta.unanchored_since = None;
                }
                let _ = self.save_meta(&run, st, true);
            }
        }
    }

    /// Raise anchored lengths learned elsewhere (restore, startup) and mark
    /// regressions. Returns the runs newly marked regressed.
    pub fn apply_anchored_lengths(
        &self,
        lengths: &std::collections::HashMap<String, u64>,
    ) -> Vec<String> {
        let mut regressed = Vec::new();
        for (id, entries) in lengths {
            let Some(run) = self.get(id) else { continue };
            let was = run.lock().meta.regressed;
            self.mark_anchored(&[(id.clone(), *entries)]);
            if !was && run.lock().meta.regressed {
                regressed.push(id.clone());
            }
        }
        regressed
    }
}

impl Store {
    /// Take and release a run's locks exclusively, so that anything that
    /// was acting on the run (a retention action, say) has finished. Used
    /// after placing a hold.
    pub fn quiesce(&self, run_id: &str) {
        if let Some(run) = self.get(run_id) {
            let _file = run.file.write().unwrap_or_else(|e| e.into_inner());
            let _st = run.lock();
        }
    }

    /// Run ids whose `run.start` subjects include this subject hash (the
    /// subjects index, design 4.9).
    pub fn runs_with_subject(&self, hash: &str) -> Vec<String> {
        let mut out = Vec::new();
        for run in self.all() {
            let st = run.lock();
            if !st.deleted && st.meta.summary.subjects.iter().any(|s| s == hash) {
                out.push(run.id.clone());
            }
        }
        out
    }

    /// Append a note to a run the server itself writes (reserved
    /// `pragmatic:` ids, such as a witness log), creating the run with its
    /// `run.start` note if needed. `decide` sees the journal so far and
    /// returns the note to append, or an error to append nothing; the
    /// decision and the append happen under the run's lock. Returns the
    /// decision's value and the note's cursor.
    pub fn internal_append<T>(
        &self,
        run_id: &str,
        decide: impl FnOnce(&Journal) -> Result<(String, String, Vec<pragmatic::Value>, T), ApiError>,
    ) -> Result<(T, u64), ApiError> {
        let run = match self.get(run_id) {
            Some(r) => r,
            None => {
                let who = crate::tokens::Principal::system("internal");
                match self.create_run(&who, run_id, None) {
                    Ok(_)
                    | Err(ApiError {
                        code: "run_exists", ..
                    }) => {}
                    Err(e) => return Err(e),
                }
                let run = self.find(run_id)?;
                let mut guard = run.lock();
                let st: &mut RunState = &mut guard;
                st.lease = None;
                if st.meta.entries == 0 {
                    let data = serde_json::json!({
                        "format": 2,
                        "labels": {},
                        "nonce": random_nonce()?,
                        "run_id": run_id,
                        "sdk": "pragmatic-server",
                        "sdk_version": env!("CARGO_PKG_VERSION"),
                    })
                    .to_string();
                    let w = self.writer(&run, st)?;
                    w.journal
                        .append(
                            pragmatic::journal::META,
                            pragmatic::Event::Note {
                                kind: "run.start".into(),
                                data,
                                payload: Vec::new(),
                            },
                        )
                        .map_err(|f| ApiError::storage_unavailable(f.to_string()))?;
                    self.persist(&run, st, true)?;
                }
                drop(guard);
                run
            }
        };
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if let Some(why) = &st.broken {
            return Err(ApiError::chain_broken(why));
        }
        let w = self.writer(&run, st)?;
        let (kind, data, payload, value) = decide(&w.journal)?;
        w.journal
            .append(
                pragmatic::journal::META,
                pragmatic::Event::Note {
                    kind,
                    data,
                    payload: payload
                        .into_iter()
                        .map(pragmatic::Content::Sealed)
                        .collect(),
                },
            )
            .map_err(|f| ApiError::bad_request(f.to_string()))?;
        let cursor = w.journal.len() - 1;
        self.persist(&run, st, true)?;
        Ok((value, cursor))
    }

    /// Re-apply an erasure from the ledger during a restore: no holds,
    /// lease or retention checks (the erasure already happened once).
    /// Slots that no longer exist or are no longer sealed are skipped.
    /// Returns the slots erased now and whether some listed slots lie
    /// beyond the restored journal.
    pub fn reapply_erasure(
        &self,
        run_id: &str,
        slots: Option<&[(u64, u8)]>,
        note: &ErasureNote,
    ) -> Result<(Vec<(u64, u8)>, bool), ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.write().unwrap_or_else(|e| e.into_inner());
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if let Some(why) = &st.broken {
            return Err(ApiError::chain_broken(why));
        }
        st.lease = None;
        let journal = &self.writer(&run, st)?.journal;
        let (selector, beyond) = match slots {
            None => (EraseSelector::All, false),
            Some(list) => {
                let beyond = list.iter().any(|&(c, _)| c >= journal.len());
                let present: Vec<(u64, u8)> = list
                    .iter()
                    .copied()
                    .filter(|&(c, s)| {
                        journal.get(c).is_some_and(|e| {
                            e.event
                                .slot_contents()
                                .get(s as usize)
                                .is_some_and(|c| c.is_sealed())
                        })
                    })
                    .collect();
                (EraseSelector::Slots(present), beyond)
            }
        };
        if matches!(&selector, EraseSelector::Slots(p) if p.is_empty()) {
            return Ok((Vec::new(), beyond));
        }
        let erasure = match journal.erase(&selector, note, timefmt::now_unix_ns()) {
            Ok(e) => e,
            Err(pragmatic::Fault::Unsupported(m)) if m.starts_with("nothing to erase") => {
                return Ok((Vec::new(), beyond))
            }
            Err(f) => return Err(ApiError::bad_request(f.to_string())),
        };
        for torn in self.layout.torn_files(&run.stem)? {
            std::fs::remove_file(torn)?;
        }
        self.commit_rewrite(&run, st, &erasure.file, erasure.journal)?;
        Ok((erasure.slots, beyond))
    }

    /// Delete a run during a restore (re-applying a retention delete):
    /// tombstone, then remove the files, with no checks.
    pub fn reapply_delete(&self, run_id: &str, at: &str) -> Result<(), ApiError> {
        let Some(run) = self.get(run_id) else {
            return Ok(());
        };
        let _file = run.file.write().unwrap_or_else(|e| e.into_inner());
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        let tomb = Tombstone {
            run_id: run_id.to_string(),
            deleted_at: at.to_string(),
            entries: st.meta.entries,
            head: st.meta.head.clone(),
            policy: json!({"reapplied_from": "erasure-ledger"}),
        };
        fsutil::write_json_atomic(&self.layout.tombstone(&run.stem), &tomb)?;
        self.forget_deleted(&run, st, tomb)?;
        Ok(())
    }

    /// End every lease restored from a backup (they mean nothing now),
    /// each with its custody note (design 4.5), so the entries written
    /// under it stay attributed in the run. Returns how many ended and the
    /// runs whose note could not be written (their lease is dropped all the
    /// same).
    pub fn end_restored_leases(&self) -> (usize, Vec<(String, String)>) {
        let mut ended = 0;
        let mut failed = Vec::new();
        for run in self.all() {
            let mut guard = run.lock();
            let st: &mut RunState = &mut guard;
            if st.lease.is_none() {
                continue;
            }
            ended += 1;
            if let Err(e) = self.end_lease(&run, st, EndReason::Restored) {
                failed.push((run.id.clone(), e.message));
                st.lease = None;
            }
            st.writer = None;
            if let Err(e) = self.write_meta(&run, st) {
                failed.push((run.id.clone(), e.message));
            }
        }
        (ended, failed)
    }
}

fn random_nonce() -> Result<String, ApiError> {
    let mut b = [0u8; 16];
    pragmatic::rand::fill(&mut b)
        .map_err(|e| ApiError::storage_unavailable(format!("random number generator: {e}")))?;
    Ok(hex_encode(&b))
}

fn remove_if_exists(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
