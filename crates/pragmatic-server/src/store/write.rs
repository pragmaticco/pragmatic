//! Creating runs, leases (design 4.5) and the append protocol (design
//! 4.6).
//!
//! # The append protocol
//!
//! `POST /v1/runs/{id}/frames?at=N` is checked in this order, and the first
//! failing check decides the answer:
//!
//! 1. auth and scope (the HTTP layer);
//! 2. the run exists, or 410 for a tombstone (and it is neither regressed
//!    nor damaged);
//! 3. **duplicate**: if `at + k ≤ entries` and the stored hashes at
//!    `[at, at+k)` equal the hashes of the submitted frames, answer 200
//!    with `duplicate: true` whatever the lease state. A client whose
//!    response was lost resends the identical request and learns that it
//!    landed;
//! 4. the lease;
//! 5. `at` equals the number of entries;
//! 6. the frames: exactly `k` complete frames, each canonically decoded,
//!    re-encoded and byte-compared, commitments recomputed, refs resolved,
//!    chained from the current head, no erased or withheld slots, no
//!    server-only notes, and the head after the last frame equal to
//!    `Pragmatic-Head`;
//! 7. the write: one positioned write and one fsync, then the index.
//!
//! All or nothing: if the write fails the file is truncated back, the
//! frames are dropped from memory and the client gets 503
//! `storage_unavailable` (it resends; the duplicate and `at` checks sort
//! out what landed).
//!
//! The duplicate rule compares stored hashes, read from the writer's
//! journal when it is loaded and otherwise from disk by offset: a request
//! from a token without the lease never makes the server load a journal.
//! [`Store::precheck_append`] runs the checks that need no body before the
//! body is read, so a request that can only be refused is refused before
//! its body is buffered.
//!
//! A run's first entry is its `run.start` note, naming the run's own id,
//! and no later entry is a `run.start`: a journal that claimed to be
//! another run would be refused by every reader that checks (the server's
//! own startup reindex among them).

use std::fs::OpenOptions;
use std::time::Instant;

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{frame_hash, split_frames};
use pragmatic::sha256::sha256;
use pragmatic::Journal;
use subtle::ConstantTimeEq;

use super::{EndReason, Lease, LeaseRecord, Meta, Run, RunState, Store, Writer};
use crate::error::ApiError;
use crate::fsutil;
use crate::layout::DATA_FORMAT;
use crate::summary::Summary;
use crate::timefmt;
use crate::tokens::Principal;

/// How many ended leases a run remembers.
const ENDED_MEMORY: usize = 8;

/// A granted lease, as the API returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease: String,
    pub ttl_secs: u64,
    pub entries: u64,
}

/// One `POST /frames` request.
#[derive(Debug, Clone)]
pub struct AppendRequest<'a> {
    pub at: u64,
    pub count: u64,
    pub lease: &'a str,
    /// `Pragmatic-Head`, lowercase hex.
    pub head: &'a str,
    pub body: &'a [u8],
}

/// A successful append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOk {
    pub entries: u64,
    pub head: String,
    pub duplicate: bool,
    /// The cursors of the accepted frames (for the access log).
    pub from: u64,
    pub to: u64,
}

fn random_hex(bytes: usize) -> Result<String, ApiError> {
    let mut b = vec![0u8; bytes];
    pragmatic::rand::fill(&mut b)
        .map_err(|e| ApiError::storage_unavailable(format!("random number generator: {e}")))?;
    Ok(hex_encode(&b))
}

fn ct_str_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl Store {
    /// `PUT /v1/runs/{id}`: create the run and grant a lease atomically.
    pub fn create_run(
        &self,
        who: &Principal,
        run_id: &str,
        holder: Option<&str>,
    ) -> Result<LeaseGrant, ApiError> {
        if self.is_tombstoned(run_id) {
            return Err(ApiError::run_deleted());
        }
        if self.load_late(run_id)?.is_some() {
            return Err(ApiError::run_exists());
        }
        let stem = crate::layout::stem(run_id);
        let now_text = timefmt::now_rfc3339();
        let genesis = Journal::new(None);
        let meta = Meta {
            format: DATA_FORMAT,
            run_id: run_id.to_string(),
            created_at: now_text.clone(),
            updated_at: now_text,
            entries: 0,
            byte_len: pragmatic::journal::HEADER_LEN as u64,
            head: hex_encode(&genesis.head()),
            anchored_entries: 0,
            last_anchor_leaf: None,
            leases: Vec::new(),
            holds: Vec::new(),
            status: "active".into(),
            created_by: Some(who.token_id.clone()),
            regressed: false,
            unanchored_since: None,
            regression_accepted: false,
            summary: Summary::default(),
        };
        let run = std::sync::Arc::new(Run::new(
            run_id,
            &stem,
            super::state_from_meta(meta, self.opts.lease_ttl),
        ));
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        {
            let mut runs = self.runs.write().expect("runs lock");
            if runs.contains_key(run_id) {
                return Err(ApiError::run_exists());
            }
            if self.is_tombstoned(run_id) {
                return Err(ApiError::run_deleted());
            }
            runs.insert(run_id.to_string(), run.clone());
        }
        match self.create_files(&run, st) {
            Ok(()) => {}
            Err(e) => {
                st.deleted = true;
                self.runs.write().expect("runs lock").remove(run_id);
                return Err(e);
            }
        }
        self.signals.metrics.add_runs(1);
        self.grant(&run, st, who, holder.map(str::to_string))
    }

    /// Write `meta.json`, then the journal header (temp, fsync, rename,
    /// directory fsync). Meta first: a journal without meta and without
    /// entries could not be told apart from debris, while meta without a
    /// journal is recreated at startup.
    ///
    /// Files already on disk for this id are never replaced: a run the
    /// index does not know about (its files could not be read) is not a
    /// run that does not exist.
    fn create_files(&self, run: &Run, st: &mut RunState) -> Result<(), ApiError> {
        let dir = self.layout.run_dir(&run.stem);
        fsutil::create_dir_durable(&dir)?;
        self.ensure_absent(&run.stem)?;
        self.write_meta(run, st)?;
        let path = self.layout.journal(&run.stem);
        fsutil::write_atomic(&path, &pragmatic::journal::header(0))?;
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        st.writer = Some(Writer {
            journal: Journal::new(None),
            file,
        });
        Ok(())
    }

    /// Refuse to create a run whose files exist: a tombstone is a deleted
    /// run (410); a journal or meta is a run the index could not read,
    /// which becomes unavailable (503) until it loads.
    fn ensure_absent(&self, stem: &str) -> Result<(), ApiError> {
        let paths = [
            (self.layout.tombstone(stem), true),
            (self.layout.journal(stem), false),
            (self.layout.meta(stem), false),
        ];
        for (path, tombstone) in paths {
            match std::fs::symlink_metadata(&path) {
                Ok(_) if tombstone => return Err(ApiError::run_deleted()),
                Ok(_) => {
                    self.unavailable
                        .lock()
                        .expect("unavailable lock")
                        .insert(stem.to_string());
                    return Err(ApiError::storage_unavailable(
                        "files of this run exist but are not in the index; they are never \
                         replaced",
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(ApiError::from(e)),
            }
        }
        Ok(())
    }

    /// `POST /v1/runs/{id}/lease`: acquire, or renew for the same holder
    /// and token.
    ///
    /// A lease granted by `PUT` without a `Pragmatic-Holder` has no holder
    /// yet; it is renewed only by a request that presents the lease id
    /// (`presented`), which then records its holder. Another process using
    /// the same token cannot adopt it by naming any holder.
    pub fn acquire_lease(
        &self,
        who: &Principal,
        run_id: &str,
        holder: &str,
        presented: Option<&str>,
    ) -> Result<LeaseGrant, ApiError> {
        let run = self.find(run_id)?;
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        refuse_if_unwritable(st)?;
        let now = Instant::now();
        let ttl = self.opts.lease_ttl;
        if let Some(lease) = &mut st.lease {
            let same_token = lease.record.token_id == who.token_id;
            let proves = presented.is_some_and(|p| ct_str_eq(p, &lease.record.id));
            let same_holder = lease.record.holder.as_deref() == Some(holder);
            if same_token && (same_holder || proves) {
                lease.record.holder = Some(holder.to_string());
                lease.expires = now + ttl;
                let grant = LeaseGrant {
                    lease: lease.record.id.clone(),
                    ttl_secs: ttl.as_secs(),
                    entries: st.meta.entries,
                };
                st.last_activity = now;
                st.dangling_alerted = false;
                self.save_meta(&run, st, false)?;
                return Ok(grant);
            }
            if lease.expires > now {
                let left = (lease.expires - now).as_secs_f64().ceil() as u64;
                return Err(ApiError::run_locked(left.max(1), left));
            }
            // Lazy expiry: the expired lease ends only now that someone
            // else wants the run.
            self.end_lease(&run, st, EndReason::Expired)?;
        }
        self.grant(&run, st, who, Some(holder.to_string()))
    }

    fn grant(
        &self,
        run: &Run,
        st: &mut RunState,
        who: &Principal,
        holder: Option<String>,
    ) -> Result<LeaseGrant, ApiError> {
        let id = random_hex(16)?;
        let now = Instant::now();
        st.lease = Some(Lease {
            record: LeaseRecord {
                id: id.clone(),
                holder,
                token_id: who.token_id.clone(),
                granted_at: timefmt::now_rfc3339(),
                from_entries: st.meta.entries,
                requests: 0,
                first_received: None,
                last_received: None,
                clock_skew: false,
            },
            expires: now + self.opts.lease_ttl,
        });
        st.last_activity = now;
        st.dangling_alerted = false;
        if let Err(e) = self.save_meta(run, st, true) {
            st.lease = None;
            return Err(e);
        }
        Ok(LeaseGrant {
            lease: id,
            ttl_secs: self.opts.lease_ttl.as_secs(),
            entries: st.meta.entries,
        })
    }

    /// `DELETE /v1/runs/{id}/lease`: end the caller's lease, writing its
    /// custody note.
    pub fn release_lease(
        &self,
        who: &Principal,
        run_id: &str,
        lease: &str,
    ) -> Result<(), ApiError> {
        let run = self.find(run_id)?;
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        check_lease(st, who, lease)?;
        self.end_lease(&run, st, EndReason::Released)?;
        st.writer = None;
        self.save_meta(&run, st, true)
    }

    /// Check that `lease` is the caller's current lease on the run (for
    /// reading the journal).
    pub fn check_lease(&self, who: &Principal, run_id: &str, lease: &str) -> Result<(), ApiError> {
        let run = self.find(run_id)?;
        let guard = run.lock();
        check_lease(&guard, who, lease)
    }

    /// End the current lease: append its custody note (design 4.5) and
    /// remember why it ended. If the note cannot be written, the lease
    /// stays and the error is returned.
    pub(super) fn end_lease(
        &self,
        run: &Run,
        st: &mut RunState,
        reason: EndReason,
    ) -> Result<(), ApiError> {
        let Some(lease) = st.lease.clone() else {
            return Ok(());
        };
        // A run whose first entry is not written yet has no history to
        // record custody of, and its first entry must be run.start.
        if st.meta.entries > 0 && st.broken.is_none() {
            let data = custody_data(&lease.record, st.meta.entries, reason);
            let w = self.writer(run, st)?;
            w.journal
                .append_server_note(timefmt::now_unix_ns(), "custody", &data, Vec::new())
                .map_err(|f| ApiError::storage_unavailable(format!("custody note: {f}")))?;
            self.persist(run, st, false)?;
        }
        st.lease = None;
        st.ended.push_back((lease.record.id, reason));
        if st.ended.len() > ENDED_MEMORY {
            st.ended.pop_front();
        }
        Ok(())
    }

    /// The writer's journal, read from disk on first use and checked
    /// against the index.
    pub(super) fn writer<'a>(
        &self,
        run: &Run,
        st: &'a mut RunState,
    ) -> Result<&'a mut Writer, ApiError> {
        if st.writer.is_none() {
            let path = self.layout.journal(&run.stem);
            let file = OpenOptions::new().read(true).write(true).open(&path)?;
            let size = file.metadata()?.len();
            if size != st.meta.byte_len {
                let why = format!(
                    "journal is {size} bytes but the index says {}",
                    st.meta.byte_len
                );
                self.mark_broken(&run.id, st, why.clone());
                return Err(ApiError::chain_broken(&why));
            }
            let bytes = fsutil::read_prefix(&file, size)?;
            let journal = match Journal::parse(&bytes, None) {
                Ok(p) if p.tail_len == 0 && hex_encode(&p.journal.head()) == st.meta.head => {
                    p.journal
                }
                Ok(_) => {
                    let why = "journal does not match the index".to_string();
                    self.mark_broken(&run.id, st, why.clone());
                    return Err(ApiError::chain_broken(&why));
                }
                Err(e) => {
                    let why = e.to_string();
                    self.mark_broken(&run.id, st, why.clone());
                    return Err(ApiError::chain_broken(&why));
                }
            };
            st.writer = Some(Writer { journal, file });
        }
        Ok(st.writer.as_mut().expect("loaded"))
    }

    /// Write the writer's pending frames (one positioned write, one fsync)
    /// and then update the index. `client` marks a client append, which
    /// moves `updated_at`. On failure the file is truncated back and the
    /// frames are dropped.
    pub(super) fn persist(
        &self,
        run: &Run,
        st: &mut RunState,
        client: bool,
    ) -> Result<(), ApiError> {
        let byte_len = st.meta.byte_len;
        let Some(w) = st.writer.as_mut() else {
            return Ok(());
        };
        let Some((first, frames, head)) = w.journal.pending() else {
            return Ok(());
        };
        let result = (|| -> std::io::Result<()> {
            let size = w.file.metadata()?.len();
            if size != byte_len {
                return Err(std::io::Error::other(format!(
                    "journal is {size} bytes, expected {byte_len}"
                )));
            }
            fsutil::write_all_at(&w.file, frames, byte_len)?;
            w.file.sync_data()
        })();
        if let Err(e) = result {
            let _ = w.file.set_len(byte_len);
            let _ = w.file.sync_data();
            w.journal.discard_pending();
            st.writer = None;
            return Err(ApiError::storage_unavailable(format!(
                "journal write failed: {e}"
            )));
        }
        let len = w.journal.len();
        w.journal.mark_persisted(len);
        st.meta.entries = len;
        st.meta.byte_len = w.journal.byte_len();
        st.meta.head = hex_encode(&head);
        if client {
            st.meta.updated_at = timefmt::now_rfc3339();
        }
        if st.meta.entries > st.meta.anchored_entries && st.meta.unanchored_since.is_none() {
            st.meta.unanchored_since = Some(timefmt::now_unix_secs());
        }
        let mut ended_ok = false;
        for c in first..len {
            let entry = w.journal.get(c).expect("appended entry");
            ended_ok |= st
                .meta
                .summary
                .observe(entry, &self.opts.index_key)
                .attempt_ended_ok;
        }
        if let Some(v) = &mut st.verify {
            v.entries = len;
        }
        if ended_ok {
            self.signals.anchor_soon.request();
        }
        // The index is current in memory; meta.json follows within a
        // second, written by the flusher rather than on the append path.
        self.mark_dirty(&run.id);
        Ok(())
    }

    /// `POST /v1/runs/{id}/frames` (see the module documentation).
    pub fn append(
        &self,
        who: &Principal,
        run_id: &str,
        req: AppendRequest<'_>,
    ) -> Result<AppendOk, ApiError> {
        let started = Instant::now();
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let mut guard = run.lock();
        let st: &mut RunState = &mut guard;
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        refuse_if_unwritable(st)?;
        let frames = split_frames(req.body).ok();
        if let Some(dup) = self.duplicate(&run, st, &req, frames.as_deref())? {
            return Ok(dup);
        }
        // The writer's journal is loaded (by `accept`) only past this
        // check, for the holder of the lease.
        check_lease(st, who, req.lease)?;
        if req.at != st.meta.entries {
            return Err(ApiError::conflict(st.meta.entries, req.at, &st.meta.head));
        }
        let frames =
            frames.ok_or_else(|| ApiError::invalid_frames("the body is not whole frames"))?;
        if frames.len() as u64 != req.count {
            return Err(ApiError::invalid_frames(format!(
                "Pragmatic-Frames says {} but the body holds {} frames",
                req.count,
                frames.len()
            )));
        }
        let accepted = self.accept(&run, st, &req)?;
        self.note_receipt(&run, st, accepted.clone());
        self.persist(&run, st, true)?;
        self.signals.metrics.observe_append(started.elapsed());
        Ok(AppendOk {
            entries: st.meta.entries,
            head: st.meta.head.clone(),
            duplicate: false,
            from: accepted.start,
            to: accepted.end,
        })
    }

    /// Step 3: the duplicate rule.
    fn duplicate(
        &self,
        run: &Run,
        st: &mut RunState,
        req: &AppendRequest<'_>,
        frames: Option<&[&[u8]]>,
    ) -> Result<Option<AppendOk>, ApiError> {
        let Some(frames) = frames else {
            return Ok(None);
        };
        let k = frames.len() as u64;
        if k == 0
            || k != req.count
            || req
                .at
                .checked_add(k)
                .is_none_or(|end| end > st.meta.entries)
        {
            return Ok(None);
        }
        let entries = st.meta.entries;
        let mut last = None;
        for (i, f) in frames.iter().enumerate() {
            let stored = self.stored_hash(run, st, req.at + i as u64)?;
            if stored.is_none() || frame_hash(f) != stored {
                return Ok(None);
            }
            last = stored;
        }
        Ok(Some(AppendOk {
            entries,
            head: hex_encode(&last.expect("k > 0")),
            duplicate: true,
            from: req.at,
            to: req.at + k,
        }))
    }

    /// The checks of `POST /frames` that need no body, in the order of
    /// design 4.6: the run exists and is writable, and unless the request
    /// may be a resend of frames already stored (its `Pragmatic-Head` is
    /// the stored hash at `at + count - 1`, which the duplicate rule then
    /// confirms against the body), the lease and `at`. The HTTP layer
    /// calls this before reading the body, so a request that can only be
    /// refused never has its body buffered; [`append`](Self::append)
    /// checks everything again.
    pub fn precheck_append(
        &self,
        who: &Principal,
        run_id: &str,
        at: u64,
        count: u64,
        head: &str,
        lease: &str,
    ) -> Result<(), ApiError> {
        let run = self.find(run_id)?;
        let _file = run.file.read().unwrap_or_else(|p| p.into_inner());
        let st = run.lock();
        if st.deleted {
            return Err(ApiError::run_deleted());
        }
        refuse_if_unwritable(&st)?;
        let resend = count > 0
            && at
                .checked_add(count)
                .is_some_and(|end| end <= st.meta.entries);
        if resend {
            let last = self.stored_hash(&run, &st, at + count - 1)?;
            if last.is_some_and(|h| hex_encode(&h) == head) {
                return Ok(());
            }
        }
        check_lease(&st, who, lease)?;
        if at != st.meta.entries {
            return Err(ApiError::conflict(st.meta.entries, at, &st.meta.head));
        }
        Ok(())
    }

    /// Step 6: validate the frames into the writer's journal (pending).
    fn accept(
        &self,
        run: &Run,
        st: &mut RunState,
        req: &AppendRequest<'_>,
    ) -> Result<std::ops::Range<u64>, ApiError> {
        let w = self.writer(run, st)?;
        let range = w.journal.append_frames(req.body).map_err(|e| {
            ApiError::invalid_frames(e.to_string())
                .with("frame", e.index)
                .with("cursor", e.cursor)
                .with("reason", e.reason)
        })?;
        if hex_encode(&w.journal.head()) != req.head {
            w.journal.discard_pending();
            return Err(ApiError::invalid_frames(
                "the head after the last frame is not Pragmatic-Head",
            ));
        }
        if let Err(e) = check_run_start(&run.id, &w.journal, range.clone()) {
            w.journal.discard_pending();
            return Err(e);
        }
        Ok(range)
    }

    /// Record the request in the lease for its custody note, and flag clock
    /// skew.
    fn note_receipt(&self, run: &Run, st: &mut RunState, range: std::ops::Range<u64>) {
        let now_ns = timefmt::now_unix_ns();
        let skew_ns = self.opts.max_clock_skew.as_nanos() as u64;
        let skewed = st.writer.as_ref().is_some_and(|w| {
            range.clone().any(|c| {
                w.journal
                    .get(c)
                    .is_some_and(|e| e.at.abs_diff(now_ns) > skew_ns)
            })
        });
        st.last_activity = Instant::now();
        st.dangling_alerted = false;
        let Some(lease) = &mut st.lease else { return };
        let r = &mut lease.record;
        r.requests += 1;
        r.first_received.get_or_insert(now_ns);
        r.last_received = Some(now_ns);
        if skewed && !r.clock_skew {
            r.clock_skew = true;
            self.webhook(
                "clock_skew",
                &run.id,
                serde_json::json!({"max_clock_skew_secs": self.opts.max_clock_skew.as_secs()}),
            );
        }
    }
}

/// The first entry of a run is its `run.start` note, naming the run's own
/// id; no later entry is a `run.start`.
fn check_run_start(
    run_id: &str,
    journal: &Journal,
    range: std::ops::Range<u64>,
) -> Result<(), ApiError> {
    for cursor in range {
        let Some(entry) = journal.get(cursor) else {
            continue;
        };
        let is_start = entry.event.note_kind() == Some(pragmatic::journal::note::RUN_START);
        let refuse = |why: &str| {
            Err(ApiError::invalid_frames(why.to_string())
                .with("cursor", cursor)
                .with("reason", why.to_string()))
        };
        if cursor == 0 {
            if !is_start {
                return refuse("the first entry of a run must be its run.start note");
            }
            if journal.run_start_id().as_deref() != Some(run_id) {
                return refuse("run.start names a different run id");
            }
        } else if is_start {
            return refuse("run.start may only be the first entry");
        }
    }
    Ok(())
}

/// Refuse writes to runs an admin must look at first.
fn refuse_if_unwritable(st: &RunState) -> Result<(), ApiError> {
    if st.meta.regressed {
        return Err(ApiError::regressed());
    }
    if let Some(why) = &st.broken {
        return Err(ApiError::chain_broken(why));
    }
    if st.missing {
        return Err(ApiError::chain_broken("the journal is missing"));
    }
    Ok(())
}

/// The caller's lease must be the current one (lazily expired leases still
/// count until someone else takes the run).
fn check_lease(st: &RunState, who: &Principal, lease: &str) -> Result<(), ApiError> {
    if let Some(l) = &st.lease {
        if ct_str_eq(&l.record.id, lease) && l.record.token_id == who.token_id {
            return Ok(());
        }
    }
    match st.ended.iter().rev().find(|(id, _)| ct_str_eq(id, lease)) {
        Some((_, EndReason::Expired)) => Err(ApiError::lease_expired()),
        _ => Err(ApiError::lease_lost()),
    }
}

/// The `custody` note's data (design 2.11). `principal` is the token id:
/// notes never carry names or email addresses.
fn custody_data(r: &LeaseRecord, to_entries: u64, reason: EndReason) -> String {
    serde_json::json!({
        "lease": hex_encode(&sha256(r.id.as_bytes())),
        "token": r.token_id,
        "principal": r.token_id,
        "from_entries": r.from_entries,
        "to_entries": to_entries,
        "requests": r.requests,
        "first_received": r.first_received,
        "last_received": r.last_received,
        "clock_skew": r.clock_skew,
        "end": reason.as_str(),
    })
    .to_string()
}
