//! The **Runtime**: record, resume, replay.
//!
//! Wrap your agent in a closure over [`Ctx`], hand it to the runtime under a
//! stable run id, and every oracle call, effect, receive, and clock read is
//! journaled as the run proceeds:
//!
//! ```
//! use pragmatic::{Runtime, SeededOracle};
//!
//! let rt = Runtime::in_memory(SeededOracle::new(42));
//! let report = rt.run("run-1", |ctx| {
//!     let plan = ctx.oracle("plan the task")?;
//!     let step = ctx.oracle(format!("execute: {plan}"))?;
//!     Ok(format!("done: {step}").into())
//! }).unwrap();
//!
//! // Crash anywhere; `resume` replays the journaled prefix (no model calls)
//! // and continues recording at the tail.
//! // Replay the whole run later, exactly: the model is never consulted.
//! let audit = rt.replay("run-1", |ctx| {
//!     let plan = ctx.oracle("plan the task")?;
//!     let step = ctx.oracle(format!("execute: {plan}"))?;
//!     Ok(format!("done: {step}").into())
//! }).unwrap();
//! assert_eq!(report.trace, audit.trace); // T1, empirically
//! ```
//!
//! # Attempts
//!
//! Each call to `run`, `resume` or `replay` is one *attempt*:
//! [`Runtime::begin`] checks the run out of its backend (taking its write
//! lock) or, for replay, reads a snapshot without any lock; the agent runs
//! against the attempt's [`Ctx`]; [`Attempt::finish`] writes `attempt.end`,
//! persists and checks the run back in. Dropping an attempt without
//! finishing it is a crash: the lock is released and nothing more is
//! written.
//!
//! The runtime holds no lock across agent code, takes `&self` everywhere and
//! is `Send + Sync` when its oracle is, so one runtime can drive many runs
//! from many threads.
//!
//! For `async` agents, see [`AsyncRuntime`](crate::AsyncRuntime).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::backend::{Backend, Checkout, DirBackend, MemoryBackend};
use crate::ctx::{Ctx, RunOptions, TraceLabel};
use crate::fault::Fault;
use crate::journal::{validate_run_id, Journal, VerifyReport, ROOT};
use crate::oracle::{Oracle, RefusingOracle};
use crate::session::{Inbox, ProgramChange, RecoverPolicy, Session};
use crate::sha256::Digest;
use crate::value::Value;

pub use crate::session::{Mode, Recover, RecoverRequest};

/// The result of driving one attempt to completion.
#[derive(Clone, Debug)]
pub struct RunReport {
    pub run_id: String,
    /// The agent's output.
    pub output: Value,
    /// The observable trace, sorted by cursor and ending in
    /// [`TraceLabel::Done`]: identical between a recorded run and its
    /// replay (T1).
    pub trace: Vec<TraceLabel>,
    /// Journal length after this attempt, notes included. For what the
    /// agent did, count [`Journal::program_entries`].
    pub journal_len: u64,
    /// Head of the tamper-evident hash chain (the run's integrity
    /// commitment).
    pub chain_head: Option<Digest>,
    /// Steps served from the journal (zero model calls, zero effects
    /// performed).
    pub replayed_steps: u64,
    /// Model calls made in this attempt.
    pub fresh_steps: u64,
    /// Recorded programs whose hash changed and that this attempt accepted
    /// under [`OnCodeChange::Continue`](crate::OnCodeChange::Continue).
    pub program_changes: Vec<ProgramChange>,
}

/// What `Runtime` and `AsyncRuntime` share: the backend, the HMAC key and
/// the channel inboxes, and the opening of sessions on them.
pub(crate) struct Core {
    backend: Arc<dyn Backend>,
    key: Option<Vec<u8>>,
    inboxes: Mutex<HashMap<String, Inbox>>,
}

impl Core {
    pub(crate) fn new(backend: Arc<dyn Backend>) -> Core {
        Core {
            backend,
            key: None,
            inboxes: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn on_dir(dir: impl Into<PathBuf>) -> std::io::Result<Core> {
        let backend = DirBackend::new(dir.into()).map_err(std::io::Error::other)?;
        Ok(Core::new(Arc::new(backend)))
    }

    pub(crate) fn set_key(&mut self, key: &[u8]) {
        self.key = Some(key.to_vec());
    }

    fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    pub(crate) fn backend(&self) -> &dyn Backend {
        &*self.backend
    }

    fn inbox(&self, run_id: &str) -> Inbox {
        self.inboxes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(run_id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn send(&self, run_id: &str, channel: &str, value: Value) {
        self.inbox(run_id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(channel.to_string())
            .or_default()
            .push_back(value);
    }

    /// Open the session of one attempt: a checkout for `Run` and `Resume`
    /// (with the opening notes and recovery persisted), a snapshot for
    /// `Replay`.
    pub(crate) fn open(
        &self,
        run_id: &str,
        mode: Mode,
        opts: &RunOptions,
        policy: Option<RecoverPolicy<'_>>,
    ) -> Result<Session, Fault> {
        validate_run_id(run_id)?;
        let inbox = Some(self.inbox(run_id));
        if mode == Mode::Replay {
            let journal = self.backend.snapshot(run_id, self.key())?;
            return Session::new(run_id, mode, journal, None, opts, inbox);
        }
        let Checkout {
            journal,
            sink,
            guard,
            torn,
        } = self
            .backend
            .checkout(run_id, mode == Mode::Run, self.key())?;
        let mut session = Session::new(run_id, mode, journal, Some((sink, guard)), opts, inbox)?;
        session.start(opts, torn.as_ref(), policy, self.backend.is_remote())?;
        Ok(session)
    }

    /// A checkout outside any attempt (saga compensation).
    pub(crate) fn checkout(&self, run_id: &str) -> Result<Checkout, Fault> {
        self.backend.checkout(run_id, false, self.key())
    }

    pub(crate) fn snapshot(&self, run_id: &str) -> Result<Journal, Fault> {
        self.backend.snapshot(run_id, self.key())
    }

    pub(crate) fn verify(&self, run_id: &str) -> Result<VerifyReport, Fault> {
        Ok(self.snapshot(run_id)?.audit())
    }

    pub(crate) fn runs(&self) -> Result<Vec<String>, Fault> {
        self.backend.list()
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_journal_mut<R>(
        &self,
        run_id: &str,
        f: impl FnOnce(&mut Journal) -> R,
    ) -> Result<R, Fault> {
        let mut co = self.checkout(run_id)?;
        let out = f(&mut co.journal);
        let bytes = co.journal.to_bytes();
        co.sink
            .rewrite(&bytes)
            .map_err(|e| e.into_fault(bytes.len() as u64))?;
        Ok(out)
    }
}

/// Finish a session with the agent's result and build the report.
pub(crate) fn finish_session(
    mut session: Session,
    result: Result<Value, Fault>,
) -> Result<RunReport, Fault> {
    let output = session.end(result)?;
    Ok(session.into_report(output))
}

/// One attempt of one run: the session, and the oracle its contexts call.
///
/// Created by [`Runtime::begin`]. [`finish`](Self::finish) ends it with the
/// agent's result; dropping it instead is a crash (the lock or lease is
/// released, `attempt.end` is not written and unpersisted frames are lost).
pub struct Attempt<'r> {
    session: Session,
    oracle: &'r dyn Oracle,
}

impl std::fmt::Debug for Attempt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attempt")
            .field("session", &self.session)
            .finish()
    }
}

impl Attempt<'_> {
    /// The context of the root branch.
    pub fn ctx(&mut self) -> Ctx<'_> {
        Ctx::new(&mut self.session, ROOT.to_vec(), self.oracle)
    }

    /// The session, for split-phase steps on any branch.
    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }

    /// End the attempt with the agent's result: check completeness, write
    /// `attempt.end` (recording attempts), persist and check the run back
    /// in.
    pub fn finish(self, result: Result<Value, Fault>) -> Result<RunReport, Fault> {
        finish_session(self.session, result)
    }
}

static REFUSING: RefusingOracle = RefusingOracle;

/// The Pragmatic runtime: owns the oracle (your model client) and the
/// backend the journals of every run live in.
pub struct Runtime<O> {
    oracle: O,
    core: Core,
}

impl<O: Oracle> Runtime<O> {
    /// A runtime whose journals live in memory only (tests, ephemeral runs).
    pub fn in_memory(oracle: O) -> Self {
        Runtime::with_backend(Box::new(MemoryBackend::new()), oracle)
    }

    /// A runtime that persists one append-only journal file per run under
    /// `dir`. Runs survive process crashes: reopen the runtime on the same
    /// directory and `resume`.
    pub fn on_dir(dir: impl Into<PathBuf>, oracle: O) -> std::io::Result<Self> {
        Ok(Runtime {
            oracle,
            core: Core::on_dir(dir)?,
        })
    }

    /// A runtime over any backend.
    pub fn with_backend(backend: Box<dyn Backend>, oracle: O) -> Self {
        Runtime {
            oracle,
            core: Core::new(Arc::from(backend)),
        }
    }

    /// Key the journals' hash chains with HMAC-SHA-256 under `key`. Only
    /// holders of the key can then extend or rewrite a journal undetected.
    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.core.set_key(key);
        self
    }

    /// Begin an attempt (see the module documentation). `Run` creates the
    /// run if it does not exist; `Resume` requires it and decides its open
    /// effect intents with the default recovery policy; `Replay` reads a
    /// snapshot and never writes.
    pub fn begin(&self, run_id: &str, mode: Mode, opts: RunOptions) -> Result<Attempt<'_>, Fault> {
        self.begin_inner(run_id, mode, opts, None)
    }

    /// [`begin`](Self::begin) with an explicit recovery policy, consulted on
    /// resume for every effect intent an earlier attempt left without a
    /// result, and for a frontier effect whose latest result failed.
    pub fn begin_with(
        &self,
        run_id: &str,
        mode: Mode,
        opts: RunOptions,
        recover: RecoverPolicy<'_>,
    ) -> Result<Attempt<'_>, Fault> {
        self.begin_inner(run_id, mode, opts, Some(recover))
    }

    fn begin_inner(
        &self,
        run_id: &str,
        mode: Mode,
        opts: RunOptions,
        policy: Option<RecoverPolicy<'_>>,
    ) -> Result<Attempt<'_>, Fault> {
        let session = self.core.open(run_id, mode, &opts, policy)?;
        let oracle: &dyn Oracle = if mode == Mode::Replay {
            &REFUSING
        } else {
            &self.oracle
        };
        Ok(Attempt { session, oracle })
    }

    fn drive(
        attempt: Result<Attempt<'_>, Fault>,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        let mut attempt = attempt?;
        let result = agent(&mut attempt.ctx());
        attempt.finish(result)
    }

    /// Start (or continue) a durable run. If a journal for `run_id` already
    /// exists, its prefix is replayed first: `run` is safely re-enterable,
    /// which is what makes retries idempotent.
    pub fn run(
        &self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.run_with(run_id, RunOptions::default(), agent)
    }

    /// [`run`](Self::run) with explicit options.
    pub fn run_with(
        &self,
        run_id: &str,
        opts: RunOptions,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        Self::drive(self.begin(run_id, Mode::Run, opts), agent)
    }

    /// Resume a crashed run: replay the journaled prefix (zero model calls,
    /// no duplicate effects), then continue recording where it stopped.
    /// Effects the crash left without a result are written off and performed
    /// again (on a server-backed runtime, an explicit policy is required);
    /// a failed effect at the end of a branch is retried. Errors if no
    /// journal exists for `run_id`.
    pub fn resume(
        &self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        Self::drive(
            self.begin(run_id, Mode::Resume, RunOptions::default()),
            agent,
        )
    }

    /// [`resume`](Self::resume) with options and an explicit recovery policy
    /// for effects a crash left without a result ([Eff-recover]): for each,
    /// decide whether it completed (`Recover::Commit(result)`, for example
    /// after checking the world) or must be written off
    /// (`Recover::Compensate`: the resumed run performs it again). Failed
    /// effects at the end of a branch are retried, as by
    /// [`resume`](Self::resume); use [`begin_with`](Self::begin_with) to
    /// decide those too.
    pub fn resume_with(
        &self,
        run_id: &str,
        opts: RunOptions,
        mut recovery: impl FnMut(&str, &Value) -> Recover,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        let mut policy = |req: &RecoverRequest<'_>| match req.failure {
            None => recovery(req.name, req.arg),
            Some(_) => Recover::Compensate,
        };
        Self::drive(
            self.begin_with(run_id, Mode::Resume, opts, &mut policy),
            agent,
        )
    }

    /// Replay a recorded run, exactly, for debugging and audit: T1. Every
    /// outcome is read from the journal and the model is **never** called.
    /// Replay reads a snapshot, so it takes no lock and can audit a run that
    /// is still recording. Errors with [`Fault::ReplayExhausted`] if the
    /// recorded run never got as far as the agent does.
    pub fn replay(
        &self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.replay_with(run_id, RunOptions::default(), agent)
    }

    /// [`replay`](Self::replay) with options; only `on_code_change` applies.
    pub fn replay_with(
        &self,
        run_id: &str,
        opts: RunOptions,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        Self::drive(self.begin(run_id, Mode::Replay, opts), agent)
    }

    /// Deliver a value to a run's channel inbox (single-process delivery;
    /// the receive itself is journaled when the agent consumes it).
    pub fn send(&self, run_id: &str, channel: &str, value: impl Into<Value>) {
        self.core.send(run_id, channel, value.into());
    }

    /// Verify the run's durable journal: every chain link, commitment and
    /// ref, plus erasure accounting.
    pub fn verify(&self, run_id: &str) -> Result<VerifyReport, Fault> {
        self.core.verify(run_id)
    }

    /// The run's durable journal, read without a lock. Never writes.
    pub fn snapshot(&self, run_id: &str) -> Result<Journal, Fault> {
        self.core.snapshot(run_id)
    }

    /// Every run id in the backend.
    pub fn runs(&self) -> Result<Vec<String>, Fault> {
        self.core.runs()
    }

    /// The backend the journals live in.
    pub fn backend(&self) -> &dyn Backend {
        self.core.backend()
    }

    /// Formerly dropped a cached journal. Journals are no longer cached
    /// between attempts, so there is nothing to drop.
    #[deprecated(note = "journals are not cached between attempts; this does nothing")]
    pub fn evict(&self, run_id: &str) {
        let _ = run_id;
    }

    /// The oracle this runtime records with.
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// CRASH SIMULATION ONLY: check the run out, let `f` change its journal
    /// and write the result back whole, as a damaged disk or a crash might
    /// have left it.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn with_journal_mut<R>(
        &self,
        run_id: &str,
        f: impl FnOnce(&mut Journal) -> R,
    ) -> Result<R, Fault> {
        self.core.with_journal_mut(run_id, f)
    }

    /// CRASH SIMULATION ONLY: keep the first `keep` entries of the stored
    /// journal (notes included), as if the process had died with only that
    /// prefix durable.
    #[cfg(any(test, feature = "testing"))]
    pub fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        self.core.backend().crash_truncate(run_id, keep)
    }

    /// The saga's checkout (see [`Supervisor`](crate::Supervisor)).
    pub(crate) fn checkout(&self, run_id: &str) -> Result<Checkout, Fault> {
        self.core.checkout(run_id)
    }
}
