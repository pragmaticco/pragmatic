//! The **Runtime** - record, resume, replay.
//!
//! Wrap your agent in a closure over [`Ctx`], hand it to the runtime under a
//! stable run id, and every oracle call, effect, receive, and clock read is
//! journaled as the run proceeds:
//!
//! ```
//! use pragmatic::{Runtime, SeededOracle};
//!
//! let mut rt = Runtime::in_memory(SeededOracle::new(42));
//! let report = rt.run("run-1", |ctx| {
//!     let plan = ctx.oracle("plan the task")?;
//!     let step = ctx.oracle(format!("execute: {plan}"))?;
//!     Ok(format!("done: {step}").into())
//! }).unwrap();
//!
//! // Crash anywhere; `resume` replays the journaled prefix (no model calls)
//! // and continues recording at the tail.
//! // Replay the whole run later, exactly - the model is never consulted.
//! let audit = rt.replay("run-1", |ctx| {
//!     let plan = ctx.oracle("plan the task")?;
//!     let step = ctx.oracle(format!("execute: {plan}"))?;
//!     Ok(format!("done: {step}").into())
//! }).unwrap();
//! assert_eq!(report.trace, audit.trace); // T1, empirically
//! ```
//!
//! For `async` agents, see [`AsyncRuntime`](crate::AsyncRuntime).

use std::path::PathBuf;

use crate::ctx::{Ctx, RunOptions, TraceLabel};
use crate::fault::Fault;
use crate::journal_v1::{Cursor, Journal};
use crate::oracle::{Oracle, RefusingOracle};
use crate::sha256::Digest;
use crate::store::JournalStore;
use crate::value::Value;

pub use crate::store::Recover;

/// The result of driving one run to completion.
#[derive(Clone, Debug)]
pub struct RunReport {
    pub run_id: String,
    /// The agent's output.
    pub output: Value,
    /// The observable trace - identical between a recorded run and its
    /// replay (T1).
    pub trace: Vec<TraceLabel>,
    /// Journal length after this attempt.
    pub journal_len: u64,
    /// Head of the tamper-evident hash chain (the run's integrity
    /// commitment).
    pub chain_head: Option<Digest>,
    /// Steps served from the journal (zero model calls).
    pub replayed_steps: u64,
    /// Steps recorded fresh this attempt.
    pub fresh_steps: u64,
}

/// The Pragmatic runtime: owns the oracle (your model client) and the
/// journals for every run it drives.
pub struct Runtime<O> {
    oracle: O,
    store: JournalStore,
}

impl<O: Oracle> Runtime<O> {
    /// A runtime whose journals live in memory only (tests, ephemeral runs).
    pub fn in_memory(oracle: O) -> Self {
        Runtime {
            oracle,
            store: JournalStore::in_memory(),
        }
    }

    /// A runtime that persists one append-only journal file per run under
    /// `dir`. Runs survive process crashes: reopen the runtime on the same
    /// directory and `resume`.
    pub fn on_dir(dir: impl Into<PathBuf>, oracle: O) -> std::io::Result<Self> {
        Ok(Runtime {
            oracle,
            store: JournalStore::on_dir(dir)?,
        })
    }

    /// Key the journals' hash chains with HMAC-SHA-256 under `key`, making
    /// the audit trail attributable to this runtime, not just tamper-evident.
    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.store.set_key(key);
        self
    }

    fn execute(
        &mut self,
        run_id: &str,
        opts: &RunOptions,
        strict: bool,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        let (journal, inbox) = self.store.parts(run_id);

        let refusing = RefusingOracle;
        let oracle: &dyn Oracle = if strict { &refusing } else { &self.oracle };

        let mut ctx = Ctx::new(journal, oracle, inbox, strict, opts);
        let result = agent(&mut ctx);
        let (trace, replayed, fresh) = ctx.finish(result.as_ref().ok());

        // The attempt is over; make everything recorded so far durable.
        journal.sync()?;

        let output = result?;
        Ok(RunReport {
            run_id: run_id.to_string(),
            output,
            trace,
            journal_len: journal.len(),
            chain_head: journal.head(),
            replayed_steps: replayed,
            fresh_steps: fresh,
        })
    }

    /// Start (or continue) a durable run. If a journal for `run_id` already
    /// exists, its prefix is replayed first - `run` is safely re-enterable,
    /// which is what makes retries idempotent.
    pub fn run(
        &mut self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.run_with(run_id, RunOptions::default(), agent)
    }

    /// [`run`](Self::run) with explicit budget / capability options.
    pub fn run_with(
        &mut self,
        run_id: &str,
        opts: RunOptions,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.store.load(run_id, true)?;
        self.execute(run_id, &opts, false, agent)
    }

    /// Resume a crashed run: replay the journaled prefix (zero model calls,
    /// no duplicate effects), then continue recording where it stopped.
    /// Errors if no journal exists for `run_id`.
    pub fn resume(
        &mut self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.resume_with(
            run_id,
            RunOptions::default(),
            |_, _| Recover::Compensate,
            agent,
        )
    }

    /// [`resume`](Self::resume) with options and an explicit recovery policy
    /// for dangling effect intents ([Eff-recover]): for each effect that
    /// crashed inside its write-ahead window, decide whether it completed
    /// (`Recover::Commit(result)` - e.g. after re-running an idempotent
    /// effect or checking the world) or must be written off
    /// (`Recover::Compensate`, the default - the resumed run performs it
    /// fresh).
    pub fn resume_with(
        &mut self,
        run_id: &str,
        opts: RunOptions,
        mut recovery: impl FnMut(&str, &Value) -> Recover,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.store.recover_dangling(run_id, &mut recovery)?;
        self.execute(run_id, &opts, false, agent)
    }

    /// Replay a recorded run, exactly, for debugging and audit - T1. Every
    /// outcome is read from the journal; the model is **never** called (the
    /// oracle is replaced by one that refuses). Errors with
    /// [`Fault::ReplayExhausted`] if the recorded run never completed.
    pub fn replay(
        &mut self,
        run_id: &str,
        agent: impl FnOnce(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        self.store.load(run_id, false)?;
        self.execute(run_id, &RunOptions::default(), true, agent)
    }

    /// Deliver a value to a run's channel inbox (single-process delivery;
    /// the receive itself is journaled when the agent consumes it).
    pub fn send(&mut self, run_id: &str, channel: &str, value: impl Into<Value>) {
        self.store.send(run_id, channel, value.into());
    }

    /// Verify the run's hash chain end to end. `Err(cursor)` names the first
    /// tampered entry.
    pub fn verify(&mut self, run_id: &str) -> Result<Result<(), Cursor>, Fault> {
        Ok(self.store.load(run_id, false)?.verify())
    }

    /// Direct access to a loaded journal (inspection, tests).
    pub fn journal(&mut self, run_id: &str) -> Result<&mut Journal, Fault> {
        self.store.load(run_id, false)
    }

    /// Drop the in-memory cache for `run_id` (Dir mode: forces a reload from
    /// disk on next use - how tests model a process restart).
    pub fn evict(&mut self, run_id: &str) {
        self.store.evict(run_id);
    }

    /// The oracle this runtime records with.
    pub fn oracle(&self) -> &O {
        &self.oracle
    }
}
