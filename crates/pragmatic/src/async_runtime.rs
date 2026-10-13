//! The **async runtime** - the same three guarantees for `async` agents.
//!
//! Executor-agnostic and still zero-dependency: the runtime returns ordinary
//! futures and never spawns, sleeps, or does async I/O itself (journal
//! writes are fast local appends). Drive it from tokio, async-std, smol, or
//! the built-in [`block_on`].
//!
//! ```
//! use pragmatic::{block_on, AsyncCtx, AsyncRuntime, Fault, SeededOracle, Value};
//!
//! async fn research(ctx: &mut AsyncCtx<'_, SeededOracle>) -> Result<Value, Fault> {
//!     let plan = ctx.oracle("plan the task").await?;          // journaled
//!     let step = ctx.oracle(format!("execute: {plan}")).await?;
//!     Ok(format!("done: {step}").into())
//! }
//!
//! let mut rt = AsyncRuntime::in_memory(SeededOracle::new(42));
//! let report = block_on(rt.run("run-1", research)).unwrap();
//! let audit  = block_on(rt.replay("run-1", research)).unwrap();
//! assert_eq!(report.trace, audit.trace); // T1, empirically
//! ```
//!
//! Replay safety is mode-ordered, not oracle-swapped: in strict replay the
//! context errors with [`Fault::ReplayExhausted`] *before* the fresh-sample
//! path can run, so the model is never consulted - same guarantee as the
//! sync runtime, enforced in the same place.

use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use crate::ctx::{Ctx, RunOptions};
use crate::fault::Fault;
use crate::journal_v1::{Cursor, Journal};
use crate::oracle::{Oracle, RefusingOracle};
use crate::runtime::RunReport;
use crate::store::{JournalStore, Recover};
use crate::value::Value;

/// A model call that is awaited: prompt in, one realized outcome out.
///
/// Every synchronous [`Oracle`] is automatically an `AsyncOracle` (the call
/// resolves immediately, blocking the polling thread for its duration - fine
/// for tests and CLIs; implement `AsyncOracle` natively over your async HTTP
/// client for servers).
pub trait AsyncOracle {
    /// Sample one outcome for `prompt` from the model's distribution.
    fn call(&self, prompt: &Value) -> impl Future<Output = Result<Value, Fault>> + '_;

    /// Audit metadata recorded with each draw; never consulted on replay.
    fn provenance(&self) -> String {
        "oracle".to_string()
    }
}

impl<O: Oracle> AsyncOracle for O {
    fn call(&self, prompt: &Value) -> impl Future<Output = Result<Value, Fault>> + '_ {
        let out = Oracle::call(self, prompt);
        async move { out }
    }

    fn provenance(&self) -> String {
        Oracle::provenance(self)
    }
}

static REFUSING: RefusingOracle = RefusingOracle;

/// The async durable execution context. Identical semantics to [`Ctx`] -
/// same journal, same record/replay rules, same trace - with awaited oracle
/// calls and effects.
pub struct AsyncCtx<'a, O> {
    inner: Ctx<'a>,
    oracle: &'a O,
}

impl<'a, O: AsyncOracle> AsyncCtx<'a, O> {
    /// `let x ⇐ oracle(e)` - one model call, journaled once
    /// ([O-rec]/[O-rep]/[O-resume]).
    pub async fn oracle(&mut self, prompt: impl Into<Value>) -> Result<Value, Fault> {
        let prompt = prompt.into();
        if let Some(outcome) = self.inner.oracle_replay(&prompt)? {
            return Ok(outcome);
        }
        let outcome = self.oracle.call(&prompt).await?;
        let provenance = self.oracle.provenance();
        self.inner.oracle_commit(prompt, outcome, provenance)
    }

    /// A durable effect under the three-phase write-ahead discipline, with
    /// an awaited perform step ([Eff-intent]/[Eff-perform]/[Eff-commit]).
    pub async fn effect<F>(
        &mut self,
        name: &str,
        arg: impl Into<Value>,
        perform: F,
    ) -> Result<Value, Fault>
    where
        F: AsyncFnOnce(&Value) -> Result<Value, Fault>,
    {
        let arg = arg.into();
        if let Some(result) = self.inner.effect_replay(name, &arg)? {
            return Ok(result);
        }
        self.inner.effect_begin(name, arg.clone())?;
        let result = perform(&arg).await?;
        self.inner.effect_commit(name, result)
    }

    /// Receive on a channel (journaled; [Rcv-rec]/[Rcv-rep]).
    pub fn recv(&mut self, channel: &str) -> Result<Value, Fault> {
        self.inner.recv(channel)
    }

    /// A journaled clock read.
    pub fn now(&mut self) -> Result<u64, Fault> {
        self.inner.now()
    }

    /// Assert an agent contract; falsified contracts are `ContractViol`
    /// faults.
    pub fn contract(&self, holds: bool, msg: &str) -> Result<(), Fault> {
        self.inner.contract(holds, msg)
    }

    /// Journal (or verify) the program identity - emitted by
    /// `#[pragmatic::durable]`.
    pub fn program_marker(&mut self, name: &str, hash: &str) -> Result<(), Fault> {
        self.inner.program_marker(name, hash)
    }

    /// True while steps are served from the journal.
    pub fn is_replaying(&self) -> bool {
        self.inner.is_replaying()
    }
}

/// The async Pragmatic runtime. Same storage, journals, and guarantees as
/// [`Runtime`](crate::Runtime); agents are `async` functions over
/// [`AsyncCtx`].
pub struct AsyncRuntime<O> {
    oracle: O,
    store: JournalStore,
}

impl<O: AsyncOracle> AsyncRuntime<O> {
    /// A runtime whose journals live in memory only.
    pub fn in_memory(oracle: O) -> Self {
        AsyncRuntime {
            oracle,
            store: JournalStore::in_memory(),
        }
    }

    /// One append-only journal file per run under `dir`; runs survive
    /// process crashes.
    pub fn on_dir(dir: impl Into<PathBuf>, oracle: O) -> std::io::Result<Self> {
        Ok(AsyncRuntime {
            oracle,
            store: JournalStore::on_dir(dir)?,
        })
    }

    /// HMAC-key the journals' hash chains.
    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.store.set_key(key);
        self
    }

    async fn execute<F>(
        &mut self,
        run_id: &str,
        opts: &RunOptions,
        strict: bool,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let (journal, inbox) = self.store.parts(run_id);

        let inner = Ctx::new(journal, &REFUSING, inbox, strict, opts);
        let mut ctx = AsyncCtx {
            inner,
            oracle: &self.oracle,
        };
        // The future borrows ctx; it is driven to completion before ctx is
        // torn down, so the journal sees every step of this attempt.
        let result = agent(&mut ctx).await;
        let (trace, replayed, fresh) = ctx.inner.finish(result.as_ref().ok());

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

    /// Start (or continue) a durable run. Re-enterable: an existing journal
    /// prefix is replayed first.
    pub async fn run<F>(&mut self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.run_with(run_id, RunOptions::default(), agent).await
    }

    /// [`run`](Self::run) with explicit budget / capability options.
    pub async fn run_with<F>(
        &mut self,
        run_id: &str,
        opts: RunOptions,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.store.load(run_id, true)?;
        self.execute(run_id, &opts, false, agent).await
    }

    /// Resume a crashed run: replay the prefix (zero model calls), continue
    /// recording at the tail. Dangling effect intents are written off
    /// (performed fresh); use [`resume_with`](Self::resume_with) to commit
    /// them instead.
    pub async fn resume<F>(&mut self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.resume_with(
            run_id,
            RunOptions::default(),
            |_, _| Recover::Compensate,
            agent,
        )
        .await
    }

    /// [`resume`](Self::resume) with an explicit recovery policy for
    /// dangling effect intents ([Eff-recover]).
    pub async fn resume_with<F>(
        &mut self,
        run_id: &str,
        opts: RunOptions,
        mut recovery: impl FnMut(&str, &Value) -> Recover,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.store.recover_dangling(run_id, &mut recovery)?;
        self.execute(run_id, &opts, false, agent).await
    }

    /// Replay a recorded run, exactly, for debugging and audit - T1. The
    /// model is never consulted.
    pub async fn replay<F>(&mut self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.store.load(run_id, false)?;
        self.execute(run_id, &RunOptions::default(), true, agent)
            .await
    }

    /// Deliver a value to a run's channel inbox.
    pub fn send(&mut self, run_id: &str, channel: &str, value: impl Into<Value>) {
        self.store.send(run_id, channel, value.into());
    }

    /// Verify the run's hash chain end to end.
    pub fn verify(&mut self, run_id: &str) -> Result<Result<(), Cursor>, Fault> {
        Ok(self.store.load(run_id, false)?.verify())
    }

    /// Direct access to a loaded journal.
    pub fn journal(&mut self, run_id: &str) -> Result<&mut Journal, Fault> {
        self.store.load(run_id, false)
    }

    /// Drop the in-memory cache for `run_id`.
    pub fn evict(&mut self, run_id: &str) {
        self.store.evict(run_id);
    }

    /// The oracle this runtime records with.
    pub fn oracle(&self) -> &O {
        &self.oracle
    }
}

/// Drive a future to completion on the current thread - a minimal,
/// dependency-free executor for CLIs, tests, and simple binaries. Servers
/// should use their existing executor (tokio et al.); the runtime's futures
/// are executor-agnostic.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}
