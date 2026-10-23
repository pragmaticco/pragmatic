//! The **async runtime**: the same three guarantees for `async` agents.
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
//! let rt = AsyncRuntime::in_memory(SeededOracle::new(42));
//! let report = block_on(rt.run("run-1", research)).unwrap();
//! let audit  = block_on(rt.replay("run-1", research)).unwrap();
//! assert_eq!(report.trace, audit.trace); // T1, empirically
//! ```
//!
//! # Concurrency
//!
//! An [`AsyncCtx`] shares the attempt's [`Session`] through a `RefCell` and
//! borrows it only for the synchronous part of a step, never across an
//! `.await`. That is what lets [`AsyncCtx::parallel`] poll its children
//! concurrently: while one child awaits its model call, another can record
//! its own steps on its own branch. Replay matches each branch on its own,
//! so a replay whose children interleave differently from the recording
//! still reproduces every child exactly.
//!
//! Replay safety is mode-ordered: in strict replay the session raises
//! [`Fault::ReplayExhausted`] *before* the fresh-sample path can run, so the
//! model is never consulted.

use std::cell::RefCell;
use std::future::Future;
use std::path::PathBuf;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use crate::backend::{Backend, MemoryBackend};
use crate::ctx::{
    effect_fault, failed_draw, failed_effect, lowest_failure, replayed_draw, RunOptions,
};
use crate::fault::Fault;
use crate::journal::{Branch, Journal, VerifyReport, ROOT};
use crate::oracle::Oracle;
use crate::runtime::{finish_session, Core, Mode, Recover, RecoverRequest, RunReport};
use crate::session::{DrawStart, EffectStart, Session, META_OK};
use crate::value::Value;

/// A model call that is awaited: prompt in, one realized outcome out.
///
/// Every synchronous [`Oracle`] is automatically an `AsyncOracle` (the call
/// resolves immediately, blocking the polling thread for its duration: fine
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

/// The async durable execution context: one branch of one attempt. Same
/// journal, same record and replay rules and same trace as [`Ctx`], with
/// awaited model calls and effects.
///
/// [`Ctx`]: crate::Ctx
pub struct AsyncCtx<'a, O> {
    session: &'a RefCell<Session>,
    branch: Branch,
    oracle: &'a O,
}

impl<'a, O: AsyncOracle> AsyncCtx<'a, O> {
    /// A context for `branch` of the session in `session`. Hosts that drive
    /// a [`Session`] themselves can build one; the runtime builds the root
    /// context of each attempt.
    pub fn new(session: &'a RefCell<Session>, branch: Branch, oracle: &'a O) -> Self {
        AsyncCtx {
            session,
            branch,
            oracle,
        }
    }

    /// The branch this context steps on.
    pub fn branch(&self) -> &Branch {
        &self.branch
    }

    /// Run `f` with the session borrowed. The borrow ends when `f` returns,
    /// so it is never held across an `.await`.
    fn with<R>(&self, f: impl FnOnce(&mut Session, &Branch) -> R) -> R {
        f(&mut self.session.borrow_mut(), &self.branch)
    }

    /// `let x ⇐ oracle(e)`: one model call, journaled once
    /// ([O-rec]/[O-rep]/[O-resume]).
    pub async fn oracle(&mut self, prompt: impl Into<Value>) -> Result<Value, Fault> {
        let prompt = prompt.into();
        let provenance = self.oracle.provenance();
        let start = self.with(|s, b| s.draw_begin(b, &provenance, vec![prompt.clone()]))?;
        let intent = match start {
            DrawStart::Replayed { meta, body, .. } => return replayed_draw(&meta, body),
            DrawStart::Fresh(intent) => intent,
        };
        match self.oracle.call(&prompt).await {
            Ok(outcome) => {
                self.with(|s, _| {
                    s.draw_end(
                        intent,
                        META_OK.to_string(),
                        Value::default(),
                        outcome.clone(),
                    )
                })?;
                Ok(outcome)
            }
            Err(fault) => Err(self.with(|s, _| failed_draw(s, intent, &fault))?),
        }
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
        let start = self.with(|s, b| s.effect_begin(b, name, arg.clone()))?;
        let intent = match start {
            EffectStart::Replayed(result) => return Ok(result),
            EffectStart::Failed { kind, message } => return Err(effect_fault(&kind, message)),
            EffectStart::Fresh { intent, .. } => intent,
        };
        match perform(&arg).await {
            Ok(result) => {
                self.with(|s, _| s.effect_end(intent, Ok(result.clone())))?;
                Ok(result)
            }
            Err(fault) => Err(self.with(|s, _| failed_effect(s, intent, &fault))?),
        }
    }

    /// Receive on a channel (journaled; [Rcv-rec]/[Rcv-rep]).
    pub fn recv(&mut self, channel: &str) -> Result<Value, Fault> {
        self.with(|s, b| s.recv(b, channel))
    }

    /// A journaled clock read.
    pub fn now(&mut self) -> Result<u64, Fault> {
        self.with(|s, b| s.now(b))
    }

    /// A journaled random draw; see [`Session::random`].
    pub fn random(&mut self, source: &str, args: &str) -> Result<Value, Fault> {
        self.with(|s, b| s.random(b, source, args))
    }

    /// True if this run takes the patch `name`; see [`Session::patched`].
    pub fn patched(&mut self, name: &str) -> Result<bool, Fault> {
        self.with(|s, b| s.patched(b, name))
    }

    /// Consume the marker of patch `name` if this run took it; see
    /// [`Session::deprecate_patch`].
    pub fn deprecate_patch(&mut self, name: &str) -> Result<(), Fault> {
        self.with(|s, b| s.deprecate_patch(b, name))
    }

    /// Assert an agent contract; falsified contracts are `ContractViol`
    /// faults.
    pub fn contract(&self, holds: bool, msg: &str) -> Result<(), Fault> {
        if holds {
            Ok(())
        } else {
            Err(Fault::ContractViol(msg.to_string()))
        }
    }

    /// Journal (or check) the program identity on this branch: emitted by
    /// `#[pragmatic::durable]`.
    pub fn program_marker(&mut self, name: &str, hash: &str) -> Result<(), Fault> {
        self.with(|s, b| s.program_marker(b, name, hash))
    }

    /// True while this branch's steps are served from the journal.
    pub fn is_replaying(&self) -> bool {
        self.session.borrow().is_replaying(&self.branch)
    }

    /// Run `n` children concurrently in a parallel region (spec 2.7).
    /// `f(i, ctx)` returns the future of child `i`, which owns its context.
    ///
    /// The fork is journaled when the region starts. Every child runs to
    /// completion even when a sibling fails, results come back in child
    /// order, and if any child failed the region fails with the failure of
    /// the lowest-index failed child, not the first failure in time. While
    /// the region runs, this context's own branch is suspended. Dropping
    /// the region's future part way is a crash of the attempt: nothing more
    /// is journaled for it.
    pub async fn parallel<T, F, Fut>(&mut self, n: u32, mut f: F) -> Result<Vec<T>, Fault>
    where
        F: FnMut(u32, AsyncCtx<'a, O>) -> Fut,
        Fut: Future<Output = Result<T, Fault>>,
    {
        if n == 0 {
            return Ok(Vec::new());
        }
        let children = self.with(|s, b| s.fork(b, n))?;
        let futures = children
            .iter()
            .enumerate()
            .map(|(i, child)| {
                f(
                    i as u32,
                    AsyncCtx::new(self.session, child.clone(), self.oracle),
                )
            })
            .collect();
        let results = JoinAll::new(futures).await;
        let ok: Vec<bool> = results.iter().map(Result::is_ok).collect();
        let joined = self.with(|s, b| s.join_each(b, &children, &ok));
        lowest_failure(results, joined)
    }
}

/// Polls every child future until all of them have finished, keeping their
/// outputs in order. Each poll of the join polls every unfinished child, so
/// whichever child a wakeup was meant for makes progress.
struct JoinAll<F: Future> {
    futures: Vec<Option<Pin<Box<F>>>>,
    outputs: Vec<Option<F::Output>>,
}

impl<F: Future> JoinAll<F> {
    fn new(futures: Vec<F>) -> Self {
        let outputs = futures.iter().map(|_| None).collect();
        JoinAll {
            futures: futures.into_iter().map(|f| Some(Box::pin(f))).collect(),
            outputs,
        }
    }
}

// The children are pinned in their own boxes and the outputs are never
// pinned, so moving a `JoinAll` is harmless.
impl<F: Future> Unpin for JoinAll<F> {}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut pending = false;
        for (slot, out) in this.futures.iter_mut().zip(this.outputs.iter_mut()) {
            if let Some(fut) = slot {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(v) => {
                        *out = Some(v);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(
                this.outputs
                    .iter_mut()
                    .map(|o| o.take().expect("every child finished"))
                    .collect(),
            )
        }
    }
}

/// The async Stet runtime. Same storage, journals, and guarantees as
/// [`Runtime`](crate::Runtime); agents are `async` functions over
/// [`AsyncCtx`].
pub struct AsyncRuntime<O> {
    oracle: O,
    core: Core,
}

impl<O: AsyncOracle> AsyncRuntime<O> {
    /// A runtime whose journals live in memory only.
    pub fn in_memory(oracle: O) -> Self {
        AsyncRuntime::with_backend(Box::new(MemoryBackend::new()), oracle)
    }

    /// One append-only journal file per run under `dir`; runs survive
    /// process crashes.
    pub fn on_dir(dir: impl Into<PathBuf>, oracle: O) -> std::io::Result<Self> {
        Ok(AsyncRuntime {
            oracle,
            core: Core::on_dir(dir)?,
        })
    }

    /// A runtime over any backend.
    pub fn with_backend(backend: Box<dyn Backend>, oracle: O) -> Self {
        AsyncRuntime {
            oracle,
            core: Core::new(Arc::from(backend)),
        }
    }

    /// HMAC-key the journals' hash chains.
    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.core.set_key(key);
        self
    }

    async fn drive<F>(&self, session: Session, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let cell = RefCell::new(session);
        let result = {
            let mut ctx = AsyncCtx::new(&cell, ROOT.to_vec(), &self.oracle);
            agent(&mut ctx).await
        };
        finish_session(cell.into_inner(), result)
    }

    /// Start (or continue) a durable run. Re-enterable: an existing journal
    /// prefix is replayed first.
    pub async fn run<F>(&self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.run_with(run_id, RunOptions::default(), agent).await
    }

    /// [`run`](Self::run) with explicit options.
    pub async fn run_with<F>(
        &self,
        run_id: &str,
        opts: RunOptions,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let session = self.core.open(run_id, Mode::Run, &opts, None)?;
        self.drive(session, agent).await
    }

    /// Resume a crashed run: replay the prefix (zero model calls), continue
    /// recording at the tail. Effects a crash left without a result are
    /// written off (performed again); use [`resume_with`](Self::resume_with)
    /// to commit them instead.
    pub async fn resume<F>(&self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let session = self
            .core
            .open(run_id, Mode::Resume, &RunOptions::default(), None)?;
        self.drive(session, agent).await
    }

    /// [`resume`](Self::resume) with an explicit recovery policy for
    /// effects a crash left without a result ([Eff-recover]).
    pub async fn resume_with<F>(
        &self,
        run_id: &str,
        opts: RunOptions,
        mut recovery: impl FnMut(&str, &Value) -> Recover,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let mut policy = |req: &RecoverRequest<'_>| match req.failure {
            None => recovery(req.name, req.arg),
            Some(_) => Recover::Compensate,
        };
        let session = self
            .core
            .open(run_id, Mode::Resume, &opts, Some(&mut policy))?;
        self.drive(session, agent).await
    }

    /// Replay a recorded run, exactly, for debugging and audit: T1. The
    /// model is never consulted.
    pub async fn replay<F>(&self, run_id: &str, agent: F) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        self.replay_with(run_id, RunOptions::default(), agent).await
    }

    /// [`replay`](Self::replay) with options; only `on_code_change` applies.
    pub async fn replay_with<F>(
        &self,
        run_id: &str,
        opts: RunOptions,
        agent: F,
    ) -> Result<RunReport, Fault>
    where
        F: AsyncFnOnce(&mut AsyncCtx<'_, O>) -> Result<Value, Fault>,
    {
        let session = self.core.open(run_id, Mode::Replay, &opts, None)?;
        self.drive(session, agent).await
    }

    /// Deliver a value to a run's channel inbox.
    pub fn send(&self, run_id: &str, channel: &str, value: impl Into<Value>) {
        self.core.send(run_id, channel, value.into());
    }

    /// Verify the run's durable journal; see
    /// [`Runtime::verify`](crate::Runtime::verify).
    pub fn verify(&self, run_id: &str) -> Result<VerifyReport, Fault> {
        self.core.verify(run_id)
    }

    /// The run's durable journal, read without a lock.
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

    /// Formerly dropped a cached journal; does nothing.
    #[deprecated(note = "journals are not cached between attempts; this does nothing")]
    pub fn evict(&self, run_id: &str) {
        let _ = run_id;
    }

    /// The oracle this runtime records with.
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// CRASH SIMULATION ONLY: see
    /// [`Runtime::with_journal_mut`](crate::Runtime::with_journal_mut).
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn with_journal_mut<R>(
        &self,
        run_id: &str,
        f: impl FnOnce(&mut Journal) -> R,
    ) -> Result<R, Fault> {
        self.core.with_journal_mut(run_id, f)
    }

    /// CRASH SIMULATION ONLY: see
    /// [`Runtime::crash_truncate`](crate::Runtime::crash_truncate).
    #[cfg(any(test, feature = "testing"))]
    pub fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        self.core.backend().crash_truncate(run_id, keep)
    }
}

/// Drive a future to completion on the current thread: a minimal,
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
