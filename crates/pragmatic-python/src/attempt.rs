//! One attempt of one run, held by a Python object (spec 6.2).
//!
//! # Locks and the GIL
//!
//! An [`Attempt`] is shared by every task and thread the agent steps from,
//! so its state sits behind two Rust locks: `state` (the core
//! [`OwnedAttempt`] and its session) and `slot` (the session's sink while
//! no persist is running). Both are taken only inside `Python::detach`, so
//! a thread waiting for one never holds the GIL, and neither is ever held
//! while Python code runs: a step locks the session, runs the core
//! primitive (which only appends) and unlocks before anything else happens.
//! The lock order is `slot` before `state`, and `state` is never held while
//! `slot` is taken.
//!
//! # Durability (spec 3.2, 6.2)
//!
//! The session's sink is detached when the attempt begins
//! ([`Session::detach_sink`]), so primitives append without persisting and
//! return the journal length the step needs to be durable (`upto`, or
//! `None` when it appended nothing new). The Python layer then calls
//! [`Attempt::persist`] before it releases the value: inline in a
//! synchronous attempt, on the attempt's dedicated single-thread executor
//! in an async one, so the event loop never waits on storage. `persist`
//! takes the sink out of its slot, persists every buffered frame through it
//! with no lock held (a Python store takes the GIL itself), and puts it
//! back. At most one persist runs at a time; one that arrives meanwhile
//! waits, then sends everything buffered since (group commit).
//!
//! A persist failure is sticky: the session fails, and every later step
//! raises the same exception object the store raised the first time.
//!
//! # Ownership
//!
//! Every step first checks that its caller owns the attempt
//! ([`Attempt::enter`]): the context variable `pragmatic._native.CURRENT`
//! must hold this attempt's token, and then either the calling thread is
//! the one that runs a synchronous attempt, or (for `arun`) the current
//! task is the attempt's root task or a `ctx.gather` child. A thread with
//! no running event loop that carries the token (what `asyncio.to_thread`
//! creates) is accepted; `loop.run_in_executor` does not copy context
//! variables, so its threads are refused. The step's branch comes from the
//! same variable, which is how `ctx.gather` routes each child's steps to its
//! own branch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::ThreadId;

use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PySet};

use pragmatic_rt::journal::{Branch, Content, Event};
use pragmatic_rt::runtime::OwnedAttempt;
use pragmatic_rt::{DrawStart, EffectStart, Fault, Mode, Session, Sink, Value};

use crate::errors::{clear_store_error, fault_err, not_in_run, take_store_error, FaultHandle};
use crate::report::{convert_report, RunReport};

/// The context variable holding `(attempt token, branch)` for the code
/// running in it (spec 6.4).
pub static CURRENT: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

/// Create `CURRENT` (called once, at module initialization).
pub fn context_var(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    CURRENT
        .get_or_try_init(py, || {
            let cv = py.import("contextvars")?.getattr("ContextVar")?;
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("default", py.None())?;
            Ok::<_, PyErr>(cv.call(("pragmatic_attempt",), Some(&kwargs))?.unbind())
        })
        .map(|v| v.bind(py))
}

static GET_RUNNING_LOOP: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static CURRENT_TASK: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

/// Tokens identify attempts in the context variable. They are never reused
/// within a process, so a context copied from a finished attempt can never
/// pass for a later one.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Who may step an attempt.
pub enum Owner {
    /// A synchronous attempt: the thread that runs it.
    Thread(ThreadId),
    /// An async attempt: the tasks in the attempt's task set (its root task
    /// and the children of `ctx.gather`), and threads that carry its token
    /// without a running event loop (`asyncio.to_thread`).
    Tasks,
}

/// The sink while no persist runs.
struct Slot {
    sink: Option<Box<dyn Sink>>,
    busy: bool,
}

/// Why a step could not run.
enum StepError {
    /// The attempt has finished or been abandoned.
    Finished,
    /// The core refused the step. `sticky` is true when the fault is the
    /// session's sticky persist failure.
    Fault { fault: Fault, sticky: bool },
}

/// What a waiting persist found when it got the slot.
enum Next {
    Done,
    Gone,
    Failed(Fault),
    Persist {
        sink: Box<dyn Sink>,
        at: u64,
        frames: Vec<u8>,
        head: [u8; 32],
        upto: u64,
    },
}

/// One attempt of one run. See the module documentation.
#[pyclass(frozen, module = "pragmatic._native")]
pub struct Attempt {
    token: u64,
    run_id: String,
    mode: Mode,
    owner: Owner,
    tasks: Py<PySet>,
    state: Mutex<Option<OwnedAttempt>>,
    slot: Mutex<Slot>,
    idle: Condvar,
    /// The exception the first failed persist raised, raised again by every
    /// later step.
    sticky: PyOnceLock<Py<PyAny>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The journal length a step needs durable, or `None` when everything it
/// appended (if anything) is already durable.
fn pending_upto(s: &Session) -> Option<u64> {
    let len = s.journal().len();
    (len > s.journal().persisted_len()).then_some(len)
}

impl Attempt {
    /// Wrap a begun attempt. Its sink is detached here, so from now on the
    /// binding persists (see the module documentation).
    pub fn new(
        py: Python<'_>,
        mut owned: OwnedAttempt,
        run_id: &str,
        mode: Mode,
        owner: Owner,
    ) -> PyResult<Attempt> {
        let sink = owned.session().detach_sink();
        Ok(Attempt {
            token: NEXT_TOKEN.fetch_add(1, Ordering::Relaxed),
            run_id: run_id.to_string(),
            mode,
            owner,
            tasks: PySet::empty(py)?.unbind(),
            state: Mutex::new(Some(owned)),
            slot: Mutex::new(Slot { sink, busy: false }),
            idle: Condvar::new(),
            sticky: PyOnceLock::new(),
        })
    }

    fn hint(&self) -> String {
        format!(
            "ctx used outside the attempt that owns it (run '{}'): journaled steps run in the \
             agent's own thread or task, in a ctx.gather child, or in a thread started with \
             asyncio.to_thread; use ctx.gather or asyncio.to_thread instead of \
             asyncio.create_task, asyncio.gather, loop.run_in_executor or a new thread",
            self.run_id
        )
    }

    /// The ownership check every step makes before it touches anything,
    /// returning the branch the step runs on.
    fn enter(&self, py: Python<'_>) -> PyResult<Branch> {
        let current = context_var(py)?.call_method0("get")?;
        if current.is_none() {
            return Err(not_in_run(py, self.hint()));
        }
        let (token, branch): (u64, Vec<u32>) =
            current.extract().map_err(|_| not_in_run(py, self.hint()))?;
        if token != self.token {
            return Err(not_in_run(py, self.hint()));
        }
        match self.owner {
            Owner::Thread(id) => {
                if std::thread::current().id() != id {
                    return Err(not_in_run(py, self.hint()));
                }
            }
            Owner::Tasks => {
                let running = GET_RUNNING_LOOP
                    .import(py, "asyncio", "_get_running_loop")?
                    .call0()?;
                if !running.is_none() {
                    let task = CURRENT_TASK
                        .import(py, "asyncio", "current_task")?
                        .call1((running,))?;
                    if task.is_none() || !self.tasks.bind(py).contains(task)? {
                        return Err(not_in_run(py, self.hint()));
                    }
                }
            }
        }
        Ok(branch)
    }

    /// Run a core primitive on the caller's branch: the ownership check,
    /// then the primitive under the session lock with the GIL released.
    /// Returns the primitive's value and the journal length that must be
    /// durable before the value is released.
    fn step<T, F>(&self, py: Python<'_>, f: F) -> PyResult<(T, Option<u64>)>
    where
        T: Send,
        F: FnOnce(&mut Session, &Branch) -> Result<T, Fault> + Send,
    {
        let branch = self.enter(py)?;
        let out = py.detach(|| {
            let mut state = lock(&self.state);
            let Some(owned) = state.as_mut() else {
                return Err(StepError::Finished);
            };
            let s = owned.session();
            match f(s, &branch) {
                Ok(v) => Ok((v, pending_upto(s))),
                Err(fault) => {
                    let sticky = s.failure() == Some(&fault);
                    Err(StepError::Fault { fault, sticky })
                }
            }
        });
        out.map_err(|e| self.raise_step(py, e))
    }

    fn raise_step(&self, py: Python<'_>, e: StepError) -> PyErr {
        match e {
            StepError::Finished => not_in_run(
                py,
                format!(
                    "the attempt on run '{}' has finished; its ctx can no longer be used",
                    self.run_id
                ),
            ),
            StepError::Fault { fault, sticky } => self.raise_fault(py, fault, sticky),
        }
    }

    /// The exception for a fault: the stored exception of the sticky persist
    /// failure when that is what the fault is, the fault's own otherwise.
    fn raise_fault(&self, py: Python<'_>, fault: Fault, sticky: bool) -> PyErr {
        if sticky {
            if let Some(exc) = self.sticky.get(py) {
                return PyErr::from_value(exc.bind(py).clone());
            }
        }
        fault_err(py, fault)
    }

    /// Wait until no persist runs, then take the slot for good: the sink
    /// and the attempt. Used by `finish` and `abandon`.
    fn take_for_end(&self) -> Option<(OwnedAttempt, Option<Box<dyn Sink>>)> {
        let mut slot = lock(&self.slot);
        while slot.busy {
            slot = self.idle.wait(slot).unwrap_or_else(|e| e.into_inner());
        }
        let owned = lock(&self.state).take()?;
        slot.busy = true;
        Some((owned, slot.sink.take()))
    }

    fn release_slot(&self) {
        let mut slot = lock(&self.slot);
        slot.busy = false;
        self.idle.notify_all();
    }

    fn clear_tasks(&self, py: Python<'_>) {
        self.tasks.bind(py).clear();
    }

    /// Wait for the slot, then decide what this persist does.
    fn next_persist(&self, upto: u64) -> Next {
        let mut slot = lock(&self.slot);
        while slot.busy {
            slot = self.idle.wait(slot).unwrap_or_else(|e| e.into_inner());
        }
        let mut state = lock(&self.state);
        let Some(owned) = state.as_mut() else {
            return Next::Gone;
        };
        let s = owned.session();
        if s.journal().persisted_len() >= upto {
            return Next::Done;
        }
        if let Some(f) = s.failure() {
            return Next::Failed(f.clone());
        }
        let Some((at, frames, head)) = s.unpersisted() else {
            return Next::Done;
        };
        let upto = s.journal().len();
        let Some(sink) = slot.sink.take() else {
            return Next::Failed(Fault::Unsupported(
                "this attempt has no sink to persist through".into(),
            ));
        };
        slot.busy = true;
        Next::Persist {
            sink,
            at,
            frames,
            head,
            upto,
        }
    }

    /// Record a persist's outcome in the session and hand the sink back.
    fn after_persist(
        &self,
        sink: Box<dyn Sink>,
        outcome: Result<(), Fault>,
        upto: u64,
    ) -> Option<Fault> {
        let fault = {
            let mut state = lock(&self.state);
            match (state.as_mut(), outcome) {
                (Some(owned), Ok(())) => {
                    owned.session().mark_persisted(upto);
                    None
                }
                (Some(owned), Err(f)) => {
                    owned.session().persist_failed(f.clone());
                    Some(f)
                }
                (None, outcome) => outcome.err(),
            }
        };
        let mut slot = lock(&self.slot);
        slot.sink = Some(sink);
        slot.busy = false;
        self.idle.notify_all();
        fault
    }
}

fn bytes<'py>(py: Python<'py>, v: &Value) -> Bound<'py, PyBytes> {
    PyBytes::new(py, v.as_bytes())
}

#[pymethods]
impl Attempt {
    /// The token `CURRENT` must hold for code stepping this attempt.
    #[getter]
    fn token(&self) -> u64 {
        self.token
    }

    #[getter]
    fn run_id(&self) -> &str {
        &self.run_id
    }

    /// `run`, `resume` or `replay`.
    #[getter]
    fn mode(&self) -> &'static str {
        self.mode.as_str()
    }

    /// Make the current task an owner of this attempt (the root task of
    /// `arun`, and each `ctx.gather` child as it starts).
    fn own_current_task(&self, py: Python<'_>) -> PyResult<()> {
        let task = CURRENT_TASK
            .import(py, "asyncio", "current_task")?
            .call0()?;
        if task.is_none() {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "an async attempt must be owned by a task",
            ));
        }
        self.tasks.bind(py).add(task)
    }

    /// Stop treating the current task as an owner (a `ctx.gather` child
    /// that has returned).
    fn disown_current_task(&self, py: Python<'_>) -> PyResult<()> {
        let task = CURRENT_TASK
            .import(py, "asyncio", "current_task")?
            .call0()?;
        if !task.is_none() {
            self.tasks.bind(py).discard(task)?;
        }
        Ok(())
    }

    /// The caller's branch, after the ownership check.
    fn branch(&self, py: Python<'_>) -> PyResult<Vec<u32>> {
        self.enter(py)
    }

    /// True while the caller's branch still has recorded steps to replay.
    fn is_replaying(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.step(py, |s, b| Ok(s.is_replaying(b)))?.0)
    }

    /// Entries known to be durable.
    fn durable(&self, py: Python<'_>) -> u64 {
        py.detach(|| {
            lock(&self.state)
                .as_mut()
                .map_or(0, |a| a.session().journal().persisted_len())
        })
    }

    /// Begin a model call. Returns `("replayed", intent, head, body, meta)`
    /// or `("fresh", intent, upto)`: the intent must be durable (`persist`)
    /// before the model is called.
    #[pyo3(signature = (parts, provenance))]
    fn draw_begin<'py>(
        &self,
        py: Python<'py>,
        parts: Vec<Vec<u8>>,
        provenance: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let parts: Vec<Value> = parts.into_iter().map(Value::from).collect();
        let (start, upto) = self.step(py, move |s, b| s.draw_begin(b, &provenance, parts))?;
        Ok(match start {
            DrawStart::Replayed {
                intent,
                head,
                body,
                meta,
            } => ("replayed", intent, bytes(py, &head), bytes(py, &body), meta)
                .into_pyobject(py)?
                .into_any(),
            DrawStart::Fresh(intent) => ("fresh", intent, upto).into_pyobject(py)?.into_any(),
        })
    }

    /// Complete the model call at `intent`. `meta` is strict JSON with at
    /// least `outcome`. Returns `upto`.
    fn draw_end(
        &self,
        py: Python<'_>,
        intent: u64,
        meta: String,
        head: Vec<u8>,
        body: Vec<u8>,
    ) -> PyResult<Option<u64>> {
        let (head, body) = (Value::from(head), Value::from(body));
        Ok(self
            .step(py, move |s, _| s.draw_end(intent, meta, head, body))?
            .1)
    }

    /// Begin an effect. Returns `("replayed", result)`, `("failed", kind,
    /// message)` or `("fresh", intent, idempotency_key, upto)`: the intent
    /// must be durable before the effect is performed.
    fn effect_begin<'py>(
        &self,
        py: Python<'py>,
        name: String,
        arg: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let arg = Value::from(arg);
        let (start, upto) = self.step(py, move |s, b| s.effect_begin(b, &name, arg))?;
        Ok(match start {
            EffectStart::Replayed(v) => ("replayed", bytes(py, &v)).into_pyobject(py)?.into_any(),
            EffectStart::Failed { kind, message } => {
                ("failed", kind, message).into_pyobject(py)?.into_any()
            }
            EffectStart::Fresh {
                intent,
                idempotency_key,
            } => ("fresh", intent, idempotency_key, upto)
                .into_pyobject(py)?
                .into_any(),
        })
    }

    /// Complete the effect at `intent` with its result, or with the
    /// `(error_kind, message)` of a perform that raised. Returns `upto`.
    #[pyo3(signature = (intent, result=None, failure=None))]
    fn effect_end(
        &self,
        py: Python<'_>,
        intent: u64,
        result: Option<Vec<u8>>,
        failure: Option<(String, String)>,
    ) -> PyResult<Option<u64>> {
        let outcome = match (result, failure) {
            (Some(r), None) => Ok(Value::from(r)),
            (None, Some(f)) => Err(f),
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "effect_end takes a result or a failure",
                ))
            }
        };
        Ok(self.step(py, move |s, _| s.effect_end(intent, outcome))?.1)
    }

    /// Receive on a channel. Returns `(value, upto)`.
    fn recv<'py>(
        &self,
        py: Python<'py>,
        channel: String,
    ) -> PyResult<(Bound<'py, PyBytes>, Option<u64>)> {
        let (v, upto) = self.step(py, move |s, b| s.recv(b, &channel))?;
        Ok((bytes(py, &v), upto))
    }

    /// A journaled clock read in Unix nanoseconds. Returns `(nanos, upto)`.
    fn now(&self, py: Python<'_>) -> PyResult<(u64, Option<u64>)> {
        self.step(py, |s, b| s.now(b))
    }

    /// A journaled random draw. Returns `(value, upto)`.
    fn random<'py>(
        &self,
        py: Python<'py>,
        source: String,
        args: String,
    ) -> PyResult<(Bound<'py, PyBytes>, Option<u64>)> {
        let (v, upto) = self.step(py, move |s, b| s.random(b, &source, &args))?;
        Ok((bytes(py, &v), upto))
    }

    /// Fork `n` children of the caller's branch. Returns `(children,
    /// upto)`; the caller's branch is suspended until `join`.
    fn fork(&self, py: Python<'_>, n: u32) -> PyResult<(Vec<Vec<u32>>, Option<u64>)> {
        self.step(py, move |s, b| s.fork(b, n))
    }

    /// Join the region the caller's branch forked. `ok[i]` says whether
    /// child `i` returned normally. Returns, per child, `None` or the
    /// exception its completeness check raised.
    fn join(
        &self,
        py: Python<'_>,
        children: Vec<Vec<u32>>,
        ok: Vec<bool>,
    ) -> PyResult<Vec<Option<Py<PyAny>>>> {
        let (checks, _) = self.step(py, move |s, b| Ok(s.join_each(b, &children, &ok)))?;
        Ok(checks
            .into_iter()
            .map(|c| c.err().map(|f| fault_err(py, f).into_value(py).into_any()))
            .collect())
    }

    /// `patched(name)` on the caller's branch. Returns `(taken, upto)`.
    fn patched(&self, py: Python<'_>, name: String) -> PyResult<(bool, Option<u64>)> {
        self.step(py, move |s, b| s.patched(b, &name))
    }

    /// `deprecate_patch(name)` on the caller's branch.
    fn deprecate_patch(&self, py: Python<'_>, name: String) -> PyResult<()> {
        self.step(py, move |s, b| s.deprecate_patch(b, &name))?;
        Ok(())
    }

    /// Journal or check the program identity on the caller's branch.
    /// Returns `upto`.
    fn program_marker(&self, py: Python<'_>, name: String, hash: String) -> PyResult<Option<u64>> {
        Ok(self
            .step(py, move |s, b| s.program_marker(b, &name, &hash))?
            .1)
    }

    /// The request parts recorded by the `DrawIntent` at `cursor`, for the
    /// diff a draw desync carries; `None` if the entry is not a draw intent
    /// or a part was erased.
    fn recorded_parts<'py>(
        &self,
        py: Python<'py>,
        cursor: u64,
    ) -> PyResult<Option<Vec<Bound<'py, PyBytes>>>> {
        let (parts, _) = self.step(py, move |s, _| {
            Ok(match s.entry(cursor).map(|e| &e.event) {
                Some(Event::DrawIntent { parts, .. }) => parts
                    .iter()
                    .map(|c| match c {
                        Content::Sealed(v) => Some(v.clone()),
                        _ => None,
                    })
                    .collect::<Option<Vec<Value>>>(),
                _ => None,
            })
        })?;
        Ok(parts.map(|ps| ps.iter().map(|v| bytes(py, v)).collect()))
    }

    /// Make the journal durable up to `upto` entries (see the module
    /// documentation). Never checks ownership: it is the binding's own
    /// call, made from the executor thread in async attempts.
    fn persist(&self, py: Python<'_>, upto: u64) -> PyResult<()> {
        loop {
            match py.detach(|| self.next_persist(upto)) {
                Next::Done => return Ok(()),
                Next::Gone => {
                    return Err(not_in_run(
                        py,
                        format!("the attempt on run '{}' has finished", self.run_id),
                    ))
                }
                Next::Failed(f) => return Err(self.raise_fault(py, f, true)),
                Next::Persist {
                    mut sink,
                    at,
                    frames,
                    head,
                    upto: all,
                } => {
                    clear_store_error();
                    let (sink, outcome) = py.detach(move || {
                        let size = frames.len() as u64;
                        let r = sink
                            .persist(at, &frames, &head)
                            .map_err(|e| e.into_fault(size));
                        (sink, r)
                    });
                    let stored = take_store_error();
                    if let Err(fault) = &outcome {
                        // Kept before the session is marked failed, so a
                        // step on another task that sees the failure always
                        // finds the exception to raise again.
                        let exc = stored.unwrap_or_else(|| fault_err(py, fault.clone()));
                        let _ = self
                            .sticky
                            .set(py, exc.value(py).clone().into_any().unbind());
                    }
                    if let Some(fault) = py.detach(|| self.after_persist(sink, outcome, all)) {
                        return Err(self.raise_fault(py, fault, true));
                    }
                }
            }
        }
    }

    /// End the attempt: `outcome` is `"ok"` with the output bytes,
    /// `"fault"` with the `FaultHandle` the agent's exception carried, or
    /// `"error"` with the text of any other exception. Waits for any
    /// persist in flight, persists `attempt.end` and checks the run in.
    fn finish(
        &self,
        py: Python<'_>,
        outcome: &str,
        value: Bound<'_, PyAny>,
    ) -> PyResult<RunReport> {
        let result = match outcome {
            "ok" => Ok(Value::from(value.cast::<PyBytes>()?.as_bytes().to_vec())),
            "fault" => Err(value.cast::<FaultHandle>()?.get().fault.clone()),
            _ => Err(Fault::ToolErr(format!(
                "python agent raised: {}",
                value.str()?.to_cow()?
            ))),
        };
        let taken = py.detach(|| self.take_for_end());
        let Some((mut owned, sink)) = taken else {
            return Err(not_in_run(
                py,
                format!("the attempt on run '{}' has already finished", self.run_id),
            ));
        };
        clear_store_error();
        let (report, failed_before) = py.detach(move || {
            let failed_before = owned.session().failure().cloned();
            if let Some(sink) = sink {
                owned.session().attach_sink(sink);
            }
            (owned.finish(result), failed_before)
        });
        let stored = take_store_error();
        self.release_slot();
        self.clear_tasks(py);
        match report {
            Ok(r) => Ok(convert_report(r)),
            Err(f) => {
                let sticky = failed_before.as_ref() == Some(&f);
                if sticky && self.sticky.get(py).is_some() {
                    return Err(self.raise_fault(py, f, true));
                }
                Err(stored.unwrap_or_else(|| fault_err(py, f)))
            }
        }
    }

    /// End the attempt as a crash: nothing more is journaled, no
    /// `attempt.end` is written, and the run is checked in (spec 2.7, rule
    /// 7). Waits for any persist in flight first.
    fn abandon(&self, py: Python<'_>) {
        if let Some((owned, sink)) = py.detach(|| self.take_for_end()) {
            py.detach(move || {
                drop(sink);
                owned.abandon();
            });
            self.release_slot();
        }
        self.clear_tasks(py);
    }

    /// True once the attempt has finished or been abandoned.
    #[getter]
    fn finished(&self, py: Python<'_>) -> bool {
        py.detach(|| lock(&self.state).is_none())
    }
}

/// `pragmatic.EffectUnrecorded` for an effect whose result could not be
/// persisted, carrying the result so the caller can log or reconcile it.
#[pyfunction]
pub fn effect_unrecorded(py: Python<'_>, name: String, intent: u64, result: Vec<u8>) -> Py<PyAny> {
    fault_err(
        py,
        Fault::EffectUnrecorded {
            name,
            intent,
            result: Value::from(result),
        },
    )
    .into_value(py)
    .into_any()
}
