//! Native core of the `pragmatic` Python package.
//!
//! This extension module (`pragmatic._native`) is the Rust runtime plus the
//! smallest surface the pure-Python layer needs: the runtime itself, the
//! per-attempt context, and split-phase record/replay primitives so Python
//! can perform model calls and tool calls itself (sync or async SDK
//! clients) while the journal stays authoritative. The split-phase
//! primitives sit on the core's session API: a fresh draw or effect intent
//! is durable before Python makes the call or runs the tool. The public API
//! lives in `python/pragmatic/`; see its `__init__.py`.

use std::cell::RefCell;
use std::rc::Rc;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use pragmatic_rt::journal::{Content, Cursor, Event};
use pragmatic_rt::json::Json;
use pragmatic_rt::{DrawStart, EffectStart, Fault, Oracle, TraceLabel, Value};

create_exception!(
    pragmatic,
    PragmaticError,
    PyRuntimeError,
    "A well-typed runtime fault (oracle, tool, contract, budget, io)."
);
create_exception!(
    pragmatic,
    JournalDesync,
    PragmaticError,
    "Replay found the journal disagreeing with the program: the agent code \
     or its inputs changed since the run was recorded."
);
create_exception!(
    pragmatic,
    ReplayExhausted,
    PragmaticError,
    "Strict replay ran past the end of the journal; use resume to continue \
     a run that never finished."
);

fn fault_err(f: &Fault) -> PyErr {
    match f {
        Fault::JournalDesync { .. } => JournalDesync::new_err(f.to_string()),
        Fault::ReplayExhausted { .. } => ReplayExhausted::new_err(f.to_string()),
        _ => PragmaticError::new_err(f.to_string()),
    }
}

/// A `pragmatic_rt::Oracle` backed by a Python callable `(str) -> str`, or
/// no default oracle at all (agents that make their model calls through
/// `ctx.wrap(client)` or `ctx.draw` do not need one).
struct PyCallableOracle {
    func: Option<Py<PyAny>>,
}

impl Oracle for PyCallableOracle {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        let Some(func) = &self.func else {
            return Err(Fault::OracleErr(
                "ctx.oracle needs a default oracle: pass one to Runtime(dir, oracle), \
                 or make model calls through ctx.wrap(client)"
                    .to_string(),
            ));
        };
        Python::attach(|py| {
            let out = func
                .call1(py, (prompt.as_str().into_owned(),))
                .map_err(|e| Fault::OracleErr(format!("python oracle raised: {e}")))?;
            let text: String = out
                .extract(py)
                .map_err(|e| Fault::OracleErr(format!("python oracle must return str: {e}")))?;
            Ok(Value::from(text))
        })
    }

    fn provenance(&self) -> String {
        Python::attach(|py| match &self.func {
            Some(func) => func
                .bind(py)
                .getattr("__name__")
                .and_then(|n| n.extract::<String>())
                .map(|n| format!("python:{n}"))
                .unwrap_or_else(|_| "python-oracle".to_string()),
            None => "python-oracle".to_string(),
        })
    }
}

/// A split-phase step whose intent is durable but whose result is not
/// recorded yet. Any other journaled step in between is refused: journaled
/// steps from Python run one at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pending {
    Draw(Cursor),
    Effect(Cursor, String),
}

/// The `meta` the core records for a draw that returned normally.
const META_OK: &str = r#"{"outcome":"ok"}"#;

/// A string member of a draw's metadata (`outcome`, `error_type`).
fn meta_field(meta: &str, key: &str) -> Option<String> {
    Json::parse(meta)
        .ok()?
        .get(key)?
        .as_str()
        .map(str::to_string)
}

/// The `meta` of a model call that raised an exception of type `type_name`.
fn error_meta(type_name: &str) -> String {
    Json::Object(vec![
        ("error_type".to_string(), Json::from(type_name)),
        ("outcome".to_string(), Json::from("error")),
    ])
    .to_string()
}

/// The name a Python exception is recorded under (`module.QualName`, or a
/// builtin's bare name), from `pragmatic._failures.type_name`.
fn exception_type_name(py: Python<'_>, e: &PyErr) -> String {
    py.import("pragmatic._failures")
        .and_then(|m| m.call_method1("type_name", (e.value(py),)))
        .and_then(|n| n.extract::<String>())
        .unwrap_or_else(|_| "Exception".to_string())
}

/// The exception a recorded failure raises on replay: an `EffectFailed` or
/// `DrawFailed` that is also an instance of the recorded exception type
/// when the program has that type loaded (see `pragmatic/_failures.py`).
fn replayed_exception(py: Python<'_>, step: &str, type_name: &str, message: &str) -> PyErr {
    match py
        .import("pragmatic._failures")
        .and_then(|m| m.call_method1("replayed", (step, type_name, message)))
    {
        Ok(exc) => PyErr::from_value(exc),
        Err(e) => e,
    }
}

/// The per-attempt durable context. Valid only during the
/// `run`/`resume`/`replay` call that created it; the pointer is nulled when
/// the attempt finishes, so a leaked reference fails loudly instead of
/// dangling.
#[pyclass(unsendable)]
struct Ctx {
    ptr: *mut pragmatic_rt::Ctx<'static>,
    pending: Option<Pending>,
    /// The last fault raised to Python, so it can be restored with its
    /// original type when it propagates out of the agent.
    last_fault: Rc<RefCell<Option<Fault>>>,
}

impl Ctx {
    fn get(&mut self) -> PyResult<&mut pragmatic_rt::Ctx<'static>> {
        unsafe { self.ptr.as_mut() }
            .ok_or_else(|| PragmaticError::new_err("ctx used outside its run"))
    }

    /// Guard for every step that touches the journal.
    fn idle(&self) -> PyResult<()> {
        match &self.pending {
            None => Ok(()),
            Some(p) => Err(PragmaticError::new_err(format!(
                "{p:?} is still open: journaled steps must run one at a time \
                 (await model and tool calls sequentially, not concurrently)"
            ))),
        }
    }

    fn check<T>(&self, r: Result<T, Fault>) -> PyResult<T> {
        r.map_err(|f| {
            let err = fault_err(&f);
            *self.last_fault.borrow_mut() = Some(f);
            err
        })
    }

    /// Begin an effect on this context's branch.
    fn begin_effect(&mut self, name: &str, arg: &str) -> PyResult<EffectStart> {
        let ctx = self.get()?;
        let branch = ctx.branch().clone();
        let r = ctx.session().effect_begin(&branch, name, Value::from(arg));
        self.check(r)
    }

    /// Record the result of the effect at `intent`.
    fn end_effect(
        &mut self,
        intent: Cursor,
        outcome: Result<Value, (String, String)>,
    ) -> PyResult<()> {
        let r = self.get()?.session().effect_end(intent, outcome);
        self.check(r)
    }

    /// The exception a recorded failure of `step` raises again on replay.
    /// It is the agent's to handle like the original; if it escapes the
    /// agent it is re-raised as is, so no earlier fault is restored for it.
    fn replayed_failure(&self, py: Python<'_>, step: &str, kind: &str, message: &str) -> PyErr {
        *self.last_fault.borrow_mut() = None;
        replayed_exception(py, step, kind, message)
    }

    /// Record that `perform` raised `e`, unless `e` is not an `Exception`
    /// (KeyboardInterrupt, SystemExit, a cancelled task): that is a crash,
    /// not a result, and the intent stays open for resume's recovery.
    fn fail_effect(&mut self, py: Python<'_>, intent: Cursor, e: &PyErr) -> PyResult<()> {
        if !e.is_instance_of::<PyException>(py) {
            return Ok(());
        }
        let kind = exception_type_name(py, e);
        let message = e.value(py).to_string();
        self.end_effect(intent, Err((kind, message)))
    }
}

#[pymethods]
impl Ctx {
    /// One model call through the runtime's default oracle, journaled once.
    fn oracle(&mut self, prompt: &str) -> PyResult<String> {
        self.idle()?;
        let r = self.get()?.oracle(prompt);
        Ok(self.check(r)?.as_str().into_owned())
    }

    /// A durable effect under the write-ahead discipline. `perform` is a
    /// Python callable `(str) -> str`. If it raises, the failure is recorded
    /// (type name and message) and the exception propagates unchanged; a
    /// replay raises `EffectFailed` with the recorded type and message,
    /// which is also an instance of the recorded type when it is loaded.
    fn effect(
        &mut self,
        py: Python<'_>,
        name: &str,
        arg: &str,
        perform: Py<PyAny>,
    ) -> PyResult<String> {
        self.idle()?;
        let intent = match self.begin_effect(name, arg)? {
            EffectStart::Replayed(v) => return Ok(v.as_str().into_owned()),
            EffectStart::Failed { kind, message } => {
                return Err(self.replayed_failure(py, "effect", &kind, &message))
            }
            EffectStart::Fresh { intent, .. } => intent,
        };
        let out = perform
            .call1(py, (arg,))
            .and_then(|v| v.extract::<String>(py));
        match out {
            Ok(text) => {
                self.end_effect(intent, Ok(Value::from(text.as_str())))?;
                Ok(text)
            }
            Err(e) => {
                self.fail_effect(py, intent, &e)?;
                // The tool's own exception propagates unchanged.
                Err(e)
            }
        }
    }

    /// Split-phase draw, step 1: the recorded outcome for `prompt`, or None
    /// when the model must be called. A None means the intent is already
    /// durable; `draw_commit` with the same prompt (or `draw_fail`, or
    /// `draw_abort`) must come next. A recorded failure is raised again as
    /// `DrawFailed` (also an instance of the recorded exception type when it
    /// is loaded).
    #[pyo3(signature = (prompt, provenance="python"))]
    fn draw_replay(
        &mut self,
        py: Python<'_>,
        prompt: &str,
        provenance: &str,
    ) -> PyResult<Option<String>> {
        self.idle()?;
        let ctx = self.get()?;
        let branch = ctx.branch().clone();
        let r = ctx
            .session()
            .draw_begin(&branch, provenance, vec![Value::from(prompt)]);
        match self.check(r)? {
            DrawStart::Replayed { meta, body, .. } => {
                if meta_field(&meta, "outcome").as_deref() == Some("error") {
                    let kind = meta_field(&meta, "error_type").unwrap_or_default();
                    return Err(self.replayed_failure(py, "draw", &kind, &body.as_str()));
                }
                Ok(Some(body.as_str().into_owned()))
            }
            DrawStart::Fresh(intent) => {
                self.pending = Some(Pending::Draw(intent));
                Ok(None)
            }
        }
    }

    /// Split-phase draw, step 2: journal the model's realized outcome. The
    /// provenance was recorded with the intent; it is accepted here for
    /// compatibility.
    #[pyo3(signature = (prompt, outcome, provenance="python"))]
    fn draw_commit(&mut self, prompt: &str, outcome: &str, provenance: &str) -> PyResult<String> {
        let _ = provenance;
        let Some(Pending::Draw(intent)) = self.pending.clone() else {
            return Err(PragmaticError::new_err(
                "draw_commit without a matching draw_replay that returned None",
            ));
        };
        let matches = matches!(
            self.get()?.session().entry(intent).map(|e| &e.event),
            Some(Event::DrawIntent { parts, .. })
                if parts.len() == 1 && parts[0] == Content::from(prompt)
        );
        if !matches {
            return Err(PragmaticError::new_err(
                "draw_commit without a matching draw_replay that returned None",
            ));
        }
        self.pending = None;
        let r = self.get()?.session().draw_end(
            intent,
            META_OK.to_string(),
            Value::default(),
            Value::from(outcome),
        );
        self.check(r)?;
        Ok(outcome.to_string())
    }

    /// Split-phase draw, step 2 for a model call that raised: record the
    /// failure (the exception's type name and message) as the call's
    /// result, so an agent that handles it replays identically (spec 2.12:
    /// errors are results too). A failure the agent did not handle ends the
    /// attempt at the frontier of its branch, where a resume calls the
    /// model again.
    fn draw_fail(&mut self, type_name: &str, message: &str) -> PyResult<()> {
        let Some(Pending::Draw(intent)) = self.pending.clone() else {
            return Err(PragmaticError::new_err(
                "draw_fail without a matching draw_replay that returned None",
            ));
        };
        self.pending = None;
        let r = self.get()?.session().draw_end(
            intent,
            error_meta(type_name),
            Value::default(),
            Value::from(message),
        );
        self.check(r)
    }

    /// Abandon an open draw whose model call was interrupted (a
    /// KeyboardInterrupt, a cancelled task). Its intent stays on record
    /// without a result, as if the process had died during the call: a
    /// resumed run makes the call again. A call that raised an ordinary
    /// exception is recorded with `draw_fail` instead.
    fn draw_abort(&mut self) {
        if matches!(self.pending, Some(Pending::Draw(_))) {
            self.pending = None;
        }
    }

    /// Split-phase effect, step 1: the recorded result, or None when the
    /// effect must be performed. A None means the intent is already durable;
    /// call `effect_begin` and then `effect_commit` (or `effect_fail`) next.
    /// A recorded failure is raised again as `EffectFailed`.
    fn effect_replay(&mut self, py: Python<'_>, name: &str, arg: &str) -> PyResult<Option<String>> {
        self.idle()?;
        match self.begin_effect(name, arg)? {
            EffectStart::Replayed(v) => Ok(Some(v.as_str().into_owned())),
            EffectStart::Failed { kind, message } => {
                Err(self.replayed_failure(py, "effect", &kind, &message))
            }
            EffectStart::Fresh { intent, .. } => {
                self.pending = Some(Pending::Effect(intent, name.to_string()));
                Ok(None)
            }
        }
    }

    /// Split-phase effect, step 2: the write-ahead intent. `effect_replay`
    /// already made it durable, so this only checks the sequence.
    fn effect_begin(&mut self, name: &str, arg: &str) -> PyResult<()> {
        let _ = arg;
        match &self.pending {
            Some(Pending::Effect(_, n)) if n == name => Ok(()),
            _ => Err(PragmaticError::new_err(
                "effect_begin without a matching effect_replay that returned None",
            )),
        }
    }

    /// Split-phase effect, step 3: journal the realized result.
    fn effect_commit(&mut self, name: &str, result: &str) -> PyResult<String> {
        let intent = match &self.pending {
            Some(Pending::Effect(intent, n)) if n == name => *intent,
            _ => {
                return Err(PragmaticError::new_err(
                    "effect_commit without a matching effect_begin",
                ))
            }
        };
        self.pending = None;
        self.end_effect(intent, Ok(Value::from(result)))?;
        Ok(result.to_string())
    }

    /// Split-phase effect, step 3 for a perform that raised: record the
    /// failure (type name and message) as the effect's result.
    fn effect_fail(&mut self, name: &str, type_name: &str, message: &str) -> PyResult<()> {
        let intent = match &self.pending {
            Some(Pending::Effect(intent, n)) if n == name => *intent,
            _ => {
                return Err(PragmaticError::new_err(
                    "effect_fail without a matching effect_begin",
                ))
            }
        };
        self.pending = None;
        self.end_effect(intent, Err((type_name.to_string(), message.to_string())))
    }

    /// Receive on a channel (journaled).
    fn recv(&mut self, channel: &str) -> PyResult<String> {
        self.idle()?;
        let r = self.get()?.recv(channel);
        Ok(self.check(r)?.as_str().into_owned())
    }

    /// A journaled clock read (nanoseconds since epoch).
    fn now(&mut self) -> PyResult<u64> {
        self.idle()?;
        let r = self.get()?.now();
        self.check(r)
    }

    /// Assert an agent contract; a falsified contract raises.
    fn contract(&mut self, holds: bool, msg: &str) -> PyResult<()> {
        let r = self.get()?.contract(holds, msg);
        self.check(r)
    }

    /// Journal (or, on replay, verify) the agent program's identity.
    fn program_marker(&mut self, name: &str, hash: &str) -> PyResult<()> {
        self.idle()?;
        let r = self.get()?.program_marker(name, hash);
        self.check(r)
    }

    /// True while steps are served from the journal.
    fn is_replaying(&mut self) -> PyResult<bool> {
        Ok(self.get()?.is_replaying())
    }
}

/// The result of driving one run to completion.
#[pyclass]
struct RunReport {
    #[pyo3(get)]
    run_id: String,
    #[pyo3(get)]
    output: String,
    #[pyo3(get)]
    journal_len: u64,
    #[pyo3(get)]
    replayed_steps: u64,
    #[pyo3(get)]
    fresh_steps: u64,
    /// Hex head of the tamper-evident hash chain, or None for an empty run.
    #[pyo3(get)]
    chain_head: Option<String>,
    /// The observable trace: (cursor, kind, summary) triples. Identical
    /// between a recorded run and its replay (T1).
    #[pyo3(get)]
    trace: Vec<(u64, String, String)>,
}

#[pymethods]
impl RunReport {
    fn __repr__(&self) -> String {
        format!(
            "RunReport(run_id={:?}, journal_len={}, replayed_steps={}, fresh_steps={})",
            self.run_id, self.journal_len, self.replayed_steps, self.fresh_steps
        )
    }
}

fn convert_report(r: pragmatic_rt::RunReport) -> RunReport {
    let trace = r
        .trace
        .iter()
        .map(|l| match l {
            TraceLabel::Oracle {
                cursor, outcome, ..
            } => (*cursor, "oracle".to_string(), outcome.as_str().into_owned()),
            TraceLabel::Effect {
                cursor,
                name,
                result,
                ..
            } => (
                *cursor,
                "effect".to_string(),
                format!("{name} -> {}", result.as_str()),
            ),
            TraceLabel::Recv {
                cursor,
                channel,
                value,
                ..
            } => (
                *cursor,
                "recv".to_string(),
                format!("{channel} ? {}", value.as_str()),
            ),
            TraceLabel::Clock { cursor, nanos, .. } => {
                (*cursor, "clock".to_string(), nanos.to_string())
            }
            TraceLabel::Random {
                cursor,
                source,
                value,
                ..
            } => (
                *cursor,
                "random".to_string(),
                format!("{source} -> {}", value.as_str()),
            ),
            TraceLabel::Done { output } => {
                (u64::MAX, "done".to_string(), output.as_str().into_owned())
            }
            other => (
                other.cursor().unwrap_or(u64::MAX),
                "other".to_string(),
                String::new(),
            ),
        })
        .collect();
    RunReport {
        run_id: r.run_id,
        output: r.output.as_str().into_owned(),
        journal_len: r.journal_len,
        replayed_steps: r.replayed_steps,
        fresh_steps: r.fresh_steps,
        chain_head: r.chain_head.map(|h| pragmatic_rt::sha256::hex(&h)),
        trace,
    }
}

enum Mode {
    Run,
    Resume(Option<Py<PyAny>>),
    Replay,
}

fn run_options(budget: Option<u64>, caps: Option<Vec<String>>) -> pragmatic_rt::RunOptions {
    let mut opts = pragmatic_rt::RunOptions::default();
    if let Some(b) = budget {
        opts = opts.with_budget(b);
    }
    if let Some(c) = caps {
        opts = opts.with_caps(c);
    }
    opts
}

/// The native runtime. Wrapped by `pragmatic.Runtime`.
#[pyclass(unsendable)]
struct Runtime {
    inner: pragmatic_rt::Runtime<PyCallableOracle>,
}

impl Runtime {
    fn drive(
        &mut self,
        py: Python<'_>,
        run_id: &str,
        agent: Py<PyAny>,
        mode: Mode,
        opts: pragmatic_rt::RunOptions,
    ) -> PyResult<RunReport> {
        // An exception the agent raised that is not a runtime fault (a bug
        // in the agent, a tool error) is re-raised unchanged after the
        // runtime has flushed and closed the attempt.
        let agent_exc: RefCell<Option<PyErr>> = RefCell::new(None);
        let agent_fn = |ctx: &mut pragmatic_rt::Ctx| -> Result<Value, Fault> {
            // The Python-visible ctx borrows this attempt's Ctx. The pointer
            // is nulled before the attempt returns, so references Python
            // keeps around cannot dangle.
            let ptr: *mut pragmatic_rt::Ctx<'static> = (ctx as *mut pragmatic_rt::Ctx<'_>).cast();
            let last_fault = Rc::new(RefCell::new(None));
            let pyctx = Py::new(
                py,
                Ctx {
                    ptr,
                    pending: None,
                    last_fault: last_fault.clone(),
                },
            )
            .map_err(|e| Fault::ToolErr(format!("ctx allocation failed: {e}")))?;
            let result = agent.call1(py, (pyctx.clone_ref(py),));
            pyctx.borrow_mut(py).ptr = std::ptr::null_mut();
            match result {
                Ok(v) => {
                    let text: String = v.extract(py).map_err(|e| {
                        Fault::ToolErr(format!("python agent must return str: {e}"))
                    })?;
                    Ok(Value::from(text))
                }
                Err(e) => {
                    // A fault we raised round-trips with its original type,
                    // so replay desyncs stay desyncs.
                    if let Some(f) = last_fault.borrow_mut().take() {
                        if e.is_instance_of::<PragmaticError>(py) {
                            return Err(f);
                        }
                    }
                    let msg = format!("python agent raised: {e}");
                    *agent_exc.borrow_mut() = Some(e);
                    Err(Fault::ToolErr(msg))
                }
            }
        };
        // A recovery policy that raises is recorded here and re-raised; the
        // intent is compensated meanwhile, the conservative choice.
        let recover_exc: RefCell<Option<PyErr>> = RefCell::new(None);
        let report = match mode {
            Mode::Run => self.inner.run_with(run_id, opts, agent_fn),
            Mode::Resume(policy) => self.inner.resume_with(
                run_id,
                opts,
                |name, arg| {
                    let Some(policy) = &policy else {
                        return pragmatic_rt::Recover::Compensate;
                    };
                    let out = policy
                        .call1(py, (name, arg.as_str().into_owned()))
                        .and_then(|v| v.extract::<Option<String>>(py));
                    match out {
                        Ok(Some(result)) => pragmatic_rt::Recover::Commit(Value::from(result)),
                        Ok(None) => pragmatic_rt::Recover::Compensate,
                        Err(e) => {
                            recover_exc.borrow_mut().get_or_insert(e);
                            pragmatic_rt::Recover::Compensate
                        }
                    }
                },
                agent_fn,
            ),
            Mode::Replay => self.inner.replay(run_id, agent_fn),
        };
        if let Some(e) = recover_exc.into_inner() {
            return Err(e);
        }
        match report {
            Ok(r) => Ok(convert_report(r)),
            Err(f) => match agent_exc.into_inner() {
                Some(e) => Err(e),
                None => Err(fault_err(&f)),
            },
        }
    }
}

#[pymethods]
impl Runtime {
    #[new]
    #[pyo3(signature = (dir, oracle=None, key=None))]
    fn new(
        dir: &str,
        oracle: Option<Py<PyAny>>,
        key: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let mut inner = pragmatic_rt::Runtime::on_dir(dir, PyCallableOracle { func: oracle })
            .map_err(|e| PragmaticError::new_err(e.to_string()))?;
        if let Some(k) = key {
            inner = inner.with_key(k.as_bytes());
        }
        Ok(Runtime { inner })
    }

    #[pyo3(signature = (run_id, agent, budget=None, caps=None))]
    fn run(
        &mut self,
        py: Python<'_>,
        run_id: &str,
        agent: Py<PyAny>,
        budget: Option<u64>,
        caps: Option<Vec<String>>,
    ) -> PyResult<RunReport> {
        self.drive(py, run_id, agent, Mode::Run, run_options(budget, caps))
    }

    /// `recover(name, arg) -> str | None` decides each dangling effect
    /// intent: a str commits it with that result, None compensates it (the
    /// resumed run performs it fresh). Without a policy, all compensate.
    #[pyo3(signature = (run_id, agent, recover=None, budget=None, caps=None))]
    fn resume(
        &mut self,
        py: Python<'_>,
        run_id: &str,
        agent: Py<PyAny>,
        recover: Option<Py<PyAny>>,
        budget: Option<u64>,
        caps: Option<Vec<String>>,
    ) -> PyResult<RunReport> {
        let opts = run_options(budget, caps);
        self.drive(py, run_id, agent, Mode::Resume(recover), opts)
    }

    fn replay(&mut self, py: Python<'_>, run_id: &str, agent: Py<PyAny>) -> PyResult<RunReport> {
        let opts = pragmatic_rt::RunOptions::default();
        self.drive(py, run_id, agent, Mode::Replay, opts)
    }

    fn send(&mut self, run_id: &str, channel: &str, value: &str) {
        self.inner.send(run_id, channel, value);
    }

    /// Verify the run's journal: every chain link and commitment, and that
    /// every erased slot is accounted for. Returns True if intact.
    fn verify(&mut self, run_id: &str) -> PyResult<bool> {
        Ok(self
            .inner
            .verify(run_id)
            .map_err(|f| fault_err(&f))?
            .is_ok())
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Runtime>()?;
    m.add_class::<Ctx>()?;
    m.add_class::<RunReport>()?;
    m.add("PragmaticError", py.get_type::<PragmaticError>())?;
    m.add("JournalDesync", py.get_type::<JournalDesync>())?;
    m.add("ReplayExhausted", py.get_type::<ReplayExhausted>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
