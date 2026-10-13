//! Native core of the `pragmatic` Python package.
//!
//! This extension module (`pragmatic._native`) is the Rust runtime plus the
//! smallest surface the pure-Python layer needs (spec 6.1 to 6.4):
//!
//! - [`Runtime`]: a frozen, thread-safe handle on the core runtime and its
//!   backend, shared by every thread and task of the process. It begins
//!   attempts and serves read-only views (verify reports, Entry JSON, run
//!   summaries).
//! - [`attempt::Attempt`]: one attempt, owned by the thread or task that
//!   runs it, with the split-phase primitives (draws, effects, receives,
//!   clock and random reads, regions, patches, program markers) and the
//!   persistence the Python layer drives so that a value reaches the agent
//!   only once it is durable.
//! - [`backend::NativeStore`]: the native directory and memory backends, and
//!   the adapter that drives a Python store (spec 6.3) as a core backend.
//!
//! No Rust lock is ever held while Python code runs, and every lock is
//! taken with the GIL released. The public API lives in `python/pragmatic/`;
//! see its `__init__.py`.

mod attempt;
mod backend;
mod errors;
mod inspect;
mod report;

use std::collections::BTreeMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};

use pragmatic_rt::{
    Fault, Mode, OnCodeChange, Recover, RecoverRequest, RefusingOracle, RunOptions, Value,
};

use attempt::{Attempt, Owner};
use backend::NativeStore;
use errors::{clear_store_error, raise, stash_policy_error, take_policy_error, take_store_error};

/// The native runtime: a backend, the journal key, and the channel inboxes
/// of its runs. Wrapped by `pragmatic.Runtime`.
///
/// Model calls never go through a Rust oracle here: the Python layer makes
/// them itself with the split-phase draw primitives, so the core runtime
/// carries a refusing oracle.
#[pyclass(frozen, module = "pragmatic._native")]
struct Runtime {
    inner: pragmatic_rt::Runtime<RefusingOracle>,
}

fn parse_mode(mode: &str) -> PyResult<Mode> {
    match mode {
        "run" => Ok(Mode::Run),
        "resume" => Ok(Mode::Resume),
        "replay" => Ok(Mode::Replay),
        other => Err(PyValueError::new_err(format!(
            "mode must be 'run', 'resume' or 'replay', not {other:?}"
        ))),
    }
}

fn parse_on_code_change(policy: Option<&str>) -> PyResult<Option<OnCodeChange>> {
    match policy {
        None => Ok(None),
        Some("refuse") => Ok(Some(OnCodeChange::Refuse)),
        Some("continue") => Ok(Some(OnCodeChange::Continue)),
        Some(other) => Err(PyValueError::new_err(format!(
            "on_code_change must be 'refuse' or 'continue', not {other:?}"
        ))),
    }
}

/// One recovery decision from the Python policy (spec 2.12). The policy is
/// the package's normalized wrapper around the user's `recover`: it takes
/// `(name, arg, branch, intent, at_frontier)` and returns `("commit",
/// result)`, `("compensate",)` or `("fail",)`. Failed frontier effects are
/// retried without asking, as the Rust `resume_with` does.
///
/// A policy that raises aborts the resume: the exception is kept, the
/// attempt's sink refuses to persist its opening notes and decisions, and
/// the intent stays undecided for the next resume.
fn decide(policy: &Py<PyAny>, req: &RecoverRequest<'_>) -> Recover {
    if req.failure.is_some() || errors::policy_failed() {
        return Recover::Compensate;
    }
    Python::attach(|py| {
        let call = || -> PyResult<Recover> {
            let branch = PyTuple::new(py, req.branch)?;
            let arg = PyBytes::new(py, req.arg.as_bytes());
            let out = policy.call1(py, (req.name, arg, branch, req.intent, req.at_frontier))?;
            let out = out.bind(py);
            let kind: String = out.get_item(0)?.extract()?;
            match kind.as_str() {
                "commit" => {
                    let result = out.get_item(1)?;
                    Ok(Recover::Commit(Value::from(
                        result.cast::<PyBytes>()?.as_bytes().to_vec(),
                    )))
                }
                "fail" => Ok(Recover::Fail),
                _ => Ok(Recover::Compensate),
            }
        };
        call().unwrap_or_else(|e| {
            stash_policy_error(e);
            Recover::Compensate
        })
    })
}

#[pymethods]
impl Runtime {
    /// A runtime over `store`, keying journal chains with `key` when given.
    #[new]
    #[pyo3(signature = (store, key=None))]
    fn new(store: &NativeStore, key: Option<Vec<u8>>) -> Runtime {
        let mut inner =
            pragmatic_rt::Runtime::with_backend(Box::new(store.backend.clone()), RefusingOracle);
        if let Some(k) = key {
            inner = inner.with_key(&k);
        }
        Runtime { inner }
    }

    /// Begin an attempt. `owner` is `"thread"` (a synchronous attempt,
    /// owned by the calling thread) or `"tasks"` (an async attempt, owned by
    /// the tasks the package registers). `recover` is the package's
    /// normalized recovery policy, consulted on resume.
    #[pyo3(signature = (run_id, mode, *, budget=None, caps=None, labels=None, subjects=None,
                        on_code_change=None, program=None, recover=None, owner="thread"))]
    #[allow(clippy::too_many_arguments)]
    fn begin(
        &self,
        py: Python<'_>,
        run_id: &str,
        mode: &str,
        budget: Option<u64>,
        caps: Option<Vec<String>>,
        labels: Option<BTreeMap<String, String>>,
        subjects: Option<Vec<String>>,
        on_code_change: Option<&str>,
        program: Option<(String, String)>,
        recover: Option<Py<PyAny>>,
        owner: &str,
    ) -> PyResult<Attempt> {
        let mode = parse_mode(mode)?;
        let mut opts = RunOptions {
            budget,
            labels: labels.unwrap_or_default(),
            subjects: subjects.unwrap_or_default(),
            on_code_change: parse_on_code_change(on_code_change)?,
            program,
            ..RunOptions::default()
        };
        if let Some(c) = caps {
            opts = opts.with_caps(c);
        }
        let owner = match owner {
            "thread" => Owner::Thread(std::thread::current().id()),
            "tasks" => Owner::Tasks,
            other => {
                return Err(PyValueError::new_err(format!(
                    "owner must be 'thread' or 'tasks', not {other:?}"
                )))
            }
        };
        clear_store_error();
        take_policy_error();
        let began = py.detach(|| match &recover {
            Some(policy) => {
                let mut decide = |req: &RecoverRequest<'_>| decide(policy, req);
                self.inner
                    .begin_with(run_id, mode, opts, &mut decide)
                    .map(|a| a.into_owned())
            }
            None => self.inner.begin(run_id, mode, opts).map(|a| a.into_owned()),
        });
        let policy_error = take_policy_error();
        let store_error = take_store_error();
        match began {
            Ok(owned) => {
                if let Some(e) = policy_error {
                    py.detach(move || owned.abandon());
                    return Err(e);
                }
                Attempt::new(py, owned, run_id, mode, owner)
            }
            Err(fault) => Err(policy_error
                .or(store_error)
                .unwrap_or_else(|| errors::fault_err(py, fault))),
        }
    }

    /// The full integrity check of the run's durable journal (spec 2.5,
    /// 2.13) as a dict.
    fn verify<'py>(&self, py: Python<'py>, run_id: &str) -> PyResult<Bound<'py, PyDict>> {
        clear_store_error();
        let report = py
            .detach(|| self.inner.verify(run_id))
            .map_err(|f| raise(py, f))?;
        inspect::verify_dict(py, &report)
    }

    /// The run's entries in the Entry JSON shape (spec 4.4), as JSON text.
    fn entries(&self, py: Python<'_>, run_id: &str) -> PyResult<String> {
        clear_store_error();
        py.detach(|| {
            self.inner
                .snapshot(run_id)
                .map(|j| inspect::entries_json(&j))
        })
        .map_err(|f| raise(py, f))
    }

    /// The run's summary in the RunSummary shape (spec 4.4), as JSON text.
    fn summary(&self, py: Python<'_>, run_id: &str) -> PyResult<String> {
        clear_store_error();
        py.detach(|| {
            self.inner
                .snapshot(run_id)
                .map(|j| inspect::summary_json(run_id, &j))
        })
        .map_err(|f| raise(py, f))
    }

    /// Every run id in the store.
    fn runs(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        clear_store_error();
        py.detach(|| self.inner.runs()).map_err(|f| raise(py, f))
    }

    /// Deliver a value to a run's channel inbox (this process only).
    fn send(&self, run_id: &str, channel: &str, value: Vec<u8>) {
        self.inner.send(run_id, channel, Value::from(value));
    }
}

/// The exception for a fault that carries no more than a message (`kind`
/// is its variant name, `ContractViol` for one), carrying the fault so it
/// round-trips through the agent like any fault the runtime raised.
#[pyfunction]
fn fault_exception(py: Python<'_>, kind: &str, message: &str) -> PyResult<Py<PyAny>> {
    let fault = Fault::from_recorded(kind, message)
        .ok_or_else(|| PyValueError::new_err(format!("{kind} is not a message-only fault")))?;
    Ok(errors::fault_err(py, fault).into_value(py).into_any())
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Runtime>()?;
    m.add_class::<Attempt>()?;
    m.add_class::<report::RunReport>()?;
    m.add_class::<errors::FaultHandle>()?;
    m.add_class::<NativeStore>()?;
    m.add_function(wrap_pyfunction!(attempt::effect_unrecorded, m)?)?;
    m.add_function(wrap_pyfunction!(inspect::journal_info, m)?)?;
    m.add_function(wrap_pyfunction!(inspect::check_journal, m)?)?;
    m.add_function(wrap_pyfunction!(fault_exception, m)?)?;
    m.add("CURRENT", attempt::context_var(py)?)?;
    m.add(
        "JOURNAL_HEADER",
        PyBytes::new(py, &inspect::unkeyed_header()),
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
