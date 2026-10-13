//! Faults as Python exceptions, and Python exceptions as faults.
//!
//! The exception classes live in `pragmatic/_errors.py` (spec 6.7), so their
//! constructors and attributes are ordinary Python. This module builds them
//! from core faults, and carries the fault along: every exception raised for
//! a fault holds a [`FaultHandle`], so when that exception escapes the agent
//! the attempt ends with the very fault that was raised (a desync stays a
//! desync in `attempt.end`) instead of a generic "the agent raised".
//!
//! Stores written in Python raise their own exceptions (`pragmatic.Locked`,
//! `Unavailable`, `OSError` and so on), which the core sees only as
//! [`SinkError`]s or faults. The original exception is kept on the thread
//! that called the store, and raised in place of the mapped fault when the
//! core call returns, so the caller sees exactly what the store raised.

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyDict};

use pragmatic_rt::{Fault, SinkError};

/// A core fault, held by the Python exception it was raised as.
#[pyclass(frozen, module = "pragmatic._native")]
pub struct FaultHandle {
    pub fault: Fault,
}

#[pymethods]
impl FaultHandle {
    /// The fault's variant name (`JournalDesync`, `Locked`, ...).
    #[getter]
    fn kind(&self) -> &'static str {
        self.fault.kind()
    }

    /// The fault's text. Storage and journal faults never carry slot
    /// content, so this is safe to log.
    #[getter]
    fn message(&self) -> String {
        self.fault.to_string()
    }

    /// The journal cursor the fault names, if any.
    #[getter]
    fn cursor(&self) -> Option<u64> {
        self.fault.cursor()
    }

    /// The variant's own fields, for the exception's attributes.
    fn details<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        match &self.fault {
            Fault::JournalDesync {
                cursor,
                expected,
                found,
            } => {
                d.set_item("cursor", cursor)?;
                d.set_item("expected", expected)?;
                d.set_item("found", found)?;
            }
            Fault::ReplayExhausted { cursor }
            | Fault::Erased { cursor }
            | Fault::DanglingIntent { cursor }
            | Fault::DanglingEffect { cursor } => d.set_item("cursor", cursor)?,
            Fault::Locked { retry_after_secs } => d.set_item("retry_after", retry_after_secs)?,
            Fault::Conflict { expected, actual } => {
                d.set_item("expected", expected)?;
                d.set_item("actual", actual)?;
            }
            Fault::TooLarge { size, limit } => {
                d.set_item("size", size)?;
                d.set_item("limit", limit)?;
            }
            Fault::EffectUnrecorded {
                name,
                intent,
                result,
            } => {
                d.set_item("name", name)?;
                d.set_item("intent", intent)?;
                d.set_item("result", PyBytes::new(py, result.as_bytes()))?;
            }
            Fault::Unsupported(m) | Fault::Unavailable(m) => d.set_item("detail", m)?,
            _ => {}
        }
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!("FaultHandle({:?})", self.fault)
    }
}

static FROM_FAULT: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static STORE_ERROR_INFO: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static NOT_IN_RUN: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

/// The Python exception for `fault`, carrying it.
pub fn fault_err(py: Python<'_>, fault: Fault) -> PyErr {
    let build = || -> PyResult<PyErr> {
        let from_fault = FROM_FAULT.import(py, "pragmatic._errors", "_from_fault")?;
        let exc = from_fault.call1((FaultHandle { fault },))?;
        Ok(PyErr::from_value(exc))
    };
    build().unwrap_or_else(|e| e)
}

/// `pragmatic.NotInRun(message)`.
pub fn not_in_run(py: Python<'_>, message: String) -> PyErr {
    let build = || -> PyResult<PyErr> {
        let cls = NOT_IN_RUN.import(py, "pragmatic._errors", "NotInRun")?;
        Ok(PyErr::from_value(cls.call1((message,))?))
    };
    build().unwrap_or_else(|e| e)
}

thread_local! {
    /// The exception the last failing store call on this thread raised.
    static STORE_ERROR: RefCell<Option<PyErr>> = const { RefCell::new(None) };
    /// The exception a recovery policy raised during the begin running on
    /// this thread. While it is set, sinks refuse to persist, so the
    /// attempt's opening notes and recovery decisions never become durable.
    static POLICY_ERROR: RefCell<Option<PyErr>> = const { RefCell::new(None) };
}

/// Forget any store exception left on this thread. Called before every core
/// call that may reach a store, so a stale exception is never raised for an
/// unrelated fault.
pub fn clear_store_error() {
    STORE_ERROR.with(|s| s.borrow_mut().take());
}

/// The exception the store raised during the last core call, if any.
pub fn take_store_error() -> Option<PyErr> {
    STORE_ERROR.with(|s| s.borrow_mut().take())
}

fn stash_store_error(e: PyErr) {
    STORE_ERROR.with(|s| *s.borrow_mut() = Some(e));
}

/// Remember that the recovery policy raised `e` on this thread.
pub fn stash_policy_error(e: PyErr) {
    POLICY_ERROR.with(|s| {
        s.borrow_mut().get_or_insert(e);
    });
}

/// True while a recovery policy failure is pending on this thread.
pub fn policy_failed() -> bool {
    POLICY_ERROR.with(|s| s.borrow().is_some())
}

/// Take the pending recovery policy failure, if any.
pub fn take_policy_error() -> Option<PyErr> {
    POLICY_ERROR.with(|s| s.borrow_mut().take())
}

/// What a store exception means to the core, decided by
/// `pragmatic._errors._store_error_info` so the class checks stay in Python.
enum StoreErrorKind {
    Locked(Option<u64>),
    LeaseLost,
    Conflict(u64, u64),
    Deleted,
    TooLarge(u64),
    Unavailable(String),
    Io(String),
}

fn classify(py: Python<'_>, e: &PyErr) -> StoreErrorKind {
    let info = || -> PyResult<(String, Option<u64>, Option<u64>, String)> {
        let f = STORE_ERROR_INFO.import(py, "pragmatic._errors", "_store_error_info")?;
        f.call1((e.value(py),))?.extract()
    };
    match info() {
        Ok((kind, a, b, text)) => match kind.as_str() {
            "locked" => StoreErrorKind::Locked(a),
            "lease_lost" => StoreErrorKind::LeaseLost,
            "conflict" => StoreErrorKind::Conflict(a.unwrap_or(0), b.unwrap_or(0)),
            "deleted" => StoreErrorKind::Deleted,
            "too_large" => StoreErrorKind::TooLarge(a.unwrap_or(0)),
            "unavailable" => StoreErrorKind::Unavailable(text),
            _ => StoreErrorKind::Io(text),
        },
        Err(_) => StoreErrorKind::Io(e.to_string()),
    }
}

/// The fault for an exception a store raised, remembering the exception so
/// it can be raised as is.
pub fn store_fault(py: Python<'_>, e: PyErr) -> Fault {
    let fault = match classify(py, &e) {
        StoreErrorKind::Locked(retry_after_secs) => Fault::Locked { retry_after_secs },
        StoreErrorKind::LeaseLost => Fault::LeaseLost,
        StoreErrorKind::Conflict(expected, actual) => Fault::Conflict { expected, actual },
        StoreErrorKind::Deleted => Fault::Deleted,
        StoreErrorKind::TooLarge(limit) => Fault::TooLarge { size: 0, limit },
        StoreErrorKind::Unavailable(m) => Fault::Unavailable(m),
        StoreErrorKind::Io(m) => Fault::Io(m),
    };
    stash_store_error(e);
    fault
}

/// The sink error for an exception a store raised from `persist`,
/// remembering the exception so it can be raised as is.
pub fn store_sink_error(py: Python<'_>, e: PyErr) -> SinkError {
    let err = match classify(py, &e) {
        StoreErrorKind::Locked(retry_after_secs) => SinkError::Locked { retry_after_secs },
        StoreErrorKind::LeaseLost => SinkError::LeaseLost,
        StoreErrorKind::Conflict(expected, actual) => SinkError::Conflict { expected, actual },
        StoreErrorKind::Deleted => SinkError::Deleted,
        StoreErrorKind::TooLarge(limit) => SinkError::TooLarge { limit },
        StoreErrorKind::Unavailable(m) => SinkError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("storage unavailable: {m}"),
        )),
        StoreErrorKind::Io(m) => SinkError::Io(std::io::Error::other(m)),
    };
    stash_store_error(e);
    err
}

/// Raise the outcome of a core call that may have reached a store: the
/// store's own exception when it raised one, the fault's exception
/// otherwise.
pub fn raise(py: Python<'_>, fault: Fault) -> PyErr {
    take_store_error().unwrap_or_else(|| fault_err(py, fault))
}
