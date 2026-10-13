//! Where the Python package's journals live: the native backends behind
//! `pragmatic.DirStore` and `pragmatic.MemoryStore`, and [`PyBackend`],
//! which drives a Python object implementing the store protocol of spec
//! 6.3 (`pragmatic.ServerStore`, or a store of the user's own).
//!
//! Every backend is reached through [`HostBackend`], which shares one
//! backend between runtimes (two runtimes over one `MemoryStore` see the
//! same runs, as two processes over one directory do) and wraps each
//! checkout's sink in a [`GuardedSink`]. The guard is how a recovery policy
//! that raises aborts a resume: while the policy's exception is pending on
//! the thread running `begin`, the sink refuses to persist, so the opening
//! notes and the recovery decisions of that attempt never become durable
//! and the intent stays undecided for the next resume.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use pragmatic_rt::backend::{
    Backend, Checkout, CheckoutGuard, DirBackend, MemoryBackend, Sink, SinkError,
};
use pragmatic_rt::journal::{Journal, FORMAT1_READ_ONLY};
use pragmatic_rt::sha256::{hex, Digest, DIGEST_LEN};
use pragmatic_rt::{Fault, VerifyReport};

use crate::errors::{policy_failed, store_fault, store_sink_error};

/// A backend shared by every runtime built over the same store object.
#[derive(Clone)]
pub struct HostBackend(pub Arc<dyn Backend>);

impl Backend for HostBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        let mut co = self.0.checkout(run_id, create, key)?;
        co.sink = Box::new(GuardedSink(co.sink));
        Ok(co)
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        self.0.snapshot(run_id, key)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        self.0.list()
    }

    fn verify(&self, run_id: &str, key: Option<&[u8]>) -> Result<VerifyReport, Fault> {
        self.0.verify(run_id, key)
    }

    fn is_remote(&self) -> bool {
        self.0.is_remote()
    }
}

/// A sink that refuses to persist while a recovery policy failure is
/// pending on the current thread (see the module documentation).
struct GuardedSink(Box<dyn Sink>);

impl Sink for GuardedSink {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError> {
        if policy_failed() {
            return Err(SinkError::Io(std::io::Error::other(
                "the recovery policy raised, so this attempt records nothing",
            )));
        }
        self.0.persist(at, frames, head_after)
    }

    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError> {
        self.0.rewrite(file)
    }

    fn remove_copies(&mut self) -> Result<(), SinkError> {
        self.0.remove_copies()
    }
}

/// A native backend handle: what `pragmatic.DirStore`,
/// `pragmatic.MemoryStore` and the wrapper around a Python store hold.
#[pyclass(frozen, module = "pragmatic._native")]
pub struct NativeStore {
    pub backend: HostBackend,
    kind: &'static str,
}

#[pymethods]
impl NativeStore {
    /// Journals as files under `path`, one per run, each with a sidecar lock
    /// file (spec 3.3).
    #[staticmethod]
    fn dir(py: Python<'_>, path: std::path::PathBuf) -> PyResult<NativeStore> {
        let backend = py
            .detach(|| DirBackend::new(&path))
            .map_err(|f| crate::errors::fault_err(py, f))?;
        Ok(NativeStore {
            backend: HostBackend(Arc::new(backend)),
            kind: "dir",
        })
    }

    /// Journals in this process's memory.
    #[staticmethod]
    fn memory() -> NativeStore {
        NativeStore {
            backend: HostBackend(Arc::new(MemoryBackend::new())),
            kind: "memory",
        }
    }

    /// A Python object implementing the store protocol (spec 6.3).
    #[staticmethod]
    fn python(py: Python<'_>, store: Py<PyAny>) -> PyResult<NativeStore> {
        let remote = match store.bind(py).getattr("remote") {
            Ok(v) => v.is_truthy()?,
            Err(_) => false,
        };
        Ok(NativeStore {
            backend: HostBackend(Arc::new(PyBackend { store, remote })),
            kind: "python",
        })
    }

    /// `dir`, `memory` or `python`.
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind
    }

    /// Every run id in the store.
    fn list(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        crate::errors::clear_store_error();
        let backend = self.backend.clone();
        py.detach(move || backend.list())
            .map_err(|f| crate::errors::raise(py, f))
    }
}

/// A backend over a Python object implementing the store protocol:
/// `checkout`, `snapshot`, `persist`, `checkin` and `list` (spec 6.3).
///
/// Every call takes the GIL itself, so the backend can be called from inside
/// `Python::detach` with no Rust lock held, which is the only way the
/// binding calls it.
pub struct PyBackend {
    store: Py<PyAny>,
    remote: bool,
}

/// The journal bytes a store returned, with the entry count and head the
/// store vouches for when it returned `(bytes, entries, head_hex)` (as
/// `ServerStore` does with the `Pragmatic-Entries` and `Pragmatic-Head`
/// headers of a download).
struct Download {
    bytes: Vec<u8>,
    expect: Option<(u64, String)>,
}

fn download(obj: &Bound<'_, PyAny>) -> PyResult<Download> {
    if let Ok(t) = obj.cast::<PyTuple>() {
        let (bytes, entries, head): (Vec<u8>, u64, String) = (
            t.get_item(0)?.cast::<PyBytes>()?.as_bytes().to_vec(),
            t.get_item(1)?.extract()?,
            t.get_item(2)?.extract()?,
        );
        return Ok(Download {
            bytes,
            expect: Some((entries, head)),
        });
    }
    Ok(Download {
        bytes: obj.cast::<PyBytes>()?.as_bytes().to_vec(),
        expect: None,
    })
}

/// Read and verify journal bytes from a store: the chain and every
/// commitment (spec 4.6: the client verifies every journal it downloads),
/// the format, and the entry count and head the store vouched for.
fn read_journal(
    run_id: &str,
    dl: Download,
    key: Option<&[u8]>,
    writable: bool,
) -> Result<Journal, Fault> {
    let bytes = if dl.bytes.is_empty() {
        pragmatic_rt::journal::header(0).to_vec()
    } else {
        dl.bytes
    };
    let parsed = Journal::parse(&bytes, key)?;
    if writable && parsed.journal.format() == 1 {
        return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
    }
    if writable && parsed.tail_len > 0 {
        return Err(Fault::Io(format!(
            "the store returned run '{run_id}' with {} bytes past its last whole entry; a store \
             must hold only whole frames",
            parsed.tail_len
        )));
    }
    if let Some((entries, head)) = dl.expect {
        let got = parsed.journal.len();
        if got != entries {
            return Err(Fault::Conflict {
                expected: entries,
                actual: got,
            });
        }
        let head_ok = if entries == 0 {
            head.is_empty() || head == hex(&parsed.journal.genesis())
        } else {
            head == hex(&parsed.journal.head())
        };
        if !head_ok {
            return Err(Fault::Io(format!(
                "the journal downloaded for run '{run_id}' does not end at the head the store \
                 reported"
            )));
        }
    }
    if !parsed.journal.is_empty() {
        match parsed.journal.run_start_id() {
            Some(id) if id == run_id => {}
            Some(other) => {
                return Err(Fault::Io(format!(
                    "the store returned the journal of run '{other}' for '{run_id}'"
                )))
            }
            None => {
                return Err(Fault::Io(format!(
                    "the journal of run '{run_id}' does not begin with a run.start note"
                )))
            }
        }
    }
    Ok(parsed.journal)
}

impl Backend for PyBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        let dl = Python::attach(|py| {
            let out = self
                .store
                .call_method1(py, "checkout", (run_id, create))
                .map_err(|e| store_fault(py, e))?;
            download(out.bind(py)).map_err(|e| store_fault(py, e))
        })?;
        let journal = match read_journal(run_id, dl, key, true) {
            Ok(j) => j,
            Err(f) => {
                // The store took the run's lock or lease; hand it back.
                self.checkin(run_id);
                return Err(f);
            }
        };
        let store = Python::attach(|py| self.store.clone_ref(py));
        let guard_store = Python::attach(|py| self.store.clone_ref(py));
        let id = run_id.to_string();
        let guard = CheckoutGuard::new(move || {
            Python::attach(|py| {
                // Checkin is best effort: a lease that is not released
                // expires on its own, and a failure here must not hide the
                // outcome of the attempt.
                if let Err(e) = guard_store.call_method1(py, "checkin", (id.as_str(),)) {
                    e.write_unraisable(py, None);
                }
            })
        });
        Ok(Checkout {
            journal,
            sink: Box::new(PySink {
                store,
                run_id: run_id.to_string(),
            }),
            guard,
            torn: None,
        })
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        let dl = Python::attach(|py| {
            let out = self
                .store
                .call_method1(py, "snapshot", (run_id,))
                .map_err(|e| store_fault(py, e))?;
            download(out.bind(py)).map_err(|e| store_fault(py, e))
        })?;
        read_journal(run_id, dl, key, false)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        Python::attach(|py| {
            self.store
                .call_method0(py, "list")
                .and_then(|v| v.extract::<Vec<String>>(py))
                .map_err(|e| store_fault(py, e))
        })
    }

    fn is_remote(&self) -> bool {
        self.remote
    }
}

impl PyBackend {
    fn checkin(&self, run_id: &str) {
        Python::attach(|py| {
            if let Err(e) = self.store.call_method1(py, "checkin", (run_id,)) {
                e.write_unraisable(py, None);
            }
        })
    }
}

/// Persists through the Python store's `persist(run_id, at, frames,
/// frame_count, head_hex)`.
struct PySink {
    store: Py<PyAny>,
    run_id: String,
}

/// The number of whole frames in `frames` (each is a `u32` length, the
/// record and a 32-byte hash).
pub fn count_frames(frames: &[u8]) -> u64 {
    let mut pos = 0usize;
    let mut n = 0u64;
    while pos + 4 <= frames.len() {
        let len = u32::from_le_bytes(frames[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        pos += 4 + len + DIGEST_LEN;
        n += 1;
    }
    n
}

impl Sink for PySink {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError> {
        let count = count_frames(frames);
        Python::attach(|py| {
            self.store
                .call_method1(
                    py,
                    "persist",
                    (
                        self.run_id.as_str(),
                        at,
                        PyBytes::new(py, frames),
                        count,
                        hex(head_after),
                    ),
                )
                .map(|_| ())
                .map_err(|e| store_sink_error(py, e))
        })
    }

    fn rewrite(&mut self, _file: &[u8]) -> Result<(), SinkError> {
        Err(SinkError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a Python store cannot rewrite journals; erase runs through the store's own tools",
        )))
    }
}
