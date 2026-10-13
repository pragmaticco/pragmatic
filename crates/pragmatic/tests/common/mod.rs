//! Helpers shared by the integration suites. Each suite uses a different
//! subset, hence the blanket `dead_code` allowance.
#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use pragmatic::sha256::Digest;
use pragmatic::{
    AsyncOracle, Backend, Checkout, CountingOracle, Fault, Journal, SeededOracle, Sink, SinkError,
    TraceLabel, Value,
};

/// The trace as T1 compares it: `(branch, cursor, label)`.
pub fn keyed(trace: &[TraceLabel]) -> Vec<(Option<Vec<u32>>, Option<u64>, TraceLabel)> {
    trace
        .iter()
        .map(|l| (l.branch().cloned(), l.cursor(), l.clone()))
        .collect()
}

/// Simulate a crash that left only the journal's entries before its `k`-th
/// program entry durable (notes before it survive with it). `k` past the
/// end keeps everything.
pub fn crash_before(backend: &dyn Backend, run_id: &str, k: usize) {
    let snap = backend.snapshot(run_id, None).unwrap();
    let keep = snap
        .program_entries()
        .get(k)
        .map_or(snap.len(), |e| e.cursor);
    backend.crash_truncate(run_id, keep).unwrap();
}

/// The note kinds of a journal, in order.
pub fn note_kinds(journal: &Journal) -> Vec<String> {
    journal
        .entries()
        .iter()
        .filter_map(|e| e.event.note_kind().map(str::to_string))
        .collect()
}

/// A fresh, empty directory under the system temp dir, removed on drop.
pub struct TempDir(pub std::path::PathBuf);

impl TempDir {
    pub fn new(name: &str) -> TempDir {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("pragmatic-it-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Yield to the executor once.
pub async fn yield_now() {
    struct Yield(bool);
    impl std::future::Future for Yield {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    Yield(false).await
}

/// An async oracle over a counting seeded oracle that yields `n % 3` times
/// before answering its `n`-th call, so concurrent children finish their
/// model calls out of index order.
pub struct Staggered {
    inner: CountingOracle<SeededOracle>,
}

impl Staggered {
    pub fn new(seed: u64) -> Staggered {
        Staggered {
            inner: CountingOracle::new(SeededOracle::new(seed)),
        }
    }

    pub fn calls(&self) -> u64 {
        self.inner.calls()
    }
}

impl AsyncOracle for Staggered {
    fn call(&self, prompt: &Value) -> impl std::future::Future<Output = Result<Value, Fault>> + '_ {
        let prompt = prompt.clone();
        let n = self.inner.calls();
        let out = pragmatic::Oracle::call(&self.inner, &prompt);
        async move {
            for _ in 0..(n % 3) {
                yield_now().await;
            }
            out
        }
    }
}

/// A backend whose sinks fail once a shared budget of persists is spent:
/// `persists_left` counts down on every persist, and a persist that finds it
/// at zero fails with an I/O error. Negative means "never fail".
pub struct FlakyBackend {
    pub inner: pragmatic::MemoryBackend,
    pub persists_left: Arc<AtomicI64>,
}

impl FlakyBackend {
    pub fn new() -> FlakyBackend {
        FlakyBackend {
            inner: pragmatic::MemoryBackend::new(),
            persists_left: Arc::new(AtomicI64::new(-1)),
        }
    }

    /// Let `n` more persists succeed, then fail.
    pub fn fail_after(&self, n: i64) {
        self.persists_left.store(n, Ordering::SeqCst);
    }
}

impl Clone for FlakyBackend {
    fn clone(&self) -> Self {
        FlakyBackend {
            inner: self.inner.clone(),
            persists_left: self.persists_left.clone(),
        }
    }
}

struct FlakySink {
    inner: Box<dyn Sink>,
    persists_left: Arc<AtomicI64>,
}

impl Sink for FlakySink {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError> {
        let left = self.persists_left.load(Ordering::SeqCst);
        if left == 0 {
            return Err(SinkError::Io(std::io::Error::other("disk full (injected)")));
        }
        if left > 0 {
            self.persists_left.store(left - 1, Ordering::SeqCst);
        }
        self.inner.persist(at, frames, head_after)
    }

    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError> {
        self.inner.rewrite(file)
    }
}

impl Backend for FlakyBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        let co = self.inner.checkout(run_id, create, key)?;
        Ok(Checkout {
            journal: co.journal,
            sink: Box::new(FlakySink {
                inner: co.sink,
                persists_left: self.persists_left.clone(),
            }),
            guard: co.guard,
            torn: co.torn,
        })
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        self.inner.snapshot(run_id, key)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        self.inner.list()
    }

    fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        self.inner.crash_truncate(run_id, keep)
    }
}

/// A memory backend that says it is remote, so recovery has no default
/// for effects left without a result.
pub struct RemoteBackend(pub pragmatic::MemoryBackend);

impl Backend for RemoteBackend {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault> {
        self.0.checkout(run_id, create, key)
    }

    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault> {
        self.0.snapshot(run_id, key)
    }

    fn list(&self) -> Result<Vec<String>, Fault> {
        self.0.list()
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn crash_truncate(&self, run_id: &str, keep: u64) -> Result<(), Fault> {
        self.0.crash_truncate(run_id, keep)
    }
}
