//! Memory bounds: what a request, a read or a background job may hold.
//!
//! A counting global allocator measures this process's live and peak heap
//! (server and client share it). The tests take one lock so they never
//! run at the same time and disturb each other's measurements; other test
//! binaries are separate processes.

mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use common::*;
use pragmatic_server::access_log::AccessRecord;
use reqwest::{Method, StatusCode};
use serde_json::json;

struct Counting;

static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        let p = unsafe { std::alloc::System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size() as i64, Ordering::Relaxed) + l.size() as i64;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) };
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, new: usize) -> *mut u8 {
        let q = unsafe { std::alloc::System.realloc(p, l, new) };
        if !q.is_null() {
            let d = new as i64 - l.size() as i64;
            let now = LIVE.fetch_add(d, Ordering::Relaxed) + d;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Held by each test for its whole run.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn live_mib() -> i64 {
    LIVE.load(Ordering::Relaxed) >> 20
}

/// Start measuring the peak from the current live heap.
fn reset_peak() -> i64 {
    let now = LIVE.load(Ordering::Relaxed);
    PEAK.store(now, Ordering::Relaxed);
    now
}

/// MiB the peak rose above `base`.
fn peak_above(base: i64) -> i64 {
    (PEAK.load(Ordering::Relaxed) - base) >> 20
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unauthenticated_requests_leave_no_memory_behind() {
    let _one = SERIAL.lock().await;
    let ts = TestServer::start(|_| {}).await;
    for i in 0..20 {
        let _ = ts
            .client
            .get(format!("{}/v1/runs/warm{i}", ts.url))
            .send()
            .await;
    }
    ts.app().access.flush().await.unwrap();
    // The same traffic twice: one repeated 60 KB id, then 1,500 distinct
    // ones. Nothing about a record may stay in memory, so the second pass
    // must not leave more behind than the first.
    async fn blast(ts: &TestServer, distinct: bool, tag: &str) {
        let mut tasks = Vec::new();
        for batch in 0..30 {
            let (client, url, tag) = (ts.client.clone(), ts.url.clone(), tag.to_string());
            tasks.push(tokio::spawn(async move {
                for j in 0..50 {
                    let id = if distinct {
                        format!("{tag}{batch:05}-{j:03}-{}", "x".repeat(60_000))
                    } else {
                        format!("{tag}-{}", "x".repeat(60_000))
                    };
                    let r = client
                        .get(format!("{url}/v1/runs/{id}"))
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        ts.app().access.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let r0 = live_mib();
    blast(&ts, false, "same").await;
    let r1 = live_mib();
    blast(&ts, true, "uniq").await;
    let r2 = live_mib();
    assert!(
        r2 - r1 < (r1 - r0).max(0) + 16,
        "1,500 unauthenticated 401s with distinct run ids left {} MiB behind ({} MiB for one \
         repeated id)",
        r2 - r1,
        r1 - r0
    );
    // And the log itself stayed small: the ids were not written into it.
    let len = std::fs::metadata(ts.data_dir().join("audit").join("access.journal"))
        .unwrap()
        .len();
    assert!(len < 8 << 20, "the access log grew to {len} bytes");
}

/// Fill the access log with `n` records of about `size` bytes each, through
/// the log itself (requests can no longer make records this large).
async fn fill_access_log(ts: &TestServer, n: usize, size: usize) {
    let padding = "p".repeat(size);
    for i in 0..n {
        let mut r = AccessRecord::new("request", json!({"route": "/fill", "n": i}));
        r.personal
            .insert("user_agent".into(), padding.clone().into());
        ts.app().access.submit(r);
    }
    ts.app().access.flush().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn verify_data_and_startup_read_the_access_log_frame_by_frame() {
    let _one = SERIAL.lock().await;
    let ts = TestServer::start(|_| {}).await;
    fill_access_log(&ts, 1600, 60_000).await;
    let log_mib = std::fs::metadata(ts.data_dir().join("audit").join("access.journal"))
        .unwrap()
        .len()
        >> 20;
    assert!(log_mib >= 80, "precondition: a large log ({log_mib} MiB)");

    let base = reset_peak();
    let resp = ts
        .req(Method::POST, "/v1/verify-data", &ts.admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let report: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(report["access_log"]["ok"], true, "{report}");
    let peak = peak_above(base);
    assert!(
        peak < 32,
        "verify-data of a {log_mib} MiB access log raised peak heap by {peak} MiB"
    );

    // A restart reads the whole log again to rebuild its index.
    let base = reset_peak();
    let ts = ts.restart().await;
    let peak = peak_above(base);
    assert!(
        peak < 32,
        "a restart over a {log_mib} MiB access log raised peak heap by {peak} MiB"
    );
    assert!(ts.app().access.tip().0 > 1600);
}

/// Reading a page of entries, or one slot, reads those frames, not the
/// journal: three concurrent one-entry pages of a 68 MiB journal (more
/// than any cache would hold) stay far below its size.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_page_of_a_large_journal_reads_only_its_entries() {
    let _one = SERIAL.lock().await;
    let ts = TestServer::start(|c| c.lease_ttl_secs = 600).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let (auditor, _) = ts.issue("auditor", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "big").await;
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    for i in 0..2 {
        w.add(recv(&format!("{i}{}", "z".repeat(34 << 20))));
        let r = w.push(&ts).await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    w.add(recv("small and last"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    // The holder's writer journal is in memory already; release it.
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let base = reset_peak();
    let mut tasks = Vec::new();
    for path in [
        run_path("big", "/entries?from=0&limit=1"),
        run_path("big", "/entries?from=3&limit=10"),
        run_path("big", "/entries/3/slots/0"),
    ] {
        let (client, url, tok) = (
            ts.client.clone(),
            format!("{}{path}", ts.url),
            auditor.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let r = client.get(url).bearer_auth(tok).send().await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            r.bytes().await.unwrap().len()
        }));
    }
    let mut served = 0;
    for t in tasks {
        served += t.await.unwrap();
    }
    let peak = peak_above(base);
    assert!(
        peak < 16,
        "three small reads ({served} bytes served) raised peak heap by {peak} MiB"
    );
    // A resend of a stored frame by a token without the lease is checked
    // against stored hashes, without loading the journal.
    let (other, _) = ts.issue("agent", &["*"], false).await;
    let frame = w.journal.frame_bytes(3).unwrap();
    let head = pragmatic::encoding::hex_encode(&w.journal.get(3).unwrap().hash);
    let base = reset_peak();
    let resp = send_frames(&ts, &other, "big", "none", 3, 1, &head, frame).await;
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["duplicate"], true, "{v}");
    assert!(peak_above(base) < 16);
}

/// A body sent without the lease is refused before it is buffered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_without_the_lease_never_have_their_body_buffered() {
    let _one = SERIAL.lock().await;
    let ts = TestServer::start(|c| c.lease_ttl_secs = 600).await;
    let (owner, _) = ts.issue("agent", &["*"], false).await;
    let (other, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &owner, "leased").await;
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let body = vec![0u8; 128 << 20];
    let base = reset_peak();
    let resp = ts
        .req(Method::POST, &run_path("leased", "/frames?at=1"), &other)
        .header("pragmatic-lease", "not-a-lease")
        .header("pragmatic-frames", "1")
        .header("pragmatic-head", "0".repeat(64))
        .body(body)
        .send()
        .await
        .unwrap();
    let (status, c) = code(resp).await;
    let peak = peak_above(base);
    assert_eq!((status, c.as_str()), (StatusCode::CONFLICT, "lease_lost"));
    assert!(
        peak < 16,
        "a request without the lease was refused only after {peak} MiB was buffered"
    );
}
