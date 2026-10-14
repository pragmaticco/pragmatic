//! Performance (design 4.16).
//!
//! The always-on test is a sanity check that concurrent appends to many
//! runs all land and that throughput is not pathological, with bounds loose
//! enough for a debug build on a laptop disk. The load test is the
//! measurement against the design's targets; run it in release mode on the
//! target hardware (4 vCPU, SSD):
//!
//! ```text
//! cargo test -p pragmatic-server --release --test perf -- --ignored --nocapture
//! ```
//!
//! `PRAGMATIC_LOAD_STARTUP_RUNS` sets how many runs the startup part
//! creates (default 1,000,000; 0 skips it). With 1,000,000 runs startup
//! must take at most 30 s (design 4.16); `PRAGMATIC_LOAD_STARTUP_LIMIT_SECS`
//! sets the bound for a smaller count, as CI does on its runners.

mod common;

use std::time::{Duration, Instant};

use common::*;
use pragmatic::encoding::hex_encode;
use pragmatic::journal::{self, META};
use pragmatic::{Content, Journal};
use pragmatic_server::layout;
use reqwest::StatusCode;
use serde_json::json;

/// `runs` concurrent writers, each appending `per_run` single-frame
/// requests with `payload` bytes of content. Returns appends per second.
async fn hammer(ts: &TestServer, prefix: &str, runs: usize, per_run: usize, payload: usize) -> f64 {
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut writers = Vec::new();
    for i in 0..runs {
        let mut w = Writer::create(ts, &agent, &format!("{prefix}-{i}")).await;
        let resp = w.push(ts).await;
        assert_eq!(resp.status(), StatusCode::OK);
        writers.push(w);
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for mut w in writers {
        let ts_url = ts.url.clone();
        let client = ts.client.clone();
        let body = "x".repeat(payload);
        tasks.push(tokio::spawn(async move {
            for _ in 0..per_run {
                w.journal
                    .append(
                        journal::ROOT,
                        pragmatic::Event::ChannelRecv {
                            channel: "in".into(),
                            value: Content::from(body.as_str()),
                        },
                    )
                    .unwrap();
                let (at, frames, head) = w.journal.pending().unwrap();
                let url = format!("{ts_url}{}", run_path(&w.run, &format!("/frames?at={at}")));
                // Like an SDK, resend the identical request on transport
                // errors (a burst of new connections can overflow the
                // listen backlog); the duplicate rule makes that safe.
                let mut tries = 0;
                let resp = loop {
                    tries += 1;
                    let sent = client
                        .post(&url)
                        .bearer_auth(&w.token)
                        .header("pragmatic-lease", &w.lease)
                        .header("pragmatic-frames", "1")
                        .header("pragmatic-head", hex_encode(&head))
                        .body(frames.to_vec())
                        .send()
                        .await;
                    match sent {
                        Ok(r) => break r,
                        Err(e) if tries < 100 => {
                            let _ = e;
                            tokio::time::sleep(Duration::from_millis(10)).await
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                assert_eq!(resp.status(), StatusCode::OK);
                w.journal.mark_persisted(w.journal.len());
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    (runs * per_run) as f64 / started.elapsed().as_secs_f64()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_all_land_at_a_sane_rate() {
    let ts = TestServer::start(|_| {}).await;
    let rate = hammer(&ts, "load", 16, 20, 256).await;
    for i in 0..16 {
        assert_eq!(stored(&ts, &format!("load-{i}")).len(), 21);
    }
    assert_eq!(ts.app().metrics.appends(), 16 * 21);
    eprintln!("sanity: {rate:.0} appends/s");
    assert!(rate > 20.0, "{rate:.1} appends/s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load test: run in release mode on the target hardware"]
async fn load_meets_the_design_targets() {
    let ts = TestServer::start(|_| {}).await;
    // Warm up, then measure 200 concurrent runs with 4 KiB frames.
    hammer(&ts, "warm", 8, 10, 4096).await;
    let before = ts.app().metrics.appends();
    let rate = hammer(&ts, "load", 200, 50, 4096).await;
    let m = &ts.app().metrics;
    let p50 = m.append_fraction_within(0.005).unwrap();
    let p99 = m.append_fraction_within(0.025).unwrap();
    eprintln!(
        "{} appends at {rate:.0}/s; {:.1}% within 5 ms, {:.2}% within 25 ms",
        m.appends() - before,
        p50 * 100.0,
        p99 * 100.0
    );
    let runs: usize = std::env::var("PRAGMATIC_LOAD_STARTUP_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    if runs > 0 {
        startup_with(runs).await;
    }
    assert!(
        rate >= 1000.0,
        "at least 1,000 appends per second across 200 runs"
    );
    assert!(p50 >= 0.5, "p50 at most 5 ms server-side");
    assert!(p99 >= 0.99, "p99 at most 25 ms server-side");
}

/// Write `n` small runs straight to a data directory (as a server would
/// have left them), then time a cold start until the index is ready.
async fn startup_with(n: usize) {
    let dir = std::sync::Arc::new(TempDir::new("startup-load"));
    let config = test_config(dir.path());
    pragmatic_server::keys::ServerKey::generate(&config.server_name())
        .unwrap()
        .write_new(&config.keys.signing_key_file)
        .unwrap();
    let l = layout::Layout::new(config.data_dir.clone());
    std::fs::create_dir_all(&config.data_dir).unwrap();
    layout::write_format(&l, layout::DATA_FORMAT).unwrap();
    let index_key = layout::index_key(&l).unwrap();
    let made = Instant::now();
    std::thread::scope(|s| {
        let workers = 8;
        for w in 0..workers {
            let l = &l;
            let index_key = &index_key;
            s.spawn(move || {
                for i in (w..n).step_by(workers) {
                    write_run(l, &format!("startup-{i}"), index_key);
                }
            });
        }
    });
    eprintln!("wrote {n} runs in {:?}", made.elapsed());
    let started = Instant::now();
    let ts = TestServer::boot(dir, config, None).await;
    let took = started.elapsed();
    eprintln!("startup with {n} runs: {took:?}");
    assert_eq!(ts.app().store.len(), n);
    let limit: Option<u64> = std::env::var("PRAGMATIC_LOAD_STARTUP_LIMIT_SECS")
        .ok()
        .and_then(|v| v.parse().ok());
    if let Some(secs) = limit.or((n >= 1_000_000).then_some(30)) {
        assert!(
            took <= Duration::from_secs(secs),
            "startup at most {secs} s with {n} runs"
        );
    }
}

fn write_run(l: &layout::Layout, run: &str, index_key: &[u8]) {
    let mut j = Journal::new(None);
    j.append(
        META,
        note(
            "run.start",
            json!({"run_id": run, "format": 2, "labels": {}}),
            vec![],
        ),
    )
    .unwrap();
    j.mark_persisted(j.len());
    let stem = layout::stem(run);
    std::fs::create_dir_all(l.run_dir(&stem)).unwrap();
    std::fs::write(l.journal(&stem), j.to_bytes()).unwrap();
    let now = pragmatic_server::timefmt::now_rfc3339();
    let meta = pragmatic_server::store::Meta {
        format: 1,
        run_id: run.into(),
        created_at: now.clone(),
        updated_at: now,
        entries: j.len(),
        byte_len: j.byte_len(),
        head: hex_encode(&j.head()),
        anchored_entries: 0,
        last_anchor_leaf: None,
        leases: vec![],
        holds: vec![],
        status: "idle".into(),
        created_by: None,
        regressed: false,
        unanchored_since: None,
        regression_accepted: false,
        summary: pragmatic_server::summary::Summary::rebuild(&j, index_key),
    };
    std::fs::write(l.meta(&stem), serde_json::to_vec(&meta).unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test: writes a 1 GiB journal"]
async fn a_one_gib_journal_is_appended_restarted_and_served() {
    let ts = TestServer::start(|c| c.max_request_bytes = 1 << 30).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "big").await;
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    // 16 slots of 64 MiB, each distinct so none is deduplicated.
    for i in 0..16u8 {
        let mut content = vec![b'a' + i; 64 << 20];
        content[0] = i;
        w.journal
            .append(
                journal::ROOT,
                pragmatic::Event::ChannelRecv {
                    channel: "in".into(),
                    value: Content::from(content),
                },
            )
            .unwrap();
        assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    }
    let size = w.journal.byte_len();
    assert!(size > 1 << 30);
    let ts = ts.restart().await;
    let started = Instant::now();
    let resp = ts.get(&run_path("big", "/journal"), &ts.admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.bytes().await.unwrap();
    eprintln!("served {} bytes in {:?}", body.len(), started.elapsed());
    assert_eq!(body.len() as u64, size);
    let v: serde_json::Value = ts
        .get(&run_path("big", "/entries?from=16&limit=1"), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["entries"][0]["slots"][0]["truncated"], true);
}
