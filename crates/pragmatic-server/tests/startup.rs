//! Startup (design 4.1 and 4.2): rules, the data directory lock, the
//! index with its byte_len shortcut, torn journals, meta mismatches,
//! corruption, missing and regressed runs, and readiness.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use pragmatic_server::config::Config;
use pragmatic_server::server::{self, Hooks};
use pragmatic_server::store::Meta;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn run_file(ts: &TestServer, run: &str, suffix: &str) -> std::path::PathBuf {
    let stem = pragmatic_server::layout::stem(run);
    ts.data_dir()
        .join("runs")
        .join(&stem[..2])
        .join(format!("{stem}{suffix}"))
}

fn read_meta(ts: &TestServer, run: &str) -> Meta {
    serde_json::from_slice(&std::fs::read(run_file(ts, run, ".meta.json")).unwrap()).unwrap()
}

fn write_meta(ts: &TestServer, run: &str, meta: &Meta) {
    std::fs::write(
        run_file(ts, run, ".meta.json"),
        serde_json::to_vec(meta).unwrap(),
    )
    .unwrap();
}

async fn summary(ts: &TestServer, run: &str) -> Value {
    ts.get(&run_path(run, ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_torn_journal_is_truncated_moved_aside_and_recorded() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    ts.stop().await;
    // A crash in the middle of the next append: half a frame.
    w.add(recv("never acknowledged"));
    let (_, frames, _, _) = w.pending();
    let path = run_file(&ts, "r", ".journal");
    let mut bytes = std::fs::read(&path).unwrap();
    let good = bytes.len();
    bytes.extend_from_slice(&frames[..frames.len() / 2]);
    std::fs::write(&path, &bytes).unwrap();
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    let j = stored(&ts, "r");
    assert_eq!(j.len(), 6, "five entries plus the torn_tail note");
    assert_eq!(j.get(5).unwrap().event.note_kind(), Some("torn_tail"));
    let moved: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".torn-"))
        .collect();
    assert_eq!(moved.len(), 1);
    assert_eq!(
        std::fs::read(moved[0].path()).unwrap(),
        frames[..frames.len() / 2]
    );
    let s = summary(&ts, "r").await;
    assert_eq!(s["entries"], 6);
    assert_eq!(s["verify"]["ok"], true);
    assert!(std::fs::metadata(&path).unwrap().len() > good as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_or_wrong_meta_is_rebuilt_from_the_journal() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    for run in ["stale", "wrong-head", "no-meta"] {
        Writer::create(&ts, &agent, run).await.attempt(&ts, 2).await;
    }
    ts.stop().await;
    // Meta from before the last append (meta.json lags by up to a second).
    let mut m = read_meta(&ts, "stale");
    m.entries = 2;
    m.byte_len -= 10;
    write_meta(&ts, "stale", &m);
    // Same size, different head: the shortcut must not trust it.
    let mut m = read_meta(&ts, "wrong-head");
    m.head = "00".repeat(32);
    m.summary.labels.insert("bogus".into(), "1".into());
    write_meta(&ts, "wrong-head", &m);
    std::fs::remove_file(run_file(&ts, "no-meta", ".meta.json")).unwrap();
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    for run in ["stale", "wrong-head", "no-meta"] {
        let s = summary(&ts, run).await;
        assert_eq!(s["entries"], 5, "{run}: {s}");
        assert_eq!(s["last_outcome"], "ok", "{run}");
        assert_eq!(s["labels"], json!({}), "{run}");
        let head = pragmatic::encoding::hex_encode(&stored(&ts, run).head());
        assert_eq!(s["head"], head, "{run}");
    }
    assert!(run_file(&ts, "no-meta", ".meta.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corruption_marks_the_run_damaged_and_is_never_truncated() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 4).await;
    ts.stop().await;
    let path = run_file(&ts, "r", ".journal");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.windows(9).position(|x| x == b"message 1").unwrap();
    bytes[at] = b'M';
    std::fs::write(&path, &bytes).unwrap();
    // Size and head still match the meta, so the index trusts the file;
    // background verification finds the damage.
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    let run = ts.app().store.get("r").unwrap();
    let mut tries = 0;
    while run.lock().broken.is_none() && tries < 200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        tries += 1;
    }
    let s = summary(&ts, "r").await;
    assert_eq!(s["verify"]["ok"], false);
    assert_eq!(s["verify"]["first_bad"], 3);
    w.add(recv("more"));
    assert_eq!(code(w.push(&ts).await).await.1, "chain_broken");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "never truncated or rewritten"
    );
    let metrics = ts
        .client
        .get(format!("{}/metrics", ts.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("pragmatic_chain_broken_total 1"),
        "{metrics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_torn_tail_below_the_anchored_length_is_not_truncated() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    ts.stop().await;
    let mut m = read_meta(&ts, "r");
    m.anchored_entries = 9;
    m.byte_len += 1;
    write_meta(&ts, "r", &m);
    let path = run_file(&ts, "r", ".journal");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&[9, 0, 0]);
    std::fs::write(&path, &bytes).unwrap();
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let run = ts.app().store.get("r").unwrap();
    assert!(run.lock().broken.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_without_a_journal_is_recreated_or_missing() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let _ = Writer::create(&ts, &agent, "fresh").await;
    Writer::create(&ts, &agent, "anchored")
        .await
        .attempt(&ts, 1)
        .await;
    ts.stop().await;
    std::fs::remove_file(run_file(&ts, "fresh", ".journal")).unwrap();
    let mut m = read_meta(&ts, "anchored");
    m.anchored_entries = 4;
    write_meta(&ts, "anchored", &m);
    std::fs::remove_file(run_file(&ts, "anchored", ".journal")).unwrap();
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    assert_eq!(summary(&ts, "fresh").await["status"], "active");
    assert!(run_file(&ts, "fresh", ".journal").exists());
    assert_eq!(summary(&ts, "anchored").await["status"], "missing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_regressed_run_refuses_appends_until_accepted() {
    let mut ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    ts.stop().await;
    let mut m = read_meta(&ts, "r");
    m.anchored_entries = 10;
    write_meta(&ts, "r", &m);
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    let s = summary(&ts, "r").await;
    assert_eq!(s["status"], "regressed");
    w.add(recv("x"));
    assert_eq!(
        code(w.push(&ts).await).await,
        (StatusCode::CONFLICT, "regressed".into())
    );
    let resp = ts
        .post_json(&run_path("r", "/accept-regression"), &ts.admin, json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["anchored_entries_before"], 10);
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let records = ts.audit().await;
    assert!(records
        .iter()
        .any(|r| r["action"] == "accept_regression" && r["run_id"] == "r"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_endpoints_wait_for_the_index_but_health_does_not() {
    let ts = TestServer::start(|_| {}).await;
    ts.app().ready.store(false, Ordering::SeqCst);
    let resp = ts.get("/v1/runs", &ts.admin).await;
    assert_eq!(resp.headers()["retry-after"], "1");
    assert_eq!(
        code(resp).await,
        (StatusCode::SERVICE_UNAVAILABLE, "starting".into())
    );
    assert_eq!(ts.get("/v1/info", &ts.admin).await.status(), StatusCode::OK);
    let health = ts
        .client
        .get(format!("{}/healthz", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let ready = ts
        .client
        .get(format!("{}/readyz", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(code(ready).await.1, "starting");
    ts.app().ready.store(true, Ordering::SeqCst);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_server_on_the_same_data_exits() {
    let ts = TestServer::start(|_| {}).await;
    let err = server::start(ts.config.clone(), [0; 32], Hooks::stubs(&ts.config))
        .await
        .err()
        .unwrap();
    assert!(err.0.contains("server.lock"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_rules_are_enforced() {
    let dir = Arc::new(TempDir::new("rules"));
    let base = test_config(dir.path());
    pragmatic_server::keys::ServerKey::generate()
        .unwrap()
        .write_new(&base.keys.signing_key_file)
        .unwrap();
    let start = |c: Config| async move {
        server::start(c.clone(), [0; 32], Hooks::stubs(&c))
            .await
            .err()
    };
    let mut c = base.clone();
    c.listen = "0.0.0.0:0".into();
    assert!(start(c).await.unwrap().0.contains("loopback"));
    let mut c = base.clone();
    c.anchoring.allow_self_anchoring = false;
    assert!(start(c).await.unwrap().0.contains("independent witness"));
    let mut c = base.clone();
    c.keys.signing_key_file = c.data_dir.join("server.ed25519");
    assert!(start(c).await.unwrap().0.contains("inside data_dir"));
    let mut c = base.clone();
    c.keys.signing_key_file = dir.path().join("missing.ed25519");
    assert!(start(c).await.unwrap().0.contains("keygen"));
    // An unknown data format is refused.
    std::fs::create_dir_all(&base.data_dir).unwrap();
    std::fs::write(base.data_dir.join("FORMAT"), r#"{"data_format": 7}"#).unwrap();
    assert!(start(base.clone())
        .await
        .unwrap()
        .0
        .contains("data format 7"));
}
