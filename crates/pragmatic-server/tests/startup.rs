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
async fn a_stale_or_missing_meta_is_rebuilt_from_the_journal() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    for run in ["stale", "no-meta"] {
        Writer::create(&ts, &agent, run).await.attempt(&ts, 2).await;
    }
    ts.stop().await;
    // Meta from before the last appends (meta.json lags by up to a
    // second): the first two entries, as they were then.
    let j = stored(&ts, "stale");
    let mut m = read_meta(&ts, "stale");
    m.entries = 2;
    m.byte_len = (pragmatic::journal::HEADER_LEN
        + j.frame_bytes(0).unwrap().len()
        + j.frame_bytes(1).unwrap().len()) as u64;
    m.head = pragmatic::encoding::hex_encode(&j.get(1).unwrap().hash);
    m.summary.labels.insert("bogus".into(), "1".into());
    write_meta(&ts, "stale", &m);
    std::fs::remove_file(run_file(&ts, "no-meta", ".meta.json")).unwrap();
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    for run in ["stale", "no-meta"] {
        let s = summary(&ts, run).await;
        assert_eq!(s["entries"], 5, "{run}: {s}");
        assert_eq!(s["last_outcome"], "ok", "{run}");
        assert_eq!(s["labels"], json!({}), "{run}");
        let head = pragmatic::encoding::hex_encode(&stored(&ts, run).head());
        assert_eq!(s["head"], head, "{run}");
    }
    assert!(run_file(&ts, "no-meta", ".meta.json").exists());
}

/// A journal that no longer holds what its meta recorded (fewer entries
/// than were acknowledged, or another hash where the last acknowledged
/// entry was) lost or rewrote history: it is damaged, never accepted, and
/// its meta is kept as evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_journal_that_lost_or_rewrote_acknowledged_history_is_damaged() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    for run in ["short", "wrong-head"] {
        let mut w = Writer::create(&ts, &agent, run).await;
        w.attempt(&ts, 3).await;
        assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    }
    ts.stop().await;
    // Drop the last three committed frames (whole frames: no torn tail).
    let path = run_file(&ts, "short", ".journal");
    let bytes = std::fs::read(&path).unwrap();
    let frames =
        pragmatic::journal::split_frames(&bytes[pragmatic::journal::HEADER_LEN..]).unwrap();
    let keep: usize =
        pragmatic::journal::HEADER_LEN + frames[..4].iter().map(|f| f.len()).sum::<usize>();
    std::fs::write(&path, &bytes[..keep]).unwrap();
    let short_meta = std::fs::read(run_file(&ts, "short", ".meta.json")).unwrap();
    // Same size, another head: what the index recorded is not in the file.
    let mut m = read_meta(&ts, "wrong-head");
    m.head = "00".repeat(32);
    write_meta(&ts, "wrong-head", &m);
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    for run in ["short", "wrong-head"] {
        let resp = ts
            .post_json(&run_path(run, "/lease"), &agent, json!({"holder": "h2"}))
            .await;
        assert_eq!(
            code(resp).await,
            (StatusCode::CONFLICT, "chain_broken".to_string()),
            "{run}"
        );
        let s = summary(&ts, run).await;
        assert_eq!(s["entries"], 7, "{run}: the recorded history is kept: {s}");
    }
    assert_eq!(
        std::fs::read(run_file(&ts, "short", ".meta.json")).unwrap(),
        short_meta
    );
    let metrics = reqwest::get(format!("{}/metrics", ts.url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("pragmatic_chain_broken_total 2"),
        "{metrics}"
    );
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
    pragmatic_server::keys::ServerKey::generate(&base.server_name())
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

/// True when this process can read a file it removed every permission
/// from (root can): permission tests then prove nothing.
fn permissions_bind(path: &std::path::Path) -> bool {
    std::fs::read(path).is_err()
}

/// A journal the index cannot read at startup (permissions, I/O errors)
/// is unavailable, not absent: the create flow (POST lease, then PUT on
/// `not_found`) never replaces it, and it loads on first use once it reads
/// again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_journal_is_unavailable_and_never_replaced() {
    use std::os::unix::fs::PermissionsExt;
    let mut ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one", "two", "three"]).await;
    let before = std::fs::read(run_file(&ts, "r", ".journal")).unwrap();
    let path = run_file(&ts, "r", ".journal");
    ts.stop().await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if !permissions_bind(&path) {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        eprintln!("skipped: permissions do not bind for this user");
        return;
    }
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    // While it cannot be read: 503, and PUT refuses to replace it.
    let lease_path = run_path("r", "/lease");
    let lease = || ts.post_json(&lease_path, &agent, json!({"holder": "h1"}));
    let (status, c) = code(lease().await).await;
    assert_eq!(
        (status, c.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
    );
    let resp = ts
        .req(reqwest::Method::PUT, &run_path("r", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!ts.app().store.run_ids().contains(&"r".to_string()));
    // Readable again: it loads on first use, history intact.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let resp = lease().await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["entries"], 7,
        "six entries and the custody note of the release"
    );
    let after = std::fs::read(&path).unwrap();
    assert_eq!(&after[..before.len()], before.as_slice());
}

/// A tombstone that cannot be read still deletes its id: 410, never a
/// fresh run under a deleted id.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_tombstone_still_deletes_its_id() {
    use std::os::unix::fs::PermissionsExt;
    let mut ts = TestServer::start(|c| {
        c.retention.push(pragmatic_server::config::RetentionPolicy {
            matcher: pragmatic_server::config::RetentionMatch {
                prefix: "old".into(),
                labels: Default::default(),
            },
            delete_after_days: 1,
            ..Default::default()
        })
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "old", &["x"]).await;
    {
        let r = ts.app().store.get("old").unwrap();
        r.lock().meta.updated_at = pragmatic_server::timefmt::rfc3339(0);
    }
    let rep: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rep["deleted"], json!(["old"]));
    ts.stop().await;
    let tomb = run_file(&ts, "old", ".tombstone.json");
    std::fs::set_permissions(&tomb, std::fs::Permissions::from_mode(0o000)).unwrap();
    if !permissions_bind(&tomb) {
        eprintln!("skipped: permissions do not bind for this user");
        return;
    }
    let ts = TestServer::boot(ts.dir.clone(), ts.config.clone(), None).await;
    let resp = ts
        .req(reqwest::Method::PUT, &run_path("old", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(resp).await,
        (StatusCode::GONE, "run_deleted".to_string())
    );
    assert_eq!(
        ts.get(&run_path("old", ""), &ts.admin).await.status(),
        StatusCode::GONE
    );
    std::fs::set_permissions(&tomb, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// Damage at the end of an acknowledged frame looks like a cut write, but
/// meta.json says the entry was acknowledged: the journal is damaged, and
/// never truncated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_never_truncates_acknowledged_entries_as_a_torn_tail() {
    let mut ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    ts.stop().await; // clean shutdown: meta.json says 4 entries
    let path = run_file(&ts, "r", ".journal");
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    bytes[n - 8..].fill(0);
    std::fs::write(&path, &bytes).unwrap();
    let ts = ts.restart().await;
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "never truncated");
    let resp = ts
        .post_json(&run_path("r", "/lease"), &agent, json!({"holder": "h2"}))
        .await;
    assert_eq!(
        code(resp).await,
        (StatusCode::CONFLICT, "chain_broken".to_string())
    );
    let moved = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".torn-"));
    assert!(!moved);
}
