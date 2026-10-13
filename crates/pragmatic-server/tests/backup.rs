//! A backup and restore drill (design 4.13 and 9): a backup taken live,
//! erasures, deletions and anchors after it, a disaster, and a restore
//! that re-applies the erasure ledger and detects regressed runs.

mod common;

use std::sync::Arc;

use common::*;
use pragmatic::SlotState;
use pragmatic_server::config::{RetentionMatch, RetentionPolicy};
use pragmatic_server::hooks::BatchReason;
use pragmatic_server::ops;
use reqwest::StatusCode;
use serde_json::{json, Value};

async fn finished(ts: &TestServer, token: &str, run: &str, n: usize) -> Writer {
    let mut w = Writer::create(ts, token, run).await;
    w.attempt(ts, n).await;
    assert_eq!(w.release(ts).await.status(), StatusCode::NO_CONTENT);
    w
}

fn anchor(ts: &TestServer) {
    ts.app().anchor_batch(BatchReason::Interval).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_and_restore_with_erasure_reapplication_and_regression_detection() {
    let mut ts = TestServer::start_anchored(|c| {
        c.lease_ttl_secs = 60;
        c.retention.push(RetentionPolicy {
            matcher: RetentionMatch {
                prefix: "doomed".into(),
                labels: Default::default(),
            },
            delete_after_days: 1,
            ..RetentionPolicy::default()
        });
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "keep", 2).await;
    finished(&ts, &agent, "later", 3).await;
    finished(&ts, &agent, "doomed", 1).await;
    let mut grow = Writer::create(&ts, &agent, "grow").await;
    grow.attempt(&ts, 1).await;
    anchor(&ts);
    let anchored: Value = ts
        .get(&run_path("grow", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(anchored["anchored_entries"], 4);

    // A live backup. It copies each journal up to the length its meta.json
    // records, which lags appends by up to a second; flush so the test
    // knows exactly what it copies.
    ts.app().store.flush_meta(true);
    let backup_dir = TempDir::new("backup");
    let target = backup_dir.path().join("b1");
    let config = ts.config.clone();
    let report = tokio::task::spawn_blocking(move || ops::backup(&config, &target))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.runs, 4);

    // After the backup: an erasure, more anchored appends, a deletion.
    let resp = ts
        .post_json(
            &run_path("later", "/erase"),
            &ts.admin,
            json!({"slots": [[3, 0]], "reason_code": "dsar"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    grow.add(recv("written after the backup"));
    grow.add(recv("and anchored"));
    assert_eq!(grow.push(&ts).await.status(), StatusCode::OK);
    anchor(&ts);
    {
        let r = ts.app().store.get("doomed").unwrap();
        r.lock().meta.updated_at = pragmatic_server::timefmt::rfc3339(0);
    }
    let rep: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rep["deleted"], json!(["doomed"]));
    ts.stop().await;

    // The ledger was streamed off the host; the host is lost.
    let offhost = backup_dir.path().join("offhost-ledger.jsonl");
    std::fs::copy(ts.data_dir().join("erasure-ledger.jsonl"), &offhost).unwrap();
    let anchoring = ts.anchoring.clone().unwrap();
    let mut restored = ts.config.clone();
    restored.data_dir = ts.dir.path().join("restored");
    let (cfg, from, ledger, a) = (
        restored.clone(),
        backup_dir.path().join("b1"),
        offhost.clone(),
        anchoring.clone(),
    );
    let report =
        tokio::task::spawn_blocking(move || ops::restore(&cfg, &from, Some(&ledger), a.as_ref()))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(report["ledger_records_applied"], 2, "{report}");
    assert_eq!(report["slots_erased_again"], 1);
    assert_eq!(report["runs_deleted_again"], json!(["doomed"]));
    assert_eq!(report["regressed"], json!(["grow"]));

    let ts2 = TestServer::boot(ts.dir.clone(), restored, Some(anchoring)).await;
    // The erasure that happened after the backup holds again.
    let later = stored(&ts2, "later");
    assert_eq!(later.get(3).unwrap().slots[0].state, SlotState::Erased);
    assert!(later.audit().is_ok());
    let kinds: Vec<&str> = later
        .entries()
        .iter()
        .filter_map(|e| e.event.note_kind())
        .collect();
    assert_eq!(kinds.last(), Some(&"erasure"));
    // The deletion holds again.
    assert_eq!(
        ts2.get(&run_path("doomed", ""), &ts2.admin).await.status(),
        StatusCode::GONE
    );
    // The run that lost anchored entries is regressed.
    let s: Value = ts2
        .get(&run_path("grow", ""), &ts2.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["status"], "regressed", "{s}");
    assert_eq!(s["entries"], 4);
    let s: Value = ts2
        .get(&run_path("keep", ""), &ts2.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["status"], "idle");
    assert_eq!(s["verify"]["ok"], true);
    // The restore is in the access log.
    let records = ts2.audit().await;
    let done = records
        .iter()
        .find(|r| r["kind"] == "restore" && r["phase"] == "done")
        .unwrap();
    assert_eq!(done["regressed"], json!(["grow"]));
    // The restored ledger has the re-applied records too.
    let ledger =
        pragmatic_server::ledger::read(&ts2.data_dir().join("erasure-ledger.jsonl")).unwrap();
    assert_eq!(ledger.len(), 2);
    let _ = Arc::strong_count(&ts2.dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restore_refuses_tampered_backups_running_servers_and_full_directories() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", 1).await;
    let dir = TempDir::new("backup2");
    let target = dir.path().join("b");
    let config = ts.config.clone();
    let t = target.clone();
    tokio::task::spawn_blocking(move || ops::backup(&config, &t))
        .await
        .unwrap()
        .unwrap();
    assert!(ops::verify_backup(&target).is_ok());

    // While the server runs, its directory is locked.
    let cfg = ts.config.clone();
    let t = target.clone();
    let err = tokio::task::spawn_blocking(move || {
        ops::restore(
            &cfg,
            &t,
            None,
            &pragmatic_server::hooks::NoAnchoring::default(),
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        err.contains("server.lock") || err.contains("not empty"),
        "{err}"
    );
    ts.stop().await;

    // A restore needs an empty directory.
    let cfg = ts.config.clone();
    let t = target.clone();
    let err = tokio::task::spawn_blocking(move || {
        ops::restore(
            &cfg,
            &t,
            None,
            &pragmatic_server::hooks::NoAnchoring::default(),
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(err.contains("not empty"), "{err}");

    // A changed file fails its hash; a changed manifest fails its signature.
    let stem = pragmatic_server::layout::stem("r");
    let journal = target
        .join("runs")
        .join(&stem[..2])
        .join(format!("{stem}.journal"));
    let mut bytes = std::fs::read(&journal).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&journal, &bytes).unwrap();
    assert!(ops::verify_backup(&target)
        .unwrap_err()
        .contains("does not match"));
    bytes[last] ^= 1;
    std::fs::write(&journal, &bytes).unwrap();
    let manifest = target.join("manifest.json");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(
        &manifest,
        text.replace("\"ledger_seq\": 0", "\"ledger_seq\": 9"),
    )
    .unwrap();
    assert!(ops::verify_backup(&target)
        .unwrap_err()
        .contains("signature"));
}
