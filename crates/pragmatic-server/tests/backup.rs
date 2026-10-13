//! A backup and restore drill (design 4.13 and 9): a backup taken live,
//! erasures, deletions and anchors after it, a disaster, and a restore
//! that re-applies the erasure ledger and detects regressed runs.

mod common;

use std::sync::Arc;

use common::*;
use pragmatic::encoding::hex_encode;
use pragmatic::sha256::sha256;
use pragmatic::SlotState;
use pragmatic_server::config::{RetentionMatch, RetentionPolicy};
use pragmatic_server::hooks::{BatchReason, NoAnchoring};
use pragmatic_server::keys::ServerKey;
use pragmatic_server::ops::{self, Manifest, ManifestSignature};
use reqwest::StatusCode;
use serde_json::{json, Value};

async fn finished_n(ts: &TestServer, token: &str, run: &str, n: usize) -> Writer {
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
    finished_n(&ts, &agent, "keep", 2).await;
    finished_n(&ts, &agent, "later", 3).await;
    finished_n(&ts, &agent, "doomed", 1).await;
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
    // The 4 restored entries, and the custody note of the lease that was
    // live when the backup was taken, which the restore ended.
    assert_eq!(s["entries"], 5);
    let grow = stored(&ts2, "grow");
    let custody = grow.get(4).unwrap();
    assert_eq!(custody.event.note_kind(), Some("custody"));
    if let pragmatic::Event::Note { data, .. } = &custody.event {
        let d: Value = serde_json::from_str(data).unwrap();
        assert_eq!(d["end"], "restored");
        assert_eq!(d["to_entries"], 4);
    }
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
    finished_n(&ts, &agent, "r", 1).await;
    let dir = TempDir::new("backup2");
    let target = dir.path().join("b");
    let config = ts.config.clone();
    let t = target.clone();
    tokio::task::spawn_blocking(move || ops::backup(&config, &t))
        .await
        .unwrap()
        .unwrap();
    let trusted = ops::trusted_keys(&ts.config, &[]).unwrap();
    assert!(ops::verify_backup(&target, &trusted).is_ok());

    // While the server runs, its directory is locked.
    let cfg = ts.config.clone();
    let t = target.clone();
    let err = tokio::task::spawn_blocking(move || {
        ops::restore(&cfg, &t, None, &pragmatic_server::hooks::NoAnchoring)
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
        ops::restore(&cfg, &t, None, &pragmatic_server::hooks::NoAnchoring)
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
    assert!(ops::verify_backup(&target, &trusted)
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
    assert!(ops::verify_backup(&target, &trusted)
        .unwrap_err()
        .contains("signature"));
}

/// Restore a backup into `<dir>/<name>` with `ledger`, trusting the
/// configured key (and `extra`).
async fn restore_into(
    ts: &TestServer,
    from: &std::path::Path,
    name: &str,
    ledger: Option<std::path::PathBuf>,
    extra: Vec<String>,
) -> (pragmatic_server::config::Config, Result<Value, String>) {
    let mut config = ts.config.clone();
    config.data_dir = ts.dir.path().join(name);
    let (cfg, from) = (config.clone(), from.to_path_buf());
    let result = tokio::task::spawn_blocking(move || {
        ops::restore_trusting(&cfg, &from, ledger.as_deref(), &NoAnchoring, &extra)
    })
    .await
    .unwrap();
    (config, result)
}

/// Erasures, deletions and holds made while a live backup runs are applied
/// again by a restore: the backup records the ledger's position from
/// before it copied any journal. (A FIFO in `anchors/` pauses the backup
/// right after it copied every journal.)
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changes_made_while_a_backup_runs_are_applied_by_restore() {
    let mut ts = TestServer::start(|c| {
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
    finished(&ts, &agent, "subject", &["alice@example.com, card 4111"]).await;
    finished(&ts, &agent, "doomed", &["to be deleted"]).await;
    finished(&ts, &agent, "case-1", &["evidence"]).await;
    ts.app().store.flush_meta(true);
    let anchors = ts.data_dir().join("anchors");
    std::fs::create_dir_all(&anchors).unwrap();
    let fifo = anchors.join("pause.fifo");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let backups = TempDir::new("race-backup");
    let target = backups.path().join("b");
    let (config, t) = (ts.config.clone(), target.clone());
    let backup = tokio::task::spawn_blocking(move || ops::backup(&config, &t));
    // Opening the FIFO for writing returns once the backup opened it for
    // reading: every journal has been copied.
    let f = fifo.clone();
    let hold_open = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new().write(true).open(f).unwrap()
    })
    .await
    .unwrap();
    let resp = ts
        .post_json(
            &run_path("subject", "/erase"),
            &ts.admin,
            json!({"slots": [[2, 0]], "reason_code": "dsar"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
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
    let resp = ts
        .post_json(
            "/v1/holds",
            &ts.admin,
            json!({"matter": "case-42", "scope": {"prefix": "case-"}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    drop(hold_open);
    backup.await.unwrap().unwrap();
    ts.stop().await;
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(target.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.ledger_seq, 0, "the position before any journal");
    // Without the off-host ledger (the backup's own ledger has the records
    // too), and with it: both apply them, neither twice.
    let offhost = backups.path().join("offhost.jsonl");
    std::fs::copy(ts.data_dir().join("erasure-ledger.jsonl"), &offhost).unwrap();
    for (name, ledger) in [("restored-own", None), ("restored-offhost", Some(offhost))] {
        let (config, report) = restore_into(&ts, &target, name, ledger, vec![]).await;
        let report = report.unwrap();
        assert_eq!(report["ledger_records_applied"], 3, "{name}: {report}");
        let subject = pragmatic::Journal::parse(
            &std::fs::read(run_file_in(&config.data_dir, "subject", ".journal")).unwrap(),
            None,
        )
        .unwrap()
        .journal;
        assert_eq!(
            subject.get(2).unwrap().slots[0].state,
            SlotState::Erased,
            "{name}"
        );
        assert!(
            !run_file_in(&config.data_dir, "doomed", ".journal").exists(),
            "{name}"
        );
        let holds: Value =
            serde_json::from_slice(&std::fs::read(config.data_dir.join("holds.json")).unwrap())
                .unwrap();
        assert_eq!(holds["holds"].as_array().unwrap().len(), 1, "{name}");
        let ledger =
            pragmatic_server::ledger::read(&config.data_dir.join("erasure-ledger.jsonl")).unwrap();
        assert_eq!(ledger.len(), 3, "{name}: no record is written twice");
    }
}

/// Holds placed after a backup are placed again by a restore with the
/// off-host ledger, so retention cannot delete what a hold protects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn holds_placed_after_a_backup_survive_a_restore() {
    let mut ts = TestServer::start(|c| {
        c.retention.push(RetentionPolicy {
            matcher: RetentionMatch {
                prefix: "case-".into(),
                labels: Default::default(),
            },
            delete_after_days: 1,
            ..RetentionPolicy::default()
        });
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "case-1", &["evidence"]).await;
    finished(&ts, &agent, "case-2", &["evidence"]).await;
    ts.app().store.flush_meta(true);
    let dir = TempDir::new("holdrestore");
    let target = dir.path().join("b");
    let (cfg, t) = (ts.config.clone(), target.clone());
    tokio::task::spawn_blocking(move || ops::backup(&cfg, &t))
        .await
        .unwrap()
        .unwrap();
    let resp = ts
        .post_json(
            "/v1/holds",
            &ts.admin,
            json!({"matter": "case-42", "scope": {"prefix": "case-"}}),
        )
        .await;
    let placed: Value = resp.json().await.unwrap();
    // And one placed and removed again: it stays removed.
    let resp = ts
        .post_json(
            "/v1/holds",
            &ts.admin,
            json!({"matter": "brief", "scope": {"run_ids": ["case-2"]}}),
        )
        .await;
    let brief: Value = resp.json().await.unwrap();
    let id = brief["id"].as_str().unwrap();
    let resp = ts
        .req(
            reqwest::Method::DELETE,
            &format!("/v1/holds/{id}"),
            &ts.admin,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    ts.stop().await;
    let offhost = dir.path().join("offhost.jsonl");
    std::fs::copy(ts.data_dir().join("erasure-ledger.jsonl"), &offhost).unwrap();
    let (restored, report) = restore_into(&ts, &target, "restored", Some(offhost), vec![]).await;
    let report = report.unwrap();
    assert_eq!(report["holds_placed_again"], 2, "{report}");
    assert_eq!(report["holds_removed_again"], 1);
    let ts2 = TestServer::boot(ts.dir.clone(), restored, None).await;
    let holds: Value = ts2.get("/v1/holds", &ts2.admin).await.json().await.unwrap();
    assert_eq!(holds["holds"], json!([placed]));
    for run in ["case-1", "case-2"] {
        let r = ts2.app().store.get(run).unwrap();
        r.lock().meta.updated_at = pragmatic_server::timefmt::rfc3339(0);
    }
    let rep: Value = ts2
        .post_json("/v1/retention/run", &ts2.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rep["deleted"], json!([]), "{rep}");
    assert_eq!(rep["skipped_held"], json!(["case-1", "case-2"]));
}

/// Re-sign a backup's manifest with `key` after changing its files.
fn resign(target: &std::path::Path, key: &ServerKey) {
    let mpath = target.join("manifest.json");
    let mut m: Manifest = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
    for f in &mut m.files {
        let b = std::fs::read(target.join(&f.path)).unwrap();
        f.bytes = b.len() as u64;
        f.sha256 = hex_encode(&sha256(&b));
    }
    m.signature = None;
    let canon = pragmatic::json::parse(&serde_json::to_string(&m).unwrap())
        .unwrap()
        .canonical_string();
    let digest = sha256(canon.as_bytes());
    m.signature = Some(ManifestSignature {
        key_id: key.key_id(),
        public_key: hex_encode(&key.public_key()),
        value: hex_encode(&key.sign(&digest)),
    });
    std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
}

/// Whoever can write the backup can write its key ring, so a backup is
/// trusted only when signed by a key from outside it: the configured
/// signing key, a key it replaced, or one named with `--trust-key`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backup_signed_by_a_key_from_inside_the_backup_is_refused() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "victim", &["one"]).await;
    let (auditor, _) = ts.issue("auditor", &["*"], true).await;
    assert_eq!(
        ts.get(&run_path("victim", "/journal"), &auditor)
            .await
            .status(),
        StatusCode::OK
    );
    ts.app().access.flush().await.unwrap();
    ts.stop().await;
    let dir = TempDir::new("forge");
    let attacker = ServerKey::generate().unwrap();
    for (n, replace_ring) in [(0, true), (1, false)] {
        let target = dir.path().join(format!("b{n}"));
        ops::backup(&ts.config, &target).unwrap();
        // An admin token the attacker knows, a log without the raw read...
        let tokens_path = target.join("tokens.json");
        let mut toks: Value =
            serde_json::from_slice(&std::fs::read(&tokens_path).unwrap()).unwrap();
        toks["tokens"].as_array_mut().unwrap().push(json!({
            "id": "tok_attacker", "name": "x", "principal": "x", "role": "admin",
            "scopes": ["*"], "view_raw": true, "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null, "revoked_at": null,
            "sha256": pragmatic_server::tokens::token_sha256("prag_attacker"),
        }));
        std::fs::write(&tokens_path, serde_json::to_vec(&toks).unwrap()).unwrap();
        // ...the attacker's key in the ring (replacing it, or added)...
        let ring_path = target.join("keys.json");
        let mut ring: Value = serde_json::from_slice(&std::fs::read(&ring_path).unwrap()).unwrap();
        let entry = json!({
            "key_id": attacker.key_id(),
            "public_key": hex_encode(&attacker.public_key()),
            "not_before": "2026-01-01T00:00:00Z", "not_after": null,
        });
        if replace_ring {
            ring["keys"] = json!([entry]);
        } else {
            ring["keys"].as_array_mut().unwrap().push(entry);
        }
        std::fs::write(&ring_path, serde_json::to_vec(&ring).unwrap()).unwrap();
        // ...and the manifest re-signed with it.
        resign(&target, &attacker);
        let trusted = ops::trusted_keys(&ts.config, &[]).unwrap();
        let err = ops::verify_backup(&target, &trusted).unwrap_err();
        assert!(err.contains("--trust-key"), "{err}");
        let (_, result) = restore_into(&ts, &target, &format!("r{n}"), None, vec![]).await;
        assert!(result.unwrap_err().contains("--trust-key"));
    }
    // A key named on the command line is trusted: an operator restoring a
    // backup signed by a key this host never had.
    let target = dir.path().join("b0");
    let (_, result) = restore_into(
        &ts,
        &target,
        "trusted",
        None,
        vec![hex_encode(&attacker.public_key())],
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
}
