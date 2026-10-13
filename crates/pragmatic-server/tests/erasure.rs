//! Erasure, holds, retention, tombstones and the subjects index (design
//! 4.9).

mod common;

use common::*;
use pragmatic::journal::ROOT;
use pragmatic::{Content, Event, SlotState};
use pragmatic_server::config::{ErasurePolicy, RetentionMatch, RetentionPolicy};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

async fn erase(ts: &TestServer, run: &str, body: Value) -> (StatusCode, Value) {
    let resp = ts
        .post_json(&run_path(run, "/erase"), &ts.admin, body)
        .await;
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// A finished run with its lease released.
async fn finished(ts: &TestServer, token: &str, run: &str, messages: &[&str]) -> Writer {
    let mut w = Writer::create(ts, token, run).await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    for m in messages {
        w.add(recv(m));
    }
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(ts).await.status(), StatusCode::NO_CONTENT);
    w
}

fn erasure_notes(ts: &TestServer, run: &str) -> Vec<Value> {
    stored(ts, run)
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            Event::Note { kind, data, .. } if kind == "erasure" => {
                Some(serde_json::from_str(data).unwrap())
            }
            _ => None,
        })
        .collect()
}

fn policy(prefix: &str, min: u64, shred: u64, delete: u64, deny: bool) -> RetentionPolicy {
    RetentionPolicy {
        matcher: RetentionMatch {
            prefix: prefix.into(),
            labels: Default::default(),
        },
        retain_min_days: min,
        shred_after_days: shred,
        delete_after_days: delete,
        erasure: if deny {
            ErasurePolicy::DenyDuringMin
        } else {
            ErasurePolicy::Allow
        },
    }
}

/// Pretend the run was last updated `days` ago.
fn age(ts: &TestServer, run: &str, days: f64) {
    let r = ts.app().store.get(run).unwrap();
    let when = pragmatic_server::timefmt::now_unix_secs() - (days * 86_400.0) as i64;
    r.lock().meta.updated_at = pragmatic_server::timefmt::rfc3339(when);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erasure_writes_the_note_ledger_and_access_record() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(
        &ts,
        &agent,
        "r",
        &["keep", "jane@example.com said hi", "keep too"],
    )
    .await;
    let (status, body) = erase(
        &ts,
        "r",
        json!({"slots": [[3, 0]], "reason_code": "dsar", "reason": "ticket 42"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["erased"], json!([[3, 0]]));
    assert_eq!(body["can_resume"], true);
    let j = stored(&ts, "r");
    assert_eq!(j.get(3).unwrap().slots[0].state, SlotState::Erased);
    assert!(j.audit().is_ok());
    let notes = erasure_notes(&ts, "r");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["by"], "bootstrap");
    assert_eq!(notes[0]["authenticated"], true);
    assert_eq!(notes[0]["reason_code"], "dsar");
    // The note points at the durable intent record in the access log.
    let cursor = notes[0]["access_log_cursor"].as_u64().unwrap();
    let records = ts.audit().await;
    let intent = records.iter().find(|r| r["cursor"] == cursor).unwrap();
    assert_eq!(intent["kind"], "intent");
    assert_eq!(intent["action"], "erase");
    assert_eq!(intent["run_id"], "r");
    // And the ledger has it.
    let ledger =
        pragmatic_server::ledger::read(&ts.data_dir().join("erasure-ledger.jsonl")).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].slots, vec![(3, 0)]);
    assert_eq!(ledger[0].access_log_cursor, Some(cursor));
    // The entries view shows the slot erased, for every viewer.
    let v: Value = ts
        .get(&run_path("r", "/entries"), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["entries"][3]["slots"][0]["state"], "erased");
    assert!(v["entries"][3]["slots"][0]["text"].is_null());
    let summary: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(summary["erased_slots"], 1);
    assert_eq!(summary["verify"]["ok"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn match_mode_erases_every_copy_including_refs() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let big = format!("my phone is 555-0100 {}", "padding ".repeat(40));
    let mut w = finished(&ts, &agent, "r", &[&big, "other", &big]).await;
    let j = stored(&ts, "r");
    assert_eq!(j.get(4).unwrap().slots[0].state, SlotState::Ref);
    let (status, body) = erase(
        &ts,
        "r",
        json!({"match": "555-0100", "reason_code": "dsar"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["erased"],
        json!([[2, 0]]),
        "one erasure through the dedup target"
    );
    let j = stored(&ts, "r");
    assert!(!j.get(4).unwrap().event.slot_contents()[0].is_sealed());
    let bytes = j.to_bytes();
    assert!(!bytes.windows(8).any(|x| x == b"555-0100"));
    // The client's copy is stale now: its next append conflicts.
    w.journal = j;
    let _ = w;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_lease_blocks_erasure_unless_forced() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    let (status, body) = erase(&ts, "r", json!({"slots": [[2, 0]], "reason_code": "dsar"})).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("run_locked"))
    );
    let (status, body) = erase(
        &ts,
        "r",
        json!({"slots": [[2, 0]], "reason_code": "dsar", "force": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The custody note of the revoked lease comes before the erasure note.
    let j = stored(&ts, "r");
    let kinds: Vec<&str> = j
        .entries()
        .iter()
        .filter_map(|e| e.event.note_kind())
        .collect();
    assert_eq!(&kinds[kinds.len() - 2..], ["custody", "erasure"]);
    w.add(recv("after"));
    assert_eq!(code(w.push(&ts).await).await.1, "lease_lost");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unfinished_runs_need_allow_unfinished() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(recv("half way"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let (status, body) = erase(&ts, "r", json!({"slots": [[2, 0]], "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["unfinished"], true);
    let (status, body) = erase(
        &ts,
        "r",
        json!({"slots": [[2, 0]], "reason_code": "dsar", "allow_unfinished": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["can_resume"], false);
    assert!(body["warning"]
        .as_str()
        .unwrap()
        .contains("no longer be resumed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_cannot_supply_by_or_malformed_requests() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["x"]).await;
    for body in [
        json!({"slots": [[2, 0]], "reason_code": "dsar", "by": "someone-else"}),
        json!({"slots": [[2, 0]], "match": "x", "reason_code": "dsar"}),
        json!({"reason_code": "dsar"}),
        json!({"slots": [[2, 0]], "reason_code": "Not Valid"}),
        json!({"slots": "some", "reason_code": "dsar"}),
    ] {
        let (status, _) = erase(&ts, "r", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // Duplicate keys are not strict JSON.
    let resp = ts
        .req(Method::POST, &run_path("r", "/erase"), &ts.admin)
        .body(r#"{"slots":"all","reason_code":"a","reason_code":"b"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn holds_block_erasure_and_cover_runs_created_later() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let resp = ts
        .post_json(
            "/v1/holds",
            &ts.admin,
            json!({"matter": "case-7", "scope": {"prefix": "eu:"}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let hold: Value = resp.json().await.unwrap();
    // Created after the hold, under its prefix: held.
    finished(&ts, &agent, "eu:1", &["x"]).await;
    let summary: Value = ts
        .get(&run_path("eu:1", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(summary["holds"], json!([hold["id"]]));
    let (status, body) = erase(&ts, "eu:1", json!({"slots": "all", "reason_code": "dsar"})).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("on_hold"))
    );
    let resp = ts
        .req(
            Method::DELETE,
            &format!("/v1/holds/{}", hold["id"].as_str().unwrap()),
            &ts.admin,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, _) = erase(&ts, "eu:1", json!({"slots": "all", "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = ts.get("/v1/holds", &ts.admin).await.json().await.unwrap();
    assert_eq!(v["holds"], json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_during_min_refuses_with_retain_until_and_logs_the_obligation() {
    let ts = TestServer::start(|c| c.retention.push(policy("", 30, 0, 0, true))).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["x"]).await;
    let (status, body) = erase(&ts, "r", json!({"slots": "all", "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "retention_locked");
    assert!(body["error"]["retain_until"].is_string());
    let records = ts.audit().await;
    assert!(records.iter().any(|r| r["route"] == "/v1/runs/{id}/erase"
        && r["reason"] == "legal_obligation"
        && r["status"] == 409));
    age(&ts, "r", 31.0);
    let (status, _) = erase(&ts, "r", json!({"slots": "all", "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_shreds_deletes_and_skips_held_and_leased_runs() {
    let ts = TestServer::start(|c| {
        c.lease_ttl_secs = 60;
        c.retention.push(policy("", 1, 2, 4, false));
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    for run in ["fresh", "old", "ancient", "held", "busy-old"] {
        finished(&ts, &agent, run, &["personal content"]).await;
    }
    // A run that is being written right now.
    let busy = Writer::create(&ts, &agent, "busy").await;
    age(&ts, "old", 3.0);
    age(&ts, "ancient", 5.0);
    age(&ts, "held", 5.0);
    age(&ts, "busy", 5.0);
    ts.post_json(
        "/v1/holds",
        &ts.admin,
        json!({"matter": "m", "scope": {"run_ids": ["held"]}}),
    )
    .await;
    let report: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["shredded"], json!(["old"]), "{report}");
    assert_eq!(report["deleted"], json!(["ancient"]));
    assert_eq!(report["skipped_held"], json!(["held"]));
    assert_eq!(report["skipped_leased"], json!(["busy"]));
    // Shredded: every content slot erased, reason retention.
    let j = stored(&ts, "old");
    assert!(j
        .entries()
        .iter()
        .all(|e| e.slots.iter().all(|s| s.state != SlotState::Sealed)));
    assert_eq!(erasure_notes(&ts, "old")[0]["reason_code"], "retention");
    // A second run shreds nothing more.
    let report: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["shredded"], json!([]));
    // Deleted: tombstoned, 410 everywhere, never recreated.
    let (status, c) = code(ts.get(&run_path("ancient", ""), &ts.admin).await).await;
    assert_eq!((status, c.as_str()), (StatusCode::GONE, "run_deleted"));
    let resp = ts
        .req(Method::PUT, &run_path("ancient", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(code(resp).await.1, "run_deleted");
    let resp = send_frames(
        &ts,
        &agent,
        "ancient",
        "x",
        0,
        1,
        &"0".repeat(64),
        vec![0; 40],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::GONE);
    let stem = pragmatic_server::layout::stem("ancient");
    let tomb = ts
        .data_dir()
        .join("runs")
        .join(&stem[..2])
        .join(format!("{stem}.tombstone.json"));
    let t: Value = serde_json::from_slice(&std::fs::read(tomb).unwrap()).unwrap();
    assert_eq!(t["run_id"], "ancient");
    assert_eq!(t["policy"]["delete_after_days"], 4);
    // Tombstones survive restarts.
    let ts = ts.restart().await;
    assert_eq!(
        ts.get(&run_path("ancient", ""), &ts.admin).await.status(),
        StatusCode::GONE
    );
    let v: Value = ts.get("/v1/runs", &ts.admin).await.json().await.unwrap();
    assert!(!v.to_string().contains("ancient"));
    let ledger =
        pragmatic_server::ledger::read(&ts.data_dir().join("erasure-ledger.jsonl")).unwrap();
    let kinds: Vec<String> = ledger.iter().map(|r| format!("{:?}", r.kind)).collect();
    assert_eq!(kinds, ["Delete", "Shred"], "runs are visited in id order");
    drop(busy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_policies_never_shred_inside_a_minimum() {
    let ts = TestServer::start(|c| {
        c.retention.push(policy("", 10, 0, 0, false));
        c.retention.push(policy("x:", 0, 1, 0, false));
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "x:1", &["content"]).await;
    age(&ts, "x:1", 5.0);
    let report: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["shredded"], json!([]));
    age(&ts, "x:1", 11.0);
    let report: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["shredded"], json!(["x:1"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_subjects_index_finds_runs_until_the_subjects_are_erased() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer {
        run: "s".into(),
        token: agent.clone(),
        lease: String::new(),
        journal: pragmatic::Journal::new(None),
    };
    let created = Writer::create(&ts, &agent, "s").await;
    w.lease = created.lease;
    w.add(note(
        "run.start",
        json!({"run_id": "s", "labels": {}}),
        vec![Content::from(r#"{"subjects":["customer-981"]}"#)],
    ));
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let body = json!({"subject": "customer-981"});
    let v: Value = ts
        .post_json("/v1/subjects/search", &ts.admin, body.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["run_ids"], json!(["s"]));
    // The identifier is never logged.
    assert!(!serde_json::to_string(&ts.audit().await)
        .unwrap()
        .contains("customer-981"));
    let (status, _) = erase(&ts, "s", json!({"slots": [[0, 0]], "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = ts
        .post_json("/v1/subjects/search", &ts.admin, body)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["run_ids"], json!([]));
    let _ = ROOT;
}
