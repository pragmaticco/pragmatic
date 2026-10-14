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
    // The hold placed earlier is a ledger record too (a restore places it
    // again); retention visits runs in id order.
    assert_eq!(kinds, ["HoldAdd", "Delete", "Shred"]);
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

/// A forced erasure that is refused (here: a cursor that does not exist)
/// changes nothing: the holder keeps its lease and no custody note is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_forced_erasure_leaves_the_lease_alone() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    let before = note_kinds(&stored(&ts, "r"));
    let (status, v) = erase(
        &ts,
        "r",
        json!({"slots": [[999, 0]], "reason_code": "dsar", "force": true}),
    )
    .await;
    assert_eq!(
        (status, v["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    assert_eq!(note_kinds(&stored(&ts, "r")), before);
    w.add(recv("the agent carries on"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    // A forced erasure that can proceed revokes the lease, and meta.json
    // says so at once.
    let (status, _) = erase(
        &ts,
        "r",
        json!({"slots": [[2, 0]], "reason_code": "dsar", "force": true, "allow_unfinished": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let meta: Value = serde_json::from_slice(
        &std::fs::read(run_file_in(&ts.data_dir(), "r", ".meta.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(meta["leases"], json!([]));
}

/// An erasure never waits for a download, and a download in flight never
/// serves bytes read after an erasure committed: it is aborted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_erasure_aborts_a_download_in_flight() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "big").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    for i in 0..24 {
        w.add(recv(&format!("{i:04}{}", "x".repeat(1 << 20))));
    }
    w.add(recv("SECRET-PERSONAL-DATA-0123456789"));
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let mut download = ts.get(&run_path("big", "/journal"), &ts.admin).await;
    assert_eq!(download.status(), StatusCode::OK);
    let total = download.content_length().unwrap();
    let mut got = download.chunk().await.unwrap().unwrap().to_vec();
    let erased = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        erase(
            &ts,
            "big",
            json!({"match": "SECRET-PERSONAL-DATA", "reason_code": "dsar"}),
        ),
    )
    .await
    .expect("the erasure does not wait for the download");
    assert_eq!(erased.0, StatusCode::OK);
    let mut aborted = false;
    loop {
        match download.chunk().await {
            Ok(Some(c)) => got.extend_from_slice(&c),
            Ok(None) => break,
            Err(_) => {
                aborted = true;
                break;
            }
        }
    }
    let served_secret = got
        .windows(b"SECRET-PERSONAL-DATA".len())
        .any(|x| x == b"SECRET-PERSONAL-DATA");
    assert!(!served_secret, "the download served erased content");
    assert!(
        aborted && (got.len() as u64) < total,
        "the download was not aborted"
    );
    // A download that starts afterwards serves the erased journal whole.
    let after = ts
        .get(&run_path("big", "/journal"), &ts.admin)
        .await
        .bytes()
        .await
        .unwrap();
    assert!(pragmatic::Journal::parse(&after, None).is_ok());
}

/// Content erased without an erasure note (someone with disk access) is
/// the tampering erasure accounting exists to catch: the run is damaged
/// (writes refused, `chain_broken` webhook and metric), and verify-data
/// names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_erased_without_a_note_is_damage_that_is_reported_and_named() {
    let (url, got) = webhook_receiver().await;
    let secrets = TempDir::new("erasure-hook");
    let hook = webhook(&secrets, &url, &["chain_broken"]);
    let mut ts = TestServer::start(move |c| c.webhooks.push(hook)).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "quiet", &["message 0", "message 1"]).await;
    ts.stop().await;
    let path = run_file_in(&ts.data_dir(), "quiet", ".journal");
    let j = pragmatic::Journal::parse(&std::fs::read(&path).unwrap(), None)
        .unwrap()
        .journal;
    let e = j
        .erase(
            &pragmatic::journal::EraseSelector::Slots(vec![(2, 0)]),
            &pragmatic::journal::ErasureNote::local("x", ""),
            1,
        )
        .unwrap();
    let frames =
        pragmatic::journal::split_frames(&e.file[pragmatic::journal::HEADER_LEN..]).unwrap();
    let keep: usize = pragmatic::journal::HEADER_LEN
        + frames[..frames.len() - 1]
            .iter()
            .map(|f| f.len())
            .sum::<usize>();
    std::fs::write(&path, &e.file[..keep]).unwrap();
    let ts = ts.restart().await;
    let report: Value = ts
        .post_json("/v1/verify-data", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["failing_run_ids"], json!(["quiet"]), "{report}");
    let summary: Value = ts
        .get(&run_path("quiet", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(summary["verify"]["unaccounted_erasures"], json!([[2, 0]]));
    assert_eq!(
        metric(&metrics(&ts).await, "pragmatic_chain_broken_total"),
        Some(1.0)
    );
    let event = got.wait_for("chain_broken").await.expect("a webhook");
    assert_eq!(event["run_id"], "quiet");
    let resp = ts
        .post_json(&run_path("quiet", "/lease"), &agent, json!({"holder": "h"}))
        .await;
    assert_eq!(
        code(resp).await,
        (StatusCode::CONFLICT, "chain_broken".into())
    );
}

/// Slots an erasure note lists that hold content again (a file restored
/// from somewhere else) are damage too, but erasing again repairs it, so
/// erasure stays allowed and clears the damage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_incomplete_erasure_is_reported_and_repaired_by_erasing_again() {
    let mut ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["message 0", "message 1"]).await;
    let original = std::fs::read(run_file_in(&ts.data_dir(), "r", ".journal")).unwrap();
    let (status, _) = erase(&ts, "r", json!({"slots": [[2, 0]], "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::OK);
    ts.stop().await;
    // Put the sealed frame of cursor 2 back: same chain hash, content back.
    let path = run_file_in(&ts.data_dir(), "r", ".journal");
    let erased = std::fs::read(&path).unwrap();
    let h = pragmatic::journal::HEADER_LEN;
    let old = pragmatic::journal::split_frames(&original[h..]).unwrap();
    let new = pragmatic::journal::split_frames(&erased[h..]).unwrap();
    let mut file = erased[..h].to_vec();
    for (i, f) in new.iter().enumerate() {
        file.extend_from_slice(if i == 2 { old[2] } else { f });
    }
    std::fs::write(&path, &file).unwrap();
    let ts = ts.restart().await;
    let report: Value = ts
        .post_json("/v1/verify-data", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(report["failing_run_ids"], json!(["r"]), "{report}");
    let resp = ts
        .post_json(&run_path("r", "/lease"), &agent, json!({"holder": "h"}))
        .await;
    assert_eq!(code(resp).await.1, "chain_broken");
    let (status, _) = erase(
        &ts,
        "r",
        json!({"slots": [[2, 0]], "reason_code": "repair"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let summary: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(summary["verify"]["ok"], true, "{summary}");
    let resp = ts
        .post_json(&run_path("r", "/lease"), &agent, json!({"holder": "h"}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A retention delete whose files cannot be removed is still a deletion:
/// once the tombstone is durable the run takes no more writes, and the
/// next start removes what is left. (macOS: the user-immutable flag makes
/// the unlink fail.)
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_whose_files_cannot_be_removed_still_deletes_the_run() {
    let ts = TestServer::start(|c| {
        c.lease_ttl_secs = 60;
        c.retention.push(policy("old", 0, 0, 1, false));
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let w = finished(&ts, &agent, "old", &["kept"]).await;
    age(&ts, "old", 2.0);
    let path = run_file_in(&ts.data_dir(), "old", ".journal");
    let flag = |f: &str| {
        assert!(std::process::Command::new("chflags")
            .arg(f)
            .arg(&path)
            .status()
            .unwrap()
            .success())
    };
    flag("uchg");
    let rep: Value = ts
        .post_json("/v1/retention/run", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    flag("nouchg");
    assert_eq!(rep["deleted"], json!(["old"]), "{rep}");
    assert_eq!(rep["errors"][0]["run_id"], "old");
    // Deleted: no lease, no append.
    let resp = ts
        .post_json(&run_path("old", "/lease"), &agent, json!({"holder": "h2"}))
        .await;
    assert_eq!(code(resp).await, (StatusCode::GONE, "run_deleted".into()));
    let resp = send_frames(
        &ts,
        &agent,
        "old",
        &w.lease,
        7,
        1,
        &"0".repeat(64),
        vec![0; 40],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::GONE);
    assert!(path.exists(), "the journal could not be removed yet");
    let ts = ts.restart().await;
    assert!(!path.exists(), "the next start removed it");
    assert_eq!(
        ts.get(&run_path("old", ""), &ts.admin).await.status(),
        StatusCode::GONE
    );
}

/// The ledger record is written before the erasure commits, so no
/// committed erasure lacks one: here the commit fails (the run's directory
/// refuses new files) after the record is durable, nothing is erased, and
/// the record only asks again for what the admin asked.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ledger_record_is_written_before_the_erasure_commits() {
    use std::os::unix::fs::PermissionsExt;
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["message 0"]).await;
    let journal = run_file_in(&ts.data_dir(), "r", ".journal");
    let dir = journal.parent().unwrap().to_path_buf();
    let before = std::fs::read(&journal).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let probe = dir.join("probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipped: permissions do not bind for this user");
        return;
    }
    let (status, _) = erase(&ts, "r", json!({"slots": [[2, 0]], "reason_code": "dsar"})).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        before,
        "nothing was erased"
    );
    let ledger =
        pragmatic_server::ledger::read(&ts.data_dir().join("erasure-ledger.jsonl")).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].slots, vec![(2, 0)]);
    // The admin's retry erases.
    let (status, _) = erase(&ts, "r", json!({"slots": [[2, 0]], "reason_code": "dsar"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        stored(&ts, "r").get(2).unwrap().slots[0].state,
        SlotState::Erased
    );
}

/// A data subject request erases by `match`, and a streamed model reply
/// holds the subject's email split across token deltas: the erasure
/// reaches the reply too, so nobody can join the deltas back afterwards
/// (design 1.1, 2.13).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_match_erasure_reaches_an_email_echoed_in_a_streamed_reply() {
    const EMAIL: &str = "jane.doe@example.com";
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "support:7").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    let request = json!({"model": "claude", "stream": true, "messages": [
        {"role": "user", "content": format!("I am Jane ({EMAIL}), refund my order")}]});
    let d = w.add(pragmatic::Event::DrawIntent {
        provenance: "anthropic".into(),
        parts: vec![pragmatic::Content::from(request.to_string())],
    });
    let mut body = String::new();
    for delta in [
        "Done! A confirmation went to ",
        "jane",
        ".doe",
        "@example",
        ".com",
        ".",
    ] {
        body.push_str("event: content_block_delta\ndata: ");
        body.push_str(
            &json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": delta}})
            .to_string(),
        );
        body.push_str("\n\n");
    }
    w.add(pragmatic::Event::DrawResult {
        intent: d,
        meta: r#"{"outcome":"ok"}"#.into(),
        head: pragmatic::Content::from(r#"{"status":200}"#),
        body: pragmatic::Content::from(body.as_str()),
    });
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);

    let (status, v) = erase(
        &ts,
        "support:7",
        json!({"match": EMAIL, "reason_code": "gdpr_art17"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v["erased"],
        json!([[2, 0], [3, 1]]),
        "the request and the reply"
    );
    let j = stored(&ts, "support:7");
    for e in j.entries() {
        if let pragmatic::Event::DrawResult { body, .. } = &e.event {
            assert!(body.value().is_none(), "the streamed reply is erased");
        }
    }
    assert!(j.audit().is_ok());
}
