//! The access log (design 4.11).

mod common;

use common::*;
use pragmatic::Journal;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_request_is_logged_with_its_route_template_and_no_query_values() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, agent_id) = ts.issue("agent", &["a:"], false).await;
    Writer::create(&ts, &agent, "a:1")
        .await
        .attempt(&ts, 1)
        .await;
    ts.get("/v1/runs?q=very-secret-search&label.team=red", &agent)
        .await;
    ts.get(&run_path("b:hidden", ""), &agent).await;
    ts.get("/v1/runs", "prag_nope").await;
    ts.get("/v1/no-such-endpoint", &agent).await;
    let records = ts.audit().await;
    let text = serde_json::to_string(&records).unwrap();
    assert!(
        !text.contains("very-secret-search"),
        "query values are never logged"
    );
    assert!(!text.contains("red\""), "query values are never logged");
    let list = records
        .iter()
        .find(|r| r["route"] == "/v1/runs" && r["token_id"] == agent_id)
        .unwrap();
    assert_eq!(list["query"], json!(["q", "label.team"]));
    assert_eq!(list["role"], "agent");
    assert_eq!(list["principal"], "agent@example.test");
    assert_eq!(list["status"], 200);
    assert_eq!(list["source_ip"], "127.0.0.1");
    let hidden = records.iter().find(|r| r["run_id"] == "b:hidden").unwrap();
    assert_eq!(hidden["status"], 404);
    assert_eq!(hidden["route"], "/v1/runs/{id}");
    let frames = records
        .iter()
        .find(|r| r["route"] == "/v1/runs/{id}/frames")
        .unwrap();
    assert_eq!(frames["run_id"], "a:1");
    assert_eq!(frames["cursor_from"], 0);
    assert_eq!(frames["cursor_to"], 4);
    let denied = records.iter().find(|r| r["status"] == 401).unwrap();
    assert!(denied["token_id"].is_null());
    assert_eq!(denied["token_fp"].as_str().unwrap().len(), 8);
    assert!(records
        .iter()
        .any(|r| r["route"] == "<unknown>" && r["status"] == 404));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_records_config_loaded() {
    let ts = TestServer::start(|_| {}).await;
    let records = ts.audit().await;
    assert_eq!(records[0]["kind"], "run.start");
    assert_eq!(records[0]["run_id"], "pragmatic:access-log");
    let loaded = &records[1];
    assert_eq!(loaded["kind"], "config.loaded");
    assert_eq!(loaded["key_id"].as_str().unwrap().len(), 64);
    assert_eq!(loaded["token_ids"], json!(["bootstrap"]));
    assert_eq!(loaded["config_sha256"].as_str().unwrap().len(), 64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_reads_and_token_changes_are_recorded_before_they_act() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let w = {
        let mut w = Writer::create(&ts, &agent, "r").await;
        w.attempt(&ts, 1).await;
        w
    };
    let (raw, raw_id) = ts.issue("auditor", &["*"], true).await;
    let resp = ts.get(&run_path("r", "/journal"), &raw).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let records = ts.audit().await;
    let intent_at = records
        .iter()
        .position(|r| r["kind"] == "intent" && r["action"] == "read_raw" && r["token_id"] == raw_id)
        .unwrap();
    let request_at = records
        .iter()
        .position(|r| r["route"] == "/v1/runs/{id}/journal" && r["token_id"] == raw_id)
        .unwrap();
    assert!(intent_at < request_at);
    assert_eq!(records[request_at]["raw"], true);
    assert!(records
        .iter()
        .any(|r| r["kind"] == "intent" && r["action"] == "token.issue"));
    let _ = w;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_access_log_fails_closed() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    ts.app().access.inject_write_failure();
    // A request whose record must be durable before it acts fails, and
    // from then on every authenticated request is refused.
    let resp = ts
        .post_json(
            "/v1/tokens",
            &ts.admin,
            json!({"name": "n", "principal": "p", "role": "admin"}),
        )
        .await;
    assert_eq!(
        code(resp).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable".into()
        )
    );
    assert!(ts.app().access.is_failed());
    for path in ["/v1/info", "/v1/runs", "/v1/tokens"] {
        let resp = ts.get(path, &ts.admin).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert!(resp.headers().contains_key("retry-after"));
    }
    w.add(recv("not stored"));
    assert_eq!(code(w.push(&ts).await).await.1, "storage_unavailable");
    // Health stays up, so the operator can see the server is alive.
    let resp = ts
        .client
        .get(format!("{}/healthz", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Nothing unlogged reached the run.
    assert_eq!(stored(&ts, "r").len(), 4);
    // The token was not issued.
    let tokens = std::fs::read_to_string(ts.data_dir().join("tokens.json")).unwrap();
    assert_eq!(tokens.matches("\"id\"").count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_access_log_is_a_journal_that_verifies() {
    let ts = TestServer::start(|_| {}).await;
    for _ in 0..20 {
        ts.get("/v1/info", &ts.admin).await;
    }
    ts.audit().await;
    let bytes = std::fs::read(ts.data_dir().join("audit/access.journal")).unwrap();
    let parsed = Journal::parse(&bytes, None).unwrap();
    assert_eq!(parsed.tail_len, 0);
    assert!(parsed.journal.len() >= 22);
    assert!(parsed.journal.audit().is_ok());
    // Personal fields live in the payload slot, so they can be erased.
    let e = parsed.journal.get(5).unwrap();
    assert_eq!(e.slots.len(), 1);
    if let pragmatic::Event::Note { data, .. } = &e.event {
        let d: Value = serde_json::from_str(data).unwrap();
        assert!(d.get("source_ip").is_none() && d.get("principal").is_none());
    }
    let _ = Method::GET;
}
