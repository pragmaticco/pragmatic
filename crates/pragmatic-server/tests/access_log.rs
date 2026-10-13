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
    assert_eq!(loaded["key_id"].as_str().unwrap().len(), 8);
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

/// A run id in a path is logged only when it is well formed (or names a
/// run the server holds); anything else, up to the URI limit, is logged as
/// its length and hash. Query parameter names are capped too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_run_ids_and_many_query_names_are_logged_in_bounded_form() {
    let ts = TestServer::start(|_| {}).await;
    let huge = "a".repeat(60_000);
    let resp = ts
        .client
        .get(format!("{}/v1/runs/{huge}/entries", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let many: Vec<String> = (0..40).map(|i| format!("p{i}=v")).collect();
    ts.get(&format!("/v1/runs?{}", many.join("&")), &ts.admin)
        .await;
    let records = ts.audit().await;
    let longest = records
        .iter()
        .filter_map(|r| r["run_id"].as_str())
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(longest <= 200, "a {longest}-byte run id was logged");
    let invalid = records
        .iter()
        .find(|r| r["invalid_run_id"].is_object())
        .expect("the malformed id is recorded as a length and a hash");
    assert_eq!(invalid["invalid_run_id"]["bytes"], 60_000);
    assert_eq!(
        invalid["invalid_run_id"]["sha256"],
        pragmatic::encoding::hex_encode(&pragmatic::sha256::sha256(huge.as_bytes()))
    );
    assert!(invalid["run_id"].is_null());
    assert_eq!(invalid["status"], 401);
    let listed = records
        .iter()
        .find(|r| r["route"] == "/v1/runs" && r["query_dropped"].is_number())
        .unwrap();
    assert_eq!(listed["query"].as_array().unwrap().len(), 32);
    assert_eq!(listed["query_dropped"], 8);
}

/// Without `view_raw`, the personal fields of access-log records are
/// withheld whole, whatever they hold (an IPv6 address and a principal
/// that is not an email address match no content detector).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personal_fields_are_withheld_from_auditors_without_view_raw() {
    let ts = TestServer::start(|c| {
        c.trusted_proxy_header = "x-forwarded-for".into();
        c.redaction.builtin = vec![];
    })
    .await;
    let resp = ts
        .post_json(
            "/v1/tokens",
            &ts.admin,
            json!({"name": "n", "principal": "Jane Doe", "role": "agent", "scopes": ["*"]}),
        )
        .await;
    let agent = resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = ts
        .req(Method::GET, &run_path("r6", ""), &agent)
        .header("x-forwarded-for", "2001:db8:85a3::8a2e:370:7334")
        .header("user-agent", "agent-sdk/1.0 (jane's laptop)")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    ts.app().access.flush().await.unwrap();
    let (auditor, _) = ts.issue("auditor", &["*"], false).await;
    let v: Value = ts
        .get("/v1/audit?run_id=r6", &auditor)
        .await
        .json()
        .await
        .unwrap();
    let text = v.to_string();
    for personal in ["2001:db8:85a3::8a2e:370:7334", "Jane Doe", "jane's laptop"] {
        assert!(
            !text.contains(personal),
            "{personal} reached an auditor: {text}"
        );
    }
    let record = &v["records"][0];
    assert_eq!(record["source_ip"], "[withheld]");
    assert_eq!(record["principal"], "[withheld]");
    assert_eq!(record["user_agent"], "[withheld]");
    // Every record carries its chain hash, for checking against anchors.
    assert_eq!(record["hash"].as_str().unwrap().len(), 64);
    // With view_raw they are there.
    let (raw, _) = ts.issue("auditor", &["*"], true).await;
    let v: Value = ts
        .get("/v1/audit?run_id=r6", &raw)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["records"][0]["source_ip"], "2001:db8:85a3::8a2e:370:7334");
    assert_eq!(v["records"][0]["principal"], "Jane Doe");
}

/// Who issued a token is durable before the token exists: the issue's
/// intent names the new token id, and the token records its issuer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_issuer_of_a_token_is_recorded_before_the_token_exists() {
    let ts = TestServer::start(|_| {}).await;
    let (_, id) = ts.issue("auditor", &["*"], true).await;
    // A crash (here: the disk failing) right after the response: nothing
    // queued after it reaches the disk.
    ts.app().access.inject_write_failure();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut ts = ts;
    ts.stop().await;
    let bytes = std::fs::read(pragmatic_server::access_log::path(&ts.data_dir())).unwrap();
    let log = Journal::parse(&bytes, None).unwrap().journal;
    let intent = log
        .entries()
        .iter()
        .find_map(|e| match &e.event {
            pragmatic::Event::Note { kind, data, .. } if kind == "intent" => {
                let d: Value = serde_json::from_str(data).unwrap();
                (d["action"] == "token.issue").then_some(d)
            }
            _ => None,
        })
        .expect("a durable token.issue intent");
    assert_eq!(intent["issued"], id.as_str());
    assert_eq!(intent["token_id"], "bootstrap");
    let tokens: Value =
        serde_json::from_slice(&std::fs::read(ts.data_dir().join("tokens.json")).unwrap()).unwrap();
    assert_eq!(tokens["tokens"][0]["created_by"], "bootstrap");
}

/// A failed access log is not silent: readiness fails, a gauge says so,
/// and the `access_log_failed` webhook fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_access_log_fails_readiness_and_is_reported() {
    let (url, got) = webhook_receiver().await;
    let secrets = TempDir::new("alog-hook");
    let hook = webhook(&secrets, &url, &["access_log_failed"]);
    let ts = TestServer::start(move |c| c.webhooks.push(hook)).await;
    let before = metrics(&ts).await;
    assert_eq!(metric(&before, "pragmatic_access_log_failed"), Some(0.0));
    ts.app().access.inject_write_failure();
    let resp = ts
        .post_json(
            "/v1/holds",
            &ts.admin,
            json!({"matter": "m", "scope": {"prefix": "x"}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ts.get("/v1/whoami", &ts.admin).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let ready = reqwest::get(format!("{}/readyz", ts.url)).await.unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let after = metrics(&ts).await;
    assert_eq!(metric(&after, "pragmatic_access_log_failed"), Some(1.0));
    let event = got.wait_for("access_log_failed").await.expect("a webhook");
    assert!(event["reason"].as_str().unwrap().contains("injected"));
    // Health stays up: the process is alive, just not ready.
    let health = reqwest::get(format!("{}/healthz", ts.url)).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}
