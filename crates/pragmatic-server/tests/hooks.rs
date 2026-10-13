//! The integration points (anchoring, evidence, console) as the server
//! calls them, console sessions, anchors endpoints and webhooks.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::HeaderMap;
use common::*;
use pragmatic_server::hooks::{
    ConsoleError, ConsolePage, ConsoleRenderer, EvidenceBuilder, EvidenceBundle, EvidenceError,
    EvidenceRequest,
};
use pragmatic_server::webhooks::signature;
use reqwest::{redirect, Method, StatusCode};
use serde_json::{json, Value};

/// An evidence builder that reports what it was given.
struct EchoEvidence;

impl EvidenceBuilder for EchoEvidence {
    fn build(&self, req: EvidenceRequest<'_>) -> Result<EvidenceBundle, EvidenceError> {
        let body = json!({
            "run_id": req.run_id,
            "entries": req.journal.len(),
            "bytes": req.journal_bytes.len(),
            "requested_by": req.requested_by,
            "redact": req.redact,
            "independent": req.independent,
            "generator": req.generator,
        });
        Ok(EvidenceBundle {
            file_name: format!("{}.evidence.json", req.run_id),
            content_type: "application/json".into(),
            body: body.to_string().into_bytes(),
        })
    }
}

/// A console renderer that shows the page data as JSON.
struct JsonConsole;

impl ConsoleRenderer for JsonConsole {
    fn render(&self, page: &ConsolePage<'_>) -> Result<String, ConsoleError> {
        Ok(match page {
            ConsolePage::SignIn { error, .. } => json!({"page": "sign_in", "error": error}),
            ConsolePage::Runs { viewer, runs, .. } => {
                json!({"page": "runs", "viewer": viewer.token_id, "licensee": viewer.licensee, "runs": runs})
            }
            ConsolePage::Run { summary, entries, .. } => json!({"page": "run", "summary": summary, "entries": entries}),
            ConsolePage::AccessLog { records, .. } => json!({"page": "access", "records": records}),
            ConsolePage::Holds { holds, .. } => json!({"page": "holds", "holds": holds}),
            ConsolePage::Tokens { tokens, .. } => json!({"page": "tokens", "tokens": tokens}),
        }
        .to_string())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_goes_through_the_hook_after_access_checks() {
    let ts = TestServer::start_hooked(|_| {}, |h| h.evidence = Arc::new(EchoEvidence)).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    Writer::create(&ts, &agent, "r").await.attempt(&ts, 2).await;
    let (auditor, auditor_id) = ts.issue("auditor", &["*"], false).await;
    let resp = ts
        .get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-disposition"],
        "attachment; filename=\"r.evidence.json\""
    );
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["entries"], 5);
    assert_eq!(v["requested_by"], auditor_id);
    assert_eq!(v["redact"], "detectors", "no view_raw: redacted by default");
    assert_eq!(v["independent"], true);
    // anchor=now ran a batch: the run is anchored.
    let s: Value = ts
        .get(&run_path("r", ""), &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["anchored_entries"], 5);
    assert_eq!(s["unanchored_entries"], 0);
    // An unredacted bundle needs view_raw.
    let resp = ts
        .get(&run_path("r", "/evidence?redact=none"), &auditor)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let (raw, _) = ts.issue("auditor", &["*"], true).await;
    let v: Value = ts
        .get(&run_path("r", "/evidence"), &raw)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["redact"], "none");
    let resp = ts.get(&run_path("r", "/evidence?redact=weird"), &raw).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stubs_answer_501() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    Writer::create(&ts, &agent, "r").await.attempt(&ts, 1).await;
    let (status, c) = code(ts.get(&run_path("r", "/evidence"), &ts.admin).await).await;
    assert_eq!(
        (status, c.as_str()),
        (StatusCode::NOT_IMPLEMENTED, "not_implemented")
    );
    let resp = ts
        .client
        .get(format!("{}/console/sign-in", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchors_are_filtered_by_scope() {
    let ts = TestServer::start_anchored(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    Writer::create(&ts, &agent, "a:1")
        .await
        .attempt(&ts, 1)
        .await;
    Writer::create(&ts, &agent, "b:1")
        .await
        .attempt(&ts, 1)
        .await;
    ts.app()
        .anchor_batch(pragmatic_server::hooks::BatchReason::Interval)
        .unwrap();
    let (auditor, _) = ts.issue("auditor", &["a:"], false).await;
    let v: Value = ts.get("/v1/anchors", &auditor).await.json().await.unwrap();
    let leaves = v["checkpoints"][0]["leaves"].as_array().unwrap();
    assert_eq!(leaves.len(), 1, "{v}");
    assert_eq!(leaves[0]["run_id"], "a:1");
    let v: Value = ts.get("/v1/anchors", &ts.admin).await.json().await.unwrap();
    assert_eq!(
        v["checkpoints"][0]["leaves"].as_array().unwrap().len(),
        3,
        "both runs and the access log"
    );
    let v: Value = ts
        .get("/v1/anchors/log", &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["leaves"].as_array().unwrap().len(), 1);
    let v: Value = ts
        .get("/v1/anchors/0", &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["seq"], 0);
    // Nothing changed since: the next batch has only the access log.
    let receipt = ts
        .app()
        .anchor_batch(pragmatic_server::hooks::BatchReason::Interval)
        .unwrap()
        .unwrap();
    assert!(receipt.leaves.iter().all(|l| l.run_id.is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn console_sessions_sign_in_expire_and_end_with_their_token() {
    let ts = TestServer::start_hooked(
        |c| c.license.licensee = "Example Corp".into(),
        |h| h.console = Arc::new(JsonConsole),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    Writer::create(&ts, &agent, "a:1")
        .await
        .attempt(&ts, 1)
        .await;
    Writer::create(&ts, &agent, "b:1")
        .await
        .attempt(&ts, 1)
        .await;
    let (auditor, auditor_id) = ts.issue("auditor", &["a:"], false).await;
    let browser = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .build()
        .unwrap();
    // Not signed in: redirected.
    let resp = browser
        .get(format!("{}/console", ts.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()["location"], "/console/sign-in");
    // A wrong token: 401, no cookie.
    let resp = browser
        .post(format!("{}/console/sign-in", ts.url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=prag_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("set-cookie").is_none());
    // The right token: a strict, HTTP-only session cookie.
    let resp = browser
        .post(format!("{}/console/sign-in", ts.url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("token={auditor}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    assert!(!cookie.contains("Secure"), "plain http in tests");
    let session = cookie.split(';').next().unwrap().to_string();
    let page: Value = browser
        .get(format!("{}/console", ts.url))
        .header("cookie", &session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["viewer"], auditor_id);
    assert_eq!(page["licensee"], "Example Corp");
    let runs: Vec<&str> = page["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["run_id"].as_str().unwrap())
        .collect();
    assert_eq!(runs, ["a:1"], "the console filters by scope too");
    let resp = browser
        .get(format!("{}/console/runs/b:1", ts.url))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let page: Value = browser
        .get(format!("{}/console/runs/a:1", ts.url))
        .header("cookie", &session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["entries"].as_array().unwrap().len(), 4);
    let resp = browser
        .get(format!("{}/console/tokens", ts.url))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "tokens are for admins"
    );
    // Idle sessions end.
    ts.app().sessions.age(Duration::from_secs(16 * 60));
    let resp = browser
        .get(format!("{}/console", ts.url))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Sign out ends a session; revoking its token ends it too.
    let (admin2, admin2_id) = ts.issue("admin", &[], false).await;
    let sign_in = |token: String| {
        browser
            .post(format!("{}/console/sign-in", ts.url))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("token={token}"))
            .send()
    };
    let c2 = sign_in(admin2.clone()).await.unwrap().headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let resp = browser
        .get(format!("{}/console/tokens", ts.url))
        .header("cookie", &c2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    ts.req(
        Method::DELETE,
        &format!("/v1/tokens/{admin2_id}"),
        &ts.admin,
    )
    .send()
    .await
    .unwrap();
    let resp = browser
        .get(format!("{}/console/tokens", ts.url))
        .header("cookie", &c2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let c3 = sign_in(ts.admin.clone()).await.unwrap().headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let resp = browser
        .post(format!("{}/console/sign-out", ts.url))
        .header("cookie", &c3)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = browser
        .get(format!("{}/console", ts.url))
        .header("cookie", &c3)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Sign-in and sign-out are logged, the failed one with a fingerprint.
    let records = ts.audit().await;
    assert!(records
        .iter()
        .any(|r| r["action"] == "sign_in" && r["token_id"] == auditor_id && r["status"] == 303));
    assert!(records
        .iter()
        .any(|r| r["action"] == "sign_in" && r["status"] == 401 && r["token_fp"].is_string()));
    assert!(records
        .iter()
        .any(|r| r["action"] == "sign_out" && r["token_id"] == "bootstrap"));
}

#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<(HeaderMap, Bytes)>>>);

async fn receiver() -> (String, Received) {
    let got = Received::default();
    let g = got.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let g = g.clone();
            async move {
                g.0.lock().unwrap().push((headers, body));
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhooks_are_signed_and_carry_no_content() {
    let (url, got) = receiver().await;
    let secret_dir = TempDir::new("hook-secret");
    let secret_file = secret_dir.path().join("secret");
    std::fs::write(&secret_file, "s3cret\n").unwrap();
    let ts = TestServer::start(|c| {
        c.webhooks.push(pragmatic_server::config::WebhookConfig {
            url: url.clone(),
            secret_file: secret_file.clone(),
            events: vec!["erasure".into()],
        })
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    w.release(&ts).await;
    let resp = ts
        .post_json(
            &run_path("r", "/erase"),
            &ts.admin,
            json!({"slots": [[2, 0]], "reason_code": "dsar"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut tries = 0;
    while got.0.lock().unwrap().is_empty() && tries < 100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tries += 1;
    }
    let calls = got.0.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let (headers, body) = &calls[0];
    assert_eq!(
        headers["pragmatic-signature"],
        signature(b"s3cret", body).as_str()
    );
    let v: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(v["event"], "erasure");
    assert_eq!(v["run_id"], "r");
    assert_eq!(v["slots"], 1);
    assert!(!String::from_utf8_lossy(body).contains("message 0"));
}
