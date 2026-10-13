//! The basic life of a run: create, append, read, release.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_is_created_appended_read_and_released() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["team:"], false).await;
    let mut w = Writer::create(&ts, &agent, "team:run-1").await;
    w.attempt(&ts, 3).await;
    let summary: Value = ts
        .get(&run_path("team:run-1", ""), &agent)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(summary["entries"], 6, "{summary}");
    assert_eq!(summary["status"], "active");
    assert_eq!(summary["last_outcome"], "ok");
    assert_eq!(summary["verify"]["ok"], true);

    let entries: Value = ts
        .get(&run_path("team:run-1", "/entries"), &agent)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(entries["total"], 6);
    assert_eq!(entries["entries"][2]["kind"], "ChannelRecv");

    let journal = ts
        .req(Method::GET, &run_path("team:run-1", "/journal"), &agent)
        .header("pragmatic-lease", &w.lease)
        .send()
        .await
        .unwrap();
    assert_eq!(journal.status(), StatusCode::OK);
    assert_eq!(journal.headers()["pragmatic-entries"], "6");
    let bytes = journal.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), w.journal.to_bytes().as_slice());

    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let stored = stored(&ts, "team:run-1");
    assert_eq!(stored.len(), 7);
    let custody = stored.get(6).unwrap();
    assert_eq!(custody.event.note_kind(), Some("custody"));
}
