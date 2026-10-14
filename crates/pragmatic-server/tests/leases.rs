//! Leases (design 4.5): renewal, lazy expiry, takeover, persistence and
//! custody notes.

mod common;

use std::time::Duration;

use common::*;
use pragmatic::encoding::hex_encode;
use pragmatic::sha256::sha256;
use pragmatic::{Content, Event};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

async fn lease(
    ts: &TestServer,
    token: &str,
    run: &str,
    holder: &str,
    presented: Option<&str>,
) -> reqwest::Response {
    let mut req = ts
        .req(Method::POST, &run_path(run, "/lease"), token)
        .header("content-type", "application/json")
        .body(json!({ "holder": holder }).to_string());
    if let Some(l) = presented {
        req = req.header("pragmatic-lease", l);
    }
    req.send().await.unwrap()
}

fn custody_notes(ts: &TestServer, run: &str) -> Vec<Value> {
    stored(ts, run)
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            Event::Note { kind, data, .. } if kind == "custody" => {
                Some(serde_json::from_str(data).unwrap())
            }
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewal_keeps_the_lease_and_others_wait() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 30).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    // A PUT lease has no holder yet: naming one is not enough to renew it.
    let resp = lease(&ts, &agent, "r", "holder-a", None).await;
    let (status, c) = code(resp).await;
    assert_eq!((status, c.as_str()), (StatusCode::CONFLICT, "run_locked"));
    // Presenting the lease id renews it and records the holder.
    let v: Value = lease(&ts, &agent, "r", "holder-a", Some(&w.lease))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["lease"], w.lease);
    assert_eq!(v["ttl_secs"], 30);
    // From now on the holder id alone renews.
    let v: Value = lease(&ts, &agent, "r", "holder-a", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["lease"], w.lease);
    // Anyone else waits, with Retry-After and how long the holder has left.
    let resp = lease(&ts, &agent, "r", "holder-b", None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=30).contains(&retry));
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], "run_locked");
    assert!(v["error"]["holder_expires_in"].as_u64().unwrap() <= 30);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn takeover_after_expiry_writes_custody_for_the_old_lease() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 1).await;
    let (agent, agent_id) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    w.add(recv("more"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let (other, _) = ts.issue("agent", &["*"], false).await;
    let v: Value = lease(&ts, &other, "r", "holder-2", None)
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(v["lease"], w.lease);
    let notes = custody_notes(&ts, "r");
    assert_eq!(notes.len(), 1);
    let n = &notes[0];
    assert_eq!(n["lease"], hex_encode(&sha256(w.lease.as_bytes())));
    assert_eq!(n["token"], agent_id);
    assert_eq!(
        n["principal"], agent_id,
        "notes carry token ids, never names"
    );
    assert_eq!(n["from_entries"], 0);
    assert_eq!(n["to_entries"], 6);
    assert_eq!(n["requests"], 2);
    assert_eq!(n["clock_skew"], false);
    assert_eq!(n["end"], "expired");
    assert!(n["first_received"].as_u64().unwrap() <= n["last_received"].as_u64().unwrap());
    // The old holder learns its lease expired.
    w.add(recv("stale"));
    assert_eq!(code(w.push(&ts).await).await.1, "lease_expired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_writes_custody_and_ends_the_lease() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let notes = custody_notes(&ts, "r");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["end"], "released");
    assert_eq!(code(w.release(&ts).await).await.1, "lease_lost");
    // A run whose first entry was never written gets no custody note:
    // its first entry must be run.start.
    let empty = Writer::create(&ts, &agent, "empty").await;
    assert_eq!(empty.release(&ts).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(stored(&ts, "empty").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clock_skew_is_accepted_and_flagged_for_custody() {
    let ts = TestServer::start(|c| c.max_clock_skew_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.journal.set_clock(|| 1_000_000_000);
    w.attempt(&ts, 1).await;
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(custody_notes(&ts, "r")[0]["clock_skew"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_survive_a_restart() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 30).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 1).await;
    let ts = ts.restart().await;
    w.add(recv("after restart"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let (other, _) = ts.issue("agent", &["*"], false).await;
    assert_eq!(
        code(lease(&ts, &other, "r", "h", None).await).await.1,
        "run_locked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_effect_without_a_result_dangles_after_twice_the_ttl() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 1).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(Event::EffectIntent {
        name: "send_email".into(),
        arg: Content::from("{}"),
    });
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let status = |ts: &TestServer| {
        ts.app()
            .store
            .get("r")
            .map(|r| ts.app().store.status(&r.lock()))
    };
    assert_eq!(status(&ts), Some("active"));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(status(&ts), Some("idle"));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(status(&ts), Some("dangling"));
    ts.app().store.sweep();
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
        metrics.contains("pragmatic_dangling_effects 1"),
        "{metrics}"
    );
}
