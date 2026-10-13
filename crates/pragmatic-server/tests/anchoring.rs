//! What the server offers anchoring (design 4.7), what it recovers from
//! the anchor log after a crash, and what it claims when anchoring is not
//! part of the build.

mod common;

use std::sync::Arc;

use common::*;
use pragmatic_server::config::TsaConfig;
use pragmatic_server::hooks::{Anchoring, BatchReason};
use reqwest::StatusCode;
use serde_json::Value;

/// Copy a directory tree (a crash image of a data directory).
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &dest);
        } else if e.file_name() != "server.lock" {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// The access log is offered to a batch only when it grew, naming its
/// previous leaf, so its leaves form a chain; a batch with nothing new
/// does not run at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_access_log_is_anchored_only_when_it_grew_and_its_leaves_chain() {
    let rec = Arc::new(Recording::default());
    let r2 = rec.clone();
    let ts =
        TestServer::start_hooked(|_| {}, move |h| h.anchoring = r2 as Arc<dyn Anchoring>).await;
    ts.app().access.flush().await.unwrap();
    let first = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let leaf = first
        .leaves
        .iter()
        .find(|l| l.run_id.is_none())
        .unwrap()
        .leaf_index;
    assert_eq!(
        rec.inputs.lock().unwrap()[0]
            .access_log
            .clone()
            .unwrap()
            .prev_leaf,
        None
    );
    // Nothing happened since: no batch.
    assert_eq!(ts.app().anchor_batch(BatchReason::Interval).unwrap(), None);
    assert_eq!(rec.inputs.lock().unwrap().len(), 1);
    // A request later, the log grew: offered again, naming its last leaf.
    ts.get("/v1/whoami", &ts.admin).await;
    ts.app().access.flush().await.unwrap();
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let second = rec.inputs.lock().unwrap()[1].access_log.clone().unwrap();
    assert_eq!(second.prev_leaf, Some(leaf));
    // The leaf survives a restart (audit/anchor.json).
    let saved = pragmatic_server::access_log::read_leaf(&ts.data_dir())
        .unwrap()
        .unwrap();
    assert_eq!(saved.entries, second.entries);
    assert_eq!(saved.head, pragmatic::encoding::hex_encode(&second.head));
}

/// A crash right after a batch, before the flusher would have written
/// `meta.json`, does not fork a run's leaf chain: `last_anchor_leaf` is
/// written at once, and recovered from the anchor log at startup anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_after_a_batch_does_not_fork_a_runs_leaf_chain() {
    let rec = Arc::new(Recording::default());
    let r2 = rec.clone();
    let ts = TestServer::start_hooked(
        |c| c.lease_ttl_secs = 60,
        move |h| h.anchoring = r2 as Arc<dyn Anchoring>,
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["hello"]).await;
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let leaf = receipt
        .leaves
        .iter()
        .find(|l| l.run_id.as_deref() == Some("r"))
        .unwrap()
        .leaf_index;
    ts.app().access.flush().await.unwrap();
    for lagging_meta in [false, true] {
        let crash = TempDir::new("anchor-crash");
        let data = crash.path().join("data");
        copy_tree(&ts.data_dir(), &data);
        if lagging_meta {
            // As if meta.json had not been written yet: the leaf is only
            // in the anchor log.
            let path = run_file_in(&data, "r", ".meta.json");
            let mut meta: pragmatic_server::store::Meta =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            meta.last_anchor_leaf = None;
            std::fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
        }
        let mut config = ts.config.clone();
        config.data_dir = data;
        let mut h = pragmatic_server::server::Hooks::stubs(&config);
        h.anchoring = rec.clone() as Arc<dyn Anchoring>;
        let handle = pragmatic_server::server::start(config, [0u8; 32], h)
            .await
            .unwrap();
        handle.wait_ready().await;
        let n = rec.inputs.lock().unwrap().len();
        let _ = handle.app.anchor_batch(BatchReason::Interval);
        let offered = rec.inputs.lock().unwrap()[n..]
            .iter()
            .flat_map(|i| i.runs.clone())
            .find(|t| t.run_id == "r");
        handle.shutdown().await.unwrap();
        assert!(
            offered.is_none(),
            "the unchanged run was anchored again with prev_leaf {:?}, skipping leaf {leaf} \
             (meta lagging: {lagging_meta})",
            offered.map(|t| t.prev_leaf)
        );
    }
}

/// The stub anchors nothing, so it claims no independent witness whatever
/// the configuration names, `/v1/info` says anchoring is not integrated,
/// and the anchoring lag grows from the first append.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_anchoring_nothing_claims_to_be_anchored() {
    let ts = TestServer::start(|c| {
        c.anchoring.allow_self_anchoring = false;
        c.anchoring.tsa.push(TsaConfig {
            url: "https://tsa.example/tsr".into(),
            roots_pem: "/etc/pragmatic/tsa/root.pem".into(),
            operator: "example".into(),
        });
    })
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    assert_eq!(ts.app().anchor_batch(BatchReason::Interval).unwrap(), None);
    let info: Value = ts.get("/v1/info", &ts.admin).await.json().await.unwrap();
    assert_eq!(info["independent_witness"], false, "{info}");
    assert_eq!(info["components"]["anchoring"], "not_integrated");
    assert_eq!(info["components"]["evidence"], "not_integrated");
    assert_eq!(info["components"]["console"], "not_integrated");
    let run: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(run["anchored_entries"], 0);
    // Age the oldest unanchored append, then let the sweeper see it.
    {
        let r = ts.app().store.get("r").unwrap();
        r.lock().meta.unanchored_since = Some(pragmatic_server::timefmt::now_unix_secs() - 120);
    }
    ts.app().store.sweep();
    let lag = metric(&metrics(&ts).await, "pragmatic_anchor_lag_seconds").unwrap();
    assert!(
        lag >= 120.0,
        "the anchoring lag is {lag} with nothing anchored"
    );
}

/// An access log that holds fewer records than its last anchor leaf
/// covers (cut back, or replaced) is reported at startup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_access_log_shorter_than_its_anchored_leaf_is_reported() {
    let ts = TestServer::start_anchored(|_| {}).await;
    ts.app().access.flush().await.unwrap();
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let mut ts = ts;
    ts.stop().await;
    let mut leaf = pragmatic_server::access_log::read_leaf(&ts.data_dir())
        .unwrap()
        .unwrap();
    leaf.entries += 1000;
    pragmatic_server::access_log::write_leaf(&ts.data_dir(), &leaf).unwrap();
    let ts = ts.restart().await;
    let page = metrics(&ts).await;
    assert_eq!(
        metric(&page, "pragmatic_chain_broken_total"),
        Some(1.0),
        "{page}"
    );
    let records = ts.audit().await;
    let damaged = records
        .iter()
        .find(|r| r["kind"] == "access_log.damaged")
        .expect("the finding is in the log itself");
    assert!(damaged["reason"]
        .as_str()
        .unwrap()
        .contains("were anchored"));
    let v: Value = ts
        .post_json("/v1/verify-data", &ts.admin, serde_json::json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["access_log"]["ok"], false, "{v}");
    assert_eq!(v["access_log"]["anchored"]["ok"], false);
    assert_eq!(
        ts.get("/v1/whoami", &ts.admin).await.status(),
        StatusCode::OK,
        "the server goes on recording"
    );
}
