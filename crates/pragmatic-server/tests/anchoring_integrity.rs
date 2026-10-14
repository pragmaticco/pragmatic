//! What the server concludes from its anchor log, and what it claims
//! (design 4.2, 4.7 and 5.1), with the anchoring library integrated:
//! startup recovery that survives a lost batch index, the access log
//! checked against its signed leaf, the anchors API's scope filter,
//! evidence anchors cut by checkpoint, honest independence claims, the
//! anchoring-lag alert, and what accepting a regression claims.

mod common;

use std::time::Duration;

use common::tsa::{openssl_usable, OpensslTokens, TsaServer};
use common::*;
use pragmatic::evidence::{
    self as ev, Audit, Bundle, NoTsaVerifier, TrustPolicy, TsaRoot, Verdict,
};
use pragmatic::note::VerifierKey;
use pragmatic_anchor::tsa::TsaPolicy;
use pragmatic_anchor::RetryPolicy;
use pragmatic_server::anchoring::Options;
use pragmatic_server::config::{Config, TsaConfig, WitnessConfig};
use pragmatic_server::evidence::BundleBuilder;
use pragmatic_server::hooks::{BatchReason, EvidenceRequest};
use pragmatic_server::keys::ServerKey;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn fast() -> Options {
    Options {
        tsa_policy: TsaPolicy {
            timeout: Duration::from_secs(10),
            min_spacing: Duration::ZERO,
            max_attempts: 2,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        },
        retry: RetryPolicy {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            ..RetryPolicy::default()
        },
        ..Options::default()
    }
}

fn tsa_config(name: &str, t: &TsaServer) -> TsaConfig {
    TsaConfig {
        url: t.url.clone(),
        roots_pem: t.tsa.root_pem(),
        operator: name.into(),
        name: String::new(),
    }
}

async fn summary(ts: &TestServer, run: &str) -> Value {
    ts.get(&run_path(run, ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap()
}

/// Cut a run's stored journal back to its first `keep` entries and make
/// its meta agree, as a restore of an older copy would leave it.
fn roll_back(data: &std::path::Path, run: &str, keep: u64) {
    let journal_path = run_file_in(data, run, ".journal");
    let original = std::fs::read(&journal_path).unwrap();
    let j = pragmatic::Journal::parse(&original, None).unwrap().journal;
    let mut bytes = original[..pragmatic::journal::HEADER_LEN].to_vec();
    for c in 0..keep {
        bytes.extend(j.frame_bytes(c).unwrap());
    }
    std::fs::write(&journal_path, &bytes).unwrap();
    let meta_path = run_file_in(data, run, ".meta.json");
    let mut meta: pragmatic_server::store::Meta =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    meta.entries = keep;
    meta.byte_len = bytes.len() as u64;
    meta.head = pragmatic::encoding::hex_encode(&j.get(keep - 1).unwrap().hash);
    meta.last_anchor_leaf = None;
    std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
}

/// One lost batch index (of an unrelated checkpoint) does not switch off
/// startup recovery: an independently anchored run whose files are gone
/// is still `missing`, and the problem is alerted on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_batch_index_does_not_hide_a_missing_run() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let (hook_url, got) = webhook_receiver().await;
    let hookdir = TempDir::new("batch-index-hook");
    let hook = webhook(&hookdir, &hook_url, &["anchor_failed", "record_missing"]);
    let mut ts = TestServer::start_integrated(
        |c| {
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.min_independent_operators = 1;
            c.anchoring.tsa = vec![tsa_config("alpha", &alpha)];
            c.webhooks = vec![hook];
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "a", &["one"]).await;
    let first = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    finished(&ts, &agent, "b", &["two"]).await;
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let s = summary(&ts, "b").await;
    assert_eq!(s["anchored_entries"], s["entries"], "{s}");
    ts.stop().await;

    let data = ts.data_dir();
    std::fs::remove_file(run_file_in(&data, "b", ".journal")).unwrap();
    std::fs::remove_file(run_file_in(&data, "b", ".meta.json")).unwrap();
    std::fs::remove_file(
        data.join("anchors")
            .join("batches")
            .join(format!("{:020}.json", first.seq)),
    )
    .unwrap();
    let ts = ts.restart().await;
    let s = summary(&ts, "b").await;
    assert_eq!(s["status"], "missing", "{s}");
    assert!(got.wait_for("record_missing").await.is_some());
    // The unusable index is alerted on with the next pass.
    ts.app().anchor_retry();
    let mut alerted = false;
    for _ in 0..100 {
        alerted = got.events().iter().any(|e| {
            e["event"] == "anchor_failed"
                && e["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("batch index"))
        });
        if alerted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(alerted, "{:?}", got.events());
}

/// The anchors API decides visibility by leaf type: a run leaf whose run
/// the server cannot map (its batch index is gone) is never shown to an
/// auditor as if it were an access-log leaf. With plain run ids the id is
/// read from the leaf itself, so in-scope leaves stay visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_anchors_api_never_shows_an_out_of_scope_leaf() {
    let mut ts = TestServer::start_integrated(|_| {}, fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "case-1", &["one"]).await;
    finished(&ts, &agent, "secret-hr-42", &["two"]).await;
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    ts.stop().await;
    std::fs::remove_file(
        ts.data_dir()
            .join("anchors")
            .join("batches")
            .join(format!("{:020}.json", receipt.seq)),
    )
    .unwrap();
    let ts = ts.restart().await;
    let (auditor, _) = ts.issue("auditor", &["case-"], false).await;
    let ids = |v: &Value| -> Vec<String> {
        let leaves: Vec<Value> = match v["checkpoints"].as_array() {
            Some(cps) => cps
                .iter()
                .flat_map(|c| c["leaves"].as_array().cloned().unwrap_or_default())
                .collect(),
            None => v["leaves"].as_array().cloned().unwrap_or_default(),
        };
        leaves
            .iter()
            .map(|l| {
                let bytes = pragmatic::encoding::hex_decode(l["leaf"].as_str().unwrap()).unwrap();
                String::from_utf8_lossy(&ev::Leaf::decode(&bytes).unwrap().id).into_owned()
            })
            .collect()
    };
    for path in ["/v1/anchors", "/v1/anchors/log"] {
        let v: Value = ts.get(path, &auditor).await.json().await.unwrap();
        let seen = ids(&v);
        assert!(
            !seen.iter().any(|id| id == "secret-hr-42"),
            "{path}: {seen:?}"
        );
        assert!(seen.iter().any(|id| id == "case-1"), "{path}: {seen:?}");
        assert!(seen.iter().any(|id| id == "access"), "{path}: {seen:?}");
        let v: Value = ts.get(path, &ts.admin).await.json().await.unwrap();
        assert!(
            ids(&v).iter().any(|id| id == "secret-hr-42"),
            "admins see all"
        );
    }
}

/// Under HMAC run ids a leaf whose batch index is gone cannot be mapped to
/// its run at all: it is shown to administrators only, and an auditor
/// still sees the access log's leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_hmac_ids_an_unmapped_run_leaf_is_shown_to_administrators_only() {
    let keys = TempDir::new("hmac-key");
    let key_file = keys.path().join("anchor.key");
    pragmatic_server::keys::write_secret(&key_file, &[7u8; 32]).unwrap();
    let mut ts = TestServer::start_integrated(
        |c| {
            c.anchoring.anchor_run_ids = "hmac".into();
            c.keys.anchor_key_file = key_file.clone();
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "case-1", &["one"]).await;
    finished(&ts, &agent, "secret-hr-42", &["two"]).await;
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    ts.stop().await;
    std::fs::remove_file(
        ts.data_dir()
            .join("anchors")
            .join("batches")
            .join(format!("{:020}.json", receipt.seq)),
    )
    .unwrap();
    let ts = ts.restart().await;
    let (auditor, _) = ts.issue("auditor", &["case-"], false).await;
    let kinds = |v: &Value| -> Vec<String> {
        v["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["type"].as_str().unwrap().to_string())
            .collect()
    };
    let v: Value = ts
        .get("/v1/anchors/log", &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert!(kinds(&v).iter().all(|k| k != "run"), "{v}");
    assert!(
        kinds(&v).iter().any(|k| k != "run"),
        "access-log leaves stay visible: {v}"
    );
    let v: Value = ts
        .get("/v1/anchors/log", &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(kinds(&v).iter().filter(|k| *k == "run").count(), 2, "{v}");
}

/// Replace the access log's records from `from` on with forged ones (the
/// log is an unkeyed journal, so the forgery chains).
fn forge_access_log(data: &std::path::Path, from: u64, forged: usize) {
    let path = data.join("audit").join("access.journal");
    let original = std::fs::read(&path).unwrap();
    let j = pragmatic::Journal::parse(&original, None).unwrap().journal;
    let mut bytes = original[..pragmatic::journal::HEADER_LEN].to_vec();
    for c in 0..from {
        bytes.extend(j.frame_bytes(c).unwrap());
    }
    let mut j = pragmatic::Journal::parse(&bytes, None).unwrap().journal;
    for i in 0..forged {
        j.append(
            pragmatic::journal::META,
            pragmatic::Event::Note {
                kind: "request".into(),
                data: format!("{{\"forged\":{i}}}"),
                payload: vec![],
            },
        )
        .unwrap();
    }
    std::fs::write(&path, j.to_bytes()).unwrap();
    let _ = std::fs::remove_file(data.join("audit").join("access.index"));
}

async fn rewritten_access_log(delete_side_file: bool) -> (f64, Value) {
    let mut ts = TestServer::start_integrated(|_| {}, fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    let leaf = receipt
        .leaves
        .iter()
        .find(|l| l.run_id.is_none())
        .unwrap()
        .clone();
    ts.stop().await;
    let data = ts.data_dir();
    forge_access_log(&data, leaf.entries - 1, 10);
    if delete_side_file {
        std::fs::remove_file(data.join("audit").join("anchor.json")).unwrap();
    }
    let ts = ts.restart().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let broken = metric(&metrics(&ts).await, "pragmatic_chain_broken_total").unwrap_or(0.0);
    let report: Value = ts
        .post_json("/v1/verify-data", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    (broken, report)
}

/// The access log is checked against its leaf in the anchor log, the
/// signed record, not against `audit/anchor.json`: a rewritten anchored
/// prefix is caught whether the side file is there or gone (the crash
/// case), at startup and by verify-data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewritten_access_log_is_caught_without_its_side_file() {
    for delete in [true, false] {
        let (broken, report) = rewritten_access_log(delete).await;
        assert!(broken >= 1.0, "side file deleted: {delete}: {broken}");
        assert_eq!(report["access_log"]["anchored"]["ok"], false, "{report}");
    }
}

/// When a batch anchors appends made after the journal was read, the
/// bundle's anchors and latest checkpoint stop at the checkpoint that was
/// the latest when the journal was read, so an honest bundle passes the
/// full-log audit instead of failing it with `anchor_omitted`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_built_while_a_batch_lands_passes_the_full_log_audit() {
    let ts = TestServer::start_integrated(|_| {}, fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 2).await;
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    // The evidence request notes the latest checkpoint and reads the
    // journal here...
    let through = ts.app().hooks.anchoring.latest_seq();
    let read = std::fs::read(run_file_in(&ts.data_dir(), "r", ".journal")).unwrap();
    // ...and a batch anchors appends made since, before the anchors are
    // read.
    w.attempt(&ts, 2).await;
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();

    let journal = pragmatic::Journal::parse(&read, None).unwrap().journal;
    let app = ts.app();
    let req = EvidenceRequest {
        run_id: "r",
        journal: &journal,
        journal_bytes: &read,
        anchors_through: through,
        requested_by: "tok_auditor",
        redact: "none",
        redactor: &app.redactor,
        anchoring: app.hooks.anchoring.as_ref(),
        key: &app.key,
        independent: false,
        generator: "pragmatic-server test",
    };
    let bundle: Bundle = BundleBuilder.bundle(&req).unwrap();
    assert_eq!(bundle.anchors.len(), 1, "the newer batch is left out");
    let log: Value = ts
        .get("/v1/anchors/log", &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    let file = json!({"leaves": log["leaves"].as_array().unwrap().iter()
        .map(|l| l["leaf"].clone()).collect::<Vec<_>>()});
    let audit = Audit {
        log: Some(ev::AnchorLog::from_json(file.to_string().as_bytes()).unwrap()),
        witness_logs: Vec::new(),
    };
    let report = ev::verify_with(&bundle, &TrustPolicy::default(), &NoTsaVerifier, &audit);
    let failures: Vec<String> = report
        .failures()
        .map(|f| format!("{}: {}", f.code.as_str(), f.message))
        .collect();
    assert_ne!(report.verdict, Verdict::Failed, "{failures:?}");
}

/// Two TSAs of different operators, both pinned.
fn two_tsas(c: &mut Config, alpha: &TsaServer, beta: &TsaServer) {
    c.lease_ttl_secs = 60;
    c.anchoring.allow_self_anchoring = false;
    c.anchoring.tsa = vec![tsa_config("alpha", alpha), tsa_config("beta", beta)];
}

/// A run rolled back after it was independently anchored is `regressed`,
/// and its bundle carries the leaf its journal contradicts (the cut is by
/// checkpoint, not by the journal's length), so the bundle does not
/// verify: the regression is never hidden from an auditor who holds only
/// the bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_of_a_rolled_back_run_does_not_verify() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let beta = TsaServer::start("beta");
    let mut ts = TestServer::start_integrated(|c| two_tsas(c, &alpha, &beta), fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let (auditor, _) = ts.issue("auditor", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(recv("refund approved: 10 EUR"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let keep = w.journal.len();
    let r = ts
        .get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    w.add(recv("refund reversed: customer complained"));
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let r = ts
        .get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    let s = summary(&ts, "r").await;
    assert_eq!(s["anchored_entries"], s["entries"], "{s}");
    ts.stop().await;
    roll_back(&ts.data_dir(), "r", keep);
    let ts = ts.restart().await;
    assert_eq!(summary(&ts, "r").await["status"], "regressed");

    let resp = ts.get(&run_path("r", "/evidence"), &auditor).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let b = Bundle::from_json(&resp.bytes().await.unwrap()).unwrap();
    assert!(b
        .anchors
        .iter()
        .any(|a| ev::Leaf::decode(&a.leaf).unwrap().entries > keep));
    let key = ServerKey::load(&ts.config.keys.signing_key_file).unwrap();
    let pinned = TrustPolicy {
        tsa_roots: vec![
            TsaRoot {
                operator: "alpha".into(),
                path: alpha.tsa.root_pem(),
            },
            TsaRoot {
                operator: "beta".into(),
                path: beta.tsa.root_pem(),
            },
        ],
        log_keys: vec![VerifierKey::parse(&key.vkey()).unwrap()],
        ..TrustPolicy::default()
    };
    let report = ev::verify(&b, &pinned, &OpensslTokens);
    assert_eq!(report.verdict, Verdict::Failed);
}

/// A bundle claims `independent` only when one of its anchors is
/// independently witnessed: not before the run is anchored, and yes
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_claims_independence_only_for_witnessed_anchors() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let ts = TestServer::start_integrated(
        |c| {
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.min_independent_operators = 1;
            c.anchoring.tsa = vec![tsa_config("alpha", &alpha)];
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    let (auditor, _) = ts.issue("auditor", &["*"], true).await;
    let resp = ts.get(&run_path("r", "/evidence"), &auditor).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let b = Bundle::from_json(&resp.bytes().await.unwrap()).unwrap();
    assert!(b.anchors.is_empty());
    assert!(!b.independent, "no anchors, no claim");
    let resp = ts
        .get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    let b = Bundle::from_json(&resp.bytes().await.unwrap()).unwrap();
    assert!(!b.anchors.is_empty());
    assert!(b.independent, "anchored and witnessed");
}

/// Accepting a regression claims nothing about anchoring: a run never
/// independently anchored (no external witness) stays at 0, with its lag
/// counting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepting_a_regression_claims_no_anchoring() {
    let mut ts = TestServer::start_integrated(|c| c.lease_ttl_secs = 60, fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one", "two", "three"]).await;
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    assert_eq!(summary(&ts, "r").await["anchored_entries"], 0);
    ts.stop().await;
    roll_back(&ts.data_dir(), "r", 3);
    let ts = ts.restart().await;
    assert_eq!(summary(&ts, "r").await["status"], "regressed");
    let resp = ts
        .post_json(&run_path("r", "/accept-regression"), &ts.admin, json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["anchored_entries"], 0, "{v}");
    let s = summary(&ts, "r").await;
    assert_eq!(s["anchored_entries"], 0, "{s}");
    assert_eq!(s["unanchored_entries"], s["entries"]);
    ts.app().store.sweep();
    let r = ts.app().store.get("r").unwrap();
    assert!(r.lock().meta.unanchored_since.is_some(), "the lag counts");
}

/// With independent witnesses, acceptance keeps what the journal still
/// holds of its independently anchored leaves: rolled back to the prefix a
/// leaf covers, that leaf's length; the later leaf it lost is not claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepting_a_regression_keeps_the_anchors_the_journal_still_holds() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let beta = TsaServer::start("beta");
    let mut ts = TestServer::start_integrated(|c| two_tsas(c, &alpha, &beta), fast()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let (auditor, _) = ts.issue("auditor", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(recv("first"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let keep = w.journal.len();
    ts.get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    w.add(recv("second"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    ts.get(&run_path("r", "/evidence?anchor=now"), &auditor)
        .await;
    let s = summary(&ts, "r").await;
    assert_eq!(s["anchored_entries"], s["entries"], "{s}");
    ts.stop().await;
    roll_back(&ts.data_dir(), "r", keep);
    let ts = ts.restart().await;
    let resp = ts
        .post_json(&run_path("r", "/accept-regression"), &ts.admin, json!({}))
        .await;
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["anchored_entries"], keep, "{v}");
}

/// On a quiet server whose witnesses fail, no batch runs (nothing new to
/// anchor), yet `anchor_failed` fires once the oldest unanchored append is
/// three intervals old, once, and re-arms when anchoring catches up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quiet_server_alerts_once_anchoring_lags_three_intervals() {
    let (hook_url, got) = webhook_receiver().await;
    let hookdir = TempDir::new("lag-hook");
    let hook = webhook(&hookdir, &hook_url, &["anchor_failed"]);
    let ts = TestServer::start_integrated(
        |c| {
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.min_independent_operators = 1;
            // A witness nobody answers for.
            c.anchoring.witness = vec![WitnessConfig {
                url: "http://127.0.0.1:9".into(),
                vkey: witness_cosigner().verifier_key().encode(),
                operator: "down".into(),
                token_file: std::path::PathBuf::new(),
            }];
            c.webhooks = vec![hook];
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    let interval = ts.config.anchoring.interval_secs as i64;
    let lagging = |secs: i64| {
        let r = ts.app().store.get("r").unwrap();
        r.lock().meta.unanchored_since = Some(pragmatic_server::timefmt::now_unix_secs() - secs);
        ts.app().store.sweep();
        ts.app().check_anchoring_lag();
    };
    let alerts = || {
        got.events()
            .iter()
            .filter(|e| {
                e["event"] == "anchor_failed"
                    && e["reason"]
                        .as_str()
                        .is_some_and(|r| r.contains("three anchoring intervals"))
            })
            .count()
    };
    lagging(2 * interval);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(alerts(), 0, "two intervals is not yet an alert");
    lagging(3 * interval + 10);
    lagging(10 * interval);
    let mut n = 0;
    for _ in 0..100 {
        n = alerts();
        if n > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(alerts(), 1, "alerted once while it lasts ({n})");
    // Anchoring catches up, then falls behind again: a new alert.
    {
        let r = ts.app().store.get("r").unwrap();
        let mut st = r.lock();
        st.meta.anchored_entries = st.meta.entries;
        st.meta.unanchored_since = None;
    }
    ts.app().store.sweep();
    ts.app().check_anchoring_lag();
    {
        let r = ts.app().store.get("r").unwrap();
        r.lock().meta.anchored_entries = 0;
    }
    lagging(4 * interval);
    for _ in 0..100 {
        if alerts() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(alerts(), 2);
}
