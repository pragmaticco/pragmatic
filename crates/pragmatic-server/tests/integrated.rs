//! The server wired to its components (design 4.7, 4.8 and 5): anchoring
//! with the anchoring library against local OpenSSL TSAs and another
//! server in witness mode, and evidence bundles that verify offline with
//! the core verifier, the reference verifier and the CLI, against pinned
//! roots and keys, and fail without them.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use common::tsa::{openssl_usable, OpensslTokens, TsaServer};
use common::*;
use pragmatic::evidence::{
    self, AnchorLog, Audit, Bundle, NoTsaVerifier, TrustPolicy, TsaRoot, Verdict, WitnessKey,
    WitnessLog,
};
use pragmatic::note::VerifierKey;
use pragmatic_anchor::tsa::TsaPolicy;
use pragmatic_anchor::RetryPolicy;
use pragmatic_server::anchoring::Options;
use pragmatic_server::config::{TsaConfig, WitnessConfig, WitnessOrigin};
use pragmatic_server::hooks::BatchReason;
use pragmatic_server::keys::ServerKey;
use pragmatic_server::tokens::token_sha256;
use reqwest::StatusCode;
use serde_json::{json, Value};

/// The design's timing, shortened for tests.
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

/// A console page as `token` sees it: signed in through the form, the
/// session cookie kept.
async fn console_page(ts: &TestServer, token: &str, path: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let cookie = |resp: &reqwest::Response| {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .collect::<Vec<_>>()
            .join("; ")
    };
    let resp = client
        .get(format!("{}/console/sign-in", ts.url))
        .send()
        .await
        .unwrap();
    let jar = cookie(&resp);
    let html = resp.text().await.unwrap();
    let field = "name=\"csrf\" value=\"";
    let at = html.find(field).unwrap() + field.len();
    let csrf = &html[at..at + html[at..].find('"').unwrap()];
    let body: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("token", token), ("csrf", csrf)])
        .finish();
    let resp = client
        .post(format!("{}/console/sign-in", ts.url))
        .header("cookie", jar)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session = cookie(&resp);
    let resp = client
        .get(format!("{}{path}", ts.url))
        .header("cookie", session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    resp.text().await.unwrap()
}

/// A bundle as `GET /v1/runs/{id}/evidence` serves it.
async fn bundle(ts: &TestServer, token: &str, run: &str, query: &str) -> Vec<u8> {
    let resp = ts
        .get(&run_path(run, &format!("/evidence{query}")), token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/json");
    resp.bytes().await.unwrap().to_vec()
}

/// Run the reference verifier (`tools/verify_evidence.py`, standard
/// library only) on a bundle; its exit code, or `None` without Python.
fn reference_verifier(file: &Path, args: &[String]) -> Option<i32> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify_evidence.py");
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(file)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "reference verifier: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.code()
}

/// The `pragmatic` CLI built in this target directory, when the workspace
/// was built (as `cargo test --workspace` does).
fn cli() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.parent()?;
    let bin = dir.join(format!("pragmatic{}", std::env::consts::EXE_SUFFIX));
    if bin.is_file() {
        Some(bin)
    } else {
        eprintln!("the pragmatic CLI is not built here; skipping its check");
        None
    }
}

fn cli_verify(file: &Path, args: &[String]) -> Option<i32> {
    let bin = cli()?;
    let out = Command::new(bin)
        .arg("verify-evidence")
        .arg(file)
        .args(args)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "pragmatic verify-evidence: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.code()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundles_verify_offline_against_pinned_roots_and_fail_without_them() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let beta = TsaServer::start("beta");
    let ts = TestServer::start_integrated(
        |c| {
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.tsa = vec![
                TsaConfig {
                    name: "Alpha Time".into(),
                    ..tsa_config("alpha", &alpha)
                },
                tsa_config("beta", &beta),
            ];
        },
        fast(),
    )
    .await;
    let info: Value = ts.get("/v1/info", &ts.admin).await.json().await.unwrap();
    assert_eq!(info["components"]["anchoring"], "integrated", "{info}");
    assert_eq!(info["components"]["evidence"], "integrated");
    assert_eq!(info["independent_witness"], true);

    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(
        &ts,
        &agent,
        "case-1",
        &["hello", "write to jane.doe@example.com", "done"],
    )
    .await;
    let (auditor, auditor_id) = ts.issue("auditor", &["case-"], false).await;
    let bytes = bundle(&ts, &auditor, "case-1", "?anchor=now").await;
    let b = Bundle::from_json(&bytes).unwrap();
    assert_eq!(b.run_id, "case-1");
    assert_eq!(b.requested_by, auditor_id);
    assert!(b.generator.starts_with("pragmatic-server "));
    assert_eq!(b.redaction.mode, "detectors", "no view_raw: redacted");
    assert_eq!(b.redacted_slots.len(), 1, "the message with an email");
    assert!(b.independent);
    assert!(!b.anchors.is_empty());
    assert!(b.latest_checkpoint.is_some());
    assert!(b.verification_spec.is_some());
    assert!(!String::from_utf8_lossy(&bytes).contains("jane.doe"));

    let key = ServerKey::load(&ts.config.keys.signing_key_file).unwrap();
    let log_key = VerifierKey::parse(&key.vkey()).unwrap();
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
        log_keys: vec![log_key.clone()],
        ..TrustPolicy::default()
    };
    let report = evidence::verify(&b, &pinned, &OpensslTokens);
    assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");
    // The run is independently anchored on the server too.
    let s: Value = ts
        .get(&run_path("case-1", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["anchored_entries"], s["entries"], "{s}");
    assert_eq!(
        metric(&metrics(&ts).await, "pragmatic_anchor_lag_seconds"),
        Some(0.0)
    );
    // The console names each service as configured, or by its operator
    // set as an identifier, with the root its pinned anchors chain to.
    let html = console_page(&ts, &auditor, "/console/runs/case-1").await;
    assert!(
        html.contains(">Anchored by 2 independent timestamp services</h2>"),
        "{html}"
    );
    assert!(html.contains(
        "<span class=\"nm\">Alpha Time</span><span class=\"st\">RFC 3161 \u{b7} trusted</span>\
         <span class=\"root\">alpha Test Root</span>"
    ));
    assert!(html.contains(
        "<span class=\"nm m\">beta</span><span class=\"st\">RFC 3161 \u{b7} trusted</span>\
         <span class=\"root\">beta Test Root</span>"
    ));
    assert!(
        !html.contains("class=\"meter\""),
        "fully anchored: a hairline"
    );

    // Without pinned roots nothing counts: unanchored. With one operator's
    // roots only, the default policy of two is not met either.
    let unpinned = TrustPolicy {
        log_keys: vec![log_key.clone()],
        ..TrustPolicy::default()
    };
    let report = evidence::verify(&b, &unpinned, &OpensslTokens);
    assert_eq!(report.verdict, Verdict::Unanchored, "{report:#?}");
    let one = TrustPolicy {
        tsa_roots: pinned.tsa_roots[..1].to_vec(),
        ..pinned.clone()
    };
    assert_eq!(
        evidence::verify(&b, &one, &OpensslTokens).verdict,
        Verdict::Unanchored
    );
    // A bundle edited after it was signed fails against the pinned key.
    let mut forged = b.clone();
    forged.requested_by = "tok_someone_else".into();
    assert_eq!(
        evidence::verify(&forged, &pinned, &OpensslTokens).verdict,
        Verdict::Failed
    );

    // The full anchor log, as an administrator reads it, hides nothing.
    let log: Value = ts
        .get("/v1/anchors/log", &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    let file = json!({"leaves": log["leaves"].as_array().unwrap().iter()
        .map(|l| l["leaf"].clone()).collect::<Vec<_>>()});
    let audit = Audit {
        log: Some(AnchorLog::from_json(file.to_string().as_bytes()).unwrap()),
        witness_logs: Vec::new(),
    };
    let report = evidence::verify_with(&b, &pinned, &OpensslTokens, &audit);
    assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");

    // The reference verifier and the CLI agree, with the same pins.
    let dir = TempDir::new("bundle-files");
    let path = dir.path().join("case-1.evidence.json");
    std::fs::write(&path, &bytes).unwrap();
    let log_file = dir.path().join("log.json");
    std::fs::write(&log_file, file.to_string()).unwrap();
    let args = vec![
        "--tsa-roots".to_string(),
        format!("alpha={}", alpha.tsa.root_pem().display()),
        "--tsa-roots".to_string(),
        format!("beta={}", beta.tsa.root_pem().display()),
        "--log-key".to_string(),
        key.vkey(),
        "--log".to_string(),
        log_file.display().to_string(),
    ];
    if let Some(code) = reference_verifier(&path, &args) {
        assert_eq!(code, 0, "the reference verifier verifies the bundle");
    }
    if let Some(code) = cli_verify(&path, &args) {
        assert_eq!(code, 0, "pragmatic verify-evidence verifies the bundle");
    }
    if let Some(code) = cli_verify(&path, &["--log-key".to_string(), key.vkey()]) {
        assert_eq!(code, 3, "unpinned: unanchored");
    }

    // An unredacted bundle for a view_raw auditor, logged as a raw read.
    let (raw, raw_id) = ts.issue("auditor", &["*"], true).await;
    let full = Bundle::from_json(&bundle(&ts, &raw, "case-1", "").await).unwrap();
    assert_eq!(full.redaction.mode, "none");
    assert!(full.redacted_slots.is_empty());
    assert_eq!(
        evidence::verify(&full, &pinned, &OpensslTokens).verdict,
        Verdict::Verified
    );
    let records = ts.audit().await;
    assert!(records
        .iter()
        .any(|r| r["route"] == "/v1/runs/{id}/evidence"
            && r["token_id"] == raw_id
            && r["raw"] == true
            && r["redact"] == "none"));

    // The anchors API shows witnessed checkpoints, filtered by scope.
    let v: Value = ts.get("/v1/anchors", &auditor).await.json().await.unwrap();
    let cp = &v["checkpoints"][0];
    assert_eq!(cp["independent"], true, "{v}");
    assert_eq!(cp["witnesses"].as_array().unwrap().len(), 2);
    assert!(cp["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l["run_id"].is_null() || l["run_id"] == "case-1"));

    // A restart recovers the leaves from the anchor log: nothing unchanged
    // is anchored again, and the anchored length stays.
    let ts = ts.restart().await;
    let receipt = ts.app().anchor_batch(BatchReason::Interval).unwrap();
    assert!(
        receipt.is_none_or(|r| r.leaves.iter().all(|l| l.run_id.is_none())),
        "an unchanged run was anchored again"
    );
    let s: Value = ts
        .get(&run_path("case-1", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["anchored_entries"], s["entries"]);
    let v: Value = ts
        .post_json("/v1/verify-data", &ts.admin, json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["anchors"]["ok"], true, "{v}");
}

/// A witness that fails is retried between batches, and the run becomes
/// independently anchored once enough operators have answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_witnesses_are_retried_until_the_run_is_independently_anchored() {
    if !openssl_usable() {
        return;
    }
    let alpha = TsaServer::start("alpha");
    let beta = TsaServer::start("beta");
    beta.healthy
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let ts = TestServer::start_integrated(
        |c| {
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.tsa = vec![tsa_config("alpha", &alpha), tsa_config("beta", &beta)];
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    ts.app().anchor_batch(BatchReason::Interval).unwrap();
    let s: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["anchored_entries"], 0, "one operator is not two");
    assert!(metric(&metrics(&ts).await, "pragmatic_anchor_failures_total").unwrap() >= 1.0);
    beta.healthy
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut anchored = Value::Null;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        let a = ts.handle.as_ref().unwrap().app.clone();
        tokio::task::spawn_blocking(move || a.anchor_retry())
            .await
            .unwrap();
        let s: Value = ts
            .get(&run_path("r", ""), &ts.admin)
            .await
            .json()
            .await
            .unwrap();
        anchored = s["anchored_entries"].clone();
        if anchored == s["entries"] {
            break;
        }
    }
    let s: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(anchored, s["entries"], "the retry anchored the run: {s}");
}

/// A journal cut back after it was anchored contradicts its leaf: the
/// anchoring library refuses the snapshot and the server marks the run
/// regressed, so its appends are refused until an administrator acts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_rolled_back_after_it_was_anchored_is_marked_regressed() {
    let (url, got) = webhook_receiver().await;
    let hook_dir = TempDir::new("regress-hook");
    let mut ts = TestServer::start_integrated(
        |c| {
            c.lease_ttl_secs = 60;
            c.webhooks.push(webhook(&hook_dir, &url, &["regressed"]));
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let w = finished(&ts, &agent, "r", &["one", "two", "three"]).await;
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    assert!(receipt
        .leaves
        .iter()
        .any(|l| l.run_id.as_deref() == Some("r")));
    ts.stop().await;
    // Cut the journal back to its first three entries, and its meta with
    // it, as a restore of an old copy would.
    let data = ts.data_dir();
    let keep = 3u64;
    let journal_path = run_file_in(&data, "r", ".journal");
    let mut bytes = pragmatic::journal::header(0).to_vec();
    for c in 0..keep {
        bytes.extend(w.journal.frame_bytes(c).unwrap());
    }
    std::fs::write(&journal_path, &bytes).unwrap();
    let meta_path = run_file_in(&data, "r", ".meta.json");
    let mut meta: pragmatic_server::store::Meta =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    meta.entries = keep;
    meta.byte_len = bytes.len() as u64;
    meta.head = pragmatic::encoding::hex_encode(&w.journal.get(keep - 1).unwrap().hash);
    meta.last_anchor_leaf = None;
    std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
    let ts = ts.restart().await;
    // Self-anchoring only: the leaf never became independent, so startup
    // saw nothing wrong. The next batch does.
    let _ = ts.app().anchor_batch(BatchReason::Interval);
    let s: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(s["status"], "regressed", "{s}");
    let event = got.wait_for("regressed").await.expect("regressed webhook");
    assert_eq!(event["run_id"], "r");
    // An administrator accepts the journal; the refusal is not reported
    // again while the run has not grown past its leaf.
    let resp = ts
        .post_json(&run_path("r", "/accept-regression"), &ts.admin, json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = ts.app().anchor_batch(BatchReason::Interval);
    let s: Value = ts
        .get(&run_path("r", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(s["status"], "regressed", "{s}");
}

/// A log witnessed by another Stet Server in witness mode: the
/// anchoring library's witness client against the server's witness
/// service, and a bundle that verifies with the witness key pinned and
/// against the witness's own cosigned history.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_witnessed_by_another_server_verifies_with_the_witness_history() {
    const CLIENT: &str = "prag_log_client_token";
    let keys = TempDir::new("log-keys");
    let log_key = ServerKey::generate("log.example").unwrap();
    let key_path = keys.path().join("log.key");
    log_key.write_new(&key_path).unwrap();
    let witness = TestServer::start_integrated(
        |c| {
            enable_witness_mode(
                c,
                vec![WitnessOrigin {
                    name: "log".into(),
                    origin: log_key.origin().into(),
                    log_vkeys: vec![log_key.vkey()],
                    token_sha256: token_sha256(CLIENT),
                }],
            );
        },
        fast(),
    )
    .await;
    let token_file = keys.path().join("witness.token");
    std::fs::write(&token_file, format!("{CLIENT}\n")).unwrap();
    let wvkey = witness_cosigner().verifier_key().encode();
    let ts = TestServer::start_integrated(
        |c| {
            c.name = "log.example".into();
            c.keys.signing_key_file = key_path.clone();
            c.anchoring.allow_self_anchoring = false;
            c.anchoring.min_independent_operators = 1;
            c.anchoring.witness = vec![WitnessConfig {
                url: witness.url.clone(),
                vkey: wvkey.clone(),
                operator: "witness-operator".into(),
                token_file: token_file.clone(),
            }];
        },
        fast(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    finished(&ts, &agent, "r", &["one"]).await;
    let (auditor, _) = ts.issue("auditor", &["*"], true).await;
    let first = Bundle::from_json(&bundle(&ts, &auditor, "r", "?anchor=now").await).unwrap();
    assert!(!first.anchors.is_empty());
    // A second batch extends the tree, so the witness checks a consistency
    // proof from the size it cosigned.
    finished(&ts, &agent, "s", &["two"]).await;
    let b = Bundle::from_json(&bundle(&ts, &auditor, "s", "?anchor=now").await).unwrap();
    let policy = TrustPolicy {
        witness_keys: vec![WitnessKey {
            operator: "witness-operator".into(),
            key: VerifierKey::parse(&wvkey).unwrap(),
            not_before: None,
            not_after: None,
        }],
        log_keys: vec![VerifierKey::parse(&log_key.vkey()).unwrap()],
        min_operators: 1,
        ..TrustPolicy::default()
    };
    let report = evidence::verify(&b, &policy, &NoTsaVerifier);
    assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");

    // The witness's cosigned history, assembled from its log endpoint.
    let page: Value = witness
        .get("/v1/witness/log/log", &witness.admin)
        .await
        .json()
        .await
        .unwrap();
    let cosigned = page["cosigned"].as_array().unwrap();
    assert!(cosigned.len() >= 2, "{page}");
    let file = json!({
        "witness": page["witness"],
        "origin": page["origin_line"],
        "checkpoints": cosigned.iter().map(|c| c["checkpoint"].clone()).collect::<Vec<_>>(),
    });
    let history = WitnessLog::from_json(file.to_string().as_bytes()).unwrap();
    let audit = Audit {
        log: None,
        witness_logs: vec![history],
    };
    let report = evidence::verify_with(&b, &policy, &NoTsaVerifier, &audit);
    assert_eq!(report.verdict, Verdict::Verified, "{report:#?}");
    let dir = TempDir::new("witnessed-bundle");
    let path = dir.path().join("s.evidence.json");
    std::fs::write(&path, b.to_json()).unwrap();
    let wlog = dir.path().join("witness-log.json");
    std::fs::write(&wlog, file.to_string()).unwrap();
    let args = vec![
        "--witness-key".to_string(),
        format!("witness-operator={wvkey}"),
        "--log-key".to_string(),
        log_key.vkey(),
        "--min-operators".to_string(),
        "1".to_string(),
        "--witness-log".to_string(),
        wlog.display().to_string(),
    ];
    if let Some(code) = reference_verifier(&path, &args) {
        assert_eq!(code, 0);
    }
    if let Some(code) = cli_verify(&path, &args) {
        assert_eq!(code, 0);
    }
    // The witness record is a run of the witness server, anchored there
    // like any other.
    let s: Value = witness
        .get(&run_path("pragmatic:witness:log", ""), &witness.admin)
        .await
        .json()
        .await
        .unwrap();
    assert!(s["entries"].as_u64().unwrap() >= 3, "{s}");
    let receipt = witness
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    assert!(receipt
        .leaves
        .iter()
        .any(|l| l.run_id.as_deref() == Some("pragmatic:witness:log")));
}

/// Keygen makes the log key with its origin, and the server refuses a
/// configured name the origin does not carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_origin_is_fixed_by_the_first_key() {
    let dir = TempDir::new("origin");
    let mut config = test_config(dir.path());
    let key = ServerKey::generate("first-name").unwrap();
    key.write_new(&config.keys.signing_key_file).unwrap();
    config.name = "another-name".into();
    let err = pragmatic_server::server::start(
        config.clone(),
        [0; 32],
        pragmatic_server::server::Hooks::stubs(&config),
    )
    .await
    .err()
    .unwrap();
    assert!(err.0.contains("first-name"), "{err}");
    // An empty name takes the key's.
    config.name = String::new();
    let handle = pragmatic_server::server::start(
        config.clone(),
        [0; 32],
        pragmatic_server::server::Hooks::stubs(&config),
    )
    .await
    .unwrap();
    assert_eq!(handle.app.server_name, "first-name");
    handle.shutdown().await.unwrap();
}
