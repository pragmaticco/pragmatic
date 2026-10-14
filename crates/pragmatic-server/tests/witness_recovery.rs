//! A witness never cosigns from a record that may have forgotten what it
//! cosigned (design 4.8): a record rolled back after it was anchored, a
//! record whose files are gone while the anchor log holds a leaf for it,
//! and every record a restore brought back. Each refuses (503) until an
//! administrator resumes it with the latest checkpoint the witness
//! cosigned, taken from outside the host.

mod common;

use std::time::Duration;

use common::*;
use pragmatic::encoding::base64_encode;
use pragmatic::merkle;
use pragmatic::note::{self, Checkpoint, Note, NoteSignature, SignatureType};
use pragmatic::sha256::Digest;
use pragmatic_anchor::tsa::TsaPolicy;
use pragmatic_anchor::RetryPolicy;
use pragmatic_server::anchoring::{OfflineAnchoring, Options};
use pragmatic_server::config::WitnessOrigin;
use pragmatic_server::hooks::BatchReason;
use pragmatic_server::keys::ServerKey;
use pragmatic_server::tokens::token_sha256;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const ORIGIN: &str = "example.com/log";
const NAME: &str = "example-log";
const RECORD: &str = "pragmatic:witness:example-log";
const CLIENT: &str = "prag_witness_client_token";

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

fn leaves(prefix: &str, n: usize) -> Vec<Digest> {
    (0..n)
        .map(|i| merkle::leaf_hash(format!("{prefix}{i}").as_bytes()))
        .collect()
}

/// A checkpoint of `tree` signed by the log key.
fn signed(key: &ServerKey, tree: &[Digest]) -> String {
    let body = Checkpoint {
        origin: ORIGIN.into(),
        tree_size: tree.len() as u64,
        root: merkle::root(tree),
        extensions: vec![],
    }
    .encode()
    .unwrap();
    Note {
        signatures: vec![NoteSignature {
            name: ORIGIN.into(),
            key_id: note::key_id(ORIGIN, SignatureType::Ed25519, &key.public_key()),
            signature: key.sign(body.as_bytes()).to_vec(),
        }],
        body,
    }
    .encode()
    .unwrap()
}

fn body(old: usize, proof: &[Digest], checkpoint: &str) -> String {
    let mut out = format!("old {old}\n");
    for p in proof {
        out.push_str(&base64_encode(p));
        out.push('\n');
    }
    out.push('\n');
    out.push_str(checkpoint);
    out
}

async fn submit(ts: &TestServer, text: String) -> (StatusCode, String) {
    let resp = ts
        .req(Method::POST, "/add-checkpoint", CLIENT)
        .body(text)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

/// The checkpoint with the witness's cosignature line, as the witnessed
/// log keeps it (what an administrator resumes from).
fn cosigned(checkpoint: &str, line: &str) -> String {
    format!("{checkpoint}{}\n", line.trim_end())
}

fn origins(log: &ServerKey) -> Vec<WitnessOrigin> {
    vec![WitnessOrigin {
        name: NAME.into(),
        origin: ORIGIN.into(),
        log_vkeys: vec![log.vkey()],
        token_sha256: token_sha256(CLIENT),
    }]
}

async fn witness(log: &ServerKey) -> TestServer {
    let o = origins(log);
    TestServer::start_integrated(move |c| enable_witness_mode(c, o), fast()).await
}

async fn summary(ts: &TestServer, run: &str) -> Value {
    ts.get(&run_path(run, ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap()
}

async fn resume(ts: &TestServer, checkpoint: &str) -> (StatusCode, Value) {
    let resp = ts
        .post_json(
            &format!("/v1/witness/resume/{NAME}"),
            &ts.admin,
            json!({"checkpoint": checkpoint, "reason": "re-established from the log's own copy"}),
        )
        .await;
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
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

/// A record rolled back after it was anchored (it lost the size-5
/// cosignature) is `regressed` from startup, before any batch, and the
/// witness refuses to cosign a fork of the tree it cosigned at size 5
/// until an administrator resumes it from that checkpoint. Acceptance as
/// for a run is refused for a witness record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rolled_back_record_cosigns_nothing_until_it_is_resumed() {
    let log = ServerKey::generate_for_origin(ORIGIN).unwrap();
    let mut ts = witness(&log).await;
    let tree = leaves("leaf-", 5);
    let cp3 = signed(&log, &tree[..3]);
    let (status, line3) = submit(&ts, body(0, &[], &cp3)).await;
    assert_eq!(status, StatusCode::OK, "{line3}");
    let cp5 = signed(&log, &tree);
    let proof = merkle::consistency_proof(3, &tree).unwrap();
    let (status, line5) = submit(&ts, body(3, &proof, &cp5)).await;
    assert_eq!(status, StatusCode::OK, "{line5}");
    let receipt = ts
        .app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    assert!(receipt
        .leaves
        .iter()
        .any(|l| l.run_id.as_deref() == Some(RECORD)));
    ts.stop().await;

    // The record loses its size-5 cosignature.
    roll_back(&ts.data_dir(), RECORD, 2);
    let ts = ts.restart().await;
    assert_eq!(summary(&ts, RECORD).await["status"], "regressed");

    // A size-6 tree that extends size 3 but not size 5: never cosigned.
    let mut forked = tree[..3].to_vec();
    forked.extend(leaves("fork-", 3));
    let fork_proof = merkle::consistency_proof(3, &forked).unwrap();
    let cp6 = signed(&log, &forked);
    let (status, text) = submit(&ts, body(3, &fork_proof, &cp6)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert_eq!(stored(&ts, RECORD).len(), 2, "nothing was recorded");

    // accept-regression is not how a witness record comes back.
    let resp = ts
        .post_json(
            &run_path(RECORD, "/accept-regression"),
            &ts.admin,
            json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.text().await.unwrap().contains("witness-resume"));

    // Resuming needs a checkpoint this witness cosigned...
    let (status, _) = resume(&ts, &cp5).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no cosignature line");
    // ...and not one older than a cosignature the record still holds
    // would be fine, but it must carry the log's signature.
    let impostor = ServerKey::generate_for_origin(ORIGIN).unwrap();
    let (status, _) = resume(&ts, &cosigned(&signed(&impostor, &tree), &line5)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "not the log's signature");

    // The latest cosigned checkpoint, from the log's own copy.
    let (status, v) = resume(&ts, &cosigned(&cp5, &line5)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["tree_size"], 5);
    assert_ne!(summary(&ts, RECORD).await["status"], "regressed");
    // The witness is at size 5 again: the fork is refused as such, and a
    // consistent extension is cosigned.
    let (status, text) = submit(&ts, body(3, &fork_proof, &cp6)).await;
    assert_eq!((status, text.as_str()), (StatusCode::CONFLICT, "5\n"));
    let mut grown = tree.clone();
    grown.extend(leaves("more-", 1));
    let proof = merkle::consistency_proof(5, &grown).unwrap();
    let (status, text) = submit(&ts, body(5, &proof, &signed(&log, &grown))).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    // The resumed checkpoint is in the witness's published history.
    let page: Value = ts
        .get(&format!("/v1/witness/log/{NAME}"), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    let sizes: Vec<(u64, bool)> = page["cosigned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["tree_size"].as_u64().unwrap(), c["resumed"] == true))
        .collect();
    assert_eq!(sizes, vec![(3, false), (5, true), (6, false)]);
    // A record that takes writes has nothing to resume.
    let (status, _) = resume(&ts, &cosigned(&cp5, &line5)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A record whose files are gone while the anchor log holds a leaf for it
/// was lost, not never written: it is `missing`, never begun afresh, so
/// the witness cannot cosign a fork from size 0. Resuming begins it again
/// from the latest checkpoint cosigned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_record_is_never_begun_afresh() {
    let log = ServerKey::generate_for_origin(ORIGIN).unwrap();
    let mut ts = witness(&log).await;
    let tree = leaves("leaf-", 5);
    let cp5 = signed(&log, &tree);
    let (status, line5) = submit(&ts, body(0, &[], &cp5)).await;
    assert_eq!(status, StatusCode::OK);
    ts.app()
        .anchor_batch(BatchReason::Interval)
        .unwrap()
        .unwrap();
    ts.stop().await;
    let data = ts.data_dir();
    std::fs::remove_file(run_file_in(&data, RECORD, ".journal")).unwrap();
    std::fs::remove_file(run_file_in(&data, RECORD, ".meta.json")).unwrap();
    let ts = ts.restart().await;
    assert_eq!(summary(&ts, RECORD).await["status"], "missing");

    let forked = leaves("fork-", 6);
    let (status, _) = submit(&ts, body(0, &[], &signed(&log, &forked))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!run_file_in(&data, RECORD, ".journal").exists());

    let (status, v) = resume(&ts, &cosigned(&cp5, &line5)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, text) = submit(&ts, body(0, &[], &signed(&log, &forked))).await;
    assert_eq!((status, text.as_str()), (StatusCode::CONFLICT, "5\n"));
    let j = stored(&ts, RECORD);
    assert_eq!(note_kinds(&j), vec!["run.start", "witness.resume"]);
}

/// The anchor log alone decides whether a record may be begun: a record
/// the log never anchored is created on first contact as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_log_never_anchored_is_created_on_first_contact() {
    let log = ServerKey::generate_for_origin(ORIGIN).unwrap();
    let ts = witness(&log).await;
    let (status, text) = submit(&ts, body(0, &[], &signed(&log, &leaves("leaf-", 2)))).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(summary(&ts, RECORD).await["entries"], 2);
}

/// A restore brings every witness record back as old as the backup, and
/// the anchor log with it, so nothing on the host can tell what was
/// cosigned since: every restored record is held until it is resumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_witness_holds_every_record_until_it_is_resumed() {
    let log = ServerKey::generate_for_origin(ORIGIN).unwrap();
    let mut ts = witness(&log).await;
    let tree = leaves("leaf-", 5);
    let cp3 = signed(&log, &tree[..3]);
    let (status, _) = submit(&ts, body(0, &[], &cp3)).await;
    assert_eq!(status, StatusCode::OK);
    ts.app().anchor_batch(BatchReason::Interval).unwrap();
    let backups = TempDir::new("witness-backup");
    let target = backups.path().join("b1");
    let (config, t) = (ts.config.clone(), target.clone());
    tokio::task::spawn_blocking(move || pragmatic_server::ops::backup(&config, &t))
        .await
        .unwrap()
        .unwrap();
    let proof = merkle::consistency_proof(3, &tree).unwrap();
    let cp5 = signed(&log, &tree);
    let (status, line5) = submit(&ts, body(3, &proof, &cp5)).await;
    assert_eq!(status, StatusCode::OK);
    ts.stop().await;

    let mut restored = ts.config.clone();
    restored.data_dir = ts.dir.path().join("restored");
    let (cfg, from) = (restored.clone(), target.clone());
    let report = tokio::task::spawn_blocking(move || {
        let anchoring = OfflineAnchoring {
            config: cfg.clone(),
        };
        pragmatic_server::ops::restore(&cfg, &from, None, &anchoring)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(report["witness_records_held"], json!([RECORD]), "{report}");
    let o = origins(&log);
    let (data, key) = (
        restored.data_dir.clone(),
        ts.config.keys.signing_key_file.clone(),
    );
    let ts2 = TestServer::start_integrated(
        move |c| {
            c.data_dir = data;
            c.keys.signing_key_file = key;
            enable_witness_mode(c, o);
        },
        fast(),
    )
    .await;
    assert_eq!(summary(&ts2, RECORD).await["status"], "regressed");

    let mut forked = tree[..3].to_vec();
    forked.extend(leaves("fork-", 3));
    let fork_proof = merkle::consistency_proof(3, &forked).unwrap();
    let cp6 = signed(&log, &forked);
    let (status, _) = submit(&ts2, body(3, &fork_proof, &cp6)).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a restored witness must not cosign a fork of a tree it cosigned after the backup"
    );
    let (status, v) = resume(&ts2, &cosigned(&cp5, &line5)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, text) = submit(&ts2, body(3, &fork_proof, &cp6)).await;
    assert_eq!((status, text.as_str()), (StatusCode::CONFLICT, "5\n"));
    // The resume is in the access log, durable before it acted.
    ts2.app().access.flush().await.unwrap();
    assert!(ts2
        .audit()
        .await
        .iter()
        .any(|r| r["kind"] == "intent" && r["action"] == "witness_resume"));
}
