//! End-to-end anchoring: batches of real journals through local OpenSSL
//! TSAs run as different operators and a tlog-witness cosigner over HTTP,
//! retries, restarts, and the evidence anchor section checked the way an
//! offline verifier would. TSA tests skip, with a message, when `openssl`
//! is missing.

mod support;

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pragmatic::encoding::{base64_decode, hex_decode, hex_decode_exact};
use pragmatic::journal::{Event, Journal, META};
use pragmatic::json::Json;
use pragmatic::merkle::{leaf_hash, verify_consistency, verify_inclusion};
use pragmatic::note::{verify_note, Checkpoint, Note, NoteSignature};
use pragmatic::sha256::{sha256, Digest};
use pragmatic_anchor::leaf::hmac_run_id;
use pragmatic_anchor::tsa::{OpensslVerifier, TsaClient, TsaConfig, TsaPolicy, UreqTransport};
use pragmatic_anchor::witness::{
    verify_cosignature, Cosigner, WitnessClient, WitnessConfig, WitnessOrigin, WitnessService,
};
use pragmatic_anchor::{
    AnchorError, Anchorer, AnchorerConfig, ExternalWitness, IndependencePolicy, Leaf, LeafType,
    LogSigner, RetryPolicy, RunIdMode, SkipReason, Snapshot, ACCESS_LOG_ID, WITNESS_RUN_ID,
};
use support::{openssl_available, TestServer, TsaServer};

const ORIGIN: &str = "pragmatic/test-server";

fn signer() -> LogSigner {
    LogSigner::from_seed(ORIGIN, [7u8; 32]).unwrap()
}

/// A journal with a `run.start` note and `steps` markers.
fn journal(run_id: &str, steps: usize) -> Journal {
    let mut j = Journal::new(None);
    let data = format!(
        "{{\"run_id\":\"{run_id}\",\"nonce\":\"{}\",\"sdk\":\"test\",\"sdk_version\":\"0\",\"format\":2,\"labels\":{{}}}}",
        "0".repeat(32)
    );
    j.append(
        META,
        Event::Note {
            kind: "run.start".into(),
            data,
            payload: vec![],
        },
    )
    .unwrap();
    grow(&mut j, steps);
    j
}

fn grow(j: &mut Journal, steps: usize) {
    for i in 0..steps {
        j.append(
            &[],
            Event::Marker {
                name: format!("step-{i}"),
            },
        )
        .unwrap();
    }
}

fn snap(id: &str, j: &Journal) -> Snapshot {
    Snapshot {
        leaf_type: LeafType::Run,
        id: id.to_string(),
        entries: j.len(),
        head: j.head(),
    }
}

/// A provider whose snapshots the test sets before each batch.
#[derive(Clone, Default)]
struct Snapshots(Arc<Mutex<Vec<Snapshot>>>);

impl Snapshots {
    fn set(&self, s: Vec<Snapshot>) {
        *self.0.lock().unwrap() = s;
    }

    fn provider(&self) -> impl Fn() -> Result<Vec<Snapshot>, String> + '_ {
        move || Ok(self.0.lock().unwrap().clone())
    }
}

fn fast_tsa() -> TsaPolicy {
    TsaPolicy {
        timeout: Duration::from_secs(10),
        min_spacing: Duration::ZERO,
        max_attempts: 1,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    }
}

fn tsa_witness(server: &TsaServer, operator: &str) -> ExternalWitness {
    ExternalWitness::Tsa(TsaClient::new(
        TsaConfig::new(&server.server.url, operator, server.tsa.root_pem()).unwrap(),
        fast_tsa(),
        Arc::new(UreqTransport::new()),
        OpensslVerifier::default(),
    ))
}

fn config(min: usize) -> AnchorerConfig {
    AnchorerConfig {
        id_mode: RunIdMode::Plain,
        policy: IndependencePolicy {
            min_independent_operators: min,
        },
        retry: RetryPolicy {
            initial_backoff: Duration::ZERO,
            ..RetryPolicy::default()
        },
    }
}

fn open(dir: &Path, witnesses: Vec<ExternalWitness>, cfg: AnchorerConfig) -> Anchorer {
    Anchorer::open(dir, signer(), witnesses, cfg).unwrap().0
}

/// Check one run's anchor section as an offline verifier would (design 5.3
/// step 8), with the TSA tokens re-verified by OpenSSL against the roots
/// given here.
fn verify_section(
    anchorer: &Anchorer,
    run_id: &str,
    journal_heads: &[(u64, Digest)],
    roots: &[(&str, std::path::PathBuf)],
) -> Json {
    let section = anchorer.anchor_section(LeafType::Run, run_id).unwrap();
    let anchors = section.anchors_json();
    let latest_text = section.latest_checkpoint.clone().unwrap();
    let latest_note = Note::parse(&latest_text).unwrap();
    let latest = Checkpoint::parse(&latest_note.body).unwrap();
    let vkey = signer().verifier_key();
    assert!(verify_note(&latest_note, std::slice::from_ref(&vkey)).is_ok());
    let mut prev_index: Option<u64> = None;
    for a in anchors.as_array().unwrap() {
        let keys: Vec<&str> = a
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "seq",
                "tree_size",
                "leaf_index",
                "leaf",
                "inclusion_proof",
                "root",
                "checkpoint",
                "anchor_digest",
                "consistency_to_latest",
                "witnesses"
            ]
        );
        let num = |k: &str| a.get(k).unwrap().as_u64_strict().unwrap();
        let hex32 = |s: &Json| -> Digest { hex_decode_exact(s.as_str().unwrap()).unwrap() };
        let list = |k: &str| -> Vec<Digest> {
            a.get(k)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(hex32)
                .collect()
        };
        let (tree_size, leaf_index) = (num("tree_size"), num("leaf_index"));
        let leaf_bytes = hex_decode(a.get("leaf").unwrap().as_str().unwrap()).unwrap();
        let leaf = Leaf::decode(&leaf_bytes).unwrap();
        // The leaf names the run and a state the journal really had.
        assert_eq!(leaf.id, run_id.as_bytes());
        assert!(journal_heads.contains(&(leaf.entries, leaf.head)));
        // The chain is continuous.
        assert_eq!(leaf.prev_leaf_index, prev_index);
        prev_index = Some(leaf_index);
        // Inclusion under the checkpoint root.
        let root = hex32(a.get("root").unwrap());
        assert!(verify_inclusion(
            &leaf_hash(&leaf_bytes),
            leaf_index,
            tree_size,
            &list("inclusion_proof"),
            &root
        ));
        // The checkpoint states that size and root, is signed by the log
        // key, and its body hashes to anchor_digest.
        let note = Note::parse(a.get("checkpoint").unwrap().as_str().unwrap()).unwrap();
        assert!(verify_note(&note, std::slice::from_ref(&vkey)).is_ok());
        let cp = Checkpoint::parse(&note.body).unwrap();
        assert_eq!((cp.tree_size, cp.root), (tree_size, root));
        let digest = hex32(a.get("anchor_digest").unwrap());
        assert_eq!(digest, sha256(note.body.as_bytes()));
        // Consistent with the latest checkpoint.
        assert!(verify_consistency(
            tree_size,
            latest.tree_size,
            &root,
            &latest.root,
            &list("consistency_to_latest")
        ));
        // Every RFC 3161 token verifies with OpenSSL against its operator's
        // pinned root only.
        for w in a.get("witnesses").unwrap().as_array().unwrap() {
            if w.get("type").unwrap().as_str() != Some("rfc3161") {
                continue;
            }
            let operator = w.get("operator").unwrap().as_str().unwrap();
            let token = base64_decode(w.get("token").unwrap().as_str().unwrap()).unwrap();
            let certs = w.get("certs_pem").unwrap().as_str().unwrap();
            for (op, root) in roots {
                let ok = OpensslVerifier::default()
                    .verify_token(&token, &digest, root, certs)
                    .is_ok();
                assert_eq!(ok, *op == operator, "{operator} token against {op}'s root");
            }
        }
    }
    anchors
}

#[test]
fn end_to_end_batches_through_two_independent_tsas() {
    if !openssl_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let alpha = TsaServer::start("Alpha", 0);
    let beta = TsaServer::start("Beta", 0);
    let roots = [
        ("digicert", alpha.tsa.root_pem()),
        ("sectigo", beta.tsa.root_pem()),
    ];
    let anchorer = open(
        dir.path(),
        vec![
            tsa_witness(&alpha, "DigiCert"),
            tsa_witness(&beta, "Sectigo"),
        ],
        config(2),
    );
    let snaps = Snapshots::default();
    let mut r1 = journal("r1", 2);
    let r2 = journal("r2", 4);
    let r4 = journal("r4", 4);
    let mut r5 = journal("r5", 1);
    let access = Snapshot {
        leaf_type: LeafType::AccessLog,
        id: "access".into(),
        entries: 10,
        head: [3; 32],
    };
    snaps.set(vec![
        snap("r2", &r2),
        snap("r1", &r1),
        access.clone(),
        snap("r4", &r4),
        snap("r5", &r5),
        // A run created by PUT, with no entries yet.
        Snapshot {
            leaf_type: LeafType::Run,
            id: "empty".into(),
            entries: 0,
            head: Journal::new(None).head(),
        },
    ]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    let cp = out.committed.clone().unwrap();
    assert_eq!((cp.seq, cp.tree_size()), (0, 6));
    let ids: Vec<&str> = out.leaves.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(ids, ["empty", "r1", "r2", "r4", "r5", "access"]);
    assert_eq!(out.attempts.len(), 2);
    assert!(
        out.attempts.iter().all(|a| a.result.is_ok()),
        "{:?}",
        out.attempts
    );
    assert_eq!(out.newly_independent, vec![0]);
    assert_eq!(out.advanced.len(), 6);
    let r1_adv = out.advanced.iter().find(|a| a.id == "r1").unwrap();
    assert_eq!((r1_adv.entries, r1_adv.head), (r1.len(), r1.head()));
    assert_eq!(alpha.server.count(), 1);
    assert_eq!(beta.server.count(), 1);
    let first_head = (r1.len(), r1.head());
    verify_section(&anchorer, "r1", &[first_head], &roots);

    // Batch 2: r1 grew, r2 is unchanged, r4 went backwards, r5 was
    // rewritten at the same length, r3 is new.
    grow(&mut r1, 3);
    let r3 = journal("r3", 1);
    let r4_rolled_back = journal("r4", 2);
    r5 = journal("r5", 1); // same length, new salts: another head
    snaps.set(vec![
        snap("r1", &r1),
        snap("r2", &r2),
        snap("r3", &r3),
        snap("r4", &r4_rolled_back),
        snap("r5", &r5),
    ]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    let ids: Vec<&str> = out.leaves.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(ids, ["r1", "r3"]);
    let reasons: Vec<(&str, &SkipReason)> = out
        .skipped
        .iter()
        .map(|s| (s.id.as_str(), &s.reason))
        .collect();
    assert_eq!(
        reasons,
        [
            ("r2", &SkipReason::Unchanged),
            ("r4", &SkipReason::Regressed { anchored: 5 }),
            ("r5", &SkipReason::HeadMismatch),
        ]
    );
    assert_eq!(out.newly_independent, vec![1]);
    let anchors = verify_section(
        &anchorer,
        "r1",
        &[first_head, (r1.len(), r1.head())],
        &roots,
    );
    assert_eq!(anchors.as_array().unwrap().len(), 2);
    let status = anchorer.status();
    assert_eq!(status.latest_seq, Some(1));
    assert_eq!(status.latest_independent_seq, Some(1));
    assert_eq!(status.consecutive_short_batches, 0);
    assert!(status.pending.is_empty());

    // Nothing changed: no batch, no requests.
    snaps.set(vec![snap("r1", &r1)]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    assert!(out.committed.is_none());
    assert_eq!(alpha.server.count(), 2);

    // The access log has its own chain.
    let section = anchorer
        .anchor_section(
            LeafType::AccessLog,
            std::str::from_utf8(ACCESS_LOG_ID).unwrap(),
        )
        .unwrap();
    assert_eq!(section.anchors.len(), 1);
    assert_eq!(section.anchors[0].leaf.entries, access.entries);
    assert!(section.anchors[0].independent);
    assert_eq!(section.anchored_entries(), access.entries);
}

#[test]
fn aliased_operators_do_not_make_a_checkpoint_independent() {
    if !openssl_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let a = TsaServer::start("Sectigo", 0);
    let b = TsaServer::start("Entrust", 0);
    let anchorer = open(
        dir.path(),
        vec![tsa_witness(&a, "Sectigo"), tsa_witness(&b, "Entrust")],
        config(2),
    );
    let snaps = Snapshots::default();
    let mut j = journal("r", 1);
    for batch in 1..=3u32 {
        snaps.set(vec![snap("r", &j)]);
        let out = anchorer.run_batch(&snaps.provider()).unwrap();
        assert!(out.attempts.iter().all(|a| a.result.is_ok()));
        assert!(out.newly_independent.is_empty());
        assert!(out.advanced.is_empty());
        assert_eq!(anchorer.status().consecutive_short_batches, batch);
        grow(&mut j, 1);
    }
    // Every witness succeeded, so nothing is left to retry.
    assert!(anchorer.status().pending.is_empty());
    let section = anchorer.anchor_section(LeafType::Run, "r").unwrap();
    assert!(section.anchors.iter().all(|a| !a.independent));
    assert!(section
        .anchors
        .iter()
        .all(|a| a.witnesses.iter().all(|w| w.operator == "sectigo")));
    assert_eq!(section.anchored_entries(), 0);
}

#[test]
fn failed_witnesses_are_retried_against_the_same_checkpoint_across_restarts() {
    if !openssl_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let alpha = TsaServer::start("Alpha", 0);
    let beta = TsaServer::start("Beta", 0);
    beta.healthy.store(false, Ordering::SeqCst);
    let witnesses = || {
        vec![
            tsa_witness(&alpha, "DigiCert"),
            tsa_witness(&beta, "Sectigo"),
        ]
    };
    let snaps = Snapshots::default();
    let j = journal("r", 2);
    snaps.set(vec![snap("r", &j)]);
    let digest0;
    {
        let anchorer = open(dir.path(), witnesses(), config(2));
        let out = anchorer.run_batch(&snaps.provider()).unwrap();
        digest0 = out.committed.unwrap().signed.anchor_digest;
        assert_eq!(out.attempts.iter().filter(|a| a.result.is_err()).count(), 1);
        assert!(out.advanced.is_empty());
        let status = anchorer.status();
        assert_eq!(status.pending, vec![0]);
        assert_eq!(status.consecutive_short_batches, 1);
        assert_eq!(status.witness_failures_total, 1);
        // Still down: the retry fails again, alpha is not asked twice.
        let out = anchorer.retry_pending();
        assert_eq!(out.attempts.len(), 1);
        assert_eq!(alpha.server.count(), 1);
    }
    // A restart finds the checkpoint still owed by beta.
    beta.healthy.store(true, Ordering::SeqCst);
    let anchorer = open(dir.path(), witnesses(), config(2));
    assert_eq!(anchorer.status().pending, vec![0]);
    let out = anchorer.retry_pending();
    assert_eq!(out.attempts.len(), 1);
    assert!(out.attempts[0].result.is_ok());
    assert_eq!(out.newly_independent, vec![0]);
    assert_eq!(out.advanced.len(), 1);
    assert_eq!(
        out.advanced[0].id, "r",
        "run ids come back from the batch index"
    );
    assert_eq!(out.advanced[0].entries, j.len());
    // Beta timestamped the same checkpoint's digest, with a fresh nonce.
    let section = anchorer.anchor_section(LeafType::Run, "r").unwrap();
    assert_eq!(section.anchors[0].anchor_digest, digest0);
    assert_eq!(section.anchors[0].witnesses.len(), 2);
    assert!(anchorer.status().pending.is_empty());
}

/// Serve a witness service over HTTP with a bearer token.
fn witness_server(svc: Arc<WitnessService>) -> TestServer {
    TestServer::start(move |req| {
        assert_eq!(req.path, "/add-checkpoint");
        let authorized = req
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer wtoken");
        if !authorized {
            return (401, "text/plain".into(), b"unauthorized\n".to_vec());
        }
        match svc.add_checkpoint("test-server", &req.body, 1_760_000_000) {
            Ok(body) => (200, "text/plain".into(), body.into_bytes()),
            Err(e) => (e.status(), e.content_type().into(), e.body().into_bytes()),
        }
    })
}

#[test]
fn a_tlog_witness_cosigns_over_http_and_keeps_its_own_journal() {
    if !openssl_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let wdir = tempfile::tempdir().unwrap();
    let cosigner = Cosigner::from_seed("witness.example", [8u8; 32]).unwrap();
    let wkey = cosigner.verifier_key();
    let svc = Arc::new(
        WitnessService::open(
            wdir.path().join("witness.journal"),
            cosigner,
            vec![WitnessOrigin {
                name: "test-server".into(),
                origin: ORIGIN.into(),
                log_keys: vec![signer().verifier_key()],
            }],
        )
        .unwrap(),
    );
    let wserver = witness_server(svc.clone());
    let alpha = TsaServer::start("Alpha", 0);
    let witnesses = || {
        vec![
            tsa_witness(&alpha, "DigiCert"),
            ExternalWitness::Cosigner(WitnessClient::new(
                WitnessConfig::new(
                    &wserver.url,
                    wkey.clone(),
                    Some("Pragmatic Witness"),
                    Some("wtoken".into()),
                )
                .unwrap(),
                Arc::new(UreqTransport::new()),
            )),
        ]
    };
    let snaps = Snapshots::default();
    let mut j = journal("r", 1);
    {
        let anchorer = open(dir.path(), witnesses(), config(2));
        for _ in 0..2 {
            snaps.set(vec![snap("r", &j)]);
            let out = anchorer.run_batch(&snaps.provider()).unwrap();
            assert!(
                out.attempts.iter().all(|a| a.result.is_ok()),
                "{:?}",
                out.attempts
            );
            assert_eq!(out.advanced.len(), 1);
            grow(&mut j, 1);
        }
        let bodies: Vec<String> = wserver
            .seen()
            .iter()
            .map(|s| String::from_utf8(s.body.clone()).unwrap())
            .collect();
        assert!(bodies[0].starts_with("old 0\n\n"));
        assert!(bodies[1].starts_with("old 1\n"), "{}", bodies[1]);
    }
    // After a restart the anchorer does not know the witness's size: it
    // learns it from a 409 and retries with a proof from there. The
    // witness journal is anchored like any run.
    let anchorer = open(dir.path(), witnesses(), config(2));
    snaps.set(vec![snap("r", &j), svc.snapshot()]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    assert!(
        out.attempts.iter().all(|a| a.result.is_ok()),
        "{:?}",
        out.attempts
    );
    assert_eq!(out.leaves.len(), 2);
    assert!(out.leaves.iter().any(|l| l.id == WITNESS_RUN_ID));
    let statuses: Vec<String> = wserver
        .seen()
        .iter()
        .map(|s| {
            String::from_utf8(s.body.clone())
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(statuses, ["old 0", "old 1", "old 0", "old 2"]);

    // The cosignatures in evidence verify against the pinned witness key.
    let section = anchorer.anchor_section(LeafType::Run, "r").unwrap();
    assert_eq!(section.anchors.len(), 3);
    for a in &section.anchors {
        let body = Note::parse(&a.checkpoint).unwrap().body;
        let cosig = a
            .witnesses
            .iter()
            .find(|w| w.object.get("type").unwrap().as_str() == Some("cosignature"))
            .unwrap();
        assert_eq!(cosig.operator, "pragmatic-witness");
        let line = cosig.object.get("line").unwrap().as_str().unwrap();
        let sig = NoteSignature::parse_line(line).unwrap();
        assert_eq!(verify_cosignature(&wkey, &body, &sig), Some(1_760_000_000));
        assert!(a.independent);
    }
    // The witness's own history lists all three, in order.
    let log = svc.log("test-server", None, 10).unwrap();
    let sizes: Vec<u64> = log.records.iter().map(|r| r.tree_size).collect();
    assert_eq!(sizes, [1, 2, 4]);
    // An unauthenticated client is refused.
    let anon = WitnessClient::new(
        WitnessConfig::new(&wserver.url, wkey, None, None).unwrap(),
        Arc::new(UreqTransport::new()),
    );
    let latest = anchorer.log().latest_checkpoint().unwrap();
    let note = anchorer.log().checkpoint(latest.seq).unwrap().signed.note;
    assert!(anon.add_checkpoint(4, &[], &note).is_err());
}

#[test]
fn hmac_ids_and_self_anchoring() {
    let dir = tempfile::tempdir().unwrap();
    let key = [42u8; 32];
    let cfg = AnchorerConfig {
        id_mode: RunIdMode::Hmac { key },
        ..config(0)
    };
    let anchorer = open(dir.path(), vec![], cfg.clone());
    let snaps = Snapshots::default();
    let j = journal("user.42", 3);
    snaps.set(vec![snap("user.42", &j)]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    // With no independence required, the server's signature advances it.
    assert_eq!(out.newly_independent, vec![0]);
    assert_eq!(out.advanced[0].id, "user.42");
    // The leaf carries HMAC(salt, run_id); the bundle carries the salt.
    let section = anchorer.anchor_section(LeafType::Run, "user.42").unwrap();
    let salt = section.anchor_id.unwrap();
    assert_eq!(
        section.anchors[0].leaf.id,
        hmac_run_id(&salt, "user.42").to_vec()
    );
    let leaf = anchorer.log().read_leaf(0).unwrap();
    assert!(!leaf.id.windows(7).any(|w| w == b"user.42"));
    assert_eq!(
        section.anchor_id_json().as_str().unwrap().len(),
        64,
        "lowercase hex"
    );
    // Plain ids give a null anchor_id.
    let plain_dir = tempfile::tempdir().unwrap();
    let plain = open(plain_dir.path(), vec![], config(0));
    plain.run_batch(&snaps.provider()).unwrap();
    let section = plain.anchor_section(LeafType::Run, "user.42").unwrap();
    assert!(section.anchor_id_json().is_null());
    assert_eq!(section.anchors[0].leaf.id, b"user.42");
    // A run with no leaves has an empty chain but the latest checkpoint.
    let none = plain.anchor_section(LeafType::Run, "nobody").unwrap();
    assert!(none.anchors.is_empty());
    assert!(none.latest_checkpoint.is_some());
}

#[test]
fn duplicate_snapshots_abort_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let anchorer = open(dir.path(), vec![], config(0));
    let snaps = Snapshots::default();
    let j = journal("r", 1);
    snaps.set(vec![snap("r", &j), snap("x", &j), snap("r", &j)]);
    let err = anchorer.run_batch(&snaps.provider()).unwrap_err();
    assert!(matches!(err, AnchorError::DuplicateId { .. }), "{err}");
    assert_eq!(anchorer.log().size(), 0);
    // A provider failure is reported as such.
    let failing = || -> Result<Vec<Snapshot>, String> { Err("index not ready".into()) };
    assert!(matches!(
        anchorer.run_batch(&failing),
        Err(AnchorError::Provider(_))
    ));
    // Invalid ids are skipped, valid ones anchored.
    snaps.set(vec![snap("r", &j), snap("bad/id", &j)]);
    let out = anchorer.run_batch(&snaps.provider()).unwrap();
    assert_eq!(out.leaves.len(), 1);
    assert_eq!(out.skipped[0].reason, SkipReason::InvalidId);
}

#[test]
fn a_signing_key_for_another_origin_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    {
        let anchorer = open(dir.path(), vec![], config(0));
        let snaps = Snapshots::default();
        snaps.set(vec![snap("r", &journal("r", 1))]);
        anchorer.run_batch(&snaps.provider()).unwrap();
    }
    let other = LogSigner::from_seed("pragmatic/renamed", [7u8; 32]).unwrap();
    assert!(matches!(
        Anchorer::open(dir.path(), other, vec![], config(0)),
        Err(AnchorError::Key(_))
    ));
    // A rotated key for the same origin is accepted.
    let rotated = LogSigner::from_seed(ORIGIN, [8u8; 32]).unwrap();
    assert!(Anchorer::open(dir.path(), rotated, vec![], config(0)).is_ok());
}
