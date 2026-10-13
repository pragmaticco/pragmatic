//! Witness scheduling without the network: `tlog-witness` cosigners served
//! in-process behind a fake transport, so ordering, backoff, retries after
//! independence, advancement after a restart, healing a poisoned log and
//! lock independence between commits and witness passes can be tested
//! exactly. No test here needs `openssl`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pragmatic::encoding::base64_encode;
use pragmatic::note::{Checkpoint, Note, VerifierKey};
use pragmatic::sha256::sha256;
use pragmatic_anchor::tsa::{
    HttpResponse, HttpTransport, OpensslVerifier, TsaClient, TsaConfig, TsaPolicy,
};
use pragmatic_anchor::witness::{
    parse_add_checkpoint, Cosigner, WitnessClient, WitnessConfig, WitnessOrigin, WitnessService,
};
use pragmatic_anchor::{
    AnchorError, Anchorer, AnchorerConfig, ExternalWitness, IndependencePolicy, LeafType,
    LogSigner, RetryPolicy, RunIdMode, Snapshot,
};

const ORIGIN: &str = "pragmatic/test-server/0011223344556677";

fn signer() -> LogSigner {
    LogSigner::from_seed(ORIGIN, [7u8; 32]).unwrap()
}

fn snap(id: &str, entries: u64) -> Snapshot {
    Snapshot {
        leaf_type: LeafType::Run,
        id: id.into(),
        entries,
        head: sha256(format!("{id}/{entries}").as_bytes()),
    }
}

fn provider(s: Vec<Snapshot>) -> impl Fn() -> Result<Vec<Snapshot>, String> {
    move || Ok(s.clone())
}

fn config(min: usize, retry: RetryPolicy) -> AnchorerConfig {
    AnchorerConfig {
        id_mode: RunIdMode::Plain,
        policy: IndependencePolicy {
            min_independent_operators: min,
        },
        retry,
    }
}

fn no_backoff() -> RetryPolicy {
    RetryPolicy {
        initial_backoff: Duration::ZERO,
        ..RetryPolicy::default()
    }
}

/// A tlog-witness cosigner served in-process. The next `fail_next`
/// requests get a 503 before reaching the witness. Records `(old size,
/// checkpoint size, status)` of every request.
struct InProcCosigner {
    svc: WitnessService,
    vkey: VerifierKey,
    fail_next: AtomicUsize,
    seen: Mutex<Vec<(u64, u64, u16)>>,
    _dir: tempfile::TempDir,
}

impl InProcCosigner {
    fn new(seed: u8, fail_next: usize) -> Arc<InProcCosigner> {
        let dir = tempfile::tempdir().unwrap();
        let cosigner = Cosigner::from_seed(&format!("w{seed}.example"), [seed; 32]).unwrap();
        let vkey = cosigner.verifier_key();
        let svc = WitnessService::open(
            dir.path().join("witness.journal"),
            cosigner,
            vec![WitnessOrigin {
                name: "test-server".into(),
                origin: ORIGIN.into(),
                log_keys: vec![signer().verifier_key()],
            }],
        )
        .unwrap();
        Arc::new(InProcCosigner {
            svc,
            vkey,
            fail_next: AtomicUsize::new(fail_next),
            seen: Mutex::new(Vec::new()),
            _dir: dir,
        })
    }

    fn seen(&self) -> Vec<(u64, u64, u16)> {
        self.seen.lock().unwrap().clone()
    }

    fn fail(&self, n: usize) {
        self.fail_next.store(n, Ordering::SeqCst);
    }

    /// As an anchorer's witness, under operator `op`.
    fn witness(self: &Arc<Self>, op: &str) -> ExternalWitness {
        ExternalWitness::Cosigner(WitnessClient::new(
            WitnessConfig::new(
                &format!("http://{op}.invalid"),
                self.vkey.clone(),
                Some(op),
                None,
            )
            .unwrap(),
            self.clone(),
        ))
    }
}

impl HttpTransport for InProcCosigner {
    fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        body: &[u8],
        _timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let req = parse_add_checkpoint(body).unwrap();
        let size = Checkpoint::parse(&Note::parse(&req.note).unwrap().body)
            .unwrap()
            .tree_size;
        let failing = self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        let resp = if failing {
            HttpResponse {
                status: 503,
                content_type: None,
                body: b"busy\n".to_vec(),
            }
        } else {
            match self.svc.add_checkpoint("test-server", body, 1_760_000_000) {
                Ok(b) => HttpResponse {
                    status: 200,
                    content_type: Some("text/plain".into()),
                    body: b.into_bytes(),
                },
                Err(e) => HttpResponse {
                    status: e.status(),
                    content_type: Some(e.content_type().into()),
                    body: e.body().into_bytes(),
                },
            }
        };
        self.seen
            .lock()
            .unwrap()
            .push((req.old_size, size, resp.status));
        Ok(resp)
    }
}

/// Sizes a cosigner was asked to cosign, in request order, successes only.
fn cosigned_sizes(c: &InProcCosigner) -> Vec<u64> {
    c.seen()
        .into_iter()
        .filter(|(_, _, status)| *status == 200)
        .map(|(_, size, _)| size)
        .collect()
}

/// A transient failure at one cosigner must not let a newer checkpoint
/// jump ahead of the older one it still owes: the cosigner could then
/// never cosign the older one, which would stay short of the policy, and
/// a finished run in it would never advance.
#[test]
fn a_cosigner_always_sees_checkpoints_in_order() {
    let w1 = InProcCosigner::new(1, 0);
    let w2 = InProcCosigner::new(2, 1); // one 503
    let dir = tempfile::tempdir().unwrap();
    // Long enough that batch 1 surely runs inside w2's backoff.
    let backoff = Duration::from_secs(2);
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![w1.witness("w1"), w2.witness("w2")],
        config(
            2,
            RetryPolicy {
                initial_backoff: backoff,
                ..RetryPolicy::default()
            },
        ),
    )
    .unwrap();

    // Batch 0: run "a" ends; w2 blips.
    let out = anchorer.run_batch(&provider(vec![snap("a", 3)])).unwrap();
    assert_eq!(out.committed.unwrap().seq, 0);
    assert!(out.advanced.is_empty());
    // Batch 1 within w2's backoff: w2 is not offered checkpoint 1 while it
    // owes checkpoint 0.
    let out = anchorer
        .run_batch(&provider(vec![snap("a", 3), snap("b", 1)]))
        .unwrap();
    assert_eq!(out.committed.unwrap().seq, 1);
    assert!(out.attempts.iter().all(|a| a.witness != w2_label(&w2)));
    assert_eq!(anchorer.status().not_independent, vec![0, 1]);

    std::thread::sleep(backoff + Duration::from_millis(50));
    let out = anchorer.retry_pending();
    assert_eq!(out.newly_independent, vec![0, 1]);
    assert_eq!(cosigned_sizes(&w2), [1, 2], "{:?}", w2.seen());
    let a = anchorer.anchor_section(LeafType::Run, "a").unwrap();
    assert_eq!(a.anchored_entries(), 3);
    assert!(out.advanced.iter().any(|x| x.id == "a" && x.entries == 3));
    assert!(anchorer.status().pending.is_empty());
}

fn w2_label(w: &InProcCosigner) -> String {
    format!(
        "witness-{}",
        pragmatic::encoding::hex_encode(&w.vkey.key_id())
    )
}

/// The per-pass bound never lets a newer checkpoint go ahead of older ones
/// a witness owes: with one attempt per pass, a backlog drains in order.
#[test]
fn the_per_pass_bound_drains_a_backlog_in_order() {
    let w1 = InProcCosigner::new(1, 3); // down for the first three batches
    let dir = tempfile::tempdir().unwrap();
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![w1.witness("w1")],
        config(
            1,
            RetryPolicy {
                max_attempts_per_pass: 1,
                ..no_backoff()
            },
        ),
    )
    .unwrap();
    for n in 1..=3 {
        anchorer.run_batch(&provider(vec![snap("a", n)])).unwrap();
    }
    assert_eq!(anchorer.status().not_independent, vec![0, 1, 2]);
    // A fourth batch: one attempt in its pass, and it goes to the oldest.
    let out = anchorer.run_batch(&provider(vec![snap("a", 4)])).unwrap();
    assert_eq!(out.newly_independent, vec![0]);
    for _ in 0..3 {
        anchorer.retry_pending();
    }
    assert_eq!(cosigned_sizes(&w1), [1, 2, 3, 4]);
    assert!(anchorer.status().pending.is_empty());
}

/// The witness results that make a checkpoint independent are durable
/// before the server can record the advancement. If the server stops in
/// between, the first pass after a restart reports it again, so a
/// finished run (which never changes again) still advances.
#[test]
fn advancement_is_reported_again_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let w1 = InProcCosigner::new(1, 0);
    let w2 = InProcCosigner::new(2, 0);
    let open = || {
        Anchorer::open(
            dir.path(),
            signer(),
            vec![w1.witness("op-a"), w2.witness("op-b")],
            config(2, no_backoff()),
        )
        .unwrap()
        .0
    };
    {
        let anchorer = open();
        let out = anchorer
            .run_batch(&provider(vec![snap("finished-run", 5), snap("other", 1)]))
            .unwrap();
        assert_eq!(out.advanced.len(), 2);
        let out = anchorer
            .run_batch(&provider(vec![snap("other", 2)]))
            .unwrap();
        assert_eq!(out.advanced.len(), 1);
        // The server stops here, before it records anchored_entries.
    }
    let anchorer = open();
    assert!(anchorer.checkpoint_is_independent(0).unwrap());
    let out = anchorer.retry_pending();
    let mut reported: Vec<(String, u64)> = out
        .advanced
        .iter()
        .map(|a| (a.id.clone(), a.entries))
        .collect();
    reported.sort();
    // The newest independently anchored leaf of each id, once.
    assert_eq!(
        reported,
        [("finished-run".to_string(), 5), ("other".to_string(), 2)]
    );
    assert!(out.newly_independent.is_empty());
    assert!(out.attempts.is_empty());
    // Only once per open.
    assert!(anchorer.retry_pending().advanced.is_empty());

    // The same through a batch with nothing new, after another restart.
    drop(anchorer);
    let anchorer = open();
    let out = anchorer
        .run_batch(&provider(vec![snap("finished-run", 5)]))
        .unwrap();
    assert!(out.committed.is_none());
    assert!(out
        .advanced
        .iter()
        .any(|a| a.id == "finished-run" && a.entries == 5));
}

/// A witness that failed is retried after the others have made the
/// checkpoint independent: an auditor counts only the witnesses they
/// trust, so every result counts. The checkpoint is reported independent
/// once, and leaves the queue only when nothing is owed.
#[test]
fn a_failed_witness_is_retried_after_the_policy_is_met() {
    for min in [2, 0] {
        let w1 = InProcCosigner::new(1, 0);
        let w2 = InProcCosigner::new(2, 0);
        let w3 = InProcCosigner::new(3, 1);
        let dir = tempfile::tempdir().unwrap();
        let (anchorer, _) = Anchorer::open(
            dir.path(),
            signer(),
            vec![w1.witness("w1"), w2.witness("w2"), w3.witness("w3")],
            config(min, no_backoff()),
        )
        .unwrap();
        let out = anchorer.run_batch(&provider(vec![snap("r", 1)])).unwrap();
        assert_eq!(out.newly_independent, vec![0], "min {min}");
        assert_eq!(out.advanced.len(), 1);
        let status = anchorer.status();
        assert_eq!(status.pending, vec![0]);
        assert!(status.not_independent.is_empty());

        let out = anchorer.retry_pending();
        assert_eq!(out.attempts.len(), 1);
        assert!(out.attempts[0].result.is_ok());
        assert!(out.newly_independent.is_empty(), "reported once");
        assert!(out.advanced.is_empty());
        assert_eq!(anchorer.log().witnesses(0).unwrap().len(), 3);
        assert!(anchorer.status().pending.is_empty());
        assert_eq!(w3.seen(), [(0, 1, 503), (0, 1, 200)]);
    }
}

/// A restart queues the witnesses an independent checkpoint still owes.
#[test]
fn witnesses_still_owed_are_retried_after_a_restart() {
    let w1 = InProcCosigner::new(1, 0);
    let w2 = InProcCosigner::new(2, 1);
    let dir = tempfile::tempdir().unwrap();
    let open = || {
        Anchorer::open(
            dir.path(),
            signer(),
            vec![w1.witness("w1"), w2.witness("w2")],
            config(1, no_backoff()),
        )
        .unwrap()
        .0
    };
    let out = open().run_batch(&provider(vec![snap("r", 1)])).unwrap();
    assert_eq!(out.newly_independent, vec![0]);
    let anchorer = open();
    assert_eq!(anchorer.status().pending, vec![0]);
    let out = anchorer.retry_pending();
    assert_eq!(out.attempts.len(), 1);
    assert!(out.attempts[0].result.is_ok());
    assert_eq!(anchorer.log().witnesses(0).unwrap().len(), 2);
}

/// The retry queue is bounded; the oldest checkpoint leaves it, with an
/// error to alert on.
#[test]
fn the_retry_queue_is_bounded() {
    let w1 = InProcCosigner::new(1, 100);
    let dir = tempfile::tempdir().unwrap();
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![w1.witness("w1")],
        config(
            1,
            RetryPolicy {
                max_backlog: 2,
                ..no_backoff()
            },
        ),
    )
    .unwrap();
    for n in 1..=2 {
        anchorer.run_batch(&provider(vec![snap("a", n)])).unwrap();
    }
    let out = anchorer.run_batch(&provider(vec![snap("a", 3)])).unwrap();
    assert!(
        out.errors
            .iter()
            .any(|e| e.contains("checkpoint 0 left the witness retry queue")),
        "{:?}",
        out.errors
    );
    assert_eq!(anchorer.status().pending, vec![1, 2]);
}

/// A TSA that never answers: each request runs into its timeout.
struct HungTsa;

impl HttpTransport for HungTsa {
    fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        std::thread::sleep(timeout);
        Err("timed out".into())
    }
}

/// A PEM file with one stand-in certificate (the anchorer fingerprints
/// anchors at open; the hung TSA never gets as far as verifying).
fn anchors_file(dir: &Path) -> PathBuf {
    let path = dir.join("anchors.pem");
    fs::write(
        &path,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_encode(b"stand-in")
        ),
    )
    .unwrap();
    path
}

/// Commits never wait for witness network calls: while a pass is stuck on
/// a TSA that never answers, the next batch's leaves are committed at once
/// (so a batch runs within 30 s of `attempt.end`, design 4.7).
#[test]
fn a_hung_tsa_does_not_delay_the_next_commit() {
    let dir = tempfile::tempdir().unwrap();
    // The default timeouts scaled down 30 times.
    let policy = TsaPolicy {
        timeout: Duration::from_secs(1),
        min_spacing: Duration::ZERO,
        max_attempts: 3,
        initial_backoff: Duration::from_millis(66),
        max_backoff: Duration::from_secs(2),
    };
    let hung = ExternalWitness::Tsa(TsaClient::new(
        TsaConfig::new("http://hung.invalid", "DigiCert", anchors_file(dir.path())).unwrap(),
        policy,
        Arc::new(HungTsa),
        OpensslVerifier::default(),
    ));
    let anchors = dir.path().join("anchors");
    let anchorer = Anchorer::open(&anchors, signer(), vec![hung], config(1, no_backoff()))
        .unwrap()
        .0;
    // The batch's own pass spends its three timeouts on the TSA.
    let started = Instant::now();
    anchorer.run_batch(&provider(vec![snap("a", 1)])).unwrap();
    assert_eq!(anchorer.log().size(), 1);
    assert!(started.elapsed() >= Duration::from_secs(3));

    let commit_latency = std::thread::scope(|s| {
        // The retry timer fires and its pass hangs on the TSA.
        s.spawn(|| anchorer.retry_pending());
        std::thread::sleep(Duration::from_millis(100));
        // A run ends; its batch is due now.
        let requested = Instant::now();
        s.spawn(|| {
            anchorer
                .run_batch(&provider(vec![snap("a", 1), snap("b", 1)]))
                .unwrap()
        });
        while anchorer.log().size() < 2 {
            std::thread::sleep(Duration::from_millis(5));
        }
        requested.elapsed()
    });
    assert!(
        commit_latency < Duration::from_millis(500),
        "the next batch committed only after {commit_latency:?}"
    );
}

/// No witness pass outlives its time budget by more than one attempt.
#[test]
fn a_pass_stops_starting_attempts_at_its_time_budget() {
    /// A cosigner that answers slowly.
    struct Slow(Arc<InProcCosigner>);
    impl HttpTransport for Slow {
        fn post(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            body: &[u8],
            timeout: Duration,
        ) -> Result<HttpResponse, String> {
            std::thread::sleep(Duration::from_millis(200));
            self.0.post(url, headers, body, timeout)
        }
    }
    let w1 = InProcCosigner::new(1, 0);
    let slow = ExternalWitness::Cosigner(WitnessClient::new(
        WitnessConfig::new("http://slow.invalid", w1.vkey.clone(), None, None).unwrap(),
        Arc::new(Slow(w1.clone())),
    ));
    let dir = tempfile::tempdir().unwrap();
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![slow],
        config(
            1,
            RetryPolicy {
                max_pass_time: Duration::from_millis(300),
                initial_backoff: Duration::from_secs(3600),
                ..RetryPolicy::default()
            },
        ),
    )
    .unwrap();
    // A backlog of three checkpoints while the cosigner backs off.
    w1.fail(1);
    for n in 1..=3 {
        anchorer.run_batch(&provider(vec![snap("a", n)])).unwrap();
    }
    assert_eq!(anchorer.status().pending, vec![0, 1, 2]);
    // Reopen to clear the backoff; the pass then stops starting attempts
    // once its budget has run out (after the second, on an idle machine),
    // leaving the newest for the next pass.
    drop(anchorer);
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![ExternalWitness::Cosigner(WitnessClient::new(
            WitnessConfig::new("http://slow.invalid", w1.vkey.clone(), None, None).unwrap(),
            Arc::new(Slow(w1.clone())),
        ))],
        config(
            1,
            RetryPolicy {
                max_pass_time: Duration::from_millis(300),
                ..no_backoff()
            },
        ),
    )
    .unwrap();
    let out = anchorer.retry_pending();
    let tried = out.attempts.len();
    assert!((1..3).contains(&tried), "{:?}", out.attempts);
    assert!(out.attempts.iter().all(|a| a.result.is_ok()));
    let pending = anchorer.status().pending;
    assert_eq!(pending, (tried as u64..3).collect::<Vec<_>>());
}

/// A batch whose checkpoint file was published but not known durable (its
/// directory fsync failed) poisons the log; the next call reopens it,
/// recovery settles what was committed, and anchoring carries on without
/// a restart. No witness is asked while the log is poisoned.
#[cfg(unix)]
#[test]
fn a_poisoned_log_is_reopened_by_the_next_call() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        return;
    }
    let w1 = InProcCosigner::new(1, 0);
    let dir = tempfile::tempdir().unwrap();
    let (anchorer, _) = Anchorer::open(
        dir.path(),
        signer(),
        vec![w1.witness("w1")],
        config(1, no_backoff()),
    )
    .unwrap();
    anchorer.run_batch(&provider(vec![snap("a", 1)])).unwrap();
    let sth = dir.path().join("sth");
    fs::set_permissions(&sth, fs::Permissions::from_mode(0o300)).unwrap();
    let failed = anchorer.run_batch(&provider(vec![snap("a", 2)]));
    fs::set_permissions(&sth, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(failed.is_err());
    assert!(anchorer.log().is_poisoned());
    assert_eq!(cosigned_sizes(&w1), [1], "checkpoint 1 was never shown");

    let out = anchorer.retry_pending();
    assert!(!anchorer.log().is_poisoned());
    assert!(out.errors.iter().any(|e| e.contains("reopened")));
    // Checkpoint 1 survived, so it is witnessed and advances now.
    assert_eq!(out.newly_independent, vec![1]);
    assert_eq!(cosigned_sizes(&w1), [1, 2]);
    let out = anchorer.run_batch(&provider(vec![snap("a", 3)])).unwrap();
    assert_eq!(out.committed.unwrap().seq, 2);
}

/// TSAs of different operators that share a trust anchor are refused at
/// open: either one's tokens would verify as both operators.
#[test]
fn operators_sharing_a_trust_anchor_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let anchors = anchors_file(dir.path());
    let tsa = |url: &str, op: &str| {
        ExternalWitness::Tsa(TsaClient::new(
            TsaConfig::new(url, op, &anchors).unwrap(),
            TsaPolicy::default(),
            Arc::new(HungTsa),
            OpensslVerifier::default(),
        ))
    };
    let err = Anchorer::open(
        dir.path().join("a"),
        signer(),
        vec![
            tsa("http://timestamp.digicert.com", "digicert"),
            tsa("http://timestamp.digicert.com/", "sectigo"),
        ],
        config(2, no_backoff()),
    )
    .unwrap_err();
    assert!(matches!(err, AnchorError::Key(_)), "{err}");
    // One operator may use the same anchors for two endpoints.
    Anchorer::open(
        dir.path().join("b"),
        signer(),
        vec![
            tsa("http://timestamp.digicert.com", "digicert"),
            tsa("http://timestamp.digicert.com/", "DigiCert"),
        ],
        config(2, no_backoff()),
    )
    .unwrap();
}

#[cfg(unix)]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}
