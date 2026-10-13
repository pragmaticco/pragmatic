use super::*;
use crate::checkpoint::LogSigner;
use crate::tsa::HttpResponse;
use pragmatic::merkle::{consistency_proof, leaf_hash, root};

const ORIGIN: &str = "pragmatic/acme";

fn log_key() -> LogSigner {
    LogSigner::from_seed(ORIGIN, [1u8; 32]).unwrap()
}

fn cosigner() -> Cosigner {
    Cosigner::from_seed("witness.example", [2u8; 32]).unwrap()
}

fn leaves(n: usize) -> Vec<Digest> {
    (0..n as u64).map(|i| leaf_hash(&i.to_le_bytes())).collect()
}

/// The signed checkpoint of the first `n` of `all`.
fn checkpoint(all: &[Digest], n: usize) -> String {
    log_key()
        .sign_checkpoint(n as u64, root(&all[..n]))
        .unwrap()
        .note
}

fn body(old: usize, new: usize, all: &[Digest]) -> Vec<u8> {
    let proof = if old == 0 {
        Vec::new()
    } else {
        consistency_proof(old, &all[..new]).unwrap()
    };
    encode_add_checkpoint(old as u64, &proof, &checkpoint(all, new))
        .unwrap()
        .into_bytes()
}

fn service(dir: &Path) -> WitnessService {
    WitnessService::open(
        dir.join("witness.journal"),
        cosigner(),
        vec![WitnessOrigin {
            name: "acme".into(),
            origin: ORIGIN.into(),
            log_keys: vec![log_key().verifier_key()],
        }],
    )
    .unwrap()
}

#[test]
fn cosignature_round_trips_through_the_core_verifier() {
    let c = cosigner();
    let body = "pragmatic/acme\n5\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
    let sig = c.cosign(body, 1_760_000_000);
    let vkey = VerifierKey::parse(&c.verifier_key().encode()).unwrap();
    assert_eq!(vkey.signature_type(), SignatureType::CosignatureV1);
    assert!(vkey.verify(body, &sig));
    assert_eq!(verify_cosignature(&vkey, body, &sig), Some(1_760_000_000));
    // Through a whole note: log signature plus cosignature line.
    let log = log_key();
    let mut note = Note::parse(&log.sign_checkpoint(1, [0; 32]).unwrap().note).unwrap();
    note.signatures.push(c.cosign(&note.body, 42));
    let verified = note::verify_note(&note, &[log.verifier_key(), vkey.clone()]).unwrap();
    assert_eq!(verified.len(), 2);
    assert_eq!(verified[1].timestamp, Some(42));
    // Another body, another time or another key does not verify.
    assert!(!vkey.verify("pragmatic/acme\n6\n", &sig));
    let mut later = sig.clone();
    later.signature[7] ^= 1;
    assert!(!vkey.verify(body, &later));
    let other = Cosigner::from_seed("witness.example", [3u8; 32]).unwrap();
    assert!(!other.verifier_key().verify(body, &sig));
    // Key files round-trip.
    let back = Cosigner::parse_skey(&c.encode_skey()).unwrap();
    assert_eq!(back.verifier_key(), c.verifier_key());
    assert!(Cosigner::parse_skey(&log.encode_skey()).is_err());
}

#[test]
fn request_bodies_round_trip_and_reject_malformations() {
    let all = leaves(10);
    let b = body(4, 10, &all);
    let req = parse_add_checkpoint(&b).unwrap();
    assert_eq!(req.old_size, 4);
    assert_eq!(req.proof, consistency_proof(4, &all).unwrap());
    assert_eq!(req.note, checkpoint(&all, 10));
    let text = String::from_utf8(b).unwrap();
    assert!(text.starts_with("old 4\n"));

    let note = checkpoint(&all, 10);
    for bad in [
        "".to_string(),
        "old 04\n\n".to_string() + &note,
        "old -1\n\n".to_string() + &note,
        "new 4\n\n".to_string() + &note,
        "old 4\nnot base64\n\n".to_string() + &note,
        "old 4\n".to_string() + &note, // no empty line
        "old 4\n\n".to_string(),       // no checkpoint
        format!("old 4\n{}\n", "A".repeat(43) + "="),
    ] {
        assert!(parse_add_checkpoint(bad.as_bytes()).is_err(), "{bad:?}");
    }
    let too_long = vec![[0u8; 32]; MAX_PROOF_LINES + 1];
    assert!(encode_add_checkpoint(1, &too_long, &note).is_err());
    let mut lines = "old 1\n".to_string();
    for _ in 0..=MAX_PROOF_LINES {
        lines.push_str(&base64_encode(&[0u8; 32]));
        lines.push('\n');
    }
    lines.push('\n');
    lines.push_str(&note);
    assert!(parse_add_checkpoint(lines.as_bytes()).is_err());
}

#[test]
fn witness_mode_follows_the_tlog_witness_checks() {
    let dir = tempfile::tempdir().unwrap();
    let svc = service(dir.path());
    let all = leaves(20);
    let vkey = cosigner().verifier_key();

    // First checkpoint from size 0.
    let resp = svc.add_checkpoint("acme", &body(0, 5, &all), 1000).unwrap();
    let sig = NoteSignature::parse_line(resp.trim_end()).unwrap();
    let ckpt_body = Note::parse(&checkpoint(&all, 5)).unwrap().body;
    assert_eq!(verify_cosignature(&vkey, &ckpt_body, &sig), Some(1000));
    assert_eq!(svc.latest("acme"), Some((5, root(&all[..5]))));

    // Extending with a valid proof.
    svc.add_checkpoint("acme", &body(5, 12, &all), 1001)
        .unwrap();
    // Re-submitting the same size with an empty proof is cosigned again.
    svc.add_checkpoint("acme", &body(12, 12, &all), 1002)
        .unwrap();

    // A stale old size: 409 with the current size as text/x.tlog.size.
    let err = svc
        .add_checkpoint("acme", &body(5, 15, &all), 1003)
        .unwrap_err();
    assert_eq!(err, AddCheckpointError::Conflict { size: 12 });
    assert_eq!(err.status(), 409);
    assert_eq!(err.body(), "12\n");
    assert_eq!(err.content_type(), "text/x.tlog.size");
    // So is a fresh start from 0.
    assert_eq!(
        svc.add_checkpoint("acme", &body(0, 15, &all), 1003),
        Err(AddCheckpointError::Conflict { size: 12 })
    );

    // A fork: a correctly signed tree of 15 leaves that does not extend
    // the cosigned 12. Refused with 422 and recorded.
    let mut forked = all.clone();
    forked[3] = leaf_hash(b"rewritten");
    let fork_body = body(12, 15, &forked);
    let err = svc.add_checkpoint("acme", &fork_body, 1004).unwrap_err();
    assert_eq!(err.status(), 422);
    // The same size with another root is refused too.
    let same_size = encode_add_checkpoint(12, &[], &checkpoint(&forked, 12)).unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", same_size.as_bytes(), 1004)
            .unwrap_err()
            .status(),
        422
    );
    // A tampered proof.
    let mut req = parse_add_checkpoint(&body(12, 15, &all)).unwrap();
    req.proof[0][0] ^= 1;
    let tampered = encode_add_checkpoint(12, &req.proof, &req.note).unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", tampered.as_bytes(), 1004)
            .unwrap_err()
            .status(),
        422
    );
    assert_eq!(svc.latest("acme"), Some((12, root(&all[..12]))));

    // Signatures, origins and sizes.
    let other_key = LogSigner::from_seed(ORIGIN, [9u8; 32]).unwrap();
    let wrong_sig = encode_add_checkpoint(
        12,
        &consistency_proof(12, &all[..15]).unwrap(),
        &other_key
            .sign_checkpoint(15, root(&all[..15]))
            .unwrap()
            .note,
    )
    .unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", wrong_sig.as_bytes(), 1005)
            .unwrap_err()
            .status(),
        403
    );
    let other_origin = LogSigner::from_seed("pragmatic/other", [1u8; 32]).unwrap();
    let wrong_origin = encode_add_checkpoint(
        0,
        &[],
        &other_origin.sign_checkpoint(1, all[0]).unwrap().note,
    )
    .unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", wrong_origin.as_bytes(), 1005)
            .unwrap_err()
            .status(),
        403
    );
    assert_eq!(
        svc.add_checkpoint("nobody", &body(12, 15, &all), 1005),
        Err(AddCheckpointError::UnknownOrigin)
    );
    let backwards = encode_add_checkpoint(16, &[], &checkpoint(&all, 15)).unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", backwards.as_bytes(), 1005)
            .unwrap_err()
            .status(),
        400
    );
    assert_eq!(
        svc.add_checkpoint("acme", b"garbage", 1005)
            .unwrap_err()
            .status(),
        400
    );

    // The honest extension still works after all that.
    svc.add_checkpoint("acme", &body(12, 20, &all), 1006)
        .unwrap();

    // The witness log holds every cosigned checkpoint, paged by cursor.
    let page = svc.log("acme", None, 2).unwrap();
    assert_eq!(
        page.records.iter().map(|r| r.tree_size).collect::<Vec<_>>(),
        [5, 12]
    );
    let next = svc.log("acme", page.next, 100).unwrap();
    assert_eq!(
        next.records.iter().map(|r| r.tree_size).collect::<Vec<_>>(),
        [12, 20]
    );
    assert_eq!(next.next, None);
    assert_eq!(next.records[1].timestamp, 1006);
    let json = next.to_json().to_string();
    assert!(json.starts_with("{\"origin\":\"acme\",\"records\":[{\"cursor\":"));

    // The fork attempts are in the witness journal as evidence.
    let svc_state = svc.state.lock().unwrap();
    let rejects = svc_state
        .journal
        .journal()
        .entries()
        .iter()
        .filter(|e| e.event.note_kind() == Some(REJECT_NOTE))
        .count();
    assert_eq!(rejects, 3);
}

#[test]
fn witness_state_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let all = leaves(9);
    {
        let svc = service(dir.path());
        svc.add_checkpoint("acme", &body(0, 4, &all), 10).unwrap();
        svc.add_checkpoint("acme", &body(4, 7, &all), 11).unwrap();
    }
    let svc = service(dir.path());
    assert_eq!(svc.latest("acme"), Some((7, root(&all[..7]))));
    // A request from the pre-restart size 4 is a conflict, not a fork.
    assert_eq!(
        svc.add_checkpoint("acme", &body(4, 9, &all), 12),
        Err(AddCheckpointError::Conflict { size: 7 })
    );
    svc.add_checkpoint("acme", &body(7, 9, &all), 12).unwrap();
    let snap = svc.snapshot();
    assert_eq!(snap.id, WITNESS_RUN_ID);
    assert_eq!(snap.entries, 4, "run.start and three cosignatures");
    // The witness journal is an ordinary, verifiable journal.
    let bytes = std::fs::read(dir.path().join("witness.journal")).unwrap();
    let parsed = pragmatic::Journal::parse(&bytes, None).unwrap();
    assert!(parsed.journal.verify().is_ok());
    assert_eq!(parsed.journal.head(), snap.head);
}

#[test]
fn empty_tree_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let svc = service(dir.path());
    let empty = log_key().sign_checkpoint(0, merkle::empty_root()).unwrap();
    let ok = encode_add_checkpoint(0, &[], &empty.note).unwrap();
    svc.add_checkpoint("acme", ok.as_bytes(), 1).unwrap();
    let bad = log_key().sign_checkpoint(0, [1; 32]).unwrap();
    let bad = encode_add_checkpoint(0, &[], &bad.note).unwrap();
    assert_eq!(
        svc.add_checkpoint("acme", bad.as_bytes(), 2)
            .unwrap_err()
            .status(),
        422
    );
}

/// An in-process transport that hands requests to a witness service, so
/// the client and the service are tested against each other.
struct Loopback {
    svc: WitnessService,
    now: u64,
}

impl HttpTransport for Loopback {
    fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        _timeout: Duration,
    ) -> Result<HttpResponse, String> {
        assert_eq!(url, "https://w.example/add-checkpoint");
        assert!(headers.contains(&("Authorization", "Bearer secret")));
        Ok(match self.svc.add_checkpoint("acme", body, self.now) {
            Ok(text) => HttpResponse {
                status: 200,
                content_type: Some("text/plain".into()),
                body: text.into_bytes(),
            },
            Err(e) => HttpResponse {
                status: e.status(),
                content_type: Some(e.content_type().into()),
                body: e.body().into_bytes(),
            },
        })
    }
}

#[test]
fn client_against_the_service() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(Loopback {
        svc: service(dir.path()),
        now: 77,
    });
    let config = WitnessConfig::new(
        "https://w.example/",
        cosigner().verifier_key(),
        None,
        Some("secret".into()),
    )
    .unwrap();
    assert_eq!(config.operator, "witness.example");
    let client = WitnessClient::new(config, transport.clone());
    let all = leaves(8);
    let cosig = client.add_checkpoint(0, &[], &checkpoint(&all, 3)).unwrap();
    assert_eq!(cosig.timestamp, 77);
    assert_eq!(cosig.name, "witness.example");
    let obj = cosig.evidence_json().to_string();
    assert!(obj.starts_with("{\"type\":\"cosignature\",\"name\":\"witness.example\",\"line\":\""));
    // A stale size comes back as Conflict with the witness's size.
    assert_eq!(
        client.add_checkpoint(0, &[], &checkpoint(&all, 8)),
        Err(WitnessClientError::Conflict { size: 3 })
    );
    let proof = consistency_proof(3, &all).unwrap();
    client
        .add_checkpoint(3, &proof, &checkpoint(&all, 8))
        .unwrap();
    // A config with a log key instead of a witness key is refused.
    assert!(WitnessConfig::new("https://w", log_key().verifier_key(), None, None).is_err());
    // A client pinned to another witness key finds no valid cosignature.
    let wrong = WitnessConfig::new(
        "https://w.example",
        Cosigner::from_seed("witness.example", [4; 32])
            .unwrap()
            .verifier_key(),
        None,
        Some("secret".into()),
    )
    .unwrap();
    let wrong_client = WitnessClient::new(wrong, transport);
    let proof = consistency_proof(8, &all).unwrap();
    assert!(proof.is_empty());
    assert!(matches!(
        wrong_client.add_checkpoint(8, &proof, &checkpoint(&all, 8)),
        Err(WitnessClientError::NoValidCosignature(_))
    ));
}
