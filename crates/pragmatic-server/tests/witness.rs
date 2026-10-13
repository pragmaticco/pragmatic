//! Witness mode (design 4.8): cosigning a log's checkpoints under the C2SP
//! tlog-witness protocol, refusing forks, and keeping a record.

mod common;

use common::*;
use pragmatic::encoding::base64_encode;
use pragmatic::merkle;
use pragmatic::note::{self, Checkpoint, Note, NoteSignature, SignatureType, VerifierKey};
use pragmatic::sha256::Digest;
use pragmatic_server::config::WitnessOrigin;
use pragmatic_server::keys::ServerKey;
use pragmatic_server::tokens::token_sha256;
use reqwest::{Method, StatusCode};
use serde_json::Value;

const ORIGIN: &str = "example.com/log";
const CLIENT: &str = "prag_witness_client_token";

fn leaves(prefix: &str, n: usize) -> Vec<Digest> {
    (0..n)
        .map(|i| merkle::leaf_hash(format!("{prefix}{i}").as_bytes()))
        .collect()
}

/// A checkpoint of `tree` signed by the log key.
fn signed(key: &ServerKey, origin: &str, tree: &[Digest]) -> String {
    let body = Checkpoint {
        origin: origin.into(),
        tree_size: tree.len() as u64,
        root: merkle::root(tree),
        extensions: vec![],
    }
    .encode()
    .unwrap();
    Note {
        signatures: vec![NoteSignature {
            name: origin.into(),
            key_id: note::key_id(origin, SignatureType::Ed25519, &key.public_key()),
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

async fn submit(ts: &TestServer, path: &str, text: String) -> (StatusCode, String, String) {
    let resp = ts
        .req(Method::POST, path, CLIENT)
        .body(text)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, ctype, resp.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkpoints_are_cosigned_consistently_and_forks_refused() {
    let log = ServerKey::generate().unwrap();
    let vkey = VerifierKey::new(ORIGIN, SignatureType::Ed25519, log.public_key())
        .unwrap()
        .encode();
    let ts = TestServer::start(|c| {
        c.witness_mode.enabled = true;
        c.witness_mode.origins.push(WitnessOrigin {
            name: ORIGIN.into(),
            token_sha256: token_sha256(CLIENT),
            public_key: vkey,
        });
    })
    .await;
    let tree = leaves("leaf-", 5);

    // First contact: old 0, no proof.
    let cp3 = signed(&log, ORIGIN, &tree[..3]);
    let (status, ctype, line) = submit(&ts, "/add-checkpoint", body(0, &[], &cp3)).await;
    assert_eq!(status, StatusCode::OK, "{line}");
    assert!(ctype.starts_with("text/plain"));
    // The cosignature verifies against the server key as a cosigner.
    let server_key = ts.app().key.public_key();
    let witness =
        VerifierKey::new("test.example", SignatureType::CosignatureV1, server_key).unwrap();
    let mut note = Note::parse(&cp3).unwrap();
    note.signatures
        .push(NoteSignature::parse_line(line.trim_end()).unwrap());
    let verified = note::verify_note(&note, std::slice::from_ref(&witness)).unwrap();
    assert!(verified[0].timestamp.is_some());

    // A consistent extension, through the /v1 path.
    let proof = merkle::consistency_proof(3, &tree).unwrap();
    let cp5 = signed(&log, ORIGIN, &tree);
    let (status, _, line) = submit(&ts, "/v1/witness", body(3, &proof, &cp5)).await;
    assert_eq!(status, StatusCode::OK, "{line}");

    // The wrong old size: 409 with the witness's size.
    let (status, ctype, text) = submit(&ts, "/add-checkpoint", body(3, &proof, &cp5)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(ctype, "text/x.tlog.size");
    assert_eq!(text, "5\n");

    // A fork: a different tree of size 6 that does not extend size 5.
    let forked = leaves("other-", 6);
    let fork_proof = merkle::consistency_proof(5, &forked).unwrap();
    let cp6 = signed(&log, ORIGIN, &forked);
    let (status, _, _) = submit(&ts, "/add-checkpoint", body(5, &fork_proof, &cp6)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // A checkpoint not signed by the log's key.
    let impostor = ServerKey::generate().unwrap();
    let bad = signed(&impostor, ORIGIN, &tree);
    let (status, _, _) = submit(&ts, "/add-checkpoint", body(5, &[], &bad)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A checkpoint for another origin than the token's.
    let other = signed(&log, "example.com/other", &tree);
    let (status, _, _) = submit(&ts, "/add-checkpoint", body(5, &[], &other)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Old larger than the checkpoint, and garbage.
    let (status, _, _) = submit(&ts, "/add-checkpoint", body(9, &[], &cp5)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = submit(&ts, "/add-checkpoint", "nonsense".into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The witness's own record: two cosigned checkpoints.
    let v: Value = ts
        .get("/v1/witness/log/example.com%2Flog", &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    let cosigned = v["cosigned"].as_array().unwrap();
    assert_eq!(cosigned.len(), 2);
    assert_eq!(cosigned[1]["tree_size"], 5);
    assert_eq!(cosigned[1]["old_size"], 3);
    assert!(cosigned[1]["checkpoint"]
        .as_str()
        .unwrap()
        .contains("\u{2014} test.example "));
    // The record is a server-written run that clients cannot write to.
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let resp = ts
        .post_json(
            &run_path("pragmatic:witness:example.com/log", "/lease"),
            &agent,
            serde_json::json!({"holder": "h"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = stored(&ts, "pragmatic:witness:example.com/log");
    assert!(j.audit().is_ok());
    assert_eq!(
        j.run_start_id().as_deref(),
        Some("pragmatic:witness:example.com/log")
    );
    // And it survives a restart: the next checkpoint still needs old 5.
    let ts = ts.restart().await;
    let (status, _, text) = submit(&ts, "/add-checkpoint", body(0, &[], &cp3)).await;
    assert_eq!((status, text.as_str()), (StatusCode::CONFLICT, "5\n"));
}
