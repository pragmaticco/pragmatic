//! The append protocol (design 4.6): every check, in order.

mod common;

use common::*;
use pragmatic::encoding::hex_encode;
use pragmatic::journal::{EraseSelector, ErasureNote, ROOT};
use pragmatic::{Content, Event, Journal};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

async fn setup() -> (TestServer, String, Writer) {
    let ts = TestServer::start(|c| c.max_request_bytes = 64 * 1024).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "run-1").await;
    w.attempt(&ts, 2).await;
    (ts, agent, w)
}

/// Send raw frames for cursor `at` with an explicit head.
async fn send(
    ts: &TestServer,
    w: &Writer,
    at: u64,
    k: u64,
    head: &str,
    frames: Vec<u8>,
) -> (StatusCode, Value) {
    let resp = send_frames(ts, &w.token, &w.run, &w.lease, at, k, head, frames).await;
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn stored_len(ts: &TestServer) -> u64 {
    stored(ts, "run-1").len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_chain_link_is_refused() {
    let (ts, _, mut w) = setup().await;
    w.add(recv("one"));
    let (at, mut frames, head, k) = w.pending();
    let last = frames.len() - 1;
    frames[last] ^= 1;
    let (status, body) = send(&ts, &w, at, k, &head, frames).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "invalid_frames");
    assert!(
        body["error"]["reason"].as_str().unwrap().contains("chain"),
        "{body}"
    );
    assert_eq!(stored_len(&ts), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_commitment_is_refused() {
    let (ts, _, mut w) = setup().await;
    w.add(recv("payload-bytes"));
    let (at, mut frames, head, k) = w.pending();
    let i = frames.windows(7).position(|x| x == b"payload").unwrap();
    frames[i] = b'P';
    let (status, body) = send(&ts, &w, at, k, &head, frames).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("commitment"),
        "{body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erased_and_withheld_slots_are_refused() {
    let (ts, _, mut w) = setup().await;
    let c = w.add(recv("secret"));
    // An erased copy of the frame: same chain hash, state 2.
    let mut copy = Journal::parse(&w.journal.to_bytes(), None).unwrap().journal;
    copy.mark_persisted(copy.len());
    let erased = copy
        .erase(
            &EraseSelector::Slots(vec![(c, 0)]),
            &ErasureNote::local("x", ""),
            1,
        )
        .unwrap();
    let frame = erased.journal.frame_bytes(c).unwrap();
    let head = hex_encode(&erased.journal.get(c).unwrap().hash);
    let (status, body) = send(&ts, &w, c, 1, &head, frame).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["reason"], "erased slots cannot be appended");

    // A withheld copy: the sealed frame with its slot state set to 3 and
    // the salt and content cut. The chain hash only covers commitments,
    // so it still links.
    let sealed = w.journal.frame_bytes(c).unwrap();
    let state_at = 4 + 1 + 8 + 1 + 1 + (4 + 2) + 1;
    assert_eq!(sealed[state_at], 1);
    let mut record = sealed[4..state_at].to_vec();
    record.push(3);
    record.extend_from_slice(&sealed[state_at + 1..state_at + 33]);
    let mut frame = (record.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&record);
    frame.extend_from_slice(&sealed[sealed.len() - 32..]);
    let (status, body) = send(&ts, &w, c, 1, &head, frame).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["reason"], "withheld slots cannot be appended");
    // The real frame still goes in.
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_only_notes_are_refused() {
    let (ts, _, mut w) = setup().await;
    for kind in ["custody", "erasure", "torn_tail"] {
        let mut copy = w.journal.clone();
        copy.append_server_note(1, kind, "{}", vec![]).unwrap();
        let (at, frames, head) = copy.pending().unwrap();
        let (status, body) = send(&ts, &w, at, 1, &hex_encode(&head), frames.to_vec()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{kind}: {body}");
        assert_eq!(
            body["error"]["reason"],
            "server-only note kinds cannot be appended"
        );
    }
    w.add(recv("fine"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_at_is_a_conflict() {
    let (ts, _, mut w) = setup().await;
    w.add(recv("x"));
    let (at, frames, head, k) = w.pending();
    let (status, body) = send(&ts, &w, at + 1, k, &head, frames.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
    assert_eq!(body["error"]["expected"], 5);
    assert_eq!(body["error"]["actual"], 6);
    // A cursor that exists, with frames that differ from what is stored:
    // not a duplicate, so a conflict.
    let (status, body) = send(&ts, &w, at - 1, k, &head, frames).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resend_after_a_lost_response_is_a_duplicate_whatever_the_lease() {
    let (ts, agent, mut w) = setup().await;
    w.add(recv("a"));
    w.add(recv("b"));
    let (at, frames, head, k) = w.pending();
    let (status, first) = send(&ts, &w, at, k, &head, frames.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["duplicate"], false);
    // The response was "lost": the client resends the identical request.
    let (status, again) = send(&ts, &w, at, k, &head, frames.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["duplicate"], true);
    assert_eq!(again["entries"], 7);
    assert_eq!(again["head"], head);
    assert_eq!(stored_len(&ts), 7);
    // Even after the lease is gone.
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    let (status, again) = send(&ts, &w, at, k, &head, frames).await;
    assert_eq!(
        (status, again["duplicate"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    let _ = agent;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_leases_work_until_taken_over_and_foreign_leases_never() {
    let (ts, agent, mut w) = setup().await;
    tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
    // Lazy expiry: still the holder's.
    w.add(recv("late"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
    // Someone else takes the run over.
    let resp = ts
        .post_json(
            &run_path("run-1", "/lease"),
            &agent,
            json!({"holder": "other-process"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let other: Value = resp.json().await.unwrap();
    assert_eq!(
        other["entries"], 7,
        "the custody note of the old lease was appended"
    );
    w.add(recv("too late"));
    let (status, c) = code(w.push(&ts).await).await;
    assert_eq!(
        (status, c.as_str()),
        (StatusCode::CONFLICT, "lease_expired")
    );

    // A lease that belongs to another token is never accepted.
    let (agent2, _) = ts.issue("agent", &["*"], false).await;
    let mut w2 = Writer {
        run: "run-1".into(),
        token: agent2,
        lease: other["lease"].as_str().unwrap().into(),
        journal: Journal::parse(&stored(&ts, "run-1").to_bytes(), None)
            .unwrap()
            .journal,
    };
    w2.add(recv("hijack"));
    let (status, c) = code(w2.push(&ts).await).await;
    assert_eq!((status, c.as_str()), (StatusCode::CONFLICT, "lease_lost"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_bodies_are_413() {
    let (ts, _, mut w) = setup().await;
    w.add(recv(&"x".repeat(70 * 1024)));
    let (status, c) = code(w.push(&ts).await).await;
    assert_eq!(
        (status, c.as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headers_and_framing_are_checked() {
    let (ts, _, mut w) = setup().await;
    w.add(recv("a"));
    w.add(recv("b"));
    let (at, frames, head, k) = w.pending();
    // The head must be the hash after the last frame.
    let wrong = hex_encode(&[7u8; 32]);
    let (status, body) = send(&ts, &w, at, k, &wrong, frames.clone()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    // The frame count must match.
    let (status, _) = send(&ts, &w, at, k + 1, &head, frames.clone()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // Whole frames only.
    let (status, _) = send(&ts, &w, at, k, &head, frames[..frames.len() - 5].to_vec()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // Trailing bytes inside a record make it non-canonical.
    let mut bad = w.journal.frame_bytes(at).unwrap();
    let len = u32::from_le_bytes(bad[..4].try_into().unwrap()) + 1;
    bad[..4].copy_from_slice(&len.to_le_bytes());
    let hash_at = bad.len() - 32;
    bad.insert(hash_at, 0);
    let one_head = hex_encode(&w.journal.get(at).unwrap().hash);
    let (status, body) = send(&ts, &w, at, 1, &one_head, bad).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    // Missing headers are bad requests.
    let resp = ts
        .req(
            Method::POST,
            &run_path("run-1", &format!("/frames?at={at}")),
            &w.token,
        )
        .body(frames.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stored_len(&ts), 5);
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(stored_len(&ts), 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refs_and_branches_round_trip() {
    let (ts, _, mut w) = setup().await;
    let big = "conversation ".repeat(50);
    let d = w.add(Event::DrawIntent {
        provenance: "anthropic".into(),
        parts: vec![Content::from(big.as_str()), Content::from("q1")],
    });
    w.add(Event::DrawResult {
        intent: d,
        meta: r#"{"outcome":"ok","usage":{"input_tokens":7}}"#.into(),
        head: Content::from("{}"),
        body: Content::from("a1"),
    });
    let d2 = w.add(Event::DrawIntent {
        provenance: "anthropic".into(),
        parts: vec![Content::from(big.as_str()), Content::from("q2")],
    });
    assert_eq!(
        w.journal.get(d2).unwrap().slots[0].state,
        pragmatic::SlotState::Ref
    );
    w.journal
        .append(
            ROOT,
            Event::Fork {
                base: 0,
                children: 2,
            },
        )
        .unwrap();
    w.journal.append(&[0], recv("child zero")).unwrap();
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let s = stored(&ts, "run-1");
    assert_eq!(s.to_bytes(), w.journal.to_bytes());
    let v: Value = ts
        .get(&run_path("run-1", ""), &ts.admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["usage"]["input_tokens"], 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn appends_to_unknown_runs_are_404() {
    let (ts, agent, w) = setup().await;
    let (at, frames, head, k) = (0, vec![0u8; 40], hex_encode(&[0u8; 32]), 1);
    let resp = send_frames(&ts, &agent, "no-such-run", &w.lease, at, k, &head, frames).await;
    assert_eq!(code(resp).await.0, StatusCode::NOT_FOUND);
    // Reserved ids are not client-writable.
    let resp = ts
        .req(Method::PUT, &run_path("pragmatic:x", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // PUT on an existing run is run_exists.
    let resp = ts
        .req(Method::PUT, &run_path("run-1", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(resp).await,
        (StatusCode::CONFLICT, "run_exists".into())
    );
}

/// A run's first entry is its own `run.start`, and no later entry is one:
/// a journal claiming to be another run (another tenant's, say) is never
/// stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_start_comes_first_and_names_the_run() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 60).await;
    let (agent, _) = ts.issue("agent", &["team-a:"], false).await;
    let resp = ts
        .req(Method::PUT, &run_path("team-a:1", ""), &agent)
        .body(pragmatic::journal::header(0).to_vec())
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    let lease = v["lease"].as_str().unwrap().to_string();
    let fresh = |data: Value| {
        let mut w = Writer {
            run: "team-a:1".into(),
            token: agent.clone(),
            lease: lease.clone(),
            journal: Journal::new(None),
        };
        w.add(note("run.start", data, vec![]));
        w
    };
    // Another run's id.
    let mut w = fresh(json!({"run_id": "team-b:payroll", "format": 2, "labels": {}}));
    let (status, c) = code(w.push(&ts).await).await;
    assert_eq!(
        (status, c.as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_frames")
    );
    // No run.start first.
    let mut w = Writer {
        run: "team-a:1".into(),
        token: agent.clone(),
        lease: lease.clone(),
        journal: Journal::new(None),
    };
    w.add(recv("hello"));
    let (status, _) = code(w.push(&ts).await).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // The right one is stored, and a second run.start later is refused.
    let mut w = fresh(json!({"run_id": "team-a:1", "format": 2, "labels": {}}));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    w.add(note("run.start", json!({"run_id": "team-a:1"}), vec![]));
    let resp = w.push(&ts).await;
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], "invalid_frames");
    assert_eq!(v["error"]["cursor"], 1);
    assert_eq!(stored(&ts, "team-a:1").len(), 1);
}

/// A client that never finishes its headers is disconnected after the
/// header timeout, rather than holding a connection for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_never_finishes_its_headers_is_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let limits = pragmatic_server::server::Limits {
        header_read_timeout: std::time::Duration::from_secs(1),
        ..Default::default()
    };
    let ts = TestServer::start_limited(|_| {}, limits).await;
    let addr = ts.url.trim_start_matches("http://").to_string();
    let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
    s.write_all(b"GET /v1/info HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf)).await;
    assert!(
        read.is_ok(),
        "a connection that stopped mid-headers was still open after 10 s"
    );
    // A normal request still works.
    assert_eq!(ts.get("/v1/info", &ts.admin).await.status(), StatusCode::OK);
}

/// A request that can only be refused (no lease) is refused before its
/// body is read, and the client still gets the answer rather than a reset
/// connection while it sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_without_the_lease_are_refused_before_the_body_is_read() {
    let ts = TestServer::start(|c| c.lease_ttl_secs = 600).await;
    let (owner, _) = ts.issue("agent", &["*"], false).await;
    let (other, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &owner, "leased").await;
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    for (lease, want) in [
        ("not-a-lease", "lease_lost"),
        (w.lease.as_str(), "lease_lost"),
    ] {
        let resp = ts
            .req(Method::POST, &run_path("leased", "/frames?at=1"), &other)
            .header("pragmatic-lease", lease)
            .header("pragmatic-frames", "1")
            .header("pragmatic-head", "0".repeat(64))
            .body(vec![0u8; 8 << 20])
            .send()
            .await
            .unwrap();
        assert_eq!(code(resp).await, (StatusCode::CONFLICT, want.to_string()));
    }
    // A wrong `at` with the lease: conflict, also before the body.
    let resp = ts
        .req(Method::POST, &run_path("leased", "/frames?at=7"), &owner)
        .header("pragmatic-lease", &w.lease)
        .header("pragmatic-frames", "1")
        .header("pragmatic-head", "0".repeat(64))
        .body(vec![0u8; 8 << 20])
        .send()
        .await
        .unwrap();
    assert_eq!(code(resp).await.1, "conflict");
    // The connection pool still works afterwards.
    w.add(recv("after"));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
}

/// A resend of frames already stored is answered as a duplicate whatever
/// the lease (design 4.6), also when the writer's journal is not loaded:
/// the hashes are read from disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicates_are_answered_from_stored_hashes_without_the_lease() {
    let (ts, _, mut w) = setup().await;
    let (at, frames, head, k) = {
        w.add(recv("one more"));
        w.pending()
    };
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(&ts).await.status(), StatusCode::NO_CONTENT);
    // Released: the writer's journal is dropped. A resend with the old
    // lease is still a duplicate.
    assert!(ts.app().store.get("run-1").unwrap().lock().writer.is_none());
    let resp = send_frames(&ts, &w.token, &w.run, &w.lease, at, k, &head, frames).await;
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["duplicate"], true, "{v}");
    assert_eq!(v["head"], head);
    assert!(ts.app().store.get("run-1").unwrap().lock().writer.is_none());
}
