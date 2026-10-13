//! A redaction coverage scan (design 4.10 and 9): personal data seeded into
//! every kind of content must not reach an auditor without `view_raw`
//! through any response the server gives it.

mod common;

use common::*;
use pragmatic::encoding::base64_encode;
use pragmatic::{Content, EffectOutcome, Event};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const SEEDS: &[&str] = &[
    "jane.doe@example.com",
    "+1 415 555 0123",
    "123-45-6789",
    "4111 1111 1111 1111",
    "DE89370400440532013000",
    "198.51.100.23",
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
    "AKIAIOSFODNN7EXAMPLE",
];

fn image() -> String {
    base64_encode(&[
        0x89u8, b'P', b'N', b'G', 13, 10, 26, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    ])
}

/// A run that carries every seed in every place content can live.
async fn seeded_run(ts: &TestServer, token: &str, run: &str) {
    let mut w = Writer {
        run: run.into(),
        token: token.into(),
        lease: Writer::create(ts, token, run).await.lease,
        journal: pragmatic::Journal::new(None),
    };
    let all = SEEDS.join(" / ");
    w.add(note(
        "run.start",
        json!({"run_id": run, "labels": {"team": "support"}}),
        vec![Content::from(json!({"subjects": [SEEDS[0]]}).to_string())],
    ));
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    let request = json!({
        "model": "claude",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": format!("Customer details: {all}")},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image()}},
        ]}],
    });
    let d = w.add(Event::DrawIntent {
        provenance: "anthropic".into(),
        parts: vec![
            Content::from(request.to_string()),
            Content::from(format!("plain text: {all}")),
        ],
    });
    w.add(Event::DrawResult {
        intent: d,
        meta: r#"{"outcome":"ok"}"#.into(),
        head: Content::from(r#"{"status":200}"#),
        body: Content::from(
            json!({"content": [{"type": "text", "text": format!("Noted: {all}")}]}).to_string(),
        ),
    });
    let e = w.add(Event::EffectIntent {
        name: "send_email".into(),
        arg: Content::from(
            json!({"to": SEEDS[0], "card": 4111111111111111u64, "ip": SEEDS[5]}).to_string(),
        ),
    });
    w.add(Event::EffectResult {
        intent: e,
        outcome: EffectOutcome::Ok,
        error_kind: String::new(),
        payload: Some(Content::from(format!("delivered to {}", SEEDS[0]))),
    });
    w.add(recv(&format!("inbound: {all}")));
    w.add(Event::Random {
        source: "bytes".into(),
        args: "[4]".into(),
        value: Content::from(vec![0xff, 0x00, 0xfe, 0x01]),
    });
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![Content::from(format!("final answer for {all}"))],
    ));
    assert_eq!(w.push(ts).await.status(), StatusCode::OK);
    assert_eq!(w.release(ts).await.status(), StatusCode::NO_CONTENT);
    // An erasure whose free-text reason is itself personal.
    let resp = ts
        .post_json(
            &run_path(run, "/erase"),
            &ts.admin,
            json!({"slots": [[6, 0]], "reason_code": "dsar", "reason": format!("asked by {}", SEEDS[0])}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

fn leaks(body: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = SEEDS.iter().copied().filter(|s| body.contains(s)).collect();
    if body.contains(&image()) {
        found.push("image base64");
    }
    // Numbers can come back unformatted inside JSON.
    if body.contains("4111111111111111") {
        found.push("card digits");
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_auditor_without_view_raw_never_sees_seeded_personal_data() {
    let ts = TestServer::start(|c| c.redaction.patterns = vec![r"AKIA[0-9A-Z]{16}".into()]).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    seeded_run(&ts, &agent, "support:1").await;
    let (auditor, _) = ts.issue("auditor", &["support:"], false).await;

    let mut surfaces: Vec<String> = vec![
        "/v1/runs".into(),
        "/v1/runs?q=support".into(),
        run_path("support:1", ""),
        run_path("support:1", "/entries"),
        run_path("support:1", "/entries?from=2&limit=3"),
        run_path("support:1", "/journal"),
        run_path("support:1", "/evidence"),
        run_path("support:1", "/evidence?redact=none"),
        "/v1/audit".into(),
        "/v1/audit?run_id=support:1".into(),
        "/v1/anchors".into(),
        "/v1/anchors/log".into(),
        "/v1/whoami".into(),
        "/v1/info".into(),
        "/console".into(),
    ];
    let j = stored(&ts, "support:1");
    for e in j.entries() {
        for k in 0..e.slots.len() {
            surfaces.push(run_path(
                "support:1",
                &format!("/entries/{}/slots/{k}", e.cursor),
            ));
        }
    }
    let mut checked = 0;
    for path in &surfaces {
        let resp = ts.req(Method::GET, path, &auditor).send().await.unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap();
        let found = leaks(&body);
        assert!(
            found.is_empty(),
            "{path} ({status}) leaks {found:?}: {body}"
        );
        checked += 1;
    }
    let metrics = ts
        .client
        .get(format!("{}/metrics", ts.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(leaks(&metrics).is_empty());
    assert!(!metrics.contains("support:1"), "metrics carry no run ids");
    assert!(checked > 25);

    // The scan means something: a view_raw auditor does see the seeds.
    let (raw, _) = ts.issue("auditor", &["support:"], true).await;
    let body = ts
        .get(&run_path("support:1", "/entries"), &raw)
        .await
        .text()
        .await
        .unwrap();
    assert!(!leaks(&body).is_empty());
    // And binary content is described, never served, without view_raw.
    let v: Value = ts
        .get(&run_path("support:1", "/entries/7/slots/0"), &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert!(v["base64"].is_null());
    assert_eq!(v["binary"]["bytes"], 4);
    let v: Value = ts
        .get(&run_path("support:1", "/entries/2/slots/0"), &auditor)
        .await
        .json()
        .await
        .unwrap();
    assert!(v["text"]
        .as_str()
        .unwrap()
        .contains("[binary media_type=image/png bytes=18 sha256="));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn salts_are_never_served_in_any_view() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "r").await;
    w.attempt(&ts, 3).await;
    let (raw, _) = ts.issue("auditor", &["*"], true).await;
    let body = ts
        .get(&run_path("r", "/entries"), &raw)
        .await
        .text()
        .await
        .unwrap();
    let j = stored(&ts, "r");
    // Every sealed slot's salt sits right after its commitment in the
    // frame; none of them may appear in the JSON view.
    for e in j.entries() {
        let frame = j.frame_bytes(e.cursor).unwrap();
        for s in &e.slots {
            if s.state != pragmatic::SlotState::Sealed {
                continue;
            }
            let at = frame.windows(32).position(|w| w == s.commitment).unwrap() + 32;
            let salt = &frame[at..at + 16];
            assert!(!body.contains(&pragmatic::encoding::hex_encode(salt)));
            assert!(!body.contains(&base64_encode(salt)));
        }
    }
    assert!(!body.contains("salt"));
}
