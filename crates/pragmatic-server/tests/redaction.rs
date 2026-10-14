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
    // Personal data as object keys: a map keyed by customer.
    let mut by_customer = serde_json::Map::new();
    for seed in SEEDS {
        by_customer.insert(seed.to_string(), json!({"orders": 1}));
    }
    by_customer.insert("4111111111111111".into(), json!("visa"));
    w.add(recv(&json!({ "customers": by_customer }).to_string()));
    // JSON that is not strict (a repeated key) still has its image
    // withheld, and its text redacted.
    w.add(recv(&format!(
        r#"{{"role":"user","role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{}"}}}},{{"type":"text","text":"{}"}}]}}"#,
        image(),
        SEEDS.join(" / ")
    )));
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

/// The same scan over the integrated surfaces: evidence bundles in every
/// mode a viewer without `view_raw` may ask for (their journals decoded,
/// since base64 would hide a seed from a text search) and the console's
/// pages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundles_and_the_console_never_show_seeded_personal_data_without_view_raw() {
    let ts = TestServer::start_integrated(
        |c| c.redaction.patterns = vec![r"AKIA[0-9A-Z]{16}".into()],
        pragmatic_server::anchoring::Options::default(),
    )
    .await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    seeded_run(&ts, &agent, "support:1").await;
    let (auditor, _) = ts.issue("auditor", &["support:"], false).await;
    for mode in ["", "?redact=detectors", "?redact=all"] {
        let resp = ts
            .get(
                &run_path("support:1", &format!("/evidence{mode}")),
                &auditor,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "{mode}");
        let text = resp.text().await.unwrap();
        let bundle = pragmatic::evidence::Bundle::from_json(text.as_bytes()).unwrap();
        let journal = String::from_utf8_lossy(&bundle.journal.bytes).into_owned();
        assert!(leaks(&text).is_empty(), "{mode}: {:?}", leaks(&text));
        assert!(
            leaks(&journal).is_empty(),
            "{mode} journal: {:?}",
            leaks(&journal)
        );
    }
    // `none` and `binary` (which withholds attachments only) carry text
    // slots in clear: refused without view_raw, never served.
    for mode in ["none", "binary"] {
        let resp = ts
            .get(
                &run_path("support:1", &format!("/evidence?redact={mode}")),
                &auditor,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{mode}");
        assert!(leaks(&resp.text().await.unwrap()).is_empty());
    }
    let cookie = console_session(&ts, &auditor).await;
    for path in [
        "/console",
        "/console/runs/support:1",
        "/console/runs/support:1?from=4",
        "/console/access",
    ] {
        let resp = ts
            .client
            .get(format!("{}{path}", ts.url))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let body = resp.text().await.unwrap();
        assert!(leaks(&body).is_empty(), "{path} leaks {:?}", leaks(&body));
    }
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

/// A slot that is JSON but not strict JSON keeps its attachments withheld
/// in every view (design 4.10): a second `type` member in an Anthropic
/// source block does not uncover the image's base64 to an auditor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_key_never_uncovers_an_image_in_the_entries_view() {
    let ts = TestServer::start(|_| {}).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut png = vec![0x89u8, b'P', b'N', b'G', 13, 10, 26, 10];
    png.extend((0..292u32).map(|i| (i * 7 % 251) as u8));
    let b64 = base64_encode(&png);
    let request = format!(
        r#"{{"model":"claude","messages":[{{"role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}","type":"base64-image"}}}}]}}]}}"#
    );
    let mut w = Writer::create(&ts, &agent, "support:2").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    w.add(Event::ChannelRecv {
        channel: "in".into(),
        value: Content::from(request.as_str()),
    });
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let (auditor, _) = ts.issue("auditor", &["support:"], false).await;
    for path in ["/entries", "/entries/2/slots/0"] {
        let body = ts
            .get(&run_path("support:2", path), &auditor)
            .await
            .text()
            .await
            .unwrap();
        assert!(!body.contains(&b64), "{path} served the image");
        assert!(
            body.contains("[binary media_type=image/png bytes=300"),
            "{path}: {body}"
        );
    }
}

/// A model's streamed reply that repeats personal data across its token
/// deltas: an auditor without `view_raw` sees the reassembled text with
/// the value redacted, never the deltas, and a `detectors` bundle
/// withholds the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_value_split_across_stream_deltas_is_redacted_in_views_and_bundles() {
    let ts =
        TestServer::start_integrated(|_| {}, pragmatic_server::anchoring::Options::default()).await;
    let (agent, _) = ts.issue("agent", &["*"], false).await;
    let mut w = Writer::create(&ts, &agent, "support:3").await;
    w.add(note("attempt.start", json!({"attempt": 1}), vec![]));
    let d = w.add(Event::DrawIntent {
        provenance: "anthropic".into(),
        parts: vec![Content::from(r#"{"model":"claude","stream":true}"#)],
    });
    let mut body = String::new();
    for delta in [
        "A confirmation went to ",
        "jane",
        ".doe",
        "@example",
        ".com",
        ".",
    ] {
        body.push_str("event: content_block_delta\ndata: ");
        body.push_str(
            &json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": delta}})
            .to_string(),
        );
        body.push_str("\n\n");
    }
    w.add(Event::DrawResult {
        intent: d,
        meta: r#"{"outcome":"ok"}"#.into(),
        head: Content::from(r#"{"status":200}"#),
        body: Content::from(body.as_str()),
    });
    w.add(note(
        "attempt.end",
        json!({"attempt": 1, "outcome": "ok"}),
        vec![],
    ));
    assert_eq!(w.push(&ts).await.status(), StatusCode::OK);
    let (auditor, _) = ts.issue("auditor", &["support:"], false).await;
    let view = ts
        .get(&run_path("support:3", "/entries/3/slots/1"), &auditor)
        .await
        .text()
        .await
        .unwrap();
    assert!(view.contains("[email]"), "{view}");
    assert!(!view.contains(".doe"), "{view}");
    let resp = ts
        .get(
            &run_path("support:3", "/evidence?redact=detectors"),
            &auditor,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let b = pragmatic::evidence::Bundle::from_json(&resp.bytes().await.unwrap()).unwrap();
    assert!(b.redacted_slots.contains(&(3, 1)), "{:?}", b.redacted_slots);
}
