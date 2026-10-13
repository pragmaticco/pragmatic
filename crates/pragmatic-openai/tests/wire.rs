//! Live-fire wire tests: drive `OpenAiOracle` through real TCP sockets
//! against a local mock that speaks the Chat Completions API's shapes -
//! success, rate limits, server errors, malformed JSON - and through the
//! full durable runtime (record on the wire, replay with the server gone).
//!
//! A `#[ignore]`d test at the bottom hits the real API when
//! `OPENAI_API_KEY` is set (run with `cargo test -- --ignored`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use pragmatic::{Fault, Oracle, Runtime, Value};
use pragmatic_openai::OpenAiOracle;

/// One-shot mock server: accepts `hits` connections, answers each with the
/// canned (status, body), records the request bytes, then exits.
fn mock_server(
    responses: Vec<(u16, String)>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read the request until the end of its body (Content-Length).
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let request = loop {
                let n = stream.read(&mut tmp).expect("read");
                buf.extend_from_slice(&tmp[..n]);
                let text = String::from_utf8_lossy(&buf);
                if let Some(header_end) = text.find("\r\n\r\n") {
                    let content_length = text
                        .lines()
                        .find_map(|l| {
                            let l = l.to_ascii_lowercase();
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= header_end + 4 + content_length {
                        break text.into_owned();
                    }
                }
            };
            tx.send(request).ok();
            let reason = match status {
                200 => "OK",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                _ => "Unknown",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write");
        }
    });
    (format!("http://{addr}"), rx, handle)
}

fn ok_body(text: &str) -> String {
    format!(
        r#"{{"id":"chatcmpl-test","object":"chat.completion",
           "model":"gpt-5","choices":[{{"index":0,
           "message":{{"role":"assistant","content":"{text}"}},
           "finish_reason":"stop"}}],
           "usage":{{"prompt_tokens":10,"completion_tokens":5}}}}"#
    )
}

#[test]
fn success_roundtrip_over_real_sockets() {
    let (url, rx, handle) = mock_server(vec![(200, ok_body("Hello from the mock"))]);
    let oracle = OpenAiOracle::new("test-key")
        .base_url(&url)
        .model("gpt-5")
        .system("be terse");

    let out = oracle
        .call(&Value::from("say hello"))
        .expect("call succeeds");
    assert_eq!(out.as_str(), "Hello from the mock");

    // The request that actually crossed the wire has the right shape.
    let request = rx.recv().unwrap();
    assert!(request.starts_with("POST /chat/completions"));
    assert!(request.contains("authorization: Bearer test-key"));
    assert!(request.contains(r#""model":"gpt-5""#));
    assert!(request.contains(r#""role":"system""#));
    assert!(request.contains("say hello"));
    handle.join().unwrap();
}

#[test]
fn no_auth_header_without_key() {
    let (url, rx, handle) = mock_server(vec![(200, ok_body("local"))]);
    let oracle = OpenAiOracle::new("").base_url(&url).model("llama3.3");
    oracle.call(&Value::from("p")).expect("call succeeds");
    let request = rx.recv().unwrap();
    assert!(
        !request.to_ascii_lowercase().contains("authorization:"),
        "keyless call must not send an Authorization header"
    );
    handle.join().unwrap();
}

#[test]
fn rate_limit_maps_to_oracle_fault() {
    let (url, _rx, handle) = mock_server(vec![(
        429,
        r#"{"error":{"type":"rate_limit_error","message":"slow down"}}"#.into(),
    )]);
    let oracle = OpenAiOracle::new("k").base_url(&url);
    let err = oracle.call(&Value::from("p")).unwrap_err();
    match err {
        Fault::OracleErr(msg) => {
            assert!(
                msg.contains("429"),
                "message should carry the status: {msg}"
            );
            assert!(
                msg.contains("slow down"),
                "message should carry detail: {msg}"
            );
        }
        other => panic!("expected OracleErr, got {other}"),
    }
    handle.join().unwrap();
}

#[test]
fn server_error_and_malformed_are_faults_not_panics() {
    // 500 server error
    let (url, _rx, h) = mock_server(vec![(500, r#"{"error":{}}"#.into())]);
    assert!(matches!(
        OpenAiOracle::new("k")
            .base_url(&url)
            .call(&Value::from("p")),
        Err(Fault::OracleErr(_))
    ));
    h.join().unwrap();

    // 200 with garbage JSON
    let (url, _rx, h) = mock_server(vec![(200, "{not json at all".into())]);
    assert!(matches!(
        OpenAiOracle::new("k")
            .base_url(&url)
            .call(&Value::from("p")),
        Err(Fault::OracleErr(_))
    ));
    h.join().unwrap();

    // Connection refused (server not listening)
    let dead = OpenAiOracle::new("k").base_url("http://127.0.0.1:1");
    assert!(matches!(
        dead.call(&Value::from("p")),
        Err(Fault::OracleErr(_))
    ));
}

/// The guarantee customers actually buy: record against the live wire, then
/// kill the server - resume and replay still work, because outcomes come
/// from the journal, not the API.
#[test]
fn durable_run_survives_the_api_disappearing() {
    let (url, _rx, handle) =
        mock_server(vec![(200, ok_body("a plan")), (200, ok_body("a result"))]);
    let agent = |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
        let plan = ctx.oracle("plan")?;
        ctx.oracle(format!("execute: {plan}"))
    };

    let dir = std::env::temp_dir().join(format!("pragmatic-openai-wire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let recorded = {
        let oracle = OpenAiOracle::new("k").base_url(&url);
        let rt = Runtime::on_dir(&dir, oracle).unwrap();
        rt.run("wire-run", agent).unwrap()
    };
    handle.join().unwrap(); // mock server is now GONE

    // New process, no server: resume replays everything from the journal.
    let oracle = OpenAiOracle::new("k").base_url("http://127.0.0.1:1");
    let rt = Runtime::on_dir(&dir, oracle).unwrap();
    let resumed = rt.resume("wire-run", agent).unwrap();
    assert_eq!(resumed.trace, recorded.trace);
    assert_eq!(resumed.output.as_str(), "a result");
    let audit = rt.replay("wire-run", agent).unwrap();
    assert_eq!(audit.trace, recorded.trace);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Hits the real OpenAI API. Ignored by default; run explicitly:
/// `OPENAI_API_KEY=... cargo test -p pragmatic-openai -- --ignored`
#[test]
#[ignore = "requires OPENAI_API_KEY and network"]
fn live_api_record_and_replay() {
    let Ok(oracle) = OpenAiOracle::from_env() else {
        eprintln!("OPENAI_API_KEY not set; skipping");
        return;
    };
    let oracle = oracle.max_tokens(64);
    let agent = |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
        ctx.oracle("Reply with exactly the word: pong")
    };
    let rt = Runtime::in_memory(oracle);
    let recorded = rt.run("live", agent).expect("live call");
    assert!(!recorded.output.is_empty());
    let replayed = rt.replay("live", agent).expect("replay");
    assert_eq!(recorded.trace, replayed.trace);
}
