//! Live-fire wire tests: drive `AnthropicOracle` through real TCP sockets
//! against a local mock that speaks the Messages API's shapes - success,
//! rate limits, server errors, malformed JSON - and through the full durable
//! runtime (record on the wire, replay with the server gone).
//!
//! A `#[ignore]`d test at the bottom hits the real API when
//! `ANTHROPIC_API_KEY` is set (run with `cargo test -- --ignored`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use pragmatic::{Fault, Oracle, Runtime, Value};
use pragmatic_anthropic::AnthropicOracle;

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
                529 => "Overloaded",
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
        r#"{{"id":"msg_test","type":"message","role":"assistant",
           "content":[{{"type":"text","text":"{text}"}}],
           "model":"claude-sonnet-5","stop_reason":"end_turn",
           "usage":{{"input_tokens":10,"output_tokens":5}}}}"#
    )
}

#[test]
fn success_roundtrip_over_real_sockets() {
    let (url, rx, handle) = mock_server(vec![(200, ok_body("Hello from the mock"))]);
    let oracle = AnthropicOracle::new("test-key")
        .base_url(&url)
        .model("claude-sonnet-5")
        .system("be terse");

    let out = oracle
        .call(&Value::from("say hello"))
        .expect("call succeeds");
    assert_eq!(out.as_str(), "Hello from the mock");

    // The request that actually crossed the wire has the right shape.
    let request = rx.recv().unwrap();
    assert!(request.starts_with("POST /v1/messages"));
    assert!(request.contains("x-api-key: test-key"));
    assert!(request.contains("anthropic-version: 2023-06-01"));
    assert!(request.contains(r#""model":"claude-sonnet-5""#));
    assert!(request.contains("say hello"));
    handle.join().unwrap();
}

#[test]
fn rate_limit_maps_to_oracle_fault() {
    let (url, _rx, handle) = mock_server(vec![(
        429,
        r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#.into(),
    )]);
    let oracle = AnthropicOracle::new("k").base_url(&url);
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
fn overloaded_and_malformed_are_faults_not_panics() {
    // 529 overloaded
    let (url, _rx, h) = mock_server(vec![(529, r#"{"type":"error"}"#.into())]);
    assert!(matches!(
        AnthropicOracle::new("k")
            .base_url(&url)
            .call(&Value::from("p")),
        Err(Fault::OracleErr(_))
    ));
    h.join().unwrap();

    // 200 with garbage JSON
    let (url, _rx, h) = mock_server(vec![(200, "{not json at all".into())]);
    assert!(matches!(
        AnthropicOracle::new("k")
            .base_url(&url)
            .call(&Value::from("p")),
        Err(Fault::OracleErr(_))
    ));
    h.join().unwrap();

    // Connection refused (server not listening)
    let dead = AnthropicOracle::new("k").base_url("http://127.0.0.1:1");
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

    let dir = std::env::temp_dir().join(format!("pragmatic-wire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let recorded = {
        let oracle = AnthropicOracle::new("k").base_url(&url);
        let rt = Runtime::on_dir(&dir, oracle).unwrap();
        rt.run("wire-run", agent).unwrap()
    };
    handle.join().unwrap(); // mock server is now GONE

    // New process, no server: resume replays everything from the journal.
    let oracle = AnthropicOracle::new("k").base_url("http://127.0.0.1:1");
    let rt = Runtime::on_dir(&dir, oracle).unwrap();
    let resumed = rt.resume("wire-run", agent).unwrap();
    assert_eq!(resumed.trace, recorded.trace);
    assert_eq!(resumed.output.as_str(), "a result");
    let audit = rt.replay("wire-run", agent).unwrap();
    assert_eq!(audit.trace, recorded.trace);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The tool-use loop, end to end over real sockets: the model asks for a
/// tool, the tool runs as a journaled effect, the result goes back, the
/// model answers - then the API disappears and the whole loop (model turns
/// AND tool results) replays from the journal with zero calls to either.
#[test]
fn tool_loop_records_resumes_and_replays() {
    use pragmatic_anthropic::{Conversation, Turn};
    use serde_json::json;
    use std::cell::Cell;

    let tool_turn = json!({
        "id": "msg_1", "type": "message", "role": "assistant",
        "content": [
            { "type": "text", "text": "Searching." },
            { "type": "tool_use", "id": "tu_1", "name": "search",
              "input": { "q": "durable execution" } }
        ],
        "model": "claude-sonnet-5", "stop_reason": "tool_use",
        "usage": { "input_tokens": 20, "output_tokens": 15 }
    });
    let final_turn = json!({
        "id": "msg_2", "type": "message", "role": "assistant",
        "content": [{ "type": "text", "text": "Found 3 papers." }],
        "model": "claude-sonnet-5", "stop_reason": "end_turn",
        "usage": { "input_tokens": 40, "output_tokens": 8 }
    });
    let (url, rx, handle) = mock_server(vec![
        (200, tool_turn.to_string()),
        (200, final_turn.to_string()),
    ]);

    let tool_runs = std::rc::Rc::new(Cell::new(0u32));
    let agent_runs = tool_runs.clone();
    let agent = move |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
        let runs = agent_runs.clone();
        let mut convo = Conversation::user("Find papers on durable execution.");
        loop {
            let turn = Turn::parse(&ctx.oracle(convo.prompt())?)?;
            convo.push_assistant(&turn);
            if !turn.wants_tools() {
                return Ok(Value::from(turn.text()));
            }
            for call in turn.tool_uses() {
                let result = ctx.effect("search", call.input.to_string(), |_| {
                    runs.set(runs.get() + 1);
                    Ok(Value::from("3 hits"))
                })?;
                convo.push_tool_result(&call.id, result.as_str());
            }
        }
    };

    let dir = std::env::temp_dir().join(format!("pragmatic-toolwire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let recorded = {
        let oracle = AnthropicOracle::new("k").base_url(&url).tools(
            json!([{ "name": "search", "description": "Search the corpus",
                            "input_schema": { "type": "object" } }]),
        );
        let rt = Runtime::on_dir(&dir, oracle).unwrap();
        rt.run("tool-loop", agent.clone()).unwrap()
    };
    assert_eq!(recorded.output.as_str(), "Found 3 papers.");
    assert_eq!(tool_runs.get(), 1);

    // What crossed the wire: tools declared on both calls, and the second
    // request carried the assistant's tool_use turn plus our tool_result.
    let first = rx.recv().unwrap();
    assert!(first.contains(r#""tools":"#));
    let second = rx.recv().unwrap();
    assert!(second.contains(r#""type":"tool_use""#));
    assert!(second.contains(r#""tool_use_id":"tu_1""#));
    assert!(second.contains("3 hits"));
    handle.join().unwrap(); // the API is now GONE

    // New process, dead endpoint: resume and replay serve every model turn
    // and every tool result from the journal - the tool does not run again.
    let oracle = AnthropicOracle::new("k").base_url("http://127.0.0.1:1");
    let rt = Runtime::on_dir(&dir, oracle).unwrap();
    let resumed = rt.resume("tool-loop", agent.clone()).unwrap();
    assert_eq!(resumed.trace, recorded.trace);
    let audit = rt.replay("tool-loop", agent).unwrap();
    assert_eq!(audit.trace, recorded.trace);
    assert_eq!(tool_runs.get(), 1, "tool performed exactly once, ever");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Hits the real Anthropic API. Ignored by default; run explicitly:
/// `ANTHROPIC_API_KEY=... cargo test -p pragmatic-anthropic -- --ignored`
#[test]
#[ignore = "requires ANTHROPIC_API_KEY and network"]
fn live_api_record_and_replay() {
    let Ok(oracle) = AnthropicOracle::from_env() else {
        eprintln!("ANTHROPIC_API_KEY not set; skipping");
        return;
    };
    let oracle = oracle.model("claude-sonnet-5").max_tokens(64);
    let agent = |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
        ctx.oracle("Reply with exactly the word: pong")
    };
    let rt = Runtime::in_memory(oracle);
    let recorded = rt.run("live", agent).expect("live call");
    assert!(!recorded.output.is_empty());
    let replayed = rt.replay("live", agent).expect("replay");
    assert_eq!(recorded.trace, replayed.trace);
}
