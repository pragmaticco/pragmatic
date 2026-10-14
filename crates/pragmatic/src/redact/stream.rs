//! The text of a streamed model reply, put back together (design 2.13 and
//! 4.10).
//!
//! A streamed reply is journaled as the bytes the provider sent: a
//! server-sent event stream whose text arrives in deltas of a few
//! characters each. An email address the model repeated back is stored as
//! `jane`, `.doe`, `@example`, `.com` in four events, so neither a search
//! over the stored bytes (erasure by `match`) nor a detector finds it,
//! though anyone reading the stream joins it back in a moment. [`texts`]
//! reassembles what the model said in each part of the stream, so erasure
//! and redaction can look at that too.
//!
//! Each `data:` line holding one JSON object is an event. These are read:
//!
//! - Anthropic Messages: `content_block_delta` events, whose `delta` holds
//!   `text` (`text_delta`), `partial_json` (`input_json_delta`, a tool's
//!   input) or `thinking` (`thinking_delta`), one part per content block
//!   `index`;
//! - OpenAI Chat Completions: `choices[].delta.content` (and `refusal`),
//!   one part per choice `index`, and `choices[].delta.tool_calls[]`
//!   `function.arguments`, one part per tool call;
//! - OpenAI Responses: events whose `type` ends in `.delta` and whose
//!   `delta` is a string (`response.output_text.delta`,
//!   `response.function_call_arguments.delta`, ...), one part per event
//!   type, `output_index` and `content_index`.
//!
//! Everything else is ignored, and bytes that are not an event stream
//! yield nothing. Parts are kept apart because providers interleave them
//! (two choices, or a tool call next to text): joining across parts would
//! split what was said in each.

use crate::json::{self, Json};

/// The reassembled text of each part of an event stream, in the order the
/// parts first appear. Empty when `bytes` is not an event stream, or holds
/// no text deltas.
pub fn texts(bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    if !text.contains("data:") {
        return Vec::new();
    }
    let mut parts: Vec<(String, String)> = Vec::new();
    let mut add = |key: String, delta: &str| {
        if delta.is_empty() {
            return;
        }
        match parts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, t)) => t.push_str(delta),
            None => parts.push((key, delta.to_string())),
        }
    };
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.strip_prefix(' ').unwrap_or(data);
        if !data.starts_with('{') {
            continue;
        }
        let Ok(event) = json::parse(data) else {
            continue;
        };
        anthropic(&event, &mut add);
        chat(&event, &mut add);
        responses(&event, &mut add);
    }
    parts.into_iter().map(|(_, t)| t).collect()
}

/// True when the reassembled text of some part of the stream in `bytes`
/// contains `needle`.
pub fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && texts(bytes)
            .iter()
            .any(|t| t.as_bytes().windows(needle.len()).any(|w| w == needle))
}

fn text(v: Option<&Json>) -> Option<&str> {
    v.and_then(Json::as_str)
}

fn index(v: Option<&Json>) -> String {
    match v {
        Some(Json::Number(n)) => n.as_str().to_string(),
        _ => "0".to_string(),
    }
}

/// Anthropic Messages: `content_block_delta`.
fn anthropic(event: &Json, add: &mut impl FnMut(String, &str)) {
    if text(event.get("type")) != Some("content_block_delta") {
        return;
    }
    let Some(delta) = event.get("delta") else {
        return;
    };
    let key = format!("anthropic:{}", index(event.get("index")));
    for field in ["text", "partial_json", "thinking"] {
        if let Some(t) = text(delta.get(field)) {
            add(format!("{key}:{field}"), t);
        }
    }
}

/// OpenAI Chat Completions: `choices[].delta`.
fn chat(event: &Json, add: &mut impl FnMut(String, &str)) {
    let Some(choices) = event.get("choices").and_then(Json::as_array) else {
        return;
    };
    for choice in choices {
        let Some(delta) = choice.get("delta") else {
            continue;
        };
        let key = format!("chat:{}", index(choice.get("index")));
        for field in ["content", "refusal"] {
            if let Some(t) = text(delta.get(field)) {
                add(format!("{key}:{field}"), t);
            }
        }
        let Some(calls) = delta.get("tool_calls").and_then(Json::as_array) else {
            continue;
        };
        for call in calls {
            if let Some(t) = text(call.get("function").and_then(|f| f.get("arguments"))) {
                add(format!("{key}:tool:{}", index(call.get("index"))), t);
            }
        }
    }
}

/// OpenAI Responses: `*.delta` events with a string `delta`.
fn responses(event: &Json, add: &mut impl FnMut(String, &str)) {
    let Some(kind) = text(event.get("type")) else {
        return;
    };
    if !kind.ends_with(".delta") {
        return;
    }
    if let Some(t) = text(event.get("delta")) {
        let key = format!(
            "responses:{kind}:{}:{}",
            index(event.get("output_index")),
            index(event.get("content_index"))
        );
        add(key, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(events: &[&str]) -> String {
        let mut out = String::new();
        for e in events {
            out.push_str("event: x\ndata: ");
            out.push_str(e);
            out.push_str("\n\n");
        }
        out
    }

    #[test]
    fn anthropic_text_deltas_are_joined_per_block() {
        let body = sse(&[
            r#"{"type":"message_start","message":{"id":"m"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"mail jane"}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"to\":\"bob"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":".doe@example"}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"@example.org\"}"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":".com"}}"#,
        ]);
        assert_eq!(
            texts(body.as_bytes()),
            vec![
                "mail jane.doe@example.com".to_string(),
                r#"{"to":"bob@example.org"}"#.to_string()
            ]
        );
        assert!(contains(body.as_bytes(), b"jane.doe@example.com"));
        assert!(!contains(body.as_bytes(), b"jane.doe@example.combob"));
    }

    #[test]
    fn openai_chat_and_responses_deltas_are_joined() {
        let chat = sse(&[
            r#"{"choices":[{"index":0,"delta":{"content":"hi ja"}},{"index":1,"delta":{"content":"other"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"content":"ne@x.example"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":\"12"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"3-45-6789\"}"}}]}}]}"#,
            "[DONE]",
        ]);
        let got = texts(chat.as_bytes());
        assert!(got.contains(&"hi jane@x.example".to_string()), "{got:?}");
        assert!(got.contains(&"other".to_string()));
        assert!(got.contains(&r#"{"q":"123-45-6789"}"#.to_string()));
        let resp = sse(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"jane"}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"@x.example"}"#,
        ]);
        assert_eq!(texts(resp.as_bytes()), vec!["jane@x.example".to_string()]);
    }

    #[test]
    fn other_bytes_yield_nothing() {
        assert!(texts(b"plain text").is_empty());
        assert!(texts(br#"{"data:":"x"}"#).is_empty());
        assert!(texts(&[0xff, 0x00]).is_empty());
        assert!(texts(b"data: not json\n").is_empty());
        assert!(!contains(b"data: {}\n", b""));
    }
}
