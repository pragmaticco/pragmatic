//! How recorded content reaches a timeline row: as a short excerpt of
//! prose, as a gist of data, or as the state of a slot. Nothing else of a
//! slot's content is ever put in a row's title.
//!
//! - An **excerpt** is recorded prose with its whitespace collapsed, its
//!   control characters escaped ([`text::sanitize`]) and clipped at a
//!   sentence end or a word boundary. The console shows it in its own
//!   curly quotes, so a recorded string can never pass for one of the
//!   console's words.
//! - A **gist** is recorded data in a line of mono: an object's members in
//!   recorded order (`charges ×2, status delivered`), with the tool-call
//!   envelopes the SDKs write unwrapped and, for a result, the members the
//!   input already said left out.
//! - A **model response** is recognised by the same shape tests as the
//!   SDK's `tool_calls`: Anthropic Messages, OpenAI Chat Completions,
//!   OpenAI Responses, or a stream of any of them. The console reports the
//!   tools a response asks for, or an excerpt of its reply.

use pragmatic::json::Json;
use pragmatic::redact::binary;

use crate::text;

/// The default length of an excerpt, in characters.
pub const EXCERPT: usize = 56;

/// The length of an excerpt or gist inside a tool call's row. A title
/// holds two lines at most; the stylesheet ends a longer one at the width
/// the row has, so this is a ceiling, not the usual cut.
pub const GIST: usize = 64;

/// Recorded prose, collapsed, escaped and clipped to `limit` characters at
/// the last sentence end past 60% of the limit, else at the last word
/// boundary, with `…` when anything was cut.
pub fn excerpt(text: &str, limit: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let clean = text::sanitize(&collapsed);
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() <= limit {
        return clean;
    }
    let mut sentence = None;
    for i in 0..limit {
        if matches!(chars[i], '.' | '!' | '?') && chars.get(i + 1) == Some(&' ') {
            sentence = Some(i + 1);
        }
    }
    let cut = match sentence {
        Some(p) if p * 10 > limit * 6 => p,
        _ => chars[..=limit]
            .iter()
            .rposition(|&c| c == ' ')
            .filter(|&p| p > 0)
            .unwrap_or(limit),
    };
    let kept: String = chars[..cut].iter().collect();
    let kept = kept.trim_end_matches(|c: char| {
        c.is_whitespace() || matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | '-' | '\u{2013}')
    });
    format!("{kept}\u{2026}")
}

/// What a row shows of a slot's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gist {
    /// Data, set in mono.
    Data(String),
    /// Prose, set as a quoted excerpt.
    Quote(String),
    /// The slot's state in the console's words: `content erased`,
    /// `content withheld`, `empty`.
    State(&'static str),
}

/// A string member shown bare: `status delivered`.
fn bare(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= 24
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:@/+$#-".contains(c))
}

/// A scalar member's value, or `None` for a member a gist skips.
fn member(key: &str, v: &Json) -> Option<String> {
    let key = text::clip(key, 24);
    Some(match v {
        Json::Null => return None,
        Json::String(s) if bare(s) => format!("{key} {s}"),
        Json::String(s) => format!("{key} \"{}\"", clip_quoted(s)),
        Json::Array(items) => format!("{key} \u{d7}{}", items.len()),
        Json::Object(_) => format!("{key} {{\u{2026}}}"),
        other => format!("{key} {}", text::clip(&other.to_string(), 24)),
    })
}

/// A string member's text, clipped to 32 characters.
fn clip_quoted(s: &str) -> String {
    let c = text::clip(s, 32);
    match c.strip_suffix('\u{2026}') {
        Some(head) => format!("{}\u{2026}", head.trim_end()),
        None => c,
    }
}

fn scalar(v: &Json) -> String {
    match v {
        Json::String(s) if bare(s) => s.clone(),
        Json::String(s) => format!("\"{}\"", clip_quoted(s)),
        Json::Array(items) => format!("{} items", items.len()),
        Json::Object(_) => "{\u{2026}}".to_string(),
        other => text::clip(&other.to_string(), 24),
    }
}

/// Members joined with ", ", stopping before the one that would pass
/// `limit` characters and ending with ", …" when any were dropped.
fn join_members(parts: &[String], limit: usize) -> String {
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        let next = if out.is_empty() {
            p.chars().count()
        } else {
            out.chars().count() + 2 + p.chars().count()
        };
        if next > limit {
            if out.is_empty() {
                return text::clip(p, limit);
            }
            let _ = i;
            out.push_str(", \u{2026}");
            return out;
        }
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(p);
    }
    out
}

/// The gist of a JSON value, leaving out the members of an object whose
/// key and value both equal a member of `minus` (the unwrapped input of
/// the call it answers), unless that would leave nothing.
pub fn gist_json(v: &Json, minus: Option<&Json>, limit: usize) -> Gist {
    match v {
        Json::Object(members) => {
            let skip = |k: &str, val: &Json| {
                minus
                    .and_then(|m| m.get(k))
                    .is_some_and(|input| input == val)
            };
            let mut parts: Vec<String> = members
                .iter()
                .filter(|(k, val)| !skip(k, val))
                .filter_map(|(k, val)| member(k, val))
                .collect();
            if parts.is_empty() {
                parts = members.iter().filter_map(|(k, v)| member(k, v)).collect();
            }
            if parts.is_empty() {
                return Gist::State("empty");
            }
            Gist::Data(join_members(&parts, limit))
        }
        Json::Array(items) if items.is_empty() => Gist::State("empty"),
        Json::String(s) if s.trim().is_empty() => Gist::State("empty"),
        Json::String(s) if !bare(s) => Gist::Quote(excerpt(s, limit)),
        other => Gist::Data(scalar(other)),
    }
}

/// The SDKs' tool-call envelope of an argument, `{"id", "input"}`,
/// unwrapped to its input.
pub fn unwrap_argument(v: Json) -> Json {
    match &v {
        Json::Object(m)
            if m.len() == 2 && m.iter().any(|(k, _)| k == "id") && v.get("input").is_some() =>
        {
            v.get("input").cloned().unwrap_or(Json::Null)
        }
        _ => v,
    }
}

/// A tool result as the SDKs record it, `{"content", "is_error"}`.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolResult {
    /// The content, parsed as JSON when it is JSON, else a string.
    pub content: Json,
    /// The tool reported an error.
    pub is_error: bool,
}

/// The SDKs' result envelope, unwrapped, or `None` if `v` is not one.
pub fn unwrap_result(v: &Json) -> Option<ToolResult> {
    let Json::Object(m) = v else { return None };
    if m.len() != 2 {
        return None;
    }
    let content = v.get("content")?;
    let is_error = v.get("is_error")?.as_bool()?;
    let content = match content {
        Json::String(s) => Json::parse(s).unwrap_or_else(|_| Json::String(s.clone())),
        other => other.clone(),
    };
    Some(ToolResult { content, is_error })
}

/// The gist of present content: binary as its summary, JSON as a gist,
/// text as an excerpt.
pub fn gist_bytes(bytes: &[u8], minus: Option<&Json>, limit: usize) -> Gist {
    if bytes.is_empty() {
        return Gist::State("empty");
    }
    let scanned = binary::scan(bytes);
    let Some(textual) = scanned.text else {
        return Gist::Data(binary_summary(
            &scanned.binary[0].media_type,
            scanned.binary[0].bytes,
        ));
    };
    if scanned.binary.len() == 1 && scanned.binary[0].pointer.is_empty() {
        return Gist::Data(binary_summary(
            &scanned.binary[0].media_type,
            scanned.binary[0].bytes,
        ));
    }
    match Json::parse(&textual) {
        Ok(doc) => gist_json(&doc, minus, limit),
        Err(_) if textual.trim().is_empty() => Gist::State("empty"),
        Err(_) => Gist::Quote(excerpt(&textual, limit)),
    }
}

/// `image/png, 182 KB`.
pub fn binary_summary(media_type: &str, bytes: u64) -> String {
    let size = if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes.div_ceil(1024))
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    };
    format!("{}, {size}", text::clip(media_type, 48))
}

/// What a model's response says, as far as the console can tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// The response is in a shape the console recognises.
    pub recognised: bool,
    /// The tools it asks for, in order.
    pub tools: Vec<String>,
    /// The reply's text (the last text part).
    pub text: Option<String>,
    /// The response stopped at the token limit.
    pub cut: bool,
    /// The body was a stream.
    pub streamed: bool,
}

fn str_at<'a>(v: &'a Json, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str()
}

/// Recognise a response body (see the module documentation).
pub fn reply(body: &str) -> Reply {
    let trimmed = body.trim_start();
    if trimmed.starts_with("event:") || trimmed.starts_with("data:") {
        return stream_reply(body);
    }
    let Ok(doc) = Json::parse(body) else {
        return Reply::default();
    };
    let mut out = Reply::default();
    let obj = doc.get("object").and_then(Json::as_str);
    // Anthropic Messages: a message, or (as some recordings keep it) its
    // content blocks without the envelope.
    let blocks = doc
        .get("content")
        .and_then(Json::as_array)
        .is_some_and(|c| {
            c.iter().any(|b| {
                matches!(
                    b.get("type").and_then(Json::as_str),
                    Some("text" | "tool_use")
                )
            })
        });
    if doc.get("type").and_then(Json::as_str) == Some("message") || (obj.is_none() && blocks) {
        let Some(content) = doc.get("content").and_then(Json::as_array) else {
            return out;
        };
        out.recognised = true;
        for item in content {
            match item.get("type").and_then(Json::as_str) {
                Some("tool_use") => {
                    if let Some(n) = str_at(item, &["name"]) {
                        out.tools.push(n.to_string());
                    }
                }
                Some("text") => out.text = str_at(item, &["text"]).map(str::to_string),
                _ => {}
            }
        }
        out.cut = str_at(&doc, &["stop_reason"]) == Some("max_tokens");
    } else if obj == Some("chat.completion") {
        out.recognised = true;
        let choice = doc
            .get("choices")
            .and_then(Json::as_array)
            .and_then(|c| c.first());
        if let Some(choice) = choice {
            let message = choice.get("message");
            if let Some(calls) = message
                .and_then(|m| m.get("tool_calls"))
                .and_then(Json::as_array)
            {
                for c in calls {
                    if let Some(n) = str_at(c, &["function", "name"]) {
                        out.tools.push(n.to_string());
                    }
                }
            }
            out.text = match message.and_then(|m| m.get("content")) {
                Some(Json::String(s)) => Some(s.clone()),
                Some(Json::Array(parts)) => {
                    let t: Vec<&str> = parts.iter().filter_map(|p| str_at(p, &["text"])).collect();
                    (!t.is_empty()).then(|| t.join(""))
                }
                _ => None,
            };
            out.cut = str_at(choice, &["finish_reason"]) == Some("length");
        }
    } else if obj == Some("response") {
        out.recognised = true;
        for item in doc.get("output").and_then(Json::as_array).unwrap_or(&[]) {
            match item.get("type").and_then(Json::as_str) {
                Some("function_call") => {
                    if let Some(n) = str_at(item, &["name"]) {
                        out.tools.push(n.to_string());
                    }
                }
                Some("message") => {
                    let t: Vec<&str> = item
                        .get("content")
                        .and_then(Json::as_array)
                        .unwrap_or(&[])
                        .iter()
                        .filter(|p| p.get("type").and_then(Json::as_str) == Some("output_text"))
                        .filter_map(|p| str_at(p, &["text"]))
                        .collect();
                    if !t.is_empty() {
                        out.text = Some(t.join(""));
                    }
                }
                _ => {}
            }
        }
        out.cut = str_at(&doc, &["status"]) == Some("incomplete");
    }
    out
}

/// A streamed body: its `data:` lines, read as JSON.
fn stream_reply(body: &str) -> Reply {
    let mut out = Reply {
        streamed: true,
        ..Reply::default()
    };
    let mut text = String::new();
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let Ok(ev) = Json::parse(data.trim()) else {
            continue;
        };
        out.recognised = true;
        match ev.get("type").and_then(Json::as_str) {
            Some("content_block_start") => {
                if str_at(&ev, &["content_block", "type"]) == Some("tool_use") {
                    if let Some(n) = str_at(&ev, &["content_block", "name"]) {
                        out.tools.push(n.to_string());
                    }
                }
            }
            Some("content_block_delta") => {
                if let Some(t) = str_at(&ev, &["delta", "text"]) {
                    if text.len() < 400 {
                        text.push_str(t);
                    }
                }
            }
            Some("message_delta") => {
                if str_at(&ev, &["delta", "stop_reason"]) == Some("max_tokens") {
                    out.cut = true;
                }
            }
            Some("response.output_text.delta") => {
                if let Some(t) = str_at(&ev, &["delta"]) {
                    if text.len() < 400 {
                        text.push_str(t);
                    }
                }
            }
            Some("response.output_item.added") => {
                if str_at(&ev, &["item", "type"]) == Some("function_call") {
                    if let Some(n) = str_at(&ev, &["item", "name"]) {
                        out.tools.push(n.to_string());
                    }
                }
            }
            _ => {
                let choice = ev
                    .get("choices")
                    .and_then(Json::as_array)
                    .and_then(|c| c.first());
                if let Some(choice) = choice {
                    if let Some(t) = str_at(choice, &["delta", "content"]) {
                        if text.len() < 400 {
                            text.push_str(t);
                        }
                    }
                    for c in choice
                        .get("delta")
                        .and_then(|d| d.get("tool_calls"))
                        .and_then(Json::as_array)
                        .unwrap_or(&[])
                    {
                        if let Some(n) = str_at(c, &["function", "name"]) {
                            out.tools.push(n.to_string());
                        }
                    }
                    if str_at(choice, &["finish_reason"]) == Some("length") {
                        out.cut = true;
                    }
                }
            }
        }
    }
    if !text.is_empty() {
        out.text = Some(text);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpts_cut_at_a_sentence_or_a_word() {
        assert_eq!(
            excerpt(
                "Hi Sam, you were charged twice for order 20417. I've refunded the duplicate \
                 $129.00; it should reach your card in 3 to 5 business days.",
                EXCERPT
            ),
            "Hi Sam, you were charged twice for order 20417\u{2026}"
        );
        assert_eq!(excerpt("short\n\n  reply", 56), "short reply");
        assert_eq!(
            excerpt("one two three four five six seven", 20),
            "one two three four\u{2026}"
        );
        // A sentence end too early in the window is not used.
        assert_eq!(
            excerpt("Ok. then a much longer clause follows here", 30),
            "Ok. then a much longer clause\u{2026}"
        );
        assert_eq!(excerpt("a\u{1b}[2Jb", 56), "a\\u{1b}[2Jb");
        assert_eq!(
            excerpt(&"x".repeat(80), 10),
            format!("{}\u{2026}", "x".repeat(10))
        );
    }

    #[test]
    fn gists_unwrap_envelopes_and_skip_the_input() {
        let input = unwrap_argument(
            Json::parse(r#"{"id":"toolu_01","input":{"order_id":"20417"}}"#).unwrap(),
        );
        let result = unwrap_result(
            &Json::parse(
                r#"{"content":"{\"charges\":[{\"amount\":\"129.00\",\"id\":\"ch_8811\"},{\"amount\":\"129.00\",\"id\":\"ch_8812\"}],\"order_id\":\"20417\",\"status\":\"delivered\"}","is_error":false}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!result.is_error);
        assert_eq!(
            gist_json(&result.content, Some(&input), GIST),
            Gist::Data("charges \u{d7}2, status delivered".into())
        );
        let input = unwrap_argument(
            Json::parse(r#"{"id":"toolu_02","input":{"amount":"129.00","charge_id":"ch_8812","order_id":"20417"}}"#)
                .unwrap(),
        );
        let result = Json::parse(r#"{"amount":"129.00","charge_id":"ch_8812","refund_id":"re_3f9c","status":"succeeded"}"#).unwrap();
        assert_eq!(
            gist_json(&result, Some(&input), GIST),
            Gist::Data("refund_id re_3f9c, status succeeded".into())
        );
        // Nothing left after skipping: the gist is made without skipping.
        assert_eq!(
            gist_json(&input, Some(&input), GIST),
            Gist::Data("amount 129.00, charge_id ch_8812, order_id 20417".into())
        );
    }

    #[test]
    fn gists_of_every_shape() {
        let g = |s: &str| gist_bytes(s.as_bytes(), None, GIST);
        assert_eq!(
            g(r#"{"note":"duplicate charge on the card","n":3,"ok":true,"x":null}"#),
            Gist::Data("note \"duplicate charge on the card\", n 3, ok true".into())
        );
        assert_eq!(
            g(r#"{"a":{"b":1},"c":[1,2,3]}"#),
            Gist::Data("a {\u{2026}}, c \u{d7}3".into())
        );
        assert_eq!(g("[1,2]"), Gist::Data("2 items".into()));
        assert_eq!(g("42"), Gist::Data("42".into()));
        assert_eq!(
            g("plain words that are not json"),
            Gist::Quote("plain words that are not json".into())
        );
        assert_eq!(g(""), Gist::State("empty"));
        assert_eq!(g("{}"), Gist::State("empty"));
        assert_eq!(
            gist_bytes(&[0xff, 0xfe, 0, 1], None, GIST),
            Gist::Data("application/octet-stream, 4 bytes".into())
        );
        assert_eq!(binary_summary("image/png", 182_004), "image/png, 178 KB");
    }

    #[test]
    fn responses_are_recognised_by_shape() {
        let a = reply(
            r#"{"type":"message","content":[{"type":"text","text":"Checking."},{"type":"tool_use","name":"lookup_order","input":{}}],"stop_reason":"tool_use"}"#,
        );
        assert!(a.recognised);
        assert_eq!(a.tools, ["lookup_order"]);
        let a = reply(
            r#"{"type":"message","content":[{"type":"text","text":"Hi"}],"stop_reason":"max_tokens"}"#,
        );
        assert_eq!(a.text.as_deref(), Some("Hi"));
        assert!(a.cut);
        let o = reply(
            r#"{"object":"chat.completion","choices":[{"message":{"content":"Hello","tool_calls":[{"function":{"name":"f"}}]},"finish_reason":"length"}]}"#,
        );
        assert_eq!(o.tools, ["f"]);
        assert_eq!(o.text.as_deref(), Some("Hello"));
        assert!(o.cut);
        let r = reply(
            r#"{"object":"response","status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"Yo"}]},{"type":"function_call","name":"g"}]}"#,
        );
        assert_eq!(
            (r.tools.clone(), r.text.as_deref(), r.cut),
            (vec!["g".to_string()], Some("Yo"), true)
        );
        let s = reply("event: message_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"h\"}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hel\"}}\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"lo\"}}\n");
        assert!(s.streamed && s.recognised);
        assert_eq!(s.tools, ["h"]);
        assert_eq!(s.text.as_deref(), Some("Hello"));
        let c = reply("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\",\"tool_calls\":[{\"function\":{\"name\":\"t\"}}]}}]}\n");
        assert_eq!(
            (c.tools.clone(), c.text.as_deref()),
            (vec!["t".to_string()], Some("Hi"))
        );
        assert!(!reply("not a response").recognised);
        assert!(!reply(r#"{"type":"other"}"#).recognised);
    }
}
