//! Claude as a journaled **Oracle** - the Anthropic Messages API adapter for
//! the Pragmatic durable-execution runtime.
//!
//! ```no_run
//! use pragmatic::Runtime;
//! use pragmatic_anthropic::AnthropicOracle;
//!
//! let oracle = AnthropicOracle::from_env()          // reads ANTHROPIC_API_KEY
//!     .expect("set ANTHROPIC_API_KEY")
//!     .model("claude-sonnet-5")
//!     .max_tokens(1024)
//!     .system("You are a terse research assistant.");
//!
//! let rt = Runtime::on_dir("./journals", oracle).unwrap();
//! let report = rt.run("research-42", |ctx| {
//!     let plan = ctx.oracle("Plan a survey of durable execution.")?;
//!     ctx.oracle(format!("Execute step one of: {plan}"))
//! }).unwrap();
//! ```
//!
//! Every completion is journaled by the runtime; crashes resume without
//! re-calling (or re-paying for) the model, and audits replay with the model
//! never consulted.
//!
//! # Tool use
//!
//! Real agents are multi-turn tool loops, and the whole loop journals. A
//! plain-text prompt behaves as above; a [`Conversation`] prompt sends the
//! full message history with the oracle's declared tools, and the journaled
//! outcome is a [`Turn`] carrying the assistant's content blocks -
//! `tool_use` included - plus the stop reason and token usage. Tools
//! execute as `ctx.effect(...)`, under the same write-ahead journaling as
//! any other side effect:
//!
//! ```no_run
//! use pragmatic::{Ctx, Fault, Value};
//! use pragmatic_anthropic::{AnthropicOracle, Conversation, Turn};
//! use serde_json::json;
//!
//! let oracle = AnthropicOracle::from_env().unwrap().tools(json!([{
//!     "name": "search",
//!     "description": "Search the corpus",
//!     "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}
//! }]));
//!
//! let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
//!     let mut convo = Conversation::user("Find papers on durable execution.");
//!     loop {
//!         let turn = Turn::parse(&ctx.oracle(convo.prompt())?)?;   // journaled
//!         convo.push_assistant(&turn);
//!         if !turn.wants_tools() {
//!             return Ok(Value::from(turn.text()));
//!         }
//!         for call in turn.tool_uses() {
//!             let result = ctx.effect("search", call.input.to_string(), |q| {
//!                 Ok(Value::from(format!("3 hits for {q}")))       // journaled
//!             })?;
//!             convo.push_tool_result(&call.id, result.as_str());
//!         }
//!     }
//! };
//! ```
//!
//! On resume after a crash, every prior model turn *and* every prior tool
//! result replays from the journal - the loop re-executes, the world does
//! not.

use pragmatic::{Fault, Oracle, Value};
use serde_json::{json, Value as Json};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const DEFAULT_MODEL: &str = "claude-sonnet-5";
const DEFAULT_MAX_TOKENS: u32 = 1024;
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// An [`Oracle`] backed by the Anthropic Messages API. Each `call` sends the
/// prompt as a single user message and returns the model's text completion.
pub struct AnthropicOracle {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: Option<f64>,
    system: Option<String>,
    tools: Option<Json>,
    timeout: std::time::Duration,
}

impl AnthropicOracle {
    /// Build with an explicit API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        AnthropicOracle {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            max_tokens: DEFAULT_MAX_TOKENS,
            temperature: None,
            system: None,
            tools: None,
            timeout: std::time::Duration::from_secs(120),
        }
    }

    /// Build from the `ANTHROPIC_API_KEY` environment variable.
    pub fn from_env() -> Result<Self, Fault> {
        let key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| Fault::OracleErr("ANTHROPIC_API_KEY is not set".to_string()))?;
        Ok(Self::new(key))
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    pub fn temperature(mut self, t: f64) -> Self {
        self.temperature = Some(t);
        self
    }

    pub fn system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Declare tools (a Messages-API `tools` array) sent with every
    /// [`Conversation`] prompt. Plain-text prompts never send tools.
    pub fn tools(mut self, tools: Json) -> Self {
        self.tools = Some(tools);
        self
    }

    /// Override the API endpoint (proxies, gateways, mock servers in tests).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    pub fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout = d;
        self
    }

    /// The request body for `prompt` (exposed for tests and debugging).
    ///
    /// A plain-text prompt becomes a single user message. A structured
    /// prompt - a JSON object with a `"messages"` array, as produced by
    /// [`Conversation::prompt`] - is sent as the full conversation, with
    /// the oracle's declared tools attached.
    pub fn build_request(&self, prompt: &Value) -> Json {
        let messages = match Self::parse_structured(prompt) {
            Some(convo) => convo["messages"].clone(),
            None => json!([{ "role": "user", "content": prompt.as_str() }]),
        };
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        });
        if let Some(t) = self.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(s) = &self.system {
            body["system"] = json!(s);
        }
        if Self::parse_structured(prompt).is_some() {
            if let Some(tools) = &self.tools {
                body["tools"] = tools.clone();
            }
        }
        body
    }

    /// A prompt is structured when it parses as a JSON object carrying a
    /// `"messages"` array. Anything else is a plain-text prompt.
    fn parse_structured(prompt: &Value) -> Option<Json> {
        let json: Json = serde_json::from_slice(prompt.as_bytes()).ok()?;
        json.get("messages")?.as_array()?;
        Some(json)
    }

    /// Pull the concatenated text blocks out of a Messages API response.
    pub fn extract_text(response: &Json) -> Result<String, Fault> {
        let blocks = response["content"]
            .as_array()
            .ok_or_else(|| Fault::OracleErr("response has no content array".to_string()))?;
        let text: String = blocks
            .iter()
            .filter(|b| b["type"] == "text")
            .filter_map(|b| b["text"].as_str())
            .collect();
        if text.is_empty() {
            return Err(Fault::OracleErr(format!(
                "response contained no text blocks (stop_reason: {})",
                response["stop_reason"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(text)
    }
}

impl Oracle for AnthropicOracle {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        let body = self.build_request(prompt);
        let url = format!("{}/v1/messages", self.base_url);
        let response = ureq::post(&url)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .timeout(self.timeout)
            .send_string(&body.to_string());

        let response = match response {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let detail = r.into_string().unwrap_or_default();
                let snippet: String = detail.chars().take(300).collect();
                return Err(Fault::OracleErr(format!(
                    "anthropic api returned {code}: {snippet}"
                )));
            }
            Err(e) => return Err(Fault::OracleErr(format!("transport error: {e}"))),
        };

        let json: Json = response
            .into_string()
            .map_err(|e| Fault::OracleErr(format!("failed reading response body: {e}")))?
            .parse::<Json>()
            .map_err(|e| Fault::OracleErr(format!("response is not valid JSON: {e}")))?;

        // Structured prompts journal the whole assistant turn - content
        // blocks (tool_use intact), stop reason, and token usage - so the
        // journal is a complete audit record of the conversation. Plain
        // prompts keep the text-in/text-out contract.
        if Self::parse_structured(prompt).is_some() {
            Ok(Turn::from_response(&json)?.to_value())
        } else {
            Ok(Value::from(Self::extract_text(&json)?))
        }
    }

    fn provenance(&self) -> String {
        match self.temperature {
            Some(t) => format!("anthropic:{}@temperature={t}", self.model),
            None => format!("anthropic:{}", self.model),
        }
    }
}

/// The message history of a tool-use loop, sent whole on every draw.
///
/// The conversation is rebuilt from journaled values on every attempt -
/// prior [`Turn`]s and tool results all replay from the journal - so the
/// serialized prompt is byte-identical across record, resume, and replay.
#[derive(Clone, Debug, Default)]
pub struct Conversation {
    messages: Vec<Json>,
}

impl Conversation {
    /// Start a conversation with one user message.
    pub fn user(text: impl Into<String>) -> Self {
        let mut c = Conversation::default();
        c.push_user(text);
        c
    }

    pub fn push_user(&mut self, text: impl Into<String>) {
        self.messages
            .push(json!({ "role": "user", "content": text.into() }));
    }

    /// Append the assistant's turn exactly as journaled - `tool_use` blocks
    /// and all, as the Messages API requires for the follow-up request.
    pub fn push_assistant(&mut self, turn: &Turn) {
        self.messages
            .push(json!({ "role": "assistant", "content": turn.content }));
    }

    /// Append one tool's result. Consecutive results coalesce into a single
    /// user message of `tool_result` blocks, per the Messages API shape.
    pub fn push_tool_result(&mut self, tool_use_id: &str, result: impl AsRef<str>) {
        let block = json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": result.as_ref(),
        });
        if let Some(last) = self.messages.last_mut() {
            let is_result_msg = last["role"] == "user"
                && last["content"]
                    .as_array()
                    .is_some_and(|a| a.iter().all(|b| b["type"] == "tool_result"));
            if is_result_msg {
                last["content"].as_array_mut().expect("checked").push(block);
                return;
            }
        }
        self.messages
            .push(json!({ "role": "user", "content": [block] }));
    }

    /// The structured prompt for `ctx.oracle(...)`. Serialization is
    /// deterministic (sorted keys), so identical histories yield identical
    /// prompt bytes - the property journal verification depends on.
    pub fn prompt(&self) -> Value {
        Value::from(json!({ "messages": self.messages }).to_string())
    }
}

/// One tool invocation requested by the model.
#[derive(Clone, Debug)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: Json,
}

/// One assistant turn, as journaled: the full content-block array, the stop
/// reason, and token usage. This is the outcome an audit replays.
#[derive(Clone, Debug)]
pub struct Turn {
    pub content: Json,
    pub stop_reason: String,
    pub usage: Json,
}

impl Turn {
    /// Build from a live Messages API response body.
    fn from_response(response: &Json) -> Result<Turn, Fault> {
        let content = response
            .get("content")
            .filter(|c| c.is_array())
            .cloned()
            .ok_or_else(|| Fault::OracleErr("response has no content array".to_string()))?;
        let stop_reason = response["stop_reason"].as_str().unwrap_or("unknown").into();
        let usage = response.get("usage").cloned().unwrap_or(Json::Null);
        Ok(Turn {
            content,
            stop_reason,
            usage,
        })
    }

    /// Parse a journaled oracle outcome back into a turn - used identically
    /// while recording and while replaying.
    pub fn parse(outcome: &Value) -> Result<Turn, Fault> {
        let json: Json = serde_json::from_slice(outcome.as_bytes())
            .map_err(|e| Fault::OracleErr(format!("journaled turn is not valid JSON: {e}")))?;
        Self::from_response(&json)
    }

    /// The journal representation of this turn.
    pub fn to_value(&self) -> Value {
        Value::from(
            json!({
                "content": self.content,
                "stop_reason": self.stop_reason,
                "usage": self.usage,
            })
            .to_string(),
        )
    }

    /// The concatenated text blocks (empty when the turn is tools-only).
    pub fn text(&self) -> String {
        self.content
            .as_array()
            .into_iter()
            .flatten()
            .filter(|b| b["type"] == "text")
            .filter_map(|b| b["text"].as_str())
            .collect()
    }

    /// True when the model stopped to call tools.
    pub fn wants_tools(&self) -> bool {
        self.stop_reason == "tool_use"
    }

    /// Every `tool_use` block in this turn, in order.
    pub fn tool_uses(&self) -> Vec<ToolUse> {
        self.content
            .as_array()
            .into_iter()
            .flatten()
            .filter(|b| b["type"] == "tool_use")
            .map(|b| ToolUse {
                id: b["id"].as_str().unwrap_or_default().to_string(),
                name: b["name"].as_str().unwrap_or_default().to_string(),
                input: b["input"].clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_shape() {
        let oracle = AnthropicOracle::new("test-key")
            .model("claude-sonnet-5")
            .max_tokens(512)
            .temperature(0.7)
            .system("be terse");
        let body = oracle.build_request(&Value::from("hello"));
        assert_eq!(body["model"], "claude-sonnet-5");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["system"], "be terse");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "hello");
    }

    #[test]
    fn optional_fields_omitted_by_default() {
        let oracle = AnthropicOracle::new("k");
        let body = oracle.build_request(&Value::from("p"));
        assert!(body.get("temperature").is_none());
        assert!(body.get("system").is_none());
    }

    #[test]
    fn extracts_and_concatenates_text_blocks() {
        let response = json!({
            "content": [
                { "type": "text", "text": "Hello " },
                { "type": "tool_use", "id": "x", "name": "t", "input": {} },
                { "type": "text", "text": "world" }
            ],
            "stop_reason": "end_turn"
        });
        assert_eq!(
            AnthropicOracle::extract_text(&response).unwrap(),
            "Hello world"
        );
    }

    #[test]
    fn empty_content_is_an_oracle_error() {
        let response = json!({ "content": [], "stop_reason": "max_tokens" });
        assert!(matches!(
            AnthropicOracle::extract_text(&response),
            Err(Fault::OracleErr(_))
        ));
    }

    #[test]
    fn structured_prompt_sends_full_conversation_and_tools() {
        let oracle = AnthropicOracle::new("k").tools(json!([{ "name": "search" }]));
        let mut convo = Conversation::user("find papers");
        let turn = Turn {
            content: json!([{ "type": "tool_use", "id": "tu_1", "name": "search",
                              "input": { "q": "durable execution" } }]),
            stop_reason: "tool_use".into(),
            usage: Json::Null,
        };
        convo.push_assistant(&turn);
        convo.push_tool_result("tu_1", "3 hits");

        let body = oracle.build_request(&convo.prompt());
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[1]["content"][0]["type"], "tool_use");
        assert_eq!(messages[2]["content"][0]["type"], "tool_result");
        assert_eq!(messages[2]["content"][0]["tool_use_id"], "tu_1");
        assert_eq!(body["tools"][0]["name"], "search");
    }

    #[test]
    fn plain_prompts_never_send_tools() {
        let oracle = AnthropicOracle::new("k").tools(json!([{ "name": "search" }]));
        let body = oracle.build_request(&Value::from("just text"));
        assert!(body.get("tools").is_none());
        assert_eq!(body["messages"][0]["content"], "just text");
    }

    #[test]
    fn consecutive_tool_results_coalesce_into_one_user_message() {
        let mut convo = Conversation::user("go");
        let turn = Turn {
            content: json!([
                { "type": "tool_use", "id": "a", "name": "t", "input": {} },
                { "type": "tool_use", "id": "b", "name": "t", "input": {} }
            ]),
            stop_reason: "tool_use".into(),
            usage: Json::Null,
        };
        convo.push_assistant(&turn);
        convo.push_tool_result("a", "ra");
        convo.push_tool_result("b", "rb");

        let body: Json = serde_json::from_slice(convo.prompt().as_bytes()).unwrap();
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3, "both results share one user message");
        assert_eq!(messages[2]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn turn_roundtrips_through_the_journal_representation() {
        let turn = Turn {
            content: json!([
                { "type": "text", "text": "using tools " },
                { "type": "tool_use", "id": "tu_9", "name": "calc",
                  "input": { "expr": "2+2" } }
            ]),
            stop_reason: "tool_use".into(),
            usage: json!({ "input_tokens": 12, "output_tokens": 34 }),
        };
        let back = Turn::parse(&turn.to_value()).unwrap();
        assert_eq!(back.content, turn.content);
        assert_eq!(back.stop_reason, "tool_use");
        assert!(back.wants_tools());
        assert_eq!(back.text(), "using tools ");
        let calls = back.tool_uses();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "tu_9");
        assert_eq!(calls[0].name, "calc");
        assert_eq!(calls[0].input["expr"], "2+2");
    }

    #[test]
    fn conversation_prompt_bytes_are_deterministic() {
        let build = || {
            let mut c = Conversation::user("q");
            c.push_tool_result("id", "r");
            c.prompt()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn provenance_names_the_model() {
        let oracle = AnthropicOracle::new("k")
            .model("claude-opus-4-8")
            .temperature(0.0);
        assert_eq!(
            oracle.provenance(),
            "anthropic:claude-opus-4-8@temperature=0"
        );
    }
}
