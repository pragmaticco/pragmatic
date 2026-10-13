//! Any OpenAI-compatible Chat Completions server as a journaled **Oracle** -
//! OpenAI itself, or the same API spoken by Ollama, vLLM, llama.cpp, Groq,
//! and most other inference servers.
//!
//! ```no_run
//! use pragmatic::Runtime;
//! use pragmatic_openai::OpenAiOracle;
//!
//! // OpenAI (reads OPENAI_API_KEY):
//! let oracle = OpenAiOracle::from_env()
//!     .expect("set OPENAI_API_KEY")
//!     .model("gpt-5");
//!
//! // ...or a local model - no key needed:
//! let local = OpenAiOracle::new("")
//!     .base_url("http://localhost:11434/v1")
//!     .model("llama3.3");
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

use pragmatic::{Fault, Oracle, Value};
use serde_json::{json, Value as Json};

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-5";

/// An [`Oracle`] backed by an OpenAI-compatible Chat Completions API. Each
/// `call` sends the prompt as a single user message and returns the model's
/// text completion.
pub struct OpenAiOracle {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: Option<u32>,
    temperature: Option<f64>,
    system: Option<String>,
    timeout: std::time::Duration,
}

impl OpenAiOracle {
    /// Build with an explicit API key (empty string for servers that don't
    /// check one, e.g. a local Ollama).
    pub fn new(api_key: impl Into<String>) -> Self {
        OpenAiOracle {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            max_tokens: None,
            temperature: None,
            system: None,
            timeout: std::time::Duration::from_secs(120),
        }
    }

    /// Build from the `OPENAI_API_KEY` environment variable;
    /// `OPENAI_BASE_URL`, when set, overrides the endpoint.
    pub fn from_env() -> Result<Self, Fault> {
        let key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| Fault::OracleErr("OPENAI_API_KEY is not set".to_string()))?;
        let mut oracle = Self::new(key);
        if let Ok(url) = std::env::var("OPENAI_BASE_URL") {
            oracle = oracle.base_url(url);
        }
        Ok(oracle)
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Cap the completion length (sent as `max_tokens`, the field every
    /// compatible server understands). Omitted unless set.
    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn temperature(mut self, t: f64) -> Self {
        self.temperature = Some(t);
        self
    }

    /// A system message prepended to every call.
    pub fn system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Point at any compatible server: `http://localhost:11434/v1` (Ollama),
    /// a vLLM deployment, a gateway, a mock in tests. The path is the API
    /// root - `/chat/completions` is appended.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        let mut url = url.into();
        while url.ends_with('/') {
            url.pop();
        }
        self.base_url = url;
        self
    }

    pub fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout = d;
        self
    }

    /// The request body for `prompt` (exposed for tests and debugging).
    pub fn build_request(&self, prompt: &Value) -> Json {
        let mut messages = Vec::new();
        if let Some(s) = &self.system {
            messages.push(json!({ "role": "system", "content": s }));
        }
        messages.push(json!({ "role": "user", "content": prompt.as_str() }));
        let mut body = json!({
            "model": self.model,
            "messages": messages,
        });
        if let Some(m) = self.max_tokens {
            body["max_tokens"] = json!(m);
        }
        if let Some(t) = self.temperature {
            body["temperature"] = json!(t);
        }
        body
    }

    /// Pull the completion text out of a Chat Completions response.
    pub fn extract_text(response: &Json) -> Result<String, Fault> {
        let choice = response["choices"]
            .as_array()
            .and_then(|c| c.first())
            .ok_or_else(|| Fault::OracleErr("response has no choices".to_string()))?;
        let text = choice["message"]["content"].as_str().unwrap_or_default();
        if text.is_empty() {
            return Err(Fault::OracleErr(format!(
                "response contained no completion text (finish_reason: {})",
                choice["finish_reason"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(text.to_string())
    }
}

impl Oracle for OpenAiOracle {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        let body = self.build_request(prompt);
        let url = format!("{}/chat/completions", self.base_url);
        let mut request = ureq::post(&url)
            .set("content-type", "application/json")
            .timeout(self.timeout);
        if !self.api_key.is_empty() {
            request = request.set("authorization", &format!("Bearer {}", self.api_key));
        }
        let response = request.send_string(&body.to_string());

        let response = match response {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let detail = r.into_string().unwrap_or_default();
                let snippet: String = detail.chars().take(300).collect();
                return Err(Fault::OracleErr(format!(
                    "openai-compatible api returned {code}: {snippet}"
                )));
            }
            Err(e) => return Err(Fault::OracleErr(format!("transport error: {e}"))),
        };

        let json: Json = response
            .into_string()
            .map_err(|e| Fault::OracleErr(format!("failed reading response body: {e}")))?
            .parse::<Json>()
            .map_err(|e| Fault::OracleErr(format!("response is not valid JSON: {e}")))?;

        Ok(Value::from(Self::extract_text(&json)?))
    }

    fn provenance(&self) -> String {
        match self.temperature {
            Some(t) => format!("openai:{}@temperature={t}", self.model),
            None => format!("openai:{}", self.model),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_shape() {
        let oracle = OpenAiOracle::new("test-key")
            .model("gpt-5")
            .max_tokens(512)
            .temperature(0.7)
            .system("be terse");
        let body = oracle.build_request(&Value::from("hello"));
        assert_eq!(body["model"], "gpt-5");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "be terse");
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["messages"][1]["content"], "hello");
    }

    #[test]
    fn optional_fields_omitted_by_default() {
        let oracle = OpenAiOracle::new("k");
        let body = oracle.build_request(&Value::from("p"));
        assert!(body.get("max_tokens").is_none());
        assert!(body.get("temperature").is_none());
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn extracts_completion_text() {
        let response = serde_json::json!({
            "choices": [{
                "message": { "role": "assistant", "content": "Hello world" },
                "finish_reason": "stop"
            }]
        });
        assert_eq!(
            OpenAiOracle::extract_text(&response).unwrap(),
            "Hello world"
        );
    }

    #[test]
    fn empty_content_is_an_oracle_error() {
        let response = serde_json::json!({
            "choices": [{
                "message": { "role": "assistant", "content": "" },
                "finish_reason": "length"
            }]
        });
        assert!(matches!(
            OpenAiOracle::extract_text(&response),
            Err(Fault::OracleErr(_))
        ));
    }

    #[test]
    fn no_choices_is_an_oracle_error() {
        let response = serde_json::json!({ "choices": [] });
        assert!(matches!(
            OpenAiOracle::extract_text(&response),
            Err(Fault::OracleErr(_))
        ));
    }

    #[test]
    fn base_url_trailing_slash_is_normalized() {
        let oracle = OpenAiOracle::new("k").base_url("http://localhost:11434/v1/");
        assert_eq!(oracle.base_url, "http://localhost:11434/v1");
    }

    #[test]
    fn provenance_names_the_model() {
        let oracle = OpenAiOracle::new("k").model("llama3.3").temperature(0.0);
        assert_eq!(oracle.provenance(), "openai:llama3.3@temperature=0");
    }
}
