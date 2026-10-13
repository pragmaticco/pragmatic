//! Webhooks (design 4.12): signed JSON POSTs for events an operator must
//! hear about.
//!
//! A webhook body carries the event type, the run id and counts, never
//! content or field data (design 1.4). Each body is signed with the
//! endpoint's secret, `Pragmatic-Signature: sha256=<hex HMAC-SHA-256(secret,
//! body)>`, so a receiver can tell the server's events from anyone else's.
//!
//! Delivery is retried with exponential backoff (1 s doubling to at most an
//! hour) for up to 24 hours. Pending deliveries live in memory: a restart
//! drops them, which is why erasures and shreds are also written to the
//! erasure ledger on disk, the durable record to stream off the host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pragmatic::encoding::hex_encode;
use pragmatic::sha256::hmac_sha256;
use serde_json::{Map, Value as JsonValue};
use tokio::sync::mpsc;

use crate::config::WebhookConfig;
use crate::timefmt;

/// How long a delivery is retried.
pub const RETRY_FOR: Duration = Duration::from_secs(24 * 3600);
/// The first retry delay; it doubles after every failure.
const FIRST_DELAY: Duration = Duration::from_secs(1);
/// The longest delay between two attempts.
const MAX_DELAY: Duration = Duration::from_secs(3600);

/// One event to deliver.
#[derive(Debug, Clone, PartialEq)]
pub struct WebhookEvent {
    /// One of [`crate::config::WEBHOOK_EVENTS`].
    pub event: &'static str,
    pub run_id: Option<String>,
    /// Counts and other non-content numbers.
    pub detail: Map<String, JsonValue>,
}

impl WebhookEvent {
    pub fn new(event: &'static str, run_id: Option<&str>, detail: JsonValue) -> WebhookEvent {
        WebhookEvent {
            event,
            run_id: run_id.map(str::to_string),
            detail: match detail {
                JsonValue::Object(m) => m,
                _ => Map::new(),
            },
        }
    }

    /// The JSON body: `event`, `at`, `run_id` and the detail fields.
    pub fn body(&self) -> Vec<u8> {
        let mut m = self.detail.clone();
        m.insert("event".into(), self.event.into());
        m.insert("at".into(), timefmt::now_rfc3339().into());
        m.insert(
            "run_id".into(),
            self.run_id.clone().map_or(JsonValue::Null, JsonValue::from),
        );
        JsonValue::Object(m).to_string().into_bytes()
    }
}

/// The `Pragmatic-Signature` header value for `body`.
pub fn signature(secret: &[u8], body: &[u8]) -> String {
    format!("sha256={}", hex_encode(&hmac_sha256(secret, body)))
}

#[derive(Debug)]
struct Endpoint {
    url: String,
    secret: Vec<u8>,
    events: Vec<String>,
}

/// A handle that queues events for delivery.
#[derive(Clone, Debug, Default)]
pub struct Webhooks {
    tx: Option<mpsc::UnboundedSender<WebhookEvent>>,
}

impl Webhooks {
    /// No endpoints: every event is dropped.
    pub fn disabled() -> Webhooks {
        Webhooks { tx: None }
    }

    /// Read every endpoint's secret and start the dispatcher on the
    /// current tokio runtime.
    pub fn start(configs: &[WebhookConfig]) -> Result<Webhooks, String> {
        if configs.is_empty() {
            return Ok(Webhooks::disabled());
        }
        let mut endpoints = Vec::new();
        for c in configs {
            let secret = std::fs::read(&c.secret_file)
                .map_err(|e| format!("webhook secret {}: {e}", c.secret_file.display()))?;
            let secret = trim_ascii(&secret).to_vec();
            if secret.is_empty() {
                return Err(format!(
                    "webhook secret {} is empty",
                    c.secret_file.display()
                ));
            }
            endpoints.push(Endpoint {
                url: c.url.clone(),
                secret,
                events: c.events.clone(),
            });
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("webhook client: {e}"))?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(dispatch(rx, Arc::new(endpoints), client));
        Ok(Webhooks { tx: Some(tx) })
    }

    /// Queue an event. Never blocks and never fails the caller.
    pub fn send(&self, event: WebhookEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end]
}

async fn dispatch(
    mut rx: mpsc::UnboundedReceiver<WebhookEvent>,
    endpoints: Arc<Vec<Endpoint>>,
    client: reqwest::Client,
) {
    while let Some(event) = rx.recv().await {
        let body = event.body();
        for (i, e) in endpoints.iter().enumerate() {
            if e.events.iter().any(|x| x == event.event) {
                let endpoints = endpoints.clone();
                let client = client.clone();
                let body = body.clone();
                tokio::spawn(async move { deliver(&client, &endpoints[i], body).await });
            }
        }
    }
}

/// POST until a 2xx response or until [`RETRY_FOR`] has passed.
async fn deliver(client: &reqwest::Client, e: &Endpoint, body: Vec<u8>) {
    let started = Instant::now();
    let sig = signature(&e.secret, &body);
    let mut delay = FIRST_DELAY;
    loop {
        let sent = client
            .post(&e.url)
            .header("content-type", "application/json")
            .header("pragmatic-signature", &sig)
            .body(body.clone())
            .send()
            .await;
        if matches!(&sent, Ok(r) if r.status().is_success()) {
            return;
        }
        if started.elapsed() + delay > RETRY_FOR {
            return;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(MAX_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_hmac_sha256_of_the_body() {
        // RFC 4231 test case 2.
        let sig = signature(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn bodies_carry_no_content() {
        let e = WebhookEvent::new("erasure", Some("run-1"), serde_json::json!({"slots": 3}));
        let body: JsonValue = serde_json::from_slice(&e.body()).unwrap();
        assert_eq!(body["event"], "erasure");
        assert_eq!(body["run_id"], "run-1");
        assert_eq!(body["slots"], 3);
        assert_eq!(body.as_object().unwrap().len(), 4);
    }

    #[test]
    fn secrets_are_trimmed() {
        assert_eq!(trim_ascii(b"  abc\n"), b"abc");
        assert_eq!(trim_ascii(b"\n"), b"");
    }
}
