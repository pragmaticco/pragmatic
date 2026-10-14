//! Writes the journal half of the evidence test fixtures: a format 2
//! journal that exercises every part of a bundle a verifier checks, as an
//! unanchored local bundle.
//!
//! ```sh
//! cargo run -p pragmatic --example evidence_fixture -- OUT.json
//! ```
//!
//! `crates/pragmatic/tests/fixtures/evidence/generate.py` runs this and then
//! adds what only a server and its witnesses produce: the anchor log,
//! signed checkpoints, cosignatures, RFC 3161 tokens and the bundle
//! signature. Entry times are fixed so the records are stable; slot salts
//! come from the operating system's CSPRNG as always, so each run of the
//! generator produces a different (equally valid) journal.
//!
//! The run covers draws with every outcome (ok, partial, error), effects
//! that succeed, fail and are compensated, a parallel region, a refusal,
//! random and clock reads, a patch marker, a program identity, two
//! attempts with their notes, a deduplicated message, binary content, an
//! erasure with its note, and one slot withheld for privacy.

use pragmatic::evidence::{Bundle, Redact};
use pragmatic::journal::{
    note, Branch, Content, EffectOutcome, EraseSelector, ErasureNote, Event, Journal, META, ROOT,
};
use pragmatic::Value;

const RUN_ID: &str = "support-ticket-4127";

/// 2026-10-13T09:00:00Z, the first entry's time.
const T0: u64 = 1_791_882_000_000_000_000;

struct Writer {
    j: Journal,
    at: u64,
}

impl Writer {
    /// Append `event` on `branch`, 250 ms after the previous entry.
    fn put(&mut self, branch: &[u32], event: Event) -> u64 {
        self.at += 250_000_000;
        self.j
            .append_at(self.at, branch, event)
            .expect("fixture entry")
    }

    fn note(&mut self, kind: &str, data: &str, payload: Vec<Content>) -> u64 {
        self.put(
            META,
            Event::Note {
                kind: kind.into(),
                data: data.into(),
                payload,
            },
        )
    }

    fn draw(&mut self, branch: &[u32], parts: &[&str], meta: &str, body: &str) -> (u64, u64) {
        let intent = self.put(
            branch,
            Event::DrawIntent {
                provenance: "anthropic.messages".into(),
                parts: parts.iter().map(|p| Content::from(*p)).collect(),
            },
        );
        let result = self.put(
            branch,
            Event::DrawResult {
                intent,
                meta: meta.into(),
                head: Content::from(r#"{"status":200}"#),
                body: Content::from(body),
            },
        );
        (intent, result)
    }

    fn effect(
        &mut self,
        branch: &[u32],
        name: &str,
        arg: &str,
        outcome: EffectOutcome,
        out: &str,
    ) -> u64 {
        let intent = self.put(
            branch,
            Event::EffectIntent {
                name: name.into(),
                arg: arg.into(),
            },
        );
        let (error_kind, payload) = match outcome {
            EffectOutcome::Ok => (String::new(), Some(Content::from(out))),
            EffectOutcome::Failed => ("ConnectionError".to_string(), Some(Content::from(out))),
            EffectOutcome::Compensated => (String::new(), None),
        };
        self.put(
            branch,
            Event::EffectResult {
                intent,
                outcome,
                error_kind,
                payload,
            },
        );
        intent
    }
}

fn usage(input: u64, output: u64) -> String {
    format!(
        r#"{{"latency_ms":812,"model":"claude-sonnet-4-5","outcome":"ok","provider":"anthropic","stop_reason":"end_turn","usage":{{"input_tokens":{input},"output_tokens":{output}}}}}"#
    )
}

fn journal() -> Journal {
    let mut w = Writer {
        j: Journal::new(None),
        at: T0,
    };
    w.note(
        note::RUN_START,
        &format!(
            r#"{{"format":2,"labels":{{"team":"support"}},"nonce":"6f1c0e7d2a9b4c3e8d7f6a5b4c3d2e1f","run_id":"{RUN_ID}","sdk":"pragmatic-python","sdk_version":"0.6.0"}}"#
        ),
        vec![Content::from(r#"{"subjects":["customer:88412"]}"#)],
    );
    w.note(
        note::ATTEMPT_START,
        r#"{"attempt":1,"host":"agent-7","mode":"run","pid":4242,"principal":"tok_agent_ops","program":{"hash":"3f9a","name":"support_agent"},"sdk":"pragmatic-python","sdk_version":"0.6.0","torn_at_cursor":null,"torn_bytes":0,"traceparent":null}"#,
        vec![],
    );
    w.put(
        ROOT,
        Event::Program {
            name: "support_agent".into(),
            hash: "3f9a".into(),
        },
    );
    w.put(
        ROOT,
        Event::ChannelRecv {
            channel: "tickets".into(),
            value: Content::from(
                "Ticket 4127 from jane.doe@example.com: my March invoice was charged twice.",
            ),
        },
    );
    let system = format!(
        "You are a careful support agent. {}",
        "Policy text. ".repeat(30)
    );
    w.draw(
        ROOT,
        &[
            r#"POST /v1/messages {"model":"claude-sonnet-4-5"}"#,
            &system,
            "Classify the ticket.",
        ],
        &usage(1830, 42),
        r#"{"content":[{"type":"text","text":"billing/duplicate-charge"}]}"#,
    );
    w.put(
        ROOT,
        Event::Clock {
            nanos: T0 + 3_000_000_000,
        },
    );
    w.put(
        ROOT,
        Event::Random {
            source: "uuid4".into(),
            args: "[]".into(),
            value: Content::from("9b2e4c1a-7d3f-4e8a-b6c5-0f1e2d3c4b5a"),
        },
    );
    w.put(
        ROOT,
        Event::Marker {
            name: "refund-v2".into(),
        },
    );
    // A parallel region: two lookups on their own branches.
    w.put(
        ROOT,
        Event::Fork {
            base: 0,
            children: 2,
        },
    );
    let a: Branch = vec![0];
    let b: Branch = vec![1];
    w.effect(
        &a,
        "lookup_invoice",
        r#"{"invoice":"INV-0311"}"#,
        EffectOutcome::Ok,
        r#"{"amount":"49.00","charges":2}"#,
    );
    // The same long system prompt again: stored as a ref to the first copy.
    w.draw(
        &b,
        &[
            r#"POST /v1/messages {"model":"claude-sonnet-4-5"}"#,
            &system,
            "Summarize the account.",
        ],
        r#"{"outcome":"partial","model":"claude-sonnet-4-5","provider":"anthropic"}"#,
        "event: content_block_delta\ndata: {\"text\":\"Account in good stand",
    );
    w.put(
        &b,
        Event::Refusal {
            step: "effect".into(),
            name: "issue_credit".into(),
            fault: "CapabilityDenied".into(),
        },
    );
    // Back on the root: a failed call, a failed and a compensated effect.
    w.draw(
        ROOT,
        &[
            r#"POST /v1/messages {"model":"claude-sonnet-4-5"}"#,
            "Draft the reply.",
        ],
        r#"{"error_kind":"timeout","outcome":"error","provider":"anthropic"}"#,
        "read timed out",
    );
    let failed_refund = w.effect(
        ROOT,
        "refund",
        r#"{"invoice":"INV-0311","amount":"49.00"}"#,
        EffectOutcome::Failed,
        "payment gateway closed the connection",
    );
    w.note(
        note::ATTEMPT_END,
        r#"{"attempt":1,"fault_cursor":null,"fault_kind":"Io","fresh":12,"outcome":"fault","passthrough_calls":0,"replayed":0,"usage_fresh":{}}"#,
        vec![Content::from(""), Content::from("Io: process killed")],
    );
    // Attempt 2 resumes: recovery writes off the failed refund, retries it.
    w.note(
        note::ATTEMPT_START,
        r#"{"attempt":2,"host":"agent-9","mode":"resume","pid":5150,"principal":"tok_agent_ops","program":{"hash":"3f9a","name":"support_agent"},"sdk":"pragmatic-python","sdk_version":"0.6.0","torn_at_cursor":null,"torn_bytes":0,"traceparent":null}"#,
        vec![],
    );
    let written_off = w.put(
        ROOT,
        Event::EffectResult {
            intent: failed_refund,
            outcome: EffectOutcome::Compensated,
            error_kind: String::new(),
            payload: None,
        },
    );
    w.note(
        note::RECOVERY,
        &format!(
            r#"{{"branch":[],"decision":"retry","intent":{failed_refund},"name":"refund","result":{written_off}}}"#
        ),
        vec![],
    );
    w.effect(
        ROOT,
        "refund",
        r#"{"invoice":"INV-0311","amount":"49.00"}"#,
        EffectOutcome::Ok,
        r#"{"refund_id":"re_8812"}"#,
    );
    // An attachment: binary content inside JSON, and raw bytes.
    w.draw(
        ROOT,
        &[
            r#"POST /v1/messages {"model":"claude-sonnet-4-5"}"#,
            r#"{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGBgAAAABQABpfZFQAAAAABJRU5ErkJggg=="}}]}"#,
        ],
        &usage(940, 18),
        r#"{"content":[{"type":"text","text":"A screenshot of the invoice."}]}"#,
    );
    w.put(
        ROOT,
        Event::ChannelRecv {
            channel: "uploads".into(),
            value: Content::Sealed(Value::new(vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x10])),
        },
    );
    w.effect(
        ROOT,
        "send_email",
        r#"{"to":"jane.doe@example.com","body":"Your refund re_8812 is on its way."}"#,
        EffectOutcome::Ok,
        r#"{"message_id":"m-77"}"#,
    );
    w.note(
        note::ATTEMPT_END,
        r#"{"attempt":2,"fault_cursor":null,"fault_kind":null,"fresh":6,"outcome":"ok","passthrough_calls":0,"replayed":12,"usage_fresh":{}}"#,
        vec![Content::from("resolved"), Content::from("")],
    );
    w.j.mark_persisted(w.j.len());
    // The customer asked for the ticket text to be erased.
    let erased =
        w.j.erase(
            &EraseSelector::Slots(vec![(3, 0)]),
            &ErasureNote {
                by: "tok_admin_privacy".into(),
                authenticated: true,
                reason_code: "gdpr_art17".into(),
                access_log_cursor: Some(912),
                reason: "data subject request DSR-55".into(),
            },
            w.at + 60_000_000_000,
        )
        .expect("erase");
    erased.journal
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: evidence_fixture OUT.json");
    let j = journal();
    let mut bundle = Bundle::local(&j.to_bytes(), RUN_ID, &Redact::None).expect("bundle");
    // The confirmation email's argument names the customer, so it is
    // withheld by request; the erased ticket stays erased, and the binary
    // attachments stay in (they are what the records' base64 covers).
    let email = j
        .entries()
        .iter()
        .find(|e| matches!(&e.event, Event::EffectIntent { name, .. } if name == "send_email"))
        .map(|e| e.cursor)
        .expect("send_email intent");
    bundle.withhold(&[(email, 0)]).expect("withhold");
    std::fs::write(&out, bundle.to_json()).expect("write");
    eprintln!(
        "wrote {out}: {} entries, {} withheld slot(s)",
        bundle.journal.entries,
        bundle.redacted_slots.len()
    );
}
