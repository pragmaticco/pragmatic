//! Rendering the evidence fixtures (`crates/pragmatic/tests/fixtures/
//! evidence`), the recorded run `refund-20417` as the design shows it, a
//! row for every kind of entry, hostile content, and format 1 journals.

use std::path::PathBuf;

use pragmatic::evidence::{verify, Bundle, NoTsaVerifier, TrustPolicy};
use pragmatic::journal::{note, EffectOutcome, Event, Journal, META, ROOT};
use pragmatic::Value;

use super::*;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pragmatic/tests/fixtures/evidence")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn fixture_bundle() -> Bundle {
    Bundle::from_json(&fixture("bundle.json")).unwrap()
}

fn fixture_journal() -> Journal {
    Journal::parse_evidence(&fixture_bundle().journal.bytes)
        .unwrap()
        .journal
}

fn run_page(j: &Journal) -> String {
    let report = j.audit();
    render_run(&RunView::new("support-ticket-4127", j, &report))
}

/// The tags this crate writes.
const OWN: &[&str] = &[
    "!doctype", "html", "/html", "head", "/head", "meta", "title", "/title", "link", "style",
    "/style", "body", "/body", "div", "/div", "span", "/span", "svg", "/svg", "rect", "a ", "/a",
    "i ", "i>", "/i", "h1", "/h1", "h2", "/h2", "h3", "/h3", "p ", "p>", "/p", "pre", "/pre",
    "table", "/table", "caption", "/caption", "thead", "/thead", "tbody", "/tbody", "tr", "/tr",
    "th", "/th", "td", "/td", "details", "/details", "summary", "/summary", "section", "/section",
    "article", "/article", "aside", "/aside", "header", "/header", "footer", "/footer", "main",
    "/main", "nav", "/nav", "ol", "/ol", "ul", "/ul", "li", "/li", "dl", "/dl", "dt", "/dt", "dd",
    "/dd", "code", "/code", "bdi", "/bdi",
];

/// No element the page did not write itself: every `<` in the output opens
/// one of the tags this crate uses.
fn assert_only_own_markup(html: &str) {
    for (i, _) in html.match_indices('<') {
        let rest = &html[i + 1..];
        assert!(
            OWN.iter().any(|t| rest.starts_with(t)),
            "unexpected markup at {i}: {:?}",
            &rest[..rest.len().min(40)]
        );
    }
    assert!(!html.contains("<script"));
    assert!(!html.contains("javascript:"));
    assert!(!html.contains("<form"), "pages of this crate have no forms");
}

/// Text without tags, entities decoded, whitespace collapsed.
fn strip(h: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    for c in h.chars() {
        match c {
            '<' => tag = true,
            '>' => tag = false,
            c if !tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Each row of a page: its marker classes, its title (as HTML) and its
/// kinds line, as text.
fn rows(html: &str) -> Vec<(String, String, String)> {
    html.split("<li class=\"row ")
        .skip(1)
        .map(|chunk| {
            let class = chunk[..chunk.find('"').unwrap()].to_string();
            let t0 = chunk.find("<span class=\"t\">").unwrap();
            let k0 = chunk.find("<span class=\"k\">").unwrap();
            let t1 = chunk[t0..]
                .find("<span class=\"tm\"")
                .map(|i| t0 + i)
                .unwrap_or(k0)
                .min(k0);
            let k1 = chunk[k0..].find("</span>").unwrap() + k0;
            (
                class,
                chunk[t0..t1].to_string(),
                strip(&chunk[k0 + "<span class=\"k\">".len()..k1]),
            )
        })
        .collect()
}

fn titles(html: &str) -> Vec<String> {
    rows(html).into_iter().map(|(_, t, _)| strip(&t)).collect()
}

/// A title's text outside the places recorded content may go: mono data
/// and quoted excerpts.
fn console_words(title: &str) -> String {
    let mut out = String::new();
    let mut rest = title;
    loop {
        let m = rest.find("<span class=\"m");
        let q = rest.find("<bdi class=\"q\">");
        let (at, close) = match (m, q) {
            (Some(m), Some(q)) if q < m => (q, "</bdi>"),
            (Some(m), _) => (m, "</span>"),
            (None, Some(q)) => (q, "</bdi>"),
            (None, None) => {
                out.push_str(rest);
                return strip(&out);
            }
        };
        out.push_str(&rest[..at]);
        let end = rest[at..]
            .find(close)
            .map(|i| at + i + close.len())
            .unwrap();
        rest = &rest[end..];
    }
}

const AT: u64 = 1_791_937_792_000_000_000; // 2026-10-14T00:29:52Z

/// The run `refund-20417` as it was recorded on 14 October 2026 (with a
/// neutral host and principal): two model calls and two tool calls, a
/// crash, a resume that reads the four steps back and makes one more model
/// call, and its end.
fn refund_journal() -> Journal {
    let mut j = Journal::new(None);
    let at = |ms: u64| AT + ms * 1_000_000;
    let start = |n: u64, mode: &str, pid: u64| {
        format!(
            r#"{{"attempt":{n},"host":"build-host","mode":"{mode}","pid":{pid},"principal":"local:agent@build-host","program":null,"sdk":"pragmatic-rust","sdk_version":"0.5.0","torn_at_cursor":null,"torn_bytes":0,"traceparent":null}}"#
        )
    };
    let message = |id: &str, content: &str, stop: &str| {
        format!(
            r#"{{"id":"{id}","container":null,"content":{content},"model":"claude-sonnet-5-5","role":"assistant","stop_reason":"{stop}","type":"message"}}"#
        )
    };
    j.append_at(
        at(175),
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: r#"{"format":2,"labels":{},"nonce":"58f5887d7f4def073eaa081bb4d21d74","run_id":"refund-20417","sdk":"pragmatic-rust","sdk_version":"0.5.0"}"#.into(),
            payload: vec![],
        },
    )
    .unwrap();
    j.append_at(
        at(175),
        META,
        Event::Note {
            kind: "attempt.start".into(),
            data: start(1, "run", 9919),
            payload: vec![],
        },
    )
    .unwrap();
    let request = Value::from(
        r#"{"api":"anthropic.messages.create","request":{"max_tokens":512,"messages":[{"content":"Order 20417: I was charged twice. Please refund the extra charge.","role":"user"}],"model":"claude-sonnet-5-5"}}"#,
    );
    let step = |j: &mut Journal, t: (u64, u64), body: String| {
        let i = j
            .append_at(
                at(t.0),
                ROOT,
                Event::DrawIntent {
                    provenance: "anthropic:claude-sonnet-5-5".into(),
                    parts: vec![request.clone().into()],
                },
            )
            .unwrap();
        j.append_at(
            at(t.1),
            ROOT,
            Event::DrawResult {
                intent: i,
                meta: r#"{"outcome":"ok"}"#.into(),
                head: Value::from("").into(),
                body: Value::from(body).into(),
            },
        )
        .unwrap();
    };
    let tool = |j: &mut Journal, t: (u64, u64), name: &str, arg: &str, result: &str| {
        let i = j
            .append_at(
                at(t.0),
                ROOT,
                Event::EffectIntent {
                    name: format!("tool:{name}"),
                    arg: Value::from(arg).into(),
                },
            )
            .unwrap();
        j.append_at(
            at(t.1),
            ROOT,
            Event::EffectResult {
                intent: i,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Value::from(result).into()),
            },
        )
        .unwrap();
    };
    step(
        &mut j,
        (179, 1098),
        message(
            "msg_01R1",
            r#"[{"citations":null,"text":"I'll check the order first.","type":"text"},{"id":"toolu_01","input":{"order_id":"20417"},"name":"lookup_order","type":"tool_use"}]"#,
            "tool_use",
        ),
    );
    tool(
        &mut j,
        (1102, 1260),
        "lookup_order",
        r#"{"id":"toolu_01","input":{"order_id":"20417"}}"#,
        r#"{"content":"{\"charges\":[{\"amount\":\"129.00\",\"id\":\"ch_8811\"},{\"amount\":\"129.00\",\"id\":\"ch_8812\"}],\"order_id\":\"20417\",\"status\":\"delivered\"}","is_error":false}"#,
    );
    step(
        &mut j,
        (1264, 2172),
        message(
            "msg_01R2",
            r#"[{"citations":null,"text":"The second charge is a duplicate. Refunding it.","type":"text"},{"id":"toolu_02","input":{"order_id":"20417","charge_id":"ch_8812","amount":"129.00"},"name":"issue_refund","type":"tool_use"}]"#,
            "tool_use",
        ),
    );
    tool(
        &mut j,
        (2176, 2485),
        "issue_refund",
        r#"{"id":"toolu_02","input":{"amount":"129.00","charge_id":"ch_8812","order_id":"20417"}}"#,
        r#"{"content":"{\"amount\":\"129.00\",\"charge_id\":\"ch_8812\",\"refund_id\":\"re_3f9c\",\"status\":\"succeeded\"}","is_error":false}"#,
    );
    j.append_at(
        at(5867),
        META,
        Event::Note {
            kind: "attempt.start".into(),
            data: start(2, "resume", 9978),
            payload: vec![],
        },
    )
    .unwrap();
    let reply = "Hi Sam, you were charged twice for order 20417. I've refunded the duplicate $129.00; it should reach your card in 3 to 5 business days.";
    step(
        &mut j,
        (5876, 6786),
        message(
            "msg_01R3",
            &format!(r#"[{{"citations":null,"text":"{reply}","type":"text"}}]"#),
            "end_turn",
        ),
    );
    j.append_at(
        at(6790),
        META,
        Event::Note {
            kind: "attempt.end".into(),
            data: r#"{"attempt":2,"fault_cursor":null,"fault_kind":null,"fresh":1,"outcome":"ok","passthrough_calls":0,"replayed":4,"usage_fresh":{}}"#.into(),
            payload: vec![Value::from(reply).into(), Value::from("").into()],
        },
    )
    .unwrap();
    j
}

/// The run page of `refund-20417`, word for word as the design draws it.
#[test]
fn refund_20417_reads_as_designed() {
    let j = refund_journal();
    let report = j.audit();
    let view = RunView {
        source: Some("journals"),
        ..RunView::new("refund-20417", &j, &report)
    };
    let html = render_run(&view);
    assert_only_own_markup(&html);
    let got: Vec<(String, String, String)> = rows(&html)
        .into_iter()
        .map(|(c, t, k)| (c, strip(&t), k))
        .collect();
    let want = [
        ("mk-hollow", "Run started · pragmatic-rust 0.5.0", "note.run.start #0 · note.attempt.start #1"),
        ("mk-ring", "Model call asks for lookup_order", "draw.intent #2 · draw.ok #3"),
        ("mk-ring", "Tool call lookup_order · charges ×2, status delivered", "effect.intent #4 · effect.ok #5"),
        ("mk-ring", "Model call asks for issue_refund", "draw.intent #6 · draw.ok #7"),
        ("mk-ring", "Tool call issue_refund · refund_id re_3f9c, status succeeded", "effect.intent #8 · effect.ok #9"),
        ("mk-alarm-hollow crash derived", "No end: crashed · attempt 1 stopped after #9", "no note.attempt.end for attempt 1"),
        ("mk-hollow", "Attempt 2 · 4 steps read back · nothing repeated", "note.attempt.start #10"),
        ("mk-fill", "Model call asks for reply · \u{201c}Hi Sam, you were charged twice for order 20417\u{2026}\u{201d}", "draw.intent #11 · draw.ok #12"),
        ("mk-big", "Attempt 2 ended ok · 1 fresh, 4 replayed", "note.attempt.end #13"),
    ];
    assert_eq!(got.len(), want.len(), "{got:#?}");
    for ((c, t, k), (wc, wt, wk)) in got.iter().zip(want) {
        assert_eq!(c, wc, "{t}");
        assert_eq!(t, wt);
        assert_eq!(k, wk, "{t}");
    }
    // Groups, facts, state, chain.
    assert!(html.contains(">Attempt 1 \u{b7} run \u{b7} pid 9919</h3>"));
    assert!(html.contains(">Attempt 2 \u{b7} resume \u{b7} pid 9978</h3>"));
    let facts = &html[html.find("<p class=\"facts\">").unwrap()..];
    let facts = strip(&facts[..facts.find("</p>").unwrap()]);
    assert_eq!(
        facts,
        "Format 2 · 14 entries · 2 attempts · 3 model calls · 2 tool calls"
    );
    let state = &html[html.find("<p class=\"state\">").unwrap()..];
    let state = strip(&state[..state.find("</p>").unwrap()]);
    assert_eq!(
        state,
        "Ended ok · recorded 14 Oct 2026, 00:29:52 to 00:29:58 UTC"
    );
    assert!(html.contains(
        "<span class=\"badge\"><i class=\"dm\" aria-hidden=\"true\"></i>Verified</span>"
    ));
    assert!(html.contains("<span>Chain verified</span><span class=\"s\">\u{b7} 14 entries</span>"));
    // Times and the hash of each row's last entry.
    assert!(html.contains("<span class=\"tm\" aria-hidden=\"true\">00:29:52.179</span>"));
    let hash = pragmatic::encoding::hex_encode(&j.get(3).unwrap().hash);
    assert!(html.contains(&format!(
        "title=\"{hash}\" aria-hidden=\"true\">{}</span>",
        &hash[..10]
    )));
    // The side cards: not anchored, the check as `pragmatic verify` prints
    // it, the run's model, tokens not recorded, and its attempts.
    assert!(html.contains("<h2 class=\"card-t o\" id=\"h-anchor\">Not anchored</h2>"));
    assert!(html.contains("<dt>chain</dt><dd>every link, commitment and ref verifies</dd>"));
    assert!(html.contains("pragmatic verify refund-20417 --dir journals"));
    assert!(html.contains("<dt>model</dt><dd>anthropic:claude-sonnet-5-5</dd>"));
    assert!(html.contains("<dt>tokens</dt><dd><span class=\"s\">not recorded</span></dd>"));
    assert!(!html.contains(" in / "), "tokens are never shown as 0");
    assert!(html.contains("<span class=\"s alarm\">no end</span>"));
    assert!(html.contains("ok, 1 fresh, 4 replayed"));
    assert!(html.contains("Read back by attempt 2: replayed from the journal, not repeated."));
    // The masthead of a file, and its policy.
    assert!(html.contains("<title>refund-20417 \u{b7} Pragmatic</title>"));
    assert!(html.contains("<span class=\"src\">journals</span>"));
    assert!(html.contains("font-src data:"));
    every_cursor_once(&html, &j);
}

/// Every entry of the page is in exactly one row.
fn every_cursor_once(html: &str, j: &Journal) {
    for c in 0..j.len() {
        assert_eq!(
            html.matches(&format!("<span id=\"c{c}\"></span>")).count(),
            1,
            "cursor {c}"
        );
    }
}

#[test]
fn format_2_runs_render_fully() {
    let j = fixture_journal();
    let html = run_page(&j);
    assert_only_own_markup(&html);
    every_cursor_once(&html, &j);
    let t = titles(&html);
    for want in [
        "Run started · pragmatic-python 0.6.0 · team=support",
        "Program support_agent · 3f9a",
        "Received on tickets · content erased",
        "Model call asks for reply · \u{201c}billing/duplicate-charge\u{201d}",
        "Clock read · 09:00:03.000 UTC",
        "Parallel region · 2 branches",
        "Effect lookup_invoice · amount 49.00, charges 2",
        "Model call asks for streamed reply · stream ended early",
        "Effect issue_credit refused · CapabilityDenied · no capability for it",
        "Model call failed · timeout",
        "Effect refund · written off by recovery, performed again at #23",
        "Attempt 1 ended with a fault · Io · \u{201c}Io: process killed\u{201d}",
        "Recovery retries refund",
        "Received on uploads · application/octet-stream, 7 bytes",
        "Attempt 2 ended ok · 6 fresh, 12 replayed",
        "Erased 1 slot · reason gdpr_art17",
    ] {
        assert!(t.iter().any(|x| x == want), "{want}\n{t:#?}");
    }
    // Nested lanes: the parallel region's children sit one lane deep and
    // name their branch; the fork names its children.
    assert!(html.contains("<li class=\"row mk-fill d1\">"));
    let r = rows(&html);
    assert!(r.iter().any(|(_, _, k)| k == "fork #9 · branches 0 to 1"));
    assert!(r
        .iter()
        .any(|(_, _, k)| k.starts_with("branch 1 · draw.intent #12")));
    // A step joins every result recorded for it.
    assert!(r
        .iter()
        .any(|(_, _, k)| k == "effect.intent #17 · effect.failed #18 · effect.compensated #21"));
    // Slots in the expanded rows.
    assert!(html.contains("Erased: the content and its salt were dropped"));
    assert!(html.contains("Withheld from this view"));
    assert!(html.contains("The same content as <a class=\"m\" href=\"#c4\">#4</a>, request part 1"));
    assert!(html.contains("Binary content at <span class=\"m\">/content/0/source/data</span>, not shown: image/png, 70 bytes"));
    assert!(
        !html.contains("CAYAAAAfFcSJ"),
        "the fixture image is not inlined"
    );
    assert!(html.contains("Binary content, not shown: application/octet-stream, 7 bytes"));
    // Times in full, and the draw result's meta.
    assert!(html.contains("2026-10-13T09:00:00.25Z"));
    assert!(html.contains("<dt>tokens</dt><dd>1,830 in, 42 out</dd>"));
    assert!(html.contains("<dt>latency</dt><dd>812 ms</dd>"));
    assert!(
        html.contains("<dt>tokens</dt><dd>"),
        "usage recorded: the Run card shows it"
    );
    assert!(html.contains(
        "<span class=\"badge\"><i class=\"dm\" aria-hidden=\"true\"></i>Verified</span>"
    ));
}

/// Recorded text reaches a row's title only as mono data or a quoted
/// excerpt, never as the console's own words; the hostile journal puts the
/// marker everywhere it can.
#[test]
fn recorded_text_stays_out_of_the_consoles_words() {
    for j in [hostile_journal(), fixture_journal(), every_kind()] {
        let html = run_page(&j);
        for (_, title, _) in rows(&html) {
            let words = console_words(&title);
            assert!(!words.contains("PWN"), "{words}");
            for bad in ["<script", "<b>", "<i>", "onerror"] {
                assert!(!words.contains(bad), "{words}");
            }
        }
    }
}

#[test]
fn anchor_status_is_shown_when_known() {
    let j = fixture_journal();
    let report = j.audit();
    let status = AnchorStatus {
        anchored_entries: 20,
        independent: true,
        operators: vec!["digicert".into(), "sectigo".into()],
        time: Some("2026-10-13T12:00:00Z".into()),
        witnesses: vec![],
    };
    let view = RunView {
        anchor: Some(&status),
        ..RunView::new("r", &j, &report)
    };
    let html = render_run(&view);
    assert!(html.contains(">Anchored up to #19</h2>"));
    assert!(html.contains("20 of 32 entries"));
    assert!(html.contains("<span class=\"nm\">digicert</span><span class=\"st\">trusted</span>"));
    assert!(html.contains("<span style=\"width:62.50%\"></span>"));
    let operator_only = AnchorStatus {
        independent: false,
        ..status.clone()
    };
    let view = RunView {
        anchor: Some(&operator_only),
        ..view
    };
    assert!(render_run(&view).contains(">Signed by this server only</h2>"));
    let all = AnchorStatus {
        anchored_entries: 32,
        witnesses: vec![
            AnchorWitness {
                operator: "Alpha".into(),
                kind: "RFC 3161".into(),
                trust: WitnessTrust::Trusted,
                root: Some("Alpha Root".into()),
            },
            AnchorWitness {
                operator: "Beta".into(),
                kind: "RFC 3161".into(),
                trust: WitnessTrust::Waiting,
                root: None,
            },
        ],
        ..status.clone()
    };
    let view = RunView {
        anchor: Some(&all),
        ..view
    };
    let html = render_run(&view);
    assert!(html.contains(">Anchored by 2 independent timestamp services</h2>"));
    assert!(
        html.contains("existed no later than <span class=\"m nw\">13 Oct 2026, 12:00 UTC</span>")
    );
    assert!(html.contains(
        "<span class=\"st\">RFC 3161 \u{b7} trusted</span><span class=\"root\">Alpha Root</span>"
    ));
    assert!(html.contains("<span class=\"st\">waiting</span>"));
}

/// A journal whose every field and slot carries markup.
fn hostile_journal() -> Journal {
    let x = "PWN<script>alert('x')</script><img src=x onerror=alert(1)>\u{1b}[2J";
    let mut j = Journal::new(None);
    let start = format!(
        r#"{{"format":2,"labels":{{"k":"{0}"}},"nonce":"00","run_id":"evil","sdk":"{0}","sdk_version":"0"}}"#,
        "PWN<b>x</b>"
    );
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: start,
            payload: vec![Value::from(x).into()],
        },
    )
    .unwrap();
    j.append(
        META,
        Event::Note {
            kind: "attempt.start".into(),
            data: r#"{"attempt":1,"mode":"PWN<i>","pid":"PWN<i>","host":"<h>","principal":"<p>"}"#
                .into(),
            payload: vec![],
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: x.into(),
            value: Value::from(x).into(),
        },
    )
    .unwrap();
    let intent = j
        .append(
            ROOT,
            Event::DrawIntent {
                provenance: x.into(),
                parts: vec![Value::from(format!(r#"{{"t":"{}"}}"#, "<i>")).into()],
            },
        )
        .unwrap();
    j.append(
        ROOT,
        Event::DrawResult {
            intent,
            meta: r#"{"outcome":"<b>","model":"</td><script>"}"#.into(),
            head: Value::from(x).into(),
            body: Value::from(r#"{"type":"message","content":[{"type":"tool_use","name":"PWN<script>"},{"type":"text","text":"PWN <b>hi</b>"}]}"#).into(),
        },
    )
    .unwrap();
    let e = j
        .append(
            ROOT,
            Event::EffectIntent {
                name: format!("tool:{x}"),
                arg: Value::from(r#"{"id":"t","input":{"PWN<k>":"PWN<v>"}}"#).into(),
            },
        )
        .unwrap();
    j.append(
        ROOT,
        Event::EffectResult {
            intent: e,
            outcome: EffectOutcome::Failed,
            error_kind: x.into(),
            payload: Some(Value::from(x).into()),
        },
    )
    .unwrap();
    let data = r#"{"principal":"PWN<p>","from_entries":"PWN","to_entries":"PWN","requests":"PWN","bytes":"PWN","offset":"PWN","decision":"PWN<d>","name":"PWN<n>","reason_code":"PWN<r>","by":"PWN<b>","from":"PWN<f>","to":"PWN<t>","cursor":"PWN"}"#;
    for kind in ["recovery", "program.change", x] {
        j.append(
            META,
            Event::Note {
                kind: kind.into(),
                data: data.into(),
                payload: vec![],
            },
        )
        .unwrap();
    }
    for kind in note::SERVER_ONLY {
        j.append_server_note(AT, kind, data, vec![]).unwrap();
    }
    j.append(
        META,
        Event::Note {
            kind: "attempt.end".into(),
            data: r#"{"attempt":1,"outcome":"fault","fault_kind":"PWN<f>","fault_cursor":3,"fresh":"PWN","replayed":"PWN"}"#.into(),
            payload: vec![Value::from(x).into(), Value::from(x).into()],
        },
    )
    .unwrap();
    j
}

#[test]
fn hostile_content_is_escaped_everywhere() {
    let j = hostile_journal();
    let report = j.audit();
    let view = RunView {
        source: Some("<img src=x>"),
        ..RunView::new("<script>", &j, &report)
    };
    let html = render_run(&view);
    assert_only_own_markup(&html);
    assert!(html.contains("&lt;script&gt;"));
    // Mode and pid that are not a closed vocabulary keep their case.
    assert!(html.contains("<span class=\"nc\">PWN&lt;i&gt;</span>"));

    let rows = vec![
        RunRow::from_journal("<b>run</b>", &j, &report).linked("/run/\"><script>"),
        RunRow::unreadable("<x>", "<script>bad</script>"),
    ];
    let index = render_index_of(&rows, Some("<dir>"), None);
    assert_only_own_markup(&index);

    let bundle = Bundle::local(&j.to_bytes(), "evil", &pragmatic::evidence::Redact::None).unwrap();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let page = render_evidence(&bundle, &report);
    assert_only_own_markup(&page);
}

/// A journal with one entry of every kind the rows describe.
fn every_kind() -> Journal {
    let mut j = Journal::new(None);
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: r#"{"format":2,"labels":{"a":"1","b":"2","c":"3","d":"4","e":"5"},"nonce":"00","run_id":"k","sdk":"pragmatic-python","sdk_version":"0.6.0"}"#.into(),
            payload: vec![],
        },
    )
    .unwrap();
    let note = |j: &mut Journal, kind: &str, data: &str| {
        j.append(
            META,
            Event::Note {
                kind: kind.into(),
                data: data.into(),
                payload: vec![],
            },
        )
        .unwrap()
    };
    note(
        &mut j,
        "attempt.start",
        r#"{"attempt":1,"mode":"run","pid":7}"#,
    );
    let tool = |j: &mut Journal, name: &str, arg: &str| {
        j.append(
            ROOT,
            Event::EffectIntent {
                name: name.into(),
                arg: Value::from(arg).into(),
            },
        )
        .unwrap()
    };
    let result = |j: &mut Journal, intent, outcome, kind: &str, payload: Option<&str>| {
        j.append(
            ROOT,
            Event::EffectResult {
                intent,
                outcome,
                error_kind: kind.into(),
                payload: payload.map(|p| Value::from(p).into()),
            },
        )
        .unwrap()
    };
    // A tool that returned an error, one that failed, one with no fields
    // left after the input, a written-off effect done again.
    let e = tool(&mut j, "tool:lookup", r#"{"id":"t1","input":{"q":"x"}}"#);
    result(
        &mut j,
        e,
        EffectOutcome::Ok,
        "",
        Some(
            r#"{"content":"LookupError: no tool named lookup_ordr in this agent","is_error":true}"#,
        ),
    );
    let e = tool(&mut j, "tool:charge", r#"{"id":"t2","input":{"q":"x"}}"#);
    result(
        &mut j,
        e,
        EffectOutcome::Failed,
        "Timeout",
        Some("the payment service did not answer in time"),
    );
    let e = tool(&mut j, "tool:echo", r#"{"id":"t3","input":{"q":"x"}}"#);
    result(
        &mut j,
        e,
        EffectOutcome::Ok,
        "",
        Some(r#"{"content":"{\"q\":\"x\"}","is_error":false}"#),
    );
    let e = tool(&mut j, "send_email", r#"{"to":"a@b"}"#);
    result(&mut j, e, EffectOutcome::Compensated, "", None);
    note(
        &mut j,
        "recovery",
        r#"{"decision":"compensate","name":"send_email","intent":1,"result":2,"saga":"undo"}"#,
    );
    note(
        &mut j,
        "recovery",
        r#"{"decision":"commit","name":"tool:charge","intent":1,"result":2}"#,
    );
    let again = tool(&mut j, "send_email", r#"{"to":"a@b"}"#);
    result(
        &mut j,
        again,
        EffectOutcome::Ok,
        "",
        Some(r#"{"message_id":"m-1"}"#),
    );
    // Model calls: OpenAI chat with tools, OpenAI responses with a reply
    // cut at the limit, an error with a status, a stream, a binary body.
    let draw = |j: &mut Journal, meta: &str, body: Vec<u8>| {
        let i = j
            .append(
                ROOT,
                Event::DrawIntent {
                    provenance: "openai:gpt".into(),
                    parts: vec![Value::from("{}").into()],
                },
            )
            .unwrap();
        j.append(
            ROOT,
            Event::DrawResult {
                intent: i,
                meta: meta.into(),
                head: Value::from("").into(),
                body: Value::new(body).into(),
            },
        )
        .unwrap();
    };
    draw(&mut j, r#"{"outcome":"ok"}"#, br#"{"object":"chat.completion","choices":[{"message":{"content":null,"tool_calls":[{"function":{"name":"a"}},{"function":{"name":"b"}},{"function":{"name":"c"}},{"function":{"name":"d"}},{"function":{"name":"e"}}]}}]}"#.to_vec());
    draw(&mut j, r#"{"outcome":"ok"}"#, br#"{"object":"response","status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"Partial answer"}]}]}"#.to_vec());
    draw(
        &mut j,
        r#"{"outcome":"error","error_kind":"RateLimited","status":429,"error_type":"rate_limit_error"}"#,
        b"".to_vec(),
    );
    draw(
        &mut j,
        r#"{"outcome":"partial"}"#,
        b"event: x\ndata: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n".to_vec(),
    );
    draw(&mut j, r#"{"outcome":"ok"}"#, vec![0xff, 0xd8, 0xff, 0x00]);
    // A model call with no result yet.
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "openai:gpt".into(),
            parts: vec![Value::from("{}").into()],
        },
    )
    .unwrap();
    j.append(ROOT, Event::Clock { nanos: AT }).unwrap();
    j.append(
        ROOT,
        Event::Random {
            source: "randint".into(),
            args: "[1,6]".into(),
            value: Value::from("4").into(),
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::Program {
            name: "agent".into(),
            hash: "0123456789abcdef0123".into(),
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::Marker {
            name: "fix-1".into(),
        },
    )
    .unwrap();
    for (step, name, fault) in [
        ("draw", "", "BudgetExhausted"),
        ("effect", "tool:pay", "CapabilityDenied"),
        ("recv", "inbox", "Timeout"),
    ] {
        j.append(
            ROOT,
            Event::Refusal {
                step: step.into(),
                name: name.into(),
                fault: fault.into(),
            },
        )
        .unwrap();
    }
    j.append(
        ROOT,
        Event::Fork {
            base: 0,
            children: 3,
        },
    )
    .unwrap();
    j.append(
        &[0],
        Event::ChannelRecv {
            channel: "in".into(),
            value: Value::from(r#"{"n":1}"#).into(),
        },
    )
    .unwrap();
    note(
        &mut j,
        "program.change",
        r#"{"cursor":3,"from":"aaaaaaaaaaaaaaaaaaaa","to":"bbbbbbbbbbbbbbbbbbbb"}"#,
    );
    let server = |j: &mut Journal, kind: &str, data: &str| {
        j.append_server_note(AT, kind, data, vec![]).unwrap()
    };
    server(
        &mut j,
        "custody",
        r#"{"principal":"svc","from_entries":0,"to_entries":9,"requests":3,"clock_skew":true}"#,
    );
    server(&mut j, "torn_tail", r#"{"bytes":112,"offset":4096}"#);
    server(
        &mut j,
        "erasure",
        r#"{"by":"local:a@b","authenticated":false,"reason_code":"gdpr","slots":[]}"#,
    );
    note(&mut j, "app.custom", r#"{"step":"done","n":2}"#);
    j
}

#[test]
fn every_kind_of_entry_has_its_row() {
    let j = every_kind();
    let html = run_page(&j);
    assert_only_own_markup(&html);
    every_cursor_once(&html, &j);
    let t = titles(&html);
    for want in [
        "Run started · pragmatic-python 0.6.0 · a=1 b=2 c=3 · + 2 labels",
        "Tool call lookup returned an error · \u{201c}LookupError: no tool named lookup_ordr in\u{2026}\u{201d}",
        "Tool call charge failed · Timeout · \u{201c}the payment service did not answer in time\u{201d}",
        "Tool call echo · q x",
        "Effect send_email · written off by recovery, performed again at #12",
        "Recovery wrote off send_email · it runs again · saga undo",
        "Recovery recorded a result for charge",
        "Effect send_email · message_id m-1",
        "Model call asks for a, b, c + 2 more",
        "Model call asks for reply · \u{201c}Partial answer\u{201d} · cut off at the token limit",
        "Model call failed · RateLimited · HTTP 429 · rate_limit_error",
        "Model call asks for reply · \u{201c}Hel\u{201d} · stream ended early",
        "Model call · application/octet-stream, 4 bytes",
        "Model call · no response recorded",
        "Clock read · 00:29:52.000 UTC",
        "Random draw · randint(1, 6) = 4",
        "Program agent · 0123456789ab",
        "Patch taken · fix-1",
        "Model call refused · BudgetExhausted · over the run's budget",
        "Tool call pay refused · CapabilityDenied · no capability for it",
        "Receive on inbox refused · Timeout · inbox empty",
        "Parallel region · 3 branches",
        "Received on in · n 1",
        "Program changed at #3 · aaaaaaaaaaaa to bbbbbbbbbbbb",
        "Lease custody · svc · entries 0 to 9, 3 requests · clock skew flagged",
        "Torn tail moved aside · 112 bytes at offset 4,096",
        "Erased 0 slots · reason gdpr",
        "Note app.custom · step done, n 2",
        "No end yet · running, or crashed; refresh to see whether it continues",
    ] {
        assert!(t.iter().any(|x| x == want), "{want}\n{t:#?}");
    }
    let r = rows(&html);
    let class_of = |title: &str| {
        r.iter()
            .find(|(_, t, _)| strip(t) == title)
            .map(|(c, _, _)| c.clone())
            .unwrap()
    };
    assert_eq!(
        class_of("Model call · no response recorded"),
        "mk-alarm-hollow"
    );
    assert_eq!(
        class_of("Model call failed · RateLimited · HTTP 429 · rate_limit_error"),
        "mk-alarm"
    );
    assert_eq!(
        class_of("Effect send_email · written off by recovery, performed again at #12"),
        "mk-hollow"
    );
    assert_eq!(
        class_of("Model call asks for reply · \u{201c}Hel\u{201d} · stream ended early"),
        "mk-hollow"
    );
    assert!(r
        .iter()
        .any(|(c, _, k)| c == "mk-fill d1" && k == "branch 0 · chan.recv #33"));
    assert!(r.iter().any(|(_, _, k)| k == "fork #32 · branches 0 to 2"));
    assert!(r
        .iter()
        .any(|(_, _, k)| k == "note.erasure #37 · by local:a@b · unauthenticated"));
    assert!(r
        .iter()
        .any(|(_, _, k)| k == "note.recovery #11 · for #1 · result #2"));
    // The facts count tool calls, effects, failures and the open call.
    let facts = &html[html.find("<p class=\"facts\">").unwrap()..];
    let facts = strip(&facts[..facts.find("</p>").unwrap()]);
    assert_eq!(
        facts,
        "Format 2 · 39 entries · 1 attempt · 6 model calls · 3 tool calls · 2 effects · 2 failed · 1 open call"
    );
    assert!(html.contains("1 call has no result (<a class=\"m\" href=\"#c24\">#24</a>)"));
}

#[test]
fn evidence_pages_lead_with_the_verdict() {
    let bundle = fixture_bundle();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let html = render_evidence(&bundle, &report);
    assert_only_own_markup(&html);
    assert!(html.contains("Unanchored</span><span class=\"exit\">UNANCHORED \u{b7} exit 3</span>"));
    assert!(html.contains("operator-controlled"));
    assert!(html.contains("self-asserted"));
    assert!(html.contains("tsa_unchecked") || html.contains("tsa_untrusted"));
    assert!(html.contains("<h2 class=\"rhead\">Timeline</h2>"));
    assert!(html.contains("<span id=\"c31\"></span>"));
    assert!(html.contains("font-src data:"));
    // A bundle whose journal does not parse shows its records, flagged.
    let mut broken = bundle;
    broken.journal.bytes.truncate(100);
    let report = verify(&broken, &TrustPolicy::default(), &NoTsaVerifier);
    let html = render_evidence(&broken, &report);
    assert!(html.contains("FAILED"));
    assert!(html.contains("which nothing vouches for"));
}

#[test]
fn csv_has_one_row_per_record() {
    let bundle = fixture_bundle();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let csv = render_csv(&bundle, &report);
    let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1 + bundle.records.len());
    assert!(lines[0].starts_with("verdict,anchored,cursor,at_ns,at_utc"));
    assert!(lines[1].starts_with("\"UNANCHORED\",\"no\",\"0\",\""));
    assert!(csv.contains("[erased]"));
    assert!(csv.contains("[withheld]"));
    assert!(csv.contains("[binary media_type=application/octet-stream bytes=7"));
    assert!(!csv.contains("CAYAAAAfFcSJ"));
}

#[test]
fn csv_rows_come_from_the_journal_never_from_stated_records() {
    let mut bundle = fixture_bundle();
    let slot = bundle
        .records
        .iter_mut()
        .flat_map(|r| r.slots.iter_mut())
        .find(|s| s.text.is_some())
        .unwrap();
    slot.text = Some("FORGED: refund approved by the manager".into());
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    assert_eq!(report.verdict, pragmatic::evidence::Verdict::Failed);
    let csv = render_csv(&bundle, &report);
    assert!(
        !csv.contains("FORGED"),
        "the edited records never reach the CSV"
    );
    assert!(csv
        .lines()
        .skip(1)
        .all(|l| l.starts_with("\"FAILED\",\"no\",")));
    // With the journal unreadable, the stated records are all there is,
    // and every row says FAILED.
    bundle.journal.bytes.truncate(100);
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let csv = render_csv(&bundle, &report);
    assert!(csv.contains("FORGED"));
    assert!(csv.lines().skip(1).all(|l| l.starts_with("\"FAILED\",")));
}

#[test]
fn format_1_runs_render_read_only() {
    use pragmatic::journal_v1;
    let dir = std::env::temp_dir().join(format!(
        "pragmatic-console-v1-{}-{}",
        std::process::id(),
        pragmatic::journal::system_clock()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("legacy.journal");
    let mut v1 = journal_v1::Journal::create(&path).unwrap();
    v1.append(journal_v1::Event::OracleDraw {
        prompt: "plan <b>".into(),
        outcome: "ok".into(),
        provenance: "seeded".into(),
    })
    .unwrap();
    v1.append(journal_v1::Event::EffectIntent {
        name: "send".into(),
        arg: "x".into(),
    })
    .unwrap();
    v1.sync().unwrap();
    drop(v1);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let j = Journal::parse(&bytes, None).unwrap().journal;
    assert_eq!(j.format(), 1);
    let html = run_page(&j);
    assert_only_own_markup(&html);
    assert!(html.contains("A format 1 journal from Pragmatic 0.4 or 0.5"));
    assert!(html.contains("<span class=\"tag\">Read-only</span>"));
    assert!(html.contains("oracle.draw"));
    assert!(html.contains("plan &lt;b&gt;"));
    let t = titles(&html);
    assert!(
        t.contains(&"Model call · \u{201c}ok\u{201d}".to_string()),
        "{t:?}"
    );
    assert!(
        t.contains(&"Effect send · \u{201c}x\u{201d} · no result recorded".to_string()),
        "{t:?}"
    );
    assert!(html.contains("1 call has no result"));
}

#[test]
fn index_lists_runs() {
    let j = fixture_journal();
    let report = j.audit();
    let rows = vec![RunRow::from_journal("a", &j, &report).linked("/run/a")];
    let html = render_index(&rows);
    assert_only_own_markup(&html);
    assert!(html.contains("<a class=\"m\" href=\"/run/a\">a</a>"));
    assert!(html.contains("of <span class=\"n\">1</span> chains verified"));
    assert_eq!(rows[0].attempts, 2);
    assert_eq!(rows[0].last_outcome.as_deref(), Some("ok"));
    assert!(render_index(&[]).contains("No runs in this directory yet."));
}

/// A live console frames the page with its own policy and navigation,
/// shows its parts, and passes every slot's content through its filter:
/// a viewer without `view_raw` never sees the raw text, in a row's title
/// or in its detail, while fields stay as they are.
#[test]
fn a_filtered_framed_page_shows_no_raw_content() {
    let j = fixture_journal();
    let report = j.audit();
    let filter =
        |bytes: &[u8]| -> Vec<u8> { format!("[filtered {} bytes]", bytes.len()).into_bytes() };
    let frame = crate::html::Frame {
        csp: crate::html::CONSOLE_POLICY,
        fonts: crate::html::Fonts::Served("/console/assets/"),
        home: Some("/console"),
        nav: "<nav class=\"nav\"><a href=\"/console\">Runs</a></nav>",
        footer: "Licensed to Example Corp",
    };
    let view = RunView {
        frame: Some(&frame),
        filter: Some(SlotFilter(&filter)),
        server: Some(ServerRun {
            status: "dangling",
            holds: 2,
            holds_href: Some("/console/holds"),
            notices: "<p class=\"notice\">notice here</p>",
            evidence: Some("<p>evidence foot</p>"),
            erase: Some("<section class=\"card erase\">erase card</section>"),
        }),
        ..RunView::new("support-ticket-4127", &j, &report)
    };
    let html = render_run(&view);
    assert!(html.contains("form-action 'self'"));
    assert!(html.contains("font-src 'self'"));
    assert!(html.contains("Licensed to Example Corp"));
    assert!(
        html.contains("notice here")
            && html.contains("evidence foot")
            && html.contains("erase card")
    );
    assert!(html.contains("Content is redacted for you"));
    assert!(html.contains("<span class=\"tag\">Redacted</span>"));
    assert!(html.contains("[filtered "));
    assert!(
        html.contains(" \u{b7} <span class=\"alarm\">dangling</span>")
            || html.contains("\u{b7} dangling")
    );
    assert!(html.contains("<a href=\"/console/holds\">2 holds</a>"));
    assert!(html.contains("<a class=\"up\" href=\"/console\">Runs</a>"));
    // Every present slot of the fixture is replaced, in rows and details.
    for e in j.entries() {
        for c in e.event.slot_contents() {
            if let Some(v) = c.value() {
                let text = String::from_utf8_lossy(v.as_bytes());
                if text.len() >= 12 && !text.starts_with('{') && !text.starts_with('[') {
                    assert!(!html.contains(&*crate::html::esc(&text)), "{text}");
                }
            }
        }
    }
    // Structural fields are not slots, and stay.
    assert!(html.contains("<dt>tokens</dt><dd>1,830 in, 42 out</dd>"));
}

/// A run's page on Pragmatic Server says what is known of a run whose
/// last attempt has not ended: running (the lease is live) or crashed.
#[test]
fn the_end_of_a_run_says_what_is_known() {
    let mut j = refund_journal();
    // Drop the end: rebuild without the last note.
    let mut open = Journal::new(None);
    for e in &j.entries()[..13] {
        open.append_at(e.at, &e.branch, e.event.clone()).unwrap();
    }
    j = open;
    let report = j.audit();
    let local = render_run(&RunView::new("refund-20417", &j, &report));
    assert!(titles(&local).contains(
        &"No end yet · running, or crashed; refresh to see whether it continues".to_string()
    ));
    assert!(local.contains("No end yet: running, or crashed"));
    let server = |status: &'static str| {
        render_run(&RunView {
            server: Some(ServerRun {
                status,
                ..ServerRun::default()
            }),
            ..RunView::new("refund-20417", &j, &report)
        })
    };
    let running = server("active");
    assert!(titles(&running)
        .contains(&"Running · attempt 2 holds the lease · refresh to follow".to_string()));
    assert!(running.contains("<li class=\"row mk-breathe derived\">"));
    assert!(
        running.contains("Running \u{b7} attempt 2 since <span class=\"m\">00:29:57</span> UTC")
    );
    let idle = server("idle");
    assert!(titles(&idle).contains(&"No end: crashed · attempt 2 stopped after #12".to_string()));
    assert!(idle.contains("No end: attempt 2 crashed"));
    let dangling = server("dangling");
    assert!(titles(&dangling).contains(
        &"No end: crashed · attempt 2 stopped after #12 · an effect was left open".to_string()
    ));
}
