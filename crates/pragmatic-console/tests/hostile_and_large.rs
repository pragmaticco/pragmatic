//! The console against hostile journals and large ones: markup and terminal
//! escapes in every field stay inert, format 1 runs are shown in full, and
//! pages stay bounded however many entries or bytes a run holds.

use std::time::Instant;

use pragmatic::evidence::{verify, Bundle, NoTsaVerifier, Redact, TrustPolicy};
use pragmatic::journal::{note, EffectOutcome, Event, Journal, META, ROOT};
use pragmatic::Value;
use pragmatic_console::{
    render_csv, render_evidence, render_index_of, render_run, render_run_page, AnchorStatus,
    RunRow, RunView, PAGE_BYTES, PAGE_ENTRIES,
};

const X: &str = "\"'><script>alert(1)</script><img src=x onerror=alert(2)><!--\u{1b}[2J";

/// The tags the console writes.
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

fn j(x: &str) -> String {
    pragmatic::json::Json::String(x.into()).to_string()
}

/// Every string field and slot of every event kind carries the payload.
fn hostile() -> Journal {
    let mut jn = Journal::new(None);
    jn.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: format!(
                r#"{{"format":2,"labels":{{{x}:{x}}},"nonce":"00","run_id":"evil","sdk":{x},"sdk_version":{x}}}"#,
                x = j(X)
            ),
            payload: vec![Value::from(X).into()],
        },
    )
    .unwrap();
    jn.append(
        META,
        Event::Note {
            kind: "attempt.start".into(),
            data: format!(
                r#"{{"attempt":1,"host":{x},"mode":{x},"pid":{x},"principal":{x},"torn_bytes":0}}"#,
                x = j(X)
            ),
            payload: vec![],
        },
    )
    .unwrap();
    jn.append(
        ROOT,
        Event::Program {
            name: X.into(),
            hash: X.into(),
        },
    )
    .unwrap();
    jn.append(ROOT, Event::Marker { name: X.into() }).unwrap();
    jn.append(ROOT, Event::Clock { nanos: u64::MAX }).unwrap();
    let di = jn
        .append(
            ROOT,
            Event::DrawIntent {
                provenance: X.into(),
                parts: vec![
                    Value::from(format!(r#"{{"k":{x},{x}:[{x}]}}"#, x = j(X))).into(),
                    Value::from(format!(
                        r#"{{"source":{{"type":"base64","media_type":{x},"data":"QUJD"}}}}"#,
                        x = j(X)
                    ))
                    .into(),
                ],
            },
        )
        .unwrap();
    jn.append(
        ROOT,
        Event::DrawResult {
            intent: di,
            meta: format!(
                r#"{{"outcome":{x},"model":{x},"provider":{x},"stop_reason":{x},"error_kind":{x},"error_type":{x}}}"#,
                x = j(X)
            ),
            head: Value::from(X).into(),
            body: Value::new(vec![0xff, b'<', b's', 0x00]).into(),
        },
    )
    .unwrap();
    jn.append(
        ROOT,
        Event::ChannelRecv {
            channel: X.into(),
            value: Value::from(X).into(),
        },
    )
    .unwrap();
    let ei = jn
        .append(
            ROOT,
            Event::EffectIntent {
                name: X.into(),
                arg: Value::from(X).into(),
            },
        )
        .unwrap();
    jn.append(
        ROOT,
        Event::EffectResult {
            intent: ei,
            outcome: EffectOutcome::Failed,
            error_kind: X.into(),
            payload: Some(Value::from(X).into()),
        },
    )
    .unwrap();
    jn.append(
        ROOT,
        Event::Random {
            source: X.into(),
            args: format!("[{}]", j(X)),
            value: Value::from(X).into(),
        },
    )
    .unwrap();
    jn.append(
        ROOT,
        Event::Fork {
            base: 0,
            children: 2,
        },
    )
    .unwrap();
    jn.append(
        META,
        Event::Note {
            kind: X.into(),
            data: format!(r#"{{"a":{x}}}"#, x = j(X)),
            payload: vec![Value::from(X).into(), Value::from(X).into()],
        },
    )
    .unwrap();
    jn.append(
        META,
        Event::Note {
            kind: "attempt.end".into(),
            data: format!(
                r#"{{"attempt":1,"outcome":{x},"fault_kind":{x},"fresh":{x},"replayed":{x}}}"#,
                x = j(X)
            ),
            payload: vec![Value::from(X).into(), Value::from(X).into()],
        },
    )
    .unwrap();
    jn
}

fn assert_no_injection(html: &str) {
    for (i, _) in html.match_indices('<') {
        let rest = &html[i + 1..];
        assert!(
            OWN.iter().any(|t| rest.starts_with(t)),
            "unexpected markup at {i}: {:?}",
            &rest[..rest.len().min(60)]
        );
    }
    // The payload's quote must never close an attribute.
    assert!(!html.contains("\"'>"), "payload closed an attribute");
}

#[test]
fn payload_in_every_field_is_inert() {
    let jn = hostile();
    let report = jn.audit();
    let anchor = AnchorStatus {
        anchored_entries: 1,
        independent: false,
        operators: vec![X.into()],
        time: Some(X.into()),
        witnesses: vec![pragmatic_console::AnchorWitness {
            operator: X.into(),
            kind: X.into(),
            trust: pragmatic_console::WitnessTrust::Failed,
            root: Some(X.into()),
        }],
    };
    let nav = pragmatic_console::html::source_note(X, true);
    let frame = pragmatic_console::html::Frame {
        csp: pragmatic_console::html::SERVE_POLICY,
        fonts: pragmatic_console::html::Fonts::Served("/assets/"),
        home: Some(X),
        nav: &nav,
        footer: "",
    };
    let view = RunView {
        anchor: Some(&anchor),
        source: Some(X),
        frame: Some(&frame),
        exported: Some(X),
        ..RunView::new(X, &jn, &report)
    };
    assert_no_injection(&render_run(&view));
    // A later page, with links built from hostile text.
    let paged = RunView {
        from: 1,
        page_link: Some(X),
        ..view
    };
    assert_no_injection(&render_run(&paged));
    let rows = vec![
        RunRow::from_journal(X, &jn, &report).linked(X),
        RunRow::unreadable(X, X),
    ];
    assert_no_injection(&render_index_of(&rows, Some(X), Some(&frame)));
    assert_no_injection(&render_index_of(&rows, Some(X), None));
    let mut bundle = Bundle::local(&jn.to_bytes(), "evil", &Redact::None).unwrap();
    bundle.generator = X.into();
    bundle.requested_by = X.into();
    bundle.generated_at = X.into();
    bundle.redaction.mode = X.into();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    assert_no_injection(&render_evidence(&bundle, &report));
    // Broken journal: the records table path.
    let mut broken = bundle.clone();
    broken.journal.bytes.truncate(40);
    let report = verify(&broken, &TrustPolicy::default(), &NoTsaVerifier);
    assert_no_injection(&render_evidence(&broken, &report));
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let csv = render_csv(&bundle, &report);
    assert!(csv.starts_with("verdict,anchored,cursor,"));
    assert!(
        csv.contains("\"'=") || !csv.contains(",\"="),
        "formulas are defused"
    );
}

/// Format 1 records commits, not results: the facts count them.
#[test]
fn format_1_facts_count_committed_effects() {
    use pragmatic::journal_v1;
    let dir = std::env::temp_dir().join(format!(
        "pragmatic-review-v1-{}-{}",
        std::process::id(),
        pragmatic::journal::system_clock()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("legacy.journal");
    let mut v1 = journal_v1::Journal::create(&path).unwrap();
    for i in 0..3 {
        v1.append(journal_v1::Event::EffectIntent {
            name: format!("e{i}"),
            arg: "a".into(),
        })
        .unwrap();
        v1.append(journal_v1::Event::EffectCommit {
            name: format!("e{i}"),
            result: "r".into(),
        })
        .unwrap();
    }
    v1.sync().unwrap();
    drop(v1);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let jn = Journal::parse(&bytes, None).unwrap().journal;
    let report = jn.audit();
    let html = render_run(&RunView::new("legacy", &jn, &report));
    assert!(
        html.contains("<dt>effects</dt><dd>3 ok \u{b7} 0 written off \u{b7} format 1 records no failures</dd>"),
        "format 1 page under-reports committed effects"
    );
    assert!(
        html.contains(">3</span> effects"),
        "the facts count them too"
    );
}

/// Format 1 values are shown as slots are: in full up to 64 KiB, with their
/// newlines, each in its own block.
#[test]
fn format_1_export_shows_full_values() {
    use pragmatic::journal_v1;
    let dir = std::env::temp_dir().join(format!(
        "pragmatic-review-v1b-{}-{}",
        std::process::id(),
        pragmatic::journal::system_clock()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("legacy.journal");
    let mut v1 = journal_v1::Journal::create(&path).unwrap();
    let long = format!("line one\nline two\n{}TAIL-MARKER", "x".repeat(5000));
    v1.append(journal_v1::Event::OracleDraw {
        prompt: "p".into(),
        outcome: long.as_str().into(),
        provenance: "m".into(),
    })
    .unwrap();
    v1.sync().unwrap();
    drop(v1);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let jn = Journal::parse(&bytes, None).unwrap().journal;
    let report = jn.audit();
    let html = render_run(&RunView::new("legacy", &jn, &report));
    assert!(
        html.contains("TAIL-MARKER"),
        "format 1 outcome truncated at 4096 chars"
    );
    assert!(html.contains("line one\nline two"), "newlines are kept");
    assert!(html.contains(">outcome \u{b7} "));
}

fn big_journal(n: usize) -> Journal {
    let mut jn = Journal::new(None);
    jn.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: r#"{"format":2,"labels":{},"nonce":"00","run_id":"big","sdk":"x","sdk_version":"0"}"#
                .into(),
            payload: vec![],
        },
    )
    .unwrap();
    let mut i = 1;
    while i < n {
        let di = jn
            .append(
                ROOT,
                Event::DrawIntent {
                    provenance: "m".into(),
                    parts: vec![Value::from(format!(
                        r#"{{"messages":[{{"role":"user","content":"question {i} about the refund"}}]}}"#
                    ))
                    .into()],
                },
            )
            .unwrap();
        jn.append(
            ROOT,
            Event::DrawResult {
                intent: di,
                meta:
                    r#"{"outcome":"ok","model":"m","usage":{"input_tokens":10,"output_tokens":5}}"#
                        .into(),
                head: Value::from("{}").into(),
                body: Value::from(format!("answer {i}")).into(),
            },
        )
        .unwrap();
        i += 2;
    }
    jn
}

/// A journal whose `attempt.end` notes name no started attempt (hostile or
/// broken) renders in time linear in its notes.
#[test]
fn attempt_ends_are_matched_in_linear_time() {
    let mut jn = Journal::new(None);
    jn.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data:
                r#"{"format":2,"labels":{},"nonce":"00","run_id":"q","sdk":"x","sdk_version":"0"}"#
                    .into(),
            payload: vec![],
        },
    )
    .unwrap();
    let n = 20_000u64;
    for a in 0..n {
        jn.append(
            META,
            Event::Note {
                kind: "attempt.start".into(),
                data: format!(r#"{{"attempt":{a}}}"#),
                payload: vec![],
            },
        )
        .unwrap();
    }
    for a in 0..n {
        jn.append(
            META,
            Event::Note {
                kind: "attempt.end".into(),
                data: format!(r#"{{"attempt":{}}}"#, a + n),
                payload: vec![],
            },
        )
        .unwrap();
    }
    let report = jn.audit();
    let t = Instant::now();
    let html = render_run(&RunView::new("q", &jn, &report));
    let took = t.elapsed();
    eprintln!(
        "40k attempt notes: render {took:?}, {} MiB",
        html.len() >> 20
    );
    assert!(took.as_secs() < 5, "render took {took:?}");
}

/// A run of many small entries is shown a page at a time, and every page
/// links on until the last.
#[test]
fn long_timelines_are_paged() {
    let jn = big_journal(2 * PAGE_ENTRIES + 7);
    let report = jn.audit();
    let mut view = RunView::new("big", &jn, &report);
    view.page_link = Some("/run/big?from=");
    let first = render_run_page(&view);
    assert_eq!(first.next, Some(PAGE_ENTRIES as u64));
    assert!(first.html.contains("<span id=\"c0\"></span>"));
    assert!(!first
        .html
        .contains(&format!("<span id=\"c{PAGE_ENTRIES}\"></span>")));
    assert!(first.html.contains(&format!(
        "<a class=\"go\" href=\"/run/big?from={PAGE_ENTRIES}\">Next page</a>"
    )));
    let mut seen = PAGE_ENTRIES as u64;
    let mut from = first.next;
    while let Some(f) = from {
        view.from = f;
        let page = render_run_page(&view);
        assert!(page.html.contains(&format!("<span id=\"c{f}\"></span>")));
        assert!(page
            .html
            .contains("<a href=\"/run/big?from=0\">First page</a>"));
        seen = page.next.unwrap_or(jn.len());
        from = page.next;
    }
    assert_eq!(seen, jn.len());
    // An exported page says where the next one starts.
    view.page_link = None;
    view.from = 0;
    assert!(render_run(&view).contains(&format!(
        "The next file: <span class=\"m\">pragmatic export big --from {PAGE_ENTRIES}</span>"
    )));
}

/// Large slots end a page early, so a page stays within its budget
/// whatever the slots hold.
#[test]
fn pages_keep_to_their_budget() {
    let mut jn = Journal::new(None);
    jn.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data:
                r#"{"format":2,"labels":{},"nonce":"00","run_id":"r","sdk":"x","sdk_version":"0"}"#
                    .into(),
            payload: vec![],
        },
    )
    .unwrap();
    // 400 receives of 60 KiB of distinct text each: 24 MiB of content.
    for i in 0..400 {
        let text = format!("{i:08} {}", "x".repeat(60 << 10));
        jn.append(
            ROOT,
            Event::ChannelRecv {
                channel: "in".into(),
                value: Value::from(text).into(),
            },
        )
        .unwrap();
    }
    let report = jn.audit();
    let view = RunView::new("r", &jn, &report);
    let page = render_run_page(&view);
    let next = page.next.expect("the content does not fit one page");
    assert!(next > 100 && next < 400, "ends at {next}");
    // The budget, plus the facts, attempts and verification around it.
    assert!(
        page.html.len() < PAGE_BYTES + (1 << 20),
        "{}",
        page.html.len()
    );
}
