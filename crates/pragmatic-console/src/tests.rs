//! Rendering the evidence fixtures (`crates/pragmatic/tests/fixtures/
//! evidence`), hostile content, and format 1 journals.

use std::path::PathBuf;

use pragmatic::evidence::{verify, Bundle, NoTsaVerifier, TrustPolicy};
use pragmatic::journal::{note, Event, Journal, META, ROOT};
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

/// No element the page did not write itself: every `<` in the output opens
/// one of the tags this crate uses.
fn assert_only_own_markup(html: &str) {
    const OWN: &[&str] = &[
        "!doctype", "html", "/html", "head", "/head", "meta", "title", "/title", "link", "style",
        "/style", "body", "/body", "div", "/div", "span", "/span", "img", "a ", "/a", "b>", "b ",
        "/b", "i>", "/i", "h2", "/h2", "p ", "p>", "/p", "pre", "/pre", "table", "/table", "tr",
        "/tr", "th", "/th", "td", "/td", "details", "/details", "summary", "/summary",
    ];
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
}

#[test]
fn format_2_runs_render_fully() {
    let j = fixture_journal();
    let html = run_page(&j);
    assert_only_own_markup(&html);
    // Every entry has a row with an anchor.
    for c in 0..j.len() {
        assert!(html.contains(&format!("id=\"c{c}\"")), "row {c}");
    }
    // Attempts, from their notes.
    assert!(html.contains("<h2>attempts</h2>"));
    assert!(html.contains(">resume<"));
    // Nested lanes: entries on branch 0 and 1 sit one rail deep.
    assert!(html.contains("<span class=\"lane\"><i></i>0</span>"));
    assert!(html.contains("<span class=\"lane\"><i></i>1</span>"));
    assert!(html.contains("<span class=\"lane\">meta</span>"));
    // Intents carry their results' outcomes; results link back.
    for status in ["ok", "partial", "error", "failed", "compensated"] {
        assert!(html.contains(&format!(">{status}</span>")), "{status}");
    }
    assert!(html.contains("claude-sonnet-4-5, 1830 in / 42 out, 812 ms"));
    // Slot states.
    assert!(html.contains("erased: the content and its salt were dropped"));
    assert!(html.contains("withheld from this bundle"));
    assert!(html.contains("deduplicated: the same content as <a href=\"#c4\">#4</a> slot 1"));
    // Binary content is summarized, never inlined.
    assert!(html.contains("binary at <b>/content/0/source/data</b>: image/png, 70 bytes"));
    assert!(
        !html.contains("CAYAAAAfFcSJ"),
        "the fixture image is not inlined"
    );
    assert!(html.contains("binary content, not shown: application/octet-stream, 7 bytes"));
    // Notes by kind, and times from `at`.
    assert!(html.contains("recovery decided retry for refund"));
    assert!(html.contains("erased 1 slot(s) [3:0] by tok_admin_privacy (authenticated)"));
    assert!(html.contains("2026-10-13T09:00:00.25Z"));
    assert!(html.contains("chain <b>verified</b>"));
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
    };
    let view = RunView {
        anchor: Some(&status),
        ..RunView::new("r", &j, &report)
    };
    let html = render_run(&view);
    assert!(html.contains("independently anchored"));
    assert!(html.contains("<b>20</b> of 32 entries by digicert, sectigo"));
}

/// A journal whose every field and slot carries markup.
fn hostile_journal() -> Journal {
    let x = "<script>alert('x')</script><img src=x onerror=alert(1)>\u{1b}[2J";
    let mut j = Journal::new(None);
    let start = format!(
        r#"{{"format":2,"labels":{{"k":"{0}"}},"nonce":"00","run_id":"evil","sdk":"{0}","sdk_version":"0"}}"#,
        "<b>x</b>"
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
            body: Value::from(x).into(),
        },
    )
    .unwrap();
    j.append(
        META,
        Event::Note {
            kind: x.into(),
            data: r#"{"a":"</pre><script>"}"#.into(),
            payload: vec![],
        },
    )
    .unwrap();
    j
}

#[test]
fn hostile_content_is_escaped_everywhere() {
    let j = hostile_journal();
    let report = j.audit();
    let mut view = RunView::new("<script>", &j, &report);
    view.source = Some("<img src=x>");
    view.home = Some("\"><script>");
    let html = render_run(&view);
    assert_only_own_markup(&html);
    assert!(html.contains("&lt;script&gt;"));

    let rows = vec![
        RunRow::from_journal("<b>run</b>", &j, &report).linked("/run/\"><script>"),
        RunRow::unreadable("<x>", "<script>bad</script>"),
    ];
    let index = render_index_of(&rows, Some("<dir>"), Some("/"));
    assert_only_own_markup(&index);

    let bundle = Bundle::local(&j.to_bytes(), "evil", &pragmatic::evidence::Redact::None).unwrap();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let page = render_evidence(&bundle, &report);
    assert_only_own_markup(&page);
}

#[test]
fn evidence_pages_lead_with_the_verdict() {
    let bundle = fixture_bundle();
    let report = verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    let html = render_evidence(&bundle, &report);
    assert_only_own_markup(&html);
    assert!(html.contains("UNANCHORED \u{b7} exit 3"));
    assert!(html.contains("operator-controlled"));
    assert!(html.contains("self-asserted"));
    assert!(html.contains("tsa_unchecked") || html.contains("tsa_untrusted"));
    assert!(html.contains("<h2>timeline</h2>"));
    assert!(html.contains("id=\"c31\""));
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
    let csv = render_csv(&bundle);
    let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1 + bundle.records.len());
    assert!(lines[0].starts_with("cursor,at_ns,at_utc"));
    assert!(lines[1].starts_with("\"0\",\""));
    assert!(csv.contains("[erased]"));
    assert!(csv.contains("[withheld]"));
    assert!(csv.contains("[binary media_type=application/octet-stream bytes=7"));
    assert!(!csv.contains("CAYAAAAfFcSJ"));
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
    assert!(html.contains("read-only in 0.6"));
    assert!(html.contains("oracle.draw"));
    assert!(html.contains("plan &lt;b&gt;"));
    assert!(html.contains("1 open intent(s)"));
}

#[test]
fn index_lists_runs() {
    let j = fixture_journal();
    let report = j.audit();
    let rows = vec![RunRow::from_journal("a", &j, &report).linked("/run/a")];
    let html = render_index(&rows);
    assert_only_own_markup(&html);
    assert!(html.contains("<a href=\"/run/a\">a</a>"));
    assert!(html.contains("chains <b>1/1</b> verified"));
    assert_eq!(rows[0].attempts, 2);
    assert_eq!(rows[0].last_outcome.as_deref(), Some("ok"));
    assert!(render_index(&[]).contains("no runs yet"));
}
