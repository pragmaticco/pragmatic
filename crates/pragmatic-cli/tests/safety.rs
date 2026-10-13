//! The CLI against hostile inputs: journal content and file names that try
//! to drive the terminal, attachments that try to slip past redaction,
//! web pages that try to read the local console, bundles that ship links
//! and FIFOs, and an `openssl` that cannot do the job. Each test is an
//! attack (or a mistake) and the behavior that defeats it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use pragmatic::encoding::base64_encode;
use pragmatic::evidence::Bundle;
use pragmatic::journal::{note, Event, Journal, META, ROOT};
use pragmatic::{Ctx, DirBackend, Fault, Runtime, SeededOracle, Value};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pragmatic")
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pragmatic-review-{name}-{}-{}",
        std::process::id(),
        pragmatic::journal::system_clock()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pragmatic(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("PRAGMATIC_JOURNAL_KEY")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_start(run_id: &str) -> Event {
    Event::Note {
        kind: note::RUN_START.into(),
        data: format!(
            r#"{{"format":2,"labels":{{}},"nonce":"00","run_id":{},"sdk":"rust","sdk_version":"0"}}"#,
            pragmatic::json::Json::String(run_id.into())
        ),
        payload: vec![],
    }
}

/// Write `j` as the journal file of `as_run` in `dir`.
fn install(dir: &Path, as_run: &str, j: &Journal) {
    let path = DirBackend::new(dir).unwrap().journal_path(as_run);
    std::fs::write(path, j.to_bytes()).unwrap();
}

const ESC: char = '\u{1b}';

// ---------------------------------------------------------------------------
// Terminal injection
// ---------------------------------------------------------------------------

/// A draw result's `meta.outcome` is journal content: `show` prints it
/// escaped.
#[test]
fn show_escapes_draw_outcomes() {
    let dir = temp("label");
    let mut j = Journal::new(None);
    j.append(META, run_start("r1")).unwrap();
    let intent = j
        .append(
            ROOT,
            Event::DrawIntent {
                provenance: "p".into(),
                parts: vec![Value::from("hi").into()],
            },
        )
        .unwrap();
    j.append(
        ROOT,
        Event::DrawResult {
            intent,
            // OSC 0 retitles the terminal; CSI 2J clears the screen.
            meta: r#"{"outcome":"ok\u001b]0;pwned\u0007\u001b[2J"}"#.into(),
            head: Value::from("{}").into(),
            body: Value::from("ok").into(),
        },
    )
    .unwrap();
    install(&dir, "r1", &j);
    let o = pragmatic(&["show", "r1", "--dir", dir.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let out = String::from_utf8_lossy(&o.stdout);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        !out.contains(ESC),
        "raw ESC reached the terminal via the draw label: {out:?}"
    );
}

/// The error for a run whose file holds another run's journal quotes the
/// journal's own run id (`run id collides with '<id>'`): `show` and
/// `verify` print it escaped.
#[test]
fn colliding_run_ids_are_printed_escaped() {
    let dir = temp("collide");
    let mut j = Journal::new(None);
    j.append(META, run_start("x\u{1b}]0;pwned\u{7}\u{1b}[2J"))
        .unwrap();
    install(&dir, "victim", &j);
    let d = dir.to_str().unwrap();
    let show = pragmatic(&["show", "victim", "--dir", d]);
    let verify = pragmatic(&["verify", "victim", "--dir", d]);
    std::fs::remove_dir_all(&dir).unwrap();
    let show_err = String::from_utf8_lossy(&show.stderr).into_owned();
    let verify_out = String::from_utf8_lossy(&verify.stdout).into_owned();
    assert!(!show_err.contains(ESC), "show stderr: {show_err:?}");
    assert!(!verify_out.contains(ESC), "verify stdout: {verify_out:?}");
}

// ---------------------------------------------------------------------------
// Binary handling and redaction
// ---------------------------------------------------------------------------

/// `--redact binary` withholds every slot holding an attachment (design
/// 4.10), whatever its size: a request with a 13 MiB image (Anthropic
/// allows 32 MB requests) is not shipped in the bundle.
#[test]
fn redact_binary_withholds_attachments_of_any_size() {
    let dir = temp("bigbin");
    let image = vec![0x42u8; 13 << 20]; // 13 MiB decoded, ~17.3 MiB base64
    let b64 = base64_encode(&image);
    let request = format!(
        r#"{{"messages":[{{"role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}"}}}}]}}]}}"#
    );
    assert!(request.len() > 16 << 20);
    let mut j = Journal::new(None);
    j.append(META, run_start("big")).unwrap();
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "anthropic".into(),
            parts: vec![Value::from(request.as_str()).into()],
        },
    )
    .unwrap();
    install(&dir, "big", &j);
    let out = dir.join("b.json");
    let o = pragmatic(&[
        "evidence",
        "big",
        "--dir",
        dir.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--redact",
        "binary",
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let bundle = Bundle::from_json(&std::fs::read(&out).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        bundle.redacted_slots.contains(&(1, 0)),
        "the 13 MiB image slot was not withheld under --redact binary: {:?}",
        bundle.redacted_slots
    );
}

/// The same with a small attachment nested deeper than strict JSON's
/// 64-level cap.
#[test]
fn redact_binary_withholds_deeply_nested_attachments() {
    let dir = temp("deepbin");
    let b64 = base64_encode(b"\x89PNG\r\n\x1a\nsecret scan of a passport");
    let mut doc = format!(r#"{{"type":"base64","media_type":"image/png","data":"{b64}"}}"#);
    for _ in 0..70 {
        doc = format!("[{doc}]");
    }
    let mut j = Journal::new(None);
    j.append(META, run_start("deep")).unwrap();
    j.append(
        ROOT,
        Event::EffectIntent {
            name: "upload".into(),
            arg: Value::from(doc.as_str()).into(),
        },
    )
    .unwrap();
    install(&dir, "deep", &j);
    let out = dir.join("b.json");
    let o = pragmatic(&[
        "evidence",
        "deep",
        "--dir",
        dir.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--redact",
        "binary",
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let bundle = Bundle::from_json(&std::fs::read(&out).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        bundle.redacted_slots.contains(&(1, 0)),
        "nested attachment not withheld: {:?}",
        bundle.redacted_slots
    );
}

// ---------------------------------------------------------------------------
// Read-only commands on torn journals
// ---------------------------------------------------------------------------

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the refund for jane@example.com")?;
    ctx.effect("notify", plan, |arg| Ok(Value::from(format!("sent {arg}"))))
}

fn snapshot_dir(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            let p = e.path();
            let m = std::fs::metadata(&p).unwrap();
            (
                p.clone(),
                std::fs::read(&p).unwrap_or_default(),
                m.modified().unwrap(),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http_get(port: u16, path: &str, host: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            return out;
        }
        assert!(Instant::now() < deadline, "serve did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every read command (including export, evidence, serve and the evidence
/// commands) leaves a directory with a torn journal byte-for-byte as it was.
#[test]
fn read_commands_leave_torn_journals_untouched() {
    let dir = temp("torn");
    let d = dir.to_str().unwrap().to_string();
    let rt = Runtime::on_dir(&dir, SeededOracle::new(3)).unwrap();
    rt.run("t1", agent).unwrap();
    let path = DirBackend::new(&dir).unwrap().journal_path("t1");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(&[0x40, 0, 0, 0, 1, 2, 3]).unwrap(); // a torn frame
    drop(f);
    let before = snapshot_dir(&dir);
    let out = temp("torn-out");
    let o = out.to_str().unwrap().to_string();
    let page = format!("{o}/p.html");
    let bundle = format!("{o}/b.json");
    for args in [
        vec!["runs", "--dir", &d],
        vec!["show", "t1", "--dir", &d],
        vec!["verify", "t1", "--dir", &d],
        vec!["verify", "--all", "--dir", &d],
        vec!["export", "t1", "--dir", &d, "-o", &page],
        vec!["evidence", "t1", "--dir", &d, "-o", &bundle],
    ] {
        let r = pragmatic(&args);
        assert!(
            r.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
    }
    let port = free_port();
    let mut child = Command::new(bin())
        .args(["serve", "--dir", &d, "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let index = http_get(port, "/", "127.0.0.1");
    let run = http_get(port, "/run/t1", "127.0.0.1");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(index.starts_with("HTTP/1.1 200") && run.starts_with("HTTP/1.1 200"));
    let after = snapshot_dir(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&out).unwrap();
    assert_eq!(
        before, after,
        "a read command wrote to the journal directory"
    );
}

// ---------------------------------------------------------------------------
// serve: DNS rebinding
// ---------------------------------------------------------------------------

/// A web page the user visits can rebind its own name to 127.0.0.1 and
/// read the console same-origin (prompts, personal data, decrypted keyed
/// journals): `serve` refuses Host values other than its own.
#[test]
fn serve_refuses_foreign_host_headers() {
    let dir = temp("rebind");
    let d = dir.to_str().unwrap().to_string();
    let rt = Runtime::on_dir(&dir, SeededOracle::new(3)).unwrap();
    rt.run("t1", agent).unwrap();
    let port = free_port();
    let mut child = Command::new(bin())
        .args(["serve", "--dir", &d, "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let page = http_get(port, "/run/t1", &format!("attacker.example:{port}"));
    let own = http_get(port, "/run/t1", &format!("localhost:{port}"));
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        !(page.starts_with("HTTP/1.1 200") && page.contains("jane@example.com")),
        "served run content to Host: attacker.example"
    );
    assert!(page.starts_with("HTTP/1.1 421"), "{page}");
    assert!(own.starts_with("HTTP/1.1 200") && own.contains("jane@example.com"));
}

// ---------------------------------------------------------------------------
// erase and the checkout lock
// ---------------------------------------------------------------------------

/// `erase` refuses while another writer holds the run.
#[test]
fn erase_refuses_while_the_run_is_checked_out() {
    let dir = temp("eraselock");
    let d = dir.to_str().unwrap().to_string();
    let rt = Runtime::on_dir(&dir, SeededOracle::new(3)).unwrap();
    rt.run("t1", agent).unwrap();
    let backend = DirBackend::new(&dir).unwrap();
    let held = pragmatic::Backend::checkout(&backend, "t1", false, None).unwrap();
    let before = std::fs::read(backend.journal_path("t1")).unwrap();
    let o = pragmatic(&[
        "erase",
        "t1",
        "--match",
        "jane@example.com",
        "--reason-code",
        "gdpr",
        "--dir",
        &d,
    ]);
    let after = std::fs::read(backend.journal_path("t1")).unwrap();
    drop(held);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_ne!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(before, after);
}

// ---------------------------------------------------------------------------
// Large journals
// ---------------------------------------------------------------------------

/// A long run is exported a page at a time: the page is bounded, and the
/// command says how to get the next one.
#[test]
fn export_of_a_long_run_is_paged() {
    let dir = temp("long");
    let mut j = Journal::new(None);
    j.append(META, run_start("big")).unwrap();
    for i in 1..12_000 {
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "in".into(),
                value: Value::from(format!("message {i}")).into(),
            },
        )
        .unwrap();
    }
    install(&dir, "big", &j);
    let d = dir.to_str().unwrap();
    let page = dir.join("p.html");
    let o = pragmatic(&["export", "big", "--dir", d, "-o", page.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let html = std::fs::read_to_string(&page).unwrap();
    let second = dir.join("p2.html");
    let o2 = pragmatic(&[
        "export",
        "big",
        "--dir",
        d,
        "--from",
        "5000",
        "-o",
        second.to_str().unwrap(),
    ]);
    let html2 = std::fs::read_to_string(&second).unwrap();
    let past = pragmatic(&["export", "big", "--dir", d, "--from", "12000"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(out.contains("--from 5000"), "{out}");
    assert!(html.contains("id=\"c4999\"") && !html.contains("id=\"c5000\""));
    assert!(html.len() < 16 << 20, "{} bytes", html.len());
    assert_eq!(o2.status.code(), Some(0));
    assert!(html2.contains("id=\"c5000\"") && !html2.contains("id=\"c4999\""));
    assert_eq!(past.status.code(), Some(64));
}

/// `runs` lists any format 1 file by its stem; a stem the old safe-name
/// rule would change cannot be opened, and the error, which quotes the
/// file name, is printed escaped.
#[test]
fn runs_escapes_format_1_file_names() {
    let dir = temp("v1name");
    // An empty format 1 journal: magic and version 1.
    let mut bytes = pragmatic::journal::MAGIC.to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    std::fs::write(dir.join("x\u{1b}]0;pwned\u{7}.journal"), bytes).unwrap();
    let o = pragmatic(&["runs", "--dir", dir.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!out.contains(ESC), "runs stdout: {out:?}");
}

// ---------------------------------------------------------------------------
// TSA checks with the openssl the system ships
// ---------------------------------------------------------------------------

/// macOS ships LibreSSL as /usr/bin/openssl; its `ts -verify` has no
/// `-attime`, prints usage and exits non-zero. That says nothing about the
/// token: the CLI does not use such a binary, says why, and never reports
/// the token as rejected by the pinned roots.
#[test]
fn libressl_is_never_used_to_check_tokens() {
    let libre = Command::new("/usr/bin/openssl")
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("LibreSSL"))
        .unwrap_or(false);
    if !libre {
        eprintln!("skipped: /usr/bin/openssl is not LibreSSL");
        return;
    }
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pragmatic/tests/fixtures/evidence");
    let p = |n: &str| f.join(n).display().to_string();
    let o = Command::new(bin())
        .args([
            "verify-evidence".to_string(),
            p("bundle.json"),
            "--tsa-roots".into(),
            format!("fixture-tsa-a={}", p("trust/tsa-a-root.pem")),
            "--tsa-roots".into(),
            format!("fixture-tsa-b={}", p("trust/tsa-b-root.pem")),
            "--witness-key".into(),
            format!("fixture-witness={}", p("trust/witness.vkey")),
            "--log-key".into(),
            p("trust/log.vkey"),
        ])
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        !out.contains("does not verify against any pinned root (usage:)"),
        "an openssl that cannot run the check is reported as a rejected token:\n{out}"
    );
    assert!(out.contains("cannot check time-stamp tokens"), "{out}");
    assert!(
        out.contains("tsa_unchecked") && !out.contains("tsa_untrusted"),
        "{out}"
    );
    // Required with --openssl, it is a usage error naming the binary.
    let o = Command::new(bin())
        .args([
            "verify-evidence".to_string(),
            p("bundle.json"),
            "--openssl".into(),
        ])
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&o.stderr).contains("/usr/bin/openssl"));
}

// ---------------------------------------------------------------------------
// render-evidence --format csv on a bundle that fails verification
// ---------------------------------------------------------------------------

/// A bundle whose `records` were edited after the fact (design 9 "an
/// altered records section") fails verification, and `render-evidence
/// --format csv` refuses to put it in a spreadsheet, exiting with the
/// verdict's code. (The reviewer's version of this test asserted, as a
/// precondition, that the forged text reached the CSV; that is the defect,
/// so the precondition is now the assertion.)
#[test]
fn csv_of_a_forged_bundle_is_refused() {
    let dir = temp("csvforged");
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pragmatic/tests/fixtures/evidence/bundle.json");
    let mut b = Bundle::from_json(&std::fs::read(&f).unwrap()).unwrap();
    b.signature = None;
    let slot = b
        .records
        .iter_mut()
        .flat_map(|r| r.slots.iter_mut())
        .find(|s| s.text.is_some())
        .unwrap();
    slot.text = Some("FORGED: refund approved by the manager".into());
    slot.len = Some(slot.text.as_ref().unwrap().len() as u64);
    let bundle = dir.join("forged.json");
    std::fs::write(&bundle, b.to_json()).unwrap();
    let v = pragmatic(&["verify-evidence", bundle.to_str().unwrap(), "--no-openssl"]);
    assert_eq!(
        v.status.code(),
        Some(1),
        "the forged bundle fails verification"
    );
    let csv = dir.join("out.csv");
    let o = pragmatic(&[
        "render-evidence",
        bundle.to_str().unwrap(),
        "--format",
        "csv",
        "-o",
        csv.to_str().unwrap(),
        "--no-openssl",
    ]);
    let written = csv.exists();
    let html = dir.join("out.html");
    let page = pragmatic(&[
        "render-evidence",
        bundle.to_str().unwrap(),
        "--format",
        "html",
        "-o",
        html.to_str().unwrap(),
        "--no-openssl",
    ]);
    let page_text = std::fs::read_to_string(&html).unwrap_or_default();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(!written, "no CSV is written for a bundle that fails");
    assert!(String::from_utf8_lossy(&o.stderr).contains("fails verification"));
    // The page leads with the failure and shows the journal, not the edit.
    assert_eq!(page.status.code(), Some(1));
    assert!(page_text.contains("FAILED \u{b7} exit 1"));
    assert!(!page_text.contains("FORGED"));
}

/// `render-evidence` writes next to the bundle by default; a link planted
/// there by whoever sent the bundle is never written through.
#[cfg(unix)]
#[test]
fn render_evidence_never_writes_through_a_planted_link() {
    let dir = temp("planted");
    let inbox = dir.join("inbox");
    std::fs::create_dir(&inbox).unwrap();
    let victim = dir.join("victim.txt");
    std::fs::write(&victim, "the auditor's own file\n").unwrap();
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pragmatic/tests/fixtures/evidence/local.json");
    std::fs::copy(&f, inbox.join("x.evidence.json")).unwrap();
    std::os::unix::fs::symlink(&victim, inbox.join("x.evidence.csv")).unwrap();
    let o = pragmatic(&[
        "render-evidence",
        inbox.join("x.evidence.json").to_str().unwrap(),
        "--format",
        "csv",
        "--no-openssl",
    ]);
    let after = std::fs::read_to_string(&victim).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(after, "the auditor's own file\n");
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("symbolic link"));
}

/// Malformed or unreadable trust inputs are usage errors (exit 64), never
/// the code of a FAILED bundle (design 7: usage errors are distinct from
/// every outcome).
#[test]
fn malformed_trust_flags_are_usage_errors() {
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pragmatic/tests/fixtures/evidence");
    let bundle = fx.join("bundle.json").display().to_string();
    let witness_vkey = std::fs::read_to_string(fx.join("trust/witness.vkey")).unwrap();
    let cases: Vec<Vec<String>> = vec![
        vec!["--witness-key".into(), "garbage".into()],
        vec!["--witness-key".into(), "op=nothex".into()],
        vec!["--tsa-roots".into(), "/nonexistent.pem".into()],
        vec!["--log-key".into(), witness_vkey.trim().into()],
        vec!["--log-key".into(), "/nonexistent.vkey".into()],
        vec!["--log".into(), "/nonexistent.json".into()],
        vec!["--witness-log".into(), bundle.clone()],
    ];
    for extra in cases {
        let mut args = vec!["verify-evidence".to_string(), bundle.clone()];
        args.extend(extra.iter().cloned());
        args.push("--no-openssl".into());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = pragmatic(&refs);
        assert_eq!(
            o.status.code(),
            Some(64),
            "{extra:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    let o = pragmatic(&["verify-evidence", "/nonexistent-bundle.json"]);
    assert_eq!(o.status.code(), Some(64));
}

// ---------------------------------------------------------------------------
// Directory bundles from an untrusted sender
// ---------------------------------------------------------------------------

/// A directory bundle is a directory the auditor received (a tarball keeps
/// symlinks and FIFOs). A FIFO would block a reader forever and a link to
/// `/dev/zero` would exhaust memory, so neither is read: the bundle fails
/// with `bundle_file`.
#[cfg(unix)]
#[test]
fn directory_bundle_files_must_be_regular_files() {
    let dir = temp("fifo");
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pragmatic/tests/fixtures/evidence/bundle.json");
    let mut b = Bundle::from_json(&std::fs::read(&f).unwrap()).unwrap();
    let _ = b.into_directory_form();
    let bdir = dir.join("bundle");
    std::fs::create_dir(&bdir).unwrap();
    std::fs::write(
        bdir.join(pragmatic::evidence::DIRECTORY_BUNDLE_FILE),
        b.to_json(),
    )
    .unwrap();
    let fifo = bdir.join(pragmatic::evidence::DIRECTORY_JOURNAL_FILE);
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut child = Command::new(bin())
        .args(["verify-evidence", bdir.to_str().unwrap(), "--no-openssl"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut finished = false;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            finished = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !finished {
        child.kill().unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    // A link to /dev/zero, and a link to a real journal: neither is read.
    std::fs::remove_file(&fifo).unwrap();
    std::os::unix::fs::symlink("/dev/zero", &fifo).unwrap();
    let zero = pragmatic(&["verify-evidence", bdir.to_str().unwrap(), "--no-openssl"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        finished,
        "verify-evidence blocked on a FIFO in the bundle directory"
    );
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("bundle_file"), "{stdout}");
    assert_eq!(zero.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&zero.stdout).contains("bundle_file"));
}
