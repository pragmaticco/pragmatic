//! The `pragmatic` binary end to end: journal commands on a seeded
//! directory, erasure, local evidence, and `verify-evidence` against the
//! anchored fixtures in `crates/pragmatic/tests/fixtures/evidence` with
//! real OpenSSL, including the adversarial set of design section 9. Tests
//! that need `openssl` say so and skip when it is not on `PATH`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use pragmatic::evidence::{Bundle, Redact, Witness};
use pragmatic::journal::{EraseSelector, ErasureNote, Journal};
use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pragmatic")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pragmatic/tests/fixtures/evidence")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).display().to_string()
}

/// A fresh directory for one test.
fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pragmatic-cli-{name}-{}-{}",
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

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn openssl_on_path() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|d| d.join("openssl").is_file())
}

/// Skip a test that needs OpenSSL, saying so.
macro_rules! needs_openssl {
    () => {
        if !openssl_on_path() {
            eprintln!("skipped: openssl is not on PATH");
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// A seeded journal directory
// ---------------------------------------------------------------------------

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the refund for jane@example.com")?;
    let picks = ctx.parallel(2, |i, c| c.oracle(format!("option {i} of {plan}")))?;
    let t = ctx.now()?;
    ctx.effect("notify", format!("{} options @{t}", picks.len()), |arg| {
        Ok(Value::from(format!("sent {arg}")))
    })
}

fn seeded(name: &str) -> PathBuf {
    let dir = temp(name);
    let rt = Runtime::on_dir(&dir, SeededOracle::new(7)).unwrap();
    rt.run("refund-1", agent).unwrap();
    rt.run("refund-2", agent).unwrap();
    dir
}

fn journal_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            let p = e.path();
            let meta = std::fs::metadata(&p).unwrap();
            (
                p.clone(),
                std::fs::read(&p).unwrap(),
                meta.modified().unwrap(),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn journal_commands_read_format_2_runs() {
    let dir = seeded("journal");
    let d = dir.to_str().unwrap();
    let o = pragmatic(&["runs", "--dir", d]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("refund-1") && stdout(&o).contains("verified"));

    let o = pragmatic(&["show", "refund-1", "--dir", d]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let s = stdout(&o);
    assert!(s.contains("parallel region: 2 children"));
    assert!(s.contains("note.attempt.start"));
    assert!(s.contains("draw.ok"));

    let o = pragmatic(&["verify", "--all", "--dir", d]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    let s = stdout(&o);
    assert!(s.contains("unaccounted erasures  none"));
    assert_eq!(s.matches("result                verified").count(), 2);

    let out = dir.join("page.html");
    let o = pragmatic(&[
        "export",
        "refund-1",
        "--dir",
        d,
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.contains("Content-Security-Policy"));
    // The parallel region's children hang one lane deep.
    assert!(html.contains(" d1\"><details>"));
    assert!(
        html.contains("font-src data:"),
        "the file carries its fonts"
    );
    assert!(!html.contains("<script"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn read_only_commands_never_write() {
    let dir = seeded("readonly");
    let d = dir.to_str().unwrap();
    let before = journal_files(&dir);
    for args in [
        vec!["runs", "--dir", d],
        vec!["show", "refund-1", "--dir", d],
        vec!["verify", "refund-1", "--dir", d],
        vec!["verify", "--all", "--dir", d],
    ] {
        assert_eq!(code(&pragmatic(&args)), 0);
    }
    assert_eq!(journal_files(&dir), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn verify_reports_damage_without_repairing_it() {
    let dir = seeded("damage");
    let d = dir.to_str().unwrap();
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.extension().is_some_and(|e| e == "journal")
                && std::fs::read(p)
                    .unwrap()
                    .windows(8)
                    .any(|w| w == b"refund-2")
        })
        .unwrap();
    let mut bytes = std::fs::read(&file).unwrap();
    let at = bytes.windows(6).position(|w| w == b"option").unwrap();
    bytes[at] ^= 0x20;
    std::fs::write(&file, &bytes).unwrap();
    let o = pragmatic(&["verify", "refund-2", "--dir", d]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert!(stdout(&o).contains("BROKEN at cursor"), "{}", stdout(&o));
    assert_eq!(std::fs::read(&file).unwrap(), bytes, "verify never writes");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn erase_keeps_the_chain_and_accounts_for_every_slot() {
    let dir = seeded("erase");
    let d = dir.to_str().unwrap();
    // By match: every copy of the address.
    let o = pragmatic(&[
        "erase",
        "refund-1",
        "--match",
        "jane@example.com",
        "--reason-code",
        "gdpr_art17",
        "--reason",
        "DSR-1",
        "--dir",
        d,
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("erasure note at cursor"));
    assert!(stdout(&o).contains("(unauthenticated)"));
    let erased_run = journal_files(&dir)
        .into_iter()
        .find(|(p, bytes, _)| {
            p.extension().is_some_and(|e| e == "journal")
                && bytes.windows(8).any(|w| w == b"refund-1")
        })
        .unwrap();
    assert!(!erased_run.1.windows(16).any(|w| w == b"jane@example.com"));
    // By cursor: every slot of the first draw's result.
    let o = pragmatic(&[
        "erase",
        "refund-1",
        "--cursor",
        "3",
        "--reason-code",
        "test",
        "--dir",
        d,
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = pragmatic(&["verify", "refund-1", "--dir", d]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    let o = pragmatic(&["show", "refund-1", "--dir", d]);
    assert!(stdout(&o).contains("note.erasure"));
    assert!(stdout(&o).contains("slot(s) erased"));

    // Usage errors.
    assert_eq!(
        code(&pragmatic(&[
            "erase", "refund-1", "--cursor", "1", "--dir", d
        ])),
        64
    );
    assert_eq!(
        code(&pragmatic(&[
            "erase",
            "refund-1",
            "--cursor",
            "1",
            "--reason-code",
            "Has Spaces",
            "--dir",
            d
        ])),
        64
    );
    assert_eq!(
        code(&pragmatic(&[
            "erase",
            "refund-1",
            "--cursor",
            "1",
            "--match",
            "x",
            "--reason-code",
            "a",
            "--dir",
            d
        ])),
        64
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn local_evidence_round_trip() {
    let dir = seeded("evidence");
    let d = dir.to_str().unwrap();
    let b = dir.join("refund-1.evidence.json");
    let bs = b.to_str().unwrap();
    let o = pragmatic(&[
        "evidence",
        "refund-1",
        "--dir",
        d,
        "-o",
        bs,
        "--redact",
        "detectors",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle = Bundle::from_json(&std::fs::read(&b).unwrap()).unwrap();
    assert!(!bundle.redacted_slots.is_empty(), "the email is withheld");
    assert_eq!(bundle.redaction.mode, "detectors");
    assert!(bundle.generator.starts_with("pragmatic-cli "));
    assert!(bundle.verification_spec.is_some());

    let o = pragmatic(&["verify-evidence", bs, "--no-openssl"]);
    assert_eq!(code(&o), 3, "{}", stdout(&o));
    assert!(stdout(&o).contains("UNANCHORED"));
    assert!(stdout(&o).contains("the procedure this verifier ships"));

    let html = dir.join("r.html");
    let o = pragmatic(&[
        "render-evidence",
        bs,
        "--format",
        "html",
        "-o",
        html.to_str().unwrap(),
    ]);
    // render-evidence exits with the verdict's code, as verify-evidence.
    assert_eq!(code(&o), 3, "{}", stderr(&o));
    assert!(stdout(&o).contains("UNANCHORED"));
    let page = std::fs::read_to_string(&html).unwrap();
    assert!(page.contains("UNANCHORED \u{b7} exit 3"));
    let csv = dir.join("r.csv");
    let o = pragmatic(&[
        "render-evidence",
        bs,
        "--format",
        "csv",
        "-o",
        csv.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 3, "{}", stderr(&o));
    let rows = std::fs::read_to_string(&csv).unwrap();
    assert!(rows.starts_with("verdict,anchored,cursor,at_ns"));
    assert!(rows.contains("\r\n\"UNANCHORED\",\"no\",\"0\","));

    // Withholding on request.
    let o = pragmatic(&[
        "evidence",
        "refund-1",
        "--dir",
        d,
        "-o",
        bs,
        "--withhold",
        "2:0",
        "--withhold",
        "3:1",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle = Bundle::from_json(&std::fs::read(&b).unwrap()).unwrap();
    assert_eq!(bundle.redacted_slots.len(), 2);
    assert_eq!(code(&pragmatic(&["evidence", "refund-1", "--dir", d])), 64);
    assert_eq!(
        code(&pragmatic(&[
            "evidence", "refund-1", "--dir", d, "-o", bs, "--redact", "some"
        ])),
        64
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn keyed_journals_and_key_sources() {
    let dir = temp("keyed");
    let d = dir.to_str().unwrap();
    let rt = Runtime::on_dir(&dir, SeededOracle::new(1))
        .unwrap()
        .with_key(b"secret-key");
    rt.run("k1", agent).unwrap();
    let key = dir.join("key");
    std::fs::write(&key, "secret-key\n").unwrap();
    let k = key.to_str().unwrap();

    let o = pragmatic(&["show", "k1", "--dir", d]);
    assert_eq!(code(&o), 1, "a keyed journal needs its key");
    let o = pragmatic(&["show", "k1", "--dir", d, "--key-file", k]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = Command::new(bin())
        .args(["verify", "k1", "--dir", d])
        .env("PRAGMATIC_JOURNAL_KEY", "secret-key")
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    let o = pragmatic(&["show", "k1", "--dir", d, "--key", "secret-key"]);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("--key is deprecated"));
    let out = dir.join("b.json");
    let o = pragmatic(&[
        "evidence",
        "k1",
        "--dir",
        d,
        "--key-file",
        k,
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("keyed"), "{}", stderr(&o));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn usage_and_explain() {
    let o = pragmatic(&["verify-evidence", "--explain"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("## 8. Verification procedure"));
    assert_eq!(code(&pragmatic(&["show", "x", "--tsa-roots", "y"])), 64);
    assert_eq!(code(&pragmatic(&["verify-evidence"])), 64);
    assert_eq!(code(&pragmatic(&["nonsense"])), 64);
    assert_eq!(code(&pragmatic(&["help"])), 0);
    assert_eq!(
        code(&pragmatic(&[
            "verify-evidence",
            "x.json",
            "--min-operators",
            "0"
        ])),
        64
    );
}

#[test]
fn the_shipped_procedure_is_the_published_one() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let docs = manifest.join("../../docs/evidence-format.md");
    let Ok(published) = std::fs::read_to_string(&docs) else {
        eprintln!("skipped: not in the repository");
        return;
    };
    let shipped = std::fs::read_to_string(manifest.join("assets/evidence-format.md")).unwrap();
    assert_eq!(
        shipped, published,
        "copy docs/evidence-format.md to crates/pragmatic-cli/assets/"
    );
}

// ---------------------------------------------------------------------------
// verify-evidence against the anchored fixtures
// ---------------------------------------------------------------------------

/// Every trust flag the fixtures need.
fn full_trust() -> Vec<String> {
    vec![
        "--tsa-roots".into(),
        format!("fixture-tsa-a={}", fixture("trust/tsa-a-root.pem")),
        "--tsa-roots".into(),
        format!("fixture-tsa-b={}", fixture("trust/tsa-b-root.pem")),
        "--witness-key".into(),
        format!("fixture-witness={}", fixture("trust/witness.vkey")),
        "--log-key".into(),
        fixture("trust/log.vkey"),
    ]
}

fn verify_evidence(file: &str, extra: &[String]) -> Output {
    let mut args = vec!["verify-evidence".to_string(), file.to_string()];
    args.extend(extra.iter().cloned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    pragmatic(&refs)
}

#[test]
fn fixture_verifies_with_openssl_and_full_trust() {
    needs_openssl!();
    let mut flags = full_trust();
    flags.extend([
        "--log".into(),
        fixture("log.json"),
        "--witness-log".into(),
        fixture("witness-log.json"),
        "--openssl".into(),
    ]);
    for name in ["bundle.json", "bundle-hmac.json"] {
        let flags = if name == "bundle.json" {
            flags.clone()
        } else {
            full_trust()
        };
        let o = verify_evidence(&fixture(name), &flags);
        let s = stdout(&o);
        assert_eq!(code(&o), 0, "{name}: {s}");
        assert!(s.contains("VERIFIED: all 32 entries"));
        assert!(s.contains("trusted (fixture-tsa-a)"));
        assert!(s.contains("trusted (fixture-tsa-b)"));
        assert!(s.contains("trusted (fixture-witness)"));
        assert!(s.contains("operator-controlled"));
        assert!(s.contains("verified with pinned log key"));
    }
}

#[test]
fn unpinned_or_wrong_roots_leave_it_unanchored() {
    needs_openssl!();
    // No trust at all.
    let o = verify_evidence(&fixture("bundle.json"), &[]);
    assert_eq!(code(&o), 3, "{}", stdout(&o));
    assert!(stdout(&o).contains("tsa_untrusted"));
    // One TSA's root pinned under both names: the other TSA's tokens do not
    // verify, and one operator is not enough.
    let b = fixture("trust/tsa-b-root.pem");
    let flags = vec![
        "--tsa-roots".to_string(),
        format!("fixture-tsa-a={b}"),
        "--tsa-roots".to_string(),
        format!("fixture-tsa-b={b}"),
    ];
    let o = verify_evidence(&fixture("bundle.json"), &flags);
    assert_eq!(code(&o), 3, "{}", stdout(&o));
    let s = stdout(&o);
    assert!(s.contains("tsa_untrusted"));
    assert!(s.contains("unable to get local issuer certificate"), "{s}");
    // TSA B's tokens verify under both names, so they count for neither.
    assert!(s.contains("tsa_ambiguous"), "{s}");
}

/// Every certificate in a pinned file is an anchor (`-partial_chain`), so
/// an auditor can pin the certificate that issues an operator's tokens
/// rather than a root; and the operator must always be named.
#[test]
fn issuing_certificates_can_be_pinned_and_operators_must_be_named() {
    needs_openssl!();
    let b = Bundle::from_json(&std::fs::read(fixture("bundle.json")).unwrap()).unwrap();
    let issuer = b
        .anchors
        .iter()
        .flat_map(|a| &a.witnesses)
        .find_map(|w| match w {
            Witness::Rfc3161 { tsa, certs_pem, .. } if tsa.contains("tsa-a") => {
                Some(certs_pem.clone())
            }
            _ => None,
        })
        .unwrap();
    let dir = temp("issuing");
    let pinned = dir.join("tsa-a-issuer.pem");
    std::fs::write(&pinned, issuer).unwrap();
    let mut flags = full_trust();
    flags[1] = format!("fixture-tsa-a={}", pinned.display());
    let o = verify_evidence(&fixture("bundle.json"), &flags);
    let s = stdout(&o);
    assert_eq!(code(&o), 0, "{s}{}", stderr(&o));
    assert!(s.contains("trusted (fixture-tsa-a)"), "{s}");
    // A file without an operator is a usage error, not a guess.
    let o = verify_evidence(
        &fixture("bundle.json"),
        &["--tsa-roots".into(), fixture("trust/tsa-a-root.pem")],
    );
    assert_eq!(code(&o), 64, "{}", stdout(&o));
    assert!(stderr(&o).contains("OPERATOR=FILE"), "{}", stderr(&o));
    std::fs::remove_dir_all(dir).unwrap();
}

/// Write a changed copy of the fixture bundle.
fn variant(dir: &Path, name: &str, change: impl FnOnce(&mut Bundle)) -> String {
    let mut b = Bundle::from_json(&std::fs::read(fixture("bundle.json")).unwrap()).unwrap();
    b.signature = None;
    change(&mut b);
    let path = dir.join(name);
    std::fs::write(&path, b.to_json()).unwrap();
    path.display().to_string()
}

fn assert_code(o: &Output, exit: i32, finding: &str) {
    let s = stdout(o);
    assert_eq!(code(o), exit, "{s}{}", stderr(o));
    assert!(s.contains(finding), "expected {finding}: {s}");
}

#[test]
fn adversarial_self_signed_tsa() {
    needs_openssl!();
    let dir = temp("adv-tsa");
    let rogue: pragmatic::json::Json =
        pragmatic::json::Json::parse(&std::fs::read_to_string(fixture("rogue.json")).unwrap())
            .unwrap();
    let file = variant(&dir, "rogue.json", |b| {
        for a in &mut b.anchors {
            let token = rogue
                .get("tokens")
                .and_then(|t| t.get(&a.seq.to_string()))
                .and_then(|t| t.as_str())
                .unwrap();
            let token = pragmatic::encoding::base64_decode(token).unwrap();
            let certs = rogue.get("certs_pem").and_then(|c| c.as_str()).unwrap();
            for w in &mut a.witnesses {
                if let Witness::Rfc3161 {
                    token: t,
                    certs_pem,
                    ..
                } = w
                {
                    *t = token.clone();
                    *certs_pem = certs.to_string();
                }
            }
        }
    });
    let mut flags = full_trust();
    flags.truncate(4);
    assert_code(&verify_evidence(&file, &flags), 3, "tsa_untrusted");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn adversarial_swapped_witness_key() {
    let flags = vec![
        "--witness-key".to_string(),
        format!("fixture-witness={}", fixture("trust/witness-wrong.vkey")),
        "--min-operators".into(),
        "1".into(),
        "--no-openssl".into(),
    ];
    assert_code(
        &verify_evidence(&fixture("bundle.json"), &flags),
        3,
        "cosignature_untrusted",
    );
    // The right key alone, with one operator required, verifies.
    let flags = vec![
        "--witness-key".to_string(),
        format!("fixture-witness={}", fixture("trust/witness.vkey")),
        "--min-operators".into(),
        "1".into(),
        "--no-openssl".into(),
    ];
    assert_code(
        &verify_evidence(&fixture("bundle.json"), &flags),
        0,
        "VERIFIED",
    );
}

#[test]
fn adversarial_omitted_anchor_caught_with_log() {
    let dir = temp("adv-omit");
    let file = variant(&dir, "omitted.json", |b| {
        b.anchors.pop();
    });
    // The variant is unsigned, so the log key stays unpinned (a pinned log
    // key requires the bundle's signature).
    let mut flags = full_trust();
    flags.truncate(6);
    flags.push("--no-openssl".into());
    flags.extend(["--min-operators".into(), "1".into()]);
    // Without the log the bundle looks like a partial anchor.
    assert_code(&verify_evidence(&file, &flags), 2, "VERIFIED (PARTIAL)");
    flags.extend(["--log".into(), fixture("log.json")]);
    assert_code(&verify_evidence(&file, &flags), 1, "anchor_omitted");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn adversarial_integrity_failures() {
    let dir = temp("adv-integrity");
    let flags: Vec<String> = vec!["--no-openssl".into()];
    let cases: Vec<(&str, String)> = vec![
        (
            "entries_mismatch",
            variant(&dir, "entries.json", |b| b.journal.entries += 1),
        ),
        (
            "head_mismatch",
            variant(&dir, "head.json", |b| b.journal.head[5] ^= 1),
        ),
        (
            "withheld_mismatch",
            variant(&dir, "withheld.json", |b| b.redacted_slots.clear()),
        ),
        (
            "records_mismatch",
            variant(&dir, "records.json", |b| {
                b.records[5].fields = pragmatic::json::Json::Object(vec![])
            }),
        ),
        (
            "journal_trailing_bytes",
            variant(&dir, "trailing.json", |b| {
                b.journal.bytes.extend_from_slice(b"xyz")
            }),
        ),
    ];
    for (finding, file) in cases {
        assert_code(&verify_evidence(&file, &flags), 1, finding);
    }

    // An erased slot with no erasure note.
    let rt = Runtime::on_dir(dir.join("j"), SeededOracle::new(3)).unwrap();
    rt.run("e1", agent).unwrap();
    let j = rt.snapshot("e1").unwrap();
    let erased = j
        .erase(
            &EraseSelector::Match(b"jane@".to_vec()),
            &ErasureNote::local("t", ""),
            1,
        )
        .unwrap();
    let mut without_note: Journal = erased.journal;
    without_note.truncate(without_note.len() - 1);
    let b = Bundle::local(&without_note.to_bytes(), "e1", &Redact::None).unwrap();
    let file = dir.join("no-note.json");
    std::fs::write(&file, b.to_json()).unwrap();
    assert_code(
        &verify_evidence(file.to_str().unwrap(), &flags),
        1,
        "unaccounted_erasure",
    );

    // Duplicate keys and trailing bytes in the JSON itself.
    let text = std::fs::read_to_string(fixture("bundle.json")).unwrap();
    let dup = dir.join("dup.json");
    std::fs::write(
        &dup,
        text.replacen("\"run_id\":", "\"run_id\": \"other\", \"run_id\":", 1),
    )
    .unwrap();
    assert_code(
        &verify_evidence(dup.to_str().unwrap(), &flags),
        1,
        "bundle_json",
    );
    let tail = dir.join("tail.json");
    std::fs::write(&tail, format!("{text}]")).unwrap();
    assert_code(
        &verify_evidence(tail.to_str().unwrap(), &flags),
        1,
        "bundle_json",
    );

    // A signed bundle altered after signing.
    let signed = dir.join("signed.json");
    std::fs::write(
        &signed,
        text.replacen("tok_auditor_fixture", "tok_someone_else", 1),
    )
    .unwrap();
    let mut pinned = full_trust();
    pinned.push("--no-openssl".into());
    assert_code(
        &verify_evidence(signed.to_str().unwrap(), &pinned),
        1,
        "bundle_signature",
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hostile_bundle_text_cannot_reach_the_terminal() {
    let dir = temp("adv-terminal");
    let file = variant(&dir, "ansi.json", |b| {
        b.generator = "\u{1b}[2J\u{1b}[HVERIFIED: all entries".into();
        if let Some(Witness::Rfc3161 { tsa, .. }) = b.anchors[0].witnesses.first_mut() {
            *tsa = "\u{1b}]8;;http://evil\u{7}x".into();
        }
    });
    let o = verify_evidence(&file, &["--no-openssl".to_string()]);
    let s = stdout(&o);
    assert!(!s.contains('\u{1b}'), "{s}");
    assert!(s.contains("\\u{1b}[2J"));
    std::fs::remove_dir_all(dir).unwrap();
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn get(port: u16, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n");
                s.write_all(request.as_bytes()).unwrap();
                let mut out = String::new();
                s.read_to_string(&mut out).unwrap();
                return out;
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("serve did not start: {e}"),
        }
    }
}

fn get_bytes(port: u16, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n");
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    out
}

/// The CI "Console smoke test" greps the console's run page for a label;
/// that label must be one the console renders for a model draw (it
/// labels results `draw.<outcome>`), or the CI job fails on every push.
#[test]
fn the_ci_console_smoke_test_greps_what_the_console_renders() {
    let ci = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml"),
    )
    .unwrap();
    let line = ci
        .lines()
        .find(|l| l.contains("/run/research-42") && l.contains("grep -q"))
        .expect("the console smoke step");
    let term = line
        .rsplit("grep -q ")
        .next()
        .unwrap()
        .trim()
        .trim_matches('"');
    let dir = seeded("ci-grep");
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(bin())
        .args([
            "serve",
            "--dir",
            dir.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let run = get(port, "/run/refund-1");
    let _ = child.kill();
    let _ = child.wait();
    assert!(run.starts_with("HTTP/1.1 200"));
    assert!(run.contains(term), "ci.yml greps for {term:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn serve_renders_the_console_on_loopback() {
    let dir = seeded("serve");
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(bin())
        .args([
            "serve",
            "--dir",
            dir.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let index = get(port, "/");
    let run = get(port, "/run/refund-1");
    let missing = get(port, "/run/<script>");
    // The fonts come from the console itself, cached for good.
    let name = run
        .split("url(/assets/")
        .nth(1)
        .and_then(|r| r.split(')').next())
        .unwrap()
        .to_string();
    let font = get_bytes(port, &format!("/assets/{name}"));
    let _ = child.kill();
    let _ = child.wait();
    let head = String::from_utf8_lossy(&font[..font.len().min(400)]).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("content-type: font/woff2"));
    assert!(head.contains("cache-control: public, max-age=31536000, immutable"));
    assert!(font.windows(4).any(|w| w == b"wOF2"));
    assert!(index.starts_with("HTTP/1.1 200"));
    assert!(index.contains("content-security-policy: default-src 'none'"));
    assert!(index.contains("<a class=\"m\" href=\"/run/refund-1\">refund-1</a>"));
    assert!(index.contains("font-src 'self'"));
    assert!(run.contains("<span id=\"c0\"></span>"));
    assert!(run.contains("url(/assets/eb-garamond-latin."));
    assert!(missing.starts_with("HTTP/1.1 404"));
    assert!(
        missing.contains("No run named"),
        "an HTML page, not plain text"
    );
    assert!(!missing.contains("<script>"));
    std::fs::remove_dir_all(dir).unwrap();
}
