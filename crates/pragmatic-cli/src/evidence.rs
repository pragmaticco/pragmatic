//! `evidence`, `verify-evidence` and `render-evidence` (design 5 and 7).
//!
//! `evidence` packages a local run as a bundle. `verify-evidence` checks a
//! bundle against trust the auditor supplies on the command line (pinned
//! TSA roots, witness keys and log keys) and exits with the verdict's code:
//! 0 verified, 2 verified for a prefix only, 3 unanchored, 1 failed.
//! `render-evidence` turns a bundle into a page or a spreadsheet, and exits
//! with the same code. A trust input that is malformed or cannot be read is
//! a usage error (exit 64), never a verdict, so a typo in a CI gate's flags
//! cannot read as "the bundle is forged".
//!
//! Every string in a report that came from the bundle is printed through
//! `text::sanitize`, so a bundle cannot put escape sequences on the
//! auditor's terminal or forge lines of the report.

use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_decode_exact;
use pragmatic::evidence::{
    self, normalize_operator, AnchorLog, Audit, Bundle, CheckStatus, Code, EvidenceReport,
    NoTsaVerifier, Redact, Severity, SignatureStatus, TrustPolicy, TsaRoot, TsaVerifier, Verdict,
    VerificationSpec, WitnessClass, WitnessKey, WitnessLog, DIRECTORY_BUNDLE_FILE,
    DIRECTORY_THRESHOLD,
};
use pragmatic::note::{SignatureType, VerifierKey};
use pragmatic::redact::Kind;
use pragmatic::sha256::sha256;
use pragmatic::Backend;
use pragmatic_console::text::sanitize;
use pragmatic_console::{render_csv, render_evidence};

use crate::args::{journal_key, Args, Usage};
use crate::journals::backend;
use crate::openssl::{Found, OpenSslTsa};
use crate::Failure;

/// The normative format and verification procedure, as shipped with this
/// verifier (`docs/evidence-format.md`; a test keeps the copies equal).
pub const PROCEDURE: &str = include_str!("../assets/evidence-format.md");

/// Where the procedure is published for this version.
fn spec() -> VerificationSpec {
    VerificationSpec {
        url: format!(
            "https://github.com/pragmaticco/pragmatic/blob/v{}/docs/evidence-format.md",
            env!("CARGO_PKG_VERSION")
        ),
        sha256: sha256(PROCEDURE.as_bytes()),
    }
}

/// The keys of the hosted witness that Pragmatic Research runs, with
/// validity windows (Unix seconds): `(operator, vkey, not_before,
/// not_after)`. Empty until the witness launches (design 5.2).
const HOSTED_WITNESS_KEYS: &[(&str, &str, u64, u64)] = &[];

// ---------------------------------------------------------------------------
// evidence RUN -o FILE
// ---------------------------------------------------------------------------

/// The detectors `--redact detectors` applies: `--detectors a,b`, or all.
fn detectors(args: &Args) -> Result<Vec<Kind>, Usage> {
    let Some(list) = args.value("--detectors") else {
        return Ok(Kind::ALL.to_vec());
    };
    list.split(',')
        .map(|n| {
            Kind::from_name(n.trim()).ok_or_else(|| {
                let known: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
                Usage(format!(
                    "unknown detector {n:?}; known: {}",
                    known.join(", ")
                ))
            })
        })
        .collect()
}

fn redact(args: &Args) -> Result<Redact, Usage> {
    let mode = args.value("--redact").unwrap_or("none");
    if args.value("--detectors").is_some() && mode != "detectors" {
        return Err(Usage("--detectors goes with --redact detectors".into()));
    }
    Ok(match mode {
        "none" => Redact::None,
        "detectors" => Redact::Detectors(detectors(args)?),
        "binary" => Redact::Binary,
        "all" => Redact::All,
        other => {
            return Err(Usage(format!(
                "--redact must be none, detectors, binary or all, not {other:?}"
            )))
        }
    })
}

/// `C:S` pairs from `--withhold`.
fn withheld(args: &Args) -> Result<Vec<(u64, u8)>, Usage> {
    args.values("--withhold")
        .iter()
        .map(|v| {
            let (c, s) = v
                .split_once(':')
                .ok_or_else(|| Usage(format!("--withhold takes CURSOR:SLOT, not {v:?}")))?;
            Ok((
                c.parse()
                    .map_err(|_| Usage(format!("bad cursor in --withhold {v:?}")))?,
                s.parse()
                    .map_err(|_| Usage(format!("bad slot in --withhold {v:?}")))?,
            ))
        })
        .collect()
}

pub fn build(args: &Args) -> Result<(), Failure> {
    args.only(&[
        "--dir",
        "--key",
        "--key-file",
        "--out",
        "--redact",
        "--detectors",
        "--withhold",
    ])?;
    let run = args.one("RUN -o FILE")?;
    let out = args
        .path("--out")
        .ok_or_else(|| Usage("evidence needs -o FILE".into()))?;
    let redact = redact(args)?;
    let pairs = withheld(args)?;
    let key = journal_key(args)?;
    let journal = backend(&args.dir())?
        .snapshot(run, key.as_deref())
        .map_err(|e| format!("{}: {e}", sanitize(run)))?;
    if journal.is_keyed() {
        return Err(Failure::Error(
            "this journal is keyed: an evidence bundle carries an unkeyed journal, because a \
             verifier never holds the key. Evidence needs a journal written without a key (or \
             by Stet Server)"
                .into(),
        ));
    }
    let mut bundle = Bundle::local(&journal.to_bytes(), run, &redact)
        .map_err(|e| format!("{}: {e}", sanitize(run)))?;
    if !pairs.is_empty() {
        bundle
            .withhold(&pairs)
            .map_err(|e| format!("--withhold: {e}"))?;
    }
    bundle.generator = format!("pragmatic-cli {}", env!("CARGO_PKG_VERSION"));
    bundle.verification_spec = Some(spec());
    let json = bundle.to_json();
    let written = if json.len() as u64 > DIRECTORY_THRESHOLD {
        write_directory(&out, &mut bundle)?
    } else {
        crate::output::write(&out, json.as_bytes())?;
        out.display().to_string()
    };
    println!(
        "wrote {written}: run {}, {} entries, {} withheld slot(s) (redaction {})",
        sanitize(run),
        bundle.journal.entries,
        bundle.redacted_slots.len(),
        bundle.redaction.mode
    );
    println!(
        "unanchored and unsigned: local runs carry no anchors in 0.6, so the bundle proves \
         integrity, not time. Check it with: pragmatic verify-evidence {}",
        out.display()
    );
    Ok(())
}

/// The directory form, for bundles over 100 MiB: `OUT/evidence.json` and
/// the journal next to it.
fn write_directory(out: &Path, bundle: &mut Bundle) -> Result<String, String> {
    std::fs::create_dir(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let journal = bundle.into_directory_form();
    let evidence::JournalEncoding::File { path, .. } = &bundle.journal.encoding else {
        unreachable!("directory form");
    };
    std::fs::write(out.join(path), journal).map_err(|e| e.to_string())?;
    std::fs::write(out.join(DIRECTORY_BUNDLE_FILE), bundle.to_json()).map_err(|e| e.to_string())?;
    Ok(format!("{}/ (directory form)", out.display()))
}

// ---------------------------------------------------------------------------
// Trust inputs
// ---------------------------------------------------------------------------

const TRUST_FLAGS: &[&str] = &[
    "--tsa-roots",
    "--witness-key",
    "--log-key",
    "--min-operators",
    "--log",
    "--witness-log",
    "--openssl",
    "--no-openssl",
];

/// A vkey given inline, or the path of a file holding one.
fn read_vkey(value: &str) -> Result<VerifierKey, Usage> {
    let text = if value.contains('+') {
        value.to_string()
    } else {
        std::fs::read_to_string(value)
            .map_err(|e| Usage(format!("cannot read key file {}: {e}", sanitize(value))))?
    };
    VerifierKey::parse(text.trim()).map_err(|e| Usage(format!("{}: {e}", sanitize(value))))
}

/// `--witness-key NAME=VKEY` (or `NAME=HEX`, a 32-byte cosignature key
/// whose cosigner name is `NAME`). `NAME` is the operator the witness
/// counts for.
fn witness_key(value: &str) -> Result<WitnessKey, Usage> {
    let (operator, key) = value.split_once('=').ok_or_else(|| {
        Usage(format!(
            "--witness-key takes NAME=VKEY, not {:?}",
            sanitize(value)
        ))
    })?;
    if operator.trim().is_empty() {
        return Err(Usage(
            "--witness-key needs an operator name before '='".into(),
        ));
    }
    let key = match hex_decode_exact::<32>(key) {
        Ok(raw) => VerifierKey::new(operator, SignatureType::CosignatureV1, raw)
            .map_err(|e| Usage(format!("--witness-key {}: {e}", sanitize(operator))))?,
        Err(_) => read_vkey(key)?,
    };
    if key.signature_type() != SignatureType::CosignatureV1 {
        return Err(Usage(format!(
            "--witness-key {}: a witness key must be a cosignature/v1 key (type 0x04)",
            sanitize(operator)
        )));
    }
    Ok(WitnessKey {
        operator: operator.to_string(),
        key,
        not_before: None,
        not_after: None,
    })
}

/// `--tsa-roots OPERATOR=FILE`. The operator is required: it is what a
/// token is counted for, so it must be the auditor's statement, never
/// something read off a file name (design 5.2).
fn tsa_root(value: &str) -> Result<TsaRoot, Usage> {
    let (operator, path) = match value.split_once('=') {
        Some((op, p)) if !normalize_operator(op).is_empty() && !p.is_empty() => {
            (op.to_string(), PathBuf::from(p))
        }
        _ => {
            return Err(Usage(format!(
                "--tsa-roots: expected OPERATOR=FILE, got {value:?}: name the operator the \
                 anchors belong to"
            )))
        }
    };
    if !path.is_file() {
        return Err(Usage(format!(
            "--tsa-roots: {} is not a file",
            path.display()
        )));
    }
    Ok(TsaRoot { operator, path })
}

fn policy(args: &Args) -> Result<TrustPolicy, Failure> {
    let mut p = TrustPolicy::default();
    for v in args.values("--tsa-roots") {
        p.tsa_roots.push(tsa_root(v)?);
    }
    for v in args.values("--witness-key") {
        p.witness_keys.push(witness_key(v)?);
    }
    for &(operator, vkey, not_before, not_after) in HOSTED_WITNESS_KEYS {
        p.witness_keys.push(WitnessKey {
            operator: operator.into(),
            key: VerifierKey::parse(vkey).map_err(|e| format!("built-in witness key: {e}"))?,
            not_before: Some(not_before),
            not_after: Some(not_after),
        });
    }
    for v in args.values("--log-key") {
        let key = read_vkey(v)?;
        if key.signature_type() != SignatureType::Ed25519 {
            return Err(Usage(format!(
                "--log-key {}: a log key must be an Ed25519 note key (type 0x01)",
                sanitize(v)
            ))
            .into());
        }
        p.log_keys.push(key);
    }
    if let Some(n) = args.number::<usize>("--min-operators")? {
        if n == 0 {
            return Err(Usage("--min-operators must be at least 1".into()).into());
        }
        p.min_operators = n;
    }
    Ok(p)
}

fn audit(args: &Args) -> Result<Audit, Usage> {
    let read = |flag: &str, p: &str| {
        std::fs::read(p).map_err(|e| Usage(format!("{flag}: cannot read {}: {e}", sanitize(p))))
    };
    let log = match args.value("--log") {
        Some(p) => Some(
            AnchorLog::from_json(&read("--log", p)?)
                .map_err(|e| Usage(format!("--log {}: {e}", sanitize(p))))?,
        ),
        None => None,
    };
    let mut witness_logs = Vec::new();
    for p in args.values("--witness-log") {
        witness_logs.push(
            WitnessLog::from_json(&read("--witness-log", p)?)
                .map_err(|e| Usage(format!("--witness-log {}: {e}", sanitize(p))))?,
        );
    }
    Ok(Audit { log, witness_logs })
}

/// The TSA verifier: the first OpenSSL on `PATH` that can check tokens
/// (required with `--openssl`), nothing with `--no-openssl`. Returns it
/// and a line for the report.
fn tsa(args: &Args) -> Result<(Box<dyn TsaVerifier>, String), Failure> {
    if args.has("--openssl") && args.has("--no-openssl") {
        return Err(Usage("--openssl and --no-openssl contradict each other".into()).into());
    }
    if args.has("--no-openssl") {
        return Ok((
            Box::new(NoTsaVerifier),
            "not used (--no-openssl): RFC 3161 tokens are not checked".into(),
        ));
    }
    match OpenSslTsa::find() {
        Found::Usable(o, version) => {
            let about = format!("{} ({version})", o.bin().display());
            Ok((Box::new(o), about))
        }
        Found::Unusable(bin, why) if args.has("--openssl") => Err(Usage(format!(
            "--openssl: {} cannot check time-stamp tokens: {why}; put OpenSSL 3 on PATH",
            bin.display()
        ))
        .into()),
        Found::Missing if args.has("--openssl") => {
            Err(Usage("--openssl: no openssl on PATH".into()).into())
        }
        Found::Unusable(bin, why) => Ok((
            Box::new(NoTsaVerifier),
            format!(
                "{} cannot check time-stamp tokens ({why}): RFC 3161 tokens are not checked; put OpenSSL 3 on PATH",
                bin.display()
            ),
        )),
        Found::Missing => Ok((
            Box::new(NoTsaVerifier),
            "not found on PATH: RFC 3161 tokens are not checked".into(),
        )),
    }
}

/// The most bytes read from a file of a directory bundle. A directory
/// bundle comes from the party being audited, and its journal can be as
/// large as a run (gigabytes); this only refuses what no run produces.
const MAX_BUNDLE_FILE: u64 = 16 << 30;

/// Why a file of a directory bundle was not read.
enum Unread {
    /// It is not there.
    Missing,
    /// It is a link, a FIFO, a device or larger than any run: a finding
    /// (`bundle_file`) about the bundle.
    Refused(String),
    /// Reading it failed: the auditor's problem, not the bundle's.
    Io(String),
}

/// Read a file inside a directory bundle. The directory came from the
/// party being audited, and archives keep symbolic links and FIFOs: a link
/// to `/dev/zero` would exhaust memory and a FIFO would block forever, so
/// only a regular file (by `lstat`, and again on the open handle) of at
/// most [`MAX_BUNDLE_FILE`] bytes is read.
fn read_bundle_file(path: &Path) -> Result<Vec<u8>, Unread> {
    use std::io::Read;
    let shown = path.display();
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Unread::Missing),
        Err(e) => return Err(Unread::Io(format!("cannot read {shown}: {e}"))),
    };
    if !meta.file_type().is_file() {
        return Err(Unread::Refused(format!(
            "{shown} is not a regular file (a symbolic link, FIFO or device in a bundle directory is never read)"
        )));
    }
    if meta.len() > MAX_BUNDLE_FILE {
        return Err(Unread::Refused(format!(
            "{shown} is {} bytes, more than any bundle holds",
            meta.len()
        )));
    }
    let file =
        std::fs::File::open(path).map_err(|e| Unread::Io(format!("cannot read {shown}: {e}")))?;
    let opened = file
        .metadata()
        .map_err(|e| Unread::Io(format!("cannot read {shown}: {e}")))?;
    if !opened.is_file() || !same_file(&meta, &opened) {
        return Err(Unread::Refused(format!(
            "{shown} changed while it was being opened"
        )));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_BUNDLE_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Unread::Io(format!("cannot read {shown}: {e}")))?;
    if bytes.len() as u64 > MAX_BUNDLE_FILE {
        return Err(Unread::Refused(format!("{shown} grew past the size limit")));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    true
}

/// Parse and verify, attaching a directory bundle's journal file. The
/// bundle path is the auditor's own choice and is read as given (a pipe
/// from process substitution works); files inside a directory bundle are
/// read as [`read_bundle_file`] says.
fn check(path: &Path, args: &Args) -> Result<(Option<Bundle>, EvidenceReport, String), Failure> {
    let policy = policy(args)?;
    let audit = audit(args)?;
    let (tsa, about) = tsa(args)?;
    let min = policy.min_operators;
    let bytes = if path.is_dir() {
        let file = path.join(DIRECTORY_BUNDLE_FILE);
        match read_bundle_file(&file) {
            Ok(b) => b,
            Err(Unread::Refused(why)) => {
                return Ok((
                    None,
                    EvidenceReport::unreadable(Code::BundleFile, why, min),
                    about,
                ))
            }
            Err(Unread::Missing) => {
                return Err(Usage(format!(
                    "{} is a directory without {DIRECTORY_BUNDLE_FILE}: not a directory bundle",
                    path.display()
                ))
                .into())
            }
            Err(Unread::Io(e)) => return Err(Usage(e).into()),
        }
    } else {
        std::fs::read(path).map_err(|e| Usage(format!("cannot read {}: {e}", path.display())))?
    };
    let mut bundle = match Bundle::from_json(&bytes) {
        Ok(b) => b,
        Err(_) => {
            let (_, report) = evidence::verify_bytes(&bytes, &policy, tsa.as_ref(), &audit);
            return Ok((None, report, about));
        }
    };
    if path.is_dir() {
        if let evidence::JournalEncoding::File { path: name, .. } = &bundle.journal.encoding {
            let failed = |code, why: String| EvidenceReport::unreadable(code, why, min);
            match read_bundle_file(&path.join(name)) {
                Ok(journal) => {
                    if let Err(why) = bundle.attach_journal(journal) {
                        let report = failed(Code::JournalMissing, why);
                        return Ok((Some(bundle), report, about));
                    }
                }
                // Absent: verification reports journal_missing.
                Err(Unread::Missing) => {}
                Err(Unread::Refused(why)) => {
                    return Ok((Some(bundle), failed(Code::BundleFile, why), about))
                }
                Err(Unread::Io(e)) => return Err(Usage(e).into()),
            }
        }
    }
    let report = evidence::verify_with(&bundle, &policy, tsa.as_ref(), &audit);
    Ok((Some(bundle), report, about))
}

// ---------------------------------------------------------------------------
// verify-evidence FILE
// ---------------------------------------------------------------------------

pub fn verify(args: &Args) -> Result<(), Failure> {
    let mut allowed = TRUST_FLAGS.to_vec();
    allowed.push("--explain");
    args.only(&allowed)?;
    if args.has("--explain") {
        print!("{PROCEDURE}");
        return Ok(());
    }
    let file = PathBuf::from(args.one("FILE")?);
    let (bundle, report, about) = check(&file, args)?;
    print_report(&file, bundle.as_ref(), &report, args, &about);
    match report.exit_code() {
        0 => Ok(()),
        code => Err(Failure::Silent(code)),
    }
}

fn print_report(
    file: &Path,
    bundle: Option<&Bundle>,
    r: &EvidenceReport,
    args: &Args,
    openssl: &str,
) {
    println!("pragmatic verify-evidence {}", file.display());
    println!();
    // Only the bundle signature covers the generator's own fields; unless a
    // pinned key verified it, they are claims anyone could have edited.
    let signed = matches!(r.bundle_signature, SignatureStatus::Verified { .. });
    let claim = if signed {
        "signed by the log"
    } else {
        "unsigned claims"
    };
    if let Some(b) = bundle {
        println!("run        {}", sanitize(&b.run_id));
        println!(
            "journal    {} entries, {} withheld slot(s), redaction {} ({claim})",
            r.entries,
            b.redacted_slots.len(),
            sanitize(&b.redaction.mode)
        );
        println!(
            "generator  {} for {} ({claim})",
            sanitize(&b.generator),
            sanitize(&b.requested_by)
        );
        if let Some(s) = &b.verification_spec {
            let ours = spec().sha256;
            let note = if s.sha256 == ours {
                "its sha256 is that of the procedure this verifier ships"
            } else {
                "its sha256 differs from the procedure this verifier ships (see --explain)"
            };
            let url = if signed {
                "url"
            } else {
                "url, an unverified claim:"
            };
            println!("spec       {note}; {url} {}", sanitize(&s.url));
        }
    }
    let pinned = !args.values("--log-key").is_empty();
    let sig = match &r.bundle_signature {
        SignatureStatus::Verified { key } => {
            format!("verified with pinned log key {}", sanitize(key))
        }
        SignatureStatus::OperatorAsserted if pinned => {
            "signed by a key that is not the pinned log key".into()
        }
        SignatureStatus::OperatorAsserted => {
            "valid for a key that is not pinned: operator-asserted (pass --log-key)".into()
        }
        SignatureStatus::Unsigned if pinned => "unsigned, though a log key is pinned".into(),
        SignatureStatus::Unsigned => "unsigned".into(),
        SignatureStatus::Invalid => "INVALID".into(),
    };
    println!("signature  {sig}");
    println!(
        "trust      {} TSA root(s), {} witness key(s), {} log key(s); independence needs {} distinct trusted operator(s)",
        args.values("--tsa-roots").len(),
        args.values("--witness-key").len() + HOSTED_WITNESS_KEYS.len(),
        args.values("--log-key").len(),
        r.min_operators
    );
    println!("openssl    {openssl}");
    println!();
    println!("checks");
    for c in &r.checks {
        let s = match c.status {
            CheckStatus::Pass => "pass",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skipped => "skip",
            CheckStatus::Info => "info",
        };
        println!("  [{s}] {:>2} {}: {}", c.step, c.name, sanitize(&c.detail));
    }
    if !r.anchors.is_empty() {
        println!();
        println!("anchors");
    }
    for a in &r.anchors {
        let status = if !a.sound {
            "FAILS ITS CHECKS".to_string()
        } else if a.independent {
            format!("independent ({})", a.trusted_operators.join(", "))
        } else if a.trusted_operators.is_empty() {
            "no trusted operator".to_string()
        } else {
            format!("not enough operators ({})", a.trusted_operators.join(", "))
        };
        let time = a
            .earliest
            .map(|t| format!(", no later than {}", t.rfc3339()))
            .unwrap_or_default();
        println!(
            "  anchor {}: {} entries, leaf {} of {}, {status}{time}",
            a.seq, a.entries, a.leaf_index, a.tree_size
        );
        for w in &a.witnesses {
            let class = match (w.class, &w.operator) {
                (WitnessClass::Trusted, Some(op)) => format!("trusted ({op})"),
                (c, _) => c.as_str().to_string(),
            };
            let time = w.time.map(|t| t.rfc3339()).unwrap_or_default();
            println!(
                "    {:<15} {:<40} {:<26} {time}",
                w.kind,
                pragmatic_console::text::clip(&w.label, 40),
                class
            );
            if w.class != WitnessClass::Trusted && !w.detail.is_empty() {
                println!("      {}", sanitize(&w.detail));
            }
        }
    }
    let notable: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.severity() != Severity::Info)
        .collect();
    if !notable.is_empty() {
        println!();
        println!("findings");
        let mut sorted = notable;
        sorted.sort_by_key(|f| f.severity());
        for f in sorted {
            let sev = match f.severity() {
                Severity::Failure => "FAILURE",
                Severity::Warning => "warning",
                Severity::Info => "info",
            };
            println!("  {sev:<7} {}: {}", f.code, sanitize(&f.message));
        }
    }
    println!();
    let summary = match r.verdict {
        Verdict::Verified => format!(
            "all {} entries are anchored by at least {} distinct trusted operator(s)",
            r.entries, r.min_operators
        ),
        Verdict::Partial { unanchored } => format!(
            "the first {} entries are independently anchored; the last {unanchored} are not",
            r.anchored_entries
        ),
        Verdict::Unanchored => {
            "the journal's integrity checks pass, but no anchor has enough trusted operators"
                .to_string()
        }
        Verdict::Failed => format!(
            "{} failure(s) of integrity or of an audit asked for",
            r.failures().count()
        ),
    };
    println!("{}: {summary} (exit {})", r.verdict.label(), r.exit_code());
}

// ---------------------------------------------------------------------------
// render-evidence FILE --format html|csv
// ---------------------------------------------------------------------------

/// `render-evidence`: the page (verdict, checks, anchors, timeline) or the
/// CSV of the records, written safely (see `output`), and the verdict's
/// exit code, as `verify-evidence` gives it.
///
/// A bundle that fails verification is never written as CSV: a
/// spreadsheet is what gets passed on, and it has no room for the report
/// that says its rows are not what the journal holds. The page, which
/// leads with the failure, is written.
pub fn render(args: &Args) -> Result<(), Failure> {
    let mut allowed = TRUST_FLAGS.to_vec();
    allowed.extend(["--format", "--out"]);
    args.only(&allowed)?;
    let file = PathBuf::from(args.one("FILE --format html|csv")?);
    let format = args
        .value("--format")
        .ok_or_else(|| Usage("render-evidence needs --format html or --format csv".into()))?;
    if format != "html" && format != "csv" {
        return Err(Usage(format!("--format must be html or csv, not {format:?}")).into());
    }
    let (bundle, report, _) = check(&file, args)?;
    let Some(bundle) = bundle else {
        let why = report
            .failures()
            .next()
            .map(|f| f.message.clone())
            .unwrap_or_default();
        return Err(Failure::Error(format!(
            "{} is not a bundle: {}",
            file.display(),
            sanitize(&why)
        )));
    };
    if format == "csv" && report.verdict == Verdict::Failed {
        return Err(Failure::Exit(
            report.exit_code(),
            format!(
                "{} fails verification ({} failure(s)), so its records are not written as a \
                 spreadsheet; `pragmatic verify-evidence` lists the failures, and --format html \
                 writes the report",
                file.display(),
                report.failures().count()
            ),
        ));
    }
    let out = args.path("--out").unwrap_or_else(|| {
        let stem = file
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "evidence".into());
        file.with_file_name(format!("{stem}.{format}"))
    });
    let content = if format == "html" {
        render_evidence(&bundle, &report)
    } else {
        render_csv(&bundle, &report)
    };
    crate::output::write(&out, content.as_bytes())?;
    println!(
        "wrote {} ({}: {}) (exit {})",
        out.display(),
        report.verdict.label(),
        if format == "html" {
            "verification report and timeline"
        } else {
            "one row per entry, each with the verdict"
        },
        report.exit_code()
    );
    match report.exit_code() {
        0 => Ok(()),
        code => Err(Failure::Silent(code)),
    }
}
