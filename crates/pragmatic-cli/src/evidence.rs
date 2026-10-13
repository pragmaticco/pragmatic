//! `evidence`, `verify-evidence` and `render-evidence` (design 5 and 7).
//!
//! `evidence` packages a local run as a bundle. `verify-evidence` checks a
//! bundle against trust the auditor supplies on the command line (pinned
//! TSA roots, witness keys and log keys) and exits with the verdict's code:
//! 0 verified, 2 verified for a prefix only, 3 unanchored, 1 failed.
//! `render-evidence` turns a bundle into a page or a spreadsheet.
//!
//! Every string in a report that came from the bundle is printed through
//! `text::sanitize`, so a bundle cannot put escape sequences on the
//! auditor's terminal or forge lines of the report.

use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_decode_exact;
use pragmatic::evidence::{
    self, AnchorLog, Audit, Bundle, CheckStatus, EvidenceReport, NoTsaVerifier, Redact, Severity,
    SignatureStatus, TrustPolicy, TsaRoot, TsaVerifier, Verdict, VerificationSpec, WitnessClass,
    WitnessKey, WitnessLog, DIRECTORY_BUNDLE_FILE, DIRECTORY_THRESHOLD,
};
use pragmatic::note::{SignatureType, VerifierKey};
use pragmatic::redact::Kind;
use pragmatic::sha256::sha256;
use pragmatic::Backend;
use pragmatic_console::text::sanitize;
use pragmatic_console::{render_csv, render_evidence};

use crate::args::{journal_key, Args, Usage};
use crate::journals::backend;
use crate::openssl::OpenSslTsa;
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

/// The hosted Pragmatic Witness keys, with validity windows (Unix
/// seconds): `(operator, vkey, not_before, not_after)`. Empty until the
/// witness launches (design 5.2).
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
             by Pragmatic Server)"
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
        std::fs::write(&out, json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
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
fn read_vkey(value: &str) -> Result<VerifierKey, String> {
    let text = if value.contains('+') {
        value.to_string()
    } else {
        std::fs::read_to_string(value).map_err(|e| format!("cannot read key file {value}: {e}"))?
    };
    VerifierKey::parse(text.trim()).map_err(|e| format!("{value}: {e}"))
}

/// `--witness-key NAME=VKEY` (or `NAME=HEX`, a 32-byte cosignature key
/// whose cosigner name is `NAME`). `NAME` is the operator the witness
/// counts for.
fn witness_key(value: &str) -> Result<WitnessKey, String> {
    let (operator, key) = value
        .split_once('=')
        .ok_or_else(|| format!("--witness-key takes NAME=VKEY, not {value:?}"))?;
    if operator.trim().is_empty() {
        return Err("--witness-key needs an operator name before '='".into());
    }
    let key = match hex_decode_exact::<32>(key) {
        Ok(raw) => VerifierKey::new(operator, SignatureType::CosignatureV1, raw)
            .map_err(|e| format!("--witness-key {operator}: {e}"))?,
        Err(_) => read_vkey(key)?,
    };
    if key.signature_type() != SignatureType::CosignatureV1 {
        return Err(format!(
            "--witness-key {operator}: a witness key must be a cosignature/v1 key (type 0x04)"
        ));
    }
    Ok(WitnessKey {
        operator: operator.to_string(),
        key,
        not_before: None,
        not_after: None,
    })
}

/// `--tsa-roots [OPERATOR=]FILE`: the operator defaults to the file's
/// name without its extension.
fn tsa_root(value: &str) -> Result<TsaRoot, String> {
    let (operator, path) = match value.split_once('=') {
        Some((op, p)) if !Path::new(value).exists() => (op.to_string(), PathBuf::from(p)),
        _ => {
            let p = PathBuf::from(value);
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            (stem, p)
        }
    };
    if !path.is_file() {
        return Err(format!("--tsa-roots: {} is not a file", path.display()));
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
            return Err(Failure::Error(format!(
                "--log-key {}: a log key must be an Ed25519 note key (type 0x01)",
                sanitize(v)
            )));
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

fn audit(args: &Args) -> Result<Audit, Failure> {
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"));
    let log = match args.value("--log") {
        Some(p) => Some(AnchorLog::from_json(&read(p)?).map_err(|e| format!("--log {p}: {e}"))?),
        None => None,
    };
    let mut witness_logs = Vec::new();
    for p in args.values("--witness-log") {
        witness_logs
            .push(WitnessLog::from_json(&read(p)?).map_err(|e| format!("--witness-log {p}: {e}"))?);
    }
    Ok(Audit { log, witness_logs })
}

/// The TSA verifier: OpenSSL when it is on `PATH` (required with
/// `--openssl`), nothing with `--no-openssl`.
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
    match OpenSslTsa::from_path() {
        Some(o) => {
            let about = format!(
                "{} ({})",
                o.bin().display(),
                o.version().unwrap_or_else(|| "version unknown".into())
            );
            Ok((Box::new(o), about))
        }
        None if args.has("--openssl") => {
            Err(Failure::Error("--openssl: no openssl on PATH".into()))
        }
        None => Ok((
            Box::new(NoTsaVerifier),
            "not found on PATH: RFC 3161 tokens are not checked".into(),
        )),
    }
}

/// Read a bundle file, or a directory bundle.
fn load(path: &Path) -> Result<Vec<u8>, String> {
    let file = if path.is_dir() {
        path.join(DIRECTORY_BUNDLE_FILE)
    } else {
        path.to_path_buf()
    };
    std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))
}

/// Parse and verify, attaching a directory bundle's journal file.
fn check(path: &Path, args: &Args) -> Result<(Option<Bundle>, EvidenceReport, String), Failure> {
    let policy = policy(args)?;
    let audit = audit(args)?;
    let (tsa, about) = tsa(args)?;
    let bytes = load(path)?;
    let (bundle, report) = match Bundle::from_json(&bytes) {
        Ok(mut b) => {
            if path.is_dir() {
                if let evidence::JournalEncoding::File { path: name, .. } = &b.journal.encoding {
                    let journal = std::fs::read(path.join(name))
                        .map_err(|e| format!("cannot read the bundle's journal file: {e}"))?;
                    b.attach_journal(journal)?;
                }
            }
            let r = evidence::verify_with(&b, &policy, tsa.as_ref(), &audit);
            (Some(b), r)
        }
        Err(_) => evidence::verify_bytes(&bytes, &policy, tsa.as_ref(), &audit),
    };
    Ok((bundle, report, about))
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
    if let Some(b) = bundle {
        println!("run        {}", sanitize(&b.run_id));
        println!(
            "journal    {} entries, {} withheld slot(s), redaction {}",
            r.entries,
            b.redacted_slots.len(),
            sanitize(&b.redaction.mode)
        );
        println!(
            "generator  {} for {} (unsigned claims)",
            sanitize(&b.generator),
            sanitize(&b.requested_by)
        );
        if let Some(s) = &b.verification_spec {
            let ours = spec().sha256;
            let note = if s.sha256 == ours {
                "the procedure this verifier ships"
            } else {
                "differs from the procedure this verifier ships (see --explain)"
            };
            println!("spec       {} ({note})", sanitize(&s.url));
        }
    }
    let sig = match &r.bundle_signature {
        SignatureStatus::Verified { key } => {
            format!("verified with pinned log key {}", sanitize(key))
        }
        SignatureStatus::OperatorAsserted => {
            "valid for a key that is not pinned: operator-asserted (pass --log-key)".into()
        }
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
        Verdict::Failed => format!("{} integrity failure(s)", r.failures().count()),
    };
    println!("{}: {summary} (exit {})", r.verdict.label(), r.exit_code());
}

// ---------------------------------------------------------------------------
// render-evidence FILE --format html|csv
// ---------------------------------------------------------------------------

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
        if report.verdict == Verdict::Failed {
            eprintln!(
                "warning: the bundle fails verification; the CSV shows its records as stated"
            );
        }
        render_csv(&bundle)
    };
    std::fs::write(&out, content).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "wrote {} ({}: {})",
        out.display(),
        report.verdict.label(),
        if format == "html" {
            "verification report and timeline"
        } else {
            "one row per record"
        }
    );
    Ok(())
}
