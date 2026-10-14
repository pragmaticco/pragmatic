//! Commands over a journal directory: `runs`, `show`, `verify`, `export`
//! and `erase`.
//!
//! Every command but `erase` is read-only: journals are read as snapshots
//! (a torn tail is ignored, never truncated) and nothing is written to the
//! journal directory. `erase` is the one writer, and it goes through the
//! same checkout as an agent, so it holds the run's write lock and cannot
//! race a running attempt.

use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_encode;
use pragmatic::journal::{EraseSelector, ErasureNote, Journal};
use pragmatic::{Backend, DirBackend, VerifyReport};
use pragmatic_console::{render_run_page, text, RunView};

use crate::args::{journal_key, Args, Usage};
use crate::Failure;

/// The backend over an existing directory. The CLI never creates one.
pub fn backend(dir: &Path) -> Result<DirBackend, String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    DirBackend::new(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Read one run's journal as a snapshot.
pub fn open(dir: &Path, run: &str, key: Option<&[u8]>) -> Result<Journal, String> {
    backend(dir)?
        .snapshot(run, key)
        .map_err(|e| format!("{}: {e}", text::sanitize(run)))
}

/// Every run id in `dir`.
pub fn discover(dir: &Path) -> Result<Vec<String>, String> {
    backend(dir)?.list().map_err(|e| e.to_string())
}

const READ_FLAGS: &[&str] = &["--dir", "--key", "--key-file"];

pub fn runs(args: &Args) -> Result<(), Failure> {
    args.only(READ_FLAGS)?;
    if !args.positional.is_empty() {
        return Err(Usage("'runs' takes no run id (try: pragmatic show RUN)".into()).into());
    }
    let key = journal_key(args)?;
    let dir = args.dir();
    let runs = discover(&dir)?;
    if runs.is_empty() {
        println!("no journals in {}", dir.display());
        return Ok(());
    }
    println!(
        "{:<28} {:>3} {:>8} {:>8}  {:<9} {:<8} HEAD",
        "RUN", "FMT", "ENTRIES", "ATTEMPTS", "CHAIN", "LAST"
    );
    for run in runs {
        let name = text::clip(&run, 28);
        match open(&dir, &run, key.as_deref()) {
            Ok(j) => {
                let report = j.audit();
                let row = pragmatic_console::RunRow::from_journal(&run, &j, &report);
                let chain = if report.is_ok() { "verified" } else { "BROKEN" };
                let mut extra = String::new();
                if row.open_intents > 0 {
                    extra.push_str(&format!("  ({} open intent(s))", row.open_intents));
                }
                if j.torn_bytes() > 0 {
                    extra.push_str(&format!("  ({} torn bytes ignored)", j.torn_bytes()));
                }
                println!(
                    "{name:<28} {:>3} {:>8} {:>8}  {chain:<9} {:<8} {}{extra}",
                    j.format(),
                    j.len(),
                    row.attempts,
                    text::clip(row.last_outcome.as_deref().unwrap_or("-"), 8),
                    &hex_encode(&j.head())[..16],
                );
            }
            // The error can quote journal content (a format 1 file name, a
            // run.start run id), so it is printed sanitized.
            Err(e) => println!(
                "{name:<28} {:>3} {:>8} {:>8}  {:<9} {}",
                "-",
                "-",
                "-",
                "ERROR",
                text::sanitize(&e)
            ),
        }
    }
    Ok(())
}

pub fn show(args: &Args) -> Result<(), Failure> {
    args.only(READ_FLAGS)?;
    let run = args.one("RUN")?;
    let key = journal_key(args)?;
    let j = open(&args.dir(), run, key.as_deref())?;
    let report = j.audit();
    println!("run      : {}", text::sanitize(run));
    println!(
        "format   : {}{}",
        j.format(),
        if j.format() == 1 { " (read-only)" } else { "" }
    );
    println!(
        "entries  : {} ({} agent steps, {} attempt(s))",
        j.len(),
        j.program_entries().len(),
        text::attempts(&j)
    );
    println!("verify   : {}", text::verify_line(&report));
    println!("head     : {}", hex_encode(&j.head()));
    if j.torn_bytes() > 0 {
        println!(
            "torn     : {} bytes after the valid prefix (ignored)",
            j.torn_bytes()
        );
    }
    let open = text::open_intents(&j);
    if !open.is_empty() {
        println!(
            "open     : {} intent(s) without a result, first at #{}: interrupted by a crash",
            open.len(),
            open[0]
        );
    }
    println!();
    for e in j.entries() {
        let at = if e.at == 0 {
            String::new()
        } else {
            text::time(e.at).get(11..23).unwrap_or("").to_string()
        };
        let gone = text::erased_slots(e);
        let gone = if gone > 0 {
            format!("  [{gone} slot(s) erased]")
        } else {
            String::new()
        };
        println!(
            "{:>6}  {at:<12} {:<7} {:<18} {}{gone}",
            e.cursor,
            text::branch_label(&e.branch),
            text::label(&e.event),
            text::summary(&e.event, 100)
        );
    }
    Ok(())
}

/// Print a verify report in full.
fn print_report(run: &str, report: &VerifyReport, journal: Option<&Journal>) {
    let list = |slots: &[(u64, u8)]| {
        if slots.is_empty() {
            "none".to_string()
        } else {
            slots
                .iter()
                .map(|(c, s)| format!("{c}:{s}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    };
    println!("{}", text::sanitize(run));
    if let Some(j) = journal {
        println!(
            "  journal               format {}, {} entries, head {}",
            j.format(),
            j.len(),
            hex_encode(&j.head())
        );
    }
    match report.first_bad {
        None => println!("  chain                 every link, commitment and ref verifies"),
        Some(c) => println!("  chain                 BROKEN at cursor {c}"),
    }
    println!(
        "  unaccounted erasures  {}",
        list(&report.unaccounted_erasures)
    );
    println!(
        "  erasure incomplete    {}",
        list(&report.erasure_incomplete)
    );
    let invalid: Vec<String> = report
        .invalid_erasure_notes
        .iter()
        .map(u64::to_string)
        .collect();
    println!(
        "  invalid erasure notes {}",
        if invalid.is_empty() {
            "none".to_string()
        } else {
            invalid.join(" ")
        }
    );
    println!(
        "  torn bytes            {}{}",
        report.torn_bytes,
        if report.torn_bytes > 0 {
            " (after the valid prefix; ignored, never truncated here)"
        } else {
            ""
        }
    );
    println!(
        "  result                {}",
        if report.is_ok() { "verified" } else { "FAILED" }
    );
}

pub fn verify(args: &Args) -> Result<(), Failure> {
    let mut allowed = READ_FLAGS.to_vec();
    allowed.push("--all");
    args.only(&allowed)?;
    let key = journal_key(args)?;
    let dir = args.dir();
    let targets: Vec<String> = if args.has("--all") {
        if !args.positional.is_empty() {
            return Err(Usage("verify takes a RUN or --all, not both".into()).into());
        }
        discover(&dir)?
    } else {
        vec![args.one("RUN (or --all)")?.to_string()]
    };
    let b = backend(&dir)?;
    let mut failed = 0usize;
    for (i, run) in targets.iter().enumerate() {
        if i > 0 {
            println!();
        }
        // The backend's verify reads past corruption to report where it
        // starts, and never writes.
        match b.verify(run, key.as_deref()) {
            Ok(report) => {
                let journal = b.snapshot(run, key.as_deref()).ok();
                print_report(run, &report, journal.as_ref());
                failed += usize::from(!report.is_ok());
            }
            Err(e) => {
                println!(
                    "{}\n  result                FAILED: {}",
                    text::sanitize(run),
                    text::sanitize(&e.to_string())
                );
                failed += 1;
            }
        }
    }
    if failed > 0 {
        Err(Failure::Exit(
            1,
            format!("{failed} run(s) failed verification"),
        ))
    } else {
        Ok(())
    }
}

/// `export RUN [--from CURSOR] [-o FILE]`: one page of the run (a long
/// timeline is split into pages that a browser opens quickly; `--from`
/// picks the page that starts at a cursor).
pub fn export(args: &Args) -> Result<(), Failure> {
    let mut allowed = READ_FLAGS.to_vec();
    allowed.extend(["--out", "--from"]);
    args.only(&allowed)?;
    let run = args.one("RUN")?;
    let from: u64 = args.number("--from")?.unwrap_or(0);
    let key = journal_key(args)?;
    let dir = args.dir();
    let journal = open(&dir, run, key.as_deref())?;
    if from > 0 && from >= journal.len() {
        return Err(Usage(format!(
            "--from {from} is past the run's last entry ({} entries)",
            journal.len()
        ))
        .into());
    }
    let report = journal.audit();
    let source = dir.display().to_string();
    let exported = pragmatic::evidence::time::now_rfc3339();
    let mut view = RunView::new(run, &journal, &report);
    view.source = Some(&source);
    view.from = from;
    view.exported = Some(&exported);
    let page = render_run_page(&view);
    let out = args.path("--out").unwrap_or_else(|| {
        PathBuf::from(if from == 0 {
            format!("{run}.html")
        } else {
            format!("{run}.from-{from}.html")
        })
    });
    crate::output::write(&out, page.html.as_bytes())?;
    match page.next {
        None => println!("wrote {}", out.display()),
        Some(next) => println!(
            "wrote {}: entries #{from} to #{} of {}; the next page: pragmatic export {} --from {next}",
            out.display(),
            next - 1,
            journal.len(),
            text::sanitize(run)
        ),
    }
    Ok(())
}

/// `reason_code` is structural (it is a note field, never erasable), so it
/// is limited to a short code that cannot carry personal data.
fn check_reason_code(code: &str) -> Result<(), Usage> {
    let ok = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.:-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(Usage(
            "--reason-code must be 1 to 64 characters from a-z, 0-9, '_', '.', ':' and '-' \
             (put free text in --reason, which is itself erasable)"
                .into(),
        ))
    }
}

pub fn erase(args: &Args) -> Result<(), Failure> {
    let mut allowed = READ_FLAGS.to_vec();
    allowed.extend(["--cursor", "--slot", "--match", "--reason-code", "--reason"]);
    args.only(&allowed)?;
    let run = args.one("RUN")?;
    let code = args
        .value("--reason-code")
        .ok_or_else(|| Usage("erase needs --reason-code".into()))?;
    check_reason_code(code)?;
    let cursor: Option<u64> = args.number("--cursor")?;
    let slot: Option<u8> = args.number("--slot")?;
    let needle = args.value("--match");
    if cursor.is_some() == needle.is_some() {
        return Err(Usage("erase takes --cursor N [--slot K] or --match TEXT".into()).into());
    }
    if slot.is_some() && cursor.is_none() {
        return Err(Usage("--slot needs --cursor".into()).into());
    }
    let key = journal_key(args)?;
    let backend = backend(&args.dir())?;
    let mut checkout = backend
        .checkout(run, false, key.as_deref())
        .map_err(|e| format!("{}: {e}", text::sanitize(run)))?;
    let selector = match (cursor, slot, needle) {
        (Some(c), Some(s), _) => EraseSelector::Slots(vec![(c, s)]),
        (Some(c), None, _) => {
            let entry = checkout
                .journal
                .get(c)
                .ok_or_else(|| format!("cursor {c} does not exist"))?;
            EraseSelector::Slots((0..entry.slots.len() as u8).map(|s| (c, s)).collect())
        }
        (None, _, Some(text)) => EraseSelector::Match(text.as_bytes().to_vec()),
        _ => unreachable!("checked above"),
    };
    let note = ErasureNote::local(code, args.value("--reason").unwrap_or(""));
    let erased = checkout
        .erase(&selector, &note)
        .map_err(|e| format!("{}: {e}", text::sanitize(run)))?;
    let note_cursor = checkout.journal.len() - 1;
    drop(checkout);
    println!(
        "erased {} slot(s) of {}: {}",
        erased.len(),
        text::sanitize(run),
        erased
            .iter()
            .map(|(c, s)| format!("{c}:{s}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "erasure note at cursor {note_cursor}: by {} (unauthenticated), reason {code}",
        text::sanitize(&note.by)
    );
    println!("every chain hash is unchanged; `pragmatic verify` accounts for the erased slots");
    Ok(())
}
