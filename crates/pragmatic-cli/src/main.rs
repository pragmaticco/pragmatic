//! `pragmatic`: journal tooling for the Pragmatic runtime.
//!
//! ```text
//! pragmatic runs   [--dir DIR]                         list runs and their status
//! pragmatic show   RUN [--dir DIR] [--key-file FILE]   print a run's timeline
//! pragmatic verify RUN|--all [--dir DIR] [--key-file FILE]
//!                                                      check chain, commitments, erasures
//! pragmatic export RUN [--dir DIR] [--key-file FILE] [-o FILE]
//!                                                      self-contained HTML replay console
//! pragmatic serve  [--dir DIR] [--key-file FILE] [--port P]
//!                                                      live web console on localhost
//! ```
//!
//! Every command is read-only: journals are read as snapshots (a torn tail
//! is ignored, never truncated) and nothing is ever written to a journal
//! directory. Format 2 journals and read-only format 1 journals (0.4, 0.5)
//! are both understood.

mod export;
mod serve;
mod view;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pragmatic::journal::Journal;
use pragmatic::sha256::hex;
use pragmatic::{Backend, DirBackend};

struct Args {
    command: String,
    positional: Vec<String>,
    dir: PathBuf,
    key: Option<Vec<u8>>,
    out: Option<PathBuf>,
    all: bool,
    port: u16,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let command = argv.next().unwrap_or_else(|| "help".to_string());
    let mut args = Args {
        command,
        positional: Vec::new(),
        dir: PathBuf::from("."),
        key: None,
        out: None,
        all: false,
        port: 7171,
    };
    let mut key_flag: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    while let Some(a) = argv.next() {
        match a.as_str() {
            "--dir" => args.dir = argv.next().ok_or("--dir needs a value")?.into(),
            "--key" => key_flag = Some(argv.next().ok_or("--key needs a value")?),
            "--key-file" => key_file = Some(argv.next().ok_or("--key-file needs a value")?.into()),
            "-o" | "--out" => args.out = Some(argv.next().ok_or("-o needs a value")?.into()),
            "--all" => args.all = true,
            "--port" => {
                args.port = argv
                    .next()
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|_| "--port must be a number".to_string())?
            }
            "-h" | "--help" => {
                args.command = "help".to_string();
            }
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => args.positional.push(other.to_string()),
        }
    }
    args.key = journal_key(key_flag, key_file)?;
    Ok(args)
}

/// The HMAC key for keyed journals: `--key-file`, else
/// `PRAGMATIC_JOURNAL_KEY`, else the deprecated `--key` (which puts the
/// secret in the process list, so it warns).
fn journal_key(flag: Option<String>, file: Option<PathBuf>) -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = file {
        let mut bytes = std::fs::read(&path)
            .map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
        while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            bytes.pop();
        }
        return Ok(Some(bytes));
    }
    if let Some(k) = flag {
        eprintln!(
            "warning: --key exposes the key to other users of this machine; \
             use --key-file or PRAGMATIC_JOURNAL_KEY"
        );
        return Ok(Some(k.into_bytes()));
    }
    Ok(std::env::var("PRAGMATIC_JOURNAL_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .map(String::into_bytes))
}

/// The backend over an existing directory. The CLI never creates one.
fn backend(dir: &Path) -> Result<DirBackend, String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    DirBackend::new(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Read one run's journal as a snapshot.
fn open(dir: &Path, run: &str, key: Option<&[u8]>) -> Result<Journal, String> {
    backend(dir)?
        .snapshot(run, key)
        .map_err(|e| format!("{run}: {e}"))
}

/// Every run id in `dir`.
fn discover(dir: &Path) -> Result<Vec<String>, String> {
    backend(dir)?.list().map_err(|e| e.to_string())
}

fn cmd_runs(args: &Args) -> Result<(), String> {
    let runs = discover(&args.dir)?;
    if runs.is_empty() {
        println!("no journals in {}", args.dir.display());
        return Ok(());
    }
    let (c1, c2, c3, c4, c5) = ("RUN", "FMT", "ENTRIES", "STATUS", "HEAD");
    println!("{c1:<28} {c2:>3} {c3:>8}  {c4:<9} {c5}");
    for run in runs {
        match open(&args.dir, &run, args.key.as_deref()) {
            Ok(j) => {
                let status = if j.audit().is_ok() {
                    "verified"
                } else {
                    "BROKEN"
                };
                let head = hex(&j.head())[..16].to_string();
                let mut extra = String::new();
                let open = view::open_intents(&j).len();
                if open > 0 {
                    extra.push_str(&format!("  ({open} open intent(s))"));
                }
                if j.torn_bytes() > 0 {
                    extra.push_str(&format!("  ({} torn bytes ignored)", j.torn_bytes()));
                }
                println!(
                    "{run:<28} {:>3} {:>8}  {status:<9} {head}{extra}",
                    j.format(),
                    j.len()
                );
            }
            Err(e) => println!("{run:<28} {:>3} {:>8}  {:<9} {e}", "-", "-", "ERROR"),
        }
    }
    Ok(())
}

fn cmd_show(args: &Args) -> Result<(), String> {
    let run = args.positional.first().ok_or("usage: pragmatic show RUN")?;
    let j = open(&args.dir, run, args.key.as_deref())?;
    let report = j.audit();

    println!("run      : {run}");
    println!("format   : {}", j.format());
    println!(
        "entries  : {} ({} agent steps)",
        j.len(),
        j.program_entries().len()
    );
    println!("verify   : {}", view::verify_line(&report));
    println!("head     : {}", hex(&j.head()));
    if j.torn_bytes() > 0 {
        println!(
            "torn     : {} bytes after the valid prefix (ignored)",
            j.torn_bytes()
        );
    }
    let open = view::open_intents(&j);
    if !open.is_empty() {
        println!(
            "open     : {} intent(s) without a result, first at cursor {}: interrupted by a crash",
            open.len(),
            open[0]
        );
    }
    println!();
    for e in j.entries() {
        let erased = view::erased_slots(e);
        let erased = if erased > 0 {
            format!("  [{erased} slot(s) erased]")
        } else {
            String::new()
        };
        println!(
            "{:>6}  {:<6} {:<18} {}{erased}",
            e.cursor,
            view::branch_label(&e.branch),
            view::label(&e.event),
            view::summary(&e.event, 100)
        );
    }
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<(), String> {
    let targets: Vec<String> = if args.all {
        discover(&args.dir)?
    } else {
        let run = args
            .positional
            .first()
            .ok_or("usage: pragmatic verify RUN (or --all)")?;
        vec![run.clone()]
    };
    let mut failed = false;
    for run in targets {
        match open(&args.dir, &run, args.key.as_deref()) {
            Ok(j) => {
                let report = j.audit();
                let torn = if report.torn_bytes > 0 {
                    format!(", {} torn bytes ignored", report.torn_bytes)
                } else {
                    String::new()
                };
                println!(
                    "{run}: {} ({} entries, format {}{torn})",
                    view::verify_line(&report),
                    j.len(),
                    j.format()
                );
                failed |= !report.is_ok();
            }
            Err(e) => {
                println!("{e}");
                failed = true;
            }
        }
    }
    if failed {
        Err("verification failed".to_string())
    } else {
        Ok(())
    }
}

fn cmd_export(args: &Args) -> Result<(), String> {
    let run = args
        .positional
        .first()
        .ok_or("usage: pragmatic export RUN [-o FILE]")?;
    let journal = open(&args.dir, run, args.key.as_deref())?;
    let html = export::render(run, &journal);
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{run}.html")));
    std::fs::write(&out, html).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("wrote {}", out.display());
    Ok(())
}

fn help() {
    println!(
        "pragmatic - journal tooling for the Pragmatic durable-execution runtime

USAGE:
    pragmatic runs   [--dir DIR] [--key-file FILE]
    pragmatic show   RUN [--dir DIR] [--key-file FILE]
    pragmatic verify RUN|--all [--dir DIR] [--key-file FILE]
    pragmatic export RUN [--dir DIR] [--key-file FILE] [-o FILE]
    pragmatic serve  [--dir DIR] [--key-file FILE] [--port PORT]

COMMANDS:
    runs      List every run journaled under DIR (default: .)
    show      Print a run's full timeline: branches, steps, notes, erased slots
    verify    Check every chain link, commitment and erasure; never writes
    export    Write a self-contained HTML replay console for a run
    serve     Live web console on http://127.0.0.1:PORT (default 7171)

OPTIONS:
    --dir DIR        Journal directory (default: current directory)
    --key-file FILE  HMAC key for keyed journals (or PRAGMATIC_JOURNAL_KEY)
    --key KEY        Deprecated: puts the key on the command line
    -o FILE          Output path for export (default: RUN.html)
    --port PORT      Port for serve (loopback only; default 7171)"
    );
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = match args.command.as_str() {
        "runs" => cmd_runs(&args),
        "show" => cmd_show(&args),
        "verify" => cmd_verify(&args),
        "export" => cmd_export(&args),
        "serve" => serve::serve(args.dir.clone(), args.key.clone(), args.port),
        "help" | "--help" | "-h" => {
            help();
            Ok(())
        }
        other => Err(format!("unknown command '{other}' (try: pragmatic help)")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
