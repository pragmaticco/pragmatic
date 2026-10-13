//! `pragmatic` - journal tooling for the Pragmatic runtime.
//!
//! ```text
//! pragmatic runs   [--dir DIR]                       list runs and their status
//! pragmatic show   RUN [--dir DIR] [--key KEY]       print a run's timeline
//! pragmatic verify RUN|--all [--dir DIR] [--key KEY] check the hash chain
//! pragmatic export RUN [--dir DIR] [--key KEY] [-o FILE]
//!                                                    self-contained HTML replay console
//! pragmatic serve  [--dir DIR] [--key KEY] [--port P]
//!                                                    live web console on localhost
//! ```

mod export;
mod serve;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pragmatic::journal_v1::{Event, Journal, Loaded};
use pragmatic::sha256::hex;

struct Args {
    command: String,
    positional: Vec<String>,
    dir: PathBuf,
    key: Option<String>,
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
    while let Some(a) = argv.next() {
        match a.as_str() {
            "--dir" => args.dir = argv.next().ok_or("--dir needs a value")?.into(),
            "--key" => args.key = Some(argv.next().ok_or("--key needs a value")?),
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
    Ok(args)
}

fn open(path: &Path, key: Option<&str>) -> Result<Loaded, String> {
    let loaded = match key {
        Some(k) => Journal::open_keyed(path, k.as_bytes()),
        None => Journal::open(path),
    };
    loaded.map_err(|e| format!("{}: {e}", path.display()))
}

/// All `*.journal` files under `dir`, as (run_id, path).
fn discover(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut runs = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("journal") {
            let run = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            runs.push((run, path));
        }
    }
    runs.sort();
    Ok(runs)
}

fn event_kind(e: &Event) -> &'static str {
    match e {
        Event::Program { .. } => "program",
        Event::OracleDraw { .. } => "oracle",
        Event::ChannelRecv { .. } => "recv",
        Event::EffectIntent { .. } => "intent",
        Event::EffectCommit { .. } => "commit",
        Event::EffectCompensated { .. } => "compensated",
        Event::Clock { .. } => "clock",
    }
}

fn event_summary(e: &Event, width: usize) -> String {
    let clip = |s: &str| -> String {
        let s = s.replace('\n', " ");
        if s.chars().count() > width {
            let cut: String = s.chars().take(width).collect();
            format!("{cut}…")
        } else {
            s
        }
    };
    match e {
        Event::Program { name, hash } => format!("{name} [{hash}]"),
        Event::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => format!(
            "{} ⟶ {}  ({provenance})",
            clip(&prompt.as_str()),
            clip(&outcome.as_str())
        ),
        Event::ChannelRecv { channel, value } => {
            format!("{channel} ? {}", clip(&value.as_str()))
        }
        Event::EffectIntent { name, arg } => format!("{name}({})", clip(&arg.as_str())),
        Event::EffectCommit { name, result } => {
            format!("{name} ⟶ {}", clip(&result.as_str()))
        }
        Event::EffectCompensated { name } => name.to_string(),
        Event::Clock { nanos } => format!("{nanos} ns"),
    }
}

fn cmd_runs(args: &Args) -> Result<(), String> {
    let runs = discover(&args.dir)?;
    if runs.is_empty() {
        println!("no journals in {}", args.dir.display());
        return Ok(());
    }
    let (c1, c2, c3, c4) = ("RUN", "ENTRIES", "CHAIN", "HEAD");
    println!("{c1:<28} {c2:>8}  {c3:<9} {c4}");
    for (run, path) in runs {
        match open(&path, args.key.as_deref()) {
            Ok(loaded) => {
                let j = loaded.journal;
                let chain = if j.verify().is_ok() {
                    "verified"
                } else {
                    "BROKEN"
                };
                let head = j
                    .head()
                    .map(|h| hex(&h)[..16].to_string())
                    .unwrap_or_else(|| "-".to_string());
                let torn = if loaded.torn_bytes > 0 {
                    format!("  (truncated {} torn bytes)", loaded.torn_bytes)
                } else {
                    String::new()
                };
                println!("{run:<28} {:>8}  {chain:<9} {head}{torn}", j.len());
            }
            Err(e) => println!("{run:<28} {:>8}  {:<9} {e}", "-", "ERROR"),
        }
    }
    Ok(())
}

fn cmd_show(args: &Args) -> Result<(), String> {
    let run = args.positional.first().ok_or("usage: pragmatic show RUN")?;
    let path = args.dir.join(format!("{run}.journal"));
    let loaded = open(&path, args.key.as_deref())?;
    let j = loaded.journal;

    println!("run      : {run}");
    println!("entries  : {}", j.len());
    println!(
        "chain    : {}",
        match j.verify() {
            Ok(()) => "verified".to_string(),
            Err(c) => format!("BROKEN at cursor {c}"),
        }
    );
    if let Some(h) = j.head() {
        println!("head     : {}", hex(&h));
    }
    let dangling = j.dangling_intents();
    if !dangling.is_empty() {
        println!(
            "dangling : {} effect intent(s) without commit - crashed mid-effect",
            dangling.len()
        );
    }
    println!();
    for e in j.entries() {
        println!(
            "{:>6}  {:<12} {}",
            e.cursor,
            event_kind(&e.event),
            event_summary(&e.event, 100)
        );
    }
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<(), String> {
    let targets: Vec<(String, PathBuf)> = if args.all {
        discover(&args.dir)?
    } else {
        let run = args
            .positional
            .first()
            .ok_or("usage: pragmatic verify RUN (or --all)")?;
        vec![(run.clone(), args.dir.join(format!("{run}.journal")))]
    };
    let mut failed = false;
    for (run, path) in targets {
        match open(&path, args.key.as_deref()) {
            Ok(loaded) => match loaded.journal.verify() {
                Ok(()) => println!("{run}: verified ({} entries)", loaded.journal.len()),
                Err(c) => {
                    println!("{run}: HASH CHAIN BROKEN at cursor {c}");
                    failed = true;
                }
            },
            Err(e) => {
                println!("{run}: {e}");
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
    let path = args.dir.join(format!("{run}.journal"));
    let loaded = open(&path, args.key.as_deref())?;
    let html = export::render(run, &loaded.journal);
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
    pragmatic runs   [--dir DIR] [--key KEY]
    pragmatic show   RUN [--dir DIR] [--key KEY]
    pragmatic verify RUN|--all [--dir DIR] [--key KEY]
    pragmatic export RUN [--dir DIR] [--key KEY] [-o FILE]
    pragmatic serve  [--dir DIR] [--key KEY] [--port PORT]

COMMANDS:
    runs      List every run journaled under DIR (default: .)
    show      Print a run's full event timeline
    verify    Walk the tamper-evident hash chain end to end
    export    Write a self-contained HTML replay console for a run
    serve     Live web console on http://127.0.0.1:PORT (default 7171)

OPTIONS:
    --dir DIR    Journal directory (default: current directory)
    --key KEY    HMAC key for keyed (signed) journals
    -o FILE      Output path for export (default: RUN.html)
    --port PORT  Port for serve (loopback only; default 7171)"
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
