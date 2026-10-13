//! `pragmatic`: tooling for Pragmatic journals and evidence bundles.
//!
//! ```text
//! pragmatic runs             list runs and their status
//! pragmatic show RUN         print a run's timeline
//! pragmatic verify RUN|--all check chains, commitments and erasures
//! pragmatic export RUN       write a run's page as self-contained HTML
//! pragmatic serve            live console on localhost
//! pragmatic erase RUN        erase slots, keeping the chain verifiable
//! pragmatic evidence RUN     package a run as an evidence bundle
//! pragmatic verify-evidence  verify a bundle against pinned trust roots
//! pragmatic render-evidence  a bundle as HTML or CSV
//! ```
//!
//! Every command except `erase` is read-only: journals are read as
//! snapshots (a torn tail is ignored, never truncated). Format 2 journals
//! and read-only format 1 journals (0.4, 0.5) are both understood.
//!
//! The CLI makes no network connections, and has no dependencies beyond
//! the core and console crates.

mod args;
mod evidence;
mod journals;
mod openssl;
mod serve;

use std::process::ExitCode;

use args::{journal_key, Args, Usage};

/// How a command ends when it does not succeed.
#[derive(Debug)]
pub enum Failure {
    /// Bad arguments: exit 64, with the message.
    Usage(String),
    /// A failure with a message: exit 1.
    Error(String),
    /// A specific exit code, with a message.
    Exit(u8, String),
    /// A specific exit code; the command already printed why.
    Silent(u8),
}

impl From<Usage> for Failure {
    fn from(u: Usage) -> Failure {
        Failure::Usage(u.0)
    }
}

impl From<String> for Failure {
    fn from(e: String) -> Failure {
        Failure::Error(e)
    }
}

fn serve(args: &Args) -> Result<(), Failure> {
    args.only(&["--dir", "--key", "--key-file", "--port"])?;
    let port = args.number::<u16>("--port")?.unwrap_or(7171);
    let key = journal_key(args)?;
    serve::serve(args.dir(), key, port).map_err(Failure::Error)
}

const HELP: &str = "pragmatic - tooling for Pragmatic journals and evidence bundles

USAGE:
    pragmatic runs    [--dir DIR]
    pragmatic show    RUN [--dir DIR]
    pragmatic verify  RUN|--all [--dir DIR]
    pragmatic export  RUN [--dir DIR] [-o FILE]
    pragmatic serve   [--dir DIR] [--port PORT]
    pragmatic erase   RUN (--cursor N [--slot K] | --match TEXT) --reason-code CODE
                      [--reason TEXT] [--dir DIR]
    pragmatic evidence RUN -o FILE [--dir DIR] [--redact none|detectors|binary|all]
                      [--detectors NAME,...] [--withhold CURSOR:SLOT]...
    pragmatic verify-evidence FILE [--tsa-roots [OPERATOR=]PEM]...
                      [--witness-key OPERATOR=VKEY]... [--log-key VKEY]...
                      [--min-operators N] [--log FILE] [--witness-log FILE]...
                      [--openssl | --no-openssl]
    pragmatic verify-evidence --explain
    pragmatic render-evidence FILE --format html|csv [-o FILE] [trust flags as above]

COMMANDS:
    runs             List every run journaled under DIR
    show             Print a run's timeline: attempts, branches, steps, notes
    verify           Print the full verification report; never writes
    export           Write a self-contained HTML page of a run
    serve            Live console on http://127.0.0.1:PORT (default 7171)
    erase            Erase slot content under the run's write lock; records an
                     erasure note by local:<user>@<host>, unauthenticated
    evidence         Write a local evidence bundle (unanchored, unsigned)
    verify-evidence  Verify a bundle offline against the roots and keys you pin.
                     Exit 0 VERIFIED, 2 VERIFIED (PARTIAL), 3 UNANCHORED, 1 FAILED
    render-evidence  Write a bundle's verification report and timeline (html)
                     or its records (csv)

OPTIONS:
    --dir DIR        Journal directory (default: the current directory)
    --key-file FILE  HMAC key for keyed journals (or PRAGMATIC_JOURNAL_KEY)
    --key KEY        Deprecated: puts the key on the command line
    -o, --out FILE   Output path
    --tsa-roots      A pinned TSA root PEM; tokens it verifies count for
                     OPERATOR (default: the file name)
    --witness-key    A pinned witness key (C2SP vkey, or 64 hex digits), counted
                     for OPERATOR
    --log-key        The log's pinned key (C2SP vkey or a file holding one);
                     checks checkpoint and bundle signatures
    --min-operators  Distinct trusted operators an anchor needs (default 2)
    --log FILE       The full anchor log, to find anchors a bundle leaves out
    --witness-log    A witness's cosigned history, to find split views
    --openssl        Require openssl for RFC 3161 tokens (default: use it if on PATH)
    --explain        Print the verification procedure this verifier implements

Usage errors exit 64. Nothing in a bundle is ever trusted: trust comes only from
the roots and keys given on the command line.";

fn dispatch(args: &Args) -> Result<(), Failure> {
    if args.has("--help") {
        println!("{HELP}");
        return Ok(());
    }
    match args.command.as_str() {
        "runs" => journals::runs(args),
        "show" => journals::show(args),
        "verify" => journals::verify(args),
        "export" => journals::export(args),
        "serve" => serve(args),
        "erase" => journals::erase(args),
        "evidence" => evidence::build(args),
        "verify-evidence" => evidence::verify(args),
        "render-evidence" => evidence::render(args),
        "help" => {
            println!("{HELP}");
            Ok(())
        }
        other => Err(Failure::Usage(format!(
            "unknown command '{}' (try: pragmatic help)",
            pragmatic_console::text::sanitize(other)
        ))),
    }
}

fn main() -> ExitCode {
    let result = Args::parse(std::env::args().skip(1))
        .map_err(Failure::from)
        .and_then(|args| dispatch(&args));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(m)) => {
            eprintln!("error: {m}");
            ExitCode::from(64)
        }
        Err(Failure::Error(m)) => {
            eprintln!("error: {m}");
            ExitCode::FAILURE
        }
        Err(Failure::Exit(code, m)) => {
            eprintln!("error: {m}");
            ExitCode::from(code)
        }
        Err(Failure::Silent(code)) => ExitCode::from(code),
    }
}
