//! A live durable run against the Anthropic API. Requires
//! `ANTHROPIC_API_KEY`; exits gracefully without it.
//!
//! ```sh
//! ANTHROPIC_API_KEY=... cargo run --release -p pragmatic-anthropic --example live_research
//! ```
//!
//! Run it, kill it mid-run (^C), run it again: the journal picks up exactly
//! where it stopped - the completions already paid for are read back, not
//! re-sampled.

use pragmatic::{Ctx, Fault, Runtime, Value};
use pragmatic_anthropic::AnthropicOracle;

fn brief(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle(
        "In exactly three numbered bullet points, plan a one-paragraph brief on \
         why durable execution matters for LLM agents. Terse.",
    )?;
    println!("── plan ──\n{plan}\n");

    let mut notes = Vec::new();
    for step in 1..=3 {
        let note = ctx.oracle(format!(
            "One sentence executing step {step} of this plan:\n{plan}"
        ))?;
        println!("── step {step} ──\n{note}\n");
        notes.push(note.as_str().into_owned());
    }

    ctx.oracle(format!(
        "Synthesize these notes into a single crisp paragraph:\n{}",
        notes.join("\n")
    ))
}

fn main() {
    let Ok(oracle) = AnthropicOracle::from_env() else {
        eprintln!("ANTHROPIC_API_KEY not set - skipping live example.");
        return;
    };
    let oracle = oracle.model("claude-sonnet-5").max_tokens(400);

    let dir = std::env::temp_dir().join("pragmatic-live");
    let rt = Runtime::on_dir(&dir, oracle).expect("journal dir");

    let report = rt.run("live-brief", brief).expect("run");
    println!("═══ final ═══\n{}\n", report.output);
    println!(
        "{} journal entries ({} steps replayed from a previous attempt, {} fresh model calls)",
        report.journal_len, report.replayed_steps, report.fresh_steps
    );
    let backend = pragmatic::DirBackend::new(&dir).expect("journal dir");
    println!("journal: {}", backend.journal_path("live-brief").display());

    // The audit replay never touches the API.
    let audit = rt.replay("live-brief", brief).expect("replay");
    assert_eq!(audit.trace, report.trace);
    println!("audit replay: exact, zero API calls");
}
