//! The landing-page example, runnable: a research agent that plans, probes,
//! and synthesizes - then crashes on step nine of its probe loop, resumes
//! without re-sampling a single journaled step (only the steps it never
//! reached are drawn), and replays bit-for-bit for audit.
//!
//! ```sh
//! cargo run --example research_agent
//! ```

use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

/// Wrap the run. Every oracle call is journaled once, and the program's
/// identity is journaled up front - a run recorded under this version of
/// `research` refuses to replay under a changed one.
///
/// `crash_at` simulates the process dying in the middle of the probe loop.
#[pragmatic::durable]
fn research(ctx: &mut Ctx, crash_at: Option<u32>) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan: survey durable execution for agents")?; // journaled

    let mut findings = Vec::new();
    for step in 0..12 {
        if crash_at == Some(step) {
            return Err(Fault::Io("the process was killed".into()));
        }
        let f = ctx.oracle(format!("probe {step} of plan {plan}"))?; // journaled
        findings.push(f);
    }

    // A durable effect under the write-ahead discipline: intent journaled
    // before the world changes, result journaled after.
    let stored = ctx.effect(
        "publish_report",
        format!("{} findings", findings.len()),
        |arg| Ok(Value::from(format!("s3://reports/{arg}"))),
    )?;

    Ok(Value::from(format!("report at {stored}")))
}

fn main() {
    let dir = std::env::temp_dir().join("pragmatic-research-agent");
    let _ = std::fs::remove_dir_all(&dir);

    // ── Record, and crash on step nine ──────────────────────────────────
    let rt = Runtime::on_dir(&dir, SeededOracle::new(42))
        .expect("journal dir")
        .with_key(b"demo-signing-key");
    let crashed = rt.run("research-42", |ctx: &mut Ctx| research(ctx, Some(9)));
    println!("recorded  : crashed with {}", crashed.unwrap_err());
    drop(rt); // the process is gone

    // ── Recover from any crash ──────────────────────────────────────────
    // New process, same journal dir. Every journaled step (the program
    // identity, the plan and nine probes) is read back from the Journal
    // instead of paid for again; the run continues on step nine.
    let rt = Runtime::on_dir(&dir, SeededOracle::new(42))
        .expect("journal dir")
        .with_key(b"demo-signing-key");
    let resumed = rt
        .resume("research-42", |ctx: &mut Ctx| research(ctx, None))
        .expect("resume");
    println!(
        "resumed   : {} steps replayed from journal, {} recorded fresh",
        resumed.replayed_steps, resumed.fresh_steps
    );
    println!("output    : {}", resumed.output);

    // ── Replay faithfully (T1) ──────────────────────────────────────────
    // Reproduce the whole run for audit. The model is never called.
    let audit = rt
        .replay("research-42", |ctx: &mut Ctx| research(ctx, None))
        .expect("replay");
    assert_eq!(
        audit.trace, resumed.trace,
        "T1: replay reproduces the run exactly"
    );
    println!(
        "replayed  : trace identical, {} steps, zero model calls",
        audit.replayed_steps
    );

    // ── The signed audit trail ──────────────────────────────────────────
    let verified = rt.verify("research-42").unwrap().is_ok();
    let journal = rt.snapshot("research-42").unwrap();
    println!(
        "journal   : {} entries ({} agent steps, the rest attempt notes)",
        journal.len(),
        journal.program_entries().len()
    );
    println!(
        "audit log : hash chain verified = {verified}, head = {}",
        audit
            .chain_head
            .map(|h| pragmatic::sha256::hex(&h)[..16].to_string())
            .unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
