//! Case study CS4 (paper §6.1): **tool use with retries and crash recovery.**
//!
//! An agent drafts a query, calls a flaky external tool as a durable effect,
//! and synthesizes an answer - under a Supervisor that restarts transient
//! faults from the journal. The tool fails twice before succeeding; each
//! failure is recorded, and each restart replays the journaled prefix (no
//! re-drafting, no duplicate model calls) and retries only the failed step.
//!
//! ```sh
//! cargo run -p pragmatic --example tool_use_retries
//! ```

use std::cell::Cell;
use std::rc::Rc;

use pragmatic::{Ctx, Fault, RunOptions, Runtime, SeededOracle, Supervisor, Value};

fn main() {
    // A tool that fails its first two invocations - a rate-limited search
    // API, say. `Rc<Cell>` stands in for the outside world's state.
    let attempts = Rc::new(Cell::new(0u32));
    let tool_attempts = attempts.clone();

    let agent = move |ctx: &mut Ctx| -> Result<Value, Fault> {
        let query = ctx.oracle("draft a search query about durable execution")?;

        let results = ctx.effect("search_api", query.as_str().into_owned(), |q| {
            let n = tool_attempts.get() + 1;
            tool_attempts.set(n);
            if n <= 2 {
                Err(Fault::ToolErr(format!(
                    "attempt {n}: 429 too many requests"
                )))
            } else {
                Ok(Value::from(format!("3 documents for '{q}'")))
            }
        })?;

        ctx.oracle(format!("synthesize an answer from: {results}"))
    };

    let rt = Runtime::in_memory(SeededOracle::new(7));
    let mut sup = Supervisor::new().max_restarts(5);

    let report = sup
        .supervise(&rt, "cs4", RunOptions::default().with_budget(50), agent)
        .expect("supervised run completes");

    println!(
        "tool attempts   : {} (failed twice, then succeeded)",
        attempts.get()
    );
    println!("output          : {}", report.output);
    println!(
        "final attempt   : {} steps replayed from journal, {} fresh",
        report.replayed_steps, report.fresh_steps
    );
    println!("journal entries : {}", report.journal_len);

    // The journal shows the whole story: one draft draw, two failed tool
    // calls (each retried on restart, with a recovery note saying so), one
    // committed tool call and one synthesis draw.
    assert_eq!(attempts.get(), 3);
    let journal = rt.snapshot("cs4").expect("snapshot");
    let retries = journal
        .entries()
        .iter()
        .filter(|e| e.event.note_kind() == Some("recovery"))
        .count();
    println!("retried calls   : {retries} (recorded as recovery notes)");
    assert_eq!(retries, 2);
}
