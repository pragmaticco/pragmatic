//! Case study CS1 (paper §6.2): **map-reduce summarization** across
//! coordinated runs, with per-agent recovery.
//!
//! Three mapper runs each summarize a shard; a reducer run receives their
//! summaries over channels and synthesizes the final answer. Every receive
//! is journaled, so when one mapper crashes it recovers from *its own*
//! journal without unwinding the others - and the reducer replays exactly.
//!
//! ```sh
//! cargo run -p pragmatic --example map_reduce
//! ```

use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

const SHARDS: [&str; 3] = [
    "shard A: 40 pages on process calculi",
    "shard B: 25 pages on probabilistic semantics",
    "shard C: 31 pages on durable execution engines",
];

fn mapper(ctx: &mut Ctx, shard: &str) -> Result<Value, Fault> {
    ctx.oracle(format!("summarize {shard} in one line"))
}

fn reducer(ctx: &mut Ctx) -> Result<Value, Fault> {
    let mut summaries = Vec::new();
    for i in 0..SHARDS.len() {
        // Receives are journaled ([Rcv-rec]) - replay is exact even though
        // arrival order is scheduler-determined.
        summaries.push(ctx.recv(&format!("mapper-{i}"))?);
    }
    let joined = summaries
        .iter()
        .map(|s| s.as_str().into_owned())
        .collect::<Vec<_>>()
        .join("; ");
    ctx.oracle(format!("synthesize a survey from: {joined}"))
}

fn main() {
    let rt = Runtime::in_memory(SeededOracle::new(2026));

    // ── Map phase: one durable run per shard ────────────────────────────
    let mut summaries = Vec::new();
    for (i, shard) in SHARDS.iter().enumerate() {
        let run_id = format!("mapper-{i}");
        let report = rt.run(&run_id, |ctx| mapper(ctx, shard)).expect("mapper");
        summaries.push(report.output);
    }

    // Simulate mapper-1 crashing after its work was journaled: recovery
    // reads its journal; the other mappers are untouched.
    let recovered = rt
        .resume("mapper-1", |ctx| mapper(ctx, SHARDS[1]))
        .expect("recover");
    assert_eq!(recovered.output, summaries[1]);
    assert_eq!(recovered.fresh_steps, 0, "recovery re-sampled nothing");
    println!("mapper-1 recovered from its own journal (0 fresh model calls)\n");

    // ── Reduce phase: deliver summaries over channels ───────────────────
    for (i, s) in summaries.iter().enumerate() {
        rt.send("reducer", &format!("mapper-{i}"), s.clone());
    }
    let report = rt.run("reducer", reducer).expect("reducer");
    println!("survey: {}\n", report.output);

    // ── Audit: the reducer replays exactly, inbox empty, model untouched ─
    let audit = rt.replay("reducer", reducer).expect("audit replay");
    assert_eq!(audit.trace, report.trace);
    println!(
        "audit replay: exact ({} steps from journal, {} model calls)",
        audit.replayed_steps, audit.fresh_steps
    );
}
