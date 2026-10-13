//! Seed a demo journal directory so you can try the CLI without wiring a
//! model:
//!
//! ```sh
//! cargo run -p pragmatic-cli --example seed_demo -- ./demo-journals
//! cargo run -p pragmatic-cli -- runs --dir ./demo-journals
//! cargo run -p pragmatic-cli -- export research-42 --dir ./demo-journals -o run.html
//! ```

use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan: survey durable execution for agents")?;
    let mut findings = Vec::new();
    for step in 0..4 {
        findings.push(ctx.oracle(format!("probe {step} of plan {plan}"))?);
    }
    let t = ctx.now()?;
    ctx.effect(
        "publish_report",
        format!("{} findings @{t}", findings.len()),
        |arg| Ok(Value::from(format!("s3://reports/{arg}"))),
    )
}

fn failing(ctx: &mut Ctx) -> Result<Value, Fault> {
    let x = ctx.oracle("draw")?;
    ctx.effect("charge_card", x.as_str().into_owned(), |_| {
        Err(Fault::ToolErr("connection dropped mid-flight".into()))
    })
}

fn parallel(ctx: &mut Ctx) -> Result<Value, Fault> {
    let picks = ctx.parallel(3, |i, c| c.oracle(format!("candidate {i}")))?;
    let joined: Vec<String> = picks.iter().map(|v| v.as_str().into_owned()).collect();
    ctx.oracle(format!("pick the best of: {}", joined.join(" | ")))
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./demo-journals".to_string());

    let rt = Runtime::on_dir(&dir, SeededOracle::new(42)).expect("journal dir");
    rt.run("research-42", research).expect("run");
    let _ = rt.run("payment-7", failing); // fails on purpose: a failed effect
    rt.run("best-of-3", parallel).expect("run");

    println!("seeded {dir} with:");
    println!("  research-42  - a completed run");
    println!("  payment-7    - a tool call that failed, recorded as a failed effect");
    println!("  best-of-3    - a parallel region of three branches");
}
