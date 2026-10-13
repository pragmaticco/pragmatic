//! A real tool-use agent, durable end to end: Claude decides when to call
//! tools, each tool runs as a write-ahead journaled effect, and the whole
//! loop - model turns and tool results - records, resumes, and replays.
//!
//! ```sh
//! ANTHROPIC_API_KEY=... cargo run -p pragmatic-anthropic --example tool_loop
//! ```
//!
//! After the run, point the console at it:
//!
//! ```sh
//! pragmatic serve --dir ./journals
//! ```

use pragmatic::{Ctx, Fault, Runtime, Value};
use pragmatic_anthropic::{AnthropicOracle, Conversation, Turn};
use serde_json::json;

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let mut convo = Conversation::user(
        "What is 1729 divided by 7? Use the calculator tool, then answer in one sentence.",
    );
    loop {
        let turn = Turn::parse(&ctx.oracle(convo.prompt())?)?; // journaled draw
        convo.push_assistant(&turn);
        if !turn.wants_tools() {
            return Ok(Value::from(turn.text()));
        }
        for call in turn.tool_uses() {
            // The tool is a durable effect: intent journaled before it runs,
            // result journaled after. Replay never re-runs it.
            let result = ctx.effect(&call.name, call.input.to_string(), |input| {
                let parsed: serde_json::Value = serde_json::from_str(&input.as_str())
                    .map_err(|e| Fault::ToolErr(e.to_string()))?;
                let (a, b) = (parsed["a"].as_f64(), parsed["b"].as_f64());
                match (a, b) {
                    (Some(a), Some(b)) if b != 0.0 => Ok(Value::from(format!("{}", a / b))),
                    _ => Err(Fault::ToolErr("calculator needs numeric a and b".into())),
                }
            })?;
            convo.push_tool_result(&call.id, result.as_str());
        }
    }
}

fn main() {
    let Ok(oracle) = AnthropicOracle::from_env() else {
        eprintln!("Set ANTHROPIC_API_KEY to run this example against the live API.");
        eprintln!("The same loop is proved keylessly on every CI run:");
        eprintln!("  cargo test -p pragmatic-anthropic --test wire tool_loop");
        return;
    };
    let oracle = oracle
        .model("claude-sonnet-5")
        .max_tokens(1024)
        .tools(json!([{
            "name": "divide",
            "description": "Divide a by b.",
            "input_schema": {
                "type": "object",
                "properties": { "a": { "type": "number" }, "b": { "type": "number" } },
                "required": ["a", "b"]
            }
        }]));

    let rt = Runtime::on_dir("./journals", oracle).expect("journal dir");

    let recorded = rt.run("tool-loop-demo", agent).expect("run");
    println!("answer : {}", recorded.output);
    println!(
        "steps  : {} fresh this attempt, {} replayed",
        recorded.fresh_steps, recorded.replayed_steps
    );

    // The audit: the entire conversation - every model turn, every tool
    // call - replays from the journal. The model is never consulted.
    let audit = rt.replay("tool-loop-demo", agent).expect("replay");
    assert_eq!(audit.trace, recorded.trace);
    println!("replay : bit-identical, zero model calls, zero tool runs");
}
