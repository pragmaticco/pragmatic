# Quickstart

Five minutes from `cargo add` to a crash-proof, replayable agent.

## 1. Install

```toml
# Cargo.toml
[dependencies]
pragmatic = "0.4"
pragmatic-anthropic = "0.4"   # or implement Oracle for your own model client
```

## 2. Write the agent

Agents are plain functions over `Ctx`. Route model calls through
`ctx.oracle`, external writes through `ctx.effect`, and mark the function
`#[pragmatic::durable]`:

```rust
use pragmatic::{Ctx, Fault, Value};

#[pragmatic::durable]
fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the research task")?;          // journaled

    let mut findings = Vec::new();
    for step in 0..10 {
        findings.push(ctx.oracle(format!("probe {step}: {plan}"))?);
    }

    // A durable effect: journaled *before* it runs (write-ahead), its
    // result journaled after. Replay reuses the result; the world is
    // touched exactly once.
    ctx.effect("publish", format!("{} findings", findings.len()), |arg| {
        // your real side effect here: S3 write, webhook, DB insert...
        Ok(Value::from(format!("s3://reports/{arg}")))
    })
}
```

## 3. Run it durably

```rust
use pragmatic::Runtime;
use pragmatic_anthropic::AnthropicOracle;

let oracle = AnthropicOracle::from_env()?      // ANTHROPIC_API_KEY
    .model("claude-sonnet-5")
    .max_tokens(1024);

let rt = Runtime::on_dir("./journals", oracle)?;
let report = rt.run("research-42", research)?;
println!("{}", report.output);
```

Every oracle call's realized outcome now lands in
`./journals/research-42.journal` - append-only, hash-chained, synced to disk
as the run proceeds.

## 4. Crash. Recover.

Kill the process anywhere - step nine of a thousand. Then:

```rust
let report = rt.resume("research-42", research)?;
```

The nine recorded steps are **read back from the journal** (zero model
calls, zero duplicate effects); recording continues at step nine. The agent
function cannot tell the difference - that is Theorem T1's content.

## 5. Replay, exactly

```rust
let audit = rt.replay("research-42", research)?;   // the model is NEVER called
assert_eq!(audit.trace, report.trace);
```

Strict replay reproduces the run bit-for-bit - nondeterministic model
behavior included - for time-travel debugging and audit.

## 6. Inspect from the terminal - or the console

```sh
cargo install pragmatic-cli

pragmatic runs   --dir ./journals            # every run, chain status
pragmatic show   research-42 --dir ./journals
pragmatic verify --all --dir ./journals      # walk the tamper-evident chain
pragmatic export research-42 --dir ./journals -o run.html   # replay console file
pragmatic serve  --dir ./journals            # live console on 127.0.0.1:7171
```

## Async agents

Same API, `await`ed - executor-agnostic and still zero-dependency:

```rust
use pragmatic::{AsyncCtx, AsyncRuntime, Fault, Value};

#[pragmatic::durable]
async fn research(ctx: &mut AsyncCtx<'_, MyOracle>) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the task").await?;
    ctx.effect("publish", plan, async |arg| {
        Ok(Value::from(format!("s3://{arg}")))   // awaited tool call
    }).await
}

let rt = AsyncRuntime::on_dir("./journals", oracle)?;
let report = rt.run("research-42", research).await?;   // drive from tokio,
                                                        // smol, or pragmatic::block_on
```

Implement `AsyncOracle` over your async HTTP client for native async model
calls; every sync `Oracle` also works as-is.

## Python

```sh
pip install pragmatic-runtime
```

```python
import pragmatic

rt = pragmatic.Runtime("./journals", my_model_fn)   # (str) -> str

def research(ctx):
    plan = ctx.oracle("plan the task")
    return ctx.effect("publish", plan, lambda arg: f"s3://{arg}")

report = rt.run("research-42", research)
report = rt.resume("research-42", research)   # crash-recover, no re-sampling
audit  = rt.replay("research-42", research)   # model never called
assert audit.trace == report.trace and rt.verify("research-42")
```

Journals written from Python are byte-compatible with the Rust runtime and
every CLI command above.

## Where next

- [Concepts](concepts.md) - the execution model: Oracle, Journal, effects,
  faults, capabilities.
- `examples/tool_use_retries.rs` - flaky tools under a Supervisor.
- `examples/map_reduce.rs` - multi-run coordination with per-agent recovery.
- [Concepts](concepts.md) - the calculus and proofs underneath.
