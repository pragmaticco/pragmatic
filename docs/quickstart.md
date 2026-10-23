# Quickstart

Five minutes from an empty project to a crash-recoverable, replayable
agent. For the whole product story in one command (Stet Server,
anchoring, erasure and an auditor's evidence check), run
`examples/demo/run.sh` from a clone of this repository's
`system-of-record` branch instead.

## 1. Install

Stet 0.6.0 is not on crates.io yet, so depend on the repository. It
is on the `system-of-record` branch until it is merged to `main` (which
still holds 0.4.0), so pin the branch:

```toml
# Cargo.toml
[dependencies]
pragmatic = { git = "https://github.com/pragmaticco/pragmatic", branch = "system-of-record" }
# or implement Oracle for your own model client
pragmatic-anthropic = { git = "https://github.com/pragmaticco/pragmatic", branch = "system-of-record" }
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
    // result journaled after. Once the result is on record, resume and
    // replay reuse it instead of running the effect again.
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

Every oracle call's request and realized outcome now land in `./journals`,
in one journal file per run (named by the SHA-256 of the run id), before
the agent sees the outcome: append-only, hash-chained, synced to disk as the
run proceeds.

## 4. Crash. Recover.

Kill the process anywhere - step nine of a thousand. Then:

```rust
let report = rt.resume("research-42", research)?;
```

The nine recorded steps are **read back from the journal** (no model
calls and no repeated effects for them); recording continues at step nine.
A step the crash cut off midway, with no result on record, is decided by
the recovery policy: a model call is sent again, and an effect is
performed again by default on local runs (see the
[usage guide](usage.md#5-side-effects-recorded-write-ahead)). The agent
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
cargo install --path crates/pragmatic-cli    # from a clone (system-of-record branch), until it is on crates.io

pragmatic runs   --dir ./journals            # every run, chain status
pragmatic show   research-42 --dir ./journals
pragmatic verify --all --dir ./journals      # the chain, every commitment, erasures
pragmatic export research-42 --dir ./journals -o run.html   # replay console file
pragmatic serve  --dir ./journals            # live console on 127.0.0.1:7171
pragmatic evidence research-42 --dir ./journals -o run.evidence.json
pragmatic verify-evidence run.evidence.json  # a local bundle is UNANCHORED
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

From a clone of the repository's `system-of-record` branch, until the
package is on PyPI:

```sh
pip install "./crates/pragmatic-python[anthropic]"   # or [openai]
```

Most Python agents keep their SDK client and wrap it with `ctx.wrap(client)`
(see the [Python guide](python.md)). The lower-level API mirrors Rust:

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
- `crates/pragmatic/examples/tool_use_retries.rs` - flaky tools under a
  Supervisor.
- `crates/pragmatic/examples/map_reduce.rs` - multi-run coordination with
  per-agent recovery.
- [`examples/demo`](../examples/demo/README.md) - the whole product story in
  one command, also run as assertions by [`tests/e2e`](../tests/e2e/README.md).
- [Usage guide](usage.md) - recovery policies, erasure and evidence bundles.
- [Concepts](concepts.md) - the calculus and proofs underneath.
