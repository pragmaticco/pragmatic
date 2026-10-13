# Using Pragmatic

A hands-on guide for someone who just found this repo and wants to actually
run it. If you want the theory, read [Concepts](concepts.md); if you want the
five-minute tour, read the [Quickstart](quickstart.md). This page is the
middle path: everything you need to go from zero to a crash-proof, replayable
agent, in the order you'll actually hit it.

**What Pragmatic gives you:** you write an agent as an ordinary function. Every
model call and every side effect it makes is journaled to an append-only log
as it happens. Kill the process at any point and resume - the steps already
taken are read back from the log instead of re-run, so you never pay for a
model call twice or fire a side effect twice. Replay the whole run later,
bit-for-bit, without calling the model at all - for debugging or audit.

**When you want it:** long or expensive agent runs you can't afford to restart
from scratch, anything that touches the outside world (writes, charges,
webhooks) and must do so exactly once, and anything you need to be able to
prove later (what the model was asked, what it answered, what the agent did).

---

## 1. Try it now - no API key, nothing to install but Rust

Clone the repo and run the landing-page example. It uses a seeded stand-in
for the model, so it needs no API key and no network:

```sh
git clone https://github.com/pragmaticco/pragmatic
cd pragmatic
cargo run --example research_agent
```

You'll watch one run get **recorded**, **crash** on step nine of a twelve-step
loop, **resume** exactly where it stopped (no re-sampling), and **replay**
bit-for-bit with the model never consulted. That single example is the whole
value proposition in ~60 lines - read it at
[`crates/pragmatic/examples/research_agent.rs`](../crates/pragmatic/examples/research_agent.rs).

Three more runnable examples, same command shape:

```sh
cargo run --example async_research      # the same, async
cargo run --example tool_use_retries    # flaky tools under a Supervisor
cargo run --example map_reduce          # many runs, per-agent recovery
```

---

## 2. Install it in your own project

### Rust

```toml
# Cargo.toml
[dependencies]
pragmatic = "0.4"
pragmatic-anthropic = "0.4"   # optional: Claude as an Oracle. Skip it to bring your own model.
```

### Python

```sh
pip install pragmatic-runtime
```

```python
import pragmatic   # the import name is `pragmatic`, the package is `pragmatic-runtime`
```

### The CLI (optional, for inspecting journals)

```sh
cargo install pragmatic-cli    # installs the `pragmatic` command
```

---

## 3. Write your first durable agent (Rust)

An agent is a plain function over a `Ctx`. Two rules:

1. Route **model calls** through `ctx.oracle(...)` - so they get journaled.
2. Route **side effects** (anything touching the outside world) through
   `ctx.effect(...)` - so they run exactly once.

Mark it `#[pragmatic::durable]` and you're done. Here's a complete program you
can run today with **no API key** - it uses `SeededOracle`, a deterministic
stand-in for a real model:

```rust
use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

#[pragmatic::durable]
fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the research task")?;          // journaled

    let mut findings = Vec::new();
    for step in 0..10 {
        findings.push(ctx.oracle(format!("probe {step}: {plan}"))?);
    }

    // A side effect, done exactly once. Replay reuses the recorded result
    // instead of re-running the closure.
    ctx.effect("publish", format!("{} findings", findings.len()), |arg| {
        // your real side effect here: S3 write, webhook, DB insert...
        Ok(Value::from(format!("s3://reports/{arg}")))
    })
}

fn main() -> Result<(), Fault> {
    let rt = Runtime::on_dir("./journals", SeededOracle::new(42))?;
    let report = rt.run("research-42", research)?;
    println!("output: {}", report.output);
    println!("{} steps journaled", report.journal_len);
    Ok(())
}
```

Run it and look in `./journals/` - you'll find `research-42.journal`, an
append-only, hash-chained record of every step.

### Swap in a real model

When you're ready for an actual LLM, replace the oracle - nothing else
changes:

```rust
use pragmatic_anthropic::AnthropicOracle;

let oracle = AnthropicOracle::from_env()?    // reads ANTHROPIC_API_KEY
    .model("claude-sonnet-5")
    .max_tokens(1024);

let rt = Runtime::on_dir("./journals", oracle)?;
```

Or any OpenAI-compatible server - OpenAI itself, or a local Ollama / vLLM /
llama.cpp with no key at all:

```rust
use pragmatic_openai::OpenAiOracle;

let oracle = OpenAiOracle::from_env()?       // reads OPENAI_API_KEY
    .model("gpt-5");
// ...or, keyless and local:
let local = OpenAiOracle::new("")
    .base_url("http://localhost:11434/v1")
    .model("llama3.3");
```

Flaky API? Wrap any oracle in bounded retries with doubling backoff -
retries happen before anything is journaled, so replay never sees the
failed attempts:

```rust
use pragmatic::RetryOracle;
use std::time::Duration;

let oracle = RetryOracle::new(oracle)
    .max_retries(4)
    .base_delay(Duration::from_millis(250)); // 250ms, 500ms, 1s, 2s
```

The agent function is identical. The only thing that changed is where the
draws come from.

---

## 4. The three things you'll do with a run

Once a run exists, these are the operations that matter:

```rust
let report  = rt.run("research-42", research)?;    // record from scratch
let resumed = rt.resume("research-42", research)?;  // continue after a crash
let audit   = rt.replay("research-42", research)?;  // reproduce, model never called
```

- **`run`** starts fresh under a run id and records every step.
- **`resume`** picks up a run whose process died. The steps already in the
  journal are read back (zero model calls, zero duplicate effects); recording
  continues from exactly where the journal ends. Call it after any crash - if
  the run already finished, it just returns the finished result.
- **`replay`** reproduces a completed run bit-for-bit for debugging or audit.
  The model is *never* called - the oracle is replaced by one that refuses, so
  "no model calls on replay" is enforced, not hoped for. `audit.trace` equals
  the original `report.trace`.

The run id is the handle. Use a stable, meaningful one (a job id, a request
id) - that's how you find and resume the run later.

---

## 5. Side effects, done exactly once

Anything that changes the outside world goes through `ctx.effect(name, arg,
closure)`. Pragmatic journals the *intent* before your closure runs and the
*result* after, so:

- On **resume**, if the crash happened after the effect committed, the
  recorded result is reused - the effect does **not** run again.
- On **replay**, the closure never runs at all; the recorded result is
  returned.

If a crash lands in the narrow window *between* intent and commit (the effect
may or may not have happened), the runtime flags a **dangling intent** on
resume rather than guessing. You resolve it explicitly - commit the known
result if the effect did happen (or is idempotent), or compensate and let the
resumed run redo it. See [Concepts → Durable effects](concepts.md#durable-effects-and-the-crash-window).

Rule of thumb: **reads** (fetching a web page, a DB query you don't mind
repeating) can be plain code; **writes** (charging a card, sending an email,
inserting a row) belong in `ctx.effect`.

---

## 6. Inspect your runs

### From the terminal

```sh
pragmatic runs   --dir ./journals              # list every run + chain status
pragmatic show   research-42 --dir ./journals  # full timeline of one run
pragmatic verify --all --dir ./journals        # walk the tamper-evident hash chain
```

### In the browser

```sh
pragmatic serve  --dir ./journals              # live console on 127.0.0.1:7171
pragmatic export research-42 --dir ./journals -o run.html   # or a self-contained file
```

`serve` gives you a live console over your journal directory: every run, its
chain status, dangling-effect warnings, and a full per-run timeline (every
prompt, outcome, effect, and chain hash). `export` bakes one run into a single
HTML file you can attach to an incident ticket - it opens anywhere.

> Journals contain your prompts and completions in plaintext (they *are* the
> audit trail), so `serve` binds to loopback only by default. See
> [SECURITY.md](../SECURITY.md).

---

## 7. Using it from Python

The Python API mirrors the Rust one. Your "oracle" is just a function from a
prompt string to a completion string - wrap any model client you like:

```python
import pragmatic

def my_model(prompt: str) -> str:
    # call Anthropic, OpenAI, a local server, anything - return the text
    ...

rt = pragmatic.Runtime("./journals", my_model)

def research(ctx):
    plan = ctx.oracle("plan the task")                       # journaled
    findings = [ctx.oracle(f"probe {i}: {plan}") for i in range(10)]
    return ctx.effect("publish", f"{len(findings)} findings",
                      lambda arg: f"s3://reports/{arg}")      # done once

report = rt.run("research-42", research)     # record
report = rt.resume("research-42", research)  # crash-recover, no re-sampling
audit  = rt.replay("research-42", research)  # bit-for-bit, model never called

assert audit.trace == report.trace
assert rt.verify("research-42")              # tamper-evident chain intact
```

The `report` object exposes `output`, `trace`, `journal_len`,
`replayed_steps`, `fresh_steps`, and `chain_head`. Journals written from
Python are byte-compatible with the Rust runtime and every CLI command above -
record in Python, inspect with `pragmatic serve`, replay in Rust, all on the
same files.

---

## 8. Bringing your own model

You are not tied to the bundled adapters. In Rust, implement the `Oracle`
trait (one method: given a prompt `Value`, return the drawn `Value`) over any
client - a router, a bespoke gateway, anything whose result is "a draw from a
distribution" (and note `pragmatic-openai` already covers any server that
speaks Chat Completions: OpenAI, Ollama, vLLM, llama.cpp, Groq, …). In
Python, the oracle is already just a `(str) -> str` callable, so you wrap
whatever SDK you use directly - and the same goes for the
[C++ / Java / Go / Node bindings](../bindings/), where the oracle is a plain
function in that language. The runtime doesn't care where the outcome came
from; it only cares that it gets journaled.

---

## 9. Common questions

**Do I need a server or a cloud account?** No. The runtime is a library that
links into the process you already run, and journals are files on local disk.
There is nothing to provision. (A hosted backend for shared journals and a
team console is a separate, optional commercial layer - it changes operations,
not the semantics on this page.)

**What happens if I change my agent's code and replay an old journal?**
`#[pragmatic::durable]` hashes your function's source and journals it as step
zero. Replaying an old journal under changed code fails fast with a
`JournalDesync` fault at cursor 0 - it will not silently misreplay.

**Is replay actually free of model calls?** Yes, by construction. Strict
replay swaps in an oracle that refuses to sample, so a stray draw is an error,
not a silent API call. This is Theorem T1, proved on paper and checked
empirically by the test suite (1000/1000 runs replay byte-identically).

**How much does journaling cost?** An append is O(1) - roughly 0.44 µs at a
million entries on an Apple M5 Pro, including full SHA-256 chaining, and flat
from a thousand to a million entries.

**Where are my secrets?** Journals store prompts and completions in
plaintext by design - they are the audit trail. Treat the journal directory
like you'd treat your logs, and read [SECURITY.md](../SECURITY.md).

---

## Where to go next

- [Quickstart](quickstart.md) - the condensed version of this page.
- [Concepts](concepts.md) - the execution model: Oracle, Journal, effects,
  faults, capabilities, information flow.
- [`crates/pragmatic/examples/`](../crates/pragmatic/examples) - four runnable
  programs, no API key required.
- [`crates/pragmatic-anthropic/examples/tool_loop.rs`](../crates/pragmatic-anthropic/examples/tool_loop.rs)
  - a real Messages-API tool-use agent, durable end to end: `Conversation`
  in, `Turn` out, every tool call a write-ahead journaled effect.
- [Concepts](concepts.md) - the calculus and proofs underneath the
  guarantees.
