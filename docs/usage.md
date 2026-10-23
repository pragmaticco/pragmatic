# Using Stet

A hands-on guide for someone who just found this repo and wants to actually
run it. If you want the theory, read [Concepts](concepts.md); if you want the
five-minute tour, read the [Quickstart](quickstart.md). This page is the
middle path: everything you need to go from zero to a crash-recoverable,
replayable agent, in the order you'll actually hit it.

**What Stet gives you:** you write an agent as an ordinary function. Every
model call and every side effect it makes is journaled to an append-only log
as it happens. Kill the process at any point and resume - the steps already
on record are read back from the log instead of re-run, so a recorded model
answer is never paid for again and a committed side effect never runs
again. (A call the crash cut off midway, with no result on record, is
decided by the recovery policy; see [section 5](#5-side-effects-recorded-write-ahead).)
Replay the whole run later, bit-for-bit, without calling the model at all -
for debugging or audit.

**When you want it:** long or expensive agent runs you can't afford to restart
from scratch, anything that touches the outside world (writes, charges,
webhooks) and must not repeat what it already did, and anything you need to
be able to prove later (what the model was asked, what it answered, what the
agent did).

---

## 1. Try it now - no API key, nothing to install but Rust

Clone the repo and run the landing-page example. It uses a seeded stand-in
for the model, so it needs no API key and no network. 0.6 is on the
`system-of-record` branch until it is merged to `main`, so clone that
branch:

```sh
git clone -b system-of-record https://github.com/pragmaticco/pragmatic
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

To see the whole product instead (Stet Server, anchoring, erasure and
an evidence bundle checked by an auditor's tools), run the one-command
demo, `examples/demo/run.sh`. It needs Rust, Python 3.10 or later and
OpenSSL 3; see [examples/demo](../examples/demo/README.md).

---

## 2. Install it in your own project

Stet is not on crates.io or PyPI yet, so for now every install comes
from this repository. This page describes 0.6.0, which is on the
`system-of-record` branch; `main` still builds 0.4.0 until 0.6 is merged,
so pin the branch.

### Rust

```toml
# Cargo.toml
[dependencies]
pragmatic = { git = "https://github.com/pragmaticco/pragmatic", branch = "system-of-record" }
# optional: Claude as an Oracle. Skip it to bring your own model.
pragmatic-anthropic = { git = "https://github.com/pragmaticco/pragmatic", branch = "system-of-record" }
```

Once they are published, these become `pragmatic = "0.6"` and
`pragmatic-anthropic = "0.6"`.

### Python

From a clone of the `system-of-record` branch (step 1; this needs a Rust
toolchain):

```sh
pip install "./crates/pragmatic-python[anthropic]"   # or [openai]
```

Once it is published, that becomes `pip install "pragmatic-runtime[anthropic]"`.

```python
import pragmatic   # the import name is `pragmatic`, the package is `pragmatic-runtime`
```

### The CLI (optional, for inspecting journals)

```sh
cargo install --path crates/pragmatic-cli    # from the same clone; installs the `pragmatic` command
```

---

## 3. Write your first durable agent (Rust)

An agent is a plain function over a `Ctx`. Two rules:

1. Route **model calls** through `ctx.oracle(...)` - so they get journaled.
2. Route **side effects** (anything touching the outside world) through
   `ctx.effect(...)` - so they are recorded write-ahead and a committed
   effect never runs again.

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

    // A side effect, recorded write-ahead. Once its result is on record,
    // resume and replay reuse it instead of re-running the closure.
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

Run it and look in `./journals/`: you'll find a `.journal` file named by
the SHA-256 of the run id (so any run id is a safe file name), with a
`.lock` file beside it that stops a second process on this machine from
writing the same run. The journal is an append-only, hash-chained record
of every step; `pragmatic runs --dir ./journals` lists it by run id.

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
  journal are read back (no model calls for recorded answers, no repeat of
  committed effects); recording continues from exactly where the journal
  ends, and an effect the crash cut off midway goes to the recovery policy
  ([section 5](#5-side-effects-recorded-write-ahead)). Call it after any
  crash - if the run already finished, it just returns the finished result.
- **`replay`** reproduces a completed run bit-for-bit for debugging or audit.
  The model is *never* called - the oracle is replaced by one that refuses, so
  "no model calls on replay" is enforced, not hoped for. `audit.trace` equals
  the original `report.trace`. Replay reads a snapshot and writes nothing,
  so it can audit a run that is still recording.

The run id is the handle. Use a stable, meaningful one (a job id, a request
id) - that's how you find and resume the run later.

---

## 5. Side effects, recorded write-ahead

Anything that changes the outside world goes through `ctx.effect(name, arg,
closure)`. Stet journals the *intent* before your closure runs and the
*result* after, so:

- On **resume**, if the crash happened after the effect committed, the
  recorded result is reused - the effect does **not** run again.
- On **replay**, the closure never runs at all; the recorded result is
  returned.

If a crash lands in the narrow window *between* intent and result (the effect
may or may not have happened), resume has to decide what happened.
`rt.resume` writes the effect off and performs it again; a runtime backed by
Stet Server refuses with `DanglingEffect` instead, until you decide.
`rt.resume_with` takes a recovery policy: commit the known result if the
effect did happen (`Recover::Commit`), or write it off so the resumed run
performs it again (`Recover::Compensate`). Every decision is written to the
journal as a `recovery` note. An effect made with `ctx.effect_keyed`
receives an idempotency key, `<run_id>/<branch>/<intent cursor>`, that is
the same on every retry, so the service it calls can recognize the repeat.
A model call cut off the same way is sent again when the resumed run
reaches it, so one the provider answered but the journal did not record is
paid for twice.
See [Concepts → Durable effects](concepts.md#durable-effects-and-the-crash-window).

Rule of thumb: **reads** (fetching a web page, a DB query you don't mind
repeating) can be plain code; **writes** (charging a card, sending an email,
inserting a row) belong in `ctx.effect`.

---

## 6. Inspect your runs

### From the terminal

```sh
pragmatic runs   --dir ./journals              # list every run + chain status
pragmatic show   research-42 --dir ./journals  # full timeline of one run
pragmatic verify --all --dir ./journals        # the chain, every commitment, erasures
```

### In the browser

```sh
pragmatic serve  --dir ./journals              # live console on 127.0.0.1:7171
pragmatic export research-42 --dir ./journals -o run.html   # or a self-contained file
```

`serve` gives you a live console over your journal directory: every run, its
chain status, calls a crash left open, and a per-run timeline whose rows say
in words what happened ("Model call → lookup_order", "No end: crashed") and
open to every prompt, outcome, effect and chain hash. `export` bakes one run
into a single HTML file, fonts included, that you can attach to an incident
ticket - it opens anywhere and loads nothing.

> Journals contain your prompts and completions in plaintext (they *are* the
> audit trail), so `serve` binds to loopback only by default. See
> [SECURITY.md](../SECURITY.md).

### Erase and export evidence

```sh
pragmatic erase research-42 --match "jane@example.com" --reason-code gdpr_art17 --dir ./journals
pragmatic evidence research-42 --dir ./journals -o research-42.evidence.json --redact detectors
pragmatic verify-evidence research-42.evidence.json
```

`erase` drops the content of the matching slots under the run's write lock
and records an `erasure` note; every chain hash still verifies. `evidence`
packages a run as an evidence bundle (a local bundle is unanchored: it
proves integrity, not time), and `verify-evidence` checks a bundle against
the trust roots you pin. Bundles exported from Stet Server carry
anchors from independent timestamp authorities. See
[evidence.md](evidence.md).

---

## 7. Using it from Python

Most Python agents keep their Anthropic or OpenAI client and wrap it with
`ctx.wrap(client)`, which journals every call at the SDK's HTTP layer,
streams and frameworks included; tool calls go through `ctx.run_tools`.
That path is in the [README](../README.md#your-agent-journaled) and the
[Python guide](python.md).

The lower-level API mirrors the Rust one. Your "oracle" is just a function
from a prompt string to a completion string - wrap any model client you like:

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
                      lambda arg: f"s3://reports/{arg}")      # write-ahead

report = rt.run("research-42", research)     # record
report = rt.resume("research-42", research)  # crash-recover, no re-sampling
audit  = rt.replay("research-42", research)  # bit-for-bit, model never called

assert audit.trace == report.trace
assert rt.verify("research-42")              # a VerifyReport, truthy when intact
```

The `report` object exposes `run_id`, `output`, `trace`, `journal_len`,
`replayed_steps`, `fresh_steps`, `chain_head` and `program_changes`. Journals
written from Python are byte-compatible with the Rust runtime and every CLI
command above - record in Python, inspect with `pragmatic serve`, replay in
Rust, all on the same files.

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
There is nothing to provision. Stet Server is an optional, self-hosted
commercial store (in design-partner preview) that adds a single writer per
run across machines, anchoring, retention, access control and evidence
export; it changes operations, not the semantics on this page. See
[server.md](server.md).

**What happens if I change my agent's code and replay an old journal?**
`#[pragmatic::durable]` hashes your function's source and journals it before
the agent's first step. Replaying an old journal under changed code fails
fast with a `JournalDesync` fault at that entry, before any step can
misreplay, unless you opt in with
`on_code_change: Some(OnCodeChange::Continue)` in `RunOptions`. `run` and `resume` under changed code carry on by default
and record the change as a `program.change` note. For a deliberate change,
`ctx.patched(name)` lets new runs take the new path while recorded runs keep
the old one.

**Is replay actually free of model calls?** Yes, by construction. Strict
replay swaps in an oracle that refuses to sample, so a stray draw is an error,
not a silent API call. This is Theorem T1, proved on paper and checked
empirically by the test suite (1000/1000 runs replay byte-identically).

**How much does journaling cost?** An append is O(1): about 2.2 µs at a
million entries on an Apple M5 Pro in release mode, flat from a thousand to
a million entries (journal format 2, in memory, before the disk sync). That
includes a fresh random salt and a SHA-256 commitment for every content slot
and the chain hash. Measure it with
`cargo test --release -p pragmatic --test e3_journal_overhead -- --nocapture`.

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
- [`examples/demo`](../examples/demo/README.md) - the whole product story in
  one command, and [`tests/e2e`](../tests/e2e/README.md), the same steps as
  assertions.
- [Python](python.md), [Stet Server](server.md) and
  [evidence for auditors](evidence.md).
- [`crates/pragmatic-anthropic/examples/tool_loop.rs`](../crates/pragmatic-anthropic/examples/tool_loop.rs)
  - a real Messages-API tool-use agent, durable end to end: `Conversation`
  in, `Turn` out, every tool call a write-ahead journaled effect.
- [Concepts](concepts.md) - the calculus and proofs underneath the
  guarantees.
