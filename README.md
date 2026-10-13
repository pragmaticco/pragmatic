<div align="center">

# Pragmatic

**The black-box recorder for LLM agents: crash recovery that never
re-pays for a token, and a tamper-evident journal that proves what your
agent actually did.**

[![CI](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml/badge.svg)](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)
![status: public beta](https://img.shields.io/badge/status-public%20beta-brightgreen.svg)

[Usage guide](docs/usage.md) · [Quickstart](docs/quickstart.md) · [Concepts](docs/concepts.md) ·
[Strategy](docs/STRATEGY.md) · [Research](docs/concepts.md) ·
[Early access / design partners](mailto:me@aniketh.net?subject=Pragmatic%20early%20access)

</div>

---

Two things go wrong with agents in production, and they are expensive in
different currencies:

1. **The run dies.** An agent 900 steps into a 1,000-step job crashes - and
   naive retry re-runs the whole thing, re-paying for every token and
   possibly re-executing side effects. Pragmatic resumes **on** step 901:
   recorded outcomes are read back, not re-sampled; committed effects are
   not re-performed.
2. **Someone asks what the agent did.** An incident review, a customer, an
   auditor. Pragmatic replays the entire run **bit-for-bit** from an
   append-only, SHA-256 hash-chained journal - every prompt, every model
   turn, every tool call and its result - with the model never consulted.
   Any post-hoc edit to the journal breaks the chain at that exact cursor.

Durable execution engines can give you a version of (1) if you wrap every
model call as an opaque cached activity and keep everything around it
deterministic yourself. They were never built for (2). Pragmatic is built
for both, and the reason it can be is the thesis: **each LLM call is
modeled as a first-class probability distribution** (the **Oracle**), every
realized outcome lands in the **Journal**, and replay soundness (**T1**) is
proved in the [Agentical calculus](docs/concepts.md) - derived from the
semantics, not assumed.

## Three guarantees, every run

1. **Journal every step.** Each model call's realized outcome is recorded to
   an append-only log as the run proceeds - the source of truth for what the
   agent actually did.
2. **Recover from any crash.** Resume exactly where the agent stopped;
   recorded outcomes are read back instead of re-sampled. No duplicate model
   calls, no divergent paths, no lost work.
3. **Replay faithfully.** Reproduce the entire run bit-for-bit for
   time-travel debugging and audit - with the model never consulted.

## Your agent, journaled - one line

```sh
pip install "pragmatic-runtime[anthropic]"    # or [openai]
```

Keep your agent as it is. Wrap the SDK client and hand tool calls to
`ctx.run_tools`; every model call and tool call is now journaled:

```python
import anthropic, pragmatic

rt = pragmatic.Runtime("./journals")

def research(ctx):
    client = ctx.wrap(anthropic.Anthropic())            # the only new line
    messages = [{"role": "user", "content": "Find papers on durable execution."}]
    while True:
        msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=1024,
                                     tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": msg.content})
        if msg.stop_reason != "tool_use":
            return msg.content[0].text
        messages += ctx.run_tools(msg, {"search_corpus": search_corpus})

rt.run("research-42", research)       # record
rt.resume("research-42", research)    # after a crash: no repeated API or tool calls
rt.replay("research-42", research)    # audit: nothing is called at all
rt.verify("research-42")              # tamper evidence: the hash chain is intact
```

Works with `Anthropic`, `AsyncAnthropic`, `OpenAI`, and `AsyncOpenAI`
(Messages, Chat Completions, and Responses APIs). Details:
[crates/pragmatic-python](crates/pragmatic-python).

## In Rust

The same guarantees natively. Claude decides when to call tools, each tool
runs as a write-ahead journaled effect, and the whole loop records,
resumes, and replays:

```rust
use pragmatic::{Ctx, Fault, Runtime, Value};
use pragmatic_anthropic::{AnthropicOracle, Conversation, Turn};
use serde_json::json;

#[pragmatic::durable]
fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let mut convo = Conversation::user("Find papers on durable execution.");
    loop {
        let turn = Turn::parse(&ctx.oracle(convo.prompt())?)?;   // journaled draw
        convo.push_assistant(&turn);
        if !turn.wants_tools() {
            return Ok(Value::from(turn.text()));
        }
        for call in turn.tool_uses() {
            let result = ctx.effect(&call.name, call.input.to_string(), |input| {
                Ok(search_corpus(input))            // write-ahead journaled effect
            })?;
            convo.push_tool_result(&call.id, result.as_str());
        }
    }
}

let oracle = AnthropicOracle::from_env()?
    .model("claude-sonnet-5")
    .tools(json!([{ "name": "search_corpus", /* … */ }]));

let mut rt = Runtime::on_dir("./journals", oracle)?;
let report  = rt.run("research-42", research)?;    // record
// Crash mid-loop? Every prior model turn AND tool result replays from
// the journal; the world is not touched again.
let resumed = rt.resume("research-42", research)?; // resume - no re-sampling
let audit   = rt.replay("research-42", research)?; // replay bit-for-bit - T1
assert_eq!(audit.trace, resumed.trace);
```

Run it live: `ANTHROPIC_API_KEY=... cargo run -p pragmatic-anthropic --example tool_loop`
Try the runtime without a model: `cargo run -p pragmatic --example research_agent`

**Async?** Same guarantees, `await`ed - executor-agnostic (tokio, smol, or
the built-in `block_on`), still zero dependencies (`AsyncRuntime`, see
[docs/usage.md](docs/usage.md)). **Python?** The same runtime (above); journals
are byte-compatible with Rust and the CLI. **C++, Java,
Go, Node.js?** One C ABI ([bindings/](bindings/)), full record → resume →
replay surface, typed faults.

## Measured, not promised

Every number below is a test in this repo (`cargo test --release`):

| Claim | Result |
|---|---|
| **Replay determinism** (E1) | 1000 / 1000 seeded stochastic runs replay byte-identically, zero model calls |
| **Crash recovery** (E2) | Crash at *every* journal prefix → exact resume; no re-sampling; no orphaned effects; survives process restarts |
| **Tool-use loop** | Full Messages-API tool loop recorded over real sockets; API killed; resume + replay byte-identical; tool performed exactly once, ever |
| **Journal overhead** (E3) | O(1) append, flat from 1k to 1M entries (~0.44 µs steady-state at 1M on an Apple M5 Pro, incl. full SHA-256 chaining) |
| **Replay speedup** (E3) | ~1000× under a 1 ms/draw oracle - replay performs zero oracle calls |
| **Tamper evidence** | Any post-hoc edit breaks the chain at that cursor; HMAC-keyed journals refuse the wrong key |
| **Code-change safety** | A journal recorded under one agent version refuses to replay under another (`JournalDesync` at cursor 0) |

## Why not Temporal (or Restate, Inngest, DBOS)?

If you already run one of these for general workflows, keep it - they are
excellent at what they were built for. Pragmatic exists for when **the
agent itself** must be recoverable and auditable:

| | Generic durable execution | Pragmatic |
|---|---|---|
| The model call | Opaque activity; cached output the engine never understands | A probability distribution the runtime models |
| Determinism discipline | You keep the workflow code deterministic; a violation surfaces as a confusing divergent replay | The determinism boundary is principled (Oracle/effect/clock/recv are *the* nondeterminism); a changed agent fails loudly at cursor 0 before any step can misreplay |
| The history | Engine-internal state | An audit artifact: hash-chained, tamper-evident, optionally HMAC-keyed, exportable as a single HTML file you attach to the incident ticket |
| Replay for audit | Re-run your code against history inside the engine | A first-class mode in which the model is *provably* never consulted (the oracle is replaced by one that refuses) |
| Operations | A cluster/service to provision | A zero-dependency library that links into the agent you already run - Linux, containers, any cloud |
| Soundness | Assumed, given your discipline | Proved (T1) in the calculus and validated empirically (E1: 1000/1000); probability bounds (T3) and information-flow discipline (T2) on paper |

## The workspace

| Crate | What | Deps |
|---|---|---|
| [`pragmatic`](crates/pragmatic) | The runtime, sync **and async**: Journal, Oracle, Ctx, Runtime, AsyncRuntime, Supervisor, IFC memory, capabilities | **zero** |
| [`pragmatic-macros`](crates/pragmatic-macros) | `#[pragmatic::durable]` - program identity, journaled and verified (sync and async fns) | **zero** |
| [`pragmatic-anthropic`](crates/pragmatic-anthropic) | Claude as a journaled Oracle - plain completions **and full tool-use loops** (Messages API), wire-tested over real sockets | `ureq`, `serde_json` |
| [`pragmatic-openai`](crates/pragmatic-openai) | Any OpenAI-compatible server (OpenAI, Ollama, vLLM, …) as a journaled Oracle, wire-tested | `ureq`, `serde_json` |
| [`pragmatic-cli`](crates/pragmatic-cli) | `pragmatic runs / show / verify / export / serve` - HTML replay console, exportable or served live | **zero** |
| [`pragmatic-python`](crates/pragmatic-python) | The runtime from Python (`pip install pragmatic-runtime`); journals byte-compatible with Rust | `pyo3` |
| [`pragmatic-ffi`](crates/pragmatic-ffi) | The C ABI behind the [C++ / Java / Go / Node bindings](bindings/) | **zero** |

Implement `Oracle` for any model client - Anthropic, OpenAI, a local server,
any step whose result is a draw from a distribution. The core links into the
agent you already run. Nothing to provision.

## The replay console

```sh
pragmatic serve --dir ./journals               # live console on 127.0.0.1:7171
pragmatic export research-42 --dir ./journals  # or a self-contained run.html
```

`serve` gives you a live, self-hostable console over your journal directory:
every run, its chain status, dangling-effect warnings, and a full timeline
per run - every prompt, model turn, effect intent/commit, and chain hash.
`export` produces the same timeline as one HTML file; attach it to the
incident ticket, it opens anywhere. Loopback-only by default: journals
contain prompts and outputs.

## Honest scope

- **T1** is proved on paper in the Agentical calculus and demonstrated
  empirically here (E1: 1000/1000 runs replay byte-identically). A Lean 4
  mechanization is in progress - the syntax, semantics and journal model are
  formalized and T1 is stated, but the proof bodies are still `sorry`. It is a
  skeleton, not a machine-checked proof, and we do not claim it as one.
  **T2/T3** are pen-and-paper results; the runtime implements their
  disciplines, the theorems are not mechanized.
- Single-process journals on local disk. The managed cloud backend (hosted
  journaling at scale, shared console, alerting) is the commercial layer -
  it changes operations, not semantics.
- The Anthropic and OpenAI adapters are wire-tested against API-shaped mocks
  over real sockets on every CI run; the live-API tests need a key
  (`cargo test -p pragmatic-anthropic -- --ignored`, same for
  `pragmatic-openai`). Structured tool-use conversations are currently an
  Anthropic-adapter feature; OpenAI-adapter parity is next
  ([strategy](docs/STRATEGY.md)).
- Journals store prompts/completions in plaintext by design (they *are* the
  audit trail). See [SECURITY.md](SECURITY.md).

## Research

Pragmatic's guarantees are real because they are proved. The theory is
**Agentical** - a probabilistic process calculus with six primitives (Agent,
Oracle, Channel, Memory, Journal, Supervisor), probabilistic small-step
semantics in record and replay modes, and three theorems stated with honest
scope. [Read the concepts doc](docs/concepts.md).

## License & commercial use

Pragmatic is **source-available** under the
[Business Source License 1.1](LICENSE) - read it, modify it, self-host it.

- **Free** for non-production use, and for **production use by organizations
  under US $1M annual revenue** (and not as a competing hosted service). See
  the [Additional Use Grant](LICENSE) for exact terms.
- **Production use beyond that requires a commercial license** -
  [contact us](mailto:me@aniketh.net?subject=Pragmatic%20commercial%20license).
- Each released version automatically converts to **Apache 2.0** four years
  after release (its Change Date), so nothing is ever locked up forever.

© 2026 Pragmatic Research, Inc.
