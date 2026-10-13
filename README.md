<div align="center">

# Pragmatic

**The system of record for AI agents.** Every model call and tool call
your agent makes is recorded before the agent sees the result, in a
journal that anyone can check without trusting you. A crashed run picks
up where it stopped, without paying for the same model calls twice.

[![CI](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml/badge.svg)](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)
![status: public beta](https://img.shields.io/badge/status-public%20beta-brightgreen.svg)

[Usage guide](docs/usage.md) · [Quickstart](docs/quickstart.md) · [Concepts](docs/concepts.md) ·
[Threat model](docs/threat-model.md) · [Compliance mapping](docs/compliance.md) ·
[Privacy](docs/privacy.md) · [Strategy](docs/STRATEGY.md) ·
[Early access / design partners](mailto:me@aniketh.net?subject=Pragmatic%20early%20access)

</div>

---

Sooner or later someone outside engineering asks what your agent did. It
might be a customer's security review, an auditor, a regulator or a court.
"Here are our traces" is a weak answer when the traces sit in a database
anyone with access can edit, and expire after a few weeks.

Pragmatic gives you a better answer. It is built for teams putting AI
agents into production in fintech, insurance, health and legal work, and
for AI-agent startups selling to regulated enterprises.

> **Status.** Release 0.5 (drop-in Python, Apache 2.0) is about to be
> released. It is not yet on PyPI or crates.io; until it is, build from
> source. Everything marked **0.6** below (journal format 2, erasure,
> anchoring, evidence bundles and Pragmatic Server) is being built now
> and is in **design-partner preview**, not generally available.

## What Pragmatic records, and what you can prove with it

Every model call, tool call, message received, random draw and clock read
that your agent makes through Pragmatic's journaled interfaces is written
to a journal **before** its result reaches the agent. The journal is:

- **Tamper-evident.** Each entry is chained to the one before it with
  SHA-256. Change any recorded entry and verification reports the exact
  entry where the chain breaks. A secret key, or anchoring, also catches
  someone who recomputes the whole chain after an edit.
- **Anchored** (0.6, Pragmatic Server). The state of every run is
  time-stamped by independent timestamp authorities, so even the person
  who runs the server cannot quietly rewrite anchored history.
- **Replayable exactly.** Replay runs your agent code against the journal
  and serves every recorded answer. The model is never called and no tool
  runs again.
- **Erasable for privacy law** (0.6). Personal content can be erased
  while the rest of the journal still verifies.
- **Retained by policy, access-controlled and attributed** (0.6, Pragmatic
  Server). Retention rules, legal holds, roles, scoped tokens, and an
  access log of every request.
- **Exportable as evidence** (0.6). An evidence bundle is one file that an
  auditor verifies on their own laptop, offline, against trust roots they
  choose themselves.

## And when a run crashes

A run that dies 900 steps into a 1,000-step job resumes from its journal,
on any machine that can reach the journal. Recorded model answers are read
back instead of being requested again. Tool calls that already happened
are not repeated. Only one process writes a run at a time (a file lock on
one machine, a lease with Pragmatic Server), so two copies of an agent
never both continue it.

## How it differs

- **Observability tools** (Langfuse, LangSmith, Datadog) record traces in
  databases that can be edited, and keep them for a limited time set by
  the plan.
- **Durable-execution engines** (Temporal, DBOS) recover workflows after a
  crash, but their history is engine state, not an audit record that an
  outsider can check.
- **A model or cloud provider's own logs** cover one vendor, and only that
  vendor vouches for them.
- **Pragmatic** captures completely by construction (a result reaches the
  agent only after it is recorded), replays without calling the model, and
  produces evidence anyone can verify without trusting the operator.

| | Tracing tools | Durable-execution engines | Pragmatic |
|---|---|---|---|
| When a call is recorded | After the fact, by an exporter; recording prompt content is often optional | When the engine checkpoints a step | Before the result reaches the agent |
| Tamper evidence | None: an ordinary database | None: the history is not signed or anchored | A hash chain, plus anchoring with independent timestamp authorities (0.6) |
| How long it is kept | Set by the vendor's plan | Set by the engine's history retention | Your retention policy, with legal holds (0.6) |
| Replay a run without the model | No | Inside the engine, against its history | Anywhere, from the journal; the model is never called |
| Crash recovery | No | Yes | Yes, without repeating model or tool calls |
| Erase one person's data and still prove the rest | No | No | Yes (0.6) |
| Checked by an outsider who does not trust you | No | No | Yes: an offline verifier with pinned trust roots (0.6) |
| What you run | A hosted service or a self-hosted stack | A cluster or a cloud service | A library in your agent, plus Pragmatic Server if you want it |

If you already run Temporal or DBOS for general workflows, keep it.
Pragmatic is for the agent itself, when its record has to hold up in front
of someone who does not trust you.

## Your agent, journaled

Until 0.5 is on PyPI, install from a clone of this repository (this needs
a Rust toolchain):

```sh
pip install "./crates/pragmatic-python[anthropic]"   # or [openai]
```

Once it is published, that becomes `pip install "pragmatic-runtime[anthropic]"`.

Keep your agent as it is. Wrap the SDK client with `ctx.wrap` and hand
tool calls to `ctx.run_tools`. Every model call and tool call is now
journaled:

```python
import anthropic, pragmatic

TOOLS = [{"name": "search_corpus", "description": "Search the paper corpus",
          "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}]

def search_corpus(q: str) -> list[str]:
    ...  # your tool

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
rt.resume("research-42", research)    # after a crash: no repeated model or tool calls
rt.replay("research-42", research)    # audit: the model is never called, no tool runs
assert rt.verify("research-42")       # the chain is intact
```

This works with `Anthropic`, `AsyncAnthropic`, `OpenAI` and `AsyncOpenAI`
(Messages, Chat Completions and Responses APIs). In 0.6 the journal moves
down to the SDK's HTTP layer, so streaming, `.parse()`, raw responses, the
Anthropic tool runner and frameworks built on these clients (the OpenAI
Agents SDK, Pydantic AI, LangChain) are recorded too. Details:
[crates/pragmatic-python](crates/pragmatic-python) and
[docs/python.md](docs/python.md).

## Verify a run

From the command line (`cargo install --path crates/pragmatic-cli` until
the release is published):

```sh
pragmatic verify research-42 --dir ./journals      # is the chain intact?
```

In 0.6 you can also package a run as an evidence bundle and check it the
way an auditor would:

```sh
pragmatic evidence research-42 --dir ./journals -o research-42.evidence.json
pragmatic verify-evidence research-42.evidence.json
```

A bundle built from a local journal has no anchors. It proves the record
is intact, not when it existed, so the verifier reports `UNANCHORED`. A
bundle exported from Pragmatic Server carries its anchors. The auditor
checks it against timestamp-authority roots and keys they obtained
themselves, never ones taken from the bundle:

```sh
pragmatic verify-evidence support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTrustedRootG4.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem \
  --log-key "pragmatic/acme+5e6f7a8b+AQ..."
```

The verdict is `VERIFIED` (exit 0) when the whole journal is anchored by
at least two independent operators the auditor trusts, `VERIFIED
(PARTIAL)` (exit 2) when only the start of it is, `UNANCHORED` (exit 3),
or `FAILED` (exit 1). A second verifier written in plain Python, sharing
no code with the first (`tools/verify_evidence.py`), runs the same checks.
The auditor's walkthrough is [docs/evidence.md](docs/evidence.md).

## Pragmatic Server (design-partner preview)

The open-source runtime writes journals on the machine that runs the
agent. Pragmatic Server is the commercial product that turns them into a
shared system of record. It runs inside your own infrastructure, so your
prompts and outputs never reach us. It provides:

- one journal store for all your agents, with a single writer per run;
- independent anchoring with RFC 3161 timestamp authorities and witnesses;
- retention policies, legal holds, and erasure that keeps the proof;
- roles, scoped tokens and an access log of every request;
- redacted views for auditors, and evidence bundles on demand;
- a console for runs, verification status, holds and the access log.

Pragmatic Server is being built for 0.6 and is available to design
partners now. It is not generally available. Setup and configuration are
in [docs/server.md](docs/server.md). To join as a design partner,
[contact us](mailto:me@aniketh.net?subject=Pragmatic%20design%20partner).

## Measured, not promised

Every row is a test in this repository. The timings come from
`cargo test --release` on an Apple M5 Pro.

| Claim | Result |
|---|---|
| **Replay determinism** (E1) | 1,000 of 1,000 seeded random runs replay byte for byte with zero model calls. Runs with parallel branches replay exactly even when the branches interleave differently |
| **Crash recovery** (E2) | A run crashed at every possible journal prefix resumes exactly: nothing journaled is requested again, and no tool call is left unaccounted for |
| **Tool-use loop** | A full Messages API tool loop recorded over real sockets; the API is shut down; resume and replay match byte for byte; the tool ran exactly once |
| **Journal overhead** (E3) | Appending takes constant time: about 2.2 µs per entry at 1,000 entries and at 1,000,000 (journal format 2, in memory, not counting the disk sync), including a fresh random salt and a SHA-256 commitment for every content slot and the chain hash. Earlier releases quoted about 0.44 µs for format 1, which did less work per entry |
| **Replay cost** (E3) | 40 calls to a stand-in model that takes 5 ms per call: about 250 ms to record, under 1 ms to replay, because replay makes no model calls |
| **Tamper evidence** | Any change to a recorded entry is reported at that entry; a keyed journal refuses a wrong or missing key |
| **Code-change safety** | Replaying a run under changed agent code stops with `JournalDesync` unless you opt in to the change, and a resume under changed code records the change in the journal |

## Network behavior and telemetry

Pragmatic sends no telemetry, checks for no updates and reports no
crashes. The SDK talks only to model APIs through your own SDK clients,
and to your Pragmatic Server if you configure one. The server talks only
to the timestamp authorities, witnesses and webhook URLs you configure. A
timestamp authority receives a 32-byte digest and a random number; a
witness receives a log name, a sequence number, a tree size and a root
hash; a webhook receives an event type, a run id and counts. No prompt,
output or other content leaves the server.

## Honest scope

- Pragmatic records what goes through its journaled interfaces: wrapped
  model clients, `ctx.tool`, `ctx.run_tools`, `ctx.effect`, received
  messages, clock reads and random draws. Anything the agent does another
  way is not recorded. MCP tool calls made through the `mcp` package's own
  client need `ctx.tool`, and websocket and realtime APIs are not
  supported yet.
- In 0.5, `ctx.wrap` records the SDK calls listed above but not every path
  a framework can take, and it refuses streaming. 0.6 records at the HTTP
  layer to close that gap. Until 0.6 ships, check that your framework's
  calls appear in the journal.
- A journal on the agent's own machine can be deleted by whoever controls
  that machine. Anchoring and Pragmatic Server make deletion and rewriting
  detectable; see the [threat model](docs/threat-model.md).
- Anchoring proves that a journal existed, exactly as it is, no later than
  a certain time. It does not prove that what the agent was told was true.
- Journals hold prompts and outputs in plain text, because they are the
  record. Protect them like the data they contain. See
  [SECURITY.md](SECURITY.md) and [docs/privacy.md](docs/privacy.md).
- Pragmatic helps you meet record-keeping obligations; it does not meet
  them for you. The [compliance mapping](docs/compliance.md) says which
  part is ours and which is yours.
- Replay soundness (T1) is proved on paper in the Agentical calculus and
  shown empirically above. A Lean 4 mechanization is in progress: the
  theorem is stated but its proof is not finished, and we do not claim it
  as machine-checked.

## Other languages

The runtime is Rust with zero dependencies. Rust agents use it directly
(`#[pragmatic::durable]`, `ctx.oracle`, `ctx.effect`), synchronously or
with `async`; see the [usage guide](docs/usage.md). C++, Java, Go and
Node.js use one C ABI ([bindings/](bindings/)). Journals are
byte-compatible across every language and the CLI.

| Crate | What | Dependencies |
|---|---|---|
| [`pragmatic`](crates/pragmatic) | The runtime: journal, replay, recovery, verification, evidence bundles | none |
| [`pragmatic-macros`](crates/pragmatic-macros) | `#[pragmatic::durable]`: program identity, recorded and checked | none |
| [`pragmatic-anthropic`](crates/pragmatic-anthropic) | Claude as a journaled model, including tool-use loops | `ureq`, `serde_json` |
| [`pragmatic-openai`](crates/pragmatic-openai) | Any OpenAI-compatible server as a journaled model | `ureq`, `serde_json` |
| [`pragmatic-cli`](crates/pragmatic-cli) | `pragmatic`: list, show, verify, export and serve runs; in 0.6 also erase, evidence and verify-evidence | none |
| [`pragmatic-console`](crates/pragmatic-console) | The HTML and CSV views of runs and evidence bundles (0.6) | none |
| [`pragmatic-python`](crates/pragmatic-python) | The Python SDK (`pragmatic-runtime`) | `pyo3` |
| [`pragmatic-ffi`](crates/pragmatic-ffi) | The C ABI behind the C++, Java, Go and Node.js bindings | none |
| [`pragmatic-server`](crates/pragmatic-server) | Pragmatic Server (0.6, commercial) | `axum`, `tokio` |

## Research

Pragmatic's replay soundness comes from **Agentical**, a probabilistic
process calculus in which each model call is a draw from a distribution
and every realized draw lands in the journal. [Read the concepts
doc](docs/concepts.md).

## License

- **Open source, Apache 2.0** (from release 0.5): the runtime, the Python
  SDK, the Rust crates and language bindings, the CLI, the journal format,
  the offline verifier and the console views. Use them anywhere, in
  production, at any scale. Anyone, including an auditor who does not
  trust the operator, can verify a journal or an evidence bundle with
  them. See [LICENSE](LICENSE).
- **Commercial: Pragmatic Server.** Its source is public in this
  repository under the Business Source License 1.1, so auditors can read
  it. Development, testing and evaluation are free. Production use needs
  a commercial license from Pragmatic Research, Inc. Each version becomes
  Apache 2.0 four years after its release.
- **Planned: a hosted independent witness**, run by Pragmatic Research,
  that cosigns anchors and sees only a log name and hashes.

Design partners: [contact us](mailto:me@aniketh.net?subject=Pragmatic%20commercial%20license).

© 2026 Pragmatic Research, Inc.
