<div align="center">

# Stet

**The system of record for AI agents.** Every model call and tool call
your agent makes through Stet's journaled interfaces is recorded
before the agent sees the result, in a tamper-evident journal. With
anchoring (0.6, design-partner preview), anyone can check it without
trusting you. A crashed run picks up where it stopped, without repeating
recorded model answers or tool calls whose results are on record.

[![CI](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml/badge.svg)](https://github.com/pragmaticco/pragmatic/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)
![status: pre-release](https://img.shields.io/badge/status-pre--release-yellow.svg)

[Demo](examples/demo/README.md) · [Usage guide](docs/usage.md) · [Quickstart](docs/quickstart.md) ·
[Python](docs/python.md) · [Concepts](docs/concepts.md) · [Stet Server](docs/server.md) ·
[Evidence for auditors](docs/evidence.md) · [Threat model](docs/threat-model.md) ·
[Compliance mapping](docs/compliance.md) · [Privacy](docs/privacy.md) · [Strategy](docs/STRATEGY.md) ·
[Product page](https://aniketh.net/pragmatic/stet/) · [Early access / design partners](mailto:me@aniketh.net?subject=Pragmatic%20early%20access)

</div>

---

Sooner or later someone outside engineering asks what your agent did. It
might be a customer's security review, an auditor, a regulator or a court.
"Here are our traces" is a weak answer when the traces sit in a database
anyone with access can edit, and expire after a few weeks.

Stet gives you a better answer. It is built for teams putting AI
agents into production in fintech, insurance, health and legal work, and
for AI-agent startups selling to regulated enterprises.

> **Status.** No release is on PyPI or crates.io yet; build from source.
> Release **0.5** (drop-in Python, Apache 2.0) is on the `release/0.5.0`
> branch. The `system-of-record` branch builds **0.6.0**, the
> system-of-record release (`main` holds 0.4.0 until 0.6 is merged):
> everything marked **0.6** below (journal format 2, erasure, anchoring,
> evidence bundles and Stet Server) is implemented and tested there.
> Stet Server is in **design-partner preview** and is not generally
> available.
>
> **Name.** Stet was called Pragmatic until 2026-10-23, and Stet Server
> was Pragmatic Server; the company is still Pragmatic Research, Inc. The
> names in code have not changed: you `import pragmatic` (the package is
> `pragmatic-runtime`), mark agents with `@pragmatic.durable`, run the
> `pragmatic` CLI, and depend on the `pragmatic-*` crates.

## Try the whole story

One command runs the product end to end on your own machine:

```sh
git clone -b system-of-record https://github.com/pragmaticco/pragmatic
cd pragmatic
examples/demo/run.sh            # add --open to open the auditor's report at the end
```

It starts a real Stet Server and two local timestamp authorities,
then follows a support agent through a refund. The agent crashes the
moment the payment provider acts, and a second process resumes it without
refunding twice or asking the model again, while a third is turned away.
The run is anchored, the customer's message is erased, and an auditor
exports an evidence bundle and checks it offline with two independent
verifiers: it passes with the pinned roots, is `UNANCHORED` with the
wrong ones, and fails with one byte changed. Each step prints `[ok]`
lines, one per check that ran and held.

The models are scripted stand-ins, so no API key or account is needed and
nothing is billed. The demo needs Rust 1.89 or later, Python 3.10 or later
and OpenSSL 3, and prints the command that installs whichever is missing.
The first run builds Stet from source and takes a few minutes. See
[examples/demo](examples/demo/README.md). The same steps run as
assertions against the real binaries in the end-to-end suite,
[tests/e2e](tests/e2e/README.md) (`python -m pytest tests/e2e -v`).

## What Stet records, and what you can prove with it

Every model call, tool call, message received, random draw and clock read
that your agent makes through Stet's journaled interfaces is written
to a journal **before** its result reaches the agent. The journal is:

- **Tamper-evident.** Each entry is chained to the one before it with
  SHA-256. Change any recorded entry and verification reports the exact
  entry where the chain breaks. A secret key, or anchoring, also catches
  someone who recomputes the whole chain after an edit.
- **Anchored** (0.6, Stet Server). The state of every run is
  time-stamped by independent timestamp authorities. With plain run ids
  (the default), even the person who runs the server cannot quietly
  rewrite anchored history: an auditor who checks the full anchor log
  against a pinned witness would see it. See the
  [threat model](docs/threat-model.md).
- **Replayable exactly.** Replay runs your agent code against the journal
  and serves every recorded answer. The model is never called and no tool
  runs again.
- **Erasable for privacy law** (0.6). Personal content can be erased
  while the rest of the journal still verifies.
- **Retained by policy, access-controlled and attributed** (0.6, Stet
  Server). Retention rules, legal holds, roles, scoped tokens, and an
  access log of every request.
- **Exportable as evidence** (0.6). An evidence bundle is one file that an
  auditor verifies on their own laptop, offline, against trust roots they
  choose themselves.

## And when a run crashes

A run that dies 900 steps into a 1,000-step job resumes from its journal,
on any machine that can reach the journal. Recorded model answers are read
back instead of being requested again, and tool calls whose results are on
record are not repeated.

A call that the crash cut off midway, with no result on record, is
handled in the open:

- A model call is sent again. If the provider answered but the answer was
  not recorded before the crash, you pay for that call twice.
- A tool call goes to your `recover` policy, which can record that it
  happened or perform it again. Without a policy, local runs perform it
  again; with Stet Server (0.6), a policy is required. In 0.6 a tool
  that takes an `idempotency_key` argument receives one, so it can
  recognize the repeat.

Only one process should continue a run at a time. In 0.5 nothing enforces
this. In 0.6 a file lock stops a second process on the same machine, and
Stet Server's lease stops one on any machine. A network file system
gives no exclusion across machines, so do not share a journal directory
between hosts; use Stet Server instead.

## How it differs

- **Observability tools** (such as Langfuse, LangSmith and Datadog)
  record traces in databases that can be edited. Hosted tracing services
  typically set retention by plan, and self-hosted stacks by your own
  configuration.
- **Durable-execution engines** (Temporal, DBOS) recover workflows after a
  crash, but their history is engine state, not an audit record that an
  outsider can check.
- **A model or cloud provider's own logs** cover one vendor, and only that
  vendor vouches for them.
- **Stet** captures every call made through its journaled
  interfaces (a result reaches the agent only after it is recorded),
  replays without calling the model, and produces evidence anyone can
  verify without trusting the operator.

| | Tracing tools | Durable-execution engines | Stet |
|---|---|---|---|
| When a call is recorded | After the fact, by an exporter; recording prompt content is often optional | When the engine checkpoints a step | Before the result reaches the agent |
| Tamper evidence | None: an ordinary database | None: the history is not signed or anchored | A hash chain, plus anchoring with independent timestamp authorities (0.6) |
| How long it is kept | Set by the hosted plan, or by your own configuration when self-hosted | Set by the engine's history retention | Your retention policy, with legal holds (0.6) |
| Replay a run without the model | No | Inside the engine, against its history | Anywhere, from the journal; the model is never called |
| Crash recovery | No | Yes | Yes, without repeating recorded model answers or committed tool calls |
| Erase one person's data and still prove the rest | No | No | Yes (0.6) |
| Checked by an outsider who does not trust you | No | No | Yes: an offline verifier with pinned trust roots (0.6) |
| What you run | A hosted service or a self-hosted stack | A cluster or a cloud service | A library in your agent, plus Stet Server if you want it |

If you already run Temporal or DBOS for general workflows, keep it.
Stet is for the agent itself, when its record has to hold up in front
of someone who does not trust you.

## Your agent, journaled

Until the SDK is on PyPI, install it from a clone of this repository's
`system-of-record` branch (this needs a Rust toolchain):

```sh
git clone -b system-of-record https://github.com/pragmaticco/pragmatic
cd pragmatic
pip install "./crates/pragmatic-python[anthropic]"   # or [openai]
```

That builds 0.6.0 (a clone of `main` would build 0.4.0). Once it is
published, it becomes `pip install "pragmatic-runtime[anthropic]"`. The
0.5 release is on the `release/0.5.0` branch; it records only `create`
calls, and its journals (format 1) are read-only under 0.6.

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
        msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=16000,
                                     tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": msg.content})
        if msg.stop_reason != "tool_use":
            return "".join(b.text for b in msg.content if b.type == "text")
        messages += ctx.run_tools(msg, {"search_corpus": search_corpus})

rt.run("research-42", research)       # record
rt.resume("research-42", research)    # after a crash: recorded results are reused
rt.replay("research-42", research)    # audit: the model is never called, no tool runs
assert rt.verify("research-42")       # the chain and every commitment check out
```

`ctx.wrap` returns a genuine Anthropic or OpenAI client, sync or async,
journaled at the SDK's HTTP layer (it needs `anthropic>=1.0` or
`openai>=3.0`). So `create`, streaming, `.parse()`, raw responses, token
counting, the Anthropic tool runner and the SDK's own retries are all
recorded, and so are the frameworks built on these clients: the OpenAI
Agents SDK, Pydantic AI, LangChain and LangGraph. The same agent runs
against Stet Server with `pragmatic.Runtime("https://...",
token=...)`. Details: [crates/pragmatic-python](crates/pragmatic-python)
and [docs/python.md](docs/python.md).

## Verify a run

From the command line (`cargo install --path crates/pragmatic-cli` from
the same checkout, until the release is published):

```sh
pragmatic verify research-42 --dir ./journals      # the chain, every commitment, erasures
pragmatic serve --dir ./journals                   # a local console on 127.0.0.1:7171
pragmatic export research-42 --dir ./journals      # one run as a self-contained HTML page
```

You can also package a run as an evidence bundle and check it the way an
auditor would:

```sh
pragmatic evidence research-42 --dir ./journals -o research-42.evidence.json
pragmatic verify-evidence research-42.evidence.json
```

A bundle built from a local journal has no anchors. It shows that the
record is internally consistent, not when it existed or that it was not
rewritten before export, so the verifier reports `UNANCHORED`. A bundle
exported from Stet Server carries its anchors. The auditor
checks it against timestamp-authority roots and keys they obtained
themselves, never ones taken from the bundle:

```sh
pragmatic verify-evidence support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTimeStampingCA.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem \
  --log-key "pragmatic/acme/0123456789abcdef+5e6f7a8b+AQ..."
```

The verdict is `VERIFIED` (exit 0) when the whole journal is anchored by
at least `--min-operators` (by default two) independent operators the
auditor trusts, `VERIFIED (PARTIAL)` (exit 2) when only the start of it
is, `UNANCHORED` (exit 3), or `FAILED` (exit 1). A second verifier written in plain Python, sharing
no code with the first (`tools/verify_evidence.py`), runs the same checks.
`pragmatic render-evidence` writes the report as HTML, or the records as
CSV. The auditor's walkthrough is [docs/evidence.md](docs/evidence.md),
and the normative format is [docs/evidence-format.md](docs/evidence-format.md).

## Stet Server (design-partner preview)

The open-source runtime writes journals on the machine that runs the
agent. Stet Server is the commercial product that turns them into a
shared system of record. It runs inside your own infrastructure, so your
prompts and outputs never reach us. In 0.6 it provides:

- one journal store for all your agents, with a single writer per run;
- independent anchoring with RFC 3161 timestamp authorities and witnesses;
- retention policies, legal holds, and erasure that keeps the proof;
- roles, scoped tokens and an access log of every request;
- redacted views for auditors, and evidence bundles on demand;
- a console for runs, verification status, holds and the access log.

All of it, anchoring, evidence export and the console included, is
implemented in this repository and exercised end to end by
[the demo](examples/demo/README.md) and [tests/e2e](tests/e2e/README.md).
Stet Server is in design-partner preview and is not generally
available. Install, configuration, tokens, sizing, backups and upgrades
are in [docs/server.md](docs/server.md). To join as a design partner,
[contact us](mailto:me@aniketh.net?subject=Pragmatic%20design%20partner).

## Measured, not promised

Every row is a test in this repository. The timings come from 0.6.0 in
release mode on an Apple M5 Pro.

| Claim | Result | Test |
|---|---|---|
| **Replay determinism** (E1) | 1,000 of 1,000 seeded random runs replay byte for byte with zero model calls. Runs with parallel branches replay exactly even when the branches interleave differently | `e1_replay_determinism` |
| **Crash recovery** (E2) | A run crashed at every possible journal prefix resumes exactly: nothing journaled is requested again, and no tool call is left unaccounted for | `e2_crash_recovery` |
| **Tool-use loop** | A full Messages API tool loop recorded over real sockets; the API is shut down; resume and replay match byte for byte; the tool ran exactly once | `pragmatic-anthropic` `wire` |
| **Journal overhead** (E3) | Appending takes constant time: about 2.2 µs per entry at 1,000,000 entries and 2.3 to 2.5 µs at 1,000 (journal format 2, in memory, not counting the disk sync), including a fresh random salt and a SHA-256 commitment for every content slot and the chain hash. Earlier releases quoted about 0.44 µs for format 1, which did less work per entry | `e3_journal_overhead` |
| **Replay cost** (E3) | 40 calls to a stand-in model that takes 5 ms per call: about 245 ms to record and about 0.24 ms to replay, roughly 1,000 times faster, because replay makes no model calls | `e3_journal_overhead` |
| **Tamper evidence** | Any change to a recorded entry is reported at that entry; a keyed journal refuses a wrong or missing key | `audit_trail` |
| **Code-change safety** | Replaying a run under changed agent code stops with `JournalDesync` unless you opt in to the change, and a resume under changed code records the change in the journal | `code_changes` |

To measure them yourself:

```sh
cargo test --release -p pragmatic --test e1_replay_determinism --test e2_crash_recovery \
  --test e3_journal_overhead --test audit_trail --test code_changes -- --nocapture
cargo test --release -p pragmatic-anthropic --test wire
```

## Network behavior and telemetry

Stet sends no telemetry, checks for no updates and reports no
crashes. The SDK talks only to model APIs through your own SDK clients,
and to your Stet Server if you configure one. The server talks only
to the timestamp authorities, witnesses and webhook URLs you configure. A
timestamp authority receives a 32-byte digest and a random number; a
witness receives a log name, a sequence number, a tree size and a root
hash; a webhook receives an event type, a run id and counts. No prompt,
output or other content leaves the server.

## Honest scope

- Stet records what goes through its journaled interfaces: wrapped
  model clients, `ctx.tool`, `ctx.run_tools`, `ctx.effect`, received
  messages, clock reads and random draws. Anything the agent does another
  way is not recorded. MCP tool calls made through the `mcp` package's own
  client need `ctx.tool`, and websocket and realtime APIs are not
  supported yet.
- A journaled client records everything that passes through the SDK's
  HTTP client. It refuses, with `Unsupported`, requests to another host
  and clients older than `anthropic` 1.0 or `openai` 3.0. Release 0.5
  recorded only `create` calls, refused streaming and OpenAI's `.parse()`,
  and let other calls, including most framework calls, run unrecorded
  without a warning. If you run 0.5, check that your framework's calls
  appear in the journal.
- A journal on the agent's own machine can be deleted by whoever controls
  that machine. Anchoring and Stet Server make deletion and rewriting
  detectable; see the [threat model](docs/threat-model.md).
- Anchoring proves that a journal existed, exactly as it is, no later than
  a certain time. It does not prove that what the agent was told was true.
- Journals hold prompts and outputs in plain text, because they are the
  record. Protect them like the data they contain. See
  [SECURITY.md](SECURITY.md) and [docs/privacy.md](docs/privacy.md).
- Stet helps you meet record-keeping obligations; it does not meet
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
| [`pragmatic`](crates/pragmatic) | The runtime: journal, replay, recovery, verification, erasure and evidence bundles | none |
| [`pragmatic-macros`](crates/pragmatic-macros) | `#[pragmatic::durable]`: program identity, recorded and checked | none |
| [`pragmatic-anthropic`](crates/pragmatic-anthropic) | Claude as a journaled model, including tool-use loops | `ureq`, `serde_json` |
| [`pragmatic-openai`](crates/pragmatic-openai) | Any OpenAI-compatible server as a journaled model | `ureq`, `serde_json` |
| [`pragmatic-cli`](crates/pragmatic-cli) | `pragmatic`: list, show, verify, export, serve and erase runs; write evidence bundles, verify them offline against pinned trust roots, and render them as HTML or CSV | none |
| [`pragmatic-console`](crates/pragmatic-console) | The HTML and CSV views of runs and evidence bundles, shared by the CLI and Stet Server | none |
| [`pragmatic-python`](crates/pragmatic-python) | The Python SDK (`pragmatic-runtime`) | `pyo3` |
| [`pragmatic-ffi`](crates/pragmatic-ffi) | The C ABI behind the C++, Java, Go and Node.js bindings | none |
| [`pragmatic-server`](crates/pragmatic-server) | Stet Server (commercial, design-partner preview) | `axum`, `tokio` |
| [`pragmatic-anchor`](crates/pragmatic-anchor) | Anchoring for Stet Server (commercial) | `ureq`, `ed25519-dalek` |

## Research

Stet's replay soundness comes from **Agentical**, a probabilistic
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
- **Commercial: Stet Server** (`pragmatic-server`, with its anchoring
  crate `pragmatic-anchor`). Their source is public in this repository
  under the Business Source License 1.1, so auditors can read it.
  Development, testing and evaluation are free. Production use needs a
  commercial license from Pragmatic Research, Inc. Each version becomes
  Apache 2.0 four years after its release.
- **Planned: a hosted independent witness**, run by Pragmatic Research,
  that cosigns anchors and sees only a log name and hashes.

Design partners: [contact us](mailto:me@aniketh.net?subject=Pragmatic%20commercial%20license).

© 2026 Pragmatic Research, Inc.
