# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com); versions follow
[SemVer](https://semver.org) (pre-1.0: minor bumps may break).

## [0.6.0] - Unreleased · system of record

0.6 turns the journal into a system of record: a complete, checkable
record of what an agent did that a party outside engineering can rely on,
while keeping crash recovery as the second pillar. The design it
implements is [docs/design/system-of-record.md](docs/design/system-of-record.md).
Pragmatic Server is in design-partner preview and is not generally
available. Like 0.5, this release has not been published to PyPI or
crates.io.

### Added

- **Journal format 2.** Every entry separates structure from content.
  *Fields* (step kind, branch, tool name, model, token usage) are chained
  directly and never hold personal data. *Slots* (prompts, responses,
  tool arguments and results) are sealed with a fresh random salt, and
  only their commitment enters the chain, so content can be erased while
  every chain hash still verifies. Identical content of 256 bytes or more
  is stored once. Decoding is strict and canonical, and the keyed (HMAC)
  flag lives in the file header and cannot be downgraded.
- **Intents and results for every model call and tool call.** The request
  is durably recorded before it is sent, and the response before the
  agent sees it. Tool calls receive an idempotency key derived from the
  run. Failed model calls (HTTP errors, transport errors, exceptions) and
  failed tool calls are recorded and replay as the same errors, so agent
  code that caught them behaves the same way on replay. Steps the runtime
  refused (an empty inbox, an exhausted budget, a denied capability) are
  recorded once the agent carries on past them.
- **Recovery decisions on resume.** A model call cut off by a crash is
  made again. A tool call cut off by a crash goes to your `recover` policy
  (commit with a result, compensate and retry, or fail). A tool call that
  failed and crashed the run is retried by default. Every decision is
  written to the journal as a `recovery` note.
- **Branches and parallel regions** (`Ctx::parallel`, `AsyncCtx::parallel`,
  Python `ctx.gather`). Children run on their own branches, results come
  back in order, a failing child never cancels its siblings, and replay is
  exact even when children interleave differently.
- **More recorded inputs:** random draws (`ctx.uuid4`, `ctx.random`,
  `ctx.randint`, `ctx.randbytes`) and UTC time (`ctx.datetime`).
- **Code changes under recorded runs:** `ctx.patched(name)` and
  `ctx.deprecate_patch(name)` let new code take a new path while old runs
  keep the old one. `on_code_change="refuse"|"continue"` sets what happens
  when the agent's source changes; an accepted change is recorded as a
  `program.change` note.
- **Run and attempt notes** on a separate branch that program replay does
  not match against (except `program.change` notes when checking code
  changes): run start (run id, labels, data subjects), each attempt's
  start and end (mode, principal, program hash, outcome, fresh token
  usage), recovery decisions, custody, erasures and torn tails.
- **Erasure.** `pragmatic erase RUN (--cursor N [--slot K] | --match TEXT)
  --reason-code CODE`, and the server's erase endpoint, remove content and
  salts from chosen slots, record an `erasure` note, and leave the chain
  verifiable. `verify` reports erased slots that no note accounts for.
- **A fuller verification report.** `verify` now checks every commitment
  as well as the chain, and reports the first bad entry, erasures that are
  unaccounted for or incomplete, and torn bytes. A damaged file is told
  apart from a crash: only torn, unacknowledged frames at the end are
  truncated (and their bytes moved aside first), never acknowledged
  entries.
- **Evidence bundles.** `pragmatic evidence RUN -o FILE` packages a run,
  with optional redaction that withholds whole slots.
  `pragmatic verify-evidence FILE` checks a bundle offline against the
  timestamp-authority roots, witness keys and log key you pin, and exits
  with `VERIFIED` (0), `VERIFIED (PARTIAL)` (2), `UNANCHORED` (3) or
  `FAILED` (1). `pragmatic render-evidence` writes HTML or CSV.
  `tools/verify_evidence.py` is an independent reference verifier that
  needs only Python and OpenSSL. The format is specified in
  `docs/evidence-format.md`, with an auditor's walkthrough in
  `docs/evidence.md`.
- **Anchoring** (Pragmatic Server). One append-only Merkle log of every
  run's state, with checkpoints in the C2SP format, time-stamped by RFC
  3161 timestamp authorities and cosigned by witnesses. A checkpoint
  counts as independently anchored once witnesses of
  `min_independent_operators` distinct operators (two by default) have
  verified it; the server's own signature never counts. Anchoring never
  blocks journaling, and its lag is a metric and an alert. The anchoring
  library, `crates/pragmatic-anchor`, is part of the commercial layer.
- **Pragmatic Server** (`crates/pragmatic-server`, commercial; design
  partners only). A shared journal store with one writer per run (leases),
  validation of every appended frame, tokens with roles (`agent`,
  `auditor`, `admin`) and run-id scopes, redacted views for auditors, an
  access log of every request that fails closed, legal holds, retention
  policies (minimum, shred, delete, erasure rule), tombstones, a subject
  index, webhooks, metrics, signed backups with restore, witness mode for
  cosigning other logs, a console, and deployment files for Docker,
  Kubernetes and systemd. See `docs/server.md`.
- **Python SDK.**
  - Model calls are journaled at the SDK's HTTP layer: `ctx.wrap(client)`
    and `pragmatic.wrap(client)` return a genuine Anthropic or OpenAI
    client. Streaming, `.parse()`, `with_raw_response`,
    `with_streaming_response`, `count_tokens`, the Anthropic tool runner
    and the SDK's own retries are all recorded. Transport headers and
    credentials are never recorded.
  - Frameworks that use these clients are covered: the OpenAI Agents SDK,
    Pydantic AI, LangChain (`pragmatic.integrations.langchain.journal`)
    and LangGraph.
  - `arun`, `aresume` and `areplay` run in your event loop; a `Runtime`
    can be shared across threads. `run`, `resume` and `replay` drive an
    async agent on a private event loop that each thread keeps from one
    call to the next, so an async client built once (`pragmatic.wrap` at
    module level, or a framework's default client) keeps its pooled
    connections from run to run.
  - Pragmatic Server as a store: `Runtime("https://...", token=...)` or
    `PRAGMATIC_URL` and `PRAGMATIC_TOKEN`, with leases renewed in the
    background. `python -m pragmatic push` uploads local format 2
    journals.
  - `labels=` and `subjects=` on runs; `volatile=` rules for request
    fields that change on every call; `rt.runs()`, `rt.entries(id)` and
    `rt.verify(id)` returning a report.
  - New exceptions: `Locked`, `Conflict`, `LeaseLost`, `Deleted`,
    `Erased`, `Unsupported`, `TooLarge`, `Unavailable`, `DanglingIntent`,
    `DanglingEffect`, `EffectFailed`, `DrawFailed`, `EffectUnrecorded`,
    `NotInRun`, `ServerError` and `JournalFault` (the carrier a fault
    travels in through a model SDK). A replayed failure is also an
    instance of the original exception type when that type is loaded.
  - Optional OpenTelemetry spans with `PRAGMATIC_OTEL=1`. Spans never
    carry content.
- **The `pragmatic-console` crate:** the HTML and CSV views of runs and
  evidence bundles, shared by the CLI and Pragmatic Server.
- **A one-command demo and an end-to-end suite.** `examples/demo/run.sh`
  tells the whole story on one machine against a real Pragmatic Server and
  two local timestamp authorities: a support agent crashes mid-refund and
  resumes in another process while a third is refused by the lease; the
  run is anchored, one message is erased, and the exported bundle verifies
  offline with pinned roots in both verifiers, is `UNANCHORED` with
  unrelated roots and fails with one byte changed. `tests/e2e` asserts the
  same steps against the real binaries, in CI and with outbound network
  blocked. The demo installs the SDK from a wheel rather than as an
  editable `.pth` file, which Python 3.13 and later skip when iCloud Drive
  marks it hidden, and both report a Python that cannot import the SDK as
  a setup problem with its fix.
- **Documentation:** `docs/threat-model.md`, `docs/compliance.md` (a
  mapping of record-keeping rules to what Pragmatic provides and what the
  customer is responsible for), `docs/privacy.md`, `docs/server.md`,
  `docs/evidence.md`, `docs/evidence-format.md` and `docs/python.md`, with
  `docs/usage.md`, `docs/quickstart.md` and `docs/concepts.md` brought up
  to journal format 2, recovery decisions and code changes.

### Changed (breaking)

- **Format 1 journals (written by 0.4 and 0.5) are read-only.** The CLI,
  the console and `verify` still read, verify and export them. Running,
  resuming or replaying them raises `Unsupported` with a pointer to the
  CLI. Finish or export in-flight 0.5 runs before upgrading, because a
  0.5 run cannot be resumed under 0.6.
- **Journal file names.** A directory store now names each journal after
  the SHA-256 of its run id, with a sidecar lock file, so any run id maps
  to a safe file name and two ids can no longer share one file. Format 1
  journals are still found under their old names for reading.
- **Rust API.**
  - `Runtime` methods take `&self`, and `Runtime` is `Send + Sync` when its
    oracle is. `begin` and `Attempt::finish` expose attempts directly.
  - `Runtime::verify` returns a `VerifyReport` instead of
    `Result<(), Cursor>`; `Journal::verify` checks every commitment, ref
    and chain link, and `Journal::audit` adds erasure accounting and
    returns a `VerifyReport`.
  - `Event` gains the format 2 kinds (`DrawIntent` and `DrawResult` replace
    `OracleDraw`; `EffectResult` replaces `EffectCommit` and
    `EffectCompensated`; new `Random`, `Fork`, `Marker`, `Note` and
    `Refusal`), carries content as `Content`, and is `#[non_exhaustive]`,
    as are `Fault`, `TraceLabel` and `VerifyReport`.
  - New faults: `Erased`, `Locked`, `Conflict`, `Unsupported`, `TooLarge`,
    `DanglingIntent`, `DanglingEffect`, `EffectUnrecorded`, `LeaseLost`,
    `Deleted` and `Unavailable`.
  - Trace labels carry their branch.
  - `evict` is a deprecated no-op.
  - The minimum Rust version is 1.89.
- **Python API.**
  - `Runtime(store=None, oracle=None, *, token=None, key=None, ...)`
    replaces `Runtime(dir, ...)`; `dir=` remains as a deprecated alias. A
    `Runtime()` with no store reads `PRAGMATIC_URL` and raises
    `ValueError` when it is not set.
  - The journaled clients need `anthropic>=1.0` or `openai>=3.0`. Older
    clients raise `Unsupported` with the upgrade to make.
  - Streaming and `.parse()` are journaled instead of refused.
  - `rt.verify(id)` returns a `VerifyReport`, which is true when the
    journal verifies, instead of a `bool`.
  - A `@durable` agent whose source changed now behaves by mode: `run`
    and `resume` continue by default and record the change as a
    `program.change` note, while `replay` still refuses unless you pass
    `on_code_change="continue"`.
- **Recovery with Pragmatic Server** needs an explicit `recover` policy
  for tool calls left unfinished by a crash; without one, resume raises
  `DanglingEffect` instead of compensating.
- **CLI.** `--key` is deprecated in favor of `--key-file` or
  `PRAGMATIC_JOURNAL_KEY`, so keys stay off the command line.

## [0.5.0] - Unreleased · drop-in Python

### Added
- **Drop-in journaling for the Anthropic and OpenAI Python SDKs.**
  `ctx.wrap(client)` returns a client you use exactly as before; every
  `messages.create` / `beta.messages.create` (Anthropic) and
  `chat.completions.create` / `responses.create` (OpenAI) call is
  journaled with its full request and response. Sync and async clients
  both work. Resume and replay hand back the same SDK response types
  rebuilt from the journal, with zero network calls. Streaming and
  `.parse()` are refused inside a durable run rather than silently
  bypassing the journal. Transport settings (`timeout`, `extra_headers`,
  `extra_query`) are never recorded, so auth headers stay out of journals.
- **`ctx.run_tools(response, tools)`** (and `arun_tools`): performs every
  tool call in an Anthropic `Message`, OpenAI `ChatCompletion`, or OpenAI
  `Response` as a write-ahead journaled effect named `tool:<name>` and
  returns the messages to append in the provider's format. A tool that
  raises is recorded and reported to the model as an error result.
- **Python surface parity with Rust:** `ctx.draw`/`adraw` for any other
  model client, `ctx.tool`/`atool` for journaled function calls,
  `ctx.aeffect`, async agents, `@pragmatic.durable` (source-hash program
  marker, so a changed agent refuses to replay), per-run `budget` and
  `caps`, a `recover` policy on `resume`, and `PRAGMATIC_JOURNAL_KEY` for
  signed journals.
- **Typed Python exceptions:** `PragmaticError`, with `JournalDesync` and
  `ReplayExhausted` subclasses. Faults keep their type across the Python
  boundary, and exceptions raised by agent code propagate unchanged.
- End-to-end Python tests drive the real Anthropic and OpenAI SDKs over a
  mock transport through record, crash, resume, and replay, run in CI on
  Python 3.10 and 3.13.
- `RELEASING.md`: one-time registry setup and the release checklist.

### Changed
- **License: Apache-2.0.** The runtime, SDKs, bindings, CLI and journal
  format are now open source under the Apache License 2.0, replacing the
  Business Source License 1.1 used by 0.4.0. Neither 0.4.0 nor 0.5.0 was
  published to a package registry, so the open-source license applies
  from the first published release. Contributions require a DCO sign-off.
- The Python package is now a mixed Rust/Python package: the extension
  moved to `pragmatic._native` and the public API lives in pure Python.
  `import pragmatic` and the existing `Runtime`/`ctx.oracle`/`ctx.effect`
  API are unchanged; `Runtime`'s `oracle` argument is now optional.
- `Ctx::oracle_replay`/`oracle_commit` and `effect_replay`/`effect_begin`/
  `effect_commit` are public: the split-phase record/replay steps for
  hosts that perform model and tool calls themselves.
- PyPI publishing uses trusted publishing (no API token). The v0.4.0
  release never reached PyPI or crates.io because the registry tokens were
  missing, and 0.5.0 was not published either.
- Roadmap reordered in `docs/STRATEGY.md`: installable drop-in Python
  first, then the hosted console, then the TypeScript SDK.

## [0.4.0] - 2026-08-08 · polyglot launch

### Added
- **Tool use, journaled end to end** (`pragmatic-anthropic`): structured
  conversations through the same `Oracle` contract. A [`Conversation`]
  prompt sends the full message history with the oracle's declared tools
  (`.tools(...)`); the journaled outcome is a [`Turn`] carrying the
  assistant's content blocks - `tool_use` intact - plus stop reason and
  token usage. Tools execute as `ctx.effect(...)` under the write-ahead
  discipline. Wire-tested: the full loop records over real sockets, the
  API is killed, resume and replay serve every model turn and tool result
  from the journal, and the tool is performed exactly once, ever. Live
  example: `cargo run -p pragmatic-anthropic --example tool_loop`.
  Plain-text prompts are unchanged (and never send tools), so existing
  journals replay as before.
- **`docs/STRATEGY.md`**: the durable record of the product wedge
  (auditability first, zero-token crash recovery second), roadmap order,
  and what is deliberately out of scope. Bindings for C++/Java/Go/Node are
  declared stable, maintenance-only.

- **C ABI** (`pragmatic-ffi`, `include/pragmatic.h`): the full runtime
  surface - run/resume/replay/send/verify plus ctx oracle/effect/recv/
  now/contract - as one flat `extern "C"` API with callback-based oracles,
  agents, and effects. Typed faults cross the boundary intact (budget stays
  budget, desync stays desync) via a pending-fault channel on the ctx.
  Zero dependencies; exercised by its own Rust-side C-discipline tests.
- **Language bindings** (`bindings/`), all on the C ABI, all journaling
  byte-compatibly with Rust and Python, each with a smoke test running the
  shared record → resume → replay → verify → typed-fault scenario:
  - **C++** (`bindings/cpp`): header-only C++17 RAII wrapper; lambdas as
    oracles/agents/effects; faults as `FaultError`; callback exceptions
    caught at the boundary.
  - **Java** (`bindings/java`): pure Java over `java.lang.foreign`
    (JDK 22+), no JNI glue to compile; try-with-resources runtimes and
    reports; faults as `FaultException`.
  - **Go** (`bindings/go`): cgo package with `cgo.Handle`-based callbacks;
    faults as `*Fault` with typed codes.
  - **Node.js** (`bindings/node`): pure-JS binding through koffi (Node has
    no built-in FFI); faults as `FaultError`; JS exceptions from callbacks
    rethrown intact.
- **`RetryOracle`** (core): wrap any oracle with bounded retries and
  doubling backoff on transient `OracleErr` faults - retries happen before
  anything is journaled, so a completion that finally succeeds is recorded
  once and replay never sees the failed attempts. Injectable sleeper for
  tests; provenance names the policy.
- **`pragmatic-openai`**: any OpenAI-compatible Chat Completions server as
  a journaled Oracle - OpenAI itself, or Ollama / vLLM / llama.cpp / Groq
  via `base_url` (keyless servers supported; no Authorization header sent
  without a key). Wire-tested over real sockets like the Anthropic
  adapter, including record-on-the-wire → kill-the-API → resume/replay
  from the journal; a `--ignored` test hits the live API when
  `OPENAI_API_KEY` is set.

### Changed
- **License**: relicensed from MIT OR Apache-2.0 to the
  [Business Source License 1.1](LICENSE). Free for non-production use, and
  for production use by organizations under US $1M annual revenue; each
  released version converts to Apache 2.0 on its Change Date, four years
  after release. The Licensor is **Pragmatic Research, Inc.**
- README repositioned around the two production pains (runs dying,
  audits asking what the agent did), featuring the real tool-use loop and
  an explicit "Why not Temporal (or Restate, Inngest, DBOS)?" comparison.

## [0.3.0] - 2026-07-14 · customer-ready beta

### Added
- **Async runtime** (`AsyncOracle`, `AsyncCtx`, `AsyncRuntime`, `block_on`):
  the same guarantees for `async` agents, executor-agnostic (tokio, smol, or
  the built-in `block_on`), still zero dependencies. Every sync `Oracle` is
  automatically usable; `#[pragmatic::durable]` works on `async fn`.
- **Python bindings** (`pragmatic-python`, PyPI name `pragmatic-runtime`):
  `Runtime(dir, oracle)` with Python-callable oracles/agents/effects;
  run/resume/replay/verify/send; faults raise `RuntimeError`. Journals are
  byte-compatible with the Rust runtime and the CLI.
- **`pragmatic serve`**: a live, self-hostable web console over a journal
  directory (run index, chain status, dangling-effect warnings, per-run
  replay timelines). Loopback-only by default; zero dependencies.
- **Wire-level validation** of `pragmatic-anthropic`: real-socket tests
  against a Messages-API mock (success, 429, 529, malformed JSON,
  connection refused) plus the headline scenario - record on the wire,
  kill the API, resume and replay from the journal. A `--ignored` test
  hits the live API when `ANTHROPIC_API_KEY` is set.

### Fixed
- **Replay divergence** on journals containing a compensated effect
  followed by its re-performed pair (`Intent, Compensated, Intent,
  Commit`): the effect replay path now consumes every compensated pair
  and the final commit instead of desyncing later steps. Regression test
  included.

## [0.2.0] - 2026-07-13 · public beta

The first tagged release. Workspace of four crates:

### Added
- **`pragmatic`** (core, zero runtime dependencies)
  - `Journal`: append-only, cursor-keyed, SHA-256/HMAC hash-chained event
    log; in-memory and durable file backends; torn-tail truncation on open;
    tamper detection via `verify`.
  - `Oracle` trait: the LLM call as a first-class distribution; `SeededOracle`,
    `CountingOracle`, `RefusingOracle` for tests and audits.
  - `Ctx`: one agent code path for record and replay - journaled oracle
    draws, channel receives, clock reads; three-phase write-ahead durable
    effects; budget and effect-capability enforcement; `program_marker`.
  - `Runtime`: `run` / `resume` / `resume_with` / `replay` keyed by run id.
    Strict replay never calls the model. Dangling-intent recovery policies
    (`Recover::Commit` / `Recover::Compensate`).
  - `Supervisor`: fault → decision control plane (restart-from-journal,
    reverse-order saga compensation, escalation).
  - `Store`: IFC-labeled memory (no read-up / no write-down).
  - `Event::Program`: program identity journaled at step zero and verified
    on replay - changed agent code fails as `JournalDesync` instead of
    misreplaying.
- **`pragmatic-macros`**: `#[pragmatic::durable]` - hashes the function's
  source tokens and injects the program marker. Zero dependencies.
- **`pragmatic-anthropic`**: Claude as a journaled Oracle over the Messages
  API (model / system / temperature / max_tokens config, provenance
  metadata, faults mapped to `Fault::OracleErr`).
- **`pragmatic-cli`** (binary `pragmatic`): `runs`, `show`, `verify`, and
  `export` - a self-contained HTML replay console per run.

### Measured
- E1: 1000/1000 seeded stochastic runs replay byte-identically, zero model
  calls during replay.
- E2: crash at every journal prefix resumes exactly; no re-sampling of the
  surviving prefix; no orphaned effects; survives process restarts.
- E3: O(1) append, flat from 1k to 1M entries (~0.8 µs with full hash
  chaining, release build); ~1000× replay speedup under a 1 ms/draw oracle.

[0.4.0]: https://github.com/pragmaticco/pragmatic/releases/tag/v0.4.0
[0.3.0]: https://github.com/pragmaticco/pragmatic/releases/tag/v0.3.0
[0.2.0]: https://github.com/pragmaticco/pragmatic/releases/tag/v0.2.0
