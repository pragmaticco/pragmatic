# Stet for Python

**The black-box recorder for LLM agents.** The package is
`pragmatic-runtime` and its import name is `pragmatic`: Stet was called
Pragmatic until October 2026, and the names in code did not change.

Wrap your existing Anthropic or OpenAI client and every model call and tool
call your agent makes is journaled to an append-only, hash-chained log,
streams included. Nothing else about your agent changes, and the agent
frameworks built on those clients (the OpenAI Agents SDK, Pydantic AI,
LangChain, LangGraph) are journaled the same way. A crashed run resumes
where it stopped without paying again for model answers already recorded
or repeating tool calls whose results are on record, and any run replays
exactly, for debugging or for an auditor, without touching the network.

> **Status.** This is 0.6.0, the system-of-record release. It is not on
> PyPI yet: install it from a clone of the repository's `system-of-record`
> branch, where 0.6 is until it is merged to `main` (see
> [Build from source](#build-from-source)). Release 0.5, the earlier
> drop-in release, is on the `release/0.5.0` branch and is not on PyPI
> either. Stet Server, the optional store for runs on a server, is in
> design-partner preview.

```sh
pip install "./crates/pragmatic-python[anthropic]"   # from a clone; or [openai]; needs anthropic>=1.0 / openai>=3.0
pip install "pragmatic-runtime[anthropic]"           # once it is published
```

## Your agent, journaled

```python
import anthropic
import pragmatic

TOOLS = [{"name": "search", "description": "Search the corpus",
          "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}]

def search(q: str) -> list[str]:
    ...  # your tool

rt = pragmatic.Runtime("./journals")

def research(ctx):
    client = ctx.wrap(anthropic.Anthropic())           # the only new line
    messages = [{"role": "user", "content": "Find papers on durable execution."}]
    while True:
        msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=1024,
                                     tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": msg.content})
        if msg.stop_reason != "tool_use":
            return msg.content[0].text
        messages += ctx.run_tools(msg, {"search": search})   # journaled tools

report = rt.run("research-42", research)
```

`ctx.wrap(client)` returns a genuine client of the same class, journaled at
the HTTP layer: every request it sends is recorded before it is sent, and
the response is recorded as the agent reads it. On resume or replay the
response comes back from the journal byte for byte, so the SDK builds the
very same `Message`, `ChatCompletion` or `Response`, the same stream events,
the same parsed output.

`ctx.run_tools(response, tools)` performs every tool call in a response as
a write-ahead journaled effect and returns the messages to append, in the
provider's format. A tool that raises is recorded and reported to the model
as an error result instead of crashing the run.

## Crash, resume, replay, verify

```python
# The process died mid-run. Resume: the journaled prefix is read back
# (no API calls, no repeated tool calls) and recording continues.
report = rt.resume("research-42", research)

# Audit: replay the whole run. Nothing is sampled or performed; if the
# code or its inputs changed, it fails with JournalDesync at the first
# differing step instead of silently diverging.
audit = rt.replay("research-42", research)
assert audit.output == report.output

# Tamper evidence: verify checks the hash chain and every commitment, and
# returns a VerifyReport, truthy when the journal is intact.
assert rt.verify("research-42")
```

Render a run as a self-contained HTML timeline for an incident ticket or an
auditor with the CLI: `pragmatic export research-42 --dir ./journals`.

## What is journaled

Everything the SDK client sends goes through one point, its HTTP client, so
there is no list of supported methods. That covers `create`, `stream=True`
and the `.stream()` helpers (`text_stream`, `get_final_message`,
`get_final_completion`, `get_final_response`), `.parse()`,
`with_raw_response`, `with_streaming_response`, token counting, the
Anthropic tool runner, and the SDK's own retries: a `429` and its retry are
two journaled exchanges, and replay serves the `429` with a one-millisecond
retry hint, so nothing waits. Errors replay as the same SDK exceptions.

A stream is recorded as the agent reads it. A stream the agent closes early
is recorded with the bytes it read (`partial`), and replay serves exactly
those. A stream the agent drops, leaves unread when it takes its next step,
or leaves open when it returns is written off the same way, so the record
always holds what the agent saw.

Clients from older SDKs (`anthropic<1.0`, `openai<3.0`, built on legacy
`httpx`) raise `pragmatic.Unsupported` with the upgrade to make. Websocket
and realtime connections raise `Unsupported`: make a durable run's model
calls over HTTP. For any other model client, journal calls yourself with
`ctx.draw(prompt, sample)` (or `await ctx.adraw(...)`), where `prompt` fully
identifies the request.

## Frameworks

`pragmatic.wrap(client)` journals a client into whichever run calls it, so
it can be built once and handed to a framework:

```python
import openai, agents, pragmatic

agents.set_default_openai_client(pragmatic.wrap(openai.AsyncOpenAI()))

async def triage(ctx):
    result = await agents.Runner.run(agent, "Triage ticket 4411")
    return result.final_output

rt.run("ticket-4411", triage)       # or await rt.arun(...) inside your event loop
```

An async client keeps its pooled connections on the event loop that opened
them. `rt.run` drives async agents on a private loop that its thread keeps
from one call to the next, so the client above serves run after run; with
`await rt.arun(...)`, use it from one long-lived loop. Where calls would
run on different loops (repeated `asyncio.run`, or `rt.run` from several
threads), build the client inside the agent with `ctx.wrap`.

| Framework | How |
|---|---|
| OpenAI Agents SDK | `set_default_openai_client(pragmatic.wrap(AsyncOpenAI()))`, `run` and `run_streamed` |
| Pydantic AI | `AnthropicProvider(anthropic_client=pragmatic.wrap(...))`, `OpenAIProvider(openai_client=...)` |
| LangChain | `pragmatic.integrations.langchain.journal(ChatAnthropic(...))`, or `ChatOpenAI` |
| LangGraph | build the agent on a journaled LangChain model |

Outside a run, a journaled client raises `pragmatic.JournalFault` carrying
`NotInRun` (read its `.error`). The carrier derives from `BaseException`
only, so the SDK's retries and frameworks' `except Exception` do not
swallow it, and `except pragmatic.NotInRun` does not catch it either.
`pragmatic.wrap(client, outside="passthrough")` lets those calls through
unrecorded. Request fields that change on every run, such as the Agents
SDK's per-run prompt cache key, are ignored when replay matches requests;
add your own with `pragmatic.Runtime(dir, volatile=["$.metadata.session_id"])`.
The rules in force are named in the journal.

## Async agents

Make the agent `async def`, use the async client and `await ctx.adraw`,
`await ctx.arun_tools` and `await ctx.atool`, and run it with
`await rt.arun(...)` inside your own event loop (or `rt.run(...)` from
synchronous code, which uses a private loop). Storage work runs on a
dedicated thread per attempt, so many runs can share one loop.

Run independent work concurrently with `ctx.gather`: each child records on
a branch of its own, so the run replays exactly however the children
interleave, and a failing child never cancels its siblings.

```python
async def research(ctx):
    a, b = await ctx.gather(lambda c: survey(c, "papers"), lambda c: survey(c, "code"))
    ...
```

Blocking work can step through `asyncio.to_thread`. Tasks made with
`asyncio.create_task`, `asyncio.gather` or `asyncio.shield`, and threads
from `loop.run_in_executor`, do not belong to the run: their steps raise
`pragmatic.NotInRun`, because the order they would land in the journal
could not be reproduced. Model calls through a journaled client are the
exception: frameworks make them from tasks and threads of their own, so
any caller that inherited the run's context may make them, and they are
matched by request on replay.

Time a step out with `asyncio.timeout` (or `asyncio.wait_for` from Python
3.12): a step the agent cancels and carries on past is recorded as a
failure, so the run ends normally, and replay waits at that step until the
timeout fires again.

## Runs on a server

```python
rt = pragmatic.Runtime("https://pragmatic.example.com", token=TOKEN)
# or set PRAGMATIC_URL and PRAGMATIC_TOKEN and call pragmatic.Runtime()
```

The runtime checks the server when it is built, holds a lease on each run
it writes (renewed in the background, through slow model calls and tools),
resends appends the server did not acknowledge, and verifies every journal
it downloads. A resume on a server needs a `recover` policy for tools that
crashed mid-call. `python -m pragmatic push DIR RUN` uploads journals
recorded locally. See [Stet Server](../../docs/server.md); the
one-command demo, `examples/demo/run.sh`, runs an agent against one end to
end.

## More controls

```python
@pragmatic.durable                     # journal the agent's source hash:
def research(ctx): ...                 # a changed agent refuses to replay
@pragmatic.durable(version="2")        # or an explicit version

ctx.tool("fetch", fetch_url, url)      # any function as a journaled effect;
                                       # it gets idempotency_key= if it takes one
ctx.now(), ctx.datetime()              # journaled clock
ctx.uuid4(), ctx.random(), ctx.randint(1, 6), ctx.randbytes(16)
ctx.recv("approval")                   # journaled input from rt.send(...)
if ctx.patched("validate-input"): ...  # change code under recorded runs

rt.run("r1", agent, budget=50)                  # cap model calls
rt.run("r1", agent, caps=["tool:search"])       # allowlist tools
rt.run("r1", agent, labels={"team": "research"}, subjects=["user-17"])
rt.resume("r1", agent, recover=lambda name, arg: None)   # settle tools
                                                         # that crashed mid-call
rt.verify("r1")                                 # a VerifyReport, truthy if intact
rt.runs(), rt.entries("r1")                     # summaries and entries

pragmatic.Runtime("./journals", key=b"...")     # HMAC-key local journals
# or set PRAGMATIC_JOURNAL_KEY
```

What is in a journal: the full request (method, path, query, body; each
message in a slot of its own, so a conversation's earlier messages are
stored once and can be erased once) and full response (status, the
content-type, request-id and retry headers, and the body) of every model
call, with the provider, model, stop reason, token usage and latency, and
the input and output of every tool call. Transport headers, and query
parameters named like credentials, are never recorded, so API keys and auth
headers never reach the journal.

See [the Python guide](../../docs/python.md) for streaming, recovery,
frameworks, normalization and the rest.

## Build from source

```sh
git clone -b system-of-record https://github.com/pragmaticco/pragmatic
cd pragmatic/crates/pragmatic-python
pip install .                  # or, for an editable install: pip install maturin && maturin develop --release
pip install pytest "anthropic>=1.0" "openai>=3.0" && pytest tests
# optional, for the framework tests:
pip install openai-agents "pydantic-ai-slim[anthropic,openai]" langchain-anthropic langchain-openai langgraph
```

`maturin develop` installs the package as an editable `.pth` file, and
Python 3.13 and later skip a `.pth` file that is marked hidden. On a Mac,
iCloud Drive marks every file of a virtual environment hidden when it
syncs the folder it is in (Desktop or Documents), and `import pragmatic`
then fails with `ModuleNotFoundError`. There, use `pip install .` (and run
it again after each change), or keep the virtual environment outside the
synced folders.

The journal files are the same format the Rust runtime and the `pragmatic`
CLI read.
