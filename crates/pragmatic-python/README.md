# pragmatic (Python)

**The black-box recorder for LLM agents.**

Wrap your existing Anthropic or OpenAI client and every model call and tool
call your agent makes is journaled to an append-only, hash-chained log.
Nothing else about your agent changes. A crashed run resumes where it
stopped without re-paying for a single token or repeating a tool call, and
any run replays exactly, for debugging or for an auditor, without touching
the network.

```sh
pip install "pragmatic-runtime[anthropic]"    # or [openai]
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

`ctx.wrap(client)` returns an object you use exactly like the client. On the
first run each call goes to the API and its response is journaled. On
resume or replay the response comes back from the journal as the same SDK
type (`Message`, `ChatCompletion`, `Response`), byte for byte.

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

# Tamper evidence: any edit to the journal breaks the hash chain.
assert rt.verify("research-42")
```

Render a run as a self-contained HTML timeline for an incident ticket or an
auditor with the CLI: `pragmatic export research-42 --dir ./journals`.

## Supported clients

| Client | Journaled calls |
|---|---|
| `anthropic.Anthropic`, `AsyncAnthropic` | `messages.create`, `beta.messages.create` |
| `openai.OpenAI`, `AsyncOpenAI`, `AzureOpenAI` | `chat.completions.create`, `responses.create` |

Streaming (`stream=True`, `.stream()`) and `.parse()` are refused inside a
durable run with a clear error rather than silently bypassing the journal.
Anything else on the client passes through unchanged. For other model
clients, journal calls yourself with `ctx.draw(prompt, sample)` (or
`await ctx.adraw(...)`), where `prompt` fully identifies the request.

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
`asyncio.create_task` or `asyncio.gather`, and threads from
`loop.run_in_executor`, do not belong to the run: their steps raise
`pragmatic.NotInRun`, because the order they would land in the journal
could not be reproduced.

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
recorded locally.

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

What is in a journal: the full request (model, messages, tools, parameters)
and full response of every model call, and the input and output of every
tool call. Transport settings (`timeout`, `extra_headers`, `extra_query`)
are not recorded, so API keys and auth headers never reach the journal.

## Build from source

```sh
pip install maturin
cd crates/pragmatic-python
maturin develop --release
pip install pytest anthropic openai && pytest tests
```

The journal files are the same format the Rust runtime and the `pragmatic`
CLI read.
