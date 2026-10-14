# Pragmatic for Python

This guide covers the Python SDK (`pip install pragmatic-runtime`): how to
journal an agent's model calls and tool calls, what ends up in the journal,
how streams, errors and retries are recorded, how crashed runs resume, and
how to use it with agent frameworks. The design it implements is
`docs/design/system-of-record.md`, sections 2 and 6.

## Install

```sh
pip install "pragmatic-runtime[anthropic]"     # anthropic>=1.0
pip install "pragmatic-runtime[openai]"        # openai>=3.0
```

The journaled clients need `anthropic>=1.0` or `openai>=3.0`, the first
releases built on `httpx2`. Clients from older releases raise
`pragmatic.Unsupported` naming the upgrade to make. The runtime itself
supports Python 3.9 and later.

## A first run

```python
import anthropic
import pragmatic

rt = pragmatic.Runtime("./journals")

def research(ctx):
    client = ctx.wrap(anthropic.Anthropic())
    msg = client.messages.create(
        model="claude-sonnet-5-5", max_tokens=1024,
        messages=[{"role": "user", "content": "Summarize durable execution."}],
    )
    return msg.content[0].text

report = rt.run("research-42", research)     # record
rt.resume("research-42", research)           # after a crash: nothing is repeated
rt.replay("research-42", research)           # audit: nothing is called at all
assert rt.verify("research-42")              # the hash chain and every commitment
```

`rt.run`, `rt.resume` and `rt.replay` each make one *attempt* of the run.
`run` starts or continues it, `resume` continues a run that crashed,
deciding what the crash left unfinished, and `replay` reads the whole run
back without writing anything and without calling anything, raising
`JournalDesync` at the first step where the program and the journal
disagree.

The store is a directory (`DirStore`), memory (`MemoryStore`), a Pragmatic
Server (`pragmatic.Runtime("https://...", token=...)`, or
`PRAGMATIC_URL` and `PRAGMATIC_TOKEN`), or a store of your own implementing
`pragmatic.Store`.

On a server, `run` and `resume` work with the agent token that records the
run. `replay` and `verify` read the run's journal without holding its
lease, which needs an admin token or an auditor token with `view_raw`: an
agent token reads a journal only while it holds the lease, so `replay` with
one raises `ServerError` saying so. `verify` with such a token returns the
server's own report instead (its verdict kept), and an auditor without
`view_raw` reads the run redacted through `rt.entries`.

## Journaled model clients

### `ctx.wrap` and `pragmatic.wrap`

`ctx.wrap(client)` and `pragmatic.wrap(client)` return a journaled copy of
an Anthropic or OpenAI client, sync or async (`Anthropic`, `AsyncAnthropic`,
`AnthropicBedrock`, `OpenAI`, `AsyncOpenAI`, `AzureOpenAI` and the rest).
The copy is a genuine client of the same class: `isinstance` checks hold,
and `with_options()` and `copy()` give journaled clients too. Journaling
happens in its HTTP client, which every request goes through, so every
method is covered:

- `create`, `stream=True`, and the `.stream()` helpers with `text_stream`,
  `get_final_message`, `get_final_completion` and `get_final_response`;
- `.parse()` (structured output);
- `with_raw_response` and `with_streaming_response`;
- `count_tokens` and `responses.input_tokens.count`;
- the Anthropic tool runner (`beta.messages.tool_runner`);
- the SDK's own retries.

The difference between the two:

- `ctx.wrap(client)` binds the client to the current attempt. Use it inside
  the agent.
- `pragmatic.wrap(client)` records into whichever run calls it. Build it
  once, at module level or in a framework's configuration, and use it from
  any number of runs.

### What a model call records

Each HTTP exchange is a *draw*: a `DrawIntent` holding the request,
persisted before the request is sent, and a `DrawResult` holding the
response, persisted before the response reaches the agent.

- **The request** is recorded as parts. The first part holds the method,
  path, query, the headers that select API behavior (`anthropic-version`,
  `anthropic-beta`, `openai-beta`) and the body without its messages. Each
  message (`messages`, or the Responses API's `input` items) is a part of
  its own: a conversation resends its earlier messages with every call, and
  as parts of their own they are stored once and can be erased once. A
  journal record holds at most 255 parts, so a longer conversation is
  stored in chunks of messages (two, four or more to a part, the fewest
  that fit); the chunks of earlier messages stay the same from call to
  call and are still stored once.
- **Transport headers are never recorded**: API keys, authorization,
  retry counts, idempotency keys, user agents. Nor are query parameters
  named like credentials (`api_key`, `token`, `sig` and the like).
- **Credentials in the body are never recorded either.** In each tool and
  MCP server definition (`tools[*]`, `mcp_servers[*]`), members named
  `authorization`, `api_key`, `password`, `secret` or `token`, or ending in
  `_token`, `_secret`, `_key` or `_password`, and every value of a
  `headers` object, are recorded as `<credential>`. That covers Anthropic's
  `mcp_servers[*].authorization_token` and the OpenAI Responses API's
  `tools[*].authorization` and `tools[*].headers`. The same replacement
  applies when a replay matches the request, so a rotated MCP token does
  not stop a run from replaying. A tool's input schema is left alone.
- **Uploads** (`files.create`, `beta.files.upload`,
  `audio.transcriptions.create`, `images.edit`) are recorded as sent,
  except that the multipart boundary, which the HTTP client draws at
  random for every request, is replaced by a fixed one, so the same upload
  matches on replay and resume.
- **The response** is recorded as its status, the headers the SDK reads
  (`content-type`, the request id, the Anthropic workspace id, the retry
  hints), and the body bytes. Rate-limit headers are dropped. The agent
  receives exactly those headers on record too; replay adds a retry hint
  only to an error response the SDK may retry (see below).
- **The meta** of each result holds the outcome, status, provider, model,
  stop reason, token usage and latency. It holds no content, so it
  survives erasure; `attempt.end` sums the usage of the attempt's fresh
  calls in `usage_fresh`.

On resume and replay the response is rebuilt from the journal, byte for
byte, and the SDK parses it into its own types as it did the first time.

### Streams

A streamed body is recorded as the agent reads it, chunk by chunk, and its
result is written when the body ends: the agent sees the end of the stream
only once it is durable.

When the agent stops early, the result holds the bytes it read so far, with
outcome `partial`, and replay serves exactly those bytes and then ends the
stream. A stream's result is written at the first of:

- the end of the body;
- `close()` (leaving a `with` block, `stream.close()`);
- the response being garbage-collected unread or half-read;
- the next journaled step on the same branch by the thread or task that
  opened the stream, for a stream it has not started reading (a call from
  another thread or task, such as a parallel LangGraph node, never cuts
  it);
- the end of a `ctx.gather` child, for a stream on that child's branch;
- the end of the attempt.

From then on the stream reads no further, so a stream the agent left alone
yields nothing more on record, as on replay. A stream that is being read
may stay open while the agent does other things: tools can run in the
middle of a stream, as the Anthropic tool runner's `run_tools_eagerly`
does.

### Errors, retries and transport failures

Every exchange is a draw, failures included, so the SDK's retry loop
replays exactly:

- A response with a status of 400 or more is recorded with outcome `error`
  and its status, and replays as the same SDK exception (`BadRequestError`,
  `RateLimitError`, with the same request id).
- A `429` followed by a successful retry is two draws. Replay serves the
  `429` with `retry-after-ms: 1`, so the SDK retries at once instead of
  waiting, whatever the recorded hint asked for. The exception is a hint
  the OpenAI SDK refused to wait for (over two minutes, so it gave up
  instead of retrying): replay serves that hint again, so the SDK gives
  up again, at no wait. A hint given as an HTTP date is recorded as the
  delay it meant when the response arrived, since the date would mean
  something else on a later replay. An error the SDK does not retry (a
  `400`, say) replays with exactly the recorded headers.
- A transport failure (a refused connection, a timeout) is recorded with
  its class and message, and replays as the same httpx2 exception, which
  the SDK turns into the same `APIConnectionError` or `APITimeoutError`.
  The journaled message leaves out credentials: quoted header values (h11
  quotes the value it refuses, such as an API key read from a file with
  its trailing newline) and the values of credential headers are cut out.
  A transport failure has no response to carry a retry hint, so its
  replay waits the SDK's own backoff before the recorded retry.
- A call cancelled while it runs (an `asyncio.timeout` or
  `asyncio.wait_for` around it, a task group cancelling it, the Agents SDK
  cancelling the model call when an input guardrail trips) is a result
  too, with the bytes received so far, once the agent catches the
  cancellation and carries on. Replay waits at that call until the task is
  cancelled again, so the agent's timeout fires and takes the same path.
- A body that breaks while it is read keeps the bytes read and the
  failure; replay serves the bytes, then raises the same failure.

Each of these counts against the run's `budget` like any model call.

### Faults inside the SDK

When the journal itself refuses a call (a replay whose request differs
from the recorded one, a run over budget, a store that cannot persist),
the SDK must not treat that as a network problem. The Anthropic SDK retries
any foreign exception from its HTTP client as a connection error, and
frameworks catch `Exception` around model calls. So the fault travels
inside `pragmatic.JournalFault`, which derives from `BaseException` only,
and `rt.run` (and the other entry points) raise the fault itself:

```python
try:
    rt.replay("research-42", changed_research)
except pragmatic.JournalDesync as e:
    print(e.diff)      # the first differing JSON paths of the two requests
```

Outside a run nothing unwraps the carrier: catch `pragmatic.JournalFault`
and read its `error`.

### Calls outside a run

A journaled client called outside every run (or from a thread that does not
carry the run's context) raises `NotInRun`. With
`pragmatic.wrap(client, outside="passthrough")` such calls are sent
unrecorded instead, for code that uses one client both inside and outside
durable runs. With `ctx.wrap(client, outside="passthrough")`, calls made
outside the attempt while it runs are sent unrecorded and counted in its
`attempt.end` note (`passthrough_calls`), so the record says that they
happened. A client bound to one run is always refused inside another.

### Not journaled

- Websocket and realtime connections (`responses.connect()`,
  `realtime.connect()`, the Agents SDK's websocket transport) raise
  `Unsupported`: their traffic never passes through the HTTP client.
- A journaled client sends only to its API host; `client.post` to another
  host raises `Unsupported`. Make such requests with a client of their own,
  journaled with `ctx.tool`.
- MCP tool calls use the `mcp` package's own client: journal them with
  `ctx.tool`.
- LiteLLM's own Anthropic handler and SDKs on legacy `httpx`.
- OpenAI clients with X.509 workload identity: they send every request
  through a transport of their own, never through the HTTP client, so
  wrapping one raises `Unsupported`. Use an API key or a token-based
  workload identity for durable runs.
- Any other model client: journal its calls with `ctx.draw(prompt,
  sample)` or `await ctx.adraw(...)`, where `prompt` identifies the request
  completely.

## Tools and effects

```python
results = ctx.run_tools(msg, {"search": search, "fetch": fetch})
messages += results                       # tool results, in the provider's format

page = ctx.tool("fetch", fetch_url, url)  # any function, journaled
sent = ctx.effect("email", body, send)    # str in, str out
```

A tool call is an *effect*: its intent is durable before the function
runs, and its result is recorded after. Resume and replay return the
recorded result without running the function. A function that takes an
`idempotency_key` argument receives `"<run_id>/<branch>/<intent cursor>"`,
the same on every retry of that effect, so the service it calls can
deduplicate. A tool that raises is recorded too, and replay raises
`EffectFailed`, which is also an instance of the original exception type.

Tools a framework runs for you are journaled by calling `ctx.tool` inside
them, as long as the framework runs them on the agent's own thread or task
(the Anthropic tool runner does):

```python
@anthropic.beta_tool
def get_weather(city: str) -> str:
    """The weather in a city."""
    return ctx.tool("get_weather", weather_api, city)
```

## Frameworks

Frameworks that take an SDK client take a journaled one. The model calls
they make, from their own tasks and worker threads too, are recorded in the
run whose context they inherited.

**OpenAI Agents SDK**

```python
import agents, openai, pragmatic

agents.set_default_openai_client(pragmatic.wrap(openai.AsyncOpenAI()), use_for_tracing=False)

async def run(ctx):
    result = await agents.Runner.run(agent, "Weather in Paris?")
    streamed = agents.Runner.run_streamed(agent, "And in Rome?")
    async for event in streamed.stream_events():
        ...
    return streamed.final_output
```

The Agents SDK sends a new `prompt_cache_key` (`agents-sdk:run:<uuid>`)
with every run. A built-in normalization rule lets replay ignore it (see
Normalization).

**Pydantic AI**

```python
from pydantic_ai import Agent
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.providers.anthropic import AnthropicProvider

client = pragmatic.wrap(anthropic.AsyncAnthropic())
agent = Agent(AnthropicModel("claude-sonnet-5-5", provider=AnthropicProvider(anthropic_client=client)))
```

`OpenAIProvider(openai_client=pragmatic.wrap(openai.AsyncOpenAI()))` works
the same way for `OpenAIChatModel` and `OpenAIResponsesModel`.

**LangChain and LangGraph**

```python
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent
from pragmatic.integrations.langchain import journal

llm = journal(ChatAnthropic(model="claude-sonnet-5-5"))
graph = create_react_agent(llm, tools=[get_weather])

def run(ctx):
    return graph.invoke({"messages": [("user", "Weather in Paris?")]})["messages"][-1].text
```

`journal(llm)` returns a journaled copy of a `ChatAnthropic` or
`ChatOpenAI` (including `use_responses_api=True` and `AzureChatOpenAI`):
`invoke`, `stream`, their async forms, tool calling and structured output
are all recorded, in whichever run calls it.

## Normalization

Replay matches each model call by its request. A field that changes on
every run without changing what the model is asked would make a recorded
run impossible to replay, so such fields can be named:

```python
rt = pragmatic.Runtime("./journals", volatile=["$.metadata.session_id", "$.messages[*].id"])
```

Each rule is a JSON path into the request body (`$`, then `.name`,
`['name']`, `[n]`, `[*]` or `.*`). Before two requests are compared, every
value a rule matches is replaced with a fixed token in both. The journal
keeps the request as it was sent; only matching is loosened. One rule is
built in: `agents-sdk:prompt_cache_key`, which ignores the Agents SDK's
per-run prompt cache keys (keys it derives from a conversation or group id
are still compared).

Every rule loosens what a replay proves, so each attempt names the rules
in force in its `attempt.start` note (`normalization`), for an auditor to
see.

## Parallel branches

```python
async def research(ctx):
    papers, code = await ctx.gather(
        lambda c: survey(c, "papers"),
        lambda c: survey(c, "code"),
    )
```

Each child of `ctx.gather` records on a branch of its own, so the run
replays exactly however the children interleave. A failing child never
cancels its siblings, and the region raises the failure of the
lowest-index failed child. Model calls through a journaled client go to the
calling child's branch.

A region can be timed out like any awaited step: when the task running
`ctx.gather` is cancelled, the children are cancelled too, and once they
have finished the region is closed, so an agent that catches the timeout
carries on stepping on its own branch. A child that ends cancelled
although the region was not (it cancelled itself, or a library did) is a
failed child: the region raises a `PragmaticError` for it, whose
`__cause__` is the `CancelledError`, never the cancellation itself.

Two concurrent calls on *one* branch (a framework issuing calls from tasks
of its own) are matched on replay in the order they were sent. When two
in-flight calls on one branch carry identical requests, the SDK logs a
warning on the `pragmatic` logger: send them in a deterministic order, or
from `ctx.gather` children.

## Async, threads and ownership

Async agents run with `await rt.arun(...)` (and `aresume`, `areplay`) in
your event loop, or with `rt.run(...)` from synchronous code. Storage work
runs on a dedicated thread per attempt, so the loop never waits on it.

An attempt belongs to the thread that runs it (sync) or to its root task
and the `ctx.gather` children (async); threads started with
`asyncio.to_thread` are accepted too. Steps from other tasks or threads
raise `NotInRun`, because the order they would land in the journal could
not be reproduced, and a refused step changes nothing. An async agent
whose arguments are bound with a lambda (`rt.run(run_id, lambda c:
agent(c, x))`) is owned exactly as with `arun`. Model calls through a
journaled client are the exception: any task or thread that inherited the
run's context may make them, because frameworks make them from tasks and
worker threads of their own.

### Timeouts

Time a step out with `asyncio.timeout` (Python 3.11 and later):

```python
async def research(ctx):
    try:
        async with asyncio.timeout(30):
            notes = await ctx.atool("search", search, "durable agents")
    except TimeoutError:
        notes = await ctx.atool("cached_search", cached_search, "durable agents")
```

The step that was cancelled is recorded as a failure, so the run ends
normally, and replay waits at that step until the timeout fires again.
`asyncio.wait_for` does the same from Python 3.12. Before 3.12 it runs the
step in a task of its own, which the attempt does not own, so a tool or
`ctx.adraw` under it raises `NotInRun` (calls through a journaled client
are accepted); `asyncio.shield` does so on every version. On Python 3.9
and 3.10, use a timeout that runs in the caller's task, such as the
`async-timeout` package.

Cancelling the run itself (the task that awaits `rt.arun`) is a crash:
nothing more is recorded, and `rt.resume` continues the run later.

## Crashes, resume and recovery

After a crash, `rt.resume(run_id, agent)` reads the journaled prefix back
(no model calls, no repeated tools) and continues recording at its end:

- A model call that was in flight when the process died has an intent and
  no result. It is made again when the resumed agent reaches it, under the
  same intent.
- A stream the process died in the middle of is the same: the call is made
  again, and the agent reads the new stream.
- A tool call that was in flight is decided by the recovery policy:

```python
def recover(name, arg):
    if already_sent(arg):
        return pragmatic.Recover.commit(receipt_for(arg))   # it happened
    return None                                            # perform it again

rt.resume("research-42", research, recover=recover)
```

Without a policy, local runs perform such tools again; runs on a server
raise `DanglingEffect` until a policy decides. For a tool call made through
`ctx.run_tools`, the policy's `name` is `tool:<tool name>`, its `arg` is the
JSON `{"id", "input"}` of the call, and the result it commits is what the
model receives as the tool's result.

On a server, a write whose answer was lost is resent until the server
answers (a repeat is recognized as a duplicate), and the store looks at
the run once more before it gives up. When it does give up, a message
received in that write goes back to its channel, unless the next attempt
finds the receive in the journal after all: a message is never received
twice.

## Changing code under recorded runs

```python
@pragmatic.durable                        # the agent's source hash is journaled
def research(ctx): ...

@pragmatic.durable(version="2")           # or an explicit version

if ctx.patched("validate-input"):         # new runs take the new path,
    validate(query)                       # recorded runs keep the old one
```

Replay refuses a changed program unless called with
`on_code_change="continue"`.

## Other journaled inputs

```python
ctx.now(), ctx.datetime()                 # the clock
ctx.uuid4(), ctx.random(), ctx.randint(1, 6), ctx.randbytes(16)
ctx.recv("approval")                      # a value sent with rt.send(run_id, "approval", ...)
```

## Inspecting runs

```python
rt.verify("research-42")       # VerifyReport, truthy when intact
rt.runs()                      # RunSummary for each run
rt.entries("research-42")      # every entry, in the Entry JSON shape
```

A report is never truthy for a journal the server says is missing or
damaged (`report.missing`, `report.damaged`), whether the journal was
checked here or the server's own report was returned.

`python -m pragmatic push DIR RUN` uploads a local run to a server. It
refuses, before anything is created on the server, a journal the server
would refuse from a client: format 1, keyed, and one erased locally with
`pragmatic erase` (the server records erasures only through its own erase
endpoint, which says who erased what). Push runs before erasing them.

With `PRAGMATIC_OTEL=1` and `opentelemetry-api` installed, each attempt is a
span and each model call a child span in the GenAI conventions, with token
usage (zero for replayed calls) and never any content.

## Exceptions

- `PragmaticError`: every runtime fault, including `JournalDesync` (with
  `diff` for a model call), `ReplayExhausted`, `NotInRun`, `Unsupported`,
  `Locked`, `LeaseLost`, `Conflict`, `Deleted`, `Erased`, `TooLarge`,
  `Unavailable`, `DanglingIntent`, `DanglingEffect`, `EffectUnrecorded`,
  `ServerError`, and the replayed failures `EffectFailed` and `DrawFailed`.
- `JournalFault`: the carrier a fault travels in through a model SDK; the
  runtime's entry points raise the fault inside it.
