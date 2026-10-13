"""End-to-end tests for journaling real SDK clients.

The Anthropic and OpenAI SDKs run unmodified against an in-process mock
HTTP transport. Each test records a tool-using agent, crashes it partway,
resumes it, and replays it, and checks that resume and replay make zero
network calls and zero repeated tool calls.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import pragmatic

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")

httpx = pytest.importorskip("httpx2")


class Crash(Exception):
    """Simulated process death at a chosen point in the agent."""


class MockAPI:
    """Serves scripted responses in order and counts every request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        return httpx.Response(200, json=self.responses[len(self.requests) - 1])

    def sync_client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def async_client(self):
        async def handler(request):
            return self(request)

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def anthropic_message(i, content, stop_reason):
    return {
        "id": f"msg_{i}",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


ANTHROPIC_SCRIPT = [
    anthropic_message(
        1,
        [
            {"type": "text", "text": "Searching."},
            {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {"q": "durable"}},
        ],
        "tool_use",
    ),
    anthropic_message(
        2,
        [{"type": "tool_use", "id": "toolu_2", "name": "fetch", "input": {"url": "a://1"}}],
        "tool_use",
    ),
    anthropic_message(3, [{"type": "text", "text": "Two papers found."}], "end_turn"),
]

TOOLS_SPEC = [
    {"name": "search", "description": "search", "input_schema": {"type": "object"}},
    {"name": "fetch", "description": "fetch", "input_schema": {"type": "object"}},
]


class Tools:
    def __init__(self):
        self.calls = []

    def registry(self):
        def search(q):
            self.calls.append(("search", q))
            return {"hits": ["a://1", "a://2"]}

        def fetch(url):
            self.calls.append(("fetch", url))
            return f"contents of {url}"

        return {"search": search, "fetch": fetch}


def anthropic_agent(api, tools, crash_after=None):
    def agent(ctx):
        client = ctx.wrap(anthropic.Anthropic(api_key="test", http_client=api.sync_client()))
        messages = [{"role": "user", "content": "find papers"}]
        turns = 0
        while True:
            msg = client.messages.create(
                model="claude-sonnet-5-5", max_tokens=256, tools=TOOLS_SPEC, messages=messages
            )
            messages.append({"role": "assistant", "content": msg.content})
            if msg.stop_reason != "tool_use":
                return msg.content[0].text
            messages += ctx.run_tools(msg, tools.registry())
            turns += 1
            if crash_after is not None and turns == crash_after:
                raise Crash()

    return agent


def test_anthropic_record_crash_resume_replay(tmp_path):
    api, tools = MockAPI(ANTHROPIC_SCRIPT), Tools()
    rt = pragmatic.Runtime(tmp_path)

    with pytest.raises(Crash):
        rt.run("r1", anthropic_agent(api, tools, crash_after=1))
    assert len(api.requests) == 1
    assert tools.calls == [("search", "durable")]

    report = rt.resume("r1", anthropic_agent(api, tools))
    assert report.output == "Two papers found."
    # The first model call and the search were read back, not repeated.
    assert len(api.requests) == 3
    assert tools.calls == [("search", "durable"), ("fetch", "a://1")]
    assert report.replayed_steps > 0

    # The tool result reached the model in the provider's format.
    second = api.requests[1]["messages"]
    assert second[-1]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": '{"hits":["a://1","a://2"]}',
    }

    audit = rt.replay("r1", anthropic_agent(api, tools))
    assert audit.output == report.output
    assert audit.fresh_steps == 0
    assert len(api.requests) == 3 and len(tools.calls) == 2
    assert rt.verify("r1")


def test_replay_detects_changed_request(tmp_path):
    api, tools = MockAPI(ANTHROPIC_SCRIPT), Tools()
    rt = pragmatic.Runtime(tmp_path)
    rt.run("r1", anthropic_agent(api, tools))

    def changed(ctx):
        client = ctx.wrap(anthropic.Anthropic(api_key="test", http_client=api.sync_client()))
        client.messages.create(
            model="claude-sonnet-5-5",
            max_tokens=999,  # differs from the recording
            tools=TOOLS_SPEC,
            messages=[{"role": "user", "content": "find papers"}],
        )
        return "unreachable"

    with pytest.raises(pragmatic.JournalDesync):
        rt.replay("r1", changed)


def test_tool_errors_are_reported_to_the_model(tmp_path):
    api = MockAPI(ANTHROPIC_SCRIPT)
    rt = pragmatic.Runtime(tmp_path)

    def agent(ctx):
        client = ctx.wrap(anthropic.Anthropic(api_key="test", http_client=api.sync_client()))
        msg = client.messages.create(
            model="claude-sonnet-5-5",
            max_tokens=256,
            messages=[{"role": "user", "content": "go"}],
        )

        def search(q):
            raise ValueError("index offline")

        out = ctx.run_tools(msg, {"search": search})
        return json.dumps(out)

    report = rt.run("r1", agent)
    [message] = json.loads(report.output)
    [block] = message["content"]
    assert block["is_error"] is True
    assert "index offline" in block["content"]


def test_async_anthropic_client(tmp_path):
    api, tools = MockAPI(ANTHROPIC_SCRIPT), Tools()
    rt = pragmatic.Runtime(tmp_path)

    async def agent(ctx):
        client = ctx.wrap(
            anthropic.AsyncAnthropic(api_key="test", http_client=api.async_client())
        )
        messages = [{"role": "user", "content": "find papers"}]
        while True:
            msg = await client.messages.create(
                model="claude-sonnet-5-5", max_tokens=256, tools=TOOLS_SPEC, messages=messages
            )
            messages.append({"role": "assistant", "content": msg.content})
            if msg.stop_reason != "tool_use":
                return msg.content[0].text
            messages += await ctx.arun_tools(msg, tools.registry())

    report = rt.run("r1", agent)
    assert report.output == "Two papers found."
    assert len(api.requests) == 3
    audit = rt.replay("r1", agent)
    assert audit.output == report.output
    assert len(api.requests) == 3 and len(tools.calls) == 2


def chat_completion(i, message, finish_reason):
    return {
        "id": f"chatcmpl-{i}",
        "object": "chat.completion",
        "created": 1_700_000_000 + i,
        "model": "gpt-5",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


OPENAI_CHAT_SCRIPT = [
    chat_completion(
        1,
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "search", "arguments": '{"q":"durable"}'},
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {"name": "fetch", "arguments": '{"url":"a://1"}'},
                },
            ],
        },
        "tool_calls",
    ),
    chat_completion(2, {"role": "assistant", "content": "Two papers found."}, "stop"),
]


def openai_chat_agent(api, tools, crash=False):
    def agent(ctx):
        client = ctx.wrap(openai.OpenAI(api_key="test", http_client=api.sync_client()))
        messages = [{"role": "user", "content": "find papers"}]
        while True:
            completion = client.chat.completions.create(model="gpt-5", messages=messages)
            message = completion.choices[0].message
            messages.append(message)
            if not message.tool_calls:
                return message.content
            messages += ctx.run_tools(completion, tools.registry())
            if crash:
                raise Crash()

    return agent


def test_openai_chat_record_crash_resume_replay(tmp_path):
    api, tools = MockAPI(OPENAI_CHAT_SCRIPT), Tools()
    rt = pragmatic.Runtime(tmp_path)

    with pytest.raises(Crash):
        rt.run("r1", openai_chat_agent(api, tools, crash=True))
    report = rt.resume("r1", openai_chat_agent(api, tools))
    assert report.output == "Two papers found."
    assert len(api.requests) == 2
    assert tools.calls == [("search", "durable"), ("fetch", "a://1")]
    tool_msgs = [m for m in api.requests[1]["messages"] if m.get("role") == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["call_1", "call_2"]

    audit = rt.replay("r1", openai_chat_agent(api, tools))
    assert audit.output == report.output
    assert len(api.requests) == 2 and len(tools.calls) == 2


OPENAI_RESPONSES_SCRIPT = [
    {
        "id": "resp_1",
        "object": "response",
        "created_at": 1_700_000_000,
        "model": "gpt-5",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_1",
                "name": "search",
                "arguments": '{"q":"durable"}',
                "status": "completed",
            }
        ],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    },
    {
        "id": "resp_2",
        "object": "response",
        "created_at": 1_700_000_001,
        "model": "gpt-5",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "Done.", "annotations": []}],
            }
        ],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    },
]


def test_openai_responses(tmp_path):
    api, tools = MockAPI(OPENAI_RESPONSES_SCRIPT), Tools()
    rt = pragmatic.Runtime(tmp_path)

    def agent(ctx):
        client = ctx.wrap(openai.OpenAI(api_key="test", http_client=api.sync_client()))
        items = [{"role": "user", "content": "find papers"}]
        while True:
            response = client.responses.create(model="gpt-5", input=items)
            items += response.output
            outputs = ctx.run_tools(response, tools.registry())
            if not outputs:
                return response.output_text
            items += outputs

    report = rt.run("r1", agent)
    assert report.output == "Done."
    assert api.requests[1]["input"][-1] == {
        "type": "function_call_output",
        "call_id": "call_1",
        "output": '{"hits":["a://1","a://2"]}',
    }
    audit = rt.replay("r1", agent)
    assert audit.output == "Done." and len(api.requests) == 2


def test_durable_marker_rejects_changed_program(tmp_path):
    rt = pragmatic.Runtime(tmp_path)

    @pragmatic.durable
    def v1(ctx):
        return ctx.tool("add", lambda a, b: a + b, 1, 2)

    assert rt.run("r1", v1).output == "3"

    @pragmatic.durable
    def v1(ctx):  # noqa: F811 - same name, different source
        return ctx.tool("add", lambda a, b: a + b, 1, 3)

    with pytest.raises(pragmatic.JournalDesync):
        rt.replay("r1", v1)


def test_budget_and_caps(tmp_path):
    api = MockAPI(ANTHROPIC_SCRIPT)
    rt = pragmatic.Runtime(tmp_path)
    with pytest.raises(pragmatic.PragmaticError, match="budget"):
        rt.run("r1", anthropic_agent(api, Tools()), budget=1)
    with pytest.raises(pragmatic.PragmaticError, match="capability denied"):
        rt.run("r2", anthropic_agent(MockAPI(ANTHROPIC_SCRIPT), Tools()), caps=["tool:fetch"])


def test_steps_from_tasks_the_attempt_does_not_own_are_refused(tmp_path):
    # asyncio.gather wraps each coroutine in a task of its own. Those tasks
    # do not own the attempt (spec 6.2): concurrent work goes through
    # ctx.gather, which gives each child a branch of its own.
    rt = pragmatic.Runtime(tmp_path)

    async def agent(ctx):
        async def slow(i):
            await asyncio.sleep(0)
            return str(i)

        await asyncio.gather(
            ctx.adraw("a", lambda: slow(1)),
            ctx.adraw("b", lambda: slow(2)),
        )

    with pytest.raises(pragmatic.NotInRun, match="ctx.gather"):
        rt.run("r1", agent)


def test_signed_journal_via_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAGMATIC_JOURNAL_KEY", "secret")
    rt = pragmatic.Runtime(tmp_path)
    rt.run("r1", lambda ctx: ctx.tool("t", lambda: "ok"))
    assert rt.verify("r1")
    monkeypatch.setenv("PRAGMATIC_JOURNAL_KEY", "wrong")
    with pytest.raises(pragmatic.PragmaticError):
        pragmatic.Runtime(tmp_path).replay("r1", lambda ctx: ctx.tool("t", lambda: "ok"))
