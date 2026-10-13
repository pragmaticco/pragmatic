"""Journaled Anthropic and OpenAI clients at the HTTP layer (spec 6.5, 6.6).

The SDKs run unmodified against ``model_api.ModelAPI`` on
``httpx2.MockTransport``. Each scenario runs for both SDKs, sync and async:
it records a run, replays it, and checks that the replay made no network
call at all and that the agent saw exactly what it saw when recording.
"""

from __future__ import annotations

import asyncio
import gc
import json
import logging
import threading
import time
from typing import Any, Callable

import pytest

import pragmatic

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
httpx2 = pytest.importorskip("httpx2")
pydantic = pytest.importorskip("pydantic")

from model_api import ANTHROPIC_MODEL, OPENAI_MODEL, STRUCTURED, TEXT, ModelAPI  # noqa: E402

PROVIDERS = ["anthropic", "openai"]
MSGS = [{"role": "user", "content": "hi"}]


class Weather(pydantic.BaseModel):
    city: str
    temp_c: int


class Crash(BaseException):
    """Simulated process death: not an Exception, so the attempt is a crash."""


def dump(obj: Any) -> Any:
    return obj.model_dump(mode="json")


@pytest.fixture
def api() -> ModelAPI:
    return ModelAPI()


def record_then_replay(rt: pragmatic.Runtime, api: ModelAPI, run_id: str, agent: Callable) -> Any:
    """Record ``agent``, replay it, and check the replay made no network
    call and returned the same output. Returns the recording's report."""
    rec = rt.run(run_id, agent)
    calls = len(api.calls)
    rep = rt.replay(run_id, agent)
    assert len(api.calls) == calls, "replay touched the network"
    assert rep.output == rec.output
    assert rep.fresh_steps == 0
    assert rt.verify(run_id)
    return rec


def draws(rt: pragmatic.Runtime, run_id: str) -> list:
    """The DrawResult metas of a run, in order."""
    return [e["fields"]["meta"] for e in rt.entries(run_id) if e["kind"] == "DrawResult"]


def notes(rt: pragmatic.Runtime, run_id: str, kind: str) -> list:
    return [
        e["fields"]["data"]
        for e in rt.entries(run_id)
        if e["kind"] == "Note" and e["fields"]["kind"] == kind
    ]


# ---------------------------------------------------------------------------
# Provider calls, sync and async
# ---------------------------------------------------------------------------


def create(c: Any, provider: str, **kw: Any) -> Any:
    if provider == "anthropic":
        return c.messages.create(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS, **kw)
    return c.chat.completions.create(model=OPENAI_MODEL, messages=MSGS, **kw)


def text_of(resp: Any, provider: str) -> str:
    if provider == "anthropic":
        return resp.content[0].text
    return resp.choices[0].message.content


def event_names(stream: Any, provider: str) -> list:
    if provider == "anthropic":
        return [e.type for e in stream]
    return [ch.choices[0].delta.content if ch.choices else None for ch in stream]


async def aevent_names(stream: Any, provider: str) -> list:
    if provider == "anthropic":
        return [e.type async for e in stream]
    return [ch.choices[0].delta.content if ch.choices else None async for ch in stream]


# ---------------------------------------------------------------------------
# create, stream=True, helpers, parse, raw and streaming responses, tokens
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS)
def test_create_records_and_replays_the_same_sdk_objects(tmp_path, api, provider):
    base = api.client(provider, False)
    sdk_cls = type(base)

    def agent(ctx):
        c = ctx.wrap(base)
        assert isinstance(c, sdk_cls) and type(c).__name__ == sdk_cls.__name__
        r = create(c, provider)
        return json.dumps({"r": dump(r), "id": r._request_id, "cls": type(r).__name__})

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    out = json.loads(rec.output)
    assert out["id"] in ("req_ant_1", "req_oai_chat_1")
    assert text_of(_rebuild(out, provider), provider) == TEXT
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "ok" and meta["status"] == 200 and meta["provider"] == provider
    assert meta["model"] in (ANTHROPIC_MODEL, OPENAI_MODEL)
    assert meta["stop_reason"] in ("end_turn", "stop")
    assert meta["usage"]["input_tokens"] > 0 and meta["usage"]["output_tokens"] > 0
    # Rate-limit headers never reach the journal; the request id does.
    result = [e for e in rt.entries("r") if e["kind"] == "DrawResult"][0]
    head = json.loads(result["slots"][0]["text"])
    names = {k for k, _ in head["headers"]}
    assert "content-type" in names and not any("ratelimit" in n for n in names)
    end = notes(rt, "r", "attempt.end")[0]
    assert end["usage_fresh"]["input_tokens"] == meta["usage"]["input_tokens"]


def _rebuild(out: dict, provider: str) -> Any:
    if provider == "anthropic":
        return anthropic.types.Message.model_validate(out["r"])
    return openai.types.chat.ChatCompletion.model_validate(out["r"])


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_create(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        r = await create(c, provider)
        return json.dumps({"r": dump(r), "id": r._request_id})

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert [m["outcome"] for m in draws(rt, "r")] == ["ok"]


def test_requests_are_split_into_parts_without_transport_headers(tmp_path, api):
    base = api.client(
        "anthropic", False, default_headers={"X-Secret": "s3cr3t"},
        default_query={"api_key": "q-s3cr3t", "region": "eu"},
    )
    conversation = [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "second"},
        {"role": "user", "content": "third"},
    ]

    def agent(ctx):
        c = ctx.wrap(base)
        c.messages.create(model=ANTHROPIC_MODEL, max_tokens=8, messages=conversation)
        return "ok"

    rt = pragmatic.Runtime(tmp_path)
    rt.run("r", agent)
    [intent] = [e for e in rt.entries("r") if e["kind"] == "DrawIntent"]
    parts = [s["text"] for s in intent["slots"]]
    head = json.loads(parts[0])
    assert head["method"] == "POST" and head["path"] == "/v1/messages"
    assert head["body"]["messages"] == {"$parts": 3}
    assert head["headers"] == {"anthropic-version": "2023-06-01"}
    assert head["query"] == [["region", "eu"]]
    assert [json.loads(p)["content"] for p in parts[1:]] == ["first", "second", "third"]
    raw = json.dumps(rt.entries("r"))
    assert "s3cr3t" not in raw and "sk-test" not in raw and "x-stainless" not in raw.lower()
    assert len(api.calls) == 1 and api.calls[0][0] == "/v1/messages"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_stream_true(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        c = ctx.wrap(base)
        s = create(c, provider, stream=True)
        assert isinstance(s, (anthropic.Stream, openai.Stream))
        return json.dumps(event_names(s, provider))

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert len(json.loads(rec.output)) > 5
    assert all(u.closed for u in api.upstreams)
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "ok" and meta["stop_reason"] in ("end_turn", "stop")


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_stream_true(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        s = await create(c, provider, stream=True)
        assert isinstance(s, (anthropic.AsyncStream, openai.AsyncStream))
        return json.dumps(await aevent_names(s, provider))

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert all(u.closed for u in api.upstreams)


def test_anthropic_stream_helper(tmp_path, api):
    base = api.client("anthropic", False)

    def agent(ctx):
        c = ctx.wrap(base)
        with c.messages.stream(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS) as st:
            text = "".join(st.text_stream)
            final = dump(st.get_final_message())
            final_text = st.get_final_text()
            rid = st.request_id
        with c.beta.messages.stream(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS) as st:
            beta = dump(st.get_final_message())
        return json.dumps([text, final, final_text, rid, beta])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    text, final, final_text, rid, _ = json.loads(rec.output)
    assert text == TEXT == final_text and final["usage"]["output_tokens"] == 30 and rid == "req_ant_1"


def test_async_anthropic_stream_helper(tmp_path, api):
    base = api.client("anthropic", True)

    async def agent(ctx):
        c = ctx.wrap(base)
        async with c.messages.stream(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS) as st:
            text = "".join([t async for t in st.text_stream])
            final = dump(await st.get_final_message())
        return json.dumps([text, final])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output)[0] == TEXT


def test_openai_stream_helpers(tmp_path, api):
    base = api.client("openai", False)

    def agent(ctx):
        c = ctx.wrap(base)
        with c.chat.completions.stream(model=OPENAI_MODEL, messages=MSGS) as st:
            deltas = [e.delta for e in st if e.type == "content.delta"]
            final = dump(st.get_final_completion())
        with c.responses.stream(model=OPENAI_MODEL, input="hi") as st:
            text = "".join(e.delta for e in st if e.type == "response.output_text.delta")
            response = st.get_final_response()
        return json.dumps([deltas, final, text, response.output_text])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    deltas, _, text, final_text = json.loads(rec.output)
    assert "".join(deltas) == text == final_text == TEXT


def test_async_openai_stream_helpers(tmp_path, api):
    base = api.client("openai", True)

    async def agent(ctx):
        c = ctx.wrap(base)
        async with c.chat.completions.stream(model=OPENAI_MODEL, messages=MSGS) as st:
            deltas = [e.delta async for e in st if e.type == "content.delta"]
            final = dump(await st.get_final_completion())
        async with c.responses.stream(model=OPENAI_MODEL, input="hi") as st:
            text = "".join([e.delta async for e in st if e.type == "response.output_text.delta"])
            response = await st.get_final_response()
        return json.dumps([deltas, final, text, response.output_text])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output)[3] == TEXT


@pytest.mark.parametrize("is_async", [False, True])
def test_parse(tmp_path, api, is_async):
    ant, oai = api.client("anthropic", is_async), api.client("openai", is_async)

    def calls(ctx):
        a, o = ctx.wrap(ant), ctx.wrap(oai)
        return (
            a.messages.parse(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS, output_format=Weather),
            o.chat.completions.parse(model=OPENAI_MODEL, messages=MSGS, response_format=Weather),
            o.responses.parse(model=OPENAI_MODEL, input="hi", text_format=Weather),
        )

    def out(a: Any, c: Any, r: Any) -> str:
        return json.dumps([
            a.parsed_output.model_dump(),
            c.choices[0].message.parsed.model_dump(),
            r.output_parsed.model_dump(),
            c._request_id,
        ])

    if is_async:

        async def agent(ctx):
            a, c, r = calls(ctx)
            return out(await a, await c, await r)

    else:

        def agent(ctx):
            return out(*calls(ctx))

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    parsed = json.loads(rec.output)
    assert parsed[:3] == [json.loads(STRUCTURED)] * 3 and parsed[3] == "req_oai_chat_1"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_with_raw_response(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        c = ctx.wrap(base)
        if provider == "anthropic":
            raw = c.messages.with_raw_response.create(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS)
            rid = raw.headers.get("request-id")
        else:
            raw = c.chat.completions.with_raw_response.create(model=OPENAI_MODEL, messages=MSGS)
            rid = raw.headers.get("x-request-id")
        return json.dumps([rid, raw.status_code, text_of(raw.parse(), provider)])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output)[1:] == [200, TEXT]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_with_raw_response(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        if provider == "anthropic":
            raw = await c.messages.with_raw_response.create(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS)
        else:
            raw = await c.chat.completions.with_raw_response.create(model=OPENAI_MODEL, messages=MSGS)
        parsed = raw.parse()
        if asyncio.iscoroutine(parsed):  # the Anthropic SDK's async parse is awaited
            parsed = await parsed
        return json.dumps([raw.status_code, text_of(parsed, provider)])

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_with_streaming_response(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        c = ctx.wrap(base)
        resource = c.messages if provider == "anthropic" else c.chat.completions
        kw = {"max_tokens": 64} if provider == "anthropic" else {}
        model = ANTHROPIC_MODEL if provider == "anthropic" else OPENAI_MODEL
        with resource.with_streaming_response.create(model=model, messages=MSGS, **kw) as resp:
            body = b"".join(resp.iter_bytes()).decode()
        with resource.with_streaming_response.create(model=model, messages=MSGS, stream=True, **kw) as resp:
            lines = [line for line in resp.iter_lines() if line]
        return json.dumps([json.loads(body)["id"], len(lines)])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output)[1] > 5
    assert [m["outcome"] for m in draws(rt, "r")] == ["ok", "ok"]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_with_streaming_response(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        resource = c.messages if provider == "anthropic" else c.chat.completions
        kw = {"max_tokens": 64} if provider == "anthropic" else {}
        model = ANTHROPIC_MODEL if provider == "anthropic" else OPENAI_MODEL
        async with resource.with_streaming_response.create(model=model, messages=MSGS, stream=True, **kw) as resp:
            lines = [line async for line in resp.iter_lines() if line]
        return str(len(lines))

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)


@pytest.mark.parametrize("is_async", [False, True])
def test_count_tokens(tmp_path, api, is_async):
    ant, oai = api.client("anthropic", is_async), api.client("openai", is_async)

    def calls(ctx):
        return (
            ctx.wrap(ant).messages.count_tokens(model=ANTHROPIC_MODEL, messages=MSGS),
            ctx.wrap(oai).responses.input_tokens.count(model=OPENAI_MODEL, input="hi"),
        )

    if is_async:

        async def agent(ctx):
            a, o = calls(ctx)
            return json.dumps([(await a).input_tokens, (await o).input_tokens])

    else:

        def agent(ctx):
            a, o = calls(ctx)
            return json.dumps([a.input_tokens, o.input_tokens])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output) == [12, 12]
    # A token count is not a generation: it adds nothing to usage.
    assert all("usage" not in m for m in draws(rt, "r"))


# ---------------------------------------------------------------------------
# Streams closed early, abandoned, or left open
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS)
def test_early_close_records_a_partial_stream(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        c = ctx.wrap(base)
        s = create(c, provider, stream=True)
        seen = []
        for event in s:
            seen.append(repr(event)[:40])
            if len(seen) == 3:
                break
        s.close()
        return json.dumps(seen)

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert len(json.loads(rec.output)) == 3
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "partial"
    assert api.upstreams[0].closed


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_early_close(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        s = await create(c, provider, stream=True)
        seen = 0
        async for _ in s:
            seen += 1
            if seen == 2:
                break
        await s.close()
        return str(seen)

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert [m["outcome"] for m in draws(rt, "r")] == ["partial"]


def test_a_stream_helper_left_early_is_partial(tmp_path, api):
    base = api.client("anthropic", False)

    def agent(ctx):
        c = ctx.wrap(base)
        with c.messages.stream(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS) as st:
            first = next(iter(st.text_stream))
        return first

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert rec.output == "Hel"
    assert [m["outcome"] for m in draws(rt, "r")] == ["partial"]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_abandoned_streams_are_written_off(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        c = ctx.wrap(base)
        # Dropped without being read: collected, written off as partial.
        s = create(c, provider, stream=True)
        del s
        gc.collect()
        # Held but never read when the agent takes its next step on the
        # branch: written off by the next-step rule, and empty from then on.
        held = create(c, provider, stream=True)
        ctx.now()
        after_step = len(event_names(held, provider))
        # Started, then dropped mid-way.
        started = create(c, provider, stream=True)
        next(iter(started))
        del started
        gc.collect()
        # Left half-read when the agent returns: written at the attempt's end.
        open_at_end = create(c, provider, stream=True)
        it = iter(open_at_end)
        next(it)
        agent.keep = (open_at_end, it)
        return str(after_step)

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert rec.output == "0"
    assert [m["outcome"] for m in draws(rt, "r")] == ["partial"] * 4
    # The end of the attempt came after every draw's result.
    kinds = [e["kind"] for e in rt.entries("r")]
    assert kinds.index("DrawResult") < len(kinds) - 1


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_abandoned_streams_are_written_off(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        dropped = await create(c, provider, stream=True)
        del dropped
        gc.collect()
        held = await create(c, provider, stream=True)
        ctx.now()
        return str(len(await aevent_names(held, provider)))

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert rec.output == "0"
    assert [m["outcome"] for m in draws(rt, "r")] == ["partial", "partial"]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_async_stream_open_at_the_end_of_the_attempt(tmp_path, api, provider):
    base = api.client(provider, True)

    async def agent(ctx):
        c = ctx.wrap(base)
        s = await create(c, provider, stream=True)
        it = s.__aiter__()
        await it.__anext__()
        agent.keep = (s, it)
        return "left open"

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert [m["outcome"] for m in draws(rt, "r")] == ["partial"]


def test_a_stream_can_stay_open_while_tools_run(tmp_path, api):
    base = api.client("anthropic", False)

    def agent(ctx):
        c = ctx.wrap(base)
        with c.messages.stream(model=ANTHROPIC_MODEL, max_tokens=64, messages=MSGS) as st:
            pieces = []
            for text in st.text_stream:
                pieces.append(text)
                if len(pieces) == 2:
                    pieces.append(ctx.tool("lookup", lambda: "tool ran mid-stream"))
            return json.dumps(pieces)

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert "tool ran mid-stream" in json.loads(rec.output)
    assert [m["outcome"] for m in draws(rt, "r")] == ["ok"]


# ---------------------------------------------------------------------------
# HTTP errors, retries and transport failures
# ---------------------------------------------------------------------------


def rate_limited(provider: str) -> Any:
    error = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    if provider == "openai":
        error = {"error": {"message": "slow down", "type": "rate_limit_error", "code": None}}
    return httpx2.Response(429, headers={"retry-after-ms": "5", "x-ratelimit-remaining": "0"}, json=error)


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("is_async", [False, True])
def test_429_then_200_replays_the_retry_without_waiting(tmp_path, api, provider, is_async):
    base = api.client(provider, is_async, max_retries=2)
    api.fail_next(rate_limited(provider))
    if is_async:

        async def agent(ctx):
            return text_of(await create(ctx.wrap(base), provider), provider)

    else:

        def agent(ctx):
            return text_of(create(ctx.wrap(base), provider), provider)

    rt = pragmatic.Runtime(tmp_path)
    rec = rt.run("r", agent)
    assert rec.output == TEXT and len(api.calls) == 2
    started = time.monotonic()
    rep = rt.replay("r", agent)
    assert time.monotonic() - started < 0.4, "replay waited out a retry"
    assert rep.output == TEXT and len(api.calls) == 2
    first, second = draws(rt, "r")
    assert first["outcome"] == "error" and first["status"] == 429
    assert second["outcome"] == "ok"


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("is_async", [False, True])
def test_400_replays_as_the_same_sdk_error(tmp_path, api, provider, is_async):
    if provider == "anthropic":
        body = {"type": "error", "error": {"type": "invalid_request_error", "message": "bad model"}}
        error_cls = anthropic.BadRequestError
    else:
        body = {"error": {"message": "bad model", "type": "invalid_request_error", "code": None}}
        error_cls = openai.BadRequestError
    base = api.client(provider, is_async)

    def bad_request() -> None:
        api.fail_next(httpx2.Response(400, headers={"request-id": "req_bad", "x-request-id": "req_bad"}, json=body))

    def describe(e: Any) -> str:
        return json.dumps([type(e).__name__, e.status_code, e.request_id, str(e)])

    if is_async:

        async def agent(ctx):
            bad_request()
            try:
                await create(ctx.wrap(base), provider)
            except error_cls as e:
                return describe(e)
            return "no error"

    else:

        def agent(ctx):
            bad_request()
            try:
                create(ctx.wrap(base), provider)
            except error_cls as e:
                return describe(e)
            return "no error"

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output)[:3] == ["BadRequestError", 400, "req_bad"]
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "error" and meta["status"] == 400


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("is_async", [False, True])
def test_transport_errors_are_results(tmp_path, api, provider, is_async):
    base = api.client(provider, is_async, max_retries=0)
    error_cls = anthropic.APIConnectionError if provider == "anthropic" else openai.APIConnectionError

    def describe(e: BaseException) -> str:
        cause = e.__cause__
        return json.dumps([type(e).__name__, type(cause).__name__, str(cause)])

    if is_async:

        async def agent(ctx):
            api.fail_next(httpx2.ConnectError("connection refused"))
            try:
                await create(ctx.wrap(base), provider)
            except error_cls as e:
                return describe(e)

    else:

        def agent(ctx):
            api.fail_next(httpx2.ConnectError("connection refused"))
            try:
                create(ctx.wrap(base), provider)
            except error_cls as e:
                return describe(e)

    rt = pragmatic.Runtime(tmp_path)
    rec = rt.run("r", agent)
    api.faults.clear()
    calls = len(api.calls)
    rep = rt.replay("r", agent)
    api.faults.clear()
    assert len(api.calls) == calls and rep.output == rec.output
    assert json.loads(rec.output) == ["APIConnectionError", "ConnectError", "connection refused"]
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "error" and meta["error_kind"] == "connect"
    assert meta["error_type"].endswith("ConnectError") and "status" not in meta


def test_a_timeout_replays_as_a_timeout_and_is_retried(tmp_path, api):
    base = api.client("openai", False, max_retries=1)

    def agent(ctx):
        api.fail_next(httpx2.ReadTimeout("read timed out"))
        return text_of(create(ctx.wrap(base), "openai"), "openai")

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert rec.output == TEXT
    first, second = draws(rt, "r")
    assert first["error_kind"] == "timeout" and second["outcome"] == "ok"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_body_that_breaks_mid_stream_replays_the_same_failure(tmp_path, api, provider):
    base = api.client(provider, False)

    def agent(ctx):
        api.fail_next(("break", 700, httpx2.ReadError("connection reset")))
        seen = 0
        try:
            for _ in create(ctx.wrap(base), provider, stream=True):
                seen += 1
        except Exception as e:  # noqa: BLE001 - the SDK may wrap it
            cause = e.__cause__ or e
            return json.dumps([seen, type(cause).__name__, str(cause)])
        return "unbroken"

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    seen, name, message = json.loads(rec.output)
    assert seen > 0 and name == "ReadError" and message == "connection reset"
    [meta] = draws(rt, "r")
    assert meta["outcome"] == "error" and meta["status"] == 200 and meta["error_kind"] == "protocol"


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("is_async", [False, True])
def test_crash_mid_stream_then_resume(tmp_path, api, provider, is_async):
    base = api.client(provider, is_async)
    crash = {"on": True}

    if is_async:

        async def agent(ctx):
            c = ctx.wrap(base)
            before = text_of(await create(c, provider), provider)
            names = []
            async for event in await create(c, provider, stream=True):
                names.append(repr(event)[:30])
                if crash["on"] and len(names) == 2:
                    raise Crash()
            return json.dumps([before, len(names)])

    else:

        def agent(ctx):
            c = ctx.wrap(base)
            before = text_of(create(c, provider), provider)
            names = []
            for event in create(c, provider, stream=True):
                names.append(repr(event)[:30])
                if crash["on"] and len(names) == 2:
                    raise Crash()
            return json.dumps([before, len(names)])

    rt = pragmatic.Runtime(tmp_path)
    with pytest.raises(Crash):
        rt.run("r", agent)
    assert len(api.calls) == 2
    # The stream's intent is on record without a result: nothing was
    # written after the crash.
    kinds = [e["kind"] for e in rt.entries("r")]
    assert kinds.count("DrawIntent") == 2 and kinds.count("DrawResult") == 1
    assert "attempt.end" not in [e["fields"].get("kind") for e in rt.entries("r")]
    crash["on"] = False
    report = rt.resume("r", agent)
    # The first call came from the journal; the interrupted stream was made
    # again, under the intent the crash left open.
    assert len(api.calls) == 3
    assert report.replayed_steps >= 1
    calls = len(api.calls)
    audit = rt.replay("r", agent)
    assert audit.output == report.output and len(api.calls) == calls
    assert [m["outcome"] for m in draws(rt, "r")] == ["ok", "ok"]


# ---------------------------------------------------------------------------
# Faults inside the SDK, runs and branches
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("is_async", [False, True])
def test_a_desync_reaches_the_caller_unwrapped_and_unretried(tmp_path, api, provider, is_async):
    base = api.client(provider, is_async, max_retries=3)

    def make(prompt):
        if is_async:

            async def agent(ctx):
                c = ctx.wrap(base)
                if provider == "anthropic":
                    r = await c.messages.create(model=ANTHROPIC_MODEL, max_tokens=8,
                                                messages=[{"role": "user", "content": prompt}])
                else:
                    r = await c.chat.completions.create(model=OPENAI_MODEL,
                                                        messages=[{"role": "user", "content": prompt}])
                return text_of(r, provider)

            return agent

        def agent(ctx):
            c = ctx.wrap(base)
            if provider == "anthropic":
                r = c.messages.create(model=ANTHROPIC_MODEL, max_tokens=8,
                                      messages=[{"role": "user", "content": prompt}])
            else:
                r = c.chat.completions.create(model=OPENAI_MODEL, messages=[{"role": "user", "content": prompt}])
            return text_of(r, provider)

        return agent

    rt = pragmatic.Runtime(tmp_path)
    rt.run("r", make("hello"))
    started = time.monotonic()
    with pytest.raises(pragmatic.JournalDesync) as caught:
        rt.replay("r", make("goodbye"))
    assert time.monotonic() - started < 0.4, "the SDK retried a journal fault"
    assert any("content" in line and "goodbye" in line for line in caught.value.diff)
    assert len(api.calls) == 1


def test_a_failed_persist_is_not_retried_by_the_sdk(tmp_path, api, pystore):
    base = api.client("anthropic", False, max_retries=3)
    pystore.fail = lambda n, frames: OSError("disk full") if n == 2 else None
    rt = pragmatic.Runtime(pystore)
    with pytest.raises(OSError, match="disk full"):
        rt.run("r", lambda ctx: create(ctx.wrap(base), "anthropic"))
    assert api.calls == [], "the model was called before its intent was durable"


def test_pragmatic_wrap_follows_the_calling_run(tmp_path, api):
    client = pragmatic.wrap(api.client("anthropic", False))

    def agent(ctx):
        return text_of(create(client, "anthropic"), "anthropic")

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "one", agent)
    record_then_replay(rt, api, "two", agent)
    assert len(api.calls) == 2


def test_outside_a_run_a_journaled_client_refuses_or_passes_through(tmp_path, api):
    strict = pragmatic.wrap(api.client("anthropic", False))
    with pytest.raises(pragmatic.JournalFault) as caught:
        create(strict, "anthropic")
    assert isinstance(caught.value.error, pragmatic.NotInRun)
    assert api.calls == []

    loose = pragmatic.wrap(api.client("anthropic", False), outside="passthrough")
    assert text_of(create(loose, "anthropic"), "anthropic") == TEXT
    assert len(api.calls) == 1

    with pytest.raises(ValueError):
        pragmatic.wrap(api.client("anthropic", False), outside="sometimes")


def test_passthrough_calls_are_counted_in_attempt_end(tmp_path, api):
    base = api.client("openai", False)

    def agent(ctx):
        c = ctx.wrap(base, outside="passthrough")
        create(c, "openai")
        # A plain thread does not carry the run's context: its call is let
        # through unrecorded, and counted.
        t = threading.Thread(target=lambda: create(c, "openai"))
        t.start()
        t.join()
        return "ok"

    rt = pragmatic.Runtime(tmp_path)
    rt.run("r", agent)
    assert len(api.calls) == 2
    assert len(draws(rt, "r")) == 1
    assert notes(rt, "r", "attempt.end")[0]["passthrough_calls"] == 1


def test_a_client_bound_to_one_run_is_refused_in_another(tmp_path, api):
    base = api.client("anthropic", False)
    kept = {}

    def first(ctx):
        kept["client"] = ctx.wrap(base, outside="passthrough")
        return "ok"

    def second(ctx):
        return text_of(create(kept["client"], "anthropic"), "anthropic")

    rt = pragmatic.Runtime(tmp_path)
    rt.run("one", first)
    with pytest.raises(pragmatic.NotInRun, match="wrapped by the attempt on run 'one'"):
        rt.run("two", second)


def test_requests_to_another_host_are_refused(tmp_path, api):
    base = api.client("anthropic", False)

    def agent(ctx):
        c = ctx.wrap(base)
        c.post("https://elsewhere.example/v1/upload", cast_to=dict, body={"a": 1})

    rt = pragmatic.Runtime(tmp_path)
    with pytest.raises(pragmatic.Unsupported, match="elsewhere.example"):
        rt.run("r", agent)
    assert api.calls == []


def test_websocket_and_realtime_surfaces_are_refused(tmp_path, api):
    c = pragmatic.wrap(api.client("openai", False), outside="passthrough")
    with pytest.raises(pragmatic.Unsupported, match="websocket"):
        c.websocket_base_url
    with pytest.raises(pragmatic.Unsupported, match="websocket"):
        with c.responses.connect() as connection:
            connection.send({"type": "response.create"})
    with pytest.raises(pragmatic.Unsupported, match="websocket"):
        c.with_options(timeout=5).realtime.connect(model="gpt-realtime").enter()


def test_copies_of_a_journaled_client_keep_journaling(tmp_path, api):
    base = api.client("openai", False)

    def agent(ctx):
        c = ctx.wrap(base)
        derived = [c.with_options(timeout=5, max_retries=0), c.copy(), c.copy(http_client=api.http_client(False))]
        for d in derived:
            assert isinstance(d, openai.OpenAI) and type(d) is type(c)
            create(d, "openai")
        return "ok"

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert len(draws(rt, "r")) == 3


def test_sdk_releases_before_httpx2_are_refused_with_the_upgrade(monkeypatch, api):
    client = api.client("anthropic", False)
    monkeypatch.setattr(anthropic, "__version__", "0.75.0")
    with pytest.raises(pragmatic.Unsupported, match=r"anthropic>=1\.0"):
        pragmatic.wrap(client)
    monkeypatch.setattr(openai, "__version__", "2.9.1")
    with pytest.raises(pragmatic.Unsupported, match=r"openai>=3\.0"):
        pragmatic.wrap(api.client("openai", False))
    with pytest.raises(TypeError, match="Anthropic and OpenAI"):
        pragmatic.wrap(object())


def test_gather_children_call_the_model_on_branches_of_their_own(tmp_path, api):
    base = api.client("anthropic", True)

    async def ask(ctx, c, prompt):
        r = await c.messages.create(model=ANTHROPIC_MODEL, max_tokens=8,
                                    messages=[{"role": "user", "content": prompt}])
        await asyncio.sleep(0)
        return prompt + ":" + r.content[0].text

    async def agent(ctx):
        c = ctx.wrap(base)
        return json.dumps(await ctx.gather(lambda x: ask(x, c, "a"), lambda x: ask(x, c, "b")))

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    branches = sorted(tuple(e["branch"]) for e in rt.entries("r") if e["kind"] == "DrawIntent")
    assert branches == [(0,), (1,)]


def test_concurrent_identical_calls_on_one_branch_are_warned_about(tmp_path, api, caplog):
    base = api.client("openai", True)

    async def agent(ctx):
        c = ctx.wrap(base)
        # What a framework does with tasks of its own: they inherit the
        # agent's context, so both calls land on the agent's branch.
        streams = await asyncio.gather(create(c, "openai", stream=True), create(c, "openai", stream=True))
        return json.dumps([await aevent_names(s, "openai") for s in streams])

    rt = pragmatic.Runtime(tmp_path)
    with caplog.at_level(logging.WARNING, logger="pragmatic"):
        record_then_replay(rt, api, "r", agent)
    assert any("identical requests" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Normalization (spec 6.6)
# ---------------------------------------------------------------------------


def test_volatile_fields_are_ignored_by_matching_but_kept_in_the_journal(tmp_path, api):
    base = api.client("anthropic", False)

    def make(session):
        def agent(ctx):
            r = ctx.wrap(base).messages.create(
                model=ANTHROPIC_MODEL, max_tokens=8, messages=MSGS, metadata={"user_id": session}
            )
            return r.content[0].text

        return agent

    rt = pragmatic.Runtime(tmp_path, volatile=["$.metadata.user_id"])
    rt.run("r", make("session-1"))
    assert rt.replay("r", make("session-2")).output == TEXT
    assert len(api.calls) == 1
    [start] = notes(rt, "r", "attempt.start")
    assert start["normalization"] == ["agents-sdk:prompt_cache_key", "$.metadata.user_id"]
    [intent] = [e for e in rt.entries("r") if e["kind"] == "DrawIntent"]
    assert "session-1" in intent["slots"][0]["text"]
    # Without the rule the same change is a desync.
    with pytest.raises(pragmatic.JournalDesync):
        pragmatic.Runtime(tmp_path).replay("r", make("session-2"))
    with pytest.raises(ValueError, match="JSON path"):
        pragmatic.Runtime(tmp_path, volatile=["metadata.user_id"])


def test_agents_sdk_run_cache_keys_are_normalized(tmp_path, api):
    base = api.client("openai", False)

    def make(key):
        def agent(ctx):
            c = ctx.wrap(base)
            return text_of(create(c, "openai", prompt_cache_key=key), "openai")

        return agent

    rt = pragmatic.Runtime(tmp_path)
    rt.run("r", make("agents-sdk:run:1111"))
    assert rt.replay("r", make("agents-sdk:run:2222")).output == TEXT
    # A stable key (from a group or conversation id) is still compared.
    rt.run("s", make("agents-sdk:group:abc"))
    with pytest.raises(pragmatic.JournalDesync):
        rt.replay("s", make("agents-sdk:group:xyz"))


# ---------------------------------------------------------------------------
# Tool runners, frameworks' faults, spans
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("streaming,eager", [(False, False), (True, False), (True, True)])
def test_anthropic_tool_runner_with_journaled_tools(tmp_path, api, streaming, eager):
    base = api.client("anthropic", False)
    performed = []

    def agent(ctx):
        @anthropic.beta_tool
        def get_weather(city: str) -> str:
            """The weather in a city."""
            # The runner calls the tool; ctx.tool journals it as an effect,
            # so replay returns the recorded result without performing it.
            return ctx.tool("get_weather", lambda c: performed.append(c) or f"sunny in {c}", city)

        kw = {"stream": True, "run_tools_eagerly": eager} if streaming else {}
        runner = ctx.wrap(base).beta.messages.tool_runner(
            model=ANTHROPIC_MODEL, max_tokens=64, tools=[get_weather], messages=MSGS, **kw
        )
        if streaming:
            # Eagerly, the tool runs while its reply is still streaming: the
            # effect is journaled while the draw is open.
            return json.dumps([stream.get_final_message().stop_reason for stream in runner])
        return json.dumps([message.stop_reason for message in runner])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "r", agent)
    assert json.loads(rec.output) == ["tool_use", "end_turn"]
    assert performed == ["Paris"], "replay performed the tool again"
    kinds = [e["kind"] for e in rt.entries("r") if e["kind"] != "Note"]
    if eager:
        assert kinds[:4] == ["DrawIntent", "EffectIntent", "EffectResult", "DrawResult"]


def test_http_draws_emit_spans_without_content(tmp_path, api, span_exporter):
    exporter = span_exporter
    base = api.client("anthropic", False)

    def agent(ctx):
        c = ctx.wrap(base)
        create(c, "anthropic")
        return json.dumps(event_names(create(c, "anthropic", stream=True), "anthropic"))

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "spans", agent)
    spans = [s for s in exporter.get_finished_spans() if s.name == f"chat {ANTHROPIC_MODEL}"]
    assert len(spans) == 4
    recorded, replayed = spans[:2], spans[2:]
    assert [s.attributes["gen_ai.usage.input_tokens"] for s in recorded] == [12, 12]
    assert all(s.attributes["pragmatic.replayed"] is True for s in replayed)
    assert all(s.attributes["gen_ai.usage.output_tokens"] == 0 for s in replayed)
    assert "Hello" not in json.dumps([dict(s.attributes) for s in spans])


def test_a_gather_child_may_return_with_a_stream_still_open(tmp_path, api):
    base = api.client("openai", True)

    async def child(ctx, c):
        s = await create(c, "openai", stream=True)
        it = s.__aiter__()
        await it.__anext__()
        child.keep = (s, it)
        return "returned mid-stream"

    async def agent(ctx):
        c = ctx.wrap(base)
        out = await ctx.gather(lambda x: child(x, c), lambda x: ask(x, c))
        return json.dumps(out + [text_of(await create(c, "openai"), "openai")])

    async def ask(ctx, c):
        return text_of(await create(c, "openai"), "openai")

    rt = pragmatic.Runtime(tmp_path)
    record_then_replay(rt, api, "r", agent)
    assert sorted(m["outcome"] for m in draws(rt, "r")) == ["ok", "ok", "partial"]
