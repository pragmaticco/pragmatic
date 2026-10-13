"""Record with pragmatic.Runtime.run, replay with Runtime.replay, compare.

Run with:
  PYTHONPATH=<repo>/crates/pragmatic-python/python intvenv/bin/python -I? (no: needs PYTHONPATH)
  intvenv/bin/python stream_proto/test_proto.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, "/Users/ankthba/Documents/Developer/Pragmatic AI/crates/pragmatic-python/python")

import anthropic
import httpx2
import openai
import pydantic

import pragmatic
from journal_http import ReplayOverrun, journaled
from mock_server import MockServer

server = MockServer()
A_MODEL, O_MODEL = "claude-sonnet-5-5", "gpt-5.5"
MSGS = [{"role": "user", "content": "hi"}]


class Weather(pydantic.BaseModel):
    city: str
    temp_c: int


def dump(m):
    return m.model_dump(mode="json")


# -- Anthropic ------------------------------------------------------------

base_anthropic = anthropic.Anthropic(api_key="sk-test", http_client=httpx2.Client(transport=server.sync_transport()))
base_aanthropic = anthropic.AsyncAnthropic(api_key="sk-test", http_client=httpx2.AsyncClient(transport=server.async_transport()))


@pragmatic.durable
def anthropic_sync(ctx):
    c = journaled(base_anthropic, ctx)
    o: dict = {"client_isinstance": isinstance(c, anthropic.Anthropic)}

    s = c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
    o["create_stream_cls"] = f"{type(s).__module__}.{type(s).__qualname__}"
    o["create_stream_isinstance"] = isinstance(s, anthropic.Stream)
    o["create_stream_events"] = [e.type for e in s]
    o["create_stream_request_id"] = s.response.headers.get("request-id")

    with c.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        o["stream_cls"] = type(st).__name__
        o["text_stream"] = "".join(st.text_stream)
        o["final_message"] = dump(st.get_final_message())
        o["final_text"] = st.get_final_text()
        o["stream_request_id"] = st.request_id

    s = c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
    early = []
    for e in s:
        early.append(e.type)
        if len(early) == 3:
            break
    s.close()
    o["early_close_events"] = early

    with c.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        o["early_text"] = next(iter(st.text_stream))  # leave the block early

    m = c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS)
    o["create"] = dump(m)
    o["create_request_id"] = m._request_id

    p = c.messages.parse(model=A_MODEL, max_tokens=64, messages=MSGS, output_format=Weather)
    o["parse_cls"] = type(p).__name__
    o["parse_output"] = p.parsed_output.model_dump()

    with c.beta.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        o["beta_stream_cls"] = type(st).__name__
        o["beta_final"] = dump(st.get_final_message())
    return json.dumps(o, sort_keys=True)


@pragmatic.durable
async def anthropic_async(ctx):
    c = journaled(base_aanthropic, ctx)
    o: dict = {"client_isinstance": isinstance(c, anthropic.AsyncAnthropic)}

    s = await c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
    o["create_stream_isinstance"] = isinstance(s, anthropic.AsyncStream)
    o["create_stream_events"] = [e.type async for e in s]

    async with c.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        o["text_stream"] = "".join([t async for t in st.text_stream])
        o["final_message"] = dump(await st.get_final_message())

    s = await c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
    early = []
    async for e in s:
        early.append(e.type)
        if len(early) == 3:
            break
    await s.close()
    o["early_close_events"] = early

    async with c.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        async for t in st.text_stream:
            o["early_text"] = t
            break

    p = await c.messages.parse(model=A_MODEL, max_tokens=64, messages=MSGS, output_format=Weather)
    o["parse_output"] = p.parsed_output.model_dump()

    async with c.beta.messages.stream(model=A_MODEL, max_tokens=64, messages=MSGS) as st:
        o["beta_final"] = dump(await st.get_final_message())
    return json.dumps(o, sort_keys=True)


# -- OpenAI ---------------------------------------------------------------

base_openai = openai.OpenAI(api_key="sk-test", http_client=httpx2.Client(transport=server.sync_transport()))
base_aopenai = openai.AsyncOpenAI(api_key="sk-test", http_client=httpx2.AsyncClient(transport=server.async_transport()))


@pragmatic.durable
def openai_sync(ctx):
    c = journaled(base_openai, ctx)
    o: dict = {"client_isinstance": isinstance(c, openai.OpenAI)}

    s = c.chat.completions.create(model=O_MODEL, messages=MSGS, stream=True)
    o["chat_stream_isinstance"] = isinstance(s, openai.Stream)
    o["chat_chunks"] = [ch.choices[0].delta.content for ch in s]

    with c.chat.completions.stream(model=O_MODEL, messages=MSGS) as st:
        o["chat_helper_cls"] = type(st).__name__
        o["chat_helper_deltas"] = [e.delta for e in st if e.type == "content.delta"]
        o["chat_final"] = dump(st.get_final_completion())

    with c.chat.completions.stream(model=O_MODEL, messages=MSGS, response_format=Weather) as st:
        o["chat_helper_parsed"] = st.get_final_completion().choices[0].message.parsed.model_dump()

    s = c.responses.create(model=O_MODEL, input="hi", stream=True)
    o["responses_events"] = [e.type for e in s]

    with c.responses.stream(model=O_MODEL, input="hi") as st:
        o["responses_helper_cls"] = type(st).__name__
        o["responses_helper_text"] = "".join(e.delta for e in st if e.type == "response.output_text.delta")
        fr = st.get_final_response()
        o["responses_final_text"] = fr.output_text
        o["responses_final_cls"] = type(fr).__name__

    pc = c.chat.completions.parse(model=O_MODEL, messages=MSGS, response_format=Weather)
    o["chat_parse"] = pc.choices[0].message.parsed.model_dump()
    o["chat_parse_request_id"] = pc._request_id

    pr = c.responses.parse(model=O_MODEL, input="hi", text_format=Weather)
    o["responses_parse"] = pr.output_parsed.model_dump()

    s = c.chat.completions.create(model=O_MODEL, messages=MSGS, stream=True)
    early = []
    for ch in s:
        early.append(ch.choices[0].delta.content)
        if len(early) == 2:
            break
    s.close()
    o["chat_early"] = early

    with c.responses.stream(model=O_MODEL, input="hi") as st:
        o["responses_early"] = next(iter(st)).type
    return json.dumps(o, sort_keys=True)


@pragmatic.durable
async def openai_async(ctx):
    c = journaled(base_aopenai, ctx)
    o: dict = {"client_isinstance": isinstance(c, openai.AsyncOpenAI)}

    s = await c.chat.completions.create(model=O_MODEL, messages=MSGS, stream=True)
    o["chat_stream_isinstance"] = isinstance(s, openai.AsyncStream)
    o["chat_chunks"] = [ch.choices[0].delta.content async for ch in s]

    async with c.chat.completions.stream(model=O_MODEL, messages=MSGS) as st:
        o["chat_helper_deltas"] = [e.delta async for e in st if e.type == "content.delta"]
        o["chat_final"] = dump(await st.get_final_completion())

    async with c.responses.stream(model=O_MODEL, input="hi") as st:
        o["responses_helper_text"] = "".join([e.delta async for e in st if e.type == "response.output_text.delta"])
        o["responses_final_text"] = (await st.get_final_response()).output_text

    pr = await c.responses.parse(model=O_MODEL, input="hi", text_format=Weather)
    o["responses_parse"] = pr.output_parsed.model_dump()

    s = await c.responses.create(model=O_MODEL, input="hi", stream=True)
    early = []
    async for e in s:
        early.append(e.type)
        if len(early) == 2:
            break
    await s.close()
    o["responses_early"] = early
    return json.dumps(o, sort_keys=True)


# -- driver ---------------------------------------------------------------


def check(name, agent):
    rt = pragmatic.Runtime(tempfile.mkdtemp(prefix=f"{name}-"))
    calls0, ups0 = len(server.calls), len(server.upstreams)
    rec = rt.run(name, agent)
    calls_rec = len(server.calls) - calls0
    stream_ups = server.upstreams[ups0:]
    rep = rt.replay(name, agent)
    calls_rep = len(server.calls) - calls0 - calls_rec
    same = rec.output == rep.output
    print(f"\n== {name}: record {rec}  replay {rep}")
    print(f"   network calls: record={calls_rec} replay={calls_rep}; outputs identical: {same}; chain verified: {rt.verify(name)}")
    print(f"   upstream SSE bodies closed after record: {[u.closed for u in stream_ups]}")
    assert same and calls_rep == 0, "replay diverged"
    assert all(u.closed for u in stream_ups), "an upstream stream leaked"
    out = json.loads(rec.output)
    for k in sorted(out):
        v = json.dumps(out[k])
        print(f"   {k}: {v[:150]}{'...' if len(v) > 150 else ''}")
    return rt


if __name__ == "__main__":
    check("anthropic-sync", anthropic_sync)
    check("anthropic-async", anthropic_async)
    check("openai-sync", openai_sync)
    check("openai-async", openai_async)

    # A replay whose agent reads further than the recording did must fail loudly.
    @pragmatic.durable
    def reads_less(ctx):
        c = journaled(base_anthropic, ctx)
        s = c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
        for i, _ in enumerate(s):
            if i == 1:
                break
        s.close()
        return "ok"

    @pragmatic.durable
    def reads_less_then_more(ctx):  # same name/body shape differs -> program marker differs
        return "unused"

    rt = pragmatic.Runtime(tempfile.mkdtemp(prefix="overrun-"))
    rt.run("overrun", reads_less)

    def reads_all(ctx):
        c = journaled(base_anthropic, ctx)
        s = c.messages.create(model=A_MODEL, max_tokens=64, messages=MSGS, stream=True)
        return str(len(list(s)))

    reads_all.__pragmatic_program__ = reads_less.__pragmatic_program__  # pretend same program
    try:
        rt.replay("overrun", reads_all)
        print("\n== overrun: NOT detected")
    except ReplayOverrun as e:
        print(f"\n== overrun detected: ReplayOverrun: {e}")
    except Exception as e:  # noqa: BLE001
        print(f"\n== overrun surfaced as {type(e).__module__}.{type(e).__name__}: {e}")
