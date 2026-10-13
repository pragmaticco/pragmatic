"""Agent frameworks over journaled clients, end to end (spec 6.5).

Each framework runs unmodified against ``model_api.ModelAPI``. Every test
records a run that includes a tool-using turn, then replays it and checks
that the replay made no network call at all and produced the same output.
The frameworks are optional: a test skips when its package is missing.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import pytest

import pragmatic

pytest.importorskip("anthropic")
pytest.importorskip("openai")
pytest.importorskip("httpx2")

from model_api import ANTHROPIC_MODEL, OPENAI_MODEL, TEXT, ModelAPI  # noqa: E402


@pytest.fixture
def api() -> ModelAPI:
    return ModelAPI()


def record_then_replay(rt: pragmatic.Runtime, api: ModelAPI, run_id: str, agent: Callable) -> Any:
    rec = rt.run(run_id, agent)
    calls = len(api.calls)
    assert calls > 0
    rep = rt.replay(run_id, agent)
    assert len(api.calls) == calls, "replay touched the network"
    assert rep.output == rec.output and rep.fresh_steps == 0
    assert rt.verify(run_id)
    return rec


def weather(city: str) -> str:
    """The weather in a city."""
    return f"sunny in {city}"


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------


@pytest.fixture
def agents_sdk(monkeypatch: pytest.MonkeyPatch) -> Any:
    agents = pytest.importorskip("agents")
    from agents.models import _openai_shared

    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "1")
    agents.set_tracing_disabled(True)
    monkeypatch.setattr(_openai_shared, "_default_openai_client", None)
    return agents


def test_openai_agents_sdk_run_and_run_streamed(tmp_path, api, agents_sdk):
    agents = agents_sdk
    # One journaled client for the whole process: it records into
    # whichever run calls it.
    agents.set_default_openai_client(pragmatic.wrap(api.client("openai", True)), use_for_tracing=False)
    tool = agents.function_tool(weather)
    agent = agents.Agent(name="forecaster", instructions="Be brief.", model=OPENAI_MODEL, tools=[tool])

    async def run(ctx):
        result = await agents.Runner.run(agent, "Weather in Paris?")
        streamed = agents.Runner.run_streamed(agent, "Weather in Paris?")
        deltas = []
        async for event in streamed.stream_events():
            if event.type == "raw_response_event" and event.data.type == "response.output_text.delta":
                deltas.append(event.data.delta)
        return json.dumps([result.final_output, streamed.final_output, "".join(deltas)])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "agents", run)
    final, streamed_final, deltas = json.loads(rec.output)
    assert final == TEXT and streamed_final == TEXT and deltas == TEXT
    # Each run sends a fresh per-run prompt cache key, which the built-in
    # normalization rule lets replay ignore.
    assert any(str(body.get("prompt_cache_key", "")).startswith("agents-sdk:run:") for _, body in api.calls)
    # Tool turns: the tool's result went back to the model.
    assert any(
        any(isinstance(i, dict) and i.get("type") == "function_call_output" for i in body.get("input", []))
        for _, body in api.calls
    )


# ---------------------------------------------------------------------------
# Pydantic AI
# ---------------------------------------------------------------------------


def test_pydantic_ai_anthropic_provider(tmp_path, api):
    pai = pytest.importorskip("pydantic_ai")
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.providers.anthropic import AnthropicProvider

    client = pragmatic.wrap(api.client("anthropic", True))
    model = AnthropicModel(ANTHROPIC_MODEL, provider=AnthropicProvider(anthropic_client=client))
    agent = pai.Agent(model, tools=[weather])

    async def run(ctx):
        result = await agent.run("Weather in Paris?")
        async with agent.run_stream("Weather in Paris?") as streamed:
            text = await streamed.get_output()
        return json.dumps([result.output, text])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "pai-anthropic", run)
    assert json.loads(rec.output) == [TEXT, TEXT]


def test_pydantic_ai_openai_provider(tmp_path, api):
    pai = pytest.importorskip("pydantic_ai")
    from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
    from pydantic_ai.providers.openai import OpenAIProvider

    provider = OpenAIProvider(openai_client=pragmatic.wrap(api.client("openai", True)))
    chat = pai.Agent(OpenAIChatModel(OPENAI_MODEL, provider=provider), tools=[weather])
    responses = pai.Agent(OpenAIResponsesModel(OPENAI_MODEL, provider=provider))

    async def run(ctx):
        a = await chat.run("Weather in Paris?")
        async with responses.run_stream("Hello?") as streamed:
            b = await streamed.get_output()
        return json.dumps([a.output, b])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "pai-openai", run)
    assert json.loads(rec.output) == [TEXT, TEXT]


# ---------------------------------------------------------------------------
# LangChain and LangGraph
# ---------------------------------------------------------------------------


def chat_anthropic(api: ModelAPI) -> Any:
    """A ChatAnthropic whose SDK clients talk to the fake API (ChatAnthropic
    builds its clients itself, as cached properties)."""
    langchain_anthropic = pytest.importorskip("langchain_anthropic")
    llm = langchain_anthropic.ChatAnthropic(model=ANTHROPIC_MODEL, api_key="sk-test", max_tokens=64)
    llm.__dict__["_client"] = api.client("anthropic", False)
    llm.__dict__["_async_client"] = api.client("anthropic", True)
    return llm


def chat_openai(api: ModelAPI, **kwargs: Any) -> Any:
    langchain_openai = pytest.importorskip("langchain_openai")
    return langchain_openai.ChatOpenAI(
        model=OPENAI_MODEL,
        api_key="sk-test",
        http_client=api.http_client(False),
        http_async_client=api.http_client(True),
        **kwargs,
    )


def test_langchain_chat_anthropic(tmp_path, api):
    from pragmatic.integrations.langchain import journal

    original = chat_anthropic(api)
    llm = journal(original)
    assert original.__dict__["_client"] is not llm.__dict__["_client"]

    def run(ctx):
        out = llm.invoke("hi").content
        streamed = "".join(str(chunk.content) for chunk in llm.stream("hi"))
        return json.dumps([out, streamed])

    async def arun(ctx):
        out = (await llm.ainvoke("hi")).content
        streamed = "".join([str(chunk.content) async for chunk in llm.astream("hi")])
        return json.dumps([out, streamed])

    rt = pragmatic.Runtime(tmp_path)
    assert json.loads(record_then_replay(rt, api, "sync", run).output) == [TEXT, TEXT]
    assert json.loads(record_then_replay(rt, api, "async", arun).output) == [TEXT, TEXT]


@pytest.mark.parametrize("responses_api", [False, True])
def test_langchain_chat_openai(tmp_path, api, responses_api):
    from pragmatic.integrations.langchain import journal

    llm = journal(chat_openai(api, use_responses_api=responses_api))

    def run(ctx):
        out = llm.invoke("hi").text
        streamed = "".join(chunk.text for chunk in llm.stream("hi"))
        return json.dumps([out, streamed])

    async def arun(ctx):
        out = (await llm.ainvoke("hi")).text
        streamed = "".join([chunk.text async for chunk in llm.astream("hi")])
        return json.dumps([out, streamed])

    rt = pragmatic.Runtime(tmp_path)
    assert json.loads(record_then_replay(rt, api, "sync", run).output) == [TEXT, TEXT]
    assert json.loads(record_then_replay(rt, api, "async", arun).output) == [TEXT, TEXT]


def test_journal_refuses_other_models():
    from pragmatic.integrations.langchain import journal

    with pytest.raises(TypeError, match="ChatAnthropic or ChatOpenAI"):
        journal(object())


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_langgraph_agent(tmp_path, api, provider):
    prebuilt = pytest.importorskip("langgraph.prebuilt")
    from pragmatic.integrations.langchain import journal

    llm = journal(chat_anthropic(api) if provider == "anthropic" else chat_openai(api))
    graph = prebuilt.create_react_agent(llm, tools=[weather])

    def run(ctx):
        state = graph.invoke({"messages": [("user", "Weather in Paris?")]})
        return json.dumps([m.type for m in state["messages"]] + [state["messages"][-1].text])

    async def arun(ctx):
        state = await graph.ainvoke({"messages": [("user", "Weather in Paris?")]})
        return json.dumps([m.type for m in state["messages"]] + [state["messages"][-1].text])

    rt = pragmatic.Runtime(tmp_path)
    rec = record_then_replay(rt, api, "graph", run)
    assert json.loads(rec.output) == ["human", "ai", "tool", "ai", TEXT]
    record_then_replay(rt, api, "agraph", arun)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_a_desync_surfaces_through_framework_tasks_and_threads(tmp_path, api, agents_sdk):
    """A replay that disagrees with the journal raises ``JournalDesync``
    from ``rt.replay`` however deep in a framework the model call was made:
    in the Agents SDK's background task of ``run_streamed``, in a LangGraph
    node, never swallowed by their error handling or retried."""
    agents = agents_sdk
    from pragmatic.integrations.langchain import journal

    agents.set_default_openai_client(pragmatic.wrap(api.client("openai", True)), use_for_tracing=False)
    prebuilt = pytest.importorskip("langgraph.prebuilt")
    graph = prebuilt.create_react_agent(journal(chat_anthropic(api)), tools=[weather])

    def streamed(prompt):
        async def run(ctx):
            agent = agents.Agent(name="a", instructions="Be brief.", model=OPENAI_MODEL)
            result = agents.Runner.run_streamed(agent, prompt)
            async for _ in result.stream_events():
                pass
            return result.final_output

        return run

    def node(prompt):
        def run(ctx):
            return graph.invoke({"messages": [("user", prompt)]})["messages"][-1].text

        return run

    rt = pragmatic.Runtime(tmp_path)
    for run_id, make in (("streamed", streamed), ("graph", node)):
        rt.run(run_id, make("Weather in Paris?"))
        calls = len(api.calls)
        with pytest.raises(pragmatic.JournalDesync):
            rt.replay(run_id, make("Weather in Rome?"))
        assert len(api.calls) == calls
