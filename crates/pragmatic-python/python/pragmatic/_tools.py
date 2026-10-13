"""Journaled tool execution for model tool-use responses.

``ctx.run_tools(response, tools)`` finds the tool calls in an Anthropic
``Message``, an OpenAI ``ChatCompletion``, or an OpenAI Responses
``Response``, performs each one as a write-ahead journaled effect, and
returns the messages to append to the conversation. On resume and replay
the recorded results are reused and the tools are not called again.

A tool that raises is recorded as an error result and reported back to the
model, the way the provider APIs expect; the run keeps going. A tool that
takes an ``idempotency_key`` argument gets the effect's key
(``<run_id>/<branch>/<intent cursor>``), so a service it calls can
deduplicate the retry of an effect a crash interrupted.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping

from ._codec import canonical, to_jsonable

if TYPE_CHECKING:
    from ._runtime import Ctx


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: Any


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _parse_arguments(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return raw
    return raw


def _kind(response: Any) -> str:
    obj = _get(response, "object")
    if obj == "chat.completion":
        return "openai-chat"
    if obj == "response":
        return "openai-responses"
    if _get(response, "type") == "message" and _get(response, "content") is not None:
        return "anthropic"
    raise TypeError(
        "run_tools expects an Anthropic Message, an OpenAI ChatCompletion, or an "
        f"OpenAI Response; got {type(response).__name__}"
    )


def tool_calls(response: Any) -> list[ToolCall]:
    """The tool calls a model response asks for, in order."""
    kind = _kind(response)
    calls: list[ToolCall] = []
    if kind == "anthropic":
        for block in _get(response, "content") or []:
            if _get(block, "type") == "tool_use":
                calls.append(ToolCall(_get(block, "id"), _get(block, "name"), _get(block, "input")))
    elif kind == "openai-chat":
        choices = _get(response, "choices") or []
        message = _get(choices[0], "message") if choices else None
        for call in (_get(message, "tool_calls") or []) if message is not None else []:
            fn = _get(call, "function")
            calls.append(
                ToolCall(_get(call, "id"), _get(fn, "name"), _parse_arguments(_get(fn, "arguments")))
            )
    else:
        for item in _get(response, "output") or []:
            if _get(item, "type") == "function_call":
                calls.append(
                    ToolCall(
                        _get(item, "call_id"),
                        _get(item, "name"),
                        _parse_arguments(_get(item, "arguments")),
                    )
                )
    return calls


def accepts_key(fn: Callable) -> bool:
    """True if ``fn`` takes an ``idempotency_key`` argument by name."""
    try:
        param = inspect.signature(fn).parameters.get("idempotency_key")
    except (TypeError, ValueError):
        return False
    return param is not None and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def _invoke(fn: Callable, arguments: Any, key: str) -> Any:
    extra = {"idempotency_key": key} if accepts_key(fn) else {}
    if isinstance(arguments, dict):
        return fn(**arguments, **extra)
    return fn(arguments, **extra)


def _content(result: Any) -> str:
    return result if isinstance(result, str) else canonical(result)


def _record(result: Any = None, error: BaseException | None = None) -> str:
    if error is not None:
        return canonical({"content": f"{type(error).__name__}: {error}", "is_error": True})
    return canonical({"content": _content(to_jsonable(result)), "is_error": False})


def _messages(kind: str, calls: list[ToolCall], results: list[dict]) -> list[dict]:
    if not calls:
        return []
    if kind == "anthropic":
        blocks = []
        for call, r in zip(calls, results):
            block = {"type": "tool_result", "tool_use_id": call.id, "content": r["content"]}
            if r["is_error"]:
                block["is_error"] = True
            blocks.append(block)
        return [{"role": "user", "content": blocks}]
    if kind == "openai-chat":
        return [
            {"role": "tool", "tool_call_id": call.id, "content": r["content"]}
            for call, r in zip(calls, results)
        ]
    return [
        {"type": "function_call_output", "call_id": call.id, "output": r["content"]}
        for call, r in zip(calls, results)
    ]


def _lookup(tools: Mapping[str, Callable], call: ToolCall) -> Callable:
    fn = tools.get(call.name)
    if fn is None:

        def missing(*_: Any, **__: Any) -> Any:
            raise LookupError(f"no tool named {call.name!r}")

        return missing
    return fn


def run_tools(ctx: "Ctx", response: Any, tools: Mapping[str, Callable]) -> list[dict]:
    kind = _kind(response)
    calls = tool_calls(response)
    results = []
    for call in calls:
        fn = _lookup(tools, call)

        def perform(_arg: str, idempotency_key: str = "", fn=fn, call=call) -> str:
            try:
                out = _invoke(fn, call.input, idempotency_key)
            except Exception as e:  # reported to the model, not raised
                return _record(error=e)
            if inspect.isawaitable(out):
                raise TypeError(f"tool {call.name!r} is async; use await ctx.arun_tools(...)")
            return _record(out)

        stored = ctx.effect(f"tool:{call.name}", canonical({"id": call.id, "input": call.input}), perform)
        results.append(json.loads(stored))
    return _messages(kind, calls, results)


async def arun_tools(ctx: "Ctx", response: Any, tools: Mapping[str, Callable]) -> list[dict]:
    kind = _kind(response)
    calls = tool_calls(response)
    results = []
    for call in calls:
        fn = _lookup(tools, call)

        async def perform(_arg: str, idempotency_key: str = "", fn=fn, call=call) -> str:
            try:
                out = _invoke(fn, call.input, idempotency_key)
                if inspect.isawaitable(out):
                    out = await out
            except Exception as e:
                return _record(error=e)
            return _record(out)

        stored = await ctx.aeffect(
            f"tool:{call.name}", canonical({"id": call.id, "input": call.input}), perform
        )
        results.append(json.loads(stored))
    return _messages(kind, calls, results)
