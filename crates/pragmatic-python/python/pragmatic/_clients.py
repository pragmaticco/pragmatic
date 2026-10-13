"""Drop-in journaling for the Anthropic and OpenAI Python SDKs.

``ctx.wrap(client)`` returns a proxy that behaves like ``client``. Model
calls on the surfaces listed below are journaled: recorded fresh the first
time, read back on resume and replay without touching the network.
Everything else passes through to the real client untouched.

Record and replay hand the agent the same object: on record the SDK
response is serialized, journaled, and rebuilt from the journal before it
is returned, so the agent can never observe a difference.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from ._codec import request_prompt, to_jsonable

if TYPE_CHECKING:
    from ._runtime import Ctx


@dataclass(frozen=True)
class _Surface:
    api: str
    provider: str
    response_type: Callable[[], type]


def _anthropic_message() -> type:
    from anthropic.types import Message

    return Message


def _anthropic_beta_message() -> type:
    from anthropic.types.beta import BetaMessage

    return BetaMessage


def _openai_chat_completion() -> type:
    from openai.types.chat import ChatCompletion

    return ChatCompletion


def _openai_response() -> type:
    from openai.types.responses import Response

    return Response


_ANTHROPIC = {
    ("messages", "create"): _Surface(
        "anthropic.messages.create", "anthropic", _anthropic_message
    ),
    ("beta", "messages", "create"): _Surface(
        "anthropic.beta.messages.create", "anthropic", _anthropic_beta_message
    ),
}
_ANTHROPIC_UNSUPPORTED = {
    ("messages", "stream"): "messages.stream",
    ("beta", "messages", "stream"): "beta.messages.stream",
    ("messages", "batches"): "messages.batches",
}

_OPENAI = {
    ("chat", "completions", "create"): _Surface(
        "openai.chat.completions.create", "openai", _openai_chat_completion
    ),
    ("responses", "create"): _Surface(
        "openai.responses.create", "openai", _openai_response
    ),
}
_OPENAI_UNSUPPORTED = {
    ("chat", "completions", "stream"): "chat.completions.stream",
    ("chat", "completions", "parse"): "chat.completions.parse",
    ("responses", "stream"): "responses.stream",
    ("responses", "parse"): "responses.parse",
}


def _provider_tables(client: Any):
    module = type(client).__module__.split(".")[0]
    if module == "anthropic":
        return _ANTHROPIC, _ANTHROPIC_UNSUPPORTED
    if module == "openai":
        return _OPENAI, _OPENAI_UNSUPPORTED
    raise TypeError(
        f"ctx.wrap supports Anthropic and OpenAI SDK clients (sync or async); got "
        f"{type(client).__module__}.{type(client).__name__}. For any other model "
        "client, journal calls with ctx.draw(prompt, sample)."
    )


def _rebuild(surface: _Surface, outcome: str) -> Any:
    data = json.loads(outcome)
    cls = surface.response_type()
    try:
        return cls.model_validate(data)
    except Exception:
        # Tolerate responses newer than the installed SDK's schema, the same
        # way the SDK itself does.
        return cls.model_construct(**data)


def _serialize(response: Any) -> str:
    return json.dumps(to_jsonable(response), separators=(",", ":"), ensure_ascii=False)


def _check_request(surface: _Surface, kwargs: dict) -> None:
    if kwargs.get("stream") is True:
        raise NotImplementedError(
            f"{surface.api}(stream=True) is not journaled yet; call it without "
            "stream=True inside a durable run"
        )


def _provenance(surface: _Surface, kwargs: dict) -> str:
    model = kwargs.get("model")
    return f"{surface.provider}:{model}" if isinstance(model, str) else surface.provider


def _sync_call(ctx: "Ctx", surface: _Surface, real: Callable, kwargs: dict) -> Any:
    _check_request(surface, kwargs)
    prompt = request_prompt(surface.api, kwargs)
    outcome = ctx.draw(
        prompt,
        lambda: _serialize(real(**kwargs)),
        provenance=_provenance(surface, kwargs),
    )
    return _rebuild(surface, outcome)


async def _async_call(ctx: "Ctx", surface: _Surface, real: Callable, kwargs: dict) -> Any:
    _check_request(surface, kwargs)
    prompt = request_prompt(surface.api, kwargs)

    async def sample() -> str:
        return _serialize(await real(**kwargs))

    outcome = await ctx.adraw(prompt, sample, provenance=_provenance(surface, kwargs))
    return _rebuild(surface, outcome)


def _journaled(ctx: "Ctx", surface: _Surface, real: Callable, is_async: bool) -> Callable:
    if is_async:

        @functools.wraps(real)
        async def acreate(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise TypeError(f"{surface.api} takes keyword arguments only")
            return await _async_call(ctx, surface, real, kwargs)

        return acreate

    @functools.wraps(real)
    def create(*args: Any, **kwargs: Any) -> Any:
        if args:
            raise TypeError(f"{surface.api} takes keyword arguments only")
        return _sync_call(ctx, surface, real, kwargs)

    return create


def _unsupported(name: str) -> Callable:
    def refuse(*_: Any, **__: Any) -> Any:
        raise NotImplementedError(
            f"{name} is not journaled yet; inside a durable run use the "
            "non-streaming create() call"
        )

    return refuse


class JournaledClient:
    """A proxy over an SDK client (or one of its sub-resources) that routes
    model calls through the journal."""

    def __init__(self, target: Any, ctx: "Ctx", tables, is_async: bool, path: tuple = ()):
        self._target = target
        self._ctx = ctx
        self._tables = tables
        self._is_async = is_async
        self._path = path

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._target, name)
        path = self._path + (name,)
        journaled, unsupported = self._tables
        if path in journaled:
            return _journaled(self._ctx, journaled[path], attr, self._is_async)
        if path in unsupported:
            return _unsupported(unsupported[path])
        if path == ("with_options",):
            # A reconfigured client is still journaled.
            return lambda *a, **k: JournaledClient(
                attr(*a, **k), self._ctx, self._tables, self._is_async
            )
        if any(p[: len(path)] == path for p in (*journaled, *unsupported)):
            return JournaledClient(attr, self._ctx, self._tables, self._is_async, path)
        return attr

    def __repr__(self) -> str:
        return f"<journaled {self._target!r}>"


def wrap(client: Any, ctx: "Ctx") -> JournaledClient:
    # SDK methods are wrapped by decorators that hide `async def`, so the
    # client class decides: AsyncAnthropic, AsyncOpenAI, AsyncAzureOpenAI.
    is_async = any(c.__name__.startswith("Async") for c in type(client).__mro__)
    return JournaledClient(client, ctx, _provider_tables(client), is_async)
