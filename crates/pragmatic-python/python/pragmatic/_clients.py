"""Journaled Anthropic and OpenAI SDK clients (spec 6.5).

``ctx.wrap(client)`` and ``pragmatic.wrap(client)`` return a genuine SDK
client: ``client.copy(http_client=JournalingHttpClient(...))``, of a
subclass of the client's own class that differs in three ways only:

- ``copy()`` and ``with_options()`` keep the journaling HTTP client (and
  journal any ``http_client`` passed to them), so every derived client
  records too;
- the API host of each copy is the host its requests may go to; a request
  to any other host raises ``Unsupported``;
- on OpenAI clients, ``websocket_base_url`` raises ``Unsupported``: the
  websocket and realtime surfaces (``responses.connect()``,
  ``realtime.connect()``, the Agents SDK websocket transport) read it
  before they connect, and their traffic never passes through the HTTP
  client, so it could not be journaled.

``isinstance`` checks against the SDK classes hold, so frameworks that
check the client's type (Pydantic AI, LangChain) accept it. Everything the
SDK does goes through the journaling HTTP client: there is no list of
supported methods.

The floors are ``anthropic>=1.0`` and ``openai>=3.0``, the first releases
built on ``httpx2``. Older releases raise ``Unsupported`` with the upgrade
to make.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, Dict, Optional

from ._errors import Unsupported

if TYPE_CHECKING:
    from ._draws import AttemptHttp

FLOORS = {"anthropic": 1, "openai": 3}
"""The first major version of each SDK built on httpx2."""

OUTSIDE = ("error", "passthrough")

_WS_ATTR = "_pragmatic_websocket_base_url"
_WS_PLACEHOLDER = "wss://websockets-are-not-journaled.invalid"
_CLASSES: Dict[type, type] = {}


def _major(version: str) -> int:
    head = version.split(".", 1)[0]
    digits = "".join(c for c in head if c.isdigit())
    return int(digits) if digits else 0


def provider_of(client: Any) -> str:
    """``"anthropic"`` or ``"openai"`` for a client of a supported SDK at
    or above its floor; ``TypeError`` or ``Unsupported`` otherwise."""
    provider = type(client).__module__.split(".")[0]
    if provider not in FLOORS:
        raise TypeError(
            "pragmatic journals Anthropic and OpenAI SDK clients (sync or async); got "
            f"{type(client).__module__}.{type(client).__qualname__}. For another model "
            "client, journal each call with ctx.draw(prompt, sample)."
        )
    floor = FLOORS[provider]
    version = str(getattr(sys.modules.get(provider), "__version__", "0"))
    if _major(version) < floor:
        raise Unsupported(
            f"pragmatic journals {provider} clients at the HTTP layer, which needs "
            f"{provider}>={floor}.0 (the releases built on httpx2); this is {provider} "
            f"{version}. Upgrade with: pip install -U '{provider}>={floor}.0'"
        )
    return provider


def _ws_get(self: Any) -> Any:
    from ._http import WEBSOCKETS_UNSUPPORTED

    raise Unsupported(WEBSOCKETS_UNSUPPORTED)


def _ws_set(self: Any, value: Any) -> None:
    self.__dict__[_WS_ATTR] = value


def _journaled_class(cls: type) -> type:
    """The journaled subclass of an SDK client class (see the module
    documentation). One per class, named like it."""
    found = _CLASSES.get(cls)
    if found is not None:
        return found
    from ._http import JOURNALING

    base_copy = cls.copy  # type: ignore[attr-defined]
    openai = cls.__module__.split(".")[0] == "openai"

    def copy(self: Any, *args: Any, **kwargs: Any) -> Any:
        http_client = kwargs.get("http_client")
        if http_client is not None and not isinstance(http_client, JOURNALING):
            kwargs["http_client"] = self._client.rebound(http_client)
        if openai and kwargs.get("websocket_base_url") is None:
            kwargs["websocket_base_url"] = self.__dict__.get(_WS_ATTR) or _WS_PLACEHOLDER
        new = base_copy(self, *args, **kwargs)
        new._client.binding.allow(new.base_url)
        return new

    copy.__doc__ = base_copy.__doc__
    namespace: Dict[str, Any] = {
        "__module__": cls.__module__,
        "__qualname__": cls.__qualname__,
        "__doc__": cls.__doc__,
        "__pragmatic_journaled__": True,
        "copy": copy,
        "with_options": copy,
    }
    if openai:
        namespace["websocket_base_url"] = property(_ws_get, _ws_set)
    sub = type(cls.__name__, (cls,), namespace)
    _CLASSES[cls] = sub
    return sub


def wrap(client: Any, *, outside: str = "error", http: Optional["AttemptHttp"] = None) -> Any:
    """A journaled copy of an Anthropic or OpenAI SDK client: bound to the
    attempt ``http`` (``ctx.wrap``), or following the caller's attempt
    (``pragmatic.wrap``). See ``pragmatic.wrap``."""
    if outside not in OUTSIDE:
        raise ValueError(f"outside must be 'error' or 'passthrough', not {outside!r}")
    provider = provider_of(client)
    import httpx2

    from ._http import JOURNALING, AsyncJournalingHttpClient, Binding, JournalingHttpClient

    inner = getattr(client, "_client", None)
    if isinstance(inner, JOURNALING):
        inner = inner._inner
    if isinstance(inner, httpx2.AsyncClient):
        journaling: Any = AsyncJournalingHttpClient
    elif isinstance(inner, httpx2.Client):
        journaling = JournalingHttpClient
    else:
        raise Unsupported(
            f"this {provider} client sends through a {type(inner).__module__}."
            f"{type(inner).__qualname__}; pragmatic journals clients built on httpx2: pass "
            "http_client=httpx2.Client() (or httpx2.AsyncClient()), or none"
        )
    binding = Binding(http, outside, provider)
    journaled = client.copy(http_client=journaling(inner, binding))
    if not getattr(journaled, "__pragmatic_journaled__", False):
        websocket = journaled.__dict__.pop("websocket_base_url", None)
        journaled.__class__ = _journaled_class(type(journaled))
        if provider == "openai":
            journaled.__dict__[_WS_ATTR] = websocket
    binding.allow(journaled.base_url)
    return journaled
