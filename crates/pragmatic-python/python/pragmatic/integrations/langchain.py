"""Journaled LangChain chat models (spec 6.5).

``journal(llm)`` returns a copy of a LangChain ``ChatAnthropic`` or
``ChatOpenAI`` (or ``AzureChatOpenAI``) whose SDK clients are journaled
with ``pragmatic.wrap``, so every model call it makes (``invoke``,
``stream``, their async forms, structured output, tool calling, and the
calls of a LangGraph agent built on it) is recorded in the durable run that
makes it, and replayed from the journal on resume and replay::

    from langchain_anthropic import ChatAnthropic
    from pragmatic.integrations.langchain import journal

    llm = journal(ChatAnthropic(model="claude-sonnet-5-5"))

    def agent(ctx):
        return llm.invoke("Summarize the incident report.").content

    rt.run("summary-7", agent)

Build it once and use it from any run: the copy follows the run that calls
it. ``outside`` is as for ``pragmatic.wrap``. The original model is left
as it was.

``ChatAnthropic`` builds its Anthropic clients itself and offers no way to
pass one in, so its clients are replaced on the copy (they are cached
properties named ``_client`` and ``_async_client``); ``ChatOpenAI`` takes
its clients as fields.
"""

from __future__ import annotations

from typing import Any

from .._clients import wrap

__all__ = ["journal"]


def _is(llm: Any, module: str, name: str) -> bool:
    return any(c.__module__.startswith(module) and c.__name__ == name for c in type(llm).__mro__)


def journal(llm: Any, *, outside: str = "error") -> Any:
    """A copy of ``llm`` whose model calls are journaled. See the module
    documentation."""
    if _is(llm, "langchain_anthropic", "ChatAnthropic"):
        copy = llm.model_copy()
        copy.__dict__["_client"] = wrap(llm._client, outside=outside)
        copy.__dict__["_async_client"] = wrap(llm._async_client, outside=outside)
        return copy
    if _is(llm, "langchain_openai", "BaseChatOpenAI"):
        update = {}
        if llm.root_client is not None:
            root = wrap(llm.root_client, outside=outside)
            update.update(root_client=root, client=root.chat.completions)
        if llm.root_async_client is not None:
            root_async = wrap(llm.root_async_client, outside=outside)
            update.update(root_async_client=root_async, async_client=root_async.chat.completions)
        if not update:
            raise TypeError(f"{type(llm).__name__} has no SDK client to journal")
        return llm.model_copy(update=update)
    raise TypeError(
        "journal() takes a LangChain ChatAnthropic or ChatOpenAI model; got "
        f"{type(llm).__module__}.{type(llm).__qualname__}. For a framework that accepts an SDK "
        "client, pass it pragmatic.wrap(client)."
    )
