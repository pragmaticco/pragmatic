"""Pragmatic: the black-box recorder for LLM agents.

Every model call and tool call your agent makes is journaled to an
append-only, hash-chained log. A crashed run resumes where it stopped
without re-paying for a single token, and any run replays exactly for
debugging and audit.

    import anthropic, pragmatic

    rt = pragmatic.Runtime("./journals")
    tools = {"search": search}

    def agent(ctx):
        client = ctx.wrap(anthropic.Anthropic())      # journaled model calls
        messages = [{"role": "user", "content": "Find papers on durable execution."}]
        while True:
            msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=1024,
                                         tools=TOOLS, messages=messages)
            messages.append({"role": "assistant", "content": msg.content})
            if msg.stop_reason != "tool_use":
                return msg.content[0].text
            messages += ctx.run_tools(msg, tools)     # journaled tool calls

    rt.run("research-42", agent)       # record
    rt.resume("research-42", agent)    # after a crash: no repeated calls
    rt.replay("research-42", agent)    # audit: nothing is called at all
"""

from ._native import (
    JournalDesync,
    PragmaticError,
    ReplayExhausted,
    RunReport,
    __version__,
)
from ._clients import JournaledClient
from ._failures import DrawFailed, EffectFailed
from ._runtime import Ctx, Runtime, durable
from ._tools import ToolCall, tool_calls

__all__ = [
    "Ctx",
    "DrawFailed",
    "EffectFailed",
    "JournalDesync",
    "JournaledClient",
    "PragmaticError",
    "ReplayExhausted",
    "RunReport",
    "Runtime",
    "ToolCall",
    "__version__",
    "durable",
    "tool_calls",
]
