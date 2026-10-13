"""Pragmatic: the system of record for AI agents.

Every model call, tool call, channel receive, random draw and clock read an
agent makes through Pragmatic is journaled to an append-only, hash-chained
log before its result reaches the agent. A crashed run resumes where it
stopped without re-paying for a single token or repeating a tool call, and
any run replays exactly for debugging and audit.

    import anthropic, pragmatic

    rt = pragmatic.Runtime("./journals")   # or a server: "https://..." with a token
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

Async agents use ``await rt.arun(...)`` and ``await ctx.gather(...)`` for
parallel branches.
"""

from ._native import RunReport, __version__
from ._clients import JournaledClient
from ._errors import (
    Conflict,
    DanglingEffect,
    DanglingIntent,
    Deleted,
    EffectUnrecorded,
    Erased,
    JournalDesync,
    LeaseLost,
    Locked,
    NotInRun,
    PragmaticError,
    ReplayExhausted,
    ServerError,
    TooLarge,
    Unavailable,
    Unsupported,
)
from ._failures import DrawFailed, EffectFailed
from ._reports import RunSummary, VerifyReport
from ._runtime import Ctx, Recover, Runtime, durable
from ._server import ServerStore
from ._stores import JOURNAL_HEADER, DirStore, MemoryStore, Store
from ._tools import ToolCall, tool_calls

__all__ = [
    "JOURNAL_HEADER",
    "Conflict",
    "Ctx",
    "DanglingEffect",
    "DanglingIntent",
    "Deleted",
    "DirStore",
    "DrawFailed",
    "EffectFailed",
    "EffectUnrecorded",
    "Erased",
    "JournalDesync",
    "JournaledClient",
    "LeaseLost",
    "Locked",
    "MemoryStore",
    "NotInRun",
    "PragmaticError",
    "Recover",
    "ReplayExhausted",
    "RunReport",
    "RunSummary",
    "Runtime",
    "ServerError",
    "ServerStore",
    "Store",
    "TooLarge",
    "ToolCall",
    "Unavailable",
    "Unsupported",
    "VerifyReport",
    "__version__",
    "durable",
    "tool_calls",
]
