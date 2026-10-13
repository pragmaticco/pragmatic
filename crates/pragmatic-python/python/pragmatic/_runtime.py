"""The Python-facing runtime and durable context."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional

from . import _native
from ._clients import JournaledClient, wrap as _wrap
from ._codec import canonical, to_jsonable
from ._tools import arun_tools as _arun_tools, run_tools as _run_tools

Agent = Callable[["Ctx"], Any]

_PROGRAM_ATTR = "__pragmatic_program__"


def durable(fn: Agent) -> Agent:
    """Journal the agent's identity (name + source hash) as the run's first
    step. A run recorded under one version of the agent then refuses to
    replay under another, failing with ``JournalDesync`` at cursor 0 instead
    of diverging silently."""
    try:
        source = inspect.getsource(fn)
    except (OSError, TypeError) as e:
        raise TypeError(
            f"@durable needs the source of {fn.__qualname__} (it cannot be defined "
            "in a REPL or generated at runtime)"
        ) from e
    digest = hashlib.sha256(source.encode()).hexdigest()
    setattr(fn, _PROGRAM_ATTR, (f"{fn.__module__}.{fn.__qualname__}", digest))
    return fn


class Ctx:
    """The durable execution context handed to your agent.

    Every method that touches the outside world is journaled: recorded on
    the first run, read back on ``resume`` and ``replay``. Journaled steps
    must happen one at a time; await them sequentially rather than with
    ``asyncio.gather``.
    """

    __slots__ = ("_native",)

    def __init__(self, native: "_native.Ctx"):
        self._native = native

    # -- model calls ------------------------------------------------------

    def wrap(self, client: Any) -> JournaledClient:
        """Return ``client`` (an Anthropic or OpenAI SDK client, sync or
        async) with its model calls journaled. Use the result exactly like
        the original client."""
        return _wrap(client, self)

    def draw(self, prompt: str, sample: Callable[[], str], *, provenance: str = "python") -> str:
        """Journal one model call made by ``sample()``. ``prompt`` must
        identify the request completely; ``sample`` runs only when the
        outcome is not already in the journal."""
        recorded = self._native.draw_replay(prompt)
        if recorded is not None:
            return recorded
        try:
            outcome = sample()
        except BaseException:
            self._native.draw_abort()
            raise
        if not isinstance(outcome, str):
            self._native.draw_abort()
            raise TypeError("draw's sample() must return str")
        return self._native.draw_commit(prompt, outcome, provenance)

    async def adraw(
        self, prompt: str, sample: Callable[[], Awaitable[str]], *, provenance: str = "python"
    ) -> str:
        """``draw`` for an async model call."""
        recorded = self._native.draw_replay(prompt)
        if recorded is not None:
            return recorded
        try:
            outcome = await sample()
        except BaseException:
            self._native.draw_abort()
            raise
        if not isinstance(outcome, str):
            self._native.draw_abort()
            raise TypeError("adraw's sample() must return str")
        return self._native.draw_commit(prompt, outcome, provenance)

    def oracle(self, prompt: str) -> str:
        """One call to the runtime's default oracle (``Runtime(dir, oracle)``)."""
        return self._native.oracle(prompt)

    # -- tools and effects ------------------------------------------------

    def run_tools(self, response: Any, tools: Mapping[str, Callable]) -> list:
        """Perform every tool call in a model response as a journaled effect
        and return the messages to append to the conversation."""
        return _run_tools(self, response, tools)

    async def arun_tools(self, response: Any, tools: Mapping[str, Callable]) -> list:
        """``run_tools`` for async (or mixed) tool functions."""
        return await _arun_tools(self, response, tools)

    def tool(self, name: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """Call ``fn(*args, **kwargs)`` as a journaled effect named ``name``.
        Arguments and the result must be JSON-serializable; the returned
        value is the JSON round-trip of the result, identical on replay."""
        arg = canonical({"args": list(args), "kwargs": kwargs})
        stored = self.effect(name, arg, lambda _a: canonical(fn(*args, **kwargs)))
        return json.loads(stored)

    async def atool(self, name: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """``tool`` for an async function."""

        async def perform(_a: str) -> str:
            out = fn(*args, **kwargs)
            if inspect.isawaitable(out):
                out = await out
            return canonical(out)

        arg = canonical({"args": list(args), "kwargs": kwargs})
        return json.loads(await self.aeffect(name, arg, perform))

    def effect(self, name: str, arg: str, perform: Callable[[str], str]) -> str:
        """A durable effect under the write-ahead discipline: the intent is
        journaled before ``perform(arg)`` runs and the result after. Replay
        returns the recorded result without calling ``perform``."""
        return self._native.effect(name, arg, perform)

    async def aeffect(self, name: str, arg: str, perform: Callable[[str], Awaitable[str]]) -> str:
        """``effect`` for an async ``perform``."""
        recorded = self._native.effect_replay(name, arg)
        if recorded is not None:
            return recorded
        self._native.effect_begin(name, arg)
        # A failure here leaves the intent dangling on purpose: resume's
        # recovery policy decides whether the world saw the effect.
        result = await perform(arg)
        if not isinstance(result, str):
            raise TypeError("aeffect's perform must return str")
        return self._native.effect_commit(name, result)

    # -- other journaled inputs ------------------------------------------

    def recv(self, channel: str) -> str:
        """Receive a value sent with ``Runtime.send`` (journaled)."""
        return self._native.recv(channel)

    def now(self) -> int:
        """A journaled clock read, in nanoseconds since the epoch."""
        return self._native.now()

    def contract(self, holds: bool, msg: str) -> None:
        """Assert an agent contract; a falsified contract raises."""
        self._native.contract(holds, msg)

    @property
    def is_replaying(self) -> bool:
        """True while steps are served from the journal. For logging only;
        agent logic must not branch on it."""
        return self._native.is_replaying()


def _encode_output(value: Any) -> str:
    if isinstance(value, str):
        return value
    return canonical(to_jsonable(value))


def _adapt(agent: Agent) -> Callable[["_native.Ctx"], str]:
    program = getattr(agent, _PROGRAM_ATTR, None)

    def call(native_ctx: "_native.Ctx") -> str:
        ctx = Ctx(native_ctx)
        if program is not None:
            native_ctx.program_marker(*program)
        result = agent(ctx)
        if inspect.isawaitable(result):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                if inspect.iscoroutine(result):
                    result.close()
                raise RuntimeError(
                    "an async agent cannot be driven from inside a running event loop; "
                    "call rt.run from a worker thread (e.g. asyncio.to_thread) or from "
                    "synchronous code"
                )

            async def main() -> Any:
                return await result

            result = asyncio.run(main())
        return _encode_output(result)

    return call


class Runtime:
    """Journals every step an agent takes under a stable run id, so the run
    survives any crash, resumes without re-paying for model calls, and
    replays exactly for audit.

    ``Runtime(dir, oracle=None, *, key=None)``: journals persist under
    ``dir``, one append-only hash-chained file per run. ``oracle`` is an
    optional default ``(str) -> str`` model for ``ctx.oracle``; agents that
    use ``ctx.wrap(client)`` do not need one. ``key`` (bytes) HMAC-signs the
    journals so the chain cannot be recomputed without it; it can also be
    supplied through the ``PRAGMATIC_JOURNAL_KEY`` environment variable.
    """

    def __init__(
        self,
        dir: "str | os.PathLike[str]",
        oracle: Optional[Callable[[str], str]] = None,
        *,
        key: Optional[bytes] = None,
    ):
        if key is None and os.environ.get("PRAGMATIC_JOURNAL_KEY"):
            key = os.environ["PRAGMATIC_JOURNAL_KEY"].encode()
        os.makedirs(dir, exist_ok=True)
        self._native = _native.Runtime(os.fspath(dir), oracle, key)

    def run(
        self,
        run_id: str,
        agent: Agent,
        *,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
    ) -> "_native.RunReport":
        """Start or continue a durable run. Re-enterable: an existing journal
        prefix is read back first, so retrying a run id is idempotent.

        ``budget`` caps model calls for this attempt; ``caps`` allowlists
        effect names (tool effects are named ``tool:<name>``)."""
        return self._native.run(
            run_id, _adapt(agent), budget, list(caps) if caps is not None else None
        )

    def resume(
        self,
        run_id: str,
        agent: Agent,
        *,
        recover: Optional[Callable[[str, str], Optional[str]]] = None,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
    ) -> "_native.RunReport":
        """Resume a crashed run: the journaled prefix is read back (zero
        model calls, no duplicate effects) and recording continues at the
        tail. ``recover(name, arg)`` settles effects that crashed mid-flight:
        return the result to mark one done, or None to perform it again
        (the default)."""
        return self._native.resume(
            run_id, _adapt(agent), recover, budget, list(caps) if caps is not None else None
        )

    def replay(self, run_id: str, agent: Agent) -> "_native.RunReport":
        """Replay a recorded run exactly, for debugging and audit. Nothing
        is sampled or performed; a run that never finished raises
        ``ReplayExhausted``."""
        return self._native.replay(run_id, _adapt(agent))

    def send(self, run_id: str, channel: str, value: str) -> None:
        """Deliver a value to a run's channel inbox."""
        self._native.send(run_id, channel, value)

    def verify(self, run_id: str) -> bool:
        """Walk the run's tamper-evident hash chain. True if intact."""
        return self._native.verify(run_id)
