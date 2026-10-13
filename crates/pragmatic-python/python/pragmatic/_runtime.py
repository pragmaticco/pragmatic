"""The runtime, its attempts and the durable context (spec 6.1, 6.2, 6.4,
6.7).

An *attempt* is one ``run``, ``resume`` or ``replay`` of one run. It is
owned by the thread that runs it (synchronous attempts) or by the task
that awaits ``arun`` plus the children ``ctx.gather`` creates (async
attempts). Every journaled step checks ownership before it touches
anything, and finds its branch in a context variable, so the children of
``ctx.gather`` (and threads started with ``asyncio.to_thread``, which copy
the variable) record on the right branch.

A step's value reaches the agent only once the journal entries holding it
are durable. A synchronous attempt persists inline. An async attempt
persists on a dedicated single-thread executor, so its event loop never
waits on storage: begin (the checkout), every persist and finish (the
checkin) run there, in order, and at most one persist is in flight. The
synchronous steps (``ctx.now()`` and friends) wait for that executor too
when they are called from an async agent, which stalls the loop for one
persist; their values are released only once durable all the same.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as _dt
import functools
import hashlib
import inspect
import json
import os
import uuid as _uuid
import warnings
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from . import _native, _otel
from ._clients import JournaledClient, wrap as _wrap
from ._codec import canonical, to_jsonable
from ._diff import request_diff
from ._errors import JournalDesync, PragmaticError, ServerError
from ._failures import replayed as _replayed_failure, type_name as _type_name
from ._reports import Entry, RunSummary, VerifyReport
from ._server import ServerStore, check_url, is_server_url
from ._stores import DirStore, MemoryStore, native_store
from ._tools import accepts_key as _accepts_key, arun_tools as _arun_tools, run_tools as _run_tools

Agent = Callable[["Ctx"], Any]

CURRENT = _native.CURRENT
"""The context variable holding ``(attempt token, branch)``."""

_PROGRAM_ATTR = "__pragmatic_program__"
_META_OK = '{"outcome":"ok"}'


def _error_meta(type_name: str) -> str:
    return json.dumps({"error_type": type_name, "outcome": "error"}, sort_keys=True, separators=(",", ":"))


def _text(value: Union[str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"expected str or bytes, got {type(value).__name__}")


def _decode(value: bytes) -> str:
    return value.decode("utf-8", "replace")


def _close(value: Any) -> None:
    if inspect.iscoroutine(value):
        value.close()


# ---------------------------------------------------------------------------
# Durability drivers
# ---------------------------------------------------------------------------


class _SyncDriver:
    """Persists inline, on the thread that steps (synchronous attempts)."""

    __slots__ = ("att",)

    def __init__(self, att: Any):
        self.att = att

    def durable(self, upto: Optional[int]) -> None:
        if upto is not None:
            self.att.persist(upto)

    async def adurable(self, upto: Optional[int]) -> None:
        self.durable(upto)


class _AsyncDriver:
    """Persists on the attempt's single-thread executor (async attempts)."""

    __slots__ = ("att", "executor")

    def __init__(self, att: Any, executor: concurrent.futures.Executor):
        self.att = att
        self.executor = executor

    def durable(self, upto: Optional[int]) -> None:
        if upto is not None:
            self.executor.submit(self.att.persist, upto).result()

    async def adurable(self, upto: Optional[int]) -> None:
        if upto is not None:
            await asyncio.wrap_future(self.executor.submit(self.att.persist, upto))


# ---------------------------------------------------------------------------
# Recovery policies
# ---------------------------------------------------------------------------


class Recover:
    """A recovery decision for an effect a crash left without a result
    (spec 2.12), returned by a ``recover`` policy:

    - ``Recover.commit(result)``: the effect happened (the world was
      checked); record ``result``. A plain ``str`` or ``bytes`` return means
      the same.
    - ``Recover.COMPENSATE``: write it off; the resumed run performs it again
      under a new intent. ``None`` means the same.
    - ``Recover.FAIL``: record it as failed, so the agent sees the failure.
    """

    __slots__ = ("kind", "result")

    COMPENSATE: "Recover"
    FAIL: "Recover"

    def __init__(self, kind: str, result: Optional[bytes] = None):
        self.kind = kind
        self.result = result

    @classmethod
    def commit(cls, result: Union[str, bytes]) -> "Recover":
        return cls("commit", _text(result))

    def _decision(self) -> Tuple[Any, ...]:
        if self.kind == "commit":
            return ("commit", self.result)
        return (self.kind,)

    def __repr__(self) -> str:
        return f"Recover.{self.kind}"


Recover.COMPENSATE = Recover("compensate")
Recover.FAIL = Recover("fail")


def _decision(out: Any) -> Tuple[Any, ...]:
    if out is None:
        return ("compensate",)
    if isinstance(out, Recover):
        return out._decision()
    if isinstance(out, (str, bytes, bytearray)):
        return ("commit", _text(out))
    raise TypeError(
        "recover must return a str or bytes result to commit, None to compensate, or a "
        f"pragmatic.Recover; got {type(out).__name__}"
    )


def _policy_arity(recover: Callable) -> int:
    try:
        params = list(inspect.signature(recover).parameters.values())
    except (TypeError, ValueError):
        return 4
    if any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params):
        return 4
    positional = [
        p
        for p in params
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 4:
        return 4
    if len(positional) >= 2:
        return 2
    raise TypeError("recover takes (name, arg) or (name, arg, branch, intent_cursor)")


async def _as_coroutine(awaitable: Awaitable) -> Any:
    return await awaitable


def _normalize_policy(
    recover: Optional[Callable], loop: Optional[asyncio.AbstractEventLoop]
) -> Optional[Callable]:
    """The native layer's view of ``recover``: called with ``(name, arg,
    branch, intent, at_frontier)`` and returning a decision tuple. ``arg``
    reaches the policy as ``str`` when it is UTF-8 text. An async policy
    runs on ``loop`` (``aresume``) while the begin it decides for waits on
    the attempt's executor thread."""
    if recover is None:
        return None
    arity = _policy_arity(recover)

    def policy(
        name: str, arg: bytes, branch: Tuple[int, ...], intent: int, at_frontier: bool
    ) -> Tuple[Any, ...]:
        try:
            value: Union[str, bytes] = arg.decode("utf-8")
        except UnicodeDecodeError:
            value = arg
        out = recover(name, value) if arity == 2 else recover(name, value, tuple(branch), intent)
        if inspect.isawaitable(out):
            if loop is None:
                _close(out)
                raise TypeError(
                    "recover returned an awaitable: async recovery policies need "
                    "`await rt.aresume(...)`"
                )
            out = asyncio.run_coroutine_threadsafe(_as_coroutine(out), loop).result()
        return _decision(out)

    return policy


# ---------------------------------------------------------------------------
# Program identity
# ---------------------------------------------------------------------------


def _unwrap(fn: Any) -> Any:
    while isinstance(fn, functools.partial):
        fn = fn.func
    return fn


def _source_identity(fn: Any) -> Tuple[str, str]:
    source = inspect.getsource(fn)
    name = f"{fn.__module__}.{fn.__qualname__}"
    return name, hashlib.sha256(source.encode()).hexdigest()


def _program_identity(agent: Any) -> Optional[Tuple[str, str]]:
    """The agent's ``(name, hash)`` for ``attempt.start``: what ``durable``
    recorded, else the source hash when the source is available. It is
    information only and never makes replay stricter (spec 2.11)."""
    found = getattr(agent, _PROGRAM_ATTR, None)
    if found is not None:
        return found
    try:
        return _source_identity(_unwrap(agent))
    except (OSError, TypeError, AttributeError):
        return None


def _find_ctx(args: Sequence[Any], kwargs: Mapping[str, Any]) -> "Ctx":
    for value in list(args) + list(kwargs.values()):
        if isinstance(value, Ctx):
            return value
    raise TypeError("a @durable function takes the ctx among its arguments")


def durable(fn: Optional[Agent] = None, *, version: Optional[str] = None) -> Any:
    """Journal a program's identity on the branch that calls it (spec 2.10).

    ``@durable`` records ``Program{name, hash}`` with the hash of the
    function's source; ``@durable(version="2")`` records the explicit
    version instead, so edits that do not change behavior need not count as
    a change. Replay refuses a changed program by default; pass
    ``on_code_change="continue"`` to replay or resume recorded runs under
    changed code. The function must take the ``ctx`` among its arguments,
    and may be sync or async.
    """
    if fn is None:
        return lambda f: durable(f, version=version)
    if version is not None:
        identity = (f"{fn.__module__}.{fn.__qualname__}", str(version))
    else:
        try:
            identity = _source_identity(fn)
        except (OSError, TypeError) as e:
            raise TypeError(
                f"@durable needs the source of {fn.__qualname__} (it cannot be defined in a REPL "
                "or generated at runtime); pass @durable(version=...) instead"
            ) from e
    name, digest = identity

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def awrapper(*args: Any, **kwargs: Any) -> Any:
            await _find_ctx(args, kwargs)._aprogram_marker(name, digest)
            return await fn(*args, **kwargs)

        wrapper: Any = awrapper
    else:

        @functools.wraps(fn)
        def swrapper(*args: Any, **kwargs: Any) -> Any:
            _find_ctx(args, kwargs)._program_marker(name, digest)
            return fn(*args, **kwargs)

        wrapper = swrapper
    setattr(wrapper, _PROGRAM_ATTR, identity)
    return wrapper


# ---------------------------------------------------------------------------
# The durable context
# ---------------------------------------------------------------------------


class Ctx:
    """The durable execution context handed to your agent.

    Every method that touches the outside world is journaled: recorded on
    the first run, read back on ``resume`` and ``replay``. A step's value is
    returned only once it is durable.

    One ``Ctx`` serves the whole attempt. Each step runs on the branch the
    calling code is on: the root for the agent itself, a child branch inside
    ``ctx.gather``. Steps from tasks created with ``asyncio.create_task`` or
    ``asyncio.gather``, or from threads started with ``loop.run_in_executor``
    or ``threading.Thread``, are refused with ``NotInRun``; use
    ``ctx.gather`` or ``asyncio.to_thread``.
    """

    __slots__ = ("_att", "_io", "_rt")

    def __init__(self, attempt: Any, driver: Any, runtime: "Runtime"):
        self._att = attempt
        self._io = driver
        self._rt = runtime

    @property
    def run_id(self) -> str:
        return self._att.run_id

    @property
    def branch(self) -> Tuple[int, ...]:
        """The branch the calling code steps on (the root is ``()``)."""
        return tuple(self._att.branch())

    @property
    def is_replaying(self) -> bool:
        """True while this branch's steps are served from the journal. For
        logging only: agent logic must not depend on it."""
        return self._att.is_replaying()

    def _span_branch(self) -> Tuple[int, ...]:
        return self.branch if _otel.enabled() else ()

    # -- model calls ------------------------------------------------------

    def wrap(self, client: Any) -> JournaledClient:
        """Return ``client`` (an Anthropic or OpenAI SDK client, sync or
        async) with its model calls journaled. Use the result exactly like
        the original client."""
        return _wrap(client, self)

    def _draw_begin(self, parts: List[bytes], provenance: str) -> Tuple[Any, ...]:
        try:
            return self._att.draw_begin(parts, provenance)
        except JournalDesync as e:
            raise self._with_diff(e, parts) from None

    def _with_diff(self, e: JournalDesync, parts: List[bytes]) -> JournalDesync:
        """The desync with the first differing JSON paths of the request."""
        if e.cursor is None:
            return e
        try:
            recorded = self._att.recorded_parts(e.cursor)
        except PragmaticError:
            recorded = None
        if not recorded:
            return e
        diff = request_diff(recorded, parts)
        if not diff:
            return e
        out = JournalDesync(
            str(e) + "\n  " + "\n  ".join(diff),
            cursor=e.cursor,
            expected=e.expected,
            found=e.found,
            diff=diff,
        )
        out._pragmatic_fault = e._pragmatic_fault
        return out

    @staticmethod
    def _replayed_body(start: Tuple[Any, ...]) -> bytes:
        _, _intent, _head, body, meta = start
        try:
            doc = json.loads(meta)
        except ValueError:
            doc = {}
        if doc.get("outcome") == "error":
            raise _replayed_failure("draw", doc.get("error_type") or "", _decode(body))
        return body

    def _fail_draw(self, intent: int, exc: BaseException) -> Optional[int]:
        return self._att.draw_end(intent, _error_meta(_type_name(exc)), b"", str(exc).encode())

    def draw(self, prompt: str, sample: Callable[[], str], *, provenance: str = "python") -> str:
        """Journal one model call made by ``sample()``. ``prompt`` must
        identify the request completely; ``sample`` runs only when the
        outcome is not already in the journal.

        A ``sample()`` that raises is recorded too (the exception's type and
        message), so an agent that catches the exception replays the same
        way: replay raises ``DrawFailed``, which is also an instance of the
        original exception type."""
        with _otel.draw(self.run_id, self._span_branch(), provenance) as span:
            start = self._draw_begin([_text(prompt)], provenance)
            if start[0] == "replayed":
                span.set(cursor=start[1], replayed=True, input_tokens=0, output_tokens=0)
                return _decode(self._replayed_body(start))
            _, intent, upto = start
            span.set(cursor=intent, replayed=False)
            self._io.durable(upto)
            try:
                outcome = sample()
                if inspect.isawaitable(outcome):
                    _close(outcome)
                    raise TypeError("draw's sample() is async; use await ctx.adraw(...)")
                if not isinstance(outcome, str):
                    raise TypeError("draw's sample() must return str")
            except Exception as e:
                self._io.durable(self._fail_draw(intent, e))
                raise
            self._io.durable(self._att.draw_end(intent, _META_OK, b"", outcome.encode()))
            return outcome

    async def adraw(
        self, prompt: str, sample: Callable[[], Awaitable[str]], *, provenance: str = "python"
    ) -> str:
        """``draw`` for an async model call."""
        with _otel.draw(self.run_id, self._span_branch(), provenance) as span:
            start = self._draw_begin([_text(prompt)], provenance)
            if start[0] == "replayed":
                span.set(cursor=start[1], replayed=True, input_tokens=0, output_tokens=0)
                return _decode(self._replayed_body(start))
            _, intent, upto = start
            span.set(cursor=intent, replayed=False)
            await self._io.adurable(upto)
            try:
                outcome = await sample()
                if not isinstance(outcome, str):
                    raise TypeError("adraw's sample() must return str")
            except Exception as e:
                await self._io.adurable(self._fail_draw(intent, e))
                raise
            await self._io.adurable(self._att.draw_end(intent, _META_OK, b"", outcome.encode()))
            return outcome

    def oracle(self, prompt: str) -> str:
        """One call to the runtime's default oracle (``Runtime(store,
        oracle)``), journaled as a draw."""
        oracle = self._rt._oracle
        if oracle is None:
            raise PragmaticError(
                "ctx.oracle needs a default oracle: pass one to Runtime(store, oracle), or make "
                "model calls through ctx.wrap(client)"
            )
        name = getattr(oracle, "__name__", None) or type(oracle).__name__
        return self.draw(prompt, lambda: oracle(prompt), provenance=f"python:{name}")

    # -- tools and effects ------------------------------------------------

    def _fail_effect(self, intent: int, exc: BaseException) -> Optional[int]:
        return self._att.effect_end(intent, failure=(_type_name(exc), str(exc)))

    def _effect_start(self, name: str, arg: Union[str, bytes]) -> Tuple[Any, ...]:
        start = self._att.effect_begin(name, _text(arg))
        if start[0] == "failed":
            raise _replayed_failure("effect", start[1], start[2])
        return start

    def effect(self, name: str, arg: str, perform: Callable[..., str]) -> str:
        """A durable effect under the write-ahead discipline: the intent is
        durable before ``perform(arg)`` runs, and the result is recorded
        after. Replay returns the recorded result without calling
        ``perform``. A ``perform`` that takes an ``idempotency_key`` argument
        gets ``"<run_id>/<branch>/<intent cursor>"``, the same whenever this
        intent is performed, so a downstream service can deduplicate a retry.

        A ``perform`` that raises is recorded too (the exception's type and
        message) and its exception propagates; replay raises
        ``EffectFailed``, which is also an instance of the original
        exception type, so the agent's ``except`` clause behaves the same."""
        with _otel.effect(self.run_id, self._span_branch(), name) as span:
            start = self._effect_start(name, arg)
            if start[0] == "replayed":
                span.set(replayed=True)
                return _decode(start[1])
            _, intent, key, upto = start
            span.set(cursor=intent, replayed=False)
            self._io.durable(upto)
            try:
                result = perform(arg, idempotency_key=key) if _accepts_key(perform) else perform(arg)
                if inspect.isawaitable(result):
                    _close(result)
                    raise TypeError(
                        f"the perform of effect {name!r} is async; use await ctx.aeffect(...)"
                    )
                if not isinstance(result, str):
                    raise TypeError(f"the perform of effect {name!r} must return str")
            except Exception as e:
                self._io.durable(self._fail_effect(intent, e))
                raise
            self._commit(name, intent, result)
            return result

    def _commit(self, name: str, intent: int, result: str) -> None:
        data = result.encode()
        upto = self._att.effect_end(intent, data)
        try:
            self._io.durable(upto)
        except Exception as e:  # whatever the store raised
            raise _native.effect_unrecorded(name, intent, data) from e

    async def _acommit(self, name: str, intent: int, result: str) -> None:
        data = result.encode()
        upto = self._att.effect_end(intent, data)
        try:
            await self._io.adurable(upto)
        except Exception as e:  # whatever the store raised
            raise _native.effect_unrecorded(name, intent, data) from e

    async def aeffect(self, name: str, arg: str, perform: Callable[..., Any]) -> str:
        """``effect`` for an async (or sync) ``perform``."""
        with _otel.effect(self.run_id, self._span_branch(), name) as span:
            start = self._effect_start(name, arg)
            if start[0] == "replayed":
                span.set(replayed=True)
                return _decode(start[1])
            _, intent, key, upto = start
            span.set(cursor=intent, replayed=False)
            await self._io.adurable(upto)
            # A cancelled perform leaves the intent open on purpose: resume's
            # recovery policy decides whether the world saw the effect.
            try:
                result = perform(arg, idempotency_key=key) if _accepts_key(perform) else perform(arg)
                if inspect.isawaitable(result):
                    result = await result
                if not isinstance(result, str):
                    raise TypeError(f"the perform of effect {name!r} must return str")
            except Exception as e:
                await self._io.adurable(self._fail_effect(intent, e))
                raise
            await self._acommit(name, intent, result)
            return result

    def tool(self, name: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """Call ``fn(*args, **kwargs)`` as a journaled effect named ``name``.
        Arguments and the result must be JSON-serializable; the returned
        value is the JSON round trip of the result, identical on replay.
        ``fn`` gets ``idempotency_key=`` when it takes one."""
        arg = canonical({"args": list(args), "kwargs": kwargs})
        keyed = _accepts_key(fn)

        def perform(_arg: str, idempotency_key: str = "") -> str:
            out = fn(*args, idempotency_key=idempotency_key, **kwargs) if keyed else fn(*args, **kwargs)
            if inspect.isawaitable(out):
                _close(out)
                raise TypeError(f"tool {name!r} is async; use await ctx.atool(...)")
            return canonical(out)

        return json.loads(self.effect(name, arg, perform))

    async def atool(self, name: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """``tool`` for an async (or sync) function."""
        arg = canonical({"args": list(args), "kwargs": kwargs})
        keyed = _accepts_key(fn)

        async def perform(_arg: str, idempotency_key: str = "") -> str:
            out = fn(*args, idempotency_key=idempotency_key, **kwargs) if keyed else fn(*args, **kwargs)
            if inspect.isawaitable(out):
                out = await out
            return canonical(out)

        return json.loads(await self.aeffect(name, arg, perform))

    def run_tools(self, response: Any, tools: Mapping[str, Callable]) -> list:
        """Perform every tool call in a model response as a journaled effect
        and return the messages to append to the conversation."""
        return _run_tools(self, response, tools)

    async def arun_tools(self, response: Any, tools: Mapping[str, Callable]) -> list:
        """``run_tools`` for async (or mixed) tool functions."""
        return await _arun_tools(self, response, tools)

    # -- other journaled inputs ------------------------------------------

    def recv(self, channel: str) -> str:
        """Receive a value sent with ``Runtime.send`` (journaled). An empty
        inbox raises ``PragmaticError`` (a timeout), which replays too once
        the agent carries on past it."""
        value, upto = self._att.recv(channel)
        self._io.durable(upto)
        return _decode(value)

    def now(self) -> int:
        """A journaled clock read, in nanoseconds since the Unix epoch."""
        nanos, upto = self._att.now()
        self._io.durable(upto)
        return nanos

    def datetime(self) -> _dt.datetime:
        """A journaled clock read as an aware UTC ``datetime`` (one Clock
        entry, microsecond precision)."""
        nanos = self.now()
        epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
        return epoch + _dt.timedelta(microseconds=nanos // 1000)

    def _random(self, source: str, args: str) -> bytes:
        value, upto = self._att.random(source, args)
        self._io.durable(upto)
        return value

    def uuid4(self) -> _uuid.UUID:
        """A journaled random UUID (version 4)."""
        return _uuid.UUID(self._random("uuid4", "[]").decode("ascii"))

    def random(self) -> float:
        """A journaled random float in [0, 1)."""
        return float(self._random("random", "[]").decode("ascii"))

    def randint(self, a: int, b: int) -> int:
        """A journaled random integer N with ``a <= N <= b`` (64-bit
        bounds)."""
        for v in (a, b):
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError("randint takes two ints")
            if not -(2**63) <= v < 2**63:
                raise ValueError("randint bounds must fit in 64 bits")
        if a > b:
            raise ValueError(f"empty range for randint({a}, {b})")
        return int(self._random("randint", f"[{a},{b}]").decode("ascii"))

    def randbytes(self, n: int) -> bytes:
        """``n`` journaled random bytes from the operating system's CSPRNG."""
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValueError("randbytes takes a non-negative int")
        return self._random("bytes", f"[{n}]")

    def patched(self, name: str) -> bool:
        """True if this run takes the code patch ``name`` (spec 2.9): runs
        recorded before the patch keep their old path, new runs take the new
        one."""
        taken, upto = self._att.patched(name)
        self._io.durable(upto)
        return taken

    def deprecate_patch(self, name: str) -> None:
        """Consume the marker of patch ``name`` if this run took it; never
        records one. Replaces ``patched`` once no run without the patch can
        still resume."""
        self._att.deprecate_patch(name)

    def contract(self, holds: bool, msg: str) -> None:
        """Assert an agent contract; a falsified contract raises."""
        if not holds:
            raise _native.fault_exception("ContractViol", msg)

    def _program_marker(self, name: str, digest: str) -> None:
        self._io.durable(self._att.program_marker(name, digest))

    async def _aprogram_marker(self, name: str, digest: str) -> None:
        await self._io.adurable(self._att.program_marker(name, digest))

    # -- parallel regions -------------------------------------------------

    async def gather(self, *fns: Callable[["Ctx"], Any]) -> list:
        """Run ``fns`` concurrently as a parallel region (spec 2.7), each on
        its own child branch, and return their results in order.

        Each ``fn`` is called with this same ``ctx`` and may return a value
        or an awaitable: ``await ctx.gather(lambda c: research(c, "a"),
        lambda c: research(c, "b"))``. Every child runs to completion even
        when another fails, and if any failed the region raises the failure
        of the lowest-index failed child, never the first in time. Replay
        matches each child's branch on its own, so children that interleave
        differently on replay still replay exactly."""
        for fn in fns:
            if inspect.iscoroutine(fn) or not callable(fn):
                _close(fn)
                raise TypeError(
                    "ctx.gather takes callables that receive the ctx, such as "
                    "`lambda c: research(c, 'a')`, not coroutines"
                )
        if not fns:
            return []
        children, upto = self._att.fork(len(fns))
        await self._io.adurable(upto)
        loop = asyncio.get_running_loop()
        tasks = [loop.create_task(self._child(tuple(c), fn)) for c, fn in zip(children, fns)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok = [not isinstance(r, BaseException) for r in results]
        checks = self._att.join([list(c) for c in children], ok)
        for result, check in zip(results, checks):
            if isinstance(result, BaseException):
                raise result
            if check is not None:
                raise check
        return list(results)

    async def _child(self, branch: Tuple[int, ...], fn: Callable[["Ctx"], Any]) -> Any:
        CURRENT.set((self._att.token, branch))
        self._att.own_current_task()
        try:
            out = fn(self)
            if inspect.isawaitable(out):
                out = await out
            return out
        finally:
            self._att.disown_current_task()


# ---------------------------------------------------------------------------
# The runtime
# ---------------------------------------------------------------------------


def _encode_output(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return canonical(to_jsonable(value)).encode("utf-8")


def _is_async_agent(agent: Any) -> bool:
    fn = _unwrap(agent)
    if inspect.iscoroutinefunction(fn):
        return True
    if inspect.isfunction(fn) or inspect.ismethod(fn):
        return False
    return inspect.iscoroutinefunction(getattr(fn, "__call__", None))


def _running_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _agent_name(agent: Any) -> str:
    return getattr(_unwrap(agent), "__qualname__", None) or type(agent).__name__


def _end_failed(att: Any, exc: BaseException) -> None:
    """End an attempt whose agent raised. An exception that is not an
    ``Exception`` (an interrupt, a cancelled task, ``SystemExit``) is a
    crash: nothing more is journaled (spec 2.7, rule 7). Anything else is
    recorded in ``attempt.end``, with the runtime's own fault when the
    exception carries one. The agent's exception is what the caller sees,
    so a failure to end is not raised over it."""
    if not isinstance(exc, Exception):
        att.abandon()
        return
    handle = getattr(exc, "_pragmatic_fault", None)
    try:
        if handle is not None:
            att.finish("fault", handle)
        else:
            att.finish("error", f"{_type_name(exc)}: {exc}")
    except Exception:  # noqa: BLE001 - the agent's exception wins
        pass


async def _uncancellable(fut: "asyncio.Future[Any]") -> Tuple["asyncio.Future[Any]", bool]:
    """Wait for ``fut`` to finish even if this task is cancelled meanwhile
    (checkin is shielded from cancellation, spec 6.2). Returns the finished
    future and whether a cancellation arrived."""
    cancelled = False
    while True:
        try:
            await asyncio.shield(fut)
        except asyncio.CancelledError:
            cancelled = True
            if not fut.done():
                continue
        except BaseException:  # noqa: BLE001 - the caller reads fut's outcome
            pass
        return fut, cancelled


def _resolve_store(store: Any, token: Optional[str], timeout: float) -> Any:
    if isinstance(store, os.PathLike):
        store = os.fspath(store)
    if isinstance(store, str):
        if is_server_url(store):
            check_url(store)
            token = token or os.environ.get("PRAGMATIC_TOKEN")
            if not token:
                raise ValueError(
                    f"a server URL needs a token: pass token= or set PRAGMATIC_TOKEN ({store})"
                )
            return ServerStore(store, token, timeout=timeout)
        return DirStore(store)
    return store


class Runtime:
    """Journals every step an agent takes under a stable run id, so the run
    survives any crash, resumes without re-paying for model calls, and
    replays exactly for audit.

    ``Runtime(store=None, oracle=None, *, token=None, key=None,
    timeout=30.0, require_server=False, volatile=None)`` (spec 6.1):

    - ``store`` is a directory path, a server URL (``https://``, or
      ``http://`` to a loopback host), or a store object (``DirStore``,
      ``MemoryStore``, ``ServerStore`` or your own ``pragmatic.Store``).
      Without one, ``PRAGMATIC_URL`` is used; without that, ``ValueError``.
    - ``token`` (or ``PRAGMATIC_TOKEN``) authenticates to a server. The
      runtime checks the server eagerly (``GET /v1/info`` and
      ``/v1/whoami``) and raises a ``PragmaticError`` naming the URL and
      status if it is unreachable, refuses the token, or is incompatible.
    - ``key`` (bytes, or ``PRAGMATIC_JOURNAL_KEY``) HMAC-keys the hash chains
      of local journals. Server-stored runs are always unkeyed: an explicit
      ``key`` with a server is a ``ValueError`` and the variable is ignored
      with a warning.
    - ``require_server=True`` (or ``PRAGMATIC_REQUIRE_SERVER=1``) refuses a
      local store, so a misconfigured deployment cannot quietly journal to
      local disk.
    - ``oracle`` is an optional default ``(str) -> str`` model for
      ``ctx.oracle``; agents that use ``ctx.wrap(client)`` do not need one.
    - ``timeout`` is the server read timeout in seconds; ``volatile`` lists
      request-normalization rules (JSON paths) for journaled HTTP clients.
    - ``dir=`` is a deprecated alias of ``store``.
    """

    def __init__(
        self,
        store: Any = None,
        oracle: Optional[Callable[[str], str]] = None,
        *,
        token: Optional[str] = None,
        key: Optional[Union[bytes, str]] = None,
        timeout: float = 30.0,
        require_server: bool = False,
        volatile: Optional[Iterable[str]] = None,
        dir: Any = None,
    ):
        if dir is not None:
            warnings.warn(
                "Runtime(dir=...) is deprecated; pass the directory as the store",
                DeprecationWarning,
                stacklevel=2,
            )
            if store is None:
                store = dir
        if store is None:
            url = os.environ.get("PRAGMATIC_URL")
            if not url:
                raise ValueError("pass a directory or set PRAGMATIC_URL")
            store = url
        store = _resolve_store(store, token, timeout)
        remote = bool(getattr(store, "remote", False))
        if (require_server or os.environ.get("PRAGMATIC_REQUIRE_SERVER") == "1") and not remote:
            raise ValueError(
                "a server store is required (require_server or PRAGMATIC_REQUIRE_SERVER), "
                f"but the store is {store!r}"
            )
        native_key = self._key(store, key, remote)
        if isinstance(store, ServerStore) and store.info is None:
            store.connect()
        self._store = store
        self._oracle = oracle
        self.volatile: Tuple[str, ...] = tuple(volatile or ())
        self._native = _native.Runtime(native_store(store), native_key)

    @staticmethod
    def _key(store: Any, key: Optional[Union[bytes, str]], remote: bool) -> Optional[bytes]:
        env = os.environ.get("PRAGMATIC_JOURNAL_KEY")
        local = isinstance(store, (DirStore, MemoryStore))
        if remote or not local:
            if key is not None:
                raise ValueError(
                    "journal keys apply to local stores (DirStore, MemoryStore); runs on a "
                    "server or in a store of your own are unkeyed"
                )
            if env:
                warnings.warn(
                    "PRAGMATIC_JOURNAL_KEY is ignored: runs on a server or in a store of your "
                    "own are unkeyed",
                    stacklevel=3,
                )
            return None
        if key is None and env:
            key = env
        return _text(key) if key is not None else None

    @property
    def store(self) -> Any:
        """The store the runtime journals to."""
        return self._store

    # -- attempts ---------------------------------------------------------

    def _options(
        self,
        agent: Agent,
        budget: Optional[int],
        caps: Optional[Iterable[str]],
        labels: Optional[Mapping[str, str]],
        subjects: Optional[Iterable[str]],
        on_code_change: Optional[str],
    ) -> dict:
        return dict(
            budget=budget,
            caps=list(caps) if caps is not None else None,
            labels=dict(labels) if labels else None,
            subjects=list(subjects) if subjects else None,
            on_code_change=on_code_change,
            program=_program_identity(agent),
        )

    def _sync(
        self, mode: str, run_id: str, agent: Agent, recover: Optional[Callable], opts: dict
    ) -> Any:
        if _is_async_agent(agent):
            if _running_loop() is not None:
                raise RuntimeError(
                    f"{_agent_name(agent)} is async and an event loop is running here; use "
                    f"`await rt.a{mode}(...)` instead of rt.{mode}(...)"
                )
            return asyncio.run(self._async(mode, run_id, agent, recover, opts))
        att = self._native.begin(
            run_id, mode, recover=_normalize_policy(recover, None), owner="thread", **opts
        )
        ctx = Ctx(att, _SyncDriver(att), self)
        token = CURRENT.set((att.token, ()))
        try:
            with _otel.attempt(run_id, mode):
                try:
                    result = agent(ctx)
                    if inspect.isawaitable(result):
                        result = self._await_privately(agent, result)
                    output = _encode_output(result)
                except BaseException as exc:
                    _end_failed(att, exc)
                    raise
                return att.finish("ok", output)
        finally:
            CURRENT.reset(token)

    @staticmethod
    def _await_privately(agent: Agent, awaitable: Awaitable) -> Any:
        """Drive the awaitable a sync-looking agent returned on a private
        loop, or refuse inside a running one."""
        if _running_loop() is not None:
            _close(awaitable)
            raise RuntimeError(
                f"{_agent_name(agent)} returned an awaitable inside a running event loop; "
                "use `await rt.arun(...)`"
            )
        return asyncio.run(_as_coroutine(awaitable))

    async def _async(
        self, mode: str, run_id: str, agent: Agent, recover: Optional[Callable], opts: dict
    ) -> Any:
        loop = asyncio.get_running_loop()
        if asyncio.current_task() is None:
            raise RuntimeError("an async run must be awaited inside a task")
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pragmatic-persist"
        )
        try:
            begin = functools.partial(
                self._native.begin,
                run_id,
                mode,
                recover=_normalize_policy(recover, loop),
                owner="tasks",
                **opts,
            )
            fut, cancelled = await _uncancellable(loop.run_in_executor(executor, begin))
            if cancelled:
                if fut.exception() is None:
                    await _uncancellable(loop.run_in_executor(executor, fut.result().abandon))
                raise asyncio.CancelledError()
            att = fut.result()
            ctx = Ctx(att, _AsyncDriver(att, executor), self)
            att.own_current_task()
            token = CURRENT.set((att.token, ()))
            failure: Optional[BaseException] = None
            output = b""
            try:
                with _otel.attempt(run_id, mode):
                    try:
                        result = agent(ctx)
                        if inspect.isawaitable(result):
                            result = await result
                        output = _encode_output(result)
                    except BaseException as exc:
                        failure = exc
            finally:
                CURRENT.reset(token)
            if failure is None:
                fut, cancelled = await _uncancellable(
                    loop.run_in_executor(executor, att.finish, "ok", output)
                )
                if cancelled:
                    raise asyncio.CancelledError()
                return fut.result()
            await _uncancellable(loop.run_in_executor(executor, _end_failed, att, failure))
            raise failure
        finally:
            executor.shutdown(wait=False)

    def run(
        self,
        run_id: str,
        agent: Agent,
        *,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """Start or continue a durable run. Re-enterable: an existing journal
        prefix is read back first, so retrying a run id is idempotent.

        ``budget`` caps the run's model calls; ``caps`` allowlists effect
        names (tool effects are named ``tool:<name>``); ``labels`` (at most
        32, non-personal) and ``subjects`` (data subjects, erasable) are
        recorded when the run is created; ``on_code_change`` is
        ``"continue"`` (the default here) or ``"refuse"``. An async agent
        runs on a private event loop; inside a running loop use ``arun``."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return self._sync("run", run_id, agent, None, opts)

    def resume(
        self,
        run_id: str,
        agent: Agent,
        *,
        recover: Optional[Callable] = None,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """Resume a crashed run: the journaled prefix is read back (zero
        model calls, no duplicate effects) and recording continues at the
        tail.

        ``recover(name, arg)`` or ``recover(name, arg, branch,
        intent_cursor)`` decides each effect a crash left without a result:
        return its result (or ``Recover.commit(result)``) to record that it
        happened, ``None`` (or ``Recover.COMPENSATE``) to perform it again,
        or ``Recover.FAIL``. Without a policy local runs perform such effects
        again, and server-backed runs raise ``DanglingEffect``. A policy that
        raises aborts the resume and records nothing."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return self._sync("resume", run_id, agent, recover, opts)

    def replay(
        self,
        run_id: str,
        agent: Agent,
        *,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """Replay a recorded run exactly, for debugging and audit. Nothing is
        sampled or performed and nothing is written; it takes no lock, so it
        can audit a run that is still recording. A run that never finished
        raises ``ReplayExhausted``; changed code raises ``JournalDesync``
        unless ``on_code_change="continue"``."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return self._sync("replay", run_id, agent, None, opts)

    async def arun(
        self,
        run_id: str,
        agent: Agent,
        *,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """``run`` inside the caller's event loop. The attempt is owned by
        the awaiting task (and the children of ``ctx.gather``); storage work
        runs on a dedicated thread so the loop never blocks on it. Cancelling
        the task is a crash: nothing more is journaled, and the run is
        checked in (shielded from the cancellation) before it propagates."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return await self._async("run", run_id, agent, None, opts)

    async def aresume(
        self,
        run_id: str,
        agent: Agent,
        *,
        recover: Optional[Callable] = None,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """``resume`` inside the caller's event loop; ``recover`` may be
        async."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return await self._async("resume", run_id, agent, recover, opts)

    async def areplay(
        self,
        run_id: str,
        agent: Agent,
        *,
        budget: Optional[int] = None,
        caps: Optional[Iterable[str]] = None,
        labels: Optional[Mapping[str, str]] = None,
        subjects: Optional[Iterable[str]] = None,
        on_code_change: Optional[str] = None,
    ) -> Any:
        """``replay`` inside the caller's event loop."""
        opts = self._options(agent, budget, caps, labels, subjects, on_code_change)
        return await self._async("replay", run_id, agent, None, opts)

    # -- channels and views -----------------------------------------------

    def send(self, run_id: str, channel: str, value: Union[str, bytes]) -> None:
        """Deliver a value to a run's channel inbox (this process only; the
        receive itself is journaled when the agent takes it)."""
        self._native.send(run_id, channel, _text(value))

    def verify(self, run_id: str) -> VerifyReport:
        """The full integrity check of a run's journal: every chain link,
        commitment and ref, and erasure accounting. Truthy when intact.

        On a server, the journal is downloaded and checked here when the
        token may read it; otherwise the server's own report is returned."""
        if isinstance(self._store, ServerStore):
            try:
                return VerifyReport.from_dict(self._native.verify(run_id))
            except (ServerError, FileNotFoundError):
                doc = self._store.summary(run_id).get("verify") or {}
                return VerifyReport.from_dict(doc)
        return VerifyReport.from_dict(self._native.verify(run_id))

    def runs(self) -> List[RunSummary]:
        """A summary of every run in the store."""
        if isinstance(self._store, ServerStore):
            return [RunSummary.from_json(d) for d in self._store.summaries()]
        return [
            RunSummary.from_json(json.loads(self._native.summary(r))) for r in self._native.runs()
        ]

    def entries(self, run_id: str) -> List[Entry]:
        """A run's journal entries in the Entry JSON shape (spec 4.4). On a
        server, content is redacted unless the token has ``view_raw``."""
        if isinstance(self._store, ServerStore):
            return self._store.entries(run_id)
        return json.loads(self._native.entries(run_id))
