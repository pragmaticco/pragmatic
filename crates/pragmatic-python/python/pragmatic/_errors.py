"""The exceptions of the runtime (spec 6.7).

Every exception the runtime raises for a core fault is a ``PragmaticError``
and carries the fault itself (``_pragmatic_fault``), so that when it
escapes the agent the attempt ends with the very fault that was raised: a
desync stays a desync in the run's ``attempt.end`` note.

Stores raise these classes too (spec 6.3): ``Locked``, ``LeaseLost``,
``Conflict``, ``Deleted``, ``TooLarge`` and ``Unavailable`` map to the core
faults of the same names, and anything else (``OSError`` included) to an
I/O fault. The caller then sees exactly the exception the store raised.

``PragmaticError`` subclasses ``RuntimeError``, as it did in 0.5.
"""

from __future__ import annotations

from typing import Any, Optional, Tuple


class PragmaticError(RuntimeError):
    """A runtime fault: a desync, a refused step, a storage failure."""

    _pragmatic_fault: Any = None


class JournalDesync(PragmaticError):
    """Replay found the journal disagreeing with the program: the agent code
    or its inputs changed since the run was recorded.

    ``cursor`` is the recorded entry that did not match. For a model call,
    ``diff`` lists the first differing JSON paths of the request, with the
    values shortened; it is part of this exception only and is never
    written to a journal."""

    def __init__(
        self,
        message: str,
        *,
        cursor: Optional[int] = None,
        expected: Optional[str] = None,
        found: Optional[str] = None,
        diff: Tuple[str, ...] = (),
    ):
        super().__init__(message)
        self.cursor = cursor
        self.expected = expected
        self.found = found
        self.diff = tuple(diff)


class ReplayExhausted(PragmaticError):
    """Strict replay ran past the end of the journal: the recorded run never
    got this far. Use resume to continue a run that never finished."""

    def __init__(self, message: str, *, cursor: Optional[int] = None):
        super().__init__(message)
        self.cursor = cursor


class Locked(PragmaticError):
    """Another writer holds the run (a lock in this or another process, or a
    server lease). ``retry_after`` is the server's hint in seconds, if any."""

    def __init__(self, retry_after: Optional[int] = None, message: Optional[str] = None):
        if message is None:
            message = "run is locked by another writer"
            if retry_after is not None:
                message += f" (retry after {retry_after}s)"
        super().__init__(message)
        self.retry_after = retry_after


class LeaseLost(Locked):
    """The run's lease (or lock) was lost while this attempt held it: it
    expired and was granted to another writer, or was revoked. The attempt
    can record nothing more. A ``Locked`` too, which is the client action
    spec 4.4 names for ``lease_lost``."""

    def __init__(self, message: Optional[str] = None):
        super().__init__(None, message or "the run's lease or lock was lost")


class Conflict(PragmaticError):
    """The stored journal changed underneath this writer: it holds
    ``actual`` where ``expected`` was assumed (entries or bytes)."""

    def __init__(self, expected: int, actual: int, message: Optional[str] = None):
        super().__init__(
            message
            or f"journal changed underneath this writer: expected {expected}, found {actual}"
        )
        self.expected = expected
        self.actual = actual


class Deleted(PragmaticError):
    """The run was deleted and can never be recreated."""

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or "the run has been deleted")


class Erased(PragmaticError):
    """Replay needed content that was erased. An erased run can be verified,
    not replayed or resumed."""

    def __init__(self, cursor: int, message: Optional[str] = None):
        super().__init__(message or f"content at cursor {cursor} has been erased")
        self.cursor = cursor


class Unsupported(PragmaticError):
    """The operation is not supported for this journal, store or input."""


class TooLarge(PragmaticError):
    """Content exceeds a limit: a slot, a record or a request. ``size`` is 0
    when the store did not report it."""

    def __init__(self, message: Optional[str] = None, *, size: int = 0, limit: int = 0):
        super().__init__(message or f"too large: {size} bytes exceeds the limit of {limit}")
        self.size = size
        self.limit = limit


class Unavailable(PragmaticError):
    """Storage is temporarily unavailable (the server could not be reached
    before the deadline); retrying later may succeed."""


class DanglingIntent(PragmaticError):
    """The agent returned while a model call or effect it started had no
    result."""

    def __init__(self, message: str, *, cursor: Optional[int] = None):
        super().__init__(message)
        self.cursor = cursor


class DanglingEffect(PragmaticError):
    """An effect was left without a result by a crash, and the runtime needs
    a recovery policy to decide it (``recover=`` on resume)."""

    def __init__(self, message: str, *, cursor: Optional[int] = None):
        super().__init__(message)
        self.cursor = cursor


class EffectUnrecorded(PragmaticError):
    """An effect was performed but its result could not be recorded. The
    result is attached so it can be logged or reconciled; the next resume
    decides the effect from its intent."""

    def __init__(self, name: str, intent: int, result: bytes, message: Optional[str] = None):
        super().__init__(
            message
            or f"effect {name!r} (intent at cursor {intent}) succeeded, but its "
            f"{len(result)}-byte result could not be recorded"
        )
        self.name = name
        self.intent = intent
        self.result = result


class NotInRun(PragmaticError):
    """A journaled step was attempted outside the attempt that owns the
    context: after the run ended, from another run, or from a thread or task
    the attempt does not own. Use ``ctx.gather`` or ``asyncio.to_thread``."""


class ServerError(PragmaticError):
    """The server refused a request with a definitive error (spec 4.4):
    ``status`` and ``code`` are what it answered, ``url`` the request."""

    def __init__(self, message: str, *, status: int = 0, code: str = "", url: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code
        self.url = url


def _from_fault(handle: Any) -> PragmaticError:
    """The exception for a core fault (called by the native layer)."""
    kind = handle.kind
    message = handle.message
    d = handle.details()
    exc: PragmaticError
    if kind == "JournalDesync":
        exc = JournalDesync(
            message, cursor=d.get("cursor"), expected=d.get("expected"), found=d.get("found")
        )
    elif kind == "ReplayExhausted":
        exc = ReplayExhausted(message, cursor=d.get("cursor"))
    elif kind == "Locked":
        exc = Locked(d.get("retry_after"), message)
    elif kind == "LeaseLost":
        exc = LeaseLost(message)
    elif kind == "Conflict":
        exc = Conflict(d["expected"], d["actual"], message)
    elif kind == "Deleted":
        exc = Deleted(message)
    elif kind == "Erased":
        exc = Erased(d["cursor"], message)
    elif kind == "Unsupported":
        exc = Unsupported(message)
    elif kind == "TooLarge":
        exc = TooLarge(message, size=d.get("size", 0), limit=d.get("limit", 0))
    elif kind == "Unavailable":
        exc = Unavailable(message)
    elif kind == "DanglingIntent":
        exc = DanglingIntent(message, cursor=d.get("cursor"))
    elif kind == "DanglingEffect":
        exc = DanglingEffect(message, cursor=d.get("cursor"))
    elif kind == "EffectUnrecorded":
        exc = EffectUnrecorded(d["name"], d["intent"], d["result"], message)
    else:
        exc = PragmaticError(message)
    exc._pragmatic_fault = handle
    return exc


def _seconds(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return max(0, int(-(-float(value) // 1)))
    except (TypeError, ValueError):
        return None


def _store_error_info(exc: BaseException) -> Tuple[str, Optional[int], Optional[int], str]:
    """What an exception a store raised means to the core: ``(kind, a, b,
    text)``, where ``a`` and ``b`` carry the numbers of the kind (called by
    the native layer)."""
    text = str(exc)
    if isinstance(exc, LeaseLost):
        return ("lease_lost", None, None, text)
    if isinstance(exc, Locked):
        return ("locked", _seconds(exc.retry_after), None, text)
    if isinstance(exc, Conflict):
        return ("conflict", _seconds(exc.expected), _seconds(exc.actual), text)
    if isinstance(exc, Deleted):
        return ("deleted", None, None, text)
    if isinstance(exc, TooLarge):
        return ("too_large", _seconds(exc.limit), None, text)
    if isinstance(exc, Unavailable):
        return ("unavailable", None, None, text)
    name = type(exc).__name__
    return ("io", None, None, f"{name}: {text}" if text else name)
