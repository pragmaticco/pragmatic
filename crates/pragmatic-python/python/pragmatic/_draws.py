"""The HTTP draws of one attempt (spec 6.5): open streams, matching under
normalization, and the counts ``attempt.end`` reports.

An ``AttemptHttp`` belongs to one attempt. Journaled clients reach it in
one of two ways: ``ctx.wrap`` binds a client to it, and ``pragmatic.wrap``
finds it through the context variable ``CURRENT``, which every step of an
attempt (and every task or thread that inherited the agent's context)
carries. ``LIVE`` maps attempt tokens to the attempts that are running.

Open streams. A streamed response's ``DrawResult`` is written when the
stream ends, or with the bytes read so far (``partial``) when it is closed
early, collected unread (``weakref.finalize``), left untouched while the
agent takes its next step on the same branch, or left open when a
``ctx.gather`` child or the attempt ends, whichever comes first. A stream
whose result is written reads no further, so what the agent saw on record
is what replay serves.

Nothing here persists from a close or a finalizer: those can run inside
another persist (a garbage collection triggered by a store) or on a thread
that must not block, so they only append, and the entry becomes durable
with the next persist or at the end of the attempt. Nothing is released to
the agent from a stream once its result is written, so durability can
wait.

This module needs no HTTP library; ``_http`` holds the httpx2 side.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import weakref
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import _native, _wire
from ._diff import with_diff
from ._errors import JournalDesync

CURRENT = _native.CURRENT

LIVE: "weakref.WeakValueDictionary[int, AttemptHttp]" = weakref.WeakValueDictionary()
"""The running attempts, by token, for ``pragmatic.wrap`` to route to."""

log = logging.getLogger("pragmatic")


def _digest(parts: Sequence[bytes]) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(8, "little"))
        h.update(p)
    return h.digest()


class AttemptHttp:
    """The HTTP-draw state of one attempt. See the module documentation."""

    __slots__ = (
        "att",
        "io",
        "normalizer",
        "token",
        "run_id",
        "lock",
        "open",
        "inflight",
        "passthrough",
        "live",
        "__weakref__",
    )

    def __init__(self, att: Any, io: Any, normalizer: Any):
        self.att = att
        self.io = io
        self.normalizer = normalizer
        self.token: int = att.token
        self.run_id: str = att.run_id
        # Re-entrant: a finalizer can run on a thread that already holds it.
        self.lock = threading.RLock()
        self.open: Dict[int, Any] = {}
        self.inflight: Dict[int, Tuple[Tuple[int, ...], bytes]] = {}
        self.passthrough = 0
        self.live = True
        LIVE[self.token] = self

    # -- the lifecycle ----------------------------------------------------

    def end(self) -> None:
        """Before ``attempt.end``: write the result of every stream still
        open (``partial``) and report the passthrough calls. Appends only;
        the attempt's finish persists."""
        for rec in self._open_records():
            rec.settle_quietly()
        with self.lock:
            calls, self.passthrough = self.passthrough, 0
        try:
            if calls:
                self.att.count_passthrough(calls)
        finally:
            self.retire()

    def abandon(self) -> None:
        """A crash: open streams are dropped unrecorded, so their intents
        stay dangling and a resume makes those calls again."""
        for rec in self._open_records():
            rec.kill()
        self.retire()

    def retire(self) -> None:
        with self.lock:
            self.live = False
            self.open.clear()
            self.inflight.clear()
        if LIVE.get(self.token) is self:
            del LIVE[self.token]

    def _open_records(self) -> List[Any]:
        with self.lock:
            return list(self.open.values())

    # -- open streams -----------------------------------------------------

    def track(self, rec: Any) -> None:
        with self.lock:
            self.open[rec.intent] = rec

    def forget(self, rec: Any) -> None:
        with self.lock:
            self.open.pop(rec.intent, None)
            self.inflight.pop(rec.intent, None)

    def settle_untouched(self, branch: Optional[Tuple[int, ...]] = None) -> None:
        """The next-step rule: a stream on the caller's branch that the agent
        has not started reading is written off as ``partial`` (empty)."""
        if not self.open:
            return
        if branch is None:
            current = CURRENT.get()
            if current is None or current[0] != self.token:
                return
            branch = tuple(current[1])
        for rec in self._open_records():
            if rec.branch == branch and not rec.touched:
                rec.settle_quietly()

    def settle_regions(self, children: Sequence[Sequence[int]]) -> None:
        """Before a parallel region joins: write the result of every stream
        still open on a child branch, or below one (``partial``), as at the
        end of an attempt. A child is complete only once every intent on
        its branch has a result (spec 2.7)."""
        if not self.open:
            return
        prefixes = [tuple(c) for c in children]
        for rec in self._open_records():
            if any(rec.branch[: len(p)] == p for p in prefixes):
                rec.settle_quietly()

    # -- draws ------------------------------------------------------------

    def branch(self) -> Tuple[int, ...]:
        current = CURRENT.get()
        return tuple(current[1]) if current is not None else ()

    def begin(self, request: _wire.Request, provenance: str) -> Tuple[Any, ...]:
        """Begin the draw of one exchange on the caller's branch: the
        native ``draw_begin`` with the relaxed ownership check of journaled
        clients. Under normalization (spec 6.6) the recorded request is
        compared normalized and, when it matches, the draw begins with the
        recorded parts, so the core's exact comparison holds."""
        branch = self.branch()
        self.settle_untouched(branch)
        parts = request.parts()
        send = parts
        normalized, changed = self.normalizer(request.body)
        if changed:
            mine = request.parts(normalized, use=True)
            recorded = self.att.next_draw_parts(relaxed=True)
            if recorded is not None and _wire.normalized_parts(recorded, self.normalizer) == mine:
                send = recorded
        try:
            start = self.att.draw_begin(send, provenance, relaxed=True)
        except JournalDesync as e:
            raise self._with_diff(e, parts) from None
        if start[0] == "fresh":
            self._in_flight(start[1], branch, parts)
        return start

    def _with_diff(self, e: JournalDesync, parts: List[bytes]) -> JournalDesync:
        """The desync with the first differing JSON paths of the normalized
        requests, so a loosened field never shows up as the difference."""
        if e.cursor is None:
            return e
        try:
            recorded = self.att.recorded_parts(e.cursor)
        except Exception:  # noqa: BLE001 - the desync is what matters
            recorded = None
        if not recorded:
            return e
        return with_diff(
            e,
            _wire.normalized_parts(recorded, self.normalizer),
            _wire.normalized_parts(parts, self.normalizer),
        )

    def _in_flight(self, intent: int, branch: Tuple[int, ...], parts: List[bytes]) -> None:
        """Track a fresh draw until its result, and warn when another call
        with the identical request is in flight on the same branch: replay
        matches the two in the order they were sent (spec 2.7)."""
        digest = _digest(parts)
        with self.lock:
            twin = any(b == branch and d == digest for b, d in self.inflight.values())
            self.inflight[intent] = (branch, digest)
        if twin:
            log.warning(
                "run %r: two model calls with identical requests are in flight on branch %s. "
                "Replay matches them in the order they were sent, so send them in a "
                "deterministic order, or from ctx.gather children (one branch each).",
                self.run_id,
                list(branch),
            )

    def complete(self, intent: int, meta: str, head: bytes, body: bytes) -> Optional[int]:
        """Append the result of the draw at ``intent``. Returns the journal
        length that must be durable before the result is released."""
        try:
            return self.att.complete_draw(intent, meta, head, body)
        finally:
            with self.lock:
                self.inflight.pop(intent, None)

    def count_passthrough(self) -> None:
        with self.lock:
            if self.live:
                self.passthrough += 1
