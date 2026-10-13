"""Journaling HTTP clients for the Anthropic and OpenAI SDKs (spec 6.5).

``JournalingHttpClient`` subclasses ``httpx2.Client`` (and
``AsyncJournalingHttpClient`` ``httpx2.AsyncClient``) and overrides
``send()``, the one call every SDK request goes through: ``create``,
``stream=True``, the ``.stream()`` helpers, ``.parse()``,
``with_raw_response``, ``with_streaming_response``, tool runners, token
counting, and every framework built on the SDK client. The real I/O is
delegated to the client the SDK was built with.

Record. The request becomes a ``DrawIntent``, durable before anything is
sent. The response body is teed into the journal while the caller reads
it; the ``DrawResult`` is written when the body ends (and is durable before
the end reaches the caller), or with the bytes read so far when the stream
is closed early (``partial``). A non-streaming response and every error
response are read whole inside ``send()``. A transport error is a result
too, so the SDK's retry loop replays exactly.

Replay. ``send()`` builds the response from the journal: the recorded
status, headers and bytes, so the SDK parses into its own types from
identical input. A recorded transport error is raised again, as an
instance of the recorded httpx2 class, so the SDK wraps and retries it as
it did. A retryable error response is served with ``retry-after-ms: 1``,
so the SDK's retry costs no waiting.

Journal faults (a desync, a refused step, a failed persist) are raised
inside a ``JournalFault`` carrier: SDKs and frameworks catch ``Exception``
around ``send()``, and a fault must reach the runtime unchanged.
"""

from __future__ import annotations

import datetime
import json
import time
import weakref
from typing import Any, Callable, List, Optional, Set, Tuple

import httpx2

from . import _otel, _wire
from ._draws import CURRENT, LIVE, AttemptHttp
from ._errors import JournalFault, NotInRun, Unsupported
from ._failures import replayed as _replayed_failure, type_name as _type_name

_OPEN, _DONE, _DEAD = 0, 1, 2

WEBSOCKETS_UNSUPPORTED = (
    "websocket and realtime connections are not journaled (spec 6.5): make the model calls "
    "of a durable run over HTTP, or record what the connection exchanges with ctx.tool"
)


def _journal(fn: Callable[..., Any], *args: Any) -> Any:
    """Run a journal operation, raising whatever it raises inside the
    carrier. A store's own exception (an ``OSError``, say) is carried too:
    an SDK would otherwise retry it as a connection error."""
    try:
        return fn(*args)
    except JournalFault:
        raise
    except Exception as e:
        raise JournalFault(e) from None


async def _ajournal(fn: Callable[..., Any], *args: Any) -> Any:
    try:
        return await fn(*args)
    except JournalFault:
        raise
    except Exception as e:
        raise JournalFault(e) from None


def _parse(request: httpx2.Request) -> _wire.Request:
    url = request.url
    return _wire.Request.parse(
        request.method, url.path, url.params.multi_items(), request.headers, request.content
    )


def _provenance(provider: str, request: _wire.Request) -> str:
    return f"{provider}:{request.model}" if request.model else provider


# ---------------------------------------------------------------------------
# Which attempt a client records into
# ---------------------------------------------------------------------------


class Binding:
    """What a journaled client records into: the attempt ``ctx.wrap`` bound
    it to, or (``pragmatic.wrap``) whichever attempt the caller's context
    belongs to. Shared by every copy of one journaled SDK client.

    ``outside`` decides a call made outside the attempt: ``"error"`` raises
    ``NotInRun``; ``"passthrough"`` sends it unrecorded, counted in the
    bound attempt's ``attempt.end.passthrough_calls`` while that attempt
    runs. A call from inside a different attempt is always refused: it
    would be missing from that attempt's record."""

    __slots__ = ("http", "outside", "provider", "hosts")

    def __init__(self, http: Optional[AttemptHttp], outside: str, provider: str):
        self.http = http
        self.outside = outside
        self.provider = provider
        self.hosts: Set[str] = set()

    def allow(self, url: Any) -> None:
        """Accept requests to ``url``'s host: the API host of each SDK
        client sharing this binding."""
        host = getattr(url, "host", None)
        if host:
            self.hosts.add(host)

    def resolve(self, request: httpx2.Request) -> Optional[AttemptHttp]:
        """The attempt to record ``request`` into, or ``None`` to pass it
        through. Raises ``NotInRun`` or ``Unsupported``."""
        current = CURRENT.get()
        token = current[0] if current is not None else None
        caller = LIVE.get(token) if token is not None else None
        if self.http is not None:
            if caller is self.http:
                return self._checked(self.http, request)
            if caller is not None:
                raise NotInRun(
                    f"this client was wrapped by the attempt on run {self.http.run_id!r} and "
                    f"called from the attempt on run {caller.run_id!r}: wrap it in the attempt "
                    "that uses it, or use pragmatic.wrap(client), which follows the caller"
                )
        elif caller is not None:
            return self._checked(caller, request)
        if self.outside == "passthrough":
            if self.http is not None:
                self.http.count_passthrough()
            return None
        raise NotInRun(
            "a journaled model client was called outside a durable run (or from a thread or "
            "task that does not carry the run's context): call it from the agent, a "
            "ctx.gather child, or asyncio.to_thread, or wrap it with outside='passthrough' "
            "to let calls outside a run through unrecorded"
        )

    def _checked(self, http: AttemptHttp, request: httpx2.Request) -> AttemptHttp:
        if self.hosts and request.url.host not in self.hosts:
            raise Unsupported(
                f"a journaled {self.provider} client sends only to its API host "
                f"({', '.join(sorted(self.hosts))}), not {request.url.host}: make other "
                "requests with a client of their own, journaled with ctx.tool"
            )
        return http


# ---------------------------------------------------------------------------
# Recording a response
# ---------------------------------------------------------------------------


class _Recording:
    """One response being teed into the journal. The first of end, close,
    collection, the next-step rule and the end of the attempt writes its
    result; after that it reads no further."""

    __slots__ = (
        "http",
        "intent",
        "branch",
        "provider",
        "request_model",
        "upstream",
        "status",
        "headers",
        "content_type",
        "chunks",
        "state",
        "touched",
        "t0",
        "latency_ms",
        "span",
        "finalizer",
        "__weakref__",
    )

    def __init__(
        self,
        http: AttemptHttp,
        intent: int,
        branch: Tuple[int, ...],
        provider: str,
        request: _wire.Request,
        upstream: httpx2.Response,
        t0: float,
        span: _otel.Step,
    ):
        self.http = http
        self.intent = intent
        self.branch = branch
        self.provider = provider
        self.request_model = request.model
        self.upstream = upstream
        self.status = upstream.status_code
        self.headers = _wire.kept_headers(upstream.headers.multi_items())
        self.content_type = upstream.headers.get("content-type", "")
        self.chunks: List[bytes] = []
        self.state = _OPEN
        self.touched = False
        self.t0 = t0
        self.latency_ms: Optional[int] = None
        self.span = span
        self.finalizer: Optional[weakref.finalize] = None

    def elapsed(self) -> datetime.timedelta:
        if self.latency_ms is not None:
            return datetime.timedelta(milliseconds=self.latency_ms)
        return datetime.timedelta(seconds=time.monotonic() - self.t0)

    def add(self, chunk: bytes) -> bool:
        """Keep ``chunk`` if the result is not written yet. Under the
        attempt's lock, so a chunk is either in the result or never
        released."""
        with self.http.lock:
            if self.state != _OPEN:
                return False
            self.chunks.append(chunk)
            return True

    def _take(self) -> bool:
        with self.http.lock:
            if self.state != _OPEN:
                return False
            self.state = _DONE
            self.latency_ms = max(0, round((time.monotonic() - self.t0) * 1000))
        if self.finalizer is not None:
            self.finalizer.detach()
        return True

    def settle(self, outcome: str, error: Optional[BaseException] = None) -> Optional[int]:
        """Write the result: ``ok`` at the end of the body, ``partial`` when
        cut short, ``error`` when reading raised. Returns the journal length
        to make durable, ``None`` if the result was already written."""
        if not self._take():
            return None
        body = b"".join(self.chunks)
        if self.status >= 400:
            outcome = "error"
        elif outcome == "partial" and _wire.ended(body, self.content_type):
            outcome = "ok"
        meta = _wire.meta(
            outcome,
            provider=self.provider,
            status=self.status,
            body=body,
            content_type=self.content_type,
            request_model=self.request_model,
            latency_ms=self.latency_ms,
            error=error,
            error_type=_type_name(error) if error is not None else None,
        )
        head = _wire.head_bytes(self.status, self.headers, str(error) if error is not None else None)
        try:
            return self.http.complete(self.intent, meta, head, body)
        finally:
            self.http.forget(self)
            _end_span(self.span, meta)

    def settle_quietly(self) -> None:
        """Write a ``partial`` result if none is written yet, from a close,
        a finalizer, the next step or the end of the attempt. Appends only
        (see ``_draws``) and never raises: a session that failed reports
        its fault at the next step, and an attempt that ended has nothing
        left to record into."""
        try:
            self.settle("partial")
        except Exception:  # noqa: BLE001 - see the docstring
            pass

    def kill(self) -> None:
        """The attempt crashed: write nothing."""
        with self.http.lock:
            self.state = _DEAD
        if self.finalizer is not None:
            self.finalizer.detach()


def _end_span(span: _otel.Step, meta: str) -> None:
    if span.span is None:
        return
    doc = json.loads(meta)
    usage = doc.get("usage") or {}
    span.set(input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"))
    span.end()


def _durable(http: AttemptHttp, upto: Optional[int]) -> None:
    _journal(http.io.durable, upto)


async def _adurable(http: AttemptHttp, upto: Optional[int]) -> None:
    await _ajournal(http.io.adurable, upto)


class _TeeStream(httpx2.SyncByteStream):
    """The caller's view of a recorded response body."""

    def __init__(self, rec: _Recording):
        self._rec = rec

    @property
    def elapsed(self) -> datetime.timedelta:
        return self._rec.elapsed()

    def __iter__(self):  # type: ignore[override]
        rec = self._rec
        rec.touched = True
        if rec.state != _OPEN:
            return  # written off before the caller read anything: nothing to read
        try:
            for chunk in rec.upstream.iter_bytes():
                if not rec.add(chunk):
                    return  # the result is written: the stream ends here, as on replay
                yield chunk
        except GeneratorExit:
            raise
        except Exception as e:
            _durable(rec.http, _journal(rec.settle, "error", e))
            raise
        _durable(rec.http, _journal(rec.settle, "ok"))

    def close(self) -> None:
        rec = self._rec
        rec.settle_quietly()
        rec.upstream.close()


class _AsyncTeeStream(httpx2.AsyncByteStream):
    """``_TeeStream`` for an async response."""

    def __init__(self, rec: _Recording):
        self._rec = rec

    @property
    def elapsed(self) -> datetime.timedelta:
        return self._rec.elapsed()

    async def __aiter__(self):  # type: ignore[override]
        rec = self._rec
        rec.touched = True
        if rec.state != _OPEN:
            return
        try:
            async for chunk in rec.upstream.aiter_bytes():
                if not rec.add(chunk):
                    return
                yield chunk
        except GeneratorExit:
            raise
        except Exception as e:
            await _adurable(rec.http, _journal(rec.settle, "error", e))
            raise
        await _adurable(rec.http, _journal(rec.settle, "ok"))

    async def aclose(self) -> None:
        rec = self._rec
        rec.settle_quietly()
        await rec.upstream.aclose()


# ---------------------------------------------------------------------------
# Replaying a response
# ---------------------------------------------------------------------------


def _replica(type_name: str, message: str, request: httpx2.Request) -> BaseException:
    """A recorded transport failure, raised again: a ``DrawFailed`` that is
    also an instance of the recorded httpx2 class when it is loaded, so the
    SDK classifies it (timeout or connection error) as it did."""
    exc = _replayed_failure("draw", type_name, message)
    if isinstance(exc, httpx2.HTTPError):
        exc.request = request
    return exc


class _Replayed:
    """A recorded response: status, headers, bytes, and the failure that
    cut the body short, if one did."""

    __slots__ = ("status", "headers", "body", "failure", "elapsed")

    def __init__(self, start: Tuple[Any, ...], request: httpx2.Request):
        _, _intent, head, body, meta = start
        doc = json.loads(meta)
        if not head:
            # The exchange failed before any response: raise it again.
            raise _replica(doc.get("error_type") or "", body.decode("utf-8", "replace"), request)
        recorded = json.loads(head)
        self.status: int = recorded["status"]
        self.headers = _wire.replay_headers(recorded["headers"], self.status)
        self.body: bytes = body
        self.failure: Optional[Callable[[], BaseException]] = None
        if doc.get("outcome") == "error" and doc.get("error_type"):
            name, message = doc["error_type"], recorded.get("error", "")
            self.failure = lambda: _replica(name, message, request)
        self.elapsed = datetime.timedelta(milliseconds=doc.get("latency_ms") or 0)


class _ReplayStream(httpx2.SyncByteStream):
    def __init__(self, replayed: _Replayed):
        self._r = replayed
        self.elapsed = replayed.elapsed

    def __iter__(self):  # type: ignore[override]
        if self._r.body:
            yield self._r.body
        if self._r.failure is not None:
            raise self._r.failure()


class _AsyncReplayStream(httpx2.AsyncByteStream):
    def __init__(self, replayed: _Replayed):
        self._r = replayed
        self.elapsed = replayed.elapsed

    async def __aiter__(self):  # type: ignore[override]
        if self._r.body:
            yield self._r.body
        if self._r.failure is not None:
            raise self._r.failure()


# ---------------------------------------------------------------------------
# The exchange
# ---------------------------------------------------------------------------


class _Exchange:
    """The journal side of one ``send()``: begin the draw, and record a
    transport failure."""

    __slots__ = ("http", "provider", "request", "parsed", "branch", "intent", "span")

    def __init__(self, http: AttemptHttp, provider: str, request: httpx2.Request):
        self.http = http
        self.provider = provider
        self.request = request
        self.parsed = _parse(request)
        self.branch = http.branch()
        self.intent: Optional[int] = None
        self.span = _otel.Step(None)

    def begin(self) -> Tuple[Any, ...]:
        provenance = _provenance(self.provider, self.parsed)
        start = _journal(self.http.begin, self.parsed, provenance)
        self.span = _otel.start_draw(self.http.run_id, self.branch, provenance)
        if start[0] == "replayed":
            self.span.set(cursor=start[1], replayed=True, input_tokens=0, output_tokens=0)
            self.span.end()
        else:
            self.intent = start[1]
            self.span.set(cursor=start[1], replayed=False)
        return start

    def failed(self, exc: BaseException, t0: float) -> Optional[int]:
        """Record a transport failure as the exchange's result."""
        latency = max(0, round((time.monotonic() - t0) * 1000))
        meta = _wire.meta(
            "error",
            provider=self.provider,
            request_model=self.parsed.model,
            latency_ms=latency,
            error=exc,
            error_type=_type_name(exc),
        )
        assert self.intent is not None
        try:
            return _journal(self.http.complete, self.intent, meta, b"", str(exc).encode("utf-8"))
        finally:
            _end_span(self.span, meta)

    def recording(self, upstream: httpx2.Response, t0: float) -> _Recording:
        assert self.intent is not None
        return _Recording(
            self.http, self.intent, self.branch, self.provider, self.parsed, upstream, t0, self.span
        )


def _watch(http: AttemptHttp, rec: _Recording, response: httpx2.Response) -> None:
    """Track an open stream, and write it off if the caller drops it."""
    http.track(rec)
    rec.finalizer = weakref.finalize(response, rec.settle_quietly)
    rec.finalizer.atexit = False


def _response(status: int, headers: List[List[str]], stream: Any, request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(status, headers=[(k, v) for k, v in headers], stream=stream, request=request)


class _NoTransport(httpx2.BaseTransport):
    """Never used: ``send()`` is overridden. Avoids building a real
    transport (and loading TLS roots) for a client that never connects."""

    def handle_request(self, request: httpx2.Request) -> httpx2.Response:
        raise RuntimeError("a journaling client sends through the client it wraps")


class _AsyncNoTransport(httpx2.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        raise RuntimeError("a journaling client sends through the client it wraps")


class JournalingHttpClient(httpx2.Client):
    """An ``httpx2.Client`` that journals every exchange of an SDK client
    and sends through ``inner``, the client the SDK was built with (which
    stays the caller's: closing this one leaves it open)."""

    def __init__(self, inner: httpx2.Client, binding: Binding):
        super().__init__(
            timeout=inner.timeout,
            follow_redirects=inner.follow_redirects,
            transport=_NoTransport(),
            trust_env=False,
        )
        self._inner = inner
        self._binding = binding

    @property
    def binding(self) -> Binding:
        return self._binding

    def rebound(self, inner: httpx2.Client) -> "JournalingHttpClient":
        """A journaling client over ``inner`` with this client's binding
        (an SDK ``copy(http_client=...)``)."""
        return type(self)(inner, self._binding)

    @property
    def is_closed(self) -> bool:  # type: ignore[override]
        return self._inner.is_closed

    def build_request(self, *args: Any, **kwargs: Any) -> httpx2.Request:  # type: ignore[override]
        # The inner client's base URL, default headers and cookies apply.
        return self._inner.build_request(*args, **kwargs)

    def send(self, request: httpx2.Request, *, stream: bool = False, **kwargs: Any) -> httpx2.Response:  # type: ignore[override]
        http = _journal(self._binding.resolve, request)
        if http is None:
            return self._inner.send(request, stream=stream, **kwargs)
        request.read()
        exchange = _Exchange(http, self._binding.provider, request)
        start = exchange.begin()
        if start[0] == "replayed":
            replayed = _Replayed(start, request)
            response = _response(replayed.status, replayed.headers, _ReplayStream(replayed), request)
            if not stream:
                response.read()
            return response
        _durable(http, start[2])
        t0 = time.monotonic()
        try:
            upstream = self._inner.send(request, stream=True, **kwargs)
        except Exception as e:
            _durable(http, exchange.failed(e, t0))
            raise
        rec = exchange.recording(upstream, t0)
        response = _response(rec.status, rec.headers, _TeeStream(rec), request)
        if stream and rec.status < 400:
            _watch(http, rec, response)
        else:
            response.read()
        return response

    def close(self) -> None:
        pass

    def websocket(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise Unsupported(WEBSOCKETS_UNSUPPORTED)


class AsyncJournalingHttpClient(httpx2.AsyncClient):
    """``JournalingHttpClient`` for async SDK clients."""

    def __init__(self, inner: httpx2.AsyncClient, binding: Binding):
        super().__init__(
            timeout=inner.timeout,
            follow_redirects=inner.follow_redirects,
            transport=_AsyncNoTransport(),
            trust_env=False,
        )
        self._inner = inner
        self._binding = binding

    @property
    def binding(self) -> Binding:
        return self._binding

    def rebound(self, inner: httpx2.AsyncClient) -> "AsyncJournalingHttpClient":
        return type(self)(inner, self._binding)

    @property
    def is_closed(self) -> bool:  # type: ignore[override]
        return self._inner.is_closed

    def build_request(self, *args: Any, **kwargs: Any) -> httpx2.Request:  # type: ignore[override]
        return self._inner.build_request(*args, **kwargs)

    async def send(self, request: httpx2.Request, *, stream: bool = False, **kwargs: Any) -> httpx2.Response:  # type: ignore[override]
        http = _journal(self._binding.resolve, request)
        if http is None:
            return await self._inner.send(request, stream=stream, **kwargs)
        await request.aread()
        exchange = _Exchange(http, self._binding.provider, request)
        start = exchange.begin()
        if start[0] == "replayed":
            replayed = _Replayed(start, request)
            response = _response(replayed.status, replayed.headers, _AsyncReplayStream(replayed), request)
            if not stream:
                await response.aread()
            return response
        await _adurable(http, start[2])
        t0 = time.monotonic()
        try:
            upstream = await self._inner.send(request, stream=True, **kwargs)
        except Exception as e:
            await _adurable(http, exchange.failed(e, t0))
            raise
        rec = exchange.recording(upstream, t0)
        response = _response(rec.status, rec.headers, _AsyncTeeStream(rec), request)
        if stream and rec.status < 400:
            _watch(http, rec, response)
        else:
            await response.aread()
        return response

    async def aclose(self) -> None:
        pass

    def websocket(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise Unsupported(WEBSOCKETS_UNSUPPORTED)


JOURNALING = (JournalingHttpClient, AsyncJournalingHttpClient)

__all__ = [
    "AsyncJournalingHttpClient",
    "Binding",
    "JOURNALING",
    "JournalingHttpClient",
    "WEBSOCKETS_UNSUPPORTED",
]
