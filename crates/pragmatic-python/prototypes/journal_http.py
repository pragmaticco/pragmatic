"""Prototype: journal Anthropic/OpenAI SDK calls at the HTTP layer.

The SDK client is copied with ``http_client=Journaling(Async)HttpClient``.
Every request the SDK sends (create, create(stream=True), .stream(),
.parse(), tool runners, with_raw_response, framework calls) goes through
``send()``. On record the upstream body is teed into the journal while the
caller consumes it; on replay a response is rebuilt from the journal with
the same status, headers and *byte chunks*, so the SDK builds its own
Stream / MessageStream / ChatCompletionStream / ResponseStream / parsed
objects from identical input. Nothing is duck-typed.

The draw is split-phase (pragmatic's draw_replay / draw_commit /
draw_abort): it opens in send() and commits when the body is fully read or
the caller closes the response early (journaled as complete=false).
"""

from __future__ import annotations

import base64
import datetime
import json
from typing import Any

import httpx2

# Request headers that change what the model sees; everything else
# (auth, x-stainless-*, idempotency keys, retry counts) stays out of the key.
SEMANTIC_REQUEST_HEADERS = ("anthropic-version", "anthropic-beta", "openai-beta")
# Response headers we drop because the journal stores the *decoded* body.
HOP_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}
RETRYABLE = {408, 409, 429}


def canonical(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_key(request: httpx2.Request) -> tuple[str, str]:
    raw = request.read()
    try:
        body: Any = json.loads(raw) if raw else None
    except ValueError:
        body = {"$bytes": base64.b64encode(raw).decode()}
    key = {
        "method": request.method,
        "url": f"{request.url.scheme}://{request.url.host}{request.url.path}",
        "query": sorted(request.url.params.multi_items()),
        "headers": {h: request.headers[h] for h in SEMANTIC_REQUEST_HEADERS if h in request.headers},
        "body": body,
    }
    host = request.url.host
    provider = "anthropic" if "anthropic" in host else "openai" if "openai" in host else host
    model = body.get("model") if isinstance(body, dict) else None
    return canonical(key), (f"{provider}:{model}" if model else provider)


def _retryable(resp: httpx2.Response) -> bool:
    should = resp.headers.get("x-should-retry")
    if should == "true":
        return True
    if should == "false":
        return False
    return resp.status_code in RETRYABLE or resp.status_code >= 500


class _Recording:
    """One open draw. Idempotent: the first of commit/abort wins."""

    def __init__(self, native, prompt: str, provenance: str, resp: httpx2.Response):
        self.native, self.prompt, self.provenance = native, prompt, provenance
        self.status = resp.status_code
        self.headers = [(k, v) for k, v in resp.headers.multi_items() if k.lower() not in HOP_HEADERS]
        self.chunks: list[bytes] = []
        self.state = "open"

    def add(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    def commit(self, complete: bool) -> None:
        if self.state != "open":
            return
        self.state = "committed"
        body = b"".join(self.chunks)
        try:
            body_field: dict = {"text": body.decode("utf-8")}
        except UnicodeDecodeError:
            body_field = {"b64": base64.b64encode(body).decode()}
        outcome = {
            "status": self.status,
            "headers": self.headers,
            **body_field,
            "chunk_sizes": [len(c) for c in self.chunks],  # replay re-chunks identically
            "complete": complete,
        }
        self.native.draw_commit(self.prompt, canonical(outcome), self.provenance)

    def abort(self) -> None:
        if self.state == "open":
            self.state = "aborted"
            self.native.draw_abort()


def _decode_outcome(outcome: str) -> tuple[int, list, list[bytes], bool]:
    o = json.loads(outcome)
    body = o["text"].encode("utf-8") if "text" in o else base64.b64decode(o["b64"])
    chunks, i = [], 0
    for n in o["chunk_sizes"]:
        chunks.append(body[i : i + n])
        i += n
    return o["status"], [tuple(h) for h in o["headers"]], chunks, o["complete"]


class ReplayOverrun(RuntimeError):
    """The agent read past the point where the recorded stream was closed."""


# -- sync -----------------------------------------------------------------


class _TeeStream(httpx2.SyncByteStream):
    def __init__(self, upstream: httpx2.Response, rec: _Recording):
        self._up, self._rec = upstream, rec

    def __iter__(self):
        try:
            for chunk in self._up.iter_bytes():
                self._rec.add(chunk)
                yield chunk
        except GeneratorExit:
            raise
        except BaseException:
            self._rec.abort()  # dropped mid-stream: the step never happened
            raise
        self._rec.commit(complete=True)

    def close(self) -> None:
        self._rec.commit(complete=False)  # no-op if already committed
        self._up.close()

    @property
    def elapsed(self) -> datetime.timedelta:
        return self._up.elapsed


class _ReplayStream(httpx2.SyncByteStream):
    elapsed = datetime.timedelta(0)

    def __init__(self, chunks: list[bytes], complete: bool):
        self._chunks, self._complete = chunks, complete

    def __iter__(self):
        yield from self._chunks
        if not self._complete:
            raise ReplayOverrun("replay read past the end of a stream that was closed early when recorded")


class JournalingHttpClient(httpx2.Client):
    """An httpx2.Client (so the SDK's isinstance check passes) that journals
    each send() and delegates the real I/O to ``inner``."""

    def __init__(self, inner: Any, native: Any):
        super().__init__()
        self._inner, self._native = inner, native

    def send(self, request: httpx2.Request, *, stream: bool = False, **kwargs: Any) -> httpx2.Response:
        prompt, provenance = request_key(request)
        recorded = self._native.draw_replay(prompt)
        if recorded is not None:
            status, headers, chunks, complete = _decode_outcome(recorded)
            resp = httpx2.Response(status, headers=headers, stream=_ReplayStream(chunks, complete), request=request)
        else:
            try:
                up = self._inner.send(request, stream=True, **kwargs)
            except BaseException:
                self._native.draw_abort()
                raise
            if _retryable(up):
                # Let the SDK's retry loop retry; only the outcome it accepts is journaled.
                self._native.draw_abort()
                if not stream:
                    up.read()
                return up
            rec = _Recording(self._native, prompt, provenance, up)
            resp = httpx2.Response(up.status_code, headers=rec.headers, stream=_TeeStream(up, rec), request=request)
        if not stream:
            resp.read()  # non-streaming: commits inside the SDK call
        return resp

    def close(self) -> None:  # the caller owns ``inner``
        pass


# -- async ----------------------------------------------------------------


class _AsyncTeeStream(httpx2.AsyncByteStream):
    def __init__(self, upstream: httpx2.Response, rec: _Recording):
        self._up, self._rec = upstream, rec

    async def __aiter__(self):
        try:
            async for chunk in self._up.aiter_bytes():
                self._rec.add(chunk)
                yield chunk
        except GeneratorExit:
            raise
        except BaseException:
            self._rec.abort()
            raise
        self._rec.commit(complete=True)

    async def aclose(self) -> None:
        self._rec.commit(complete=False)
        await self._up.aclose()

    @property
    def elapsed(self) -> datetime.timedelta:
        return self._up.elapsed


class _AsyncReplayStream(httpx2.AsyncByteStream):
    elapsed = datetime.timedelta(0)

    def __init__(self, chunks: list[bytes], complete: bool):
        self._chunks, self._complete = chunks, complete

    async def __aiter__(self):
        for c in self._chunks:
            yield c
        if not self._complete:
            raise ReplayOverrun("replay read past the end of a stream that was closed early when recorded")


class AsyncJournalingHttpClient(httpx2.AsyncClient):
    def __init__(self, inner: Any, native: Any):
        super().__init__()
        self._inner, self._native = inner, native

    async def send(self, request: httpx2.Request, *, stream: bool = False, **kwargs: Any) -> httpx2.Response:
        prompt, provenance = request_key(request)
        recorded = self._native.draw_replay(prompt)
        if recorded is not None:
            status, headers, chunks, complete = _decode_outcome(recorded)
            resp = httpx2.Response(status, headers=headers, stream=_AsyncReplayStream(chunks, complete), request=request)
        else:
            try:
                up = await self._inner.send(request, stream=True, **kwargs)
            except BaseException:
                self._native.draw_abort()
                raise
            if _retryable(up):
                self._native.draw_abort()
                if not stream:
                    await up.aread()
                return up
            rec = _Recording(self._native, prompt, provenance, up)
            resp = httpx2.Response(up.status_code, headers=rec.headers, stream=_AsyncTeeStream(up, rec), request=request)
        if not stream:
            await resp.aread()
        return resp

    async def aclose(self) -> None:
        pass


# -- entry point ----------------------------------------------------------


def journaled(client: Any, ctx: Any) -> Any:
    """Return a genuine SDK client (same class as ``client``) whose HTTP
    traffic is journaled under ``ctx``. No proxy: isinstance checks pass."""
    is_async = isinstance(client._client, httpx2.AsyncClient) or type(client).__name__.startswith("Async")
    cls = AsyncJournalingHttpClient if is_async else JournalingHttpClient
    return client.copy(http_client=cls(client._client, ctx._native))
