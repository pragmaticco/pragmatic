"""What one journaled HTTP exchange records (spec 6.5).

Every request a journaled model client sends is a draw:

- **Request parts.** Part 0 is the canonical JSON of ``{"method", "path",
  "query", "headers", "body"}``: the query as sorted ``[name, value]``
  pairs (without parameters named like credentials), ``headers`` only the
  ones that change what the API does
  (``anthropic-version``, ``anthropic-beta``, ``openai-beta``), and the
  body without ``messages`` and ``input``. Each element of those lists is
  a part of its own, after part 0, and the list itself is replaced in part
  0 by ``{"$parts": n}`` so part 0 says which parts follow. A conversation
  resends its earlier messages with every call; as parts of their own they
  are stored once (the core deduplicates identical slots of 256 bytes or
  more) and can be erased once. Transport headers (authorization, API
  keys, retry counts, idempotency keys, user agents) are never recorded.
- **Response head.** ``{"status", "headers"}`` with only the headers that
  shape what the SDK does with the response: ``content-type``, the request
  ids, and the retry hints. Rate-limit and other headers are dropped.
- **Response body.** The bytes as the caller read them (decoded from any
  content encoding).
- **Meta.** ``outcome``, ``status``, ``provider``, ``model``,
  ``stop_reason``, ``usage`` and ``latency_ms``, extracted from the body or
  the stream's events. Meta is a structural field: it never holds content.

Canonical JSON (sorted keys, no insignificant whitespace) is a stable
re-encoding of the wire body: the same call always encodes to the same
parts, whatever order the SDK wrote the keys in.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

SPLIT_KEYS = ("messages", "input")
"""Body members whose list elements become parts of their own."""

SEMANTIC_HEADERS = ("anthropic-version", "anthropic-beta", "openai-beta")
"""Request headers that select API behavior, recorded in part 0."""

CREDENTIAL_QUERY_WORDS = ("key", "token", "secret", "sig", "password", "auth", "credential")
"""A query parameter whose name contains one of these is left out of part 0:
gateways that take credentials in the URL would otherwise put them in the
journal. Leaving them out also keeps them out of replay matching, where a
rotated credential has no business causing a desync."""

RESPONSE_HEADERS = frozenset(
    {"content-type", "request-id", "x-request-id", "retry-after", "retry-after-ms", "x-should-retry"}
)
"""Response headers kept in the head: what the SDKs read to parse, identify
and retry a response."""

RETRY_REWRITE_LIMIT_SECS = 60.0
"""A recorded retry hint longer than this is replayed as recorded (see
``replay_headers``)."""

_MARKER = "$parts"


def dumps(value: Any) -> bytes:
    """Canonical JSON as UTF-8. Lone surrogates (which JSON can carry) are
    kept as their code units rather than refused."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8", "surrogatepass")


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _credential(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in CREDENTIAL_QUERY_WORDS)


class Request:
    """The parts of an HTTP request that a draw records.

    ``body`` is the parsed JSON body (``None`` without one), and ``raw`` the
    body bytes when they are not JSON (a multipart upload), recorded as a
    final part as they are."""

    __slots__ = ("head", "body", "raw", "model")

    def __init__(self, head: Dict[str, Any], body: Any, raw: Optional[bytes]):
        self.head = head
        self.body = body
        self.raw = raw
        model = body.get("model") if isinstance(body, dict) else None
        self.model = model if isinstance(model, str) else None

    @classmethod
    def parse(cls, method: str, path: str, query: Iterable[Tuple[str, str]],
              headers: Any, content: bytes) -> "Request":
        """``headers`` is any mapping with ``get``; ``content`` the body as
        sent."""
        semantic = {h: headers.get(h) for h in SEMANTIC_HEADERS if headers.get(h) is not None}
        head = {
            "headers": semantic,
            "method": method.upper(),
            "path": path,
            "query": sorted([k, v] for k, v in query if not _credential(k)),
        }
        body: Any = None
        raw: Optional[bytes] = None
        if content:
            try:
                body = json.loads(content)
            except (ValueError, UnicodeDecodeError):
                head["raw_body"] = True
                raw = bytes(content)
        return cls(head, body, raw)

    def parts(self, body: Any = None, *, use: bool = False) -> List[bytes]:
        """The request parts: of this request's body, or of ``body`` when
        ``use`` is set (the normalized body)."""
        extra = [self.raw] if self.raw is not None else []
        return split(self.head, body if use else self.body, extra)


def split(head: Dict[str, Any], body: Any, extra: Sequence[bytes] = ()) -> List[bytes]:
    """Part 0 (``head`` plus the body with its message lists replaced by
    markers), one part per message, then ``extra`` as they are."""
    elements: List[bytes] = []
    shown = body
    if isinstance(body, dict):
        shown = dict(body)
        for key in SPLIT_KEYS:
            value = body.get(key)
            if isinstance(value, list):
                shown[key] = {_MARKER: len(value)}
                elements.extend(dumps(v) for v in value)
    part0 = dict(head)
    part0["body"] = shown
    return [dumps(part0), *elements, *extra]


def join(parts: Sequence[bytes]) -> Optional[Tuple[Dict[str, Any], Any, List[bytes]]]:
    """The inverse of ``split``: ``(head, body, extra parts)``, or ``None``
    when the parts were not written by ``split`` (a ``ctx.draw`` prompt)."""
    if not parts:
        return None
    try:
        part0 = json.loads(parts[0])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(part0, dict) or "body" not in part0 or "method" not in part0:
        return None
    body = part0.pop("body")
    rest = list(parts[1:])
    if isinstance(body, dict):
        body = dict(body)
        for key in SPLIT_KEYS:
            marker = body.get(key)
            if isinstance(marker, dict) and set(marker) == {_MARKER}:
                n = marker[_MARKER]
                if not isinstance(n, int) or n < 0 or n > len(rest):
                    return None
                try:
                    body[key] = [json.loads(p) for p in rest[:n]]
                except (ValueError, UnicodeDecodeError):
                    return None
                rest = rest[n:]
    return part0, body, rest


def normalized_parts(parts: Sequence[bytes], normalizer: Any) -> List[bytes]:
    """``parts`` with the normalizer's rules applied to the body they
    encode; parts ``split`` did not write come back unchanged."""
    joined = join(parts)
    if joined is None:
        return list(parts)
    head, body, extra = joined
    body, _ = normalizer(body)
    return split(head, body, extra)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


def kept_headers(items: Iterable[Tuple[str, str]]) -> List[List[str]]:
    """The response headers a head keeps, names lowercased, in order."""
    return [[k.lower(), v] for k, v in items if k.lower() in RESPONSE_HEADERS]


def head_bytes(status: int, headers: List[List[str]], error: Optional[str] = None) -> bytes:
    """The head slot. ``error`` is the message of a failure that cut the
    body short (the read raised), replayed after the recorded bytes."""
    head: Dict[str, Any] = {"headers": headers, "status": status}
    if error is not None:
        head["error"] = error
    return dumps(head)


def _retry_delay(headers: List[List[str]]) -> Optional[float]:
    """The delay a response's retry hints ask for, in seconds, read the way
    the SDKs read them (``retry-after-ms`` first); ``None`` if unknown."""
    found = dict((k, v) for k, v in headers)
    for name, scale in (("retry-after-ms", 1000.0), ("retry-after", 1.0)):
        value = found.get(name)
        if value is None:
            continue
        try:
            return float(value) / scale
        except ValueError:
            return None
    return None


def replay_headers(headers: List[List[str]], status: int) -> List[List[str]]:
    """The headers an error response is replayed with: ``retry-after-ms:
    1``, so an SDK that retries it waits a millisecond, not the recorded
    delay. Both SDKs treat a hint of 0 as no hint and fall back to their
    own exponential backoff, so the hint is the smallest positive one.

    A recorded hint over ``RETRY_REWRITE_LIMIT_SECS`` is kept: an SDK may
    refuse to retry past a ceiling of its own (the OpenAI SDK's is two
    minutes), and a shorter hint could turn that refusal into a retry the
    recording never made."""
    if status < 400:
        return headers
    delay = _retry_delay(headers)
    if delay is not None and delay > RETRY_REWRITE_LIMIT_SECS:
        return headers
    return [h for h in headers if h[0] != "retry-after-ms"] + [["retry-after-ms", "1"]]


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

_USAGE = (
    ("input_tokens", "input_tokens"),
    ("prompt_tokens", "input_tokens"),
    ("output_tokens", "output_tokens"),
    ("completion_tokens", "output_tokens"),
    ("cache_read_input_tokens", "cache_read_tokens"),
    ("cache_creation_input_tokens", "cache_write_tokens"),
)
_USAGE_DETAILS = (
    ("input_tokens_details", "cached_tokens", "cache_read_tokens"),
    ("prompt_tokens_details", "cached_tokens", "cache_read_tokens"),
    ("output_tokens_details", "reasoning_tokens", "reasoning_tokens"),
    ("completion_tokens_details", "reasoning_tokens", "reasoning_tokens"),
)
_FINAL_STATUSES = frozenset({"completed", "incomplete", "failed", "cancelled"})


def _count(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def usage_of(usage: Dict[str, Any]) -> Dict[str, int]:
    """A provider's usage object in the meta's counter names (spec 2.6)."""
    out: Dict[str, int] = {}
    for src, dst in _USAGE:
        n = _count(usage.get(src))
        if n is not None:
            out[dst] = n
    for outer, inner, dst in _USAGE_DETAILS:
        details = usage.get(outer)
        if isinstance(details, dict):
            n = _count(details.get(inner))
            if n is not None:
                out[dst] = n
    return out


def _sse_events(body: bytes) -> Iterator[Any]:
    """The JSON data of each server-sent event in ``body``."""
    text = body.decode("utf-8", "replace")
    for block in re.split(r"\r?\n\r?\n", text):
        data = []
        for line in block.splitlines():
            if line.startswith("data:"):
                value = line[5:]
                data.append(value[1:] if value.startswith(" ") else value)
        if not data:
            continue
        payload = "\n".join(data)
        if payload.strip() == "[DONE]":
            continue
        try:
            yield json.loads(payload)
        except ValueError:
            continue


TERMINAL_EVENTS = frozenset(
    {"message_stop", "response.completed", "response.incomplete", "response.failed", "error"}
)
"""Event types after which a provider sends nothing more."""


def ended(body: bytes, content_type: str) -> bool:
    """Whether ``body`` is a whole response although it was closed before
    the connection ended: an event stream whose last event is a provider's
    terminal one (``data: [DONE]``, ``message_stop``,
    ``response.completed`` and the like), or a complete JSON document. The
    OpenAI SDK stops reading at ``[DONE]`` and closes the response without
    waiting for the end of the body, and that is no early close."""
    if "text/event-stream" in content_type:
        text = body.decode("utf-8", "replace").rstrip()
        if text.endswith("data: [DONE]") or text.endswith("data:[DONE]"):
            return True
        last = None
        for last in _sse_events(body):
            pass
        return isinstance(last, dict) and last.get("type") in TERMINAL_EVENTS
    try:
        json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def _documents(body: bytes, content_type: str) -> Iterator[Any]:
    if "text/event-stream" in content_type:
        yield from _sse_events(body)
        return
    try:
        yield json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return


def _stop_reason(obj: Dict[str, Any]) -> Optional[str]:
    stop = obj.get("stop_reason")
    if isinstance(stop, str):
        return stop
    choices = obj.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if isinstance(choice, dict) and isinstance(choice.get("finish_reason"), str):
                return choice["finish_reason"]
    if obj.get("object") == "response":
        details = obj.get("incomplete_details")
        if isinstance(details, dict) and isinstance(details.get("reason"), str):
            return details["reason"]
        status = obj.get("status")
        if status in _FINAL_STATUSES:
            return status
    return None


def summarize(body: bytes, content_type: str) -> Tuple[Optional[str], Optional[str], Dict[str, int]]:
    """``(model, stop_reason, usage)`` from a JSON body or an event stream.
    Later events win, which is how both providers report: Anthropic's
    ``message_delta`` carries the final stop reason and output tokens, and
    OpenAI's last chunk or ``response.completed`` event the usage."""
    model: Optional[str] = None
    stop: Optional[str] = None
    usage: Dict[str, int] = {}
    for doc in _documents(body, content_type):
        if not isinstance(doc, dict):
            continue
        for obj in (doc, doc.get("message"), doc.get("response"), doc.get("delta")):
            if not isinstance(obj, dict):
                continue
            if isinstance(obj.get("model"), str) and obj["model"]:
                model = obj["model"]
            if isinstance(obj.get("usage"), dict):
                usage.update(usage_of(obj["usage"]))
            found = _stop_reason(obj)
            if found is not None:
                stop = found
    return model, stop, usage


def meta(
    outcome: str,
    *,
    provider: str,
    status: Optional[int] = None,
    body: bytes = b"",
    content_type: str = "",
    request_model: Optional[str] = None,
    latency_ms: Optional[int] = None,
    error: Optional[BaseException] = None,
    error_type: Optional[str] = None,
) -> str:
    """The DrawResult meta of one exchange, as strict JSON (spec 2.6)."""
    doc: Dict[str, Any] = {"outcome": outcome, "provider": provider}
    if status is not None:
        doc["status"] = status
    if latency_ms is not None:
        doc["latency_ms"] = latency_ms
    if status is not None and status < 400 and body:
        model, stop, usage = summarize(body, content_type)
    else:
        model, stop, usage = None, None, {}
    model = model or request_model
    if model:
        doc["model"] = model
    if stop:
        doc["stop_reason"] = stop
    if usage:
        doc["usage"] = usage
    if error is not None:
        doc["error_kind"] = error_kind(error)
        doc["error_type"] = error_type or ""
    return dumps(doc).decode("utf-8")


def error_kind(exc: BaseException) -> str:
    """The transport class of a failed exchange: ``timeout``, ``connect``
    or ``protocol`` (anything else that broke the exchange)."""
    names = {c.__name__ for c in type(exc).__mro__}
    if "TimeoutException" in names or isinstance(exc, TimeoutError):
        return "timeout"
    if "ConnectError" in names or isinstance(exc, ConnectionError):
        return "connect"
    return "protocol"

