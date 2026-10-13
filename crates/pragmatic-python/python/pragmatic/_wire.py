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
  more) and can be erased once. A record holds at most 255 slots, so a
  longer conversation is stored in chunks: ``{"$parts": n, "$chunk": g}``
  says that ``n`` elements follow as JSON arrays of ``g`` (a power of two,
  the smallest that fits), and a chunk of earlier messages stays the same
  from call to call, so it is still stored once. Transport headers
  (authorization, API keys, retry counts, idempotency keys, user agents)
  are never recorded, and neither are the credentials some bodies carry
  for MCP servers (``CREDENTIAL_CONTAINERS``): their values are replaced by
  ``<credential>`` before the request is recorded or matched.
- **Multipart bodies** (file uploads, transcriptions, image edits) are
  recorded as sent, except that the boundary, which the HTTP client draws
  at random for every request, is replaced by ``MULTIPART_BOUNDARY``: the
  same upload then matches on replay.
- **Response head.** ``{"status", "headers"}`` with only the headers that
  shape what the SDK does with the response: ``content-type``, the request
  ids, the workspace id, and the retry hints. Rate-limit and other headers
  are dropped. A retry hint given as an HTTP date is also recorded as the
  delay it meant when the response arrived (``retry_after``), since the
  date means something else by the time the run is replayed.
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

import email.utils
import json
import math
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
    {
        "content-type",
        "request-id",
        "x-request-id",
        "anthropic-workspace-id",
        "retry-after",
        "retry-after-ms",
        "x-should-retry",
    }
)
"""Response headers kept in the head: what the SDKs read to parse, identify
(the request id, and the workspace id the Anthropic SDK exposes as
``_workspace_id``) and retry a response."""

OPENAI_MAX_RETRY_AFTER_SECS = 120.0
"""The longest retry hint the OpenAI SDK waits for (``MAX_RETRY_AFTER_DELAY``):
a longer one makes it give up instead of retrying. The Anthropic SDK has no
such ceiling."""

SLOT_LIMIT = 255
"""The most slots one record holds (spec 2.15)."""

MULTIPART_BOUNDARY = "pragmatic-multipart-boundary"
"""What a multipart body's boundary is replaced with in the journal."""

CREDENTIAL_CONTAINERS = ("tools", "mcp_servers")
"""Request body lists whose elements may carry credentials: Anthropic
``mcp_servers[*].authorization_token``, and OpenAI Responses MCP tools'
``tools[*].authorization`` and ``tools[*].headers``."""

CREDENTIAL = "<credential>"
"""What a credential in a request body is replaced with."""

_MARKER = "$parts"
_CHUNK = "$chunk"


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


def _credential_member(name: str) -> bool:
    """A member of a tool or MCP server definition that holds a credential:
    ``authorization``, ``api_key``, ``password``, ``secret``, ``token`` and
    names ending in ``_token``, ``_secret``, ``_key`` or ``_password``."""
    lowered = name.lower()
    return lowered in ("authorization", "api_key", "apikey", "password", "secret", "token") or (
        lowered.endswith(("_token", "_secret", "_key", "_password"))
    )


def _redacted_definition(item: Any) -> Any:
    """One tool or MCP server definition with its credentials replaced (the
    same object when it has none)."""
    if not isinstance(item, dict):
        return item
    out = None
    for name, value in item.items():
        if value is None:
            continue
        if name.lower() == "headers" and isinstance(value, dict):
            replaced: Any = {k: (CREDENTIAL if v is not None else v) for k, v in value.items()}
        elif _credential_member(name) and value != CREDENTIAL:
            replaced = CREDENTIAL
        else:
            continue
        if replaced == value:
            continue
        if out is None:
            out = dict(item)
        out[name] = replaced
    return item if out is None else out


def redact_credentials(body: Any) -> Any:
    """``body`` with the credentials of its tool and MCP server definitions
    replaced by ``CREDENTIAL`` (see ``CREDENTIAL_CONTAINERS``). Bearer
    tokens for MCP servers expire within the hour: in the journal they
    would leak, and a replay holding a fresh one would never match. Only
    the definitions themselves are looked at, never a tool's input schema.
    The body passed in is never modified."""
    if not isinstance(body, dict):
        return body
    out = None
    for key in CREDENTIAL_CONTAINERS:
        items = body.get(key)
        if not isinstance(items, list):
            continue
        redacted = [_redacted_definition(item) for item in items]
        if any(a is not b for a, b in zip(redacted, items)):
            if out is None:
                out = dict(body)
            out[key] = redacted
    return body if out is None else out


_BOUNDARY = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.IGNORECASE)


def canonical_multipart(content: bytes, content_type: str) -> Optional[bytes]:
    """A multipart body with its boundary replaced by
    ``MULTIPART_BOUNDARY``, or ``None`` when ``content_type`` names no
    multipart boundary. The boundary is random per request and must not
    occur anywhere inside the parts, so the replacement changes nothing
    else."""
    if not content_type.lower().startswith("multipart/"):
        return None
    m = _BOUNDARY.search(content_type)
    if m is None:
        return None
    boundary = (m.group(1) or m.group(2) or "").strip()
    try:
        raw = boundary.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not raw:
        return None
    return content.replace(raw, MULTIPART_BOUNDARY.encode("ascii"))


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
        sent. A JSON body's credentials are replaced (``redact_credentials``)
        and a multipart body's boundary is made canonical
        (``canonical_multipart``)."""
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
                body = redact_credentials(json.loads(content))
            except (ValueError, UnicodeDecodeError):
                head["raw_body"] = True
                raw = bytes(content)
                canonical = canonical_multipart(raw, headers.get("content-type") or "")
                if canonical is not None:
                    head["boundary"] = MULTIPART_BOUNDARY
                    raw = canonical
        return cls(head, body, raw)

    def parts(self, body: Any = None, *, use: bool = False) -> List[bytes]:
        """The request parts: of this request's body, or of ``body`` when
        ``use`` is set (the normalized body)."""
        extra = [self.raw] if self.raw is not None else []
        return split(self.head, body if use else self.body, extra)


def chunk_size(counts: Sequence[int], budget: int) -> int:
    """How many list elements go in one part: 1 while every element fits in
    a part of its own within ``budget`` parts, otherwise the smallest power
    of two that makes them fit. Chunk boundaries depend on nothing but the
    element index and this size, so a chunk of earlier messages encodes the
    same way on the next call of a growing conversation."""
    if sum(counts) <= budget:
        return 1
    size = 2
    while sum(-(-n // size) for n in counts) > budget:
        size *= 2
    return size


def split(head: Dict[str, Any], body: Any, extra: Sequence[bytes] = ()) -> List[bytes]:
    """Part 0 (``head`` plus the body with its message lists replaced by
    markers), one part per message (or per chunk of messages, see
    ``chunk_size``), then ``extra`` as they are."""
    elements: List[bytes] = []
    shown = body
    lists: List[Tuple[str, List[Any]]] = []
    if isinstance(body, dict):
        shown = dict(body)
        lists = [(k, body[k]) for k in SPLIT_KEYS if isinstance(body.get(k), list)]
    size = chunk_size([len(v) for _, v in lists], SLOT_LIMIT - 1 - len(extra))
    for key, value in lists:
        if size == 1:
            shown[key] = {_MARKER: len(value)}
            elements.extend(dumps(v) for v in value)
        else:
            shown[key] = {_CHUNK: size, _MARKER: len(value)}
            elements.extend(dumps(value[i : i + size]) for i in range(0, len(value), size))
    part0 = dict(head)
    part0["body"] = shown
    return [dumps(part0), *elements, *extra]


def _elements(marker: Any, rest: List[bytes]) -> Optional[Tuple[List[Any], int]]:
    """The list a ``split`` marker stands for, rebuilt from the parts that
    follow, and how many parts it took; ``None`` if ``marker`` is not a
    marker or the parts do not fit it."""
    if not isinstance(marker, dict) or _MARKER not in marker or not set(marker) <= {_MARKER, _CHUNK}:
        return None
    n, size = marker[_MARKER], marker.get(_CHUNK, 1)
    if not isinstance(n, int) or not isinstance(size, int) or n < 0 or size < 1:
        return None
    count = n if size == 1 else -(-n // size)
    if count > len(rest):
        return None
    try:
        decoded = [json.loads(p) for p in rest[:count]]
    except (ValueError, UnicodeDecodeError):
        return None
    if size == 1:
        return decoded, count
    items: List[Any] = []
    for chunk in decoded:
        if not isinstance(chunk, list):
            return None
        items.extend(chunk)
    return (items, count) if len(items) == n else None


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
            if not isinstance(marker, dict):
                continue
            found = _elements(marker, rest)
            if found is None:
                return None
            body[key], used = found
            rest = rest[used:]
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


def head_bytes(
    status: int,
    headers: List[List[str]],
    error: Optional[str] = None,
    retry_after: Optional[float] = None,
) -> bytes:
    """The head slot. ``error`` is the message of a failure that cut the
    body short (the read raised), replayed after the recorded bytes.
    ``retry_after`` is the delay an HTTP-date retry hint meant when the
    response arrived (see ``dated_retry_delay``)."""
    head: Dict[str, Any] = {"headers": headers, "status": status}
    if error is not None:
        head["error"] = error
    if retry_after is not None:
        head["retry_after"] = retry_after
    return dumps(head)


def _numeric_retry_delay(found: Dict[str, str]) -> Optional[float]:
    for name, scale in (("retry-after-ms", 1000.0), ("retry-after", 1.0)):
        value = found.get(name)
        if value is None:
            continue
        try:
            return float(value) / scale
        except ValueError:
            continue
    return None


def retry_delay(headers: List[List[str]]) -> Optional[float]:
    """The delay a response's numeric retry hints ask for, in seconds, read
    the way both SDKs read them: ``retry-after-ms`` first, then
    ``retry-after`` as seconds; ``None`` without one."""
    return _numeric_retry_delay({k: v for k, v in headers})


def dated_retry_delay(headers: List[List[str]], now: float) -> Optional[float]:
    """The delay, from ``now`` (Unix seconds), of a ``retry-after`` given as
    an HTTP date and no numeric hint, as the SDKs compute it; ``None`` for
    any other response. Recorded in the head, since replay happens at
    another time."""
    found = {k: v for k, v in headers}
    if _numeric_retry_delay(found) is not None:
        return None
    value = found.get("retry-after")
    if value is None:
        return None
    try:
        parsed = email.utils.parsedate_tz(value)
        if parsed is None:
            return None
        return float(email.utils.mktime_tz(parsed) - now)
    except (TypeError, ValueError, OverflowError):
        return None


def sdk_may_retry(status: int, headers: List[List[str]]) -> bool:
    """Whether the SDKs would consider retrying a response with ``status``
    and ``headers`` (their ``_should_retry``, before any retry hint):
    ``x-should-retry`` decides when present, otherwise 408, 409, 429 and
    5xx are retried."""
    flag = {k: v for k, v in headers}.get("x-should-retry")
    if flag == "true":
        return True
    if flag == "false":
        return False
    return status in (408, 409, 429) or status >= 500


def replay_headers(
    headers: List[List[str]], status: int, provider: str, recorded_delay: Optional[float] = None
) -> List[List[str]]:
    """The headers an error response is replayed with, so that the SDK's
    retry decision is the recorded one and its wait is a millisecond:

    - a response the SDK would not retry is served as recorded;
    - ``retry-after-ms: 1`` otherwise (both SDKs read it first, and treat a
      hint of 0 as none at all and fall back to their own backoff);
    - except when the OpenAI SDK refused to retry because the hint was over
      its ceiling (``OPENAI_MAX_RETRY_AFTER_SECS``): a numeric hint is then
      served as recorded, and an HTTP-date one (which by now lies in the
      past) as the ``retry-after-ms`` it meant when it was recorded
      (``recorded_delay``), so the SDK refuses again. Refused, it waits for
      nothing.

    The Anthropic SDK retries whatever the hint, so its replays always get
    the 1 ms hint."""
    if status < 400 or not sdk_may_retry(status, headers):
        return headers
    delay = recorded_delay if recorded_delay is not None else retry_delay(headers)
    if provider == "openai" and delay is not None and delay > OPENAI_MAX_RETRY_AFTER_SECS:
        if recorded_delay is None:
            return headers
        millis = str(math.ceil(recorded_delay * 1000))
        return [h for h in headers if h[0] != "retry-after-ms"] + [["retry-after-ms", millis]]
    return [h for h in headers if h[0] != "retry-after-ms"] + [["retry-after-ms", "1"]]


_QUOTED_HEADER = re.compile(
    r"""(headers?\s+(?:name|value)s?\s*:?\s*)(b?'(?:[^'\\]|\\.)*'|b?"(?:[^"\\]|\\.)*")""",
    re.IGNORECASE,
)
_REDACTED = "<redacted>"


def _secrets(value: str) -> List[str]:
    """The forms a credential header's value can take inside a message:
    whole, stripped, and each long word (``Bearer sk-...`` quotes the
    key)."""
    found = {value, value.strip()}
    found.update(word for word in value.split() if len(word) >= 8)
    return sorted((s for s in found if len(s) >= 4), key=len, reverse=True)


def scrub_message(message: str, request_headers: Iterable[Tuple[str, str]]) -> str:
    """A transport error's message, safe to journal: quoted header names and
    values are cut out (h11 quotes the offending value, so a key read from
    a file with its trailing newline would land in the journal whole), and
    so is every value of a request header named like a credential
    (``authorization``, ``x-api-key``, ``api-key``, cookies)."""
    out = _QUOTED_HEADER.sub(lambda m: m.group(1) + _REDACTED, message)
    for name, value in request_headers:
        lowered = name.lower()
        if not (_credential(lowered) or lowered in ("cookie", "set-cookie")):
            continue
        for secret in _secrets(value):
            out = out.replace(secret, _REDACTED)
    return out


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
    """The transport class of a failed exchange: ``cancelled`` (the caller's
    task was cancelled and carried on), ``timeout``, ``connect`` or
    ``protocol`` (anything else that broke the exchange)."""
    names = {c.__name__ for c in type(exc).__mro__}
    if "CancelledError" in names:
        return "cancelled"
    if "TimeoutException" in names or isinstance(exc, TimeoutError):
        return "timeout"
    if "ConnectError" in names or isinstance(exc, ConnectionError):
        return "connect"
    return "protocol"

