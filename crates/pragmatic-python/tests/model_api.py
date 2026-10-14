"""A fake Anthropic and OpenAI API on ``httpx2.MockTransport``.

The SDKs and the frameworks built on them run unmodified against it. It
serves the Messages, Chat Completions and Responses APIs (JSON, and server
sent events for ``stream: true``, in small irregular chunks so events
straddle chunk boundaries), token counting, tool calls (a request that
offers tools and carries no tool result yet gets a tool call), and
structured output. Every request is counted, so a test can assert that a
replay made no network calls at all, and every streamed body records
whether it was closed.

Failures are scripted with ``fail_next``: an HTTP status, a transport
exception, or a body that breaks after some bytes.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional, Tuple

import httpx2

TEXT_PIECES = ["Hel", "lo, ", "wor", "ld! ", "Durable ", "streams ", "work."]
TEXT = "".join(TEXT_PIECES)
STRUCTURED = '{"city": "Paris", "temp_c": 21}'
ANTHROPIC_MODEL = "claude-sonnet-5-5"
OPENAI_MODEL = "gpt-5.5"


class Upstream:
    """One streamed body, chunked oddly; remembers whether it was closed."""

    def __init__(self, body: bytes, log: list, break_after: Optional[int] = None, exc=None):
        self.chunks = [body[i : i + 37] for i in range(0, len(body), 37)]
        self.closed = False
        self.break_after = break_after
        self.exc = exc
        log.append(self)

    def _gen(self):
        sent = 0
        for c in self.chunks:
            if self.break_after is not None and sent >= self.break_after:
                raise self.exc
            sent += len(c)
            yield c


class SyncUpstream(Upstream, httpx2.SyncByteStream):
    def __iter__(self):
        yield from self._gen()

    def close(self):
        self.closed = True


class AsyncUpstream(Upstream, httpx2.AsyncByteStream):
    async def __aiter__(self):
        for c in self._gen():
            yield c

    async def aclose(self):
        self.closed = True


def sse(events: List[Tuple[Optional[str], Any]]) -> bytes:
    out = []
    for name, data in events:
        payload = data if isinstance(data, str) else json.dumps(data)
        out.append((f"event: {name}\n" if name else "") + f"data: {payload}\n\n")
    return "".join(out).encode()


# -- Anthropic ----------------------------------------------------------------


def anthropic_message(content: list, model: str, stop_reason: str) -> dict:
    return {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 9, "cache_read_input_tokens": 3},
    }


def anthropic_wants_tool(body: dict) -> bool:
    if not body.get("tools"):
        return False
    for message in body.get("messages", []):
        content = message.get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") == "tool_result" for b in content
        ):
            return False
    return True


def anthropic_json(body: dict, text: str) -> dict:
    model = body.get("model", ANTHROPIC_MODEL)
    if anthropic_wants_tool(body):
        tool = body["tools"][0]["name"]
        block = {"type": "tool_use", "id": "toolu_1", "name": tool, "input": {"city": "Paris"}}
        return anthropic_message([block], model, "tool_use")
    return anthropic_message([{"type": "text", "text": text}], model, "end_turn")


def anthropic_sse(body: dict, pieces: List[str]) -> bytes:
    model = body.get("model", ANTHROPIC_MODEL)
    start = anthropic_message([], model, None)
    start["usage"] = {"input_tokens": 12, "output_tokens": 1}
    ev: list = [("message_start", {"type": "message_start", "message": start})]
    ev.append(("content_block_start", {"type": "content_block_start", "index": 0,
                                       "content_block": {"type": "text", "text": ""}}))
    ev.append(("ping", {"type": "ping"}))
    for p in pieces:
        ev.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                                           "delta": {"type": "text_delta", "text": p}}))
    ev.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
    stop = "end_turn"
    if anthropic_wants_tool(body):
        stop = "tool_use"
        tool = body["tools"][0]["name"]
        ev.append(("content_block_start", {"type": "content_block_start", "index": 1,
                                           "content_block": {"type": "tool_use", "id": "toolu_1",
                                                             "name": tool, "input": {}}}))
        for frag in ['{"ci', 'ty": "Par', 'is"}']:
            ev.append(("content_block_delta", {"type": "content_block_delta", "index": 1,
                                               "delta": {"type": "input_json_delta", "partial_json": frag}}))
        ev.append(("content_block_stop", {"type": "content_block_stop", "index": 1}))
    ev.append(("message_delta", {"type": "message_delta",
                                 "delta": {"stop_reason": stop, "stop_sequence": None},
                                 "usage": {"output_tokens": 30}}))
    ev.append(("message_stop", {"type": "message_stop"}))
    return sse(ev)


# -- OpenAI -------------------------------------------------------------------


def chat_wants_tool(body: dict) -> bool:
    if not body.get("tools"):
        return False
    return not any(m.get("role") == "tool" for m in body.get("messages", []))


def chat_completion(body: dict, text: str) -> dict:
    model = body.get("model", OPENAI_MODEL)
    message: dict = {"role": "assistant", "content": text, "refusal": None}
    finish = "stop"
    if chat_wants_tool(body):
        name = body["tools"][0]["function"]["name"]
        message = {"role": "assistant", "content": None, "refusal": None, "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": name, "arguments": '{"city": "Paris"}'}}]}
        finish = "tool_calls"
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1760000000,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish, "logprobs": None}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12,
                  "completion_tokens_details": {"reasoning_tokens": 2}},
    }


def chat_sse(body: dict, pieces: List[str]) -> bytes:
    model = body.get("model", OPENAI_MODEL)
    base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1760000000, "model": model}
    ev: list = [(None, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""},
                                            "finish_reason": None}]})]
    for p in pieces:
        ev.append((None, {**base, "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]}))
    ev.append((None, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}))
    if (body.get("stream_options") or {}).get("include_usage"):
        ev.append((None, {**base, "choices": [],
                          "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}}))
    ev.append((None, "[DONE]"))
    return sse(ev)


def responses_wants_tool(body: dict) -> bool:
    if not body.get("tools"):
        return False
    items = body.get("input")
    if isinstance(items, list):
        return not any(isinstance(i, dict) and i.get("type") == "function_call_output" for i in items)
    return True


def responses_obj(body: dict, text: str, status: str = "completed") -> dict:
    model = body.get("model", OPENAI_MODEL)
    if status == "in_progress":
        output: list = []
    elif responses_wants_tool(body):
        name = body["tools"][0]["name"]
        output = [{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": name,
                   "arguments": '{"city": "Paris"}', "status": "completed"}]
    else:
        output = [{"id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
                   "content": [{"type": "output_text", "text": text, "annotations": []}]}]
    return {
        "id": "resp_1", "object": "response", "created_at": 1760000000, "model": model,
        "status": status, "output": output, "parallel_tool_calls": True, "tool_choice": "auto",
        "tools": [], "error": None, "incomplete_details": None, "instructions": None,
        "metadata": {}, "temperature": 1.0, "top_p": 1.0,
        "usage": None if status == "in_progress" else {
            "input_tokens": 5, "output_tokens": 7, "total_tokens": 12,
            "input_tokens_details": {"cached_tokens": 1}, "output_tokens_details": {"reasoning_tokens": 0}},
    }


def responses_sse(body: dict, pieces: List[str]) -> bytes:
    text = "".join(pieces)
    seq = iter(range(1000))
    ev: list = [("response.created", {"type": "response.created", "sequence_number": next(seq),
                                      "response": responses_obj(body, "", "in_progress")})]
    ev.append(("response.output_item.added", {"type": "response.output_item.added", "sequence_number": next(seq),
                                              "output_index": 0, "item": {"id": "msg_1", "type": "message",
                                                                          "status": "in_progress",
                                                                          "role": "assistant", "content": []}}))
    ev.append(("response.content_part.added", {"type": "response.content_part.added", "sequence_number": next(seq),
                                               "item_id": "msg_1", "output_index": 0, "content_index": 0,
                                               "part": {"type": "output_text", "text": "", "annotations": []}}))
    for p in pieces:
        ev.append(("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": next(seq),
                                                  "item_id": "msg_1", "output_index": 0, "content_index": 0,
                                                  "delta": p, "logprobs": []}))
    ev.append(("response.output_text.done", {"type": "response.output_text.done", "sequence_number": next(seq),
                                             "item_id": "msg_1", "output_index": 0, "content_index": 0,
                                             "text": text, "logprobs": []}))
    ev.append(("response.content_part.done", {"type": "response.content_part.done", "sequence_number": next(seq),
                                              "item_id": "msg_1", "output_index": 0, "content_index": 0,
                                              "part": {"type": "output_text", "text": text, "annotations": []}}))
    final = responses_obj({**body, "tools": []}, text)
    ev.append(("response.output_item.done", {"type": "response.output_item.done", "sequence_number": next(seq),
                                             "output_index": 0, "item": final["output"][0]}))
    ev.append(("response.completed", {"type": "response.completed", "sequence_number": next(seq),
                                      "response": final}))
    return sse(ev)


# -- the server ---------------------------------------------------------------


class ModelAPI:
    """The fake API. ``calls`` lists ``(path, body)`` of every request that
    reached it; ``upstreams`` every streamed body."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, dict]] = []
        self.upstreams: List[Upstream] = []
        self.faults: List[Any] = []

    def fail_next(self, *faults: Any) -> None:
        """Serve these before anything else, one per request: an
        ``httpx2.Response`` (an error status), an exception (raised as a
        transport failure), or ``("break", n_bytes, exception)`` (a normal
        streamed body that raises after ``n_bytes``)."""
        self.faults.extend(faults)

    def _structured(self, body: dict) -> bool:
        return bool((body.get("output_config") or {}).get("format") or body.get("response_format")
                    or (body.get("text") or {}).get("format"))

    def respond(self, request: httpx2.Request, is_async: bool) -> httpx2.Response:
        body = json.loads(request.content or b"{}")
        path = request.url.path
        self.calls.append((path, body))
        brk = None
        if self.faults:
            fault = self.faults.pop(0)
            if isinstance(fault, httpx2.Response):
                return fault
            if isinstance(fault, BaseException):
                raise fault
            brk = fault
        pieces = [STRUCTURED] if self._structured(body) else TEXT_PIECES
        text = "".join(pieces)
        stream_cls = AsyncUpstream if is_async else SyncUpstream

        def streamed(data: bytes, headers: dict) -> httpx2.Response:
            kwargs = {"break_after": brk[1], "exc": brk[2]} if brk else {}
            return httpx2.Response(200, headers={**headers, "content-type": "text/event-stream"},
                                   stream=stream_cls(data, self.upstreams, **kwargs))

        if path.endswith("/v1/messages/count_tokens"):
            return httpx2.Response(200, headers={"request-id": "req_count"}, json={"input_tokens": 12})
        if path.endswith("/v1/responses/input_tokens"):
            return httpx2.Response(200, headers={"x-request-id": "req_count"},
                                   json={"object": "response.input_tokens", "input_tokens": 12})
        if path.endswith("/v1/messages"):
            headers = {"request-id": "req_ant_1", "anthropic-ratelimit-requests-remaining": "99"}
            if body.get("stream"):
                return streamed(anthropic_sse(body, pieces), headers)
            return httpx2.Response(200, headers=headers, json=anthropic_json(body, text))
        if path.endswith("/chat/completions"):
            headers = {"x-request-id": "req_oai_chat_1", "x-ratelimit-remaining-requests": "99"}
            if body.get("stream"):
                return streamed(chat_sse(body, pieces), headers)
            return httpx2.Response(200, headers=headers, json=chat_completion(body, text))
        if path.endswith("/responses"):
            headers = {"x-request-id": "req_oai_resp_1"}
            if body.get("stream"):
                return streamed(responses_sse(body, pieces), headers)
            return httpx2.Response(200, headers=headers, json=responses_obj(body, text))
        return httpx2.Response(404, json={"error": {"message": f"no route {path}"}})

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(lambda r: self.respond(r, False))

    def async_transport(self) -> httpx2.MockTransport:
        async def handler(r: httpx2.Request) -> httpx2.Response:
            return self.respond(r, True)

        return httpx2.MockTransport(handler)

    def http_client(self, is_async: bool) -> Any:
        if is_async:
            return httpx2.AsyncClient(transport=self.async_transport())
        return httpx2.Client(transport=self.transport())

    def client(self, provider: str, is_async: bool, **kwargs: Any) -> Any:
        """An SDK client of ``provider`` that talks to this API."""
        kwargs.setdefault("api_key", "sk-test")
        http_client = self.http_client(is_async)
        if provider == "anthropic":
            import anthropic

            cls = anthropic.AsyncAnthropic if is_async else anthropic.Anthropic
        else:
            import openai

            cls = openai.AsyncOpenAI if is_async else openai.OpenAI
        return cls(http_client=http_client, **kwargs)
