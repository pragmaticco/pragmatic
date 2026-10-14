"""The support agent of the end-to-end story, and the world around it.

The agent handles a refund request the way a customer support agent built
on the real SDKs would:

1. Claude (the Anthropic SDK) reads the ticket and calls the
   ``issue_refund`` tool;
2. ``ctx.run_tools`` performs the refund at the payment provider;
3. Claude writes the reply to the customer, streamed;
4. GPT (the OpenAI SDK) writes the internal case note.

Both SDK clients are journaled with ``ctx.wrap``. Their HTTP goes to
``ScriptedModels`` on an ``httpx2.MockTransport``, so nothing leaves this
machine, and every request that would have reached a provider (and been
paid for) is written to ``model-calls.jsonl``. Every perform of the refund
tool is written to ``tool-calls.jsonl``, and every refund the provider
issues to ``payments.jsonl``: the story counts all three across processes.

Run as a program, it is one process of the story, talking to Pragmatic
Server through ``PRAGMATIC_URL`` and ``PRAGMATIC_TOKEN``:

    python support_agent.py MODE RUN_ID WORK [--crash-in-refund] [--gate CALL:NAME]

``MODE`` is ``run`` (start the run), ``resume`` (resume it with the
recovery policy, waiting out the lease of a writer that died holding it)
or ``contend`` (resume it once, and report a run another writer holds).
``--crash-in-refund`` ends the process with ``os._exit`` right after the
payment provider issued the refund, before the tool's result is recorded.
``--gate CALL:NAME`` pauses at the first ``CALL`` (``claude``,
``claude.stream`` or ``gpt``) that reaches the model API: the process
writes ``WORK/NAME.ready`` and waits for ``WORK/NAME.go``. The process
prints one JSON line saying how it ended.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import anthropic
import httpx2
import openai

import pragmatic

CLAUDE = "claude-sonnet-5-5"
GPT = "gpt-5.5"
CRASH_EXIT = 17
GATE_TIMEOUT = 300.0

SYSTEM = (
    "You are the support agent of an online shop. Refund orders that arrived damaged "
    "with issue_refund, then answer the customer."
)
NOTE_PROMPT = "Write a one-line internal case note for the CRM about this support reply."
TOOLS = [
    {
        "name": "issue_refund",
        "description": "Refund an order to the customer's card.",
        "input_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount_usd": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["order_id", "amount_usd", "reason"],
        },
    }
]


@dataclass(frozen=True)
class Ticket:
    customer: str
    email: str
    customer_id: str
    order_id: str
    amount_usd: float

    @property
    def message(self) -> str:
        return (
            f"Hi, this is {self.customer} ({self.email}). My order {self.order_id} "
            f"(${self.amount_usd:.2f}) arrived damaged. Can I get a refund?"
        )


TICKETS = {
    "support:ticket-4127": Ticket("Jane Doe", "jane.doe@example.com", "customer-8812", "A-1001", 49.00),
    "support:ticket-4128": Ticket("Sam Lee", "sam.lee@example.com", "customer-9120", "A-1002", 19.50),
}


def _append_line(path: Path, doc: Dict[str, Any]) -> None:
    # One write per line on a file opened for appending: lines from
    # different processes never interleave.
    with open(path, "a") as f:
        f.write(json.dumps(doc, sort_keys=True) + "\n")


def read_lines(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# -- the payment provider -------------------------------------------------------


class Payments:
    """A payment provider that deduplicates by idempotency key, as real
    ones do, and that a recovery policy can ask what it did."""

    def __init__(self, work: Path):
        self.ledger = work / "payments.jsonl"

    def refund(self, order_id: str, amount_usd: float, idempotency_key: str) -> Dict[str, Any]:
        for r in read_lines(self.ledger):
            if r["idempotency_key"] == idempotency_key:
                return r
        refund_id = "re_" + hashlib.sha256(idempotency_key.encode()).hexdigest()[:12]
        receipt = {
            "refund_id": refund_id,
            "order_id": order_id,
            "amount_usd": amount_usd,
            "status": "succeeded",
            "idempotency_key": idempotency_key,
        }
        _append_line(self.ledger, receipt)
        return receipt

    def find(self, order_id: str) -> Optional[Dict[str, Any]]:
        for r in read_lines(self.ledger):
            if r["order_id"] == order_id:
                return r
        return None


# -- the model APIs -------------------------------------------------------------


class _Chunks(httpx2.SyncByteStream):
    """A streamed body in small chunks, so events straddle reads."""

    def __init__(self, body: bytes):
        self.body = body

    def __iter__(self) -> Iterator[bytes]:
        for i in range(0, len(self.body), 41):
            yield self.body[i : i + 41]


def _sse(events: List[Tuple[str, Dict[str, Any]]]) -> bytes:
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()


def _last_tool_result(body: Dict[str, Any]) -> Dict[str, Any]:
    for message in reversed(body.get("messages") or []):
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    return json.loads(block["content"])
    raise ValueError("no tool result in the request")


class ScriptedModels:
    """The Anthropic Messages API and the OpenAI Chat Completions API,
    answering from the request: what a capable model would answer in this
    story, deterministically."""

    def __init__(self, work: Path, run_id: str, gate: Optional[str] = None):
        self.calls = work / "model-calls.jsonl"
        self.work = work
        self.run_id = run_id
        self.gate_call, self.gate_name = (gate.split(":", 1) if gate else (None, None))

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.respond)

    def _wait_at_gate(self, call: str) -> None:
        if call != self.gate_call or self.gate_name is None:
            return
        name, self.gate_name = self.gate_name, None
        (self.work / f"{name}.ready").write_text(str(os.getpid()))
        deadline = time.monotonic() + GATE_TIMEOUT
        while not (self.work / f"{name}.go").exists():
            if time.monotonic() > deadline:
                raise TimeoutError(f"gate {name} was never opened")
            time.sleep(0.05)

    def respond(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content or b"{}")
        path = request.url.path
        if path.endswith("/v1/messages"):
            call = "claude.stream" if body.get("stream") else "claude"
        elif path.endswith("/chat/completions"):
            call = "gpt"
        else:
            return httpx2.Response(404, json={"error": {"message": f"no route {path}"}})
        _append_line(self.calls, {"run_id": self.run_id, "call": call, "pid": os.getpid()})
        self._wait_at_gate(call)
        if call == "claude":
            return httpx2.Response(200, headers={"request-id": "req_decide"}, json=self._decide(body))
        if call == "claude.stream":
            return httpx2.Response(
                200,
                headers={"request-id": "req_reply", "content-type": "text/event-stream"},
                stream=_Chunks(self._reply(body)),
            )
        return httpx2.Response(200, headers={"x-request-id": "req_note"}, json=self._note(body))

    def _decide(self, body: Dict[str, Any]) -> Dict[str, Any]:
        text = body["messages"][0]["content"]
        order = re.search(r"order (\S+)", text).group(1)
        amount = float(re.search(r"\$(\d+\.\d\d)", text).group(1))
        return {
            "id": f"msg_decide_{order}",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": [
                {"type": "text", "text": "The order arrived damaged, so I will refund it."},
                {
                    "type": "tool_use",
                    "id": f"toolu_{order}",
                    "name": "issue_refund",
                    "input": {"order_id": order, "amount_usd": amount, "reason": "arrived damaged"},
                },
            ],
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": {"input_tokens": 412, "output_tokens": 61},
        }

    def _reply(self, body: Dict[str, Any]) -> bytes:
        receipt = _last_tool_result(body)
        first = re.search(r"this is (\w+)", body["messages"][0]["content"]).group(1)
        text = (
            f"Hi {first}, I am sorry your order {receipt['order_id']} arrived damaged. "
            f"I have refunded ${receipt['amount_usd']:.2f} to your card (reference "
            f"{receipt['refund_id']}); it should arrive within 5 business days."
        )
        start = {
            "id": "msg_reply",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 530, "output_tokens": 1},
        }
        events: List[Tuple[str, Dict[str, Any]]] = [
            ("message_start", {"type": "message_start", "message": start}),
            (
                "content_block_start",
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            ),
        ]
        for word in re.findall(r"\S+\s*", text):
            events.append(
                (
                    "content_block_delta",
                    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": word}},
                )
            )
        events += [
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 48},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
        return _sse(events)

    def _note(self, body: Dict[str, Any]) -> Dict[str, Any]:
        reply = body["messages"][-1]["content"]
        order = re.search(r"order (\S+)", reply).group(1)
        amount = re.search(r"\$(\d+\.\d\d)", reply).group(1)
        refund = re.search(r"reference (\w+)", reply).group(1)
        note = f"Refunded ${amount} for damaged order {order} ({refund}); customer notified."
        return {
            "id": "chatcmpl-note",
            "object": "chat.completion",
            "created": 1760000000,
            "model": body["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": note, "refusal": None},
                    "finish_reason": "stop",
                    "logprobs": None,
                }
            ],
            "usage": {"prompt_tokens": 96, "completion_tokens": 24, "total_tokens": 120},
        }


# -- the agent ------------------------------------------------------------------


class World:
    """What one process of the story sees: the provider APIs, the payment
    provider and the record of every tool perform, all under ``work``."""

    def __init__(self, work: Path, run_id: str, gate: Optional[str] = None):
        self.work = work
        self.run_id = run_id
        self.ticket = TICKETS[run_id]
        self.models = ScriptedModels(work, run_id, gate)
        self.payments = Payments(work)
        self.tool_calls = work / "tool-calls.jsonl"


def make_agent(world: World, crash_in_refund: bool = False) -> Callable[[Any], Dict[str, str]]:
    """The agent function for ``world``'s ticket."""

    def issue_refund(order_id: str, amount_usd: float, reason: str, idempotency_key: str) -> Dict[str, Any]:
        _append_line(
            world.tool_calls,
            {"run_id": world.run_id, "tool": "issue_refund", "order_id": order_id, "pid": os.getpid()},
        )
        receipt = world.payments.refund(order_id, amount_usd, idempotency_key)
        if crash_in_refund:
            # The refund went through, and the process dies before its
            # result reaches the journal: only the intent is recorded.
            sys.stdout.flush()
            os._exit(CRASH_EXIT)
        return receipt

    def support_agent(ctx: Any) -> Dict[str, str]:
        claude = ctx.wrap(
            anthropic.Anthropic(
                api_key="sk-ant-e2e-placeholder",
                http_client=httpx2.Client(transport=world.models.transport()),
                max_retries=0,
            )
        )
        gpt = ctx.wrap(
            openai.OpenAI(
                api_key="sk-e2e-placeholder",
                http_client=httpx2.Client(transport=world.models.transport()),
                max_retries=0,
            )
        )
        messages: List[Dict[str, Any]] = [{"role": "user", "content": world.ticket.message}]
        decision = claude.messages.create(
            model=CLAUDE, max_tokens=1024, system=SYSTEM, tools=TOOLS, messages=messages
        )
        messages.append({"role": "assistant", "content": decision.content})
        messages += ctx.run_tools(decision, {"issue_refund": issue_refund})
        with claude.messages.stream(
            model=CLAUDE, max_tokens=1024, system=SYSTEM, tools=TOOLS, messages=messages
        ) as stream:
            reply = "".join(stream.text_stream)
        note = gpt.chat.completions.create(
            model=GPT,
            messages=[
                {"role": "system", "content": NOTE_PROMPT},
                {"role": "user", "content": reply},
            ],
        )
        return {"reply": reply, "case_note": note.choices[0].message.content}

    return support_agent


def make_recover(world: World) -> Callable[[str, str], Any]:
    """The recovery policy: a refund a crash cut off is settled by asking
    the payment provider whether it went through."""

    def recover(name: str, arg: str) -> Any:
        if name != "tool:issue_refund":
            return None
        call = json.loads(arg)
        receipt = world.payments.find(call["input"]["order_id"])
        if receipt is None:
            return None  # it never reached the provider: perform it again
        return pragmatic.Recover.commit(json.dumps(receipt, sort_keys=True, separators=(",", ":")))

    return recover


def _resume_after_dead_writer(rt: Any, run_id: str, agent: Any, recover: Any, timeout: float) -> Any:
    """Resume, waiting while the lease of a writer that died holding it runs
    out: the server gives the run to a new holder only then."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return rt.resume(run_id, agent, recover=recover)
        except pragmatic.Locked as e:
            if isinstance(e, pragmatic.LeaseLost) or time.monotonic() > deadline:
                raise
            time.sleep(min(1.0, e.retry_after) if e.retry_after else 0.25)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("mode", choices=["run", "resume", "contend"])
    p.add_argument("run_id", choices=sorted(TICKETS))
    p.add_argument("work", type=Path)
    p.add_argument("--crash-in-refund", action="store_true")
    p.add_argument("--gate", metavar="CALL:NAME")
    p.add_argument("--wait", type=float, default=120.0, help="how long resume waits out a dead writer")
    args = p.parse_args(argv)

    world = World(args.work, args.run_id, args.gate)
    rt = pragmatic.Runtime()  # PRAGMATIC_URL and PRAGMATIC_TOKEN
    agent = make_agent(world, crash_in_refund=args.crash_in_refund)
    try:
        if args.mode == "run":
            report = rt.run(
                args.run_id,
                agent,
                labels={"queue": "refunds"},
                subjects=[world.ticket.customer_id],
            )
        elif args.mode == "resume":
            report = _resume_after_dead_writer(rt, args.run_id, agent, make_recover(world), args.wait)
        else:
            report = rt.resume(args.run_id, agent, recover=make_recover(world))
    except pragmatic.Locked as e:
        print(json.dumps({"outcome": "locked", "error": str(e), "retry_after": e.retry_after}))
        return 0
    print(
        json.dumps(
            {
                "outcome": "ok",
                "output": json.loads(report.output),
                "journal_len": report.journal_len,
                "replayed_steps": report.replayed_steps,
                "fresh_steps": report.fresh_steps,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
