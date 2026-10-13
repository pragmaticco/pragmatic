"""Regression tests from the adversarial review of the format 2 port of the
Python binding: failed model and tool calls are results, recorded and
raised again on replay as exceptions the agent's ``except`` clauses
recognise. Run with pytest, or directly with python.
"""

from __future__ import annotations

import asyncio
import tempfile

import pragmatic


class Overloaded(Exception):
    """What a model client raises once its own retries are spent."""


def test_adversarial_handled_draw_failure_fails_the_run():
    # A model call that fails and is handled by the agent. The DrawIntent is
    # durable before the call, so the failure must be recorded as its
    # result: otherwise the agent's normal return ends the attempt with
    # DanglingIntent, and replay and resume can never get past the call.
    calls = []

    def fail():
        calls.append("x")
        raise Overloaded("529 overloaded")

    def agent(ctx):
        try:
            first = ctx.draw("x", fail)
        except Overloaded:
            first = "fallback"
        return ctx.draw("y after " + first, lambda: "answer y")

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    report = rt.run("handled", agent)
    assert report.output == '"answer y"' or "answer y" in report.output
    # The handled failure must replay identically, without the model.
    rt.replay("handled", agent)
    # And a resume must not call the model again for it.
    calls.clear()
    rt.resume("handled", agent)
    assert calls == []


def test_adversarial_handled_effect_failure_replays_as_another_exception():
    # Record re-raises the tool's own exception (ValueError), which the agent
    # handles. Replay must raise an exception the same `except` clause
    # catches, with the same text (spec 2.12 carries the original type name).
    def perform(_arg):
        raise ValueError("card declined")

    def agent(ctx):
        try:
            return ctx.effect("charge", "10 EUR", perform)
        except ValueError as e:
            return "declined: " + str(e)

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    recorded = rt.run("effect", agent)
    assert recorded.output == "declined: card declined"
    assert rt.replay("effect", agent).output == recorded.output


def test_replayed_failures_carry_their_type_and_message():
    seen = []

    def perform(_arg):
        raise KeyError("missing")

    def busy():
        raise Overloaded("busy")

    def agent(ctx):
        try:
            ctx.effect("lookup", "k", perform)
        except KeyError as e:
            seen.append(e)
        try:
            ctx.draw("q", busy)
        except Overloaded as e:
            seen.append(e)
        return "ok"

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    rt.run("types", agent)
    assert [type(e) for e in seen] == [KeyError, Overloaded]
    seen.clear()
    rt.replay("types", agent)
    effect, draw = seen
    assert isinstance(effect, pragmatic.EffectFailed) and isinstance(effect, KeyError)
    assert effect.type_name == "KeyError" and str(effect) == str(KeyError("missing"))
    assert isinstance(draw, pragmatic.DrawFailed) and isinstance(draw, Overloaded)
    assert draw.type_name.endswith("Overloaded") and draw.message == "busy"


def test_a_type_that_cannot_be_combined_replays_as_effect_failed():
    # OSError subclasses have their own instance layout; the replayed
    # exception is then a plain EffectFailed naming the type.
    def perform(_arg):
        raise FileNotFoundError("no such file")

    def agent(ctx):
        try:
            return ctx.effect("read", "/x", perform)
        except (FileNotFoundError, pragmatic.EffectFailed) as e:
            return type(e).__name__ + ": " + str(e)

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    assert rt.run("oserror", agent).output == "FileNotFoundError: no such file"
    assert rt.replay("oserror", agent).output == "EffectFailed: no such file"


def test_async_tool_failures_are_recorded_too():
    attempts = []

    async def perform(_arg):
        attempts.append(1)
        raise ValueError("rate limited")

    async def agent(ctx):
        try:
            return await ctx.aeffect("send", "hello", perform)
        except ValueError:
            return "will retry later"

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    assert rt.run("async", agent).output == "will retry later"
    assert rt.replay("async", agent).output == "will retry later"
    rt.resume("async", agent)
    assert attempts == [1]


def test_an_unhandled_draw_failure_is_called_again_on_resume():
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise Overloaded("first call fails")
        return "answer"

    def agent(ctx):
        return ctx.draw("q", flaky)

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    try:
        rt.run("frontier", agent)
    except Overloaded:
        pass
    else:
        raise AssertionError("the failure was not raised")
    assert rt.resume("frontier", agent).output == "answer"
    assert len(calls) == 2
    assert rt.replay("frontier", agent).output == "answer"


def test_an_interrupted_draw_stays_open():
    # Cancellation is a crash, not a result: nothing is recorded for the
    # call, and a resumed run makes it.
    calls = []

    async def sample():
        calls.append(1)
        if len(calls) == 1:
            raise asyncio.CancelledError()
        return "answer"

    async def agent(ctx):
        return await ctx.adraw("q", sample)

    rt = pragmatic.Runtime(tempfile.mkdtemp())
    try:
        rt.run("cancelled", agent)
    except BaseException as e:  # noqa: BLE001
        assert isinstance(e, asyncio.CancelledError) or "cancel" in str(e).lower(), e
    else:
        raise AssertionError("the cancellation was not raised")
    assert rt.resume("cancelled", agent).output == "answer"
    assert len(calls) == 2


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            test()
            print("ok  ", name)
        except Exception as e:  # noqa: BLE001
            print("FAIL", name, type(e).__name__, e)
