"""The runtime layer of the Python SDK (spec 6.1, 6.2, 6.4, 6.7) over local
stores: attempts and their ownership, async attempts in a running loop,
parallel regions, the journaled inputs, recovery, durability failures and
the views of stored runs.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import sys
import threading
import time
import uuid
import warnings

import pytest

import pragmatic
from conftest import PyMemoryStore


class Die(BaseException):
    """A crash: not an Exception, so the attempt is abandoned, not ended."""


def notes(rt, run_id, kind):
    return [e for e in rt.entries(run_id) if e["kind"] == "Note" and e["fields"]["kind"] == kind]


def program_entries(rt, run_id):
    return [e for e in rt.entries(run_id) if e["branch"] != [0xFFFFFFFF]]


def fields(rt, run_id, kind):
    return [e["fields"] for e in rt.entries(run_id) if e["kind"] == kind]


needs_timeout = pytest.mark.skipif(sys.version_info < (3, 11), reason="asyncio.timeout is new in 3.11")

CANCELLED = "asyncio.exceptions.CancelledError"


async def never(*_args):
    await asyncio.sleep(30)
    return "never"


# ---------------------------------------------------------------------------
# Async attempts in a running loop
# ---------------------------------------------------------------------------


def test_fifty_concurrent_runs_share_one_event_loop(tmp_path):
    rt = pragmatic.Runtime(tmp_path)
    performed = []

    async def agent(ctx):
        n = await ctx.atool("count", lambda: (performed.append(ctx.run_id), len(ctx.run_id))[1])
        await asyncio.sleep(0)
        stamp = ctx.now()
        parts = await ctx.gather(
            lambda c: c.atool("left", lambda: "l"),
            lambda c: c.atool("right", lambda: "r"),
        )
        return {"n": n, "parts": parts, "positive": stamp > 0}

    async def main():
        return await asyncio.gather(*(rt.arun(f"run-{i}", agent) for i in range(50)))

    reports = asyncio.run(main())
    assert len(reports) == 50
    assert sorted(performed) == sorted(f"run-{i}" for i in range(50))
    for i, r in enumerate(reports):
        assert json.loads(r.output) == {"n": len(f"run-{i}"), "parts": ["l", "r"], "positive": True}

    async def audit():
        return await asyncio.gather(*(rt.areplay(f"run-{i}", agent) for i in range(50)))

    audits = asyncio.run(audit())
    assert [a.output for a in audits] == [r.output for r in reports]
    assert len(performed) == 50, "replay performs nothing"
    assert all(rt.verify(f"run-{i}") for i in range(50))


def test_an_async_agent_runs_inside_the_callers_loop():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    loop_seen = []

    async def agent(ctx):
        loop_seen.append(asyncio.get_running_loop())
        return await ctx.atool("t", lambda: "ok")

    async def main():
        report = await rt.arun("r", agent)
        return report, asyncio.get_running_loop()

    report, loop = asyncio.run(main())
    assert report.output == "ok"
    assert loop_seen == [loop]


def test_sync_wrappers_use_a_private_loop_and_refuse_a_running_one():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        return await ctx.atool("t", lambda: 1)

    assert rt.run("r", agent).output == "1"
    assert rt.replay("r", agent).output == "1"

    async def inside():
        with pytest.raises(RuntimeError, match="arun"):
            rt.run("r2", agent)

    asyncio.run(inside())


def test_sync_calls_on_one_thread_share_a_private_loop_between_calls():
    """An async client built once pools its connections on the first loop
    that used it, so the private loop outlives a call: three calls run on
    one loop. Each still ends as asyncio.run ends it: the caller's context
    as it is now reaches the agent, nothing leaks from one call to the
    next, and tasks the agent left running are cancelled."""
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    tag = contextvars.ContextVar("tag", default="unset")
    loops, seen, stragglers = [], [], []

    async def straggle():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            stragglers.append("cancelled")
            raise

    async def agent(ctx):
        loops.append(asyncio.get_running_loop())
        seen.append(tag.get())
        tag.set("set inside the run")
        asyncio.get_running_loop().create_task(straggle())
        return await ctx.atool("t", lambda: "ok")

    for i in range(3):
        tag.set(f"call {i}")
        assert rt.run(f"r{i}", agent).output == "ok"
        assert not loops[-1].is_closed()
        assert stragglers == ["cancelled"] * (i + 1)
    assert loops[0] is loops[1] is loops[2]
    assert seen == ["call 0", "call 1", "call 2"]
    assert tag.get() == "call 2"
    # The private loop is never the thread's current loop.
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()


def test_a_crash_closes_the_private_loop_and_the_next_call_starts_a_fresh_one():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    loops = []

    async def crashes(ctx):
        loops.append(asyncio.get_running_loop())
        await ctx.atool("t", lambda: 1)
        raise Die()

    async def fine(ctx):
        loops.append(asyncio.get_running_loop())
        return await ctx.atool("t", lambda: 2)

    assert rt.run("before", fine).output == "2"
    with pytest.raises(Die):
        rt.run("crash", crashes)
    assert loops[0] is loops[1] and loops[1].is_closed()
    # The crashed run was checked in: it resumes on a fresh loop, and the
    # tool's recorded result is read back.
    assert rt.resume("crash", fine).output == "1"
    assert loops[2] is not loops[1] and not loops[2].is_closed()


def test_each_thread_has_its_own_private_loop():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    loops = {}

    async def agent(ctx):
        loops.setdefault(threading.get_ident(), []).append(asyncio.get_running_loop())
        return await ctx.atool("t", lambda: "ok")

    def twice(n):
        rt.run(f"a{n}", agent)
        rt.run(f"b{n}", agent)

    threads = [threading.Thread(target=twice, args=(n,)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    first, second = loops.values()
    assert first[0] is first[1] and second[0] is second[1]
    assert first[0] is not second[0]


def test_cancelling_an_async_run_is_a_crash():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def slow(_arg):
        await asyncio.sleep(30)
        return "never"

    async def agent(ctx):
        return await ctx.aeffect("slow", "x", slow)

    async def main():
        task = asyncio.ensure_future(rt.arun("c", agent))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    # Nothing more was journaled after the intent: no result (the
    # cancellation's was only appended, and the crash dropped it), no
    # attempt.end.
    assert notes(rt, "c", "attempt.end") == []
    intents = [e for e in rt.entries("c") if e["kind"] == "EffectIntent"]
    assert len(intents) == 1
    assert fields(rt, "c", "EffectResult") == []
    # The run was checked in: it resumes, and the policy decides the intent.
    report = rt.resume("c", agent, recover=lambda name, arg: "committed")
    assert report.output == "committed"


# ---------------------------------------------------------------------------
# Steps the agent cancels and carries on past (spec 2.7 rule 7, 2.12)
# ---------------------------------------------------------------------------


@needs_timeout
def test_a_timed_out_effect_is_a_failure_the_run_carries_on_past():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    performed = []

    async def slow(arg):
        performed.append(arg)
        return await never()

    async def agent(ctx):
        try:
            async with asyncio.timeout(0.05):
                await ctx.aeffect("slow", "x", slow)
        except TimeoutError:
            pass
        return await ctx.atool("fallback", lambda: "fallback")

    assert rt.run("t", agent).output == "fallback"
    failed, ok = fields(rt, "t", "EffectResult")
    assert failed["outcome"] == "failed" and failed["error_kind"] == CANCELLED
    assert ok["outcome"] == "ok"
    # Replay waits at the step until the agent's own timeout cancels it
    # again, and performs nothing.
    started = time.monotonic()
    assert rt.replay("t", agent).output == "fallback"
    assert time.monotonic() - started >= 0.05
    assert performed == ["x"]
    assert rt.resume("t", agent).output == "fallback" and performed == ["x"]


@needs_timeout
def test_a_timed_out_model_call_is_a_failure_the_run_carries_on_past():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        try:
            async with asyncio.timeout(0.05):
                await ctx.adraw("prompt", never)
        except TimeoutError:
            return "carried on"
        return "answered"

    assert rt.run("d", agent).output == "carried on"
    [result] = fields(rt, "d", "DrawResult")
    assert result["meta"] == {"error_type": CANCELLED, "outcome": "error"}
    assert rt.replay("d", agent).output == "carried on"


@pytest.mark.skipif(
    sys.version_info < (3, 12), reason="before 3.12 asyncio.wait_for runs the step in a task of its own"
)
def test_wait_for_around_a_step_runs_it_in_the_callers_task():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        try:
            await asyncio.wait_for(ctx.atool("slow", never), 0.05)
        except TimeoutError:
            return "timed out"
        return "answered"

    assert rt.run("w", agent).output == "timed out"
    assert rt.replay("w", agent).output == "timed out"


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="from 3.12 asyncio.wait_for runs in the caller's task")
def test_wait_for_before_3_12_runs_the_step_in_a_task_the_attempt_does_not_own():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        with pytest.raises(pragmatic.NotInRun):
            await asyncio.wait_for(ctx.atool("t", lambda: 1), 5)
        return "refused"

    assert rt.run("w", agent).output == "refused"


@needs_timeout
def test_a_region_cancelled_by_a_timeout_leaves_the_parent_branch_usable():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def slow_child(c):
        await c.atool("started", lambda: 1)
        return await never()

    async def agent(ctx):
        try:
            async with asyncio.timeout(0.1):
                await ctx.gather(slow_child, slow_child)
        except TimeoutError:
            pass
        # The region is over: the root branch steps again (spec 2.7, rule 5).
        return str(ctx.now() > 0)

    assert rt.run("g", agent).output == "True"
    assert rt.replay("g", agent).output == "True"


def test_a_child_cancelled_inside_the_region_is_a_failed_child():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def cancelled_child(c):
        asyncio.current_task().cancel()
        await asyncio.sleep(0)
        return "never"

    async def agent(ctx):
        try:
            await ctx.gather(lambda c: c.atool("a", lambda: 1), cancelled_child)
        except asyncio.CancelledError:
            raise
        except pragmatic.PragmaticError as e:
            return f"{type(e.__cause__).__name__}: {e}"
        return "no failure"

    async def main():
        # Nothing cancelled this task: it must not see a CancelledError.
        report = await rt.arun("cc", agent)
        if sys.version_info >= (3, 11):
            assert asyncio.current_task().cancelling() == 0
        return report.output

    out = asyncio.run(main())
    assert out == "CancelledError: child 1 of the parallel region was cancelled"
    assert rt.replay("cc", agent).output == out


# ---------------------------------------------------------------------------
# Parallel regions (spec 2.7)
# ---------------------------------------------------------------------------


def test_gather_results_come_back_in_child_order_whatever_the_interleaving():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    delays = {"a": 0.03, "b": 0.0, "c": 0.01}

    async def child(c, name):
        await asyncio.sleep(delays[name])
        x = await c.atool("look", lambda q: f"found {q}", name)
        await asyncio.sleep(delays[name])
        y = c.uuid4()
        return f"{name}:{x}:{c.branch}:{y}"

    async def agent(ctx):
        return await ctx.gather(*(lambda c, n=n: child(c, n) for n in "abc"))

    recorded = json.loads(rt.run("g", agent).output)
    assert [r.split(":")[0] for r in recorded] == ["a", "b", "c"]
    assert [r.split(":")[2] for r in recorded] == ["(0,)", "(1,)", "(2,)"]
    # Replay with the opposite interleaving gives back each child's own
    # values (including its random draw).
    delays.update(a=0.0, b=0.03, c=0.015)
    assert json.loads(rt.replay("g", agent).output) == recorded


def test_a_failing_child_never_cancels_its_siblings_and_the_lowest_index_wins():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    finished = []

    async def late_failure(c):
        await asyncio.sleep(0.05)
        await c.atool("work", lambda: 0)
        finished.append(0)
        raise KeyError("child 0, late")

    async def steady(c):
        await asyncio.sleep(0.02)
        await c.atool("work", lambda: 1)
        finished.append(1)
        return 1

    async def early_failure(c):
        await c.atool("work", lambda: 2)
        finished.append(2)
        raise ValueError("child 2, early")

    async def agent(ctx):
        try:
            await ctx.gather(late_failure, steady, early_failure)
        except KeyError as e:
            return f"region failed with {e}"
        except ValueError:
            return "wrong child"

    assert rt.run("f", agent).output == "region failed with 'child 0, late'"
    assert sorted(finished) == [0, 1, 2], "every child ran to its end"
    # The replayed region fails the same way.
    finished.clear()
    assert rt.replay("f", agent).output == "region failed with 'child 0, late'"


def test_regions_nest_and_bare_coroutines_are_refused():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def leaf(c, tag):
        return f"{tag}@{c.branch}"

    async def middle(c, tag):
        inner = await c.gather(lambda x: leaf(x, tag + "1"), lambda x: leaf(x, tag + "2"))
        return inner

    async def agent(ctx):
        assert await ctx.gather() == []
        coro = leaf(ctx, "bare")
        with pytest.raises(TypeError, match="not coroutines"):
            await ctx.gather(coro)
        return await ctx.gather(lambda c: middle(c, "a"), lambda c: middle(c, "b"))

    out = json.loads(rt.run("n", agent).output)
    assert out == [["a1@(0, 0)", "a2@(0, 1)"], ["b1@(1, 0)", "b2@(1, 1)"]]
    assert json.loads(rt.replay("n", agent).output) == out


def test_the_parent_branch_is_suspended_while_its_region_runs():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    seen = []

    async def agent(ctx):
        root_ctx_token = pragmatic._native.CURRENT.get()

        async def child(c):
            # A step on the parent's branch from inside the region.
            ctx_token = pragmatic._native.CURRENT.set(root_ctx_token)
            try:
                c.now()
            except pragmatic.PragmaticError as e:
                seen.append(str(e))
            finally:
                pragmatic._native.CURRENT.reset(ctx_token)
            return 1

        await ctx.gather(child)
        return "ok"

    assert rt.run("s", agent).output == "ok"
    assert seen and "suspended in a parallel region" in seen[0]


# ---------------------------------------------------------------------------
# Ownership (spec 6.2, 6.4)
# ---------------------------------------------------------------------------


def test_asyncio_to_thread_routes_to_the_callers_branch():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    def blocking_lookup(c, q):
        return c.tool("lookup", lambda: f"result {q}")

    async def child(c, q):
        return await asyncio.to_thread(blocking_lookup, c, q)

    async def agent(ctx):
        first = await asyncio.to_thread(blocking_lookup, ctx, "root")
        rest = await ctx.gather(lambda c: child(c, "x"), lambda c: child(c, "y"))
        return [first] + rest

    out = json.loads(rt.run("t", agent).output)
    assert out == ["result root", "result x", "result y"]
    # The children's threads run concurrently, so their entries may come in
    # either order; each result is on its own child's branch.
    results = {
        tuple(e["branch"]): json.loads(e["slots"][0]["text"])
        for e in rt.entries("t")
        if e["kind"] == "EffectResult"
    }
    assert results == {(): "result root", (0,): "result x", (1,): "result y"}
    assert json.loads(rt.replay("t", agent).output) == out


def test_run_in_executor_is_refused():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        loop = asyncio.get_running_loop()
        with pytest.raises(pragmatic.NotInRun, match="asyncio.to_thread"):
            await loop.run_in_executor(None, ctx.now)
        return "refused"

    assert rt.run("e", agent).output == "refused"


def test_tasks_the_attempt_does_not_own_are_refused():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def agent(ctx):
        task = asyncio.ensure_future(ctx.atool("t", lambda: 1))
        with pytest.raises(pragmatic.NotInRun):
            await task
        return "refused"

    assert rt.run("k", agent).output == "refused"
    # Nothing was recorded for the refused step.
    assert not [e for e in rt.entries("k") if e["kind"] == "EffectIntent"]


def test_an_async_agent_passed_through_a_lambda_is_owned_by_its_tasks():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    async def gathered(ctx, tag):
        async def slow(x):
            await asyncio.sleep(0.01)
            return x

        return await asyncio.gather(ctx.atool("a", slow, tag), ctx.atool("b", slow, tag))

    # Binding arguments with a lambda runs the agent on a private loop; its
    # tasks are owned as in arun, so tasks the agent creates are refused.
    with pytest.raises(pragmatic.NotInRun):
        rt.run("direct", lambda c: gathered(c, "x"))

    async def owned(ctx, tag):
        stamp = await asyncio.to_thread(ctx.now)
        parts = await ctx.gather(lambda c: c.atool("l", lambda: tag), lambda c: c.atool("r", lambda: tag))
        return [stamp > 0, parts]

    assert json.loads(rt.run("bound", lambda c: owned(c, "y")).output) == [True, ["y", "y"]]


def test_a_synchronous_attempt_belongs_to_its_thread():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    errors = []

    def agent(ctx):
        def other():
            try:
                ctx.now()
            except pragmatic.NotInRun as e:
                errors.append(e)

        # A plain thread does not carry the context variable, and a thread
        # that copies it still is not the owner.
        t = threading.Thread(target=other)
        t.start()
        t.join()
        copied = contextvars.copy_context()
        t = threading.Thread(target=copied.run, args=(other,))
        t.start()
        t.join()
        return "ok"

    assert rt.run("th", agent).output == "ok"
    assert len(errors) == 2
    assert all("outside the attempt that owns it" in str(e) for e in errors)


def test_a_ctx_cannot_outlive_or_cross_its_attempt():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    saved = []

    def first(ctx):
        saved.append(ctx)
        return ctx.tool("t", lambda: 1)

    rt.run("one", first)
    with pytest.raises(pragmatic.NotInRun):
        saved[0].now()

    def second(ctx):
        with pytest.raises(pragmatic.NotInRun):
            saved[0].now()
        return "ok"

    assert rt.run("two", second).output == "ok"


# ---------------------------------------------------------------------------
# Journaled inputs (spec 6.7)
# ---------------------------------------------------------------------------


def test_random_and_clock_reads_replay_exactly():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    def agent(ctx):
        return {
            "uuid": str(ctx.uuid4()),
            "random": ctx.random(),
            "int": ctx.randint(-5, 5),
            "bytes": ctx.randbytes(8).hex(),
            "now": ctx.now(),
            "when": ctx.datetime().isoformat(),
        }

    recorded = json.loads(rt.run("r", agent).output)
    assert uuid.UUID(recorded["uuid"]).version == 4
    assert 0.0 <= recorded["random"] < 1.0
    assert -5 <= recorded["int"] <= 5
    assert len(recorded["bytes"]) == 16
    assert recorded["when"].endswith("+00:00")
    assert json.loads(rt.replay("r", agent).output) == recorded
    kinds = [(e["kind"], e["fields"].get("source")) for e in program_entries(rt, "r")]
    assert kinds == [
        ("Random", "uuid4"),
        ("Random", "random"),
        ("Random", "randint"),
        ("Random", "bytes"),
        ("Clock", None),
        ("Clock", None),
    ]

    def bad(ctx):
        with pytest.raises(ValueError):
            ctx.randint(3, 1)
        with pytest.raises(TypeError):
            ctx.randint(1.5, 2)
        with pytest.raises(ValueError):
            ctx.randbytes(-1)
        return "ok"

    assert rt.run("bad", bad).output == "ok"


def test_patches_keep_old_runs_on_their_path():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    log = []

    def v1(ctx):
        return ctx.tool("a", lambda: log.append("a") or 1)

    def v2(ctx):
        if ctx.patched("validate"):
            ctx.tool("validate", lambda: log.append("validate") or True)
        return ctx.tool("a", lambda: log.append("a") or 1)

    def v3(ctx):
        ctx.deprecate_patch("validate")
        ctx.tool("validate", lambda: log.append("validate") or True)
        return ctx.tool("a", lambda: log.append("a") or 1)

    rt.run("old", v1)
    assert rt.replay("old", v2).output == "1", "a run recorded before the patch skips it"
    rt.run("new", v2)
    assert log == ["a", "validate", "a"]
    assert [e["kind"] for e in program_entries(rt, "new")][:1] == ["Marker"]
    assert rt.replay("new", v3).output == "1", "deprecate_patch consumes the marker"
    rt.run("newer", v3)
    assert "Marker" not in [e["kind"] for e in program_entries(rt, "newer")]


def test_recv_and_contract():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    rt.send("c", "jobs", "summarize")

    def agent(ctx):
        job = ctx.recv("jobs")
        try:
            ctx.recv("jobs")
        except pragmatic.PragmaticError as e:
            empty = str(e)
        ctx.contract(job == "summarize", "the job arrived")
        return f"{job} / {empty}"

    out = rt.run("c", agent).output
    assert out == "summarize / timeout"
    assert rt.replay("c", agent).output == out

    with pytest.raises(pragmatic.PragmaticError, match="contract violated: nope"):
        rt.run("v", lambda ctx: ctx.contract(False, "nope"))


def test_effects_and_tools_receive_their_idempotency_key():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    keys = []

    def charge(amount, idempotency_key):
        keys.append(idempotency_key)
        return f"charged {amount}"

    def perform(arg, *, idempotency_key):
        keys.append(idempotency_key)
        return arg.upper()

    async def child(c):
        return await c.atool("charge", charge, 5)

    async def agent(ctx):
        a = ctx.tool("charge", charge, 10)
        b = ctx.effect("shout", "hi", perform)
        c = await ctx.gather(child)
        return [a, b] + c

    out = json.loads(rt.run("k", agent).output)
    assert out == ["charged 10", "HI", "charged 5"]
    intents = [e for e in rt.entries("k") if e["kind"] == "EffectIntent"]
    assert keys == [
        f"k//{intents[0]['cursor']}",
        f"k//{intents[1]['cursor']}",
        f"k/0/{intents[2]['cursor']}",
    ]
    # The key is never part of the journaled argument.
    assert [e["slots"][0]["text"] for e in intents] == [
        '{"args":[10],"kwargs":{}}',
        "hi",
        '{"args":[5],"kwargs":{}}',
    ]


def test_durable_versions_and_code_changes():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    @pragmatic.durable(version="1")
    def agent(ctx):
        return ctx.tool("t", lambda: "x")

    rt.run("p", agent)

    @pragmatic.durable(version="2")
    def agent(ctx):  # noqa: F811 - the same program, a new version
        return ctx.tool("t", lambda: "x")

    with pytest.raises(pragmatic.JournalDesync, match="on_code_change='continue'"):
        rt.replay("p", agent)
    audit = rt.replay("p", agent, on_code_change="continue")
    assert audit.program_changes and audit.program_changes[0][2:] == ("1", "2")
    rt.resume("p", agent)
    assert len(notes(rt, "p", "program.change")) == 1
    # Accepted once, the new version replays under the default policy.
    assert rt.replay("p", agent).output == "x"

    @pragmatic.durable(version="3")
    def agent(ctx):  # noqa: F811
        return ctx.tool("t", lambda: "x")

    with pytest.raises(pragmatic.JournalDesync):
        rt.resume("p", agent, on_code_change="refuse")


def test_durable_programs_mark_their_branch_and_record_attempt_start():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    @pragmatic.durable(version="sub-1")
    async def researcher(c, topic):
        return await c.atool("search", lambda: topic)

    async def agent(ctx):
        return await ctx.gather(lambda c: researcher(c, "a"), lambda c: researcher(c, "b"))

    rt.run("d", agent)
    programs = [(e["branch"], e["fields"]["hash"]) for e in rt.entries("d") if e["kind"] == "Program"]
    assert programs == [([0], "sub-1"), ([1], "sub-1")]
    start = notes(rt, "d", "attempt.start")[0]["fields"]["data"]
    assert start["program"]["name"].endswith("agent")


def test_draw_desyncs_carry_a_diff_that_is_never_journaled():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    def request(max_tokens):
        return json.dumps(
            {"model": "m", "max_tokens": max_tokens, "messages": [{"role": "user", "content": "hi"}]}
        )

    rt.run("x", lambda ctx: ctx.draw(request(256), lambda: "answer"))
    with pytest.raises(pragmatic.JournalDesync) as caught:
        rt.replay("x", lambda ctx: ctx.draw(request(999), lambda: "answer"))
    assert caught.value.diff == ("part 0 at $.max_tokens: recorded 256, now 999",)
    assert "now 999" in str(caught.value)
    # A resume that hits the same desync records the fault, not the diff.
    with pytest.raises(pragmatic.JournalDesync):
        rt.resume("x", lambda ctx: ctx.draw(request(999), lambda: "answer"))
    assert "now 999" not in json.dumps(rt.entries("x"))


# ---------------------------------------------------------------------------
# Recovery (spec 2.12)
# ---------------------------------------------------------------------------


def crash_during(effect_name):
    def perform(_arg):
        raise Die()

    def agent(ctx):
        return ctx.effect(effect_name, "payload", perform)

    return agent


def test_recovery_policies_take_two_or_four_arguments():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    with pytest.raises(Die):
        rt.run("two", crash_during("send"))
    asked = []

    def two(name, arg):
        asked.append((name, arg))
        return "sent before the crash"

    report = rt.resume("two", crash_during("send"), recover=two)
    assert report.output == "sent before the crash"
    assert asked == [("send", "payload")]

    with pytest.raises(Die):
        rt.run("four", crash_during("send"))

    def four(name, arg, branch, intent_cursor):
        asked.append((name, branch, intent_cursor))
        return pragmatic.Recover.commit("checked")

    assert rt.resume("four", crash_during("send"), recover=four).output == "checked"
    intent = [e for e in rt.entries("four") if e["kind"] == "EffectIntent"][0]["cursor"]
    assert asked[-1] == ("send", (), intent)
    decisions = [n["fields"]["data"]["decision"] for n in notes(rt, "four", "recovery")]
    assert decisions == ["commit"]


def test_recover_fail_and_compensate():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    with pytest.raises(Die):
        rt.run("f", crash_during("send"))

    def handled(ctx):
        try:
            return ctx.effect("send", "payload", lambda a: "again")
        except pragmatic.EffectFailed as e:
            return f"failed: {e.type_name}"

    assert rt.resume("f", handled, recover=lambda n, a: pragmatic.Recover.FAIL).output == "failed: Dangling"

    with pytest.raises(Die):
        rt.run("c", crash_during("send"))
    assert rt.resume("c", handled, recover=lambda n, a: None).output == "again"


def test_a_raising_policy_aborts_the_resume_and_records_nothing():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    with pytest.raises(Die):
        rt.run("p", crash_during("send"))
    before = len(rt.entries("p"))

    def broken(name, arg):
        raise LookupError("the payments API is down")

    with pytest.raises(LookupError, match="payments API"):
        rt.resume("p", crash_during("send"), recover=broken)
    assert len(rt.entries("p")) == before, "no attempt.start, no decision"
    assert rt.resume("p", crash_during("send"), recover=lambda n, a: "ok").output == "ok"


def test_async_recovery_policies_run_in_aresume():
    rt = pragmatic.Runtime(pragmatic.MemoryStore())
    with pytest.raises(Die):
        rt.run("a", crash_during("send"))

    async def check(name, arg, branch, intent):
        await asyncio.sleep(0.01)
        return f"checked {name} at {intent}"

    async def agent(ctx):
        return await ctx.aeffect("send", "payload", lambda a: "never")

    report = asyncio.run(rt.aresume("a", agent, recover=check))
    assert report.output.startswith("checked send at ")

    with pytest.raises(Die):
        rt.run("b", crash_during("send"))
    with pytest.raises(TypeError, match="aresume"):
        rt.resume("b", crash_during("send"), recover=check)


def test_server_style_stores_require_a_policy(pystore):
    pystore.remote = True
    rt = pragmatic.Runtime(pystore)
    with pytest.raises(Die):
        rt.run("r", crash_during("send"))
    with pytest.raises(pragmatic.DanglingEffect):
        rt.resume("r", crash_during("send"))
    assert rt.resume("r", crash_during("send"), recover=lambda n, a: "done").output == "done"


# ---------------------------------------------------------------------------
# Durability failures (spec 3.2, 6.3)
# ---------------------------------------------------------------------------


def test_a_persist_failure_is_sticky_and_raises_what_the_store_raised(pystore):
    rt = pragmatic.Runtime(pystore)
    down = pragmatic.Unavailable("the server went away")
    caught = []

    def agent(ctx):
        ctx.now()
        pystore.fail = lambda n, frames: down
        for step in (ctx.now, ctx.uuid4, lambda: ctx.tool("t", lambda: 1)):
            try:
                step()
            except pragmatic.Unavailable as e:
                caught.append(e)
        return "done"

    with pytest.raises(pragmatic.Unavailable) as ended:
        rt.run("s", agent)
    assert caught == [down, down, down]
    assert all(e is down for e in caught) and ended.value is down
    assert pystore.persists == 3, "begin, the first clock read, then the failure"
    pystore.fail = None
    kinds = [e["fields"].get("kind") for e in rt.entries("s") if e["kind"] == "Note"]
    assert kinds == ["run.start", "attempt.start"], "no attempt.end after a failed persist"
    # The next attempt starts from what was durable.
    assert rt.resume("s", lambda ctx: ctx.now() and "resumed").output == "resumed"


@pytest.mark.parametrize(
    "make",
    [lambda: OSError("disk full"), lambda: pragmatic.Unavailable("server down")],
    ids=["oserror", "unavailable"],
)
def test_a_region_raises_what_the_store_raised(pystore, make):
    """Child 0 returns first, with no steps; child 1's persist fails. The
    region raises the store's own exception, as every step after a failed
    persist does (spec 6.3), whichever child happened to finish first."""
    rt = pragmatic.Runtime(pystore)
    boom = make()
    seen = {}

    async def ok_child(c):
        return "fine"

    async def failing_child(c):
        await asyncio.sleep(0.01)
        pystore.fail = lambda n, frames: boom
        try:
            await c.atool("t", lambda: 1)
        except BaseException as e:  # noqa: BLE001
            seen["child"] = e
            raise

    async def agent(ctx):
        try:
            await ctx.gather(ok_child, failing_child)
        except BaseException as e:  # noqa: BLE001
            seen["region"] = e
            raise

    with pytest.raises(type(boom)) as ended:
        rt.run("sticky-gather", agent)
    assert seen["child"] is boom and seen["region"] is boom and ended.value is boom


def test_store_exceptions_map_to_their_faults(pystore):
    rt = pragmatic.Runtime(pystore)
    rt.run("m", lambda ctx: "x")
    for raised, expected in [
        (pragmatic.LeaseLost(), pragmatic.LeaseLost),
        (pragmatic.Conflict(3, 4), pragmatic.Conflict),
        (pragmatic.Deleted(), pragmatic.Deleted),
        (pragmatic.TooLarge(limit=10), pragmatic.TooLarge),
        (OSError("disk full"), OSError),
    ]:
        pystore.fail = lambda n, f, raised=raised: raised
        with pytest.raises(expected) as caught:
            rt.resume("m", lambda ctx: "x")
        assert caught.value is raised
    pystore.fail = None
    pystore.locked.add("m")
    with pytest.raises(pragmatic.Locked) as locked:
        rt.resume("m", lambda ctx: "x")
    assert locked.value.retry_after == 7


def test_an_effect_whose_result_cannot_be_recorded(pystore):
    rt = pragmatic.Runtime(pystore)
    performed = []

    def charge(_arg):
        performed.append(1)
        pystore.fail = lambda n, f: pragmatic.Unavailable("down")
        return "charged"

    def agent(ctx):
        return ctx.effect("charge", "10 EUR", charge)

    with pytest.raises(pragmatic.EffectUnrecorded) as caught:
        rt.run("u", agent)
    assert (caught.value.name, caught.value.result) == ("charge", b"charged")
    assert isinstance(caught.value.__cause__, pragmatic.Unavailable)
    pystore.fail = None
    # The intent is durable and its result is not: the policy decides.
    report = rt.resume("u", agent, recover=lambda name, arg: "charged")
    assert report.output == "charged" and performed == [1]


def test_receives_go_back_to_the_inbox_when_their_persist_fails(pystore):
    rt = pragmatic.Runtime(pystore)
    rt.send("q", "jobs", "the only job")

    def agent(ctx):
        pystore.fail = lambda n, f: pragmatic.Unavailable("down")
        return ctx.recv("jobs")

    with pytest.raises(pragmatic.Unavailable):
        rt.run("q", agent)
    pystore.fail = None
    assert rt.resume("q", lambda ctx: ctx.recv("jobs")).output == "the only job"


def test_locks_between_runtimes_on_one_directory(tmp_path):
    rt1 = pragmatic.Runtime(tmp_path)
    rt2 = pragmatic.Runtime(tmp_path)

    def agent(ctx):
        with pytest.raises(pragmatic.Locked):
            rt2.run("L", lambda c: "never")
        return "held"

    assert rt1.run("L", agent).output == "held"
    assert rt2.resume("L", lambda ctx: "now mine").output == "now mine"


# ---------------------------------------------------------------------------
# Construction (spec 6.1) and views (spec 6.7)
# ---------------------------------------------------------------------------


def test_runtime_construction_rules(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="PRAGMATIC_URL"):
        pragmatic.Runtime()
    monkeypatch.setenv("PRAGMATIC_URL", str(tmp_path / "from-env"))
    assert isinstance(pragmatic.Runtime().store, pragmatic.DirStore)
    monkeypatch.delenv("PRAGMATIC_URL")
    with pytest.raises(ValueError, match="server store is required"):
        pragmatic.Runtime(tmp_path, require_server=True)
    monkeypatch.setenv("PRAGMATIC_REQUIRE_SERVER", "1")
    with pytest.raises(ValueError, match="server store is required"):
        pragmatic.Runtime(tmp_path)
    monkeypatch.delenv("PRAGMATIC_REQUIRE_SERVER")
    with pytest.raises(ValueError, match="loopback"):
        pragmatic.Runtime("http://example.com", token="t")
    with pytest.raises(ValueError, match="token"):
        pragmatic.Runtime("https://example.com")
    with pytest.raises(ValueError, match="local stores"):
        pragmatic.Runtime(PyMemoryStore(), key=b"k")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        rt = pragmatic.Runtime(dir=tmp_path / "old")
    assert any(issubclass(x.category, DeprecationWarning) for x in w)
    assert rt.run("r", lambda ctx: "ok").output == "ok"


def test_memory_stores_are_shared_between_runtimes():
    store = pragmatic.MemoryStore()
    with pytest.raises(Die):
        pragmatic.Runtime(store).run("m", crash_during("send"))
    report = pragmatic.Runtime(store).resume("m", crash_during("send"), recover=lambda n, a: "ok")
    assert report.output == "ok"
    assert store.list() == ["m"]


def test_views_of_stored_runs(tmp_path):
    rt = pragmatic.Runtime(tmp_path)

    def agent(ctx):
        ctx.draw("prompt", lambda: "answer")
        return ctx.tool("t", lambda: {"k": 1})

    rt.run("v", agent, labels={"team": "research"}, subjects=["user-17"])
    report = rt.verify("v")
    assert isinstance(report, pragmatic.VerifyReport) and report and report.ok
    [summary] = rt.runs()
    assert summary.run_id == "v" and summary.status == "idle"
    assert summary.labels == {"team": "research"}
    assert summary.last_outcome == "ok" and summary.entries == len(rt.entries("v"))
    assert summary.created_at.endswith("Z")
    entries = rt.entries("v")
    start = entries[0]
    assert start["kind"] == "Note" and start["fields"]["kind"] == "run.start"
    assert start["fields"]["data"]["labels"] == {"team": "research"}
    assert json.loads(start["slots"][0]["text"]) == {"subjects": ["user-17"]}
    draw = [e for e in entries if e["kind"] == "DrawResult"][0]
    assert draw["fields"]["meta"] == {"outcome": "ok"}
    assert draw["slots"][1]["text"] == "answer" and draw["slots"][1]["state"] == "sealed"
    assert set(start) == {"cursor", "at", "branch", "kind", "fields", "slots", "hash"}


def test_open_spans_when_opentelemetry_is_enabled(span_exporter):
    exporter = span_exporter
    rt = pragmatic.Runtime(pragmatic.MemoryStore())

    def agent(ctx):
        ctx.draw("SECRET PROMPT", lambda: "SECRET ANSWER", provenance="anthropic:claude-x")
        return ctx.effect("send", "SECRET ARG", lambda a: "SECRET RESULT")

    rt.run("o", agent)
    rt.replay("o", agent)
    spans = exporter.get_finished_spans()
    names = [s.name for s in spans]
    assert names.count("pragmatic.attempt") == 2
    assert names.count("chat claude-x") == 2 and names.count("pragmatic.effect") == 2
    replayed_draw = [s for s in spans if s.name == "chat claude-x"][1]
    assert replayed_draw.attributes["pragmatic.replayed"] is True
    assert replayed_draw.attributes["gen_ai.usage.input_tokens"] == 0
    assert all(s.attributes.get("pragmatic.run_id") == "o" for s in spans)
    dumped = json.dumps([dict(s.attributes) for s in spans])
    assert "SECRET" not in dumped


def test_concurrent_children_all_see_the_first_persist_failure(pystore):
    rt = pragmatic.Runtime(pystore)
    down = pragmatic.Unavailable("the store went away")
    seen = []

    first_attempt = [True]

    async def child(c, i):
        if i == 0 and first_attempt:
            first_attempt.clear()
            pystore.fail = lambda n, frames: down
        await asyncio.sleep(0.01 * i)
        try:
            await c.atool("work", lambda: i)
        except pragmatic.Unavailable as e:
            seen.append(e)
            raise

    async def agent(ctx):
        await ctx.gather(*(lambda c, i=i: child(c, i) for i in range(4)))

    async def main():
        with pytest.raises(pragmatic.Unavailable) as caught:
            await rt.arun("sticky", agent)
        return caught.value

    raised = asyncio.run(main())
    assert raised is down
    assert len(seen) == 4 and all(e is down for e in seen)
    pystore.fail = None
    # The fork was durable before the children started, so the resumed run
    # takes the same region from there.
    assert json.loads(asyncio.run(rt.aresume("sticky", agent)).output) is None


def test_an_async_effect_whose_result_cannot_be_recorded(pystore):
    rt = pragmatic.Runtime(pystore)

    async def charge(_arg):
        await asyncio.sleep(0)
        pystore.fail = lambda n, f: OSError("disk full")
        return "charged"

    async def agent(ctx):
        return await ctx.aeffect("charge", "10 EUR", charge)

    async def main():
        with pytest.raises(pragmatic.EffectUnrecorded) as caught:
            await rt.arun("ua", agent)
        return caught.value

    exc = asyncio.run(main())
    assert exc.result == b"charged" and isinstance(exc.__cause__, OSError)
