"""ServerStore against an in-process mock of Pragmatic Server (spec 4.4 to
4.6, 6.1, 6.3): construction checks, the create order, crash in one
process and resume in another, leases held through calls longer than
their TTL, resending with duplicate reconciliation, and the mapping of
the server's error codes.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import threading
import time
import warnings

import pytest

import pragmatic
from mock_server import HASH_LEN, MockServer, split_frames
from server_agent import make_agent

TOKEN = "test-token"
HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.join(os.path.dirname(HERE), "python")


class Die(BaseException):
    pass


@pytest.fixture
def server():
    with MockServer() as srv:
        yield srv


def runtime(srv, **kw):
    return pragmatic.Runtime(srv.url, token=TOKEN, **kw)


def child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([PACKAGE, HERE, env.get("PYTHONPATH", "")])
    return env


def log_lines(path):
    try:
        with open(path) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


# ---------------------------------------------------------------------------
# Construction (spec 6.1)
# ---------------------------------------------------------------------------


def test_the_runtime_checks_the_server_when_it_is_built(server, monkeypatch):
    rt = runtime(server)
    assert isinstance(rt.store, pragmatic.ServerStore)
    assert rt.store.whoami["principal"] == "svc:test"
    assert [m for m, p, _ in server.log[:2]] == ["GET", "GET"]

    with pytest.raises(pragmatic.PragmaticError) as bad_token:
        pragmatic.Runtime(server.url, token="wrong")
    assert server.url in str(bad_token.value) and "401" in str(bad_token.value)

    monkeypatch.setenv("PRAGMATIC_URL", server.url)
    monkeypatch.setenv("PRAGMATIC_TOKEN", TOKEN)
    assert isinstance(pragmatic.Runtime().store, pragmatic.ServerStore)
    with pytest.raises(ValueError, match="unkeyed"):
        pragmatic.Runtime(key=b"secret")
    monkeypatch.setenv("PRAGMATIC_JOURNAL_KEY", "secret")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        pragmatic.Runtime()
    assert any("PRAGMATIC_JOURNAL_KEY is ignored" in str(w.message) for w in caught)


def test_an_incompatible_or_unreachable_server_is_refused():
    with MockServer(api_version=2) as srv:
        with pytest.raises(pragmatic.PragmaticError, match="incompatible: api_version 2"):
            pragmatic.Runtime(srv.url, token=TOKEN)
    with MockServer() as srv:
        url = srv.url
    with pytest.raises(pragmatic.PragmaticError, match="cannot reach the server at " + url):
        pragmatic.Runtime(url, token=TOKEN)


# ---------------------------------------------------------------------------
# Runs on a server
# ---------------------------------------------------------------------------


def test_a_run_dies_in_one_process_and_resumes_in_another(tmp_path):
    log = str(tmp_path / "tools.log")
    with MockServer(ttl=1.0) as srv:
        died = subprocess.run(
            [sys.executable, os.path.join(HERE, "server_agent.py"), srv.url, "r-1", log, "run-and-die"],
            env=child_env(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert died.returncode == 17, died.stderr
        assert log_lines(log) == ["search durable execution"]
        # The dead process never released its lease: a resume waits it out
        # (lazy expiry), then continues without repeating the search.
        resumed = subprocess.run(
            [sys.executable, os.path.join(HERE, "server_agent.py"), srv.url, "r-1", log, "resume"],
            env=child_env(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert resumed.returncode == 0, resumed.stderr
        assert resumed.stdout.strip() == "search, then fetch the first hit: contents of a://1"
        assert log_lines(log) == ["search durable execution", "fetch a://1"]
        # Replayed here, from the server's journal, nothing is performed.
        rt = runtime(srv)
        audit = rt.replay("r-1", make_agent(log))
        assert audit.output == resumed.stdout.strip()
        assert len(log_lines(log)) == 2
        assert rt.verify("r-1")
        assert srv.count("PUT", "/v1/runs/r-1$") == 1


def test_calls_longer_than_the_lease_never_let_a_competing_resume_in(tmp_path):
    log = str(tmp_path / "tools.log")
    sampled = []
    with MockServer(ttl=1.0) as srv:
        rt = runtime(srv)
        rival = runtime(srv)

        def slow_model():
            sampled.append(1)
            time.sleep(2.2)
            return "a plan"

        def slow_tool(q):
            with open(log, "a") as f:
                f.write(q + "\n")
            time.sleep(2.2)
            return "done"

        def agent(ctx):
            plan = ctx.draw("plan", slow_model)
            return plan + ": " + ctx.tool("work", slow_tool, "job")

        refusals = []

        def compete():
            for delay in (0.4, 2.0, 1.2):
                time.sleep(delay)
                try:
                    rival.resume("long", agent, recover=lambda n, a: "never")
                    refusals.append("got in")
                except pragmatic.Locked as e:
                    refusals.append(type(e).__name__)

        t = threading.Thread(target=compete)
        t.start()
        report = rt.run("long", agent)
        t.join()
        assert report.output == "a plan: done"
        assert refusals == ["Locked", "Locked", "Locked"]
        assert srv.renewals >= 6, "renewed every ttl/3 through both calls"
        # Neither call happened twice, and the rival resumes cleanly now.
        assert sampled == [1] and log_lines(log) == ["job"]
        again = rival.resume("long", agent)
        assert again.output == report.output and again.fresh_steps == 0
        assert sampled == [1] and log_lines(log) == ["job"]


def test_a_lost_answer_is_resent_and_reconciled_as_a_duplicate(server):
    rt = runtime(server)
    performed = []

    def agent(ctx):
        a = ctx.tool("first", lambda: performed.append("first") or 1)
        b = ctx.tool("second", lambda: performed.append("second") or 2)
        return a + b

    server.inject("POST", "/frames$", "drop", count=2)
    server.inject("POST", "/frames$", "503", count=2)
    report = rt.run("lost", agent)
    assert report.output == "3" and performed == ["first", "second"]
    assert server.entries("lost") == report.journal_len, "every frame stored exactly once"
    assert rt.verify("lost")
    # Two answers were lost after the server stored the frames; the resent
    # requests were answered as duplicates.
    appends = [s for m, p, s in server.log if m == "POST" and p.endswith("/frames")]
    assert appends.count(503) == 2 and len(appends) >= 2 + 2 + 2


def test_a_conflict_is_reconciled_through_the_duplicate_rule(tmp_path, server):
    # A journal recorded locally gives real frames to append by hand.
    local = pragmatic.Runtime(tmp_path)
    local.run("c", lambda ctx: [ctx.tool(f"t{i}", lambda: i) for i in range(3)])
    path = tmp_path / (hashlib.sha256(b"c").hexdigest() + ".journal")
    frames = split_frames(path.read_bytes()[16:])
    store = pragmatic.ServerStore(server.url, TOKEN)
    store.connect()
    store.checkout("c", True)
    try:
        store.persist("c", 0, b"".join(frames[:5]), 5, frames[4][-HASH_LEN:].hex())
        # This writer believes only 3 entries are durable and sends 3..8:
        # the server holds 3..5 already, so only 5..8 are appended.
        tail = b"".join(frames[3:8])
        store.persist("c", 3, tail, 5, frames[7][-HASH_LEN:].hex())
        assert server.entries("c") == 8
        # A resent prefix is a duplicate, whatever else changed since.
        store.persist("c", 2, frames[2], 1, frames[2][-HASH_LEN:].hex())
        # A gap cannot be reconciled.
        with pytest.raises(pragmatic.Conflict):
            store.persist("c", 9, frames[8], 1, frames[8][-HASH_LEN:].hex())
    finally:
        store.checkin("c")
    assert server.journal("c") == path.read_bytes()[: 16 + sum(len(f) for f in frames[:8])]


def test_unavailable_after_the_deadline_is_sticky(server, monkeypatch):
    monkeypatch.setenv("PRAGMATIC_SYNC_DEADLINE", "0.5")
    rt = runtime(server)
    caught = []

    def agent(ctx):
        server.inject("POST", "/frames$", "503", count=1000)
        for _ in range(2):
            try:
                ctx.now()
            except pragmatic.Unavailable as e:
                caught.append(e)
        return "x"

    with pytest.raises(pragmatic.Unavailable):
        rt.run("u", agent)
    assert len(caught) == 2 and caught[0] is caught[1]


def test_run_deleted_maps_to_deleted_and_is_never_recreated(server):
    rt = runtime(server)
    server.tombstone("gone")
    with pytest.raises(pragmatic.Deleted):
        rt.run("gone", lambda ctx: "x")
    assert server.count("PUT", "/v1/runs/gone$") == 0

    def agent(ctx):
        ctx.tool("before", lambda: 1)
        server.tombstone("mid")
        try:
            ctx.tool("after", lambda: 2)
        except pragmatic.Deleted:
            return "deleted"
        return "not deleted"

    with pytest.raises(pragmatic.Deleted):
        rt.run("mid", agent)


def test_payload_too_large_maps_to_too_large_before_anything_is_performed():
    with MockServer(max_request_bytes=4096, advertised_max=1 << 20) as srv:
        rt = runtime(srv)
        performed = []

        def agent(ctx):
            return ctx.effect("upload", "x" * 20_000, lambda arg: performed.append(1) or "ok")

        with pytest.raises(pragmatic.TooLarge) as caught:
            rt.run("big", agent)
        assert caught.value.limit == 4096
        assert performed == []


def test_appends_are_split_to_fit_the_servers_limit():
    with MockServer(max_request_bytes=600, advertised_max=600) as srv:
        rt = runtime(srv)
        report = rt.run("split", lambda ctx: [ctx.uuid4() and 1 for _ in range(3)] and "ok")
        assert report.output == "ok"
        assert srv.entries("split") == report.journal_len
        # attempt.end and its neighbours did not fit one request.
        assert srv.count("POST", "/frames$") > 3


def test_a_lost_lease_fails_the_session(server):
    rt = runtime(server)

    def agent(ctx):
        ctx.tool("before", lambda: 1)
        server.steal_lease("stolen")
        ctx.tool("after", lambda: 2)
        return "x"

    with pytest.raises(pragmatic.LeaseLost) as caught:
        rt.run("stolen", agent)
    assert isinstance(caught.value, pragmatic.Locked)


def test_a_head_the_client_did_not_compute_is_a_conflict(server):
    rt = runtime(server)

    def agent(ctx):
        server.inject("POST", "/frames$", "bad_head")
        return ctx.tool("t", lambda: 1)

    with pytest.raises(pragmatic.Conflict):
        rt.run("h", agent)


def test_server_runs_need_a_recovery_policy_for_dangling_effects(server):
    rt = runtime(server)

    def perform(_arg):
        raise Die()

    def crash(ctx):
        return ctx.effect("charge", "10 EUR", perform)

    with pytest.raises(Die):
        rt.run("d", crash)
    with pytest.raises(pragmatic.DanglingEffect):
        rt.resume("d", crash)

    async def checked(name, arg, branch, intent):
        await asyncio.sleep(0)
        return f"{name} {arg} confirmed"

    async def agent(ctx):
        return await ctx.aeffect("charge", "10 EUR", perform)

    report = asyncio.run(rt.aresume("d", agent, recover=checked))
    assert report.output == "charge 10 EUR confirmed"


def test_concurrent_async_runs_against_one_server(server):
    rt = runtime(server)

    async def agent(ctx):
        parts = await ctx.gather(
            lambda c: c.atool("a", lambda: ctx.run_id + ":a"),
            lambda c: c.atool("b", lambda: ctx.run_id + ":b"),
        )
        return "+".join(parts)

    async def main():
        return await asyncio.gather(*(rt.arun(f"async-{i}", agent) for i in range(10)))

    reports = asyncio.run(main())
    assert [r.output for r in reports] == [f"async-{i}:a+async-{i}:b" for i in range(10)]
    assert sorted(s.run_id for s in rt.runs()) == sorted(f"async-{i}" for i in range(10))
    assert len(rt.entries("async-3")) == reports[3].journal_len


# ---------------------------------------------------------------------------
# python -m pragmatic push
# ---------------------------------------------------------------------------


def push(srv, *args):
    env = child_env()
    env["PRAGMATIC_TOKEN"] = TOKEN
    return subprocess.run(
        [sys.executable, "-m", "pragmatic", "push", *args, "--url", srv.url],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_push_uploads_unkeyed_local_journals(tmp_path, server):
    local = pragmatic.Runtime(tmp_path / "journals")
    local.run("local-1", lambda ctx: ctx.tool("t", lambda: "x"))
    out = push(server, str(tmp_path / "journals"), "local-1")
    assert out.returncode == 0, out.stdout + out.stderr
    entries = len(local.entries("local-1"))
    assert f"local-1: pushed {entries} of {entries} entries" in out.stdout
    assert server.entries("local-1") == entries
    # The run continues locally; pushing again sends only what is new.
    local.resume("local-1", lambda ctx: ctx.tool("t", lambda: "x"))
    more = len(local.entries("local-1")) - entries
    again = push(server, str(tmp_path / "journals"), "--all")
    assert again.returncode == 0 and f"pushed {more} of" in again.stdout
    assert runtime(server).verify("local-1")


def test_push_refuses_keyed_and_format_1_journals(tmp_path, server):
    keyed = pragmatic.Runtime(tmp_path / "j", key=b"secret")
    keyed.run("keyed", lambda ctx: "x")
    legacy = tmp_path / "j" / (hashlib.sha256(b"old").hexdigest() + ".journal")
    legacy.write_bytes(b"PRAGJRNL" + (1).to_bytes(4, "little"))
    out = push(server, str(tmp_path / "j"), "keyed", "old")
    assert out.returncode == 1
    assert "keyed: refused: the journal is keyed" in out.stdout
    assert "old: refused: the journal is a format 1 journal" in out.stdout
    assert server.count("PUT", "/v1/runs/") == 0
