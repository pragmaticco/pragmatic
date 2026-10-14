"""The Python SDK's server store against the real ``pragmatic-server``
(design 9, Python): what the SDK suite checks against its in-process mock,
checked again against the binary, since the mock has drifted from the
server before. Calls longer than the lease with a competing resume, a lost
response followed by a retry, ``run_deleted`` and ``payload_too_large``;
then the server's verdict on damaged and missing runs as ``rt.verify``
reports it, the roles ``replay`` needs, and ``push`` of a journal erased
locally.

The server runs without witnesses (``allow_self_anchoring``): nothing here
depends on time-stamps.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterator, Optional

import pytest

import harness
from harness import Server

PACKAGE = harness.REPO / "crates" / "pragmatic-python" / "python"

pragmatic = pytest.importorskip("pragmatic")


class LocalServer(Server):
    """A real server with no witnesses, a short lease, a retention policy
    that deletes ``doomed-*`` runs a day after their last append, and
    optionally a small request limit."""

    def __init__(self, *a, max_request_bytes: Optional[int] = None, **kw):
        super().__init__(*a, **kw)
        self.max_request_bytes = max_request_bytes

    def write_config(self, admin_sha256: str) -> None:
        q = harness._toml_string
        limit = (
            f"max_request_bytes = {self.max_request_bytes}\n" if self.max_request_bytes else ""
        )
        self.config.write_text(
            f"""name = {q(self.name)}
listen = {q(f"127.0.0.1:{self.port}")}
data_dir = {q(self.data_dir)}
lease_ttl_secs = {self.lease_ttl_secs}
{limit}
[keys]
signing_key_file = {q(self.keys_dir / "log.key")}

[bootstrap]
admin_token_sha256 = {q(admin_sha256)}

[anchoring]
interval_secs = 60
allow_self_anchoring = true

[[retention]]
match = {{ prefix = "doomed-" }}
delete_after_days = 1
"""
        )


@pytest.fixture(scope="module")
def env_bits() -> Iterator[dict]:
    bin_dir = harness.build_binaries()
    yield {"bin_dir": bin_dir, "env": harness.child_env(harness.find_openssl())}


def _server(env_bits: dict, work: Path, **kw) -> LocalServer:
    srv = LocalServer(
        work,
        env_bits["bin_dir"],
        env_bits["env"],
        name="sdk-e2e",
        witnesses=[],
        lease_ttl_secs=kw.pop("ttl", 2),
        licensee="",
        **kw,
    )
    srv.work.mkdir(parents=True, exist_ok=True)
    srv.setup()
    srv.start()
    return srv


@pytest.fixture
def server(env_bits: dict, tmp_path: Path) -> Iterator[LocalServer]:
    srv = _server(env_bits, tmp_path / "server")
    try:
        yield srv
    finally:
        srv.stop()


def _stem(run_id: str) -> str:
    return hashlib.sha256(run_id.encode()).hexdigest()


def _agent_token(srv: LocalServer) -> str:
    return srv.issue("agent", "svc:agent", "agent", ["*"])["token"]


# -- what the SDK suite checks against its mock ---------------------------------


def test_calls_longer_than_the_lease_never_let_a_competing_resume_in(server, tmp_path):
    token = _agent_token(server)
    rt = pragmatic.Runtime(server.api.url, token=token)
    rival = pragmatic.Runtime(server.api.url, token=token)
    log = tmp_path / "tools.log"
    sampled = []

    def slow_model():
        sampled.append(1)
        time.sleep(4.5)
        return "a plan"

    def slow_tool(q):
        with open(log, "a") as f:
            f.write(q + "\n")
        time.sleep(4.5)
        return "done"

    def agent(ctx):
        plan = ctx.draw("plan", slow_model)
        return plan + ": " + ctx.tool("work", slow_tool, "job")

    refusals = []

    def compete():
        for delay in (1.0, 3.0, 3.0):
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
    assert sampled == [1] and log.read_text().splitlines() == ["job"]
    again = rival.resume("long", agent)
    assert again.output == report.output and again.fresh_steps == 0
    assert sampled == [1] and log.read_text().splitlines() == ["job"]


class _DroppingProxy:
    """An HTTP proxy in front of the server that forwards every request and
    throws away the answers of the first ``drop`` appends: the server
    stored the frames, the client never hears so."""

    def __init__(self, upstream_port: int, drop: int):
        self.upstream_port = upstream_port
        self.drop = drop
        self.dropped = 0
        lock = threading.Lock()
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # noqa: D401 - quiet
                pass

            def _forward(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                headers = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in ("host", "connection", "content-length")
                }
                conn = http.client.HTTPConnection("127.0.0.1", proxy.upstream_port, timeout=60)
                try:
                    conn.request(self.command, self.path, body=body, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read()
                finally:
                    conn.close()
                with lock:
                    drop = (
                        self.command == "POST"
                        and self.path.split("?")[0].endswith("/frames")
                        and proxy.dropped < proxy.drop
                    )
                    if drop:
                        proxy.dropped += 1
                if drop:
                    self.close_connection = True
                    return
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _forward

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def test_a_lost_response_is_resent_and_reconciled_as_a_duplicate(server):
    token = _agent_token(server)
    proxy = _DroppingProxy(server.port, drop=2)
    try:
        rt = pragmatic.Runtime(proxy.url, token=token)
        performed = []

        def agent(ctx):
            a = ctx.tool("first", lambda: performed.append("first") or 1)
            b = ctx.tool("second", lambda: performed.append("second") or 2)
            return a + b

        report = rt.run("lost", agent)
    finally:
        proxy.close()
    assert proxy.dropped == 2
    assert report.output == "3" and performed == ["first", "second"]
    summary = server.api.ok("GET", server.api.run_path("lost"), server.admin_token)
    assert summary["entries"] >= report.journal_len, summary
    assert summary["verify"]["ok"] is True, summary
    duplicates = [
        r
        for r in server.api.audit(server.admin_token)
        if r.get("route", "").endswith("/frames") and r.get("duplicate") is True
    ]
    assert duplicates, "a resent append was answered as a duplicate"


def test_run_deleted_maps_to_deleted_and_is_never_recreated(server):
    token = _agent_token(server)
    rt = pragmatic.Runtime(server.api.url, token=token)
    rt.run("doomed-1", lambda ctx: ctx.tool("t", lambda: "x"))
    server.stop()
    stem = _stem("doomed-1")
    meta_path = server.data_dir / "runs" / stem[:2] / f"{stem}.meta.json"
    meta = json.loads(meta_path.read_text())
    meta["updated_at"] = "2020-01-01T00:00:00Z"
    meta_path.write_text(json.dumps(meta))
    server.start()
    report = server.api.ok("POST", "/v1/retention/run", server.admin_token, json_body={})
    assert report["deleted"] == ["doomed-1"], report
    with pytest.raises(pragmatic.Deleted):
        rt.resume("doomed-1", lambda ctx: ctx.tool("t", lambda: "x"))
    with pytest.raises(pragmatic.Deleted):
        rt.run("doomed-1", lambda ctx: "x")
    resp = server.api.request("GET", server.api.run_path("doomed-1"), server.admin_token)
    assert resp.status == 410


def test_payload_too_large_maps_to_too_large_before_anything_is_performed(env_bits, tmp_path):
    srv = _server(env_bits, tmp_path / "small", max_request_bytes=4096)
    try:
        rt = pragmatic.Runtime(srv.api.url, token=_agent_token(srv))
        performed = []

        def agent(ctx):
            return ctx.effect("upload", "x" * 20_000, lambda arg: performed.append(1) or "ok")

        with pytest.raises(pragmatic.TooLarge) as caught:
            rt.run("big", agent)
        assert caught.value.limit == 4096
        assert performed == []
    finally:
        srv.stop()


# -- the server's verdict, as the SDK reports it ----------------------------------


def _cut_last_frame(path: Path) -> None:
    data = path.read_bytes()
    pos, frames = 16, []
    while pos + 4 <= len(data):
        n = int.from_bytes(data[pos : pos + 4], "little")
        frames.append(pos)
        pos += 4 + n + 32
    path.write_bytes(data[: frames[-1]])


def test_verify_of_a_missing_run_fails_for_every_token(server):
    token = _agent_token(server)
    auditor = server.issue("aud", "auditor@example.com", "auditor", ["*"])["token"]
    rt = pragmatic.Runtime(server.api.url, token=token)
    rt.run("gone", lambda ctx: ctx.effect("e", "x", lambda a, **k: "ok"))
    # Anchored (by the server's own signature): the log knows the run.
    server.api.ok("GET", "/v1/runs/gone/evidence", server.admin_token, query={"anchor": "now"})
    server.stop()
    stem = _stem("gone")
    for p in (server.data_dir / "runs" / stem[:2]).glob(stem + "*"):
        p.unlink()
    server.start()
    s = server.api.ok("GET", "/v1/runs/gone", server.admin_token)
    assert s["status"] == "missing" and s["verify"]["ok"] is False, s
    for who in (auditor, server.admin_token, token):
        report = pragmatic.Runtime(server.api.url, token=who).verify("gone")
        assert not report, f"a missing run reported intact: {report}"


def test_verify_and_snapshot_of_a_damaged_run_answer_at_once(server):
    token = _agent_token(server)
    rt = pragmatic.Runtime(server.api.url, token=token)
    rt.run("lost", lambda ctx: ctx.effect("e", "x", lambda a, **k: "ok"))
    server.stop()
    stem = _stem("lost")
    _cut_last_frame(server.data_dir / "runs" / stem[:2] / f"{stem}.journal")
    server.start()
    admin = pragmatic.Runtime(server.api.url, token=server.admin_token)
    report = admin.verify("lost")
    assert not report and report.damaged, report
    store = pragmatic.ServerStore(server.api.url, server.admin_token, sync_deadline=30)
    store.connect()
    started = time.monotonic()
    with pytest.raises(pragmatic.ServerError) as caught:
        store.snapshot("lost")
    assert caught.value.code == "chain_broken"
    assert time.monotonic() - started < 10, "a definitive answer, not resends until the deadline"


def test_replay_names_the_tokens_that_may_read_a_journal(server):
    token = _agent_token(server)
    rt = pragmatic.Runtime(server.api.url, token=token)

    def agent(ctx):
        return ctx.effect("e", "x", lambda a, **k: "y")

    rt.run("rp-1", agent)
    with pytest.raises(pragmatic.ServerError) as caught:
        rt.replay("rp-1", agent)
    assert "admin token or an auditor token with view_raw" in str(caught.value)
    raw = server.issue("raw", "auditor@example.com", "auditor", ["*"], view_raw=True)["token"]
    assert pragmatic.Runtime(server.api.url, token=raw).replay("rp-1", agent).output == "y"


def test_push_of_a_journal_erased_locally_is_refused_before_anything_is_created(
    server, env_bits, tmp_path
):
    token = _agent_token(server)
    local = tmp_path / "journals"
    script = (
        "import sys, pragmatic\n"
        "rt = pragmatic.Runtime(sys.argv[1])\n"
        "rt.run('dsar-1', lambda ctx: ctx.tool('note', lambda t: 'ok', "
        "'customer jane.doe@example.com asked for a refund'))\n"
    )
    env = dict(env_bits["env"], PYTHONPATH=str(PACKAGE))
    subprocess.run([sys.executable, "-c", script, str(local)], env=env, check=True)
    erased = subprocess.run(
        [
            str(env_bits["bin_dir"] / harness.exe("pragmatic")),
            "erase",
            "dsar-1",
            "--dir",
            str(local),
            "--match",
            "jane.doe@example.com",
            "--reason-code",
            "dsar",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert erased.returncode == 0, erased.stdout + erased.stderr
    pushed = subprocess.run(
        [sys.executable, "-m", "pragmatic", "push", str(local), "dsar-1"],
        env=dict(env, PRAGMATIC_URL=server.api.url, PRAGMATIC_TOKEN=token),
        capture_output=True,
        text=True,
    )
    assert pushed.returncode == 1, pushed.stdout + pushed.stderr
    assert "dsar-1: refused" in pushed.stdout and "erase" in pushed.stdout, pushed.stdout
    resp = server.api.request("GET", server.api.run_path("dsar-1"), server.admin_token)
    assert resp.status == 404, "no empty run was left behind"
