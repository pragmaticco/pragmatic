"""An in-process stand-in for Pragmatic Server, for the ServerStore tests.

It implements the parts of the HTTP API v1 (spec 4.4 to 4.6) the Python
client relies on: info and whoami, run creation with a lease, lease
acquire, renew and release with lazy expiry, journal download, appends with
the duplicate rule and the check order of 4.6 (run, duplicate, lease, at,
frames), run summaries and Entry JSON pages, and the error codes of the 4.4
table. Every append is validated by parsing the whole journal with the
native verifier, so a client that sends a broken chain fails here as it
would on the real server.

Faults are injected per route: a lost response (the request is processed
and the connection closed before the answer), a 503, a delay, or a wrong
head in the answer.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from pragmatic import _native

HEADER = _native.JOURNAL_HEADER
HASH_LEN = 32


def split_frames(body: bytes) -> Optional[List[bytes]]:
    out = []
    pos = 0
    while pos < len(body):
        if pos + 4 > len(body):
            return None
        n = int.from_bytes(body[pos : pos + 4], "little")
        end = pos + 4 + n + HASH_LEN
        if end > len(body):
            return None
        out.append(body[pos:end])
        pos = end
    return out


@dataclass
class Lease:
    holder: str
    id: str
    expires: float


@dataclass
class Run:
    frames: List[bytes] = field(default_factory=list)
    lease: Optional[Lease] = None
    created_at: float = field(default_factory=time.time)

    @property
    def journal(self) -> bytes:
        return HEADER + b"".join(self.frames)

    @property
    def head(self) -> str:
        return self.frames[-1][-HASH_LEN:].hex() if self.frames else ""


@dataclass
class Fault:
    method: str
    pattern: str
    action: str
    count: int


class MockServer:
    """See the module documentation. Use as a context manager."""

    def __init__(
        self,
        *,
        token: str = "test-token",
        ttl: float = 60.0,
        max_request_bytes: int = 64 << 20,
        advertised_max: Optional[int] = None,
        api_version: int = 1,
        snapshots: bool = True,
        page_cap: Optional[int] = None,
    ):
        self.token = token
        self.ttl = ttl
        self.max_request_bytes = max_request_bytes
        self.advertised_max = advertised_max if advertised_max is not None else max_request_bytes
        self.api_version = api_version
        self.snapshots = snapshots
        self.page_cap = page_cap
        self.runs: Dict[str, Run] = {}
        self.tombstones: set = set()
        self.lock = threading.RLock()
        self.faults: List[Fault] = []
        self.log: List[Tuple[str, str, int]] = []
        self.renewals = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.mock = self  # type: ignore[attr-defined]
        self.httpd = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "MockServer":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- test controls ----------------------------------------------------

    def inject(self, method: str, pattern: str, action: str, count: int = 1) -> None:
        """Make the next ``count`` requests matching ``method`` and the path
        regex ``pattern`` fail with ``action``: ``drop`` (process, then close
        the connection unanswered), ``503``, ``delay:<secs>``, ``bad_head``
        or ``error:<status>:<code>`` (answer with that error unprocessed)."""
        with self.lock:
            self.faults.append(Fault(method, pattern, action, count))

    def tombstone(self, run_id: str) -> None:
        with self.lock:
            self.runs.pop(run_id, None)
            self.tombstones.add(run_id)

    def steal_lease(self, run_id: str) -> None:
        """Grant the run's lease to another holder."""
        with self.lock:
            self.runs[run_id].lease = Lease("thief", uuid.uuid4().hex, time.monotonic() + self.ttl)

    def entries(self, run_id: str) -> int:
        with self.lock:
            return len(self.runs[run_id].frames)

    def journal(self, run_id: str) -> bytes:
        with self.lock:
            return self.runs[run_id].journal

    def count(self, method: str, pattern: str) -> int:
        return sum(1 for m, p, _ in self.log if m == method and re.search(pattern, p))

    def take_fault(self, method: str, path: str) -> Optional[str]:
        with self.lock:
            for f in self.faults:
                if f.method == method and re.search(f.pattern, path) and f.count > 0:
                    f.count -= 1
                    return f.action
        return None

    # -- routes -------------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        return {
            "server": "mock",
            "version": "0.6.0",
            "api_version": self.api_version,
            "min_sdk": "0.6.0",
            "journal_format": 2,
            "chain": "sha256",
            "lease_ttl_secs": self.ttl,
            "max_request_bytes": self.advertised_max,
            "max_frame_bytes": self.advertised_max,
            "server_time": time.time(),
            "independent_witness": False,
            "licensee": "",
        }

    def summary(self, run_id: str, run: Run) -> Dict[str, Any]:
        return {
            "run_id": run_id,
            "entries": len(run.frames),
            "head": run.head or None,
            "created_at": None,
            "updated_at": None,
            "status": "active" if run.lease else "idle",
            "erased_slots": 0,
            "anchored_entries": 0,
            "unanchored_entries": len(run.frames),
            "holds": [],
            "labels": {},
            "program": None,
            "created_by": None,
            "last_outcome": None,
            "usage": {},
            "verify": {
                "first_bad": None,
                "unaccounted_erasures": [],
                "erasure_incomplete": [],
                "invalid_erasure_notes": [],
                "torn_bytes": 0,
            },
        }

    def grant(self, run: Run, holder: str) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        now = time.monotonic()
        lease = run.lease
        if lease is None or lease.holder == holder or lease.expires < now:
            if lease is not None and lease.holder == holder:
                self.renewals += 1
                lease.expires = now + self.ttl
            else:
                run.lease = Lease(holder, uuid.uuid4().hex, now + self.ttl)
            return 200, {"lease": run.lease.id, "ttl_secs": self.ttl}, {}
        left = lease.expires - now
        return (
            409,
            error("run_locked", "the run is leased", holder_expires_in=left),
            {"Retry-After": str(math.ceil(left))},
        )


def error(code: str, message: str, **extra: Any) -> Dict[str, Any]:
    return {"error": dict(code=code, message=message, **extra)}


_RUN = re.compile(r"^/v1/runs/([^/]+)(/lease|/journal|/frames|/entries)?$")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # quiet
        pass

    @property
    def mock(self) -> MockServer:
        return self.server.mock  # type: ignore[attr-defined]

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, status: int, body: Any, headers: Optional[Dict[str, str]] = None) -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        ctype = "application/octet-stream" if isinstance(body, bytes) else "application/json"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, method: str) -> None:
        parts = urlsplit(self.path)
        body = self._body()
        action = self.mock.take_fault(method, parts.path)
        if action == "503":
            self.mock.log.append((method, parts.path, 503))
            self._send(503, error("storage_unavailable", "try again"), {"Retry-After": "0"})
            return
        if action and action.startswith("delay:"):
            time.sleep(float(action.split(":", 1)[1]))
        if action and action.startswith("error:"):
            _, status, code = action.split(":", 2)
            self.mock.log.append((method, parts.path, int(status)))
            self._send(int(status), error(code, f"injected {code}"))
            return
        if self.headers.get("Authorization") != f"Bearer {self.mock.token}":
            status, out, hdrs = 401, error("unauthorized", "bad token"), {}
        else:
            status, out, hdrs = self._route(method, parts.path, parse_qs(parts.query), body)
        self.mock.log.append((method, parts.path, status))
        if action == "drop":
            # Processed, but the answer never arrives.
            self.close_connection = True
            self.connection.shutdown(2)
            return
        if action == "bad_head" and isinstance(out, dict) and "head" in out:
            out = dict(out, head="00" * 32)
        self._send(status, out, hdrs)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _route(self, method: str, path: str, query: Dict[str, List[str]], body: bytes):
        m = self.mock
        if path == "/v1/info" and method == "GET":
            return 200, m.info(), {}
        if path == "/v1/whoami" and method == "GET":
            return 200, {"token_id": "t1", "name": "test", "principal": "svc:test", "role": "admin", "scopes": ["*"]}, {}
        if path == "/v1/runs" and method == "GET":
            with m.lock:
                runs = [m.summary(r, run) for r, run in sorted(m.runs.items())]
            return 200, {"runs": runs, "next": None}, {}
        match = _RUN.match(path)
        if not match:
            return 404, error("not_found", path), {}
        run_id, sub = unquote(match.group(1)), match.group(2) or ""
        with m.lock:
            if run_id in m.tombstones:
                return 410, error("run_deleted", "deleted"), {}
            run = m.runs.get(run_id)
            if method == "PUT" and not sub:
                if run is not None:
                    return 409, error("run_exists", "exists"), {}
                if body != HEADER:
                    return 400, error("bad_request", "the body must be the unkeyed header"), {}
                run = m.runs[run_id] = Run()
                return 201, m.grant(run, self.headers.get("Pragmatic-Holder") or uuid.uuid4().hex)[1], {}
            if run is None:
                return 404, error("not_found", run_id), {}
            if sub == "" and method == "GET":
                return 200, m.summary(run_id, run), {}
            if sub == "/lease" and method == "POST":
                return m.grant(run, json.loads(body)["holder"])
            if sub == "/lease" and method == "DELETE":
                if run.lease and run.lease.id == self.headers.get("Pragmatic-Lease"):
                    run.lease = None
                return 204, b"", {}
            if sub == "/journal" and method == "GET":
                held = run.lease and run.lease.id == self.headers.get("Pragmatic-Lease")
                if not held and not m.snapshots:
                    return 404, error("not_found", run_id), {}
                return 200, run.journal, {"Pragmatic-Entries": str(len(run.frames)), "Pragmatic-Head": run.head}
            if sub == "/entries" and method == "GET":
                # As the server pages (spec 4.4): {entries, next, total},
                # and a page may stop short of `limit` (the server bounds
                # pages by bytes too), which `page_cap` imitates.
                start = int(query.get("from", ["0"])[0])
                limit = int(query.get("limit", ["1000"])[0])
                if m.page_cap is not None:
                    limit = min(limit, m.page_cap)
                total = len(run.frames)
                end = min(total, start + limit)
                entries = [{"cursor": i} for i in range(start, end)]
                return 200, {"entries": entries, "next": end if end < total else None, "total": total}, {}
            if sub == "/frames" and method == "POST":
                return self._append(run, query, body)
        return 404, error("not_found", path), {}

    def _append(self, run: Run, query: Dict[str, List[str]], body: bytes):
        m = self.mock
        if len(body) > m.max_request_bytes:
            return 413, error("payload_too_large", "too large", limit=m.max_request_bytes), {}
        at = int(query["at"][0])
        k = int(self.headers.get("Pragmatic-Frames") or -1)
        frames = split_frames(body)
        if frames is None or len(frames) != k:
            return 422, error("invalid_frames", "frames do not split"), {}
        stored = run.frames
        if at + k <= len(stored) and [f[-HASH_LEN:] for f in stored[at : at + k]] == [f[-HASH_LEN:] for f in frames]:
            return 200, {"entries": len(stored), "head": stored[at + k - 1][-HASH_LEN:].hex(), "duplicate": True}, {}
        if run.lease is None or run.lease.id != self.headers.get("Pragmatic-Lease"):
            return 409, error("lease_lost", "the lease is held by another writer"), {}
        if at != len(stored):
            return 409, error("conflict", "wrong position", entries=len(stored), head=run.head), {}
        try:
            entries, head = _native.check_journal(run.journal + body)
        except ValueError as e:
            return 422, error("invalid_frames", str(e)), {}
        if head != self.headers.get("Pragmatic-Head"):
            return 422, error("invalid_frames", "the head does not match"), {}
        stored.extend(frames)
        return 200, {"entries": entries, "head": head, "duplicate": False}, {}
