"""``ServerStore``: journals on a Pragmatic Server (spec 4.4 to 4.6, 6.3).

Standard library only. The store speaks the server's HTTP API v1:

- **Connections.** One persistent keep-alive connection per thread (the
  agent's thread, the attempt's persist executor and each lease's renewal
  thread), with a 5 second connect timeout and the runtime's ``timeout`` for
  reads.
- **Resending.** Connect errors, timeouts and 502, 503 and 504 answers are
  resent as the identical request, with exponential backoff, until success,
  a definitive error, ``PRAGMATIC_SYNC_DEADLINE`` (default 120 s) or, for a
  request made under a lease, the lease deadline; then ``Unavailable``.
  Every request is safe to resend: appends carry their position (``at``) and
  the server answers a repeat with ``duplicate: true`` (4.6), lease requests
  name their holder, and a repeated ``PUT`` that finds the run created goes
  on with ``POST lease`` as the create order does anyway. A server that
  answers before it has read a request's whole body (a 413 for a body over
  its limit) and closes the connection makes the write fail; its answer is
  read all the same, so it is never mistaken for a connection error.
- **Unknown outcomes.** An append whose resends ran out may still have been
  stored (an earlier try whose answer was lost): before raising
  ``Unavailable`` the store looks once at the run's entries and head, and
  reports success if its frames are there. A duplicate answer from a run
  that has grown past the frames (another writer took it over and appended
  at least its custody note) is ``LeaseLost``: the frames are durable, but
  this writer no longer holds the run and must not act on them.
- **Leases.** A checkout acquires the run's lease, creating the run when
  asked (POST lease; on ``not_found`` PUT; on ``run_exists`` POST lease
  again), starts a dedicated OS thread that renews the lease every
  ``ttl/3`` for the whole checkout (the journal download, model calls,
  effects and recovery callbacks alike), and downloads the journal. The
  client keeps its own deadline, the time a grant was requested plus
  ``ttl - ttl/4`` on its monotonic clock, and never compares wall clocks. A
  lease the server gives to someone else is lost: the next persist raises
  ``LeaseLost``. Checkin stops the renewal thread, which never resends once
  asked to stop and gives back any grant that arrives after that, and then
  releases the lease, so a released lease is never granted again.
- **Verification.** Every downloaded journal is verified (chain and
  commitments, by the native layer) and must end at the entry count and head
  the server sent with it, and the head the server returns after every
  append must equal the client's own. A mismatch is ``Conflict``.

Errors map to exceptions per the table in spec 4.4: ``run_locked`` is
``Locked(retry_after)``, ``lease_lost`` and ``lease_expired`` are
``LeaseLost``, ``run_deleted`` is ``Deleted`` (the run is never recreated),
``payload_too_large`` is ``TooLarge`` (raised without sending for a frame
over the ``max_request_bytes`` or ``max_frame_bytes`` the server announced),
``conflict`` is reconciled through the duplicate rule or raised as
``Conflict``, a missing run is
``FileNotFoundError``, and other refusals (``unauthorized``, ``forbidden``,
``invalid_frames``, ``regressed``, ``bad_request``) are ``ServerError``.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import random
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple, Union
from urllib.parse import quote, urlencode, urlsplit

from . import _native
from ._errors import (
    Conflict,
    Deleted,
    LeaseLost,
    Locked,
    PragmaticError,
    ServerError,
    TooLarge,
    Unavailable,
)

API_VERSION = 1
JOURNAL_FORMAT = 2
CHAIN = "sha256"
CONNECT_TIMEOUT = 5.0
DEFAULT_SYNC_DEADLINE = 120.0
_RESEND_STATUSES = frozenset({502, 503, 504})
_HASH_LEN = 32

Deadline = Union[float, Callable[[], float]]


def is_server_url(value: str) -> bool:
    """True for ``http://`` and ``https://`` values (spec 6.1)."""
    return value.startswith("http://") or value.startswith("https://")


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> None:
    """Refuse URLs the SDK will not talk to: anything but http(s), and plain
    ``http://`` to a host that is not loopback (credentials and journal
    content would cross the network unencrypted)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not a server URL: {url!r}")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise ValueError(
            f"plain http:// is allowed only for loopback hosts; use https:// for {parts.hostname}"
        )


def _version_tuple(text: str) -> Tuple[int, ...]:
    out = []
    for piece in str(text).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


@dataclass
class _Response:
    status: int
    headers: Dict[str, str]
    body: bytes
    sent_at: float

    def json(self) -> Any:
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None

    @property
    def error(self) -> Dict[str, Any]:
        doc = self.json()
        if isinstance(doc, dict) and isinstance(doc.get("error"), dict):
            return doc["error"]
        return {}

    @property
    def code(self) -> str:
        return str(self.error.get("code") or "")

    @property
    def message(self) -> str:
        return str(self.error.get("message") or "")

    def retry_after(self) -> Optional[int]:
        value = self.headers.get("retry-after")
        if value is None:
            return None
        try:
            return max(0, int(float(value)))
        except ValueError:
            return None


@dataclass
class _Lease:
    """One checkout's lease and its renewal thread."""

    run_id: str
    holder: str
    lease: str = ""
    ttl: float = 60.0
    deadline: float = 0.0
    lost: str = ""
    stop: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def grant(self, doc: Mapping[str, Any], sent_at: float) -> None:
        """Take a grant (or renewal): the client's deadline is the time the
        request was sent plus ``ttl - ttl/4`` (spec 4.5)."""
        ttl = float(doc.get("ttl_secs") or self.ttl)
        with self.lock:
            self.lease = str(doc.get("lease") or self.lease)
            self.ttl = ttl
            self.deadline = sent_at + ttl - ttl / 4


def _early_answer(conn: http.client.HTTPConnection) -> Optional[http.client.HTTPResponse]:
    """The answer a server sent before the request's body was written
    whole, if one arrived; ``None`` otherwise."""
    try:
        return conn.getresponse()
    except (OSError, http.client.HTTPException):
        return None


def _frames(frames: bytes) -> List[Tuple[int, int]]:
    """The ``(start, end)`` byte range of every frame in ``frames``."""
    out = []
    pos = 0
    while pos + 4 <= len(frames):
        n = int.from_bytes(frames[pos : pos + 4], "little")
        end = pos + 4 + n + _HASH_LEN
        out.append((pos, end))
        pos = end
    if pos != len(frames):
        raise ValueError("frames do not split into whole frames")
    return out


class ServerStore:
    """Runs on a Pragmatic Server. See the module documentation.

    ``ServerStore(url, token, *, timeout=30.0, ssl_context=None)``;
    ``ssl_context`` verifies a server whose certificate a private CA issued
    (the default trusts the system's roots). The runtime calls
    :meth:`connect` (``GET /v1/info`` and ``/v1/whoami``) when it is built
    over the store, so a wrong URL or token fails there, not in the middle
    of a run."""

    remote = True
    """Server-backed: a resume needs an explicit recovery policy for effects
    a crash left open (spec 2.12)."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = 30.0,
        sync_deadline: Optional[float] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        check_url(url)
        if not token:
            raise ValueError("a server store needs a token")
        self.url = url.rstrip("/")
        parts = urlsplit(self.url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port
        self._base = parts.path.rstrip("/")
        self._token = token
        self.timeout = float(timeout)
        if sync_deadline is None:
            sync_deadline = float(os.environ.get("PRAGMATIC_SYNC_DEADLINE") or DEFAULT_SYNC_DEADLINE)
        self.sync_deadline = float(sync_deadline)
        self.info: Optional[Dict[str, Any]] = None
        self.whoami: Optional[Dict[str, Any]] = None
        self._local = threading.local()
        self._lock = threading.Lock()
        self._leases: Dict[str, Optional[_Lease]] = {}
        self._ssl = (ssl_context or ssl.create_default_context()) if self._https else None

    def __repr__(self) -> str:
        return f"ServerStore({self.url!r})"

    # -- HTTP --------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self._https:
                conn = http.client.HTTPSConnection(
                    self._host, self._port, timeout=CONNECT_TIMEOUT, context=self._ssl
                )
            else:
                conn = http.client.HTTPConnection(self._host, self._port, timeout=CONNECT_TIMEOUT)
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(self.timeout)
            self._local.conn = conn
        return conn

    def _drop_connection(self) -> None:
        conn = getattr(self._local, "conn", None)
        self._local.conn = None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a broken socket
                pass

    def _send_once(self, method: str, path: str, body: Optional[bytes], headers: Mapping[str, str]) -> _Response:
        sent_at = time.monotonic()
        conn = self._connection()
        broken = False
        try:
            conn.request(method, self._base + path, body=body, headers=dict(headers))
        except OSError as failed:
            # A server may answer before it has read the whole body (a 413
            # as soon as a body passes its limit) and close the connection,
            # which fails the write. Its answer may be waiting all the same.
            early = _early_answer(conn)
            if early is None:
                raise failed
            resp, broken = early, True
        else:
            resp = conn.getresponse()
        data = resp.read()
        if broken or resp.will_close:
            self._drop_connection()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return _Response(resp.status, hdrs, data, sent_at)

    def _headers(self, extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": f"pragmatic-python/{_native.__version__}",
            "Accept": "application/json",
        }
        if extra:
            h.update(extra)
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        deadline: Optional[Deadline] = None,
        stop: Optional[threading.Event] = None,
    ) -> _Response:
        """Send a request, resending the identical request on connect errors,
        timeouts and 502, 503 and 504 until ``deadline`` (a monotonic time,
        or a function returning one). ``None`` sends once. At least one try
        is always made. Once ``stop`` is set nothing more is resent (the
        backoff wakes up for it), so its owner can be stopped within one
        request."""
        hdrs = self._headers(headers)
        tries = 0
        while True:
            failure: str
            retry_after: Optional[int] = None
            try:
                resp = self._send_once(method, path, body, hdrs)
            except (OSError, http.client.HTTPException) as e:
                self._drop_connection()
                failure = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
            else:
                if resp.status not in _RESEND_STATUSES:
                    return resp
                failure = f"HTTP {resp.status} {resp.code or ''}".strip()
                retry_after = resp.retry_after()
            limit = deadline() if callable(deadline) else deadline
            now = time.monotonic()
            if limit is None or now >= limit:
                raise Unavailable(f"{method} {self.url}{path} failed until the deadline: {failure}")
            if stop is not None and stop.is_set():
                raise Unavailable(f"{method} {self.url}{path} stopped: {failure}")
            delay = min(2.0, 0.05 * (2**tries)) * (0.5 + random.random() / 2)
            if retry_after is not None:
                delay = max(delay, float(retry_after))
            wait = max(0.0, min(delay, limit - now))
            if stop is not None:
                if stop.wait(wait):
                    raise Unavailable(f"{method} {self.url}{path} stopped: {failure}")
            else:
                time.sleep(wait)
            tries += 1

    def _sync_deadline(self) -> float:
        return time.monotonic() + self.sync_deadline

    def _path(self, run_id: str, suffix: str = "") -> str:
        return f"/v1/runs/{quote(run_id, safe='')}{suffix}"

    def _fail(self, resp: _Response, what: str, run_id: Optional[str] = None) -> PragmaticError:
        """The exception for a definitive error answer (spec 4.4)."""
        code = resp.code
        detail = resp.message or code or f"HTTP {resp.status}"
        where = f"{what} on {self.url}"
        if code == "run_locked":
            expires = resp.error.get("holder_expires_in")
            retry = resp.retry_after()
            if retry is None and expires is not None:
                retry = max(0, int(float(expires)))
            return Locked(retry, f"run {run_id!r} is locked by another writer ({where})")
        if code in ("lease_lost", "lease_expired"):
            return LeaseLost(f"the lease on run {run_id!r} was lost: {detail} ({where})")
        if code == "run_deleted" or resp.status == 410:
            return Deleted(f"run {run_id!r} was deleted and can never be recreated ({where})")
        if code == "payload_too_large" or resp.status == 413:
            limit = resp.error.get("limit") or (self.info or {}).get("max_request_bytes") or 0
            return TooLarge(f"the request is larger than the server accepts ({where})", limit=int(limit))
        if code == "conflict":
            entries = resp.error.get("entries")
            return Conflict(
                int(resp.error.get("expected") or 0),
                int(entries or 0),
                f"run {run_id!r} changed underneath this writer: {detail} ({where})",
            )
        if code in ("starting", "storage_unavailable"):
            return Unavailable(f"{detail} ({where})")
        return ServerError(
            f"{where} failed: HTTP {resp.status} {code or ''} {detail}".rstrip(),
            status=resp.status,
            code=code,
            url=self.url,
        )

    # -- connection checks (spec 6.1) ---------------------------------------

    def connect(self) -> None:
        """``GET /v1/info`` and ``/v1/whoami``: check that the server is
        reachable, speaks API version 1 with journal format 2 and SHA-256
        chains, accepts this SDK version and accepts the token. Raises a
        ``PragmaticError`` naming the URL and status otherwise."""
        info = self._get_json("/v1/info", "server info")
        problems = []
        if info.get("api_version") != API_VERSION:
            problems.append(f"api_version {info.get('api_version')!r} (this SDK speaks {API_VERSION})")
        if info.get("journal_format") != JOURNAL_FORMAT:
            problems.append(f"journal_format {info.get('journal_format')!r} (expected {JOURNAL_FORMAT})")
        if info.get("chain") != CHAIN:
            problems.append(f"chain {info.get('chain')!r} (expected {CHAIN!r})")
        min_sdk = info.get("min_sdk")
        if min_sdk and _version_tuple(_native.__version__) < _version_tuple(min_sdk):
            problems.append(f"min_sdk {min_sdk} (this SDK is {_native.__version__})")
        if problems:
            raise PragmaticError(f"the server at {self.url} is incompatible: " + "; ".join(problems))
        self.info = info
        self.whoami = self._get_json("/v1/whoami", "token check")

    def _get_json(self, path: str, what: str) -> Dict[str, Any]:
        try:
            resp = self._request("GET", path)
        except Unavailable as e:
            raise PragmaticError(f"cannot reach the server at {self.url}: {e}") from None
        if resp.status != 200 or not isinstance(resp.json(), dict):
            raise ServerError(
                f"{what} failed at {self.url}{path}: HTTP {resp.status} {resp.code} {resp.message}".rstrip(),
                status=resp.status,
                code=resp.code,
                url=self.url,
            )
        return resp.json()

    # -- the store protocol (spec 6.3) --------------------------------------

    def checkout(self, run_id: str, create: bool) -> Tuple[bytes, int, str]:
        """Acquire the run's lease (creating the run when ``create``),
        download its journal and start renewing the lease. Returns ``(bytes,
        entries, head)`` for the native layer to verify."""
        with self._lock:
            if run_id in self._leases:
                raise Locked(None, f"run {run_id!r} is already checked out through this store")
            self._leases[run_id] = None
        lease = _Lease(run_id, str(uuid.uuid4()))
        try:
            created = self._acquire(lease, create)
            # Renewing starts before the download: the lease must hold for
            # the whole checkout, however long the journal takes to arrive.
            self._start_renewal(lease)
            with self._lock:
                self._leases[run_id] = lease
            if created:
                return (_native.JOURNAL_HEADER, 0, "")
            result = self._download(run_id, lease)
            if lease.lost:
                raise LeaseLost(f"the lease on run {run_id!r} was lost ({lease.lost}) on {self.url}")
            return result
        except BaseException:
            with self._lock:
                self._leases.pop(run_id, None)
            self._stop_renewal(lease)
            if lease.lease:
                self._release(lease)
            raise

    def _start_renewal(self, lease: _Lease) -> None:
        lease.thread = threading.Thread(
            target=self._renew, args=(lease,), name=f"pragmatic-lease-{lease.run_id}", daemon=True
        )
        lease.thread.start()

    def _stop_renewal(self, lease: _Lease) -> None:
        """Stop the renewal thread and wait for it: it resends nothing once
        stopped, so one request's worth of time is enough. One still in a
        request after that gives back any grant it receives (see
        ``_renew``)."""
        lease.stop.set()
        thread = lease.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(self.timeout + CONNECT_TIMEOUT)

    def _acquire(self, lease: _Lease, create: bool) -> bool:
        """The create order of spec 4.6. Returns True if this call created
        the run (its journal is the bare header)."""
        deadline = self._sync_deadline()
        body = json.dumps({"holder": lease.holder}).encode()
        for _ in range(4):
            resp = self._request(
                "POST",
                self._path(lease.run_id, "/lease"),
                body=body,
                headers={"Content-Type": "application/json"},
                deadline=deadline,
            )
            if resp.status == 200:
                lease.grant(resp.json() or {}, resp.sent_at)
                return False
            if resp.code != "not_found" and resp.status != 404:
                raise self._fail(resp, "lease", lease.run_id)
            if not create:
                raise FileNotFoundError(f"run {lease.run_id!r} does not exist on {self.url}")
            resp = self._request(
                "PUT",
                self._path(lease.run_id),
                body=_native.JOURNAL_HEADER,
                headers={"Content-Type": "application/octet-stream", "Pragmatic-Holder": lease.holder},
                deadline=deadline,
            )
            if resp.status in (200, 201):
                lease.grant(resp.json() or {}, resp.sent_at)
                return True
            if resp.code != "run_exists":
                raise self._fail(resp, "create", lease.run_id)
        raise ServerError(
            f"could not create or lease run {lease.run_id!r} on {self.url}", url=self.url
        )

    def _download(self, run_id: str, lease: Optional[_Lease]) -> Tuple[bytes, int, str]:
        """The run's journal, under ``lease`` when given (resent until the
        earlier of the sync and lease deadlines) or as a snapshot."""
        headers = {"Accept": "application/octet-stream"}
        deadline: Deadline = self._sync_deadline()
        if lease is not None:
            headers["Pragmatic-Lease"] = lease.lease
            sync = deadline

            def deadline() -> float:
                return min(sync, lease.deadline)

        resp = self._request("GET", self._path(run_id, "/journal"), headers=headers, deadline=deadline)
        if resp.status != 200:
            if resp.status == 404 and resp.code in ("", "not_found"):
                raise FileNotFoundError(f"run {run_id!r} does not exist on {self.url}")
            raise self._fail(resp, "journal download", run_id)
        try:
            entries = int(resp.headers.get("pragmatic-entries", ""))
        except ValueError:
            raise ServerError(
                f"the journal of run {run_id!r} came without a Pragmatic-Entries header",
                status=resp.status,
                url=self.url,
            ) from None
        return (resp.body, entries, resp.headers.get("pragmatic-head", ""))

    def _renew(self, lease: _Lease) -> None:
        """The renewal thread: renew every ``ttl/3`` until checkin, or until
        the server gives the lease to someone else. Once checkin has set
        ``stop`` it resends nothing, and a grant that still arrives (a
        renewal checkin could not wait out) is given back at once, so a
        lease checkin released is never held again (spec 6.3)."""
        body = json.dumps({"holder": lease.holder}).encode()
        while not lease.stop.wait(max(0.05, lease.ttl / 3)):
            try:
                resp = self._request(
                    "POST",
                    self._path(lease.run_id, "/lease"),
                    body=body,
                    headers={"Content-Type": "application/json"},
                    deadline=lambda: lease.deadline,
                    stop=lease.stop,
                )
            except Exception:  # noqa: BLE001 - keep trying until the lease is gone
                continue
            if lease.stop.is_set():
                if resp.status == 200:
                    granted = (resp.json() or {}).get("lease") or lease.lease
                    self._release_id(lease.run_id, str(granted))
                return
            if resp.status == 200:
                lease.grant(resp.json() or {}, resp.sent_at)
            elif resp.code in ("run_locked", "lease_lost", "lease_expired", "run_deleted", "not_found"):
                lease.lost = resp.code
                return

    def _lease(self, run_id: str) -> _Lease:
        lease = self._leases.get(run_id)
        if lease is None:
            raise LeaseLost(f"run {run_id!r} is not checked out through this store")
        if lease.lost:
            raise LeaseLost(f"the lease on run {run_id!r} was lost ({lease.lost})")
        return lease

    def persist(self, run_id: str, at: int, frames: bytes, frame_count: int, head_hex: str) -> None:
        """Append ``frame_count`` frames at entry ``at`` (spec 4.6), split into
        requests the server accepts, resending each until it is durable."""
        lease = self._lease(run_id)
        ranges = _frames(frames)
        if len(ranges) != frame_count:
            raise ValueError(f"{len(ranges)} frames given where {frame_count} were announced")
        start = time.monotonic()
        limit = int((self.info or {}).get("max_request_bytes") or 0)
        self._check_sizes(ranges, limit)
        for lo, hi in self._batches(ranges, limit):
            chunk = frames[ranges[lo][0] : ranges[hi - 1][1]]
            self._append(lease, at + lo, chunk, ranges[lo : hi], start)

    def _check_sizes(self, ranges: List[Tuple[int, int]], request_limit: int) -> None:
        """Refuse, without sending it, a frame larger than the server
        announced it accepts (``max_frame_bytes``, ``max_request_bytes``):
        such a request can never succeed, and a server that answers it
        early and closes the connection would otherwise look unreachable."""
        frame_limit = int((self.info or {}).get("max_frame_bytes") or 0)
        for lo, hi in ranges:
            size = hi - lo
            for limit in (frame_limit, request_limit):
                if limit and size > limit:
                    raise TooLarge(
                        f"a {size}-byte journal frame is larger than the server at {self.url} "
                        f"accepts ({limit} bytes)",
                        size=size,
                        limit=limit,
                    )

    @staticmethod
    def _batches(ranges: List[Tuple[int, int]], limit: int) -> Iterator[Tuple[int, int]]:
        """Group frames into requests of at most ``limit`` bytes (one frame
        per request if a single frame is larger, when the server did not
        announce its limits; it answers that one with
        ``payload_too_large``)."""
        lo = 0
        while lo < len(ranges):
            hi = lo + 1
            if limit > 0:
                while hi < len(ranges) and ranges[hi][1] - ranges[lo][0] <= limit:
                    hi += 1
            else:
                hi = len(ranges)
            yield lo, hi
            lo = hi

    def _append(
        self, lease: _Lease, at: int, chunk: bytes, ranges: List[Tuple[int, int]], start: float
    ) -> None:
        base = ranges[0][0]
        hashes = [chunk[e - base - _HASH_LEN : e - base].hex() for _, e in ranges]

        def deadline() -> float:
            return min(start + self.sync_deadline, max(lease.deadline, start))

        while True:
            k = len(hashes)
            try:
                resp = self._request(
                    "POST",
                    self._path(lease.run_id, "/frames") + "?" + urlencode({"at": at}),
                    body=chunk,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Pragmatic-Lease": lease.lease,
                        "Pragmatic-Frames": str(k),
                        "Pragmatic-Head": hashes[-1],
                    },
                    deadline=deadline,
                )
            except Unavailable:
                if self._landed(lease.run_id, at, hashes):
                    return
                raise
            if resp.status == 200:
                doc = resp.json() or {}
                entries = int(doc.get("entries", -1))
                if doc.get("head") != hashes[-1] or entries < at + k:
                    raise Conflict(
                        at + k,
                        int(doc.get("entries") or 0),
                        f"the server's head for run {lease.run_id!r} after entry {at + k} is not "
                        "the head this writer computed",
                    )
                if entries > at + k:
                    # A duplicate answer (4.6 answers one whatever the lease
                    # state) from a run that grew past these frames: another
                    # writer holds the run, and appended at least the
                    # custody note of its takeover. The frames are durable,
                    # but acting on them could repeat what the new holder
                    # did (recovery may have written an intent off and
                    # performed it again), so the lease is lost.
                    lease.lost = "lease_lost"
                    raise LeaseLost(
                        f"the lease on run {lease.run_id!r} was lost: the run holds {entries} "
                        f"entries where this writer appended up to {at + k} ({self.url})"
                    )
                return
            if resp.code in ("lease_lost", "lease_expired", "run_locked"):
                lease.lost = resp.code
                raise LeaseLost(
                    f"the lease on run {lease.run_id!r} was lost ({resp.code}) on {self.url}"
                )
            if resp.code != "conflict":
                raise self._fail(resp, "append", lease.run_id)
            # Reconcile through the duplicate rule: the server already holds
            # a prefix of these frames (an earlier copy of this request whose
            # answer was lost). Send only what it is missing.
            entries, head = self._position(lease.run_id, resp)
            held = entries - at
            if 0 < held <= k and head == hashes[held - 1]:
                if held == k:
                    return
                cut = ranges[held][0] - base
                chunk, ranges, hashes = chunk[cut:], ranges[held:], hashes[held:]
                base = ranges[0][0]
                at = entries
                continue
            raise Conflict(
                at,
                entries,
                f"run {lease.run_id!r} holds {entries} entries on {self.url}; this writer appends at {at}",
            )

    def _landed(self, run_id: str, at: int, hashes: List[str]) -> bool:
        """After an append's resends ran out: whether its frames were stored
        anyway (an earlier try whose answer was lost), judged from one look
        at the run's entry count and head. ``False`` when the run cannot be
        read or has grown past the frames, which then stay in doubt."""
        try:
            resp = self._request("GET", self._path(run_id))
        except Unavailable:
            return False
        doc = resp.json() if resp.status == 200 else None
        if not isinstance(doc, dict):
            return False
        try:
            entries = int(doc.get("entries"))
        except (TypeError, ValueError):
            return False
        return entries == at + len(hashes) and doc.get("head") == hashes[-1]

    def _position(self, run_id: str, resp: _Response) -> Tuple[int, str]:
        """The server's ``(entries, head)`` for a run: from a conflict answer
        when it carries them, from the run summary otherwise."""
        err = resp.error
        if "entries" in err and "head" in err:
            return int(err["entries"]), str(err["head"] or "")
        summary = self._request("GET", self._path(run_id), deadline=self._sync_deadline())
        doc = summary.json() if summary.status == 200 else None
        if not isinstance(doc, dict):
            raise self._fail(resp, "append", run_id)
        return int(doc.get("entries") or 0), str(doc.get("head") or "")

    def checkin(self, run_id: str) -> None:
        """Stop renewing, then release the lease (best effort: a lease that
        is not released expires on its own)."""
        with self._lock:
            lease = self._leases.pop(run_id, None)
        if lease is None:
            return
        self._stop_renewal(lease)
        self._release(lease)

    def _release(self, lease: _Lease) -> None:
        self._release_id(lease.run_id, lease.lease)

    def _release_id(self, run_id: str, lease_id: str) -> None:
        try:
            self._request(
                "DELETE",
                self._path(run_id, "/lease"),
                headers={"Pragmatic-Lease": lease_id},
                deadline=time.monotonic() + min(self.sync_deadline, 10.0),
            )
        except Exception:  # noqa: BLE001 - the lease expires on its own
            pass

    def snapshot(self, run_id: str) -> Tuple[bytes, int, str]:
        """The run's durable journal, without a lease (auditors with
        ``view_raw`` and admins)."""
        return self._download(run_id, None)

    def list(self) -> List[str]:
        return [s["run_id"] for s in self.summaries()]

    # -- read-only views ---------------------------------------------------

    def summaries(self, **filters: Any) -> List[Dict[str, Any]]:
        """``GET /v1/runs`` with every page followed. ``filters`` are the
        query parameters of spec 4.4 (``prefix``, ``status``, ...)."""
        out: List[Dict[str, Any]] = []
        after: Optional[str] = None
        while True:
            query = {k: v for k, v in filters.items() if v is not None}
            if after:
                query["after"] = after
            path = "/v1/runs" + ("?" + urlencode(query) if query else "")
            resp = self._request("GET", path, deadline=self._sync_deadline())
            if resp.status != 200:
                raise self._fail(resp, "run list")
            doc = resp.json() or {}
            out.extend(doc.get("runs") or [])
            after = doc.get("next")
            if not after:
                return out

    def summary(self, run_id: str) -> Dict[str, Any]:
        """``GET /v1/runs/{id}``: the run's summary with its cached verify
        report."""
        resp = self._request("GET", self._path(run_id), deadline=self._sync_deadline())
        if resp.status != 200:
            if resp.status == 404:
                raise FileNotFoundError(f"run {run_id!r} does not exist on {self.url}")
            raise self._fail(resp, "run summary", run_id)
        return resp.json() or {}

    def entries(self, run_id: str, page: int = 1000) -> List[Dict[str, Any]]:
        """``GET /v1/runs/{id}/entries`` with every page followed. Content is
        redacted unless the token has ``view_raw``.

        A page is ``{entries, next, total}``. The server also bounds a page
        by bytes, so a page shorter than ``limit`` is not the last: only a
        ``next`` of ``null`` is."""
        out: List[Dict[str, Any]] = []
        start = 0
        while True:
            path = self._path(run_id, "/entries") + "?" + urlencode({"from": start, "limit": page})
            resp = self._request("GET", path, deadline=self._sync_deadline())
            if resp.status != 200:
                raise self._fail(resp, "entries", run_id)
            doc = resp.json()
            if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
                raise ServerError(
                    f"entries of run {run_id!r} on {self.url}: the answer is not an entries page",
                    status=resp.status,
                    url=self.url,
                )
            out.extend(doc["entries"])
            following = doc.get("next")
            if following is None:
                return out
            if int(following) <= start:
                raise ServerError(
                    f"entries of run {run_id!r} on {self.url}: the next page does not advance",
                    status=resp.status,
                    url=self.url,
                )
            start = int(following)

    # -- pushing local journals --------------------------------------------

    def push(self, run_id: str, data: bytes) -> int:
        """Upload an unkeyed format 2 journal (its whole bytes): create or
        lease the run, append whatever the server does not hold yet, and
        release. Returns the number of entries sent. The server's journal
        must be a prefix of this one, else ``Conflict``."""
        info = _native.journal_info(data)
        if info["format"] != JOURNAL_FORMAT or info["keyed"]:
            raise ValueError("only unkeyed format 2 journals can be pushed")
        if info.get("run_id") not in (None, run_id):
            raise ValueError(f"the journal belongs to run {info.get('run_id')!r}, not {run_id!r}")
        frames = bytes(data[16 : info["valid_len"]])
        total = int(info["entries"])
        held, _, held_head = self.checkout(run_id, True)
        try:
            ranges = _frames(frames)
            entries = int(_native.journal_info(held)["entries"])
            if entries > total:
                raise Conflict(total, entries, f"run {run_id!r} on {self.url} is longer than the local journal")
            if entries and frames[ranges[entries - 1][1] - _HASH_LEN : ranges[entries - 1][1]].hex() != held_head:
                raise Conflict(entries, entries, f"run {run_id!r} on {self.url} is not a prefix of the local journal")
            if entries < total:
                rest = frames[ranges[entries][0] :]
                self.persist(run_id, entries, rest, total - entries, info["head"])
            return total - entries
        finally:
            self.checkin(run_id)
