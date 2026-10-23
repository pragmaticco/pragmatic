"""Processes for the end-to-end suite: the real ``pragmatic-server`` and
``pragmatic`` binaries, a small HTTP client for the server's API, and the
OpenSSL every time-stamp check needs.

Everything runs on this machine. The server listens on a loopback port of
its own, keeps its data, keys and logs in the work directory it is given,
and reaches nothing but the local time-stamping authorities it is
configured with.

Binaries come from Cargo's target directory (``CARGO_TARGET_DIR``, or
``target`` in the repository), as a debug build unless
``PRAGMATIC_E2E_PROFILE=release``. They are built (``cargo build``) first,
which costs nothing when they are current, unless
``PRAGMATIC_E2E_SKIP_BUILD=1``: a suite that ran a stale binary would test
code that is not the code in front of it.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import quote, urlencode

REPO = Path(__file__).resolve().parents[2]
E2E = Path(__file__).resolve().parent

# Where Homebrew keeps OpenSSL 3 on Apple silicon and on Intel Macs, whose
# own /usr/bin/openssl is LibreSSL and cannot check time-stamp tokens
# against pinned issuing CAs.
_OPENSSL_CANDIDATES = (
    "/opt/homebrew/opt/openssl@3/bin",
    "/opt/homebrew/opt/openssl/bin",
    "/usr/local/opt/openssl@3/bin",
    "/usr/local/opt/openssl/bin",
)


class SetupError(RuntimeError):
    """Something this machine lacks; the message says how to get it."""


# -- prerequisites -------------------------------------------------------------


def _openssl_usable(binary: str) -> bool:
    try:
        version = subprocess.run(
            [binary, "version"], capture_output=True, text=True, timeout=10
        ).stdout
        helptext = subprocess.run(
            [binary, "ts", "-help"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    text = helptext.stdout + helptext.stderr
    return version.startswith("OpenSSL") and "-partial_chain" in text


def find_openssl() -> str:
    """The directory of an OpenSSL (not LibreSSL) ``openssl`` whose ``ts``
    command verifies with ``-partial_chain``: the server, the CLI and the
    reference verifier all need one on ``PATH``."""
    on_path = shutil.which("openssl")
    candidates = ([str(Path(on_path).parent)] if on_path else []) + list(_OPENSSL_CANDIDATES)
    for directory in candidates:
        binary = os.path.join(directory, "openssl")
        if os.path.isfile(binary) and _openssl_usable(binary):
            return directory
    raise SetupError(
        "OpenSSL 3 is needed to make and check time-stamps (macOS ships LibreSSL, which "
        "cannot). On a Mac: brew install openssl@3. On Linux: install your distribution's "
        "openssl package."
    )


#: What the agent processes import (support_agent.py).
AGENT_MODULES = ("pragmatic", "anthropic", "openai", "httpx2")


def hidden_pth_files(python: str = sys.executable) -> List[str]:
    """The ``.pth`` files in ``python``'s site-packages that carry the
    hidden flag. Python 3.13 and later skip them, so a package installed
    as an editable ``.pth`` (``maturin develop``) cannot be imported. On a
    Mac, iCloud Drive marks every file in a virtual environment hidden when
    the environment sits in a folder it syncs (Desktop or Documents)."""
    hidden_flag = getattr(stat, "UF_HIDDEN", 0)
    if not hidden_flag:
        return []
    try:
        out = subprocess.run(
            [python, "-c", "import site, sys; print('\\n'.join(site.getsitepackages()))"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    found = []
    for directory in out.stdout.splitlines():
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if name.endswith(".pth") and getattr(os.lstat(path), "st_flags", 0) & hidden_flag:
                found.append(path)
    return found


def import_problem(error: BaseException, python: str = sys.executable) -> str:
    """What to tell someone whose Python cannot import what the suite needs,
    and how to fix it."""
    lines = [f"{python} cannot import what the agent needs: {error}"]
    hidden = hidden_pth_files(python)
    if hidden:
        lines.append(
            "Python 3.13 and later skip hidden .pth files, and these are hidden (iCloud Drive "
            "marks the files of a virtual environment in a synced folder hidden): "
            + ", ".join(hidden)
        )
        lines.append(
            "Install the SDK without an editable .pth (pip install ./crates/pragmatic-python, "
            "or maturin build and pip install the wheel), or keep the virtual environment "
            "outside Desktop and Documents."
        )
    else:
        lines.append(
            "Build the SDK into this Python (pip install ./crates/pragmatic-python) and install "
            "anthropic, openai and httpx2; examples/demo/run.sh does both."
        )
    return "\n  ".join(lines)


def check_python(
    env: Mapping[str, str],
    modules: Sequence[str] = AGENT_MODULES,
    python: str = sys.executable,
) -> None:
    """Check that ``python`` imports ``modules`` in the environment the agent
    processes get. An SDK they cannot import is something this machine
    lacks, so it is a ``SetupError``, never a failed check."""
    code = "import importlib, sys\nfor m in sys.argv[1:]: importlib.import_module(m)"
    try:
        out = subprocess.run(
            [python, "-c", code, *modules],
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SetupError(import_problem(e, python)) from None
    if out.returncode != 0:
        lines = [line for line in out.stderr.strip().splitlines() if line.strip()]
        why = lines[-1] if lines else f"exit {out.returncode}"
        raise SetupError(import_problem(RuntimeError(why), python))


def target_dir() -> Path:
    """Cargo's target directory; a relative ``CARGO_TARGET_DIR`` is relative
    to the workspace, where the suite runs cargo."""
    return REPO / os.environ.get("CARGO_TARGET_DIR", "target")


def build_binaries() -> Path:
    """Build ``pragmatic-server`` and ``pragmatic`` and return the directory
    holding them."""
    release = os.environ.get("PRAGMATIC_E2E_PROFILE") == "release"
    out = target_dir() / ("release" if release else "debug")
    if os.environ.get("PRAGMATIC_E2E_SKIP_BUILD") != "1":
        cargo = shutil.which("cargo")
        if cargo is None:
            raise SetupError(
                "Rust is needed to build Stet Server: install it from https://rustup.rs "
                "(or, on a Mac, brew install rust)."
            )
        cmd = [cargo, "build", "--quiet", "-p", "pragmatic-server", "-p", "pragmatic-cli"]
        if release:
            cmd.append("--release")
        subprocess.run(cmd, cwd=REPO, check=True)
    for name in ("pragmatic-server", "pragmatic"):
        if not (out / exe(name)).is_file():
            raise SetupError(f"{out / exe(name)} is missing; build it with cargo build")
    return out


def exe(name: str) -> str:
    return name + (".exe" if sys.platform == "win32" else "")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PROXY_VARIABLES = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}


def child_env(openssl_dir: str, extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """The environment of every process the suite starts: OpenSSL 3 first on
    ``PATH``, and nothing inherited that would point an SDK elsewhere or
    send the server's loopback requests to the TSAs through a proxy."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PRAGMATIC_") and k.lower() not in _PROXY_VARIABLES
    }
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env["PATH"] = openssl_dir + os.pathsep + env.get("PATH", "")
    env["PYTHONUNBUFFERED"] = "1"
    if extra:
        env.update(extra)
    return env


# -- the API -------------------------------------------------------------------


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None

    @property
    def code(self) -> str:
        doc = self.json() if self.body[:1] == b"{" else None
        if isinstance(doc, dict) and isinstance(doc.get("error"), dict):
            return str(doc["error"].get("code") or "")
        return ""


class Api:
    """The server's HTTP API, one request per connection."""

    def __init__(self, port: int):
        self.port = port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        *,
        json_body: Any = None,
        query: Optional[Mapping[str, Any]] = None,
        timeout: float = 60.0,
    ) -> Response:
        if query:
            path += "?" + urlencode(query)
        headers = {}
        body = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return Response(
                resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
            )
        finally:
            conn.close()

    def ok(self, method: str, path: str, token: Optional[str] = None, **kw: Any) -> Any:
        """The JSON of a 2xx answer; anything else is an error naming it."""
        resp = self.request(method, path, token, **kw)
        if not 200 <= resp.status < 300:
            raise AssertionError(
                f"{method} {path}: HTTP {resp.status} {resp.body[:500].decode(errors='replace')}"
            )
        return resp.json()

    @staticmethod
    def run_path(run_id: str, rest: str = "") -> str:
        return f"/v1/runs/{quote(run_id, safe='')}{rest}"

    def audit(self, token: str) -> List[Dict[str, Any]]:
        """Every access-log record the token may read, page by page."""
        out: List[Dict[str, Any]] = []
        after = None
        while True:
            query = {"limit": 1000}
            if after is not None:
                query["after"] = after
            page = self.ok("GET", "/v1/audit", token, query=query)
            out.extend(page["records"])
            after = page.get("next")
            if after is None:
                return out


# -- the server ----------------------------------------------------------------


def _toml_string(value: object) -> str:
    """A TOML basic string: JSON's escapes are TOML's, for any path."""
    return json.dumps(str(value), ensure_ascii=False)


@dataclass
class Witness:
    operator: str
    url: str
    roots_pem: Path


class Server:
    """A ``pragmatic-server`` process with its configuration, keys and data
    in ``work``. ``setup`` writes the log key and the bootstrap admin
    token; ``start``, ``stop`` and ``restart`` manage the process."""

    def __init__(
        self,
        work: Path,
        bin_dir: Path,
        env: Mapping[str, str],
        *,
        name: str,
        witnesses: Sequence[Witness],
        lease_ttl_secs: int,
        licensee: str,
    ):
        self.work = work
        self.bin = bin_dir / exe("pragmatic-server")
        self.env = dict(env)
        self.name = name
        self.witnesses = list(witnesses)
        self.lease_ttl_secs = lease_ttl_secs
        self.licensee = licensee
        self.port = free_port()
        self.api = Api(self.port)
        self.data_dir = work / "data"
        self.keys_dir = work / "keys"
        self.config = work / "pragmatic.toml"
        self.log = work / "server.log"
        self.proc: Optional[subprocess.Popen] = None
        self.admin_token = ""
        self.log_vkey = ""
        self.origin = ""

    def _cli(self, *args: str) -> str:
        out = subprocess.run(
            [str(self.bin), "--config", str(self.config), *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if out.returncode != 0:
            raise RuntimeError(f"pragmatic-server {' '.join(args)}: {out.stderr.strip()}")
        return out.stdout

    def setup(self) -> None:
        """Write the configuration, the log key (``keygen``) and the first
        admin token (``token bootstrap``), as an operator would."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        admin_sha256 = ""
        for line in self._cli("token", "bootstrap").splitlines():
            if line.startswith("token "):
                self.admin_token = line.split(" ", 1)[1].strip()
            elif line.startswith("admin_token_sha256 = "):
                admin_sha256 = line.split("=", 1)[1].strip().strip('"')
        assert self.admin_token and admin_sha256, "token bootstrap printed no token"
        self.write_config(admin_sha256)
        printed = dict(
            line.split(" ", 1) for line in self._cli("keygen").splitlines() if " " in line
        )
        self.log_vkey = printed["vkey"].strip()
        self.origin = printed["origin"].strip()

    def write_config(self, admin_sha256: str) -> None:
        q = _toml_string
        tsa = ",\n".join(
            f"  {{ url = {q(w.url)}, operator = {q(w.operator)}, roots_pem = {q(w.roots_pem)} }}"
            for w in self.witnesses
        )
        self.config.write_text(
            f"""# Written by the end-to-end suite. See docs/server.md.
name = {q(self.name)}
listen = {q(f"127.0.0.1:{self.port}")}
data_dir = {q(self.data_dir)}
lease_ttl_secs = {self.lease_ttl_secs}

[keys]
signing_key_file = {q(self.keys_dir / "log.key")}

[bootstrap]
admin_token_sha256 = {q(admin_sha256)}

[anchoring]
interval_secs = 60
min_independent_operators = 2
tsa = [
{tsa},
]

[license]
licensee = {q(self.licensee)}
"""
        )

    def start(self, timeout: float = 90.0) -> None:
        """Start ``serve`` and wait until ``/readyz`` answers 200."""
        assert self.proc is None, "the server is already running"
        log = open(self.log, "ab")
        self.proc = subprocess.Popen(
            [str(self.bin), "--config", str(self.config), "serve"],
            env=self.env,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        log.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"pragmatic-server exited at startup:\n{self.log_tail()}")
            try:
                if self.api.request("GET", "/readyz", timeout=2).status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"pragmatic-server was not ready in {timeout:.0f}s:\n{self.log_tail()}")

    def stop(self, timeout: float = 30.0) -> None:
        """Stop the server the way an orchestrator does: SIGTERM, then wait."""
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise RuntimeError(f"pragmatic-server ignored SIGTERM:\n{self.log_tail()}")
        self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()

    def log_tail(self, lines: int = 40) -> str:
        try:
            text = self.log.read_text(errors="replace").splitlines()
        except OSError:
            return "(no server log)"
        return "\n".join(text[-lines:])

    def issue(
        self, name: str, principal: str, role: str, scopes: Iterable[str], view_raw: bool = False
    ) -> Dict[str, str]:
        """Issue a token through the API as the admin: ``{token, id}``."""
        doc = self.api.ok(
            "POST",
            "/v1/tokens",
            self.admin_token,
            json_body={
                "name": name,
                "principal": principal,
                "role": role,
                "scopes": list(scopes),
                "view_raw": view_raw,
                "expires_at": None,
            },
        )
        return {"token": doc["token"], "id": doc["record"]["id"]}


# -- the CLI and the reference verifier ------------------------------------------


@dataclass
class Verdict:
    code: int
    output: str

    @property
    def verdict_line(self) -> str:
        """The line both verifiers end their report with: the verdict, then
        why."""
        for line in reversed(self.output.strip().splitlines()):
            if line.startswith(("VERIFIED", "UNANCHORED", "FAILED")):
                return line.strip()
        return ""

    @property
    def verdict(self) -> str:
        line = self.verdict_line
        for word in ("VERIFIED (PARTIAL)", "VERIFIED", "UNANCHORED", "FAILED"):
            if line.startswith(word):
                return word
        return ""

    @property
    def failures(self) -> List[str]:
        """The failure findings of the report, ``code: why``."""
        prefix = "FAILURE "
        return [
            line.strip()[len(prefix) :]
            for line in self.output.splitlines()
            if line.strip().startswith(prefix)
        ]


def run_tool(cmd: Sequence[str], env: Mapping[str, str], timeout: float = 120.0) -> Verdict:
    out = subprocess.run(
        list(cmd), env=dict(env), capture_output=True, text=True, timeout=timeout
    )
    return Verdict(out.returncode, out.stdout + out.stderr)
