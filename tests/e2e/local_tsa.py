"""Throwaway RFC 3161 time-stamping authorities, served on loopback.

Each ``LocalTsa`` is a certificate authority of its own (a self-signed
root) and a time-stamping certificate it issued, with the critical
``timeStamping`` extended key usage RFC 3161 requires. Tokens are made by
``openssl ts -reply``, so the server and both verifiers check real CMS
signatures rather than a stand-in. Two of them, each standing for a
different company, are the two independent operators the anchoring policy
asks for.

``TsaResponder`` is the HTTP side: it answers ``POST`` with a DER
``TimeStampReq`` body with the ``TimeStampResp`` OpenSSL produced, as a
public TSA does over plain HTTP.

``make_ca`` makes a root that issued nothing the server ever sees, for
checking that a verifier pinning the wrong root trusts nothing.
"""

from __future__ import annotations

import http.client
import itertools
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional

_EXTENSIONS = """\
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_tsa]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""

_EC_KEY = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]


def _openssl(openssl: str, cwd: Path, *args: str) -> None:
    out = subprocess.run(
        [openssl, *args], cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True
    )
    if out.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {out.stderr.strip()}")


def make_ca(directory: Path, name: str, openssl: str) -> Path:
    """A self-signed root CA in ``directory``; returns its PEM file."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ext.cnf").write_text(_EXTENSIONS)
    _openssl(
        openssl, directory, "req", "-x509", *_EC_KEY, "-keyout", "ca.key", "-out", "root.pem",
        "-days", "30", "-config", "ext.cnf", "-extensions", "v3_ca", "-subj", f"/CN={name}",
    )
    return directory / "root.pem"


class LocalTsa:
    """A time-stamping authority operated by ``operator``, in ``directory``."""

    def __init__(self, directory: Path, operator: str, display_name: str, openssl: str):
        self.directory = directory
        self.operator = operator
        self.display_name = display_name
        self.openssl = openssl
        self.requests = 0
        # `openssl ts -reply` reads and rewrites the serial file, so replies
        # are made one at a time.
        self._lock = threading.Lock()
        self._names = itertools.count()
        make_ca(directory, f"{display_name} Root CA", openssl)
        _openssl(
            openssl, directory, "req", "-new", *_EC_KEY, "-keyout", "tsa.key", "-out", "tsa.csr",
            "-config", "ext.cnf", "-subj", f"/CN={display_name} Time Stamping",
        )
        _openssl(
            openssl, directory, "x509", "-req", "-in", "tsa.csr", "-CA", "root.pem",
            "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.crt", "-days", "30",
            "-extfile", "ext.cnf", "-extensions", "v3_tsa",
        )
        (directory / "tsa.cnf").write_text(
            "[tsa]\ndefault_tsa = tsa1\n[tsa1]\n"
            f"dir = {directory}\nserial = $dir/serial\ncrypto_device = builtin\n"
            "signer_cert = $dir/tsa.crt\nsigner_key = $dir/tsa.key\ncerts = $dir/tsa.crt\n"
            "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\nother_policies = 1.2.3.4.5\n"
            "digests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = yes\n"
            "ess_cert_id_chain = no\ness_cert_id_alg = sha256\n"
        )
        (directory / "serial").write_text("01\n")

    @property
    def root_pem(self) -> Path:
        """The root a verifier pins for this operator."""
        return self.directory / "root.pem"

    def reply(self, query: bytes) -> bytes:
        """``openssl ts -reply`` for a DER ``TimeStampReq``."""
        with self._lock:
            n = next(self._names)
            q, r = f"q{n}.tsq", f"r{n}.tsr"
            (self.directory / q).write_bytes(query)
            _openssl(
                self.openssl, self.directory, "ts", "-reply", "-config", "tsa.cnf",
                "-queryfile", q, "-out", r,
            )
            self.requests += 1
            return (self.directory / r).read_bytes()


class TsaResponder:
    """Serves one ``LocalTsa`` over HTTP on a loopback port, on threads of
    this process, until ``close``."""

    def __init__(self, tsa: LocalTsa):
        self.tsa = tsa
        handler = _handler_for(tsa)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}/tsr"
        self._thread: Optional[threading.Thread] = threading.Thread(
            target=self._server.serve_forever, name=f"tsa-{tsa.operator}", daemon=True
        )
        self._thread.start()

    def check(self) -> None:
        """Time-stamp a document over HTTP, as the server will, and verify
        the token against this TSA's root, as an auditor will."""
        d = self.tsa.directory
        (d / "check.txt").write_text(f"{self.tsa.operator} is answering\n")
        _openssl(
            self.tsa.openssl, d, "ts", "-query", "-data", "check.txt", "-sha256", "-cert",
            "-out", "check.tsq",
        )
        host, port = self._server.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=30)
        try:
            conn.request(
                "POST",
                "/tsr",
                body=(d / "check.tsq").read_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
            )
            resp = conn.getresponse()
            assert resp.status == 200, f"{self.url} answered {resp.status}"
            (d / "check.tsr").write_bytes(resp.read())
        finally:
            conn.close()
        _openssl(
            self.tsa.openssl, d, "ts", "-verify", "-in", "check.tsr", "-queryfile", "check.tsq",
            "-CAfile", "root.pem",
        )

    def close(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread = None


def _handler_for(tsa: LocalTsa) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - the http.server interface
            length = int(self.headers.get("Content-Length") or 0)
            query = self.rfile.read(length)
            try:
                status, body = 200, tsa.reply(query)
                kind = "application/timestamp-reply"
            except RuntimeError as e:
                status, body, kind = 500, str(e).encode(), "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    return Handler


def start_tsas(work: Path, operators: Dict[str, str], openssl: str) -> Dict[str, TsaResponder]:
    """One ``LocalTsa`` and responder per ``{operator: display name}``."""
    out = {}
    for operator, display in operators.items():
        tsa = LocalTsa(work / f"tsa-{operator}", operator, display, openssl)
        out[operator] = TsaResponder(tsa)
    return out
