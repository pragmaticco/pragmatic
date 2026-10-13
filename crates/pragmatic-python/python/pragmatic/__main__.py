"""``python -m pragmatic push DIR [RUN ... | --all] [--url URL]``

Uploads local journals to a Pragmatic Server (spec 6.7). The server URL
comes from ``--url`` or ``PRAGMATIC_URL`` and the token from
``PRAGMATIC_TOKEN`` (never from the command line, where other users of the
machine can read it).

Only unkeyed format 2 journals can be pushed. Format 1 journals (0.4, 0.5)
are read-only, and a keyed journal's HMAC chain is one only the key holder
can check, while server-stored runs are verified by anyone; both are
refused with an explanation, and nothing of them is sent. A run already on
the server is extended when the server holds a prefix of the local journal
and left alone when it holds all of it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from typing import List, Optional, Sequence

from . import _native
from ._errors import PragmaticError
from ._server import ServerStore, check_url
from ._stores import DirStore


def _journal_path(directory: str, run_id: str) -> str:
    return os.path.join(directory, hashlib.sha256(run_id.encode()).hexdigest() + ".journal")


def _refusal(info: dict) -> Optional[str]:
    if info["format"] == 1:
        return (
            "is a format 1 journal, which is read-only in 0.6: verify and export it with the "
            "pragmatic CLI"
        )
    if info["format"] != 2:
        return f"has unknown journal format {info['format']}"
    if info["keyed"]:
        return (
            "is keyed (HMAC): only the key holder can check its chain, and server-stored runs are "
            "unkeyed so that anyone can verify them; record it again without a key to push it"
        )
    return None


def push(directory: str, run_ids: Sequence[str], store: ServerStore, out=sys.stdout) -> int:
    """Push each run; returns the number of runs that could not be pushed."""
    failed = 0
    for run_id in run_ids:
        path = _journal_path(directory, run_id)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(
                f"{run_id}: refused: no format 2 journal for this run (a format 1 journal is "
                "read-only in 0.6: verify and export it with the pragmatic CLI)",
                file=out,
            )
            failed += 1
            continue
        try:
            info = _native.journal_info(data)
        except ValueError as e:
            print(f"{run_id}: refused: {e}", file=out)
            failed += 1
            continue
        why = _refusal(info)
        if why is not None:
            print(f"{run_id}: refused: the journal {why}", file=out)
            failed += 1
            continue
        try:
            sent = store.push(run_id, data[: info["valid_len"]])
        except (PragmaticError, OSError, ValueError) as e:
            print(f"{run_id}: failed: {e}", file=out)
            failed += 1
            continue
        torn = f" ({info['tail_len']} torn bytes left behind)" if info.get("tail_len") else ""
        print(f"{run_id}: pushed {sent} of {info['entries']} entries{torn}", file=out)
    return failed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pragmatic")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("push", help="upload local journals to a Pragmatic Server")
    p.add_argument("dir", help="the journal directory")
    p.add_argument("runs", nargs="*", help="run ids to push")
    p.add_argument("--all", action="store_true", help="push every run in the directory")
    p.add_argument("--url", help="the server URL (default: PRAGMATIC_URL)")
    args = parser.parse_args(argv)

    url = args.url or os.environ.get("PRAGMATIC_URL")
    token = os.environ.get("PRAGMATIC_TOKEN")
    if not url:
        parser.error("set PRAGMATIC_URL or pass --url")
    if not token:
        parser.error("set PRAGMATIC_TOKEN (tokens are never taken from the command line)")
    if bool(args.runs) == bool(args.all):
        parser.error("name the runs to push, or pass --all")
    try:
        check_url(url)
        store = ServerStore(url, token)
        store.connect()
    except (ValueError, PragmaticError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    run_ids = DirStore(args.dir).list() if args.all else list(args.runs)
    failed = push(args.dir, run_ids, store)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
