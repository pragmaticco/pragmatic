"""An agent the server tests run in this process and in child processes.

``python server_agent.py URL RUN_ID LOG MODE`` runs it against a server:
``MODE`` is ``run-and-die`` (the process exits hard after the search tool,
with no attempt.end and its lease never released) or ``resume`` (prints the
output). Every tool call appends a line to ``LOG``, so the test can count
performs across processes.
"""

from __future__ import annotations

import os
import sys
import time

import pragmatic


def make_agent(log_path: str, die_after_search: bool = False):
    def note(line: str) -> None:
        with open(log_path, "a") as f:
            f.write(line + "\n")

    def search(q):
        note(f"search {q}")
        return ["a://1", "a://2"]

    def fetch(url):
        note(f"fetch {url}")
        return f"contents of {url}"

    def agent(ctx):
        plan = ctx.draw("plan the research", lambda: "search, then fetch the first hit")
        hits = ctx.tool("search", search, "durable execution")
        if die_after_search:
            os._exit(17)
        page = ctx.tool("fetch", fetch, hits[0])
        return f"{plan}: {page}"

    return agent


def resume_until_unlocked(rt, run_id, agent, timeout=20.0):
    """Resume, waiting out the lease of a writer that died holding it."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return rt.resume(run_id, agent)
        except pragmatic.Locked as e:
            if time.monotonic() > deadline:
                raise
            time.sleep(min(1.0, e.retry_after) if e.retry_after else 0.2)


if __name__ == "__main__":
    url, run_id, log_path, mode = sys.argv[1:5]
    rt = pragmatic.Runtime(url, token="test-token")
    if mode == "run-and-die":
        rt.run(run_id, make_agent(log_path, die_after_search=True))
    else:
        print(resume_until_unlocked(rt, run_id, make_agent(log_path)).output)
