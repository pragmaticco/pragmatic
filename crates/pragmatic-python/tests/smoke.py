"""Smoke test for the pragmatic Python bindings.

Run after building the extension (see README): record, crash-resume,
strict replay, effects, channels, and chain verification - the same
guarantees the Rust suites prove, exercised from Python.
"""

import random
import shutil
import sys
import tempfile

import pragmatic

calls = {"n": 0}


def oracle(prompt: str) -> str:
    calls["n"] += 1
    # Deterministic per (seed, sequence) but different across draws - a
    # stand-in for a stochastic model.
    rng = random.Random(f"{calls['n']}:{prompt}")
    return f"{rng.choice(['plan', 'answer', 'refine'])}:{rng.getrandbits(32):x}"


def research(ctx):
    plan = ctx.oracle("plan the task")
    findings = [ctx.oracle(f"probe {i}: {plan}") for i in range(3)]
    stored = ctx.effect(
        "publish", f"{len(findings)} findings", lambda arg: f"s3://reports/{arg}"
    )
    t = ctx.now()
    ctx.contract(t > 0, "clock must be positive")
    return f"done: {stored}"


def main() -> None:
    d = tempfile.mkdtemp(prefix="pragmatic-py-")
    try:
        rt = pragmatic.Runtime(d, oracle, key=b"py-signing-key")

        # ── record ──
        report = rt.run("py-run", research)
        assert report.output.startswith("done: s3://reports/3 findings"), report.output
        assert report.fresh_steps > 0
        recorded_calls = calls["n"]
        print(f"record : {report.journal_len} entries, output={report.output!r}")

        # ── resume (complete run): everything replays, zero model calls ──
        report2 = rt.resume("py-run", research)
        assert calls["n"] == recorded_calls, "resume must not re-sample"
        assert report2.fresh_steps == 0
        assert report2.output == report.output
        print(f"resume : {report2.replayed_steps} steps from journal, 0 fresh")

        # ── strict replay: bit-for-bit, model never called ──
        audit = rt.replay("py-run", research)
        assert calls["n"] == recorded_calls, "replay must never call the model"
        assert audit.trace == report.trace, "T1: trace must be identical"
        print(f"replay : trace identical ({len(audit.trace)} labels)")

        # ── tamper-evident chain ──
        # Every recording attempt adds its notes, so the head is the one the
        # resume left; strict replay appends nothing.
        assert rt.verify("py-run")
        assert audit.chain_head == report2.chain_head
        print(f"chain  : verified, head={audit.chain_head[:16]}")

        # ── crash mid-run: process restart via a fresh Runtime ──
        rt2 = pragmatic.Runtime(d, oracle, key=b"py-signing-key")
        report3 = rt2.resume("py-run", research)
        assert report3.output == report.output
        assert calls["n"] == recorded_calls
        print("restart: resumed from disk, 0 model calls")

        # ── channels ──
        rt.send("chan-run", "tasks", "summarize the corpus")
        out = rt.run("chan-run", lambda ctx: ctx.oracle("solve " + ctx.recv("tasks")))
        # run.start, attempt.start, the receive, the draw (intent and
        # response) and attempt.end.
        assert out.journal_len == 6, out.journal_len
        print("channel: journaled receive replays")

        # ── faults surface as exceptions ──
        try:
            rt.run("bad-run", lambda ctx: ctx.contract(False, "always fails") or "x")
            raise AssertionError("contract violation should raise")
        except RuntimeError as e:
            assert "contract violated" in str(e), e
        print("faults : contract violation raised as RuntimeError")

        print("\nALL PYTHON SMOKE TESTS PASSED")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
