"""The Pragmatic demo: the whole product story, told step by step.

Start it with ``examples/demo/run.sh``, which builds what it needs first.
It runs the same steps as the end-to-end suite (``tests/e2e``), against a
real Pragmatic Server on this machine, and keeps what it made (the
server's data, the evidence and the auditor's report) in a folder it names
at the end.

    python examples/demo/demo.py [--open] [--keep-running]

``--open`` opens the auditor's report in the browser at the end.
``--keep-running`` leaves the server running afterwards, with its console
at ``/console``, until Ctrl-C.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "e2e"))

import harness  # noqa: E402
from story import Narrator, Story  # noqa: E402

INTRO = """\
Pragmatic: the system of record for AI agents
=============================================

You are about to watch a customer support agent, built on Claude and GPT,
refund a damaged order while we crash it, erase a customer's data, audit
it, tamper with the evidence and restart the server under it.

Everything runs on this computer. The AI models are scripted stand-ins, so
no API key, account or internet connection is used, and the two timestamp
authorities are started here too. Every check you see is a real one."""


def main() -> int:
    p = argparse.ArgumentParser(description="The Pragmatic demo.")
    p.add_argument("--open", action="store_true", help="open the auditor's report at the end")
    p.add_argument("--keep-running", action="store_true", help="leave the server running until Ctrl-C")
    args = p.parse_args()

    work = Path(tempfile.mkdtemp(prefix="pragmatic-demo-"))
    narrator = Narrator()
    print(INTRO)
    story = Story(work, narrator)
    started = time.monotonic()
    try:
        story.run_all()
    except harness.SetupError as e:
        print(f"\nThis computer is missing something the demo needs:\n  {e}")
        story.close()
        return 2
    except BaseException as e:  # noqa: BLE001 - report anything, then clean up
        story.close()
        if isinstance(e, KeyboardInterrupt):
            print("\nStopped.")
            return 130
        print(f"\nThe demo stopped at a check that did not hold:\n  {type(e).__name__}: {e}")
        if story.server is not None:
            print(f"\nThe server's log is {story.server.log}")
        return 1

    elapsed = time.monotonic() - started
    print(
        f"""
All 8 steps passed in {elapsed:.0f} seconds.

What the demo left behind, in {work}:
  the auditor's report     {story.report_html}
  the evidence bundle      {story.bundle}
  the server's data        {story.server.data_dir if story.server else ''}"""
    )
    if args.open and story.report_html is not None and sys.platform == "darwin":
        subprocess.run(["open", str(story.report_html)], check=False)
    if args.keep_running and story.server is not None:
        token_file = story.server.work / "admin.token"
        with open(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(story.admin + "\n")
        print(
            f"\nThe server is still running: sign in to {story.api.url}/console with the "
            f"administrator token in {token_file}. Ctrl-C stops it."
        )
        try:
            while story.server.proc is not None and story.server.proc.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    story.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
