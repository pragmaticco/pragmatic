"""pytest wiring for the end-to-end suite.

The steps of the story share one ``Story`` (one server, one set of TSAs,
one work directory) for the whole session, and run in order. Each step
builds on the ones before it, so once a step fails the later steps are
skipped, naming the step that failed, rather than failing for a reason
that is not theirs.

A machine without what the suite needs (OpenSSL 3, Rust, the SDKs) fails
the suite with a message saying what to install: a suite that skipped
itself there would read as a pass.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, Iterator

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from story import Narrator, Story  # noqa: E402

_failed: Dict[str, str] = {}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "story: a step of the end-to-end story, run in order")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "story" in item.keywords and "step" in _failed:
        pytest.skip(f"an earlier step failed: {_failed['step']}")


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    if "story" not in item.keywords or call.excinfo is None:
        return
    if call.excinfo.errisinstance(pytest.skip.Exception):
        return
    _failed.setdefault("step", item.name)


@pytest.fixture(scope="session")
def story(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Story]:
    s = Story(tmp_path_factory.mktemp("story"), Narrator(sys.stdout))
    try:
        yield s
    finally:
        if "step" in _failed and s.server is not None:
            sys.stdout.write(f"\n--- the server's log ({s.server.log}) ---\n{s.server.log_tail(80)}\n")
        s.close()
