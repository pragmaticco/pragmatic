"""The end-to-end suite: the product story of ``story.py``, one test per
step, in order.

Everything is real except the model providers: the ``pragmatic-server``
and ``pragmatic`` binaries, the Python SDK with its native extension, the
Anthropic and OpenAI SDKs (talking to scripted APIs on an
``httpx2.MockTransport``), the reference verifier, and two OpenSSL
time-stamping authorities on loopback. Nothing leaves the machine.

    python -m pytest tests/e2e -v        # add -s to read the story as it runs

It needs OpenSSL 3 on PATH (or from Homebrew on a Mac), Rust to build the
binaries, and a Python with the SDK built (``maturin develop``) and
``pytest``, ``anthropic``, ``openai`` and ``httpx2`` installed.
"""

from __future__ import annotations

import pytest

from story import Story

pytestmark = pytest.mark.story


def test_1_two_independent_timestamp_authorities(story: Story) -> None:
    story.step1_timestamp_authorities()


def test_2_the_server_starts_with_a_token_per_role(story: Story) -> None:
    story.step2_server()


def test_3_a_crash_mid_refund_resumes_without_repeating_a_call(story: Story) -> None:
    story.step3_crash_and_resume()


def test_4_the_run_is_anchored_by_two_operators_and_replays(story: Story) -> None:
    story.step4_anchoring()


def test_5_an_erasure_keeps_the_chain_and_stops_replay(story: Story) -> None:
    story.step5_erasure()


def test_6_the_auditor_verifies_the_evidence_offline(story: Story) -> None:
    story.step6_evidence()


def test_7_the_access_log_and_scopes(story: Story) -> None:
    story.step7_access_log()


def test_8_a_restart_keeps_leases_indexes_and_proofs(story: Story) -> None:
    story.step8_restart()
