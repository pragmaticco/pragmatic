"""Shared fixtures for the Python SDK tests."""

from __future__ import annotations

import os
import sys
from typing import Any, Callable, Dict, List, Optional

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import pragmatic  # noqa: E402


class PyMemoryStore:
    """A store written in Python (spec 6.3), in memory, with fault hooks.

    ``fail(n, frames)`` is consulted before the ``n``-th persist and may
    return an exception to raise instead of persisting."""

    def __init__(self) -> None:
        self.files: Dict[str, bytearray] = {}
        self.locked: set = set()
        self.persists = 0
        self.checkins: List[str] = []
        self.fail: Optional[Callable[[int, bytes], Optional[BaseException]]] = None

    def checkout(self, run_id: str, create: bool) -> bytes:
        if run_id in self.locked:
            raise pragmatic.Locked(7)
        if run_id not in self.files:
            if not create:
                raise FileNotFoundError(run_id)
            self.files[run_id] = bytearray(pragmatic.JOURNAL_HEADER)
        self.locked.add(run_id)
        return bytes(self.files[run_id])

    def snapshot(self, run_id: str) -> bytes:
        return bytes(self.files[run_id])

    def persist(self, run_id: str, at: int, frames: bytes, frame_count: int, head_hex: str) -> None:
        self.persists += 1
        if self.fail is not None:
            exc = self.fail(self.persists, frames)
            if exc is not None:
                raise exc
        self.files[run_id] += frames

    def checkin(self, run_id: str) -> None:
        self.checkins.append(run_id)
        self.locked.discard(run_id)

    def list(self) -> List[str]:
        return sorted(self.files)


@pytest.fixture
def pystore() -> PyMemoryStore:
    return PyMemoryStore()


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "PRAGMATIC_URL",
        "PRAGMATIC_TOKEN",
        "PRAGMATIC_JOURNAL_KEY",
        "PRAGMATIC_REQUIRE_SERVER",
        "PRAGMATIC_SYNC_DEADLINE",
        "PRAGMATIC_OTEL",
    ):
        monkeypatch.delenv(var, raising=False)


_TRACER_PROVIDER: List[Any] = []


@pytest.fixture
def span_exporter(monkeypatch: pytest.MonkeyPatch) -> Any:
    """An in-memory exporter of the spans the SDK emits during one test,
    with ``PRAGMATIC_OTEL=1``. OpenTelemetry takes one tracer provider per
    process, so the provider is installed once and each test adds an
    exporter of its own to it."""
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    export = pytest.importorskip("opentelemetry.sdk.trace.export")
    in_memory = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
    from opentelemetry import trace

    if not _TRACER_PROVIDER:
        provider = sdk.TracerProvider()
        trace.set_tracer_provider(provider)
        if trace.get_tracer_provider() is not provider:
            pytest.skip("another tracer provider is already installed")
        _TRACER_PROVIDER.append(provider)
    exporter = in_memory.InMemorySpanExporter()
    _TRACER_PROVIDER[0].add_span_processor(export.SimpleSpanProcessor(exporter))
    monkeypatch.setenv("PRAGMATIC_OTEL", "1")
    yield exporter
    exporter.shutdown()
