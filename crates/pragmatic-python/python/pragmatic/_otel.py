"""Optional OpenTelemetry spans (spec 6.7).

With ``PRAGMATIC_OTEL=1`` and ``opentelemetry-api`` importable, every
attempt is a ``pragmatic.attempt`` span, every model call a child span in
the GenAI semantic conventions and every effect a ``pragmatic.effect``
span. Spans carry ``pragmatic.run_id``, ``pragmatic.cursor``,
``pragmatic.branch`` and ``pragmatic.replayed``, never content, and a
replayed model call reports zero usage. Without the variable or the
package, every span here is a no-op costing one environment lookup.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any, Iterator, Optional, Sequence

from . import _native

_tracer: Any = None
_loaded = False


def _get_tracer() -> Any:
    global _tracer, _loaded
    if os.environ.get("PRAGMATIC_OTEL") != "1":
        return None
    if not _loaded:
        _loaded = True
        try:
            from opentelemetry import trace
        except ImportError:
            _tracer = None
        else:
            _tracer = trace.get_tracer("pragmatic", _native.__version__)
    return _tracer


class Step:
    """The span of one step, or nothing."""

    __slots__ = ("span",)

    def __init__(self, span: Any):
        self.span = span

    def set(self, **attrs: Any) -> None:
        if self.span is None:
            return
        for key, value in attrs.items():
            if value is not None:
                self.span.set_attribute(_ATTR.get(key, key), value)

    def end(self) -> None:
        """End a span started with ``start_draw`` (once; later calls do
        nothing)."""
        span, self.span = self.span, None
        if span is not None:
            span.end()


_ATTR = {
    "cursor": "pragmatic.cursor",
    "replayed": "pragmatic.replayed",
    "input_tokens": "gen_ai.usage.input_tokens",
    "output_tokens": "gen_ai.usage.output_tokens",
}


def _branch(branch: Sequence[int]) -> str:
    return ".".join(str(i) for i in branch)


@contextlib.contextmanager
def attempt(run_id: str, mode: str) -> Iterator[Step]:
    tracer = _get_tracer()
    if tracer is None:
        yield Step(None)
        return
    with tracer.start_as_current_span(
        "pragmatic.attempt", attributes={"pragmatic.run_id": run_id, "pragmatic.mode": mode}
    ) as span:
        yield Step(span)


def _draw_attrs(run_id: str, branch: Sequence[int], provenance: str) -> tuple:
    provider, _, model = provenance.partition(":")
    attrs = {
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": provider or "unknown",
        "pragmatic.run_id": run_id,
        "pragmatic.branch": _branch(branch),
    }
    if model:
        attrs["gen_ai.request.model"] = model
    return (f"chat {model}" if model else "chat"), attrs


@contextlib.contextmanager
def draw(run_id: str, branch: Sequence[int], provenance: str) -> Iterator[Step]:
    tracer = _get_tracer()
    if tracer is None:
        yield Step(None)
        return
    name, attrs = _draw_attrs(run_id, branch, provenance)
    with tracer.start_as_current_span(name, attributes=attrs) as span:
        yield Step(span)


def start_draw(run_id: str, branch: Sequence[int], provenance: str) -> Step:
    """The span of one journaled HTTP exchange, ended with ``Step.end()``
    when its result is written: a stream's span lasts until the stream
    ends or is closed, so it cannot be a context manager."""
    tracer = _get_tracer()
    if tracer is None:
        return Step(None)
    name, attrs = _draw_attrs(run_id, branch, provenance)
    return Step(tracer.start_span(name, attributes=attrs))


@contextlib.contextmanager
def effect(run_id: str, branch: Sequence[int], name: str) -> Iterator[Step]:
    tracer = _get_tracer()
    if tracer is None:
        yield Step(None)
        return
    attrs = {
        "pragmatic.effect.name": name,
        "pragmatic.run_id": run_id,
        "pragmatic.branch": _branch(branch),
    }
    with tracer.start_as_current_span("pragmatic.effect", attributes=attrs) as span:
        yield Step(span)


def enabled() -> Optional[bool]:
    """True when spans are being emitted."""
    return _get_tracer() is not None
