"""Canonical JSON for journaled requests and results.

Replay matches a model call by its prompt bytes, so the same logical
request must always encode to the same bytes: keys sorted, SDK sentinels
(``NOT_GIVEN``/``omit``) dropped, pydantic models dumped the same way
whether they came from the API or were rebuilt from the journal.
"""

from __future__ import annotations

import base64
import json
from typing import Any

# Keyword arguments that shape the HTTP transport, not the request the model
# sees. They stay out of the journal (``extra_headers`` can carry secrets).
TRANSPORT_KWARGS = frozenset({"timeout", "extra_headers", "extra_query"})

_SENTINELS = frozenset({"NotGiven", "Omit"})


def _is_sentinel(value: Any) -> bool:
    return type(value).__name__ in _SENTINELS


def to_jsonable(value: Any) -> Any:
    """Reduce ``value`` to plain JSON types, deterministically."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {
            str(k): to_jsonable(v) for k, v in value.items() if not _is_sentinel(v)
        }
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return to_jsonable(model_dump(mode="json"))
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": base64.b64encode(bytes(value)).decode("ascii")}
    if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
        return [to_jsonable(v) for v in value]
    raise TypeError(
        f"pragmatic cannot journal a {type(value).__name__}: model-call "
        "arguments and tool inputs/outputs must be JSON-serializable"
    )


def canonical(value: Any) -> str:
    """The canonical encoding: stable across processes and replays."""
    return json.dumps(
        to_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def request_prompt(api: str, kwargs: dict) -> str:
    """The journaled prompt for one SDK call: the API surface plus every
    argument the model sees."""
    request = {
        k: v for k, v in kwargs.items() if k not in TRANSPORT_KWARGS and not _is_sentinel(v)
    }
    return canonical({"api": api, "request": request})
