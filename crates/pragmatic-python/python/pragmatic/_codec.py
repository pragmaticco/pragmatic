"""Canonical JSON for journaled tool arguments and results.

Replay matches an effect by its argument bytes, so the same logical call
must always encode to the same bytes: keys sorted, SDK sentinels
(``NOT_GIVEN``/``omit``) dropped, pydantic models dumped the same way
whether they came from the API or were rebuilt from the journal.
"""

from __future__ import annotations

import base64
import json
from typing import Any

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
