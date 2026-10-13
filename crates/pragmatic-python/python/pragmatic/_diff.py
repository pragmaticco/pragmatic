"""Where a model call's request differs from the recorded one.

When replay meets a model call whose request differs from the journal, a
bare "part 3 differs" leaves the developer diffing two large JSON bodies by
hand. ``request_diff`` names the first differing JSON paths instead, with
both values shortened, for the ``JournalDesync`` it raises. The diff lives
only in that exception: it is never written to a journal field, because it
quotes request content.
"""

from __future__ import annotations

import json
from typing import Any, List, Sequence

_MISSING = object()
_WIDTH = 60


def _short(value: Any) -> str:
    if value is _MISSING:
        return "(missing)"
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, bytes) else repr(value)
    return text if len(text) <= _WIDTH else text[: _WIDTH - 3] + "..."


def _key(path: str, key: str) -> str:
    if key.isidentifier():
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key)}]"


def _walk(a: Any, b: Any, path: str, out: List[str], limit: int) -> None:
    if len(out) >= limit or a == b:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            _walk(a.get(k, _MISSING), b.get(k, _MISSING), _key(path, k), out, limit)
        return
    if isinstance(a, list) and isinstance(b, list):
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else _MISSING
            y = b[i] if i < len(b) else _MISSING
            _walk(x, y, f"{path}[{i}]", out, limit)
        return
    out.append(f"{path}: recorded {_short(a)}, now {_short(b)}")


def _parse(part: bytes) -> Any:
    try:
        return json.loads(part)
    except (ValueError, UnicodeDecodeError):
        try:
            return part.decode("utf-8")
        except UnicodeDecodeError:
            return part


def request_diff(recorded: Sequence[bytes], now: Sequence[bytes], limit: int = 5) -> List[str]:
    """The first ``limit`` differences between two lists of request parts,
    each as ``part K at PATH: recorded X, now Y``."""
    out: List[str] = []
    if len(recorded) != len(now):
        out.append(f"the request has {len(now)} parts; the recorded one had {len(recorded)}")
    for k in range(min(len(recorded), len(now))):
        if recorded[k] == now[k]:
            continue
        found: List[str] = []
        _walk(_parse(recorded[k]), _parse(now[k]), "$", found, limit - len(out))
        out.extend(f"part {k} at {line}" for line in found)
        if len(out) >= limit:
            break
    return out[:limit]
