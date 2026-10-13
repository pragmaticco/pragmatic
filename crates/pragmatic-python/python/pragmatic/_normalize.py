"""Request normalization: which request fields replay may ignore (spec 6.6).

Replay matches a model call by its request, part for part. A few request
fields change on every run without changing what the model is asked (the
OpenAI Agents SDK, for one, sends a fresh ``prompt_cache_key`` of the form
``agents-sdk:run:<uuid>`` with each run), so a recorded run could never
replay. A *rule* names such a field; both the recorded request and the new
one have its value replaced with a fixed token before they are compared.

Every rule loosens what a replay proves, so the rules are explicit:

- the built-in rule ``agents-sdk:prompt_cache_key`` replaces the Agents
  SDK's per-run prompt cache keys, and nothing else;
- ``Runtime(volatile=[...])`` adds JSON-path rules over the request body,
  such as ``"$.metadata.session_id"`` or ``"$.messages[*].id"``;
- the names of the rules in force are recorded in each ``attempt.start``
  note (``normalization``), so an auditor sees what was loosened.

The journal always stores the request as it was sent. Normalization only
decides whether a new request matches a recorded one.

Path syntax: ``$`` then any of ``.name``, ``['name']`` (or double quotes),
``[n]``, ``[*]`` and ``.*``. A ``*`` matches every member of an object or
every element of an array. A path that matches nothing changes nothing.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable, List, Sequence, Tuple, Union

TOKEN = "<volatile>"
"""What a normalized value is replaced with."""

AGENTS_SDK_RULE = "agents-sdk:prompt_cache_key"
_AGENTS_RUN_KEY = "agents-sdk:run:"

Segment = Union[str, int, None]  # a member name, an index, or None for `*`

_SEGMENT = re.compile(
    r"""\.(?P<name>[^.\[\]]+)
      | \[(?P<index>\d+)\]
      | \[\*\]
      | \['(?P<sq>(?:[^'\\]|\\.)*)'\]
      | \["(?P<dq>(?:[^"\\]|\\.)*)"\]""",
    re.VERBOSE,
)


def parse_path(path: str) -> Tuple[Segment, ...]:
    """The segments of a JSON path, or ``ValueError`` naming the problem."""
    if not isinstance(path, str) or not path.startswith("$"):
        raise ValueError(f"a volatile rule is a JSON path starting with '$', not {path!r}")
    segments: List[Segment] = []
    pos = 1
    while pos < len(path):
        m = _SEGMENT.match(path, pos)
        if m is None:
            raise ValueError(f"cannot parse the JSON path {path!r} at offset {pos}")
        if m.group("name") is not None:
            name = m.group("name")
            segments.append(None if name == "*" else name)
        elif m.group("index") is not None:
            segments.append(int(m.group("index")))
        elif m.group("sq") is not None:
            segments.append(_unescape(m.group("sq")))
        elif m.group("dq") is not None:
            segments.append(_unescape(m.group("dq")))
        else:
            segments.append(None)
        pos = m.end()
    if not segments:
        raise ValueError("the JSON path '$' would match the whole request; name a field")
    return tuple(segments)


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def _replace(node: Any, segments: Sequence[Segment], dry: bool = False) -> bool:
    """Replace what ``segments`` match under ``node`` with the token, in
    place. Returns whether anything changed; a ``dry`` run only answers."""
    head, rest = segments[0], segments[1:]
    if isinstance(node, dict):
        keys = list(node) if head is None else ([head] if isinstance(head, str) and head in node else [])
    elif isinstance(node, list):
        if head is None:
            keys = list(range(len(node)))
        elif isinstance(head, int) and head < len(node):
            keys = [head]
        else:
            keys = []
    else:
        return False
    changed = False
    for k in keys:
        if rest:
            changed = _replace(node[k], rest, dry) or changed
        elif node[k] != TOKEN:
            if dry:
                return True
            node[k] = TOKEN
            changed = True
        if changed and dry:
            return True
    return changed


class _PathRule:
    __slots__ = ("name", "segments")

    def __init__(self, path: str):
        self.name = path
        self.segments = parse_path(path)

    def apply(self, body: Any, dry: bool = False) -> bool:
        return _replace(body, self.segments, dry)


class _AgentsSdkPromptCacheKey:
    """The OpenAI Agents SDK's per-run ``prompt_cache_key``. Only the
    ``agents-sdk:run:`` keys are replaced: keys the SDK derives from a
    conversation, session or group id are stable and still compared."""

    __slots__ = ()
    name = AGENTS_SDK_RULE

    def apply(self, body: Any, dry: bool = False) -> bool:
        if not isinstance(body, dict):
            return False
        value = body.get("prompt_cache_key")
        if not isinstance(value, str) or not value.startswith(_AGENTS_RUN_KEY):
            return False
        token = _AGENTS_RUN_KEY + TOKEN
        if value == token:
            return False
        if not dry:
            body["prompt_cache_key"] = token
        return True


class Normalizer:
    """The rules one runtime matches requests under: the built-in rule
    first, then ``volatile`` in the order given."""

    __slots__ = ("rules",)

    def __init__(self, volatile: Iterable[str] = ()):
        rules: List[Any] = [_AgentsSdkPromptCacheKey()]
        for path in volatile:
            rules.append(_PathRule(path))
        self.rules = tuple(rules)

    @property
    def names(self) -> List[str]:
        """The rule names recorded in ``attempt.start``."""
        return [r.name for r in self.rules]

    def __call__(self, body: Any) -> Tuple[Any, bool]:
        """``(normalized body, changed)``. The body passed in is never
        modified; an unchanged body comes back as the same object."""
        if not isinstance(body, (dict, list)):
            return body, False
        # A dry run first, so the common request that no rule touches is
        # never copied.
        if not any(rule.apply(body, dry=True) for rule in self.rules):
            return body, False
        out = copy.deepcopy(body)
        for rule in self.rules:
            rule.apply(out)
        return out, True
