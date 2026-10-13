"""Recorded failures, raised again on replay.

A model call or a tool call that raises is a result too (spec 2.12): the
journal records the exception's type and message, so an agent that caught
the exception takes the same path when the run is resumed or replayed. On
replay the call is not made, so the exception has to be rebuilt from the
record:

- ``EffectFailed`` (a tool call) and ``DrawFailed`` (a model call) carry
  the recorded ``type_name`` and ``message``.
- When the recorded type can be found among the modules the program has
  already imported, the raised exception is *also* an instance of it, so
  ``except ValueError`` or ``except anthropic.RateLimitError`` catches it
  exactly as it caught the original, and ``str()`` gives the recorded
  text. Only the type and the message are kept: attributes the original's
  constructor set (a status code, say) are not. A type that cannot be
  rebuilt that way (one defined inside a function, an ``OSError``) replays
  as the plain base class.

Lookup never imports anything: a journal names the type, and importing
whatever a journal names would let the journal run code.
"""

from __future__ import annotations

import builtins
import sys
from typing import Dict, Optional, Tuple, Type

from ._errors import PragmaticError


class EffectFailed(PragmaticError):
    """A tool call that failed when the run was recorded, raised again on
    replay. ``type_name`` is the recorded exception type and ``message`` its
    text."""

    def __init__(self, type_name: str, message: str):
        super().__init__(message)
        self.type_name = type_name
        self.message = message


class DrawFailed(PragmaticError):
    """A model call that failed when the run was recorded, raised again on
    replay. ``type_name`` is the recorded exception type and ``message`` its
    text."""

    def __init__(self, type_name: str, message: str):
        super().__init__(message)
        self.type_name = type_name
        self.message = message


def type_name(exc: BaseException) -> str:
    """The name a failure is recorded under: ``module.QualName``, or the
    bare name of a builtin exception."""
    cls = type(exc)
    if cls.__module__ == "builtins":
        return cls.__qualname__
    return f"{cls.__module__}.{cls.__qualname__}"


def _resolve(name: str) -> Optional[Type[Exception]]:
    """The exception class a recorded name refers to, if the program has
    already imported it."""
    found: object = None
    if "." not in name:
        found = getattr(builtins, name, None)
    else:
        parts = name.split(".")
        for split in range(len(parts) - 1, 0, -1):
            module = sys.modules.get(".".join(parts[:split]))
            if module is None:
                continue
            found = module
            for attr in parts[split:]:
                found = getattr(found, attr, None)
                if found is None:
                    break
            break
    if isinstance(found, type) and issubclass(found, Exception):
        return found
    return None


_COMBINED: Dict[Tuple[type, type], type] = {}


def _recorded_str(exc: BaseException) -> str:
    # str() of the original was what the journal recorded, so the rebuilt
    # exception shows exactly that, whatever the original type's __str__
    # would make of it (KeyError quotes its argument, for one).
    return exc.message  # type: ignore[attr-defined]


def _combined(base: type, cls: type) -> Optional[type]:
    """A class that is both ``base`` and ``cls``, or None when the two
    cannot be combined (builtin exceptions with different layouts)."""
    key = (base, cls)
    if key not in _COMBINED:
        try:
            _COMBINED[key] = type(
                cls.__name__,
                (base, cls),
                {
                    "__module__": cls.__module__,
                    "__qualname__": cls.__qualname__,
                    "__str__": _recorded_str,
                },
            )
        except Exception:  # layouts that conflict, metaclasses that refuse
            _COMBINED[key] = None  # type: ignore[assignment]
    return _COMBINED[key]


def replayed(step: str, name: str, message: str) -> BaseException:
    """The exception a recorded failure of ``step`` (``"effect"`` or
    ``"draw"``) raises on replay."""
    base = EffectFailed if step == "effect" else DrawFailed
    cls = _resolve(name)
    combined = _combined(base, cls) if cls is not None and not issubclass(cls, base) else None
    if combined is None:
        return base(name, message)
    # The original constructor may need arguments the journal does not
    # keep, so it is skipped: the exception gets exactly the recorded
    # message, as its only argument and as what str() shows. Some builtin
    # types (OSError and its subclasses) cannot be created that way; they
    # replay as the plain base class.
    try:
        exc = combined.__new__(combined)
        BaseException.__init__(exc, message)
    except Exception:
        return base(name, message)
    exc.type_name = name
    exc.message = message
    return exc
