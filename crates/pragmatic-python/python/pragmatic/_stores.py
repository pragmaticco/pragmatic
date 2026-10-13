"""Where journals live: ``DirStore``, ``MemoryStore`` and the store protocol.

``DirStore`` and ``MemoryStore`` are the native backends (spec 3.3);
persisting through them never runs Python code. Any other object that
implements :class:`Store` (``ServerStore``, or a store of your own) is
driven by the native layer through that protocol (spec 6.3).
"""

from __future__ import annotations

import os
from typing import Any, List, Tuple, Union

from . import _native

try:  # Python 3.8+
    from typing import Protocol
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore[assignment,misc]


JOURNAL_HEADER: bytes = _native.JOURNAL_HEADER
"""The 16 bytes an unkeyed format 2 journal starts with. A store of your
own writes them when it creates a run."""


class Store(Protocol):
    """What the runtime calls on a store written in Python (spec 6.3).

    A store keeps each run's journal as whole bytes: the 16-byte header
    (:data:`JOURNAL_HEADER`) followed by whole frames. Journals in Python
    stores are unkeyed.

    - ``checkout(run_id, create)`` takes the run's lock or lease (and starts
      any heartbeat) and returns its journal bytes, or ``(bytes, entries,
      head_hex)`` when the store can vouch for the length and head. With
      ``create`` a missing run is created (its journal is the header);
      without it, a missing run raises ``FileNotFoundError``.
    - ``snapshot(run_id)`` returns the journal without any lock.
    - ``persist(run_id, at, frames, frame_count, head_hex)`` durably appends
      ``frame_count`` frames as entries ``at`` and on, ending at
      ``head_hex``; all or nothing.
    - ``checkin(run_id)`` stops the heartbeat and releases the run.
    - ``list()`` returns every run id.

    Raise ``pragmatic.Locked``, ``LeaseLost``, ``Conflict``, ``Deleted``,
    ``TooLarge``, ``Unavailable`` or ``OSError``; they map to the core
    faults of the same names (anything else is an I/O fault), and the
    caller sees the exception you raised. Set ``remote = True`` on a store
    other processes write to: a resume then needs an explicit recovery
    policy for effects a crash left open."""

    def checkout(self, run_id: str, create: bool) -> Union[bytes, Tuple[bytes, int, str]]: ...

    def snapshot(self, run_id: str) -> Union[bytes, Tuple[bytes, int, str]]: ...

    def persist(self, run_id: str, at: int, frames: bytes, frame_count: int, head_hex: str) -> None: ...

    def checkin(self, run_id: str) -> None: ...

    def list(self) -> List[str]: ...


class DirStore:
    """Journals as files under ``path``, one per run (named by the SHA-256 of
    the run id) with a sidecar lock file. Runs survive process crashes:
    open a runtime on the same directory and resume. The lock gives no
    exclusion across hosts on network filesystems; use a server for that."""

    def __init__(self, path: "Union[str, os.PathLike[str]]"):
        self.path = os.fspath(path)
        os.makedirs(self.path, exist_ok=True)
        self._native = _native.NativeStore.dir(self.path)

    def list(self) -> List[str]:
        """Every run id in the directory (format 1 journals by file name)."""
        return self._native.list()

    def __repr__(self) -> str:
        return f"DirStore({self.path!r})"


class MemoryStore:
    """Journals in this process's memory. Every runtime built over the same
    ``MemoryStore`` sees the same runs, so a test can crash a run under one
    runtime and resume it under another."""

    def __init__(self) -> None:
        self._native = _native.NativeStore.memory()

    def list(self) -> List[str]:
        return self._native.list()

    def __repr__(self) -> str:
        return "MemoryStore()"


def native_store(store: Any) -> Any:
    """The native backend handle for a store object."""
    if isinstance(store, (DirStore, MemoryStore)):
        return store._native
    for method in ("checkout", "snapshot", "persist", "checkin", "list"):
        if not callable(getattr(store, method, None)):
            raise TypeError(
                f"{type(store).__name__} is not a store: it has no {method}() (see pragmatic.Store)"
            )
    return _native.NativeStore.python(store)
