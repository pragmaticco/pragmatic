"""Reports about stored runs: ``VerifyReport`` and ``RunSummary``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple


def _pairs(items: Any) -> Tuple[Tuple[int, int], ...]:
    return tuple((int(c), int(s)) for c, s in (items or ()))


@dataclass(frozen=True)
class VerifyReport:
    """The full integrity check of a run's journal (spec 2.5, 2.13).

    Truthy when ``ok``: the chain, every commitment and every erasure check
    out. A torn tail (``torn_bytes``) is what a crash during an append
    leaves behind and does not make a report fail."""

    first_bad: Optional[int] = None
    """The first cursor whose chain link, commitment or ref fails."""
    unaccounted_erasures: Tuple[Tuple[int, int], ...] = ()
    """Erased ``(cursor, slot)`` pairs no ``erasure`` note lists."""
    erasure_incomplete: Tuple[Tuple[int, int], ...] = ()
    """Slots an ``erasure`` note lists that still hold content."""
    invalid_erasure_notes: Tuple[int, ...] = ()
    """``erasure`` notes that list slots that do not exist."""
    torn_bytes: int = 0
    """Bytes past the valid prefix (a torn tail)."""

    @property
    def ok(self) -> bool:
        return (
            self.first_bad is None
            and not self.unaccounted_erasures
            and not self.erasure_incomplete
            and not self.invalid_erasure_notes
        )

    def __bool__(self) -> bool:
        return self.ok

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "VerifyReport":
        return cls(
            first_bad=d.get("first_bad"),
            unaccounted_erasures=_pairs(d.get("unaccounted_erasures")),
            erasure_incomplete=_pairs(d.get("erasure_incomplete")),
            invalid_erasure_notes=tuple(int(c) for c in d.get("invalid_erasure_notes") or ()),
            torn_bytes=int(d.get("torn_bytes") or 0),
        )


@dataclass(frozen=True)
class RunSummary:
    """One run, in the RunSummary shape of spec 4.4.

    For a local store the summary is built from the journal itself: there
    are no anchors, holds or leases, so ``anchored_entries`` is 0 and
    ``status`` is ``dangling`` (an intent without a result) or ``idle``.
    Times are RFC 3339 UTC text. ``raw`` keeps the whole document,
    including anything a newer server adds."""

    run_id: str
    entries: int = 0
    head: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    status: str = "idle"
    erased_slots: int = 0
    anchored_entries: int = 0
    unanchored_entries: int = 0
    holds: Tuple[str, ...] = ()
    labels: Mapping[str, str] = field(default_factory=dict)
    program: Optional[Mapping[str, str]] = None
    created_by: Optional[str] = None
    last_outcome: Optional[str] = None
    usage: Mapping[str, int] = field(default_factory=dict)
    verify: Optional[VerifyReport] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_json(cls, d: Mapping[str, Any]) -> "RunSummary":
        verify = d.get("verify")
        return cls(
            run_id=str(d["run_id"]),
            entries=int(d.get("entries") or 0),
            head=d.get("head"),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
            status=str(d.get("status") or "idle"),
            erased_slots=int(d.get("erased_slots") or 0),
            anchored_entries=int(d.get("anchored_entries") or 0),
            unanchored_entries=int(d.get("unanchored_entries") or 0),
            holds=tuple(d.get("holds") or ()),
            labels=dict(d.get("labels") or {}),
            program=d.get("program"),
            created_by=d.get("created_by"),
            last_outcome=d.get("last_outcome"),
            usage=dict(d.get("usage") or {}),
            verify=VerifyReport.from_dict(verify) if isinstance(verify, dict) else None,
            raw=dict(d),
        )


Entry = Dict[str, Any]
"""One journal entry in the Entry JSON shape of spec 4.4."""
