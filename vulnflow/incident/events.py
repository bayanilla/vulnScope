"""The normalized event every incident adapter produces, and the adapter interface.

One event is one record of a source file. It keeps where the record is (``evidence_id`` and
``locator``), how its time was known (``time_basis``), the source's own identifiers (``ids``) and
its original fields (``fields``), so every statement in a report can be traced to the record.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator, Protocol

# How an event's time was known.
STATED = "stated"              # the record says the zone (epoch seconds, a "Z" or "+hh:mm" suffix)
ASSUMED_UTC = "assumed_utc"    # no zone in the record; read as UTC
ANALYST_OFFSET = "analyst_offset"   # corrected by an offset the analyst set for this source
TIME_BASES = (STATED, ASSUMED_UTC, ANALYST_OFFSET)

CATEGORIES = ("authentication", "process", "network", "control_plane", "account", "service",
              "detection", "sensor", "other")

# Columns of the events Parquet files, in order, with their DuckDB types.
COLUMNS = {
    "event_id": "VARCHAR", "evidence_id": "VARCHAR", "locator": "VARCHAR", "seq": "BIGINT",
    "event_time": "BIGINT",            # microseconds since the epoch, UTC; NULL when unknown
    "time_original": "VARCHAR", "time_field": "VARCHAR", "time_basis": "VARCHAR",
    "provider": "VARCHAR", "source_type": "VARCHAR", "category": "VARCHAR",
    "action": "VARCHAR", "action_original": "VARCHAR", "outcome": "VARCHAR", "outcome_reason": "VARCHAR",
    "actor": "JSON", "host": "JSON", "target": "JSON",
    "src_ip": "VARCHAR", "src_port": "INTEGER", "dst_ip": "VARCHAR", "dst_port": "INTEGER",
    "proto": "VARCHAR", "ids": "JSON", "fields": "JSON",
}

_ZONE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$", re.I)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def event_id(evidence_id: str, locator: str) -> str:
    """Stable ID: the same record of the same file always gets the same ID."""
    return hashlib.sha256(f"{evidence_id}|{locator}".encode()).hexdigest()[:20]


def time_basis(value) -> str:
    """Whether a raw time value carries its zone. Epoch numbers are UTC by definition."""
    if value is None:
        return ASSUMED_UTC
    s = str(value).strip()
    try:
        float(s)
        return STATED
    except ValueError:
        pass
    return STATED if _ZONE.search(s) else ASSUMED_UTC


def micros(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    d = ts - EPOCH
    return (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds


@dataclass(slots=True)
class Event:
    evidence_id: str
    locator: str
    seq: int                                   # position in the file, for a stable order
    provider: str
    source_type: str
    category: str
    action: str
    event_time: datetime | None = None
    time_original: str = ""
    time_field: str = ""
    time_basis: str = ASSUMED_UTC
    action_original: str = ""
    outcome: str = "unknown"
    outcome_reason: str = ""
    actor: dict = field(default_factory=dict)
    host: dict = field(default_factory=dict)
    target: dict = field(default_factory=dict)
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str = ""
    ids: dict = field(default_factory=dict)
    fields: dict = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        return event_id(self.evidence_id, self.locator)

    def row(self) -> dict:
        return {
            "event_id": self.event_id, "evidence_id": self.evidence_id, "locator": self.locator,
            "seq": self.seq, "event_time": micros(self.event_time), "time_original": self.time_original,
            "time_field": self.time_field, "time_basis": self.time_basis, "provider": self.provider,
            "source_type": self.source_type, "category": self.category, "action": self.action,
            "action_original": self.action_original, "outcome": self.outcome,
            "outcome_reason": self.outcome_reason, "actor": self.actor, "host": self.host,
            "target": self.target, "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port, "proto": self.proto,
            "ids": {k: str(v) for k, v in self.ids.items() if v not in (None, "")},
            "fields": self.fields,
        }


@dataclass(slots=True)
class Reject:
    """A record that could not be read, and where it is."""
    locator: str
    reason: str


class Adapter(Protocol):
    """Reads one kind of source file into events.

    ``version`` changes whenever the events an adapter writes change; it is part of the cache key
    and the report's run key. ``coverage`` names what the source can only show when it was
    collected (an audit policy, a sensor's placement), for the report's gaps section."""
    name: str
    version: str
    coverage: dict[str, str]

    def accepts(self, path: str, detected: str) -> bool: ...

    def read(self, path: str, evidence_id: str, stats, on_reject: Callable[[Reject], None]
             ) -> Iterator[Event]: ...


def to_json(value) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
