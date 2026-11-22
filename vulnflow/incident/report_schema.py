"""The declared shape of incident_report.json (baseline), checked with the same small validator
as results.json (vulnflow/results_schema.py). Published as docs/incident_report.schema.json.

This schema covers incident reports only. The vulnerability workflow's results.json is unchanged.
"""
from __future__ import annotations

import json

from ..results_schema import BOOL, INT, STR, _lenient, _walk, arr, counts, obj, opt

REPORT_SCHEMA_VERSION = 1
IDS = arr(STR)

INPUT = obj({
    "evidence_id": STR, "original_name": STR, "sha256": STR, "size": INT, "format": STR, "adapter": STR,
    "adapter_version": STR, "status": STR, "status_detail": STR, "uploaded_by": STR, "uploaded_at": STR,
    "duplicate_uploads": INT, "read": INT, "events": INT, "rejected": INT, "dropped": counts(),
    "notes": arr(STR), "rejects": arr(obj({"locator": STR, "reason": STR})),
})
ITEM = obj({"item_id": STR, "time": STR, "last_time": STR, "kind": {"type": "string", "enum": ["observed", "inferred"]},
            "category": STR, "action": STR, "summary": STR, "entities": arr(STR), "evidence": IDS,
            "evidence_count": INT})
FINDING = obj({"finding_id": STR, "rule_id": STR, "title": STR,
               "kind": {"type": "string", "enum": ["observed", "inferred"]},
               "basis": {"type": "string", "enum": ["same records", "same_id", "same_tuple", "host_reported_socket",
                                                    "time_proximity", "ip_only"]},
               "statement": STR, "entities": arr(STR), "evidence": IDS, "evidence_count": INT})
LINK = obj({"from": STR, "to": STR, "basis": STR, "identifier": STR, "value": STR, "relation": STR})
GAP = obj({"type": STR, "text": STR}, {"evidence_id": STR, "evidence": IDS})
EVIDENCE_RECORD = obj({"event_id": STR, "evidence_id": STR, "file": STR, "sha256": STR, "locator": STR,
                       "original": STR, "truncated": BOOL, "found": BOOL})

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "VulnScope incident baseline report (incident_report.json)",
    **obj({
        "schema_version": INT, "kind": {"type": "string", "enum": ["baseline"]}, "report_id": STR, "version": INT,
        "run_key": STR, "generated": STR, "engine_version": STR, "ruleset_version": STR,
        "adapters": {"type": "object", "additionalProperties": STR},
        "case": obj({"case_id": STR, "name": STR, "entities": arr(STR), "notes": STR}),
        "scope": obj({"networks": arr(STR), "hosts": arr(STR), "accounts": arr(STR),
                      "window": obj({"start": opt(STR), "end": opt(STR), "margin_minutes": INT}),
                      "filtered": obj({"events_total": INT, "out_of_scope": INT, "outside_window": INT,
                                       "untimed": INT, "kept": INT})}),
        "inputs": arr(INPUT),
        "counts": obj({"events_kept": INT, "by_category": counts(), "by_outcome": counts(),
                       "by_source": arr(obj({"provider": STR, "source_type": STR, "category": STR, "outcome": STR,
                                             "events": INT})),
                       "timeline_items": INT, "findings": INT, "entities": INT}),
        "timeline": arr(ITEM), "findings": arr(FINDING),
        "entities": arr(obj({"type": STR, "value": STR, "first_seen": opt(STR), "last_seen": opt(STR), "events": INT,
                             "as_source": INT, "as_destination": INT, "inside": BOOL})),
        "links": obj({"same_id_total": INT, "by_action": counts(), "examples": arr(LINK)}),
        "untimed": obj({"count": INT, "examples": arr(obj({"event_id": STR, "evidence_id": STR, "locator": STR,
                                                            "source_type": STR}))}),
        "gaps": arr(GAP), "reading_notes": arr(STR), "evidence_records": arr(EVIDENCE_RECORD),
    }),
}


def problems(report, limit: int = 20, required: bool = True) -> list[str]:
    out: list[str] = []
    _walk(report, SCHEMA if required else _lenient(SCHEMA), "incident_report.json", out, limit)
    if required and not out:
        out += _citations(report, limit)
    return out


def _citations(report: dict, limit: int) -> list[str]:
    """Every statement must cite at least one event."""
    out = []
    for where in ("timeline", "findings"):
        for i, item in enumerate(report.get(where, [])):
            if not item.get("evidence"):
                out.append(f"incident_report.json.{where}[{i}]: cites no evidence")
                if len(out) >= limit:
                    return out
    return out


def as_json() -> str:
    return json.dumps(SCHEMA, indent=2) + "\n"


if __name__ == "__main__":     # python -m vulnflow.incident.report_schema > docs/incident_report.schema.json
    print(as_json(), end="")
