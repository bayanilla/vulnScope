"""The declared shape of results.json.

results.json is the contract between the analysis and everything that reads it: the reports, the
Assistant, Compare, a reopened run, and any script of the user's. ``SCHEMA`` states that contract
once, as JSON Schema (also published as ``docs/results.schema.json``), and ``problems`` checks a
document against it without any third-party package.

Only what readers rely on is required. Extra keys are allowed everywhere, so a results.json from a
newer copy that adds a field still opens; a key that is present must have the declared type.
"""
from __future__ import annotations

import json

from .correlate import RESULTS_SCHEMA_VERSION

STR, INT, NUM, BOOL = {"type": "string"}, {"type": "integer"}, {"type": "number"}, {"type": "boolean"}


def opt(kind: dict) -> dict:
    """The kind, or null."""
    return {"anyOf": [kind, {"type": "null"}]}


def arr(items: dict) -> dict:
    return {"type": "array", "items": items}


def counts() -> dict:
    """A name -> whole number table (severities, protocols, drop reasons)."""
    return {"type": "object", "additionalProperties": INT}


def obj(required: dict, optional: dict | None = None) -> dict:
    return {"type": "object", "properties": {**required, **(optional or {})}, "required": list(required)}


PAIRS = arr(arr({"anyOf": [STR, INT, BOOL]}))            # [[address, count, ...], ...]
WINDOW = obj({"start": STR, "end": STR, "days": INT})

EXPOSURE = obj({
    "label": STR, "factor": NUM, "scope": STR, "telemetry_seen": BOOL, "inbound_total": INT,
    "established": INT, "denied": INT, "refused": INT, "attempts": INT, "internal_sources": INT,
    "external_sources": INT, "top_sources": PAIRS, "first_seen": opt(STR), "last_seen": opt(STR),
    "bytes": INT, "threat_alerts": INT, "threat_blocked": INT, "threat_blocked_sources": PAIRS,
}, {"window": WINDOW, "windows": arr(WINDOW)})

INDICATOR = obj({"type": STR, "confidence": STR, "text": STR}, {
    "sources": PAIRS, "at": STR, "peer": STR, "ports": arr(INT), "port": INT, "proto": STR, "bytes": INT,
    "targets": arr(obj({"ip": STR, "ports": arr(INT)})),
})

FINDING = obj({
    "host": STR, "hostname": STR, "os": STR, "plugin_id": STR, "plugin_name": STR, "severity": INT,
    "severity_name": STR, "port": INT, "proto": STR, "service": STR, "cvss": NUM, "cves": arr(STR),
    "exploit_available": BOOL, "exploit_frameworks": arr(STR), "synopsis": STR, "solution": STR,
    "source": STR, "exposure": EXPOSURE, "blast_factor": NUM, "exploit_factor": NUM, "likelihood": STR,
    "score": INT, "priority": STR, "indicators": arr(INDICATOR), "rationale": arr(STR),
}, {"network": STR})

BLAST = obj({
    "reachable_count": INT, "direct_count": INT,
    "reachable": arr(obj({"ip": STR, "hop": INT, "ports": arr(STR), "max_severity": STR})),
    "vulnerable_pivots": arr(STR), "lateral_protocols": counts(), "external_destinations": INT,
    "top_external_destinations": PAIRS, "factor": NUM,
})

HOST = obj({
    "host": STR, "hostname": STR, "os": STR, "findings": INT, "by_severity": counts(),
    "max_score": opt(INT), "priority": opt(STR), "internet_exposed": opt(BOOL), "indicators": INT,
    "blast": BLAST, "telemetry_seen": BOOL, "inbound_flows": INT, "outbound_flows": INT,
}, {"network": STR})

SCANNER = obj({"ip": STR, "sessions": INT, "hosts": INT, "ports": INT, "targets": INT, "failed_pct": INT,
               "kind": STR, "evidence": arr(STR), "internal": BOOL, "expected": BOOL, "name": STR})

SUMMARY = obj({
    "vulnerability_data_available": BOOL, "flows": INT, "findings_total": INT, "findings_scored": INT,
    "hosts_with_findings": INT, "priority_counts": {"type": "object", "additionalProperties": opt(INT)},
    "internet_exposed_findings": opt(INT), "exploitable_and_exposed": opt(INT),
    "hosts_with_indicators": arr(STR), "hosts_corroborated": arr(STR), "hosts_to_investigate": arr(STR),
    "hosts_possible_spread": arr(STR), "threat_alerts": INT, "zeek_event_counts": counts(),
    "ot_protocol_counts": counts(), "hosts_internet_exposed": INT, "window_start": opt(STR),
    "window_end": opt(STR), "duplicate_flows_removed": INT, "cross_sensor_duplicates_removed": INT,
    "duplicate_findings_merged": INT, "scanner_ips": arr(STR), "scanner_sessions_excluded": INT,
    "traffic_scanners": arr(SCANNER), "traffic_scanners_total": INT,
})

COVERAGE = obj({
    "scanned_hosts": INT, "telemetry_internal_hosts": INT, "probed_only_addresses": INT,
    "probed_blocked_addresses": INT, "probed_only_subnets": PAIRS, "sessions_answered_pct": opt(NUM),
    "capture_loss_pct": opt(NUM), "one_way_capture_suspected": BOOL, "scanned_and_seen": INT,
    "scanned_not_seen": arr(STR),
    "active_servers_not_scanned": arr(obj({"ip": STR, "services": arr(STR), "sessions": INT})),
})

IOC_MATCH = obj({"id": STR, "type": STR, "value": STR, "articles": arr(STR), "sources": arr(STR),
                 "first_seen": STR, "last_seen": STR, "disposition": STR, "hosts": arr(STR),
                 "observed": counts()})

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "VulnScope results.json",
    "description": f"Results format {RESULTS_SCHEMA_VERSION}. Extra keys are allowed; a listed key must have the type shown.",
    **obj({
        "schema_version": INT, "generated": STR,
        "config": obj({"internal_nets": arr(STR), "hops": INT, "min_severity": STR, "normalized_copies": BOOL}),
        "inputs": arr(obj({"file": STR, "format": STR, "read": INT, "kept": INT, "dropped": counts(),
                           "notes": arr(STR)})),
        "summary": SUMMARY, "coverage": COVERAGE, "hosts": arr(HOST), "findings": arr(FINDING),
        "telemetry_leads": arr(obj({"host": STR, "alerts": INT, "unblocked": INT, "blocked": INT,
                                    "role": arr(STR), "signatures": arr(STR), "note": STR})),
        "network_leads": arr(obj({"host": STR, "peer": STR, "sessions": INT, "note": STR})),
    }, {
        "report": obj({"name": STR, "description": STR, "network": STR}),
        "ioc_matches": arr(IOC_MATCH),
        "ioc_archive": obj({"files": arr(STR), "indicators": INT, "matches": INT}),
        "network_map": arr(obj({"cidr": STR, "name": STR, "type": STR, "cloud": BOOL})),
        "networks": arr(obj({"name": STR, "type": STR, "cloud": BOOL, "ranges": arr(STR), "scanned": INT,
                             "with_findings": INT, "p1": INT})),
        "article_briefs": {"type": "object"},
    }),
}

_KINDS = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list,
          "object": dict, "null": type(None)}


def _is(value, kind: str) -> bool:
    if kind in ("integer", "number") and isinstance(value, bool):
        return False                               # True is not a count
    return isinstance(value, _KINDS[kind])


def _walk(value, schema: dict, where: str, out: list[str], limit: int) -> None:
    if len(out) >= limit:
        return
    if "anyOf" in schema:
        for choice in schema["anyOf"]:
            found: list[str] = []
            _walk(value, choice, where, found, 1)
            if not found:
                return
        out.append(f"{where}: {type(value).__name__} is not one of the kinds allowed here")
        return
    kind = schema.get("type")
    if kind and not _is(value, kind):
        out.append(f"{where}: expected {kind}, found {type(value).__name__}")
        return
    if kind == "object":
        props = schema.get("properties", {})
        for key in schema.get("required", ()):
            if key not in value:
                out.append(f"{where}: \"{key}\" is missing")
        extra = schema.get("additionalProperties")
        for key, item in value.items():
            if key in props:
                _walk(item, props[key], f"{where}.{key}", out, limit)
            elif isinstance(extra, dict):
                _walk(item, extra, f"{where}.{key}", out, limit)
    elif kind == "array" and "items" in schema:
        for i, item in enumerate(value):
            if len(out) >= limit:
                return
            _walk(item, schema["items"], f"{where}[{i}]", out, limit)


def problems(res, limit: int = 20, required: bool = True) -> list[str]:
    """What in ``res`` does not fit the declared shape, as readable lines (at most ``limit``).

    ``required=False`` checks only the types of what is present; that is the rule for a saved
    file, since an older copy of VulnScope wrote fewer keys."""
    out: list[str] = []
    _walk(res, SCHEMA if required else _lenient(SCHEMA), "results.json", out, limit)
    return out


def _lenient(schema):
    if isinstance(schema, dict):
        return {k: _lenient(v) for k, v in schema.items() if k != "required"}
    if isinstance(schema, list):
        return [_lenient(v) for v in schema]
    return schema


def as_json() -> str:
    """The text of docs/results.schema.json."""
    return json.dumps(SCHEMA, indent=2) + "\n"


if __name__ == "__main__":                         # python -m vulnflow.results_schema > docs/results.schema.json
    print(as_json(), end="")
