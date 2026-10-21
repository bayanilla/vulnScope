"""Load every input file, normalize it into the common schema and clean it."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .parsers import FORMATS, detect
from .schema import Finding, Flow, OTEvent, ParseStats, ThreatEvent, ZeekEvent


@dataclass
class Dataset:
    flows: list[Flow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    threats: list[ThreatEvent] = field(default_factory=list)      # IPS/IDS alerts
    zeek_events: list[ZeekEvent] = field(default_factory=list)
    ot_events: list[OTEvent] = field(default_factory=list)
    scanned_hosts: dict[str, dict] = field(default_factory=dict)   # ip -> {hostname, os}
    stats: list[ParseStats] = field(default_factory=list)
    duplicate_flows: int = 0
    duplicate_findings: int = 0


def load(paths: list[str], overrides: dict[str, str] | None = None) -> Dataset:
    """overrides maps a file path or basename to a format name."""
    overrides = overrides or {}
    ds = Dataset()
    raw_flows: list[Flow] = []
    raw_findings: list[Finding] = []
    for path in paths:
        name = os.path.basename(path)
        fmt = overrides.get(path) or overrides.get(name) or detect(path)
        if fmt not in FORMATS:
            raise ValueError(f"{name}: unknown format '{fmt}' (choose from {', '.join(FORMATS)})")
        kind, parser = FORMATS[fmt]
        stats = ParseStats(file=name, fmt=fmt)
        try:
            records = parser(path, stats)
        except Exception as exc:  # a broken file should not sink the whole run
            stats.note(f"file could not be parsed: {exc}")
            records = []
        for r in records:
            r.source = name
        stats.kept = len(records)
        ds.stats.append(stats)
        if kind == "findings":
            raw_findings.extend(records)
        else:
            raw_flows.extend(r for r in records if isinstance(r, Flow))
            threats = [r for r in records if isinstance(r, ThreatEvent)]
            if threats:
                stats.note(f"{len(threats)} IPS/IDS alert(s) used as exploitation evidence")
            ds.threats.extend(threats)
            ds.zeek_events.extend(r for r in records if isinstance(r, ZeekEvent))
            ds.ot_events.extend(r for r in records if isinstance(r, OTEvent))

    # Flows seen by two sensors (e.g. Zeek and the firewall) are kept once each
    # per sensor, but exact duplicates within the combined set are removed.
    seen = set()
    for f in raw_flows:
        k = f.key()
        if k in seen:
            ds.duplicate_flows += 1
            continue
        seen.add(k)
        ds.flows.append(f)
    ds.flows.sort(key=lambda f: (f.ts is None, f.ts))
    ds.threats = sorted({t.key(): t for t in ds.threats}.values(), key=lambda t: (t.ts is None, t.ts))

    # Overlapping scans: keep one finding per host/port/plugin, preferring the richer record.
    best: dict[tuple, Finding] = {}
    for f in raw_findings:
        ds.scanned_hosts.setdefault(f.host_ip, {"hostname": "", "os": ""})
        h = ds.scanned_hosts[f.host_ip]
        h["hostname"] = h["hostname"] or f.hostname
        h["os"] = h["os"] or f.os
        cur = best.get(f.key())
        if cur is None:
            best[f.key()] = f
        else:
            ds.duplicate_findings += 1
            if (f.exploit_available, f.cvss or 0) > (cur.exploit_available, cur.cvss or 0):
                best[f.key()] = f
    for f in best.values():
        f.hostname = f.hostname or ds.scanned_hosts[f.host_ip]["hostname"]
        f.os = f.os or ds.scanned_hosts[f.host_ip]["os"]
    ds.findings = sorted(best.values(), key=lambda f: (-f.severity, f.host_ip, f.port))
    return ds
