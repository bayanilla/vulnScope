"""Load every input file, normalize it into the common schema and clean it."""
from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from multiprocessing import get_context

from . import resources
from .errors import UserError
from .parsers import FORMATS, detect, native
from .schema import Finding, Flow, OTEvent, ParseStats, ThreatEvent, ZeekEvent
from .store import (DEFAULT_BATCH, DEFAULT_SKEW_SECONDS, SENSOR_RANK, EventSpool, FlowView,
                    PartWriter, Store)


@dataclass
class Dataset:
    """Normalized inputs.

    ``load`` fills ``flows`` with a disk-backed FlowView and the Zeek/OT event lists with
    Parquet-backed spools, so memory stays flat as inputs grow. Plain lists still work (tests and
    small callers build Datasets by hand); ``flow_store`` loads them into DuckDB on demand.
    """
    flows: list[Flow] | FlowView = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    threats: list[ThreatEvent] = field(default_factory=list)      # IPS/IDS alerts
    zeek_events: list[ZeekEvent] | EventSpool = field(default_factory=list)
    ot_events: list[OTEvent] | EventSpool = field(default_factory=list)
    scanned_hosts: dict[str, dict] = field(default_factory=dict)   # ip -> {hostname, os}
    scanner_ips: set[str] = field(default_factory=set)   # the vulnerability scanner(s), from plugin 19506
    stats: list[ParseStats] = field(default_factory=list)
    duplicate_flows: int = 0
    duplicate_findings: int = 0
    cross_sensor_duplicates: int = 0
    store: Store | None = field(default=None, repr=False, compare=False)

    def flow_store(self) -> Store:
        """The DuckDB store holding ``flows``; built from a plain list the first time."""
        if isinstance(self.flows, FlowView):
            return self.flows.store
        key = (id(self.flows), len(self.flows))
        if self.store is None or getattr(self, "_list_key", None) != key:
            if self.store is not None:
                self.store.close()
            self.store = Store()
            self.store.load_flow_list(self.flows)
            object.__setattr__(self, "_list_key", key)
        return self.store

    def close(self):
        """Delete the working directory (Parquet, DuckDB file, event spools)."""
        if self.store is not None:
            self.store.close()


def _scan_times(f: Finding) -> list[tuple]:
    return list(f.scan_times) or ([(f.scan_start, f.scan_end)] if f.scan_start else [])


def _sensor(fmt: str) -> str:
    return "zeek" if fmt in ("zeek", "filebeat_zeek") else fmt if fmt in SENSOR_RANK else "generic"


def load(paths: list[str], overrides: dict[str, str] | None = None, *,
         workdir: str | None = None, skew_seconds: float | None = DEFAULT_SKEW_SECONDS,
         batch_size: int = DEFAULT_BATCH, budget: resources.Budget | None = None) -> Dataset:
    """overrides maps a file path or basename to a format name.

    Files are parsed in parallel worker processes (see ``parse_workers``). Records stream from
    each parser in batches: flows go to Parquet under ``workdir`` and are de-duplicated with
    DuckDB; other Zeek streams go to compressed Parquet too. ``skew_seconds`` is the clock-skew tolerance used to recognise the same
    session seen by two sensors (None disables cross-sensor matching).
    """
    overrides = overrides or {}
    store = Store(workdir, budget=budget)
    try:
        return _load(store, paths, overrides, skew_seconds, batch_size)
    except Exception as exc:
        store.close()
        friendly = None if isinstance(exc, resources.ResourceError) else resources.explain(exc, store.budget)
        if friendly is not None:
            raise friendly from exc
        raise


# Inputs smaller than this are parsed in the main process: starting worker processes would take
# longer than the parsing itself.
PARALLEL_MIN_BYTES = 64 * 1024 * 1024


def _load(store, paths, overrides, skew_seconds, batch_size) -> Dataset:
    ds = Dataset(store=store)
    jobs = []
    for fid, path in enumerate(paths):
        name = os.path.basename(path)
        fmt = overrides.get(path) or overrides.get(name) or detect(path)
        if fmt not in FORMATS:
            raise UserError(f"{name}: unknown format '{fmt}' (choose from {', '.join(FORMATS)})")
        jobs.append((fid, path, fmt, store.dir, batch_size))
    raw_findings: list[Finding] = []
    threats: dict[tuple, ThreatEvent] = {}
    counts = {"zeek_events": 0, "ot_events": 0}
    for stats, records, threat_list, part_counts, fatal in _parse_all(jobs, store.budget):
        if fatal:
            raise RuntimeError(fatal)       # out of memory or disk in a worker: resources.explain words it
        raw_findings.extend(records)
        for t in threat_list:
            threats[t.key()] = t            # first position, last record wins (as before)
        for k in counts:
            counts[k] += part_counts[k]
        ds.stats.append(stats)
    ds.zeek_events = store.events("zeek_events", ot=False, count=counts["zeek_events"])
    ds.ot_events = store.events("ot_events", ot=True, count=counts["ot_events"])

    # Exact duplicates are removed; a session seen by two sensors (e.g. Zeek and the
    # firewall) is counted once. Both steps run in DuckDB over the Parquet batches.
    ds.duplicate_flows, ds.cross_sensor_duplicates = store.finalize_flows(skew_seconds)
    ds.flows = FlowView(store)
    ds.threats = sorted(threats.values(), key=lambda t: (t.ts is None, t.ts))

    # Overlapping scans: keep one finding per host/port/plugin, preferring the richer record.
    best: dict[tuple, Finding] = {}
    for f in raw_findings:
        ds.scanned_hosts.setdefault(f.host_ip, {"hostname": "", "os": ""})
        h = ds.scanned_hosts[f.host_ip]
        h["hostname"] = h["hostname"] or f.hostname
        h["os"] = h["os"] or f.os
        if f.scanner_ip:
            ds.scanner_ips.add(f.scanner_ip)
        cur = best.get(f.key())
        if cur is None:
            best[f.key()] = f
        else:
            ds.duplicate_findings += 1
            # Keep every scan's time: each scan gets its own window (not one span over the gap between them).
            times = sorted(set(_scan_times(cur) + _scan_times(f)), key=lambda t: t[0])
            if (f.exploit_available, f.cvss or 0) > (cur.exploit_available, cur.cvss or 0):
                best[f.key()] = cur = f
            cur.scan_times = times
            if times:
                cur.scan_start, cur.scan_end = times[-1]          # the latest scan, for display
    for f in best.values():
        f.hostname = f.hostname or ds.scanned_hosts[f.host_ip]["hostname"]
        f.os = f.os or ds.scanned_hosts[f.host_ip]["os"]
    ds.findings = sorted(best.values(), key=lambda f: (-f.severity, f.host_ip, f.port))
    return ds


def parse_workers(jobs: list, budget: resources.Budget | None) -> int:
    """How many processes parse files at once: one per CPU, at most one per input file and one
    per GiB of the analysis' memory ceiling (each worker holds about half a GiB at peak).
    VULNSCOPE_PARSE_WORKERS overrides it (1 parses everything in the main process). Small inputs
    are parsed in the main process unless the variable is set."""
    raw = os.environ.get("VULNSCOPE_PARSE_WORKERS", "").strip()
    if raw:
        try:
            return max(1, min(int(raw), len(jobs)))
        except ValueError:
            raise UserError(f"VULNSCOPE_PARSE_WORKERS must be a whole number, not '{raw}'.") from None
    size = 0
    for job in jobs:
        try:
            size += os.path.getsize(job[1])
        except OSError:
            pass
    if len(jobs) < 2 or size < PARALLEL_MIN_BYTES:
        return 1
    cpus = budget.machine.cpus if budget else resources.cpu_count()
    by_memory = max(1, (budget.ceiling if budget else resources.GiB) // resources.GiB)
    return max(1, min(cpus, len(jobs), by_memory))


def _parse_all(jobs: list, budget):
    """Parse every file, yielding results in input order. Files are spread over worker
    processes when there is more than one worker (see ``parse_workers``)."""
    workers = parse_workers(jobs, budget)
    if workers == 1:
        for job in jobs:
            yield parse_file(job)
        return
    # "spawn" (not fork): the main process has DuckDB threads running, and spawn is what macOS
    # and Windows use anyway, so every platform behaves the same.
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn"))
    try:
        # map() keeps input order; results are small (findings, alerts, counts), since flows and
        # events go straight to Parquet in the worker.
        yield from pool.map(parse_file, jobs)
    except BrokenProcessPool:
        raise resources.ResourceError(
            "A file-parsing process stopped unexpectedly, most likely because the machine ran out of "
            "memory. Set VULNSCOPE_PARSE_WORKERS to a lower number (1 parses one file at a time).") from None
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def _native(fmt: str, path: str, name: str, stats: ParseStats, writer: PartWriter):
    """(records kept, alerts) when a native reader handled the file, else None."""
    if fmt == "zeek":
        kept = native.zeek_conn(path, name, writer.fid, writer.base, writer.dir, writer._con(), stats)
        return None if kept is None else (kept, [])
    if fmt == "paloalto":
        got = native.paloalto(path, name, writer.fid, writer.base, writer.dir, writer._con(), stats)
        return None if got is None else (got[0] + len(got[1]), got[1])
    return None


def parse_file(job):
    """Parse one input file (in a worker process or the main one). Flows and Zeek/OT events are
    written to Parquet in the run's working directory; findings and IPS/IDS alerts, which are
    small, are returned. Returns (stats, findings, alerts, event counts, fatal error or None)."""
    fid, path, fmt, workdir, batch_size = job
    name = os.path.basename(path)
    kind, parser = FORMATS[fmt]
    sensor = _sensor(fmt)
    stats = ParseStats(file=name, fmt=fmt)
    writer = PartWriter(workdir, fid, batch_size)
    findings, alerts = [], []
    kept = 0
    try:
        try:
            # The two formats that make up most of a large run are read by DuckDB itself when
            # the file is an ordinary one (parsers/native.py); anything else, and every other
            # format, goes through the Python parser below.
            done = _native(fmt, path, name, stats, writer)
            if done is not None:
                kept, alerts = done
            for r in (parser(path, stats) if done is None else ()):
                r.source = name
                kept += 1
                if kind == "findings":
                    findings.append(r)
                elif isinstance(r, Flow):
                    writer.add_flow(r, sensor)
                elif isinstance(r, ThreatEvent):
                    alerts.append(r)
                elif isinstance(r, ZeekEvent):
                    writer.add_event(r)              # OT events are Zeek events too (as before)
        except Exception as exc:  # a broken file should not sink the whole run
            if resources.explain(exc, None) is not None:
                raise                    # out of memory or disk: stop, don't report a "broken file"
            # Records parsed before the error (e.g. a truncated .gz) are kept.
            stats.note(f"file could not be parsed: {exc}"
                       + (f" (kept {kept} record(s) read before the error)" if kept else ""))
        writer.close()
    except Exception as exc:
        if resources.explain(exc, None) is None:
            raise
        writer.con = None
        return stats, [], [], writer.counts, str(exc) or repr(exc)
    stats.kept = kept
    if alerts:
        stats.note(f"{len(alerts)} IPS/IDS alert(s) used as exploitation evidence")
    return stats, findings, alerts, writer.counts, None
