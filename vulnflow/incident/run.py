"""Process a case: parse each stored file into events, then build the baseline report.

Deterministic and offline: no network use and no model. The same evidence, adapter versions,
ruleset and case scope give the same run key and the same report (apart from its generation time).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone

from .. import db, resources
from ..correlate import DEFAULT_INTERNAL_NETS
from ..schema import ParseStats
from ..sqlfile import Model
from . import ENGINE_VERSION, adapters
from .case import Case, now_iso
from .events import COLUMNS, EPOCH, to_json

RULES_FILE = os.path.join(os.path.dirname(__file__), "incident.sql")
SAMPLE = 3                 # event IDs cited per timeline item (plus the last one)
MIN_PORTS = 20             # many_ports: distinct ports without a completed connection
MIN_HOSTS = 20             # many_hosts: distinct destinations without a completed connection
LISTED = 2000              # entities and untimed events listed in the report
TIMELINE_MAX = 20000       # timeline items kept in the JSON report
CITED_MAX = 5000           # original records copied into the report
REJECTS_LISTED = 1000      # rejected records kept per file (all are counted)
RAW_MAX = 4000             # characters of an original record copied into the report


def ruleset_version() -> str:
    with open(RULES_FILE, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"--\s*ruleset:\s*(\S+)", line)
            if m:
                return m.group(1)
    raise RuntimeError("incident.sql has no ruleset version line")


# ---------------------------------------------------------------- parsing
def parse_evidence(case: Case, rec: dict) -> dict:
    """Parse one stored file (or reuse its cached events). Updates ``rec`` in place and returns
    the parse summary: status, counts, notes, rejected records and the events file, if any."""
    path = case.evidence_path(rec)
    adapter, detected, reason = adapters.pick(path)
    rec["detected_format"] = detected
    if adapter is None:
        rec.update(status="rejected", status_detail=reason, adapter=None, adapter_version=None)
        return {"status": "rejected", "events": 0, "parquet": None, "read": 0, "kept": 0, "dropped": {},
                "notes": [reason], "rejects": [], "rejects_total": 0, "error": ""}
    rec.update(adapter=adapter.name, adapter_version=adapter.version)
    key = f"{rec['sha256']}_{adapter.name}_{adapter.version}"
    folder = case.path("parsed")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    meta_path = os.path.join(folder, key + ".json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    else:
        meta = _parse(path, rec, adapter, detected, os.path.join(folder, key))
        tmp = meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, sort_keys=True)
        os.replace(tmp, meta_path)
    rec["status"] = meta["status"]
    rec["status_detail"] = meta["error"] or (f"{meta['rejects_total']} record(s) could not be read"
                                             if meta["rejects_total"] else "")
    return meta


def _parse(path, rec, adapter, detected, base) -> dict:
    stats = ParseStats(file=rec["original_name"], fmt=detected)
    rejects, total_rejects, events, error = [], 0, 0, ""

    def on_reject(r):
        nonlocal total_rejects
        total_rejects += 1
        if len(rejects) < REJECTS_LISTED:
            rejects.append({"locator": r.locator, "reason": r.reason})
    jsonl = base + ".jsonl"
    with open(jsonl, "w", encoding="utf-8") as fh:
        try:
            for ev in adapter.read(path, rec["evidence_id"], stats, on_reject):
                fh.write(to_json(ev.row()) + "\n")
                events += 1
        except Exception as exc:          # a broken file keeps what was read before the break
            if resources.explain(exc, None) is not None:
                raise
            error = f"reading stopped: {exc}" + (f" (kept {events} event(s) read before it)" if events else "")
    parquet = None
    try:
        if events:
            parquet = base + ".parquet"
            cols = ", ".join(f"'{k}': '{v}'" for k, v in COLUMNS.items())
            con = db.connect()
            try:
                con.execute(f"COPY (SELECT * FROM read_json('{_q(jsonl)}', format = 'newline_delimited', "
                            f"columns = {{{cols}}}, maximum_object_size = 268435456)) "
                            f"TO '{_q(parquet)}' (FORMAT parquet, COMPRESSION zstd)")
            finally:
                con.close()
    finally:
        os.remove(jsonl)
    status = "failed" if error and not events else ("parsed_with_errors" if error or total_rejects else "parsed")
    return {"status": status, "events": events, "parquet": os.path.basename(parquet) if parquet else None,
            "read": stats.read, "kept": stats.kept, "dropped": dict(sorted(stats.dropped.items())),
            "notes": stats.notes, "rejects": rejects, "rejects_total": total_rejects, "error": error}


# ---------------------------------------------------------------- the run
def run_key(case: Case, records: list[dict]) -> str:
    parts = sorted((r["sha256"], r.get("adapter") or "", r.get("adapter_version") or "") for r in records)
    body = {"evidence": parts, "ruleset": ruleset_version(), "engine": ENGINE_VERSION,
            "scope": case.data["scope"], "window": case.data["window"]}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def baselines(case: Case) -> list[tuple[int, str]]:
    """(version, folder) of every baseline report, oldest first."""
    root = case.path("reports")
    out = []
    if os.path.isdir(root):
        for name in os.listdir(root):
            m = re.fullmatch(r"baseline-v(\d+)", name)
            if m and os.path.exists(os.path.join(root, name, "incident_report.json")):
                out.append((int(m.group(1)), os.path.join(root, name)))
    return sorted(out)


def run(case: Case, actor: str, force: bool = False) -> dict:
    """Parse the case's evidence and write a new baseline report version.

    Returns {"version", "folder", "reused", "run_key", "inputs"}. When the evidence, adapters,
    ruleset and scope are unchanged since the last baseline, that baseline is returned instead
    (``reused``), unless ``force``."""
    records = case.evidence()
    case.audit(actor, "run_started", evidence=len(records))
    metas = []
    for rec in records:
        meta = parse_evidence(case, rec)
        metas.append(meta)
    case.save_evidence(records)
    key = run_key(case, records)
    existing = baselines(case)
    if existing and not force:
        version, folder = existing[-1]
        with open(os.path.join(folder, "incident_report.json"), encoding="utf-8") as fh:
            if json.load(fh).get("run_key") == key:
                case.audit(actor, "report_reused", version=version, run_key=key)
                return {"version": version, "folder": folder, "reused": True, "run_key": key,
                        "inputs": _inputs(records, metas)}
    from .report import build, write
    version = (existing[-1][0] if existing else 0) + 1
    report = build(case, records, metas, key, version)
    folder = write(case, report)
    case.audit(actor, "report_generated", version=version, run_key=key,
               report_id=report["report_id"], timeline_items=len(report["timeline"]),
               findings=len(report["findings"]))
    return {"version": version, "folder": folder, "reused": False, "run_key": key,
            "inputs": report["inputs"]}


def _inputs(records, metas) -> list[dict]:
    out = []
    for rec, meta in zip(records, metas):
        out.append({
            "evidence_id": rec["evidence_id"], "original_name": rec["original_name"], "sha256": rec["sha256"],
            "size": rec["size"], "format": rec.get("detected_format") or "unknown",
            "adapter": rec.get("adapter") or "", "adapter_version": rec.get("adapter_version") or "",
            "status": rec["status"], "status_detail": rec.get("status_detail") or "",
            "uploaded_by": rec["uploaded_by"], "uploaded_at": rec["uploaded_at"],
            "duplicate_uploads": len(rec.get("duplicate_uploads") or []),
            "read": meta["read"], "events": meta["events"], "rejected": meta["rejects_total"],
            "dropped": meta["dropped"], "notes": meta["notes"], "rejects": meta["rejects"][:20],
        })
    return out


# ---------------------------------------------------------------- analysis over the events
def analyze(case: Case, records: list[dict], metas: list[dict]) -> dict:
    """Load the parsed events into DuckDB, apply scope and window, and run every rule.
    Returns plain Python rows keyed by query name, plus helpers the report needs."""
    files = [os.path.join(case.path("parsed"), m["parquet"]) for m in metas if m.get("parquet")]
    work = tempfile.mkdtemp(prefix="incident-", dir=case.dir)
    con = db.connect(os.path.join(work, "work.duckdb"))
    try:
        con.execute(f"SET temp_directory = '{_q(os.path.join(work, 'tmp'))}'")
        con.execute("SET threads = 1")      # identical results and order on any machine
        model = Model(RULES_FILE, {"sample": str(SAMPLE), "min_ports": str(MIN_PORTS),
                                   "min_hosts": str(MIN_HOSTS), "listed": str(LISTED)})
        if files:
            listed = ", ".join(f"'{_q(f)}'" for f in sorted(files))
            con.execute(f"CREATE TABLE ev AS SELECT * FROM read_parquet([{listed}])")
        else:
            cols = ", ".join(f"{k} {v}" for k, v in COLUMNS.items())
            con.execute(f"CREATE TABLE ev ({cols})")
        scope_nets = case.data["scope"]["networks"]
        nets = [ipaddress.ip_network(n, strict=False) for n in (scope_nets or DEFAULT_INTERNAL_NETS)]
        ips = [r[0] for r in con.execute(
            "SELECT DISTINCT ip FROM (SELECT src_ip AS ip FROM ev UNION SELECT dst_ip FROM ev) WHERE ip IS NOT NULL").fetchall()]
        con.execute("CREATE TABLE ipnet (ip VARCHAR, inside BOOLEAN)")
        rows = [(ip, _inside(ip, nets)) for ip in sorted(ips)]
        if rows:
            con.executemany("INSERT INTO ipnet VALUES (?, ?)", rows)
        lo, hi = _window(case)
        scoped = "TRUE" if not scope_nets else "(s.inside OR d.inside OR (ev.src_ip IS NULL AND ev.dst_ip IS NULL))"
        window = "TRUE"
        if lo is not None or hi is not None:
            conds = []
            if lo is not None:
                conds.append(f"ev.event_time >= {lo}")
            if hi is not None:
                conds.append(f"ev.event_time <= {hi}")
            window = f"(ev.event_time IS NULL OR ({' AND '.join(conds)}))"
        con.execute(f"""
            CREATE TABLE evs AS
            SELECT ev.*, coalesce({scoped}, FALSE) AS in_scope, coalesce({window}, FALSE) AS in_window,
                   coalesce(s.inside, FALSE) AS src_int, coalesce(d.inside, FALSE) AS dst_int
            FROM ev LEFT JOIN ipnet s ON s.ip = ev.src_ip LEFT JOIN ipnet d ON d.ip = ev.dst_ip""")
        con.execute("ALTER TABLE evs ADD COLUMN kept BOOLEAN")
        con.execute("UPDATE evs SET kept = in_scope AND in_window AND event_time IS NOT NULL")
        out = {}
        for name in model.names():
            if name == "cited":
                continue
            out[name] = con.execute(model(name)).fetchall()
        out["_con"], out["_model"], out["_work"] = con, model, work
        return out
    except Exception:
        con.close()
        shutil.rmtree(work, ignore_errors=True)
        raise


def cited_locations(res: dict, event_ids: list[str]) -> list[tuple]:
    con, model = res["_con"], res["_model"]
    con.execute("CREATE OR REPLACE TABLE cited (event_id VARCHAR)")
    if event_ids:
        con.executemany("INSERT INTO cited VALUES (?)", [(e,) for e in event_ids])
    return con.execute(model("cited")).fetchall()


def close(res: dict) -> None:
    try:
        res["_con"].close()
    finally:
        shutil.rmtree(res["_work"], ignore_errors=True)


def _inside(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _window(case: Case) -> tuple[int | None, int | None]:
    w = case.data["window"]
    margin = timedelta(minutes=w.get("margin_minutes") or 0)

    def us(s, sign):
        if not s:
            return None
        dt = datetime.fromisoformat(s.replace("Z", "+00:00")) + sign * margin
        d = dt - EPOCH
        return (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds
    return us(w.get("start"), -1), us(w.get("end"), 1)


def iso_us(us: int | None) -> str | None:
    if us is None:
        return None
    return (EPOCH + timedelta(microseconds=int(us))).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _q(s: str) -> str:
    return str(s).replace("'", "''")


__all__ = ["run", "parse_evidence", "analyze", "baselines", "ruleset_version", "iso_us", "now_iso"]
