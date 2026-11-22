"""The baseline incident report: built from the rules' rows, checked against its schema, written as
JSON (the contract), Markdown and HTML. No model is involved.

Every timeline item and finding cites event IDs. The report carries a copy of each cited original
record with its file, SHA-256 and locator, so a reader can check a statement without the tool.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
from collections import defaultdict

from ..parsers._util import open_text
from ..parsers.zeek import _json_array
from ..report import CSS, HTML_OPEN, THEME_INIT, theme_control
from . import ENGINE_VERSION, adapters
from .case import Case, now_iso
from .report_schema import REPORT_SCHEMA_VERSION, problems
from .run import (CITED_MAX, RAW_MAX, TIMELINE_MAX, _inputs, analyze, cited_locations, close, iso_us,
                  ruleset_version)

READING_NOTES = [
    "Every statement cites event IDs; the evidence section holds each cited original record with its file, SHA-256 and position.",
    "'Observed' items restate what records say. 'Inferred' items connect records that share no identifier; they are leads to check, not facts.",
    "A completed connection means packets went both ways. It does not show that a login or request succeeded.",
    "Counts are exact for the events kept after the case scope and window. Timeline items group records; open the cited events to see them.",
]


def build(case: Case, records: list[dict], metas: list[dict], run_key: str, version: int) -> dict:
    res = analyze(case, records, metas)
    try:
        return _build(case, records, metas, run_key, version, res)
    finally:
        close(res)


def _build(case, records, metas, run_key, version, res) -> dict:
    total, out_scope, outside, untimed_n, kept = res["filtered_counts"][0]
    timeline, findings = [], []

    for (src, dst, port, proto, first, last, n, done, refused, tried, ids, last_id, s_int, d_int) in res["connection_groups"]:
        where = f"{dst}:{port}/{proto}" if port is not None else f"{dst} ({proto or 'no port'})"
        parts = [f"{done} completed"] + ([f"{refused} refused"] if refused else []) + ([f"{tried} without a reply"] if tried else [])
        timeline.append(_item("connection", first, last, "network", "connection",
                              f"{src} connected to {where} {_times(n)}: {', '.join(parts)}",
                              [src, dst], _ids(ids, last_id), n))
    for (action, src, dst, subject, first, last, n, linked, ids, last_id) in res["application_groups"]:
        about = f" ({subject})" if subject else ""
        link = f"; {linked} tied to a connection record by Zeek uid" if linked else ""
        who = f"{src or 'unknown'} to {dst or 'unknown'}"
        timeline.append(_item(action, first, last, "network", action,
                              f"{_label(action)} {who}{about}, {_times(n)}{link}",
                              [x for x in (src, dst) if x], _ids(ids, last_id), n))
    detections = defaultdict(list)
    for (eid, t, action, name, src, dst, port, msg) in res["detections"]:
        text = f"Sensor detection {name or action}" + (f": {msg}" if msg else "") + \
               (f" ({src} to {dst}" + (f":{port}" if port is not None else "") + ")" if src or dst else "")
        timeline.append(_item("detection", t, t, "detection", action, text, [x for x in (src, dst) if x], [eid], 1))
        detections[name or action].append((eid, t, src, dst))
    timeline.sort(key=lambda i: (i["time"], i["item_id"]))
    timeline_total = len(timeline)
    timeline = timeline[:TIMELINE_MAX]

    for (src, dst, ports, ports_done, n, first, last, ids) in res["many_ports"]:
        findings.append(_finding(
            "INC-NET-001", "Connection attempts to many ports", "observed", "same records",
            f"{src} tried {ports} ports on {dst} in {_times(n)} between {iso_us(first)} and {iso_us(last)}; "
            f"connections completed on {ports_done} of them.", [src, dst], list(ids), n))
    for (src, port, proto, hosts, hosts_done, n, first, last, ids) in res["many_hosts"]:
        findings.append(_finding(
            "INC-NET-002", "Connection attempts to many hosts on one port", "observed", "same records",
            f"{src} tried {port}/{proto} on {hosts} hosts between {iso_us(first)} and {iso_us(last)}; "
            f"connections completed to {hosts_done} of them.", [src], list(ids), n))
    for (host, peer, t1, e1, t2, e2, n, ports) in res["return_after_inbound"]:
        mins = (t2 - t1) / 60_000_000
        findings.append(_finding(
            "INC-NET-003", "Outbound connection to an address that connected in first", "inferred", "time_proximity",
            f"{peer} completed a connection to {host} at {iso_us(t1)}; {host} later completed "
            f"{_times(n)} to {peer} (ports {', '.join(str(p) for p in ports if p is not None) or 'none'}), "
            f"the first {mins:.1f} minutes after. Only the addresses and the order in time link them; "
            "this can be ordinary traffic.", [host, peer], [e1, e2], n + 1))
    for name, rows in sorted(detections.items()):
        hosts = sorted({x for _, _, s, d in rows for x in (s, d) if x})
        findings.append(_finding(
            "INC-DET-001", f"Sensor detection: {name}", "observed", "same records",
            f"The sensor recorded '{name}' {_times(len(rows))}"
            + (f", involving {', '.join(hosts[:10])}" + (" and others" if len(hosts) > 10 else "") if hosts else "")
            + ". A detection is a lead, not proof of compromise.",
            hosts[:20], [r[0] for r in rows[:5]], len(rows)))

    by_action: dict[str, int] = {}
    examples: list[dict] = []
    for action, eid, conn_id, uid in res["uid_links"]:
        by_action[action] = by_action.get(action, 0) + 1
        if len(examples) < 200:
            examples.append({"from": eid, "to": conn_id, "basis": "same_id", "identifier": "zeek_uid",
                             "value": uid, "relation": f"{_label(action)} record of this connection"})
    links = {"same_id_total": len(res["uid_links"]), "by_action": by_action, "examples": examples}

    inputs = _inputs(records, metas)
    gaps = _gaps(case, inputs, res, untimed_n, timeline_total)
    cited = sorted({e for i in timeline for e in i["evidence"]} | {e for f in findings for e in f["evidence"]}
                   | {lk["from"] for lk in examples} | {lk["to"] for lk in examples})
    evidence_records, cited_cut = _originals(case, records, res, cited)
    if cited_cut:
        gaps.append({"type": "evidence_copies_cut", "text": f"Original records were copied for the first {CITED_MAX} "
                     f"of {len(cited)} cited events; use 'vulnflow incident record' for the rest."})
    by_cat, by_out = defaultdict(int), defaultdict(int)
    by_source = []
    for provider, stype, cat, outcome, n in res["counts_by_source"]:
        by_cat[cat] += n
        by_out[outcome] += n
        by_source.append({"provider": provider, "source_type": stype, "category": cat, "outcome": outcome, "events": n})
    entities = [{"type": "ip", "value": ip, "first_seen": iso_us(a), "last_seen": iso_us(b), "events": n,
                 "as_source": s, "as_destination": d, "inside": bool(inside)}
                for ip, a, b, n, s, d, inside in res["entities"]]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION, "kind": "baseline",
        "report_id": f"{case.case_id}-baseline-v{version}", "version": version, "run_key": run_key,
        "generated": now_iso(), "engine_version": ENGINE_VERSION, "ruleset_version": ruleset_version(),
        "adapters": adapters.versions(),
        "case": {"case_id": case.case_id, "name": case.data["name"], "entities": case.data["entities"],
                 "notes": case.data["notes"]},
        "scope": {"networks": case.data["scope"]["networks"], "hosts": case.data["scope"]["hosts"],
                  "accounts": case.data["scope"]["accounts"], "window": case.data["window"],
                  "filtered": {"events_total": total, "out_of_scope": out_scope, "outside_window": outside,
                               "untimed": untimed_n, "kept": kept}},
        "inputs": inputs,
        "counts": {"events_kept": kept, "by_category": dict(sorted(by_cat.items())),
                   "by_outcome": dict(sorted(by_out.items())), "by_source": by_source,
                   "timeline_items": timeline_total, "findings": len(findings),
                   "entities": res["entity_count"][0][0]},
        "timeline": timeline, "findings": findings, "entities": entities, "links": links,
        "untimed": {"count": untimed_n, "examples": [{"event_id": e, "evidence_id": ev, "locator": loc, "source_type": st}
                                                    for e, ev, loc, st in res["untimed"]]},
        "gaps": gaps, "reading_notes": READING_NOTES, "evidence_records": evidence_records,
    }
    found = problems(report)
    if found:
        raise RuntimeError("incident report does not fit its schema: " + "; ".join(found))
    return report


def _item(kind, first, last, category, action, summary, entities, evidence, count) -> dict:
    t = iso_us(first)
    return {"item_id": _hid(kind, t, summary), "time": t, "last_time": iso_us(last), "kind": "observed",
            "category": category, "action": action, "summary": summary, "entities": sorted(set(entities)),
            "evidence": evidence, "evidence_count": count}


def _finding(rule, title, kind, basis, statement, entities, evidence, count) -> dict:
    return {"finding_id": _hid(rule, statement), "rule_id": rule, "title": title, "kind": kind, "basis": basis,
            "statement": statement, "entities": sorted(set(entities)), "evidence": list(evidence),
            "evidence_count": count}


def _hid(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _ids(first_ids, last_id) -> list[str]:
    ids = list(first_ids)
    if last_id and last_id not in ids:
        ids.append(last_id)
    return ids


def _times(n: int) -> str:
    return "once" if n == 1 else f"{n} times"


def _label(action: str) -> str:
    return {"dns_query": "DNS lookup", "http_request": "HTTP request", "tls_session": "TLS session",
            "file_transfer": "File transfer", "ssh_session": "SSH session", "rdp_session": "RDP session",
            "smb_file": "SMB file access", "smb_share": "SMB share access", "kerberos_request": "Kerberos request",
            "ntlm_auth": "NTLM exchange", "dce_rpc_call": "DCE/RPC call", "certificate": "Certificate",
            "protocol_anomaly": "Protocol anomaly", "dhcp_lease": "DHCP lease", "smtp_message": "SMTP message",
            "ftp_command": "FTP command"}.get(action, action.replace("_", " ").capitalize() + " record")


def _gaps(case, inputs, res, untimed_n, timeline_total) -> list[dict]:
    gaps: list[dict] = []
    cats = {row[2] for row in res["counts_by_source"]}
    if not cats & {"authentication", "process", "account", "service"}:
        gaps.append({"type": "missing_source", "text": "No host logs (Windows event logs, Linux auth or audit logs) "
                     "are in this case. Logons, processes and account changes are unknown, not absent."})
    gaps.append({"type": "missing_source", "text": "No vulnerability scan is used by incident cases yet; "
                 "vulnerability status of the hosts is unknown."})
    if not cats & {"control_plane"}:
        gaps.append({"type": "missing_source", "text": "No cloud audit logs (CloudTrail, Azure Activity Log) are in this case."})
    for i in inputs:
        if i["status"] in ("rejected", "failed"):
            gaps.append({"type": "file_not_used", "evidence_id": i["evidence_id"],
                         "text": f"{i['original_name']} was not used: {(i['status_detail'] or i['status']).rstrip('.')}."})
        elif i["rejected"]:
            where = ", ".join(r["locator"] for r in i["rejects"][:5])
            gaps.append({"type": "unreadable_records", "evidence_id": i["evidence_id"],
                         "text": f"{i['original_name']}: {i['rejected']} record(s) could not be read (first at {where})."})
        if i["status"] == "parsed_with_errors" and i["status_detail"].startswith("reading stopped"):
            gaps.append({"type": "file_cut_short", "evidence_id": i["evidence_id"],
                         "text": f"{i['original_name']}: {i['status_detail'].rstrip('.')}."})
    for evid, basis, n in res["time_basis_counts"]:
        if basis == "assumed_utc":
            gaps.append({"type": "time_assumed_utc", "evidence_id": evid,
                         "text": f"{n} event time(s) from {_name(inputs, evid)} carry no time zone and were read as UTC."})
    if untimed_n:
        gaps.append({"type": "untimed", "text": f"{untimed_n} in-scope event(s) have no readable time; they are listed "
                     "apart and are not on the timeline."})
    w = case.data["window"]
    spans = res["evidence_spans"]
    if spans and (w.get("start") or w.get("end")):
        first = iso_us(min(s[1] for s in spans))
        last = iso_us(max(s[2] for s in spans))
        if w.get("start") and first > w["start"]:
            gaps.append({"type": "window_coverage", "text": f"The evidence starts at {first}, after the case window "
                         f"starts ({w['start']}). Nothing is known before then."})
        if w.get("end") and last < w["end"]:
            gaps.append({"type": "window_coverage", "text": f"The evidence ends at {last}, before the case window "
                         f"ends ({w['end']}). Nothing is known after then."})
    for eid, t, msg in res["capture_loss"]:
        gaps.append({"type": "capture_loss", "evidence": [eid],
                     "text": f"The sensor reported dropped packets at {iso_us(t) or 'an unknown time'}: {msg}. "
                             "Some sessions may be missing or incomplete."})
    if timeline_total > TIMELINE_MAX:
        gaps.append({"type": "timeline_cut", "text": f"The timeline holds the first {TIMELINE_MAX} of {timeline_total} items."})
    sc = case.data["scope"]
    if sc["hosts"] or sc["accounts"]:
        gaps.append({"type": "scope_not_applied", "text": "Host names and accounts in the case scope are recorded "
                     "but not yet used to filter network events; only address ranges and the window are."})
    return gaps


def _name(inputs, evid) -> str:
    return next((i["original_name"] for i in inputs if i["evidence_id"] == evid), evid)


def _originals(case, records, res, cited) -> tuple[list[dict], bool]:
    """Copy the cited original records out of the stored files, one pass per file."""
    cut = len(cited) > CITED_MAX
    rows = cited_locations(res, cited[:CITED_MAX])
    by_file = defaultdict(dict)
    for eid, evid, loc in rows:
        by_file[evid][loc] = eid
    recs = {r["evidence_id"]: r for r in records}
    out = []
    for evid in sorted(by_file):
        rec = recs[evid]
        raw = read_records(case.evidence_path(rec), set(by_file[evid]))
        for loc, eid in sorted(by_file[evid].items(), key=lambda kv: _loc_key(kv[0])):
            text = raw.get(loc)
            out.append({"event_id": eid, "evidence_id": evid, "file": rec["original_name"], "sha256": rec["sha256"],
                        "locator": loc, "original": (text or "")[:RAW_MAX],
                        "truncated": bool(text and len(text) > RAW_MAX), "found": text is not None})
    out.sort(key=lambda r: r["event_id"])
    return out, cut


def _loc_key(loc: str):
    kind, _, n = loc.partition(":")
    return (kind, int(n) if n.isdigit() else 0)


def read_records(path: str, locators: set[str]) -> dict[str, str]:
    """The original text of records at ``line:N`` / ``item:N`` locators (decompressed for .gz)."""
    want_lines = {int(l.split(":")[1]) for l in locators if l.startswith("line:")}
    want_items = {int(l.split(":")[1]) for l in locators if l.startswith("item:")}
    out = {}
    if want_lines:
        top = max(want_lines)
        with open_text(path) as fh:
            for n, line in enumerate(fh, 1):
                if n in want_lines:
                    out[f"line:{n}"] = line.rstrip("\r\n")
                if n >= top:
                    break
    if want_items:
        top = max(want_items)
        with open_text(path) as fh:
            for n, obj in enumerate(_json_array(fh), 1):
                if n in want_items:
                    out[f"item:{n}"] = json.dumps(obj, ensure_ascii=False, sort_keys=True)
                if n >= top:
                    break
    return out


# ---------------------------------------------------------------- writing
def write(case: Case, report: dict) -> str:
    folder = case.path("reports", f"baseline-v{report['version']}")
    os.makedirs(folder, mode=0o700, exist_ok=False)
    with open(os.path.join(folder, "incident_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    with open(os.path.join(folder, "incident_report.md"), "w", encoding="utf-8") as fh:
        fh.write(markdown(report))
    with open(os.path.join(folder, "incident_report.html"), "w", encoding="utf-8") as fh:
        fh.write(page(report))
    return folder


MD_TIMELINE = 500


def _cell(v) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def markdown(r: dict) -> str:
    c, s = r["case"], r["scope"]
    w = s["window"]
    L = [f"# Incident baseline: {c['name']}", "",
         f"Version {r['version']} · generated {r['generated']} · engine {r['engine_version']} · "
         f"ruleset {r['ruleset_version']} · run key `{r['run_key'][:16]}`", "",
         "Built from the evidence alone, with fixed rules and no AI model.", "", "## How to read this report", ""]
    L += [f"- {n}" for n in r["reading_notes"]]
    L += ["", "## Scope", "",
          f"- Networks: {', '.join(s['networks']) or 'not set (private ranges count as inside)'}",
          f"- Window: {w.get('start') or 'open'} to {w.get('end') or 'open'} (margin {w.get('margin_minutes', 0)} min)",
          f"- Events read: {s['filtered']['events_total']}; outside the scope: {s['filtered']['out_of_scope']}; "
          f"outside the window: {s['filtered']['outside_window']}; without a time: {s['filtered']['untimed']}; "
          f"kept: {s['filtered']['kept']}"]
    if c["entities"]:
        L.append(f"- Known entities: {', '.join(c['entities'])}")
    if c["notes"]:
        L.append(f"- Notes: {c['notes']}")
    L += ["", "## Evidence files", "", "| File | SHA-256 | Format | Status | Records read | Events | Unreadable |",
          "|---|---|---|---|---|---|---|"]
    for i in r["inputs"]:
        status = i["status"] + (f": {i['status_detail']}" if i["status_detail"] else "")
        L.append(f"| {_cell(i['original_name'])} | `{i['sha256'][:16]}` | {_cell(i['format'])} | {_cell(status)} | "
                 f"{i['read']} | {i['events']} | {i['rejected']} |")
    L += ["", "## Findings", ""]
    if not r["findings"]:
        L.append("No rule in this ruleset matched.")
    for f in r["findings"]:
        L += [f"### {f['title']} ({f['rule_id']}, {f['kind']}, basis: {f['basis']})", "", f["statement"], "",
              "Evidence: " + ", ".join(f"`{e}`" for e in f["evidence"])
              + (f" (of {f['evidence_count']} records)" if f["evidence_count"] > len(f["evidence"]) else ""), ""]
    L += ["## Gaps and uncertainty", ""] + [f"- {g['text']}" for g in r["gaps"]]
    L += ["", "## Timeline", "", "| Time (UTC) | Until | What | Evidence |", "|---|---|---|---|"]
    for i in r["timeline"][:MD_TIMELINE]:
        L.append(f"| {i['time']} | {i['last_time'] if i['last_time'] != i['time'] else ''} | {_cell(i['summary'])} | "
                 + " ".join(f"`{e}`" for e in i["evidence"]) + " |")
    if len(r["timeline"]) > MD_TIMELINE:
        L += ["", f"The first {MD_TIMELINE} of {r['counts']['timeline_items']} items; incident_report.json has the rest."]
    if r["untimed"]["count"]:
        L += ["", f"{r['untimed']['count']} event(s) have no readable time and are not placed on the timeline."]
    L += ["", "## Addresses", "", "| Address | Inside | First seen | Last seen | Events |", "|---|---|---|---|---|"]
    for e in r["entities"][:100]:
        L.append(f"| {e['value']} | {'yes' if e['inside'] else 'no'} | {e['first_seen']} | {e['last_seen']} | {e['events']} |")
    L += ["", "## Direct links", "",
          f"{r['links']['same_id_total']} record(s) are tied to a connection record by the same Zeek uid."]
    L += ["", "## Evidence records", "", "Each cited event: file, position in the file, and the original record.", ""]
    for e in r["evidence_records"][:MD_TIMELINE * 2]:
        L += [f"- `{e['event_id']}` {e['file']} {e['locator']} (sha256 `{e['sha256'][:16]}`)", "",
              "```", e["original"] if e["found"] else "(record not found at this position)", "```", ""]
    return "\n".join(L) + "\n"


PAGE_CSS = """
.ev{font-family:ui-monospace,Consolas,monospace;font-size:.82em;white-space:nowrap}
.kind{display:inline-block;padding:1px 6px;border-radius:8px;font-size:.78em;border:1px solid currentColor}
.inferred{opacity:.85;font-style:italic}
pre.orig{white-space:pre-wrap;word-break:break-all;font-size:.8em;max-height:12em;overflow:auto}
.evrec:target{outline:2px solid currentColor;outline-offset:4px}
table.tl td:first-child{white-space:nowrap}
"""


def _evlinks(ids) -> str:
    return " ".join(f'<a class="ev" href="#ev-{html.escape(e)}">{html.escape(e[:8])}</a>' for e in ids)


def page(r: dict) -> str:
    e = html.escape
    c, s = r["case"], r["scope"]
    w = s["window"]
    out = [f"<h1>Incident baseline: {e(c['name'])}</h1>",
           f"<p>Version {r['version']} · generated {e(r['generated'])} · engine {e(r['engine_version'])} · ruleset "
           f"{e(r['ruleset_version'])} · run key <code>{e(r['run_key'][:16])}</code></p>",
           "<p>Built from the evidence alone, with fixed rules and no AI model. Event links jump to the original record.</p>",
           "<h2>How to read this report</h2><ul>" + "".join(f"<li>{e(n)}</li>" for n in r["reading_notes"]) + "</ul>",
           "<h2>Scope</h2><ul>",
           f"<li>Networks: {e(', '.join(s['networks']) or 'not set (private ranges count as inside)')}</li>",
           f"<li>Window: {e(w.get('start') or 'open')} to {e(w.get('end') or 'open')} (margin {w.get('margin_minutes', 0)} min)</li>",
           f"<li>Events read {s['filtered']['events_total']}, outside the scope {s['filtered']['out_of_scope']}, outside the "
           f"window {s['filtered']['outside_window']}, without a time {s['filtered']['untimed']}, kept {s['filtered']['kept']}</li>"]
    if c["entities"]:
        out.append(f"<li>Known entities: {e(', '.join(c['entities']))}</li>")
    if c["notes"]:
        out.append(f"<li>Notes: {e(c['notes'])}</li>")
    out.append("</ul><h2>Evidence files</h2><table><tr><th>File</th><th>SHA-256</th><th>Format</th><th>Status</th>"
               "<th>Records read</th><th>Events</th><th>Unreadable</th></tr>")
    for i in r["inputs"]:
        status = i["status"] + (f": {i['status_detail']}" if i["status_detail"] else "")
        out.append(f"<tr><td>{e(i['original_name'])}</td><td><code>{e(i['sha256'][:16])}</code></td><td>{e(i['format'])}</td>"
                   f"<td>{e(status)}</td><td>{i['read']}</td><td>{i['events']}</td><td>{i['rejected']}</td></tr>")
    out.append("</table><h2>Findings</h2>")
    if not r["findings"]:
        out.append("<p>No rule in this ruleset matched.</p>")
    for f in r["findings"]:
        cls = ' class="inferred"' if f["kind"] == "inferred" else ""
        more = f" (of {f['evidence_count']} records)" if f["evidence_count"] > len(f["evidence"]) else ""
        out.append(f"<h3>{e(f['title'])}</h3><p><span class=\"kind\">{e(f['kind'])}</span> "
                   f"<span class=\"kind\">basis: {e(f['basis'])}</span> <code>{e(f['rule_id'])}</code></p>"
                   f"<p{cls}>{e(f['statement'])}</p><p>Evidence: {_evlinks(f['evidence'])}{more}</p>")
    out.append("<h2>Gaps and uncertainty</h2><ul>" + "".join(f"<li>{e(g['text'])}</li>" for g in r["gaps"]) + "</ul>")
    out.append("<h2>Timeline</h2><table class=\"tl\"><tr><th>Time (UTC)</th><th>What</th><th>Evidence</th></tr>")
    for i in r["timeline"]:
        until = f"<br><small>until {e(i['last_time'])}</small>" if i["last_time"] != i["time"] else ""
        out.append(f"<tr><td>{e(i['time'])}{until}</td><td>{e(i['summary'])}</td><td>{_evlinks(i['evidence'])}</td></tr>")
    out.append("</table>")
    if r["untimed"]["count"]:
        out.append(f"<p>{r['untimed']['count']} event(s) have no readable time and are not placed on the timeline.</p>")
    out.append("<h2>Addresses</h2><table><tr><th>Address</th><th>Inside</th><th>First seen</th><th>Last seen</th><th>Events</th></tr>")
    for en in r["entities"][:500]:
        out.append(f"<tr><td>{e(en['value'])}</td><td>{'yes' if en['inside'] else 'no'}</td><td>{e(en['first_seen'] or '')}</td>"
                   f"<td>{e(en['last_seen'] or '')}</td><td>{en['events']}</td></tr>")
    out.append("</table>")
    out.append(f"<h2>Direct links</h2><p>{r['links']['same_id_total']} record(s) are tied to a connection record by the same Zeek uid.</p>")
    out.append("<h2>Evidence records</h2>")
    for ev in r["evidence_records"]:
        body = e(ev["original"]) if ev["found"] else "(record not found at this position)"
        out.append(f"<div class=\"evrec\" id=\"ev-{e(ev['event_id'])}\"><p><code>{e(ev['event_id'])}</code> · "
                   f"{e(ev['file'])} · {e(ev['locator'])} · sha256 <code>{e(ev['sha256'][:16])}</code></p>"
                   f"<pre class=\"orig\">{body}</pre></div>")
    return (f"{HTML_OPEN}<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>Incident baseline · {e(c['name'])}</title>{THEME_INIT}<style>{CSS}{PAGE_CSS}</style></head><body>"
            + theme_control() + "\n".join(out) + "</body></html>\n")


__all__ = ["build", "write", "markdown", "page", "read_records"]
