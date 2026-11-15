"""Data and page for the host explorer: a logical graph of scanned or observed hosts.

Click a host and the view flies in on it. On the left is all of its north/south traffic: every outside
address that reached, tried to reach, or was contacted by it (with firewall and IPS outcome). On the
right is all of its east/west traffic: every internal host it exchanged traffic with in either direction,
including failed attempts, with an estimate of how likely each one is to be compromised next if this
host is exploited.

The estimate is a heuristic built only from observed traffic and scan results (see `_reach`). It ranks
where to look; it is not a probability of compromise and it never confirms one.
"""
from __future__ import annotations

import base64
import io
import ipaddress
import json
import math
import os
import re
import zlib
from collections import Counter, defaultdict
from datetime import datetime

from .correlate import LATERAL_PORTS, Config, _Net
from .store import naive, utc

STATIC = os.path.join(os.path.dirname(__file__), "static")
MAX_HOP2, MAX_NODES = 30, 2000
MAX_SUBNET_LINKS, MAX_RISKY_LINKS, MAX_INTERNET, MAX_INTERNET_TARGETS = 600, 200, 80, 12
MAX_CONNECTION_EXAMPLES, MAX_OT_EVENTS_PER_HOST = 6, 40
# A host's card keeps its first MAX_LIST outside addresses and MAX_LIST internal peers (in the card's
# own order); outside addresses with an IPS alert that was not blocked are kept even past that, up to
# MAX_LIST_ALERTS. (Hits on vulnerable services are not: an exposed server can be reached by thousands
# of internet scanners. They rank right after alerts, so they fill the list first.) Counts, the internet panel, Attack paths and the overview are worked out from the full
# lists first, so they stay exact. When a list is cut, only its first MAX_LIST_EXAMPLES rows keep their
# connection examples. The full lists go to normalized/explorer_contacts.parquet (with the flow copies),
# which the upload server hands to the page, one host at a time, when the report is opened through it.
MAX_LIST, MAX_LIST_EXAMPLES, MAX_LIST_ALERTS = 200, 20, 1000
# Timeline view: individual flows drawn at their timestamps. Large runs keep flagged flows (to/from an
# alert or IOC address, then blocked) up to half the cap, sampled over the whole run, and fill the rest
# with a fixed random sample (see _timeline).
MAX_TIMELINE_FLOWS, MAX_TIMELINE_ALERTS, MAX_TIMELINE_IOC_LOOKUPS = 20_000, 200, 400
SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEV = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _band(p: float) -> str:
    return "High" if p >= 0.6 else "Medium" if p >= 0.35 else "Low"


def _subnet(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 64}", strict=False))


class _Pair:
    __slots__ = ("sessions", "established", "blocked", "ports", "tried", "bytes", "first", "last",
                 "first_est", "last_est", "examples")

    def __init__(self):
        self.sessions = self.established = self.blocked = self.bytes = 0
        self.ports: set = set()       # ports with completed sessions
        self.tried: set = set()       # every port seen, including blocked attempts
        self.first = self.last = None
        self.first_est = self.last_est = None     # completed sessions only
        self.examples: list[dict] = []


def _pair(row) -> _Pair:
    """A _Pair from a PAIR_STATS row (store.py); None when the row is empty (no traffic that way)."""
    n, est, blocked, tried, ports, nbytes, first, last, first_est, last_est = row
    if n is None:
        return None
    p = _Pair()
    p.sessions, p.established, p.blocked, p.bytes = int(n), int(est), int(blocked), int(nbytes)
    p.tried, p.ports = set(tried or ()), set(ports or ())
    p.first, p.last = utc(first), utc(last)
    p.first_est, p.last_est = utc(first_est), utc(last_est)
    return p


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def _parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _vuln_services(res: dict) -> dict[str, list[tuple]]:
    """host -> [(port, proto, window start, window end)] for each port-level finding.

    The window is the scan window the correlator used for that finding (None = all telemetry), so
    the explorer marks the same traffic as "reached a vulnerable service" that the report counts."""
    out = defaultdict(list)
    for r in res["findings"]:
        if not r.get("port"):
            continue
        exp = r.get("exposure") or {}
        for w in exp.get("windows") or [exp.get("window") or {}]:
            out[r["host"]].append((r["port"], r.get("proto") or "tcp", _parse_iso(w.get("start")), _parse_iso(w.get("end"))))
    return out


def _hits_service(services, port, proto, ts) -> bool:
    return any(port == p and proto == pr and (lo is None or ts is None or lo <= ts <= hi)
               for p, pr, lo, hi in services)


def _returned(inbound, outbound) -> bool:
    """The host connected back out to an outside address after that address reached it, the same
    ordering the report uses for return-connection leads (untimed sessions are not ruled out)."""
    if not (inbound and inbound.established and outbound and outbound.established):
        return False
    return inbound.first_est is None or outbound.last_est is None or outbound.last_est >= inbound.first_est


def _vuln_hits(ds, services: dict, scanners=()) -> dict[tuple, set]:
    """(source, host) -> {(port, proto)}: completed sessions onto a vulnerable service, matched on
    port, protocol and the finding's scan window exactly as the report does. Probes from the
    vulnerability scanner itself are not counted, as in the report."""
    rows = [(h, p, pr, naive(lo), naive(hi)) for h, svcs in services.items() for p, pr, lo, hi in svcs]
    hits = defaultdict(set)
    for src, dst, port, proto in ds.flow_store().vuln_hits(rows, scanners):
        hits[(src, dst)].add((port, proto))
    return hits


def _ms(iso) -> float | None:
    try:
        return _parse_iso(iso).timestamp() * 1000 if iso else None
    except (TypeError, ValueError):
        return None


def _attack_bins(window, rows) -> list:
    """The Attack paths view's timeline bars for one host, from all of its outside addresses:
    [[bar, vuln, blocked, outbound]], with the bars attackpaths.js renderTimeline draws."""
    t0, t1 = (_ms(w) for w in (window or [None, None])[:2])
    if t0 is None or t1 is None or not t1 > t0:
        return []
    width = max(3600e3, math.ceil((t1 - t0) / 56 / 3600e3) * 3600e3)
    nb = math.ceil((t1 - t0) / width)
    bins: dict[int, list] = {}
    for a in rows:
        col = {"vuln": 1, "blocked": 2, "outbound": 3}.get(a["kind"])
        t = _ms(a["first"]) if col else None
        if t is None:
            continue
        i = math.floor((t - t0) / width)
        if 0 <= i < nb:
            bins.setdefault(i, [i, 0, 0, 0])[col] += 1
    return [bins[i] for i in sorted(bins)]


def _cut(rows: list, cap: int | None, keep=lambda r: False) -> list:
    """The first ``cap`` rows, plus any later row ``keep`` says must stay (in order)."""
    if cap is None or len(rows) <= cap:
        return rows
    return rows[:cap] + [r for r in rows[cap:] if keep(r)]


def build(res: dict, ds, cfg: Config | None = None, cap: int | None = MAX_LIST,
          contacts_path: str | None = None) -> dict:
    """The Explorer data for a run. ``cap``: rows kept in each host's lists (None keeps every row).
    ``contacts_path``: also write every host's full lists there (Parquet), for the upload server."""
    cfg = cfg or Config(internal_nets=res["config"]["internal_nets"])
    net = _Net(cfg.internal_nets)
    telemetry_only = not res["summary"].get("vulnerability_data_available", True)
    store = ds.flow_store()
    scanned = [h["host"] for h in res["hosts"]]

    def ext(ip):
        try:
            return not net.internal(ip)
        except ValueError:
            return False

    store.explorer_tables(ext, scanned)
    # Pairs between internal hosts (and hosts with a card) are held here; a host's contacts with
    # outside addresses stream from DuckDB one host at a time below.
    pairs = {}
    out_of, in_to = defaultdict(set), defaultdict(set)
    for s, d, *row in store.inner_pairs():
        pairs[(s, d)] = _pair(row)
        out_of[s].add(d)
        in_to[d].add(s)

    findings = defaultdict(list)
    for r in res["findings"]:
        findings[r["host"]].append(r)
    services = _vuln_services(res)
    scanners = set(res["summary"].get("scanner_ips") or ())
    vhits = _vuln_hits(ds, services, scanners)
    hostinfo = {h["host"]: h for h in res["hosts"]}
    alerts = defaultdict(lambda: defaultdict(list))
    for t in ds.threats:
        alerts[t.dst_ip][t.src_ip].append(t)
        if net.internal(t.src_ip) and not net.internal(t.dst_ip):
            alerts[t.src_ip][t.dst_ip].append(t)     # internal host set off an alert going out (e.g. a beacon)
    ot_by_host = defaultdict(list)
    ot_counts = defaultdict(int)
    for event in ds.ot_events:
        row = {"ts": _iso(event.ts), "src_ip": event.src_ip, "dst_ip": event.dst_ip,
               "originator": event.fields.get("id.orig_h"), "responder": event.fields.get("id.resp_h"),
               "protocol": event.protocol, "operation": event.operation,
               "message_side": event.direction, "source": event.source}
        for host in {event.src_ip, event.dst_ip, row["originator"], row["responder"]} - {None, ""}:
            ot_counts[host] += 1
            if len(ot_by_host[host]) < MAX_OT_EVENTS_PER_HOST:
                ot_by_host[host].append(row)

    # Addresses that were only probed and never answered are not hosts: they are counted per host
    # ("probed, no answer") instead of being drawn as peers.
    answering = store.answering_ips()
    broadcast = store.broadcast_ips() - answering
    traffic_scanners = {e["ip"]: e for e in res["summary"].get("traffic_scanners") or ()}
    reached: dict[tuple, dict] = {}

    def reach(a: str, b: str) -> dict:
        """How easily someone in control of `a` could compromise `b`, from what was observed
        (it depends only on the two hosts, so each pair is worked out once)."""
        got = reached.get((a, b))
        if got is None:
            got = reached[(a, b)] = _reach(a, b)
        return got

    def _reach(a: str, b: str) -> dict:
        fwd, back = pairs.get((a, b)), pairs.get((b, a))
        if telemetry_only:
            return {"p": 0.0, "why": ["Vulnerability status unknown; observed connections do not establish compromise likelihood."]}
        why = []
        if fwd and fwd.established:
            r = 1.0
            why.append(f"{a} opened {fwd.established} session(s) to it on "
                       + ", ".join(str(p) for p in sorted(fwd.ports)[:6]))
        elif back and back.established:
            r = 0.35
            why.append(f"only {b} connects to {a}; an attacker would have to wait for or ride those sessions")
        else:
            return {"p": 0.0, "why": ["no completed sessions between them"]}
        used = fwd.ports if fwd else set()
        hit = vhits.get((a, b), set())        # port, protocol and scan window all match
        best, v = None, 0.1
        for fd in findings.get(b, []):
            cv = (fd["cvss"] or 0) / 10
            if fd["port"] and (fd["port"], fd["proto"]) in hit:
                s = cv * (1.0 if fd["exploit_available"] else 0.55)
                tag = f"vulnerable service {fd['port']}/{fd['proto']} is the one {a} already reaches"
            elif fd["severity"] >= 3:
                s = cv * (0.45 if fd["exploit_available"] else 0.25)
                tag = f"{fd['severity_name']} finding on another service ({fd['plugin_name'][:60]})"
            else:
                continue
            if s > v:
                v, best = s, (tag, fd)
        if best:
            why.append(best[0] + (", public exploit" if best[1]["exploit_available"] else ""))
        admin = sorted({LATERAL_PORTS[p] for p in used if p in LATERAL_PORTS})
        if admin and 0.5 > v:
            v = 0.5
            why.append(f"admin/lateral protocol in use ({', '.join(admin)}): stolen credentials would carry over")
        elif admin:
            why.append(f"admin/lateral protocol in use ({', '.join(admin)})")
        if b not in hostinfo:
            v = max(v, 0.3)
            why.append("not in the vulnerability scan, so its weaknesses are unknown")
        return {"p": round(min(1.0, r * v), 2), "why": why}

    nodes: dict[str, dict] = {}
    from .netmap import NetMap
    netmap = NetMap(res.get("network_map", []))

    def node(ip):
        if ip in nodes:
            return nodes[ip]
        h = hostinfo.get(ip)
        fl = findings.get(ip, [])
        worst = max((r["severity"] for r in fl), default=-1)
        ev = ("likely" if any(i["confidence"] == "corroborated" for r in fl for i in r["indicators"])
              else "lead" if any(r["indicators"] for r in fl) else "")
        sc = traffic_scanners.get(ip)
        name = (h or {}).get("hostname", "") or ("Vulnerability scanner" if ip in scanners else
                                                 "" if not sc else
                                                 "Expected scanner" + (f": {sc['name']}" if sc["name"] else "")
                                                 if sc["expected"] else "Scanner (review)")
        nodes[ip] = {"id": ip, "name": name, "scanned": ip in ds.scanned_hosts,
                     "observed": h is not None,
                     "subnet": _subnet(ip), "sev": SEV.get(worst, ""), "pri": (h or {}).get("priority", ""),
                     "score": (h or {}).get("max_score", 0), "ev": ev, "os": (h or {}).get("os", "") or ""}
        if netmap and netmap.index(ip) is not None:
            nodes[ip]["net"] = netmap.index(ip)
        return nodes[ip]

    contacts = _ContactWriter(store) if contacts_path else None
    inports: dict[str, Counter] = defaultdict(Counter)      # ports hosts with a card use on each peer
    peers_cut = False
    focus = {}
    for ip in scanned:
        node(ip)
        # east/west: every internal peer in either direction (failed attempts too), then onward peers
        peers, probed_only, probed_blocked = [], Counter(), 0
        for other in (out_of.get(ip, set()) | in_to.get(ip, set())):
            if ext(other) or other in broadcast:
                continue
            if other not in answering and other not in hostinfo and other not in ds.scanned_hosts:
                probed_only[_subnet(other)] += 1
                tried = pairs.get((ip, other))
                probed_blocked += bool(tried and tried.blocked)
                continue
            o, i = pairs.get((ip, other)), pairs.get((other, ip))
            ok = bool((o and o.established) or (i and i.established))
            if ok:
                est = reach(ip, other)
            else:
                tries = (o.sessions if o else 0) + (i.sessions if i else 0)
                est = {"p": 0.0, "why": [f"{tries} attempt(s), none completed: no working path seen"]}
            node(other)
            peers.append({"ip": other, "out": o.established if o else 0, "in": i.established if i else 0,
                          "out_tries": o.sessions if o else 0, "in_tries": i.sessions if i else 0,
                          "ports_out": sorted(o.ports if ok else o.tried)[:8] if o else [],
                          "ports_in": sorted(i.ports if ok else i.tried)[:8] if i else [],
                          "connection_examples": [],
                          "p": est["p"], "band": ("Unknown" if telemetry_only else _band(est["p"])) if ok else "None", "why": est["why"]})
        peers.sort(key=lambda p: (-p["p"], p["band"] == "None", -(p["out"] + p["in"]),
                                  -(p["out_tries"] + p["in_tries"]), p["ip"]))
        n_peers = len(peers)
        for p in peers:
            inports[p["ip"]].update(p["ports_out"])
        hop1 = {p["ip"]: p["p"] for p in peers}
        hop2 = {}
        for mid, p1 in hop1.items():
            if p1 <= 0:
                continue
            for nxt in out_of.get(mid, ()):
                if nxt == ip or nxt in hop1 or ext(nxt) or not pairs.get((mid, nxt)).established:
                    continue
                est = reach(mid, nxt)
                p2 = round(p1 * est["p"], 2)
                if p2 > hop2.get(nxt, {}).get("p", -1):
                    hop2[nxt] = {"ip": nxt, "via": mid, "p": p2, "band": _band(p2),
                                 "why": [f"via {mid} ({p1:.2f})"] + est["why"]}
        h2 = sorted((p for p in hop2.values() if p["p"] >= 0.05), key=lambda p: (-p["p"], p["ip"]))[:MAX_HOP2]
        for p in h2:
            node(p["ip"])
        if contacts:
            contacts.add(ip, "p", peers)
        blast = {"high": sum(p["band"] == "High" for p in peers),
                 "medium": sum(p["band"] == "Medium" for p in peers),
                 "low": sum(p["band"] == "Low" for p in peers)}
        kept_peers = _cut(peers, cap)
        peers_cut |= len(kept_peers) < n_peers
        focus[ip] = {
            "attackers": [], "attackers_total": 0, "peers": kept_peers, "peers_total": n_peers, "hop2": h2,
            "probed_only": sum(probed_only.values()), "probed_blocked": probed_blocked,
            # where this host's unanswered probing went: [subnet, addresses], most probed first
            "probed_ranges": [[sn, n] for sn, n in sorted(probed_only.items(), key=lambda kv: (-kv[1], kv[0]))[:12]],
            "probed_ranges_total": len(probed_only),
            "ot_events": ot_by_host.get(ip, []), "ot_events_total": ot_counts[ip],
            "findings": [{"pri": r["priority"], "score": r["score"], "name": r["plugin_name"],
                          "port": r["port"], "proto": r["proto"], "sev": r["severity_name"], "cvss": r["cvss"],
                          "cves": r["cves"][:4], "exploit": r["exploit_available"],
                          "exposure": r["exposure"]["label"],
                          "evidence": [{"c": i["confidence"], "t": i["text"]} for i in r["indicators"]]}
                         for r in findings.get(ip, [])],
            "blast": blast,
        }

    # overview edges: internal pairs touching at least one node we keep
    # Past MAX_NODES, draw the riskiest hosts: evidence first, then priority and score. Sorting by
    # address alone would drop whole ranges (for example cloud subnets that sort after on-prem).
    # Then hosts in IPS/IDS alerts, OT devices and the busiest hosts, so telemetry-only runs (no
    # priorities or scores) do not fall back to address order and drop alerted hosts and PLCs.
    ev_rank = {"likely": 0, "lead": 1}
    alerted = {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip)}
    alerted |= {ip for ip, e in traffic_scanners.items() if not e["expected"]}
    ot_hosts = {ip for ip, c in ot_counts.items() if c}

    def activity(n):
        h = hostinfo.get(n) or {}
        return (h.get("inbound_flows") or 0) + (h.get("outbound_flows") or 0)
    keep = sorted(nodes, key=lambda n: (not nodes[n]["observed"], ev_rank.get(nodes[n]["ev"], 2),
                                        nodes[n]["pri"] or "P9", -(nodes[n]["score"] or 0),
                                        n not in alerted, n not in ot_hosts, -activity(n), n))[:MAX_NODES]
    kept = set(keep)

    # north/south: every outside address each host exchanged traffic with, in either direction,
    # one host at a time; the internet panel adds up all of them
    inet = _InternetTally(kept)
    ext_stats: dict[str, tuple[int, bool]] = {}
    window = [res["summary"].get("window_start"), res["summary"].get("window_end")]
    atk_cut = False

    def outside(ip, rows):
        nonlocal atk_cut
        atk = []
        for src, (p, back) in rows.items():
            al = alerts[ip].get(src, [])
            open_al = [t for t in al if not t.blocked]
            hit = sorted({port for port, _ in vhits.get((src, ip), ())}) if p else []
            if p:
                kind = ("alert" if open_al else "vuln" if hit else "reached" if p.established
                        else "blocked" if p.blocked else "attempt")
            else:
                kind = "alert" if open_al else "outbound"
            span = [x for x in (p, back) if x]
            first = min((x.first for x in span if x.first), default=None)
            last = max((x.last for x in span if x.last), default=None)
            atk.append({"ip": src, "kind": kind, "dir": "both" if p and back else "in" if p else "out",
                        "sessions": p.sessions if p else 0, "established": p.established if p else 0,
                        "blocked": p.blocked if p else 0, "ports": sorted(p.tried)[:8] if p else [],
                        "vuln_ports": hit,
                        "out_sessions": back.sessions if back else 0,
                        "out_established": back.established if back else 0,
                        "out_ports": sorted(back.tried)[:8] if back else [],
                        "connection_examples": [],
                        "alerts": len(open_al), "alerts_blocked": len(al) - len(open_al),
                        "alerts_in": sum(t.src_ip == src for t in al),
                        "alert_examples": [{"src_ip": t.src_ip, "dst_ip": t.dst_ip,
                                            "dst_port": t.dst_port, "name": t.name,
                                            "blocked": t.blocked} for t in al[:MAX_CONNECTION_EXAMPLES]],
                        "signatures": sorted({t.name for t in al})[:3],
                        "returned": _returned(p, back),
                        "first": _iso(first), "last": _iso(last)})
        for src, al in alerts[ip].items():           # IPS-only sources with no flow in either direction
            if ext(src) and src not in rows:
                open_al = [t for t in al if not t.blocked]
                atk.append({"ip": src, "kind": "alert" if open_al else "blocked",
                            "dir": "out" if all(t.src_ip == ip for t in al) else "in", "sessions": 0,
                            "established": 0, "blocked": 0, "ports": sorted({t.dst_port for t in al if t.dst_port})[:8],
                            "vuln_ports": [], "out_sessions": 0, "out_established": 0, "out_ports": [],
                            "connection_examples": [],
                            "alerts": len(open_al), "alerts_blocked": len(al) - len(open_al),
                            "alerts_in": sum(t.src_ip == src for t in al),
                            "alert_examples": [{"src_ip": t.src_ip, "dst_ip": t.dst_ip,
                                                "dst_port": t.dst_port, "name": t.name,
                                                "blocked": t.blocked} for t in al[:MAX_CONNECTION_EXAMPLES]],
                            "signatures": sorted({t.name for t in al})[:3], "returned": False,
                            "first": None, "last": None})
        atk.sort(key=lambda a: (KIND_RANK[a["kind"]], -a["alerts"], -a["alerts_blocked"], -a["established"],
                                -a["sessions"] - a["out_sessions"], a["ip"]))
        if contacts:
            contacts.add(ip, "a", atk)
        for a in atk:
            inet.add(ip, a)
        f = focus[ip]
        ext_stats[ip] = (len(atk), any(a["kind"] == "alert" for a in atk))
        kept_atk = _cut(atk, cap, lambda a: a["kind"] == "alert")
        if cap is not None and len(kept_atk) > max(cap, MAX_LIST_ALERTS):
            kept_atk = kept_atk[:max(cap, MAX_LIST_ALERTS)]
        f["attackers"], f["attackers_total"] = kept_atk, len(atk)
        if len(kept_atk) < len(atk):
            atk_cut = True
            kinds = Counter(a["kind"] for a in atk)
            f["capped"] = {"kinds": dict(sorted(kinds.items())), "times": _attack_bins(window, atk),
                           "vports": sorted({p for a in atk if a["kind"] == "vuln" for p in a["vuln_ports"]})}

    done = set()
    group, rows = None, {}
    for host, addr, inbound, outbound in store.outside_contacts():
        if host != group:
            if group in focus:
                outside(group, rows)
                done.add(group)
            group, rows = host, {}
        rows[addr] = (_pair(inbound), _pair(outbound))
    if group in focus:
        outside(group, rows)
        done.add(group)
    for ip in scanned:
        if ip not in done:
            outside(ip, {})

    links = {}
    for (s, d), pair in pairs.items():
        if pair.established and s in kept and d in kept:
            k = tuple(sorted((s, d)))
            links[k] = links.get(k, 0) + pair.established
    for n in keep:
        nodes[n]["ext"], nodes[n]["alert"] = ext_stats.get(n, (0, False))
    overview = _overview_summary(pairs, nodes, ext_stats, kept, ext, inet)
    ioc_by_host = defaultdict(set)
    for match in res.get("ioc_matches", []):
        for host in match.get("hosts", []):
            if host in focus:
                ioc_by_host[host].add(match["id"])
    timeline = _timeline(ds, res, keep, ext, services, scanners)

    # connection examples: every row of the full lists (written beside the flow copies), or only the
    # rows the page shows them for
    shown = {ip: f for ip, f in focus.items() if ip in kept}
    want = set()
    for ip, f in shown.items():
        for a in _example_rows(f["attackers"], f["attackers_total"], cap):
            want |= {(a["ip"], ip), (ip, a["ip"])}
        for q in _example_rows(f["peers"], f["peers_total"], cap):
            want |= {(ip, q["ip"]), (q["ip"], ip)}
    store.pair_examples(None if contacts else want, MAX_CONNECTION_EXAMPLES)
    ex = store.examples_for(want) if want else {}
    for ip, f in shown.items():
        for a in _example_rows(f["attackers"], f["attackers_total"], cap):
            a["connection_examples"] = ex.get((a["ip"], ip), []) + ex.get((ip, a["ip"]), [])
        for q in _example_rows(f["peers"], f["peers_total"], cap):
            q["connection_examples"] = ex.get((ip, q["ip"]), []) + ex.get((q["ip"], ip), [])
    if contacts:
        contacts.finish(contacts_path)
    s = res["summary"]
    data = {
        "vulnerability_data_available": not telemetry_only,
        "generated": res["generated"], "report": res.get("report") or {"name": "", "description": ""},
        "window": window,
        "counts": {"hosts": len(scanned) if telemetry_only else res["coverage"]["scanned_hosts"], "flows": s["flows"], "p1": s["priority_counts"]["P1"],
                   "alerts": s.get("threat_alerts", 0)},
        "nodes": [nodes[n] for n in keep],
        "links": [[a, b, w] for (a, b), w in sorted(links.items(), key=lambda kv: -kv[1])[:3000]],
        # the page expects every focusable host to be drawn
        "networks": [{"name": e["name"], "type": e["type"], "cloud": e["cloud"], "cidr": e["cidr"]}
                     for e in res.get("network_map", [])],
        "focus": shown, "ioc_matches": res.get("ioc_matches", []), **overview,
        "ioc_counts": {host: len(ids) for host, ids in ioc_by_host.items()},
        "article_briefs": res.get("article_briefs", {}),
        "probed_subnets": dict(res["coverage"].get("probed_only_subnets") or ()),
        "start": (keep[0] if telemetry_only and keep else res["hosts"][0]["host"] if res["hosts"] else None),
        "timeline": timeline,
    }
    if atk_cut or peers_cut:
        # Some lists are cut: what the page needs from the full lists, and where they are
        data["lists"] = {"cap": cap, "file": bool(contacts)}
        if peers_cut:          # Attack paths: ports other hosts use on each drawn host
            data["inports"] = {n: [p for p, _ in sorted(inports[n].items(), key=lambda kv: (-kv[1], kv[0]))[:4]]
                               for n in keep if inports.get(n)}
        if atk_cut:            # the all-networks map adds up outside addresses over reports
            data["outside_all"] = inet.compact()
    return data


def _example_rows(rows: list, total: int, cap: int | None) -> list:
    """The rows of a host's list that carry connection examples on the page: all of them, or the
    first MAX_LIST_EXAMPLES when the list was cut."""
    return rows if cap is None or len(rows) >= total else rows[:MAX_LIST_EXAMPLES]


class _ContactWriter:
    """Every host's full lists, rows streamed into DuckDB in batches, then written to Parquet with
    their connection examples (store.write_contacts)."""

    def __init__(self, store):
        self.store, self.rows, self.first = store, [], True

    def add(self, host: str, side: str, rows: list):
        for rank, r in enumerate(rows):
            body = {k: v for k, v in r.items() if k != "connection_examples"}
            self.rows.append((host, side, rank, r["ip"], json.dumps(body, separators=(",", ":"), default=str)))
        if len(self.rows) >= 50_000:
            self.flush()

    def flush(self):
        self.store.insert_rows("explore_contacts", {"host": "VARCHAR", "side": "VARCHAR", "rank": "INTEGER",
                                                    "ip": "VARCHAR", "row": "VARCHAR"},
                               self.rows, append=not self.first)
        self.rows, self.first = [], False

    def finish(self, path: str):
        self.flush()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.store.write_contacts(path)


class _InternetTally:
    """Outside addresses added up over every host's full list (for the overview's internet panel):
    each keeps its strongest kind, session and alert totals, how many hosts it touched and its
    MAX_INTERNET_TARGETS strongest drawn hosts."""

    def __init__(self, kept: set):
        self.kept, self.e = kept, {}

    def add(self, host: str, a: dict):
        e = self.e.get(a["ip"])
        if e is None:
            e = self.e[a["ip"]] = {"ip": a["ip"], "kind": a["kind"], "sessions": 0, "alerts": 0, "targets": [],
                                   "in_sessions": 0, "out_sessions": 0, "out_hosts": 0, "alerts_in": 0,
                                   "hosts_total": 0}
        if KIND_RANK[a["kind"]] < KIND_RANK[e["kind"]]:
            e["kind"] = a["kind"]
        e["sessions"] += a["sessions"] + a["out_sessions"]
        e["in_sessions"] += a["sessions"]
        e["out_sessions"] += a["out_sessions"]
        e["out_hosts"] += a["out_sessions"] > 0
        e["alerts"] += a["alerts"]
        e["alerts_in"] += a.get("alerts_in", 0)
        e["hosts_total"] += 1
        if host in self.kept:
            # direction of this host's traffic with the address: in (it reached the host), out (the host
            # connected out to it) or both
            d = "both" if a["sessions"] and a["out_sessions"] else "out" if a["out_sessions"] else "in"
            e["targets"].append([host, a["kind"], a["sessions"] + a["out_sessions"], d])
            if len(e["targets"]) > 8 * MAX_INTERNET_TARGETS:
                e["targets"] = _top_targets(e["targets"])

    def compact(self) -> list:
        """Every address as [ip, kind, inbound sessions, outbound sessions, hosts calling out to it,
        alerts, alerts it set off, hosts], for the all-networks map (combine.py)."""
        return [[e["ip"], e["kind"], e["in_sessions"], e["out_sessions"], e["out_hosts"], e["alerts"],
                 e["alerts_in"], e["hosts_total"]] for e in self.e.values()]


def _top_targets(targets: list) -> list:
    return sorted(targets, key=lambda t: (KIND_RANK[t[1]], -t[2], t[0]))[:MAX_INTERNET_TARGETS]


def _hours(ts, t0) -> float:
    return round((ts - t0).total_seconds() / 3600, 4)


def _even(items: list, n: int) -> list:
    """`n` items picked at even steps through `items`, so a time-sorted list keeps its whole span."""
    if len(items) <= n:
        return list(items)
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def _spread(items: list, cap: int, favour=None, key=lambda x: x[0]) -> list:
    """At most `cap` of the time-sorted `items`, spread over the whole run instead of the earliest ones.
    Items for which `favour` is true are kept first (themselves spread if there are more than `cap`)."""
    if len(items) <= cap:
        return list(items)
    fav = [x for x in items if favour(x)] if favour else []
    if len(fav) >= cap:
        return _even(fav, cap)
    rest = [x for x in items if not favour(x)] if favour else items
    return sorted(fav + _even(rest, cap - len(fav)), key=key)


def _timeline(ds, res: dict, keep: list, ext, services: dict, scanners=frozenset()) -> dict | None:
    """Flows, IPS alerts and IOC lookups in time order for the Timeline view.

    Hosts are referenced by their index in ``nodes`` (>= 0), as len(nodes) + i into ``more`` for internal
    hosts the network view leaves out (so their traffic is still drawn), or as -(index + 1) into ``ext``
    for outside addresses. Flow flags: 1 blocked or failed, 2 to/from an IPS-alert or IOC address, 4 onto
    a port with a known vulnerability on the destination host.

    Large runs are sampled: flows to/from an alert or IOC address first, then blocked flows, up to half
    the budget, each tier sampled at random over the whole run (never just the earliest); the rest is a
    random sample of everything else. ``hist`` then counts every flow per time bucket so the page can say
    how many flows a stretch of time really had. Alerts and IOC lookups beyond their caps are thinned
    evenly over the run, keeping alerts that were not blocked first. Alerts with no timestamp of their
    own are listed apart (``untimed``) rather than placed at a guessed time."""
    store = ds.flow_store()
    total, t0, t1 = store.flow_span()
    if not total or t0 is None:
        return None
    t0 = t0.replace(microsecond=0)          # t0 is sent to the page to the second; hours are counted from it
    idx = {ip: i for i, ip in enumerate(keep)}
    ext_idx: dict[str, int] = {}
    more_idx: dict[str, int] = {}

    def ref(ip):
        if ip in idx:
            return idx[ip]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if ext(ip):
            if ip not in ext_idx:
                ext_idx[ip] = len(ext_idx)
            return -(ext_idx[ip] + 1)
        if ip not in more_idx:
            more_idx[ip] = len(more_idx)
        return len(keep) + more_idx[ip]

    flagged = {t.src_ip for t in ds.threats if ext(t.src_ip)}
    flagged |= {m["value"] for m in res.get("ioc_matches", []) if m.get("type") == "ip"}
    rows, sampled = store.timeline_flows(flagged, MAX_TIMELINE_FLOWS)
    hist = None
    if sampled:
        # every flow, counted per bucket of time, so a window's real total can be shown next to the sample
        hours = (t1 - t0).total_seconds() / 3600
        bw = max(0.25, hours / 2000)
        hist = {"bucket": round(bw, 4),
                "counts": [[int(b), int(n)] for b, n in store.timeline_counts(t0, bw * 3600)]}
    flows, hidden = [], 0
    for r in rows:
        ts, src, dst, port, action, est, proto = r[:7]
        s, d = ref(src), ref(dst)
        if s is None or d is None:
            hidden += 1
            continue
        f = (1 if action != "allow" or est is False else 0) | (2 if src in flagged or dst in flagged else 0) \
            | (4 if port and src not in scanners and _hits_service(services.get(dst, ()), port, proto, utc(ts)) else 0)
        flows.append([_hours(utc(ts), t0), s, d, port or 0, f])

    def dst_ref(ip):
        r = ref(ip)
        return -1 if r is None or r < 0 else r
    timed, untimed = [], []
    for t in ds.threats:
        (timed.append((utc(t.ts), t)) if t.ts else untimed.append(t))
    timed.sort(key=lambda x: x[0])
    alerts = [[_hours(ts, t0), dst_ref(t.dst_ip), t.src_ip, t.name, t.blocked, t.dst_ip]
              for ts, t in _spread(timed, MAX_TIMELINE_ALERTS, favour=lambda x: not x[1].blocked)]
    no_time = [[dst_ref(t.dst_ip), t.src_ip, t.name, t.blocked] for t in untimed[:MAX_TIMELINE_ALERTS]]
    domains = {m["value"].lower() for m in res.get("ioc_matches", []) if m.get("type") == "domain"}
    found = []
    if domains:
        for e in ds.zeek_events:
            q = str((e.fields or {}).get("query") or "").lower().rstrip(".")
            if e.ts and q in domains:
                r = ref(e.src_ip)
                if r is not None and r >= 0:
                    found.append((utc(e.ts), r, q))
        found.sort(key=lambda x: x[0])
    lookups = [[_hours(ts, t0), r, q] for ts, r, q in _spread(found, MAX_TIMELINE_IOC_LOOKUPS)]
    return {"t0": _iso(t0), "hours": _hours(t1, t0), "total": total, "sampled": sampled, "hist": hist,
            "hidden": hidden, "flows": flows,
            "ext": [[ip, ip in flagged] for ip in ext_idx], "more": [[ip, _subnet(ip)] for ip in more_idx],
            "alerts": alerts, "alerts_total": len(timed), "untimed": no_time, "untimed_total": len(untimed),
            "ioc_lookups": lookups, "ioc_lookups_total": len(found)}


KIND_RANK = {"alert": 0, "vuln": 1, "reached": 2, "outbound": 3, "attempt": 4, "blocked": 5}


def _interleave(by_in: list, by_out: list, cap: int) -> list:
    """Two inbound entries, then one outbound, until `cap`; whichever list runs out first leaves its
    slots to the other. An address in both lists is kept once, where it first comes up."""
    top, seen, i, o = [], set(), 0, 0
    while len(top) < cap and (i < len(by_in) or o < len(by_out)):
        take_out = o < len(by_out) and (len(top) % 3 == 2 or i >= len(by_in))
        if take_out:
            e, o = by_out[o], o + 1
        else:
            e, i = by_in[i], i + 1
        if e["ip"] not in seen:
            seen.add(e["ip"])
            top.append(e)
    return top


def _overview_summary(pairs, nodes, ext_stats, kept, ext, tally) -> dict:
    """Overview aggregates. Subnet totals and subnet-to-subnet traffic cover every host and pair,
    so they stay complete when the host graph is capped at MAX_NODES. Host-level links are kept
    only for risky paths (admin/lateral protocols, or completed sessions into a P1 or a host with
    exploitation evidence), and outside addresses are ranked by how they touched the network
    (``tally``: every host's full list added up, see _InternetTally)."""
    subnets = {}
    for ip, n in nodes.items():
        if ext(ip):
            continue
        sn = subnets.setdefault(n["subnet"], {"id": n["subnet"], "hosts": 0, "drawn": 0, "p1": 0, "likely": 0,
                                               "lead": 0, "max_score": 0, "exposed": 0, "alert_hosts": 0})
        sn["hosts"] += 1
        sn["drawn"] += ip in kept
        if "net" in n:
            sn.setdefault("nets", {})
            sn["nets"][n["net"]] = sn["nets"].get(n["net"], 0) + 1
        sn["p1"] += n["pri"] == "P1"
        sn["likely"] += n["ev"] == "likely"
        sn["lead"] += n["ev"] == "lead"
        sn["max_score"] = max(sn["max_score"], n["score"] or 0)
        n_ext, any_alert = ext_stats.get(ip, (0, False))
        if n_ext:
            sn["exposed"] += 1
            sn["alert_hosts"] += any_alert
    sublinks: dict[tuple, list] = defaultdict(lambda: [0, 0])
    risky = {}
    for (s, d), p in pairs.items():
        if not p.established or s not in nodes or d not in nodes or ext(s) or ext(d):
            continue
        a, b = nodes[s]["subnet"], nodes[d]["subnet"]
        lateral = sorted({LATERAL_PORTS[x] for x in p.ports if x in LATERAL_PORTS})
        if a != b:
            k = tuple(sorted((a, b)))
            sublinks[k][0] += p.established
            sublinks[k][1] += p.established if lateral else 0
        hot = nodes[d]["pri"] == "P1" or nodes[d]["ev"] in ("likely", "lead")
        if (lateral or hot) and s in kept and d in kept:
            parts = ([", ".join(lateral)] if lateral else []) + (["into " + (nodes[d]["pri"] or "flagged") + " host"] if hot else [])
            # level 2: admin protocol into a P1/flagged host; 1: either one
            risky[(s, d)] = [s, d, p.established, " · ".join(parts), 2 if lateral and hot else 1]
    inet = tally.e
    for e in inet.values():
        # an alert only counts as inbound when the outside address set it off (it was the source);
        # a client-side alert such as a bad server certificate is the internal host going out
        e["dir"] = ("both" if e["out_sessions"] and (e["in_sessions"] or e["alerts_in"])
                    else "out" if e["out_sessions"] else "in")
    # Inbound and outbound are ranked separately and interleaved, so internal hosts calling out are not
    # crowded off the overview by inbound scanners (which outnumber them and rank first by kind).
    by_in = sorted((e for e in inet.values() if e["dir"] != "out"),
                   key=lambda e: (KIND_RANK[e["kind"]], -e["hosts_total"], -e["sessions"], e["ip"]))
    by_out = sorted((e for e in inet.values() if e["out_sessions"]),
                    key=lambda e: (e["kind"] != "alert", -e["out_hosts"], -e["out_sessions"], e["ip"]))
    top = _interleave(by_in, by_out, MAX_INTERNET)
    internet = []
    for e in top[:MAX_INTERNET]:
        e = {k: e[k] for k in ("ip", "kind", "sessions", "alerts", "targets", "in_sessions", "out_sessions",
                               "out_hosts", "alerts_in", "dir", "hosts_total")}
        e["targets"] = _top_targets(e["targets"])
        internet.append(e)
    for sn in subnets.values():          # a subnet belongs to the named network most of its hosts are in
        nets = sn.pop("nets", None)
        if nets:
            sn["net"] = max(nets, key=lambda k: (nets[k], -k))
    return {
        "subnets": sorted(subnets.values(), key=lambda x: x["id"]),
        "subnet_links": [[a, b, w, lw] for (a, b), (w, lw) in
                         sorted(sublinks.items(), key=lambda kv: (-kv[1][1], -kv[1][0]))[:MAX_SUBNET_LINKS]],
        "risky_links": sorted(risky.values(), key=lambda r: (-r[4], -r[2], r[0], r[1]))[:MAX_RISKY_LINKS],
        "internet": internet, "internet_total": len(inet),
        "internet_in_total": sum(e["dir"] != "out" for e in inet.values()),
        "internet_out_total": sum(e["out_sessions"] > 0 for e in inet.values()),
    }


def _read(name: str) -> str:
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


CONTACTS_FILE = os.path.join("normalized", "explorer_contacts.parquet")


def full_lists(path: str, host: str) -> dict:
    """A host's full lists (outside addresses and internal peers, every row with its connection
    examples) from the contacts file ``build`` wrote, for the page to show in place of its cut ones."""
    from .store import contact_rows
    out: dict[str, list] = {"attackers": [], "peers": []}
    for side, row, ex in contact_rows(path, host):
        r = json.loads(row)
        r["connection_examples"] = ex or []
        out["attackers" if side == "a" else "peers"].append(r)
    return out


DATA_TAG = '<script id="vf-data" type="application/octet-stream" data-encoding="gzip-base64">'
_DATA = re.compile(r'<script id="vf-data" type="application/(json|octet-stream)"( data-encoding="gzip-base64")?>(.*?)</script>', re.S)
MAX_DATA = 2 * 1024 ** 3        # Explorer data larger than this once unpacked is refused (saved pages)


def _json_parts(data: dict):
    """``data`` as compact JSON, in pieces no larger than one host's card (so the whole text is
    never built in memory at once). Same text as json.dumps(data, separators=(",", ":"))."""
    dump = lambda v: json.dumps(v, separators=(",", ":"), default=str)
    yield "{"
    for n, (k, v) in enumerate(data.items()):
        yield ("," if n else "") + dump(k) + ":"
        if k == "focus" and isinstance(v, dict):
            yield "{"
            for m, (ip, f) in enumerate(v.items()):
                yield ("," if m else "") + dump(ip) + ":" + dump(f)
            yield "}"
        else:
            yield dump(v)
    yield "}"


def write_data(fh, data: dict) -> None:
    """The Explorer data as gzip in base64, written to ``fh`` piece by piece. The page unpacks it
    itself (vendored fflate), so it still opens offline and straight from disk."""
    comp = zlib.compressobj(6, zlib.DEFLATED, 31)       # gzip framing, no timestamp
    pending = b""

    def out(chunk: bytes):
        nonlocal pending
        pending += chunk
        cut = len(pending) - len(pending) % 3 if len(pending) > 1 << 16 else 0
        if cut:
            fh.write(base64.b64encode(pending[:cut]).decode("ascii"))
            pending = pending[cut:]
    buf, size = [], 0
    for part in _json_parts(data):
        buf.append(part)
        size += len(part)
        if size >= 1 << 20:
            out(comp.compress("".join(buf).encode()))
            buf, size = [], 0
    out(comp.compress("".join(buf).encode()))
    out(comp.flush())
    fh.write(base64.b64encode(pending).decode("ascii"))


def read_data(page: str):
    """The Explorer data inside a page this module wrote (gzip in base64, or plain JSON in pages
    written before that). Raises ValueError when there is none or it can't be read."""
    m = _DATA.search(page)
    if not m:
        raise LookupError("no Explorer data in the page")
    if not m.group(2):
        return json.loads(m.group(3))
    try:
        raw = base64.b64decode(m.group(3).strip(), validate=True)
        d = zlib.decompressobj(31)
        text = d.decompress(raw, MAX_DATA)
        if d.unconsumed_tail:
            raise ValueError("the Explorer data is larger than VulnScope reads back "
                             f"({MAX_DATA // 1024 ** 3} GB unpacked)")
    except (ValueError, zlib.error) as exc:
        raise ValueError(f"the Explorer data is damaged ({exc})") from None
    return json.loads(text)


def html(data: dict, ioc_drawer: list | None = None) -> str:
    """The Explorer page for ``data`` (see write_html)."""
    buf = io.StringIO()
    write_html(buf, data, ioc_drawer)
    return buf.getvalue()


def write_html(fh, data: dict, ioc_drawer: list | None = None) -> None:
    """Write the Explorer page for ``data`` to ``fh``. ``ioc_drawer``: the IOC list for the indicator
    details drawer, when it should name hosts differently from the map (the all-networks map does)."""
    from . import ioc_archive
    from html import escape
    from .branding import EXPLORER_NAME, icon_data_uri, load as load_branding
    from .report import HTML_OPEN
    from .theme_backgrounds import explorer_background_css
    brand = load_branding()
    logo = brand.logo_data_uri()
    brand_markup = ((f'<img class="brand-logo{brand.logo_class}" src="{logo}" alt="" aria-hidden="true">' if logo else "")
                    + (f'{escape(brand.prefix)} ' if brand.prefix else "") + "<b>VULNSCOPE</b>")
    report = data.get("report") or {}
    name = report.get("name") or ""
    report_markup = (f'<span id="report-name" title="{escape(report.get("description") or name)}">{escape(name)}</span>'
                     if name else "")
    fh.write(HTML_OPEN + "<head><meta charset=\"utf-8\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             f"<title>{escape(name) + ' · ' if name else ''}{EXPLORER_NAME} · {escape(brand.name)}</title><meta name=\"application-name\" content=\"{escape(brand.name)}\"><link rel=\"icon\" href=\"{icon_data_uri()}\"><style>" + _read("analyst_chat.css") + _read("explorer.css") + _read("attackpaths.css") + _read("timeline3d.css") + explorer_background_css() + ioc_archive.CSS + "</style></head><body>"
             + _read("explorer.html").replace("<!--BRAND-->", brand_markup, 1).replace("<!--REPORT-->", report_markup, 1))
    fh.write(DATA_TAG)
    write_data(fh, data)
    fh.write("</script>"
             # fflate (MIT) unpacks the data and Three.js (MIT) draws the 3D views, both vendored so the
             # page works offline; the Explorer falls back to its 2D canvas when WebGL is unavailable
             + "<script>" + _read("vendor/fflate.min.js") + "</script>"
             + "<script>" + _read("vf_data.js") + "</script>"
             + "<script>" + _read("vendor/three.min.js") + "</script>"
             + "<script>" + _read("explorer3d.js") + "</script>"
             + "<script>" + _read("explorer.js") + "</script>"
             + "<script>" + _read("attackpaths.js") + "</script>"
             + "<script>" + _read("timeline3d.js") + "</script>"
             + "<script>" + _read("analyst_chat.js") + "</script>"
             + ioc_archive.drawer_html(data["ioc_matches"] if ioc_drawer is None else ioc_drawer,
                                      data.get("article_briefs")) + "</body></html>\n")
