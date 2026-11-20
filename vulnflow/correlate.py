"""Tie scanner findings to observed network activity.

For every vulnerability we ask three questions of the telemetry:
  1. Exposure:    is the vulnerable service actually reachable, and from where?
  2. Blast radius: if this host is compromised, what can it reach next?
  3. Indicators:  does the traffic already look like exploitation?
and fold the answers into an explainable 0-100 risk score.
"""
from __future__ import annotations

import ipaddress
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import scanners, sqlfile
from .normalize import Dataset
from .schema import SEVERITY_NAMES, Finding, Flow
from .store import naive, utc

DEFAULT_INTERNAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                         "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"]
EXTERNAL_ZONES = {"untrust", "outside", "internet", "external", "wan"}
LATERAL_PORTS = {22: "SSH", 23: "Telnet", 88: "Kerberos", 135: "RPC", 139: "NetBIOS",
                 389: "LDAP", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 3306: "MySQL",
                 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
SEVERITY_CVSS = {4: 9.5, 3: 7.5, 2: 5.0, 1: 2.5, 0: 0.0}
EXFIL_BYTES = 20 * 1024 * 1024
BROAD_REACH = 5               # distinct internal clients that make a service "widely reached"
# Version of the results.json layout. Raise it when a field the reports read changes meaning or
# shape, so a saved results.json from another version is refused instead of misread on reopen.
RESULTS_SCHEMA_VERSION = 1


@dataclass
class Config:
    internal_nets: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL_NETS))
    hops: int = 2                 # depth of the blast-radius walk
    min_severity: int = 1         # ignore Info findings by default
    # Only telemetry within this many days of a host's scan (Nessus HOST_START/HOST_END) is
    # used for that host's findings. None or 0 uses all telemetry; findings without a scan
    # time always use all telemetry.
    scan_window_days: float | None = 7
    # Clock-skew tolerance for recognising one session seen by two sensors (Zeek + firewall).
    dedup_skew_seconds: float | None = 2.0
    # Optional CSV naming address ranges (cidr,name,type), e.g. AWS VPCs; see netmap.py.
    network_map: str | None = None
    # Optional list of scanners you expect (address,name); see scanners.py. ``known_scanner_list``
    # holds the parsed entries.
    known_scanners: str | None = None
    known_scanner_list: list = field(default_factory=list)
    # Write the full normalized copies of the input (normalized/flows.csv, zeek_events.jsonl,
    # ot_events.jsonl). They are about as large as the input itself; turning them off saves that
    # much disk on large runs. The small normalized files (findings, alerts, probed) are always written.
    normalized_copies: bool = True


class _Net:
    def __init__(self, cidrs):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self._cache = {}

    def internal(self, ip: str) -> bool:
        if ip not in self._cache:
            addr = ipaddress.ip_address(ip)
            self._cache[ip] = any(addr.version == n.version and addr in n for n in self.nets)
        return self._cache[ip]

    def external_src(self, f: Flow) -> bool:
        return not self.internal(f.src_ip) or f.src_zone in EXTERNAL_ZONES


def _iso(ts):
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z") if ts else None


def _priority(score: int, indicators: list) -> str:
    if score >= 75 or any(i["confidence"] == "corroborated" for i in indicators):
        return "P1"
    if score >= 50 or indicators:
        return "P2"
    return "P3" if score >= 25 else "P4"


PRIORITY_LABELS = {"P1": "P1 - act now", "P2": "P2 - this cycle", "P3": "P3 - scheduled",
                   "P4": "P4 - routine"}


# Flow lookups run as DuckDB SQL over the clean ``flows`` table (see store.py); the
# correlator never holds per-host flow lists in memory. ``fx`` is that table plus the
# internal/external classification for the current Config.
# A host talking to its own address is not exposure, so self-traffic never matches a finding.
_KEY_MATCH = ("f.dst_ip = k.host AND f.src_ip <> f.dst_ip "
              "AND (k.host_level OR (f.dst_port = k.port AND f.proto = k.proto)) AND {win}")
# A finding can have several scan windows (one row per window in xkeys, never overlapping). An
# untimed flow matches only the first row, so it is counted once.
_WIN = "(k.lo IS NULL OR (f.ts IS NULL AND k.wi = 0) OR f.ts BETWEEN k.lo AND k.hi)"
_LATERAL_SQL = ", ".join(str(p) for p in LATERAL_PORTS)


def _win(alias: str = "f") -> str:
    return _WIN.replace("f.ts", f"{alias}.ts")


def _key_match(alias: str = "f") -> str:
    return _KEY_MATCH.replace("f.", f"{alias}.").format(win=_win(alias))


# The correlator's queries live in model.sql; these are the fixed fragments they are built with.
MODEL = sqlfile.Model(os.path.join(os.path.dirname(__file__), "model.sql"), {
    "zones": ", ".join(f"'{z}'" for z in sorted(EXTERNAL_ZONES)),
    "key_match": _key_match(), "win": _win(), "win_g": _win("g"),
    "win_prior": _win("g").replace("k.", "c."),
    "lateral_ports": _LATERAL_SQL, "exfil_bytes": str(EXFIL_BYTES),
})


def _counts(events, column: str) -> dict:
    """Events per stream or protocol: asked of DuckDB for a disk-backed spool, counted here for a
    plain list (tests and small callers)."""
    if hasattr(events, "counts"):
        return events.counts(column)
    return dict(Counter(getattr(e, column) for e in events))


def _port(v):
    return None if v == -1 else v


class Correlator:
    def __init__(self, ds: Dataset, cfg: Config):
        self.ds, self.cfg, self.net = ds, cfg, _Net(cfg.internal_nets)
        self.store = ds.flow_store()
        self.con = self.store.con
        con = self.con
        ips = [r[0] for r in con.execute(
            "SELECT src_ip FROM flows UNION SELECT dst_ip FROM flows").fetchall()]
        self.store.insert_rows("ipnet", {"ip": "VARCHAR", "internal": "BOOLEAN"},
                               ((ip, self.net.internal(ip)) for ip in ips))
        # The vulnerability scanner's own probes (address from Nessus plugin 19506) are not use of a
        # service, so sessions it starts are left out of everything scored below. They still show
        # that sensors cover a host ("seen"), which counts all flows.
        self.scanner_ips = sorted(getattr(ds, "scanner_ips", ()) or ())
        self.store.insert_rows("scanners", {"ip": "VARCHAR"}, ((ip,) for ip in self.scanner_ips))
        con.execute(MODEL("flows_in_scope"))
        self.scanner_sessions = con.execute(
            "SELECT count(*) FROM flows WHERE src_ip IN (SELECT ip FROM scanners)").fetchone()[0]
        self.internal_ips = {r[0] for r in con.execute("SELECT ip FROM ipnet WHERE internal").fetchall()}
        # Hosts that exist: they started a session, or answered one (completed, refused with a reset,
        # or sent data back). Addresses that were only probed and never answered are not hosts.
        self.live_ips = self.store.answering_ips() & self.internal_ips
        del ips
        # per-host session counts, for internal hosts and scanned hosts
        wanted = self.internal_ips | {fd.host_ip for fd in ds.findings}
        self.store.insert_rows("wanted", {"ip": "VARCHAR"}, ((ip,) for ip in wanted))
        self.in_count, self.out_count = {}, {}
        for ip, n_in, n_out in con.execute(MODEL("session_counts_per_host")).fetchall():
            if n_in:
                self.in_count[ip] = int(n_in)
            if n_out:
                self.out_count[ip] = int(n_out)
        self.adj: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        for src, dst, ports in con.execute(MODEL("internal_adjacency")).fetchall():
            self.adj[src][dst].update(ports)
        self.max_sev = Counter()
        for fd in ds.findings:
            self.max_sev[fd.host_ip] = max(self.max_sev[fd.host_ip], fd.severity)
        self._blast_cache = {}
        self._blast_data = {}
        # IPS/IDS alerts live in DuckDB next to the flows, so "which alerts hit this finding's
        # service inside its scan window" is one join for all findings (see prepare), not a
        # Python filter per finding. ``aid`` is the alert's position in ds.threats (time order).
        self.threats = list(ds.threats)
        self.store.insert_rows(
            "alerts", {"aid": "BIGINT", "ts": "TIMESTAMP", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
                       "dst_port": "INTEGER", "blocked": "BOOLEAN"},
            ((i, naive(t.ts), t.src_ip, t.dst_ip, t.dst_port, t.blocked) for i, t in enumerate(self.threats)))
        self._kalerts: dict[int, tuple[list, list]] = {}
        self.suspects: dict[str, datetime | None] = {}   # host -> when it was first flagged for investigation
        self._kid: dict[tuple, int] = {}
        self._agg, self._top, self._contact, self._returns = {}, {}, {}, {}
        self._before, self._new_lat, self._exfil, self._spread = {}, {}, {}, {}

    # -- scan time window -------------------------------------------------
    def windows(self, fd: Finding) -> tuple:
        """((start, end), ...): telemetry within scan_window_days of each scan that reported the
        finding, overlapping windows merged. () means all telemetry (no scan time, or disabled)."""
        days = self.cfg.scan_window_days
        times = fd.scan_times or ([(fd.scan_start, fd.scan_end)] if fd.scan_start else [])
        if not days or not times:
            return ()
        d = timedelta(days=days)
        spans = sorted((s - d, max(e or s, s) + d) for s, e in times)
        merged = [list(spans[0])]
        for lo, hi in spans[1:]:
            if lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        return tuple((lo, hi) for lo, hi in merged)

    @staticmethod
    def _in_windows(windows: tuple, ts) -> bool:
        return not windows or ts is None or any(lo <= ts <= hi for lo, hi in windows)

    def _key(self, fd: Finding) -> tuple:
        w = self.windows(fd)
        if fd.port == 0:
            return (fd.host_ip, None, None, True, w)
        return (fd.host_ip, fd.port, fd.proto, False, w)

    # -- batch SQL ----------------------------------------------------------
    def prepare(self, findings: list[Finding]):
        """Run every flow query the findings need, in a few set-based SQL statements."""
        con = self.con
        for fd in findings:
            self._kid.setdefault(self._key(fd), len(self._kid))
        self.store.insert_rows(
            "xkeys", {"kid": "BIGINT", "host": "VARCHAR", "port": "INTEGER", "proto": "VARCHAR",
                      "host_level": "BOOLEAN", "wi": "INTEGER", "lo": "TIMESTAMP", "hi": "TIMESTAMP"},
            ((kid, h, p, pr, hl, wi, naive(lo), naive(hi))
             for (h, p, pr, hl, w), kid in self._kid.items()
             for wi, (lo, hi) in enumerate(w or ((None, None),))))
        # alerts on each finding's service: same host, the finding's port (or an alert without a
        # port, or a host-level finding), inside one of the finding's scan windows
        hit: dict[int, list] = {}
        for kid, aid in con.execute(MODEL("alerts_per_finding")).fetchall():
            hit.setdefault(kid, []).append(self.threats[aid])
        self._kalerts = {kid: ([t for t in ts if not t.blocked], [t for t in ts if t.blocked])
                         for kid, ts in hit.items()}
        for row in con.execute(MODEL("exposure_per_finding")).fetchall():
            self._agg[row[0]] = row[1:]
        for kid, ip, n, ext in con.execute(MODEL("top_sources_per_finding")).fetchall():
            self._top.setdefault(kid, []).append([ip, int(n), bool(ext)])
        # first contact by each outside address that completed a session to the service
        con.execute(MODEL("first_contact"))
        for kid, peer, t0 in con.execute("SELECT kid, peer, t0 FROM contact ORDER BY kid, first").fetchall():
            self._contact.setdefault(kid, []).append((peer, utc(t0)))
        # the vulnerable host later connects back out to that address
        for kid, peer, n, ports in con.execute(MODEL("return_connections")).fetchall():
            self._returns[(kid, peer)] = (int(n), [_port(p) for p in ports])
        # anchors depend on alerts and return connections, both known now
        anchors = []
        for fd in findings:
            kid = self._kid[self._key(fd)]
            t0 = self._anchor(fd, kid)
            if t0 is not None:
                anchors.append((kid, naive(t0)))
        self.store.insert_rows("anchors", {"kid": "BIGINT", "t0": "TIMESTAMP"}, set(anchors))
        for (kid,) in con.execute(MODEL("activity_before_anchor")).fetchall():
            self._before[kid] = True
        # Written as joins, not a correlated NOT EXISTS: DuckDB 1.5 fails to bind that form
        # ("Failed to bind column reference") when timed and untimed findings are mixed.
        for kid, ip, ports in con.execute(MODEL("new_lateral_sessions")).fetchall():
            self._new_lat.setdefault(kid, {})[ip] = set(ports)
        for kid, ip, n in con.execute(MODEL("large_outbound_transfers")).fetchall():
            self._exfil.setdefault(kid, []).append((ip, int(n)))

    def prepare_spread(self):
        """Lateral spread: the first completed session from a flagged host to each service."""
        self._spread = {}
        if not self.suspects:
            return
        self.store.insert_rows("suspects", {"ip": "VARCHAR", "t": "TIMESTAMP"},
                               ((ip, naive(t)) for ip, t in self.suspects.items()))
        # joins instead of a correlated EXISTS, for the same DuckDB binder issue as in prepare()
        for kid, src, port, proto, ts in self.con.execute(MODEL("lateral_spread")).fetchall():
            self._spread[kid] = (src, port, proto, utc(ts))

    def _capture_loss(self) -> float | None:
        worst = None
        events = self.ds.zeek_events
        for e in (events.of_stream("capture_loss") if hasattr(events, "of_stream") else events):
            if e.stream == "capture_loss":
                try:
                    pct = float(e.fields.get("percent_lost"))
                except (TypeError, ValueError):
                    continue
                worst = pct if worst is None else max(worst, pct)
        return None if worst is None else round(worst, 2)

    def prepare_blast(self, hosts):
        con = self.con
        hosts = [h for h in hosts if h not in self._blast_data]
        if not hosts:
            return
        self.store.insert_rows("bhosts", {"ip": "VARCHAR"}, ((h,) for h in hosts))
        data = {h: {"lateral": {}, "ext_total": 0, "ext_top": []} for h in hosts}
        for src, port, n, first in con.execute(MODEL("lateral_protocols_per_host")).fetchall():
            name = LATERAL_PORTS[port]
            n0, f0 = data[src]["lateral"].get(name, (0, first))
            data[src]["lateral"][name] = (n0 + n, min(f0, first))
        for src, total, dst, n in con.execute(MODEL("external_destinations_per_host")).fetchall():
            data[src]["ext_total"] = int(total)
            data[src]["ext_top"].append([dst, int(n)])
        self._blast_data.update(data)

    # -- exposure ---------------------------------------------------------
    def exposure(self, fd: Finding) -> dict:
        host_level = fd.port == 0
        kid = self._kid[self._key(fd)]
        total, n_est, denied, refused, n_ext, n_int, first, last, nbytes = self._agg.get(
            kid, (0, 0, 0, 0, 0, 0, None, None, 0))
        seen = fd.host_ip in self.in_count or fd.host_ip in self.out_count
        alerts, blocked = self._threats_to(fd)

        if not seen:
            label, factor = "No telemetry for this host (unknown)", 0.5
        elif host_level:
            # local/client-side flaws need another foothold first, so weigh them lower
            if n_ext:
                label, factor = "Host receives internet traffic", 0.7
            elif n_est or self.out_count.get(fd.host_ip):
                label, factor = "Host is active on the network", 0.5
            else:
                label, factor = "Host seen, little activity", 0.35
        elif n_ext:
            label, factor = "Vulnerable service reached from the internet", 1.0
        elif n_int >= BROAD_REACH:
            label, factor = "Vulnerable service reached internally by many hosts", 0.85
        elif n_int:
            label, factor = "Vulnerable service reached internally", 0.75
        elif denied and not n_est:
            label, factor = "Connections to service blocked by firewall", 0.35
        elif refused and not n_est:
            # Zeek REJ: the host answered with a reset (closed port or host firewall), not a network block
            label, factor = "Connections to service refused by the host", 0.35
        elif total:
            label, factor = "Connection attempts only (no completed sessions)", 0.45
        else:
            label, factor = "Service not observed in use", 0.3
        exp = {
            "label": label, "factor": factor, "scope": "host" if host_level else "port",
            "telemetry_seen": seen, "inbound_total": total, "established": n_est,
            "denied": denied, "refused": refused, "attempts": total - n_est - denied - refused,
            "internal_sources": n_int, "external_sources": n_ext,
            "top_sources": self._top.get(kid, []),
            "first_seen": _iso(utc(first)), "last_seen": _iso(utc(last)),
            "bytes": int(nbytes),
            "threat_alerts": len(alerts), "threat_blocked": len(blocked),
            "threat_blocked_sources": [[ip, n] for ip, n in
                                       Counter(t.src_ip for t in blocked).most_common(8)],
            "_kid": kid,
        }
        windows = self.windows(fd)
        if windows:
            spans = [{"start": _iso(lo), "end": _iso(hi), "days": self.cfg.scan_window_days} for lo, hi in windows]
            exp["window"] = spans[-1]            # around the latest scan
            exp["windows"] = spans               # one per scan (merged where they overlap)
        return exp

    # -- blast radius -----------------------------------------------------
    def blast(self, host: str) -> dict:
        if host in self._blast_cache:
            return self._blast_cache[host]
        if host not in self._blast_data:
            self.prepare_blast([host])
        hops, frontier = {}, [host]
        for depth in range(1, self.cfg.hops + 1):
            nxt = []
            for h in frontier:
                for peer in self.adj.get(h, {}):
                    if peer != host and peer not in hops:
                        hops[peer] = depth
                        nxt.append(peer)
            frontier = nxt
        direct = self.adj.get(host, {})
        reachable = sorted(
            ({"ip": ip, "hop": d, "ports": sorted(direct.get(ip, set())) if d == 1 else [],
              "max_severity": SEVERITY_NAMES.get(self.max_sev.get(ip), "") if ip in self.max_sev else ""}
             for ip, d in hops.items()),
            key=lambda r: (r["hop"], -self.max_sev.get(r["ip"], -1), r["ip"]))
        data = self._blast_data[host]
        lateral = {name: n for name, (n, _) in
                   sorted(data["lateral"].items(), key=lambda kv: (-kv[1][0], kv[1][1]))}
        pivots = [r["ip"] for r in reachable if self.max_sev.get(r["ip"], 0) >= 3]
        b = {
            "reachable_count": len(reachable), "direct_count": len(direct),
            "reachable": reachable[:50], "vulnerable_pivots": pivots,
            "lateral_protocols": lateral,
            "external_destinations": data["ext_total"],
            "top_external_destinations": data["ext_top"],
        }
        b["factor"] = round(1 + min(0.5, 0.04 * len(direct) + 0.02 * (len(reachable) - len(direct))
                                    + 0.08 * len(pivots) + (0.1 if lateral else 0)), 2)
        self._blast_cache[host] = b
        return b

    # -- exploitation indicators -----------------------------------------
    # Every network pattern on its own is a "lead": worth investigating, not proof.
    # A finding is "corroborated" only when an IPS/IDS alert and post-contact host
    # behaviour agree. Even then only host forensics can confirm a compromise.
    def _threats_to(self, fd: Finding) -> tuple[list, list]:
        """(alerts that passed, alerts that were blocked) on this finding's service, in time
        order, from the join in prepare()."""
        return self._kalerts.get(self._kid[self._key(fd)], ((), ()))

    def _return_peers(self, kid: int) -> list[tuple]:
        """[(peer, first contact, sessions back, ports)] in first-contact order."""
        out = []
        for ip, t0 in self._contact.get(kid, []):
            back = self._returns.get((kid, ip))
            if back:
                out.append((ip, t0, back[0], back[1]))
        return out

    def _anchor(self, fd: Finding, kid: int):
        # Anchor "after" checks on contact that triggered a return connection or an alert. A
        # service the whole internet uses has no meaningful "first contact", so otherwise we only
        # anchor when very few outside addresses reached it.
        contact = self._contact.get(kid, [])
        if not contact:
            return None
        alerts, _ = self._threats_to(fd)
        flagged = {p[0] for p in self._return_peers(kid)} | {t.src_ip for t in alerts}
        anchors = [t for ip, t in contact if t and (ip in flagged or (not flagged and len(contact) <= 3))]
        return min(anchors) if anchors else None

    def indicators(self, fd: Finding, exp: dict) -> list[dict]:
        found = []
        kid = exp["_kid"]
        # a host already flagged for investigation newly reached this vulnerable service
        if kid in self._spread:
            src, port, proto, ts = self._spread[kid]
            found.append({"type": "lateral_spread", "confidence": "lead", "peer": src,
                          "port": port, "proto": proto, "text":
                          f"{src}, which is flagged for investigation, newly connected to this "
                          f"vulnerable service at {_iso(ts) or 'an unknown time'}. Check this host "
                          f"for signs of lateral movement."})
        alerts, _ = self._threats_to(fd)
        if alerts:
            names = sorted({t.name for t in alerts})
            cve_hit = sorted({c for c in fd.cves for t in alerts if c.lower() in t.name.lower()})
            srcs = sorted({t.src_ip for t in alerts})
            found.append({"type": "threat_alert", "confidence": "lead",
                          "sources": [[ip, n] for ip, n in Counter(t.src_ip for t in alerts).most_common()],
                          "text":
                          f"IPS/IDS alerted {len(alerts)} time(s) on traffic to this service and did not block it: "
                          f"{'; '.join(names[:3])}{' ...' if len(names) > 3 else ''} (from {', '.join(srcs[:4])})"
                          + (f", matching {', '.join(cve_hit)}" if cve_hit else "")
                          + ". An alert shows an attempt, not that it succeeded."})
        if not self._contact.get(kid):
            return found
        # 1. the vulnerable host later connects out to the same outside address that reached the service
        for ip, t0, n, port_list in self._return_peers(kid):
            ports = sorted({str(p) for p in port_list})
            found.append({"type": "return_connection", "confidence": "lead", "at": _iso(t0), "peer": ip,
                          "ports": sorted(set(port_list)), "text":
                          f"{fd.host_ip} opened {n} outbound connection(s) to {ip} "
                          f"(port {', '.join(ports)}) after {ip} connected to the vulnerable service. "
                          f"This is consistent with an exploit callback, but on its own it can also be "
                          f"legitimate traffic; confirm with IPS/threat logs, payload or application logs, "
                          f"or host evidence."})
        t0 = self._anchor(fd, kid)
        if t0 is not None:
            # 2. new lateral movement that only starts after outside contact
            targets = self._new_lat.get(kid) if self._before.get(kid) else None
            if targets:
                protos = sorted({LATERAL_PORTS[p] for ps in targets.values() for p in ps})
                found.append({"type": "new_lateral", "confidence": "lead", "at": _iso(t0),
                              "targets": [{"ip": ip, "ports": sorted(ps)} for ip, ps in sorted(targets.items())],
                              "text":
                              f"After the flagged inbound contact at {_iso(t0)}, {fd.host_ip} "
                              f"began connecting to {len(targets)} internal host(s) it had not talked to "
                              f"before, over {', '.join(protos)}."})
            # 3. large uploads to the internet after outside contact
            for ip, n in self._exfil.get(kid, []):
                found.append({"type": "exfil", "confidence": "lead", "at": _iso(t0), "peer": ip, "bytes": n,
                              "text":
                              f"{fd.host_ip} sent {n / 1048576:.1f} MB to external address {ip} "
                              f"after the flagged inbound contact at {_iso(t0)}."})
        # Corroboration: an alert on this service plus post-contact behaviour from the host.
        behaviour = [i for i in found if i["type"] in ("return_connection", "new_lateral", "exfil")]
        if alerts and behaviour:
            peers = {i.get("peer") for i in behaviour if i.get("peer")}
            same = sorted({t.src_ip for t in alerts} & peers)
            found.append({"type": "corroborated", "confidence": "corroborated",
                          "at": min((i["at"] for i in behaviour if i.get("at")), default=None), "text":
                          "Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service"
                          + (f" from {', '.join(same)}, the same address the host then connected back to" if same else "")
                          + f", and the host then showed {', '.join(sorted({i['type'].replace('_', ' ') for i in behaviour}))}. "
                          "Treat this as likely exploitation and start incident response; host forensics is "
                          "still needed to confirm a compromise."})
        return found

    # -- scoring ----------------------------------------------------------
    def score(self, fd: Finding) -> dict:
        exp = self.exposure(fd)
        bl = self.blast(fd.host_ip)
        ind = self.indicators(fd, exp)
        cvss = fd.cvss if fd.cvss is not None else SEVERITY_CVSS.get(fd.severity, 0)
        e_factor = (1.0 + (0.1 if fd.exploit_frameworks else 0)) if fd.exploit_available else 0.65
        raw = cvss * 10 * e_factor * exp["factor"] * bl["factor"]
        if any(i["confidence"] == "corroborated" for i in ind):
            raw *= 1.25
        elif ind:
            raw *= 1.1
        score = int(min(100, round(raw)))
        likelihood = e_factor * exp["factor"]
        why = [f"Base severity: CVSS{fd.cvss_version and ' v' + fd.cvss_version} {cvss:.1f} ({fd.severity_name})."]
        if fd.exploit_available:
            fw = f" ({', '.join(fd.exploit_frameworks)})" if fd.exploit_frameworks else ""
            why.append(f"A public exploit is available{fw}.")
        else:
            why.append("No public exploit is known to the scanner.")
        why.append(f"Exposure: {exp['label'].lower()}"
                   + (f" - {exp['established']} completed sessions from {exp['external_sources']} "
                      f"external and {exp['internal_sources']} internal sources." if exp["established"] else "."))
        if exp["denied"]:
            why.append(f"{exp['denied']} connection(s) to it were blocked by a firewall.")
        if exp["refused"]:
            why.append(f"{exp['refused']} connection(s) to it were refused by the host (reset, as Zeek logs REJ).")
        if bl["reachable_count"]:
            why.append(f"Blast radius: the host talks to {bl['direct_count']} internal host(s) directly and "
                       f"{bl['reachable_count']} within {self.cfg.hops} hops"
                       + (f", including {len(bl['vulnerable_pivots'])} with High/Critical findings." if bl["vulnerable_pivots"] else "."))
        if exp["threat_blocked"]:
            why.append(f"The IPS/IDS blocked {exp['threat_blocked']} alerted attempt(s) against it.")
        if any(i["confidence"] == "corroborated" for i in ind):
            why.append("Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.")
        elif ind:
            why.append("Traffic gives leads worth investigating; nothing in the logs confirms exploitation.")
        exp_public = {k: v for k, v in exp.items() if not k.startswith("_")}
        return {
            "host": fd.host_ip, "hostname": fd.hostname, "os": fd.os,
            "plugin_id": fd.plugin_id, "plugin_name": fd.plugin_name,
            "severity": fd.severity, "severity_name": fd.severity_name,
            "port": fd.port, "proto": fd.proto, "service": fd.service,
            "cvss": cvss, "cves": fd.cves, "exploit_available": fd.exploit_available,
            "exploit_frameworks": fd.exploit_frameworks, "synopsis": fd.synopsis,
            "solution": fd.solution, "source": fd.source,
            "exposure": exp_public, "blast_factor": bl["factor"], "exploit_factor": e_factor,
            "likelihood": "High" if likelihood >= 0.75 else "Medium" if likelihood >= 0.45 else "Low",
            "score": score, "priority": _priority(score, ind), "indicators": ind, "rationale": why,
        }

    # -- whole run --------------------------------------------------------
    def run(self) -> dict:
        ds, cfg = self.ds, self.cfg
        vulnerability_data_available = bool(ds.findings)
        todo = [fd for fd in ds.findings if fd.severity >= cfg.min_severity]
        self.prepare(todo)
        self.prepare_blast(sorted({fd.host_ip for fd in todo}))
        scored = [self.score(fd) for fd in todo]
        # second pass: hosts flagged for investigation make the vulnerable services they reach riskier
        for r in scored:
            for i in r["indicators"]:
                if i["type"] in ("return_connection", "corroborated"):
                    t = datetime.fromisoformat(i["at"].replace("Z", "+00:00")) if i.get("at") else None
                    cur = self.suspects.get(r["host"], "no")
                    if cur == "no" or (t and cur and t < cur):
                        self.suspects[r["host"]] = t
        if self.suspects:
            self.prepare_spread()
            scored = [self.score(fd) for fd in todo]
        scored.sort(key=lambda r: (r["priority"], -r["score"], -r["severity"], r["host"]))

        hosts = {}
        for r in scored:
            h = hosts.setdefault(r["host"], {
                "host": r["host"], "hostname": r["hostname"], "os": r["os"], "findings": 0,
                "by_severity": Counter(), "max_score": 0, "priority": "P4",
                "internet_exposed": False, "indicators": 0, "blast": self.blast(r["host"]),
                "telemetry_seen": r["exposure"]["telemetry_seen"],
                "inbound_flows": self.in_count.get(r["host"], 0),
                "outbound_flows": self.out_count.get(r["host"], 0),
            })
            h["findings"] += 1
            h["by_severity"][r["severity_name"]] += 1
            h["max_score"] = max(h["max_score"], r["score"])
            h["priority"] = min(h["priority"], r["priority"])
            h["internet_exposed"] |= r["exposure"]["external_sources"] > 0 and r["exposure"]["scope"] == "port"
            h["indicators"] += len(r["indicators"])
        host_list = sorted(hosts.values(), key=lambda h: (h["priority"], -h["max_score"], h["host"]))
        if not vulnerability_data_available:
            # Keep observed internal hosts navigable without assigning a vulnerability score.
            telemetry_hosts = sorted(self.live_ips | {ip for t in ds.threats
                                                      for ip in (t.src_ip, t.dst_ip)
                                                      if self.net.internal(ip)})
            self.prepare_blast(telemetry_hosts)
            for ip in telemetry_hosts:
                hosts[ip] = {"host": ip, "hostname": "", "os": "", "findings": 0,
                             "by_severity": {}, "max_score": None, "priority": None,
                             "internet_exposed": None, "indicators": 0, "blast": self.blast(ip),
                             "telemetry_seen": True, "inbound_flows": self.in_count.get(ip, 0),
                             "outbound_flows": self.out_count.get(ip, 0)}
            host_list = list(hosts.values())
        for h in host_list:
            h["by_severity"] = dict(h["by_severity"])

        internal_seen = set(self.internal_ips)
        # a scanned host counts as seen whenever it is in the telemetry, internal address or not
        # (DMZ hosts on public addresses are scanned too)
        seen_scanned = set(self.in_count) | set(self.out_count)
        if not vulnerability_data_available:
            internal_seen |= {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip)
                              if self.net.internal(ip)}
        servers: dict[str, list] = defaultdict(list)     # ip -> [(service, sessions)] most used first
        for ip, svc, n in self.con.execute(MODEL("unscanned_servers")).fetchall():
            servers[ip].append((svc, int(n)))
        scanned = set(ds.scanned_hosts)
        alert_ips = {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip) if self.net.internal(ip)}
        live = self.live_ips | (alert_ips if not vulnerability_data_available else set())
        # subnet broadcasts are not hosts, nor addresses that failed to answer
        probed_only = self.internal_ips - live - scanned - self.store.broadcast_ips()
        probed_subnets = Counter(scanners.subnet(ip) for ip in probed_only)
        n_sessions, n_answered = self.store.answered_share()
        sessions = {ip: sum(n for _, n in svcs) for ip, svcs in servers.items()}
        not_scanned = sorted(set(servers) - scanned, key=lambda ip: (-sessions[ip], ip))
        coverage = {
            "scanned_hosts": len(scanned), "telemetry_internal_hosts": len(live),
            "probed_only_addresses": len(probed_only),
            # of those, addresses a firewall log shows traffic to being blocked
            "probed_blocked_addresses": len(probed_only & self.store.firewall_blocked_ips()),
            # where the unanswered probing went: [subnet, addresses], most probed first
            "probed_only_subnets": [[sn, n] for sn, n in sorted(probed_subnets.items(),
                                                                 key=lambda kv: (-kv[1], kv[0]))[:200]],
            "sessions_answered_pct": round(100 * n_answered / n_sessions, 1) if n_sessions else None,
            # highest packet loss Zeek estimated (capture_loss.log / CaptureLoss notice), in percent
            "capture_loss_pct": self._capture_loss(),
            # almost nothing answered: the sensor probably sees only one direction of the traffic
            "one_way_capture_suspected": n_sessions >= scanners.ONE_WAY_MIN_SESSIONS
                                         and n_answered < scanners.ONE_WAY_MAX_ANSWERED * n_sessions,
            "scanned_and_seen": len(scanned & (internal_seen | seen_scanned)),
            "scanned_not_seen": sorted(scanned - internal_seen - seen_scanned),
            "active_servers_not_scanned": [
                {"ip": ip, "services": [p for p, _ in servers[ip][:6]],
                 "sessions": sessions[ip]} for ip in not_scanned],
        }
        kinds = defaultdict(set)
        for r in scored:
            kinds[r["host"]] |= {i["type"] for i in r["indicators"]}
        corroborated = {h for h, k in kinds.items() if "corroborated" in k}
        spread = {h for h, k in kinds.items() if k == {"lateral_spread"}}
        investigate = {h for h, k in kinds.items() if k} - corroborated - spread
        t_min, t_max = self.con.execute("SELECT min(ts), max(ts) FROM flows").fetchone()
        times = [utc(t) for t in (t_min, t_max) if t] + [t.ts for t in ds.threats if t.ts]
        pc = Counter(r["priority"] for r in scored)
        traffic_scanners = scanners.detect(self.con, ds.threats, self.net.internal,
                                           scanners.Known(self.cfg.known_scanner_list, self.scanner_ips))
        summary = {
            "vulnerability_data_available": vulnerability_data_available,
            "flows": len(ds.flows), "findings_total": len(ds.findings), "findings_scored": len(scored),
            "hosts_with_findings": len({r["host"] for r in scored}),
            "priority_counts": {p: pc.get(p, 0) if vulnerability_data_available else None
                                for p in ("P1", "P2", "P3", "P4")},
            "internet_exposed_findings": (sum(1 for r in scored if r["exposure"]["external_sources"]
                                              and r["exposure"]["scope"] == "port")
                                          if vulnerability_data_available else None),
            "exploitable_and_exposed": (sum(1 for r in scored if r["exploit_available"]
                                            and r["exposure"]["established"] and r["exposure"]["scope"] == "port")
                                        if vulnerability_data_available else None),
            "hosts_with_indicators": sorted({r["host"] for r in scored if r["indicators"]}),
            "hosts_corroborated": sorted(corroborated),
            "hosts_to_investigate": sorted(investigate),
            "hosts_possible_spread": sorted(spread),
            "threat_alerts": len(ds.threats),
            "zeek_event_counts": dict(sorted((k, n) for k, n in _counts(ds.zeek_events, "stream").items()
                                             if k != "capture_loss")),
            "ot_protocol_counts": dict(sorted(_counts(ds.ot_events, "protocol").items())),
            "hosts_internet_exposed": sum(1 for h in host_list if h["internet_exposed"]),
            "window_start": _iso(min(times)) if times else None,
            "window_end": _iso(max(times)) if times else None,
            "duplicate_flows_removed": ds.duplicate_flows,
            "cross_sensor_duplicates_removed": ds.cross_sensor_duplicates,
            "duplicate_findings_merged": ds.duplicate_findings,
            "scanner_ips": self.scanner_ips,
            "scanner_sessions_excluded": int(self.scanner_sessions),
            "traffic_scanners": traffic_scanners[:scanners.MAX_LISTED],
            "traffic_scanners_total": len(traffic_scanners),
        }
        network_leads = []
        if not vulnerability_data_available:
            rows = self.con.execute(MODEL("network_leads")).fetchall()
            for host, peer, n in sorted(r for r in rows if r[0] in hosts):
                network_leads.append({"host": host, "peer": peer, "sessions": int(n),
                                      "note": "Host connected to an outside address after inbound contact; this may be legitimate traffic."})
        return {
            "schema_version": RESULTS_SCHEMA_VERSION,
            "generated": _iso(datetime.now(timezone.utc)),
            "config": {"internal_nets": cfg.internal_nets, "hops": cfg.hops,
                       "min_severity": SEVERITY_NAMES[cfg.min_severity]},
            "inputs": [{"file": s.file, "format": s.fmt, "read": s.read, "kept": s.kept,
                        "dropped": dict(s.dropped), "notes": s.notes} for s in ds.stats],
            "summary": summary, "coverage": coverage, "hosts": host_list, "findings": scored,
            "telemetry_leads": self._telemetry_leads() if not vulnerability_data_available else [],
            "network_leads": network_leads,
        }

    def _telemetry_leads(self) -> list[dict]:
        """IPS/IDS alerts grouped by the internal hosts involved: the target and the internal source
        (an internal host that set off an alert, towards an outside address or another internal host)."""
        by_host: dict[str, list] = defaultdict(list)
        role: dict[str, set] = defaultdict(set)
        for t in self.ds.threats:
            if self.net.internal(t.dst_ip):
                by_host[t.dst_ip].append(t)
                role[t.dst_ip].add("target")
            # the internal source is listed too, also when the target is internal (lateral movement)
            if self.net.internal(t.src_ip) and t.src_ip != t.dst_ip:
                by_host[t.src_ip].append(t)
                role[t.src_ip].add("source")
        return [{"host": ip, "alerts": len(alerts), "unblocked": sum(not t.blocked for t in alerts),
                 "blocked": sum(t.blocked for t in alerts), "role": sorted(role[ip]),
                 "signatures": sorted({t.name for t in alerts}),
                 "note": "IPS/IDS alerts are investigation leads, not verified exploitation."}
                for ip, alerts in sorted(by_host.items())]


def correlate(ds: Dataset, cfg: Config | None = None) -> dict:
    return Correlator(ds, cfg or Config()).run()
