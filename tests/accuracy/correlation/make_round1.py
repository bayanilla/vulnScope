"""Ground-truth dataset for Zeek + Nessus correlation accuracy in VulnScope.

Writes data/ (inputs) and expected.json (hand-derived answers, one per scenario).
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

OUT = sys.argv[1]
D = os.path.join(OUT, "data")
os.makedirs(os.path.join(D, "sensor_a"), exist_ok=True)
os.makedirs(os.path.join(D, "sensor_b"), exist_ok=True)

SCAN = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)
uid = 0
conn_a = []      # sensor A, Zeek TSV
conn_b = []      # sensor B, Zeek JSON (a second tap)


def ts(t):
    return f"{t.timestamp():.6f}"


def c(t, src, sport, dst, dport, proto="tcp", state="SF", ob=500, rb=4000, history="ShADadFf",
      service="-", sink=None):
    global uid
    uid += 1
    row = dict(ts=t, uid=f"CGT{uid:05d}", src=src, sport=sport, dst=dst, dport=dport, proto=proto,
               state=state, ob=ob, rb=rb, history=history, service=service)
    (conn_a if sink is None else sink).append(row)
    return row


m = lambda minutes: T0 + timedelta(minutes=minutes)

# A  web01 10.60.0.10: Critical 443 reached from 3 outside addresses + 1 inside, alert + callback
for i, ip in enumerate(["203.0.113.5", "203.0.113.6", "203.0.113.7"]):
    for k in range(2):
        c(m(60 + i * 10 + k), ip, 40000 + i * 10 + k, "10.60.0.10", 443, service="ssl")
c(m(200), "10.60.1.50", 51000, "10.60.0.10", 443, service="ssl")
c(m(75), "10.60.0.10", 52000, "203.0.113.5", 4444, rb=300)                    # callback after first contact (m60)
# B  10.60.0.11: High 445 reached by 6 internal clients
for i in range(1, 7):
    c(m(300 + i), f"10.60.1.{i}", 50000 + i, "10.60.0.11", 445, service="smb")
# C  10.60.0.12: High 3389 from 2 clients; .20's session also seen by sensor B 0.4 s later;
#    .21's line repeated verbatim in sensor A (exact duplicate)
r20 = c(m(400), "10.60.1.20", 53000, "10.60.0.12", 3389, service="rdp")
r21 = c(m(401), "10.60.1.21", 53001, "10.60.0.12", 3389, service="rdp")
conn_a.append(dict(r21))
dup = dict(r20, ts=r20["ts"] + timedelta(milliseconds=400), uid="CGTB0001")
conn_b.append(dup)
# D  10.60.0.13: High 22, only REJ (host answered with RST) from one outside address, 3 times
for k in range(3):
    c(m(500 + k), "198.51.100.66", 41000 + k, "10.60.0.13", 22, state="REJ", ob=0, rb=0, history="Sr")
# E  10.60.0.14: Medium 21, only S0 (no answer) from an inside client, 4 times
for k in range(4):
    c(m(520 + k), "10.60.1.30", 42000 + k, "10.60.0.14", 21, state="S0", ob=0, rb=0, history="S")
# F  10.60.0.15: scanned, never in telemetry
# G  10.60.0.16: host-level finding; host only talks outbound (to B's SMB)
c(m(600), "10.60.0.16", 43000, "10.60.0.11", 445, service="smb")
# H  10.60.0.200: unscanned server, 3 internal clients on 80
for i in range(3):
    c(m(620 + i), f"10.60.1.{70 + i}", 44000 + i, "10.60.0.200", 80, service="http")
# I  db01.corp.local (host-ip 10.60.0.17): High 1433, one internal client
c(m(640), "10.60.1.40", 45000, "10.60.0.17", 1433)
# J  files02.corp.local: scanned by NAME only (no host-ip); dns.log maps it to 10.60.0.18; traffic to 445
c(m(660), "10.60.1.41", 45100, "10.60.0.18", 445, service="smb")
# K  10.60.0.19: High 161/udp; 2 internal UDP clients, 1 outside TCP/161 session (must not count)
c(m(680), "10.60.1.42", 45200, "10.60.0.19", 161, proto="udp", history="Dd", ob=80, rb=200)
c(m(681), "10.60.1.43", 45201, "10.60.0.19", 161, proto="udp", history="Dd", ob=80, rb=200)
c(m(682), "203.0.113.40", 45202, "10.60.0.19", 161, proto="tcp")
# L  10.60.0.20: High 443; outside traffic only 31 days before the scan (outside the 7-day window)
c(SCAN - timedelta(days=31), "203.0.113.9", 46000, "10.60.0.20", 443, service="ssl")
# M  fd00::21: High 443 reached from outside over IPv6 (Zeek writes the expanded form here)
c(m(700), "2001:db8::5", 46100, "fd00:0:0:0:0:0:0:21", 443, service="ssl")
# N  10.60.0.22: Medium 443; mid-stream session (OTH, no handshake seen) with data both ways
c(m(720), "203.0.113.20", 46200, "10.60.0.22", 443, state="OTH", history="Dd", ob=900, rb=9000)
# O  198.51.100.10: public-address DMZ host, High 443; outside + inside clients
c(m(740), "203.0.113.30", 46300, "198.51.100.10", 443, service="ssl")
c(m(741), "10.60.1.60", 46301, "198.51.100.10", 443, service="ssl")

# ---- write Zeek TSV (sensor A) and JSON (sensor B)
hdr = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
       "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory",
       "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring"]
with open(os.path.join(D, "sensor_a", "conn.log"), "w") as fh:
    fh.write("\n".join(hdr) + "\n")
    for r in sorted(conn_a, key=lambda r: r["ts"]):
        fh.write("\t".join(map(str, [ts(r["ts"]), r["uid"], r["src"], r["sport"], r["dst"], r["dport"], r["proto"],
                                     r["service"], "1.0", r["ob"], r["rb"], r["state"], r["history"]])) + "\n")
with open(os.path.join(D, "sensor_b", "conn.log"), "w") as fh:
    for r in conn_b:
        fh.write(json.dumps({"ts": r["ts"].timestamp(), "uid": r["uid"], "id.orig_h": r["src"], "id.orig_p": r["sport"],
                             "id.resp_h": r["dst"], "id.resp_p": r["dport"], "proto": r["proto"], "service": r["service"],
                             "duration": 1.0, "orig_bytes": r["ob"], "resp_bytes": r["rb"], "conn_state": r["state"],
                             "history": r["history"]}) + "\n")
with open(os.path.join(D, "sensor_a", "notice.log"), "w") as fh:
    fh.write(json.dumps({"ts": m(61).timestamp(), "note": "Signatures::Sensitive_Signature",
                         "msg": "Possible exploit attempt CVE-2026-1111", "src": "203.0.113.5",
                         "dst": "10.60.0.10", "p": 443, "actions": ["Notice::ACTION_LOG"]}) + "\n")
    fh.write(json.dumps({"ts": m(501).timestamp(), "note": "SSH::Password_Guessing", "msg": "brute force",
                         "src": "198.51.100.66", "dst": "10.60.0.13", "p": 22,
                         "actions": ["Notice::ACTION_DROP"]}) + "\n")
with open(os.path.join(D, "sensor_a", "dns.log"), "w") as fh:
    fh.write(json.dumps({"ts": m(659).timestamp(), "uid": "CDNS1", "id.orig_h": "10.60.1.41", "id.orig_p": 5353,
                         "id.resp_h": "10.60.0.53", "id.resp_p": 53, "proto": "udp", "query": "files02.corp.local",
                         "qtype_name": "A", "answers": ["10.60.0.18"]}) + "\n")


# ---- Nessus
def item(port, proto, sev, pid, name, cvss, exploit=False, msf=False, cves=(), svc="www"):
    x = f'<ReportItem port="{port}" svc_name="{svc}" protocol="{proto}" severity="{sev}" pluginID="{pid}" pluginName="{name}" pluginFamily="General">'
    x += f"<cvss3_base_score>{cvss}</cvss3_base_score><exploit_available>{'true' if exploit else 'false'}</exploit_available>"
    if msf:
        x += "<exploit_framework_metasploit>true</exploit_framework_metasploit>"
    x += "".join(f"<cve>{v}</cve>" for v in cves)
    x += "<synopsis>test</synopsis><solution>patch</solution></ReportItem>"
    return x


def host(name, items, ip=None, fqdn=None, start=SCAN):
    tags = [f'<tag name="HOST_START_TIMESTAMP">{int(start.timestamp())}</tag>',
            f'<tag name="HOST_END_TIMESTAMP">{int((start + timedelta(minutes=20)).timestamp())}</tag>']
    if ip:
        tags.append(f'<tag name="host-ip">{ip}</tag>')
    if fqdn:
        tags.append(f'<tag name="host-fqdn">{fqdn}</tag>')
    return f'<ReportHost name="{name}"><HostProperties>{"".join(tags)}</HostProperties>{"".join(items)}</ReportHost>'


def nessus(path, hosts):
    with open(path, "w") as fh:
        fh.write('<?xml version="1.0" ?><NessusClientData_v2><Report name="gt">' + "".join(hosts) + "</Report></NessusClientData_v2>")


nessus(os.path.join(D, "scan_main.nessus"), [
    host("10.60.0.10", [item(443, "tcp", 4, "900001", "WebApp RCE", 9.8, True, True, ["CVE-2026-1111"]),
                        item(8080, "tcp", 2, "900002", "Admin console info leak", 5.3)], ip="10.60.0.10", fqdn="web01.corp.local"),
    host("10.60.0.11", [item(445, "tcp", 3, "900003", "SMB flaw", 8.1, True, svc="cifs")], ip="10.60.0.11"),
    host("10.60.0.12", [item(3389, "tcp", 3, "900004", "RDP flaw", 8.1, svc="msrdp")], ip="10.60.0.12"),
    host("10.60.0.13", [item(22, "tcp", 3, "900005", "SSH flaw", 7.5, svc="ssh")], ip="10.60.0.13"),
    host("10.60.0.14", [item(21, "tcp", 2, "900006", "FTP flaw", 5.0, svc="ftp")], ip="10.60.0.14"),
    host("10.60.0.15", [item(80, "tcp", 3, "900007", "HTTP flaw", 7.5)], ip="10.60.0.15"),
    host("10.60.0.16", [item(0, "tcp", 2, "900008", "Missing OS patch", 6.5, svc="general")], ip="10.60.0.16"),
    host("db01.corp.local", [item(1433, "tcp", 3, "900009", "MSSQL flaw", 8.8, svc="mssql")], ip="10.60.0.17", fqdn="db01.corp.local"),
    host("files02.corp.local", [item(445, "tcp", 3, "900010", "SMB flaw (name-only scan)", 8.1, svc="cifs")]),
    host("10.60.0.19", [item(161, "udp", 3, "900011", "SNMP default community", 7.5, svc="snmp")], ip="10.60.0.19"),
    host("10.60.0.20", [item(443, "tcp", 3, "900012", "TLS flaw", 7.4)], ip="10.60.0.20"),
    host("fd00::21", [item(443, "tcp", 3, "900013", "IPv6 web flaw", 7.5)], ip="fd00::21"),
    host("10.60.0.22", [item(443, "tcp", 2, "900014", "Weak TLS", 5.9)], ip="10.60.0.22"),
    host("198.51.100.10", [item(443, "tcp", 3, "900015", "DMZ web flaw", 8.6, True)], ip="198.51.100.10"),
])
# Older overlapping scan: web01 again, same plugin, recorded before an exploit was published
nessus(os.path.join(D, "scan_old.nessus"), [
    host("10.60.0.10", [item(443, "tcp", 4, "900001", "WebApp RCE", 9.8, False)], ip="10.60.0.10",
         start=SCAN - timedelta(days=3)),
])

W = "web01.corp.local"
expected = {
    "A web01 443 internet + alert + callback": {"host": "10.60.0.10", "port": 443, "label": "Vulnerable service reached from the internet",
        "established": 7, "external_sources": 3, "internal_sources": 1, "denied": 0, "attempts": 0,
        "exploit_available": True, "indicators": ["threat_alert", "return_connection", "corroborated"], "priority": "P1", "hostname": W},
    "A web01 8080 unused": {"host": "10.60.0.10", "port": 8080, "label": "Service not observed in use",
        "established": 0, "external_sources": 0, "internal_sources": 0},
    "B SMB 6 internal clients + host G": {"host": "10.60.0.11", "port": 445, "label": "Vulnerable service reached internally by many hosts",
        "established": 7, "internal_sources": 7, "external_sources": 0},
    "C RDP two clients, one also seen by 2nd sensor, one exact dup": {"host": "10.60.0.12", "port": 3389,
        "label": "Vulnerable service reached internally", "established": 2, "internal_sources": 2},
    "D SSH only REJ (host refused, no firewall involved)": {"host": "10.60.0.13", "port": 22,
        "label": "Connections to service refused by the host",
        "established": 0, "denied": 0, "refused": 3, "threat_blocked": 1},
    "E FTP only S0 (no answer)": {"host": "10.60.0.14", "port": 21, "label": "Connection attempts only (no completed sessions)",
        "established": 0, "attempts": 4, "denied": 0},
    "F no telemetry": {"host": "10.60.0.15", "port": 80, "label": "No telemetry for this host (unknown)", "telemetry_seen": False},
    "G host-level, outbound only": {"host": "10.60.0.16", "port": 0, "label": "Host is active on the network"},
    "I scanned by FQDN with host-ip": {"host": "10.60.0.17", "port": 1433, "label": "Vulnerable service reached internally",
        "established": 1, "hostname": "db01.corp.local"},
    "J scanned by name only; dns.log knows its IP": {"host": "10.60.0.18", "port": 445,
        "label_truth": "Vulnerable service reached internally (needs dns.log name->IP join)"},
    "K SNMP udp/161; tcp/161 traffic must not count": {"host": "10.60.0.19", "port": 161, "proto": "udp",
        "label": "Vulnerable service reached internally", "established": 2, "internal_sources": 2, "external_sources": 0},
    "L traffic only 31 days before scan": {"host": "10.60.0.20", "port": 443, "label": "Service not observed in use",
        "established": 0, "external_sources": 0},
    "M IPv6 host, expanded address in Zeek": {"host": "fd00::21", "port": 443, "label": "Vulnerable service reached from the internet",
        "established": 1, "external_sources": 1},
    "N mid-stream OTH with data both ways": {"host": "10.60.0.22", "port": 443, "label": "Vulnerable service reached from the internet",
        "established": 1, "external_sources": 1},
    "O public-address DMZ host": {"host": "198.51.100.10", "port": 443, "label": "Vulnerable service reached from the internet",
        "established": 2, "external_sources": 1, "internal_sources": 1, "telemetry_seen": True},
}
summary_expected = {
    "scanned_hosts": 14,  # 13 by IP + files02 by name
    "scanned_not_seen": ["10.60.0.15"],
    "active_servers_not_scanned": ["10.60.0.200"],
    "duplicate_findings_merged": 1,
    "duplicate_flows_removed_at_least": 1,
    "sessions_counted_once_across_sensors": 1,
}
json.dump({"findings": expected, "summary": summary_expected}, open(os.path.join(OUT, "expected.json"), "w"), indent=2)
print("conn A", len(conn_a), "conn B", len(conn_b))
