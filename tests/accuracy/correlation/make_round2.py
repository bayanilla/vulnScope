"""Round 2 ground truth: harder Zeek + Nessus cases, plus a telemetry-only folder.

Writes round2/data, round2/expected.json, telemetry_only/data, telemetry_only/expected.json.
"""
import gzip
import json
import os
import sys
from datetime import datetime, timedelta, timezone

OUT = sys.argv[1]
SCAN = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
SCAN_END = SCAN + timedelta(minutes=20)
DAY = timedelta(days=1)
_uid = [0]


def zj(t, src, sport, dst, dport, proto="tcp", state="SF", ob=500, rb=4000):
    _uid[0] += 1
    return json.dumps({"ts": round(t.timestamp(), 6), "uid": f"CR{_uid[0]:05d}", "id.orig_h": src, "id.orig_p": sport,
                       "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "conn_state": state,
                       "orig_bytes": ob, "resp_bytes": rb, "duration": 1.0}) + "\n"


TSV_HDR = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\n"
           "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\n")


def zt(t, src, sport, dst, dport, proto="tcp", state="SF", ob="500", rb="4000"):
    _uid[0] += 1
    return "\t".join(map(str, [f"{t.timestamp():.6f}", f"CT{_uid[0]:05d}", src, sport, dst, dport, proto, "-", "1.0",
                               ob, rb, state, "ShADadFf"])) + "\n"


def item(port, proto, sev, pid, name, cvss, exploit=False, output=""):
    x = (f'<ReportItem port="{port}" svc_name="x" protocol="{proto}" severity="{sev}" pluginID="{pid}" '
         f'pluginName="{name}" pluginFamily="General"><cvss3_base_score>{cvss}</cvss3_base_score>'
         f"<exploit_available>{'true' if exploit else 'false'}</exploit_available>")
    if output:
        x += f"<plugin_output>{output}</plugin_output>"
    return x + "<synopsis>t</synopsis><solution>patch</solution></ReportItem>"


def host(ip, items, start=SCAN, netbios=None):
    tags = (f'<tag name="host-ip">{ip}</tag><tag name="HOST_START_TIMESTAMP">{int(start.timestamp())}</tag>'
            f'<tag name="HOST_END_TIMESTAMP">{int((start + timedelta(minutes=20)).timestamp())}</tag>')
    if netbios:
        tags += f'<tag name="netbios-name">{netbios}</tag>'
    return f'<ReportHost name="{ip}"><HostProperties>{tags}</HostProperties>{"".join(items)}</ReportHost>'


def write(path, text, gz=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with (gzip.open(path, "wt") if gz else open(path, "w")) as fh:
        fh.write(text)


# =============================================================== round 2
D = os.path.join(OUT, "round2", "data")
t = SCAN + timedelta(hours=1)
a, b, gz_tsv, plain_tsv, notice = [], [], [], [], []
SCANNER = "10.70.9.9"
SCAN_INFO = ("Information about this scan : Nessus version : 10.8.3 Scanner IP : 10.70.9.9 "
             "Port scanner(s) : nessus_syn_scanner")

# R1 the scanner's own probes are the only traffic to 8443
a += [zj(SCAN + timedelta(minutes=3), SCANNER, 60001, "10.70.0.10", 8443),
      zj(SCAN + timedelta(minutes=3), SCANNER, 60002, "10.70.0.10", 8444, state="REJ", ob=0, rb=0)]
# R2 scan-window edges (7 days): exactly on each edge counts, one second outside does not
a += [zj(SCAN - 7 * DAY, "203.0.113.101", 1101, "10.70.0.11", 443),
      zj(SCAN - 7 * DAY - timedelta(seconds=1), "203.0.113.102", 1102, "10.70.0.11", 443),
      zj(SCAN_END + 7 * DAY, "203.0.113.103", 1103, "10.70.0.11", 443),
      zj(SCAN_END + 7 * DAY + timedelta(seconds=1), "203.0.113.104", 1104, "10.70.0.11", 443)]
# R3 host scanned 20 days ago and again now; traffic only near the newer scan
a += [zj(t, "203.0.113.110", 1110, "10.70.0.12", 443)]
# R4 reach threshold: 5 internal clients = "many", 4 = "internally"
a += [zj(t + timedelta(seconds=i), f"10.70.1.{i}", 2000 + i, "10.70.0.13", 445) for i in range(1, 6)]
a += [zj(t + timedelta(seconds=i), f"10.70.1.{10 + i}", 2100 + i, "10.70.0.14", 445) for i in range(1, 5)]
# R5 host talks to itself on its vulnerable port
a += [zj(t, "10.70.0.15", 2200, "10.70.0.15", 8080)]
# R6 alert on a different port of the same host (must not attach to the 22/tcp finding); SSH used internally
a += [zj(t, "10.70.1.30", 2300, "10.70.0.16", 22)]
notice.append({"ts": t.timestamp(), "note": "Sig", "msg": "MySQL brute force", "src": "203.0.113.120",
               "dst": "10.70.0.16", "p": 3306, "actions": ["Notice::ACTION_LOG"]})
# R7 host contacted the outside address only BEFORE that address reached it: no callback
a += [zj(t, "10.70.0.17", 2400, "203.0.113.130", 443), zj(t + timedelta(minutes=5), "203.0.113.130", 2401, "10.70.0.17", 443)]
#     ... and a host that connects back AFTER contact: callback lead
a += [zj(t, "203.0.113.131", 2402, "10.70.0.18", 443), zj(t + timedelta(minutes=5), "10.70.0.18", 2403, "203.0.113.131", 8443)]
# R8 25 MB upload to a different outside address after a single inbound contact
a += [zj(t, "203.0.113.140", 2500, "10.70.0.19", 443),
      zj(t + timedelta(minutes=10), "10.70.0.19", 2501, "198.51.100.200", 443, ob=25 * 1024 * 1024, rb=2000)]
# R9 UDP request with no reply (S0)
a += [zj(t, "10.70.1.40", 2600, "10.70.0.20", 161, proto="udp", state="S0", ob=80, rb=0)]
# R10 host only in a Nessus CSV export (no scan time): all telemetry counts, even 60 days old
a += [zj(t, "10.70.1.41", 2700, "10.70.0.21", 3389), zj(SCAN - 60 * DAY, "203.0.113.150", 2701, "10.70.0.21", 3389)]
# R11 rotated, gzipped Zeek TSV with a dated file name
gz_tsv += [zt(t, "10.70.1.42", 2800, "10.70.0.22", 80)]
# R12 Zeek TSV with unset byte counts and S1 (handshake done, still open)
plain_tsv += [zt(t, "203.0.113.160", 2900, "10.70.0.23", 25, state="S1", ob="-", rb="-")]
# R13 netbios name only -> hostname FILESRV (no traffic)
# R14 Info-only host with traffic: scanned, so not an "unscanned server"
a += [zj(t, "10.70.1.43", 3000, "10.70.0.25", 80)]
# R17 firewall deny + Zeek S0 for the same attempt (cross-sensor) -> one blocked attempt
a += [zj(t + timedelta(seconds=0.5), "203.0.113.170", 3100, "10.70.0.26", 3389, state="S0", ob=0, rb=0)]
pa = ("Receive Time,Type,Source address,Destination address,Source Port,Destination Port,IP Protocol,Action,"
      "Bytes Sent,Bytes Received,Start Time,Source Zone,Destination Zone,Application\n"
      f"{t:%Y/%m/%d %H:%M:%S},TRAFFIC,203.0.113.170,10.70.0.26,3100,3389,tcp,deny,60,0,{t:%Y/%m/%d %H:%M:%S},untrust,trust,incomplete\n")
# R18 asymmetric routing: tap A (read first) saw only the SYN (S0), tap B saw the full session
a += [zj(t, "10.70.1.50", 3200, "10.70.0.27", 5432, state="S0", ob=0, rb=0)]
b += [zj(t + timedelta(seconds=0.2), "10.70.1.50", 3200, "10.70.0.27", 5432)]

# R19 (PR review) scans 60 days apart: traffic halfway between them is outside both windows
a += [zj(SCAN - 30 * DAY, "203.0.113.180", 3300, "10.70.0.28", 443),
      zj(SCAN + timedelta(hours=2), "203.0.113.181", 3301, "10.70.0.28", 443)]
# R20 (PR review) two taps log the same session at the same instant: SYN-only copy read first
a += [zj(t, "10.70.1.51", 3400, "10.70.0.29", 5432, state="S0", ob=0, rb=0)]
b += [zj(t, "10.70.1.51", 3400, "10.70.0.29", 5432)]
write(os.path.join(D, "tap_a", "conn.log"), "".join(a))
write(os.path.join(D, "tap_b", "conn.log"), "".join(b))
write(os.path.join(D, "tap_a", "conn.2026-11-02-13-00-00.log.gz"), TSV_HDR + "".join(gz_tsv), gz=True)
write(os.path.join(D, "tap_a", "conn_tsv.log"), TSV_HDR + "".join(plain_tsv))
write(os.path.join(D, "tap_a", "notice.log"), "".join(json.dumps(n) + "\n" for n in notice))
write(os.path.join(D, "firewall", "traffic.csv"), pa)
info = item(0, "tcp", 0, "19506", "Nessus Scan Information", 0, output=SCAN_INFO)
hosts = [
    host("10.70.0.10", [info, item(8443, "tcp", 3, "910001", "Mgmt UI flaw", 8.0)]),
    host("10.70.0.11", [info, item(443, "tcp", 3, "910002", "TLS lib flaw", 7.5)]),
    host("10.70.0.12", [info, item(443, "tcp", 3, "910003", "Web flaw (rescanned)", 7.5)], start=SCAN - 20 * DAY),
    host("10.70.0.13", [info, item(445, "tcp", 3, "910004", "SMB flaw", 8.1)]),
    host("10.70.0.14", [info, item(445, "tcp", 3, "910004", "SMB flaw", 8.1)]),
    host("10.70.0.15", [info, item(8080, "tcp", 2, "910005", "App flaw", 5.0)]),
    host("10.70.0.16", [info, item(22, "tcp", 3, "910006", "SSH flaw", 7.5)]),
    host("10.70.0.17", [info, item(443, "tcp", 3, "910007", "Web flaw", 7.5)]),
    host("10.70.0.18", [info, item(443, "tcp", 3, "910007", "Web flaw", 7.5)]),
    host("10.70.0.19", [info, item(443, "tcp", 3, "910007", "Web flaw", 7.5)]),
    host("10.70.0.20", [info, item(161, "udp", 3, "910008", "SNMP flaw", 7.5)]),
    host("10.70.0.22", [info, item(80, "tcp", 2, "910009", "HTTP flaw", 5.3)]),
    host("10.70.0.23", [info, item(25, "tcp", 2, "910010", "SMTP flaw", 5.3)]),
    host("10.70.0.24", [info, item(139, "tcp", 2, "910011", "NetBIOS flaw", 5.3)], netbios="FILESRV"),
    host("10.70.0.25", [info]),
    host("10.70.0.26", [info, item(3389, "tcp", 3, "910012", "RDP flaw", 8.1)]),
    host("10.70.0.27", [info, item(5432, "tcp", 3, "910013", "Postgres flaw", 8.1)]),
    host("10.70.0.12", [info, item(443, "tcp", 3, "910003", "Web flaw (rescanned)", 7.5)], start=SCAN),
    host("10.70.0.28", [info, item(443, "tcp", 3, "910015", "Web flaw (scans 60 days apart)", 7.5)], start=SCAN - 60 * DAY),
    host("10.70.0.28", [info, item(443, "tcp", 3, "910015", "Web flaw (scans 60 days apart)", 7.5)], start=SCAN),
    host("10.70.0.29", [info, item(5432, "tcp", 3, "910013", "Postgres flaw", 8.1)]),
]
write(os.path.join(D, "scan.nessus"),
      '<?xml version="1.0" ?><NessusClientData_v2><Report name="r2">' + "".join(hosts) + "</Report></NessusClientData_v2>")
write(os.path.join(D, "scan_export.csv"),
      "Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output\n"
      "910014,CVE-2026-2001,9.3,8.8,High,10.70.0.21,tcp,3389,RDP flaw (CSV),s,d,patch,\n"
      "910014,CVE-2026-2002,9.3,8.8,High,10.70.0.21,tcp,3389,RDP flaw (CSV),s,d,patch,\n")

exp2 = {
    "R1 only the scanner's probes reach 8443": dict(host="10.70.0.10", port=8443, label="Service not observed in use", internal_sources=0, established=0),
    "R2 window edges inclusive, 1 s outside excluded": dict(host="10.70.0.11", port=443, external_sources=2, established=2),
    "R3 rescanned host, traffic near newer scan": dict(host="10.70.0.12", port=443, label="Vulnerable service reached from the internet", external_sources=1),
    "R4a 5 internal clients = many": dict(host="10.70.0.13", port=445, label="Vulnerable service reached internally by many hosts", internal_sources=5),
    "R4b 4 internal clients": dict(host="10.70.0.14", port=445, label="Vulnerable service reached internally", internal_sources=4),
    "R5 host talking to itself is not exposure": dict(host="10.70.0.15", port=8080, label="Service not observed in use", internal_sources=0),
    "R6 alert on 3306 must not attach to 22": dict(host="10.70.0.16", port=22, threat_alerts=0, indicators=[]),
    "R7a outbound before contact is not a callback": dict(host="10.70.0.17", port=443, indicators=[]),
    "R7b callback after contact": dict(host="10.70.0.18", port=443, indicators=["return_connection"], priority="P2"),
    "R8 25 MB upload after contact": dict(host="10.70.0.19", port=443, indicators=["exfil"]),
    "R9 UDP request with no reply": dict(host="10.70.0.20", port=161, proto="udp", label="Connection attempts only (no completed sessions)", attempts=1, established=0),
    "R10 Nessus CSV, no scan time, all telemetry": dict(host="10.70.0.21", port=3389, label="Vulnerable service reached from the internet", external_sources=1, internal_sources=1, cves=["CVE-2026-2001", "CVE-2026-2002"], cvss=8.8),
    "R11 rotated .gz TSV conn log": dict(host="10.70.0.22", port=80, label="Vulnerable service reached internally", established=1),
    "R12 S1 with unset byte counts": dict(host="10.70.0.23", port=25, label="Vulnerable service reached from the internet", established=1),
    "R13 netbios-name as hostname": dict(host="10.70.0.24", port=139, hostname="FILESRV", label="No telemetry for this host (unknown)"),
    "R17 firewall deny + Zeek S0, same attempt": dict(host="10.70.0.26", port=3389, label="Connections to service blocked by firewall", denied=1, attempts=0),
    "R18 tap A saw SYN only, tap B the full session": dict(host="10.70.0.27", port=5432, label="Vulnerable service reached internally", established=1, attempts=0),
    "R19 scans 60 days apart, traffic halfway not counted": dict(host="10.70.0.28", port=443, external_sources=1, established=1),
    "R20 same-instant taps, SYN-only copy read first": dict(host="10.70.0.29", port=5432, label="Vulnerable service reached internally", established=1, attempts=0),
}
summary2 = {"scanned_hosts": 20, "not_in_active_servers_not_scanned": ["10.70.0.25"],
            "scanner_not_an_internal_peer": SCANNER}
json.dump({"findings": exp2, "summary": summary2}, open(os.path.join(OUT, "round2", "expected.json"), "w"), indent=2)

# =============================================================== telemetry only
D = os.path.join(OUT, "telemetry_only", "data")
a, b, notice = [], [], []
# T1 web server: 3 outside clients; an unblocked alert from one; host calls back to it afterwards
a += [zj(t + timedelta(minutes=i), f"203.0.113.{200 + i}", 4000 + i, "10.80.0.10", 443) for i in range(3)]
a += [zj(t + timedelta(minutes=10), "10.80.0.10", 4010, "203.0.113.200", 4444)]
notice.append({"ts": (t + timedelta(minutes=1)).timestamp(), "note": "Sig", "msg": "Exploit attempt", "src": "203.0.113.200",
               "dst": "10.80.0.10", "p": 443, "actions": ["Notice::ACTION_LOG"]})
# T2 host browsed out first, outside address then connected in; nothing afterwards -> no lead
a += [zj(t, "10.80.0.11", 4100, "203.0.113.210", 443), zj(t + timedelta(minutes=5), "203.0.113.210", 4101, "10.80.0.11", 22)]
# T3 blocked alert only
notice.append({"ts": t.timestamp(), "note": "SSH::Password_Guessing", "msg": "bf", "src": "198.51.100.66",
               "dst": "10.80.0.12", "p": 22, "actions": ["Notice::ACTION_DROP"]})
# T4 internal SMB server with 3 internal clients
a += [zj(t + timedelta(seconds=i), f"10.80.1.{i}", 4200 + i, "10.80.0.13", 445) for i in range(1, 4)]
# T5 outside-to-outside transit: must not create hosts
a += [zj(t, "203.0.113.220", 4300, "198.51.100.220", 80)]
# T6 refused telnet from outside
a += [zj(t, "203.0.113.230", 4400, "10.80.0.14", 23, state="REJ", ob=0, rb=0)]
# T7 one session seen by two Zeek taps
a += [zj(t, "10.80.1.9", 4500, "10.80.0.15", 3389)]
b += [zj(t + timedelta(seconds=0.3), "10.80.1.9", 4500, "10.80.0.15", 3389)]
# T8 alert where the internal host is the SOURCE and no flow exists for it
notice.append({"ts": t.timestamp(), "note": "Sig", "msg": "Beacon", "src": "10.80.0.16",
               "dst": "203.0.113.240", "p": 8080, "actions": ["Notice::ACTION_LOG"]})
write(os.path.join(D, "tap_a", "conn.log"), "".join(a))
write(os.path.join(D, "tap_b", "conn.log"), "".join(b))
write(os.path.join(D, "tap_a", "notice.log"), "".join(json.dumps(n) + "\n" for n in notice))
exp_t = {
    "flows": 12,                                   # 13 conn lines, one session seen by both taps
    "hosts": sorted(["10.80.0.10", "10.80.0.11", "10.80.0.13", "10.80.0.14", "10.80.0.15", "10.80.0.16",
                     "10.80.1.1", "10.80.1.2", "10.80.1.3", "10.80.1.9", "10.80.0.12"]),
    "telemetry_leads": {"10.80.0.10": [1, 0], "10.80.0.12": [0, 1], "10.80.0.16": [1, 0]},   # leads name the internal host
    "network_leads": [["10.80.0.10", "203.0.113.200", 1]],
    "threat_alerts": 3,
    "inbound": {"10.80.0.13": 3, "10.80.0.15": 1, "10.80.0.10": 3, "10.80.0.14": 1},
}
json.dump(exp_t, open(os.path.join(OUT, "telemetry_only", "expected.json"), "w"), indent=2)
print("ok")
