"""Generate a small synthetic environment that exercises every code path.

Story: web01 (DMZ) runs a vulnerable Apache. An outside address trips the firewall's
IPS signature for that CVE (alert only), web01 then connects back to it, uploads data
and starts probing internal SMB/RDP. BlueKeep probes against ws-031 are reset by the IPS. Meanwhile
the scanner missed the domain controller and a new file server.
"""
from __future__ import annotations

import csv
import os
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

START = datetime(2026, 10, 12, tzinfo=timezone.utc)
ATTACK = datetime(2026, 10, 16, 3, 12, tzinfo=timezone.utc)
ATTACKER = "203.0.113.45"

HOSTS = {  # ip: (hostname, os)
    "10.10.1.10": ("web01.corp.example", "Linux Kernel 5.4 on Ubuntu 20.04"),
    "10.10.1.20": ("app01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04"),
    "10.10.2.20": ("db01.corp.example", "Linux Kernel 5.15 on Ubuntu 22.04"),
    "10.10.2.25": ("fs01.corp.example", "Microsoft Windows Server 2012 R2"),
    "10.10.3.5": ("jump01.corp.example", "Microsoft Windows Server 2019"),
    "10.10.3.31": ("ws-031.corp.example", "Microsoft Windows 7 Professional"),
    "10.10.4.50": ("prn-4f.corp.example", "HP LaserJet"),
    "10.10.5.60": ("ups-mgmt.corp.example", "Embedded Linux"),
}
WORKSTATIONS = [f"10.10.3.{i}" for i in range(40, 48)]
for ip in WORKSTATIONS:
    HOSTS[ip] = (f"ws-{ip.split('.')[-1]:0>3}.corp.example", "Microsoft Windows 10 Enterprise")

# (ip, port, proto, svc, pluginID, name, sev, cvss3, cves, exploit, metasploit, synopsis, solution)
VULNS = [
    ("10.10.1.10", 443, "tcp", "www", "153884", "Apache 2.4.49 < 2.4.51 Path Traversal and RCE", 4, 9.8,
     ["CVE-2021-41773", "CVE-2021-42013"], True, True,
     "The remote web server is affected by a path traversal vulnerability that can lead to remote code execution.",
     "Upgrade to Apache version 2.4.51 or later."),
    ("10.10.1.10", 22, "tcp", "ssh", "187201", "OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)", 2, 5.9,
     ["CVE-2023-48795"], False, False,
     "The SSH server is affected by a prefix truncation weakness.", "Upgrade to OpenSSH 9.6 or later."),
    ("10.10.1.20", 8009, "tcp", "ajp13", "134862", "Apache Tomcat AJP Connector Request Injection (Ghostcat)", 4, 9.8,
     ["CVE-2020-1938"], True, True,
     "An AJP connector is listening and is affected by a file read/inclusion vulnerability.",
     "Update Tomcat to 9.0.31 / 8.5.51 / 7.0.100 or later, or disable the AJP connector."),
    ("10.10.2.20", 5432, "tcp", "postgresql", "183965", "PostgreSQL 13.x < 13.13 Multiple Vulnerabilities", 3, 8.8,
     ["CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870"], False, False,
     "The database server is affected by multiple vulnerabilities including an integer overflow.",
     "Upgrade to PostgreSQL 13.13 or later."),
    ("10.10.2.25", 445, "tcp", "cifs", "97833", "MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)", 4, 8.1,
     ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"], True, True,
     "The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1.",
     "Apply MS17-010 and disable SMBv1."),
    ("10.10.3.31", 3389, "tcp", "msrdp", "125313", "Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)", 4, 9.8,
     ["CVE-2019-0708"], True, True,
     "The remote host is affected by a remote code execution vulnerability in Remote Desktop Services.",
     "Apply the May 2019 security update and enable Network Level Authentication."),
    ("10.10.3.5", 3389, "tcp", "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", 2, 4.0,
     [], False, False, "The remote Terminal Services doesn't use NLA only.", "Enable Network Level Authentication."),
    ("10.10.4.50", 23, "tcp", "telnet", "42263", "Unencrypted Telnet Server", 2, 6.5, [], False, False,
     "The remote Telnet server transmits traffic in cleartext.", "Disable Telnet and use SSH instead."),
    ("10.10.5.60", 161, "udp", "snmp", "41028", "SNMP Agent Default Community Name (public)", 3, 7.5,
     ["CVE-1999-0517"], True, False, "The community name of the remote SNMP server can be guessed.",
     "Disable SNMP or change the default community string."),
]
for ip in WORKSTATIONS:
    VULNS.append((ip, 0, "tcp", "general", "207053", "Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities",
                  3, 8.8, ["CVE-2024-7965", "CVE-2024-7971"], True, False,
                  "The browser installed on the remote host is affected by multiple vulnerabilities.",
                  "Upgrade to Microsoft Edge version 129.0.2792.52 or later."))


def _nessus(path):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="Quarterly internal scan")
    for ip, (fqdn, os_name) in HOSTS.items():
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        for k, v in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name)):
            ET.SubElement(hp, "tag", name=k).text = v
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in VULNS:
            if v[0] != ip:
                continue
            _, port, proto, svc, pid, name, sev, cvss, cves, expl, msf, syn, sol = v
            it = ET.SubElement(rh, "ReportItem", port=str(port), svc_name=svc, protocol=proto,
                               severity=str(sev), pluginID=pid, pluginName=name, pluginFamily="General")
            ET.SubElement(it, "cvss3_base_score").text = str(cvss)
            for c in cves:
                ET.SubElement(it, "cve").text = c
            ET.SubElement(it, "exploit_available").text = "true" if expl else "false"
            if msf:
                ET.SubElement(it, "exploit_framework_metasploit").text = "true"
            ET.SubElement(it, "synopsis").text = syn
            ET.SubElement(it, "solution").text = sol
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def _flows(rng):
    """Return (zeek_rows, pan_rows, netflow_rows) as dicts."""
    zeek, pan, nf, threats = [], [], [], []
    span = (ATTACK + timedelta(days=2) - START).total_seconds()

    def t(lo=START, hi=None):
        hi = hi or START + timedelta(seconds=span)
        return lo + timedelta(seconds=rng.uniform(0, (hi - lo).total_seconds()))

    def z(ts, s, d, dp, proto="tcp", svc="-", state="SF", ob=None, rb=None):
        zeek.append(dict(ts=ts, s=s, sp=rng.randint(49152, 65535), d=d, dp=dp, proto=proto, svc=svc,
                         state=state, ob=rng.randint(200, 5000) if ob is None else ob,
                         rb=rng.randint(500, 40000) if rb is None else rb))

    def p(ts, s, d, dp, app, action="allow", fz="untrust", tz="dmz", sent=None, rcvd=None):
        pan.append(dict(ts=ts, s=s, sp=rng.randint(1024, 65535), d=d, dp=dp, app=app, action=action,
                        fz=fz, tz=tz, sent=rng.randint(400, 3000) if sent is None else sent,
                        rcvd=(rng.randint(2000, 90000) if action == "allow" else 0) if rcvd is None else rcvd))

    # internet -> web01:443 (normal customers), seen by the firewall
    for _ in range(220):
        p(t(), f"198.51.100.{rng.randint(2, 250)}", "10.10.1.10", 443, "ssl")
    # attacker: exploit, callback, staging upload, then internal probing
    for k in range(4):
        p(ATTACK + timedelta(seconds=k * 7), ATTACKER, "10.10.1.10", 443, "web-browsing")
    threats.append(dict(ts=ATTACK + timedelta(seconds=14), s=ATTACKER, d="10.10.1.10", dp=443, fz="untrust", tz="dmz",
                        name="Apache HTTP Server Path Traversal Vulnerability CVE-2021-41773(91694)",
                        sev="critical", action="alert"))
    p(ATTACK + timedelta(minutes=1), "10.10.1.10", ATTACKER, 4444, "unknown-tcp", fz="dmz", tz="untrust")
    p(ATTACK + timedelta(minutes=40), "10.10.1.10", ATTACKER, 443, "ssl", fz="dmz", tz="untrust",
      sent=62_000_000, rcvd=4000)
    for k, dst in enumerate(["10.10.2.25", "10.10.3.31", "10.10.6.70"]):
        dp = 445 if dst != "10.10.3.31" else 3389
        z(ATTACK + timedelta(minutes=55 + k), "10.10.1.10", dst, dp, svc="smb" if dp == 445 else "rdp")
    # internet scanning noise against RDP and SSH, blocked at the perimeter
    for _ in range(60):
        p(t(), f"192.0.2.{rng.randint(2, 250)}", "10.10.3.31", 3389, "incomplete", action="deny", tz="trust")
    for _ in range(3):  # IPS saw BlueKeep probes and reset them
        threats.append(dict(ts=t(), s=f"192.0.2.{rng.randint(2, 250)}", d="10.10.3.31", dp=3389, fz="untrust", tz="trust",
                            name="Microsoft RDP Remote Code Execution Vulnerability CVE-2019-0708(55188)",
                            sev="critical", action="reset-both"))
    for _ in range(25):
        p(t(), f"192.0.2.{rng.randint(2, 250)}", "10.10.1.10", 22, "incomplete", action="deny")
    # workstations browsing out
    for _ in range(150):
        p(t(), rng.choice(WORKSTATIONS), f"93.184.{rng.randint(0, 255)}.{rng.randint(1, 254)}", 443, "ssl",
          fz="trust", tz="untrust")

    # east-west, seen by Zeek on the core switch
    for _ in range(120):
        z(t(), "10.10.1.10", "10.10.1.20", 8009, svc="ajp")
    for _ in range(40):
        z(t(), "10.10.1.10", "10.10.0.53", 53, proto="udp", svc="dns")
    for _ in range(140):
        z(t(), "10.10.1.20", "10.10.2.20", 5432, svc="postgresql")
    for ws in WORKSTATIONS:
        for _ in range(25):
            z(t(), ws, "10.10.2.25", 445, svc="smb")
        for _ in range(10):
            z(t(), ws, "10.10.0.10", 88, svc="krb")
            z(t(), ws, "10.10.0.10", 389, svc="ldap")
        for _ in range(6):
            z(t(), ws, "10.10.0.53", 53, proto="udp", svc="dns")
    for _ in range(30):
        z(t(), "10.10.3.5", "10.10.3.31", 3389, svc="rdp")
        z(t(), "10.10.3.5", "10.10.2.20", 22, svc="ssh")
    for _ in range(8):  # SYNs to the printer's web UI, never answered
        z(t(), "10.10.3.42", "10.10.4.50", 80, svc="-", state="S0", rb=0)
    z(t(), "10.10.3.41", "10.10.3.31", 445, state="REJ", ob=0, rb=0)
    # one malformed row to show cleaning
    zeek.append(dict(ts=t(), s="not-an-ip", sp=1, d="10.10.2.25", dp=445, proto="tcp", svc="-",
                     state="SF", ob=1, rb=1))

    # a segment only covered by NetFlow
    for _ in range(80):
        nf.append(dict(ts=t(), s=rng.choice(WORKSTATIONS), d="10.10.6.70", sp=rng.randint(49152, 65535),
                       dp=rng.choice([445, 3389]), bytes=rng.randint(1000, 90000)))
    for _ in range(30):
        nf.append(dict(ts=t(), s="10.10.2.20", d="10.10.6.71", sp=rng.randint(49152, 65535), dp=8443,
                       bytes=rng.randint(1000, 90000)))
    nf.append(dict(ts=t(), s="10.10.3.40", d="10.10.6.71", sp=50000, dp=8443, bytes=500))
    nf.append(nf[-1])  # exact duplicate, removed during cleaning
    return zeek, pan, nf, threats


def generate(outdir: str, seed: int = 7) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(seed)
    zeek, pan, nf, threats = _flows(rng)
    paths = []

    p = os.path.join(outdir, "zeek_conn.log")
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
              "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
    with open(p, "w") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(fields) + "\n")
        for i, r in enumerate(sorted(zeek, key=lambda r: r["ts"])):
            fh.write("\t".join([f"{r['ts'].timestamp():.6f}", f"C{i:08x}", r["s"], str(r["sp"]), r["d"],
                                str(r["dp"]), r["proto"], r["svc"], f"{rng.uniform(0.01, 30):.3f}",
                                str(r["ob"]), str(r["rb"]), r["state"], "ShADadFf" if r["state"] == "SF" else "S"]) + "\n")
        fh.write("#close\t2026-10-18-23-59-59\n")
    paths.append(p)

    p = os.path.join(outdir, "paloalto_traffic.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address",
                    "Destination address", "Rule", "Application", "Source Zone", "Destination Zone",
                    "Source Port", "Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent",
                    "Bytes Received", "Start Time", "Threat/Content Name", "Severity"])
        rows = [("TRAFFIC", r) for r in pan] + [("THREAT", r) for r in threats]
        for kind, r in sorted(rows, key=lambda x: x[1]["ts"]):
            ts = r["ts"].strftime("%Y/%m/%d %H:%M:%S")
            if kind == "THREAT":
                w.writerow([ts, "016401000001", "THREAT", "vulnerability", r["s"], r["d"], "allow-web", "web-browsing",
                            r["fz"], r["tz"], rng.randint(1024, 65535), r["dp"], "tcp", r["action"], "", "", "", "",
                            r["name"], r["sev"]])
                continue
            w.writerow([ts, "016401000001", "TRAFFIC", "end", r["s"], r["d"],
                        "allow-web" if r["action"] == "allow" else "default-deny", r["app"], r["fz"], r["tz"],
                        r["sp"], r["dp"], "tcp", r["action"], r["sent"] + r["rcvd"], r["sent"], r["rcvd"], ts, "", ""])
    paths.append(p)

    p = os.path.join(outdir, "netflow_segment6.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "sa", "da", "sp", "dp", "pr", "ibyt"])
        for r in nf:
            w.writerow([r["ts"].strftime("%Y-%m-%d %H:%M:%S"), r["s"], r["d"], r["sp"], r["dp"], "TCP", r["bytes"]])
    paths.append(p)

    p = os.path.join(outdir, "quarterly_scan.nessus")
    _nessus(p)
    paths.append(p)
    return paths
