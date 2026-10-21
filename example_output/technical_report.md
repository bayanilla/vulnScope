# Technical Analysis: Vulnerability and Network Telemetry Correlation

Generated 2026-10-21T23:15:37Z. Telemetry window 2026-10-12T00:02:03Z to 2026-10-18T03:11:38Z.

## 1. Inputs and data quality

| File | Format | Records read | Kept | Dropped | Notes |
|---|---|---|---|---|---|
| netflow_segment6.csv | generic | 112 | 112 | 0 |  |
| paloalto_traffic.csv | paloalto | 465 | 465 | 0 | firewall timestamps are assumed to be UTC; 4 IPS/IDS alert(s) used as exploitation evidence |
| quarterly_scan.nessus | nessus | 33 | 33 | 0 |  |
| zeek_conn.log | zeek | 781 | 780 | 1 missing or invalid IP |  |

Exact duplicate sessions removed: 1. Duplicate findings merged across scans: 0. IPS/IDS alerts loaded: 4. Internal address space: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, fc00::/7, fe80::/10, ::1/128.

## 2. Method

Each finding is scored 0-100 as `CVSS x 10 x Exploit x Exposure x BlastRadius`, capped at 100, then multiplied by 1.25 with corroborated exploitation evidence or 1.1 with investigation leads.

- **Exploit**: 1.0 if a public exploit exists (1.1 if in Metasploit/CANVAS/Core), otherwise 0.65.
- **Exposure** (from telemetry): 1.0 service reached from the internet; 0.85 reached internally by 5+ hosts; 0.75 reached internally; 0.45 attempts only; 0.35 blocked by firewall; 0.3 service not observed in use; 0.5 host absent from telemetry (unknown). Host-level findings (port 0, e.g. missing patches or client software) use 0.7 / 0.5 / 0.35 for internet-facing / active / quiet hosts.
- **Blast radius**: 1.0 to 1.5 from the number of internal hosts this host has completed sessions with (walked 2 hops), how many of those carry High/Critical findings, and use of lateral-movement protocols (SMB, RDP, SSH, WinRM, database ports).
- **Indicators** are leads, not proof. *Lead*: the host connects back to an outside address that reached the vulnerable service; new lateral connections or >20 MB uploaded to the internet after that contact; an IPS/IDS alert on the service that was not blocked; a flagged host newly connecting to this vulnerable service. *Corroborated*: an unblocked IPS/IDS alert on the service plus post-contact behaviour from the host. Confirming a compromise still needs host evidence (EDR, logs, forensics), which this tool does not see.
- **Priority**: P1 score >= 75 or corroborated evidence; P2 >= 50 or any lead; P3 >= 25; P4 below.

## 3. Prioritized findings

| Pri | Score | Host | Vulnerability | Port | CVSS | Exploit | Exposure | Blast | Likelihood |
|---|---|---|---|---|---|---|---|---|---|
| P1 | 100 | web01.corp.example (10.10.1.10) | Apache 2.4.49 < 2.4.51 Path Traversal and RCE (153884) | 443/tcp (www) | 9.8 | Yes | Vulnerable service reached from the internet | x1.5 | High |
| P1 | 100 | app01.corp.example (10.10.1.20) | Apache Tomcat AJP Connector Request Injection (Ghostcat) (134862) | 8009/tcp (ajp13) | 9.8 | Yes | Vulnerable service reached internally | x1.24 | High |
| P1 | 89 | ws-031.corp.example (10.10.3.31) | Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (125313) | 3389/tcp (msrdp) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 83 | fs01.corp.example (10.10.2.25) | MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE) (97833) | 445/tcp (cifs) | 8.1 | Yes | Vulnerable service reached internally by many hosts | x1.0 | High |
| P2 | 61 | ws-040.corp.example (10.10.3.40) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.38 | Medium |
| P2 | 59 | ws-041.corp.example (10.10.3.41) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-042.corp.example (10.10.3.42) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-043.corp.example (10.10.3.43) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-044.corp.example (10.10.3.44) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-045.corp.example (10.10.3.45) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-046.corp.example (10.10.3.46) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-047.corp.example (10.10.3.47) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P3 | 45 | db01.corp.example (10.10.2.20) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.04 | Medium |
| P3 | 38 | ups-mgmt.corp.example (10.10.5.60) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | No telemetry for this host (unknown) | x1.0 | Medium |
| P4 | 20 | web01.corp.example (10.10.1.10) | OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin) (187201) | 22/tcp (ssh) | 5.9 | No | Connections to service blocked by firewall | x1.5 | Low |
| P4 | 13 | prn-4f.corp.example (10.10.4.50) | Unencrypted Telnet Server (42263) | 23/tcp (telnet) | 6.5 | No | Service not observed in use | x1.0 | Low |
| P4 | 11 | jump01.corp.example (10.10.3.5) | Terminal Services Doesn't Use Network Level Authentication (NLA) Only (58453) | 3389/tcp (msrdp) | 4.0 | No | Service not observed in use | x1.36 | Low |

## 4. Host details

### web01.corp.example (10.10.1.10) - P1 - act now

- Operating system: Linux Kernel 5.4 on Ubuntu 20.04
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (249 inbound, 165 outbound sessions)
- Internet-exposed vulnerable service: yes

**Exploitation indicators** (leads unless marked corroborated)

- [lead] IPS/IDS alerted 1 time(s) on traffic to this service and did not block it: Apache HTTP Server Path Traversal Vulnerability CVE-2021-41773(91694) (from 203.0.113.45), matching CVE-2021-41773. An alert shows an attempt, not that it succeeded.
- [lead] 10.10.1.10 opened 2 outbound connection(s) to 203.0.113.45 (port 443, 4444) after 203.0.113.45 connected to the vulnerable service. This is consistent with an exploit callback, but on its own it can also be legitimate traffic; confirm with IPS/threat logs, payload or application logs, or host evidence.
- [lead] After the flagged inbound contact at 2026-10-16T03:12:00Z, 10.10.1.10 began connecting to 3 internal host(s) it had not talked to before, over RDP, SMB.
- [lead] 10.10.1.10 sent 59.1 MB to external address 203.0.113.45 after the flagged inbound contact at 2026-10-16T03:12:00Z.
- [corroborated] Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service from 203.0.113.45, the same address the host then connected back to, and the host then showed exfil, new lateral, return connection. Treat this as likely exploitation and start incident response; host forensics is still needed to confirm a compromise.

**Findings and exposure evidence**

#### P1 (100) Apache 2.4.49 < 2.4.51 Path Traversal and RCE

- Plugin 153884, Critical, CVSS 9.8, port 443/tcp (www), CVE-2021-41773, CVE-2021-42013
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached from the internet - 224 completed sessions from 154 external and 0 internal sources. Blast radius: the host talks to 5 internal host(s) directly and 6 within 2 hops, including 4 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 224 completed, 0 attempts, 0 blocked; first 2026-10-12T00:02:03Z, last 2026-10-18T02:50:10Z; top sources: 198.51.100.65 (ext) x6, 198.51.100.38 (ext) x5, 198.51.100.176 (ext) x4, 198.51.100.102 (ext) x4, 198.51.100.20 (ext) x4, 203.0.113.45 (ext) x4, 198.51.100.131 (ext) x3, 198.51.100.10 (ext) x3
- Synopsis: The remote web server is affected by a path traversal vulnerability that can lead to remote code execution.
- Remediation: Upgrade to Apache version 2.4.51 or later.

#### P4 (20) OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin)

- Plugin 187201, Medium, CVSS 5.9, port 22/tcp (ssh), CVE-2023-48795
- Why this score: Base severity: CVSS v3 5.9 (Medium). No public exploit is known to the scanner. Exposure: connections to service blocked by firewall. 25 connection(s) to it were blocked by a firewall. Blast radius: the host talks to 5 internal host(s) directly and 6 within 2 hops, including 4 with High/Critical findings.
- Traffic to service: 0 completed, 0 attempts, 25 blocked; first 2026-10-12T09:38:38Z, last 2026-10-17T20:49:02Z
- Synopsis: The SSH server is affected by a prefix truncation weakness.
- Remediation: Upgrade to OpenSSH 9.6 or later.

**Blast radius**

Completed sessions to 5 internal host(s) directly, 6 within 2 hops.
Lateral-movement protocols used: SMB (2), RDP (1).
Reachable hosts with High/Critical findings: 10.10.1.20, 10.10.2.25, 10.10.3.31, 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.20 | 1 | 8009/tcp | Critical |
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.3.31 | 1 | 3389/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 445/tcp | - |
| 10.10.2.20 | 2 |  | High |

Outbound to 1 external address(es); top: 203.0.113.45 x2.

### app01.corp.example (10.10.1.20) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (120 inbound, 140 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Tomcat AJP Connector Request Injection (Ghostcat)

- Plugin 134862, Critical, CVSS 9.8, port 8009/tcp (ajp13), CVE-2020-1938
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 120 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 120 completed, 0 attempts, 0 blocked; first 2026-10-12T00:38:11Z, last 2026-10-18T02:46:28Z; top sources: 10.10.1.10 x120
- Synopsis: An AJP connector is listening and is affected by a file read/inclusion vulnerability.
- Remediation: Update Tomcat to 9.0.31 / 8.5.51 / 7.0.100 or later, or disable the AJP connector.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (140).
Reachable hosts with High/Critical findings: 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.20 | 1 | 5432/tcp | High |
| 10.10.6.71 | 2 |  | - |

### ws-031.corp.example (10.10.3.31) - P1 - act now

- Operating system: Microsoft Windows 7 Professional
- Findings: 1 Critical
- Seen in telemetry: yes (92 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Exploitation indicators** (leads unless marked corroborated)

- [lead] 10.10.1.10, which is flagged for investigation, newly connected to this vulnerable service at 2026-10-16T04:08:00Z. Check this host for signs of lateral movement.

**Findings and exposure evidence**

#### P1 (89) Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)

- Plugin 125313, Critical, CVSS 9.8, port 3389/tcp (msrdp), CVE-2019-0708
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 31 completed sessions from 0 external and 2 internal sources. 60 connection(s) to it were blocked by a firewall. The IPS/IDS blocked 3 alerted attempt(s) against it. Traffic gives leads worth investigating; nothing in the logs confirms exploitation.
- Traffic to service: 31 completed, 0 attempts, 60 blocked; first 2026-10-12T05:08:06Z, last 2026-10-18T03:11:38Z; top sources: 10.10.3.5 x30, 10.10.1.10 x1
- Synopsis: The remote host is affected by a remote code execution vulnerability in Remote Desktop Services.
- Remediation: Apply the May 2019 security update and enable Network Level Authentication.

**Blast radius**

No completed internal sessions from this host were observed.

### fs01.corp.example (10.10.2.25) - P1 - act now

- Operating system: Microsoft Windows Server 2012 R2
- Findings: 1 Critical
- Seen in telemetry: yes (201 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Exploitation indicators** (leads unless marked corroborated)

- [lead] 10.10.1.10, which is flagged for investigation, newly connected to this vulnerable service at 2026-10-16T04:07:00Z. Check this host for signs of lateral movement.

**Findings and exposure evidence**

#### P1 (83) MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)

- Plugin 97833, Critical, CVSS 8.1, port 445/tcp (cifs), CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
- Why this score: Base severity: CVSS v3 8.1 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 201 completed sessions from 0 external and 9 internal sources. Traffic gives leads worth investigating; nothing in the logs confirms exploitation.
- Traffic to service: 201 completed, 0 attempts, 0 blocked; first 2026-10-12T01:53:43Z, last 2026-10-18T02:55:10Z; top sources: 10.10.3.44 x25, 10.10.3.45 x25, 10.10.3.41 x25, 10.10.3.47 x25, 10.10.3.40 x25, 10.10.3.46 x25, 10.10.3.43 x25, 10.10.3.42 x25
- Synopsis: The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1.
- Remediation: Apply MS17-010 and disable SMBv1.

**Blast radius**

No completed internal sessions from this host were observed.

### ws-040.corp.example (10.10.3.40) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 88 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (61) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 5 internal host(s) directly and 5 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 5 internal host(s) directly, 5 within 2 hops.
Lateral-movement protocols used: SMB (29), Kerberos (10), LDAP (10), RDP (9).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |
| 10.10.6.71 | 1 | 8443/tcp | - |

Outbound to 23 external address(es); top: 93.184.254.146 x1, 93.184.34.189 x1, 93.184.24.67 x1, 93.184.108.144 x1, 93.184.146.48 x1.

### ws-041.corp.example (10.10.3.41) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 81 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (27), LDAP (10), Kerberos (10), RDP (7).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 20 external address(es); top: 93.184.150.65 x1, 93.184.177.121 x1, 93.184.251.202 x1, 93.184.143.53 x1, 93.184.92.207 x1.

### ws-042.corp.example (10.10.3.42) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 98 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (35), Kerberos (10), LDAP (10), RDP (5).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 24 external address(es); top: 93.184.29.234 x1, 93.184.193.22 x1, 93.184.242.127 x1, 93.184.42.55 x1, 93.184.154.188 x1.

### ws-043.corp.example (10.10.3.43) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 73 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (28), Kerberos (10), LDAP (10), RDP (4).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 15 external address(es); top: 93.184.95.199 x1, 93.184.73.235 x1, 93.184.57.9 x1, 93.184.186.111 x1, 93.184.157.203 x1.

### ws-044.corp.example (10.10.3.44) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 76 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (32), LDAP (10), Kerberos (10), RDP (3).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 15 external address(es); top: 93.184.212.230 x1, 93.184.79.186 x1, 93.184.24.184 x1, 93.184.199.32 x1, 93.184.176.250 x1.

### ws-045.corp.example (10.10.3.45) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 81 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (30), Kerberos (10), LDAP (10), RDP (6).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 19 external address(es); top: 93.184.224.121 x1, 93.184.243.41 x1, 93.184.14.6 x1, 93.184.172.109 x1, 93.184.74.93 x1.

### ws-046.corp.example (10.10.3.46) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 76 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (25), Kerberos (10), LDAP (10), RDP (8).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp | - |

Outbound to 17 external address(es); top: 93.184.223.178 x1, 93.184.85.157 x1, 93.184.64.87 x1, 93.184.247.117 x1, 93.184.80.151 x1.

### ws-047.corp.example (10.10.3.47) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 75 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (30), LDAP (10), Kerberos (10), RDP (2).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 17 external address(es); top: 93.184.191.222 x1, 93.184.59.143 x1, 93.184.89.58 x1, 93.184.108.230 x1, 93.184.67.66 x1.

### db01.corp.example (10.10.2.20) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (170 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (45) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 140 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 140 completed, 0 attempts, 0 blocked; first 2026-10-12T00:34:43Z, last 2026-10-18T02:23:17Z; top sources: 10.10.1.20 x140
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.6.71 | 1 | 8443/tcp | - |

### ups-mgmt.corp.example (10.10.5.60) - P3 - scheduled

- Operating system: Embedded Linux
- Findings: 1 High
- Seen in telemetry: no (0 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: no telemetry for this host (unknown).
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-4f.corp.example (10.10.4.50) - P4 - routine

- Operating system: HP LaserJet
- Findings: 1 Medium
- Seen in telemetry: yes (8 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (13) Unencrypted Telnet Server

- Plugin 42263, Medium, CVSS 6.5, port 23/tcp (telnet)
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use.
- Synopsis: The remote Telnet server transmits traffic in cleartext.
- Remediation: Disable Telnet and use SSH instead.

**Blast radius**

No completed internal sessions from this host were observed.

### jump01.corp.example (10.10.3.5) - P4 - routine

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 60 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (11) Terminal Services Doesn't Use Network Level Authentication (NLA) Only

- Plugin 58453, Medium, CVSS 4.0, port 3389/tcp (msrdp)
- Why this score: Base severity: CVSS v3 4.0 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Synopsis: The remote Terminal Services doesn't use NLA only.
- Remediation: Enable Network Level Authentication.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: SSH (30), RDP (30).
Reachable hosts with High/Critical findings: 10.10.3.31, 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.3.31 | 1 | 3389/tcp | Critical |
| 10.10.2.20 | 1 | 22/tcp | High |
| 10.10.6.71 | 2 |  | - |

## 5. Coverage gaps

15 of 16 scanned hosts appear in telemetry; 19 internal addresses were seen in total.

**Scanned but not seen in telemetry** (exposure unknown; check sensor placement): 10.10.5.60

**Active internal servers not in the scan** (add to scan scope):

| Host | Services observed | Sessions |
|---|---|---|
| 10.10.0.10 | 389/tcp, 88/tcp | 160 |
| 10.10.0.53 | 53/udp | 88 |
| 10.10.6.70 | 3389/tcp, 445/tcp | 81 |
| 10.10.6.71 | 8443/tcp | 31 |

## 6. Output files

- `executive_summary.md/.html`: leadership summary
- `technical_report.md/.html`: this report
- `correlated_findings.csv`: one row per finding with scores, for ticketing or spreadsheets
- `results.json`: full machine-readable result
- `hostile_activity.svg`: the hostile activity diagram as a standalone image
- `explorer.html`: interactive host explorer (who targets each host, and its internal blast radius)
- `normalized/flows.csv`, `normalized/findings.csv`: cleaned inputs in the common schema
- `normalized/zeek_events.jsonl`: other Zeek streams with stream identity and source fields
- `normalized/ot_events.jsonl`: industrial protocol records with operation and message direction
