# VulnScope: Technical Analysis

Generated 2026-11-22T12:42:46Z. Telemetry window 2026-10-12T00:00:04Z to 2026-10-18T03:11:38Z.

## 1. Inputs and data quality

| File | Format | Records read | Kept | Dropped | Notes |
|---|---|---|---|---|---|
| dns.log | zeek | 16 | 16 | 0 | Zeek stream records preserved as events; only conn sessions and notice alerts affect scoring |
| flows.csv | generic | 18 | 18 | 0 |  |
| modbus.log | zeek | 4 | 4 | 0 | Zeek stream records preserved as events; only conn sessions and notice alerts affect scoring |
| netflow_segment6.csv | generic | 112 | 112 | 0 |  |
| notice.log | zeek | 1 | 1 | 0 | 1 IPS/IDS alert(s) used as exploitation evidence |
| paloalto_traffic.csv | paloalto | 2271 | 2271 | 0 | firewall timestamps are assumed to be UTC; 4 IPS/IDS alert(s) used as exploitation evidence |
| quarterly_scan.nessus | nessus | 687 | 687 | 0 |  |
| scan.csv | nessus_csv | 1 | 1 | 0 | Nessus CSV exports usually omit exploit availability; prefer the .nessus file |
| zeek_conn.log | zeek | 8083 | 8082 | 1 missing or invalid IP |  |
| ioc_indicators.csv | ioc_csv | 28 | 28 | 0 |  |

Exact duplicate sessions removed: 1. Sessions seen by two sensors counted once: 0. Duplicate findings merged across scans: 0. IPS/IDS alerts loaded: 5. Internal address space: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, fc00::/7, fe80::/10, ::1/128.

Zeek stream events preserved (separate from connection sessions and alerts): dns 16, modbus 4.

Industrial protocol records: Modbus 4. These records show observed activity; they do not, by themselves, change risk scores.

## 2. Method

Each finding is scored 0-100 as `CVSS x 10 x Exploit x Exposure x BlastRadius`, capped at 100, then multiplied by 1.25 with corroborated exploitation evidence or 1.1 with investigation leads.

- **Exploit**: 1.0 if a public exploit exists (1.1 if in Metasploit/CANVAS/Core), otherwise 0.65.
- **Exposure** (from telemetry): 1.0 service reached from the internet; 0.85 reached internally by 5+ hosts; 0.75 reached internally; 0.45 attempts only; 0.35 blocked by firewall or refused by the host; 0.3 service not observed in use; 0.5 host absent from telemetry (unknown). Host-level findings (port 0, e.g. missing patches or client software) use 0.7 / 0.5 / 0.35 for internet-facing / active / quiet hosts.
- **Blast radius**: 1.0 to 1.5 from the number of internal hosts this host has completed sessions with (walked 2 hops), how many of those carry High/Critical findings, and use of lateral-movement protocols (SMB, RDP, SSH, WinRM, database ports).
- **Indicators** are leads, not proof. *Lead*: the host connects back to an outside address that reached the vulnerable service; new lateral connections or >20 MB uploaded to the internet after that contact; an IPS/IDS alert on the service that was not blocked; a flagged host newly connecting to this vulnerable service. *Corroborated*: an unblocked IPS/IDS alert on the service plus post-contact behaviour from the host. Confirming a compromise still needs host evidence (EDR, logs, forensics), which this tool does not see.
- **Priority**: P1 score >= 75 or corroborated evidence; P2 >= 50 or any lead; P3 >= 25; P4 below.

## 3. Prioritized findings

| Pri | Score | Host | Vulnerability | Port | CVSS | Exploit | Exposure | Blast | Likelihood |
|---|---|---|---|---|---|---|---|---|---|
| P1 | 100 | web01.corp.example (10.10.1.10) | Apache 2.4.49 < 2.4.51 Path Traversal and RCE (153884) | 443/tcp (www) | 9.8 | Yes | Vulnerable service reached from the internet | x1.5 | High |
| P1 | 100 | web02.corp.example (10.10.1.11) | Synthetic Magento StyleSmuggler finding (990001) | 443/tcp | 10.0 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P1 | 100 | app01.corp.example (10.10.1.20) | Apache Tomcat AJP Connector Request Injection (Ghostcat) (134862) | 8009/tcp (ajp13) | 9.8 | Yes | Vulnerable service reached internally | x1.24 | High |
| P1 | 100 | vpn01.corp.example (10.10.1.30) | Ivanti Connect Secure Command Injection (CVE-2024-21887) (189987) | 443/tcp (www) | 9.1 | Yes | Vulnerable service reached from the internet | x1.0 | High |
| P1 | 100 | app02.corp.example (10.10.2.30) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.38 | High |
| P1 | 100 | app03.corp.example (10.10.2.31) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.26 | High |
| P1 | 100 | app04.corp.example (10.10.2.32) | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (156057) | 8080/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.38 | High |
| P1 | 100 | jenkins01.corp.example (10.10.2.45) | Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897) (189463) | 8080/tcp (www) | 9.8 | Yes | Vulnerable service reached internally by many hosts | x1.38 | High |
| P1 | 93 | backup01.corp.example (10.10.2.41) | Veeam Backup & Replication Credential Disclosure (CVE-2023-27532) (173914) | 9401/tcp (veeam) | 7.5 | Yes | Vulnerable service reached internally | x1.5 | High |
| P1 | 89 | ws-031.corp.example (10.10.3.31) | Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (125313) | 3389/tcp (msrdp) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 85 | git01.corp.example (10.10.2.44) | GitLab 16.1 < 16.7.2 Account Takeover via Password Reset (187600) | 443/tcp (www) | 10.0 | Yes | Vulnerable service reached internally by many hosts | x1.0 | High |
| P1 | 84 | web02.corp.example (10.10.1.11) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P1 | 83 | fs01.corp.example (10.10.2.25) | MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE) (97833) | 445/tcp (cifs) | 8.1 | Yes | Vulnerable service reached internally by many hosts | x1.0 | High |
| P1 | 81 | cam-60.corp.example (10.10.4.60) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-61.corp.example (10.10.4.61) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-62.corp.example (10.10.4.62) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-63.corp.example (10.10.4.63) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-64.corp.example (10.10.4.64) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-65.corp.example (10.10.4.65) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-66.corp.example (10.10.4.66) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-67.corp.example (10.10.4.67) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-68.corp.example (10.10.4.68) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P1 | 81 | cam-69.corp.example (10.10.4.69) | Hikvision IP Camera Command Injection (CVE-2021-36260) (153600) | 80/tcp (www) | 9.8 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 73 | print01.corp.example (10.10.2.43) | Windows Print Spooler Service Enabled (PrintNightmare) (151440) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 67 | web04.corp.example (10.10.1.13) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.38 | Medium |
| P2 | 66 | ws-100.corp.example (10.10.3.100) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-101.corp.example (10.10.3.101) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-101.corp.example (10.10.3.101) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-102.corp.example (10.10.3.102) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-105.corp.example (10.10.3.105) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-106.corp.example (10.10.3.106) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-108.corp.example (10.10.3.108) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-109.corp.example (10.10.3.109) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-111.corp.example (10.10.3.111) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-116.corp.example (10.10.3.116) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-117.corp.example (10.10.3.117) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-121.corp.example (10.10.3.121) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-122.corp.example (10.10.3.122) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-124.corp.example (10.10.3.124) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-125.corp.example (10.10.3.125) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-127.corp.example (10.10.3.127) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-128.corp.example (10.10.3.128) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-131.corp.example (10.10.3.131) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-132.corp.example (10.10.3.132) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-133.corp.example (10.10.3.133) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-134.corp.example (10.10.3.134) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-135.corp.example (10.10.3.135) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-136.corp.example (10.10.3.136) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-138.corp.example (10.10.3.138) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-139.corp.example (10.10.3.139) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-143.corp.example (10.10.3.143) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-143.corp.example (10.10.3.143) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-150.corp.example (10.10.3.150) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-151.corp.example (10.10.3.151) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-152.corp.example (10.10.3.152) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-153.corp.example (10.10.3.153) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-156.corp.example (10.10.3.156) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-158.corp.example (10.10.3.158) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-160.corp.example (10.10.3.160) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-161.corp.example (10.10.3.161) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-161.corp.example (10.10.3.161) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-163.corp.example (10.10.3.163) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-164.corp.example (10.10.3.164) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-169.corp.example (10.10.3.169) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-170.corp.example (10.10.3.170) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-173.corp.example (10.10.3.173) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-174.corp.example (10.10.3.174) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-177.corp.example (10.10.3.177) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-179.corp.example (10.10.3.179) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-182.corp.example (10.10.3.182) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-182.corp.example (10.10.3.182) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-183.corp.example (10.10.3.183) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-183.corp.example (10.10.3.183) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-185.corp.example (10.10.3.185) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-186.corp.example (10.10.3.186) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-187.corp.example (10.10.3.187) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-189.corp.example (10.10.3.189) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-189.corp.example (10.10.3.189) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-190.corp.example (10.10.3.190) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-191.corp.example (10.10.3.191) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-192.corp.example (10.10.3.192) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-051.corp.example (10.10.3.51) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-052.corp.example (10.10.3.52) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-053.corp.example (10.10.3.53) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-055.corp.example (10.10.3.55) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-056.corp.example (10.10.3.56) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-057.corp.example (10.10.3.57) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-058.corp.example (10.10.3.58) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-060.corp.example (10.10.3.60) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-062.corp.example (10.10.3.62) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-064.corp.example (10.10.3.64) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-065.corp.example (10.10.3.65) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-068.corp.example (10.10.3.68) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-069.corp.example (10.10.3.69) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-070.corp.example (10.10.3.70) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-070.corp.example (10.10.3.70) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-072.corp.example (10.10.3.72) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-072.corp.example (10.10.3.72) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-074.corp.example (10.10.3.74) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-078.corp.example (10.10.3.78) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-079.corp.example (10.10.3.79) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-080.corp.example (10.10.3.80) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-082.corp.example (10.10.3.82) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-084.corp.example (10.10.3.84) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-085.corp.example (10.10.3.85) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-086.corp.example (10.10.3.86) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-087.corp.example (10.10.3.87) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-090.corp.example (10.10.3.90) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-091.corp.example (10.10.3.91) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-093.corp.example (10.10.3.93) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-096.corp.example (10.10.3.96) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-098.corp.example (10.10.3.98) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | ws-099.corp.example (10.10.3.99) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-010.corp.example (10.10.7.10) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-011.corp.example (10.10.7.11) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-015.corp.example (10.10.7.15) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-018.corp.example (10.10.7.18) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-020.corp.example (10.10.7.20) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-023.corp.example (10.10.7.23) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-025.corp.example (10.10.7.25) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-026.corp.example (10.10.7.26) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-028.corp.example (10.10.7.28) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-029.corp.example (10.10.7.29) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-033.corp.example (10.10.7.33) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-035.corp.example (10.10.7.35) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-041.corp.example (10.10.7.41) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-041.corp.example (10.10.7.41) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-042.corp.example (10.10.7.42) | Google Chrome < 128.0.6613.84 Multiple Vulnerabilities (206722) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 66 | lt-045.corp.example (10.10.7.45) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.5 | Medium |
| P2 | 62 | web03.corp.example (10.10.1.12) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.28 | Medium |
| P2 | 61 | ws-040.corp.example (10.10.3.40) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.38 | Medium |
| P2 | 59 | ws-041.corp.example (10.10.3.41) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-042.corp.example (10.10.3.42) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-043.corp.example (10.10.3.43) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-044.corp.example (10.10.3.44) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-045.corp.example (10.10.3.45) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-046.corp.example (10.10.3.46) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 59 | ws-047.corp.example (10.10.3.47) | Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (207053) | host-level | 8.8 | Yes | Host is active on the network | x1.34 | Medium |
| P2 | 58 | web05.corp.example (10.10.1.14) | nginx 1.25.x < 1.25.4 Multiple Vulnerabilities (200206) | 443/tcp (www) | 7.5 | No | Vulnerable service reached from the internet | x1.2 | Medium |
| P2 | 56 | prn-51.corp.example (10.10.4.51) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-52.corp.example (10.10.4.52) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-53.corp.example (10.10.4.53) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-54.corp.example (10.10.4.54) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-55.corp.example (10.10.4.55) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-56.corp.example (10.10.4.56) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-57.corp.example (10.10.4.57) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 56 | prn-58.corp.example (10.10.4.58) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Vulnerable service reached internally | x1.0 | High |
| P2 | 52 | db02.corp.example (10.10.2.21) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.22 | Medium |
| P3 | 49 | sql01.corp.example (10.10.2.24) | Microsoft SQL Server Unsupported Version Detection (73756) | 1433/tcp (mssql) | 10.0 | No | Vulnerable service reached internally | x1.0 | Medium |
| P3 | 49 | db04.corp.example (10.10.2.23) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally by many hosts | x1.0 | Medium |
| P3 | 48 | sccm01.corp.example (10.10.2.40) | KB5041578: Windows Server 2019 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-101.corp.example (10.10.3.101) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-103.corp.example (10.10.3.103) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-104.corp.example (10.10.3.104) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-105.corp.example (10.10.3.105) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-107.corp.example (10.10.3.107) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-110.corp.example (10.10.3.110) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-112.corp.example (10.10.3.112) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-118.corp.example (10.10.3.118) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-119.corp.example (10.10.3.119) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-121.corp.example (10.10.3.121) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-122.corp.example (10.10.3.122) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-125.corp.example (10.10.3.125) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-131.corp.example (10.10.3.131) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-132.corp.example (10.10.3.132) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-137.corp.example (10.10.3.137) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-141.corp.example (10.10.3.141) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-145.corp.example (10.10.3.145) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-146.corp.example (10.10.3.146) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-152.corp.example (10.10.3.152) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-153.corp.example (10.10.3.153) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-154.corp.example (10.10.3.154) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-156.corp.example (10.10.3.156) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-159.corp.example (10.10.3.159) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-161.corp.example (10.10.3.161) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-166.corp.example (10.10.3.166) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-172.corp.example (10.10.3.172) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-173.corp.example (10.10.3.173) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-175.corp.example (10.10.3.175) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-176.corp.example (10.10.3.176) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-180.corp.example (10.10.3.180) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-182.corp.example (10.10.3.182) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-186.corp.example (10.10.3.186) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-191.corp.example (10.10.3.191) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-192.corp.example (10.10.3.192) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-059.corp.example (10.10.3.59) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-061.corp.example (10.10.3.61) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-062.corp.example (10.10.3.62) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-066.corp.example (10.10.3.66) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-079.corp.example (10.10.3.79) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-080.corp.example (10.10.3.80) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-085.corp.example (10.10.3.85) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-088.corp.example (10.10.3.88) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-095.corp.example (10.10.3.95) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-096.corp.example (10.10.3.96) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | ws-097.corp.example (10.10.3.97) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-010.corp.example (10.10.7.10) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-011.corp.example (10.10.7.11) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-013.corp.example (10.10.7.13) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-017.corp.example (10.10.7.17) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-018.corp.example (10.10.7.18) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-021.corp.example (10.10.7.21) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-026.corp.example (10.10.7.26) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-027.corp.example (10.10.7.27) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-029.corp.example (10.10.7.29) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-031.corp.example (10.10.7.31) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-034.corp.example (10.10.7.34) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-039.corp.example (10.10.7.39) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-041.corp.example (10.10.7.41) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 48 | lt-042.corp.example (10.10.7.42) | KB5041580: Windows 10 Version 22H2 Security Update (August 2024) (205440) | host-level | 9.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 45 | db01.corp.example (10.10.2.20) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.04 | Medium |
| P3 | 43 | proxy01.corp.example (10.10.1.40) | Squid < 6.4 Multiple Vulnerabilities (182251) | 3128/tcp (http_proxy) | 7.5 | No | Vulnerable service reached internally by many hosts | x1.04 | Medium |
| P3 | 43 | db03.corp.example (10.10.2.22) | PostgreSQL 13.x < 13.13 Multiple Vulnerabilities (183965) | 5432/tcp (postgresql) | 8.8 | No | Vulnerable service reached internally | x1.0 | Medium |
| P3 | 40 | app06.corp.example (10.10.2.34) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.38 | Medium |
| P3 | 40 | app07.corp.example (10.10.2.35) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.36 | Medium |
| P3 | 40 | app08.corp.example (10.10.2.36) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.38 | Medium |
| P3 | 40 | app09.corp.example (10.10.2.37) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.36 | Medium |
| P3 | 39 | mail01.corp.example (10.10.1.25) | Postfix SMTP Smuggling (187315) | 25/tcp (smtp) | 5.3 | No | Vulnerable service reached from the internet | x1.14 | Medium |
| P3 | 39 | ws-165.corp.example (10.10.3.165) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-183.corp.example (10.10.3.183) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-048.corp.example (10.10.3.48) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 39 | ws-093.corp.example (10.10.3.93) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally | x1.5 | Medium |
| P3 | 38 | ws-113.corp.example (10.10.3.113) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-115.corp.example (10.10.3.115) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-117.corp.example (10.10.3.117) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-121.corp.example (10.10.3.121) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-123.corp.example (10.10.3.123) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-131.corp.example (10.10.3.131) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-132.corp.example (10.10.3.132) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-133.corp.example (10.10.3.133) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-137.corp.example (10.10.3.137) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-140.corp.example (10.10.3.140) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-149.corp.example (10.10.3.149) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-151.corp.example (10.10.3.151) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-154.corp.example (10.10.3.154) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-155.corp.example (10.10.3.155) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-158.corp.example (10.10.3.158) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-160.corp.example (10.10.3.160) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-167.corp.example (10.10.3.167) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-177.corp.example (10.10.3.177) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-179.corp.example (10.10.3.179) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-190.corp.example (10.10.3.190) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-191.corp.example (10.10.3.191) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-193.corp.example (10.10.3.193) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-050.corp.example (10.10.3.50) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-052.corp.example (10.10.3.52) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-054.corp.example (10.10.3.54) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-056.corp.example (10.10.3.56) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-061.corp.example (10.10.3.61) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-063.corp.example (10.10.3.63) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-065.corp.example (10.10.3.65) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-066.corp.example (10.10.3.66) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-068.corp.example (10.10.3.68) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-071.corp.example (10.10.3.71) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-072.corp.example (10.10.3.72) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-076.corp.example (10.10.3.76) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-077.corp.example (10.10.3.77) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-081.corp.example (10.10.3.81) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-082.corp.example (10.10.3.82) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-083.corp.example (10.10.3.83) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ws-099.corp.example (10.10.3.99) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | ups-mgmt.corp.example (10.10.5.60) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | No telemetry for this host (unknown) | x1.0 | Medium |
| P3 | 38 | lt-010.corp.example (10.10.7.10) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-016.corp.example (10.10.7.16) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-017.corp.example (10.10.7.17) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-025.corp.example (10.10.7.25) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-027.corp.example (10.10.7.27) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-032.corp.example (10.10.7.32) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-033.corp.example (10.10.7.33) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-034.corp.example (10.10.7.34) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-038.corp.example (10.10.7.38) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-040.corp.example (10.10.7.40) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 38 | lt-044.corp.example (10.10.7.44) | Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29) (192951) | host-level | 7.8 | No | Host is active on the network | x1.5 | Low |
| P3 | 37 | app05.corp.example (10.10.2.33) | Apache Tomcat 9.0.x < 9.0.71 Information Disclosure (171340) | 8080/tcp (www) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.26 | Medium |
| P3 | 34 | mon01.corp.example (10.10.2.42) | SNMP Agent Default Community Name (public) (41028) | 161/udp (snmp) | 7.5 | Yes | Service not observed in use | x1.5 | Low |
| P3 | 34 | ws-102.corp.example (10.10.3.102) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-103.corp.example (10.10.3.103) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-112.corp.example (10.10.3.112) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-114.corp.example (10.10.3.114) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-116.corp.example (10.10.3.116) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-118.corp.example (10.10.3.118) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-124.corp.example (10.10.3.124) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-125.corp.example (10.10.3.125) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-129.corp.example (10.10.3.129) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-130.corp.example (10.10.3.130) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-136.corp.example (10.10.3.136) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-137.corp.example (10.10.3.137) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-140.corp.example (10.10.3.140) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-143.corp.example (10.10.3.143) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-146.corp.example (10.10.3.146) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-151.corp.example (10.10.3.151) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-152.corp.example (10.10.3.152) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-155.corp.example (10.10.3.155) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-156.corp.example (10.10.3.156) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-162.corp.example (10.10.3.162) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-164.corp.example (10.10.3.164) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-166.corp.example (10.10.3.166) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-168.corp.example (10.10.3.168) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-169.corp.example (10.10.3.169) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-172.corp.example (10.10.3.172) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-174.corp.example (10.10.3.174) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-176.corp.example (10.10.3.176) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-179.corp.example (10.10.3.179) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-180.corp.example (10.10.3.180) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-184.corp.example (10.10.3.184) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-187.corp.example (10.10.3.187) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-188.corp.example (10.10.3.188) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-194.corp.example (10.10.3.194) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-049.corp.example (10.10.3.49) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-051.corp.example (10.10.3.51) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-053.corp.example (10.10.3.53) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-054.corp.example (10.10.3.54) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-063.corp.example (10.10.3.63) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-065.corp.example (10.10.3.65) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-066.corp.example (10.10.3.66) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-068.corp.example (10.10.3.68) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-070.corp.example (10.10.3.70) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-074.corp.example (10.10.3.74) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-077.corp.example (10.10.3.77) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-083.corp.example (10.10.3.83) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-084.corp.example (10.10.3.84) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-089.corp.example (10.10.3.89) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-092.corp.example (10.10.3.92) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-093.corp.example (10.10.3.93) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-094.corp.example (10.10.3.94) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-095.corp.example (10.10.3.95) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-096.corp.example (10.10.3.96) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | ws-097.corp.example (10.10.3.97) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-016.corp.example (10.10.7.16) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-022.corp.example (10.10.7.22) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-024.corp.example (10.10.7.24) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-028.corp.example (10.10.7.28) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-030.corp.example (10.10.7.30) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-032.corp.example (10.10.7.32) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-037.corp.example (10.10.7.37) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 34 | lt-043.corp.example (10.10.7.43) | 7-Zip < 24.07 Code Execution (189385) | host-level | 7.0 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-102.corp.example (10.10.3.102) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-114.corp.example (10.10.3.114) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-120.corp.example (10.10.3.120) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-126.corp.example (10.10.3.126) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-128.corp.example (10.10.3.128) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-130.corp.example (10.10.3.130) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-134.corp.example (10.10.3.134) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-136.corp.example (10.10.3.136) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-142.corp.example (10.10.3.142) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-144.corp.example (10.10.3.144) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-145.corp.example (10.10.3.145) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-146.corp.example (10.10.3.146) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-147.corp.example (10.10.3.147) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-148.corp.example (10.10.3.148) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-157.corp.example (10.10.3.157) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-160.corp.example (10.10.3.160) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-162.corp.example (10.10.3.162) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-163.corp.example (10.10.3.163) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-169.corp.example (10.10.3.169) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-171.corp.example (10.10.3.171) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-174.corp.example (10.10.3.174) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-178.corp.example (10.10.3.178) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-181.corp.example (10.10.3.181) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-185.corp.example (10.10.3.185) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-192.corp.example (10.10.3.192) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-048.corp.example (10.10.3.48) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-051.corp.example (10.10.3.51) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-059.corp.example (10.10.3.59) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-061.corp.example (10.10.3.61) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-064.corp.example (10.10.3.64) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-067.corp.example (10.10.3.67) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-073.corp.example (10.10.3.73) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-075.corp.example (10.10.3.75) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-088.corp.example (10.10.3.88) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-089.corp.example (10.10.3.89) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-092.corp.example (10.10.3.92) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-095.corp.example (10.10.3.95) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | ws-097.corp.example (10.10.3.97) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-011.corp.example (10.10.7.11) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-014.corp.example (10.10.7.14) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-020.corp.example (10.10.7.20) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-024.corp.example (10.10.7.24) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-025.corp.example (10.10.7.25) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-034.corp.example (10.10.7.34) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-035.corp.example (10.10.7.35) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-036.corp.example (10.10.7.36) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-037.corp.example (10.10.7.37) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-039.corp.example (10.10.7.39) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-042.corp.example (10.10.7.42) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-043.corp.example (10.10.7.43) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | lt-044.corp.example (10.10.7.44) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 32 | eng-lt01.corp.example (10.10.7.46) | Zoom Client < 6.0.2 Privilege Escalation (201084) | host-level | 6.5 | No | Host is active on the network | x1.5 | Low |
| P3 | 29 | fs02.corp.example (10.10.2.26) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Vulnerable service reached internally by many hosts | x1.0 | Medium |
| P4 | 20 | web01.corp.example (10.10.1.10) | OpenSSH < 9.6 Multiple Vulnerabilities (Terrapin) (187201) | 22/tcp (ssh) | 5.9 | No | Connections to service blocked by firewall | x1.5 | Low |
| P4 | 16 | ws-106.corp.example (10.10.3.106) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-107.corp.example (10.10.3.107) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-108.corp.example (10.10.3.108) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-112.corp.example (10.10.3.112) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-113.corp.example (10.10.3.113) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-114.corp.example (10.10.3.114) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-117.corp.example (10.10.3.117) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-118.corp.example (10.10.3.118) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-119.corp.example (10.10.3.119) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-122.corp.example (10.10.3.122) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-123.corp.example (10.10.3.123) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-128.corp.example (10.10.3.128) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-141.corp.example (10.10.3.141) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-145.corp.example (10.10.3.145) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-155.corp.example (10.10.3.155) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-164.corp.example (10.10.3.164) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-166.corp.example (10.10.3.166) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-168.corp.example (10.10.3.168) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-185.corp.example (10.10.3.185) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-189.corp.example (10.10.3.189) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-193.corp.example (10.10.3.193) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-053.corp.example (10.10.3.53) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-055.corp.example (10.10.3.55) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-056.corp.example (10.10.3.56) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-058.corp.example (10.10.3.58) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-064.corp.example (10.10.3.64) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-074.corp.example (10.10.3.74) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-078.corp.example (10.10.3.78) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-081.corp.example (10.10.3.81) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-085.corp.example (10.10.3.85) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | ws-091.corp.example (10.10.3.91) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-012.corp.example (10.10.7.12) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-013.corp.example (10.10.7.13) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-014.corp.example (10.10.7.14) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-017.corp.example (10.10.7.17) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-019.corp.example (10.10.7.19) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-021.corp.example (10.10.7.21) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-022.corp.example (10.10.7.22) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-023.corp.example (10.10.7.23) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-029.corp.example (10.10.7.29) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-033.corp.example (10.10.7.33) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-036.corp.example (10.10.7.36) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-037.corp.example (10.10.7.37) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-044.corp.example (10.10.7.44) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 16 | lt-045.corp.example (10.10.7.45) | SMB Signing not required (57608) | 445/tcp (cifs) | 5.3 | No | Service not observed in use | x1.5 | Low |
| P4 | 13 | prn-4f.corp.example (10.10.4.50) | Unencrypted Telnet Server (42263) | 23/tcp (telnet) | 6.5 | No | Service not observed in use | x1.0 | Low |
| P4 | 12 | jump02.corp.example (10.10.3.6) | Terminal Services Doesn't Use Network Level Authentication (NLA) Only (58453) | 3389/tcp (msrdp) | 4.0 | No | Service not observed in use | x1.5 | Low |
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

### web02.corp.example (10.10.1.11) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (106 inbound, 105 outbound sessions)
- Internet-exposed vulnerable service: yes

**Exploitation indicators** (leads unless marked corroborated)

- [lead] IPS/IDS alerted 1 time(s) on traffic to this service and did not block it: Intel::Notice - Synthetic StyleSmuggler exploitation alert on the web service (from 209.73.130.148). An alert shows an attempt, not that it succeeded.
- [lead] 10.10.1.11 sent 24.8 MB to external address 99.84.67.186 after the flagged inbound contact at 2026-10-17T08:00:00Z.
- [corroborated] Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service, and the host then showed exfil. Treat this as likely exploitation and start incident response; host forensics is still needed to confirm a compromise.

**Findings and exposure evidence**

#### P1 (100) Synthetic Magento StyleSmuggler finding

- Plugin 990001, Critical, CVSS 10.0, port 443/tcp, CVE-2026-75650
- Why this score: Base severity: CVSS v3 10.0 (Critical). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 88 completed sessions from 75 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 88 completed, 0 attempts, 0 blocked; first 2026-10-12T02:37:23Z, last 2026-10-18T01:13:29Z; top sources: 198.51.100.247 (ext) x3, 198.51.100.60 (ext) x2, 198.51.100.155 (ext) x2, 198.51.100.249 (ext) x2, 198.51.100.142 (ext) x2, 198.51.100.158 (ext) x2, 198.51.100.35 (ext) x2, 198.51.100.92 (ext) x2
- Synopsis: Fabricated scan finding for the source-linked web server storyline.
- Remediation: Apply the vendor hotfix and review host evidence.

#### P1 (84) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 88 completed sessions from 75 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings. Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.
- Traffic to service: 88 completed, 0 attempts, 0 blocked; first 2026-10-12T02:37:23Z, last 2026-10-18T01:13:29Z; top sources: 198.51.100.247 (ext) x3, 198.51.100.60 (ext) x2, 198.51.100.155 (ext) x2, 198.51.100.249 (ext) x2, 198.51.100.142 (ext) x2, 198.51.100.158 (ext) x2, 198.51.100.35 (ext) x2, 198.51.100.92 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 5 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.24, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

Outbound to 3 external address(es); top: 99.84.67.186 x3, 185.157.160.251 x2, 209.141.43.95 x1.

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

### vpn01.corp.example (10.10.1.30) - P1 - act now

- Operating system: Ivanti Connect Secure 22.3
- Findings: 1 Critical
- Seen in telemetry: yes (298 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P1 (100) Ivanti Connect Secure Command Injection (CVE-2024-21887)

- Plugin 189987, Critical, CVSS 9.1, port 443/tcp (www), CVE-2023-46805, CVE-2024-21887
- Why this score: Base severity: CVSS v3 9.1 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached from the internet - 250 completed sessions from 250 external and 0 internal sources.
- Traffic to service: 250 completed, 0 attempts, 0 blocked; first 2026-10-12T00:44:13Z, last 2026-10-18T03:09:59Z; top sources: 73.162.196.108 (ext) x1, 73.162.200.14 (ext) x1, 24.18.204.8 (ext) x1, 73.162.156.163 (ext) x1, 73.162.34.42 (ext) x1, 24.18.52.54 (ext) x1, 73.162.197.196 (ext) x1, 24.18.133.212 (ext) x1
- Synopsis: The VPN appliance is affected by authentication bypass and command injection vulnerabilities.
- Remediation: Apply the vendor patch and run the integrity checker.

**Blast radius**

No completed internal sessions from this host were observed.

### app02.corp.example (10.10.2.30) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (150 inbound, 93 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 142 completed sessions from 0 external and 27 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 142 completed, 0 attempts, 0 blocked; first 2026-10-12T01:14:05Z, last 2026-10-18T02:15:03Z; top sources: 10.10.1.11 x89, 10.10.3.112 x4, 10.10.3.136 x4, 10.10.3.73 x4, 10.10.3.187 x3, 10.10.3.184 x3, 10.10.3.166 x3, 10.10.3.70 x3
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (66), MSSQL (23), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### app03.corp.example (10.10.2.31) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (143 inbound, 71 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 132 completed sessions from 0 external and 28 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 132 completed, 0 attempts, 0 blocked; first 2026-10-12T00:08:34Z, last 2026-10-18T02:51:14Z; top sources: 10.10.1.12 x70, 10.10.7.13 x4, 10.10.7.31 x4, 10.10.3.171 x4, 10.10.3.147 x4, 10.10.3.61 x4, 10.10.3.48 x4, 10.10.3.105 x4
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (67), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### app04.corp.example (10.10.2.32) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (135 inbound, 98 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell)

- Plugin 156057, Critical, CVSS 10.0, port 8080/tcp (www), CVE-2021-44228
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 124 completed sessions from 0 external and 22 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 124 completed, 0 attempts, 0 blocked; first 2026-10-12T00:20:59Z, last 2026-10-18T01:35:42Z; top sources: 10.10.1.13 x66, 10.10.3.95 x4, 10.10.3.84 x4, 10.10.3.89 x4, 10.10.3.121 x4, 10.10.3.52 x4, 10.10.3.185 x4, 10.10.3.69 x4
- Synopsis: The application uses a Log4j version affected by remote code execution.
- Remediation: Upgrade to Apache Log4j 2.17.1 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (55), MSSQL (39), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.22 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### jenkins01.corp.example (10.10.2.45) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (44 inbound, 82 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (100) Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)

- Plugin 189463, Critical, CVSS 9.8, port 8080/tcp (www), CVE-2024-23897
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 33 completed sessions from 0 external and 18 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 33 completed, 0 attempts, 0 blocked; first 2026-10-12T03:42:43Z, last 2026-10-17T09:09:49Z; top sources: 10.10.3.88 x3, 10.10.3.122 x3, 10.10.3.116 x3, 10.10.3.129 x3, 10.10.3.166 x3, 10.10.3.77 x3, 10.10.7.11 x2, 10.10.3.185 x2
- Synopsis: The Jenkins CLI allows unauthenticated reading of arbitrary files.
- Remediation: Upgrade to Jenkins 2.442 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SSH (52).
Reachable hosts with High/Critical findings: 10.10.2.44, 10.10.2.21.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.35 | 1 | 22/tcp | Medium |
| 10.10.2.21 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

Outbound to 30 external address(es); top: 104.16.24.85 x1, 104.16.24.78 x1, 104.16.24.58 x1, 104.16.24.45 x1, 104.16.24.205 x1.

### backup01.corp.example (10.10.2.41) - P1 - act now

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Critical
- Seen in telemetry: yes (13 inbound, 46 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (93) Veeam Backup & Replication Credential Disclosure (CVE-2023-27532)

- Plugin 173914, Critical, CVSS 7.5, port 9401/tcp (veeam), CVE-2023-27532
- Why this score: Base severity: CVSS v3 7.5 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 23 internal host(s) directly and 50 within 2 hops, including 36 with High/Critical findings.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-14T16:09:44Z, last 2026-10-17T22:18:10Z; top sources: 10.10.2.40 x4
- Synopsis: The backup service exposes encrypted credentials to unauthenticated users.
- Remediation: Upgrade to Veeam Backup & Replication 12.0.0.1420 P20230223 or later.

**Blast radius**

Completed sessions to 23 internal host(s) directly, 50 within 2 hops.
Lateral-movement protocols used: SSH (38), SMB (8).
Reachable hosts with High/Critical findings: 10.10.1.11, 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.11 | 1 | 22/tcp | Critical |
| 10.10.2.24 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 22/tcp | Critical |
| 10.10.2.31 | 1 | 22/tcp | Critical |
| 10.10.2.32 | 1 | 22/tcp | Critical |
| 10.10.2.40 | 1 | 445/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.45 | 1 | 22/tcp | Critical |
| 10.10.1.12 | 1 | 22/tcp | High |
| 10.10.1.13 | 1 | 22/tcp | High |
| 10.10.1.14 | 1 | 22/tcp | High |
| 10.10.1.40 | 1 | 22/tcp | High |
| 10.10.2.21 | 1 | 22/tcp | High |
| 10.10.2.22 | 1 | 22/tcp | High |
| ... 35 more | | | |

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
- Traffic to service: 31 completed, 0 attempts, 60 blocked; first 2026-10-12T03:26:52Z, last 2026-10-18T02:05:18Z; top sources: 10.10.3.5 x30, 10.10.1.10 x1
- Synopsis: The remote host is affected by a remote code execution vulnerability in Remote Desktop Services.
- Remediation: Apply the May 2019 security update and enable Network Level Authentication.

**Blast radius**

No completed internal sessions from this host were observed.

### git01.corp.example (10.10.2.44) - P1 - act now

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Critical
- Seen in telemetry: yes (156 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (85) GitLab 16.1 < 16.7.2 Account Takeover via Password Reset

- Plugin 187600, Critical, CVSS 10.0, port 443/tcp (www), CVE-2023-7028
- Why this score: Base severity: CVSS v3 10.0 (Critical). A public exploit is available. Exposure: vulnerable service reached internally by many hosts - 72 completed sessions from 0 external and 18 internal sources.
- Traffic to service: 72 completed, 0 attempts, 0 blocked; first 2026-10-12T01:02:00Z, last 2026-10-18T02:41:25Z; top sources: 10.10.3.185 x6, 10.10.3.91 x6, 10.10.3.77 x6, 10.10.3.88 x5, 10.10.3.127 x5, 10.10.3.166 x5, 10.10.3.143 x4, 10.10.3.122 x4
- Synopsis: The GitLab instance allows account takeover through the password reset flow.
- Remediation: Upgrade to GitLab 16.7.2 or later and enable two-factor authentication.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 24 external address(es); top: 140.82.112.196 x2, 140.82.112.86 x1, 140.82.112.75 x1, 140.82.112.38 x1, 140.82.112.64 x1.

### fs01.corp.example (10.10.2.25) - P1 - act now

- Operating system: Microsoft Windows Server 2012 R2
- Findings: 1 Critical
- Seen in telemetry: yes (533 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Exploitation indicators** (leads unless marked corroborated)

- [lead] 10.10.1.10, which is flagged for investigation, newly connected to this vulnerable service at 2026-10-16T04:07:00Z. Check this host for signs of lateral movement.

**Findings and exposure evidence**

#### P1 (83) MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)

- Plugin 97833, Critical, CVSS 8.1, port 445/tcp (cifs), CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
- Why this score: Base severity: CVSS v3 8.1 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally by many hosts - 533 completed sessions from 0 external and 62 internal sources. Traffic gives leads worth investigating; nothing in the logs confirms exploitation.
- Traffic to service: 533 completed, 0 attempts, 0 blocked; first 2026-10-12T00:03:04Z, last 2026-10-18T03:08:18Z; top sources: 10.10.3.44 x25, 10.10.3.45 x25, 10.10.3.41 x25, 10.10.3.47 x25, 10.10.3.42 x25, 10.10.3.46 x25, 10.10.3.40 x25, 10.10.3.43 x25
- Synopsis: The remote Windows host is affected by multiple remote code execution vulnerabilities in SMBv1.
- Remediation: Apply MS17-010 and disable SMBv1.

**Blast radius**

No completed internal sessions from this host were observed.

### cam-60.corp.example (10.10.4.60) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T19:51:17Z, last 2026-10-17T23:43:48Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.58 x1, 47.88.59.142 x1, 47.88.59.68 x1, 47.88.59.218 x1, 47.88.59.106 x1.

### cam-61.corp.example (10.10.4.61) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 3 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T01:13:48Z, last 2026-10-18T00:59:01Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 3 external address(es); top: 47.88.59.219 x1, 47.88.59.217 x1, 47.88.59.140 x1.

### cam-62.corp.example (10.10.4.62) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (14 inbound, 6 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 4 attempts, 0 blocked; first 2026-10-12T12:03:54Z, last 2026-10-17T17:23:19Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 6 external address(es); top: 47.88.59.169 x1, 47.88.59.50 x1, 47.88.59.142 x1, 47.88.59.70 x1, 47.88.59.113 x1.

### cam-63.corp.example (10.10.4.63) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 8 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T01:00:48Z, last 2026-10-17T01:07:44Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 8 external address(es); top: 47.88.59.171 x1, 47.88.59.77 x1, 47.88.59.2 x1, 47.88.59.131 x1, 47.88.59.89 x1.

### cam-64.corp.example (10.10.4.64) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 8 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T13:53:34Z, last 2026-10-13T21:56:33Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 8 external address(es); top: 47.88.59.159 x1, 47.88.59.144 x1, 47.88.59.37 x1, 47.88.59.56 x1, 47.88.59.135 x1.

### cam-65.corp.example (10.10.4.65) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 4 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T10:52:55Z, last 2026-10-17T08:03:47Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 4 external address(es); top: 47.88.59.64 x1, 47.88.59.225 x1, 47.88.59.114 x1, 47.88.59.24 x1.

### cam-66.corp.example (10.10.4.66) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T06:00:08Z, last 2026-10-14T19:58:08Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.90 x1, 47.88.59.51 x1, 47.88.59.225 x1, 47.88.59.108 x1, 47.88.59.157 x1.

### cam-67.corp.example (10.10.4.67) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 8 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-13T04:18:10Z, last 2026-10-17T21:49:52Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.201 x2, 47.88.59.123 x1, 47.88.59.106 x1, 47.88.59.54 x1, 47.88.59.188 x1.

### cam-68.corp.example (10.10.4.68) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 7 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T11:20:14Z, last 2026-10-17T03:46:00Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 7 external address(es); top: 47.88.59.47 x1, 47.88.59.11 x1, 47.88.59.218 x1, 47.88.59.244 x1, 47.88.59.222 x1.

### cam-69.corp.example (10.10.4.69) - P1 - act now

- Operating system: Hikvision IP Camera
- Findings: 1 Critical
- Seen in telemetry: yes (10 inbound, 5 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P1 (81) Hikvision IP Camera Command Injection (CVE-2021-36260)

- Plugin 153600, Critical, CVSS 9.8, port 80/tcp (www), CVE-2021-36260
- Why this score: Base severity: CVSS v3 9.8 (Critical). A public exploit is available (Metasploit). Exposure: vulnerable service reached internally - 4 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 4 completed, 0 attempts, 0 blocked; first 2026-10-12T18:11:12Z, last 2026-10-16T07:42:17Z; top sources: 10.10.2.42 x4
- Synopsis: The camera's web server is affected by an unauthenticated command injection vulnerability.
- Remediation: Upgrade the camera firmware to the vendor's fixed release.

**Blast radius**

No completed internal sessions from this host were observed.

Outbound to 5 external address(es); top: 47.88.59.127 x1, 47.88.59.4 x1, 47.88.59.85 x1, 47.88.59.100 x1, 47.88.59.15 x1.

### print01.corp.example (10.10.2.43) - P2 - this cycle

- Operating system: Microsoft Windows Server 2016
- Findings: 1 Critical
- Seen in telemetry: yes (159 inbound, 158 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (73) Windows Print Spooler Service Enabled (PrintNightmare)

- Plugin 151440, Critical, CVSS 8.8, port host-level, CVE-2021-34527
- Why this score: Base severity: CVSS v3 8.8 (Critical). A public exploit is available (Metasploit). Exposure: host is active on the network - 159 completed sessions from 0 external and 94 internal sources. Blast radius: the host talks to 9 internal host(s) directly and 9 within 2 hops, including 8 with High/Critical findings.
- Traffic to host: 159 completed, 0 attempts, 0 blocked; first 2026-10-12T00:52:00Z, last 2026-10-18T02:34:53Z; top sources: 10.10.3.6 x6, 10.10.2.42 x3, 10.10.3.124 x2, 10.10.3.159 x2, 10.10.7.31 x2, 10.10.3.182 x2, 10.10.3.82 x2, 10.10.3.131 x2
- Synopsis: The Print Spooler service on the remote host is affected by remote code execution.
- Remediation: Apply the July 2021 updates and restrict Point and Print.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 9 within 2 hops.
Lateral-movement protocols used: LDAP (6).
Reachable hosts with High/Critical findings: 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.4.51 | 1 | 9100/tcp | High |
| 10.10.4.52 | 1 | 9100/tcp | High |
| 10.10.4.53 | 1 | 9100/tcp | High |
| 10.10.4.54 | 1 | 9100/tcp | High |
| 10.10.4.55 | 1 | 9100/tcp | High |
| 10.10.4.56 | 1 | 9100/tcp | High |
| 10.10.4.57 | 1 | 9100/tcp | High |
| 10.10.4.58 | 1 | 9100/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### web04.corp.example (10.10.1.13) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (93 inbound, 76 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (67) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 76 completed sessions from 66 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 5 within 2 hops, including 3 with High/Critical findings.
- Traffic to service: 76 completed, 0 attempts, 0 blocked; first 2026-10-12T04:58:29Z, last 2026-10-17T23:42:16Z; top sources: 198.51.100.188 (ext) x2, 198.51.100.18 (ext) x2, 198.51.100.38 (ext) x2, 198.51.100.87 (ext) x2, 198.51.100.193 (ext) x2, 198.51.100.28 (ext) x2, 198.51.100.132 (ext) x2, 198.51.100.95 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 5 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.24, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

### ws-100.corp.example (10.10.3.100) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-101.corp.example (10.10.3.101) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-102.corp.example (10.10.3.102) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T21:38:42Z, last 2026-10-15T01:02:15Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T21:38:42Z, last 2026-10-15T01:02:15Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T21:38:42Z, last 2026-10-15T01:02:15Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| 10.10.3.174 | 2 |  | High |
| ... 9 more | | | |

### ws-105.corp.example (10.10.3.105) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (4), SMB (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-106.corp.example (10.10.3.106) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-108.corp.example (10.10.3.108) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-109.corp.example (10.10.3.109) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 23 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-111.corp.example (10.10.3.111) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T00:40:55Z, last 2026-10-17T13:37:25Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-116.corp.example (10.10.3.116) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (4), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 14 more | | | |

### ws-117.corp.example (10.10.3.117) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-121.corp.example (10.10.3.121) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-122.corp.example (10.10.3.122) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (3), SSH (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 22 more | | | |

### ws-124.corp.example (10.10.3.124) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-125.corp.example (10.10.3.125) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 39 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-127.corp.example (10.10.3.127) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 45 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (10), SSH (3), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 22 more | | | |

### ws-128.corp.example (10.10.3.128) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-131.corp.example (10.10.3.131) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-132.corp.example (10.10.3.132) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-133.corp.example (10.10.3.133) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-134.corp.example (10.10.3.134) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-135.corp.example (10.10.3.135) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-136.corp.example (10.10.3.136) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-138.corp.example (10.10.3.138) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 24 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T15:50:18Z, last 2026-10-17T21:39:10Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

### ws-139.corp.example (10.10.3.139) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (3), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-143.corp.example (10.10.3.143) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (3), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 13 more | | | |

### ws-150.corp.example (10.10.3.150) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-151.corp.example (10.10.3.151) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-152.corp.example (10.10.3.152) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-153.corp.example (10.10.3.153) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (5), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-156.corp.example (10.10.3.156) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (3 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 16 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T12:07:44Z, last 2026-10-16T20:13:09Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 16 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T12:07:44Z, last 2026-10-16T20:13:09Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 16 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T12:07:44Z, last 2026-10-16T20:13:09Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (4), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| 10.10.3.174 | 2 |  | High |
| ... 9 more | | | |

### ws-158.corp.example (10.10.3.158) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-160.corp.example (10.10.3.160) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-161.corp.example (10.10.3.161) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-163.corp.example (10.10.3.163) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-164.corp.example (10.10.3.164) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 18 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (4), SMB (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-169.corp.example (10.10.3.169) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: Kerberos (4), SMB (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-170.corp.example (10.10.3.170) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-173.corp.example (10.10.3.173) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-174.corp.example (10.10.3.174) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 17 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T05:58:43Z, last 2026-10-16T16:44:16Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 17 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T05:58:43Z, last 2026-10-16T16:44:16Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 17 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T05:58:43Z, last 2026-10-16T16:44:16Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 9 more | | | |

### ws-177.corp.example (10.10.3.177) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-179.corp.example (10.10.3.179) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-182.corp.example (10.10.3.182) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 47 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), SSH (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| ... 23 more | | | |

### ws-183.corp.example (10.10.3.183) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 25 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T15:02:06Z, last 2026-10-15T11:03:45Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 25 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T15:02:06Z, last 2026-10-15T11:03:45Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 25 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-12T15:02:06Z, last 2026-10-15T11:03:45Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

### ws-185.corp.example (10.10.3.185) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 45 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (4), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 14 more | | | |

### ws-186.corp.example (10.10.3.186) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-187.corp.example (10.10.3.187) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-189.corp.example (10.10.3.189) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-190.corp.example (10.10.3.190) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-191.corp.example (10.10.3.191) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-192.corp.example (10.10.3.192) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (3 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T23:59:15Z, last 2026-10-17T20:13:18Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T23:59:15Z, last 2026-10-17T20:13:18Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 15 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T23:59:15Z, last 2026-10-17T20:13:18Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| 10.10.3.174 | 2 |  | High |
| ... 9 more | | | |

### ws-051.corp.example (10.10.3.51) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-052.corp.example (10.10.3.52) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-053.corp.example (10.10.3.53) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-055.corp.example (10.10.3.55) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: LDAP (5), Kerberos (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-056.corp.example (10.10.3.56) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (5).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-057.corp.example (10.10.3.57) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-16T18:42:38Z, last 2026-10-17T23:23:40Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 10 more | | | |

### ws-058.corp.example (10.10.3.58) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-060.corp.example (10.10.3.60) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 27 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 27 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), SSH (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 12 more | | | |

### ws-062.corp.example (10.10.3.62) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-064.corp.example (10.10.3.64) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (4), SMB (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-065.corp.example (10.10.3.65) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-068.corp.example (10.10.3.68) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-069.corp.example (10.10.3.69) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-070.corp.example (10.10.3.70) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-072.corp.example (10.10.3.72) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 3 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 27 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 27 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 27 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 27 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 12 more | | | |

### ws-074.corp.example (10.10.3.74) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-078.corp.example (10.10.3.78) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-079.corp.example (10.10.3.79) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-080.corp.example (10.10.3.80) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-082.corp.example (10.10.3.82) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (4), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-084.corp.example (10.10.3.84) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (3 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T08:11:27Z, last 2026-10-16T14:00:33Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T08:11:27Z, last 2026-10-16T14:00:33Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 19 more | | | |

### ws-085.corp.example (10.10.3.85) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-086.corp.example (10.10.3.86) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 36 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 21 more | | | |

### ws-087.corp.example (10.10.3.87) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-090.corp.example (10.10.3.90) - P2 - this cycle

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. 3 connection(s) to it were refused by the host (reset, as Zeek logs REJ). Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 19 with High/Critical findings.
- Traffic to host: 0 completed, 0 attempts, 0 blocked, 3 refused by the host; first 2026-10-13T05:41:03Z, last 2026-10-15T07:09:30Z
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (3), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 14 more | | | |

### ws-091.corp.example (10.10.3.91) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 37 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 37 within 2 hops.
Lateral-movement protocols used: SMB (7), SSH (3), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 22 more | | | |

### ws-093.corp.example (10.10.3.93) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (3 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 24 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T15:05:22Z, last 2026-10-16T09:48:48Z; top sources: 10.10.2.40 x3
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 24 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-13T15:05:22Z, last 2026-10-15T15:58:34Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 24 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T15:05:22Z, last 2026-10-16T09:48:48Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

### ws-096.corp.example (10.10.3.96) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-098.corp.example (10.10.3.98) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-099.corp.example (10.10.3.99) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-010.corp.example (10.10.7.10) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-011.corp.example (10.10.7.11) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 40 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (5), SSH (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| ... 23 more | | | |

### lt-015.corp.example (10.10.7.15) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-018.corp.example (10.10.7.18) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 20 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-020.corp.example (10.10.7.20) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-023.corp.example (10.10.7.23) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 42 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-025.corp.example (10.10.7.25) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-026.corp.example (10.10.7.26) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-028.corp.example (10.10.7.28) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-029.corp.example (10.10.7.29) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-033.corp.example (10.10.7.33) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-035.corp.example (10.10.7.35) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-041.corp.example (10.10.7.41) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High, 1 Critical
- Seen in telemetry: yes (0 inbound, 20 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (2), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-042.corp.example (10.10.7.42) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Google Chrome < 128.0.6613.84 Multiple Vulnerabilities

- Plugin 206722, High, CVSS 8.8, port host-level, CVE-2024-7965
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Google Chrome version 128.0.6613.84 or later.

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-045.corp.example (10.10.7.45) - P2 - this cycle

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (66) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### web03.corp.example (10.10.1.12) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (101 inbound, 80 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (62) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 82 completed sessions from 65 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 82 completed, 0 attempts, 0 blocked; first 2026-10-12T01:23:24Z, last 2026-10-18T03:02:58Z; top sources: 198.51.100.84 (ext) x4, 198.51.100.85 (ext) x3, 198.51.100.156 (ext) x3, 198.51.100.245 (ext) x2, 198.51.100.60 (ext) x2, 198.51.100.65 (ext) x2, 198.51.100.142 (ext) x2, 198.51.100.165 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.23 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

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
Lateral-movement protocols used: SMB (30), LDAP (10), Kerberos (10), RDP (8).
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
- Seen in telemetry: yes (0 inbound, 82 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (28), Kerberos (10), LDAP (10), RDP (7).
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
Lateral-movement protocols used: SMB (35), LDAP (10), Kerberos (10), RDP (5).
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
- Seen in telemetry: yes (0 inbound, 74 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (29), Kerberos (10), LDAP (10), RDP (4).
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
Lateral-movement protocols used: SMB (32), Kerberos (10), LDAP (10), RDP (3).
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
- Seen in telemetry: yes (0 inbound, 80 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (30), LDAP (10), Kerberos (10), RDP (5).
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
- Seen in telemetry: yes (0 inbound, 74 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (59) Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities

- Plugin 207053, High, CVSS 8.8, port host-level, CVE-2024-7965, CVE-2024-7971
- Why this score: Base severity: CVSS v3 8.8 (High). A public exploit is available. Exposure: host is active on the network. Blast radius: the host talks to 4 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Synopsis: The browser installed on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Microsoft Edge version 129.0.2792.52 or later.

**Blast radius**

Completed sessions to 4 internal host(s) directly, 4 within 2 hops.
Lateral-movement protocols used: SMB (26), LDAP (10), Kerberos (10), RDP (5).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 17 external address(es); top: 93.184.223.178 x1, 93.184.85.157 x1, 93.184.64.87 x1, 93.184.247.117 x1, 93.184.80.151 x1.

### ws-047.corp.example (10.10.3.47) - P2 - this cycle

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
Lateral-movement protocols used: SMB (30), Kerberos (10), LDAP (10), RDP (3).
Reachable hosts with High/Critical findings: 10.10.2.25.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.6.70 | 1 | 3389/tcp, 445/tcp | - |

Outbound to 17 external address(es); top: 93.184.191.222 x1, 93.184.59.143 x1, 93.184.89.58 x1, 93.184.108.230 x1, 93.184.67.66 x1.

### web05.corp.example (10.10.1.14) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (118 inbound, 95 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P2 (58) nginx 1.25.x < 1.25.4 Multiple Vulnerabilities

- Plugin 200206, High, CVSS 7.5, port 443/tcp (www), CVE-2024-24989
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 102 completed sessions from 89 external and 0 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 4 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 102 completed, 0 attempts, 0 blocked; first 2026-10-12T00:10:42Z, last 2026-10-18T02:34:27Z; top sources: 198.51.100.143 (ext) x3, 198.51.100.209 (ext) x3, 198.51.100.132 (ext) x2, 198.51.100.120 (ext) x2, 198.51.100.208 (ext) x2, 198.51.100.130 (ext) x2, 198.51.100.232 (ext) x2, 198.51.100.166 (ext) x2
- Synopsis: The web server is affected by multiple denial of service vulnerabilities.
- Remediation: Upgrade to nginx 1.25.4 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 4 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.23 | 2 |  | High |
| 10.10.0.10 | 2 |  | - |

### prn-51.corp.example (10.10.4.51) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (22 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T14:52:05Z, last 2026-10-18T02:16:27Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-52.corp.example (10.10.4.52) - P2 - this cycle

- Operating system: Xerox VersaLink
- Findings: 1 High
- Seen in telemetry: yes (23 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T03:02:52Z, last 2026-10-17T11:01:25Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-53.corp.example (10.10.4.53) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (24 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T10:17:43Z, last 2026-10-17T23:05:09Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-54.corp.example (10.10.4.54) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (17 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T11:07:18Z, last 2026-10-18T02:33:44Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-55.corp.example (10.10.4.55) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (22 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-13T06:51:33Z, last 2026-10-17T05:48:26Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-56.corp.example (10.10.4.56) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (32 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T07:53:32Z, last 2026-10-15T14:31:46Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-57.corp.example (10.10.4.57) - P2 - this cycle

- Operating system: HP LaserJet
- Findings: 1 High
- Seen in telemetry: yes (35 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-12T01:32:32Z, last 2026-10-16T01:38:22Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### prn-58.corp.example (10.10.4.58) - P2 - this cycle

- Operating system: Ricoh MP
- Findings: 1 High
- Seen in telemetry: yes (25 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (56) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: vulnerable service reached internally - 6 completed sessions from 0 external and 1 internal sources.
- Traffic to service: 6 completed, 0 attempts, 0 blocked; first 2026-10-13T09:11:44Z, last 2026-10-18T02:56:29Z; top sources: 10.10.2.42 x6
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

No completed internal sessions from this host were observed.

### db02.corp.example (10.10.2.21) - P2 - this cycle

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (129 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P2 (52) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 121 completed sessions from 0 external and 2 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 121 completed, 0 attempts, 0 blocked; first 2026-10-12T00:56:13Z, last 2026-10-18T02:32:25Z; top sources: 10.10.2.35 x67, 10.10.2.37 x54
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.
Lateral-movement protocols used: PostgreSQL (30).
Reachable hosts with High/Critical findings: 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.22 | 1 | 5432/tcp | High |

### db04.corp.example (10.10.2.23) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (310 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (49) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 299 completed sessions from 0 external and 5 internal sources.
- Traffic to service: 299 completed, 0 attempts, 0 blocked; first 2026-10-12T00:06:03Z, last 2026-10-18T02:49:54Z; top sources: 10.10.2.31 x67, 10.10.2.30 x66, 10.10.2.34 x65, 10.10.2.33 x60, 10.10.2.36 x41
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

No completed internal sessions from this host were observed.

### sql01.corp.example (10.10.2.24) - P3 - scheduled

- Operating system: Microsoft Windows Server 2016
- Findings: 1 Critical
- Seen in telemetry: yes (132 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (49) Microsoft SQL Server Unsupported Version Detection

- Plugin 73756, Critical, CVSS 10.0, port 1433/tcp (mssql)
- Why this score: Base severity: CVSS v3 10.0 (Critical). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 124 completed sessions from 0 external and 4 internal sources.
- Traffic to service: 124 completed, 0 attempts, 0 blocked; first 2026-10-12T00:34:22Z, last 2026-10-18T02:52:20Z; top sources: 10.10.2.32 x39, 10.10.2.34 x32, 10.10.2.36 x30, 10.10.2.30 x23
- Synopsis: The installed version of SQL Server is no longer supported.
- Remediation: Upgrade to a supported version of SQL Server.

**Blast radius**

No completed internal sessions from this host were observed.

### sccm01.corp.example (10.10.2.40) - P3 - scheduled

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Critical
- Seen in telemetry: yes (291 inbound, 95 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041578: Windows Server 2019 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 291 completed sessions from 0 external and 187 internal sources. Blast radius: the host talks to 18 internal host(s) directly and 43 within 2 hops, including 29 with High/Critical findings.
- Traffic to host: 291 completed, 0 attempts, 0 blocked; first 2026-10-12T00:23:24Z, last 2026-10-18T02:50:03Z; top sources: 10.10.3.6 x7, 10.10.2.42 x3, 10.10.3.187 x2, 10.10.3.144 x2, 10.10.3.107 x2, 10.10.7.12 x2, 10.10.3.129 x2, 10.10.3.57 x2
- Synopsis: The remote Windows host is missing security update 5041578.
- Remediation: Apply Security Update 5041578.

**Blast radius**

Completed sessions to 18 internal host(s) directly, 43 within 2 hops.
Lateral-movement protocols used: SMB (34), RPC (17).
Reachable hosts with High/Critical findings: 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.1.11, 10.10.2.24, 10.10.2.25, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.41 | 1 | 9401/tcp | Critical |
| 10.10.3.156 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.192 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.66 | 1 | 135/tcp, 445/tcp | Critical |
| 10.10.3.102 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.111 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.129 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.138 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.174 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.183 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.57 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.84 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.93 | 1 | 135/tcp, 445/tcp | High |
| 10.10.3.120 | 1 | 135/tcp, 445/tcp | Medium |
| 10.10.3.147 | 1 | 135/tcp, 445/tcp | Medium |
| ... 28 more | | | |

Outbound to 36 external address(es); top: 13.107.4.87 x2, 13.107.4.121 x2, 13.107.4.201 x2, 13.107.4.127 x2, 13.107.4.89 x1.

### ws-103.corp.example (10.10.3.103) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (4), SMB (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-104.corp.example (10.10.3.104) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-107.corp.example (10.10.3.107) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-110.corp.example (10.10.3.110) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-112.corp.example (10.10.3.112) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-118.corp.example (10.10.3.118) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-119.corp.example (10.10.3.119) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-137.corp.example (10.10.3.137) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 2 High
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (4), Kerberos (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-141.corp.example (10.10.3.141) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-145.corp.example (10.10.3.145) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 2 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-146.corp.example (10.10.3.146) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (6), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-154.corp.example (10.10.3.154) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), SMB (5), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-159.corp.example (10.10.3.159) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-166.corp.example (10.10.3.166) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 9 internal host(s) directly and 38 within 2 hops, including 29 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 38 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (3), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| ... 23 more | | | |

### ws-172.corp.example (10.10.3.172) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-175.corp.example (10.10.3.175) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-176.corp.example (10.10.3.176) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-180.corp.example (10.10.3.180) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-059.corp.example (10.10.3.59) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-061.corp.example (10.10.3.61) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: LDAP (4), Kerberos (4), SMB (3), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 13 more | | | |

### ws-066.corp.example (10.10.3.66) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 2 High
- Seen in telemetry: yes (3 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T03:43:43Z, last 2026-10-15T08:53:03Z; top sources: 10.10.2.40 x3
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T03:43:43Z, last 2026-10-15T08:53:03Z; top sources: 10.10.2.40 x3
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-14T03:43:43Z, last 2026-10-15T08:53:03Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 18 more | | | |

### ws-088.corp.example (10.10.3.88) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (3), LDAP (3), SSH (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 13 more | | | |

### ws-095.corp.example (10.10.3.95) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-097.corp.example (10.10.3.97) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-013.corp.example (10.10.7.13) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-017.corp.example (10.10.7.17) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-021.corp.example (10.10.7.21) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-027.corp.example (10.10.7.27) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-031.corp.example (10.10.7.31) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-034.corp.example (10.10.7.34) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-039.corp.example (10.10.7.39) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Critical, 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (48) KB5041580: Windows 10 Version 22H2 Security Update (August 2024)

- Plugin 205440, Critical, CVSS 9.8, port host-level, CVE-2024-38063
- Why this score: Base severity: CVSS v3 9.8 (Critical). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The remote Windows host is missing security update 5041580.
- Remediation: Apply Security Update 5041580.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

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

### proxy01.corp.example (10.10.1.40) - P3 - scheduled

- Operating system: Linux Kernel 4.18 on Red Hat Enterprise Linux 8
- Findings: 1 High
- Seen in telemetry: yes (1466 inbound, 660 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) Squid < 6.4 Multiple Vulnerabilities

- Plugin 182251, High, CVSS 7.5, port 3128/tcp (http_proxy), CVE-2023-46846
- Why this score: Base severity: CVSS v3 7.5 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 1461 completed sessions from 0 external and 184 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 1461 completed, 0 attempts, 0 blocked; first 2026-10-12T00:02:12Z, last 2026-10-18T03:05:06Z; top sources: 10.10.3.131 x12, 10.10.3.162 x12, 10.10.3.125 x12, 10.10.3.171 x12, 10.10.3.59 x12, 10.10.3.87 x12, 10.10.3.113 x12, 10.10.3.153 x12
- Synopsis: The proxy is affected by request smuggling and denial of service vulnerabilities.
- Remediation: Upgrade to Squid 6.4 or later.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.0.53 | 1 | 53/udp | - |

Outbound to 597 external address(es); top: 93.184.24.113 x2, 93.184.109.16 x2, 93.184.241.48 x2, 93.184.214.133 x1, 151.101.128.197 x1.

### db03.corp.example (10.10.2.22) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (92 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (43) PostgreSQL 13.x < 13.13 Multiple Vulnerabilities

- Plugin 183965, High, CVSS 8.8, port 5432/tcp (postgresql), CVE-2023-5868, CVE-2023-5869, CVE-2023-5870
- Why this score: Base severity: CVSS v3 8.8 (High). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 85 completed sessions from 0 external and 2 internal sources.
- Traffic to service: 85 completed, 0 attempts, 0 blocked; first 2026-10-12T02:52:00Z, last 2026-10-18T00:23:16Z; top sources: 10.10.2.32 x55, 10.10.2.21 x30
- Synopsis: The database server is affected by multiple vulnerabilities including an integer overflow.
- Remediation: Upgrade to PostgreSQL 13.13 or later.

**Blast radius**

No completed internal sessions from this host were observed.

### app06.corp.example (10.10.2.34) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (71 inbound, 101 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 64 completed sessions from 0 external and 21 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 64 completed, 0 attempts, 0 blocked; first 2026-10-12T00:21:56Z, last 2026-10-18T01:34:01Z; top sources: 10.10.3.182 x4, 10.10.3.90 x4, 10.10.7.17 x4, 10.10.3.98 x4, 10.10.3.173 x4, 10.10.7.30 x4, 10.10.3.80 x4, 10.10.7.14 x4
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (65), MSSQL (32), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### app07.corp.example (10.10.2.35) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (69 inbound, 71 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 48 completed sessions from 0 external and 26 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 48 completed, 0 attempts, 0 blocked; first 2026-10-12T00:08:50Z, last 2026-10-18T00:30:12Z; top sources: 10.10.3.62 x4, 10.10.3.60 x4, 10.10.3.77 x3, 10.10.3.146 x3, 10.10.7.42 x3, 10.10.3.191 x3, 10.10.3.189 x3, 10.10.7.25 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (67), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### app08.corp.example (10.10.2.36) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (73 inbound, 75 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 66 completed sessions from 0 external and 25 internal sources. Blast radius: the host talks to 3 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 66 completed, 0 attempts, 0 blocked; first 2026-10-12T01:37:34Z, last 2026-10-17T19:58:09Z; top sources: 10.10.3.64 x4, 10.10.3.87 x4, 10.10.7.35 x4, 10.10.7.21 x4, 10.10.7.37 x3, 10.10.3.158 x3, 10.10.3.134 x3, 10.10.3.180 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 3 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (41), MSSQL (30), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 1433/tcp | Critical |
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### app09.corp.example (10.10.2.37) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (65 inbound, 58 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (40) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 56 completed sessions from 0 external and 23 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 3 within 2 hops, including 2 with High/Critical findings.
- Traffic to service: 56 completed, 0 attempts, 0 blocked; first 2026-10-12T01:57:19Z, last 2026-10-18T01:37:29Z; top sources: 10.10.3.63 x4, 10.10.3.178 x4, 10.10.3.192 x4, 10.10.7.19 x4, 10.10.7.23 x3, 10.10.3.176 x3, 10.10.3.127 x3, 10.10.3.50 x3
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 3 within 2 hops.
Lateral-movement protocols used: PostgreSQL (54), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.21, 10.10.2.22.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.21 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |
| 10.10.2.22 | 2 |  | High |

### mail01.corp.example (10.10.1.25) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (125 inbound, 90 outbound sessions)
- Internet-exposed vulnerable service: yes

**Findings and exposure evidence**

#### P3 (39) Postfix SMTP Smuggling

- Plugin 187315, Medium, CVSS 5.3, port 25/tcp (smtp), CVE-2023-51764
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached from the internet - 90 completed sessions from 72 external and 0 internal sources. Blast radius: the host talks to 1 internal host(s) directly and 1 within 2 hops.
- Traffic to service: 90 completed, 0 attempts, 0 blocked; first 2026-10-12T01:00:38Z, last 2026-10-18T02:06:53Z; top sources: 209.85.220.81 (ext) x4, 209.85.220.119 (ext) x4, 209.85.220.131 (ext) x2, 209.85.220.173 (ext) x2, 209.85.220.201 (ext) x2, 209.85.220.235 (ext) x2, 209.85.220.135 (ext) x2, 209.85.220.33 (ext) x2
- Synopsis: The mail server is affected by an SMTP smuggling vulnerability.
- Remediation: Upgrade Postfix and set smtpd_forbid_bare_newline.

**Blast radius**

Completed sessions to 1 internal host(s) directly, 1 within 2 hops.
Lateral-movement protocols used: LDAP (20).

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.0.10 | 1 | 389/tcp | - |

Outbound to 60 external address(es); top: 40.107.22.67 x2, 40.107.22.85 x2, 40.107.22.128 x2, 40.107.22.129 x2, 40.107.22.37 x2.

### ws-165.corp.example (10.10.3.165) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (3 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 17 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-12T18:50:35Z, last 2026-10-16T04:09:12Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 9 more | | | |

### ws-048.corp.example (10.10.3.48) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 Medium
- Seen in telemetry: yes (3 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (39) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally - 2 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 27 with High/Critical findings.
- Traffic to service: 2 completed, 0 attempts, 0 blocked; first 2026-10-13T14:56:13Z, last 2026-10-14T17:25:44Z; top sources: 10.10.2.40 x2
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 27 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T14:56:13Z, last 2026-10-15T22:20:56Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

Outbound to 3 external address(es); top: 103.160.59.97 x2, 103.245.231.248 x1, 2.57.241.246 x1.

### ws-113.corp.example (10.10.3.113) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 38 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (5).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-115.corp.example (10.10.3.115) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 20 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-123.corp.example (10.10.3.123) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-140.corp.example (10.10.3.140) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-149.corp.example (10.10.3.149) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-155.corp.example (10.10.3.155) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 2 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-167.corp.example (10.10.3.167) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-193.corp.example (10.10.3.193) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-050.corp.example (10.10.3.50) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-054.corp.example (10.10.3.54) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-063.corp.example (10.10.3.63) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), LDAP (5), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-071.corp.example (10.10.3.71) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-076.corp.example (10.10.3.76) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-077.corp.example (10.10.3.77) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 43 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 9 internal host(s) directly and 36 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 9 internal host(s) directly, 36 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (3), SSH (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 21 more | | | |

### ws-081.corp.example (10.10.3.81) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-083.corp.example (10.10.3.83) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (3), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

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

### lt-016.corp.example (10.10.7.16) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-032.corp.example (10.10.7.32) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 High
- Seen in telemetry: yes (0 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (12), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-038.corp.example (10.10.7.38) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-040.corp.example (10.10.7.40) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (4), LDAP (4), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-044.corp.example (10.10.7.44) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 29 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (38) Adobe Acrobat Reader < 24.002.20687 Multiple Vulnerabilities (APSB24-29)

- Plugin 192951, High, CVSS 7.8, port host-level, CVE-2024-30284
- Why this score: Base severity: CVSS v3 7.8 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The PDF reader on the remote host is affected by multiple vulnerabilities.
- Remediation: Upgrade to Adobe Acrobat Reader 24.002.20687 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (5), Kerberos (4).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### app05.corp.example (10.10.2.33) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 Medium
- Seen in telemetry: yes (128 inbound, 64 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (37) Apache Tomcat 9.0.x < 9.0.71 Information Disclosure

- Plugin 171340, Medium, CVSS 5.3, port 8080/tcp (www), CVE-2023-28708
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 117 completed sessions from 0 external and 16 internal sources. Blast radius: the host talks to 2 internal host(s) directly and 2 within 2 hops, including 1 with High/Critical findings.
- Traffic to service: 117 completed, 0 attempts, 0 blocked; first 2026-10-12T00:20:45Z, last 2026-10-18T01:17:14Z; top sources: 10.10.1.14 x85, 10.10.3.172 x4, 10.10.3.142 x4, 10.10.7.32 x3, 10.10.3.181 x3, 10.10.3.51 x3, 10.10.3.54 x3, 10.10.3.53 x2
- Synopsis: The Tomcat server is affected by an information disclosure vulnerability.
- Remediation: Upgrade to Apache Tomcat 9.0.71 or later.

**Blast radius**

Completed sessions to 2 internal host(s) directly, 2 within 2 hops.
Lateral-movement protocols used: PostgreSQL (60), LDAP (4).
Reachable hosts with High/Critical findings: 10.10.2.23.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.23 | 1 | 5432/tcp | High |
| 10.10.0.10 | 1 | 389/tcp | - |

### mon01.corp.example (10.10.2.42) - P3 - scheduled

- Operating system: Linux Kernel 5.15 on Ubuntu 22.04
- Findings: 1 High
- Seen in telemetry: yes (6 inbound, 228 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) SNMP Agent Default Community Name (public)

- Plugin 41028, High, CVSS 7.5, port 161/udp (snmp), CVE-1999-0517
- Why this score: Base severity: CVSS v3 7.5 (High). A public exploit is available. Exposure: service not observed in use. Blast radius: the host talks to 43 internal host(s) directly and 62 within 2 hops, including 48 with High/Critical findings.
- Synopsis: The community name of the remote SNMP server can be guessed.
- Remediation: Disable SNMP or change the default community string.

**Blast radius**

Completed sessions to 43 internal host(s) directly, 62 within 2 hops.
Reachable hosts with High/Critical findings: 10.10.1.11, 10.10.1.30, 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.41, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.4.60, 10.10.4.61, 10.10.4.62, 10.10.4.63, 10.10.4.64, 10.10.4.65, 10.10.4.66, 10.10.4.67, 10.10.4.68, 10.10.4.69, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.1.11 | 1 | 161/udp | Critical |
| 10.10.1.30 | 1 | 161/udp | Critical |
| 10.10.2.24 | 1 | 161/udp | Critical |
| 10.10.2.30 | 1 | 161/udp | Critical |
| 10.10.2.31 | 1 | 161/udp | Critical |
| 10.10.2.32 | 1 | 161/udp | Critical |
| 10.10.2.40 | 1 | 161/udp | Critical |
| 10.10.2.41 | 1 | 161/udp | Critical |
| 10.10.2.43 | 1 | 161/udp | Critical |
| 10.10.2.44 | 1 | 161/udp | Critical |
| 10.10.2.45 | 1 | 161/udp | Critical |
| 10.10.4.60 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.61 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.62 | 1 | 554/tcp, 80/tcp | Critical |
| 10.10.4.63 | 1 | 554/tcp, 80/tcp | Critical |
| ... 47 more | | | |

Outbound to 4 external address(es); top: 104.194.158.65 x2, 104.248.131.53 x1, 109.224.53.140 x1, 138.68.244.146 x1.

### ws-114.corp.example (10.10.3.114) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-129.corp.example (10.10.3.129) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (3 inbound, 43 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 8 internal host(s) directly and 28 within 2 hops, including 19 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T05:20:23Z, last 2026-10-17T17:03:29Z; top sources: 10.10.2.40 x3
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 28 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (4), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 13 more | | | |

### ws-130.corp.example (10.10.3.130) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.35 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-162.corp.example (10.10.3.162) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 19 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-168.corp.example (10.10.3.168) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (7), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-184.corp.example (10.10.3.184) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 28 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-188.corp.example (10.10.3.188) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-194.corp.example (10.10.3.194) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (3), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-049.corp.example (10.10.3.49) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: Kerberos (4), LDAP (3), SMB (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

Outbound to 1 external address(es); top: 103.27.110.220 x1.

### ws-089.corp.example (10.10.3.89) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (4), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-092.corp.example (10.10.3.92) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 32 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-094.corp.example (10.10.3.94) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (6), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-022.corp.example (10.10.7.22) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### lt-024.corp.example (10.10.7.24) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-030.corp.example (10.10.7.30) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (2), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-037.corp.example (10.10.7.37) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 2 Medium
- Seen in telemetry: yes (0 inbound, 33 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (3), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.36 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### lt-043.corp.example (10.10.7.43) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 High, 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (34) 7-Zip < 24.07 Code Execution

- Plugin 189385, High, CVSS 7.0, port host-level, CVE-2024-11477
- Why this score: Base severity: CVSS v3 7.0 (High). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The archiver on the remote host is affected by a code execution vulnerability.
- Remediation: Upgrade to 7-Zip 24.07 or later.

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: Kerberos (5), LDAP (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-120.corp.example (10.10.3.120) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (3 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T12:07:37Z, last 2026-10-16T02:33:48Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

### ws-126.corp.example (10.10.3.126) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (4), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.32, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.22, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.32 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.22 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-142.corp.example (10.10.3.142) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### ws-144.corp.example (10.10.3.144) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 31 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (8), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-147.corp.example (10.10.3.147) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (3 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 7 internal host(s) directly and 33 within 2 hops, including 26 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-12T13:05:49Z, last 2026-10-15T16:52:36Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 33 within 2 hops.
Lateral-movement protocols used: SMB (7), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 18 more | | | |

### ws-148.corp.example (10.10.3.148) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 25 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (10), LDAP (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-157.corp.example (10.10.3.157) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 24 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 18 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### ws-171.corp.example (10.10.3.171) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 36 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (8), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-178.corp.example (10.10.3.178) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 35 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (9), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-181.corp.example (10.10.3.181) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 27 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (4), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

### ws-067.corp.example (10.10.3.67) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 27 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), LDAP (5), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### ws-073.corp.example (10.10.3.73) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 41 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 8 internal host(s) directly and 29 within 2 hops, including 20 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 8 internal host(s) directly, 29 within 2 hops.
Lateral-movement protocols used: SMB (10), Kerberos (2), LDAP (2), SSH (1).
Reachable hosts with High/Critical findings: 10.10.2.30, 10.10.2.40, 10.10.2.44, 10.10.2.45, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.30 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp, 443/tcp | Critical |
| 10.10.2.45 | 1 | 8080/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| ... 14 more | | | |

### ws-075.corp.example (10.10.3.75) - P3 - scheduled

- Operating system: Microsoft Windows 10 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (3 inbound, 34 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network - 3 completed sessions from 0 external and 1 internal sources. Blast radius: the host talks to 6 internal host(s) directly and 24 within 2 hops, including 18 with High/Critical findings.
- Traffic to host: 3 completed, 0 attempts, 0 blocked; first 2026-10-13T18:25:18Z, last 2026-10-17T23:14:53Z; top sources: 10.10.2.40 x3
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 24 within 2 hops.
Lateral-movement protocols used: SMB (9), LDAP (4), Kerberos (3).
Reachable hosts with High/Critical findings: 10.10.2.25, 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.25 | 1 | 445/tcp | Critical |
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 9 more | | | |

### lt-014.corp.example (10.10.7.14) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 Medium
- Seen in telemetry: yes (0 inbound, 37 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 35 within 2 hops, including 26 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 35 within 2 hops.
Lateral-movement protocols used: SMB (11), Kerberos (3), LDAP (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| ... 20 more | | | |

### lt-036.corp.example (10.10.7.36) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 2 Medium
- Seen in telemetry: yes (0 inbound, 28 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: LDAP (4), Kerberos (4), SMB (4).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.24, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.34 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.24 | 2 |  | Critical |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

### eng-lt01.corp.example (10.10.7.46) - P3 - scheduled

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 30 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (32) Zoom Client < 6.0.2 Privilege Escalation

- Plugin 201084, Medium, CVSS 6.5, port host-level, CVE-2024-27240
- Why this score: Base severity: CVSS v3 6.5 (Medium). No public exploit is known to the scanner. Exposure: host is active on the network. Blast radius: the host talks to 7 internal host(s) directly and 26 within 2 hops, including 17 with High/Critical findings.
- Synopsis: The Zoom client on the remote host is affected by a privilege escalation vulnerability.
- Remediation: Upgrade to Zoom Client 6.0.2 or later.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 26 within 2 hops.
Lateral-movement protocols used: Kerberos (4), SMB (3), LDAP (2), RDP (2).
Reachable hosts with High/Critical findings: 10.10.2.31, 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.31 | 1 | 8080/tcp | Critical |
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.6.11 | 1 | 3389/tcp | Info |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 11 more | | | |

Outbound to 1 external address(es); top: 198.51.100.77 x2.

### fs02.corp.example (10.10.2.26) - P3 - scheduled

- Operating system: Microsoft Windows Server 2019
- Findings: 1 Medium
- Seen in telemetry: yes (835 inbound, 0 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P3 (29) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: vulnerable service reached internally by many hosts - 825 completed sessions from 0 external and 132 internal sources.
- Traffic to service: 825 completed, 0 attempts, 0 blocked; first 2026-10-12T00:01:19Z, last 2026-10-18T03:00:57Z; top sources: 10.10.7.30 x10, 10.10.3.155 x10, 10.10.3.150 x10, 10.10.3.67 x10, 10.10.3.82 x10, 10.10.7.26 x10, 10.10.3.151 x10, 10.10.3.73 x10
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

No completed internal sessions from this host were observed.

### lt-012.corp.example (10.10.7.12) - P4 - routine

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 22 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 6 internal host(s) directly and 25 within 2 hops, including 16 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 6 internal host(s) directly, 25 within 2 hops.
Lateral-movement protocols used: LDAP (5), SMB (3), Kerberos (2).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.23, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.33 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.23 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| 10.10.3.138 | 2 |  | High |
| ... 10 more | | | |

### lt-019.corp.example (10.10.7.19) - P4 - routine

- Operating system: Microsoft Windows 11 Enterprise
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 26 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (16) SMB Signing not required

- Plugin 57608, Medium, CVSS 5.3, port 445/tcp (cifs)
- Why this score: Base severity: CVSS v3 5.3 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 7 internal host(s) directly and 34 within 2 hops, including 25 with High/Critical findings.
- Synopsis: Signing is not required on the remote SMB server.
- Remediation: Enforce message signing in the host's configuration.

**Blast radius**

Completed sessions to 7 internal host(s) directly, 34 within 2 hops.
Lateral-movement protocols used: SMB (5), Kerberos (5), LDAP (3).
Reachable hosts with High/Critical findings: 10.10.2.40, 10.10.2.43, 10.10.1.40, 10.10.2.41, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.2.21, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.40 | 1 | 8530/tcp | Critical |
| 10.10.2.43 | 1 | 445/tcp | Critical |
| 10.10.1.40 | 1 | 3128/tcp | High |
| 10.10.2.26 | 1 | 445/tcp | Medium |
| 10.10.2.37 | 1 | 8080/tcp | Medium |
| 10.10.0.10 | 1 | 389/tcp, 88/tcp | - |
| 10.10.0.53 | 1 | 53/udp | - |
| 10.10.2.41 | 2 |  | Critical |
| 10.10.3.156 | 2 |  | Critical |
| 10.10.3.192 | 2 |  | Critical |
| 10.10.3.66 | 2 |  | Critical |
| 10.10.2.21 | 2 |  | High |
| 10.10.3.102 | 2 |  | High |
| 10.10.3.111 | 2 |  | High |
| 10.10.3.129 | 2 |  | High |
| ... 19 more | | | |

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

### jump02.corp.example (10.10.3.6) - P4 - routine

- Operating system: Microsoft Windows Server 2022
- Findings: 1 Medium
- Seen in telemetry: yes (0 inbound, 89 outbound sessions)
- Internet-exposed vulnerable service: no

**Findings and exposure evidence**

#### P4 (12) Terminal Services Doesn't Use Network Level Authentication (NLA) Only

- Plugin 58453, Medium, CVSS 4.0, port 3389/tcp (msrdp)
- Why this score: Base severity: CVSS v3 4.0 (Medium). No public exploit is known to the scanner. Exposure: service not observed in use. Blast radius: the host talks to 19 internal host(s) directly and 62 within 2 hops, including 49 with High/Critical findings.
- Synopsis: The remote Terminal Services doesn't use NLA only.
- Remediation: Enable Network Level Authentication.

**Blast radius**

Completed sessions to 19 internal host(s) directly, 62 within 2 hops.
Lateral-movement protocols used: SSH (60), RDP (29).
Reachable hosts with High/Critical findings: 10.10.2.24, 10.10.2.30, 10.10.2.31, 10.10.2.32, 10.10.2.40, 10.10.2.41, 10.10.2.43, 10.10.2.44, 10.10.2.45, 10.10.2.21, 10.10.2.22, 10.10.2.23, 10.10.2.42, 10.10.1.11, 10.10.1.30, 10.10.3.156, 10.10.3.192, 10.10.3.66, 10.10.4.60, 10.10.4.61, 10.10.4.62, 10.10.4.63, 10.10.4.64, 10.10.4.65, 10.10.4.66, 10.10.4.67, 10.10.4.68, 10.10.4.69, 10.10.1.12, 10.10.1.13, 10.10.1.14, 10.10.1.40, 10.10.3.102, 10.10.3.111, 10.10.3.129, 10.10.3.138, 10.10.3.174, 10.10.3.183, 10.10.3.57, 10.10.3.84, 10.10.3.93, 10.10.4.51, 10.10.4.52, 10.10.4.53, 10.10.4.54, 10.10.4.55, 10.10.4.56, 10.10.4.57, 10.10.4.58.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.2.24 | 1 | 3389/tcp | Critical |
| 10.10.2.30 | 1 | 22/tcp | Critical |
| 10.10.2.31 | 1 | 22/tcp | Critical |
| 10.10.2.32 | 1 | 22/tcp | Critical |
| 10.10.2.40 | 1 | 3389/tcp | Critical |
| 10.10.2.41 | 1 | 3389/tcp | Critical |
| 10.10.2.43 | 1 | 3389/tcp | Critical |
| 10.10.2.44 | 1 | 22/tcp | Critical |
| 10.10.2.45 | 1 | 22/tcp | Critical |
| 10.10.2.21 | 1 | 22/tcp | High |
| 10.10.2.22 | 1 | 22/tcp | High |
| 10.10.2.23 | 1 | 22/tcp | High |
| 10.10.2.42 | 1 | 22/tcp | High |
| 10.10.2.26 | 1 | 3389/tcp | Medium |
| 10.10.2.33 | 1 | 22/tcp | Medium |
| ... 47 more | | | |

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
Lateral-movement protocols used: RDP (30), SSH (30).
Reachable hosts with High/Critical findings: 10.10.3.31, 10.10.2.20.

| Reachable host | Hops | Ports used | Worst finding |
|---|---|---|---|
| 10.10.3.31 | 1 | 3389/tcp | Critical |
| 10.10.2.20 | 1 | 22/tcp | High |
| 10.10.6.71 | 2 |  | - |

## 5. Coverage gaps

249 of 250 scanned hosts appear in telemetry; 252 internal hosts sent or answered traffic.

**Scanned but not seen in telemetry** (exposure unknown; check sensor placement): 10.10.5.60

**Active internal servers not in the scan** (add to scan scope):

| Host | Services observed | Sessions |
|---|---|---|
| 10.10.0.10 | 389/tcp, 88/tcp | 1468 |
| 10.10.0.53 | 53/udp | 886 |
| 10.10.6.70 | 445/tcp, 3389/tcp | 81 |
| 10.10.6.71 | 8443/tcp | 31 |

## 6. Output files

- `executive_summary.md/.html`: leadership summary
- `technical_report.md/.html`: this report
- `correlated_findings.csv`: one row per finding with scores, for ticketing or spreadsheets
- `results.json`: full machine-readable result
- `hostile_activity.svg`: the hostile activity diagram as a standalone image
- `explorer.html`: interactive host explorer (who targets each host, and its internal blast radius)
- `normalized/flows.csv`, `normalized/findings.csv`: cleaned inputs in the common schema
- `normalized/threats.csv`: IPS/IDS alerts (signature, action and addresses)
- `normalized/zeek_events.jsonl`: other Zeek streams with stream identity and source fields
- `normalized/ot_events.jsonl`: industrial protocol records with operation and message direction

## IOC matches

Exact matches to the imported IOC CSV are leads for review, not proof of malicious activity.

| Indicator | Type | Related hosts | Observed in | Source links |
|---|---|---|---|---|
| 247.cdnflare.xyz | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| adsaw.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| adswre.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| beraskencur.site | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| bunstar.harej.si | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| byveo.org | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| checkout-cdn.com | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| groy.cc | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| magento.ink | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| microsoft-flash.com | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| my-662ylt3w.pages.dev | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| ntp.timesync.to | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| secure-dns-hub.com | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| solidmonpe.com | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| trews.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| wps-cn.com | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| 103.160.59.97 | ip | 10.10.3.48 | 2 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 103.245.231.248 | ip | 10.10.3.48 | 1 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 103.27.110.220 | ip | 10.10.3.49 | 1 network session | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| 104.194.158.65 | ip | 10.10.2.42 | 2 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 104.248.131.53 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 109.224.53.140 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 138.68.244.146 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 185.157.160.251 | ip | 10.10.1.11 | 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 2.57.241.246 | ip | 10.10.3.48 | 1 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 209.141.43.95 | ip | 10.10.1.11 | 1 network session | https://sansec.io/research/stylesmuggler-0day |
| 209.73.130.148 | ip | 10.10.1.11 | 1 IDS/IPS alert, 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 99.84.67.186 | ip | 10.10.1.11 | 3 network session | https://sansec.io/research/stylesmuggler-0day |
