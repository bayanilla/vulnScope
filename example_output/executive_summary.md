# Executive Summary: Vulnerability Exposure Assessment

Prepared 2026-10-21. Network activity analysed from 2026-10-12T00:02:03Z to 2026-10-18T03:11:38Z.

## Bottom line

**Likely exploitation on web01.corp.example (10.10.1.10).** An IPS/IDS alert on a vulnerable service and the host's own traffic afterwards point the same way. Start incident response; host forensics is needed to confirm a compromise.

A flagged system later made new connections to vulnerable services on 2 other systems (fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31)). If the first system is compromised, these are the likely next targets.

4 vulnerabilities on 4 systems need action now (Priority 1).

1 vulnerable service on 1 system is being reached from the internet; it has a publicly available exploit.

Of 17 vulnerabilities reported by the scanner, 2 sit on services with no observed traffic and can be scheduled rather than rushed.

4 active servers seen on the network were not in the scan, so their risk is unknown.

## Key numbers

| Measure | Value |
|---|---|
| Systems scanned | 16 |
| Systems with vulnerabilities (Low and above) | 16 |
| Network sessions analysed | 1,352 |
| Priority 1 / 2 / 3 / 4 findings | 4 / 8 / 2 / 3 |
| Vulnerable services reached from the internet | 1 |
| Exploitable vulnerabilities with observed traffic | 4 |
| Systems with corroborated evidence / to investigate / possible next targets | 1 / 0 / 2 |
| Active servers missing from the scan | 4 |

## Top risks

1. **web01.corp.example (10.10.1.10)**: Apache 2.4.49 < 2.4.51 Path Traversal and RCE (CVE-2021-41773, CVE-2021-42013). Vulnerable service reached from the internet; public exploit exists; compromise could spread to 6 connected systems; **IPS alert and host traffic both point to exploitation**. Risk score 100/100, P1 - act now.
2. **app01.corp.example (10.10.1.20)**: Apache Tomcat AJP Connector Request Injection (Ghostcat) (CVE-2020-1938). Vulnerable service reached internally; public exploit exists; compromise could spread to 2 connected systems. Risk score 100/100, P1 - act now.
3. **ws-031.corp.example (10.10.3.31)**: Microsoft RDP RCE (CVE-2019-0708) (BlueKeep). Vulnerable service reached internally; public exploit exists; **traffic pattern worth investigating (not confirmed)**. Risk score 89/100, P1 - act now.
4. **fs01.corp.example (10.10.2.25)**: MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE) (CVE-2017-0143, CVE-2017-0144). Vulnerable service reached internally by many hosts; public exploit exists; **traffic pattern worth investigating (not confirmed)**. Risk score 83/100, P1 - act now.
5. **ws-040.corp.example (10.10.3.40)**: Microsoft Edge (Chromium) < 129.0.2792.52 Multiple Vulnerabilities (CVE-2024-7965, CVE-2024-7971). Host is active on the network; public exploit exists; compromise could spread to 5 connected systems. Risk score 61/100, P2 - this cycle.

## Recommended actions

1. **Start incident response for web01.corp.example (10.10.1.10).** Preserve logs and memory, confirm on the host, contain, then patch. Patching alone will not remove an attacker. Include fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31) in the scope.
2. **Patch or shield internet-facing exploitable services within 48 hours**: web01.corp.example (10.10.1.10). If a patch cannot go in, restrict access at the firewall.
3. **Limit how far a breach can spread.** 10 high-priority systems can reach other vulnerable systems directly; restrict admin protocols (SMB, RDP, SSH) between these segments.
4. **Fix 11 internally reachable high-priority vulnerabilities** in the current patch cycle; they are the next step for an attacker already inside.
5. **Close the scan gap.** Add the 4 unscanned active servers to the scan scope so their exposure can be assessed.
6. **Schedule the remaining findings** through normal patching, and switch off services that no one is using.

## How confident is this?

The assessment combines the vulnerability scan with 1,352 observed network sessions. 15 of 16 scanned systems appeared in the network data. A system with no observed traffic is scored as "unknown" rather than safe. Telemetry only shows what the sensors could see, so absence of traffic is not proof that a service is unreachable.

Full evidence for every finding is in the technical report.
