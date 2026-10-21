# Executive Summary: Vulnerability Exposure Assessment

Prepared 2026-10-21. Network activity analysed from 2026-10-12T00:01:19Z to 2026-10-18T03:11:38Z.

## Bottom line

**Likely exploitation on web01.corp.example (10.10.1.10).** An IPS/IDS alert on a vulnerable service and the host's own traffic afterwards point the same way. Start incident response; host forensics is needed to confirm a compromise.

A flagged system later made new connections to vulnerable services on 2 other systems (fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31)). If the first system is compromised, these are the likely next targets.

20 vulnerabilities on 20 systems need action now (Priority 1).

6 vulnerable services on 6 systems are being reached from the internet; 1 of them have a publicly available exploit.

Of 447 vulnerabilities reported by the scanner, 48 sit on services with no observed traffic and can be scheduled rather than rushed.

4 active servers seen on the network were not in the scan, so their risk is unknown.

## Key numbers

| Measure | Value |
|---|---|
| Systems scanned | 250 |
| Systems with vulnerabilities (Low and above) | 250 |
| Network sessions analysed | 9,764 |
| Priority 1 / 2 / 3 / 4 findings | 20 / 130 / 249 / 48 |
| Vulnerable services reached from the internet | 6 |
| Exploitable vulnerabilities with observed traffic | 28 |
| Systems with corroborated evidence / to investigate / possible next targets | 1 / 0 / 2 |
| Active servers missing from the scan | 4 |

## Top risks

1. **web01.corp.example (10.10.1.10)**: Apache 2.4.49 < 2.4.51 Path Traversal and RCE (CVE-2021-41773, CVE-2021-42013). Vulnerable service reached from the internet; public exploit exists; compromise could spread to 6 connected systems; **IPS alert and host traffic both point to exploitation**. Risk score 100/100, P1 - act now.
2. **app01.corp.example (10.10.1.20)**: Apache Tomcat AJP Connector Request Injection (Ghostcat) (CVE-2020-1938). Vulnerable service reached internally; public exploit exists; compromise could spread to 2 connected systems. Risk score 100/100, P1 - act now.
3. **app02.corp.example (10.10.2.30)**: Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (CVE-2021-44228). Vulnerable service reached internally by many hosts; public exploit exists; compromise could spread to 4 connected systems. Risk score 100/100, P1 - act now.
4. **app03.corp.example (10.10.2.31)**: Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (CVE-2021-44228). Vulnerable service reached internally by many hosts; public exploit exists; compromise could spread to 2 connected systems. Risk score 100/100, P1 - act now.
5. **app04.corp.example (10.10.2.32)**: Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (CVE-2021-44228). Vulnerable service reached internally by many hosts; public exploit exists; compromise could spread to 3 connected systems. Risk score 100/100, P1 - act now.

## Recommended actions

1. **Start incident response for web01.corp.example (10.10.1.10).** Preserve logs and memory, confirm on the host, contain, then patch. Patching alone will not remove an attacker. Include fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31) in the scope.
2. **Patch or shield internet-facing exploitable services within 48 hours**: web01.corp.example (10.10.1.10). If a patch cannot go in, restrict access at the firewall.
3. **Limit how far a breach can spread.** 120 high-priority systems can reach other vulnerable systems directly; restrict admin protocols (SMB, RDP, SSH) between these segments.
4. **Fix 145 internally reachable high-priority vulnerabilities** in the current patch cycle; they are the next step for an attacker already inside.
5. **Close the scan gap.** Add the 4 unscanned active servers to the scan scope so their exposure can be assessed.
6. **Schedule the remaining findings** through normal patching, and switch off services that no one is using.

## How confident is this?

The assessment combines the vulnerability scan with 9,764 observed network sessions. 249 of 250 scanned systems appeared in the network data. A system with no observed traffic is scored as "unknown" rather than safe. Telemetry only shows what the sensors could see, so absence of traffic is not proof that a service is unreachable.

Full evidence for every finding is in the technical report.
