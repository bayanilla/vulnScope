-- VulnScope's correlation model: every multi-line query the correlator runs, by name.
--
-- Tables these read: flows (deduplicated sessions), ipnet (address -> internal?), scanners,
-- wanted, alerts, xkeys (one row per finding service and scan window), anchors, suspects, bhosts.
-- $word is a fixed fragment filled in by vulnflow/correlate.py (see MODEL there); values that
-- come from analysed files reach these queries only as rows of those tables.

-- name: flows_in_scope
-- Every session not started by the vulnerability scanner, with each end marked inside or outside
-- and whether the session completed (est).
CREATE OR REPLACE TABLE fx AS
SELECT f.*, s.internal AS src_int, d.internal AS dst_int,
       (NOT s.internal OR f.src_zone IN ($zones)) AS ext_src,
       (f.action = 'allow' AND f.established) AS est
FROM flows f JOIN ipnet s ON s.ip = f.src_ip JOIN ipnet d ON d.ip = f.dst_ip
WHERE f.src_ip NOT IN (SELECT ip FROM scanners);

-- name: session_counts_per_host
-- Sessions in and out for each internal or scanned host.
SELECT ip, sum(i), sum(o) FROM (
    SELECT dst_ip AS ip, 1 AS i, 0 AS o FROM flows
    UNION ALL SELECT src_ip, 0, 1 FROM flows) JOIN wanted USING (ip)
GROUP BY ip;

-- name: internal_adjacency
-- Which internal host completed sessions to which, and on what services (the blast-radius graph).
SELECT src_ip, dst_ip, list(DISTINCT coalesce(CAST(dst_port AS VARCHAR), 'None') || '/' || proto)
FROM fx WHERE est AND src_int AND dst_int AND src_ip <> dst_ip
GROUP BY src_ip, dst_ip;

-- name: alerts_per_finding
-- Alerts on each finding's service: same host, the finding's port (or an alert without a port, or a
-- host-level finding), inside one of the finding's scan windows.
SELECT DISTINCT k.kid, a.aid FROM xkeys k JOIN alerts a
  ON a.dst_ip = k.host AND (k.host_level OR a.dst_port IS NULL OR a.dst_port = k.port)
WHERE k.lo IS NULL OR a.ts IS NULL OR a.ts BETWEEN k.lo AND k.hi
ORDER BY k.kid, a.aid;

-- name: exposure_per_finding
-- Inbound sessions to each finding's service: totals, outcomes, distinct sources, first and last seen.
SELECT k.kid, count(*), count(*) FILTER (f.est), count(*) FILTER (f.action = 'deny'),
       count(*) FILTER (f.action = 'reject'),
       count(DISTINCT f.src_ip) FILTER (f.est AND f.ext_src),
       count(DISTINCT f.src_ip) FILTER (f.est AND NOT f.ext_src),
       min(f.ts), max(f.ts), coalesce(sum(f.bytes_out + f.bytes_in) FILTER (f.est), 0)
FROM xkeys k JOIN fx f ON $key_match GROUP BY k.kid;

-- name: top_sources_per_finding
-- The eight busiest sources of completed sessions to each finding's service.
SELECT kid, src_ip, n, ext FROM (
    SELECT k.kid, f.src_ip, count(*) AS n, bool_or(f.ext_src) AS ext,
           row_number() OVER (PARTITION BY k.kid ORDER BY count(*) DESC, min(f.seq)) AS rn
    FROM xkeys k JOIN fx f ON $key_match WHERE f.est GROUP BY k.kid, f.src_ip)
WHERE rn <= 8 ORDER BY kid, rn;

-- name: first_contact
-- First contact by each outside address that completed a session to the service.
CREATE OR REPLACE TABLE contact AS
SELECT k.kid, f.src_ip AS peer, min(f.ts) AS t0, min(f.seq) AS first
FROM xkeys k JOIN fx f ON $key_match WHERE f.est AND f.ext_src GROUP BY k.kid, f.src_ip;

-- name: return_connections
-- The vulnerable host later connects back out to an address that reached it.
SELECT c.kid, c.peer, count(*), list(DISTINCT coalesce(f.dst_port, -1))
FROM contact c JOIN xkeys k USING (kid)
JOIN fx f ON f.src_ip = k.host AND f.dst_ip = c.peer
WHERE f.est AND (c.t0 IS NULL OR f.ts IS NULL OR f.ts >= c.t0) AND $win
GROUP BY c.kid, c.peer;

-- name: activity_before_anchor
-- Findings whose host was already making allowed sessions before the suspicious moment.
SELECT DISTINCT a.kid FROM anchors a JOIN xkeys k USING (kid)
JOIN fx f ON f.src_ip = k.host
WHERE f.action = 'allow' AND f.ts < a.t0 AND $win;

-- name: new_lateral_sessions
-- After the suspicious moment the host completes sessions to internal admin services it had not
-- used before. Written as joins, not a correlated NOT EXISTS: DuckDB 1.5 fails to bind that form
-- when timed and untimed findings are mixed.
WITH cand AS (
    SELECT a.kid, k.host, a.t0, k.wi, k.lo, k.hi, f.dst_ip, f.dst_port
    FROM anchors a JOIN xkeys k USING (kid) JOIN fx f ON f.src_ip = k.host
    WHERE f.est AND f.ts >= a.t0 AND f.dst_int AND f.dst_port IN ($lateral_ports) AND $win),
prior AS (
    SELECT DISTINCT c.kid, c.dst_ip
    FROM (SELECT DISTINCT kid, host, t0, wi, lo, hi, dst_ip FROM cand) c
    JOIN fx g ON g.src_ip = c.host AND g.dst_ip = c.dst_ip
    WHERE g.action = 'allow' AND g.ts < c.t0 AND $win_prior)
SELECT kid, dst_ip, list(DISTINCT dst_port) FROM cand ANTI JOIN prior USING (kid, dst_ip)
GROUP BY kid, dst_ip;

-- name: large_outbound_transfers
-- After the suspicious moment the host sends a large amount of data to an outside address.
SELECT a.kid, f.dst_ip, sum(f.bytes_out) AS n
FROM anchors a JOIN xkeys k USING (kid) JOIN fx f ON f.src_ip = k.host
WHERE f.est AND f.ts >= a.t0 AND NOT f.dst_int AND $win
GROUP BY a.kid, f.dst_ip HAVING sum(f.bytes_out) >= $exfil_bytes
ORDER BY a.kid, min(f.seq);

-- name: lateral_spread
-- The first completed session from a flagged host to each finding's service, unless that host
-- already talked to it before it was flagged.
WITH prior AS (       -- the suspect's normal pre-incident traffic to this host
    SELECT DISTINCT k.kid, s.ip FROM xkeys k JOIN suspects s ON s.t IS NOT NULL
    JOIN fx g ON g.src_ip = s.ip AND g.dst_ip = k.host
    WHERE g.ts < s.t AND $win_g)
SELECT kid, src_ip, dst_port, proto, ts FROM (
    SELECT k.kid, f.src_ip, f.dst_port, f.proto, f.ts,
           row_number() OVER (PARTITION BY k.kid ORDER BY f.seq) AS rn
    FROM xkeys k JOIN fx f ON $key_match JOIN suspects s ON s.ip = f.src_ip
    ANTI JOIN prior p ON p.kid = k.kid AND p.ip = f.src_ip
    WHERE f.est AND f.src_ip <> k.host
      AND NOT (s.t IS NOT NULL AND f.ts IS NOT NULL AND f.ts < s.t))
WHERE rn = 1;

-- name: lateral_protocols_per_host
-- Admin services each host completes sessions to inside the network.
SELECT f.src_ip, f.dst_port, count(*), min(f.seq) FROM fx f JOIN bhosts b ON b.ip = f.src_ip
WHERE f.est AND f.dst_int AND f.dst_port IN ($lateral_ports)
GROUP BY f.src_ip, f.dst_port;

-- name: external_destinations_per_host
SELECT src_ip, total, dst_ip, n FROM (
    SELECT f.src_ip, f.dst_ip, count(*) AS n,
           count(*) OVER (PARTITION BY f.src_ip) AS total,
           row_number() OVER (PARTITION BY f.src_ip ORDER BY count(*) DESC, min(f.seq)) AS rn
    FROM fx f JOIN bhosts b ON b.ip = f.src_ip
    WHERE f.est AND NOT f.dst_int GROUP BY f.src_ip, f.dst_ip)
WHERE rn <= 5 ORDER BY src_ip, rn;

-- name: unscanned_servers
SELECT dst_ip, CAST(dst_port AS VARCHAR) || '/' || proto, count(*) FROM fx
WHERE est AND dst_int AND dst_port IS NOT NULL
GROUP BY dst_ip, dst_port, proto ORDER BY dst_ip, count(*) DESC, min(seq);

-- name: network_leads
WITH c AS (SELECT dst_ip AS host, src_ip AS peer, min(ts) AS contact FROM fx
           WHERE est AND ext_src GROUP BY dst_ip, src_ip)
SELECT c.host, c.peer, count(*) FROM c JOIN fx f ON f.src_ip = c.host AND f.dst_ip = c.peer
WHERE f.est AND (c.contact IS NULL OR f.ts IS NULL OR f.ts >= c.contact)
GROUP BY c.host, c.peer;
