-- VulnScope incident ruleset. Every query the baseline report runs, by name.
-- ruleset: 0.1
--
-- Table read: evs, one row per normalized event (columns of vulnflow/incident/events.py COLUMNS),
-- plus t (event time as TIMESTAMP), in_scope, in_window, kept (= in_scope AND in_window),
-- src_int and dst_int (address inside the case's networks, or a private range when none are set).
-- $$ stands for a literal dollar sign (JSON paths). $word is a fixed fragment filled in by vulnflow/incident/run.py; values from evidence files
-- reach these queries only as rows of evs.
-- Each result is ordered on every column it returns, so the same events give the same report.

-- name: counts_by_source
-- Events kept for the report, per source, category and outcome.
SELECT provider, source_type, category, outcome, count(*) AS n
FROM evs WHERE kept
GROUP BY ALL ORDER BY provider, source_type, category, outcome;

-- name: filtered_counts
-- What the case scope and window took out, and what has no time.
SELECT count(*) AS total,
       count(*) FILTER (WHERE NOT in_scope) AS out_of_scope,
       count(*) FILTER (WHERE in_scope AND NOT in_window) AS outside_window,
       count(*) FILTER (WHERE in_scope AND event_time IS NULL) AS untimed,
       count(*) FILTER (WHERE kept) AS kept
FROM evs;

-- name: time_basis_counts
-- How each file's event times were known (stated in the record or assumed UTC).
SELECT evidence_id, time_basis, count(*) FROM evs WHERE kept AND event_time IS NOT NULL
GROUP BY ALL ORDER BY evidence_id, time_basis;

-- name: evidence_spans
-- First and last event time per file, over all events (before scope and window).
SELECT evidence_id, min(event_time), max(event_time), count(*) FROM evs
WHERE event_time IS NOT NULL GROUP BY evidence_id ORDER BY evidence_id;

-- name: connection_groups
-- Connections grouped by source, destination, port and protocol. 'completed' means packets went
-- both ways (Zeek's connection state), not that a login or request succeeded.
SELECT src_ip, dst_ip, dst_port, proto,
       min(event_time) AS first_us, max(event_time) AS last_us, count(*) AS n,
       count(*) FILTER (WHERE outcome = 'completed') AS completed,
       count(*) FILTER (WHERE outcome = 'refused') AS refused,
       count(*) FILTER (WHERE outcome = 'attempted') AS attempted,
       list(event_id ORDER BY event_time, evidence_id, seq)[1:$sample] AS first_ids,
       list(event_id ORDER BY event_time DESC, evidence_id DESC, seq DESC)[1] AS last_id,
       bool_or(src_int) AS src_int, bool_or(dst_int) AS dst_int
FROM evs WHERE kept AND action = 'connection' AND event_time IS NOT NULL
GROUP BY src_ip, dst_ip, dst_port, proto
ORDER BY first_us, src_ip, dst_ip, dst_port NULLS FIRST, proto;

-- name: application_groups
-- Other network records (DNS, HTTP, TLS, files, ...) grouped by what they are about, with how many
-- share a Zeek uid with a connection record (a direct link, not a time match).
WITH conn_uids AS (
    SELECT DISTINCT json_extract_string(ids, '$$.zeek_uid') AS uid FROM evs
    WHERE kept AND action = 'connection' AND json_extract_string(ids, '$$.zeek_uid') IS NOT NULL)
SELECT action, coalesce(src_ip, '') AS src, coalesce(dst_ip, '') AS dst, coalesce(action_original, '') AS subject,
       min(event_time) AS first_us, max(event_time) AS last_us, count(*) AS n,
       count(*) FILTER (WHERE json_extract_string(ids, '$$.zeek_uid') IN (SELECT uid FROM conn_uids)) AS linked,
       list(event_id ORDER BY event_time, evidence_id, seq)[1:$sample] AS first_ids,
       list(event_id ORDER BY event_time DESC, evidence_id DESC, seq DESC)[1] AS last_id
FROM evs WHERE kept AND category = 'network' AND action <> 'connection' AND event_time IS NOT NULL
GROUP BY ALL ORDER BY first_us, action, src, dst, subject;

-- name: uid_links
-- Records tied to a connection record by the same Zeek uid: a direct link.
WITH c AS (SELECT json_extract_string(ids, '$$.zeek_uid') AS uid, event_id AS conn_id FROM evs
           WHERE kept AND action = 'connection' AND json_extract_string(ids, '$$.zeek_uid') IS NOT NULL)
SELECT a.action, a.event_id, c.conn_id, c.uid
FROM evs a JOIN c ON json_extract_string(a.ids, '$$.zeek_uid') = c.uid
WHERE a.kept AND a.action <> 'connection'
ORDER BY a.action, a.event_time, a.event_id, c.conn_id;

-- name: detections
-- Sensor detections (Zeek notices, IDS alerts in a Zeek export), one row each.
SELECT event_id, event_time, action, action_original, src_ip, dst_ip, dst_port,
       coalesce(json_extract_string(fields, '$$.msg'), '') AS msg
FROM evs WHERE kept AND category = 'detection'
ORDER BY event_time NULLS LAST, evidence_id, seq;

-- name: capture_loss
-- Sensor packet loss reported by Zeek's CaptureLoss notices.
SELECT event_id, event_time, coalesce(json_extract_string(fields, '$$.msg'), '') AS msg
FROM evs WHERE in_scope AND category = 'sensor' AND action = 'capture_loss'
ORDER BY event_time NULLS LAST, evidence_id, seq;

-- name: untimed
-- In-scope events with no readable time: listed apart, never placed on the timeline.
SELECT event_id, evidence_id, locator, source_type FROM evs
WHERE in_scope AND event_time IS NULL ORDER BY evidence_id, seq LIMIT $listed;

-- name: many_ports
-- One source trying many ports on one destination without a completed connection on most.
SELECT src_ip, dst_ip, count(DISTINCT dst_port) AS ports,
       count(DISTINCT dst_port) FILTER (WHERE outcome = 'completed') AS ports_completed,
       count(*) AS n, min(event_time), max(event_time),
       list(event_id ORDER BY event_time, evidence_id, seq)[1:$sample] AS ids
FROM evs WHERE kept AND action = 'connection' AND event_time IS NOT NULL
GROUP BY src_ip, dst_ip
HAVING count(DISTINCT dst_port) FILTER (WHERE outcome <> 'completed') >= $min_ports
ORDER BY ports DESC, src_ip, dst_ip;

-- name: many_hosts
-- One source trying one port on many destinations.
SELECT src_ip, dst_port, proto, count(DISTINCT dst_ip) AS hosts,
       count(DISTINCT dst_ip) FILTER (WHERE outcome = 'completed') AS hosts_completed,
       count(*) AS n, min(event_time), max(event_time),
       list(event_id ORDER BY event_time, evidence_id, seq)[1:$sample] AS ids
FROM evs WHERE kept AND action = 'connection' AND event_time IS NOT NULL AND dst_port IS NOT NULL
GROUP BY src_ip, dst_port, proto
HAVING count(DISTINCT dst_ip) FILTER (WHERE outcome <> 'completed') >= $min_hosts
ORDER BY hosts DESC, src_ip, dst_port, proto;

-- name: return_after_inbound
-- An outside address completed a connection to an inside host, and later that host completed a
-- connection to the same outside address. The two are linked only by address and order in time:
-- no shared identifier shows they belong together.
WITH inb AS (
    SELECT dst_ip AS host, src_ip AS peer, min(event_time) AS t1,
           list(event_id ORDER BY event_time, evidence_id, seq)[1] AS e1
    FROM evs WHERE kept AND action = 'connection' AND outcome = 'completed' AND NOT src_int AND dst_int
      AND event_time IS NOT NULL
    GROUP BY dst_ip, src_ip),
outb AS (
    SELECT src_ip AS host, dst_ip AS peer, event_time AS t2, event_id AS e2, evidence_id, seq, dst_port
    FROM evs WHERE kept AND action = 'connection' AND outcome = 'completed' AND src_int AND NOT dst_int
      AND event_time IS NOT NULL)
SELECT inb.host, inb.peer, inb.t1, inb.e1, min(outb.t2) AS t2,
       list(outb.e2 ORDER BY outb.t2, outb.evidence_id, outb.seq)[1] AS e2,
       count(*) AS n, list(DISTINCT outb.dst_port ORDER BY outb.dst_port) AS ports
FROM inb JOIN outb ON outb.host = inb.host AND outb.peer = inb.peer AND outb.t2 > inb.t1
GROUP BY inb.host, inb.peer, inb.t1, inb.e1
ORDER BY inb.t1, inb.host, inb.peer;

-- name: entities
-- Every address seen in kept events, with first and last time and its roles.
SELECT ip, min(t) AS first_us, max(t) AS last_us, count(*) AS n,
       count(*) FILTER (WHERE role = 'src') AS as_src, count(*) FILTER (WHERE role = 'dst') AS as_dst,
       bool_or(internal) AS internal
FROM (SELECT src_ip AS ip, event_time AS t, 'src' AS role, src_int AS internal FROM evs WHERE kept AND src_ip IS NOT NULL
      UNION ALL
      SELECT dst_ip, event_time, 'dst', dst_int FROM evs WHERE kept AND dst_ip IS NOT NULL)
GROUP BY ip ORDER BY n DESC, ip LIMIT $listed;

-- name: entity_count
SELECT count(DISTINCT ip) FROM (SELECT src_ip AS ip FROM evs WHERE kept UNION ALL SELECT dst_ip FROM evs WHERE kept)
WHERE ip IS NOT NULL;

-- name: cited
-- Where each cited event is, so its original record can be read back.
SELECT e.event_id, e.evidence_id, e.locator FROM evs e JOIN cited c USING (event_id)
ORDER BY e.evidence_id, e.seq;
