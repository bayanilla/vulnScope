"""Disk-backed storage for large telemetry sets.

Parsers stream records into this module in batches. Flows are written to Parquet files
inside a local working directory, then de-duplicated and sorted with DuckDB SQL into a single
on-disk table that the correlator queries. Zeek and OT events are written to compressed Parquet
too. Each input file gets its own ``PartWriter``, so files can be parsed in separate processes
(see normalize.py) and write their parts side by side. Nothing here holds the whole input in memory.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import tempfile
import weakref
from datetime import datetime, timedelta, timezone
from itertools import islice

from . import db, resources
from .schema import Flow, OTEvent, ZeekEvent

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_BATCH = 100_000
DEFAULT_SKEW_SECONDS = 2.0
# Connection examples for the Explorer are worked out over at most this many flows at a time.
EXAMPLE_SLICE_ROWS = 1_000_000
# Records are numbered (file number << FID_SHIFT) | position in the file, so the order is the
# order the files were given in, whichever process parsed them.
FID_SHIFT = 40
EVENT_COLUMNS = {"ord": "BIGINT", "ts": "BIGINT", "stream": "VARCHAR", "uid": "VARCHAR",
                 "src_ip": "VARCHAR", "dst_ip": "VARCHAR", "source": "VARCHAR", "fields": "JSON",
                 "protocol": "VARCHAR", "operation": "VARCHAR", "direction": "VARCHAR"}
# When two different sensors record the same session, keep the record from the sensor that
# knows the most about it: the firewall knows the policy action and zones, Zeek the byte counts.
SENSOR_RANK = {"paloalto": 0, "zeek": 1, "suricata": 2, "generic": 3}

FLOW_COLUMNS = ["ord", "ts_us", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "action",
                "established", "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source",
                "sensor", "fid", "day"]
_CSV_TYPES = {"ord": "BIGINT", "ts_us": "BIGINT", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
              "src_port": "INTEGER", "dst_port": "INTEGER", "proto": "VARCHAR", "action": "VARCHAR",
              "established": "BOOLEAN", "bytes_out": "BIGINT", "bytes_in": "BIGINT", "app": "VARCHAR",
              "src_zone": "VARCHAR", "dst_zone": "VARCHAR", "source": "VARCHAR", "sensor": "VARCHAR",
              "fid": "INTEGER", "day": "VARCHAR"}
# Columns read back into Flow objects, in Flow field order.
FLOW_SELECT = ("ts, src_ip, dst_ip, dst_port, proto, src_port, action, established, "
               "bytes_out, bytes_in, app, src_zone, dst_zone, source")


def _us(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    delta = ts - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def utc(ts: datetime | None) -> datetime | None:
    """DuckDB TIMESTAMP values come back naive; they are always UTC here."""
    return ts.replace(tzinfo=timezone.utc) if ts is not None and ts.tzinfo is None else ts


def naive(ts: datetime | None) -> datetime | None:
    """Aware UTC datetime -> naive UTC, for binding to TIMESTAMP parameters."""
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts is not None and ts.tzinfo else ts


def row_to_flow(r) -> Flow:
    return Flow(utc(r[0]), r[1], r[2], r[3], r[4], src_port=r[5], action=r[6], established=r[7],
                bytes_out=r[8], bytes_in=r[9], app=r[10], src_zone=r[11], dst_zone=r[12], source=r[13])


class Store:
    """One working directory + DuckDB database per analysis run."""

    def __init__(self, workdir: str | None = None, memory_limit: str | None = None,
                 budget: resources.Budget | None = None):
        """DuckDB's memory, threads and spill cap are sized to this machine (see resources.py);
        ``memory_limit`` or $VULNSCOPE_DUCKDB_MEMORY override the memory, clamped to a safe ceiling."""
        base = workdir or os.environ.get("VULNSCOPE_WORKDIR") or None
        if base:
            os.makedirs(base, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="vulnscope-work-", dir=base)
        self.budget = budget or resources.plan(memory_limit, self.dir)
        self.con = db.connect(os.path.join(self.dir, "work.duckdb"))
        tmp = os.path.join(self.dir, "duckdb_tmp")
        os.makedirs(tmp, exist_ok=True)
        self.con.execute(f"SET temp_directory = '{_q(tmp)}'")
        self.con.execute(f"SET memory_limit = '{self.budget.memory // resources.MiB}MiB'")
        self.con.execute(f"SET threads = {int(self.budget.threads)}")
        if self.budget.max_temp:
            self.con.execute(f"SET max_temp_directory_size = '{self.budget.max_temp // resources.MiB}MiB'")
        self.con.execute("SET preserve_insertion_order = false")
        self.parquet_dir = os.path.join(self.dir, "flows_parquet")
        self._batches = 0
        self._finalizer = weakref.finalize(self, _cleanup, self.con, self.dir)

    def close(self):
        self._finalizer()

    # -- bulk loading -------------------------------------------------------
    def _write_csv(self, rows, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            write_csv_rows(fh, rows)
        return path

    def _read_csv_sql(self, path: str, columns: dict[str, str]) -> str:
        cols = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
        return (f"read_csv('{_q(path)}', columns={{{cols}}}, header=false, delim=',', quote='\"', "
                f"escape='\"', nullstr='', auto_detect=false, strict_mode=false)")

    def write_flow_batch(self, rows: list[tuple]):
        """Append one batch of flow rows (FLOW_COLUMNS order) as a Parquet file."""
        if rows:
            self._batches += 1
            write_flow_parquet(self.con, self.dir, rows, f"main_{self._batches}")

    def finalize_flows(self, skew_seconds: float | None = DEFAULT_SKEW_SECONDS) -> tuple[int, int]:
        """Build the clean ``flows`` table from the Parquet partitions.

        1. Exact duplicates (same time, 5-tuple and action) are kept once: the most complete copy
           (preferred sensor, completed session, most bytes, then first read).
        2. The same session recorded by two different sensors (same 5-tuple, start times within
           ``skew_seconds``) is kept once, from the higher-ranked sensor. Two sensors of the same
           kind in different input files (e.g. two Zeek taps) count too: when they agree on the
           action, the most complete record (completed session, then most bytes) is kept.
        Returns (exact duplicates removed, cross-sensor duplicates removed).
        """
        con = self.con
        if not self._batches and not _has_parquet(self.parquet_dir):
            con.execute("CREATE OR REPLACE TABLE flows (seq BIGINT, ts TIMESTAMP, src_ip VARCHAR, "
                        "dst_ip VARCHAR, src_port INTEGER, dst_port INTEGER, proto VARCHAR, "
                        "action VARCHAR, established BOOLEAN, bytes_out BIGINT, bytes_in BIGINT, "
                        "app VARCHAR, src_zone VARCHAR, dst_zone VARCHAR, source VARCHAR, sensor VARCHAR)")
            return 0, 0
        rank = " ".join(f"WHEN '{k}' THEN {v}" for k, v in SENSOR_RANK.items())
        glob = _q(os.path.join(self.parquet_dir, "*.parquet"))
        con.execute(f"""
            CREATE OR REPLACE TABLE flows_exact AS
            SELECT * EXCLUDE (ts_us, day), make_timestamp(ts_us) AS ts,
                   CASE sensor {rank} ELSE 9 END AS sensor_rank
            FROM read_parquet('{glob}', hive_partitioning = false)
            -- keep the most complete copy: preferred sensor, then a completed session (one tap may have
            -- seen only the SYN at the same instant), then most bytes, then the one read first
            QUALIFY row_number() OVER (PARTITION BY ts_us, src_ip, src_port, dst_ip, dst_port, proto, action
                                       ORDER BY CASE sensor {rank} ELSE 9 END, established DESC,
                                                bytes_out + bytes_in DESC, ord) = 1""")
        total = con.execute(f"SELECT count(*) FROM read_parquet('{glob}')").fetchone()[0]
        kept = con.execute("SELECT count(*) FROM flows_exact").fetchone()[0]
        exact = total - kept
        if skew_seconds is not None and skew_seconds >= 0:
            con.execute(f"""
                CREATE OR REPLACE TEMP TABLE cross_dups AS
                SELECT DISTINCT a.ord FROM flows_exact a JOIN flows_exact b
                  ON a.src_ip = b.src_ip AND a.dst_ip = b.dst_ip AND a.src_port = b.src_port
                 AND a.dst_port = b.dst_port AND a.proto = b.proto
                WHERE (b.sensor_rank < a.sensor_rank
                       OR (b.sensor_rank = a.sensor_rank AND b.fid <> a.fid AND b.action = a.action
                           -- same kind of sensor: keep the most complete record (a tap that saw the
                           -- whole session beats one that saw only the SYN), then the one read first
                           AND (b.established AND NOT a.established
                                OR (b.established = a.established
                                    AND (b.bytes_out + b.bytes_in > a.bytes_out + a.bytes_in
                                         OR (b.bytes_out + b.bytes_in = a.bytes_out + a.bytes_in
                                             AND b.ord < a.ord))))))
                  AND abs(epoch_us(a.ts) - epoch_us(b.ts)) <= {int(skew_seconds * 1_000_000)}""")
        else:
            con.execute("CREATE OR REPLACE TEMP TABLE cross_dups (ord BIGINT)")
        cross = con.execute("SELECT count(*) FROM cross_dups").fetchone()[0]
        con.execute("""
            CREATE OR REPLACE TABLE flows AS
            SELECT row_number() OVER (ORDER BY ts NULLS LAST, ord) AS seq,
                   ts, src_ip, dst_ip, src_port, dst_port, proto, action, established,
                   bytes_out, bytes_in, app, src_zone, dst_zone, source, sensor
            FROM flows_exact ANTI JOIN cross_dups USING (ord)""")
        con.execute("DROP TABLE flows_exact; DROP TABLE cross_dups")
        shutil.rmtree(self.parquet_dir, ignore_errors=True)
        return exact, cross

    def load_flow_list(self, flows: list[Flow]):
        """Load an in-memory list (tests, small callers) as-is: no de-duplication."""
        writer = FlowWriter(self)
        for f in flows:
            writer.add(f, "list")
        writer.flush()
        self.finalize_flows(skew_seconds=None)

    def events(self, name: str, ot: bool, count: int) -> "EventSpool":
        """The ``name`` events (zeek_events / ot_events) that PartWriters wrote for this run."""
        return EventSpool(self, name, ot, count)

    def answering_ips(self) -> set[str]:
        """Addresses that exist: they started a session, or answered one (completed, refused with a
        reset, or sent data back). An address that was only probed and never answered is left out,
        also when a firewall blocked the probe: a firewall logs a deny for an empty address too."""
        return {r[0] for r in self.con.execute("""
            SELECT src_ip FROM flows
            UNION SELECT dst_ip FROM flows
                  WHERE established OR action = 'reject' OR bytes_in > 0""").fetchall()}

    def flow_ips(self) -> list[str]:
        """Every distinct address in the clean flows, as source or destination."""
        return [r[0] for r in self.con.execute(
            "SELECT src_ip FROM flows UNION SELECT dst_ip FROM flows").fetchall()]

    def pair_counts(self, ips) -> list[tuple[str, str, int]]:
        """(source, destination, sessions) for every address pair with one of ``ips`` on either side."""
        ips = sorted(set(ips))
        if not ips:
            return []
        self.insert_rows("pair_ips", {"ip": "VARCHAR"}, ((ip,) for ip in ips))
        try:
            return self.con.execute("""
                SELECT src_ip, dst_ip, count(*) FROM flows
                WHERE src_ip IN (SELECT ip FROM pair_ips) OR dst_ip IN (SELECT ip FROM pair_ips)
                GROUP BY src_ip, dst_ip""").fetchall()
        finally:
            self.con.execute("DROP TABLE pair_ips")

    def broadcast_ips(self) -> set[str]:
        """IPv4 broadcast-like destinations: 255.255.255.255, or an address ending in .255 that only
        ever received UDP/ICMP (subnet broadcasts such as NetBIOS or discovery). They are not hosts,
        so they are left out of the probed-address counts. An address ending in .255 that received
        TCP is treated as an ordinary address (it can be a real host in networks larger than /24)."""
        return {r[0] for r in self.con.execute("""
            SELECT dst_ip FROM flows WHERE dst_ip LIKE '%.255' AND dst_ip NOT LIKE '%:%'
            GROUP BY dst_ip HAVING bool_and(proto <> 'tcp')""").fetchall()}

    def probed_rows(self):
        """One row per address that was probed and never answered: (address, probing sources,
        ports tried, attempts, blocked by a firewall, first, last). Sources and ports are capped."""
        return self.con.execute("""
            WITH live AS (SELECT src_ip AS ip FROM flows
                          UNION SELECT dst_ip FROM flows
                                WHERE established OR action = 'reject' OR bytes_in > 0)
            SELECT dst_ip, list_sort(list(DISTINCT src_ip))[:10], count(DISTINCT src_ip),
                   list_sort(list(DISTINCT dst_port) FILTER (dst_port IS NOT NULL))[:20],
                   count(*), bool_or(action = 'deny'), min(ts), max(ts)
            FROM flows WHERE dst_ip NOT IN (SELECT ip FROM live)
            GROUP BY dst_ip
            HAVING NOT (dst_ip LIKE '%.255' AND dst_ip NOT LIKE '%:%' AND bool_and(proto <> 'tcp'))
            ORDER BY dst_ip""").fetchall()

    def firewall_blocked_ips(self) -> set[str]:
        """Addresses a firewall log shows traffic to being blocked (Zeek cannot tell a silent drop
        from an empty address, so this only comes from firewall logs)."""
        return {r[0] for r in self.con.execute(
            "SELECT DISTINCT dst_ip FROM flows WHERE action = 'deny'").fetchall()}

    def answered_share(self) -> tuple[int, int]:
        """(sessions, sessions with any answer). When almost nothing is answered, the sensor is
        probably seeing one direction of the traffic only."""
        n, a = self.con.execute("""
            SELECT count(*), count(*) FILTER (established OR action = 'reject' OR bytes_in > 0)
            FROM flows""").fetchone()
        return int(n or 0), int(a or 0)

    def insert_rows(self, table: str, columns: dict[str, str], rows, append: bool = False) -> None:
        """Create ``table`` and bulk-load rows through a CSV file (fast, needs no numpy/arrow).
        ``append`` adds the rows to the table when it already exists."""
        cols = ", ".join(f"{k} {v}" for k, v in columns.items())
        self.con.execute(f"CREATE {'TABLE IF NOT EXISTS' if append else 'OR REPLACE TABLE'} {table} ({cols})")
        rows = list(rows)
        if not rows:
            return
        self._batches += 1
        path = self._write_csv(rows, f"{table}_{self._batches}.csv")
        try:
            self.con.execute(f"INSERT INTO {table} SELECT * FROM {self._read_csv_sql(path, columns)}")
        finally:
            os.remove(path)


    # -- Explorer queries (explore.py) ---------------------------------------------------------
    # The Explorer reads flows only through these methods. Per-pair rollups stream in batches, and
    # the outside addresses of each host come grouped by host, so the Explorer never holds every
    # host-to-internet pair in memory at once.
    def explorer_tables(self, ext, hosts) -> None:
        """Tables the Explorer queries join on: every address in the flows and whether it is
        outside (``ext(ip)``), and the hosts that get a card (``hosts``)."""
        ips = [r[0] for r in self.con.execute(
            "SELECT src_ip FROM flows UNION SELECT dst_ip FROM flows").fetchall()]
        self.insert_rows("explore_ip", {"ip": "VARCHAR", "ext": "BOOLEAN"}, ((ip, bool(ext(ip))) for ip in ips))
        self.insert_rows("explore_hosts", {"ip": "VARCHAR"}, ((ip,) for ip in set(hosts)))

    def inner_pairs(self):
        """Per (source, destination) rollup of every pair that is not a host's contact with an
        outside address: both ends inside, or a host with a card at an outside end. Rows:
        (src, dst) + PAIR_STATS, in the order the pairs first appear in the flows."""
        cur = self.con.cursor()
        cur.execute(f"""
            SELECT f.src_ip, f.dst_ip, {PAIR_STATS}
            FROM flows f JOIN explore_ip s ON s.ip = f.src_ip JOIN explore_ip d ON d.ip = f.dst_ip
            WHERE f.src_ip <> f.dst_ip
              AND (NOT s.ext OR f.src_ip IN (SELECT ip FROM explore_hosts))
              AND (NOT d.ext OR f.dst_ip IN (SELECT ip FROM explore_hosts))
            GROUP BY f.src_ip, f.dst_ip ORDER BY min(f.seq)""")
        try:
            while rows := cur.fetchmany(10_000):
                yield from rows
        finally:
            cur.close()

    def outside_contacts(self):
        """Every (host with a card, outside address) that exchanged traffic, grouped by host:
        (host, address, inbound stats, outbound stats), each stats a PAIR_STATS tuple (all None
        when there was no traffic that way). DuckDB sorts on disk, so memory stays flat."""
        n = len(_split_stats())
        cols = ", ".join(f"i.c{k}" for k in range(n)) + ", " + ", ".join(f"o.c{k}" for k in range(n))
        stats = ", ".join(f"{expr} AS c{k}" for k, expr in enumerate(_split_stats()))
        cur = self.con.cursor()
        cur.execute(f"""
            WITH p AS (
                SELECT f.src_ip, f.dst_ip, s.ext AS s_ext, d.ext AS d_ext, {stats}
                FROM flows f JOIN explore_ip s ON s.ip = f.src_ip JOIN explore_ip d ON d.ip = f.dst_ip
                WHERE f.src_ip <> f.dst_ip AND (s.ext OR d.ext)
                  AND (f.src_ip IN (SELECT ip FROM explore_hosts) OR f.dst_ip IN (SELECT ip FROM explore_hosts))
                GROUP BY ALL),
            i AS (SELECT * FROM p WHERE s_ext AND dst_ip IN (SELECT ip FROM explore_hosts)),
            o AS (SELECT * FROM p WHERE d_ext AND src_ip IN (SELECT ip FROM explore_hosts))
            SELECT coalesce(i.dst_ip, o.src_ip) AS host, coalesce(i.src_ip, o.dst_ip) AS addr, {cols}
            FROM i FULL JOIN o ON i.dst_ip = o.src_ip AND i.src_ip = o.dst_ip
            ORDER BY host""")
        try:
            while rows := cur.fetchmany(10_000):
                for r in rows:
                    yield r[0], r[1], r[2:2 + n], r[2 + n:]
        finally:
            cur.close()

    def vuln_hits(self, services: list[tuple], scanners=()) -> list[tuple]:
        """(source, host, port, proto) of completed sessions onto a vulnerable service: ``services``
        rows are (host, port, proto, window start, window end), a None window meaning any time.
        Sessions the vulnerability scanner started are not counted."""
        if not services:
            return []
        self.insert_rows("explore_vkeys", {"host": "VARCHAR", "port": "INTEGER", "proto": "VARCHAR",
                                           "lo": "TIMESTAMP", "hi": "TIMESTAMP"}, set(services))
        try:
            return self.con.execute("""
                SELECT DISTINCT f.src_ip, f.dst_ip, f.dst_port, f.proto FROM flows f JOIN explore_vkeys k
                  ON f.dst_ip = k.host AND f.dst_port = k.port AND f.proto = k.proto
                 AND (k.lo IS NULL OR f.ts IS NULL OR f.ts BETWEEN k.lo AND k.hi)
                WHERE f.action = 'allow' AND f.established AND f.src_ip <> f.dst_ip
                  AND NOT list_contains(?, f.src_ip)""", [list(scanners)]).fetchall()
        finally:
            self.con.execute("DROP TABLE explore_vkeys")

    def pair_examples(self, pairs=None, n: int = 6) -> None:
        """Table ``explore_ex`` (src_ip, dst_ip, ex): for each pair, its first ``n`` distinct
        connections (ports, protocol, app, action, outcome, source) in the order seen. ``pairs``
        limits it to those (source, destination) pairs; None means every pair. Large runs are done
        in slices of source addresses, so DuckDB's memory limit holds."""
        join = ""
        if pairs is not None:
            self.insert_rows("explore_exkeys", {"src": "VARCHAR", "dst": "VARCHAR"}, set(pairs))
            join = "JOIN explore_exkeys k ON k.src = f.src_ip AND k.dst = f.dst_ip"
        flows = self.con.execute("SELECT count(*) FROM flows").fetchone()[0]
        slices = max(1, -(-int(flows) // EXAMPLE_SLICE_ROWS))
        self.con.execute("CREATE OR REPLACE TABLE explore_ex (src_ip VARCHAR, dst_ip VARCHAR, ex STRUCT("
                         "src_ip VARCHAR, src_port INTEGER, dst_ip VARCHAR, dst_port INTEGER, proto VARCHAR, "
                         "app VARCHAR, action VARCHAR, established BOOLEAN, source VARCHAR)[])")
        for part in range(slices):
            where = f"AND hash(f.src_ip) % {slices} = {part}" if slices > 1 else ""
            self.con.execute(f"""
                INSERT INTO explore_ex
                WITH d AS (SELECT f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.proto, f.app, f.action,
                                  f.established, f.source, min(f.seq) AS s
                           FROM flows f {join} WHERE f.src_ip <> f.dst_ip {where} GROUP BY ALL),
                r AS (SELECT * FROM d QUALIFY row_number() OVER (PARTITION BY src_ip, dst_ip ORDER BY s) <= {int(n)})
                SELECT src_ip, dst_ip,
                       list({{'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port,
                              'proto': proto, 'app': app, 'action': action, 'established': established,
                              'source': source}} ORDER BY s) AS ex
                FROM r GROUP BY src_ip, dst_ip""")
        if pairs is not None:
            self.con.execute("DROP TABLE explore_exkeys")

    def examples_for(self, pairs) -> dict[tuple, list[dict]]:
        """{(src, dst): examples} from ``explore_ex`` (see pair_examples) for ``pairs``."""
        self.insert_rows("explore_exkeys", {"src": "VARCHAR", "dst": "VARCHAR"}, set(pairs))
        try:
            return {(s, d): ex for s, d, ex in self.con.execute("""
                SELECT e.src_ip, e.dst_ip, e.ex FROM explore_ex e
                JOIN explore_exkeys k ON k.src = e.src_ip AND k.dst = e.dst_ip""").fetchall()}
        finally:
            self.con.execute("DROP TABLE explore_exkeys")

    def write_contacts(self, path: str) -> None:
        """Write ``explore_contacts`` (host, side, rank, ip, row) to Parquet with each row's
        connection examples (from ``explore_ex``): for outside addresses ('a') the inbound pair's
        then the outbound pair's, for internal peers ('p') the host's own then the peer's."""
        self.con.execute(f"""
            COPY (SELECT c.host, c.side, c.rank, c.ip, c.row,
                         coalesce(e1.ex, []) || coalesce(e2.ex, []) AS ex
                  FROM explore_contacts c
                  LEFT JOIN explore_ex e1 ON e1.src_ip = CASE c.side WHEN 'a' THEN c.ip ELSE c.host END
                                         AND e1.dst_ip = CASE c.side WHEN 'a' THEN c.host ELSE c.ip END
                  LEFT JOIN explore_ex e2 ON e2.src_ip = CASE c.side WHEN 'a' THEN c.host ELSE c.ip END
                                         AND e2.dst_ip = CASE c.side WHEN 'a' THEN c.ip ELSE c.host END
                  ORDER BY c.host, c.side, c.rank)
            TO '{_q(path)}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100000)""")

    def flow_span(self) -> tuple[int, datetime | None, datetime | None]:
        """(timed flows between two addresses, first, last)."""
        row = self.con.execute("SELECT count(*), min(ts), max(ts) FROM flows "
                               "WHERE ts IS NOT NULL AND src_ip <> dst_ip").fetchone()
        return int(row[0] or 0), utc(row[1]), utc(row[2])

    def timeline_flows(self, flagged: list[str], cap: int):
        """Timed flows (ts, src, dst, dst_port, action, established, proto) in time order, at most
        ``cap``: when there are more, flows to or from a ``flagged`` address first, then blocked
        flows, up to half of ``cap``, each tier a random sample over the whole run, and the rest a
        random sample of everything else. Returns (rows iterator, sampled)."""
        cols = "ts, src_ip, dst_ip, dst_port, action, established, proto"
        base = "FROM flows WHERE ts IS NOT NULL AND src_ip <> dst_ip"
        con = self.con
        total = self.flow_span()[0]
        cur = con.cursor()
        sampled = total > cap
        if not sampled:
            cur.execute(f"SELECT {cols} {base} ORDER BY seq")
        else:
            # Flagged addresses are a table and each flow is tested by a join. (Searching a list of
            # addresses for every flow, per tier, was most of the Timeline's build time.) The tiers
            # read flows directly, in its own row order, so each sample is the one a list search gave.
            self.insert_rows("timeline_flagged", {"ip": "VARCHAR"}, ((ip,) for ip in sorted(set(flagged))))
            hot = "(src_ip IN (SELECT ip FROM timeline_flagged) OR dst_ip IN (SELECT ip FROM timeline_flagged))"
            half = cap // 2
            tiers = [hot, f"action <> 'allow' AND NOT {hot}", f"action = 'allow' AND NOT {hot}"]
            counts = [int(n or 0) for n in con.execute(
                "SELECT " + ", ".join(f"count(*) FILTER ({w})" for w in tiers) + f" {base}").fetchone()]
            take = [min(counts[0], half)]
            take.append(min(counts[1], half - take[0]))
            take.append(min(counts[2], cap - take[0] - take[1]))
            parts = []
            for w, n, k in zip(tiers, counts, take):
                if not k:
                    continue
                sample = "" if k >= n else f" USING SAMPLE reservoir({k} ROWS) REPEATABLE (7)"
                parts.append(f"SELECT * FROM (SELECT {cols}, seq {base} AND {w}){sample}")
            cur.execute(" UNION ALL ".join(parts) + " ORDER BY seq")

        def rows():
            try:
                while batch := cur.fetchmany(10_000):
                    yield from batch
            finally:
                cur.close()
        return rows(), sampled

    def timeline_counts(self, t0: datetime, bucket_seconds: float) -> list[tuple[int, int]]:
        """Every timed flow counted per bucket of ``bucket_seconds`` from ``t0``: [(bucket, flows)]."""
        return self.con.execute(
            "SELECT CAST(floor((epoch(ts) - ?) / ?) AS BIGINT) AS b, count(*) FROM flows "
            "WHERE ts IS NOT NULL AND src_ip <> dst_ip GROUP BY b ORDER BY b",
            [t0.timestamp(), bucket_seconds]).fetchall()

    def export_flows_parquet(self, path: str) -> None:
        """The cleaned flows, in the order read, as one zstd Parquet file (the columns of
        normalized/flows.csv)."""
        self.con.execute(f"""
            COPY (SELECT ts, src_ip, src_port, dst_ip, dst_port, proto, action, established,
                         bytes_out, bytes_in, app, src_zone, dst_zone, source FROM flows ORDER BY seq)
            TO '{_q(path)}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880)""")

    def export_flows_csv(self, path: str) -> None:
        """The cleaned flows as normalized/flows.csv, written by DuckDB instead of a Python loop
        over every session. The file is the same as the csv module wrote: ISO times in UTC,
        True/False, CRLF line ends, and text cells that a spreadsheet would run as a formula
        prefixed with an apostrophe (see report._cell)."""
        def safe(c):
            return (f"CASE WHEN length({c}) > 1 AND {c}[1] IN ('=', '+', '-', '@', chr(9), chr(13)) "
                    f"THEN chr(39) || {c} ELSE nullif({c}, '') END AS {c}")
        self.con.execute(f"""
            COPY (SELECT strftime(ts, '%Y-%m-%dT%H:%M:%S')
                         || CASE WHEN epoch_us(ts) % 1000000 = 0 THEN ''
                                 ELSE '.' || lpad(CAST(epoch_us(ts) % 1000000 AS VARCHAR), 6, '0') END
                         || '+00:00' AS ts,
                         src_ip, src_port, dst_ip, dst_port, {safe('proto')}, {safe('action')},
                         CASE WHEN established THEN 'True' ELSE 'False' END AS established,
                         bytes_out, bytes_in, {safe('app')}, {safe('src_zone')}, {safe('dst_zone')},
                         {safe('source')}
                  FROM flows ORDER BY seq)
            TO '{_q(path)}' (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"',
                             NEW_LINE '\\r\\n')""")


def contact_rows(path: str, host: str) -> list[tuple]:
    """One host's rows from an Explorer contacts file (Store.write_contacts): (side, row JSON,
    connection examples), outside addresses ('a') then internal peers ('p'), each in rank order."""
    con = db.connect()
    try:
        con.execute("SET threads = 2")
        return con.execute("SELECT side, row, ex FROM read_parquet(?) WHERE host = ? ORDER BY side, rank",
                           [path, host]).fetchall()
    finally:
        con.close()

# Per (source, destination) rollup columns read into explore._Pair: sessions, completed, blocked,
# ports tried, ports with completed sessions, bytes, first, last, first completed, last completed.
PAIR_STATS = """count(*), count(*) FILTER (action = 'allow' AND established),
    count(*) FILTER (action <> 'allow'),
    list(DISTINCT dst_port) FILTER (dst_port IS NOT NULL),
    list(DISTINCT dst_port) FILTER (dst_port IS NOT NULL AND action = 'allow' AND established),
    coalesce(sum(bytes_out + bytes_in), 0), min(ts), max(ts),
    min(ts) FILTER (action = 'allow' AND established), max(ts) FILTER (action = 'allow' AND established)"""


def _split_stats() -> list[str]:
    """PAIR_STATS as its separate column expressions."""
    out, depth, cur = [], 0, ""
    for ch in PAIR_STATS:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        depth += (ch == "(") - (ch == ")")
        cur += ch
    out.append(cur.strip())
    return out

class FlowWriter:
    """Buffers flows and writes one Parquet batch per ``batch_size`` rows."""

    def __init__(self, store: Store, batch_size: int = DEFAULT_BATCH):
        self.store, self.batch_size, self.rows, self.ord = store, batch_size, [], 0
        self._days: dict[int, str] = {}

    def add(self, f: Flow, sensor: str, fid: int = 0):
        """``fid`` numbers the input file, so sessions repeated by a second sensor of the same
        kind (another Zeek tap) can be told apart from records inside one file."""
        self.rows.append(flow_row(self.ord, f, sensor, fid, self._days))
        self.ord += 1
        if len(self.rows) >= self.batch_size:
            self.flush()

    def flush(self):
        self.store.write_flow_batch(self.rows)
        self.rows = []


class FlowView:
    """Read-only, sequence-like view of the clean flows table, in time order."""

    def __init__(self, store: Store):
        self.store = store
        self._len = None

    def __len__(self):
        if self._len is None:
            self._len = self.store.con.execute("SELECT count(*) FROM flows").fetchone()[0]
        return self._len

    def __bool__(self):
        return len(self) > 0

    def __iter__(self):
        cur = self.store.con.cursor()
        cur.execute(f"SELECT {FLOW_SELECT} FROM flows ORDER BY seq")
        while True:
            rows = cur.fetchmany(10_000)
            if not rows:
                break
            for r in rows:
                yield row_to_flow(r)
        cur.close()

    def counts(self, column: str = "stream") -> dict[str, int]:
        """Events per ``column`` value ("stream", or "protocol" for OT events), counted by DuckDB
        from the Parquet files instead of reading every event back into Python."""
        if not self._len or not _has_parquet(self.path):
            return {}
        assert column in ("stream", "protocol")
        return {k: int(n) for k, n in self.store.con.execute(
            f"SELECT {column}, count(*) FROM read_parquet('{_q(os.path.join(self.path, '*.parquet'))}') "
            f"GROUP BY {column}").fetchall()}

    def of_stream(self, stream: str):
        """Only the events of one stream, in input order (a filter DuckDB applies on the files)."""
        if not self._len or not _has_parquet(self.path):
            return
        for r in self.store.con.execute(
                f"SELECT ts, uid, src_ip, dst_ip, source, fields FROM read_parquet("
                f"'{_q(os.path.join(self.path, '*.parquet'))}') WHERE stream = ? ORDER BY ord", [stream]).fetchall():
            yield ZeekEvent(ts=EPOCH + timedelta(microseconds=r[0]) if r[0] is not None else None,
                            stream=stream, uid=r[1], src_ip=r[2], dst_ip=r[3],
                            fields=json.loads(r[5]) if r[5] is not None else {}, source=r[4])

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(self)[i]
        n = len(self)
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError(i)
        r = self.store.con.execute(f"SELECT {FLOW_SELECT} FROM flows WHERE seq = ?", [i + 1]).fetchone()
        return row_to_flow(r)

    def __eq__(self, other):
        if isinstance(other, (list, FlowView)):
            return len(self) == len(other) and list(self) == list(other)
        return NotImplemented

    __hash__ = None


class PartWriter:
    """Writes one input file's flows and events as Parquet files into a run's working directory.

    It has its own small in-memory DuckDB connection, so it works the same inside a parse worker
    process as in the main process. File names carry the file number, so writers for different
    files never touch the same file."""

    def __init__(self, workdir: str, fid: int, batch_size: int = DEFAULT_BATCH):
        self.dir, self.fid, self.batch_size = workdir, fid, batch_size
        self.con = None
        self.flows, self.events = [], {"zeek_events": [], "ot_events": []}
        self.n_flows = self.n_events = 0
        self.base = fid << FID_SHIFT
        self._batch = 0
        self._days: dict[int, str] = {}
        self.counts = {"zeek_events": 0, "ot_events": 0}

    def _con(self):
        if self.con is None:
            self.con = db.connect()
            # one batch at a time: little memory, no threads competing with the other workers
            self.con.execute("SET threads = 1")
            self.con.execute("SET memory_limit = '512MiB'")
            self.con.execute(f"SET temp_directory = '{_q(os.path.join(self.dir, 'duckdb_tmp'))}'")
        return self.con

    def add_flow(self, f: Flow, sensor: str):
        self.flows.append(flow_row(self.base + self.n_flows, f, sensor, self.fid, self._days))
        self.n_flows += 1
        if len(self.flows) >= self.batch_size:
            self._flush_flows()

    def add_event(self, e: ZeekEvent):
        """A Zeek event; an OT event is also written to the OT event set (as before)."""
        ord_ = self.base + self.n_events
        self.n_events += 1
        row = {"ord": ord_, "ts": _us(e.ts), "stream": e.stream, "uid": e.uid, "src_ip": e.src_ip,
               "dst_ip": e.dst_ip, "source": e.source, "fields": e.fields}
        self._add_event("zeek_events", row)
        if isinstance(e, OTEvent):
            self._add_event("ot_events", dict(row, protocol=e.protocol, operation=e.operation,
                                              direction=e.direction))

    def _add_event(self, name, row):
        self.events[name].append(row)
        self.counts[name] += 1
        if len(self.events[name]) >= self.batch_size:
            self._flush_events(name)

    def _flush_flows(self):
        if self.flows:
            self._batch += 1
            write_flow_parquet(self._con(), self.dir, self.flows, f"f{self.fid}_{self._batch}")
            self.flows = []

    def _flush_events(self, name):
        rows = self.events[name]
        if not rows:
            return
        self._batch += 1
        out = os.path.join(self.dir, name)
        os.makedirs(out, exist_ok=True)
        tmp = os.path.join(self.dir, f"{name}_f{self.fid}_{self._batch}.jsonl")
        with open(tmp, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, default=str, ensure_ascii=False) + "\n")
        try:
            cols = ", ".join(f"'{k}': '{v}'" for k, v in EVENT_COLUMNS.items())
            self._con().execute(
                f"COPY (SELECT * FROM read_json('{_q(tmp)}', format = 'newline_delimited', "
                f"columns = {{{cols}}})) TO '{_q(os.path.join(out, f'f{self.fid}_{self._batch}.parquet'))}' "
                f"(FORMAT parquet, COMPRESSION zstd)")
        finally:
            os.remove(tmp)
        self.events[name] = []

    def close(self):
        """Write what is left and release the connection."""
        try:
            self._flush_flows()
            for name in self.events:
                self._flush_events(name)
        finally:
            if self.con is not None:
                self.con.close()
                self.con = None


class EventSpool:
    """Sequence-like read view of the Zeek / OT events PartWriters wrote, in input order.
    Events are read back in batches, so memory stays flat however many there are."""

    def __init__(self, store: Store, name: str, ot: bool, count: int = 0):
        self.store, self.ot, self._len = store, ot, count
        self.path = os.path.join(store.dir, name)

    def close(self):
        pass

    def __len__(self):
        return self._len

    def __bool__(self):
        return self._len > 0

    def __iter__(self):
        if not self._len or not _has_parquet(self.path):
            return
        cols = "ts, stream, uid, src_ip, dst_ip, source, fields" + (", protocol, operation, direction" if self.ot else "")
        cur = self.store.con.cursor()
        try:
            cur.execute(f"SELECT {cols} FROM read_parquet('{_q(os.path.join(self.path, '*.parquet'))}') ORDER BY ord")
            while rows := cur.fetchmany(10_000):
                for r in rows:
                    ts = EPOCH + timedelta(microseconds=r[0]) if r[0] is not None else None
                    common = dict(ts=ts, stream=r[1], uid=r[2], src_ip=r[3], dst_ip=r[4],
                                  fields=json.loads(r[6]) if r[6] is not None else {}, source=r[5])
                    if self.ot:
                        yield OTEvent(**common, protocol=r[7], operation=r[8], direction=r[9])
                    else:
                        yield ZeekEvent(**common)
        finally:
            cur.close()

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(self)[i]
        if i < 0:
            i += self._len
        if not 0 <= i < self._len:
            raise IndexError(i)
        return next(islice(iter(self), i, None))


def flow_row(ord_: int, f: Flow, sensor: str, fid: int, days: dict) -> tuple:
    """One flow as a row in FLOW_COLUMNS order. ``days`` caches day names."""
    us = _us(f.ts)
    if us is None:
        day = "untimed"
    else:
        d = us // 86_400_000_000
        day = days.get(d)
        if day is None:
            day = days[d] = (EPOCH + timedelta(days=d)).strftime("%Y-%m-%d")
    return (ord_, us, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto, f.action,
            f.established, f.bytes_out or 0, f.bytes_in or 0, f.app, f.src_zone,
            f.dst_zone, f.source, sensor, fid, day)


def _csv_cell(value) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if any(c in text for c in ',"\r\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def csv_lines(rows):
    """Rows as csv.writer writes them (default dialect), built by hand."""
    for row in rows:
        line = ",".join(_csv_cell(v) for v in row)
        yield (line or ('""' if len(row) == 1 else "")) + "\r\n"     # a lone empty cell is written quoted


def write_csv_rows(fh, rows) -> None:
    """csv.writer(fh).writerows(rows), also where the csv module cannot write a value: before
    Python 3.11 it refuses text holding a NUL character, which a damaged log can contain."""
    rows = rows if isinstance(rows, list) else list(rows)
    start = fh.tell()
    try:
        csv.writer(fh).writerows(rows)
    except csv.Error:
        fh.seek(start)
        fh.truncate()
        fh.writelines(csv_lines(rows))


def write_flow_parquet(con, workdir: str, rows: list[tuple], name: str) -> None:
    """Write flow rows (FLOW_COLUMNS order) to ``flows_parquet/<name>.parquet`` through a CSV file
    (fast, needs no numpy/arrow)."""
    out = os.path.join(workdir, "flows_parquet")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(workdir, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        write_csv_rows(fh, rows)
    try:
        cols = ", ".join(f"'{k}': '{v}'" for k, v in _CSV_TYPES.items())
        source = (f"read_csv('{_q(path)}', columns={{{cols}}}, header=false, delim=',', quote='\"', "
                  f"escape='\"', nullstr='', auto_detect=false, strict_mode=false)")
        # Empty strings are read back as NULL by nullstr=''; restore them for text columns.
        text = {"app", "src_zone", "dst_zone", "source"}
        select = ", ".join(f"coalesce({c}, '') AS {c}" if c in text else c for c in FLOW_COLUMNS)
        con.execute(f"COPY (SELECT {select} FROM {source}) TO '{_q(os.path.join(out, name + '.parquet'))}' "
                    f"(FORMAT parquet)")
    finally:
        os.remove(path)


def _has_parquet(path: str) -> bool:
    try:
        return any(n.endswith(".parquet") for n in os.listdir(path))
    except OSError:
        return False


def _q(s: str) -> str:
    return str(s).replace("'", "''")


def _cleanup(con, path):
    try:
        con.close()
    except Exception:
        pass
    shutil.rmtree(path, ignore_errors=True)
