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

import duckdb

from . import resources
from .schema import Flow, OTEvent, ZeekEvent

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_BATCH = 100_000
DEFAULT_SKEW_SECONDS = 2.0
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
        self.con = duckdb.connect(os.path.join(self.dir, "work.duckdb"))
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
            csv.writer(fh).writerows(rows)
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

    def insert_rows(self, table: str, columns: dict[str, str], rows) -> None:
        """Create ``table`` and bulk-load rows through a CSV file (fast, needs no numpy/arrow)."""
        cols = ", ".join(f"{k} {v}" for k, v in columns.items())
        self.con.execute(f"CREATE OR REPLACE TABLE {table} ({cols})")
        rows = list(rows)
        if not rows:
            return
        self._batches += 1
        path = self._write_csv(rows, f"{table}_{self._batches}.csv")
        try:
            self.con.execute(f"INSERT INTO {table} SELECT * FROM {self._read_csv_sql(path, columns)}")
        finally:
            os.remove(path)


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
            self.con = duckdb.connect()
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


def write_flow_parquet(con, workdir: str, rows: list[tuple], name: str) -> None:
    """Write flow rows (FLOW_COLUMNS order) to ``flows_parquet/<name>.parquet`` through a CSV file
    (fast, needs no numpy/arrow)."""
    out = os.path.join(workdir, "flows_parquet")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(workdir, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)
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
