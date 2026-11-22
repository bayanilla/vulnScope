"""Native readers: DuckDB reads the two busiest formats itself, with no Python object per record.

A Zeek ``conn`` log (TSV) and a Palo Alto CSV export with a header row make up nearly all the
bytes of a large run. For those, DuckDB's own reader parses the file and one SELECT applies the
same field rules as the Python parsers (zeek.py, paloalto.py), writing the flows straight to
Parquet. On the 1 GB benchmark this is the difference between minutes and seconds of parsing.

The Python parsers stay the reference. A native reader only handles a file when it can give
exactly what the Python parser gives, and steps aside otherwise:

* before reading, the file must look ordinary (plain text, the default Zeek separators, a
  header the reader knows);
* while reading, any value in a shape the SQL rules do not cover exactly (a time that is not
  plain epoch seconds, a port written "80.0", a field with non-ASCII text, ...) makes the reader
  give up, having written nothing.

Giving up returns ``None`` and the caller runs the Python parser on the file as before. So odd
and hostile files take the slow, well-tested path, and the fast path never has to guess.
``VULNSCOPE_NATIVE_READERS=0`` turns the native readers off altogether.

tests/test_native_readers.py holds the proof: for every bundled sample and for files with
damaged lines, the native reader's Parquet rows and statistics equal the Python parser's.
"""
from __future__ import annotations

import os
import shutil

import duckdb

from ..schema import ParseStats, ThreatEvent
from ..store import utc
from ._util import clean_ip, norm_header, open_gzip_binary
from .paloalto import DENY_ACTIONS, HEADER_ALIASES
from .zeek import ESTABLISHED_STATES, REJECTED_STATES

# Plain dotted-quad IPv4 with no leading zeros: its canonical form is itself. Every other
# address text goes through clean_ip() once per distinct value (see _ip_map).
_IPV4 = (r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
         r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
_ASCII = r"^[\x20-\x7e]*$"               # printable ASCII: lower()/upper()/strip() agree with Python
_EPOCH = r"^[0-9]{1,11}(\.[0-9]{1,9})?$"  # plain epoch seconds, what Zeek writes for a time
_DIGITS = r'^[0-9]{1,15}$'            # past 15 digits int(float(x)) rounds, so the Python parser takes those
_MAX_LINE = 16 * 1024 * 1024
UNTIMED_NOTE = "some rows had no parseable timestamp (kept, untimed)"


def enabled() -> bool:
    return os.environ.get("VULNSCOPE_NATIVE_READERS", "1").strip().lower() not in ("0", "false", "no", "off")


# Errors that mean the SQL here is wrong, not the file: never hidden behind the fallback.
_OUR_FAULT = (duckdb.BinderException, duckdb.ParserException, duckdb.CatalogException)


class _GiveUp(Exception):
    """This file needs the Python parser."""


def _q(s: str) -> str:
    return s.replace("'", "''")


class _Plain:
    """The file as plain text on disk, for DuckDB to read. A ``.gz`` file is expanded into the
    working directory through the same size-capped reader the Python parsers use, so a
    decompression bomb is stopped at the same limit; when that reader refuses or fails, the
    native reader steps aside and the Python parser reports the problem as before."""

    def __init__(self, path: str, workdir: str, fid: int):
        self.path, self.temp = path, None
        if path.lower().endswith(".parquet"):
            raise _GiveUp
        if path.lower().endswith(".gz"):
            self.temp = os.path.join(workdir, f"native_{fid}.txt")
            try:
                with open_gzip_binary(path) as src, open(self.temp, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
            except Exception:                      # too large, truncated or not gzip at all
                self.close()
                raise _GiveUp from None
            self.path = self.temp

    def close(self):
        if self.temp and os.path.exists(self.temp):
            os.remove(self.temp)

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self.close()


def _day_sql(us: str) -> str:
    return (f"CASE WHEN {us} IS NULL THEN 'untimed' "
            f"ELSE strftime(make_timestamp({us}), '%Y-%m-%d') END")


def _epoch_us(col: str) -> str:
    """Epoch-seconds text -> microseconds, rounded exactly as datetime.fromtimestamp rounds
    (whole seconds plus the fraction rounded half-to-even), or NULL outside years 1-9999."""
    d = f"CAST({col} AS DOUBLE)"
    us = f"(CAST(trunc({d}) AS BIGINT) * 1000000 + CAST(round_even(({d} - trunc({d})) * 1e6, 0) AS BIGINT))"
    return f"CASE WHEN {d} <= 253402300799 THEN {us} END"


def _ip_map(con, table: str, columns: list[str]) -> None:
    """Table ``ipmap(raw, ip)``: the canonical form of every address text in ``columns`` that is
    not a plain IPv4, worked out by the same clean_ip() the Python parsers use."""
    union = " UNION ".join(f"SELECT {c} AS raw FROM {table} WHERE {c} IS NOT NULL "
                           f"AND NOT regexp_matches({c}, '{_IPV4}')" for c in columns)
    raws = [r[0] for r in con.execute(union).fetchall()]
    con.execute("CREATE OR REPLACE TEMP TABLE ipmap (raw VARCHAR, ip VARCHAR)")
    rows = [(raw, clean_ip(raw)) for raw in raws]
    if rows:
        con.executemany("INSERT INTO ipmap VALUES (?, ?)", rows)


def _ip(col: str, alias: str) -> str:
    return f"CASE WHEN regexp_matches({col}, '{_IPV4}') THEN {col} ELSE {alias}.ip END"


def _write(con, select: str, workdir: str, name: str) -> None:
    out = os.path.join(workdir, "flows_parquet")
    os.makedirs(out, exist_ok=True)
    con.execute(f"COPY ({select}) TO '{_q(os.path.join(out, name + '.parquet'))}' (FORMAT parquet)")


def _drops(con, stats: ParseStats, sql: str) -> None:
    """Record dropped rows in the order their reasons first appear in the file, as the Python
    parser's counter does."""
    for reason, n in con.execute(sql).fetchall():
        stats.dropped[reason] += int(n)


# -- Zeek conn.log (TSV) -----------------------------------------------------------------------
_ZEEK_TYPES = {      # column -> #types values the SQL rules below are exact for
    "ts": {"time", "string"}, "id.orig_h": {"addr", "string"}, "id.resp_h": {"addr", "string"},
    "id.orig_p": {"port", "count", "int", "string"}, "id.resp_p": {"port", "count", "int", "string"},
    "proto": {"enum", "string"}, "service": {"string"}, "conn_state": {"string"}, "history": {"string"},
    "orig_bytes": {"count", "int", "string"}, "resp_bytes": {"count", "int", "string"},
    "orig_ip_bytes": {"count", "int", "string"}, "resp_ip_bytes": {"count", "int", "string"},
    "orig_pkts": {"count", "int", "string"}, "resp_pkts": {"count", "int", "string"},
}
_ZEEK_DEFAULTS = {"#separator": "\\x09", "#set_separator": ",", "#empty_field": "(empty)",
                  "#unset_field": "-"}


def _zeek_header(path: str) -> list[str] | None:
    """The #fields of an ordinary Zeek conn log, or None when the file is anything else."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    except OSError:
        return None
    if not head.startswith(b"#separator \\x09\n"):
        return None
    fields = types = path_ = None
    for raw in head.split(b"\n"):
        if not raw.startswith(b"#"):
            break
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        key, _, value = line.partition(" " if line.startswith("#separator") else "\t")
        if key in _ZEEK_DEFAULTS and value != _ZEEK_DEFAULTS[key]:
            return None
        if key == "#fields":
            fields = value.split("\t")
        elif key == "#types":
            types = value.split("\t")
        elif key == "#path":
            path_ = value.strip()
    if path_ != "conn" or not fields or len(set(fields)) != len(fields):
        return None
    if types is not None and len(types) != len(fields):
        types = None                                  # the Python parser then treats all as text
    for i, f in enumerate(fields):
        if f in _ZEEK_TYPES and types is not None and types[i] not in _ZEEK_TYPES[f]:
            return None
    if not {"id.orig_h", "id.resp_h"} <= set(fields):
        return None
    if not any(f in fields for f in ("conn_state", "orig_bytes", "resp_bytes", "history", "duration")):
        return None
    return fields


def zeek_conn(path: str, name: str, fid: int, base: int, workdir: str, con, stats: ParseStats) -> int | None:
    """Write a Zeek conn log's flows to Parquet. Returns the number kept, or None to hand the
    file to the Python parser (nothing has been written or counted then)."""
    if not enabled():
        return None
    try:
        with _Plain(path, workdir, fid) as plain:
            fields = _zeek_header(plain)
            if fields is None:
                return None
            return _zeek_conn(plain, name, fid, base, workdir, con, stats, fields)
    except _GiveUp:
        return None
    except duckdb.Error as exc:           # DuckDB could not read it (bad UTF-8, a huge line, ...)
        if isinstance(exc, _OUR_FAULT):
            raise
        return None
    finally:
        con.execute("DROP TABLE IF EXISTS zl; DROP TABLE IF EXISTS zr; DROP TABLE IF EXISTS ipmap")


def _zeek_conn(path, name, fid, base, workdir, con, stats, fields) -> int:
    n = len(fields)
    # One text column per line: the split below is then the Python parser's line.split("\t").
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE zl AS
        SELECT row_number() OVER () AS ln, line FROM read_csv('{_q(path)}', delim='\\0', quote='',
            escape='', header=false, auto_detect=false, columns={{'line': 'VARCHAR'}},
            nullstr='\\x02', max_line_size={_MAX_LINE}, encoding='utf-8')
        WHERE line IS NOT NULL AND NOT regexp_matches(line, '^\\s*$')""")
    # A JSON line, a non-ASCII byte, or a later header block that differs from the first (logs
    # with different columns joined into one file): not an ordinary log.
    odd, = con.execute("""
        SELECT (SELECT count(*) FROM zl WHERE regexp_matches(line, '^\\s*\\{')
                   OR NOT regexp_matches(line, '^[\\x09\\x20-\\x7e]*$'))
             + (SELECT count(DISTINCT line) - count(DISTINCT regexp_extract(line, '^#[a-z_]+'))
                FROM zl WHERE regexp_matches(line, '^#(separator|set_separator|empty_field|unset_field|path|fields|types)'))
        """).fetchone()
    if odd:
        raise _GiveUp
    idx = {f: i + 1 for i, f in enumerate(fields)}

    def col(f):                         # the field as the Python parser sees it: None when unset
        if f not in idx:
            return "CAST(NULL AS VARCHAR)"
        return f"nullif(v[{idx[f]}], '-')"

    def num(f):                         # '(empty)' reads as no value for numbers, times and addresses
        return "CAST(NULL AS VARCHAR)" if f not in idx else f"nullif(nullif(v[{idx[f]}], '-'), '(empty)')"

    b_out = "orig_bytes" if "orig_bytes" in idx else "orig_ip_bytes"
    b_in = "resp_bytes" if "resp_bytes" in idx else "resp_ip_bytes"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE zr AS
        SELECT ln, len(v) = {n} AS ok, {num('ts')} AS ts, {num('id.orig_h')} AS src, {num('id.resp_h')} AS dst,
               {num('id.orig_p')} AS sport, {num('id.resp_p')} AS dport, {col('proto')} AS proto,
               {col('conn_state')} AS state, {col('history')} AS history, {col('service')} AS service,
               {num(b_out)} AS b_out, {num(b_in)} AS b_in, {num('orig_pkts')} AS p_out, {num('resp_pkts')} AS p_in
        FROM (SELECT ln, string_split(line, chr(9)) AS v FROM zl WHERE line[1] <> '#')""")
    # Values the rules below are not exact for send the whole file to the Python parser.
    digits = " OR ".join(f"({c} IS NOT NULL AND NOT regexp_matches({c}, '{_DIGITS}'))"
                         for c in ("sport", "dport", "b_out", "b_in", "p_out", "p_in"))
    odd, = con.execute(f"""
        SELECT count(*) FROM zr WHERE ok AND (
            (ts IS NOT NULL AND NOT regexp_matches(ts, '{_EPOCH}')) OR {digits}
            OR length(coalesce(src, '')) > 64 OR length(coalesce(dst, '')) > 64)""").fetchone()
    if odd:
        raise _GiveUp
    _ip_map(con, "(SELECT * FROM zr WHERE ok)", ["src", "dst"])
    est = ", ".join(f"'{s}'" for s in sorted(ESTABLISHED_STATES))
    rej = ", ".join(f"'{s}'" for s in sorted(REJECTED_STATES))
    us = _epoch_us("ts")
    select = f"""
        WITH r AS (
            SELECT zr.ln, {_ip('src', 'ms')} AS src_ip, {_ip('dst', 'md')} AS dst_ip, {us} AS ts_us,
                   CASE WHEN CAST(sport AS BIGINT) <= 65535 THEN CAST(sport AS INTEGER) END AS src_port,
                   CASE WHEN CAST(dport AS BIGINT) <= 65535 THEN CAST(dport AS INTEGER) END AS dst_port,
                   CASE lower(trim(coalesce(nullif(proto, '(empty)'), '')))
                        WHEN '6' THEN 'tcp' WHEN '17' THEN 'udp' WHEN '1' THEN 'icmp' WHEN '58' THEN 'icmp'
                        WHEN '' THEN 'other'
                        ELSE CASE WHEN starts_with(lower(trim(proto)), 'icmp') THEN 'icmp' ELSE lower(trim(proto)) END
                   END AS proto,
                   upper(coalesce(nullif(state, '(empty)'), '')) AS state,
                   replace(coalesce(nullif(history, '(empty)'), ''), '^', '') AS hist,
                   coalesce(CAST(b_out AS BIGINT), 0) AS bytes_out, coalesce(CAST(b_in AS BIGINT), 0) AS bytes_in,
                   coalesce(CAST(p_out AS BIGINT), 0) AS p_out, coalesce(CAST(p_in AS BIGINT), 0) AS p_in,
                   coalesce(nullif(service, '(empty)'), '') AS app
            FROM zr LEFT JOIN ipmap ms ON ms.raw = zr.src LEFT JOIN ipmap md ON md.raw = zr.dst
            WHERE zr.ok)
        SELECT {base} + row_number() OVER (ORDER BY ln) - 1 AS ord, ts_us, src_ip, dst_ip, src_port, dst_port,
               proto, CASE WHEN state IN ({rej}) THEN 'reject' ELSE 'allow' END AS action,
               (state IN ({est}) OR (bytes_out > 0 AND bytes_in > 0)
                OR CASE WHEN proto = 'tcp'
                        THEN state IN ('OTH', 'SH', 'SHR') AND regexp_matches(hist, '[AD]') AND regexp_matches(hist, '[ad]')
                        ELSE p_out > 0 AND p_in > 0 END) AS established,
               bytes_out, bytes_in, app, '' AS src_zone, '' AS dst_zone, '{_q(name)}' AS source,
               'zeek' AS sensor, {fid} AS fid, {_day_sql('ts_us')} AS day
        FROM r WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL ORDER BY ln"""
    # proto is compared with tcp/udp only after the mapping above; anything else stays as written
    # (the Python parser keeps unknown protocol names too).
    _write(con, select, workdir, f"f{fid}_native")
    out = os.path.join(workdir, "flows_parquet", f"f{fid}_native.parquet")
    kept, untimed = con.execute(
        f"SELECT count(*), count(*) FILTER (ts_us IS NULL) FROM read_parquet('{_q(out)}')").fetchone()
    stats.read += con.execute("SELECT count(*) FROM zr").fetchone()[0]
    _drops(con, stats, f"""
        SELECT reason, count(*) FROM (
            SELECT zr.ln, CASE WHEN NOT ok THEN 'column count mismatch' ELSE 'missing or invalid IP' END AS reason
            FROM zr LEFT JOIN ipmap ms ON ms.raw = zr.src LEFT JOIN ipmap md ON md.raw = zr.dst
            WHERE NOT ok OR {_ip('src', 'ms')} IS NULL OR {_ip('dst', 'md')} IS NULL)
        GROUP BY reason ORDER BY min(ln)""")
    if untimed:
        stats.note(UNTIMED_NOTE)
    if not kept:
        os.remove(out)
    return int(kept)


# -- Palo Alto CSV export (with a header row) ---------------------------------------------------
_PA_TIME = r"^[0-9]{4}[/-][0-9]{2}[/-][0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$"


def _pa_header(path: str) -> list[str] | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    except OSError:
        return None
    first, nl, _ = head.partition(b"\n")
    if not nl or first.startswith(b"\xef\xbb\xbf") or b'"' in first:
        return None
    try:
        line = first.decode("ascii").rstrip("\r")
    except UnicodeDecodeError:
        return None
    low = line.lower()
    if "source address" not in low and "destination port" not in low:
        return None
    header = [norm_header(h) for h in line.split(",")]
    return header if all(header) and len(set(header)) == len(header) else None


def paloalto(path: str, name: str, fid: int, base: int, workdir: str, con, stats: ParseStats):
    """Write a Palo Alto CSV export's TRAFFIC rows to Parquet and return (kept, THREAT rows as
    ThreatEvents), or None to hand the file to the Python parser."""
    if not enabled():
        return None
    notes = list(stats.notes)
    try:
        with _Plain(path, workdir, fid) as plain:
            header = _pa_header(plain)
            if header is None:
                return None
            return _paloalto(plain, name, fid, base, workdir, con, stats, header)
    except _GiveUp:
        stats.notes[:] = notes
        return None
    except duckdb.Error as exc:
        if isinstance(exc, _OUR_FAULT):
            raise
        stats.notes[:] = notes
        return None
    finally:
        con.execute("DROP TABLE IF EXISTS pr; DROP TABLE IF EXISTS ipmap")


def _paloalto(path, name, fid, base, workdir, con, stats, header):
    idx = {}
    for key, aliases in HEADER_ALIASES.items():
        for a in aliases:
            if a in header:
                idx[key] = header.index(a)
                break
    if "src_ip" not in idx or "dst_ip" not in idx:
        raise _GiveUp
    ts_cols = [header.index(a) for a in HEADER_ALIASES["ts"] if a in header]
    cols = "{" + ", ".join(f"'c{i}': 'VARCHAR'" for i in range(len(header))) + "}"
    # strict_mode: a row the csv module and DuckDB could read differently (stray quotes, too many
    # cells) is an error here, which sends the file to the Python parser. Short rows are padded
    # with NULL, which is the Python parser's "no such cell".
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pr AS
        SELECT row_number() OVER () AS ln, * FROM read_csv('{_q(path)}', delim=',', quote='"', escape='"',
            header=false, skip=1, auto_detect=false, columns={cols}, nullstr='\\x02', null_padding=true,
            strict_mode=true, max_line_size={_MAX_LINE}, encoding='utf-8')""")
    every = " || ".join(f"coalesce(c{i}, '')" for i in range(len(header)))
    odd, = con.execute(f"SELECT count(*) FROM pr WHERE NOT regexp_matches({every}, '{_ASCII}')").fetchone()
    if odd:
        raise _GiveUp
    con.execute(f"DELETE FROM pr WHERE trim({every}) = ''")           # blank rows are not counted

    def c(key):
        return f"c{idx[key]}" if key in idx else "CAST(NULL AS VARCHAR)"

    ts_text = "coalesce(" + ", ".join([f"nullif(trim(c{i}), '')" for i in ts_cols] + ["NULL"]) + ")"
    kind = f"upper(trim(coalesce(nullif({c('type')}, ''), 'TRAFFIC')))"
    nums = [c(k) for k in ("src_port", "dst_port", "bytes_sent", "bytes_received")]
    digits = " OR ".join(f"(trim(coalesce({n}, '')) <> '' AND NOT regexp_matches(trim({n}), '{_DIGITS}'))"
                         for n in nums)
    odd, = con.execute(f"""
        SELECT count(*) FROM pr WHERE ({ts_text} IS NOT NULL AND (NOT regexp_matches({ts_text}, '{_PA_TIME}')
                                                                  OR starts_with({ts_text}, '0000')))
            OR {digits} OR length(coalesce({c('src_ip')}, '')) > 64 OR length(coalesce({c('dst_ip')}, '')) > 64""").fetchone()
    if odd:
        raise _GiveUp
    stats.note("firewall timestamps are assumed to be UTC")
    src_raw, dst_raw = f"trim({c('src_ip')})", f"trim({c('dst_ip')})"
    con.execute(f"ALTER TABLE pr ADD COLUMN src VARCHAR; ALTER TABLE pr ADD COLUMN dst VARCHAR; "
                f"UPDATE pr SET src = nullif({src_raw}, ''), dst = nullif({dst_raw}, '')")
    _ip_map(con, "pr", ["src", "dst"])
    ts_us = (f"epoch_us(coalesce(try_strptime({ts_text}, '%Y/%m/%d %H:%M:%S'), "
             f"try_strptime({ts_text}, '%Y-%m-%d %H:%M:%S')))")
    deny = " OR ".join(f"starts_with(lower(trim(coalesce({c('action')}, ''))), '{d}')" for d in DENY_ACTIONS)
    proto = f"lower(trim(coalesce({c('proto')}, '')))"
    b_in = f"coalesce(CAST(nullif(trim({c('bytes_received')}), '') AS BIGINT), 0)"
    port = lambda k: (f"CASE WHEN CAST(nullif(trim({c(k)}), '') AS BIGINT) <= 65535 "
                      f"THEN CAST(nullif(trim({c(k)}), '') AS INTEGER) END")
    select = f"""
        WITH r AS (
            SELECT pr.ln, {_ip('src', 'ms')} AS src_ip, {_ip('dst', 'md')} AS dst_ip, {ts_us} AS ts_us,
                   {port('src_port')} AS src_port, {port('dst_port')} AS dst_port,
                   CASE {proto} WHEN '6' THEN 'tcp' WHEN '17' THEN 'udp' WHEN '1' THEN 'icmp' WHEN '58' THEN 'icmp'
                        WHEN '' THEN 'other'
                        ELSE CASE WHEN starts_with({proto}, 'icmp') THEN 'icmp' ELSE {proto} END END AS proto,
                   ({deny}) AS denied, {c('bytes_received')} IS NULL AS no_in,
                   coalesce(CAST(nullif(trim({c('bytes_sent')}), '') AS BIGINT), 0) AS bytes_out, {b_in} AS bytes_in,
                   trim(coalesce({c('app')}, '')) AS app, lower(trim(coalesce({c('src_zone')}, ''))) AS src_zone,
                   lower(trim(coalesce({c('dst_zone')}, ''))) AS dst_zone
            FROM pr LEFT JOIN ipmap ms ON ms.raw = pr.src LEFT JOIN ipmap md ON md.raw = pr.dst
            WHERE {kind} = 'TRAFFIC')
        SELECT {base} + row_number() OVER (ORDER BY ln) - 1 AS ord, ts_us, src_ip, dst_ip, src_port, dst_port, proto,
               CASE WHEN denied THEN 'deny' ELSE 'allow' END AS action,
               (NOT denied AND (bytes_in > 0 OR no_in)) AS established, bytes_out, bytes_in, app, src_zone,
               dst_zone, '{_q(name)}' AS source, 'paloalto' AS sensor, {fid} AS fid, {_day_sql('ts_us')} AS day
        FROM r WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL ORDER BY ln"""
    _write(con, select, workdir, f"f{fid}_native")
    out = os.path.join(workdir, "flows_parquet", f"f{fid}_native.parquet")
    kept, untimed = con.execute(
        f"SELECT count(*), count(*) FILTER (ts_us IS NULL) FROM read_parquet('{_q(out)}')").fetchone()
    if not kept:
        os.remove(out)
    threats = []
    for ts, src, dst, dport, tname, sev, action in con.execute(f"""
            SELECT make_timestamp({ts_us}), {_ip('src', 'ms')}, {_ip('dst', 'md')}, {port('dst_port')},
                   trim(coalesce(nullif({c('threat')}, ''), 'unnamed threat')),
                   lower(trim(coalesce({c('severity')}, ''))),
                   lower(trim(coalesce(nullif({c('action')}, ''), 'alert')))
            FROM pr LEFT JOIN ipmap ms ON ms.raw = pr.src LEFT JOIN ipmap md ON md.raw = pr.dst
            WHERE {kind} = 'THREAT' AND {_ip('src', 'ms')} IS NOT NULL AND {_ip('dst', 'md')} IS NOT NULL
            ORDER BY pr.ln""").fetchall():
        threats.append(ThreatEvent(ts=utc(ts), src_ip=src, dst_ip=dst, dst_port=dport, name=tname,
                                   severity=sev, action=action, source=name))
    stats.read += con.execute("SELECT count(*) FROM pr").fetchone()[0]
    _drops(con, stats, f"""
        SELECT reason, count(*) FROM (
            SELECT pr.ln, CASE WHEN {kind} NOT IN ('TRAFFIC', 'THREAT') THEN {kind} || ' log type not used'
                               ELSE 'missing or invalid IP' END AS reason
            FROM pr LEFT JOIN ipmap ms ON ms.raw = pr.src LEFT JOIN ipmap md ON md.raw = pr.dst
            WHERE {kind} NOT IN ('TRAFFIC', 'THREAT') OR {_ip('src', 'ms')} IS NULL OR {_ip('dst', 'md')} IS NULL)
        GROUP BY reason ORDER BY min(ln)""")
    if untimed:
        stats.note(UNTIMED_NOTE)
    return int(kept), threats

