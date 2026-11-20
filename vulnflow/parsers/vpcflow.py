"""AWS VPC Flow Logs: plain text (with or without a header line), CloudWatch exports, and Parquet.

AWS writes one record per direction, per network interface, per capture window (1 or 10 minutes),
so a single TCP session normally shows up as at least two records: the request (client -> server)
and the reply (server -> client), and one more pair for every window the session stays open. Read
as flat rows (the generic CSV parser did that) the reply looks like the server opening a session to
the client's ephemeral port, the client always seems to receive 0 bytes, and every ACCEPT looks like
a completed session. This parser joins the records of one session back together:

* records with the same two endpoints and protocol are one session while it keeps logging (an idle
  gap of more than ``IDLE_SECONDS`` starts a new one);
* the client is the side whose record carries SYN without SYN-ACK (``tcp-flags``, versions 3+),
  else the side talking to the well-known / lower port, else the side logged first;
* bytes the client sent become ``bytes_out``, the reply's become ``bytes_in``. When both endpoints'
  interfaces log the same session, each direction is counted once (the larger figure), not twice;
* a session is established when a reply was logged and accepted: for TCP, a SYN-ACK
  (``tcp-flags``) or, without flags, more than one reply packet; a reply that only carries RST is
  the host refusing ("reject", like Zeek's REJ). When no record in the file has a reply at all (an
  export with only one direction), ACCEPT is taken as established, except a TCP client that sent a
  single packet (a SYN that got no further, as in a port scan).

``pkt-srcaddr``/``pkt-dstaddr`` (custom formats) are preferred over ``srcaddr``/``dstaddr`` when
present, so traffic through a NAT gateway or from EKS pods is tied to the real endpoints.

Inputs recognised:

* files delivered to S3 or written by hand: a header line (``version account-id ... log-status``,
  any field order, ``_`` or ``-``) followed by space-separated records, ``.gz`` included;
* the default version 2 format with no header line (14 fields), e.g. records copied out of
  CloudWatch, or a CloudWatch export to S3 where each line starts with an ISO timestamp;
* CSV with a ``message`` / ``@message`` column (CloudWatch console or Logs Insights download) and
  NDJSON with a ``message`` field;
* comma-separated query results with the field names as columns (Athena);
* Parquet (the S3 "Parquet" delivery option, or a local copy of it), read with DuckDB. Only local
  files are read: nothing here fetches from S3.

A CloudWatch record in a custom format cannot be read without its header (the field order is not in
the record); those lines are dropped and counted.
"""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone

from ..errors import UserError
from ..schema import Flow, ParseStats
from ._util import clean_ip, clean_port, clean_proto, count, open_text, to_int

DEFAULT_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
                  "protocol", "packets", "bytes", "start", "end", "action", "log-status"]
ACTIONS = {"ACCEPT", "REJECT", "-"}
STATUSES = {"OK", "NODATA", "SKIPDATA"}
# Records of one session are joined while it keeps logging; this much silence starts a new session.
# Longer than the 10-minute maximum capture window, so consecutive windows always join.
IDLE_SECONDS = 15 * 60
# Open sessions held while reading (about 1 KB each, so about 250 MB at most per file being read).
# Past this the oldest are written out as they stand, so a huge or badly ordered file cannot exhaust
# memory; the report notes it. A 15-minute window this full is about 280 new sessions a second.
MAX_OPEN = 250_000
FLUSH_EVERY = 20_000
# Server ports above 1023 that are common enough to decide who the client is.
SERVICE_PORTS = {1433, 1521, 2049, 2181, 2379, 3000, 3128, 3306, 3389, 5000, 5432, 5601, 5671, 5672,
                 5900, 5985, 5986, 6379, 6443, 8000, 8080, 8081, 8088, 8443, 8888, 9000, 9042, 9090,
                 9092, 9093, 9094, 9200, 9300, 10250, 11211, 27017}
EPHEMERAL = 32768
SYN, RST, SYN_ACK = 2, 4, 16          # AWS tcp-flags: SYN-ACK is logged as 18 (SYN + bit 16)

_ISO_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+")
_DEFAULT_IN_TEXT = re.compile(r"(?:^|[\s\"'])2 (?:\d{12}|unknown) (?:eni-[0-9a-z]+|-) \S+ \S+ \S+ \S+ \S+ \S+ \S+ "
                              r"\S+ \S+ (?:ACCEPT|REJECT|-) (?:OK|NODATA|SKIPDATA)\b")
PARQUET_MAGIC = b"PAR1"


def _csv_row(line: str) -> list[str]:
    """One CSV line split into cells. NUL bytes (damaged files) are dropped first: Python 3.10's csv
    module refuses them, and detection must never fail on a file that is not a flow log."""
    try:
        return next(csv.reader([line.replace("\x00", "")]), [])
    except csv.Error:
        return []


def _field(name) -> str:
    s = str(name).strip().strip('"').strip()
    if s.startswith("${") and s.endswith("}"):        # the format string as typed in the AWS console
        s = s[2:-1]
    return s.strip().lower().replace("_", "-")


def header_fields(line: str) -> list[str] | None:
    """The field names when ``line`` is a VPC flow log header (space or comma separated)."""
    if "srcaddr" not in line.lower():
        return None
    cols = _csv_row(line) if "," in line else line.split()
    names = [_field(c) for c in cols]
    has = set(names)
    if {"srcaddr", "dstaddr"} <= has and has & {"action", "log-status", "interface-id", "start", "version"}:
        return names
    return None


def _strip_iso(line: str) -> str:
    return _ISO_PREFIX.sub("", line, count=1)


def default_record(line: str) -> dict | None:
    """A record in the default version 2 format (no header needed), else None."""
    toks = _strip_iso(line.strip()).split()
    if len(toks) != 14 or toks[0] != "2" or toks[12] not in ACTIONS or toks[13] not in STATUSES:
        return None
    return dict(zip(DEFAULT_FIELDS, toks))


def looks_like(head: str, first: str) -> bool:
    """True for VPC flow log text: a header line, default-format records, or a CloudWatch export."""
    if header_fields(first):
        return True
    if default_record(first):
        return True
    s = first.lstrip()
    if s.startswith("{"):
        try:
            rec = json.loads(s)
        except ValueError:
            return False
        if isinstance(rec, dict):
            msg = rec.get("message", rec.get("@message"))
            return isinstance(msg, str) and default_record(msg) is not None
        return False
    cols = {c.strip().strip('"').lower() for c in _csv_row(first)}
    return bool(cols & {"message", "@message"}) and bool(_DEFAULT_IN_TEXT.search(head))


def is_parquet(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == PARQUET_MAGIC
    except OSError:
        return False


def _duckdb():
    from .. import db
    # A flow log never needs an extension: Parquet is built in. db.connect never fetches one.
    con = db.connect()
    con.execute("SET threads = 1")
    return con


def parquet_is_vpc(path: str) -> bool:
    try:
        con = _duckdb()
        try:
            names = {_field(r[0]) for r in con.execute("SELECT name FROM parquet_schema(?)", [path]).fetchall()}
        finally:
            con.close()
    except Exception:        # damaged or not really Parquet: let the caller fall back
        return False
    return {"srcaddr", "dstaddr"} <= names


# -- reading records -------------------------------------------------------------------------

def _parquet_rows(path: str, stats: ParseStats):
    import duckdb
    con = _duckdb()
    try:
        cur = con.execute("SELECT * FROM read_parquet(?)", [path])
        names = [_field(d[0]) for d in cur.description]
        while True:
            batch = cur.fetchmany(10_000)
            if not batch:
                break
            for row in batch:
                yield dict(zip(names, row))
    except duckdb.Error as exc:          # damaged file: records read before this are kept
        raise UserError(f"not a readable Parquet file ({str(exc).splitlines()[0]})") from None
    finally:
        con.close()


def _text_rows(path: str, stats: ParseStats):
    """Yield one dict per record (field name -> value), or None for a line that is not one."""
    fields: list[str] | None = None
    comma = False
    msg_col: int | None = None
    first = True
    with open_text(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            if first:
                first = False
                cols = [c.strip().lower() for c in _csv_row(line)]
                for name in ("message", "@message"):
                    if name in cols and "srcaddr" not in cols:
                        msg_col = cols.index(name)
                if msg_col is not None:
                    continue                         # CloudWatch CSV header
            if msg_col is not None:
                vals = _csv_row(line)
                line = vals[msg_col].strip() if msg_col < len(vals) else ""
            elif line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    yield None
                    continue
                if not isinstance(obj, dict):
                    yield None
                    continue
                if "srcaddr" in obj or "srcAddr" in obj:     # records already split into fields
                    yield {_field(k): v for k, v in obj.items()}
                    continue
                line = str(obj.get("message", obj.get("@message", ""))).strip()
            names = header_fields(line)
            if names:                     # a header, also mid-file when delivered files were concatenated
                fields, comma = names, "," in line
                continue
            if fields:
                vals = _csv_row(line) if comma else _strip_iso(line).split()
                if len(vals) == len(fields):
                    yield dict(zip(fields, vals))
                    continue
            rec = default_record(line)
            yield rec


def _epoch(value):
    if isinstance(value, datetime):
        return value.timestamp() if value.tzinfo else value.replace(tzinfo=timezone.utc).timestamp()
    n = to_int(value)
    if n is None:
        return None
    if n > 10 ** 12:              # milliseconds
        n //= 1000
    return n if 0 < n < 253402300800 else None


# -- joining the two directions of a session ------------------------------------------------

class _Dir:
    """What one direction of a session (one endpoint -> the other) logged, over all its records."""
    __slots__ = ("eni", "flags", "accept", "reject", "start", "order")

    def __init__(self, order):
        # interface -> [bytes, packets]. Kept per interface because, when both endpoints are in the
        # VPC, each one's interface logs the same packets: summing them would count traffic twice.
        self.eni: dict = {}
        self.flags = 0
        self.accept = self.reject = False
        self.start = None
        self.order = order            # record number of the first record, for "logged first"


class _Session:
    """One session being joined: its two directions (index 0 = from key[0] to key[1])."""
    __slots__ = ("dirs", "last", "proto")

    def __init__(self, proto):
        self.dirs: list = [None, None]
        self.last = None
        self.proto = proto


class _Joiner:
    """Joins records into sessions while streaming; ``add`` and ``finish`` yield finished Flows."""

    def __init__(self, stats: ParseStats):
        self.stats = stats
        self.open: dict = {}
        self.seen = 0
        self.newest = None
        # Sessions with records in both directions so far. Non-zero means this file logs replies, so
        # a session without one really got no answer. A session written out before the first reply
        # in the file is judged by the one-direction rule instead (rare: needs a 15-minute lead).
        self.replies = 0
        self.capped = False

    def add(self, src, sport, dst, dport, proto, nbytes, packets, start, end, action, flags, eni):
        a = (src, -1 if sport is None else sport)        # -1: no port (keeps the key sortable)
        b = (dst, -1 if dport is None else dport)
        # The key is the same for a record and its reply (endpoints in sorted order); d says which
        # way this record went. Who the client is gets decided only at write-out, once both are in.
        key = (a, b, proto) if a <= b else (b, a, proto)
        d = 0 if key[0] == a else 1
        sess = self.open.get(key)
        stamp = end if end is not None else start
        # The same endpoints and ports after a long silence are a new session (e.g. a reused port).
        if sess is not None and stamp is not None and sess.last is not None and stamp - sess.last > IDLE_SECONDS:
            yield self._flow(key, self.open.pop(key))
            sess = None
        if sess is None:
            sess = self.open[key] = _Session(proto)
        side = sess.dirs[d]
        if side is None:
            side = sess.dirs[d] = _Dir(self.seen)
            if sess.dirs[1 - d] is not None:
                self.replies += 1
        tally = side.eni.setdefault(eni, [0, 0])
        tally[0] += nbytes
        tally[1] += packets
        side.flags |= flags or 0
        if action == "ACCEPT":
            side.accept = True
        elif action == "REJECT":
            side.reject = True
        if start is not None and (side.start is None or start < side.start):
            side.start = start
        if stamp is not None and (sess.last is None or stamp > sess.last):
            sess.last = stamp
        if stamp is not None and (self.newest is None or stamp > self.newest):
            self.newest = stamp
        self.seen += 1
        if self.seen % FLUSH_EVERY == 0:
            yield from self._flush_idle()

    def _flush_idle(self):
        if self.newest is not None:
            cutoff = self.newest - IDLE_SECONDS
            done = [k for k, s in self.open.items() if s.last is not None and s.last < cutoff]
            for k in done:
                yield self._flow(k, self.open.pop(k))
        if len(self.open) > MAX_OPEN:
            if not self.capped:
                self.capped = True
                self.stats.note("too many sessions open at once (busy or out-of-order file): some "
                                "request/reply records could not be joined and count as separate sessions")
            for k in list(self.open)[: len(self.open) - MAX_OPEN // 2]:
                yield self._flow(k, self.open.pop(k))

    def finish(self):
        for k in list(self.open):
            yield self._flow(k, self.open.pop(k))
        if self.replies:
            self.stats.note(f"{self.replies} session(s) had request and reply logged separately; "
                            "each was joined into one session")

    def _client(self, key, sess) -> int:
        """0 when key[0] is the client, 1 when key[1] is."""
        for d in (0, 1):
            side = sess.dirs[d]
            if side is not None and sess.proto == "tcp":
                if side.flags & SYN and not side.flags & SYN_ACK:
                    return d
                if side.flags & SYN_ACK:
                    return 1 - d
        p0, p1 = key[0][1], key[1][1]
        if p0 >= 0 and p1 >= 0 and p0 != p1:
            # the client is the side that is not talking from the service port
            if (p1 < 1024) != (p0 < 1024):
                return 0 if p1 < 1024 else 1
            if (p1 in SERVICE_PORTS) != (p0 in SERVICE_PORTS):
                return 0 if p1 in SERVICE_PORTS else 1
            if (p0 >= EPHEMERAL) != (p1 >= EPHEMERAL):
                return 0 if p0 >= EPHEMERAL else 1
        sides = [s for s in sess.dirs if s is not None]
        firstd = min(sides, key=lambda s: s.order)
        return sess.dirs.index(firstd)

    def _flow(self, key, sess) -> Flow:
        c = self._client(key, sess)
        out, back = sess.dirs[c], sess.dirs[1 - c]
        (src, sport), (dst, dport) = key[c], key[1 - c]
        sport, dport = (None if sport < 0 else sport), (None if dport < 0 else dport)
        req = out if out is not None else back
        bytes_out = max((t[0] for t in out.eni.values()), default=0) if out else 0
        bytes_in = max((t[0] for t in back.eni.values()), default=0) if back else 0
        # The client's records decide allow/deny: a security group or NACL acts on the request.
        if out is not None:
            action = "allow" if out.accept else "deny" if out.reject else "allow"
        else:                                     # only the reply was logged
            action = "allow" if back.accept else "deny" if back.reject else "allow"
        established = False
        if action == "allow":
            if back is None or out is None:
                if self.replies:
                    established = False           # replies are logged in this file; none came
                else:                             # an export with only one direction
                    # A TCP client that completed the handshake sent at least two packets (SYN, then
                    # ACK); one packet is a probe that got no further (a port scan's SYN).
                    packets = max((t[1] for t in req.eni.values()), default=0)
                    established = not (sess.proto == "tcp" and (
                        (req.flags and not req.flags & ~(SYN | RST)) or 0 < packets < 2))
            elif not back.accept:
                established = False               # the reply was blocked (e.g. an outbound NACL)
            elif sess.proto == "tcp":
                if back.flags:
                    # SYN-ACK in the reply: the handshake happened. A client with flags but no SYN
                    # is a session already open when logging began, so it was established too.
                    established = bool(back.flags & SYN_ACK) or (bool(out.flags) and not out.flags & SYN)
                    if not established and back.flags & RST and not back.flags & SYN_ACK:
                        action = "reject"         # the host answered with a reset: refused
                else:                             # no flags (version 2): SYN-ACK plus more, not a lone RST
                    established = max((t[1] for t in back.eni.values()), default=0) > 1
            else:                                 # UDP/ICMP: anything that came back is an answer
                established = bytes_in > 0
        start = req.start if out is None else out.start
        if start is None:
            start = back.start if back is not None else None
        ts = datetime.fromtimestamp(start, tz=timezone.utc) if start is not None else None
        return Flow(ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, proto=sess.proto,
                    action=action, established=established, bytes_out=bytes_out, bytes_in=bytes_in)


def _addr(rec, pkt, plain):
    """(address, whether the pkt-* field replaced the plain one). srcaddr/dstaddr name the
    interface's side of the packet: a NAT gateway's own address, or an EKS node instead of its pod.
    pkt-srcaddr/pkt-dstaddr (custom formats) hold the packet's real source and destination."""
    v = rec.get(pkt)
    ip = clean_ip(v) if v not in (None, "-") else None
    return ip or clean_ip(rec.get(plain)), ip is not None and ip != clean_ip(rec.get(plain))


def parse(path: str, stats: ParseStats):
    rows = _parquet_rows(path, stats) if is_parquet(path) else _text_rows(path, stats)
    join = _Joiner(stats)
    untimed = pkt_used = False
    for rec in rows:
        stats.read += 1
        if rec is None:
            stats.drop("not a VPC flow log record (a custom format needs its header line)")
            continue
        status = str(rec.get("log-status") or "").upper()
        if status == "NODATA":
            stats.drop("no traffic in the capture window (NODATA)")
            continue
        if status == "SKIPDATA":
            stats.drop("records AWS skipped during the capture window (SKIPDATA)")
            stats.note("AWS skipped some records (SKIPDATA): traffic in those windows is missing")
            continue
        src, s_pkt = _addr(rec, "pkt-srcaddr", "srcaddr")
        dst, d_pkt = _addr(rec, "pkt-dstaddr", "dstaddr")
        if not src or not dst:
            stats.drop("missing or invalid IP")
            continue
        pkt_used = pkt_used or s_pkt or d_pkt
        proto = clean_proto(rec.get("protocol"))
        start, end = _epoch(rec.get("start")), _epoch(rec.get("end"))
        untimed = untimed or start is None
        action = str(rec.get("action") or "").upper()
        yield from join.add(src, clean_port(rec.get("srcport")), dst, clean_port(rec.get("dstport")), proto,
                            count(rec.get("bytes")), count(rec.get("packets")), start, end, action,
                            to_int(rec.get("tcp-flags"), 0) or 0, str(rec.get("interface-id") or ""))
    yield from join.finish()
    if untimed:
        stats.note("some records had no start time (kept, untimed)")
    if pkt_used:
        stats.note("pkt-srcaddr/pkt-dstaddr used where they differ from srcaddr/dstaddr "
                   "(NAT gateway or EKS pod traffic tied to its real endpoints)")
