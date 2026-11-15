"""Fuzz tests for every input reader: Zeek (TSV, JSON, Zui/Brim array, .gz), Filebeat CSV/NDJSON,
Palo Alto CSV, Nessus (.nessus XML and CSV), Suricata EVE, generic flow CSV, format detection and
the PCAP hand-off.

Analysts load data from networks that may be compromised, so a reader must survive anything a
file can hold. For thousands of generated files (valid records with hostile values, random byte
damage to real-looking files, truncated gzip, XML bombs) each test checks that:

  * the reader either finishes or stops with one of the errors that mean "this file is broken"
    (UserError, bad XML, bad gzip, a CSV error); any other exception is a bug;
  * it finishes within a time limit (no hangs, no runaway regular expressions);
  * every record it yields is well formed: canonical IP addresses, ports 0-65535 or None,
    timezone-aware times, known protocols and actions, non-negative byte counts.

Uses Hypothesis (requirements-dev.txt); the tests skip when it is not installed. CI runs the
short profile on every pull request. For a longer search:

    FUZZ_PROFILE=long python -m unittest tests.test_fuzz_parsers      # ~20x more inputs per test

A failure prints the smallest input that triggers it and a @reproduce_failure line to replay it.
"""
from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import json
import math
import os
import shutil
import signal
import tempfile
import threading
import unittest
import zlib
from contextlib import contextmanager
from datetime import datetime
from xml.etree.ElementTree import ParseError

try:
    from hypothesis import HealthCheck, assume, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - the tests below skip
    st = None

from vulnflow.errors import UserError
from vulnflow.parsers import FORMATS, detect, filebeat, generic, nessus, paloalto, suricata, zeek
from vulnflow.schema import Finding, Flow, ParseStats, ThreatEvent, ZeekEvent

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")

# Errors that mean "the file itself is broken". parse_file() turns them into a note on the input
# table and keeps the records read before the error; anything else escaping a reader is a bug.
BROKEN_FILE = (UserError, ParseError, EOFError, gzip.BadGzipFile, zlib.error, csv.Error,
               UnicodeDecodeError, json.JSONDecodeError)
TIME_LIMIT = 20          # seconds for one file; a reader that takes longer is treated as hung

if st is not None:
    PROFILE = os.environ.get("FUZZ_PROFILE", "ci")
    common = dict(deadline=None, derandomize=PROFILE == "ci", print_blob=True,
                  suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large,
                                         HealthCheck.filter_too_much])
    settings.register_profile("ci", max_examples=60, **common)
    settings.register_profile("long", max_examples=1500, **common)
    settings.load_profile(PROFILE)


@contextmanager
def time_limit(seconds=TIME_LIMIT):
    """Fail instead of hanging. Uses SIGALRM where available (Linux, macOS, main thread)."""
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def hung(*_):
        raise TimeoutError(f"reader did not finish within {seconds} s (possible hang)")
    old = signal.signal(signal.SIGALRM, hung)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# ---------------------------------------------------------------- record checks

ACTIONS = {"allow", "deny", "reject"}


def _ip_ok(ip):
    if ip is None:
        return True
    return isinstance(ip, str) and str(ipaddress.ip_address(ip)) == ip


def _port_ok(p):
    return p is None or (isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535)


def _ts_ok(ts):
    return ts is None or (isinstance(ts, datetime) and ts.tzinfo is not None)


def check_record(tc, r):
    """Each record a reader yields must be safe for the rest of the pipeline to take as is."""
    if isinstance(r, Flow):
        tc.assertTrue(_ip_ok(r.src_ip) and r.src_ip, f"bad src_ip {r.src_ip!r}")
        tc.assertTrue(_ip_ok(r.dst_ip) and r.dst_ip, f"bad dst_ip {r.dst_ip!r}")
        tc.assertTrue(_port_ok(r.src_port), f"bad src_port {r.src_port!r}")
        tc.assertTrue(_port_ok(r.dst_port), f"bad dst_port {r.dst_port!r}")
        # tcp, udp, icmp, or whatever else the sensor named (sctp, gre, ...): lower case, no spaces
        tc.assertTrue(isinstance(r.proto, str) and r.proto and r.proto == r.proto.strip().lower(),
                      f"bad proto {r.proto!r}")
        tc.assertIn(r.action, ACTIONS)
        tc.assertIsInstance(r.established, bool)
        for n in (r.bytes_out, r.bytes_in):
            tc.assertIsInstance(n, int)
            tc.assertGreaterEqual(n, 0)
            tc.assertLess(n, 2 ** 63, "byte count does not fit a 64-bit column")
        tc.assertTrue(_ts_ok(r.ts), f"bad ts {r.ts!r}")
        for s in (r.app, r.src_zone, r.dst_zone):
            tc.assertIsInstance(s, str)
    elif isinstance(r, ThreatEvent):
        tc.assertTrue(_ip_ok(r.src_ip), f"bad src_ip {r.src_ip!r}")
        tc.assertTrue(_ip_ok(r.dst_ip), f"bad dst_ip {r.dst_ip!r}")
        tc.assertTrue(_port_ok(r.dst_port), f"bad dst_port {r.dst_port!r}")
        tc.assertIsInstance(r.name, str)
        tc.assertIsInstance(r.action, str)
        tc.assertTrue(_ts_ok(r.ts), f"bad ts {r.ts!r}")
    elif isinstance(r, ZeekEvent):                          # also OTEvent
        tc.assertTrue(_ip_ok(r.src_ip) and _ip_ok(r.dst_ip))
        tc.assertIsInstance(r.stream, str)
        tc.assertIsInstance(r.fields, dict)
        tc.assertTrue(_ts_ok(r.ts), f"bad ts {r.ts!r}")
        json.dumps(r.fields, default=str)                   # normalized copies write these as JSON
    elif isinstance(r, Finding):
        tc.assertTrue(_ip_ok(r.host_ip) and r.host_ip, f"bad host_ip {r.host_ip!r}")
        tc.assertTrue(_port_ok(r.port), f"bad port {r.port!r}")
        tc.assertIsInstance(r.severity, int)
        tc.assertTrue(r.cvss is None or (isinstance(r.cvss, float) and math.isfinite(r.cvss)), f"bad cvss {r.cvss!r}")
        tc.assertTrue(_ts_ok(r.scan_start) and _ts_ok(r.scan_end))
    else:
        tc.fail(f"unexpected record type {type(r).__name__}")


class FuzzCase(unittest.TestCase):
    def setUp(self):
        if st is None:
            self.skipTest("hypothesis is not installed (pip install -r requirements-dev.txt)")
        self.tmp = tempfile.mkdtemp(prefix="vs-fuzz-")
        self.n = 0

    def tearDown(self):
        if hasattr(self, "tmp"):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, data: bytes | str, gz=False):
        self.n += 1
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogatepass")
        path = os.path.join(self.tmp, f"{self.n}_{name}" + (".gz" if gz else ""))
        with open(path, "wb") as fh:
            fh.write(gzip.compress(data, mtime=0) if gz else data)
        return path

    def run_reader(self, parse, path):
        """Run one reader to the end; return its records, or None if it stopped on a broken file."""
        stats = ParseStats(file=os.path.basename(path), fmt="fuzz")
        out = []
        with time_limit():
            try:
                for r in parse(path, stats):
                    check_record(self, r)
                    out.append(r)
            except BROKEN_FILE:
                return None
        self.assertGreaterEqual(stats.read, 0)
        return out

    def run_detected(self, path):
        """What the pipeline does: detect the format, then run that reader."""
        with time_limit():
            fmt = detect(path)
        self.assertIn(fmt, FORMATS)
        return self.run_reader(FORMATS[fmt][1], path)


# ---------------------------------------------------------------- hostile values

if st is not None:
    hostile_text = st.one_of(
        st.text(max_size=40),
        st.sampled_from(["", "-", "(empty)", "(empty)", "null", "None", "NaN", "inf", "-inf", "1e999",
                         "-1", "65536", "99999999999999999999999", "0x50", "1,000", "1.5KB", "::",
                         "::ffff:10.0.0.1", "fe80::1%eth0", "[2001:db8::1]", "10.0.0.256", "10.0.0",
                         "999.1.1.1", "\x00", "\ud800", "‮", "\t", "\n", "\r\n", "#fields", "{",
                         "[", '"', "'", "\\", "%s%n", "../../etc/passwd", "1e308", "-0",
                         "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "0000-00-00 00:00:00",
                         "2026-02-30 12:00:00", "253402300800", "-62135596801", "1.7e18"]),
    )
    hostile_json = st.recursive(
        st.one_of(st.none(), st.booleans(), st.integers(min_value=-(2 ** 70), max_value=2 ** 70),
                  st.floats(allow_nan=True, allow_infinity=True), hostile_text),
        lambda kids: st.one_of(st.lists(kids, max_size=4), st.dictionaries(st.text(max_size=8), kids, max_size=4)),
        max_leaves=8)

    def valid_ip():
        return st.one_of(st.ip_addresses(v=4).map(str), st.ip_addresses(v=6).map(str))

    def value_or_hostile(good):
        return st.one_of(good, good, hostile_json)

    def mutated(seed: bytes):
        """Random byte damage to a real-looking file: flips, cuts, insertions, duplicated lines."""
        ops = st.lists(st.tuples(st.sampled_from(["flip", "cut", "insert", "truncate", "dupline"]),
                                 st.integers(min_value=0, max_value=max(len(seed) - 1, 0)),
                                 st.binary(min_size=1, max_size=16)), max_size=6)

        def apply(edits):
            b = bytearray(seed)
            for op, pos, junk in edits:
                pos = min(pos, max(len(b) - 1, 0))
                if op == "flip" and b:
                    b[pos] ^= junk[0] or 0xFF
                elif op == "cut":
                    del b[pos:pos + len(junk) * 8]
                elif op == "insert":
                    b[pos:pos] = junk
                elif op == "truncate":
                    del b[pos:]
                elif op == "dupline":
                    end = b.find(b"\n", pos)
                    line = b[pos:end + 1] if end >= 0 else b[pos:]
                    b[pos:pos] = line * (1 + junk[0] % 4)
            return bytes(b)
        return ops.map(apply)


def head(rel, lines=40):
    """The first lines of a bundled sample file, as a seed for byte damage."""
    with open(os.path.join(SAMPLES, rel), "rb") as fh:
        return b"".join(fh.readline() for _ in range(lines))


ZEEK_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
                    "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts",
                    "local_orig", "tunnel_parents"]
ZEEK_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
              "string", "string", "count", "count", "bool", "set[string]"]
CONN_STATES = ["S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"]


# ---------------------------------------------------------------- the tests

class ZeekFuzz(FuzzCase):
    if st is not None:
        conn_rec = st.fixed_dictionaries({
            "ts": value_or_hostile(st.floats(min_value=0, max_value=4e9)),
            "uid": value_or_hostile(st.text(max_size=12)),
            "id.orig_h": value_or_hostile(valid_ip()), "id.orig_p": value_or_hostile(st.integers(0, 65535)),
            "id.resp_h": value_or_hostile(valid_ip()), "id.resp_p": value_or_hostile(st.integers(0, 65535)),
            "proto": value_or_hostile(st.sampled_from(["tcp", "udp", "icmp", "unknown_transport"])),
            "conn_state": value_or_hostile(st.sampled_from(CONN_STATES)),
            "history": value_or_hostile(st.text(alphabet="ShADadFfRrTtWwIiQq^", max_size=12)),
            "orig_bytes": value_or_hostile(st.integers(0, 2 ** 40)),
            "resp_bytes": value_or_hostile(st.integers(0, 2 ** 40)),
            "orig_pkts": value_or_hostile(st.integers(0, 2 ** 20)),
            "resp_pkts": value_or_hostile(st.integers(0, 2 ** 20)),
            "duration": value_or_hostile(st.floats(min_value=0, max_value=1e6)),
        }, optional={"_path": st.sampled_from(["conn", "notice", "dns", "modbus", "alert", "weird", "x"]),
                     "note": hostile_text, "msg": hostile_text, "src": hostile_json, "dst": hostile_json,
                     "p": hostile_json, "event_type": st.just("alert"), "alert": hostile_json,
                     "id": hostile_json, "func": hostile_json})

        @given(st.lists(conn_rec, min_size=1, max_size=12), st.sampled_from(["conn.log", "notice.log", "dns.log",
                                                                             "modbus.log", "x.log"]),
               st.booleans())
        def test_json_lines(self, recs, name, gz):
            lines = "\n".join(json.dumps(r) for r in recs) + "\n"
            path = self.write(name, lines, gz=gz)
            self.run_reader(zeek.parse, path)
            self.run_detected(path)

        @given(st.lists(st.lists(hostile_text, min_size=len(ZEEK_CONN_FIELDS), max_size=len(ZEEK_CONN_FIELDS)),
                        min_size=1, max_size=10),
               st.sampled_from(["\\x09", "\\x2c", "\\x7c", "\\xZZ", "", "\\x0a", "\\x"]),
               st.booleans(), st.booleans())
        def test_tsv_with_hostile_cells_and_headers(self, rows, sep_decl, with_types, gz):
            sep = "\t"
            hdr = [f"#separator {sep_decl}", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
                   "#path\tconn", "#fields\t" + "\t".join(ZEEK_CONN_FIELDS)]
            if with_types:
                hdr.append("#types\t" + "\t".join(ZEEK_TYPES))
            body = [sep.join(c.replace("\t", " ").replace("\n", " ").replace("\r", " ") for c in r) for r in rows]
            path = self.write("conn.log", "\n".join(hdr + body) + "\n", gz=gz)
            self.run_reader(zeek.parse, path)
            self.run_detected(path)

        @given(st.lists(hostile_json, max_size=6), st.booleans())
        def test_zui_json_array_export(self, items, close):
            recs = [{"_path": "conn", "ts": "2018-03-24T17:15:20Z", "id": {"orig_h": "10.0.0.1", "orig_p": 1,
                                                                         "resp_h": "10.0.0.2", "resp_p": 80}},
                    *items]
            text = json.dumps(recs)
            if not close:
                text = text[: max(1, len(text) // 2)]
            path = self.write("export.json", text)
            self.run_reader(zeek.parse, path)
            self.run_detected(path)

        @given(mutated(head("scan_and_telemetry/zeek_conn.log")), st.booleans())
        def test_damaged_tsv(self, data, gz):
            path = self.write("conn.log", data, gz=gz)
            self.run_reader(zeek.parse, path)
            self.run_detected(path)

        @given(mutated(head("cyberstrike_ai_fortigate_intrusion/notice.log")))
        def test_damaged_notice(self, data):
            self.run_detected(self.write("notice.log", data))

        @given(mutated(head("scan_and_telemetry/modbus.log")))
        def test_damaged_ot_log(self, data):
            self.run_detected(self.write("modbus.log", data))

        @given(st.binary(min_size=0, max_size=4096), st.integers(0, 4096))
        def test_truncated_or_bogus_gzip(self, junk, cut):
            good = gzip.compress(head("scan_and_telemetry/zeek_conn.log"), mtime=0)
            for data in (good[:cut], junk, good[:20] + junk):
                path = self.write("conn.log.gz", data)
                self.run_reader(zeek.parse, path)
                with time_limit():
                    try:
                        detect(path)
                    except BROKEN_FILE:
                        pass


class FilebeatFuzz(FuzzCase):
    if st is not None:
        COLS = ["@timestamp", "event.dataset", "fileset.name", "source.ip", "source.port", "destination.ip",
                "destination.port", "network.transport", "zeek.session_id", "zeek.connection.state",
                "zeek.connection.history", "source.bytes", "destination.bytes", "event.duration",
                "event.original", "message", "rule.name", "zeek.notice.note"]

        @given(st.lists(st.fixed_dictionaries({c: value_or_hostile(st.sampled_from(["zeek.connection", "zeek.dns",
                                                                                   "zeek.notice", "connection",
                                                                                   "10.0.0.1", "443", "tcp", "SF",
                                                                                   "1.5KB", "48,000",
                                                                                   "Nov 11, 2025 @ 08:33:20.250"]))
                                               for c in COLS}), min_size=1, max_size=8),
               st.sampled_from([",", ";", "\t"]), st.booleans())
        def test_kibana_csv(self, rows, delim, gz):
            buf = io.StringIO()
            w = csv.writer(buf, delimiter=delim, quoting=csv.QUOTE_ALL)
            w.writerow(self.COLS)
            for r in rows:
                w.writerow([v if isinstance(v, str) else json.dumps(v) for v in (r[c] for c in self.COLS)])
            path = self.write("discover.csv", buf.getvalue(), gz=gz)
            self.run_reader(filebeat.parse, path)
            self.run_detected(path)

        @given(st.lists(hostile_json, min_size=1, max_size=8))
        def test_ndjson_elasticdump(self, sources):
            lines = []
            for s in sources:
                lines.append(json.dumps({"_index": "filebeat-7", "_source": {
                    "@timestamp": "2025-11-11T08:33:20.250Z", "event": {"dataset": "zeek.connection"},
                    "source": {"ip": "10.0.0.1", "port": s}, "destination": s, "zeek": s, "message": s}}))
            path = self.write("dump.json", "\n".join(lines) + "\n")
            self.run_reader(filebeat.parse, path)
            self.run_detected(path)

        @given(st.lists(hostile_json, min_size=1, max_size=6))
        def test_zeek_json_inside_message_column(self, recs):
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["@timestamp", "message"])
            for r in recs:
                rec = {"_path": "conn", "ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": r, "id.resp_p": r}
                w.writerow(["x", json.dumps(rec)])
            self.run_detected(self.write("bare.csv", buf.getvalue()))


class PaloAltoFuzz(FuzzCase):
    if st is not None:
        @given(mutated(head("scan_and_telemetry/paloalto_traffic.csv")))
        def test_damaged_traffic_csv(self, data):
            path = self.write("paloalto_traffic.csv", data)
            self.run_reader(paloalto.parse, path)
            self.run_detected(path)

        @given(st.lists(st.lists(hostile_text, min_size=0, max_size=24), min_size=1, max_size=8))
        def test_hostile_rows(self, rows):
            with open(os.path.join(SAMPLES, "scan_and_telemetry/paloalto_traffic.csv"), encoding="utf-8") as fh:
                header = fh.readline()
            buf = io.StringIO()
            w = csv.writer(buf)
            for r in rows:
                w.writerow(r[:2] + ["THREAT" if len(r) % 2 else "TRAFFIC"] + r[2:])
            path = self.write("pa.csv", header + buf.getvalue())
            self.run_reader(paloalto.parse, path)

        @given(st.lists(st.lists(hostile_text, min_size=30, max_size=50), min_size=1, max_size=6))
        def test_headerless_syslog_csv(self, rows):
            buf = io.StringIO()
            w = csv.writer(buf)
            for r in rows:
                r[3] = "TRAFFIC" if len(r) % 2 else "THREAT"
                w.writerow(r)
            path = self.write("syslog.csv", buf.getvalue())
            self.run_reader(paloalto.parse, path)


class NessusFuzz(FuzzCase):
    if st is not None:
        @given(mutated(head("scan_and_telemetry/quarterly_scan.nessus", 120)), st.booleans())
        def test_damaged_nessus_xml(self, data, gz):
            path = self.write("scan.nessus", data, gz=gz)
            self.run_reader(nessus.parse_xml, path)
            self.run_detected(path)

        @given(st.lists(st.fixed_dictionaries({
            "ip": value_or_hostile(valid_ip()), "name": hostile_text, "port": hostile_text, "sev": hostile_text,
            "cvss": hostile_text, "start": hostile_text, "out": hostile_text, "proto": hostile_text}),
            min_size=1, max_size=6))
        def test_hostile_host_properties(self, hosts):
            from xml.sax.saxutils import escape, quoteattr

            def x(v):
                return escape(str(v).encode("utf-8", "replace").decode("utf-8")
                              .translate({c: None for c in range(32) if c not in (9, 10, 13)}))
            parts = ['<?xml version="1.0"?><NessusClientData_v2><Report name="r">']
            for h in hosts:
                parts.append(
                    f'<ReportHost name={quoteattr(x(h["name"]))}><HostProperties>'
                    f'<tag name="host-ip">{x(h["ip"])}</tag><tag name="HOST_START_TIMESTAMP">{x(h["start"])}</tag>'
                    f'</HostProperties><ReportItem port={quoteattr(x(h["port"]))} '
                    f'protocol={quoteattr(x(h["proto"]))} severity={quoteattr(x(h["sev"]))} pluginID="19506">'
                    f'<cvss3_base_score>{x(h["cvss"])}</cvss3_base_score><plugin_output>{x(h["out"])}'
                    f'</plugin_output><cve>{x(h["name"])}</cve></ReportItem></ReportHost>')
            parts.append("</Report></NessusClientData_v2>")
            self.run_reader(nessus.parse_xml, self.write("h.nessus", "".join(parts)))

        def test_xml_bombs_and_external_entities_are_refused(self):
            bombs = [
                '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">'
                '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><NessusClientData_v2><Report><ReportHost name="&c;">'
                '</ReportHost></Report></NessusClientData_v2>',
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
                '<NessusClientData_v2><Report><ReportHost name="&e;"/></Report></NessusClientData_v2>',
                '<?xml version="1.0"?>\n<!--c-->\n<!doctype x [<!ENTITY e "x">]><NessusClientData_v2/>',
            ]
            for i, b in enumerate(bombs):
                for gz in (False, True):
                    path = self.write(f"bomb{i}.nessus", b, gz=gz)
                    with self.assertRaises(UserError):
                        list(nessus.parse_xml(path, ParseStats(file="b", fmt="nessus")))

        @given(mutated(head("scan_and_telemetry/scan.csv")))
        def test_damaged_nessus_csv(self, data):
            path = self.write("scan.csv", data)
            self.run_reader(nessus.parse_csv, path)
            self.run_detected(path)

        @given(st.lists(st.lists(hostile_text, min_size=0, max_size=12), min_size=1, max_size=8))
        def test_hostile_nessus_csv_rows(self, rows):
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["Plugin ID", "CVE", "CVSS v3.0 Base Score", "Risk", "Host", "Protocol", "Port", "Name",
                        "Synopsis", "Solution", "IP Address", "Plugin Output"])
            for r in rows:
                w.writerow(r)
            self.run_reader(nessus.parse_csv, self.write("scan.csv", buf.getvalue()))


class SuricataFuzz(FuzzCase):
    if st is not None:
        eve = st.fixed_dictionaries({
            "timestamp": value_or_hostile(st.just("2026-10-27T00:55:49.400+0000")),
            "event_type": value_or_hostile(st.sampled_from(["alert", "flow", "dns", "http", "netflow"])),
            "src_ip": value_or_hostile(valid_ip()), "src_port": value_or_hostile(st.integers(0, 65535)),
            "dest_ip": value_or_hostile(valid_ip()), "dest_port": value_or_hostile(st.integers(0, 65535)),
            "proto": value_or_hostile(st.sampled_from(["TCP", "UDP", "ICMP", "IPv6-ICMP", "17"])),
        }, optional={"alert": hostile_json, "flow": hostile_json, "app_proto": hostile_json})

        @given(st.lists(eve, min_size=1, max_size=10), st.booleans())
        def test_eve_records(self, recs, gz):
            lines = "\n".join(json.dumps(r) for r in recs) + "\n"
            path = self.write("eve.json", lines, gz=gz)
            self.run_reader(suricata.parse, path)
            self.run_detected(path)

        @given(mutated(head("compare_two_companies/ridgeline_tampa/suricata_eve.json", 30)))
        def test_damaged_eve(self, data):
            path = self.write("eve.json", data)
            self.run_reader(suricata.parse, path)
            self.run_detected(path)


class GenericFlowFuzz(FuzzCase):
    if st is not None:
        @given(mutated(head("scan_and_telemetry/flows.csv")))
        def test_damaged_flow_csv(self, data):
            path = self.write("flows.csv", data)
            self.run_reader(generic.parse, path)
            self.run_detected(path)

        @given(st.lists(st.text(max_size=20), min_size=1, max_size=14),
               st.lists(st.lists(hostile_text, max_size=14), min_size=1, max_size=8))
        def test_any_header_any_rows(self, header, rows):
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(header)
            for r in rows:
                w.writerow(r)
            self.run_detected(self.write("x.csv", buf.getvalue()))

        @given(st.binary(max_size=2048))
        def test_random_bytes_any_reader(self, data):
            path = self.write("blob.log", data)
            self.run_detected(path)
            for parse in (zeek.parse, filebeat.parse, paloalto.parse, suricata.parse, generic.parse,
                          nessus.parse_csv, nessus.parse_xml):
                self.run_reader(parse, path)


class PcapHandoffFuzz(FuzzCase):
    """What happens before Zeek: recognising captures and naming the logs Zeek writes."""
    if st is not None:
        @given(st.binary(max_size=64), st.text(max_size=40))
        def test_capture_sniffing_and_names(self, data, name):
            from vulnflow import pcap
            assume("/" not in name and "\x00" not in name and name not in ("", ".", ".."))
            try:
                path = self.write(name[:60], data)
            except OSError:              # a name the file system refuses is not this test's business
                return
            with time_limit():
                self.assertIsInstance(pcap.is_pcap(path), bool)
                stem = pcap._safe_stem(name)
            # Used as "<n>_<stem>" for a folder and "<stem>-conn.log" for the logs: never a path.
            self.assertRegex(stem, r"\A[A-Za-z0-9._-]{1,80}\Z")

        @given(st.binary(min_size=4, max_size=512))
        def test_garbage_capture_gives_a_clean_error(self, data):
            from vulnflow import pcap
            if not pcap.find_zeek():
                self.skipTest("Zeek is not installed")
            path = self.write("x.pcap", b"\xd4\xc3\xb2\xa1" + data)
            with time_limit(60):
                try:
                    pcap.convert([path], os.path.join(self.tmp, f"w{self.n}"))
                except UserError:
                    pass


class PipelineFuzz(FuzzCase):
    """A whole folder of damaged inputs through load() and correlate(): no crash past the readers."""
    if st is not None:
        @settings(max_examples=12 if os.environ.get("FUZZ_PROFILE", "ci") == "ci" else 200)
        @given(mutated(head("scan_and_telemetry/zeek_conn.log", 80)),
               mutated(head("scan_and_telemetry/paloalto_traffic.csv", 60)),
               mutated(head("scan_and_telemetry/quarterly_scan.nessus", 150)),
               mutated(head("compare_two_companies/ridgeline_tampa/suricata_eve.json", 40)))
        def test_damaged_folder_end_to_end(self, conn, pa, scan, eve):
            from vulnflow.correlate import correlate
            from vulnflow.normalize import load
            paths = [self.write("conn.log", conn), self.write("paloalto_traffic.csv", pa),
                     self.write("scan.nessus", scan), self.write("eve.json", eve)]
            with time_limit(120):
                try:
                    ds = load(paths)
                except UserError:
                    return
                try:
                    res = correlate(ds)
                except UserError:
                    return
                finally:
                    close = getattr(ds, "close", None)
                    if close:
                        close()
            json.dumps(res, default=str)


if __name__ == "__main__":
    unittest.main()
