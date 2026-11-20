"""The native DuckDB readers must give exactly what the Python parsers give.

Each case parses the same file twice, once with the native readers switched off and once with
them on, and compares every Parquet row, the file statistics and the alerts. A native reader may
always step aside for the Python parser; what it may never do is give a different answer.
"""
import glob
import gzip
import os
import random
import shutil
import tempfile
import unittest
from unittest import mock

from vulnflow import db
from vulnflow.normalize import parse_file
from vulnflow.parsers import detect

ROOT = os.path.join(os.path.dirname(__file__), "..")
ZEEK_HEAD = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
             "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t"
             "orig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
             "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\t"
             "string\tcount\tcount\n")
PA_HEAD = ("Receive Time,Serial #,Type,Threat/Content Type,Source address,Destination address,Rule,"
           "Application,Source Zone,Destination Zone,Source Port,Destination Port,IP Protocol,Action,"
           "Bytes,Bytes Sent,Bytes Received,Start Time,Threat/Content Name,Severity\n")


def _parse(path: str, fmt: str, native: bool):
    tmp = tempfile.mkdtemp()
    try:
        with mock.patch.dict(os.environ, {"VULNSCOPE_NATIVE_READERS": "1" if native else "0"}):
            stats, _, alerts, _, fatal = parse_file((3, path, fmt, tmp, 1000))
        files = glob.glob(os.path.join(tmp, "flows_parquet", "*.parquet"))
        rows = db.connect().execute(
            f"SELECT * FROM read_parquet('{os.path.join(tmp, 'flows_parquet', '*.parquet')}') ORDER BY ord"
        ).fetchall() if files else []
        used = any(f.endswith("_native.parquet") for f in files)
        leftovers = [f for f in os.listdir(tmp) if f.startswith("native_")]
        return {"rows": rows, "read": stats.read, "kept": stats.kept, "dropped": list(stats.dropped.items()),
                "notes": stats.notes, "fatal": fatal,
                "alerts": [(a.ts, a.src_ip, a.dst_ip, a.dst_port, a.name, a.severity, a.action, a.source)
                           for a in alerts]}, used, leftovers
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class Same(unittest.TestCase):
    def same(self, path, fmt=None, native=None):
        """Both ways agree; ``native`` says whether the native reader must (True) or must not
        (False) have handled the file."""
        fmt = fmt or detect(path)
        old, _, _ = _parse(path, fmt, False)
        new, used, leftovers = _parse(path, fmt, True)
        self.assertEqual(new, old, path)
        self.assertEqual(leftovers, [])
        if native is not None:
            self.assertEqual(used, native, f"{path}: native reader {'not ' if native else ''}used")
        return new

    def write(self, text, name="conn.log", gz=False, encoding="utf-8"):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, name + (".gz" if gz else ""))
        data = text.encode(encoding) if isinstance(text, str) else text
        with (gzip.open(path, "wb") if gz else open(path, "wb")) as fh:
            fh.write(data)
        return path


class Samples(Same):
    def test_every_bundled_conn_log_and_firewall_export(self):
        paths = [p for p in glob.glob(os.path.join(ROOT, "samples", "**", "*"), recursive=True)
                 if os.path.basename(p) in ("conn.log", "zeek_conn.log", "paloalto_traffic.csv")]
        self.assertGreater(len(paths), 15)
        for p in paths:
            got = self.same(p, native=True)
            self.assertGreater(len(got["rows"]), 100)

    def test_other_zeek_streams_stay_with_the_python_parser(self):
        for p in glob.glob(os.path.join(ROOT, "samples", "artex_ai_agentic_intrusion", "*.log")):
            if os.path.basename(p) != "conn.log":
                self.same(p, native=False)


ZEEK_ROWS = [
    "1792368028.164796\tC1\t203.0.113.31\t59567\t10.50.1.12\t443\ttcp\thttp\t0.2\t890\t5316\tSF\tShADadFf\t5\t6",
    "1792368028.0000005\tC2\t2001:DB8::0001\t1\tfe80::1%eth0\t53\tudp\tdns\t-\t-\t-\tS0\t-\t2\t3",
    "1792368028.9999995\tC3\t10.0.0.1\t65535\t10.0.0.2\t0\t6\t(empty)\t-\t0\t0\tREJ\tSr\t1\t1",
    "-\tC4\t10.0.0.1\t70000\t10.0.0.2\t22\tICMP6\t-\t-\t7\t0\tOTH\t^hADad\t0\t0",
    "1792368029\tC5\t010.0.0.1\t5\t10.0.0.2\t22\ttcp\t-\t-\t7\t9\tS0\t-\t0\t0",          # not an address
    "1792368030\tC6\t10.0.0.9\t5\t-\t22\ttcp\t-\t-\t7\t9\tS0\t-\t0\t0",                  # no destination
    "1792368031\tC7\t10.0.0.9\t5\t10.0.0.2\t22\ttcp",                                    # too few columns
    "1792368032.5\tC8\t 10.0.0.9 \t-\t[10.0.0.2]\t(empty)\tsctp\tssl,http\t-\t999999999999999\t1\tSH\tDa\t9\t9",
    "1792368033\tC9\t10.0.0.9\t5\t10.0.0.2\t3389\t(empty)\t-\t-\t(empty)\t(empty)\tshr\tAd\t-\t-",
    "99999999999\tC10\t10.0.0.9\t5\t10.0.0.2\t80\ttcp\t-\t-\t1\t1\tRSTO\t-\t-\t-",
    "0\tC11\t::ffff:10.0.0.9\t5\t10.0.0.2\t80\tudp\t-\t-\t1\t0\tSF\t-\t4\t0",
]


class ZeekConn(Same):
    def test_awkward_but_ordinary_rows(self):
        got = self.same(self.write(ZEEK_HEAD + "\n".join(ZEEK_ROWS) + "\n\n   \n#close\t2026-10-19-00-00-00\n"), native=True)
        self.assertEqual(got["read"], len(ZEEK_ROWS))
        self.assertEqual(dict(got["dropped"]), {"missing or invalid IP": 2, "column count mismatch": 1})

    def test_gzip_and_crlf(self):
        text = ZEEK_HEAD + "\n".join(ZEEK_ROWS) + "\n"
        self.same(self.write(text, gz=True), native=True)
        self.same(self.write(text.replace("\n", "\r\n")))

    def test_same_header_repeated_is_ordinary(self):
        self.same(self.write(ZEEK_HEAD + ZEEK_ROWS[0] + "\n" + ZEEK_HEAD + ZEEK_ROWS[1] + "\n"), native=True)

    def test_no_types_line_and_missing_columns(self):
        head = "#separator \\x09\n#path\tconn\n#fields\tts\tid.orig_h\tid.resp_h\tconn_state\n"
        self.same(self.write(head + "1792368028.5\t10.0.0.1\t10.0.0.2\tSF\n-\t10.0.0.1\t10.0.0.3\tS0\n"), native=True)

    def test_steps_aside_for_anything_unusual(self):
        row = ZEEK_ROWS[0]
        unusual = {
            "iso time": ZEEK_HEAD + row.replace("1792368028.164796", "2026-10-19T00:00:28Z") + "\n",
            "millisecond time": ZEEK_HEAD + row.replace("1792368028.164796", "1792368028164") + "\n",
            "port as decimal": ZEEK_HEAD + row.replace("\t443\t", "\t443.0\t") + "\n",
            "non-ascii": ZEEK_HEAD + row.replace("http", "h\u00e9ttp") + "\n",
            "json line": ZEEK_HEAD + row + '\n{"ts": 1, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "conn_state": "SF"}\n',
            "other unset field": ZEEK_HEAD.replace("#unset_field\t-", "#unset_field\tNA") + row + "\n",
            "second header differs": ZEEK_HEAD + row + "\n#fields\tts\tid.orig_h\tid.resp_h\tconn_state\n1\t10.0.0.1\t10.0.0.2\tSF\n",
            "service is a set": ZEEK_HEAD.replace("addr\tport\tenum\tstring", "addr\tport\tenum\tset[string]") + row + "\n",
            "byte order mark": "\ufeff" + ZEEK_HEAD + row + "\n",
            "more digits than a float holds": ZEEK_HEAD + row.replace("\t890\t", "\t999999999999999999\t") + "\n",
            "negative bytes": ZEEK_HEAD + row.replace("\t890\t", "\t-5\t") + "\n",
            "nul byte": ZEEK_HEAD + row.replace("http", "ht\x00tp") + "\n",
        }
        for what, text in unusual.items():
            with self.subTest(what):
                self.same(self.write(text), native=False)

    def test_bad_utf8_and_truncated_gzip(self):
        self.same(self.write((ZEEK_HEAD + ZEEK_ROWS[0]).encode() + b"\xff\xfe\n"), native=False)
        whole = self.write(ZEEK_HEAD + "\n".join(ZEEK_ROWS * 200) + "\n", gz=True)
        with open(whole, "rb") as fh:
            data = fh.read()
        cut = self.write(data[:len(data) // 2], name="conn.log.gz")
        got = self.same(cut, fmt="zeek", native=False)
        self.assertTrue(any("could not be parsed" in n for n in got["notes"]))

    def test_gzip_bomb_limit_still_applies(self):
        path = self.write(ZEEK_HEAD + "\n".join(ZEEK_ROWS * 50) + "\n", gz=True)
        with mock.patch.dict(os.environ, {"VULNSCOPE_MAX_GZ_BYTES": "2000"}):
            got = self.same(path, native=False)
        self.assertTrue(any("decompresses to more than" in n for n in got["notes"]))

    def test_random_damage(self):
        rng = random.Random(20261120)
        junk = ["", "-", "(empty)", "x", "1e3", " 7", "0x10", "::1", "999.1.1.1", "tcp ", "\u00e9", "7.50",
                "10.0.0.300", "-1", "99999999999999999999", "SF", "1792368028.1234567891", "a\tb", "{"]
        for case in range(120):
            rows = []
            for _ in range(rng.randint(1, 12)):
                cells = rng.choice(ZEEK_ROWS).split("\t")
                for _ in range(rng.choice((0, 0, 0, 1, 2))):
                    cells[rng.randrange(len(cells))] = rng.choice(junk)
                rows.append("\t".join(cells))
            with self.subTest(case=case):
                self.same(self.write(ZEEK_HEAD + "\n".join(rows) + "\n"))


PA_ROWS = [
    "2026/10/12 00:00:04,0164,TRAFFIC,end,10.10.1.40,93.184.214.133,allow-web,ssl,dmz,untrust,59009,443,tcp,allow,269007,1782,267225,2026/10/12 00:00:04,,",
    "2026/10/12 05:36:45,0164,THREAT,vulnerability,192.0.2.216,10.10.3.31,allow-web,web-browsing,untrust,trust,37061,3389,tcp,reset-both,,,,,Microsoft RDP RCE CVE-2019-0708(55188),Critical",
    "2026/10/12 05:36:46,0164,THREAT,vulnerability,192.0.2.216,10.10.3.31,r,web,untrust,trust,1,,tcp,,,,,,, HIGH ",
    "2026-10-12 09:38:38,0164,traffic,end,192.0.2.91,10.10.1.10,default-deny,incomplete, Untrust ,DMZ,41030,22,6,Deny,1433,1433,0,,,",
    "2026/10/12 09:38:39,0164,TRAFFIC,end,2001:DB8::5,10.10.1.10,r,\"app, with comma\",a,b,1,70000,ICMP,drop,5,5,,2026/10/12 09:38:39,,",
    "2026/10/12 09:38:40,0164,SYSTEM,general,,,,,,,,,,,,,,,,",
    "2026/10/12 09:38:41,0164,,end,10.1.1.1,not-an-ip,r,dns,a,b,1,53,udp,allow,5,5,9,,,",
    ",,,,,,,,,,,,,,,,,,,",
    ",0164,TRAFFIC,end,10.1.1.1,10.1.1.2,r,dns,a,b,1,53,17,allow,5,5,9,,,",
    "2026/02/30 09:38:41,0164,TRAFFIC,end,10.1.1.1,10.1.1.2,r,dns,a,b,,,,reset-client,,,,2026/02/30 09:38:41,,",
    "2026/10/12 09:38:42,0164,TRAFFIC,end,10.1.1.1,10.1.1.2,r,dns,a,b,1,53,udp,allow",
]


class PaloAlto(Same):
    def test_awkward_but_ordinary_rows(self):
        got = self.same(self.write(PA_HEAD + "\n".join(PA_ROWS) + "\n", name="pa.csv"), fmt="paloalto", native=True)
        self.assertEqual(len(got["alerts"]), 2)
        self.assertEqual(dict(got["dropped"]), {"SYSTEM log type not used": 1, "missing or invalid IP": 1})
        self.assertEqual(got["read"], len(PA_ROWS) - 1)            # the blank row is not counted

    def test_gzip_and_crlf(self):
        text = PA_HEAD + "\n".join(PA_ROWS) + "\n"
        self.same(self.write(text, name="pa.csv", gz=True), fmt="paloalto", native=True)
        self.same(self.write(text.replace("\n", "\r\n"), name="pa.csv"), fmt="paloalto")

    def test_steps_aside_for_anything_unusual(self):
        row = PA_ROWS[0]
        unusual = {
            "iso time": PA_HEAD + row.replace("2026/10/12 00:00:04", "2026-10-12T00:00:04Z") + "\n",
            "epoch time": PA_HEAD + row.replace("2026/10/12 00:00:04", "1792368028") + "\n",
            "thousands separator": PA_HEAD + row.replace(",269007,1782,", ',269007,"1,782",') + "\n",
            "non-ascii": PA_HEAD + row.replace("allow-web", "allow-w\u00e9b") + "\n",
            "extra cells": PA_HEAD + row + ",x,y\n",
            "line break in a cell": PA_HEAD + row.replace("allow-web", '"allow\nweb"') + "\n",
            "syslog lines without a header": "Oct 12 00:00:04 fw 1,2026/10/12 00:00:04,0164,TRAFFIC,end,1,2026/10/12 00:00:04,10.1.1.1,10.1.1.2\n",
            "quoted header": PA_HEAD.replace("Receive Time", '"Receive Time"') + row + "\n",
        }
        for what, text in unusual.items():
            with self.subTest(what):
                self.same(self.write(text, name="pa.csv"), fmt="paloalto", native=False)

    def test_stray_quote_reads_the_same_either_way(self):
        self.same(self.write(PA_HEAD + PA_ROWS[0].replace("allow-web", 'allow"web') + "\n", name="pa.csv"), fmt="paloalto")

    def test_random_damage(self):
        rng = random.Random(7)
        junk = ["", " ", "-", "x", "1e3", " 7 ", "::1", "999.1.1.1", "DENY", "Reset-Both", "threat", "\u00e9",
                "7.5", "-1", "2026/13/01 00:00:00", "2026/10/12 24:00:00", "0000/01/01 00:00:00", '"q"', "a b"]
        for case in range(120):
            rows = []
            for _ in range(rng.randint(1, 12)):
                cells = rng.choice(PA_ROWS).split(",")
                for _ in range(rng.choice((0, 0, 0, 1, 2))):
                    cells[rng.randrange(len(cells))] = rng.choice(junk)
                rows.append(",".join(cells))
            with self.subTest(case=case):
                self.same(self.write(PA_HEAD + "\n".join(rows) + "\n", name="pa.csv"), fmt="paloalto")


if __name__ == "__main__":
    unittest.main()
