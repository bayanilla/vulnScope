"""Work moved from Python loops into DuckDB must give exactly what the loops gave."""
import csv
import os
import tempfile
import unittest
from datetime import datetime, timezone

from vulnflow.ioc_archive import Matcher, match_archive
from vulnflow.normalize import Dataset
from vulnflow.report import csv_row
from vulnflow.schema import Flow

T = datetime(2026, 10, 19, 3, 12, 1, tzinfo=timezone.utc)
AWKWARD = [
    Flow(T, "203.0.113.5", "10.0.0.5", 443, "tcp", src_port=50000, app="=HYPERLINK(\"http://x\")"),
    Flow(T.replace(microsecond=42), "10.0.0.5", "203.0.113.5", 53, "udp", src_port=1, app='say "hi", twice'),
    Flow(None, "10.0.0.6", "10.0.0.5", None, "icmp", app="line\nbreak", src_zone="-trust", dst_zone="@dmz"),
    Flow(T, "2001:db8::1", "10.0.0.5", 22, "tcp", action="deny", established=False, bytes_out=7,
         source="+weird name.log", app=""),
    Flow(T, "10.0.0.7", "10.0.0.5", 80, "tcp", app="-", bytes_in=9),      # one character: left alone
]
COLS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "action", "established",
        "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source"]


def _python_csv(flows, path):
    """The writer as it was before the export moved into DuckDB."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        cw = csv.writer(fh)
        cw.writerow(COLS)
        for f in flows:
            cw.writerow(csv_row((f.ts.isoformat() if f.ts else "") if c == "ts" else getattr(f, c) for c in COLS))


class FlowsCsv(unittest.TestCase):
    def test_same_rows_as_the_python_writer(self):
        ds = Dataset(flows=list(AWKWARD))
        self.addCleanup(ds.close)
        store = ds.flow_store()
        with tempfile.TemporaryDirectory() as tmp:
            new, old = os.path.join(tmp, "new.csv"), os.path.join(tmp, "old.csv")
            store.export_flows_csv(new)
            _python_csv(list(store_flows(store)), old)
            read = lambda p: list(csv.reader(open(p, newline="", encoding="utf-8")))
            self.assertEqual(read(new), read(old))
            self.assertIn(b"\r\n", open(new, "rb").read())


def store_flows(store):
    from vulnflow.store import FlowView
    return FlowView(store)


class IocFlows(unittest.TestCase):
    def test_same_matches_as_walking_every_flow(self):
        archive = {("ip", "203.0.113.5"): {"id": "ip:203.0.113.5", "type": "ip", "value": "203.0.113.5"},
                   ("ip", "2001:db8::1"): {"id": "ip:2001:db8::1", "type": "ip", "value": "2001:db8::1"},
                   ("ip", "198.51.100.1"): {"id": "ip:198.51.100.1", "type": "ip", "value": "198.51.100.1"}}
        ds = Dataset(flows=list(AWKWARD))
        self.addCleanup(ds.close)
        ds.scanned_hosts = {"10.0.0.5": {"hostname": "", "os": ""}}
        expected = Matcher(archive, {"10.0.0.5"})
        for f in ds.flows:
            expected.flow(f.src_ip, f.dst_ip)
        got = match_archive(ds, archive)
        self.assertEqual(got, expected.matches())
        self.assertEqual({m["value"]: m["observed"] for m in got},
                         {"203.0.113.5": {"network session": 2}, "2001:db8::1": {"network session": 1}})


if __name__ == "__main__":
    unittest.main()
