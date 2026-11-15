"""Parallel file parsing, Parquet-backed Zeek/OT events and the optional normalized copies."""
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from vulnflow import normalize
from vulnflow.correlate import Config
from vulnflow.pipeline import run
from vulnflow.samples import generate
from vulnflow.schema import OTEvent, ZeekEvent
from vulnflow.store import PartWriter, Store


def _snapshot(ds):
    return {
        "flows": [(f.ts, f.src_ip, f.dst_ip, f.dst_port, f.proto, f.action, f.source) for f in ds.flows],
        "zeek": [(e.ts, e.stream, e.uid, e.src_ip, e.dst_ip, e.source, e.fields) for e in ds.zeek_events],
        "ot": [(e.ts, e.protocol, e.operation, e.direction, e.uid) for e in ds.ot_events],
        "threats": [(t.ts, t.src_ip, t.dst_ip, t.name) for t in ds.threats],
        "findings": [(f.host_ip, f.port, f.plugin_id) for f in ds.findings],
        "stats": [(s.file, s.fmt, s.read, s.kept, dict(s.dropped)) for s in ds.stats],
        "dups": (ds.duplicate_flows, ds.cross_sensor_duplicates),
    }


class ParallelParseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.samples = generate(os.path.join(cls.tmp, "in"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def load(self, workers):
        with patch.dict(os.environ, {"VULNSCOPE_PARSE_WORKERS": str(workers)}):
            ds = normalize.load(self.samples, workdir=self.tmp)
        try:
            return _snapshot(ds)
        finally:
            ds.close()

    def test_worker_processes_give_the_same_result_as_one_process(self):
        one, several = self.load(1), self.load(3)
        self.assertTrue(one["flows"] and one["zeek"] and one["ot"] and one["threats"])
        self.assertEqual(one, several)

    def test_small_inputs_stay_in_one_process(self):
        jobs = [(i, p, "zeek", self.tmp, 10) for i, p in enumerate(self.samples)]
        with patch.dict(os.environ, {"VULNSCOPE_PARSE_WORKERS": ""}):
            self.assertEqual(normalize.parse_workers(jobs, None), 1)
            with patch.object(normalize, "PARALLEL_MIN_BYTES", 0), \
                    patch("vulnflow.resources.cpu_count", return_value=4):
                self.assertEqual(normalize.parse_workers(jobs, None), 1)    # 1 GiB ceiling -> 1 worker
        with patch.dict(os.environ, {"VULNSCOPE_PARSE_WORKERS": "99"}):
            self.assertEqual(normalize.parse_workers(jobs, None), len(jobs))
        with patch.dict(os.environ, {"VULNSCOPE_PARSE_WORKERS": "lots"}):
            with self.assertRaises(ValueError):
                normalize.parse_workers(jobs, None)


class EventParquetTests(unittest.TestCase):
    def test_events_round_trip_in_input_order(self):
        store = Store(tempfile.mkdtemp())
        try:
            t = datetime(2026, 11, 2, 13, 0, 0, 250000, tzinfo=timezone.utc)
            # file 1 is written before file 0: reading back still follows file order
            w1 = PartWriter(store.dir, 1, batch_size=2)
            w1.add_event(ZeekEvent(ts=None, stream="dns", uid="", src_ip="10.0.0.9", dst_ip=None,
                                   fields={"query": "b.example", "answers": ["1.2.3.4"]}, source="dns2.log"))
            w1.close()
            w0 = PartWriter(store.dir, 0, batch_size=2)
            for i in range(3):
                w0.add_event(ZeekEvent(ts=t, stream="http", uid=f"C{i}", src_ip="10.0.0.1", dst_ip="203.0.113.5",
                                       fields={"host": "a.example", "n": i, "ok": True, "none": None, "é": "ü"},
                                       source="http.log"))
            w0.add_event(OTEvent(ts=t, stream="modbus", uid="M1", src_ip="10.9.0.1", dst_ip="10.9.0.2",
                                 fields={"func": "READ"}, source="modbus.log", protocol="modbus",
                                 operation="READ", direction="request"))
            w0.close()
            zeek = list(store.events("zeek_events", ot=False, count=5))
            ot = list(store.events("ot_events", ot=True, count=1))
        finally:
            store.close()
        self.assertEqual([e.uid for e in zeek], ["C0", "C1", "C2", "M1", ""])
        self.assertEqual(zeek[0].ts, t)
        self.assertEqual(zeek[0].fields, {"host": "a.example", "n": 0, "ok": True, "none": None, "é": "ü"})
        self.assertIsNone(zeek[4].ts)
        self.assertIsNone(zeek[4].dst_ip)
        self.assertEqual(zeek[4].uid, "")
        self.assertEqual(len(ot), 1)
        self.assertIsInstance(ot[0], OTEvent)
        self.assertEqual((ot[0].protocol, ot[0].operation, ot[0].direction), ("modbus", "READ", "request"))


class NormalizedCopiesTests(unittest.TestCase):
    def test_copies_can_be_left_out(self):
        tmp = tempfile.mkdtemp()
        try:
            samples = generate(os.path.join(tmp, "in"))
            full, _ = run(samples, os.path.join(tmp, "full"), article_previews=False)
            lean, paths = run(samples, os.path.join(tmp, "lean"), Config(normalized_copies=False),
                              article_previews=False)
            norm = os.path.join(tmp, "lean", "normalized")
            for name in ("flows.csv", "zeek_events.jsonl", "ot_events.jsonl"):
                self.assertFalse(os.path.exists(os.path.join(norm, name)), name)
                self.assertTrue(os.path.exists(os.path.join(tmp, "full", "normalized", name)), name)
            for name in ("findings.csv", "threats.csv", "probed_addresses.csv"):
                self.assertTrue(os.path.exists(os.path.join(norm, name)), name)
            self.assertNotIn("normalized/flows.csv", paths)
            self.assertFalse(lean["config"]["normalized_copies"])
            self.assertEqual(lean["hosts"], full["hosts"])
            self.assertEqual(lean["findings"], full["findings"])
            with open(os.path.join(tmp, "lean", "technical_report.md"), encoding="utf-8") as fh:
                self.assertIn("were not written for this run", fh.read())
            with open(os.path.join(tmp, "lean", "results.json"), encoding="utf-8") as fh:
                self.assertFalse(json.load(fh)["config"]["normalized_copies"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
