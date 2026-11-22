"""Zeek JSON written with id_orig_h style names (SimpleRock, Logstash and Elastic pipelines)."""
import json
import os
import tempfile
import unittest

from vulnflow.parsers import detect, zeek
from vulnflow.schema import ParseStats


class UnderscoreIds(unittest.TestCase):
    def test_conn_json_with_underscore_ids_is_read(self):
        rows = [{"ts": 1700000000.5, "uid": "Cu1", "id_orig_h": "10.0.1.4", "id_orig_p": 50000,
                 "id_resp_h": "10.0.0.4", "id_resp_p": 445, "proto": "tcp", "conn_state": "SF",
                 "orig_bytes": 10, "resp_bytes": 20, "orig_pkts": 2, "resp_pkts": 2}]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "conn.log")
            with open(path, "w") as fh:
                fh.write("".join(json.dumps(r) + "\n" for r in rows))
            self.assertEqual(detect(path), "zeek")
            flows = [f for f in zeek.parse(path, ParseStats(path, "zeek")) if hasattr(f, "dst_port")]
        self.assertEqual(len(flows), 1)
        self.assertEqual((flows[0].src_ip, flows[0].dst_ip, flows[0].dst_port), ("10.0.1.4", "10.0.0.4", 445))

    def test_underscore_ids_never_replace_zeek_names(self):
        rec = zeek._flatten({"id.orig_h": "10.0.0.1", "id_orig_h": "10.9.9.9"})
        self.assertEqual(rec["id.orig_h"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
