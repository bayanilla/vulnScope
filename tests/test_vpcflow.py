"""AWS VPC Flow Logs: detection of every delivery shape, and joining request and reply records."""
import gzip
import json
import os
import shutil
import tempfile
import unittest

from vulnflow.parsers import detect, vpcflow
from vulnflow.schema import ParseStats

HEADER = ("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes "
          "start end action log-status")
REQ = "2 123456789012 eni-0a1 10.0.1.5 52.1.2.3 44321 443 6 10 840 1700000000 1700000060 ACCEPT OK"
REPLY = "2 123456789012 eni-0a1 52.1.2.3 10.0.1.5 443 44321 6 8 5000 1700000000 1700000060 ACCEPT OK"
PROBE = "2 123456789012 eni-0a1 45.9.9.9 10.0.1.5 51000 22 6 1 40 1700000000 1700000060 REJECT OK"
NODATA = "2 123456789012 eni-0a1 - - - - - - - 1700000000 1700000060 - NODATA"


class VpcFlowTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, text, gz=False):
        path = os.path.join(self.dir, name)
        with (gzip.open(path, "wt") if gz else open(path, "w")) as fh:
            fh.write(text)
        return path

    def parse(self, path):
        fmt = detect(path)
        self.assertEqual(fmt, "aws_vpcflow", os.path.basename(path))
        stats = ParseStats(file=os.path.basename(path), fmt=fmt)
        return list(vpcflow.parse(path, stats)), stats

    def assert_https_session(self, flows):
        web = [f for f in flows if f.dst_port == 443]
        self.assertEqual(len(web), 1)                      # request + reply = one session
        f = web[0]
        self.assertEqual((f.src_ip, f.src_port, f.dst_ip), ("10.0.1.5", 44321, "52.1.2.3"))
        self.assertEqual((f.bytes_out, f.bytes_in, f.action, f.established), (840, 5000, "allow", True))
        self.assertEqual(int(f.ts.timestamp()), 1700000000)

    def test_with_and_without_header_and_gzip(self):
        body = "\n".join([REQ, REPLY, PROBE, NODATA]) + "\n"
        for name, text, gz in (("with_header.log", HEADER + "\n" + body, False),
                               ("no_header.log", body, False),
                               ("delivered.log.gz", HEADER + "\n" + body, True)):
            flows, stats = self.parse(self.write(name, text, gz))
            self.assertEqual(len(flows), 2, name)
            self.assert_https_session(flows)
            probe = next(f for f in flows if f.dst_port == 22)
            self.assertEqual((probe.action, probe.established), ("deny", False))
            self.assertEqual(stats.dropped["no traffic in the capture window (NODATA)"], 1)

    def test_cloudwatch_exports(self):
        csv_text = "@timestamp,@message\n" + "".join(f'2026-11-19 00:00:00.000,"{r}"\n' for r in (REQ, REPLY))
        ndjson = "".join(json.dumps({"timestamp": 1700000000000, "message": r}) + "\n" for r in (REQ, REPLY))
        s3_export = "".join(f"2026-11-19T00:00:01.000Z {r}\n" for r in (REQ, REPLY))
        for name, text in (("insights.csv", csv_text), ("events.json", ndjson), ("000000.log", s3_export)):
            flows, _ = self.parse(self.write(name, text))
            self.assert_https_session(flows)

    def test_athena_csv_and_parquet(self):
        cols = HEADER.replace("-", "_").split()
        rows = [dict(zip(cols, r.split())) for r in (REQ, REPLY)]
        athena = ",".join(f'"{c}"' for c in cols) + "\n" + "".join(
            ",".join(f'"{r[c]}"' for c in cols) + "\n" for r in rows)
        self.assert_https_session(self.parse(self.write("athena.csv", athena))[0])
        import duckdb
        src = self.write("rows.json", "\n".join(json.dumps(r) for r in rows))
        pq = os.path.join(self.dir, "flows.parquet")
        duckdb.sql(f"COPY (SELECT * REPLACE (srcport::INT AS srcport, dstport::INT AS dstport, "
                   f"bytes::BIGINT AS bytes, packets::BIGINT AS packets, start::BIGINT AS start, "
                   f"\"end\"::BIGINT AS \"end\") FROM read_json_auto('{src}')) TO '{pq}' (FORMAT parquet)")
        self.assert_https_session(self.parse(pq)[0])

    def test_other_parquet_is_not_taken(self):
        import duckdb
        pq = os.path.join(self.dir, "other.parquet")
        duckdb.sql(f"COPY (SELECT 1 AS a, 'x' AS b) TO '{pq}' (FORMAT parquet)")
        self.assertEqual(detect(pq), "generic")

    def test_tcp_flags_decide_client_and_refusal(self):
        hdr = "version interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status tcp-flags"
        lines = [hdr,
                 # client on a high port talks to a server on a high port: SYN says who is the client
                 "5 eni-1 10.0.2.8 10.0.1.5 9999 40001 6 5 400 1700000000 1700000060 ACCEPT OK 2",
                 "5 eni-1 10.0.1.5 10.0.2.8 40001 9999 6 5 900 1700000000 1700000060 ACCEPT OK 18",
                 # closed port: the reply is only a reset
                 "5 eni-1 10.0.1.9 10.0.1.5 50000 8080 6 1 60 1700000000 1700000060 ACCEPT OK 2",
                 "5 eni-1 10.0.1.5 10.0.1.9 8080 50000 6 1 40 1700000000 1700000060 ACCEPT OK 4"]
        flows, _ = self.parse(self.write("flags.log", "\n".join(lines) + "\n"))
        by_port = {f.dst_port: f for f in flows}
        self.assertEqual(set(by_port), {40001, 8080})
        self.assertEqual((by_port[40001].src_ip, by_port[40001].established), ("10.0.2.8", True))
        self.assertEqual((by_port[8080].action, by_port[8080].established), ("reject", False))

    def test_no_reply_when_replies_are_logged_is_not_established(self):
        lines = [HEADER, REQ, REPLY,
                 "2 123456789012 eni-0a1 10.0.1.5 10.0.3.3 40000 3389 6 1 60 1700000001 1700000061 ACCEPT OK"]
        flows, _ = self.parse(self.write("noreply.log", "\n".join(lines) + "\n"))
        rdp = next(f for f in flows if f.dst_port == 3389)
        self.assertFalse(rdp.established)

    def test_one_direction_export_keeps_old_meaning(self):
        flows, _ = self.parse(self.write("oneway.log", HEADER + "\n" + REQ + "\n"))
        self.assertEqual((len(flows), flows[0].established, flows[0].bytes_in), (1, True, 0))

    def test_one_direction_single_packet_probe_is_not_established(self):
        # a port scan as AWS logs it from the scanner's side only (Splunk attack_data, nmap in AWS)
        lines = [f"2 123397614277 eni-0b0f 10.0.1.30 10.0.1.15 {40000 + p} {p} 6 1 60 1697606571 1697606601 ACCEPT OK"
                 for p in (22, 80, 443, 3389)]
        flows, _ = self.parse(self.write("scan.log", "\n".join(lines) + "\n"))
        self.assertEqual([f.established for f in flows], [False] * 4)

    def test_windows_join_and_both_interfaces_count_once(self):
        hdr = "version interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
        lines = [hdr]
        for eni in ("eni-a", "eni-b"):                 # both ends inside the VPC: each interface logs it
            for w in range(3):                         # three 1-minute windows of one long session
                t = 1700000000 + 60 * w
                lines.append(f"5 {eni} 10.0.1.5 10.0.1.6 50000 5432 6 10 1000 {t} {t + 60} ACCEPT OK")
                lines.append(f"5 {eni} 10.0.1.6 10.0.1.5 5432 50000 6 10 2000 {t} {t + 60} ACCEPT OK")
        # the same 5-tuple again after a long silence is a new session
        t = 1700000000 + 3600
        lines += [f"5 eni-a 10.0.1.5 10.0.1.6 50000 5432 6 10 1000 {t} {t + 60} ACCEPT OK",
                  f"5 eni-a 10.0.1.6 10.0.1.5 5432 50000 6 10 2000 {t} {t + 60} ACCEPT OK"]
        flows, _ = self.parse(self.write("windows.log", "\n".join(lines) + "\n"))
        self.assertEqual(len(flows), 2)
        first = min(flows, key=lambda f: f.ts)
        self.assertEqual((first.src_ip, first.dst_port, first.bytes_out, first.bytes_in), ("10.0.1.5", 5432, 3000, 6000))

    def test_open_session_cap_writes_out_oldest(self):
        from unittest import mock
        lines = [HEADER] + [f"2 1 eni-a 10.0.1.{i} 52.1.2.3 4{i:04d} 443 6 2 100 1700000000 1700000060 ACCEPT OK"
                            for i in range(1, 60)]
        with mock.patch.object(vpcflow, "MAX_OPEN", 10), mock.patch.object(vpcflow, "FLUSH_EVERY", 5):
            flows, stats = self.parse(self.write("busy.log", "\n".join(lines) + "\n"))
        self.assertEqual(len(flows), 59)                  # nothing lost, nothing doubled
        self.assertTrue(any("too many sessions" in n for n in stats.notes))

    def test_nat_gateway_uses_packet_addresses(self):
        hdr = "version interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status pkt-srcaddr pkt-dstaddr"
        lines = [hdr,
                 "5 eni-nat 10.0.9.9 8.8.8.8 40000 53 17 1 60 1700000000 1700000060 ACCEPT OK 10.0.1.77 8.8.8.8",
                 "5 eni-nat 8.8.8.8 10.0.9.9 53 40000 17 1 120 1700000000 1700000060 ACCEPT OK 8.8.8.8 10.0.1.77"]
        flows, stats = self.parse(self.write("nat.log", "\n".join(lines) + "\n"))
        self.assertEqual([(f.src_ip, f.dst_ip, f.bytes_in, f.established) for f in flows],
                         [("10.0.1.77", "8.8.8.8", 120, True)])
        self.assertTrue(any("pkt-srcaddr" in n for n in stats.notes))

    def test_custom_format_without_header_is_counted_not_guessed(self):
        line = "vpc-1 10.0.1.5 52.1.2.3 44321 443 6 840 ACCEPT"
        path = self.write("custom.log", HEADER + "\n" + REQ + "\n" + line + "\n")
        flows, stats = self.parse(path)
        self.assertEqual(len(flows), 1)
        self.assertEqual(sum(stats.dropped.values()), 1)

    def test_not_taken_for_other_csv(self):
        self.assertNotEqual(detect(self.write("flows.csv", "src_ip,dst_ip,dst_port\n10.0.0.1,10.0.0.2,80\n")),
                            "aws_vpcflow")
        self.assertNotEqual(detect(self.write("notes.csv", "timestamp,message\n1,hello world\n")), "aws_vpcflow")


if __name__ == "__main__":
    unittest.main()
