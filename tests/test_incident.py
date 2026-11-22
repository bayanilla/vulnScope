"""Incident cases (P0): evidence is preserved and checked, every statement cites an original
record, the same evidence gives the same report, and broken or unsupported files never stop a case.
No Nessus scan and no AI model are involved."""
import gzip
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout

from vulnflow.cli import main as cli
from vulnflow.errors import UserError
from vulnflow.incident import case as cases
from vulnflow.incident.report_schema import as_json, problems
from vulnflow.incident.run import run
from vulnflow.parsers import zeek
from vulnflow.schema import ParseStats

ROOT = os.path.join(os.path.dirname(__file__), "..")
ARTEX = os.path.join(ROOT, "samples", "artex_ai_agentic_intrusion")

CONN_HEAD = ("#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
             "\tservice\tconn_state\torig_bytes\tresp_bytes\n"
             "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tcount\tcount\n")


def conn(ts, uid, src, sport, dst, dport, state="SF", ob=100, rb=200, proto="tcp"):
    return f"{ts}\t{uid}\t{src}\t{sport}\t{dst}\t{dport}\t{proto}\t-\t{state}\t{ob}\t{rb}\n"


def report(folder):
    with open(os.path.join(folder, "incident_report.json"), encoding="utf-8") as fh:
        return json.load(fh)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self._clean)

    def _clean(self):
        for root, dirs, files in os.walk(self.tmp):
            for name in dirs + files:
                os.chmod(os.path.join(root, name), 0o700)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text, gz=False):
        path = os.path.join(self.tmp, "in", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if gz:
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                fh.write(text)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return path

    def new_case(self, name="case", **kw):
        return cases.create(os.path.join(self.tmp, name), "Test case", actor="tester", **kw)


class ZeekOnlyCase(Base):
    """Case A's network half on the Artex sample: no scan, no host logs."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        c = cases.create(os.path.join(cls.dir, "artex"), "Artex", actor="tester", scope_nets=["10.50.0.0/16"])
        for name in ("conn.log", "dns.log", "http.log", "notice.log", "ssl.log", "northfold_scan.nessus"):
            cases.add_evidence(c, os.path.join(ARTEX, name), "tester")
        cls.case = c
        cls.out = run(c, "tester")
        cls.rep = report(cls.out["folder"])

    @classmethod
    def tearDownClass(cls):
        for root, dirs, files in os.walk(cls.dir):
            for name in dirs + files:
                os.chmod(os.path.join(root, name), 0o700)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_fits_schema_and_published_copy(self):
        self.assertEqual(problems(self.rep), [])
        with open(os.path.join(ROOT, "docs", "incident_report.schema.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), as_json(), "run: python -m vulnflow.incident.report_schema > docs/incident_report.schema.json")

    def test_every_statement_cites_a_found_original(self):
        records = {e["event_id"]: e for e in self.rep["evidence_records"]}
        cited = [e for i in self.rep["timeline"] for e in i["evidence"]] + \
                [e for f in self.rep["findings"] for e in f["evidence"]]
        self.assertTrue(cited)
        for eid in cited:
            self.assertIn(eid, records)
            self.assertTrue(records[eid]["found"], eid)
        shas = {r["sha256"] for r in self.case.evidence()}
        self.assertTrue(all(r["sha256"] in shas for r in records.values()))

    def test_cited_original_is_the_record_described(self):
        item = next(i for i in self.rep["timeline"] if i["action"] == "connection")
        rec = next(e for e in self.rep["evidence_records"] if e["event_id"] == item["evidence"][0])
        src, dst = item["entities"]
        self.assertIn(src, rec["original"])
        self.assertIn(dst, rec["original"])

    def test_no_scan_needed_and_gaps_say_what_is_unknown(self):
        status = {i["original_name"]: i["status"] for i in self.rep["inputs"]}
        self.assertEqual(status["northfold_scan.nessus"], "rejected")
        self.assertEqual(status["conn.log"], "parsed")
        gaps = " ".join(g["text"] for g in self.rep["gaps"])
        self.assertIn("vulnerability status of the hosts is unknown", gaps)
        self.assertIn("unknown, not absent", gaps)

    def test_inferred_link_is_labelled(self):
        inferred = [f for f in self.rep["findings"] if f["rule_id"] == "INC-NET-003"]
        self.assertTrue(inferred)
        for f in inferred:
            self.assertEqual((f["kind"], f["basis"]), ("inferred", "time_proximity"))

    def test_uid_links_are_direct(self):
        self.assertGreater(self.rep["links"]["same_id_total"], 0)
        self.assertTrue(all(lk["basis"] == "same_id" for lk in self.rep["links"]["examples"]))

    def test_nothing_says_a_login_succeeded(self):
        text = json.dumps([self.rep["timeline"], self.rep["findings"]]).lower()
        for word in ("logged on", "logged in", "login succeeded", "successful login", "compromised"):
            self.assertNotIn(word, text)

    def test_same_evidence_same_report(self):
        again = run(self.case, "tester")
        self.assertTrue(again["reused"])
        forced = run(self.case, "tester", force=True)
        self.assertEqual(forced["version"], self.out["version"] + 1)
        a, b = self.rep, report(forced["folder"])
        for r in (a, b):
            for k in ("generated", "version", "report_id"):
                r.pop(k)
        self.assertEqual(a, b)
        self.assertEqual(cases.verify_audit(self.case), [])

    def test_html_links_every_cited_event(self):
        with open(os.path.join(self.out["folder"], "incident_report.html"), encoding="utf-8") as fh:
            page = fh.read()
        for f in self.rep["findings"]:
            for eid in f["evidence"]:
                self.assertIn(f'href="#ev-{eid}"', page)
                self.assertIn(f'id="ev-{eid}"', page)


class Evidence(Base):
    def test_duplicate_stored_once_and_audited(self):
        c = self.new_case()
        path = self.write("conn.log", CONN_HEAD + conn(1700000000, "C1", "10.0.0.1", 5000, "10.0.0.2", 22))
        copy = self.write("renamed.log", open(path).read())
        rec, new = cases.add_evidence(c, path, "tester")
        rec2, new2 = cases.add_evidence(c, copy, "someone")
        self.assertTrue(new)
        self.assertFalse(new2)
        self.assertEqual(rec["evidence_id"], rec2["evidence_id"])
        self.assertEqual(len(c.evidence()), 1)
        self.assertEqual(c.evidence()[0]["duplicate_uploads"][0]["uploaded_by"], "someone")
        with open(c.path("audit.jsonl"), encoding="utf-8") as fh:
            actions = [json.loads(l)["action"] for l in fh]
        self.assertEqual(actions, ["case_created", "evidence_stored", "evidence_duplicate"])

    def test_original_is_read_only_and_matches_its_hash(self):
        c = self.new_case()
        rec, _ = cases.add_evidence(c, self.write("conn.log", CONN_HEAD), "tester")
        stored = c.evidence_path(rec)
        self.assertEqual(stat.S_IMODE(os.stat(stored).st_mode), stat.S_IRUSR)
        self.assertEqual(cases.sha256_file(stored)[0], rec["sha256"])

    def test_size_limit(self):
        c = self.new_case()
        with self.assertRaises(UserError):
            cases.add_evidence(c, self.write("big.log", "x" * 2000), "tester", max_bytes=1000)
        self.assertEqual(c.evidence(), [])

    def test_audit_edit_or_removal_is_detected(self):
        c = self.new_case()
        cases.add_evidence(c, self.write("conn.log", CONN_HEAD), "tester")
        cases.add_evidence(c, self.write("dns.log", CONN_HEAD.replace("conn", "dns")), "tester")
        self.assertEqual(cases.verify_audit(c), [])
        with open(c.path("audit.jsonl"), encoding="utf-8") as fh:
            lines = fh.readlines()
        edited = list(lines)
        edited[1] = edited[1].replace('"tester"', '"intruder"')
        with open(c.path("audit.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(edited)
        self.assertTrue(any("edited" in p for p in cases.verify_audit(c)))
        with open(c.path("audit.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines([lines[0], lines[2]])
        self.assertTrue(any("removed or changed" in p for p in cases.verify_audit(c)))

    def test_window_needs_a_zone(self):
        with self.assertRaises(UserError):
            self.new_case(start="2026-11-18T06:00:00")
        with self.assertRaises(UserError):
            self.new_case(name="b", start="2026-11-19T00:00:00Z", end="2026-11-18T00:00:00Z")


class Robustness(Base):
    def test_damaged_files_keep_what_can_be_read(self):
        c = self.new_case()
        good = conn(1700000000, "C1", "10.0.0.1", 5000, "10.0.0.2", 22)
        text = CONN_HEAD + good + "garbage line without tabs\n" + good.replace("C1", "C2")
        cases.add_evidence(c, self.write("conn.log", text), "tester")
        raw = gzip.compress((CONN_HEAD + good.replace("C1", "C3") * 50).encode())
        with open(os.path.join(self.tmp, "in", "conn.cut.log.gz"), "wb") as fh:
            fh.write(raw[: len(raw) // 2])                  # truncated gzip
        cases.add_evidence(c, os.path.join(self.tmp, "in", "conn.cut.log.gz"), "tester")
        cases.add_evidence(c, self.write("notes.docx", "not a log"), "tester")
        out = run(c, "tester")
        rep = report(out["folder"])
        by = {i["original_name"]: i for i in rep["inputs"]}
        self.assertEqual(by["conn.log"]["status"], "parsed_with_errors")
        self.assertEqual(by["conn.log"]["rejects"], [{"locator": "line:6", "reason": "column count mismatch"}])
        self.assertEqual(by["conn.log"]["events"], 2)
        self.assertIn(by["conn.cut.log.gz"]["status"], ("parsed_with_errors", "failed"))
        self.assertIn("reading stopped", by["conn.cut.log.gz"]["status_detail"])
        self.assertEqual(by["notes.docx"]["status"], "rejected")
        self.assertTrue(any(g["type"] == "unreadable_records" for g in rep["gaps"]))

    def test_scope_window_and_untimed(self):
        c = self.new_case(scope_nets=["10.1.0.0/16"], start="2023-11-14T22:00:00Z", end="2023-11-14T23:00:00Z",
                          margin_minutes=0)
        rows = (conn(1700000000, "A", "10.1.0.5", 1, "8.8.8.8", 53, proto="udp")      # 22:13 in scope
                + conn(1700000000, "B", "10.9.0.5", 1, "8.8.8.8", 53, proto="udp")    # out of scope
                + conn(1700050000, "C", "10.1.0.5", 1, "8.8.8.8", 53, proto="udp")    # outside window
                + conn("-", "D", "10.1.0.5", 1, "8.8.8.8", 53, proto="udp"))          # no time
        cases.add_evidence(c, self.write("conn.log", CONN_HEAD + rows), "tester")
        rep = report(run(c, "tester")["folder"])
        self.assertEqual(rep["scope"]["filtered"], {"events_total": 4, "out_of_scope": 1, "outside_window": 1,
                                                    "untimed": 1, "kept": 1})
        self.assertEqual(len(rep["timeline"]), 1)
        self.assertEqual(rep["untimed"]["count"], 1)
        self.assertEqual(rep["untimed"]["examples"][0]["locator"], "line:8")

    def test_rules_on_synthetic_scan_and_return(self):
        c = self.new_case()
        rows = "".join(conn(1700000000 + p, f"S{p}", "203.0.113.9", 4000, "10.0.0.7", p, state="REJ", ob=0, rb=0)
                       for p in range(1, 31))
        rows += conn(1700001000, "I1", "198.51.100.4", 5555, "10.0.0.8", 443)
        rows += conn(1700001300, "O1", "10.0.0.8", 6000, "198.51.100.4", 8443)
        cases.add_evidence(c, self.write("conn.log", CONN_HEAD + rows), "tester")
        rep = report(run(c, "tester")["folder"])
        rules = {f["rule_id"]: f for f in rep["findings"]}
        self.assertIn("30 ports", rules["INC-NET-001"]["statement"])
        self.assertIn("completed on 0", rules["INC-NET-001"]["statement"])
        ret = rules["INC-NET-003"]
        self.assertEqual(ret["kind"], "inferred")
        self.assertIn("5.0 minutes", ret["statement"])

    def test_upload_order_does_not_change_the_report(self):
        a = self.write("conn.log", CONN_HEAD + conn(1700000000, "A", "10.0.0.1", 1, "10.0.0.2", 22))
        b = self.write("dns.log", "#separator \\x09\n#path\tdns\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\t"
                       "id.resp_p\tquery\n1700000001\tA\t10.0.0.1\t1\t10.0.0.2\t53\texample.org\n")
        reps = []
        for name, order in (("one", [a, b]), ("two", [b, a])):
            c = self.new_case(name)
            for f in order:
                cases.add_evidence(c, f, "tester")
            r = report(run(c, "tester")["folder"])
            for k in ("generated", "report_id"):
                r.pop(k)
            r["case"].pop("case_id")
            r["inputs"].sort(key=lambda i: i["sha256"])
            for i in r["inputs"]:
                i.pop("uploaded_at")
            reps.append(r)
        self.assertEqual(reps[0], reps[1])


class ZeekLocators(unittest.TestCase):
    def test_locators_point_at_the_line(self):
        path = os.path.join(ARTEX, "conn.log")
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        seen = 0
        for loc, stream, rec in zeek.records(path, ParseStats(file="", fmt="zeek")):
            n = int(loc.split(":")[1])
            self.assertIn(rec["uid"], lines[n - 1])
            seen += 1
            if seen > 50:
                break
        self.assertEqual(stream, "conn")


class Cli(Base):
    def test_commands(self):
        folder = os.path.join(self.tmp, "c")
        path = self.write("conn.log", CONN_HEAD + conn(1700000000, "C9", "10.0.0.1", 5000, "10.0.0.2", 22))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli(["incident", "new", folder, "--name", "CLI case", "--actor", "bay"]), 0)
            self.assertEqual(cli(["incident", "add", folder, path, "--actor", "bay"]), 0)
            self.assertEqual(cli(["incident", "run", folder, "--actor", "bay"]), 0)
            self.assertEqual(cli(["incident", "verify", folder]), 0)
        c = cases.open_case(folder)
        from vulnflow.incident.run import baselines
        rep = report(baselines(c)[-1][1])
        eid = rep["timeline"][0]["evidence"][0]
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli(["incident", "record", folder, eid, "--actor", "bay"]), 0)
        self.assertIn("C9", out.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli(["incident", "record", folder, "0" * 20]), 2)
        with open(c.path("audit.jsonl"), encoding="utf-8") as fh:
            self.assertIn("evidence_viewed", fh.read())


if __name__ == "__main__":
    unittest.main()
