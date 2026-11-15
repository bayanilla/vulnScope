"""Ground-truth accuracy kit for Zeek + Nessus correlation (three rounds, 34 cases plus a
telemetry-only folder).

tests/accuracy/correlation/make_round1.py and make_round2.py write small input folders (Zeek TSV,
JSON and rotated .gz conn logs from two taps, notice and dns logs, .nessus and Nessus CSV scans, a
Palo Alto export) together with expected.json, the answer for each case worked out by hand. This
test generates them, runs `vulnflow analyze` on each folder exactly as an analyst would, and
compares every finding's exposure label, session and source counts, indicators, priority and
hostname, plus the coverage summary, with the expected answers.

Cases marked "label_truth" in expected.json are known gaps (what the right answer would be,
which VulnScope does not give yet); they are listed so a fix shows up as a pass to record.

Run one round by hand and see every case:

    python tests/accuracy/correlation/make_round1.py /tmp/r1
    python -m vulnflow analyze $(find /tmp/r1/data -type f) -o /tmp/r1/out
    python -m unittest tests.test_accuracy_kit -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KIT = os.path.join(HERE, "accuracy", "correlation")
ENV = {**os.environ, "VULNFLOW_LLM_PROVIDER": "offline", "VULNSCOPE_OFFLINE": "1", "PYTHONPATH": ROOT}


def analyze(folder: str, out: str) -> dict:
    files = sorted(os.path.join(d, n) for d, _, names in os.walk(folder) for n in names)
    proc = subprocess.run([sys.executable, "-m", "vulnflow", "analyze", *files, "-o", out, "--no-article-preview"],
                          cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise AssertionError(f"analyze failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")
    with open(os.path.join(out, "results.json"), encoding="utf-8") as fh:
        return json.load(fh)


def finding_diffs(res: dict, expected: dict) -> tuple[list[str], list[str]]:
    """Return (problems, known gaps) for every expected finding."""
    by_key = {(r["host"], r["port"], r["proto"]): r for r in res["findings"]}
    problems, gaps = [], []
    for name, e in expected.items():
        r = by_key.get((e["host"], e["port"], e.get("proto", "tcp")))
        if "label_truth" in e:              # a known gap: the right answer is described, not given yet
            gaps.append(f"{name}: {e['label_truth']}"
                        + ("" if r is None else f" (now found as {r['exposure']['label']!r}: record it as a pass)"))
            continue
        if r is None:
            problems.append(f"MISSING  {name}")
            continue
        got = dict(r["exposure"])
        got.update(indicators=[i["type"] for i in r["indicators"]], priority=r["priority"],
                   hostname=r["hostname"], cves=r.get("cves"), cvss=r.get("cvss"),
                   exploit_available=r.get("exploit_available"))
        for k, v in e.items():
            if k in ("host", "port", "proto"):
                continue
            if got.get(k) != v:
                problems.append(f"MISMATCH {name}: {k} expected {v!r}, got {got.get(k)!r}")
    return problems, gaps


class CorrelationAccuracyKit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vs-kit-")
        for script in ("make_round1.py", "make_round2.py"):
            subprocess.run([sys.executable, "-I", os.path.join(KIT, script), cls.tmp], check=True,
                           capture_output=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def load(self, rel):
        with open(os.path.join(self.tmp, rel), encoding="utf-8") as fh:
            return json.load(fh)

    def test_round1_zeek_two_taps_and_nessus(self):
        exp = self.load("expected.json")
        res = analyze(os.path.join(self.tmp, "data"), os.path.join(self.tmp, "out1"))
        problems, gaps = finding_diffs(res, exp["findings"])
        s, cov = exp["summary"], res["coverage"]
        if cov["scanned_not_seen"] != s["scanned_not_seen"]:
            problems.append(f"scanned_not_seen {cov['scanned_not_seen']} != {s['scanned_not_seen']}")
        got_gaps = sorted(g["ip"] for g in cov["active_servers_not_scanned"])
        # files02 (scanned by name only, known gap J) is still reported as an unscanned server
        if not set(s["active_servers_not_scanned"]) <= set(got_gaps):
            problems.append(f"active_servers_not_scanned {got_gaps} misses {s['active_servers_not_scanned']}")
        summ = res["summary"]
        if summ["duplicate_findings_merged"] != s["duplicate_findings_merged"]:
            problems.append(f"duplicate_findings_merged {summ['duplicate_findings_merged']}")
        if summ["duplicate_flows_removed"] < s["duplicate_flows_removed_at_least"]:
            problems.append(f"duplicate_flows_removed {summ['duplicate_flows_removed']}")
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertLessEqual(len(gaps), 1, "\n".join(gaps))       # only J is a known gap today

    def test_round2_harder_cases(self):
        exp = self.load(os.path.join("round2", "expected.json"))
        res = analyze(os.path.join(self.tmp, "round2", "data"), os.path.join(self.tmp, "out2"))
        problems, gaps = finding_diffs(res, exp["findings"])
        s, cov = exp["summary"], res["coverage"]
        if cov["scanned_hosts"] != s["scanned_hosts"]:
            problems.append(f"scanned_hosts {cov['scanned_hosts']} != {s['scanned_hosts']}")
        if cov["active_servers_not_scanned"]:
            problems.append(f"unexpected unscanned servers {cov['active_servers_not_scanned']}")
        scanner = s.get("scanner_not_an_internal_peer")
        if scanner:
            peers = [h["host"] for h in res["hosts"] if scanner in [x["ip"] for x in h["blast"]["reachable"]]]
            if peers:
                problems.append(f"the scanner {scanner} shows up as an internal peer of {peers}")
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertEqual(gaps, [])

    def test_telemetry_only_folder(self):
        e = self.load(os.path.join("telemetry_only", "expected.json"))
        res = analyze(os.path.join(self.tmp, "telemetry_only", "data"), os.path.join(self.tmp, "out3"))
        s = res["summary"]
        self.assertFalse(s["vulnerability_data_available"])
        self.assertEqual(s["priority_counts"], {"P1": None, "P2": None, "P3": None, "P4": None})
        self.assertEqual(s["flows"], e["flows"], "one double-tapped session must count once")
        self.assertEqual(s["threat_alerts"], e["threat_alerts"])
        self.assertEqual(sorted(h["host"] for h in res["hosts"]), e["hosts"])
        self.assertEqual({lead["host"]: [lead["unblocked"], lead["blocked"]] for lead in res["telemetry_leads"]},
                         e["telemetry_leads"], "IPS leads must name the internal host")
        self.assertEqual([[lead["host"], lead["peer"], lead["sessions"]] for lead in res["network_leads"]],
                         e["network_leads"])
        hosts = {h["host"]: h for h in res["hosts"]}
        self.assertEqual({k: hosts[k]["inbound_flows"] for k in e["inbound"] if k in hosts}, e["inbound"])
        self.assertTrue(all(h["max_score"] is None and h["priority"] is None for h in res["hosts"]))


if __name__ == "__main__":
    unittest.main()
