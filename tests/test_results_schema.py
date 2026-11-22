"""results.json has one declared shape: every analysis fits it, the published copy matches the
code, and a saved file that breaks it is refused with a reason."""
import copy
import json
import os
import tempfile
import unittest

from vulnflow import saved
from vulnflow.pipeline import run
from vulnflow.results_schema import SCHEMA, as_json, problems

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _run(sample: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        folder = os.path.join(ROOT, "samples", sample)
        files = sorted(os.path.join(d, f) for d, _, fs in os.walk(folder) for f in fs
                       if not f.endswith((".md", ".json")))
        run(files, os.path.join(tmp, "out"))
        with open(os.path.join(tmp, "out", "results.json"), encoding="utf-8") as fh:
            return json.load(fh)


class Declared(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = _run("scan_and_telemetry")

    def test_published_copy_matches_the_code(self):
        with open(os.path.join(ROOT, "docs", "results.schema.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), as_json(), "run: python -m vulnflow.results_schema > docs/results.schema.json")

    def test_fresh_analyses_fit(self):
        self.assertEqual(problems(self.res), [])
        for sample in ("telemetry_only", "hosts_onprem_and_aws"):
            self.assertEqual(problems(_run(sample)), [], sample)

    def test_every_top_level_key_written_is_declared(self):
        self.assertEqual(sorted(set(self.res) - set(SCHEMA["properties"])), [])

    def test_wrong_types_and_missing_keys_are_named(self):
        bad = copy.deepcopy(self.res)
        bad["summary"]["flows"] = "many"
        bad["findings"][0]["score"] = True
        del bad["hosts"][0]["blast"]
        got = problems(bad)
        self.assertIn("results.json.summary.flows: expected integer, found str", got)
        self.assertIn("results.json.findings[0].score: expected integer, found bool", got)
        self.assertIn('results.json.hosts[0]: "blast" is missing', got)
        self.assertEqual(len(problems(bad, limit=1)), 1)

    def test_reopening_allows_missing_keys_but_not_wrong_types(self):
        older = copy.deepcopy(self.res)
        del older["coverage"], older["summary"]["traffic_scanners"]
        older["added_by_a_newer_copy"] = {"x": 1}
        self.assertIs(saved.check_results(older), older)
        bad = copy.deepcopy(self.res)
        bad["findings"][0]["exposure"] = "internet"
        with self.assertRaises(saved.SavedRunError) as ctx:
            saved.check_results(bad)
        self.assertIn("findings[0].exposure", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
