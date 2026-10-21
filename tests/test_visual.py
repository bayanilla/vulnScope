import os
import re
import tempfile
import unittest
import xml.dom.minidom

from vulnflow.correlate import Config, correlate
from vulnflow.diagram import blast_svg, hostile_activity_svg, hostile_graph
from vulnflow.normalize import load
from vulnflow.report import md_body, write_all
from vulnflow.samples import generate


class VisualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        files = generate(os.path.join(cls.tmp, "in"))
        cls.ds = load(files)
        cls.res = correlate(cls.ds, Config())

    def test_hostile_graph_edges_follow_evidence(self):
        nodes, edges = hostile_graph(self.res)
        kinds = {(e["src"], e["dst"], e["style"]) for e in edges}
        self.assertIn(("203.0.113.45", "10.10.1.10", "ips"), kinds)
        self.assertIn(("10.10.1.10", "203.0.113.45", "return"), kinds)
        self.assertIn(("10.10.1.10", "10.10.2.25", "spread"), kinds)
        self.assertEqual(sum(1 for e in edges if e["style"] == "ips-blocked" and e["dst"] == "10.10.3.31"), 3)
        self.assertEqual(nodes["10.10.1.10"]["ev"], "likely")
        self.assertEqual(nodes["10.10.3.31"]["ev"], "lead")

    def test_svgs_are_well_formed(self):
        xml.dom.minidom.parseString(hostile_activity_svg(self.res, standalone=True))
        for h in self.res["hosts"]:
            xml.dom.minidom.parseString(blast_svg(h, self.res, set()))

    def test_html_reports_have_visuals_and_valid_badges(self):
        out = os.path.join(self.tmp, "out")
        write_all(self.res, self.ds, out)
        with open(os.path.join(out, "technical_report.html"), encoding="utf-8") as fh:
            tech = fh.read()
        with open(os.path.join(out, "executive_summary.html"), encoding="utf-8") as fh:
            ex = fh.read()
        self.assertIn('class="findings"', tech)
        self.assertIn('class="why"', tech)
        self.assertIn("Blast radius map", tech)
        self.assertIn('class="tiles"', ex)
        self.assertIn("Hostile activity against vulnerable services", ex)
        self.assertTrue(os.path.exists(os.path.join(out, "hostile_activity.svg")))
        for page in (ex, tech):
            self.assertNotIn('">"', page)                      # no badge injected inside an attribute
            self.assertFalse(re.search(r'="[^"]*<span', page))   # no badge inside an attribute value
        # Markdown versions stay plain
        with open(os.path.join(out, "technical_report.md"), encoding="utf-8") as fh:
            self.assertNotIn("<span", fh.read())

    def test_italics_and_table_swap(self):
        self.assertIn("<em>Lead</em>", md_body("An *Lead*: x and 2 * 3 * 4"))
        self.assertNotIn("<em> 3 </em>", md_body("2 * 3 * 4"))
        h = md_body("## T\n\n| a |\n|---|\n| 1 |\n", {"T": [{"replace_table": "<p>X</p>"}]})
        self.assertIn("<p>X</p>", h)
        self.assertNotIn("<table>", h)


if __name__ == "__main__":
    unittest.main()
