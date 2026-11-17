"""A folder with a sites list (sites.csv): one report per site, then a comparison of them (sites.py),
so two companies analyzed from one folder stay two networks."""
import contextlib
import http.client
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from vulnflow import cli, sites
from vulnflow.correlate import Config
from vulnflow.errors import UserError

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "compare_two_companies")
OFFLINE = mock.patch("vulnflow.article_preview.fetch_preview", side_effect=AssertionError("went online"))


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def two_sites(root):
    """A small folder holding one site of each sample company, and its sites list."""
    shutil.copytree(os.path.join(SAMPLE, "ridgeline", "tampa"), os.path.join(root, "tampa"))
    shutil.copytree(os.path.join(SAMPLE, "corvane", "dresden"), os.path.join(root, "dresden"))
    write(os.path.join(root, "sites.csv"), "folder,name,network\ntampa,Tampa office,Ridgeline\n"
                                           "dresden,Dresden service center,Corvane\n")
    return root


class SitesListTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for d in ("a", "b"):
            os.makedirs(os.path.join(self.root, d))

    def read(self, text):
        write(os.path.join(self.root, "sites.csv"), text)
        return sites.read(sites.find(self.root))

    def test_reads_names_networks_and_defaults(self):
        got = self.read("Folder,Site,Company,Notes\na/,Alpha  office,Acme,first\nb,,,\n")
        self.assertEqual([(os.path.basename(s.folder), s.name, s.network, s.description) for s in got],
                         [("a", "Alpha office", "Acme", "first"), ("b", "b", "", "")])
        self.assertEqual(got[0].folder, os.path.realpath(os.path.join(self.root, "a")))

    def test_network_defaults_to_the_company_folder(self):
        for d in ("acme/hq", "acme/plant", "globex/hq"):
            os.makedirs(os.path.join(self.root, d))
        got = self.read("folder,network\nacme/hq,\nacme/plant,Acme Corp\nglobex/hq\na\n")
        self.assertEqual([(s.name, s.network) for s in got],
                         [("hq", "acme"), ("plant", "Acme Corp"), ("hq", "globex"), ("a", "")])

    def test_skips_comments_blank_lines_and_a_byte_order_mark(self):
        got = self.read("﻿folder,name\n# the plant is next quarter\n\n,\nb,Bravo\n")
        self.assertEqual([s.name for s in got], ["Bravo"])

    def test_refuses_a_list_it_cannot_use(self):
        for text, words in [
            ("", "is empty"),
            ("name,network\nA,Acme\n", "needs a 'folder' column"),
            ("folder\n", "lists no sites"),
            ("folder\nmissing\n", "line 2: folder 'missing' not found"),
            ("folder,name\n,Nameless\n", "line 2: '' must be a folder inside"),
            ("folder\n../a\n", "must be a folder inside"),
            ("folder\n/etc\n", "must be a folder inside"),
            ("folder\n.\n", "must be a folder inside"),
            ("folder\na\n./a/\n", "line 3: folder './a/' is already listed on line 2"),
        ]:
            with self.subTest(text=text), self.assertRaisesRegex(UserError, re.escape(words)):
                self.read(text)

    def test_refuses_more_sites_than_one_analysis_takes(self):
        for i in range(sites.MAX_SITES + 1):
            os.makedirs(os.path.join(self.root, f"s{i}"))
        self.assertEqual(len(self.read("folder\n" + "".join(f"s{i}\n" for i in range(sites.MAX_SITES)))),
                         sites.MAX_SITES)
        with self.assertRaisesRegex(UserError, f"lists {sites.MAX_SITES + 1} sites; at most {sites.MAX_SITES}"):
            self.read("folder\n" + "".join(f"s{i}\n" for i in range(sites.MAX_SITES + 1)))

    def test_a_link_out_of_the_folder_is_refused(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        os.symlink(outside, os.path.join(self.root, "link"))
        with self.assertRaisesRegex(UserError, "must be a folder inside"):
            self.read("folder\nlink\n")

    def test_found_in_any_letter_case_and_only_at_the_top(self):
        self.assertIsNone(sites.find(self.root))
        self.assertIsNone(sites.find(os.path.join(self.root, "missing")))
        write(os.path.join(self.root, "Sites.CSV"), "folder\na\n")
        self.assertEqual(os.path.basename(sites.find(self.root)), "Sites.CSV")
        self.assertIsNone(sites.find(os.path.join(self.root, "a")))

    def test_plan_shares_top_level_lists_and_refuses_loose_logs(self):
        write(os.path.join(self.root, "a", "conn.log"), "x")
        write(os.path.join(self.root, "b", "deep", "conn.log"), "x")
        write(os.path.join(self.root, "b", "runs", "old", "conn.log"), "x")        # the data folder: skipped
        write(os.path.join(self.root, "b", ".hidden", "conn.log"), "x")
        write(os.path.join(self.root, "network_map.csv"), "cidr,name,type\n10.0.0.0/8,LAN,onprem\n")
        write(os.path.join(self.root, "known_scanners.csv"), "10.0.0.5,Nessus\n")
        write(os.path.join(self.root, "feed.csv"), "type,value\nip,198.51.100.7\n")
        write(os.path.join(self.root, "README.md"), "notes")
        write(os.path.join(self.root, ".DS_Store"), "x")
        write(os.path.join(self.root, "sites.csv"), "folder\na\nb\n")
        plan = sites.plan(self.root, os.path.join(self.root, "b", "runs"))
        rel = [sorted(os.path.relpath(f, self.root) for f in files) for _, files in plan]
        shared = ["feed.csv", "known_scanners.csv", "network_map.csv"]
        self.assertEqual(rel, [sorted(["a/conn.log"] + shared), sorted(["b/deep/conn.log"] + shared)])
        write(os.path.join(self.root, "conn.log"), "x")
        with self.assertRaisesRegex(UserError, r"conn.log is directly in .*put each site's logs"):
            sites.plan(self.root, os.path.join(self.root, "runs"))


class SitesAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with OFFLINE, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_two_company_sample_is_two_networks_of_site_reports(self):
        data = os.path.join(self.tmp, "web")
        code, out, err = self.cli("analyze-sites", SAMPLE, "--data-dir", data)
        self.assertEqual(code, 0, err)
        runs = re.findall(r"/runs/([^/\s]+)/", out)
        cid = re.search(r"/compare/([^/\s]+)/", out)[1]
        self.assertEqual([r.split("_")[0] for r in runs],
                         ["Ridgeline-Denver-office", "Ridgeline-Tampa-office", "Corvane-HQ", "Corvane-Phoenix-plant",
                          "Corvane-Austin-design-center", "Corvane-Dresden-service-center"])
        for run_id in runs:
            with open(os.path.join(data, run_id, "out", "results.json"), encoding="utf-8") as fh:
                report = json.load(fh)["report"]
            self.assertEqual(report["network"], report["name"].split()[0])
            with open(os.path.join(data, run_id, "in", "SOURCE.txt"), encoding="utf-8") as fh:
                self.assertNotIn("sites.csv", fh.read())
        folder = os.path.join(data, "comparisons", cid)
        with open(os.path.join(folder, "comparison.json"), encoding="utf-8") as fh:
            result = json.load(fh)
        self.assertEqual((result["summary"]["reports"], result["summary"]["networks"]), (6, 2))
        self.assertGreaterEqual(result["summary"]["found_by_hunt"], 1)       # Dresden's egress, as in compare-sample
        with open(os.path.join(folder, "explorer.json"), encoding="utf-8") as fh:
            explorer = json.load(fh)
        self.assertEqual(sorted({r["network"] for r in explorer["combined"]["reports"]}), ["Corvane", "Ridgeline"])
        # both companies run a 10.20.0.10: one host per site, never merged across the two companies
        nets = [explorer["combined"]["reports"][int(n["id"].rsplit("@", 1)[1])]["network"]
                for n in explorer["nodes"] if n["id"].startswith("10.20.0.10@")]
        self.assertEqual(sorted(set(nets)), ["Corvane", "Ridgeline"])

    def test_plain_analyze_names_the_sites_command_and_ignores_the_list(self):
        folder = two_sites(os.path.join(self.tmp, "two"))
        code, out, err = self.cli("analyze", folder, "-o", os.path.join(self.tmp, "out"))
        self.assertEqual(code, 0, err)
        self.assertIn("vulnflow analyze-sites", err)
        with open(os.path.join(self.tmp, "out", "results.json"), encoding="utf-8") as fh:
            self.assertNotIn("sites.csv", [os.path.basename(i["file"]) for i in json.load(fh)["inputs"]])

    def test_a_site_that_cannot_be_analyzed_leaves_nothing_behind(self):
        folder = two_sites(os.path.join(self.tmp, "two"))
        os.makedirs(os.path.join(folder, "plant"))
        shutil.copy(os.path.join(SAMPLE, "corvane", "hq", "dns.log"), os.path.join(folder, "plant"))   # no flows
        os.makedirs(os.path.join(folder, "empty"))
        data = os.path.join(self.tmp, "web")
        for extra, words in (("plant,Plant 7", "Plant 7: "), ("empty,Empty site", "Empty site: no files found")):
            with open(os.path.join(folder, "sites.csv"), "a", encoding="utf-8") as fh:
                fh.write(extra + "\n")
            code, _, err = self.cli("analyze-sites", folder, "--data-dir", data)
            self.assertEqual(code, 2, err)
            self.assertIn(words, err)
            self.assertEqual([n for n in os.listdir(data) if n != "comparisons"], [])
            write(os.path.join(folder, "sites.csv"), "folder,name,network\ntampa,Tampa office,Ridgeline\n"
                                                     "dresden,Dresden service center,Corvane\n")
        code, _, err = self.cli("analyze-sites", os.path.join(self.tmp, "missing"), "--data-dir", data)
        self.assertEqual(code, 2)
        self.assertIn("folder not found", err)
        code, _, err = self.cli("analyze-sites", os.path.join(folder, "tampa"), "--data-dir", data)
        self.assertEqual(code, 2)
        self.assertIn("No sites list", err)


class WebSitesTests(unittest.TestCase):
    """Analyze folder on the upload page: a folder with a sites list opens the sites' comparison."""

    @classmethod
    def setUpClass(cls):
        from vulnflow.web import make_handler
        cls.tmp = tempfile.mkdtemp()
        cls.folder = two_sites(os.path.join(cls.tmp, "two"))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(cls.tmp, "runs"), Config()))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, True)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=120)
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.srv.server_port}", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, data, resp

    def csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]

    def kind(self, path):
        status, body, _ = self.request("POST", "/folder-kind", json.dumps({"csrf": self.csrf(), "path": path}),
                                       {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        return json.loads(body)

    def post(self, folder):
        body = urllib.parse.urlencode({"csrf": self.csrf(), "path": folder, "report_name": "Ignored"})
        return self.request("POST", "/analyze-folder", body, {"Content-Type": "application/x-www-form-urlencoded"})

    def test_page_says_what_a_sites_list_does(self):
        page = self.request("GET", "/")[1]
        self.assertIn('id="sites-msg"', page)
        self.assertIn("<code>sites.csv</code>", page)

    def test_page_counts_the_sites(self):
        self.assertEqual(self.kind(self.folder), {"report": False, "sites": 2})
        self.assertEqual(self.kind(os.path.join(self.folder, "tampa")), {"report": False})
        broken = os.path.join(self.tmp, "broken")
        write(os.path.join(broken, "sites.csv"), "folder\nnot_here\n")
        self.assertEqual(self.kind(broken), {"report": False, "sites": -1})

    def test_analyze_folder_opens_the_comparison_of_the_sites(self):
        with OFFLINE, contextlib.redirect_stderr(io.StringIO()):
            status, page, resp = self.post(self.folder)
        self.assertEqual(status, 303, page)
        cid = re.fullmatch(r"/compare/([^/]+)/", resp.getheader("Location"))[1]
        status, page, _ = self.request("GET", f"/compare/{cid}/")
        self.assertEqual(status, 200)
        for name in ("Tampa office", "Dresden service center", "Ridgeline", "Corvane"):
            self.assertIn(name, page)
        self.assertNotIn("Ignored", page)
        self.assertEqual(self.request("GET", f"/compare/{cid}/explorer.html")[0], 200)
        runs = sorted(n for n in os.listdir(os.path.join(self.tmp, "runs")) if n != "comparisons")
        self.assertEqual([r.split("_")[0] for r in runs], ["Dresden-service-center", "Tampa-office"])

    def test_a_broken_list_is_shown_on_the_page(self):
        broken = os.path.join(self.tmp, "broken2")
        write(os.path.join(broken, "sites.csv"), "folder\nnot_here\n")
        status, page, _ = self.post(broken)
        self.assertEqual(status, 200)
        self.assertIn("sites.csv line 2: folder &#x27;not_here&#x27; not found", page)


if __name__ == "__main__":
    unittest.main()
