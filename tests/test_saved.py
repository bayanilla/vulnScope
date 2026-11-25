"""Reopening a saved results.json (and explorer.html) from the upload page."""
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import unittest.mock
import urllib.parse
from http.server import ThreadingHTTPServer

from vulnflow import explore, saved
from vulnflow.correlate import RESULTS_SCHEMA_VERSION, Config
from vulnflow.pipeline import run
from vulnflow.samples import generate
from vulnflow.web import SAVED_SANDBOX, make_handler


class SavedRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "first_run")
        run(generate(os.path.join(cls.tmp, "in")), cls.out)
        with open(os.path.join(cls.out, "results.json"), "rb") as fh:
            cls.results = fh.read()
        with open(os.path.join(cls.out, "explorer.html"), "rb") as fh:
            cls.explorer = fh.read()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(cls.tmp, "runs"), Config()))
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, True)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, data, resp

    def post_folder(self, folder, action="/analyze-folder"):
        token = re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]
        body = urllib.parse.urlencode({"csrf": token, "path": folder})
        return self.request("POST", action, body, {"Content-Type": "application/x-www-form-urlencoded"})

    def opened(self, folder, action="/analyze-folder"):
        status, page, resp = self.post_folder(folder, action)
        self.assertEqual(status, 303, page)
        return resp.getheader("Location")

    def copy(self, name, edit=None):
        """A copy of the first run's output folder, optionally edited."""
        folder = os.path.join(self.tmp, name)
        shutil.copytree(self.out, folder)
        if edit:
            edit(folder)
        return folder

    def test_report_folder_reopens_without_reanalyzing(self):
        before = os.listdir(self.out)
        here = self.opened(self.out)
        self.assertEqual(sorted(os.listdir(self.out)), sorted(before))       # folder left as it was
        status, index, _ = self.request("GET", here)
        self.assertEqual(status, 200)
        self.assertIn("Saved report reopened from", index)
        for name in ("explorer.html", "normalized/flows.csv", "normalized/findings.csv", "correlated_findings.csv"):
            self.assertIn(name, index)
        for name in ("executive_summary.html", "technical_report.html", "explorer.html", "correlated_findings.csv",
                     "normalized/flows.csv"):
            status, _, resp = self.request("GET", here + name)
            self.assertEqual(status, 200, name)
            self.assertIn(SAVED_SANDBOX, resp.getheader("Content-Security-Policy"), name)
        with open(os.path.join(self.out, "normalized", "flows.csv"), encoding="utf-8", newline="") as fh:
            self.assertEqual(self.request("GET", here + "normalized/flows.csv")[1], fh.read())
        page = self.request("GET", here + "explorer.html")[1]
        old = explore.read_data(self.explorer.decode())
        new = explore.read_data(page)
        self.assertEqual(old["nodes"], new["nodes"])
        self.assertEqual(old["links"], new["links"])
        self.assertEqual(json.loads(self.request("GET", here + "results.json")[1]), json.loads(self.results))

    def test_page_can_tell_a_report_folder_from_a_data_folder(self):
        token = re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]

        def kind(path, csrf=token):
            status, body, _ = self.request("POST", "/folder-kind", json.dumps({"csrf": csrf, "path": path}),
                                           {"Content-Type": "application/json"})
            return status, json.loads(body)
        self.assertEqual(kind(self.out), (200, {"report": True}))
        self.assertEqual(kind(os.path.join(self.tmp, "in")), (200, {"report": False}))
        self.assertEqual(kind(os.path.join(self.tmp, "missing")), (200, {"report": False}))
        self.assertEqual(kind(""), (200, {"report": False}))
        self.assertEqual(kind(self.out, "wrong")[0], 403)

    def test_only_listed_files_are_served_from_the_folder(self):
        folder = self.copy("extra", lambda f: open(os.path.join(f, "secret.txt"), "w").write("x"))
        here = self.opened(folder)
        for name in ("secret.txt", "../secret.txt", "normalized/../secret.txt", "%2e%2e/%2e%2e/etc/passwd"):
            self.assertEqual(self.request("GET", here + name)[0], 404, name)

    def test_folder_without_explorer_opens_reports_and_says_why(self):
        here = self.opened(self.copy("no_explorer", lambda f: os.remove(os.path.join(f, "explorer.html"))))
        index = self.request("GET", here)[1]
        self.assertIn("no <code>explorer.html</code>", index)
        self.assertEqual(self.request("GET", here + "explorer.html")[0], 404)
        self.assertEqual(self.request("GET", here + "technical_report.html")[0], 200)

    def test_fresh_runs_are_not_sandboxed(self):
        self.assertEqual(json.loads(self.results)["schema_version"], RESULTS_SCHEMA_VERSION)
        os.makedirs(os.path.join(self.tmp, "runs", "a" * 16, "out"), exist_ok=True)
        shutil.copy(os.path.join(self.out, "technical_report.html"), os.path.join(self.tmp, "runs", "a" * 16, "out"))
        _, _, resp = self.request("GET", f"/runs/{'a' * 16}/technical_report.html")
        self.assertNotIn("sandbox", resp.getheader("Content-Security-Policy"))

    def assertRefused(self, folder, message):
        runs = os.path.join(self.tmp, "runs")
        before = set(os.listdir(runs)) if os.path.isdir(runs) else set()
        status, page, _ = self.post_folder(folder)
        self.assertEqual(status, 200)
        self.assertIn(message, page)
        self.assertEqual(set(os.listdir(runs)) - before if os.path.isdir(runs) else set(), set())   # nothing left behind

    def test_reopened_explorer_loads_full_host_lists(self):
        # A busy host's lists are cut in the page; the server hands the page the full ones, also to a
        # reopened report's page in its opaque origin, and only with this server's token.
        data = explore.read_data(self.explorer.decode())
        host = next(ip for ip, f in data["focus"].items() if len(f["attackers"]) < f["attackers_total"])
        cut = data["focus"][host]
        here = self.opened(self.out)
        page = self.request("GET", here + "explorer.html")[1]
        where = re.search(r'<meta name="vulnscope-contacts" content="(contacts/[0-9a-f]{32}/)">', page)[1]
        status, body, resp = self.request("GET", here + where + host, headers={"Origin": "null"})
        self.assertEqual(status, 200, body)
        self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), "null")
        full = json.loads(body)
        self.assertEqual(len(full["attackers"]), cut["attackers_total"])
        self.assertEqual(len(full["peers"]), cut["peers_total"])
        n = explore.MAX_LIST
        self.assertEqual([a["ip"] for a in full["attackers"][:n]], [a["ip"] for a in cut["attackers"][:n]])
        self.assertEqual(full["attackers"][:explore.MAX_LIST_EXAMPLES], cut["attackers"][:explore.MAX_LIST_EXAMPLES])
        self.assertTrue(any(a["connection_examples"] for a in full["attackers"][n:]))
        self.assertEqual(self.request("GET", here + "contacts/" + "0" * 32 + "/" + host)[0], 404)
        # saved without the flow copies: the page is told the full lists are not there
        bare = self.copy("no-contacts", lambda f: os.remove(os.path.join(f, explore.CONTACTS_FILE)))
        page = self.request("GET", self.opened(bare) + "explorer.html")[1]
        self.assertIn('<meta name="vulnscope-contacts" content="">', page)

    def test_reopened_explorer_searches_full_host_lists(self):
        # The host search asks the server for addresses past the page's cut lists: a full IP matches
        # exactly, a partial one from its start, a.b.c.d/n by range; anything else is refused.
        data = explore.read_data(self.explorer.decode())
        host = next(ip for ip, f in data["focus"].items() if len(f["attackers"]) < f["attackers_total"])
        here = self.opened(self.out)
        page = self.request("GET", here + "explorer.html")[1]
        where = re.search(r'<meta name="vulnscope-contacts" content="(contacts/[0-9a-f]{32}/)">', page)[1]
        full = json.loads(self.request("GET", here + where + host)[1])
        hidden = full["attackers"][-1]["ip"]           # in the full list only
        self.assertNotIn(hidden, [a["ip"] for a in data["focus"][host]["attackers"]])

        def search(q):
            status, body, resp = self.request("GET", here + where + "search/" + q, headers={"Origin": "null"})
            self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), "null")
            return status, body
        status, body = search(hidden)
        self.assertEqual(status, 200, body)
        found = {h: (side, ip) for h, side, ip, _ in json.loads(body)["hosts"]}
        self.assertEqual(found[host], ("a", hidden))
        octets = hidden.split(".")
        for q in (".".join(octets[:3]) + ".", ".".join(octets[:3]) + ".0/24"):
            self.assertIn(host, {h for h, *_ in json.loads(search(q)[1])["hosts"]}, q)
        for q in ("abc", "x' OR 1=1", "1.2.3.4/40", "1.2.3.999/8"):
            self.assertEqual(search(q.replace(" ", "%20"))[0], 400, q)
        self.assertEqual(self.request("GET", here + "contacts/" + "0" * 32 + "/search/" + hidden)[0], 404)

    def test_bad_folders_are_refused_with_a_reason(self):
        res = json.loads(self.results)

        def results(obj):
            def edit(f):
                with open(os.path.join(f, "results.json"), "wb") as fh:
                    fh.write(obj if isinstance(obj, bytes) else json.dumps(obj).encode())
            return edit

        def explorer(text):
            return lambda f: open(os.path.join(f, "explorer.html"), "wb").write(text)

        self.assertRefused(self.copy("b1", results(b"{not json")), "not valid JSON")
        self.assertRefused(self.copy("b2", results(b'{"a":' * 100000 + b"1" + b"}" * 100000)), "nested too deeply")
        self.assertRefused(self.copy("b3", results({**res, "schema_version": RESULTS_SCHEMA_VERSION + 1})), "newer VulnScope")
        self.assertRefused(self.copy("b4", results({**res, "hosts": "x"})), "&quot;hosts&quot; is missing")
        self.assertRefused(self.copy("b5", results({**res, "findings": [{"host": "10.0.0.1"}]})), "can&#x27;t be drawn")
        other = explore.html({**explore.read_data(self.explorer.decode()), "generated": "2001-01-01T00:00:00Z"}).encode()
        self.assertRefused(self.copy("b6", explorer(other)), "different analysis")
        self.assertRefused(self.copy("b7", explorer(b"<!doctype html><p>hi")), "not a VulnScope Explorer page")

    def test_results_without_schema_version_still_open(self):
        res = json.loads(self.results)
        del res["schema_version"]
        self.opened(self.copy("legacy", lambda f: open(os.path.join(f, "results.json"), "w").write(json.dumps(res))))

    def test_oversized_results_are_refused(self):
        with unittest.mock.patch.object(saved, "MAX_SAVED_FILE", 1000):
            self.assertRefused(self.out, "too large to reopen")


if __name__ == "__main__":
    unittest.main()
