import http.client
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from vulnflow import article_library
from vulnflow.pipeline import run
from vulnflow.correlate import Config
from vulnflow.samples import generate
from vulnflow.web import make_handler
from vulnflow.web.runs import ARTICLE_SANDBOX


class ArticleLibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.samples = generate(os.path.join(cls.tmp, "in"))
        lib = cls.lib = os.path.join(cls.tmp, "library")
        os.makedirs(os.path.join(lib, "pages"))
        for name, body in (("report.pdf", b"%PDF-1.4 saved"), ("report.html", b"<p>saved</p>"),
                           ("evil.sh", b"echo"), ("big.pdf", b"x")):
            with open(os.path.join(lib, "pages", name), "wb") as fh:
                fh.write(body)
        with open(os.path.join(cls.tmp, "outside.pdf"), "wb") as fh:
            fh.write(b"%PDF outside")
        with open(os.path.join(lib, article_library.LIBRARY_FILE), "w") as fh:
            json.dump({"version": 1, "articles": {
                "https://research.example/report": {"title": "Saved source report",
                                                    "files": ["pages/report.pdf", "pages/report.html",
                                                              "pages/evil.sh", "../outside.pdf", "pages/none.pdf"]},
                "javascript:alert(1)": {"files": ["pages/report.pdf"]}}}, fh)
        cls.archive = os.path.join(cls.tmp, "iocs.csv")
        with open(cls.archive, "w") as fh:
            fh.write("indicatorType,indicator,articleUrls\n"
                     "cve,CVE-2024-21887,https://research.example/report/\n"
                     "ip,8.8.8.8,https://research.example/not-saved\n")

    def test_read_keeps_only_safe_files_inside_the_library(self):
        _, articles = article_library.read(self.lib)
        self.assertEqual(list(articles), ["https://research.example/report"])
        self.assertEqual([os.path.basename(f) for f in articles["https://research.example/report"]["files"]],
                         ["report.pdf", "report.html"])

    def test_report_carries_saved_copies_offline(self):
        out = os.path.join(self.tmp, "out")
        with patch.dict(os.environ, {"VULNSCOPE_OFFLINE": "1", "VULNSCOPE_ARTICLE_LIBRARY": self.lib}):
            res, paths = run(self.samples + [self.archive], out)
        self.assertEqual(sorted(os.listdir(os.path.join(out, "articles"))), ["report.html", "report.pdf"])
        cve = next(m for m in res["ioc_matches"] if m["value"] == "CVE-2024-21887")
        url = "https://research.example/report/"
        self.assertEqual(cve["article_copies"][url], [{"href": "articles/report.pdf", "kind": "PDF"},
                                                      {"href": "articles/report.html", "kind": "HTML"}])
        self.assertEqual(cve["article_previews"][url]["title"], "Saved source report")
        ip = next(m for m in res["ioc_matches"] if m["value"] == "8.8.8.8")
        self.assertNotIn("article_copies", ip)
        with open(paths["technical_report.html"], encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn("articles/report.pdf", page)
        self.assertIn("Open saved copy", page)

    def test_no_library_changes_nothing(self):
        out = os.path.join(self.tmp, "out-plain")
        with patch.dict(os.environ, {"VULNSCOPE_OFFLINE": "1"}):
            os.environ.pop("VULNSCOPE_ARTICLE_LIBRARY", None)
            res, _ = run(self.samples + [self.archive], out)
        self.assertFalse(os.path.exists(os.path.join(out, "articles")))
        self.assertTrue(all("article_copies" not in m for m in res["ioc_matches"]))

    def test_served_copies_are_sandboxed_in_a_reopened_report(self):
        out = os.path.join(self.tmp, "out-served")
        with patch.dict(os.environ, {"VULNSCOPE_OFFLINE": "1", "VULNSCOPE_ARTICLE_LIBRARY": self.lib}):
            run(self.samples + [self.archive], out)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(self.tmp, "runs"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host = f"127.0.0.1:{srv.server_port}"

        def request(method, path, body=None, headers=None):
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=60)
            conn.request(method, path, body=body, headers={"Host": host, **(headers or {})})
            resp = conn.getresponse()
            return resp.status, resp.read(), resp
        try:
            token = re.search(rb'name="csrf" value="([^"]+)"', request("GET", "/")[1])[1].decode()
            status, _, resp = request("POST", "/analyze-folder", urllib.parse.urlencode({"csrf": token, "path": out}),
                                      {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(status, 303)
            here = resp.getheader("Location")
            status, body, resp = request("GET", here + "articles/report.html")
            self.assertEqual((status, body), (200, b"<p>saved</p>"))
            self.assertIn(ARTICLE_SANDBOX, resp.getheader("Content-Security-Policy"))
            status, body, resp = request("GET", here + "articles/report.pdf")
            self.assertEqual((status, resp.getheader("Content-Type")), (200, "application/pdf"))
            for bad in ("articles/x/report.pdf", "articles/evil.sh", "articles/missing.pdf"):
                self.assertEqual(request("GET", here + bad)[0], 404, bad)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
