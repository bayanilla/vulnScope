"""Upload page: the switch to "Investigate an incident", the case form and case pages, and the
Options shared by both ways of analyzing (IOC CSV with a folder run)."""
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer

from vulnflow.correlate import Config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTEX = os.path.join(ROOT, "samples", "artex_ai_agentic_intrusion")


def multipart_body(fields: dict, files: list[tuple[str, str, bytes]]):
    boundary = uuid.uuid4().hex
    body = b""
    for k, v in fields.items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for name, fname, data in files:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'
                 "Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class InvestigateWebTests(unittest.TestCase):
    def setUp(self):
        from vulnflow.web import make_handler
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = os.path.join(self.tmp, "data")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.data, Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.base = f"http://127.0.0.1:{srv.server_port}"
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', self.get("/")[1])[1]
        self.opener = urllib.request.build_opener(_NoRedirect)

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), dict(exc.headers)

    def post(self, path, fields, files=()):
        body, ctype = multipart_body({"csrf": self.csrf, **fields}, list(files))
        req = urllib.request.Request(self.base + path, data=body, headers={"Content-Type": ctype})
        try:
            with self.opener.open(req) as resp:
                return resp.status, resp.read().decode(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), dict(exc.headers)

    def cases(self):
        root = os.path.join(self.data, "cases")
        return sorted(os.listdir(root)) if os.path.isdir(root) else []

    # -- the upload page ------------------------------------------------------------------------
    def test_upload_page_has_the_switch_options_and_folded_upload(self):
        _, page, _ = self.get("/")
        self.assertIn('<nav class="modes"', page)
        self.assertIn('href="/investigate"', page)
        self.assertIn('aria-current="page">Analyze network and vulnerabilities', page)
        self.assertIn('id="shared-options"', page)
        self.assertEqual(page.count('id="ioc_archive"'), 1)
        self.assertEqual(page.count('name="internal_nets"'), 1)       # one field, sent with either form
        self.assertRegex(page, r'<details id="upload-instead"><summary>Upload files instead</summary>')
        self.assertIn('action="/analyze-folder" enctype="multipart/form-data"', page)

    def test_folder_run_takes_the_ioc_csv_from_options(self):
        src = os.path.join(self.tmp, "telemetry")
        os.makedirs(src)
        for f in ("conn.log", "notice.log"):
            shutil.copy(os.path.join(ARTEX, f), src)
        with open(os.path.join(ARTEX, "ioc_indicators.csv"), "rb") as fh:
            ioc = fh.read()
        code, _, headers = self.post("/analyze-folder", {"path": src, "report_name": "IOC from options"},
                                     [("ioc_archive", "iocs.csv", ioc), ("folder", "stray.log", b"x")])
        self.assertEqual(code, 303, headers)
        run_id = headers["Location"].split("/")[2]
        with open(os.path.join(self.data, run_id, "out", "results.json"), encoding="utf-8") as fh:
            res = json.load(fh)
        self.assertGreater(res["ioc_archive"]["indicators"], 0)
        kept = os.listdir(os.path.join(self.data, run_id, "in"))
        self.assertIn("SOURCE.txt", kept)
        self.assertEqual([k for k in kept if k.endswith("stray.log")], [])     # only the IOC CSV is kept
        self.assertEqual([d for d in os.listdir(self.data) if d.startswith("upload_")], [])

    def test_folder_form_still_takes_url_encoded_posts(self):
        import urllib.parse
        form = {"csrf": self.csrf, "path": os.path.join(self.tmp, "missing")}
        req = urllib.request.Request(self.base + "/analyze-folder", data=urllib.parse.urlencode(form).encode())
        with urllib.request.urlopen(req) as resp:
            self.assertIn("Folder not found", resp.read().decode())

    def test_upload_error_reopens_the_upload_section(self):
        code, page, _ = self.post("/analyze", {})
        self.assertEqual(code, 200)
        self.assertIn('<details id="upload-instead" open>', page)

    # -- investigations -------------------------------------------------------------------------
    def test_investigate_page(self):
        code, page, _ = self.get("/investigate")
        self.assertEqual(code, 200)
        self.assertIn('aria-current="page">Investigate an incident', page)
        self.assertIn('action="/investigate"', page)
        self.assertIn('data-optional="1"', page)
        self.assertNotIn("Recent cases", page)

    def test_investigation_from_a_folder(self):
        code, _, headers = self.post("/investigate", {"case_name": "Artex callback", "path": ARTEX,
                                                      "scope_nets": "10.50.0.0/16", "notes": "Ticket 7"})
        self.assertEqual(code, 303, headers)
        loc = headers["Location"]
        self.assertRegex(loc, r"^/cases/Artex-callback_\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d/$")
        code, page, _ = self.get(loc)
        self.assertEqual(code, 200)
        self.assertIn("Artex callback", page)
        self.assertIn("10.50.0.0/16", page)
        self.assertIn("Ticket 7", page)
        self.assertIn('href="v1/incident_report.html"', page)
        self.assertIn("northfold_scan.nessus", page)
        self.assertIn("not readable yet", page)                  # kept, listed, not read
        code, report, headers = self.get(loc + "v1/incident_report.html")
        self.assertEqual(code, 200)
        self.assertTrue(any("sandbox" in v for v in headers.get_all("Content-Security-Policy")))
        self.assertIn('id="ev-', report)
        code, js, _ = self.get(loc + "v1/incident_report.json")
        self.assertEqual(json.loads(js)["version"], 1)
        _, inv, _ = self.get("/investigate")
        self.assertIn("Recent cases", inv)
        self.assertIn(loc, inv)
        # the folder is copied, not touched; the case is a normal CLI case
        from vulnflow.incident import case as cases
        c = cases.open_case(os.path.join(self.data, "cases", self.cases()[0]))
        self.assertEqual(cases.verify_audit(c), [])
        self.assertEqual({r["original_name"] for r in c.evidence()} & {"conn.log", "northfold_scan.nessus"},
                         {"conn.log", "northfold_scan.nessus"})

    def test_investigation_from_uploads_keeps_original_names(self):
        with open(os.path.join(ARTEX, "conn.log"), "rb") as fh:
            conn = fh.read()
        code, _, headers = self.post("/investigate", {"case_name": "Uploaded"},
                                     [("evidence", "conn.log", conn), ("evidence", "copy-of-conn.log", conn)])
        self.assertEqual(code, 303, headers)
        from vulnflow.incident import case as cases
        c = cases.open_case(os.path.join(self.data, "cases", self.cases()[0]))
        ev = c.evidence()
        self.assertEqual([r["original_name"] for r in ev], ["conn.log"])
        self.assertEqual(ev[0]["duplicate_uploads"][0]["original_name"], "copy-of-conn.log")
        self.assertEqual([d for d in os.listdir(self.data) if d.startswith("incident-upload")], [])

    def test_bad_case_form_keeps_what_was_typed_and_leaves_no_case(self):
        code, page, _ = self.post("/investigate", {"case_name": "No zone", "path": ARTEX,
                                                   "start": "2026-11-18 06:00"})
        self.assertEqual(code, 200)
        self.assertIn("zone", page)
        self.assertIn('value="No zone"', page)
        self.assertIn('value="2026-11-18 06:00"', page)
        self.assertEqual(self.cases(), [])
        _, page, _ = self.post("/investigate", {"case_name": "Nothing"})
        self.assertIn("Add evidence", page)
        _, page, _ = self.post("/investigate", {"case_name": "Bad scope", "path": ARTEX, "scope_nets": "10.0.0.0/33"})
        self.assertIn("not an address range", page)
        self.assertEqual(self.cases(), [])

    def test_case_urls_only_reach_report_files(self):
        self.post("/investigate", {"case_name": "Paths", "path": ARTEX})
        cid = self.cases()[0]
        for path in (f"/cases/{cid}/case.json", f"/cases/{cid}/audit.jsonl", f"/cases/{cid}/v1/../case.json",
                     f"/cases/{cid}/v9/incident_report.html", "/cases/nope/", "/cases/../data/"):
            self.assertEqual(self.get(path)[0], 404, path)

    def test_investigate_refuses_without_csrf(self):
        body, ctype = multipart_body({"csrf": "wrong", "case_name": "x", "path": ARTEX}, [])
        req = urllib.request.Request(self.base + "/investigate", data=body, headers={"Content-Type": ctype})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(self.cases(), [])


if __name__ == "__main__":
    unittest.main()
