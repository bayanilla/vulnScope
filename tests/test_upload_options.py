"""Upload page: the Options shared by both ways of analyzing (IOC CSV with a folder run) and the
folded upload form. (Incident cases moved to the separate vulnscope_incident tool.)"""
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


class UploadOptionsTests(unittest.TestCase):
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

    # -- the upload page ------------------------------------------------------------------------
    def test_upload_page_has_options_and_folded_upload(self):
        _, page, _ = self.get("/")
        self.assertNotIn('<nav class="modes"', page)          # incident cases moved to vulnscope_incident
        self.assertNotIn('href="/investigate"', page)
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

    def test_investigate_is_gone(self):
        code, _, _ = self.get("/investigate")
        self.assertEqual(code, 404)
