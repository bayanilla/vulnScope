import io
import os
import tempfile
import unittest
from unittest import mock

from vulnflow import multipart


def body(boundary, parts):
    out = b""
    for name, filename, data in parts:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename is not None else "")
        out += f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


class MultipartTests(unittest.TestCase):
    def test_streams_files_across_chunk_boundaries(self):
        b = "XyZb0undary"
        tricky = (b"line1\r\n--XyZb0und not quite\r\n" * 50) + bytes(range(256)) * 20
        raw = body(b, [("telemetry", "../../evil name.log", tricky), ("internal_nets", None, b"10.0.0.0/8"),
                       ("scans", "", b""), ("scans", "scan.nessus", b"<x/>")])
        d = tempfile.mkdtemp()
        for chunk in (5, 7, 64, 1 << 16):          # small chunks force boundaries to straddle reads
            with mock.patch.object(multipart, "CHUNK", chunk):
                sub = tempfile.mkdtemp(dir=d)
                fields, files = multipart.parse(io.BytesIO(raw), len(raw), f"multipart/form-data; boundary={b}",
                                                sub, lambda i, n: f"{i:02d}_{os.path.basename(n)}")
                self.assertEqual(fields, {"internal_nets": "10.0.0.0/8"})
                self.assertEqual([n for n, _ in files], ["telemetry", "scans"])
                with open(files[0][1], "rb") as fh:
                    self.assertEqual(fh.read(), tricky)
                self.assertTrue(files[0][1].startswith(sub))

    def test_rejects_non_multipart_and_truncated(self):
        with self.assertRaises(multipart.MultipartError):
            multipart.parse(io.BytesIO(b"x"), 1, "application/json", tempfile.mkdtemp(), lambda i, n: n)
        raw = body("bb", [("telemetry", "a.log", b"abc" * 1000)])[:-200]
        with self.assertRaises(multipart.MultipartError):
            multipart.parse(io.BytesIO(raw), len(raw), "multipart/form-data; boundary=bb",
                            tempfile.mkdtemp(), lambda i, n: n)


if __name__ == "__main__":
    unittest.main()
