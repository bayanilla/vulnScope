"""Incident adapters, and which one reads a file."""
from __future__ import annotations

import os
import shutil
import tempfile
import zlib

from ...parsers import detect
from .zeek import ZeekAdapter

ADAPTERS = [ZeekAdapter()]

# Formats the vulnerability workflow reads that incident cases do not read yet, with the reason
# shown in the file's status.
NOT_YET = {
    "nessus": "Nessus scans are optional context; incident cases do not read them yet.",
    "nessus_csv": "Nessus scans are optional context; incident cases do not read them yet.",
    "paloalto": "Palo Alto logs are not read by incident cases yet.",
    "aws_vpcflow": "AWS VPC Flow Logs are not read by incident cases yet.",
    "suricata": "Suricata logs are not read by incident cases yet.",
    "filebeat_zeek": "Filebeat exports of Zeek logs are not read by incident cases yet.",
}


def pick(path: str):
    """(adapter or None, detected format, reason when None)."""
    try:
        detected = detect(path)
    except Exception as exc:                       # unreadable file: say why, don't stop the case
        detected = _detect_cut_gzip(path) if path.lower().endswith(".gz") else None
        if detected is None:
            return None, "unknown", f"could not be read to detect its format: {exc}"
    for adapter in ADAPTERS:
        if adapter.accepts(path, detected):
            return adapter, detected, ""
    if detected in NOT_YET:
        return None, detected, NOT_YET[detected]
    return None, detected, "format not recognised as a supported incident source"


def versions() -> dict[str, str]:
    return {a.name: a.version for a in ADAPTERS}


def _detect_cut_gzip(path: str) -> str | None:
    """A .gz file cut short (an interrupted copy) still has a readable start: detect its format
    from that, so the records before the break can be kept. None when nothing can be read."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    head = b""
    try:
        with open(path, "rb") as fh:
            while len(head) < 16384 and (chunk := fh.read(4096)):
                head += d.decompress(chunk)
    except zlib.error:
        pass
    if not head:
        return None
    folder = tempfile.mkdtemp(prefix="vulnscope-sniff-")
    try:
        probe = os.path.join(folder, os.path.basename(path)[:-3])
        with open(probe, "wb") as fh:
            fh.write(head[:16384])
        return detect(probe)
    except Exception:
        return None
    finally:
        shutil.rmtree(folder, ignore_errors=True)
