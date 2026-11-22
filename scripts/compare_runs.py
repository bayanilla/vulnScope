#!/usr/bin/env python3
"""Check that two analysis output folders hold the same results.

Used to prove an engine change leaves the analysis untouched: run the same input through the
reference version and the changed one, then

    python3 scripts/compare_runs.py REFERENCE_OUT NEW_OUT

Compares results.json (everything but the "generated" time), the correlated findings CSV and the
normalized copies both folders have. Exit status 0 when identical, 1 with the differences listed.
"""
import hashlib
import json
import os
import sys

FILES = ["correlated_findings.csv", "normalized/flows.csv", "normalized/findings.csv",
         "normalized/threats.csv", "normalized/probed_addresses.csv",
         "normalized/zeek_events.jsonl", "normalized/ot_events.jsonl"]


def _diff(a, b, path, out, limit=20):
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'new' if k in b else 'reference'}")
            else:
                _diff(a[k], b[k], f"{path}/{k}", out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: {len(a)} items in reference, {len(b)} in new")
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, f"{path}[{i}]", out, limit)
    elif a != b:
        out.append(f"{path}: {a!r} -> {b!r}")


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def compare(ref: str, new: str) -> list[str]:
    out: list[str] = []
    a, b = (json.load(open(os.path.join(d, "results.json"), encoding="utf-8")) for d in (ref, new))
    for r in (a, b):
        r.pop("generated", None)
    _diff(a, b, "results.json:", out)
    for name in FILES:
        pa, pb = os.path.join(ref, name), os.path.join(new, name)
        if os.path.exists(pa) and os.path.exists(pb) and _sha(pa) != _sha(pb):
            out.append(f"{name}: contents differ")
        elif os.path.exists(pa) != os.path.exists(pb):
            out.append(f"{name}: only in {'reference' if os.path.exists(pa) else 'new'}")
    return out


if __name__ == "__main__":
    diffs = compare(sys.argv[1], sys.argv[2])
    print("\n".join(diffs) if diffs else "identical")
    sys.exit(1 if diffs else 0)
