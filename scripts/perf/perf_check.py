#!/usr/bin/env python3
"""Performance check: analyze one small, fixed synthetic dataset and fail on a large slowdown,
memory growth or a much bigger Explorer page.

CI runs this on every pull request. It generates the same log set every time (scripts/bench/
gen_logs.py with a fixed seed: Zeek conn/dns, Palo Alto TRAFFIC/THREAT, a Nessus CSV, some
gzip, duplicates and cross-sensor overlap), runs `vulnflow analyze` on it in a child process
with fixed DuckDB memory, threads and parse workers, and measures:

  time      wall-clock seconds for the analysis, divided by a short fixed CPU calibration run
            on the same machine, so a slower CI machine does not look like a regression
  memory    peak resident memory of the analysis (largest process)
  explorer  size of explorer.html (grows with what the page embeds)
  results   size of results.json

Each is compared with scripts/perf/baseline.json and the check fails when it is more than the
allowed factor above it (time 1.6x, memory 1.35x, page sizes 1.25x). The flow and finding counts
must match exactly, so a change that silently drops data fails here too.

    python scripts/perf/perf_check.py                 # check against the baseline
    python scripts/perf/perf_check.py --update        # write a new baseline (after a deliberate change)
    python scripts/perf/perf_check.py --size 400M     # a bigger run, not compared with the baseline

Run it on an otherwise idle machine. baseline.json was measured on a 4-CPU, 16 GB Linux machine, like
the GitHub ubuntu-latest runner CI uses.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
BASELINE = os.path.join(HERE, "baseline.json")

DATASET = {"size": "40M", "hours": 4, "hosts": 300, "externals": 4000, "seed": 7}
LIMITS = {"time_ratio": 1.6, "peak_rss_mb": 1.35, "explorer_mb": 1.25, "results_mb": 1.25}
ENV = {  # fixed resources, so the numbers do not depend on the machine's RAM or core count
    "VULNSCOPE_DUCKDB_MEMORY": "1GB", "VULNSCOPE_DUCKDB_THREADS": "2", "VULNSCOPE_PARSE_WORKERS": "2",
    "VULNFLOW_LLM_PROVIDER": "offline", "VULNSCOPE_OFFLINE": "1", "PYTHONDONTWRITEBYTECODE": "1",
}


def calibrate() -> float:
    """Seconds for a fixed mix of Python and DuckDB work; best of 3 to dodge noisy neighbours."""
    import duckdb
    best = float("inf")
    for _ in range(3):
        t = time.perf_counter()
        d: dict = {}
        for i in range(400_000):
            k = f"10.{i % 251}.{i % 13}.{i % 97}"
            d[k] = d.get(k, 0) + len(k)
        con = duckdb.connect()
        con.execute("SET threads=2")
        con.execute("SELECT count(DISTINCT (a % 100003, b % 7)), sum(a * b) FROM "
                    "(SELECT range a, range * 31 b FROM range(4000000))").fetchall()
        con.close()
        best = min(best, time.perf_counter() - t)
    return best


def generate(out: str, size: str) -> dict:
    ds = dict(DATASET, size=size)
    cmd = [sys.executable, os.path.join(ROOT, "scripts", "bench", "gen_logs.py"), out, "--size", ds["size"],
           "--hours", str(ds["hours"]), "--hosts", str(ds["hosts"]), "--externals", str(ds["externals"]),
           "--seed", str(ds["seed"]), "--scan"]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    with open(os.path.join(out, ".manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


def analyze(data: str, out: str) -> dict:
    files = []
    for dirpath, _, names in os.walk(data):
        files += [os.path.join(dirpath, n) for n in sorted(names) if not n.startswith(".")]
    env = {**os.environ, **ENV, "PYTHONPATH": ROOT}
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    t = time.perf_counter()
    proc = subprocess.run([sys.executable, "-m", "vulnflow", "analyze", *sorted(files), "-o", out,
                           "--no-article-preview", "--workdir", os.path.join(out, "_work")],
                          env=env, cwd=ROOT, capture_output=True, text=True)
    wall = time.perf_counter() - t
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        raise SystemExit(f"analyze failed with exit code {proc.returncode}")
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if peak <= before:
        print("warning: peak memory may be under-reported (an earlier child used more)", file=sys.stderr)
    scale = 1 if platform.system() == "Darwin" else 1024     # ru_maxrss: bytes on macOS, KiB on Linux
    with open(os.path.join(out, "results.json"), encoding="utf-8") as fh:
        res = json.load(fh)
    mb = lambda p: round(os.path.getsize(os.path.join(out, p)) / 1e6, 2)
    s = res["summary"]
    return {"wall_s": round(wall, 2), "peak_rss_mb": round(peak * scale / 1e6, 1),
            "explorer_mb": mb("explorer.html"), "results_mb": mb("results.json"),
            "counts": {"flows": s.get("flows"), "findings": len(res["findings"]), "hosts": len(res["hosts"]),
                       "threat_alerts": s.get("threat_alerts"),
                       "duplicate_flows_removed": s.get("duplicate_flows_removed"),
                       "priority_counts": s.get("priority_counts")}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true", help="write the measured numbers as the new baseline")
    ap.add_argument("--size", default=DATASET["size"], help="dataset size (a non-default size skips the comparison)")
    ap.add_argument("--keep", metavar="DIR", help="keep the dataset and outputs in DIR")
    a = ap.parse_args()

    work = a.keep or tempfile.mkdtemp(prefix="vs-perf-")
    try:
        data, out = os.path.join(work, "data"), os.path.join(work, "out")
        if not os.path.isdir(data):
            manifest = generate(data, a.size)
        else:
            with open(os.path.join(data, ".manifest.json"), encoding="utf-8") as fh:
                manifest = json.load(fh)
        shutil.rmtree(out, ignore_errors=True)
        calib = calibrate()
        m = analyze(data, out)
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
    m["calibration_s"] = round(calib, 3)
    m["time_ratio"] = round(m["wall_s"] / calib, 2)
    m["dataset"] = dict(DATASET, size=a.size, bytes_on_disk=manifest.get("bytes_on_disk"))

    if a.update:
        with open(BASELINE, "w", encoding="utf-8") as fh:
            json.dump({**m, "limits": LIMITS, "machine": f"{platform.system()} {platform.machine()}, "
                                                         f"{os.cpu_count()} CPUs"}, fh, indent=2)
            fh.write("\n")
        print(json.dumps(m, indent=2))
        print(f"wrote {BASELINE}")
        return 0

    with open(BASELINE, encoding="utf-8") as fh:
        base = json.load(fh)
    rows, bad = [], []
    if a.size != DATASET["size"]:
        print(json.dumps(m, indent=2))
        print("(non-default size: not compared with the baseline)")
        return 0
    for key, limit in LIMITS.items():
        b, now = base[key], m[key]
        ratio = now / b if b else 1.0
        ok = ratio <= limit
        rows.append(f"| {key} | {b} | {now} | {ratio:.2f}x | {limit}x | {'ok' if ok else '**too high**'} |")
        if not ok:
            bad.append(f"{key} is {ratio:.2f}x the baseline (limit {limit}x)")
    for key, b in base["counts"].items():
        now = m["counts"].get(key)
        ok = now == b
        rows.append(f"| {key} | {b} | {now} | | exact | {'ok' if ok else '**changed**'} |")
        if not ok:
            bad.append(f"{key} changed from {b} to {now}")
    table = "\n".join(["### Performance check", "",
                       f"Fixed dataset {DATASET['size']} (seed {DATASET['seed']}); analysis took "
                       f"{m['wall_s']} s, calibration {m['calibration_s']} s on this machine.", "",
                       "| Measure | Baseline | Now | Ratio | Limit | |", "| --- | ---: | ---: | ---: | ---: | --- |",
                       *rows, ""])
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(table + "\n")
    if bad:
        print("FAILED: " + "; ".join(bad), file=sys.stderr)
        print("If the change is deliberate, run `python scripts/perf/perf_check.py --update` and commit "
              "scripts/perf/baseline.json with a note on why.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
