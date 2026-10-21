"""One call that runs the whole workflow: load -> clean -> correlate -> report."""
from __future__ import annotations

from .correlate import Config, correlate
from .normalize import load
from .report import write_all


def run(paths: list[str], outdir: str, cfg: Config | None = None,
        overrides: dict[str, str] | None = None) -> tuple[dict, dict[str, str]]:
    ds = load(paths, overrides)
    if not ds.findings and not any(s.fmt.startswith("nessus") for s in ds.stats):
        raise ValueError("No vulnerability scan was provided. Add a .nessus file or Nessus CSV export.")
    if not ds.flows:
        raise ValueError("No network telemetry was provided (or none could be parsed). "
                         "Add Zeek conn.log, Palo Alto traffic logs or a flow CSV.")
    res = correlate(ds, cfg)
    return res, write_all(res, ds, outdir)
