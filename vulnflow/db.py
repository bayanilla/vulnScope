"""The one place a DuckDB connection is opened.

Every connection is opened here so two rules hold everywhere:

* DuckDB never downloads anything. Auto-install and auto-load of extensions are off; the engine
  uses only what is built into the DuckDB package (Parquet, JSON, CSV). An analysis tool for
  closed networks must not reach for the internet because a query happened to name a function
  from an extension.
* Known-bad DuckDB versions are refused before they can report less than is in the data. The
  analysis is SQL, so a faulty engine does not crash: it quietly returns fewer rows.
"""
from __future__ import annotations

import duckdb

from .errors import UserError

MIN_VERSION = (1, 2, 0)          # 1.1 has no read_csv(strict_mode=...), which the store needs
# 1.3.0 returns no rows, without an error, for a join on an equality plus a time range on a
# file-backed database (fixed in 1.3.1). Every scan-window join here has that shape.
BAD_VERSIONS = {(1, 3, 0)}
OFFLINE = {"autoinstall_known_extensions": False, "autoload_known_extensions": False}


def _version(text: str) -> tuple:
    parts = []
    for p in text.split(".")[:3]:
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0] * (3 - len(parts)))


def check_version(text: str | None = None) -> None:
    """Raise UserError when the installed DuckDB cannot be trusted with the analysis."""
    text = text or duckdb.__version__
    v = _version(text)
    if v < MIN_VERSION or v in BAD_VERSIONS:
        raise UserError(
            f"DuckDB {text} is installed, and it gives wrong or no results for this analysis. "
            "Install a supported version: pip install 'duckdb>=1.2,!=1.3.0,<2'")


def connect(path: str = ":memory:", config: dict | None = None):
    """A DuckDB connection that never downloads extensions, on a version known to be sound."""
    check_version()
    return duckdb.connect(path, config={**OFFLINE, **(config or {})})
