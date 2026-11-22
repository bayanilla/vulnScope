"""Several sites in one folder, analyzed as one report per site and compared.

A sites list, ``sites.csv`` in the analyzed folder, names each site's subfolder, the report's name and
the network (the company) the site belongs to. With one folder per company, each holding a folder per
site:

    folder,name,network,description
    corvane/hq,Corvane HQ,Corvane,Head office
    corvane/phoenix,Corvane Phoenix plant,Corvane,
    ridgeline/denver,Ridgeline Denver office,Ridgeline,

Analyzing the folder then makes one report per site and a comparison of them (as Compare reports
does), instead of one analysis of everything. That keeps the networks apart: the same internal
address at two companies (two head offices that both use 10.20.0.0/24) stays two hosts, and the
comparison's all-networks map draws each network's sites together.

``folder`` is a subfolder of the analyzed folder and is required; ``name`` defaults to the folder's
name, and ``network`` to the folder the site's folder sits in (``corvane`` for ``corvane/hq``), or to
none for a site directly in the analyzed folder (the site is then a network of its own). Files directly in the analyzed
folder are used for every site when they are an IOC CSV, a network map, a known-scanners list or saved
article overviews; logs and scans belong in the sites' folders. Without a sites list nothing changes.
"""
from __future__ import annotations

import csv
import os
import shutil
from dataclasses import dataclass

from . import ioc_archive, netmap, runname, scanners
from .errors import UserError

FILENAME = "sites.csv"
MAX_SITES = 50
_HEADERS = {"folder": ("folder", "subfolder", "directory", "dir", "path"),
            "name": ("name", "report", "report_name", "site", "site_name"),
            "network": ("network", "company", "organization", "organisation", "org", "customer", "client", "tenant"),
            "description": ("description", "notes", "note", "about")}


@dataclass
class Site:
    folder: str          # absolute path of the site's folder
    name: str            # the report's name
    network: str
    description: str


def is_sites_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def find(folder: str) -> str | None:
    """The folder's sites list (any letter case), if it has one."""
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return None
    return next((os.path.join(folder, n) for n in names
                 if n.lower() == FILENAME and os.path.isfile(os.path.join(folder, n))), None)


def read(path: str) -> list[Site]:
    """The sites a sites list names, in file order. Raises UserError naming the line."""
    base = os.path.realpath(os.path.dirname(os.path.abspath(path)))
    label = os.path.basename(path)
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
    except (OSError, UnicodeError, csv.Error) as exc:
        raise UserError(f"{label} could not be read: {exc}") from None
    rows = [r for r in rows if any(c.strip() for c in r) and not r[0].lstrip().startswith("#")]
    if not rows:
        raise UserError(f"{label} is empty; expected a header row: folder,name,network,description")
    head = [h.strip().lower() for h in rows[0]]
    idx = {k: next((head.index(a) for a in aliases if a in head), None) for k, aliases in _HEADERS.items()}
    if idx["folder"] is None:
        raise UserError(f"{label} needs a 'folder' column; header was: {', '.join(head)}")
    sites, seen = [], {}
    for line, row in enumerate(rows[1:], 2):
        get = lambda k: row[idx[k]].strip() if idx[k] is not None and idx[k] < len(row) else ""
        rel = get("folder")
        where = os.path.realpath(os.path.join(base, rel)) if rel and not os.path.isabs(rel) else ""
        if not where or os.path.commonpath([base, where]) != base or where == base:
            raise UserError(f"{label} line {line}: '{rel}' must be a folder inside {base}")
        if not os.path.isdir(where):
            raise UserError(f"{label} line {line}: folder '{rel}' not found in {base}")
        if where in seen:
            raise UserError(f"{label} line {line}: folder '{rel}' is already listed on line {seen[where]}")
        seen[where] = line
        parts = os.path.relpath(where, base).split(os.sep)
        network = get("network") or (parts[0] if len(parts) > 1 else "")      # the company folder
        report = runname.clean(get("name") or os.path.basename(where), get("description"), network)
        sites.append(Site(where, report["name"], report["network"], report["description"]))
    if not sites:
        raise UserError(f"{label} lists no sites; add one line per site folder")
    if len(sites) > MAX_SITES:
        raise UserError(f"{label} lists {len(sites)} sites; at most {MAX_SITES} can be analyzed at once")
    return sites


def _shared(path: str) -> bool:
    """Files used by every site: IOC lists, a network map, a known-scanners list, article overviews."""
    from .pipeline import PREVIEW_CACHE
    return (os.path.basename(path) == PREVIEW_CACHE or netmap.is_map_file(path) or scanners.is_list_file(path)
            or ioc_archive.is_archive(path))


def plan(folder: str, outdir: str) -> list[tuple[Site, list[str]]]:
    """Each site of ``folder``'s sites list with the files its analysis reads: its own folder's (as
    pipeline.input_files lists them) and the files every site shares. Raises UserError for a log or
    scan directly in ``folder``, since it would belong to no site."""
    from .pipeline import NOTES, input_files
    listed = find(folder)
    if not listed:
        raise UserError(f"No sites list ({FILENAME}) in {folder}")
    sites = read(listed)
    shared = []
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name.startswith(".") or not os.path.isfile(path) or is_sites_file(path) or name.lower() in NOTES:
            continue
        if not _shared(path):
            raise UserError(f"{name} is directly in {folder}, which has a sites list ({FILENAME}): put each "
                            "site's logs and scans in that site's folder. Only IOC lists, a network map, a "
                            "known-scanners list and article overviews can sit next to the sites list; every "
                            "site uses them.")
        shared.append(path)
    skip = os.path.realpath(outdir) + os.sep              # a data folder kept inside a site's folder
    return [(s, [f for f in input_files([s.folder], outdir) if not os.path.realpath(f).startswith(skip)] + shared)
            for s in sites]


def analyze(data_dir: str, folder: str, cfg=None, log=print, workdir: str | None = None) -> tuple[list[str], str]:
    """Analyze every site of ``folder``'s sites list into its own run in ``data_dir`` (the upload
    page's data folder), named and with its network set, then save a comparison of them there.
    Returns the run ids and the comparison id. When a site can't be analyzed (UserError), the runs
    made so far are removed and the error names the site. Temporary files go in each run's folder,
    or in ``workdir``."""
    from . import compare, pipeline
    from .web import compare_page
    todo = plan(folder, data_dir)
    runs: list[str] = []
    try:
        for site, files in todo:
            if not files:
                raise UserError(f"{site.name}: no files found in {site.folder}")
            run_id = runname.new_run(data_dir, site.name)
            runs.append(run_id)
            root = os.path.join(data_dir, run_id)
            os.makedirs(os.path.join(root, "in"))
            with open(os.path.join(root, "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"Read in place from {site.folder} (site of {folder})\n" + "\n".join(files) + "\n")
            log(f"Analyzing {site.name}…")
            try:
                pipeline.run(files, os.path.join(root, "out"), cfg, workdir=workdir or root,
                             report=runname.clean(site.name, site.description, site.network))
            except UserError as exc:
                raise UserError(f"{site.name}: {exc}") from None
    except UserError:
        for run_id in runs:
            shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
        raise
    reports = []
    for run_id in runs:                       # as compare.server_reports lists them, without reading every run
        rep = compare.describe(os.path.join(data_dir, run_id, "out"), run_id)
        rep.href = f"/runs/{run_id}/"
        reports.append(rep)
    cid, out = compare_page.new_comparison(data_dir)
    log(f"Comparing the {len(reports)} site reports…")
    compare_page.save(out, reports, [], crosscheck=True)
    return runs, cid
