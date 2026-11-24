"""Saved copies of the articles an IOC CSV links to, for reading a report with no network.

An article library is a folder with ``article_library.json`` at its top::

    {"version": 1,
     "articles": {"https://example.org/post": {"title": "...", "files": ["pages/post.pdf", "pages/post.html"]}}}

Each file path is relative to that folder. When a run is given a library (``--article-library``
or ``$VULNSCOPE_ARTICLE_LIBRARY``), the saved copies of every article a matched indicator cites
are copied into the report folder under ``articles/`` and the IOC drawer links to them, so the
report folder carries its own sources and still reads in an air-gapped network.

Only PDF, HTML, text, CSV and JSON copies are taken. HTML copies are expected to be cleaned
(scripts removed, a no-network CSP); they are served from the report under a sandbox either way.
"""
from __future__ import annotations

import json
import os
import re
import shutil

LIBRARY_FILE = "article_library.json"
FOLDER = "articles"
KINDS = {".pdf": "PDF", ".html": "HTML", ".txt": "Text", ".csv": "CSV", ".json": "JSON"}
MAX_FILE = 64 * 1024 * 1024


def key(url: str) -> str:
    return url.strip().rstrip("/")


def location() -> str | None:
    return os.environ.get("VULNSCOPE_ARTICLE_LIBRARY") or None


def read(path: str) -> tuple[str, dict[str, dict]]:
    """(library folder, {article key: {"title", "files": [absolute paths]}}). ``path`` is the
    folder or its article_library.json. Files outside the folder, missing, too large or of
    another kind are left out."""
    if os.path.isdir(path):
        path = os.path.join(path, LIBRARY_FILE)
    root = os.path.realpath(os.path.dirname(os.path.abspath(path)))
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    for url, entry in (data.get("articles") or {}).items():
        if not isinstance(url, str) or not re.match(r"https?://", url) or not isinstance(entry, dict):
            continue
        files = []
        for rel in entry.get("files") or []:
            full = os.path.realpath(os.path.join(root, str(rel)))
            if (full.startswith(root + os.sep) and os.path.isfile(full)
                    and os.path.splitext(full)[1].lower() in KINDS and os.path.getsize(full) <= MAX_FILE):
                files.append(full)
        if files:
            out[key(url)] = {"title": str(entry.get("title") or ""), "files": files}
    return root, out


def attach(matches: list[dict], library: str, outdir: str) -> int:
    """Copy the saved copies of every article the matches cite into ``outdir/articles`` and add
    ``article_copies`` ({url: [{"href", "kind"}]}) to each match. Returns the articles copied."""
    _, articles = read(library)
    dest = os.path.join(outdir, FOLDER)
    copied: dict[str, list[dict]] = {}
    for row in matches:
        for url in row.get("articles") or []:
            entry = articles.get(key(url))
            if not entry:
                continue
            if key(url) not in copied:
                os.makedirs(dest, exist_ok=True)
                links = []
                for src in entry["files"]:
                    name = os.path.basename(src)
                    shutil.copyfile(src, os.path.join(dest, name))
                    links.append({"href": f"{FOLDER}/{name}", "kind": KINDS[os.path.splitext(name)[1].lower()]})
                copied[key(url)] = links
            row.setdefault("article_copies", {})[url] = copied[key(url)]
            previews = row.setdefault("article_previews", {})
            if entry["title"] and not (previews.get(url) or {}).get("title"):
                previews[url] = {**(previews.get(url) or {}), "title": entry["title"]}
    return len(copied)
