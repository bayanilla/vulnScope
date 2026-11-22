"""Named SQL kept in a .sql file.

A file is a run of queries, each under a ``-- name: some_name`` line; the comment lines right
after it describe the query. ``$word`` marks a fragment the caller fills in (a list of ports, a
join condition): fixed text chosen by the program, never anything read from a file being analysed.
Values from data always go in as tables or bound parameters.
"""
from __future__ import annotations

import os
import re
from string import Template

_NAME = re.compile(r"^-- name:\s*([a-z][a-z0-9_]*)\s*$")


def load(path: str) -> dict[str, str]:
    queries: dict[str, list[str]] = {}
    current = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = _NAME.match(line)
            if m:
                if m.group(1) in queries:
                    raise ValueError(f"{os.path.basename(path)}: query \"{m.group(1)}\" is defined twice")
                current = queries.setdefault(m.group(1), [])
            elif current is not None:
                current.append(line)
    return {name: "".join(lines).strip().rstrip(";") for name, lines in queries.items()}


class Model:
    """The queries of one file, each with its fragments filled in once, on first use."""

    def __init__(self, path: str, fragments: dict[str, str]):
        self._raw, self._fragments, self._ready = load(path), fragments, {}

    def __call__(self, name: str) -> str:
        if name not in self._ready:
            self._ready[name] = Template(self._raw[name]).substitute(self._fragments)   # KeyError: unknown name or fragment
        return self._ready[name]

    def names(self) -> list[str]:
        return list(self._raw)
