"""`vulnflow incident ...`: create a case, add evidence, build the baseline report, read records."""
from __future__ import annotations

import json
import os
import sys

from ..errors import UserError


def add_parser(sub) -> None:
    p = sub.add_parser("incident", help="incident cases: preserve evidence and build a baseline report "
                                         "(no scan needed, no AI model)")
    isub = p.add_subparsers(dest="incident_cmd", required=True)

    def actor(q):
        q.add_argument("--actor", help="who is acting, for the audit log (default $VULNSCOPE_ACTOR or this account)")

    n = isub.add_parser("new", help="create a case folder")
    n.add_argument("case", help="new, empty folder for the case")
    n.add_argument("--name", required=True, help="case name")
    n.add_argument("--scope-net", action="append", default=[], metavar="CIDR",
                   help="address range in scope (repeatable); events touching none of them are left out")
    n.add_argument("--scope-host", action="append", default=[], metavar="NAME", help="host name in scope (recorded)")
    n.add_argument("--scope-account", action="append", default=[], metavar="NAME", help="account in scope (recorded)")
    n.add_argument("--start", help="window start, ISO with a zone, e.g. 2026-11-18T06:00:00Z")
    n.add_argument("--end", help="window end, ISO with a zone")
    n.add_argument("--margin-minutes", type=int, default=60, help="kept on each side of the window (default 60)")
    n.add_argument("--entity", action="append", default=[], metavar="NAME", help="known affected entity (repeatable)")
    n.add_argument("--notes", default="", help="free-text notes")
    actor(n)

    a = isub.add_parser("add", help="store evidence files in a case (originals are kept read-only)")
    a.add_argument("case")
    a.add_argument("files", nargs="+", help="files or folders (folders are read recursively, hidden files skipped)")
    a.add_argument("--max-file-mb", type=int, default=None, help="refuse files larger than this")
    actor(a)

    r = isub.add_parser("run", help="parse the evidence and write a new baseline report version")
    r.add_argument("case")
    r.add_argument("--force", action="store_true", help="write a new version even if nothing changed")
    actor(r)

    s = isub.add_parser("status", help="each evidence file's status and the report versions")
    s.add_argument("case")
    s.add_argument("--json", action="store_true")

    rec = isub.add_parser("record", help="print the original record behind an event ID")
    rec.add_argument("case")
    rec.add_argument("event_id")
    actor(rec)

    v = isub.add_parser("verify", help="check the audit log chain and every stored file's SHA-256")
    v.add_argument("case")


def main(args) -> int:
    try:
        return _main(args)
    except UserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _main(args) -> int:
    from . import case as cases
    from .run import baselines, run
    who = cases.actor_name(getattr(args, "actor", None))
    cmd = args.incident_cmd
    if cmd == "new":
        c = cases.create(args.case, args.name, actor=who, scope_nets=args.scope_net, scope_hosts=args.scope_host,
                         scope_accounts=args.scope_account, start=args.start, end=args.end,
                         margin_minutes=args.margin_minutes, entities=args.entity, notes=args.notes)
        print(f"Case created: {c.dir} (id {c.case_id})")
        return 0
    c = cases.open_case(args.case)
    if cmd == "add":
        from ..pipeline import input_files
        files = input_files(args.files, c.dir)
        files = [f for f in files if not os.path.realpath(f).startswith(os.path.realpath(c.dir) + os.sep)]
        if not files:
            raise UserError("No files to add.")
        cap = args.max_file_mb * 1024 * 1024 if args.max_file_mb else None
        failed = 0
        for f in files:
            try:
                rec, new = cases.add_evidence(c, f, who, cap)
            except UserError as exc:
                failed += 1
                c.audit(who, "evidence_refused", original_name=os.path.basename(f), reason=str(exc))
                print(f"refused   {os.path.basename(f)}: {exc}")
                continue
            word = "stored   " if new else "duplicate"
            print(f"{word} {rec['evidence_id']}  {os.path.basename(f)}"
                  + ("" if new else f" (same content as {rec['original_name']})"))
        return 1 if failed else 0
    if cmd == "run":
        out = run(c, who, force=args.force)
        for i in out["inputs"]:
            detail = f" ({i['status_detail']})" if i["status_detail"] else ""
            print(f"{i['status']:<19} {i['original_name']}: {i['events']} event(s){detail}")
        word = "unchanged, existing" if out["reused"] else "written"
        print(f"Baseline v{out['version']} {word}: {out['folder']}")
        return 0
    if cmd == "status":
        ev = c.evidence()
        versions = [v for v, _ in baselines(c)]
        if args.json:
            print(json.dumps({"case": c.data, "evidence": ev, "baselines": versions}, indent=2, sort_keys=True))
            return 0
        print(f"{c.data['name']} ({c.case_id})")
        for r in ev:
            dup = f", {len(r['duplicate_uploads'])} duplicate upload(s)" if r.get("duplicate_uploads") else ""
            detail = f": {r['status_detail']}" if r.get("status_detail") else ""
            print(f"  {r['evidence_id']}  {r['status']:<19} {r['original_name']}{detail}{dup}")
        print("Baselines: " + (", ".join(f"v{v}" for v in versions) or "none yet"))
        return 0
    if cmd == "record":
        return _record(c, args.event_id, who)
    if cmd == "verify":
        problems = cases.verify_audit(c)
        for r in c.evidence():
            got, _ = cases.sha256_file(c.evidence_path(r))
            if got != r["sha256"]:
                problems.append(f"{r['stored_path']}: SHA-256 differs from the one recorded at upload")
        for p in problems:
            print(p)
        print("Audit log and evidence intact." if not problems else f"{len(problems)} problem(s).")
        return 0 if not problems else 1
    raise UserError(f"unknown incident command {cmd}")


def _record(c, event_id: str, who: str) -> int:
    import duckdb  # noqa: F401  (db.connect checks the version)
    from .. import db
    from .report import read_records
    files = sorted(f for f in os.listdir(c.path("parsed")) if f.endswith(".parquet")) if os.path.isdir(c.path("parsed")) else []
    if not files or not all(ch in "0123456789abcdef" for ch in event_id) or len(event_id) != 20:
        raise UserError("Unknown event ID for this case.")
    con = db.connect()
    try:
        listed = ", ".join(f"'{os.path.join(c.path('parsed'), f)}'" for f in files)
        row = con.execute(f"SELECT evidence_id, locator FROM read_parquet([{listed}]) WHERE event_id = ? LIMIT 1",
                          [event_id]).fetchone()
    finally:
        con.close()
    if row is None:
        raise UserError("Unknown event ID for this case.")
    rec = next(r for r in c.evidence() if r["evidence_id"] == row[0])
    text = read_records(c.evidence_path(rec), {row[1]}).get(row[1])
    c.audit(who, "evidence_viewed", event_id=event_id, evidence_id=row[0], locator=row[1])
    print(f"{rec['original_name']} {row[1]} sha256 {rec['sha256']}")
    print(text if text is not None else "(record not found at this position)")
    return 0
