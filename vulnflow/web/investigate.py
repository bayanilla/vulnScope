"""Investigate an incident from the portal: the case form, its run, and the case pages.

The form creates an incident case (vulnflow/incident), stores the evidence in it (copied, hashed,
read-only), builds the baseline report and opens the case page. No scan is needed and no AI model
is used. Cases live in <data_dir>/cases/<name>_<timestamp>/, one folder each, laid out as the CLI
lays them out (docs/INCIDENTS.md), so `vulnflow incident status|record|verify` works on them too.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import traceback

from .. import multipart, resources, runname
from ..errors import UserError
from ..incident import case as cases
from ..incident.run import baselines, run
from ..pipeline import input_files
from ..report import CSS, HTML_OPEN, THEME_INIT, theme_control
from ..branding import icon_data_uri, product_name
from . import folders
from .pages import asset, busy_overlay, error_html, modes, page, page_config, picker
from .runs import SAVED_SANDBOX

CASES = "cases"
LISTED = 10                     # recent cases shown under the form
REPORT_FILES = {"incident_report.html", "incident_report.md", "incident_report.json"}
RUN_HINT = "Evidence is copied into the case and hashed first, then read. Keep this tab open; the case opens here when it's ready."

FORM = """{html_open}<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Investigate an incident · {product_name}</title>
<link rel="icon" href="{icon}">{theme_init}<style>{css}{forms_css}</style></head><body>{theme_ui}
{modes}
<h1>Investigate an incident</h1>
<p>Start a case from the logs around an incident. The files are copied into the case, hashed and kept
read-only; {product_name} then builds a baseline report: a timeline, findings that say whether they were
observed or inferred, and what the evidence can't show. Every line points back to the original record.
No vulnerability scan is needed and no AI model is used.</p>
{error}
<form method="post" action="/investigate" enctype="multipart/form-data" data-busy="Building the case…" data-busy-hint="{run_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<section id="case-details"><h2>Case</h2>
<label for="case_name">Case name</label>
<input id="case_name" type="text" name="case_name" value="{case_name}" maxlength="100" required placeholder="e.g. Suspicious callback from 10.50.1.10" autocomplete="off">
<label for="scope_nets">Networks in scope <span class="hint">(optional)</span></label>
<input id="scope_nets" type="text" name="scope_nets" value="{scope_nets}" placeholder="10.50.0.0/16, 192.168.10.0/24" autocomplete="off">
<div class="hint">Events that touch none of these ranges are left out. Leave blank to keep everything.</div>
<label for="start">Window start <span class="hint">(optional)</span></label>
<input id="start" type="text" name="start" value="{start}" placeholder="2026-11-18T06:00:00Z" autocomplete="off">
<label for="end">Window end <span class="hint">(optional)</span></label>
<input id="end" type="text" name="end" value="{end}" placeholder="2026-11-18T18:00:00-05:00" autocomplete="off">
<div class="hint">Date and time with a zone (Z or an offset such as -05:00). One hour either side is kept too.
Leave both blank to use all of the evidence.</div>
<label for="notes">Notes <span class="hint">(optional)</span></label>
<textarea id="notes" name="notes" maxlength="4000" rows="3" placeholder="Ticket number, who reported it, what was seen first&hellip;">{notes}</textarea>
</section>
<section><h2>Evidence</h2>
<p class="hint">Zeek logs are read today; other files are kept in the case and listed as not yet readable.
Give a folder, upload files, or both.</p>
<label for="path">Folder on this computer</label>
{picker}
<div class="hint">{folder_hint}Its files, including subfolders, are copied into the case. Hidden files are skipped.</div>
<label for="evidence">Or upload files</label>
<input id="evidence" type="file" name="evidence" multiple>
<div class="hint">Copied to this server; {upload_mb} MB in all.</div>
</section>
<div class="btnrow"><button type="submit">Start investigation</button></div>
</form>
{recent}
<p class="hint"><a href="/">Analyze network and vulnerabilities</a> · <a href="/compare">Compare reports</a></p>
{busy}{config}
<script>{busy_js}</script>
<script>{picker_js}</script>
</body></html>"""


def cases_dir(app) -> str:
    return os.path.join(app.data_dir, CASES)


def view(req, error: str = "", typed: dict | None = None):
    """GET /investigate, and the form again after a problem (keeping what was typed)."""
    app, typed = req.app, typed or {}
    container = bool(folders.CONTAINER_DATA)
    req.send(200, FORM.format(
        html_open=HTML_OPEN, product_name=html.escape(product_name()), icon=icon_data_uri(), theme_init=THEME_INIT,
        css=CSS, forms_css=asset("forms.css"), theme_ui=theme_control(), modes=modes("investigate"),
        error=error_html(error), run_hint=html.escape(RUN_HINT), csrf=app.csrf,
        case_name=html.escape(typed.get("case_name", "")), scope_nets=html.escape(typed.get("scope_nets", "")),
        start=html.escape(typed.get("start", "")), end=html.escape(typed.get("end", "")),
        notes=html.escape(typed.get("notes", "")), picker=picker(typed.get("path", ""), optional=True),
        folder_hint=("Click Browse&hellip; and choose the folder; its path fills in here. "
                     "Nothing is sent by the folder window; VulnScope only uses it to find the folder. ")
        if container else "",
        upload_mb=app.max_upload // 1048576, recent=_recent(app), busy=busy_overlay(),
        config=page_config({"csrf": app.csrf, "native": folders.NATIVE_PICKER, "dialog": bool(folders.BROWSE_ROOTS)}),
        busy_js=asset("busy.js"), picker_js=asset("folder_picker.js")))


def _safe_name(i, fname):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(fname.replace("\\", "/")))[:120] or "evidence"
    return f"{i:03d}_{safe}"


def start(req):
    """POST /investigate: create the case, store the evidence, build the baseline, open the case."""
    app = req.app
    if resources.busy():
        req.close_connection = True
        return view(req, "Another analysis is already running on this machine. Wait for it to finish and try again.")
    length = req.length()
    if length <= 0 or length > app.max_upload:
        req.close_connection = True
        return view(req, f"Upload must be between 1 byte and {app.max_upload // 1048576} MB.")
    tmp = app.run_root(runname.new_run(app.data_dir, "incident-upload"))
    try:
        try:
            fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""), tmp, _safe_name)
        except multipart.MultipartError as exc:
            req.close_connection = True
            return view(req, str(exc))
        if not app.csrf_ok(fields.get("csrf", "")):
            return req.send_text(403, "Forbidden")
        return _start(req, fields, [p for name, p in parts if name == "evidence"], tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)        # uploads were copied into the case


def _start(req, fields: dict, uploads: list[str], tmp: str):
    app = req.app
    typed = {k: fields.get(k, "") for k in ("case_name", "scope_nets", "start", "end", "notes", "path")}
    raw = typed["path"].strip().strip('"').strip("'")
    files: list[str] = []
    if raw:
        folder = folders.resolve(raw)
        if not os.path.isdir(folder):
            return view(req, f"Folder not found: {raw}. Use the full path, for example {folders.path_example()}.", typed)
        data_dir = os.path.realpath(app.data_dir) + os.sep
        files = [f for f in input_files([folder], app.data_dir) if not os.path.realpath(f).startswith(data_dir)]
        if not files:
            return view(req, f"No files found in {raw}.", typed)
    files += uploads
    if not files:
        return view(req, "Add evidence: choose a folder, upload files, or both.", typed)
    who = cases.actor_name(None)
    os.makedirs(cases_dir(app), mode=0o700, exist_ok=True)
    case_id = runname.new_run(cases_dir(app), typed["case_name"])
    case_dir = os.path.join(cases_dir(app), case_id)
    try:
        c = cases.create(case_dir, typed["case_name"], actor=who,
                         scope_nets=[n for n in re.split(r"[,\s]+", typed["scope_nets"]) if n],
                         start=typed["start"].strip() or None, end=typed["end"].strip() or None,
                         notes=typed["notes"])
    except UserError as exc:
        shutil.rmtree(case_dir, ignore_errors=True)
        return view(req, str(exc), typed)
    stored = 0
    for f in files:
        name = os.path.basename(f)
        if f in uploads:
            name = name.split("_", 1)[1] if "_" in name else name     # drop the upload's numbering
        try:
            cases.add_evidence(c, f, who, original_name=name)
            stored += 1
        except UserError as exc:
            c.audit(who, "evidence_refused", original_name=name, reason=str(exc))
    shutil.rmtree(tmp, ignore_errors=True)           # the uploads are in the case now
    if not stored:
        shutil.rmtree(case_dir, ignore_errors=True)
        return view(req, "None of the evidence could be stored.", typed)
    try:
        with resources.job_slot():
            run(c, who)
    except UserError as exc:
        return view(req, f"The case was created, but its report could not be built: {exc}", typed)
    except Exception:
        traceback.print_exc()          # the case folder is kept for a look at what went wrong
        return view(req, "The case was created, but its report failed; see the server console for details.", typed)
    req.redirect(f"/cases/{case_id}/")


def _open(app, case_id: str):
    root = os.path.realpath(cases_dir(app))
    d = os.path.realpath(os.path.join(root, case_id))
    if not d.startswith(root + os.sep) or not os.path.isfile(os.path.join(d, cases.CASE_FILE)):
        return None
    try:
        return cases.open_case(d)
    except UserError:
        return None


def _recent(app) -> str:
    root = cases_dir(app)
    if not os.path.isdir(root):
        return ""
    rows = []
    for name in os.listdir(root):
        c = _open(app, name)
        if c is not None:
            rows.append((c.data.get("created", ""), name, c))
    if not rows:
        return ""
    rows.sort(reverse=True)
    body = "".join(f'<tr><td><a href="/cases/{html.escape(name)}/">{html.escape(c.data["name"])}</a></td>'
                   f'<td>{html.escape(created[:16].replace("T", " "))} UTC</td><td>{len(c.evidence())} file(s)</td></tr>'
                   for created, name, c in rows[:LISTED])
    return f'<h2>Recent cases</h2><table class="cases">{body}</table>'


STATUS_WORDS = {"parsed": "read", "parsed_with_errors": "read, some records could not be",
                "rejected": "not readable yet", "stored": "stored, not read yet"}


def case_get(req, case_id: str, rest: str):
    """GET /cases/<id>/ (the case page) and /cases/<id>/v<N>/<report file>."""
    c = _open(req.app, case_id)
    if c is None:
        return req.send_text(404, "Not found")
    if not rest:
        return _case_page(req, case_id, c)
    m = re.fullmatch(r"v(\d{1,6})/([a-z_.]+)", rest)
    if not m or m.group(2) not in REPORT_FILES:
        return req.send_text(404, "Not found")
    target = os.path.join(c.path("reports"), f"baseline-v{int(m.group(1))}", m.group(2))
    if not os.path.isfile(target):
        return req.send_text(404, "Not found")
    # the report quotes original log lines: run its page in an opaque origin, like a reopened report
    req.send_file(target, {"Content-Security-Policy": SAVED_SANDBOX})


def _case_page(req, case_id: str, c):
    d = c.data
    versions = baselines(c)
    latest = versions[-1][0] if versions else None
    summary = {}
    if latest is not None:
        with open(os.path.join(versions[-1][1], "incident_report.json"), encoding="utf-8") as fh:
            r = json.load(fh)
        summary = {"timeline": len(r.get("timeline", [])), "findings": len(r.get("findings", [])),
                   "gaps": len(r.get("gaps", []))}
    e = html.escape
    window = d.get("window") or {}
    scope = ", ".join((d.get("scope") or {}).get("networks") or []) or "everything in the evidence"
    when = (f"{e(window['start'] or 'the first record')} to {e(window['end'] or 'the last record')}"
            if window.get("start") or window.get("end") else "all of the evidence")
    ev_rows = "".join(
        f"<tr><td>{e(r['original_name'])}</td><td>{r['size']:,} bytes</td>"
        f"<td>{e(STATUS_WORDS.get(r.get('status', ''), r.get('status', '')))}"
        f"{(': ' + e(r['status_detail'])) if r.get('status_detail') else ''}</td>"
        f"<td><code title=\"{e(r['sha256'])}\">{e(r['sha256'][:16])}…</code></td></tr>" for r in c.evidence())
    if latest is not None:
        report = (f'<p><a class="button" href="v{latest}/incident_report.html"><strong>Open the baseline report '
                  f'(v{latest})</strong></a></p><p>{summary["timeline"]:,} timeline item(s), {summary["findings"]} finding(s), '
                  f'{summary["gaps"]} note(s) on what the evidence can\'t show.</p>'
                  f'<p class="hint">Also as <a href="v{latest}/incident_report.md">Markdown</a> and '
                  f'<a href="v{latest}/incident_report.json">JSON</a>.'
                  + (" Earlier versions: " + ", ".join(f'<a href="v{v}/incident_report.html">v{v}</a>'
                                                       for v, _ in versions[:-1]) if len(versions) > 1 else "")
                  + "</p>")
    else:
        report = "<p>No report yet.</p>"
    notes = f"<p>{e(d['notes'])}</p>" if d.get("notes") else ""
    body = (f'<p><a href="/investigate">&larr; Investigate an incident</a></p>'
            f"<h1>{e(d['name'])}</h1>{notes}"
            f"<p>Scope: {e(scope)}. Window: {when}.</p>"
            f"{report}<h2>Evidence</h2>"
            f'<table class="cases"><tr><th>File</th><th>Size</th><th>Status</th><th>SHA-256</th></tr>{ev_rows}</table>'
            f'<p class="hint">Case folder: <code>{e(c.dir)}</code>. The originals are kept read-only there, with a '
            f"hash-chained audit log; <code>vulnflow incident verify</code> checks both.</p>")
    req.send(200, page(d["name"], body, f"<style>{asset('forms.css')}</style>"))
