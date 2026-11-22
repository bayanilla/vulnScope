"""The upload page and the two ways to start an analysis from it: uploading files, or reading a
folder on this machine in place. Both end in ``_analyze``; a completed report's output folder is
reopened instead (see saved.py), and a folder with a sites list is analyzed one report per site,
then compared (see sites.py)."""
from __future__ import annotations

import dataclasses
import html
import os
import re
import shutil
import sys
import traceback

from .. import multipart, resources, runname, saved, sites
from ..branding import icon_data_uri, product_name
from ..errors import UserError
from ..parsers import FORMATS
from ..pipeline import input_files, run
from ..report import CSS, HTML_OPEN, THEME_INIT, theme_control
from . import folders
from .pages import asset, busy_overlay, error_html, page_config, picker

ANALYZE_HINT = "Large folders can take several minutes. Keep this tab open; the report opens here when it's ready."

FORM = """{html_open}<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{product_name}</title><link rel="icon" href="{icon}">
{theme_init}<style>{css}{forms_css}</style></head><body>{theme_ui}
<h1>Analyze files with {product_name}</h1>
<p>Point the workflow at network telemetry, with optional Nessus results. It cleans and
normalizes the data and produces an executive summary and a technical report. Without scan data,
vulnerability status remains unknown.</p>
{error}
<section id="report-details" aria-labelledby="rd-title"><h2 id="rd-title">Report details <span class="hint">(optional)</span></h2>
<label for="report_name">Report name</label>
<input id="report_name" type="text" name="report_name" value="{report_name}" maxlength="100" placeholder="e.g. Plant 3 network review, November" autocomplete="off">
<label for="report_network">Network</label>
<input id="report_network" type="text" name="report_network" value="{report_network}" maxlength="60" placeholder="e.g. Plant 3" autocomplete="off">
<div class="hint">The network or site the data comes from. When you <a href="/compare">compare reports</a>, reports with the same
network count as one network.</div>
<label for="report_description">Description</label>
<textarea id="report_description" name="report_description" maxlength="2000" rows="3" placeholder="Scope, case number, who asked for it&hellip;">{report_description}</textarea>
<div class="hint">Shown at the top of the reports and in the Explorer. Results are saved in a folder named after the report
plus the date and time (for example <code>Plant-3-network-review_2026-11-12_10-19-14</code>); without a name, the usual
folder name plus the date and time.</div></section>
<section id="shared-options" aria-labelledby="so-title"><h2 id="so-title">Options <span class="hint">(optional, used by either way of analyzing)</span></h2>
<label for="nets">Internal networks</label>
<input id="nets" type="text" name="internal_nets" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16">
<div class="hint">Anything outside these ranges is treated as the internet. Leave blank for private ranges.</div>
<label for="ioc_archive">IOC CSV</label>
<input id="ioc_archive" type="file" name="ioc_archive" accept=".csv,text/csv">
<div class="hint">Use a CSV with type and indicator columns. Source links are optional. An IOC CSV inside the folder is found too.</div>
<label class="check"><input type="checkbox" id="skip_copies" name="skip_copies" value="1"{skip_copies}> Skip full copies of flows and Zeek events</label>
<div class="hint">For large inputs: leaves out <code>normalized/flows.csv</code> and the Zeek event files, which are about as large as the input. Reports and the Explorer are the same.</div>
</section>
<form method="post" action="/analyze-folder" enctype="multipart/form-data" data-busy="Analyzing…" data-busy-hint="{analyze_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="path">Folder on this computer</label>
{picker}
<div class="hint">{folder_hint}The files are read where they are, including subfolders; nothing is copied or uploaded. Hidden files are skipped.</div>
<div class="btnrow"><button type="submit" id="analyze-folder">Analyze folder</button></div>
<div id="sites-msg" class="hint" role="status" aria-live="polite"></div>
<div class="hint">To see a completed report again, choose its output folder (the one with <code>results.json</code>
and <code>explorer.html</code>): the button changes to Open report, and nothing is reanalyzed. A folder with a sites
list (<code>{sites_file}</code>) is analyzed one report per site, then compared, so each network's sites stay apart.</div>
</form>
<details id="upload-instead"{upload_open}><summary>Upload files instead</summary>
<p class="hint">For files that aren't in a folder this server can read, for example when it runs on another machine.
Uploads are copied to this server and limited to {upload_mb} MB in all.</p>
<form method="post" action="/analyze" enctype="multipart/form-data" data-busy="Analyzing…" data-busy-hint="{analyze_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="folder">Folder of telemetry and scans</label>
<input id="folder" type="file" name="folder" webkitdirectory directory multiple>
<div class="hint">Choose one folder to include its files and subfolders in a single analysis. A Nessus scan is optional.</div>
<label for="telemetry">Network telemetry</label>
<input id="telemetry" type="file" name="telemetry" multiple>
<div class="hint">Optional additional files: Zeek connection, DNS, SMTP and industrial protocol logs; Palo Alto traffic and threat logs; NetFlow / VPC flow / SIEM CSV; Zeek logs exported from Elastic/Filebeat (Kibana CSV or NDJSON); packet captures (.pcap/.pcapng, converted with Zeek).</div>
<label for="scans">Vulnerability scans</label>
<input id="scans" type="file" name="scans" multiple>
<div class="hint">Optional: Nessus .nessus (preferred) or Nessus CSV export. Without one, no vulnerability score or priority is assigned.</div>
<button type="submit">Analyze uploaded files</button>
</form></details>
<p class="hint">Formats are detected automatically: {formats}. Folder selection is supported by Chrome and other compatible browsers. Files stay on this machine.
<a href="/compare">Compare reports</a> · <a href="/settings">Security Assistant settings</a> · <a href="/branding">Branding</a></p>
{busy}{config}
<script>{busy_js}</script>
<script>{picker_js}</script>
<script>{upload_js}</script>
</body></html>"""

BUSY_MESSAGE = ("Another analysis is already running on this machine. "
                "Wait for it to finish and try again.")


def page(req, error: str = "", upload_open: bool = False):
    """GET / and every refusal of the two analysis forms (the form keeps what was typed)."""
    app = req.app
    container = bool(folders.CONTAINER_DATA)
    req.send(200, FORM.format(
        css=CSS, forms_css=asset("forms.css"), html_open=HTML_OPEN, theme_init=THEME_INIT, theme_ui=theme_control(),
        product_name=html.escape(product_name()), icon=icon_data_uri(), error=error_html(error),
        formats=", ".join(FORMATS) + ", pcap/pcapng (converted with Zeek)", csrf=app.csrf,
        analyze_hint=html.escape(ANALYZE_HINT), sites_file=sites.FILENAME,
        picker=picker(app.last_path),
        report_name=html.escape(app.last_report.get("name", "")),
        report_network=html.escape(app.last_report.get("network", "")),
        report_description=html.escape(app.last_report.get("description", "")),
        folder_hint=("Click Browse&hellip;, choose the folder and confirm; its path fills in here. "
                     "Your browser may ask twice to upload (the folder window's Upload button, "
                     "then &ldquo;Upload files to this site?&rdquo;): click Upload both times. "
                     "Nothing is sent; VulnScope only uses it to find the folder. ") if container else "",
        skip_copies=" checked" if not req.app.base_cfg.normalized_copies else "",
        upload_mb=app.max_upload // 1048576,
        upload_open=" open" if upload_open else "",
        busy=busy_overlay(),
        config=page_config({"csrf": app.csrf, "native": folders.NATIVE_PICKER, "dialog": bool(folders.BROWSE_ROOTS)}),
        busy_js=asset("busy.js"), picker_js=asset("folder_picker.js"), upload_js=asset("upload.js")))


def _report_details(fields: dict) -> dict:
    return runname.clean(fields.get("report_name"), fields.get("report_description"), fields.get("report_network"))


def _config(req, nets: str, skip_copies: bool = False):
    """The server's analysis settings, with the internal networks typed on the form (if any) and
    the form's choice to skip the full normalized copies."""
    base = req.app.base_cfg
    cfg = dataclasses.replace(base, internal_nets=list(base.internal_nets))
    if skip_copies:
        cfg.normalized_copies = False
    nets = nets.strip()
    if nets:
        cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
    return cfg


def _analyze(req, run_id: str, files: list[str], nets: str, report: dict, skip_copies: bool = False):
    """Analyze ``files`` into run ``run_id`` and open its page; on a problem the person can fix,
    show it on the upload page and drop the run folder."""
    root = req.app.run_root(run_id)
    try:
        run(files, os.path.join(root, "out"), _config(req, nets, skip_copies), workdir=root, report=report)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return page(req, str(exc))
    except Exception:
        traceback.print_exc()          # the run folder is kept for a look at what went wrong
        return page(req, "The analysis failed; see the server console for details.")
    req.app.last_report = {}           # a new analysis starts with empty report details
    req.redirect(f"/runs/{run_id}/")


def analyze_upload(req):
    """POST /analyze: files uploaded from the browser, streamed to disk, then analyzed."""
    app = req.app
    if resources.busy():                          # refuse before reading a large upload
        req.close_connection = True
        return page(req, BUSY_MESSAGE)
    length = req.length()
    if length <= 0 or length > app.max_upload:
        req.close_connection = True               # don't read an oversized body at all
        return page(req, f"Upload must be between 1 byte and {app.max_upload // 1048576} MB.", upload_open=True)
    # The name arrives inside the upload, after the files, so the run starts in a temporary
    # folder and is renamed "<name>_<timestamp>" once the form has been read.
    tmp_id = runname.new_run(app.data_dir, "upload")
    tmp_root = app.run_root(tmp_id)
    in_dir = os.path.join(tmp_root, "in")
    os.makedirs(in_dir)
    try:
        fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""), in_dir, _safe_name)
    except multipart.MultipartError as exc:
        shutil.rmtree(tmp_root, ignore_errors=True)
        req.close_connection = True
        return page(req, str(exc), upload_open=True)
    if not app.csrf_ok(fields.get("csrf", "")):
        shutil.rmtree(tmp_root, ignore_errors=True)
        return req.send_text(403, "Forbidden")
    report = app.last_report = _report_details(fields)
    if not parts:
        shutil.rmtree(tmp_root, ignore_errors=True)
        return page(req, "Please choose at least one telemetry file and one scan file.", upload_open=True)
    run_id = runname.new_run(app.data_dir, report["name"])
    os.rmdir(app.run_root(run_id))
    os.rename(tmp_root, app.run_root(run_id))
    files = [os.path.join(app.run_root(run_id), os.path.relpath(path, tmp_root)) for _, path in parts]
    return _analyze(req, run_id, files, fields.get("internal_nets", ""), report,
                    fields.get("skip_copies") == "1")


def _safe_name(i, fname):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(fname.replace("\\", "/")))[:120] or "upload"
    return f"{i:02d}_{safe}"


def _folder_form(req):
    """The folder form: url-encoded (older pages, scripts) or multipart, when it carries the IOC CSV
    chosen under Options. Returns (form, IOC CSV paths, temporary folder holding them) or None."""
    app = req.app
    if not req.headers.get("Content-Type", "").lower().startswith("multipart/form-data"):
        form = req.read_form()
        return None if form is None else (form, [], None)
    length = req.length()
    if length <= 0 or length > app.max_upload:
        req.close_connection = True
        return None
    tmp_root = app.run_root(runname.new_run(app.data_dir, "upload"))
    os.makedirs(os.path.join(tmp_root, "in"))
    try:
        fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""),
                                        os.path.join(tmp_root, "in"), _safe_name)
    except multipart.MultipartError:
        shutil.rmtree(tmp_root, ignore_errors=True)
        req.close_connection = True
        return None
    iocs = []
    for name, path in parts:
        if name == "ioc_archive" and not iocs:
            iocs.append(path)
        else:                                      # only the IOC CSV belongs on this form
            os.remove(path)
    return fields, iocs, tmp_root


def analyze_folder(req):
    """POST /analyze-folder: a folder on the machine running the server, read in place (plus the
    IOC CSV chosen under Options, if any); a completed report's output folder is reopened instead
    of analyzed."""
    got = _folder_form(req)
    if got is None:
        return req.send_text(400, "Bad request")
    form, iocs, tmp_root = got
    try:
        return _analyze_folder(req, form, iocs, tmp_root)
    finally:
        if tmp_root and os.path.isdir(tmp_root):    # not moved into a run: nothing to keep
            shutil.rmtree(tmp_root, ignore_errors=True)


def _analyze_folder(req, form: dict, iocs: list[str], tmp_root: str | None):
    app = req.app
    if not app.csrf_ok(form.get("csrf", "")):
        return req.send_text(403, "Forbidden")
    raw = form.get("path", "").strip().strip('"').strip("'")
    folder = folders.resolve(raw)
    app.last_path = raw
    app.last_report = report = _report_details(form)
    if not raw:
        return page(req, "Choose a folder first: click Browse… and pick one, or type its full path.")
    if not os.path.isdir(folder):
        return page(req, f"Folder not found: {raw}. Use the full path, for example {folders.path_example()}.")
    if saved.is_report_folder(folder):
        return _open_report(req, folder)
    if resources.busy():
        return page(req, BUSY_MESSAGE)
    if sites.find(folder):
        if iocs:
            return page(req, "A folder with a sites list can't take an IOC CSV from Options yet: "
                             "put the IOC CSV in the folder instead, or clear the IOC CSV field.")
        return _analyze_sites(req, folder, form)
    data_dir = os.path.realpath(app.data_dir) + os.sep
    files = [f for f in input_files([folder], app.data_dir) if not os.path.realpath(f).startswith(data_dir)]
    if not files:
        return page(req, f"No files found in {folder}.")
    run_id = runname.new_run(app.data_dir, report["name"])
    root = app.run_root(run_id)
    if tmp_root:
        os.rmdir(root)
        os.rename(tmp_root, root)
        files += [os.path.join(root, os.path.relpath(p, tmp_root)) for p in iocs]
    else:
        os.makedirs(os.path.join(root, "in"))
    with open(os.path.join(root, "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
    return _analyze(req, run_id, files, form.get("internal_nets", ""), report,
                    form.get("skip_copies") == "1")


def _analyze_sites(req, folder: str, form: dict):
    """A folder with a sites list: one report per site, named and with its network from the list,
    then a comparison of them, which opens when it's ready (sites.py)."""
    app = req.app
    try:
        _, cid = sites.analyze(app.data_dir, folder, _config(req, form.get("internal_nets", ""),
                                                             form.get("skip_copies") == "1"),
                               log=lambda m: print(m, file=sys.stderr))
    except UserError as exc:
        return page(req, str(exc))
    except Exception:
        traceback.print_exc()          # the run folders are kept for a look at what went wrong
        return page(req, "The analysis failed; see the server console for details.")
    app.last_report = {}
    req.redirect(f"/compare/{cid}/")


def _open_report(req, folder: str):
    """Rebuild a completed report's pages from its output folder, without reanalyzing."""
    app, root = req.app, None
    try:
        res, data = saved.load_folder(folder)
        run_id = runname.new_run(app.data_dir, (res.get("report") or {}).get("name", ""))
        root = app.run_root(run_id)
        saved.write(res, data, os.path.join(root, "out"), folder, app.last_path)
    except saved.SavedRunError as exc:
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return page(req, str(exc))
    except Exception:
        traceback.print_exc()
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return page(req, "The saved report could not be opened; see the server console for details.")
    req.redirect(f"/runs/{run_id}/")


def folder_kind(req):
    """POST /folder-kind: whether a folder is a completed report's output folder, and how many sites
    its sites list names (the page relabels its button)."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    folder = folders.resolve(str(body.get("path") or ""))
    found = bool(folder) and os.path.isdir(folder)
    kind = {"report": found and saved.is_report_folder(folder)}
    listed = found and not kind["report"] and sites.find(folder)
    if listed:
        try:
            kind["sites"] = len(sites.read(listed))
        except UserError:
            kind["sites"] = -1         # Analyze folder shows what's wrong with the list
    return req.send_json(200, kind)
