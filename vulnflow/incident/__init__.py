"""Incident Analysis: cases, preserved evidence, normalized events and a deterministic baseline report.

The vulnerability workflow (pipeline.py, correlate.py, results.json) is not used or changed here.
An incident case is a folder:

    case.json            name, scope, time window, known entities, notes
    evidence.json        one record per stored file (sha256, uploader, time, format, status)
    evidence/<sha256>/   the original files, stored once and made read-only
    audit.jsonl          append-only, hash-chained log of what was done to the case
    parsed/              normalized events per file, cached by (sha256, adapter version)
    reports/baseline-vN/ incident_report.json, .md and .html, one folder per baseline version

See docs/INCIDENTS.md.
"""
ENGINE_VERSION = "0.1.0"
