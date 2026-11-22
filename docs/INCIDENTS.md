# Incident cases (first step)

Incident Analysis helps an authorized responder work out what happened from the evidence they
have, without a vulnerability scan and without any one required log source. This first step is
command-line only and reads Zeek logs. Windows event logs, the web pages, and the optional AI
interpretation come in later steps.

The vulnerability workflow (`vulnflow analyze`, the upload page, `results.json`) is not changed by
any of this.

## Try it

```sh
python -m vulnflow incident new cases/demo --name "Demo case" --scope-net 10.50.0.0/16 \
    --start 2026-10-19T00:00:00Z --end 2026-10-21T00:00:00Z --notes "Ticket 123"
python -m vulnflow incident add cases/demo samples/artex_ai_agentic_intrusion
python -m vulnflow incident run cases/demo
python -m vulnflow incident status cases/demo
python -m vulnflow incident record cases/demo <event id from the report>
python -m vulnflow incident verify cases/demo
```

`run` prints each file's status and writes `cases/demo/reports/baseline-v1/` with
`incident_report.json`, `.md` and `.html`. Open the HTML file in a browser.

## What a case folder holds

| Path | What |
| --- | --- |
| `case.json` | Name, scope (address ranges, hosts, accounts), time window with a margin, known entities, notes |
| `evidence.json` | One record per stored file: SHA-256, size, original name, who uploaded it and when, detected format, status |
| `evidence/<sha256>/` | The original file, stored once and made read-only |
| `audit.jsonl` | Every action on the case. Each line carries the hash of the line before it; `verify` finds an edited or removed line |
| `parsed/` | Normalized events per file (Parquet), reused while the file and its reader are unchanged |
| `reports/baseline-vN/` | One folder per baseline version. Earlier versions are kept |

- **Duplicates.** A file with the same content as one already in the case is recorded as a
  duplicate upload and not stored again.
- **Damaged files.** Records before the damage are kept. Unreadable records are listed with their
  line number and reason. Files of an unsupported format are listed as rejected with the reason.
  None of these stop the case.
- **New evidence.** Add files and run again: a new baseline version is written, and files already
  parsed are not parsed again. If nothing changed, the existing baseline is reported instead
  (`--force` writes a new version anyway).
- **Who.** `--actor NAME` (or `VULNSCOPE_ACTOR`) names the person for the audit log; otherwise the
  account running the command.

## The baseline report

Built from the evidence with fixed rules (`vulnflow/incident/incident.sql`, ruleset version in its
header) and no AI model. The same evidence, readers, ruleset and scope give the same report apart
from its generation time; the `run_key` identifies that combination.

- **Timeline.** Records grouped by who talked to whom about what, with first and last time.
  Records without a readable time are listed apart, never placed at a guessed time.
- **Findings.** Each says whether it is *observed* (restates what records say) or *inferred*
  (connects records that share no identifier), and on what basis: `same_id` (for example the Zeek
  `uid` that ties an HTTP record to its connection) or `time_proximity`.
- **Evidence.** Every timeline item and finding cites event IDs. The report carries each cited
  original record with its file, SHA-256 and line, so a statement can be checked without the tool.
  `incident record` prints any event's original record and logs that it was viewed.
- **Gaps and uncertainty.** Missing sources (no host logs means logons and processes are unknown,
  not absent), unreadable records, times without a zone that were read as UTC, evidence that does
  not cover the whole window, sensor packet loss.
- A completed connection means packets went both ways. It never shows that a login or request
  succeeded.

The report's format is declared in `vulnflow/incident/report_schema.py` and published as
[incident_report.schema.json](incident_report.schema.json). This schema covers incident reports
only; `results.json` is unchanged.

## Not in this step

Windows EVTX, Linux, CloudTrail, Azure and the other network formats; Nessus as context; the web
pages, background jobs and sign-in; the AI interpretation; S3 storage. Host names and accounts in
the scope are recorded but not yet used to filter events.
