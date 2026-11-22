# What ULTRA changes from MAX

ULTRA starts from VulnScope MAX (commit `621599b`) and keeps every feature: the upload page,
Compare, the Security Assistant, PCAP input, and the Explorer with its 3D, Timeline and Attack
paths views. The changes are in the engine. The rule for each one was that the reports must not
change: `scripts/compare_runs.py` compares a MAX run and an ULTRA run of the same input, and all
six bundled samples and a generated 1 GB set come out the same (results.json apart from its
timestamp, and every CSV).

| Change | Where | Why |
| --- | --- | --- |
| One way to open DuckDB | `vulnflow/db.py` | Every connection goes through `db.connect()`. It refuses DuckDB older than 1.2 (cannot run the store) and 1.3.0 (silently drops rows from joins on a time range), and turns off DuckDB's on-demand download of extensions, so the engine never reaches the internet by itself. `requirements.txt` pins `duckdb>=1.2,!=1.3.0,<2`. |
| IOC matching in SQL | `vulnflow/ioc_archive.py`, `Store.flow_ips`, `Store.pair_counts` | Indicators are matched against the distinct addresses in the store, not by walking every session in Python. |
| `flows.csv` written by DuckDB | `Store.export_flows_csv` | One `COPY` statement, byte for byte what the Python writer produced, spreadsheet formula guard included. |
| Alerts are a table | `vulnflow/correlate.py` | IDS and firewall alerts are joined to findings in one query, not looked up finding by finding. Event counts per stream come from DuckDB too. |
| Native readers | `vulnflow/parsers/native.py` | Zeek `conn` logs (TSV) and Palo Alto CSV exports, usually most of the bytes, are parsed by DuckDB straight into Parquet. |
| Timeline flow sample by join | `Store.timeline_flows` | On large runs the Timeline keeps a sample of flows, flagged addresses first. Each flow was tested against the list of flagged addresses several times over; it is now a join. Same flows picked, 58 seconds down to under 1 on the 1 GB set. |
| The model is a SQL file | `vulnflow/model.sql`, `vulnflow/sqlfile.py` | The correlator's queries have names and live in one file that can be read, reviewed and run by hand. |
| A declared results format | `vulnflow/results_schema.py`, `docs/results.schema.json` | results.json has a published JSON Schema. A fresh analysis is checked against it, and a saved file that does not fit is refused with the reason. |

## Speed

The generated 1 GB set (4.2 million sessions after de-duplication, 6,904 findings), 4 CPUs,
DuckDB 1.4.1, without the normalized copies:

| | MAX | ULTRA |
| --- | --- | --- |
| Whole run | 303 s | 243 s |
| Reading and de-duplicating the files | 65 s | 40 s |
| Correlation and scoring | 34 s | 34 s |
| Building the Explorer | about 200 s | about 150 s |

Building the Explorer is now most of a large run. That time is Python walking every host's
contacts with outside addresses, and it is the next thing to move into SQL.

## Native readers and the fallback

A native reader takes a file only when every line in it is ordinary: plain epoch times, whole
numbers of at most 15 digits, ASCII text, the expected number of columns, one header. If anything
else turns up, the whole file goes to the Python parser, as in MAX. Addresses that are not plain
dotted IPv4 are still canonicalised by the same Python function, so IPv6 comes out the same.
`.gz` files are expanded under the same size cap as before.

`tests/test_native_readers.py` parses each test file both ways and compares every row, the file
counts, the notes and the alerts, over the bundled samples, hand-written awkward rows and a few
hundred randomly damaged files. Set `VULNSCOPE_NATIVE_READERS=0` to switch the native readers off.

## Not changed yet

- Findings are still Python records. Only the alerts moved into DuckDB; exposure, anchors and
  scoring are computed in the same mix of SQL and Python as in MAX.
- IOC matching against Zeek events (DNS, TLS, HTTP, files) is still a Python loop.
- The Explorer's per-host contact lists are still assembled in Python (see Speed above).
- The store's own SQL (`vulnflow/store.py`) and the Explorer's flow queries are still inline; only
  the correlator's queries moved to `model.sql`.
- Other formats (Zeek JSON, Suricata, NetFlow CSV, Filebeat, Nessus) keep their Python parsers.
