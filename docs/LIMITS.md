# Configured limits

Numeric bounds in one place. Each row names where the value is set; change it there.

| Boundary | Limit | Meaning | Set in |
| --- | ---: | --- | --- |
| Upload size | 1,024 MB | per upload; `serve --max-upload-mb` | `vulnflow/web/server.py` |
| Upload chunk | 64 KB | uploads stream to disk in chunks | `vulnflow/multipart.py` |
| `.gz` expansion | 200× | of compressed size, minimum 256 MB; `VULNSCOPE_MAX_GZ_BYTES` | `vulnflow/parsers/_util.py` |
| Parser batch | 100,000 | records per Parquet batch | `vulnflow/store.py` |
| Native readers | on | DuckDB parses ordinary Zeek conn logs and Palo Alto CSV; `VULNSCOPE_NATIVE_READERS=0` uses the Python parsers for everything | `vulnflow/parsers/native.py` |
| Parse workers | 1 per CPU | at most one per input file and one per GiB of the memory ceiling; inputs under 64 MB use one process; `VULNSCOPE_PARSE_WORKERS` | `vulnflow/normalize.py` |
| De-duplication skew | 2 s | cross-sensor match window; `--dedup-skew` | `vulnflow/store.py` |
| Scan window | 7 days | telemetry before/after a host's scan; `--scan-window-days` | `vulnflow/cli.py` |
| Blast-radius depth | 2 hops | `--hops` | `vulnflow/cli.py` |
| Large upload | 20 MB | upload size counted as a post-contact lead | `vulnflow/correlate.py` |
| DuckDB memory | 60% | of usable RAM, ≤80% of free RAM, keeping 25% (≥1.5 GiB); `VULNSCOPE_DUCKDB_MEMORY` | `vulnflow/resources.py` |
| DuckDB threads | 1 per GiB | of DuckDB memory, up to usable CPUs; `VULNSCOPE_DUCKDB_THREADS` | `vulnflow/resources.py` |
| DuckDB spill | 80% | of the working disk's free space; `VULNSCOPE_DUCKDB_MAX_TEMP` | `vulnflow/resources.py` |
| Concurrent analyses | 1 | per process; `VULNSCOPE_MAX_JOBS` | `vulnflow/resources.py` |
| Article previews | 60 | pages per run, 800 KB each | `vulnflow/article_preview.py` |
| Article briefs | 20 | articles per run, 18,000 characters each | `vulnflow/article_brief.py` |
| Assistant context | 150 | findings for hosted providers; 10 for `local` | `vulnflow/llm.py` |
| Assistant history | 20 | conversation turns kept | `vulnflow/llm.py` |
| Hostile activity diagram | 40 | nodes | `vulnflow/diagram.py` |
| Explorer focus | 24 / 400 | labeled / drawn peers per side | `vulnflow/static/explorer.js` |
| Explorer IP list | 8 / 20 | preview rows / rows per page | `vulnflow/static/explorer.js` |
| Explorer host lists in the page | 200 / 1,000 / 20 | outside addresses and internal peers kept per host / outside addresses with IPS alerts kept even past 200 / rows with connection examples when a list is cut (counts use the full lists; the upload server sends the full lists from `normalized/explorer_contacts.parquet`) | `vulnflow/explore.py` |
| Explorer data in the browser | 1 GB / ~512 MB | unpacked report data a page will open / what Chrome and Edge can hold as text (use Firefox or Safari beyond it) | `vulnflow/static/vf_data.js` |
| Explorer data read back | 2 GB | unpacked Explorer data in a saved page (Open report, Compare) | `vulnflow/explore.py` |
| Explorer overview | 2,000 / 200 / 48 | hosts (riskiest) / risky paths / outside addresses drawn | `vulnflow/explore.py`, `vulnflow/static/explorer.js` |
| Attack paths | 9 | ranked lines | `vulnflow/static/attackpaths.js` |
| Timeline | 20,000 | flows drawn; 200 alerts, 400 IOC lookups | `vulnflow/explore.py` |
| Explainer note | 15 s | the **?** note opens by itself when a view opens | `vulnflow/static/explorer.js` |
| Scanner detection | 100 / 70% / 200 | address/port pairs tried / sessions failed / scanners listed | `vulnflow/scanners.py` |
| One-way sensor warning | 2% / 500 | sessions with any answer / minimum sessions | `vulnflow/scanners.py` |
| Packet-loss warning | 1% | Zeek's estimated capture loss | `vulnflow/report.py` |
| Branding name | 40 | characters before "VulnScope" | `vulnflow/branding.py` |
| Branding logo | 512 KB, 2,048 px | file size, longest side | `vulnflow/branding.py` |
| Branding unlock | 30 min, 5 attempts | unlock lifetime; free attempts before a doubling lockout | `vulnflow/web/branding_page.py` |
| Report network name | 60 | characters | `vulnflow/runname.py` |
| Compare upload | 64 MB | IOC CSVs added on the Compare page | `vulnflow/web/compare_page.py` |
| Compare hosts | 12 / 1,000 | related hosts per report drawn on the page / per CSV cell (`comparison.json` has all) | `vulnflow/compare.py` |
| Compare folder search | 4 levels | how deep `vulnflow compare FOLDER` looks for report folders | `vulnflow/compare.py` |
| Earlier comparisons | 12 | listed on the Compare page (all are kept) | `vulnflow/web/compare_page.py` |
| All-networks Explorer | 3,000 / 3,000 / 300 / 80 | hosts / links / risky paths / outside addresses drawn over all compared reports | `vulnflow/combine.py` |
| All-networks host cards | 24 / 24 / 6 / 12 | outside addresses / peers / two-hop hosts per card; hosts beamed per outside address (each report's Explorer has all) | `vulnflow/combine.py` |
