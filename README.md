# Múcaro VulnScope

**Network telemetry and vulnerability scans, correlated into reports for system owners.**

VulnScope reads network telemetry (Zeek, Palo Alto, Suricata, flow exports, packet captures)
and optional Nessus results, then writes an **executive summary**, a **technical report** and an
interactive **Explorer** of the hosts involved. When scan findings are present, it correlates
vulnerable services with observed reachability and investigation leads. With telemetry alone, it
reports observed connections, IPS/IDS alerts and exact IOC matches, and marks vulnerability status
as **unknown**. Inputs are streamed into Parquet and correlated with DuckDB, so multi-GB log sets
fit in bounded memory.

**Proof of concept.** VulnScope is a local investigation aid for analysts. It reads files you
already have; it never scans, probes or contacts the hosts and addresses in your data. Scores and
indicators come from fixed, documented rules. An AI model is used only if you choose one for the
optional Security Assistant or article briefs. Reports prioritize investigation; they do not
confirm a compromise, establish exposure on their own, or replace host forensics.

The command-line package is `vulnflow`.

## Contents

- [Start VulnScope](#start-vulnscope)
- [Analyze your logs and scans](#analyze-your-logs-and-scans)
- [Explore hosts](#explore-hosts)
- [Ask the Security Assistant](#ask-the-security-assistant)
- [Interpret and validate the report](#interpret-and-validate-the-report)
- [Save and share results](#save-and-share-results)
- [Compare reports](#compare-reports)
- [Branding and themes](#branding-and-themes)
- [Privacy and practical limits](#privacy-and-practical-limits)
- [Further documentation](#further-documentation)

## Start VulnScope

### With Docker (Linux, macOS, Windows, air-gapped networks)

One image holds VulnScope, DuckDB and [Zeek](https://zeek.org) for linux/amd64 and linux/arm64, so
packet captures work out of the box. You need Docker Desktop on macOS and Windows, or Docker Engine
with the Compose plugin on Linux.

From the [latest release](https://github.com/bayanilla/vulnscope_max/releases/latest), download
`compose.yaml` and `env.example` into a folder of their own, then:

```sh
cp env.example .env           # optional: set VULNSCOPE_DATA, VULNSCOPE_RUNS, port, memory
docker compose pull           # download the image
docker compose up -d          # start the upload page
```

Open **http://127.0.0.1:8765/**. Results go to `VULNSCOPE_RUNS` (default `./vulnscope-out`). Stop
it with `docker compose down`.

To build the image from source instead, clone this repository, `cp .env.example .env`, and run
`docker compose up -d`. For networks with no internet, each release also carries the image as a
file to `docker load`; see [Air-gapped networks](ARCHITECTURE.md#air-gapped-networks-and-enclaves).

**Update.** The image holds the code it was built with, so a restart keeps the old version.
Run `docker compose pull && docker compose up -d` (or, from source, `git pull` then
`docker compose up -d --build`), then **analyze your data again**: each run's reports and Explorer
keep the version they were made with. Your `.env`, runs, settings and branding are kept.

### With Python

With Python 3.10 or later, in the environment you will run VulnScope from:

```sh
python3 -m pip install -r requirements.txt   # DuckDB, the one dependency
python3 -m vulnflow serve                    # upload page on http://127.0.0.1:8080/
```

`python3 start_upload_page.py` does the same, picks a free port and opens the browser. Packet
captures also need Zeek on the PATH (or `VULNSCOPE_ZEEK=/path/to/zeek`).

If the page does not start or load (port in use, a proxy in the way, an update that doesn't show),
see [Troubleshooting](docs/TROUBLESHOOTING.md).

### Try it without your own data

`example_output/` holds a finished synthetic 250-host run: open `explorer.html`,
`executive_summary.html` or `technical_report.html` in your browser. To analyze a bundled sample:

```sh
python3 -m vulnflow analyze samples/gootloader_seo_poisoning -o gootloader_output
python3 -m vulnflow compare-sample      # seven site reports from two companies, plus their comparison
```

All sample data is fabricated. [The sample guide](samples/README.md) describes every sample and
scenario, and the [screenshot gallery](screenshots/README.md) shows the reports and views.

## Analyze your logs and scans

1. On the upload page, enter a folder path on the computer running the server, or click
   **Browse…**, then **Analyze folder**. Every file in it and its subfolders is read where it sits;
   nothing is copied. Formats are detected by content, so any mix of files works. You can instead
   upload files under **Analyze files** (up to 1 GB per upload by default).
2. Optionally list your internal networks. The default is RFC 1918, CGNAT, loopback, link-local and
   ULA ranges.
3. Optionally open **Report details** to give the run a name, the **network** or site the data
   comes from, and a description. They appear in the reports and the Explorer, name the run folder,
   and let [Compare reports](#compare-reports) group reports from the same network.
4. When the run finishes, the results page links the reports, the Explorer and the Security
   Assistant. One analysis runs at a time.

From the command line:

```sh
python3 -m vulnflow analyze /path/to/case -o out --internal-net 10.0.0.0/8
python3 -m vulnflow analyze /path/to/case -o out --name "Plant 3 November" --network-name "Plant 3"
python3 -m vulnflow explore /path/to/case        # analyze and open the Explorer
```

**In Docker**, Compose shares your home folder **read-only** and **Browse** walks it (`/Users/you`
on macOS, `/home/you` on Linux, `/host` for `C:\Users\you` on Windows; pasted Windows paths are
translated). To share an evidence drive or a single inbox folder instead, set `VULNSCOPE_BROWSE`
in `.env`; see [Docker folders](ARCHITECTURE.md#docker-container).

**Several sites or companies in one folder.** One analysis treats everything in a folder as one
network, so the same private address at two sites becomes one host. To keep sites apart, give each
its own folder (one folder per company, a folder per site inside it) and add a `sites.csv` next to
the company folders:

```csv
folder,name,network,description
corvane/hq,Corvane HQ,Corvane,Head office
corvane/phoenix,Corvane Phoenix plant,Corvane,
ridgeline/denver,Ridgeline Denver office,Ridgeline,
```

The button then reads **Analyze 3 sites and compare**: each site gets its own report, and their
comparison opens when they are done. Only `folder` is required; `name` defaults to the site folder
and `network` to the company folder. An IOC CSV, `network_map.csv` or `known_scanners.csv` next to
`sites.csv` applies to every site. From the command line: `python3 -m vulnflow analyze-sites /path/to/folder`.

**What it reads.** Zeek logs (TSV or JSON, or a Zui/Brim export), Palo Alto TRAFFIC/THREAT,
Suricata EVE, AWS VPC Flow Logs (text, CloudWatch exports or local Parquet), generic flow CSVs
(nfdump, SIEM exports), Nessus `.nessus` or CSV,
and:

- **Packet captures** (`.pcap`/`.pcapng`, plain or `.gz`), run through Zeek into a temporary folder.
  A capture Zeek can't read is reported and the run continues.
- **Zeek logs shipped by Filebeat**, from a Kibana Discover CSV or NDJSON export. To get plain Zeek
  logs for another tool: `python3 -m vulnflow filebeat-to-zeek kibana_export.csv -o zeek_logs/`.
- **IOC CSV**: `type,indicator[,source_url]` (`ip`, `domain`, `url`, `hash`, `cve`, `package`), in
  the folder, uploaded, or passed with `--ioc-csv`. Exact matches are reported.
- **Network map** (optional): `network_map.csv` (`cidr,name,type`) marks cloud networks such as AWS
  VPCs.
- **Known scanners** (optional): `known_scanners.csv` (`address,name`) lists scanners you run
  yourself, so they are labelled "expected" instead of "review".

[Methods](METHODS.md#inputs-and-normalization) lists every format, how it is detected, and what each
source can and cannot contribute. Force a format with `--format file.csv=paloalto` if detection
guesses wrong.

**Large inputs.** DuckDB sizes its memory and threads to the machine and spills to disk beyond that;
plan for free disk of about the size of the uncompressed logs. `--workdir` (or `VULNSCOPE_WORKDIR`)
moves the temporary files. See [Large inputs](ARCHITECTURE.md#large-inputs-and-resource-sizing).

## Explore hosts

`explorer.html` is written with every run: a single offline file that opens in Chrome or Edge 80+,
Firefox 113+ or Safari 16.4+. The view switcher offers:

- **3D** (the default where WebGL works). Each subnet is a platform and each host a pillar whose
  height is its risk score. Risky paths and the most significant outside addresses, on an arc
  overhead, are drawn. Drag to rotate, right-drag or Shift-drag to pan, middle-drag to move the
  picture up or down, scroll to zoom.
- **Flat** (the 2 key; `explorer.html?2d` always opens flat).
- **Attack paths**, the most likely ways in drawn like a transit map (internet origin, entry, first
  and second pivot). **Simulate fix** shows how much path risk fixing or isolating one host would
  remove; nothing on the network changes.
- **Timeline** (the I key, or `explorer.html#timeline`), a tunnel through time where every flow is a
  chord at the moment it happened, with alerts as rings and IOC lookups as dots.

Click a host, or pick it from the host list (grouped by subnet, riskiest first), and the camera
flies to it. The left side shows outside addresses that exchanged traffic with it; the right side
shows internal peers with an estimated likelihood that a compromise could spread there. The panel
lists every recorded IP with session counts and connection tuples. **Focus** pivots to a peer; Esc
or **← All hosts** goes back. The **?** button explains the current view. Deep links work:
`explorer.html#host=10.0.1.10`.

Drawing limits keep large runs responsive; [Methods](METHODS.md#explorer-drawing-and-sampling)
explains what is drawn and how the likelihood is estimated.

## Ask the Security Assistant

Out of the box the Security Assistant is **Built-in (offline, no AI)**: it answers questions and
writes a brief from the run's own results with fixed rules and templates, and sends nothing
anywhere. Ask about a host, CVE, plugin, outside IP or IOC, or about priorities, callbacks, lateral
movement and coverage gaps; answers include ready-to-paste Zeek and Palo Alto filters.

To use a model instead, open **Security Assistant settings** and pick a provider:

| Provider | What it is | Key |
| --- | --- | --- |
| `offline` (default) | Built-in rules and templates, no AI model, nothing sent | none |
| `anthropic` | Claude via the Anthropic SDK (`pip install anthropic`) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI's API or an OpenAI-hosted gateway | `OPENAI_API_KEY` |
| `local` | Any OpenAI-compatible server you run (Ollama, vLLM, LM Studio, llama.cpp) | usually none |

With a hosted provider, correlated results (not raw logs) leave your network; **Redact IPs and
hostnames** replaces them with tokens and refuses to send if any survive. If the endpoint is
neither OpenAI's API nor this computer, the settings page warns that questions, run data and the
key will go to that server. The same features work from the terminal (`brief`, `ask`,
`analyze --llm`); see [Methods](METHODS.md#security-assistant) for flags and safeguards.

**Article briefs.** When IOC matches carry source article links and you have chosen OpenAI,
**Generate article briefs with OpenAI** on the results page summarizes each article. Nothing is
sent until you click it.

## Interpret and validate the report

Treat the report as a list of precise questions for system owners and responders:

> These hosts have these findings, and these sessions reached the vulnerable services in this
> window. Is that exposure intended? Did the host do anything afterwards that we can confirm on
> the host itself?

Every scored finding carries a priority (P1 act now to P4 routine) and a plain-English rationale
built from CVSS, exploit availability, observed exposure and blast radius. Indicators are graded
so the reports never overstate them:

- **Lead, not confirmed.** Worth investigating: a return connection to an outside address that
  reached the vulnerable service, new lateral connections or large uploads afterwards, or an
  unblocked IPS/IDS alert.
- **Likely exploitation.** An unblocked alert on the vulnerable service **and** follow-on behavior
  from the host. Reports ask for incident response and host forensics; they never state a
  compromise as confirmed.

**Worked example:** analyze the bundled Gootloader sample and open `hr-ws-07` (10.20.10.27) in the
Explorer. Follow its download, the beacon to an outside address and the SMB and RDP sessions to
the domain controllers in the Timeline. Give the host owner the finding, the session tuples and
times, and the suggested Zeek or Palo Alto filter. They can confirm on the host (EDR, memory, logs)
whether the activity happened and whether the service should be reachable.

Absence of traffic means "not observed by these sensors". Scanned hosts never seen on the wire,
and active servers never scanned, are listed as coverage gaps rather than scored as safe. An IOC
match is a lead for review, not proof of compromise.

**What counts as a host.** A host is an internal address that started a session or answered one.
Addresses that were probed but never answered are counted separately and listed in
`normalized/probed_addresses.csv`. A **Scanning hosts** section lists hosts that probed many
addresses or ports with mostly failed sessions; those not in your `known_scanners.csv`, and not the
Nessus scanner, are marked **Review**. Detection only labels hosts; it does not change scores.

**Check the sensor.** The reports warn when Zeek estimated 1% or more packet loss, or when fewer
than 2% of sessions show any answer (the sensor probably sees one direction only). Either way,
hosts and sessions may be missing; fix the capture before relying on counts.

## Save and share results

Each run writes to its output folder (`vulnflow_runs/<id>/out/` on the upload page):

- **Executive summary** and **technical report**, as Markdown and standalone HTML. Print or save
  them as PDF from your browser.
- **Explorer**: `explorer.html`, a single offline file. On busy networks each host keeps its top
  200 outside addresses and internal peers in the page; counts use the full lists, and the upload
  page loads a host's full lists when you click it. Very large reports may need Firefox or Safari;
  see [Configured limits](docs/LIMITS.md).
- **CSV and JSON:** `correlated_findings.csv` for ticketing; `results.json` for automation.
- **Normalized inputs** under `normalized/`: `flows.csv` and `flows.parquet`, `findings.csv`,
  `threats.csv` (IPS/IDS alerts), `zeek_events.jsonl`, `ot_events.jsonl`, `probed_addresses.csv`
  and `explorer_contacts.parquet`. The flow and Zeek event copies are about as large as the input;
  tick **Skip full copies of flows and Zeek events** (or `--no-normalized-copies`) to leave them out.
- **Hostile activity diagram** as `hostile_activity.svg`.
- **Security Assistant** brief and an audit log of every question and answer (`ai_chat_log.md`),
  when used.

The HTML files work offline and embed the branding, theme, matched IOC source links and article
overviews they were made with. Runs are kept until you delete them from the data folder.

**Reopen a saved report:** on the upload page, choose a completed report's output folder (the one
with `results.json` and `explorer.html`). The button changes to **Open report**; the reports and
Explorer are redrawn with the current version and branding, and nothing is reanalyzed or changed.
Keep `explorer.html` with `results.json`: it holds the traffic the Explorer is drawn from.

## Compare reports

**Compare reports** (linked from the upload page and every results page) shows which IOCs and
vulnerabilities appear in more than one saved report, and in how many networks.

1. Tick the reports to compare. The list holds every run saved by this upload page, newest first.
   To include a report saved somewhere else, open it on the upload page first (**Open report**).
2. Check each report's **Network**. Reports with the same network count as one network.
3. Leave **Look for every IOC matched in any chosen report in all of them** ticked, and optionally
   add an IOC CSV, to search each report's saved data again: an indicator learned after a report
   was made, or matched in only one report, is found in the others too.
4. Click **Compare**. The comparison has IOC, Vulnerability and Report tabs. Each row shows how
   many reports, networks and hosts it was seen in, with one square per report, oldest first:
   filled when the analysis found it, striped when only the new search did. Click a row for the
   hosts in each report.

**Open all networks in the Explorer** draws every compared report on one map, each network as its
own labelled cluster, with outside addresses merged onto the arc overhead. Hover a host to see what
it shares with other reports; its card links to that report's own Explorer.

Comparisons are saved in the data folder under `comparisons/<time>/` (`ioc_overlap.csv`,
`vulnerability_overlap.csv`, `comparison.json`, and the map). The reports themselves are not
changed. From the command line:

```sh
python3 -m vulnflow compare vulnflow_runs/ -o compare_out --ioc-csv new_iocs.csv
python3 -m vulnflow compare nov/out dec/out --network "dec/out=Plant 3"   # set a report's network
```

Vulnerabilities are matched by Nessus plugin and IOCs by indicator, never by internal address,
since the same private address in two networks is two different machines. See
[Comparing reports](METHODS.md#comparing-reports) for the rules.

## Branding and themes

**Branding** (linked from the upload page) replaces the name before "VulnScope" and adds a small
PNG, JPEG, GIF or WebP logo (up to 512 KB) at Small or Medium size, used by the upload page,
command line, reports and Explorer. Changing it needs a password. Set your own before first use:
run `python3 -m vulnflow branding-password`, then start the server with the
`VULNSCOPE_BRANDING_PASSWORD_HASH` it prints. Branding is saved per user in
`~/.vulnscope/branding.json` (or `$VULNSCOPE_HOME`; in Docker, inside the runs folder).

The pages share a theme picker: Graphite (the default), SOC Dark, Amphibious, Olive Drab, Matrix,
High Contrast and Light. The browser remembers the choice, and the Explorer follows it.
Comparisons and reopened reports open in Graphite.

## Privacy and practical limits

| Consideration | What to expect |
| --- | --- |
| Target contact | VulnScope never scans, probes or resolves hosts, IPs or domains found in your data. Zeek reads captures offline. |
| Outbound connections | Only four, each tied to a feature: IOC **article previews** (fetches matched source article pages, on by default when the IOC CSV has links), **Cloudflare Radar** (only with a token, only when you click), the **Security Assistant** with a hosted or network model, and **article briefs** (OpenAI, only when you click). |
| `VULNSCOPE_OFFLINE=1` | Turns off article previews only. It does not block Radar, a chosen AI provider or article briefs; leave those unconfigured on an air-gapped system. Docker defaults to `0`. |
| Upload page access | No login, and it can read any folder your account (or the container) can. It listens on `127.0.0.1` and refuses other host names. For remote use, see [Upload page security](ARCHITECTURE.md#upload-page-security). |
| API keys | Held in the server's memory only; never written to disk, logs or reports. Cleared when the server stops. |
| Memory and disk | DuckDB takes up to about 60% of RAM (or the container limit) and spills to disk. Roughly 1 GB of DuckDB memory per GB of Zeek logs for de-duplication; free disk of about the uncompressed log size. Docker Desktop's VM memory cap also applies. |
| Input size | 1 GB per upload by default; folders are read in place with no size cap. A `.gz` may expand to 200× its size (minimum 256 MB). |
| Concurrency | One analysis at a time per process unless `VULNSCOPE_MAX_JOBS` is raised. Within a run, files are parsed in parallel, one process per CPU (`VULNSCOPE_PARSE_WORKERS`). |
| Local retention | Run folders and reports stay on disk, readable by your account only, until you delete them. Temporary Parquet/DuckDB/Zeek files are deleted when the run ends. |
| Deployment | Intended for local use. A shared server needs `--allow-remote` behind your SSO proxy and its own security review. |

Review sensitive inputs before sharing an export. VulnScope does not encrypt reports.
[Configured limits](docs/LIMITS.md) lists every numeric bound.

## Further documentation

- [Troubleshooting](docs/TROUBLESHOOTING.md): port in use, proxies, updates that don't show, Docker
  on macOS.
- [Methods, inputs, and interpretation limits](METHODS.md): supported formats, correlation and
  scoring, Explorer estimates, outbound network use, and what VulnScope cannot establish.
- [Architecture](ARCHITECTURE.md): pipeline and module responsibilities, large-input design,
  Docker container, offline bundle, and upload page security.
- [Development and verification](DEVELOPMENT.md): tests, benchmarks, Docker builds and releases.
- [Local API](API.md): the upload page's HTTP routes.
- [Configured limits](docs/LIMITS.md): numeric bounds in one table.
- [Changelog](CHANGELOG.md) and [upgrading from vulnScope PRO](UPGRADE.md).

## License

MIT. See [LICENSE](LICENSE). The Múcaro browser tab icon retains its original MIT attribution in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
