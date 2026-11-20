# Upgrading from vulnScope PRO

VulnScope MAX is the scaled edition of vulnScope PRO. The `vulnflow` command line, the Python
upload page on port 8080 and the report formats remain the same; the Docker image uses port 8765.

## What changed

- Streaming parsers, Parquet and DuckDB, so multi-GB Zeek and Palo Alto sets fit in bounded memory.
  DuckDB is now a required dependency.
- Docker image with Zeek for Linux, macOS and Windows, plus an offline bundle for enclaves.
- Packet capture input, Filebeat/Kibana exports of Zeek logs, and an optional network map.
- Explorer: 3D overview, Attack paths, Timeline, and a host list grouped by subnet.
- Built-in offline Security Assistant as the default; Branding page with password lock.
- Host counts include only internal addresses that sent or answered traffic. Addresses that were
  only probed are a separate count, so host counts can be much lower than before on scanned networks.
  Scanning hosts are detected and listed, and the reports warn about packet loss and one-way
  sensors.
- Zui/Brim exports are read, and every pull request is tested in CI, including an accuracy check
  on Brim's public sample captures.

VulnScope remains a proof of concept. It reads existing files; it does not scan targets or make
enforcement decisions.

## Install alongside PRO

Keep your PRO checkout as it is. Clone MAX into its own folder:

```sh
git clone https://github.com/bayanilla/vulnscope_max.git
cd vulnscope_max
python3 -m pip install -r requirements.txt
python3 -m vulnflow serve --port 8081      # pick another port if PRO is running on 8080
```

Or use Docker; see [Quickstart](README.md#quickstart).

## Update an existing MAX installation

Stop the server. In an unchanged checkout on the main branch:

```sh
git pull --ff-only origin main
python3 -m pip install -r requirements.txt
```

With Docker: `git pull --ff-only origin main && docker compose up -d --build`, then analyze again.
A plain restart keeps the old version. Fixes for common problems are in
[Troubleshooting](docs/TROUBLESHOOTING.md#problems-after-an-update); what each release changed is in
the [Changelog](CHANGELOG.md).

Restarting clears API keys held in server memory. Run folders, settings and branding stay on disk.
Reports made by an earlier version stay as they were; analyze the inputs again to get new features.

## Reports made before 0.1.0

- They did not save their IPS/IDS alerts, so in [Compare reports](docs/COMPARE.md) an IP
  seen only in an alert is not found again in them; the comparison says so.
- Comparisons made before 0.1.0 open in the SOC Dark theme. Compare again to update them.

Analyze the inputs again to bring an old report up to date.
