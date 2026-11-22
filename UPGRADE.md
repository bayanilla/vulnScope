# Moving to vulnScope from PRO, MAX or ULTRA

VulnScope now lives in one repository, [bayanilla/vulnScope](https://github.com/bayanilla/vulnScope).
It replaces vulnScope PRO, VulnScope MAX and VulnScope ULTRA. It has every MAX feature with ULTRA's
faster engine, and gives the same reports. The `vulnflow` command line, the Python upload page on
port 8080 and the report formats stay the same; the Docker image uses port 8765. Incident cases are
a separate tool: [vulnscope_incident](https://github.com/bayanilla/vulnscope_incident).

## Coming from MAX or ULTRA

- Clone this repository into a new folder, or point an existing checkout at it:
  `git remote set-url origin https://github.com/bayanilla/vulnScope.git`.
- The ready-made image is now `ghcr.io/bayanilla/vulnscope` (was `ghcr.io/bayanilla/vulnscope-max`).
  If your `.env` sets `VULNSCOPE_IMAGE`, change the name there. The image built from source is
  `vulnscope:latest`.
- The Branding page has no password any more, and the default name is just "VulnScope". A saved
  `branding.json` keeps working.
- Run folders, settings and branding stay on disk and are read as before.

## Coming from PRO

What changed since PRO:

- Streaming parsers, Parquet and DuckDB, so multi-GB Zeek and Palo Alto sets fit in bounded memory.
  DuckDB is now a required dependency.
- Docker image with Zeek for Linux, macOS and Windows, plus an offline bundle for enclaves.
- Packet capture input, Filebeat/Kibana exports of Zeek logs, and an optional network map.
- Explorer: 3D overview, Attack paths, Timeline, and a host list grouped by subnet.
- Built-in offline Security Assistant as the default; a Branding page for your name and logo.
- Host counts include only internal addresses that sent or answered traffic. Addresses that were
  only probed are a separate count, so host counts can be much lower than before on scanned networks.
  Scanning hosts are detected and listed, and the reports warn about packet loss and one-way
  sensors.
- Zui/Brim exports are read, and every pull request is tested in CI, including an accuracy check
  on Brim's public sample captures.

VulnScope remains a proof of concept. It reads existing files; it does not scan targets or make
enforcement decisions.

Keep your PRO checkout as it is and clone vulnScope into its own folder:

```sh
git clone https://github.com/bayanilla/vulnScope.git
cd vulnScope
python3 -m pip install -r requirements.txt
python3 -m vulnflow serve --port 8081      # pick another port if PRO is running on 8080
```

Or use Docker; see [Quickstart](README.md#quickstart).

## Update an existing installation

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
