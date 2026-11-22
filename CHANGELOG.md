# Changelog

Notable changes for analysts and operators. Each release's image is published as
`ghcr.io/bayanilla/vulnscope-max:<version>`. Reports keep the version they were made with; analyze
again to get a release's changes. Upgrading from vulnScope PRO: see [UPGRADE.md](UPGRADE.md).

## Unreleased

- **ULTRA engine changes** (reports unchanged, checked against MAX on every sample): Zeek conn logs
  and Palo Alto exports are parsed by DuckDB; IOC matching, `flows.csv` and alert matching run as
  SQL; the correlation queries live in `vulnflow/model.sql`; results.json has a published format
  (`docs/results.schema.json`) that saved reports are checked against; DuckDB 1.3.0 and anything
  older than 1.2 are refused, and DuckDB no longer downloads extensions on demand. See
  [docs/ULTRA.md](docs/ULTRA.md).
- **AWS VPC Flow Logs** have their own reader. It also reads records with no header line,
  CloudWatch exports and local Parquet files. It joins each session's request and reply, which AWS
  logs separately, so replies no longer show up as sessions to the client's port and received bytes
  are counted.
- **Several sites in one folder.** A `sites.csv` next to per-company folders makes one report per
  site and opens their comparison (`vulnflow analyze-sites`).
- **All-networks map:** each company is drawn as its own labelled cluster; hovering a host shows
  what it shares with other reports; faint moving dots show which way each internet beam's traffic
  went.
- **Explorer:** report data is unpacked with the browser's built-in gzip decoder (Chrome or Edge
  80+, Firefox 113+, Safari 16.4+); reports up to 1 GB unpacked open, with a clear note beyond that.
- **3D and Timeline:** middle-drag moves the picture up or down.
- **Samples:** the two-company Compare sample is grouped by company and shares ARTEX activity
  between the two.

## 0.1.2 (2026-11-15)

- **Explorer on large inputs:** busy hosts keep their top 200 outside addresses and internal peers
  in the page, with exact totals; the upload page loads a host's full lists when you click it.
  Explorer files are much smaller.
- Every input reader is fuzz tested; several crashes and bad records on malformed input are fixed.

## 0.1.1 (2026-11-15)

- **Docker uses port 8765** on your computer by default (8080 is often taken by local proxies such
  as Burp Suite or OWASP ZAP). The release `compose.yaml` runs as its own Compose project, so it can
  run beside a copy built from source.
- New [Troubleshooting](docs/TROUBLESHOOTING.md) guide for a busy port and proxies.

## 0.1.0 (2026-11-15)

First release of the ready-made image for linux/amd64 and linux/arm64, with offline image files for
air-gapped networks. Compared with vulnScope PRO, see [UPGRADE.md](UPGRADE.md#what-changed).
