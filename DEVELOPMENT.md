# Development and verification

Run from this directory with Python 3.10+ and DuckDB installed:

```sh
python3 -m pip install -r requirements.txt
python3 -m vulnflow serve
```

Verification uses synthetic data and never needs a model, an API key or network access. Run:

```sh
python3 -m unittest discover -s tests
```

`tests/test_pcap.py` runs Zeek when it is installed and skips those cases otherwise.

## Code checks

```sh
python3 -m pip install -r requirements-dev.txt         # ruff, mypy, coverage, hypothesis (pinned)
ruff check .                                           # lint
mypy                                                   # type check against Python 3.10
coverage run -m unittest discover -s tests && coverage combine && coverage report
FUZZ_PROFILE=long python3 -m unittest tests.test_fuzz_parsers     # longer fuzzing (about 10 minutes)
python3 scripts/perf/perf_check.py                     # performance check (about 1 minute)
```

Settings for ruff, mypy and coverage are in `pyproject.toml`.

- **Lint**: ruff's default rules (undefined names, unused imports and variables, syntax problems).
  Short lambdas assigned to names and `l` as a variable name are allowed on purpose.
- **Type check**: mypy with `python_version = 3.10`, so a call to something only newer Pythons have
  fails before it ships. It starts lenient: the error codes listed in `pyproject.toml` are off
  because un-annotated code trips them constantly. Switch them on one at a time as code gets types.
- **Coverage**: CI's Python 3.13 test run measures which lines and branches of `vulnflow/` the tests
  reach and shows the table on the run's summary page; the HTML report is kept as the
  `coverage-html` artifact. It reports only and fails nothing.
- **Fuzz tests**: `tests/test_fuzz_parsers.py` (Hypothesis) feeds every reader thousands of generated
  files: valid records with hostile values (NaN, huge numbers, wrong JSON types, control characters,
  impossible dates), random byte damage to real-looking sample files, truncated gzip, XML entity
  bombs, a whole damaged folder through `load()` and `correlate()`. A reader may stop on a broken file
  (UserError, bad XML/gzip/CSV/JSON) but nothing else, must finish within a time limit, and every
  record it yields must be well formed. CI runs the short, repeatable profile; `.github/workflows/fuzz.yml`
  runs the long profile with fresh random inputs every Monday and on demand. A failure prints the
  smallest breaking input and a `@reproduce_failure` line to replay it.
- **Correlation accuracy kit**: `tests/test_accuracy_kit.py` generates three hand-checked datasets
  (`tests/accuracy/correlation/make_round1.py`, `make_round2.py`: 34 cases across two Zeek taps,
  `.nessus` and Nessus CSV, Palo Alto, plus a telemetry-only folder), runs `vulnflow analyze` on each
  and compares every finding with `expected.json`. Cases with `label_truth` are known gaps (today: a
  host scanned by name only).
- **Performance check**: `scripts/perf/perf_check.py` analyzes the same synthetic dataset every time
  (40 MB of Zeek, Palo Alto and a Nessus CSV, seed 7) with fixed DuckDB memory, threads and parse
  workers, and compares time (scaled by a short CPU calibration run), peak memory, `explorer.html`
  and `results.json` size and the main counts with `scripts/perf/baseline.json`. It fails when time
  is over 1.6x, memory over 1.35x or a page over 1.25x the baseline, or when a count changes. After a
  deliberate change run it with `--update` and commit the new baseline with a note on why.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `main`:

- **Repository hygiene**: `scripts/check_repo.py` fails on local branding (`branding.json`, `.vulnscope/`),
  `.env` files, packet captures, executables and archives (by name and by their first bytes), private or
  API keys, files over 5 MB, and images outside `screenshots/`, `vulnflow/static/` and `example_output/`.
  Run it before committing, or install it as a pre-commit hook (the script's header shows how).
- **Lint and type check**: `ruff check .` and `mypy` (see [Code checks](#code-checks)).
- **Tests**: the suite above on Python 3.10 (the oldest supported) and 3.13 (the Docker image's),
  with the short fuzz run and the accuracy kit; the 3.13 run also reports coverage.
- **Performance check**: `scripts/perf/perf_check.py` against `scripts/perf/baseline.json`.
- **Explorer pages**: `scripts/smoke/explorer_smoke.py --samples WORK` analyzes the bundled samples, an
  edge case (IOCs with no article link) and the two-company comparison, opens each `explorer.html` in
  headless Chromium and walks 3D, a focused host, Flat, Attack paths and Timeline. It fails on any page
  error, when 3D draws fewer hosts than the data holds, or when the Timeline draws fewer flows than it
  has. Screenshots of every view are kept with the run. Locally: `pip install playwright` and
  `python -m playwright install chromium` first (about 3 minutes).
- **Docker image**: builds the image (linux/amd64), checks Zeek and DuckDB are inside, analyzes the
  Gootloader sample in the container and checks the upload page answers.
- **Accuracy on Brim sample data**: `scripts/accuracy/run.sh` downloads Brim's public captures and
  logs (9 PCAPs from brimcap and Zui, the WRCCDC 2018 Zeek logs as TSV and JSON, a Zui JSON export),
  runs the image on each, runs Suricata on one capture, and compares every count with ground truth
  that `scripts/accuracy/groundtruth.py` computes from the raw logs without any VulnScope code (the
  PCAPs get their reference logs from a separate Zeek). The files are pinned to exact upstream commits
  and checked against the SHA-256 hashes in `brim_manifest.txt`; they are downloaded on the CI machine
  only and never committed or put in the image. None of them contains malware: the captures are
  ordinary web browsing and the WRCCDC data is Zeek logs, which hold no file contents. Run it locally
  with `scripts/accuracy/run.sh /tmp/brim-data /tmp/brim-work` (needs Docker; about 10 minutes).

The Release workflow runs all of it again on a version tag before publishing an image (see
[Releasing](#releasing-a-ready-made-image)). It needs no secrets, API key or model. A PR shows a green check or a red cross for each job; the
failing step's log is one click away under **Details**.

| Test file | Covers |
| --- | --- |
| `test_fuzz_parsers.py` | Fuzzing every reader, format detection and the PCAP hand-off with hostile and damaged files |
| `test_accuracy_kit.py`, `test_correlation_accuracy.py` | Hand-checked correlation answers: the three-round kit and targeted regression cases |
| `test_workflow.py` | Parsing, normalization, correlation, scoring and reports end to end; the bundled samples; the Docker entry point |
| `test_scale.py`, `test_resources.py` | Streaming, Parquet/DuckDB de-duplication, memory/thread/disk sizing |
| `test_pcap.py`, `test_filebeat.py` | Packet capture conversion; Filebeat CSV/NDJSON back to Zeek |
| `test_capture_accuracy.py` | Mid-stream sessions, answered pings, broadcasts, capture loss, Zui/Brim exports, Suricata mid-stream flows |
| `test_explore.py`, `test_visual.py` | Explorer data, drawing limits, HTML output |
| `test_security.py`, `test_multipart.py` | Host/Origin/CSRF checks on every state-changing route (DNS rebinding), API-key endpoint rules and the unfamiliar-endpoint warning, Browse confinement, upload parsing, `.gz` limits |
| `test_scanners.py` | Hosts vs probed-only addresses, scanner detection, `known_scanners.csv`, probed ranges, firewall blocks, the one-way sensor warning |
| `test_llm.py`, `test_offline_assistant.py` | Provider adapters, redaction, grounding; the built-in assistant |
| `test_article_brief.py`, `test_radar.py` | Article briefs and Radar lookups with stubbed services |
| `test_branding.py` | Branding page, logo validation |
| `test_saved.py`, `test_report_name.py` | Reopening a saved report; report names, networks and timestamped run folders |
| `test_compare.py` | Compare reports: counts per report and network, the re-hunt over saved data, the all-networks Explorer (islands, shared items per host, fair trimming), command line and page, the two-company sample |
| `test_sites.py` | A folder with a `sites.csv`: reading and checking the list, files shared by every site, a report per site and their comparison from the command line and the upload page |
| `test_web_errors.py` | Which analysis errors the upload page shows, and which go to the server console |
| `test_release.py` | The ready-made image's `compose.release.yaml` matches `compose.yaml` apart from the image and project name; default port 8765 on the host; `.env.example` does not pin an image |

## Samples

`python3 -m vulnflow samples` rewrites the sample folders: scan-backed, telemetry-only, the 4,324-host
on-prem + AWS sample, Gootloader (`vulnflow/sample_gootloader.py`), the two-company Compare sample
(`vulnflow/sample_compare.py`) and the Artex AI and CyberStrike AI samples (`vulnflow/sample_artex.py`,
`vulnflow/sample_cyberstrike.py`, sharing the writers in `vulnflow/sample_kit.py`; their README files are
written by hand). The Compare sample has one folder per company and a `sites.csv`, so
`python3 -m vulnflow analyze-sites samples/compare_two_companies` (or **Analyze folder** on it) makes
six site reports and compares them; `python3 -m vulnflow compare-sample` analyzes its sites and the
Gootloader sample, seven in all, into an upload page's data folder and compares them. All sample data is fabricated. See
[samples/README.md](samples/README.md). Use `samples/` and `example_output/` for interface testing
only. Tests check that each generated sample matches its checked-in folder byte for byte.

## Benchmarks

`scripts/bench/` generates synthetic Zeek + Palo Alto log sets of a target size and measures time
and peak memory for the pipeline, uploads and folder runs. Run one benchmark at a time. See
[scripts/bench/README.md](scripts/bench/README.md) and the results in
[RESULTS_DUCKDB.md](scripts/bench/RESULTS_DUCKDB.md).

## Docker

```sh
docker compose build                                   # or: docker build -t vulnscope-max .
docker compose run --rm vulnscope analyze /opt/vulnscope/samples/gootloader_seo_poisoning -o /runs/demo
scripts/docker/offline-bundle.sh linux/arm64           # air-gapped bundle; see ARCHITECTURE.md
```

The image must use the same Python as the Zeek base (Debian trixie, Python 3.13), since DuckDB is
a compiled wheel. Both linux/amd64 and linux/arm64 builds are supported.

## Releasing a ready-made image

`.github/workflows/release.yml` publishes the image so analysts can `docker compose pull` instead of
building. It runs when a tag starting with `v` is pushed:

```sh
git checkout main && git pull --ff-only
git tag v1.2.0 && git push origin v1.2.0      # or GitHub: Releases > Draft a new release > new tag v1.2.0
```

1. **CI**: the whole `ci.yml` (hygiene, tests, Explorer, Docker image, accuracy) runs on the tagged
   commit. Nothing is published if any job fails.
2. **Image**: builds linux/amd64 and linux/arm64 (arm64 under QEMU) and pushes
   `ghcr.io/bayanilla/vulnscope-max:1.2.0`, `:1.2` and `:latest`. A pre-release tag such as
   `v1.2.0-rc1` gets only its own tag and never moves `latest`.
3. **Release**: pulls each architecture back from ghcr.io, checks it starts, saves it with
   `docker save` (about 190 MB each, gzipped) and attaches both files, `compose.yaml` (a copy of
   `compose.release.yaml`), `env.example`, `LOAD.txt` (from `scripts/docker/LOAD-release.txt`) and
   `SHA256SUMS` to the GitHub release, creating the release with generated notes if it does not exist.

It uses only the workflow's own `GITHUB_TOKEN`; no secrets to set up. **Actions > Release > Run
workflow** builds both architectures without pushing or releasing anything, as a dry run.

The first push creates the package on ghcr.io. If `docker compose pull` then asks for a login, the
package is private: open it from the repository's **Packages** list, **Package settings > Change
visibility > Public**. A private package works too, but every analyst then needs
`docker login ghcr.io` with a GitHub token that can read it.

`compose.release.yaml` must stay the same as `compose.yaml` apart from where the image comes from;
`tests/test_release.py` fails when one is changed without the other.

## Local data that must stay local

Never commit private inputs, credentials, unredacted exports or local branding; `scripts/check_repo.py`
enforces the mechanical part in CI. `.gitignore`
excludes `.env`, `vulnscope-out/`, `vulnflow_runs/`, `.vulnscope/` and `branding.json`; keep test
branding in `~/.vulnscope` (or `$VULNSCOPE_HOME`), not in the repository. Never print or log a
configured API key while debugging.
