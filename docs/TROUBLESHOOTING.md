# Troubleshooting

Fixes for problems starting, opening or updating VulnScope. VulnScope never changes your computer's
network or proxy settings, so most of these are checks on your own system.

- [The page does not start: port in use](#the-page-does-not-start-port-in-use)
- [The page does not load behind a proxy](#the-page-does-not-load-behind-a-proxy)
- [Problems after an update](#problems-after-an-update)
- [Python install problems](#python-install-problems)

## The page does not start: port in use

Docker uses port **8765** on your computer; the Python `serve` command uses **8080**. Another
program may already be listening there: often a local proxy (Burp Suite, OWASP ZAP and mitmproxy all
default to 8080), another web app, or another copy of VulnScope. You see:

- Docker: `Bind for 127.0.0.1:8765 failed: port is already allocated`, `ports are not available`
  (Docker Desktop), or on Linux `failed to bind host port ... address already in use`, and the
  container does not start.
- Python: `OSError: [Errno 48] Address already in use` (macOS), `[Errno 98]` (Linux) or
  `[WinError 10048]` (Windows).

Find out what is using the port (for Python, use 8080):

| System | Command |
|---|---|
| macOS | `lsof -nP -iTCP:8765 -sTCP:LISTEN` |
| Linux | `sudo ss -ltnp 'sport = :8765'` |
| Windows (PowerShell) | `Get-Process -Id (Get-NetTCPConnection -LocalPort 8765 -State Listen).OwningProcess` |
| Windows (Command Prompt) | `netstat -ano \| findstr :8765`, then `tasklist /FI "PID eq <pid>"` |
| Docker | `docker ps --filter publish=8765` (another container holding the port) |

Then either stop that program, or run VulnScope on another port:

- **Docker:** set `VULNSCOPE_PORT=8090` in `.env`, run `docker compose up -d`, and open
  **http://127.0.0.1:8090/**. Do not edit the `ports:` line in `compose.yaml`: the `8080` on its
  right is the port inside the container, and changing it stops the page from answering. The
  release `compose.yaml` runs as its own Compose project (`vulnscope-release`), so it and a copy
  built from source can run side by side on different ports.
- **Python:** `python3 -m vulnflow serve --port 8090`, then open **http://127.0.0.1:8090/**.
  `start_upload_page.py` moves to the next free port on its own and prints which one.

Theme, view and Explorer choices are remembered per address, so on a new port pick them again.

## The page does not load behind a proxy

If your browser or operating system sends web traffic through a proxy, it may also send
`http://127.0.0.1:8765/` there, and the proxy refuses or cannot reach it (an error page from the
proxy, a timeout, or "access denied"). Add `127.0.0.1` and `localhost` to the proxy bypass list:

- **Windows:** Settings > Network & internet > Proxy > Manual proxy setup, add
  `127.0.0.1;localhost` under "Use the proxy server except for addresses", and tick
  "Don't use the proxy server for local (intranet) addresses".
- **macOS:** System Settings > Network > (your connection) > Details > Proxies, add `127.0.0.1`
  and `localhost` to "Bypass proxy settings for these hosts & domains".
- **Firefox** has its own setting: Settings > Network Settings, "No proxy for".
- **PAC file or group policy:** if a managed PAC file sends everything to the proxy or the settings
  are locked, ask your IT or proxy team to exempt `127.0.0.1` and `localhost`.

Chrome and Edge already skip the proxy for `localhost` and `127.0.0.1` unless a policy or PAC file
says otherwise. A proxy on another machine (such as `proxy.corp.example:8080`) does not conflict
with VulnScope's port; only a program listening on this computer does. Always open the page as
`127.0.0.1` or `localhost`: other names for this computer are refused on purpose (see
[Upload page security](../ARCHITECTURE.md#upload-page-security)).

If you set `HTTP_PROXY` or `HTTPS_PROXY` in the environment VulnScope runs in, its own outbound
calls (IOC article previews, Cloudflare Radar, the AI provider) use that proxy too. Add
`NO_PROXY=localhost,127.0.0.1` there if you point the Security Assistant at a model on this
computer (for example `--llm-base-url http://localhost:11434/v1`).

## Problems after an update

To check the container, `docker compose ps` should show it as `Up` (not `Restarting`), and
`docker compose logs --tail 30` shows recent errors.

| Problem | What to do |
|---|---|
| The page looks unchanged | You restarted without `pull` (release image) or `--build` (from source), or you are looking at an old run. Update, reload the page, and analyze again: each run keeps the version it was made with. |
| `git pull` refuses: "Your local changes would be overwritten" | Files in your clone were edited. `git status` lists them. Keep a copy with `git stash` (restore it later with `git stash pop`), or discard them with `git checkout -- <file>`, then pull again. `.env` is not tracked, so your settings are safe. |
| macOS: `docker: command not found` or `docker-credential-desktop` not found | Docker Desktop's tools are not on your PATH. Run `export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"`, or add that line to `~/.zshrc`. |
| `docker compose pull`: "denied" or "unauthorized" | The image name in `VULNSCOPE_IMAGE` is wrong, or a registry login is getting in the way (`docker logout ghcr.io`). Check the [package page](https://github.com/bayanilla/vulnScope/pkgs/container/vulnscope), or build from source. |
| A pinned version does not change | If `.env` pins `VULNSCOPE_IMAGE=ghcr.io/bayanilla/vulnscope:<version>`, change the number first. |
| Explorer, theme or view choices look different | The browser remembers them per address (`127.0.0.1:8765` and `127.0.0.1:8080` are separate). Pick them again, or clear the site's data. |
| Air-gapped installation | `docker load` the newer image file from the release, then `docker compose up -d`. For a bundle built from source, see [Air-gapped networks](../ARCHITECTURE.md#air-gapped-networks-and-enclaves). |

## Python install problems

| Problem | What to do |
|---|---|
| `ModuleNotFoundError: No module named 'duckdb'` | DuckDB is installed in a different Python than the one running VulnScope. Activate your virtual environment, then `python3 -m pip install -r requirements.txt` with the same `python3`. |
| "Packet captures need Zeek to be analyzed" | Zeek is not installed or not on the PATH. Install it (`brew install zeek` or your Linux package) or set `VULNSCOPE_ZEEK=/path/to/zeek`, or use the Docker image, which includes Zeek. |
