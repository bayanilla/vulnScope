"""Pure-Python SVG diagrams for the HTML reports (no Graphviz, works offline).

- hostile_activity_svg: outside sources, the vulnerable services they hit, and what the host did next.
  Ported from the vulnPath diagram and fed from vulnflow's correlation result.
- blast_svg: one host's internal neighbourhood, coloured by the worst finding on each neighbour.

Colours come from CSS classes and variables so the diagrams follow the report theme; the fallbacks in
DIAGRAM_CSS keep a saved .svg readable on its own.
"""
from __future__ import annotations

import math
from html import escape

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0, "": 0, None: -1}
NODE_W, NODE_H, COL_GAP, ROW_GAP, MARGIN = 230, 70, 380, 30, 30
MAX_NODES = 40

# style -> (dash, width, rank, legend). The strongest style wins when one edge carries several behaviours.
STYLES = {
    "return": ("", 2.6, 7, "Host connected back to the source after contact (lead)"),
    "ips": ("", 2.6, 6, "IPS/IDS alert NOT blocked (alert only)"),
    "spread": ("", 2.2, 5, "Flagged host newly reached this vulnerable service"),
    "onward": ("", 1.8, 4, "New lateral connection after contact (candidate path)"),
    "ips-blocked": ("4 3", 1.6, 3, "IPS/IDS alert blocked or reset"),
    "internet": ("6 4", 1.4, 2, "Internet sessions to the vulnerable service"),
}

DIAGRAM_CSS = """
.dg-bg{fill:var(--panel,#111c31)}.dg-ink{fill:var(--fg,#f1f5f9)}.dg-ink2{fill:var(--muted,#cbd5e1)}
.dg-box{fill:var(--bg,#0f172a)}.dg-box.src{fill:var(--head,#1e293b)}
.dg-halo{paint-order:stroke;stroke:var(--panel,#111c31);stroke-width:4px;stroke-linejoin:round}
.sev-Critical{stroke:var(--sev-critical,#f87171)}.sev-High{stroke:var(--sev-high,#fb923c)}
.sev-Medium{stroke:var(--sev-medium,#facc15)}.sev-Low{stroke:var(--sev-low,#60a5fa)}
.sev-none,.sev-Info{stroke:var(--sev-none,#94a3b8)}
.tx-Critical{fill:var(--sev-critical,#f87171)}.tx-High{fill:var(--sev-high,#fb923c)}
.tx-Medium{fill:var(--sev-medium,#facc15)}.tx-Low{fill:var(--sev-low,#60a5fa)}.tx-none,.tx-Info{fill:var(--sev-none,#94a3b8)}
.e-return{stroke:var(--e-return,#c084fc);fill:var(--e-return,#c084fc)}
.e-ips,.e-ips-blocked{stroke:var(--e-ips,#ef4444);fill:var(--e-ips,#ef4444)}
.e-spread{stroke:var(--e-spread,#fb923c);fill:var(--e-spread,#fb923c)}
.e-onward{stroke:var(--fg,#f1f5f9);fill:var(--fg,#f1f5f9)}
.e-internet{stroke:var(--e-internet,#94a3b8);fill:var(--e-internet,#94a3b8)}
.lb-return{fill:var(--e-return,#c084fc)}.lb-ips,.lb-ips-blocked{fill:var(--e-ips,#ef4444)}
.lb-spread{fill:var(--e-spread,#fb923c)}.lb-onward{fill:var(--fg,#f1f5f9)}.lb-internet{fill:var(--e-internet,#94a3b8)}
path.e-return,path.e-ips,path.e-ips-blocked,path.e-spread,path.e-onward,path.e-internet,line.edge-line{fill:none}
.tag-likely{fill:var(--sev-critical,#f87171)}.tag-lead{fill:var(--sev-medium,#facc15)}.tag-tx{fill:var(--bg,#0f172a)}
.dg-dim{opacity:.18}.dg-focus rect,.dg-focus circle{stroke-width:4px}
.node,.bnode{cursor:pointer}
"""


def _sev_of(res: dict) -> dict:
    """Worst finding per host: (severity name, short vulnerability label, hostname, evidence level)."""
    out = {}
    for r in res["findings"]:
        cur = out.get(r["host"])
        ev = ("likely" if any(i["confidence"] == "corroborated" for i in r["indicators"])
              else "lead" if r["indicators"] else "")
        label = ((r["cves"] or [r["plugin_name"]])[0])[:34]
        if cur is None or SEV_RANK.get(r["severity_name"], 0) > SEV_RANK.get(cur[0], 0):
            out[r["host"]] = [r["severity_name"], label, r["hostname"], cur[3] if cur else ""]
        if ev == "likely" or (ev == "lead" and out[r["host"]][3] != "likely"):
            out[r["host"]][3] = ev
    return out


def _role(roles: set | None) -> str:
    if not roles:
        return "not in scan"
    if "exploit attempts" in roles:
        roles = roles - {"contacted the service"}
    return "source: " + ", ".join(sorted(roles))


def hostile_graph(res: dict):
    """Nodes and edges for the hostile activity diagram, derived from the correlation result."""
    hosts = _sev_of(res)
    edges: dict[tuple, dict] = {}
    order: dict[str, None] = {}
    roles: dict[str, set] = {}
    internet_sources = 0

    def put(src, dst, style, label, finding=None):
        key = (src, dst, style if style == "return" else "fwd")
        cur = edges.get(key)
        if cur is None or STYLES[style][2] > STYLES[cur["style"]][2]:
            edges[key] = {"src": src, "dst": dst, "style": style, "label": label, "findings": set()}
        if finding:
            edges[key]["findings"].add(finding)
        order.setdefault(src)
        order.setdefault(dst)

    for r in res["findings"]:
        e, h, fid = r["exposure"], r["host"], f"{r['host']}|{r['plugin_id']}|{r['port']}"
        svc = f"{r['proto']}/{r['port']}" if r["port"] else "host"
        exfil = {i["peer"]: i.get("bytes", 0) for i in r["indicators"] if i["type"] == "exfil" and i.get("peer")}
        for i in r["indicators"]:
            t = i["type"]
            if t == "threat_alert":
                for ip, n in i.get("sources", []):
                    put(ip, h, "ips", f"{svc} · IPS NOT blocked ×{n}", fid)
                    roles.setdefault(ip, set()).add("exploit attempts")
            elif t == "return_connection" and i.get("peer"):
                ports = ", ".join(str(p) for p in i.get("ports", []))
                lab = f"connected back on {ports}" if ports else "connected back"
                if i["peer"] in exfil:
                    lab += f" · {exfil[i['peer']] / 1048576:.0f} MB out"
                put(h, i["peer"], "return", lab, fid)
                roles.setdefault(i["peer"], set()).add("contacted the service")
            elif t == "new_lateral":
                for tg in i.get("targets", []):
                    put(h, tg["ip"], "onward", " ".join(f"tcp/{p}" for p in tg["ports"][:3]) + " onward", fid)
            elif t == "lateral_spread" and i.get("peer"):
                put(i["peer"], h, "spread", f"{i.get('proto', 'tcp')}/{i.get('port', r['port'])} · newly reached", fid)
        for ip, n in e.get("threat_blocked_sources", []):
            put(ip, h, "ips-blocked", f"{svc} · IPS blocked ×{n}", fid)
            roles.setdefault(ip, set()).add("blocked attempts")
        if (e["scope"] == "port" and e["external_sources"] and r["priority"] in ("P1", "P2")):
            internet_sources = max(internet_sources, e["external_sources"])
            put("internet", h, "internet", f"{svc} · {e['established']} sessions", fid)

    keep = sorted(order, key=lambda n: n == "internet")[:MAX_NODES]   # the aggregate node goes last
    kept = set(keep)
    edges = {k: v for k, v in edges.items() if v["src"] in kept and v["dst"] in kept}
    nodes = {}
    for n in keep:
        if n == "internet":
            nodes[n] = {"id": n, "title": "Internet", "sub": f"{internet_sources} outside sources",
                        "sev": None, "vuln": "", "ev": "", "src": True}
        elif n in hosts:
            sev, vuln, hn, ev = hosts[n]
            nodes[n] = {"id": n, "title": n, "sub": hn or "", "sev": sev, "vuln": vuln, "ev": ev, "src": False}
        else:
            nodes[n] = {"id": n, "title": n + " (external)" if n in roles else n,
                        "sub": _role(roles.get(n)),
                        "sev": None, "vuln": "", "ev": "", "src": n in roles}
    return nodes, list(edges.values())


def _layout(nodes: dict, edges: list):
    fwd = [e for e in edges if e["style"] != "return"]
    inbound = {e["dst"] for e in fwd}
    depth = {n: 0 for n in nodes if n not in inbound}
    for _ in range(len(nodes) + 1):
        changed = False
        for e in fwd:
            s, d = e["src"], e["dst"]
            if s in depth and depth[s] + 1 > depth.get(d, -1) and depth[s] + 1 <= 6:
                depth[d] = depth[s] + 1
                changed = True
        if not changed:
            break
    for n in nodes:
        depth.setdefault(n, 1)
    cols: dict[int, list[str]] = {}
    for n in nodes:
        cols.setdefault(depth[n], []).append(n)
    pos = {}
    for c, col in cols.items():
        for r, n in enumerate(col):
            pos[n] = (MARGIN + c * COL_GAP, MARGIN + 40 + r * (NODE_H + ROW_GAP))
    return pos, cols


def _marker(style: str) -> str:
    return (f'<marker id="dg-arr-{style}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="lb-{style}"/></marker>')


def hostile_activity_svg(res: dict, standalone: bool = False) -> str:
    nodes, edges = hostile_graph(res)
    pos, cols = _layout(nodes, edges)
    width = max(MARGIN * 2 + (max(cols) + 1) * COL_GAP - (COL_GAP - NODE_W) if cols else 400, 760)
    height = max((y for _, y in pos.values()), default=0) + NODE_H + MARGIN + 170
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" class="dg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" role="img" aria-label="Hostile activity against vulnerable services" '
           f'font-family="system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif" font-size="12">']
    if standalone:
        out.append(f"<style>{DIAGRAM_CSS}</style>")
    out.append("<defs>" + "".join(_marker(s) for s in STYLES) + "</defs>")
    out.append(f'<rect class="dg-bg" width="{width}" height="{height}" rx="8"/>')
    out.append(f'<text x="{MARGIN}" y="{MARGIN + 6}" font-size="15" font-weight="600" class="dg-ink">'
               'Hostile activity against vulnerable services</text>')
    if not nodes:
        out.append(f'<text x="{MARGIN}" y="{MARGIN + 40}" class="dg-ink2">'
                   'No alerts, return connections or internet exposure reached a scanned host.</text>')

    for e in sorted(edges, key=lambda e: STYLES[e["style"]][2]):
        (sx, sy), (dx_, dy) = pos[e["src"]], pos[e["dst"]]
        dash, w, _, _ = STYLES[e["style"]]
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        if dx_ > sx:                                   # left to right
            x1, y1, x2, y2 = sx + NODE_W, sy + NODE_H / 2, dx_, dy + NODE_H / 2
            c = max(60, (x2 - x1) / 2)
            d = f"M{x1},{y1} C{x1 + c},{y1} {x2 - c},{y2} {x2},{y2}"
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 6
        else:                                          # back towards the left (return connection)
            x1, y1, x2, y2 = sx, sy + NODE_H * 0.78, dx_ + NODE_W, dy + NODE_H * 0.78
            drop = 34 + abs(y1 - y2) * 0.15
            d = f"M{x1},{y1} C{x1 - 70},{y1 + drop} {x2 + 70},{y2 + drop} {x2},{y2}"
            mx, my = x2 + 70, dy + NODE_H + 16         # in the gap under the source box
        fids = " ".join(sorted(e["findings"]))
        out.append(f'<g class="edge" data-src="{escape(e["src"])}" data-dst="{escape(e["dst"])}" '
                   f'data-findings="{escape(fids)}">')
        out.append(f'<path d="{d}" class="e-{e["style"]}" stroke-width="{w}"{dash_attr} '
                   f'marker-end="url(#dg-arr-{e["style"]})"/>')
        out.append(f'<text x="{mx:.0f}" y="{my:.0f}" text-anchor="middle" font-size="11" '
                   f'class="dg-halo lb-{e["style"]}">{escape(e["label"])}</text>')
        out.append('</g>')

    for n, nd in nodes.items():
        x, y = pos[n]
        sev = nd["sev"] or "none"
        out.append(f'<g class="node" data-host="{escape(n)}" data-sev="{sev}" tabindex="0">'
                   f'<title>{escape(n)}: click to focus</title>')
        out.append(f'<rect class="dg-box{" src" if nd["src"] else ""} sev-{sev}" x="{x}" y="{y}" width="{NODE_W}" '
                   f'height="{NODE_H}" rx="8" stroke-width="2"/>')
        out.append(f'<text x="{x + 10}" y="{y + 20}" font-weight="600" class="dg-ink">{escape(nd["title"][:32])}</text>')
        out.append(f'<text x="{x + 10}" y="{y + 37}" class="dg-ink2">{escape(nd["sub"][:36])}</text>')
        if nd["sev"]:
            out.append(f'<text x="{x + 10}" y="{y + 55}" class="tx-{sev}">{escape(sev)}: {escape(nd["vuln"])}</text>')
        if nd["ev"]:
            tag = "LIKELY" if nd["ev"] == "likely" else "LEAD"
            out.append(f'<rect x="{x + NODE_W - 62}" y="{y - 9}" width="58" height="18" rx="9" class="tag-{nd["ev"]}"/>'
                       f'<text x="{x + NODE_W - 33}" y="{y + 4}" text-anchor="middle" font-size="10" '
                       f'font-weight="700" class="tag-tx">{tag}</text>')
        out.append('</g>')

    ly = height - 140
    out.append(f'<text x="{MARGIN}" y="{ly}" font-weight="600" class="dg-ink">Legend</text>')
    for i, (st, (dash, w, _, label)) in enumerate(STYLES.items()):
        yy = ly + 18 + i * 18
        d = f' stroke-dasharray="{dash}"' if dash else ""
        out.append(f'<line x1="{MARGIN}" y1="{yy - 4}" x2="{MARGIN + 40}" y2="{yy - 4}" class="edge-line e-{st}" '
                   f'stroke-width="{w}"{d}/><text x="{MARGIN + 50}" y="{yy}" class="dg-ink2">{escape(label)}</text>')
    lx = MARGIN + 420
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"]):
        out.append(f'<rect x="{lx}" y="{ly + 6 + i * 18}" width="14" height="12" fill="none" stroke-width="2" '
                   f'class="sev-{sev}"/><text x="{lx + 22}" y="{ly + 16 + i * 18}" class="dg-ink2">'
                   f'{sev} vulnerability on target</text>')
    for i, (ev, tag, label) in enumerate([("likely", "LIKELY", "Alert and host behaviour agree (likely exploitation)"),
                                          ("lead", "LEAD", "Pattern worth investigating, not confirmed")]):
        yy = ly + 80 + i * 20
        out.append(f'<rect x="{lx}" y="{yy}" width="44" height="15" rx="7.5" class="tag-{ev}"/>'
                   f'<text x="{lx + 22}" y="{yy + 11}" text-anchor="middle" font-size="9" font-weight="700" '
                   f'class="tag-tx">{tag}</text><text x="{lx + 52}" y="{yy + 11}" class="dg-ink2">{label}</text>')
    out.append(f'<text x="{MARGIN}" y="{height - 10}" font-size="11" class="dg-ink2">'
               'Detected behaviour and candidate paths are leads, not confirmed compromise.</text>')
    out.append("</svg>")
    return "\n".join(out)


def blast_svg(host: dict, res: dict, spread_targets: set[str]) -> str:
    """One host and its internal neighbours: direct peers on the inner ring, 2-hop peers outside."""
    names = {h["host"]: h["hostname"] for h in res["hosts"]}
    bl = host["blast"]
    hop1 = [r for r in bl["reachable"] if r["hop"] == 1][:10]
    hop2 = [r for r in bl["reachable"] if r["hop"] == 2][:10]
    W, H = 660, 380
    cx, cy = W / 2, H / 2 + 6
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" class="dg blast" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           f'role="img" aria-label="Blast radius of {escape(host["host"])}" '
           'font-family="system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif" font-size="11">',
           "<defs>" + _marker("spread") + _marker("onward") + "</defs>",
           f'<rect class="dg-bg" width="{W}" height="{H}" rx="8"/>']
    pts = []
    for ring, (rx, ry), group in ((1, (175, 105), hop1), (2, (290, 160), hop2)):
        for k, r in enumerate(group):
            a = -math.pi / 2 + (2 * math.pi * k / max(1, len(group))) + (0.3 if ring == 2 else 0)
            pts.append((r, ring, cx + rx * math.cos(a), cy + ry * math.sin(a)))
    for r, ring, x, y in pts:
        if ring != 1:
            continue
        spread = r["ip"] in spread_targets
        cls = "e-spread" if spread else "e-onward"
        # stop the line at the neighbour's circle edge so the arrowhead shows
        dx, dy = x - cx, y - cy
        L = math.hypot(dx, dy) or 1
        x2, y2 = x - dx / L * 17, y - dy / L * 17
        x1, y1 = cx + dx / L * 24, cy + dy / L * 24
        out.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" class="edge-line {cls}" '
                   f'stroke-width="{2.4 if spread else 1}" opacity="{1 if spread else .55}"'
                   + (f' marker-end="url(#dg-arr-spread)"' if spread else "") + "/>")
        ports = ", ".join(str(p) for p in r["ports"][:3])
        if ports:
            out.append(f'<text x="{(x1 + x2) / 2:.0f}" y="{(y1 + y2) / 2 - 3:.0f}" text-anchor="middle" font-size="10" '
                       f'class="dg-halo dg-ink2">{escape(ports)}</text>')
    for r, ring, x, y in pts:
        sev = r["max_severity"] or "none"
        rad = 13 if ring == 1 else 9
        label = names.get(r["ip"]) or r["ip"]
        label = label.split(".")[0] if names.get(r["ip"]) else label
        out.append(f'<g class="bnode" data-host="{escape(r["ip"])}"><title>{escape(r["ip"])} '
                   f'{escape(names.get(r["ip"], ""))} - {r["hop"]} hop(s), worst finding {escape(r["max_severity"] or "none")}</title>'
                   f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{rad}" class="dg-box sev-{sev}" stroke-width="{2.5 if ring == 1 else 1.5}"'
                   + (' stroke-dasharray="3 2"' if ring == 2 else "") + "/>"
                   f'<text x="{x:.0f}" y="{y + rad + 13:.0f}" text-anchor="middle" class="{"dg-ink" if ring == 1 else "dg-ink2"}">'
                   f'{escape(label[:18])}</text></g>')
    sev = next((s for s in ("Critical", "High", "Medium", "Low") if host["by_severity"].get(s)), "none")
    out.append(f'<circle cx="{cx}" cy="{cy}" r="24" class="dg-box src sev-{sev}" stroke-width="3.5"/>'
               f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" font-weight="700" class="dg-ink">'
               f'{escape((host["hostname"] or host["host"]).split(".")[0][:10])}</text>')
    more = bl["reachable_count"] - len(pts)
    out.append(f'<text x="14" y="22" class="dg-ink2">Inner ring: direct peers ({bl["direct_count"]}). '
               f'Outer ring: 2 hops away.{f" {more} more not shown." if more > 0 else ""}</text>')
    if spread_targets:
        out.append(f'<text x="14" y="{H - 12}" class="dg-ink2"><tspan class="tx-High">Orange arrows</tspan>: '
                   'new connections that started after the flagged contact.</text>')
    out.append("</svg>")
    return "\n".join(out)
