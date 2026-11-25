// Investigate view: an investigation graph that grows outward from one lead. Every entity (host, outside
// address, service, finding, CVE, IPS alert, IOC domain, source article, subnet) is a typed icon, every
// arrow says what it means, and clicking an entity lists the pivots it offers (who reached this host, the
// hosts with this CVE, where an alert came from...). Pivots only read the Explorer data already in the
// page: nothing is looked up on the internet. Drawn on a plain 2D canvas; a case stays small (tens to a few
// hundred entities), so no graph library is needed.
vfWhenReady(function (D) {   // starts once vf_data.js has unpacked the data
'use strict';
const root = document.getElementById('investigate-view'), openBtn = document.getElementById('btn-investigate');
if (!root || !openBtn) return;
const FOCUS = D.focus || {};
if (!Object.keys(FOCUS).length) { openBtn.hidden = true; return; }
openBtn.hidden = false;
// the switchers inside Attack paths and Timeline offer this view too
document.querySelectorAll('#attack-paths [data-view="investigate"], #timeline-view [data-view="investigate"]').forEach(b => { b.hidden = false; });
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
// all-networks map: ids carry "@<island>" so equal addresses in two reports stay apart; labels drop it
const shown = id => String(id ?? '').replace(/@\d+$/, '');
const html = document.documentElement, CALM = html.hasAttribute('data-calm'), LIGHT = html.dataset.theme === 'light';

// ---------------------------------------------------------------- colours (same families as the network view)
const PAL = LIGHT ? {crit: '#da3737', high: '#f0782f', med: '#e0a100', low: '#3d85f0', none: '#8e9196', violet: '#5b7ba8', ioc: '#bc1e70',
  host: '#7a7d82', ip: '#8e9196', svc: '#5f7f8f', cve: '#6d5fb0', alert: '#c62828', article: '#3d6aa8', subnet: '#6c7076',
  line: '#a6a8ab', label: '#1b1c1e', sub: '#5c5e62', halo: 'rgba(255,255,255,.92)', bg: '#ffffff', grid: 'rgba(0,0,0,.05)'}
  : CALM ? {crit: '#e5534b', high: '#d98845', med: '#c9a544', low: '#7c9fd4', none: '#6f7276', violet: '#9088b0', ioc: '#c4627c',
  host: '#5d6168', ip: '#6c7076', svc: '#4f6a78', cve: '#7a6fa0', alert: '#b8443e', article: '#4d6a95', subnet: '#45505a',
  line: '#6c7076', label: '#ececea', sub: '#9a9b97', halo: 'rgba(17,18,20,.92)', bg: '', grid: 'rgba(255,255,255,.025)'}
  : {crit: '#ff3b5c', high: '#ff8a3d', med: '#ffd23f', low: '#4dabf7', none: '#8da2b5', violet: '#b98cff', ioc: '#ff2e88',
  host: '#3a5578', ip: '#4a5d7a', svc: '#2f6f80', cve: '#7b5cc9', alert: '#d9334f', article: '#3567b5', subnet: '#34465f',
  line: '#5d7aa3', label: '#e6f1ff', sub: '#8ea3bd', halo: 'rgba(3,6,12,.9)', bg: '', grid: 'rgba(120,170,255,.035)'};
const SEV = {Critical: PAL.crit, High: PAL.high, Medium: PAL.med, Low: PAL.low, Info: PAL.none, '': PAL.none};
const KIND = {alert: PAL.crit, vuln: PAL.high, reached: PAL.none, outbound: PAL.violet, attempt: PAL.none, blocked: PAL.subnet};
const KIND_RANK = {alert: 0, vuln: 1, reached: 2, outbound: 3, attempt: 4, blocked: 5};
const ACCENT = (getComputedStyle(html).getPropertyValue('--accent').trim() || getComputedStyle(html).getPropertyValue('--cyan').trim() || '#2ee6d6');

// ---------------------------------------------------------------- entity types and their pictograms (white on a coloured disc)
const pict = body => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`);
const TYPES = {
  host:    {name: 'Host', color: PAL.host, icon: pict('<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>')},
  ip:      {name: 'Outside address', color: PAL.ip, icon: pict('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.5 3.8 5.5 3.8 9s-1.2 6.5-3.8 9c-2.6-2.5-3.8-5.5-3.8-9S9.4 5.5 12 3z"/>')},
  svc:     {name: 'Service', color: PAL.svc, icon: pict('<path d="M9 3v5M15 3v5"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v4"/>')},
  vuln:    {name: 'Finding', color: PAL.high, icon: pict('<path d="M12 3l8 3v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M12 8v5M12 16.5v.01"/>')},
  cve:     {name: 'CVE', color: PAL.cve, icon: pict('<path d="M3 12V4h8l10 10-8 8z"/><circle cx="7.5" cy="8.5" r="1.2"/>')},
  alert:   {name: 'IPS alert', color: PAL.alert, icon: pict('<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 21h4"/>')},
  domain:  {name: 'IOC domain', color: PAL.ioc, icon: pict('<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>')},
  article: {name: 'Source article', color: PAL.article, icon: pict('<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>')},
  subnet:  {name: 'Subnet', color: PAL.subnet, icon: pict('<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-5.5 5.5M12 12l5.5 5.5"/>')},
};
const TYPE_ORDER = Object.keys(TYPES);
const IMG = {};
TYPE_ORDER.forEach(t => { const im = new Image(); im.onload = () => draw(); im.src = TYPES[t].icon; IMG[t] = im; });

// ---------------------------------------------------------------- what the report already knows, indexed once
const HOSTS = new Map((D.nodes || []).map(n => [n.id, n]));
const isHost = ip => HOSTS.has(ip) || !!FOCUS[ip];
const entOf = ip => (isHost(ip) ? 'host:' : 'ip:') + ip;
const shortName = ip => { const h = HOSTS.get(ip); return h && h.name ? h.name.split('.')[0] : ''; };
const IOCS = D.ioc_matches || [];
const iocByValue = new Map(IOCS.map(m => [m.value, m]));
const iocEnt = m => (m.type === 'domain' ? 'domain:' : m.type === 'cve' ? 'cve:' : entOf(m.value).split(':')[0] + ':') + m.value;
const ipHosts = new Map(), cveHosts = new Map(), findHosts = new Map(), sigs = new Map();
const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
Object.entries(FOCUS).forEach(([ip, f]) => {
  (f.attackers || []).forEach(a => {
    push(ipHosts, a.ip, {host: ip, kind: a.kind, n: a.sessions || 0, ports: (a.ports && a.ports.length ? a.ports : a.out_ports || []).slice(0, 3)});
    (a.alert_examples || []).forEach(x => { if (!x.name) return; if (!sigs.has(x.name)) sigs.set(x.name, {src: new Set(), dst: new Set()});
      sigs.get(x.name).src.add(a.ip); sigs.get(x.name).dst.add(ip); });
  });
  (f.findings || []).forEach(x => { (x.cves || []).forEach(c => push(cveHosts, c, ip)); push(findHosts, x.name, ip); });
});
const portTxt = ps => (ps || []).length ? ':' + ps.slice(0, 3).join(' :') : '';
const findingOf = (ip, name) => ((FOCUS[ip] || {}).findings || []).find(x => x.name === name) || {};
const svcKey = f => (f.port || 0) + '/' + (f.proto || 'tcp');

// an entity's label, colour and properties, from its id ("type:key")
function entity(id) {
  const i = id.indexOf(':'), type = id.slice(0, i), key = id.slice(i + 1);
  const e = {type, key, label: shown(key), sub: '', color: TYPES[type].color, props: [], full: ''};
  if (type === 'host') {
    const h = HOSTS.get(key) || {}, f = FOCUS[key] || {};
    e.label = shortName(key) || shown(key); e.sub = shortName(key) ? shown(key) : (h.subnet || '');
    if (h.sev) e.color = SEV[h.sev];
    e.props = [['Address', shown(key)], ['Name', h.name || '–'], ['Subnet', h.subnet || '–'], ['Operating system', h.os || '–'],
      ['Worst finding', h.sev || 'none'], ['Priority', h.pri ? `<span class="pill ${esc(h.pri)}">${esc(h.pri)}</span>` : '–', true],
      ['Risk score', h.score ?? '–'], ['Outside addresses', f.attackers_total ?? 0], ['Internal peers', f.peers_total ?? 0]];
  } else if (type === 'ip') {
    const ioc = iocByValue.get(key), seen = ipHosts.get(key) || [];
    const worst = seen.reduce((m, t) => (KIND_RANK[t.kind] ?? 9) < (KIND_RANK[m] ?? 9) ? t.kind : m, '');
    e.worst = worst;
    e.color = ioc ? PAL.ioc : KIND[worst] || TYPES.ip.color;
    e.sub = ioc ? 'IOC match' : worst === 'alert' ? 'IPS alert' : '';
    e.props = [['Address', shown(key)], ['Inside hosts it touched', seen.length], ['Worst contact', worst || '–'],
      ['IOC match', ioc ? 'yes · ' + (ioc.disposition || 'listed') : 'no']];
  } else if (type === 'svc') {
    const [ip, port] = key.split('|');
    e.label = port.startsWith('0/') ? 'host-level' : port; e.sub = shortName(ip) || shown(ip);
    e.props = [['Host', shown(ip)], ['Port', port]];
  } else if (type === 'vuln') {
    const bar = key.indexOf('|'), ip = key.slice(0, bar), name = key.slice(bar + 1), f = findingOf(ip, name);
    e.full = name; e.label = name.length > 34 ? name.slice(0, 32) + '…' : name;
    e.sub = [f.pri, f.cvss != null ? 'CVSS ' + f.cvss : ''].filter(Boolean).join(' · ');
    if (f.sev) e.color = SEV[f.sev];
    e.props = [['Finding', name], ['Host', shown(ip)], ['Port', f.port ? f.port + '/' + f.proto : 'host-level'], ['Severity', f.sev || '–'],
      ['CVSS', f.cvss ?? '–'], ['Public exploit', f.exploit ? 'yes' : 'no'], ['Exposure', f.exposure || '–'], ['CVEs', (f.cves || []).join(', ') || '–']];
  } else if (type === 'cve') {
    const n = (cveHosts.get(key) || []).length;
    e.sub = `${n} host${n === 1 ? '' : 's'}`; e.props = [['CVE', key], ['Hosts with it', n]];
  } else if (type === 'alert') {
    const s = sigs.get(key) || {src: new Set(), dst: new Set()};
    e.full = key; e.label = key.length > 34 ? key.slice(0, 32) + '…' : key; e.sub = 'not blocked';
    e.props = [['Signature', key], ['From', s.src.size + ' address(es)'], ['Against', s.dst.size + ' host(s)']];
  } else if (type === 'domain') {
    const m = iocByValue.get(key) || {};
    e.sub = m.disposition || 'IOC';
    e.props = [['Domain', key], ['Disposition', m.disposition || '–'],
      ['Seen as', Object.entries(m.observed || {}).map(([k, v]) => `${k} ×${v}`).join(', ') || '–'],
      ['Reported by', (m.sources || []).join(', ') || '–'], ['First seen', (m.first_seen || '').slice(0, 10) || '–'], ['Last seen', (m.last_seen || '').slice(0, 10) || '–']];
  } else if (type === 'article') {
    let site = key; try { site = new URL(key).hostname; } catch (_) {}
    e.label = site; e.sub = 'article'; e.props = [['Source', site], ['Address', key]];
  } else if (type === 'subnet') {
    const n = (D.nodes || []).filter(h => h.subnet === key).length;
    e.sub = `${n} host${n === 1 ? '' : 's'}`; e.props = [['Subnet', key], ['Hosts', n]];
  }
  return e;
}

// ---------------------------------------------------------------- pivots: what each entity type opens up
// each returns [{id, label (words on the arrow), color, from: 'me' | 'it' (which end the arrow starts from), parent?}]
const LIMIT = 12;
const PIVOTS = {
  host: [
    {key: 'reached', name: 'Who reached it from outside', run: ip => ((FOCUS[ip] || {}).attackers || []).filter(a => a.dir !== 'out')
      .sort((a, b) => (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9) || (b.sessions || 0) - (a.sessions || 0)).slice(0, 8)
      .map(a => ({id: entOf(a.ip), label: (a.kind === 'alert' ? 'IPS alert ' : a.kind === 'blocked' ? 'blocked ' : a.kind === 'attempt' ? 'tried ' : 'reached ') + portTxt(a.ports),
        color: KIND[a.kind] || PAL.line, from: 'it'})), note: 'riskiest 8'},
    {key: 'out', name: 'Where it connected out', run: ip => ((FOCUS[ip] || {}).attackers || []).filter(a => a.dir === 'out' || a.dir === 'both').slice(0, LIMIT)
      .map(a => ({id: entOf(a.ip), label: 'connected out ' + portTxt(a.out_ports), color: KIND.outbound, from: 'me'}))},
    {key: 'svc', name: 'Services and findings', run: ip => {
      const out = [], ports = new Map();
      ((FOCUS[ip] || {}).findings || []).forEach(f => { const p = svcKey(f); if (!ports.has(p)) ports.set(p, []); ports.get(p).push(f); });
      ports.forEach((fs, p) => {
        const svc = `svc:${ip}|${p}`;
        out.push({id: svc, label: 'listens', color: PAL.line, from: 'me'});
        fs.forEach(f => out.push({id: `vuln:${ip}|${f.name}`, label: `${f.pri} ${f.sev}`, color: SEV[f.sev] || PAL.line, from: 'me', parent: svc}));
      });
      return out; }},
    {key: 'peers', name: 'Talks to inside', run: ip => ((FOCUS[ip] || {}).peers || []).slice(0, LIMIT)
      .map(p => ({id: entOf(p.ip), label: p.out ? 'talks to ' + portTxt(p.ports_out) : 'reached by ' + portTxt(p.ports_in), color: PAL.none, from: p.out ? 'me' : 'it'}))},
    {key: 'hop2', name: 'Could reach next', run: ip => ((FOCUS[ip] || {}).hop2 || []).filter(x => x.p >= 0.05).slice(0, 10)
      .map(x => ({id: entOf(x.ip), label: `could reach · ${Math.round((x.p || 0) * 100)}%`, color: PAL.violet, from: 'me'}))},
    {key: 'ioc', name: 'IOC matches', run: ip => IOCS.filter(m => (m.hosts || []).includes(ip))
      .map(m => ({id: iocEnt(m), label: Object.keys(m.observed || {})[0] || 'matched', color: PAL.ioc, from: 'me'}))},
    {key: 'subnet', name: 'Subnet', run: ip => { const h = HOSTS.get(ip); return h && h.subnet ? [{id: 'subnet:' + h.subnet, label: 'member of', color: PAL.line, from: 'me'}] : []; }},
  ],
  ip: [
    {key: 'hosts', name: 'Inside hosts it touched', run: ip => (ipHosts.get(ip) || []).slice()
      .sort((a, b) => (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9) || b.n - a.n).slice(0, LIMIT)
      .map(t => ({id: 'host:' + t.host, label: (t.kind === 'outbound' ? 'contacted by ' : t.kind === 'alert' ? 'IPS alert ' : t.kind === 'blocked' ? 'blocked ' : 'reached ') + portTxt(t.ports),
        color: KIND[t.kind] || PAL.line, from: t.kind === 'outbound' ? 'it' : 'me'}))},
    {key: 'alerts', name: 'IPS alerts it set off', run: ip => [...sigs.entries()].filter(([, s]) => s.src.has(ip))
      .map(([sig]) => ({id: 'alert:' + sig, label: 'set off', color: PAL.crit, from: 'me'}))},
    {key: 'art', name: 'Source articles', run: ip => ((iocByValue.get(ip) || {}).articles || []).map(u => ({id: 'article:' + u, label: 'reported in', color: PAL.article, from: 'me'}))},
  ],
  svc: [
    {key: 'vulns', name: 'Findings on this port', run: key => { const [ip, p] = key.split('|');
      return ((FOCUS[ip] || {}).findings || []).filter(f => svcKey(f) === p).map(f => ({id: `vuln:${ip}|${f.name}`, label: `${f.pri} ${f.sev}`, color: SEV[f.sev] || PAL.line, from: 'me'})); }},
  ],
  vuln: [
    {key: 'cves', name: 'CVEs', run: key => { const b = key.indexOf('|');
      return (findingOf(key.slice(0, b), key.slice(b + 1)).cves || []).map(c => ({id: 'cve:' + c, label: 'tracked as', color: PAL.cve, from: 'me'})); }},
    {key: 'same', name: 'Other hosts with this finding', run: key => { const b = key.indexOf('|'), ip = key.slice(0, b);
      return (findHosts.get(key.slice(b + 1)) || []).filter(h => h !== ip).slice(0, LIMIT).map(h => ({id: 'host:' + h, label: 'also on', color: PAL.high, from: 'me'})); }},
  ],
  cve: [
    {key: 'hosts', name: 'Hosts with this CVE', run: c => (cveHosts.get(c) || []).slice(0, 15).map(h => ({id: 'host:' + h, label: 'affects', color: PAL.cve, from: 'me'}))},
  ],
  alert: [
    {key: 'src', name: 'Where it came from', run: s => [...((sigs.get(s) || {}).src || [])].map(ip => ({id: entOf(ip), label: 'set off by', color: PAL.crit, from: 'it'}))},
    {key: 'dst', name: 'Hosts it was against', run: s => [...((sigs.get(s) || {}).dst || [])].map(ip => ({id: 'host:' + ip, label: 'against', color: PAL.crit, from: 'me'}))},
  ],
  domain: [
    {key: 'hosts', name: 'Hosts that looked it up', run: d => ((iocByValue.get(d) || {}).hosts || []).filter(isHost).map(h => ({id: 'host:' + h, label: 'looked up by', color: PAL.ioc, from: 'me'}))},
    {key: 'art', name: 'Source articles', run: d => ((iocByValue.get(d) || {}).articles || []).map(u => ({id: 'article:' + u, label: 'reported in', color: PAL.article, from: 'me'}))},
  ],
  article: [
    {key: 'iocs', name: 'Other IOCs from this article', run: u => IOCS.filter(m => (m.articles || []).includes(u)).map(m => ({id: iocEnt(m), label: 'names', color: PAL.ioc, from: 'me'}))},
  ],
  subnet: [
    {key: 'hosts', name: 'Riskiest hosts in it', run: s => (D.nodes || []).filter(h => h.subnet === s).sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 15)
      .map(h => ({id: 'host:' + h.id, label: 'contains', color: PAL.line, from: 'me'}))},
  ],
};
const pivotsOf = id => PIVOTS[id.slice(0, id.indexOf(':'))] || [];
const keyOf = id => id.slice(id.indexOf(':') + 1);

// ---------------------------------------------------------------- page chrome
root.innerHTML = `<canvas id="iv-canvas" aria-label="Investigation graph"></canvas>
<header class="iv-top"><div class="iv-title"><div class="t">Investigate</div><div class="s" id="iv-sub"></div></div>
  <input id="iv-seed" type="search" placeholder="Start from a host, IP, CVE or domain" aria-label="Start from a host, IP, CVE or domain" autocomplete="off" list="iv-seed-list"><datalist id="iv-seed-list"></datalist>
  <div class="seg" role="group" aria-label="Layout"><button type="button" data-lay="tree" title="Each pivot opens to the right (T)">Tree</button><button type="button" data-lay="radial" title="Pivots open outwards from the start (R)">Radial</button><button type="button" data-lay="organic" title="Pulled together by links (O)">Organic</button></div>
  <button type="button" id="iv-elabels" aria-pressed="true" title="Words on the arrows">Link labels</button>
  <button type="button" id="iv-remove" title="Remove the selected entity and what only it brought in (Delete)">Remove</button>
  <button type="button" id="iv-clear" title="Start over from the selected entity, or from the start">Clear</button>
  <div class="seg" role="group" aria-label="View"><button type="button" data-view="flat" title="Flat network view (2)">Flat</button><button type="button" data-view="3d" title="3D network view (3)">3D</button><button type="button" data-view="paths" title="Attack paths (P)">Attack paths</button><button type="button" data-view="timeline" title="Flows over time (I)">Timeline</button><button type="button" class="on" aria-current="true" title="Investigate (Esc to go back)">Investigate</button></div>
  <span class="iv-qwrap"><button type="button" id="iv-about-toggle" aria-controls="iv-about" aria-expanded="false" aria-label="What am I looking at?" title="What am I looking at? (?)">?</button></span></header>
<aside class="iv-palette"><h3>Entities</h3><div id="iv-types"></div>
  <p class="iv-hint"><b>Click</b> an entity for its details and pivots. <b>Double-click</b> runs its next pivot. Drag an entity to move it. <kbd>Del</kbd> removes it. Uncheck a pivot to take back what it added. Click a type above to hide it.</p></aside>
<aside class="iv-props" id="iv-props" aria-live="polite"></aside>
<p id="iv-about" hidden>An investigation graph that grows from one lead. Each <b>icon</b> is an entity (host, outside address, service, finding, CVE, IPS alert, IOC domain, article, subnet) and each <b>arrow</b> says how two are connected. Click an entity and run a <b>pivot</b> to follow the trail. Pivots read only this report; nothing is looked up online. Connections are leads, not confirmed compromise.</p>
<div id="iv-tip" hidden></div>`;
const $ = id => document.getElementById(id);
const cv = $('iv-canvas'), ctx = cv.getContext('2d');

// ---------------------------------------------------------------- the case: entities and links
const ents = new Map();   // id -> {id, e (entity), x, y, tx, ty, r, parent, ran: Map pivot -> what it added}
const links = [];         // {a, b, label, color}
let seedId = null, selected = null, hover = null, layout = 'tree', edgeLabels = true;
const hidden = new Set();
function addEntity(id, parent, at) {
  if (ents.has(id)) return false;
  const e = entity(id);
  ents.set(id, {id, e, x: at ? at.x : 0, y: at ? at.y : 0, tx: 0, ty: 0, r: 17, parent: parent || null, ran: new Map()});
  return true;
}
function link(a, b, label, color) {
  if (a === b || links.some(l => (l.a === a && l.b === b) || (l.a === b && l.b === a))) return null;
  const l = {a, b, label: (label || '').trim(), color: color || PAL.line};
  links.push(l);
  return l;
}
function runPivot(id, pk, relayout = true) {
  const pv = pivotsOf(id).find(p => p.key === pk), at = ents.get(id); if (!pv || !at) return 0;
  if (at.ran.has(pk)) return 0;
  const made = {ents: [], links: [], hits: new Set(), pairs: []};
  pv.run(keyOf(id)).forEach(r => {
    const parent = r.parent || id, from = ents.get(parent) || at;
    if (addEntity(r.id, parent, from)) made.ents.push(r.id);
    made.hits.add(r.id);
    const pair = r.from === 'it' ? [r.id, parent, r.label, r.color] : [parent, r.id, r.label, r.color];
    made.pairs.push(pair);
    const l = link(...pair);
    if (l) made.links.push(l);
  });
  at.ran.set(pk, made);
  const added = made.ents.length;
  if (relayout) { applyLayout(false, id); refreshUI(); }
  return added;
}
// Unchecking a pivot takes back what it added: its links, the entities it brought in, and in turn
// whatever was pivoted to from them. Entities that were there before, or that a pivot still checked
// also reached, stay, and so do the links a pivot still checked also draws.
function undoPivot(id, pk, relayout = true) {
  const at = ents.get(id), made = at && at.ran.get(pk);
  if (!made) return 0;
  const keep = new Set();     // reached by a pivot that stays checked on an entity that stays
  let undone, drop;
  for (;;) {
    undone = new Set([made]); drop = new Set();
    const take = x => { const n = ents.get(x); if (!n || x === seedId || drop.has(x) || keep.has(x)) return;
      drop.add(x); n.ran.forEach(m => { undone.add(m); m.ents.forEach(take); }); };
    made.ents.forEach(take);
    const before = keep.size;
    ents.forEach(n => { if (!drop.has(n.id)) n.ran.forEach(m => { if (!undone.has(m)) m.hits.forEach(x => keep.add(x)); }); });
    if (keep.size === before) break;
  }
  const kept = () => { const out = []; ents.forEach(n => n.ran.forEach(m => { if (!undone.has(m)) out.push(m); })); return out; };
  at.ran.delete(pk);
  for (let i = links.length - 1; i >= 0; i--) {
    const l = links[i];
    if (drop.has(l.a) || drop.has(l.b) || [...undone].some(m => m.links.includes(l))) links.splice(i, 1);
  }
  drop.forEach(x => ents.delete(x));
  kept().forEach(m => m.pairs.forEach(p => { if (ents.has(p[0]) && ents.has(p[1])) { const l = link(...p); if (l) m.links.push(l); } }));
  ents.forEach(n => { if (n.parent && !ents.has(n.parent)) { const l = links.find(l => l.a === n.id || l.b === n.id); n.parent = l ? (l.a === n.id ? l.b : l.a) : null; } });
  if (selected && !ents.has(selected)) selected = null;
  if (relayout) { applyLayout(false, id); refreshUI(); }
  return drop.size;
}
function togglePivot(id, pk) { const n = ents.get(id); return n && n.ran.has(pk) ? -undoPivot(id, pk) : runPivot(id, pk); }
const visible = n => !hidden.has(n.e.type);

// ---------------------------------------------------------------- layouts (world units; y grows down)
const COL = 330, ROW = 104;
function treeOrder() {
  const kids = new Map([...ents.keys()].map(k => [k, []])), roots = [];
  ents.forEach(n => { if (n.parent && ents.has(n.parent)) kids.get(n.parent).push(n.id); else roots.push(n.id); });
  const rank = id => { const n = ents.get(id); return TYPE_ORDER.indexOf(n.e.type) * 10 +
    (n.e.type === 'ip' ? (iocByValue.has(n.e.key) ? 0 : 1 + (KIND_RANK[n.e.worst] ?? 6)) : 0); };
  kids.forEach(l => l.sort((a, b) => rank(a) - rank(b) || ents.get(a).e.label.localeCompare(ents.get(b).e.label)));
  roots.sort((a, b) => (a === seedId ? -1 : b === seedId ? 1 : 0));
  return {kids, roots};
}
function treeTargets() {
  const {kids, roots} = treeOrder(); let slot = 0;
  const place = (id, d) => {
    const n = ents.get(id), ks = kids.get(id).filter(k => visible(ents.get(k)));
    if (!ks.length) { n.tx = d * COL; n.ty = slot++ * ROW; return n.ty; }
    const ys = ks.map(k => place(k, d + 1));
    n.tx = d * COL; n.ty = (ys[0] + ys[ys.length - 1]) / 2; return n.ty;
  };
  roots.forEach(r => { place(r, 0); slot += 0.6; });
}
function radialTargets() {
  const {kids, roots} = treeOrder(), leaves = [], depth = new Map(), ang = new Map();
  const walk = (id, d) => { depth.set(id, d); const ks = kids.get(id); if (!ks.length) leaves.push(id); ks.forEach(k => walk(k, d + 1)); };
  roots.forEach((r, i) => walk(r, i ? 1 : 0));
  leaves.forEach((id, i) => ang.set(id, i / Math.max(1, leaves.length) * Math.PI * 2));
  const up = id => { const ks = kids.get(id); if (ks.length) { ks.forEach(up); ang.set(id, (ang.get(ks[0]) + ang.get(ks[ks.length - 1])) / 2); } };
  roots.forEach(up);
  const maxD = Math.max(1, ...depth.values()), R = Math.max(230, leaves.length * 78 / (Math.PI * 2) / maxD);
  ents.forEach(n => { const r = (depth.get(n.id) || 0) * R, a = ang.get(n.id) || 0; n.tx = r * Math.cos(a); n.ty = r * Math.sin(a); });
}
// a small force layout: links pull, every pair pushes, starting from the radial picture
function organicTargets() {
  radialTargets();
  const list = [...ents.values()], idx = new Map(list.map((n, i) => [n.id, i]));
  const P = list.map(n => ({x: n.tx, y: n.ty, vx: 0, vy: 0}));
  const L = links.map(l => [idx.get(l.a), idx.get(l.b)]).filter(([a, b]) => a != null && b != null);
  for (let it = 0; it < 320; it++) {
    const cool = 1 - it / 320;
    for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) {
      let dx = P[j].x - P[i].x, dy = P[j].y - P[i].y, d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      const f = 22000 / d2, d = Math.sqrt(d2);
      P[i].vx -= f * dx / d; P[i].vy -= f * dy / d; P[j].vx += f * dx / d; P[j].vy += f * dy / d;
    }
    L.forEach(([a, b]) => { const dx = P[b].x - P[a].x, dy = P[b].y - P[a].y, d = Math.hypot(dx, dy) || 1, f = (d - 190) * 0.06;
      P[a].vx += f * dx / d; P[a].vy += f * dy / d; P[b].vx -= f * dx / d; P[b].vy -= f * dy / d; });
    P.forEach(p => { p.vx -= p.x * 0.004; p.vy -= p.y * 0.004; const s = Math.min(1, 40 * cool / (Math.hypot(p.vx, p.vy) || 1));
      p.x += p.vx * s; p.y += p.vy * s; p.vx *= 0.5; p.vy *= 0.5; });
  }
  list.forEach((n, i) => { n.tx = P[i].x; n.ty = P[i].y; });
}

// ---------------------------------------------------------------- camera: world -> screen
let W = 0, H = 0, DPR = 1;
const cam = {x: 0, y: 0, s: 1, tx: 0, ty: 0, ts: 1};
const panelL = () => W > 1100 ? 210 : 0, panelR = () => W > 800 ? 350 : 0, TOP = 64;
const sx = x => (x - cam.x) * cam.s + (panelL() + W - panelR()) / 2;
const sy = y => (y - cam.y) * cam.s + (TOP + H) / 2;
const wx = px => (px - (panelL() + W - panelR()) / 2) / cam.s + cam.x;
const wy = py => (py - (TOP + H) / 2) / cam.s + cam.y;
// fit the case in the free stage, but never shrink it below SCALE_MIN so labels stay readable; a bigger case
// starts at its top left (the lead) and the analyst pans or zooms out
function fit(snap, about) {
  const vis = [...ents.values()].filter(visible); if (!vis.length) return;
  let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
  vis.forEach(n => { x0 = Math.min(x0, n.tx); x1 = Math.max(x1, n.tx); y0 = Math.min(y0, n.ty); y1 = Math.max(y1, n.ty); });
  const sw = W - panelL() - panelR(), sh = H - TOP, mx = 150, my = 70, SCALE_MIN = 0.6;
  const s = Math.max(SCALE_MIN, Math.min(1, sw / (x1 - x0 + 2 * mx), sh / (y1 - y0 + 2 * my)));
  cam.ts = s;
  cam.tx = (x1 - x0 + 2 * mx) * s > sw ? x0 - mx + sw / 2 / s : (x0 + x1) / 2;
  cam.ty = (y1 - y0 + 2 * my) * s > sh ? y0 - my + sh / 2 / s : (y0 + y1) / 2;
  // after a pivot on a big case, keep the entity it ran from (and what it opened) on screen
  const a = about && ents.get(about);
  if (a && (y1 - y0 + 2 * my) * s > sh) cam.ty = Math.max(y0 - my + sh / 2 / s, Math.min(y1 + my - sh / 2 / s, a.ty));
  if (a && (x1 - x0 + 2 * mx) * s > sw) cam.tx = Math.max(x0 - mx + sw / 2 / s, Math.min(x1 + mx - sw / 2 / s, a.tx + sw / 4 / s));
  if (snap) { cam.x = cam.tx; cam.y = cam.ty; cam.s = cam.ts; }
}
function applyLayout(snap, about) {
  if (layout === 'tree') treeTargets(); else if (layout === 'radial') radialTargets(); else organicTargets();
  fit(snap, about);
  if (snap) ents.forEach(n => { n.x = n.tx; n.y = n.ty; });
  kick();
}

// ---------------------------------------------------------------- drawing
function resize() {
  DPR = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = W * DPR; cv.height = H * DPR; cv.style.width = W + 'px'; cv.style.height = H + 'px';
}
let raf = 0, moving = false;
function kick() { if (!raf && isOpen) raf = requestAnimationFrame(frame); }
function frame() {
  raf = 0; moving = false;
  const k = 0.2;
  ents.forEach(n => { if (n === drag.node) return; const dx = n.tx - n.x, dy = n.ty - n.y;
    if (Math.abs(dx) > 0.3 || Math.abs(dy) > 0.3) { n.x += dx * k; n.y += dy * k; moving = true; } else { n.x = n.tx; n.y = n.ty; } });
  for (const p of ['x', 'y', 's']) { const t = cam['t' + p], d = t - cam[p];
    if (Math.abs(d) > (p === 's' ? 0.0005 : 0.3)) { cam[p] += d * k; moving = true; } else cam[p] = t; }
  draw();
  if (moving) kick();
}
function labelBox(text, font) { ctx.font = font; return ctx.measureText(text).width; }
function draw() {
  if (!isOpen) return;
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0); ctx.clearRect(0, 0, W, H);
  if (PAL.bg) { ctx.fillStyle = PAL.bg; ctx.fillRect(0, 0, W, H); }
  const s = cam.s, R = n => n.r * (n.id === seedId ? 1.3 : 1) * Math.max(0.85, s);
  const fs = Math.max(10.5, Math.min(13, 12.5 * s));
  // links: from edge to edge, arrowhead at the far end, words along the middle
  links.forEach(l => {
    const a = ents.get(l.a), b = ents.get(l.b); if (!a || !b || !visible(a) || !visible(b)) return;
    const x1 = sx(a.x), y1 = sy(a.y), x2 = sx(b.x), y2 = sy(b.y), d = Math.hypot(x2 - x1, y2 - y1); if (d < 1) return;
    const ux = (x2 - x1) / d, uy = (y2 - y1) / d, ra = R(a) + 2, rb = R(b) + 3;
    const on = selected && (l.a === selected || l.b === selected), dim = selected && !on;
    ctx.globalAlpha = dim ? 0.5 : 1;
    ctx.strokeStyle = l.color; ctx.fillStyle = l.color; ctx.lineWidth = on ? 2.4 : 1.3;
    ctx.beginPath(); ctx.moveTo(x1 + ux * ra, y1 + uy * ra); ctx.lineTo(x2 - ux * (rb + 6), y2 - uy * (rb + 6)); ctx.stroke();
    const hx = x2 - ux * rb, hy = y2 - uy * rb, ah = 8 * Math.max(0.8, s);
    ctx.beginPath(); ctx.moveTo(hx, hy); ctx.lineTo(hx - ux * ah - uy * ah * 0.5, hy - uy * ah + ux * ah * 0.5);
    ctx.lineTo(hx - ux * ah + uy * ah * 0.5, hy - uy * ah - ux * ah * 0.5); ctx.closePath(); ctx.fill();
    if (edgeLabels && l.label) {
      const font = `${Math.max(9, fs - 2)}px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace`, tw = labelBox(l.label, font);
      if (tw + 30 < d - ra - rb) {
        let ang = Math.atan2(y2 - y1, x2 - x1); if (ang > Math.PI / 2 || ang < -Math.PI / 2) ang += Math.PI;
        ctx.save(); ctx.translate((x1 + x2) / 2, (y1 + y2) / 2); ctx.rotate(ang);
        ctx.textAlign = 'center'; ctx.lineJoin = 'round'; ctx.lineWidth = 3.5; ctx.strokeStyle = PAL.halo; ctx.strokeText(l.label, 0, -4);
        ctx.fillStyle = on ? PAL.label : PAL.sub; ctx.fillText(l.label, 0, -4); ctx.restore();
      }
    }
  });
  ctx.globalAlpha = 1;
  // entities: coloured disc, white pictogram, name and a second line underneath
  ents.forEach(n => {
    if (!visible(n)) return;
    const x = sx(n.x), y = sy(n.y), r = R(n);
    if (x < -200 || x > W + 200 || y < -100 || y > H + 100) return;
    const dim = selected && n.id !== selected && !links.some(l => (l.a === selected && l.b === n.id) || (l.b === selected && l.a === n.id));
    ctx.globalAlpha = dim ? 0.6 : 1;
    ctx.fillStyle = n.e.color; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
    if (IMG[n.e.type] && IMG[n.e.type].complete) ctx.drawImage(IMG[n.e.type], x - r * 0.62, y - r * 0.62, r * 1.24, r * 1.24);
    if (n.id === selected || n === hover) { ctx.strokeStyle = ACCENT; ctx.lineWidth = 2.5; ctx.beginPath(); ctx.arc(x, y, r + 4, 0, Math.PI * 2); ctx.stroke(); }
    ctx.textAlign = 'center'; ctx.lineJoin = 'round';
    ctx.font = `${n.id === selected ? 600 : 500} ${fs}px system-ui,-apple-system,"Segoe UI",sans-serif`;
    ctx.lineWidth = 3.5; ctx.strokeStyle = PAL.halo; ctx.strokeText(n.e.label, x, y + r + fs + 2);
    ctx.fillStyle = PAL.label; ctx.fillText(n.e.label, x, y + r + fs + 2);
    if (n.e.sub) { ctx.font = `${Math.max(9, fs - 2)}px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace`;
      ctx.strokeText(n.e.sub, x, y + r + fs * 2 + 3); ctx.fillStyle = PAL.sub; ctx.fillText(n.e.sub, x, y + r + fs * 2 + 3); }
  });
  ctx.globalAlpha = 1;
}

// ---------------------------------------------------------------- mouse: click selects, double-click pivots, drag moves or pans, wheel zooms
function hit(px, py) {
  let best = null, bd = Infinity;
  ents.forEach(n => { if (!visible(n)) return; const d = Math.hypot(sx(n.x) - px, sy(n.y) - py), r = n.r * Math.max(0.85, cam.s) * (n.id === seedId ? 1.3 : 1) + 6;
    if (d < r && d < bd) { bd = d; best = n; } });
  return best;
}
const drag = {on: false, node: null, x: 0, y: 0, moved: 0};
cv.addEventListener('pointerdown', e => {
  drag.on = true; drag.node = hit(e.offsetX, e.offsetY); drag.x = e.offsetX; drag.y = e.offsetY; drag.moved = 0;
  cv.setPointerCapture(e.pointerId); cv.classList.add('drag');
});
cv.addEventListener('pointermove', e => {
  if (drag.on) {
    const dx = e.offsetX - drag.x, dy = e.offsetY - drag.y; drag.moved += Math.abs(dx) + Math.abs(dy); drag.x = e.offsetX; drag.y = e.offsetY;
    if (drag.node) { drag.node.x += dx / cam.s; drag.node.y += dy / cam.s; drag.node.tx = drag.node.x; drag.node.ty = drag.node.y; }
    else { cam.x -= dx / cam.s; cam.y -= dy / cam.s; cam.tx = cam.x; cam.ty = cam.y; }
    $('iv-tip').hidden = true; draw(); return;
  }
  const n = hit(e.offsetX, e.offsetY);
  if (n !== hover) { hover = n; cv.classList.toggle('hover', !!n); draw(); }
  const tip = $('iv-tip');
  if (n && n.e.full) { tip.textContent = n.e.full; tip.hidden = false; tip.style.left = e.clientX + 14 + 'px'; tip.style.top = e.clientY + 14 + 'px'; }
  else tip.hidden = true;
});
cv.addEventListener('pointerup', e => {
  cv.classList.remove('drag'); drag.on = false;
  if (drag.moved < 4) { const n = hit(e.offsetX, e.offsetY); select(n ? n.id : null); }
  drag.node = null;
});
cv.addEventListener('dblclick', e => {
  const n = hit(e.offsetX, e.offsetY); if (!n) return;
  select(n.id);
  const next = pivotsOf(n.id).find(p => !n.ran.has(p.key) && p.run(keyOf(n.id)).length);
  if (next) runPivot(n.id, next.key);
});
cv.addEventListener('wheel', e => {
  e.preventDefault();
  const px = e.offsetX, py = e.offsetY, bx = wx(px), by = wy(py);
  cam.s = cam.ts = Math.max(0.15, Math.min(2.5, cam.s * Math.exp(-e.deltaY * 0.0015)));
  cam.x = cam.tx = bx - (px - (panelL() + W - panelR()) / 2) / cam.s; cam.y = cam.ty = by - (py - (TOP + H) / 2) / cam.s;
  draw();
}, {passive: false});

// ---------------------------------------------------------------- side panels
function select(id) { selected = id && ents.has(id) ? id : null; renderProps(); draw(); }
function renderProps() {
  const p = $('iv-props');
  if (!selected) {
    const s = ents.get(seedId);
    p.innerHTML = `<h3>Investigation</h3><p class="iv-hint">Started from <b>${esc(s ? s.e.label : '')}</b>. Click an entity to see its details and the pivots you can run from it, the way you work outward from one lead.</p>` +
      `<p class="iv-hint">Pivots read only this report; nothing is looked up online. Connections are leads to check, not confirmed compromise.</p>`;
    return;
  }
  const n = ents.get(selected), e = n.e, T = TYPES[e.type];
  const pv = pivotsOf(selected).map(x => { const c = x.run(keyOf(selected)).length, done = n.ran.has(x.key);
    return `<button class="iv-pv${done ? ' done' : ''}" type="button" role="checkbox" aria-checked="${done}" data-pk="${esc(x.key)}"${c || done ? '' : ' disabled'}` +
      ` title="${done ? 'Uncheck to take back what this pivot added' : 'Run this pivot'}"><span class="box" aria-hidden="true"></span>` +
      `<span class="nm">${esc(x.name)}</span><span class="ct">${x.note && c > 8 ? '8 of ' : ''}${c}</span></button>`; }).join('');
  const hostIp = e.type === 'host' && window.VFExplorer && D.focus[e.key] ? e.key : '';
  p.innerHTML = `<div class="iv-ehead"><span class="ico" style="background:${esc(e.color)}"><img alt="" src="${T.icon}"></span><div><div class="ty">${esc(T.name)}</div><h2>${esc(e.full || e.label)}</h2></div></div>` +
    `<h3>Properties</h3><table class="iv-kv">${e.props.map(([k, v, raw]) => `<tr><td>${esc(k)}</td><td>${raw ? v : esc(v)}</td></tr>`).join('')}</table>` +
    (pv ? `<h3>Pivots</h3>${pv}` : '') +
    (hostIp ? `<button type="button" class="iv-goto" data-host="${esc(hostIp)}">Show this host in the network view</button>` : '');
}
$('iv-props').addEventListener('click', ev => {
  const b = ev.target.closest('.iv-pv'); if (b && selected) { togglePivot(selected, b.dataset.pk); renderProps(); return; }
  const g = ev.target.closest('.iv-goto'); if (g) { close(); if (window.VFExplorer) window.VFExplorer.focus(g.dataset.host); }
});
function refreshUI() {
  const counts = {}; ents.forEach(n => { counts[n.e.type] = (counts[n.e.type] || 0) + 1; });
  $('iv-types').innerHTML = TYPE_ORDER.map(t => `<button class="iv-etype" type="button" data-t="${t}" aria-pressed="${!hidden.has(t)}"><span class="ico" style="background:${TYPES[t].color}"><img alt="" src="${TYPES[t].icon}"></span>` +
    `<span class="nm">${esc(TYPES[t].name)}</span><span class="ct">${counts[t] || 0}</span></button>`).join('');
  $('iv-sub').textContent = `${ents.size} entit${ents.size === 1 ? 'y' : 'ies'} · ${links.length} link${links.length === 1 ? '' : 's'}`;
  root.querySelectorAll('[data-lay]').forEach(b => { b.classList.toggle('on', b.dataset.lay === layout); b.setAttribute('aria-pressed', b.dataset.lay === layout); });
  renderProps();
}
$('iv-types').addEventListener('click', ev => { const b = ev.target.closest('.iv-etype'); if (!b) return;
  const t = b.dataset.t; if (hidden.has(t)) hidden.delete(t); else hidden.add(t);
  if (selected && hidden.has(ents.get(selected).e.type)) selected = null;
  applyLayout(); refreshUI(); });

// ---------------------------------------------------------------- controls
function setLayout(name) { layout = name; applyLayout(); refreshUI(); }
root.querySelectorAll('[data-lay]').forEach(b => { b.onclick = () => setLayout(b.dataset.lay); });
$('iv-elabels').onclick = () => { edgeLabels = !edgeLabels; $('iv-elabels').setAttribute('aria-pressed', edgeLabels); draw(); };
function removeEntity(id) {
  if (!id || id === seedId || !ents.has(id)) return;
  const drop = new Set([id]);   // and whatever only it brought in, if nothing else links to it
  const degree = x => links.filter(l => l.a === x || l.b === x).length;
  const walk = x => ents.forEach(n => { if (n.parent === x && !drop.has(n.id) && degree(n.id) <= 1) { drop.add(n.id); walk(n.id); } });
  walk(id);
  drop.forEach(x => ents.delete(x));
  for (let i = links.length - 1; i >= 0; i--) if (drop.has(links[i].a) || drop.has(links[i].b)) links.splice(i, 1);
  ents.forEach(n => { if (n.parent && !ents.has(n.parent)) { const l = links.find(l => l.a === n.id || l.b === n.id); n.parent = l ? (l.a === n.id ? l.b : l.a) : null; } });
  selected = null; applyLayout(); refreshUI();
}
$('iv-remove').onclick = () => removeEntity(selected);
$('iv-clear').onclick = () => start(selected || seedId, false);
root.querySelectorAll('.seg [data-view]').forEach(b => { b.onclick = () => showView(b.dataset.view);
  if (b.dataset.view === '3d' && !(window.VFExplorer && window.VFExplorer.can3d)) b.hidden = true; });
function syncViewButtons() {
  const paths = document.getElementById('btn-paths'), tl = document.getElementById('btn-timeline');
  root.querySelector('[data-view="paths"]').hidden = !paths || paths.hidden;
  root.querySelector('[data-view="timeline"]').hidden = !tl || tl.hidden;
}
// start from what the analyst types: a host name or address, an outside address, a CVE or an IOC domain
$('iv-seed-list').innerHTML = (D.nodes || []).filter(h => h.pri === 'P1').slice(0, 200)
  .map(h => `<option value="${esc(shown(h.id))}">${esc(h.name || '')}</option>`).join('') +
  IOCS.slice(0, 200).map(m => `<option value="${esc(m.value)}">IOC ${esc(m.type)}</option>`).join('');
function resolve(q) {
  q = String(q || '').trim(); if (!q) return null;
  if (q.includes(':') && ents.has(q)) return q;
  const asType = /^(host|ip|cve|domain|subnet|alert|article|svc|vuln):/.exec(q); if (asType) return q;
  const host = [...HOSTS.keys()].find(id => shown(id) === q) || [...HOSTS.values()].find(h => h.name && (h.name === q || h.name.split('.')[0] === q));
  if (host) return 'host:' + (typeof host === 'string' ? host : host.id);
  if (/^cve-/i.test(q) && cveHosts.has(q.toUpperCase())) return 'cve:' + q.toUpperCase();
  if (iocByValue.has(q)) return iocEnt(iocByValue.get(q));
  if (ipHosts.has(q)) return 'ip:' + q;
  if ((D.nodes || []).some(h => h.subnet === q)) return 'subnet:' + q;
  return null;
}
$('iv-seed').addEventListener('keydown', ev => {
  if (ev.key !== 'Enter') return;
  const id = resolve(ev.target.value);
  ev.target.classList.toggle('bad', !id);
  if (id) { start(id, true); ev.target.blur(); }
});

// a new case from one entity; auto opens the first ring of pivots, the way an analyst would start
function start(id, auto) {
  ents.clear(); links.length = 0; selected = null; seedId = id; hidden.clear();
  addEntity(id, null);
  if (auto) {
    const t = id.slice(0, id.indexOf(':'));
    if (t === 'host') {
      ['reached', 'svc', 'ioc'].forEach(k => runPivot(id, k, false));
      // follow the first alerting addresses one more step, and the IOC domains to their articles
      [...ents.values()].filter(n => n.e.type === 'ip' && n.parent === id && n.e.worst === 'alert').slice(0, 2).forEach(n => runPivot(n.id, 'alerts', false));
      [...ents.values()].filter(n => n.e.type === 'domain' && n.parent === id).forEach(n => runPivot(n.id, 'art', false));
    } else pivotsOf(id).slice(0, 2).forEach(p => runPivot(id, p.key, false));
  }
  applyLayout(true); refreshUI();
}
// default lead: the host the network view has open, else a host with both an IOC match and an unblocked IPS
// alert, else the report's start host
function defaultLead() {
  const f = window.VFExplorer && window.VFExplorer.focused && window.VFExplorer.focused();
  if (f && FOCUS[f]) return 'host:' + f;
  const lead = Object.keys(FOCUS).find(ip => IOCS.some(m => (m.hosts || []).includes(ip)) && (FOCUS[ip].attackers || []).some(a => a.kind === 'alert'));
  return 'host:' + (lead || (FOCUS[D.start] ? D.start : Object.keys(FOCUS)[0]));
}

// ---------------------------------------------------------------- open and close
let isOpen = false;
const ABOUT_MS = 15000; let aboutTimer = 0;
function openAbout() { $('iv-about').hidden = false; $('iv-about-toggle').setAttribute('aria-expanded', 'true'); clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, ABOUT_MS); }
function closeAbout() { clearTimeout(aboutTimer); $('iv-about').hidden = true; $('iv-about-toggle').setAttribute('aria-expanded', 'false'); }
$('iv-about-toggle').onclick = () => { if ($('iv-about').hidden) openAbout(); else closeAbout(); };
$('iv-about').addEventListener('mouseenter', () => clearTimeout(aboutTimer));
$('iv-about').addEventListener('mouseleave', () => { clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, 3000); });
// open(): the case as it was left, or a new one from `id` ("host:10.0.0.5", or a plain address, CVE, domain)
function open(id) {
  if (window.VFPaths) window.VFPaths.close();
  if (window.VFTimeline) window.VFTimeline.close();
  const want = id ? resolve(id) : null;
  isOpen = true; root.hidden = false; openBtn.setAttribute('aria-expanded', 'true');
  resize(); syncViewButtons();
  if (want) start(want, true); else if (!ents.size) start(defaultLead(), true); else { applyLayout(true); refreshUI(); }
  openAbout();
  if (!/[?&#]investigate\b/.test(location.hash)) history.replaceState(null, '', '#investigate');
  if (window.VFExplorer) window.VFExplorer.markSeg();
  draw();
}
function close() {
  if (!isOpen) return;
  isOpen = false; root.hidden = true; closeAbout(); $('iv-tip').hidden = true; openBtn.setAttribute('aria-expanded', 'false');
  cancelAnimationFrame(raf); raf = 0;
  if (/[?&#]investigate\b/.test(location.hash)) history.replaceState(null, '', location.pathname + location.search);
  if (window.VFExplorer) window.VFExplorer.markSeg();
}
function showView(v) {
  close();
  if (v === 'paths') { if (window.VFPaths) window.VFPaths.open(); }
  else if (v === 'timeline') { if (window.VFTimeline) window.VFTimeline.open(); }
  else if (window.VFExplorer) window.VFExplorer.set3d(v === '3d');
}
openBtn.onclick = () => { if (!isOpen) open(); };
addEventListener('resize', () => { if (isOpen) { resize(); fit(); kick(); draw(); } });
// while open, keys belong to this view so the network view underneath does not react
addEventListener('keydown', e => {
  const typing = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || (e.target.closest && e.target.closest('#analyst-chat'));
  if (!isOpen) { if ((e.key === 'n' || e.key === 'N') && !e.metaKey && !e.ctrlKey && !typing) open(); return; }
  if (typing) { if (e.key === 'Escape') e.target.blur(); return; }
  e.stopImmediatePropagation();
  if (e.key === 'Escape') { if (selected) select(null); else close(); }
  else if (e.key === 'n' || e.key === 'N') close();
  else if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); removeEntity(selected); }
  else if (e.key === '?') $('iv-about-toggle').click();
  else if (e.key === '/') { e.preventDefault(); $('iv-seed').focus(); }
  else if (e.key === 't' || e.key === 'T') setLayout('tree');
  else if (e.key === 'r' || e.key === 'R') setLayout('radial');
  else if (e.key === 'o' || e.key === 'O') setLayout('organic');
  else if (e.key === 'l' || e.key === 'L') $('iv-elabels').click();
  else if (e.key === '2') showView('flat');
  else if (e.key === '3' && window.VFExplorer && window.VFExplorer.can3d) showView('3d');
  else if ((e.key === 'p' || e.key === 'P') && !document.getElementById('btn-paths').hidden) showView('paths');
  else if ((e.key === 'i' || e.key === 'I') && !document.getElementById('btn-timeline').hidden) showView('timeline');
}, true);
// #investigate or #investigate=<lead> opens this view, on load and when the address changes in an open tab
function fromAddress() {
  const m = /[?&#]investigate(?:=([^&]+))?/.exec(location.search + location.hash);
  if (m && !(isOpen && !m[1])) open(m[1] ? decodeURIComponent(m[1]) : null);
}
addEventListener('hashchange', fromAddress);
fromAddress();
// stats(): read-only counts for the browser smoke test (scripts/smoke): entities, links, and entities that
// ended up with no usable position
function stats() {
  let misplaced = 0; ents.forEach(n => { if (!Number.isFinite(n.tx) || !Number.isFinite(n.ty)) misplaced++; });
  return {entities: ents.size, links: links.length, misplaced, seed: seedId, ids: [...ents.keys()]};
}
window.VFInvestigate = {open, close, isOpen: () => isOpen, runPivot, undoPivot, select, setLayout, stats};
});
