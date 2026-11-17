// The Explorer data: gzip in base64 inside #vf-data (plain JSON in pages from older versions),
// unpacked once here for every view. Pages opened through VulnScope may name where a host's full
// lists can be loaded (<meta name="vulnscope-contacts">, see explorer.js loadFullLists).
//
// The browser's own gzip decoder (DecompressionStream) unpacks it in the background, so a big report
// shows "Unpacking" instead of a frozen tab; no JavaScript library is needed and the page still opens
// offline and straight from disk. The views wait for it: each one starts with
// vfWhenReady(function (D) { ... }), in page order, once the data is there (D is also window.VF_DATA).
// Unpacking stops at VF_LIMIT bytes: past that a browser tab can't hold the data as text anyway, so the
// page says the report is too big instead of crashing the tab.
(function () {
'use strict';
const VF_LIMIT = 500 * 1024 * 1024;     // unpacked bytes; V8 strings stop at ~536 million characters
const SHOW_AFTER_MS = 200;              // small reports open before the loading note would flash up
const queue = [];
let data = null;

const fail = (title, detail) => {
  window.VF_ERROR = title;
  document.documentElement.dataset.vf = 'failed';
  note(title, detail, true);
};
window.vfWhenReady = fn => { if (data) start(fn); else queue.push(fn); };

function start(fn) {
  try { fn(data); } catch (e) {     // one broken view must not stop the others; still reported as uncaught
    if (window.reportError) window.reportError(e); else setTimeout(() => { throw e; });
  }
}

function note(title, detail, error) {
  let el = document.getElementById('vf-loading');
  if (!el) {
    el = document.createElement('div');
    el.id = 'vf-loading';
    el.setAttribute('role', 'status');
    el.innerHTML = '<div class="vf-box"><div class="vf-spin" aria-hidden="true"></div><b></b><p></p></div>';
    document.body.appendChild(el);
  }
  el.classList.toggle('vf-error', !!error);
  if (error) el.setAttribute('role', 'alert');
  el.querySelector('b').textContent = title;
  el.querySelector('p').textContent = detail || '';
  el.hidden = false;
}

function base64Bytes(b64) {
  if (Uint8Array.fromBase64) return Uint8Array.fromBase64(b64);
  const s = atob(b64), bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

// gzip in base64 -> text, never more than VF_LIMIT bytes unpacked. The base64 is decoded a few MB at a
// time as the decoder asks for more, so no step holds up the page for long and the packed bytes never
// all exist at once; the text is kept per chunk and joined once.
async function gunzipText(b64) {
  const STEP = 4 << 20;               // base64 characters per piece (a multiple of 4)
  const ds = new DecompressionStream('gzip'), writer = ds.writable.getWriter(), reader = ds.readable.getReader();
  (async () => {
    for (let i = 0; i < b64.length; i += STEP) {
      await writer.ready;
      await new Promise(r => setTimeout(r));   // let the page draw between pieces
      writer.write(base64Bytes(b64.slice(i, i + STEP))).catch(() => {});
    }
    await writer.close();
  })().catch(e => { writer.abort(e).catch(() => {}); reader.cancel(e).catch(() => {}); });
  const dec = new TextDecoder('utf-8', {fatal: true}), parts = [];
  let total = 0;
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > VF_LIMIT) {
      reader.cancel().catch(() => {});
      throw Object.assign(new Error('too big'), {tooBig: true});
    }
    parts.push(dec.decode(value, {stream: true}));
  }
  parts.push(dec.decode());
  return parts.join('');
}

async function load() {
  const el = document.getElementById('vf-data');
  if (!el) throw new Error('This page has no Explorer data.');
  let text = el.textContent;
  el.textContent = '';                // the packed copy is no longer needed
  if (el.dataset.encoding === 'gzip-base64') {
    if (typeof DecompressionStream !== 'function') {
      fail('This browser is too old to open the Explorer.',
           'Open this file in Chrome or Edge 80+, Firefox 113+ or Safari 16.4+. The report itself is fine.');
      return;
    }
    const b64 = text.trim();
    text = null;
    try { text = await gunzipText(b64); } catch (e) {
      if (e && e.tooBig) {
        fail('This report is too big to open in a browser tab.',
             `Its Explorer data unpacks to more than ${VF_LIMIT / 1024 / 1024} MB. ` +
             'The reports and CSV files next to it still hold every finding; for the map, analyze a shorter ' +
             'time window or fewer sensors.');
        return;
      }
      throw new Error('damaged');
    }
  }
  try { data = JSON.parse(text); } catch (e) { throw new Error('damaged'); }
  window.VF_DATA = data;
  document.documentElement.dataset.vf = 'ready';
  const el2 = document.getElementById('vf-loading');
  if (el2) el2.hidden = true;
  while (queue.length) start(queue.shift());
}

document.documentElement.dataset.vf = 'loading';
const timer = setTimeout(() => { if (!data && !window.VF_ERROR) note('Unpacking report data…'); }, SHOW_AFTER_MS);
load().catch(() => fail('This Explorer file is damaged.',
  'Its report data could not be unpacked. Open the report again from VulnScope, or re-run Analyze.'))
  .finally(() => clearTimeout(timer));
})();
