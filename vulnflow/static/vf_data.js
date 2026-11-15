// The Explorer data: gzip in base64 inside #vf-data (plain JSON in pages from older versions),
// unpacked once here for every view. Pages opened through VulnScope may name where a host's full
// lists can be loaded (<meta name="vulnscope-contacts">, see explorer.js loadFullLists).
window.VF_DATA = (() => {
  const el = document.getElementById('vf-data');
  let text = el.textContent;
  if (el.dataset.encoding === 'gzip-base64') {
    const b64 = text.trim();
    let bytes;
    if (Uint8Array.fromBase64) bytes = Uint8Array.fromBase64(b64);
    else { const s = atob(b64); bytes = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i); }
    text = new TextDecoder().decode(fflate.gunzipSync(bytes));
  }
  el.textContent = '';        // the packed copy is no longer needed
  return JSON.parse(text);
})();
