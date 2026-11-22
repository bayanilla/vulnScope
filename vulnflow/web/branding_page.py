"""The Branding page (name before "VulnScope" and an optional logo)."""
from __future__ import annotations

import html
import os
import tempfile
import traceback

from .. import branding, multipart
from .pages import FORM_PAGE_CSS, error_html, page

MAX_BRANDING_UPLOAD = branding.MAX_LOGO_BYTES + 64 * 1024

BRANDING = """<style>{css}
.brand-preview{{display:flex;align-items:center;gap:10px;padding:12px 14px;margin:8px 0 4px;max-width:520px;
border:1px solid var(--line);border-radius:var(--radius);background:var(--bar);font-weight:800;font-size:1.1rem;letter-spacing:.02em}}
.brand-preview img{{height:36px;width:auto;max-width:180px;object-fit:contain}}
.brand-preview img.logo-small{{height:24px;max-width:96px}}
.sizes{{display:flex;gap:18px;flex-wrap:wrap}} .sizes label{{display:flex;gap:6px;align-items:center;font-weight:400;margin:0}}
.check{{display:flex;gap:8px;align-items:center;font-weight:400;margin-top:10px}}
form{{border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin:16px 0;max-width:640px}}</style>
<h1>Branding</h1>
<p>Change the name shown at the top left of the upload page, reports and Explorer, and add a small logo
to the left of it. The choice is saved on this computer and used for every new analysis; pages that were
already generated keep the branding they were made with.</p>
{error}
<div class="hint">Preview</div>
<div class="brand-preview" id="bp">{logo}<span id="bp-name">{name}</span></div>
<form method="post" action="/branding" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{csrf}">
<label for="prefix">Name before “VulnScope”</label>
<input id="prefix" name="prefix" type="text" value="{prefix}" maxlength="{max_prefix}" placeholder="e.g. Ford" autocomplete="off">
<div class="hint">Shown as “<i>name</i> VulnScope”. Leave blank to show just “VulnScope”. Up to {max_prefix} characters.</div>
<label for="logo">Logo (optional)</label>
<input id="logo" name="logo" type="file" accept="image/png,image/jpeg,image/gif,image/webp">
<div class="hint">PNG, JPEG, GIF or WebP, up to {max_kb} KB. A square or wide image with a transparent background works best.
SVG isn't accepted. Leave empty to keep the current logo.</div>
{remove}
<label>Logo size</label>
<div class="sizes" role="radiogroup" aria-label="Logo size">
<label><input type="radio" name="logo_size" value="small"{small_checked}> Small <span class="hint">(about 24 px tall)</span></label>
<label><input type="radio" name="logo_size" value="medium"{medium_checked}> Medium <span class="hint">(about 36 px tall)</span></label>
</div>
<button type="submit">Save branding</button>
</form>
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
<form method="post" action="/branding" enctype="multipart/form-data" style="border:0;padding:0;margin:0;background:none">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="reset">
<button type="submit" class="secondary">Reset to VulnScope</button></form></div>
<p><a href="/">Back to the upload page</a></p>
<script>
(function () {{
  const input = document.getElementById("prefix"), out = document.getElementById("bp-name");
  const img = document.querySelector("#bp img");
  document.querySelectorAll('input[name="logo_size"]').forEach(r => r.addEventListener("change", () => {{
    if (img) img.classList.toggle("logo-small", r.value === "small" && r.checked);
  }}));
  input.addEventListener("input", () => {{
    const v = input.value.replace(/\\s+/g, " ").trim();
    out.textContent = v ? v + " VulnScope" : "VulnScope";
  }});
}})();
</script>"""

def view(req, error: str = "", code: int = 200):
    """GET /branding (and the page again after a refused save)."""
    cur = branding.load()
    remove = ('<label class="check"><input type="checkbox" name="remove_logo" value="1"> Remove the current logo</label>'
              if cur.logo else "")
    body = BRANDING.format(css=FORM_PAGE_CSS, error=error_html(error), logo=branding.logo_img(""),
                           name=html.escape(cur.name), prefix=html.escape(cur.prefix), csrf=req.app.csrf,
                           max_prefix=branding.MAX_PREFIX, max_kb=branding.MAX_LOGO_BYTES // 1024,
                           remove=remove, small_checked=" checked" if cur.logo_size == "small" else "",
                           medium_checked=" checked" if cur.logo_size != "small" else "")
    req.send(code, page("Branding", body), headers={"Cache-Control": "no-store"})


def save(req):
    """POST /branding: the name prefix and logo. The logo is checked by content, never trusted by name."""
    length = req.length()
    if length <= 0 or length > MAX_BRANDING_UPLOAD:
        req.close_connection = True
        return view(req, f"Logos must be {branding.MAX_LOGO_BYTES // 1024} KB or smaller.", 413)
    with tempfile.TemporaryDirectory(prefix="vulnscope-brand-") as tmp:
        try:
            fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""),
                                            tmp, lambda i, _name: f"logo{i}")
        except multipart.MultipartError as exc:
            req.close_connection = True
            return view(req, str(exc), 400)
        if not req.app.csrf_ok(fields.get("csrf", "")):
            return req.send_text(403, "Forbidden")
        logo = None
        for field, path in parts:
            if field == "logo":
                if os.path.getsize(path) > branding.MAX_LOGO_BYTES:
                    return view(req, f"Logos must be {branding.MAX_LOGO_BYTES // 1024} KB or smaller.", 400)
                with open(path, "rb") as fh:
                    logo = fh.read()
    try:
        if fields.get("action") == "reset":
            branding.reset()
        else:
            branding.update(fields.get("prefix", ""), logo, remove_logo=fields.get("remove_logo") == "1",
                            logo_size=fields.get("logo_size") or None)
    except branding.BrandingError as exc:
        return view(req, str(exc), 400)
    except OSError:
        traceback.print_exc()
        return view(req, "The branding couldn't be saved; see the server console for details.", 500)
    req.redirect("/branding")
