// Upload page: send the report details with whichever form is submitted, and relabel the folder
// form's button "Open report" when the folder is a completed report's output folder, or "Analyze N
// sites and compare" when it has a sites list (sites.csv).
(function () {
  const cfg = JSON.parse(document.getElementById("vs-page").textContent);
  const $ = id => document.getElementById(id);
  document.querySelectorAll('form[action="/analyze"],form[action="/analyze-folder"]').forEach(f => f.addEventListener("submit", () => {
    // the report details sit outside both forms
    ["report_name", "report_network", "report_description"].forEach(n => {
      let h = f.querySelector('input[type=hidden][name="' + n + '"]');
      if (!h) { h = document.createElement("input"); h.type = "hidden"; h.name = n; f.prepend(h); }
      h.value = $(n).value;
    });
  }));
  const path = $("path"), btn = $("analyze-folder"), form = path.form, msg = $("sites-msg");
  const analyzing = {busy: form.dataset.busy, hint: form.dataset.busyHint};
  let kindSeq = 0, kindTimer = null;
  async function checkKind() {
    const p = path.value.trim(), seq = ++kindSeq;
    let report = false, sites = 0;
    if (p) {
      try {
        const r = await fetch("/folder-kind", {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({csrf: cfg.csrf, path: p})});
        const kind = await r.json();
        report = !!kind.report;
        sites = kind.sites | 0;
      } catch (e) {}
    }
    if (seq !== kindSeq) return;
    btn.textContent = report ? "Open report" : sites > 0 ? `Analyze ${sites} site${sites > 1 ? "s" : ""} and compare`
                                                         : "Analyze folder";
    if (report) btn.dataset.report = "1"; else delete btn.dataset.report;
    form.dataset.busy = report ? "Opening report…" : sites > 0 ? `Analyzing ${sites} site${sites > 1 ? "s" : ""}…`
                                                               : analyzing.busy;
    form.dataset.busyHint = report ? "" : sites > 0
      ? "Each site gets its own report, then they're compared. The comparison opens here when it's ready."
      : analyzing.hint;
    msg.textContent = report ? "" : sites > 0
      ? `This folder has a sites list (sites.csv): ${sites} site report${sites > 1 ? "s" : ""}, then a comparison of them. Each site's name and network come from the list, not from Report details.`
      : sites < 0 ? "This folder's sites list (sites.csv) has a problem; Analyze folder shows what it is." : "";
  }
  path.addEventListener("input", () => { clearTimeout(kindTimer); kindTimer = setTimeout(checkKind, 300); });
  path.addEventListener("change", checkKind);
  checkKind();
})();
