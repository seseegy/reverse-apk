/* Tab Build (Tahap 5): polling ringan status build. Patuh CSP (script-src 'self'): tanpa inline, tanpa eval.
 * Halaman memasang atribut data-build-poll (URL JSON status) dan data-build-status (status saat dirender) hanya untuk build yang berubah sendiri
 * (disetujui/antre/membangun/menandatangani). Status berubah -> muat ulang halaman (server merender ulang semuanya, termasuk tombol unduh). */
(function () {
  "use strict";
  var root = document.querySelector("[data-build-poll]");
  if (!root || typeof fetch !== "function") return;
  var url = root.getAttribute("data-build-poll");
  var current = root.getAttribute("data-build-status");
  var failures = 0;
  var timer = null;

  function schedule(ms) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(tick, ms);
  }

  function tick() {
    if (document.hidden) { schedule(5000); return; }
    fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { window.location.href = "/login"; return null; }
        if (!r.ok) throw new Error("status " + r.status);
        return r.json();
      })
      .then(function (d) {
        if (!d) return;
        failures = 0;
        if (d.status !== current || d.final) { window.location.reload(); return; }
        schedule(3000);
      })
      .catch(function () {
        failures += 1;
        if (failures < 10) schedule(Math.min(30000, 3000 * failures));
      });
  }

  document.addEventListener("visibilitychange", function () { if (!document.hidden) schedule(500); });
  schedule(3000);
})();
