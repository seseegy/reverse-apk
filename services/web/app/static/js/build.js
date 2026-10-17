/* Tab Build: polling status build. Patuh CSP (script-src 'self', connect-src 'self'): tanpa skrip inline, tanpa eval, tanpa penyisipan HTML mentah.
 * Halaman memasang data-build-poll (URL JSON /status) dan data-build-status (status saat dirender) hanya untuk build yang berubah sendiri
 * (disetujui/antre/membangun/menandatangani).
 *  - Halaman DETAIL juga memasang data-build-live (URL /live: JSON kecil berisi fragmen HTML yang dirender server). Selama status belum final
 *    hanya slot [data-live-slot] (badge dan kalimat tahap) yang diganti di tempat; gulir, <details>, seleksi teks, dan fokus tidak tersentuh.
 *  - Halaman DAFTAR memakai /status: status berubah -> satu reload penuh (alert, badge baris, dan tombol Ajukan bergantung status).
 *  - Status final -> polling berhenti lalu SATU reload penuh agar kartu hasil dan tombol unduh dirender server (gulir dipulihkan).
 * Mesin keadaan: idle (menunggu) -> loading (fetch) -> idle | backoff (gagal) ; paused (tab tersembunyi) ; final/stopped (berhenti).
 * Hanya satu pewaktu (timer): dipakai bergantian untuk jeda antar-poll dan untuk batas waktu fetch (tidak pernah bersamaan). */
(function () {
  "use strict";
  var root = document.querySelector("[data-build-poll]");
  if (!root || typeof fetch !== "function") return;
  var liveUrl = root.getAttribute("data-build-live");
  var url = liveUrl || root.getAttribute("data-build-poll");
  var current = root.getAttribute("data-build-status");
  var INTERVAL = 3000;      // jeda normal
  var MAX_DELAY = 30000;    // batas atas backoff
  var TIMEOUT = 10000;      // batas waktu satu fetch
  var CALM_AFTER = 3;       // gagal beruntun sebelum pesan tenang muncul
  var state = "idle";
  var timer = null;
  var ctrl = null;
  var seq = 0;
  var failures = 0;
  var lastFragment = null;
  var busyEl = root.querySelector("[data-live-busy]");
  var updatedEl = root.querySelector("[data-live-updated]");
  var noteEl = root.querySelector("[data-live-note]");
  var announceEl = root.querySelector("[data-live-announce]");
  var KEY = "rv-build-scroll:" + window.location.pathname;

  // Muat ulang penuh (hanya saat final / daftar berubah) tidak boleh melempar pembaca ke atas halaman: simpan lalu pulihkan posisi gulir.
  try {
    var saved = window.sessionStorage.getItem(KEY);
    if (saved !== null) { window.sessionStorage.removeItem(KEY); window.scrollTo(0, parseInt(saved, 10) || 0); }
  } catch (e) { /* penyimpanan dinonaktifkan: abaikan */ }

  function reloadFull() {
    state = "final";
    stopTimer();
    try { window.sessionStorage.setItem(KEY, String(window.pageYOffset || 0)); } catch (e) { /* abaikan */ }
    window.location.reload();
  }

  function schedule(ms, fn) {
    clearTimeout(timer);
    timer = setTimeout(fn, ms);
  }

  function stopTimer() {
    clearTimeout(timer);
    timer = null;
  }

  function abortFetch() {
    seq += 1;
    if (ctrl) { try { ctrl.abort(); } catch (e) { /* abaikan */ } }
    ctrl = null;
  }

  function setBusy(on) {
    if (busyEl) busyEl.classList.toggle("is-busy", on);
  }

  function setNote(text) {
    if (noteEl && noteEl.textContent !== text) noteEl.textContent = text;
  }

  function announce(text) {
    if (announceEl) announceEl.textContent = text;
  }

  function pad(n) { return (n < 10 ? "0" : "") + n; }

  function stamp() {
    if (!updatedEl) return;
    var d = new Date();
    updatedEl.textContent = "Terakhir diperbarui " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  // Ganti isi satu slot hanya bila berbeda (isEqualNode): isi yang sama tidak disentuh sehingga seleksi/fokus aman.
  function swapSlot(slot, src) {
    var fresh = Array.prototype.slice.call(document.importNode(src, true).childNodes);
    var old = Array.prototype.slice.call(slot.childNodes);
    var same = fresh.length === old.length && fresh.every(function (n, i) { return n.isEqualNode(old[i]); });
    if (same) return;
    fresh.forEach(function (n) {
      if (n.querySelectorAll) Array.prototype.forEach.call(n.querySelectorAll("script"), function (s) { s.remove(); });
    });
    slot.replaceChildren.apply(slot, fresh);
  }

  function applyFragment(d) {
    if (typeof d.fragment !== "string" || d.fragment === lastFragment) return;
    lastFragment = d.fragment;
    var doc = new DOMParser().parseFromString(d.fragment, "text/html");
    Array.prototype.forEach.call(doc.querySelectorAll("[data-live-slot]"), function (src) {
      var slot = root.querySelector('[data-live-slot="' + src.getAttribute("data-live-slot") + '"]');
      if (slot) swapSlot(slot, src);
    });
  }

  // Elemen statis (form aksi) tidak pernah diganti: hanya ditampilkan/disembunyikan atau dinonaktifkan.
  function applyControls(d) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-live-show]"), function (el) {
      el.hidden = (" " + el.getAttribute("data-live-show") + " ").indexOf(" " + d.status + " ") < 0;
    });
    Array.prototype.forEach.call(root.querySelectorAll("[data-live-cancel]"), function (el) { el.disabled = !!d.cancel_requested; });
  }

  function ok(d) {
    failures = 0;
    setNote("");
    setBusy(false);
    stamp();
    if (d.final) { reloadFull(); return; }
    if (liveUrl) {
      applyFragment(d);
      applyControls(d);
      if (d.status !== current) { current = d.status; announce("Status build: " + d.label); }
    } else if (d.status !== current) {
      reloadFull();
      return;
    }
    state = "idle";
    schedule(INTERVAL, poll);
  }

  function fail() {
    failures += 1;
    state = "backoff";
    setBusy(false);
    if (failures >= CALM_AFTER) setNote("Belum bisa memeriksa status; mencoba lagi otomatis. Build tetap berjalan di server.");
    var delay = Math.min(MAX_DELAY, INTERVAL * Math.pow(2, failures - 1));
    schedule(delay + Math.floor(Math.random() * 400), poll);
  }

  function poll() {
    if (state === "final" || state === "stopped" || state === "loading") return;
    if (document.hidden) { pause(); return; }
    stopTimer();
    state = "loading";
    setBusy(true);
    seq += 1;
    var mine = seq;
    var opts = { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } };
    if (typeof AbortController === "function") { ctrl = new AbortController(); opts.signal = ctrl.signal; }
    var local = ctrl;
    schedule(TIMEOUT, function () { if (local) local.abort(); else if (mine === seq) { seq += 1; fail(); } });
    fetch(url, opts)
      .then(function (r) {
        if (mine !== seq) return null;
        if (r.status === 401) { window.location.href = "/login"; return null; }
        if (r.status === 404) { state = "stopped"; stopTimer(); setBusy(false); setNote("Build tidak ditemukan. Muat ulang halaman."); return null; }
        if (!r.ok) throw new Error("status " + r.status);
        return r.json();
      })
      .then(function (d) {
        if (!d || mine !== seq) return;
        ok(d);
      })
      .catch(function () {
        if (mine !== seq) return;
        fail();
      });
  }

  function pause() {
    if (state === "final" || state === "stopped") return;
    state = "paused";
    stopTimer();
    abortFetch();
    setBusy(false);
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { pause(); return; }
    if (state === "paused") { state = "idle"; poll(); }
  });
  window.addEventListener("pagehide", function () { stopTimer(); abortFetch(); });

  if (document.hidden) { state = "paused"; } else { schedule(INTERVAL, poll); }
})();
