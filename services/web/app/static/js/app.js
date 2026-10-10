// reverse-apk — JS minimal (tanpa inline script agar CSP tetap ketat).
// Semua teks dari server/APK dimasukkan lewat textContent / setAttribute, tidak pernah innerHTML.
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function fmtBytes(n) {
    var units = ["B", "KB", "MB", "GB"], i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
  }

  function fmtDuration(sec) {
    sec = Math.max(0, Math.floor(sec));
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (h) return h + " j " + m + " m";
    if (m) return m + " m " + s + " d";
    return s + " d";
  }

  // ------------------------------------------------------------------ login & umum

  // Tampilkan/sembunyikan password. Nama aksesibel tetap; status lewat aria-pressed.
  $all("[data-toggle-password]").forEach(function (btn) {
    var input = document.getElementById(btn.getAttribute("aria-controls"));
    if (!input) return;
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
    });
  });

  // Konfirmasi aksi berisiko (hapus / analisis ulang). Harus terdaftar SEBELUM data-submit-lock.
  $all("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var msg = form.getAttribute("data-confirm");
      if (msg && !window.confirm(msg)) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    });
  });

  // Cegah kirim ganda dan beri umpan balik saat form dikirim.
  $all("form[data-submit-lock]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      var btn = form.querySelector("button[type=submit]");
      if (!btn) return;
      var label = btn.querySelector("span") || btn;
      label.textContent = "Memproses…";
      // Ditunda: menonaktifkan tombol sinkron dapat membatalkan pengiriman di beberapa browser.
      setTimeout(function () { btn.disabled = true; }, 0);
    });
  });

  // Jika halaman dipulihkan dari tombol Back (bfcache), muat ulang agar state tombol & token segar.
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) location.reload();
  });

  // Uji antrean sedang berjalan: muat ulang beberapa kali sampai hasilnya ada.
  if ($("[data-poll]")) {
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      if (tries > 8) { clearInterval(timer); return; }
      location.reload();
    }, 2000);
  }

  // Waktu server (UTC) -> zona waktu browser. Teks UTC tetap sebagai cadangan tanpa JS.
  $all("time[data-local]").forEach(function (el) {
    var d = new Date(el.getAttribute("datetime"));
    if (!isNaN(d)) {
      el.textContent = d.toLocaleString();
      el.title = el.getAttribute("datetime");
    }
  });
  function localizeLogTime(el) {
    var d = new Date(parseFloat(el.getAttribute("data-ts")) * 1000);
    if (!isNaN(d)) el.textContent = d.toLocaleTimeString();
  }
  $all("time[data-ts]").forEach(localizeLogTime);

  // ------------------------------------------------------------------ upload

  var uploadForm = document.getElementById("upload-form");
  if (uploadForm) initUpload(uploadForm);

  function initUpload(form) {
    var csrf = form.getAttribute("data-csrf");
    var maxMb = Number(form.getAttribute("data-max-mb")) || 200;
    var fileInput = document.getElementById("file");
    var dropzone = document.getElementById("dropzone");
    var fileInfo = document.getElementById("file-info");
    var authorized = document.getElementById("authorized");
    var deobf = document.getElementById("opt-deobf");
    var submitBtn = document.getElementById("upload-submit");
    var summary = document.getElementById("upload-errors");
    var summaryList = document.getElementById("upload-errors-list");
    var progressBox = document.getElementById("upload-progress-box");
    var progress = document.getElementById("upload-progress");
    var statusEl = document.getElementById("upload-status");
    var dupBox = document.getElementById("dup-box");
    var dupName = document.getElementById("dup-name");
    var dupOpen = document.getElementById("dup-open");
    var dupRetry = document.getElementById("dup-retry");
    var dupForm = document.getElementById("dup-retry-form");
    var fieldErrors = {
      file: document.getElementById("file-error"),
      authorized: document.getElementById("authorized-error")
    };
    var chosen = null;
    var uploading = false;
    var dupAnalysisId = null;

    function clearErrors() {
      summary.hidden = true;
      while (summaryList.firstChild) summaryList.removeChild(summaryList.firstChild);
      Object.keys(fieldErrors).forEach(function (k) {
        fieldErrors[k].hidden = true;
        fieldErrors[k].textContent = "";
      });
      fileInput.removeAttribute("aria-invalid");
      authorized.removeAttribute("aria-invalid");
      dropzone.classList.remove("has-error");
    }

    // errors: [{field: "file"|"authorized"|null, message}]
    function showErrors(errors) {
      clearErrors();
      errors.forEach(function (err) {
        var li = document.createElement("li");
        if (err.field && fieldErrors[err.field]) {
          var a = document.createElement("a");
          a.href = "#" + (err.field === "file" ? "file" : "authorized");
          a.textContent = err.message;
          a.addEventListener("click", function (ev) {
            ev.preventDefault();
            (err.field === "file" ? fileInput : authorized).focus();
          });
          li.appendChild(a);
          fieldErrors[err.field].textContent = err.message;
          fieldErrors[err.field].hidden = false;
          (err.field === "file" ? fileInput : authorized).setAttribute("aria-invalid", "true");
          if (err.field === "file") dropzone.classList.add("has-error");
        } else {
          li.textContent = err.message;
        }
        summaryList.appendChild(li);
      });
      summary.hidden = false;
      summary.focus();
    }

    function setFile(f) {
      chosen = f || null;
      fileInfo.textContent = chosen ? chosen.name + " · " + fmtBytes(chosen.size) : "";
      dupBox.hidden = true;
      clearErrors();
    }

    function validate() {
      var errors = [];
      if (!chosen) {
        errors.push({ field: "file", message: "Pilih berkas APK terlebih dahulu." });
      } else if (!/\.apk$/i.test(chosen.name)) {
        errors.push({ field: "file", message: "Hanya berkas .apk yang didukung (XAPK/APKS belum)." });
      } else if (chosen.size === 0) {
        errors.push({ field: "file", message: "Berkas kosong." });
      } else if (chosen.size > maxMb * 1024 * 1024) {
        errors.push({ field: "file", message: "Berkas " + fmtBytes(chosen.size) + " melebihi batas " + maxMb + " MB." });
      }
      if (!authorized.checked) {
        errors.push({ field: "authorized", message: "Centang pernyataan bahwa Anda berwenang menganalisis berkas ini." });
      }
      return errors;
    }

    fileInput.addEventListener("change", function () { setFile(fileInput.files && fileInput.files[0]); });

    ["dragenter", "dragover"].forEach(function (name) {
      dropzone.addEventListener(name, function (e) {
        e.preventDefault();
        dropzone.classList.add("is-over");
      });
    });
    ["dragleave", "dragend"].forEach(function (name) {
      dropzone.addEventListener(name, function () { dropzone.classList.remove("is-over"); });
    });
    dropzone.addEventListener("drop", function (e) {
      e.preventDefault();
      dropzone.classList.remove("is-over");
      var files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length) {
        try { fileInput.files = files; } catch (_) { /* browser lama: pakai referensi langsung */ }
        setFile(files[0]);
      }
    });
    // Jangan biarkan browser membuka berkas yang dijatuhkan di luar dropzone.
    ["dragover", "drop"].forEach(function (name) {
      window.addEventListener(name, function (e) { if (!dropzone.contains(e.target)) e.preventDefault(); });
    });

    function setBusy(busy) {
      uploading = busy;
      submitBtn.disabled = busy;
      fileInput.disabled = busy;
      progressBox.hidden = !busy && !progress.value;
    }

    function failMessage(xhr) {
      var data = null;
      try { data = JSON.parse(xhr.responseText); } catch (_) { /* bukan JSON (mis. galat proxy) */ }
      if (data && data.error) return data.error;
      if (xhr.status === 413) return "Berkas melebihi batas ukuran server.";
      if (xhr.status === 401) return "Sesi berakhir. Muat ulang halaman lalu masuk lagi.";
      return "Upload gagal (HTTP " + xhr.status + ").";
    }

    function upload(file) {
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/uploads");
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.setRequestHeader("X-Upload-Name", encodeURIComponent(file.name.slice(-200)));
      xhr.setRequestHeader("X-Authorized", authorized.checked ? "1" : "0");
      xhr.setRequestHeader("X-Opt-Deobf", deobf && deobf.checked ? "1" : "0");

      progress.value = 0;
      progressBox.hidden = false;
      statusEl.textContent = "Memulai upload…";
      setBusy(true);

      xhr.upload.onprogress = function (e) {
        if (!e.lengthComputable) return;
        var pct = Math.floor((e.loaded / e.total) * 100);
        progress.value = pct;
        statusEl.textContent = pct < 100
          ? "Mengunggah " + pct + "% (" + fmtBytes(e.loaded) + " dari " + fmtBytes(e.total) + ")…"
          : "Upload selesai. Memvalidasi dan menyimpan…";
      };
      xhr.onload = function () {
        setBusy(false);
        var data = null;
        try { data = JSON.parse(xhr.responseText); } catch (_) { /* ditangani di bawah */ }
        if (xhr.status === 201 && data && typeof data.redirect === "string" && data.redirect.indexOf("/analyses/") === 0) {
          statusEl.textContent = "Berhasil. Membuka halaman analisis…";
          location.href = data.redirect;
          return;
        }
        if (xhr.status === 200 && data && data.duplicate) {
          progressBox.hidden = true;
          dupAnalysisId = data.analysis_id;
          dupName.textContent = data.name ? "(" + data.name + ")" : "";
          dupOpen.href = data.analysis_id ? "/analyses/" + data.analysis_id : "/";
          dupRetry.hidden = !data.analysis_id;
          dupBox.hidden = false;
          dupBox.focus();
          return;
        }
        progressBox.hidden = true;
        showErrors([{ field: null, message: failMessage(xhr) }]);
      };
      xhr.onerror = function () {
        setBusy(false);
        progressBox.hidden = true;
        showErrors([{ field: null, message: "Koneksi terputus saat upload. Periksa jaringan lalu coba lagi." }]);
      };
      xhr.ontimeout = xhr.onerror;
      xhr.send(file);
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (uploading) return;
      var errors = validate();
      if (errors.length) { showErrors(errors); return; }
      clearErrors();
      dupBox.hidden = true;
      upload(chosen);
    });

    dupRetry.addEventListener("click", function () {
      if (!dupAnalysisId) return;
      dupForm.setAttribute("action", "/analyses/" + encodeURIComponent(dupAnalysisId) + "/retry");
      dupRetry.disabled = true;
      dupForm.submit();
    });
  }

  // ------------------------------------------------------------------ status live (SSE + cadangan polling)

  var liveRoot = $("[data-live]");
  if (liveRoot) initLive(liveRoot);

  function initLive(root) {
    var id = root.getAttribute("data-analysis-id");
    var terminal = root.getAttribute("data-terminal") === "true";
    var stepsEl = $("[data-steps]", root);
    var summaryEl = $("[data-summary]", root);
    var logEl = $("[data-log]", root);
    var logEmpty = $("[data-log-empty]", root);
    var errorBox = $("[data-error]", root);
    var errorText = $("[data-error-text]", root);
    var elapsedEl = $("[data-elapsed]", root);
    var offset = (parseFloat(root.getAttribute("data-server-now")) || 0) - Date.now() / 1000;
    // Status saat halaman dirender server. Bila snapshot berikutnya berbeda, halaman dimuat ulang.
    var initialStatus = root.getAttribute("data-status");

    function nowServer() { return Date.now() / 1000 + offset; }

    function renderElapsed() {
      if (!elapsedEl) return;
      var started = parseFloat(root.getAttribute("data-started"));
      var finished = parseFloat(root.getAttribute("data-finished"));
      if (!started) { elapsedEl.textContent = "menunggu antrean"; return; }
      elapsedEl.textContent = (finished ? "durasi " : "berjalan ") + fmtDuration((finished || nowServer()) - started);
    }
    renderElapsed();
    if (terminal) return;

    function applySteps(steps) {
      steps.forEach(function (s) {
        var li = stepsEl && stepsEl.querySelector('[data-key="' + s.key + '"]');
        if (!li) return;
        li.setAttribute("data-state", s.state);
        var use = li.querySelector("use");
        if (use) use.setAttribute("href", "#st-" + s.state);
        var st = li.querySelector(".step-state");
        if (st) st.textContent = s.state_label || s.state;
        var d = li.querySelector("[data-detail]");
        if (d) d.textContent = s.detail || "";
      });
    }

    function applyLogs(logs) {
      var nearBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
      $all("li.log-line", logEl).forEach(function (li) { logEl.removeChild(li); });
      logs.forEach(function (l) {
        var li = document.createElement("li");
        li.className = "log-line log-" + (l.level === "error" || l.level === "warn" ? l.level : "info");
        var t = document.createElement("time");
        t.className = "log-time";
        t.setAttribute("data-ts", String(l.ts));
        localizeLogTime(t);
        var lv = document.createElement("span");
        lv.className = "log-level";
        lv.textContent = String(l.level || "info").toUpperCase();
        var msg = document.createElement("span");
        msg.className = "log-msg";
        msg.textContent = (l.stage ? "[" + l.stage + "] " : "") + l.message;
        li.appendChild(t); li.appendChild(lv); li.appendChild(msg);
        logEl.insertBefore(li, logEmpty);
      });
      if (logEmpty) logEmpty.hidden = logs.length > 0;
      if (nearBottom) logEl.scrollTop = logEl.scrollHeight;
    }

    function apply(snap) {
      if (snap.server_now) offset = snap.server_now - Date.now() / 1000;
      root.setAttribute("data-started", snap.started_at || "");
      root.setAttribute("data-finished", snap.finished_at || "");
      // Perubahan status (queued -> running -> selesai) mengubah badge, tombol aksi, artefak, dan manifest:
      // render ulang dari server agar semuanya konsisten.
      if (snap.status !== initialStatus) {
        stop();
        setTimeout(function () { location.reload(); }, 300);
        return;
      }
      if (summaryEl) summaryEl.textContent = snap.summary || "";
      if (stepsEl && snap.steps) applySteps(snap.steps);
      if (logEl && snap.logs) applyLogs(snap.logs);
      if (errorBox) {
        errorBox.hidden = !snap.error;
        if (errorText) errorText.textContent = snap.error || "";
      }
      renderElapsed();
    }

    var es = null, pollTimer = null, tick = setInterval(renderElapsed, 1000), errorsInRow = 0;

    function stop() {
      if (es) { es.close(); es = null; }
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      clearInterval(tick);
    }

    function poll() {
      fetch("/analyses/" + encodeURIComponent(id) + "/status", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) {
          if (r.status === 401) { location.reload(); return null; }
          return r.ok ? r.json() : null;
        })
        .then(function (snap) { if (snap) apply(snap); })
        .catch(function () { /* jaringan putus sesaat; coba lagi pada putaran berikut */ });
    }

    function startPolling() {
      if (pollTimer) return;
      if (es) { es.close(); es = null; }
      poll();
      pollTimer = setInterval(poll, 2000);
    }

    function startSSE() {
      if (!window.EventSource) { startPolling(); return; }
      es = new EventSource("/analyses/" + encodeURIComponent(id) + "/events");
      es.onmessage = function (ev) {
        errorsInRow = 0;
        try { apply(JSON.parse(ev.data)); } catch (_) { /* abaikan payload rusak */ }
      };
      es.addEventListener("end", function () { /* status akhir sudah ditangani apply() lewat reload */ });
      es.addEventListener("gone", function () { stop(); location.href = "/?notice=not_found"; });
      es.onerror = function () {
        errorsInRow += 1;
        // Browser menyambung ulang otomatis; bila terus gagal (proxy memblokir SSE), pakai polling.
        if (errorsInRow >= 3 || (es && es.readyState === 2)) startPolling();
      };
    }

    startSSE();
  }
})();
