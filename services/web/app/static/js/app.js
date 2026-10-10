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

  // ------------------------------------------------------------------ tampilkan nilai secret (tercatat di audit log)

  $all("[data-reveal]").forEach(function (btn) {
    var root = document.querySelector("[data-findings]");
    var csrf = root ? root.getAttribute("data-csrf") : "";
    var out = btn.parentNode.querySelector("[data-secret]");
    var label = btn.querySelector("span");
    btn.addEventListener("click", function () {
      if (btn.getAttribute("aria-pressed") === "true") {          // sembunyikan lagi
        out.hidden = true; out.textContent = "";
        btn.setAttribute("aria-pressed", "false"); label.textContent = "Tampilkan nilai";
        return;
      }
      btn.disabled = true;
      fetch(btn.getAttribute("data-url"), { method: "POST", credentials: "same-origin",
                                           headers: { "X-CSRF-Token": csrf } })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          btn.disabled = false;
          if (!res.ok) { out.hidden = false; out.textContent = res.d.error || "Gagal menampilkan nilai."; return; }
          out.textContent = res.d.value;                          // textContent: nilai dari APK tak pernah jadi HTML
          out.hidden = false;
          btn.setAttribute("aria-pressed", "true"); label.textContent = "Sembunyikan";
        })
        .catch(function () { btn.disabled = false; out.hidden = false; out.textContent = "Koneksi gagal."; });
    });
  });

  // ------------------------------------------------------------------ penjelajah kode

  var codeRoot = $("[data-code]");
  if (codeRoot) initCode(codeRoot);

  var JAVA_KW = new Set(("abstract assert boolean break byte case catch char class const continue default do double else enum extends " +
    "final finally float for goto if implements import instanceof int interface long native new package private protected public " +
    "return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null var record").split(" "));
  var TOKEN_RE = {
    java: /\/\/[^\n]*|\/\*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d[\w.]*\b|@\w+|\b[A-Za-z_$][\w$]*\b/g,
    smali: /#[^\n]*|"(?:[^"\\]|\\.)*"|\.[a-z\-]+|\b[vp]\d+\b|L[\w\/$]+;|\b0x[0-9a-fA-F]+\b|\b(?:invoke|const|move|return|new|if|goto|iget|iput|sget|sput|check|aget|aput|add|sub|mul|div|rem|and|or|xor|shl|shr|neg|not|cmp|throw|nop|monitor|fill|array|instance|packed|sparse)[\w\-\/]*/g,
    xml: /<!--|-->|<\/?[\w:.\-]+|\/?>|[\w:.\-]+(?==)|"[^"]*"|'[^']*'/g
  };

  function langOf(path) {
    if (/\.smali$/.test(path)) return "smali";
    if (/\.(xml|html|svg)$/.test(path) || /AndroidManifest/.test(path)) return "xml";
    if (/\.java$/.test(path)) return "java";
    return "plain";
  }

  // Penyorot per baris. `state.block` melacak komentar blok /* ... */ lintas baris.
  function highlightLine(text, lang, state) {
    var frag = document.createDocumentFragment();
    function put(str, cls) {
      if (!str) return;
      if (!cls) { frag.appendChild(document.createTextNode(str)); return; }
      var sp = document.createElement("span"); sp.className = cls; sp.textContent = str; frag.appendChild(sp);
    }
    if (lang === "plain" || text.length > 2000) { put(text); return frag; }
    var i = 0;
    if (state.block) {
      var endMark = lang === "xml" ? "-->" : "*/";
      var end = text.indexOf(endMark);
      if (end < 0) { put(text, "tk-c"); return frag; }
      put(text.slice(0, end + endMark.length), "tk-c"); i = end + endMark.length; state.block = false;
    }
    var re = new RegExp(TOKEN_RE[lang].source, "g"); re.lastIndex = i;
    var m;
    while ((m = re.exec(text)) !== null) {
      put(text.slice(i, m.index)); i = m.index;
      var t = m[0], cls = "";
      if (lang === "java") {
        if (t === "/*") { var e2 = text.indexOf("*/", m.index + 2); if (e2 < 0) { put(text.slice(i), "tk-c"); state.block = true; return frag; } t = text.slice(m.index, e2 + 2); re.lastIndex = e2 + 2; cls = "tk-c"; }
        else if (t[0] === "/") cls = "tk-c";
        else if (t[0] === '"' || t[0] === "'") cls = "tk-s";
        else if (t[0] === "@") cls = "tk-a";
        else if (/^\d/.test(t)) cls = "tk-n";
        else if (JAVA_KW.has(t)) cls = "tk-k";
        else if (/^[A-Z]/.test(t)) cls = "tk-t";
      } else if (lang === "smali") {
        if (t[0] === "#") cls = "tk-c"; else if (t[0] === '"') cls = "tk-s"; else if (t[0] === ".") cls = "tk-k";
        else if (/^[vp]\d+$/.test(t)) cls = "tk-n"; else if (t[0] === "L") cls = "tk-t"; else if (/^0x/.test(t)) cls = "tk-n"; else cls = "tk-k";
      } else {
        if (t === "<!--") { var e3 = text.indexOf("-->", m.index + 4); if (e3 < 0) { put(text.slice(i), "tk-c"); state.block = true; return frag; } t = text.slice(m.index, e3 + 3); re.lastIndex = e3 + 3; cls = "tk-c"; }
        else if (t[0] === "<" || t[0] === "/" || t[0] === ">") cls = "tk-k";
        else if (t[0] === '"' || t[0] === "'") cls = "tk-s"; else cls = "tk-a";
      }
      put(t, cls); i = m.index + t.length;
    }
    put(text.slice(i));
    return frag;
  }

  function initCode(root) {
    var id = root.getAttribute("data-analysis-id");
    var base = "/analyses/" + encodeURIComponent(id) + "/code";
    var tree = $("[data-tree]", root), view = $("[data-view]", root), empty = $("[data-empty]", root);
    var pathEl = $("[data-viewer-path]", root), metaEl = $("[data-meta]", root);
    var rootSel = $("[data-root]", root);
    var results = $("[data-results]", root), resList = $("[data-results-list]", root), resStatus = $("[data-results-status]", root);
    var searchForm = $("[data-code-search]", root);
    var qInput = searchForm.querySelector("input[type=search]"), appOnly = $("#cs-app", root);
    var state = { root: "java", path: "", line: 0, terms: [], token: 0 };

    function api(kind, params) {
      var q = Object.keys(params).map(function (k) { return k + "=" + encodeURIComponent(params[k]); }).join("&");
      return fetch(base + "/" + kind + "?" + q, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
        if (r.status === 401) { location.reload(); return Promise.reject(new Error("auth")); }
        return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || "Gagal"); return d; });
      });
    }
    function setUrl() {
      var u = "?root=" + encodeURIComponent(state.root) + (state.path ? "&path=" + encodeURIComponent(state.path) : "") +
              (state.line ? "&line=" + state.line : "");
      history.replaceState(null, "", u);
    }

    // ---------------- pohon (lazy)
    function nodeLabel(e) { return e.name; }
    function renderDir(container, data, depth) {
      var ul = document.createElement("ul"); ul.className = "tree-list"; ul.setAttribute("role", "group");
      data.entries.forEach(function (e) {
        var li = document.createElement("li"); li.setAttribute("role", "none");
        if (e.type === "dir") {
          var b = document.createElement("button"); b.type = "button"; b.className = "tree-item tree-dir";
          b.setAttribute("role", "treeitem"); b.setAttribute("aria-expanded", "false"); b.setAttribute("data-path", e.path);
          var ch = document.createElement("span"); ch.className = "tree-caret"; ch.setAttribute("aria-hidden", "true"); ch.textContent = "▸";
          var nm = document.createElement("span"); nm.className = "tree-name mono"; nm.textContent = nodeLabel(e);
          b.appendChild(ch); b.appendChild(nm); li.appendChild(b);
          b.addEventListener("click", function () { toggleDir(b, li); });
        } else {
          var a = document.createElement("button"); a.type = "button"; a.className = "tree-item tree-file";
          a.setAttribute("role", "treeitem"); a.setAttribute("data-path", e.path);
          var nm2 = document.createElement("span"); nm2.className = "tree-name mono"; nm2.textContent = e.name;
          a.appendChild(nm2); li.appendChild(a);
          a.addEventListener("click", function () { openFile(e.path, 0, []); });
        }
        ul.appendChild(li);
      });
      if (data.truncated) { var n = document.createElement("li"); n.className = "muted hint tree-note"; n.textContent = "Daftar dipotong (terlalu banyak entri)."; ul.appendChild(n); }
      container.appendChild(ul);
    }
    function toggleDir(btn, li) {
      var open = btn.getAttribute("aria-expanded") === "true";
      var sub = li.querySelector(":scope > ul");
      if (open) { btn.setAttribute("aria-expanded", "false"); btn.querySelector(".tree-caret").textContent = "▸"; if (sub) sub.hidden = true; return Promise.resolve(); }
      btn.setAttribute("aria-expanded", "true"); btn.querySelector(".tree-caret").textContent = "▾";
      if (sub) { sub.hidden = false; return Promise.resolve(); }
      return api("tree", { root: state.root, path: btn.getAttribute("data-path") }).then(function (d) { renderDir(li, d); })
        .catch(function () { var n = document.createElement("div"); n.className = "muted hint"; n.textContent = "Gagal memuat direktori."; li.appendChild(n); });
    }
    function loadRoot() {
      while (tree.firstChild) tree.removeChild(tree.firstChild);
      return api("tree", { root: state.root, path: "" }).then(function (d) { renderDir(tree, d); })
        .catch(function () { tree.textContent = "Sumber ini tidak tersedia untuk analisis ini."; });
    }
    // Buka pohon sampai berkas target terlihat (direktori digabung seperti paket Java -> cocokkan lewat prefiks path).
    function revealPath(path) {
      function step(container) {
        var dirs = $all(":scope > ul > li > button.tree-dir", container);
        var next = dirs.filter(function (b) { var p = b.getAttribute("data-path"); return path.indexOf(p + "/") === 0; })[0];
        if (!next) { markCurrent(path); return Promise.resolve(); }
        var li = next.parentNode;
        return (next.getAttribute("aria-expanded") === "true" ? Promise.resolve() : toggleDir(next, li)).then(function () { return step(li); });
      }
      return step(tree);
    }
    function markCurrent(path) {
      $all(".tree-item.is-current", tree).forEach(function (e) { e.classList.remove("is-current"); e.removeAttribute("aria-current"); });
      var cur = $all("button.tree-file", tree).filter(function (b) { return b.getAttribute("data-path") === path; })[0];
      if (cur) { cur.classList.add("is-current"); cur.setAttribute("aria-current", "true"); cur.scrollIntoView({ block: "nearest" }); }
    }

    // ---------------- penampil (dirender bertahap agar berkas besar tidak membekukan halaman)
    function openFile(path, line, terms) {
      var token = ++state.token;
      state.path = path; state.line = line || 0; state.terms = terms || [];
      pathEl.textContent = path; metaEl.textContent = "Memuat…"; setUrl();
      markCurrent(path);
      api("file", { root: state.root, path: path }).then(function (d) {
        if (token !== state.token) return;
        renderFile(d, token);
      }).catch(function (e) { if (token === state.token) { metaEl.textContent = ""; showMsg("Berkas tidak dapat dibuka: " + e.message); } });
    }
    function showMsg(msg) { view.hidden = true; empty.hidden = false; empty.textContent = msg; }
    function renderFile(d, token) {
      empty.hidden = true; view.hidden = false;
      while (view.firstChild) view.removeChild(view.firstChild);
      if (d.binary) { metaEl.textContent = d.size + " B"; showMsg("Berkas biner (" + d.size.toLocaleString() + " byte) tidak ditampilkan."); return; }
      var lang = langOf(state.path), lines = d.text.split("\n"), idx = 0, st = { block: false };
      var lowTerms = state.terms.map(function (t) { return t.toLowerCase(); }).filter(Boolean);
      metaEl.textContent = lines.length.toLocaleString() + " baris · " + lang + (d.truncated ? " · DIPOTONG di 2 MiB" : "");
      var firstHit = 0;
      function batch() {
        if (token !== state.token) return;
        var end = Math.min(idx + 400, lines.length), frag = document.createDocumentFragment();
        for (; idx < end; idx++) {
          var n = idx + 1, row = document.createElement("div");
          row.className = "cl"; row.id = "L" + n; row.setAttribute("data-ln", String(n));
          var num = document.createElement("a"); num.className = "ln"; num.href = "#L" + n; num.setAttribute("aria-label", "Baris " + n); num.setAttribute("data-ln", String(n));
          var code = document.createElement("span"); code.className = "lc"; code.appendChild(highlightLine(lines[idx], lang, st));
          if (lowTerms.length && lowTerms.some(function (t) { return lines[idx].toLowerCase().indexOf(t) >= 0; })) { row.classList.add("cl-match"); if (!firstHit) firstHit = n; }
          if (n === state.line) row.classList.add("cl-hit");
          row.appendChild(num); row.appendChild(code); frag.appendChild(row);
        }
        view.appendChild(frag);
        if (idx < lines.length) { requestAnimationFrame(batch); return; }
        if (d.truncated) { var t = document.createElement("div"); t.className = "cl-note muted"; t.textContent = "— tampilan dipotong; berkas lebih besar dari 2 MiB —"; view.appendChild(t); }
        var target = state.line || firstHit;
        if (target) { var el = document.getElementById("L" + target); if (el) { if (!state.line && firstHit) el.classList.add("cl-hit"); el.scrollIntoView({ block: "center" }); } }
        else view.scrollTop = 0;
      }
      batch();
    }
    view.addEventListener("click", function (e) {
      var a = e.target.closest && e.target.closest("a.ln"); if (!a) return;
      e.preventDefault();
      var n = parseInt(a.getAttribute("data-ln"), 10);
      $all(".cl-hit", view).forEach(function (x) { x.classList.remove("cl-hit"); });
      document.getElementById("L" + n).classList.add("cl-hit");
      state.line = n; setUrl();
      if (navigator.clipboard) navigator.clipboard.writeText(location.href).then(function () { metaEl.textContent = "Tautan baris " + n + " disalin"; }, function () {});
    });

    // ---------------- pencarian
    function closeResults() { results.hidden = true; while (resList.firstChild) resList.removeChild(resList.firstChild); }
    $("[data-results-close]", root).addEventListener("click", closeResults);
    function pathToRoot(rel) {                    // path relatif work/ -> {root, path}
      if (rel.indexOf("jadx/sources/") === 0) return { root: "java", path: rel.slice(13) };
      if (rel.indexOf("jadx/resources/") === 0) return { root: "jres", path: rel.slice(15) };
      if (rel.indexOf("apktool/") === 0) return { root: "smali", path: rel.slice(8) };
      return null;
    }
    function addResult(rel, label, snip, terms) {
      var loc = pathToRoot(rel); if (!loc) return;
      var li = document.createElement("li"), b = document.createElement("button");
      b.type = "button"; b.className = "result-item";
      var head = document.createElement("span"); head.className = "mono result-path break"; head.textContent = label;
      b.appendChild(head);
      if (snip) {
        var sn = document.createElement("span"); sn.className = "result-snip mono";
        snip.split(/(\u0002[^\u0003]*\u0003)/).forEach(function (part) {      // \u0002..\u0003 = bagian yang cocok
          if (part.charAt(0) === "\u0002") { var mk = document.createElement("mark"); mk.textContent = part.slice(1, -1); sn.appendChild(mk); }
          else sn.appendChild(document.createTextNode(part));
        });
        b.appendChild(sn);
      }
      b.addEventListener("click", function () {
        if (rootSel.value !== loc.root) { rootSel.value = loc.root; state.root = loc.root; loadRoot().then(go); } else go();
        function go() { openFile(loc.path, 0, terms); revealPath(loc.path); }
      });
      li.appendChild(b); resList.appendChild(li);
    }
    searchForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var q = qInput.value.trim(); if (!q) { closeResults(); return; }
      resStatus.textContent = "Mencari…"; results.hidden = false; while (resList.firstChild) resList.removeChild(resList.firstChild);
      api("search", { q: q, scope: appOnly.checked ? "app" : "all" }).then(function (d) {
        if (d.error) { resStatus.textContent = d.error; return; }
        var terms = q.split(/[^A-Za-z0-9_]+/).filter(Boolean);
        resStatus.textContent = d.classes.length + " class · " + d.hits.length + (d.hits.length >= 100 ? "+" : "") + " berkas · " + d.ms + " ms";
        d.classes.forEach(function (c) { addResult(c.path, c.package ? c.package + "." + c.name : c.name, "", [c.name]); });
        d.hits.forEach(function (h) { addResult(h.path, h.path.replace(/^jadx\/sources\//, ""), h.snip, terms); });
        if (!d.classes.length && !d.hits.length) resStatus.textContent = "Tidak ada hasil untuk “" + q + "” (" + d.ms + " ms)";
      }).catch(function () { resStatus.textContent = "Pencarian gagal."; });
    });

    rootSel.addEventListener("change", function () { state.root = rootSel.value; state.path = ""; state.line = 0; closeResults(); loadRoot(); setUrl(); });

    // ---------------- keadaan awal dari URL (?root=&path=&line=)
    var params = new URLSearchParams(location.search);
    var r0 = params.get("root"); if (r0 && $all("option", rootSel).some(function (o) { return o.value === r0; })) { state.root = r0; rootSel.value = r0; }
    var p0 = params.get("path"), l0 = parseInt(params.get("line"), 10) || 0;
    loadRoot().then(function () { if (p0) { openFile(p0, l0, []); return revealPath(p0); } });
  }
})();
