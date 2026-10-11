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

  // Lebar bilah dari data-pct. Atribut style="" inline DIBLOKIR CSP (style-src 'self'); mengubah style lewat CSSOM tidak.
  $all("[data-pct]").forEach(function (el) {
    var v = parseFloat(el.getAttribute("data-pct"));
    if (isFinite(v)) el.style.width = Math.max(0, Math.min(100, v)) + "%";
  });

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

  // Kartu "Hasil dekompilasi": saring daftar method di sisi klien, dan muat daftar lengkap bila dipotong. Semua teks lewat textContent.
  (function initDecompile() {
    var root = $("[data-decompile]");
    if (!root) return;
    var input = $("[data-dq-filter]", root), body = $("[data-dq-rows]", root), count = $("[data-dq-count]", root), allBtn = $("[data-dq-all]", root);
    if (!input || !body) return;
    var total = parseInt((count.textContent.split("dari")[1] || "").replace(/[^\d]/g, ""), 10) || body.children.length;
    function apply() {
      var q = input.value.trim().toLowerCase(), shown = 0;
      $all("tr", body).forEach(function (tr) {
        var hit = !q || tr.textContent.toLowerCase().indexOf(q) >= 0;
        tr.hidden = !hit; if (hit) shown++;
      });
      count.textContent = shown + " dari " + total.toLocaleString("id-ID") + (q ? " (disaring)" : "");
    }
    input.addEventListener("input", apply);
    if (allBtn) allBtn.addEventListener("click", function () {
      allBtn.disabled = true; allBtn.textContent = "Memuat…";
      fetch("/analyses/" + encodeURIComponent(root.getAttribute("data-analysis-id")) + "/decompile/errors", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (!res.ok) { allBtn.textContent = res.d.error || "Gagal memuat"; allBtn.disabled = false; return; }
          while (body.firstChild) body.removeChild(body.firstChild);
          res.d.errors.forEach(function (e) {
            var tr = document.createElement("tr"); tr.setAttribute("data-cat", e.category);
            var a1 = document.createElement("td"); a1.className = "mono break"; a1.textContent = e.method;
            var a2 = document.createElement("td"); a2.textContent = e.type;
            if (e["pass"]) { var ps = document.createElement("span"); ps.className = "muted hint"; ps.textContent = " · " + e["pass"]; a2.appendChild(ps); }
            var a3 = document.createElement("td"); a3.className = "muted break"; a3.textContent = e.reason;
            tr.appendChild(a1); tr.appendChild(a2); tr.appendChild(a3); body.appendChild(tr);
          });
          total = res.d.total; allBtn.parentNode.removeChild(allBtn); apply();
        })
        .catch(function () { allBtn.textContent = "Koneksi gagal. Coba lagi"; allBtn.disabled = false; });
    });
  })();

  // Tab bisa digulir di layar sempit: pusatkan tab aktif agar pengguna langsung tahu sedang di bagian mana.
  (function centerActiveTab() {
    var tabs = $(".tabs"), cur = tabs && $("a[aria-current='page']", tabs);
    if (cur && tabs.scrollWidth > tabs.clientWidth) tabs.scrollLeft = Math.max(0, cur.offsetLeft - (tabs.clientWidth - cur.offsetWidth) / 2);
  })();

  // ------------------------------------------------------------------ penjelajah kode

  var JAVA_KW = new Set(("abstract assert boolean break byte case catch char class const continue default do double else enum extends " +
    "final finally float for goto if implements import instanceof int interface long native new package private protected public " +
    "return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null var record").split(" "));
  var TOKEN_RE = {
    java: /\/\/[^\n]*|\/\*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d[\w.]*\b|@\w+|\b[A-Za-z_$][\w$]*\b/g,
    smali: /#[^\n]*|"(?:[^"\\]|\\.)*"|\.[a-z\-]+|\b[vp]\d+\b|L[\w\/$]+;|\b0x[0-9a-fA-F]+\b|\b(?:invoke|const|move|return|new|if|goto|iget|iput|sget|sput|check|aget|aput|add|sub|mul|div|rem|and|or|xor|shl|shr|neg|not|cmp|throw|nop|monitor|fill|array|instance|packed|sparse)[\w\-\/]*/g,
    xml: /<!--|-->|<\/?[\w:.\-]+|\/?>|[\w:.\-]+(?==)|"[^"]*"|'[^']*'/g
  };

  var KW_SCRIPT = {
    py: new Set(("False None True and as assert async await break class continue def del elif else except finally for from global if import in is " +
      "lambda nonlocal not or pass raise return try while with yield self").split(" ")),
    js: new Set(("async await break case catch class const continue debugger default delete do else export extends finally for function if import in " +
      "instanceof let new of return static super switch this throw try typeof var void while with yield true false null undefined").split(" ")),
    sh: new Set("if then else elif fi for while do done case esac function in echo export local return exit set unset source".split(" "))
  };
  TOKEN_RE.py = /#[^\n]*|"""|'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d[\w.]*\b|@\w+|\b[A-Za-z_]\w*\b/g;
  TOKEN_RE.js = /\/\/[^\n]*|\/\*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\b\d[\w.]*\b|\b[A-Za-z_$][\w$]*\b/g;
  TOKEN_RE.sh = /#[^\n]*|"(?:[^"\\]|\\.)*"|'[^']*'|\$\{?\w+\}?|\b[A-Za-z_]\w*\b/g;
  TOKEN_RE.json = /"(?:[^"\\]|\\.)*"|-?\b\d[\d.eE+-]*\b|\b(?:true|false|null)\b/g;

  function langOf(path) {
    if (/\.smali$/.test(path)) return "smali";
    if (/\.(xml|html|svg)$/.test(path) || /AndroidManifest/.test(path)) return "xml";
    if (/\.(java|kt|kts)$/.test(path)) return "java";
    if (/\.(py|pyi)$/.test(path)) return "py";
    if (/\.(js|mjs|cjs|ts|tsx|jsx)$/.test(path)) return "js";
    if (/\.(sh|bash|zsh)$/.test(path)) return "sh";
    if (/\.(json|jsonl)$/.test(path)) return "json";
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
      } else if (lang === "json") {
        if (t[0] === '"') cls = /^\s*:/.test(text.slice(m.index + t.length)) ? "tk-a" : "tk-s";
        else if (/^-?\d/.test(t)) cls = "tk-n"; else cls = "tk-k";
      } else if (lang === "py" || lang === "js" || lang === "sh") {
        if (t === "/*") { var e4 = text.indexOf("*/", m.index + 2); if (e4 < 0) { put(text.slice(i), "tk-c"); state.block = true; return frag; } t = text.slice(m.index, e4 + 2); re.lastIndex = e4 + 2; cls = "tk-c"; }
        else if (t[0] === "#" || (t[0] === "/" && t[1] === "/")) cls = "tk-c";
        else if (t[0] === '"' || t[0] === "'" || t[0] === "`") cls = "tk-s";
        else if (t[0] === "@" || t[0] === "$") cls = "tk-a";
        else if (/^\d/.test(t)) cls = "tk-n";
        else if (KW_SCRIPT[lang].has(t)) cls = "tk-k";
        else if (/^[A-Z]/.test(t)) cls = "tk-t";
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

  // Dipanggil SETELAH JAVA_KW/TOKEN_RE terisi (var ter-hoist sebagai undefined; lihat catatan di initChat).
  var codeRoot = $("[data-code]");
  if (codeRoot) initCode(codeRoot);

  // ------------------------------------------------------------------ chat agent

  var CITE_RE = /((?:jadx\/sources|jadx\/resources|apktool)\/[\w$.\/\-]{1,300}?):(\d{1,7})/g;
  var FILE_EXT = { python: "py", py: "py", javascript: "js", js: "js", java: "java", kotlin: "kt", bash: "sh", sh: "sh", shell: "sh",
                   json: "json", xml: "xml", markdown: "md", md: "md", smali: "smali", sql: "sql", yaml: "yml", yml: "yml", html: "txt" };
  var enc = encodeURIComponent;

  // Salin ke papan klip. navigator.clipboard hanya ada di konteks aman (HTTPS/localhost); bila tidak ada, pakai textarea + execCommand.
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.cssText = "position:fixed;top:-1000px;opacity:0";
      document.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = !!(document.execCommand && document.execCommand("copy")); } catch (_) { ok = false; }
      document.body.removeChild(ta);
      if (ok) resolve(); else reject(new Error("copy"));
    });
  }

  function citeParts(path) {
    if (path.indexOf("jadx/sources/") === 0) return { root: "java", rel: path.slice(13) };
    if (path.indexOf("jadx/resources/") === 0) return { root: "jres", rel: path.slice(15) };
    return { root: "smali", rel: path.slice(8) };
  }
  function citeUrl(analysisId, path, line) {
    var p = citeParts(path);
    return "/analyses/" + enc(analysisId) + "/code?root=" + p.root + "&path=" + enc(p.rel).replace(/%2F/g, "/") + "&line=" + line;
  }

  // Ikon kecil dibangun lewat DOM (bukan innerHTML). Gaya garis sama dengan _icons.html.
  var SVG_NS = "http://www.w3.org/2000/svg";
  var ICON_DEF = {
    check: [["polyline", { points: "20 6 9 17 4 12" }]],
    x: [["line", { x1: 18, y1: 6, x2: 6, y2: 18 }], ["line", { x1: 6, y1: 6, x2: 18, y2: 18 }]],
    spinner: [["path", { d: "M21 12a9 9 0 1 1-6.22-8.56" }]],
    dot: [["circle", { cx: 12, cy: 12, r: 3 }]],
    copy: [["rect", { x: 9, y: 9, width: 13, height: 13, rx: 2, ry: 2 }], ["path", { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" }]],
    paperclip: [["path", { d: "m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48" }]],
    image: [["rect", { x: 3, y: 3, width: 18, height: 18, rx: 2, ry: 2 }], ["circle", { cx: 9, cy: 9, r: 2 }], ["path", { d: "m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21" }]],
    download: [["path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }], ["polyline", { points: "7 10 12 15 17 10" }], ["line", { x1: 12, y1: 15, x2: 12, y2: 3 }]],
    eye: [["path", { d: "M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0" }], ["circle", { cx: 12, cy: 12, r: 3 }]],
    file: [["path", { d: "M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" }], ["path", { d: "M14 2v4a2 2 0 0 0 2 2h4" }]],
    "file-code": [["path", { d: "M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" }], ["path", { d: "M14 2v4a2 2 0 0 0 2 2h4" }], ["path", { d: "m10 13-2 2 2 2" }], ["path", { d: "m14 17 2-2-2-2" }]],
    "file-text": [["path", { d: "M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" }], ["path", { d: "M14 2v4a2 2 0 0 0 2 2h4" }], ["path", { d: "M10 9H8" }], ["path", { d: "M16 13H8" }], ["path", { d: "M16 17H8" }]],
    archive: [["rect", { x: 2, y: 3, width: 20, height: 5, rx: 1 }], ["path", { d: "M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8" }], ["path", { d: "M10 12h4" }]],
    alert: [["path", { d: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" }], ["line", { x1: 12, y1: 9, x2: 12, y2: 13 }], ["line", { x1: 12, y1: 17, x2: 12.01, y2: 17 }]]
  };
  function svgIcon(name, size, spin) {
    var s = document.createElementNS(SVG_NS, "svg");
    s.setAttribute("width", size || 16); s.setAttribute("height", size || 16); s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor"); s.setAttribute("stroke-width", "2");
    s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round"); s.setAttribute("aria-hidden", "true");
    s.setAttribute("class", "icon" + (spin ? " spin" : ""));
    (ICON_DEF[name] || []).forEach(function (d) {
      var el = document.createElementNS(SVG_NS, d[0]);
      Object.keys(d[1]).forEach(function (k) { el.setAttribute(k, d[1][k]); });
      s.appendChild(el);
    });
    return s;
  }

  // Markdown -> DOM. HANYA membuat elemen yang kita tentukan; teks selalu lewat createTextNode. Tidak ada innerHTML,
  // tidak ada tautan dari model (URL ditampilkan sebagai teks), tidak ada gambar/HTML mentah.
  // Didukung: heading, paragraf, daftar (bersarang), kutipan, garis, tabel, blok kode, **tebal**, *miring*, `kode`, sitasi.
  function renderMarkdown(src, container, opts) {
    opts = opts || {};
    while (container.firstChild) container.removeChild(container.firstChild);
    var lines = String(src).replace(/\r/g, "").split("\n"), i = 0, depth = opts._depth || 0;
    function textWithCites(parent, text) {
      var last = 0, m;
      CITE_RE.lastIndex = 0;
      while ((m = CITE_RE.exec(text)) !== null) {
        if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
        parent.appendChild(cite(m[1], parseInt(m[2], 10)));
        last = m.index + m[0].length;
      }
      if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
    }
    // Sitasi tampil sebagai chip "NamaBerkas:baris" (path lengkap di tooltip & label pembaca layar). Klik membuka pratinjau.
    function cite(path, line) {
      var a = document.createElement("a");
      a.className = "cite"; a.textContent = path.split("/").pop() + ":" + line;
      a.href = citeUrl(opts.analysisId, path, line);
      a.title = path + ":" + line;
      a.setAttribute("aria-label", path + " baris " + line);
      a.setAttribute("data-path", path); a.setAttribute("data-line", String(line));
      var info = opts.citations && opts.citations[path + ":" + line];
      if (info === false) {
        a.className = "cite cite-bad"; a.title = "Sitasi tidak terverifikasi: berkas atau baris tidak ditemukan (" + path + ":" + line + ")";
        var b = document.createElement("span"); b.className = "cite-flag"; b.textContent = " [tidak terverifikasi]";
        var w = document.createElement("span"); w.appendChild(a); w.appendChild(b); return w;
      }
      return a;
    }
    function inline(parent, text) {
      var re = /`([^`\n]+)`|\*\*([^*\n]+)\*\*|\*([^*\s][^*\n]*)\*/g, last = 0, m;
      while ((m = re.exec(text)) !== null) {
        if (m.index > last) textWithCites(parent, text.slice(last, m.index));
        if (m[1] !== undefined) { var c = document.createElement("code"); c.className = "ic"; textWithCites(c, m[1]); parent.appendChild(c); }
        else if (m[2] !== undefined) { var st = document.createElement("strong"); textWithCites(st, m[2]); parent.appendChild(st); }
        else { var em = document.createElement("em"); textWithCites(em, m[3]); parent.appendChild(em); }
        last = m.index + m[0].length;
      }
      if (last < text.length) textWithCites(parent, text.slice(last));
    }
    function codeBlock(lang, code) {
      var wrap = document.createElement("div"); wrap.className = "codeblock";
      var bar = document.createElement("div"); bar.className = "codeblock-bar";
      var lb = document.createElement("span"); lb.className = "mono muted"; lb.textContent = lang || "teks";
      var copy = document.createElement("button"); copy.type = "button"; copy.className = "btn btn-ghost btn-sm"; copy.textContent = "Salin";
      var dl = document.createElement("button"); dl.type = "button"; dl.className = "btn btn-ghost btn-sm"; dl.textContent = "Unduh";
      copy.addEventListener("click", function () {
        function ok() { copy.textContent = "Tersalin"; setTimeout(function () { copy.textContent = "Salin"; }, 1500); }
        copyText(code).then(ok, function () { copy.textContent = "Gagal"; });
      });
      dl.addEventListener("click", function () {
        var ext = FILE_EXT[(lang || "").toLowerCase()] || "txt";
        var blob = new Blob([code], { type: "text/plain;charset=utf-8" });       // text/plain: tidak pernah dijalankan browser
        var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "kode-ai." + ext;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
      });
      bar.appendChild(lb); bar.appendChild(copy); bar.appendChild(dl);
      var pre = document.createElement("pre"), cd = document.createElement("code"); cd.textContent = code; pre.appendChild(cd);
      var note = document.createElement("div"); note.className = "codeblock-note muted"; note.textContent = "Dibuat AI. Baca dan pahami sebelum dijalankan; tidak pernah dijalankan oleh aplikasi ini.";
      wrap.appendChild(bar); wrap.appendChild(pre); wrap.appendChild(note); container.appendChild(wrap);
    }

    var LIST_RE = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
    var HR_RE = /^\s{0,3}([-*_])(?:\s*\1){2,}\s*$/;
    var QUOTE_RE = /^\s{0,3}>\s?(.*)$/;
    var TABLE_SEP_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
    var MAX_LIST_DEPTH = 6;

    function splitRow(ln) {
      var s = ln.trim();
      if (s.charAt(0) === "|") s = s.slice(1);
      if (s.length && s.charAt(s.length - 1) === "|" && s.charAt(s.length - 2) !== "\\") s = s.slice(0, -1);
      var cells = [], cur = "", tick = false;
      for (var k = 0; k < s.length; k++) {
        var ch = s.charAt(k);
        if (ch === "\\" && s.charAt(k + 1) === "|") { cur += "|"; k++; continue; }
        if (ch === "`") tick = !tick;
        if (ch === "|" && !tick) { cells.push(cur.trim()); cur = ""; continue; }
        cur += ch;
      }
      cells.push(cur.trim());
      return cells;
    }
    function isTableStart(idx) {
      return idx + 1 < lines.length && lines[idx].indexOf("|") >= 0 && TABLE_SEP_RE.test(lines[idx + 1]) && lines[idx + 1].indexOf("-") >= 0 &&
             (lines[idx + 1].indexOf("|") >= 0 || splitRow(lines[idx]).length === 1);
    }
    function buildTable() {
      var head = splitRow(lines[i]), aligns = splitRow(lines[i + 1]).map(function (c) {
        return /^:-+:$/.test(c) ? "ta-center" : /-:$/.test(c) ? "ta-right" : "";
      });
      i += 2;
      var wrap = document.createElement("div"); wrap.className = "md-tablewrap";
      wrap.tabIndex = 0; wrap.setAttribute("role", "region"); wrap.setAttribute("aria-label", "Tabel (geser untuk melihat semua kolom)");
      var table = document.createElement("table"); table.className = "md-table";
      var thead = document.createElement("thead"), hr = document.createElement("tr");
      head.forEach(function (h, idx) { var th = document.createElement("th"); th.scope = "col"; if (aligns[idx]) th.className = aligns[idx]; inline(th, h); hr.appendChild(th); });
      thead.appendChild(hr); table.appendChild(thead);
      var tbody = document.createElement("tbody");
      while (i < lines.length && lines[i].trim() && lines[i].indexOf("|") >= 0) {
        var cells = splitRow(lines[i]), tr = document.createElement("tr");
        for (var c = 0; c < head.length; c++) { var td = document.createElement("td"); if (aligns[c]) td.className = aligns[c]; inline(td, cells[c] || ""); tr.appendChild(td); }
        tbody.appendChild(tr); i++;
      }
      table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
    }

    // Daftar bersarang berdasarkan indentasi; baris kosong di antara item tidak memutus daftar (penomoran tetap berlanjut).
    function parseList() {
      var stack = [], top = null, last = null, rootList = null;
      while (i < lines.length) {
        var ln = lines[i], m = LIST_RE.exec(ln);
        if (!m || HR_RE.test(ln)) {
          if (!ln.trim()) {
            var j = i + 1;
            while (j < lines.length && !lines[j].trim()) j++;
            if (j < lines.length && LIST_RE.test(lines[j]) && !HR_RE.test(lines[j])) { i = j; continue; }
            break;
          }
          if (m || !last || !/^\s{2,}\S/.test(ln) || /^\s*```/.test(ln)) break;
          last.text += "\n" + ln.trim(); i++; continue;               // lanjutan item (baris terindentasi)
        }
        var indent = m[1].replace(/\t/g, "    ").length, ordered = /^\d/.test(m[2]);
        var startNo = ordered ? parseInt(m[2], 10) : 1;
        if (!stack.length) {
          top = { indent: indent, ordered: ordered, items: [], start: startNo }; rootList = top; stack.push(top);
        } else {
          while (stack.length > 1 && indent < stack[stack.length - 1].indent) stack.pop();
          top = stack[stack.length - 1];
          if (stack.length === 1 && indent < top.indent) top.indent = indent;
          if (indent > top.indent && last && stack.length < MAX_LIST_DEPTH) {
            var child = { indent: indent, ordered: ordered, items: [], start: startNo };
            last.children.push(child); stack.push(child); top = child;
          } else if (stack.length === 1 && ordered !== top.ordered && indent <= top.indent) {
            break;                                                    // ganti jenis daftar di tingkat atas = daftar baru
          }
        }
        last = { text: m[3], children: [] }; top.items.push(last); i++;
      }
      return rootList;
    }
    function buildList(L) {
      var el = document.createElement(L.ordered ? "ol" : "ul"); el.className = "md-list";
      if (L.ordered && L.start !== 1) el.start = L.start;
      L.items.forEach(function (it) {
        var li = document.createElement("li"); inline(li, it.text);
        it.children.forEach(function (ch) { li.appendChild(buildList(ch)); });
        el.appendChild(li);
      });
      return el;
    }

    while (i < lines.length) {
      var ln = lines[i], fence = /^\s*```\s*([\w+-]*)\s*$/.exec(ln);
      if (fence) {
        var buf = []; i++;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { buf.push(lines[i]); i++; }
        i++; codeBlock(fence[1], buf.join("\n")); continue;
      }
      if (!ln.trim()) { i++; continue; }
      var h = /^(#{1,4})\s+(.*)$/.exec(ln);
      if (h) { var hd = document.createElement("h" + (Math.min(h[1].length, 3) + 2)); hd.className = "md-h"; inline(hd, h[2]); container.appendChild(hd); i++; continue; }
      if (HR_RE.test(ln)) { var hrEl = document.createElement("hr"); hrEl.className = "md-hr"; container.appendChild(hrEl); i++; continue; }
      if (QUOTE_RE.test(ln)) {
        var qb = [];
        while (i < lines.length) { var q = QUOTE_RE.exec(lines[i]); if (!q) break; qb.push(q[1]); i++; }
        var bq = document.createElement("blockquote"); bq.className = "md-quote";
        if (depth < 3) renderMarkdown(qb.join("\n"), bq, { analysisId: opts.analysisId, citations: opts.citations, _depth: depth + 1 });
        else bq.textContent = qb.join("\n");
        container.appendChild(bq); continue;
      }
      if (isTableStart(i)) { buildTable(); continue; }
      if (LIST_RE.test(ln)) { var L = parseList(); if (L) container.appendChild(buildList(L)); continue; }
      var para = [];
      while (i < lines.length && lines[i].trim() && !/^\s*```/.test(lines[i]) && !/^(#{1,4})\s+/.test(lines[i]) && !LIST_RE.test(lines[i]) &&
             !HR_RE.test(lines[i]) && !QUOTE_RE.test(lines[i]) && !isTableStart(i)) { para.push(lines[i]); i++; }
      if (!para.length) { para.push(lines[i]); i++; }
      var p = document.createElement("p"); p.className = "md-p"; inline(p, para.join("\n")); container.appendChild(p);
    }
  }
  window.__rvRenderMarkdown = renderMarkdown;    // dipakai pengujian

  // ---- label langkah tool yang manusiawi (argumen berasal dari model: selalu lewat textContent)
  function shortCls(n) { n = String(n || ""); var k = n.lastIndexOf("."); return k >= 0 ? n.slice(k + 1) : n; }
  function baseName(p) { var s = String(p || "").split("/"); return s[s.length - 1]; }
  var TOOL_LABELS = {
    get_overview: function () { return "Ringkasan aplikasi"; },
    get_manifest: function () { return "Baca manifest"; },
    list_packages: function (a) { return "Daftar package" + (a.prefix ? " " + a.prefix : ""); },
    list_classes: function (a) { return "Daftar class di " + (a["package"] || "?"); },
    search_code: function (a) { return "Cari “" + (a.query || "") + "”"; },
    get_class: function (a) { return "Baca " + shortCls(a.name) + (a.format === "smali" ? " (smali)" : "") + (a.start_line > 1 ? " dari baris " + a.start_line : ""); },
    get_method: function (a) { return "Baca " + shortCls(a["class"]) + "." + (a.method || ""); },
    find_xrefs: function (a) { return a.string ? "Cari pemakai string “" + a.string + "”" : "Cari pemakai " + shortCls(a["class"]) + (a.member ? "." + a.member : ""); },
    find_callees: function (a) { return "Isi method " + shortCls(a["class"]) + "." + (a.method || ""); },
    class_info: function (a) { return "Struktur " + shortCls(a["class"]); },
    find_paths: function (a) { return "Jalur " + shortCls(a.from_class) + (a.from_method ? "." + a.from_method : "") + " → " + shortCls(a.to_class) + (a.to_method ? "." + a.to_method : ""); },
    list_strings: function (a) { return "Daftar string" + (a.kind ? " " + a.kind : "") + (a.filter ? " “" + a.filter + "”" : ""); },
    get_findings: function (a) { return "Temuan statis" + (a.category ? " (" + a.category + ")" : ""); },
    read_file: function (a) { return "Baca " + baseName(a.path) + (a.start_line ? ":" + a.start_line + (a.end_line ? "-" + a.end_line : "") : ""); },
    list_files: function () { return "Daftar berkas & lampiran"; },
    write_file: function (a) { return (a.mode === "append" ? "Sambung " : "Tulis ") + baseName(a.path); },
    edit_file: function (a) { return "Ubah " + baseName(a.path); },
    view_image: function (a) { return "Lihat gambar " + baseName(a.path); }
  };
  function toolLabel(name, argsText) {
    var a = null;
    try { a = JSON.parse(argsText || "{}"); } catch (_) { a = null; }
    var fn = Object.prototype.hasOwnProperty.call(TOOL_LABELS, name) ? TOOL_LABELS[name] : null;
    var label = "";
    if (fn && a && typeof a === "object") { try { label = String(fn(a)); } catch (_) { label = ""; } }
    if (!label) label = name;
    return label.length > 110 ? label.slice(0, 109) + "…" : label;
  }
  window.__rvToolLabel = toolLabel;
  function fmtDur(ms) { return ms < 950 ? Math.max(1, Math.round(ms / 100) * 100) + " ms" : (ms / 1000).toFixed(ms < 10000 ? 1 : 0).replace(".", ",") + " dtk"; }

  function makeStep(name, argsText) {
    var li = document.createElement("li"); li.className = "tstep is-run";
    var ic = document.createElement("span"); ic.className = "tstep-ic"; ic.appendChild(svgIcon("spinner", 16, true));
    var body = document.createElement("span");
    var label = document.createElement("span"); label.className = "tstep-label"; label.textContent = toolLabel(name, argsText); label.title = name + " " + argsText;
    var sub = document.createElement("span"); sub.className = "tstep-sub"; sub.hidden = true;
    body.appendChild(label); body.appendChild(sub);
    var time = document.createElement("span"); time.className = "tstep-time";
    li.appendChild(ic); li.appendChild(body); li.appendChild(time);
    var t0 = Date.now();
    var api = {
      li: li,
      done: function (ok, summary, ms) {
        li.className = "tstep " + (ok ? "is-ok" : "is-bad");
        while (ic.firstChild) ic.removeChild(ic.firstChild);
        ic.appendChild(svgIcon(ok ? "check" : "x", 16, false));
        if (summary) { sub.textContent = summary; sub.hidden = false; }
        time.textContent = fmtDur(ms === undefined ? Date.now() - t0 : ms);
        li.setAttribute("aria-label", label.textContent + (ok ? ": berhasil" : ": gagal"));
      }
    };
    return api;
  }

  // ------------------------------------------------------------------ berkas: ikon, penampil, kartu (chat & halaman Berkas)
  // Teks berkas/AI SELALU lewat textContent. Berkas tidak pernah dirender sebagai HTML; hanya gambar raster yang ditampilkan lewat <img>.
  var CODE_EXT = /\.(py|pyi|js|mjs|cjs|ts|tsx|jsx|sh|bash|java|kt|kts|smali|c|h|cc|cpp|go|rs|rb|php|lua|swift|dart|sql|gradle|ps1|bat|json|ya?ml|xml|html|css|toml|ini)$/i;
  function fileKind(name, media) {
    if (media === "image") return "image";
    if (/\.(zip|apk|tar|gz|tgz|7z|rar|jar)$/i.test(name)) return "archive";
    if (CODE_EXT.test(name)) return "file-code";
    return media === "text" ? "file-text" : "file";
  }
  function fileUrls(aid, id) {
    var b = "/analyses/" + enc(aid) + "/files/" + enc(id);
    return { text: b + "/text", raw: b + "/raw", download: b + "/download", del: b + "/delete" };
  }
  function fileInfoFrom(el, aid) {
    var g = function (k) { return el.getAttribute("data-file-" + k); };
    return { aid: aid, id: g("id"), name: g("name") || "berkas", media: g("media") || "binary", size: parseInt(g("size"), 10) || 0,
             rev: parseInt(g("rev"), 10) || 1, path: g("path") || "" };
  }
  var fviewApi = null;
  function fileViewer() {
    if (fviewApi) return fviewApi;
    var dlg = $("[data-fview]");
    if (!dlg) return null;
    var E = { ic: $("[data-fview-ic]", dlg), name: $("[data-fview-name]", dlg), meta: $("[data-fview-meta]", dlg), note: $("[data-fview-note]", dlg),
              body: $("[data-fview-body]", dlg), copy: $("[data-fview-copy]", dlg), dl: $("[data-fview-download]", dlg),
              close: $("[data-fview-close]", dlg), modes: $("[data-fview-modes]", dlg) };
    var tok = 0, opener = null, info = null, textRaw = "", mode = "source", isMd = false, shown = 0, allLines = [], lang = "plain", hlState = { block: false };
    var CHUNK = 1500;                                       // baris per potongan tampilan (hanya agar DOM tetap ringan)

    function clearBody() { while (E.body.firstChild) E.body.removeChild(E.body.firstChild); }
    function copyLabel(t) { var sp = $("span", E.copy); if (sp) sp.textContent = t; }
    function addRows(from, to) {
      var frag = document.createDocumentFragment();
      for (var n = from; n < to; n++) {
        var row = document.createElement("div"); row.className = "pl";
        var ln = document.createElement("span"); ln.className = "ln"; ln.textContent = String(n + 1);
        var cd = document.createElement("code"); cd.appendChild(highlightLine(allLines[n], lang, hlState));
        row.appendChild(ln); row.appendChild(cd); frag.appendChild(row);
      }
      return frag;
    }
    function paintSource() {
      clearBody(); hlState = { block: false }; shown = 0;
      var wrap = document.createElement("div"); wrap.className = "fview-code";
      E.body.appendChild(wrap);
      function more() {
        var old = $(".fview-more", wrap); if (old) wrap.removeChild(old);
        var to = Math.min(allLines.length, shown + CHUNK);
        wrap.appendChild(addRows(shown, to)); shown = to;
        if (shown < allLines.length) {
          var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-ghost btn-sm fview-more";
          b.textContent = "Tampilkan " + Math.min(CHUNK, allLines.length - shown).toLocaleString("id-ID") + " baris berikutnya (sisa " + (allLines.length - shown).toLocaleString("id-ID") + ")";
          b.addEventListener("click", more); wrap.appendChild(b);
        }
      }
      more();
    }
    function paintRendered() {
      clearBody();
      var d = document.createElement("div"); d.className = "msg-body fview-md"; E.body.appendChild(d);
      renderMarkdown(textRaw, d, { analysisId: info.aid, citations: {} });
    }
    function paint() { (isMd && mode === "render") ? paintRendered() : paintSource(); }
    function setMode(m) {
      mode = m;
      $all("button", E.modes).forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-mode") === m ? "true" : "false"); });
      paint();
    }
    function showImage(url) {
      clearBody();
      var btn = document.createElement("button"); btn.type = "button"; btn.className = "fview-imgbtn";
      btn.setAttribute("aria-label", "Ganti antara ukuran pas layar dan ukuran asli");
      var img = document.createElement("img"); img.className = "fview-img"; img.alt = info.name;
      img.addEventListener("load", function () { E.note.textContent = img.naturalWidth + " × " + img.naturalHeight + " px · klik gambar untuk ukuran asli"; });
      img.addEventListener("error", function () { E.note.textContent = "Gambar tidak dapat dimuat."; });
      btn.addEventListener("click", function () { E.body.classList.toggle("is-actual"); });
      img.src = url; btn.appendChild(img); E.body.appendChild(btn);
    }
    function msg(t) { clearBody(); var p = document.createElement("p"); p.className = "fview-empty muted"; p.textContent = t; E.body.appendChild(p); }

    function open(i, openerEl) {
      info = i; opener = openerEl || null; textRaw = ""; E.copy.hidden = true; E.modes.hidden = true; E.body.classList.remove("is-actual");
      var u = fileUrls(i.aid, i.id), t = ++tok;
      E.name.textContent = i.path || i.name; E.name.title = i.path || i.name;
      E.meta.textContent = fmtBytes(i.size) + (i.rev > 1 ? " · revisi " + i.rev : "");
      while (E.ic.firstChild) E.ic.removeChild(E.ic.firstChild); E.ic.appendChild(svgIcon(fileKind(i.name, i.media), 20));
      E.dl.href = u.download; E.dl.setAttribute("download", i.name);
      E.note.textContent = i.media === "image" ? "Memuat gambar…" : "Memuat…"; clearBody();
      if (typeof dlg.showModal === "function") { if (!dlg.open) dlg.showModal(); } else dlg.setAttribute("open", "");
      if (i.media === "image") { showImage(u.raw); return; }
      fetch(u.text, { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (t !== tok) return;                              // penampil sudah dipakai untuk berkas lain / ditutup
          var d = res.d;
          if (!res.ok) { E.note.textContent = d.error || "Berkas tidak dapat dimuat."; msg(E.note.textContent); return; }
          if (d.missing) { E.note.textContent = "Isi berkas tidak ditemukan di penyimpanan."; msg(E.note.textContent); return; }
          if (d.binary) { E.note.textContent = "Berkas biner"; msg("Berkas biner tidak bisa ditampilkan. Gunakan Unduh untuk membukanya di aplikasi lain."); return; }
          if (d.image) { showImage(u.raw); return; }
          textRaw = d.text; allLines = textRaw.split("\n"); if (allLines.length > 1 && allLines[allLines.length - 1] === "") allLines.pop();
          lang = langOf(i.name); isMd = /\.(md|markdown)$/i.test(i.name);
          E.note.textContent = allLines.length.toLocaleString("id-ID") + " baris" + (d.truncated ? " · pratinjau dibatasi " + fmtBytes(textRaw.length) + " dari " + fmtBytes(d.size) + "; Unduh untuk berkas lengkap" : "");
          E.copy.hidden = false; copyLabel("Salin");
          E.modes.hidden = !isMd; mode = isMd ? "render" : "source";
          if (isMd) setMode("render"); else paint();
          E.body.scrollTop = 0;
        })
        .catch(function () { if (t === tok) { E.note.textContent = "Koneksi gagal. Coba lagi."; msg("Koneksi gagal. Tutup lalu buka lagi."); } });
    }
    function close() { if (dlg.open) dlg.close(); else dlg.removeAttribute("open"); }
    dlg.addEventListener("close", function () {
      tok++; clearBody(); textRaw = ""; allLines = [];
      var o = opener; opener = null;
      if (o && document.body.contains(o)) o.focus();
    });
    dlg.addEventListener("click", function (e) { if (e.target === dlg) close(); });       // klik di luar kotak
    E.close.addEventListener("click", close);
    E.copy.addEventListener("click", function () {
      copyText(textRaw).then(function () { copyLabel("Tersalin"); setTimeout(function () { copyLabel("Salin"); }, 1500); },
                             function () { copyLabel("Gagal"); setTimeout(function () { copyLabel("Salin"); }, 1500); });
    });
    $all("button", E.modes).forEach(function (b) { b.addEventListener("click", function () { setMode(b.getAttribute("data-mode")); }); });
    fviewApi = { open: open, close: close, isOpen: function () { return dlg.open || dlg.hasAttribute("open"); } };
    return fviewApi;
  }
  document.addEventListener("click", function (e) {
    var el = e.target && e.target.closest ? e.target.closest("[data-file-view]") : null;
    if (!el || e.defaultPrevented) return;
    var host = el.closest("[data-analysis-id]") || $("[data-analysis-id]"), v = fileViewer();
    var aid = host && host.getAttribute("data-analysis-id");
    if (!aid || !v) return;
    e.preventDefault(); v.open(fileInfoFrom(el, aid), el);
  });

  // Kartu berkas buatan AI di bawah jawaban (dibuat/diperbarui langsung saat peristiwa 'file' tiba).
  function buildFileCard(aid, f) {
    var u = fileUrls(aid, f.id), name = f.name || baseName(f.path), path = f.path || name;
    var dir = path.length > name.length ? path.slice(0, path.length - name.length) : "";
    var card = document.createElement("div"); card.className = "fcard"; card.setAttribute("data-fcard", String(f.id));
    var ic = document.createElement("span"); ic.className = "fcard-ic"; ic.appendChild(svgIcon(fileKind(name, f.media || "text"), 20));
    var main = document.createElement("div"); main.className = "fcard-main";
    var nm = document.createElement("span"); nm.className = "fcard-name mono";
    var dr = document.createElement("span"); dr.className = "fcard-dir"; dr.textContent = dir; nm.appendChild(dr); nm.appendChild(document.createTextNode(name));
    var meta = document.createElement("span"); meta.className = "fcard-meta muted hint";
    meta.textContent = fmtBytes(f.size) + (f.revision > 1 ? " · revisi " + f.revision : "");
    main.appendChild(nm); main.appendChild(meta);
    var act = document.createElement("div"); act.className = "fcard-actions";
    var view = document.createElement("button"); view.type = "button"; view.className = "btn btn-ghost btn-sm";
    view.setAttribute("data-file-view", ""); view.setAttribute("data-file-id", String(f.id)); view.setAttribute("data-file-name", name);
    view.setAttribute("data-file-media", f.media || "text"); view.setAttribute("data-file-size", String(f.size)); view.setAttribute("data-file-rev", String(f.revision || 1));
    view.setAttribute("data-file-path", path); view.setAttribute("aria-label", "Lihat " + name);
    view.appendChild(svgIcon("eye", 16)); var vs = document.createElement("span"); vs.textContent = "Lihat"; view.appendChild(vs);
    var dl = document.createElement("a"); dl.className = "btn btn-ghost btn-sm"; dl.href = u.download; dl.setAttribute("download", name);
    dl.setAttribute("aria-label", "Unduh " + name); dl.appendChild(svgIcon("download", 16)); var ds = document.createElement("span"); ds.textContent = "Unduh"; dl.appendChild(ds);
    act.appendChild(view); act.appendChild(dl);
    card.appendChild(ic); card.appendChild(main); card.appendChild(act);
    return card;
  }
  function upsertFileCard(box, aid, f) {
    var ex = null;
    $all("[data-fcard]", box).forEach(function (c) { if (c.getAttribute("data-fcard") === String(f.id)) ex = c; });
    var el = buildFileCard(aid, f);
    if (ex) box.replaceChild(el, ex); else box.appendChild(el);
    return el;
  }
  window.__rvFileViewer = fileViewer;           // dipakai pengujian

  function initChat(root) {
    var aid = root.getAttribute("data-analysis-id"), csrf = root.getAttribute("data-csrf");
    var sessionId = root.getAttribute("data-session-id") || null;
    var log = $("[data-log]", root), form = $("[data-form]", root), input = $("[data-input]", root);
    var statusEl = $("[data-status]", root), stopBtn = $("[data-stop]", root), sendBtn = $("[data-send]", root);
    var modelEl = $("[data-model]", root), sugg = $("[data-suggestions]", root), jumpBtn = $("[data-jump]", root);
    var peek = $("[data-peek]", root), peekTitle = $("[data-peek-title]", root), peekOpen = $("[data-peek-open]", root);
    var peekNote = $("[data-peek-note]", root), peekCode = $("[data-peek-code]", root), peekClose = $("[data-peek-close]", root);
    var fold = $("[data-sidefold]", root);
    var attBox = $("[data-atts]", root), attBtn = $("[data-attach]", root), fileInput = $("[data-file]", root), attWarn = $("[data-att-warn]", root);
    var dz = $("[data-dropzone]", root), chatMain = $(".chat-main", root);
    var maxFile = parseInt(root.getAttribute("data-max-file") || "0", 10) || 0;
    var es = null, busy = false, lastUserText = "", peekToken = 0, peekOpener = null, peekDir = "";
    var atts = [], attSeq = 0;
    function setPeekNote(t) { peekNote.textContent = (peekDir ? peekDir + "  ·  " : "") + t; }

    // Daftar sesi dilipat otomatis di layar sempit agar percakapan langsung terlihat.
    if (fold && window.matchMedia && window.matchMedia("(max-width: 900px)").matches) fold.open = false;

    function citeMap(list) {
      var m = {}; (list || []).forEach(function (c) { m[c.path + ":" + c.line] = !!c.valid; }); return m;
    }
    // Tinggi log = sisa layar di bawah posisinya (dihitung dari posisi absolut, jadi benar walau halaman sedang digulir) dikurangi tinggi
    // kotak pesan. Tanpa ini bagian bawah log (pesan terbaru) menjulur ke luar layar atau tertutup kotak pesan.
    var pinned = true;      // true = log mengikuti isi baru sampai pengguna sendiri menggulir ke atas
    function fitLog() {
      var top = log.getBoundingClientRect().top + (window.pageYOffset || 0);
      var avail = window.innerHeight - top - form.offsetHeight - 28;
      var h = Math.max(320, Math.round(avail)) + "px";
      if (log.style.maxHeight !== h) { log.style.maxHeight = h; if (pinned) log.scrollTop = log.scrollHeight; updateJump(); }
    }
    function nearBottom() { return log.scrollHeight - log.scrollTop - log.clientHeight < 80; }
    // "Menempel di dasar": log terus mengikuti isi baru SAMPAI pengguna sendiri menggulir ke atas. Jarak ke dasar tidak dipakai untuk
    // memutuskan mengikuti, karena satu blok langkah tool bisa menambah >80px sekaligus dan membuat log tertinggal.
    function updateJump() { if (jumpBtn) jumpBtn.hidden = nearBottom(); }
    function scrollDown(force) { if (force) pinned = true; if (pinned) log.scrollTop = log.scrollHeight; updateJump(); }
    // Hanya gulir oleh PENGGUNA (roda, sentuh, keyboard, klik bilah gulir) yang boleh melepas "menempel". Peristiwa gulir akibat tata
    // letak (font termuat, kotak pesan tumbuh, scroll anchoring browser) tidak boleh membuat log berhenti mengikuti.
    var userAt = 0;
    function markUser() { userAt = Date.now(); }
    ["wheel", "touchstart", "touchmove", "mousedown", "keydown"].forEach(function (ev) { log.addEventListener(ev, markUser, { passive: true }); });
    log.addEventListener("scroll", function () {
      if (Date.now() - userAt < 800) pinned = nearBottom();
      else if (nearBottom()) pinned = true;
      updateJump();
    });
    if (jumpBtn) jumpBtn.addEventListener("click", function () { pinned = true; log.scrollTop = log.scrollHeight; updateJump(); log.focus(); });

    function copyBtn(getText, label) {
      var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-ghost btn-sm";
      var ic = svgIcon("copy", 14), tx = document.createElement("span"); tx.textContent = label;
      b.appendChild(ic); b.appendChild(tx); b.setAttribute("aria-label", "Salin jawaban sebagai Markdown");
      b.addEventListener("click", function () {
        function flash(t) { tx.textContent = t; setTimeout(function () { tx.textContent = label; }, 1500); }
        copyText(getText()).then(function () { flash("Tersalin"); }, function () { flash("Gagal"); });
      });
      return b;
    }
    // Dua tombol Salin: di judul pesan (judul menempel di atas selama pesan digulir) dan di bawah jawaban, tempat pembaca berhenti.
    // Mengembalikan baris `.msg-foot` agar pemanggil bisa menambahkan meta biaya ke dalamnya.
    function addActions(art, getText) {
      var head = $(".msg-head", art), foot = $(".msg-foot", art);
      if (foot) return foot;
      if (head && !$(".msg-actions", head)) {
        var box = document.createElement("span"); box.className = "msg-actions"; box.appendChild(copyBtn(getText, "Salin")); head.appendChild(box);
      }
      foot = document.createElement("div"); foot.className = "msg-foot";
      foot.appendChild(copyBtn(getText, "Salin jawaban"));
      art.appendChild(foot);
      return foot;
    }
    function stepsFromStored(art) {
      var items = $all(".msg-tools li[data-tool]", art);
      if (!items.length) return;
      var ul = items[0].parentNode; ul.className = "tsteps";
      items.forEach(function (li) {
        var st = makeStep(li.getAttribute("data-tool"), li.getAttribute("data-args") || "");
        st.done(li.getAttribute("data-ok") === "1", li.getAttribute("data-summary") || "", 0);
        st.li.querySelector(".tstep-time").textContent = "";
        ul.replaceChild(st.li, li);
      });
    }

    // --- render pesan yang sudah tersimpan (dari server)
    $all("article.msg", log).forEach(function (art) {
      var body = $("[data-md]", art);
      if (!body) return;
      var raw = body.textContent, cites = {};
      try { cites = citeMap(JSON.parse(body.getAttribute("data-citations") || "[]")); } catch (_) { /* abaikan */ }
      // Satu pesan yang gagal dirender tidak boleh mematikan seluruh halaman: tampilkan teks apa adanya.
      try {
        if (art.getAttribute("data-role") === "assistant") { renderMarkdown(raw, body, { analysisId: aid, citations: cites }); addActions(art, function () { return raw; }); }
        else body.classList.add("msg-plain");
        stepsFromStored(art);
      } catch (err) {
        body.textContent = raw; body.classList.add("msg-plain");
        if (window.console) console.error("render pesan gagal:", err);
      }
    });
    scrollDown(true);

    function addMsg(role, label) {
      var art = document.createElement("article"); art.className = "msg msg-" + role; art.setAttribute("data-role", role);
      var head = document.createElement("header"); head.className = "msg-head"; head.textContent = label; art.appendChild(head);
      log.appendChild(art); return art;
    }
    function updateSend() {
      var hasContent = !!input.value.trim() || readyAtts().length > 0;
      sendBtn.disabled = busy || !hasContent || uploading() || visionBlocked();
    }
    function grow() { input.style.height = "auto"; input.style.height = Math.min(input.scrollHeight + 2, 224) + "px"; if (log.style.maxHeight) fitLog(); }
    function setBusy(b) {
      busy = b; input.disabled = b; stopBtn.hidden = !b; if (attBtn) attBtn.disabled = b; updateSend();
      if (modelEl && modelEl.tagName === "SELECT") modelEl.disabled = b;
      // Pembaca layar: jangan umumkan setiap potongan streaming; cukup status ringkas + hasil akhir.
      log.setAttribute("aria-busy", b ? "true" : "false");
      log.setAttribute("aria-live", b ? "off" : "polite");
    }
    function fail(msg, retryText, retryAtts) {
      var art = addMsg("error", "Galat"); var d = document.createElement("div"); d.className = "msg-body"; d.textContent = msg; art.appendChild(d);
      art.setAttribute("role", "alert");
      if (retryText) {
        var row = document.createElement("div"); row.className = "msg-note";
        var rb = document.createElement("button"); rb.type = "button"; rb.className = "btn btn-ghost btn-sm"; rb.textContent = "Coba lagi";
        rb.addEventListener("click", function () { rb.disabled = true; send(retryText, retryAtts && retryAtts.length ? retryAtts : []); });
        row.appendChild(rb); art.appendChild(row);
      }
      scrollDown(true);
    }
    function updateBudget(b) {
      if (!b) return;
      var set = function (sel, t) { var el = $(sel, root); if (el) el.textContent = t; };
      set("[data-b-today]", Number(b.today).toFixed(3));
      set("[data-b-idr]", Math.round(b.today_idr).toLocaleString("id-ID"));
      var bar = $("[data-b-bar]", root), meter = $("[data-b-meter]", root);
      if (bar && b.today_limit) {
        var pct = Math.min(100, b.today / b.today_limit * 100);
        bar.style.width = pct.toFixed(1) + "%";
        if (meter) meter.className = "meter" + (pct >= 90 ? " is-bad" : pct >= 70 ? " is-warn" : "");
      }
    }

    // --- pratinjau kode untuk sitasi (tanpa meninggalkan percakapan)
    function openPeek(opener, path, line) {
      if (!peek) return;
      var parts = citeParts(path), tok = ++peekToken;
      peekOpener = opener;
      var base = baseName(path);
      peekDir = path.slice(0, path.length - base.length);
      peekTitle.textContent = base + ":" + line; peekTitle.title = path + ":" + line;
      peekOpen.href = citeUrl(aid, path, line);
      setPeekNote("Memuat…"); while (peekCode.firstChild) peekCode.removeChild(peekCode.firstChild);
      peek.hidden = false; peek.focus();
      fetch("/analyses/" + enc(aid) + "/code/file?root=" + parts.root + "&path=" + enc(parts.rel), { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (tok !== peekToken) return;                                  // sitasi lain sudah diklik
          if (!res.ok) { setPeekNote(res.d.error || "Berkas tidak dapat dimuat."); return; }
          var d = res.d;
          if (d.binary) { setPeekNote("Berkas biner: tidak ditampilkan."); return; }
          var all = String(d.text).split("\n"), from = Math.max(1, line - 12), to = Math.min(all.length, line + 12), note = "";
          if (line > all.length) { from = Math.max(1, all.length - 24); to = all.length; note = "Baris " + line + " di luar berkas (" + all.length + " baris). "; }
          var lang = langOf(path), state = { block: false }, hit = null;
          for (var n = from; n <= to; n++) {
            var row = document.createElement("div"); row.className = "pl" + (n === line ? " pl-hit" : "");
            var ln = document.createElement("span"); ln.className = "ln"; ln.textContent = String(n);
            var cd = document.createElement("code"); cd.appendChild(highlightLine(all[n - 1], lang, state));
            row.appendChild(ln); row.appendChild(cd); peekCode.appendChild(row);
            if (n === line) { hit = row; row.setAttribute("aria-current", "true"); }
          }
          setPeekNote(note + "Baris " + from + "–" + to + " dari " + all.length + (d.truncated ? " · berkas dipotong" : ""));
          if (hit) peekCode.scrollTop = Math.max(0, hit.offsetTop - peekCode.offsetTop - peekCode.clientHeight / 2);
        })
        .catch(function () { if (tok === peekToken) setPeekNote("Koneksi gagal. Coba lagi."); });
    }
    function closePeek() {
      peekToken++; peek.hidden = true;
      var o = peekOpener; peekOpener = null;
      if (o && document.body.contains(o)) o.focus();
    }
    if (peekClose) peekClose.addEventListener("click", closePeek);
    root.addEventListener("click", function (e) {
      var a = peek && e.target && e.target.closest ? e.target.closest("a.cite") : null;
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;   // modifier = perilaku bawaan (tab baru)
      var path = a.getAttribute("data-path"), line = parseInt(a.getAttribute("data-line"), 10);
      if (!path || !line) return;
      e.preventDefault(); openPeek(a, path, line);
    });

    // --- lampiran: unggah (XHR agar ada progres), pratinjau, seret-lepas, tempel
    function readyAtts() { return atts.filter(function (a) { return a.state === "ready"; }); }
    function uploading() { return atts.some(function (a) { return a.state === "uploading"; }); }
    function visionOk() {
      if (!modelEl) return false;
      var el = modelEl.tagName === "SELECT" ? modelEl.options[modelEl.selectedIndex] : modelEl;
      return !!el && el.getAttribute("data-vision") === "1";
    }
    function visionBlocked() { return !visionOk() && atts.some(function (a) { return a.state !== "error" && a.isImage; }); }
    function refreshAtts() {
      if (attBox) attBox.hidden = atts.length === 0;
      var m = visionBlocked() ? "Model ini tidak bisa melihat gambar. Pilih model yang bertanda “gambar”, atau hapus gambar dari lampiran." : "";
      if (attWarn) { attWarn.textContent = m; attWarn.hidden = !m; }
      updateSend();
    }
    function attChip(a) {
      var el = document.createElement("div"); el.setAttribute("role", "listitem");
      var th = document.createElement("span"); th.className = "att-thumb";
      var body = document.createElement("span"); body.className = "att-body";
      var nm = document.createElement("span"); nm.className = "att-name"; nm.textContent = a.name; nm.title = a.name;
      var sub = document.createElement("span"); sub.className = "att-sub";
      var bar = document.createElement("span"); bar.className = "att-bar"; bar.setAttribute("role", "progressbar");
      bar.setAttribute("aria-label", "Mengunggah " + a.name); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100");
      var fill = document.createElement("span"); bar.appendChild(fill);
      body.appendChild(nm); body.appendChild(sub); body.appendChild(bar);
      var retry = document.createElement("button"); retry.type = "button"; retry.className = "att-btn"; retry.textContent = "Coba lagi"; retry.hidden = true;
      retry.addEventListener("click", function () { upload(a); });
      var x = document.createElement("button"); x.type = "button"; x.className = "att-x"; x.setAttribute("aria-label", "Hapus lampiran " + a.name);
      x.title = "Hapus"; x.appendChild(svgIcon("x", 14));
      x.addEventListener("click", function () { removeAtt(a); });
      el.appendChild(th); el.appendChild(body); el.appendChild(retry); el.appendChild(x);
      a.el = el; a.p = { th: th, sub: sub, bar: bar, fill: fill, retry: retry, shown: "" };
      paintAtt(a);
      return el;
    }
    function paintAtt(a) {
      var p = a.p;
      a.el.className = "att is-" + a.state;
      var key = a.state + (a.raw || "");
      if (p.shown !== key) {                                           // ganti isi thumbnail hanya saat status berubah (hindari memuat ulang gambar)
        p.shown = key;
        while (p.th.firstChild) p.th.removeChild(p.th.firstChild);
        if (a.state === "ready" && a.raw) { var img = document.createElement("img"); img.alt = ""; img.src = a.raw; p.th.appendChild(img); }
        else p.th.appendChild(svgIcon(a.state === "uploading" ? "spinner" : a.state === "error" ? "alert" : fileKind(a.name, a.media || (a.isImage ? "image" : "binary")), 20, a.state === "uploading"));
      }
      p.sub.textContent = a.state === "uploading" ? "Mengunggah " + Math.round(a.pct) + "%" : a.state === "error" ? a.err : fmtBytes(a.size);
      p.bar.hidden = a.state !== "uploading";
      p.fill.style.width = Math.round(a.pct) + "%";
      p.bar.setAttribute("aria-valuenow", String(Math.round(a.pct)));
      p.retry.hidden = !(a.state === "error" && a.file && a.retryable);
    }
    function attFail(a, text, retryable) { a.state = "error"; a.err = text; a.retryable = !!retryable; a.xhr = null; paintAtt(a); refreshAtts(); }
    function upload(a) {
      a.state = "uploading"; a.pct = 0; a.err = ""; paintAtt(a); refreshAtts();
      var xhr = new XMLHttpRequest(); a.xhr = xhr;
      xhr.open("POST", "/api/files/upload?analysis=" + enc(aid));
      xhr.setRequestHeader("X-CSRF-Token", csrf); xhr.setRequestHeader("X-File-Name", enc(a.name)); xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = function (e) { if (e.lengthComputable && e.total) { a.pct = e.loaded / e.total * 100; paintAtt(a); } };
      xhr.onload = function () {
        var d = {}; try { d = JSON.parse(xhr.responseText); } catch (_) { d = {}; }
        if (xhr.status === 201 && d.id) {
          a.state = "ready"; a.id = d.id; a.media = d.media; a.raw = d.raw; a.size = d.size || a.size; a.isImage = d.media === "image"; a.xhr = null; a.pct = 100;
          paintAtt(a); refreshAtts();
        } else attFail(a, d.error || "Gagal mengunggah (HTTP " + xhr.status + ").", xhr.status >= 500 || xhr.status === 0);
      };
      xhr.onerror = function () { attFail(a, "Koneksi terputus saat mengunggah.", true); };
      xhr.ontimeout = xhr.onerror;
      xhr.send(a.file);
    }
    function addFiles(list) {
      Array.prototype.slice.call(list || []).forEach(function (f) {
        if (!f) return;
        var a = { key: ++attSeq, file: f, name: f.name || "berkas", size: f.size, state: "uploading", pct: 0, id: null, raw: null, err: "", media: null,
                  isImage: /^image\/(png|jpeg|gif|webp)$/.test(f.type) };
        atts.push(a); attBox.appendChild(attChip(a));
        if (!f.size) attFail(a, "Berkas kosong (atau folder; folder tidak bisa dilampirkan).", false);
        else if (maxFile && f.size > maxFile) attFail(a, "Melebihi batas " + fmtBytes(maxFile) + " per berkas.", false);
        else upload(a);
      });
      refreshAtts();
    }
    function removeAtt(a) {
      if (a.xhr) { try { a.xhr.abort(); } catch (_) { /* abaikan */ } }
      var i = atts.indexOf(a); if (i >= 0) atts.splice(i, 1);
      if (a.el && a.el.parentNode) a.el.parentNode.removeChild(a.el);
      if (a.state === "ready" && a.id) {                                // buang juga dari server (belum pernah dikirim)
        fetch("/analyses/" + enc(aid) + "/files/" + enc(a.id) + "/delete", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf } }).catch(function () { /* dibersihkan otomatis nanti */ });
      }
      refreshAtts(); input.focus();
    }
    function clearAtts() { atts.forEach(function (a) { if (a.el && a.el.parentNode) a.el.parentNode.removeChild(a.el); }); atts = []; refreshAtts(); }
    function renderSentAtts(art, list) {
      var box = document.createElement("div"); box.className = "msg-atts"; box.setAttribute("role", "list"); box.setAttribute("aria-label", "Lampiran");
      list.forEach(function (a) {
        var isImg = a.media === "image", b = document.createElement("button"); b.type = "button"; b.setAttribute("role", "listitem");
        b.className = isImg ? "att-img" : "file-chip";
        b.setAttribute("data-file-view", ""); b.setAttribute("data-file-id", String(a.id)); b.setAttribute("data-file-name", a.name);
        b.setAttribute("data-file-media", a.media || "binary"); b.setAttribute("data-file-size", String(a.size)); b.title = a.name;
        if (isImg) { b.setAttribute("aria-label", "Lihat gambar " + a.name); var im = document.createElement("img"); im.alt = ""; im.src = a.raw; b.appendChild(im); }
        else {
          b.appendChild(svgIcon(fileKind(a.name, a.media), 16));
          var n = document.createElement("span"); n.className = "file-chip-name"; n.textContent = a.name; b.appendChild(n);
          var z = document.createElement("span"); z.className = "muted hint"; z.textContent = fmtBytes(a.size); b.appendChild(z);
        }
        box.appendChild(b);
      });
      art.appendChild(box);
    }
    // Komposer lampiran bersifat opsional: bila elemennya tidak ada, chat teks tetap berfungsi penuh.
    var composerOk = !!(attBox && attBtn && fileInput && attWarn && chatMain && dz);
    if (composerOk) {
    attBtn.addEventListener("click", function () { fileInput.click(); });
    fileInput.addEventListener("change", function () { addFiles(fileInput.files); fileInput.value = ""; });
    if (modelEl) modelEl.addEventListener("change", refreshAtts);
    input.addEventListener("paste", function (e) {                      // tangkapan layar / berkas dari papan klip
      var cd = e.clipboardData;
      if (!cd || !cd.files || !cd.files.length || busy) return;
      e.preventDefault();
      var stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      addFiles(Array.prototype.map.call(cd.files, function (f, i) {
        if (f.name && !/^image\.(png|jpe?g|gif|webp)$/i.test(f.name)) return f;
        var ext = (f.type.split("/")[1] || "png").replace("jpeg", "jpg");
        try { return new File([f], "tangkapan-" + stamp + (i ? "-" + (i + 1) : "") + "." + ext, { type: f.type }); } catch (_) { return f; }
      }));
    });
    var dragDepth = 0;
    function hasFiles(e) { var t = e.dataTransfer && e.dataTransfer.types; return !!t && Array.prototype.indexOf.call(t, "Files") >= 0; }
    chatMain.addEventListener("dragenter", function (e) { if (!hasFiles(e)) return; e.preventDefault(); if (busy) return; dragDepth++; dz.hidden = false; });
    chatMain.addEventListener("dragover", function (e) { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = busy ? "none" : "copy"; });
    chatMain.addEventListener("dragleave", function (e) { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dz.hidden = true; });
    chatMain.addEventListener("drop", function (e) { if (!hasFiles(e)) return; e.preventDefault(); dragDepth = 0; dz.hidden = true; if (!busy) addFiles(e.dataTransfer.files); });
    window.addEventListener("dragover", function (e) { if (hasFiles(e)) e.preventDefault(); });      // jangan membuka berkas yang jatuh di luar area
    window.addEventListener("drop", function (e) { if (hasFiles(e)) { e.preventDefault(); dragDepth = 0; dz.hidden = true; } });
    }   // composerOk

    function send(text, retryAtts) {
      text = String(text || "").trim();
      var sent = retryAtts || readyAtts();
      if ((!text && !sent.length) || busy) return;
      if (!retryAtts && (uploading() || visionBlocked())) return;
      lastUserText = text;
      if (sugg) sugg.hidden = true;
      var u = addMsg("user", "Anda");
      if (sent.length) renderSentAtts(u, sent);
      if (text) { var ub = document.createElement("div"); ub.className = "msg-body msg-plain"; ub.textContent = text; u.appendChild(ub); }
      input.value = ""; grow(); setBusy(true); statusEl.textContent = "Mengirim…"; scrollDown(true);

      var asst = addMsg("assistant", "Asisten"), toolsBox = null, toolsList = null, toolsSummary = null, bodyEl = document.createElement("div"), raw = "", pending = false;
      var typing = document.createElement("div"); typing.className = "typing"; typing.setAttribute("aria-hidden", "true");
      typing.appendChild(document.createElement("span")); typing.appendChild(document.createElement("span")); typing.appendChild(document.createElement("span"));
      bodyEl.className = "msg-body"; asst.appendChild(typing); asst.appendChild(bodyEl);
      var t0 = Date.now(), nSteps = 0, running = 0;
      function setTyping(on) { if (on && !typing.parentNode) asst.insertBefore(typing, bodyEl); else if (!on && typing.parentNode) typing.parentNode.removeChild(typing); }
      function ensureTools() {
        if (toolsBox) return;
        toolsBox = document.createElement("details"); toolsBox.className = "msg-tools is-running"; toolsBox.open = true;
        toolsSummary = document.createElement("summary"); toolsList = document.createElement("ul"); toolsList.className = "tsteps";
        toolsBox.appendChild(toolsSummary); toolsBox.appendChild(toolsList); asst.insertBefore(toolsBox, typing.parentNode ? typing : bodyEl);
      }
      function sumText() { toolsSummary.textContent = "Langkah tool (" + nSteps + ")" + (running ? " · bekerja…" : ""); }
      var stepById = {};
      function paint() {                                   // render ulang dibatasi ~8x/detik agar streaming tidak berat
        if (pending) return; pending = true;
        setTimeout(function () { pending = false; renderMarkdown(raw, bodyEl, { analysisId: aid, citations: {} }); scrollDown(false); }, 120);
      }

      var payload = { text: text, session_id: sessionId ? parseInt(sessionId, 10) : null };
      if (sent.length) payload.attachment_ids = sent.map(function (a) { return a.id; });
      if (modelEl && modelEl.value) payload.model = modelEl.value;
      fetch("/analyses/" + enc(aid) + "/chat/send", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(payload) })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (!res.ok) {
            log.removeChild(asst); setBusy(false); statusEl.textContent = "";
            if (sent.length && !retryAtts) {                           // kembalikan ke kotak pesan agar bisa diperbaiki (mis. ganti model) lalu kirim lagi
              log.removeChild(u); input.value = text; grow(); updateSend();
              if (attWarn) { attWarn.textContent = res.d.error || "Gagal mengirim pesan."; attWarn.hidden = false; } input.focus(); return;
            }
            fail(res.d.error || "Gagal mengirim pesan.", lastUserText, sent); return;
          }
          if (sent.length && !retryAtts) clearAtts();                  // lampiran sudah pindah ke gelembung pesan
          sessionId = String(res.d.session_id); root.setAttribute("data-session-id", sessionId);
          history.replaceState(null, "", "?s=" + sessionId);
          statusEl.textContent = "Asisten bekerja…";
          es = new EventSource(res.d.stream);
          var finished = false;
          es.addEventListener("delta", function (e) { setTyping(false); raw += JSON.parse(e.data).text; paint(); });
          es.addEventListener("tool_start", function (e) {
            var d = JSON.parse(e.data); ensureTools(); setTyping(false);
            var st = makeStep(d.name, d.args || ""); stepById[d.id] = { step: st, t0: Date.now() };
            toolsList.appendChild(st.li); nSteps++; running++; sumText(); scrollDown(false);
            statusEl.textContent = "Memanggil " + d.name + "…";
          });
          es.addEventListener("tool_end", function (e) {
            var d = JSON.parse(e.data), rec = stepById[d.id];
            if (rec) { rec.step.done(!!d.ok, d.summary || (d.ok ? "ok" : "galat"), Date.now() - rec.t0); running = Math.max(0, running - 1); sumText(); }
            if (!running && !raw) setTyping(true);
            scrollDown(false);
          });
          var cardsBox = null;
          function cards() {
            if (!cardsBox) { cardsBox = document.createElement("div"); cardsBox.className = "fcards"; cardsBox.setAttribute("aria-label", "Berkas yang dibuat asisten"); asst.appendChild(cardsBox); }
            return cardsBox;
          }
          es.addEventListener("file", function (e) { setTyping(false); upsertFileCard(cards(), aid, JSON.parse(e.data)); scrollDown(false); });
          es.addEventListener("final", function (e) {
            finished = true; var d = JSON.parse(e.data);
            (d.files || []).forEach(function (f) { upsertFileCard(cards(), aid, f); });
            var text = d.content || ""; raw = text; setTyping(false);
            renderMarkdown(text, bodyEl, { analysisId: aid, citations: citeMap(d.citations) });
            if (toolsBox) {
              toolsBox.open = false; toolsBox.className = "msg-tools";
              toolsSummary.textContent = d.tools + " langkah tool · " + fmtDur(Date.now() - t0);
            }
            var foot = addActions(asst, function () { return raw; });
            var meta = document.createElement("div"); meta.className = "msg-meta";
            meta.textContent = d.steps + " langkah · giliran ≈ Rp" + Number(d.turn_idr).toFixed(2) + " · sesi ≈ Rp" + Number(d.session_idr).toFixed(2);
            foot.appendChild(meta);
            var notes = { max_steps: "Berhenti di batas langkah (AI_MAX_STEPS).", budget: "Anggaran habis.", cancelled: "Dihentikan.", error: "Terjadi galat.",
                          tool_budget: "Batas total data tool giliran ini tercapai; jawaban disusun dari yang sudah dibaca." };
            if (d.stopped !== "done" && notes[d.stopped]) {
              var n = document.createElement("div"); n.className = "msg-note";
              var nt = document.createElement("span"); nt.textContent = notes[d.stopped] + (d.error ? " " + d.error : ""); n.appendChild(nt);
              if (d.stopped === "max_steps" || d.stopped === "tool_budget") {
                var cb = document.createElement("button"); cb.type = "button"; cb.className = "btn btn-ghost btn-sm"; cb.textContent = "Lanjutkan";
                cb.addEventListener("click", function () { cb.disabled = true; send("lanjutkan", []); });
                n.appendChild(cb);
              } else if (d.stopped === "error") {
                var rb = document.createElement("button"); rb.type = "button"; rb.className = "btn btn-ghost btn-sm"; rb.textContent = "Coba lagi";
                rb.addEventListener("click", function () { rb.disabled = true; send(lastUserText || "Lanjutkan", []); });   // lampiran pesan itu sudah tersimpan di riwayat
                n.appendChild(rb);
              }
              asst.insertBefore(n, foot);
            }
            updateBudget(d.budget);
            statusEl.textContent = "Biaya giliran ≈ Rp" + Number(d.turn_idr).toFixed(2) + " · sesi ≈ Rp" + Number(d.session_idr).toFixed(2) + " · " + d.steps + " langkah";
            scrollDown(true);
          });
          es.addEventListener("end", function () { if (es) es.close(); es = null; setTyping(false); setBusy(false); input.focus(); if (!finished) fail("Koneksi terputus sebelum jawaban selesai. Muat ulang halaman untuk melihat hasil tersimpan."); });
          es.onerror = function () {
            if (es && es.readyState === 2) { es = null; setTyping(false); if (!finished) { setBusy(false); fail("Koneksi stream terputus. Muat ulang halaman untuk melihat hasil tersimpan."); } }
          };
        })
        .catch(function () {
          setTyping(false); setBusy(false); statusEl.textContent = "";
          if (sent.length && !retryAtts && u.parentNode) {
            if (asst.parentNode) log.removeChild(asst);
            log.removeChild(u); input.value = text; grow(); updateSend();
            if (attWarn) { attWarn.textContent = "Koneksi gagal. Periksa jaringan lalu coba lagi."; attWarn.hidden = false; } return;
          }
          fail("Koneksi gagal. Periksa jaringan lalu coba lagi.", lastUserText, sent);
        });
    }

    form.addEventListener("submit", function (e) { e.preventDefault(); send(input.value); });
    input.addEventListener("input", function () { grow(); updateSend(); });
    input.addEventListener("keydown", function (e) { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(input.value); } });
    $all("[data-suggest]", root).forEach(function (b) { b.addEventListener("click", function () { send(b.getAttribute("data-suggest"), []); }); });
    function stop() {
      if (!sessionId) return;
      stopBtn.disabled = true; statusEl.textContent = "Menghentikan…";
      fetch("/analyses/" + enc(aid) + "/chat/cancel?s=" + enc(sessionId), { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf } })
        .finally(function () { stopBtn.disabled = false; });
    }
    stopBtn.addEventListener("click", stop);
    // Esc: tutup pratinjau dulu; bila tidak ada, hentikan giliran yang sedang berjalan.
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      var fv = fileViewer(); if (fv && fv.isOpen()) return;           // Esc menutup penampil berkas (ditangani <dialog>), bukan menghentikan giliran
      if (peek && !peek.hidden) { e.preventDefault(); closePeek(); }
      else if (busy) { e.preventDefault(); stop(); }
    });
    window.addEventListener("resize", function () { fitLog(); updateJump(); });
    if (window.ResizeObserver) {
      var ro = new window.ResizeObserver(function () { if (pinned) log.scrollTop = log.scrollHeight; updateJump(); });
      ro.observe(log);                                        // tinggi kotak log berubah (mis. kotak pesan tumbuh)
      if (log.firstElementChild) { /* isi diamati lewat MutationObserver di bawah */ }
    }
    if (window.MutationObserver) {
      new window.MutationObserver(function () { if (pinned) log.scrollTop = log.scrollHeight; updateJump(); })
        .observe(log, { childList: true, subtree: true, characterData: true });   // isi tumbuh: tetap menempel di dasar
    }
    grow(); updateSend(); fitLog(); scrollDown(true);
    // Font web memuat belakangan dan mengubah tinggi isi: sesuaikan lagi agar posisi "dasar" tetap benar.
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () { fitLog(); scrollDown(true); });
  }

  // HARUS setelah semua `var` di atas (CITE_RE, FILE_EXT, TOOL_LABELS, JAVA_KW/TOKEN_RE) terisi: `var` ter-hoist sebagai undefined, jadi
  // memanggil initChat lebih awal membuat render riwayat melempar galat dan listener form tidak pernah terpasang (Kirim = GET biasa).
  var chatRoot = $("[data-chat]");
  if (chatRoot) initChat(chatRoot);
})();
