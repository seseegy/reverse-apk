/* Pengaturan AI: tampil/sembunyikan kunci + muat daftar model dari router (POST ke endpoint JSON).
   Tanpa pustaka; progresif — formulir tetap bisa disimpan manual tanpa skrip ini. */
(function () {
  "use strict";
  var form = document.getElementById("ai-settings-form");
  if (!form) return;

  var keyInput = document.getElementById("f-api-key");
  var toggle = document.getElementById("key-toggle");
  if (toggle && keyInput) {
    toggle.addEventListener("click", function () {
      var show = keyInput.type === "password";
      keyInput.type = show ? "text" : "password";
      toggle.setAttribute("aria-pressed", show ? "true" : "false");
      toggle.querySelector("span").textContent = show ? "Sembunyikan" : "Tampilkan";
      keyInput.focus();
    });
  }

  var btn = document.getElementById("models-btn");
  var status = document.getElementById("models-status");
  var list = document.getElementById("ai-model-list");
  if (!btn || !status || !list) return;

  btn.addEventListener("click", function () {
    var body = new URLSearchParams();
    body.set("csrf", form.querySelector('input[name="csrf"]').value);
    body.set("base_url", document.getElementById("f-base-url").value);
    body.set("api_key", keyInput ? keyInput.value : "");
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    status.textContent = "Menarik daftar model dari router…";
    status.classList.remove("is-error");
    fetch("/pengaturan/ai/models", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      credentials: "same-origin",
    })
      .then(function (r) {
        return r.json().then(function (d) { return { ok: r.ok, d: d }; });
      })
      .then(function (res) {
        if (!res.ok || !res.d || res.d.error) {
          throw new Error((res.d && res.d.error) || "Gagal menarik daftar model.");
        }
        list.innerHTML = "";
        res.d.models.forEach(function (m) {
          var o = document.createElement("option");
          o.value = m.id;
          if (m.context_window) o.label = "konteks " + Number(m.context_window).toLocaleString("id-ID") + " token";
          list.appendChild(o);
        });
        status.textContent = res.d.count + " model ditemukan di router. Klik bidang model utama lalu pilih dari daftarnya, atau ketik slug persisnya.";
      })
      .catch(function (err) {
        status.textContent = err.message || "Gagal menarik daftar model.";
        status.classList.add("is-error");
      })
      .finally(function () {
        btn.disabled = false;
        btn.removeAttribute("aria-busy");
      });
  });
})();
