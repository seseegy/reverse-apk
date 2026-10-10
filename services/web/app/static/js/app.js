// reverse-apk — JS minimal (tanpa inline script agar CSP tetap ketat).
(function () {
  "use strict";

  // Tampilkan/sembunyikan password. Nama aksesibel tetap; status lewat aria-pressed.
  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    var input = document.getElementById(btn.getAttribute("aria-controls"));
    if (!input) return;
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
    });
  });

  // Cegah kirim ganda dan beri umpan balik saat form dikirim.
  document.querySelectorAll("form[data-submit-lock]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit]");
      if (!btn) return;
      var label = btn.querySelector("span") || btn;
      label.textContent = "Memproses…";
      btn.disabled = true;
    });
  });

  // Jika halaman dipulihkan dari tombol Back (bfcache), muat ulang agar state tombol & token segar.
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) location.reload();
  });

  // Uji antrean sedang berjalan: muat ulang beberapa kali sampai hasilnya ada.
  if (document.querySelector("[data-poll]")) {
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      if (tries > 8) { clearInterval(timer); return; }
      location.reload();
    }, 2000);
  }
})();
