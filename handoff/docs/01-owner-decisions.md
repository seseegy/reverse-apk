# Keputusan pemilik — fitur "AI memodifikasi & membangun APK" (14 Okt 2026)

Sumber: jawaban langsung pemilik di sesi. Mengikat; mengalahkan default PRD 09 bila berbeda.

| # | Topik | Keputusan pemilik | Tafsiran yang dipakai (verifikasi saat implementasi) |
|---|---|---|---|
| 1 | Kunci tanda tangan | `make init` | Satu keystore per instalasi, dibuat `make init` (idempoten, tidak menimpa yang ada), dipasang ke layanan `signer` saja lewat compose `secrets:`. |
| 2 | Tujuan | Riset pribadi; "wajib berfungsi 100%" | Hanya untuk perangkat pemilik. "100%" tidak bisa dijanjikan untuk aplikasi dengan anti-tamper/packer/Play Integrity/hash `.so` — UI & README harus jujur; selain itu semua jalur (APK & XAPK) harus berfungsi end-to-end dan terbukti oleh skrip verifikasi. |
| 3 | Shell & jaringan AI | Dinyalakan, "tanpa batasan" | `AI_SHELL_ENABLED=1` bawaan. `AI_SHELL_NET_ALLOW` dibuka untuk semua host publik & port. DIPERTAHANKAN (usulan, minta konfirmasi pemilik): blokir alamat privat/loopback/metadata/CGNAT di egress, karena itu melindungi VPS pemilik sendiri dari SSRF, bukan membatasi riset. |
| 4 | bench-selftest | Lulus; Landlock ABI v4 tersedia | Isolasi bench terbukti di VPS pemilik. |
| 5 | Batas ukuran APK | Naik ke 1 GB | `MAX_UPLOAD_MB` & turunannya (Caddy, ZIP_MAX_ENTRY_MB, MAX_OUTPUT_MB, tmpfs/timeout runner) disesuaikan & diukur. |
| 6 | VPS | RAM 8 GB, disk 100 GB | Anggaran RAM ketat (total mem_limit ±6,4 GB). Build & analisis diserialkan di runner. |
| 7 | Anggaran AI | "default no limit" | Anggaran harian/sesi & `AI_MAX_STEPS` bawaan dibuat sangat besar/tidak membatasi; tetap bisa diturunkan lewat env. Tombol batal tetap ada. |
| 8 | Model | Bawaan `AI_MODEL`; pengguna boleh pilih `AI_MODEL_PRO` per pesan | Pertahankan mekanisme `_allowed_models` yang ada. |
| 9 | Persetujuan manual | Wajib | Tiap build harus disetujui pengguna di UI (CSRF + pernyataan wewenang, terikat SHA-256 diff). AI tidak punya tool setujui/tanda tangan/unduh. |
| 10 | Cakupan | APK dan XAPK harus berfungsi, "dinamis" | Bukan hanya base: semua split ikut diproses. Base → decode/ubah/build; split lain → buang sisa META-INF lama, zipalign, tanda tangan ulang dengan kunci yang SAMA (syarat Android untuk satu sesi instalasi). Keluaran sesuai format asal (APK→APK, XAPK→XAPK, APKS→APKS) + skrip `adb install-multiple`. |
| 11 | Unduhan | Pemilik bertanya maksudnya | Lihat penjelasan di chat: mengunduh APK/XAPK hasil build dari web ke perangkat untuk dipasang. Menunggu jawaban pemilik. |
| 12 | Retensi build | 10 per analisis | `BUILD_KEEP=10`. |
| 13 | Perubahan berisiko | Boleh mengubah apa saja, tanpa batasan; hasil AI harus maksimal | Tidak ada daftar larangan konten perubahan. Layar persetujuan TETAP menampilkan diff (transparansi, bukan pembatasan). |
| 14 | CI | Boleh | Tambah job CI build image `signer` & `runner` (+ yang bisa dijalankan tanpa jaringan). |
| 15 | Uji di VPS | Pemilik cukup dibuatkan skrip | Sediakan satu skrip (mis. `make verify-build` / `scripts/verify-build.sh`) yang menjalankan seluruh pembuktian di VPS dan mencetak SATU laporan ringkas OK/GAGAL yang bisa ditempel kembali. |

## Fakta teknis terkait
- Paket 1 (sedang berjalan, workflow wf_5afc13cc2454ab70, cabang `feat/signer-toolchain`): image `signer` (Build-Tools 37.0.0 dipin SHA-256), `signer-selftest`, profil compose `build`, `make tools-check`. TIDAK termasuk keystore/daemon/DB/AI/UI.
- Paket berikut harus berdiri di atas cabang itu.
- Sisa META-INF v1 lama pada split yang hanya ditandatangani ulang adalah risiko nyata (DUGAAN di laporan) → wajib diuji.

## Aturan kerja (ditegaskan pemilik, 15 Okt 2026) — mengikat orkestrator dan semua workflow
- Tahap 3, 4, 5, dan 6 masing-masing adalah SATU paket/PR. JANGAN dipecah menjadi sub-tahap (3a/3b dst) atas inisiatif sendiri. Bila ada tahap yang tampak terlalu berisiko untuk satu paket, TANYA pemilik dulu dan tunggu jawaban.
- Tahap 2 sudah dipecah (2a selesai; 2b sisa) atas inisiatif orkestrator; itu satu-satunya pengecualian.
- Perubahan kecil dan mekanis (mis. mengubah satu angka bawaan) dikerjakan LANGSUNG oleh orkestrator tanpa workflow. Workflow hanya untuk pekerjaan yang benar-benar besar atau berisiko.
- Perbaikan susulan (bug yang ditemukan pemilik saat menguji di VPS) BUKAN pemecahan tahap; itu wajar dan dikerjakan sebagai PR perbaikan terpisah.
