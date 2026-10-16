# reverse-apk

Platform web **privat** (satu pengguna) untuk membongkar dan memahami APK Android dengan bantuan AI (DeepSeek).
Berjalan di VPS sendiri lewat Docker Compose.

> **Status:** M4 (chat agent) tersedia — tanya kode APK dalam bahasa biasa; AI memakai tool baca-saja dan menyertakan sitasi yang
> diverifikasi. **Opsional** dan mati secara bawaan (isi `AI_*` di `.env`, lalu `make ai-check`). M3 (laporan otomatis) belum dikerjakan.
>
> Sebelumnya: M2 (analisis statis & penjelajah kode) selesai — selain upload & dekompilasi (M1), kini ada tab **Temuan**
> (secret, kripto, jaringan, manifest, tanda tangan), **Jaringan** (URL/domain/IP, network security config), dan **Kode**
> (pohon + penampil + pencarian ≤ 500 ms). Ringkasan AI (M3) menyusul.
> Lihat [roadmap](docs/prd/08-roadmap.md).
>
> **Fitur build APK (PRD 09 Bagian B) — fondasi + daemon penanda tangan (Tahap 2a):** tabel `build` + state machine persetujuan manual (migrasi v5), keystore penanda
> tangan yang dibuat `make init`, toolchain `signer`, dan kini **`signer-daemon`** yang menandatangani APK dengan keystore pemilik (`make signer-verify`). Pada 2a **belum ada** tahap `build`, antarmuka, maupun tool AI (2b di bawah menambahkan pipeline dan CLI-nya). Keystore dipasang ke layanan `signer` saja (read-only) dan berkasnya kini mode 644 di folder `secrets/` 700 (keputusan sadar, lihat
> [docs/deploy.md](docs/deploy.md#signer-daemon--akses-kunci-tahap-2a)). Cadangkan `secrets/signing_keystore.*` setelah `make init`
> ([docs/deploy.md](docs/deploy.md#keystore-penanda-tangan-tahap-1)). Uji Docker/cgroup untuk Tahap 2a menunggu VPS (daftar V0–V12 di deploy.md).
>
> **Build APK Tahap 2b (pipeline `bench → runner → signer`):** worker `run_build` (runner `apktool b` → signer → verifikasi → artefak bernama sistem → retensi `BUILD_KEEP`), CLI pemilik
> `docker compose exec -T web python -m app.buildctl` (analyze/init/shell/diff/request/approve/status/wait/cancel/artifact-info/delete), persetujuan manual terikat hash diff
> (HANYA lewat CLI; tidak ada rute web, tool AI, atau unduhan), `runner` memasang `bench` read-only, signer bekerja di volume privat `signwork` (penutupan R3/R10 di kode). Env baru
> `TIMEOUT_BUILD`/`TIMEOUT_SIGN`. **FR-9.24 (badging) dan FR-9.41 ditunda ke Tahap 5** — menunggu konfirmasi pemilik (PRD 09); prasyarat Tahap 5: unduh = salin-lalu-hash-lalu-bandingkan.
> **BELUM DIUJI:** semuanya di Docker/Compose nyata, cgroup, dan RQ/Redis nyata (sandbox memakai `fakeredis`; Docker di sandbox rusak, jadi compose hanya dibuktikan lewat tes yang mem-parse YAML).
> Bukti satu-perintah di VPS: `make verify-build` (BELUM DIUJI di Docker). Detail, tabel mount, dan gejala VPS: [docs/deploy.md](docs/deploy.md#build-apk-tahap-2b-pipeline-bench--runner--signer-status-terbukti-di-sandbox-belum-diuji-di-docker).
>
> **Build XAPK/APKS Tahap 3 (split APK):** `request`/`approve` kini juga untuk analisis XAPK dan APKS. Base dibangun ulang (apktool), SETIAP split lain dibuang tanda tangan lamanya lalu ditandatangani ulang dengan **kunci pemilik yang sama**; keluaran **format asal** (XAPK→XAPK, APKS→APKS) ditambah skrip teks `adb install-multiple` di folder build (aplikasi tidak memanggil adb; tanpa tautan unduh sampai Tahap 5). Sampel uji dibuat `scripts/make-test-bundles.py` (tanpa material kunci). `make verify-build` diperluas (12a–12f). **Batas jujur: tidak bisa dijanjikan 100%** untuk aplikasi dengan anti-tamper, packer, Play Integrity, atau pemeriksaan hash `.so`. **BELUM DIUJI:** Docker nyata, `adb install-multiple` pada perangkat Android 12+, XAPK/APKS nyata dari toko. **Cadangkan `secrets/signing_keystore.p12` + `secrets/signing_keystore_pass` DI LUAR VPS** — tanpa kunci itu, hasil build lama tidak bisa diperbarui di tempat. Detail: [docs/deploy.md](docs/deploy.md#build-xapkapks-tahap-3-split-apk-status-terbukti-di-sandbox-belum-diuji-di-docker-dan-di-perangkat).

## Mulai cepat
```bash
make init        # buat .env + rahasia acak + keystore penanda tangan (CADANGKAN secrets/signing_keystore.*)
make password    # atur password admin
make up          # build & jalankan (jalankan `make init` dan `make up` sebagai dua perintah)
make doctor      # periksa kesehatan
```
Panduan lengkap untuk VPS: [docs/deploy.md](docs/deploy.md).

## Perintah
`make help` menampilkan semuanya: `init`, `keystore` (buat keystore bila belum ada; tidak pernah menimpa), `keystore-info` (sidik jari, tanpa kata sandi), `keystore-access` (pastikan kunci terbaca kontainer signer: `secrets/` 700, berkas 644; hanya `chmod`), `password`, `up`, `down`, `restart`, `logs`, `ps`, `update`, `runner-selftest`, `signer-selftest`, `signer-verify` (bukti end-to-end penandatanganan dengan keystore pemilik; `BIG_MB=1000` menambah APK besar), `verify-build` (bukti end-to-end pipeline build 2b: satu tabel OK/GAGAL, membersihkan analisis ujinya sendiri), `tools-check` (tabel versi alat build), `bench-selftest`, `net-check` (shell AI dan jaringannya, lihat `.env.example`), `doctor`, `test`.

Tes (tanpa Docker): `pip install -r services/web/requirements.txt -r tests/requirements.txt` lalu `make test`. CI menjalankannya di setiap PR.

Set berkas uji (zip bomb sintetis, APK besar, APK sampah): `scripts/make-test-apks.py --help`.
APK uji berisi kelemahan yang sengaja ditanam (untuk memverifikasi analisis statis): `python3 scripts/sample-apk/build.py`.
XAPK/APKS uji (untuk `make verify-build`; tanpa material kunci): `python3 scripts/make-test-bundles.py xapk|apks|splits --help` (butuh `testdata/vulnsample.apk`).

## Struktur
```
docker-compose.yml        Caddy, web, worker, runner, redis
deploy/Caddyfile          HTTPS otomatis + reverse proxy (batas body upload hanya di /api/uploads)
services/web              FastAPI + Jinja (login, dashboard, upload, detail analisis, SSE)
services/worker           Worker RQ: orkestrasi pipeline, ringkasan manifest, pemulihan setelah restart
services/runner           jadx + apktool; TANPA jaringan, read-only, non-root; menerima job lewat spool berkas
services/signer           zipalign + apksigner (Build-Tools dipin SHA-256) + `signer-daemon` (Tahap 2a; menandatangani lewat antrean `signspool`); profil Compose `build`, aktif bila keystore ada
services/runner/analyzer  Analisis statis (indeks FTS5, deteksi secret/kripto/jaringan, sertifikat) — berjalan di runner
services/rvcore           Kode bersama (skema SQLite, protokol spool, utilitas berkas); hanya stdlib
design-system/            Token & aturan visual (UI/UX Pro Max)
docs/prd/                 Dokumen kebutuhan produk per bagian
scripts/init.sh           Penyiapan .env, secrets/, dan keystore penanda tangan
scripts/keystore.sh       Membuat/menampilkan keystore (keytool di image signer; tidak pernah menimpa); `access`/`check` memastikan kunci terbaca signer
scripts/signer-verify.sh  `make signer-verify`: bukti end-to-end penandatanganan (tabel OK/GAGAL yang bisa ditempel)
scripts/verify-build.sh   `make verify-build`: bukti end-to-end pipeline build APK + XAPK/APKS (satu tabel OK/GAGAL)
scripts/make-test-bundles.py  Pembuat sampel XAPK/APKS uji (stdlib; tanpa kunci; keluaran di testdata/, di-ignore Git)
docker-compose.keystore.yml  Berkas tambahan: memasang keystore HANYA ke `signer` (dimuat Makefile bila keystore ada)
```

## Alat & versi terkunci
apktool, jadx, dan Build-Tools (zipalign + apksigner) dipin dengan SHA-256 di Dockerfile dan diverifikasi saat build. JRE (apt Debian trixie) dan image dasar `python:3.12-slim-trixie` TIDAK dipin per-hash/digest (praktik yang sudah ada; lihat docs/deploy.md). Rincian (sumber, hash, lokasi, cara menaikkan versi): [docs/deploy.md](docs/deploy.md#alat-build--tanda-tangan-apk-b-1b). Cek di server: `make tools-check`.

| Alat | Versi terkunci | Image |
|------|----------------|-------|
| apktool (aapt2 dari dalam jar, dipasang di `/opt/apktool/aapt2`, disalin ke tmpfs khusus `/opt/aapt-exec`; `/tmp` runner tetap `noexec`) | 3.0.3 | runner |
| jadx | 1.5.6 | runner |
| Android SDK Build-Tools (`zipalign`, `apksigner`) | 37.0.0 | signer |
| OpenJDK JRE (headless, termasuk `keytool`) | 21 (apt Debian trixie) | runner, signer |

## Keamanan singkat
- Semua layanan berjalan non-root, `cap_drop: ALL`, `no-new-privileges`, rootfs read-only.
- Redis dan worker berada di jaringan `internal` (tanpa rute ke internet); hanya Caddy mempublikasikan port.
- Login: argon2id, sesi bertanda tangan (cookie `__Host-`, HttpOnly, SameSite=Strict), CSRF, pembatas percobaan per IP.
- Header CSP ketat, tanpa skrip/gaya inline, font di-host sendiri (tanpa permintaan ke pihak ketiga).
- Image `runner` memverifikasi SHA-256 jadx dan apktool saat build; APK tidak pernah dieksekusi.
- Image `signer` memverifikasi SHA-256 Android Build-Tools saat build. Tanpa jaringan, rootfs read-only, uid 10001, tmpfs `/tmp` `noexec`. Sejak Tahap 2a keystore dipasang ke `signer` SAJA (read-only, lewat `docker-compose.keystore.yml`; tidak ada di image maupun layanan lain); berkasnya mode 644 di folder `secrets/` mode 700 — kerahasiaan bertumpu pada folder (jangan `chmod 755 secrets`). Kata sandi tidak pernah di argv/env/log/hasil. Volume `builds` dan `signspool` dipasang; profil `build` diaktifkan Makefile hanya bila keystore ada.
- Hanya runner yang mem-parsing APK. Runner **tanpa jaringan, tanpa Redis/DB, tanpa Docker socket**; APK dimount read-only.
  Timeout, pembatalan, dan batas ukuran keluaran dipaksakan dengan mematikan seluruh process group tool.
- Upload: streaming ke disk (tidak ke RAM), validasi struktur ZIP tanpa dekompresi (rasio, jumlah entri, path traversal,
  entri ganda), SHA-256 untuk dedup, pernyataan otorisasi wajib dan dicatat di audit log.

## Dokumentasi
- [PRD](docs/prd/README.md) — kebutuhan produk
- [Design system](design-system/reverse-apk/MASTER.md) — acuan visual
- [Deploy](docs/deploy.md) — pemasangan di VPS

## Lisensi font
Lihat [services/web/app/static/fonts/LICENSES.md](services/web/app/static/fonts/LICENSES.md).
