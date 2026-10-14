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
> **Fitur build APK (PRD 09 Bagian B) — fondasi saja:** tabel `build` + state machine persetujuan manual (migrasi v5), keystore penanda
> tangan yang dibuat `make init`, dan toolchain `signer`. **Belum ada** daemon build/tanda tangan, antarmuka, maupun tool AI: aplikasi
> belum bisa membangun APK. Keystore belum dipasang ke layanan mana pun. Cadangkan `secrets/signing_keystore.*` setelah `make init`
> ([docs/deploy.md](docs/deploy.md#keystore-penanda-tangan-tahap-1)).

## Mulai cepat
```bash
make init        # buat .env + rahasia acak + keystore penanda tangan (CADANGKAN secrets/signing_keystore.*)
make password    # atur password admin
make up          # build & jalankan
make doctor      # periksa kesehatan
```
Panduan lengkap untuk VPS: [docs/deploy.md](docs/deploy.md).

## Perintah
`make help` menampilkan semuanya: `init`, `keystore` (buat keystore bila belum ada; tidak pernah menimpa), `keystore-info` (sidik jari, tanpa kata sandi), `password`, `up`, `down`, `restart`, `logs`, `ps`, `update`, `runner-selftest`, `signer-selftest`, `tools-check` (tabel versi alat build), `bench-selftest`, `net-check` (shell AI dan jaringannya, lihat `.env.example`), `doctor`, `test`.

Tes (tanpa Docker): `pip install -r services/web/requirements.txt -r tests/requirements.txt` lalu `make test`. CI menjalankannya di setiap PR.

Set berkas uji (zip bomb sintetis, APK besar, APK sampah): `scripts/make-test-apks.py --help`.
APK uji berisi kelemahan yang sengaja ditanam (untuk memverifikasi analisis statis): `python3 scripts/sample-apk/build.py`.

## Struktur
```
docker-compose.yml        Caddy, web, worker, runner, redis
deploy/Caddyfile          HTTPS otomatis + reverse proxy (batas body upload hanya di /api/uploads)
services/web              FastAPI + Jinja (login, dashboard, upload, detail analisis, SSE)
services/worker           Worker RQ: orkestrasi pipeline, ringkasan manifest, pemulihan setelah restart
services/runner           jadx + apktool; TANPA jaringan, read-only, non-root; menerima job lewat spool berkas
services/signer           zipalign + apksigner (Build-Tools dipin SHA-256); HANYA toolchain + selftest, profil Compose `build` (belum ada daemon; keystore belum dipasang ke image ini)
services/runner/analyzer  Analisis statis (indeks FTS5, deteksi secret/kripto/jaringan, sertifikat) — berjalan di runner
services/rvcore           Kode bersama (skema SQLite, protokol spool, utilitas berkas); hanya stdlib
design-system/            Token & aturan visual (UI/UX Pro Max)
docs/prd/                 Dokumen kebutuhan produk per bagian
scripts/init.sh           Penyiapan .env, secrets/, dan keystore penanda tangan
scripts/keystore.sh       Membuat/menampilkan keystore (keytool di image signer; tidak pernah menimpa)
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
- Image `signer` memverifikasi SHA-256 Android Build-Tools saat build. Pada tahap ini: tanpa jaringan, tanpa keystore di image/layanan (keystore hanya berkas di `secrets/` host, belum dipasang), tanpa volume, dan mati secara bawaan (profil `build`).
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
