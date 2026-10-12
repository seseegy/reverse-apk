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

## Mulai cepat
```bash
make init        # buat .env + rahasia acak
make password    # atur password admin
make up          # build & jalankan
make doctor      # periksa kesehatan
```
Panduan lengkap untuk VPS: [docs/deploy.md](docs/deploy.md).

## Perintah
`make help` menampilkan semuanya: `init`, `password`, `up`, `down`, `restart`, `logs`, `ps`, `update`, `runner-selftest`, `bench-selftest`, `net-check` (shell AI dan jaringannya, lihat `.env.example`), `doctor`, `test`.

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
services/runner/analyzer  Analisis statis (indeks FTS5, deteksi secret/kripto/jaringan, sertifikat) — berjalan di runner
services/rvcore           Kode bersama (skema SQLite, protokol spool, utilitas berkas); hanya stdlib
design-system/            Token & aturan visual (UI/UX Pro Max)
docs/prd/                 Dokumen kebutuhan produk per bagian
scripts/init.sh           Penyiapan .env dan secrets/
```

## Keamanan singkat
- Semua layanan berjalan non-root, `cap_drop: ALL`, `no-new-privileges`, rootfs read-only.
- Redis dan worker berada di jaringan `internal` (tanpa rute ke internet); hanya Caddy mempublikasikan port.
- Login: argon2id, sesi bertanda tangan (cookie `__Host-`, HttpOnly, SameSite=Strict), CSRF, pembatas percobaan per IP.
- Header CSP ketat, tanpa skrip/gaya inline, font di-host sendiri (tanpa permintaan ke pihak ketiga).
- Image `runner` memverifikasi SHA-256 jadx dan apktool saat build; APK tidak pernah dieksekusi.
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
