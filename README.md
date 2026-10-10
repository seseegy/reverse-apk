# reverse-apk

Platform web **privat** (satu pengguna) untuk membongkar dan memahami APK Android dengan bantuan AI (DeepSeek).
Berjalan di VPS sendiri lewat Docker Compose.

> **Status:** M0 (fondasi) selesai — login, dashboard status sistem, antrean worker, dan image runner terisolasi.
> Upload dan analisis APK hadir di M1. Lihat [roadmap](docs/prd/08-roadmap.md).

## Mulai cepat
```bash
make init        # buat .env + rahasia acak
make password    # atur password admin
make up          # build & jalankan
make doctor      # periksa kesehatan
```
Panduan lengkap untuk VPS: [docs/deploy.md](docs/deploy.md).

## Perintah
`make help` menampilkan semuanya: `init`, `password`, `up`, `down`, `restart`, `logs`, `ps`, `update`, `runner-selftest`, `doctor`.

## Struktur
```
docker-compose.yml        Caddy, web, worker, redis (+ runner, profil "tools")
deploy/Caddyfile          HTTPS otomatis + reverse proxy
services/web              FastAPI + Jinja (login, dashboard)
services/worker           Worker RQ (antrean, heartbeat)
services/runner           jadx + apktool; dijalankan tanpa jaringan, read-only, non-root
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

## Dokumentasi
- [PRD](docs/prd/README.md) — kebutuhan produk
- [Design system](design-system/reverse-apk/MASTER.md) — acuan visual
- [Deploy](docs/deploy.md) — pemasangan di VPS

## Lisensi font
Lihat [services/web/app/static/fonts/LICENSES.md](services/web/app/static/fonts/LICENSES.md).
