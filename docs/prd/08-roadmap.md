# 08 — Roadmap

Urutan kerja disusun supaya tiap milestone bisa dicoba langsung di VPS dan memberi nilai sendiri.

## M0 — Fondasi & infra (±2–3 hari)
- Struktur repo, Docker Compose (caddy, web, worker, redis), `.env.example`.
- Image worker dengan jadx + apktool + JDK ter-pin; uji `--network none`.
- Auth dasar, `/healthz`, akses lewat Tailscale/domain.
- **Selesai bila:** halaman login berjalan di VPS dan hanya bisa diakses lewat jalur privat; image worker mendekompilasi APK sampel.

## M1 — Upload & dekompilasi (MVP-1) ✅ selesai
- 01 (upload, validasi, dedup, anti zip-bomb) + 02 (antrian, pipeline, status live, timeout).
- UI: dashboard, upload, status job, tampilan manifest dasar.
- **Selesai bila:** upload APK → artefak `jadx/` dan `apktool/` tersimpan, status live tampil, job gagal tertangani.

## M2 — Analisis statis & penjelajah kode
- 03: manifest, sertifikat, string, endpoint, secret, crypto, obfuscation, indeks FTS.
- UI: tab Temuan, Jaringan, Kode (pohon + penampil + pencarian).
- **Selesai bila:** APK uji dengan secret/flag berisiko menghasilkan temuan yang benar dan bisa dicari ≤ 500 ms.

## M3 — Ringkasan & laporan AI
- 04: adapter DeepSeek, pemilihan class, map-reduce, laporan dengan sitasi, verifikasi sitasi, cache, anggaran, redaksi secret, pencatatan biaya.
- Vendor skill pack (modul terpilih, pin commit, LICENSE) + `apk-analyst/SKILL.md` adaptasi.
- **Selesai bila:** laporan AI untuk APK uji dengan ≥ 90% sitasi valid, biaya sesuai anggaran, analisis ulang = 0 panggilan API.

## M4 — Chat agent
- 05: tool read-only, loop agent, streaming, sitasi yang bisa diklik, batas langkah/anggaran.
- **Selesai bila:** skenario uji (base URL, alur login, lokasi kunci enkripsi) terjawab benar; tes injeksi lolos.

## M5 — Hardening & operasional
- 07: backup + uji restore, retensi, rotasi log, audit log, pemindaian dependensi, dokumentasi runbook.
- **Selesai bila:** checklist keamanan 07 lolos dan restore dari backup terbukti.

## Pasca-MVP (P1/P2)
- Diff versi APK, dukungan XAPK/split, deteksi SDK, ekspor PDF, pencarian lintas APK.
- Analisis native `.so` (Ghidra headless / radare2) dalam container terisolasi.
- iOS (IPA).

## Set APK uji (dibuat sejak M1)
- Aplikasi sampel buatan sendiri dengan: API key palsu tertanam, `debuggable=true`, cleartext traffic, WebView dengan JS interface, AES/ECB, string injeksi prompt, obfuscation R8.
- Satu APK besar (≥ 80 MB) untuk uji performa dan batas sumber daya.
- Satu zip-bomb sintetis untuk uji validasi.
- APK sampel CTF/open-source bebas lisensi.

## Metrik pemantauan setelah rilis
Durasi tiap tahap, tingkat gagal job, biaya per analisis, rasio cache hit, rasio sitasi valid, pemakaian RAM/disk.

## Pertanyaan terbuka (lintas-bagian)
Lihat bagian "Pertanyaan terbuka" di tiap dokumen. Yang paling memengaruhi M0: akses privat (Tailscale vs domain) dan cara memulai container job (socket-proxy vs runner terpisah).
