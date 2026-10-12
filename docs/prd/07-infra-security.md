# 07 — Infra & Security

## Target lingkungan
- VPS UpCloud SG-SIN1, 4 vCPU / 8 GB RAM / 100 GB, Ubuntu, user `deploy` sudah dibuat dan SSH aktif.
- Deploy dengan Docker Compose. Domain opsional.

## Keputusan akses
Web diakses lewat browser pada domain publik **`revers3.my.id`** (disarankan subdomain `apk.revers3.my.id`) menuju VPS `94.237.78.162`. Karena terbuka ke internet, lapisan perlindungan berikut **wajib**: HTTPS (Caddy/Let's Encrypt), login aplikasi dengan rate limit, tidak ada endpoint tanpa auth (selain `/healthz` minimal), dan sebaiknya Cloudflare Access (login email/Google) di depan Caddy. Tailscale tetap opsional untuk SSH/administrasi.

## Komponen & jaringan
```
Internet ──(tidak ada port analisis publik)
Tailscale/Cloudflare ──► Caddy :443 ──► web (FastAPI) ──► redis
                                            │               │
                                            └── sqlite ◄── worker ──► job container (--network none)
                                                              └──► api.deepseek.com (hanya dari web/worker AI, bukan dari job container)
```
| Layanan | Tugas | Jaringan |
|---------|-------|----------|
| `caddy` | TLS, reverse proxy, header keamanan | publik / tailnet |
| `web` | API + UI | internal; egress ke DeepSeek |
| `worker` | Orkestrasi pipeline, panggilan AI | internal; egress ke DeepSeek |
| `redis` | Antrian | internal saja |
| `job-runner` (per job) | jadx/apktool/analisis | **tanpa jaringan** |

## Kebutuhan fungsional / operasional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-7.1 | `docker compose up -d` menjalankan seluruh stack; `restart: unless-stopped` | P0 |
| FR-7.2 | Konfigurasi lewat `.env` (tidak di-commit); `.env.example` di repo | P0 |
| FR-7.3 | Akses privat: **Tailscale** (rekomendasi, tanpa buka port) atau domain + Cloudflare Access / basic auth | P0 |
| FR-7.4 | Auth aplikasi: satu akun, password di-hash (argon2), sesi cookie `HttpOnly; Secure; SameSite=Strict`, rate limit login, CSRF untuk aksi mengubah state | P0 |
| FR-7.5 | Firewall `ufw`: izinkan SSH (dibatasi) dan 443 jika perlu; default deny | P0 |
| FR-7.6 | `fail2ban` untuk SSH; login SSH hanya dengan key | P0 |
| FR-7.7 | Backup terjadwal `db/` + laporan + catatan (bukan `jadx/` yang bisa dibangun ulang) ke lokasi terpisah; uji restore | P1 |
| FR-7.8 | Snapshot UpCloud sebelum upgrade besar | P1 |
| FR-7.9 | Pembersihan otomatis `work/` sesuai retensi (01 FR-1.10) dan peringatan disk > 80% | P1 |
| FR-7.10 | Log terstruktur dengan rotasi; secret ter-mask | P0 |
| FR-7.11 | Health check `/healthz` dan pemantauan sederhana (Uptime Kuma, opsional) | P1 |
| FR-7.12 | Skrip deploy: `git pull && docker compose up -d --build` terdokumentasi | P0 |

## Model ancaman (ringkas)
| Ancaman | Kontrol |
|---------|---------|
| APK berbahaya menyerang decompiler → kompromi host | Container job tanpa jaringan, non-root, cap-drop, seccomp, batas sumber daya, APK tidak dieksekusi |
| Akses tidak sah ke UI | Tailscale/Cloudflare Access + auth app + rate limit |
| Kebocoran API key DeepSeek | Hanya di env server; tidak ke browser/log; batas anggaran |
| Prompt injection dari isi APK | Kode = data; tool read-only; sanitasi output (04, 05) |
| XSS dari konten APK/LLM | Escape selalu, CSP ketat |
| Path traversal lewat tool/viewer | Normalisasi path, whitelist root `work/<id>` |
| Lampiran berbahaya (HTML/SVG/JS, polyglot) | Jenis dari isi, bukan ekstensi; hanya png/jpeg/gif/webp yang disajikan inline (CSP `sandbox`); selain itu hanya unduhan `octet-stream` + `nosniff`; pratinjau teks lewat `textContent` |
| AI menulis path/berkas berbahaya | `clean_ai_path` (allowlist ekstensi teks, tanpa `..`/absolut), tulis atomik, tanpa symlink, tidak pernah dijalankan; folder terpisah dari `work/` dan tidak terpasang di runner/worker |
| Gambar lampiran membocorkan rahasia ke provider | Tidak bisa diredaksi: peringatan di UI; teks lampiran diredaksi seperti pesan |
| Disk penuh lewat lampiran | `ATTACH_MAX_MB`, kuota ukuran & jumlah per APK, `MIN_FREE_GB`, pembersihan unggahan pending |
| Shell AI (`shell_run`, [09](09-bundles-and-workbench.md) Bagian C; **sudah ada, MATI secara bawaan**) | Shell hanya di `bench` (tanpa jaringan/rahasia, rootfs read-only, non-root, `cap_drop ALL`); tiap perintah dikurung Landlock ke satu analisis dan **ditolak bila pengurungan gagal**; `work/<id>/index` tertutup; keluaran/perintah diredaksi; audit `ai_shell_run` tanpa isi perintah; bukti isolasi `make bench-selftest` |
| *(Rencana, [09](09-bundles-and-workbench.md))* Build & tanda tangan APK | Persetujuan manual atas build; keystore hanya di `signer`; lihat tabel ancaman di 09 |
| Penyalahgunaan sebagai alat serang pihak ketiga | Tidak ada tool jaringan/eksekusi; kebijakan penggunaan (00 §7); audit log |
| Disk penuh / DoS diri sendiri | Batas ukuran upload, disk guard, kuota job, retensi |
| Supply chain (image, dependency, skill eksternal) | Pin versi + hash, build image terkontrol, skill di-vendor pada commit tertentu & ditinjau (04) |

## Docker socket
Worker perlu memulai container job. Jangan mount `/var/run/docker.sock` mentah ke service yang terpapar jaringan. [DIPUTUSKAN di M1] Dipilih **runner terpisah yang menerima job dari antrian lokal** (volume `spool`), tanpa Docker socket di service mana pun. Lihat 02-decompile-pipeline.md.

## Kebutuhan non-fungsional
- NFR-7.1: Pemulihan dari reboot VPS tanpa intervensi (≤ 2 menit stack kembali).
- NFR-7.2: Dua job paralel + web tidak melebihi 6,5 GB RAM total.
- NFR-7.3: Tidak ada service selain Caddy yang listen di antarmuka publik.
- NFR-7.4: Dependensi diaudit (pip-audit/Trivy) minimal sekali per rilis.

## Kriteria penerimaan
- `nmap` dari luar hanya menunjukkan port yang diizinkan (22 dibatasi, 443 bila domain; atau tidak ada bila Tailscale-only).
- Redis tidak bisa dijangkau dari luar host.
- Setelah `reboot`, aplikasi hidup kembali otomatis.
- Mencoba login 10× salah memicu rate limit.

## Pertanyaan terbuka
- [DIPUTUSKAN] Domain publik revers3.my.id (lihat "Keputusan akses").
- [OPEN] Lokasi backup (UpCloud Object Storage, rsync ke mesin lain)?
- [OPEN] Ukuran VPS: €52/bln cukup besar; resize ke 2 vCPU/4 GB setelah beban nyata terukur?
