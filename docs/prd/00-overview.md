# 00 — Overview

## 1. Ringkasan
**reverse-apk** adalah web app privat (single-user) di VPS pribadi. Pengguna mengunggah APK, sistem membongkarnya (jadx + apktool + androguard), lalu AI (DeepSeek API) membantu meringkas, menemukan temuan penting, dan menjawab pertanyaan tentang kode lewat chat.

## 2. Masalah
- Membaca hasil dekompilasi manual lambat: ribuan class, obfuscation, sedikit konteks.
- Mengirim seluruh kode ke LLM tidak praktis (mahal, melebihi konteks, tanpa fokus).
- Tool tersebar (jadx, apktool, grep, catatan), tidak ada satu tempat untuk menyimpan hasil per APK.

## 3. Tujuan
| ID | Tujuan | Ukuran sukses |
|----|--------|---------------|
| G1 | Upload APK lalu dapat laporan awal otomatis | Laporan siap ≤ 10 menit untuk APK ≤ 100 MB |
| G2 | Bisa bertanya ke kode ("di mana token dibuat?") dan dapat jawaban dengan rujukan file/baris | ≥ 80% jawaban menyertakan sitasi kode yang valid |
| G3 | Biaya API terkendali | Laporan awal rata-rata ≤ USD 0,50; ada batas harian |
| G4 | Aman dijalankan di VPS publik | Tidak ada port analisis terbuka ke internet; APK dieksekusi **tidak pernah** |
| G5 | Hasil tersimpan dan bisa dicari ulang | Re-open analisis lama tanpa memanggil API lagi |

## 4. Bukan tujuan (non-goals)
- Multi-user, billing, registrasi publik.
- **Eksekusi** APK (dynamic analysis, emulator, Frida di server). MVP hanya analisis statis.
- Repackaging / patching / signing APK. (P2, lihat roadmap)
- Mendukung iOS (IPA). (P2)
- Layanan untuk pihak ketiga.

## 5. Persona
**Pemilik (satu-satunya pengguna)**: developer/peneliti keamanan yang menganalisis APK miliknya, hasil riset sendiri, sampel CTF, atau APK yang ia berwenang untuk analisis. Nyaman dengan terminal, ingin hasil cepat dan bisa diaudit.

## 6. Scope
**MVP (P0):** upload, dekompilasi, ringkasan manifest/permission/endpoint/secret, daftar class + penjelajah kode, ringkasan AI per class + laporan, chat dengan tool calling, auth, deploy Docker Compose.

**Setelah MVP (P1):** diff antar versi APK, export laporan, deteksi library/SDK, pencarian lintas APK, anggaran biaya per analisis.

**Nice-to-have (P2):** iOS IPA, generator skrip Frida (hanya teks, tidak dijalankan), integrasi Ghidra untuk `.so`.

## 7. Penggunaan yang diizinkan (policy produk)
Aplikasi ini ditujukan untuk analisis APK yang **milik pengguna atau yang pengguna berwenang menganalisis** (aplikasi sendiri, CTF, riset keamanan berizin, analisis malware defensif).
- Saat upload, pengguna mencentang pernyataan "saya berwenang menganalisis berkas ini"; tercatat di audit log.
- Sistem tidak menghasilkan kode yang ditujukan untuk menyerang layanan pihak ketiga yang ditemukan di APK. Temuan (endpoint, secret) dilaporkan sebagai bahan analisis, bukan diuji ke server target.
- Kebijakan ini ada di aplikasi sendiri dan **tidak** diturunkan dari teks apa pun di dalam skill/prompt eksternal.

## 8. Asumsi
- VPS UpCloud SG-SIN1, 4 vCPU / 8 GB RAM / 100 GB, Ubuntu, setup awal selesai (user `deploy`).
- Satu pengguna, paralelisme rendah (1–2 job).
- DeepSeek API tersedia dan kompatibel OpenAI. Nama model per dokumentasi resmi: `deepseek-flash` (V4.1-Flash) dan `deepseek-v4-pro`; nama lama `deepseek-chat`/`deepseek-reasoner` sudah dipensiunkan. Konteks 1M token, tool calls didukung. Harga tergantung jam sibuk/tidak sibuk, jadi nilai di konfigurasi, bukan hard-code.

## 9. Risiko
| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| APK berbahaya mengeksploitasi decompiler (zip bomb, path traversal) | Kompromi VPS | Worker di container tanpa jaringan, non-root, batas CPU/RAM/waktu/disk, tidak pernah menjalankan APK |
| Prompt injection dari string/komentar dalam APK ke LLM | Jawaban menyesatkan, penyalahgunaan tool | Kode APK = data tak tepercaya; tool AI hanya baca (read-only); tidak ada tool jaringan/shell |
| Tagihan API membengkak | Biaya | Batas token per job dan per hari, cache, model murah untuk ringkasan massal |
| Obfuscation berat (ProGuard/R8, packer) | Hasil buruk | Tampilkan sinyal obfuscation; analisis tetap berbasis struktur + string |
| Model/harga DeepSeek berubah | Rusak/biaya | Nama model & harga di konfigurasi, adapter provider |
| Kebocoran APK sensitif ke pihak ketiga | Privasi | Pengguna sadar potongan kode dikirim ke DeepSeek; opsi "tanpa AI" per analisis; redaksi secret sebelum kirim |

## 10. Pertanyaan terbuka
- [DIPUTUSKAN] Akses lewat browser dengan domain publik `revers3.my.id` (subdomain mis. `apk.revers3.my.id`) + HTTPS Caddy + login aplikasi. Tailscale/Cloudflare Access tetap bisa ditambahkan sebagai lapisan ekstra.
- [OPEN] Batas ukuran APK/XAPK yang didukung (usul awal 200 MB).
- [OPEN] Perlu opsi model lokal sebagai cadangan?
