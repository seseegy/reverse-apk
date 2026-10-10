# 06 — Web UI

## Tujuan
Antarmuka web cepat dan fokus untuk satu pengguna: unggah, pantau, jelajahi, tanya.

## Design system
Sumber kebenaran visual ada di [`design-system/reverse-apk/MASTER.md`](../../design-system/reverse-apk/MASTER.md), dibuat dengan skill UI/UX Pro Max lalu disesuaikan dan diverifikasi kontrasnya. Override per halaman ada di `design-system/reverse-apk/pages/` (saat ini: `login.md`, `analysis-detail.md`). Bila ada override, aturannya menang atas MASTER.

Ringkasan keputusan:
- **Arah visual:** gelap, minimal, padat (variance 3, motion 3, density 7). Aksen hijau `#22C55E`, latar `#0F172A`, kartu `#1B2336`.
- **Tipografi:** JetBrains Mono untuk judul dan semua kode/path; IBM Plex Sans untuk isi teks.
- **Kontras:** teks ≥ 4,5:1; batas kontrol input ≥ 3:1 (`--color-border-control #64748B`, bukan border dekoratif bawaan yang hanya ~2,1:1).
- **Severity:** info / low / medium / high selalu berupa warna **+ label teks + ikon**.
- **Gerak:** hanya transisi 150–250 ms; hormati `prefers-reduced-motion`; tanpa animasi scroll-reveal.
- **Bukan landing page:** pola "FAQ/Documentation Landing" dari generator sengaja tidak dipakai.

## Halaman
| Halaman | Isi | Prioritas |
|---------|-----|-----------|
| **Login** | Login sederhana (lihat 07) | P0 |
| **Dashboard** | Daftar APK (ikon, nama, package, versi, tanggal, status, biaya), pencarian, filter tag, tombol Upload | P0 |
| **Upload** | Drag & drop, pernyataan otorisasi, opsi: aktifkan AI, deobf jadx, anggaran | P0 |
| **Detail Analisis** | Tab di bawah | P0 |
| ├ *Ringkasan* | Metadata, status pipeline, laporan AI, temuan utama | P0 |
| ├ *Manifest* | Permission, komponen, flag; sorot yang `exported`/berisiko | P0 |
| ├ *Temuan* | Tabel temuan, filter kategori/severity, mask secret | P0 |
| ├ *Kode* | Pohon package/class, penampil Java/smali dengan highlight, pencarian FTS, lompat ke xref | P0 |
| ├ *Jaringan* | Endpoint, domain, pinning, konfigurasi cleartext | P0 |
| ├ *Chat* | Percakapan dengan agent (05) | P0 |
| ├ *Biaya & Log* | Panggilan AI, token, biaya, log job | P0 |
| └ *Diff* | Bandingkan dengan versi lain | P1 |
| **Pengaturan** | Model, anggaran harian, retensi, kunci API (status saja) | P0 |

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-6.1 | Status job real-time (SSE/WebSocket) dengan tahap dan persentase kasar | P0 |
| FR-6.2 | Penampil kode: syntax highlight, nomor baris, salin tautan ke baris, tema gelap | P0 |
| FR-6.3 | Sitasi di laporan/chat membuka penampil kode pada lokasi tepat | P0 |
| FR-6.4 | Pencarian global dalam satu analisis (nama class, string, isi kode) | P0 |
| FR-6.5 | Secret di-mask default dengan tombol reveal; aksi reveal tercatat | P0 |
| FR-6.6 | Ekspor laporan Markdown/PDF | P1 |
| FR-6.7 | Peringatan eksplisit sebelum mengirim ke AI: "potongan kode akan dikirim ke DeepSeek" | P0 |
| FR-6.8 | Responsif untuk tablet; ponsel cukup bisa dibaca | P1 |
| FR-6.9 | Aksesibilitas: kontras sesuai design system, fokus terlihat (`focus-visible`), navigasi keyboard penuh, label ARIA, hitungan dinamis memakai `role="status"` | P0 |
| FR-6.10 | Upload tidak bergantung pada drag: selalu ada tombol "Pilih berkas" | P0 |
| FR-6.11 | Login mengizinkan password manager dan paste, ada tombol tampilkan password | P0 |
| FR-6.12 | Tahap pipeline tampil sebagai stepper dengan teks status, bukan spinner polos | P0 |

## Alur utama
1. Upload → centang otorisasi → (opsional) lihat estimasi biaya → mulai.
2. Pantau tahap pipeline di halaman detail.
3. Baca laporan, telusuri temuan, buka kode dari sitasi.
4. Tanya di tab Chat; klik sitasi untuk verifikasi.

## Teknologi (usulan)
- Frontend: **HTMX + Jinja + Tailwind** untuk MVP (sederhana, mudah di-deploy). Penampil kode: CodeMirror atau Monaco read-only.
- Alternatif: Next.js bila nanti butuh interaktivitas lebih tinggi.
- Backend: FastAPI.

## Kebutuhan non-fungsional
- NFR-6.1: Halaman dashboard < 1 detik untuk 500 APK.
- NFR-6.2: Penampil kode membuka class 5.000 baris tanpa membeku (virtualisasi/chunking).
- NFR-6.3: Konten dari APK/LLM selalu di-escape; CSP ketat (tanpa inline script dari data).
- NFR-6.4: Semua endpoint API butuh sesi/auth.

## Kriteria penerimaan
- Dari klik Upload hingga halaman detail dengan status live ≤ 3 klik.
- Klik sitasi membuka lokasi yang benar pada penampil kode.
- String berisi `<script>` di APK tampil sebagai teks, bukan dieksekusi.

## Pertanyaan terbuka
- [OPEN] HTMX vs SPA?
- [OPEN] Perlu mode terang selain gelap?
