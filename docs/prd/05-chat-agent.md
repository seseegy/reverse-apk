# 05 — Chat Agent

## Tujuan
Memberi pengguna antarmuka tanya-jawab ke kode APK. Model menelusuri kode sendiri lewat tool **baca-saja**, dan setiap jawaban dapat diverifikasi ke sumbernya.

## Prinsip
1. **Read-only**: tool hanya membaca artefak analisis yang sudah ada.
2. **Tanpa efek samping**: tidak ada shell, jaringan, tulis berkas, atau eksekusi APK.
3. **Terikat sesi**: semua tool dibatasi pada satu `analysis_id`.
4. **Bisa diaudit**: setiap tool call dicatat dan terlihat di UI.

## Daftar tool
| Tool | Parameter | Hasil | Batas |
|------|-----------|-------|-------|
| `get_overview` | – | ringkasan manifest, temuan statis, ringkasan AI aplikasi | – |
| `get_manifest` | – | manifest ter-parse | – |
| `list_packages` | `prefix?` | package dan jumlah class | 200 baris |
| `list_classes` | `package`, `limit` | class + ukuran | 200 baris |
| `search_code` | `query`, `regex?`, `path?` | lokasi cocok + konteks | 50 hasil |
| `get_class` | `name`, `format=java|smali` | kode | dipotong ke N token, ada penanda lanjut |
| `get_method` | `class`, `method` | kode method | – |
| `find_xrefs` | `symbol` | pemanggil / pengguna | 100 hasil |
| `list_strings` | `filter?`, `kind?` | string dan lokasi | 100 hasil |
| `get_findings` | `category?` | temuan statis | – |
| `get_resource` | `path` | isi resource teks | ukuran dibatasi |

Validasi: semua path dinormalisasi dan harus berada di bawah `work/<analysis_id>/`; tolak `..`, symlink keluar, dan berkas biner besar.

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-5.1 | Chat per analisis, riwayat tersimpan | P0 |
| FR-5.2 | Loop agent dengan tool calling, batas langkah (default 12) dan batas token per giliran | P0 |
| FR-5.3 | Streaming jawaban; tool call tampil sebagai langkah yang bisa dibuka | P0 |
| FR-5.4 | Jawaban memuat sitasi `kelas#method` / `file:baris` yang bisa diklik untuk membuka di penjelajah kode | P0 |
| FR-5.5 | Sistem memverifikasi sitasi seperti di FR-4.4 | P0 |
| FR-5.6 | Model dapat dipilih per pesan (Flash default, Pro opsional) | P1 |
| FR-5.7 | Tombol "jelaskan kode ini" pada class/method yang sedang dibuka | P1 |
| FR-5.8 | Pencatatan biaya per sesi dan batas anggaran sesi | P0 |
| FR-5.9 | Ekspor percakapan ke Markdown | P1 |
| FR-5.10 | Saran pertanyaan awal berdasar temuan ("Bagaimana alur login?", "Di mana kunci enkripsi dibuat?") | P1 |

## Skill dalam chat
- Skill `apk-analyst` (04, FR-4.22) dimuat sebagai bagian konteks sistem: metodologi triase, daftar kata kunci pencarian (login, sign, encrypt, token, root, certificate, okhttp, webview), dan checklist pemeriksaan.
- Referensi tambahan (mis. checklist keamanan APK, penjelasan obfuscation) dimuat **bila relevan** dengan pertanyaan, bukan semuanya.
- Jika skill menyebut tool yang tidak ada di app (jadx CLI, Frida, adb), model harus menjawab bahwa aksi itu tidak tersedia dan menyarankan langkah manual, bukan berpura-pura mengeksekusi.

## Penanganan permintaan di luar kebijakan
Permintaan untuk menyerang layanan pihak ketiga (mis. mengeksploitasi endpoint yang ditemukan, menyusun muatan serangan untuk server milik orang lain) ditolak dengan singkat dan model menawarkan alternatif defensif/analitis. Analisis cara kerja, deskripsi kerentanan, dan saran perbaikan tetap dilayani.

## Kebutuhan non-fungsional
- NFR-5.1: Token pertama muncul ≤ 3 detik (non-thinking).
- NFR-5.2: Satu tool call ≤ 1 detik untuk operasi indeks.
- NFR-5.3: Output tool dibatasi agar satu giliran tidak melewati batas token yang ditetapkan.
- NFR-5.4: Output model di-render sebagai Markdown ter-sanitasi.

## Kriteria penerimaan
- Pertanyaan "di mana base URL API?" pada APK uji dijawab dengan lokasi benar dan sitasi valid.
- Upaya model memanggil path di luar `work/<id>` menghasilkan error tool dan tercatat.
- Batas langkah tercapai → agent berhenti dan merangkum yang sudah ditemukan.
- Instruksi tersembunyi di string APK tidak memicu tool call di luar daftar.

## Keputusan M4 (chat agent)
- **Tab Chat** per analisis; sesi, riwayat, dan biaya tersimpan (`chat_session`, `chat_message`, `ai_call`). Satu giliran aktif per sesi; tombol **Berhenti** membatalkan di tengah streaming.
- **11 tool baca-saja** (`services/web/app/ai/tools.py`): `get_overview`, `get_manifest`, `list_packages`, `list_classes`, `search_code`, `get_class`, `get_method`, `find_xrefs`, `list_strings`, `get_findings`, `get_resource`. `analysis_id` terikat pada sesi (model tidak bisa menyebutnya); argumen divalidasi; nama tool di luar daftar ditolak.
- **`find_xrefs` hanya perkiraan**: pencarian teks atas nama simbol, bukan call graph (FR-3.12 belum dikerjakan). Hasilnya selalu diberi label PERKIRAAN.
- **Redaksi secret sebelum kirim ke provider** memakai pola yang sama dengan analyzer (`AI_REDACT_SECRETS=1` bawaan). Berlaku untuk pesan pengguna, hasil tool, dan kueri yang dipantulkan. Nilai secret mentah tidak pernah diberikan ke model (`get_findings` tidak memuatnya).
- **Kode APK = data**: prompt sistem menyatakannya, setiap hasil tool dibungkus `<hasil_tool>` + peringatan, dan tidak ada tool tulis/shell/jaringan.
- **Sitasi** `path:baris` diverifikasi server (berkas dan baris harus ada); yang gagal tetap ditampilkan dengan label "tidak terverifikasi".
- **Pengaman loop**: batas langkah (`AI_MAX_STEPS`), batas total data tool per giliran, panggilan identik berulang dihentikan, anggaran dicek sebelum tiap panggilan; bila model membandel di langkah final, pengguna tetap mendapat pesan jelas (bukan gelembung kosong).
- **Skrip & `.md` dari AI**: hanya teks, dengan tombol Salin/Unduh (`text/plain`). Tidak ada penyimpanan di server dan tidak pernah dijalankan. Jawaban dirender lewat DOM (tanpa `innerHTML`); tautan dari model tidak pernah menjadi `<a>`.
- **Pilihan model per pesan** hanya dari `AI_MODEL`/`AI_MODEL_PRO` di `.env` (browser tidak bisa menyuntikkan slug sembarang).

## Batasan
- Kualitas jawaban bergantung model; sitasi diverifikasi tetapi *kesimpulan* model tidak. Perlakukan sebagai petunjuk, bukan bukti.
- Riwayat dibatasi (24 pesan / 60 ribu karakter); hasil tool dari giliran lama tidak dikirim ulang.
- Belum ada: ekspor PDF, tombol "jelaskan kode ini" di penampil kode (FR-5.7), memori lintas sesi.

## Pertanyaan terbuka
- [OPEN] Perlu tool `decompile_with_other_engine` (CFR/Fernflower) untuk method yang gagal di jadx?
- [OPEN] Memori lintas sesi (catatan pengguna per APK) diinjeksikan ke konteks?
