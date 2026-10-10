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
| `find_xrefs` | `class` + `member?` ATAU `string`, `limit?` | pemanggil/pengakses NYATA dari call graph bytecode; atau method pemakai string konstanta | tanpa batas jumlah |
| `find_callees` | `class`, `method` | method dipanggil, field, string, class yang dibuat | tanpa batas jumlah |
| `class_info` | `class` | super chain, interface, turunan, method (native ditandai), status komponen manifest | tanpa batas jumlah |
| `find_paths` | `from_class`, `from_method?`, `to_class`, `to_method?`, `max_depth?`, `max_paths?`, `max_approx?` | jalur panggilan statis terbobot | tanpa batas kedalaman/node |
| `list_strings` | `filter?`, `kind?` | string dan lokasi | 100 hasil |
| `get_findings` | `category?` | temuan statis | – |
| `read_file` | `path`, `start_line?`, `end_line?` | berkas teks apa pun (Java, **smali semua class**, resource, manifest) dengan nomor baris; path sama persis dengan format sitasi | ukuran dibatasi, ada penanda lanjut |

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
- **14 tool baca-saja** (`services/web/app/ai/tools.py`): `get_overview`, `get_manifest`, `list_packages`, `list_classes`, `search_code`, `get_class`, `get_method`, `find_xrefs`, `find_callees`, `class_info`, `find_paths`, `list_strings`, `get_findings`, `read_file`. `analysis_id` terikat pada sesi (model tidak bisa menyebutnya); argumen divalidasi; nama tool di luar daftar ditolak.
- **Call graph nyata (FR-3.12)**: `find_xrefs` bukan lagi pencarian teks. Analyzer membaca smali (`analyzer/callgraph.py`) dan menyimpan hierarki class, method, field, panggilan, akses field, `new-instance`/`const-class`, dan string konstanta ke `index.sqlite` (tabel `cls`, `impl`, `msym`, `fsym`, `call`, `fref`, `cref`, `sref`; `meta.callgraph` = complete|partial|failed). Isi `invoke` hanya dibaca untuk class aplikasi; pustaka cukup kepala class-nya. Pemanggil dilaporkan dengan hubungan `langsung` / `lewat subclass` / `lewat supertype`.
- **`find_paths` jujur soal tebakan**: edge `langsung` (invoke nyata) berbobot 1; `dispatch` (override), `intent` (const-class ke komponen), dan `callback` (instance lambda/listener dibuat di method itu) adalah PERKIRAAN, berbobot lebih mahal dan dibatasi `max_approx` (bawaan 2; 0 = hanya invoke nyata). Dispatch ke >8 implementer dilewati (terlalu ambigu). Tidak ada jalur ≠ tidak terjangkau.
- **Tidak terlihat dari call graph**: refleksi, JNI, callback yang dipanggil framework, kode dinamis, dan isi pustaka pihak ketiga. Batas ini ikut dikirim di setiap hasil tool dan ada di prompt sistem. Analisis lama (indeks sebelum v2) perlu "Jalankan ulang analisis statis".
- **Pembungkus hasil tool tak bisa ditutup dari dalam APK**: `</hasil_tool` pada isi diganti escape JSON `<\/hasil_tool`.
- **Floor price router**: biaya satu request = `max(biaya token, floor_per_request)`; floor bawaan 0,01 kredit (`config/ai_models.json`), setara ±33 ribu token pada tarif 0,3/juta. Satu pertanyaan ke agent = banyak request (tiap selesai tool, model dipanggil lagi), jadi satu giliran 12 langkah minimal 0,12 kredit (Rp36). Anggaran sesi bawaan 1 kredit ≈ 8 giliran terpanjang; naikkan `AI_SESSION_BUDGET_CREDITS` bila perlu.
- **Redaksi secret sebelum kirim ke provider** memakai pola yang sama dengan analyzer (`AI_REDACT_SECRETS=1` bawaan). Berlaku untuk pesan pengguna, hasil tool, dan kueri yang dipantulkan. Nilai secret mentah tidak pernah diberikan ke model (`get_findings` tidak memuatnya).
- **Kode APK = data**: prompt sistem menyatakannya, setiap hasil tool dibungkus `<hasil_tool>` + peringatan, dan tidak ada tool tulis/shell/jaringan.
- **Sitasi** `path:baris` diverifikasi server (berkas dan baris harus ada); yang gagal tetap ditampilkan dengan label "tidak terverifikasi".
- **Pengaman loop**: batas langkah (`AI_MAX_STEPS`), batas total data tool per giliran, panggilan identik berulang dihentikan, anggaran dicek sebelum tiap panggilan; bila model membandel di langkah final, pengguna tetap mendapat pesan jelas (bukan gelembung kosong).
- **Skrip & `.md` dari AI**: hanya teks, dengan tombol Salin/Unduh (`text/plain`). Tidak ada penyimpanan di server dan tidak pernah dijalankan. Jawaban dirender lewat DOM (tanpa `innerHTML`); tautan dari model tidak pernah menjadi `<a>`.
- **Pilihan model per pesan** hanya dari `AI_MODEL`/`AI_MODEL_PRO` di `.env` (browser tidak bisa menyuntikkan slug sembarang).

- **Class yang tidak dihasilkan jadx** (mis. satu dex gagal didekompilasi, `smali_classes7`): `get_class`/`get_method` otomatis jatuh ke smali dan mengatakannya (`format: smali`, nomor baris = baris berkas smali, bisa disitir `apktool/smali_classes7/pkg/A.smali:123`); `read_file` membaca path apa pun persis seperti sitasi; `list_classes` memuat `hanya_smali`. Analyzer memindai smali class-class itu (secret, URL, string) dan mengindeksnya ke `search_code`, serta menambah temuan `coverage.jadx_missing_classes`. Artefak desugar (`$$ExternalSyntheticLambda`) dan stub `android/`/`java/` tidak dihitung sebagai hilang.
- **Pembacaan terhadap hasil kerja model sendiri**: bila `get_method` menemukan `Method not decompiled`, smali method itu diberikan sebagai gantinya.

## Batas yang dikenakan pada AI
**Prinsip: hanya batas dari `.env` yang berlaku.** Tidak ada lagi batas jumlah/panjang yang ditulis di kode untuk apa yang boleh dilihat atau dilakukan AI:
- Pesan pengguna, riwayat percakapan, jumlah tool call per respons, dan panggilan identik berulang: **tanpa batas** (loop dibatasi `AI_MAX_STEPS`).
- Hasil tool (daftar paket/class/string/temuan/xref/callees/method/turunan, hit pencarian, kedalaman & node pencarian jalur, ukuran berkas yang dibaca, panjang argumen): **tanpa batas jumlah**. `limit` opsional dari model dihormati bila diisi.
- Satu-satunya pembatas ukuran: `AI_MAX_TOOL_CHARS` (per hasil, JSON tetap valid) dan `AI_MAX_TURN_TOOL_CHARS` (total per giliran). Satu-satunya pembatas waktu: `AI_TOOL_TIMEOUT` (detik, 0 = tanpa batas). Lalu `AI_MAX_STEPS`, `AI_MAX_OUTPUT_TOKENS`, anggaran harian/sesi.
- **Sengaja TIDAK dihapus** (bukan batas untuk AI, melainkan pengaman server dan penyaring kualitas): batas badan HTTP `chat/send` 4 MiB; batas jawaban provider 16 MiB (non-stream) / 32 MiB (stream) dan 3x retry; antrean peristiwa SSE; batas pembangunan indeks saat analisis (waktu 150 dtk, jumlah edge/string, ukuran smali; lihat `analyzer/callgraph.py`, `scan.py`); heuristik performa pencarian (`PROBE_LIMIT`: kata yang cocok di >300 berkas tidak diurutkan relevansi); penyaring dispatch `MAX_DISPATCH_FANOUT=8` pada `find_paths` (dispatch ke >8 implementer terlalu ambigu dan menghasilkan jalur palsu); rentang validasi nilai `.env` dilonggarkan jauh.
- Ukuran berkas yang dibaca AI tidak dibatasi (dibaca utuh ke memori; berkas biner ditolak dari 8 KB pertama tanpa dibaca penuh). Penjelajah kode di UI tetap memakai batas 2 MiB.

## Batasan
- Kualitas jawaban bergantung model; sitasi diverifikasi tetapi *kesimpulan* model tidak. Perlakukan sebagai petunjuk, bukan bukti.
- Riwayat dibatasi (24 pesan / 60 ribu karakter); hasil tool dari giliran lama tidak dikirim ulang.
- Belum ada: ekspor PDF, tombol "jelaskan kode ini" di penampil kode (FR-5.7), memori lintas sesi.

## Pertanyaan terbuka
- [OPEN] Perlu tool `decompile_with_other_engine` (CFR/Fernflower) untuk method yang gagal di jadx?
- [OPEN] Memori lintas sesi (catatan pengguna per APK) diinjeksikan ke konteks?
