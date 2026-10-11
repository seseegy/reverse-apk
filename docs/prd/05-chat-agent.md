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
| `get_overview` | – | ringkasan manifest, temuan statis, ringkasan AI aplikasi, hasil dekompilasi (method yang gagal di jadx) | – |
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
| `list_files` | – | lampiran pengguna (`lampiran/<id>`) dan berkas buatan AI (`hasil_ai/<path>`) | – |
| `write_file` | `path`, `content`, `mode=overwrite|append|create` | menulis berkas teks/kode ke folder berkas analisis (lihat "Lampiran & berkas buatan AI") | ekstensi teks saja, ukuran/kuota dari `.env` |
| `edit_file` | `path`, `old_string`, `new_string?` | mengganti SATU potongan persis di berkas buatan AI | gagal bila `old_string` tidak unik |
| `view_image` | `path` | melihat gambar lampiran (`lampiran/<id>`) atau gambar di APK (`apktool/res/...png`); hanya ditawarkan ke model bertanda `vision` | gambar ≤ `AI_MAX_IMAGE_MB` |

`read_file` juga membaca `lampiran/<id|nama>` dan `hasil_ai/<path>`.

Validasi: semua path dinormalisasi dan harus berada di bawah akar yang diizinkan (`work/<analysis_id>/` untuk APK, `files/<analysis_id>/` untuk lampiran/berkas AI); tolak `..`, symlink keluar, dan berkas biner besar.

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
| FR-5.11 | Pengguna melampirkan berkas/gambar di chat (tombol, seret-lepas, tempel tangkapan layar), dengan progres unggah dan pratinjau | P0 |
| FR-5.12 | AI membaca gambar (lampiran dan gambar dalam APK) pada model yang mendukung; model tanpa dukungan ditolak jelas, bukan gambar dibuang diam-diam | P0 |
| FR-5.13 | AI membuat berkas sungguhan (py, js, md, json, ...) di folder khusus per APK; tampil sebagai kartu Lihat/Unduh di jawaban dan di tab **Berkas**, unduh ZIP | P0 |
| FR-5.14 | Berkas pengguna/AI bertahan saat "Analisis ulang" dan terhapus bersama APK; kuota ukuran & jumlah per APK | P0 |

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
- **14 tool baca-saja** (`services/web/app/ai/tools.py`): `get_overview`, `get_manifest`, `list_packages`, `list_classes`, `search_code`, `get_class`, `get_method`, `find_xrefs`, `find_callees`, `class_info`, `find_paths`, `list_strings`, `get_findings`, `read_file`; ditambah `list_files`, `write_file`, `edit_file`, `view_image` (lihat "Lampiran & berkas buatan AI"). `analysis_id` terikat pada sesi (model tidak bisa menyebutnya); argumen divalidasi; nama tool di luar daftar ditolak.
- **Call graph nyata (FR-3.12)**: `find_xrefs` bukan lagi pencarian teks. Analyzer membaca smali (`analyzer/callgraph.py`) dan menyimpan hierarki class, method, field, panggilan, akses field, `new-instance`/`const-class`, dan string konstanta ke `index.sqlite` (tabel `cls`, `impl`, `msym`, `fsym`, `call`, `fref`, `cref`, `sref`; `meta.callgraph` = complete|partial|failed). Isi `invoke` hanya dibaca untuk class aplikasi; pustaka cukup kepala class-nya. Pemanggil dilaporkan dengan hubungan `langsung` / `lewat subclass` / `lewat supertype`.
- **`find_paths` jujur soal tebakan**: edge `langsung` (invoke nyata) berbobot 1; `dispatch` (override), `intent` (const-class ke komponen), dan `callback` (instance lambda/listener dibuat di method itu) adalah PERKIRAAN, berbobot lebih mahal dan dibatasi `max_approx` (bawaan 2; 0 = hanya invoke nyata). Dispatch ke >8 implementer dilewati (terlalu ambigu). Tidak ada jalur ≠ tidak terjangkau.
- **Tidak terlihat dari call graph**: refleksi, JNI, callback yang dipanggil framework, kode dinamis, dan isi pustaka pihak ketiga. Batas ini ikut dikirim di setiap hasil tool dan ada di prompt sistem. Analisis lama (indeks sebelum v2) perlu "Jalankan ulang analisis statis".
- **Pembungkus hasil tool tak bisa ditutup dari dalam APK**: `</hasil_tool` pada isi diganti escape JSON `<\/hasil_tool`.
- **Floor price router**: biaya satu request = `max(biaya token, floor_per_request)`; floor bawaan 0,01 kredit (`config/ai_models.json`), setara ±33 ribu token pada tarif 0,3/juta. Satu pertanyaan ke agent = banyak request (tiap selesai tool, model dipanggil lagi), jadi satu giliran sampai `AI_MAX_STEPS` (bawaan 100) langkah minimal 1 kredit (Rp300) = seluruh anggaran sesi bawaan. Giliran yang benar-benar memakai ratusan langkah akan berhenti karena anggaran; naikkan `AI_SESSION_BUDGET_CREDITS` bila perlu.
- **Redaksi secret sebelum kirim ke provider** memakai pola yang sama dengan analyzer (`AI_REDACT_SECRETS=1` bawaan). Berlaku untuk pesan pengguna, hasil tool, dan kueri yang dipantulkan. Nilai secret mentah tidak pernah diberikan ke model (`get_findings` tidak memuatnya).
- **Kode APK = data**: prompt sistem menyatakannya, setiap hasil tool dibungkus `<hasil_tool>` + peringatan, dan tidak ada tool tulis/shell/jaringan.
- **Sitasi** `path:baris` diverifikasi server (berkas dan baris harus ada); yang gagal tetap ditampilkan dengan label "tidak terverifikasi".
- **Pengaman loop**: batas langkah (`AI_MAX_STEPS`), batas total data tool per giliran, panggilan identik berulang dihentikan, anggaran dicek sebelum tiap panggilan; bila model membandel di langkah final, pengguna tetap mendapat pesan jelas (bukan gelembung kosong).
- **Skrip & `.md` dari AI**: hanya teks, dengan tombol Salin/Unduh (`text/plain`). Tidak ada penyimpanan di server dan tidak pernah dijalankan. Jawaban dirender lewat DOM (tanpa `innerHTML`); tautan dari model tidak pernah menjadi `<a>`.
- **Pilihan model per pesan** hanya dari `AI_MODEL`/`AI_MODEL_PRO` di `.env` (browser tidak bisa menyuntikkan slug sembarang).

- **Class yang tidak dihasilkan jadx** (mis. satu dex gagal didekompilasi, `smali_classes7`): `get_class`/`get_method` otomatis jatuh ke smali dan mengatakannya (`format: smali`, nomor baris = baris berkas smali, bisa disitir `apktool/smali_classes7/pkg/A.smali:123`); `read_file` membaca path apa pun persis seperti sitasi; `list_classes` memuat `hanya_smali`. Analyzer memindai smali class-class itu (secret, URL, string) dan mengindeksnya ke `search_code`, serta menambah temuan `coverage.jadx_missing_classes`. Artefak desugar (`$$ExternalSyntheticLambda`) dan stub `android/`/`java/` tidak dihitung sebagai hilang.
- **Pembacaan terhadap hasil kerja model sendiri**: bila `get_method` menemukan `Method not decompiled`, smali method itu diberikan sebagai gantinya.

## Lampiran & berkas buatan AI
**Penyimpanan.** Volume terpisah `files`, hanya dipasang di `web` (runner yang mem-parsing APK tak tepercaya dan worker tidak punya akses). Tata letak: `files/<analysis_id>/up/<token-acak>` untuk lampiran (nama asli HANYA di DB) dan `files/<analysis_id>/ai/<path>` untuk buatan AI. Metadata di tabel `analysis_file` + `message_file` (migrasi v4). Karena bukan di `work/<id>`, "Analisis ulang" tidak menghapusnya (diverifikasi di stack nyata); `ON DELETE CASCADE` + `rmtree` membersihkannya saat APK dihapus. Menghapus sesi chat TIDAK menghapus berkas (tampil di tab Berkas).

**Unggah.** `POST /api/files/upload?analysis=<id>` dengan badan mentah (bukan multipart, alasan sama dengan `/api/uploads`), nama di header `X-File-Name`, CSRF di `X-CSRF-Token`. Jenis berkas ditentukan dari ISI (magic bytes), bukan ekstensi/Content-Type klien: png/jpeg/gif/webp = gambar; teks (UTF-8 atau hampir tanpa karakter kontrol) = teks; sisanya biner. SVG/HTML diperlakukan sebagai teks dan tidak pernah disajikan inline. Unggahan yang tidak pernah dikirim (pending) dibersihkan setelah 6 jam.

**Yang dilihat model.** Gambar → bagian `image_url` bila model bertanda `"vision": true` di `config/ai_models.json` (perkiraan dari nama; `make ai-check` membuktikannya dengan satu permintaan kecil per model). Teks ≤ `AI_INLINE_ATTACH_CHARS` disertakan langsung; yang lebih besar dibaca lewat `read_file lampiran/<id>`. Biner: metadata + hex awal. Isi lampiran dibungkus `<lampiran>` (tag penutup dinetralkan), diperlakukan sebagai DATA tak tepercaya, dan teksnya melewati redaksi secret; **gambar tidak bisa diredaksi** (peringatan di UI). Pesan lama disusun ulang dengan fungsi yang sama saat riwayat dikirim, jadi model melihatnya persis seperti pertama kali. `view_image` pada gambar yang sudah inline tidak mengirimnya dua kali.

**Menulis berkas.** Satu-satunya tool yang menulis. Path dari model divalidasi ketat (`userfiles.clean_ai_path`: tanpa `..`/absolut/titik awal/spasi, maks 5 tingkat, ekstensi teks saja; 80 ribu masukan acak/mutasi di-fuzz), ditulis atomik (tmp + fsync + `os.replace`), tidak mengikuti symlink, dan tidak pernah dijalankan. Berkas besar ditulis bertahap (`mode=append`) karena satu panggilan dibatasi `AI_MAX_OUTPUT_TOKENS`; JSON argumen yang terpotong menghasilkan petunjuk itu. Path sama = revisi baru.

**Batas (semua dari `.env`, infrastruktur, bukan batas kemampuan AI):** `ATTACH_MAX_MB` (25; juga dipakai Caddy), `FILES_QUOTA_MB` (1024), `FILES_MAX_COUNT` (2000), `AI_MAX_IMAGE_MB` (10; gambar lebih besar tetap tersimpan, hanya tidak dikirim ke model), `AI_INLINE_ATTACH_CHARS` (16000). Tampilan UI: pratinjau teks 512 KB dan 1500 baris per potongan hanyalah batas tampilan (berkas utuh tetap bisa diunduh).

## UI/UX chat (peningkatan)
- **Lini masa langkah tool** dengan label manusiawi ("Baca LoginActivity (smali)", "Cari pemakai Cipher.doFinal"), status (centang/silang/berputar), ringkasan hasil, dan durasi per langkah; terlipat setelah selesai ("11 langkah tool · 38 dtk").
- **Sitasi sebagai chip** `NamaBerkas:baris` (path lengkap di tooltip dan label pembaca layar). Klik membuka **pratinjau kode** (±12 baris, baris target disorot) tanpa meninggalkan percakapan; Ctrl/Cmd+klik tetap membuka tab baru; Esc menutup.
- **Markdown lebih lengkap**: tabel (dapat digeser dan difokus), daftar bersarang, kutipan, garis. Semua tetap dibangun lewat DOM (tanpa `innerHTML`).
- **Indikator "berpikir"** sebelum token pertama (bukan gelembung kosong); tombol **Salin** per jawaban; tombol **Lanjutkan** saat berhenti di batas langkah, **Coba lagi** saat galat; baris meta (langkah, biaya).
- **Mengikuti isi baru** hanya sampai pengguna menggulir ke atas sendiri; tombol "Ke pesan terbaru" bila tertinggal.
- **Anggaran** harian ditampilkan sebagai meter (kuning ≥ 70%, merah ≥ 90%) dan diperbarui langsung dari event `final`.
- **Kotak pesan** tumbuh otomatis, Kirim nonaktif saat kosong, pintasan Enter / Shift+Enter / Esc (berhenti).
- **Aksesibilitas**: `aria-busy` dan `aria-live=off` selama streaming (pembaca layar tidak dibanjiri), status per langkah memakai label teks (bukan hanya warna/ikon), area tabel dapat difokus.
- **Ponsel**: daftar sesi terlipat otomatis, pratinjau menjadi *bottom sheet*, tab dapat digulir dan tab aktif dipusatkan. Memperbaiki overflow horizontal ±60px di semua halaman analisis pada layar sempit (grid `.page` satu-kolom melebar mengikuti daftar tab).

## Batas yang dikenakan pada AI
**Prinsip: hanya batas dari `.env` yang berlaku.** Tidak ada lagi batas jumlah/panjang yang ditulis di kode untuk apa yang boleh dilihat atau dilakukan AI:
- Pesan pengguna, riwayat percakapan, jumlah tool call per respons, dan panggilan identik berulang: **tanpa batas** (loop dibatasi `AI_MAX_STEPS`).
- Hasil tool (daftar paket/class/string/temuan/xref/callees/method/turunan, hit pencarian, kedalaman & node pencarian jalur, ukuran berkas yang dibaca, panjang argumen): **tanpa batas jumlah**. `limit` opsional dari model dihormati bila diisi.
- Satu-satunya pembatas ukuran: `AI_MAX_TOOL_CHARS` (per hasil, JSON tetap valid; bawaan 14.000). Total per giliran (`AI_MAX_TURN_TOOL_CHARS`) kini **tanpa batas** secara bawaan (0); isi nilai bila ingin membatasi. Satu-satunya pembatas waktu: `AI_TOOL_TIMEOUT` (detik, 0 = tanpa batas). Lalu `AI_MAX_STEPS`, `AI_MAX_OUTPUT_TOKENS`, anggaran harian/sesi.
- **Sengaja TIDAK dihapus** (bukan batas untuk AI, melainkan pengaman server dan penyaring kualitas): batas badan HTTP `chat/send` 4 MiB; batas jawaban provider 16 MiB (non-stream) / 32 MiB (stream) dan 3x retry; antrean peristiwa SSE; batas pembangunan indeks saat analisis (waktu 150 dtk, jumlah edge/string, ukuran smali; lihat `analyzer/callgraph.py`, `scan.py`); heuristik performa pencarian (`PROBE_LIMIT`: kata yang cocok di >300 berkas tidak diurutkan relevansi); penyaring dispatch `MAX_DISPATCH_FANOUT=8` pada `find_paths` (dispatch ke >8 implementer terlalu ambigu dan menghasilkan jalur palsu); rentang validasi nilai `.env` dilonggarkan jauh.
- Ukuran berkas yang dibaca AI tidak dibatasi (dibaca utuh ke memori; berkas biner ditolak dari 8 KB pertama tanpa dibaca penuh). Penjelajah kode di UI tetap memakai batas 2 MiB.

## Batasan
- Kualitas jawaban bergantung model; sitasi diverifikasi tetapi *kesimpulan* model tidak. Perlakukan sebagai petunjuk, bukan bukti.
- Seluruh riwayat teks dikirim (tanpa pemangkasan; anggaran `.env` yang menjaga biaya); hasil tool dari giliran lama tidak dikirim ulang. Gambar di riwayat ikut dikirim lagi tiap giliran (menambah token).
- Belum ada: ekspor PDF, tombol "jelaskan kode ini" di penampil kode (FR-5.7), memori lintas sesi.

## Pertanyaan terbuka
- [OPEN] Perlu tool `decompile_with_other_engine` (CFR/Fernflower) untuk method yang gagal di jadx?
- [OPEN] Memori lintas sesi (catatan pengguna per APK) diinjeksikan ke konteks?
