# 10 — Penyimpanan (melihat, lalu membersihkan)

> **Status: Tahap 1 (melihat), Tahap 2 (membersihkan), dan Tahap 3 (penjelajah folder, hanya baca) SUDAH ADA** di halaman `/storage` (menu **Penyimpanan**) dan `/storage/jelajah`. Semua penghapusan lewat halaman konfirmasi dengan pratinjau; tidak ada penghapus berkas mentah.

## Tujuan
Pemilik bisa melihat **apa yang memakai disk**, seberapa besar, dan mana yang sudah tidak punya pemilik, lalu membersihkannya dari web. Sebelum halaman ini, satu-satunya cara menghapus adalah **Hapus APK** (menghapus APK asli, hasil dekompilasi, lampiran, dan riwayat sekaligus), dan tidak ada cara melihat ukurannya.

## Keputusan pemilik (12 Okt 2026)
| # | Keputusan |
|---|---|
| 1 | Penghapusan **bermakna**, bukan penghapus berkas mentah: tombol tahu apa yang dihapus dan akibatnya ("Bersihkan hasil dekompilasi: bebas 2,1 GB, bisa dibuat ulang"). Folder `db` **tidak punya tombol hapus**. |
| 2 | **Tanpa pembersihan otomatis** (retensi 01 FR-1.10 tidak dijalankan sendiri). |
| 3 | Hapus **permanen**, tanpa tempat sampah. |
| 4 | Docker, log, dan sistem (di luar jangkauan web) **hanya panduan perintah**. Aplikasi tidak memegang Docker socket dan tidak akan. |

## Apa yang terukur di VPS pemilik (12 Okt 2026)
`df -h /`: 99 GB total, 9,0 GB terpakai, 86 GB tersedia. `docker system df`: image 948 MB, **volume 1,03 GB** (seluruh data aplikasi), **cache build 2,69 GB** (1,99 GB bisa dibuang). Artinya saat ini **data aplikasi kecil**; yang terbesar adalah cache build Docker, yang tidak terlihat dari web. Fitur ini menjadi penting saat APK besar (batas 1 GB, lihat 09) mulai dianalisis: satu analisis bisa memakai beberapa GB.

## Prinsip
1. **Hanya jujur**: angka yang tampil adalah yang diukur. Yang diperkirakan diberi label "perkiraan dari catatan database".
2. **Ukuran di disk**, bukan jumlah byte isi (blok terpakai, seperti `du`). Terukur: byte isi lebih kecil 26% (apktool AntennaPod), 19% (NewPipe), 12% (jadx NexLoad) dari ruang yang benar-benar terpakai, karena ribuan berkas kecil memakai satu blok penuh. Tanpa ini halaman selalu tampak lebih kecil dari `df`/`du`.
3. **Halaman tidak pernah memindai disk sendiri.** Pemindaian dipicu tombol (POST + CSRF), dibatasi 3 juta berkas / 20 detik, dan hasilnya disimpan 2 menit di memori. Terukur ±200 ribu berkas/detik (sandbox pengembangan, cache disk hangat; di disk dingin lebih lambat).
4. **Tidak ada kesimpulan dari pemindaian yang berhenti dini.** Hasil parsial ditandai (angka = batas bawah); daftar "tanpa pemilik" tidak pernah berisi sesuatu yang sebenarnya punya pemilik.
5. **Yang baru dibuat bukan yatim.** Folder tanpa catatan DB yang berumur < 10 menit (diukur dari berkas terbaru di dalamnya) tidak dilaporkan sebagai yatim: worker membuat `work/<id>` sesaat sebelum barisnya terlihat. Ini pagar wajib sebelum tombol hapus ada.

## Tahap 1 — Melihat (SELESAI)
| ID | Kebutuhan | Status |
|----|-----------|--------|
| FR-10.1 | Halaman `/storage` + menu **Penyimpanan**; tautan "Lihat rincian penyimpanan" dari kartu Disk data di Beranda | ✅ |
| FR-10.2 | **Disk server**: bebas / terpakai / **cadangan sistem berkas** / dipakai aplikasi / hal lain (OS, Docker, log). Menjelaskan kenapa kartu Beranda mengukur seluruh disk | ✅ |
| FR-10.3 | **Isi penyimpanan aplikasi**: bilah komposisi (APK asli, hasil dekompilasi, lampiran & AI, database, sisa sementara) dengan legenda angka; penanda **bisa dibuat ulang** untuk hasil dekompilasi dan sisa sementara | ✅ |
| FR-10.4 | **Per APK**: ukuran APK asli / hasil dekompilasi / lampiran & AI / total, urut Nama / Hasil dekompilasi / Total (tautan, tanpa JavaScript); kolom **Di disk** setelah pemindaian; analisis berjalan ditandai "ukuran belum final" | ✅ |
| FR-10.5 | **Pemeriksaan konsistensi**: folder `work/` dan `files/` tanpa catatan, APK di `uploads/` tanpa catatan, berkas liar di `work/`, catatan APK tanpa berkas asli, catatan lampiran/hasil AI tanpa berkas; item baru dilaporkan terpisah | ✅ |
| FR-10.6 | **Panduan server**: `df`, `docker system df [-v]`, `docker builder prune --filter until=168h` dengan tombol Salin; peringatan jangan `docker system prune -a --volumes` / `docker volume prune` | ✅ |
| FR-10.7 | Dua sumber angka dipisah: **catatan DB** (instan, selalu ada) dan **disk** (atas permintaan) | ✅ |

### Perubahan terkait di luar halaman ini
- **Header**: menu atas kini tiga tautan. Isi header butuh ±400 px (dihitung dari lebar elemen yang terukur: merek 79, menu 58+52+95, tombol keluar, celah) sedangkan ponsel 320–414 px, sehingga **menu dapat digulir** di layar sempit, "Keluar" menjadi **ikon saja** (nama aksesibel tetap), dan menu otomatis menggulir ke halaman aktif. Terukur sebelum perbaikan: Beranda *sudah* meluber 72 px di 375 px; kini delapan halaman diuji pada 320/375/1280 px semuanya pas.

## Tahap 2 — Membersihkan (SELESAI)
Aksi bermakna, masing-masing dengan **pratinjau** ("akan menghapus N berkas, membebaskan X"), **konfirmasi**, **audit log**, CSRF, dan penolakan bila analisis sedang berjalan (`store.ACTIVE`):
| ID | Aksi | Akibat yang ditulis di UI |
|----|------|----|
| FR-10.8 | Bersihkan **hasil dekompilasi** satu analisis (**apktool dan jadx saja**; `index/`, `logs/`, `manifest.json` sengaja dipertahankan karena tab Temuan/Jaringan/pencarian memakainya, ±38 MB pada AntennaPod) | Bisa dibuat ulang lewat Analisis ulang. Tab Kode kosong dan AI tak bisa membaca kode sampai itu. (Diuji: ketujuh tab analisis tetap terbuka bila `work/<id>` hilang.) |
| FR-10.9 | Hapus **sisa tanpa pemilik** (folder `work/` / `files/` yatim, APK yatim, berkas liar) | Tidak ada catatan yang terkait; tidak bisa dibuat ulang. |
| FR-10.10 | Hapus **sisa unggahan sementara** (`.tmp`) | Unggahan yang terputus. |
| FR-10.11 | Bereskan **catatan tanpa berkas** (lampiran/hasil AI yang hilang) | Baris database dihapus; halaman Berkas berhenti menampilkannya. |
| FR-10.12 | **Hapus semuanya** per APK (sudah ada sebagai *Hapus APK*) | Permanen. |

Syarat teknis (dari temuan tahap 1):
- **Hapus bertahap**: folder dengan ratusan ribu berkas (hasil jadx sebuah APK 15 MB sudah 22 ribu berkas / 357 MB) dipindahkan dulu ke `.trash` (di akar yang sama, supaya `rename` atomik), lalu dihapus di belakang layar oleh `Reaper` (thread latar; sisa `.trash` setelah crash dilanjutkan saat startup). **Catatan izin (terukur)**: memindahkan sebuah *direktori* butuh izin tulis pada direktori itu sendiri, dan hasil jadx/apktool bisa berupa direktori `r-x`; sebagai non-root `rename` gagal dengan `PermissionError`. Karena itu izin direktori teratas dipulihkan dulu bila rename pertama gagal. Tes biasa tidak bisa menangkap ini (root mengabaikan izin), sehingga ada tes yang menjatuhkan hak ke `nobody`.
- Pemeriksaan "tanpa pemilik" **dijalankan ulang tepat sebelum menghapus** (bukan memakai hasil cache), karena keadaan bisa berubah sejak pemindaian terakhir.
- Hanya folder di bawah akar yang dikenal (`uploads`, `work`, `files`) dan nama yang cocok pola yang boleh dihapus; `db/` tidak pernah. Jalur memakai `resolve_under`/`safe_rmtree` yang sudah ada (tolak symlink, `..`).
- Setelah menghapus, angka yang ditampilkan adalah ukuran yang **diukur sebelum dipindah**; bukti pada data nyata: `du` melaporkan `work/` berkurang 407 MB, sama dengan yang dijanjikan (407 MB).

### Rancangan yang diterapkan (dan alasannya)
- **Verifikasi ulang tepat sebelum menghapus**, bukan memakai hasil pratinjau. Folder analisis dipindah **di dalam transaksi DB (`BEGIN IMMEDIATE`)** bersama pemeriksaan status, sehingga *Analisis ulang* dan klaim worker (yang juga transaksi tulis) tidak bisa menyelip di antaranya. Bila transaksi gagal setelah rename, folder **dikembalikan** (DB menganggap hasil masih ada, disk tidak boleh kosong).
- **Daftar yang dipratinjau = daftar yang boleh dihapus.** Form konfirmasi membawa nama eksplisit; yang tidak lagi memenuhi syarat (kini punya pemilik, baru dibuat, sudah hilang) **dilewati dan dilaporkan**, bukan dihapus. Folder yang muncul *sesudah* pratinjau tidak ikut.
- **Pertahanan berlapis**, tiap lapisan diuji sendiri (mutasi membuktikan): bentuk kunci di HTTP, pola nama (`[A-Za-z0-9._-]{1,200}`), keanggotaan dalam daftar kandidat, penolakan symlink dan jalur di luar akar di `_move_item`.
- **Aksi tak bisa dibatalkan** (sisa tanpa pemilik, sisa sementara, catatan) wajib kotak centang "Saya mengerti"; hasil dekompilasi (bisa dibuat ulang) tidak. Halaman konfirmasi adalah GET tanpa efek (aman di-refresh); penghapusan hanya lewat POST + CSRF.
- Audit gagal-tertutup: `storage_clean` dicatat dalam transaksi yang sama dengan penghapusan catatan/pemindahan.
- Setelah dibersihkan, tombol hanya tampil bila ada yang benar-benar bisa dibersihkan (`cleanable` = apktool+jadx, tanpa `index`), dan analisis aktif ditandai "sedang berjalan".
- Hasil terakhir ditampilkan **sekali** lewat variabel di memori (angka tidak lewat URL, tidak bisa dipalsukan).

## Tahap 3 — Penjelajah folder (SELESAI, hanya baca)
Halaman `/storage/jelajah` (tombol **Jelajahi folder…** di halaman Penyimpanan): daftar isi folder, **Lihat** (pratinjau teks) dan **Unduh**, untuk `uploads/`, `work/`, `files/`. **Tidak ada tombol hapus atau tulis**; penghapusan tetap hanya lewat aksi bermakna tahap 2. Ada tes yang membaca sumber `storage_browse.py` dan gagal bila memuat pemanggilan tulis/hapus.

| ID | Persyaratan |
|----|----|
| FR-10.13 | Daftar isi satu folder (tidak rekursif): folder dulu, nama menaik tanpa membedakan huruf besar/kecil; nama, ukuran **di disk**, waktu ubah. 200 entri per halaman (folder `res/` bisa berisi puluhan ribu berkas). |
| FR-10.14 | **Lihat**: pratinjau teks hingga 512 KB (dipotong dan ditandai bila lebih); berkas biner tidak ditampilkan isinya. Diisi lewat `textContent`, tidak pernah `innerHTML`. |
| FR-10.15 | **Unduh**: selalu `application/octet-stream` + `attachment`, CSP `default-src 'none'; sandbox`, `nosniff`, `no-store`. HTML tidak pernah disajikan inline, tidak ada pratinjau gambar. Isi dialirkan **tepat sebesar `Content-Length`** (berkas `logs/` bisa bertambah saat analisis berjalan). |
| FR-10.16 | Wajib login (halaman: alihkan ke `/login`; Lihat: JSON 401; Unduh: 401). |

### Aturan akses: daftar putih, bukan daftar hitam
Halaman ini menyajikan berkas dari disk lewat jalur pilihan pengguna, jadi aturannya sempit dan eksplisit:
- `uploads/`: hanya `<sha256>.apk` di tingkat atas. `.tmp`, `.trash`, berkas liar: tertutup.
- `work/<id>/`: hanya `apktool/`, `jadx/`, `logs/`, dan `manifest.json`. `<id>` harus angka biasa (tanpa nol di depan); `.trash`, `.tmp`, dan berkas liar tertutup.
- `files/<id>/`: hanya `up/` dan `ai/` (kategori yang dikenal `FileStore`).
- **`work/<id>/index/` DITUTUP.** Terukur: `findings.jsonl` (field `secret`) dan `index.sqlite` (tabel `code`) menyimpan nilai rahasia **mentah** (contoh: `AKIAIOSFODNN7EXAMPLE` tersimpan apa adanya di keduanya). Aplikasi sengaja hanya mengirim nilai rahasia lewat tombol "Tampilkan nilai" yang tercatat di audit (`secret_reveal`); penjelajah tidak boleh menjadi jalan pintas di sekitarnya.
- **`db/` tidak bisa dijelajahi** sama sekali (hanya ukurannya terlihat di halaman Penyimpanan).
- Entri yang ada di disk tetapi tertutup **tidak ditawarkan**, namun namanya dicatat dan UI menulis "N entri sengaja tidak ditampilkan", supaya pengguna tidak mengira hilang.
- Symlink tidak pernah ditawarkan dan tidak pernah diikuti. Nama dengan karakter kontrol atau lebih dari 255 karakter per komponen tidak ditawarkan.

### Rancangan yang diterapkan (dan alasannya)
- **Jalur dikirim lewat query** (`?akar=&jalur=&hal=`), bukan path-parameter. Terukur: Starlette/klien menormalkan `/x/1/../index` menjadi `/x/index` sebelum rute berjalan, dan mendekode `%2e%2e`, `%00`, `%5c`. Dengan query, jalur sampai apa adanya ke penjaga kita.
- **Empat lapis penjagaan, tiap lapis diuji sendiri**: (1) `_parts` menolak `..`, jalur mutlak, NUL, backslash, karakter kontrol, komponen >255, jalur >600; (2) `allowed()` (daftar putih di atas); (3) `resolve()` memakai `resolve_under` **dan** menuntut realpath sama dengan jalur yang diminta, sehingga symlink *di dalam* akar yang menunjuk ke folder tertutup (mis. `work/1/jadx -> work/1/index`) tidak bisa mengelak dari daftar putih; (4) `open_file` memakai `O_NOFOLLOW` dan memeriksa berkas biasa.
- Tabel biasa + remah roti `<ol>` (bukan widget pohon ARIA kustom yang rawan masalah fokus), tanpa modal baru. Ponsel (≤640 px): kolom tanggal disembunyikan dan tombol jadi ikon 44×44 px dengan `aria-label` memuat nama berkas.
- Pagar: pemindaian satu folder dibatasi 200.000 entri; bila lebih, daftar ditandai **tidak lengkap**.

### Bukti (diukur di sandbox, bukan di VPS)
- 134 tes baru (`tests/test_storage_browse.py`); seluruh suite 471 lulus dua kali berturut-turut; `pyflakes` bersih.
- **Uji mutasi: 33 mutasi, 27 tertangkap, 6 setara.** Awalnya 6 dari 18 mutasi di logika lolos; tiga di antaranya celah tes nyata (`O_NOFOLLOW`, penolakan symlink di `list_dir`, `db` di tabel akar) karena `resolve()` menutupinya sehingga lapisan di bawahnya tak pernah teruji. Ditambah tes per-lapisan (`resolve` diganti agar menyerahkan symlink) dan kini tertangkap. Enam mutan setara: tiga di logika (cek NUL, symlink di daftar, `resolve_under` yang None) ditutup tumpang-tindih oleh cek kontrol, `follow_symlinks=False`, dan perbandingan realpath; tiga di rute (`nosniff` dan `no-store` ganda) ditambahkan juga oleh middleware global di `main.py`. Pertahanan berlapis, bukan celah.
- Browser (Chromium) pada data nyata AntennaPod/NewPipe/NexLoad: 42 cek lulus tanpa galat JS/CSP, termasuk paginasi `res/drawable`, remah roti, Lihat teks dan biner, **unduhan APK 15.861.139 byte identik (SHA-256 sama)**, `index/` tak tampil dan URL langsung ke `index/`/`db/`/`..` ditolak dengan 404 tanpa kebocoran, tanpa luber horizontal di 375/768/1024/1440 px, target sentuh ≥44 px pada layar sentuh, fokus keyboard terlihat.
- **Bug yang hampir lolos**: draf pertama menawarkan nama non-UTF-8 dengan karakter pengganti. Tes logika lulus, tetapi diukur lewat HTTP satu berkas bernama `a\xffb.txt` membuat **seluruh halaman folder galat 500** (`UnicodeEncodeError` pada `urlencode` di template). Diperbaiki (entri dihitung, tidak ditawarkan) dan diuji sampai HTML; dua mutasi menyalakan tes itu.
- Cek browser pertama **melewatkan** dua masalah yang baru terlihat di tangkapan layar 375 px: nama berkas terhimpit satu-dua huruf per baris dan tombol terpotong (cek "tanpa luber" tidak menangkapnya karena teks membungkus). Diperbaiki (lihat atas).

### Keterbatasan yang diketahui
- **Berkas dengan nama bukan UTF-8 tidak bisa dibuka lewat penjelajah** (byte tak valid tidak bisa dijadikan alamat web). Tidak ditawarkan, tetapi **dihitung dan dijelaskan** ("N entri tidak ditampilkan karena namanya bukan teks UTF-8 yang valid"). Berkas itu tetap bisa dilihat lewat shell di VPS. Berkas jadx/apktool yang sah jarang bernama begitu; belum pernah ditemui di data uji.
- Di layar 320 px tabel masih bergulir horizontal sedikit (±9 px; wadahnya bisa difokus dan digulir) dan nama terpecah antar-huruf. Tidak diperbaiki lebih jauh.
- Ukuran, waktu, dan perilaku diukur di sandbox. Daftar folder dengan jutaan entri di VPS dengan disk dingin belum diukur.

## Di luar cakupan
Pembersihan otomatis (keputusan 2), tempat sampah dengan undo (keputusan 3), akses Docker dari web (keputusan 4), dan bagian disk di luar `/data` (OS, image, log).

## Pertanyaan terbuka
- [OPEN] Waktu pemindaian di VPS sebenarnya (disk dingin) belum diukur; batas 20 detik / 3 juta berkas ditentukan dari ukuran di sandbox. Perlu ukur dengan APK 1 GB nyata.
- [OPEN] Apakah "cadangan sistem berkas" benar blok cadangan ext4 (≈5%): angka dihitung dari selisih total−terpakai−bebas (99−9,0−86 ≈ 4 GB di VPS pemilik); penyebabnya tidak diperiksa (`sudo tune2fs -l /dev/vda2 | grep -i reserved`).
- [OPEN] Menjalankan pemindaian di tab lain saat satu pemindaian sedang berjalan hanya menampilkan "sedang berjalan"; tidak ada progres. Cukup untuk saat ini; perlu progres bila pemindaian rutin > 10 detik.
