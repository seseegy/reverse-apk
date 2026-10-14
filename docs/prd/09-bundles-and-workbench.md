# 09 — Paket multi-APK & bengkel modifikasi

> **Status: Bagian A (XAPK/APKS) dan Bagian C (shell AI) SEBAGIAN SUDAH ADA; Bagian B (membangun & menandatangani APK) masih RENCANA, belum ada kode.** Shell AI (PR C, lihat "Status PR C") **mati secara bawaan** dan sengaja lebih sempit dari rancangan: tanpa build/tanda tangan, tanpa `bench_diff`/`request_build`/`get_build_status`, dan tanpa `apktool`/`jadx` di dalam `bench`. Selama Bagian B belum dikerjakan, tidak ada penulisan APK dan tidak ada tanda tangan. **Sub-paket B-1b (toolchain) SUDAH ada**: image `signer` (Build-Tools 37.0.0 dipin SHA-256, profil Compose `build`, mati secara bawaan) + `signer-selftest` + `make tools-check`; BELUM ada daemon, keystore, tahap `build`, persetujuan, maupun UI (lihat "Status paket B-1b").

## Tujuan
Dua kemampuan baru, dikerjakan terpisah supaya risikonya terkendali:

1. **Paket multi-APK** — menerima `.xapk`, `.apks`, `.apkm` (dan `.aab` hanya untuk dianalisis), bukan hanya `.apk` tunggal.
2. **Bengkel modifikasi** — AI (dan pengguna) bisa mengubah APK di ruang kerja terisolasi, lalu menghasilkan APK yang **sudah ditandatangani dan siap dipasang**, dengan persetujuan pengguna sebelum dibangun.

## Keputusan pemilik (dasar rancangan)
| # | Keputusan |
|---|---|
| 1 | Format: `.xapk`, `.apks`, `.apkm`; `.aab` **hanya dianalisis** (tidak bisa dimodifikasi atau dipasang). |
| 2 | Hasil dari paket: **dua keluaran** — satu APK gabungan dan paket dengan format asalnya (lihat FR-9.17). |
| 3 | Pembangunan APK memerlukan **persetujuan pengguna** (klik "Setujui") sebelum dijalankan. |
| 4 | AI mendapat **shell bebas**, tetapi hanya di kontainer terpisah ("bengkel"), bukan di layanan `web`. |

## Prinsip yang tetap, dan yang berubah
| Prinsip | Setelah dokumen ini dikerjakan |
|---|---|
| APK **tidak pernah dijalankan** (00 G4) | **Tetap.** Membongkar, menyusun ulang, dan menandatangani adalah operasi pada berkas, bukan eksekusi aplikasi. Tidak ada emulator, tidak ada instalasi di server. |
| Layanan `web` memegang kunci AI dan internet, **tanpa shell** | **Tetap.** Shell tidak pernah berjalan di `web`. |
| Runner dan bengkel **tanpa jaringan** | **Tetap.** |
| Kode APK = data tak tepercaya | **Tetap**, dan lebih penting: keluaran shell diperlakukan sama seperti keluaran tool lain (dibungkus, dibatasi, diredaksi sebelum ke provider). |
| 05: "tidak ada shell, tidak ada tulis berkas" | **Berubah**: ada shell di bengkel dan tool penulis ruang kerja. Dicatat di 05 dan 07 saat PR C. |
| 00 §4: "Repackaging / patching / signing" non-goal | **Berubah**: menjadi tujuan P1. Dicatat di 00 saat PR B. |

## Bagian A — Paket multi-APK

### Format yang dikenali
Jenis ditentukan dari **isi arsip**, bukan ekstensi (seperti lampiran di 07). Ekstensi yang tidak cocok dengan isi ditolak dengan pesan jelas.

| Jenis | Ciri isi (dibaca dari *central directory*, tanpa dekompresi) | Keterangan |
|---|---|---|
| `apk` | `AndroidManifest.xml` + `classes*.dex` di akar | seperti sekarang |
| `xapk` | `manifest.json` di akar + satu atau lebih `*.apk`; boleh ada `Android/obb/…` | OBB **tidak diekstrak** |
| `apks` | `toc.pb` + `splits/*.apk` (atau `standalones/`, `universal.apk`) | keluaran bundletool |
| `apkm` | `info.json` + `base.apk` + `split_*.apk` | format APKMirror |
| `aab` | `BundleConfig.pb` + `base/manifest/AndroidManifest.xml` | **analisis saja**; tidak ada build, tidak ada unduh APK |

### Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-9.1 | Unggah menerima ekstensi `.apk .xapk .apks .apkm .aab`; jenis ditentukan dari isi, dan ketidakcocokan ditolak | P1 |
| FR-9.2 | Validasi di `web` tetap hanya membaca *central directory* (tanpa dekompresi): batas entri, rasio, path traversal, entri ganda — memakai batas yang sama dengan APK | P1 |
| FR-9.3 | Batas khusus paket: maks. 200 entri `*.apk` di dalam paket; entri selain allowlist (OBB, ikon, `manifest.json`/`info.json`/`toc.pb`) **tidak pernah diekstrak** | P1 |
| FR-9.4 | **Pembongkaran dilakukan di runner**, bukan di `web`: tahap baru `unpack` mengeluarkan hanya APK dalam allowlist, dengan batas ukuran per entri dan total yang dipantau saat streaming | P1 |
| FR-9.5 | Nama entri dari paket **tidak pernah dipakai sebagai path**. Bagian disimpan sebagai `parts/part-NN.apk`; nama asli, peran (`base`/`config`/`feature`), dan SHA-256 hanya di DB | P1 |
| FR-9.6 | Tiap bagian divalidasi dengan pemeriksaan APK yang sama (manifest, `classes*.dex` untuk base, batas ukuran). Satu bagian cacat membatalkan seluruh analisis dengan pesan yang menyebut bagiannya | P1 |
| FR-9.7 | Tahap `merge`: split digabung menjadi **satu APK utuh** (`merged.apk`) dengan APKEditor; hasilnya divalidasi lagi. Gagal gabung → analisis tetap berjalan pada `base.apk` saja dengan peringatan jelas | P1 |
| FR-9.8 | Tahap `apktool` dan `jadx` berjalan pada `merged.apk`. Runner menghitung sendiri path-nya dari `analysis_id` (tidak ada path dari worker) | P1 |
| FR-9.9 | Sertifikat penandatangan dibaca dari **APK asli di dalam paket** (`base.apk`), bukan dari `merged.apk` (hasil gabung tidak bertanda tangan) | P1 |
| FR-9.10 | Halaman analisis menampilkan jenis paket, jumlah bagian, dan daftar bagian beserta perannya dan ukurannya | P1 |
| FR-9.11 | `.aab`: hanya jadx yang dijalankan (apktool tidak membaca AAB). Tab Manifes menampilkan "tidak tersedia untuk AAB" bila manifest biner protobuf tidak bisa diurai | P2 |
| FR-9.12 | SHA-256 dihitung atas **berkas yang diunggah** (paket luar); dedup (01 FR-1.4) memakai nilai itu | P1 |
| FR-9.13 | Tahap `unpack`/`merge` tampil di status live, dengan batas waktu sendiri (`TIMEOUT_UNPACK`, `TIMEOUT_MERGE`) | P1 |

### Perubahan data
- `apk.kind` (`apk|xapk|apks|apkm|aab`, bawaan `apk`). Path penyimpanan: `uploads/<sha256>.<kind>`; `Layout.upload_path(sha256, kind)`. Berkas lama (`.apk`) tetap valid tanpa migrasi berkas.
- Tabel baru `bundle_part(analysis_id, idx, role, original_name, sha256, size)`.
- Tahap baru di `analysis_stage`: `unpack`, `merge` — hanya dibuat bila `kind` bukan `apk`/`aab`.
- Spool: `TOOL_STAGES` ditambah `unpack`, `merge`; direktori keluaran `bundle/` di `work/<id>/`.

### Pemindahan kode
`validate_apk` sekarang ada di `services/web/app/apkcheck.py`. Runner juga membutuhkannya (FR-9.6), sehingga dipindah ke `rvcore/apkcheck.py` (paket bersama yang sudah dipakai web, worker, dan runner). `web` memanggil dari sana. Ini perubahan murni pemindahan, dengan tes yang sudah ada sebagai jaring pengaman.

### Alat baru di runner
- **APKEditor** (`REAndroid/APKEditor`, Apache-2.0; rilis 1.4.9 pada 19 Mei 2026, repositori aktif). Dipin dengan SHA-256 di Dockerfile, seperti jadx dan apktool.
- Dari README APKEditor (dibaca 12 Okt 2026): perintah `m` (merge) menerima direktori berisi split **maupun** arsip XAPK/APKM/APKS langsung. Rancangan ini **tetap membongkar dulu** di tahap `unpack` (FR-9.4) supaya hanya APK dalam allowlist yang diekstrak dan batas ukuran dipantau; `merge` lalu menerima direktori `parts/`.
- Saat menggabung, APKEditor **mengubah manifest**: membuang atribut/elemen penanda split (`splitTypes`, `isSplitRequired`, metadata Play seperti `com.android.vending.splits`) dan menerapkan `extractNativeLibs=false`. Jadi manifest `merged.apk` **berbeda dari manifest `base.apk`**. Tab Manifes menampilkan versi gabungan, dan perbedaannya dicatat di UI agar tidak membingungkan. Ini juga alasan paket format asal (FR-9.17b) tidak bisa diturunkan dari perubahan pada `merged.apk` begitu saja.
- Contoh log README memakai APKEditor 1.4.3, sedangkan rilis terbaru 1.4.9: **perilaku harus diuji ulang pada versi yang dipin** (sudah tercantum di Pertanyaan terbuka).

### Keluaran "dua bentuk" (FR-9.17)
`merged.apk` selalu ada. "Paket format asal" hanya bisa dibuat bila perubahan mengenai berkas yang ada di `base.apk`; perubahan di resource hasil gabungan tidak bisa dipetakan balik ke split mana pun. Aturannya ada di Bagian B.

## Bagian B — Bengkel modifikasi: membangun dan menandatangani

### Alur
```
 ruang kerja (hasil apktool)  ──ubah (AI/pengguna)──►  diff
                                                          │
                          AI/pengguna: "minta build"      ▼
                                              ┌─────────────────────┐
                                              │ menunggu persetujuan│  ◄── pengguna melihat diff, klik "Setujui"
                                              └──────────┬──────────┘
                                                         ▼
                      worker ─► runner: build (apktool b, zipalign) ─► signer: apksigner ─► artefak
                                                         ▼
                                       halaman Berkas: unduh + audit log
```

### Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-9.14 | **Ruang kerja**: salinan hasil `apktool` milik satu analisis, di volume `bench` (lihat Bagian C). Asli di `work/<id>/apktool` tidak pernah diubah | P1 |
| FR-9.15 | **Diff dihitung sistem**, bukan dilaporkan AI: perbandingan ruang kerja dengan hasil `apktool` asli (tambah/ubah/hapus, per berkas). Diff inilah yang disetujui dan dibangun | P1 |
| FR-9.16 | Permintaan build berstatus: `awaiting_approval → approved → queued → building → signing → done` atau `rejected / failed / cancelled`. Tanpa `approved`, tidak ada job build yang masuk antrean | P1 |
| FR-9.17 | Keluaran: (a) `merged.apk` ber-tanda-tangan, selalu; (b) paket format asal (`xapk/apks/apkm`) berisi `base.apk` hasil modifikasi + split asli, **semua ditandatangani ulang dengan kunci yang sama**, hanya bila semua berkas yang diubah ada di `base.apk`. Bila tidak, UI menjelaskan mengapa (b) tidak tersedia | P1 |
| FR-9.18 | Persetujuan menampilkan: ringkasan diff, daftar berkas berubah, jumlah baris, dan tombol **Setujui** disertai pernyataan "saya berwenang memodifikasi berkas ini" (dicatat di audit log, seperti pernyataan unggah) | P1 |
| FR-9.19 | Build berjalan di **runner** tahap `build` **tanpa akses kunci**; hasil tak bertanda tangan ditaruh di `work/<id>/build/<n>/unsigned.apk` | P1 |
| FR-9.20 | Tanda tangan dibuat oleh layanan kecil **`signer`** yang terpisah dari runner: hanya ia yang memasang keystore (secret), tanpa jaringan, dan hanya menjalankan `zipalign` lalu `apksigner sign` pada satu berkas masukan, lalu `apksigner verify` pada hasilnya | P1 |
| FR-9.21 | Keystore: **satu per instalasi**, dibuat oleh `make init`, tidak pernah masuk repo, `web`, `worker`, atau runner. Ini kunci uji, **bukan** kunci rilis, dan tidak boleh dipakai di tempat lain | P1 |
| FR-9.22 | Skema tanda tangan: v2 + v3 (target SDK modern mewajibkan, dan `resources.arsc` harus tak terkompresi serta rata 4 byte; `zipalign` dijalankan **sebelum** `apksigner`) | P1 |
| FR-9.23 | Setiap APK hasil memuat berkas jejak `assets/reverse-apk-modified.txt` berisi SHA-256 APK asal, nomor build, dan waktu, agar asal-usulnya jelas. Berkas ini ditambahkan sistem, bukan AI | P1 |
| FR-9.24 | Verifikasi akhir wajib sebelum status `done`: `apksigner verify` lulus, `aapt2 dump badging` terbaca, paket dan versi sesuai harapan, dan SHA-256 hasil dicatat | P1 |
| FR-9.25 | Unduhan hanya lewat sesi login (CSRF + header unduhan seperti di 07), `Content-Type: application/vnd.android.package-archive`, `Content-Disposition: attachment`, `nosniff` | P1 |
| FR-9.26 | Audit log: `build_requested`, `build_approved`, `build_rejected`, `build_done`, `build_failed`, `build_download`, masing-masing dengan `analysis_id`, nomor build, SHA-256 diff, dan SHA-256 hasil | P1 |
| FR-9.27 | Build dapat dibatalkan (seperti job lain), dan hasil sementara dibersihkan oleh *housekeeping* runner | P1 |
| FR-9.28 | Batas: maks. N build per analisis yang disimpan (usul 5), kuota disk build ikut `MIN_FREE_GB`/`MAX_OUTPUT_MB` | P1 |
| FR-9.40 | **Layar persetujuan harus tahan perubahan yang sangat banyak** (pemilik: jenis perubahan "apa saja, sangat banyak"): diff dikelompokkan per berkas dengan jumlah baris tambah/hapus, dapat dicari dan disaring (smali / resource / manifest / aset biner), berkas terbesar dan paling banyak berubah di atas, dan setiap berkas dapat dibuka penuh. Persetujuan terikat pada **SHA-256 diff**: bila ruang kerja berubah lagi setelah diajukan, persetujuan lama tidak berlaku | P1 |
| FR-9.41 | Verifikasi (FR-9.24) membaca `targetSdkVersion`/`minSdkVersion` dan menampilkan peringatan jelas bila APK **tidak akan terpasang di Android 14+** (target SDK di bawah 23 ditolak oleh sistem terlepas dari tanda tangan). Tidak memblokir unduhan | P1 |
| FR-9.42 | Ruang kerja punya **titik simpan** (*snapshot*) yang dibuat sistem sebelum tiap permintaan build dan dapat dipulihkan ("Kembali ke titik simpan N"), karena perubahan banyak dan bertahap oleh AI mudah salah arah | P2 |

### Hal yang **tidak** dijanjikan (harus tampil di UI dan README)
- **Tanda tangan berbeda dari aslinya.** APK hasil tidak bisa memperbarui aplikasi asli yang sudah terpasang; harus mencopot yang lama (data aplikasinya hilang).
- **"Siap pasang" ≠ "pasti jalan".** Yang dijamin: struktur valid, tanda tangan lolos verifikasi, manifest terbaca. Aplikasi dengan proteksi anti-modifikasi (cek tanda tangan, Play Integrity, DexGuard/packer, hash `.so`) bisa tetap gagal.
- **Tidak ada uji jalan.** Menjalankan emulator berarti mengeksekusi APK, yang bertentangan dengan 00 G4. Di luar cakupan.
- **Perubahan smali oleh AI rawan salah.** Karena itu ada log `apktool b` yang dikembalikan ke AI, dan batas jumlah percobaan build.

## Bagian C — Bengkel (shell bebas untuk AI)

### Mengapa kontainer terpisah
Pada `docker-compose.yml`, `web` memegang `AI_API_KEY`, DB, volume `files`, dan jaringan `edge` (internet). Shell di sana berarti teks di dalam APK yang membujuk AI (prompt injection) dapat berujung pada pencurian kunci atau data. Maka shell **tidak pernah** berjalan di `web`, worker, atau runner.

### Layanan baru: `bench`
```
 web (AI) ──► benchspool (volume khusus web↔bench) ──► bench (tanpa jaringan bawaan; lihat "Status PR D")
                                                          └─ ruang kerja per analisis (volume `bench`)
```
| Aspek | Rancangan |
|---|---|
| Jaringan | Rancangan awal `network_mode: none`. **Sejak PR D**: bawaan tetap tanpa jalan keluar (jaringan internal `benchnet`); jaringan hanya bila `AI_SHELL_NET_ALLOW` diisi, itu pun hanya lewat proxy `egress` (lihat "Status PR D") |
| Rahasia | **Tidak ada**: bukan kunci AI, bukan keystore, bukan DB, bukan Redis |
| Sistem berkas | `read_only: true`, `tmpfs` untuk `/tmp`, volume `bench` untuk ruang kerja |
| Hak | non-root, `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit`, `mem_limit`, `cpus` |
| Perintah | dijalankan lewat `bash -c` dalam grup proses sendiri; batas waktu per perintah, batas ukuran keluaran, batas ukuran ruang kerja; seluruh grup dimatikan saat habis waktu atau dibatalkan |
| Alat | `bash`, `coreutils`, `grep/sed/awk`, `python3`, `apktool`, `jadx`, `aapt2`, `zipalign`, `unzip/zip`, `xxd`, `file`; **tanpa** `apksigner` dan tanpa keystore |
| Masa hidup | proses keluar (dan Docker memulai yang baru) setelah *idle* atau setelah analisis selesai, seperti `RUNNER_RECYCLE` |

### Protokol `web` ↔ `bench`
`web` tidak punya spool dengan worker; supaya perintah shell terasa cepat (tanpa jalan memutar lewat Redis → worker), dipakai **volume terpisah `benchspool`** yang hanya dipasang di `web` dan `bench`, dengan protokol berkas yang sama seperti `rvcore/spool.py` (request/running/results/cancel, rename atomik).

Konsekuensinya diterima dengan sadar: `web` kini membaca berkas hasil dari kontainer yang memproses isi APK. Karena itu hasilnya diperlakukan sebagai **data tak tepercaya**: ukuran dibatasi sebelum dibaca, di-parse sebagai JSON ketat, dan dibungkus `<hasil_tool>` seperti hasil tool lain.

### Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-9.30 | Tool AI **`shell_run`**: `command` (teks), `timeout` (detik, dibatasi). Berjalan di ruang kerja analisis yang sedang dibuka | P1 |
| FR-9.31 | Tool **`bench_diff`**: ringkasan perubahan ruang kerja dibanding hasil apktool asli | P1 |
| FR-9.32 | Tool **`request_build`** (`catatan`): membuat permintaan build berstatus `awaiting_approval` (FR-9.16). **Tidak** membangun apa pun; AI tidak bisa menyetujui sendiri | P1 |
| FR-9.33 | Tool **`get_build_status`**: status dan log `apktool b` terpangkas, supaya AI bisa memperbaiki kesalahan | P1 |
| FR-9.34 | Tidak ada tool untuk menyetujui, menandatangani, mengunduh, atau memasang. Persetujuan hanya lewat UI dengan CSRF | P1 |
| FR-9.35 | Setiap perintah dan keluarannya tampil di percakapan (terlipat), tersimpan di `chat_message.tool_calls`, dan dihitung ke anggaran | P1 |
| FR-9.36 | Batas per giliran: jumlah perintah, total keluaran (`AI_MAX_TOOL_CHARS`), total waktu; pada batas, AI diberi tahu dan giliran selesai dengan rapi (pola `stopped` yang sudah ada di `agent.py`) | P1 |
| FR-9.37 | Keluaran shell melewati redaksi secret yang sama sebelum dikirim ke provider (`AI_REDACT_SECRETS`) | P1 |
| FR-9.38 | Pengguna dapat membuka antarmuka ruang kerja (daftar berkas, lihat isi, tombol "Reset ke asli") tanpa AI | P2 |
| FR-9.39 | Ruang kerja dibuat lazily dari `work/<id>/apktool` saat pertama dibutuhkan, dan dihapus bersama analisis | P1 |

### Isolasi antar analisis — **[OPEN]**
Satu volume `bench` berisi ruang kerja semua analisis. Perintah AI di analisis A bisa membaca ruang kerja analisis B bila tidak dibatasi, dan APK A yang berbahaya dapat membujuk AI untuk "menyalin" isi B ke dalam jawabannya. Dampaknya terbatas pada pemilik yang sama dan provider yang sudah menerima potongan kode, tetapi tetap pelanggaran batas yang harus ditutup. Pilihan, untuk diuji pada spike di awal PR C:

| Opsi | Cara | Catatan |
|---|---|---|
| **1 (usul)** Salin per sesi | Daemon menyalin ruang kerja analisis aktif ke area privat (uid terpisah, `0700`) lalu menjalankan perintah AI sebagai uid itu; daemon menyalin balik perubahan | butuh `cap_add: [SETUID, SETGID]` hanya untuk daemon; `no-new-privileges` mencegah eskalasi. Paling sederhana dan bisa diuji |
| 2 | Landlock (kernel ≥ 5.13) membatasi proses anak ke satu direktori | tanpa kapabilitas tambahan, tetapi bergantung pada profil seccomp Docker/host; **belum diverifikasi** |
| 3 | `bwrap` (namespace) | butuh user namespace tanpa hak; sering diblokir di Docker bawaan |

Keputusan diambil setelah uji nyata di VPS, dan hasilnya ditulis di dokumen ini.

## Model ancaman tambahan
| Ancaman | Kontrol |
|---|---|
| Prompt injection dari isi APK memerintahkan shell | Shell hanya di `bench`: tanpa jaringan, tanpa rahasia; keluaran = data; batas langkah/waktu/keluaran; tidak ada tool setujui/tanda tangan |
| AI membangun dan menandatangani tanpa sepengetahuan pengguna | Persetujuan manual lewat UI (CSRF), pernyataan wewenang, audit log; tidak ada tool untuk menyetujui |
| Pencurian keystore lewat eksploitasi apktool/aapt pada pohon yang dimodifikasi | Keystore hanya di `signer`, yang tidak mem-parse pohon sumber (hanya `zipalign` + `apksigner` pada satu `.apk`); `runner` dan `bench` tidak memilikinya. Kuncinya kunci uji tanpa nilai kepercayaan di luar instalasi ini |
| Hasil unduhan disalahgunakan seolah APK asli | Tanda tangan berbeda secara terang-terangan; berkas jejak `assets/reverse-apk-modified.txt`; audit log unduhan; kebijakan 00 §7 diperluas ke modifikasi |
| Zip bomb di dalam paket | Validasi *central directory* di `web`; ekstraksi hanya di runner dengan allowlist dan batas streaming; OBB tak pernah diekstrak |
| Path traversal / nama entri berbahaya di paket | Nama entri tidak pernah dipakai sebagai path (FR-9.5) |
| Volume `benchspool` dipakai kontainer `bench` yang terkompromi untuk menyerang `web` | Ukuran dan format hasil dibatasi dan di-parse ketat; tidak ada path dari bench yang dipercaya `web` |
| Bocornya ruang kerja analisis lain | Lihat "Isolasi antar analisis" |
| Disk penuh oleh ruang kerja/build | Kuota ruang kerja, batas jumlah build, `MIN_FREE_GB`, *housekeeping* |

## Kebijakan penggunaan (perluasan 00 §7)
Modifikasi hanya untuk APK yang **milik pengguna atau yang pengguna berwenang memodifikasi**. Persetujuan build mencatat pernyataan itu. Sistem tidak menyediakan pembagian/penerbitan APK hasil modifikasi (tidak ada tautan publik, hanya unduhan dari sesi login).

## Konfigurasi baru (usul)
`TIMEOUT_UNPACK` (120), `TIMEOUT_MERGE` (300), `TIMEOUT_BUILD` (600), `BENCH_CMD_TIMEOUT` (60), `BENCH_CMD_MAX_OUTPUT_KB` (64), `BENCH_WORKSPACE_MAX_MB` (2048), `BENCH_IDLE_EXIT` (900), `BUILD_KEEP` (5), `SIGNER_KEYSTORE_FILE` (secret). Semuanya **wajib diteruskan di `docker-compose.yml`** (pelajaran OP-01 di `audit.md` §10.3).

## Urutan kerja
| PR | Isi | Selesai bila |
|---|---|---|
| **A** | Bagian A lengkap: `rvcore/apkcheck.py`, jenis berkas, tahap `unpack`/`merge`, APKEditor di image runner, UI daftar bagian, tes (paket sintetis dari `scripts/make-test-apks.py`) | `.xapk/.apks/.apkm` sampel dianalisis penuh; zip bomb dan path traversal di dalam paket ditolak; `.aab` terbuka lewat jadx; seluruh tes lama tetap lulus |
| **B** | (sub-paket **B-1b**, hanya toolchain: SELESAI di kode, uji Docker menunggu VPS) Build + tanda tangan **tanpa AI**: ruang kerja, diff, persetujuan, tahap `build`, layanan `signer`, `make init` membuat keystore, unduhan, audit | APK sampel diubah manual (mis. mengganti string), disetujui, dibangun, `apksigner verify` lulus, dan `aapt2 dump badging` benar; tanpa persetujuan tidak ada job |
| **C** | `bench` + `benchspool` + tool AI (`shell_run`, `bench_diff`, `request_build`, `get_build_status`) + keputusan isolasi antar analisis + pembaruan 00/05/07 | skenario uji: AI mengubah satu string di smali, mengajukan build, pengguna menyetujui, hasil terverifikasi; **tes injeksi**: APK dengan teks yang menyuruh AI membaca `/data`, mengakses jaringan, atau menyetujui sendiri **gagal** melakukannya |
| **D** | (P2) antarmuka ruang kerja untuk pengguna, "paket format asal" (FR-9.17b) bila belum masuk A–C | — |

PR B memakai kembali jalur *spool* yang sudah ada dan bisa diuji tanpa AI sama sekali, sehingga bagian paling sensitif (tanda tangan) terbukti dulu sebelum AI diberi akses.

## Hasil riset dan keputusan tambahan (12 Okt 2026)

### Perangkat target: Android 14 ke atas
- Tanda tangan **v2 + v3 sudah mencukupi**; v1 tidak diperlukan. Tidak ada alasan menurunkan skema demi perangkat lama.
- Android 14 menolak memasang aplikasi yang `targetSdkVersion`-nya di bawah 23. APK lama seperti itu tidak akan terpasang walau ditandatangani benar → FR-9.41.
- Pemasangan tetap manual oleh pengguna (`adb install` atau pemasang paket). Untuk hasil berbentuk paket split, pemasang biasa tidak membukanya; `merged.apk` (satu berkas) adalah bentuk yang paling mudah dipasang.

### Jenis perubahan: "apa saja, sangat banyak"
Konsekuensi untuk rancangan:
- Ini **membenarkan shell bebas** (keputusan 4): tool khusus per jenis perubahan tidak akan cukup.
- Beban pindah ke **layar persetujuan** (FR-9.40): diff besar membuat orang cenderung menyetujui tanpa membaca. Karena itu diff dikelompokkan, dapat disaring, dan terikat hash.
- Ruang kerja dan keluaran build membesar bersama ukuran APK → titik simpan (FR-9.42) dan kuota (di bawah).
- Tidak ada penyaringan jenis perubahan. Pengaman yang berlaku tetap sama untuk semuanya: pernyataan wewenang saat menyetujui, audit log, persetujuan manual, dan tidak ada tombol bagikan/terbitkan.

### Batas ukuran: hingga 1 GB
`MAX_UPLOAD_MB` satu variabel yang dibaca `web` **dan** Caddy (`docker-compose.yml`), jadi cukup satu nilai (1024). Tetapi batas lain dirancang untuk APK jauh lebih kecil dan **akan menolak atau menggagalkan** berkas besar. Nilai "usul" di bawah hanyalah titik awal; angka akhir **harus diukur** dengan APK/XAPK besar sungguhan di PR A (pelajaran BE-09: ukur, jangan tebak).

| Pengaturan | Sekarang | Masalah untuk berkas hingga 1 GB | Usul awal |
|---|---|---|---|
| `MAX_UPLOAD_MB` | 200 | batas unggah itu sendiri | 1024 |
| `ZIP_MAX_ENTRY_MB` | 512 | **satu APK di dalam paket bisa >512 MB** → ditolak sebagai "entri terlalu besar" | 1024 |
| `ZIP_MAX_UNCOMPRESSED_MB` | 3072 | paket 1 GB berisi APK yang sudah terkompresi hampir tidak mengecil; tetapi APK 1 GB bisa membesar 2–3× | naik bila terukur perlu |
| `MAX_OUTPUT_MB` (runner) | 3072 | hasil dekompilasi APK sebesar itu bisa melampaui 3 GB → "keluaran terlalu besar" | diukur |
| `JADX_HEAP` / `mem_limit` runner | 2 GB / 3 GB | jadx untuk APK sangat besar bisa kehabisan memori; VPS hanya 8 GB total (jumlah `mem_limit` web + worker + redis + caddy saja sudah 1,6 GB, belum termasuk runner 3 GB dan sistem) | diukur; **tidak bisa dinaikkan sembarangan** |
| `TIMEOUT_JADX` / `TIMEOUT_APKTOOL` / `JOB_TIMEOUT` | 900 / 300 / 2700 detik | kemungkinan terlalu pendek | diukur |
| `MIN_FREE_GB` / `JOB_MIN_FREE_GB` | 15 / 5 | hasil dekompilasi + ruang kerja `bench` + build bisa puluhan GB per APK | disesuaikan dengan disk VPS |
| `BENCH_WORKSPACE_MAX_MB` (baru) | — | bawaan 2048 usulan terlalu kecil untuk APK 1 GB | skala dengan ukuran |
| Cloudflare | proxy dimatikan (`docs/deploy.md`) | bila dinyalakan, batas body ±100 MB (paket gratis) membuat unggahan >100 MB gagal | tetap "DNS only" |

Selain itu, `max_size` Caddy dan pembacaan unggahan sudah streaming ke disk (NFR-1.1), jadi 1 GB tidak membebani memori `web`; yang perlu dipantau adalah waktu unggah dan sesi (`SESSION_MAX_AGE` 12 jam sudah mencukupi).

### Isolasi `bench`: data VPS
VPS: kernel `6.8.0-146-generic` x86_64, Docker `29.9.0`, profil `apparmor` + `seccomp builtin`, LSM aktif: `lockdown, capability, landlock, yama, apparmor`, `max_user_namespaces=31245`.
- **Landlock aktif di kernel host** → opsi 2 realistis. Yang belum diketahui: apakah profil seccomp bawaan Docker 29 mengizinkan syscall Landlock **di dalam kontainer**.
- `bwrap` (opsi 3) kemungkinan diblokir di dalam kontainer oleh seccomp/AppArmor bawaan, walau namespace diaktifkan di host.
- **Cara membuktikan**: `scripts/bench-probe.sh` menjalankan uji di kontainer dengan pengaturan yang sama seperti rencana `bench` (tanpa jaringan, rootfs read-only, non-root, `cap-drop ALL`, `no-new-privileges`). Skrip Python-nya (`scripts/bench-probe.py`) sudah diuji di sandbox pengembangan, termasuk uji negatif (pengurungan dimatikan sengaja → dilaporkan BOCOR). Pembungkus Docker-nya **belum pernah dijalankan** (sandbox pengembangan tidak punya Docker); hanya sintaksnya yang diperiksa.
- Keputusan: bila `bench-probe.sh` lulus di VPS → opsi 2 (Landlock; perintah AI dikurung ke folder ruang kerja analisis yang aktif + folder alat baca-saja + `/tmp`). Bila gagal → opsi 1.

### Temuan alat
- **jadx** mencantumkan `.aab`, `.xapk`, `.apkm`, `.apks` sebagai masukan yang didukung (README cabang utama). Artinya analisis kode dapat berjalan **tanpa** menggabung dulu; penggabungan tetap dibutuhkan untuk apktool (tab Manifes) dan untuk modifikasi. Versi yang dipin (1.5.6) belum dicocokkan dengan README itu; dibuktikan dengan sampel nyata di PR A.
- **Sampel dari pemilik (12 Okt 2026)**: `sample.xapk/.apks/.apkm/.aab` ternyata **placeholder** (isi `AndroidManifest.xml` berupa teks "PLACEHOLDER", `classes.dex` 40 byte, `toc.pb` berisi teks). Strukturnya benar dan berguna untuk **tes pendeteksi jenis** (nama berkas dan kolom `manifest.json` / `info.json`), tetapi **tidak bisa** dibuka apktool/jadx/APKEditor, jadi tidak membuktikan gabung atau dekompilasi. Sampel nyata tetap dibutuhkan.
- **`apksigner` / `zipalign`** dari Android SDK Build-Tools (terbaru 37.0.0, zip Linux ±66 MB). Google menerbitkan **hanya SHA-1** untuk paket ini; maka SHA-256 dihitung sendiri saat pertama diunduh, dipin di Dockerfile, dan SHA-1 Google dipakai sebagai pembanding. Dipin: SHA-256 `01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060` (SHA-1 Google `70954e99f4c3d9d46ee70fa32624672fe7cd6ebe` cocok).
- Dari zip itu hanya **3 berkas** yang dipakai (±3 MB): `zipalign`, `lib/apksigner.jar`, dan `lib64/libc++.so`. `zipalign` memuat `libc++.so` lewat RUNPATH (`$ORIGIN/lib64`), jadi keduanya harus berdampingan. **aapt2 dibundel di dalam jar apktool 3.0.3** (`prebuilt/linux/aapt2`, ELF x86-64 statis) dan tidak dipasang dari sumber lain. KOREKSI (14 Okt 2026): klaim lama "`apktool b` terbukti jalan offline" hanya benar di **sandbox** yang `/tmp`-nya boleh `exec` (`unshare -n`). **Di kontainer runner GAGAL** (`Permission denied`, errno 13) karena Docker memasang tmpfs `/tmp` sebagai `noexec` sedangkan apktool mengekstrak aapt2 ke `/tmp` lalu menjalankannya. Diperbaiki dengan aapt2 yang diekstrak ke `/opt/apktool/aapt2` saat build image (rootfs read-only, dipin SHA-256) dan wrapper `apktool` yang menyisipkan `--aapt` untuk `b`; `/tmp` TETAP `noexec` (lihat "Status perbaikan aapt2/noexec"). Pembuktian di kontainer = `make runner-selftest` di VPS.
- Dokumentasi Google menegaskan `zipalign` dijalankan **sebelum** `apksigner` (menandatangani lalu mengubah berkas membatalkan tanda tangan) → sudah di FR-9.22.

## Status PR A (12 Okt 2026): XAPK dan APKS

**Sudah ada:** `.apk`, `.xapk`, `.apks` diterima (jenis ditentukan dari ISI, bukan ekstensi). Hanya **base APK** yang dianalisis. Kode: `services/rvcore/bundle.py` (dipakai web dan runner), `apkcheck.py`, `runner-daemon`, `tests/test_bundle.py`.

**Sengaja lebih sempit dari rancangan di atas** (agar bisa dibuktikan, bukan dijanjikan):
| Rancangan | Yang dikerjakan | Alasan |
|----|----|----|
| FR-9.1 `.apkm`, `.aab` | **Tidak.** `.apkm` ditolak dengan pesan jelas; `.aab` ditolak di ekstensi | Belum ada sampel asli; klaim "didukung" baru ditulis setelah terbukti (aturan di bawah) |
| FR-9.4 tahap pipeline `unpack`, `TIMEOUT_UNPACK` | **Tidak ada tahap baru.** Runner mengekstrak base di dalam tiap job (`prepared_apk`), dengan detak jantung selama menyalin | Tidak perlu migrasi DB, tahap spool, maupun perubahan UI status; ekstraksi base terukur 0,07-0,23 dtk untuk 15 MB. Konsekuensi: base diekstrak 3 kali per analisis (apktool, jadx, analyzer), lalu dihapus |
| Merge split (APKEditor) | **Tidak.** | Terukur: hasil merge membawa tanda tangan v1 yang TIDAK cocok lagi (`SHA1 digest error`) dan blok v2/v3 milik base; analyzer hanya membaca sertifikat, jadi merge tampak "ditandatangani penerbit" padahal tidak sah. Memakai base ASLI menghindarinya |
| FR-9.3 allowlist entri, maks. 200 `*.apk` | Hanya batas zip yang sudah ada (entri, rasio, ukuran per entri/total) | Yang diekstrak hanya satu entri, dengan batas byte nyata (`MAX_BASE_APK_MB`, bawaan 1024) |
| FR-9.10 daftar bagian dan perannya | Baris "Paket" di halaman analisis: format, base, jumlah APK, dan peringatan jujur | Daftar lengkap split belum diperlukan karena split tidak dianalisis |

**Aturan pemilihan base** (`bundle.plan_bundle`, sama untuk web dan runner):
- XAPK: entri `split_apks[]` dengan `id == "base"` di `manifest.json`; cadangan `<package_name>.apk` di akar, lalu satu-satunya APK di akar; selain itu **ditolak**, tidak ditebak. Nama dari manifest hanya diterima bila sama persis dengan entri yang ada.
- APKS: `universal.apk`; lalu `base-master.apk` (juga `splits/`), lalu `base-master_N.apk` (nomor terkecil, numerik); lalu satu-satunya `standalones/*.apk`; selain itu ditolak. Jumlah kandidat lain dicatat sebagai `alternates` dan ditampilkan di UI.

**Terbukti pada berkas NYATA** (sandbox; runner-daemon, apktool 3.0.3, jadx 1.5.6, analyzer, dan pipeline worker asli; tanpa Docker dan Redis):
| Berkas | Hasil |
|----|----|
| XAPK YouSee Musik 5.22.0 (23,3 MB; base + 3 split) | status `done`; package/versi/SDK terisi dari base; apktool 24.131 berkas, jadx 16.075 berkas Java (138 method gagal, sama dengan uji manual); sertifikat penerbit asli (`CN=247 Entertainment`, skema v2/v3, SHA-256 `9B:60:58:F6…`) |
| APKS NexLoad mode default (65 MB; 87 APK, 2 master) | status `done`; dipilih `splits/base-master.apk`, `alternates=1`; jadx 21.697 berkas Java (272 method gagal) |
| APK F-Droid NewPipe (regresi) | status `done` seperti sebelumnya; tanpa opsi bundel; 4 library native terbaca |
Kedua master pada sampel APKS default **identik** (173 entri, CRC sama semua). Itu belum tentu berlaku untuk bundel lain, sehingga yang dipilih deterministik dan jumlah alternatif ditampilkan.

**Keterbatasan yang diketahui (juga tertulis di UI):**
- **Split tidak dianalisis.** Terukur pada XAPK nyata: `native: {libs: {}}` kosong padahal aplikasi memuat `librealm-jni.so` (ada di split `config.arm64_v8a`). Resource bahasa dan kerapatan layar juga tidak ikut.
- `.apks` buatan bundletool tanpa keystore dilaporkan `signing.unsigned` (benar untuk sampel itu); `.apks` dari toko bisa bertanda tangan.
- Bundel dengan OBB atau total > `ZIP_MAX_UNCOMPRESSED_MB` (3072) ditolak oleh batas zip yang ada. Batas unggah bawaan masih 200 MB (keputusan 1 GB belum diterapkan di PR ini).
- Belum diuji: `.apkm`, `.aab`, XAPK versi lain/dengan OBB, dan isolasi Docker sungguhan.
- Satu XAPK dan dua APKS: sampel sangat sedikit.

**Keputusan isolasi `bench` (hasil `scripts/bench-probe.sh` di VPS pemilik, 12 Okt 2026):** kernel `6.8.0-146-generic`, Docker 29.9.0, kontainer `python:3.12-slim-trixie` uid 10001. **Landlock ABI v4 berfungsi** (berkas di dalam folder terbaca; baca, tulis, dan daftar folder di luar ditolak). User namespace diblokir (`EPERM`), jadi bwrap (opsi 3) tidak bisa dipakai. **Keputusan: opsi 2 (Landlock).** Opsi 1 (salin per sesi + uid terpisah) tidak diperlukan. Catatan: probe memakai `docker run` polos; pengaturan layanan `bench` yang sebenarnya (`cap_drop`, `read_only`, `seccomp`) harus diuji ulang saat PR C dikerjakan.

## Status PR C (12 Okt 2026): shell AI (`shell_run`)

**Sudah ada, MATI secara bawaan** (`AI_SHELL_ENABLED=0`). Kode: `services/bench/` (daemon, kebijakan, Landlock, eksekutor, `bench-selftest`), `services/rvcore/shellspool.py` (protokol web↔bench), tool `shell_run` di `ai/tools.py`, `docker-compose.yml` (layanan `bench`, volume `bench` dan `benchspool`), `make bench-selftest`.

**Sengaja lebih sempit dari rancangan Bagian C** (alasannya: bagian yang tidak bisa dibuktikan di sini tidak dikirim):
| Rancangan | Yang dikerjakan | Alasan |
|----|----|----|
| FR-9.30 `shell_run` | **Ya** | |
| FR-9.31 `bench_diff`, FR-9.32 `request_build`, FR-9.33 `get_build_status`, FR-9.34 | **Tidak** | Bergantung Bagian B (build, `signer`, persetujuan) yang belum ada. AI **tidak** punya tool untuk membangun, menandatangani, atau menyetujui apa pun |
| Alat `apktool`, `jadx`, `aapt2`, `zipalign` di `bench` | **Tidak** (hanya `bash`, `coreutils`, `grep/sed/awk`, `find`, `unzip/zip`, `file`, `xxd`, `diff`, `patch`, `python3`) | Tanpa Java image tetap kecil; hasil apktool/jadx sudah ada di `$WORK`. Konsekuensi: AI bisa mengubah **salinan** smali/resource di `$WS`, tetapi tidak bisa membangun APK |
| FR-9.14/9.39 ruang kerja "salinan `apktool`" dibuat lazily | Ruang kerja `bench/<id>/` **kosong**, dibuat saat perintah pertama; AI menyalin sendiri dari `$WORK` | Lebih sederhana; tidak ada salinan otomatis berukuran ratusan MB |
| FR-9.35 perintah dan keluaran tampil (terlipat), tersimpan di `chat_message.tool_calls` | **Ya**, dibatasi (perintah 2000, stdout 6000, stderr 3000 karakter, sudah diredaksi) | |
| FR-9.36 batas per giliran | Jumlah perintah (`AI_SHELL_MAX_CALLS_PER_TURN`, bawaan 40) dan waktu per perintah; total keluaran memakai `AI_MAX_TURN_TOOL_CHARS` yang sudah ada | |
| FR-9.37 redaksi | **Ya**: stdout, stderr, **perintah**, dan argumen yang disimpan/dikirim ke UI | Lihat temuan kebocoran argumen di `audit.md` 10.11 |
| FR-9.38 antarmuka ruang kerja untuk pengguna | **Tidak** | P2 |
| Daur ulang kontainer per analisis | `BENCH_IDLE_EXIT` (bawaan 900 dtk idle) | Ruang kerja ada di volume dan bertahan |

**Keputusan isolasi antar analisis: Landlock (opsi 2)**, berdasarkan hasil `bench-probe.sh` di VPS pemilik (ABI v4). Setiap perintah berjalan di proses anak (`bench.confined_exec`) yang memasang Landlock lalu `exec bash`. **GAGAL TERTUTUP**: bila Landlock tidak tersedia/gagal dipasang, atau uji kenari (daftar folder di luar aturan harus ditolak) tidak lulus, bash **tidak pernah dijalankan**; daemon hanya menganggap perintah berjalan bila "penanda terkurung" sudah ditulis lewat pipa sebelum `exec` (sehingga `exit 121` dari perintah AI tidak tertukar dengan kegagalan pengurungan).

**Aturan akses (daftar putih; `policy.py`)**, semua path dihitung daemon dari `analysis_id` (angka) dan `sha256` (heksa 64), tidak pernah dari web:
- **Baca**: sistem (`/usr`, `/bin`, `/lib*`, `/etc`, `/opt`), `work/<id>/{apktool,jadx,logs,manifest.json}`, dan APK analisis itu (`uploads/<sha>.apk`, satu berkas).
- **Tulis**: `bench/<id>/` (`$WS`) dan folder sementara job.
- **Tertutup**: **`work/<id>/index/`** (berisi nilai rahasia mentah; alasan yang sama dengan penjelajah folder), analisis lain, ruang kerja lain, `db`, `files`, `spool`, `benchspool`, dan **daftar isi** `/data`, `work/<id>`, `uploads`, `bench`. Akibat yang disengaja: `ls $WORK` ditolak (Landlock tidak punya "daftar folder tanpa membuka anak-anaknya"), sedangkan `ls $WORK/apktool` bisa. Hal ini dijelaskan di prompt tool agar AI tidak menganggapnya galat.

**Kontainer `bench`** (saat PR C; diubah PR D): `network_mode: none` (sejak PR D: jaringan internal `benchnet` tanpa rute keluar), `read_only`, non-root (uid 10001), `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, `mem_limit 1g`, `pids_limit 512`. **Tanpa** kunci AI, DB, Redis, `files`, `spool` runner, keystore, dan Docker socket (diperiksa oleh `tests/test_shell_tool.py`). `work` dan `uploads` dipasang **baca saja**.

**Batas per perintah**: timeout (bawaan 60 dtk, maks. 120), keluaran (kepala+ekor, 64 KB/aliran di bench lalu `AI_SHELL_MAX_OUTPUT_CHARS` di web), ukuran satu berkas (256 MB), kuota ruang kerja (2048 MB, ditolak sebelum jalan), `RLIMIT_NPROC`, `RLIMIT_CPU`, tanpa core dump. Seluruh keturunan (termasuk `setsid`/double-fork, dan proses yang mengabaikan `SIGTERM`) dimatikan sesudah tiap perintah (subreaper + `SIGKILL`). Daemon `non-dumpable` supaya perintah AI tidak bisa menyuntik kode ke daemon yang tidak dikurung.

**Kepercayaan di kedua arah**: bench menolak request yang bidangnya tidak valid (`analysis_id`, `sha256`, tipe, panjang); web memperlakukan hasil bench sebagai data tak tepercaya (ukuran berkas dicek **sebelum** dibaca, symlink ditolak, JSON ketat, tiap bidang dinormalkan, `parse_result` tidak pernah melempar).

**Audit**: `ai_shell_run` mencatat `analysis_id`, status, kode keluar, panjang perintah, durasi, jumlah karakter keluaran. **Isi perintah dan keluaran tidak dicatat** (bisa memuat rahasia dari APK).

**Terbukti** (sandbox; kernel 6.1, Landlock ABI v2; Python 3.12; sebagai `nobody` bila relevan):
| Bukti | Hasil |
|----|----|
| Pengurungan nyata | 24 upaya baca/tulis/hapus/tautan/`..`/`/proc/self/root`/symlink di luar daftar putih **semua ditolak**, tanpa satu pun umpan bocor; kontrol positif (manifest/jadx/APK sendiri, tulis di `$WS`, `python3`) berjalan |
| Gagal tertutup | Landlock dimatikan di proses pembantu → `refused`, perintah tidak jalan; tiap lapis (Landlock-error, kenari, penanda) dipaksa gagal **sendirian** dan masing-masing menolak |
| Ujian menyeluruh | Server web asli (`AI_SHELL_ENABLED=1`) + `bench-daemon` asli sebagai `nobody` + "model" palsu yang meminta tool; analisis NewPipe NYATA (7.095 berkas Java): **23 dari 23 cek lulus**: alur normal, tiga upaya injeksi (baca `index/`, baca analisis lain, `/proc/1/environ`) ditolak kernel, `$WS` bertahan antar giliran dan hasil dekompilasi asli tidak berubah, rahasia dalam perintah tidak bocor di event/UI/halaman muat-ulang/DB/audit, **Batal menghentikan `sleep 60` dalam 2,2 dtk** tanpa proses sisa, bench mati → galat tool yang jelas |
| Browser (Chromium) | Kartu perintah+keluaran terlipat di 1280 dan 375 px; keluaran jahat (`<img onerror>`, `<script>`) tampil sebagai teks (`window.__pwned` tetap kosong, nol elemen `<img>`/`<script>`); target sentuh 44 px; tanpa luber; tanpa galat JS/CSP |
| Tes | `tests/test_shell_bench.py` (86), `tests/test_shell_tool.py` (49), `tests/test_spool.py` (9, spool sebelumnya tanpa tes); suite 692 lulus; urutan terbalik lulus; urutan acak hanya 10 error lama `test_files_page` |
| Mutasi | **79 mutasi unik: 77 tertangkap, 2 setara.** Awalnya 16 lolos; 14 ditutup dengan tes baru yang memaksa **tiap lapis gagal sendirian**, 2 dibuktikan setara (L1: jalur kedua tetap melempar, terukur; X12: disapu ulang di tiga tempat). Pengecualian jujur: L5 (`NO_NEW_PRIVS`) tertangkap oleh tes yang mensimulasikan kegagalan `prctl`, bukan oleh perilaku kernel, karena sandbox ini sudah `NoNewPrivs: 1` |

**Temuan yang mengubah rancangan:**
1. **`RLIMIT_NPROC` dihitung per UID di seluruh host** (terukur: 90 proses lain dengan uid sama membuat perintah yang hanya butuh 40 proses gagal pada batas 100). Karena web/worker/runner/bench memakai uid 10001, nilai kecil membuat perintah sah gagal secara acak. Batas bawaan dinaikkan ke 2048 dan pembatas proses yang tepat per kontainer adalah `pids_limit` (cgroup).
2. **Uid terpisah untuk bench tidak dipakai**: web (10001) tidak bisa menghapus ruang kerja milik uid lain (terukur: EACCES), padahal hapus analisis harus membersihkannya. Dipertahankan satu uid; isolasi antar analisis ditegakkan Landlock, bukan uid.
3. **Argumen tool yang disimpan memuat perintah mentah** (lihat `audit.md` 10.11).

**Keterbatasan dan yang BELUM terbukti (penting sebelum menyalakan `AI_SHELL_ENABLED`):**
- **Belum dijalankan di Docker.** Sandbox tidak punya daemon Docker. Yang nyata: daemon, Landlock, eksekutor, spool, web, agent. Yang belum: `network_mode: none` (kini jaringan internal, lihat PR D), `read_only`, `cap_drop`, `pids_limit`, `mem_limit`, `Dockerfile` bench, dan interaksi profil seccomp/AppArmor Docker dengan syscall Landlock. **Jalankan `make bench-selftest` di VPS** (kegagalan Landlock membuatnya gagal keras, bukan lolos diam-diam); itu satu-satunya bukti yang sah untuk lingkungan produksi.
- Sandbox memakai **Landlock ABI v2**, VPS pemilik v4. Perbedaannya: pada v4 ada pembatasan TCP (lapis kedua selain `network_mode: none`); itu tidak teruji di sini. Pada ABI < 4, satu-satunya penghalang jaringan adalah kontainer. `bench-selftest` menyebut lapis mana yang menahan.
- Perintah AI **tidak bisa** menjalankan alat Java (`apktool`, `jadx`) dan **tidak bisa** membangun/menandatangani APK. Jaringan: mati bawaan; lihat "Status PR D" bila dinyalakan.
- Redaksi memakai pola yang sama dengan tool lain: **bukan jaminan** (string rahasia tanpa pola dikenal tetap bisa lolos); keluaran shell, seperti isi APK, dikirim ke provider AI.
- Perintah yang disusun AI dikurung, tetapi di dalam `$WS` AI bebas membuat berkas/proses selama batas waktu; proses yang melepaskan diri dimatikan setelah perintah selesai.
- Penyapu ruang kerja yatim (jaring pengaman bila web gagal menghapus) ada di daemon, sangat konservatif (penanda aktivitas, `mtime` terbaru di seluruh pohon, masa tenggang 1 jam, tidak jalan bila `work/` kosong). Ia menghapus data, jadi diuji ketat; versi pertamanya menghapus ruang kerja yang sedang dipakai (lihat `audit.md` 10.11).
- Nama berkas non-UTF-8 di `$WS` tidak dipengaruhi (tidak ada tampilan daftar berkas ruang kerja untuk pengguna).

## Status PR D (12 Okt 2026): jaringan untuk shell AI (menguji API)

**Tujuan pemilik:** AI dapat menguji endpoint API yang ditemukan di APK. **Mati secara bawaan**, dan hanya berlaku bila `AI_SHELL_ENABLED=1`. Kode: `services/egress/` (proxy), `services/bench/bench/{landlock,confined_exec,policy,executor,netprobe}.py` dan `bench-daemon`/`bench-selftest`, `docker-compose.yml` (jaringan `benchnet`/`egressnet`, layanan `egress`), `ai/{config,agent,tools}.py`, `make bench-selftest` dan `make net-check`.

### Rancangan
```
 bench ──(benchnet, internal: tanpa rute keluar)──► egress ──(egressnet)──► internet
   ▲ Landlock ABI ≥ 4: connect() TCP hanya ke port 3128          ▲ hanya CONNECT, daftar putih, hanya alamat PUBLIK
```
| Keputusan | Alasan |
|---|---|
| **Satu sakelar**: `AI_SHELL_NET_ALLOW` kosong = tanpa jaringan; terisi menyalakan KEDUA sisi (`BENCH_NET_PROXY: ${AI_SHELL_NET_ALLOW:+egress:3128}` dan `EGRESS_ALLOW`) | Dua sakelar bisa tidak sejalan (satu sisi lupa diisi). Ditolak: variabel kedua |
| `bench` pindah dari `network_mode: none` ke `benchnet` (`internal: true`, hanya `bench` + `egress`; bukan `edge`/`backend`) | `bench` tidak bisa menjangkau web, Redis, Caddy, atau internet langsung. `egress` punya kaki keluar sendiri (`egressnet`) dan **tidak** ada di `edge`/`backend` |
| Proxy **buatan sendiri** (Python, `services/egress/`), bukan squid/tinyproxy | Tidak ada Docker di sandbox pengembangan, jadi squid tidak bisa diuji di sini; proxy sendiri bisa diuji penuh (194 tes + soket nyata). Harga: kode keamanan yang harus dirawat |
| Hanya `CONNECT` (HTTPS), port bawaan 443 (`AI_SHELL_NET_PORTS`) | Isi lalu lintas tidak dibaca/dimodifikasi; `http://` hanya lewat terowongan (`curl -p -x "$https_proxy"`), **plain HTTP forwarding sengaja tidak ada** |
| DNS di-resolve **sekali** di proxy lalu connect ke ALAMAT itu; **semua** alamat hasil resolusi harus publik | Anti-DNS-rebinding. Nama tanpa titik (`redis`, `web`, `egress`), `localhost`, `.internal`, dan alamat IPv4 gaya lama (`127.1`, `0x7f.1`, `2130706433`) ditolak sebelum DNS |
| Alamat internal SELALU ditolak walau `*` | privat, loopback, link-local (metadata cloud `169.254.169.254`), CGNAT, `192.0.0.0/24`, `198.18.0.0/15`, NAT64, 6to4, Teredo, multicast |
| Mode `*` = semua host **publik** | Host API baru ketahuan dari APK; daftar statis tidak praktis. Risiko di bawah |
| Landlock ABI ≥ 4: `LANDLOCK_RULE_NET_PORT` hanya hak CONNECT ke port proxy | Klien yang mengabaikan variabel proxy tidak punya rute lain. ABI < 4 + jaringan diminta → daemon **mematikan jaringan dengan peringatan** (tidak membukanya tanpa pengunci); `confined_exec` menolak menjalankan bila `net_ports` ada tetapi pengunci tidak aktif |
| **Tanpa tambahan prompt sistem** (keputusan pemilik: yang diinginkan hanya akses internet, AI dibiarkan maksimal). Bila jaringan aktif, prompt dan deskripsi `shell_run` hanya **dikurangi** klaim "tanpa jaringan" yang kini salah (4 kalimat di prompt, 2 di deskripsi); aturan A (anti-injeksi) dan F tetap utuh | Tanpa pengurangan itu model membaca "tanpa jaringan" dan menolak memakai jaringan yang ada. Klien memakai proxy lewat `$https_proxy` yang sudah diset bench, jadi `curl` dll. bekerja tanpa instruksi. Dijaga tes yang membandingkan hasil dengan **kesamaan persis** (prompt/deskripsi dasar dikurangi literal klaim itu) dan menolak kata baru seperti `proxy`/`curl`/`konfirmasi`. Teks dasar berubah = `RuntimeError`. Konsekuensi yang diterima: AI tidak diberi tahu host mana yang diizinkan atau arti kode penolakan (`X-Egress-Reason` tetap terlihat di keluaran `curl -v`), dan tidak ada permintaan konfirmasi sebelum POST/PUT/DELETE |
| Image `bench` kini memasang `curl` dan `ca-certificates` | Ditemukan saat meninjau Dockerfile: awalnya prompt menyuruh AI memakai `curl` padahal image sengaja tanpa `curl`. Setelah prompt tidak lagi menyebut alat apa pun, `curl` tetap perlu ada agar HTTPS lewat proxy bisa dipakai. Tanpa jaringan keduanya tak berguna, jadi tidak menambah kemampuan saat jaringan mati. Dijaga tes isi Dockerfile |

**Batas proxy:** koneksi bersamaan (32), durasi, idle, byte per koneksi (100 MB), byte per jam seluruhnya (1024 MB). Log hanya `IZIN/TOLAK host port alasan ip byte detik`, **tanpa isi lalu lintas**. Alasan penolakan dikirim ke klien lewat header `X-Egress-Reason` supaya AI tahu itu batas sistem.

### Peringatan untuk mode `*`
1. **Eksfiltrasi:** AI (atau teks berbahaya di dalam APK yang membujuknya, lihat aturan A) dapat mengirim isi APK dan hasil analisis ke server mana pun.
2. **Asal permintaan:** semua permintaan keluar membawa IP server Anda. Menguji API pihak ketiga tanpa izin bisa melanggar ketentuan layanan atau hukum.
3. **Tidak ada batas laju permintaan per detik**; yang dibatasi hanya koneksi bersamaan dan kuota byte. Satu perintah bisa menjalankan banyak `curl`. Batas panggilan per giliran (40) dan batas waktu per perintah hanya membatasi sebagian.
4. **Tanpa pagar di prompt** (keputusan pemilik): tidak ada instruksi yang membatasi pemindaian, brute force, atau permintaan massal; satu-satunya pagar adalah yang ditegakkan sistem (daftar host, alamat internal ditolak, kuota). Batas proxy bisa dinaikkan lewat `EGRESS_MAX_*` (sampai 1024 koneksi, 100 GB per koneksi, ~10 TB per jam).
Pagar yang **tetap**, karena melindungi server Anda sendiri, bukan membatasi internet: alamat internal/privat/metadata cloud (Redis, web, dan layanan lain di VPS) selalu ditolak, apa pun isi `AI_SHELL_NET_ALLOW`.
Rekomendasi: daftar host spesifik; `*` hanya untuk API milik sendiri atau yang Anda berwenang menguji. Mengisi sakelar = menerima risiko ini.

### Terbukti (sandbox: kernel 6.1, Landlock **ABI v2**, tanpa Docker, tanpa Redis)
| Bukti | Hasil |
|---|---|
| Tes | `test_egress_policy` 154, `test_egress_server` 40 (soket nyata), `test_shell_net` 64, `test_netprobe` 16 (proxy nyata di loopback). Suite penuh **966 lulus**; juga sebagai non-root (`nobody`, python3.12) |
| Mutasi | **132 mutasi unik: 128 tertangkap, 4 setara** (policy 22, server 17, bench/web/compose/tool/probe/prompt 93). Awalnya lolos: policy E1/E3/E4/E11/E22; server V13/V14/V17; sesi ini 14 (N1, N11, N33, N34, N36, N37, N38, N39, N46, P4, P8, T3, T5, R3) → 12 ditutup dengan tes baru, 2 setara. Setara: V9 (`wait_for` dengan timeout ≤ 0 langsung `TimeoutError`), V16 (`line.decode("ascii")` menolak lebih awal), N34 (nama kosong tetap ditolak cek label), T3 (`shell_run` sudah disaring `shell` sebelum deskripsi dipakai) |
| Proses `egress-proxy` NYATA (entrypoint produksi, non-root, env seperti compose) + `curl` sungguhan | `https://example.com/` → **200** dan `https://www.iana.org/` → **200** (TLS sungguhan melewati terowongan); `iana.org` (padahal `*.iana.org` hanya subdomain), `github.com`, `169.254.169.254`, `localhost`, `:8443` → **403** dengan alasan di log; `GET` polos → 405; `--health` berhasil |
| Daemon NYATA di ABI v2 dengan `BENCH_NET_PROXY=egress:3128` | Log `PERINGATAN ... ABI < 4 ... jaringan DIMATIKAN` lalu `jaringan: mati`; nilai tak valid → peringatan + mati |
| Ujian menyeluruh shell (web asli + bench-daemon asli + "model" palsu) | **23 dari 23** tetap lulus (jaringan mati: tidak ada regresi) |
| Bagian jaringan `bench-selftest` (harness: ABI dipalsukan = 4, pengurungan diganti eksekusi biasa, melawan egress nyata) | Jalur kabel/logika terbukti: 10 target `DENY_TARGETS` (metadata cloud, loopback, privat, `redis`, `web`, proxy sendiri, `.internal`, IPv4 gaya lama) → 403; `SELFTEST_NET_URL=https://example.com/` → **HTTP 200** bila diizinkan, `curl: (7) CONNECT tunnel failed, response 403` bila tidak. **Bukan** bukti Landlock (lihat di bawah) |

### Temuan di luar fitur (rincian di `audit.md` 10.12)
`*.` (salah ketik) menjadi `*` di dua parser (membuka semua host), NAT64 `is_global=True`, IP gaya lama, header 20 KB memutus koneksi tanpa jawaban, prompt awalnya menyuruh memakai `curl` yang tidak ada di image, tes konstanta kernel yang melingkar.

### BELUM terbukti (jujur)
- **Docker:** tidak ada daemon di sandbox. Belum teruji: `benchnet` benar-benar tanpa rute keluar, `egress` benar-benar punya rute keluar lewat `egressnet`, DNS Docker me-resolve `egress` pada jaringan internal, build image (`apt-get install curl ca-certificates`), healthcheck compose.
- **Landlock TCP (ABI ≥ 4) di kernel nyata:** sandbox ABI v2. Yang teruji hanya **argumen syscall** lewat simulasi (`FakeSys`) dan konstanta kernel yang dikunci angka literal. Perilaku kernel (EACCES untuk `connect()` selain port proxy) baru terbukti oleh `make bench-selftest` di VPS (ABI v4).
- **Kebocoran lewat DNS:** apakah DNS tertanam Docker pada jaringan `internal` meneruskan kueri ke luar tidak diketahui. Jika ya, DNS menjadi jalan keluar data yang melewati daftar putih. `bench-selftest` mengukurnya (`example.com` tidak boleh ter-resolve dari perintah AI) dan **GAGAL** bila bocor. Mitigasi (belum dipasang karena tidak bisa diverifikasi di sini): opsi `dns:` ke alamat tak terjangkau pada layanan `bench`.
- **`http://` lewat `curl -p`** hanya terbukti ditolak (403) saat port 80 tidak diizinkan; terowongan ke port 80 yang diizinkan belum dicoba. Tidak diuji juga: IPv6 keluar di VPS.
- **Jalur penuh web → bench → egress dengan model AI asli** belum dijalankan (butuh Docker + kunci AI + kernel ABI ≥ 4).

### Langkah untuk pemilik (VPS)
1. `git pull`, lalu `make bench-selftest` (membangun ulang `bench` dan `egress`; tanpa `AI_SHELL_NET_ALLOW` bagian proxy dilewati, **tetapi cek DNS tetap jalan**).
2. Isi `AI_SHELL_NET_ALLOW` di `.env` (mulai dengan satu host), `make restart`, lalu `make bench-selftest` lagi: bagian proxy harus semua `[OK ]`.
3. `make net-check URL=https://host-anda/jalur` membuktikan jalur penuh (HTTP 200 dari kontainer yang terkurung).
4. Baru nyalakan `AI_SHELL_ENABLED=1`. Kirim keluaran bila ada `[GAGAL]`.

## Pertanyaan terbuka
- [DIPUTUSKAN] Isolasi antar analisis di `bench`: **Landlock (opsi 2)**, berdasarkan `scripts/bench-probe.sh` di VPS (lihat Status PR A). [OPEN] diuji ulang dengan pengaturan kontainer `bench` yang sebenarnya.
- [DIPUTUSKAN] Batas unggah hingga **1 GB**. [OPEN] nilai akhir batas lain yang ikut terdampak (tabel "Batas ukuran"), ditentukan dengan pengukuran APK besar sungguhan.
- [SEBAGIAN TERBUKTI] jadx 1.5.6 membuka `.xapk` langsung (XAPK nyata, 32 dtk) dan APKEditor menggabungkannya, tetapi **dipakai** hanya base asli (lihat Status PR A). `.apkm` dan `.aab` belum terbukti; butuh sampel nyata.
- [DIPUTUSKAN] Build-Tools **37.0.0** (stabil terbaru; `37.0.0-rc*` preview). Kebutuhan glibc terukur dengan `objdump -T` di sandbox: `zipalign` GLIBC_2.14 dan `libc++.so` GLIBC_2.17 (aapt2 di dalam jar apktool terhubung statis, tanpa kebutuhan glibc), sementara image trixie memakai glibc 2.41 (angka dari rencana, belum diukur di image). [OPEN] uji di Docker nyata: `docker compose --profile build build signer && make signer-selftest` di VPS.
- [OPEN] Apakah "paket format asal" (FR-9.17b) cukup bernilai untuk dikerjakan, atau cukup `merged.apk`. Dinilai setelah PR B.

## Status paket B-1b (14 Okt 2026): toolchain penanda tangan

**Sudah ada (HANYA penyediaan alat):**
- `services/signer/Dockerfile`: `python:3.12-slim-trixie` + `openjdk-21-jre-headless` + `zipalign` dan `apksigner` dari Build-Tools 37.0.0 resmi Google, SHA-256 dipin dan diverifikasi (`sha256sum -c`) SEBELUM ekstraksi. Tanpa keystore di image, user uid 10001.
- `services/signer/signer-selftest` (`make signer-selftest`): keystore SEMENTARA → `zipalign` → `apksigner sign` → `apksigner verify` (v2 dan v3), tes negatif (tanpa tanda tangan; dirusak setelah ditandatangani), dan bukti isolasi kontainer.
- Layanan `signer` di compose: `network_mode: none`, `read_only`, `cap_drop: ALL`, tanpa volume dan tanpa secrets, profil `build` (tidak ikut `make up`).
- `make tools-check`: tabel versi java/apktool/jadx/keytool/zipalign/apksigner dari image runner dan signer. `runner-selftest` kini juga memeriksa `keytool` dan bahwa `apktool b` membangun proyek smali minimal OFFLINE (di kontainer nyata, awalnya GAGAL: lihat "Status perbaikan aapt2/noexec").

**Belum ada (sengaja):** `signer-daemon`, pembuatan/penyimpanan keystore (menunggu keputusan pemilik soal jenis kunci), tahap `build` di runner/worker, migrasi DB, persetujuan, tool AI, UI.

**Keputusan:** Build-Tools resmi Google + pin SHA-256, bukan paket apt `apksigner` (35.0.2, lebih tua; bergantung pada `default-jre | javaN-runtime` sehingga kemungkinan menarik JRE non-headless: dugaan dari metadata, belum diuji). Rantai alat tetap `apktool b` → `zipalign -P 16 -f 4` → `apksigner sign` → `apksigner verify`.

**Terbukti di sandbox (tanpa Docker):** hash SHA-256/SHA-1 dan penolakan hash salah; ekstraksi 3 berkas dan `libc++.so` ditemukan via RUNPATH (kontrol negatif: dipindah → `zipalign` gagal); `signer-selftest --toolchain-only` hijau dan mutasi alat tertangkap; rantai penuh `apktool b` (offline, di sandbox yang `/tmp`-nya boleh exec; di kontainer runner lihat koreksi di bawah) → `zipalign` → `sign` → `verify` v2/v3 `true`; APK tanpa tanda tangan dan APK yang dirusak → `DOES NOT VERIFY`. Java sandbox 25 dan 21.0.2 (image: 21).
**Belum diuji (butuh Docker di VPS):** `docker build` image signer (apt, guard `ldd` di trixie, ukuran image), bagian isolasi kontainer pada `signer-selftest`, `docker compose --profile build`, `make tools-check` penuh, heap `-Xmx256m` untuk APK besar.

**Langkah untuk pemilik:** lihat "Alat build & tanda tangan APK (B-1b)" di `docs/deploy.md`; keputusan jenis kunci keystore diperlukan sebelum B-1c.

## Status perbaikan aapt2/noexec (14 Okt 2026): `apktool b` di kontainer runner

**Temuan di VPS pemilik (Docker nyata):** `make runner-selftest` → `[GAGAL] apktool b dapat membangun proyek smali minimal OFFLINE — kode 1: ...ProcessImpl.start...` dan `[GAGAL] hasil build adalah APK utuh`. Di kontainer: `tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,...` dan `cp /bin/true /tmp/t && /tmp/t` → `Permission denied`.

**Akar masalah:** compose memakai `tmpfs: /tmp:rw,size=256m,nosuid`; Docker menambahkan `noexec`. Tanpa `--aapt`, apktool 3.0.3 mengekstrak aapt2 dari jarnya (`prebuilt/linux/aapt2`, 6.449.680 byte, statis) ke `java.io.tmpdir` lalu menjalankannya → exec ditolak. `apktool d` tidak terpengaruh (decode tidak memanggil aapt2).

**Keputusan (mengikat):** `/tmp` runner TIDAK diberi `exec`. Runner memproses APK tak tepercaya, jadi `/tmp` tanpa exec adalah pertahanan berlapis yang sengaja dijaga. Sebagai gantinya:
- `services/runner/Dockerfile` mengekstrak `prebuilt/linux/aapt2` ke `/opt/apktool/aapt2` (root, 0755, read-only saat runtime), memverifikasi `ARG AAPT2_SHA256` (`df312db8…368cc`, dihitung dari jar apktool 3.0.3 ber-SHA-256 `dbf930b0…9423`) dengan `sha256sum -c`, memeriksa header ELF 64-bit x86-64, dan menjalankan `aapt2 version` saat build. Build digagalkan dengan pesan jelas bila `uname -m` bukan `x86_64` (aapt2 prebuilt Linux hanya x86-64; jar apktool/jadx sendiri tidak terikat arsitektur, tetapi image runner kini hanya untuk amd64).
- Wrapper `/usr/local/bin/apktool` menyisipkan `--aapt /opt/apktool/aapt2` bila subperintah pertama `b`/`build`; subperintah lain (`d`, `--version`) tidak diubah. **KOREKSI: ini TIDAK cukup di kontainer nyata** (apktool lalu memanggil `chmod` pada aapt2); lihat "Perbaikan lanjutan" di bawah, tempat wrapper kini menyisipkan `--aapt /opt/aapt-exec/aapt2` (salinan terverifikasi).
- `runner-selftest`: `apktool b` lewat wrapper yang sama; pemeriksaan baru "tmp runner noexec" (opsi mount + percobaan exec sungguhan), "aapt2 terpasang di rootfs" (ELF, executable, milik root, tidak bisa ditulis, sha256 cocok `AAPT2_SHA256` dari ENV image), "wrapper menyisipkan --aapt"; pesan GAGAL kini memuat baris `Caused by:`/`error=` dan 300 karakter pertama keluaran bermakna (bukan lagi ekor stack trace).
- `scripts/sample-apk/build.py` memakai `--aapt /opt/apktool/aapt2` (skrip itu juga memakai `--tmpfs /tmp` tanpa exec, jadi sebelumnya hampir pasti gagal di kontainer sungguhan). **Dikoreksi di perbaikan lanjutan:** kini memanggil `apktool b` lewat wrapper dan memasang tmpfs `/opt/aapt-exec`.
- Tes `tests/test_runner_aapt2.py` menjaga: tidak ada tmpfs runner/bench/signer/egress yang memuat `exec` supaya bug ini tak "diperbaiki" dengan melemahkan isolasi. (Diperbarui sadar di perbaikan lanjutan: kini "tepat satu tmpfs exec", lihat di bawah.)

**Terbukti di sandbox (tmpfs `noexec,nosuid,nodev` NYATA lewat `unshare -Urm`; JDK 25, bukan Docker):** tanpa `--aapt` → `Cannot run program ".../aapt2_*.tmp": error=13 (Permission denied)`, keluar 1; dengan wrapper final → keluar 0, APK utuh (`testzip` None; `classes.dex` magic `dex\n037`), TIDAK ada `aapt2_*.tmp` di `/tmp`, satu-satunya berkas di tmpfs hanya `HOME/.local/share/apktool/framework/1.apk` (jar framework, dibaca bukan dieksekusi). `apktool d` dan `--version` lewat wrapper tetap jalan. Potongan `RUN` Dockerfile dijalankan apa adanya (jalur diganti): `sha256sum -c` OK, ELF x86-64 statis, `aapt2 version` jalan.
**Belum diuji (butuh Docker di VPS):** `docker compose build runner` (apt, `uname -m`, `unzip -p` pada image nyata, JRE 21 trixie), `make runner-selftest` (semua `[OK ]` termasuk `apktool b ... OFFLINE` dan `tmp runner noexec`), `python3 scripts/sample-apk/build.py` di kontainer sungguhan, `apktool d --aapt` (tidak dipakai).

## Perbaikan lanjutan (14 Okt 2026): chmod aapt2 pada rootfs read-only — tmpfs exec khusus `/opt/aapt-exec`

**Temuan di VPS pemilik (Docker nyata, SESUDAH perbaikan di atas):**
```
[OK ] tmp runner noexec — mount /tmp: rw,nosuid,nodev,noexec,relatime; exec dari /tmp ditolak (benar, disengaja)
[OK ] aapt2 terpasang di rootfs (ELF, executable, sha256 cocok pin) — /opt/apktool/aapt2 6449680 byte sha256 df312db814c0…
[OK ] wrapper apktool menyisipkan --aapt untuk b
[GAGAL] apktool b dapat membangun proyek smali minimal OFFLINE — kode 1: keluaran: Could not set aapt binary as executable: /opt/apktool/aapt2
```
`python3 scripts/sample-apk/build.py` di VPS gagal dengan pesan yang sama.

**Akar masalah (Apktool v3.0.3, `AaptManager.setBinaryExecutable`):** fungsi itu menolak berkas yang tak terbaca, lalu `if (!binFile.setExecutable(true)) throw "Could not set aapt binary as executable"`. `File.setExecutable(true)` di JDK memanggil `chmod(2)` SELALU, walau mode tidak berubah. Di runner `chmod` ditolak: rootfs `read_only: true` (EROFS) dan berkas milik root sedangkan proses uid 10001 (EPERM). Jadi `--aapt` ke berkas di rootfs read-only milik root TIDAK PERNAH lolos. Perbaikan sebelumnya lolos uji sandbox hanya karena berkas aapt2 di sandbox milik pengguna yang sama pada disk yang bisa ditulis.

**Keputusan (mengikat; pin apktool/jadx/aapt2/Build-Tools TIDAK berubah, jar TIDAK ditambal, `/tmp` TETAP noexec):**
- `docker-compose.yml`, service `runner`: tmpfs kedua `/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755`. Ini SATU-SATUNYA tmpfs exec di seluruh stack. 16m: aapt2 6,15 MiB; penggantian atomik butuh ≤ 2 salinan (≈ 12,3 MiB). `network_mode`, `cap_drop`, `read_only`, `user`, `security_opt` runner tidak diubah.
- `services/runner/Dockerfile`: `mkdir -p /opt/aapt-exec` (titik mount, milik root, kosong); pin ditulis ke `/opt/apktool/aapt2.sha256` dari `ARG AAPT2_SHA256` (berkas, bukan ENV: `runner-daemon` dan `runner-selftest` menjalankan alat dengan lingkungan yang dibersihkan sehingga ENV tidak ikut). Biner sumber tetap di `/opt/apktool/aapt2` (root, 0755, hash dipin).
- Wrapper pindah dari `printf` bertingkat kutip ke berkas `services/runner/apktool-wrapper`: untuk `b`/`build` menyalin aapt2 ke `/opt/aapt-exec/aapt2` secara atomik (berkas sementara + `mv -f`, dikunci `flock`), memverifikasi sha256 SALINAN, memeriksa salinan bisa dijalankan, baru menyisipkan `--aapt /opt/aapt-exec/aapt2`. Direktori yang bukan mount yang benar menghasilkan `GALAT apktool: ...` jelas. `-Duser.home` dan `-Djava.io.tmpdir=/tmp` dipertahankan. Opsi global di depan subperintah ditolak apktool 3.0.3 sendiri (`-v b` → `Unrecognized command: -v`, terbukti dengan jar asli), jadi hanya argumen pertama yang diperiksa dan pemanggil wajib `apktool b ...` (didokumentasikan + dikunci tes).
- `runner-selftest`: cek lama dipertahankan; cek baru: `/opt/aapt-exec` mount tmpfs terpisah dengan `exec`, `nosuid,nodev`, ≤ 16 MiB, milik uid 10001 sementara `/tmp` TETAP noexec; sumber aapt2 tidak bisa diubah runner (`chmod` dan tulis ditolak); isi `/opt/aapt-exec` hanya `aapt2` ber-hash pin SESUDAH `apktool b`; `apktool b` sungguhan lewat wrapper produksi dalam lingkungan bersih.
- `scripts/sample-apk/build.py`: `--tmpfs /opt/aapt-exec:...` dan `apktool b ...` lewat wrapper.
- Tes: penjaga lama "tidak ada tmpfs exec" diganti SADAR menjadi "tepat satu tmpfs exec": hanya service `runner`, hanya `/opt/aapt-exec`, `nosuid,nodev`, ukuran ≤ 16m; tmpfs lain (runner `/tmp`, bench, signer, egress, web, worker, caddy, dan `--tmpfs` di skrip) tidak boleh exec. Penjaga dibuktikan tidak hampa dengan mutasi.

**Kompromi keamanan (jujur):** ada satu direktori kecil yang bisa DITULIS dan DIEKSEKUSI uid 10001 di runner yang memproses APK tak tepercaya. Mitigasi: tanpa jaringan, `cap_drop: ALL`, `no-new-privileges`, rootfs read-only, `/tmp` tetap noexec, `nosuid,nodev`, 16 MiB, hilang tiap kontainer, hanya `aapt2` pin yang diharapkan (diperiksa selftest). Ini melemahkan pertahanan berlapis dibanding sebelumnya dan diterima dengan sadar; alternatif `exec` pada `/tmp` dan menambal jar ditolak.

**PELAJARAN:** uji sandbox untuk kontainer harus meniru NON-PEMILIK dan FILESYSTEM READ-ONLY (uid proses ≠ pemilik berkas, mount `ro`), bukan hanya `noexec`. Perbaikan sebelumnya meleset karena itu.

**DIBUKTIKAN di sandbox** (root nyata → `unshare -m` → `setpriv --reuid=10001`; jar apktool 3.0.3 asli; JDK 25, bukan Docker): bug kedua direproduksi (non-pemilik EPERM, mount `ro` EROFS) dengan pesan yang sama dengan VPS; tata letak baru (tmpfs `exec,nosuid,nodev,size=16m,uid=10001` + `/tmp` tmpfs noexec + sumber di bind-mount `ro` milik root) membangun APK utuh lewat wrapper nyata sebagai uid 10001; hash salah, sumber hilang, salinan korup, direktori hilang/noexec/tak bisa ditulis, empat build paralel; tes repo (gagal di kode lama, lulus di kode baru) dan mutasi penjaga.
**BELUM DIUJI (butuh Docker di VPS):** `docker compose build runner` (apt, `COPY` wrapper, berkas pin, `mkdir`), Docker/Compose VPS menerima `uid/gid/mode/exec/nosuid/nodev/size` pada tmpfs bentuk pendek, `make runner-selftest` penuh (cek baru), `python3 scripts/sample-apk/build.py`, JRE 21 trixie dan overlayfs `read_only` nyata, `flock` di image. Hasil diharapkan: semua `[OK ]` termasuk `apktool b ... OFFLINE`, cek `/opt/aapt-exec` dan APK sampel jadi.
**Risiko residual:** bila opsi `uid/gid/mode` ditolak (gejala: `invalid mount option`/`mount: invalid argument`, atau selftest `dimiliki uid ..., harus 10001`), cadangannya mengganti HANYA opsi menjadi `size=16m,mode=1777` tanpa `uid/gid` (berkas buatan uid 10001 tetap miliknya sehingga `chmod` lolos); bentuk panjang `type: tmpfs` BUKAN cadangan karena tak bisa `exec`.
