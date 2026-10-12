# 09 — Paket multi-APK & bengkel modifikasi

> **Status: RENCANA. Belum ada kode.** Dokumen ini adalah rancangan untuk disetujui. Selama belum dikerjakan, pernyataan di 00 §4, 05 "Prinsip", dan 07 "Model ancaman" **tetap berlaku apa adanya** (tidak ada shell, tidak ada penulisan APK, tidak ada tanda tangan). Tiap PR implementasi di bagian "Urutan kerja" mengubah pernyataan itu bersamaan dengan kodenya.

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
 web (AI) ──► benchspool (volume khusus web↔bench) ──► bench (tanpa jaringan)
                                                          └─ ruang kerja per analisis (volume `bench`)
```
| Aspek | Rancangan |
|---|---|
| Jaringan | `network_mode: none` |
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
| **B** | Build + tanda tangan **tanpa AI**: ruang kerja, diff, persetujuan, tahap `build`, layanan `signer`, `make init` membuat keystore, unduhan, audit | APK sampel diubah manual (mis. mengganti string), disetujui, dibangun, `apksigner verify` lulus, dan `aapt2 dump badging` benar; tanpa persetujuan tidak ada job |
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
- **`apksigner` / `zipalign`** dari Android SDK Build-Tools (terbaru 37.0.0, zip Linux ±66 MB). Google menerbitkan **hanya SHA-1** untuk paket ini; maka SHA-256 dihitung sendiri saat pertama diunduh, dipin di Dockerfile, dan SHA-1 Google dipakai sebagai pembanding.
- Dokumentasi Google menegaskan `zipalign` dijalankan **sebelum** `apksigner` (menandatangani lalu mengubah berkas membatalkan tanda tangan) → sudah di FR-9.22.

## Pertanyaan terbuka
- [OPEN] Isolasi antar analisis di `bench`: data VPS sudah ada (Landlock aktif); menunggu hasil `scripts/bench-probe.sh` di VPS.
- [DIPUTUSKAN] Batas unggah hingga **1 GB**. [OPEN] nilai akhir batas lain yang ikut terdampak (tabel "Batas ukuran"), ditentukan dengan pengukuran APK besar sungguhan.
- [OPEN] Memastikan jadx 1.5.6 membuka `.aab/.xapk/.apkm/.apks` dengan benar dan apakah `merged.apk` dari APKEditor lulus `apktool d`. README jadx menyatakan didukung, tetapi sampel yang tersedia placeholder; butuh sampel nyata dari pemilik. Klaim "didukung" di UI baru ditulis setelah terbukti.
- [OPEN] Versi pasti Build-Tools yang dipin (kandidat: 37.0.0) dan uji bahwa `zipalign`/`apksigner` berjalan di image `python:3.12-slim-trixie` (pustaka sistem yang dibutuhkan biner bawaan Google).
- [OPEN] Apakah "paket format asal" (FR-9.17b) cukup bernilai untuk dikerjakan, atau cukup `merged.apk`. Dinilai setelah PR B.
