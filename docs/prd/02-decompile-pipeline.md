# 02 — Decompile Pipeline

## Tujuan
Mengubah APK menjadi artefak yang bisa dibaca (Java, smali, resource, manifest) secara andal, terisolasi, dan terukur, tanpa pernah menjalankan APK.

## Alur
```
queued → validating → decoding(apktool) → decompiling(jadx) → indexing → analyzing(static)
       → ai_summarizing (opsional) → done | failed | cancelled
```

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-2.1 | Antrian job (Redis + RQ/Celery); 1–2 worker paralel (konfigurabel) | P0 |
| FR-2.2 | Jalankan `apktool d` untuk manifest, resource, smali | P0 |
| FR-2.3 | Jalankan `jadx` (flag `--deobf` opsional) untuk source Java; tahan error parsial (output parsial tetap dipakai) | P0 |
| FR-2.4 | Status job real-time (SSE/WebSocket) dengan log per tahap | P0 |
| FR-2.5 | Timeout per tahap (default: apktool 5 mnt, jadx 15 mnt) dan batalkan job | P0 |
| FR-2.6 | Catat versi tool dan argumen yang dipakai di `analysis.tool_versions` | P0 |
| FR-2.7 | Retry otomatis 1× untuk kegagalan sementara; kegagalan permanen tersimpan dengan pesan error | P1 |
| FR-2.8 | Multi-dex dan split APK ditangani (semua `classes*.dex`) | P0 |
| FR-2.9 | Error jadx dirinci per method (penyebab, dampak) dan ditampilkan ringkas di UI & ke AI, tanpa membanjiri log | P1 |
| FR-2.9 | Re-run tahap tertentu tanpa mengulang semuanya | P1 |
| FR-2.10 | Ekstrak `lib/*.so` dan DEX tertanam; tandai untuk analisis native (tanpa menganalisis di MVP) | P1 |

## Isolasi worker (wajib)
Setiap job berjalan di container sekali pakai:
- `--network none`
- user non-root, `--read-only` rootfs, tmpfs untuk `/tmp`
- `--cap-drop ALL`, `--security-opt no-new-privileges`, profil seccomp default
- batas: `--memory 3g`, `--cpus 2`, `--pids-limit 512`, kuota disk working dir, timeout keras
- hanya mount: APK (read-only) dan direktori output job (read-write)
- JVM heap jadx diatur eksplisit (`JAVA_OPTS=-Xmx2g`)

APK **tidak pernah** dieksekusi, di-install, atau dimuat di emulator.

## Kebutuhan non-fungsional
- NFR-2.1: APK 50 MB biasa selesai dekompilasi ≤ 5 menit di spek VPS.
- NFR-2.2: Kegagalan satu job tidak mengganggu job lain atau web.
- NFR-2.3: Setelah restart server, job `running` yang terputus ditandai `failed` lalu bisa di-retry.
- NFR-2.4: Image worker dipin versinya (jadx, apktool, JDK) dan dibangun ulang secara terkontrol.

## Kriteria penerimaan
- APK contoh (app sampel sendiri) menghasilkan folder `jadx/` dan `apktool/` dengan manifest terbaca.
- Job yang melebihi timeout dihentikan, container dihapus, status `failed: timeout`.
- Dari dalam container worker, `curl https://example.com` gagal (tidak ada jaringan).
- Dua job bersamaan tidak melebihi batas RAM total yang ditetapkan.

## Kebijakan kegagalan (M1)
| Kondisi | Hasil |
|---------|-------|
| Timeout tahap, batas keluaran terlampaui, runner mati | Analisis **gagal** (`timeout` / `output_limit` / `runner_unavailable`) |
| jadx keluar non-nol tetapi ada source Java | Tahap `peringatan`, analisis tetap lanjut (FR-2.3) |
| jadx keluar 0 tetapi **tidak ada** source Java | Tahap **gagal** (dex rusak; exit 0 saja menyesatkan) |
| jadx melaporkan `finished with errors, count: N` | Tahap `peringatan` dengan satu pesan ringkas berisi N; rincian per method tidak membanjiri log (lihat "Laporan error jadx") |
| Satu tool gagal, yang lain berhasil | Analisis `selesai` dengan peringatan |
| Kedua tool gagal | Analisis **gagal** (`tool_error`) |
| Worker/server restart saat job berjalan | `failed: interrupted`, bisa **Coba lagi** (NFR-2.3) |
| Runner restart saat tahap berjalan | Tahap diulang otomatis 1× (FR-2.7), lalu gagal bila terulang |

## Catatan teknis
- JVM mengabaikan `$HOME` dan memakai home dari `/etc/passwd`; pada rootfs read-only, jadx/apktool gagal total.
  Runner memaksa `-Duser.home` ke direktori tmpfs per-job. `make runner-selftest` kini menjalankan kedua alat
  (bukan hanya `--version`) agar regresi ini tertangkap.

## Pertanyaan terbuka
- [DIPUTUSKAN di M1] Tidak memakai Docker socket sama sekali. Service `runner` terpisah (tanpa jaringan, Redis, atau DB) menerima job lewat volume `spool` berbasis berkas (`services/rvcore/spool.py`). Alasan: socket-proxy tidak bisa membatasi *isi* `create container`, sehingga kompromi worker setara root di host.
  - **Penyimpangan dari "container sekali pakai"**: runner satu proses yang memproses job berurutan (1 job paralel). Untuk mendekati isolasi sekali pakai, runner **keluar setelah tiap job** dan Docker memulai container baru (`RUNNER_RECYCLE=1`): tmpfs, memori, dan proses bersih. Setiap tool berjalan di process group sendiri yang dimatikan seluruhnya saat timeout/batal.
  - Paralelisme 2 job (FR-2.1) belum diaktifkan; menambah instance runner kedua adalah langkah berikutnya bila diperlukan.
- [OPEN] Perlu `dex2jar`/CFR sebagai pembanding bila jadx gagal pada method tertentu?

## Laporan error jadx (FR-2.9)

Pada APK Kotlin/Compose/R8, jadx hampir selalu gagal pada sebagian kecil method (contoh terukur: NewPipe 117 dari 5.643 unit, VLC 365; APK pengguna 18 dari 24.515 = 0,07%). Itu normal, tetapi pengguna berhak tahu **method mana, kenapa, dan seberapa parah**.

- Runner menjalankan jadx dengan `--log-level error` (+ `--show-bad-code`) agar tiap kegagalan tercatat per method. Stack trace Java (`\tat ...`) dibuang saat menulis `jadx.log` oleh `FrameFilter` (aman terhadap potongan chunk), ukuran log 150 KiB → ~50 KiB pada NewPipe.
- `LogTail` (worker) **menelan** baris rincian per method dari log pipeline: pengguna hanya melihat progres, satu baris info jumlah, dan satu peringatan penjelas di akhir tahap. Kegagalan jadx sungguhan (zip rusak, OOM, dsb.) tetap tampil sebagai error.
- Analyzer (`analyzer/jadxlog.py`) mem-parse `jadx.log` secara linear (bukan satu regex besar: regex awal 20 dtk pada baris patologis, kini 0,01 dtk) dan menulis `index/decompile_errors.jsonl` (`method, class, type, category, pass, reason`) serta blok `summary.decompile`: jumlah error, per jenis/kategori, penilaian (`baik`/`sebagian`/`banyak`), dan penanda `/* JADX WARN */` di Java per tingkat dampak (`hilang`, `struktur`, `tipe`, `kosmetik`).
- Web: kartu **Hasil dekompilasi** di Ringkasan (penilaian, penjelasan "Kenapa gagal?" dan "Yang dilakukan", tabel method dengan filter) dan `GET /analyses/{id}/decompile/errors` (JSON, perlu sesi) untuk daftar lengkap.
- AI: `get_overview` memuat blok `dekompilasi`, sehingga model tahu method mana yang harus dibaca lewat smali (`get_method`/`read_file`).
- Analisis lama menampilkan "tanpa rincian" sampai **analisis ulang penuh** (analisis ulang statis memakai ulang log jadx lama).
- Opsi jadx yang diukur dan **tidak** mengurangi error pada NewPipe: `-Xss16m/64m`, `--type-update-limit 100` (117 tetap 117). Karena itu tidak dipakai; hanya informasinya yang diperbaiki.
