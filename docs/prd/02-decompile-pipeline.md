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
