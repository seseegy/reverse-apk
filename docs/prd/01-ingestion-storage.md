# 01 — Ingestion & Storage

## Tujuan
Menerima berkas dengan aman, mengenali duplikat, dan menyimpan semua artefak per analisis dengan struktur yang rapi dan bisa dibersihkan.

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-1.1 | Upload `.apk` lewat UI (drag & drop) dengan progress | P0 |
| FR-1.2 | Dukungan `.xapk` / `.apks` / `.apkm` (ekstrak base + split APK) | P1 |
| FR-1.3 | Hitung SHA-256, MD5, ukuran saat upload | P0 |
| FR-1.4 | Dedup: jika SHA-256 sudah ada, tawarkan "buka hasil lama" atau "analisis ulang" | P0 |
| FR-1.5 | Validasi: magic bytes ZIP, ada `AndroidManifest.xml` dan `classes*.dex`, batas ukuran | P0 |
| FR-1.6 | Cek anti zip-bomb: rasio kompresi, total ukuran terekstrak, jumlah entri, path traversal (`../`) | P0 |
| FR-1.7 | Pernyataan otorisasi (checkbox) wajib sebelum upload diproses | P0 |
| FR-1.8 | Tag, catatan, dan nama tampilan per APK | P1 |
| FR-1.9 | Hapus analisis (berkas + DB + cache AI) | P0 |
| FR-1.10 | Retensi otomatis: hapus hasil dekompilasi > N hari (default 30), simpan laporan & metadata | P1 |

## Kebutuhan non-fungsional
- NFR-1.1: Upload besar di-stream ke disk (tidak dimuat ke memori).
- NFR-1.2: Nama berkas asli tidak dipakai sebagai path; semua disimpan berdasar ID/hash.
- NFR-1.3: Berkas upload disimpan read-only setelah tervalidasi.
- NFR-1.4: Disk guard: tolak upload bila sisa disk < 15 GB.

## Model data (ringkas)
```
apk            id, sha256 (unique), md5, filename_display, size, package, version_name,
               version_code, min_sdk, target_sdk, created_at, notes, tags
analysis       id, apk_id, status, started_at, finished_at, tool_versions(json),
               ai_enabled, error
artifact       id, analysis_id, kind (jadx|apktool|report|strings|index), path, size
finding        id, analysis_id, category, severity, title, evidence(json), source (static|ai)
ai_call        id, analysis_id, purpose, model, input_tokens, output_tokens, cache_hit_tokens,
               cost_usd, created_at
chat_session   id, analysis_id, created_at
chat_message   id, session_id, role, content, tool_calls(json), citations(json), created_at
audit_log      id, ts, action, detail(json)
```

## Struktur di disk
```
/data/
  uploads/<sha256>.apk
  work/<analysis_id>/
    jadx/          # source Java hasil dekompilasi
    apktool/       # smali + resources + manifest
    index/         # sqlite FTS + json (class, string, endpoint)
    report.md
  db/app.sqlite
```

## Kriteria penerimaan
- Upload APK valid → tampil di daftar dengan hash dan metadata dasar dalam ≤ 5 dtk setelah selesai upload.
- Zip bomb sintetis (rasio > 100:1) ditolak dengan pesan jelas, tanpa menghabiskan disk.
- Upload kedua dari berkas sama tidak membuat salinan baru.
- Menghapus analisis mengosongkan seluruh `work/<id>` dan baris terkait.

## Pertanyaan terbuka
- [DIPUTUSKAN di M1] SQLite mode WAL, dibagi web dan worker lewat volume `db` (runner tidak punya akses). Skema dimigrasi lewat `PRAGMA user_version` (`services/rvcore/db.py`).
- [OPEN] Perlu enkripsi at-rest untuk `/data`?
- [DIPUTUSKAN di M1] Batas ukuran APK 200 MB (`MAX_UPLOAD_MB`). Unggahan berupa badan mentah (octet-stream) dengan metadata di header, bukan multipart, agar bisa di-stream ke disk tanpa melewati tmpfs berbasis RAM.
