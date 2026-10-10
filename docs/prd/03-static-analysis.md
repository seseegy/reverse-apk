# 03 — Static Analysis

## Tujuan
Menghasilkan fakta deterministik (tanpa LLM) dari APK, plus indeks kode yang bisa dicari cepat. Ini fondasi bagi AI: LLM menerima fakta ringkas dan mencari detail lewat indeks, bukan membaca semua kode.

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-3.1 | **Manifest**: package, versi, min/target SDK, permission, komponen (activity/service/receiver/provider), main launcher, flag `debuggable`, `allowBackup`, `usesCleartextTraffic`, komponen `exported` | P0 |
| FR-3.2 | **Sertifikat penanda tangan**: subjek, penerbit, fingerprint SHA-256, skema v1/v2/v3, debug cert? | P0 |
| FR-3.3 | **Indeks kode**: daftar package/class/method (nama, ukuran, jumlah baris), disimpan di SQLite + FTS5 | P0 |
| FR-3.4 | **Ekstraksi string**: URL, domain, IP, path API, base64/hex panjang, string dari resource | P0 |
| FR-3.5 | **Deteksi secret** (regex + entropi): API key, token, kunci privat, kredensial hard-coded; tiap temuan berisi lokasi dan potongan ter-mask | P0 |
| FR-3.6 | **Endpoint & jaringan**: URL dasar, anotasi Retrofit, pemakaian OkHttp, `network_security_config`, certificate pinning | P0 |
| FR-3.7 | **Pemakaian crypto**: `Cipher.getInstance` (mode/padding), `MessageDigest`, `SecureRandom` vs `Random`, kunci statis | P0 |
| FR-3.8 | **Library/SDK pihak ketiga** dari nama package + versi bila ada (iklan, analytics, payment, dll.) | P1 |
| FR-3.9 | **Sinyal obfuscation**: rasio nama 1–2 huruf, ProGuard/R8 mapping, packer/native loader dikenal | P0 |
| FR-3.10 | **Komponen berisiko**: WebView + `addJavascriptInterface`, `rawQuery` dengan konkatenasi, ContentProvider `openFile`, intent implisit | P1 |
| FR-3.11 | **Native libs**: daftar `.so`, ABI, export JNI (`Java_*`), string menarik | P1 |
| FR-3.12 | **Call graph ringan**: siapa memanggil method X (untuk tool `find_xrefs`) | P1 |
| FR-3.13 | **Diff antar versi APK** (manifest, permission, endpoint, class baru/hilang) | P1 |

## Format output
Semua temuan disimpan sebagai `finding`:
```
category: manifest|network|secret|crypto|webview|storage|native|obfuscation|library
severity: info|low|medium|high   # heuristik, bukan klaim kerentanan final
title, description
evidence: [{file, line_start, line_end, snippet(masked)}]
source: static
```

## Referensi checklist
Aturan deteksi (FR-3.1, 3.5–3.7, 3.10) mengacu pada checklist umum seperti OWASP MASTG. Isi checklist dari skill eksternal (lihat 04) boleh dijadikan **bahan**, tetapi aturan akhir ditulis dan diuji di repo ini.

## Kebutuhan non-fungsional
- NFR-3.1: Indexing APK 50 MB ≤ 2 menit.
- NFR-3.2: Pencarian FTS atas indeks ≤ 500 ms.
- NFR-3.3: Setiap aturan deteksi punya unit test dengan sampel positif dan negatif.
- NFR-3.4: Secret tidak pernah ditulis penuh ke log; di UI di-mask dan bisa di-reveal manual.

## Kriteria penerimaan
- APK uji dengan API key palsu yang sengaja ditanam → muncul sebagai temuan `secret` beserta lokasi.
- `debuggable=true` pada APK uji → temuan `manifest/high`.
- Query "login" pada indeks mengembalikan class terkait ≤ 500 ms.

## Pertanyaan terbuka
- [OPEN] Pakai androguard, atau parsing manifest sendiri dari output apktool + baca DEX via `dexlib`? (usul awal: androguard + parsing XML apktool)
- [OPEN] Ambang entropi untuk deteksi secret yang menyeimbangkan false positive.
