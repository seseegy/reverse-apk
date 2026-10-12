# Audit reverse-apk

> **Dibuat:** 10 Okt 2026 · **Kode yang diaudit:** `main` @ `71054ba` (setelah PR #23) · **Sifat:** hanya temuan, **belum ada perbaikan** di dokumen ini.
> Dokumen ini ditulis agar sesi berikutnya bisa langsung bekerja tanpa membaca riwayat percakapan.

## 0. Cara membaca

| Tanda | Arti |
|---|---|
| **Terverifikasi** | Direproduksi (dijalankan dan hasilnya diamati) atau dibuktikan langsung dari kode. Ada langkah reproduksi. |
| **Dugaan** | Berdasarkan pembacaan kode/pola, belum dijalankan. Verifikasi dulu sebelum memperbaiki. |
| **Tinggi** | Risiko keamanan, kehilangan data, atau layanan mati. |
| **Sedang** | Bug yang terlihat pengguna, atau celah operasional yang membuat masalah tak bisa didiagnosis. |
| **Rendah** | Konsistensi, polesan, ketahanan kasus tepi. |
| **Catatan** | Informasi atau keputusan desain yang perlu konfirmasi pemilik. |

ID: `BE` backend · `OP` operasional/konfigurasi · `UI` antarmuka & UX · `DOC` dokumen · `QA` proses pengujian.

## 1. Ringkasan

**Kesehatan umum: baik.** Tidak ditemukan celah keamanan tingkat Tinggi. Fondasi kuat: semua 39 rute memeriksa sesi, semua POST memeriksa CSRF, header keamanan lengkap, tidak ada kebocoran informasi pada respons error, nol kerentanan dikenal pada 33 dependensi, dan nol pelanggaran kontras/label/ID ganda di 11 halaman × 5 ukuran layar (lihat §6).

Yang perlu dikerjakan, berurutan menurut nilai:

| # | Temuan | Tingkat | Status |
|---|---|---|---|
| **QA-01** | Seluruh tes (±70 skrip Python + 20 skrip Node) ada **di luar repo** (`/projects/.scratch`), tanpa CI. Hilang bila sandbox dibersihkan. | Tinggi (keberlanjutan) | Terverifikasi |
| **BE-01** | `session_id` integer raksasa di `POST /chat/send` → **HTTP 500** | Sedang | Terverifikasi |
| **BE-02** | `Last-Event-ID` berisi digit non-ASCII (`²`) di `/chat/stream` → **HTTP 500** | Sedang | Terverifikasi |
| **BE-03** | `text` bukan string diterima: `null` terkirim ke AI sebagai teks `"None"` | Sedang | Terverifikasi |
| **BE-04** | Galat di thread chat **tidak pernah dilog**; paket `ai/` tidak punya logging sama sekali | Sedang | Terverifikasi |
| **BE-05** | Audit log hanya mencakup 8 aksi; unggah/hapus berkas, tulis berkas AI, chat tidak tercatat | Sedang | Terverifikasi |
| **OP-01** | 14 variabel dibaca kode tetapi **tidak diteruskan compose** → tak bisa diatur lewat `.env` | Sedang | Terverifikasi |
| **UI-01** | Halaman melebar ke samping di layar 320px (semua halaman) | Sedang | Terverifikasi |
| **UI-02** | Target sentuh < 44px (sebagian < 24px, gagal WCAG 2.2 AA 2.5.8) | Sedang | Terverifikasi |
| BE-06…BE-12, OP-02…OP-04, UI-03…UI-05, UI-07, DOC-01 | Lihat rincian | Rendah | — |
| OP-05, UI-06, UI-08 | Butuh keputusan pemilik | Catatan | — |

Hitungan: **1 Tinggi (proses) · 8 Sedang · 15 Rendah · 3 Catatan** (27 butir; QA-02 hanya penunjuk ke §7).

> **Status terkini ada di §10** (11 Okt 2026): apa yang sudah diperbaiki beserta nomor PR, hasil pengukuran butir yang tadinya hanya dugaan angka, dan keputusan pemilik. Tabel di atas adalah temuan awal 10 Okt dan sengaja tidak diubah.

---

## 2. Backend

### BE-01 · `session_id` raksasa menyebabkan HTTP 500 — Sedang · Terverifikasi
- **Lokasi:** `services/web/app/routes_apk.py` ±baris 631–651 (`chat_send` → `prepare`) → `services/rvcore/store.py:370` (`get_chat_session`).
- **Penyebab:** `session_id` hanya dicek `isinstance(int)`; nilai > 2⁶³ membuat sqlite3 melempar `OverflowError: Python int too large to convert to SQLite INTEGER`.
- **Reproduksi:** `POST /analyses/1/chat/send` (sesi + header `X-CSRF-Token`), body `{"text":"x","session_id":1000000000000000000000000000000}` → `500`. Traceback ada di log web.
- **Saran:** validasi `0 < session_id < 2**31` (sama seperti `Path(ge=1, le=2**31-1)` di rute lain) dan balas `422`. Pertimbangkan handler global `OverflowError → 422`.

### BE-02 · `Last-Event-ID` non-ASCII menyebabkan HTTP 500 — Sedang · Terverifikasi
- **Lokasi:** `routes_apk.py:690–691`: `resume_at = int(last) + 1 if last.isdigit() else 0`.
- **Penyebab:** `str.isdigit()` bernilai `True` untuk `²`, `³`, dan digit Unicode lain, tetapi `int("²")` melempar `ValueError`. Header HTTP latin-1 mengizinkan `²` (0xB2).
- **Reproduksi (soket mentah):** `GET /analyses/1/chat/stream?s=<sid>` dengan header `Last-Event-ID: ²` → `500`. Nilai `9999…9` (40 digit) → 200 (aman, hanya melewati log).
- **Saran:** `last.isascii() and last.isdigit()` atau `try/except ValueError`, dan batasi panjang (mis. ≤ 12 digit).

### BE-03 · Validasi tipe `text` pada chat longgar — Sedang · Terverifikasi
- **Lokasi:** `routes_apk.py:617`: `text = str(body.get("text", "")).strip()`.
- **Pengamatan (diuji):** `{"text": null}` → 202 dan **tersimpan/terkirim sebagai `"None"`**; `123` → `"123"`; `["a"]` → `"['a']"`; `{"a":1}` → `"{'a': 1}"`; `"a\u0000b"` → NUL ikut tersimpan.
- **Dampak:** klien resmi tak pernah mengirim ini, tetapi memakan satu giliran AI berbayar dengan teks sampah, dan data aneh masuk riwayat.
- **Saran:** wajib `isinstance(text, str)` (selain itu `422`), tolak `\x00`.

### BE-04 · Galat di thread chat tidak dilog — Sedang · Terverifikasi
- **Lokasi:** `services/web/app/ai/chat.py:152` (`except Exception … emit("final", "Galat internal (…)")`); `grep -c "getLogger\|import logging"` pada `ai/{chat,agent,tools,provider}.py` = **0**.
- **Dampak:** pengguna hanya melihat "Galat internal (TipeError)". Operator tidak punya jejak untuk mendiagnosis. Saat diuji menghapus APK di tengah giliran AI, **tidak ada satu baris log pun** muncul. Satu-satunya jejak galat provider ada di tabel `ai_call` (kolom `error`) yang belum punya UI (tab "Biaya & Log" belum dibuat).
- **Saran:** `log.exception(...)` di `chat.py` (sertakan `session_id`, `analysis_id`, model; **jangan** sertakan isi pesan/kunci), dan `log.warning` untuk kegagalan tool di `run_tool`. Pakai logger `reverse-apk.ai` agar seragam dengan modul lain.

### BE-05 · Audit log tidak mencakup aksi baru — Sedang · Terverifikasi
- **Tercatat (8):** `upload`, `upload_duplicate`, `upload_rejected`, `analysis_retry`, `analysis_cancel`, `analysis_rerun_static`, `apk_delete`, `secret_reveal`.
- **Tidak tercatat:** unggah/hapus lampiran, **penulisan/pengeditan berkas oleh AI** (path, ukuran, sha256), hapus berkas, kirim pesan chat, hapus sesi chat, `POST /selftest`.
- **Dampak:** AI menulis ke disk dan berkasnya bisa diunduh; tidak ada jejak siapa/kapan. Bertentangan dengan tujuan PRD 07 (audit).
- **Saran:** tambah `file_upload`, `file_delete`, `ai_file_write` (di `FileStore.write_ai`/tool), `chat_session_delete`. Detail JSON kecil saja (id, path, size).

### BE-06 · Pembersihan unggahan "pending" hanya untuk analisis yang sama — Rendah · Terverifikasi
- **Lokasi:** `routes_files.py:113` → `FileStore.purge_stale_uploads(analysis)`.
- **Pengamatan:** lampiran pending berumur 10 jam di analisis 2 **tetap ada** setelah ada unggahan di analisis 1; baru hilang setelah ada unggahan di analisis 2. Analisis yang tak pernah menerima unggahan lagi menyimpan yatim selamanya (dihitung ke kuota).
- **Saran:** bersihkan global (semua analisis) sekali per unggahan atau saat startup (`init_storage`), mis. `DELETE … WHERE pending=1 AND created_at < ?` + hapus berkasnya.

### BE-07 · Tidak ada rekonsiliasi DB ↔ disk untuk berkas — Rendah · Terverifikasi
- **Berkas ada di DB, hilang di disk:** halaman Berkas tetap menampilkan barisnya; `/files/{id}/text` → 200 dengan `missing:true`; `/download` → 404; ZIP melewatinya **diam-diam** (200, tanpa pemberitahuan).
- **Berkas ada di disk, tak ada di DB (yatim):** tak tampil di UI dan tak dihitung kuota. Terjadi bila proses mati di antara `os.replace` dan `upsert_ai_file` (`userfiles.py` `write_ai`).
- **Saran:** perintah `make files-check` (laporan + opsi perbaikan) dan/atau lencana "berkas hilang" di halaman Berkas; tulis ke DB lebih dulu dengan status, atau bersihkan yatim saat startup.

### BE-08 · Daftar sesi chat dibatasi 30 tanpa petunjuk — Rendah · Terverifikasi
- **Lokasi:** `store.py:374` `list_chat_sessions(..., limit: int = 30)`.
- **Pengamatan:** dengan 41 sesi, sisi chat hanya menampilkan 30 dan **lencana hitungan menampilkan 30**; 11 sesi terlama tak terjangkau dari UI (hanya via URL `?s=<id>`).
- **Catatan:** ini batas tersembunyi — bertentangan dengan prinsip proyek "tidak ada batas tersembunyi" (PRD 05 §Batas).
- **Saran:** paginasi / "Lihat semua"; hitungan jujur (`COUNT(*)`).

### BE-09 · Halaman tumbuh tanpa batas (tanpa paginasi) — Rendah · Terverifikasi
Diukur lokal (server cepat, Chrome headless):

| Halaman | Data | Waktu server | Ukuran HTML | DOM | `DOMContentLoaded` |
|---|---|---|---|---|---|
| Chat | 600 pesan | 20 ms | **1,8 MB** | 81.304 simpul | ±980 ms |
| Berkas | 1.500 berkas | 105 ms | **4,1 MB** | 51.139 simpul | ±670 ms |
| Ekspor `.md` | 600 pesan | 8 ms | 1,6 MB | — | — |

`FILES_MAX_COUNT` bawaan 2000 mengizinkan kondisi ini. Di ponsel (CPU lebih lambat, jaringan seluler) akan terasa jauh lebih buruk. **Saran:** paginasi/"muat pesan lebih lama" pada chat; paginasi atau pencarian pada Berkas.

### BE-10 · `chat_send` membaca seluruh body sebelum memeriksa ukuran — Rendah · Terverifikasi
- **Lokasi:** `routes_apk.py:612` `raw = await request.body()` baru kemudian `len(raw) > MAX_CHAT_BODY` (4 MiB).
- **Pengamatan:** body 3 MB diterima langsung oleh app. Di produksi Caddy menolak > 1 MB sehingga risikonya kecil (defense-in-depth saja).
- **Saran:** periksa header `Content-Length` lebih dulu.

### BE-11 · `/healthz` dangkal — Rendah · Terverifikasi
- `main.py:118` selalu `{"status":"ok"}` tanpa memeriksa SQLite/Redis. Dipakai healthcheck compose (web) dan `health_uri` Caddy → layanan dianggap sehat walau DB terkunci atau Redis mati.
- **Saran:** `/healthz` tetap murah (liveness), tambahkan `/readyz` yang memeriksa `SELECT 1` dan `PING` Redis; pakai untuk healthcheck compose.

### BE-12 · Halaman error tidak seragam — Rendah · Terverifikasi
| Permintaan | Hasil |
|---|---|
| `GET /nope` | 404 JSON `{"detail":"Not Found"}` (Inggris, mentah) |
| `GET /analyses/abc` | 422 JSON `int_parsing` (struktur internal FastAPI terlihat) |
| `GET /analyses/999999` | 303 → `/?notice=not_found` (halaman ramah) |
Pengguna yang mengetik URL salah melihat JSON mentah. **Saran:** `exception_handler` untuk 404/422/500 yang merender halaman/notice berbahasa Indonesia (JSON hanya untuk `/api/*` dan XHR).

---

## 3. Operasional & konfigurasi

### OP-01 · 14 variabel `.env` tidak berefek (tidak diteruskan compose) — Sedang · Terverifikasi
Dibaca kode, **tidak** ada di `docker-compose.yml` → selalu memakai bawaan walau diisi di `.env`:

`LOGIN_MAX_FAILS`(5) · `LOGIN_WINDOW`(900) · `LOGIN_LOCK`(900) · `SESSION_MAX_AGE`(43200) · `DISK_WARN_PERCENT`(80) · `ZIP_MAX_ENTRIES`(100000) · `ZIP_MAX_UNCOMPRESSED_MB`(3072) · `ZIP_MAX_ENTRY_MB`(512) · `ZIP_MAX_RATIO`(100) · `AI_CONNECT_TIMEOUT`(10) · `AI_READ_TIMEOUT`(120) · `RUNNER_PICKUP_TIMEOUT`(120) · `JOB_MIN_FREE_GB`(5) · `MAX_OUTPUT_FILES`(600000).

- **Mitigasi yang sudah ada:** `make env-check` (PR #22) melaporkan variabel yang "diabaikan compose".
- **Saran:** pilih satu: (a) teruskan yang layak diatur pengguna (`AI_READ_TIMEOUT`, `SESSION_MAX_AGE`, `LOGIN_*`) di compose + `.env.example`; (b) biarkan internal dan jangan baca dari env agar tidak menyesatkan.
- Cek konsistensi default compose ↔ `.env.example` ↔ kode: **konsisten** (§6).

### OP-02 · Pin image & dependensi belum ketat — Rendah · Terverifikasi
- `python:3.12-slim-trixie` (×3), `caddy:2.11-alpine`, `redis:8.8-alpine` memakai tag mengambang, bukan digest.
- `requirements.txt` ter-pin versi (`==`) tetapi tanpa `--hash`; `pip-audit` sendiri memperingatkannya.
- `pip-audit` (10 Okt 2026): **0 kerentanan dikenal** pada 27 paket web + 6 paket worker. Trivy/scan image **belum** dijalankan (NFR-7.4).

### OP-03 · Retensi, backup, rotasi log, VACUUM belum ada — Rendah · Terverifikasi (diketahui: M5)
- `docker-compose.yml` tanpa `logging:` (log Docker tumbuh tanpa rotasi); tanpa job backup; tanpa `VACUUM`/checkpoint WAL terjadwal; peringatan disk hanya di sisi unggah/dashboard.
- Tabel yang tumbuh tanpa batas: `analysis_log`, `ai_call`, `audit_log`, `chat_message`, plus volume `files` (belum masuk rencana backup).
- Lihat PRD `07-infra-security.md` FR-7.7/7.9 dan `01-ingestion-storage.md` FR-1.10.

### OP-04 · Tanpa CI, tanpa linter — Rendah · Terverifikasi
Tidak ada `.github/`, `tests/`, konfigurasi `ruff`/`pyflakes`. `pyflakes` dijalankan manual (hasil bersih saat audit). Terkait **QA-01**.

### OP-05 · Tombol pengembang ada di UI produksi — Catatan
Dashboard memiliki tombol **"Uji antrean"** (`POST /selftest`, `dashboard.html:122`). Berguna untuk diagnosis, tetapi tampil permanen; pertimbangkan memindahkannya ke `make doctor` atau halaman Pengaturan.

---

## 4. Antarmuka & UX

### UI-01 · Overflow horizontal di layar 320px — Sedang · Terverifikasi
- **Pengamatan:** di viewport 320×640 (mobile), **semua** halaman (dashboard, upload, ringkasan, temuan, jaringan, kode, chat, berkas, manifest) memiliki `scrollWidth` 351–352 > 320. Pelaku: `form.header-user` → `button.btn-ghost` ("Keluar") di header, `r=352`.
- **Reproduksi:** DevTools → perangkat 320 px → buka `/` setelah login; halaman bisa digeser ke samping.
- **Aman:** 390, 768, 1024, 1440 px tanpa overflow (termasuk nama berkas 180 karakter dan pesan 400 karakter tanpa spasi).
- **Saran:** `.header-row` boleh `flex-wrap`, atau tombol "Keluar" ikon-saja di bawah ±360 px.

### UI-02 · Target sentuh di bawah standar — Sedang · Terverifikasi
Panduan proyek (`design-system/…/MASTER.md`): ≥ 44 px. WCAG 2.2 AA **2.5.8** mensyaratkan minimal 24×24 px. Aturan CSS 44 px hanya mencakup `.btn`, `.btn-toggle`, `input[type=text|password]`. Terukur pada 390 px:

| Elemen | Ukuran | Halaman | Gagal 2.5.8 (24px)? |
|---|---|---|---|
| `a.back-link` ("Semua APK") | 99×22 | semua halaman analisis | **ya** |
| Tautan di tabel Temuan (`a.mono.break`) | 264×19 (×13) | Temuan | **ya** |
| `summary` dalam tabel Temuan | 83×22 (×11) | Temuan | **ya** |
| Tombol nama berkas `frow-link` | 226×19 | Berkas | **ya** |
| `a.link-quiet` | 53×22 | Dashboard | **ya** |
| Tautan tab | 66×41 | semua | tidak (di bawah 44) |
| Pohon kode `button.tree-dir` | 328×28 (×16) | Kode | tidak (di bawah 44) |
| Tombol Salin pada pesan (`.msg-foot .btn`) | 131×28 (×4) | Chat | tidak (di bawah 44); aturan `.msg-foot .btn {min-height:28px}` menimpa aturan 44 px |
| `summary` langkah tool | 315×32 | Chat | tidak |
- Checkbox Upload (20×20) **bukan** pelanggaran: `<label>` pembungkusnya 308×89 / 274×67 dan ikut menerima ketukan.
- **Saran:** tambah `min-height:44px` (atau padding) untuk `a`/`summary`/`.tree-item` di `@media (pointer: coarse), (max-width: 640px)`, dan hapus penimpaan di `.msg-foot .btn` pada layar sempit.

### UI-03 · Glyph tidak ada pada font self-host — Rendah · Terverifikasi
IBM Plex Sans dan JetBrains Mono (woff2 di `static/fonts/`) **tidak memuat**: `≈` (5 pemakaian, mis. "≈ Rp" anggaran/biaya), `→` (2), `●` (1, judul tab), `▸` (2, pohon kode), `∞` (1, batas tak terhingga). Di browser biasa jatuh ke font sistem (tampilan tak seragam); di lingkungan tanpa font cadangan (termasuk Chrome headless di sandbox) tampil sebagai kotak ▯ — terlihat di tangkapan layar PR #21–#23.
- **Saran:** ganti dengan teks/SVG ("sekitar", ikon panah) atau subset font ulang termasuk glyph tersebut. Cek ulang dengan `fontTools` (`getBestCmap`).

### UI-04 · Format angka tidak konsisten — Rendah · Terverifikasi
- Anggaran `Rp` pada elemen yang sama: dirender server dengan `'{:,.0f}'` → `1,500` (gaya en-US) tetapi diperbarui klien dengan `toLocaleString("id-ID")` → `1.500` (`chat.html:52` vs `app.js:1413`). Angkanya **berubah format** setelah pesan pertama.
- `toLocaleString()` tanpa locale di penampil kode (`app.js:689`, `:692`) dan waktu `time[data-local]` (`app.js:85`) mengikuti bahasa browser; `.toFixed(2)` memberi titik desimal (`Rp6.00`) sementara `fmtDur` memakai koma (`1,5 dtk`).
- **Saran:** satu helper `fmtNum`/`fmtRp` di server (filter Jinja) dan klien dengan locale `id-ID` tetap.

### UI-05 · Pesan "Koneksi gagal" menyesatkan untuk respons non-JSON — Rendah · Terverifikasi dari kode
`app.js` (±451, 482, 609): `fetch(...).then(r => r.json()...)`. Bila yang kembali bukan JSON (413 dari Caddy untuk badan > 1 MB, 502/504 HTML dari proxy), `r.json()` ditolak dan jatuh ke `.catch` → "Koneksi gagal. Periksa jaringan" padahal masalahnya "pesan terlalu besar". **Saran:** periksa `r.ok`/`Content-Type` dulu dan tampilkan pesan sesuai status (413 → "Pesan terlalu besar").

### UI-06 · Bahasa campuran pada navigasi — Catatan (**selesai**, lihat §10.1 dan §10.4)
Tab/menu: **Dashboard, Upload, Chat, Manifest** (Inggris) bercampur dengan **Ringkasan, Temuan, Jaringan, Kode, Berkas** (Indonesia). Mungkin sengaja (istilah teknis), tetapi belum pernah diputuskan. Istilah "berkas" konsisten (85 pemakaian; tidak ada "file" di teks UI).

### UI-07 · Ikon tombol "Kirim" kurang semantik — Rendah
Tombol Kirim chat, "Uji antrean", dan "Buka Chat" memakai ikon `activity` (denyut). Set ikon hanya ±30 buah; tambahkan ikon "send" (pesawat kertas) agar maknanya jelas.

### UI-08 · Aksi "Batalkan" analisis tanpa konfirmasi — Catatan
`_analysis_head.html:17`: hanya `data-submit-lock`. "Hapus" dan "Analisis ulang" (bila sudah selesai) punya konfirmasi. Membatalkan job berjalan tidak merusak data (bisa dicoba ulang), jadi mungkin sengaja.

---

## 5. Dokumen & proses

### DOC-01 · PRD 05 memuat klaim usang — Rendah · Terverifikasi
- **FR-5.2** "batas langkah (**default 12**) dan batas token per giliran" → kini default **100**, token per giliran **tanpa batas** (`AI_MAX_TURN_TOOL_CHARS=0`).
- **Tabel "Daftar tool", kolom Batas:** `list_packages`/`list_classes` "200 baris", `search_code` "50 hasil", `list_strings` "100 hasil" — sudah dihapus sejak PR #12 (tanpa batas jumlah).
- **FR-5.6** "Flash default, Pro opsional" → model ditentukan `AI_MODEL`/`AI_MODEL_PRO` (bukan "Flash"/"Pro" tetap).

### QA-01 · Tes berada di luar repo — Tinggi (keberlanjutan) · Terverifikasi
Semua tes ada di `/projects/.scratch` (±70 skrip Python + 20 skrip Node, fixture NewPipe/VLC, `local_run.sh`, mock AI). Keputusan lama: "tes tidak di-commit". Konsekuensi: sesi/orang baru tidak bisa menjalankan regresi; bila sandbox dibersihkan, hilang total; tak ada CI sehingga PR bisa merusak tanpa terdeteksi.
- **Saran:** konfirmasi ulang keputusan itu. Opsi: komit tes ringan (unit + server lokal + mock AI) ke `tests/` dan jalankan di GitHub Actions; biarkan fixture besar (APK) di luar repo. Tes stack Docker penuh (5–12 menit) cukup manual/nightly.

### QA-02 · Cakupan audit — lihat §7.

---

## 6. Sudah diperiksa dan BAIK (jangan diaudit ulang tanpa alasan)

**Keamanan & backend**
- 39 rute: semua rute non-publik memeriksa sesi; 22 GET diuji **tanpa sesi** → semuanya ditolak (303/401); 10 POST tanpa sesi dan tanpa CSRF → 401/403.
- Semua POST memeriksa CSRF (header `X-CSRF-Token` atau field `csrf`).
- Header keamanan (CSP, nosniff, X-Frame-Options, Referrer-Policy) ada di setiap tipe respons; halaman sensitif `Cache-Control: no-store`; aset statis ber-ETag + Last-Modified.
- Respons error tidak membocorkan traceback, path internal (`/srv`, `/data`), atau SQL. Path traversal pada `/code/file` → 404.
- Kuki sesi: `HttpOnly`, `Secure` (sesuai `COOKIE_SECURE`), `SameSite=Strict` (`context.py:84–86`).
- Tanpa `shell=True`, `eval`, `exec`, `pickle`, `yaml.load`; satu-satunya `subprocess` memanggil `keytool` dengan argumen daftar (`analyzer/signing.py:153`). Tanpa `innerHTML`/`outerHTML`/`document.write` di JS. Satu-satunya `|safe` di template adalah simbol ikon statis.
- Tidak ada rahasia di log (grep `api_key|password|secret|token|csrf|cookie` pada panggilan log) dan tidak ada rahasia di git (`.env`, `secrets/` diabaikan; 0 berkas ter-track).
- Fuzz: ±435 permintaan GET (20 nilai aneh × 21 pola path/query), 15 bentuk body `chat/send`, ±100 POST ke rute lain → **hanya 2 bug 500** (BE-01, BE-02).
- Balapan diuji: dua sesi menulis berkas yang sama bersamaan → konsisten (revisi naik, 1 berkas di disk); hapus APK saat giliran AI menulis berkas → **tanpa berkas yatim**, tanpa baris DB yatim, tidak ada deadlock.
- Konfigurasi: default compose = `.env.example` = kode untuk semua 30 variabel yang diteruskan.
- Dependensi: `pip-audit` 0 kerentanan.

**UI & aksesibilitas** (11 halaman × 5 ukuran = 55 pengamatan; login diperiksa lewat HTML)
- 0 error konsol / pelanggaran CSP.
- 0 pelanggaran kontras teks WCAG AA (dihitung terhadap latar efektif).
- 0 kontrol tanpa label (selain positif palsu di §6.1), 0 `<img>` tanpa `alt`, 0 ID ganda.
- Struktur: tepat 1 `h1` per halaman, tanpa lompatan tingkat judul, `lang="id"`, landmark `main`, `nav` berlabel ("Navigasi utama", "Bagian analisis"), judul halaman unik, tabel punya `th`.
- Indikator fokus terlihat pada semua elemen yang diuji dengan **tombol Tab sungguhan** (dashboard, upload, ringkasan, chat).
- Area yang bisa digulir dapat difokus keyboard (`tabindex`).
- Login: `autocomplete=username/current-password`, tombol tampilkan sandi, galat `role="alert"`.
- Tanpa overflow pada 390/768/1024/1440 px; nama berkas/pesan panjang tidak merusak tata letak.

### 6.1 Positif palsu yang sudah dipastikan (jangan dikejar lagi)
| Tampak seperti | Kenyataan |
|---|---|
| 26 "HTTP 5xx" saat fuzz | Kesalahan skrip uji: `http.client` tidak bisa mengirim URL non-ASCII mentah. Setelah di-percent-encode: 0. |
| "Elemen fokus tanpa indikator" (probe `focus()`) | `focus()` terprogram tidak memicu `:focus-visible`. Dengan Tab sungguhan: semuanya punya outline putih 2px. |
| `<input>` tanpa nama aksesibel di Chat | `input[type=file][hidden]` dengan `aria-hidden="true"` dan `tabindex=-1` (dipicu tombol Lampirkan). |
| "Login tanpa `role=alert`" | Ada (`login.html:12`); skrip hanya memeriksa halaman tanpa galat. |
| "8 default tidak cocok" (compose vs kode) | Artefak parser: argumen batas bawah/atas (`_int(..., 100, 1, 100_000)`) dan `True` vs `true`. |
| `make git` tidak ada | Teks `apt-get install -y make git` di `docs/deploy.md:33`. |
| `<form action="/">` di `upload.html` | `app.js:294–299` menimpa `action` sebelum `submit`. |
| 3 MB teks "tersimpan 2 karakter" | Skrip membaca pesan asisten ("ok"), bukan pesan pengguna. |
| Checkbox Upload 20×20 "terlalu kecil" | Label pembungkusnya 308×89 / 274×67 menerima ketukan; target efektif besar. |
| Kotak ▯ di tangkapan layar | Glyph tidak ada pada font + tanpa font cadangan di headless (lihat UI-03). |

---

## 7. Belum diaudit (area buta)

Jangan menganggap area ini aman hanya karena audit ini bersih:
1. **Pipeline dekompilasi & analyzer:** ketepatan aturan temuan (false positive/negative), call graph, perilaku pada APK sangat besar/rusak/ber-obfuscate selain NewPipe/VLC, batas waktu jadwal, recycle runner.
2. **Isolasi runner:** bukti `runner-selftest` sudah ada, tetapi tidak diaudit ulang (seccomp/cgroup, tmpfs 256 MB).
3. **Kualitas & keamanan AI dengan model sungguhan:** prompt injection nyata dari APK/lampiran/gambar, halusinasi sitasi, biaya riil, perilaku `tool_draft` pada router asli, penanda `vision` per model (gunakan `make ai-check`).
4. **Redis/queue:** perilaku saat Redis mati, job yatim, antrean macet, restart `web` saat giliran chat berjalan.
5. **Caddy/TLS/Cloudflare:** konfigurasi TLS, SSE + `Last-Event-ID` melalui Caddy (tidak diuji end-to-end), batas 100 MB Cloudflare.
6. **Keamanan sesi mendalam:** parameter argon2, rotasi `SECRET_KEY`, pengelolaan sesi bersamaan, rate-limit selain login.
7. **Aksesibilitas dengan pembaca layar sungguhan** (NVDA/VoiceOver), Safari/Firefox, mode kontras tinggi, `prefers-reduced-motion` pada animasi baru (`msg-live-dot` memakai aturan global yang menonaktifkan animasi—belum diverifikasi visual).
8. **Halaman login** tidak ikut sapuan UI otomatis (sesi aktif mengalihkan ke `/`); hanya dicek lewat HTML.
9. **Kinerja pada VPS nyata** (2 vCPU?) dan unggahan APK 200 MB end-to-end.
10. **Backup/restore** (belum ada), rebuild image yang reprodusibel, upgrade skema DB di data produksi (migrasi v4 diuji hanya pada DB uji).

---

## 8. Urutan perbaikan yang disarankan

| Paket | Isi | Perkiraan | Catatan |
|---|---|---|---|
| **A · Kekokohan input chat** | BE-01, BE-02, BE-03, BE-10 + tes regresi | kecil (≈1 PR) | Perbaikan 3–10 baris; paling murah, hilangkan semua HTTP 500 yang ditemukan. |
| **B · Observabilitas** | BE-04 (logging), BE-05 (audit log), BE-11 (`/readyz`) | kecil–sedang | Tanpa ini, masalah produksi berikutnya sulit didiagnosis. |
| **C · Mobile & aksesibilitas** | UI-01, UI-02, UI-03, UI-04, UI-05 | sedang | Verifikasi ulang dengan skrip audit UI (§9); target: 0 overflow di 320, 0 target < 24px. |
| **D · Skala & kebersihan data** | BE-06, BE-07, BE-08, BE-09 | sedang | Paginasi chat/berkas, rekonsiliasi DB↔disk, sesi > 30. |
| **E · Konfigurasi & dokumen** | OP-01, DOC-01, OP-02 (pin digest) | kecil | Putuskan mana variabel yang diteruskan. |
| **F · Proses** | QA-01, OP-04 (CI + lint), OP-03 (rotasi log dulu) | sedang | Butuh keputusan pemilik soal tes di repo. |
| **G · Keputusan produk** | UI-06, UI-08, OP-05 | — | Tanya pemilik; tidak perlu kode dulu. |

Saat memperbaiki, ikuti kebiasaan proyek: satu cabang baru dari `origin/main` per paket, PR lewat `gh api` (bukan `gh pr`), jujur soal apa yang belum diuji.

> **Pembaruan 11 Okt 2026:** pemilik mengizinkan tes di repo. Tes kini ada di `tests/` dan dijalankan CI (lihat `.kiro/steering/testing.md`); aturan lama "jangan commit tes" tidak berlaku lagi.

---

## 9. Cara mengulang audit (alat ada di `/projects/.scratch`, di luar repo)

> Jika folder itu hilang, minimal reproduksi tiap temuan sudah ditulis di atas. Alat di bawah hanya mempercepat.

| Berkas | Fungsi |
|---|---|
| `local_run.sh <skrip.py ...>` | Menyalakan web (uvicorn) + mock AI lokal, menjalankan skrip, lalu mematikannya (±1–2 menit). `SEED_LIVE=1` menyalin data NewPipe nyata ke instans uji. Dibersihkan lewat `local_run.pids`. |
| `mockpkg/mockfiles_server.py` | Mock OpenAI: paham gambar, `write_file`, `view_image`; skenario lambat ("tulis lambat" / "tulis sangat lambat") dengan argumen tool call dialirkan bertahap. Mencatat apa yang diterima provider. |
| `audit_fuzz.py` | Fuzz rute (§2): akses tanpa sesi, nilai aneh pada path/query, bentuk body `chat/send`, `Last-Event-ID`, header keamanan, kebocoran info. |
| `audit_logic.py`, `audit_probe2.py`, `audit_probe3.py`, `audit_sess.py`, `audit_perf.py` | Skenario logika (validasi body, pending, DB↔disk, balapan, hapus saat berjalan), perilaku `Last-Event-ID`, perbandingan skala. |
| `js/audit_ui.scn.js` + `audit_ui.py` | Sapuan UI otomatis di Chrome nyata: overflow, nama aksesibel, kontras, struktur judul, ID ganda, target sentuh, indikator fokus; 11 halaman × 5 viewport → `audit_ui_results.json`. |
| `js/audit_ui2.scn.js` + `audit_ui2.py` | Verifikasi ketat: Tab sungguhan (`Input.dispatchKeyEvent`), rincian target sentuh, nama berkas/pesan sangat panjang. |
| `js/cdpweb.js` | Pembungkus DevTools Protocol (navigasi, evaluasi, tangkapan layar, `setFiles`, `key`). |
| `test_*.py`, `js/*.js`, `t*.py` + `cycle.sh` | Suite regresi: unit (`test_userfiles`, `test_files_ai`, `test_tools`, `test_agent`, …), server lokal (`test_files_routes`, `test_resume`), Chrome (`test_ui_chrome`, `test_ui_resume`), stack Docker penuh (`cycle.sh t40.py …`, lambat). |

**Menjalankan ulang cepat:**
```bash
cd /projects/sandbox/reverse-apk
SEED_LIVE=1 /projects/.scratch/local_run.sh audit_fuzz.py       # §2 (backend)
SEED_LIVE=1 /projects/.scratch/local_run.sh audit_ui.py         # §4 (UI otomatis)
/projects/.scratch/local_run.sh test_files_routes.py            # regresi rute (112 cek)
/projects/.scratch/local_run.sh test_resume.py                  # regresi sambung-ulang chat (35 cek)
```
Jalankan satu skrip uji per panggilan `local_run.sh` bila skrip membuat APK dengan sha256 sama (benturan `UNIQUE`).

**Catatan lingkungan sandbox (jebakan yang sudah memakan waktu):**
- `/tmp` dihapus antar panggilan tool → simpan berkas sementara di `/projects/.scratch`.
- Jangan mematikan proses dengan `pkill -f <pola>` dari shell yang baris perintahnya memuat pola itu (mematikan shell sendiri, exit 143); gunakan berkas PID.
- Membaca gambar (`read_file`) secara paralel dengan perintah yang membuatnya bisa menghasilkan versi lama; baca setelah perintah selesai.
- Chrome headless minimal selebar ±500 px; gunakan `Emulation.setDeviceMetricsOverride` (lihat `cdpweb.js`) untuk viewport sempit, dan ukur dengan `visualViewport.width` (bukan `innerWidth`, yang ikut melebar bila ada overflow).
- Tes stack Docker butuh `mkdir -p /run/podman`; `cycle.sh` menghapus semua container/volume lain.
- Starlette 1.x: `app.routes` tidak menampilkan router yang di-include; daftar rute diambil dari dekorator (AST) atau diuji langsung.

---

## 10. Status & hasil pengukuran (11 Okt 2026)

Ditulis sesi berikutnya, setelah tiap temuan diverifikasi ulang dari kode dan dijalankan. Angka di bawah **terukur**, bukan dugaan.

### 10.1 Sudah diperbaiki

| Butir | PR | Catatan |
|---|---|---|
| BE-01, BE-02, BE-03 | #25 | + dua temuan baru: `model` berupa list/objek → 500 (`TypeError` unhashable), JSON bersarang dalam → 500 (`RecursionError`). BE-02 hanya bisa dipicu dengan **byte latin-1 mentah** (`0xB2`); klien HTTP yang menyandikan ke UTF-8 tidak memicunya. |
| BE-04, BE-05, BE-11 | #26 | Logger `reverse-apk.ai` (`ai/logutil.py`). Audit log + `file_upload`, `file_delete`, `ai_file_write`, `chat_session_delete`. `/readyz` **sengaja tidak** dipakai Caddy: saat Redis mati situs harus tetap tampil agar kartu Status sistem bisa dibuka. |
| BE-12 | #27 | Pilihan halaman vs JSON dari header `Accept`, **bukan** `/api/*` seperti saran §4: sebagian besar endpoint XHR ada di bawah `/analyses/...`. Temuan tambahan: respons 500 sebelumnya **tanpa header keamanan** (handler 500 berjalan di luar middleware) — berarti klaim §6 "header ada di setiap tipe respons" tidak berlaku untuk 500. |
| QA-01, OP-04 | #28 | `tests/` + CI (pyflakes + pytest). Menggantikan aturan lama "jangan commit tes". |
| UI-04, UI-05, UI-07 | #29 | Satu sumber format angka `rvcore/fmt.py` (dipakai web, worker, runner) + `fmtNum` di `app.js`. `readJson()` agar respons non-JSON tidak lagi jadi "Koneksi gagal". |
| Sesi kosong saat anggaran habis (tidak ada di audit awal) | #29 | `budget.check()` dipindah sebelum `create_chat_session()`. |
| UI-08 | #32 | Konfirmasi "Batalkan" **hanya saat berjalan**. Catatan koreksi atas §4: membatalkan job berjalan **tidak** sepenuhnya tanpa kerugian — `_finish_cancelled` langsung menghapus hasil sementara `apktool/` dan `jadx/`, jadi harus diulang dari awal. Saat masih antre tidak ada yang hilang, jadi tanpa konfirmasi. |
| UI-06 | #33 | Bahasa seragam Indonesia pada **teks yang tampil**: Dashboard → **Beranda**, Upload → **Unggah**, Chat → **Percakapan**, Manifest → **Manifes** (menu, tab, judul tab browser, tombol, pesan galat server dan JS, `README`/`docs/deploy.md`). **Sengaja tidak diubah** karena itu kode, bukan tampilan: alamat (`/chat`, `/upload`, `/manifest`), kelas CSS, `id`, `data-*`, nama tool AI dan prompt, nilai aksi audit `upload`, log operator, dan PRD (istilah konseptual). `tests/test_ui_language.py` memeriksa teks yang terlihat di 9 halaman; Chromium memastikan tidak ada kata lama di layar setelah JavaScript berjalan. |
| AI tak bisa menelusuri resource (tidak ada di audit awal) | #35 | Tool baca-saja **`list_dir`** (satu folder, tidak rekursif; path keluaran = path masukan `read_file`) dan **layout/menu/navigation ikut diindeks pencarian** (analyzer v3). Layout sengaja hanya masuk pencarian, **tidak** ikut pemindaian secret/URL, jadi tab Temuan & Jaringan tidak berubah. Rincian ukur di §10.7. |

### 10.2 Hasil pengukuran

**BE-09 — ukuran halaman** (Chromium 153, server lokal, 1.280×900):

| Halaman | HTML | Simpul DOM | Server | `loadEventEnd` | CPU 4× lambat |
|---|---|---|---|---|---|
| Dashboard (pembanding) | 10 KB | 153 | 13 ms | 59 ms | — |
| Chat, 600 pesan | 649 KB | 29.094 | 78 ms | 455 ms | 1.327 ms |
| **Berkas, 1.500 berkas** | **4.349 KB** | 52.628 | 118 ms | 753 ms | **2.468 ms** |

Waktu server murah (13–118 ms); biayanya ada di ukuran HTML dan DOM klien. Halaman **Berkas** yang terparah, dan `FILES_MAX_COUNT` bawaan 2000 mengizinkan ±5,8 MB. Angka Berkas cocok dengan §2; angka Chat lebih kecil dari klaim §2 (1,8 MB / 81k simpul) karena panjang pesan uji berbeda — jadi perbandingan antar sesi hanya sah bila isi pesannya sama.

**UI-02 — target sentuh pada 390 px** (`min(lebar, tinggi)`; target efektif dihitung dari `<label>` pembungkus bila ada):

| Elemen | Ukuran | Jumlah | Halaman |
|---|---|---|---|
| `a.cite` (chip sitasi) | **18px** | 600 | Chat |
| `a` di dalam tabel | **19px** | 32 | Dashboard, Temuan, Manifest |
| `a.link-quiet`, `a.back-link`, checkbox tab Kode | **22px** | 9 | hampir semua halaman analisis |
| `button.btn` di `.msg-foot` (Salin) | 28px | 600 | Chat |
| `summary` daftar sesi | 29px | 301 | Chat |
| `input[type=search]`, `select` | 36–40px | 5 | Kode, Temuan |
| tautan nav & tab, `a.skip-link` | 39px | 76 | semua |

Yang **gagal WCAG 2.2 AA 2.5.8 (< 24px)**: 642 elemen, 6 jenis. Sisanya (982 elemen) lolos WCAG tetapi di bawah panduan proyek 44px.

> **Dua koreksi atas cara mengukur** (penting sebelum angka di atas dipakai lagi):
> 1. Metrik memakai `min(lebar, tinggi)`. Sebagian "39px" sebenarnya **lebar** label pendek (mis. tab `Kode` berukuran 39×44 px) — itu **lolos** 2.5.8 yang mensyaratkan 24×24. Jadi hitungan 982 di atas kelebihan hitung.
> 2. WCAG 2.5.8 punya pengecualian **Inline**: target di dalam kalimat, yang ukurannya ditentukan `line-height` teks sekitarnya, dikecualikan. Itu berlaku untuk chip sitasi dan tautan "Ringkasan" di paragraf halaman Manifest.

> **Positif palsu yang sudah dipastikan:** `input.file-input` di halaman Upload terukur 1×1 px, tetapi tombol sebenarnya adalah `<label for="file" class="btn">` terpisah (sudah ≥ 44px di ponsel). Begitu juga `input` di `label.check` (20px): yang diketuk adalah labelnya (terukur 332×44 px setelah perbaikan). Jangan dikejar.

**BE-07 — rekonsiliasi DB ↔ disk** (dijalankan, bukan dibaca):

| Keadaan | Perilaku nyata |
|---|---|
| Baris ada di DB, berkas hilang dari disk | Halaman Berkas menampilkan barisnya **tanpa penanda apa pun**; `/text` → 200 `{"missing": true}` (penampil baru memberi tahu saat dibuka); `/download` → 404; **ZIP → 200 berisi arsip kosong 22 byte, tanpa peringatan**; kuota tetap menghitungnya. |
| Berkas ada di disk, tidak ada barisnya di DB | Tidak tampil di UI, tidak dihitung kuota, tidak ikut ZIP. Hanya hilang saat APK dihapus (`rmtree`). |

**BE-06 — lampiran *pending*:** lampiran berumur 10 jam di analisis B **tetap ada** setelah `purge_stale_uploads(analisis A)`, dan terus dihitung ke kuota analisis B sampai ada unggahan baru di sana. Sesuai §2.

**OP-02 — pin versi:**

| Hal | Keadaan |
|---|---|
| Dependensi Python | **37 dari 37 paket ter-pin `==`** (web 27, worker 6, tes 4); **0 dengan `--hash`** |
| Image | `python:3.12-slim-trixie` (×3), `caddy:2.11-alpine`, `redis:8.8-alpine` — **tidak ada `@sha256:` sama sekali** |
| jadx & apktool | **Sudah** diverifikasi SHA-256 saat build (`sha256sum -c`) |
| GitHub Actions | `actions/checkout@v4`, `actions/setup-python@v5` (tag, bukan commit) |

### 10.3 OP-01 — 14 variabel yang tidak diteruskan compose

Dikelompokkan menurut **layanan yang membacanya**; ini yang menentukan ke mana variabelnya harus ditambahkan.

| Variabel | Dibaca | Bawaan | Usul |
|---|---|---|---|
| `LOGIN_MAX_FAILS`, `LOGIN_WINDOW`, `LOGIN_LOCK` | web | 5 · 900 s · 900 s | teruskan (keamanan login) |
| `SESSION_MAX_AGE` | web | 43200 s | teruskan |
| `AI_READ_TIMEOUT`, `AI_CONNECT_TIMEOUT` | web | 120 s · 10 s | teruskan (model lambat) |
| `DISK_WARN_PERCENT` | web | 80 | teruskan (murah) |
| `ZIP_MAX_ENTRIES`, `ZIP_MAX_UNCOMPRESSED_MB`, `ZIP_MAX_ENTRY_MB`, `ZIP_MAX_RATIO` | web | 100000 · 3072 · 512 · 100 | biarkan internal (pengaman zip-bomb) |
| `JOB_MIN_FREE_GB`, `RUNNER_PICKUP_TIMEOUT` | **worker** | 5 GB · 120 s | biarkan, atau tambahkan ke service `worker` |
| `MAX_OUTPUT_FILES` | **runner** | 600000 | biarkan internal (pengaman) |

`REDIS_URL` dan `REDIS_PORT` bukan masalah: keduanya alternatif dari `REDIS_HOST`/`REDIS_PASSWORD` yang sudah diteruskan. `TOOL_HOME_ROOT`, `HOME`, `PATH` internal.

### 10.4 Keputusan pemilik (11 Okt 2026)

| Butir | Keputusan |
|---|---|
| QA-01 / OP-04 (tes di repo) | **Boleh** → #28 |
| OP-03 (backup, rotasi log) | **Tidak dikerjakan** untuk sekarang |
| BE-10 (`MAX_CHAT_BODY` 4 MiB) | **Ditutup**: pengaman yang disengaja (PRD 05), Caddy sudah menahan 1 MB di rute itu |
| UI-01 (overflow 320 px) | **Dibiarkan**: di bawah breakpoint uji design system (375 px ke atas) |
| UI-03 (glyph ▯) | **Tidak dikerjakan** |
| UI-06 (bahasa campuran) | **Diseragamkan penuh** → #33 (4 kata; hanya teks tampil). Ditolak: dibiarkan, dan jalan tengah 2 kata |
| UI-08 | **Dikerjakan** → #32 (konfirmasi hanya saat berjalan) |
| OP-05 | Belum diputuskan |

### 10.5 Hasil setelah perbaikan BE-09 (halaman Berkas) & UI-02

**Halaman Berkas** dengan 1.500 berkas, pengukuran yang sama persis:

| | Sebelum | Sesudah (paginasi, `PAGE_SIZE = 50`) |
|---|---|---|
| HTML | 4.349 KB | **153 KB** (28× lebih kecil) |
| Simpul DOM | 52.628 | **1.891** |
| `loadEventEnd` | 753 ms | **93 ms** |
| CPU 4× lambat | 2.468 ms | **186 ms** |

Biaya per baris terukur **±2,9 KB** (ikon SVG sebaris, tiga tombol, dan form hapus per baris). Kalau nanti perlu lebih ringan lagi, langkah berikutnya adalah memakai sprite `<use href="#…">` seperti `state_sprite()` di `_parts.html`, bukan menurunkan `PAGE_SIZE` lagi.

**Chat 600 pesan belum disentuh** (649 KB, 29.094 simpul): memecah riwayat chat menjadi halaman bersinggungan dengan sambung-ulang aliran (FR-5.15) dan dengan perilaku "menempel di dasar", jadi risikonya jauh lebih besar daripada halaman Berkas dan dikerjakan terpisah.

**Target sentuh** sesudah perbaikan, pengukuran yang sama (390 px):

| Sisa yang masih < 24px | Alasan dibiarkan |
|---|---|
| `a` "Ringkasan" di paragraf Manifest, 19px | di tengah kalimat → pengecualian **Inline** 2.5.8 |
| `input.file-input` 1px, `input` di `label.check` 20px | positif palsu: labelnya yang diketuk (44px) |

Chip sitasi dinaikkan 18px → **24px**. Yang tadinya 982 elemen di bawah 44px kini tinggal `a.skip-link` (tersembunyi sampai difokus) dan beberapa label tab yang **lebarnya** 39px dengan tinggi 44px.

> **Jangan diulangi:** lapisan `::after` tak terlihat untuk memperbesar area ketuk chip sitasi tanpa mengubah tata letak **tidak bekerja** — diuji dengan `elementFromPoint`, hanya menambah ±2px di atas dan 0 di bawah. Yang berhasil adalah `padding-block` pada elemennya sendiri.

### 10.6 Cara mengulang pengukuran

Alat di §9 (`/projects/.scratch`) **sudah hilang**; risiko QA-01 sudah terjadi. Pengukuran di atas memakai Playwright + Chromium di luar repo, dan sengaja **tidak** ditambahkan ke CI (unduhan Chromium ±115 MB). Tes yang ada di `tests/` menjalankan aplikasi web tanpa jaringan (Redis & provider AI tidak terjangkau); worker, runner, analyzer, dan stack Docker penuh belum tercakup.

### 10.7 `list_dir` & indeks layout (12 Okt 2026)

**Masalah.** AI bisa membaca resource lewat `read_file`, tetapi hanya bila tahu path persisnya, dan `search_code` tidak menjangkau `res/layout`, `res/menu`, `res/navigation`, maupun `jadx/resources` (analyzer hanya mengindeks Java, smali, `res/values|xml|raw`, `assets`, manifest). Jadi pertanyaan seperti "layar mana yang punya tombol login?" tak terjawab.

**Biaya indeks** (diukur dengan `Scanner` + `IndexWriter` sungguhan pada hasil `apktool` dua aplikasi open-source F-Droid, SHA-256 APK dicocokkan dengan indeks F-Droid; indeks "lama" = perilaku sebelum perubahan):

| Aplikasi | Layout+menu+navigation | Dokumen FTS | Halaman terpakai (lama → baru) | Waktu |
|---|---|---|---|---|
| AntennaPod 3.12.2 | 293 berkas / 420 KB teks | 2.216 → 2.509 | 33.756 → 34.412 KB (**+656 KB**) | 2,01 → 2,06 s |
| NewPipe 0.29.1 | 231 berkas / 423 KB teks | 2.372 → 2.603 | 42.836 → 43.452 KB (**+616 KB**) | 2,15 → 2,18 s |

- Biaya nyata ±0,6 MB per aplikasi (±1,5% dari indeks). Pada Compose-only app (NexLoad) hampir nol karena nyaris tanpa layout.
- **Jangan membandingkan ukuran berkas**: pada NewPipe berkas indeks tampak *mengecil* 352 KB, padahal itu artefak halaman kosong SQLite (*freelist* turun 968 KB). Yang sah dibandingkan adalah halaman terpakai (`page_count − freelist_count`). Pengukuran diulang 3× dan identik, jadi ini bukan derau acak.
- Temuan (3) dan string (73) pada AntennaPod **identik** sebelum/sesudah, termasuk file, baris, dan count.

**Kebenaran dasar.** `RecyclerView` ditemukan di 20 berkas layout = hasil `grep` langsung (20). `ProgressBar` 24 vs 25: yang terlewat adalah `CircularProgressBar` (kata di tengah token); `feed_url` tidak menemukan `edit_feed_url_item`. Keduanya **keterbatasan lama pencarian token** (token utuh atau awalannya), bukan berkas yang hilang dari indeks, dan kini ditulis di deskripsi tool & prompt.

**Batas pengaman.** Per berkas 512 KB (sama dengan `scan_resource`), total layout 64 MB per analisis, symlink diabaikan, hanya `.xml` di folder `layout*|menu*|navigation*` (termasuk varian kualifier). Folder XML lain (`drawable`, `anim`, `color`) sengaja tidak diindeks.

**Analisis lama.** Indeks buatan analyzer < v3 tidak memuat layout. `search_code` kini menambahkan peringatan ke AI ("tidak ada hasil" ≠ "tidak ada di layout") sampai pengguna menekan **Jalankan analisis statis** lagi.

**Belum diukur.** APK sangat besar (ratusan MB) dengan puluhan ribu layout; batas 64 MB melindungi, tetapi waktu `index.finish` pada kasus itu tidak diukur. Pengujian dijalankan di sandbox pengembangan, bukan di runner/VPS.

### 10.8 Halaman Penyimpanan (12 Okt 2026, PR #36 dan tahap 2)

Lihat `docs/prd/10-storage.md`. Ringkasan temuan yang berguna di luar halaman itu:

- **Header meluber di ponsel sebelum perubahan apa pun**: Beranda 447 px vs layar 375 px (+72 px). Terukur; menambah satu menu memperburuknya. Diperbaiki (menu bisa digulir, "Keluar" ikon saja); 8 halaman × 320/375/1280 px kini pas.
- **Ukuran berkas menyesatkan, ukuran di disk benar**: byte isi lebih kecil 26% (apktool AntennaPod) / 19% (NewPipe) / 12% (jadx NexLoad) dari ruang terpakai. Membandingkan ukuran *berkas* SQLite juga menyesatkan (freelist), seperti di §10.7.
- **Data aplikasi hanya 1,03 GB di VPS pemilik; cache build Docker 2,69 GB** (1,99 GB bisa dibuang) dan tidak terlihat dari web. Disk 99 GB: terpakai 9,0 GB, tersedia 86 GB, selisih ±4 GB (dihitung, penyebab belum diperiksa).
- **Rename direktori `r-x` gagal sebagai non-root** (terukur; Python 3.12, uid 65534). Tes yang berjalan sebagai root tidak mungkin melihatnya. Ada tes yang menjatuhkan hak ke `nobody` (dilewati dengan alasan bila lingkungan tak mengizinkan).

**Kerapuhan tes yang SUDAH ADA sebelum pekerjaan ini** (diukur pada `main` bersih e02a4f4, bukan disebabkan tes baru):
- `tests/test_files_page.py`: pada urutan acak, 10 tes `ERROR` (`UNIQUE constraint failed: apk.sha256`) karena fixture memakai hash tetap. Urutan normal dan terbalik lulus.
- `tests/test_chat_input.py::test_normal_message_is_stored_trimmed`: kadang gagal pada urutan terbalik (1 dari 8 di `main` bersih, 3 dari 8 di cabang ini; sampel terlalu kecil untuk menyimpulkan perbedaan). Menunggu baris DB dari thread giliran chat di latar, jadi perlombaan waktu.

### 10.9 Penjelajah folder (12 Okt 2026, tahap 3)

Lihat `docs/prd/10-storage.md`. Temuan yang berguna di luar halaman itu:

- **Nilai rahasia disimpan MENTAH di `work/<id>/index/`** (`findings.jsonl` field `secret`, tabel `code` di `index.sqlite`; contoh `AKIAIOSFODNN7EXAMPLE` tersimpan apa adanya di keduanya). Aplikasi menjaganya dengan tidak pernah mengirim nilai itu ke browser kecuali lewat tombol "Tampilkan nilai" yang tercatat (`secret_reveal`). Konsekuensi: **setiap fitur baru yang menyajikan berkas dari `work/` harus menutup `index/`**. Penjelajah memakai daftar putih; ada tes khusus untuk ini. Folder `index/` tidak dienkripsi di disk, jadi siapa pun dengan akses shell/volume ke VPS membacanya.
- **Starlette/klien menormalkan jalur URL**: `/x/1/../index` menjadi `/x/index`, dan `%2e%2e`, `%00`, `%5c` didekode sebelum rute. Karena itu penjelajah mengirim jalur lewat **query**, bukan path-parameter; penjaga di kode tidak boleh mengandalkan "klien tidak akan mengirim `..`".
- **Symlink di dalam akar**: `resolve_under` saja tidak cukup, karena `work/1/jadx -> work/1/index` tetap berada di bawah akar. Perlu perbandingan realpath dengan jalur yang diminta. Terbukti dengan mutasi (3 tes gagal bila perbandingan dihapus).
- **Tes logika lulus, halaman HTTP galat 500**: satu nama berkas non-UTF-8 menjatuhkan seluruh halaman karena `urlencode` di template. Hanya terlihat setelah halaman dijalankan sungguhan. Pelajaran: untuk data dari disk, uji sampai HTML.
- **Mutasi menemukan 3 celah tes nyata** (`O_NOFOLLOW`, penolakan symlink di `list_dir`, `db` di tabel akar): lapisan atas menutupi lapisan bawah sehingga tidak pernah teruji. Diperbaiki dengan tes yang memanggil tiap lapisan langsung. Total 33 mutasi: 27 tertangkap, 6 setara (ditutup tumpang-tindih, bukan celah).
- **Cek otomatis "tanpa luber horizontal" tidak cukup**: di 375 px nama berkas terhimpit satu-dua huruf per baris dan tombol terpotong, tetapi halaman tidak meluber. Hanya terlihat di tangkapan layar. Diperbaiki (kolom tanggal disembunyikan, tombol ikon 44×44 px).
- Aturan sentuh 44 px aplikasi hanya berlaku untuk `pointer: coarse` atau lebar ≤640 px; mengukurnya di desktop menghasilkan positif palsu. Diuji dengan emulasi sentuh.

**Belum terbukti:** semua diukur di sandbox, bukan di VPS pemilik; folder dengan jutaan entri pada disk dingin belum diukur; di 320 px tabel masih sedikit bergulir (±9 px).

### 10.10 Unggah XAPK dan APKS (12 Okt 2026, PR A)

Lihat `docs/prd/09-bundles-and-workbench.md` "Status PR A". Temuan yang berguna di luar fitur itu:

- **Tombol "Pilih berkas" di halaman Unggah tidak bisa diklik di `main`.** Terukur dengan klik nyata (Playwright): elemen lain mencegat klik. Penyebab: dua fitur memakai kelas CSS `.dropzone`; aturan zona lepas chat (`position:absolute; inset:0; z-index:20`) menimpa dropzone Unggah sehingga ukurannya 1280×900 (satu layar penuh). Hanya seret-lepas yang bekerja. Tidak pernah tertangkap karena tidak ada tes browser. Diperbaiki dengan mengganti nama kelas chat menjadi `.chat-dropzone`; zona lepas chat diuji ulang (tetap muncul saat berkas diseret). Tes regresi membaca CSS, dan dua mutasi yang mengembalikan bug tertangkap.
- **Tidak ada satu pun tes untuk `/api/uploads` dan `validate_apk` sebelum PR ini.** Kini ada (77 tes di `tests/test_bundle.py`), termasuk unggah APK biasa, duplikat, ekstensi salah, CSRF/login, dan galat validasi.
- **Hasil merge split membawa tanda tangan yang tidak sah, dan analyzer tidak memverifikasi tanda tangan.** XAPK nyata: v1 hasil merge `SHA1 digest error for AndroidManifest.xml`, tetapi `analyze_signing` tetap melaporkan sertifikat penerbit asli karena hanya mem-parsing blok v2/v3 yang disalin dari base. Akibatnya "ditandatangani oleh X" di UI tidak berarti tanda tangan sah. Itu sifat lama (berlaku juga untuk APK biasa yang dimodifikasi). PR ini menghindarinya untuk paket dengan memakai base asli; masalah umumnya (analyzer tidak memverifikasi) belum diperbaiki dan tidak ada `apksigner` di runner.
- **Analyzer hanya melihat satu APK.** Pada paket, daftar library native kosong (`native.libs = {}`) padahal aplikasinya memuat `.so` (ada di split ABI). Ditampilkan sebagai peringatan di halaman analisis; belum diperbaiki.
- **`options` analisis dari web tidak dipercaya runner.** Info bundel di `analysis.options` hanya catatan untuk UI; runner memutuskan ulang dari ISI berkas yang ada di `uploads/` (juga setelah "Analisis ulang"). Bila isi dan catatan berbeda, isi yang menang.
- **Nama internal `uploads/<sha>.apk` dipertahankan walau isinya paket.** Mengubahnya akan memengaruhi halaman Penyimpanan, pembersihan sisa tanpa pemilik, penjelajah, dan retry. Konsekuensi: berkas yang diunduh dari penjelajah bernama `<sha>.apk` padahal bisa XAPK/APKS.
- **Pelajaran uji:** (1) tes pertama saya untuk "manifest besar tidak dibuka" gagal di SETIAP mutasi karena patch dipasang sebelum berkas uji dibangun, sehingga satu batch mutasi tidak sah dan harus diulang; (2) skrip uji acak gagal membaca ID tes karena parameter tes berupa seluruh isi biner ZIP, kini diberi `ids=`; (3) proses latar belakang uji APKS mati tanpa keluaran dan saya hampir menganggapnya berjalan.
- **Mutasi:** 37 mutasi unik pada `bundle.py`, `apkcheck.py`, rute unggah, dan dropzone: 32 tertangkap, 5 setara. Awalnya 6 lolos; satu celah tes nyata (batas ukuran manifest, yang tertutup lapis kedua) dan satu (`O_EXCL`, perlu simulasi balapan symlink) ditutup dengan tes baru. Lima mutan setara: batas byte yang ditulis dan batas ukuran terdeklarasi saling menutup, karena `zipfile` Python 3.12 tidak pernah mengembalikan lebih dari ukuran terdeklarasi (terukur: berbohong soal ukuran berujung `BadZipFile: Bad CRC-32`, bukan melewati batas), jadi keduanya hanya jaring pengaman bila perilaku `zipfile` berubah; `O_NOFOLLOW` ditutup `O_EXCL`; penolakan entri terenkripsi sudah dilakukan `zipfile` sendiri; batas pembacaan manifest ditutup batas ukuran terdeklarasi.

**Kerapuhan tes lama, ukuran lebih lengkap (bukan dari PR ini):** pada `main` bersih (ca11236, 471 tes, tanpa tes PR ini), 10 urutan acak menghasilkan, selain 10 error `tests/test_files_page.py` di tiap urutan, dua kegagalan acak: `test_chat_input.py::test_text_must_be_plain_string` (pesan baru muncul di tengah tes: `max_message_id() 9 == 8`, perlombaan dengan thread giliran chat) dan `test_storage_clean.py::test_execute_rejects_malformed_input_without_touching_anything`, masing-masing 1 dari 10. Catatan §10.8 hanya menyebut `test_normal_message_is_stored_trimmed`; kelasnya sama (thread latar chat) tetapi tesnya lebih banyak. Pada cabang ini urutan acak seed 3 memunculkan `test_text_must_be_plain_string`; diverifikasi bukan sebab PR ini karena tes itu juga gagal di `main` bersih. Urutan normal dan terbalik: semua lulus.

**Belum terbukti:** semua di sandbox; runner, apktool, jadx, dan analyzer dijalankan nyata tetapi **tanpa isolasi Docker** (tanpa `network none`, `read_only`, `cap_drop`, batas memori), dan tanpa Redis (pipeline worker dipanggil langsung). Hanya 1 XAPK dan 2 APKS nyata. `.apkm` dan `.aab` tidak diuji. Ekstraksi base dari berkas ratusan MB belum diukur (15 MB: 0,07-0,23 dtk).

