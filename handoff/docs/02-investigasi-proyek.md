# Laporan pemahaman proyek `reverse-apk` — dasar untuk fitur "AI memodifikasi & membangun APK"

> Sifat: investigasi BACA-SAJA (tidak ada kode yang diubah, tidak ada commit, stack Docker tidak dijalankan).
> Repo: `/projects/sandbox/reverse-apk` (branch `main`, HEAD `bfa4e8c`). Semua path relatif terhadap repo ini.
> Permintaan asli pengguna: "saya ingin menambahkan agar ai bisa modifikasi apk dan build apk, silahkan pahami seluruh project terlebih dahulu".
> Tanda: **[TERBUKTI]** = dibaca langsung di kode/dokumen; **[DUGAAN]** = inferensi, perlu diuji; **tidak ditemukan** = dicari dan memang tidak ada.

---

## 0. Jawaban singkat (baca ini dulu)

1. **Belum ada kemampuan edit/repack/sign APK sama sekali di kode.** Satu-satunya jejak `apktool b` ada di skrip pengembangan `scripts/sample-apk/build.py:241-247` (membangun APK uji lewat `docker run` pada image runner) dan jejak penandatanganan v1 `jarsigner` di `build.py:249-260` (di mesin host, bukan di layanan). Tidak ada `zipalign`, `apksigner`, `aapt2` (CLI), `d8`, `smali`/`baksmali` (CLI), keystore, atau job "build" di Dockerfile/compose/worker/runner mana pun (grep seluruh `services/ scripts/ docker-compose.yml Makefile tests/ .github/` → hanya hasil di atas + komentar yang menegaskan *ketiadaannya*, mis. `services/bench/Dockerfile:14`).
2. **Fitur ini SUDAH dirancang rinci di PRD** — `docs/prd/09-bundles-and-workbench.md` "Bagian B" (FR-9.14 … FR-9.28, FR-9.40 … FR-9.42) dan "Bagian C" (FR-9.30 … FR-9.39), dengan keputusan pemilik yang mengikat (persetujuan manual, shell bebas di kontainer terpisah, `signer` terpisah, keystore per instalasi, v2+v3, `zipalign` sebelum `apksigner`, berkas jejak `assets/reverse-apk-modified.txt`). Status PRD 09: **Bagian B = RENCANA, belum ada kode** (baris 3 dokumen); **Bagian C = sebagian** (hanya `shell_run` + jaringan `egress`, mati bawaan).
3. **Yang sudah ada & bisa dipakai ulang**: (a) pola antrean berkas `Spool` (rename atomik) untuk web↔bench dan worker↔runner; (b) runner terisolasi dengan Java 21 + apktool 3.0.3 (pin SHA-256) yang sudah mendekode APK dengan **dekode penuh** (`apktool d -f -j 2`, `runner-daemon:87`) sehingga hasilnya *secara prinsip* bisa dibangun ulang; (c) `bench` + Landlock (kurungan per-analisis, gagal tertutup) yang sudah memberi AI salinan kerja `$WS` dan akses baca ke `$WORK/apktool`; (d) mekanisme tool AI (`ai/tools.py`) dengan validasi ketat, redaksi, audit; (e) halaman Berkas + unduhan aman, audit log, CSRF, kuota.
4. **Celah terbesar**: (i) tidak ada Java/apktool di `bench`, jadi AI bisa mengubah salinan smali di `$WS` tetapi **tidak bisa mem-build**; (ii) tidak ada layanan penanda-tangan/keystore; (iii) tidak ada model data & status "build"/persetujuan (DB sampai skema v4); (iv) tidak ada penyimpanan artefak biner (tabel `analysis_file` hanya `kind IN ('upload','ai')` dan AI hanya boleh menulis ekstensi teks); (v) runner tidak bisa melihat volume `bench` (dan ada tes yang *sengaja* menjaga itu); (vi) tidak ada tool AI `bench_diff`/`request_build`/`get_build_status`, tidak ada UI persetujuan/unduh APK hasil; (vii) dokumen/prompt/tes saat ini secara eksplisit menyatakan "tidak ada build/sign".
5. **Rekomendasi**: ikuti rancangan PRD 09 (Opsi 1 di §9) tetapi dikerjakan bertahap: **B-1** build+sign *tanpa AI* (state machine, runner stage `build`, layanan `signer`, UI persetujuan, unduhan), lalu **B-2** tool AI (`bench_diff`, `request_build`, `get_build_status`) di balik flag baru. Perkiraan: ±12 berkas baru + ±25 berkas diubah (rinci di §9.4). Ada 12 pertanyaan terbuka untuk pemilik di §11 — yang paling menentukan: jenis kunci tanda tangan, apakah `AI_SHELL_ENABLED=1` boleh dinyalakan di produksi, batas ukuran APK, dan anggaran RAM VPS (8 GB, sudah ±6 GB ter-*limit*).

---

## 1. Arsitektur keseluruhan

### 1.1 Diagram (dari `docker-compose.yml`, `docs/prd/07`, `docs/prd/09`)

```
Internet ─► caddy :80/:443 ──(edge)──► web (FastAPI+Jinja, uid 10001)                       [docker-compose.yml:14-39, 41-111]
                                         │  │  │ └─ AI_API_KEY ► provider LLM (OpenAI-compatible, via net `edge`)
          volumes web: uploads(rw) work(rw) files(rw) db bench(rw, hanya hapus) benchspool config(ro)
                                         │  │
              (backend, internal)        │  └─ benchspool ──────────────► bench (shell AI, Landlock, tanpa rahasia) ─(benchnet)─► egress ─(egressnet)─► internet
                  redis ◄─ RQ queue ─────┘                                [volume: uploads:ro work:ro bench benchspool]   [AI_SHELL_NET_ALLOW]
                    ▲                                                     
                    │                                                     
                 worker (orkestrasi pipeline, SQLite rw)                                                              
                    │  spool (berkas: requests/running/results/cancel)
                    ▼
                 runner (jadx + apktool + analyzer; network_mode none; read_only; recycle tiap job)
                    volumes: uploads:ro  work(rw)  spool

SQLite WAL (volume db): web + worker saja.  runner/bench: TANPA DB, TANPA Redis, TANPA rahasia.
```

### 1.2 Alur data (upload → … → chat)

| Tahap | Pelaku | Bukti |
|---|---|---|
| Upload (stream ke disk, validasi *central directory* tanpa dekompresi, SHA-256, dedup, pernyataan otorisasi → audit) | web | `routes_apk.py:190` (`/api/uploads`), `apkcheck.py`, `uploads.py`, `rvcore/bundle.py` (XAPK/APKS: hanya base) |
| Antre analisis ke Redis (RQ queue `jobs`, `tasks.run_analysis`) | web → redis | `web/app/jobs.py:12-29`, `worker/tasks.py:11-18` |
| Pipeline: `validating → apktool → jadx → analyzing` (+ ringkasan manifest) | worker → runner via spool | `worker/pipeline.py:170-215` (`_execute`), `rvcore/store.py:25-30` (`PIPELINE_STAGES`) |
| Dekompilasi/analisis berat | runner | `runner-daemon:79-94` (`build_command`), `:308` (`_run_tool`) |
| Analisis statis (indeks FTS5, call graph, secret/kripto/jaringan, sertifikat) | runner (`analyzer/`) → `work/<id>/index/` | `services/runner/analyzer/*.py` |
| Baca hasil + chat agent | web (read-only atas `work/`) | `web/app/codeindex.py` (allowlist akar + `resolve_under` + `O_NOFOLLOW`), `ai/agent.py`, `ai/tools.py` |
| Ringkasan/laporan AI otomatis (M3) | **tidak ditemukan** — README: "M3 belum dikerjakan"; `grep ai_summar` hanya `decompile.ai_summary` (ringkasan error jadx untuk AI) |

### 1.3 Tata letak penyimpanan (`services/rvcore/paths.py:1-49`)

```
/data/uploads/<sha256>.apk      APK/XAPK/APKS asli (nama internal selalu .apk)       web rw · worker ro · runner ro · bench ro
/data/work/<analysis_id>/       apktool/ jadx/ index/ logs/ manifest.json            worker+runner rw · web rw · bench ro
/data/files/<analysis_id>/{up,ai}/   lampiran pengguna & berkas buatan AI            HANYA web
/data/bench/<analysis_id>/      ruang kerja shell AI ($WS)                            bench rw · web (hanya safe_rmtree)
/data/benchspool/               antrean web→bench                                     web + bench
/data/spool/                    antrean worker→runner                                 worker + runner
/data/db/app.sqlite             SQLite WAL (skema v4)                                 web + worker
```
`Layout` **tidak** punya properti `bench`/`builds`; jalur bench dihitung ad hoc `layout.root / "bench"` (`routes_apk.py:977`) dan `policy.Dirs.bench` (`bench/policy.py:34-36`).

### 1.4 Antrean & model data
- **Redis** hanya untuk RQ (`worker.py:QUEUE_NAME="jobs"`, `jobs.py`), heartbeat worker/runner, rate-limit login. Redis: `maxmemory 256mb`, `noeviction` (`docker-compose.yml:~166`).
- **Spool berkas** (bukan Redis) untuk runner & bench karena keduanya tanpa jaringan/Redis: `rvcore/spool.py` (requests/running/results/cancel/tmp + `runner.hb`), `rvcore/shellspool.py` (bench).
- **SQLite** `rvcore/db.py:_MIGRATIONS` (v1–v4): `apk`, `analysis`, `analysis_stage`, `artifact`, `analysis_log`, `audit_log` (v1); `finding` (v2); `ai_call`, `chat_session`, `chat_message` (v3); `analysis_file`, `message_file` (v4, `db.py:153-186`). `SCHEMA_VERSION = len(_MIGRATIONS)` (`db.py:188`). **Tidak ada tabel build/modifikasi/persetujuan.**

---

## 2. Tabel service → tanggung jawab → file kunci

| Service | Tanggung jawab | Hak/jaringan/limit (compose) | File kunci (simbol) |
|---|---|---|---|
| **caddy** | TLS, reverse proxy, batas body per rute (`/api/uploads` = `MAX_UPLOAD_MB`, `/api/files/upload` = `ATTACH_MAX_MB`, lainnya 1 MB) | edge; 256m | `deploy/Caddyfile` |
| **web** | Auth (argon2id, sesi bertanda tangan, CSRF), upload, UI Jinja, SSE status, chat agent (thread), penyimpanan `files`, klien provider AI | `edge`+`backend`; **satu-satunya pemegang `AI_API_KEY`**; 512m, pids 256; rootfs ro | `web/app/main.py` (app, CSP `:62`, router `:52-54`), `routes_apk.py`, `routes_files.py`, `routes_storage.py`, `context.py`, `ai/{agent,chat,tools,provider,config,budget,redact,attach}.py`, `userfiles.py`, `codeindex.py`, `decompile.py` |
| **worker** | RQ worker; orkestrasi pipeline (tanpa alat berat); heartbeat; pemulihan setelah restart | `backend` internal; 512m; volume uploads:ro, work, db, spool | `worker/worker.py` (`main`, `requeue_orphans`), `tasks.py` (`run_analysis`, `selftest`), `pipeline.py` (`run_analysis`, `_execute`, `_stage_tool`, `_run_job`, `_wait_result`, `reconcile`) |
| **runner** | Satu-satunya pem-parse APK tak tepercaya: apktool, jadx, analyzer (+ ekstraksi base dari XAPK/APKS) | `network_mode: none`, uid 10001, ro, `cap_drop ALL`, tmpfs `/tmp` 256m, **3g RAM / 2 CPU / 512 pids**, recycle per job | `runner/runner-daemon` (`build_command`, `validate_request`, `run_job`, `_run_tool`, `kill_group`, `main`), `runner/analyzer/*`, `runner/runner-selftest` |
| **rvcore** | Kode bersama (stdlib saja): skema/DB, store, spool, shellspool, fsutil (aman symlink), bundle, layout | — | `db.py`, `store.py`, `spool.py`, `shellspool.py`, `fsutil.py` (`safe_rmtree`, `resolve_under`, `atomic_write_json`, `tree_stats`, `remove_unsafe_entries`), `bundle.py` (`plan_bundle`, `prepared_apk`), `paths.py` (`Layout`) |
| **bench** | Shell AI terisolasi (`shell_run`): satu perintah sekali jalan, dikurung Landlock per analisis, gagal tertutup | jaringan internal `benchnet` (hanya ke `egress`), uid 10001, ro, `cap_drop ALL`, 1g / 1 CPU / 512 pids; **tanpa rahasia**; `uploads:ro work:ro bench benchspool` | `bench/bench-daemon` (`validate_run`, `run_job`, `sweep_orphan_workspaces`), `bench/bench/{policy,landlock,confined_exec,executor,netprobe}.py`, `bench/bench-selftest` |
| **egress** | Proxy CONNECT berdaftar-putih; menolak alamat internal/metadata; kuota byte | `benchnet`+`egressnet`; uid 10003; 256m; tanpa volume/rahasia | `egress/egress/{policy,server}.py` |
| **redis** | Antrean RQ + heartbeat | `backend`; 320m | compose `:156-177` |
| *(catatan)* volume `benchspool` vs `spool` | dipisah sengaja: `claim_next` mengklaim apa pun yang lolos regex id di `requests/` (komentar `spool.py:Spool.__init__`) | | |

**bench** & **egress** dan layanan AI-shell **mati secara bawaan** (`AI_SHELL_ENABLED=0`, `docker-compose.yml:81`; `AI_SHELL_NET_ALLOW` kosong = tanpa jaringan).

---

## 3. Chat agent / AI

### 3.1 Provider & konfigurasi
- Klien generik OpenAI-compatible (stdlib), `ai/provider.py` (`Client.chat(..., tools, stream, on_delta, on_tool)`); `http://` ke host publik ditolak (`ai/config.py:load_ai_config`).
- `config/ai_models.json`: tabel harga (kredit/juta token), `floor_per_request` 0,01, penanda `chat` & `vision` per slug (DeepSeek V4*, Claude Haiku/Sonnet/Opus/Fable, GPT-6*, Grok 4.5). Dimuat `ai/pricing.py` (`PriceTable`); model dipilih per pesan hanya dari `AI_MODEL`/`AI_MODEL_PRO` (`routes_apk.py:_allowed_models`).
- Anggaran dalam kredit: `ai/budget.py` (`check` sebelum tiap panggilan, `record` sesudah). Default 5 kredit/hari, 1 kredit/sesi, `AI_MAX_STEPS=100`. **Implikasi build**: tiap putaran model ≥ 0,01 kredit → siklus ubah→build→perbaiki yang panjang cepat menghabiskan anggaran sesi (1 kredit = 100 putaran minimum).

### 3.2 Loop & streaming
- `ai/chat.py:run_in_thread` → thread `chat-<sid>`; `Turn` menyimpan *log peristiwa* di **memori proses web** (TTL 600 dtk; hilang bila web restart) dan melayani SSE dengan `Last-Event-ID` (`routes_apk.py:chat_stream`). `ToolContext` dibuat di `chat.py` (~baris 150) — `analysis_id`, `work`, `bench_sha256` dari DB, **bukan dari model**.
- `ai/agent.py:run_turn` (`:247`): `for step in range(1, max_steps+2)` → `client.chat(messages, tools=schemas, stream=True)` → bila ada `tool_calls`, eksekusi **berurutan** via `T.run_tool` (`:~330`), hasil dimasukkan sebagai pesan `role: tool`. Pengaman: batas langkah, anggaran, batal (`cancel` Event), `AI_MAX_TURN_TOOL_CHARS`, langkah final tanpa tool.
- Gambar: `view_image` → `ctx.pending_images` → dikirim sebagai pesan user (protokol tool hanya teks).
- Event SSE: `round`, `delta`, `tool_draft`, `tool_start`, `tool_end` (+`detail` untuk shell), `file`, `final`, `end`.

### 3.3 Daftar tool yang ada (`ai/tools.py:927 TOOLS`) 
Handler = fungsi `def x(ctx: ToolContext, args: dict) -> dict` di file yang sama.

| Tool | Handler (baris) | Jenis |
|---|---|---|
| `get_overview` | `tools.py:163` | baca (summary, dekompilasi, call graph) |
| `get_manifest` | `:191` | baca |
| `list_packages` / `list_classes` | `:208` / `:218` | baca (indeks) |
| `search_code` | `:241` | baca (FTS5) |
| `get_class` / `get_method` | `:306` / `:337` | baca (Java; jatuh ke smali) |
| `find_xrefs` / `find_callees` / `class_info` / `find_paths` | `:463` / `:490` / `:505` / `:531` | baca (call graph) |
| `list_strings` / `get_findings` | `:551` / `:565` | baca |
| `read_file` / `list_dir` | `:640` / `:689` | baca (jadx/sources, jadx/resources, apktool/, lampiran/, hasil_ai/) |
| `list_files` | `:759` | baca (DB) |
| **`write_file` / `edit_file`** | `:789` / `:801` | **tulis** — hanya `files/<id>/ai/`, ekstensi teks (`userfiles.AI_TEXT_EXTS` `:44`, termasuk `smali`, `patch`, `diff`, `xml`), tidak pernah dijalankan |
| `view_image` | `:813` | baca (hanya model `vision`) |
| **`shell_run`** | `:870` | **eksekusi** di `bench` — hanya ditawarkan bila `AI_SHELL_ENABLED=1` (`SHELL_ONLY` `:1029`, `schemas()` `:1050`) |

Tidak ada tool untuk: build, diff ruang kerja, minta persetujuan, status build, unduh/pasang APK (sesuai FR-9.34 — memang sengaja: AI tidak boleh menyetujui/menandatangani).

### 3.4 Pola persis menambah tool baru (diverifikasi dari kode + tes)
1. Tulis `def nama(ctx: ToolContext, args: dict) -> dict` di `ai/tools.py`; validasi argumen dengan `_str/_int/_opt_limit/_content_arg` (`:87-118`, `:770`); gagal → `raise ToolError("pesan aman untuk model")`. Hasil = dict JSON; field `ringkas` dipakai UI (`agent._summarize`). **`analysis_id`/path berbahaya tidak boleh datang dari model** (ambil dari `ctx`).
2. Daftarkan di dict `TOOLS` (`tools.py:927`): `"nama": (fungsi, {"description":..., "properties": {...}, "required": [...]})`. Skema otomatis jadi `additionalProperties: False` (`schemas()` `:1050`).
3. Bila harus bersyarat (flag): tambahkan ke frozenset ala `SHELL_ONLY`/`VISION_ONLY` dan ke filter `schemas()`; tambah parameter di panggilan `agent.py:261`; tambah field `AIConfig` (`ai/config.py`) + env + **teruskan di `docker-compose.yml`** (pelajaran OP-01; ada tes yang memeriksa: `tests/test_shell_tool.py:106`).
4. Tool dengan **teks bebas** (perintah, patch, isi file) → daftarkan juga di set yang argumennya diredaksi (`run_tool` entry `args`, `agent._shown_args` `:379`), pelajaran kebocoran argumen `audit.md` §10.11.
5. Hasil dibungkus `<hasil_tool>` + peringatan data-tak-tepercaya oleh `run_tool` (`:1058+`); jangan memotongnya sendiri.
6. Audit aksi sensitif: pola `_shell_audit` (`tools.py:861`) → `store.audit(conn, "aksi", {...})`, **tanpa isi** perintah/keluaran.
7. UI: tambahkan label di `static/js/app.js` `TOOL_LABELS` (`:1121-1141`) dan label draft (`:1760-1762`); bila ada `detail`, isi `ctx.ui_detail` seperti `shell_run`.
8. Prompt: `ai/agent.py` — aturan D (`:109`) dan `SHELL_PROMPT_BLOCK` (`:119`) kini menyatakan "tidak ada build"; `system_prompt()` (`:158`) memakai pergantian string persis (RuntimeError bila teks dasar berubah) dan `tests/test_shell_tool.py:322-330` menjaga prompt tidak berjanji "apktool b"/"apksigner"/"pasang APK" → **tes ini harus direvisi sadar** saat fitur build dinyalakan.
9. Tes: gunakan pola `tests/test_shell_tool.py` (`fake_bench`, `ctx_for`, `FakeClient`) dan fixture `clean_shared_db_rows` agar DB bersama tidak tercemar.

### 3.5 Lampiran, "writing file", workbench, bundles
- **Lampiran**: upload badan mentah ke `POST /api/files/upload?analysis=<id>` (`routes_files.py:83`), jenis dari *magic bytes* (`userfiles.sniff`), disimpan `files/<id>/up/<token>`; teks ≤ `AI_INLINE_ATTACH_CHARS` inline, sisanya `read_file lampiran/<id>`; gambar → `image_url` bila model `vision`; semuanya dibungkus `<lampiran>` + redaksi secret (`ai/attach.py`).
- **"Writing file"** (screenshot `docs/screenshots/chat-resume`): event `tool_draft` memberi tahu UI nama berkas + jumlah karakter selagi model menyusun argumen `write_file` (`agent.py:on_tool`, throttling 0,4 dtk; UI `app.js:~1760`). Penulisan sebenarnya `FileStore.write_ai` (`userfiles.py:242`): path dibersihkan `clean_ai_path` (tanpa `..`, abs, titik awal; ≤5 tingkat; allowlist ekstensi), tulis atomik (tmp+fsync+`os.replace`), tolak symlink, kuota `FILES_QUOTA_MB`/`FILES_MAX_COUNT`/`ATTACH_MAX_MB`, audit `ai_file_write`. **Berkas biner/APK tidak bisa lewat jalur ini.**
- **Bundles (PRD 09 Bagian A, sebagian)**: XAPK/APKS diterima, **hanya base APK** yang dianalisis (`rvcore/bundle.py:plan_bundle`, `prepared_apk` mengekstrak ke `work/<id>/base.apk` sementara). `.apkm`/`.aab` ditolak. Merge split sengaja tidak dilakukan (tanda tangan hasil merge tidak sah — `audit.md` §10.10).
- **Workbench (PRD 09 Bagian C, sebagian)**: `bench` + `shell_run`; `$WS`=`/data/bench/<id>` (RW, awalnya *kosong*, dibuat saat perintah pertama — **bukan** salinan apktool seperti FR-9.14), `$WORK`=`work/<id>` (RO; hanya `apktool/ jadx/ logs/ manifest.json`; `index/` tertutup), `$APK` (RO). Env dibangun di `bench/policy.py:env_for`.

---

## 4. Sandbox & keamanan (krusial untuk build)

### 4.1 Peran dan batas
| Komponen | Boleh | Tidak boleh | Bukti |
|---|---|---|---|
| **runner** | menjalankan apktool/jadx/analyzer pada APK tak tepercaya; menulis `work/`, `spool/` | jaringan, Redis/DB, `files`, `bench`, `benchspool`, Docker socket, menulis `uploads` | `docker-compose.yml:183-216`; `runner-daemon` docstring; `runner-selftest` membuktikan |
| **bench** | `bash -c` per perintah di proses anak yang dikurung Landlock; tulis hanya `$WS`+scratch; baca sistem, `$WORK/{apktool,jadx,logs,manifest.json}`, `$APK` | rahasia apa pun; baca `index/`, analisis lain, `db`, `files`, `spool`; **Java/apktool/jadx/compiler** (image tanpa itu `bench/Dockerfile:14-17`); daftar isi `/data` | `bench/policy.py:rules_for`, `confined_exec.py` (kenari + penanda sebelum `exec`), `landlock.py` |
| **egress** | CONNECT HTTPS ke host daftar-putih, port 443 default; kuota 32 koneksi/100 MB/1 GB per jam | HTTP polos, alamat privat/loopback/metadata/CGNAT/NAT64, nama tanpa titik | `egress/policy.py`, `server.py` |
| **web** | semua rute berautentikasi; membaca hasil runner/bench **sebagai tak tepercaya** (`resolve_under`+`O_NOFOLLOW`, ukuran dicek sebelum dibaca, JSON ketat) | tidak ada shell/subprocess; tidak menjalankan berkas | `rvcore/fsutil.py`, `shellspool.read_result`, `codeindex.py` |

### 4.2 Resource limit yang ada
- runner: `mem_limit 3g`, `cpus 2`, `pids_limit 512`, tmpfs `/tmp` 256m; `JADX_OPTS -Xmx2g`, wrapper apktool `-Xmx2g` (`runner/Dockerfile:29`); `TIMEOUT_APKTOOL=300`, `TIMEOUT_JADX=900`, `TIMEOUT_ANALYZE=300`, `JOB_TIMEOUT=2700`; klem timeout 10–3600 dtk (`runner-daemon:55,268`); `MAX_OUTPUT_MB=3072` + `MAX_OUTPUT_FILES=600000` (zip-bomb jujur-bohong); log 5 MiB; kill *process group*.
- bench: timeout bawaan 60/maks 120 dtk, keluaran 64 KB/aliran, kuota `$WS` 2048 MB, file 256 MB, `RLIMIT_NPROC 2048`, `RLIMIT_CPU`.
- Total `mem_limit` kini ≈ 256+512+512+320+3072+1024+256 = **5,95 GB** dari VPS 8 GB (PRD 00 §8; NFR-7.2 menargetkan ≤ 6,5 GB).

### 4.3 Hal yang belum terbukti (jujur, dari PRD/audit)
`bench`/`egress`/Landlock di Docker nyata **belum terbukti** (tidak ada Docker di sandbox pengembangan): jalankan `make bench-selftest` di VPS dulu (`docs/prd/09` "Status PR C/D", `audit.md` §10.11-10.12). Kebocoran DNS Docker-internal tidak diketahui. Tidak ada tes untuk worker/runner/analyzer (`.kiro/steering/testing.md`: "Cakupan saat ini hanya aplikasi web").

---

## 5. Inventaris toolchain APK di image Docker

| Alat | Ada? | Di mana / versi | Bukti |
|---|---|---|---|
| JDK/JRE | **JRE 21 headless** | image `runner` (`openjdk-21-jre-headless`, paket Debian trixie) | `runner/Dockerfile:21` |
| apktool | **3.0.3** (SHA-256 `dbf930b0…9423`) — `d` dipakai; `b` hanya terbukti di sandbox yang `/tmp`-nya boleh exec (KOREKSI 14 Okt 2026: di kontainer runner GAGAL, lihat bawah) | `/opt/apktool/apktool.jar`, wrapper `/usr/local/bin/apktool` (`-Xmx2g`) | `runner/Dockerfile:8-9,26-30`; `scripts/sample-apk/build.py:241-247` menjalankan `apktool b` di image runner dengan `--network none --read-only --tmpfs /tmp:256m --cap-drop ALL --user 10001` **[KOREKSI: klaim "terbukti jalan di kondisi mirip runner" KELIRU. `--tmpfs /tmp` Docker bersifat `noexec` dan apktool menjalankan aapt2 yang diekstrak ke /tmp, jadi skrip ini gagal di kontainer sungguhan (bukti: `make runner-selftest` di VPS, errno 13). Diperbaiki: aapt2 terpasang di `/opt/apktool/aapt2` + `--aapt`]** |
| jadx | **1.5.6** (SHA-256 dipin) | runner | `runner/Dockerfile:6-7,22-25` |
| smali/baksmali | hanya sebagai pustaka **di dalam** apktool.jar; **tidak ada CLI** mandiri | — | tidak ditemukan sebagai berkas terpisah |
| aapt2 | **tidak ada CLI mandiri**; apktool 3.0 menjatuhkan aapt1 dan memakai aapt2 (dibundel di jar) — dipakai internal oleh `apktool b` | — | rilis apktool 3.0.0 (apktool.org/blog/apktool-3.0.0, "dropping support for aapt1") **[DUGAAN untuk detail bundel — kini terukur: `prebuilt/linux/aapt2`, ELF x86-64 statis, 6.449.680 byte. Perilaku `b` TIDAK terbukti oleh build.py (lihat koreksi di baris apktool); `apktool b` dengan `--aapt /opt/apktool/aapt2` terbukti di tmpfs noexec nyata di sandbox]** |
| zipalign | **tidak ada** | PRD 09 merencanakan Build-Tools (kandidat 37.0.0), Google hanya menerbitkan SHA-1 → SHA-256 dihitung sendiri; "uji berjalan di `python:3.12-slim-trixie`" masih **[OPEN]** | `09` "Temuan alat", "Pertanyaan terbuka" |
| apksigner | **tidak ada** (JAR Java dari Build-Tools; butuh JRE) | belum ada image | idem; `bench/Dockerfile:14` "Sengaja TIDAK ada … apksigner/keystore" |
| d8 / dx / compiler | **tidak ada** | — | `bench/Dockerfile:14` "TIDAK ada compiler" |
| keytool | kemungkinan ada (bagian `jre-headless`); dipakai analyzer (`signing.py:149-153`) — tidak dicakup `runner-selftest` | runner | **[DUGAAN]** perlu dikonfirmasi `docker run … keytool -help` |
| jarsigner | kemungkinan **tidak ada** di runner (ada di paket JDK, bukan JRE-headless); dipakai skrip dev di *host* | host dev | `build.py:249-260` **[DUGAAN]** |
| Android SDK / platform android.jar | **tidak ada** (tidak diperlukan untuk `apktool b`; `build.py:5` "Tidak memerlukan Android SDK") | — | |
| bench: Python 3.12, bash, coreutils, unzip/zip, patch, diffutils, binutils, curl+ca-certificates | ada; **tanpa Java** | `bench/Dockerfile:17` | |

### 5.1 Bagaimana dekompilasi dijalankan (jawaban #4)
`worker/pipeline.py:_execute` mengirim job per tahap lewat `Spool.submit` (`pipeline.py:_run_job` `:345`) dengan `{job_id, analysis_id, stage, sha256, options:{deobf}, timeout}`; runner (`runner-daemon:main` `:469`) `claim_next` → `validate_request` (`:254`) → `run_job` (`:272`; path APK/work dihitung sendiri dari `analysis_id`+`sha256`, bukan dari request) → `_run_tool` (`:308`) → `subprocess.Popen(cmd, start_new_session=True)` dengan `HOME` sementara & `JADX_OPTS`. Perintah dari **allowlist** `build_command` (`:79`): `apktool d -f -j 2 -o <out> <apk>`; `jadx -j 2 --show-bad-code --log-level error [--deobf] -d <out> <apk>`; `python3 -m analyzer …`. Keluaran dipantau tiap 5 dtk (`tree_stats`), simbolik/khusus dibuang (`remove_unsafe_entries`). Setelah satu job runner keluar (`RUNNER_RECYCLE`).

---

## 6. Apakah sudah ada edit / repack / sign? (jawaban #5)

| Pencarian | Hasil |
|---|---|
| `apktool b`, `repack`, `rebuild` | hanya `scripts/sample-apk/build.py:241-247` (skrip pengembangan, butuh Docker host) |
| `zipalign`, `apksigner`, `keystore` | tidak ada kode; hanya komentar penolakan (`bench/Dockerfile:3,14`, `bench-daemon:6`, `docker-compose.yml:219`), PRD 09 (rencana), dan `analyzer/signals.py:133-143` (mendeteksi *berkas* keystore di aset APK — temuan, bukan fitur) |
| `smali` / `baksmali` / `patch` | `smali`, `patch`, `diff` hanyalah **ekstensi teks yang boleh ditulis AI** (`userfiles.py:44`) dan `patch` ada di image bench (`bench/Dockerfile:17`); tidak ada mesin yang menerapkan/menyusun-ulang |
| **`scripts/sample-apk/build.py`** (267 baris) | Membangun "VulnSample" dari smali+manifest tulisan tangan, `apktool b` di container runner tanpa jaringan, lalu opsional `jarsigner` v1 + keystore debug publik (`android/android`) di host. Bukan bagian produk; berguna sebagai **bukti kelayakan** `apktool b` (KOREKSI: hanya setelah memakai `--aapt /opt/apktool/aapt2`; sebelumnya gagal di kontainer karena tmpfs `noexec`) di sandbox runner dan **sumber APK uji** build |
| **`scripts/make-test-apks.py`** (89 baris) | Hanya pembuat berkas uji upload: `bomb` (zip bomb ~300 MB), `large` (APK + padding acak ≥ N MB — "tanda tangan menjadi tidak valid"), `junk` (struktur valid, isi sampah). Tidak menyentuh apktool |
| `analyzer/signing.py` | **Membaca** sertifikat/skema v1–v3 (parser biner + `keytool -printcert`), tidak memverifikasi validitas tanda tangan (`audit.md` §10.10: "analyzer tidak memverifikasi tanda tangan") |

---

## 7. Web UI, API, auth

- **Auth**: satu admin; argon2id; cookie sesi `__Host-rv_session` (HttpOnly, Secure, SameSite=Strict) bertanda tangan; token CSRF per sesi (form: field `csrf`, XHR: header `X-CSRF-Token`); rate-limit login per IP (`security.py`, `main.py`). Semua rute non-publik cek `current_session` (audit §6: 39 rute diuji tanpa sesi → ditolak). CSP ketat (`main.py:62-66`): `script-src 'self'`, tanpa inline; rute boleh memasang CSP lebih ketat (mis. unduhan: `default-src 'none'; sandbox`).
- **Rute** (semua `include_in_schema=False`):
  - Sistem: `GET /healthz`, `/readyz`, `/robots.txt`, `GET|POST /login`, `POST /logout`, `POST /selftest` (`main.py:199-299`).
  - Dashboard/upload: `GET /`, `GET /upload`, `POST /api/uploads` (`routes_apk.py:101,122,190`).
  - Analisis: `GET /analyses/{id}` (Ringkasan), `/decompile/errors`, `/manifest`, `/findings`, `POST /findings/{fid}/reveal`, `/network`, `/code`, `/code/tree`, `/code/file`, `/code/search`, `POST /static` (analisis statis ulang), `/status`, `/events` (SSE), `POST /cancel`, `POST /retry`, `POST /apks/{id}/delete`.
  - Chat: `GET /analyses/{id}/chat`, `POST /chat/send`, `GET /chat/stream`, `GET /chat/active`, `POST /chat/cancel`, `POST /chat/{sid}/delete`, `GET /chat/{sid}/export.md`.
  - Berkas: `POST /api/files/upload`, `GET /analyses/{id}/files`, `/files/{fid}/raw|download|text`, `POST /files/{fid}/delete`, `GET /files/download.zip` (`routes_files.py`).
  - Penyimpanan: `GET /storage`, `POST /storage/scan`, `GET|POST /storage/bersihkan`, `GET /storage/jelajah[/lihat|/unduh]` (`routes_storage.py`).
- **Tab detail** (`templates/_analysis_head.html`): Ringkasan · Temuan · Jaringan · Kode · Percakapan · Berkas · Manifes. Tab dibangun lewat `_tab_context(request, id, tab)` (`routes_apk.py:347`). **Tidak ada** tab Build/Modifikasi.
- **Viewer/editor**: penampil kode read-only (Java/smali/resource dari `work/<id>`; `codeindex.ROOTS` java/jres/smali, batas 2 MiB) dan pratinjau teks berkas (`files/{fid}/text`, textContent). **Tidak ada editor** manual dan **tidak ada penampil diff**.
- **Unduhan**: berkas selalu `attachment` + `application/octet-stream` + `nosniff` + CSP `sandbox` (`routes_files.py:file_download`); gambar raster hanya bila lolos sniffing. Unduhan `application/vnd.android.package-archive` (FR-9.25) belum ada. Penjelajah folder hasil dekompilasi: `routes_storage.py` (`/storage/jelajah/unduh`).
- **Halaman Penyimpanan** (`storage.py:44-48` `CATEGORIES`: apk/decompile/files/db/tmp): **tidak menghitung `bench/` sama sekali** (grep `bench` di `storage*.py` → kosong) — ruang kerja AI sampai 2 GB/analisis tak terlihat di UI; gap yang akan memburuk dengan build.

---

## 8. Konvensi kode, konfigurasi, tes, CI

- **Bahasa**: Python 3.12 (image `python:3.12-slim-trixie`), FastAPI+Jinja2, JS vanilla (tanpa framework, tanpa `innerHTML`), SQLite; **seluruh teks/komentar/pesan dalam Bahasa Indonesia**. rvcore = stdlib saja.
- **Gaya**: dataclass beku untuk config; fungsi kecil; komentar menjelaskan *kenapa* + pelajaran audit; galat ke pengguna = pesan aman (tanpa path internal); tool jangan pernah melempar ke agent (`run_tool` membungkus); logging satu baris per kejadian, tanpa isi data/kunci (`ai/logutil.py:describe`); audit lewat `store.audit` / `context.audit_event` (tidak boleh menggagalkan aksi).
- **Konfigurasi**: env → `Settings` (`web/app/config.py`), `AIConfig` (`ai/config.py`), `userfiles.limits_from_env`, `runner-daemon`/`bench-daemon` (`_int_env`), `pipeline.Config.from_env`. **Wajib** ditulis di `docker-compose.yml` dan `.env.example` (OP-01: variabel yang tidak diteruskan compose tidak pernah sampai; dijaga tes `test_shell_tool.py:106`). `make init` (`scripts/init.sh`) membuat `.env` + `secrets/`; rahasia berkas lewat compose `secrets:` (`admin_password_hash`, `docker-compose.yml:322-324`).
- **Menambah job type worker/runner** (pola nyata): (1) daftarkan tahap di `rvcore/spool.py` (`TOOL_STAGES` `:29`, `JOB_ID_RE` `:30`, `STAGE_OUT_DIR` `:32`); (2) tambah cabang di `runner-daemon:build_command` (`:79`, **allowlist** argumen), `tool_version`, penilaian hasil di `_run_tool`; (3) tambah tahap di `store.PIPELINE_STAGES` (butuh migrasi data untuk baris `analysis_stage` lama, contoh v2 di `db.py`); (4) orkestrasi di `worker/pipeline.py` (`_stage_tool` + `Config.timeouts` + env `TIMEOUT_*` di compose); (5) RQ task di `worker/tasks.py` dan pengiriman di `web/app/jobs.py`; (6) **tambahkan modul baru ke daftar `COPY` di `worker/Dockerfile:21-22`** (daftar eksplisit!).
- **Migrasi DB**: tambah string baru di akhir `_MIGRATIONS` (`db.py`), pernyataan dipisah `;` (tanpa trigger/`;` dalam string), otomatis lewat `migrate()` saat web/worker start; **SQLite tidak bisa mengubah `CHECK`** (mis. `analysis_file.kind`, `db.py:162`) tanpa membangun ulang tabel.
- **Tes** (`.kiro/steering/testing.md`): pytest di `tests/` (≈ 507 fungsi tes statis; PRD 09 menyebut suite 966 lulus termasuk parametrisasi), dijalankan CI. `tests/conftest.py`: `DATA_DIR` sementara, `REDIS_URL=127.0.0.1:1`, `AI_BASE_URL=127.0.0.1:9`, fixture `seeded`, `client` (login), `anon`, `json_headers`, `blocking_turns`, helper `query`, `new_analysis`, `wait_for`. Aturan: tiap perbaikan bug punya tes yang **gagal di kode lama, lulus di kode baru**. Tes yang menulis DB bersama harus membersihkan miliknya. Worker/runner/analyzer belum bertes (hanya diuji manual); bench/egress diuji di `test_shell_bench.py`, `test_shell_net.py`, `test_egress_*.py`. `pytest --collect-only` tidak bisa dijalankan di sandbox ini (`fastapi` belum terpasang) — tidak dipaksakan.
- **CI** `.github/workflows/ci.yml`: Python 3.12 → `pip install -r services/web/requirements.txt -r tests/requirements.txt` → `python -m pyflakes services tests` → `python -m pytest`. Tidak ada build Docker di CI.
- **Makefile**: `help init password up down restart logs ps update runner-selftest bench-selftest net-check ai-check env-check doctor test`. Pola untuk layanan baru: `<svc>-selftest` yang menjalankan `docker compose run --rm --no-deps … <svc>-selftest` dan membuktikan isolasi dari dalam kontainer.
- **Proses**: satu cabang baru dari `origin/main` per paket; PR via `gh api` (audit §8); jujur soal apa yang belum diuji; tidak ada `AGENTS.md`/`CONTRIBUTING.md` (**tidak ditemukan**); `.kiro/steering/` hanya `testing.md`.

---

## 9. Pola job & titik integrasi untuk 'modify' dan 'build/repack/sign'

### 9.1 Pola yang ada (ringkas)
```
web ──RQ(Redis)──► worker ──Spool(berkas)──► runner         # analisis; tahap alat berat
web ──Spool(benchspool)──────────────────► bench            # perintah shell AI (sinkron, web menunggu)
```
- Dua protokol spool serupa: `Spool` (worker↔runner, `JOB_ID_RE=^a\d+-(stage)-hex8$`) dan `shellspool` (web↔bench, `JOB_ID_RE=^s\d+-hex12$`, `OP_RUN` saja — `bench-daemon:run_job` menolak `op` lain `:97`).
- Prinsip kepercayaan: penerima **menghitung path sendiri** dari `analysis_id` (int) + `sha256` (hex64); hasil dari sisi tak tepercaya dinormalkan (`shellspool.parse_result`).

### 9.2 Titik integrasi paling tepat
| Kebutuhan | Titik integrasi | Alasan |
|---|---|---|
| **Inisialisasi ruang kerja** = salinan `work/<id>/apktool` ke `bench/<id>/project/` dengan baseline pasti | op baru di `bench-daemon:run_job` (mis. `OP_INIT`) + `shellspool.build_*_request`/`parse_result`; salin tanpa mengikuti symlink | FR-9.14/9.39; baseline pasti diperlukan agar diff dihitung **sistem** (FR-9.15) |
| **Diff yang disetujui** (per-berkas, +/− baris, SHA-256 diff) | op baru `OP_DIFF` di bench (daemon punya akses `$WORK:ro` + `$WS`) → JSON ringkas dibaca web (`read_result`, batas 1 MB) | web tidak boleh membaca isi `bench/` mentah (data tak tepercaya); bench sudah satu-satunya yang melihat keduanya |
| **Mengubah isi APK (oleh AI)** | `shell_run` yang ada (sed/awk/python3 pada `$WS/project`) — sesuai keputusan pemilik #4 | tool khusus per jenis perubahan "tidak akan cukup" (PRD 09 "apa saja, sangat banyak") |
| **Build (`apktool b`)** | runner: tahap baru `build` — `spool.TOOL_STAGES`/`JOB_ID_RE`/`STAGE_OUT_DIR`, cabang `build_command` + cabang `run_job` **sebelum** pemeriksaan APK (build tidak butuh `uploads/`), orkestrasi **worker** task baru `tasks.run_build(build_id)` | runner sudah punya Java+apktool, timeout, kill group, batas keluaran, recycle; worker sudah jadi satu-satunya pengirim ke runner. Runner perlu `bench:ro` (atau menerima snapshot) — mengubah invarian yang dijaga tes (§10) |
| **Tanda tangan** | **layanan baru `signer`** (JRE + `apksigner.jar` + `zipalign` + keystore via compose `secrets:`), spool terpisah (mis. `signspool`) hanya dengan worker; membaca `unsigned.apk` (ro), menulis `signed.apk`, menjalankan `apksigner verify` | FR-9.20/9.21; keystore tak boleh di runner/bench/web |
| **Status & persetujuan** | tabel baru `build` (migrasi v5) + `store.py` (CAS seperti `claim_analysis`) + rute `routes_builds.py` (pola `routes_files.py`, di-*include* di `main.py:52-54`) | status FR-9.16: `awaiting_approval → approved → queued → building → signing → done / rejected / failed / cancelled` |
| **Artefak biner & unduhan** | volume baru `builds` (web ro/rw hapus, signer rw, runner rw output) — **bukan** `work/` (dihapus oleh "Analisis ulang": `pipeline._execute` `safe_rmtree(run.work)`) dan **bukan** `analysis_file` (CHECK kind/teks, perlu rebuild tabel) | masa hidup mandiri, kuota, `Content-Type: application/vnd.android.package-archive` |
| **Tool AI** | `bench_diff`, `request_build`, `get_build_status` di `ai/tools.py` (pola §3.4) di balik flag baru (mis. `AI_BUILD_ENABLED`) + flag `shell` | FR-9.31–9.34; **tidak ada tool setujui/tanda tangan/unduh** |

### 9.3 Opsi desain

**Opsi 1 — Ruang kerja apktool + `shell_run` + build/sign terpisah dengan persetujuan (rancangan PRD 09 B+C). ★ Direkomendasikan**
- Alur: `OP_INIT` salin → AI mengubah smali/res/manifest di `$WS/project` lewat `shell_run` → `bench_diff` → `request_build` (status `awaiting_approval`) → pengguna menyetujui di UI (CSRF + pernyataan wewenang, terikat SHA-256 diff) → web enqueue RQ → worker → runner `build` (`apktool b`, tanpa kunci) → signer (`zipalign` lalu `apksigner sign` v2+v3, lalu `verify`) → artefak di `builds/` → unduh via sesi.
- Kelebihan: sesuai keputusan pemilik (persetujuan, shell bebas, signer terpisah); bisa mengubah **apa saja** (manifest, resource, smali, aset, `lib/`); komponen aman-by-design (runner tanpa kunci, signer tanpa parsing pohon).
- Kekurangan: pekerjaan terbesar (layanan baru, volume baru, migrasi, UI diff); bergantung `AI_SHELL_ENABLED=1` yang **belum terbukti di Docker nyata**; smali oleh AI rawan salah (butuh log `apktool b` dikembalikan ke AI + batas percobaan, FR-9.33); build memakai satu runner → antre di belakang analisis.
- Berkas: ±12 baru, ±25 diubah (rinci §9.4).

**Opsi 2 — Ruang kerja terstruktur TANPA shell: tool khusus `apk_workspace_init/apk_edit/apk_delete/apk_diff/request_build`**
- AI mengedit lewat tool dengan allowlist path (`smali*/`, `res/`, `AndroidManifest.xml`, `assets/`), batas ukuran, ekstensi; dieksekusi oleh op bench (tanpa `bash`). Build/sign/persetujuan sama seperti Opsi 1.
- Kelebihan: **tidak butuh** `AI_SHELL_ENABLED` (permukaan serangan jauh lebih kecil, tanpa jaringan egress); diff lebih mudah dikontrol; tool dapat memvalidasi (mis. XML/smali sintaks dasar).
- Kekurangan: bertentangan dengan keputusan pemilik #4/ "apa saja, sangat banyak" (tool tidak menutup kebutuhan seperti `python3` transform massal, `sed -i` ratusan berkas, biner `.so`); lebih banyak kode tool; AI kehilangan fleksibilitas.
- Berguna sebagai **pelengkap P2** Opsi 1 (bagi yang tak mau menyalakan shell), bukan pengganti.

**Opsi 3 — Overlay tingkat-APK (tanpa `apktool b`)**: ganti/tambah entri di ZIP asli (aset, `classesN.dex` baru yang dikompilasi dari smali memakai smali.jar), pertahankan `resources.arsc` & manifest biner asli, `zipalign`+`apksigner`.
- Kelebihan: build cepat, risiko "apktool gagal membangun ulang" kecil, byte asli terjaga; tak perlu salinan penuh pohon.
- Kekurangan: **tidak bisa mengubah manifest/resource** (biner AXML/ARSC) → memotong sebagian besar use-case modifikasi (izin, `debuggable`, network security config, string); butuh `smali.jar` terpisah + penambahan dex multi-dex; perubahan atas satu class di dex besar sulit tanpa baksmali penuh. Tidak direkomendasikan sebagai jalur utama.

**Opsi 4 — Build + sign di dalam `bench` (jalan pintas)**: tambah Java+apktool+apksigner+keystore ke image bench; tool `build_apk` langsung.
- Kelebihan: paling sedikit komponen.
- Kekurangan: **melanggar invarian bench "tanpa rahasia"** (keystore di kontainer yang menjalankan perintah AI + bisa punya jaringan via `egress` → eksfiltrasi kunci); melewati persetujuan (keputusan #3); menggabungkan penjalan kode-AI dan signer. **Ditolak** kecuali dengan kunci sekali-pakai per build (tak ada rahasia persisten) *dan* persetujuan tetap ada — varian ini hanya layak sebagai prototipe lokal.

### 9.4 Estimasi berkas untuk Opsi 1 (rekomendasi)

**Baru (±12)**: `services/signer/{Dockerfile, signer-daemon, signer-selftest}` (+ modul kecil bila perlu); `services/web/app/routes_builds.py`; `services/web/app/templates/builds.html` (+ partial diff/persetujuan); modul build worker (mis. `services/worker/builds.py`) dan, bila dipisah, `rvcore/signspool.py`; tes: `tests/test_build_store.py`, `tests/test_build_routes.py`, `tests/test_build_tool.py`, `tests/test_signer*.py`; dokumen `docs/prd/` (pembaruan, bukan berkas baru) + entri `audit.md` §10.13.

**Diubah (±25)**: `docker-compose.yml` (layanan `signer`, volume `builds`+`signspool`, mount `bench:ro` ke runner atau mekanisme snapshot, env `AI_BUILD_*`/`TIMEOUT_BUILD`/`BUILD_KEEP`/`SIGNER_*`, secret keystore); `.env.example`; `scripts/init.sh` + `Makefile` (buat keystore, `signer-selftest`); `rvcore/{db.py (v5), store.py, spool.py, shellspool.py, paths.py}`; `worker/{tasks.py, pipeline.py/Config, Dockerfile (daftar COPY)}`; `runner/{runner-daemon, Dockerfile?, runner-selftest}`; `bench/{bench-daemon, bench/policy.py, bench/executor.py}`; `web/app/{main.py, routes_apk.py (_delete `:974-979`), context.py, storage.py (+kategori), storage_clean.py, jobs.py, ai/{tools.py, agent.py, config.py, chat.py}, templates/_analysis_head.html (+tab), static/js/app.js (+label tool, UI persetujuan), static/css/app.css}`; tes yang harus direvisi sadar: `tests/test_shell_tool.py` (`:119-135` isolasi compose, `:322-330` prompt), `tests/test_pages_smoke.py` (tab baru); dokumen `README.md`, `docs/prd/{00,05,07,09}.md`, `docs/deploy.md`.

### 9.5 Urutan kerja yang disarankan (selaras PRD 09 "Urutan kerja")
1. **B-1a** skema + state machine (`build` table, store CAS, audit action) + tes.
2. **B-1b** `signer` (image, pin SHA-256 Build-Tools, `signer-selftest`, `make init` keystore) — dibuktikan dulu di VPS, sebelum AI diberi akses.
3. **B-1c** runner stage `build` + worker `run_build` + volume `builds`; uji dengan APK `scripts/sample-apk/build.py` (ubah satu string → build → `apksigner verify`).
4. **B-1d** UI: tab Build/Modifikasi, diff terkelompok, persetujuan (CSRF + pernyataan), unduh APK.
5. **B-2** `OP_INIT/OP_DIFF` di bench + tool AI `bench_diff/request_build/get_build_status` + pembaruan prompt/aturan D + tes injeksi ("APK menyuruh AI menyetujui sendiri/membaca `/data`/jaringan" harus gagal).
6. Dokumentasi: PRD 00 §4 (non-goal "repackaging/signing" berubah), 05, 07, 09; README (status); `audit.md`.

---

## 10. Risiko & batasan

### 10.1 Keamanan
| Risiko | Penjelasan / bukti | Mitigasi yang sudah ada / perlu |
|---|---|---|
| **Pencurian keystore** | apktool/aapt memproses pohon yang dimodifikasi AI (tak tepercaya); jika keystore ada di kontainer yang sama → bisa dicuri | Signer terpisah, tanpa jaringan, hanya `zipalign`+`apksigner` pada satu `.apk` (FR-9.20); keystore via compose `secrets:` (pola `admin_password_hash`); jangan masuk `web/worker/runner/bench` (perluas tes isolasi `test_shell_tool.py:119`) |
| **Prompt injection → AI membangun/menandatangani sendiri** | isi APK = data tak tepercaya (aturan A prompt) | Tidak ada tool setujui/tanda tangan/unduh (FR-9.34); persetujuan hanya UI+CSRF; tes injeksi wajib |
| **Eksekusi kode tak tepercaya** | `apktool b` membaca `apktool.yml` & pohon dari AI; `shell_run` menjalankan `python3`/binary di `$WS` (Landlock RW termasuk EXECUTE `landlock.py:RW`) | Build di runner (tanpa jaringan/rahasia/ro rootfs); bersihkan symlink/khusus (`remove_unsafe_entries`) dari salinan sebelum build; **APK hasil tidak pernah dijalankan** (00 G4) |
| **Race/TOCTOU workspace** | AI bisa mengubah `$WS` saat build berlangsung (volume sama) | Build dari *snapshot* + hitung ulang SHA-256 diff = nilai yang disetujui; tolak bila beda (FR-9.40) |
| **Path traversal / zip bomb / symlink** | pohon & APK dari/ke AI; XAPK/APKS | Pola yang ada: `resolve_under`+`O_NOFOLLOW`, nama entri tidak jadi path (`bundle.py`), batas keluaran runner; web membaca hasil bench/runner sebagai tak tepercaya; ulangi untuk `builds/` |
| **Stale v1 signature / tanda tangan tidak sah** | `apktool b` menyalin `original/META-INF` bila ada; `audit.md` §10.10: "analyzer tidak memverifikasi" | **[DUGAAN]** uji bahwa `apksigner` membuang sisa tanda tangan v1 lama; wajib `apksigner verify` + cocokkan sertifikat dengan kunci instalasi (FR-9.24); jangan percaya `analyze_signing` untuk validasi |
| **Penyalahgunaan (malware, penerbitan APK modifikasi)** | PRD 00 §7: penggunaan hanya untuk APK yang berwenang; non-goal 00 §4 saat ini "Repackaging/patching/signing" | Pernyataan wewenang per persetujuan (dicatat audit), tanda tangan jelas berbeda, berkas jejak `assets/reverse-apk-modified.txt` (FR-9.23), tanpa tautan publik, audit `build_*`; perluas kebijakan 00 §7 |
| **Bocornya data ke provider AI** | keluaran shell/diff dikirim ke LLM | Redaksi (`AI_REDACT_SECRETS`); jangan kirim isi biner/keystore; diff untuk UI, ringkasan untuk AI |
| **Argumen tool memuat rahasia** | pelajaran `audit.md` §10.11 | redaksi argumen tool teks-bebas baru |
| **Perubahan prompt & tes pagar** | prompt/aturan D menyatakan tak ada build | ubah via `system_prompt()` dengan aturan A tetap utuh; revisi tes secara sadar |

### 10.2 Resource
- **RAM**: ±5,95 GB ter-*limit* + `signer` (JVM kecil ~256–512m) ≈ 6,3–6,5 GB dari 8 GB; `apktool b` memakai `-Xmx2g` (wrapper) di runner 3g yang **satu job pada satu waktu** (analisis & build antre di runner yang sama).
- **Disk**: build menyalin pohon apktool (APK 100 MB → puluhan ribu berkas, ratusan MB), + `build/` + `unsigned.apk` + `signed.apk` + bench `$WS` (kuota 2 GB). `MIN_FREE_GB=15` (web), `JOB_MIN_FREE_GB=5` (worker) hanya memeriksa saat upload/validasi → butuh pemeriksaan sebelum build. `/tmp` runner hanya 256m — **[DUGAAN]** apktool/aapt2 menaruh file sementara di sana; ukur dengan APK besar (jangan menebak: pelajaran BE-09).
- **Timeout**: usulan PRD `TIMEOUT_BUILD=600`; `apktool b` pada APK besar bisa lebih lama; klem runner 10–3600 dtk. Giliran chat tidak boleh memblokir selama build (shell_run sudah memblokir ≤ 120 dtk; build harus asinkron + `get_build_status`).
- **Batas ukuran**: bawaan upload 200 MB (`MAX_UPLOAD_MB`); keputusan pemilik 1 GB belum diterapkan (`09` "Batas ukuran"); `ZIP_MAX_ENTRY_MB=512` menolak APK >512 MB per entri.
- **Retensi/kuota**: `BUILD_KEEP=5` per analisis (FR-9.28); belum ada retensi otomatis di proyek (OP-03 "tidak dikerjakan" oleh pemilik) → build lama menumpuk bila tak dibersihkan; halaman Penyimpanan perlu kategori `builds` dan `bench`.

### 10.3 Jaringan
Runner dan (bawaan) bench tanpa jaringan → `apktool b` **offline** berjalan (terbukti oleh `build.py` pada container tanpa jaringan; apktool tidak perlu mengunduh framework untuk APK yang kerangka bawaannya sudah dikodekan; framework non-standar (mis. HTC/Samsung `-t`) tidak tersedia **[DUGAAN]**). Signer: tanpa jaringan. Egress hanya untuk shell AI (opsional).

### 10.4 Keterbatasan fungsional yang harus jujur di UI/README (PRD 09 "Hal yang tidak dijanjikan")
Tanda tangan berbeda dari aslinya → tidak bisa memperbarui aplikasi asli (harus uninstall); "siap pasang" ≠ "pasti jalan" (anti-tamper, Play Integrity, packer, hash `.so`); tidak ada uji jalan (G4); perubahan smali oleh AI rawan salah; Android 14+ menolak `targetSdkVersion < 23` (FR-9.41). **Khusus paket**: hanya base APK yang dianalisis/dibangun (`bundle.py`), sehingga hasil build XAPK/APKS = **base saja**; aplikasi yang butuh split bisa tidak terpasang/berjalan (paket format asal = FR-9.17b, P2).

### 10.5 Legal/etika yang sudah ada di PRD
00 §7 (penggunaan yang diizinkan; pernyataan wewenang saat upload tercatat audit); prompt aturan F (analisis boleh, menyerang pihak ketiga ditolak); 09 "Kebijakan penggunaan" (modifikasi hanya untuk APK yang berwenang; tanpa tautan publik). Perlu diperbarui saat Bagian B dikerjakan: 00 §4 (non-goal), 00 §7, 05 prinsip 2, 07 tabel ancaman baris "Rencana".

---

## 11. Pertanyaan terbuka untuk pemilik proyek

1. **Kunci tanda tangan**: satu kunci per instalasi (dibuat `make init`, seperti PRD FR-9.21) atau kunci debug Android publik (`android`/`android`, mudah tapi siapa pun bisa menandatangani "sebagai" Anda) atau kunci yang disediakan pengguna (impor keystore → manajemen rahasia lebih berat)? Apakah perlu *rotasi*?
2. **Shell**: apakah `AI_SHELL_ENABLED=1` boleh dinyalakan di produksi? Sudah menjalankan `make bench-selftest` (Landlock di Docker nyata) dan hasilnya lulus? Bila tidak, apakah Opsi 2 (tool terstruktur tanpa shell) lebih diinginkan?
3. **Build offline**: konfirmasi runner/signer tetap tanpa jaringan; apakah framework apktool non-standar (OEM) perlu didukung (akan butuh unggah framework sebagai input, bukan jaringan)?
4. **Batas ukuran**: APK maksimum yang harus bisa dimodifikasi (bawaan 200 MB vs rencana 1 GB)? Menentukan RAM/tmpfs/disk/timeout; perlu diukur pada APK besar nyata.
5. **Unduhan hasil**: boleh diunduh langsung dari UI (sesi login saja, tanpa tautan publik) — atau juga perlu kolom hash/QR/`adb install` helper? Apakah *paket format asal* (XAPK/APKS) dibutuhkan atau cukup base/merged APK?
6. **Persetujuan**: tetap wajib setiap build (PRD keputusan #3)? Apakah ada mode "otomatis untuk build uji kecil"? (Mengubah model ancaman.)
7. **RAM VPS**: menambah `signer` + build di runner membawa total `mem_limit` ≈ 6,4 GB dari 8 GB; apakah VPS akan di-upgrade, atau runner/bench diturunkan, atau build diserialkan ketat?
8. **Anggaran AI**: siklus ubah→build→perbaiki memakan banyak putaran; naikkan `AI_SESSION_BUDGET_CREDITS` (default 1) / `AI_MAX_STEPS`? Model mana yang dipakai (smali butuh model kuat)?
9. **Cakupan v1**: hanya APK tunggal + base dari XAPK/APKS, atau juga memodifikasi semua split + tanda tangan ulang? `.aab` tetap analisis-saja (keputusan #1)?
10. **Retensi build**: `BUILD_KEEP=5`? Pembersihan otomatis build lama/ruang kerja `bench` (OP-03 sebelumnya "tidak dikerjakan")? Tampilkan `bench`+`builds` di halaman Penyimpanan?
11. **Kebijakan keamanan tambahan**: izinkan AI mengubah *apa saja* (termasuk menyuntik izin berbahaya/`debuggable`, menonaktifkan pinning) selama ada persetujuan manusia, atau perlu daftar larangan/peringatan otomatis di layar persetujuan (mis. sorot perubahan izin & `exported`)? Pernyataan wewenang perlu teks apa?
12. **Verifikasi & CI**: tidak ada build Docker di CI dan worker/runner tanpa tes — apakah boleh menambah job CI (build image `signer`/`runner`, `*-selftest`) atau cukup `make *-selftest` manual di VPS? Siapa yang menjalankan uji Docker (sandbox pengembangan tidak punya Docker)?

---

## 12. Celah konkret (checklist untuk fitur "AI modifikasi + build APK")

| # | Celah | Lokasi saat ini | Keadaan |
|---|---|---|---|
| G1 | Ruang kerja baseline = salinan apktool + diff dihitung sistem | `bench` `$WS` kosong; tak ada diff | tidak ada |
| G2 | Java + apktool di jalur build | hanya `runner` | runner tak melihat `bench` (volume & tes `test_shell_tool.py:131-135`) |
| G3 | `zipalign`, `apksigner`, keystore, layanan `signer` | — | tidak ditemukan |
| G4 | Job `build` di spool/runner/worker/web | `spool.TOOL_STAGES` hanya apktool/jadx/analyze | tidak ada |
| G5 | Model data & state machine build + persetujuan + audit | DB v4 | tidak ada |
| G6 | Penyimpanan artefak biner + unduhan `…package-archive` | `analysis_file` (CHECK kind, media teks untuk AI) | tidak cocok, perlu volume/tabel baru |
| G7 | Tool AI: `bench_diff`, `request_build`, `get_build_status` (+ flag, prompt, label UI, audit) | `ai/tools.py` | tidak ada; prompt & tes menyatakan sebaliknya |
| G8 | UI: tab Build, penampil diff (besar), persetujuan, status build live | templates | tidak ada |
| G9 | Penyimpanan/kuota/retensi untuk `bench` & `builds`; hapus analisis membersihkan `builds` | `storage.py`, `routes_apk._delete` | `bench` pun belum terlihat di Penyimpanan |
| G10 | Verifikasi hasil (`apksigner verify`, badging, `targetSdk` Android 14+) | — | tidak ada (aapt2 CLI tak ada; opsi: baca manifest via apktool/`manifest.py`) |
| G11 | Bukti Docker nyata (`bench-selftest`, `signer-selftest`, `apktool b` di runner) & tes worker/runner | — | belum terbukti / belum bertes |
| G12 | Dokumen: 00 §4/§7, 05, 07, 09 status, README, `.env.example`, `audit.md` | — | perlu diperbarui |

---

## 13. Lampiran: jalur file kunci (cheat-sheet)

- Tool & agent: `services/web/app/ai/{tools.py (TOOLS:927, schemas:1050, run_tool:1058, shell_run:870), agent.py (SYSTEM_PROMPT:32, rule D:109, SHELL_PROMPT_BLOCK:119, system_prompt:158, run_turn:247), chat.py (run_in_thread), config.py (AIConfig, load_ai_config)}`
- Spool/protokol: `services/rvcore/{spool.py:29-32 (TOOL_STAGES/JOB_ID_RE/STAGE_OUT_DIR), shellspool.py:34 (OP_RUN), :61 (build_run_request), :80 (parse_result), :123 (run_command)}`
- Runner: `services/runner/runner-daemon:{79 build_command, 254 validate_request, 272 run_job, 308 _run_tool}`; image `services/runner/Dockerfile`
- Worker: `services/worker/{tasks.py, pipeline.py:{56 Config, 170 _execute, 277 _stage_tool, 345 _run_job, 366 _wait_result}, worker.py}`; `Dockerfile:21-22` (COPY eksplisit)
- Bench: `services/bench/bench-daemon:{78 validate_run, 95 run_job, 129 sweep_orphan_workspaces}`, `bench/bench/{policy.py, executor.py, confined_exec.py, landlock.py}`
- Web: `services/web/app/{main.py:52-54, routes_apk.py:{347 _tab_context, 608 chat_send, 960 _delete}, routes_files.py, userfiles.py:{44, 176, 242}, storage.py:44, static/js/app.js:1121}`; `templates/_analysis_head.html`
- Data: `services/rvcore/{db.py:{153-186 v4, 188 SCHEMA_VERSION}, store.py:{106 audit}, paths.py}`
- Infra: `docker-compose.yml` (runner `:183`, bench `:222`, egress `:270`, volumes `:310`, secrets `:322`), `Makefile`, `.env.example`, `.github/workflows/ci.yml`, `.kiro/steering/testing.md`
- Dokumen kunci: `docs/prd/09-bundles-and-workbench.md` (Bagian B = rancangan build; "Status PR A/C/D" = apa yang sudah), `docs/prd/07-infra-security.md` (tabel ancaman), `audit.md` §10.10-10.12 (pelajaran terbaru)
