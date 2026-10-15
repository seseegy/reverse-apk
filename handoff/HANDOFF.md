# HANDOFF — fitur "AI memodifikasi & membangun APK" (reverse-apk)

> **Pembaca: agen AI baru yang tidak tahu apa-apa.** Baca file ini dari atas sampai bawah SEBELUM berbuat apa pun.
> Ditulis 15 Okt 2026 oleh agen sebelumnya karena kredit akun pemilik hampir habis dan akun akan diganti.
> Semua teks proyek, komentar, pesan, dan dokumen berbahasa **INDONESIA**. Jawab pemilik dalam Bahasa Indonesia, ringkas dan jujur.

Repo: `seseegy/reverse-apk` (GitHub). Pemilik: `seseegy`. Cabang ini (`handoff/ai-apk-build`) hanya berisi catatan; JANGAN di-merge ke `main`.

---

## 0. Cara mulai (urutan wajib)
1. `git fetch origin`. Kode kerja terkini ada di **`origin/feat/build-pipeline`** (HEAD `dc92b87`, 3 commit di atas `origin/main` `4302ca9`). Itu pekerjaan **Tahap 2b yang SETENGAH JALAN, belum ada PR**.
2. Baca bagian 1–5 file ini, lalu `handoff/docs/01-owner-decisions.md` (keputusan pemilik, MENGIKAT).
3. Verifikasi cepat (lihat §7) sebelum mengubah apa pun. Jangan percaya klaim di dokumen; ukur sendiri.
4. Tanyakan pemilik: "lanjut Tahap 2b dari FEAT D?" — jangan langsung meluncurkan pekerjaan besar tanpa konfirmasi (pemilik pernah keberatan karena memakai workflow untuk perubahan sepele).

## 1. Tujuan proyek & keputusan pemilik (ringkas; rincian di `docs/01-owner-decisions.md`)
- Aplikasi web analisis APK (FastAPI + worker + runner + bench + egress). Tambahan yang sedang dibangun: **AI dapat memodifikasi APK lalu membangun (build) dan menandatanganinya**, dengan **persetujuan manual pemilik di setiap build**.
- Tujuan penggunaan: **riset pribadi** di perangkat pemilik. Pemilik minta "wajib berfungsi 100%" — jujur: tidak bisa dijanjikan untuk aplikasi dengan anti-tamper/packer/Play Integrity/hash `.so`.
- Kunci tanda tangan: **satu keystore per instalasi**, dibuat `make init`, tidak pernah ditimpa. Ada HANYA di VPS pemilik (`secrets/signing_keystore.p12` + `signing_keystore_pass`). **Tidak ada di sandbox/Git.** Pemilik diingatkan mencadangkannya.
- Persetujuan manual **wajib** tiap build. AI TIDAK punya tool untuk menyetujui/menandatangani/mengunduh.
- Retensi `BUILD_KEEP=10` per analisis. Unduhan = **tombol di web saja** (login), tanpa tautan publik, tanpa skrip `adb`.
- APK **dan XAPK/APKS** harus berfungsi ("dinamis") — semua split ditandatangani ulang dengan kunci yang sama (Tahap 3).
- Shell AI aktif, jaringan AI terbuka ke semua host & port publik, tetapi **alamat privat/loopback/metadata/CGNAT tetap diblokir** di proxy `egress` (pemilik setuju). AI boleh mengubah apa saja (tanpa daftar larangan).
- Anggaran AI "tanpa batas" (`0`), `AI_MAX_STEPS` besar. Model: `AI_MODEL` bawaan, pemilik boleh pilih `AI_MODEL_PRO` per pesan.
- Batas upload APK naik ke **1 GB** (Tahap 6).
- VPS pemilik: **Docker Compose 5.6.0, RAM 8 GB, disk 100 GB, user host `deploy` (bukan uid 10001), TANPA JDK di host.** Landlock ABI v4 tersedia (`bench-selftest` lulus).

### Aturan kerja pemilik (mengikat)
- **Tahap 3, 4, 5, 6 masing-masing SATU paket/PR. JANGAN dipecah** tanpa bertanya. (Tahap 2 sudah dipecah 2a/2b atas inisiatif agen; itu satu-satunya pengecualian. 2b tinggal SATU paket.)
- Perubahan kecil & mekanis (mis. ganti satu angka bawaan) dikerjakan **langsung**, tanpa workflow. Workflow hanya untuk pekerjaan benar-benar besar/berisiko.
- Bug yang pemilik temukan saat menguji di VPS = **PR perbaikan terpisah**, bukan "tahap baru".
- Pemilik tidak suka pertanyaan berulang/berlebihan dan overhead. Jelaskan singkat, beri perintah VPS yang bisa ditempel, dan minta tempel hasilnya.
- Loop desain/review: maksimal 2 iterasi; bila desain masih `CHANGES_REQUESTED`, jadikan temuan sebagai **adendum mengikat** dan lanjut (jangan berhenti menunggu pemilik). Loop review kode akhir: maks 2 putaran lalu tanya pemilik bila masih ada temuan memblokir.

## 2. Status tahap (per 15 Okt 2026)
| Tahap | Isi | Status | PR |
|---|---|---|---|
| (awal) | Image `signer` (Build-Tools 37.0.0 dipin SHA-256), `signer-selftest`, `make tools-check` | **SELESAI, terbukti di VPS** | #42 |
| perbaikan | `apktool b` offline di runner: aapt2 terpasang, `/tmp` tetap `noexec` | **SELESAI, terbukti di VPS** | #43 |
| perbaikan | `aapt2` butuh `chmod` → tmpfs khusus `/opt/aapt-exec` (16m, exec) di runner | **SELESAI, terbukti di VPS** | #44 |
| perbaikan | `scripts/sample-apk/build.py` bersihkan pohon buatan kontainer | **SELESAI, terbukti di VPS** | #45 |
| **1** | Keystore `make init`, tabel `build` (migrasi v5), state machine persetujuan, `Layout.builds`, `BUILD_KEEP` | **SELESAI, `make init` terbukti di VPS** | #46 |
| **2a** | `signer-daemon` nyata + keystore (mode 644 di `secrets/` 700, via `docker-compose.keystore.yml`) + `signspool` + `make signer-verify` | **SELESAI, `signer-selftest` 27 OK & `signer-verify` 21 langkah OK di VPS** | #47 |
| config | `AI_SHELL_MAX_CALLS_PER_TURN` bawaan 40 → 200 | **SELESAI** | #48 |
| **2b** | Pipeline build ujung-ke-ujung TANPA AI/UI | **SETENGAH JALAN** — lihat §3 | belum ada PR; kode di `feat/build-pipeline` |
| 3 | XAPK/APKS split (semua split diproses & ditandatangani ulang, hasil format asal) | belum | — |
| 4 | Tool AI: `bench_diff`, `request_build`, `get_build_status` + pembaruan prompt | belum | — |
| 5 | UI: tab Build, diff, tombol Setujui, status live, tombol Unduh | belum | — |
| 6 | Batas 1 GB di semua tempat, egress dibuka luas, bawaan AI tanpa batas, job CI, titik pemeriksaan "lanjut?" | belum | — |

`origin/main` = `4302ca9` (PR #48 merge). Tes di `main` ±2071 lulus.

## 3. Tahap 2b — di mana persisnya
**Satu paket, satu PR, cabang `feat/build-pipeline`.** Brief asli ada di `docs/04-brief-tahap-2b.md`, desain di `docs/05`, rencana FEAT di `docs/07`, bukti di `docs/08`.

Alur yang dituju: APK sampel dianalisis → ruang kerja disalin (`bench/<aid>/project`) → diubah lewat shell bench → diff kanonik (hash) dihitung → build diajukan → **pemilik menyetujui (CLI)** → runner `apktool b` pada **snapshot** (hash dihitung ulang; beda = `workspace_changed`) → signer menandatangani dengan keystore pemilik → verifikasi → artefak tersimpan. Pembuktian akhir untuk pemilik: **`make verify-build`** (13 langkah, tabel OK/GAGAL).

### SELESAI & TERVERIFIKASI (3 commit, di-push ke `origin/feat/build-pipeline`)
Saya (agen sebelumnya) memverifikasi sendiri pada HEAD `dc92b87`: `pyflakes services tests` bersih; `pytest` = **2629 lulus, 27 dilewati, kode keluar 0**; pohon kerja bersih.
| FEAT | Commit | Isi |
|---|---|---|
| A | `28b2e0c` | `rvcore/treediff.py`: manifes/diff kanonik (hash streaming, `base` terakhir), salin pohon aman tanpa ikut symlink, batas per pohon; NB-1 (`RecursionError` di `store.create_build`) |
| B | `3f0f96f` | Op bench `init` & `diff` (`bench/workspace.py`, `shellspool.run_op`, bench-daemon), kontrak `$WS/project`; perbaikan `safe_rmtree` mode 000, status tak-hashable |
| C | `dc92b87` | Tahap `build` di runner (`runner/buildstage.py`, `rvcore/buildproto.py`), mount runner `bench:ro` + `builds` rw, **penutupan R3/R10 di signer** (kerja di volume privat `signwork`, `expect_sha256`, terbit tahan balapan), `fsutil.open_dir_chain/rmtree_at/scrub_paths`, `Layout.bench/signwork/project_dir/base_tree`, NB-3, warisan 2a |

Keputusan R3/R10 (penting): signer bekerja HANYA di `signwork` (tidak dipasang ke runner); membuka `unsigned.apk` sekali (`O_NOFOLLOW|O_NONBLOCK`, `S_ISREG`, `nlink==1`), menyalin+hash dari fd yang sama, menolak bila hash ≠ `expect_sha256` dari runner; menerbitkan lewat `.sign-signed.tmp` (`O_EXCL`) + `rename` atomik, lalu baca ulang. Sisa risiko jujur: runner terkompromi masih bisa mengubah `signed.apk` SETELAH terbit → tahap D menghitung ulang hash, **Tahap 5 unduhan wajib salin-lalu-hash**.

Mutasi: FEAT A–C 51+28+15 mutan, semua tertangkap (dibaca dari `docs/08`; saya TIDAK menjalankan ulang).

### BELUM DIKERJAKAN (urutan, semua di rencana `docs/07-rencana-tahap-2b.md`)
- **FEAT D** — worker `run_build` (`services/worker/builds.py`, `tasks.py`, `worker.py`, `Dockerfile` COPY, env `TIMEOUT_BUILD`/`TIMEOUT_SIGN`): claim → runner → signer → verifikasi → nama artefak dari sistem → `finish_build` → prune → pemulihan; heartbeat `signer:heartbeat`. Tes `tests/test_worker_builds.py`. (**Workflow terhenti persis di sini: sesi `feat-d-worker` baru membaca brief, 0 kode ditulis.**)
- **FEAT E** — web `app/builds.py` + CLI `app/buildctl.py` (analyze/init/shell/diff/request/approve/status/wait/cancel/artifact-info/delete), `jobs.enqueue_build`, `store.approve_build(via=cli)`, NB-2 (tolak analisis ulang/hapus saat build aktif), hapus `builds/`+`bench/` saat hapus analisis, mount web.
- **FEAT F** — tes invarian compose final (`tests/test_build_compose.py` sudah ada sebagian dari C), `.env.example`, dokumen (deploy.md, PRD 09, README, audit.md), keputusan FR-9.24/9.41 ditunda ke Tahap 5 (tanyakan pemilik di PR).
- **FEAT G** — `scripts/verify-build.sh` + `make verify-build` + `signer-selftest --check-apk`.
- Lalu: **sandbox-e2e** (semua daemon nyata sebagai proses, uid 10001, `unshare -m` bind ro, tanpa Docker), **mutations**, **final-review** (3 reviewer paralel: keamanan, isolasi, kebenaran; maks 2 putaran), **submit-pr**, **loop CI**, **bersih-bersih scratch**.
- Temuan desain mengikat: `docs/05-desain-tahap-2b.md` bagian "ADENDUM MENGIKAT" A-01…A-17 (F-01…F-17 di `docs/06`). Ringkas: hash streaming `base` terakhir; signer terikat `expect_sha256`; `signcheck` ikut rantai-dirfd; jejak waktu verify-build dari DB (`stage_log signing_mulai`) bukan polling; verify-build memakai `docker compose run --rm --no-deps -T runner` bukan `exec`; Redis sandbox = `fakeredis` (RQ nyata BELUM DIUJI); dst.

### Status workflow lama
Workflow `wf_53ca7b04967f5e64` **dijeda** di `feat-d-worker` pada akun lama. Jangan bergantung padanya; akun baru memulai workflow baru dari cabang ini. Cara paling hemat: luncurkan workflow baru yang MELANJUTKAN dari FEAT D (kasih path `handoff/docs/04…08` dan cabang `feat/build-pipeline`), bukan mengulang dari desain.

## 4. Yang SUDAH terbukti di VPS pemilik (Docker nyata) vs BELUM
**Terbukti** (hasil tempelan pemilik): `make runner-selftest` (semua OK termasuk `apktool b` offline & `/opt/aapt-exec`), `scripts/sample-apk/build.py` (APK 4068 B jadi), `make init` (keystore RSA 3072 berlaku sampai 2056, mode 600), `make signer-selftest` (27 OK), `make signer-verify` (21 langkah OK, v2/v3, sertifikat = pemilik, negatif lulus, sandi tak bocor), Compose 5.6.0 menerima opsi tmpfs & secret yang dipakai.
**BELUM terbukti di VPS:** semua isi 2b (FEAT A–C hanya diuji di sandbox: lihat `docs/08` "BELUM DIUJI"), `BIG_MB=1000 make signer-verify` (APK besar; memori vs `mem_limit 512m` belum diukur — **pemilik belum menjalankannya**), RQ/Redis nyata, antre runner, izin volume baru (`bench:ro`, `builds`, `signwork`), shell AI end-to-end (`AI_SHELL_ENABLED=1` belum tentu diisi di `.env` VPS), dan semua Tahap 3–6.

## 5. PELAJARAN KERAS (jangan diulang)
Empat bug nyata hanya muncul di Docker VPS dan lolos di sandbox: (1) tmpfs Docker = **noexec**; (2) `File.setExecutable` → `chmod` gagal di rootfs ro / non-pemilik (apktool memanggilnya tanpa cek); (3) berkas milik **uid 10001** di folder milik host tak bisa dihapus host; (4) kunci mode 600 milik uid host tak terbaca uid 10001 (Compose mengabaikan `uid/gid/mode` secret `file:`). Aturan: untuk setiap interaksi file/izin/uid/mount, **tiru kontainer di sandbox** (`setpriv --reuid=10001 --regid=10001 --clear-groups`, `unshare -m` + bind `ro`, tmpfs noexec/exec, berkas milik uid lain mode 600/644) dan **jangan simpulkan "jalan" dari skenario pemilik-sama**. Selalu beri daftar "DIBUKTIKAN di sandbox" vs "BELUM DIUJI (butuh Docker VPS)" + perintah VPS + gejala kegagalan.

## 6. Lingkungan sandbox (agen) — kebiasaan yang menjebak
- **Docker/Compose di sandbox RUSAK** (`conmon` hilang): `docker compose config` tak bisa. Uji Docker hanya di VPS pemilik.
- Python sistem 3.11 memberi kegagalan tak terkait. Pakai Python 3.12: `/root/.pyenv/versions/3.12.13/bin/python -m venv <dir>` lalu `pip install -r services/web/requirements.txt -r tests/requirements.txt pyflakes pyyaml`. (venv lama bisa hilang di sandbox baru; buat ulang.)
- `/tmp` **tidak bertahan** antar-perintah di sandbox; kerja di bawah `/projects/sandbox/` dan jalankan langkah dalam SATU perintah bash.
- `.agents/` ada di `.gitignore` (dokumen kerja agen; TIDAK ikut Git). Itu sebab catatan ini disalin ke cabang handoff.
- Tool `grep_search`: `includePattern` harus berbentuk `**/*.py` / `**/dir/*.py`; pola seperti `dir/**` sering tidak menemukan apa-apa.
- PR: **`gh api repos/seseegy/reverse-apk/pulls -f title=… -f body=… -f head=<cabang> -f base=main`** — JANGAN `gh pr create` (GraphQL gagal di sini). CI: `gh api repos/seseegy/reverse-apk/commits/<sha>/check-runs`. Jangan commit ke `main`; satu cabang per paket.
- Alat nyata untuk uji di sandbox: apktool 3.0.3 (jar SHA-256 `dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423`), aapt2 hasil ekstrak (`df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc`), Build-Tools 37.0.0 (zip SHA-256 `01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060`, `https://dl.google.com/android/repository/build-tools_r37_linux.zip`), JDK 21/25 via mise.
- Folder sisa di `/projects/sandbox/` (`scratch-t2a`, `scratch-review`, `scratch-2b`, `emu-run`, `ver`, `.venv-*`, `.sig-run`, `.fix-artifacts`, `pwnl`) adalah sampah workflow lama; berisi **kunci uji sementara** (bukan kunci pemilik). Pemilik belum menjawab apakah boleh dibersihkan — tanya dulu.

## 7. Verifikasi cepat (jalankan sebelum melanjutkan)
```bash
cd /projects/sandbox/reverse-apk
git fetch origin && git checkout feat/build-pipeline && git status --short   # harus bersih
git log --oneline origin/main..HEAD                                          # 3 commit: 28b2e0c 3f0f96f dc92b87
/root/.pyenv/versions/3.12.13/bin/python -m venv /projects/sandbox/.venv-new
/projects/sandbox/.venv-new/bin/pip install -q -r services/web/requirements.txt -r tests/requirements.txt pyflakes pyyaml
/projects/sandbox/.venv-new/bin/python -m pyflakes services tests && echo pyflakes-ok
/projects/sandbox/.venv-new/bin/python -m pytest -p no:cacheprovider -W ignore -o addopts="" -q 2>&1 | tail -3   # ±2629 passed, 27 skipped
```

## 8. Keputusan/pertanyaan yang MASIH menunggu pemilik
1. **Lanjutkan Tahap 2b dari FEAT D?** (disarankan; sisa pekerjaan besar = D, E, F, G + e2e + mutasi + review + PR).
2. `AI_SHELL_TIMEOUT` (60/120 s sekarang) — saran: 300 bawaan, 900 maksimal. Kuota ruang kerja bench per analisis (2 GB sekarang) — saran 10 GB. **Belum dijawab.** (Dikerjakan di Tahap 6 atau langsung bila pemilik minta.)
3. Bawaan lain yang belum diubah: `AI_MAX_OUTPUT_TOKENS=4096` (terlalu kecil untuk menulis smali besar), `AI_MAX_TOOL_CHARS=14000`, `AI_SHELL_MAX_OUTPUT_CHARS=12000`, `AI_MAX_STEPS=100`, anggaran harian/sesi 5/1 (0 = tanpa batas). Pemilik minta "tanpa batas"; konfirmasi angka lalu ubah (kecil → langsung).
4. **Perilaku saat AI mencapai batas giliran**: pemilik ingin AI **berhenti rapi, merangkum yang diketahui, lalu bertanya "mau lanjut?"** (bukan penghentian paksa). Saat ini `tools.py` ~baris 883 hanya melempar galat per panggilan. Belum dikerjakan (workflow `ai-checkpoint-continue` dibatalkan karena berlebihan). Tawarkan sebagai perubahan kecil terpisah.
5. FR-9.24 (verifikasi badging) & FR-9.41 (targetSdk Android 14+) ditunda ke Tahap 5 — tanyakan pemilik di PR 2b.
6. Boleh membersihkan folder `scratch-*` di sandbox? (lihat §6).
7. Pemilik belum menjalankan `BIG_MB=1000 make signer-verify` dan belum mengonfirmasi `AI_SHELL_ENABLED=1` di `.env` VPS; ingatkan.
8. Pastikan pemilik **mencadangkan** `secrets/signing_keystore.p12` + `signing_keystore_pass` di luar VPS.

## 9. Temuan non-blocking yang diwariskan (kerjakan bila menyentuh area itu)
- Tahap 1 review: `scripts/keystore.sh` — sinyal di antara dua `ln` meninggalkan berkas sandi yatim (aman: pindahkan lalu `make keystore`); pesan galat `ln` terlalu seragam; `make doctor` menelan kode 2 (keadaan satu-berkas).
- 2a review: TOCTOU alat (sudah ditutup di 2b FEAT C); `error_text` keystore tak disaring (ditutup di FEAT C); sandi di argv `grep` host (ditutup di FEAT C); tes `signcheck` tanpa batas waktu FIFO (ditutup di FEAT C).
- Tahap 1 store review: NB-2 `reset_for_retry` vs build aktif (**FEAT E**); NB-3 `_scrub_paths` path relatif (ditutup di FEAT C).

## 10. Prompt siap tempel untuk agen baru
> Kamu melanjutkan proyek `seseegy/reverse-apk`. Baca `handoff/HANDOFF.md` di cabang `origin/handoff/ai-apk-build` (`git fetch origin && git show origin/handoff/ai-apk-build:handoff/HANDOFF.md`), lalu dokumen di `handoff/docs/`. Kode kerja ada di `origin/feat/build-pipeline` (Tahap 2b setengah jalan; lanjutkan dari FEAT D). Verifikasi dulu dengan §7, jangan percaya klaim. Taati aturan kerja di §1. Setelah membaca, ringkas posisi kita dalam 5 baris dan tanya pemilik apakah boleh melanjutkan 2b dari FEAT D.
