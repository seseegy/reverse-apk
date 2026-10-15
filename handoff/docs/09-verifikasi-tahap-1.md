# verification.md — Tahap 1 (fondasi data & kunci) · cabang `feat/build-foundation` · iterasi 1

HEAD yang diverifikasi: `6e54175` (turunan `origin/main` 5ed8ec1). Semua keluaran di bawah NYATA, dijalankan di sandbox ini pada HEAD tersebut (venv `/projects/sandbox/.venv-t1`, Python 3.12.13; keytool JDK 21.0.2). Pemeriksa TIDAK perlu menjalankan ulang suite: baca diff + dokumen ini.
Perubahan iterasi ini (di atas dua commit bagian A dan B+C): tinjauan jahitan (tidak ada cacat jahitan kode ditemukan, §0; yang basi: dokumen), dokumen (PRD 09, deploy.md, README, audit.md 10.16), satu tes baru yang memperkuat penjaga `prune_builds` (ditemukan lewat mutasi, §5), dan verifikasi penuh.

## 0. Tinjauan jahitan antar bagian (`git diff origin/main...HEAD`: 12 berkas, tanpa biner/rahasia)
| Jahitan | Diperiksa | Hasil |
|---|---|---|
| `init.sh` ↔ `keystore.sh` | `init.sh` membuat `.env` dan `secrets/` (700) LEBIH DULU, baru memanggil `./scripts/keystore.sh create` (syarat: `.env` untuk membangun image, `secrets/` untuk direktori kerja); `set -e` → gagal keystore = init berhenti (gagal-tertutup), ulang aman. Peringatan cadangan hanya dicetak bila kedua berkas ada | OK; dijalankan nyata lewat `make init` di klon bersih (§7) |
| `keystore.sh` ↔ Makefile | target `keystore`, `keystore-info` ada, masuk `.PHONY` dan `make help`; `doctor` memanggil `keystore.sh status \|\| true` (stack lama tanpa keystore tetap OK; keadaan satu-berkas hanya peringatan) | OK (§7) |
| `keystore.sh` ↔ compose | nama image `reverse-apk-signer` = `name: reverse-apk` + layanan `signer` tanpa `image:` (pola Compose v2); build lewat `docker compose --profile build build signer` (profil sama dengan `make signer-selftest`). Compose TIDAK menyebut keystore | OK secara teks; nama image nyata BELUM DIUJI (butuh Docker) |
| compose ↔ `.env.example` ↔ kode | `BUILD_KEEP` ada di `.env.example` (dikomentari, 10), di `web` dan `worker` (`${BUILD_KEEP:-10}`), dibaca `store.build_keep()` (bawaan 10); tes penjaga OP-01 (`test_every_build_env_read_by_store_is_forwarded_by_compose`) | OK |
| dokumen ↔ perilaku | PRD 09 masih menulis `BUILD_KEEP (5)`, "keystore belum ada", "keputusan jenis kunci diperlukan"; README/deploy menyebut "tanpa keystore"/"belum ada keystore" | DIPERBAIKI di commit dokumen (kini 10; keystore ada tetapi belum dipasang ke layanan mana pun; RSA 3072) |

Tidak ada cacat kode lintas bagian yang perlu diperbaiki. Satu-satunya perbaikan non-dokumen: tes penjaga `prune_builds` yang lemah (§5, M6).

## 1. Baseline vs sekarang
| | baseline `origin/main` (baseline.md) | sekarang |
|---|---|---|
| pytest penuh | 1030 lulus, 2 dilewati | **1378 lulus, 2 dilewati** (+348 tes baru) |
| `python -m pyflakes services tests` | bersih | bersih |

Dua yang dilewati bukan milik kita: `tests/test_storage_clean.py:524` dan `:540` (butuh root+setpriv+Python≥3.12 di luar venv).
```
$ python -m pyflakes services tests
exit=0
$ python -m pytest        (pytest.ini: -q -p no:cacheprovider)
............                                                             [100%]
1378 passed, 2 skipped in 42.49s
$ bash -n (skrip shell yang diubah/baru + yang berdekatan)
OK bash -n scripts/keystore.sh
OK bash -n scripts/init.sh
OK bash -n scripts/envcheck.sh
OK bash -n scripts/tools-check.sh
OK bash -n scripts/bench-probe.sh
```
Rincian tes baru: `tests/test_build_store.py` 278 · `tests/test_keystore_script.py` 44 · `tests/test_build_migration.py` 8 · `tests/test_build_paths.py` 18 = 348. Tidak ada berkas tes lama yang diubah (`git diff --name-status origin/main...HEAD -- tests` hanya `A`).

## 2. Tes baru GAGAL di kode lama dan LULUS di kode baru
Worktree `git worktree add --detach /projects/sandbox/wt-old origin/main`, hanya 4 berkas tes baru disalin (tanpa kode produksi), dijalankan, lalu `git worktree remove --force` (worktree sudah dihapus; `git worktree list` hanya repo ini).
```
per berkas (kode LAMA):
test_build_store.py     : 275 failed, 3 passed
test_keystore_script.py :   7 failed, 3 passed, 34 errors
test_build_migration.py :   7 failed, 1 passed
test_build_paths.py     :  16 failed, 2 passed
gabungan                : 305 failed + 34 errors (= 339 gagal/error), 9 passed   [total 348]

yang LULUS di kode lama:
PASSED tests/test_build_store.py::test_no_generic_status_setter_exists
PASSED tests/test_build_store.py::test_ai_package_cannot_reach_lifecycle_functions
PASSED tests/test_build_store.py::test_compose_gains_no_volume_or_secret_and_stays_clean_for_signing_guard
PASSED tests/test_keystore_script.py::test_gitignore_ignores_secrets
PASSED tests/test_keystore_script.py::test_compose_does_not_reference_keystore_yet
PASSED tests/test_keystore_script.py::test_compose_is_still_valid_yaml
PASSED tests/test_build_migration.py::test_newer_schema_is_refused
PASSED tests/test_build_paths.py::test_existing_paths_unchanged
PASSED tests/test_build_paths.py::test_compose_has_no_builds_volume_yet
305 failed, 9 passed, 34 errors in 2.33s
```
Kode BARU: seluruh 348 lulus (§1). **Sembilan yang lulus di kode lama TIDAK membuktikan fitur baru; itu disengaja** — penjaga negatif yang mengunci perilaku lama agar tidak rusak oleh fitur baru: `.gitignore` mengabaikan `secrets/`; compose belum merujuk keystore / belum punya volume `builds` / tidak menambah volume atau secret; YAML compose tetap valid; tidak ada setter status generik; paket `ai` tidak memanggil fungsi siklus hidup build; skema lebih baru dari yang dikenal ditolak (`RuntimeError`); `work_dir/files_dir/upload_path` tidak berubah. Bahwa penjaga-penjaga itu tidak hampa: mutasi §5 (M1–M12 menyerang kode/DB nyata) dan mutasi keystore (§4).

## 3. (i) Transisi state machine terhadap tabel — tidak ada jalur persetujuan palsu
Tabel `BUILD_TRANSITIONS` (dicetak dari kode, bukan disalin):
```
awaiting_approval  -> ['approved', 'cancelled', 'rejected']
approved           -> ['cancelled', 'failed', 'queued']
queued             -> ['building', 'cancelled', 'failed']
building           -> ['cancelled', 'failed', 'signing']
signing            -> ['cancelled', 'done', 'failed']
done               -> []
rejected           -> []
failed             -> []
cancelled          -> []
```
Diagram: `awaiting_approval →(approve_build)→ approved →(queue_build)→ queued →(claim_build)→ building →(mark_signing)→ signing →(finish_build)→ done`; cabang: `reject_build` (hanya dari awaiting), `fail_build`/`recover_stuck_builds` (approved/queued/building/signing → failed), batal: awaiting/approved/queued langsung `cancelled`, building/signing hanya menandai `cancel_requested=1` lalu pelaksana memanggil `cancel_build`. Final (`done/rejected/failed/cancelled`) tanpa jalan keluar; `awaiting_approval → failed` TIDAK sah.

Peta tes → transisi (semua di `tests/test_build_store.py`):
| Tes | Apa yang dibuktikan | Kasus |
|---|---|---|
| `test_action_table_covers_exactly_the_documented_transitions` | himpunan pasangan (dari,ke) yang bisa dicapai 10 fungsi == `BUILD_TRANSITIONS` persis (tak ada transisi gelap/yatim) | 1 |
| `test_every_function_from_every_status` | matriks 10 fungsi × 9 status: yang sah pindah ke tujuan yang benar; yang tidak sah → `BuildStateError`/`False`/`noop`/`[]` dan baris + `audit_log` TIDAK berubah | 90 |
| `test_jumps_and_returns_from_final_are_refused` | lompatan (awaiting→queue/claim/finish/fail, approved→claim/mark_signing, building→finish/queue, …) dan kembali dari final (done/failed/cancelled/rejected → approve/queue/fail/…) ditolak | 20 |
| `test_only_approve_build_targets_approved` (AST) | dari semua fungsi store hanya `approve_build` yang memanggil `_build_cas` dengan tujuan `B_APPROVED`; hanya `finish_build`→`B_DONE`, hanya `claim_build`→`B_BUILDING`; UPDATE mentah hanya `_build_cas` + `cancel_requested` | 1 |
| `test_no_generic_status_setter_exists` | tidak ada nama publik `set_build_status/force/update_build/override` | 1 |
| `test_ai_package_cannot_reach_lifecycle_functions` | `services/web/app/ai/**` tidak menyebut fungsi siklus hidup (AI tidak bisa menyetujui) | 1 |
| `test_approve_with_different_diff_is_refused`, `test_approve_rejects_malformed_diff`, `test_race_approve_with_stale_diff_never_wins_against_good_diff` | persetujuan butuh `diff_sha256` identik dengan yang diajukan (di dalam WHERE CAS); diff basi tak pernah menang balapan | 1 + 8 + 1 |
| `test_approve_requires_a_known_statement`, `test_approval_statement_v1_is_pinned`, `test_approve_records_evidence` | pernyataan wewenang versi/hash harus dikenal; hash golden dipin; `approved_at` + hash + versi tercatat | 1 + 1 + 1 |
| `test_double_approve_is_refused_and_keeps_first_approval`, `test_race_approve_build_has_exactly_one_winner`, `test_race_claim_build_has_exactly_one_winner`, `test_race_cancel_vs_claim_is_consistent`, `test_race_two_creates_for_the_same_analysis` | CAS/balapan dengan 2 thread + 2 koneksi SQLite nyata (25 putaran/skenario): tepat satu pemenang | 5 |
| `test_database_refuses_approved_without_evidence`, `test_database_refuses_done_without_verification`, `test_database_refuses_malformed_rows`, `test_database_allows_one_active_and_many_final_only` | pertahanan berlapis di DB: status ≥ approved wajib bukti persetujuan; `done` wajib `verify_ok=1` + keluaran + `cert_sha256`; satu build aktif per analisis | 1 + 1 + 13 + 1 |
| `test_finish_refuses_unverified_signature`, `test_claim_refuses_when_cancel_was_requested`, `test_cancel_request_blocks_progress_but_not_failure`, `test_cancel_build_needs_a_request` | `done` hanya dengan `verify_ok` tepat 1; batal-diminta menghalangi claim/signing/finish tetapi tidak menghalangi gagal | 9 + 1 + 1 + 2 |
| `test_audit_records_each_action_without_content`, `test_audit_failure_rolls_the_transition_back` | audit satu transaksi dengan transisi (status berubah ⇔ audit tercatat), tanpa isi bebas | 2 |

**Jujur:** tanpa trigger SQLite, `INSERT/UPDATE` SQL mentah dengan hash karangan tetap lolos CHECK (CHECK hanya mewajibkan bukti ADA, bukan benar). Jalur kode lazim tertutup; AI tidak punya akses DB maupun fungsi ini (tes penjaga membaca paket `ai`).

## 4. (ii) Keystore tidak mungkin tertimpa dan kata sandi tidak bocor
Dijalankan ULANG pada HEAD ini: `.agents/tasks/build-foundation/emu/evidence-1-4.sh` (skrip nyata + keytool JDK 21.0.2 lokal via `KEYTOOL_CMD`; keluaran di bawah, argv dipotong 330 karakter).
```
##### (1) bash -n
OK  scripts/keystore.sh
OK  scripts/init.sh
OK  scripts/envcheck.sh
OK  scripts/tools-check.sh
OK  scripts/bench-probe.sh

##### (6a) versi keytool lokal & dukungan :file
keytool 21.0.2
keytool 25.0.2
 -keypass <arg>          key password
 -signerkeypass <arg>    signer key password
 -storepass <arg>        keystore password

##### (2) create NYATA (keytool lokal 21.0.2) ke direktori sementara
• membuat keystore PKCS12 (RSA 3072, SHA256withRSA, berlaku 10950 hari)…
Generating 3,072 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,950 days
	for: CN=reverse-apk 2b8d686d
✓ keystore dibuat:
  Berkas     : /tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk 2b8d686d
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 16:59:49 UTC 2026 until: Fri Oct 06 16:59:49 UTC 2056 (sisa 10950 hari)
  SHA-256 (keytool)   : BA:30:31:6E:E8:E1:88:0C:DA:CE:E0:E0:56:F2:EE:F9:5F:7D:DA:AE:EF:68:65:F9:35:EC:1E:39:EF:08:E4:E2
  SHA-256 (heks kecil): ba30316ee8e1880cdacee0e056f2eef95f7ddaaeef6865f935ec1e39ef08e4e2

⚠  CADANGKAN SEKARANG di tempat aman (di luar server): secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass
   Keduanya dibutuhkan bersama. Kehilangan salah satunya = kunci BARU: aplikasi yang sudah terpasang dengan kunci lama tidak
   bisa diperbarui (Android menolak update berbeda tanda tangan; harus dicopot, data aplikasi hilang) dan tanda tangan semua build lama berubah.
   Kunci ini untuk riset pribadi (bukan kunci rilis). Sidik jari: make keystore-info
kode=0
total 8
drwx------. 2 root root   80 Oct 14 16:59 .
drwx------. 3 root root   60 Oct 14 16:59 ..
-rw-------. 1 root root 3442 Oct 14 16:59 signing_keystore.p12
-rw-------. 1 root root   64 Oct 14 16:59 signing_keystore_pass
700 root:root /tmp/tmp.w4M9fUxIsQ/secrets
600 root:root /tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore.p12
600 root:root /tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore_pass
--- keytool -list -v ringkas
Keystore type: PKCS12
Alias name: reverse-apk
Entry type: PrivateKeyEntry
Owner: CN=reverse-apk 2b8d686d
Valid from: Wed Oct 14 16:59:49 UTC 2026 until: Fri Oct 06 16:59:49 UTC 2056
	 SHA256: BA:30:31:6E:E8:E1:88:0C:DA:CE:E0:E0:56:F2:EE:F9:5F:7D:DA:AE:EF:68:65:F9:35:EC:1E:39:EF:08:E4:E2
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key

##### (3a) idempoten
✓ keystore sudah ada (/tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore.p12 + signing_keystore_pass); tidak diubah.
  Pastikan sudah DICADANGKAN di tempat aman (kehilangan = kunci baru). Sidik jari: make keystore-info
kode=0
/tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore.p12: OK
/tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore_pass: OK
mtime sama

##### info
  Berkas     : /tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk 2b8d686d
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 16:59:49 UTC 2026 until: Fri Oct 06 16:59:49 UTC 2056 (sisa 10949 hari)
  SHA-256 (keytool)   : BA:30:31:6E:E8:E1:88:0C:DA:CE:E0:E0:56:F2:EE:F9:5F:7D:DA:AE:EF:68:65:F9:35:EC:1E:39:EF:08:E4:E2
  SHA-256 (heks kecil): ba30316ee8e1880cdacee0e056f2eef95f7ddaaeef6865f935ec1e39ef08e4e2
kode=0

##### (3b) satu berkas saja -> gagal
✗ HANYA signing_keystore_pass yang ada di /tmp/tmp.w4M9fUxIsQ/secrets (pasangannya hilang). Tidak ada yang diubah atau dihapus. Pulihkan pasangannya dari cadangan; jika memang ingin kunci BARU, pindahkan berkas itu ke tempat lain secara manual lalu ulangi.
kode=2
signing_keystore_pass
/tmp/tmp.w4M9fUxIsQ/secrets/signing_keystore_pass: OK
--- arah sebaliknya (hanya p12)
✗ HANYA signing_keystore.p12 yang ada di /projects/sandbox/reverse-apk/.agents/tasks/build-foundation/.kscopy (pasangannya hilang). Tidak ada yang diubah atau dihapus. Pulihkan pasangannya dari cadangan; jika memang ingin kunci BARU, pindahkan berkas itu ke tempat lain secara manual lalu ulangi.
kode=2
signing_keystore.p12
/projects/sandbox/reverse-apk/.agents/tasks/build-foundation/.kscopy/signing_keystore.p12: OK

##### (4) sandi tidak bocor ke argv/environ (pembungkus perekam + keytool asli)
kode=0
baris log: 3; kemunculan sandi di log argv/env: 0; di keluaran skrip: 0
contoh ARGV terekam:
ARGV: -J-Duser.language=en -J-Duser.country=US -genkeypair -keystore /tmp/tmp.UtGy6FAGuO/secrets/.keystore-work.X2H5HY/ks.p12 -storetype PKCS12 -alias reverse-apk -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 10950 -dname CN=reverse-apk cdd5ff3f -storepass:file /tmp/tmp.UtGy6FAGuO/secret
ARGV: -J-Duser.language=en -J-Duser.country=US -list -v -keystore /tmp/tmp.UtGy6FAGuO/secrets/.keystore-work.X2H5HY/ks.p12 -storetype PKCS12 -storepass:file /tmp/tmp.UtGy6FAGuO/secrets/.keystore-work.X2H5HY/pass
ARGV: -J-Duser.language=en -J-Duser.country=US -list -v -keystore /tmp/tmp.UtGy6FAGuO/secrets/signing_keystore.p12 -storetype PKCS12 -storepass:file /tmp/tmp.UtGy6FAGuO/secrets/signing_keystore_pass
kontrol negatif (hitung dari argv palsu yang membocorkan): 1
```
Ringkasan bukti: alias `reverse-apk`, `3072-bit RSA`, `SHA256withRSA`, valid 14 Okt 2026 → 6 Okt 2056, SHA-256 dicetak dua format; mode `600` kedua berkas dan `700` direktori; `create` kedua kode 0 dengan sha256 + mtime identik (idempoten); hanya satu berkas → kode 2 dan isi tidak berubah (dua arah); kemunculan kata sandi di argv/environ keytool = **0** (kontrol negatif: argv palsu yang sengaja membocorkan = 1, jadi pencari memang bisa menemukan), di keluaran skrip = 0.

Mutasi keystore (dari notes-keystore.md; dasar hijau dicek tiap kali; TIDAK dijalankan ulang di iterasi ini karena `scripts/` tidak berubah sejak commit 8777845 — `git diff 8777845 HEAD --stat -- scripts/` kosong): M7 `ln` sandi→`cp -f` tertangkap; M7b `ln` p12→`cp -f` tertangkap (setelah tes balapan pembungkus `ln` ditambah; pertama kali LOLOS); M8 hapus `chmod 600` (4 tes); M9 sandi lewat argv `-storepass "$(cat …)"` (9 gagal + 8 error); M10 hapus `trap` (8); M11 mount seluruh `secrets/` rw (4).
Peta tes (`tests/test_keystore_script.py`, 44 tes; 6 butuh JDK asli dan dilewati bersih tanpa keytool — di sini JDK ada sehingga semuanya jalan):
- tidak menimpa: `test_second_run_changes_nothing`, `test_only_one_file_fails_without_touching_anything`, `test_not_a_regular_file_is_refused` (symlink/direktori), `test_race_existing_password_created_midway_is_not_overwritten`, `test_race_during_publication_never_overwrites_winner[sandi|p12]`, `test_parallel_creates_yield_exactly_one_consistent_pair`, `test_real_second_create_keeps_hashes_and_single_file_fails`;
- sandi tidak bocor: `test_password_never_appears_in_argv_environ_or_output`, `test_script_text_never_traces_or_exports_password`, `test_docker_mode_run_arguments_are_confined`, `test_docker_mode_does_not_see_other_secrets`, `test_docker_mode_info_mounts_read_only_only`;
- gagal-tertutup: `test_keytool_failure_leaves_no_files`, `test_failed_run_can_be_repeated_successfully`, `test_interrupted_run_cleans_work_dir`;
- keytool nyata: `test_real_pkcs12_is_valid`, `test_real_wrong_password_is_rejected`, `test_real_validity_is_at_least_30_years`, `test_real_dn_and_fingerprint_match_independent_computation`, `test_real_files_have_strict_modes_and_password_format`.

## 5. (iii) Migrasi v4→v5 dengan data, dan mutasi store
DB v4 dibuat dari 4 migrasi ASLI (`rvdb._MIGRATIONS[:4]`), diisi di SEMUA tabel v1–v4, lalu `rvdb.migrate`:
```
$ pytest tests/test_build_migration.py -v -o addopts=""
tests/test_build_migration.py::test_schema_version_is_5 PASSED
tests/test_build_migration.py::test_v4_database_with_real_data_migrates_intact PASSED
tests/test_build_migration.py::test_migration_is_idempotent PASSED
tests/test_build_migration.py::test_fresh_database_equals_stepwise_migrated_schema PASSED
tests/test_build_migration.py::test_build_table_structure PASSED
tests/test_build_migration.py::test_newer_schema_is_refused PASSED
tests/test_build_migration.py::test_v5_follows_migration_string_rules PASSED
tests/test_build_migration.py::test_failed_migration_is_atomic PASSED
========================= 8 passed, 1 warning in 0.05s =========================

--- demonstrasi langsung (DB v4 berisi data -> migrate -> v5):
sebelum: user_version = 4 {'ai_call': 2, 'analysis': 3, 'analysis_file': 2, 'analysis_log': 1, 'analysis_stage': 4, 'apk': 2, 'artifact': 1, 'audit_log': 1, 'chat_message': 2, 'chat_session': 1, 'finding': 1, 'message_file': 2}
sesudah: user_version = 5 {'ai_call': 2, 'analysis': 3, 'analysis_file': 2, 'analysis_log': 1, 'analysis_stage': 4, 'apk': 2, 'artifact': 1, 'audit_log': 1, 'build': 0, 'chat_message': 2, 'chat_session': 1, 'finding': 1, 'message_file': 2}
data lama persis sama (semua baris, semua tabel v1-v4): True
integrity_check: ok | foreign_key_check: []
kolom build: 26 | indeks build: ['build_one_open_per_analysis', 'build_status', 'build_analysis']
```
Tes juga menguji: idempoten (migrate berulang tidak mengubah apa pun), DB baru == DB hasil migrasi bertahap (`sqlite_master` identik), atomik (kegagalan di tengah → `user_version` tetap 4 dan tidak ada tabel setengah jadi), skema lebih baru ditolak, string migrasi mengikuti aturan `_split_statements`, hapus APK meng-cascade ke build (`PRAGMA foreign_keys=ON` dipakai `rvcore.db.connect`).

Mutasi store/DB/paths (skrip sementara di luar repo; dasar HIJAU dicek dulu: 304 lulus; tiap mutasi diterapkan lalu dipulihkan; dijalankan terhadap `test_build_store/migration/paths`):
```
DASAR (tanpa mutasi): 304 passed in 1.47s []
TERTANGKAP | M1 approve_build: buang perbandingan diff (jadi if False) | 1 failed, 303 passed in 1.46s | contoh: test_approve_with_different_diff_is_refused
TERTANGKAP | M2 approve_build: buang diff dari WHERE CAS + perbandingan | 2 failed, 302 passed in 1.43s | contoh: test_approve_with_different_diff_is_refused, test_race_approve_with_stale_diff_never_wins_against_good_diff
TERTANGKAP | M3 claim_build: buang cancel_requested = 0 | 1 failed, 303 passed in 1.48s | contoh: test_claim_refuses_when_cancel_was_requested
TERTANGKAP | M4 finish_build: terima verify_ok != 1 | 3 failed, 301 passed in 1.45s | contoh: test_finish_refuses_unverified_signature[0], test_finish_refuses_unverified_signature[2], test_finish_refuses_unverified_signature[-1]
TERTANGKAP | M5 _build_cas: hapus syarat status asal (AND status IN) | 80 failed, 224 passed in 1.41s | contoh: test_every_function_from_every_status[awaiting_approval-claim], test_every_function_from_every_status[awaiting_approval-fail], test_every_
TERTANGKAP | M6 prune_builds: sertakan build aktif | 2 failed, 302 passed in 1.48s | contoh: test_prune_never_returns_an_active_build_even_when_older_than_final_ones[queued], test_prune_never_returns_an_active_build_even_when_older_than_final_ones[bu
TERTANGKAP | M7 db.py: hapus ON DELETE CASCADE pada build.analysis_id | 3 failed, 301 passed in 1.49s | contoh: test_deleting_the_analysis_removes_its_builds, test_v4_database_with_real_data_migrates_intact, test_build_table_structure
TERTANGKAP | M8 paths.build_dir: pakai int() (terima string/float) | 10 failed, 294 passed in 1.51s | contoh: test_only_positive_int_is_accepted[0], test_only_positive_int_is_accepted[-1], test_only_positive_int_is_accepted[1_0]
TERTANGKAP | M9 BUILD_TRANSITIONS: awaiting_approval boleh langsung ke queued | 1 failed, 303 passed in 1.51s | contoh: test_action_table_covers_exactly_the_documented_transitions
TERTANGKAP | M10 approve_build: buang pemeriksaan hash pernyataan wewenang | 1 failed, 303 passed in 1.49s | contoh: test_approve_requires_a_known_statement
TERTANGKAP | M11 db.py: CHECK done memakai verify_ok = 1 tanpa COALESCE (NULL lolos) | 1 failed, 303 passed in 1.47s | contoh: test_database_refuses_done_without_verification
TERTANGKAP | M12 db.py: hapus indeks unik build aktif | 2 failed, 302 passed in 1.47s | contoh: test_database_allows_one_active_and_many_final_only, test_build_table_structure
PULIH (tanpa mutasi): 304 passed in 1.48s []
```
Temuan: **M6 LOLOS pada 299 tes pertama** (lewat API, build aktif selalu yang terbaru, jadi `prune_builds` yang keliru menyertakannya tetap tak terlihat). Diperbaiki dengan tes baru `test_prune_never_returns_an_active_build_even_when_older_than_final_ones` (baris aktif lebih tua lewat SQL mentah); kini M6 tertangkap (baris di atas). Kode produksi dipulihkan setelah tiap mutasi (`git status` bersih).

## 6. Compose dan isolasi
```
PyYAML 6.0.3 - YAML valid, layanan: ['bench', 'caddy', 'egress', 'redis', 'runner', 'signer', 'web', 'worker']
perbedaan struktural vs origin/main:
   ('+ ditambah', "/services/web/environment/BUILD_KEEP = '${BUILD_KEEP:-10}'")
   ('+ ditambah', "/services/worker/environment/BUILD_KEEP = '${BUILD_KEEP:-10}'")
top-level volumes sama: True | secrets sama: True
git diff origin/main...HEAD -- docker-compose.yml (hanya baris tambahan):
+      # --- Build APK: jumlah build selesai yang disimpan per analisis (klem 1-100)
+      BUILD_KEEP: ${BUILD_KEEP:-10}      (web)
+      BUILD_KEEP: ${BUILD_KEEP:-10}      (worker)
$ pytest tests/test_signer_toolchain.py tests/test_runner_aapt2.py tests/test_shell_tool.py   (tidak diubah/dilonggarkan: git diff tests/ hanya berkas baru)
115 passed in 3.42s
```
PyYAML tidak ada di venv proyek/CI (sengaja: tes memakainya hanya bila tersedia); bukti YAML di atas memakai venv terpisah `/projects/sandbox/.venv-yaml` (PyYAML 6.0.3). `docker compose config` TIDAK dijalankan (tidak ada Docker). Tidak ada service baru, volume baru, secret baru, atau perubahan isolasi; blok web/worker tidak memuat kata keystore/signer (penjaga `test_signer_toolchain` lulus).

## 7. Jahitan nyata: `make init` di klon bersih (tanpa Docker; `KEYTOOL_CMD` menggantikan `docker run`)
```
$ make init   (KEYTOOL_CMD=keytool lokal menggantikan docker run; repo bersih hasil git clone)
• .env dibuat dari .env.example
• SECRET_KEY dibuat
• REDIS_PASSWORD dibuat
• membuat keystore PKCS12 (RSA 3072, SHA256withRSA, berlaku 10950 hari)…
Generating 3,072 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,950 days
	for: CN=reverse-apk c9b09c0d
✓ keystore dibuat:
  Berkas     : /projects/sandbox/seam/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk c9b09c0d
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 17:01:04 UTC 2026 until: Fri Oct 06 17:01:04 UTC 2056 (sisa 10949 hari)
  SHA-256 (keytool)   : 82:56:0A:4F:E6:EC:A6:11:80:01:BF:DA:C6:39:31:6B:69:79:95:02:CF:C6:83:32:CF:50:C6:83:22:FF:3A:78
  SHA-256 (heks kecil): 82560a4fe6eca6118001bfdac639316b69799502cfc68332cf50c68322ff3a78

⚠  CADANGKAN SEKARANG di tempat aman (di luar server): secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass
   Keduanya dibutuhkan bersama. Kehilangan salah satunya = kunci BARU: aplikasi yang sudah terpasang dengan kunci lama tidak
   bisa diperbarui (Android menolak update berbeda tanda tangan; harus dicopot, data aplikasi hilang) dan tanda tangan semua build lama berubah.
   Kunci ini untuk riset pribadi (bukan kunci rilis). Sidik jari: make keystore-info
Selesai. Langkah berikut: make password
⚠ INGAT: cadangkan secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass di tempat aman. Kehilangan = kunci baru (aplikasi terpasang tidak bisa diperbarui).
exit=0

$ ls -la secrets/
total 12
drwx------.  2 root root   90 Oct 14 17:01 .
drwxr-xr-x. 13 root root 4096 Oct 14 17:01 ..
-rw-r--r--.  1 root root    0 Oct 14 17:01 admin_password_hash
-rw-------.  1 root root 3442 Oct 14 17:01 signing_keystore.p12
-rw-------.  1 root root   64 Oct 14 17:01 signing_keystore_pass

$ make init  (kedua)
✓ keystore sudah ada (/projects/sandbox/seam/secrets/signing_keystore.p12 + signing_keystore_pass); tidak diubah.
  Pastikan sudah DICADANGKAN di tempat aman (kehilangan = kunci baru). Sidik jari: make keystore-info
Selesai. Langkah berikut: make password
⚠ INGAT: cadangkan secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass di tempat aman. Kehilangan = kunci baru (aplikasi terpasang tidak bisa diperbarui).
secrets/signing_keystore.p12: OK
secrets/signing_keystore_pass: OK

$ make keystore-info
  Berkas     : /projects/sandbox/seam/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk c9b09c0d
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 17:01:04 UTC 2026 until: Fri Oct 06 17:01:04 UTC 2056 (sisa 10949 hari)
  SHA-256 (keytool)   : 82:56:0A:4F:E6:EC:A6:11:80:01:BF:DA:C6:39:31:6B:69:79:95:02:CF:C6:83:32:CF:50:C6:83:22:FF:3A:78
  SHA-256 (heks kecil): 82560a4fe6eca6118001bfdac639316b69799502cfc68332cf50c68322ff3a78

$ ./scripts/keystore.sh status
✓ keystore penanda tangan ada (mode 600/600); pastikan sudah dicadangkan

$ make help | grep keystore
  [32minit            [0m Buat .env (rahasia acak), folder secrets/, dan keystore penanda tangan (butuh Docker; membangun image signer bila perlu)
  [32mkeystore        [0m Buat keystore penanda tangan (secrets/signing_keystore.p12) bila belum ada; aman diulang, TIDAK PERNAH menimpa
  [32mkeystore-info   [0m Cetak sidik jari SHA-256, DN, masa berlaku, algoritma keystore (tanpa kata sandi)
  [32msigner-selftest [0m Uji signer: zipalign + apksigner (keystore sementara -> sign -> verify, tes negatif) + bukti isolasi dari dalam kontainer (profil `build`, tidak ikut `make up`)

$ git status --short (di klon, setelah init)
(kosong = secrets/ dan .env tidak terlacak)
```
Yang TIDAK terbukti oleh langkah ini: jalur `docker run` (lihat §9).

## 8. Emulasi kontainer (uid non-root, rootfs read-only, tmpfs /tmp, HOME=/tmp, tanpa jaringan)
Dijalankan ULANG pada HEAD ini: `emu/run-emu.sh` (docker PALSU `emu/fake-docker` yang menjalankan keytool di dalam `unshare -Urmn` + chroot rootfs tmpfs dengan usr/JDK di-bind READ-ONLY, `/tmp` tmpfs `noexec,nosuid,nodev`, `/out` satu-satunya bind rw, uid:gid 10001:10001, semua capability 0, NoNewPrivs=1; keluaran dipotong 300 karakter per baris).
```
##### (a) create lewat fake-docker (kontainer ditiru) sebagai uid 10001; secrets/ BELUM ada (dibuat oleh user host, bukan Docker)
• membuat keystore PKCS12 (RSA 3072, SHA256withRSA, berlaku 10950 hari)…
Generating 3,072 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,950 days
	for: CN=reverse-apk 174f42b4
✓ keystore dibuat:
  Berkas     : /projects/sandbox/emu-run/host/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk 174f42b4
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 16:59:49 UTC 2026 until: Fri Oct 06 16:59:49 UTC 2056 (sisa 10950 hari)
  SHA-256 (keytool)   : 68:D6:94:11:40:E1:93:BA:7C:02:F6:03:8F:29:A1:C5:06:11:76:53:86:7F:41:1C:47:BF:65:46:B5:57:8E:3F
  SHA-256 (heks kecil): 68d6941140e193ba7c02f6038f29a1c506117653867f411c47bf6546b5578e3f

⚠  CADANGKAN SEKARANG di tempat aman (di luar server): secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass
   Keduanya dibutuhkan bersama. Kehilangan salah satunya = kunci BARU: aplikasi yang sudah terpasang dengan kunci lama tidak
   bisa diperbarui (Android menolak update berbeda tanda tangan; harus dicopot, data aplikasi hilang) dan tanda tangan semua build lama berubah.
   Kunci ini untuk riset pribadi (bukan kunci rilis). Sidik jari: make keystore-info
kode=0
total 8
drwx------. 2 10001 10001   63 Oct 14 16:59 .
drwxr-xr-x. 3 10001 10001   21 Oct 14 16:59 ..
-rw-------. 1 10001 10001 3442 Oct 14 16:59 signing_keystore.p12
-rw-------. 1 10001 10001   64 Oct 14 16:59 signing_keystore_pass
700 10001:10001 /projects/sandbox/emu-run/host/secrets
600 10001:10001 /projects/sandbox/emu-run/host/secrets/signing_keystore.p12
600 10001:10001 /projects/sandbox/emu-run/host/secrets/signing_keystore_pass
--- bukti sandi tidak ada di argv docker:
tidak ada (0 kemunculan)
--- argv docker run (baris pertama):
run --rm --pull never --network none --read-only --tmpfs /tmp:rw\,size=64m\,nosuid --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 --memory 512m --user 10001:10001 -e HOME=/tmp --workdir /tmp -v /projects/sandbox/emu-run/host/secrets/.keystore-work.V4SebG:/out --entrypoint keyt

##### (a2) info lewat fake-docker (hanya mount :ro)
  Berkas     : /projects/sandbox/emu-run/host/secrets/signing_keystore.p12  (mode 600)
  Tipe       : PKCS12
  Alias      : reverse-apk
  DN (Owner) : CN=reverse-apk 174f42b4
  Algoritma  : 3072-bit RSA key, tanda tangan SHA256withRSA
  Berlaku    : Wed Oct 14 16:59:49 UTC 2026 until: Fri Oct 06 16:59:49 UTC 2056 (sisa 10949 hari)
  SHA-256 (keytool)   : 68:D6:94:11:40:E1:93:BA:7C:02:F6:03:8F:29:A1:C5:06:11:76:53:86:7F:41:1C:47:BF:65:46:B5:57:8E:3F
  SHA-256 (heks kecil): 68d6941140e193ba7c02f6038f29a1c506117653867f411c47bf6546b5578e3f
kode=0

##### (a3) create kedua (idempoten) tidak memanggil docker run lagi
kode=0 ; docker run sebelum=3 sesudah=3

##### (c-f) probe di dalam 'kontainer' (flag identik dengan docker run milik keystore.sh, mode create)
uid:gid=10001:10001  HOME=/tmp  PWD=/tmp
CapInh:	0000000000000000 CapPrm:	0000000000000000 CapEff:	0000000000000000 CapBnd:	0000000000000000 CapAmb:	0000000000000000 
NoNewPrivs:	1
--- (e) mountinfo /, /tmp, /out:
/ ro,relatime
/out rw,nosuid,nodev,relatime
/tmp rw,nosuid,nodev,noexec,relatime
/usr ro,nosuid,nodev,relatime
--- tulis rootfs (harus ditolak):
touch: cannot touch '/usr/x': Read-only file system
touch: cannot touch '/newdir': Read-only file system
--- /tmp dapat ditulis, exec ditolak:
tulis /tmp OK
bash: line 4: /tmp/e: Permission denied
--- /out (satu-satunya bind rw):
tulis /out OK
total 0
-rw-r--r--. 1 10001 10001 0 Oct 14 16:59 ok
--- (d) jaringan:
bash: connect: Network is unreachable
    lo
--- (f) HOME=/tmp: keytool tanpa direktori home khusus:
keytool 21.0.2
total 4
drwxrwxrwt.  2 10001 10001  80 Oct 14 16:59 .
drwxr-xr-x. 12 10001 10001 240 Oct 14 16:59 ..
-rwxr-xr-x.  1 10001 10001  21 Oct 14 16:59 e
-rw-r--r--.  1 10001 10001   0 Oct 14 16:59 ok

##### (c) kontrol negatif B: info memasang berkas :ro; menulis harus ditolak
mount /in:
/inner_container ro,nosuid,nodev,relatime
/in/signing_keystore.p12 ro,nosuid,nodev,relatime
/in/signing_keystore_pass ro,nosuid,nodev,relatime
bash: line 1: /in/signing_keystore.p12: Read-only file system
rm: cannot remove '/in/signing_keystore_pass': Read-only file system
signing_keystore.p12
signing_keystore_pass

##### (b) kontrol negatif A: direktori kerja milik ROOT (host user = root, seperti secrets/ yang dibuat Docker sebagai root) tetapi kontainer berjalan sebagai 10001
Cannot find file: /out/pass
✗ keytool gagal membuat keystore. Tidak ada berkas yang dibuat di /projects/sandbox/emu-run/hostroot/secrets.
kode=1
isi hostroot/secrets (harus kosong):
--- kontrol positif untuk (b): sama, tetapi user kontainer = pemilik (root, EMU_MODE=root tanpa FORCE_USER) => harus berhasil
✓ keystore dibuat:
kode=0
600 0:0 /projects/sandbox/emu-run/hostroot/secrets/signing_keystore.p12
600 0:0 /projects/sandbox/emu-run/hostroot/secrets/signing_keystore_pass
```
Yang ditunjukkan: skrip jalan sebagai uid 10001 (bukan root) dan membuat `secrets/` SENDIRI (bukan Docker) → berkas milik user host, mode 600/700; argv `docker run` memuat `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 -e HOME=/tmp`, hanya direktori kerja sementara di-mount rw (bukan `secrets/`), 0 kemunculan kata sandi di argv docker; di dalam "kontainer": `/` ro, tulis ke rootfs ditolak, `/tmp` dapat ditulis tetapi exec ditolak, jaringan "Network is unreachable", `keytool` berjalan dengan `HOME=/tmp`; `info` hanya mount `:ro` (tulis/hapus ditolak); `create` kedua tidak memanggil `docker run` lagi (3 → 3); KONTROL NEGATIF: direktori kerja milik root + kontainer 10001 → keytool gagal, kode 1 dan `secrets` kosong; KONTROL POSITIF (pemilik = user kontainer) → berhasil.

## 9. Daftar eksplisit: DIBUKTIKAN di sandbox vs BELUM DIUJI (butuh Docker VPS)
**DIBUKTIKAN di sandbox:**
- Seluruh suite hijau (1378 lulus / 2 dilewati), pyflakes bersih, `bash -n` OK; 348 tes baru gagal/error di kode lama (339) dan lulus di kode baru; 12 mutasi store/DB/paths tertangkap (satu tes lemah ditemukan dan diperkuat), 6 mutasi keystore tertangkap (iterasi sebelumnya).
- State machine terhadap tabel: matriks 90 kasus + 20 lompatan + AST + balapan dengan koneksi SQLite nyata; DB menolak `approved/done` tanpa bukti; satu build aktif per analisis ditegakkan indeks unik.
- Migrasi v4→v5 dengan data nyata: semua tabel lama utuh, `integrity_check` ok, idempoten, atomik, cascade.
- Keystore dengan keytool JDK 21.0.2 ASLI: RSA 3072/SHA256withRSA/PKCS12/alias/validitas 30 tahun, SHA-256, mode 600/700, idempoten, tidak menimpa (termasuk balapan), satu berkas → kode 2, sandi tidak di argv/environ/keluaran, sandi salah ditolak, `make init`/`make keystore-info`/`make help` lewat Makefile asli di klon bersih.
- Argumen `docker run` yang disusun skrip (diperiksa lewat docker palsu): flag isolasi, hanya direktori kerja sementara rw, `info` hanya `:ro`, `--pull never`, `--entrypoint keytool`.
- Emulasi kontainer non-root/ro/tmpfs/tanpa jaringan seperti §8, termasuk kegagalan bersih bila direktori milik root.
- Compose: YAML valid, diff hanya `BUILD_KEEP` di web+worker, isolasi tidak dilonggarkan (115 tes isolasi lulus), tidak ada rahasia/biner di diff, `git ls-files | grep -Ei 'secrets|\.p12|keystore_pass'` kosong.

**BELUM DIUJI (butuh Docker di VPS; daemon sandbox rusak: `conmon` hilang):**
- Jalur `docker run ... --entrypoint keytool reverse-apk-signer ...` sungguhan: image `signer` (JRE 21 Debian trixie, `ENV HOME=/tmp/home` yang di-override `-e HOME=/tmp`, perilaku `--entrypoint` + `CMD`); keytool di image adalah JRE trixie, BUKAN JDK 21.0.2 sandbox.
- `make init` penuh: pembangunan otomatis image (`docker compose --profile build build signer`; butuh jaringan sekali) dan nama image hasilnya (`reverse-apk-signer` dari `name: reverse-apk` + layanan `signer`; berbeda bila `COMPOSE_PROJECT_NAME` di-override → `SIGNER_IMAGE=`), `docker compose config`.
- Izin tulis ke direktori kerja `secrets/.keystore-work.*` oleh proses non-root DI DALAM kontainer nyata; Docker rootless / `userns-remap` (uid hasil bisa bukan pemilik di host), SELinux (`:Z`), semantik bind mount Docker.
- Kunci belum pernah dipakai menandatangani (apksigner/jarsigner): "dipakai apksigner" diuji di Tahap 2.
- Balapan store lintas PROSES di volume Docker nyata (diuji hanya 2 thread/2 koneksi).

**Perintah di VPS:** `git pull --ff-only && make init && make keystore-info && ls -la secrets/`
**Hasil yang diharapkan:** pertama kali — baris `• image reverse-apk-signer belum ada: membangun…` (bila image belum pernah dibangun) lalu `✓ keystore dibuat:` dengan `Tipe: PKCS12`, `Alias: reverse-apk`, `3072-bit RSA key, tanda tangan SHA256withRSA`, `Berlaku ... until ... 2056 (sisa ~10950 hari)`, SHA-256 dua format, blok `⚠ CADANGKAN SEKARANG`, `Selesai.`, `⚠ INGAT`; `make keystore-info` mencetak sidik jari yang sama; `ls -la secrets/` menunjukkan `signing_keystore.p12` (±3,4 KB) dan `signing_keystore_pass` (64 byte) `-rw-------` milik user deploy, `secrets/` `drwx------`, `admin_password_hash` tetap ada. Ulangi `make init`: `✓ keystore sudah ada … tidak diubah`, sidik jari SAMA.
**Gejala kegagalan yang mungkin:** (a) `Tidak bisa membuat direktori kerja di .../secrets` → `secrets/` milik root (mis. dibuat Docker dulu): `sudo chown -R "$(id -u):$(id -g)" secrets`; (b) `Cannot find file: /out/pass` + `keytool gagal membuat keystore` → kontainer (uid host) tidak bisa membaca/menulis direktori kerja (izin/SELinux/userns-remap); kegagalan bersih, tidak ada berkas tersisa; (c) `Image reverse-apk-signer belum ada dan .env belum ada` → jalankan `make init`; (d) `Gagal membangun image signer` → jaringan/apt/hash Build-Tools (`docker compose --profile build build signer` untuk galat penuh); (e) `Image ... tidak ditemukan setelah build` → `COMPOSE_PROJECT_NAME` di-override: `SIGNER_IMAGE=<nama> make keystore`; (f) galat JVM terkait HOME/`/tmp/hsperfdata_*` untuk uid tanpa entri `/etc/passwd` (hanya terbukti di tiruan). Tidak ada kegagalan yang meninggalkan keystore setengah jadi (verifikasi `-list -v` SEBELUM publikasi; p12 dipublikasikan TERAKHIR). Kirim keluaran bila gagal.
**Celah emulasi sandbox vs kontainer Docker nyata:** (1) rootfs tiruan = tmpfs + bind ro, bukan overlayfs image; `/proc`, `/dev` dan daftar direktori berbeda; (2) cgroup (`--memory 512m`, `--pids-limit 128`) tidak ditiru; seccomp/AppArmor/SELinux Docker tidak ada; (3) uid dipetakan lewat user namespace bersarang, bukan `setuid` oleh daemon root; pembuatan titik mount/sumber `-v` otomatis oleh Docker (sebagai root) tidak ditiru — skrip memang membuat sumbernya lebih dulu sebagai user host; (4) JDK 21.0.2 host vs JRE 21 Debian trixie di image, libc berbeda; (5) tidak ada jaringan nyata untuk build image; (6) `--pull never` / `--entrypoint` / urutan opsi hanya diperiksa lewat docker palsu yang menolak bendera tak dikenal (exit 97), bukan parser Docker.

## 10. Kebersihan repo
```
$ git ls-files | grep -Ei 'secrets|\.p12|keystore_pass'      -> (kosong), exit 1
$ git status --short                                        -> (bersih)  [folder .agents/ diabaikan git]
$ git diff origin/main...HEAD | grep -E '^Binary|GIT binary|BEGIN (RSA|PRIVATE|CERT)'  -> (kosong)
$ git diff --name-status origin/main...HEAD
M	.env.example
M	Makefile
M	README.md
M	audit.md
M	docker-compose.yml
M	docs/deploy.md
M	docs/prd/09-bundles-and-workbench.md
M	scripts/init.sh
A	scripts/keystore.sh
M	services/rvcore/db.py
M	services/rvcore/paths.py
M	services/rvcore/store.py
A	tests/test_build_migration.py
A	tests/test_build_paths.py
A	tests/test_build_store.py
A	tests/test_keystore_script.py
$ git log --oneline origin/main..HEAD
6e54175 docs: status Tahap 1 (skema build, state machine, keystore) di PRD 09, deploy.md, README, audit.md 10.16; test: prune tidak menyebut build aktif yang lebih tua dari build final (mutasi M6 lolos sebelumnya)
ff81484 feat: tabel build (migrasi v5) + state machine persetujuan manual, Layout.builds, env BUILD_KEEP
8777845 feat: keystore penanda tangan dibuat make init lewat keytool di image signer (idempoten, tidak menimpa, sandi lewat berkas)
```
Satu-satunya string heks 64 karakter di diff adalah hash golden pernyataan wewenang (`8b96c9b8…`), bukan rahasia. Tidak ada berkas rahasia/biner. Tidak ada push; tidak ada commit ke `main`.
