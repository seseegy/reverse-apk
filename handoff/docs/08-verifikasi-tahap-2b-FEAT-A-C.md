# Verifikasi Tahap 2b

Dokumen ini diisi per FEAT. Semua perintah dijalankan di `/projects/sandbox/reverse-apk` (cabang `feat/build-pipeline`) dengan `PY=/projects/sandbox/.venv-t2b/bin/python` (Python 3.12.13).
Docker/Compose RUSAK di sandbox (conmon hilang), jadi tidak ada klaim tentang kontainer; yang diklaim hanya yang diukur di bawah.

---

## FEAT A — `rvcore/treediff.py` (+ NB-1 di `store.create_build`)

### Berkas yang berubah
| Berkas | Isi |
|---|---|
| `services/rvcore/treediff.py` (baru, stdlib saja) | `Limits`, `TreeLimitError`, `compute_diff`, `copy_tree_safe`, `manifest_hash`, `DiffResult.summary()`, `CopyStats` |
| `tests/test_treediff.py` (baru, 103 tes) | properti, pembanding independen, batas, entri khusus, balapan, uid 10001, bind `ro`, tmpfs `noexec`, Dockerfile |
| `services/rvcore/store.py` | `create_build` juga menangkap `RecursionError` (NB-1), satu baris |
| `tests/test_build_store.py` | satu tes baru: struktur 100.000 tingkat → `BuildInputError` |

Tidak disentuh (di luar lingkup FEAT A): `fsutil.py` (`open_dir_chain`/`rmtree_at`/`scrub_paths`), `paths.py` (`Layout.bench/signwork/project_dir/base_tree`, `MAX_PROTO_ID`), dan NB-3 (`_clean_text` path relatif). Itu ada di plan.md A.1/A.2/A.4 tetapi tidak di lingkup FEAT A yang diberikan; FEAT berikutnya yang butuh harus mengerjakannya.

### Keputusan yang diambil (dan alasannya)
- **Payload hash** persis `{"v":2,"e":[...],"base":"<hex64>"}` (separator rapat, `ensure_ascii=True`), `base` TERAKHIR (adendum A-01), dihitung streaming satu lintasan; diuji sama byte dengan `json.dumps` penuh atas dict berurutan.
- **Kunci banding** = tuple byte per komponen (`os.fsencode`), bukan string jalur; `res/values/x` mendahului `res/values-v21/y` (F-02).
- **Entri dihitung** = setiap nama yang ditemui `scandir`, termasuk yang diabaikan (symlink/FIFO/`build`/`dist` akar): pohon dengan jutaan symlink tetap dibatasi. Batas berlaku PER POHON (A-07).
- **Direktori kosong** = `scandir` tidak mengembalikan apa pun; direktori yang isinya habis difilter tidak dicatat dan tidak dibuat saat salin (A-16) → hash pohon hidup == hash snapshot.
- **`build`/`dist` di akar** diabaikan menurut NAMA (berkas atau direktori) di kedua pohon dan di salinan; di kedalaman lain tidak.
- **Gagal-tertutup**: berkas/direktori yang tak terbaca (EACCES/EPERM) → `TreeLimitError('unreadable')` dengan jalur RELATIF; akar tak ada / symlink → `unreadable` tanpa jalur absolut di pesan.
- **Ringkasan**: `DiffResult.summary()` mengembalikan `{v, counts, bytes, kinds, lines, skipped, top, truncated}` (kedalaman 4) dan memotong `top` 40→20→10→5→2→1→0 sampai `json.dumps(sort_keys=True, ensure_ascii=False)` ≤ 7000 karakter (`store.BUILD_SUMMARY_MAX` = 8192 MENOLAK, tidak memotong). Jalur ditampilkan diganti `?` untuk karakter tak tercetak, pengendali arah, dan surrogate sisa (nama non-UTF-8 membuat sqlite menolak teks).
- **+/− baris** perkiraan (selisih multiset baris, ≤ 300 berkas teks, ≤ 256 KiB per sisi), di luar hash. `lines.skipped_files` = berkas berubah yang barisnya tidak dihitung (biner, besar, melewati 300, atau tak terbaca).
- **Mode salin**: direktori 0755, berkas 0644/0755 menurut bit x, dengan `fchmod` eksplisit (tidak bergantung umask). mtime tidak dipertahankan.
- **Rekursi**: pejalan rekursif (kedalaman ≤ 64 bawaan); `RecursionError` apa pun ditangkap di pembungkus publik → `TreeLimitError('too_deep')`.
- **Pemuatan di image**: semua Dockerfile pemakai rvcore (`bench`, `runner`, `signer`, `web`, `worker`) memakai `COPY rvcore ./rvcore` (seluruh paket, bukan daftar berkas) dan `services/.dockerignore` tidak mengecualikan `.py`; jadi `treediff.py` ikut otomatis, tidak ada daftar COPY yang perlu ditambah. `egress` tidak memakai rvcore. Dijaga `test_every_image_that_uses_rvcore_copies_the_whole_package` dan `test_module_is_stdlib_only_and_loads_without_site_packages` (impor di `python -S`).

### Perintah dan keluaran
```
$ $PY -m pyflakes services tests ; echo $?
0
$ $PY -m pytest            # penuh
2175 passed, 14 skipped, 1 warning in 143.26s      # baseline 2071 passed, 14 skipped  → +104 (103 treediff + 1 store)
$ $PY -m pytest tests/test_treediff.py
103 passed, 1 warning in 1.92s
```
Tes uid 10001 / bind ro / tmpfs noexec BENAR-BENAR berjalan di sandbox ini (bukan dilewati): `-k "uid10001 or loads or every_image" -v` → 6 passed.

### Bukti "gagal di kode lama, lulus di kode baru" (dua jenis dipisah)
Kode lama = `treediff.py` dipindahkan dan `store.py` di-`git stash` (`evidence/FEAT-A-lama.txt`, `FEAT-A-baru.txt`; folder `.agents/` diabaikan git).

| Jenis | Tes | Di kode lama | Di kode baru |
|---|---|---|---|
| (i) modul baru gagal impor | `tests/test_treediff.py` (103 tes) | `ImportError: cannot import name 'treediff' from 'rvcore'` (galat koleksi) — hanya bukti keberadaan | 103 passed |
| (ii) perilaku atas berkas lama | `test_build_store.py::test_create_rejects_summary_nested_too_deep_without_recursion_error` | `RecursionError: maximum recursion depth exceeded while encoding a JSON object` lolos dari `store.create_build` | passed → `BuildInputError`, tidak ada baris build |

Jujurnya: modul murni baru tidak punya "perilaku lama" untuk dibandingkan; satu-satunya bukti jenis (ii) FEAT A adalah NB-1.

### Mutan cepat atas `treediff.py` (pemeriksaan tes; daftar mutasi resmi ada di langkah workflow `mutations`)
Tiap mutan diterapkan pada berkas nyata, `tests/test_treediff.py` dijalankan, lalu berkas dipulihkan (`cmp` dengan salinan asli = sama). Semua TERTANGKAP:

| Mutan | Tes yang gagal |
|---|---|
| bit x diabaikan (`x = 0`) | `test_matches_independent_oracle…` |
| hapus `O_NONBLOCK` dari FILE_FLAGS | `test_fifo_named_x_does_not_hang_and_swapped_in_fifo_or_symlink_is_skipped` |
| hapus `O_NOFOLLOW` dari FILE_FLAGS | idem (symlink yang ditukar) |
| hapus `O_NOFOLLOW` dari DIR_FLAGS | `test_symlinked_dir_contents_are_not_read…` |
| `base` dipindah ke depan/dibuang dari payload (A-01) | `test_matches_independent_oracle…` |
| tanpa `sorted(names)` | `test_matches_independent_oracle…` |
| penggabung membandingkan string jalur, bukan kunci komponen-byte (dua titik banding) | `test_matches_independent_oracle…` |
| `ROOT_IGNORE = ()` | `test_directory_empty_means_scandir_empty…` |
| direktori kosong tidak dicatat / semua direktori dicatat (A-16) | `test_matches_independent_oracle…` |
| hash tanpa isi (`h.update` dihapus) | `test_matches_independent_oracle…` |
| `RecursionError` tak ditangkap | `test_recursion_error_is_converted_not_leaked` |
| `fchmod` berkas dihapus (bergantung umask) | `test_copy_modes_are_deterministic…` |
| batas entri dimatikan | `test_entry_limit_counts_every_name_and_is_per_tree` |
| `ELOOP/ENOTDIR` pada dir yang ditukar tidak ditangani | `test_dir_swapped_for_symlink_between_stat_and_open_is_not_followed` |
| pra-cek ukuran berkas dimatikan (berkas sparse 2 GiB dibaca) | `test_total_and_per_file_byte_limits` (setelah tes diperketat dengan `_read_chunk` yang dilarang dipanggil; versi pertama tes LOLOS mutan ini, jadi diperketat) |

### Cara meniru kontainer (dan apa yang BELUM ditiru)
- uid 10001 NYATA: `setpriv --reuid=10001 --regid=10001 --clear-groups env -i … <python dasar>` (interpreter dasar pyenv butuh `LD_LIBRARY_PATH` karena RUNPATH-nya di `/root`); pohon uji milik root (mode 644/755, FIFO, symlink, `build/`), tujuan salinan milik 10001.
- Non-pemilik: berkas root mode 600 dan direktori root mode 700 dibaca 10001 → `unreadable` (gagal-tertutup, jalur relatif, tanpa jalur absolut); tujuan salinan di folder root 755 → `PermissionError` dan tidak ada yang tercipta; berkas hasil salin milik 10001 dengan mode 0644/0755.
- `unshare -m`: pohon sumber di bind `ro` (tulis → EROFS, diperiksa), salinan ke tmpfs `noexec,nosuid` (mode `1777`); hash langsung == hash snapshot == hash yang dihitung root.
- Balapan: `os.stat` disuntik agar berkas diganti FIFO / symlink dan direktori diganti symlink TEPAT setelah `stat` dan sebelum `open` → dilewati dan dihitung, tidak menggantung (`within(5)` via SIGALRM), tidak mengikuti symlink; tidak ada fd bocor (`/proc/self/fd` sama sebelum/sesudah, termasuk saat `on_tick` membatalkan).

### Celah emulasi (JUJUR)
- Bukan kontainer: tanpa cgroup (memori 1g bench/3g runner tidak berlaku), tanpa seccomp/`cap_drop`, tanpa `read_only` rootfs; Landlock bench tidak dipakai di FEAT A (belum ada bench-daemon op).
- Python 3.12.13 pyenv sandbox, bukan python di image; filesystem tmp sandbox (overlay/ext4-like), bukan volume Docker; `O_NONBLOCK`/`fstat` FIFO teruji, tetapi perilaku FUSE/overlayfs VPS belum.
- Pohon besar nyata (600.000 entri / 3 GiB) TIDAK diuji karena lambat dan memenuhi disk: batas diuji lewat `Limits` kecil; kecepatan pejalan atas pohon apktool nyata dan penggunaan memori belum diukur (diukur di langkah sandbox-e2e dengan apktool nyata).
- Jam: batas `TICK_SECONDS` diuji dengan jam palsu, bukan 5 dtk nyata di bawah beban.

### BELUM DIUJI (butuh Docker VPS)
- `docker compose --profile build build` memakai `COPY rvcore ./rvcore` (dibaca dari Dockerfile + tes teks; build image tidak dijalankan).
- Perilaku `treediff` di dalam bench (1g RAM, Landlock) dan runner (bind `bench:ro`) — tergantung FEAT B/C.


---

## FEAT B — op bench `init` dan `diff` (shellspool, bench-daemon, workspace, selftest, policy)

### Berkas yang berubah
| Berkas | Isi |
|---|---|
| `services/bench/bench/workspace.py` (baru, stdlib + `rvcore.treediff`) | `op_init` / `op_diff`: logika murni, jalur dari int saja, `copy_tree_safe` + `compute_diff` |
| `services/bench/bench-daemon` | `validate_op`, `run_op`; `run_job` mengarahkan `init`/`diff`; op lain tetap `refused "operasi tidak dikenal"`; `validate_run` (op `run`) TIDAK diubah |
| `services/bench/bench/policy.py` | `project_dir()` / `base_tree()` (int murni 1..999 999 999); `rules_for` TIDAK berubah |
| `services/bench/bench-selftest` | 8 pemeriksaan baru (bagian 3a): init, init tak menimpa, diff kosong, tulis `$WS/project` terkurung, tulis baseline ditolak, diff 1A+1M, baseline utuh, tanpa `/data/builds` |
| `services/rvcore/shellspool.py` | `OP_INIT/OP_DIFF`, `build_init_request/build_diff_request`, `parse_init_result/parse_diff_result`, `run_op` (inti tunggu bersama `run_command` lewat `_submit_and_wait`), `read_result(parser=)` lewat `read_small` (A-13) |
| `services/rvcore/paths.py` | `MAX_PROTO_ID = 999_999_999` dan `check_proto_id()` (hanya ini dari rencana A.1 yang dibutuhkan B; `Layout.bench/project_dir/base_tree` TIDAK ditambahkan: jalur dihitung bench di `policy`) |
| `services/rvcore/fsutil.py` | perbaikan `safe_rmtree` untuk direktori mode 000 (lihat "Temuan di luar lingkup" di bawah) |
| `tests/test_bench_workspace.py` (baru, 138 tes) | protokol, logika, daemon, uid 10001, bind `ro`, tmpfs `noexec`, daemon NYATA, statis |
| `tests/test_shell_bench.py` (+3 tes) | policy `$WS/project`, Landlock nyata menulis `$WS/project` |

### Keputusan (dan alasannya)
- **Kontrak `$WS`**: `$WS` tetap `bench/<aid>` (shell_run tidak berubah). **Pohon yang dibangun dan di-diff adalah `$WS/project`**; berkas lain di `$WS` bebas dan diabaikan. Sebelum `init`, `project/` tidak ada dan `diff` → `refused code=belum_init`. Landlock: `rules_for` hanya punya `Rule($WS, RW)`; `project/` ada di bawahnya, jadi sudah boleh ditulis (dibuktikan dengan kernel nyata, bukan dari asumsi; baseline `work/<aid>/apktool` tetap RO).
- **Semantik `force`** (dipilih): tanpa `force`, `project` yang sudah ada (direktori, symlink, berkas) → `ok created=false reason=exists`, NOL perubahan (pesan menegaskan isinya tidak dibandingkan dengan baseline). `force=true` → salin ke `.project.tmp` DULU (galat → `project` lama utuh), baru hapus `project` lama tanpa mengikuti symlink, lalu `rename` (`reason=reset`). `force` bertipe `bool` murni (string `"true"`/`1` → `refused`) dan hanya dibangun oleh `build_init_request`; tes statis menjamin tidak ada kode di `web/app/ai` yang memanggilnya. Pemanggil sah satu-satunya nanti: `buildctl init --force` (FEAT E).
- **Kuota**: salinan dibatasi ¾ kuota (ukuran isi); sesudah salin, `executor.tree_bytes` (blok disk, ukuran yang dipakai kuota `run`) ≤ 90% kuota atau `project` dibatalkan dan `refused code=kuota` → `init` yang sukses tidak membuat perintah shell pertama ditolak kuota. Pada `force`, `project` lama tidak dihitung dua kali. `statvfs(ws)` bebas ≥ ukuran baseline + 64 MiB (A-15), kalau tidak `refused kuota` tanpa `.project.tmp`.
- **Hasil**: `parse_init_result`/`parse_diff_result` (pola `parse_result`): bidang tak dikenal dibuang, tipe/rentang dipaksa, `top` ≤ 40 dan `path` disaring (kontrol/bidi/surrogate → `?`), `status=ok` tanpa `diff_sha256` heksa-64 yang sah → `failed`. Ditambah `code` (huruf kecil/`_` ≤ 40) agar CLI bisa mencetak `kode=belum_init` dsb. Batas 1 MB hasil dan baca-berbatas dipertahankan.
- Op baru TIDAK dikurung Landlock (daemon sendiri membaca baseline `work` ro dan menulis `bench/<aid>`; semua pembacaan lewat `treediff`: tanpa ikut symlink, FIFO tak menggantung). Tidak ada `builds` di volume bench (dijaga tes statis + selftest).
- Tenggat op: `OP_MAX_TIMEOUT = 600` dtk (bukan 120 dtk perintah shell); `pickup_timeout` klien op = 120 dtk (bench bisa sedang menjalankan perintah AI).

### Temuan di luar lingkup yang ikut diperbaiki (kecil, dengan tes)
1. `shellspool.parse_result({"status": []})` melempar `TypeError: unhashable type: 'list'` (bench terkompromi bisa membuat `run_command` web melempar) → `_status()` memakai `isinstance` dulu. Dipakai juga oleh parser baru.
2. `fsutil.safe_rmtree` pada direktori mode 000 → `TypeError: open() missing required argument 'flags'` (handler memanggil `func(path)` padahal `func` = `os.open(nama, flags, dir_fd=)`). AI (uid 10001, tak terkurung terhadap `chmod` di `$WS`) bisa membuat `init --force` tak bisa menghapus `project`. Perbaikan: untuk `os.open/scandir/listdir` ulangi `shutil.rmtree` setelah chmod, dengan himpunan `tried` agar tak rekursi tak berujung bila chmod gagal (bukan pemilik). Dipakai juga penyapu yatim dan hapus-analisis web.
3. `paths.SHA256_RE` (`^…$`) cocok sebelum `\n` akhir: `"a"*64 + "\n"` lolos. TIDAK diubah (dipakai di banyak tempat); parser baru memakai `fullmatch`. Dicatat untuk FEAT C/D/E: validator `diff_sha256` di runner/web memakai `fullmatch`.

### Perintah dan keluaran
```
$ $PY -m pyflakes services tests ; echo $?
0
$ $PY -m pytest
2316 passed, 14 skipped in 148.86s      # sebelum FEAT B: 2175 passed → +141 (138 test_bench_workspace + 3 test_shell_bench)
$ $PY -m pytest tests/test_bench_workspace.py tests/test_shell_bench.py     # sebagai uid 10001 (setpriv, non-root seperti CI): 9 dilewati bersih (tes yang butuh root), sisanya hijau
```

### Daemon NYATA sebagai proses (uid 10001, Landlock ABI v2) — DIBUKTIKAN
`tests/test_bench_workspace.py::test_real_daemon_process_runs_init_diff_and_a_confined_shell_that_writes_ws_project` menjalankan `bench-daemon` SUNGGUHAN lewat `setpriv --reuid=10001` (di dalam `unshare -m` supaya interpreter pyenv bisa dimuat uid 10001 tanpa `LD_LIBRARY_PATH`, karena `executor` memakai env bersih), data milik root (baseline 644/755), spool 777, `bench/` milik 10001. Urutan yang dibuktikan, lewat klien `shellspool` (peran web):
`run_op(init)` → `created=true`; `diff` kosong; `init` ulang → `exists`; `run_command` (Landlock nyata) `sed -i` + `echo > $WS/project/assets/baru.txt` + percobaan menulis `$WORK/apktool/hack.txt` (ditolak, tidak ada berkas); `diff` → tepat `{added:1, modified:1}` dengan `top` = `A assets/baru.txt`, `M res/values/strings.xml`; `init` tanpa force tidak menimpa; `init force` → `reset` dan penanda hilang; `diff` kembali kosong; log daemon tanpa `Traceback`. Tes kedua menjatuhkan permintaan MENTAH ke spool (id string/bool/10^9, `force` string/1, op `hapus`, traversal) → semua `refused`, daemon tetap hidup melayani.
`bench-selftest` sebagai uid 10001 di sandbox (bagian 3a baru): 8 OK. Tiga GAGAL yang tersisa murni lingkungan sandbox (internet terjangkau dari sandbox: "jaringan terisolasi", "jaringan dari perintah AI ditolak", "DNS publik"); bukan bagian FEAT B dan benar-benar harus lulus di Docker VPS.

### Bukti "gagal di kode lama, lulus di kode baru" (dua jenis dipisah; `evidence/FEAT-B-lama.txt`)
| Jenis | Tes / perilaku | Kode lama | Kode baru |
|---|---|---|---|
| (i) modul/nama baru | `tests/test_bench_workspace.py` (138 tes) | `ImportError: cannot import name 'workspace' from 'bench'` (galat koleksi) | semua lulus |
| (i) | `test_shell_bench.py`: `test_policy_project_and_baseline_paths_…`, `test_policy_makes_ws_project_writable_…`, `test_confined_command_builds_inside_ws_project_…` | 3 FAILED (`AttributeError: policy.project_dir` / `bench.workspace`) | lulus (Landlock nyata) |
| (ii) perilaku atas berkas lama | `parse_result({"status": []})` | `TypeError: unhashable type: 'list'` | `status="failed"` |
| (ii) | `safe_rmtree` direktori mode 000 milik 10001, dijalankan sebagai 10001 | `TypeError: open() missing required argument 'flags'` (rc 1) | terhapus (`test_uid10001_force_resets_its_own_project_even_with_mode000…`) |
| (ii) | `parse_diff_result` dengan hash `"a"*64+"\n"` (kalau memakai `SHA256_RE.match`) | lolos sebagai hash sah | `failed` (mutan MB17 tertangkap) |

Jujurnya: pembacaan FIFO dan symlink di `read_result` LAMA sudah aman lewat `is_file()`/`is_symlink()` (hasil lama: `failed`, tidak menggantung), jadi tes FIFO/symlink A-13 lulus juga di kode lama; nilainya mengunci jendela balapan lstat→open lewat `read_small` (mutan MB18 `open()` biasa → tertangkap oleh tes FIFO dengan `within(5)`).

### Mutasi pada berkas NYATA (28 mutan; `evidence/FEAT-B-mutasi.txt`) — semua TERTANGKAP
`init` menimpa tanpa force (MB1) · `.project.tmp`/umpan symlink tak dihapus (MB2) · tanpa kuota pasca-salin (MB3) · tanpa `statvfs` (MB4) · `shutil.copytree` menggantikan `copy_tree_safe` (MB5) · baseline tak diperiksa (MB6) · tanpa `touch_activity` awal (MB7; pertama LOLOS karena ada sentuhan akhir yang redundan → sentuhan akhir DIHAPUS dan tes `.last-used` untuk op yang tidak menyalin ditambahkan) · `force` menghapus `project` lama SEBELUM menyalin (MB8) · `_ticker` tanpa pembatalan (MB9) · `op_diff` tanpa `check_proto_id` (MB10) · daemon: `force` boleh 1/0 (MB11), `analysis_id` bool lolos (MB12), batas lama `2**31` (MB13), op init/diff tak diarahkan (MB14), timeout tak dijepit (MB15) · shellspool: `force` bukan bool lolos (MB16), `match` bukan `fullmatch` (MB17), baca hasil dengan `open` biasa (MB18), status tak-hashable (MB19), path `top` tak disaring (MB20), `ok` tanpa hash tetap `ok` (MB21), `top` tak dipotong (MB22), `run_op` menerima op `run` (MB26), `build_init_request` tanpa batas id (MB27) · `policy.project_dir` memakai `int()` (MB23) · `safe_rmtree` tanpa perbaikan mode 000 (MB24) · selftest tanpa pemeriksaan builds (MB25) · `diff` tanpa sentuhan akhir (MB28) LOLOS karena redundan → sentuhan akhir `diff` dan `init` dihapus dari kode (tidak ada yang bergantung padanya: mtime berkas hasil salin sudah segar).
Setiap mutan: berkas dipulihkan (`cmp` dengan salinan = sama) sebelum mutan berikut.

### Meniru kontainer (apa yang dilakukan)
- uid 10001 NYATA (`setpriv --reuid=10001 --regid=10001 --clear-groups`); baseline milik root 644/755.
- Berkas milik uid LAIN: baseline berkas mode 600 → `refused unreadable` (gagal-tertutup, jalur relatif, tidak ada `project`/`.project.tmp`); `bench/` milik root → `failed PermissionError` tanpa jalur absolut, tidak ada yang tercipta, `diff` → `belum_init`; `bench/1` milik uid 10002 mode 700 → `init`, `init --force`, dan `diff` semuanya `failed` (bukan crash), isinya utuh; `project` lama milik root di folder tak dapat ditulis + subdirektori mode 000 → `force` `failed`, isi lama utuh, tanpa rekursi tak berujung (`within(30)`); `project` milik 10001 dengan direktori mode 000 dan berkas 444 → `force` berhasil.
- `unshare -m` + `mount --bind … ro` untuk `work`, `bench` = tmpfs `noexec,nosuid` milik 10001: `init` berhasil (berkas 0644/0755 tetap bisa dibuat di `noexec`), baseline tidak bisa ditulis (EROFS diperiksa).
- Symlink umpan: `.project.tmp` → direktori di luar; `project` → direktori di luar (tanpa force: dibiarkan; dengan force: symlink dihapus, sasaran utuh); baseline berisi symlink/loop/FIFO/`build/`/`dist/` → tidak disalin, tidak menggantung (`within(10)`), `diff` terhadap salinan kosong.

### Celah emulasi (JUJUR)
- Bukan kontainer: tanpa cgroup (bench 1g/512 PID tidak berlaku), tanpa seccomp/`cap_drop`/`read_only` rootfs (rootfs-ro hanya pada bind `work`), jaringan sandbox terbuka (3 pemeriksaan jaringan selftest gagal karena itu).
- Landlock di sandbox ABI **v2** (VPS: kernel Docker host, kemungkinan ≥ v4); `REFER` (mv antar-subdirektori di `project/`) diuji pada v2; hak `TRUNCATE` (ABI 3) dan pengunci TCP (ABI 4) tidak.
- Interpreter pyenv sandbox bukan python image; dijalankan uid 10001 lewat tmpfs-di-atas-`/root` dalam namespace mount (artefak lokasi interpreter, bukan perilaku produk). `/tmp` sandbox tidak dapat ditulis uid lain, jadi `TMPDIR` daemon diarahkan ke folder milik 10001 (di kontainer `/tmp` adalah tmpfs milik 10001).
- Filesystem tmp sandbox ≠ volume Docker; `st_blocks`/`statvfs` volume nyata (ukuran blok, overlay) tidak diuji. Pohon apktool nyata besar (ratusan ribu berkas) tidak diuji di FEAT ini; kecepatan/memori hash atas APK sampel dan APK besar diukur di tahap sandbox-e2e.
- Redis/RQ, web, worker belum terlibat di FEAT B (op dipanggil langsung lewat klien `shellspool` pada spool berkas).

### BELUM DIUJI (butuh Docker VPS)
- `docker compose --profile build build bench` dan `docker compose up -d bench` dengan kode baru (Dockerfile bench menyalin seluruh paket `bench/` dan `rvcore/`, jadi `workspace.py`/`treediff.py` ikut otomatis; dibaca + tes teks, build tidak dijalankan). `make bench-selftest` (perintah VPS) harus menampilkan 8 baris OK baru di bagian 3a plus semua baris lama; gejala gagal yang mungkin: `GAGAL init menyalin baseline` → volume `work` bench tidak berisi `apktool/` (analisis belum selesai) atau izin `bench/` bukan 10001 (volume baru mewarisi izin dari image: `mkdir -p /data/bench` + chown ada di Dockerfile bench); `GAGAL perintah terkurung boleh MENULIS di $WS/project` → Landlock host tanpa `REFER`/versi lama; `GAGAL volume bench TIDAK memuat builds` → compose salah memasang `builds` ke bench.
- Perilaku `statvfs`/kuota pada volume Docker `bench` nyata dan waktu `init` untuk baseline apktool besar (tenggat 600 dtk).


---

## FEAT C — tahap `build` di runner, mount runner, penutupan R3/R10 di signer, warisan 2a

### Berkas yang berubah
| Berkas | Isi |
|---|---|
| `services/runner/buildstage.py` (baru) | tahap build: prasyarat → cek disk → snapshot `copy_tree_safe` → hash ulang ATAS SNAPSHOT → jejak FR-9.23 → `apktool b -f` (wrapper produksi) → hasil → pembersihan; loop pengawas sendiri |
| `services/runner/runner-daemon` | cabang `build` di `run_job` SEBELUM pemeriksaan APK; `build_command("build")` → `ValueError`; `tool_version("build")`; tahap lama tidak berubah |
| `services/rvcore/buildproto.py` (baru), `spool.py` | `TOOL_STAGES`/`JOB_ID_RE` + `build`; `validate_build_request`, `parse_build_result` (A-11), `dump_result` (≤ 8 KiB) |
| `services/rvcore/fsutil.py`, `paths.py`, `store.py` | `open_dir_chain`, `rmtree_at` (iteratif, satu fd), `scrub_paths` (absolut + relatif, NB-3); `Layout.bench/signwork/project_dir/base_tree`; `store._clean_text(scrub=True)` memakai `scrub_paths` |
| `services/signer/signer-daemon`, `rvcore/signspool.py` | R3/R10: kerja di `signwork` privat, `expect_sha256` (A-02), terbit tahan balapan, baca ulang; `error_text`/`signer.hb` keystore disaring |
| `services/worker/signcheck.py`, `scripts/signer-verify.sh` | rantai-dirfd (A-03), `expect_sha256`; sandi tidak di argv `grep` |
| `docker-compose.yml`, Dockerfile runner/signer/web, `runner-selftest`, `signer-selftest`, `docs/deploy.md` | runner `bench:ro` + `builds`; signer + `signwork`; web + `builds`; volume `signwork`; tmpfs runner TIDAK berubah |
| tes baru | `test_runner_build.py` (83), `test_signer_race.py` (49), `test_build_fs_chain.py` (60), `test_buildproto.py` (93), `test_build_compose.py` (16) |

### Keputusan R3/R10 (dan alternatif yang ditolak)
**Dipilih:** signer bekerja HANYA di volume privat `signwork` (tidak dipasang ke runner): buka `unsigned.apk` SEKALI (`O_NOFOLLOW|O_NONBLOCK`, `S_ISREG`, `nlink==1`), salin + SHA-256 dari fd yang sama, TOLAK `input_unsafe` bila hash salinan ≠ `expect_sha256` (dari runner, di request) SEBELUM alat apa pun jalan, align/sign/verify di `signwork`, terbitkan ke `builds` lewat `.sign-signed.tmp` (`O_CREAT|O_EXCL|O_NOFOLLOW`) + `rename` atomik, BACA ULANG `signed.apk` (berkas biasa, `nlink==1`, hash sama; beda → hapus + gagal).
**Ditolak:** (1) uid berbeda untuk signer — mengulang pelajaran 3 (hapus/prune gagal EACCES), tak bisa dibuktikan di sandbox, tak menutup pembacaan jalur runner; (2) `builds` ro untuk signer + volume `artifacts` terpisah — paling kuat tetapi menyalahi matriks mengikat brief; dicatat sebagai peningkatan Tahap 5 bila R-1 tak dapat diterima; (3) baca-sekali tanpa `signwork` (`/proc/self/fd`) — keluaran tetap di folder runner; (4) worker menyalin ke `signspool` — memindah ≤ 1 GiB lewat antrean JSON; (5) `chattr +i`/fs-verity — butuh capability.
**Sisa (jujur):** runner terkompromi masih dapat mengubah `signed.apk` SETELAH terbit; tanda tangan pemilik tidak ikut sah dan hash DB dihitung ulang worker (Tahap D); unduhan Tahap 5 wajib salin-lalu-hash.

### Hasil
```
$ pyflakes services tests ; echo $?                    → 0
$ pytest                                               → 2629 passed, 27 skipped        (baseline 2316 passed, 14 skipped sebelum FEAT C)
$ pytest (+ SIGNER_TEST_*, BUILD_TEST_* diset)          → test_runner_build/test_signer_race/test_signer_daemon/test_signcheck: 444 passed, 3 skipped
```
Tes yang BENAR-BENAR berjalan di sandbox (bukan dilewati): uid 10001 via `setpriv`; `unshare -m` dengan `bench` bind READ-ONLY, `/tmp` tmpfs `noexec`, tmpfs `exec` (uid 10001, 16m) untuk salinan aapt2; pohon milik root mode 644/755 dan 600; **runner-daemon NYATA sebagai proses uid 10001** membangun lewat spool dengan apktool 3.0.3 + aapt2 NYATA (jar `dbf930b0…`, aapt2 `df312db8…` terverifikasi), `workspace_changed`, `tree_unreadable` (file root mode 600), `bad_request`; signer: dua proses uid 10001 TERPISAH (signer vs 'runner').

### Bukti balapan R3/R10 (kode lama vs baru; `evidence/FEAT-C-race-lama-vs-baru.txt`)
| Serangan 'runner' di jendela | Kode LAMA (HEAD 3f0f96f) | Kode BARU |
|---|---|---|
| `unsigned.apk` ditimpa saat zipalign | **ok:true, byte penyerang diterbitkan** | ok:true, byte ASLI, `input_sha256` = asli |
| `unsigned.apk` → symlink `/etc/passwd` | **ok:true, isi `/etc/passwd` diterbitkan** | byte asli |
| `unsigned.apk` → FIFO | timeout (menggantung 10 dtk) | tidak berpengaruh |
| `.sign-signed.tmp` ditimpa sesudah verify | **ok:true, byte penyerang diterbitkan** | ok:false `internal` (O_EXCL), tidak ada signed.apk |
| `.sign-signed.tmp` → symlink | ok:false | ok:false |
Tes tambahan di `test_signer_race.py`: tukar sebelum buka → `input_unsafe` dengan 0 panggilan alat (A-02); `.sign-signed.tmp` berupa berkas/FIFO/symlink/direktori/symlink menggantung; `signed.apk` berupa direktori/FIFO/berkas/symlink; tukar tepat setelah rename (berkas/FIFO/symlink/direktori/tautan keras); `builds/<aid>` jadi symlink sebelum/ saat job; folder build dipindah; file tumbuh saat disalin; **alat NYATA** dengan 'runner' yang menghantam folder terus-menerus (4 mode) — tidak pernah menerbitkan byte asing.

### Bukti "gagal di kode lama, lulus di kode baru" (worktree HEAD lama + tes baru; dua jenis dipisah)
| Jenis | Tes | Kode lama | Kode baru |
|---|---|---|---|
| (i) modul baru gagal impor | `test_buildproto.py`, `test_runner_build.py` | error koleksi (`buildproto`/`buildstage` tak ada) | lulus |
| (i) | `test_build_fs_chain.py` | 59 gagal (`fsutil.open_dir_chain`/`Layout.project_dir` tak ada) | lulus |
| (ii) perilaku atas berkas lama | `test_signer_race.py` | 44 gagal (signer lama bekerja di folder runner, tanpa `expect_sha256`) | lulus |
| (ii) | `test_signspool.py` / `test_signer_daemon.py` / `test_signcheck.py` | 41 / 53 / 12 gagal (protokol `expect_sha256`, alat di `signwork`, rantai-dirfd, `input_sha256`) | lulus |
| (ii) | `test_build_compose.py` | 8 gagal (matriks mount) | lulus |

### Mutasi pada berkas NYATA (51 mutan, `evidence/`; semua TERTANGKAP)
Runner C1–C17: hapus bandingan hash · hash atas pohon hidup · hapus `-f` · `copytree` ikut symlink · hapus cek disk · jejak sebelum hash · hapus pembersihan `src/` · `unsigned.apk` tak dihapus saat gagal · `output_limit` mengukur snapshot · log tak disaring · tenggat hanya di apktool · kill group dihapus (tes MENGGANTUNG → tertangkap) · `build.log` tak dibatasi · `build/` tak dibuang · terima `path` · cabang build setelah cek APK · STOP→cancelled. Signer S1–S16, fsutil/signcheck F1–F7, protokol P1–P3, compose K1–K8 (bench rw, signwork di worker, builds di bench, exec di /tmp, read_only false, signspool di runner, signer tanpa signwork, web tanpa builds).
Celah yang DITEMUKAN mutasi dan ditutup: C11 (tes tenggat tak membuktikan apktool tak diluncurkan → kini cek pesan "mulai:"), S12 (tes salinan terbit), F4 (tes pohon dipindah → cek ident induk). Satu insiden proses: eksekusi mutasi terputus meninggalkan mutan C12 di `buildstage.py`; dipulihkan dan harness diberi batas 40 dtk (mutan hang = tertangkap).

### Tes lama yang SENGAJA diubah (alasan)
| Tes | Alasan |
|---|---|
| `test_shell_tool::test_compose_bench_service_is_isolated_and_secretless` | runner kini boleh `bench:ro` SAJA (sumber snapshot); tanpa `benchspool`; worker tetap tak melihat bench; bench tanpa `builds` |
| `test_build_paths::…only_for_worker_and_signer` → `…only_where_intended` | `builds` = web+worker+runner+signer; signspool tetap worker+signer; `signwork` hanya signer |
| `test_build_store::test_compose_gains_no_volume…` | volume akar + `signwork` |
| `test_signer_toolchain` (5 tes), `test_signer_keystore_access` (1) | `mkdir` signer + `/data/signwork`; volume signer = 3; holders `builds`; Dockerfile web/runner memuat `/data/builds`; `check_data_dir` butuh `signwork` |
| `test_signspool`, `test_signer_daemon`, `test_signcheck` | `expect_sha256` wajib; alat bekerja di `signwork`; `input_sha256` di hasil; tes balik-folder kini membuktikan terbit ke inode yang dibuka |
| `test_signer_verify_script` | bentuk `grep -F -q -f <(printf …)`; sandi tak di argv |
Tes isolasi lain tidak dilonggarkan. Invarian baru ketat: `tests/test_build_compose.py` (matriks mount per layanan + mode, runner tanpa benchspool/signspool/signwork/files/db/secrets/docker.sock, satu-satunya tmpfs exec = `/opt/aapt-exec`, hardening, mkdir Dockerfile).

### Warisan 2a
`error_text` keystore + `signer.hb` disaring (jalur `/run/secrets` hilang, petunjuk `make keystore-access` tetap) · sandi tidak di argv `grep` (`-f <(printf)`) · tes FIFO signcheck dibatasi waktu (`within_call` di `conftest`, FIFO/symlink untuk `status`/`sign`).

### Dikerjakan di luar daftar FEAT A yang dilewati (dibutuhkan C)
`open_dir_chain`/`rmtree_at`/`scrub_paths`/`Layout` baru/NB-3 (plan A.1/A.2/A.4 tidak masuk commit A). Web diberi mount `builds` + `mkdir` Dockerfile sekarang (invarian "web: builds rw" diminta; belum ada kode web yang memakainya).

### Celah emulasi (JUJUR)
Bukan kontainer: tanpa cgroup (`mem_limit`, `pids_limit`, `memory.peak` → `peak_mem_mib` null), seccomp, `cap_drop`/`no-new-privileges`, rootfs ro hanya lewat bind; JDK 21 mise ≠ `openjdk-21-jre-headless` Debian; `/tmp` tmpfs buatan `mount -t tmpfs`; Landlock tidak terlibat di FEAT ini; filesystem sandbox ≠ volume Docker (`statvfs`/izin mount baru); apktool dijalankan dengan HOME di tmpfs `noexec` tetapi JDK di luar image; uid host `deploy` ≠ 1000 tak ditiru; jalur waktu nyata 1800 dtk / 3 GiB / 600.000 entri tidak diuji (batas diturunkan di tes).
### BELUM DIUJI (butuh Docker VPS)
`docker compose config -q`; build image runner/signer/web (COPY `buildstage.py`, `mkdir` baru); izin awal volume `bench:ro`/`builds`/`signwork` baru; `make runner-selftest` (bagian 7: 3 baris OK baru) dan `make signer-selftest` (`/data` = builds, signspool, signwork); `make signer-verify` ulang; antre runner di belakang analisis + daur ulang kontainer; disk nyata (2× + 1 GiB runner; signwork 2× + 1 GiB). Gejala: `EROFS`/`Permission denied` saat salin → volume baru tak berizin 10001; `workspace_changed` palsu → AI menulis saat snapshot; `signer … input_unsafe hash tak cocok` → berkas diganti runner setelah build.
