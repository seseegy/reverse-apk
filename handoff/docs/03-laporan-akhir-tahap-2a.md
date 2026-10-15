# Laporan Akhir — Tahap 2a: `signer-daemon` nyata dengan keystore pemilik

**PR:** https://github.com/seseegy/reverse-apk/pull/47 (`feat/signer-daemon` → `main`, belum di-merge; tidak ada push ke `main`, tidak ada force-push)
**HEAD:** `d13b4716961723f77b86ee29d2bca8b2f0a99827` (8 commit di atas `main` `dbc854c`; 30 berkas, +8719/−94)

## 1. Keputusan akses kunci dan alasannya
Compose mengisi secret `file:` sebagai bind-mount dan mengabaikan `uid/gid/mode`, sehingga keystore mode 600 milik `deploy` (uid 1000) tidak bisa dibaca `signer` (uid 10001). **Keputusan [A]: `signing_keystore.p12` dan `signing_keystore_pass` menjadi mode 644 di dalam `secrets/` mode 700.**
- Alasan: tanpa langkah manual (`make up`/`restart` memanggil `keystore.sh access --auto`), sama dengan pola `admin_password_hash`, tanpa kontainer/kapabilitas tambahan, kunci tidak masuk image/env/argumen.
- **Kompromi:** kerahasiaan bertumpu pada izin FOLDER 700, bukan berkas. Root host, pemilik, dan uid 10001 di kontainer `signer` dapat membaca kunci. `check`/`doctor`/`signer-verify` memeriksa folder dan memberi diagnosis.
- Ditolak: B (volume bernama + helper root), C1 (secret dari env/content), C2 (ACL `setfacl`; tetap boleh manual), C3 (signer sebagai uid host), C4 (`sudo chown`), C5 (entrypoint root + turun hak). Alasan lengkap ada di badan PR dan `docs/deploy.md`.
- Pernyataan proses: **desain tidak pernah APPROVED sebelum coding** (loop desain diakhiri pemilik; verdict terakhir `CHANGES_REQUESTED`); 41 temuan dikerjakan di kode, 0 ditolak.

## 2. Berkas yang berubah (30)
- `.env.example`
- `Makefile`
- `README.md`
- `audit.md`
- `docker-compose.keystore.yml`
- `docker-compose.yml`
- `docs/deploy.md`
- `docs/prd/09-bundles-and-workbench.md`
- `scripts/init.sh`
- `scripts/keystore.sh`
- `scripts/signer-verify.sh`
- `services/rvcore/paths.py`
- `services/rvcore/signkeys.py`
- `services/rvcore/signspool.py`
- `services/signer/Dockerfile`
- `services/signer/signer-daemon`
- `services/signer/signer-selftest`
- `services/worker/Dockerfile`
- `services/worker/signcheck.py`
- `tests/test_build_paths.py`
- `tests/test_build_store.py`
- `tests/test_keystore_script.py`
- `tests/test_signcheck.py`
- `tests/test_signer_daemon.py`
- `tests/test_signer_keystore_access.py`
- `tests/test_signer_selftest_watch.py`
- `tests/test_signer_toolchain.py`
- `tests/test_signer_verify_script.py`
- `tests/test_signkeys.py`
- `tests/test_signspool.py`

Tidak disentuh: `spool.py`, `shellspool.py`, `fsutil.py`, runner/bench/web/egress, `scripts/sample-apk/build.py`, `test_runner_aapt2.py`, `test_shell_tool.py`, `test_spool.py`, `test_shell_bench.py`. Tidak ada `.agents/`, rahasia, keystore, atau biner yang terlacak.

## 3. Hasil verifikasi (angka sebenarnya)
| Pemeriksaan | Hasil |
|---|---|
| `git status --short` | bersih |
| `git ls-files` | tanpa `.p12/.jks/.pfx/.apk/.jar`, tanpa `signing_keystore*`, tanpa `.agents/` |
| `pyflakes services tests` | bersih |
| `pytest` penuh lokal (sandbox, tanpa PyYAML) pada `8969371` | **2063 lulus, 22 dilewati**, 140,77 dtk (baseline `main`: 1378/2) |
| `pytest tests/test_signer_keystore_access.py` setelah perbaikan CI | 67 lulus, 8 dilewati |
| CI GitHub (PyYAML ada; 2053 lulus, 30 dilewati pada run gagal) | lihat §4 |
| Mutasi penjaga | 69/69 TERTANGKAP di akhir; 4 gagal pertama kali (M11, M31b, M35, M46) diperbaiki dengan tes baru |
| Bukti sandbox | daemon + alat asli menandatangani APK nyata sebagai uid 10001 dengan kunci uid 1000 (644 di 700); kasus negatif; sandi tidak bocor; ukuran terbesar teruji 1.055.300.391 B, puncak `sign` 294,6 MiB (di luar cgroup) |
| Verdict review implementasi terakhir | **APPROVED**, 5 temuan non-blocking tersisa (TOCTOU alat → syarat 2b; `error_text` keystore tak disaring; sandi di argv `grep` host; tes signcheck tanpa batas waktu FIFO; sisa BELUM DIUJI) |

## 4. Status CI
- `8969371`: **GAGAL** (2 tes di `test_signer_keystore_access.py`). Penyebab cacat TES: nama pemilik berkas uji diambil dari `stat -c %U /proc/self` (jadi `root` di runner), padahal skrip mencetak `runner` (uid 1001); di sandbox root tak terlihat. Produk benar.
- Perbaikan `d13b471` (hanya tes; `pwd.getpwuid(os.getuid())`). Diperiksa ulang satu kali: **CI HIJAU** (`test`: success, https://github.com/seseegy/reverse-apk/actions/runs/38687231140).
- Keterbatasan: perbaikan diverifikasi lokal sebagai root, bukan non-root; konfirmasinya adalah run CI hijau.

## 5. Risiko residual
R1 kerahasiaan kunci bertumpu pada folder 700 · **R3/R10 uid sama untuk semua penulis `builds/` dan signer = oracle penandatanganan; WAJIB ditutup sebelum runner diberi akses tulis ke `builds` (2b)** · R2 eksploitasi JVM/zip di kontainer berkunci · R4 memori di cgroup belum diukur · R9 kunci basi (label + `stale` + langkah 7 bergantung perilaku Docker belum teruji; setelah mengganti kunci: `make restart`) · lima temuan non-blocking review · desain tidak pernah APPROVED sebelum coding.
Temuan sampingan (di luar 2a, tidak disentuh): traceback pembersihan `TemporaryDirectory` di `scripts/sample-apk/build.py` (berkas milik uid 10001 di folder milik `deploy` = pelajaran #3); APK tetap jadi.

## 6. Perintah VPS untuk pemilik (BELUM DIUJI — butuh Docker)
Jalankan berurutan di `~/reverse-apk` dan tempel hasil/tabel ke chat:
```
git pull --ff-only
docker compose version
docker compose config -q
COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml docker compose config -q
docker compose --profile build build signer worker
make up
make signer-selftest
make signer-verify
BIG_MB=1000 make signer-verify
```
| Langkah | Hasil diharapkan | Gejala kegagalan → tindakan |
|---|---|---|
| `git pull --ff-only` | fast-forward | gagal → perubahan lokal, `git status` |
| `docker compose version` | v2.x / v5.x | tak ada subperintah `compose` → pasang Compose v2 |
| `docker compose config -q` (dua bentuk) | tanpa galat | galat YAML → baris yang disebut; bila Compose membuat DIREKTORI pengganti berkas keystore → `rmdir secrets/<berkas>` dan laporkan versi |
| `... build signer worker` | build sukses, SHA-256 Build-Tools cocok | `sha256sum` gagal → pin; `COPY failed` → daftar COPY; `Unable to locate package` → jaringan |
| `make up` | `signer` healthy ≤ 30 dtk | UNHEALTHY → `docker inspect --format '{{json .State.Health.Log}}' $(docker compose ps -q signer)`; volume `builds`/`signspool` harus milik 10001 (`docker run --rm -v reverse-apk_builds:/v alpine ls -ln /v`) |
| `make signer-selftest` | semua `[OK ]`, 0 GAGAL | "terbaca uid 10001" GAGAL → `make keystore-access`; wrapper `MaxDirectMemorySize` GAGAL → image lama, build ulang; `/data` hanya builds & signspool GAGAL → volume salah pasang |
| `make signer-verify` | tabel 20 langkah semua OK, kode keluar 0 | langkah 12 GAGAL → keystore lain terpasang (cek `COMPOSE_FILE`); 15 → `O_NOFOLLOW` tak berlaku; **18 GAGAL → sandi bocor: hentikan dan buat kunci baru**; vulnsample hilang → `python3 scripts/sample-apk/build.py` sekali |
| `BIG_MB=1000 make signer-verify` (bebas ≥ 3040 MiB di `builds`) | langkah 17a/17b/17c OK, `oom_kill=0`, puncak `anon` < 400 MiB | `oom_kill>0`/restart → turunkan `-Xmx`/`MaxDirectMemorySize` atau naikkan `mem_limit` (keputusan pemilik); 17a lulus tetapi 17b/17c gagal → `MaxDirectMemorySize` kurang/hilang (`docker compose exec -T signer cat /usr/local/bin/apksigner`); `no_space` → `docker system df` |

Opsional (V8–V12, rincian di `docs/deploy.md`): `docker compose exec -T signer sh -c 'ls -ln /run/secrets; id'` (dua berkas, `uid=10001`); `docker stats --no-stream` (PIDS < 128, MEM < 512 MiB); `docker compose --profile build down && make up`; uji kunci basi pada SALINAN (`cp` + `mv`, harapan `0 <inode>` / `keystore_stale`, lalu `make restart`); Ctrl+C saat `signer-verify` lalu pastikan tak ada `signer-selftest --watch` tersisa ≤ 10 dtk.
Juga belum teruji: pewarisan izin volume baru, SELinux/ACL/userns, argv alat di kontainer nyata, `pids_limit`, semua angka memori terhadap `mem_limit: 512m`.
