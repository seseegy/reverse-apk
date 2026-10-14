# Deploy ke VPS

Panduan memasang reverse-apk di VPS Ubuntu dengan domain `apk.revers3.my.id`.
Semua perintah dijalankan sebagai user `deploy` (bukan root), kecuali dinyatakan lain.

## Prasyarat
- VPS Ubuntu dengan user `deploy` yang punya `sudo` dan login SSH key.
- DNS: record **A** `apk.revers3.my.id` → IP VPS, **proxy Cloudflare dimatikan** (awan abu-abu / "DNS only"). Proxy dinyalakan hanya setelah HTTPS jalan.

Cek DNS dari VPS:
```bash
getent hosts apk.revers3.my.id      # harus menampilkan IP VPS ini
```

## 1. Firewall
Pastikan SSH tetap diizinkan **sebelum** mengaktifkan firewall.
```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp      # HTTP/3
sudo ufw enable
sudo ufw status
```
> Docker menambahkan aturan iptables sendiri untuk port yang dipublikasikan, yang melewati `ufw`.
> Karena itu `docker-compose.yml` hanya mempublikasikan 80/443 (milik Caddy). Redis, web, dan worker
> **tidak** punya port yang dipublikasikan ke host.

## 2. Pasang Docker dan make
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker deploy
sudo apt-get install -y make git
```
Keluar lalu masuk SSH lagi (agar grup `docker` aktif), lalu cek:
```bash
docker --version && docker compose version
```

## 3. Ambil kode
```bash
git clone https://github.com/seseegy/reverse-apk.git
cd reverse-apk
```

## 4. Konfigurasi
```bash
make init        # membuat .env (SECRET_KEY & REDIS_PASSWORD acak) dan folder secrets/
make password    # atur password admin (min 12 karakter; disimpan sebagai hash argon2id)
```
Periksa `.env` (opsional): `APP_DOMAIN` sudah `apk.revers3.my.id`, `ADMIN_USERNAME` default `admin`.

## 5. Jalankan
```bash
make up          # build image dan jalankan semua layanan
make doctor      # periksa konfigurasi, status kontainer, dan https://<domain>/healthz
```
Saat pertama kali, Caddy meminta sertifikat dari Let's Encrypt (butuh DNS benar dan port 80 terbuka).
Biasanya selesai dalam beberapa detik. Lalu buka **https://apk.revers3.my.id**.

## 6. Verifikasi
1. Login dengan `admin` dan password tadi.
2. Di kartu **Status sistem**, semua baris harus *Normal*.
3. Tekan **Uji antrean** → baris *Antrean* menjadi "uji berhasil".
4. Baris **Runner** juga harus *Normal* ("siaga (tanpa jaringan)").
5. Uji isolasi dan kemampuan alat dekompilasi:
   ```bash
   make runner-selftest
   ```
   Semua baris harus `[OK ]`: termasuk "jaringan terisolasi", "rootfs read-only", dan "apktool/jadx dapat bekerja"
   (menjalankan alat sungguhan, bukan hanya `--version`). Perintah ini keluar dengan kode 0 hanya jika semua lulus.
6. Uji alur utama: buka **Unggah**, pilih sebuah APK (centang pernyataan otorisasi), dan pastikan halaman analisis
   menampilkan tahap *Validasi → apktool → jadx → Selesai* secara live.

## Analisis statis (M2)
Analisis berjalan otomatis setelah jadx (tahap **Analisis statis**, batas `TIMEOUT_ANALYZE`, bawaan 5 menit).
Kegagalan tahap ini **tidak** membuang hasil apktool/jadx: analisis tetap selesai dengan peringatan.

**Analisis yang dibuat sebelum M2** tidak punya temuan/indeks. Buka tab **Temuan**, **Jaringan**, atau **Kode** pada analisis itu
lalu tekan **Jalankan analisis statis**: hasil dekompilasi yang ada dipakai ulang (hitungan detik), tidak perlu mendekompilasi lagi.

Indeks pencarian memakan ruang tambahan (terukur: 69 MiB untuk NewPipe dengan 7.095 class / 50 MiB kode, 152 MiB untuk VLC dengan 15.256 class). Secret yang ditemukan di-*mask*
secara bawaan; tombol **Tampilkan nilai** dicatat di audit log (`secret_reveal`).

## AI / chat agent (M4)
AI bersifat **opsional** dan mati secara bawaan (tidak ada data yang keluar). Untuk mengaktifkan, isi di `.env` (bukan di chat):
`AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL`, lalu jalankan:
```bash
docker compose up -d web     # muat ulang .env
make ai-check                # uji koneksi, streaming, tool calling, dan pelaporan token
```
Semua baris harus `[OK ]`. **Tool calling wajib** untuk chat agent; bila `[GAGAL]`, pilih model lain di portal router.
Anggaran dalam *kredit* (`AI_DAILY_BUDGET_CREDITS`, `AI_SESSION_BUDGET_CREDITS`); chat berhenti rapi saat habis.
Harga per model ada di `config/ai_models.json` (kredit per 1 juta token): sesuaikan dengan portal, lalu `docker compose restart web`.
Bandingkan angka token dari `make ai-check` dengan selisih saldo di portal untuk memastikan harga input/output.

**Chat agent:** buka tab **Percakapan** pada sebuah analisis. Pertanyaan contoh: "Di mana base URL API?", "Bagaimana alur login?",
"Buatkan skrip Python untuk mendekripsi string di Crypto.java". Hasil berupa teks dengan tombol **Salin/Unduh**; skrip tidak pernah
dijalankan aplikasi. Butuh analisis statis selesai (agar pencarian tersedia). Ekspor percakapan ke `.md` dari panel samping.

**Privasi:** potongan kode APK yang Anda tanyakan dikirim ke provider (dan model di belakangnya). Secret diredaksi lebih dulu.
Kunci hanya dibaca service `web`; tidak pernah dikirim ke browser, worker, atau runner, dan tidak dicatat di log.

## Alat build & tanda tangan APK (B-1b)
Paket ini HANYA menyediakan alat di server; **belum ada** daemon penanda tangan, keystore, tahap `build`, maupun UI. Layanan `signer` memakai profil Compose `build`,
jadi `make up` / `docker compose up` **tidak** menjalankannya dan RAM tidak bertambah sampai fitur build dipakai.

**Memasang / memperbarui di VPS** (butuh Docker Compose v2 untuk `--profile`):
```bash
git pull --ff-only
docker compose --profile build build signer   # unduh Build-Tools, verifikasi SHA-256 (build GAGAL bila hash tidak cocok)
make signer-selftest                          # semua baris harus [OK ]
make tools-check                              # tabel versi java/apktool/jadx/keytool/zipalign/apksigner dari image runner & signer
make runner-selftest                          # juga membuktikan `apktool b` jalan OFFLINE di kontainer runner (salinan aapt2 di tmpfs khusus /opt/aapt-exec) dan /tmp runner tetap noexec
```
`signer-selftest` membuat keystore SEMENTARA di `/tmp` (dihapus di akhir; tidak pernah disimpan), lalu: `zipalign` → `apksigner sign` → `apksigner verify` (v2 dan v3 harus `true`),
tes negatif (APK tanpa tanda tangan dan APK yang dirusak setelah ditandatangani HARUS ditolak), serta bukti isolasi dari dalam kontainer (bukan root, rootfs read-only, tanpa jaringan, tanpa keystore/rahasia di image).
Kirim keluaran bila ada `[GAGAL]`.

**Perkiraan sumber daya** (belum diukur di VPS; isi kolom "ukur" setelah `docker images`):
| Hal | Perkiraan | Ukur di VPS |
|-----|-----------|-------------|
| Berkas Build-Tools yang disalin ke image | 2.983.423 byte (zipalign 256.480 + apksigner.jar 1.181.416 + libc++.so 1.545.448), terukur; zip unduhan ±66 MB dibuang di layer yang sama | – |
| `openjdk-21-jre-headless` | ≈ 199 MB terpasang (amd64, menurut packages.debian.org; bukan diukur di sini) | `docker images` |
| Image `signer` | image dasar + JRE + ±3 MB | `docker images \| grep signer` |
| RAM | `mem_limit: 512m` **hanya saat profil `build` dipakai**. Jumlah `mem_limit` layanan lain saat ini 5.952 MB → 6.464 MB bila signer ikut berjalan | `docker stats` |

**`/tmp` runner SENGAJA `noexec`; aapt2 sumber ada di `/opt/apktool/aapt2`, salinan yang dijalankan ada di tmpfs khusus `/opt/aapt-exec`.** Docker memasang tmpfs `/tmp` runner dengan `noexec` (juga `nosuid`; `exec` TIDAK boleh ditambahkan: runner memproses APK tak tepercaya).
Ada dua akar masalah berurutan untuk `apktool b`:
1. Tanpa `--aapt`, apktool 3.0.3 mengekstrak aapt2 ke `/tmp` lalu menjalankannya dan gagal (`Cannot run program ... error=13, Permission denied`). Perbaikan pertama (PR #43): aapt2 dipasang di rootfs dan dipakai lewat `--aapt /opt/apktool/aapt2`.
2. **Itu belum cukup (hanya terlihat di Docker nyata):** dengan `--aapt`, `AaptManager.setBinaryExecutable` (Apktool v3.0.3) memanggil `File.setExecutable(true)`, dan di JDK itu SELALU `chmod(2)` — walau bit x sudah ada. Di runner `chmod` ditolak: rootfs `read_only: true` (EROFS) dan berkas milik root sedangkan proses uid 10001 (EPERM). Hasilnya `Could not set aapt binary as executable: /opt/apktool/aapt2`. Berkas aapt2 di rootfs read-only milik root TIDAK PERNAH bisa lolos.

Perbaikan kedua: **satu tmpfs khusus** `/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755` di service `runner` (titik mount dibuat di image, milik root, kosong). Wrapper `/usr/local/bin/apktool` (berkas `services/runner/apktool-wrapper`) untuk `b`/`build`:
(a) menyalin aapt2 pin dari `/opt/apktool/aapt2` ke `/opt/aapt-exec/aapt2` secara atomik (berkas sementara di direktori yang sama lalu `mv -f`, dikunci `flock` agar build serentak tidak saling menimpa), (b) memverifikasi sha256 SALINAN terhadap pin di `/opt/apktool/aapt2.sha256` (ditulis dari `ARG AAPT2_SHA256`; berkas, bukan ENV, karena `runner-daemon`/`runner-selftest` menjalankan alat dengan lingkungan yang dibersihkan), (c) memeriksa salinan bisa dijalankan,
lalu (d) menyisipkan `--aapt /opt/aapt-exec/aapt2`. Salinan itu milik uid 10001 di filesystem yang bisa ditulis, jadi `chmod` Java lolos. Bila direktori itu bukan mount yang benar (tidak ada, tidak bisa ditulis, atau `noexec`), wrapper berhenti dengan pesan `GALAT apktool: ...` yang menyebut penyebabnya — tidak diam-diam. `d`, `--version`, dan subperintah lain tidak berubah.
**Batasan:** hanya argumen pertama yang diperiksa. Opsi global di depan subperintah (`apktool -v b ...`) ditolak apktool 3.0.3 sendiri (`Unrecognized command: -v`, terbukti dengan jar asli); `-v`/`-q` sah hanya sesudah subperintah (`apktool b -v ...`). Semua pemanggil di repo memakai `apktool <subperintah> ...`.

**Kompromi keamanan (jujur).** Sebelumnya tidak ada tmpfs runner yang bisa dieksekusi. Sekarang ada satu: `/opt/aapt-exec`, direktori tmpfs kecil (16 MiB) yang bisa ditulis dan dijalankan uid 10001 (volume data `work`/`spool` tidak disetel `noexec` oleh compose; itu di luar cakupan perbaikan ini dan tidak diperiksa di sini). Kontainer yang sudah disusupi lewat bug parser bisa menaruh biner di sana dan menjalankannya. Mitigasi, bukan penghapusan risiko: kontainer tanpa jaringan (`network_mode: none`), `cap_drop: ALL`, `no-new-privileges`, rootfs read-only, `/tmp` TETAP `noexec`, mount `nosuid,nodev`, ukuran kecil, isinya hilang tiap kontainer (`RUNNER_RECYCLE`), dan yang diharapkan di sana hanya satu berkas — `aapt2` ber-hash pin (`runner-selftest` memeriksa isinya setelah `apktool b`).
`noexec` pada `/tmp` juga bukan penghalang mutlak (kode bisa dijalankan dari memori lewat loader/`memfd`), tetapi lapisan pertahanan yang sengaja dipertahankan. Alternatif yang DITOLAK: `exec` pada `/tmp` (permukaan jauh lebih besar), dan menambal jar apktool (pin SHA-256 berubah, beban pemeliharaan). Tes `tests/test_runner_aapt2.py` menjaga bahwa tmpfs `exec` hanya satu: service `runner`, jalur `/opt/aapt-exec`, `nosuid,nodev`, ukuran ≤ 16m.
Mengapa 16m: aapt2 6.449.680 byte (≈ 6,15 MiB); saat penggantian atomik ada paling banyak dua salinan (≈ 12,3 MiB). Lebih besar memperlebar permukaan tulis+eksekusi tanpa manfaat.
**Risiko residual / rencana cadangan:** opsi `uid`, `gid`, `mode` pada tmpfs bentuk pendek compose belum diuji di Docker/Compose VPS (Docker meneruskannya ke `mount(2)` tmpfs; bentuk panjang `type: tmpfs` tidak dipakai karena hanya punya `size`/`mode` dan tidak bisa `exec`). Gejala bila ditolak: `docker compose run/up` gagal dengan `invalid mount option`/`mount: invalid argument`, atau `runner-selftest` melaporkan `dimiliki uid ..., harus 10001` / wrapper `tidak bisa ... ditulis`. Cadangan: ubah HANYA opsi menjadi `/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,mode=1777` (tanpa uid/gid; berkas yang dibuat uid 10001 tetap miliknya sehingga `chmod` Java lolos), lalu longgarkan cek "uid 10001" pada selftest dan tes sesuai.
Image runner **hanya untuk x86-64** (aapt2 prebuilt Linux); build di arm64 sengaja digagalkan dengan pesan `GALAT: aapt2 bawaan apktool ... hanya untuk x86-64` (`docker compose build runner` di host arm64 perlu `--platform linux/amd64`/emulasi).

**Verifikasi di VPS** (setelah pembaruan ini; semua baris harus `[OK ]`):
```bash
git pull --ff-only
docker compose build runner                   # GAGAL bila hash aapt2 tidak cocok atau arsitektur bukan x86-64
make runner-selftest                          # harus memuat [OK ] "tmp runner noexec", "aapt2 terpasang di rootfs", "sumber aapt2 tidak bisa diubah runner", "tmpfs exec khusus /opt/aapt-exec", "apktool b ... OFFLINE", "hasil build adalah APK utuh", "isi /opt/aapt-exec hanya aapt2"
python3 scripts/sample-apk/build.py           # membangun APK uji lewat `apktool b` di kontainer (tmpfs /tmp tanpa exec + tmpfs /opt/aapt-exec) -> testdata/vulnsample.apk
docker compose run --rm --no-deps runner sh -c 'grep -E " (/tmp|/opt/aapt-exec) " /proc/mounts; ls -l /opt/apktool/aapt2; cp /bin/true /tmp/t && /tmp/t && echo EXEC_OK || echo EXEC_DENIED'   # /tmp noexec + EXEC_DENIED; /opt/aapt-exec tmpfs rw,nosuid,nodev,size=16384k,uid=10001
```
Bila `[GAGAL]`, pesannya kini memuat baris `Caused by:`/`error=` pertama dan awal keluaran; kirim seluruh baris itu.

**Alat & versi terkunci** (sumber kebenaran: `ARG` di Dockerfile; tes `tests/test_signer_toolchain.py` memastikan tabel ini tidak menyimpang):
| Alat | Versi | Sumber | Pin hash | Lokasi di image |
|------|-------|--------|----------|-----------------|
| apktool | 3.0.3 | github.com/iBotPeaches/Apktool/releases (v3.0.3) | SHA-256 `dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423` | runner: `/opt/apktool/apktool.jar`, wrapper `/usr/local/bin/apktool` (dari `services/runner/apktool-wrapper`) |
| aapt2 | dibundel di dalam jar apktool 3.0.3 (`prebuilt/linux/aapt2`, ELF x86-64 statis, 6.449.680 byte); diekstrak saat build image | – | SHA-256 `df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc` (`ARG AAPT2_SHA256`, dihitung dari jar apktool 3.0.3; hitung ulang bila apktool dinaikkan) | runner: sumber `/opt/apktool/aapt2` (root, 0755, rootfs read-only) + pin `/opt/apktool/aapt2.sha256`; salinan runtime `/opt/aapt-exec/aapt2` (tmpfs exec khusus, uid 10001) yang dipakai `apktool b` lewat wrapper (`--aapt`) |
| jadx | 1.5.6 | github.com/skylot/jadx/releases (v1.5.6) | SHA-256 `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974` | runner: `/opt/jadx`, symlink `/usr/local/bin/jadx` |
| Android SDK Build-Tools (`zipalign` + `apksigner`) | 37.0.0 (stabil; `37.0.0-rc*` adalah preview) | dl.google.com/android/repository/build-tools_r37_linux.zip (`repository2-3.xml`) | SHA-256 zip `01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060` (dihitung sendiri); SHA-1 Google `70954e99f4c3d9d46ee70fa32624672fe7cd6ebe` | signer: `/opt/build-tools/{zipalign,apksigner.jar,lib64/libc++.so}`, symlink `/usr/local/bin/zipalign`, wrapper `/usr/local/bin/apksigner` |
| JRE (+ `keytool`) | `openjdk-21-jre-headless` dari apt Debian trixie | repositori Debian (versi mengikuti image dasar) | tidak dipin per-hash (praktik yang sudah ada) | runner dan signer |
| Image dasar | `python:3.12-slim-trixie` | Docker Hub | tidak dipin per-digest (praktik yang sudah ada) | semua image Python |

**Mengapa bukan paket apt `apksigner`/`zipalign`?** Debian trixie hanya punya `apksigner` 35.0.2-1 dan `zipalign` 1:10.0.0+r36-1.1 (lebih tua dari 37.0.0), dan `apksigner` bergantung pada `default-jre | javaN-runtime`:
menurut packages.debian.org, alternatif itu dipenuhi `default-jre`/`openjdk-21-jre` (bukan varian `-headless`), sehingga apt kemungkinan menarik JRE non-headless yang besar. Ini **dugaan dari metadata paket**, belum diuji dengan `apt` (tidak ada di sandbox pengembangan).
Build-Tools resmi Google dengan hash terkunci lebih baru dan hasilnya dapat diperiksa.

**Menaikkan versi:** ubah `ARG` + hash di Dockerfile terkait; untuk Build-Tools hitung SHA-256 sendiri dari unduhan, cocokkan SHA-1-nya dengan `repository2-3.xml` (abaikan paket ber-`<preview>`), lalu perbarui tabel di atas dan di README. Tes akan gagal bila lupa.
Pemeriksaan stabil terakhir (14 Okt 2026): apktool v3.0.3 dan jadx v1.5.6 sudah rilis stabil terbaru (tidak ada selisih), Build-Tools 37.0.0 stabil terbaru.

**Risiko yang diketahui:** heap `apksigner` dibatasi `-Xmx256m` di wrapper; belum diukur untuk APK ratusan MB (diukur di paket B-1c; batas kontainer 512 MB).
`--enable-native-access=ALL-UNNAMED` di wrapper mencegah peringatan conscrypt pada JDK baru.

**Pemecahan masalah:** `libc++.so: cannot open shared object file` → `libc++.so` harus berdampingan di `/opt/build-tools/lib64/` (RUNPATH `$ORIGIN/lib64`). Jangan percaya `ldd /usr/local/bin/zipalign`
(symlink) yang selalu melaporkan `not found`; periksa `ldd /opt/build-tools/zipalign` atau jalankan `zipalign` langsung. `unknown flag: --profile` → Compose terlalu lama (butuh v2).

## Upload besar dan Cloudflare
Batas ukuran APK diatur `MAX_UPLOAD_MB` di `.env` (bawaan 200). Nilai yang sama dipakai aplikasi dan Caddy.
Jika proxy Cloudflare (awan oranye) dinyalakan, paket gratis membatasi body request ~100 MB sehingga APK yang
lebih besar gagal di tepi; gunakan "DNS only" untuk host ini atau naikkan paket.

## Data dan volume
| Volume | Isi | Diakses oleh |
|--------|-----|--------------|
| `uploads` | APK asli `<sha256>.apk` (read-only setelah tervalidasi) | web (rw), worker & runner (ro) |
| `work` | hasil per analisis: `jadx/`, `apktool/`, `logs/`, `manifest.json` | web, worker, runner |
| `files` | lampiran chat (`up/`) dan berkas buatan AI (`ai/`) per analisis; tidak hilang saat "Analisis ulang" | **hanya web** |
| `db` | SQLite (mode WAL) | web, worker — **runner tidak punya akses** |
| `spool` | antrean berkas worker → runner | worker, runner |

SQLite mode WAL membutuhkan filesystem lokal host (volume Docker biasa). Jangan memetakan `db` ke NFS/SMB.
Hasil dekompilasi bisa besar (puluhan–ratusan MB per APK): pantau kartu **Disk data** di **Beranda**.
Upload ditolak otomatis bila sisa disk < `MIN_FREE_GB` (bawaan 15 GB).

**Lampiran & berkas AI.** Batas dari `.env`: `ATTACH_MAX_MB` (per berkas, bawaan 25), `FILES_QUOTA_MB` (total per APK, 1024), `FILES_MAX_COUNT` (2000), `AI_MAX_IMAGE_MB` (10). `ATTACH_MAX_MB` juga dibaca Caddy, jadi setelah mengubahnya jalankan `docker compose up -d caddy web`. Volume `files` baru dibuat otomatis oleh `make up`; backup ikut volume ini bila Anda ingin menyimpan hasil kerja AI. Berkas dihapus bersama APK-nya. Tombol gambar hanya aktif untuk model bertanda `"vision": true` di `config/ai_models.json`; jalankan `make ai-check` untuk membuktikan model Anda benar-benar bisa melihat gambar.

## Operasi harian
| Tujuan | Perintah |
|--------|----------|
| Lihat log | `make logs` |
| Status kontainer | `make ps` |
| Cek kesiapan (SQLite + Redis) | `curl -fsS https://<domain>/readyz` — 200 `{"status":"ok"}` atau 503; rincian penyebab ada di `make logs` (`readyz gagal`). `/healthz` hanya cek proses hidup. |
| Update kode | `make update` |
| Ganti password | `make password` lalu `docker compose restart web` |
| Hentikan | `make down` (data tetap ada di volume) |

### Saya sudah mengubah `.env` tetapi nilainya tidak berlaku
1. **Terapkan dengan `make restart` atau `make up`**, bukan `docker compose restart`. Perintah `restart` memakai ulang container lama beserta environment saat container itu dibuat, jadi `.env` yang baru tidak terbaca. `up -d` membuat ulang container yang konfigurasinya berubah.
2. Jalankan **`make env-check`**: membandingkan tiap variabel di `.env` dengan yang benar-benar ada di container (web, worker, runner, caddy). Ia melaporkan (a) nilai yang belum diterapkan dan (b) variabel yang ada di `.env` tetapi **tidak diteruskan** oleh `docker-compose.yml` (diabaikan, tidak berefek apa pun).
3. Format yang aman: `NAMA=nilai` per baris. Kutip dan komentar ` # ...` di akhir baris dibaca benar oleh Compose; angka desimal boleh `0.5` atau `0,5`. Nilai tidak valid (mis. `abc`) membuat halaman Chat menampilkan "Konfigurasi AI bermasalah".
4. Anggaran: ada DUA batas, `AI_DAILY_BUDGET_CREDITS` (per hari) dan `AI_SESSION_BUDGET_CREDITS` (per sesi chat, bawaan hanya 1 kredit). Pesan "Anggaran sesi chat habis" berarti batas sesi, bukan harian. `0` = tanpa batas.

## Pemecahan masalah
**Sertifikat HTTPS gagal / browser menunjukkan peringatan**
```bash
docker compose logs caddy | tail -50
```
- `no such host` / `NXDOMAIN` → DNS belum menyebar. Cek `getent hosts apk.revers3.my.id`.
- `connection refused` / timeout dari Let's Encrypt → port 80 tertutup (cek `ufw`, firewall UpCloud) atau Cloudflare proxy masih menyala.
- `too many certificates` → batas Let's Encrypt; tunggu atau pakai domain lain untuk uji.

**`make up` berkata password belum diatur** → jalankan `make password`.

**Login selalu gagal** → `docker compose logs web | tail`. Pesan "Password admin belum diatur" berarti file `secrets/admin_password_hash` kosong.

**Terkunci karena terlalu banyak percobaan** → tunggu 15 menit, atau `docker compose restart web` (pembatas disimpan di memori).

**Status "Runner" merah / analisis macet di "Antre"** → `docker compose logs runner`. Runner sengaja keluar setelah
setiap job lalu dimulai ulang oleh Docker (`RUNNER_RECYCLE=1`), jadi baris `daur ulang` di log itu normal. Jika
job tidak diambil dalam 2 menit, analisis gagal dengan kode `runner_unavailable`.

**Analisis berstatus "Gagal: terputus"** → worker/server dimulai ulang saat job berjalan. Tekan **Coba lagi**.

**Status "Worker" merah** → `docker compose logs worker`; biasanya Redis belum sehat. `make ps` harus menunjukkan semua `healthy`.

## Catatan keamanan
- `.env` dan `secrets/` tidak boleh di-commit (sudah ada di `.gitignore`). Izin: `.env` 600, `secrets/` 700.
- Aplikasi terbuka ke internet pada satu alamat; yang tampil ke publik hanya halaman login. Setelah HTTPS jalan,
  pertimbangkan Cloudflare Access di depannya (lihat PRD 07).
- Batasan memori/proses di `docker-compose.yml` (`mem_limit`, `pids_limit`) berlaku di VPS Linux biasa.
