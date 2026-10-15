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
make init        # membuat .env (SECRET_KEY & REDIS_PASSWORD acak), folder secrets/, dan keystore penanda tangan (membangun image signer bila perlu; lihat "Keystore penanda tangan")
make password    # atur password admin (min 12 karakter; disimpan sebagai hash argon2id)
```
Periksa `.env` (opsional): `APP_DOMAIN` sudah `apk.revers3.my.id`, `ADMIN_USERNAME` default `admin`.

**Penting: jalankan `make init` dan `make up` sebagai dua perintah** (bukan `make init up`): Makefile memeriksa ada-tidaknya keystore saat Makefile DIBACA (sebelum perintah apa pun dijalankan), jadi `make up` hanya memasang keystore ke `signer` bila keystore sudah ada SEBELUM `make up` dimulai. Satu perintah gabungan membuat `up` berjalan tanpa melihat keystore yang baru dibuat `init`.

## 5. Jalankan
```bash
make up          # build image dan jalankan semua layanan
make doctor      # periksa konfigurasi, status kontainer, dan https://<domain>/healthz
```
Saat pertama kali, Caddy meminta sertifikat dari Let's Encrypt (butuh DNS benar dan port 80 terbuka).
**Catatan Tahap 2a:** `make up` membangun ulang image `web`, `worker`, `runner`, dan `bench` karena paket bersama `rvcore` berubah (tambahan `signkeys.py`/`signspool.py`, `Layout.signspool`); perilaku keempat layanan itu tidak berubah. Bila keystore ada, `signer` ikut naik (lihat "Signer-daemon & akses kunci (Tahap 2a)").
**Catatan Tahap 2b (FEAT C: tahap `build` di runner + penutupan R3/R10):** `make up` membangun ulang image `web`, `worker`, `runner`, `bench`, dan `signer` (paket `rvcore` bertambah `buildproto.py`/`fsutil` rantai-dirfd, `runner/buildstage.py`, signer bekerja di volume baru `signwork`). Volume baru `signwork` HANYA dipasang ke `signer`; `runner` kini memasang `bench` **read-only** dan `builds` (rw); `web` memasang `builds`. Volume baru mewarisi izin dari image (`mkdir -p /data/bench /data/builds` / `/data/signwork` + `chown 10001` ada di Dockerfile). `make runner-selftest` dan `make signer-selftest` memeriksa mount itu (bench `ro`, builds dapat ditulis, tanpa benchspool/signspool/signwork/files/db di runner; `/data` signer = builds, signspool, signwork).
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
Paket ini menyediakan alat di server dan keystore (lihat "Keystore penanda tangan" di bawah). **Pembaruan Tahap 2a:** `signer-daemon` kini ada dan keystore dipasang ke layanan `signer` saja (lihat "Signer-daemon & akses kunci (Tahap 2a)"); **belum ada** tahap `build`, UI, maupun tool AI. Layanan `signer` memakai profil Compose `build`: `make up` mengaktifkan profil itu (`COMPOSE_PROFILES=build`) HANYA bila `secrets/signing_keystore.p12` dan `secrets/signing_keystore_pass` sudah ada,
jadi pada instalasi tanpa keystore `signer` tidak ikut naik dan RAM tidak bertambah; `docker compose up` yang dijalankan tanpa `make` juga tidak menjalankannya.

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
| RAM | `mem_limit: 512m` (tidak dinaikkan di Tahap 2a). Sejak Tahap 2a `signer` ikut `make up` bila keystore ada (profil `build` diaktifkan Makefile): jumlah `mem_limit` layanan lain 5.952 MB → 6.464 MB (+512 MB) saat signer berjalan; tanpa keystore tetap 5.952 MB. Puncak pemakaian terukur di sandbox (di LUAR cgroup): lihat "Ukuran terbesar yang teruji" | `docker stats` |

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

**Risiko yang diketahui:** heap `apksigner` dibatasi `-Xmx256m` dan memori langsung NIO `-XX:MaxDirectMemorySize=64m` di wrapper (Tahap 2a: `-Xmx256m` saja TIDAK cukup; tanpa batas memori langsung puncak anon JVM pada 1 CPU terukur 406 MiB untuk APK 60.000 entri ≈ 1,0 GB). Kini TERUKUR di sandbox (di luar cgroup, 1 CPU): lihat "Ukuran terbesar yang teruji" di bagian Tahap 2a; di bawah cgroup 512m BELUM DIUJI (V7).
`--enable-native-access=ALL-UNNAMED` di wrapper mencegah peringatan conscrypt pada JDK baru.

**Pemecahan masalah:** `libc++.so: cannot open shared object file` → `libc++.so` harus berdampingan di `/opt/build-tools/lib64/` (RUNPATH `$ORIGIN/lib64`). Jangan percaya `ldd /usr/local/bin/zipalign`
(symlink) yang selalu melaporkan `not found`; periksa `ldd /opt/build-tools/zipalign` atau jalankan `zipalign` langsung. `unknown flag: --profile` → Compose terlalu lama (butuh v2).

### Keystore penanda tangan (Tahap 1)
`make init` membuat kunci penanda tangan APK sekali saja: `secrets/signing_keystore.p12` (PKCS12, RSA 3072, `SHA256withRSA`, alias `reverse-apk`, berlaku 30 tahun) dan `secrets/signing_keystore_pass` (kata sandi acak 64 heks). `keytool` dijalankan di dalam image `signer` (server **tidak** perlu JDK), tanpa jaringan, rootfs read-only, tanpa capability, sebagai user host. Kata sandi tidak pernah menjadi argumen proses/variabel lingkungan. Skrip **tidak pernah menimpa**: jika kedua berkas sudah ada ia hanya berkata "sudah ada"; jika hanya satu yang ada ia berhenti (kode 2) tanpa mengubah apa pun. **Koreksi Tahap 2a:** keystore kini dipasang ke layanan `signer` (HANYA signer) lewat berkas tambahan `docker-compose.keystore.yml`, tetap tidak ada di `docker-compose.yml` dasar; mode berkas berubah dari 600 menjadi 644 di folder `secrets/` 700 — keputusan sadar, lihat "Signer-daemon & akses kunci (Tahap 2a)".

**Langkah di VPS** (pembaruan dari kode yang sudah berjalan):
```bash
git pull --ff-only
make init                 # idempoten; membangun image signer bila belum ada (butuh jaringan sekali), lalu membuat keystore bila belum ada
make keystore-info        # alias, algoritma, masa berlaku, SHA-256 (tanpa kata sandi)
ls -la secrets/           # harus ada signing_keystore.p12 dan signing_keystore_pass, keduanya -rw-r--r-- (644) milik user deploy; folder secrets/ drwx------ (700)
```
Hasil yang diharapkan: `✓ keystore dibuat` (pertama kali) dengan `3072-bit RSA key`, `SHA256withRSA`, `Berlaku ... until ... 2056`; `make init` kedua kali: `✓ keystore sudah ada ... tidak diubah` dan sidik jari SHA-256 yang SAMA di `make keystore-info`. `make doctor` menampilkan `✓ keystore penanda tangan ada (mode 644/644, folder 700); pastikan sudah dicadangkan` (Tahap 1 menampilkan `mode 600/600`; berkas lama mode 600 diperbaiki otomatis oleh `make up`/`make restart`/`make keystore-access`, isinya tidak berubah).

**CADANGKAN SEKARANG** (di luar server, mis. pengelola kata sandi atau penyimpanan terenkripsi): `secrets/signing_keystore.p12` **dan** `secrets/signing_keystore_pass`. Keduanya dibutuhkan bersama; simpan juga sidik jari SHA-256 dari `make keystore-info` untuk memeriksa pemulihan.
**Apa artinya kehilangan kunci:** tidak ada cara memulihkan. Anda harus membuat kunci BARU (pindahkan berkas yang tersisa ke tempat lain secara manual, lalu `make keystore`). APK yang sudah terpasang di perangkat dengan kunci lama TIDAK bisa diperbarui oleh APK bertanda tangan kunci baru (Android menolak pembaruan dengan tanda tangan berbeda): aplikasi harus dicopot dulu dan data aplikasinya hilang; tanda tangan semua build lama juga tidak lagi cocok dengan yang baru. Sebaliknya, siapa pun yang memegang kedua berkas ini bisa menandatangani APK atas nama kunci ini: jaga folder `secrets/` tetap mode `700` (berkas 644 hanya aman di dalamnya; lihat Tahap 2a) dan jangan masukkan ke repo/chat/tiket. Kunci ini untuk riset pribadi, bukan kunci rilis.

**Kemungkinan kegagalan** (pesan dari `scripts/keystore.sh`; tidak ada berkas yang dibuat bila gagal):
| Gejala | Penyebab / tindakan |
|---|---|
| `Tidak bisa membuat direktori kerja di .../secrets` | `secrets/` dimiliki root (mis. dibuat Docker sebelumnya). `sudo chown -R "$(id -u):$(id -g)" secrets` lalu ulangi |
| `keytool gagal membuat keystore` dan `Cannot find file: /out/pass` | kontainer (user host) tidak bisa membaca/menulis direktori kerja di `secrets/` (izin, SELinux, atau Docker rootless/userns-remap yang memetakan uid lain). Perbaiki kepemilikan/konteks lalu ulangi; sisa `secrets/.keystore-work.*` dihapus sendiri oleh skrip |
| `Image reverse-apk-signer belum ada dan .env belum ada` | jalankan `make init` (bukan `make keystore`) pada instalasi baru |
| `Gagal membangun image signer` | butuh jaringan sekali (apt + unduh Build-Tools, hash diverifikasi); coba `docker compose --profile build build signer` untuk melihat galat lengkap |
| `Image ... tidak ditemukan setelah build` | nama project Compose di-override (`COMPOSE_PROJECT_NAME`); jalankan `SIGNER_IMAGE=<nama> make keystore` (cek `docker images \| grep signer`) |
| `HANYA signing_keystore... yang ada (pasangannya hilang)` (kode 2) | salah satu berkas hilang. Pulihkan dari cadangan; JANGAN buat baru kecuali memang rela kehilangan kunci lama |
| `ada sisa direktori kerja keystore` (dari `make doctor`) | proses terputus keras; aman dihapus `secrets/.keystore-work.*` bila tidak ada `make keystore` yang sedang berjalan |

**Jumlah build yang disimpan:** `BUILD_KEEP` di `.env` (bawaan 10 per analisis; opsional, lihat `.env.example`). Belum berefek sampai tahap build ada.

### Signer-daemon & akses kunci (Tahap 2a)
Tahap 2a menambah **`signer-daemon`** (`services/signer/signer-daemon`): proses di kontainer `signer` yang menerima permintaan lewat antrean berkas `signspool` (volume `signspool`, protokol `rvcore/signspool.py`) dan menandatangani `builds/<analisis>/<build>/unsigned.apk` (jalur dibentuk HANYA dari dua bilangan bulat; isi permintaan tidak pernah menjadi jalur). Alurnya: `zipalign` → `apksigner sign` dengan keystore pemilik (kata sandi lewat `--ks-pass file:`, tidak pernah argv/env/log/hasil) → `apksigner verify` → sertifikat penanda tangan HARUS sama dengan sidik jari keystore pemilik → `signed.apk` (tepat satu penanda tangan, v2 dan v3 benar). Kontainer tetap tanpa jaringan, rootfs read-only, uid 10001, `cap_drop: ALL`, `no-new-privs`, `mem_limit: 512m`, `/tmp` tmpfs `noexec`. **Belum ada** tahap `build` di runner/worker, UI, tool AI, dan persetujuan manual yang memanggil signer (Tahap 2b dan seterusnya).

**Keputusan akses kunci (risiko utama #1): berkas keystore mode 644 di dalam folder `secrets/` mode 700 — sebuah KOMPROMI yang disadari.**
Compose mengisi secret bentuk `file:` sebagai bind-mount dan **mengabaikan** `uid`/`gid`/`mode` (fakta K1 di bawah), sehingga berkas yang dibuat user host (uid 1000) dengan mode 600 TIDAK bisa dibaca `signer` yang berjalan sebagai uid 10001 (`Permission denied`; terbukti pada peniruan kontainer di sandbox, lihat `audit.md` §10.17). Pilihan **[A]**: `secrets/` tetap 700 dan `signing_keystore.p12` + `signing_keystore_pass` menjadi **644**; kerahasiaan kini bertumpu pada izin FOLDER, bukan berkas (pola yang sama dengan `admin_password_hash`, yang sudah berjalan di VPS). Yang bisa membaca kunci di host: pemilik dan root; kontainer lain tidak memasang berkas itu (hanya `signer`). Bila folder `secrets/` dibuka (`chmod 755 secrets`), kunci 644 terbaca user lain: itu dijaga `make doctor` dan `make signer-verify` (GAGAL keras, kode 11) dan diperbaiki otomatis oleh `make up`/`make restart`/`make keystore-access` (hanya `chmod`, isi berkas tidak berubah).
Alternatif yang DITOLAK:
| Alternatif | Mengapa ditolak |
|---|---|
| B. volume bernama berisi salinan kunci milik 10001 (helper berhak mengisi) | menambah kontainer root + `CAP_CHOWN`/`DAC_OVERRIDE`, dua salinan kunci yang bisa menyimpang dan tidak ikut cadangan pemilik, harus diulang tiap kunci diganti |
| C1. secret dari `environment`/`content` (uid/gid/mode berfungsi) | MUSTAHIL: Compose menolak secret jenis itu untuk service `read_only: true`; selain itu kunci masuk `.env`/environment |
| C2. ACL `setfacl -m u:10001:r` pada berkas 600 | paling sempit, tetapi butuh paket `acl` + filesystem yang mendukung, hilang pada `cp`/cadangan yang membuang xattr, dan tidak bisa dibuktikan di sandbox. **Tidak jadi jalur utama; tetap boleh sebagai opsi manual pemilik** (kode tidak bergantung padanya) |
| C3. `signer` dijalankan sebagai uid host | volume `builds`/`signspool` dimiliki 10001: signer tak bisa menulis, dan `signed.apk` milik uid lain tak bisa dihapus (pelajaran izin volume yang sama dengan runner) |
| C4. `sudo chown 10001` pada berkas | `deploy` tak bisa lagi `keystore-info`/mencadangkan tanpa sudo; sudo tidak pasti ada |
| C5. entrypoint root yang menyalin ke tmpfs lalu menurunkan hak | butuh `SETUID/SETGID/CHOWN` dan tanpa `no-new-privileges`: membatalkan hardening signer |

**Perintah dan alur:**
| Perintah | Fungsi |
|---|---|
| `make keystore-access` | memastikan `secrets/` 700 dan kedua berkas keystore 644 (verbose: tabel sebelum→sesudah + penjelasan kompromi); hanya `chmod`, hanya berkas biasa milik sendiri |
| `make signer-verify` | bukti end-to-end 20 langkah (tabel `LANGKAH \| STATUS \| KETERANGAN`, kode keluar 0/1/64): APK uji ditandatangani lewat spool, verifikasi independen di kontainer, kasus negatif, kebocoran sandi, memori. `BIG_MB=1000 make signer-verify` menambah APK besar (langkah 17); tempel tabelnya ke chat bila ada GAGAL |
| `make up` / `make restart` | memanggil `scripts/keystore.sh access --auto` (satu baris bila ada yang diperbaiki; tidak pernah menggagalkan `up`) dan memuat berkas tambahan hanya bila keystore ada |
Berkas tambahan `docker-compose.keystore.yml` HANYA menambah secret dan label stempel ke `signer` (tes menjaga: tidak ada kunci lain, tidak ada `volumes`/`tmpfs`/`read_only`/`cap_add`/`user`/`network_mode`). Makefile memuatnya lewat `COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml` dan `COMPOSE_PROFILES=build` HANYA bila kedua berkas keystore ada. **Memakai `docker compose` langsung (tanpa `make`)** perlu mengekspor keduanya secara manual, dan hanya bila keystore ada: `export COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml COMPOSE_PROFILES=build`. Tanpa itu `signer` berjalan TANPA kunci (`/run/secrets` kosong): daemon tetap hidup tetapi **UNHEALTHY dengan alasan** (`docker inspect --format '{{json .State.Health.Log}}' $(docker compose ps -q signer)`) dan menjawab permintaan dengan `keystore_missing`. Berkas tambahan tidak pernah dimuat tanpa keystore karena Compose gagal membuat kontainer yang merujuk berkas secret yang tidak ada.
**Keadaan kunci basi (`stale`).** Bind-mount berkas mengunci INODE-nya: bila `secrets/signing_keystore.p12` atau `..._pass` DIGANTI (`mv`, `cp --remove-destination`, `rsync`, pemulihan dari cadangan), kontainer lama tetap memegang berkas lama. Dua lapis menanganinya: label `reverse-apk.keystore-stamp` (inode-ukuran-mtime) berubah sehingga `up -d` membuat ulang `signer`, dan daemon mendeteksi `st_nlink == 0` lalu melaporkan `keystore_stale` (UNHEALTHY). **Setelah mengganti atau memulihkan berkas kunci, SELALU jalankan `make restart`.** (`chmod` di tempat tidak membuat kunci basi: daemon memeriksa ulang tiap ≤ 10 dtk dan pulih sendiri.) Pembuatan ulang kontainer lewat label belum terbukti di Compose VPS (V11); cadangannya `docker compose up -d --force-recreate signer`.
**Disk.** Penandatanganan membutuhkan ruang di volume `builds`: ≈ 2× ukuran APK + 16 MiB + cadangan 1 GiB bebas (3,2 GiB untuk batas 1100 MiB; 3,0 GiB untuk APK 1 GiB; `BIG_MB=1000 make signer-verify` butuh bebas ≥ 3040 MiB, kurang → langkah 17 DILEWATI dengan angka). Sisa berkas job lama dibersihkan SEBELUM pemeriksaan ruang, jadi sisa itu tidak menimbulkan `no_space` palsu. Batas ukuran masukan: `SIGN_MAX_MB` (bawaan 1100) dan tenggat `SIGN_TIMEOUT` (bawaan 900 dtk), keduanya opsional di `.env` (lihat `.env.example`).

**Fakta Compose yang diperiksa (rentang v2.20.0 … v5.6.0; dibaca dari kode sumber, bukan dari `docker compose` di sandbox):**
- **K1.** Secret bentuk `file:` = bind-mount; `uid`/`gid`/`mode` pada sintaks panjang **diabaikan**. Peringatan `secrets uid, gid and mode are not supported` ada di sebagian versi (v2.23.0 … v5.0.0 yang diperiksa) dan tidak ada di v2.20.0 maupun v5.6.0; perilakunya (diabaikan) sama di semuanya. Karena itu berkas tambahan memakai sintaks pendek.
- **K3.** Mode/pemilik di dalam kontainer = mode/pemilik berkas host apa adanya (logika bind-mount + peniruan di sandbox; untuk p12 di Docker nyata BELUM TERBUKTI — V8).
- **K6.** `up`/`run` layanan yang merujuk berkas secret yang hilang gagal membuat kontainer itu (tanpa membuat direktori pengganti); belum terbukti apakah seluruh `up` ikut gagal (V2). Itu sebabnya berkas tambahan tidak pernah dimuat tanpa keystore.

**Risiko yang diketahui (WAJIB dibaca sebelum Tahap 2b):**
- **STATUS 2b (FEAT C): R3 dan R10 DITUTUP di kode** sebelum runner diberi tulis ke `builds`. Signer menyalin `unsigned.apk` SEKALI dari satu fd (`O_NOFOLLOW|O_NONBLOCK`, berkas biasa, `nlink==1`) ke ruang kerja PRIVAT `signwork/<job>/` (volume yang tidak dipasang ke runner), menolak `input_unsafe` bila hash salinan != `expect_sha256` (hash dari runner, di request) SEBELUM `zipalign`/`apksigner` berjalan, melakukan align/sign/verify di `signwork`, lalu menerbitkan ke `builds` dengan `.sign-signed.tmp` (`O_CREAT|O_EXCL|O_NOFOLLOW`) + rename atomik dan MEMBACA ULANG `signed.apk` (berkas biasa, `nlink==1`, hash sama). Yang TIDAK dicegah (terdeteksi, bukan dicegah): runner yang terkompromi dapat mengubah `signed.apk` SETELAH terbit; hash di DB dihitung ulang oleh worker (Tahap 2b D) dan unduhan Tahap 5 wajib salin-lalu-hash. Bukti: `tests/test_signer_race.py` (balapan nyata, termasuk dua proses uid 10001 dan alat NYATA) dan `verification.md` FEAT C. Teks asli risiko (untuk riwayat) di bawah.
- **R3 — uid yang sama (10001) untuk semua penulis volume `builds`.** Pada 2a hanya worker dan signer yang menulis, jadi tidak ada eskalasi. Dua jenis perlombaan ada bila penulis lain diberi akses: (1) symlink diselipkan sebelum alat membuka jalur; (2) `.sign-signed.tmp` ditukar antara `verify` dan penerbitan sehingga berkas yang tidak terverifikasi terbit sebagai `signed.apk` dengan `ok:true`. **WAJIB ditutup sebelum runner diberi akses tulis ke `builds` di 2b** (kandidat: verifikasi lewat `/proc/self/fd/N` + `os.link` pada inode yang sama, atau subdirektori keluaran yang hanya dapat ditulis signer).
- **R10 — signer adalah *oracle penandatanganan*** bagi siapa pun yang dapat menulis `builds/` dan `signspool/`: mereka dapat membuat signer menandatangani APK APA PUN dengan kunci pemilik. Itu inheren pada fungsi signer; pembatasan siapa yang boleh meminta ada di lapis worker/web (2b). `signed.apk` bukan bukti bahwa isinya berasal dari tahap `build`.
- Kerahasiaan kunci kini bertumpu pada folder `secrets/` 700 (di atas); `apksigner`/`zipalign` memproses APK tak tepercaya di kontainer yang memegang kunci uji (bukan kunci rilis), terkurung seperti runner.

**Ukuran terbesar yang teruji: 1.055.300.391 B** (`unsigned.apk` 60.000 entri + `META-INF`; hasil `signed.apk` 1.060.235.748 B), melalui daemon nyata di sandbox, 1 CPU (`taskset -c 0` + `-XX:ActiveProcessorCount=1`), **di luar cgroup**. Puncak `RssAnon` terukur (pemotret `/proc` 20 ms): `apksigner sign` 291,4–294,6 MiB (60.000 entri; 184,8 MiB untuk satu entri 1.048.580.116 B), `apksigner verify` 99,2–103,4 MiB, `zipalign` 24,9 MiB, daemon Python 11,8 MiB; 14 thread JVM; `sign` 16–23 dtk. **Di bawah cgroup `mem_limit: 512m` BELUM DIUJI** (sandbox tidak punya controller memory): angka itu bukan bukti bahwa `signer` muat di 512 MiB; keputusannya ada pada V7.

**BELUM DIUJI (butuh Docker di VPS) — jalankan berurutan; salin keluarannya bila ada yang tidak sesuai.** Urutan: `git pull --ff-only` → `docker compose version` → `docker compose config -q` → `docker compose --profile build build signer worker` → `make up` → `make signer-selftest` → `make signer-verify`.
| # | Perintah di VPS | Hasil diharapkan | Gejala → diagnosis |
|---|---|---|---|
| V0 | `git pull --ff-only` | cabang fast-forward | "Not possible to fast-forward" → ada perubahan lokal; `git status` |
| V1 | `docker compose version` | v2.x atau v5.x | tidak ada subperintah `compose` → pasang Compose v2 (`--profile` dan `COMPOSE_FILE` multi-berkas butuh v2) |
| V2 | `docker compose config -q` lalu `COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml docker compose config -q`. Opsional (K5/K6): pindahkan SATU berkas keystore sementara, jalankan `COMPOSE_FILE=… docker compose --profile build run --rm --no-deps signer true`, kembalikan berkasnya, dan pastikan `ls -ld secrets/signing_keystore.p12` tidak berubah menjadi direktori | keduanya tanpa galat; `config` tidak mengeluh berkas hilang; `run` gagal dengan "bind source path does not exist" | galat YAML → baris yang disebut; bila Compose MEMBUAT direktori → `rmdir secrets/signing_keystore.p12` dan laporkan versi Compose (Makefile tidak pernah memuat berkas tambahan tanpa keystore) |
| V3 | `docker compose --profile build build signer worker` | build sukses; SHA-256 Build-Tools cocok; `ldd` OK; wrapper baru | `sha256sum` gagal → pin; `Unable to locate package` → jaringan; `COPY failed` → daftar COPY signer/worker |
| V4 | `make up` | stack naik; `signer` **healthy** ≤ 30 dtk (bila keystore ada) | `signer` UNHEALTHY → `docker inspect --format '{{json .State.Health.Log}}' $(docker compose ps -q signer)` memuat alasannya; izin volume `builds`/`signspool`: `docker run --rm -v reverse-apk_builds:/v alpine ls -ln /v` (harus milik 10001) |
| V5 | `make signer-selftest` | semua `[OK ]`; bagian kunci `[OK ]`; ringkasan 0 GAGAL | "terbaca uid 10001" GAGAL → `make keystore-access`; "`/data` hanya builds, signspool & signwork" GAGAL → volume salah pasang (2b: `signwork` harus ada); wrapper `MaxDirectMemorySize` GAGAL → image lama (build ulang) |
| V6 | `make signer-verify` | tabel semua `OK`, kode keluar 0 | per baris tabel; langkah 12 sertifikat beda → keystore lain terpasang (periksa `COMPOSE_FILE`); langkah 15 gagal → `O_NOFOLLOW` tak berlaku; langkah 18 gagal → **sandi bocor** (hentikan, ganti kunci: `make keystore` baru) |
| V7 | `BIG_MB=1000 make signer-verify` (bebas ≥ 3040 MiB di volume `builds`) | langkah 17a (1 entri), 17b (60.000 entri), dan 17c (60.000 entri + `META-INF`, v1 aktif) OK; langkah 19: `oom_kill=0` dan puncak `anon` < 400 MiB pada ketiganya | `oom_kill>0`/`signer` restart/"alat dimatikan (kemungkinan kehabisan memori 512m)" → turunkan `-Xmx`/`MaxDirectMemorySize` atau naikkan `mem_limit` (keputusan pemilik); lulus 17a tetapi gagal 17b/17c ⇒ `MaxDirectMemorySize` kurang atau hilang dari wrapper (`docker compose exec -T signer cat /usr/local/bin/apksigner`); `no_space` → `docker system df` |
| V8 | `docker compose exec -T signer sh -c 'ls -ln /run/secrets; id'` | dua berkas; `uid=10001` | berkas tak ada → `COMPOSE_FILE` tak memuat berkas tambahan (jalankan lewat `make`); mode 600 → V5 |
| V9 | `docker stats --no-stream` (saat/sesudah job) | signer PIDS < 128, MEM < 512 MiB | PIDS mendekati 128 → naikkan `pids_limit` (JVM) |
| V10 | `docker compose --profile build down && make up` | stack naik lagi | – |
| V11 | ganti inode berkas kunci pada SALINAN uji (`cp secrets/signing_keystore_pass secrets/pw.new && mv secrets/pw.new secrets/signing_keystore_pass`), lalu `docker compose exec -T signer stat -c '%h %i' /run/secrets/signing_keystore_pass`; langkah 5 `signer-verify`/`docker inspect` health; `make restart`; label `reverse-apk.keystore-stamp` berubah | `0 <inode lama>`; `keystore_stale`/UNHEALTHY; `signer` dibuat ulang dan sehat; label berubah | `1 <inode>` → deteksi `stale` tidak berfungsi: andalkan label + "selalu `make restart`"; tidak dibuat ulang → `docker compose up -d --force-recreate signer` |
| V12 | Ctrl+C saat `make signer-verify` langkah 10–16, lalu hitung proses `signer-selftest --watch` di kontainer | `0` dalam ≤ 10 dtk | `1` sesudah > 10 dtk → `docker compose exec -T` tak meneruskan EOF stdin; pemotret berhenti paling lambat pada 600 dtk; hapus: `docker compose exec -T signer touch /tmp/selftest-watch.stop` |
Tambahan yang juga BELUM DIUJI: pewarisan izin volume bernama baru `builds`/`signspool`; SELinux/ACL/userns-remap/rootless terhadap bind-mount berkas 644 (diagnosis: `ls -lnZ secrets/`, `docker info | grep -i userns`, `getfacl secrets/signing_keystore.p12`); argv alat di kontainer nyata (langkah 18: `argv_apksigner ≥ 1`, bila 0 hasilnya DILEWATI bukan bukti); `pids_limit: 128`/`cpus: 1` pada JVM nyata; `restart: unless-stopped` bersama `run --rm`. `docker compose config` tidak bisa dijalankan di sandbox pengembangan (Docker rusak), jadi semua yang menyangkut Compose nyata ada di daftar ini.


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
- `secrets/signing_keystore.p12` dan `secrets/signing_keystore_pass` (mode 644 DI DALAM folder `secrets/` mode 700 sejak Tahap 2a; sebelumnya 600) adalah kunci penanda tangan APK: **cadangkan di luar server** dan jangan dibagikan. Kehilangan = kunci baru (lihat "Keystore penanda tangan"). Kerahasiaannya kini bertumpu pada folder 700: jangan `chmod 755 secrets` (lihat "Signer-daemon & akses kunci (Tahap 2a)").
- Aplikasi terbuka ke internet pada satu alamat; yang tampil ke publik hanya halaman login. Setelah HTTPS jalan,
  pertimbangkan Cloudflare Access di depannya (lihat PRD 07).
- Batasan memori/proses di `docker-compose.yml` (`mem_limit`, `pids_limit`) berlaku di VPS Linux biasa.
