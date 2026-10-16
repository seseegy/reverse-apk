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


### Build APK Tahap 2b: pipeline `bench → runner → signer` (status: terbukti di sandbox, BELUM DIUJI di Docker)
Tahap 2b menyambung semuanya: AI/pemilik mengubah pohon proyek di ruang kerja `bench`, pemilik **menyetujui secara manual** (CLI, dan sejak Tahap 5 juga tombol di tab Build; tidak ada tool AI atau mode otomatis untuk menyetujui, menandatangani, atau mengunduh; sejak Tahap 4 AI hanya dapat MEMBUAT permintaan `awaiting_approval`, lihat "Tool build AI (Tahap 4)"), worker membangun lewat `runner` (`apktool b`), `signer` menandatangani dengan keystore pemilik, lalu worker memverifikasi dan memberi nama artefak. Antarmuka pemilik = CLI di kontainer web: `docker compose exec -T web python -m app.buildctl <perintah>` dengan perintah `analyze`, `init`, `shell`, `diff`, `request`, `approve`, `status`, `wait`, `cancel`, `artifact-info`, `delete`. Keluaran skrip-ramah: baris `kunci=nilai` (kode keluar 0 = sesuai harapan, 3 = tidak sesuai/galat operasional, 64 = salah pakai). Bukti terpadu satu-perintah untuk pemilik: **`make verify-build`** (bagian di bawah); perintah `buildctl` juga dapat dijalankan manual.

**`make up` membangun ulang** image `web`, `worker`, `runner`, `bench`, dan `signer` (paket bersama `rvcore` bertambah `treediff.py`, `buildproto.py`, `Layout.bench/signwork`, `shellspool`, `signspool`). Setelah `git pull`, jalankan `make up` (bukan hanya `docker compose up -d`) supaya kode baru masuk ke image.

**Matriks mount final** (satu-satunya yang diizinkan; dijaga `tests/test_build_compose.py` yang mem-parse YAML). `rw`/`ro` = mode di compose, `–` = tidak dipasang:

| Volume | web | worker | runner | bench | signer | redis | caddy | egress |
|---|---|---|---|---|---|---|---|---|
| `uploads` | rw | ro | ro | ro | – | – | – | – |
| `work` | rw | rw | rw | ro | – | – | – | – |
| `files` | rw | – | – | – | – | – | – | – |
| `db` | rw | rw | – | – | – | – | – | – |
| `spool` | – | rw | rw | – | – | – | – | – |
| `bench` | rw (hanya menghapus) | – | **ro** | rw | – | – | – | – |
| `benchspool` | rw | – | – | rw | – | – | – | – |
| `builds` | rw | rw | rw | **–** | rw | – | – | – |
| `signspool` | – | rw | – | – | rw | – | – | – |
| `signwork` | – | – | – | – | rw | – | – | – |

Tambahan: keystore hanya ke `signer` (berkas `docker-compose.keystore.yml`); bind `./config` (`ro`) ke web dan `./deploy/Caddyfile` (`ro`) ke caddy. Runner: `bench` hanya `bench:ro` (runner tidak boleh mengubah pekerjaan AI), tanpa `benchspool`/`signspool`/`signwork`/`files`/`db`, tanpa jaringan, tanpa `secrets:`, tanpa Docker socket, uid 10001, `cap_drop: ALL`, `no-new-privileges`, `mem_limit: 3g`, `cpus: 2`, `pids_limit: 512`. Satu-satunya tmpfs `exec` di seluruh stack tetap `/opt/aapt-exec` milik runner (16m); `/tmp` runner `rw,size=256m,nosuid` tanpa `exec`. Volume baru mewarisi izin dari image (`mkdir -p` + `chown 10001` di Dockerfile pemasangnya).

**Penutupan R3/R10 (tingkat kode).** Signer tidak lagi bekerja di folder yang ditulis runner: `unsigned.apk` disalin sekali dari satu fd ke `signwork` (privat, hanya signer), hash dibandingkan dengan `expect_sha256` dari worker SEBELUM `zipalign`, lalu hasil diterbitkan atomik. Ini mencegah penukaran `unsigned.apk` setelah persetujuan; BUKAN jaminan bahwa keluaran `apktool` sama dengan yang disetujui (persetujuan mengikat isi pohon sumber, hash diff). 

**R-1 (sisa risiko, tidak dicegah di 2b).** Runner yang terkompromi (uid sama, `builds` rw) bisa mengubah `signed.apk` SETELAH diterbitkan. Perubahan itu tidak dapat membawa tanda tangan pemilik yang sah, dan hash di DB mendeteksinya. **Prasyarat Tahap 5 (unduh): unduh = salin-lalu-hash-lalu-bandingkan** — rute unduhan harus menyalin berkas ke tempat yang runner tidak bisa tulis, menghitung hash dari salinan itu, lalu membandingkannya dengan hash di DB; membaca langsung dari `builds` lalu mengirim tidak aman. Tahap 2b tidak punya rute unduh, jadi tidak menegakkannya.

**Konfigurasi.** `TIMEOUT_BUILD` (bawaan 1800 dtk, tahap runner) dan `TIMEOUT_SIGN` (bawaan 900 dtk) diteruskan ke `worker` dan `web` (web hanya menghitung `job_timeout` RQ = `TIMEOUT_BUILD + TIMEOUT_SIGN + 600`). Nilai efektif batas tanda tangan = **min(`TIMEOUT_SIGN`, `SIGN_TIMEOUT`)** karena signer juga membatasi dirinya sendiri; menaikkan salah satunya saja tidak memperpanjang batas. `BUILD_KEEP` (bawaan 10, klem 1–100) = jumlah build selesai yang disimpan per analisis; build yang berjalan/menunggu tidak dipangkas. Ketiganya ada di `.env.example`. `scripts/envcheck.sh` tidak perlu diubah: ia mengambil daftar variabel dari `${NAMA` di compose sehingga variabel baru terdeteksi otomatis.

**Konsekuensi satu runner + satu worker.** Build antre FIFO di belakang analisis (dan sebaliknya). Setelah tiap job runner keluar agar Docker memulai kontainer segar (`RUNNER_RECYCLE=1`). Jeda antar-job = waktu restart kontainer runner (hitungan detik). Koreksi klaim lama: `MIN_UPTIME_BEFORE_RECYCLE` (12 dtk, dihitung dari impor modul) hanya melindungi runner yang baru hidup dari backoff restart Docker; runner yang sudah lama menganggur keluar SEGERA setelah hasil ditulis. Premis keamanan tidak berubah: job berikutnya berjalan di kontainer segar.

**Penundaan fitur (menunggu konfirmasi pemilik).** FR-9.23 (berkas jejak `assets/reverse-apk-modified.txt`) DIKERJAKAN di 2b. FR-9.24 (`aapt2 dump badging`, pemeriksaan paket/versi) dan FR-9.41 (peringatan target SDK < 23) DITUNDA ke Tahap 5 (**kini dikerjakan di Tahap 5**, lihat “Build web Tahap 5”). Gerbang `done` di 2b = `apksigner verify` + sertifikat sama dengan keystore pemilik + `zipalign` + hash cocok. Alasan, opsi, dan pertanyaan ke pemilik ada di PRD 09 ("Keputusan tercatat Tahap 2b").

**`make verify-build` (Tahap 2b, FEAT G; BELUM DIUJI di Docker — hanya skrip + `docker` palsu di sandbox).** Satu perintah, SATU tabel `LANGKAH | STATUS | KETERANGAN` (OK/GAGAL/DILEWATI/INFO); kode keluar 0 = tanpa GAGAL, 1 = ada GAGAL / dihentikan / analisis uji TERTINGGAL, 64 = salah pakai. Dijalankan dari host oleh user biasa (mis. `deploy`, bukan uid 10001; host tanpa JDK): semua pekerjaan berisi dilakukan di kontainer, host tidak menulis/menghapus apa pun di volume. Aman diulang (APK sampel dibuat unik tiap run lewat `--uniq`; bila hash tetap `duplicate=1`, skrip BERHENTI tanpa menyentuh analisis milik pemilik) dan membersihkan analisis ujinya sendiri (`trap`: `cancel` build aktif → `wait` sampai final → `delete`; bila tak final dalam 120 dtk dicetak `analisis uji TERTINGGAL aid=<n>`). Prasyarat: stack sudah `make up`, keystore ada (`make keystore`), `testdata/vulnsample.apk` ada (`python3 scripts/sample-apk/build.py`; skrip itu dapat mencetak traceback `PermissionError` dari `TemporaryDirectory` yang sudah diketahui dan tidak menggagalkan APK). Opsional: `BIG_MB=<1..1100>` (hanya dicatat sebagai INFO), `VB_STRICT_DIFF=0` (langkah 8: selisih di luar allowlist hanya INFO; bawaan 1 = GAGAL. Allowlist memuat `original/META-INF/*` yang ditambahkan apktool, hasil pengukuran e2e T-3), `TIMEOUT_BUILD`/`TIMEOUT_SIGN` (menentukan batas tunggu `wait`). Tahap 3 menambah langkah 12a–12f (bagian "Build XAPK/APKS Tahap 3" di bawah) dan variabel `PYTHON3`.

| Langkah | Arti | Gejala bila GAGAL |
|---|---|---|
| 1 prasyarat | Compose v2; web/worker/redis/runner/bench/signer sehat; image memuat kode 2b; `bench-daemon --check` (Landlock); isolasi mount runtime lewat kontainer runner sekali pakai (tanpa signwork/signspool/benchspool/files/db, `bench` ro, `builds` rw); `signwork` hanya di signer | "image lama" → `make up`; `bench:ro` tidak berlaku → pelanggaran isolasi, hentikan stack |
| 2 analisis uji | `analyze - --uniq` lewat stdin; `duplicate=0`, `status=done` | `duplicate=1` (berhenti), analisis gagal/waktu habis, `terlalu_besar` |
| 3 init + diff kosong | salin baseline; dua `diff` kosong dengan hash sama; `init` ulang `created=0 reason=exists` | `bench_mati` (daemon bench), `Permission denied` di `bench` |
| 4 ubah string | `sed` lewat `buildctl shell` (bench + Landlock nyata) mengganti `app_name`; diff = tepat satu `M res/values/strings.xml` | shell gagal (Landlock/`AI_SHELL_ENABLED` tidak relevan), diff tidak 1 berkas |
| 5 negatif persetujuan | id tak ada → `build_tidak_ada`; hash salah → `diff_berubah`; `run_build` tanpa persetujuan tanpa kerja; `cancel` | persetujuan tidak terikat hash / eksekutor bekerja tanpa persetujuan (BERHENTI dan laporkan) |
| 6 build nyata | `request` → `approve` → `wait --trace`; OK bila `done`, `verify_ok=1`, sertifikat terisi, nama artefak sesuai pola, dan cap waktu DB monoton (`approved_at ≤ started_at < signing_mulai < finished_at`) | `no_space`, `timeout`, `workspace_changed` palsu, `signer_unavailable`, build antre lama (runner sibuk), `mem_limit` 3g |
| 7 verifikasi independen | `signer-selftest --check-apk`: `signers=1 v2=1 v3=1`, sertifikat = `make keystore-info`, `zipalign=ok`, sha256/ukuran sama dengan DB dan hash ulang disk | `cert` beda → keystore lain terpasang; sha beda → artefak berubah |
| 7b deteksi ubah-pasca-terbit | runner membalik 1 byte artefak → `artifact-info` harus kode 3 `hash_tidak_cocok`; dibalik lagi → `cocok=1` | kode 0 = deteksi R-1 TIDAK bekerja (jangan lanjut ke Tahap 5) |
| 8 isi artefak | `apktool d -f` artefak di runner lalu `treediff` vs `work/<aid>/apktool`: string baru ada, lama hilang, jejak memuat `asal_sha256`/`diff_sha256`; selisih di luar allowlist = GAGAL (bawaan; INFO dengan `VB_STRICT_DIFF=0`) | `apktool` gagal di runner (tmpfs `/tmp` 256m / `/opt/aapt-exec` 16m penuh) |
| 9 negatif TOCTOU | `approve --hold` → ubah workspace → lepas dengan hash lama → `failed/workspace_changed`, tanpa `unsigned.apk`/`src/` | build jalan padahal pohon berubah (BERHENTI dan laporkan) |
| 10 negatif pembatalan | `approve --hold` → `cancel` → `cancelled`, tanpa folder build | folder build tersisa |
| 11 retensi | dua build `done` tambahan lalu `builds.prune_for` NYATA di kontainer worker sekali pakai dengan `BUILD_KEEP=2`: tersisa tepat dua folder `done`, yang tertua hilang dari volume dan DB | `PermissionError` saat prune (pemilik volume ≠ uid 10001) |
| 12 kebersihan | `delete` → `deleted`, `builds_ada=bench_ada=work_ada=0`, tanpa `PermissionError` di keluaran/log web, `signwork/g<aid>-*` tak ada (INFO bila signer sibuk) | `busy` (build aktif), `sisa_direktori` (yatim, bersihkan lewat kontainer web, bukan dari host) |
| 13 ringkasan | total waktu dan daftar BELUM DIUJI | — |

**Gejala di VPS yang perlu diwaspadai (semua BELUM DIUJI di Docker).**
| Gejala | Diagnosis |
|---|---|
| Runner gagal membaca `bench` / `Permission denied` pada `/data/bench` | bind `bench:/data/bench:ro` atau izin volume baru: volume lama tanpa `mkdir`/`chown 10001` dari image baru; build ulang image runner (`make up`) lalu periksa `docker compose run --rm --no-deps -T runner ls -ln /data` |
| Runner BISA menulis ke `/data/bench` | mount `ro` tidak berlaku: periksa `docker compose config` (harus `read_only: true` pada mount itu) — ini pelanggaran isolasi, hentikan stack |
| `izin ditolak` menulis `builds`/`signwork` | volume baru dibuat sebelum image baru; hapus volume kosong atau perbaiki pemilik ke 10001 lewat kontainer berhak (bukan dari host) |
| `workspace_changed` berulang | AI/pemilik masih menulis di ruang kerja setelah `request`; ajukan ulang setelah penulisan berhenti (gagal aman, disengaja) |
| Build lama tidak mulai | runner sibuk dengan analisis/job lain (satu runner); `status` menampilkan alasan antre |
| `build.log` penuh pesan `No space left` pada `/opt/aapt-exec` | tmpfs exec 16m penuh (aapt2 6,15 MiB; maksimum 2 salinan saat penggantian atomik) |
| Galat tulis di `/tmp` runner/signer | tmpfs `/tmp` 256m penuh |
| Runner terbunuh (OOM) / `exit 137` | `mem_limit: 3g` terlampaui; lihat `docker inspect` (`OOMKilled`) |
| `no_space` dari runner atau signer | disk kurang: runner butuh 2× ukuran + 1 GiB, signer butuh 2× ukuran APK + 16 MiB + 1 GiB di volume `signwork`/`builds`; angka konservatif dan TIDAK diukur pada 1 GiB |
| Build `timeout` | `build.log`, naikkan `TIMEOUT_BUILD` (ingat min(`TIMEOUT_SIGN`, `SIGN_TIMEOUT`) untuk tanda tangan) |

**Terbukti di sandbox (BUKAN Docker):** tes mem-parse `docker-compose.yml`/`docker-compose.keystore.yml` (matriks mount, mode, hardening, jaringan, tmpfs, env), tes unit/integrasi tiap modul dengan proses uid 10001 nyata (`setpriv`), `unshare -m`, tmpfs `noexec`, berkas milik uid lain; Redis = `fakeredis`. **BELUM DIUJI:** `docker compose config`/`up`/`build` (Docker di sandbox rusak), bind `ro` nyata terhadap runner, izin volume bernama baru, tmpfs dan cgroup (`mem_limit`, `pids_limit`, `cpus`), healthcheck, RQ/Redis nyata (hanya `fakeredis`), Landlock ABI v4 di VPS (sandbox v2), pewarisan izin pada VPS dengan user host `deploy`, serta semua angka memori/disk terhadap cgroup. Jangan mengklaim 2b "berfungsi di VPS" sebelum daftar itu dijalankan.

### Build XAPK/APKS Tahap 3: split APK (status: terbukti di sandbox, BELUM DIUJI di Docker dan di perangkat)
Tahap 3 memperluas pipeline 2b ke paket **XAPK** dan **APKS**: base dibangun ulang seperti APK biasa, SETIAP split lain dibuang sisa tanda tangan lamanya, di-`zipalign`, dan ditandatangani ulang dengan **kunci pemilik yang sama** (Android mensyaratkan satu sertifikat untuk semua split satu sesi pasang). Keluaran = **format asal** (XAPK→XAPK, APKS→APKS, APK→APK) berisi extras utuh (`manifest.json`, ikon, OBB, `toc.pb`) ditambah satu skrip teks `<nama>-modified-<id>-install.sh` berisi perintah `adb install-multiple`. Aplikasi ini **tidak memanggil adb** dan tidak punya perangkat/emulator; skrip hanya teks yang disalin pemilik dari folder build di server (`builds/<analisis>/<build>/`), **tanpa tautan unduh atau tombol web** (baru Tahap 5). Persetujuan tetap manual lewat CLI, AI tetap tanpa tool setujui/tanda tangan/unduh, runner dan signer tetap tanpa jaringan, batas upload tetap `MAX_UPLOAD_MB` (bawaan 200 MiB; 1 GB = Tahap 6).

**Batas jujur (tidak bisa dijanjikan 100%).** Aplikasi dengan anti-tamper, packer, Play Integrity/SafetyNet, pemeriksaan tanda tangan di dalam kode, atau pemeriksaan hash `.so`/dex dapat menolak berjalan setelah dimodifikasi dan ditandatangani ulang dengan kunci lain. Persetujuan hanya atas diff base; split tidak dimodifikasi. Aplikasi asli yang sudah terpasang harus dihapus lebih dulu (tanda tangan berbeda); skrip tidak melakukannya. Perubahan `package`/`versionCode` base oleh AI membuat set tak terpasang (hanya diperingatkan). **BELUM DIUJI:** pemasangan nyata `adb install-multiple` pada perangkat Android 12+ milik pemilik (semua klaim kompatibilitas = ASUMSI sampai pemilik menempel hasilnya), XAPK/APKS nyata dari toko dengan OBB, split fitur bundletool nyata, memori/laju pada paket besar.

**Cadangkan kunci di LUAR VPS.** `secrets/signing_keystore.p12` dan `secrets/signing_keystore_pass` hanya ada di VPS ini (tidak di Git). Salin keduanya sekarang ke penyimpanan terenkripsi di luar VPS (pengelola kata sandi/brankas). Bila hilang, build berikutnya memakai kunci baru: aplikasi hasil build lama tidak bisa diperbarui di tempat oleh build baru (tanda tangan berbeda → Android menolak), pemilik harus uninstall lalu pasang ulang dan data aplikasi hilang.

**Konfigurasi.** Satu env baru: `SIGN_MAX_TOTAL_MB` (signer; bawaan 3072, klem 1–16384; jumlah byte semua berkas satu set; `SIGN_MAX_MB` tetap batas per berkas) di `.env.example`. Batas bongkar paket `ZIP_MAX_ENTRIES`, `ZIP_MAX_UNCOMPRESSED_MB`, `ZIP_MAX_ENTRY_MB`, `ZIP_MAX_RATIO` dibaca di tiga layanan (**web, runner, worker**) dan bawaannya harus sama; menaikkannya berarti mengubah compose di ketiganya (satu sisi saja membuat paket lolos unggah lalu gagal di build). Salinan upload memakai `memfd` (runner ≤ 512 MiB, worker ≤ 256 MiB; kecukupan `mem_limit: 512m` worker adalah ASUMSI yang belum diukur); `ASSEMBLE_TIMEOUT` (1200 dtk) dan tambahan tenggat job RQ untuk paket (3800 dtk di atas `TIMEOUT_BUILD`+`TIMEOUT_SIGN`) adalah hitungan, bukan pengukuran. `BUILD_KEEP=10` per analisis ikut menghapus seluruh set (paket, skrip, `build.log`): 10 paket besar dapat memakai puluhan GiB.

**Pembuat sampel.** `scripts/make-test-bundles.py` (stdlib, python3 di host) membuat XAPK/APKS uji dari `testdata/vulnsample.apk` ke folder sementara; TIDAK memuat material kunci (tanda tangan dibuat signer saat build; "META-INF basi" di split hanyalah byte sampah bernama `BNDLTOOL.*`). Hasil di `testdata/` di-ignore Git. `PYTHON3=/jalur/python3 make verify-build` bila python3 host bukan `python3`.

**`make verify-build` diperluas (tabel TETAP satu; langkah 1–13 tidak berubah selain baris ringkasan).** Langkah baru di antara 12 dan 13. Bila 12a GAGAL, 12b–12f DILEWATI; 12b–12e dilewati juga bila analisis uji langkah 2 belum bersih; 12f berdiri sendiri. Kegagalan 12b/12e tidak menggagalkan satu sama lain.

| Langkah | Arti | Gejala bila GAGAL |
|---|---|---|
| 12a prasyarat paket | `python3` host dan `scripts/make-test-bundles.py` ada; `signer-selftest` punya `--check-bundle`; runner dan worker memuat modul Tahap 3 dan `memfd_create` bisa dipakai; sampel XAPK, APKS, dan split lepas dibuat | "image ... lama" atau `--check-bundle` tak ada → `make up` lalu ulangi; `memfd_create tidak tersedia` (di build menjadi `memfd_unavailable`) → seccomp/kernel kontainer; `python3 tidak ada` → pasang atau `PYTHON3=`; pembangkit gagal → pesan stderr-nya ikut dicetak |
| 12b XAPK build | `analyze - --uniq --name vb-sampel.xapk` → `init` → ubah string lewat shell → `request`/`approve`/`wait`; OK bila `done`, `verify_ok=1`, `source_kind` dan `output_format` = `xapk`, nama `*-modified-<id>.xapk`, skrip `*-install.sh` terbit | `error_code` dan `petunjuk`/`split_gagal` dari `status` dicetak (mis. `split_invalid`: split rusak/terenkripsi; `bundle_invalid`: susunan paket; `bundle_changed`: upload berubah; `sign_*`: tanda tangan; `no_space`); `output_format` ≠ `xapk` = format asal tidak terjaga; `verify_ok` ≠ 1 = ada berkas belum terverifikasi |
| 12c XAPK verifikasi | `signer-selftest --check-bundle` atas paket: tiap APK `signers=1 v2=1 v3=1 zipalign=ok sisa_ttd=0`, `cert_berbeda=1`, sertifikat semua berkas = sertifikat build di DB = keystore pemilik; nama dan jumlah APK dan extras sama dengan sampel | `sisa_ttd` > 0 = tanda tangan lama tersisa (DUGAAN v1 lama; jangan pasang); `cert_berbeda` > 1 atau `cert` ≠ keystore = split ditandatangani kunci lain (BERHENTI dan laporkan); `entri_apk`/nama beda = split hilang atau bertambah; `zipalign=gagal`; `kode=bukan_paket` = paket tak lolos pagar zip |
| 12d XAPK isi | tamu runner membuka paket (rantai-dirfd, `O_NOFOLLOW`): OBB dan ikon utuh, `manifest.json` sama kecuali `total_size`, extras = sampel + tepat satu `assets/uniq-*`; skrip install-multiple lolos `sh -n`; `artifact-info`: `skrip_cocok=1`, `skrip_lint=ok`, semua `split.N` `verifikasi=ok`; analisis uji dihapus bersih | `same ...: isi berbeda` = OBB/ikon berubah; `manifest ...` = manifest berubah selain `total_size`; `extras tak terduga/hilang`; `skrip_cocok=0` = skrip berubah setelah terbit; `skrip_lint` ≠ ok = baris di luar allowlist; `verifikasi=ttd_lama/rusak/tanpa_manifest` pada suatu split; `PermissionError`/`builds_ada` saat delete (pemilik volume ≠ uid 10001) |
| 12e APKS build+verifikasi | sama untuk APKS (`vb-sampel.apks`): alias `splits/base-master_2.apk` berbyte sama dengan base bertanda tangan, `toc.pb` utuh | gejala seperti 12b–12d; `alias ... tidak berbyte sama` = alias master tidak disalin dari base bertanda tangan |
| 12f negatif set | lewat `signcheck` (analisis sentinel 2147483000): split diganti → `input_unsafe`, split hilang → `input_missing`, split memuat `META-INF/OLD.RSA` → `stale_signature`, masing-masing tanpa `signed*.apk`; kontrol positif: set bersih ditandatangani dengan sertifikat pemilik | signer MENERIMA set cacat (kode lain/`ok`) = pagar `expect_sha256`/pindaian tanda tangan tidak bekerja (BERHENTI dan laporkan); `signed*.apk tersisa` = hasil cacat terbit; kontrol positif gagal = sampel/signer bermasalah (lihat `ALASAN`) |

Tambahan di ringkasan (13): daftar BELUM DIUJI kini memuat paket besar, XAPK/APKS nyata dari toko, `adb install-multiple` di Android 12+, dan aplikasi anti-tamper/packer/Play Integrity/hash `.so`.

### Tool build AI (Tahap 4): `make verify-build` 14a–14n, tanpa model dan tanpa kunci API

**Yang ditambahkan.** Tiga tool AI: `bench_diff` (daftar perubahan ruang kerja + `diff_sha256`, tanpa isi berkas), `request_build` (membuat build `awaiting_approval` dari diff SAAT INI; hash selalu dihitung ulang dari bench) dan `get_build_status` (status, tahap, kode galat + pesan tersanitasi, `artefak_tercatat` menurut DB, `verifikasi_tanda_tangan`, format/jumlah split; tanpa path, keystore, atau tautan unduh). Ketiganya **hanya ditawarkan bila `AI_SHELL_ENABLED=1`** (gerbang yang sama dengan `shell_run`; tidak ada env baru, jadi `.env.example` tidak berubah) dan hanya untuk analisis chat yang sedang dibuka. **AI tidak punya tool untuk menyetujui, membatalkan, menandatangani, mengunduh, atau membaca artefak. Persetujuan tetap HANYA lewat CLI pemilik** (`docker compose exec -T web python -m app.buildctl approve <build_id> --diff-sha256 <hash>`) sampai Tahap 5; sejak Tahap 5 tombol Setujui di tab Build juga bisa (lihat “Build web Tahap 5”), dan pemilik tetap menyetujui sendiri. Kebijakan: satu build aktif per analisis (permintaan identik yang masih menunggu dipakai ulang; yang lain `build_tertunda`), satu build baru per giliran, `get_build_status` maks. 3 kali per giliran, tanpa build dari diff kosong (`diff_kosong`). Bila AI mengubah berkas lagi setelah `request_build`, pemilik harus membatalkan permintaan lama (`buildctl cancel <id>`) sebelum AI bisa mengajukan yang baru. **Pratinjau isi berkas dilepas:** `bench_diff` hanya mengembalikan ringkasan (op A/M/D + path + `diff_sha256`); pratinjau unified-diff opsional per path yang ada di rancangan awal TIDAK diimplementasikan (menghindari permukaan perintah shell yang disusun server). Untuk melihat isi, AI memakai `shell_run`; pemilik memakai `buildctl diff`. **Runbook pemilik:** satu `request_build` dari AI menahan slot build aktif analisis itu sampai Anda menyetujui atau membatalkannya (AI tidak bisa membatalkan atau menggantinya). Nama berkas dari APK tampil ke model dan bisa dibuat menyesatkan; salin perintah `approve` dan hash HANYA dari keluaran `buildctl diff`/`buildctl status`, bukan dari chat, dan tinjau diff sendiri. Edit setelah `request_build` dalam giliran yang sama membuat hash lama, dan build gagal di runner (`workspace_changed`, aman/fail-closed).

**Perbarui VPS (pemilik, user `deploy`):**
```bash
cd ~/reverse-apk && git fetch && git checkout feat/ai-build-tools && git pull --ff-only && make up
sleep 60 && docker compose ps      # tunggu sampai semua healthy
make verify-build
```
Setelah PR digabung: `git pull --ff-only && make up` (bukan `docker compose build` saja: image `signer` ada di profil `build`).

**Pembantu tanpa LLM `app.aitoolcheck`.** Dipakai langkah 14a–14n; boleh dijalankan manual di VPS. Ia memanggil `tools.run_tool` dan `tools.schemas` (jalur kode YANG SAMA dengan chat: gerbang, pembungkus `<hasil_tool>`, batas keluaran, penghitung, audit), bukan implementasi paralel, dan tidak mengimpor `buildctl`/`builds`/`jobs` (dijaga tes AST). Keluaran hanya baris `kunci=nilai` (kode keluar 0 = tool sukses, 3 = tool menolak dengan `kode=<stabil>`, 64 = salah pakai):
```bash
docker compose exec -T web python -m app.aitoolcheck schema --shell 1
docker compose exec -T web python -m app.aitoolcheck call <analysis_id> bench_diff
docker compose exec -T web python -m app.aitoolcheck call <analysis_id> request_build [--args '{"diff_sha256":"<hex64>"}']
docker compose exec -T web python -m app.aitoolcheck call <analysis_id> get_build_status [--args '{"build_id":<id>}']
docker compose exec -T web python -m app.aitoolcheck audit-approvals <analysis_id>
```
`--shell` bawaan 1 (pembantu memaksa gerbang hidup supaya verifikasi tidak bergantung `.env`, seperti `buildctl shell`); `--shell 0` membuktikan gerbang menolak (`fitur_nonaktif`). Setiap `call` adalah satu giliran baru (penghitung per giliran mulai dari nol) dan memakai sesi chat terbaru analisis itu (dibuat sekali bila belum ada, dihapus bersama analisis).

**`make verify-build` diperluas (tabel TETAP satu).** Langkah 14a–14n dijalankan sesudah 12f dan sebelum baris ringkasan 13 (skrip tidak punya langkah 13 sebelum ringkasan; penomoran 14 mengikuti brief). Bila 14a GAGAL, 14b–14n DILEWATI; 14b–14e GAGAL menghentikan 14c–14m tetapi 14n tetap membersihkan; 14j DILEWATI bila langkah 6 tidak OK (jalur runner/signer tidak sehat) atau ruang kerja tidak kembali ke hash 14d; 14k DILEWATI bila sampel XAPK tidak dibuat (12a). Langkah ini membuat tiga analisis uji tambahan (bisa beberapa menit), semuanya dibersihkan `trap` seperti analisis utama.

| Langkah | Arti | Gejala bila GAGAL |
|---|---|---|
| 14a tool build: modul+skema | `app.aitoolcheck` jalan tanpa kunci API; `schema --shell 1` memuat tepat `bench_diff`, `request_build`, `get_build_status` dan tidak ada nama approve/sign/download/cancel/delete/artifact/init; `--shell 0` menyembunyikan ketiganya | "modul app.aitoolcheck tidak jalan" = image web lama → `make up` lalu ulangi; "tool … TIDAK ada" / "nama tool penyetujuan…" / "tool … muncul padahal shell=0" = skema atau gerbang salah (laporkan) |
| 14b tool build: analisis uji + bench_diff awal | `analyze - --uniq` + `init`; `bench_diff` awal 0 perubahan dan `diff_sha256` = `buildctl diff` | `bench_mati` = kontainer `bench` bermasalah (`make logs`); "beda dari buildctl diff" = tool tidak memakai diff kanonik yang sama |
| 14c tool build: request diff kosong | `request_build` pada diff kosong → `ok=0 kode=diff_kosong`, 0 build tercipta | "harus ditolak kode diff_kosong" atau "build terbentuk dari diff kosong" |
| 14d tool build: ubah via shell + bench_diff | `sed` lewat shell nyata; `bench_diff` = tepat satu `M res/values/strings.xml`, hash = `buildctl diff` | modified/added/removed salah, atau hash berbeda |
| 14e tool build: request_build | build `awaiting_approval` dengan hash 14d; `buildctl status` sama; tercatat diminta oleh AI | status lain, "beda dari hash bench_diff 14d", "tidak tercatat diminta oleh AI" |
| 14f tool build: permintaan kedua | hash model salah → `hash_tidak_cocok`; permintaan sama → `dipakai_ulang=1` (id sama, tanpa baris baru); perubahan baru → `build_tertunda`; tetap 1 build; ruang kerja dipulihkan ke hash 14d | salah satu kode di atas tidak muncul, atau jumlah build ≠ 1 |
| 14g tool build: get_build_status menunggu | `awaiting_approval`, `artefak_tercatat=0`, verifikasi kosong, `langkah_pemilik` memuat `buildctl approve`, `jangan_klaim_selesai=1` | bidang hilang atau bernilai lain |
| 14h tool build: negatif lintas analisis | build milik analisis lain (dibuat lewat `buildctl request`) diminta dari analisis uji → `build_bukan_milik_analisis` tanpa data build itu; id ngawur memberi kode DAN pesan identik | "mengembalikan data" / "tanpa oracle keberadaan" = cakupan analisis bocor (BERHENTI dan laporkan) |
| 14i tool build: tanpa tool persetujuan + gerbang | `approve_build`, `cancel_build`, `download_artifact` → `tool_tidak_ada`; `--shell 0` → `fitur_nonaktif`; semua build uji tetap `awaiting_approval` | tool persetujuan ada = pagar utama rusak (BERHENTI dan laporkan); status berubah setelah panggilan tool |
| 14j tool build: persetujuan pemilik -> selesai | skrip bertindak sebagai pemilik: `buildctl approve … --diff-sha256 …`, lalu `get_build_status` (dipoll) sampai `done`: `artefak_tercatat=1`, `verifikasi_tanda_tangan=1`, `source_kind=apk`, `jangan_klaim_selesai=0` | tidak mencapai `done` (kode_galat + pesan tersanitasi + petunjuk dicetak; lihat juga langkah 6), verifikasi bukan 1 |
| 14k tool build: permintaan XAPK | analisis XAPK uji → `init` → ubah → `request_build` → `awaiting_approval` dengan `source_kind=xapk`; dibatalkan pemilik (`buildctl cancel`), TIDAK disetujui | `source_kind` bukan `xapk` |
| 14l tool build: tanpa kebocoran | seluruh keluaran `aitoolcheck` 14a–14k tidak memuat `/data/`, `secrets`, `keystore`, `.p12`, `.jks`, `signing_`, `signwork`, `://`, maupun `output_name`/`output_sha256`/`cert_sha256` build 14j (hanya NAMA pola yang dilaporkan, bukan nilainya) | "pola:<nama>" = tool membocorkan hal yang dilarang (BERHENTI dan laporkan) |
| 14m tool build: pagar persetujuan | build uji hanya `awaiting_approval`/`cancelled` sebelum persetujuan pemilik; `audit-approvals`: jumlah `build_approved` = jumlah `buildctl approve` skrip (satu) dan `via=cli`; analisis pembanding/paket tanpa persetujuan | `via='ai'` atau jumlah tak cocok = ada jalur persetujuan selain pemilik (BERHENTI dan laporkan) |
| 14n tool build: kebersihan | cancel → wait → delete untuk semua analisis uji langkah 14 | `TERTINGGAL aid=<n>` (build masih aktif atau delete gagal); hapus manual dengan `buildctl cancel`/`delete` |

**Cek live opsional dengan model nyata (MANUAL, bukan syarat).** `make ai-check` (`docker compose run --rm --no-deps web python -m app.ai.check`) hanya menguji provider: konfigurasi, koneksi, streaming, tool calling bawaan, pelaporan token, gambar. Ia butuh kunci API di `.env`, memakai anggaran AI, dan **tidak menyentuh tool build**. Cek live tool build: nyalakan `AI_SHELL_ENABLED=1` (setelah `make bench-selftest` lulus; `docker compose up -d web`), `buildctl analyze` + `buildctl init <id>`, buka chat analisis itu dan minta perubahan kecil (mis. ganti `app_name`) lalu "ajukan build". Yang diharapkan: AI memakai `shell_run` → `bench_diff` → `request_build`, lalu BERHENTI dan meminta Anda menyetujui lewat CLI dengan perintah dan hash yang benar; ia tidak mengklaim "selesai" sebelum `get_build_status` = selesai. Perilaku model bisa berbeda; skrip `verify-build` tidak menguji model.

**BELUM DIUJI (butuh Docker VPS / model nyata):** semua langkah 14 di Docker nyata (sandbox: `docker` palsu + `app.aitoolcheck` diuji dengan bench palsu), bench/Landlock nyata untuk `bench_diff` dalam loop chat, RQ nyata, dan model nyata (apakah ia mengikuti alur di prompt). Batas jujur: anti-tamper, packer, Play Integrity, dan pemeriksaan hash `.so` bisa membuat APK hasil tidak berfungsi; tidak ada jaminan 100%.

### Build web Tahap 5: tab Build, layar persetujuan, unduhan (status: terbukti di sandbox, BELUM DIUJI di VPS)

**Yang ditambahkan.** Tab **Build** di halaman analisis (`/analyses/<id>/build`): daftar build, tombol **Siapkan ruang kerja** dan **Ajukan build dari ruang kerja**, dan per build **layar persetujuan** (ringkasan diff, berkas per jenis dari yang paling banyak berubah, saringan jenis/teks, penanda “diminta oleh AI”, pernyataan wewenang dengan kotak centang, tombol Setujui/Tolak/Batalkan). Persetujuan terikat pada hash diff dan hanya sah dari sesi login pemilik dengan CSRF; **CLI `buildctl approve` tetap ada** (audit `via=cli`; web = `via=ui`). AI tetap tidak punya tool untuk menyetujui, membatalkan, menandatangani, atau mengunduh. Build `done` punya tombol **Unduh** (APK/XAPK/APKS) dan, untuk paket, **skrip adb install-multiple**. Badging (paket, versionCode, versionName, minSdk, targetSdk) dibaca runner dengan `aapt2 dump badging` dari `unsigned.apk` dan tampil di halaman; target SDK < 23 diberi peringatan (Android 14+ menolak memasangnya), perbandingan dengan APK asal tidak memblokir.

**Unduhan = salin-lalu-hash-lalu-bandingkan.** Server menyalin berkas ke berkas anonim di `files/.tmp` (volume `files` tidak dipasang di runner), menghitung ulang SHA-256 dari SALINAN, membandingkannya dengan hash di DB, baru mengalirkannya. Hash tidak cocok → HTTP **409** dengan pesan jelas dan tanpa byte. Ruang disk kurang → 507; dua unduhan sudah berjalan → 503. Setiap unduhan yang lulus tercatat di audit (`build_download`: analisis, build, hash hasil, hash diff, ukuran, IP).

**Perbarui VPS (pemilik, user `deploy`):**
```bash
cd ~/reverse-apk && git pull --ff-only && make up      # image web, worker, dan RUNNER berubah (badging); jangan hanya `docker compose build web`
sleep 60 && docker compose ps                           # semua healthy
make runner-selftest && make verify-build               # regresi Tahap 2b-4 (34 baris OK)
```
Tidak ada variabel `.env` baru dan tidak ada volume/mount baru.

**Runbook verifikasi manual (menggantikan langkah `verify-build` 15x; BELUM ADA langkah otomatis).** Pembantu `app.webcheck` memakai sesi pemilik dari `SECRET_KEY` kontainer (tanpa password) dan mengirim permintaan ke web yang sedang berjalan; keluaran hanya `kunci=nilai`:
```bash
docker compose exec -T web python -m app.buildctl init <analysis_id>       # atau tombol “Siapkan ruang kerja”
docker compose exec -T web python -m app.buildctl shell <analysis_id> 'sed -i "s/Asli/Ubah/" project/res/values/strings.xml'
docker compose exec -T web python -m app.buildctl request <analysis_id>    # atau tombol “Ajukan build”; catat build_id
docker compose exec -T web python -m app.webcheck get /analyses/<aid>/build/<bid>                    # form_diff_sha256 = hash diff, has_checkbox=1
docker compose exec -T web python -m app.webcheck approve <aid> <bid> --no-statement                  # HARUS ditolak: location ...notice=pernyataan_wajib
docker compose exec -T web python -m app.webcheck approve <aid> <bid> --hash 0000000000000000000000000000000000000000000000000000000000000000   # HARUS ditolak: diff_berubah
docker compose exec -T web python -m app.webcheck approve <aid> <bid>                                 # disetujui: notice=disetujui
docker compose exec -T web python -m app.buildctl wait <bid>                                          # status done
docker compose exec -T web python -m app.webcheck get /analyses/<aid>/build/<bid>/download --save /tmp/hasil.apk   # sha256= harus sama dengan output_sha256 (buildctl status)
docker compose exec -T web python -m app.buildctl artifact-info <bid>                                 # cocok=1
docker compose exec -T web python -m app.webcheck get /analyses/<aid>/build/<bid>                    # halaman hasil memuat blok “Verifikasi APK hasil (badging)” (lihat di browser)
```
Uji negatif unduhan: ubah satu byte artefak sebagai runner (`docker compose exec -T -u 10001 runner sh -c 'printf X | dd of=/data/builds/<aid>/<bid>/<nama>.apk bs=1 count=1 conv=notrunc'`; kontainer runner memasang `builds` rw) lalu `webcheck get .../download` harus **status=409**; kembalikan byte aslinya. Terakhir buka tab Build di **browser**: layar persetujuan terbaca di ponsel, kotak centang wajib, polling memperbarui status tanpa reload manual.

**Gejala dan tindakan**
| Gejala | Penyebab paling mungkin | Tindakan |
|----|----|----|
| build gagal `badging_unreadable` | `aapt2 dump badging` gagal pada `unsigned.apk` (aapt2 tidak bisa dieksekusi di runner, batas 30 dtk, atau APK yang tak bisa dibaca aapt2) | `make runner-selftest` (cek 6a: aapt2 rootfs); `docker compose exec runner /opt/apktool/aapt2 version`; periksa `build.log`; ajukan build baru |
| unduhan 409 “Hash berkas TIDAK sama” | artefak berubah setelah terbit (runner terkompromi, disk rusak, atau uji negatif) | JANGAN pasang berkasnya; `buildctl artifact-info <bid>` (kode 3 `hash_tidak_cocok`); ajukan build baru; selidiki runner |
| unduhan 507 / 503 | `files/.tmp` kekurangan ruang / dua unduhan masih berjalan | kosongkan disk (`make storage`); coba lagi |
| tombol Setujui menjawab `diff_berubah` | build diajukan ulang/diganti sejak halaman dibuka | muat ulang halaman, tinjau lagi |
| halaman tidak memperbarui status | JS diblokir CSP/cache lama | muat ulang keras; `/static/js/build.js` harus 200 |
| setelah Setujui: “antrean tidak terjangkau” | Redis mati saat menyetujui; build `queued` tanpa job | `make up`, lalu “Kirim ulang ke antrean” |

**BELUM DIUJI:** semua di atas di Docker/VPS nyata; `aapt2 dump badging` nyata (format keluaran belum dicocokkan dengan aapt2 3.0.3), unduhan besar (waktu dan disk untuk APK ratusan MB sampai 1 GiB), browser nyata, pemasangan hasil di perangkat. Tidak ada jaminan hasil berfungsi pada aplikasi dengan anti-tamper, packer, Play Integrity, atau pemeriksaan hash `.so`; tanda tangan berbeda dari aslinya (aplikasi asli harus dicopot dulu).

### Limit AI, berhenti rapi, dan batas 1 GB (Tahap 6)
Tahap 6 menambah tiga variabel (`AI_SHELL_MAX_SECONDS_PER_TURN`, `AI_SHELL_MAX_TURN_OUTPUT_CHARS`, `AI_BUILD_MAX_PER_SESSION`; semuanya sudah diteruskan di `docker-compose.yml`) dan mengubah bawaan batas ukuran agar APK/XAPK hingga 1 GB tidak ditolak tanpa sengaja. Tabel sebelum/sesudah dan alasannya: PRD 09 "Status Tahap 6". Setelah `git pull`: `make up`, lalu `make env-check`.
- **Berubah (bawaan baru)**: `MAX_UPLOAD_MB` 1024, `ZIP_MAX_ENTRY_MB` 1024, `MAX_OUTPUT_MB` 6144, `BENCH_WORKSPACE_MAX_MB` 4096, `BENCH_FILE_MAX_MB` 1024, `SIGN_MAX_MB` 1280, `TIMEOUT_APKTOOL/JADX/ANALYZE` 600/2400/600, `JOB_TIMEOUT` 4500. `ZIP_MAX_*` dan `MAX_BASE_APK_MB` kini diteruskan compose (web, runner, worker memakai nilai yang sama). Caddy perlu dimulai ulang agar membaca `MAX_UPLOAD_MB` baru (`make restart` sudah mencakupnya).
- **Tidak berubah dengan sengaja**: semua `mem_limit` (VPS 8 GB), `JADX_HEAP`, `MIN_FREE_GB`/`JOB_MIN_FREE_GB`. Siapkan disk >= 60 GB bila memproses APK ~1 GB dan kecilkan `BUILD_KEEP` (10 paket besar = puluhan GiB).
- **Batas yang masih menolak**: build XAPK/APKS dengan unggahan > 256 MiB (`bundle_too_large`; salinan memori worker). Analisis paket 1 GB dan build APK tunggal tidak terkena.
- **Cara mengukur (BELUM DIUJI, tidak ada pengukuran di sandbox)**: unggah APK terbesar Anda; catat durasi tiap tahap di halaman analisis, `memory.peak` runner (`docker stats`), ukuran `work/<id>` dan `bench/<id>`; sesuaikan variabel yang menolak. Gejala: "keluaran terlalu besar" (`MAX_OUTPUT_MB`), "entri terlalu besar" (`ZIP_MAX_ENTRY_MB`), `input_too_large` (`SIGN_MAX_MB`), `tree_too_large`, `kuota` pada `buildctl init` (`BENCH_WORKSPACE_MAX_MB`), time out tahap jadx (`TIMEOUT_JADX`).
- **Chat**: kartu "berhenti karena batas" dengan tombol Lanjutkan, sisa anggaran sesi/harian, dan peringatan 80% ada di halaman Chat; tidak ada langkah `make verify-build` baru (tahap ini diuji dengan klien palsu, BELUM dengan model nyata).

## Upload besar dan Cloudflare
Batas ukuran APK diatur `MAX_UPLOAD_MB` di `.env` (bawaan 1024 sejak Tahap 6; sebelumnya 200). Nilai yang sama dipakai aplikasi dan Caddy.
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
