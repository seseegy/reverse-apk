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
4. Uji isolasi alat dekompilasi:
   ```bash
   make runner-selftest
   ```
   Semua baris harus `[OK ]`, termasuk "jaringan terisolasi" dan "rootfs read-only". Perintah ini keluar dengan kode 0 hanya jika semua lulus.

## Operasi harian
| Tujuan | Perintah |
|--------|----------|
| Lihat log | `make logs` |
| Status kontainer | `make ps` |
| Update kode | `make update` |
| Ganti password | `make password` lalu `docker compose restart web` |
| Hentikan | `make down` (data tetap ada di volume) |

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

**Status "Worker" merah** → `docker compose logs worker`; biasanya Redis belum sehat. `make ps` harus menunjukkan semua `healthy`.

## Catatan keamanan
- `.env` dan `secrets/` tidak boleh di-commit (sudah ada di `.gitignore`). Izin: `.env` 600, `secrets/` 700.
- Aplikasi terbuka ke internet pada satu alamat; yang tampil ke publik hanya halaman login. Setelah HTTPS jalan,
  pertimbangkan Cloudflare Access di depannya (lihat PRD 07).
- Batasan memori/proses di `docker-compose.yml` (`mem_limit`, `pids_limit`) berlaku di VPS Linux biasa.
