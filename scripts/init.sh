#!/usr/bin/env bash
# Menyiapkan .env (dengan rahasia acak), folder secrets/, dan keystore penanda tangan APK. Aman dijalankan berulang kali:
# nilai yang sudah ada tidak ditimpa (keystore yang sudah ada TIDAK PERNAH dibuat ulang).
set -euo pipefail
cd "$(dirname "$0")/.."

rand_hex() { # rand_hex BYTES -> BYTES*2 karakter hex
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else # cadangan bila openssl tidak terpasang
    head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n'
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
  echo "• .env dibuat dari .env.example"
fi
chmod 600 .env

fill() { # fill KEY BYTES — isi hanya bila masih __GENERATE__
  local key="$1" bytes="$2"
  if grep -q "^${key}=__GENERATE__$" .env; then
    local value
    value="$(rand_hex "$bytes")"
    # Jangan pernah menulis nilai kosong/pendek: kegagalan harus terlihat, bukan diam-diam.
    if [ "${#value}" -ne $((bytes * 2)) ]; then
      echo "✗ Gagal membuat ${key} (hasil: ${#value} karakter, seharusnya $((bytes * 2)))." >&2
      exit 1
    fi
    sed -i "s|^${key}=__GENERATE__$|${key}=${value}|" .env
    echo "• ${key} dibuat"
  fi
}
fill SECRET_KEY 32
fill REDIS_PASSWORD 24

mkdir -p secrets
chmod 700 secrets
# File harus ada agar `docker compose` mau jalan; isinya diisi oleh `make password`.
[ -f secrets/admin_password_hash ] || { : > secrets/admin_password_hash; chmod 644 secrets/admin_password_hash; }

# Keystore dibuat lewat keytool di image `signer` (server tidak perlu JDK; butuh Docker). Gagal = init berhenti (gagal-tertutup); mengulang `make init` aman.
# Kunci dibuat mode 644 di dalam secrets/ (700) agar terbaca kontainer signer (uid 10001); `make up` memasangnya ke signer lewat docker-compose.keystore.yml.
./scripts/keystore.sh create

echo "Selesai. Langkah berikut: make password"
echo "Catatan: 'make up' memasang kunci ke signer (kunci mode 644 di folder secrets/ mode 700); jalankan 'make init' dan 'make up' sebagai dua perintah terpisah."
if [ -f secrets/signing_keystore.p12 ] && [ -f secrets/signing_keystore_pass ]; then
  echo "⚠ INGAT: cadangkan secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass di tempat aman. Kehilangan = kunci baru (aplikasi terpasang tidak bisa diperbarui)."
fi
