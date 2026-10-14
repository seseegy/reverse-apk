#!/usr/bin/env bash
# Tabel versi semua alat build/dekompilasi (java, apktool, jadx, keytool, zipalign, apksigner) dari image runner dan signer,
# dibandingkan dengan versi yang dipin di Dockerfile (dibaca dari ENV image, bukan disalin ke sini).
# Menjawab: "alat apa saja yang benar-benar terpasang di VPS, dan versinya sama dengan yang dikunci?"
# Ini bukti PEMASANGAN alat, bukan bukti isolasi: untuk isolasi pakai `make runner-selftest` dan `make signer-selftest`.
# Pemakaian: scripts/tools-check.sh   (lewat `make tools-check`; butuh Docker Compose v2 karena layanan signer memakai --profile)
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE="${COMPOSE:-docker compose}"

# Pra-periksa: --profile hanya ada di Docker Compose v2. Tanpa itu layanan signer (profil `build`) tidak dikenali.
# Galat `config` ditampilkan apa adanya (mis. .env belum ada -> variabel wajib kosong), bukan disembunyikan.
cfg_err="$(mktemp)"
if ! services="$($COMPOSE --profile build config --services 2>"$cfg_err")"; then
  echo "✗ '$COMPOSE --profile build config --services' gagal:"; sed 's/^/    /' "$cfg_err"; rm -f "$cfg_err"
  echo "  Bila pesannya soal variabel wajib kosong (APP_DOMAIN/SECRET_KEY/...), jalankan 'make init' dulu."
  echo "  Bila Compose tidak mengenal --profile, pasang Docker Compose v2."
  exit 1
fi
rm -f "$cfg_err"
if ! grep -qx signer <<<"$services"; then
  echo "✗ layanan signer tidak ada di docker-compose.yml (atau Compose Anda tidak mendukung --profile: butuh Docker Compose v2)."
  echo "  Periksa: $COMPOSE version   dan   $COMPOSE --profile build config --services"
  exit 1
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
echo "Membangun image runner dan signer (keluaran build disembunyikan kecuali gagal)..."
if ! { $COMPOSE build runner && $COMPOSE --profile build build signer; } >"$log" 2>&1; then
  cat "$log"
  echo "✗ build gagal"
  exit 1
fi

# Dijalankan DI DALAM kontainer. Satu baris per alat: nama|versi terpasang|pin. Rootfs read-only + tmpfs /tmp, seperti layanan aslinya.
runner_probe='mkdir -p "$HOME"
first() { head -n 1 | tr -d "\r|"; }
echo "java|$(java -version 2>&1 | first)|21"
echo "apktool|$(apktool --version 2>&1 | first)|${APKTOOL_VERSION:-?}"
echo "jadx|$(jadx --version 2>&1 | first)|${JADX_VERSION:-?}"
echo "keytool|$(keytool -version 2>&1 | first)|(ikut JRE 21)"'
signer_probe='mkdir -p "$HOME"
first() { head -n 1 | tr -d "\r|"; }
echo "java|$(java -version 2>&1 | first)|21"
echo "keytool|$(keytool -version 2>&1 | first)|(ikut JRE 21)"
echo "apksigner|$(apksigner --version 2>&1 | first)|Build-Tools ${BUILD_TOOLS_VERSION:-?}"
echo "zipalign|$(zipalign 2>&1 | first)|Build-Tools ${BUILD_TOOLS_VERSION:-?}"'

bad=0
rows=()
collect() { # image, perintah compose..., probe
  local image="$1" probe="$2"; shift 2
  local out
  if ! out="$("$@" sh -c "$probe" 2>"$log")"; then
    echo "✗ gagal menjalankan alat di image $image:"; sed 's/^/    /' "$log"
    bad=1
    return
  fi
  local line tool ver pin status
  while IFS='|' read -r tool ver pin; do
    [ -n "$tool" ] || continue
    case "$tool" in
      apktool|jadx) [[ "$ver" == *"$pin"* && "$pin" != "?" ]] && status="OK" || status="GAGAL" ;;
      java) [[ "$ver" == *'"21.'* ]] && status="OK" || status="GAGAL" ;;
      *) [ -n "$ver" ] && status="info" || status="GAGAL" ;;
    esac
    [ "$status" = "GAGAL" ] && bad=1
    rows+=("$tool|$image|${ver:-(kosong)}|$pin|$status")
  done <<<"$out"
}
# shellcheck disable=SC2086
collect runner "$runner_probe" $COMPOSE run --rm --no-deps -T runner
# shellcheck disable=SC2086
collect signer "$signer_probe" $COMPOSE --profile build run --rm --no-deps -T signer

{
  echo "ALAT|IMAGE|TERPASANG|PIN|STATUS"
  printf '%s\n' "${rows[@]+"${rows[@]}"}"
} | awk -F'|' '{ for (i = 1; i <= NF; i++) { c[NR, i] = $i; if (length($i) > w[i]) w[i] = length($i) } n = NR; f = NF }
     END { for (r = 1; r <= n; r++) { line = ""; for (i = 1; i <= f; i++) line = line sprintf("%-" w[i] "s  ", c[r, i]); print line } }'
echo
echo "OK = versi terpasang memuat pin; info = alat tanpa versi sendiri (zipalign/apksigner/keytool ikut paketnya); GAGAL = tidak jalan / tidak cocok."
echo "Ini bukan bukti isolasi: jalankan 'make runner-selftest' dan 'make signer-selftest'."
[ "$bad" -eq 0 ] || { echo "✗ ada alat yang gagal atau tidak cocok dengan pin"; exit 1; }
echo "✓ semua alat terpasang dan sesuai pin"
