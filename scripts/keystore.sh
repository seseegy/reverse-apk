#!/usr/bin/env bash
# Keystore penanda tangan APK: dibuat sekali oleh `make init` (atau `make keystore`), TIDAK PERNAH ditimpa.
#   scripts/keystore.sh create   buat secrets/signing_keystore.p12 + secrets/signing_keystore_pass bila belum ada (idempoten)
#   scripts/keystore.sh info     cetak sidik jari SHA-256, DN, masa berlaku, algoritma (tanpa kata sandi)
#   scripts/keystore.sh status   ringkasan satu baris per pemeriksaan untuk `make doctor` (tanpa Docker/keytool)
#
# Server pemilik hanya punya Docker (tanpa JDK), jadi keytool dijalankan DI DALAM image `signer` (JRE 21), terkurung seperti layanan lain:
# tanpa jaringan, rootfs read-only, tanpa capability, user = user host (berkas hasil milik user host). Kata sandi dibuat langsung ke berkas
# mode 0600 dan diberikan ke keytool lewat `-storepass:file` / `-keypass:file`: TIDAK pernah menjadi argumen proses, variabel lingkungan, atau riwayat shell.
#
# Hanya direktori kerja sementara (secrets/.keystore-work.*) yang di-bind rw ke kontainer, bukan seluruh secrets/ (admin_password_hash tidak terlihat).
# Hasil dipublikasikan oleh HOST dengan `ln` (hard link: atomik dan GAGAL bila tujuan sudah ada, jadi tidak pernah menimpa): sandi dulu, p12 terakhir.
#
# Pada tahap ini keystore BELUM dihubungkan ke layanan mana pun di docker-compose.yml (itu pekerjaan signer-daemon berikutnya).
#
# Variabel lingkungan (semua opsional; untuk tes dan pengaturan khusus, bukan konfigurasi stack):
#   KEYTOOL_CMD   perintah keytool LOKAL (mis. /jalur/ke/keytool), tanpa Docker. Kosong = pakai Docker. Dipakai tes di mesin tanpa Docker.
#   SECRETS_DIR   lokasi berkas (bawaan: <repo>/secrets)
#   DOCKER_CMD    biner docker (bawaan: docker)
#   COMPOSE       perintah compose untuk membangun image (bawaan: docker compose)
#   SIGNER_IMAGE  nama image signer (bawaan: reverse-apk-signer; ganti bila COMPOSE_PROJECT_NAME di-override)
#
# Kode keluar: 0 sukses/sudah ada; 1 galat umum (keytool/docker gagal, alat hilang); 2 keadaan tidak konsisten atau balapan; 64 pemakaian salah.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly KS_FILE=signing_keystore.p12
readonly PW_FILE=signing_keystore_pass
readonly KS_ALIAS=reverse-apk
readonly KS_KEYALG=RSA
# RSA 3072 (bukan 4096): ± 128-bit keamanan (NIST SP 800-57), cukup melewati masa berlaku. Ancaman nyata ke kunci ini adalah pencurian berkas, bukan pemfaktoran.
readonly KS_KEYSIZE=3072
# Dipin eksplisit agar tidak bergantung pada bawaan JDK.
readonly KS_SIGALG=SHA256withRSA
readonly KS_VALIDITY=10950   # 30 tahun: melewati 2033 dengan lega
readonly KS_STORETYPE=PKCS12

SECRETS_DIR="${SECRETS_DIR:-$PWD/secrets}"
KEYTOOL_CMD="${KEYTOOL_CMD:-}"
DOCKER_CMD="${DOCKER_CMD:-docker}"
COMPOSE="${COMPOSE:-docker compose}"
SIGNER_IMAGE="${SIGNER_IMAGE:-reverse-apk-signer}"

WORK=""
KT_RUN=()
KT_DIR=""

ks_log() { echo "$*"; }
ks_warn() { echo "⚠ $*" >&2; }
ks_die() { # ks_die KODE PESAN
  local code="$1"; shift
  echo "✗ $*" >&2
  exit "$code"
}

ks_rand_hex() { # ks_rand_hex BYTES -> BYTES*2 karakter hex
  local value
  if command -v openssl >/dev/null 2>&1; then
    value="$(openssl rand -hex "$1")"
  else # cadangan bila openssl tidak terpasang
    value="$(head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n')"
  fi
  # Jangan pernah memakai nilai kosong/pendek: kegagalan harus terlihat.
  [ "${#value}" -eq $((${1} * 2)) ] || ks_die 1 "Gagal membuat bilangan acak (hasil: ${#value} karakter, seharusnya $(($1 * 2)))."
  printf '%s' "$value"
}

ks_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo '?'; }

ks_state() { # mencetak none|both|only_p12|only_pass
  local f have_p12=0 have_pw=0
  for f in "$SECRETS_DIR/$KS_FILE" "$SECRETS_DIR/$PW_FILE"; do
    # Symlink (termasuk yang patah) atau direktori bernama sama: jangan ditebak, jangan ditimpa.
    if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then
      ks_die 2 "$f ada tetapi BUKAN berkas biasa (symlink/direktori). Tidak ada yang diubah. Periksa secara manual."
    fi
  done
  [ -f "$SECRETS_DIR/$KS_FILE" ] && have_p12=1
  [ -f "$SECRETS_DIR/$PW_FILE" ] && have_pw=1
  if [ $have_p12 -eq 1 ] && [ $have_pw -eq 1 ]; then echo both
  elif [ $have_p12 -eq 1 ]; then echo only_p12
  elif [ $have_pw -eq 1 ]; then echo only_pass
  else echo none; fi
}

ks_die_partial() { # ks_die_partial STATE
  local present
  if [ "$1" = only_p12 ]; then present="$KS_FILE"; else present="$PW_FILE"; fi
  ks_die 2 "HANYA ${present} yang ada di ${SECRETS_DIR} (pasangannya hilang). Tidak ada yang diubah atau dihapus. Pulihkan pasangannya dari cadangan; jika memang ingin kunci BARU, pindahkan berkas itu ke tempat lain secara manual lalu ulangi."
}

ks_prepare_dir() {
  mkdir -p "$SECRETS_DIR"
  chmod 700 "$SECRETS_DIR"
  SECRETS_DIR="$(cd "$SECRETS_DIR" && pwd -P)" # docker -v butuh jalur absolut
}

ks_ensure_image() { # hanya mode Docker
  local -a compose
  read -r -a compose <<<"$COMPOSE"
  if ! "$DOCKER_CMD" image inspect "$SIGNER_IMAGE" >/dev/null 2>&1; then
    [ -f .env ] || ks_die 1 "Image ${SIGNER_IMAGE} belum ada dan .env belum ada (untuk membangunnya). Jalankan 'make init' dulu."
    ks_log "• image ${SIGNER_IMAGE} belum ada: membangun (docker compose --profile build build signer; butuh jaringan sekali)…"
    "${compose[@]}" --profile build build signer || ks_die 1 "Gagal membangun image signer."
  fi
  "$DOCKER_CMD" image inspect "$SIGNER_IMAGE" >/dev/null 2>&1 \
    || ks_die 1 "Image ${SIGNER_IMAGE} tidak ditemukan setelah build. Lihat 'docker images | grep signer' lalu jalankan ulang dengan SIGNER_IMAGE=<nama>."
}

ks_setup_keytool() { # ks_setup_keytool rw DIR_KERJA | ks_setup_keytool ro
  local mode="$1"
  if [ -n "$KEYTOOL_CMD" ]; then
    read -r -a KT_RUN <<<"$KEYTOOL_CMD"
    if [ "$mode" = rw ]; then KT_DIR="$2"; else KT_DIR="$SECRETS_DIR"; fi
    return 0
  fi
  ks_ensure_image
  # Isolasi sama seperti layanan signer: tanpa jaringan, rootfs read-only, tanpa capability. tmpfs /tmp TANPA exec.
  # --user numerik host: berkas hasil milik user host. HOME=/tmp mengganti HOME=/tmp/home dari ENV image (tidak ada di tmpfs kosong).
  # --pull never: image yang hilang menghasilkan galat jelas, bukan mencoba menarik dari Docker Hub. --entrypoint: tetap benar bila image kelak punya ENTRYPOINT.
  KT_RUN=("$DOCKER_CMD" run --rm --pull never --network none --read-only
    --tmpfs /tmp:rw,size=64m,nosuid --cap-drop ALL --security-opt no-new-privileges:true
    --pids-limit 128 --memory 512m --user "$(id -u):$(id -g)" -e HOME=/tmp --workdir /tmp)
  if [ "$mode" = rw ]; then
    KT_RUN+=(-v "$2:/out")
    KT_DIR=/out
  else # info: tidak ada mount rw sama sekali
    KT_RUN+=(-v "$SECRETS_DIR/$KS_FILE:/in/$KS_FILE:ro" -v "$SECRETS_DIR/$PW_FILE:/in/$PW_FILE:ro")
    KT_DIR=/in
  fi
  KT_RUN+=(--entrypoint keytool "$SIGNER_IMAGE")
}

ks_keytool() { # bahasa Inggris tetap agar keluaran bisa diparsing; stdin ditutup
  "${KT_RUN[@]}" -J-Duser.language=en -J-Duser.country=US "$@" </dev/null
}

ks_cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK" || ks_warn "Gagal menghapus direktori kerja sementara ${WORK}; hapus manual."
  fi
}

ks_field() { # ks_field "label" <<< keluaran  -> nilai setelah label (baris pertama yang cocok)
  sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" | sed -n 1p
}

ks_print_details() { # ks_print_details KELUARAN_LIST_V
  local out="$1" sha until_s days="" until_epoch now
  sha="$(ks_field SHA256 <<<"$out")"
  until_s="$(printf '%s\n' "$out" | sed -n 's/^.*until:[[:space:]]*//p' | sed -n 1p)"
  if until_epoch="$(date -d "$until_s" +%s 2>/dev/null)"; then
    now="$(date +%s)"
    days=" (sisa $(((until_epoch - now) / 86400)) hari)"
  fi
  echo "  Berkas     : ${SECRETS_DIR}/${KS_FILE}  (mode $(ks_mode "$SECRETS_DIR/$KS_FILE"))"
  echo "  Tipe       : $(ks_field 'Keystore type' <<<"$out")"
  echo "  Alias      : $(ks_field 'Alias name' <<<"$out")"
  echo "  DN (Owner) : $(ks_field Owner <<<"$out")"
  echo "  Algoritma  : $(ks_field 'Subject Public Key Algorithm' <<<"$out"), tanda tangan $(ks_field 'Signature algorithm name' <<<"$out")"
  echo "  Berlaku    : $(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*Valid from:[[:space:]]*//p' | sed -n 1p)${days}"
  echo "  SHA-256 (keytool)   : ${sha}"
  echo "  SHA-256 (heks kecil): $(printf '%s' "$sha" | tr -d ':' | tr 'A-F' 'a-f')"
  if [ "$(ks_mode "$SECRETS_DIR/$KS_FILE")" != 600 ] || [ "$(ks_mode "$SECRETS_DIR/$PW_FILE")" != 600 ]; then
    ks_warn "mode berkas keystore/sandi bukan 600. Perbaiki: chmod 600 ${SECRETS_DIR}/${KS_FILE} ${SECRETS_DIR}/${PW_FILE}"
  fi
}

ks_print_backup_warning() {
  cat <<'EOF'
⚠  CADANGKAN SEKARANG di tempat aman (di luar server): secrets/signing_keystore.p12 DAN secrets/signing_keystore_pass
   Keduanya dibutuhkan bersama. Kehilangan salah satunya = kunci BARU: aplikasi yang sudah terpasang dengan kunci lama tidak
   bisa diperbarui (Android menolak update berbeda tanda tangan; harus dicopot, data aplikasi hilang) dan tanda tangan semua build lama berubah.
   Kunci ini untuk riset pribadi (bukan kunci rilis). Sidik jari: make keystore-info
EOF
}

ks_list_v() { # ks_list_v DIR -> keluaran keytool -list -v (kode keluar dipertahankan)
  ks_keytool -list -v -keystore "$1/$2" -storetype "$KS_STORETYPE" -storepass:file "$1/$3"
}

ks_create() {
  local st out dn pw
  ks_prepare_dir
  umask 077
  st="$(ks_state)" || exit "$?"
  case "$st" in
    both)
      ks_log "✓ keystore sudah ada (${SECRETS_DIR}/${KS_FILE} + ${PW_FILE}); tidak diubah."
      ks_log "  Pastikan sudah DICADANGKAN di tempat aman (kehilangan = kunci baru). Sidik jari: make keystore-info"
      return 0 ;;
    only_p12 | only_pass) ks_die_partial "$st" ;;
  esac

  # Direktori kerja milik user host, mode 700; trap dipasang SEBELUM berkas apa pun dibuat.
  WORK="$(mktemp -d "$SECRETS_DIR/.keystore-work.XXXXXX")" \
    || ks_die 1 "Tidak bisa membuat direktori kerja di ${SECRETS_DIR} (izin? Bila Docker pernah membuat secrets/ sebagai root: sudo chown -R \"\$(id -u):\$(id -g)\" secrets)."
  trap ks_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  # Kata sandi: langsung ke berkas 0600 lewat printf bawaan shell (bukan argv/env/echo ke terminal).
  pw="$(ks_rand_hex 32)"
  printf '%s' "$pw" >"$WORK/pass"
  unset pw
  chmod 600 "$WORK/pass"

  ks_setup_keytool rw "$WORK"
  dn="CN=reverse-apk $(ks_rand_hex 4)"
  ks_log "• membuat keystore ${KS_STORETYPE} (${KS_KEYALG} ${KS_KEYSIZE}, ${KS_SIGALG}, berlaku ${KS_VALIDITY} hari)…"
  ks_keytool -genkeypair -keystore "$KT_DIR/ks.p12" -storetype "$KS_STORETYPE" -alias "$KS_ALIAS" \
    -keyalg "$KS_KEYALG" -keysize "$KS_KEYSIZE" -sigalg "$KS_SIGALG" -validity "$KS_VALIDITY" -dname "$dn" \
    -storepass:file "$KT_DIR/pass" -keypass:file "$KT_DIR/pass" -noprompt \
    || ks_die 1 "keytool gagal membuat keystore. Tidak ada berkas yang dibuat di ${SECRETS_DIR}."

  # Verifikasi di direktori kerja SEBELUM dipublikasikan (keluaran ditangkap; bukan lewat pipa yang menelan kode keluar).
  out="$(ks_list_v "$KT_DIR" ks.p12 pass)" || ks_die 1 "keytool tidak bisa membaca keystore yang baru dibuat. Tidak ada berkas yang dibuat di ${SECRETS_DIR}."
  [[ "$out" == *"Alias name: ${KS_ALIAS}"* && "$out" == *"${KS_KEYSIZE}-bit ${KS_KEYALG}"* && "$out" == *"Keystore type: ${KS_STORETYPE}"* && "$out" == *"${KS_SIGALG}"* ]] \
    || ks_die 1 "Keystore yang dibuat tidak sesuai harapan (alias/ukuran/tipe/algoritma). Tidak ada berkas yang dibuat di ${SECRETS_DIR}."

  # keytool menulis p12 dengan mode 644 (umask kontainer/JDK): wajib 600 sebelum dipublikasikan.
  [ -s "$WORK/ks.p12" ] || ks_die 1 "Berkas keystore kosong. Tidak ada berkas yang dibuat di ${SECRETS_DIR}."
  chmod 600 "$WORK/ks.p12"

  # Jaring pengaman balapan, lalu publikasi tanpa-timpa: sandi dulu, p12 TERAKHIR (titik komit = keberadaan p12).
  st="$(ks_state)" || exit "$?"
  [ "$st" = none ] || ks_die 2 "Ada proses lain yang membuat keystore lebih dulu (keadaan: ${st}). Tidak ada yang ditimpa."
  ln -- "$WORK/pass" "$SECRETS_DIR/$PW_FILE" 2>/dev/null \
    || ks_die 2 "${PW_FILE} sudah dibuat proses lain. Tidak ada yang ditimpa."
  if ! ln -- "$WORK/ks.p12" "$SECRETS_DIR/$KS_FILE" 2>/dev/null; then
    # Hanya cabut sandi yang BARU SAJA saya buat (isi identik), bukan milik pemenang balapan.
    if cmp -s "$WORK/pass" "$SECRETS_DIR/$PW_FILE"; then rm -f -- "$SECRETS_DIR/$PW_FILE"; fi
    ks_die 2 "${KS_FILE} sudah dibuat proses lain. Tidak ada yang ditimpa."
  fi

  ks_log "✓ keystore dibuat:"
  ks_print_details "$out" || ks_warn "Ringkasan keystore gagal dicetak (keystore sudah dibuat; lihat: make keystore-info)."
  echo
  ks_print_backup_warning
}

ks_info() {
  local st out
  st="$(ks_state)" || exit "$?"
  case "$st" in
    none) ks_die 1 "Keystore belum ada di ${SECRETS_DIR}. Jalankan: make keystore" ;;
    only_p12 | only_pass) ks_die_partial "$st" ;;
  esac
  ks_setup_keytool ro
  out="$(ks_list_v "$KT_DIR" "$KS_FILE" "$PW_FILE")" || ks_die 1 "keytool gagal membaca keystore (berkas rusak atau sandi tidak cocok?)."
  ks_print_details "$out"
}

ks_status() { # tanpa Docker/keytool: cepat dan aman dipanggil dari `make doctor`
  local st m1 m2 stale
  st="$(ks_state)" || exit "$?"
  case "$st" in
    none) ks_warn "keystore penanda tangan belum dibuat (make keystore); stack tetap bisa jalan." ;;
    only_p12 | only_pass) ks_die_partial "$st" ;;
    both)
      m1="$(ks_mode "$SECRETS_DIR/$KS_FILE")"
      m2="$(ks_mode "$SECRETS_DIR/$PW_FILE")"
      if [ "$m1" = 600 ] && [ "$m2" = 600 ]; then
        echo "✓ keystore penanda tangan ada (mode ${m1}/${m2}); pastikan sudah dicadangkan"
      else
        ks_warn "keystore ada tetapi mode berkas ${m1}/${m2}, seharusnya 600/600: chmod 600 secrets/${KS_FILE} secrets/${PW_FILE}"
      fi ;;
  esac
  stale="$(find "$SECRETS_DIR" -maxdepth 1 -name '.keystore-work.*' 2>/dev/null | head -n 1)" || true
  if [ -n "$stale" ]; then ks_warn "ada sisa direktori kerja keystore (${stale}); aman dihapus bila tidak ada 'make keystore' yang sedang berjalan."; fi
  return 0
}

main() {
  case "${1:-}" in
    create) ks_create ;;
    info) ks_info ;;
    status) ks_status ;;
    *)
      echo "Pemakaian: scripts/keystore.sh <create|info|status>" >&2
      exit 64 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
