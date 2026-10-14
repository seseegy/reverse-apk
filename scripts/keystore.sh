#!/usr/bin/env bash
# Keystore penanda tangan APK: dibuat sekali oleh `make init` (atau `make keystore`), TIDAK PERNAH ditimpa.
#   scripts/keystore.sh create   buat secrets/signing_keystore.p12 + secrets/signing_keystore_pass bila belum ada (idempoten)
#   scripts/keystore.sh info     cetak sidik jari SHA-256, DN, masa berlaku, algoritma (tanpa kata sandi)
#   scripts/keystore.sh status   ringkasan satu baris per pemeriksaan untuk `make doctor` (tanpa Docker/keytool)
#   scripts/keystore.sh present  senyap: kode 0 bila KEDUA berkas ada dan berkas biasa (bukan symlink/direktori), selain itu 1. Tanpa efek samping
#                                (tidak membuat secrets/, tanpa Docker/keytool); dipanggil Makefile pada SETIAP `make`.
#   scripts/keystore.sh access [--auto]
#                                pastikan secrets/ mode 700 dan kedua berkas mode 644 (HANYA chmod; hanya berkas biasa milik user ini). Tanpa --auto: tabel
#                                sebelum -> sesudah + penjelasan. Dengan --auto (dipanggil `make up`/`make restart`): satu baris bila ada yang diubah,
#                                hanya peringatan bila gagal, dan TIDAK PERNAH keluar dengan kode != 0.
#   scripts/keystore.sh check    prediksi (dari `stat`, bukan percobaan baca) apakah kontainer signer (uid 10001) bisa membaca kunci; kode keluar di bawah.
#
# Server pemilik hanya punya Docker (tanpa JDK), jadi keytool dijalankan DI DALAM image `signer` (JRE 21), terkurung seperti layanan lain:
# tanpa jaringan, rootfs read-only, tanpa capability, user = user host (berkas hasil milik user host). Kata sandi dibuat langsung ke berkas
# mode 0600 (selama di direktori kerja) dan diberikan ke keytool lewat `-storepass:file` / `-keypass:file`: TIDAK pernah menjadi argumen proses,
# variabel lingkungan, atau riwayat shell.
#
# Hanya direktori kerja sementara (secrets/.keystore-work.*) yang di-bind rw ke kontainer, bukan seluruh secrets/ (admin_password_hash tidak terlihat).
# Hasil dipublikasikan oleh HOST dengan `ln` (hard link: atomik dan GAGAL bila tujuan sudah ada, jadi tidak pernah menimpa): sandi dulu, p12 terakhir.
#
# AKSES KUNCI UNTUK KONTAINER SIGNER (keputusan SADAR yang menggantikan "mode 600" Tahap 1): layanan `signer` berjalan sebagai uid 10001, BUKAN pemilik
# berkas (user host), dan Compose mengabaikan uid/gid/mode untuk secret bersumber `file:`. Agar kunci terbaca, kedua berkas dibuat mode 644 DI DALAM
# secrets/ yang tetap mode 700. KOMPROMI dinyatakan terang-terangan: kerahasiaan kini bertumpu pada izin FOLDER (700, pola yang sama dengan
# admin_password_hash), bukan pada berkas; yang bisa membaca di host hanya pemilik dan root. Membuka folder (chmod 755 secrets) membuka kunci:
# `check`/`status`/`doctor` melaporkannya. Kunci dipasang HANYA ke layanan `signer`, lewat docker-compose.keystore.yml (dimuat Makefile bila kedua berkas ada).
#
# Variabel lingkungan (semua opsional; untuk tes dan pengaturan khusus, bukan konfigurasi stack):
#   KEYTOOL_CMD       perintah keytool LOKAL (mis. /jalur/ke/keytool), tanpa Docker. Kosong = pakai Docker. Dipakai tes di mesin tanpa Docker.
#   SECRETS_DIR       lokasi berkas (bawaan: <repo>/secrets)
#   DOCKER_CMD        biner docker (bawaan: docker)
#   COMPOSE           perintah compose untuk membangun image (bawaan: docker compose)
#   SIGNER_IMAGE      nama image signer (bawaan: reverse-apk-signer; ganti bila COMPOSE_PROJECT_NAME di-override)
#   KS_CONTAINER_UID  uid kontainer signer yang diprediksi oleh `check` (bawaan: 10001). Pengungkit uji, TIDAK diteruskan compose.
#
# Kode keluar: 0 sukses/sudah ada; 1 galat umum (keytool/docker gagal, alat hilang); 2 keadaan tidak konsisten atau balapan; 64 pemakaian salah.
# `check`: 0 kunci terbaca kontainer; 10 berkas tak terbaca uid kontainer; 11 folder secrets/ terbuka untuk user lain (MENANG atas 10); 2 tidak ada/tidak konsisten.
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
# Mode berkas keystore/sandi di dalam secrets/ (644: dapat dibaca uid 10001) dan mode folder (700: satu-satunya penjaga kerahasiaan). Lihat header.
readonly KS_MODE=644
readonly KS_DIR_MODE=700

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
      ks_die 2 "$f ada tetapi BUKAN berkas biasa (symlink/direktori). Tidak ada yang diubah. Periksa secara manual. Bila itu direktori kosong buatan Docker (bind-mount berkas yang belum ada): hapus dengan 'rmdir $f' (butuh sudo bila milik root), lalu ulangi."
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
  chmod "$KS_DIR_MODE" "$SECRETS_DIR"
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
  # Aturan akses kunci (644 di folder 700): peringatan = pesan `check` (tanpa mengubah apa pun).
  local verdict
  if ! verdict="$(ks_check 2>&1)"; then
    printf '%s\n' "$verdict" | sed 's/^✗/⚠/' >&2
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
      ks_access --auto # hanya chmod (isi tidak disentuh) agar kontainer signer bisa membaca; tidak pernah gagal keras
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

  # Mode final KEDUA berkas = 644 (terbaca uid 10001; kerahasiaan dijaga folder 700): diberikan SETELAH verifikasi dan SEBELUM publikasi.
  # Hard link (`ln`) mempertahankan mode. Selama di direktori kerja (700) sandi tetap 600; direktori kerja dihapus oleh trap.
  [ -s "$WORK/ks.p12" ] || ks_die 1 "Berkas keystore kosong. Tidak ada berkas yang dibuat di ${SECRETS_DIR}."
  chmod "$KS_MODE" "$WORK/ks.p12" "$WORK/pass"

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

ks_present() { # senyap, tanpa efek samping: kode 0 hanya bila KEDUA berkas ada dan berkas biasa (symlink/direktori/FIFO ditolak)
  local f
  for f in "$SECRETS_DIR/$KS_FILE" "$SECRETS_DIR/$PW_FILE"; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then return 1; fi
  done
  return 0
}

ks_access() { # ks_access [--auto]
  local auto=0 f label before after changed=0 failed=0 skipped=0 rows=() summary=() st joined item
  case "${1:-}" in
    "") ;;
    --auto) auto=1 ;;
    *) echo "Pemakaian: scripts/keystore.sh access [--auto]" >&2; exit 64 ;;
  esac
  # Tidak memanggil ks_prepare_dir: `access` tidak membuat apa pun. --auto tidak pernah keluar != 0 (dipanggil `make up`/`make restart`).
  for f in "$SECRETS_DIR/$KS_FILE" "$SECRETS_DIR/$PW_FILE"; do
    if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then
      if [ $auto -eq 1 ]; then
        ks_warn "akses kunci tidak diperiksa: $f BUKAN berkas biasa (symlink/direktori); periksa manual (make keystore-access)"
        return 0
      fi
      ks_die 2 "$f ada tetapi BUKAN berkas biasa (symlink/direktori). Tidak ada yang diubah. Periksa secara manual."
    fi
  done
  if [ ! -f "$SECRETS_DIR/$KS_FILE" ] && [ ! -f "$SECRETS_DIR/$PW_FILE" ]; then
    if [ $auto -eq 1 ]; then return 0; fi # stack lama tanpa keystore: tidak ada yang perlu diperbaiki, senyap
    ks_die 1 "Keystore belum ada di ${SECRETS_DIR}. Jalankan: make keystore"
  fi
  if [ ! -f "$SECRETS_DIR/$KS_FILE" ] || [ ! -f "$SECRETS_DIR/$PW_FILE" ]; then
    if [ $auto -eq 1 ]; then
      ks_warn "akses kunci tidak diperiksa: hanya satu dari dua berkas keystore yang ada (make doctor)"
      return 0
    fi
    st="$(ks_state)" || exit "$?"
    ks_die_partial "$st"
  fi

  # Folder DULU (dijadikan 700 sebelum ada berkas yang menjadi 644), lalu kedua berkas.
  for f in "$SECRETS_DIR" "$SECRETS_DIR/$KS_FILE" "$SECRETS_DIR/$PW_FILE"; do
    if [ "$f" = "$SECRETS_DIR" ]; then
      label="secrets/"
      after="$KS_DIR_MODE"
    else
      label="secrets/${f##*/}"
      after="$KS_MODE"
    fi
    before="$(ks_mode "$f")"
    if [ "$before" = "$after" ]; then
      rows+=("$(printf '  %-32s %s (sudah benar)' "$label" "$before")")
      continue
    fi
    if [ -L "$f" ] || [ ! -O "$f" ]; then # hanya milik user ini; folder symlink tidak diikuti
      skipped=1
      rows+=("$(printf '  %-32s %s (DILEWATI: bukan milik user ini atau symlink)' "$label" "$before")")
      ks_warn "${label}: mode ${before} tidak diubah (bukan milik user ini atau symlink). Jalankan sebagai pemilik: make keystore-access"
      continue
    fi
    if chmod "$after" "$f" 2>/dev/null; then
      changed=1
      summary+=("${label} ${before}→${after}")
      rows+=("$(printf '  %-32s %s → %s' "$label" "$before" "$after")")
    else
      failed=1
      rows+=("$(printf '  %-32s %s (GAGAL diubah ke %s)' "$label" "$before" "$after")")
      ks_warn "chmod ${after} ${label} gagal (mode tetap ${before})"
    fi
  done

  if [ $auto -eq 1 ]; then
    if [ $changed -eq 1 ]; then
      joined=""
      for item in "${summary[@]}"; do joined+="${joined:+, }${item}"; done
      echo "✓ akses kunci untuk kontainer signer diperbaiki: ${joined}"
    fi
    return 0
  fi
  echo "• akses kunci untuk kontainer signer (uid 10001):"
  printf '%s\n' "${rows[@]}"
  cat <<'PENJELASAN'
  Kompromi SADAR: kontainer signer berjalan sebagai uid 10001 (bukan pemilik berkas), jadi kedua berkas dibuat mode 644. Kerahasiaan kini
  bertumpu pada FOLDER secrets/ (mode 700): user lain di server ini tidak bisa masuk ke folder itu; hanya pemilik dan root yang bisa membaca kunci.
  Jangan membuka folder (chmod 755 secrets). Berkas kunci yang diganti/dipulihkan dari cadangan (mode 600) diperbaiki lagi oleh perintah ini.
PENJELASAN
  if [ $failed -eq 1 ] || [ $skipped -eq 1 ]; then exit 1; fi
  return 0
}

ks_check() { # prediksi dari `stat`: apakah uid kontainer signer bisa membaca kunci? ACL/SELinux/userns TIDAK diperhitungkan
  local u="${KS_CONTAINER_UID:-10001}" st dm f path uid gid m owner readable bad=0 shown mods=() loose=0
  [[ "$u" =~ ^[0-9]+$ ]] || ks_die 64 "KS_CONTAINER_UID harus bilangan bulat (uid kontainer), bukan '${u}'."
  st="$(ks_state)" || exit "$?"
  case "$st" in
    none)
      echo "✗ keystore belum ada di secrets/. Jalankan: make keystore" >&2
      exit 2 ;;
    only_p12 | only_pass) ks_die_partial "$st" ;;
  esac
  for f in "$KS_FILE" "$PW_FILE"; do
    mods+=("$(ks_mode "$SECRETS_DIR/$f")")
  done
  [[ "${mods[0]}${mods[1]}" =~ ^[0-7]+$ ]] || ks_die 2 "Mode berkas keystore tidak terbaca (stat gagal) di ${SECRETS_DIR}."

  # FOLDER DULU: bit grup/other pada secrets/ membuka kunci bagi user lain di server (berkas 644 di folder terbuka = kunci terbuka).
  dm="$(ks_mode "$SECRETS_DIR")"
  [[ "$dm" =~ ^[0-7]+$ ]] || ks_die 2 "Mode folder secrets/ tidak terbaca (stat gagal)."
  if [ $((8#$dm & 8#077)) -ne 0 ]; then
    if [ "${mods[0]}" = "${mods[1]}" ]; then shown="${mods[0]}"; else shown="${mods[0]}/${mods[1]}"; fi
    if [ $((8#${mods[0]} & 8#044)) -ne 0 ] || [ $((8#${mods[1]} & 8#044)) -ne 0 ]; then loose=1; fi
    if [ $loose -eq 1 ]; then
      echo "✗ secrets/ mode ${dm} sedangkan berkas keystore ${shown}: user lain di server ini bisa membaca kunci → jalankan: chmod 700 secrets   (atau make keystore-access)" >&2
    else
      echo "✗ secrets/ mode ${dm} (terbuka untuk user lain di server ini) sedangkan berkas keystore ${shown}; make keystore-access menjadikan berkas 644, jadi tutup folder dulu → jalankan: chmod 700 secrets   (atau make keystore-access)" >&2
    fi
    exit 11
  fi

  for f in "$KS_FILE" "$PW_FILE"; do
    path="$SECRETS_DIR/$f"
    uid="" gid="" m="" owner=""
    IFS=' ' read -r uid gid m owner <<<"$(stat -c '%u %g %a %U' "$path" 2>/dev/null)" || true
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$m" =~ ^[0-7]+$ ]] || ks_die 2 "stat gagal untuk secrets/${f}."
    readable=0
    # terbaca = pemilik uid kontainer, ATAU o+r, ATAU (gid berkas = uid kontainer DAN g+r)
    if [ "$uid" -eq "$u" ] || [ $((8#$m & 8#004)) -ne 0 ] || { [ "$gid" -eq "$u" ] && [ $((8#$m & 8#040)) -ne 0 ]; }; then readable=1; fi
    if [ $readable -eq 0 ]; then
      bad=1
      echo "✗ secrets/${f}: mode ${m} milik ${owner} (uid ${uid}). Kontainer signer berjalan sebagai uid ${u} dan TIDAK bisa membacanya → jalankan: make keystore-access" >&2
    fi
  done
  if [ $bad -ne 0 ]; then exit 10; fi
  echo "✓ kunci terbaca uid ${u} (secrets/ mode ${dm}, berkas ${mods[0]}/${mods[1]})"
}

ks_status() { # tanpa Docker/keytool: cepat dan aman dipanggil dari `make doctor`
  local st m1 m2 dm stale verdict
  st="$(ks_state)" || exit "$?"
  case "$st" in
    none) ks_warn "keystore penanda tangan belum dibuat (make keystore); stack tetap bisa jalan." ;;
    only_p12 | only_pass) ks_die_partial "$st" ;;
    both)
      # Satu-satunya berkas tambahan yang dikenal di secrets/ adalah .signer-verify.lock (milik `make signer-verify`); status tidak memeriksa berkas lain.
      m1="$(ks_mode "$SECRETS_DIR/$KS_FILE")"
      m2="$(ks_mode "$SECRETS_DIR/$PW_FILE")"
      dm="$(ks_mode "$SECRETS_DIR")"
      if verdict="$(ks_check 2>&1)"; then
        echo "✓ keystore penanda tangan ada (mode ${m1}/${m2}, folder ${dm}); pastikan sudah dicadangkan"
      else
        printf '%s\n' "$verdict" | sed 's/^✗/⚠/' >&2
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
    present) ks_present || exit 1 ;;
    access) shift; ks_access "$@" ;;
    check) ks_check ;;
    *)
      echo "Pemakaian: scripts/keystore.sh <create|info|status|present|access [--auto]|check>" >&2
      exit 64 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
