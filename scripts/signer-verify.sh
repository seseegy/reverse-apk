#!/usr/bin/env bash
# Bukti end-to-end signer-daemon di server pemilik: APK uji dikirim lewat spool ke signer, ditandatangani dengan keystore PEMILIK, lalu diperiksa ulang
# secara independen. Satu laporan: tabel `LANGKAH | STATUS | KETERANGAN` (status OK, GAGAL, DILEWATI, INFO), tempel seluruhnya ke chat bila ada GAGAL.
# Pemakaian: scripts/signer-verify.sh   (lewat `make signer-verify`; butuh Docker Compose v2, keystore sudah dibuat dan stack sudah pernah `make up`)
#   BIG_MB=1000 make signer-verify     tambahan: uji APK besar (langkah 17) dan ukur memori (langkah 19); butuh ruang bebas >= 2*BIG_MB + 1040 MiB
# Kode keluar: 0 tidak ada GAGAL; 1 ada GAGAL (atau dihentikan); 64 salah pakai.
#
# Prinsip: bash di host TIDAK PERNAH mem-parse JSON (host hanya terjamin punya Docker + bash + coreutils/sed/grep). Semua keputusan yang bergantung pada isi
# hasil dibuat DI DALAM kontainer (worker/signcheck.py, signer-selftest) dan dilaporkan sebagai kode keluar 0/2/3/64 plus baris `kunci=nilai` / `HASIL ...`.
# Skrip ini hanya membaca baris itu dengan sed. Host tidak pernah menulis/menghapus di volume Docker (semua lewat kontainer uid 10001) dan tidak mengubah
# keystore maupun testdata/. Id uji = sentinel (analysis_id 2147483000, build_id 1..7): tidak mungkin menyentuh analisis nyata.
#
# Variabel (opsional, untuk tes/pengaturan khusus): COMPOSE (dari Makefile), DOCKER_CMD (bawaan docker), BIG_MB, HEALTH_WAIT (detik menunggu signer sehat; bawaan 90).
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE="${COMPOSE:-docker compose}"
DOCKER_CMD="${DOCKER_CMD:-docker}"
BIG_MB="${BIG_MB:-}"
HEALTH_WAIT="${HEALTH_WAIT:-90}"
SENT_AID=2147483000
APK=testdata/vulnsample.apk

case "${1-}" in
  -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) echo "✗ pemakaian: scripts/signer-verify.sh   (tanpa argumen; opsional BIG_MB=<MiB>)" >&2; exit 64 ;;
esac
if [ -n "$BIG_MB" ]; then
  if ! [[ "$BIG_MB" =~ ^[0-9]+$ ]] || [ "$BIG_MB" -lt 1 ] || [ "$BIG_MB" -gt 1100 ]; then
    echo "✗ BIG_MB harus bilangan bulat 1..1100 (MiB), diterima: '$BIG_MB'" >&2
    exit 64
  fi
fi
[[ "$HEALTH_WAIT" =~ ^[0-9]+$ ]] || HEALTH_WAIT=90

N1="1 versi Compose"
N2="2 keystore ada"
N3="3 izin kunci host"
N4="4 bangun image"
N5="5 signer hidup & sehat"
N6="6 status daemon via spool"
N7="7 sidik jari daemon = keystore.sh info"
N8="8 APK uji"
N9="9 taruh masukan"
N10="10 kirim job & tunggu"
N11="11 hasil koheren"
N12="12 verifikasi independen"
N13="13 negatif: tanpa berkas"
N14="14 negatif: ZIP palsu"
N15="15 negatif: symlink"
N16="16 negatif: request mentah traversal"
N17="17 APK besar (BIG_MB)"
N18="18 kebocoran sandi"
N19="19 memori"
N20="20 pembersihan"

# ------------------------------------------------------------------------------------------------ tabel
ROWS_ST=(); ROWS_STEP=(); ROWS_NOTE=()
row() { # row OK|GAGAL|DILEWATI|INFO "langkah" "keterangan"
  local note="${3-}"
  note="$(printf '%s' "$note" | tr '\r\n\t' '   ')"
  ROWS_ST+=("$1"); ROWS_STEP+=("$2"); ROWS_NOTE+=("$note")
}
halt_from() { # halt_from N "alasan": sisa langkah N..20 DILEWATI
  local i var
  for ((i = $1; i <= 20; i++)); do var="N$i"; row DILEWATI "${!var}" "$2"; done
}
print_table() {
  local n=${#ROWS_ST[@]} i w=7 gagal=0 skip=0
  for ((i = 0; i < n; i++)); do
    [ "${#ROWS_STEP[i]}" -gt "$w" ] && w=${#ROWS_STEP[i]}
    [ "${ROWS_ST[i]}" = GAGAL ] && gagal=$((gagal + 1))
    [ "${ROWS_ST[i]}" = DILEWATI ] && skip=$((skip + 1))
  done
  echo
  printf '%-*s | %-8s | %s\n' "$w" "LANGKAH" "STATUS" "KETERANGAN"
  for ((i = 0; i < n; i++)); do printf '%-*s | %-8s | %s\n' "$w" "${ROWS_STEP[i]}" "${ROWS_ST[i]}" "${ROWS_NOTE[i]}"; done
  echo
  if [ "$gagal" -gt 0 ]; then
    echo "✗ $gagal GAGAL — tempel tabel ini ke chat"
    return 1
  fi
  if [ "$skip" -gt 0 ]; then echo "✓ semua OK ($n langkah, $skip dilewati)"; else echo "✓ semua OK ($n langkah)"; fi
}

# ------------------------------------------------------------------------------------------------ pembaca keluaran (tanpa JSON)
lv() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | sed -n 1p; }                       # nilai SATU BARIS `kunci=nilai` (nilai boleh berspasi)
kv() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^$1=//p" | sed -n 1p; }         # token `kunci=nilai` di dalam SATU baris HASIL
pick() { printf '%s\n' "$OUT" | sed -n "/^$1/p" | sed -n 1p; }                       # baris pertama dari $OUT yang diawali $1
is_hex64() { [[ "${1-}" =~ ^[0-9a-f]{64}$ ]]; }
is_num() { [[ "${1-}" =~ ^[0-9]+$ ]]; }
short() { printf '%s' "${1:0:12}"; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# ------------------------------------------------------------------------------------------------ pemanggil kontainer
# shellcheck disable=SC2086
sc() { $COMPOSE run --rm --no-deps -T ${SC_DIAG:+-e SIGNCHECK_DIAG=1} worker python signcheck.py "$@" </dev/null 7>&-; }
# shellcheck disable=SC2086
sc_in() { $COMPOSE run --rm --no-deps -T ${SC_DIAG:+-e SIGNCHECK_DIAG=1} worker python signcheck.py "$@" 7>&-; }
SC_DIAG=""
OUT=""; RC=0
run_sc() { OUT="$(exec 7>&- 9>&-; sc "$@" 2>&1 | tr -d '\r')"; RC=$?; printf '%s\n' "$OUT" >>"$T/outputs.log"; }
run_sc_in() { OUT="$(exec 7>&- 9>&-; sc_in "$@" 2>&1 | tr -d '\r')"; RC=$?; printf '%s\n' "$OUT" >>"$T/outputs.log"; }
ls_names() { sc ls "$SENT_AID" "$1" 2>/dev/null | tr -d '\r'; }
err_text() { local g; g="$(pick 'GALAT:')"; if [ -n "$g" ]; then printf '%s' "$g"; else printf 'kode keluar %s: %s' "$RC" "$(printf '%s\n' "$OUT" | tail -n 3)"; fi; }
expect_result() { # expect_result "langkah" "keterangan bila OK": dari $RC/$OUT hasil signcheck
  case "$RC" in
    0) row OK "$1" "$2" ;;
    3) row GAGAL "$1" "$(pick 'ALASAN:') [$(pick 'HASIL ')]" ;;
    *) row GAGAL "$1" "$(err_text)" ;;
  esac
}

# ------------------------------------------------------------------------------------------------ pemotret (signer-selftest --watch di kontainer signer)
T="$(mktemp -d "${TMPDIR:-/tmp}/signer-verify.XXXXXX")" || { echo "✗ tidak bisa membuat folder sementara" >&2; exit 1; }
: >"$T/outputs.log"
WPID_W1=""; WPID_W2=""; WPID_W3=""; WPID_W4=""
watch_start() { # watch_start NAME: stdin pemotret = FIFO yang ujung tulisnya dipegang skrip ini (fd 7); skrip mati -> EOF -> pemotret berhenti sendiri
  local n="$1"
  : >"$T/watch.$n"
  rm -f "$T/ctl.$n"
  mkfifo "$T/ctl.$n" 2>/dev/null || return 1
  $COMPOSE --profile build exec -T signer rm -f /tmp/selftest-watch.stop >/dev/null 2>&1 </dev/null
  exec 7<>"$T/ctl.$n"
  # 7>&- WAJIB: anak (dan subshell $(...) yang menunggu anak) tidak boleh mewarisi ujung tulis, kalau tidak EOF tidak pernah datang. 9>&-: kunci tidak ikut tertahan.
  $COMPOSE --profile build exec -T signer signer-selftest --watch 600 <"$T/ctl.$n" 7>&- 9>&- >"$T/watch.$n" 2>/dev/null &
  printf -v "WPID_$n" '%s' "$!"
}
watch_stop() { # watch_stop NAME: berkas stop DULU, lalu tutup fd 7 (EOF), lalu tunggu pemotret mencetak
  local n="$1" var="WPID_$1" pid
  pid="${!var:-}"
  [ -n "$pid" ] || return 0
  printf -v "$var" '%s' ""
  $COMPOSE --profile build exec -T signer touch /tmp/selftest-watch.stop >/dev/null 2>&1 </dev/null 7>&-
  exec 7>&-
  wait "$pid" 2>/dev/null
  $COMPOSE --profile build exec -T signer rm -f /tmp/selftest-watch.stop >/dev/null 2>&1 </dev/null 7>&-
}
wv() { lv "$2" "$(cat "$T/watch.$1" 2>/dev/null)"; }          # wv NAME KUNCI
has_watch() { is_num "$(wv "$1" samples)"; }

# ------------------------------------------------------------------------------------------------ penutup (juga lewat trap)
CAN_CLEAN=0; CLEANED=0; INTERRUPTED=0; NO_TABLE=0
teardown() {
  local n
  for n in W1 W2 W3 W4; do watch_stop "$n"; done                 # berkas stop ditulis SEBELUM folder sementara dihapus
  if [ "$CAN_CLEAN" = 1 ] && [ "$CLEANED" = 0 ]; then
    CLEANED=1
    sc clean "$SENT_AID" >/dev/null 2>&1
  fi
  [ -n "$T" ] && rm -rf "$T"
}
on_exit() {
  trap - EXIT INT TERM
  if [ "$NO_TABLE" = 1 ]; then teardown; exit 1; fi
  teardown
  [ "$INTERRUPTED" = 1 ] && row GAGAL "dihentikan" "skrip dihentikan sebelum selesai; pemotret dihentikan dan sisa uji dibersihkan"
  print_table
  exit $?
}
trap on_exit EXIT
trap 'INTERRUPTED=1; exit 1' INT TERM

echo "• signer-verify: bukti penandatanganan dengan keystore pemilik (id sentinel $SENT_AID; data nyata tidak disentuh)" >&2

# ------------------------------------------------------------------------------------------------ langkah 1-3: gerbang HOST (nol panggilan Docker)
LOCK_INFO=""
G2=GAGAL; G2_NOTE=""; G3=DILEWATI; G3_NOTE="tidak diperiksa: keystore belum ada"
if ./scripts/keystore.sh present >/dev/null 2>&1; then
  G2=OK; G2_NOTE="secrets/signing_keystore.p12 dan secrets/signing_keystore_pass ada"
  if command -v flock >/dev/null 2>&1; then
    if ! { ( umask 077; : >>secrets/.signer-verify.lock ) && exec 9>>secrets/.signer-verify.lock; } 2>/dev/null; then
      LOCK_INFO="kunci antar-proses tidak bisa dibuat (secrets/.signer-verify.lock); lanjut tanpa kunci"
    elif ! flock -n 9; then
      echo "✗ signer-verify lain sedang berjalan (kunci secrets/.signer-verify.lock)" >&2
      NO_TABLE=1
      exit 1
    fi
  else
    LOCK_INFO="flock tidak ada: dua signer-verify serentak tidak dicegah; jangan jalankan dua sekaligus"
  fi
  chk="$(./scripts/keystore.sh check 2>&1)"; crc=$?
  if [ "$crc" -eq 0 ]; then
    G3=OK; G3_NOTE="$(printf '%s\n' "$chk" | sed -n 1p)"
  else
    G3=GAGAL; G3_NOTE="$chk"
  fi
else
  G2_NOTE="keystore belum dibuat -> jalankan: make keystore"
fi
if [ "$G2" != OK ] || [ "$G3" != OK ]; then
  row DILEWATI "$N1" "tidak dijalankan: pemeriksaan kunci di host gagal lebih dulu (nol panggilan Docker)"
  row "$G2" "$N2" "$G2_NOTE"
  row "$G3" "$N3" "$G3_NOTE"
  halt_from 4 "dilewati: kunci di host belum beres (tidak ada panggilan Docker)"
  exit 1
fi

# Samakan dengan Makefile bila skrip dipanggil langsung (Makefile sudah mengekspor ketiganya bila keystore ada).
if [ -z "${COMPOSE_FILE:-}" ]; then
  export COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml
  export COMPOSE_PROFILES="${COMPOSE_PROFILES:-build}"
  KEYSTORE_STAMP="$(stat -c '%i-%s-%Y' secrets/signing_keystore.p12 secrets/signing_keystore_pass 2>/dev/null | tr '\n' ':')"
  export KEYSTORE_STAMP
fi

# ------------------------------------------------------------------------------------------------ langkah 1
# shellcheck disable=SC2086
if ver="$($COMPOSE version --short 2>&1)" && [ -n "$ver" ]; then
  row INFO "$N1" "Docker Compose $(printf '%s' "$ver" | sed -n 1p)"
  row OK "$N2" "$G2_NOTE"
  row OK "$N3" "$G3_NOTE"
  [ -n "$LOCK_INFO" ] && row INFO "kunci antar-proses" "$LOCK_INFO"
else
  row GAGAL "$N1" "'$COMPOSE version' gagal: $(printf '%s' "$ver" | tail -n 2); pasang Docker Compose v2"
  row OK "$N2" "$G2_NOTE"
  row OK "$N3" "$G3_NOTE"
  halt_from 4 "dilewati: Docker Compose tidak tersedia"
  exit 1
fi

# ------------------------------------------------------------------------------------------------ langkah 4-6 (fatal bila gagal)
step4() {
  echo "• langkah 4: membangun image signer dan worker (bisa lama pada build pertama)…" >&2
  # shellcheck disable=SC2086
  if ! $COMPOSE --profile build build signer worker >"$T/build.log" 2>&1; then
    row GAGAL "$N4" "build gagal: $(tail -n 5 "$T/build.log")"
    return 1
  fi
  row OK "$N4" "image signer dan worker terbangun"
}

step5() {
  # shellcheck disable=SC2086
  if ! $COMPOSE --profile build up -d --no-deps signer >"$T/up.log" 2>&1; then
    row GAGAL "$N5" "gagal menjalankan signer: $(tail -n 5 "$T/up.log")"
    return 1
  fi
  local cid hs waited=0 why
  cid="$($COMPOSE --profile build ps -q signer 2>/dev/null | sed -n 1p)"
  if [ -z "$cid" ]; then row GAGAL "$N5" "kontainer signer tidak ditemukan setelah 'up -d'"; return 1; fi
  while :; do
    hs="$($DOCKER_CMD inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null)"
    case "$hs" in
      healthy) row OK "$N5" "signer sehat (healthcheck signer-daemon --health lulus)"; return 0 ;;
      unhealthy)
        why="$($DOCKER_CMD inspect -f '{{range .State.Health.Log}}{{.Output}}{{end}}' "$cid" 2>/dev/null | sed '/^$/d' | tail -n 2)"
        row GAGAL "$N5" "signer UNHEALTHY: $why"
        return 1 ;;
    esac
    if [ "$waited" -ge "$HEALTH_WAIT" ]; then row GAGAL "$N5" "signer belum sehat setelah $HEALTH_WAIT dtk (status: ${hs:-tidak diketahui})"; return 1; fi
    sleep 2
    waited=$((waited + 2))
  done
}

DAEMON_CERT=""
step6() {
  local hidup ks det
  run_sc status
  if [ "$RC" -ne 0 ]; then row GAGAL "$N6" "$(err_text)"; return 1; fi
  hidup="$(lv hidup "$OUT")"; ks="$(lv keystore "$OUT")"; DAEMON_CERT="$(lv cert_sha256 "$OUT")"
  det="$(printf '%s\n' "$OUT" | sed -n 's/^detail=//p' | tr '\n' ' ')"
  if [ "$hidup" = 1 ] && [ "$ks" = ok ] && is_hex64 "$DAEMON_CERT"; then
    row OK "$N6" "hidup=1 keystore=ok cert_sha256=$(short "$DAEMON_CERT")…"
    return 0
  fi
  row GAGAL "$N6" "hidup=${hidup:--} keystore=${ks:--}: ${det:-tanpa keterangan}. Bila volume signspool/izin bermasalah periksa 'make logs'"
  return 1
}

OWNER=""
step7() {
  local info_out irc
  info_out="$(./scripts/keystore.sh info 2>&1)"; irc=$?
  OWNER="$(printf '%s\n' "$info_out" | sed -n 's/^ *SHA-256 (heks kecil): *//p' | sed -n 1p | tr -d ' \r')"
  if [ "$irc" -ne 0 ] || ! is_hex64 "$OWNER"; then
    OWNER=""
    row GAGAL "$N7" "keystore.sh info tidak memberi sidik jari (kode $irc): $(printf '%s\n' "$info_out" | tail -n 2)"
    return 1
  fi
  if [ "$OWNER" = "$DAEMON_CERT" ]; then
    row OK "$N7" "sidik jari sama dari dua jalur hitung: $(short "$OWNER")…"
  else
    row GAGAL "$N7" "BEDA: daemon $(short "$DAEMON_CERT")… vs keystore.sh info $(short "$OWNER")… (keystore berbeda terpasang? coba make restart)"
    return 1
  fi
}

# ------------------------------------------------------------------------------------------------ langkah 8-12 (jalur sukses)
APK_OK=0; SIGN_OK=0; HL=""; HIDE=""
step8() {
  local size
  if [ ! -f "$APK" ]; then
    row GAGAL "$N8" "$APK HILANG. Buat sekali: python3 scripts/sample-apk/build.py (skrip ini tidak memanggilnya). Traceback PermissionError saat pembersihan /tmp/vulnsample-* diketahui dan tidak menggagalkan APK; sisa /tmp/vulnsample-* milik uid kontainer boleh dihapus manual."
    return 1
  fi
  size="$(wc -c <"$APK" | tr -d ' ')"
  if [ "$(head -c 4 "$APK" | od -An -tx1 | tr -d ' \n')" != 504b0304 ] || ! tail -c 65557 "$APK" | grep -a -q -F -e "$(printf 'PK\005\006')"; then
    row GAGAL "$N8" "$APK bukan ZIP yang valid (tanda awal/akhir ZIP tidak ditemukan). Buat ulang: python3 scripts/sample-apk/build.py"
    return 1
  fi
  if grep -a -q -F 'APK Sig Block 42' "$APK"; then
    row GAGAL "$N8" "$APK tidak boleh bertanda tangan v2/v3 (ditemukan 'APK Sig Block 42'); buat ulang tanpa tanda tangan"
    return 1
  fi
  APK_OK=1
  if grep -a -q -E 'META-INF/[^/]+\.(RSA|DSA|EC)' "$APK"; then
    row INFO "$N8" "$APK ($size B) sudah bertanda tangan v1; signer akan menimpa"
  else
    row OK "$N8" "$APK ($size B): ZIP valid tanpa blok tanda tangan"
  fi
}

step9() {
  local want got wrote
  run_sc clean "$SENT_AID"                                          # sisa dari run yang terputus
  run_sc_in put "$SENT_AID" 1 <"$APK"
  if [ "$RC" -ne 0 ]; then row GAGAL "$N9" "$(err_text)"; return 1; fi
  want="$(sha256_of "$APK")"; got="$(lv sha256 "$OUT")"; wrote="$(lv ditulis "$OUT")"
  if [ "$want" = "$got" ] && is_hex64 "$got"; then
    row OK "$N9" "unsigned.apk ditulis lewat kontainer ($wrote B), sha256 sama dengan sha256sum host"
  else
    row GAGAL "$N9" "sha256 beda: host $(short "$want")… vs kontainer $(short "$got")…"
    return 1
  fi
}

step10() {
  local el
  watch_start W1 || row INFO "$N10" "pemotret W1 tidak bisa dimulai (mkfifo gagal); langkah 18 akan DILEWATI"
  echo "• langkah 10: mengirim job tanda tangan (tunggu hingga 5 menit)…" >&2
  run_sc sign "$SENT_AID" 1 --timeout 300 --expect-ok --owner-sha256 "$OWNER"
  HL="$(pick 'HASIL ')"
  el="$(kv elapsed "$HL")"
  expect_result "$N10" "ok=1, v2/v3, satu penanda tangan, sertifikat = pemilik (${el:-?} dtk)"
  [ "$RC" -eq 0 ] && SIGN_OK=1
  [ "$RC" -eq 0 ]
}

step11() {
  local missing="" k
  for k in ok signers v2 v3; do [ "$(kv "$k" "$HL")" = 1 ] || missing="$missing $k"; done
  [ "$(kv code "$HL")" = - ] || missing="$missing code"
  is_hex64 "$(kv sha "$HL")" || missing="$missing sha"
  is_hex64 "$(kv cert "$HL")" || missing="$missing cert"
  [ "$(kv size "$HL")" -gt 0 ] 2>/dev/null || missing="$missing size"
  if [ -z "$missing" ]; then
    row OK "$N11" "ok=1 signers=1 v2=1 v3=1 size=$(kv size "$HL") (v1=$(kv v1 "$HL"), informatif)"
  else
    row GAGAL "$N11" "bidang tidak koheren/hilang:$missing"
  fi
}

step12() {
  local f="/data/builds/$SENT_AID/1/signed.apk" v bad count rcv rca sha size
  # shellcheck disable=SC2016,SC2086
  v="$($COMPOSE --profile build run --rm --no-deps -T signer sh -c 'mkdir -p "$HOME"; f="$1"; apksigner verify --verbose --print-certs "$f"; echo "rc_verify=$?"; zipalign -c -P 16 4 "$f"; echo "rc_align=$?"; echo "sha=$(sha256sum "$f" | cut -d" " -f1)"; echo "size=$(stat -c %s "$f")"' sh "$f" </dev/null 7>&- 2>&1 | tr -d '\r')"
  count="$(printf '%s\n' "$v" | grep -o 'certificate SHA-256 digest: [0-9a-f]\{64\}' | wc -l | tr -d ' ')"
  bad="$(printf '%s\n' "$v" | grep -o 'certificate SHA-256 digest: [0-9a-f]\{64\}' | awk '{print $NF}' | grep -v -x -e "$OWNER" | wc -l | tr -d ' ')"
  rcv="$(lv rc_verify "$v")"; rca="$(lv rc_align "$v")"; sha="$(lv sha "$v")"; size="$(lv size "$v")"
  if [ "$rcv" = 0 ] && [ "$rca" = 0 ] && [ "${count:-0}" -ge 1 ] && [ "${bad:-1}" -eq 0 ] && [ "$sha" = "$(kv sha "$HL")" ] && [ "$size" = "$(kv size "$HL")" ]; then
    row OK "$N12" "apksigner verify + zipalign -c lulus; $count digest sertifikat semuanya = pemilik; sha256/ukuran sama dengan hasil daemon"
  else
    row GAGAL "$N12" "apksigner verify=$rcv zipalign=$rca digest=${count:-0} bukan-pemilik=${bad:-?} sha=$(short "$sha")… ukuran=$size (hasil daemon: $(short "$(kv sha "$HL")")… / $(kv size "$HL")). $(printf '%s\n' "$v" | tail -n 3)"
  fi
}

# ------------------------------------------------------------------------------------------------ langkah 13-16 (negatif)
step13() {
  run_sc sign "$SENT_AID" 3 --timeout 60 --expect-error input_missing
  if [ "$RC" -eq 0 ] && ls_names 3 | grep -q -x 'signed.apk'; then row GAGAL "$N13" "kode input_missing benar tetapi signed.apk tercipta"; return; fi
  expect_result "$N13" "input_missing; tidak ada signed.apk"
}

step14() {
  local names
  SC_DIAG=1 run_sc put-garbage "$SENT_AID" 2
  if [ "$RC" -ne 0 ]; then row GAGAL "$N14" "put-garbage: $(err_text)"; return; fi
  run_sc sign "$SENT_AID" 2 --timeout 60 --expect-error align_failed
  if [ "$RC" -ne 0 ]; then expect_result "$N14" ""; return; fi
  names="$(ls_names 2)"
  if [ "$names" = unsigned.apk ]; then row OK "$N14" "align_failed; folder hanya unsigned.apk (tanpa signed.apk/.sign-*/.idsig)"
  else row GAGAL "$N14" "align_failed benar tetapi ada sisa artefak: $(printf '%s' "$names" | tr '\n' ' ')"; fi
}

step15() {
  SC_DIAG=1 run_sc put-symlink "$SENT_AID" 4
  if [ "$RC" -ne 0 ]; then row GAGAL "$N15" "put-symlink: $(err_text)"; return; fi
  run_sc sign "$SENT_AID" 4 --timeout 60 --expect-error input_unsafe
  expect_result "$N15" "input_unsafe (O_NOFOLLOW terbukti di filesystem nyata)"
}

step16() {
  SC_DIAG=1 run_sc bad-request "$SENT_AID" 1 --kind traversal --expect-error bad_request
  expect_result "$N16" "bad_request untuk analysis_id berisi '../etc' dan bidang path"
  watch_stop W1
}

# ------------------------------------------------------------------------------------------------ langkah 17 (opsional)
BIG_SKIPPED=0
big_case() { # big_case LABEL BUILD_ID ENTRIES WATCH [--jar-meta]
  local label="$1" bid="$2" entries="$3" w="$4" extra="${5:-}" el
  echo "• langkah $label: menulis APK ${BIG_MB} MiB, $entries entri, lalu menandatangani (bisa beberapa menit)…" >&2
  watch_start "$w" || true
  # shellcheck disable=SC2086
  SC_DIAG=1 run_sc_in put-big "$SENT_AID" "$bid" --size-mb "$BIG_MB" --entries "$entries" $extra <"$APK"
  if [ "$RC" -ne 0 ]; then
    watch_stop "$w"
    row GAGAL "17$label APK besar" "put-big: $(err_text)"
    run_sc clean "$SENT_AID" "$bid"
    return
  fi
  run_sc sign "$SENT_AID" "$bid" --timeout 900 --expect-ok --owner-sha256 "$OWNER"
  watch_stop "$w"
  el="$(kv elapsed "$(pick 'HASIL ')")"
  expect_result "17$label APK besar $entries entri${extra:+ + META-INF}" "${BIG_MB} MiB, $entries entri${extra:+, META-INF (v1 aktif)}: sukses dalam ${el:-?} dtk"
  run_sc clean "$SENT_AID" "$bid"
}

step17() {
  local free need
  if [ -z "$BIG_MB" ]; then row DILEWATI "$N17" "uji besar tidak diminta (set BIG_MB=<MiB>, mis. BIG_MB=1000)"; BIG_SKIPPED=1; return; fi
  if [ "$APK_OK" != 1 ] || [ -z "$OWNER" ]; then row DILEWATI "$N17" "butuh APK uji yang valid (langkah 8) dan sidik jari pemilik (langkah 7)"; BIG_SKIPPED=1; return; fi
  run_sc df
  free="$(lv bebas_mib "$OUT")"; need=$((2 * BIG_MB + 16 + 1024))
  if ! is_num "$free"; then row DILEWATI "$N17" "ruang bebas tidak terbaca ($(err_text))"; BIG_SKIPPED=1; return; fi
  if [ "$free" -lt "$need" ]; then
    row DILEWATI "$N17" "ruang tidak cukup untuk uji (butuh $need MiB, bebas $free MiB); ini perilaku no_space yang benar, bukan kegagalan"
    BIG_SKIPPED=1
    return
  fi
  big_case a 5 1 W2 ""
  big_case b 6 60000 W3 ""
  big_case c 7 60000 W4 "--jar-meta"
}

# ------------------------------------------------------------------------------------------------ langkah 18-19
step18() {
  local pw bocor=0 n seen=0 b leak lrc ldiag lbocor logs_hit="" why="" fail=""
  pw="$(tr -d '\r\n' <secrets/signing_keystore_pass 2>/dev/null)"
  if [ "${#pw}" -lt 16 ]; then
    row DILEWATI "$N18" "berkas sandi tak lazim (kurang dari 16 karakter atau tak terbaca): pemeriksaan kebocoran tidak bermakna"
    return
  fi
  for n in W1 W2 W3 W4; do
    if has_watch "$n"; then
      seen=$((seen + 1))
      b="$(wv "$n" bocor)"; is_num "$b" && bocor=$((bocor + b))
    fi
  done
  # Potret SATU KALI pada daemon yang HIDUP (proses daemon dan tini ikut terperiksa).
  leak="$($COMPOSE --profile build exec -T signer signer-selftest --leak-scan 2>/dev/null </dev/null 7>&- | tr -d '\r')"; lrc=$?
  ldiag="$(lv diperiksa "$leak")"; lbocor="$(lv bocor "$leak")"
  $COMPOSE --profile build logs --no-color signer >"$T/signer.log" 2>&1 </dev/null 7>&-
  # Sandi TIDAK boleh muncul di argv `grep` (terlihat di /proc/<pid>/cmdline dan `ps` host): pola dibaca dari berkas (substitusi proses; printf builtin).
  grep -F -q -f <(printf '%s\n' "$pw") "$T/signer.log" "$T/outputs.log" && logs_hit=1
  pw=""
  [ "$bocor" -gt 0 ] && fail="$fail pemotret melihat sandi di $bocor sampel;"
  if [ "$lrc" -eq 1 ] || { is_num "$lbocor" && [ "$lbocor" -gt 0 ]; }; then fail="$fail --leak-scan: bocor=${lbocor:-?};"; fi
  [ -n "$logs_hit" ] && fail="$fail sandi ada di log signer atau keluaran HASIL/GALAT;"
  if [ -n "$fail" ]; then row GAGAL "$N18" "KATA SANDI BOCOR:$fail"; return; fi
  if ! has_watch W1; then why="pemotret tidak menghasilkan keluaran"
  elif [ "$(wv W1 argv_apksigner)" = 0 ] || ! is_num "$(wv W1 argv_apksigner)"; then why="pemotret tidak sempat melihat argv apksigner (0 sampel)"
  fi
  if [ -n "$why" ]; then
    row DILEWATI "$N18" "tidak terbukti: $why. Yang terbukti: --leak-scan (${ldiag:-?} berkas /proc) dan log/hasil tanpa sandi"
    return
  fi
  row OK "$N18" "$(wv W1 samples) sampel W1, argv apksigner teramati $(wv W1 argv_apksigner) kali, tanpa sandi; --leak-scan ${ldiag:-?} berkas /proc bersih; log signer dan hasil bersih"
}

step19() {
  local w a o fail="" unmeasured="" shown="" present=0 hint=""
  if has_watch W1; then
    row INFO "$N19 (job 1)" "informasi: anon_peak_mib=$(wv W1 anon_peak_mib) oom_kill=$(wv W1 oom_kill) memory_peak=$(wv W1 memory_peak)"
  fi
  if [ -z "$BIG_MB" ]; then row DILEWATI "$N19" "uji besar tidak diminta (set BIG_MB=<MiB>)"; return; fi
  if [ "$BIG_SKIPPED" = 1 ]; then row DILEWATI "$N19" "uji besar dilewati pada langkah 17"; return; fi
  for w in W2 W3 W4; do
    has_watch "$w" || continue
    present=$((present + 1))
    a="$(wv "$w" anon_peak_mib)"; o="$(wv "$w" oom_kill)"
    shown="$shown $w:anon=$a,oom=$o"
    if is_num "$o" && [ "$o" -gt 0 ]; then fail="$fail $w oom_kill=$o;"; fi
    if is_num "$a"; then
      [ "$a" -ge 400 ] && fail="$fail $w anon_peak_mib=$a (>=400);"
    else
      unmeasured="$unmeasured $w"
    fi
  done
  if [ -n "$fail" ]; then
    case "$fail" in *W2*) ;; *) hint=" Lulus 17a tetapi gagal 17b/17c => curigai MaxDirectMemorySize di wrapper apksigner." ;; esac
    row GAGAL "$N19" "memori melewati kriteria (oom_kill=0 dan anon_peak_mib<400):$fail$hint"
    return
  fi
  if [ "$present" -eq 0 ]; then row DILEWATI "$N19" "tidak terukur: tidak ada keluaran pemotret W2/W3/W4"; return; fi
  if [ -n "$unmeasured" ]; then row DILEWATI "$N19" "tidak terukur (cgroup v2 tidak terbaca) pada:$unmeasured;$shown"; return; fi
  row OK "$N19" "oom_kill=0 dan anon_peak_mib<400 pada$shown"
}

# ------------------------------------------------------------------------------------------------ langkah 20
step20() {
  local n b left="" bids="1 2 3 4"
  for n in W1 W2 W3 W4; do watch_stop "$n"; done
  run_sc clean "$SENT_AID"
  CLEANED=1
  if [ "$RC" -ne 0 ]; then row GAGAL "$N20" "clean sentinel gagal: $(err_text)"; return; fi
  [ -n "$BIG_MB" ] && bids="$bids 5 6 7"
  for b in $bids; do
    [ -z "$(ls_names "$b")" ] || left="$left $b"
  done
  if [ -z "$left" ]; then row OK "$N20" "builds/$SENT_AID dihapus; pemotret dihentikan; folder uji kosong"
  else row GAGAL "$N20" "masih ada isi folder build_id:$left"; fi
}

# ------------------------------------------------------------------------------------------------ alur
if ! step4; then halt_from 5 "dilewati: image tidak terbangun"; exit 1; fi
if ! step5; then halt_from 6 "dilewati: signer tidak sehat"; exit 1; fi
CAN_CLEAN=1
if ! step6; then halt_from 7 "dilewati: daemon tidak menjawab/keystore belum ok"; exit 1; fi
step7
step8
if [ "$APK_OK" = 1 ]; then
  if step9 && [ -n "$OWNER" ]; then
    step10
  else
    row DILEWATI "$N10" "butuh masukan terpasang (langkah 9) dan sidik jari pemilik (langkah 7)"
  fi
else
  row DILEWATI "$N9" "tidak ada APK uji (langkah 8)"
  row DILEWATI "$N10" "tidak ada APK uji (langkah 8)"
fi
if [ "$SIGN_OK" = 1 ]; then
  step11
  step12
else
  row DILEWATI "$N11" "job tanda tangan tidak berhasil"
  row DILEWATI "$N12" "job tanda tangan tidak berhasil"
fi
step13
step14
step15
step16
step17
step18
step19
step20
exit 0
