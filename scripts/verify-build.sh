#!/usr/bin/env bash
# Bukti end-to-end pipeline build (Tahap 2b) di server pemilik: analisis uji -> bench -> diff -> persetujuan -> build di runner -> tanda tangan di signer -> verifikasi
# independen, ditambah negatif TOCTOU/pembatalan, retensi, dan kebersihan. Satu laporan: tabel `LANGKAH | STATUS | KETERANGAN` (status OK, GAGAL, DILEWATI, INFO).
# Pemakaian: scripts/verify-build.sh   (lewat `make verify-build`; butuh Docker Compose v2, keystore sudah dibuat, stack sudah `make up`, testdata/vulnsample.apk ada)
#   BIG_MB=<1..1100>   opsional; hanya dicatat sebagai baris INFO (uji APK besar untuk signer = `BIG_MB=1000 make signer-verify`)
#   VB_STRICT_DIFF=0   opsional; langkah 8: selisih isi di luar allowlist hanya INFO (bawaan 1 = GAGAL; allowlist memuat original/META-INF/* hasil ukur nyata)
# Kode keluar: 0 tidak ada GAGAL; 1 ada GAGAL (atau dihentikan / analisis uji tertinggal); 64 salah pakai.
#
# Prinsip: bash di host TIDAK PERNAH mem-parse JSON. Semua keputusan bergantung isi dibuat DI DALAM kontainer (app.buildctl, signer-selftest --check-apk, tamu
# python di runner) dan dilaporkan sebagai kode keluar 0/3/64 plus baris `kunci=nilai`; skrip ini hanya membaca baris itu dengan sed. Host tidak menulis/menghapus
# apa pun di volume (semua lewat kontainer uid 10001). Tidak ada `exec` ke runner (A-05): kontainer runner hanya `run --rm --no-deps -T`. Analisis uji dibuat sendiri
# dari APK sampel yang dibuat unik (`--uniq`); analisis nyata milik pemilik tidak pernah disentuh (`duplicate=1` = GAGAL berhenti). `trap` selalu membersihkan:
# cancel tiap build aktif milik analisis uji -> wait sampai final -> delete.
#
# Variabel (opsional): COMPOSE (dari Makefile), DOCKER_CMD (bawaan docker; hanya `inspect`), BIG_MB, VB_STRICT_DIFF, TIMEOUT_BUILD/TIMEOUT_SIGN (detik; bawaan 1800/900, dipakai
# menghitung batas tunggu `wait` = TIMEOUT_BUILD + TIMEOUT_SIGN + 120).
# shellcheck disable=SC2329   # print_table/cleanup_aid/on_exit dipanggil lewat trap atau run_all
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
COMPOSE="${COMPOSE:-docker compose}"
DOCKER_CMD="${DOCKER_CMD:-docker}"
BIG_MB="${BIG_MB:-}"
VB_STRICT_DIFF="${VB_STRICT_DIFF:-1}"
TIMEOUT_BUILD="${TIMEOUT_BUILD:-1800}"
TIMEOUT_SIGN="${TIMEOUT_SIGN:-900}"
APK=testdata/vulnsample.apk

case "${1-}" in
  -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) echo "✗ pemakaian: scripts/verify-build.sh   (tanpa argumen; opsional BIG_MB=<MiB>, VB_STRICT_DIFF=0)" >&2; exit 64 ;;
esac
if [ -n "$BIG_MB" ]; then
  if ! [[ "$BIG_MB" =~ ^[0-9]+$ ]] || [ "$BIG_MB" -lt 1 ] || [ "$BIG_MB" -gt 1100 ]; then
    echo "✗ BIG_MB harus bilangan bulat 1..1100 (MiB), diterima: '$BIG_MB'" >&2
    exit 64
  fi
fi
if [ "$VB_STRICT_DIFF" != 0 ] && [ "$VB_STRICT_DIFF" != 1 ]; then
  echo "✗ VB_STRICT_DIFF harus 0 atau 1, diterima: '$VB_STRICT_DIFF'" >&2
  exit 64
fi
[[ "$TIMEOUT_BUILD" =~ ^[0-9]+$ ]] || TIMEOUT_BUILD=1800
[[ "$TIMEOUT_SIGN" =~ ^[0-9]+$ ]] || TIMEOUT_SIGN=900
WAIT_MAX=$((TIMEOUT_BUILD + TIMEOUT_SIGN + 120))

N1="1 prasyarat"
N2="2 analisis uji"
N3="3 init + diff kosong"
N4="4 ubah string via shell"
N5="5 negatif persetujuan"
N6="6 build nyata"
N7="7 verifikasi independen (signer)"
N7B="7b deteksi ubah-pasca-terbit"
N8="8 isi artefak"
N9="9 negatif TOCTOU"
N10="10 negatif pembatalan"
N11="11 retensi"
N12="12 kebersihan"
N13="13 ringkasan"
ORDER=(N1 N2 N3 N4 N5 N6 N7 N7B N8 N9 N10 N11 N12)

# ------------------------------------------------------------------------------------------------ tabel
ROWS_ST=(); ROWS_STEP=(); ROWS_NOTE=()
row() { # row OK|GAGAL|DILEWATI|INFO "langkah" "keterangan"
  local note="${3-}"
  note="$(printf '%s' "$note" | tr '\r\n\t' '   ')"
  ROWS_ST+=("$1"); ROWS_STEP+=("$2"); ROWS_NOTE+=("$note")
}
halt_from() { # halt_from NAMA "alasan": langkah NAMA dan seterusnya sampai 12 DILEWATI
  local v on=0
  for v in "${ORDER[@]}"; do
    [ "$v" = "$1" ] && on=1
    [ "$on" = 1 ] && row DILEWATI "${!v}" "$2"
  done
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
  if [ "$skip" -gt 0 ]; then echo "✓ semua OK ($n baris, $skip dilewati)"; else echo "✓ semua OK ($n baris)"; fi
}

# ------------------------------------------------------------------------------------------------ pembaca keluaran (tanpa JSON)
lv() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | sed -n 1p; }                      # nilai SATU BARIS `kunci=nilai` dari $OUT
is_hex64() { [[ "${1-}" =~ ^[0-9a-f]{64}$ ]]; }
is_num() { [[ "${1-}" =~ ^[0-9]+$ ]]; }
is_dec() { [[ "${1-}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }
short() { printf '%s' "${1:0:12}"; }
le() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 <= b + 0) }'; }                  # a <= b
lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'; }                   # a <  b
rand_hex() { od -An -N6 -tx1 /dev/urandom | tr -d ' \n'; }
is_final() { case "$1" in done | failed | cancelled | rejected) return 0 ;; *) return 1 ;; esac; }

# ------------------------------------------------------------------------------------------------ pemanggil kontainer (9>&-: kunci tidak ikut tertahan)
OUT=""; RC=0
# shellcheck disable=SC2086
bc() { OUT="$(exec 9>&-; $COMPOSE exec -T web python -m app.buildctl "$@" </dev/null 2>&1 | tr -d '\r')"; RC=$?; }
# shellcheck disable=SC2086
bc_in() { OUT="$(exec 9>&-; $COMPOSE exec -T web python -m app.buildctl "$@" <"$APK" 2>&1 | tr -d '\r')"; RC=$?; }
# cx LAYANAN perintah...: untuk web/worker/bench/signer saja (A-05: kontainer yang diproses data tak tepercaya hanya lewat cr)
# shellcheck disable=SC2086
cx() { OUT="$(exec 9>&-; $COMPOSE exec -T "$@" </dev/null 2>&1 | tr -d '\r')"; RC=$?; }
# cr [-e K=V] LAYANAN perintah...: kontainer sekali pakai (pola Makefile `run --rm --no-deps`); SATU-SATUNYA jalan ke runner
# shellcheck disable=SC2086
cr() { OUT="$(exec 9>&-; $COMPOSE run --rm --no-deps -T "$@" </dev/null 2>&1 | tr -d '\r')"; RC=$?; }
err_text() {
  local k a
  k="$(lv kode)"; a="$(lv alasan)"
  if [ -n "$k" ]; then printf 'kode=%s %s' "$k" "$a"; else printf 'kode keluar %s: %s' "$RC" "$(printf '%s\n' "$OUT" | tail -n 3 | tr '\n' ' ')"; fi
}
# o| baris dari `buildctl shell`: nilai app_name lama
shell_cmd() { bc shell "$AID" "$1" --timeout 60; }                                  # shell_cmd 'perintah' ($WS TIDAK diekspansi di host)
shell_ok() { [ "$RC" -eq 0 ] && [ "$(lv status)" = ok ] && [ "$(lv exit_code)" = 0 ]; }

# Tamu python di runner (kontainer sekali pakai). Penanda `# vb-...` di baris pertama membantu tes/diagnosis; jalur artefak selalu lewat rantai-dirfd.
read -r -d '' PY_FLIP <<'PYEOF'
# vb-flip: balik SATU byte (XOR 0xFF, offset 100) artefak; dipanggil dua kali (balik lalu pulihkan). Runner memang punya tulis `builds` (R-1).
import os, re, stat, sys
from rvcore.fsutil import open_dir_chain
aid, bid, name = sys.argv[1:4]
if not (aid.isascii() and aid.isdigit() and bid.isascii() and bid.isdigit() and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", name)):
    print("kode=masukan_salah")
    sys.exit(3)
dfd = open_dir_chain("/data/builds", str(int(aid)), str(int(bid)))
fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size <= 100:
        print("kode=bukan_berkas_biasa")
        sys.exit(3)
    b = os.pread(fd, 1, 100)
    os.pwrite(fd, bytes([b[0] ^ 0xFF]), 100)
    os.fsync(fd)
finally:
    os.close(fd)
    os.close(dfd)
print("flip=ok")
PYEOF
read -r -d '' PY_ISI <<'PYEOF'
# vb-isi: apktool d -f artefak (HOME runner /tmp/home, hasil di /tmp/vb-<acak>) lalu treediff.compute_diff terhadap work/<aid>/apktool; cetak kunci=nilai.
import os, re, shutil, stat, subprocess, sys, tempfile
from rvcore import treediff
from rvcore.fsutil import open_dir_chain
aid, bid, name, mark, old, asal, dsha, strict = sys.argv[1:9]
ALLOW = {("M", "res/values/strings.xml"), ("A", "assets/reverse-apk-modified.txt"), ("M", "apktool.yml"), ("M", "original/AndroidManifest.xml")}
ALLOW_DIRS = {"assets"}     # direktori baru yang hanya menampung berkas allowlist
# apktool menyalin tanda tangan lama APK asal ke original/META-INF/ (diukur nyata di e2e T-3: MANIFEST.MF, *.RSA, *.SF); namanya bergantung kunci APK asal, jadi awalan.
META_PREFIX = "original/META-INF"


def di_luar(op, p, kind):
    if (op, p) in ALLOW or (op == "A" and kind == "d" and p in ALLOW_DIRS):
        return False
    if op == "A" and (p == META_PREFIX or (p.startswith(META_PREFIX + "/") and ".." not in p.split("/"))):
        return False
    return True


def kv(key, value):
    print("%s=%s" % (key, str(value).replace("\n", " ")[:300]))


if not (aid.isascii() and aid.isdigit() and bid.isascii() and bid.isdigit() and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", name)
        and re.fullmatch(r"[0-9a-f]{64}", asal) and re.fullmatch(r"[0-9a-f]{64}", dsha) and re.fullmatch(r"VB[0-9a-f]{12}", mark)):
    kv("apktool", "masukan_salah")
    sys.exit(3)
aid, bid = str(int(aid)), str(int(bid))
dfd = open_dir_chain("/data/builds", aid, bid)
fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
if not stat.S_ISREG(os.fstat(fd).st_mode):
    kv("apktool", "bukan_berkas_biasa")
    sys.exit(3)
os.close(fd)
os.close(dfd)
os.makedirs(os.environ.get("HOME", "/tmp/home"), exist_ok=True)
tmp = tempfile.mkdtemp(prefix="vb-", dir="/tmp")
try:
    out = os.path.join(tmp, "out")
    run = subprocess.run(["apktool", "d", "-f", "-j", "2", "-o", out, "/data/builds/%s/%s/%s" % (aid, bid, name)], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=900)
    if run.returncode != 0:
        kv("apktool", "gagal kode %d: %s" % (run.returncode, (run.stdout + run.stderr).strip().splitlines()[-1:] or ""))
        sys.exit(3)
    entries = []
    try:
        treediff.compute_diff("/data/work/%s/apktool" % aid, out, collect=entries)
    except treediff.TreeLimitError as exc:
        kv("apktool", "treediff gagal: %s" % exc)
        sys.exit(3)
    diffs = [(e[0], e[1], e[2]) for e in entries]
    outside = [(op, p) for op, p, kind in diffs if di_luar(op, p, kind)]
    with open(os.path.join(out, "res/values/strings.xml"), encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    baru = int(mark in text)
    lama = int(bool(re.search(r'<string name="app_name">%s</string>' % re.escape(old), text)))
    try:
        with open(os.path.join(out, "assets/reverse-apk-modified.txt"), encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    jasal, jdiff = int("asal_sha256=" + asal in lines), int("diff_sha256=" + dsha in lines)
    kv("apktool", "ok")
    kv("strings_baru", baru)
    kv("strings_lama", lama)
    kv("jejak_asal", jasal)
    kv("jejak_diff", jdiff)
    kv("selisih_n", len(diffs))
    kv("selisih_luar_n", len(outside))
    for n, (op, p) in enumerate(outside[:20], 1):
        kv("selisih_luar.%d" % n, "%s %s" % (op, p))
    for n, (op, p, kind) in enumerate(diffs[:40], 1):
        kv("selisih.%d" % n, "%s %s" % (op, p))
    sys.exit(0 if (baru == 1 and lama == 0 and jasal and jdiff and (strict != "1" or not outside)) else 3)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
PYEOF
read -r -d '' SH_MOUNT <<'SHEOF'
for p in /data/signwork /data/signspool /data/benchspool /data/files /data/db; do test ! -e "$p" || { echo "ada=$p"; exit 1; }; done
if ( : > /data/bench/.vb-bench_tulis ) 2>/dev/null; then rm -f /data/bench/.vb-bench_tulis; echo "bench_tulis=1 (seharusnya ro)"; exit 1; fi
f=/data/builds/.vb-tulis.$$
( : > "$f" ) 2>/dev/null || { echo "builds_tulis=0 (seharusnya rw)"; exit 1; }
rm -f "$f"
echo mount=ok
SHEOF
# shellcheck disable=SC2016
SH_ABSENT='for p in "$@"; do test ! -e "$p" || exit 1; done'

# ------------------------------------------------------------------------------------------------ penutup (juga lewat trap)
AID=""; APK_SHA=""; CLEAN_NOTE=""; LEFT=""; INTERRUPTED=0; NO_TABLE=0
settle() { # settle: batalkan tiap build AKTIF milik analisis uji, tunggu sampai final; build yang tak final masuk $LEFT
  LEFT=""
  [ -n "$AID" ] || return 0
  bc status --analysis "$AID"
  [ "$RC" -eq 0 ] || return 0                                                     # analisis sudah tidak ada
  local list item id st
  local -a items=() active=()
  list="$(lv builds)"
  IFS=, read -r -a items <<<"$list"
  for item in ${items[@]+"${items[@]}"}; do
    id="${item%%:*}"; st="${item#*:}"
    if [ -n "$id" ] && ! is_final "$st"; then active+=("$id"); bc cancel "$id"; fi
  done
  for id in ${active[@]+"${active[@]}"}; do
    bc wait "$id" --timeout 120
    is_final "$(lv status)" || LEFT="$LEFT $id"
  done
}
cleanup_aid() { # urutan TETAP: cancel -> wait -> delete (delete ditolak `busy` selama ada build aktif, NB-2)
  [ -n "$AID" ] || return 0
  settle
  if [ -n "$LEFT" ]; then
    CLEAN_NOTE="analisis uji TERTINGGAL aid=$AID (build masih aktif:$LEFT)"
    echo "✗ $CLEAN_NOTE" >&2
  fi
  bc delete "$AID"
  if [ "$(lv hasil)" = deleted ]; then
    AID=""
  elif [ -z "$CLEAN_NOTE" ]; then
    CLEAN_NOTE="analisis uji TERTINGGAL aid=$AID (delete gagal: $(err_text))"
    echo "✗ $CLEAN_NOTE" >&2
  fi
}
on_exit() {
  trap - EXIT INT TERM
  if [ "$NO_TABLE" = 1 ]; then exit 1; fi
  cleanup_aid
  [ "$INTERRUPTED" = 1 ] && row GAGAL "dihentikan" "skrip dihentikan sebelum selesai; build uji dibatalkan dan analisis uji dibersihkan"
  [ -n "$CLEAN_NOTE" ] && row GAGAL "pembersihan" "$CLEAN_NOTE"
  row INFO "$N13" "total $SECONDS dtk. BELUM DIUJI oleh skrip ini: RQ/antrean di bawah beban, APK besar (BIG_MB), disk penuh, runner terkompromi; ringkasan gejala per langkah: docs/deploy.md"
  print_table
  exit $?
}
trap on_exit EXIT
trap 'INTERRUPTED=1; exit 1' INT TERM

echo "• verify-build: bukti pipeline build dengan analisis uji sendiri (APK sampel dibuat unik; data nyata tidak disentuh)" >&2

# ------------------------------------------------------------------------------------------------ gerbang HOST (nol panggilan Docker)
if ! ./scripts/keystore.sh present >/dev/null 2>&1; then
  row GAGAL "$N1" "keystore belum dibuat (secrets/signing_keystore.p12 + signing_keystore_pass) -> jalankan: make keystore (nol panggilan Docker)"
  halt_from N2 "dilewati: kunci di host belum beres (tidak ada panggilan Docker)"
  exit 1
fi
LOCK_INFO=""
if command -v flock >/dev/null 2>&1; then
  if ! { ( umask 077; : >>secrets/.verify-build.lock ) && exec 9>>secrets/.verify-build.lock; } 2>/dev/null; then
    LOCK_INFO="kunci antar-proses tidak bisa dibuat (secrets/.verify-build.lock); lanjut tanpa kunci"
  elif ! flock -n 9; then
    echo "✗ verify-build lain sedang berjalan (kunci secrets/.verify-build.lock)" >&2
    NO_TABLE=1
    exit 1
  fi
else
  LOCK_INFO="flock tidak ada: dua verify-build serentak tidak dicegah; jangan jalankan dua sekaligus"
fi
if ! chk="$(./scripts/keystore.sh check 2>&1)"; then
  row GAGAL "$N1" "izin kunci host salah: $(printf '%s' "$chk" | tail -n 2) (nol panggilan Docker)"
  halt_from N2 "dilewati: kunci di host belum beres (tidak ada panggilan Docker)"
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
health_of() { # health_of LAYANAN -> healthy|unhealthy|starting|none|absen
  local cid
  # shellcheck disable=SC2086
  cid="$($COMPOSE ps -q "$1" 2>/dev/null </dev/null | sed -n 1p)"
  [ -n "$cid" ] || { echo absen; return; }
  $DOCKER_CMD inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null </dev/null || echo absen
}
step1() {
  local ver svc hs p
  local -a bad=()
  # shellcheck disable=SC2086
  if ! ver="$($COMPOSE version --short 2>&1 </dev/null)" || [ -z "$ver" ]; then
    row GAGAL "$N1" "'$COMPOSE version' gagal: $(printf '%s' "$ver" | tail -n 2); pasang Docker Compose v2"
    return 1
  fi
  for svc in web worker redis runner bench signer; do
    hs="$(health_of "$svc")"
    [ "$hs" = healthy ] || bad+=("$svc tidak sehat (status: $hs; make logs)")
  done
  cr runner test -f /app/buildstage.py; [ "$RC" -eq 0 ] || bad+=("image runner lama (tak ada /app/buildstage.py)")
  cx bench test -f /app/bench/workspace.py; [ "$RC" -eq 0 ] || bad+=("image bench lama (tak ada /app/bench/workspace.py)")
  cx web test -f /srv/app/buildctl.py; [ "$RC" -eq 0 ] || bad+=("image web lama (tak ada /srv/app/buildctl.py)")
  cx worker test -f /app/builds.py; [ "$RC" -eq 0 ] || bad+=("image worker lama (tak ada /app/builds.py)")
  cx signer grep -q -e --check-apk /usr/local/bin/signer-selftest; [ "$RC" -eq 0 ] || bad+=("image signer lama (signer-selftest tanpa --check-apk)")
  cx bench bench-daemon --check; [ "$RC" -eq 0 ] || bad+=("bench-daemon --check gagal (Landlock?): $(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')")
  cr runner sh -c "$SH_MOUNT"
  if [ "$RC" -ne 0 ]; then bad+=("isolasi mount runner: $(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')"); fi
  cx bench test ! -e /data/builds; [ "$RC" -eq 0 ] || bad+=("/data/builds ada di bench")
  cx signer test -d /data/signwork; [ "$RC" -eq 0 ] || bad+=("/data/signwork tidak ada di signer")
  if [ ! -f "$APK" ]; then
    bad+=("$APK HILANG. Buat sekali: python3 scripts/sample-apk/build.py (skrip ini tidak memanggilnya; skrip itu dapat mencetak traceback PermissionError dari TemporaryDirectory yang SUDAH DIKETAHUI dan tidak menggagalkan APK)")
  elif [ "$(head -c 4 "$APK" | od -An -tx1 | tr -d ' \n')" != 504b0304 ]; then
    bad+=("$APK bukan ZIP/APK (tanda awal PK tidak ada)")
  fi
  if [ "${#bad[@]}" -gt 0 ]; then
    p="$(printf '%s; ' "${bad[@]}")"
    row GAGAL "$N1" "${p%; }. Bila 'image lama': jalankan make up lalu ulangi"
    return 1
  fi
  row OK "$N1" "Compose $ver; web/worker/redis/runner/bench/signer sehat; image memuat kode 2b; bench-daemon --check lulus; mount runtime sesuai (runner: tanpa signwork/signspool/benchspool/files/db, bench ro, builds rw)"
  [ -n "$LOCK_INFO" ] && row INFO "kunci antar-proses" "$LOCK_INFO"
  return 0
}

# ------------------------------------------------------------------------------------------------ langkah 2-4
H0=""; MARK=""; OLD=""; H1=""
step2() {
  local dup aid status
  echo "• langkah 2: analisis APK uji lewat stdin (bisa beberapa menit)…" >&2
  bc_in analyze - --uniq
  dup="$(lv duplicate)"; aid="$(lv analysis_id)"; status="$(lv status)"
  if [ "$dup" = 1 ]; then
    row GAGAL "$N2" "duplicate=1: APK sampel sudah ada sebagai analisis lain; menolak melanjutkan (analisis nyata milik pemilik TIDAK disentuh). Jalankan ulang; --uniq seharusnya membuat hash unik"
    return 1
  fi
  if [ "$dup" = 0 ] && is_num "$aid"; then AID="$aid"; APK_SHA="$(lv sha256)"; fi
  if [ "$RC" -ne 0 ] || [ "$status" != "done" ] || [ -z "$AID" ] || ! is_hex64 "$APK_SHA"; then
    row GAGAL "$N2" "analisis uji gagal (status=${status:--}): $(err_text)"
    return 1
  fi
  row OK "$N2" "analysis_id=$AID duplicate=0 status=done elapsed=$(lv elapsed) dtk"
}
step3() {
  local h1 h2 h3 problem=""
  bc init "$AID"
  if [ "$RC" -ne 0 ] || [ "$(lv created)" != 1 ]; then row GAGAL "$N3" "init pertama harus created=1: $(err_text) created=$(lv created)"; return 1; fi
  bc diff "$AID"; h1="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || [ "$(lv added)$(lv modified)$(lv removed)" != 000 ] || ! is_hex64 "$h1"; then
    row GAGAL "$N3" "diff awal harus kosong (added=$(lv added) modified=$(lv modified) removed=$(lv removed)): $(err_text)"
    return 1
  fi
  bc diff "$AID"; h2="$(lv diff_sha256)"
  [ "$RC" -eq 0 ] && [ "$h2" = "$h1" ] || problem="diff kedua beda hash"
  bc init "$AID"
  if [ "$RC" -ne 0 ] || [ "$(lv created)" != 0 ] || [ "$(lv reason)" != exists ]; then problem="$problem; init ulang harus created=0 reason=exists (created=$(lv created) reason=$(lv reason))"; fi
  bc diff "$AID"; h3="$(lv diff_sha256)"
  [ "$h3" = "$h1" ] || problem="$problem; hash berubah setelah init ulang"
  if [ -n "$problem" ]; then row GAGAL "$N3" "$problem"; return 1; fi
  H0="$h1"
  row OK "$N3" "created=1; diff kosong dua kali dengan hash sama ($(short "$H0")…); init ulang created=0 reason=exists dan hash tetap"
}
sed_marker() { # sed_marker MARKER: ganti nilai app_name di $WS/project lewat shell NYATA (jalur bench + Landlock yang sama dengan tool AI)
  # shellcheck disable=SC2016
  shell_cmd 'sed -i "s|\(<string name=.app_name.>\)[^<]*|\1'"$1"'|" "$WS/project/res/values/strings.xml"'
}
step4() {
  local old
  # shellcheck disable=SC2016
  shell_cmd 'grep -o "<string name=.app_name.>[^<]*" "$WS/project/res/values/strings.xml"'
  old="$(printf '%s\n' "$OUT" | sed -n 's/^o| <string name="app_name">//p' | sed -n 1p)"
  if ! shell_ok || [ -z "$old" ]; then row GAGAL "$N4" "tidak bisa membaca app_name sampel lewat shell: $(err_text)"; return 1; fi
  OLD="$old"
  MARK="VB$(rand_hex)"
  sed_marker "$MARK"
  if ! shell_ok; then row GAGAL "$N4" "sed lewat shell gagal: $(err_text) status=$(lv status) exit_code=$(lv exit_code)"; return 1; fi
  bc diff "$AID"; H1="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || [ "$(lv modified)" != 1 ] || [ "$(lv added)" != 0 ] || [ "$(lv removed)" != 0 ] || [[ "$(lv file.1)" != "M res/values/strings.xml"* ]] || [ "$H1" = "$H0" ] || ! is_hex64 "$H1"; then
    row GAGAL "$N4" "diff sesudah sed harus tepat satu 'M res/values/strings.xml' (modified=$(lv modified) added=$(lv added) removed=$(lv removed) file.1=$(lv file.1)); hash beda dari kosong: $([ "$H1" != "$H0" ] && echo ya || echo tidak)"
    return 1
  fi
  row OK "$N4" "shell nyata: app_name '$OLD' -> $MARK; diff = modified=1 'M res/values/strings.xml'; hash $(short "$H1")… beda dari diff kosong"
}

# ------------------------------------------------------------------------------------------------ langkah 5
absent() { cr runner sh -c "$SH_ABSENT" vb-absent "$@"; }                         # absent PATH...: semua tidak ada (RC 0)
step5() {
  local b1 h wrong st problem=""
  bc approve 999999999 --diff-sha256 0000000000000000000000000000000000000000000000000000000000000000
  if [ "$RC" -ne 3 ] || [ "$(lv kode)" != build_tidak_ada ]; then problem="(a) id tak ada harus kode 3 build_tidak_ada (kode keluar $RC, $(err_text))"; fi
  bc request "$AID"
  b1="$(lv build_id)"; h="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || ! is_num "$b1" || ! is_hex64 "$h"; then
    row GAGAL "$N5" "${problem:+$problem; }request gagal: $(err_text)"
    settle
    return 1
  fi
  [ "$h" = "$H1" ] || problem="$problem; (b) hash request ($(short "$h")…) beda dari diff langkah 4"
  wrong="$([ "${h:0:1}" = 0 ] && echo 1 || echo 0)${h:1}"
  bc approve "$b1" --diff-sha256 "$wrong"
  if [ "$RC" -ne 3 ] || [ "$(lv kode)" != diff_berubah ]; then problem="$problem; (b) hash salah harus kode 3 diff_berubah (kode keluar $RC, $(err_text))"; fi
  bc status "$b1"; st="$(lv status)"
  [ "$st" = awaiting_approval ] || problem="$problem; (b) status build seharusnya tetap awaiting_approval (sekarang: ${st:--})"
  cr worker python -c 'import tasks,sys; tasks.run_build(int(sys.argv[1]))' "$b1"
  [ "$RC" -eq 0 ] || problem="$problem; (c) eksekutor worker pada build belum disetujui harus kembali tanpa galat: $(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')"
  bc status "$b1"; st="$(lv status)"
  [ "$st" = awaiting_approval ] || problem="$problem; (c) status berubah setelah run_build tanpa persetujuan (${st:--})"
  absent "/data/builds/$AID/$b1"
  [ "$RC" -eq 0 ] || problem="$problem; (c) folder builds/$AID/$b1 ada padahal belum disetujui"
  bc cancel "$b1"
  if [ "$RC" -ne 0 ] || [ "$(lv hasil)" != cancelled ]; then problem="$problem; (d) cancel harus hasil=cancelled ($(err_text))"; fi
  if [ -n "$problem" ]; then
    row GAGAL "$N5" "${problem#; }"
    settle
    return 1
  fi
  row OK "$N5" "id tak ada -> build_tidak_ada; hash salah -> diff_berubah (status tetap awaiting_approval); run_build tanpa persetujuan tanpa kerja dan tanpa folder; cancel -> cancelled"
}

# ------------------------------------------------------------------------------------------------ langkah 6
BID=""; ONAME=""; OSHA=""; OSIZE=""; OCERT=""; ART_OK=0
build_once() { # build_once -> request+approve+wait; isi B_ID/B_HASH; RC 0 hanya bila done
  B_ID=""; B_HASH=""
  bc request "$AID"
  B_ID="$(lv build_id)"; B_HASH="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || ! is_num "$B_ID" || ! is_hex64 "$B_HASH"; then B_ID=""; return 2; fi
  bc approve "$B_ID" --diff-sha256 "$B_HASH"
  if [ "$RC" -ne 0 ] || [ "$(lv enqueued)" != 1 ]; then return 3; fi
  return 0
}
step6() {
  local trace a b c d antre bld sign peak why
  echo "• langkah 6: build + tanda tangan nyata (menunggu paling lama ${WAIT_MAX} dtk)…" >&2
  build_once
  case $? in
    2) row GAGAL "$N6" "request gagal: $(err_text)"; return 1 ;;
    3) row GAGAL "$N6" "approve gagal atau tidak masuk antrean: $(err_text) enqueued=$(lv enqueued)"; return 1 ;;
  esac
  BID="$B_ID"
  bc wait "$BID" --trace --timeout "$WAIT_MAX"
  trace="$(printf '%s\n' "$OUT" | sed -n 's/^trace\.[0-9]*=//p' | tr '\n' ' ')"
  if [ "$RC" -ne 0 ]; then
    row GAGAL "$N6" "build tidak selesai (status=$(lv status) error_code=$(lv error_code)): $(lv error_text) $(err_text)"
    return 1
  fi
  bc status "$BID"
  ONAME="$(lv output_name)"; OSHA="$(lv output_sha256)"; OSIZE="$(lv output_size)"; OCERT="$(lv cert_sha256)"
  a="$(lv approved_at)"; b="$(lv started_at)"; c="$(lv signing_mulai)"; d="$(lv finished_at)"
  antre="$(lv waktu_antre)"; bld="$(lv waktu_build)"; sign="$(lv waktu_tanda_tangan)"
  peak="$(printf '%s\n' "$OUT" | sed -n 's/.*peak_mem_mib=\([0-9]*\).*/\1/p' | sed -n 1p)"
  why=""
  [ "$RC" -eq 0 ] && [ "$(lv status)" = "done" ] || why="status bukan done"
  [ "$(lv verify_ok)" = 1 ] || why="$why; verify_ok bukan 1"
  is_hex64 "$OCERT" || why="$why; cert_sha256 kosong/bukan hex64"
  [[ "$ONAME" =~ ^[A-Za-z0-9._-]+-modified-${BID}\.apk$ ]] || why="$why; output_name '$ONAME' tidak cocok pola ^[A-Za-z0-9._-]+-modified-$BID\\.apk\$"
  if is_dec "$a" && is_dec "$b" && is_dec "$c" && is_dec "$d"; then
    { le "$a" "$b" && lt "$b" "$c" && lt "$c" "$d"; } || why="$why; cap waktu DB tidak monoton (approved_at=$a started_at=$b signing_mulai=$c finished_at=$d; harus approved_at<=started_at<signing_mulai<finished_at)"
  else
    why="$why; cap waktu DB hilang (approved_at='$a' started_at='$b' signing_mulai='$c' finished_at='$d')"
  fi
  if [ -n "$why" ]; then row GAGAL "$N6" "${why#; }"; return 1; fi
  ART_OK=1
  row OK "$N6" "queued -> done; antre ${antre}s, build ${bld}s, tanda tangan ${sign}s (cap DB approved_at<=started_at<signing_mulai<finished_at); verify_ok=1 cert=$(short "$OCERT")… output=$ONAME${peak:+; peak_mem_mib=$peak}${trace:+; jejak: $trace}"
  return 0
}

# ------------------------------------------------------------------------------------------------ langkah 7 dan 7b
OWNER=""
step7() {
  local info_out irc k fails=""
  local signers v2 v3 cert za sha size
  info_out="$(./scripts/keystore.sh info 2>&1)"; irc=$?
  OWNER="$(printf '%s\n' "$info_out" | sed -n 's/^ *SHA-256 (heks kecil): *//p' | sed -n 1p | tr -d ' \r')"
  if [ "$irc" -ne 0 ] || ! is_hex64 "$OWNER"; then
    OWNER=""
    row GAGAL "$N7" "keystore.sh info tidak memberi sidik jari (kode $irc): $(printf '%s\n' "$info_out" | tail -n 2 | tr '\n' ' ')"
    return 1
  fi
  cx signer signer-selftest --check-apk "$AID" "$BID" "$ONAME"
  signers="$(lv signers)"; v2="$(lv v2)"; v3="$(lv v3)"; cert="$(lv cert)"; za="$(lv zipalign)"; sha="$(lv sha)"; size="$(lv size)"
  [ "$RC" -eq 0 ] || fails="signer-selftest --check-apk kode keluar $RC ($(lv kode) $(lv alasan))"
  [ "$signers" = 1 ] || fails="$fails; signers=${signers:--} (harus 1)"
  [ "$v2" = 1 ] || fails="$fails; v2=${v2:--} (harus 1)"
  [ "$v3" = 1 ] || fails="$fails; v3=${v3:--} (harus 1)"
  [ "$cert" = "$OWNER" ] || fails="$fails; cert $(short "$cert")… != keystore pemilik $(short "$OWNER")…"
  [ "$za" = ok ] || fails="$fails; zipalign=${za:--} (harus ok)"
  bc artifact-info "$BID"
  if [ "$RC" -ne 0 ] || [ "$(lv cocok)" != 1 ]; then fails="$fails; artifact-info: $(err_text) cocok=$(lv cocok)"; fi
  [ "$sha" = "$OSHA" ] && [ "$sha" = "$(lv disk_sha256)" ] || fails="$fails; sha selftest $(short "$sha")… != DB $(short "$OSHA")… / disk $(short "$(lv disk_sha256)")…"
  [ "$size" = "$OSIZE" ] || fails="$fails; ukuran selftest ${size:--} != DB ${OSIZE:--}"
  [ "$(lv output_sha256)" = "$OSHA" ] || fails="$fails; output_sha256 artifact-info beda dari status"
  if [ -n "$fails" ]; then row GAGAL "$N7" "${fails#; }"; return 1; fi
  row OK "$N7" "signers=1 v2=1 v3=1 zipalign=ok cert=$(short "$cert")… == keystore pemilik; sha256 $(short "$sha")… dan ukuran $size sama di signer, DB, dan hash ulang disk"
}
flip() { cr runner python3 -c "$PY_FLIP" "$AID" "$BID" "$ONAME"; [ "$RC" -eq 0 ] && [ "$(lv flip)" = ok ]; }
step7b() {
  local problem="" flipped=0
  if flip; then flipped=1; else problem="balik byte gagal: $(err_text) $(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')"; fi
  if [ "$flipped" = 1 ]; then
    bc artifact-info "$BID"
    if [ "$RC" -eq 0 ]; then
      problem="deteksi R-1 TIDAK bekerja: artifact-info kode 0 padahal satu byte dibalik"
    elif [ "$RC" -ne 3 ] || [ "$(lv kode)" != hash_tidak_cocok ] || [ "$(lv cocok)" != 0 ]; then
      problem="sesudah byte dibalik diharapkan kode 3 hash_tidak_cocok cocok=0, dapat: $(err_text) cocok=$(lv cocok)"
    fi
    if flip; then
      bc artifact-info "$BID"
      if [ "$RC" -ne 0 ] || [ "$(lv cocok)" != 1 ]; then
        problem="$problem; artefak TIDAK pulih setelah byte dibalik lagi: $(err_text)"
        ART_OK=0
      fi
    else
      problem="$problem; byte TIDAK bisa dipulihkan: $(err_text)"
      ART_OK=0
    fi
  fi
  if [ -n "$problem" ]; then row GAGAL "$N7B" "${problem#; }"; return 1; fi
  row OK "$N7B" "balik 1 byte (XOR 0xFF, offset 100) lewat runner -> artifact-info kode 3 hash_tidak_cocok cocok=0; dibalik lagi -> cocok=1"
}

# ------------------------------------------------------------------------------------------------ langkah 8
step8() {
  local luar
  echo "• langkah 8: apktool d pada artefak di runner (bisa beberapa menit)…" >&2
  cr runner python3 -c "$PY_ISI" "$AID" "$BID" "$ONAME" "$MARK" "$OLD" "$APK_SHA" "$H1" "$VB_STRICT_DIFF"
  luar="$(printf '%s\n' "$OUT" | sed -n 's/^selisih_luar\.[0-9]*=//p' | head -n 10 | tr '\n' ';')"
  if [ "$RC" -ne 0 ]; then
    row GAGAL "$N8" "apktool=$(lv apktool) strings_baru=$(lv strings_baru) strings_lama=$(lv strings_lama) jejak_asal=$(lv jejak_asal) jejak_diff=$(lv jejak_diff) selisih_luar_n=$(lv selisih_luar_n)${luar:+ di luar allowlist: $luar} (VB_STRICT_DIFF=$VB_STRICT_DIFF) $(printf '%s' "$OUT" | grep -v '^[a-z_.0-9]*=' | tail -n 2 | tr '\n' ' ')"
    return 1
  fi
  row OK "$N8" "app_name = $MARK (nilai lama '$OLD' hilang); jejak memuat asal_sha256 APK uji dan diff_sha256 build; selisih $(lv selisih_n) entri terhadap work/$AID/apktool"
  if [ "$(lv selisih_luar_n)" != 0 ]; then
    row INFO "8 selisih di luar allowlist" "$(lv selisih_luar_n) entri (mode longgar VB_STRICT_DIFF=0; bawaan 1 menjadikannya GAGAL): ${luar}"
  fi
  return 0
}

# ------------------------------------------------------------------------------------------------ langkah 9-11
MARK2=""
step9() {
  local b h2 problem="" st
  bc request "$AID"
  b="$(lv build_id)"; H9="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || ! is_num "$b" || ! is_hex64 "$H9"; then row GAGAL "$N9" "request gagal: $(err_text)"; return 1; fi
  bc approve "$b" --diff-sha256 "$H9" --hold
  if [ "$RC" -ne 0 ] || [ "$(lv status)" != queued ] || [ "$(lv enqueued)" != 0 ]; then problem="approve --hold harus queued tanpa antrean: $(err_text) status=$(lv status) enqueued=$(lv enqueued)"; fi
  MARK2="VB$(rand_hex)"
  sed_marker "$MARK2"
  shell_ok || problem="$problem; sed kedua gagal: $(err_text)"
  bc diff "$AID"; h2="$(lv diff_sha256)"
  [ "$h2" != "$H9" ] && is_hex64 "$h2" || problem="$problem; hash workspace tidak berubah setelah sed kedua"
  bc approve "$b" --diff-sha256 "$H9"
  if [ "$RC" -ne 0 ] || [ "$(lv enqueued)" != 1 ]; then problem="$problem; pelepasan dengan hash H1 gagal: $(err_text)"; fi
  bc wait "$b" --timeout "$WAIT_MAX"
  st="$(lv status)"
  if [ "$RC" -eq 0 ] || [ "$st" != failed ] || [ "$(lv error_code)" != workspace_changed ]; then
    problem="$problem; akhir harus failed/workspace_changed, dapat status=${st:--} error_code=$(lv error_code) (kode keluar $RC)"
  fi
  absent "/data/builds/$AID/$b/unsigned.apk" "/data/builds/$AID/$b/src"
  [ "$RC" -eq 0 ] || problem="$problem; unsigned.apk atau src/ tersisa di builds/$AID/$b"
  if [ -n "$problem" ]; then
    row GAGAL "$N9" "${problem#; }"
    settle
    return 1
  fi
  row OK "$N9" "approve --hold -> workspace diubah (hash beda) -> pelepasan dengan hash lama -> failed/workspace_changed; tanpa unsigned.apk dan src/"
}
step10() {
  local b h problem=""
  bc request "$AID"
  b="$(lv build_id)"; h="$(lv diff_sha256)"
  if [ "$RC" -ne 0 ] || ! is_num "$b" || ! is_hex64 "$h"; then row GAGAL "$N10" "request gagal: $(err_text)"; return 1; fi
  bc approve "$b" --diff-sha256 "$h" --hold
  [ "$RC" -eq 0 ] && [ "$(lv status)" = queued ] || problem="approve --hold gagal: $(err_text)"
  bc cancel "$b"
  if [ "$RC" -ne 0 ] || [ "$(lv hasil)" != cancelled ]; then problem="$problem; cancel harus hasil=cancelled, dapat: $(err_text) hasil=$(lv hasil)"; fi
  bc status "$b"
  [ "$(lv status)" = cancelled ] || problem="$problem; status akhir ${OUT:+$(lv status)} bukan cancelled"
  absent "/data/builds/$AID/$b"
  [ "$RC" -eq 0 ] || problem="$problem; folder builds/$AID/$b ada"
  if [ -n "$problem" ]; then row GAGAL "$N10" "${problem#; }"; settle; return 1; fi
  row OK "$N10" "approve --hold -> cancel -> hasil=cancelled, status cancelled, tanpa folder build"
}
step11() {
  local i ids="" pruned dirs n problem="" first="$BID" list item id st donedirs=""
  local -a items=()
  for i in 1 2; do
    build_once
    case $? in 2) problem="$problem; request ke-$i gagal: $(err_text)"; break ;; 3) problem="$problem; approve ke-$i gagal: $(err_text)"; break ;; esac
    bc wait "$B_ID" --timeout "$WAIT_MAX"
    if [ "$RC" -ne 0 ]; then problem="$problem; build ke-$i tidak done: status=$(lv status) $(lv error_code)"; break; fi
    ids="$ids $B_ID"
  done
  if [ -n "$problem" ]; then row GAGAL "$N11" "${problem#; }"; settle; return 1; fi
  cr -e BUILD_KEEP=2 worker python -c 'import builds,sys; builds.prune_for(int(sys.argv[1]))' "$AID"
  pruned="$(lv pruned)"
  [ "$RC" -eq 0 ] || problem="prune_for gagal: $(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')"
  bc status --analysis "$AID"
  dirs="$(lv build_dirs)"; list="$(lv builds)"; n=0
  # Retensi menghitung build `done` dan build gagal/batal TERPISAH (store.prune_builds): build gagal (mis. workspace_changed di langkah 9) tetap menyisakan folder
  # berisi build.log, jadi yang dihitung hanya folder milik build berstatus `done`.
  IFS=, read -r -a items <<<"$list"
  for item in ${items[@]+"${items[@]}"}; do
    id="${item%%:*}"; st="${item#*:}"
    [ "$st" = done ] || continue
    n=$((n + 1))
    case ",$dirs," in *",$id,"*) donedirs="$donedirs${donedirs:+,}$id" ;; *) problem="$problem; build done $id tidak punya folder" ;; esac
  done
  [ "$n" = 2 ] || problem="$problem; tepat dua build done seharusnya tersisa, dapat $n (builds=${list:--}; folder=${dirs:--})"
  for i in $ids; do case ",$donedirs," in *",$i,"*) ;; *) problem="$problem; folder build $i (terbaru) hilang" ;; esac; done
  if [ -n "$first" ]; then
    case ",$dirs," in *",$first,"*) problem="$problem; build tertua $first masih ada di volume" ;; esac
    bc status "$first"
    if [ "$RC" -ne 3 ] || [ "$(lv kode)" != build_tidak_ada ]; then problem="$problem; baris build tertua $first masih ada (harus build_tidak_ada): $(err_text)"; fi
  fi
  if [ -n "$problem" ]; then row GAGAL "$N11" "${problem#; }"; return 1; fi
  row OK "$N11" "dua build done tambahan ($ids ); prune_for nyata dengan BUILD_KEEP=2 -> pruned=${pruned:--}; tersisa dua folder done ($donedirs; folder build gagal tidak dihitung); build tertua hilang dari volume dan DB; build gagal/batal tidak menggeser done"
}

# ------------------------------------------------------------------------------------------------ langkah 12
step12() {
  local a="$AID" problem="" left logs
  settle
  if [ -n "$LEFT" ]; then
    CLEAN_NOTE="analisis uji TERTINGGAL aid=$a (build masih aktif:$LEFT)"
    echo "✗ $CLEAN_NOTE" >&2
    row GAGAL "$N12" "$CLEAN_NOTE; delete tidak dicoba di langkah ini (ditolak busy), trap mencobanya lagi"
    return 1
  fi
  bc delete "$a"
  [ "$(lv hasil)" = deleted ] && AID=""
  if [ "$RC" -ne 0 ] || [ "$(lv hasil)" != deleted ] || [ "$(lv builds_ada)$(lv bench_ada)$(lv work_ada)" != 000 ]; then
    problem="delete: $(err_text) hasil=$(lv hasil) builds_ada=$(lv builds_ada) bench_ada=$(lv bench_ada) work_ada=$(lv work_ada)"
  fi
  printf '%s\n' "$OUT" | grep -q 'PermissionError' && problem="$problem; PermissionError di keluaran delete"
  cx web ls /data/builds
  if printf '%s\n' "$OUT" | grep -q -x "$a"; then problem="$problem; /data/builds/$a masih terdaftar di kontainer web"; fi
  # shellcheck disable=SC2086
  logs="$($COMPOSE logs --no-log-prefix --since "$START_TS" web 2>&1 </dev/null | tr -d '\r')"
  if printf '%s\n' "$logs" | grep -q 'PermissionError'; then problem="$problem; PermissionError di log web selama run ini"; fi
  cx signer ls /data/signwork
  left="$(printf '%s\n' "$OUT" | grep -c "^g$a-")"
  if [ -n "$problem" ]; then row GAGAL "$N12" "${problem#; }"; return 1; fi
  row OK "$N12" "delete -> hasil=deleted builds_ada=0 bench_ada=0 work_ada=0; /data/builds tanpa $a; tanpa PermissionError di keluaran dan log web"
  [ "${left:-0}" -gt 0 ] && row INFO "12 signwork" "signwork/g$a-* masih ada ($left entri; signer mungkin sibuk dengan job lain milik pemilik — INFO, bukan GAGAL)"
  return 0
}

# ------------------------------------------------------------------------------------------------ alur
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
H9=""
run_all() {
  step1 || { halt_from N2 "dilewati: prasyarat (langkah 1) gagal"; return; }
  step2 || { halt_from N3 "dilewati: analisis uji tidak tersedia (langkah 2)"; return; }
  step3 || { halt_from N4 "dilewati: bench/diff dasar gagal (langkah 3)"; return; }
  step4 || { halt_from N5 "dilewati: perubahan string via shell gagal (langkah 4)"; return; }
  step5
  if step6; then
    step7
    step7b
    if [ "$ART_OK" = 1 ]; then
      step8
    else
      row DILEWATI "$N8" "dilewati: artefak tidak utuh setelah langkah 7b"
    fi
  else
    row DILEWATI "$N7" "dilewati: tidak ada build done (langkah 6)"
    row DILEWATI "$N7B" "dilewati: tidak ada build done (langkah 6)"
    row DILEWATI "$N8" "dilewati: tidak ada build done (langkah 6)"
  fi
  step9
  step10
  step11
  step12
  if [ -n "$BIG_MB" ]; then
    row INFO "BIG_MB uji APK besar" "BIG_MB=$BIG_MB dicatat; pipeline build tidak menguji APK besar di sini — uji besar signer: BIG_MB=$BIG_MB make signer-verify"
  fi
}
run_all
exit 0
